/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package patchvalidator

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/document"
)

//nolint:gochecknoglobals
var (
	asciiRegex = regexp.MustCompile("^[A-Za-z0-9_-]+$")
)

const (
	bls12381G2Key2020                 = "Bls12381G2Key2020"
	jsonWebKey2020                    = "JsonWebKey2020"
	ecdsaSecp256k1VerificationKey2019 = "EcdsaSecp256k1VerificationKey2019"
	x25519KeyAgreementKey2019         = "X25519KeyAgreementKey2019"
	ed25519VerificationKey2018        = "Ed25519VerificationKey2018"
	ed25519VerificationKey2020        = "Ed25519VerificationKey2020"

	// public keys, services id length.
	maxIDLength = 50

	maxServiceTypeLength = 30
)

//nolint:gochecknoglobals
var allowedPurposes = map[document.KeyPurpose]bool{
	document.KeyPurposeAuthentication:       true,
	document.KeyPurposeAssertionMethod:      true,
	document.KeyPurposeKeyAgreement:         true,
	document.KeyPurposeCapabilityDelegation: true,
	document.KeyPurposeCapabilityInvocation: true,
}

type existenceMap map[string]string

//nolint:gochecknoglobals
var allowedKeyTypesGeneral = existenceMap{
	bls12381G2Key2020:                 bls12381G2Key2020,
	jsonWebKey2020:                    jsonWebKey2020,
	ecdsaSecp256k1VerificationKey2019: ecdsaSecp256k1VerificationKey2019,
	ed25519VerificationKey2018:        ed25519VerificationKey2018,
	ed25519VerificationKey2020:        ed25519VerificationKey2020,
	x25519KeyAgreementKey2019:         x25519KeyAgreementKey2019,
}

//nolint:gochecknoglobals
var allowedKeyTypesVerification = existenceMap{
	bls12381G2Key2020:                 bls12381G2Key2020,
	jsonWebKey2020:                    jsonWebKey2020,
	ecdsaSecp256k1VerificationKey2019: ecdsaSecp256k1VerificationKey2019,
	ed25519VerificationKey2018:        ed25519VerificationKey2018,
	ed25519VerificationKey2020:        ed25519VerificationKey2020,
}

//nolint:gochecknoglobals
var allowedKeyTypesAgreement = existenceMap{
	// TODO: Verify appropriate agreement key types for JWS and Secp256k1
	bls12381G2Key2020:                 bls12381G2Key2020,
	jsonWebKey2020:                    jsonWebKey2020,
	ecdsaSecp256k1VerificationKey2019: ecdsaSecp256k1VerificationKey2019,
	x25519KeyAgreementKey2019:         x25519KeyAgreementKey2019,
}

//nolint:gochecknoglobals
var allowedKeyTypes = map[string]existenceMap{
	document.KeyPurposeAuthentication:       allowedKeyTypesVerification,
	document.KeyPurposeAssertionMethod:      allowedKeyTypesVerification,
	document.KeyPurposeKeyAgreement:         allowedKeyTypesAgreement,
	document.KeyPurposeCapabilityDelegation: allowedKeyTypesVerification,
	document.KeyPurposeCapabilityInvocation: allowedKeyTypesVerification,
}

// validatePublicKeys validates public keys.
func validatePublicKeys(pubKeys []document.PublicKey) error {
	ids := make(map[string]bool)

	for _, pubKey := range pubKeys {
		if err := validatePublicKeyProperties(pubKey); err != nil {
			return err
		}

		kid := pubKey.ID()
		if err := validateID(kid); err != nil {
			return fmt.Errorf("public key: %s", err.Error())
		}

		if _, ok := ids[kid]; ok {
			return fmt.Errorf("duplicate public key id: %s", kid)
		}

		ids[kid] = true

		if err := validateKeyPurposes(pubKey); err != nil {
			return err
		}

		if !validateKeyTypePurpose(pubKey) {
			return fmt.Errorf("invalid key type: %s", pubKey.Type())
		}

		if err := validateJWK(pubKey.PublicKeyJwk()); err != nil {
			if pubKey.PublicKeyBase58() == "" || pubKey.Type() == jsonWebKey2020 {
				return err
			}
		}
	}

	return nil
}

func validatePublicKeyProperties(pubKey document.PublicKey) error { //nolint:gocyclo
	requiredKeys := []string{document.TypeProperty, document.IDProperty}
	optionalKeys := []string{document.PurposesProperty}
	oneOfNKeys := [][]string{{document.PublicKeyJwkProperty, document.PublicKeyBase58Property}}

	allowedKeys := append(requiredKeys, optionalKeys...) //nolint:gocritic

	for _, keyGroup := range oneOfNKeys {
		allowedKeys = append(allowedKeys, keyGroup...)
	}

	for _, required := range requiredKeys {
		if _, ok := pubKey[required]; !ok {
			return fmt.Errorf("key '%s' is required for public key", required)
		}
	}

	for _, keyGroup := range oneOfNKeys {
		var satisfied bool

		for _, key := range keyGroup {
			_, ok := pubKey[key]
			if ok && satisfied { // at most one element
				satisfied = false

				break
			}

			satisfied = satisfied || ok
		}

		if !satisfied {
			return fmt.Errorf("exactly one key required of '%s'", strings.Join(keyGroup, "', '"))
		}
	}

	for key := range pubKey {
		if !contains(allowedKeys, key) {
			return fmt.Errorf("key '%s' is not allowed for public key", key)
		}
	}

	return nil
}

// validateID validates id.
func validateID(id string) error {
	if len(id) > maxIDLength {
		return fmt.Errorf("id exceeds maximum length: %d", maxIDLength)
	}

	if !asciiRegex.MatchString(id) {
		return errors.New("id contains invalid characters")
	}

	return nil
}

// validateServices validates services.
func validateServices(services []document.Service) error {
	ids := make(map[string]bool)

	for _, service := range services {
		if err := validateService(service); err != nil {
			return err
		}

		if _, ok := ids[service.ID()]; ok {
			return fmt.Errorf("duplicate service id: %s", service.ID())
		}

		ids[service.ID()] = true
	}

	return nil
}

func validateService(service document.Service) error {
	// expected fields are type, id, and serviceEndpoint and some optional fields
	if err := validateServiceID(service.ID()); err != nil {
		return err
	}

	if err := validateServiceType(service.Type()); err != nil {
		return err
	}

	if err := validateServiceEndpoint(service.ServiceEndpoint()); err != nil {
		return err
	}

	return nil
}

func validateServiceID(id string) error {
	if id == "" {
		return errors.New("service id is missing")
	}

	if err := validateID(id); err != nil {
		return fmt.Errorf("service: %s", err.Error())
	}

	return nil
}

func validateServiceType(serviceType string) error {
	if serviceType == "" {
		return errors.New("service type is missing")
	}

	if len(serviceType) > maxServiceTypeLength {
		return fmt.Errorf("service type exceeds maximum length: %d", maxServiceTypeLength)
	}

	return nil
}

func validateServiceEndpoint(serviceEndpoint interface{}) error {
	if serviceEndpoint == nil {
		return errors.New("service endpoint is missing")
	}

	uri, ok := serviceEndpoint.(string)
	if ok {
		return validateURI(uri)
	}

	uris, ok := serviceEndpoint.([]string)
	if ok {
		return validateURIs(uris)
	}

	objs, ok := serviceEndpoint.([]interface{})
	if ok {
		return validateServiceEndpointObjects(objs)
	}

	return nil
}

func validateServiceEndpointObjects(objs []interface{}) error {
	for _, obj := range objs {
		uri, ok := obj.(string)
		if ok {
			return validateURI(uri)
		}
	}

	return nil
}

func validateURIs(uris []string) error {
	for _, uri := range uris {
		if err := validateURI(uri); err != nil {
			return err
		}
	}

	return nil
}

func validateURI(uri string) error {
	if uri == "" {
		return errors.New("service endpoint URI is empty")
	}

	if _, err := url.ParseRequestURI(uri); err != nil {
		return fmt.Errorf("service endpoint '%s' is not a valid URI: %s", uri, err.Error())
	}

	return nil
}

// validateKeyTypePurpose validates if the public key type is valid for a certain purpose.
func validateKeyTypePurpose(pubKey document.PublicKey) bool {
	if len(pubKey.Purpose()) == 0 {
		// general key
		_, ok := allowedKeyTypesGeneral[pubKey.Type()]
		if !ok {
			return false
		}
	}

	for _, purpose := range pubKey.Purpose() {
		allowed, ok := allowedKeyTypes[purpose]
		if !ok {
			return false
		}

		_, ok = allowed[pubKey.Type()]
		if !ok {
			return false
		}
	}

	return true
}

// validateJWK validates JWK.
func validateJWK(jwk document.JWK) error {
	if jwk == nil {
		return errors.New("key has to be in JWK format")
	}

	return jwk.Validate()
}

// The object MAY include a purposes property, and if included, its value MUST be an array of one or more
// of the strings listed in allowed purposes array.
func validateKeyPurposes(pubKey document.PublicKey) error {
	_, exists := pubKey[document.PurposesProperty]

	if exists && len(pubKey.Purpose()) == 0 {
		return fmt.Errorf("if '%s' key is specified, it must contain at least one purpose", document.PurposesProperty)
	}

	if len(pubKey.Purpose()) > len(allowedPurposes) {
		return fmt.Errorf("public key purpose exceeds maximum length: %d", len(allowedPurposes))
	}

	for _, purpose := range pubKey.Purpose() {
		if _, ok := allowedPurposes[document.KeyPurpose(purpose)]; !ok {
			return fmt.Errorf("invalid purpose: %s", purpose)
		}
	}

	return nil
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}

	return false
}

func validateIds(ids []string) error {
	for _, id := range ids {
		if err := validateID(id); err != nil {
			return err
		}
	}

	return nil
}

func getRequiredArray(entry interface{}) ([]interface{}, error) {
	arr, ok := entry.([]interface{})
	if !ok {
		return nil, errors.New("expected array of interfaces")
	}

	if len(arr) == 0 {
		return nil, errors.New("required array is empty")
	}

	return arr, nil
}
