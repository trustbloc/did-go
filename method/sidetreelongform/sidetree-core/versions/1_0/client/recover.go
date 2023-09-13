/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"errors"
	"fmt"

	"github.com/trustbloc/did-go/doc/json/canonicalizer"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/api/operation"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/commitment"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/hashing"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/internal/signutil"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/jws"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/patch"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/versions/1_0/model"
)

// RecoverRequestInfo is the information required to create recover request.
type RecoverRequestInfo struct {

	// DidSuffix is the suffix of the document to be recovered
	DidSuffix string

	// RecoveryKey is the current recovery public key
	RecoveryKey *jws.JWK

	// OpaqueDocument is opaque content
	OpaqueDocument string

	// Patches that will be used to create document
	// required if opaque document is not specified
	Patches []patch.Patch

	// RecoveryCommitment is recovery commitment to be used for the next recovery
	RecoveryCommitment string

	// UpdateCommitment is update commitment to be used for the next update
	UpdateCommitment string

	// AnchorOrigin signifies the system(s) that know the most recent anchor for this DID (optional)
	AnchorOrigin interface{}

	// AnchorFrom defines earliest time for this operation.
	AnchorFrom int64

	// AnchorUntil defines expiry time for this operation.
	AnchorUntil int64

	// MultihashCode is the latest hashing algorithm supported by protocol
	MultihashCode uint

	// Signer will be used for signing specific subset of request data
	// Signer for recover operation must be recovery key
	Signer Signer

	// RevealValue is reveal value
	RevealValue string
}

// NewRecoverRequest is utility function to create payload for 'recovery' request.
func NewRecoverRequest(info *RecoverRequestInfo) ([]byte, error) {
	err := validateRecoverRequest(info)
	if err != nil {
		return nil, err
	}

	patches, err := getPatches(info.OpaqueDocument, info.Patches)
	if err != nil {
		return nil, err
	}

	delta := &model.DeltaModel{
		UpdateCommitment: info.UpdateCommitment,
		Patches:          patches,
	}

	deltaHash, err := hashing.CalculateModelMultihash(delta, info.MultihashCode)
	if err != nil {
		return nil, err
	}

	signedDataModel := model.RecoverSignedDataModel{
		DeltaHash:          deltaHash,
		RecoveryKey:        info.RecoveryKey,
		RecoveryCommitment: info.RecoveryCommitment,
		AnchorOrigin:       info.AnchorOrigin,
		AnchorFrom:         info.AnchorFrom,
		AnchorUntil:        info.AnchorUntil,
	}

	err = validateCommitment(info.RecoveryKey, info.MultihashCode, info.RecoveryCommitment)
	if err != nil {
		return nil, err
	}

	signModel, err := signutil.SignModel(signedDataModel, info.Signer)
	if err != nil {
		return nil, err
	}

	schema := &model.RecoverRequest{
		Operation:   operation.TypeRecover,
		DidSuffix:   info.DidSuffix,
		RevealValue: info.RevealValue,
		Delta:       delta,
		SignedData:  signModel,
	}

	return canonicalizer.MarshalCanonical(schema)
}

func validateRecoverRequest(info *RecoverRequestInfo) error {
	if info.DidSuffix == "" {
		return errors.New("missing did unique suffix")
	}

	if info.RevealValue == "" {
		return errors.New("missing reveal value")
	}

	if info.OpaqueDocument == "" && len(info.Patches) == 0 {
		return errors.New("either opaque document or patches have to be supplied")
	}

	if info.OpaqueDocument != "" && len(info.Patches) > 0 {
		return errors.New("cannot provide both opaque document and patches")
	}

	if err := validateSigner(info.Signer); err != nil {
		return err
	}

	return validateRecoveryKey(info.RecoveryKey)
}

func validateRecoveryKey(key *jws.JWK) error {
	if key == nil {
		return errors.New("missing recovery key")
	}

	return key.Validate()
}

func validateCommitment(jwk *jws.JWK, multihashCode uint, nextCommitment string) error {
	currentCommitment, err := commitment.GetCommitment(jwk, multihashCode)
	if err != nil {
		return fmt.Errorf("calculate current commitment: %s", err.Error())
	}

	if currentCommitment == nextCommitment {
		return errors.New("re-using public keys for commitment is not allowed")
	}

	return nil
}
