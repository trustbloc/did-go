/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operationparser

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"

	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/api/operation"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/commitment"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/encoder"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/hashing"
	internal "github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/internal/jws"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/jws"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/versions/1_0/model"
)

// ParseRecoverOperation will parse recover operation.
func (p *Parser) ParseRecoverOperation(request []byte, batch bool) (*model.Operation, error) {
	schema, err := p.parseRecoverRequest(request)
	if err != nil {
		return nil, err
	}

	signedData, err := p.ParseSignedDataForRecover(schema.SignedData)
	if err != nil {
		return nil, err
	}

	if !batch {
		err = p.anchorOriginValidator.Validate(signedData.AnchorOrigin)
		if err != nil {
			return nil, err
		}

		until := p.getAnchorUntil(signedData.AnchorFrom, signedData.AnchorUntil)

		err = p.anchorTimeValidator.Validate(signedData.AnchorFrom, until)
		if err != nil {
			return nil, err
		}

		err = p.ValidateDelta(schema.Delta)
		if err != nil {
			return nil, err
		}

		if schema.Delta.UpdateCommitment == signedData.RecoveryCommitment {
			return nil, errors.New("recovery and update commitments cannot be equal, re-using public keys is not allowed")
		}
	}

	err = hashing.IsValidModelMultihash(signedData.RecoveryKey, schema.RevealValue)
	if err != nil {
		return nil, fmt.Errorf("canonicalized recovery public key hash doesn't match reveal value: %s", err.Error())
	}

	return &model.Operation{
		OperationRequest: request,
		Type:             operation.TypeRecover,
		UniqueSuffix:     schema.DidSuffix,
		Delta:            schema.Delta,
		SignedData:       schema.SignedData,
		RevealValue:      schema.RevealValue,
		AnchorOrigin:     signedData.AnchorOrigin,
	}, nil
}

func (p *Parser) parseRecoverRequest(payload []byte) (*model.RecoverRequest, error) {
	schema := &model.RecoverRequest{}

	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal recover request: %s", err.Error())
	}

	if err := p.validateRecoverRequest(schema); err != nil {
		return nil, err
	}

	return schema, nil
}

// ParseSignedDataForRecover will parse and validate signed data for recover.
func (p *Parser) ParseSignedDataForRecover(compactJWS string) (*model.RecoverSignedDataModel, error) {
	signedData, err := p.parseSignedData(compactJWS)
	if err != nil {
		return nil, err
	}

	schema := &model.RecoverSignedDataModel{}

	err = json.Unmarshal(signedData.Payload, schema)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signed data model for recover: %s", err.Error())
	}

	if err := p.validateSignedDataForRecovery(schema); err != nil {
		return nil, fmt.Errorf("validate signed data for recovery: %s", err.Error())
	}

	return schema, nil
}

func (p *Parser) validateSignedDataForRecovery(signedData *model.RecoverSignedDataModel) error {
	if err := p.validateSigningKey(signedData.RecoveryKey); err != nil {
		return err
	}

	if err := p.validateMultihash(signedData.RecoveryCommitment, "recovery commitment"); err != nil {
		return err
	}

	if err := p.validateMultihash(signedData.DeltaHash, "delta hash"); err != nil {
		return err
	}

	return p.validateCommitment(signedData.RecoveryKey, signedData.RecoveryCommitment)
}

func (p *Parser) parseSignedData(compactJWS string) (*internal.JSONWebSignature, error) {
	if compactJWS == "" {
		return nil, errors.New("missing signed data")
	}

	sig, err := internal.ParseJWS(compactJWS)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed data: %s", err.Error())
	}

	err = p.validateProtectedHeaders(sig.ProtectedHeaders, p.SignatureAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed data: %s", err.Error())
	}

	return sig, nil
}

func (p *Parser) validateProtectedHeaders(headers jws.Headers, allowedAlgorithms []string) error {
	if headers == nil {
		return errors.New("missing protected headers")
	}

	// kid MAY be present in the protected header.
	// alg MUST be present in the protected header, its value MUST NOT be none.
	// no additional members may be present in the protected header.

	alg, ok := headers.Algorithm()
	if !ok {
		return errors.New("algorithm must be present in the protected header")
	}

	if alg == "" {
		return errors.New("algorithm cannot be empty in the protected header")
	}

	allowedHeaders := map[string]bool{
		jws.HeaderAlgorithm: true,
		jws.HeaderKeyID:     true,
	}

	for k := range headers {
		if _, ok := allowedHeaders[k]; !ok {
			return fmt.Errorf("invalid protected header: %s", k)
		}
	}

	if !contains(allowedAlgorithms, alg) {
		return errors.Errorf("algorithm '%s' is not in the allowed list %v", alg, allowedAlgorithms)
	}

	return nil
}

func (p *Parser) validateRecoverRequest(req *model.RecoverRequest) error {
	if req.DidSuffix == "" {
		return errors.New("missing did suffix")
	}

	if req.SignedData == "" {
		return errors.New("missing signed data")
	}

	return p.validateMultihash(req.RevealValue, "reveal value")
}

func (p *Parser) validateSigningKey(key *jws.JWK) error {
	if key == nil {
		return errors.New("missing signing key")
	}

	// validate mandatory values
	err := key.Validate()
	if err != nil {
		return fmt.Errorf("signing key validation failed: %s", err.Error())
	}

	// validate key algorithm
	if !contains(p.KeyAlgorithms, key.Crv) {
		return errors.Errorf("key algorithm '%s' is not in the allowed list %v", key.Crv, p.KeyAlgorithms)
	}

	// validate optional nonce
	err = p.validateNonce(key.Nonce)
	if err != nil {
		return fmt.Errorf("validate signing key nonce: %s", err.Error())
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

func (p *Parser) validateCommitment(jwk *jws.JWK, nextCommitment string) error {
	code, err := hashing.GetMultihashCode(nextCommitment)
	if err != nil {
		return err
	}

	currentCommitment, err := commitment.GetCommitment(jwk, uint(code))
	if err != nil {
		return fmt.Errorf("calculate current commitment: %s", err.Error())
	}

	if currentCommitment == nextCommitment {
		return errors.New("re-using public keys for commitment is not allowed")
	}

	return nil
}

func (p *Parser) validateNonce(nonce string) error {
	// nonce is optional
	if nonce == "" {
		return nil
	}

	nonceBytes, err := encoder.DecodeString(nonce)
	if err != nil {
		return fmt.Errorf("failed to decode nonce '%s': %s", nonce, err.Error())
	}

	if len(nonceBytes) != int(p.NonceSize) {
		return fmt.Errorf("nonce size '%d' doesn't match configured nonce size '%d'", len(nonceBytes), p.NonceSize)
	}

	return nil
}

func (p *Parser) getAnchorUntil(from, until int64) int64 {
	if from != 0 && until == 0 {
		return from + int64(p.MaxDeltaSize)
	}

	return until
}
