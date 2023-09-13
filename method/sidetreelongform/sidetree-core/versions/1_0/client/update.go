/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"errors"

	"github.com/trustbloc/did-go/doc/json/canonicalizer"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/api/operation"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/hashing"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/internal/signutil"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/jws"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/patch"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/versions/1_0/model"
)

// UpdateRequestInfo is the information required to create update request.
type UpdateRequestInfo struct {

	// DidSuffix is the suffix of the document to be updated
	DidSuffix string

	// Patches is an array of standard patch actions
	Patches []patch.Patch

	// update commitment to be used for the next update
	UpdateCommitment string

	// update key to be used for this update
	UpdateKey *jws.JWK

	// latest hashing algorithm supported by protocol
	MultihashCode uint

	// Signer that will be used for signing request specific subset of data
	Signer Signer

	// RevealValue is reveal value
	RevealValue string

	// AnchorFrom defines earliest time for this operation.
	AnchorFrom int64

	// AnchorUntil defines expiry time for this operation.
	AnchorUntil int64
}

// NewUpdateRequest is utility function to create payload for 'update' request.
func NewUpdateRequest(info *UpdateRequestInfo) ([]byte, error) {
	if err := validateUpdateRequest(info); err != nil {
		return nil, err
	}

	delta := &model.DeltaModel{
		UpdateCommitment: info.UpdateCommitment,
		Patches:          info.Patches,
	}

	deltaHash, err := hashing.CalculateModelMultihash(delta, info.MultihashCode)
	if err != nil {
		return nil, err
	}

	signedDataModel := &model.UpdateSignedDataModel{
		DeltaHash:   deltaHash,
		UpdateKey:   info.UpdateKey,
		AnchorFrom:  info.AnchorFrom,
		AnchorUntil: info.AnchorUntil,
	}

	err = validateCommitment(info.UpdateKey, info.MultihashCode, info.UpdateCommitment)
	if err != nil {
		return nil, err
	}

	signModel, err := signutil.SignModel(signedDataModel, info.Signer)
	if err != nil {
		return nil, err
	}

	schema := &model.UpdateRequest{
		Operation:   operation.TypeUpdate,
		DidSuffix:   info.DidSuffix,
		RevealValue: info.RevealValue,
		Delta:       delta,
		SignedData:  signModel,
	}

	return canonicalizer.MarshalCanonical(schema)
}

func validateUpdateRequest(info *UpdateRequestInfo) error {
	if info.DidSuffix == "" {
		return errors.New("missing did unique suffix")
	}

	if info.RevealValue == "" {
		return errors.New("missing reveal value")
	}

	if len(info.Patches) == 0 {
		return errors.New("missing update information")
	}

	if err := validateUpdateKey(info.UpdateKey); err != nil {
		return err
	}

	return validateSigner(info.Signer)
}

func validateUpdateKey(key *jws.JWK) error {
	if key == nil {
		return errors.New("missing update key")
	}

	return key.Validate()
}
