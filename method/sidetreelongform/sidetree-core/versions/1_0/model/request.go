/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import (
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/api/operation"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/jws"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/patch"
)

// CreateRequest is the struct for create payload JCS.
type CreateRequest struct {
	// operation
	// Required: true
	Operation operation.Type `json:"type,omitempty"`

	// Suffix data object
	// Required: true
	SuffixData *SuffixDataModel `json:"suffixData,omitempty"`

	// Delta object
	// Required: true
	Delta *DeltaModel `json:"delta,omitempty"`
}

// SuffixDataModel is part of create request.
type SuffixDataModel struct {

	// Hash of the delta object (required)
	DeltaHash string `json:"deltaHash,omitempty"`

	// Commitment hash for the next recovery or deactivate operation (required)
	RecoveryCommitment string `json:"recoveryCommitment,omitempty"`

	// AnchorOrigin signifies the system(s) that know the most recent anchor for this DID (optional)
	AnchorOrigin interface{} `json:"anchorOrigin,omitempty"`

	// Type signifies the type of entity a DID represents (optional)
	Type string `json:"type,omitempty"`
}

// DeltaModel contains patch data (patches used for create, recover, update).
type DeltaModel struct {

	// Commitment hash for the next update operation
	UpdateCommitment string `json:"updateCommitment,omitempty"`

	// Patches defines document patches
	Patches []patch.Patch `json:"patches,omitempty"`
}

// UpdateRequest is the struct for update request.
type UpdateRequest struct {
	// Operation defines operation type
	Operation operation.Type `json:"type"`

	// DidSuffix is the suffix of the DID
	DidSuffix string `json:"didSuffix"`

	// RevealValue is the reveal value
	RevealValue string `json:"revealValue"`

	// SignedData is compact JWS - signature information
	SignedData string `json:"signedData"`

	// Delta is encoded delta object
	Delta *DeltaModel `json:"delta"`
}

// DeactivateRequest is the struct for deactivating document.
type DeactivateRequest struct {
	// Operation
	// Required: true
	Operation operation.Type `json:"type"`

	// DidSuffix of the DID
	// Required: true
	DidSuffix string `json:"didSuffix"`

	// RevealValue is the reveal value
	RevealValue string `json:"revealValue"`

	// Compact JWS - signature information
	SignedData string `json:"signedData"`
}

// UpdateSignedDataModel defines signed data model for update.
type UpdateSignedDataModel struct {
	// UpdateKey is the current update key
	UpdateKey *jws.JWK `json:"updateKey"`

	// DeltaHash of the unsigned delta object
	DeltaHash string `json:"deltaHash"`

	// AnchorFrom defines earliest time for this operation.
	AnchorFrom int64 `json:"anchorFrom,omitempty"`

	// AnchorUntil defines expiry time for this operation.
	AnchorUntil int64 `json:"anchorUntil,omitempty"`
}

// RecoverSignedDataModel defines signed data model for recovery.
type RecoverSignedDataModel struct {

	// DeltaHash of the unsigned delta object
	DeltaHash string `json:"deltaHash"`

	// RecoveryKey is The current recovery key
	RecoveryKey *jws.JWK `json:"recoveryKey"`

	// RecoveryCommitment is the commitment used for the next recovery/deactivate
	RecoveryCommitment string `json:"recoveryCommitment"`

	// AnchorOrigin signifies the system(s) that know the most recent anchor for this DID (optional)
	AnchorOrigin interface{} `json:"anchorOrigin,omitempty"`

	// AnchorFrom defines earliest time for this operation.
	AnchorFrom int64 `json:"anchorFrom,omitempty"`

	// AnchorUntil defines expiry time for this operation.
	AnchorUntil int64 `json:"anchorUntil,omitempty"`
}

// DeactivateSignedDataModel defines data model for deactivate.
type DeactivateSignedDataModel struct {

	// DidSuffix is the suffix of the DID
	// Required: true
	DidSuffix string `json:"didSuffix"`

	// RevealValue is the reveal value
	RevealValue string `json:"revealValue"`

	// RecoveryKey is the current recovery key
	RecoveryKey *jws.JWK `json:"recoveryKey"`

	// AnchorFrom defines earliest time for this operation.
	AnchorFrom int64 `json:"anchorFrom,omitempty"`

	// AnchorUntil defines expiry time for this operation.
	AnchorUntil int64 `json:"anchorUntil,omitempty"`
}

// RecoverRequest is the struct for document recovery payload.
type RecoverRequest struct {
	// operation
	// Required: true
	Operation operation.Type `json:"type"`

	// DidSuffix is the suffix of the DID
	// Required: true
	DidSuffix string `json:"didSuffix"`

	// RevealValue is the reveal value
	RevealValue string `json:"revealValue"`

	// Compact JWS - signature information
	SignedData string `json:"signedData"`

	// Delta object
	// Required: true
	Delta *DeltaModel `json:"delta"`
}
