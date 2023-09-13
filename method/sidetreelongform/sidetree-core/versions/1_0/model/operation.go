/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import (
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/api/operation"
)

// Operation is used for parsing operation request.
type Operation struct {

	// Type defines operation type
	Type operation.Type

	// Namespace defines document namespace
	Namespace string

	// ID is full ID for this document -  namespace + unique suffix
	ID string

	// UniqueSuffix is unique suffix
	UniqueSuffix string

	// OperationRequest is the original operation request
	OperationRequest []byte

	// SignedData is signed data for the operation (compact JWS)
	SignedData string

	// RevealValue is multihash of JWK
	RevealValue string

	// Delta is operation delta model
	Delta *DeltaModel

	// SuffixDataModel is suffix data model
	SuffixData *SuffixDataModel

	// AnchorOrigin is anchor origin
	AnchorOrigin interface{}
}
