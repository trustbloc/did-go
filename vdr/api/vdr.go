/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"errors"

	"github.com/trustbloc/did-go/doc/did"
)

// ErrNotFound is returned when a DID resolver does not find the DID.
var ErrNotFound = errors.New("DID does not exist")

const (
	// DIDCommServiceType default DID Communication service endpoint type.
	DIDCommServiceType = "did-communication"

	// DIDCommV2ServiceType is the DID Communications V2 service type.
	DIDCommV2ServiceType = "DIDCommMessaging"

	// LegacyServiceType is the DID Communication V1 indy based service type.
	LegacyServiceType = "IndyAgent"
)

// Registry vdr registry.
type Registry interface {
	Resolve(did string, opts ...DIDMethodOption) (*did.DocResolution, error)
	Create(method string, did *did.Doc, opts ...DIDMethodOption) (*did.DocResolution, error)
	Update(did *did.Doc, opts ...DIDMethodOption) error
	Deactivate(did string, opts ...DIDMethodOption) error
	Close() error
}

// VDR verifiable data registry interface.
// TODO https://github.com/hyperledger/aries-framework-go/issues/2475
type VDR interface {
	Read(did string, opts ...DIDMethodOption) (*did.DocResolution, error)
	Create(did *did.Doc, opts ...DIDMethodOption) (*did.DocResolution, error)
	Accept(method string, opts ...DIDMethodOption) bool
	Update(did *did.Doc, opts ...DIDMethodOption) error
	Deactivate(did string, opts ...DIDMethodOption) error
	Close() error
}
