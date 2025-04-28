/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package web

import (
	"errors"

	diddoc "github.com/trustbloc/did-go/doc/did"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
)

const (
	namespace = "web"
)

// VDR implements the VDR interface.
type VDR struct{}

// New creates a new VDR struct.
func New() *VDR {
	return &VDR{}
}

// Accept method of the VDR interface.
func (v *VDR) Accept(method string, opts ...vdrapi.DIDMethodOption) bool {
	return method == namespace
}

// Update did doc.
func (v *VDR) Update(didDoc *diddoc.Doc, opts ...vdrapi.DIDMethodOption) error {
	return errors.New("not supported")
}

// Deactivate did doc.
func (v *VDR) Deactivate(did string, opts ...vdrapi.DIDMethodOption) error {
	return errors.New("not supported")
}

// Close method of the VDR interface.
func (v *VDR) Close() error {
	return nil
}
