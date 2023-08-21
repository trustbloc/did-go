/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package web

import (
	"fmt"

	"github.com/trustbloc/vc-go/did"
	vdrspi "github.com/trustbloc/vc-go/spi/vdr"
)

// Create creates a did:web diddoc (unsupported at the moment).
func (v *VDR) Create(didDoc *did.Doc, opts ...vdrspi.DIDMethodOption) (*did.DocResolution, error) {
	return nil, fmt.Errorf("error building did:web did doc --> build not supported in http binding vdr")
}
