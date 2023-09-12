/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package patchvalidator

import (
	"fmt"

	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/document"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/patch"
)

// NewAddServicesValidator creates new validator.
func NewAddServicesValidator() *AddServicesValidator {
	return &AddServicesValidator{}
}

// AddServicesValidator implements validator for "add-public-keys" patch.
type AddServicesValidator struct {
}

// Validate validates patch.
func (v *AddServicesValidator) Validate(p patch.Patch) error {
	value, err := p.GetValue()
	if err != nil {
		return err
	}

	_, err = getRequiredArray(value)
	if err != nil {
		return fmt.Errorf("invalid add services value: %s", err.Error())
	}

	services := document.ParseServices(value)

	return validateServices(services)
}
