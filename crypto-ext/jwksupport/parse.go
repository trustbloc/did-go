/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwksupport

import (
	"fmt"

	"github.com/trustbloc/did-go/doc/jose/jwk"
)

const (
	ed25519PublicKeySize = 32
)

// ToED25519PublicKeyBytes convert jwk to ed25519 pub key bytes.
func ToED25519PublicKeyBytes(key *jwk.JWK) ([]byte, error) {
	if key.X == nil {
		return nil, fmt.Errorf("invalid Ed key, missing x value")
	}

	publicKey := make([]byte, ed25519PublicKeySize)
	copy(publicKey[0:ed25519PublicKeySize], key.X.Bytes())

	return publicKey, nil
}
