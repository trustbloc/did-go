/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwk

import (
	"encoding/base64"
	"fmt"

	"github.com/trustbloc/did-go/pkg/canonicalizer"
	"github.com/trustbloc/kms-go/doc/jose/jwk"

	"github.com/trustbloc/did-go/doc/did"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
)

// Create new DID document for didDoc.
func (v *VDR) Create(didDoc *did.Doc, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	// make sure there is one verification method
	if len(didDoc.VerificationMethod) == 0 {
		return nil, fmt.Errorf("missing verification method")
	}

	if len(didDoc.VerificationMethod) > 1 {
		return nil, fmt.Errorf("found more than one verification method")
	}

	if didDoc.VerificationMethod[0].Type != jsonWebKey2020 {
		return nil, fmt.Errorf("verification method type[%s] is not supported", didDoc.VerificationMethod[0].Type)
	}

	key := didDoc.VerificationMethod[0].JSONWebKey()

	didJWK, err := createDID(key)
	if err != nil {
		return nil, fmt.Errorf("error creating DID: %w", err)
	}

	return createJWKResolutionResult(didJWK, key)
}

func createDID(key *jwk.JWK) (string, error) {
	if key == nil {
		return "", fmt.Errorf("missing JWK")
	}

	keyBytes, err := key.MarshalJSON()
	if err != nil {
		return "", fmt.Errorf("marshal key: %w", err)
	}

	canonicalBytes, err := canonicalizer.MarshalCanonical(keyBytes)
	if err != nil {
		return "", fmt.Errorf("marshal canonical: %w", err)
	}

	didJWK := fmt.Sprintf("did:%s:%s", DIDMethod, base64.RawURLEncoding.EncodeToString(canonicalBytes))

	return didJWK, nil
}
