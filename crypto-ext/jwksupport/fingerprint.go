/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwksupport

import (
	"crypto/elliptic"
	"fmt"

	"github.com/trustbloc/kms-go/util/cryptoutil"

	"github.com/trustbloc/did-go/doc/jose/jwk"

	"github.com/trustbloc/did-go/doc/fingerprint"
)

// CreateDIDKeyByJwk creates a did:key ID using the multicodec key fingerprint as per the did:key format spec found at:
// https://w3c-ccg.github.io/did-method-key/#format.
func CreateDIDKeyByJwk(jsonWebKey *jwk.JWK) (string, string, error) {
	if jsonWebKey == nil {
		return "", "", fmt.Errorf("jsonWebKey is required")
	}

	switch jsonWebKey.Kty {
	case "EC":
		code, curve, err := ecCodeAndCurve(jsonWebKey.Crv)
		if err != nil {
			return "", "", err
		}

		bytes := elliptic.MarshalCompressed(curve, jsonWebKey.X.BigInt(), jsonWebKey.Y.BigInt())
		didKey, keyID := fingerprint.CreateDIDKeyByCode(code, bytes)

		return didKey, keyID, nil

	case "OKP":
		var code uint64

		switch jsonWebKey.Crv {
		case "X25519":
			var keyData = jsonWebKey.X.Bytes()

			if len(keyData) != cryptoutil.Curve25519KeySize {
				return "", "", jwk.ErrInvalidKey
			}

			code = fingerprint.X25519PubKeyMultiCodec
			didKey, keyID := fingerprint.CreateDIDKeyByCode(code, keyData)

			return didKey, keyID, nil
		case "Ed25519":
			keyData, err := ToED25519PublicKeyBytes(jsonWebKey)
			if err != nil {
				return "", "", err
			}

			didKey, keyID := fingerprint.CreateED25519DIDKey(keyData)

			return didKey, keyID, nil

		default:
			return "", "", fmt.Errorf(
				"unsupported kty %q and crv %q combination", jsonWebKey.Kty, jsonWebKey.Crv)
		}

	default:
		return "", "", fmt.Errorf("unsupported kty %q", jsonWebKey.Kty)
	}
}

func ecCodeAndCurve(ecCurve string) (uint64, elliptic.Curve, error) {
	var (
		curve elliptic.Curve
		code  uint64
	)

	switch ecCurve {
	case elliptic.P256().Params().Name, "NIST_P256":
		curve = elliptic.P256()
		code = fingerprint.P256PubKeyMultiCodec
	case elliptic.P384().Params().Name, "NIST_P384":
		curve = elliptic.P384()
		code = fingerprint.P384PubKeyMultiCodec
	case elliptic.P521().Params().Name, "NIST_P521":
		curve = elliptic.P521()
		code = fingerprint.P521PubKeyMultiCodec
	default:
		return 0, nil, fmt.Errorf("unsupported crv %s", ecCurve)
	}

	return code, curve, nil
}
