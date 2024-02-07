/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwksupport

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/trustbloc/bbs-signature-go/bbs12381g2pub"
	"github.com/trustbloc/kms-go/util/cryptoutil"

	"github.com/trustbloc/did-go/doc/jose/jwk"
)

const (
	ecKty          = "EC"
	okpKty         = "OKP"
	x25519Crv      = "X25519"
	ed25519Crv     = "Ed25519"
	bls12381G2Crv  = "BLS12381_G2"
	bls12381G2Size = 96
)

// FromEdPublicKey creates jwk from ed25519 key.
func FromEdPublicKey(pub ed25519.PublicKey) *jwk.JWK {
	return &jwk.JWK{
		Kty: "OKP",
		Crv: ed25519Crv,
		X:   jwk.NewBuffer(pub),
	}
}

// FromEdPrivateKey creates jwk from ed25519 key.
func FromEdPrivateKey(ed ed25519.PrivateKey) *jwk.JWK {
	raw := FromEdPublicKey(ed25519.PublicKey(ed[32:]))
	raw.D = jwk.NewBuffer(ed[0:32])

	return raw
}

// JWKFromX25519Key creates jwk from x25519 key.
func JWKFromX25519Key(pubKey []byte) (*jwk.JWK, error) {
	if len(pubKey) != cryptoutil.Curve25519KeySize {
		return nil, errors.New("JWKFromX25519Key: invalid key")
	}

	return &jwk.JWK{
		Crv: x25519Crv,
		Kty: okpKty,
		X:   jwk.NewFixedSizeBuffer(pubKey, cryptoutil.Curve25519KeySize),
	}, nil
}

// FromEcdsaPubKeyBytes creates jwk from ecdsa public key.
func FromEcdsaPubKeyBytes(curve elliptic.Curve, pubKeyBytes []byte) (*jwk.JWK, error) {
	x, y := elliptic.UnmarshalCompressed(curve, pubKeyBytes)
	if x == nil {
		return nil, fmt.Errorf("error unmarshalling key bytes")
	}

	return FromEcdsaContent(EcdsaContent{
		Curve: curve,
		X:     x,
		Y:     y,
	})
}

// FromBLS12381G2 creates jwk from bbs12381g2 public key.
func FromBLS12381G2(key *bbs12381g2pub.PublicKey) (*jwk.JWK, error) {
	var raw *jwk.JWK

	mKey, err := key.Marshal()
	if err != nil {
		return nil, err
	}

	raw = &jwk.JWK{
		Kty: ecKty,
		Crv: bls12381G2Crv,
		X:   jwk.NewFixedSizeBuffer(mKey, bls12381G2Size),
	}

	return raw, nil
}

// EcdsaContent represent content of ecdsa key.
type EcdsaContent struct {
	Curve elliptic.Curve

	X *big.Int
	Y *big.Int
}

// FromEcdsaContent creates jwk from ecdsa key.
func FromEcdsaContent(content EcdsaContent) (*jwk.JWK, error) {
	name, err := curveName(content.Curve)
	if err != nil {
		return nil, err
	}

	size := curveSize(content.Curve)

	xBytes := content.X.Bytes()
	yBytes := content.Y.Bytes()

	if len(xBytes) > size || len(yBytes) > size {
		return nil, fmt.Errorf("go-jose/go-jose: invalid EC key (X/Y too large)")
	}

	key := &jwk.JWK{
		Kty: "EC",
		Crv: name,
		X:   jwk.NewFixedSizeBuffer(xBytes, size),
		Y:   jwk.NewFixedSizeBuffer(yBytes, size),
	}

	return key, nil
}

// Get JOSE name of curve.
func curveName(crv elliptic.Curve) (string, error) {
	switch crv {
	case elliptic.P256():
		return "P-256", nil
	case elliptic.P384():
		return "P-384", nil
	case elliptic.P521():
		return "P-521", nil
	default:
		return "", fmt.Errorf("unsupported/unknown elliptic curve")
	}
}

// Get size of curve in bytes.
func curveSize(crv elliptic.Curve) int {
	bits := crv.Params().BitSize

	div := bits / 8
	mod := bits % 8

	if mod == 0 {
		return div
	}

	return div + 1
}
