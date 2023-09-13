/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jws

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/json"
	"golang.org/x/crypto/ed25519"
)

const (
	secp256k1Crv  = "secp256k1"
	secp256k1Kty  = "EC"
	secp256k1Size = 32
	bitsPerByte   = 8
)

// JWK (JSON Web Key) is a JSON data structure that represents a cryptographic key.
type JWK struct {
	jose.JSONWebKey

	Kty string
	Crv string
}

// PublicKeyBytes converts a public key to bytes.
func (j *JWK) PublicKeyBytes() ([]byte, error) {
	if isSecp256k1(j.Kty, j.Crv) {
		var ecPubKey *ecdsa.PublicKey

		ecPubKey, ok := j.Key.(*ecdsa.PublicKey)
		if !ok {
			ecPubKey = &j.Key.(*ecdsa.PrivateKey).PublicKey
		}

		pubKey := &btcec.PublicKey{
			Curve: btcec.S256(),
			X:     ecPubKey.X,
			Y:     ecPubKey.Y,
		}

		return pubKey.SerializeCompressed(), nil
	}

	switch pubKey := j.Public().Key.(type) {
	case *ecdsa.PublicKey, ed25519.PublicKey:
		pubKBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return nil, errors.New("failed to read public key bytes")
		}

		return pubKBytes, nil
	default:
		return nil, fmt.Errorf("unsupported public key type in kid '%s'", j.KeyID)
	}
}

// UnmarshalJSON reads a key from its JSON representation.
func (j *JWK) UnmarshalJSON(jwkBytes []byte) error {
	var key jsonWebKey

	marshalErr := json.Unmarshal(jwkBytes, &key)
	if marshalErr != nil {
		return fmt.Errorf("unable to read JWK: %w", marshalErr)
	}

	if isSecp256k1(key.Kty, key.Crv) {
		jwk, err := unmarshalSecp256k1(&key)
		if err != nil {
			return fmt.Errorf("unable to read JWK: %w", err)
		}

		*j = *jwk
	} else {
		var joseJWK jose.JSONWebKey

		err := json.Unmarshal(jwkBytes, &joseJWK)
		if err != nil {
			return fmt.Errorf("unable to read jose JWK, %w", err)
		}

		j.JSONWebKey = joseJWK
	}

	j.Kty = key.Kty
	j.Crv = key.Crv

	return nil
}

// MarshalJSON serializes the given key to its JSON representation.
func (j *JWK) MarshalJSON() ([]byte, error) {
	if isSecp256k1(j.Kty, j.Crv) {
		return marshalSecp256k1(j)
	}

	return (&j.JSONWebKey).MarshalJSON()
}

func isSecp256k1(kty, crv string) bool {
	return strings.EqualFold(kty, secp256k1Kty) && strings.EqualFold(crv, secp256k1Crv)
}

func unmarshalSecp256k1(jwk *jsonWebKey) (*JWK, error) {
	if jwk.X == nil {
		return nil, ErrInvalidKey
	}

	if jwk.Y == nil {
		return nil, ErrInvalidKey
	}

	curve := btcec.S256()

	if curveSize(curve) != len(jwk.X.data) {
		return nil, ErrInvalidKey
	}

	if curveSize(curve) != len(jwk.Y.data) {
		return nil, ErrInvalidKey
	}

	if jwk.D != nil && dSize(curve) != len(jwk.D.data) {
		return nil, ErrInvalidKey
	}

	x := jwk.X.bigInt()
	y := jwk.Y.bigInt()

	if !curve.IsOnCurve(x, y) {
		return nil, ErrInvalidKey
	}

	var key interface{}

	if jwk.D != nil {
		key = &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: curve,
				X:     x,
				Y:     y,
			},
			D: jwk.D.bigInt(),
		}
	} else {
		key = &ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}
	}

	return &JWK{
		JSONWebKey: jose.JSONWebKey{
			Key: key, KeyID: jwk.Kid, Algorithm: jwk.Alg, Use: jwk.Use,
		},
	}, nil
}

func marshalSecp256k1(jwk *JWK) ([]byte, error) {
	var raw jsonWebKey

	switch ecdsaKey := jwk.Key.(type) {
	case *ecdsa.PublicKey:
		raw = jsonWebKey{
			Kty: secp256k1Kty,
			Crv: secp256k1Crv,
			X:   newFixedSizeBuffer(ecdsaKey.X.Bytes(), secp256k1Size),
			Y:   newFixedSizeBuffer(ecdsaKey.Y.Bytes(), secp256k1Size),
		}

	case *ecdsa.PrivateKey:
		raw = jsonWebKey{
			Kty: secp256k1Kty,
			Crv: secp256k1Crv,
			X:   newFixedSizeBuffer(ecdsaKey.X.Bytes(), secp256k1Size),
			Y:   newFixedSizeBuffer(ecdsaKey.Y.Bytes(), secp256k1Size),
			D:   newFixedSizeBuffer(ecdsaKey.D.Bytes(), dSize(ecdsaKey.Curve)),
		}
	}

	raw.Kid = jwk.KeyID
	raw.Alg = jwk.Algorithm
	raw.Use = jwk.Use

	return json.Marshal(raw)
}

// jsonWebKey contains subset of json web key json properties.
type jsonWebKey struct {
	Use string `json:"use,omitempty"`
	Kty string `json:"kty,omitempty"`
	Kid string `json:"kid,omitempty"`
	Crv string `json:"crv,omitempty"`
	Alg string `json:"alg,omitempty"`

	X *byteBuffer `json:"x,omitempty"`
	Y *byteBuffer `json:"y,omitempty"`

	D *byteBuffer `json:"d,omitempty"`
}

// Get size of curve in bytes.
func curveSize(crv elliptic.Curve) int {
	bits := crv.Params().BitSize

	div := bits / bitsPerByte
	mod := bits % bitsPerByte

	if mod == 0 {
		return div
	}

	return div + 1
}

func dSize(curve elliptic.Curve) int {
	order := curve.Params().P
	bitLen := order.BitLen()
	size := bitLen / bitsPerByte

	if bitLen%bitsPerByte != 0 {
		size++
	}

	return size
}

// byteBuffer represents a slice of bytes that can be serialized to url-safe base64.
type byteBuffer struct {
	data []byte
}

func (b *byteBuffer) UnmarshalJSON(data []byte) error {
	var encoded string

	err := json.Unmarshal(data, &encoded)
	if err != nil {
		return err
	}

	if encoded == "" {
		return nil
	}

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}

	*b = byteBuffer{
		data: decoded,
	}

	return nil
}

func (b *byteBuffer) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.base64())
}

func (b *byteBuffer) base64() string {
	return base64.RawURLEncoding.EncodeToString(b.data)
}

func (b byteBuffer) bigInt() *big.Int {
	return new(big.Int).SetBytes(b.data)
}

func newFixedSizeBuffer(data []byte, length int) *byteBuffer {
	paddedData := make([]byte, length-len(data))

	return &byteBuffer{
		data: append(paddedData, data...),
	}
}

// ErrInvalidKey is returned when passed JWK is invalid.
var ErrInvalidKey = errors.New("invalid JWK")
