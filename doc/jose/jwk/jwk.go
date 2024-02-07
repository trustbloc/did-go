/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwk

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
)

const (
	bitsPerByte = 8
)

// JWK represents a public or private key in JWK format, used for parsing/serializing.
type JWK struct {
	Use   string      `json:"use,omitempty"`
	Kty   string      `json:"kty,omitempty"`
	KeyID string      `json:"kid,omitempty"`
	Crv   string      `json:"crv,omitempty"`
	Alg   string      `json:"alg,omitempty"`
	K     *ByteBuffer `json:"k,omitempty"`
	X     *ByteBuffer `json:"x,omitempty"`
	Y     *ByteBuffer `json:"y,omitempty"`
	N     *ByteBuffer `json:"n,omitempty"`
	E     *ByteBuffer `json:"e,omitempty"`
	// -- Following fields are only used for private keys --
	// RSA uses D, P and Q, while ECDSA uses only D. Fields Dp, Dq, and Qi are
	// completely optional. Therefore for RSA/ECDSA, D != nil is a contract that
	// we have a private key whereas D == nil means we have only a public key.
	D  *ByteBuffer `json:"d,omitempty"`
	P  *ByteBuffer `json:"p,omitempty"`
	Q  *ByteBuffer `json:"q,omitempty"`
	Dp *ByteBuffer `json:"dp,omitempty"`
	Dq *ByteBuffer `json:"dq,omitempty"`
	Qi *ByteBuffer `json:"qi,omitempty"`
	// Certificates
	X5c       []string `json:"x5c,omitempty"`
	X5u       string   `json:"x5u,omitempty"`
	X5tSHA1   string   `json:"x5t,omitempty"`
	X5tSHA256 string   `json:"x5t#S256,omitempty"`
}

// Get size of curve in Bytes.
func curveSize(crv elliptic.Curve) int {
	bits := crv.Params().BitSize

	div := bits / bitsPerByte
	mod := bits % bitsPerByte

	if mod == 0 {
		return div
	}

	return div + 1
}

// ByteBuffer represents a slice of Bytes that can be serialized to url-safe Base64.
type ByteBuffer struct {
	data []byte
}

// NewBuffer creates new ByteBuffer from given bytes.
func NewBuffer(data []byte) *ByteBuffer {
	return &ByteBuffer{
		data: data,
	}
}

// NewFixedSizeBuffer creates new ByteBuffer with fixed size.
func NewFixedSizeBuffer(data []byte, length int) *ByteBuffer {
	if len(data) > length {
		panic("go-jose/go-jose: invalid call to newFixedSizeBuffer (len(data) > length)")
	}

	pad := make([]byte, length-len(data))

	return NewBuffer(append(pad, data...))
}

// MarshalJSON serialize buffer data into json.
func (b *ByteBuffer) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.base64())
}

// UnmarshalJSON deserialize buffer data from json.
func (b *ByteBuffer) UnmarshalJSON(data []byte) error {
	var encoded string

	err := json.Unmarshal(data, &encoded)
	if err != nil {
		return err
	}

	if encoded == "" {
		return nil
	}

	decoded, err := base64URLDecode(encoded)
	if err != nil {
		return err
	}

	*b = *NewBuffer(decoded)

	return nil
}

func (b *ByteBuffer) base64() string {
	return base64.RawURLEncoding.EncodeToString(b.data)
}

// Bytes returns buffer bytes.
func (b *ByteBuffer) Bytes() []byte {
	return b.data
}

// BigInt construct BigInt from data bytes.
func (b *ByteBuffer) BigInt() *big.Int {
	return new(big.Int).SetBytes(b.data)
}

// base64URLDecode is implemented as defined in https://www.rfc-editor.org/rfc/rfc7515.html#appendix-C
func base64URLDecode(value string) ([]byte, error) {
	value = strings.TrimRight(value, "=")
	return base64.RawURLEncoding.DecodeString(value)
}

// ErrInvalidKey is returned when passed JWK is invalid.
var ErrInvalidKey = errors.New("invalid JWK")
