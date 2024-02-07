/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwksupport_test

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/bbs-signature-go/bbs12381g2pub"

	"github.com/trustbloc/did-go/crypto-ext/jwksupport"
	"github.com/trustbloc/did-go/doc/jose/jwk"
)

const (
	ecP256PubKeyBase58 = "23youFZZdHMVdpv28DRSWP2zJbTJ8KHBeSKUX3qVqqnmp"
	ecP384PubKeyBase58 = "ad1jjx1hRrEkMWSsFsXpLULAbmUq67ii1jRsBNtYEKhCwLXTo4wcjY7C2K4cuGZ859"
	ecP521PubKeyBase58 = "4SsRN7NAk3175KrnPVQn5XTZE49MKdFKiq4XhWdhfx3QEUb2e96A3YLonFC6B21sa4uU776QMxEnxAQP6GWko8f3aNV"
	x25519KeyBase64    = "egRLO+ygwW/VNHjQhZiHw1vhHwVj4KmzeRnKIEDz6gE="
)

func TestFromEdPublicKey(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwk := jwksupport.FromEdPublicKey(pubKey)

	_, _, err = jwksupport.CreateDIDKeyByJwk(jwk)
	require.NoError(t, err)
}

func TestFromEdPrivateKey(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwk := jwksupport.FromEdPrivateKey(privKey)
	require.NotEmpty(t, jwk.X.Bytes())
}

func TestJWKFromX25519Key(t *testing.T) {
	keyBytes, err := base64.StdEncoding.DecodeString(x25519KeyBase64)
	require.NoError(t, err)

	jwk, err := jwksupport.JWKFromX25519Key(keyBytes)
	require.NoError(t, err)

	_, _, err = jwksupport.CreateDIDKeyByJwk(jwk)
	require.NoError(t, err)

	t.Run("Failure", func(t *testing.T) {
		_, err = jwksupport.JWKFromX25519Key([]byte{})
		require.ErrorContains(t, err, "invalid key")
	})
}

func TestFromEcdsaPubKeyBytes(t *testing.T) {
	t.Run("P256", func(t *testing.T) {
		jwk, err := jwksupport.FromEcdsaPubKeyBytes(elliptic.P256(), base58.Decode(ecP256PubKeyBase58))
		require.NoError(t, err)

		_, _, err = jwksupport.CreateDIDKeyByJwk(jwk)
		require.NoError(t, err)
	})

	t.Run("P384", func(t *testing.T) {
		jwk, err := jwksupport.FromEcdsaPubKeyBytes(elliptic.P384(), base58.Decode(ecP384PubKeyBase58))
		require.NoError(t, err)

		_, _, err = jwksupport.CreateDIDKeyByJwk(jwk)
		require.NoError(t, err)
	})

	t.Run("P521", func(t *testing.T) {
		jwk, err := jwksupport.FromEcdsaPubKeyBytes(elliptic.P521(), base58.Decode(ecP521PubKeyBase58))
		require.NoError(t, err)

		_, _, err = jwksupport.CreateDIDKeyByJwk(jwk)
		require.NoError(t, err)
	})

	t.Run("Failure", func(t *testing.T) {
		_, err := jwksupport.FromEcdsaPubKeyBytes(elliptic.P256(), []byte{})
		require.ErrorContains(t, err, "error unmarshalling key bytes")

		_, err = jwksupport.FromEcdsaContent(jwksupport.EcdsaContent{Curve: elliptic.P224()})
		require.ErrorContains(t, err, "unsupported/unknown elliptic curve")
	})
}

func TestFromBLS12381G2(t *testing.T) {
	bbsPubKey, _, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
	require.NoError(t, err)

	jwk, err := jwksupport.FromBLS12381G2(bbsPubKey)
	require.NoError(t, err)
	require.NotEmpty(t, jwk.X.Bytes())
}

func TestCreateDIDKeyByJwk(t *testing.T) {
	t.Run("Failure", func(t *testing.T) {
		_, _, err := jwksupport.CreateDIDKeyByJwk(&jwk.JWK{
			Kty: "OKP",
		})
		require.ErrorContains(t, err, "unsupported kty \"OKP\" and crv \"\" combination")

		_, _, err = jwksupport.CreateDIDKeyByJwk(&jwk.JWK{})

		require.ErrorContains(t, err, "unsupported kty \"\"")

		_, _, err = jwksupport.CreateDIDKeyByJwk(&jwk.JWK{
			Kty: "OKP",
			Crv: "X25519",
			X:   jwk.NewBuffer([]byte{}),
		})
		require.ErrorContains(t, err, "invalid JWK")

		_, _, err = jwksupport.CreateDIDKeyByJwk(&jwk.JWK{
			Kty: "OKP",
			Crv: "Ed25519",
		})
		require.ErrorContains(t, err, "invalid Ed key")

		_, _, err = jwksupport.CreateDIDKeyByJwk(&jwk.JWK{
			Kty: "EC",
			Crv: "Ed25519",
		})
		require.ErrorContains(t, err, "unsupported crv Ed25519")
	})
}
