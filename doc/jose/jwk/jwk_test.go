/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwk_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/did-go/crypto-ext/jwksupport"
	"github.com/trustbloc/did-go/doc/jose/jwk"
)

func TestJWK_KeyType(t *testing.T) {
	t.Run("success: get KeyType from JWK", func(t *testing.T) {
		testCases := []struct {
			jwk     string
			keyType kms.KeyType
		}{
			{
				jwk: `{
					"kty": "OKP",
					"use": "enc",
					"crv": "Ed25519",
					"kid": "sample@sample.id",
					"x": "sEHL6KXs8bUz9Ss2qSWWjhhRMHVjrog0lzFENM132R8",
					"alg": "EdDSA"
				}`,
				keyType: kms.ED25519Type,
			},
			{
				jwk: `{
					"kty": "OKP",
					"use": "enc",
					"crv": "X25519",
					"kid": "sample@sample.id",
					"x": "sEHL6KXs8bUz9Ss2qSWWjhhRMHVjrog0lzFENM132R8"
				}`,
				keyType: kms.X25519ECDHKWType,
			},
			{
				jwk: `{
					"kty": "EC",
					"use": "enc",
					"crv": "P-256",
					"kid": "sample@sample.id",
					"x": "JR7nhI47w7bxrNkp7Xt1nbmozNn-RB2Q-PWi7KHT8J0",
					"y": "iXmKtH0caOgB1vV0CQwinwK999qdDvrssKhdbiAz9OI",
					"alg": "ES256"
				}`,
				keyType: kms.ECDSAP256TypeIEEEP1363,
			},
			{
				jwk: `{
					"kty": "EC",
					"kid": "sample@sample.id",
					"crv": "P-384",
					"x": "SNJT8Q-irydV5yppI-blGNuRTPf8sCYuL_tO92SLrufdlEgDll9cRuBLACrlBz2x",
					"y": "zIYfra2_y2hnc35sIwA1jiDx5rKmG3mX6162HkAodTJIpUYxw2rz1qHiwVcaU2tY",
					"alg": "ES384"
				}`,
				keyType: kms.ECDSAP384TypeIEEEP1363,
			},
			{
				jwk: `{
					"kty": "EC",
					"kid": "sample@sample.id",
					"crv": "P-521",
					"d": "AfcmEHp9Nd_X005hBoKEs8bvMzIH0OMYodQUw8xRWpUGOq31cyXV1dUvX-S8uSaBIbh2w-fy_OaolBmvTe3Il5Rw",
					"x": "AMIjmQpOT7oz5e8CJZQVi3cxCdF0gdmnNE8qmi5Y3_1-6gRzHoaXGs_TBcAvNgD8UCYhk3FWA8aLChJ9BjEUi44m",
					"y": "AIfNzFdbyI1rfRrcY7orl3wTXT-C_kWhyWdr3K3rSS8WbwXhqg9jb29iEoE8izpCnuoJbC_FsMf2WbI_1iNomfB4",
					"alg": "ES512"
				}`,
				keyType: kms.ECDSAP521TypeIEEEP1363,
			},
		}

		t.Parallel()

		for _, testCase := range testCases {
			t.Run(fmt.Sprintf("KeyType %s", testCase.keyType), func(t *testing.T) {
				j := &jwk.JWK{}
				e := json.Unmarshal([]byte(testCase.jwk), j)
				require.NoError(t, e)

				_, _, e = jwksupport.CreateDIDKeyByJwk(j)
				require.NoError(t, e)

				mJWK, err := json.Marshal(j)
				require.NoError(t, err)
				require.NotEmpty(t, mJWK)
			})
		}
	})

	t.Run("test ed25519 with []byte key material", func(t *testing.T) {
		jwkJSON := `{
			"kty": "OKP",
			"use": "enc",
			"crv": "Ed25519",
			"kid": "sample@sample.id",
			"x": "sEHL6KXs8bUz9Ss2qSWWjhhRMHVjrog0lzFENM132R8",
			"alg": "EdDSA"
		}`

		j := &jwk.JWK{}
		e := json.Unmarshal([]byte(jwkJSON), j)
		require.NoError(t, e)
	})

	t.Run("test secp256k1 with []byte key material", func(t *testing.T) {
		jwkJSON := `{
			"kty": "EC",
			"use": "enc",
			"crv": "secp256k1",
			"kid": "sample@sample.id",
			"x": "YRrvJocKf39GpdTnd-zBFE0msGDqawR-Cmtc6yKoFsM",
			"y": "kE-dMH9S3mxnTXo0JFEhraCU_tVYFDfpu9tpP1LfVKQ",
			"alg": "ES256K"
		}`

		j := &jwk.JWK{}
		e := json.Unmarshal([]byte(jwkJSON), j)
		require.NoError(t, e)
	})
}

func TestNewFixedSizeBuffer(t *testing.T) {
	data := make([]byte, 32)
	require.Len(t, jwk.NewFixedSizeBuffer(data, 48).Bytes(), 48)
}

func TestByteBufferUnmarshal(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		bb := &jwk.ByteBuffer{}
		err := bb.UnmarshalJSON([]byte("\"YRrvJocKf39GpdTnd-zBFE0msGDqawR-Cmtc6yKoFsM\""))

		require.NoError(t, err)
		require.Len(t, bb.Bytes(), 32)
	})

	t.Run("Empty", func(t *testing.T) {
		bb := &jwk.ByteBuffer{}
		err := bb.UnmarshalJSON([]byte("\"\""))

		require.NoError(t, err)
		require.Empty(t, bb.Bytes())
	})

	t.Run("Failure", func(t *testing.T) {
		bb := &jwk.ByteBuffer{}
		err := bb.UnmarshalJSON([]byte("{"))
		require.Error(t, err)
	})

	t.Run("Failure2", func(t *testing.T) {
		bb := &jwk.ByteBuffer{}
		err := bb.UnmarshalJSON([]byte("\"{\""))
		require.Error(t, err)
	})
}
