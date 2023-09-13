/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/commitment"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/jws"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/patch"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/util/ecsigner"
)

func TestNewUpdateRequest(t *testing.T) {
	const didSuffix = "whatever"

	patches, err := getTestPatches()
	require.NoError(t, err)

	updateJWK := &jws.JWK{
		Crv: "crv",
		Kty: "kty",
		X:   "x",
	}

	signer := NewMockSigner(nil)

	t.Run("missing unique suffix", func(t *testing.T) {
		info := &UpdateRequestInfo{}

		request, err := NewUpdateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing did unique suffix")
	})
	t.Run("missing reveal value", func(t *testing.T) {
		info := &UpdateRequestInfo{DidSuffix: didSuffix}

		request, err := NewUpdateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing reveal value")
	})
	t.Run("missing json patch", func(t *testing.T) {
		info := &UpdateRequestInfo{DidSuffix: didSuffix, RevealValue: "reveal"}

		request, err := NewUpdateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing update information")
	})
	t.Run("multihash not supported", func(t *testing.T) {
		info := &UpdateRequestInfo{
			DidSuffix:   didSuffix,
			Patches:     patches,
			UpdateKey:   updateJWK,
			Signer:      signer,
			RevealValue: "reveal",
		}

		request, err := NewUpdateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "algorithm not supported")
	})
	t.Run("missing update key", func(t *testing.T) {
		signer = NewMockSigner(nil)
		signer.MockHeaders = make(jws.Headers)

		info := &UpdateRequestInfo{
			DidSuffix:     didSuffix,
			Patches:       patches,
			MultihashCode: sha2_256,
			Signer:        signer,
			RevealValue:   "reveal",
		}

		request, err := NewUpdateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "missing update key")
	})
	t.Run("algorithm must be present in the protected header", func(t *testing.T) {
		signer = NewMockSigner(nil)
		signer.MockHeaders = make(jws.Headers)

		info := &UpdateRequestInfo{
			DidSuffix:     didSuffix,
			Patches:       patches,
			MultihashCode: sha2_256,
			UpdateKey:     updateJWK,
			Signer:        signer,
			RevealValue:   "reveal",
		}

		request, err := NewUpdateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "algorithm must be present in the protected header")
	})
	t.Run("signing error", func(t *testing.T) {
		info := &UpdateRequestInfo{
			DidSuffix:     didSuffix,
			Patches:       patches,
			MultihashCode: sha2_256,
			UpdateKey:     updateJWK,
			Signer:        NewMockSigner(errors.New(signerErr)),
			RevealValue:   "reveal",
		}

		request, err := NewUpdateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), signerErr)
	})
	t.Run("error - re-using public keys for commitment is not allowed", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signer := ecsigner.New(privateKey, "ES256", "key-1")

		currentCommitment, err := commitment.GetCommitment(updateJWK, sha2_256)
		require.NoError(t, err)

		info := &UpdateRequestInfo{
			DidSuffix:        didSuffix,
			Patches:          patches,
			MultihashCode:    sha2_256,
			UpdateKey:        updateJWK,
			UpdateCommitment: currentCommitment,
			Signer:           signer,
			RevealValue:      "reveal",
		}

		request, err := NewUpdateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "re-using public keys for commitment is not allowed")
	})
	t.Run("success", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signer := ecsigner.New(privateKey, "ES256", "key-1")

		info := &UpdateRequestInfo{
			DidSuffix:     didSuffix,
			Patches:       patches,
			MultihashCode: sha2_256,
			UpdateKey:     updateJWK,
			Signer:        signer,
			RevealValue:   "reveal",
		}

		request, err := NewUpdateRequest(info)
		require.NoError(t, err)
		require.NotEmpty(t, request)
	})
}

func getTestPatches() ([]patch.Patch, error) {
	p, err := patch.NewJSONPatch(`[{"op": "replace", "path": "/name", "value": "Jane"}]`)
	if err != nil {
		return nil, err
	}

	return []patch.Patch{p}, nil
}
