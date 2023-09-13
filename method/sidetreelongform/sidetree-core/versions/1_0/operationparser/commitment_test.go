/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operationparser

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/api/protocol"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/commitment"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/mocks"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/patch"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/util/ecsigner"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/util/pubkey"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/versions/1_0/client"
)

func TestParser_GetCommitment(t *testing.T) {
	p := mocks.NewMockProtocolClient()

	parser := New(p.Protocol)

	recoveryKey, _, err := generateKeyAndCommitment(p.Protocol)
	require.NoError(t, err)

	updateKey, _, err := generateKeyAndCommitment(p.Protocol)
	require.NoError(t, err)

	_, recoveryCommitment, err := generateKeyAndCommitment(p.Protocol)
	require.NoError(t, err)

	_, updateCommitment, err := generateKeyAndCommitment(p.Protocol)
	require.NoError(t, err)

	t.Run("success - recoverRequest", func(t *testing.T) {
		recoverRequest, err := generateRecoverRequest(recoveryKey, recoveryCommitment, parser.Protocol)
		require.NoError(t, err)

		c, err := parser.GetCommitment(recoverRequest)
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, c, recoveryCommitment)
	})

	t.Run("success - deactivate", func(t *testing.T) {
		deactivate, err := generateDeactivateRequest(recoveryKey)
		require.NoError(t, err)

		c, err := parser.GetCommitment(deactivate)
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, c, "")
	})

	t.Run("success - update", func(t *testing.T) {
		update, err := generateUpdateRequest(updateKey, updateCommitment, parser.Protocol)
		require.NoError(t, err)

		c, err := parser.GetCommitment(update)
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, c, updateCommitment)
	})

	t.Run("success - update", func(t *testing.T) {
		update, err := generateUpdateRequest(updateKey, updateCommitment, parser.Protocol)
		require.NoError(t, err)

		c, err := parser.GetCommitment(update)
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, c, updateCommitment)
	})

	t.Run("error - create", func(t *testing.T) {
		create, err := generateCreateRequest(recoveryCommitment, updateCommitment, parser.Protocol)
		require.NoError(t, err)

		c, err := parser.GetCommitment(create)
		require.Error(t, err)
		require.Empty(t, c)
		require.Contains(t, err.Error(), "operation type 'create' not supported for getting next operation commitment")
	})

	t.Run("error - parse operation fails", func(t *testing.T) {
		c, err := parser.GetCommitment([]byte(`{"type":"other"}`))
		require.Error(t, err)
		require.Empty(t, c)
		require.Contains(t, err.Error(), "get commitment - parse operation error")
	})
}

func TestParser_GetRevealValue(t *testing.T) {
	p := mocks.NewMockProtocolClient()

	parser := New(p.Protocol)

	recoveryKey, _, err := generateKeyAndCommitment(p.Protocol)
	require.NoError(t, err)

	updateKey, _, err := generateKeyAndCommitment(p.Protocol)
	require.NoError(t, err)

	_, recoveryCommitment, err := generateKeyAndCommitment(p.Protocol)
	require.NoError(t, err)

	_, updateCommitment, err := generateKeyAndCommitment(p.Protocol)
	require.NoError(t, err)

	t.Run("success - recoverRequest", func(t *testing.T) {
		recoverRequest, err := generateRecoverRequest(recoveryKey, recoveryCommitment, parser.Protocol)
		require.NoError(t, err)

		rv, err := parser.GetRevealValue(recoverRequest)
		require.NoError(t, err)
		require.NotEmpty(t, rv)

		pubJWK, err := pubkey.GetPublicKeyJWK(&recoveryKey.PublicKey)
		require.NoError(t, err)

		expected, err := commitment.GetRevealValue(pubJWK, parser.Protocol.MultihashAlgorithms[0])
		require.NoError(t, err)

		require.Equal(t, rv, expected)
	})

	t.Run("success - deactivate", func(t *testing.T) {
		deactivate, err := generateDeactivateRequest(recoveryKey)
		require.NoError(t, err)

		rv, err := parser.GetRevealValue(deactivate)
		require.NoError(t, err)
		require.NotEmpty(t, rv)

		pubJWK, err := pubkey.GetPublicKeyJWK(&recoveryKey.PublicKey)
		require.NoError(t, err)

		expected, err := commitment.GetRevealValue(pubJWK, parser.Protocol.MultihashAlgorithms[0])
		require.NoError(t, err)

		require.Equal(t, rv, expected)
	})

	t.Run("success - update", func(t *testing.T) {
		update, err := generateUpdateRequest(updateKey, updateCommitment, parser.Protocol)
		require.NoError(t, err)

		rv, err := parser.GetRevealValue(update)
		require.NoError(t, err)
		require.NotEmpty(t, rv)

		pubJWK, err := pubkey.GetPublicKeyJWK(&updateKey.PublicKey)
		require.NoError(t, err)

		expected, err := commitment.GetRevealValue(pubJWK, parser.Protocol.MultihashAlgorithms[0])
		require.NoError(t, err)

		require.Equal(t, rv, expected)
	})

	t.Run("error - create", func(t *testing.T) {
		create, err := generateCreateRequest(recoveryCommitment, updateCommitment, parser.Protocol)
		require.NoError(t, err)

		c, err := parser.GetRevealValue(create)
		require.Error(t, err)
		require.Empty(t, c)
		require.Contains(t, err.Error(), "operation type 'create' not supported for getting operation reveal value")
	})

	t.Run("error - parse operation fails", func(t *testing.T) {
		c, err := parser.GetRevealValue([]byte(`{"type":"other"}`))
		require.Error(t, err)
		require.Empty(t, c)
		require.Contains(t, err.Error(), "get reveal value - parse operation error")
	})
}

func generateRecoverRequest(
	recoveryKey *ecdsa.PrivateKey, recoveryCommitment string, p protocol.Protocol) ([]byte, error) {
	jwk, err := pubkey.GetPublicKeyJWK(&recoveryKey.PublicKey)
	if err != nil {
		return nil, err
	}

	_, updateCommitment, err := generateKeyAndCommitment(p)
	if err != nil {
		return nil, err
	}

	rv, err := commitment.GetRevealValue(jwk, sha2_256)
	if err != nil {
		return nil, err
	}

	info := &client.RecoverRequestInfo{
		DidSuffix:          "recoverRequest-suffix",
		OpaqueDocument:     `{"test":"value"}`,
		RecoveryCommitment: recoveryCommitment,
		UpdateCommitment:   updateCommitment, // not evaluated in operation getting commitment/reveal value
		RecoveryKey:        jwk,
		MultihashCode:      p.MultihashAlgorithms[0],
		Signer:             ecsigner.New(recoveryKey, "ES256", ""),
		RevealValue:        rv,
	}

	return client.NewRecoverRequest(info)
}

func generateCreateRequest(recoveryCommitment, updateCommitment string, p protocol.Protocol) ([]byte, error) {
	info := &client.CreateRequestInfo{
		OpaqueDocument:     `{"test":"value"}`,
		RecoveryCommitment: recoveryCommitment,
		UpdateCommitment:   updateCommitment,
		MultihashCode:      p.MultihashAlgorithms[0],
	}

	return client.NewCreateRequest(info)
}

func generateDeactivateRequest(recoveryKey *ecdsa.PrivateKey) ([]byte, error) {
	jwk, err := pubkey.GetPublicKeyJWK(&recoveryKey.PublicKey)
	if err != nil {
		return nil, err
	}

	rv, err := commitment.GetRevealValue(jwk, sha2_256)
	if err != nil {
		return nil, err
	}

	info := &client.DeactivateRequestInfo{
		DidSuffix:   "deactivate-suffix",
		Signer:      ecsigner.New(recoveryKey, "ES256", ""),
		RecoveryKey: jwk,
		RevealValue: rv,
	}

	return client.NewDeactivateRequest(info)
}

func generateUpdateRequest(updateKey *ecdsa.PrivateKey, updateCommitment string, p protocol.Protocol) ([]byte, error) {
	jwk, err := pubkey.GetPublicKeyJWK(&updateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	testPatch, err := patch.NewJSONPatch(`[{"op": "replace", "path": "/name", "value": "Jane"}]`)
	if err != nil {
		return nil, err
	}

	rv, err := commitment.GetRevealValue(jwk, sha2_256)
	if err != nil {
		return nil, err
	}

	info := &client.UpdateRequestInfo{
		DidSuffix:        "update-suffix",
		Signer:           ecsigner.New(updateKey, "ES256", ""),
		UpdateCommitment: updateCommitment,
		UpdateKey:        jwk,
		Patches:          []patch.Patch{testPatch},
		MultihashCode:    p.MultihashAlgorithms[0],
		RevealValue:      rv,
	}

	return client.NewUpdateRequest(info)
}

func generateKeyAndCommitment(p protocol.Protocol) (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}

	pubKey, err := pubkey.GetPublicKeyJWK(&key.PublicKey)
	if err != nil {
		return nil, "", err
	}

	c, err := commitment.GetCommitment(pubKey, p.MultihashAlgorithms[0])
	if err != nil {
		return nil, "", err
	}

	return key, c, nil
}
