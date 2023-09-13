/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metadata

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/api/operation"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/api/protocol"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/document"
)

const (
	testDID     = "did:abc:123"
	canonicalID = "canonical"
)

func TestPopulateDocumentMetadata(t *testing.T) {
	doc, err := document.FromBytes(validDoc)
	require.NoError(t, err)

	createdTimeStr := "2020-12-20T19:17:47Z"
	updatedTimeStr := "2022-12-20T19:17:47Z"

	createdTime, err := time.Parse(time.RFC3339, createdTimeStr)
	require.NoError(t, err)

	updatedTime, err := time.Parse(time.RFC3339, updatedTimeStr)
	require.NoError(t, err)

	internal := &protocol.ResolutionModel{
		Doc:                doc,
		RecoveryCommitment: "recovery",
		UpdateCommitment:   "update",
		AnchorOrigin:       "origin.com",
		VersionID:          "version",
		CreatedTime:        uint64(createdTime.Unix()),
		UpdatedTime:        uint64(updatedTime.Unix()),
	}

	t.Run("success - all info present", func(t *testing.T) {
		info := make(protocol.TransformationInfo)
		info[document.IDProperty] = testDID
		info[document.PublishedProperty] = true
		info[document.CanonicalIDProperty] = canonicalID
		info[document.EquivalentIDProperty] = []string{"equivalent"}
		info[document.AnchorOriginProperty] = "domain.com"
		info[document.DeactivatedProperty] = true

		documentMetadata, err := New(WithIncludeUnpublishedOperations(true),
			WithIncludePublishedOperations(true)).CreateDocumentMetadata(internal, info)
		require.NoError(t, err)

		require.Empty(t, documentMetadata[document.DeactivatedProperty])
		require.Equal(t, canonicalID, documentMetadata[document.CanonicalIDProperty])
		require.NotEmpty(t, documentMetadata[document.EquivalentIDProperty])

		require.Equal(t, createdTimeStr, documentMetadata[document.CreatedProperty])
		require.Equal(t, updatedTimeStr, documentMetadata[document.UpdatedProperty])

		methodMetadataEntry, ok := documentMetadata[document.MethodProperty]
		require.True(t, ok)
		methodMetadata, ok := methodMetadataEntry.(document.Metadata)
		require.True(t, ok)

		require.Equal(t, true, methodMetadata[document.PublishedProperty])
		require.Equal(t, "recovery", methodMetadata[document.RecoveryCommitmentProperty])
		require.Equal(t, "update", methodMetadata[document.UpdateCommitmentProperty])
	})

	t.Run("success - include operations (published/unpublished)", func(t *testing.T) {
		info := make(protocol.TransformationInfo)
		info[document.IDProperty] = testDID
		info[document.PublishedProperty] = true
		info[document.CanonicalIDProperty] = canonicalID
		info[document.EquivalentIDProperty] = []string{"equivalent"}
		info[document.AnchorOriginProperty] = "domain.com"

		publishedOps := []*operation.AnchoredOperation{
			{Type: "create", UniqueSuffix: "suffix", CanonicalReference: "ref1", TransactionTime: 1},
			{Type: "update", UniqueSuffix: "suffix", CanonicalReference: "ref3", TransactionTime: 3},
			{Type: "update", UniqueSuffix: "suffix", CanonicalReference: "ref2", TransactionTime: 2},
			{Type: "update", UniqueSuffix: "suffix", CanonicalReference: "ref2", TransactionTime: 2},
		}

		unpublishedOps := []*operation.AnchoredOperation{
			{Type: "update", UniqueSuffix: "suffix", TransactionTime: 4},
		}

		rm := &protocol.ResolutionModel{
			Doc:                   doc,
			RecoveryCommitment:    "recovery",
			UpdateCommitment:      "update",
			PublishedOperations:   publishedOps,
			UnpublishedOperations: unpublishedOps,
		}

		documentMetadata, err := New(WithIncludeUnpublishedOperations(true),
			WithIncludePublishedOperations(true)).CreateDocumentMetadata(rm, info)
		require.NoError(t, err)

		require.Empty(t, documentMetadata[document.DeactivatedProperty])
		require.Equal(t, canonicalID, documentMetadata[document.CanonicalIDProperty])
		require.NotEmpty(t, documentMetadata[document.EquivalentIDProperty])

		methodMetadataEntry, ok := documentMetadata[document.MethodProperty]
		require.True(t, ok)
		methodMetadata, ok := methodMetadataEntry.(document.Metadata)
		require.True(t, ok)

		require.Equal(t, true, methodMetadata[document.PublishedProperty])
		require.Equal(t, "recovery", methodMetadata[document.RecoveryCommitmentProperty])
		require.Equal(t, "update", methodMetadata[document.UpdateCommitmentProperty])

		require.Equal(t, 3, len(methodMetadata[document.PublishedOperationsProperty].([]*PublishedOperation)))
		require.Equal(t, 1, len(methodMetadata[document.UnpublishedOperationsProperty].([]*UnpublishedOperation)))
	})

	t.Run("success - deactivated, commitments empty", func(t *testing.T) {
		internal2 := &protocol.ResolutionModel{
			Doc:         doc,
			Deactivated: true,
			CreatedTime: uint64(time.Now().Unix() - 60),
			UpdatedTime: uint64(time.Now().Unix()),
			VersionID:   "version",
		}

		info := make(protocol.TransformationInfo)
		info[document.IDProperty] = testDID
		info[document.PublishedProperty] = true
		info[document.CanonicalIDProperty] = canonicalID

		documentMetadata, err := New().CreateDocumentMetadata(internal2, info)
		require.NoError(t, err)

		require.Equal(t, true, documentMetadata[document.DeactivatedProperty])
		require.NotEmpty(t, documentMetadata[document.UpdatedProperty])
		require.NotEmpty(t, documentMetadata[document.CreatedProperty])
		require.Equal(t, canonicalID, documentMetadata[document.CanonicalIDProperty])
		require.Empty(t, documentMetadata[document.EquivalentIDProperty])

		methodMetadataEntry, ok := documentMetadata[document.MethodProperty]
		require.True(t, ok)
		methodMetadata, ok := methodMetadataEntry.(document.Metadata)
		require.True(t, ok)

		require.Equal(t, true, methodMetadata[document.PublishedProperty])
		require.Empty(t, methodMetadata[document.RecoveryCommitmentProperty])
		require.Empty(t, methodMetadata[document.UpdateCommitmentProperty])
	})

	t.Run("success - deactivated, no version ID (unpublished)", func(t *testing.T) {
		internal2 := &protocol.ResolutionModel{
			Doc:         doc,
			Deactivated: true,
			CreatedTime: uint64(time.Now().Unix() - 60),
			UpdatedTime: uint64(time.Now().Unix()),
		}

		info := make(protocol.TransformationInfo)
		info[document.IDProperty] = testDID
		info[document.PublishedProperty] = true
		info[document.CanonicalIDProperty] = canonicalID

		documentMetadata, err := New().CreateDocumentMetadata(internal2, info)
		require.NoError(t, err)

		require.Equal(t, true, documentMetadata[document.DeactivatedProperty])
		require.Empty(t, documentMetadata[document.UpdatedProperty])
		require.NotEmpty(t, documentMetadata[document.CreatedProperty])
		require.Equal(t, canonicalID, documentMetadata[document.CanonicalIDProperty])
		require.Empty(t, documentMetadata[document.EquivalentIDProperty])

		methodMetadataEntry, ok := documentMetadata[document.MethodProperty]
		require.True(t, ok)
		methodMetadata, ok := methodMetadataEntry.(document.Metadata)
		require.True(t, ok)

		require.Equal(t, true, methodMetadata[document.PublishedProperty])
		require.Empty(t, methodMetadata[document.RecoveryCommitmentProperty])
		require.Empty(t, methodMetadata[document.UpdateCommitmentProperty])
	})

	t.Run("error - internal document is missing", func(t *testing.T) {
		info := make(protocol.TransformationInfo)
		info[document.IDProperty] = "doc:abc:xyz"
		info[document.PublishedProperty] = true

		result, err := New().CreateDocumentMetadata(nil, info)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "resolution model is required for creating document metadata")
	})

	t.Run("error - transformation info is missing", func(t *testing.T) {
		result, err := New().CreateDocumentMetadata(internal, nil)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "transformation info is required for creating document metadata")
	})

	t.Run("error - transformation info is missing published", func(t *testing.T) {
		info := make(protocol.TransformationInfo)

		result, err := New().CreateDocumentMetadata(internal, info)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "published is required for creating document metadata")
	})
}

//nolint:gochecknoglobals
var validDoc = []byte(`{ "name": "John Smith" }`)
