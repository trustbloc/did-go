//go:build ignore
// +build ignore

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/did-go/doc/json/canonicalizer"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/api/cas"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/api/operation"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/api/protocol"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/commitment"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/compression"
	docmocks "github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/dochandler/mocks"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/document"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/docutil"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/encoder"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/hashing"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/jws"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/mocks"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/patch"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/processor"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/util/ecsigner"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/util/pubkey"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/versions/1_0/client"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/versions/1_0/doccomposer"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/versions/1_0/doctransformer/didtransformer"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/versions/1_0/doctransformer/doctransformer"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/versions/1_0/model"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/versions/1_0/operationapplier"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/versions/1_0/operationparser"
)

//go:generate counterfeiter -o ./mocks/operationprocessor.gen.go --fake-name OperationProcessor . operationProcessor

const (
	namespace = "did:sidetree"
	alias     = "did:domain.com"

	sha2_256 = 18
)

func TestDocumentHandler_New(t *testing.T) {
	aliases := []string{"alias1", "alias2"}
	dh := New(namespace, aliases, nil, nil, nil, &mocks.MetricsProvider{})
	require.Equal(t, namespace, dh.Namespace())
	require.Equal(t, aliases, dh.aliases)
	require.Empty(t, dh.domain)

	const (
		domain = "domain.com"
		label  = "interim"
	)

	opDecorator := &mockOperationDecorator{}

	dh = New(namespace, nil, nil, nil, nil, &mocks.MetricsProvider{},
		WithLabel(label), WithDomain(domain), WithOperationDecorator(opDecorator))
	require.Equal(t, namespace, dh.Namespace())
	require.Equal(t, domain, dh.domain)
	require.Equal(t, label, dh.label)
	require.Equal(t, opDecorator, dh.decorator)
}

func TestDocumentHandler_Protocol(t *testing.T) {
	pc := newMockProtocolClient()
	dh := New("", nil, pc, nil, nil, &mocks.MetricsProvider{})
	require.NotNil(t, dh)
}

func TestDocumentHandler_ProcessOperation_Create(t *testing.T) {
	dochandler, cleanup := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)

	defer cleanup()

	createOp := getCreateOperation()

	doc, err := dochandler.ProcessOperation(createOp.OperationRequest, 0)
	require.NoError(t, err)
	require.NotNil(t, doc)
}

func TestDocumentHandler_DefaultDecorator(t *testing.T) {
	t.Run("success - create", func(t *testing.T) {
		processor := processor.New("test", mocks.NewMockOperationStore(nil), newMockProtocolClient())

		decorator := &defaultOperationDecorator{processor: processor}

		updateOp := &operation.Operation{
			Type:         operation.TypeCreate,
			UniqueSuffix: "suffix",
		}

		op, err := decorator.Decorate(updateOp)
		require.NoError(t, err)
		require.NotNil(t, op)
	})
	t.Run("success - update", func(t *testing.T) {
		store := mocks.NewMockOperationStore(nil)

		createOp := getCreateOperation()

		createOpBuffer, err := json.Marshal(createOp)
		require.NoError(t, err)

		err = store.Put(&operation.AnchoredOperation{
			UniqueSuffix:     createOp.UniqueSuffix,
			Type:             operation.TypeCreate,
			OperationRequest: createOpBuffer})
		require.NoError(t, err)

		processor := processor.New("test", store, newMockProtocolClient())

		decorator := &defaultOperationDecorator{processor: processor}

		updateOp := &operation.Operation{
			Type:         operation.TypeUpdate,
			UniqueSuffix: createOp.UniqueSuffix,
		}

		op, err := decorator.Decorate(updateOp)
		require.NoError(t, err)
		require.NotNil(t, op)
		require.Equal(t, op.AnchorOrigin, createOp.AnchorOrigin)
	})

	t.Run("error - processor error", func(t *testing.T) {
		processor := &docmocks.OperationProcessor{}
		processor.ResolveReturns(nil, fmt.Errorf("processor error"))

		decorator := &defaultOperationDecorator{processor: processor}

		updateOp := &operation.Operation{
			Type:         operation.TypeUpdate,
			UniqueSuffix: "suffix",
		}

		op, err := decorator.Decorate(updateOp)
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(), "processor error")
	})

	t.Run("error - document has been deactivated, no further operations allowed", func(t *testing.T) {
		rm := &protocol.ResolutionModel{
			Deactivated: true,
		}

		processor := &docmocks.OperationProcessor{}
		processor.ResolveReturns(rm, nil)

		decorator := &defaultOperationDecorator{processor: processor}

		updateOp := &operation.Operation{
			Type:         operation.TypeUpdate,
			UniqueSuffix: "suffix",
		}

		op, err := decorator.Decorate(updateOp)
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(), "document has been deactivated, no further operations are allowed")
	})
}

func TestDocumentHandler_ProcessOperation_Update(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store := mocks.NewMockOperationStore(nil)

		dochandler, cleanup := getDocumentHandler(store)
		require.NotNil(t, dochandler)
		defer cleanup()

		createOp := getCreateOperation()

		createOpBuffer, err := json.Marshal(createOp)
		require.NoError(t, err)

		updateOp, err := generateUpdateOperation(createOp.UniqueSuffix)
		require.NoError(t, err)

		err = store.Put(&operation.AnchoredOperation{
			UniqueSuffix: createOp.UniqueSuffix, Type: operation.TypeCreate, OperationRequest: createOpBuffer})
		require.NoError(t, err)

		doc, err := dochandler.ProcessOperation(updateOp, 0)
		require.NoError(t, err)
		require.Nil(t, doc)
	})

	t.Run("success - unpublished operation store option", func(t *testing.T) {
		store := mocks.NewMockOperationStore(nil)

		opt := WithUnpublishedOperationStore(&mockUnpublishedOpsStore{}, []operation.Type{operation.TypeUpdate})

		dochandler, cleanup := getDocumentHandler(store, opt)
		require.NotNil(t, dochandler)
		defer cleanup()

		createOp := getCreateOperation()

		createOpBuffer, err := json.Marshal(createOp)
		require.NoError(t, err)

		updateOp, err := generateUpdateOperation(createOp.UniqueSuffix)
		require.NoError(t, err)

		err = store.Put(&operation.AnchoredOperation{
			UniqueSuffix: createOp.UniqueSuffix, Type: operation.TypeCreate, OperationRequest: createOpBuffer})
		require.NoError(t, err)

		doc, err := dochandler.ProcessOperation(updateOp, 0)
		require.NoError(t, err)
		require.Nil(t, doc)
	})

	t.Run("success - unpublished operation store option(create and update)", func(t *testing.T) {
		store := mocks.NewMockOperationStore(nil)

		createOp := getCreateOperation()

		updateOp, err := generateUpdateOperation(createOp.UniqueSuffix)
		require.NoError(t, err)

		unpublishedOperationStore := &mockUnpublishedOpsStore{
			Ops: []*operation.AnchoredOperation{
				{
					Type:             "create",
					OperationRequest: createOp.OperationRequest,
					UniqueSuffix:     createOp.UniqueSuffix,
				},
			},
		}

		protocol := newMockProtocolClient()

		processor := processor.New("test",
			store, protocol, processor.WithUnpublishedOperationStore(unpublishedOperationStore))

		ctx := &BatchContext{
			ProtocolClient: protocol,
			CasClient:      mocks.NewMockCasClient(nil),
			AnchorWriter:   mocks.NewMockAnchorWriter(nil),
			OpQueue:        &opqueue.MemQueue{},
		}
		writer, err := batch.New("test", ctx)
		if err != nil {
			panic(err)
		}

		// start go routine for cutting batches
		writer.Start()

		dochandler, cleanup := New(namespace, []string{alias}, protocol, writer, processor, &mocks.MetricsProvider{},
			WithUnpublishedOperationStore(
				unpublishedOperationStore,
				[]operation.Type{operation.TypeCreate, operation.TypeUpdate})), func() { writer.Stop() }
		require.NotNil(t, dochandler)
		defer cleanup()

		doc, err := dochandler.ProcessOperation(updateOp, 0)
		require.NoError(t, err)
		require.Nil(t, doc)

		doc, err = dochandler.ResolveDocument(createOp.ID)
		require.NoError(t, err)
		fmt.Printf("%+v", doc)

		idWithHint := namespace + ":domain.com" + createOp.UniqueSuffix

		_, err = dochandler.ResolveDocument(idWithHint)
		require.NoError(t, err)
	})

	t.Run("error - update without unpublished/published create", func(t *testing.T) {
		store := mocks.NewMockOperationStore(nil)

		createOp := getCreateOperation()

		updateOp, err := generateUpdateOperation(createOp.UniqueSuffix)
		require.NoError(t, err)

		unpublishedOperationStore := &mockUnpublishedOpsStore{}

		protocol := newMockProtocolClient()

		processor := processor.New("test",
			store, protocol, processor.WithUnpublishedOperationStore(unpublishedOperationStore))

		ctx := &BatchContext{
			ProtocolClient: protocol,
			CasClient:      mocks.NewMockCasClient(nil),
			AnchorWriter:   mocks.NewMockAnchorWriter(nil),
			OpQueue:        &opqueue.MemQueue{},
		}
		writer, err := batch.New("test", ctx)
		if err != nil {
			panic(err)
		}

		// start go routine for cutting batches
		writer.Start()

		dochandler, cleanup := New(namespace, []string{alias}, protocol, writer, processor, &mocks.MetricsProvider{},
			WithUnpublishedOperationStore(
				unpublishedOperationStore,
				[]operation.Type{operation.TypeCreate, operation.TypeUpdate})), func() { writer.Stop() }
		require.NotNil(t, dochandler)
		defer cleanup()

		doc, err := dochandler.ProcessOperation(updateOp, 0)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "bad request: create operation not found")
	})

	t.Run("error - batch writer error (unpublished operation store option)", func(t *testing.T) {
		store := mocks.NewMockOperationStore(nil)

		opt := WithUnpublishedOperationStore(&noopUnpublishedOpsStore{}, []operation.Type{operation.TypeUpdate})

		dochandler, cleanup := getDocumentHandler(store, opt)
		require.NotNil(t, dochandler)
		defer cleanup()

		createOp := getCreateOperation()

		createOpBuffer, err := json.Marshal(createOp)
		require.NoError(t, err)

		updateOp, err := generateUpdateOperation(createOp.UniqueSuffix)
		require.NoError(t, err)

		err = store.Put(&operation.AnchoredOperation{
			UniqueSuffix: createOp.UniqueSuffix, Type: operation.TypeCreate, OperationRequest: createOpBuffer})
		require.NoError(t, err)

		dochandler.writer = &mockBatchWriter{Err: fmt.Errorf("batch writer error")}

		doc, err := dochandler.ProcessOperation(updateOp, 0)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "batch writer error")
	})

	t.Run("error - unpublished operation store put error", func(t *testing.T) {
		store := mocks.NewMockOperationStore(nil)

		opt := WithUnpublishedOperationStore(
			&mockUnpublishedOpsStore{PutErr: fmt.Errorf("put error")},
			[]operation.Type{operation.TypeUpdate})

		dochandler, cleanup := getDocumentHandler(store, opt)
		require.NotNil(t, dochandler)
		defer cleanup()

		createOp := getCreateOperation()

		createOpBuffer, err := json.Marshal(createOp)
		require.NoError(t, err)

		updateOp, err := generateUpdateOperation(createOp.UniqueSuffix)
		require.NoError(t, err)

		err = store.Put(&operation.AnchoredOperation{
			UniqueSuffix: createOp.UniqueSuffix, Type: operation.TypeCreate, OperationRequest: createOpBuffer})
		require.NoError(t, err)

		doc, err := dochandler.ProcessOperation(updateOp, 0)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "put error")
	})

	t.Run("error - unpublished operation store delete error", func(t *testing.T) {
		store := mocks.NewMockOperationStore(nil)

		opt := WithUnpublishedOperationStore(
			&mockUnpublishedOpsStore{DeleteErr: fmt.Errorf("delete error")},
			[]operation.Type{operation.TypeUpdate})

		dochandler, cleanup := getDocumentHandler(store, opt)
		require.NotNil(t, dochandler)
		defer cleanup()

		dochandler.deleteOperationFromUnpublishedOpsStore(&operation.AnchoredOperation{UniqueSuffix: "suffix"})
	})

	t.Run("error - decorator error", func(t *testing.T) {
		store := mocks.NewMockOperationStore(nil)

		dochandler, cleanup := getDocumentHandler(store)
		require.NotNil(t, dochandler)
		defer cleanup()

		processor := &docmocks.OperationProcessor{}
		processor.ResolveReturns(nil, fmt.Errorf("processor error"))

		dochandler.decorator = &defaultOperationDecorator{processor: processor}

		updateOp, err := generateUpdateOperation("suffix")
		require.NoError(t, err)

		doc, err := dochandler.ProcessOperation(updateOp, 0)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "processor error")
	})
}

func TestDocumentHandler_ProcessOperation_Create_WithDomain(t *testing.T) {
	dochandler, cleanup := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)

	defer cleanup()

	dochandler.domain = "https:domain.com"
	dochandler.label = "interim"

	createOp := getCreateOperation()

	result, err := dochandler.ProcessOperation(createOp.OperationRequest, 0)
	require.NoError(t, err)
	require.NotNil(t, result)

	require.Contains(t, result.Document.ID(), namespace+":interim")

	equivalentIds := result.DocumentMetadata[document.EquivalentIDProperty].([]string) //nolint:errcheck
	require.Len(t, equivalentIds, 1)
	require.Contains(t, equivalentIds[0], namespace+":https:domain.com:interim")
}

func TestDocumentHandler_ProcessOperation_Create_ApplyDeltaError(t *testing.T) {
	dochandler, cleanup := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)

	defer cleanup()

	p, err := patch.NewJSONPatch(errorPatch)
	require.NoError(t, err)

	delta := &model.DeltaModel{
		UpdateCommitment: encodedMultihash([]byte("updateReveal")),
		Patches:          []patch.Patch{p},
	}

	suffixData, err := getSuffixData(delta)
	require.NoError(t, err)

	createOp, err := getCreateOperationWithInitialState(suffixData, delta)
	require.NoError(t, err)

	doc, err := dochandler.ProcessOperation(createOp.OperationRequest, 0)
	require.Error(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "applying delta resulted in an empty document (most likely due to an invalid patch)")
}

func TestDocumentHandler_ProcessOperation_ProtocolError(t *testing.T) {
	pc := newMockProtocolClient()
	pc.Err = fmt.Errorf("injected protocol error")
	dochandler, cleanup := getDocumentHandlerWithProtocolClient(mocks.NewMockOperationStore(nil), pc)
	require.NotNil(t, dochandler)

	defer cleanup()

	createOp := getCreateOperation()

	doc, err := dochandler.ProcessOperation(createOp.OperationRequest, 0)
	require.EqualError(t, err, pc.Err.Error())
	require.Nil(t, doc)
}

func TestDocumentHandler_ResolveDocument_DID(t *testing.T) {
	store := mocks.NewMockOperationStore(nil)
	dochandler, cleanup := getDocumentHandler(store)
	require.NotNil(t, dochandler)

	defer cleanup()

	docID := getCreateOperation().ID
	uniqueSuffix := getCreateOperation().UniqueSuffix

	// scenario: not found in the store
	result, err := dochandler.ResolveDocument(docID)
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "not found")

	// insert document in the store
	err = store.Put(getAnchoredCreateOperation())
	require.NoError(t, err)

	// scenario: resolved document (success)
	result, err = dochandler.ResolveDocument(docID)
	require.NoError(t, err)
	require.NotNil(t, result)

	methodMetadataEntry, ok := result.DocumentMetadata[document.MethodProperty]
	require.True(t, ok)
	methodMetadata, ok := methodMetadataEntry.(document.Metadata)
	require.True(t, ok)

	require.Equal(t, true, methodMetadata[document.PublishedProperty])

	// scenario: resolve document with alias namespace (success)
	aliasID := alias + ":" + uniqueSuffix
	result, err = dochandler.ResolveDocument(aliasID)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, true, methodMetadata[document.PublishedProperty])
	require.Equal(t, result.DocumentMetadata[document.CanonicalIDProperty], docID)
	require.Equal(t, result.Document[keyID], aliasID)

	// scenario: invalid namespace
	result, err = dochandler.ResolveDocument("doc:invalid")
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "must start with configured namespace")

	// scenario: invalid id
	result, err = dochandler.ResolveDocument(namespace + docutil.NamespaceDelimiter)
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "did suffix is empty")
}

func TestDocumentHandler_ResolveDocument_DID_With_References(t *testing.T) {
	store := mocks.NewMockOperationStore(nil)
	dochandler, cleanup := getDocumentHandler(store)
	require.NotNil(t, dochandler)

	defer cleanup()

	const (
		reference   = "reference"
		equivalent1 = "equivalent1"
		equivalent2 = "equivalent2"
	)

	anchoredOp := getAnchoredCreateOperation()
	anchoredOp.CanonicalReference = reference
	anchoredOp.EquivalentReferences = []string{equivalent1, equivalent2}

	err := store.Put(anchoredOp)
	require.NoError(t, err)

	result, err := dochandler.ResolveDocument(namespace + docutil.NamespaceDelimiter + anchoredOp.UniqueSuffix)
	require.NoError(t, err)
	require.NotNil(t, result)

	expectedCanonical := namespace +
		docutil.NamespaceDelimiter + reference + docutil.NamespaceDelimiter + anchoredOp.UniqueSuffix
	require.Equal(t, expectedCanonical, result.DocumentMetadata[document.CanonicalIDProperty])

	expectedEquivalent1 := namespace +
		docutil.NamespaceDelimiter + equivalent1 + docutil.NamespaceDelimiter + anchoredOp.UniqueSuffix
	expectedEquivalent2 := namespace +
		docutil.NamespaceDelimiter + equivalent2 + docutil.NamespaceDelimiter + anchoredOp.UniqueSuffix
	expectedEquivalence := []string{expectedCanonical, expectedEquivalent1, expectedEquivalent2}

	require.Equal(t, expectedEquivalence, result.DocumentMetadata[document.EquivalentIDProperty])
}

func TestDocumentHandler_ResolveDocument_InitialValue(t *testing.T) {
	pc := newMockProtocolClient()
	dochandler, cleanup := getDocumentHandlerWithProtocolClient(mocks.NewMockOperationStore(nil), pc)
	require.NotNil(t, dochandler)

	defer cleanup()

	createOp := getCreateOperation()
	docID := createOp.ID

	createReq, err := canonicalizer.MarshalCanonical(model.CreateRequest{
		Delta:      createOp.Delta,
		SuffixData: createOp.SuffixData,
	})
	require.NoError(t, err)

	longFormPart := ":" + encoder.EncodeToString(createReq)

	t.Run("success - initial state", func(t *testing.T) {
		result, err := dochandler.ResolveDocument(docID + longFormPart)
		require.NoError(t, err)
		require.NotNil(t, result)

		methodMetadataEntry, ok := result.DocumentMetadata[document.MethodProperty]
		require.True(t, ok)

		methodMetadata, ok := methodMetadataEntry.(document.Metadata)
		require.True(t, ok)

		require.Equal(t, false, methodMetadata[document.PublishedProperty])

		equivalentIds := result.DocumentMetadata[document.EquivalentIDProperty].([]string) //nolint:errcheck
		require.Len(t, equivalentIds, 1)
	})

	t.Run("success - initial state with label and domain", func(t *testing.T) {
		docHandlerWithDomain, clean := getDocumentHandlerWithProtocolClient(mocks.NewMockOperationStore(nil), pc)
		require.NotNil(t, docHandlerWithDomain)
		defer clean()

		const label = "interim"
		const domain = "domain.com"

		docHandlerWithDomain.label = label
		docHandlerWithDomain.domain = domain

		result, err := docHandlerWithDomain.ResolveDocument(docID + longFormPart)
		require.NoError(t, err)
		require.NotNil(t, result)

		methodMetadataEntry, ok := result.DocumentMetadata[document.MethodProperty]
		require.True(t, ok)

		methodMetadata, ok := methodMetadataEntry.(document.Metadata)
		require.True(t, ok)

		require.Equal(t, false, methodMetadata[document.PublishedProperty])

		require.Contains(t, result.Document.ID(), fmt.Sprintf("%s:%s", namespace, label))

		equivalentIds := result.DocumentMetadata[document.EquivalentIDProperty].([]string) //nolint:errcheck
		require.Len(t, equivalentIds, 2)
		require.Contains(t, equivalentIds[0], fmt.Sprintf("%s:%s", namespace, label))
		require.NotContains(t, equivalentIds[0], fmt.Sprintf("%s:%s%s", namespace, label, domain))
		require.Contains(t, equivalentIds[1], fmt.Sprintf("%s:%s:%s", namespace, domain, label))
	})

	t.Run("error - invalid initial state format (not encoded JCS)", func(t *testing.T) {
		result, err := dochandler.ResolveDocument(docID + ":payload")
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "bad request: invalid character")
	})

	t.Run("error - did doesn't match the one created by parsing original create request", func(t *testing.T) {
		result, err := dochandler.ResolveDocument(dochandler.namespace + ":someID" + longFormPart)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "provided did doesn't match did created from initial state")
	})

	t.Run("error - transform create with initial state to external document", func(t *testing.T) {
		transformer := &mocks.DocumentTransformer{}
		transformer.TransformDocumentReturns(nil, errors.New("test error"))

		pc := newMockProtocolClient()
		pc.CurrentVersion.DocumentTransformerReturns(transformer)

		dochandlerWithValidator, cleanup :=
			getDocumentHandlerWithProtocolClient(mocks.NewMockOperationStore(nil), pc)
		require.NotNil(t, dochandlerWithValidator)
		defer cleanup()

		result, err := dochandlerWithValidator.ResolveDocument(docID + longFormPart)
		require.Error(t, err)
		require.Nil(t, result)
		require.Equal(t, err.Error(),
			"failed to transform create with initial state to external document: test error")
	})

	t.Run("error - original (create) document is not valid", func(t *testing.T) {
		dv := &mocks.DocumentValidator{}
		dv.IsValidOriginalDocumentReturns(errors.New("test error"))

		pc := newMockProtocolClient()
		pc.CurrentVersion.DocumentValidatorReturns(dv)

		dochandlerWithValidator, cleanup := getDocumentHandlerWithProtocolClient(mocks.NewMockOperationStore(nil), pc)
		require.NotNil(t, dochandlerWithValidator)
		defer cleanup()

		result, err := dochandlerWithValidator.ResolveDocument(docID + longFormPart)
		require.Error(t, err)
		require.Nil(t, result)
		require.Equal(t, err.Error(), "bad request: validate initial document: test error")
	})

	t.Run("error - protocol error", func(t *testing.T) {
		pc := newMockProtocolClient()
		pc.Err = fmt.Errorf("injected protocol error")

		dochandler, cleanup := getDocumentHandlerWithProtocolClient(mocks.NewMockOperationStore(nil), pc)
		require.NotNil(t, dochandler)
		defer cleanup()

		result, err := dochandler.ResolveDocument(docID + longFormPart)
		require.EqualError(t, err, pc.Err.Error())
		require.Nil(t, result)
	})
}

func TestDocumentHandler_ResolveDocument_Interop(t *testing.T) {
	pc := newMockProtocolClient()
	pc.Protocol.Patches = []string{"replace", "add-public-keys", "remove-public-keys", "add-services", "remove-services", "ietf-json-patch"} //nolint:lll

	parser := operationparser.New(pc.Protocol)
	oa := operationapplier.New(pc.Protocol, parser, doccomposer.New())
	transformer := didtransformer.New()

	pv := pc.CurrentVersion
	pv.OperationParserReturns(parser)
	pv.OperationApplierReturns(oa)
	pv.DocumentTransformerReturns(transformer)

	pc.CurrentVersion.ProtocolReturns(pc.Protocol)

	dochandler, cleanup := getDocumentHandlerWithProtocolClient(mocks.NewMockOperationStore(nil), pc)
	require.NotNil(t, dochandler)

	defer cleanup()

	dochandler.protocol = pc

	result, err := dochandler.ResolveDocument(interopResolveDidWithInitialState)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestDocumentHandler_ResolveDocument_InitialDocumentNotValid(t *testing.T) {
	dochandler, cleanup := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)

	defer cleanup()

	createReq, err := getCreateRequestWithDoc(invalidDocNoKeyType)
	require.NoError(t, err)

	createOp, err := getCreateOperationWithInitialState(createReq.SuffixData, createReq.Delta)
	require.NoError(t, err)

	docID := createOp.ID

	initialReq, err := canonicalizer.MarshalCanonical(model.CreateRequest{
		Delta:      createOp.Delta,
		SuffixData: createOp.SuffixData,
	})
	require.NoError(t, err)

	longFormPart := ":" + encoder.EncodeToString(initialReq)

	result, err := dochandler.ResolveDocument(docID + longFormPart)
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "bad request: key 'type' is required for public key")
}

func TestGetUniquePortion(t *testing.T) {
	const namespace = "did:sidetree"

	// id doesn't contain namespace
	_, err := getSuffix(namespace, "invalid")
	require.Error(t, err)
	require.Contains(t, err.Error(), "did must start with configured namespace")

	// id equals namespace; unique portion is empty
	_, err = getSuffix(namespace, namespace+docutil.NamespaceDelimiter)
	require.Error(t, err)
	require.Contains(t, err.Error(), "did suffix is empty")

	// valid unique portion
	const unique = "exKwW0HjS5y4zBtJ7vYDwglYhtckdO15JDt1j5F5Q0A"
	uniquePortion, err := getSuffix(namespace, namespace+docutil.NamespaceDelimiter+unique)
	require.NoError(t, err)
	require.Equal(t, unique, uniquePortion)
}

func TestProcessOperation_ParseOperationError(t *testing.T) {
	store := mocks.NewMockOperationStore(nil)
	dochandler, cleanup := getDocumentHandler(store)
	require.NotNil(t, dochandler)

	defer cleanup()

	// insert document in the store
	err := store.Put(getAnchoredCreateOperation())
	require.NoError(t, err)

	doc, err := dochandler.ProcessOperation(getUpdateOperation().OperationRequest, 0)
	require.Error(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "bad request: missing signed data")
}

func TestGetHint(t *testing.T) {
	const (
		namespace = "did:sidetree"
		testID    = "did:sidetree:unique"
	)

	t.Run("success", func(t *testing.T) {
		hint, err := GetHint("did:sidetree:hint:unique", namespace, "unique")
		require.NoError(t, err)
		require.Equal(t, "hint", hint)
	})

	t.Run("success - no hint", func(t *testing.T) {
		t.Run("success", func(t *testing.T) {
			hint, err := GetHint(testID, namespace, "unique")
			require.NoError(t, err)
			require.Empty(t, hint)
		})
	})

	t.Run("error - wrong suffix", func(t *testing.T) {
		t.Run("success", func(t *testing.T) {
			hint, err := GetHint(testID, namespace, "other")
			require.Error(t, err)
			require.Empty(t, hint)
		})
	})
}

// BatchContext implements batch writer context.
type BatchContext struct {
	ProtocolClient *mocks.MockProtocolClient
	CasClient      *mocks.MockCasClient
	AnchorWriter   *mocks.MockAnchorWriter
	OpQueue        cutter.OperationQueue
}

// Protocol returns the ProtocolClient.
func (m *BatchContext) Protocol() protocol.Client {
	return m.ProtocolClient
}

// Anchor returns the block chain client.
func (m *BatchContext) Anchor() batch.AnchorWriter {
	return m.AnchorWriter
}

// CAS returns the CAS client.
func (m *BatchContext) CAS() cas.Client {
	return m.CasClient
}

// OperationQueue returns the queue of operations pending to be cut.
func (m *BatchContext) OperationQueue() cutter.OperationQueue {
	return m.OpQueue
}

type cleanup func()

func getDocumentHandler(store *mocks.MockOperationStore, opts ...Option) (*DocumentHandler, cleanup) {
	return getDocumentHandlerWithProtocolClient(store, newMockProtocolClient(), opts...)
}

func getDocumentHandlerWithProtocolClient(
	store *mocks.MockOperationStore, protocol *mocks.MockProtocolClient, opts ...Option,
) (*DocumentHandler, cleanup) { //nolint: interfacer
	processor := processor.New("test", store, protocol)

	ctx := &BatchContext{
		ProtocolClient: protocol,
		CasClient:      mocks.NewMockCasClient(nil),
		AnchorWriter:   mocks.NewMockAnchorWriter(nil),
		OpQueue:        &opqueue.MemQueue{},
	}

	writer, err := batch.New("test", ctx)
	if err != nil {
		panic(err)
	}

	// start go routine for cutting batches
	writer.Start()

	return New(namespace,
		[]string{alias}, protocol, writer, processor, &mocks.MetricsProvider{}, opts...), func() { writer.Stop() }
}

func getCreateOperation() *model.Operation {
	request, err := getCreateRequest()
	if err != nil {
		panic(err)
	}

	op, err := getCreateOperationWithInitialState(request.SuffixData, request.Delta)
	if err != nil {
		panic(err)
	}

	return op
}

func getCreateOperationWithInitialState(suffixData *model.SuffixDataModel, delta *model.DeltaModel,
) (*model.Operation, error) {
	request := &model.CreateRequest{
		Operation:  operation.TypeCreate,
		SuffixData: suffixData,
		Delta:      delta,
	}

	payload, err := canonicalizer.MarshalCanonical(request)
	if err != nil {
		return nil, err
	}

	uniqueSuffix, err := hashing.CalculateModelMultihash(suffixData, sha2_256)
	if err != nil {
		return nil, err
	}

	return &model.Operation{
		Type:             operation.TypeCreate,
		UniqueSuffix:     uniqueSuffix,
		ID:               namespace + docutil.NamespaceDelimiter + uniqueSuffix,
		OperationRequest: payload,
		Delta:            delta,
		SuffixData:       suffixData,
	}, nil
}

func getAnchoredCreateOperation() *operation.AnchoredOperation {
	op := getCreateOperation()

	return getAnchoredOperation(op)
}

func getAnchoredOperation(op *model.Operation) *operation.AnchoredOperation {
	anchoredOp, err := model.GetAnchoredOperation(op)
	if err != nil {
		panic(err)
	}

	return anchoredOp
}

const validDoc = `{
	"publicKey": [{
		  "id": "key1",
		  "type": "JsonWebKey2020",
		  "purposes": ["authentication"],
		  "publicKeyJwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		  }
	}]
}`

const invalidDocNoKeyType = `{
	"publicKey": [{
		  "id": "key1",
		  "publicKeyJwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		  }
	}]
}`

const errorPatch = `[
{
	"op": "move",
	"path": "/test",
	"value": "new value"
}
]`

func getCreateRequest() (*model.CreateRequest, error) {
	return getCreateRequestWithDoc(validDoc)
}

func getCreateRequestWithDoc(doc string) (*model.CreateRequest, error) {
	delta, err := getDeltaWithDoc(doc)
	if err != nil {
		return nil, err
	}

	suffixData, err := getSuffixData(delta)
	if err != nil {
		return nil, err
	}

	return &model.CreateRequest{
		Operation:  operation.TypeCreate,
		Delta:      delta,
		SuffixData: suffixData,
	}, nil
}

func getDeltaWithDoc(doc string) (*model.DeltaModel, error) {
	patches, err := newAddPublicKeysPatch(doc)
	if err != nil {
		return nil, err
	}

	return &model.DeltaModel{
		Patches:          []patch.Patch{patches},
		UpdateCommitment: encodedMultihash([]byte("updateReveal")),
	}, nil
}

// newAddPublicKeysPatch creates new add public keys patch without validation.
func newAddPublicKeysPatch(doc string) (patch.Patch, error) {
	parsed, err := document.FromBytes([]byte(doc))
	if err != nil {
		return nil, err
	}

	p := make(patch.Patch)
	p[patch.ActionKey] = patch.AddPublicKeys
	p[patch.PublicKeys] = parsed.PublicKeys()

	return p, nil
}

func getSuffixData(delta *model.DeltaModel) (*model.SuffixDataModel, error) {
	jwk := &jws.JWK{
		Kty: "kty",
		Crv: "crv",
		X:   "x",
	}

	c, err := commitment.GetCommitment(jwk, sha2_256)
	if err != nil {
		return nil, err
	}

	deltaHash, err := hashing.CalculateModelMultihash(delta, sha2_256)
	if err != nil {
		return nil, err
	}

	return &model.SuffixDataModel{
		DeltaHash:          deltaHash,
		RecoveryCommitment: c,
	}, nil
}

func encodedMultihash(data []byte) string {
	mh, err := hashing.ComputeMultihash(sha2_256, data)
	if err != nil {
		panic(err)
	}

	return encoder.EncodeToString(mh)
}

func getUpdateDelta() *model.DeltaModel {
	return &model.DeltaModel{
		UpdateCommitment: encodedMultihash([]byte("updateReveal")),
	}
}

func getUpdateOperation() *operation.Operation {
	request := &model.UpdateRequest{
		Operation: operation.TypeUpdate,
		DidSuffix: getCreateOperation().UniqueSuffix,
		Delta:     getUpdateDelta(),
	}

	payload, err := json.Marshal(request)
	if err != nil {
		panic(err)
	}

	return &operation.Operation{
		OperationRequest: payload,
		Type:             operation.TypeUpdate,
		UniqueSuffix:     request.DidSuffix,
		ID:               namespace + docutil.NamespaceDelimiter + request.DidSuffix,
	}
}

func generateUpdateRequestInfo(uniqueSuffix string) (*client.UpdateRequestInfo, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	testPatch, err := getTestPatch()
	if err != nil {
		return nil, err
	}

	updateCommitment, err := generateUniqueCommitment()
	if err != nil {
		return nil, err
	}

	updatePubKey, err := pubkey.GetPublicKeyJWK(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	rv, err := commitment.GetRevealValue(updatePubKey, sha2_256)
	if err != nil {
		return nil, err
	}

	return &client.UpdateRequestInfo{
		DidSuffix:        uniqueSuffix,
		Signer:           ecsigner.New(privateKey, "ES256", ""),
		UpdateCommitment: updateCommitment,
		UpdateKey:        updatePubKey,
		Patches:          []patch.Patch{testPatch},
		MultihashCode:    sha2_256,
		RevealValue:      rv,
	}, nil
}

func generateUpdateOperation(uniqueSuffix string) ([]byte, error) {
	info, err := generateUpdateRequestInfo(uniqueSuffix)
	if err != nil {
		return nil, err
	}

	return client.NewUpdateRequest(info)
}

func getTestPatch() (patch.Patch, error) {
	return patch.NewJSONPatch(`[{"op": "replace", "path": "/name", "value": "Jane"}]`)
}

func generateUniqueCommitment() (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}

	pubKey, err := pubkey.GetPublicKeyJWK(&key.PublicKey)
	if err != nil {
		return "", err
	}

	c, err := commitment.GetCommitment(pubKey, sha2_256)
	if err != nil {
		return "", err
	}

	return c, nil
}

// test value taken from reference implementation.
//
//nolint:lll
const interopResolveDidWithInitialState = "did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ"

func newMockProtocolClient() *mocks.MockProtocolClient {
	pc := mocks.NewMockProtocolClient()

	for _, v := range pc.Versions {
		parser := operationparser.New(v.Protocol())
		dc := doccomposer.New()
		oa := operationapplier.New(v.Protocol(), parser, dc)
		dv := &mocks.DocumentValidator{}
		dt := doctransformer.New()

		pc.CasClient = mocks.NewMockCasClient(nil)
		cp := compression.New(compression.WithDefaultAlgorithms())
		oh := txnprovider.NewOperationHandler(pc.Protocol, pc.CasClient, cp, parser, &mocks.MetricsProvider{})

		v.OperationParserReturns(parser)
		v.OperationApplierReturns(oa)
		v.DocumentComposerReturns(dc)
		v.DocumentValidatorReturns(dv)
		v.DocumentTransformerReturns(dt)
		v.OperationHandlerReturns(oh)
	}

	return pc
}

type mockUnpublishedOpsStore struct {
	Ops       []*operation.AnchoredOperation
	PutErr    error
	DeleteErr error
	GetErr    error
}

func (m *mockUnpublishedOpsStore) Put(_ *operation.AnchoredOperation) error {
	return m.PutErr
}

func (m *mockUnpublishedOpsStore) Delete(_ *operation.AnchoredOperation) error {
	return m.DeleteErr
}

func (m *mockUnpublishedOpsStore) Get(uniqueSuffix string) ([]*operation.AnchoredOperation, error) {
	if m.GetErr != nil {
		return nil, m.GetErr
	}

	return m.Ops, nil
}

type mockOperationDecorator struct {
	Err error
}

func (m *mockOperationDecorator) Decorate(op *operation.Operation) (*operation.Operation, error) {
	if m.Err == nil {
		return nil, m.Err
	}

	return op, nil
}

type mockBatchWriter struct {
	Err error
}

func (mbw *mockBatchWriter) Add(_ *operation.QueuedOperation, _ uint64) error {
	return mbw.Err
}
