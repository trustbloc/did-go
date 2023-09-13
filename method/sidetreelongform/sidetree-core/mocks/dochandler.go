/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/api/operation"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/api/protocol"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/document"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/docutil"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/hashing"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/versions/1_0/doccomposer"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/versions/1_0/model"
)

const deleted = "_deleted"

// NewMockDocumentHandler returns a new mock document handler.
func NewMockDocumentHandler() *MockDocumentHandler {
	return &MockDocumentHandler{
		client: NewMockProtocolClient(),
		store:  make(map[string]document.Document),
	}
}

// MockDocumentHandler mocks the document handler.
type MockDocumentHandler struct {
	err       error
	namespace string
	client    protocol.Client
	store     map[string]document.Document
}

// WithNamespace sets the namespace.
func (m *MockDocumentHandler) WithNamespace(ns string) *MockDocumentHandler {
	m.namespace = ns

	return m
}

// WithError injects an error into the mock handler.
func (m *MockDocumentHandler) WithError(err error) *MockDocumentHandler {
	m.err = err

	return m
}

// WithProtocolClient sets the protocol client.
func (m *MockDocumentHandler) WithProtocolClient(client protocol.Client) *MockDocumentHandler {
	m.client = client

	return m
}

// Namespace returns the namespace.
func (m *MockDocumentHandler) Namespace() string {
	return m.namespace
}

// Protocol returns the Protocol.
func (m *MockDocumentHandler) Protocol() protocol.Client {
	return m.client
}

// Operation is used for parsing operation request.
type Operation struct {
	// Operation defines operation type
	Operation operation.Type `json:"type,omitempty"`

	// SuffixData object
	SuffixData *model.SuffixDataModel `json:"suffixData,omitempty"`

	// Delta object
	Delta *model.DeltaModel `json:"delta,omitempty"`

	// DidSuffix is the suffix of the DID
	DidSuffix string `json:"didSuffix"`
}

// ProcessOperation mocks process operation.
func (m *MockDocumentHandler) ProcessOperation(operationBuffer []byte, _ uint64) (*document.ResolutionResult, error) {
	if m.err != nil {
		return nil, m.err
	}

	var op Operation

	err := json.Unmarshal(operationBuffer, &op)
	if err != nil {
		return nil, fmt.Errorf("bad request: %s", err.Error())
	}

	var suffix string

	switch op.Operation {
	case operation.TypeCreate:
		suffix, err = hashing.CalculateModelMultihash(op.SuffixData, sha2_256)
		if err != nil {
			return nil, err
		}
	case operation.TypeUpdate, operation.TypeDeactivate, operation.TypeRecover:
		suffix = op.DidSuffix
	default:
		return nil, fmt.Errorf("bad request: operation type [%s] not supported", op.Operation)
	}

	id := m.namespace + docutil.NamespaceDelimiter + suffix

	if op.Operation == operation.TypeDeactivate {
		empty := applyID(make(document.Document), id)
		empty[deleted] = true
		m.store[id] = empty

		return &document.ResolutionResult{
			Document: empty,
		}, nil
	}

	doc, ok := m.store[id]
	if !ok { // create operation
		doc = make(document.Document)
	}

	doc, err = doccomposer.New().ApplyPatches(doc, op.Delta.Patches)
	if err != nil {
		return nil, err
	}

	doc = applyID(doc, id)

	m.store[id] = doc

	return &document.ResolutionResult{
		Document: doc,
	}, nil
}

// ResolveDocument mocks resolve document.
func (m *MockDocumentHandler) ResolveDocument(didOrDocument string, opts ...document.ResolutionOption,
) (*document.ResolutionResult, error) {
	if m.err != nil {
		return nil, m.err
	}

	const badRequest = "bad request"
	if !strings.HasPrefix(didOrDocument, m.namespace) {
		return nil, fmt.Errorf("%s: must start with supported namespace", badRequest)
	}

	pv, err := m.Protocol().Current()
	if err != nil {
		return nil, err
	}

	did, initial, err := pv.OperationParser().ParseDID(m.namespace, didOrDocument)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", badRequest, err.Error())
	}

	if initial != nil {
		return m.resolveWithInitialState(did, initial)
	}

	if _, ok := m.store[didOrDocument]; !ok {
		return nil, errors.New("not found")
	}

	doc := m.store[didOrDocument]

	docMetadata := make(document.Metadata)
	if isDeactivated(doc) {
		docMetadata[document.DeactivatedProperty] = true
	}

	return &document.ResolutionResult{
		Document:         doc,
		DocumentMetadata: docMetadata,
	}, nil
}

func isDeactivated(doc document.Document) bool {
	deactivated, ok := doc[deleted]
	if !ok {
		return false
	}

	return deactivated.(bool)
}

// helper function to insert ID into document.
func applyID(doc document.Document, id string) document.Document {
	// apply id to document
	doc["id"] = id

	return doc
}

func (m *MockDocumentHandler) resolveWithInitialState(did string, initial []byte) (*document.ResolutionResult, error) {
	var createReq model.CreateRequest

	err := json.Unmarshal(initial, &createReq)
	if err != nil {
		return nil, err
	}

	doc, err := doccomposer.New().ApplyPatches(make(document.Document), createReq.Delta.Patches)
	if err != nil {
		return nil, err
	}

	doc = applyID(doc, did)

	return &document.ResolutionResult{
		Document: doc,
	}, nil
}
