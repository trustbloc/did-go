/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signature

import (
	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/did-go/doc/signature/api"
)

// MockSuite mocks api.SignatureSuite.
type MockSuite struct {
	GetCanonicalDocumentVal []byte
	GetCanonicalDocumentErr error
	GetDigestVal            []byte
	AcceptVal               bool
	CompactProofVal         bool
	VerifyErr               error
}

// GetCanonicalDocument returns GetCanonicalDocumentVal, GetCanonicalDocumentErr.
func (m *MockSuite) GetCanonicalDocument(doc map[string]interface{}, opts ...processor.Opts) ([]byte, error) {
	return m.GetCanonicalDocumentVal, m.GetCanonicalDocumentErr
}

// GetDigest returns GetDigestVal.
func (m *MockSuite) GetDigest(doc []byte) []byte {
	return m.GetDigestVal
}

// Accept returns AcceptVal.
func (m *MockSuite) Accept(signatureType string) bool {
	return m.AcceptVal
}

// CompactProof returns CompactProofVal.
func (m *MockSuite) CompactProof() bool {
	return m.CompactProofVal
}

var _ api.SignatureSuite = &MockSuite{}

// MockVerifierSuite mocks api.VerifierSuite.
type MockVerifierSuite struct {
	MockSuite
	VerifyErr error
}

// Verify returns VerifyErr.
func (m *MockVerifierSuite) Verify(pubKey *api.PublicKey, doc []byte, signature []byte) error {
	return m.VerifyErr
}

var _ api.VerifierSuite = &MockVerifierSuite{}

// MockSignerSuite mocks api.SignerSuite.
type MockSignerSuite struct {
	MockSuite
	SignVal []byte
	SignErr error
	AlgVal  string
}

// Sign returns SignVal, SignErr.
func (m *MockSignerSuite) Sign(doc []byte) ([]byte, error) {
	return m.SignVal, m.SignErr
}

// Alg returns AlgVal.
func (m *MockSignerSuite) Alg() string {
	return m.AlgVal
}

var _ api.SignerSuite = &MockSignerSuite{}
