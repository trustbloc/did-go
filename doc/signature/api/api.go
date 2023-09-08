/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"time"

	"github.com/trustbloc/did-go/doc/ld/proof"
	"github.com/trustbloc/kms-go/doc/jose/jwk"

	"github.com/trustbloc/did-go/doc/ld/processor"
)

// Context holds signing options and private key.
type Context struct {
	SignatureType           string                        // required
	Creator                 string                        // required
	SignatureRepresentation proof.SignatureRepresentation // optional
	Created                 *time.Time                    // optional
	Domain                  string                        // optional
	Nonce                   []byte                        // optional
	VerificationMethod      string                        // optional
	Challenge               string                        // optional
	Purpose                 string                        // optional
	CapabilityChain         []interface{}                 // optional
}

// Signer wraps a set of SignerSuite instances and creates proofs on json LD documents.
type Signer interface {
	// Sign creates a proof using the given Context on the given json LD document.
	Sign(context *Context, jsonLdDoc []byte, opts ...processor.Opts) ([]byte, error)
}

// Verifier wraps a set of VerifierSuite instances and verifies proofs on json LD documents.
type Verifier interface {
	// Verify verifies a json LD proof on a document.
	Verify(jsonLdDoc []byte, opts ...processor.Opts) error
	// VerifyObject verifies a json LD proof on a document unmarshalled following json.Unmarshal conventions.
	VerifyObject(jsonLdObject map[string]interface{}, opts ...processor.Opts) error
}

// SignatureSuite provides common methods for signature suites.
type SignatureSuite interface {
	// GetCanonicalDocument will return normalized/canonical version of the document
	GetCanonicalDocument(doc map[string]interface{}, opts ...processor.Opts) ([]byte, error)

	// GetDigest returns document digest
	GetDigest(doc []byte) []byte

	// Accept registers this signature suite with the given signature type
	Accept(signatureType string) bool

	// CompactProof indicates whether to compact the proof doc before canonization
	CompactProof() bool
}

// VerifierSuite encapsulates signature suite methods required for signature verification.
type VerifierSuite interface {
	SignatureSuite

	// Verify will verify signature against public key
	Verify(pubKey *PublicKey, doc []byte, signature []byte) error
}

// SignerSuite encapsulates signature suite methods required for signing documents.
type SignerSuite interface {
	SignatureSuite

	// Sign will sign document and return signature
	Sign(doc []byte) ([]byte, error)

	// Alg will return algorithm
	Alg() string
}

// PublicKey contains a result of public key resolution.
type PublicKey struct {
	Type  string
	Value []byte
	JWK   *jwk.JWK
}
