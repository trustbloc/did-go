/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	_ "embed"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	sigmock "github.com/trustbloc/did-go/doc/internal/mock/signature"
	"github.com/trustbloc/did-go/doc/ld/proof"
	"github.com/trustbloc/did-go/doc/ld/testutil"
)

const signatureType = "Ed25519Signature2018"

//go:embed testdata/valid_doc.jsonld
var validDoc string //nolint:gochecknoglobals

func TestDocumentSigner_Sign(t *testing.T) {
	context := getSignatureContext()

	s := New(&sigmock.MockSignerSuite{MockSuite: sigmock.MockSuite{AcceptVal: true}, SignVal: []byte("mock signature")})
	signedDoc, err := s.Sign(context, []byte(validDoc), testutil.WithDocumentLoader(t))
	require.NoError(t, err)
	require.NotNil(t, signedDoc)

	context.SignatureRepresentation = proof.SignatureJWS
	signedJWSDoc, err := s.Sign(context, []byte(validDoc), testutil.WithDocumentLoader(t))
	require.NoError(t, err)
	require.NotNil(t, signedJWSDoc)

	var signedJWSMap map[string]interface{}
	err = json.Unmarshal(signedJWSDoc, &signedJWSMap)
	require.NoError(t, err)

	proofsIface, ok := signedJWSMap["proof"]
	require.True(t, ok)

	proofs, ok := proofsIface.([]interface{})
	require.True(t, ok)
	require.Len(t, proofs, 1)

	proofMap, ok := proofs[0].(map[string]interface{})
	require.True(t, ok)

	require.Equal(t, "creator", proofMap["creator"])
	require.Equal(t, "assertionMethod", proofMap["proofPurpose"])
	require.Equal(t, "Ed25519Signature2018", proofMap["type"])
	require.Contains(t, proofMap, "created")
	require.Contains(t, proofMap, "jws")
}

func TestDocumentSigner_SignErrors(t *testing.T) {
	context := getSignatureContext()

	s := New(&sigmock.MockSignerSuite{SignVal: []byte("mock signature")})

	// test invalid json
	signedDoc, err := s.Sign(context, []byte("not json"), testutil.WithDocumentLoader(t))
	require.NotNil(t, err)
	require.Nil(t, signedDoc)
	require.Contains(t, err.Error(), "failed to unmarshal json ld document")

	// test for signature suite not supported
	context = getSignatureContext()
	context.SignatureType = "non-existent"
	signedDoc, err = s.Sign(context, []byte(validDoc), testutil.WithDocumentLoader(t))
	require.NotNil(t, err)
	require.Nil(t, signedDoc)
	require.Contains(t, err.Error(), "signature type non-existent not supported")

	// test verify data creation error
	var validDocMap map[string]interface{}

	err = json.Unmarshal([]byte(validDoc), &validDocMap)
	require.NoError(t, err)

	validDocMap["@context"] = "invalid context"
	invalidDocBytes, err := json.Marshal(validDocMap)
	require.NoError(t, err)

	// test context error
	context = getSignatureContext()
	context.SignatureType = ""
	s = New(&sigmock.MockSignerSuite{
		MockSuite: sigmock.MockSuite{AcceptVal: true},
		SignVal:   []byte("signature"),
	})
	signedDoc, err = s.Sign(context, invalidDocBytes, testutil.WithDocumentLoader(t))
	require.NotNil(t, err)
	require.Nil(t, signedDoc)
	require.Contains(t, err.Error(), "signature type is missing")

	// test verify data creation error
	context = getSignatureContext()
	s = New(&sigmock.MockSignerSuite{MockSuite: sigmock.MockSuite{
		AcceptVal:               true,
		GetCanonicalDocumentErr: errors.New("mock error"),
	}})
	signedDoc, err = s.Sign(context, []byte(validDoc), testutil.WithDocumentLoader(t))
	require.NotNil(t, err)
	require.Nil(t, signedDoc)
	require.Contains(t, err.Error(), "mock error")

	// test signing error
	context = getSignatureContext()
	s = New(&sigmock.MockSignerSuite{
		MockSuite: sigmock.MockSuite{AcceptVal: true},
		SignErr:   errors.New("mock error"),
	})
	signedDoc, err = s.Sign(context, []byte(validDoc), testutil.WithDocumentLoader(t))
	require.NotNil(t, err)
	require.Nil(t, signedDoc)
	require.Contains(t, err.Error(), "mock error")
}

func TestDocumentSigner_isValidContext(t *testing.T) {
	s := New()

	context := getSignatureContext()
	context.SignatureType = ""
	signedDoc, err := s.Sign(context, []byte(validDoc), testutil.WithDocumentLoader(t))
	require.NotNil(t, err)
	require.Nil(t, signedDoc)
	require.Contains(t, err.Error(), "signature type is missing")
}

func getSignatureContext() *Context {
	return &Context{
		Creator:       "creator",
		SignatureType: signatureType,
	}
}
