/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package validator

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ldcontext "github.com/trustbloc/did-go/doc/ld/context"
	ldloader "github.com/trustbloc/did-go/doc/ld/documentloader"
	ldtestutil "github.com/trustbloc/did-go/doc/ld/testutil"
)

//nolint:gochecknoglobals
var (
	//go:embed testdata/context/context3.jsonld
	context3 []byte
	//go:embed testdata/context/context4.jsonld
	context4 []byte
	//go:embed testdata/context/context5.jsonld
	context5 []byte
	//go:embed testdata/context/context6.jsonld
	context6 []byte

	//go:embed testdata/context/wallet_v1.jsonld
	walletV1Context []byte

	//go:embed testdata/extended_model.json
	extendedModel string
)

func Test_ValidateJSONLD(t *testing.T) {
	t.Run("Extended both basic VC and subject model", func(t *testing.T) {
		contextURL := "http://127.0.0.1?context=3"

		vcJSONTemplate := `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "%s"
  ],
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential",
    "CustomExt12"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "referenceNumber": 83294847,
  "credentialSubject": [
    {
      "id": "did:example:abcdef1234567",
      "name": "Jane Doe",
      "favoriteFood": "Papaya"
    },
    {
      "id": "did:example:abcdef1234568",
      "name": "Alex"
    },
    {
      "id": "did:example:abcdef1234569",
      "name": "Justin"
    }
  ],
  "proof": [
    {
      "type": "Ed25519Signature2018",
      "created": "2020-04-10T21:35:35Z",
      "verificationMethod": "did:key:z6MkjRag",
      "proofPurpose": "assertionMethod",
      "jws": "eyJ..l9d0Y"
    },
    {
      "type": "Ed25519Signature2018",
      "created": "2020-04-11T21:35:35Z",
      "verificationMethod": "did:key:z6MkjRll",
      "proofPurpose": "assertionMethod",
      "jws": "eyJ..l9dZq"
    }
  ],
  "termsOfUse": [
    {
      "type": [
        "IssuerPolicy",
        "HolderPolicy"
      ],
      "id": "http://example.com/policies/credential/4"
    },
    {
      "type": [
        "IssuerPolicy",
        "HolderPolicy"
      ],
      "id": "http://example.com/policies/credential/5"
    }
  ]
}
`
		vc := fmt.Sprintf(vcJSONTemplate, contextURL)

		loader := createTestDocumentLoader(t, ldcontext.Document{
			URL:     "http://127.0.0.1?context=3",
			Content: context3,
		})

		err := ValidateJSONLD(vc, WithDocumentLoader(loader))
		require.NoError(t, err)
	})

	t.Run("Extended basic VC model, credentialSubject is defined as string (ID only)", func(t *testing.T) {
		// Use a different VC to verify the case when credentialSubject is a string (i.e. ID is defined only).

		contextURL := "http://127.0.0.1?context=4"

		vcJSONTemplate := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "%s"
  ],
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential",
    "CustomExt12"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "referenceNumber": 83294847,
  "credentialSubject": "did:example:abcdef1234567"
}
`
		vcJSON := fmt.Sprintf(vcJSONTemplate, contextURL)

		loader := createTestDocumentLoader(t, ldcontext.Document{
			URL:     "http://127.0.0.1?context=4",
			Content: context4,
		})

		err := ValidateJSONLD(vcJSON, WithDocumentLoader(loader))
		require.NoError(t, err)
	})
}

func Test_ValidateJSONLDWithExtraUndefinedFields(t *testing.T) {
	contextURL := "http://127.0.0.1?context=5"

	vcJSONTemplate := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "%s"
  ],
  "id": "http://example.com/credentials/4643",
  "type": ["VerifiableCredential", "CustomExt12"],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "referenceNumber": 83294847,
  "credentialSubject": {
    "id": "did:example:abcdef1234567",
    "name": "Jane Doe",
    "favoriteFood": "Papaya"
  }
}
`
	vc := fmt.Sprintf(vcJSONTemplate, contextURL)

	loader := createTestDocumentLoader(t, ldcontext.Document{
		URL:     "http://127.0.0.1?context=5",
		Content: context5,
	})

	err := ValidateJSONLD(vc, WithDocumentLoader(loader))
	require.Error(t, err)
	require.EqualError(t, err, "JSON-LD doc has different structure after compaction")
}

func Test_ValidateJSONLDWithExtraUndefinedSubjectFields(t *testing.T) {
	contextURL := "http://127.0.0.1?context=6"

	loader := createTestDocumentLoader(t, ldcontext.Document{
		URL:     contextURL,
		Content: context6,
	})

	t.Run("Extended basic VC model, credentialSubject is defined as object - undefined fields present",
		func(t *testing.T) {
			// Use a different VC to verify the case when credentialSubject is an array.
			vcJSONTemplate := extendedModel

			vcJSON := fmt.Sprintf(vcJSONTemplate, contextURL)

			err := ValidateJSONLD(vcJSON, WithDocumentLoader(loader))
			require.Error(t, err)
			require.EqualError(t, err, "JSON-LD doc has different structure after compaction")
		})

	t.Run("Extended basic VC model, credentialSubject is defined as object - undefined fields present and details",
		func(t *testing.T) {
			// Use a different VC to verify the case when credentialSubject is an array.
			vcJSONTemplate := extendedModel

			vcJSON := fmt.Sprintf(vcJSONTemplate, contextURL)

			err := ValidateJSONLD(vcJSON, WithDocumentLoader(loader), WithJSONLDIncludeDetailedStructureDiffOnError())
			require.Error(t, err)
			require.EqualError(t, err, "JSON-LD doc has different structure after compaction. Details: {\"$.credentialSubject\":[{\"OriginalValue\":{\"favoriteFood\":\"Papaya\",\"id\":\"did:example:abcdef1234567\",\"name\":\"Jane Doe\"},\"CompactedValue\":\"did:example:abcdef1234567\"}],\"$.credentialSubject.favoriteFood\":[{\"OriginalValue\":\"Papaya\",\"CompactedValue\":\"!missing!\"}],\"$.credentialSubject.id\":[{\"OriginalValue\":\"did:example:abcdef1234567\",\"CompactedValue\":\"!missing!\"}],\"$.credentialSubject.name\":[{\"OriginalValue\":\"Jane Doe\",\"CompactedValue\":\"!missing!\"}]}") //nolint:lll
		})

	t.Run("Extended basic VC model, credentialSubject is defined as array - undefined fields present", func(t *testing.T) {
		// Use a different VC to verify the case when credentialSubject is an array.
		vcJSONTemplate := extendedModel

		vcJSON := fmt.Sprintf(vcJSONTemplate, contextURL)

		err := ValidateJSONLD(vcJSON, WithDocumentLoader(loader))
		require.Error(t, err)
		require.EqualError(t, err, "JSON-LD doc has different structure after compaction")
	})
}

func Test_ValidateJSONLD_WithExtraUndefinedFieldsInProof(t *testing.T) {
	vcJSONWithValidProof := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "credentialSubject": [
    {
      "id": "did:example:abcdef1234567"
    }
  ],
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2020-04-10T21:35:35Z",
    "verificationMethod": "did:key:z6MkjRag",
    "proofPurpose": "assertionMethod",
    "jws": "eyJ..l9d0Y"
  }
}
`

	err := ValidateJSONLD(vcJSONWithValidProof, WithDocumentLoader(createTestDocumentLoader(t)))
	require.NoError(t, err)

	// "newProp" field is present in the proof
	vcJSONWithInvalidProof := `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "credentialSubject": [
    {
      "id": "did:example:abcdef1234567"
    }
  ],
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2020-04-10T21:35:35Z",
    "verificationMethod": "did:key:z6MkjRag",
    "proofPurpose": "assertionMethod",
    "jws": "eyJ..l9d0Y",
    "newProp": "foo"
  }
}`

	err = ValidateJSONLD(vcJSONWithInvalidProof, WithDocumentLoader(createTestDocumentLoader(t)))

	require.Error(t, err)
	require.EqualError(t, err, "JSON-LD doc has different structure after compaction")
}

func Test_ValidateJSONLD_CornerErrorCases(t *testing.T) {
	t.Run("Invalid JSON input", func(t *testing.T) {
		err := ValidateJSONLD("not a json", WithDocumentLoader(createTestDocumentLoader(t)))
		require.Error(t, err)
		require.Contains(t, err.Error(), "convert JSON-LD doc to map")
	})

	t.Run("JSON-LD compact error", func(t *testing.T) {
		vcJSONTemplate := `
{
  "@context": 777,
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential",
    "CustomExt12"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "referenceNumber": 83294847,
  "credentialSubject": "did:example:abcdef1234567"
}
`

		err := ValidateJSONLD(vcJSONTemplate, WithDocumentLoader(createTestDocumentLoader(t)))
		require.Error(t, err)
		require.Contains(t, err.Error(), "compact JSON-LD document")
	})

	t.Run("JSON-LD WithStrictContextURIPosition invalid context", func(t *testing.T) {
		vcJSONTemplate := `
{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "credentialSubject": "did:example:abcdef1234567"
}
`

		err := ValidateJSONLD(vcJSONTemplate,
			WithDocumentLoader(createTestDocumentLoader(t)),
			WithStrictContextURIPosition("https://www.w3.org/2018/credentials/v1"),
			WithStrictContextURIPosition("https://www.w3.org/2018/credentials/examples/v1"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "doc context URIs amount mismatch")
	})

	t.Run("JSON-LD WithStrictContextURIPosition invalid context URI amount", func(t *testing.T) {
		vcJSONTemplate := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "credentialSubject": "did:example:abcdef1234567"
}
`

		err := ValidateJSONLD(vcJSONTemplate,
			WithDocumentLoader(createTestDocumentLoader(t)),
			WithStrictContextURIPosition("https://www.w3.org/2018/credentials/v1"),
			WithStrictContextURIPosition("https://www.w3.org/2018/credentials/examples/v1"),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "doc context URIs amount mismatch")
	})

	t.Run("JSON-LD WithStrictContextURIPosition validate context URI position", func(t *testing.T) {
		vcJSONTemplate := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
	"https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "credentialSubject": "did:example:abcdef1234567"
}
`

		err := ValidateJSONLD(vcJSONTemplate,
			WithDocumentLoader(createTestDocumentLoader(t)),
			WithStrictContextURIPosition("https://www.w3.org/2018/credentials/examples/v1"),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid context URI on position")

		err = ValidateJSONLD(vcJSONTemplate,
			WithDocumentLoader(createTestDocumentLoader(t)),
			WithStrictContextURIPosition("https://www.w3.org/2018/credentials/v1"),
			WithStrictContextURIPosition("https://www.w3.org/2018/credentials/examples/v1"),
		)
		require.NoError(t, err)
	})
}

// nolint:gochecknoglobals // needed to avoid Go compiler perf optimizations for benchmarks.
var MajorSink string

func Benchmark_ValidateJSONLD(b *testing.B) {
	var sink string

	b.Run("Extended both basic VC and subject model", func(b *testing.B) {
		contextURL := "http://127.0.0.1?context=3"

		vcJSONTemplate := `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "%s"
  ],
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential",
    "CustomExt12"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "referenceNumber": 83294847,
  "credentialSubject": [
    {
      "id": "did:example:abcdef1234567",
      "name": "Jane Doe",
      "favoriteFood": "Papaya"
    },
    {
      "id": "did:example:abcdef1234568",
      "name": "Alex"
    },
    {
      "id": "did:example:abcdef1234569",
      "name": "Justin"
    }
  ],
  "proof": [
    {
      "type": "Ed25519Signature2018",
      "created": "2020-04-10T21:35:35Z",
      "verificationMethod": "did:key:z6MkjRag",
      "proofPurpose": "assertionMethod",
      "jws": "eyJ..l9d0Y"
    },
    {
      "type": "Ed25519Signature2018",
      "created": "2020-04-11T21:35:35Z",
      "verificationMethod": "did:key:z6MkjRll",
      "proofPurpose": "assertionMethod",
      "jws": "eyJ..l9dZq"
    }
  ],
  "termsOfUse": [
    {
      "type": [
        "IssuerPolicy",
        "HolderPolicy"
      ],
      "id": "http://example.com/policies/credential/4"
    },
    {
      "type": [
        "IssuerPolicy",
        "HolderPolicy"
      ],
      "id": "http://example.com/policies/credential/5"
    }
  ]
}
`

		vc := fmt.Sprintf(vcJSONTemplate, contextURL)

		b.RunParallel(func(pb *testing.PB) {
			b.ResetTimer()

			for pb.Next() {
				loader, err := ldtestutil.DocumentLoader(ldcontext.Document{
					URL:     "http://127.0.0.1?context=3",
					Content: context3,
				})
				require.NoError(b, err)

				err = ValidateJSONLD(vc, WithDocumentLoader(loader))
				require.NoError(b, err)

				sink = "basic_compact_test"
			}

			MajorSink = sink
		})
	})

	b.Run("Extended basic VC model, credentialSubject is defined as string (ID only)", func(b *testing.B) {
		// Use a different VC to verify the case when credentialSubject is a string (i.e. ID is defined only).

		contextURL := "http://127.0.0.1?context=4"

		vcJSONTemplate := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "%s"
  ],
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential",
    "CustomExt12"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "referenceNumber": 83294847,
  "credentialSubject": "did:example:abcdef1234567"
}
`
		vcJSON := fmt.Sprintf(vcJSONTemplate, contextURL)

		b.RunParallel(func(pb *testing.PB) {
			b.ResetTimer()

			for pb.Next() {
				loader, err := ldtestutil.DocumentLoader(ldcontext.Document{
					URL:     "http://127.0.0.1?context=4",
					Content: context4,
				})
				require.NoError(b, err)

				err = ValidateJSONLD(vcJSON, WithDocumentLoader(loader))
				require.NoError(b, err)

				sink = "extended_compact_test"
			}

			MajorSink = sink
		})
	})

	b.Run("Extended both basic VC and subject model", func(b *testing.B) {
		const testMetadata = `{
  			"@context": ["https://w3id.org/wallet/v1"],
  		  	"id": "test-id",
    		"type": "Person",
    		"name": "John Smith",
    		"image": "https://via.placeholder.com/150",
    		"description" : "Professional software developer for Acme Corp."
  		}`

		b.RunParallel(func(pb *testing.PB) {
			b.ResetTimer()

			for pb.Next() {
				loader, err := ldtestutil.DocumentLoader(ldcontext.Document{
					URL:     "https://w3id.org/wallet/v1",
					Content: walletV1Context,
				})
				require.NoError(b, err)

				err = ValidateJSONLD(testMetadata, WithDocumentLoader(loader))
				require.NoError(b, err)

				sink = "basic_compact_test"
			}

			MajorSink = sink
		})
	})
}

func TestDiffOnEduCred(t *testing.T) {
	diff := findMapDiff(map[string]any{
		"degree": map[string]any{
			"type": "BachelorDegree",
			"name": "Bachelor of Science and Arts",
		},
		"alumniOf": map[string]any{
			"id": "some-id",
			"name": []any{
				map[string]any{
					"value": "University",
					"lang":  "en",
				},
			},
		},
		"type": []interface{}{
			"VerifiableCredential",
			"UniversityDegreeCredential",
		},
	}, map[string]any{
		"degree": map[string]any{
			"type": "BachelorDegree",
			"name": "Bachelor of Science and Arts",
		},
		"schema:alumniOf": map[string]any{
			"id":          "some-id",
			"schema:name": []any{},
		},
		"type": []interface{}{
			"VerifiableCredential",
			"UniversityDegreeCredential",
		},
	})

	require.Len(t, diff, 0)
}

//go:embed testdata/credential_with_invalid_type.json
var credentialWithInvalidType []byte

//go:embed testdata/credential_with_valid_type.json
var credentialWithValidType []byte

func TestValidateType(t *testing.T) {
	loader := ld.NewCachingDocumentLoader(ld.NewDefaultDocumentLoader(http.DefaultClient))

	t.Run("invalid type", func(t *testing.T) {
		var parsed map[string]interface{}
		assert.NoError(t, json.Unmarshal(credentialWithInvalidType, &parsed))

		err := ValidateJSONLDTypes(parsed, WithDocumentLoader(loader))
		assert.ErrorContains(
			t,
			err,
			"expanded document contains unexpanded type UnknownType. All types should be declared in contexts",
		)
	})

	t.Run("no types", func(t *testing.T) {
		var parsed map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(`{"a" : "b"}`), &parsed))

		assert.NoError(t, ValidateJSONLDTypes(parsed, WithDocumentLoader(loader)))
	})

	t.Run("valid", func(t *testing.T) {
		var parsed map[string]interface{}
		assert.NoError(t, json.Unmarshal(credentialWithValidType, &parsed))

		assert.NoError(t, ValidateJSONLDTypes(parsed, WithDocumentLoader(loader)))
	})

	t.Run("invalid length", func(t *testing.T) {
		assert.ErrorContains(t, validateTypesInExpandedDoc([]any{
			1,
			2,
		}, nil), "expanded document must contain only one element")
	})

	t.Run("invalid type", func(t *testing.T) {
		assert.ErrorContains(t, validateTypesInExpandedDoc([]any{
			1,
		}, nil), "document must be a map")
	})

	t.Run("no type", func(t *testing.T) {
		assert.ErrorContains(t, validateTypesInExpandedDoc([]any{
			map[string]any{
				"xx": "yy",
			},
		}, nil), "expanded document does not contain")
	})

	t.Run("no type", func(t *testing.T) {
		assert.ErrorContains(t, validateTypesInExpandedDoc([]any{
			map[string]any{
				"@type": "yy",
			},
		}, nil), "expanded @type must be an array")
	})

	t.Run("no records", func(t *testing.T) {
		assert.NoError(t, validateTypesInExpandedDoc([]any{
			map[string]any{
				"@type": []any{},
			},
		}, nil))
	})
}

func createTestDocumentLoader(t *testing.T, extraContexts ...ldcontext.Document) *ldloader.DocumentLoader {
	t.Helper()

	loader, err := ldtestutil.DocumentLoader(extraContexts...)
	require.NoError(t, err)

	return loader
}
