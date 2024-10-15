/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package web

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	urlapi "net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	didapi "github.com/trustbloc/did-go/doc/did"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
)

const (
	prefix = "did:web:"

	validURL                = "www.example.org"
	validURLWithPath        = "www.example.org/user/example"
	validDID                = prefix + validURL
	validDIDWithPath        = prefix + "www.example.org:user:example"
	validDIDWithHost        = prefix + "localhost%3A8080"
	validDIDWithHostAndPath = prefix + "localhost%3A8080:user:example"

	invalidDIDNoMethod = "did:" + validURL
	invalidDIDNoPrefix = validURL

	validDoc = `{
  		"@context": ["https://w3id.org/did/v1"],
  		"id": "%s"
	}`

	invalidDoc = `{}`
)

func TestParseDID(t *testing.T) {
	t.Run("test parse did success", func(t *testing.T) {
		address, host, err := parseDIDWeb(validDID, false)
		require.NoError(t, err)
		require.Equal(t, "https://"+validURL+defaultPath, address)
		require.Equal(t, validURL, host)
		address, host, err = parseDIDWeb(validDIDWithPath, false)
		require.NoError(t, err)
		require.Equal(t, "https://"+validURLWithPath+documentPath, address)
		require.Equal(t, validURL, host)
		address, host, err = parseDIDWeb(validDIDWithHost, false)
		require.NoError(t, err)
		require.Equal(t, "https://localhost:8080/.well-known/did.json", address)
		require.Equal(t, "localhost", host)
		address, host, err = parseDIDWeb(validDIDWithHostAndPath, false)
		require.NoError(t, err)
		require.Equal(t, "https://localhost:8080/user/example/did.json", address)
		require.Equal(t, "localhost", host)
	})

	t.Run("test parse did failure", func(t *testing.T) {
		v := New()
		doc, err := v.Read(invalidDIDNoMethod)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "does not conform to generic did standard")
		doc, err = v.Read(invalidDIDNoPrefix)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "does not conform to generic did standard")
	})
}

func TestResolveDID(t *testing.T) {
	t.Run("test resolve did with request failure", func(t *testing.T) {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := w.Write([]byte(invalidDoc))
			require.NoError(t, err)
		}))
		defer s.Close()
		did := fmt.Sprintf("did:web:%s", urlapi.QueryEscape(strings.TrimPrefix(s.URL, "https://")))
		v := New()
		doc, err := v.Read(did)
		require.Nil(t, doc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "http request unsuccessful")
	})
	t.Run("test resolve did with invalid doc format failure", func(t *testing.T) {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := w.Write([]byte(invalidDoc))
			require.NoError(t, err)
		}))
		defer s.Close()
		did := fmt.Sprintf("did:web:%s", urlapi.QueryEscape(strings.TrimPrefix(s.URL, "https://")))
		v := New()
		doc, err := v.Read(did, vdrapi.WithOption(HTTPClientOpt, s.Client()))
		require.Nil(t, doc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error parsing did doc")
	})
	t.Run("test resolve did success", func(t *testing.T) {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data := fmt.Sprintf(validDoc, "did:web:"+urlapi.QueryEscape(r.Host))
			_, err := w.Write([]byte(data))
			require.NoError(t, err)
		}))
		defer s.Close()
		did := fmt.Sprintf("did:web:%s", urlapi.QueryEscape(strings.TrimPrefix(s.URL, "https://")))
		v := New()
		docResolution, err := v.Read(did, vdrapi.WithOption(HTTPClientOpt, s.Client()))
		require.Nil(t, err)
		data := fmt.Sprintf(validDoc, did)
		expectedDoc, err := didapi.ParseDocument([]byte(data))
		require.Nil(t, err)
		require.Equal(t, expectedDoc, docResolution.DIDDocument)
	})
	t.Run("test resolve with wrong did id", func(t *testing.T) {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data := fmt.Sprintf(validDoc, "did:web:123")
			_, err := w.Write([]byte(data))
			require.NoError(t, err)
		}))
		defer s.Close()
		did := fmt.Sprintf("did:web:%s", urlapi.QueryEscape(strings.TrimPrefix(s.URL, "https://")))
		v := New()
		doc, err := v.Read(did, vdrapi.WithOption(HTTPClientOpt, s.Client()))
		require.Nil(t, doc)
		require.ErrorContains(t, err, "did id did:web:123 not matching did")
	})
	t.Run("test resolve did with path success", func(t *testing.T) {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data := fmt.Sprintf(validDoc, "did:web:"+urlapi.QueryEscape(r.Host)+":user:example")
			_, err := w.Write([]byte(data))
			require.NoError(t, err)
		}))
		defer s.Close()
		did := fmt.Sprintf("did:web:%s:user:example", urlapi.QueryEscape(strings.TrimPrefix(s.URL, "https://")))
		v := New()
		docResolution, err := v.Read(did, vdrapi.WithOption(HTTPClientOpt, s.Client()))
		require.Nil(t, err)
		data := fmt.Sprintf(validDoc, did)
		expectedDoc, err := didapi.ParseDocument([]byte(data))
		require.Nil(t, err)
		require.Equal(t, expectedDoc, docResolution.DIDDocument)
	})
	t.Run("test not found", func(t *testing.T) {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer s.Close()

		did := fmt.Sprintf("did:web:%s:alice", urlapi.QueryEscape(strings.TrimPrefix(s.URL, "https://")))

		v := New()
		_, err := v.Read(did, vdrapi.WithOption(HTTPClientOpt, s.Client()))
		require.Error(t, err)
	})
}

func TestResolveDomain(t *testing.T) {
	aliceDoc, err := ioutil.ReadFile("testdata/alice/did.json")
	require.NoError(t, err)

	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/did.json" {
			http.NotFound(w, r)
			return
		}
		data := fmt.Sprintf(string(aliceDoc), "did:web:"+urlapi.QueryEscape(r.Host))
		_, err := w.Write([]byte(data))
		require.NoError(t, err)
	}))
	defer s.Close()

	t.Run("resolve did:web:host", func(t *testing.T) {
		did := fmt.Sprintf("did:web:%s", urlapi.QueryEscape(strings.TrimPrefix(s.URL, "https://")))

		v := New()
		docResolution, err := v.Read(did, vdrapi.WithOption(HTTPClientOpt, s.Client()))
		require.Nil(t, err)
		data := fmt.Sprintf(string(aliceDoc), did)

		expectedDoc, err := didapi.ParseDocument([]byte(data))
		require.Nil(t, err)
		require.Equal(t, expectedDoc, docResolution.DIDDocument)
	})
}

func TestResolveWebFixtures(t *testing.T) {
	aliceDoc, err := ioutil.ReadFile("testdata/alice/did.json")
	require.NoError(t, err)

	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/alice/did.json" {
			http.NotFound(w, r)
			return
		}

		data := fmt.Sprintf(string(aliceDoc), "did:web:"+urlapi.QueryEscape(r.Host)+":alice")
		_, err := w.Write([]byte(data))
		require.NoError(t, err)
	}))
	defer s.Close()

	t.Run("resolve did:web:host:alice", func(t *testing.T) {
		did := fmt.Sprintf("did:web:%s:alice", urlapi.QueryEscape(strings.TrimPrefix(s.URL, "https://")))

		v := New()
		docResolution, err := v.Read(did, vdrapi.WithOption(HTTPClientOpt, s.Client()))
		require.Nil(t, err)
		data := fmt.Sprintf(string(aliceDoc), did)

		expectedDoc, err := didapi.ParseDocument([]byte(data))
		require.Nil(t, err)
		require.Equal(t, expectedDoc, docResolution.DIDDocument)
	})
}
