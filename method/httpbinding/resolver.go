/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package httpbinding

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/trustbloc/did-go/doc/did"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
)

const (
	// VersionIDOpt version id opt this option is not mandatory.
	VersionIDOpt = "versionID"
	// VersionTimeOpt version time opt this option is not mandatory.
	VersionTimeOpt = "versionTime"
	didLDJson      = "application/did+ld+json"
)

// resolveDID makes DID resolution via HTTP.
func (v *VDR) resolveDID(uri string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("HTTP create get request failed: %w", err)
	}

	req.Header.Add("Accept", didLDJson)

	authToken := v.resolveAuthToken

	if v.authTokenProvider != nil {
		v, errToken := v.authTokenProvider.AuthToken()
		if errToken != nil {
			return nil, errToken
		}

		authToken = "Bearer " + v
	}

	if authToken != "" {
		req.Header.Add("Authorization", authToken)
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP Get request failed: %w", err)
	}

	defer closeResponseBody(resp.Body)

	var gotBody []byte

	gotBody, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body failed: %w", err)
	}

	if resp.StatusCode == http.StatusOK && strings.Contains(resp.Header.Get("Content-Type"), didLDJson) {
		return gotBody, nil
	} else if resp.StatusCode == http.StatusNotFound {
		return nil, vdrapi.ErrNotFound
	}

	return nil, fmt.Errorf("unsupported response from DID resolver [%v] header [%s] body [%s]",
		resp.StatusCode, resp.Header.Get("Content-Type"), gotBody)
}

// Read implements didresolver.DidMethod.Read interface (https://w3c-ccg.github.io/did-resolution/#resolving-input)
func (v *VDR) Read(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) { //nolint: funlen,gocyclo
	didMethodOpts := &vdrapi.DIDMethodOpts{Values: make(map[string]interface{})}

	// Apply options
	for _, opt := range opts {
		opt(didMethodOpts)
	}

	versionID := ""
	versionTime := ""

	if didMethodOpts.Values[VersionIDOpt] != nil {
		var ok bool

		versionID, ok = didMethodOpts.Values[VersionIDOpt].(string)
		if !ok {
			return nil, errors.New("versionIDOpt is not string")
		}
	}

	if didMethodOpts.Values[VersionTimeOpt] != nil {
		var ok bool

		versionTime, ok = didMethodOpts.Values[VersionTimeOpt].(string)
		if !ok {
			return nil, errors.New("versionIDOpt is not string")
		}
	}

	if versionID != "" && versionTime != "" {
		return nil, errors.New("versionID and versionTime can not set at same time")
	}

	reqURL, err := url.ParseRequestURI(v.endpointURL)
	if err != nil {
		return nil, fmt.Errorf("url parse request uri failed: %w", err)
	}

	reqURL.Path = path.Join(reqURL.Path, didID)

	if versionID != "" {
		reqURL.RawQuery = fmt.Sprintf("versionId=%s", versionID) //nolint:perfsprint
	}

	if versionTime != "" {
		reqURL.RawQuery = fmt.Sprintf("versionTime=%s", versionTime) //nolint:perfsprint
	}

	data, err := v.resolveDID(reqURL.String())
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return nil, vdrapi.ErrNotFound
	}

	// TODO: this code is looking strange, ParseDocumentResolution can return ErrDIDDocumentNotExist
	// Is it possible that we find did, but it not contains did document?
	documentResolution, err := did.ParseDocumentResolution(data)
	if err != nil {
		if !errors.Is(err, did.ErrDIDDocumentNotExist) {
			return nil, err
		}

		errLogger.Printf("parse document resolution failed %v", err)
	} else {
		return documentResolution, nil
	}

	didDoc, err := did.ParseDocument(data)
	if err != nil {
		return nil, err
	}

	didDoc = interopPreprocess(didDoc)

	return &did.DocResolution{DIDDocument: didDoc}, nil
}
