/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpbinding

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/trustbloc/did-go/doc/did"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
)

var errLogger = log.New(os.Stderr, " [did-go/vdr/httpbinding] ", log.Ldate|log.Ltime|log.LUTC)

type authTokenProvider interface {
	AuthToken() (string, error)
}

// VDR via HTTP(s) endpoint.
type VDR struct {
	endpointURL       string
	client            *http.Client
	accept            Accept
	resolveAuthToken  string
	authTokenProvider authTokenProvider
}

// Accept is method to accept did method.
type Accept func(method string) bool

// New creates new DID Resolver.
func New(endpointURL string, opts ...Option) (*VDR, error) {
	v := &VDR{client: &http.Client{}, accept: func(method string) bool { return true }}

	for _, opt := range opts {
		opt(v)
	}

	// Validate host
	_, err := url.ParseRequestURI(endpointURL)
	if err != nil {
		return nil, fmt.Errorf("base URL invalid: %w", err)
	}

	v.endpointURL = endpointURL

	return v, nil
}

// Accept did method - attempt to resolve any method.
func (v *VDR) Accept(method string, opts ...vdrapi.DIDMethodOption) bool {
	return v.accept(method)
}

// Create did doc.
func (v *VDR) Create(didDoc *did.Doc, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	return nil, errors.New("build not supported in http binding vdr")
}

// Close frees resources being maintained by vdr.
func (v *VDR) Close() error {
	return nil
}

// Update did doc.
func (v *VDR) Update(didDoc *did.Doc, opts ...vdrapi.DIDMethodOption) error {
	return errors.New("not supported")
}

// Deactivate did doc.
func (v *VDR) Deactivate(didID string, opts ...vdrapi.DIDMethodOption) error {
	return errors.New("not supported")
}

// Option configures the peer vdr.
type Option func(opts *VDR)

// WithTimeout option is for definition of HTTP(s) timeout value of DID Resolver.
func WithTimeout(timeout time.Duration) Option {
	return func(opts *VDR) {
		opts.client.Timeout = timeout
	}
}

// WithHTTPClient option is for custom http client.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(opts *VDR) {
		opts.client = httpClient
	}
}

// WithAccept option is for accept did method.
func WithAccept(accept Accept) Option {
	return func(opts *VDR) {
		opts.accept = accept
	}
}

// WithResolveAuthToken add auth token for resolve.
func WithResolveAuthToken(authToken string) Option {
	return func(opts *VDR) {
		opts.resolveAuthToken = "Bearer " + authToken
	}
}

// WithResolveAuthTokenProvider add auth token provider.
func WithResolveAuthTokenProvider(p authTokenProvider) Option {
	return func(opts *VDR) {
		opts.authTokenProvider = p
	}
}

func closeResponseBody(respBody io.Closer) {
	e := respBody.Close()
	if e != nil {
		errLogger.Printf("Failed to close response body: %v", e)
	}
}
