/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operationparser

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/trustbloc/did-go/doc/json/canonicalizer"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/api/operation"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/encoder"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/versions/1_0/model"
)

const (
	longFormSeparator = ":"
	didSeparator      = ":"
)

// ParseDID inspects resolution request and returns:
// - did and create request in case of long form resolution
// - just did in case of short form resolution (common scenario).
func (p *Parser) ParseDID(namespace, shortOrLongFormDID string) (string, []byte, error) {
	var err error

	withoutNamespace := strings.ReplaceAll(shortOrLongFormDID, namespace+didSeparator, "")
	posLongFormSeparator := strings.Index(withoutNamespace, longFormSeparator)

	if posLongFormSeparator == -1 {
		// there is short form did
		return shortOrLongFormDID, nil, nil
	}

	// long form format: '<namespace>:<unique-portion>:Base64url(JCS({suffix-data, delta}))'
	endOfDIDPos := strings.LastIndex(shortOrLongFormDID, longFormSeparator)

	did := shortOrLongFormDID[0:endOfDIDPos]
	longFormDID := shortOrLongFormDID[endOfDIDPos+1:]

	createRequest, err := parseInitialState(longFormDID)
	if err != nil {
		return "", nil, err
	}

	createRequestBytes, err := canonicalizer.MarshalCanonical(createRequest)
	if err != nil {
		return "", nil, err
	}

	// return did and initial state
	return did, createRequestBytes, nil
}

// parse initial state will get create request from encoded initial value.
func parseInitialState(initialState string) (*model.CreateRequest, error) {
	decodedJCS, err := encoder.DecodeString(initialState)
	if err != nil {
		return nil, err
	}

	var createRequest model.CreateRequest

	err = json.Unmarshal(decodedJCS, &createRequest)
	if err != nil {
		return nil, err
	}

	expected, err := canonicalizer.MarshalCanonical(createRequest)
	if err != nil {
		return nil, err
	}

	if encoder.EncodeToString(expected) != initialState {
		return nil, errors.New("initial state is not valid")
	}

	createRequest.Operation = operation.TypeCreate

	return &createRequest, nil
}
