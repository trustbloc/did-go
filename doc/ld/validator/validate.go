/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package validator

import (
	json2 "encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/piprate/json-gold/ld"

	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/did-go/doc/util/json"
)

type validateOpts struct {
	strict                                    bool
	jsonldDocumentLoader                      ld.DocumentLoader
	externalContext                           []string
	contextURIPositions                       []string
	jsonldIncludeDetailedStructureDiffOnError bool
}

// ValidateOpts sets jsonld validation options.
type ValidateOpts func(opts *validateOpts)

// WithDocumentLoader option is for passing custom JSON-LD document loader.
func WithDocumentLoader(jsonldDocumentLoader ld.DocumentLoader) ValidateOpts {
	return func(opts *validateOpts) {
		opts.jsonldDocumentLoader = jsonldDocumentLoader
	}
}

// WithJSONLDIncludeDetailedStructureDiffOnError option is for including detailed structure diff in error message.
func WithJSONLDIncludeDetailedStructureDiffOnError() ValidateOpts {
	return func(opts *validateOpts) {
		opts.jsonldIncludeDetailedStructureDiffOnError = true
	}
}

// WithExternalContext option is for definition of external context when doing JSON-LD operations.
func WithExternalContext(externalContext []string) ValidateOpts {
	return func(opts *validateOpts) {
		opts.externalContext = externalContext
	}
}

// WithStrictValidation sets if strict validation should be used.
func WithStrictValidation(checkStructure bool) ValidateOpts {
	return func(opts *validateOpts) {
		opts.strict = checkStructure
	}
}

// WithStrictContextURIPosition sets strict validation of URI position within context property.
// The index of uri in underlying slice represents the position of given uri in @context array.
// Can be used for verifiable credential base context validation.
func WithStrictContextURIPosition(uri string) ValidateOpts {
	return func(opts *validateOpts) {
		opts.contextURIPositions = append(opts.contextURIPositions, uri)
	}
}

func getValidateOpts(options []ValidateOpts) *validateOpts {
	result := &validateOpts{
		strict: true,
	}

	for _, opt := range options {
		opt(result)
	}

	return result
}

// ValidateJSONLD validates jsonld structure.
func ValidateJSONLD(doc string, options ...ValidateOpts) error {
	docMap, err := json.ToMap(doc)
	if err != nil {
		return fmt.Errorf("convert JSON-LD doc to map: %w", err)
	}

	return ValidateJSONLDMap(docMap, options...)
}

// ValidateJSONLDMap validates jsonld structure.
func ValidateJSONLDMap(
	docMap map[string]interface{},
	options ...ValidateOpts,
) error {
	opts := getValidateOpts(options)

	jsonldProc := processor.Default()

	docCompactedMap, err := jsonldProc.Compact(
		docMap,
		nil,
		processor.WithDocumentLoader(opts.jsonldDocumentLoader),
		processor.WithExternalContext(opts.externalContext...),
	)
	if err != nil {
		return fmt.Errorf("compact JSON-LD document: %w", err)
	}

	mapDiff := findMapDiff(docMap, docCompactedMap)
	if opts.strict && len(mapDiff) != 0 {
		errText := "JSON-LD doc has different structure after compaction"

		if opts.jsonldIncludeDetailedStructureDiffOnError {
			diff, _ := json2.Marshal(mapDiff) // nolint:errcheck

			errText = fmt.Sprintf("%s. Details: %v", errText, string(diff))
		}

		return errors.New(errText)
	}

	err = validateContextURIPosition(opts.contextURIPositions, docMap)
	if err != nil {
		return fmt.Errorf("validate context URI position: %w", err)
	}

	return nil
}

// ValidateJSONLDTypes validates JSON-LD types.
func ValidateJSONLDTypes(
	docMap map[string]interface{},
	options ...ValidateOpts,
) error {
	typesObj, typeObjOk := docMap["type"]

	if !typeObjOk {
		return nil
	}

	types, typesOk := typesObj.([]interface{})
	if !typesOk {
		typeStr, typeStrOk := typesObj.(string)
		if typeStrOk {
			types = []interface{}{typeStr}
		} else {
			return errors.New("type must be an array or string")
		}
	}

	if len(types) == 0 {
		return nil
	}

	documentTypes := map[string]struct{}{}
	for _, t := range types {
		documentTypes[fmt.Sprint(t)] = struct{}{}
	}

	jsonldProc := processor.Default()
	opts := getValidateOpts(options)

	docExpanded, err := jsonldProc.Expand(
		docMap,
		nil,
		processor.WithDocumentLoader(opts.jsonldDocumentLoader),
		processor.WithExternalContext(opts.externalContext...),
	)
	if err != nil {
		return errors.Join(err, errors.New("expand JSON-LD document"))
	}

	return validateTypesInExpandedDoc(docExpanded, documentTypes)
}

func validateTypesInExpandedDoc(
	docExpanded []any,
	types map[string]struct{},
) error {
	if len(docExpanded) != 1 {
		return fmt.Errorf("expanded document must contain only one element, got %d", len(docExpanded))
	}

	docExpandedMap, ok := docExpanded[0].(map[string]interface{})
	if !ok {
		return fmt.Errorf("document must be a map, got %s", reflect.TypeOf(docExpanded[0]).String())
	}

	expandedTypesObj, expandedTypesObjOk := docExpandedMap["@type"]
	if !expandedTypesObjOk {
		return errors.New("expanded document does not contain @type")
	}

	expandedTypes, expandedTypesOk := expandedTypesObj.([]interface{})
	if !expandedTypesOk {
		return errors.New("expanded @type must be an array")
	}

	if len(expandedTypes) == 0 {
		return nil
	}

	for _, t := range expandedTypes {
		typeStr := fmt.Sprint(t)

		if !strings.HasPrefix(typeStr, "http://") && !strings.HasPrefix(typeStr, "https://") {
			// expand should change types to full URIs.
			// example "VerifiableCredential" -> "https://www.w3.org/2018/credentials#VerifiableCredential".
			return fmt.Errorf("expanded document contains unexpanded type %s. "+
				"All types should be declared in contexts", typeStr)
		}
	}

	return nil
}

func validateContextURIPosition(contextURIPositions []string, docMap map[string]interface{}) error {
	if len(contextURIPositions) == 0 {
		return nil
	}

	var docContexts []interface{}

	switch t := docMap["@context"].(type) {
	case string:
		docContexts = append(docContexts, t)
	case []interface{}:
		docContexts = append(docContexts, t...)
	}

	if len(docContexts) < len(contextURIPositions) {
		return errors.New("doc context URIs amount mismatch")
	}

	for position, uri := range contextURIPositions {
		docURI, ok := docContexts[position].(string)
		if !ok {
			return fmt.Errorf("unsupported URI type %s", reflect.TypeOf(docContexts[position]).String())
		}

		if !strings.EqualFold(docURI, uri) {
			return fmt.Errorf("invalid context URI on position %d, %s expected", position, uri)
		}
	}

	return nil
}

// nolint:gocyclo,funlen
func mapsHaveSameStructure(
	originalMap,
	compactedMap map[string]interface{},
	path string,
) map[string][]*Diff {
	original := compactMap(originalMap)
	compacted := compactMap(compactedMap)

	if reflect.DeepEqual(original, compacted) {
		return nil
	}

	diffs := make(map[string][]*Diff)

	if len(original) != len(compacted) {
		for k, v := range original {
			diffKey := path + "." + k
			if _, ok := compacted[k]; !ok {
				diffs[diffKey] = append(diffs[diffKey], &Diff{OriginalValue: v, CompactedValue: "!missing!"})
			}
		}

		for k, v := range compacted {
			diffKey := path + "." + k

			if _, ok := original[k]; !ok {
				diffs[diffKey] = append(diffs[diffKey], &Diff{OriginalValue: "!missing!", CompactedValue: v})
			}
		}

		return diffs
	}

	for k, v1 := range original {
		diffKey := path + "." + k

		v1Map, isMap := v1.(map[string]interface{})
		if !isMap {
			continue
		}

		v2, present := compacted[k]
		if !present { // special case - the name of the map was mapped, cannot guess what's a new name
			continue // should not be counted as diff
		}

		v2Map, isMap := v2.(map[string]interface{})
		if !isMap {
			diffs[diffKey] = append(diffs[diffKey], &Diff{OriginalValue: v1, CompactedValue: v2})
		}

		if v2Map == nil {
			v2Map = make(map[string]interface{})
		}

		mp := mapsHaveSameStructure(v1Map, v2Map, diffKey)
		for m1, m2 := range mp {
			diffs[m1] = append(diffs[m1], m2...)
		}
	}

	return diffs
}

func findMapDiff(originalMap, compactedMap map[string]interface{}) map[string][]*Diff {
	originalMap = compactMap(originalMap)
	compactedMap = compactMap(compactedMap)

	return mapsHaveSameStructure(originalMap, compactedMap, "$")
}

func compactMap(m map[string]interface{}) map[string]interface{} {
	mCopy := make(map[string]interface{})

	for k, v := range m {
		// ignore context
		if k == "@context" {
			continue
		}

		vNorm := compactValue(v)

		switch kv := vNorm.(type) {
		case []interface{}:
			mCopy[k] = compactSlice(kv)

		case map[string]interface{}:
			mCopy[k] = compactMap(kv)

		default:
			mCopy[k] = vNorm
		}
	}

	return mCopy
}

func compactSlice(s []interface{}) []interface{} {
	sCopy := make([]interface{}, len(s))

	for i := range s {
		sItem := compactValue(s[i])

		switch sItem := sItem.(type) {
		case map[string]interface{}:
			sCopy[i] = compactMap(sItem)

		default:
			sCopy[i] = sItem
		}
	}

	return sCopy
}

func compactValue(v interface{}) interface{} {
	switch cv := v.(type) {
	case []interface{}:
		// consists of only one element
		if len(cv) == 1 {
			return compactValue(cv[0])
		}

		return cv

	case map[string]interface{}:
		// contains "id" element only
		if len(cv) == 1 {
			if _, ok := cv["id"]; ok {
				return cv["id"]
			}
		}

		return cv

	default:
		return cv
	}
}
