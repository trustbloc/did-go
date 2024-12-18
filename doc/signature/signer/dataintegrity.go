/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"encoding/json"
	"fmt"
	"github.com/trustbloc/vc-go/dataintegrity"
	"github.com/trustbloc/vc-go/dataintegrity/models"
	"time"

	"github.com/trustbloc/did-go/doc/ld/proof"
)

// DataIntegrityProofContext holds parameters for creating a Data Integrity Proof.
type DataIntegrityProofContext struct {
	SigningKeyID string     // eg did:foo:bar#key-1
	ProofPurpose string     // assertionMethod
	CryptoSuite  string     // ecdsa-2019
	Created      *time.Time //
	Domain       string     //
	Challenge    string     //
}

// AddDataIntegrityProof adds a Data Integrity Proof to the document.
func (signer *DocumentSigner) AddDataIntegrityProof(
	doc []byte,
	context *DataIntegrityProofContext,
	diSigner *dataintegrity.Signer,
) ([]byte, error) {
	var jsonLdObject map[string]interface{}

	err := json.Unmarshal(doc, &jsonLdObject)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal json ld document: %w", err)
	}

	// TODO: rewrite to use json object instead bytes presentation
	diProof, err := createDataIntegrityProof(context, doc, diSigner)
	if err != nil {
		return nil, fmt.Errorf("create data integrity proof: %w", err)
	}

	if err = proof.AddProof(jsonLdObject, diProof); err != nil {
		return nil, fmt.Errorf("add data integrity proof: %w", err)
	}

	signedDoc, err := json.Marshal(jsonLdObject)
	if err != nil {
		return nil, err
	}

	return signedDoc, nil
}

func createDataIntegrityProof(
	context *DataIntegrityProofContext,
	ldBytes []byte,
	signer *dataintegrity.Signer,
) (*proof.Proof, error) {
	var createdTime time.Time
	if context.Created == nil {
		createdTime = time.Now()
	} else {
		createdTime = *context.Created
	}

	if context.ProofPurpose == "" {
		context.ProofPurpose = defaultProofPurpose
	}

	signed, err := signer.AddProof(ldBytes, &models.ProofOptions{
		Purpose:              context.ProofPurpose,
		VerificationMethodID: context.SigningKeyID,
		ProofType:            models.DataIntegrityProof,
		SuiteType:            context.CryptoSuite,
		Domain:               context.Domain,
		Challenge:            context.Challenge,
		Created:              createdTime,
	})
	if err != nil {
		return nil, fmt.Errorf("add proof: %w", err)
	}

	type rawProof struct {
		Proof map[string]interface{} `json:"proof,omitempty"`
	}

	// Get a proof from json-ld document.
	var rProof rawProof

	err = json.Unmarshal(signed, &rProof)
	if err != nil {
		return nil, err
	}

	diProof, err := proof.NewProof(rProof.Proof)
	if err != nil {
		return nil, fmt.Errorf("new proof: %w", err)
	}

	return diProof, nil
}
