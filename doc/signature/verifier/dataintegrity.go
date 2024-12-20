/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifier

//import (
//	"encoding/json"
//	"errors"
//
//	"github.com/trustbloc/vc-go/dataintegrity/models"
//)
//
//const defaultProofPurpose = "assertionMethod"
//
//func checkDataIntegrityProof(jsonLdObject map[string]interface{}, opts *verifyDataIntegrityOpts) error {
//	if opts == nil || opts.Verifier == nil {
//		return errors.New("data integrity proof needs data integrity verifier")
//	}
//
//	docBytes, err := json.Marshal(jsonLdObject)
//	if err != nil {
//		return err
//	}
//
//	if opts.Purpose == "" {
//		opts.Purpose = defaultProofPurpose
//	}
//
//	return opts.Verifier.VerifyProof(docBytes, &models.ProofOptions{
//		ProofType: models.DataIntegrityProof,
//		Purpose:   opts.Purpose,
//		Domain:    opts.Domain,
//		Challenge: opts.Challenge,
//	})
//}
