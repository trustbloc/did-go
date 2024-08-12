/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package validator

// Diff represents the difference between two objects.
type Diff struct {
	OriginalValue  interface{}
	CompactedValue interface{}
}
