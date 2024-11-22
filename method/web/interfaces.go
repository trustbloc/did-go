/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package web

import "net/http"

//go:generate mockgen -destination interfaces_mocks_test.go -package web -source=interfaces.go

type roundTripper interface { //nolint
	http.RoundTripper
}
