/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwk

import (
	"crypto/elliptic"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestCurveSize(t *testing.T) {
	require.Equal(t, 32, curveSize(btcec.S256()))
	require.Equal(t, 32, curveSize(elliptic.P256()))
	require.Equal(t, 28, curveSize(elliptic.P224()))
	require.Equal(t, 48, curveSize(elliptic.P384()))
	require.Equal(t, 66, curveSize(elliptic.P521()))
}
