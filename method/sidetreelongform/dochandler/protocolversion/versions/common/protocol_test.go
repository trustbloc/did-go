/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-go/pkg/api/protocol"
	coremocks "github.com/trustbloc/sidetree-go/pkg/mocks"

	"github.com/trustbloc/did-go/method/sidetreelongform/dochandler/protocolversion/versions/common"
)

func TestProtocolVersion(t *testing.T) {
	p := &common.ProtocolVersion{
		VersionStr: "1.1",
		P: protocol.Protocol{
			GenesisTime: 1000,
		},
		OpParser:     &coremocks.OperationParser{},
		OpApplier:    &coremocks.OperationApplier{},
		DocValidator: &coremocks.DocumentValidator{},
	}

	require.Equal(t, p.VersionStr, p.Version())
	require.Equal(t, p.P, p.Protocol())
	require.Equal(t, p.OpParser, p.OperationParser())
	require.Equal(t, p.OpApplier, p.OperationApplier())
	require.Equal(t, p.DocValidator, p.DocumentValidator())
}
