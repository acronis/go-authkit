/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptoken_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/acronis/go-appkit/config"
	"github.com/stretchr/testify/require"

	"github.com/acronis/go-authkit/idptoken"
)

func TestConfig(t *testing.T) {
	type testCase struct {
		name      string
		cfgData   string
		expectErr bool
		errMsg    string
		setupEnv  map[string]string // Environment variables to set
	}

	testCases := []testCase{
		{
			name: "valid config",
			cfgData: `
idp:
  url: https://idp.example.com
  clientId: client-id
  clientSecret: client-secret
`,
			expectErr: false,
		},
		{
			name: "missing url",
			cfgData: `
idp:
  clientId: client-id
  clientSecret: client-secret
`,
			expectErr: true,
			errMsg:    `idp.url: IDP URL is required`,
		},
		{
			name: "missing client ID",
			cfgData: `
idp:
  url: https://idp.example.com
  clientSecret: client-secret
`,
			expectErr: true,
			errMsg:    `idp.clientId: IDP client ID is required`,
		},
		{
			name: "missing client secret",
			cfgData: `
idp:
  url: https://idp.example.com
  clientId: client-id
`,
			expectErr: true,
			errMsg:    `idp.clientSecret: IDP client secret is required`,
		},
		{
			name: "valid config from Env",
			cfgData: `
idp:
  url: https://idp.example.com
`,
			setupEnv: map[string]string{
				"IDP_CLIENTID":     "client-id",
				"IDP_CLIENTSECRET": "client-secret",
			},
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup environment variables if needed
			for k, v := range tc.setupEnv {
				err := os.Setenv(k, v)
				require.NoError(t, err)
				defer func(k string) {
					require.NoError(t, os.Unsetenv(k))
				}(k)
			}

			cfg := idptoken.NewConfig()
			err := config.NewDefaultLoader("").LoadFromReader(bytes.NewBufferString(tc.cfgData), config.DataTypeYAML, cfg)

			if tc.expectErr {
				require.EqualError(t, err, tc.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
