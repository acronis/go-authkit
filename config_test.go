/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package authkit

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/acronis/go-appkit/config"
	"github.com/stretchr/testify/require"

	"github.com/acronis/go-authkit/jwt"
)

func TestConfig_Set(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		cfgData := bytes.NewBufferString(`
auth:
  httpClient:
    requestTimeout: 1m
  grpcClient:
    requestTimeout: 2m
  jwt:
    trustedIssuers:
      my-issuer1: https://my-issuer1.com/idp
      my-issuer2: https://my-issuer2.com/idp
    trustedIssuerUrls:
      - https://*.my-company1.com/idp
      - https://*.my-company2.com/idp
    requireAudience: true
    expectedAudience:
      - https://*.my-company1.com
      - https://*.my-company2.com
  jwks:
    httpclient:
      timeout: 1m
    cache:
      updateMinInterval: 5m
  introspection:
    enabled: true
    endpoint: https://my-idp.com/introspect
    claimsCache:
        enabled: true
        maxEntries: 42000
        ttl: 42s
    negativeCache:
        enabled: true
        maxEntries: 777
        ttl: 77s
    accessTokenScope:
      - token_introspector
    grpc:
      endpoint: "127.0.0.1:1234"
      tls:
        enabled: true
        caCert: ca-cert.pem
        clientCert: client-cert.pem
        clientKey: client-key.pem
`)
		cfg := Config{}
		err := config.NewDefaultLoader("").LoadFromReader(cfgData, config.DataTypeYAML, &cfg)
		require.NoError(t, err)
		require.Equal(t, time.Minute*1, cfg.HTTPClient.RequestTimeout)
		require.Equal(t, time.Minute*2, cfg.GRPCClient.RequestTimeout)
		require.Equal(t, cfg.JWT, JWTConfig{
			TrustedIssuers: map[string]string{
				"my-issuer1": "https://my-issuer1.com/idp",
				"my-issuer2": "https://my-issuer2.com/idp",
			},
			TrustedIssuerURLs: []string{
				"https://*.my-company1.com/idp",
				"https://*.my-company2.com/idp",
			},
			RequireAudience: true,
			ExpectedAudience: []string{
				"https://*.my-company1.com",
				"https://*.my-company2.com",
			},
			ClaimsCache: ClaimsCacheConfig{
				MaxEntries: jwt.DefaultClaimsCacheMaxEntries,
			},
		})
		require.Equal(t, time.Minute*5, cfg.JWKS.Cache.UpdateMinInterval)
		require.Equal(t, cfg.Introspection, IntrospectionConfig{
			Enabled:  true,
			Endpoint: "https://my-idp.com/introspect",
			ClaimsCache: IntrospectionCacheConfig{
				Enabled:    true,
				MaxEntries: 42000,
				TTL:        time.Second * 42,
			},
			NegativeCache: IntrospectionCacheConfig{
				Enabled:    true,
				MaxEntries: 777,
				TTL:        time.Second * 77,
			},
			AccessTokenScope: []string{"token_introspector"},
			GRPC: IntrospectionGRPCConfig{
				Endpoint: "127.0.0.1:1234",
				TLS: GRPCTLSConfig{
					Enabled:    true,
					CACert:     "ca-cert.pem",
					ClientCert: "client-cert.pem",
					ClientKey:  "client-key.pem",
				},
			},
		})
	})
}

func TestConfig_SetErrors(t *testing.T) {
	tests := []struct {
		name    string
		cfgData string
		errKey  string
		errMsg  string
	}{
		{
			name: "invalid trusted issuer URL",
			cfgData: `
auth:
  jwt:
    trustedIssuerURLs:
      - ://invalid-url
`,
			errKey: cfgKeyJWTTrustedIssuerURLs,
			errMsg: "missing protocol scheme",
		},
		{
			name: "negative claims cache max entries",
			cfgData: `
auth:
  jwt:
    claimsCache:
      maxEntries: -1
`,
			errKey: cfgKeyJWTClaimsCacheMaxEntries,
			errMsg: "max entries should be non-negative",
		},
		{
			name: "invalid HTTP client timeout",
			cfgData: `
auth:
  httpClient:
    requestTimeout: invalid
`,
			errKey: cfgKeyHTTPClientRequestTimeout,
			errMsg: "invalid duration",
		},
		{
			name: "invalid gRPC client timeout",
			cfgData: `
auth:
  grpcClient:
    requestTimeout: invalid
`,
			errKey: cfgKeyGRPCClientRequestTimeout,
			errMsg: "invalid duration",
		},
		{
			name: "invalid cache update min interval",
			cfgData: `
auth:
  jwks:
    cache:
      updateMinInterval: invalid
`,
			errKey: cfgKeyJWKSCacheUpdateMinInterval,
			errMsg: "invalid duration",
		},
		{
			name: "invalid introspection endpoint URL",
			cfgData: `
auth:
  introspection:
    endpoint: ://invalid-url
`,
			errKey: cfgKeyIntrospectionEndpoint,
			errMsg: "missing protocol scheme",
		},
		{
			name: "negative introspection claims cache max entries",
			cfgData: `
auth:
  introspection:
    claimsCache:
      maxEntries: -1
`,
			errKey: cfgKeyIntrospectionClaimsCacheMaxEntries,
			errMsg: "max entries should be non-negative",
		},
		{
			name: "negative introspection negative cache max entries",
			cfgData: `
auth:
  introspection:
    negativeCache:
      maxEntries: -1
`,
			errKey: cfgKeyIntrospectionNegativeCacheMaxEntries,
			errMsg: "max entries should be non-negative",
		},
		{
			name: "invalid introspection claims cache TTL",
			cfgData: `
auth:
  introspection:
    claimsCache:
      ttl: invalid
`,
			errKey: cfgKeyIntrospectionClaimsCacheTTL,
			errMsg: "invalid duration",
		},
		{
			name: "invalid introspection negative cache TTL",
			cfgData: `
auth:
  introspection:
    negativeCache:
      ttl: invalid
`,
			errKey: cfgKeyIntrospectionNegativeCacheTTL,
			errMsg: "invalid duration",
		},
		{
			name: "invalid introspection access token scope",
			cfgData: `
auth:
  introspection:
    accessTokenScope: {}
`,
			errKey: cfgKeyIntrospectionAccessTokenScope,
			errMsg: " unable to cast",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgData := bytes.NewBufferString(tt.cfgData)
			cfg := Config{}
			err := config.NewDefaultLoader("").LoadFromReader(cfgData, config.DataTypeYAML, &cfg)
			require.ErrorContains(t, err, tt.errMsg)
			require.Truef(t, strings.HasPrefix(err.Error(), tt.errKey),
				"expected error starts with %q, got %q", tt.errKey, err.Error())
		})
	}
}
