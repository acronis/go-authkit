/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package authkit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/acronis/go-appkit/config"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type AppConfig struct {
	Auth *Config `mapstructure:"auth" json:"auth" yaml:"auth"`
}

func TestConfig(t *testing.T) {
	expectedCfg := NewDefaultConfig()
	expectedCfg.HTTPClient.RequestTimeout = config.TimeDuration(time.Minute * 1)
	expectedCfg.GRPCClient.RequestTimeout = config.TimeDuration(time.Minute * 2)
	expectedCfg.JWT.TrustedIssuers = map[string]string{
		"my-issuer1": "https://my-issuer1.com/idp",
		"my-issuer2": "https://my-issuer2.com/idp",
	}
	expectedCfg.JWT.TrustedIssuerURLs = []string{
		"https://*.my-company1.com/idp",
		"https://*.my-company2.com/idp",
	}
	expectedCfg.JWT.RequireAudience = true
	expectedCfg.JWT.ExpectedAudience = []string{
		"https://*.my-company1.com",
		"https://*.my-company2.com",
	}
	expectedCfg.JWKS.Cache.UpdateMinInterval = config.TimeDuration(time.Minute * 5)
	expectedCfg.Introspection.Enabled = true
	expectedCfg.Introspection.Endpoint = "https://my-idp.com/introspect"
	expectedCfg.Introspection.ClaimsCache.Enabled = true
	expectedCfg.Introspection.ClaimsCache.MaxEntries = 42000
	expectedCfg.Introspection.ClaimsCache.TTL = config.TimeDuration(time.Second * 42)
	expectedCfg.Introspection.NegativeCache.Enabled = true
	expectedCfg.Introspection.NegativeCache.MaxEntries = 777
	expectedCfg.Introspection.NegativeCache.TTL = config.TimeDuration(time.Minute * 77)
	expectedCfg.Introspection.EndpointDiscoveryCache.Enabled = true
	expectedCfg.Introspection.EndpointDiscoveryCache.MaxEntries = 73
	expectedCfg.Introspection.EndpointDiscoveryCache.TTL = config.TimeDuration(time.Hour * 7)
	expectedCfg.Introspection.AccessTokenScope = []string{"token_introspector"}
	expectedCfg.Introspection.GRPC.Endpoint = "127.0.0.1:1234"
	expectedCfg.Introspection.GRPC.TLS.Enabled = true
	expectedCfg.Introspection.GRPC.TLS.CACert = "ca-cert.pem"
	expectedCfg.Introspection.GRPC.TLS.ClientCert = "client-cert.pem"
	expectedCfg.Introspection.GRPC.TLS.ClientKey = "client-key.pem"

	tests := []struct {
		name        string
		cfgDataType config.DataType
		cfgData     string
		expectedCfg *Config
	}{
		{
			name:        "yaml config",
			cfgDataType: config.DataTypeYAML,
			cfgData: `
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
      ttl: 77m
    endpointDiscoveryCache:
      enabled: true
      maxEntries: 73
      ttl: 7h
    accessTokenScope:
      - token_introspector
    grpc:
      endpoint: "127.0.0.1:1234"
      tls:
        enabled: true
        caCert: ca-cert.pem
        clientCert: client-cert.pem
        clientKey: client-key.pem
`,
			expectedCfg: expectedCfg,
		},
		{
			name:        "json config",
			cfgDataType: config.DataTypeJSON,
			cfgData: `
{
  "auth": {
    "httpClient": {
      "requestTimeout": "1m"
    },
    "grpcClient": {
      "requestTimeout": "2m"
    },
    "jwt": {
      "trustedIssuers": {
        "my-issuer1": "https://my-issuer1.com/idp",
        "my-issuer2": "https://my-issuer2.com/idp"
      },
      "trustedIssuerUrls": [
        "https://*.my-company1.com/idp",
        "https://*.my-company2.com/idp"
      ],
      "requireAudience": true,
      "expectedAudience": [
        "https://*.my-company1.com",
        "https://*.my-company2.com"
      ]
    },
    "jwks": {
      "cache": {
        "updateMinInterval": "5m"
      }
    },
    "introspection": {
      "enabled": true,
      "endpoint": "https://my-idp.com/introspect",
      "claimsCache": {
        "enabled": true,
        "maxEntries": 42000,
        "ttl": "42s"
      },
      "negativeCache": {
        "enabled": true,
        "maxEntries": 777,
        "ttl": "77m"
      },
      "endpointDiscoveryCache": {
        "enabled": true,
        "maxEntries": 73,
        "ttl": "7h"
      },
      "accessTokenScope": [
        "token_introspector"
      ],
      "grpc": {
        "endpoint": "127.0.0.1:1234",
        "tls": {
          "enabled": true,
          "caCert": "ca-cert.pem",
          "clientCert": "client-cert.pem",
          "clientKey": "client-key.pem"
        }
      }
    }
  }
}
`,
			expectedCfg: expectedCfg,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Load config using config.Loader.
			appCfg := AppConfig{Auth: NewDefaultConfig()}
			expectedAppCfg := AppConfig{Auth: tt.expectedCfg}
			cfgLoader := config.NewLoader(config.NewViperAdapter())
			err := cfgLoader.LoadFromReader(bytes.NewBuffer([]byte(tt.cfgData)), tt.cfgDataType, appCfg.Auth)
			require.NoError(t, err)
			require.Equal(t, expectedAppCfg, appCfg)

			// Load config using viper unmarshal.
			appCfg = AppConfig{Auth: NewDefaultConfig()}
			expectedAppCfg = AppConfig{Auth: tt.expectedCfg}
			vpr := viper.New()
			vpr.SetConfigType(string(tt.cfgDataType))
			require.NoError(t, vpr.ReadConfig(bytes.NewBuffer([]byte(tt.cfgData))))
			require.NoError(t, vpr.Unmarshal(&appCfg, func(c *mapstructure.DecoderConfig) {
				c.DecodeHook = mapstructure.TextUnmarshallerHookFunc()
			}))
			require.Equal(t, expectedAppCfg, appCfg)

			// Load config using yaml/json unmarshal.
			appCfg = AppConfig{Auth: NewDefaultConfig()}
			expectedAppCfg = AppConfig{Auth: tt.expectedCfg}
			switch tt.cfgDataType {
			case config.DataTypeYAML:
				require.NoError(t, yaml.Unmarshal([]byte(tt.cfgData), &appCfg))
				require.Equal(t, expectedAppCfg, appCfg)
			case config.DataTypeJSON:
				require.NoError(t, json.Unmarshal([]byte(tt.cfgData), &appCfg))
				require.Equal(t, expectedAppCfg, appCfg)
			default:
				t.Fatalf("unsupported config data type: %s", tt.cfgDataType)
			}
		})
	}
}

func TestNewDefaultConfig(t *testing.T) {
	var cfg *Config

	// Empty config, all defaults for the data provider should be used
	cfg = NewConfig()
	require.NoError(t, config.NewDefaultLoader("").LoadFromReader(bytes.NewBuffer(nil), config.DataTypeYAML, cfg))
	require.Empty(t, cfg.JWT.TrustedIssuers)
	cfg.JWT.TrustedIssuers = nil // map[string]string{} is not equal to nil
	require.Equal(t, NewDefaultConfig(), cfg)

	// viper.Unmarshal
	cfg = NewDefaultConfig()
	vpr := viper.New()
	vpr.SetConfigType("yaml")
	require.NoError(t, vpr.Unmarshal(&cfg))
	require.Equal(t, NewDefaultConfig(), cfg)

	// yaml.Unmarshal
	cfg = NewDefaultConfig()
	require.NoError(t, yaml.Unmarshal([]byte(""), &cfg))
	require.Equal(t, NewDefaultConfig(), cfg)

	// json.Unmarshal
	cfg = NewDefaultConfig()
	require.NoError(t, json.Unmarshal([]byte("{}"), &cfg))
	require.Equal(t, NewDefaultConfig(), cfg)
}

func TestConfigWithKeyPrefix(t *testing.T) {
	t.Run("custom key prefix", func(t *testing.T) {
		cfgData := `
customAuth:
  httpClient:
    requestTimeout: 2m
`
		cfg := NewConfig(WithKeyPrefix("customAuth"))
		err := config.NewDefaultLoader("").LoadFromReader(bytes.NewBuffer([]byte(cfgData)), config.DataTypeYAML, cfg)
		require.NoError(t, err)
		require.Equal(t, config.TimeDuration(time.Minute*2), cfg.HTTPClient.RequestTimeout)
	})

	t.Run("default key prefix, empty struct initialization", func(t *testing.T) {
		cfgData := `
auth:
  httpClient:
    requestTimeout: 2m
`
		cfg := &Config{}
		err := config.NewDefaultLoader("").LoadFromReader(bytes.NewBuffer([]byte(cfgData)), config.DataTypeYAML, cfg)
		require.NoError(t, err)
		require.Equal(t, config.TimeDuration(time.Minute*2), cfg.HTTPClient.RequestTimeout)
	})
}

func TestConfigValidationErrors(t *testing.T) {
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
			errKey: cfgDefaultKeyPrefix + "." + cfgKeyJWTTrustedIssuerURLs,
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
			errKey: cfgDefaultKeyPrefix + "." + cfgKeyJWTClaimsCacheMaxEntries,
			errMsg: "max entries should be non-negative",
		},
		{
			name: "invalid HTTP client timeout",
			cfgData: `
auth:
  httpClient:
    requestTimeout: invalid
`,
			errKey: cfgDefaultKeyPrefix + "." + cfgKeyHTTPClientRequestTimeout,
			errMsg: "invalid duration",
		},
		{
			name: "invalid gRPC client timeout",
			cfgData: `
auth:
  grpcClient:
    requestTimeout: invalid
`,
			errKey: cfgDefaultKeyPrefix + "." + cfgKeyGRPCClientRequestTimeout,
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
			errKey: cfgDefaultKeyPrefix + "." + cfgKeyJWKSCacheUpdateMinInterval,
			errMsg: "invalid duration",
		},
		{
			name: "invalid introspection endpoint URL",
			cfgData: `
auth:
  introspection:
    endpoint: ://invalid-url
`,
			errKey: cfgDefaultKeyPrefix + "." + cfgKeyIntrospectionEndpoint,
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
			errKey: cfgDefaultKeyPrefix + "." + cfgKeyIntrospectionClaimsCacheMaxEntries,
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
			errKey: cfgDefaultKeyPrefix + "." + cfgKeyIntrospectionNegativeCacheMaxEntries,
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
			errKey: cfgDefaultKeyPrefix + "." + cfgKeyIntrospectionClaimsCacheTTL,
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
			errKey: cfgDefaultKeyPrefix + "." + cfgKeyIntrospectionNegativeCacheTTL,
			errMsg: "invalid duration",
		},
		{
			name: "invalid introspection access token scope",
			cfgData: `
auth:
  introspection:
    accessTokenScope: {}
`,
			errKey: cfgDefaultKeyPrefix + "." + cfgKeyIntrospectionAccessTokenScope,
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
