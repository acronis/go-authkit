/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package authkit

import (
	"fmt"
	"net/url"
	"time"

	"github.com/acronis/go-appkit/config"

	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/internal/idputil"
	"github.com/acronis/go-authkit/jwks"
	"github.com/acronis/go-authkit/jwt"
)

const cfgDefaultKeyPrefix = "auth"

const (
	cfgKeyHTTPClientRequestTimeout                      = "httpClient.requestTimeout"
	cfgKeyGRPCClientRequestTimeout                      = "grpcClient.requestTimeout"
	cfgKeyJWTTrustedIssuers                             = "jwt.trustedIssuers"
	cfgKeyJWTTrustedIssuerURLs                          = "jwt.trustedIssuerUrls"
	cfgKeyJWTRequireAudience                            = "jwt.requireAudience"
	cfgKeyJWTExceptedAudience                           = "jwt.expectedAudience"
	cfgKeyJWTClaimsCacheEnabled                         = "jwt.claimsCache.enabled"
	cfgKeyJWTClaimsCacheMaxEntries                      = "jwt.claimsCache.maxEntries"
	cfgKeyJWKSCacheUpdateMinInterval                    = "jwks.cache.updateMinInterval"
	cfgKeyIntrospectionEnabled                          = "introspection.enabled"
	cfgKeyIntrospectionEndpoint                         = "introspection.endpoint"
	cfgKeyIntrospectionGRPCEndpoint                     = "introspection.grpc.endpoint"
	cfgKeyIntrospectionGRPCTLSEnabled                   = "introspection.grpc.tls.enabled"
	cfgKeyIntrospectionGRPCTLSCACert                    = "introspection.grpc.tls.caCert"
	cfgKeyIntrospectionGRPCTLSClientCert                = "introspection.grpc.tls.clientCert"
	cfgKeyIntrospectionGRPCTLSClientKey                 = "introspection.grpc.tls.clientKey"
	cfgKeyIntrospectionAccessTokenScope                 = "introspection.accessTokenScope" // nolint:gosec // false positive
	cfgKeyIntrospectionClaimsCacheEnabled               = "introspection.claimsCache.enabled"
	cfgKeyIntrospectionClaimsCacheMaxEntries            = "introspection.claimsCache.maxEntries"
	cfgKeyIntrospectionClaimsCacheTTL                   = "introspection.claimsCache.ttl"
	cfgKeyIntrospectionNegativeCacheEnabled             = "introspection.negativeCache.enabled"
	cfgKeyIntrospectionNegativeCacheMaxEntries          = "introspection.negativeCache.maxEntries"
	cfgKeyIntrospectionNegativeCacheTTL                 = "introspection.negativeCache.ttl"
	cfgKeyIntrospectionEndpointDiscoveryCacheEnabled    = "introspection.endpointDiscoveryCache.enabled"
	cfgKeyIntrospectionEndpointDiscoveryCacheMaxEntries = "introspection.endpointDiscoveryCache.maxEntries"
	cfgKeyIntrospectionEndpointDiscoveryCacheTTL        = "introspection.endpointDiscoveryCache.ttl"
)

// Config represents a set of configuration parameters for authentication and authorization.
type Config struct {
	HTTPClient HTTPClientConfig `mapstructure:"httpClient" yaml:"httpClient" json:"httpClient"`
	GRPCClient GRPCClientConfig `mapstructure:"grpcClient" yaml:"grpcClient"`

	JWT           JWTConfig           `mapstructure:"jwt" yaml:"jwt" json:"jwt"`
	JWKS          JWKSConfig          `mapstructure:"jwks" yaml:"jwks" json:"jwks"`
	Introspection IntrospectionConfig `mapstructure:"introspection" yaml:"introspection" json:"introspection"`

	keyPrefix string
}

var _ config.Config = (*Config)(nil)
var _ config.KeyPrefixProvider = (*Config)(nil)

// ConfigOption is a type for functional options for the Config.
type ConfigOption func(*configOptions)

type configOptions struct {
	keyPrefix string
}

// WithKeyPrefix returns a ConfigOption that sets a key prefix for parsing configuration parameters.
// This prefix will be used by config.Loader.
func WithKeyPrefix(keyPrefix string) ConfigOption {
	return func(o *configOptions) {
		o.keyPrefix = keyPrefix
	}
}

// NewConfig creates a new instance of the Config.
func NewConfig(options ...ConfigOption) *Config {
	var opts = configOptions{keyPrefix: cfgDefaultKeyPrefix} // cfgDefaultKeyPrefix is used here for backward compatibility
	for _, opt := range options {
		opt(&opts)
	}
	return &Config{keyPrefix: opts.keyPrefix}
}

// NewConfigWithKeyPrefix creates a new instance of the Config with a key prefix.
// This prefix will be used by config.Loader.
// Deprecated: use NewConfig with WithKeyPrefix instead.
func NewConfigWithKeyPrefix(keyPrefix string) *Config {
	if keyPrefix != "" {
		keyPrefix += "."
	}
	keyPrefix += cfgDefaultKeyPrefix // cfgDefaultKeyPrefix is added here for backward compatibility
	return &Config{keyPrefix: keyPrefix}
}

// NewDefaultConfig creates a new instance of the Config with default values.
func NewDefaultConfig(options ...ConfigOption) *Config {
	opts := configOptions{keyPrefix: cfgDefaultKeyPrefix}
	for _, opt := range options {
		opt(&opts)
	}
	return &Config{
		keyPrefix: opts.keyPrefix,
		HTTPClient: HTTPClientConfig{
			RequestTimeout: config.TimeDuration(idputil.DefaultHTTPRequestTimeout),
		},
		GRPCClient: GRPCClientConfig{
			RequestTimeout: config.TimeDuration(idptoken.DefaultGRPCClientRequestTimeout),
		},
		JWT: JWTConfig{
			ClaimsCache: ClaimsCacheConfig{
				MaxEntries: jwt.DefaultClaimsCacheMaxEntries,
			},
		},
		JWKS: JWKSConfig{
			Cache: JWKSCacheConfig{
				UpdateMinInterval: config.TimeDuration(jwks.DefaultCacheUpdateMinInterval),
			},
		},
		Introspection: IntrospectionConfig{
			ClaimsCache: IntrospectionCacheConfig{
				MaxEntries: idptoken.DefaultIntrospectionClaimsCacheMaxEntries,
				TTL:        config.TimeDuration(idptoken.DefaultIntrospectionClaimsCacheTTL),
			},
			NegativeCache: IntrospectionCacheConfig{
				MaxEntries: idptoken.DefaultIntrospectionNegativeCacheMaxEntries,
				TTL:        config.TimeDuration(idptoken.DefaultIntrospectionNegativeCacheTTL),
			},
			EndpointDiscoveryCache: IntrospectionCacheConfig{
				Enabled:    true,
				MaxEntries: idptoken.DefaultIntrospectionEndpointDiscoveryCacheMaxEntries,
				TTL:        config.TimeDuration(idptoken.DefaultIntrospectionEndpointDiscoveryCacheTTL),
			},
		},
	}
}

// KeyPrefix returns a key prefix with which all configuration parameters should be presented.
// Implements config.KeyPrefixProvider interface.
func (c *Config) KeyPrefix() string {
	if c.keyPrefix == "" {
		return cfgDefaultKeyPrefix
	}
	return c.keyPrefix
}

// SetProviderDefaults sets default configuration values for auth in config.DataProvider.
func (c *Config) SetProviderDefaults(dp config.DataProvider) {
	dp.SetDefault(cfgKeyHTTPClientRequestTimeout, idputil.DefaultHTTPRequestTimeout.String())
	dp.SetDefault(cfgKeyGRPCClientRequestTimeout, idptoken.DefaultGRPCClientRequestTimeout.String())

	dp.SetDefault(cfgKeyJWTClaimsCacheMaxEntries, jwt.DefaultClaimsCacheMaxEntries)
	dp.SetDefault(cfgKeyJWKSCacheUpdateMinInterval, jwks.DefaultCacheUpdateMinInterval.String())

	dp.SetDefault(cfgKeyIntrospectionClaimsCacheMaxEntries, idptoken.DefaultIntrospectionClaimsCacheMaxEntries)
	dp.SetDefault(cfgKeyIntrospectionClaimsCacheTTL, idptoken.DefaultIntrospectionClaimsCacheTTL.String())

	dp.SetDefault(cfgKeyIntrospectionNegativeCacheMaxEntries, idptoken.DefaultIntrospectionNegativeCacheMaxEntries)
	dp.SetDefault(cfgKeyIntrospectionNegativeCacheTTL, idptoken.DefaultIntrospectionNegativeCacheTTL.String())

	dp.SetDefault(cfgKeyIntrospectionEndpointDiscoveryCacheEnabled, true)
	dp.SetDefault(cfgKeyIntrospectionEndpointDiscoveryCacheMaxEntries, idptoken.DefaultIntrospectionEndpointDiscoveryCacheMaxEntries)
	dp.SetDefault(cfgKeyIntrospectionEndpointDiscoveryCacheTTL, idptoken.DefaultIntrospectionEndpointDiscoveryCacheTTL.String())
}

// JWTConfig is a configuration of how JWT will be verified.
type JWTConfig struct {
	TrustedIssuers    map[string]string `mapstructure:"trustedIssuers" yaml:"trustedIssuers" json:"trustedIssuers"`
	TrustedIssuerURLs []string          `mapstructure:"trustedIssuerUrls" yaml:"trustedIssuerUrls" json:"trustedIssuerUrls"`
	RequireAudience   bool              `mapstructure:"requireAudience" yaml:"requireAudience" json:"requireAudience"`
	ExpectedAudience  []string          `mapstructure:"expectedAudience" yaml:"expectedAudience" json:"expectedAudience"`
	ClaimsCache       ClaimsCacheConfig `mapstructure:"claimsCache" yaml:"claimsCache" json:"claimsCache"`
}

// JWKSConfig is a configuration of how JWKS will be used.
type JWKSConfig struct {
	Cache JWKSCacheConfig `mapstructure:"cache" yaml:"cache" json:"cache"`
}

type JWKSCacheConfig struct {
	UpdateMinInterval config.TimeDuration `mapstructure:"updateMinInterval" yaml:"updateMinInterval" json:"updateMinInterval"`
}

// IntrospectionConfig is a configuration of how token introspection will be used.
type IntrospectionConfig struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled" json:"enabled"`

	Endpoint         string   `mapstructure:"endpoint" yaml:"endpoint" json:"endpoint"`
	AccessTokenScope []string `mapstructure:"accessTokenScope" yaml:"accessTokenScope" json:"accessTokenScope"`

	ClaimsCache            IntrospectionCacheConfig `mapstructure:"claimsCache" yaml:"claimsCache" json:"claimsCache"`
	NegativeCache          IntrospectionCacheConfig `mapstructure:"negativeCache" yaml:"negativeCache" json:"negativeCache"`
	EndpointDiscoveryCache IntrospectionCacheConfig `mapstructure:"endpointDiscoveryCache" yaml:"endpointDiscoveryCache" json:"endpointDiscoveryCache"` // nolint:lll

	GRPC IntrospectionGRPCConfig `mapstructure:"grpc" yaml:"grpc" json:"grpc"`
}

// ClaimsCacheConfig is a configuration of how claims cache will be used.
type ClaimsCacheConfig struct {
	Enabled    bool `mapstructure:"enabled" yaml:"enabled" json:"enabled"`
	MaxEntries int  `mapstructure:"maxEntries" yaml:"maxEntries" json:"maxEntries"`
}

// IntrospectionCacheConfig is a configuration of how claims cache will be used for introspection.
type IntrospectionCacheConfig struct {
	Enabled    bool                `mapstructure:"enabled" yaml:"enabled" json:"enabled"`
	MaxEntries int                 `mapstructure:"maxEntries" yaml:"maxEntries" json:"maxEntries"`
	TTL        config.TimeDuration `mapstructure:"ttl" yaml:"ttl" json:"ttl"`
}

// IntrospectionGRPCConfig is a configuration of how token will be introspected via gRPC.
type IntrospectionGRPCConfig struct {
	Endpoint       string              `mapstructure:"endpoint" yaml:"endpoint" json:"endpoint"`
	RequestTimeout config.TimeDuration `mapstructure:"requestTimeout" yaml:"requestTimeout" json:"requestTimeout"`
	TLS            GRPCTLSConfig       `mapstructure:"tls" yaml:"tls" json:"tls"`
}

// GRPCTLSConfig is a configuration of how gRPC connection will be secured.
type GRPCTLSConfig struct {
	Enabled    bool   `mapstructure:"enabled" yaml:"enabled" json:"enabled"`
	CACert     string `mapstructure:"caCert" yaml:"caCert" json:"caCert"`
	ClientCert string `mapstructure:"clientCert" yaml:"clientCert" json:"clientCert"`
	ClientKey  string `mapstructure:"clientKey" yaml:"clientKey" json:"clientKey"`
}

type HTTPClientConfig struct {
	RequestTimeout config.TimeDuration `mapstructure:"requestTimeout" yaml:"requestTimeout" json:"requestTimeout"`
}

type GRPCClientConfig struct {
	RequestTimeout config.TimeDuration `mapstructure:"requestTimeout" yaml:"requestTimeout" json:"requestTimeout"`
}

// Set sets auth configuration values from config.DataProvider.
func (c *Config) Set(dp config.DataProvider) error {
	var err error

	var reqDuration time.Duration
	if reqDuration, err = dp.GetDuration(cfgKeyHTTPClientRequestTimeout); err != nil {
		return err
	}
	c.HTTPClient.RequestTimeout = config.TimeDuration(reqDuration)
	if reqDuration, err = dp.GetDuration(cfgKeyGRPCClientRequestTimeout); err != nil {
		return err
	}
	c.GRPCClient.RequestTimeout = config.TimeDuration(reqDuration)
	if err = c.setJWTConfig(dp); err != nil {
		return err
	}
	if err = c.setJWKSConfig(dp); err != nil {
		return err
	}
	if err = c.setIntrospectionConfig(dp); err != nil {
		return err
	}

	return nil
}

func (c *Config) setJWTConfig(dp config.DataProvider) error {
	var err error

	if c.JWT.TrustedIssuers, err = dp.GetStringMapString(cfgKeyJWTTrustedIssuers); err != nil {
		return err
	}
	if c.JWT.TrustedIssuerURLs, err = dp.GetStringSlice(cfgKeyJWTTrustedIssuerURLs); err != nil {
		return err
	}
	for _, issURL := range c.JWT.TrustedIssuerURLs {
		if _, err = url.Parse(issURL); err != nil {
			return dp.WrapKeyErr(cfgKeyJWTTrustedIssuerURLs, err)
		}
	}
	if c.JWT.RequireAudience, err = dp.GetBool(cfgKeyJWTRequireAudience); err != nil {
		return err
	}
	if c.JWT.ExpectedAudience, err = dp.GetStringSlice(cfgKeyJWTExceptedAudience); err != nil {
		return err
	}
	if c.JWT.ClaimsCache.Enabled, err = dp.GetBool(cfgKeyJWTClaimsCacheEnabled); err != nil {
		return err
	}
	if c.JWT.ClaimsCache.MaxEntries, err = dp.GetInt(cfgKeyJWTClaimsCacheMaxEntries); err != nil {
		return err
	}
	if c.JWT.ClaimsCache.MaxEntries < 0 {
		return dp.WrapKeyErr(cfgKeyJWTClaimsCacheMaxEntries, fmt.Errorf("max entries should be non-negative"))
	}

	return nil
}

func (c *Config) setJWKSConfig(dp config.DataProvider) error {
	updateMinInterval, err := dp.GetDuration(cfgKeyJWKSCacheUpdateMinInterval)
	if err != nil {
		return err
	}
	c.JWKS.Cache.UpdateMinInterval = config.TimeDuration(updateMinInterval)
	return nil
}

func (c *Config) setIntrospectionConfig(dp config.DataProvider) error {
	var err error

	if c.Introspection.Enabled, err = dp.GetBool(cfgKeyIntrospectionEnabled); err != nil {
		return err
	}
	if c.Introspection.Endpoint, err = dp.GetString(cfgKeyIntrospectionEndpoint); err != nil {
		return err
	}
	if _, err = url.Parse(c.Introspection.Endpoint); err != nil {
		return dp.WrapKeyErr(cfgKeyIntrospectionEndpoint, err)
	}

	// GRPC
	if c.Introspection.GRPC.Endpoint, err = dp.GetString(cfgKeyIntrospectionGRPCEndpoint); err != nil {
		return err
	}
	if c.Introspection.GRPC.TLS.Enabled, err = dp.GetBool(cfgKeyIntrospectionGRPCTLSEnabled); err != nil {
		return err
	}
	if c.Introspection.GRPC.TLS.CACert, err = dp.GetString(cfgKeyIntrospectionGRPCTLSCACert); err != nil {
		return err
	}
	if c.Introspection.GRPC.TLS.ClientCert, err = dp.GetString(cfgKeyIntrospectionGRPCTLSClientCert); err != nil {
		return err
	}
	if c.Introspection.GRPC.TLS.ClientKey, err = dp.GetString(cfgKeyIntrospectionGRPCTLSClientKey); err != nil {
		return err
	}

	if c.Introspection.AccessTokenScope, err = dp.GetStringSlice(cfgKeyIntrospectionAccessTokenScope); err != nil {
		return err
	}

	// Claims cache
	if c.Introspection.ClaimsCache.Enabled, err = dp.GetBool(cfgKeyIntrospectionClaimsCacheEnabled); err != nil {
		return err
	}
	if c.Introspection.ClaimsCache.MaxEntries, err = dp.GetInt(cfgKeyIntrospectionClaimsCacheMaxEntries); err != nil {
		return err
	}
	if c.Introspection.ClaimsCache.MaxEntries < 0 {
		return dp.WrapKeyErr(cfgKeyIntrospectionClaimsCacheMaxEntries, fmt.Errorf("max entries should be non-negative"))
	}
	var cacheTTL time.Duration
	if cacheTTL, err = dp.GetDuration(cfgKeyIntrospectionClaimsCacheTTL); err != nil {
		return err
	}
	c.Introspection.ClaimsCache.TTL = config.TimeDuration(cacheTTL)

	// Negative cache
	if c.Introspection.NegativeCache.Enabled, err = dp.GetBool(cfgKeyIntrospectionNegativeCacheEnabled); err != nil {
		return err
	}
	if c.Introspection.NegativeCache.MaxEntries, err = dp.GetInt(cfgKeyIntrospectionNegativeCacheMaxEntries); err != nil {
		return err
	}
	if c.Introspection.NegativeCache.MaxEntries < 0 {
		return dp.WrapKeyErr(cfgKeyIntrospectionNegativeCacheMaxEntries, fmt.Errorf("max entries should be non-negative"))
	}
	if cacheTTL, err = dp.GetDuration(cfgKeyIntrospectionNegativeCacheTTL); err != nil {
		return err
	}
	c.Introspection.NegativeCache.TTL = config.TimeDuration(cacheTTL)

	// OpenID configuration cache
	if c.Introspection.EndpointDiscoveryCache.Enabled, err = dp.GetBool(
		cfgKeyIntrospectionEndpointDiscoveryCacheEnabled,
	); err != nil {
		return err
	}
	if c.Introspection.EndpointDiscoveryCache.MaxEntries, err = dp.GetInt(
		cfgKeyIntrospectionEndpointDiscoveryCacheMaxEntries,
	); err != nil {
		return err
	}
	if c.Introspection.EndpointDiscoveryCache.MaxEntries < 0 {
		return dp.WrapKeyErr(cfgKeyIntrospectionEndpointDiscoveryCacheMaxEntries, fmt.Errorf("max entries should be non-negative"))
	}
	if cacheTTL, err = dp.GetDuration(cfgKeyIntrospectionEndpointDiscoveryCacheTTL); err != nil {
		return err
	}
	c.Introspection.EndpointDiscoveryCache.TTL = config.TimeDuration(cacheTTL)

	return nil
}
