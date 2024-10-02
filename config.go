/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package auth

import (
	"fmt"
	"net/url"
	"time"

	"github.com/acronis/go-appkit/config"

	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/jwks"
	"github.com/acronis/go-authkit/jwt"
)

const (
	cfgKeyHTTPClientRequestTimeout             = "auth.httpClient.requestTimeout"
	cfgKeyGRPCClientRequestTimeout             = "auth.grpcClient.requestTimeout"
	cfgKeyJWTTrustedIssuers                    = "auth.jwt.trustedIssuers"
	cfgKeyJWTTrustedIssuerURLs                 = "auth.jwt.trustedIssuerUrls"
	cfgKeyJWTRequireAudience                   = "auth.jwt.requireAudience"
	cfgKeyJWTExceptedAudience                  = "auth.jwt.expectedAudience"
	cfgKeyJWTClaimsCacheEnabled                = "auth.jwt.claimsCache.enabled"
	cfgKeyJWTClaimsCacheMaxEntries             = "auth.jwt.claimsCache.maxEntries"
	cfgKeyJWKSCacheUpdateMinInterval           = "auth.jwks.cache.updateMinInterval"
	cfgKeyIntrospectionEnabled                 = "auth.introspection.enabled"
	cfgKeyIntrospectionEndpoint                = "auth.introspection.endpoint"
	cfgKeyIntrospectionGRPCTarget              = "auth.introspection.grpc.target"
	cfgKeyIntrospectionGRPCTLSEnabled          = "auth.introspection.grpc.tls.enabled"
	cfgKeyIntrospectionGRPCTLSCACert           = "auth.introspection.grpc.tls.caCert"
	cfgKeyIntrospectionGRPCTLSClientCert       = "auth.introspection.grpc.tls.clientCert"
	cfgKeyIntrospectionGRPCTLSClientKey        = "auth.introspection.grpc.tls.clientKey"
	cfgKeyIntrospectionAccessTokenScope        = "auth.introspection.accessTokenScope" // nolint:gosec // false positive
	cfgKeyIntrospectionMinJWTVer               = "auth.introspection.minJWTVersion"
	cfgKeyIntrospectionClaimsCacheEnabled      = "auth.introspection.claimsCache.enabled"
	cfgKeyIntrospectionClaimsCacheMaxEntries   = "auth.introspection.claimsCache.maxEntries"
	cfgKeyIntrospectionClaimsCacheTTL          = "auth.introspection.claimsCache.ttl"
	cfgKeyIntrospectionNegativeCacheEnabled    = "auth.introspection.negativeCache.enabled"
	cfgKeyIntrospectionNegativeCacheMaxEntries = "auth.introspection.negativeCache.maxEntries"
	cfgKeyIntrospectionNegativeCacheTTL        = "auth.introspection.negativeCache.ttl"
)

// JWTConfig is configuration of how JWT will be verified.
type JWTConfig struct {
	TrustedIssuers    map[string]string
	TrustedIssuerURLs []string
	RequireAudience   bool
	ExpectedAudience  []string
	ClaimsCache       ClaimsCacheConfig
}

// JWKSConfig is configuration of how JWKS will be used.
type JWKSConfig struct {
	Cache struct {
		UpdateMinInterval time.Duration
	}
}

// IntrospectionConfig is a configuration of how token introspection will be used.
type IntrospectionConfig struct {
	Enabled bool

	Endpoint         string
	AccessTokenScope []string

	// MinJWTVersion is a minimum version of JWT that will be accepted for introspection.
	// NOTE: it's a temporary solution for determining whether introspection is needed or not,
	// and it will be removed in the future.
	MinJWTVersion int

	ClaimsCache   IntrospectionCacheConfig
	NegativeCache IntrospectionCacheConfig

	GRPC IntrospectionGRPCConfig
}

// ClaimsCacheConfig is a configuration of how claims cache will be used.
type ClaimsCacheConfig struct {
	Enabled    bool
	MaxEntries int
}

// IntrospectionCacheConfig is a configuration of how claims cache will be used for introspection.
type IntrospectionCacheConfig struct {
	Enabled    bool
	MaxEntries int
	TTL        time.Duration
}

// IntrospectionGRPCConfig is a configuration of how token will be introspected via gRPC.
type IntrospectionGRPCConfig struct {
	Target         string
	RequestTimeout time.Duration
	TLS            GRPCTLSConfig
}

// GRPCTLSConfig is a configuration of how gRPC connection will be secured.
type GRPCTLSConfig struct {
	Enabled    bool
	CACert     string
	ClientCert string
	ClientKey  string
}

type HTTPClientConfig struct {
	RequestTimeout time.Duration
}

type GRPCClientConfig struct {
	RequestTimeout time.Duration
}

// Config represents a set of configuration parameters for authentication and authorization.
type Config struct {
	HTTPClient HTTPClientConfig
	GRPCClient GRPCClientConfig

	JWT           JWTConfig
	JWKS          JWKSConfig
	Introspection IntrospectionConfig

	keyPrefix string
}

var _ config.Config = (*Config)(nil)
var _ config.KeyPrefixProvider = (*Config)(nil)

// NewConfig creates a new instance of the Config.
func NewConfig() *Config {
	return NewConfigWithKeyPrefix("")
}

// NewConfigWithKeyPrefix creates a new instance of the Config.
// Allows specifying key prefix which will be used for parsing configuration parameters.
func NewConfigWithKeyPrefix(keyPrefix string) *Config {
	return &Config{keyPrefix: keyPrefix}
}

// KeyPrefix returns a key prefix with which all configuration parameters should be presented.
func (c *Config) KeyPrefix() string {
	return c.keyPrefix
}

// SetProviderDefaults sets default configuration values for auth in config.DataProvider.
func (c *Config) SetProviderDefaults(dp config.DataProvider) {
	dp.SetDefault(cfgKeyHTTPClientRequestTimeout, DefaultHTTPClientRequestTimeout.String())
	dp.SetDefault(cfgKeyGRPCClientRequestTimeout, DefaultGRPCClientRequestTimeout.String())
	dp.SetDefault(cfgKeyJWTClaimsCacheMaxEntries, jwt.DefaultClaimsCacheMaxEntries)
	dp.SetDefault(cfgKeyJWKSCacheUpdateMinInterval, jwks.DefaultCacheUpdateMinInterval.String())
	dp.SetDefault(cfgKeyIntrospectionMinJWTVer, idptoken.MinJWTVersionForIntrospection)
	dp.SetDefault(cfgKeyIntrospectionClaimsCacheMaxEntries, idptoken.DefaultIntrospectionClaimsCacheMaxEntries)
	dp.SetDefault(cfgKeyIntrospectionClaimsCacheTTL, idptoken.DefaultIntrospectionClaimsCacheTTL.String())
	dp.SetDefault(cfgKeyIntrospectionNegativeCacheMaxEntries, idptoken.DefaultIntrospectionNegativeCacheMaxEntries)
	dp.SetDefault(cfgKeyIntrospectionNegativeCacheTTL, idptoken.DefaultIntrospectionNegativeCacheTTL.String())
}

// Set sets auth configuration values from config.DataProvider.
func (c *Config) Set(dp config.DataProvider) error {
	var err error

	if c.HTTPClient.RequestTimeout, err = dp.GetDuration(cfgKeyHTTPClientRequestTimeout); err != nil {
		return err
	}
	if c.GRPCClient.RequestTimeout, err = dp.GetDuration(cfgKeyGRPCClientRequestTimeout); err != nil {
		return err
	}
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
	var err error
	if c.JWKS.Cache.UpdateMinInterval, err = dp.GetDuration(cfgKeyJWKSCacheUpdateMinInterval); err != nil {
		return err
	}
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
	if c.Introspection.GRPC.Target, err = dp.GetString(cfgKeyIntrospectionGRPCTarget); err != nil {
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

	if c.Introspection.MinJWTVersion, err = dp.GetInt(cfgKeyIntrospectionMinJWTVer); err != nil {
		return err
	}
	if c.Introspection.MinJWTVersion < 0 {
		return dp.WrapKeyErr(cfgKeyIntrospectionMinJWTVer, fmt.Errorf("minimum JWT version should be non-negative"))
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
	if c.Introspection.ClaimsCache.TTL, err = dp.GetDuration(cfgKeyIntrospectionClaimsCacheTTL); err != nil {
		return err
	}

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
	if c.Introspection.NegativeCache.TTL, err = dp.GetDuration(cfgKeyIntrospectionNegativeCacheTTL); err != nil {
		return err
	}

	return nil
}
