/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptoken

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/acronis/go-appkit/log"
	"github.com/acronis/go-appkit/lrucache"
	jwtgo "github.com/golang-jwt/jwt/v5"

	"github.com/acronis/go-authkit/internal/idputil"
	"github.com/acronis/go-authkit/internal/metrics"
	"github.com/acronis/go-authkit/jwt"
)

const minAccessTokenProviderInvalidationInterval = time.Minute

const tokenIntrospectorPromSource = "token_introspector"

const (
	// DefaultIntrospectionClaimsCacheMaxEntries is a default maximum number of entries in the claims cache.
	// Claims cache is used for storing introspected active tokens.
	DefaultIntrospectionClaimsCacheMaxEntries = 1000

	// DefaultIntrospectionClaimsCacheTTL is a default time-to-live for the claims cache.
	DefaultIntrospectionClaimsCacheTTL = 1 * time.Minute

	// DefaultIntrospectionNegativeCacheMaxEntries is a default maximum number of entries in the negative cache.
	// Negative cache is used for storing tokens that are not active.
	DefaultIntrospectionNegativeCacheMaxEntries = 1000

	// DefaultIntrospectionNegativeCacheTTL is a default time-to-live for the negative cache.
	DefaultIntrospectionNegativeCacheTTL = 10 * time.Minute
)

// ErrTokenNotIntrospectable is returned when token is not introspectable.
var ErrTokenNotIntrospectable = errors.New("token is not introspectable")

// ErrTokenIntrospectionNotNeeded is returned when token introspection is unnecessary
// (i.e., it already contains all necessary information).
var ErrTokenIntrospectionNotNeeded = errors.New("token introspection is not needed")

// ErrUnauthenticated is returned when a request is unauthenticated.
var ErrUnauthenticated = errors.New("request is unauthenticated")

// TrustedIssNotFoundFallback is a function called when given issuer is not found in the list of trusted ones.
// For example, it could be analyzed and then added to the list by calling AddTrustedIssuerURL method.
type TrustedIssNotFoundFallback func(ctx context.Context, i *Introspector, iss string) (issURL string, issFound bool)

// IntrospectionTokenProvider is an interface for getting access token for doing introspection.
// The token should have introspection permission.
type IntrospectionTokenProvider interface {
	GetToken(ctx context.Context, scope ...string) (string, error)
	Invalidate()
}

// IntrospectionScopeFilterAccessPolicy is an access policy for filtering scopes.
type IntrospectionScopeFilterAccessPolicy struct {
	ResourceNamespace string
}

// IntrospectorOpts is a set of options for creating Introspector.
type IntrospectorOpts struct {
	// GRPCClient is a gRPC client for doing introspection.
	// If it is set, then introspection will be done using this client.
	// Otherwise, introspection will be done via HTTP.
	GRPCClient *GRPCClient

	// HTTPEndpoint is a static URL for introspection.
	// If it is set, then introspection will be done using this endpoint.
	// Otherwise, introspection will be done using issuer URL (/.well-known/openid-configuration response).
	// In this case, issuer URL should be present in JWT header or payload.
	HTTPEndpoint string

	// HTTPClient is an HTTP client for doing requests to /.well-known/openid-configuration and introspection endpoints.
	HTTPClient *http.Client

	// AccessTokenScope is a scope for getting access token for doing introspection.
	// The token should have introspection permission.
	AccessTokenScope []string

	// ScopeFilter is a list of access policies for filtering scopes during introspection.
	// If it is set, then only scopes that match at least one of the policies will be returned.
	ScopeFilter []IntrospectionScopeFilterAccessPolicy

	// Logger is a logger for logging errors and debug information.
	Logger log.FieldLogger

	// TrustedIssuerNotFoundFallback is a function called
	// when given issuer from JWT is not found in the list of trusted ones.
	TrustedIssuerNotFoundFallback TrustedIssNotFoundFallback

	// PrometheusLibInstanceLabel is a label for Prometheus metrics.
	// It allows distinguishing metrics from different instances of the same library.
	PrometheusLibInstanceLabel string

	// ClaimsCache is a configuration of how claims cache will be used.
	ClaimsCache IntrospectorCacheOpts

	// NegativeCache is a configuration of how negative cache will be used.
	NegativeCache IntrospectorCacheOpts
}

// IntrospectorCacheOpts is a configuration of how cache will be used.
type IntrospectorCacheOpts struct {
	Enabled    bool
	MaxEntries int
	TTL        time.Duration
}

// Introspector is a struct for introspecting tokens.
type Introspector struct {
	accessTokenProvider              IntrospectionTokenProvider
	accessTokenProviderInvalidatedAt atomic.Value
	accessTokenScope                 []string

	jwtParser *jwtgo.Parser

	GRPCClient *GRPCClient

	httpEndpoint string
	httpClient   *http.Client

	scopeFilter               []IntrospectionScopeFilterAccessPolicy
	scopeFilterFormURLEncoded string

	logger log.FieldLogger

	trustedIssuerStore            *idputil.TrustedIssuerStore
	trustedIssuerNotFoundFallback TrustedIssNotFoundFallback

	promMetrics *metrics.PrometheusMetrics

	ClaimsCache      IntrospectionClaimsCache
	claimsCacheTTL   time.Duration
	NegativeCache    IntrospectionNegativeCache
	negativeCacheTTL time.Duration
}

// IntrospectionResult is a struct for introspection result.
type IntrospectionResult struct {
	Active    bool   `json:"active"`
	TokenType string `json:"token_type,omitempty"`
	jwt.Claims
}

// NewIntrospector creates a new Introspector with the given token provider.
func NewIntrospector(tokenProvider IntrospectionTokenProvider) (*Introspector, error) {
	return NewIntrospectorWithOpts(tokenProvider, IntrospectorOpts{})
}

// NewIntrospectorWithOpts creates a new Introspector with the given token provider and options.
// See IntrospectorOpts for more details.
func NewIntrospectorWithOpts(accessTokenProvider IntrospectionTokenProvider, opts IntrospectorOpts) (*Introspector, error) {
	opts.Logger = idputil.PrepareLogger(opts.Logger)
	if opts.HTTPClient == nil {
		opts.HTTPClient = idputil.MakeDefaultHTTPClient(idputil.DefaultHTTPRequestTimeout, opts.Logger)
	}

	values := url.Values{}
	for i, policy := range opts.ScopeFilter {
		values.Set("scope_filter["+strconv.Itoa(i)+"].rn", policy.ResourceNamespace)
	}
	scopeFilterFormURLEncoded := values.Encode()

	promMetrics := metrics.GetPrometheusMetrics(opts.PrometheusLibInstanceLabel, tokenIntrospectorPromSource)

	// Building claims cache if needed.
	var claimsCache IntrospectionClaimsCache = &disabledIntrospectionClaimsCache{}
	if opts.ClaimsCache.Enabled {
		if opts.ClaimsCache.TTL == 0 {
			opts.ClaimsCache.TTL = DefaultIntrospectionClaimsCacheTTL
		}
		if opts.ClaimsCache.MaxEntries == 0 {
			opts.ClaimsCache.MaxEntries = DefaultIntrospectionClaimsCacheMaxEntries
		}
		cache, err := lrucache.New[[sha256.Size]byte, IntrospectionClaimsCacheItem](
			opts.ClaimsCache.MaxEntries, promMetrics.TokenClaimsCache)
		if err != nil {
			return nil, err
		}
		claimsCache = &IntrospectionLRUCache[[sha256.Size]byte, IntrospectionClaimsCacheItem]{cache}
	}

	// Building negative cache if needed.
	var negativeCache IntrospectionNegativeCache = &disabledIntrospectionNegativeCache{}
	if opts.NegativeCache.Enabled {
		if opts.NegativeCache.TTL == 0 {
			opts.NegativeCache.TTL = DefaultIntrospectionNegativeCacheTTL
		}
		if opts.NegativeCache.MaxEntries == 0 {
			opts.NegativeCache.MaxEntries = DefaultIntrospectionNegativeCacheMaxEntries
		}
		cache, err := lrucache.New[[sha256.Size]byte, IntrospectionNegativeCacheItem](
			opts.NegativeCache.MaxEntries, promMetrics.TokenNegativeCache)
		if err != nil {
			return nil, err
		}
		negativeCache = &IntrospectionLRUCache[[sha256.Size]byte, IntrospectionNegativeCacheItem]{cache}
	}

	return &Introspector{
		accessTokenProvider:           accessTokenProvider,
		accessTokenScope:              opts.AccessTokenScope,
		jwtParser:                     jwtgo.NewParser(),
		logger:                        opts.Logger,
		GRPCClient:                    opts.GRPCClient,
		httpClient:                    opts.HTTPClient,
		httpEndpoint:                  opts.HTTPEndpoint,
		scopeFilterFormURLEncoded:     scopeFilterFormURLEncoded,
		scopeFilter:                   opts.ScopeFilter,
		trustedIssuerStore:            idputil.NewTrustedIssuerStore(),
		trustedIssuerNotFoundFallback: opts.TrustedIssuerNotFoundFallback,
		promMetrics:                   promMetrics,
		ClaimsCache:                   claimsCache,
		claimsCacheTTL:                opts.ClaimsCache.TTL,
		NegativeCache:                 negativeCache,
		negativeCacheTTL:              opts.NegativeCache.TTL,
	}, nil
}

// IntrospectToken introspects the given token.
func (i *Introspector) IntrospectToken(ctx context.Context, token string) (IntrospectionResult, error) {
	cacheKey := sha256.Sum256(
		unsafe.Slice(unsafe.StringData(token), len(token))) // nolint:gosec // prevent redundant slice copying

	if c, ok := i.ClaimsCache.Get(ctx, cacheKey); ok && c.CreatedAt.Add(i.claimsCacheTTL).After(time.Now()) {
		return IntrospectionResult{Active: true, TokenType: c.TokenType, Claims: *c.Claims}, nil
	}
	if c, ok := i.NegativeCache.Get(ctx, cacheKey); ok && c.CreatedAt.Add(i.negativeCacheTTL).After(time.Now()) {
		return IntrospectionResult{Active: false}, nil
	}

	introspectionResult, err := i.introspectToken(ctx, token)
	if err != nil {
		return IntrospectionResult{}, err
	}
	if introspectionResult.Active {
		i.ClaimsCache.Add(ctx, cacheKey, IntrospectionClaimsCacheItem{
			Claims:    &introspectionResult.Claims,
			TokenType: introspectionResult.TokenType,
			CreatedAt: time.Now(),
		})
	} else {
		i.NegativeCache.Add(ctx, cacheKey, IntrospectionNegativeCacheItem{CreatedAt: time.Now()})
	}

	return introspectionResult, nil
}

// AddTrustedIssuer adds trusted issuer with specified name and URL.
func (i *Introspector) AddTrustedIssuer(issName, issURL string) {
	i.trustedIssuerStore.AddTrustedIssuer(issName, issURL)
}

// AddTrustedIssuerURL adds trusted issuer URL.
func (i *Introspector) AddTrustedIssuerURL(issURL string) error {
	return i.trustedIssuerStore.AddTrustedIssuerURL(issURL)
}

func (i *Introspector) introspectToken(ctx context.Context, token string) (IntrospectionResult, error) {
	introspectFn, err := i.makeIntrospectFuncForToken(ctx, token)
	if err != nil {
		return IntrospectionResult{}, err
	}

	result, err := introspectFn(ctx, token)
	if err == nil {
		return result, nil
	}

	if !errors.Is(err, ErrUnauthenticated) {
		return IntrospectionResult{}, err
	}

	// If introspection is unauthorized, then invalidate access token (if it is not invalidated recently) and try again.
	t, ok := i.accessTokenProviderInvalidatedAt.Load().(time.Time)
	now := time.Now()
	if !ok || now.Sub(t) > minAccessTokenProviderInvalidationInterval {
		i.accessTokenProvider.Invalidate()
		i.accessTokenProviderInvalidatedAt.Store(now)
		return introspectFn(ctx, token)
	}
	return IntrospectionResult{}, err
}

type introspectFunc func(ctx context.Context, token string) (IntrospectionResult, error)

func (i *Introspector) makeIntrospectFuncForToken(ctx context.Context, token string) (introspectFunc, error) {
	var err error

	if token == "" {
		return nil, makeTokenNotIntrospectableError(fmt.Errorf("token is missing"))
	}

	jwtHeaderEndIdx := strings.IndexByte(token, '.')
	if jwtHeaderEndIdx == -1 {
		return i.makeStaticIntrospectFuncOrError(fmt.Errorf("no JWT header found"))
	}
	var jwtHeaderBytes []byte
	if jwtHeaderBytes, err = i.jwtParser.DecodeSegment(token[:jwtHeaderEndIdx]); err != nil {
		return i.makeStaticIntrospectFuncOrError(fmt.Errorf("decode JWT header: %w", err))
	}
	headerDecoder := json.NewDecoder(bytes.NewReader(jwtHeaderBytes))
	headerDecoder.UseNumber()
	jwtHeader := make(map[string]interface{})
	if err = headerDecoder.Decode(&jwtHeader); err != nil {
		return i.makeStaticIntrospectFuncOrError(fmt.Errorf("unmarshal JWT header: %w", err))
	}
	if typ, ok := jwtHeader["typ"].(string); !ok || !strings.EqualFold(typ, idputil.JWTTypeAccessToken) {
		return i.makeStaticIntrospectFuncOrError(fmt.Errorf("token type is not %s", idputil.JWTTypeAccessToken))
	}
	if !checkIntrospectionRequiredByJWTHeader(jwtHeader) {
		return nil, ErrTokenIntrospectionNotNeeded
	}

	if i.httpEndpoint != "" {
		return i.makeIntrospectFuncHTTP(i.httpEndpoint), nil
	}
	if i.GRPCClient != nil {
		return i.makeIntrospectFuncGRPC(), nil
	}

	// Try to get issuer from JWT header first and then from JWT payload.
	// Issuer is usually presented in the JWT payload (it's an optional field, according to RFC 7519),
	// but it could be in the header as well for optimization purposes.
	// It's relevant for JWTs with large payloads.
	issuer, ok := jwtHeader["iss"].(string)
	if !ok || issuer == "" {
		jwtPayloadEndIdx := strings.IndexByte(token[jwtHeaderEndIdx+1:], '.')
		if jwtPayloadEndIdx == -1 {
			return nil, makeTokenNotIntrospectableError(fmt.Errorf("no JWT payload found"))
		}
		var jwtPayloadBytes []byte
		if jwtPayloadBytes, err = i.jwtParser.DecodeSegment(
			token[jwtHeaderEndIdx+1 : jwtHeaderEndIdx+1+jwtPayloadEndIdx],
		); err != nil {
			return nil, makeTokenNotIntrospectableError(fmt.Errorf("decode JWT payload: %w", err))
		}
		var originalClaims jwt.Claims
		if err = json.Unmarshal(jwtPayloadBytes, &originalClaims); err != nil {
			return nil, makeTokenNotIntrospectableError(fmt.Errorf("unmarshal JWT payload: %w", err))
		}
		if originalClaims.Issuer == "" {
			return nil, makeTokenNotIntrospectableError(fmt.Errorf("no issuer found in JWT"))
		}
		issuer = originalClaims.Issuer
	}

	issuerURL, ok := i.getURLForIssuerWithCallback(ctx, issuer)
	if !ok {
		return nil, makeTokenNotIntrospectableError(fmt.Errorf("issuer %q is not trusted", issuer))
	}

	// Try to get introspection endpoint URL from issuer.
	introspectionEndpointURL, err := i.getWellKnownIntrospectionEndpointURL(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("get introspection endpoint URL: %w", err)
	}
	return i.makeIntrospectFuncHTTP(introspectionEndpointURL), nil
}

func (i *Introspector) makeStaticIntrospectFuncOrError(inner error) (introspectFunc, error) {
	if i.GRPCClient != nil {
		return i.makeIntrospectFuncGRPC(), nil
	}
	if i.httpEndpoint != "" {
		return i.makeIntrospectFuncHTTP(i.httpEndpoint), nil
	}
	return nil, makeTokenNotIntrospectableError(inner)
}

func (i *Introspector) makeIntrospectFuncHTTP(introspectionEndpointURL string) introspectFunc {
	return func(ctx context.Context, token string) (IntrospectionResult, error) {
		accessToken, err := i.accessTokenProvider.GetToken(ctx, i.accessTokenScope...)
		if err != nil {
			return IntrospectionResult{}, fmt.Errorf("get access token for doing introspection: %w", err)
		}
		formEncoded := url.Values{"token": {token}}.Encode()
		if i.scopeFilterFormURLEncoded != "" {
			formEncoded += "&" + i.scopeFilterFormURLEncoded
		}
		req, err := http.NewRequest(http.MethodPost, introspectionEndpointURL, strings.NewReader(formEncoded))
		if err != nil {
			return IntrospectionResult{}, fmt.Errorf("new request: %w", err)
		}
		req.Header.Set("Authorization", makeBearerToken(accessToken))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		startTime := time.Now()
		resp, err := i.httpClient.Do(req.WithContext(ctx))
		elapsed := time.Since(startTime)
		if err != nil {
			i.promMetrics.ObserveHTTPClientRequest(http.MethodPost, introspectionEndpointURL, 0, elapsed, metrics.HTTPRequestErrorDo)
			return IntrospectionResult{}, fmt.Errorf("do request: %w", err)
		}
		defer func() {
			if closeBodyErr := resp.Body.Close(); closeBodyErr != nil {
				i.logger.Error(fmt.Sprintf("closing response body error for POST %s", introspectionEndpointURL),
					log.Error(closeBodyErr))
			}
		}()
		if resp.StatusCode != http.StatusOK {
			i.promMetrics.ObserveHTTPClientRequest(
				http.MethodPost, introspectionEndpointURL, resp.StatusCode, elapsed, metrics.HTTPRequestErrorUnexpectedStatusCode)
			if resp.StatusCode == http.StatusUnauthorized {
				return IntrospectionResult{}, ErrUnauthenticated
			}
			return IntrospectionResult{}, fmt.Errorf("unexpected HTTP code %d for POST %s", resp.StatusCode, introspectionEndpointURL)
		}

		var res IntrospectionResult
		if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
			i.promMetrics.ObserveHTTPClientRequest(
				http.MethodPost, introspectionEndpointURL, resp.StatusCode, elapsed, metrics.HTTPRequestErrorDecodeBody)
			return IntrospectionResult{}, fmt.Errorf("decode response body json for POST %s: %w", introspectionEndpointURL, err)
		}

		i.promMetrics.ObserveHTTPClientRequest(http.MethodPost, introspectionEndpointURL, resp.StatusCode, elapsed, "")
		return res, nil
	}
}

func (i *Introspector) makeIntrospectFuncGRPC() introspectFunc {
	return func(ctx context.Context, token string) (IntrospectionResult, error) {
		accessToken, err := i.accessTokenProvider.GetToken(ctx, i.accessTokenScope...)
		if err != nil {
			return IntrospectionResult{}, fmt.Errorf("get access token for doing introspection: %w", err)
		}
		res, err := i.GRPCClient.IntrospectToken(ctx, token, i.scopeFilter, accessToken)
		if err != nil {
			return IntrospectionResult{}, fmt.Errorf("introspect token: %w", err)
		}
		return res, nil
	}
}

func (i *Introspector) getWellKnownIntrospectionEndpointURL(ctx context.Context, issuerURL string) (string, error) {
	openIDCfgURL := strings.TrimSuffix(issuerURL, "/") + wellKnownPath
	openIDCfg, err := idputil.GetOpenIDConfiguration(
		ctx, i.httpClient, openIDCfgURL, nil, i.logger, i.promMetrics)
	if err != nil {
		return "", fmt.Errorf("get OpenID configuration: %w", err)
	}
	if openIDCfg.IntrospectionEndpoint == "" {
		return "", fmt.Errorf("no introspection endpoint URL found on %s", openIDCfgURL)
	}
	return openIDCfg.IntrospectionEndpoint, nil
}

func (i *Introspector) getURLForIssuerWithCallback(ctx context.Context, issuer string) (string, bool) {
	issURL, issFound := i.trustedIssuerStore.GetURLForIssuer(issuer)
	if issFound {
		return issURL, true
	}
	if i.trustedIssuerNotFoundFallback == nil {
		return "", false
	}
	return i.trustedIssuerNotFoundFallback(ctx, i, issuer)
}

func makeTokenNotIntrospectableError(inner error) error {
	if inner != nil {
		return fmt.Errorf("%w: %w", ErrTokenNotIntrospectable, inner)
	}
	return ErrTokenNotIntrospectable
}

func makeBearerToken(token string) string {
	return "Bearer " + token
}

// checkIntrospectionRequiredByJWTHeader checks if introspection is required by JWT header.
// Introspection is required by default.
func checkIntrospectionRequiredByJWTHeader(jwtHeader map[string]interface{}) bool {
	notRequiredIntrospection, ok := jwtHeader["nri"]
	if !ok {
		return true
	}
	var bVal bool
	if bVal, ok = notRequiredIntrospection.(bool); ok {
		return !bVal
	}
	var nVal json.Number
	if nVal, ok = notRequiredIntrospection.(json.Number); ok {
		iVal, err := nVal.Int64()
		if err != nil {
			return true
		}
		return iVal == 0
	}
	return true
}

type IntrospectionClaimsCacheItem struct {
	Claims    *jwt.Claims
	TokenType string
	CreatedAt time.Time
}

type IntrospectionClaimsCache interface {
	Get(ctx context.Context, key [sha256.Size]byte) (IntrospectionClaimsCacheItem, bool)
	Add(ctx context.Context, key [sha256.Size]byte, value IntrospectionClaimsCacheItem)
	Purge(ctx context.Context)
	Len(ctx context.Context) int
}

type IntrospectionNegativeCacheItem struct {
	CreatedAt time.Time
}

type IntrospectionNegativeCache interface {
	Get(ctx context.Context, key [sha256.Size]byte) (IntrospectionNegativeCacheItem, bool)
	Add(ctx context.Context, key [sha256.Size]byte, value IntrospectionNegativeCacheItem)
	Purge(ctx context.Context)
	Len(ctx context.Context) int
}

type IntrospectionLRUCache[K comparable, V any] struct {
	cache *lrucache.LRUCache[K, V]
}

func (a *IntrospectionLRUCache[K, V]) Get(_ context.Context, key K) (V, bool) {
	return a.cache.Get(key)
}

func (a *IntrospectionLRUCache[K, V]) Add(_ context.Context, key K, val V) {
	a.cache.Add(key, val)
}

func (a *IntrospectionLRUCache[K, V]) Purge(ctx context.Context) {
	a.cache.Purge()
}

func (a *IntrospectionLRUCache[K, V]) Len(ctx context.Context) int {
	return a.cache.Len()
}

type disabledIntrospectionClaimsCache struct{}

func (c *disabledIntrospectionClaimsCache) Get(ctx context.Context, key [sha256.Size]byte) (IntrospectionClaimsCacheItem, bool) {
	return IntrospectionClaimsCacheItem{}, false
}
func (c *disabledIntrospectionClaimsCache) Add(ctx context.Context, key [sha256.Size]byte, value IntrospectionClaimsCacheItem) {
}
func (c *disabledIntrospectionClaimsCache) Purge(ctx context.Context)   {}
func (c *disabledIntrospectionClaimsCache) Len(ctx context.Context) int { return 0 }

type disabledIntrospectionNegativeCache struct{}

func (c *disabledIntrospectionNegativeCache) Get(ctx context.Context, key [sha256.Size]byte) (IntrospectionNegativeCacheItem, bool) {
	return IntrospectionNegativeCacheItem{}, false
}
func (c *disabledIntrospectionNegativeCache) Add(ctx context.Context, key [sha256.Size]byte, value IntrospectionNegativeCacheItem) {
}
func (c *disabledIntrospectionNegativeCache) Purge(ctx context.Context)   {}
func (c *disabledIntrospectionNegativeCache) Len(ctx context.Context) int { return 0 }
