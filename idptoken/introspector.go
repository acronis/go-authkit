/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptoken

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/acronis/go-appkit/log"
	jwtgo "github.com/golang-jwt/jwt/v5"

	"github.com/acronis/go-authkit/internal/idputil"
	"github.com/acronis/go-authkit/internal/metrics"
	"github.com/acronis/go-authkit/jwt"
)

const JWTTypeAccessToken = "at+jwt"

const TokenTypeBearer = "bearer"

const minAccessTokenProviderInvalidationInterval = time.Minute

const tokenIntrospectorPromSource = "token_introspector"

// ErrTokenNotIntrospectable is returned when token is not introspectable.
var ErrTokenNotIntrospectable = errors.New("token is not introspectable")

// ErrTokenIntrospectionNotNeeded is returned when token introspection is unnecessary
// (i.e., it already contains all necessary information).
var ErrTokenIntrospectionNotNeeded = errors.New("token introspection is not needed")

// ErrTokenIntrospectionUnauthenticated is returned when token introspection is unauthenticated.
var ErrTokenIntrospectionUnauthenticated = errors.New("token introspection is unauthenticated")

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
	// GRPCClient is a GRPC client for doing introspection.
	// If it is set, then introspection will be done using this client.
	// Otherwise, introspection will be done via HTTP.
	GRPCClient *GRPCClient

	// StaticHTTPEndpoint is a static URL for introspection.
	// If it is set, then introspection will be done using this endpoint.
	// Otherwise, introspection will be done using issuer URL (/.well-known/openid-configuration response).
	// In this case, issuer URL should be present in JWT header or payload.
	StaticHTTPEndpoint string

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
}

// Introspector is a struct for introspecting tokens.
type Introspector struct {
	accessTokenProvider              IntrospectionTokenProvider
	accessTokenProviderInvalidatedAt atomic.Value
	accessTokenScope                 []string

	jwtParser *jwtgo.Parser

	grpcClient    *GRPCClient
	staticHTTPURL string
	httpClient    *http.Client

	scopeFilter               []IntrospectionScopeFilterAccessPolicy
	scopeFilterFormURLEncoded string

	logger log.FieldLogger

	trustedIssuerStore            *idputil.TrustedIssuerStore
	trustedIssuerNotFoundFallback TrustedIssNotFoundFallback

	promMetrics *metrics.PrometheusMetrics
}

// IntrospectionResult is a struct for introspection result.
type IntrospectionResult struct {
	Active    bool   `json:"active"`
	TokenType string `json:"token_type,omitempty"`
	jwt.Claims
}

// NewIntrospector creates a new Introspector with the given token provider.
func NewIntrospector(tokenProvider IntrospectionTokenProvider) *Introspector {
	return NewIntrospectorWithOpts(tokenProvider, IntrospectorOpts{})
}

// NewIntrospectorWithOpts creates a new Introspector with the given token provider and options.
// See IntrospectorOpts for more details.
func NewIntrospectorWithOpts(accessTokenProvider IntrospectionTokenProvider, opts IntrospectorOpts) *Introspector {
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

	return &Introspector{
		accessTokenProvider:           accessTokenProvider,
		accessTokenScope:              opts.AccessTokenScope,
		jwtParser:                     jwtgo.NewParser(),
		logger:                        opts.Logger,
		grpcClient:                    opts.GRPCClient,
		httpClient:                    opts.HTTPClient,
		scopeFilterFormURLEncoded:     scopeFilterFormURLEncoded,
		scopeFilter:                   opts.ScopeFilter,
		staticHTTPURL:                 opts.StaticHTTPEndpoint,
		trustedIssuerStore:            idputil.NewTrustedIssuerStore(),
		trustedIssuerNotFoundFallback: opts.TrustedIssuerNotFoundFallback,
		promMetrics:                   promMetrics,
	}
}

// IntrospectToken introspects the given token.
func (i *Introspector) IntrospectToken(ctx context.Context, token string) (IntrospectionResult, error) {
	introspectFn, err := i.makeIntrospectFuncForToken(ctx, token)
	if err != nil {
		return IntrospectionResult{}, err
	}

	result, err := introspectFn(ctx, token)
	if err == nil {
		return result, nil
	}

	if !errors.Is(err, ErrTokenIntrospectionUnauthenticated) {
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

// AddTrustedIssuer adds trusted issuer with specified name and URL.
func (i *Introspector) AddTrustedIssuer(issName, issURL string) {
	i.trustedIssuerStore.AddTrustedIssuer(issName, issURL)
}

// AddTrustedIssuerURL adds trusted issuer URL.
func (i *Introspector) AddTrustedIssuerURL(issURL string) error {
	return i.trustedIssuerStore.AddTrustedIssuerURL(issURL)
}

type introspectFunc func(ctx context.Context, token string) (IntrospectionResult, error)

func (i *Introspector) makeIntrospectFuncForToken(ctx context.Context, token string) (introspectFunc, error) {
	var err error

	if token == "" {
		return i.makeStaticIntrospectFuncOrError(fmt.Errorf("token is missing"))
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
	if typ, ok := jwtHeader["typ"].(string); !ok || !strings.EqualFold(typ, JWTTypeAccessToken) {
		return i.makeStaticIntrospectFuncOrError(fmt.Errorf("token type is not %s", JWTTypeAccessToken))
	}
	if !checkIntrospectionRequiredByJWTHeader(jwtHeader) {
		return nil, ErrTokenIntrospectionNotNeeded
	}

	if i.staticHTTPURL != "" {
		return i.makeIntrospectFuncHTTP(i.staticHTTPURL), nil
	}
	if i.grpcClient != nil {
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
	if i.grpcClient != nil {
		return i.makeIntrospectFuncGRPC(), nil
	}
	if i.staticHTTPURL != "" {
		return i.makeIntrospectFuncHTTP(i.staticHTTPURL), nil
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
				return IntrospectionResult{}, ErrTokenIntrospectionUnauthenticated
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
		res, err := i.grpcClient.IntrospectToken(ctx, token, i.scopeFilter, accessToken)
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
