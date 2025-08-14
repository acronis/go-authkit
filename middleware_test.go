/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package authkit_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/acronis/go-appkit/testutil"
	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/acronis/go-authkit"
	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/internal/metrics"
	"github.com/acronis/go-authkit/jwt"
)

const (
	testErrDomain   = "TestDomain"
	testBearerToken = "a.b.c"
)

type mockJWTAuthMiddlewareNextHandler struct {
	request *http.Request
	called  int
}

func (h *mockJWTAuthMiddlewareNextHandler) ServeHTTP(_ http.ResponseWriter, r *http.Request) {
	h.request = r
	h.called++
}

type mockJWTParser struct {
	parseCalled    int
	claimsToReturn jwt.Claims
	errToReturn    error
	passedToken    string
}

func (p *mockJWTParser) Parse(_ context.Context, token string) (jwt.Claims, error) {
	p.parseCalled++
	p.passedToken = token
	return p.claimsToReturn, p.errToReturn
}

type mockTokenIntrospector struct {
	introspectCalled  int
	introspectedToken string
	resultToReturn    idptoken.IntrospectionResult
	errToReturn       error
}

func (i *mockTokenIntrospector) IntrospectToken(_ context.Context, token string) (idptoken.IntrospectionResult, error) {
	i.introspectCalled++
	i.introspectedToken = token
	return i.resultToReturn, i.errToReturn
}

func TestJWTAuthMiddleware(t *testing.T) {
	t.Run("bearer token is missing", func(t *testing.T) {
		for _, headerVal := range []string{"", "foobar", "Bearer", "Bearer "} {
			parser := &mockJWTParser{}
			next := &mockJWTAuthMiddlewareNextHandler{}
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			if headerVal != "" {
				req.Header.Set(authkit.HeaderAuthorization, headerVal)
			}
			resp := httptest.NewRecorder()

			authkit.JWTAuthMiddleware(testErrDomain, parser)(next).ServeHTTP(resp, req)

			testutil.RequireErrorInRecorder(t, resp, http.StatusUnauthorized, testErrDomain, authkit.ErrCodeBearerTokenMissing)
			require.Equal(t, 0, parser.parseCalled)
			require.Equal(t, 0, next.called)
			require.Nil(t, next.request)
		}
	})

	t.Run("authentication failed", func(t *testing.T) {
		parser := &mockJWTParser{errToReturn: errors.New("malformed JWT")}
		next := &mockJWTAuthMiddlewareNextHandler{}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		withBearerToken(req, "foobar")
		resp := httptest.NewRecorder()

		authkit.JWTAuthMiddleware(testErrDomain, parser)(next).ServeHTTP(resp, req)

		testutil.RequireErrorInRecorder(t, resp, http.StatusUnauthorized, testErrDomain, authkit.ErrCodeAuthenticationFailed)
		require.Equal(t, 1, parser.parseCalled)
		require.Equal(t, 0, next.called)
		require.Nil(t, next.request)
	})

	t.Run("ok", func(t *testing.T) {
		const issuer = "my-idp.com"
		parser := &mockJWTParser{claimsToReturn: &jwt.DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: issuer}}}
		next := &mockJWTAuthMiddlewareNextHandler{}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		withBearerToken(req, testBearerToken)
		resp := httptest.NewRecorder()

		authkit.JWTAuthMiddleware(testErrDomain, parser)(next).ServeHTTP(resp, req)

		require.Equal(t, http.StatusOK, resp.Code)
		require.Equal(t, 1, parser.parseCalled)
		require.Equal(t, 1, next.called)
		require.NotNil(t, authkit.GetJWTClaimsFromContext(next.request.Context()))
		nextIssuer, err := authkit.GetJWTClaimsFromContext(next.request.Context()).GetIssuer()
		require.NoError(t, err)
		require.Equal(t, issuer, nextIssuer)
	})

	t.Run("introspection failed", func(t *testing.T) {
		const issuer = "my-idp.com"
		parser := &mockJWTParser{claimsToReturn: &jwt.DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: issuer}}}
		introspector := &mockTokenIntrospector{errToReturn: errors.New("introspection failed")}
		next := &mockJWTAuthMiddlewareNextHandler{}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		withBearerToken(req, testBearerToken)
		resp := httptest.NewRecorder()

		testutil.RequireSamplesCountInCounter(t, metrics.GetPrometheusMetrics("", metrics.SourceHTTPMiddleware).
			TokenIntrospectionsTotal.WithLabelValues(metrics.TokenIntrospectionStatusError), 0)

		authkit.JWTAuthMiddleware(testErrDomain, parser, authkit.WithJWTAuthMiddlewareTokenIntrospector(introspector))(next).
			ServeHTTP(resp, req)

		testutil.RequireErrorInRecorder(t, resp, http.StatusUnauthorized, testErrDomain, authkit.ErrCodeAuthenticationFailed)
		require.Equal(t, 1, introspector.introspectCalled)
		require.Equal(t, 0, parser.parseCalled)
		require.Equal(t, 0, next.called)

		testutil.RequireSamplesCountInCounter(t, metrics.GetPrometheusMetrics("", metrics.SourceHTTPMiddleware).
			TokenIntrospectionsTotal.WithLabelValues(metrics.TokenIntrospectionStatusError), 1)
	})

	t.Run("service unavailable", func(t *testing.T) {
		const issuer = "my-idp.com"
		parser := &mockJWTParser{claimsToReturn: &jwt.DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: issuer}}}
		introspector := &mockTokenIntrospector{errToReturn: &idptoken.ServiceUnavailableError{
			RetryAfter: "60",
			Err:        errors.New("service unavailable"),
		}}
		next := &mockJWTAuthMiddlewareNextHandler{}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		withBearerToken(req, testBearerToken)
		resp := httptest.NewRecorder()

		testutil.RequireSamplesCountInCounter(t, metrics.GetPrometheusMetrics("", metrics.SourceHTTPMiddleware).
			TokenIntrospectionsTotal.WithLabelValues(metrics.TokenIntrospectionStatusServiceUnavailable), 0)

		authkit.JWTAuthMiddleware(testErrDomain, parser, authkit.WithJWTAuthMiddlewareTokenIntrospector(introspector))(next).
			ServeHTTP(resp, req)

		testutil.RequireErrorInRecorder(t, resp, http.StatusServiceUnavailable, testErrDomain, authkit.ErrCodeServiceUnavailable)
		require.Equal(t, "60", resp.Header().Get("Retry-After"))
		require.Equal(t, 1, introspector.introspectCalled)
		require.Equal(t, 0, parser.parseCalled)
		require.Equal(t, 0, next.called)

		testutil.RequireSamplesCountInCounter(t, metrics.GetPrometheusMetrics("", metrics.SourceHTTPMiddleware).
			TokenIntrospectionsTotal.WithLabelValues(metrics.TokenIntrospectionStatusServiceUnavailable), 1)
	})

	t.Run("throttled", func(t *testing.T) {
		const issuer = "my-idp.com"
		parser := &mockJWTParser{claimsToReturn: &jwt.DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: issuer}}}
		introspector := &mockTokenIntrospector{errToReturn: &idptoken.ThrottledError{
			RetryAfter: "30",
			Err:        errors.New("throttled"),
		}}
		next := &mockJWTAuthMiddlewareNextHandler{}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		withBearerToken(req, testBearerToken)
		resp := httptest.NewRecorder()

		const promLabel = "throttled_test"
		testutil.RequireSamplesCountInCounter(t, metrics.GetPrometheusMetrics(promLabel, metrics.SourceHTTPMiddleware).
			TokenIntrospectionsTotal.WithLabelValues(metrics.TokenIntrospectionStatusThrottled), 0)

		authkit.JWTAuthMiddleware(testErrDomain, parser, authkit.WithJWTAuthMiddlewareTokenIntrospector(introspector),
			authkit.WithJWTAuthMiddlewarePrometheusLibInstanceLabel(promLabel))(next).
			ServeHTTP(resp, req)

		testutil.RequireErrorInRecorder(t, resp, http.StatusServiceUnavailable, testErrDomain, authkit.ErrCodeServiceUnavailable)
		require.Equal(t, "30", resp.Header().Get("Retry-After"))
		require.Equal(t, 1, introspector.introspectCalled)
		require.Equal(t, 0, parser.parseCalled)
		require.Equal(t, 0, next.called)

		testutil.RequireSamplesCountInCounter(t, metrics.GetPrometheusMetrics(promLabel, metrics.SourceHTTPMiddleware).
			TokenIntrospectionsTotal.WithLabelValues(metrics.TokenIntrospectionStatusThrottled), 1)
	})

	t.Run("service unavailable from new error type", func(t *testing.T) {
		const issuer = "my-idp.com"
		parser := &mockJWTParser{claimsToReturn: &jwt.DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: issuer}}}
		introspector := &mockTokenIntrospector{errToReturn: &idptoken.ServiceUnavailableError{
			RetryAfter: "120",
			Err:        errors.New("service unavailable"),
		}}
		next := &mockJWTAuthMiddlewareNextHandler{}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		withBearerToken(req, testBearerToken)
		resp := httptest.NewRecorder()

		const promLabel = "svc_unavailable_new_test"
		testutil.RequireSamplesCountInCounter(t, metrics.GetPrometheusMetrics(promLabel, metrics.SourceHTTPMiddleware).
			TokenIntrospectionsTotal.WithLabelValues(metrics.TokenIntrospectionStatusServiceUnavailable), 0)

		authkit.JWTAuthMiddleware(testErrDomain, parser, authkit.WithJWTAuthMiddlewareTokenIntrospector(introspector),
			authkit.WithJWTAuthMiddlewarePrometheusLibInstanceLabel(promLabel))(next).
			ServeHTTP(resp, req)

		testutil.RequireErrorInRecorder(t, resp, http.StatusServiceUnavailable, testErrDomain, authkit.ErrCodeServiceUnavailable)
		require.Equal(t, "120", resp.Header().Get("Retry-After"))
		require.Equal(t, 1, introspector.introspectCalled)
		require.Equal(t, 0, parser.parseCalled)
		require.Equal(t, 0, next.called)

		testutil.RequireSamplesCountInCounter(t, metrics.GetPrometheusMetrics(promLabel, metrics.SourceHTTPMiddleware).
			TokenIntrospectionsTotal.WithLabelValues(metrics.TokenIntrospectionStatusServiceUnavailable), 1)
	})

	t.Run("introspection is not needed", func(t *testing.T) {
		const issuer = "my-idp.com"
		parser := &mockJWTParser{claimsToReturn: &jwt.DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: issuer}}}
		introspector := &mockTokenIntrospector{errToReturn: idptoken.ErrTokenIntrospectionNotNeeded}
		next := &mockJWTAuthMiddlewareNextHandler{}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		withBearerToken(req, testBearerToken)
		resp := httptest.NewRecorder()

		testutil.RequireSamplesCountInCounter(t, metrics.GetPrometheusMetrics("", metrics.SourceHTTPMiddleware).
			TokenIntrospectionsTotal.WithLabelValues(metrics.TokenIntrospectionStatusNotNeeded), 0)

		authkit.JWTAuthMiddleware(testErrDomain, parser, authkit.WithJWTAuthMiddlewareTokenIntrospector(introspector))(next).
			ServeHTTP(resp, req)

		require.Equal(t, http.StatusOK, resp.Code)
		require.Equal(t, 1, introspector.introspectCalled)
		require.Equal(t, 1, parser.parseCalled)
		require.Equal(t, 1, next.called)
		nextIssuer, err := authkit.GetJWTClaimsFromContext(next.request.Context()).GetIssuer()
		require.NoError(t, err)
		require.Equal(t, issuer, nextIssuer)

		testutil.RequireSamplesCountInCounter(t, metrics.GetPrometheusMetrics("", metrics.SourceHTTPMiddleware).
			TokenIntrospectionsTotal.WithLabelValues(metrics.TokenIntrospectionStatusNotNeeded), 1)
	})

	t.Run("ok, token is not introspectable", func(t *testing.T) {
		const issuer = "my-idp.com"
		parser := &mockJWTParser{claimsToReturn: &jwt.DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: issuer}}}
		introspector := &mockTokenIntrospector{errToReturn: idptoken.ErrTokenNotIntrospectable}
		next := &mockJWTAuthMiddlewareNextHandler{}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		withBearerToken(req, testBearerToken)
		resp := httptest.NewRecorder()

		testutil.RequireSamplesCountInCounter(t, metrics.GetPrometheusMetrics("", metrics.SourceHTTPMiddleware).
			TokenIntrospectionsTotal.WithLabelValues(metrics.TokenIntrospectionStatusNotIntrospectable), 0)

		authkit.JWTAuthMiddleware(testErrDomain, parser, authkit.WithJWTAuthMiddlewareTokenIntrospector(introspector))(next).
			ServeHTTP(resp, req)

		require.Equal(t, http.StatusOK, resp.Code)
		require.Equal(t, 1, introspector.introspectCalled)
		require.Equal(t, 1, parser.parseCalled)
		require.Equal(t, 1, next.called)
		require.NotNil(t, authkit.GetJWTClaimsFromContext(next.request.Context()))
		nextIssuer, err := authkit.GetJWTClaimsFromContext(next.request.Context()).GetIssuer()
		require.NoError(t, err)
		require.Equal(t, issuer, nextIssuer)

		testutil.RequireSamplesCountInCounter(t, metrics.GetPrometheusMetrics("", metrics.SourceHTTPMiddleware).
			TokenIntrospectionsTotal.WithLabelValues(metrics.TokenIntrospectionStatusNotIntrospectable), 1)
	})

	t.Run("authentication failed, token is introspected but inactive", func(t *testing.T) {
		parser := &mockJWTParser{}
		introspector := &mockTokenIntrospector{resultToReturn: &idptoken.DefaultIntrospectionResult{Active: false}}
		next := &mockJWTAuthMiddlewareNextHandler{}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		withBearerToken(req, testBearerToken)
		resp := httptest.NewRecorder()

		testutil.RequireSamplesCountInCounter(t, metrics.GetPrometheusMetrics("", metrics.SourceHTTPMiddleware).
			TokenIntrospectionsTotal.WithLabelValues(metrics.TokenIntrospectionStatusNotActive), 0)

		authkit.JWTAuthMiddleware(testErrDomain, parser, authkit.WithJWTAuthMiddlewareTokenIntrospector(introspector))(next).
			ServeHTTP(resp, req)

		testutil.RequireErrorInRecorder(t, resp, http.StatusUnauthorized, testErrDomain, authkit.ErrCodeAuthenticationFailed)
		require.Equal(t, 1, introspector.introspectCalled)
		require.Equal(t, 0, parser.parseCalled)
		require.Equal(t, 0, next.called)

		testutil.RequireSamplesCountInCounter(t, metrics.GetPrometheusMetrics("", metrics.SourceHTTPMiddleware).
			TokenIntrospectionsTotal.WithLabelValues(metrics.TokenIntrospectionStatusNotActive), 1)
	})

	t.Run("ok, token is introspected and active", func(t *testing.T) {
		const issuer = "my-idp.com"
		parser := &mockJWTParser{}
		introspector := &mockTokenIntrospector{resultToReturn: &idptoken.DefaultIntrospectionResult{
			Active: true, DefaultClaims: jwt.DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: issuer}}}}
		next := &mockJWTAuthMiddlewareNextHandler{}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		withBearerToken(req, testBearerToken)
		resp := httptest.NewRecorder()

		testutil.RequireSamplesCountInCounter(t, metrics.GetPrometheusMetrics("", metrics.SourceHTTPMiddleware).
			TokenIntrospectionsTotal.WithLabelValues(metrics.TokenIntrospectionStatusActive), 0)

		authkit.JWTAuthMiddleware(testErrDomain, parser, authkit.WithJWTAuthMiddlewareTokenIntrospector(introspector))(next).
			ServeHTTP(resp, req)

		require.Equal(t, http.StatusOK, resp.Code)
		require.Equal(t, 1, introspector.introspectCalled)
		require.Equal(t, 0, parser.parseCalled)
		require.Equal(t, 1, next.called)
		require.NotNil(t, authkit.GetJWTClaimsFromContext(next.request.Context()))
		nextIssuer, err := authkit.GetJWTClaimsFromContext(next.request.Context()).GetIssuer()
		require.NoError(t, err)
		require.Equal(t, issuer, nextIssuer)

		testutil.RequireSamplesCountInCounter(t, metrics.GetPrometheusMetrics("", metrics.SourceHTTPMiddleware).
			TokenIntrospectionsTotal.WithLabelValues(metrics.TokenIntrospectionStatusActive), 1)
	})

	t.Run("context keys added by verifyAccess are preserved", func(t *testing.T) {
		const issuer = "my-idp.com"
		parser := &mockJWTParser{claimsToReturn: &jwt.DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: issuer}}}
		next := &mockJWTAuthMiddlewareNextHandler{}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		withBearerToken(req, testBearerToken)
		resp := httptest.NewRecorder()

		const (
			ctxKey   = "verify-access-key"
			ctxValue = "verify-access-value"
		)
		var verifyAccess = func(r *http.Request, claims jwt.Claims) bool {
			*r = *r.WithContext(context.WithValue(r.Context(), ctxKey, ctxValue))
			return true
		}

		authkit.JWTAuthMiddleware(testErrDomain, parser, authkit.WithJWTAuthMiddlewareVerifyAccess(verifyAccess))(next).
			ServeHTTP(resp, req)

		require.Equal(t, http.StatusOK, resp.Code)
		require.Equal(t, 1, parser.parseCalled)
		require.Equal(t, 1, next.called)
		require.Equal(t, testBearerToken, authkit.GetBearerTokenFromContext(next.request.Context()),
			"context is missing bearer token")
		require.Equal(t, ctxValue, next.request.Context().Value(ctxKey),
			"context key added by verifyAccess is not preserved")
	})
}

func TestJWTAuthMiddlewareWithVerifyAccess(t *testing.T) {
	t.Run("authorization failed", func(t *testing.T) {
		parser := &mockJWTParser{claimsToReturn: &jwt.DefaultClaims{}}
		next := &mockJWTAuthMiddlewareNextHandler{}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		withBearerToken(req, testBearerToken)
		resp := httptest.NewRecorder()

		verifyAccess := authkit.NewVerifyAccessByRolesInJWT(authkit.Role{Namespace: "my-service", Name: "admin"})
		authkit.JWTAuthMiddleware(testErrDomain, parser, authkit.WithJWTAuthMiddlewareVerifyAccess(verifyAccess))(next).
			ServeHTTP(resp, req)

		testutil.RequireErrorInRecorder(t, resp, http.StatusForbidden, testErrDomain, authkit.ErrCodeAuthorizationFailed)
		require.Equal(t, 1, parser.parseCalled)
		require.Equal(t, 0, next.called)
		require.Nil(t, next.request)
	})

	t.Run("ok", func(t *testing.T) {
		scope := []jwt.AccessPolicy{{ResourceNamespace: "my-service", Role: "admin"}}
		parser := &mockJWTParser{claimsToReturn: &jwt.DefaultClaims{Scope: scope}}
		next := &mockJWTAuthMiddlewareNextHandler{}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		withBearerToken(req, testBearerToken)
		resp := httptest.NewRecorder()

		verifyAccess := authkit.NewVerifyAccessByRolesInJWT(authkit.Role{Namespace: "my-service", Name: "admin"})
		authkit.JWTAuthMiddleware(testErrDomain, parser, authkit.WithJWTAuthMiddlewareVerifyAccess(verifyAccess))(next).
			ServeHTTP(resp, req)

		require.Equal(t, http.StatusOK, resp.Code)
		require.Equal(t, 1, parser.parseCalled)
		require.Equal(t, 1, next.called)
		require.NotNil(t, authkit.GetJWTClaimsFromContext(next.request.Context()))
		require.EqualValues(t, scope, authkit.GetJWTClaimsFromContext(next.request.Context()).GetScope())
	})
}

func withBearerToken(r *http.Request, t string) {
	r.Header.Set(authkit.HeaderAuthorization, "Bearer "+t)
}
