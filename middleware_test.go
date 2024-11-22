/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package authkit

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/acronis/go-appkit/testutil"
	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/jwt"
)

type mockJWTAuthMiddlewareNextHandler struct {
	called    int
	jwtClaims jwt.Claims
}

func (h *mockJWTAuthMiddlewareNextHandler) ServeHTTP(_ http.ResponseWriter, r *http.Request) {
	h.called++
	h.jwtClaims = GetJWTClaimsFromContext(r.Context())
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
	const errDomain = "TestDomain"

	t.Run("bearer token is missing", func(t *testing.T) {
		for _, headerVal := range []string{"", "foobar", "Bearer", "Bearer "} {
			parser := &mockJWTParser{}
			next := &mockJWTAuthMiddlewareNextHandler{}
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			if headerVal != "" {
				req.Header.Set(HeaderAuthorization, headerVal)
			}
			resp := httptest.NewRecorder()

			JWTAuthMiddleware(errDomain, parser)(next).ServeHTTP(resp, req)

			testutil.RequireErrorInRecorder(t, resp, http.StatusUnauthorized, errDomain, ErrCodeBearerTokenMissing)
			require.Equal(t, 0, parser.parseCalled)
			require.Equal(t, 0, next.called)
			require.Nil(t, next.jwtClaims)
		}
	})

	t.Run("authentication failed", func(t *testing.T) {
		parser := &mockJWTParser{errToReturn: errors.New("malformed JWT")}
		next := &mockJWTAuthMiddlewareNextHandler{}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set(HeaderAuthorization, "Bearer foobar")
		resp := httptest.NewRecorder()

		JWTAuthMiddleware(errDomain, parser)(next).ServeHTTP(resp, req)

		testutil.RequireErrorInRecorder(t, resp, http.StatusUnauthorized, errDomain, ErrCodeAuthenticationFailed)
		require.Equal(t, 1, parser.parseCalled)
		require.Equal(t, 0, next.called)
		require.Nil(t, next.jwtClaims)
	})

	t.Run("ok", func(t *testing.T) {
		const issuer = "my-idp.com"
		parser := &mockJWTParser{claimsToReturn: &jwt.DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: issuer}}}
		next := &mockJWTAuthMiddlewareNextHandler{}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set(HeaderAuthorization, "Bearer a.b.c")
		resp := httptest.NewRecorder()

		JWTAuthMiddleware(errDomain, parser)(next).ServeHTTP(resp, req)

		require.Equal(t, http.StatusOK, resp.Code)
		require.Equal(t, 1, parser.parseCalled)
		require.Equal(t, 1, next.called)
		require.NotNil(t, next.jwtClaims)
		nextIssuer, err := next.jwtClaims.GetIssuer()
		require.NoError(t, err)
		require.Equal(t, issuer, nextIssuer)
	})

	t.Run("introspection failed", func(t *testing.T) {
		const issuer = "my-idp.com"
		parser := &mockJWTParser{claimsToReturn: &jwt.DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: issuer}}}
		introspector := &mockTokenIntrospector{errToReturn: errors.New("introspection failed")}
		next := &mockJWTAuthMiddlewareNextHandler{}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set(HeaderAuthorization, "Bearer a.b.c")
		resp := httptest.NewRecorder()

		JWTAuthMiddleware(errDomain, parser, WithJWTAuthMiddlewareTokenIntrospector(introspector))(next).ServeHTTP(resp, req)

		testutil.RequireErrorInRecorder(t, resp, http.StatusUnauthorized, errDomain, ErrCodeAuthenticationFailed)
		require.Equal(t, 1, introspector.introspectCalled)
		require.Equal(t, 0, parser.parseCalled)
		require.Equal(t, 0, next.called)
	})

	t.Run("introspection is not needed", func(t *testing.T) {
		const issuer = "my-idp.com"
		parser := &mockJWTParser{claimsToReturn: &jwt.DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: issuer}}}
		introspector := &mockTokenIntrospector{errToReturn: idptoken.ErrTokenIntrospectionNotNeeded}
		next := &mockJWTAuthMiddlewareNextHandler{}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set(HeaderAuthorization, "Bearer a.b.c")
		resp := httptest.NewRecorder()

		JWTAuthMiddleware(errDomain, parser, WithJWTAuthMiddlewareTokenIntrospector(introspector))(next).ServeHTTP(resp, req)

		require.Equal(t, http.StatusOK, resp.Code)
		require.Equal(t, 1, introspector.introspectCalled)
		require.Equal(t, 1, parser.parseCalled)
		require.Equal(t, 1, next.called)
		nextIssuer, err := next.jwtClaims.GetIssuer()
		require.NoError(t, err)
		require.Equal(t, issuer, nextIssuer)
	})

	t.Run("ok, token is not introspectable", func(t *testing.T) {
		const issuer = "my-idp.com"
		parser := &mockJWTParser{claimsToReturn: &jwt.DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: issuer}}}
		introspector := &mockTokenIntrospector{errToReturn: idptoken.ErrTokenNotIntrospectable}
		next := &mockJWTAuthMiddlewareNextHandler{}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set(HeaderAuthorization, "Bearer a.b.c")
		resp := httptest.NewRecorder()

		JWTAuthMiddleware(errDomain, parser, WithJWTAuthMiddlewareTokenIntrospector(introspector))(next).ServeHTTP(resp, req)

		require.Equal(t, http.StatusOK, resp.Code)
		require.Equal(t, 1, introspector.introspectCalled)
		require.Equal(t, 1, parser.parseCalled)
		require.Equal(t, 1, next.called)
		require.NotNil(t, next.jwtClaims)
		nextIssuer, err := next.jwtClaims.GetIssuer()
		require.NoError(t, err)
		require.Equal(t, issuer, nextIssuer)
	})

	t.Run("authentication failed, token is introspected but inactive", func(t *testing.T) {
		const issuer = "my-idp.com"
		parser := &mockJWTParser{}
		introspector := &mockTokenIntrospector{resultToReturn: &idptoken.DefaultIntrospectionResult{Active: false}}
		next := &mockJWTAuthMiddlewareNextHandler{}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set(HeaderAuthorization, "Bearer a.b.c")
		resp := httptest.NewRecorder()

		JWTAuthMiddleware(errDomain, parser, WithJWTAuthMiddlewareTokenIntrospector(introspector))(next).ServeHTTP(resp, req)

		testutil.RequireErrorInRecorder(t, resp, http.StatusUnauthorized, errDomain, ErrCodeAuthenticationFailed)
		require.Equal(t, 1, introspector.introspectCalled)
		require.Equal(t, 0, parser.parseCalled)
		require.Equal(t, 0, next.called)
	})

	t.Run("ok, token is introspected and active", func(t *testing.T) {
		const issuer = "my-idp.com"
		parser := &mockJWTParser{}
		introspector := &mockTokenIntrospector{resultToReturn: &idptoken.DefaultIntrospectionResult{
			Active: true, DefaultClaims: jwt.DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: issuer}}}}
		next := &mockJWTAuthMiddlewareNextHandler{}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set(HeaderAuthorization, "Bearer a.b.c")
		resp := httptest.NewRecorder()

		JWTAuthMiddleware(errDomain, parser, WithJWTAuthMiddlewareTokenIntrospector(introspector))(next).ServeHTTP(resp, req)

		require.Equal(t, http.StatusOK, resp.Code)
		require.Equal(t, 1, introspector.introspectCalled)
		require.Equal(t, 0, parser.parseCalled)
		require.Equal(t, 1, next.called)
		require.NotNil(t, next.jwtClaims)
		nextIssuer, err := next.jwtClaims.GetIssuer()
		require.NoError(t, err)
		require.Equal(t, issuer, nextIssuer)
	})
}

func TestJWTAuthMiddlewareWithVerifyAccess(t *testing.T) {
	const errDomain = "TestDomain"

	t.Run("authorization failed", func(t *testing.T) {
		parser := &mockJWTParser{claimsToReturn: &jwt.DefaultClaims{}}
		next := &mockJWTAuthMiddlewareNextHandler{}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set(HeaderAuthorization, "Bearer a.b.c")
		resp := httptest.NewRecorder()

		verifyAccess := NewVerifyAccessByRolesInJWT(Role{Namespace: "my-service", Name: "admin"})
		JWTAuthMiddleware(errDomain, parser, WithJWTAuthMiddlewareVerifyAccess(verifyAccess))(next).ServeHTTP(resp, req)

		testutil.RequireErrorInRecorder(t, resp, http.StatusForbidden, errDomain, ErrCodeAuthorizationFailed)
		require.Equal(t, 1, parser.parseCalled)
		require.Equal(t, 0, next.called)
		require.Nil(t, next.jwtClaims)
	})

	t.Run("ok", func(t *testing.T) {
		scope := []jwt.AccessPolicy{{ResourceNamespace: "my-service", Role: "admin"}}
		parser := &mockJWTParser{claimsToReturn: &jwt.DefaultClaims{Scope: scope}}
		next := &mockJWTAuthMiddlewareNextHandler{}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set(HeaderAuthorization, "Bearer a.b.c")
		resp := httptest.NewRecorder()

		verifyAccess := NewVerifyAccessByRolesInJWT(Role{Namespace: "my-service", Name: "admin"})
		JWTAuthMiddleware(errDomain, parser, WithJWTAuthMiddlewareVerifyAccess(verifyAccess))(next).ServeHTTP(resp, req)

		require.Equal(t, http.StatusOK, resp.Code)
		require.Equal(t, 1, parser.parseCalled)
		require.Equal(t, 1, next.called)
		require.NotNil(t, next.jwtClaims)
		require.EqualValues(t, scope, next.jwtClaims.GetScope())
	})
}
