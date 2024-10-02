/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptoken_test

import (
	"context"
	"net/http"
	"net/url"
	gotesting "testing"
	"time"

	"github.com/acronis/go-appkit/log"
	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/acronis/go-authkit/idptest"
	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/internal/testing"
	"github.com/acronis/go-authkit/jwks"
	"github.com/acronis/go-authkit/jwt"
)

func TestCachingIntrospector_IntrospectToken(t *gotesting.T) {
	serverIntrospector := testing.NewHTTPServerTokenIntrospectorMock()

	idpSrv := idptest.NewHTTPServer(idptest.WithHTTPTokenIntrospector(serverIntrospector))
	require.NoError(t, idpSrv.StartAndWaitForReady(time.Second))
	defer func() { _ = idpSrv.Shutdown(context.Background()) }()

	const accessToken = "access-token-with-introspection-permission"
	tokenProvider := idptest.NewSimpleTokenProvider(accessToken)

	logger := log.NewDisabledLogger()
	jwtParser := jwt.NewParser(jwks.NewClient(http.DefaultClient, logger), logger)
	require.NoError(t, jwtParser.AddTrustedIssuerURL(idpSrv.URL()))
	serverIntrospector.JWTParser = jwtParser

	jwtExpiresAtInFuture := jwtgo.NewNumericDate(time.Now().Add(time.Hour))
	jwtIssuer := idpSrv.URL()
	jwtSubject := uuid.NewString()
	jwtID := uuid.NewString()
	jwtScope := []jwt.AccessPolicy{{
		TenantUUID:        uuid.NewString(),
		ResourceNamespace: "account-server",
		Role:              "account_viewer",
		ResourcePath:      "resource-" + uuid.NewString(),
	}}

	expiredJWT := idptest.MustMakeTokenStringSignedWithTestKey(jwt.Claims{
		RegisteredClaims: jwtgo.RegisteredClaims{
			Issuer:    idpSrv.URL(),
			Subject:   uuid.NewString(),
			ID:        uuid.NewString(),
			ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(-time.Hour)),
		},
	})
	activeJWT := idptest.MustMakeTokenStringSignedWithTestKey(jwt.Claims{
		RegisteredClaims: jwtgo.RegisteredClaims{
			Issuer:    jwtIssuer,
			Subject:   jwtSubject,
			ID:        jwtID,
			ExpiresAt: jwtExpiresAtInFuture,
		},
	})

	opaqueToken1 := "opaque-token-" + uuid.NewString()
	opaqueToken2 := "opaque-token-" + uuid.NewString()
	opaqueToken3 := "opaque-token-" + uuid.NewString()
	opaqueToken1Scope := []jwt.AccessPolicy{{
		TenantUUID:        uuid.NewString(),
		ResourceNamespace: "account-server",
		Role:              "admin",
		ResourcePath:      "resource-" + uuid.NewString(),
	}}
	opaqueToken2Scope := []jwt.AccessPolicy{{
		TenantUUID:        uuid.NewString(),
		ResourceNamespace: "event-manager",
		Role:              "admin",
		ResourcePath:      "resource-" + uuid.NewString(),
	}}

	serverIntrospector.SetScopeForJWTID(jwtID, jwtScope)
	serverIntrospector.SetResultForToken(opaqueToken1, idptoken.IntrospectionResult{
		Active: true, TokenType: idptoken.TokenTypeBearer, Claims: jwt.Claims{Scope: opaqueToken1Scope}})
	serverIntrospector.SetResultForToken(opaqueToken2, idptoken.IntrospectionResult{
		Active: true, TokenType: idptoken.TokenTypeBearer, Claims: jwt.Claims{Scope: opaqueToken2Scope}})
	serverIntrospector.SetResultForToken(opaqueToken3, idptoken.IntrospectionResult{Active: false})

	tests := []struct {
		name              string
		introspectorOpts  idptoken.CachingIntrospectorOpts
		tokens            []string
		expectedSrvCalled []bool
		expectedResult    []idptoken.IntrospectionResult
		checkError        []func(t *gotesting.T, err error)
		checkIntrospector func(t *gotesting.T, introspector *idptoken.CachingIntrospector)
		delay             time.Duration
	}{
		{
			name:              "error, token is not introspectable",
			tokens:            []string{"", "opaque-token"},
			expectedSrvCalled: []bool{false, false},
			introspectorOpts: idptoken.CachingIntrospectorOpts{
				ClaimsCache:   idptoken.CachingIntrospectorCacheOpts{Enabled: true},
				NegativeCache: idptoken.CachingIntrospectorCacheOpts{Enabled: true},
			},
			checkError: []func(t *gotesting.T, err error){
				func(t *gotesting.T, err error) {
					require.ErrorIs(t, err, idptoken.ErrTokenNotIntrospectable)
					require.ErrorContains(t, err, "token is missing")
				},
				func(t *gotesting.T, err error) {
					require.ErrorIs(t, err, idptoken.ErrTokenNotIntrospectable)
					require.ErrorContains(t, err, "no JWT header found")
				},
			},
			checkIntrospector: func(t *gotesting.T, introspector *idptoken.CachingIntrospector) {
				require.Equal(t, 0, introspector.ClaimsCache.Len(context.Background()))
				require.Equal(t, 0, introspector.NegativeCache.Len(context.Background()))
			},
		},
		{
			name: "ok, dynamic introspection endpoint, introspected token is expired JWT",
			introspectorOpts: idptoken.CachingIntrospectorOpts{
				ClaimsCache:   idptoken.CachingIntrospectorCacheOpts{Enabled: true},
				NegativeCache: idptoken.CachingIntrospectorCacheOpts{Enabled: true},
			},
			tokens:            repeat(expiredJWT, 2),
			expectedSrvCalled: []bool{true, false},
			expectedResult:    []idptoken.IntrospectionResult{{Active: false}, {Active: false}},
			checkIntrospector: func(t *gotesting.T, introspector *idptoken.CachingIntrospector) {
				require.Equal(t, 0, introspector.ClaimsCache.Len(context.Background()))
				require.Equal(t, 1, introspector.NegativeCache.Len(context.Background()))
			},
		},
		{
			name: "ok, dynamic introspection endpoint, introspected token is JWT",
			introspectorOpts: idptoken.CachingIntrospectorOpts{
				ClaimsCache:   idptoken.CachingIntrospectorCacheOpts{Enabled: true},
				NegativeCache: idptoken.CachingIntrospectorCacheOpts{Enabled: true},
			},
			tokens:            repeat(activeJWT, 2),
			expectedSrvCalled: []bool{true, false},
			expectedResult: repeat(idptoken.IntrospectionResult{
				Active:    true,
				TokenType: idptoken.TokenTypeBearer,
				Claims: jwt.Claims{
					RegisteredClaims: jwtgo.RegisteredClaims{
						Issuer:    jwtIssuer,
						Subject:   jwtSubject,
						ID:        jwtID,
						ExpiresAt: jwtExpiresAtInFuture,
					},
					Scope: jwtScope,
				},
			}, 2),
			checkIntrospector: func(t *gotesting.T, introspector *idptoken.CachingIntrospector) {
				require.Equal(t, 1, introspector.ClaimsCache.Len(context.Background()))
				require.Equal(t, 0, introspector.NegativeCache.Len(context.Background()))
			},
		},
		{
			name: "ok, static introspection endpoint, introspected token is opaque",
			introspectorOpts: idptoken.CachingIntrospectorOpts{
				IntrospectorOpts: idptoken.IntrospectorOpts{
					StaticHTTPEndpoint: idpSrv.URL() + idptest.TokenIntrospectionEndpointPath,
				},
				ClaimsCache:   idptoken.CachingIntrospectorCacheOpts{Enabled: true},
				NegativeCache: idptoken.CachingIntrospectorCacheOpts{Enabled: true},
			},
			tokens:            []string{opaqueToken1, opaqueToken1, opaqueToken2, opaqueToken2, opaqueToken3, opaqueToken3},
			expectedSrvCalled: []bool{true, false, true, false, true, false},
			expectedResult: []idptoken.IntrospectionResult{
				{Active: true, TokenType: idptoken.TokenTypeBearer, Claims: jwt.Claims{Scope: opaqueToken1Scope}},
				{Active: true, TokenType: idptoken.TokenTypeBearer, Claims: jwt.Claims{Scope: opaqueToken1Scope}},
				{Active: true, TokenType: idptoken.TokenTypeBearer, Claims: jwt.Claims{Scope: opaqueToken2Scope}},
				{Active: true, TokenType: idptoken.TokenTypeBearer, Claims: jwt.Claims{Scope: opaqueToken2Scope}},
				{Active: false},
				{Active: false},
			},
			checkIntrospector: func(t *gotesting.T, introspector *idptoken.CachingIntrospector) {
				require.Equal(t, 2, introspector.ClaimsCache.Len(context.Background()))
				require.Equal(t, 1, introspector.NegativeCache.Len(context.Background()))
			},
		},
		{
			name: "ok, cache has ttl",
			introspectorOpts: idptoken.CachingIntrospectorOpts{
				IntrospectorOpts: idptoken.IntrospectorOpts{
					StaticHTTPEndpoint: idpSrv.URL() + idptest.TokenIntrospectionEndpointPath,
				},
				ClaimsCache:   idptoken.CachingIntrospectorCacheOpts{Enabled: true, TTL: 100 * time.Millisecond},
				NegativeCache: idptoken.CachingIntrospectorCacheOpts{Enabled: true, TTL: 100 * time.Millisecond},
			},
			tokens:            []string{opaqueToken1, opaqueToken1, opaqueToken3, opaqueToken3},
			expectedSrvCalled: []bool{true, true, true, true},
			expectedResult: []idptoken.IntrospectionResult{
				{Active: true, TokenType: idptoken.TokenTypeBearer, Claims: jwt.Claims{Scope: opaqueToken1Scope}},
				{Active: true, TokenType: idptoken.TokenTypeBearer, Claims: jwt.Claims{Scope: opaqueToken1Scope}},
				{Active: false},
				{Active: false},
			},
			checkIntrospector: func(t *gotesting.T, introspector *idptoken.CachingIntrospector) {
				require.Equal(t, 1, introspector.ClaimsCache.Len(context.Background()))
				require.Equal(t, 1, introspector.NegativeCache.Len(context.Background()))
			},
			delay: 200 * time.Millisecond,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *gotesting.T) {
			introspector, err := idptoken.NewCachingIntrospectorWithOpts(tokenProvider, tt.introspectorOpts)
			require.NoError(t, err)
			require.NoError(t, introspector.AddTrustedIssuerURL(idpSrv.URL()))

			for i, token := range tt.tokens {
				serverIntrospector.ResetCallsInfo()

				result, introspectErr := introspector.IntrospectToken(context.Background(), token)
				if i < len(tt.checkError) {
					tt.checkError[i](t, introspectErr)
				} else {
					require.NoError(t, introspectErr)
					require.Equal(t, tt.expectedResult[i], result)
				}

				require.Equal(t, tt.expectedSrvCalled[i], serverIntrospector.Called)
				if tt.expectedSrvCalled[i] {
					require.Equal(t, token, serverIntrospector.LastIntrospectedToken)
					require.Equal(t, "Bearer "+accessToken, serverIntrospector.LastAuthorizationHeader)
					require.Equal(t, url.Values{"token": {token}}, serverIntrospector.LastFormValues)
				}

				time.Sleep(tt.delay)
			}

			if tt.checkIntrospector != nil {
				tt.checkIntrospector(t, introspector)
			}
		})
	}
}

func repeat[V any](v V, n int) []V {
	s := make([]V, n)
	for i := range s {
		s[i] = v
	}
	return s
}
