/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptoken_test

import (
	"context"
	"net/url"
	gotesting "testing"
	"time"

	"github.com/acronis/go-appkit/log"
	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/acronis/go-authkit/idptest"
	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/idptoken/pb"
	"github.com/acronis/go-authkit/internal/idputil"
	"github.com/acronis/go-authkit/internal/testing"
	"github.com/acronis/go-authkit/jwks"
	"github.com/acronis/go-authkit/jwt"
)

func TestIntrospector_IntrospectToken(t *gotesting.T) {
	const validAccessToken = "access-token-with-introspection-permission"

	httpServerIntrospector := testing.NewHTTPServerTokenIntrospectorMock()
	httpServerIntrospector.SetAccessTokenForIntrospection(validAccessToken)

	grpcServerIntrospector := testing.NewGRPCServerTokenIntrospectorMock()
	grpcServerIntrospector.SetAccessTokenForIntrospection(validAccessToken)

	httpIDPSrv := idptest.NewHTTPServer(idptest.WithHTTPTokenIntrospector(httpServerIntrospector))
	require.NoError(t, httpIDPSrv.StartAndWaitForReady(time.Second))
	defer func() { _ = httpIDPSrv.Shutdown(context.Background()) }()

	grpcIDPSrv := idptest.NewGRPCServer(idptest.WithGRPCTokenIntrospector(grpcServerIntrospector))
	require.NoError(t, grpcIDPSrv.StartAndWaitForReady(time.Second))
	defer func() { grpcIDPSrv.GracefulStop() }()

	grpcClient, err := idptoken.NewGRPCClient(grpcIDPSrv.Addr(), insecure.NewCredentials())
	require.NoError(t, err)
	defer func() { require.NoError(t, grpcClient.Close()) }()

	jwtParser := jwt.NewParser(jwks.NewClient(), log.NewDisabledLogger())
	require.NoError(t, jwtParser.AddTrustedIssuerURL(httpIDPSrv.URL()))
	httpServerIntrospector.JWTParser = jwtParser
	grpcServerIntrospector.JWTParser = jwtParser

	jwtScopeToGRPC := func(jwtScope []jwt.AccessPolicy) []*pb.AccessTokenScope {
		grpcScope := make([]*pb.AccessTokenScope, len(jwtScope))
		for i, scope := range jwtScope {
			grpcScope[i] = &pb.AccessTokenScope{
				TenantUuid:        scope.TenantUUID,
				ResourceNamespace: scope.ResourceNamespace,
				RoleName:          scope.Role,
				ResourcePath:      scope.ResourcePath,
			}
		}
		return grpcScope
	}

	jwtExpiresAtInFuture := jwtgo.NewNumericDate(time.Now().Add(time.Hour))
	jwtIssuer := httpIDPSrv.URL()
	jwtSubject := uuid.NewString()
	jwtID := uuid.NewString()
	jwtScope := []jwt.AccessPolicy{{
		TenantUUID:        uuid.NewString(),
		ResourceNamespace: "account-server",
		Role:              "account_viewer",
		ResourcePath:      "resource-" + uuid.NewString(),
	}}

	opaqueToken := "opaque-token-" + uuid.NewString()
	opaqueTokenScope := []jwt.AccessPolicy{{
		TenantUUID:        uuid.NewString(),
		ResourceNamespace: "account-server",
		Role:              "admin",
		ResourcePath:      "resource-" + uuid.NewString(),
	}}

	httpServerIntrospector.SetScopeForJWTID(jwtID, jwtScope)
	httpServerIntrospector.SetResultForToken(opaqueToken, idptoken.IntrospectionResult{
		Active: true, TokenType: idputil.TokenTypeBearer, Claims: jwt.Claims{Scope: opaqueTokenScope}})
	grpcServerIntrospector.SetScopeForJWTID(jwtID, jwtScopeToGRPC(jwtScope))
	grpcServerIntrospector.SetResultForToken(opaqueToken, &pb.IntrospectTokenResponse{
		Active: true, TokenType: idputil.TokenTypeBearer, Scope: jwtScopeToGRPC(opaqueTokenScope)})

	tests := []struct {
		name                    string
		introspectorOpts        idptoken.IntrospectorOpts
		tokenToIntrospect       string
		accessToken             string
		expectedResult          idptoken.IntrospectionResult
		checkError              func(t *gotesting.T, err error)
		expectedHTTPSrvCalled   bool
		expectedHTTPFormVals    url.Values
		expectedGRPCSrvCalled   bool
		expectedGRPCScopeFilter []*pb.IntrospectionScopeFilter
	}{
		{
			name:              "error, token is missing",
			tokenToIntrospect: "",
			checkError: func(t *gotesting.T, err error) {
				require.ErrorIs(t, err, idptoken.ErrTokenNotIntrospectable)
				require.ErrorContains(t, err, "token is missing")
			},
		},
		{
			name:              "error, dynamic introspection endpoint, no jwt header",
			tokenToIntrospect: "opaque-token",
			checkError: func(t *gotesting.T, err error) {
				require.ErrorIs(t, err, idptoken.ErrTokenNotIntrospectable)
				require.ErrorContains(t, err, "no JWT header found")
			},
		},
		{
			name:              "error, dynamic introspection endpoint, cannot decode jwt header",
			tokenToIntrospect: "$opaque$.$token$",
			checkError: func(t *gotesting.T, err error) {
				require.ErrorIs(t, err, idptoken.ErrTokenNotIntrospectable)
				require.ErrorContains(t, err, "decode JWT header")
			},
		},
		{
			name: "error, dynamic introspection endpoint, issuer is not trusted",
			tokenToIntrospect: idptest.MustMakeTokenStringSignedWithTestKey(jwt.Claims{
				RegisteredClaims: jwtgo.RegisteredClaims{
					Issuer:    "https://untrusted-issuer.com",
					Subject:   uuid.NewString(),
					ID:        uuid.NewString(),
					ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Hour)),
				},
			}),
			checkError: func(t *gotesting.T, err error) {
				require.ErrorIs(t, err, idptoken.ErrTokenNotIntrospectable)
				require.ErrorContains(t, err, `issuer "https://untrusted-issuer.com" is not trusted`)
			},
		},
		{
			name: "error, dynamic introspection endpoint, issuer is missing in JWT header and payload",
			tokenToIntrospect: idptest.MustMakeTokenStringSignedWithTestKey(jwt.Claims{
				RegisteredClaims: jwtgo.RegisteredClaims{
					Subject:   uuid.NewString(),
					ID:        uuid.NewString(),
					ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Hour)),
				},
			}),
			checkError: func(t *gotesting.T, err error) {
				require.ErrorIs(t, err, idptoken.ErrTokenNotIntrospectable)
				require.ErrorContains(t, err, "no issuer found in JWT")
			},
		},
		{
			name: "error, dynamic introspection endpoint, nri is 1",
			tokenToIntrospect: idptest.MustMakeTokenStringWithHeader(jwt.Claims{
				RegisteredClaims: jwtgo.RegisteredClaims{
					Subject:   uuid.NewString(),
					ID:        uuid.NewString(),
					ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Hour)),
				},
			}, idptest.TestKeyID, idptest.GetTestRSAPrivateKey(), map[string]interface{}{"nri": 1}),
			checkError: func(t *gotesting.T, err error) {
				require.ErrorIs(t, err, idptoken.ErrTokenIntrospectionNotNeeded)
			},
		},
		{
			name: "error, dynamic introspection endpoint, nri is true",
			tokenToIntrospect: idptest.MustMakeTokenStringWithHeader(jwt.Claims{
				RegisteredClaims: jwtgo.RegisteredClaims{
					Subject:   uuid.NewString(),
					ID:        uuid.NewString(),
					ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Hour)),
				},
			}, idptest.TestKeyID, idptest.GetTestRSAPrivateKey(), map[string]interface{}{"nri": true}),
			checkError: func(t *gotesting.T, err error) {
				require.ErrorIs(t, err, idptoken.ErrTokenIntrospectionNotNeeded)
			},
		},
		{
			name: "ok, dynamic introspection endpoint, introspected token is expired JWT",
			tokenToIntrospect: idptest.MustMakeTokenStringSignedWithTestKey(jwt.Claims{
				RegisteredClaims: jwtgo.RegisteredClaims{
					Issuer:    httpIDPSrv.URL(),
					Subject:   uuid.NewString(),
					ID:        uuid.NewString(),
					ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(-time.Hour)),
				},
			}),
			expectedResult:        idptoken.IntrospectionResult{Active: false},
			expectedHTTPSrvCalled: true,
		},
		{
			name: "ok, dynamic introspection endpoint, introspected token is JWT",
			tokenToIntrospect: idptest.MustMakeTokenStringSignedWithTestKey(jwt.Claims{
				RegisteredClaims: jwtgo.RegisteredClaims{
					Issuer:    jwtIssuer,
					Subject:   jwtSubject,
					ID:        jwtID,
					ExpiresAt: jwtExpiresAtInFuture,
				},
			}),
			expectedResult: idptoken.IntrospectionResult{
				Active:    true,
				TokenType: idputil.TokenTypeBearer,
				Claims: jwt.Claims{
					RegisteredClaims: jwtgo.RegisteredClaims{
						Issuer:    jwtIssuer,
						Subject:   jwtSubject,
						ID:        jwtID,
						ExpiresAt: jwtExpiresAtInFuture,
					},
					Scope: jwtScope,
				},
			},
			expectedHTTPSrvCalled: true,
		},
		{
			name: "ok, static http introspection endpoint, introspected token is opaque",
			introspectorOpts: idptoken.IntrospectorOpts{
				HTTPEndpoint: httpIDPSrv.URL() + idptest.TokenIntrospectionEndpointPath,
			},
			tokenToIntrospect: opaqueToken,
			expectedResult: idptoken.IntrospectionResult{
				Active:    true,
				TokenType: idputil.TokenTypeBearer,
				Claims:    jwt.Claims{Scope: opaqueTokenScope},
			},
			expectedHTTPSrvCalled: true,
		},
		{
			name: "ok, static http introspection endpoint, introspected token is opaque, filter scope by resource namespace",
			introspectorOpts: idptoken.IntrospectorOpts{
				HTTPEndpoint: httpIDPSrv.URL() + idptest.TokenIntrospectionEndpointPath,
				ScopeFilter: []idptoken.IntrospectionScopeFilterAccessPolicy{
					{ResourceNamespace: "account-server"},
					{ResourceNamespace: "tenant-manager"},
				},
			},
			tokenToIntrospect: opaqueToken,
			expectedResult: idptoken.IntrospectionResult{
				Active:    true,
				TokenType: idputil.TokenTypeBearer,
				Claims:    jwt.Claims{Scope: opaqueTokenScope},
			},
			expectedHTTPSrvCalled: true,
			expectedHTTPFormVals: url.Values{
				"token":              {opaqueToken},
				"scope_filter[0].rn": {"account-server"},
				"scope_filter[1].rn": {"tenant-manager"},
			},
		},
		{
			name: "error, grpc introspection endpoint, unauthenticated",
			introspectorOpts: idptoken.IntrospectorOpts{
				HTTPEndpoint: httpIDPSrv.URL() + idptest.TokenIntrospectionEndpointPath,
			},
			tokenToIntrospect: opaqueToken,
			accessToken:       "invalid-access-token",
			checkError: func(t *gotesting.T, err error) {
				require.ErrorIs(t, err, idptoken.ErrUnauthenticated)
			},
			expectedHTTPSrvCalled: true,
		},
		{
			name: "ok, grpc introspection endpoint",
			introspectorOpts: idptoken.IntrospectorOpts{
				GRPCClient: grpcClient,
				ScopeFilter: []idptoken.IntrospectionScopeFilterAccessPolicy{
					{ResourceNamespace: "account-server"},
					{ResourceNamespace: "tenant-manager"},
				},
			},
			tokenToIntrospect: opaqueToken,
			expectedResult: idptoken.IntrospectionResult{
				Active:    true,
				TokenType: idputil.TokenTypeBearer,
				Claims:    jwt.Claims{Scope: opaqueTokenScope},
			},
			expectedGRPCSrvCalled: true,
			expectedGRPCScopeFilter: []*pb.IntrospectionScopeFilter{
				{ResourceNamespace: "account-server"},
				{ResourceNamespace: "tenant-manager"},
			},
		},
		{
			name: "error, grpc introspection endpoint, unauthenticated",
			introspectorOpts: idptoken.IntrospectorOpts{
				GRPCClient: grpcClient,
			},
			tokenToIntrospect: opaqueToken,
			accessToken:       "invalid-access-token",
			checkError: func(t *gotesting.T, err error) {
				require.ErrorIs(t, err, idptoken.ErrUnauthenticated)
			},
			expectedGRPCSrvCalled: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *gotesting.T) {
			if tt.accessToken == "" {
				tt.accessToken = validAccessToken
			}
			introspector, err := idptoken.NewIntrospectorWithOpts(
				idptest.NewSimpleTokenProvider(tt.accessToken), tt.introspectorOpts)
			require.NoError(t, err)
			require.NoError(t, introspector.AddTrustedIssuerURL(httpIDPSrv.URL()))

			httpServerIntrospector.ResetCallsInfo()
			grpcServerIntrospector.ResetCallsInfo()

			result, err := introspector.IntrospectToken(context.Background(), tt.tokenToIntrospect)
			if tt.checkError != nil {
				tt.checkError(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedResult, result)
			}

			require.Equal(t, tt.expectedHTTPSrvCalled, httpServerIntrospector.Called)
			if tt.expectedHTTPSrvCalled {
				require.Equal(t, tt.tokenToIntrospect, httpServerIntrospector.LastIntrospectedToken)
				require.Equal(t, "Bearer "+tt.accessToken, httpServerIntrospector.LastAuthorizationHeader)
				if tt.expectedHTTPFormVals == nil {
					tt.expectedHTTPFormVals = url.Values{"token": {tt.tokenToIntrospect}}
				}
				require.Equal(t, tt.expectedHTTPFormVals, httpServerIntrospector.LastFormValues)
			}

			require.Equal(t, tt.expectedGRPCSrvCalled, grpcServerIntrospector.Called)
			if tt.expectedGRPCSrvCalled {
				require.Equal(t, tt.tokenToIntrospect, grpcServerIntrospector.LastRequest.Token)
				require.Equal(t, tt.expectedGRPCScopeFilter, grpcServerIntrospector.LastRequest.GetScopeFilter())
				require.Equal(t, "Bearer "+tt.accessToken, grpcServerIntrospector.LastAuthorizationMeta)
			}
		})
	}
}

func TestCachingIntrospector_IntrospectTokenWithCache(t *gotesting.T) {
	const accessToken = "access-token-with-introspection-permission"

	serverIntrospector := testing.NewHTTPServerTokenIntrospectorMock()
	serverIntrospector.SetAccessTokenForIntrospection(accessToken)

	idpSrv := idptest.NewHTTPServer(idptest.WithHTTPTokenIntrospector(serverIntrospector))
	require.NoError(t, idpSrv.StartAndWaitForReady(time.Second))
	defer func() { _ = idpSrv.Shutdown(context.Background()) }()

	logger := log.NewDisabledLogger()
	jwtParser := jwt.NewParser(jwks.NewClient(), logger)
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
		Active: true, TokenType: idputil.TokenTypeBearer, Claims: jwt.Claims{Scope: opaqueToken1Scope}})
	serverIntrospector.SetResultForToken(opaqueToken2, idptoken.IntrospectionResult{
		Active: true, TokenType: idputil.TokenTypeBearer, Claims: jwt.Claims{Scope: opaqueToken2Scope}})
	serverIntrospector.SetResultForToken(opaqueToken3, idptoken.IntrospectionResult{Active: false})

	tests := []struct {
		name              string
		introspectorOpts  idptoken.IntrospectorOpts
		tokens            []string
		expectedSrvCalled []bool
		expectedResult    []idptoken.IntrospectionResult
		checkError        []func(t *gotesting.T, err error)
		checkIntrospector func(t *gotesting.T, introspector *idptoken.Introspector)
		delay             time.Duration
	}{
		{
			name:              "error, token is not introspectable",
			tokens:            []string{"", "opaque-token"},
			expectedSrvCalled: []bool{false, false},
			introspectorOpts: idptoken.IntrospectorOpts{
				ClaimsCache:   idptoken.IntrospectorCacheOpts{Enabled: true},
				NegativeCache: idptoken.IntrospectorCacheOpts{Enabled: true},
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
			checkIntrospector: func(t *gotesting.T, introspector *idptoken.Introspector) {
				require.Equal(t, 0, introspector.ClaimsCache.Len(context.Background()))
				require.Equal(t, 0, introspector.NegativeCache.Len(context.Background()))
			},
		},
		{
			name: "ok, dynamic introspection endpoint, introspected token is expired JWT",
			introspectorOpts: idptoken.IntrospectorOpts{
				ClaimsCache:   idptoken.IntrospectorCacheOpts{Enabled: true},
				NegativeCache: idptoken.IntrospectorCacheOpts{Enabled: true},
			},
			tokens:            repeat(expiredJWT, 2),
			expectedSrvCalled: []bool{true, false},
			expectedResult:    []idptoken.IntrospectionResult{{Active: false}, {Active: false}},
			checkIntrospector: func(t *gotesting.T, introspector *idptoken.Introspector) {
				require.Equal(t, 0, introspector.ClaimsCache.Len(context.Background()))
				require.Equal(t, 1, introspector.NegativeCache.Len(context.Background()))
			},
		},
		{
			name: "ok, dynamic introspection endpoint, introspected token is JWT",
			introspectorOpts: idptoken.IntrospectorOpts{
				ClaimsCache:   idptoken.IntrospectorCacheOpts{Enabled: true},
				NegativeCache: idptoken.IntrospectorCacheOpts{Enabled: true},
			},
			tokens:            repeat(activeJWT, 2),
			expectedSrvCalled: []bool{true, false},
			expectedResult: repeat(idptoken.IntrospectionResult{
				Active:    true,
				TokenType: idputil.TokenTypeBearer,
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
			checkIntrospector: func(t *gotesting.T, introspector *idptoken.Introspector) {
				require.Equal(t, 1, introspector.ClaimsCache.Len(context.Background()))
				require.Equal(t, 0, introspector.NegativeCache.Len(context.Background()))
			},
		},
		{
			name: "ok, static introspection endpoint, introspected token is opaque",
			introspectorOpts: idptoken.IntrospectorOpts{
				HTTPEndpoint:  idpSrv.URL() + idptest.TokenIntrospectionEndpointPath,
				ClaimsCache:   idptoken.IntrospectorCacheOpts{Enabled: true},
				NegativeCache: idptoken.IntrospectorCacheOpts{Enabled: true},
			},
			tokens:            []string{opaqueToken1, opaqueToken1, opaqueToken2, opaqueToken2, opaqueToken3, opaqueToken3},
			expectedSrvCalled: []bool{true, false, true, false, true, false},
			expectedResult: []idptoken.IntrospectionResult{
				{Active: true, TokenType: idputil.TokenTypeBearer, Claims: jwt.Claims{Scope: opaqueToken1Scope}},
				{Active: true, TokenType: idputil.TokenTypeBearer, Claims: jwt.Claims{Scope: opaqueToken1Scope}},
				{Active: true, TokenType: idputil.TokenTypeBearer, Claims: jwt.Claims{Scope: opaqueToken2Scope}},
				{Active: true, TokenType: idputil.TokenTypeBearer, Claims: jwt.Claims{Scope: opaqueToken2Scope}},
				{Active: false},
				{Active: false},
			},
			checkIntrospector: func(t *gotesting.T, introspector *idptoken.Introspector) {
				require.Equal(t, 2, introspector.ClaimsCache.Len(context.Background()))
				require.Equal(t, 1, introspector.NegativeCache.Len(context.Background()))
			},
		},
		{
			name: "ok, cache has ttl",
			introspectorOpts: idptoken.IntrospectorOpts{
				HTTPEndpoint:  idpSrv.URL() + idptest.TokenIntrospectionEndpointPath,
				ClaimsCache:   idptoken.IntrospectorCacheOpts{Enabled: true, TTL: 100 * time.Millisecond},
				NegativeCache: idptoken.IntrospectorCacheOpts{Enabled: true, TTL: 100 * time.Millisecond},
			},
			tokens:            []string{opaqueToken1, opaqueToken1, opaqueToken3, opaqueToken3},
			expectedSrvCalled: []bool{true, true, true, true},
			expectedResult: []idptoken.IntrospectionResult{
				{Active: true, TokenType: idputil.TokenTypeBearer, Claims: jwt.Claims{Scope: opaqueToken1Scope}},
				{Active: true, TokenType: idputil.TokenTypeBearer, Claims: jwt.Claims{Scope: opaqueToken1Scope}},
				{Active: false},
				{Active: false},
			},
			checkIntrospector: func(t *gotesting.T, introspector *idptoken.Introspector) {
				require.Equal(t, 1, introspector.ClaimsCache.Len(context.Background()))
				require.Equal(t, 1, introspector.NegativeCache.Len(context.Background()))
			},
			delay: 200 * time.Millisecond,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *gotesting.T) {
			introspector, err := idptoken.NewIntrospectorWithOpts(
				idptest.NewSimpleTokenProvider(accessToken), tt.introspectorOpts)
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
