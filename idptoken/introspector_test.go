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
	"google.golang.org/grpc/credentials/insecure"

	"github.com/acronis/go-authkit/idptest"
	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/idptoken/pb"
	"github.com/acronis/go-authkit/internal/testing"
	"github.com/acronis/go-authkit/jwks"
	"github.com/acronis/go-authkit/jwt"
)

func TestIntrospector_IntrospectToken(t *gotesting.T) {
	httpServerIntrospector := testing.NewHTTPServerTokenIntrospectorMock()
	grpcServerIntrospector := testing.NewGRPCServerTokenIntrospectorMock()

	httpIDPSrv := idptest.NewHTTPServer(idptest.WithHTTPTokenIntrospector(httpServerIntrospector))
	require.NoError(t, httpIDPSrv.StartAndWaitForReady(time.Second))
	defer func() { _ = httpIDPSrv.Shutdown(context.Background()) }()

	grpcIDPSrv := idptest.NewGRPCServer(idptest.WithGRPCTokenIntrospector(grpcServerIntrospector))
	require.NoError(t, grpcIDPSrv.StartAndWaitForReady(time.Second))
	defer func() { grpcIDPSrv.GracefulStop() }()

	const accessToken = "access-token-with-introspection-permission"
	tokenProvider := idptest.NewSimpleTokenProvider(accessToken)

	logger := log.NewDisabledLogger()
	jwtParser := jwt.NewParser(jwks.NewClient(http.DefaultClient, logger), logger)
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
		Active: true, TokenType: idptoken.TokenTypeBearer, Claims: jwt.Claims{Scope: opaqueTokenScope}})
	grpcServerIntrospector.SetScopeForJWTID(jwtID, jwtScopeToGRPC(jwtScope))
	grpcServerIntrospector.SetResultForToken(opaqueToken, &pb.IntrospectTokenResponse{
		Active: true, TokenType: idptoken.TokenTypeBearer, Scope: jwtScopeToGRPC(opaqueTokenScope)})

	tests := []struct {
		name                    string
		introspectorOpts        idptoken.IntrospectorOpts
		useGRPC                 bool
		token                   string
		expectedResult          idptoken.IntrospectionResult
		checkError              func(t *gotesting.T, err error)
		expectedHTTPSrvCalled   bool
		expectedHTTPFormVals    url.Values
		expectedGRPCSrvCalled   bool
		expectedGRPCScopeFilter []*pb.IntrospectionScopeFilter
	}{
		{
			name:  "error, token is missing",
			token: "",
			checkError: func(t *gotesting.T, err error) {
				require.ErrorIs(t, err, idptoken.ErrTokenNotIntrospectable)
				require.ErrorContains(t, err, "token is missing")
			},
		},
		{
			name:  "error, dynamic introspection endpoint, no jwt header",
			token: "opaque-token",
			checkError: func(t *gotesting.T, err error) {
				require.ErrorIs(t, err, idptoken.ErrTokenNotIntrospectable)
				require.ErrorContains(t, err, "no JWT header found")
			},
		},
		{
			name:  "error, dynamic introspection endpoint, cannot decode jwt header",
			token: "$opaque$.$token$",
			checkError: func(t *gotesting.T, err error) {
				require.ErrorIs(t, err, idptoken.ErrTokenNotIntrospectable)
				require.ErrorContains(t, err, "decode JWT header")
			},
		},
		{
			name: "error, dynamic introspection endpoint, issuer is not trusted",
			token: idptest.MustMakeTokenStringSignedWithTestKey(jwt.Claims{
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
			token: idptest.MustMakeTokenStringSignedWithTestKey(jwt.Claims{
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
			token: idptest.MustMakeTokenStringWithHeader(jwt.Claims{
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
			token: idptest.MustMakeTokenStringWithHeader(jwt.Claims{
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
			token: idptest.MustMakeTokenStringSignedWithTestKey(jwt.Claims{
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
			token: idptest.MustMakeTokenStringSignedWithTestKey(jwt.Claims{
				RegisteredClaims: jwtgo.RegisteredClaims{
					Issuer:    jwtIssuer,
					Subject:   jwtSubject,
					ID:        jwtID,
					ExpiresAt: jwtExpiresAtInFuture,
				},
			}),
			expectedResult: idptoken.IntrospectionResult{
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
			},
			expectedHTTPSrvCalled: true,
		},
		{
			name: "ok, static introspection endpoint, introspected token is opaque",
			introspectorOpts: idptoken.IntrospectorOpts{
				StaticHTTPEndpoint: httpIDPSrv.URL() + idptest.TokenIntrospectionEndpointPath,
			},
			token: opaqueToken,
			expectedResult: idptoken.IntrospectionResult{
				Active:    true,
				TokenType: idptoken.TokenTypeBearer,
				Claims:    jwt.Claims{Scope: opaqueTokenScope},
			},
			expectedHTTPSrvCalled: true,
		},
		{
			name: "ok, static introspection endpoint, introspected token is opaque, filter scope by resource namespace",
			introspectorOpts: idptoken.IntrospectorOpts{
				StaticHTTPEndpoint: httpIDPSrv.URL() + idptest.TokenIntrospectionEndpointPath,
				ScopeFilter: []idptoken.IntrospectionScopeFilterAccessPolicy{
					{ResourceNamespace: "account-server"},
					{ResourceNamespace: "tenant-manager"},
				},
			},
			token: opaqueToken,
			expectedResult: idptoken.IntrospectionResult{
				Active:    true,
				TokenType: idptoken.TokenTypeBearer,
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
			name:    "ok, grpc introspection endpoint",
			useGRPC: true,
			introspectorOpts: idptoken.IntrospectorOpts{
				ScopeFilter: []idptoken.IntrospectionScopeFilterAccessPolicy{
					{ResourceNamespace: "account-server"},
					{ResourceNamespace: "tenant-manager"},
				},
			},
			token: opaqueToken,
			expectedResult: idptoken.IntrospectionResult{
				Active:    true,
				TokenType: idptoken.TokenTypeBearer,
				Claims:    jwt.Claims{Scope: opaqueTokenScope},
			},
			expectedGRPCSrvCalled: true,
			expectedGRPCScopeFilter: []*pb.IntrospectionScopeFilter{
				{ResourceNamespace: "account-server"},
				{ResourceNamespace: "tenant-manager"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *gotesting.T) {
			if tt.useGRPC {
				grpcClient, err := idptoken.NewGRPCClient(grpcIDPSrv.Addr(), insecure.NewCredentials())
				require.NoError(t, err)
				defer func() { require.NoError(t, grpcClient.Close()) }()
				tt.introspectorOpts.GRPCClient = grpcClient
			}
			introspector := idptoken.NewIntrospectorWithOpts(tokenProvider, tt.introspectorOpts)
			require.NoError(t, introspector.AddTrustedIssuerURL(httpIDPSrv.URL()))

			httpServerIntrospector.ResetCallsInfo()
			grpcServerIntrospector.ResetCallsInfo()

			result, err := introspector.IntrospectToken(context.Background(), tt.token)
			if tt.checkError != nil {
				tt.checkError(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedResult, result)
			}

			require.Equal(t, tt.expectedHTTPSrvCalled, httpServerIntrospector.Called)
			if tt.expectedHTTPSrvCalled {
				require.Equal(t, tt.token, httpServerIntrospector.LastIntrospectedToken)
				require.Equal(t, "Bearer "+accessToken, httpServerIntrospector.LastAuthorizationHeader)
				if tt.expectedHTTPFormVals == nil {
					tt.expectedHTTPFormVals = url.Values{"token": {tt.token}}
				}
				require.Equal(t, tt.expectedHTTPFormVals, httpServerIntrospector.LastFormValues)
			}

			require.Equal(t, tt.expectedGRPCSrvCalled, grpcServerIntrospector.Called)
			if tt.expectedGRPCSrvCalled {
				require.Equal(t, tt.token, grpcServerIntrospector.LastRequest.Token)
				require.Equal(t, tt.expectedGRPCScopeFilter, grpcServerIntrospector.LastRequest.GetScopeFilter())
				require.Equal(t, "Bearer "+accessToken, grpcServerIntrospector.LastAuthorizationMeta)
			}
		})
	}
}
