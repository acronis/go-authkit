/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptoken_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	gotesting "testing"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/acronis/go-authkit/idptest"
	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/idptoken/pb"
	"github.com/acronis/go-authkit/internal/idputil"
	"github.com/acronis/go-authkit/internal/testing"
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

	// Expired JWT
	expiredJWT := idptest.MustMakeTokenStringSignedWithTestKey(&jwt.DefaultClaims{
		RegisteredClaims: jwtgo.RegisteredClaims{
			Issuer:    httpIDPSrv.URL(),
			Audience:  jwtgo.ClaimStrings{"https://rs.example.com"},
			Subject:   uuid.NewString(),
			ID:        uuid.NewString(),
			ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(-time.Hour)),
		},
	})
	httpServerIntrospector.SetResultForToken(expiredJWT, &idptoken.DefaultIntrospectionResult{Active: false}, nil)

	// Valid JWT with scope
	validJWTScope := []jwt.AccessPolicy{{
		TenantUUID:        uuid.NewString(),
		ResourceNamespace: "account-server",
		Role:              "account_viewer",
		ResourcePath:      "resource-" + uuid.NewString(),
	}}
	validJWTRegClaims := jwtgo.RegisteredClaims{
		Issuer:    httpIDPSrv.URL(),
		Audience:  jwtgo.ClaimStrings{"https://rs.example.com"},
		Subject:   uuid.NewString(),
		ID:        uuid.NewString(),
		ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Hour)),
	}
	validJWT := idptest.MustMakeTokenStringSignedWithTestKey(&jwt.DefaultClaims{RegisteredClaims: validJWTRegClaims})
	httpServerIntrospector.SetResultForToken(validJWT, &idptoken.DefaultIntrospectionResult{Active: true,
		TokenType: idputil.TokenTypeBearer, DefaultClaims: jwt.DefaultClaims{RegisteredClaims: validJWTRegClaims, Scope: validJWTScope}}, nil)
	validJWTWithAppTyp := idptest.MustMakeTokenStringWithHeader(&jwt.DefaultClaims{
		RegisteredClaims: validJWTRegClaims,
	}, idptest.TestKeyID, idptest.GetTestRSAPrivateKey(), map[string]interface{}{"typ": idputil.JWTTypeAppAccessToken})
	httpServerIntrospector.SetResultForToken(validJWTWithAppTyp, &idptoken.DefaultIntrospectionResult{Active: true,
		TokenType: idputil.TokenTypeBearer, DefaultClaims: jwt.DefaultClaims{RegisteredClaims: validJWTRegClaims, Scope: validJWTScope}}, nil)
	grpcServerIntrospector.SetResultForToken(validJWT, &pb.IntrospectTokenResponse{
		Active:    true,
		TokenType: idputil.TokenTypeBearer,
		Aud:       validJWTRegClaims.Audience,
		Exp:       validJWTRegClaims.ExpiresAt.Unix(),
		Scope:     jwtScopeToGRPC(validJWTScope),
	}, nil)

	// Valid JWT with scope and custom claims fields
	customFieldVal := uuid.NewString()
	validCustomJWTScope := jwt.Scope{{
		TenantUUID:        uuid.NewString(),
		ResourceNamespace: "account-server",
		Role:              "account_viewer",
		ResourcePath:      "resource-1",
	}, {
		TenantUUID:        uuid.NewString(),
		ResourceNamespace: "event-manager",
		Role:              "publisher",
		ResourcePath:      "resource-1",
	}}
	validCustomJWTRegClaims := jwtgo.RegisteredClaims{
		Issuer:    httpIDPSrv.URL(),
		Audience:  jwtgo.ClaimStrings{"https://rs.example.com"},
		Subject:   uuid.NewString(),
		ID:        uuid.NewString(),
		ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Hour)),
	}
	validCustomJWT := idptest.MustMakeTokenStringSignedWithTestKey(&CustomClaims{
		DefaultClaims: jwt.DefaultClaims{RegisteredClaims: validCustomJWTRegClaims}, CustomField: customFieldVal})
	httpServerIntrospector.SetResultForToken(validCustomJWT, &CustomIntrospectionResult{
		Active:    true,
		TokenType: idputil.TokenTypeBearer,
		CustomClaims: CustomClaims{
			DefaultClaims: jwt.DefaultClaims{RegisteredClaims: validCustomJWTRegClaims, Scope: validCustomJWTScope},
			CustomField:   customFieldVal,
		},
	}, nil)

	// Opaque token
	opaqueToken := "opaque-token-" + uuid.NewString()
	opaqueTokenScope := []jwt.AccessPolicy{{
		TenantUUID:        uuid.NewString(),
		ResourceNamespace: "account-server",
		Role:              "admin",
		ResourcePath:      "resource-" + uuid.NewString(),
	}}
	opaqueTokenRegClaims := jwtgo.RegisteredClaims{
		ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Hour)),
	}
	httpServerIntrospector.SetResultForToken(opaqueToken, &idptoken.DefaultIntrospectionResult{
		Active:        true,
		TokenType:     idputil.TokenTypeBearer,
		DefaultClaims: jwt.DefaultClaims{RegisteredClaims: opaqueTokenRegClaims, Scope: opaqueTokenScope},
	}, nil)
	grpcServerIntrospector.SetResultForToken(opaqueToken, &pb.IntrospectTokenResponse{
		Active:    true,
		TokenType: idputil.TokenTypeBearer,
		Aud:       opaqueTokenRegClaims.Audience,
		Exp:       opaqueTokenRegClaims.ExpiresAt.Unix(),
		Scope:     jwtScopeToGRPC(opaqueTokenScope),
	}, nil)

	// Valid tokens, but introspection fails
	grpcInternalErr := grpcstatus.Error(codes.Internal, "internal error")
	validJWTRegClaimsWithGRPCErr := validJWTRegClaims
	validJWTRegClaimsWithGRPCErr.ID = uuid.NewString()
	validJWTWithGRPCErr := idptest.MustMakeTokenStringSignedWithTestKey(&jwt.DefaultClaims{RegisteredClaims: validJWTRegClaimsWithGRPCErr})
	httpServerIntrospector.SetResultForToken(validJWTWithGRPCErr, &idptoken.DefaultIntrospectionResult{Active: true,
		TokenType: idputil.TokenTypeBearer, DefaultClaims: jwt.DefaultClaims{RegisteredClaims: validJWTRegClaimsWithGRPCErr, Scope: validJWTScope}}, nil)
	grpcServerIntrospector.SetResultForToken(validJWTWithGRPCErr, nil, grpcInternalErr)
	opaqueTokenWithPermissionErr := "opaque-token-with-permission-err"
	grpcServerIntrospector.SetResultForToken(opaqueTokenWithPermissionErr, nil, grpcstatus.Error(codes.PermissionDenied, "permission denied"))
	opaqueTokenWithInternalErr := "opaque-token-with-internal-err"
	grpcServerIntrospector.SetResultForToken(opaqueTokenWithInternalErr, nil, grpcInternalErr)
	httpServerIntrospector.SetResultForToken(opaqueTokenWithInternalErr, nil, fmt.Errorf("internal error"))

	tests := []struct {
		name                    string
		useGRPCClient           bool
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
			name: `error, dynamic introspection endpoint, invalid "typ" field in JWT header`,
			tokenToIntrospect: idptest.MustMakeTokenStringWithHeader(&jwt.DefaultClaims{
				RegisteredClaims: validJWTRegClaims,
			}, idptest.TestKeyID, idptest.GetTestRSAPrivateKey(), map[string]interface{}{"typ": "invalid"}),
			checkError: func(t *gotesting.T, err error) {
				require.ErrorIs(t, err, idptoken.ErrTokenNotIntrospectable)
				require.ErrorContains(t, err, fmt.Sprintf(
					`"typ" field is not %q or %q`, idputil.JWTTypeAccessToken, idputil.JWTTypeAppAccessToken))
			},
		},
		{
			name: "error, dynamic introspection endpoint, issuer is not trusted",
			tokenToIntrospect: idptest.MustMakeTokenStringSignedWithTestKey(&jwt.DefaultClaims{
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
			tokenToIntrospect: idptest.MustMakeTokenStringSignedWithTestKey(&jwt.DefaultClaims{
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
			tokenToIntrospect: idptest.MustMakeTokenStringWithHeader(&jwt.DefaultClaims{
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
			tokenToIntrospect: idptest.MustMakeTokenStringWithHeader(&jwt.DefaultClaims{
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
			name:                  "ok, dynamic introspection endpoint, introspected token is expired JWT",
			tokenToIntrospect:     expiredJWT,
			expectedResult:        &idptoken.DefaultIntrospectionResult{Active: false},
			expectedHTTPSrvCalled: true,
		},
		{
			name:              "ok, dynamic introspection endpoint, introspected token is JWT",
			tokenToIntrospect: validJWT,
			expectedResult: &idptoken.DefaultIntrospectionResult{
				Active:        true,
				TokenType:     idputil.TokenTypeBearer,
				DefaultClaims: jwt.DefaultClaims{RegisteredClaims: validJWTRegClaims, Scope: validJWTScope},
			},
			expectedHTTPSrvCalled: true,
		},
		{
			name:              `ok, dynamic introspection endpoint, introspected token is JWT, "typ" is "application/at+jwt"`,
			tokenToIntrospect: validJWTWithAppTyp,
			expectedResult: &idptoken.DefaultIntrospectionResult{
				Active:        true,
				TokenType:     idputil.TokenTypeBearer,
				DefaultClaims: jwt.DefaultClaims{RegisteredClaims: validJWTRegClaims, Scope: validJWTScope},
			},
			expectedHTTPSrvCalled: true,
		},
		{
			name: "ok, dynamic introspection endpoint, introspected token is JWT, custom claims, filter scope by resource namespace",
			introspectorOpts: idptoken.IntrospectorOpts{
				ResultTemplate: &CustomIntrospectionResult{CustomClaims: CustomClaims{}},
				ScopeFilter:    jwt.ScopeFilter{{ResourceNamespace: "event-manager"}},
			},
			tokenToIntrospect: validCustomJWT,
			expectedResult: &CustomIntrospectionResult{
				Active:    true,
				TokenType: idputil.TokenTypeBearer,
				CustomClaims: CustomClaims{
					DefaultClaims: jwt.DefaultClaims{RegisteredClaims: validCustomJWTRegClaims, Scope: jwt.Scope{validCustomJWTScope[1]}},
					CustomField:   customFieldVal,
				},
			},
			expectedHTTPSrvCalled: true,
			expectedHTTPFormVals: url.Values{
				"token":              {validCustomJWT},
				"scope_filter[0].rn": {"event-manager"},
			},
		},
		{
			name: "ok, static http introspection endpoint, opaque token",
			introspectorOpts: idptoken.IntrospectorOpts{
				HTTPEndpoint: httpIDPSrv.URL() + idptest.TokenIntrospectionEndpointPath,
			},
			tokenToIntrospect: opaqueToken,
			expectedResult: &idptoken.DefaultIntrospectionResult{
				Active:    true,
				TokenType: idputil.TokenTypeBearer,
				DefaultClaims: jwt.DefaultClaims{
					RegisteredClaims: jwtgo.RegisteredClaims{ExpiresAt: opaqueTokenRegClaims.ExpiresAt},
					Scope:            opaqueTokenScope,
				},
			},
			expectedHTTPSrvCalled: true,
		},
		{
			name: "ok, static http introspection endpoint, opaque token, filter scope by resource namespace",
			introspectorOpts: idptoken.IntrospectorOpts{
				HTTPEndpoint: httpIDPSrv.URL() + idptest.TokenIntrospectionEndpointPath,
				ScopeFilter: jwt.ScopeFilter{
					{ResourceNamespace: "account-server"},
					{ResourceNamespace: "tenant-manager"},
				},
			},
			tokenToIntrospect: opaqueToken,
			expectedResult: &idptoken.DefaultIntrospectionResult{
				Active:    true,
				TokenType: idputil.TokenTypeBearer,
				DefaultClaims: jwt.DefaultClaims{
					RegisteredClaims: jwtgo.RegisteredClaims{ExpiresAt: opaqueTokenRegClaims.ExpiresAt},
					Scope:            opaqueTokenScope,
				},
			},
			expectedHTTPSrvCalled: true,
			expectedHTTPFormVals: url.Values{
				"token":              {opaqueToken},
				"scope_filter[0].rn": {"account-server"},
				"scope_filter[1].rn": {"tenant-manager"},
			},
		},
		{
			name: "error, static http introspection endpoint, opaque token, unauthenticated",
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
			name: "error, static http introspection endpoint, opaque token, audience is missing",
			introspectorOpts: idptoken.IntrospectorOpts{
				HTTPEndpoint:     httpIDPSrv.URL() + idptest.TokenIntrospectionEndpointPath,
				RequireAudience:  true,
				ExpectedAudience: []string{"https://rs.my-service.com"},
			},
			tokenToIntrospect: opaqueToken,
			checkError: func(t *gotesting.T, err error) {
				require.ErrorIs(t, err, idptoken.ErrTokenIntrospectionInvalidClaims)
				require.ErrorIs(t, err, jwtgo.ErrTokenRequiredClaimMissing)
				var audMissingErr *jwt.AudienceMissingError
				require.ErrorAs(t, err, &audMissingErr)
			},
			expectedHTTPSrvCalled: true,
		},
		{
			name: "error, static http introspection endpoint, jwt token, invalid audience",
			introspectorOpts: idptoken.IntrospectorOpts{
				HTTPEndpoint:     httpIDPSrv.URL() + idptest.TokenIntrospectionEndpointPath,
				RequireAudience:  true,
				ExpectedAudience: []string{"https://rs.my-service.com"},
			},
			tokenToIntrospect: validJWT,
			checkError: func(t *gotesting.T, err error) {
				require.ErrorIs(t, err, idptoken.ErrTokenIntrospectionInvalidClaims)
				require.ErrorIs(t, err, jwtgo.ErrTokenInvalidAudience)
			},
			expectedHTTPSrvCalled: true,
		},
		{
			name:          "ok, grpc introspection endpoint, opaque token",
			useGRPCClient: true,
			introspectorOpts: idptoken.IntrospectorOpts{
				ScopeFilter: jwt.ScopeFilter{
					{ResourceNamespace: "account-server"},
					{ResourceNamespace: "tenant-manager"},
				},
			},
			tokenToIntrospect: opaqueToken,
			expectedResult: &idptoken.DefaultIntrospectionResult{
				Active:    true,
				TokenType: idputil.TokenTypeBearer,
				DefaultClaims: jwt.DefaultClaims{
					RegisteredClaims: jwtgo.RegisteredClaims{ExpiresAt: opaqueTokenRegClaims.ExpiresAt},
					Scope:            opaqueTokenScope,
				},
			},
			expectedGRPCSrvCalled: true,
			expectedGRPCScopeFilter: []*pb.IntrospectionScopeFilter{
				{ResourceNamespace: "account-server"},
				{ResourceNamespace: "tenant-manager"},
			},
		},
		{
			name:              "error, grpc introspection endpoint, opaque token, unauthenticated",
			useGRPCClient:     true,
			introspectorOpts:  idptoken.IntrospectorOpts{},
			tokenToIntrospect: opaqueToken,
			accessToken:       "invalid-access-token",
			checkError: func(t *gotesting.T, err error) {
				require.ErrorIs(t, err, idptoken.ErrUnauthenticated)
			},
			expectedGRPCSrvCalled: true,
		},
		{
			name:          "error, grpc introspection endpoint, jwt token, invalid audience",
			useGRPCClient: true,
			introspectorOpts: idptoken.IntrospectorOpts{
				RequireAudience:  true,
				ExpectedAudience: []string{"https://rs.my-service.com"},
			},
			tokenToIntrospect: validJWT,
			checkError: func(t *gotesting.T, err error) {
				require.ErrorIs(t, err, idptoken.ErrTokenIntrospectionInvalidClaims)
				require.ErrorIs(t, err, jwtgo.ErrTokenInvalidAudience)
			},
			expectedGRPCSrvCalled: true,
		},
		{
			name:          "error, grpc introspection endpoint, opaque token, audience is missing",
			useGRPCClient: true,
			introspectorOpts: idptoken.IntrospectorOpts{
				RequireAudience:  true,
				ExpectedAudience: []string{"https://rs.my-service.com"},
			},
			tokenToIntrospect: opaqueToken,
			checkError: func(t *gotesting.T, err error) {
				require.ErrorIs(t, err, idptoken.ErrTokenIntrospectionInvalidClaims)
				require.ErrorIs(t, err, jwtgo.ErrTokenRequiredClaimMissing)
				var audMissingErr *jwt.AudienceMissingError
				require.ErrorAs(t, err, &audMissingErr)
			},
			expectedGRPCSrvCalled: true,
		},
		{
			name:          "ok, grpc introspection is failed, internal error, http introspection fallback is successful",
			useGRPCClient: true,
			introspectorOpts: idptoken.IntrospectorOpts{
				HTTPEndpoint: httpIDPSrv.URL() + idptest.TokenIntrospectionEndpointPath,
			},
			tokenToIntrospect: validJWTWithGRPCErr,
			expectedResult: &idptoken.DefaultIntrospectionResult{
				Active:        true,
				TokenType:     idputil.TokenTypeBearer,
				DefaultClaims: jwt.DefaultClaims{RegisteredClaims: validJWTRegClaimsWithGRPCErr, Scope: validJWTScope},
			},
			expectedGRPCSrvCalled: true,
			expectedHTTPSrvCalled: true,
			expectedHTTPFormVals:  url.Values{"token": {validJWTWithGRPCErr}},
		},
		{
			name:          "error, grpc introspection is failed, permission denied, http introspection fallback is not called",
			useGRPCClient: true,
			introspectorOpts: idptoken.IntrospectorOpts{
				HTTPEndpoint: httpIDPSrv.URL() + idptest.TokenIntrospectionEndpointPath,
			},
			tokenToIntrospect: opaqueTokenWithPermissionErr,
			checkError: func(t *gotesting.T, err error) {
				require.ErrorIs(t, err, idptoken.ErrPermissionDenied)
			},
			expectedGRPCSrvCalled: true,
			expectedHTTPSrvCalled: false,
		},
		{
			name:          "error, both grpc introspection and http introspection fallback are failed",
			useGRPCClient: true,
			introspectorOpts: idptoken.IntrospectorOpts{
				HTTPEndpoint: httpIDPSrv.URL() + idptest.TokenIntrospectionEndpointPath,
				HTTPClient:   &http.Client{Timeout: time.Second * 5}, // custom HTTP client to avoid default retry policy
			},
			tokenToIntrospect: opaqueTokenWithInternalErr,
			checkError: func(t *gotesting.T, err error) {
				require.ErrorIs(t, err, grpcInternalErr)
				require.ErrorContains(t, err, "unexpected HTTP code 500")
			},
			expectedGRPCSrvCalled: true,
			expectedHTTPSrvCalled: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *gotesting.T) {
			if tt.useGRPCClient {
				// gRPC client is created and used by condition to avoid preserving its state (sessionID) between tests
				grpcClient, err := idptoken.NewGRPCClient(grpcIDPSrv.Addr(), insecure.NewCredentials())
				require.NoError(t, err)
				defer func() { require.NoError(t, grpcClient.Close()) }()
				tt.introspectorOpts.GRPCClient = grpcClient
			}
			if tt.accessToken == "" {
				tt.accessToken = validAccessToken
			}
			introspector, err := idptoken.NewIntrospectorWithOpts(idptest.NewSimpleTokenProvider(tt.accessToken), tt.introspectorOpts)
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

	// Expired JWT
	expiredJWT := idptest.MustMakeTokenStringSignedWithTestKey(&jwt.DefaultClaims{
		RegisteredClaims: jwtgo.RegisteredClaims{
			Issuer:    idpSrv.URL(),
			Subject:   uuid.NewString(),
			ID:        uuid.NewString(),
			ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(-time.Hour)),
		},
	})
	serverIntrospector.SetResultForToken(expiredJWT, &idptoken.DefaultIntrospectionResult{Active: false}, nil)

	// Valid JWTs with scope
	validJWT1Scope := []jwt.AccessPolicy{{
		TenantUUID:        uuid.NewString(),
		ResourceNamespace: "account-server",
		Role:              "account_viewer",
		ResourcePath:      "resource-" + uuid.NewString(),
	}}
	validJWT1RegClaims := jwtgo.RegisteredClaims{
		Issuer:    idpSrv.URL(),
		Subject:   uuid.NewString(),
		ID:        uuid.NewString(),
		ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(2 * time.Hour)),
	}
	valid1JWT := idptest.MustMakeTokenStringSignedWithTestKey(&jwt.DefaultClaims{RegisteredClaims: validJWT1RegClaims})
	serverIntrospector.SetResultForToken(valid1JWT, &idptoken.DefaultIntrospectionResult{Active: true,
		TokenType: idputil.TokenTypeBearer, DefaultClaims: jwt.DefaultClaims{RegisteredClaims: validJWT1RegClaims, Scope: validJWT1Scope}}, nil)
	validJWT2Scope := []jwt.AccessPolicy{{
		TenantUUID:        uuid.NewString(),
		ResourceNamespace: "account-server",
		Role:              "account_viewer",
		ResourcePath:      "resource-" + uuid.NewString(),
	}}
	validJWT2RegClaims := jwtgo.RegisteredClaims{
		Issuer:    idpSrv.URL(),
		Subject:   uuid.NewString(),
		ID:        uuid.NewString(),
		ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Hour)),
	}
	valid2JWT := idptest.MustMakeTokenStringSignedWithTestKey(&jwt.DefaultClaims{RegisteredClaims: validJWT2RegClaims})
	serverIntrospector.SetResultForToken(valid2JWT, &idptoken.DefaultIntrospectionResult{Active: true,
		TokenType: idputil.TokenTypeBearer, DefaultClaims: jwt.DefaultClaims{RegisteredClaims: validJWT2RegClaims, Scope: validJWT2Scope}}, nil)

	// Opaque tokens
	opaqueToken1 := "opaque-token-" + uuid.NewString()
	opaqueToken2 := "opaque-token-" + uuid.NewString()
	opaqueToken3 := "opaque-token-" + uuid.NewString()
	opaqueToken1Scope := []jwt.AccessPolicy{{
		TenantUUID:        uuid.NewString(),
		ResourceNamespace: "account-server",
		Role:              "admin",
		ResourcePath:      "resource-" + uuid.NewString(),
	}}
	opaqueToken1RegClaims := jwtgo.RegisteredClaims{
		ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Hour)),
	}
	opaqueToken2Scope := []jwt.AccessPolicy{{
		TenantUUID:        uuid.NewString(),
		ResourceNamespace: "event-manager",
		Role:              "admin",
		ResourcePath:      "resource-" + uuid.NewString(),
	}}
	opaqueToken2RegClaims := jwtgo.RegisteredClaims{
		ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Hour)),
	}
	serverIntrospector.SetResultForToken(opaqueToken1, &idptoken.DefaultIntrospectionResult{
		Active:        true,
		TokenType:     idputil.TokenTypeBearer,
		DefaultClaims: jwt.DefaultClaims{RegisteredClaims: opaqueToken1RegClaims, Scope: opaqueToken1Scope},
	}, nil)
	serverIntrospector.SetResultForToken(opaqueToken2, &idptoken.DefaultIntrospectionResult{
		Active:        true,
		TokenType:     idputil.TokenTypeBearer,
		DefaultClaims: jwt.DefaultClaims{RegisteredClaims: opaqueToken2RegClaims, Scope: opaqueToken2Scope},
	}, nil)
	serverIntrospector.SetResultForToken(opaqueToken3, &idptoken.DefaultIntrospectionResult{Active: false}, nil)

	tests := []struct {
		name              string
		introspectorOpts  idptoken.IntrospectorOpts
		tokens            []string
		expectedSrvCounts []map[string]uint64
		expectedResult    []*idptoken.DefaultIntrospectionResult
		checkError        []func(t *gotesting.T, err error)
		checkIntrospector func(t *gotesting.T, introspector *idptoken.Introspector)
		delay             time.Duration
	}{
		{
			name:              "error, token is not introspectable",
			tokens:            []string{"", "opaque-token"},
			expectedSrvCounts: []map[string]uint64{{}, {}},
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
				require.Equal(t, 0, introspector.EndpointDiscoveryCache.Len(context.Background()))
			},
		},
		{
			name: "ok, dynamic introspection endpoint, introspected token is expired JWT",
			introspectorOpts: idptoken.IntrospectorOpts{
				ClaimsCache:            idptoken.IntrospectorCacheOpts{Enabled: true},
				NegativeCache:          idptoken.IntrospectorCacheOpts{Enabled: true},
				EndpointDiscoveryCache: idptoken.IntrospectorCacheOpts{Enabled: true},
			},
			tokens: []string{expiredJWT, expiredJWT},
			expectedSrvCounts: []map[string]uint64{
				{idptest.TokenIntrospectionEndpointPath: 1, idptest.OpenIDConfigurationPath: 1},
				{},
			},
			expectedResult: []*idptoken.DefaultIntrospectionResult{{Active: false}, {Active: false}},
			checkIntrospector: func(t *gotesting.T, introspector *idptoken.Introspector) {
				require.Equal(t, 0, introspector.ClaimsCache.Len(context.Background()))
				require.Equal(t, 1, introspector.NegativeCache.Len(context.Background()))
				require.Equal(t, 1, introspector.EndpointDiscoveryCache.Len(context.Background()))
			},
		},
		{
			name: "ok, dynamic introspection endpoint, introspected token is JWT",
			introspectorOpts: idptoken.IntrospectorOpts{
				ClaimsCache:            idptoken.IntrospectorCacheOpts{Enabled: true},
				NegativeCache:          idptoken.IntrospectorCacheOpts{Enabled: true},
				EndpointDiscoveryCache: idptoken.IntrospectorCacheOpts{Enabled: true},
			},
			tokens: []string{valid1JWT, valid1JWT, valid2JWT, valid2JWT},
			expectedSrvCounts: []map[string]uint64{
				{idptest.TokenIntrospectionEndpointPath: 1, idptest.OpenIDConfigurationPath: 1},
				{},
				{idptest.TokenIntrospectionEndpointPath: 1},
				{},
			},
			expectedResult: []*idptoken.DefaultIntrospectionResult{
				{
					Active:        true,
					TokenType:     idputil.TokenTypeBearer,
					DefaultClaims: jwt.DefaultClaims{RegisteredClaims: validJWT1RegClaims, Scope: validJWT1Scope},
				},
				{
					Active:        true,
					TokenType:     idputil.TokenTypeBearer,
					DefaultClaims: jwt.DefaultClaims{RegisteredClaims: validJWT1RegClaims, Scope: validJWT1Scope},
				},
				{
					Active:        true,
					TokenType:     idputil.TokenTypeBearer,
					DefaultClaims: jwt.DefaultClaims{RegisteredClaims: validJWT2RegClaims, Scope: validJWT2Scope},
				},
				{
					Active:        true,
					TokenType:     idputil.TokenTypeBearer,
					DefaultClaims: jwt.DefaultClaims{RegisteredClaims: validJWT2RegClaims, Scope: validJWT2Scope},
				},
			},
			checkIntrospector: func(t *gotesting.T, introspector *idptoken.Introspector) {
				require.Equal(t, 2, introspector.ClaimsCache.Len(context.Background()))
				require.Equal(t, 0, introspector.NegativeCache.Len(context.Background()))
				require.Equal(t, 1, introspector.EndpointDiscoveryCache.Len(context.Background()))
			},
		},
		{
			name: "ok, static introspection endpoint, introspected token is opaque",
			introspectorOpts: idptoken.IntrospectorOpts{
				HTTPEndpoint:           idpSrv.URL() + idptest.TokenIntrospectionEndpointPath,
				ClaimsCache:            idptoken.IntrospectorCacheOpts{Enabled: true},
				NegativeCache:          idptoken.IntrospectorCacheOpts{Enabled: true},
				EndpointDiscoveryCache: idptoken.IntrospectorCacheOpts{Enabled: true},
			},
			tokens: []string{opaqueToken1, opaqueToken1, opaqueToken2, opaqueToken2, opaqueToken3, opaqueToken3},
			expectedSrvCounts: []map[string]uint64{
				{idptest.TokenIntrospectionEndpointPath: 1},
				{idptest.TokenIntrospectionEndpointPath: 0},
				{idptest.TokenIntrospectionEndpointPath: 1},
				{idptest.TokenIntrospectionEndpointPath: 0},
				{idptest.TokenIntrospectionEndpointPath: 1},
				{idptest.TokenIntrospectionEndpointPath: 0},
			},
			expectedResult: []*idptoken.DefaultIntrospectionResult{
				{Active: true, TokenType: idputil.TokenTypeBearer, DefaultClaims: jwt.DefaultClaims{RegisteredClaims: opaqueToken1RegClaims, Scope: opaqueToken1Scope}},
				{Active: true, TokenType: idputil.TokenTypeBearer, DefaultClaims: jwt.DefaultClaims{RegisteredClaims: opaqueToken1RegClaims, Scope: opaqueToken1Scope}},
				{Active: true, TokenType: idputil.TokenTypeBearer, DefaultClaims: jwt.DefaultClaims{RegisteredClaims: opaqueToken2RegClaims, Scope: opaqueToken2Scope}},
				{Active: true, TokenType: idputil.TokenTypeBearer, DefaultClaims: jwt.DefaultClaims{RegisteredClaims: opaqueToken2RegClaims, Scope: opaqueToken2Scope}},
				{Active: false},
				{Active: false},
			},
			checkIntrospector: func(t *gotesting.T, introspector *idptoken.Introspector) {
				require.Equal(t, 2, introspector.ClaimsCache.Len(context.Background()))
				require.Equal(t, 1, introspector.NegativeCache.Len(context.Background()))
				require.Equal(t, 0, introspector.EndpointDiscoveryCache.Len(context.Background()))
			},
		},
		{
			name: "ok, static introspection endpoint, cache has ttl",
			introspectorOpts: idptoken.IntrospectorOpts{
				HTTPEndpoint:           idpSrv.URL() + idptest.TokenIntrospectionEndpointPath,
				ClaimsCache:            idptoken.IntrospectorCacheOpts{Enabled: true, TTL: 100 * time.Millisecond},
				NegativeCache:          idptoken.IntrospectorCacheOpts{Enabled: true, TTL: 100 * time.Millisecond},
				EndpointDiscoveryCache: idptoken.IntrospectorCacheOpts{Enabled: true, TTL: 100 * time.Millisecond},
			},
			tokens: []string{opaqueToken1, opaqueToken1, opaqueToken3, opaqueToken3},
			expectedSrvCounts: []map[string]uint64{
				{idptest.TokenIntrospectionEndpointPath: 1},
				{idptest.TokenIntrospectionEndpointPath: 1},
				{idptest.TokenIntrospectionEndpointPath: 1},
				{idptest.TokenIntrospectionEndpointPath: 1},
			},
			expectedResult: []*idptoken.DefaultIntrospectionResult{
				{Active: true, TokenType: idputil.TokenTypeBearer, DefaultClaims: jwt.DefaultClaims{RegisteredClaims: opaqueToken1RegClaims, Scope: opaqueToken1Scope}},
				{Active: true, TokenType: idputil.TokenTypeBearer, DefaultClaims: jwt.DefaultClaims{RegisteredClaims: opaqueToken1RegClaims, Scope: opaqueToken1Scope}},
				{Active: false},
				{Active: false},
			},
			checkIntrospector: func(t *gotesting.T, introspector *idptoken.Introspector) {
				require.Equal(t, 1, introspector.ClaimsCache.Len(context.Background()))
				require.Equal(t, 1, introspector.NegativeCache.Len(context.Background()))
				require.Equal(t, 0, introspector.EndpointDiscoveryCache.Len(context.Background()))
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
				idpSrv.ResetServedCounts()

				result, introspectErr := introspector.IntrospectToken(context.Background(), token)
				if i < len(tt.checkError) {
					tt.checkError[i](t, introspectErr)
				} else {
					require.NoError(t, introspectErr)
					require.Equal(t, tt.expectedResult[i], result)
				}

				require.Equal(t, tt.expectedSrvCounts[i][idptest.TokenIntrospectionEndpointPath],
					idpSrv.ServedCounts()[idptest.TokenIntrospectionEndpointPath])
				require.Equal(t, tt.expectedSrvCounts[i][idptest.OpenIDConfigurationPath],
					idpSrv.ServedCounts()[idptest.OpenIDConfigurationPath])

				if tt.expectedSrvCounts[i][idptest.TokenIntrospectionEndpointPath] > 0 {
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

type CustomClaims struct {
	jwt.DefaultClaims
	CustomField string `json:"custom_field"`
}

func (c *CustomClaims) Clone() jwt.Claims {
	return &CustomClaims{
		DefaultClaims: *c.DefaultClaims.Clone().(*jwt.DefaultClaims),
		CustomField:   c.CustomField,
	}
}

type CustomIntrospectionResult struct {
	Active    bool   `json:"active"`
	TokenType string `json:"token_type,omitempty"`
	CustomClaims
}

func (ir *CustomIntrospectionResult) IsActive() bool {
	return ir.Active
}

func (ir *CustomIntrospectionResult) GetTokenType() string {
	return ir.TokenType
}

func (ir *CustomIntrospectionResult) GetClaims() jwt.Claims {
	return &ir.CustomClaims
}

func (ir *CustomIntrospectionResult) Clone() idptoken.IntrospectionResult {
	return &CustomIntrospectionResult{
		Active:       ir.Active,
		TokenType:    ir.TokenType,
		CustomClaims: *ir.CustomClaims.Clone().(*CustomClaims),
	}
}
