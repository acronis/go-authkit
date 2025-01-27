/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptoken_test

import (
	"context"
	"fmt"
	"strconv"
	gotesting "testing"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/acronis/go-authkit/idptest"
	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/idptoken/pb"
	"github.com/acronis/go-authkit/internal/idputil"
	"github.com/acronis/go-authkit/internal/testing"
	"github.com/acronis/go-authkit/jwt"
)

func TestGRPCClient_IntrospectToken(t *gotesting.T) {
	const validAccessToken = "access-token-with-introspection-permission"
	var validSessionID = testing.GenerateSessionID(validAccessToken)

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

	grpcServerTokenIntrospector := testing.NewGRPCServerTokenIntrospectorMock()
	grpcServerTokenIntrospector.SetAccessTokenForIntrospection(validAccessToken)
	grpcServerTokenIntrospector.SetResultForToken(opaqueToken, &pb.IntrospectTokenResponse{
		Active:    true,
		TokenType: idputil.TokenTypeBearer,
		Aud:       opaqueTokenRegClaims.Audience,
		Exp:       opaqueTokenRegClaims.ExpiresAt.Unix(),
		Scope:     jwtScopeToGRPC(opaqueTokenScope),
	})

	grpcIDPSrv := idptest.NewGRPCServer(idptest.WithGRPCTokenIntrospector(grpcServerTokenIntrospector))
	require.NoError(t, grpcIDPSrv.StartAndWaitForReady(time.Second))
	defer func() { grpcIDPSrv.GracefulStop() }()

	type introspectionRequest struct {
		requestNumber                       int
		tokenToIntrospect                   string
		accessToken                         string
		serverRespCode                      codes.Code // ask server for a specific resp code despite actual auth info
		expectedResult                      idptoken.IntrospectionResult
		serverLastAuthorizationMetaExpected string
		serverLastSessionMetaExpected       string
		checkError                          func(t *gotesting.T, err error)
	}

	tCases := []struct {
		name          string
		requestSeries []introspectionRequest
	}{
		{
			name: "Send valid access token to server on 1st introspection request",
			requestSeries: []introspectionRequest{
				{
					requestNumber:     1,
					tokenToIntrospect: opaqueToken,
					accessToken:       validAccessToken,
					expectedResult: &idptoken.DefaultIntrospectionResult{
						Active:    true,
						TokenType: idputil.TokenTypeBearer,
						DefaultClaims: jwt.DefaultClaims{
							RegisteredClaims: jwtgo.RegisteredClaims{ExpiresAt: opaqueTokenRegClaims.ExpiresAt},
							Scope:            opaqueTokenScope,
						},
					},
					serverLastAuthorizationMetaExpected: "Bearer " + validAccessToken,
					serverLastSessionMetaExpected:       "",
				},
			},
		},
		{
			name: "Send valid session id to server upon 2nd introspection request",
			requestSeries: []introspectionRequest{
				{
					requestNumber:     1,
					tokenToIntrospect: opaqueToken,
					accessToken:       validAccessToken,
					expectedResult: &idptoken.DefaultIntrospectionResult{
						Active:    true,
						TokenType: idputil.TokenTypeBearer,
						DefaultClaims: jwt.DefaultClaims{
							RegisteredClaims: jwtgo.RegisteredClaims{ExpiresAt: opaqueTokenRegClaims.ExpiresAt},
							Scope:            opaqueTokenScope,
						},
					},
					serverLastAuthorizationMetaExpected: "Bearer " + validAccessToken,
					serverLastSessionMetaExpected:       "",
				},
				{
					requestNumber:     2,
					tokenToIntrospect: opaqueToken,
					accessToken:       validAccessToken,
					expectedResult: &idptoken.DefaultIntrospectionResult{
						Active:    true,
						TokenType: idputil.TokenTypeBearer,
						DefaultClaims: jwt.DefaultClaims{
							RegisteredClaims: jwtgo.RegisteredClaims{ExpiresAt: opaqueTokenRegClaims.ExpiresAt},
							Scope:            opaqueTokenScope,
						},
					},
					serverLastAuthorizationMetaExpected: "",
					serverLastSessionMetaExpected:       validSessionID,
				},
			},
		},
		{
			name: "Drop session id when 3rd of 4 introspection requests receives 401 from server",
			requestSeries: []introspectionRequest{
				{
					requestNumber:     1,
					tokenToIntrospect: opaqueToken,
					accessToken:       validAccessToken,
					expectedResult: &idptoken.DefaultIntrospectionResult{
						Active:    true,
						TokenType: idputil.TokenTypeBearer,
						DefaultClaims: jwt.DefaultClaims{
							RegisteredClaims: jwtgo.RegisteredClaims{ExpiresAt: opaqueTokenRegClaims.ExpiresAt},
							Scope:            opaqueTokenScope,
						},
					},
					serverLastAuthorizationMetaExpected: "Bearer " + validAccessToken,
					serverLastSessionMetaExpected:       "",
				},
				{
					requestNumber:     2,
					tokenToIntrospect: opaqueToken,
					accessToken:       validAccessToken,
					expectedResult: &idptoken.DefaultIntrospectionResult{
						Active:    true,
						TokenType: idputil.TokenTypeBearer,
						DefaultClaims: jwt.DefaultClaims{
							RegisteredClaims: jwtgo.RegisteredClaims{ExpiresAt: opaqueTokenRegClaims.ExpiresAt},
							Scope:            opaqueTokenScope,
						},
					},
					serverLastAuthorizationMetaExpected: "",
					serverLastSessionMetaExpected:       validSessionID,
				},
				{
					requestNumber:     3,
					tokenToIntrospect: opaqueToken,
					accessToken:       validAccessToken,
					serverRespCode:    codes.Unauthenticated, // ask server for 401 to invalidate session id in client
					checkError: func(t *gotesting.T, err error) {
						require.ErrorIs(t, err, idptoken.ErrUnauthenticated)
					},
					serverLastAuthorizationMetaExpected: "",
					serverLastSessionMetaExpected:       validSessionID,
				},
				{
					requestNumber:     4,
					tokenToIntrospect: opaqueToken,
					accessToken:       validAccessToken,
					expectedResult: &idptoken.DefaultIntrospectionResult{
						Active:    true,
						TokenType: idputil.TokenTypeBearer,
						DefaultClaims: jwt.DefaultClaims{
							RegisteredClaims: jwtgo.RegisteredClaims{ExpiresAt: opaqueTokenRegClaims.ExpiresAt},
							Scope:            opaqueTokenScope,
						},
					},
					serverLastAuthorizationMetaExpected: "Bearer " + validAccessToken,
					serverLastSessionMetaExpected:       "", // prev 401 drops session id in client so access token ust be used
				},
			},
		},
	}

	for _, tc := range tCases {
		t.Run(tc.name, func(t *gotesting.T) {
			grpcClient, err := idptoken.NewGRPCClient(grpcIDPSrv.Addr(), insecure.NewCredentials())
			require.NoError(t, err)
			defer func() { require.NoError(t, grpcClient.Close()) }()
			grpcServerTokenIntrospector.ResetCallsInfo()

			for _, req := range tc.requestSeries {
				ctx := context.Background()
				if req.serverRespCode != 0 {
					ctx = metadata.AppendToOutgoingContext(
						ctx, testing.TestMetaRequestedRespCode, strconv.FormatUint(uint64(req.serverRespCode), 10),
					)
				}
				result, introspectErr := grpcClient.IntrospectToken(ctx, req.tokenToIntrospect, nil, req.accessToken)
				if req.checkError != nil {
					req.checkError(t, introspectErr)
				} else {
					require.Equal(t, req.expectedResult, result)
				}
				require.Equal(t, req.serverLastAuthorizationMetaExpected, grpcServerTokenIntrospector.LastAuthorizationMeta,
					fmt.Sprintf("unexpected server auth meta with introspection request number %d", req.requestNumber))
				require.Equal(t, req.serverLastSessionMetaExpected, grpcServerTokenIntrospector.LastSessionMeta,
					fmt.Sprintf("unexpected server session meta with introspection request number %d", req.requestNumber))
				if req.expectedResult != nil {
					require.Equal(t, req.tokenToIntrospect, grpcServerTokenIntrospector.LastRequest.Token,
						fmt.Sprintf("unexpected introspection result with introspection request number %d", req.requestNumber))
				}
			}
		})
	}
}

func TestGRPCClient_ExchangeToken(t *gotesting.T) {
	tokenExpiresIn := time.Hour
	tokenExpiresAt := time.Now().Add(time.Hour)
	riToken := idptest.MustMakeTokenStringSignedWithTestKey(&jwt.DefaultClaims{
		RegisteredClaims: jwtgo.RegisteredClaims{
			Subject:   "test-subject",
			ExpiresAt: jwtgo.NewNumericDate(tokenExpiresAt),
		},
	})
	nriToken := idptest.MustMakeTokenStringWithHeader(&jwt.DefaultClaims{
		RegisteredClaims: jwtgo.RegisteredClaims{
			Subject:   "test-subject",
			ExpiresAt: jwtgo.NewNumericDate(tokenExpiresAt),
		},
	}, idptest.TestKeyID, idptest.GetTestRSAPrivateKey(), map[string]interface{}{"nri": true})

	grpcServerTokenCreator := testing.NewGRPCServerTokenCreatorMock()
	grpcServerTokenCreator.SetResultForToken(riToken, &pb.CreateTokenResponse{
		AccessToken: nriToken,
		ExpiresIn:   int64(tokenExpiresIn.Seconds()),
		TokenType:   idputil.TokenTypeBearer,
	})

	grpcIDPSrv := idptest.NewGRPCServer(idptest.WithGRPCTokenCreator(grpcServerTokenCreator))
	require.NoError(t, grpcIDPSrv.StartAndWaitForReady(time.Second))
	defer func() { grpcIDPSrv.GracefulStop() }()

	grpcClient, err := idptoken.NewGRPCClient(grpcIDPSrv.Addr(), insecure.NewCredentials())
	require.NoError(t, err)
	defer func() { require.NoError(t, grpcClient.Close()) }()

	tests := []struct {
		name              string
		assertion         string
		tokenVersion      uint32
		expectedTokenData idptoken.TokenData
		expectedRequest   *pb.CreateTokenRequest
		checkErr          func(t *gotesting.T, err error)
	}{
		{
			name:      "invalid assertion",
			assertion: "invalid-assertion",
			checkErr: func(t *gotesting.T, err error) {
				require.ErrorIs(t, err, idptoken.ErrUnauthenticated)
			},
		},
		{
			name:      "ok",
			assertion: riToken,
			expectedRequest: &pb.CreateTokenRequest{
				GrantType:                idputil.GrantTypeJWTBearer,
				Assertion:                riToken,
				NotRequiredIntrospection: true,
			},
			expectedTokenData: idptoken.TokenData{
				AccessToken: nriToken,
				ExpiresIn:   tokenExpiresIn,
				TokenType:   idputil.TokenTypeBearer,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *gotesting.T) {
			tokenData, exchangeErr := grpcClient.ExchangeToken(context.Background(), tt.assertion,
				idptoken.WithNotRequiredIntrospection(true))
			if tt.checkErr != nil {
				tt.checkErr(t, exchangeErr)
			} else {
				require.Equal(t, tt.expectedTokenData, tokenData)
			}
			if tt.expectedRequest != nil {
				require.Equal(t, tt.expectedRequest.GrantType, grpcServerTokenCreator.LastRequest.GrantType)
				require.Equal(t, tt.expectedRequest.Assertion, grpcServerTokenCreator.LastRequest.Assertion)
				require.Equal(t, tt.expectedRequest.NotRequiredIntrospection,
					grpcServerTokenCreator.LastRequest.NotRequiredIntrospection)
			}
		})
	}
}
