/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptoken_test

import (
	"context"
	gotesting "testing"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/acronis/go-authkit/idptest"
	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/idptoken/pb"
	"github.com/acronis/go-authkit/internal/idputil"
	"github.com/acronis/go-authkit/internal/testing"
	"github.com/acronis/go-authkit/jwt"
)

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
