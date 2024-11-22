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
	tokenV1 := idptest.MustMakeTokenStringSignedWithTestKey(&VersionedClaims{
		DefaultClaims: jwt.DefaultClaims{
			RegisteredClaims: jwtgo.RegisteredClaims{
				Subject:   "test-subject",
				ExpiresAt: jwtgo.NewNumericDate(tokenExpiresAt),
			},
		},
		Version: 1,
	})
	tokenV2 := idptest.MustMakeTokenStringSignedWithTestKey(&VersionedClaims{
		DefaultClaims: jwt.DefaultClaims{
			RegisteredClaims: jwtgo.RegisteredClaims{
				Subject:   "test-subject",
				ExpiresAt: jwtgo.NewNumericDate(tokenExpiresAt),
			},
		},
		Version: 2,
	})

	grpcServerTokenCreator := testing.NewGRPCServerTokenCreatorMock()
	grpcServerTokenCreator.SetResultForToken(tokenV1, &pb.CreateTokenResponse{
		AccessToken: tokenV2,
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
			name:         "ok",
			assertion:    tokenV1,
			tokenVersion: 2,
			expectedRequest: &pb.CreateTokenRequest{
				GrantType:    idputil.GrantTypeJWTBearer,
				Assertion:    tokenV1,
				TokenVersion: 2,
			},
			expectedTokenData: idptoken.TokenData{
				AccessToken: tokenV2,
				ExpiresIn:   tokenExpiresIn,
				TokenType:   idputil.TokenTypeBearer,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *gotesting.T) {
			tokenData, err := grpcClient.ExchangeToken(context.Background(), tt.assertion, tt.tokenVersion)
			if tt.checkErr != nil {
				tt.checkErr(t, err)
			} else {
				require.Equal(t, tt.expectedTokenData, tokenData)
			}
			if tt.expectedRequest != nil {
				require.Equal(t, tt.expectedRequest.GrantType, grpcServerTokenCreator.LastRequest.GrantType)
				require.Equal(t, tt.expectedRequest.Assertion, grpcServerTokenCreator.LastRequest.Assertion)
				require.Equal(t, tt.expectedRequest.TokenVersion, grpcServerTokenCreator.LastRequest.TokenVersion)
			}
		})
	}
}

type VersionedClaims struct {
	jwt.DefaultClaims
	Version int `json:"ver"`
}

func (c *VersionedClaims) Clone() jwt.Claims {
	return &VersionedClaims{
		DefaultClaims: *c.DefaultClaims.Clone().(*jwt.DefaultClaims),
		Version:       c.Version,
	}
}
