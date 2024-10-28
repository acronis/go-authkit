/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package testing

import (
	"context"
	"crypto/sha256"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/acronis/go-authkit/idptoken/pb"
	"github.com/acronis/go-authkit/internal/idputil"
)

type GRPCServerTokenCreatorMock struct {
	results map[[sha256.Size]byte]*pb.CreateTokenResponse

	Called      bool
	LastRequest *pb.CreateTokenRequest
}

func NewGRPCServerTokenCreatorMock() *GRPCServerTokenCreatorMock {
	return &GRPCServerTokenCreatorMock{
		results: make(map[[sha256.Size]byte]*pb.CreateTokenResponse),
	}
}

func (m *GRPCServerTokenCreatorMock) SetResultForToken(token string, result *pb.CreateTokenResponse) {
	m.results[tokenToKey(token)] = result
}

func (m *GRPCServerTokenCreatorMock) CreateToken(
	ctx context.Context, req *pb.CreateTokenRequest,
) (*pb.CreateTokenResponse, error) {
	m.Called = true
	m.LastRequest = req

	if req.GrantType != idputil.GrantTypeJWTBearer {
		return nil, status.Error(codes.InvalidArgument, "Unsupported GrantType")
	}
	if req.Assertion == "" {
		return nil, status.Error(codes.InvalidArgument, "Assertion is missing")
	}
	result, ok := m.results[tokenToKey(req.Assertion)]
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "Invalid assertion")
	}
	return result, nil
}

func (m *GRPCServerTokenCreatorMock) ResetCallsInfo() {
	m.Called = false
	m.LastRequest = nil
}
