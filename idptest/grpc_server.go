/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptest

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/acronis/go-appkit/testutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	"github.com/acronis/go-authkit/idptoken/pb"
)

// GRPCTokenCreator is an interface for creating tokens using gRPC.
type GRPCTokenCreator interface {
	CreateToken(ctx context.Context, req *pb.CreateTokenRequest) (*pb.CreateTokenResponse, error)
}

// GRPCTokenCreatorFunc is a function that implements GRPCTokenCreator interface.
type GRPCTokenCreatorFunc func(ctx context.Context, req *pb.CreateTokenRequest) (*pb.CreateTokenResponse, error)

// CreateToken implements GRPCTokenCreator interface.
func (f GRPCTokenCreatorFunc) CreateToken(ctx context.Context, req *pb.CreateTokenRequest) (*pb.CreateTokenResponse, error) {
	return f(ctx, req)
}

// GRPCTokenIntrospector is an interface for introspecting tokens using gRPC.
type GRPCTokenIntrospector interface {
	IntrospectToken(ctx context.Context, req *pb.IntrospectTokenRequest) (*pb.IntrospectTokenResponse, error)
}

// GRPCTokenIntrospectorFunc is a function that implements GRPCTokenIntrospector interface.
type GRPCTokenIntrospectorFunc func(ctx context.Context, req *pb.IntrospectTokenRequest) (*pb.IntrospectTokenResponse, error)

// IntrospectToken implements GRPCTokenIntrospector interface.
func (f GRPCTokenIntrospectorFunc) IntrospectToken(
	ctx context.Context, req *pb.IntrospectTokenRequest,
) (*pb.IntrospectTokenResponse, error) {
	return f(ctx, req)
}

// GRPCServer is a gRPC server for IDP token service.
type GRPCServer struct {
	pb.UnimplementedIDPTokenServiceServer
	*grpc.Server
	addr              atomic.Value
	serverOpts        []grpc.ServerOption
	tokenIntrospector GRPCTokenIntrospector
	tokenCreator      GRPCTokenCreator
}

// GRPCServerOption is an option for GRPCServer.
type GRPCServerOption func(*GRPCServer)

// WithGRPCAddr is an option to set gRPC server address.
func WithGRPCAddr(addr string) GRPCServerOption {
	return func(server *GRPCServer) {
		server.addr.Store(addr)
	}
}

// WithGRPCServerOptions is an option to set gRPC server options.
func WithGRPCServerOptions(opts ...grpc.ServerOption) GRPCServerOption {
	return func(s *GRPCServer) {
		s.serverOpts = opts
	}
}

// WithGRPCTokenIntrospector is an option to set token introspector for the server.
func WithGRPCTokenIntrospector(tokenIntrospector GRPCTokenIntrospector) GRPCServerOption {
	return func(s *GRPCServer) {
		s.tokenIntrospector = tokenIntrospector
	}
}

// WithGRPCTokenCreator is an option to set token creator for the server.
func WithGRPCTokenCreator(tokenCreator GRPCTokenCreator) GRPCServerOption {
	return func(s *GRPCServer) {
		s.tokenCreator = tokenCreator
	}
}

// NewGRPCServer creates a new instance of GRPCServer.
func NewGRPCServer(
	opts ...GRPCServerOption,
) *GRPCServer {
	srv := &GRPCServer{}
	for _, opt := range opts {
		opt(srv)
	}
	srv.Server = grpc.NewServer(srv.serverOpts...)
	pb.RegisterIDPTokenServiceServer(srv.Server, srv)
	reflection.Register(srv.Server)
	return srv
}

// Addr returns the server address.
func (s *GRPCServer) Addr() string {
	return s.addr.Load().(string)
}

// Start starts the GRPC server
func (s *GRPCServer) Start() error {
	addr, ok := s.addr.Load().(string)
	if !ok {
		addr = localhostWithDynamicPortAddr
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen tcp: %w", err)
	}
	s.addr.Store(ln.Addr().String())

	go func() { _ = s.Serve(ln) }()

	return nil
}

// StartAndWaitForReady starts the server waits for the server to start listening.
func (s *GRPCServer) StartAndWaitForReady(timeout time.Duration) error {
	if err := s.Start(); err != nil {
		return fmt.Errorf("start server: %w", err)
	}
	return testutil.WaitListeningServer(s.Addr(), timeout)
}

// CreateToken is a gRPC method for creating tokens.
func (s *GRPCServer) CreateToken(ctx context.Context, req *pb.CreateTokenRequest) (*pb.CreateTokenResponse, error) {
	if s.tokenCreator != nil {
		return s.tokenCreator.CreateToken(ctx, req)
	}
	return nil, status.Errorf(codes.Unimplemented, "method CreateToken not implemented")
}

// IntrospectToken is a gRPC method for introspecting tokens.
func (s *GRPCServer) IntrospectToken(ctx context.Context, req *pb.IntrospectTokenRequest) (*pb.IntrospectTokenResponse, error) {
	if s.tokenIntrospector != nil {
		return s.tokenIntrospector.IntrospectToken(ctx, req)
	}
	return nil, status.Errorf(codes.Unimplemented, "method IntrospectToken not implemented")
}
