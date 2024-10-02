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

type GRPCTokenCreator interface {
	CreateToken(ctx context.Context, req *pb.CreateTokenRequest) (*pb.CreateTokenResponse, error)
}

type GRPCTokenIntrospector interface {
	IntrospectToken(ctx context.Context, req *pb.IntrospectTokenRequest) (*pb.IntrospectTokenResponse, error)
}

type GRPCServer struct {
	pb.UnimplementedIDPTokenServiceServer
	*grpc.Server
	addr              atomic.Value
	serverOpts        []grpc.ServerOption
	tokenIntrospector GRPCTokenIntrospector
	tokenCreator      GRPCTokenCreator
}

type GRPCServerOption func(*GRPCServer)

func WithGRPCAddr(addr string) GRPCServerOption {
	return func(server *GRPCServer) {
		server.addr.Store(addr)
	}
}

func WithGRPCServerOptions(opts ...grpc.ServerOption) GRPCServerOption {
	return func(s *GRPCServer) {
		s.serverOpts = opts
	}
}

func WithGRPCTokenIntrospector(tokenIntrospector GRPCTokenIntrospector) GRPCServerOption {
	return func(s *GRPCServer) {
		s.tokenIntrospector = tokenIntrospector
	}
}

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

func (s *GRPCServer) CreateToken(ctx context.Context, req *pb.CreateTokenRequest) (*pb.CreateTokenResponse, error) {
	if s.tokenCreator != nil {
		return s.tokenCreator.CreateToken(ctx, req)
	}
	return nil, status.Errorf(codes.Unimplemented, "method CreateToken not implemented")
}

func (s *GRPCServer) IntrospectToken(ctx context.Context, req *pb.IntrospectTokenRequest) (*pb.IntrospectTokenResponse, error) {
	if s.tokenIntrospector != nil {
		return s.tokenIntrospector.IntrospectToken(ctx, req)
	}
	return nil, status.Errorf(codes.Unimplemented, "method IntrospectToken not implemented")
}
