/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package main

import (
	"context"
	"fmt"
	golog "log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/acronis/go-appkit/log"
	"google.golang.org/grpc/metadata"

	"github.com/acronis/go-authkit"
	"github.com/acronis/go-authkit/idptest"
	"github.com/acronis/go-authkit/idptoken/pb"
	"github.com/acronis/go-authkit/jwt"
)

func main() {
	if err := runApp(); err != nil {
		golog.Fatal(err)
	}
}

func runApp() error {
	const (
		idpAddr  = "127.0.0.1:8081"
		grpcAddr = "127.0.0.1:50051"
	)

	logger, loggerClose := log.NewLogger(&log.Config{Output: log.OutputStdout, Level: log.LevelInfo, Format: log.FormatJSON})
	defer loggerClose()

	jwtParser, err := authkit.NewJWTParser(
		&authkit.Config{JWT: authkit.JWTConfig{TrustedIssuerURLs: []string{"http://" + idpAddr}}})
	if err != nil {
		return fmt.Errorf("create JWT parser: %w", err)
	}

	grpcSrv := idptest.NewGRPCServer(
		idptest.WithGRPCAddr(grpcAddr),
		idptest.WithGRPCTokenIntrospector(&demoGRPCTokenIntrospector{jwtParser: jwtParser, logger: logger}),
	)
	if err = grpcSrv.StartAndWaitForReady(time.Second * 3); err != nil {
		return err
	}
	logger.Info("GRPC server for token introspection is running on " + grpcAddr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	grpcSrv.GracefulStop()
	return nil
}

const accessTokenWithIntrospectionPermission = "access-token-with-introspection-permission"

type demoGRPCTokenIntrospector struct {
	jwtParser authkit.JWTParser
	logger    log.FieldLogger
}

func (dti *demoGRPCTokenIntrospector) IntrospectToken(
	ctx context.Context, req *pb.IntrospectTokenRequest,
) (*pb.IntrospectTokenResponse, error) {
	var userAgent string
	var authMeta string
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if userAgentList := md.Get("user-agent"); len(userAgentList) > 0 {
			userAgent = userAgentList[0]
		}
		if authList := md.Get("authorization"); len(authList) > 0 {
			authMeta = authList[0]
		}
	}

	dti.logger.Info("got IntrospectTokenRequest", log.String("user_agent", userAgent))

	if authMeta != "Bearer "+accessTokenWithIntrospectionPermission {
		return nil, idptest.ErrUnauthorized
	}
	claims, err := dti.jwtParser.Parse(ctx, req.Token)
	if err != nil {
		return &pb.IntrospectTokenResponse{Active: false}, nil
	}
	if claims.Subject == "admin2" {
		claims.Scope = append(claims.Scope, jwt.AccessPolicy{ResourceNamespace: "my_service", Role: "admin"})
	}
	resp := &pb.IntrospectTokenResponse{
		Active:    true,
		TokenType: "Bearer",
		Sub:       claims.Subject,
		Exp:       claims.ExpiresAt.Unix(),
		Aud:       claims.Audience,
		Iss:       claims.Issuer,
		Scope:     make([]*pb.AccessTokenScope, 0, len(claims.Scope)),
	}
	for _, policy := range claims.Scope {
		resp.Scope = append(resp.Scope, &pb.AccessTokenScope{
			ResourceNamespace: policy.ResourceNamespace,
			RoleName:          policy.Role,
			ResourcePath:      policy.ResourcePath,
			ResourceServer:    policy.ResourceServerID,
		})
	}
	return resp, nil
}
