/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package main

import (
	"context"
	"errors"
	"fmt"
	golog "log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/acronis/go-appkit/httpserver/middleware"
	"github.com/acronis/go-appkit/log"

	"github.com/acronis/go-authkit"
	"github.com/acronis/go-authkit/idptest"
	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/jwt"
)

func main() {
	if err := runApp(); err != nil {
		golog.Fatal(err)
	}
}

func runApp() error {
	const idpAddr = "127.0.0.1:8081"

	logger, loggerClose := log.NewLogger(&log.Config{Output: log.OutputStdout, Level: log.LevelInfo, Format: log.FormatJSON})
	defer loggerClose()

	jwtParser, err := authkit.NewJWTParser(
		&authkit.Config{JWT: authkit.JWTConfig{TrustedIssuerURLs: []string{"http://" + idpAddr}}})
	if err != nil {
		return fmt.Errorf("create JWT parser: %w", err)
	}

	idpSrv := idptest.NewHTTPServer(
		idptest.WithHTTPAddress(idpAddr),
		idptest.WithHTTPMiddleware(middleware.Logging(logger)),
		idptest.WithHTTPClaimsProvider(&demoClaimsProvider{}),
		idptest.WithHTTPTokenIntrospector(&demoTokenIntrospector{jwtParser: jwtParser}),
	)
	if err = idpSrv.StartAndWaitForReady(time.Second * 3); err != nil {
		return fmt.Errorf("start HTTP server: %w", err)
	}
	logger.Info("HTTP IDP server is running on " + idpAddr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second*3)
	defer shutdownCancel()

	if stopErr := idpSrv.Shutdown(shutdownCtx); stopErr != nil && !errors.Is(stopErr, http.ErrServerClosed) {
		return fmt.Errorf("shutdown HTTP server: %w", stopErr)
	}
	return nil
}

type demoTokenIntrospector struct {
	jwtParser authkit.JWTParser
}

func (dti *demoTokenIntrospector) IntrospectToken(r *http.Request, token string) (idptoken.IntrospectionResult, error) {
	if bearerToken := authkit.GetBearerTokenFromRequest(r); bearerToken != "access-token-with-introspection-permission" {
		return idptoken.IntrospectionResult{}, idptest.ErrUnauthorized
	}
	claims, err := dti.jwtParser.Parse(r.Context(), token)
	if err != nil {
		return idptoken.IntrospectionResult{Active: false}, nil
	}
	if claims.Subject == "admin2" {
		claims.Scope = append(claims.Scope, jwt.AccessPolicy{ResourceNamespace: "my_service", Role: "admin"})
	}
	return idptoken.IntrospectionResult{Active: true, TokenType: "Bearer", Claims: *claims}, nil
}

type demoClaimsProvider struct {
}

func (dcp *demoClaimsProvider) Provide(r *http.Request) (jwt.Claims, error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return jwt.Claims{}, idptest.ErrUnauthorized
	}
	var claims jwt.Claims
	switch {
	case username == "user" && password == "user-pwd":
		claims.Subject = "user"
	case username == "admin" && password == "admin-pwd":
		claims.Subject = "admin"
		claims.Scope = []jwt.AccessPolicy{{ResourceNamespace: "my_service", Role: "admin"}}
	case username == "admin2" && password == "admin2-pwd":
		claims.Subject = "admin2"
	default:
		return jwt.Claims{}, idptest.ErrUnauthorized
	}
	return claims, nil
}
