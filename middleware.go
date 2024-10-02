/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/acronis/go-appkit/httpserver/middleware"
	"github.com/acronis/go-appkit/log"
	"github.com/acronis/go-appkit/restapi"

	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/jwt"
)

// HeaderAuthorization contains the name of HTTP header with data that is used for authentication and authorization.
const HeaderAuthorization = "Authorization"

// Authentication and authorization error codes.
// We are using "var" here because some services may want to use different error codes.
var (
	ErrCodeBearerTokenMissing   = "bearerTokenMissing"
	ErrCodeAuthenticationFailed = "authenticationFailed"
	ErrCodeAuthorizationFailed  = "authorizationFailed"
)

// Authentication error messages.
// We are using "var" here because some services may want to use different error messages.
var (
	ErrMessageBearerTokenMissing   = "Authorization bearer token is missing."
	ErrMessageAuthenticationFailed = "Authentication is failed."
	ErrMessageAuthorizationFailed  = "Authorization is failed."
)

type ctxKey int

const (
	ctxKeyJWTClaims ctxKey = iota
	ctxKeyBearerToken
)

// JWTParser is an interface for parsing string representation of JWT.
type JWTParser interface {
	Parse(ctx context.Context, token string) (*jwt.Claims, error)
}

// CachingJWTParser does the same as JWTParser but stores parsed JWT claims in cache.
type CachingJWTParser interface {
	JWTParser
	InvalidateCache(ctx context.Context)
}

// TokenIntrospector is an interface for introspecting tokens.
type TokenIntrospector interface {
	IntrospectToken(ctx context.Context, token string) (idptoken.IntrospectionResult, error)
}

type jwtAuthHandler struct {
	next              http.Handler
	errorDomain       string
	jwtParser         JWTParser
	verifyAccess      func(r *http.Request, claims *jwt.Claims) bool
	tokenIntrospector TokenIntrospector
}

type jwtAuthMiddlewareOpts struct {
	verifyAccess      func(r *http.Request, claims *jwt.Claims) bool
	tokenIntrospector TokenIntrospector
}

// JWTAuthMiddlewareOption is an option for JWTAuthMiddleware.
type JWTAuthMiddlewareOption func(options *jwtAuthMiddlewareOpts)

// WithJWTAuthMiddlewareVerifyAccess is an option to set a function that verifies access for JWTAuthMiddleware.
func WithJWTAuthMiddlewareVerifyAccess(verifyAccess func(r *http.Request, claims *jwt.Claims) bool) JWTAuthMiddlewareOption {
	return func(options *jwtAuthMiddlewareOpts) {
		options.verifyAccess = verifyAccess
	}
}

// WithJWTAuthMiddlewareTokenIntrospector is an option to set a token introspector for JWTAuthMiddleware.
func WithJWTAuthMiddlewareTokenIntrospector(tokenIntrospector TokenIntrospector) JWTAuthMiddlewareOption {
	return func(options *jwtAuthMiddlewareOpts) {
		options.tokenIntrospector = tokenIntrospector
	}
}

// JWTAuthMiddleware is a middleware that does authentication
// by Access Token from the "Authorization" HTTP header of incoming request.
func JWTAuthMiddleware(errorDomain string, jwtParser JWTParser, opts ...JWTAuthMiddlewareOption) func(next http.Handler) http.Handler {
	var options jwtAuthMiddlewareOpts
	for _, opt := range opts {
		opt(&options)
	}
	return func(next http.Handler) http.Handler {
		return &jwtAuthHandler{next, errorDomain, jwtParser, options.verifyAccess, options.tokenIntrospector}
	}
}

func (h *jwtAuthHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	reqCtx := r.Context()
	logger := middleware.GetLoggerFromContext(reqCtx)

	bearerToken := GetBearerTokenFromRequest(r)
	if bearerToken == "" {
		apiErr := restapi.NewError(h.errorDomain, ErrCodeBearerTokenMissing, ErrMessageBearerTokenMissing)
		restapi.RespondError(rw, http.StatusUnauthorized, apiErr, logger)
		return
	}

	var jwtClaims *jwt.Claims
	if h.tokenIntrospector != nil {
		if introspectionResult, err := h.tokenIntrospector.IntrospectToken(reqCtx, bearerToken); err != nil {
			switch {
			case errors.Is(err, idptoken.ErrTokenIntrospectionNotNeeded):
				// Do nothing. Access Token already contains all necessary information for authN/authZ.
			case errors.Is(err, idptoken.ErrTokenNotIntrospectable):
				// Token is not introspectable by some reason.
				// In this case, we will parse it as JWT and use it for authZ.
				if logger != nil {
					logger.Warn("token is not introspectable, it will be used for authentication and authorization as is",
						log.Error(err))
				}
			default:
				apiErr := restapi.NewError(h.errorDomain, ErrCodeAuthenticationFailed, ErrMessageAuthenticationFailed)
				restapi.RespondError(rw, http.StatusUnauthorized, apiErr, logger)
				return
			}
		} else {
			if !introspectionResult.Active {
				apiErr := restapi.NewError(h.errorDomain, ErrCodeAuthenticationFailed, ErrMessageAuthenticationFailed)
				restapi.RespondError(rw, http.StatusUnauthorized, apiErr, logger)
				return
			}
			jwtClaims = &introspectionResult.Claims
		}
	}

	if jwtClaims == nil {
		var err error
		if jwtClaims, err = h.jwtParser.Parse(reqCtx, bearerToken); err != nil {
			if logger != nil {
				logger.Error("authentication failed", log.Error(err))
			}
			apiErr := restapi.NewError(h.errorDomain, ErrCodeAuthenticationFailed, ErrMessageAuthenticationFailed)
			restapi.RespondError(rw, http.StatusUnauthorized, apiErr, logger)
			return
		}
	}

	if h.verifyAccess != nil {
		if !h.verifyAccess(r, jwtClaims) {
			apiErr := restapi.NewError(h.errorDomain, ErrCodeAuthorizationFailed, ErrMessageAuthorizationFailed)
			restapi.RespondError(rw, http.StatusForbidden, apiErr, logger)
			return
		}
	}

	reqCtx = NewContextWithBearerToken(reqCtx, bearerToken)
	reqCtx = NewContextWithJWTClaims(reqCtx, jwtClaims)
	h.next.ServeHTTP(rw, r.WithContext(reqCtx))
}

// GetBearerTokenFromRequest extracts jwt token from request headers.
func GetBearerTokenFromRequest(r *http.Request) string {
	authHeader := strings.TrimSpace(r.Header.Get(HeaderAuthorization))
	if strings.HasPrefix(authHeader, "Bearer ") || strings.HasPrefix(authHeader, "bearer ") {
		return authHeader[7:]
	}
	return ""
}

// NewContextWithJWTClaims creates a new context with JWT claims.
func NewContextWithJWTClaims(ctx context.Context, jwtClaims *jwt.Claims) context.Context {
	return context.WithValue(ctx, ctxKeyJWTClaims, jwtClaims)
}

// GetJWTClaimsFromContext extracts JWT claims from the context.
func GetJWTClaimsFromContext(ctx context.Context) *jwt.Claims {
	value := ctx.Value(ctxKeyJWTClaims)
	if value == nil {
		return nil
	}
	return value.(*jwt.Claims)
}

// NewContextWithBearerToken creates a new context with token.
func NewContextWithBearerToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, ctxKeyBearerToken, token)
}

// GetBearerTokenFromContext extracts token from the context.
func GetBearerTokenFromContext(ctx context.Context) string {
	value := ctx.Value(ctxKeyBearerToken)
	if value == nil {
		return ""
	}
	return value.(string)
}
