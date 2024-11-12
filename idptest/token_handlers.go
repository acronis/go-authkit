/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptest

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/internal/idputil"
	"github.com/acronis/go-authkit/jwt"
)

// TokenHandler is an implementation of a handler responding with IDP token.
type TokenHandler struct {
	servedCount    atomic.Uint64
	Issuer         string
	ClaimsProvider HTTPClaimsProvider
}

func (h *TokenHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	h.servedCount.Add(1)

	var claims jwt.Claims
	if h.ClaimsProvider != nil {
		var err error
		if claims, err = h.ClaimsProvider.Provide(r); err != nil {
			if errors.Is(err, ErrUnauthorized) {
				http.Error(rw, "Unauthorized", http.StatusUnauthorized)
				return
			}
			http.Error(rw, fmt.Sprintf("Claims provider failed to provide claims: %v", err), http.StatusInternalServerError)
			return
		}
	}
	if claims.ID == "" {
		claims.ID = uuid.NewString()
	}
	if claims.ExpiresAt == nil {
		claims.ExpiresAt = jwtgo.NewNumericDate(time.Now().Add(time.Hour)) // By default, token expires in 1 hour.
	}
	if claims.Issuer == "" {
		claims.Issuer = h.Issuer
	}

	token, err := MakeTokenStringWithHeader(claims, TestKeyID, GetTestRSAPrivateKey(), nil)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Claims provider failed generate token: %v", err), http.StatusInternalServerError)
		return
	}

	expiresIn := claims.ExpiresAt.Unix() - time.Now().UTC().Unix()
	if expiresIn < 0 {
		expiresIn = 0
	}

	response := TokenResponse{
		AccessToken: token,
		TokenType:   idputil.TokenTypeBearer,
		ExpiresIn:   expiresIn,
	}
	rw.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(rw).Encode(response); err != nil {
		http.Error(rw, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

// ServedCount returns the number of times the handler has been served.
func (h *TokenHandler) ServedCount() uint64 {
	return h.servedCount.Load()
}

// ResetServedCount resets the number of times the handler has been served.
func (h *TokenHandler) ResetServedCount() {
	h.servedCount.Store(0)
}

// TokenResponse is a response for POST /idp/token endpoint.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

type TokenIntrospectionHandler struct {
	servedCount       atomic.Uint64
	JWTParser         *jwt.Parser
	TokenIntrospector HTTPTokenIntrospector
}

func (h *TokenIntrospectionHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	h.servedCount.Add(1)

	if h.TokenIntrospector == nil && h.JWTParser == nil {
		http.Error(rw, "Token introspector and JWT parser are not set", http.StatusInternalServerError)
		return
	}

	token := r.FormValue("token")
	if token == "" {
		http.Error(rw, "Token is required", http.StatusBadRequest)
		return
	}

	var introspectResult idptoken.IntrospectionResult
	if h.TokenIntrospector != nil {
		var err error
		if introspectResult, err = h.TokenIntrospector.IntrospectToken(r, token); err != nil {
			if errors.Is(err, ErrUnauthorized) {
				http.Error(rw, "Unauthorized", http.StatusUnauthorized)
				return
			}
			http.Error(rw, fmt.Sprintf("Token introspection failed: %v", err), http.StatusInternalServerError)
			return
		}
	} else {
		if claims, err := h.JWTParser.Parse(r.Context(), token); err == nil {
			introspectResult.Active = true
			introspectResult.TokenType = idputil.TokenTypeBearer
			introspectResult.Claims = *claims
		}
	}

	rw.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(rw).Encode(introspectResult); err != nil {
		http.Error(rw, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

// ServedCount returns the number of times the handler has been served.
func (h *TokenIntrospectionHandler) ServedCount() uint64 {
	return h.servedCount.Load()
}

// ResetServedCount resets the number of times the handler has been served.
func (h *TokenIntrospectionHandler) ResetServedCount() {
	h.servedCount.Store(0)
}
