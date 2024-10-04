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
)

// TokenHandler is an implementation of a handler responding with IDP token.
type TokenHandler struct {
	servedCount    atomic.Uint64
	ClaimsProvider HTTPClaimsProvider
}

func (h *TokenHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	h.servedCount.Add(1)

	if h.ClaimsProvider == nil {
		http.Error(rw, "ClaimsProvider for TokenHandler is not configured", http.StatusInternalServerError)
		return
	}

	claims, err := h.ClaimsProvider.Provide(r)
	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			http.Error(rw, "Unauthorized", http.StatusUnauthorized)
			return
		}
		http.Error(rw, fmt.Sprintf("Claims provider failed to provide claims: %v", err), http.StatusInternalServerError)
		return
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

	response := struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}{
		AccessToken: token,
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

type TokenIntrospectionHandler struct {
	servedCount       atomic.Uint64
	TokenIntrospector HTTPTokenIntrospector
}

func (h *TokenIntrospectionHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	h.servedCount.Add(1)

	if h.TokenIntrospector == nil {
		http.Error(rw, "HTTPTokenIntrospector for TokenIntrospectionHandler is not configured", http.StatusInternalServerError)
		return
	}

	token := r.FormValue("token")
	if token == "" {
		http.Error(rw, "Token is required", http.StatusBadRequest)
		return
	}
	introspectResult, err := h.TokenIntrospector.IntrospectToken(r, token)
	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			http.Error(rw, "Unauthorized", http.StatusUnauthorized)
			return
		}
		http.Error(rw, fmt.Sprintf("Token introspection failed: %v", err), http.StatusInternalServerError)
		return
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
