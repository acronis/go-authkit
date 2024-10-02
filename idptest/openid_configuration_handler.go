/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/acronis/go-authkit/internal/idputil"
)

// OpenIDConfigurationHandler is an HTTP handler that responds token's issuer OpenID configuration.
type OpenIDConfigurationHandler struct {
	servedCount              atomic.Uint64
	BaseURLFunc              func() string // for cases when 'host:port' of providers' addresses to be determined during runtime
	JWKSURL                  string
	TokenEndpointURL         string
	IntrospectionEndpointURL string
}

func (h *OpenIDConfigurationHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(rw, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	h.servedCount.Add(1)

	openIDCfg := idputil.OpenIDConfiguration{
		TokenURL:              h.makeEndpointURL(h.TokenEndpointURL, TokenIntrospectionEndpointPath),
		IntrospectionEndpoint: h.makeEndpointURL(h.IntrospectionEndpointURL, TokenIntrospectionEndpointPath),
		JWKSURI:               h.makeEndpointURL(h.JWKSURL, JWKSEndpointPath),
	}
	rw.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(rw).Encode(openIDCfg); err != nil {
		http.Error(rw, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

func (h *OpenIDConfigurationHandler) makeEndpointURL(endpointURL string, defaultPath string) string {
	if endpointURL == "" {
		endpointURL = defaultPath
	}
	if h.BaseURLFunc != nil {
		endpointURL = h.BaseURLFunc() + endpointURL
	}
	return endpointURL
}

// ServedCount returns the number of times the handler has been served.
func (h *OpenIDConfigurationHandler) ServedCount() uint64 {
	return h.servedCount.Load()
}
