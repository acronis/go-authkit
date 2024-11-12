/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idputil

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/acronis/go-appkit/log"

	"github.com/acronis/go-authkit/internal/metrics"
)

const OpenIDConfigurationPath = "/.well-known/openid-configuration"

type OpenIDConfiguration struct {
	TokenURL              string `json:"token_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

func GetOpenIDConfiguration(
	ctx context.Context,
	httpClient *http.Client,
	targetURL string,
	additionalHeaders map[string]string,
	logger log.FieldLogger,
	promMetrics *metrics.PrometheusMetrics,
) (OpenIDConfiguration, error) {
	req, err := http.NewRequest(http.MethodGet, targetURL, http.NoBody)
	if err != nil {
		return OpenIDConfiguration{}, fmt.Errorf("new request: %w", err)
	}
	for key, val := range additionalHeaders {
		req.Header.Set(key, val)
	}

	startTime := time.Now()
	resp, err := httpClient.Do(req.WithContext(ctx))
	elapsed := time.Since(startTime)
	if err != nil {
		promMetrics.ObserveHTTPClientRequest(http.MethodGet, targetURL, 0, elapsed, metrics.HTTPRequestErrorDo)
		return OpenIDConfiguration{}, fmt.Errorf("do request: %w", err)
	}
	defer func() {
		if closeBodyErr := resp.Body.Close(); closeBodyErr != nil && logger != nil {
			logger.Error(fmt.Sprintf("closing response body error for GET %s", targetURL), log.Error(closeBodyErr))
		}
	}()

	if resp.StatusCode != http.StatusOK {
		promMetrics.ObserveHTTPClientRequest(
			http.MethodGet, targetURL, resp.StatusCode, elapsed, metrics.HTTPRequestErrorUnexpectedStatusCode)
		return OpenIDConfiguration{}, fmt.Errorf("unexpected HTTP code %d", resp.StatusCode)
	}

	var openIDCfg OpenIDConfiguration
	if err = json.NewDecoder(resp.Body).Decode(&openIDCfg); err != nil {
		promMetrics.ObserveHTTPClientRequest(
			http.MethodGet, targetURL, resp.StatusCode, elapsed, metrics.HTTPRequestErrorDecodeBody)
		return OpenIDConfiguration{}, fmt.Errorf("decode response body json (Content-Type: %s): %w",
			resp.Header.Get("Content-Type"), err)
	}

	promMetrics.ObserveHTTPClientRequest(http.MethodGet, targetURL, resp.StatusCode, elapsed, "")
	return openIDCfg, nil
}
