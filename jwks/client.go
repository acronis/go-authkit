/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package jwks

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/acronis/go-appkit/log"
	"github.com/mendsley/gojwk"

	"github.com/acronis/go-authkit/internal/idputil"
	"github.com/acronis/go-authkit/internal/metrics"
)

const OpenIDConfigurationPath = "/.well-known/openid-configuration"

type jwksData struct {
	Keys []*gojwk.Key `json:"keys"`
}

// ClientOpts contains options for the JWKS client.
type ClientOpts struct {
	// HTTPClient is an HTTP client for making requests.
	HTTPClient *http.Client

	// Logger is a logger for the client.
	Logger log.FieldLogger

	// PrometheusLibInstanceLabel is a label for Prometheus metrics.
	// It allows distinguishing metrics from different instances of the same library.
	PrometheusLibInstanceLabel string
}

// Client gets public keys from remote JWKS.
// It uses jwks_uri field from /.well-known/openid-configuration endpoint.
// NOTE: CachingClient should be used in a typical service
// to avoid making HTTP requests on each JWT verification.
type Client struct {
	httpClient  *http.Client
	logger      log.FieldLogger
	promMetrics *metrics.PrometheusMetrics
}

// NewClient returns a new Client.
func NewClient() *Client {
	return NewClientWithOpts(ClientOpts{})
}

// NewClientWithOpts returns a new Client with options.
func NewClientWithOpts(opts ClientOpts) *Client {
	promMetrics := metrics.GetPrometheusMetrics(opts.PrometheusLibInstanceLabel, "jwks_client")
	opts.Logger = idputil.PrepareLogger(opts.Logger)
	if opts.HTTPClient == nil {
		opts.HTTPClient = idputil.MakeDefaultHTTPClient(idputil.DefaultHTTPRequestTimeout, opts.Logger)
	}
	return &Client{httpClient: opts.HTTPClient, logger: opts.Logger, promMetrics: promMetrics}
}

func (c *Client) getRSAPubKeysForIssuer(ctx context.Context, issuerURL string) (map[string]interface{}, error) {
	openIDConfigURL := strings.TrimPrefix(issuerURL, "/") + OpenIDConfigurationPath
	openIDConfig, err := idputil.GetOpenIDConfiguration(
		ctx, c.httpClient, openIDConfigURL, nil, c.logger, c.promMetrics)
	if err != nil {
		return nil, &GetOpenIDConfigurationError{Inner: err, URL: openIDConfigURL}
	}
	jwksRespData, err := c.getJWKS(ctx, openIDConfig.JWKSURI)
	if err != nil {
		return nil, &GetJWKSError{Inner: err, URL: openIDConfig.JWKSURI, OpenIDConfigurationURL: openIDConfigURL}
	}
	c.logger.Info(fmt.Sprintf("%d keys fetched (jwks_url: %s)", len(jwksRespData.Keys), openIDConfig.JWKSURI))

	pubKeys := make(map[string]interface{}, len(jwksRespData.Keys))
	for _, jwk := range jwksRespData.Keys {
		var pubKey crypto.PublicKey
		if pubKey, err = jwk.DecodePublicKey(); err != nil {
			c.logger.Error(fmt.Sprintf("decoding JWK (kid: %s, jwks_url: %s) to public key error",
				jwk.Kid, openIDConfig.JWKSURI), log.Error(err))
			continue
		}
		rsaPubKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			c.logger.Error(fmt.Sprintf("converting JWK (kid: %s, jwks_url: %s) to RSA public key error",
				jwk.Kid, openIDConfig.JWKSURI), log.Error(err))
			continue
		}
		pubKeys[jwk.Kid] = rsaPubKey
	}
	return pubKeys, nil
}

// GetRSAPublicKey gets JWK from JWKS and returns decoded RSA public key. The last one can be used for verifying JWT signature.
func (c *Client) GetRSAPublicKey(ctx context.Context, issuerURL, keyID string) (interface{}, error) {
	pubKeys, err := c.getRSAPubKeysForIssuer(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("get rsa public keys for issuer %q: %w", issuerURL, err)
	}
	pubKey, ok := pubKeys[keyID]
	if !ok {
		return nil, &JWKNotFoundError{IssuerURL: issuerURL, KeyID: keyID}
	}
	return pubKey, nil
}

func (c *Client) getJWKS(ctx context.Context, jwksURL string) (jwksData, error) {
	req, err := http.NewRequest(http.MethodGet, jwksURL, http.NoBody)
	if err != nil {
		return jwksData{}, fmt.Errorf("new request: %w", err)
	}
	startTime := time.Now()
	resp, err := c.httpClient.Do(req.WithContext(ctx))
	elapsed := time.Since(startTime)
	if err != nil {
		c.promMetrics.ObserveHTTPClientRequest(http.MethodGet, jwksURL, 0, elapsed, metrics.HTTPRequestErrorDo)
		return jwksData{}, fmt.Errorf("do request: %w", err)
	}
	defer func() {
		if closeBodyErr := resp.Body.Close(); closeBodyErr != nil {
			c.logger.Error(fmt.Sprintf("closing response body error for GET %s", jwksURL), log.Error(closeBodyErr))
		}
	}()

	if resp.StatusCode != http.StatusOK {
		c.promMetrics.ObserveHTTPClientRequest(
			http.MethodGet, jwksURL, resp.StatusCode, elapsed, metrics.HTTPRequestErrorUnexpectedStatusCode)
		return jwksData{}, fmt.Errorf("unexpected HTTP code %d", resp.StatusCode)
	}

	var res jwksData
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		c.promMetrics.ObserveHTTPClientRequest(
			http.MethodGet, jwksURL, resp.StatusCode, elapsed, metrics.HTTPRequestErrorDecodeBody)
		return jwksData{}, fmt.Errorf("decode response body json: %w", err)
	}

	c.promMetrics.ObserveHTTPClientRequest(http.MethodGet, jwksURL, resp.StatusCode, elapsed, "")
	return res, nil
}
