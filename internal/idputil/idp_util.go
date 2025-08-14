/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idputil

import (
	"context"
	"net/http"
	"time"

	"github.com/acronis/go-appkit/httpclient"
	"github.com/acronis/go-appkit/log"
	"github.com/acronis/go-appkit/retry"

	"github.com/acronis/go-authkit/internal/libinfo"
)

const GrantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer" //nolint: gosec // false positive

const JWTTypeAccessToken = "at+jwt"

const JWTTypeAppAccessToken = "application/at+jwt"

const TokenTypeBearer = "Bearer"

const (
	DefaultHTTPRequestTimeout          = 30 * time.Second
	DefaultHTTPRequestMaxRetryAttempts = 3
)

var DefaultLogger = log.NewDisabledLogger()

func MakeDefaultHTTPClient(
	reqTimeout time.Duration,
	loggerProvider func(ctx context.Context) log.FieldLogger,
	requestIDProvider func(ctx context.Context) string,
	userAgent string,
) *http.Client {
	retryableOpts := httpclient.RetryableRoundTripperOpts{
		MaxRetryAttempts: DefaultHTTPRequestMaxRetryAttempts,
		LoggerProvider:   loggerProvider,
	}
	return makeHTTPClient(reqTimeout, retryableOpts, requestIDProvider, userAgent)
}

// MakeHTTPClientWithFastRetryPolicy creates an HTTP client with a fast retry policy.
// It is useful for cases where we don't want to wait too long for retries (e.g., during token introspection, fetching JWKS, etc.)
func MakeHTTPClientWithFastRetryPolicy(
	reqTimeout time.Duration,
	loggerProvider func(ctx context.Context) log.FieldLogger,
	requestIDProvider func(ctx context.Context) string,
	userAgent string,
) *http.Client {
	const initialBackoff = 150 * time.Millisecond
	retryableOpts := httpclient.RetryableRoundTripperOpts{
		MaxRetryAttempts: 1,
		LoggerProvider:   loggerProvider,
		IgnoreRetryAfter: true,
		BackoffPolicy:    retry.NewExponentialBackoffPolicy(initialBackoff, 1),
	}
	return makeHTTPClient(reqTimeout, retryableOpts, requestIDProvider, userAgent)
}

func makeHTTPClient(
	reqTimeout time.Duration,
	retryableOpts httpclient.RetryableRoundTripperOpts,
	requestIDProvider func(ctx context.Context) string,
	userAgent string,
) *http.Client {
	if reqTimeout == 0 {
		reqTimeout = DefaultHTTPRequestTimeout
	}
	var tr http.RoundTripper = http.DefaultTransport.(*http.Transport).Clone()
	tr, _ = httpclient.NewRetryableRoundTripperWithOpts(tr, retryableOpts) // error is always nil
	tr = httpclient.NewUserAgentRoundTripper(tr, userAgent)
	if requestIDProvider != nil {
		tr = httpclient.NewRequestIDRoundTripperWithOpts(tr, httpclient.RequestIDRoundTripperOpts{
			RequestIDProvider: requestIDProvider,
		})
	}
	return &http.Client{Timeout: reqTimeout, Transport: tr}
}

func PrepareLogger(logger log.FieldLogger) log.FieldLogger {
	if logger == nil {
		return DefaultLogger
	}
	return log.NewPrefixedLogger(logger, libinfo.LogPrefix())
}

func GetLoggerFromProvider(ctx context.Context, provider func(ctx context.Context) log.FieldLogger) log.FieldLogger {
	if provider != nil {
		if logger := provider(ctx); logger != nil {
			return log.NewPrefixedLogger(logger, libinfo.LogPrefix())
		}
	}
	return DefaultLogger
}
