/*
Copyright © 2025 Acronis International GmbH.

Released under MIT license.
*/

package idputil

import (
	"fmt"
	"net/http"
)

// UnexpectedResponseError represents an error that occurs when an unexpected HTTP response is received.
// It captures the HTTP status code and response headers for further analysis.
type UnexpectedResponseError struct {
	StatusCode int
	Header     http.Header
}

func (e *UnexpectedResponseError) Error() string {
	return fmt.Sprintf("unexpected HTTP status code %d", e.StatusCode)
}
