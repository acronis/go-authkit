/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package jwks

import "fmt"

// GetOpenIDConfigurationError is an error that may occur during getting openID configuration for issuer.
type GetOpenIDConfigurationError struct {
	Inner error
	URL   string
}

func (e *GetOpenIDConfigurationError) Error() string {
	return fmt.Sprintf("error while getting OpenID configuration (URL: %q): %s", e.URL, e.Inner.Error())
}

func (e *GetOpenIDConfigurationError) Unwrap() error {
	return e.Inner
}

// GetJWKSError is an error that may occur during getting JWKS.
type GetJWKSError struct {
	Inner                  error
	URL                    string
	OpenIDConfigurationURL string
}

func (e *GetJWKSError) Error() string {
	return fmt.Sprintf("error while getting JWKS data (URL: %q, OpenID configuration URL: %q): %s",
		e.URL, e.OpenIDConfigurationURL, e.Inner.Error())
}

func (e *GetJWKSError) Unwrap() error {
	return e.Inner
}

// JWKNotFoundError is an error that occurs when JWK is not found by kid.
type JWKNotFoundError struct {
	IssuerURL string
	KeyID     string
}

func (e *JWKNotFoundError) Error() string {
	return fmt.Sprintf("JWK not found (Key ID: %q, Issuer URL: %q)", e.KeyID, e.IssuerURL)
}
