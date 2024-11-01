/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idputil

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

type JWKSResponse struct {
}
