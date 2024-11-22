/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package jwt

import (
	"fmt"

	jwtgo "github.com/golang-jwt/jwt/v5"
)

// SignAlgUnknownError represents an error when JWT signing algorithm is unknown.
type SignAlgUnknownError struct {
	Alg string
}

func (e *SignAlgUnknownError) Error() string {
	return fmt.Sprintf("JWT has unknown signing algorithm %q", e.Alg)
}

// IssuerUntrustedError represents an error when JWT issuer is untrusted.
type IssuerUntrustedError struct {
	Claims Claims
	Issuer string
}

func (e *IssuerUntrustedError) Error() string {
	return fmt.Sprintf("JWT issuer %q untrusted", e.Issuer)
}

// IssuerMissingError represents an error when JWT issuer is missing.
type IssuerMissingError struct {
	Claims Claims
}

func (e *IssuerMissingError) Error() string {
	return "JWT issuer missing"
}

// AudienceMissingError represents an error when JWT audience is missing, but it's required.
type AudienceMissingError struct {
	Claims Claims
}

func (e *AudienceMissingError) Error() string {
	return "JWT audience missing"
}

// AudienceNotExpectedError represents an error when JWT contains not expected audience.
type AudienceNotExpectedError struct {
	Claims   Claims
	Audience jwtgo.ClaimStrings
}

func (e *AudienceNotExpectedError) Error() string {
	return fmt.Sprintf("JWT audience %v not expected", e.Audience)
}
