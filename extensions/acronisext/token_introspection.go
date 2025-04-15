/*
Copyright © 2025 Acronis International GmbH.

Released under MIT license.
*/

package acronisext

import (
	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/jwt"
)

// TokenIntrospectionResult extends the basic token introspection response with Acronis-specific fields.
// It embeds JWTClaims to ensure consistency between JWT claims and introspection results.
type TokenIntrospectionResult struct {
	// Standard introspection fields.
	Active    bool   `json:"active"`
	TokenType string `json:"token_type,omitempty"`

	// Acronis-specific JWT claims.
	JWTClaims
}

func (ir *TokenIntrospectionResult) IsActive() bool {
	return ir.Active
}

func (ir *TokenIntrospectionResult) SetIsActive(active bool) {
	ir.Active = active
}

func (ir *TokenIntrospectionResult) GetTokenType() string {
	return ir.TokenType
}

func (ir *TokenIntrospectionResult) SetTokenType(tokenType string) {
	ir.TokenType = tokenType
}

func (ir *TokenIntrospectionResult) GetClaims() jwt.MutableClaims {
	return &ir.JWTClaims
}

func (ir *TokenIntrospectionResult) Clone() idptoken.IntrospectionResult {
	return &TokenIntrospectionResult{
		Active:    ir.Active,
		TokenType: ir.TokenType,
		JWTClaims: *ir.JWTClaims.Clone().(*JWTClaims),
	}
}
