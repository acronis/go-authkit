/*
Copyright © 2025 Acronis International GmbH.

Released under MIT license.
*/

package acronisext

import (
	"github.com/acronis/go-authkit/jwt"
)

// JWTClaims extends the jwt.DefaultClaims with Acronis-specific fields.
type JWTClaims struct {
	jwt.DefaultClaims

	// Version is the version of the token claims structure.
	Version int `json:"ver,omitempty"`

	// UserID is a unique identifier for the user, valid only for user's access token.
	// Contains empty string if the token was issued not for a regular user (e.g., for a service account).
	UserID string `json:"uid,omitempty"`

	// Represents client's origin, valid for Cyber Application connectors' clients.
	OriginID string `json:"origin,omitempty"`

	// TOTPTime is a timestamp when was the last time user did second factor authentication,
	// valid only for user's access token.
	TOTPTime int64 `json:"totp_time,omitempty"`

	// LoginTOTPTime is a timestamp when the user logged in using TOTP, valid only for user's access token.
	LoginTOTPTime int64 `json:"login_totp_time,omitempty"`

	// SubType identifies the subject type if the token was issued for a service account.
	SubType string `json:"sub_type,omitempty"`

	// ClientID identifies the API client (e.g., service account) that requested the token.
	// Contains empty string if the token was issued for a regular user.
	ClientID string `json:"client_id,omitempty"`

	// OwnerTenantUUID is the UUID of the tenant that own the API client that requested the token.
	// Contains empty string if the token was issued for a regular user.
	OwnerTenantUUID string `json:"owner_tuid,omitempty"`

	// Narrowing contains scoping information to narrow down access.
	Narrowing [][]string `json:"narrowing,omitempty"`
}

var _ jwt.Claims = (*JWTClaims)(nil)

// Clone returns a deep copy of the JWTClaims.
func (c *JWTClaims) Clone() jwt.Claims {
	defaultClaims := c.DefaultClaims.Clone().(*jwt.DefaultClaims)

	newClaims := &JWTClaims{
		DefaultClaims:   *defaultClaims,
		Version:         c.Version,
		UserID:          c.UserID,
		OriginID:        c.OriginID,
		TOTPTime:        c.TOTPTime,
		LoginTOTPTime:   c.LoginTOTPTime,
		SubType:         c.SubType,
		ClientID:        c.ClientID,
		OwnerTenantUUID: c.OwnerTenantUUID,
	}

	if len(c.Narrowing) > 0 {
		newClaims.Narrowing = make([][]string, len(c.Narrowing))
		for i, narrowGroup := range c.Narrowing {
			if len(narrowGroup) > 0 {
				newClaims.Narrowing[i] = make([]string, len(narrowGroup))
				copy(newClaims.Narrowing[i], narrowGroup)
			}
		}
	}

	return newClaims
}
