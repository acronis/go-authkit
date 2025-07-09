/*
Copyright © 2025 Acronis International GmbH.

Released under MIT license.
*/

package acronisext

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

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

var registerOnce sync.Once

// RegisterScopeDecoder registers the Acronis scope decoder for JWT claims parsing.
// This function is idempotent and safe to call multiple times concurrently.
// Call this function to enable Acronis-specific scope format support.
func RegisterScopeDecoder() {
	registerOnce.Do(func() {
		jwt.RegisterScopeDecoder(ScopeDecoder)
	})
}

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

// ScopeDecoder is a custom decoder that handles Acronis URN format scopes.
// It supports both array of URN strings and single space-delimited URN string formats.
func ScopeDecoder(raw json.RawMessage) (jwt.Scope, error) {
	if len(raw) == 0 {
		return nil, errors.New("acronis scope decoder: empty JSON")
	}
	switch raw[0] {
	case '[': // array of strings
		var policyStrs []string
		if err := json.Unmarshal(raw, &policyStrs); err != nil {
			return nil, err
		}
		scope := make(jwt.Scope, 0, len(policyStrs))
		for _, policyStr := range policyStrs {
			policy, err := ParseAccessPolicyURN(policyStr)
			if err != nil {
				return nil, err
			}
			scope = append(scope, policy)
		}
		return scope, nil

	case '"': // single space-delimited string
		var str string
		if err := json.Unmarshal(raw, &str); err != nil {
			return nil, err
		}
		policyStrs := strings.Fields(str)
		scope := make(jwt.Scope, 0, len(policyStrs))
		for _, policyStr := range policyStrs {
			policy, err := ParseAccessPolicyURN(policyStr)
			if err != nil {
				return nil, err
			}
			scope = append(scope, policy)
		}
		return scope, nil

	default:
		return nil, errors.New("acronis scope decoder: unsupported JSON")
	}
}

const accessPolicyURNPrefix = "urn:acronis:"

// ParseAccessPolicyURN parses an Acronis URN string into an AccessPolicy struct.
// Expected format: urn:acronis:resource_server:resource_namespace:resource:role
// where resource is a tenant ID and optionally a resource path, separated by '|'.
//
// EXPERIMENTAL: This function is experimental and the format of the Acronis URN
// may be changed in the future. Use with caution in production code.
func ParseAccessPolicyURN(s string) (jwt.AccessPolicy, error) {
	if !strings.HasPrefix(s, accessPolicyURNPrefix) {
		return jwt.AccessPolicy{}, errors.New("not an acronis URN")
	}
	s = s[len(accessPolicyURNPrefix):]

	resourceServerIdx := strings.IndexByte(s, ':')
	if resourceServerIdx < 0 {
		return jwt.AccessPolicy{}, errors.New("invalid URN format, missing resource server")
	}
	resourceServer := s[:resourceServerIdx]
	s = s[resourceServerIdx+1:]

	resourceNamespaceIdx := strings.IndexByte(s, ':')
	if resourceNamespaceIdx < 0 {
		return jwt.AccessPolicy{}, errors.New("invalid URN format, missing resource namespace")
	}
	resourceNamespace := s[:resourceNamespaceIdx]
	s = s[resourceNamespaceIdx+1:]

	resourceIdx := strings.IndexByte(s, ':')
	if resourceIdx < 0 {
		return jwt.AccessPolicy{}, errors.New("invalid URN format, missing resource")
	}
	resource := s[:resourceIdx]
	s = s[resourceIdx+1:]

	tenantID := resource
	var resourcePath string
	if resourcePathIdx := strings.IndexByte(resource, '|'); resourcePathIdx >= 0 {
		tenantID = resource[:resourcePathIdx]
		resourcePath = resource[resourcePathIdx+1:]
	}

	role := s
	if role == "" {
		return jwt.AccessPolicy{}, errors.New("invalid URN format, missing role")
	}

	// Check for extra colons that would indicate unexpected trailing data
	if strings.Contains(role, ":") {
		return jwt.AccessPolicy{}, fmt.Errorf("invalid URN format, unexpected trailing data: %q", role)
	}

	return jwt.AccessPolicy{
		TenantUUID:        tenantID,
		ResourceServerID:  resourceServer,
		ResourceNamespace: resourceNamespace,
		ResourcePath:      resourcePath,
		Role:              role,
	}, nil
}
