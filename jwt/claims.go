/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package jwt

import jwtgo "github.com/golang-jwt/jwt/v5"

// Scope is a slice of access policies.
type Scope []AccessPolicy

// Claims is an interface that extends jwt.Claims from the "github.com/golang-jwt/jwt/v5"
// with additional methods for working with access policies.
type Claims interface {
	jwtgo.Claims

	// GetScope returns the scope of the claims as a slice of access policies.
	GetScope() Scope

	// Clone returns a deep copy of the claims.
	Clone() Claims

	// ApplyScopeFilter filters (in-place) the scope of the claims by the specified filter.
	ApplyScopeFilter(filter ScopeFilter)
}

// DefaultClaims is a struct that extends jwt.RegisteredClaims with a custom scope field.
// It may be embedded into custom claims structs if additional fields are required.
type DefaultClaims struct {
	jwtgo.RegisteredClaims
	Scope Scope `json:"scope,omitempty"`
}

// GetScope returns the scope of the DefaultClaims as a slice of access policies.
func (c *DefaultClaims) GetScope() Scope {
	return c.Scope
}

// Clone returns a deep copy of the DefaultClaims.
func (c *DefaultClaims) Clone() Claims {
	newClaims := &DefaultClaims{
		RegisteredClaims: jwtgo.RegisteredClaims{
			Issuer:  c.Issuer,
			Subject: c.Subject,
			ID:      c.ID,
		},
	}
	if len(c.Scope) != 0 {
		newClaims.Scope = make([]AccessPolicy, len(c.Scope))
		copy(newClaims.Scope, c.Scope)
	}
	if len(c.Audience) != 0 {
		newClaims.Audience = make(jwtgo.ClaimStrings, len(c.Audience))
		copy(newClaims.Audience, c.Audience)
	}
	if c.ExpiresAt != nil {
		newClaims.ExpiresAt = jwtgo.NewNumericDate(c.ExpiresAt.Time)
	}
	if c.NotBefore != nil {
		newClaims.NotBefore = jwtgo.NewNumericDate(c.NotBefore.Time)
	}
	if c.IssuedAt != nil {
		newClaims.IssuedAt = jwtgo.NewNumericDate(c.IssuedAt.Time)
	}
	return newClaims
}

// ScopeFilter is a slice of access policy filters.
type ScopeFilter []ScopeFilterAccessPolicy

// ScopeFilterAccessPolicy is a struct that represents a single access policy filter.
type ScopeFilterAccessPolicy struct {
	ResourceNamespace string
}

// ApplyScopeFilter filters (in-place) the scope of the DefaultClaims by the specified filter.
func (c *DefaultClaims) ApplyScopeFilter(filter ScopeFilter) {
	if len(filter) == 0 {
		return
	}
	n := 0
	for j := range c.Scope {
		matched := false
		for k := range filter {
			if c.Scope[j].ResourceNamespace == filter[k].ResourceNamespace {
				matched = true
				break
			}
		}
		if matched {
			c.Scope[n] = c.Scope[j]
			n++
		}
	}
	c.Scope = c.Scope[:n]
}

// AccessPolicy represents a single access policy which specifies access rights to a tenant or resource
// in the scope of a resource server.
type AccessPolicy struct {
	// TenantID is a unique identifier of tenant for which access is granted (if resource is not specified)
	// or which the resource is owned by (if resource is specified).
	TenantID string `json:"tid,omitempty"`

	// TenantUUID is a UUID of tenant for which access is granted (if the resource is not specified)
	// or which the resource is owned by (if the resource is specified).
	TenantUUID string `json:"tuid,omitempty"`

	// ResourceServerID is a unique resource server instance or cluster ID.
	ResourceServerID string `json:"rs,omitempty"`

	// ResourceNamespace is a namespace to which resource belongs within resource server.
	// E.g.: account-server, storage-manager, task-manager, alert-manager, etc.
	ResourceNamespace string `json:"rn,omitempty"`

	// ResourcePath is a unique identifier of or path to a single resource or resource collection
	// in the scope of the resource server and namespace.
	ResourcePath string `json:"rp,omitempty"`

	// Role determines what actions are allowed to be performed on the specified tenant or resource.
	Role string `json:"role,omitempty"`
}
