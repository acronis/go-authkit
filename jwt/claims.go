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

	// GetID returns the JTI field of the claims.
	GetID() string

	// GetScope returns the scope of the claims as a slice of access policies.
	GetScope() Scope

	// Clone returns a deep copy of the claims.
	Clone() Claims

	// ApplyScopeFilter filters (in-place) the scope of the claims by the specified filter.
	ApplyScopeFilter(filter ScopeFilter)
}

// MutableClaims is an interface that extends Claims with methods for modifying the claims.
// It is used for creating new claims with modified values.
type MutableClaims interface {
	Claims

	// SetID sets the JTI field of the claims.
	SetID(jti string)

	// SetScope sets the scope of the claims.
	SetScope(scope Scope)

	// SetExpirationTime sets the expiration time of the claims.
	SetExpirationTime(exp *jwtgo.NumericDate)

	// SetIssuedAt sets the issued at time of the claims.
	SetIssuedAt(iat *jwtgo.NumericDate)

	// SetNotBefore sets the not before time of the claims.
	SetNotBefore(nbf *jwtgo.NumericDate)

	// SetIssuer sets the issuer of the claims.
	SetIssuer(iss string)

	// SetSubject sets the subject of the claims.
	SetSubject(sub string)

	// SetAudience sets the audience of the claims.
	SetAudience(aud jwtgo.ClaimStrings)
}

// DefaultClaims is a struct that extends jwt.RegisteredClaims with a custom scope field.
// It may be embedded into custom claims structs if additional fields are required.
type DefaultClaims struct {
	jwtgo.RegisteredClaims
	Scope Scope `json:"scope,omitempty"`
}

// GetID returns the JTI field of the DefaultClaims.
func (c *DefaultClaims) GetID() string {
	return c.ID
}

// SetID sets the JTI field of the DefaultClaims.
func (c *DefaultClaims) SetID(jti string) {
	c.ID = jti
}

// GetScope returns the scope of the DefaultClaims as a slice of access policies.
func (c *DefaultClaims) GetScope() Scope {
	return c.Scope
}

// SetScope sets the scope of the DefaultClaims.
func (c *DefaultClaims) SetScope(scope Scope) {
	c.Scope = scope
}

// SetExpirationTime sets the expiration time of the DefaultClaims.
func (c *DefaultClaims) SetExpirationTime(exp *jwtgo.NumericDate) {
	c.ExpiresAt = exp
}

// SetIssuedAt sets the issued at time of the DefaultClaims.
func (c *DefaultClaims) SetIssuedAt(iat *jwtgo.NumericDate) {
	c.IssuedAt = iat
}

// SetNotBefore sets the not before time of the DefaultClaims.
func (c *DefaultClaims) SetNotBefore(nbf *jwtgo.NumericDate) {
	c.NotBefore = nbf
}

// SetIssuer sets the issuer of the DefaultClaims.
func (c *DefaultClaims) SetIssuer(iss string) {
	c.Issuer = iss
}

// SetSubject sets the subject of the DefaultClaims.
func (c *DefaultClaims) SetSubject(sub string) {
	c.Subject = sub
}

// SetAudience sets the audience of the DefaultClaims.
func (c *DefaultClaims) SetAudience(aud jwtgo.ClaimStrings) {
	c.Audience = aud
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
