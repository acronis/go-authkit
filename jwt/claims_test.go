/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package jwt_test

import (
	"testing"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/acronis/go-authkit/jwt"
)

func TestDefaultClaims_ApplyScopeFilter(t *testing.T) {
	tests := []struct {
		name          string
		claims        jwt.DefaultClaims
		filter        jwt.ScopeFilter
		expectedScope jwt.Scope
	}{
		{
			name: "no filter",
			claims: jwt.DefaultClaims{
				Scope: jwt.Scope{
					{ResourceNamespace: "namespace1"},
					{ResourceNamespace: "namespace2"},
				},
			},
			filter: nil,
			expectedScope: jwt.Scope{
				{ResourceNamespace: "namespace1"},
				{ResourceNamespace: "namespace2"},
			},
		},
		{
			name: "filter matches all",
			claims: jwt.DefaultClaims{
				Scope: jwt.Scope{
					{ResourceNamespace: "namespace1"},
					{ResourceNamespace: "namespace2"},
				},
			},
			filter: jwt.ScopeFilter{
				{ResourceNamespace: "namespace1"},
				{ResourceNamespace: "namespace2"},
			},
			expectedScope: jwt.Scope{
				{ResourceNamespace: "namespace1"},
				{ResourceNamespace: "namespace2"},
			},
		},
		{
			name: "filter matches some",
			claims: jwt.DefaultClaims{
				Scope: jwt.Scope{
					{ResourceNamespace: "namespace1"},
					{ResourceNamespace: "namespace2"},
				},
			},
			filter: jwt.ScopeFilter{
				{ResourceNamespace: "namespace1"},
			},
			expectedScope: jwt.Scope{
				{ResourceNamespace: "namespace1"},
			},
		},
		{
			name: "filter matches none",
			claims: jwt.DefaultClaims{
				Scope: jwt.Scope{
					{ResourceNamespace: "namespace1"},
					{ResourceNamespace: "namespace2"},
				},
			},
			filter: jwt.ScopeFilter{
				{ResourceNamespace: "namespace3"},
			},
			expectedScope: jwt.Scope{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.claims.ApplyScopeFilter(tt.filter)
			require.Equal(t, tt.expectedScope, tt.claims.Scope)
		})
	}
}

func TestDefaultClaims_Clone(t *testing.T) {
	tests := []struct {
		name   string
		claims jwt.DefaultClaims
	}{
		{
			name:   "empty claims",
			claims: jwt.DefaultClaims{},
		},
		{
			name: "claims with jwt.Scope",
			claims: jwt.DefaultClaims{
				Scope: jwt.Scope{
					{ResourceNamespace: "namespace1"},
					{ResourceNamespace: "namespace2"},
				},
			},
		},
		{
			name: "claims with registered fields",
			claims: jwt.DefaultClaims{
				RegisteredClaims: jwtgo.RegisteredClaims{
					Issuer:    "issuer",
					Subject:   "subject",
					Audience:  []string{"audience1", "audience2"},
					ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Hour)),
					NotBefore: jwtgo.NewNumericDate(time.Now().Add(-time.Hour)),
					IssuedAt:  jwtgo.NewNumericDate(time.Now()),
					ID:        "id",
				},
			},
		},
		{
			name: "claims with all fields",
			claims: jwt.DefaultClaims{
				RegisteredClaims: jwtgo.RegisteredClaims{
					Issuer:    "issuer",
					Subject:   "subject",
					Audience:  []string{"audience1", "audience2"},
					ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Hour)),
					NotBefore: jwtgo.NewNumericDate(time.Now().Add(-time.Hour)),
					IssuedAt:  jwtgo.NewNumericDate(time.Now()),
					ID:        "id",
				},
				Scope: jwt.Scope{
					{ResourceNamespace: "namespace1"},
					{ResourceNamespace: "namespace2"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clone := tt.claims.Clone().(*jwt.DefaultClaims)
			require.Equal(t, tt.claims, *clone)
			require.NotSame(t, &tt.claims, clone)

			// Modify original claims and ensure clone is not affected
			if len(tt.claims.Scope) > 0 {
				tt.claims.Scope[0].ResourceNamespace = "modified"
				require.NotEqual(t, tt.claims.Scope[0].ResourceNamespace, clone.Scope[0].ResourceNamespace)
			}
			if len(tt.claims.Audience) > 0 {
				tt.claims.Audience[0] = "modified"
				require.NotEqual(t, tt.claims.Audience[0], clone.Audience[0])
			}
			if tt.claims.ExpiresAt != nil {
				tt.claims.ExpiresAt.Time = time.Now().Add(2 * time.Hour)
				require.NotEqual(t, tt.claims.ExpiresAt, clone.ExpiresAt)
			}
		})
	}
}

type CustomClaims struct {
	jwt.DefaultClaims
	CustomField string `json:"custom_field"`
}

func (c *CustomClaims) Clone() jwt.Claims {
	return &CustomClaims{
		DefaultClaims: *c.DefaultClaims.Clone().(*jwt.DefaultClaims),
		CustomField:   c.CustomField,
	}
}
