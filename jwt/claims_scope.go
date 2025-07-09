/*
Copyright © 2025 Acronis International GmbH.

Released under MIT license.
*/

package jwt

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

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

// Scope is a list of access policies.
type Scope []AccessPolicy

func (s *Scope) UnmarshalJSON(data []byte) error {
	scope, err := decodeScope(data)
	if err != nil {
		return err
	}
	*s = scope
	return nil
}

// ScopeDecoder tries to turn raw JSON into Scope.
type ScopeDecoder func(raw json.RawMessage) (Scope, error)

// ScopeDecodeError represents an error that occurred during scope decoding.
// It contains errors from all tried decoders and the final fallback JSON unmarshal error.
type ScopeDecodeError struct {
	// DecodedErrors contains errors from all custom decoders that were tried.
	DecodedErrors []error

	// UnmarshalError is the error from the final fallback JSON unmarshaling attempt.
	UnmarshalError error
}

func (e *ScopeDecodeError) Error() string {
	var parts []string
	if len(e.DecodedErrors) > 0 {
		decoderErrors := make([]string, len(e.DecodedErrors))
		for i, err := range e.DecodedErrors {
			decoderErrors[i] = err.Error()
		}
		parts = append(parts, fmt.Sprintf("all scope decoders failed: [%s]", strings.Join(decoderErrors, "; ")))
	}
	if e.UnmarshalError != nil {
		parts = append(parts, fmt.Sprintf("fallback error: %s", e.UnmarshalError.Error()))
	}
	return strings.Join(parts, "; ")
}

func (e *ScopeDecodeError) Unwrap() error {
	return e.UnmarshalError
}

var (
	scopeDecodersMu sync.RWMutex
	scopeDecoders   []ScopeDecoder
)

// RegisterScopeDecoder adds new scope decoder with the highest priority.
// This function is thread-safe and typically called during package initialization.
func RegisterScopeDecoder(d ScopeDecoder) {
	scopeDecodersMu.Lock()
	scopeDecoders = append([]ScopeDecoder{d}, scopeDecoders...)
	scopeDecodersMu.Unlock()
}

func decodeScope(raw json.RawMessage) (Scope, error) {
	scopeDecodersMu.RLock()
	decs := scopeDecoders
	scopeDecodersMu.RUnlock()

	var decoderErrors []error
	for _, d := range decs {
		scope, err := d(raw)
		if err == nil {
			return scope, nil
		}
		decoderErrors = append(decoderErrors, err)
	}

	var policies []AccessPolicy
	err := json.Unmarshal(raw, &policies)
	if err != nil && len(decoderErrors) > 0 {
		return nil, &ScopeDecodeError{DecodedErrors: decoderErrors, UnmarshalError: err}
	}
	return policies, err
}
