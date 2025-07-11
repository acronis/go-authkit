# Toolkit for authentication and authorization in Go services

[![GoDoc Widget]][GoDoc]

## Installation

```
go get -u github.com/acronis/go-authkit
```

## Features 

- Authenticate HTTP requests with JWT tokens via middleware that can be configured via YAML/JSON file or environment variables.
- Authorize HTTP requests with JWT tokens by verifying access based on the roles in the JWT claims.
- Fetch and cache JSON Web Key Sets (JWKS) from Identity Providers (IDP).
- Introspect Access Tokens via OAuth 2.0 Token Introspection endpoint.
- Fetch and cache Access Tokens from Identity Providers (IDP).
- Provides primitives for testing authentication and authorization in HTTP services.
- Extensions system for vendor-specific implementations (see [extensions](./extensions) directory), including Acronis-specific JWT claims.
- Pluggable JWT scope decoder architecture for custom scope parsing implementations.

## Authenticate HTTP requests with JWT tokens

`JWTAuthMiddleware()` creates a middleware that authenticates requests with JWT tokens and puts the parsed JWT claims (`jwt.Claims` interface) into the request context.

`jwt.Claims` interface extends the `jwt.Claims` from the `github.com/golang-jwt/jwt/v5` package with additional methods.

Its default implementation `jwt.DefaultClaims` is an extension of the `RegisteredClaims` struct from the `github.com/golang-jwt/jwt/v5` package.
`jwt.DefaultClaims` contains additional `Scope` field that represents a list of access policies.
They are used for authorization in the typical Acronis service, and actually can be used in any other application that performs multi-tenant authorization.

```go
package jwt

import (
	jwtgo "github.com/golang-jwt/jwt/v5"
)

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

// DefaultClaims is a struct that extends jwt.RegisteredClaims with a custom scope field.
// It may be embedded into custom claims structs if additional fields are required.
type DefaultClaims struct {
	jwtgo.RegisteredClaims
	Scope Scope `json:"scope,omitempty"`
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
```

### Custom Scope Decoders

The library supports pluggable JWT scope decoders for custom scope parsing implementations. Use `RegisterScopeDecoder()` to register a custom decoder:

```go
import "github.com/acronis/go-authkit/jwt"

// Register a custom scope decoder
jwt.RegisterScopeDecoder(func(rawScope json.RawMessage) (jwt.Scope, error) {
	// Custom scope parsing logic
	return customScope, nil
})
```

For Acronis-specific scope formats, use the provided decoder from the extensions package:

```go
import "github.com/acronis/go-authkit/extensions/acronisext"

// Register Acronis scope decoder
acronisext.RegisterScopeDecoder()
```

`JWTAuthMiddleware()` function accepts two mandatory arguments: `errorDomain` and `JWTParser`.

The `errorDomain` is usually the name of the service that uses the middleware, and it's goal is distinguishing errors from different services.
It helps to understand where the error occurred and what service caused it. For example, if the "Authorization" HTTP header is missing, the middleware will return 401 with the following response body:
```json
{
  "error": {
    "domain": "MyService",
    "code": "bearerTokenMissing",
    "message": "Authorization bearer token is missing."
  }
}
```

`JWTParser` is used to parse and validate JWT tokens.
It can be constructed with the `NewJWTParser` right from the YAML/JSON configuration or with the specific `jwt.NewParser()`/`jwt.NewCachingParser()` functions (both of them are used in the `NewJWTParser()` under the hood depending on the configuration).
`jwt.CachingParser` uses LRU in-memory cache for the JWT claims to avoid parsing and validating the same token multiple times that can be useful when JWT tokens are large and the service gets a lot of requests from the same client.
`NewJWTParser()` uses `jwks.CachingClient` for fetching and caching JWKS (JSON Web Key Set) that is used for verifying JWT tokens.
This client performs <issuer_url>/.well-known/openid-configuration request to get the JWKS URL ("jwks_uri" field) and fetches JWKS from there.
Issuer should be presented in the trusted list, otherwise the middleware will return HTTP response with 401 status code and log a corresponding error message.

### Authentication middleware example

Example of the HTTP middleware that authenticates requests with JWT tokens can be found [here](./examples/authn-middleware).

## Introspect Access Tokens via the OAuth 2.0 Token Introspection endpoint

Introspection is the process of determining the active state of an access token and the associated metadata.
More information can be found in the [RFC 7662](https://tools.ietf.org/html/rfc7662).

go-authkit provides a way to introspect any kind of access tokens, not only JWT tokens, via the OAuth 2.0 Token Introspection endpoint.
It performs unmarsalling of the response from the endpoint to the `idptoken.IntrospectionResult` struct which contains the `Active` field that indicates whether the token is active or not.
Additionally, it contains the `TokenType` field that specifies the type of the token and the `Claims` field for presenting the token's metadata in the form of JWT claims.

```go
package idptoken

import (
	"github.com/acronis/go-authkit/jwt"
)

type IntrospectionResult struct {
	Active    bool   `json:"active"`
	TokenType string `json:"token_type,omitempty"`
	jwt.Claims
}
```

The Token Introspection endpoint may be configured statically or obtained from the OpenID Connect Discovery response (GET /.well-known/openid-configuration request for the issuer URL).
In case of the static configuration, gRPC could be used instead of HTTP for the introspection request (see [idp_token.proto](./idptoken/idp_token.proto) for details).

`NewTokenIntrospector()` function creates an introspector that can be used to introspect access tokens.

It's a good practice to protect the introspection endpoint itself.
That's why `NewTokenIntrospector()` accepts the Token Provider (`TokenProvider` interface) that is used to get the Access Token (usually from the Identity Provider) to perform the introspection request with it.
Please keep in mind that the Token Provider should return a valid Access Token that has the necessary permissions to perform the introspection request.

Additionally, the `NewTokenIntrospector()` accepts the scope filter for filtering out the unnecessary claims from the introspection response.

### Introspection example

Example of the access token introspection during the HTTP request authentication can be found [here](./examples/token-introspection).

### Fetching and caching Access Tokens from Identity Providers

The `idptoken.Provider` object is used to fetch and cache Access Tokens from Identity Providers (IDP).

Example:

```go
package main

import (
	"log"
	"net/http"
	
    "github.com/acronis/go-authkit/idptoken"
)

func main() {
	// ...
	httpClient := &http.Client{Timeout: 30 * time.Second}
	source := idptoken.Source{
		URL:          idpURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
	provider := idptoken.NewProvider(httpClient, source)
	accessToken, err := provider.GetToken(ctx)
	if err != nil {
		log.Fatalf("failed to get access token: %v", err)
	}
	// ...
}
```

## Extensions

go-authkit provides an extensions system for vendor-specific implementations in the [extensions](./extensions) directory. 

Currently available extensions:
- **acronisext**: Standardized Acronis-specific JWT claims and token introspection structures to ensure consistency across services.

See [extensions/README.md](./extensions/readme.md) for more details about the extensions system.

## License

Copyright © 2025 Acronis International GmbH.

Licensed under [MIT License](./LICENSE).

[GoDoc]: https://pkg.go.dev/github.com/acronis/go-authkit
[GoDoc Widget]: https://godoc.org/github.com/acronis/go-authkit?status.svg
