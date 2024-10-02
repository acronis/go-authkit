# Simple library in Go with primitives for performing authentication and authorization

The library includes the following packages:
+ `auth` (root directory) - provides authentication and authorization primitives for using on the server side.
+ `jwt` - provides parser for JSON Web Tokens (JWT).
+ `jwks` - provides a client for fetching and caching JSON Web Key Sets (JWKS).
+ `idptoken` - provides a client for fetching and caching Access Tokens from Identity Providers (IDP).
+ `idptest` - provides primitives for testing IDP clients.

## Examples

### Authenticating requests with JWT tokens

The `JWTAuthMiddleware` function creates a middleware that authenticates requests with JWT tokens.

It uses the `JWTParser` to parse and validate JWT.
`JWTParser` can verify JWT tokens signed with RSA (RS256, RS384, RS512) algorithms for now.
It performs <issuer_url>/.well-known/openid-configuration request to get the JWKS URL ("jwks_uri" field) and fetches JWKS from there.
For other algorithms `jwt.SignAlgUnknownError` error will be returned.
The `JWTParser` can be created with the `NewJWTParser` function or with the `NewJWTParserWithCachingJWKS` function.
The last one is recommended for production use because it caches public keys (JWKS) that are used for verifying JWT tokens.

See `Config` struct for more customization options.

Example:

```go
package main

import (
	"net/http"

	"github.com/acronis/go-appkit/log"
	"github.com/acronis/go-authkit"
)

func main() {
	jwtConfig := auth.JWTConfig{
		TrustedIssuerURLs: []string{"https://my-idp.com"},
		//TrustedIssuers: map[string]string{"my-idp": "https://my-idp.com"}, // Use TrustedIssuers if you have a custom issuer name.
	}
	jwtParser, _ := auth.NewJWTParserWithCachingJWKS(&auth.Config{JWT: jwtConfig}, log.NewDisabledLogger())
	authN := auth.JWTAuthMiddleware("MyService", jwtParser)

	srvMux := http.NewServeMux()
	srvMux.Handle("/", http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write([]byte("Hello, World!"))
	}))
	srvMux.Handle("/admin", authN(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		//jwtClaims := GetJWTClaimsFromContext(r.Context()) // GetJWTClaimsFromContext is a helper function to get JWT claims from context.
		_, _ = rw.Write([]byte("Hello, admin!"))
	})))
	
	_ = http.ListenAndServe(":8080", srvMux)
}	
```

```shell
$ curl -w "\nHTTP code: %{http_code}\n" localhost:8080
Hello, World!
HTTP code: 200

$ curl -w "\nHTTP code: %{http_code}\n" localhost:8080/admin
{"error":{"domain":"MyService","code":"bearerTokenMissing","message":"Authorization bearer token is missing."}}
HTTP code: 401
```

### Authorizing requests with JWT tokens

```go
package main

import (
	"net/http"

	"github.com/acronis/go-appkit/log"
	"github.com/acronis/go-authkit"
)

func main() {
	jwtConfig := auth.JWTConfig{TrustedIssuers: map[string]string{"my-idp": idpURL}}
	jwtParser, _ := auth.NewJWTParserWithCachingJWKS(&auth.Config{JWT: jwtConfig}, log.NewDisabledLogger())
	authOnlyAdmin := auth.JWTAuthMiddlewareWithVerifyAccess("MyService", jwtParser,
		auth.NewVerifyAccessByRolesInJWT(Role{Namespace: "my-service", Name: "admin"}))

	srvMux := http.NewServeMux()
	srvMux.Handle("/", http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write([]byte("Hello, World!"))
	}))
	srvMux.Handle("/admin", authOnlyAdmin(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		_, _ = rw.Write([]byte("Hello, admin!"))
	})))
	
	_ = http.ListenAndServe(":8080", srvMux)
}
```

Please see [example_test.go](./example_test.go) for a full version of the example.

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
	accessToken, err := provider.GetToken()
	if err != nil {
		log.Fatalf("failed to get access token: %v", err)
    }
	// ...
}
```

## License

Copyright © 2024 Acronis International GmbH.

Licensed under [MIT License](./LICENSE).
