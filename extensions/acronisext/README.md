# Acronis Extensions for go-authkit

This package provides Acronis-specific extensions for the go-authkit library, including:

1. Custom JWT claims that extend the standard `jwt.DefaultClaims`
2. Token introspection result structure for Acronis-specific claims

## Purpose

The `acronisext` package aims to standardize JWT claims across Acronis services and integration developers. Instead of defining custom claim structures, it would be better to use these official Acronis-specific claim extensions to ensure consistency and interoperability.

If you need additional fields not covered by `acronisext.JWTClaims`, consider proposing additions to this package rather than creating service-specific extensions

## JWT Claims

The package defines a `JWTClaims` struct that extends `jwt.DefaultClaims` with Acronis-specific fields:

```go
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
```

## Token Introspection Result

The package provides a `TokenIntrospectionResult` structure that embeds `JWTClaims` and adds fields specific to token introspection:

```go
type TokenIntrospectionResult struct {
    // Standard introspection fields.
    Active    bool      `json:"active"`
    TokenType string    `json:"token_type,omitempty"`

    // Acronis-specific JWT claims.
    JWTClaims
}
```

## Usage Guidelines

1. When creating JWT tokens with Acronis-specific claims, use the `JWTClaims` struct:
   ```go
   claims := &acronisext.JWTClaims{
       DefaultClaims: jwt.DefaultClaims{
           RegisteredClaims: jwtgo.RegisteredClaims{
               Issuer: "https://eu8-cloud.acronis.com",
               Subject: "6a54e7c0-5760-4ed4-b97a-bd2472f79612",
           },
       },
       Version: 2,
       ClientID: "6a54e7c0-5760-4ed4-b97a-bd2472f79612",
       SubType: "task_manager",
   }
   ```

2. When parsing tokens, use the `jwt.NewParserWithOpts` function with specifying `ParserOpts.ClaimsTemplate: &acronisext.JWTClaims{}`:
   ```go
   parser := jwt.NewParserWithOpts(keysProvider, jwt.ParserOpts{
       ClaimsTemplate: &acronisext.JWTClaims{},
   })
   ```
   or `authkit.NewJWTParser` with passing `authkit.WithJWTParserClaimsTemplate(&acronisext.JWTClaims{})` variadic option for constructing the parser from the `authkit.Config`:
   ```go
   parser, err := auth.NewJWTParser(cfg,
       authkit.WithJWTParserClaimsTemplate(&acronisext.JWTClaims{}))
   ```
   
3. For token introspection, use the `idptoken.NewIntrospectorWithOpts` function with specifying `IntrospectorOpts.ResultTemplate: &acronisext.TokenIntrospectionResult{}`:
   ```go
   introspector, err := idptoken.NewIntrospectorWithOpts(accessTokenProvider, idptoken.IntrospectorOpts{
       ResultTemplate: &acronisext.TokenIntrospectionResult{},
   })
   ```
    or `authkit.NewTokenIntrospector` with passing `authkit.WithTokenIntrospectorResultTemplate(&acronisext.TokenIntrospectionResult{})` variadic option for constructing the introspector from the `authkit.Config`:
    ```go
    introspector, err := auth.NewTokenIntrospector(cfg, tokenProvider, scopeFilter,
        authkit.WithTokenIntrospectorResultTemplate(&acronisext.TokenIntrospectionResult{}))
    ```
