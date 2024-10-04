/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package authkit

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v5"

	"github.com/acronis/go-authkit/idptest"
	"github.com/acronis/go-authkit/jwt"
)

func ExampleJWTAuthMiddleware() {
	jwtConfig := JWTConfig{
		TrustedIssuerURLs: []string{"https://my-idp.com"},
		//TrustedIssuers: map[string]string{"my-idp": "https://my-idp.com"}, // Use TrustedIssuers if you have a custom issuer name.
	}
	jwtParser, _ := NewJWTParser(&Config{JWT: jwtConfig})
	authN := JWTAuthMiddleware("MyService", jwtParser)

	srvMux := http.NewServeMux()
	srvMux.Handle("/", http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write([]byte("Hello, World!"))
	}))
	srvMux.Handle("/admin", authN(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		//jwtClaims := GetJWTClaimsFromContext(r.Context()) // GetJWTClaimsFromContext is a helper function to get JWT claims from context.
		_, _ = rw.Write([]byte("Hello, admin!"))
	})))

	done := make(chan struct{})
	server := &http.Server{Addr: ":8080", Handler: srvMux}
	go func() {
		defer close(done)
		_ = server.ListenAndServe()
	}()

	time.Sleep(time.Second) // Wait for the server to start.

	client := &http.Client{Timeout: time.Second * 30}

	fmt.Println("GET http://localhost:8080/")
	resp, _ := client.Get("http://localhost:8080/")
	fmt.Println("Status code:", resp.StatusCode)
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	fmt.Println("Body:", string(respBody))

	fmt.Println("------")
	fmt.Println("GET http://localhost:8080/admin without token")
	resp, _ = client.Get("http://localhost:8080/admin")
	fmt.Println("Status code:", resp.StatusCode)
	respBody, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	fmt.Println("Body:", string(respBody))

	fmt.Println("------")
	fmt.Println("GET http://localhost:8080/admin with invalid token")
	req, _ := http.NewRequest(http.MethodGet, "http://localhost:8080/admin", http.NoBody)
	req.Header["Authorization"] = []string{"Bearer invalid-token"}
	resp, _ = client.Do(req)
	fmt.Println("Status code:", resp.StatusCode)
	respBody, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	fmt.Println("Body:", string(respBody))

	_ = server.Shutdown(context.Background())
	<-done

	// Output:
	// GET http://localhost:8080/
	// Status code: 200
	// Body: Hello, World!
	// ------
	// GET http://localhost:8080/admin without token
	// Status code: 401
	// Body: {"error":{"domain":"MyService","code":"bearerTokenMissing","message":"Authorization bearer token is missing."}}
	// ------
	// GET http://localhost:8080/admin with invalid token
	// Status code: 401
	// Body: {"error":{"domain":"MyService","code":"authenticationFailed","message":"Authentication is failed."}}
}

func ExampleJWTAuthMiddlewareWithVerifyAccess() {
	jwksServer := httptest.NewServer(&idptest.JWKSHandler{})
	defer jwksServer.Close()

	issuerConfigServer := httptest.NewServer(&idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL})
	defer issuerConfigServer.Close()

	roUserClaims := &jwt.Claims{
		RegisteredClaims: jwtgo.RegisteredClaims{
			Issuer:    "my-idp",
			ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(2 * time.Hour)),
		},
		Scope: []jwt.AccessPolicy{{ResourceNamespace: "my-service", Role: "read-only-user"}},
	}
	roUserToken := idptest.MustMakeTokenStringSignedWithTestKey(roUserClaims)

	adminClaims := &jwt.Claims{
		RegisteredClaims: jwtgo.RegisteredClaims{
			Issuer:    "my-idp",
			ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(2 * time.Hour)),
		},
		Scope: []jwt.AccessPolicy{{ResourceNamespace: "my-service", Role: "admin"}},
	}
	adminToken := idptest.MustMakeTokenStringSignedWithTestKey(adminClaims)

	jwtConfig := JWTConfig{TrustedIssuers: map[string]string{"my-idp": issuerConfigServer.URL}}
	jwtParser, _ := NewJWTParser(&Config{JWT: jwtConfig})
	authOnlyAdmin := JWTAuthMiddleware("MyService", jwtParser,
		WithJWTAuthMiddlewareVerifyAccess(NewVerifyAccessByRolesInJWT(Role{Namespace: "my-service", Name: "admin"})))

	srvMux := http.NewServeMux()
	srvMux.Handle("/", http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write([]byte("Hello, World!"))
	}))
	srvMux.Handle("/admin", authOnlyAdmin(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		_, _ = rw.Write([]byte("Hello, admin!"))
	})))

	done := make(chan struct{})
	server := &http.Server{Addr: ":8080", Handler: srvMux}
	go func() {
		defer close(done)
		_ = server.ListenAndServe()
	}()

	time.Sleep(time.Second) // Wait for the server to start.

	client := &http.Client{Timeout: time.Second * 30}

	fmt.Println("GET http://localhost:8080/")
	resp, _ := client.Get("http://localhost:8080/")
	fmt.Println("Status code:", resp.StatusCode)
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	fmt.Println("Body:", string(respBody))

	fmt.Println("------")
	fmt.Println("GET http://localhost:8080/admin without token")
	resp, _ = client.Get("http://localhost:8080/admin")
	fmt.Println("Status code:", resp.StatusCode)
	respBody, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	fmt.Println("Body:", string(respBody))

	fmt.Println("------")
	fmt.Println("GET http://localhost:8080/admin with token of read-only user")
	req, _ := http.NewRequest(http.MethodGet, "http://localhost:8080/admin", http.NoBody)
	req.Header["Authorization"] = []string{"Bearer " + roUserToken}
	resp, _ = client.Do(req)
	fmt.Println("Status code:", resp.StatusCode)
	respBody, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	fmt.Println("Body:", string(respBody))

	fmt.Println("------")
	fmt.Println("GET http://localhost:8080/admin with token of admin user")
	req, _ = http.NewRequest(http.MethodGet, "http://localhost:8080/admin", http.NoBody)
	req.Header["Authorization"] = []string{"Bearer " + adminToken}
	resp, _ = client.Do(req)
	fmt.Println("Status code:", resp.StatusCode)
	respBody, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	fmt.Println("Body:", string(respBody))

	_ = server.Shutdown(context.Background())
	<-done

	// Output:
	// GET http://localhost:8080/
	// Status code: 200
	// Body: Hello, World!
	// ------
	// GET http://localhost:8080/admin without token
	// Status code: 401
	// Body: {"error":{"domain":"MyService","code":"bearerTokenMissing","message":"Authorization bearer token is missing."}}
	// ------
	// GET http://localhost:8080/admin with token of read-only user
	// Status code: 403
	// Body: {"error":{"domain":"MyService","code":"authorizationFailed","message":"Authorization is failed."}}
	// ------
	// GET http://localhost:8080/admin with token of admin user
	// Status code: 200
	// Body: Hello, admin!
}
