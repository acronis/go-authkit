/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptest

import (
	"crypto"
	"encoding/json"

	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/mendsley/gojwk"

	"github.com/acronis/go-authkit/idptoken"
)

// SignToken signs token with key.
func SignToken(token *jwtgo.Token, rsaPrivateKey interface{}) (string, error) {
	return token.SignedString(rsaPrivateKey)
}

// MakeTokenStringWithHeader create test signed token with claims and headers.
func MakeTokenStringWithHeader(
	claims jwtgo.Claims, kid string, rsaPrivateKey interface{}, header map[string]interface{},
) (string, error) {
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)
	token.Header["typ"] = idptoken.JWTTypeAccessToken
	token.Header["kid"] = kid
	for k, v := range header {
		token.Header[k] = v
	}
	return SignToken(token, rsaPrivateKey)
}

// MustMakeTokenStringWithHeader create test signed token with claims and headers.
// It panics if error occurs.
func MustMakeTokenStringWithHeader(
	claims jwtgo.Claims, kid string, rsaPrivateKey interface{}, header map[string]interface{},
) string {
	token, err := MakeTokenStringWithHeader(claims, kid, rsaPrivateKey, header)
	if err != nil {
		panic(err)
	}
	return token
}

// MakeTokenString create signed token with claims.
func MakeTokenString(claims jwtgo.Claims, kid string, rsaPrivateKey interface{}) (string, error) {
	return MakeTokenStringWithHeader(claims, kid, rsaPrivateKey, nil)
}

// MustMakeTokenString create signed token with claims.
// It panics if error occurs.
func MustMakeTokenString(claims jwtgo.Claims, kid string, rsaPrivateKey interface{}) string {
	token, err := MakeTokenStringWithHeader(claims, kid, rsaPrivateKey, nil)
	if err != nil {
		panic(err)
	}
	return token
}

// GetTestRSAPrivateKey returns pre-defined RSA private key for testing.
func GetTestRSAPrivateKey() crypto.PrivateKey {
	var privKey gojwk.Key
	_ = json.Unmarshal([]byte(TestPlainPrivateJWK), &privKey)
	rsaPrivKey, _ := privKey.DecodePrivateKey()
	return rsaPrivKey
}

// MakeTokenStringSignedWithTestKey create test token signed with the pre-defined private key (TestKeyID) for testing.
func MakeTokenStringSignedWithTestKey(claims jwtgo.Claims) (string, error) {
	return MakeTokenStringWithHeader(claims, TestKeyID, GetTestRSAPrivateKey(), nil)
}

// MustMakeTokenStringSignedWithTestKey create test token signed
// with the pre-defined private key (TestKeyID) for testing.
// It panics if error occurs.
func MustMakeTokenStringSignedWithTestKey(claims jwtgo.Claims) string {
	token, err := MakeTokenStringSignedWithTestKey(claims)
	if err != nil {
		panic(err)
	}
	return token
}
