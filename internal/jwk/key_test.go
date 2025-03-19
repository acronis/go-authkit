package jwk_test

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/acronis/go-authkit/internal/jwk"
)

func encodeBigIntToBase64URL(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

func TestDecodePublicKey(t *testing.T) {
	// Define meaningful primes
	p := big.NewInt(61)
	q := big.NewInt(53)

	// Compute modulus n = p * q
	n := new(big.Int).Mul(p, q) // n = 61 × 53 = 3233
	e := big.NewInt(65537)      // common public exponent

	key := &jwk.Key{
		Kty: "RSA",
		N:   encodeBigIntToBase64URL(n),
		E:   encodeBigIntToBase64URL(e),
	}

	pubKey, err := key.DecodePublicKey()
	require.NoError(t, err)
	require.NotNil(t, pubKey)
	require.IsType(t, &rsa.PublicKey{}, pubKey)
	require.Equal(t, n, pubKey.(*rsa.PublicKey).N)
	require.Equal(t, int(e.Int64()), pubKey.(*rsa.PublicKey).E)
}

func TestDecodePublicKeyFails(t *testing.T) {
	key := &jwk.Key{
		Kty: "MEOW",
		N:   "invalid",
		E:   "invalid",
	}

	pubKey, err := key.DecodePublicKey()
	require.Error(t, err)
	require.ErrorContains(t, err, "unsupported key type")
	require.Nil(t, pubKey)

	key = &jwk.Key{
		Kty: "RSA",
	}

	pubKey, err = key.DecodePublicKey()
	require.Error(t, err, "N and E are missing")
	require.ErrorContains(t, err, "malformed JWK RSA key")
	require.Nil(t, pubKey)

	key = &jwk.Key{
		Kty: "RSA",
		N:   "invalid",
		E:   "!!invalid!!",
	}

	pubKey, err = key.DecodePublicKey()
	require.Error(t, err, "E is invalid")
	require.ErrorContains(t, err, "malformed JWK RSA key")
	require.Nil(t, pubKey)

	key = &jwk.Key{
		Kty: "RSA",
		N:   "!!invalid!!",
		E:   "invalid",
	}

	pubKey, err = key.DecodePublicKey()
	require.Error(t, err, "N is invalid")
	require.ErrorContains(t, err, "malformed JWK RSA key")
	require.Nil(t, pubKey)
}

func TestDecodePrivateKey(t *testing.T) {
	p := big.NewInt(11)
	q := big.NewInt(13)
	n := new(big.Int).Mul(p, q) // modulus calc: n = p * q

	e := big.NewInt(65537) // Common public exponent
	phi := new(big.Int).Mul(
		new(big.Int).Sub(p, big.NewInt(1)),
		new(big.Int).Sub(q, big.NewInt(1)),
	) // phi(n)

	d := new(big.Int).ModInverse(e, phi) // Compute private exponent
	if d == nil {
		t.Fatal("Failed to compute modular inverse for d")
	}

	dp := new(big.Int).Mod(d, new(big.Int).Sub(p, big.NewInt(1))) // dp = d mod (p-1)
	dq := new(big.Int).Mod(d, new(big.Int).Sub(q, big.NewInt(1))) // dq = d mod (q-1)
	qi := new(big.Int).ModInverse(q, p)                           // qi = q^(-1) mod p
	if qi == nil {
		t.Fatal("Failed to compute modular inverse for qi")
	}

	key := &jwk.Key{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(n.Bytes()),
		E:   encodeBigIntToBase64URL(e),
		D:   encodeBigIntToBase64URL(d),
		P:   base64.RawURLEncoding.EncodeToString(p.Bytes()),
		Q:   base64.RawURLEncoding.EncodeToString(q.Bytes()),
		DP:  encodeBigIntToBase64URL(dp),
		DQ:  encodeBigIntToBase64URL(dq),
		QI:  encodeBigIntToBase64URL(qi),
	}

	privKey, err := key.DecodePrivateKey()
	require.NoError(t, err)
	require.NotNil(t, privKey)
	require.IsType(t, &rsa.PrivateKey{}, privKey)
	require.Equal(t, n, privKey.(*rsa.PrivateKey).PublicKey.N)
	require.Equal(t, int(e.Int64()), privKey.(*rsa.PrivateKey).PublicKey.E)
}

func TestDecodePrivateKeyFails(t *testing.T) {
	key := &jwk.Key{
		Kty: "MEOW",
	}

	privKey, err := key.DecodePrivateKey()
	require.Error(t, err, "unsupported key type")
	require.ErrorContains(t, err, "unsupported key type")
	require.Nil(t, privKey)

	n := big.NewInt(111) // bad modulus, not a mul of p and q

	key = &jwk.Key{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(n.Bytes()),
		P:   base64.RawURLEncoding.EncodeToString(big.NewInt(11).Bytes()),
		Q:   base64.RawURLEncoding.EncodeToString(big.NewInt(13).Bytes()),
	}

	privKey, err = key.DecodePrivateKey()
	require.Error(t, err, "bad modulus triggers crypto error")
	require.ErrorContains(t, err, "malformed JWK RSA private exponent")
	require.Nil(t, privKey)

	key = &jwk.Key{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(n.Bytes()),
		P:   base64.RawURLEncoding.EncodeToString(big.NewInt(11).Bytes()),
		Q:   base64.RawURLEncoding.EncodeToString(big.NewInt(13).Bytes()),
		D:   "!!invalid!!",
	}

	privKey, err = key.DecodePrivateKey()
	require.Error(t, err, "malformed D")
	require.ErrorContains(t, err, "malformed Key RSA component")
	require.Nil(t, privKey)

	key = &jwk.Key{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(n.Bytes()),
		P:   base64.RawURLEncoding.EncodeToString(big.NewInt(11).Bytes()),
		Q:   base64.RawURLEncoding.EncodeToString(big.NewInt(13).Bytes()),
		D:   "asdasd",
	}

	privKey, err = key.DecodePrivateKey()
	require.Error(t, err, "exported D is not a valid base64url")
	if goVersion := runtime.Version(); goVersion >= "go1.24" {
		require.ErrorContains(t, err, "input overflows the modulus")
	} else {
		require.ErrorContains(t, err, "public exponent too small")
	}
	require.Nil(t, privKey)
}
