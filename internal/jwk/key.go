/*
Copyright © 2025 Acronis International GmbH.

Released under MIT license.
*/

// Package jwk provides JSON Web Key (JWK) structure and methods to decode it to public and private keys.
package jwk

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

const typeRSA = "RSA"

var supportedKeyTypes = map[string]struct{}{
	typeRSA: {},
}

// Key defines JSON Web Key structure.
type Key struct {
	Alg string `json:"alg"`           // algorithm
	Crv string `json:"crv,omitempty"` // curve - for EC keys
	D   string `json:"d"`             // private exponent
	DP  string `json:"dp"`            // d mod (p-1)
	DQ  string `json:"dq"`            // d mod (p-1)
	E   string `json:"e"`             // public exponent
	K   string `json:"k,omitempty"`   // symmetric key
	Kid string `json:"kid"`           // Key ID
	Kty string `json:"kty"`           // Key Type
	N   string `json:"n"`             // modulus
	P   string `json:"p"`             // prime factor 1
	Q   string `json:"q"`             // prime factor 2
	QI  string `json:"qi"`            // q^(-1) mod p
	Use string `json:"use"`
	X   string `json:"x,omitempty"` // x coordinate - for EC keys
	Y   string `json:"y,omitempty"` // y coordinate - for EC keys
}

// DecodePublicKey decodes Key to public key.
func (j *Key) DecodePublicKey() (crypto.PublicKey, error) {
	if _, ok := supportedKeyTypes[j.Kty]; !ok {
		return nil, fmt.Errorf("unsupported key type %s", j.Kty)
	}

	var result interface{}

	if j.Kty == typeRSA {
		if j.N == "" || j.E == "" {
			return nil, errors.New("malformed JWK RSA key: missing N or E")
		}

		e, err := decodeBase64URLToBigInt(j.E)
		if err != nil {
			return nil, errors.New("malformed JWK RSA key")
		}
		eBytes := e.Bytes()
		if len(eBytes) < 4 {
			ndata := make([]byte, 4)
			copy(ndata[4-len(eBytes):], eBytes)
			eBytes = ndata
		}

		pubKey := &rsa.PublicKey{
			N: &big.Int{},
			E: int(binary.BigEndian.Uint32(eBytes)),
		}

		n, err := decodeBase64URLToBigInt(j.N)
		if err != nil {
			return nil, errors.New("malformed JWK RSA key")
		}
		pubKey.N = n

		result = pubKey
	}

	return result, nil
}

// DecodePrivateKey decodes Key to private key.
func (j *Key) DecodePrivateKey() (crypto.PrivateKey, error) {
	if _, ok := supportedKeyTypes[j.Kty]; !ok {
		return nil, fmt.Errorf("unsupported key type %s", j.Kty)
	}

	var result interface{}
	var err error

	if j.Kty == typeRSA {
		if j.D == "" {
			return nil, errors.New("malformed JWK RSA private exponent")
		}

		// Decode base64url-encoded Key components
		components := []string{j.N, j.E, j.D, j.P, j.Q, j.DP, j.DQ, j.QI}
		decodedComponents := make([]*big.Int, len(components))

		for i, component := range components {
			decodedComponents[i], err = decodeBase64URLToBigInt(component)
			if err != nil {
				return nil, fmt.Errorf("malformed Key RSA component: %w", err)
			}
		}

		n := decodedComponents[0]
		e := decodedComponents[1]
		d := decodedComponents[2]
		p := decodedComponents[3]
		q := decodedComponents[4]
		dp := decodedComponents[5]
		dq := decodedComponents[6]
		qi := decodedComponents[7]

		// Convert Key to *rsa.PrivateKey.
		rsaPrivateKey := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: n,
				E: int(e.Int64()),
			},
			D:      d,
			Primes: []*big.Int{p, q},
			Precomputed: rsa.PrecomputedValues{
				Dp:   dp,
				Dq:   dq,
				Qinv: qi,
			},
		}

		rsaPrivateKey.Precompute()

		err = rsaPrivateKey.Validate()
		if err != nil {
			return nil, fmt.Errorf("invalid RSA private key: %w", err)
		}

		result = rsaPrivateKey
	}

	return result, err
}

// decodeBase64URLToBigInt is a helper function to decode base64url without padding.
func decodeBase64URLToBigInt(encoded string) (*big.Int, error) {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64url: %w", err)
	}
	return new(big.Int).SetBytes(data), nil
}
