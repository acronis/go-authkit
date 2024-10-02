/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
)

// TestKeyID is a key ID of the pre-defined key for testing.
const TestKeyID = "fac01c070cd08ba08809762da6e4f74af14e4790"

// TestPlainPrivateJWK is a plaintext representation of the pre-defined private key for testing.
// nolint: lll
const TestPlainPrivateJWK = `
{
  "alg": "RS256",
  "d": "U4iZRcf35HT68wCF4cXPvOCU-aHbHoxkb99okPIf_pyexcznb3AjJCS9PRW3MnR1UkcDJ509Cwq7HTZ6dSPO8bMagGlFR4PttNgYzRg793r7ZamhzjPy_Udr35a79z6Q3rLBzeyFljhZ708cgU-tYw_7KpPytPN9cvr9MuvHtRWZlYuFRIql0PiOkq9hLMz_rLGb2rEmlQ9Bxk0tAOct9et-k8qgqwUjd0APgyHRxBU3gKUcbwgIb4KjYzypVjAW8Y3eIN8DwJg8P9AsMWdyKLW36exN_jZXGq6HrdecqV5hOGRELQ3Ok4sn-XMEyYVu9urQkZIRHGsbvUdwXskYKQ",
  "dp": "jzn3HUi8J7QJF0JIT1VRbX8ngf4c7EDpV76rjTjdDNgGQJF6RZ34DfZoSWJlnoS2aJl2LW_Z2dXUnSi2JzVK_joEmFtMCe6vEiYKl3_2Avw43wfSJ1Kj7CTAOlRiifzdP9RosoYgznLjKq9_WyKlFVy7jXN11f-SBjiwYGyn_FM",
  "dq": "pV6go3sp23q7jJP0DMrY0fmrC3AhWTGB3hb9w_KKVDV_J1ljSCpkSB55FfHkCsiTFfBHieCThNl7iWgl0eZJ7TtsdVUSj_dZfAMfi49nj6GBa5mjEUMSGgtUrqWNWf31rKKXz4Y4o0A6U8N8FuX34ANCj9hEBE0UIzdV_e7L1AE",
  "e": "AQAB",
  "kid": "fac01c070cd08ba08809762da6e4f74af14e4790",
  "kty": "RSA",
  "n": "mWeDDhcnVdKWbYGubOB7v1rZ395noYk-MFV0Ik78nLsJc1Ni3-GaWpJOTfCFivDP6DcS68Q04olx6_CleaDWU2KHeZE9PuJcW1_Xot3w1U2WZYpzl5_E5jqHjq1-nnOfe5Mq5SbpoZi3o3-QjktiSgaZ6w-575anM-6VhfxyS0s_DKGJHzyka1hJIoGb8vBstKS6oVLcgjQO3JR_Uy4XMdO9s3z-t3_4sO7qtHuEmqFUnaUx5MuLmZnV0hWyLHoNtEQZrf6X5lcnSj-6QerRihJdQeFDm494D96UwjKt70xgbAMvY-H2RcCJ5IqB2jvumqACt70twX7VCeS8FDMP_w",
  "p": "w7rqemF-CmOU2X4p_4yzZaVq5CYmq9f-d1QLfK9AdMhIAPAlGxIkevXq6dAnjLWLJ9ksuOFkjWpoNI40JyhPJqif8U8WFyDqMsAEFif4HYVh-iR3NMr489lExBqx-YmmYHJ-pXxpcQhwAIbUkS-iF4eIx44JwVPNniU97Djy_ws",
  "q": "yKQfjhWZSFzsn1CveQS6X6H1GtIbpWW9WBR0TFyUWrDtBxe1ivv21ie9hMDhpwk9t9ONUXqt-nNDMtK558q_fGKzMDwYIztX5vXRW9MMR6A7gylSGVspsUbk-egE2dXpwaGwdwr1RvFHEjBNeJQWxvQH-g-QNhJQm6gBdzn6210",
  "qi": "Yt33e8KxCstCfgD4MvPg-uTVj6o2f893zbast8b_yunEBZK-c4WnJ73Taj7lOB2iME97XrBsx3f-jdslt6xHd9h0mam_Fi53JxQDoiyPcLWfcgcMY2w4jjoY_-Iqtnnisf7tHGgrba9eyNHRl91oXFgoaduNmeUs1z_yF_GARJo",
  "use": "sig"
}
`

type PublicJWK struct {
	Alg string `json:"alg"`
	E   string `json:"e"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	Use string `json:"use"`
}

func GetTestPublicJWKS() []PublicJWK {
	return []PublicJWK{
		{
			Alg: "RS256",
			E:   "AQAB",
			Kid: TestKeyID,
			Kty: "RSA",
			N:   "mWeDDhcnVdKWbYGubOB7v1rZ395noYk-MFV0Ik78nLsJc1Ni3-GaWpJOTfCFivDP6DcS68Q04olx6_CleaDWU2KHeZE9PuJcW1_Xot3w1U2WZYpzl5_E5jqHjq1-nnOfe5Mq5SbpoZi3o3-QjktiSgaZ6w-575anM-6VhfxyS0s_DKGJHzyka1hJIoGb8vBstKS6oVLcgjQO3JR_Uy4XMdO9s3z-t3_4sO7qtHuEmqFUnaUx5MuLmZnV0hWyLHoNtEQZrf6X5lcnSj-6QerRihJdQeFDm494D96UwjKt70xgbAMvY-H2RcCJ5IqB2jvumqACt70twX7VCeS8FDMP_w", // nolint:lll
			Use: "sig",
		},
		{
			Alg: "RS256",
			E:   "AQAB",
			Kid: "737c5114f09b5ed05276bd4b520245982f7fb29f",
			Kty: "RSA",
			N:   "51gGypRFvhTziiCLW3emsFx80G3ljpoYdDdieYM-yfvv6cfpkiEnxRRig5JdJ62vrENgbZi1GZpvTs3B7ly7Z4FI6EM-5e8vIkQSYuE3sXU7QsxEFjtMUm31kao4179gmIIrycHl5M1HE2FU2Ssgf7VuKIVmLvDypNHgBb8cV2XKu_PiGHk2turbKZXxegJTiMBYrgKSaEuBUi3WC3j-onHmQriThchQujmXVMFQ-5syNkUX7hM8PKKONkFUhKANnh0Om8_Sc3bcYZAIoFA2cD-PXopJUQa8GLRfWLExVHRvp-4_vtDYbEAeipPYz2cRmEoMKiLRk8ZpLI6M71ugLQ", // nolint:lll
			Use: "sig",
		},
	}
}

// JWKSHandler is an HTTP handler that responds JWKS.
type JWKSHandler struct {
	servedCount atomic.Uint64
	PublicJWKS  []PublicJWK
}

func (h *JWKSHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(rw, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	h.servedCount.Add(1)

	rw.Header().Set("Content-Type", "application/json")
	publicJWKS := h.PublicJWKS
	if len(publicJWKS) == 0 {
		publicJWKS = GetTestPublicJWKS()
	}
	if err := json.NewEncoder(rw).Encode(PublicJWKSResponse{Keys: publicJWKS}); err != nil {
		http.Error(rw, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

// ServedCount returns the number of times JWKS handler has been served.
func (h *JWKSHandler) ServedCount() uint64 {
	return h.servedCount.Load()
}

type PublicJWKSResponse struct {
	Keys []PublicJWK `json:"keys"`
}
