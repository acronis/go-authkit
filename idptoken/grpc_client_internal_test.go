/*
Copyright © 2025 Acronis International GmbH.

Released under MIT license.
*/

package idptoken

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildGRPCServiceConfig(t *testing.T) {
	tests := []struct {
		name         string
		opts         GRPCClientOpts
		expectedJSON string
		expectEmpty  bool
	}{
		{
			name:         "default options (round_robin)",
			opts:         GRPCClientOpts{},
			expectedJSON: `{"loadBalancingConfig":[{"round_robin":{}}]}`,
		},
		{
			name: "custom load balancing policy (pick_first)",
			opts: GRPCClientOpts{
				LoadBalancingPolicy: GRPCClientLoadBalancingPolicyPickFirst,
			},
			expectedJSON: `{"loadBalancingConfig":[{"pick_first":{}}]}`,
		},
		{
			name: "load balancing disabled",
			opts: GRPCClientOpts{
				DisableLoadBalancing: true,
			},
			expectEmpty: true,
		},
		{
			name: "load balancing disabled overrides policy setting",
			opts: GRPCClientOpts{
				DisableLoadBalancing: true,
				LoadBalancingPolicy:  GRPCClientLoadBalancingPolicyRoundRobin,
			},
			expectEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildGRPCServiceConfig(tt.opts)
			require.NoError(t, err)
			if tt.expectEmpty {
				require.Empty(t, result, "expected empty service config when load balancing is disabled")
				return
			}
			require.NotEmpty(t, result, "expected non-empty service config")
			require.JSONEq(t, tt.expectedJSON, result, "service config JSON should match expected")
			var svcCfg grpcServiceConfig
			require.NoError(t, json.Unmarshal([]byte(result), &svcCfg), "service config JSON should be valid")
			require.NotEmpty(t, svcCfg.LoadBalancingConfig, "load balancing config should not be empty")
		})
	}
}
