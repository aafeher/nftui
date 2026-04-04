package nft

import (
	"testing"

	"github.com/google/nftables"
)

func TestChainHookNumToString(t *testing.T) {
	tests := []struct {
		hook nftables.ChainHook
		want string
	}{
		{*nftables.ChainHookPrerouting, "prerouting"},
		{*nftables.ChainHookInput, "input"},
		{*nftables.ChainHookForward, "forward"},
		{*nftables.ChainHookOutput, "output"},
		{*nftables.ChainHookPostrouting, "postrouting"},
		// Ingress=0 and Egress=1 overlap with Prerouting/Input numerically;
		// ChainHookNumToString cannot distinguish them by value alone.
		{nftables.ChainHook(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := ChainHookNumToString(tt.hook)
			if got != tt.want {
				t.Errorf("ChainHookNumToString(%d) = %q, want %q", tt.hook, got, tt.want)
			}
		})
	}
}

func TestChainPolicyToString(t *testing.T) {
	drop := nftables.ChainPolicyDrop
	accept := nftables.ChainPolicyAccept

	tests := []struct {
		policy nftables.ChainPolicy
		want   string
	}{
		{drop, "drop"},
		{accept, "accept"},
		{nftables.ChainPolicy(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := ChainPolicyToString(tt.policy)
			if got != tt.want {
				t.Errorf("ChainPolicyToString(%d) = %q, want %q", tt.policy, got, tt.want)
			}
		})
	}
}
