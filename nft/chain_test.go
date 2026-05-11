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

func TestExtractChainRules(t *testing.T) {
	tests := []struct {
		name      string
		dump      string
		chainName string
		want      []string
		wantErr   bool
	}{
		{
			name: "chain with header+policy and three rules",
			dump: `table ip filter {
	chain input {
		type filter hook input priority 0; policy accept;
		ct state established,related accept
		iif "lo" accept
		drop
	}
}
`,
			chainName: "input",
			want: []string{
				"ct state established,related accept",
				`iif "lo" accept`,
				"drop",
			},
		},
		{
			name: "chain with separate policy line and a set-based rule",
			dump: `table ip filter {
	chain forward {
		type filter hook forward priority 0;
		policy accept;
		tcp dport { 22, 80, 443 } accept
	}
}
`,
			chainName: "forward",
			want: []string{
				"tcp dport { 22, 80, 443 } accept",
			},
		},
		{
			name: "empty chain",
			dump: `table ip filter {
	chain output {
		type filter hook output priority 0; policy accept;
	}
}
`,
			chainName: "output",
			want:      nil,
		},
		{
			name:      "chain not present in dump",
			dump:      "table ip filter {\n\tchain output {\n\t}\n}\n",
			chainName: "input",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractChainRules(tt.dump, tt.chainName)
			if (err != nil) != tt.wantErr {
				t.Fatalf("extractChainRules err = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d rules, want %d.\nGot: %#v\nWant: %#v", len(got), len(tt.want), got, tt.want)
			}
			for i, r := range got {
				if r != tt.want[i] {
					t.Errorf("rule %d: got %q, want %q", i, r, tt.want[i])
				}
			}
		})
	}
}
