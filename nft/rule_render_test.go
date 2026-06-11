package nft

// Tests for the human-readable rule renderer through the netlink-free
// ruleToHumanReadableWithSets seam (the caller supplies the table's sets, so
// no CAP_NET_ADMIN is needed). Token-level assertions, matching the loose
// style of the integration suite — the exact format may drift, the
// expression class must not.

import (
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func TestRuleToHumanReadableWithSets(t *testing.T) {
	tests := []struct {
		name   string
		exprs  []expr.Any
		sets   []*nftables.Set
		tokens []string
	}{
		{
			name: "ct state",
			exprs: []expr.Any{
				&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x02, 0x00, 0x00, 0x00}},
			},
			tokens: []string{"ct state"},
		},
		{
			name: "tcp dport via meta l4proto",
			exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
				&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 22}},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
			tokens: []string{"tcp", "dport", "22", "accept"},
		},
		{
			name: "ip saddr",
			exprs: []expr.Any{
				&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{10, 0, 0, 5}},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
			tokens: []string{"saddr", "10.0.0.5", "drop"},
		},
		{
			name:   "jump verdict",
			exprs:  []expr.Any{&expr.Verdict{Kind: expr.VerdictJump, Chain: "dispatch"}},
			tokens: []string{"jump", "dispatch"},
		},
		{
			name:   "masquerade",
			exprs:  []expr.Any{&expr.Masq{}},
			tokens: []string{"masquerade"},
		},
		{
			name: "named set lookup",
			exprs: []expr.Any{
				&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
				&expr.Lookup{SourceRegister: 1, SetName: "__nftui_test_set__"},
			},
			sets:   []*nftables.Set{{Name: "__nftui_test_set__", ID: 0}},
			tokens: []string{"@__nftui_test_set__"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &nftables.Rule{Exprs: tt.exprs}
			got := ruleToHumanReadableWithSets(rule, tt.sets)
			for _, token := range tt.tokens {
				if !strings.Contains(got, token) {
					t.Errorf("rendered %q does not contain %q", got, token)
				}
			}
		})
	}
}

// The public wrapper fetches sets over netlink first; in a unit-test
// environment that fails (EPERM unprivileged / ENOENT for the synthetic
// table as root) and must surface as the error text — never a hang or panic.
func TestRuleToHumanReadable_Terminates(t *testing.T) {
	rule := &nftables.Rule{
		Table: &nftables.Table{Name: "nftui_render_unit_test", Family: nftables.TableFamilyIPv4},
		Exprs: []expr.Any{&expr.Counter{}},
	}
	if got := RuleToHumanReadable(rule); got == "" {
		t.Error("RuleToHumanReadable returned an empty string")
	}
}
