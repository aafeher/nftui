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
			name: "ip6 saddr (offset 8, len 16)",
			exprs: []expr.Any{
				&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16, DestRegister: 1},
				// 2001:db8::1
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
			tokens: []string{"ip6", "saddr", "2001:db8::1", "drop"},
		},
		{
			name: "ip6 daddr (offset 24, len 16)",
			exprs: []expr.Any{
				&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16, DestRegister: 1},
				// 2001:db8::2
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
			tokens: []string{"ip6", "daddr", "2001:db8::2", "accept"},
		},
		{
			name: "ip6 saddr CIDR (payload + bitwise + cmp)",
			exprs: []expr.Any{
				&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16, DestRegister: 1},
				// /32 mask over a 16-byte address
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 16,
					Mask: []byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Xor:  make([]byte, 16)},
				// 2001:db8::
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
			tokens: []string{"ip6", "saddr", "2001:db8::/32", "drop"},
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
		{
			name:   "counter",
			exprs:  []expr.Any{&expr.Counter{}},
			tokens: []string{"counter"},
		},
		{
			name:   "objref counter",
			exprs:  []expr.Any{&expr.Objref{Type: 1, Name: "cnt"}},
			tokens: []string{"counter name cnt"},
		},
		{
			name:   "connlimit over",
			exprs:  []expr.Any{&expr.Connlimit{Count: 5, Flags: expr.NFT_CONNLIMIT_F_INV}},
			tokens: []string{"ct count over 5"},
		},
		{
			name: "ct mark equality",
			exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x10, 0x00, 0x00, 0x00}},
			},
			// meta mark is loaded into the register; the Cmp renders it.
			tokens: []string{"mark"},
		},
		{
			name: "udp via meta l4proto",
			exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{17}},
			},
			tokens: []string{"udp"},
		},
		{
			name: "ip saddr CIDR via bitwise",
			exprs: []expr.Any{
				&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4, DestRegister: 1},
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Mask: []byte{255, 255, 255, 0}, Xor: []byte{0, 0, 0, 0}},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{10, 0, 0, 0}},
			},
			tokens: []string{"ip saddr", "10.0.0.0/24"},
		},
		{
			name: "ip saddr set lookup keeps ip qualifier",
			exprs: []expr.Any{
				&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4, DestRegister: 1},
				&expr.Lookup{SourceRegister: 1, SetName: "blocklist"},
			},
			tokens: []string{"ip saddr", "@blocklist"},
		},
		{
			name: "limit",
			exprs: []expr.Any{&expr.Limit{
				Type: expr.LimitTypePkts, Rate: 10, Unit: expr.LimitTimeSecond, Burst: 5,
			}},
			tokens: []string{"limit rate"},
		},
		{
			name: "log prefix and level",
			exprs: []expr.Any{
				&expr.Log{Data: []byte("blocked"), Level: expr.LogLevelWarning},
			},
			tokens: []string{"log", `prefix "blocked"`, "level"},
		},
		{
			name: "dynset add to set",
			exprs: []expr.Any{
				&expr.Dynset{Operation: 0, SetName: "flood"},
			},
			tokens: []string{"add", "@flood"},
		},
		{
			name: "range on unknown register",
			exprs: []expr.Any{
				&expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: []byte{0, 80}, ToData: []byte{0, 90}},
			},
			tokens: []string{"register_1"},
		},
		{
			name:   "unknown expr marker",
			exprs:  []expr.Any{&expr.Byteorder{}},
			tokens: []string{"unknown expr"},
		},
		{
			name: "icmpv6 via meta l4proto",
			exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{58}}, // IPPROTO_ICMPV6
			},
			tokens: []string{"icmpv6"},
		},
		{
			name: "ip saddr CIDR via bitwise, negated",
			exprs: []expr.Any{
				&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4, DestRegister: 1},
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Mask: []byte{255, 255, 255, 0}, Xor: []byte{0, 0, 0, 0}},
				&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{10, 0, 0, 0}},
			},
			tokens: []string{"saddr", "!=", "10.0.0.0/24"},
		},
		{
			name: "ip saddr exact, negated",
			exprs: []expr.Any{
				&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{10, 0, 0, 5}},
			},
			tokens: []string{"saddr", "!=", "10.0.0.5"},
		},
		{
			name: "ip saddr byte-aligned /24 prefix (no bitwise)",
			exprs: []expr.Any{
				&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{10, 0, 0}}, // 3 bytes → /24
			},
			tokens: []string{"saddr", "10.0.0.0/24"},
		},
		{
			name: "ip daddr odd-width falls back to hex",
			exprs: []expr.Any{
				&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1, 2, 3, 4, 5}}, // >4 bytes
			},
			tokens: []string{"daddr", "0x"},
		},
		{
			name: "ip protocol icmp",
			exprs: []expr.Any{
				&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
			},
			tokens: []string{"ip protocol", "icmp"},
		},
		{
			name: "ip protocol tcp",
			exprs: []expr.Any{
				&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
			},
			tokens: []string{"tcp"},
		},
		{
			name: "ip protocol udp",
			exprs: []expr.Any{
				&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{17}},
			},
			tokens: []string{"udp"},
		},
		{
			name: "icmp type echo-request",
			exprs: []expr.Any{
				&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{8}},
			},
			tokens: []string{"icmp type", "echo-request"},
		},
		{
			name: "iif by index",
			exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIF, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 0, 0, 1}},
			},
			tokens: []string{"iif"},
		},
		{
			name:   "log without prefix",
			exprs:  []expr.Any{&expr.Log{}},
			tokens: []string{"log"},
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

// TestRuleToHumanReadableWithSets_TodoArms drives the render arms that are
// currently no-ops (`i++` only) plus the simple action arms, in one rule.
// They contribute no tokens but must be walked without panicking — this pins
// the dispatch so a future implementer's change is caught by coverage.
func TestRuleToHumanReadableWithSets_TodoArms(t *testing.T) {
	rule := &nftables.Rule{
		Exprs: []expr.Any{
			&expr.Immediate{Register: 1, Data: []byte{0, 80}},
			&expr.Redir{},
			&expr.NAT{Type: expr.NATTypeSourceNAT},
			&expr.Quota{Bytes: 100},
			&expr.Exthdr{Type: 44},
			&expr.Match{Name: "comment"},
			&expr.Target{Name: "LOG"},
			&expr.Queue{Num: 1},
			&expr.FlowOffload{Name: "ft"},
			&expr.Reject{},
			&expr.Hash{},
			&expr.CtHelper{},
			&expr.SynProxy{},
			&expr.CtExpect{},
			&expr.SecMark{},
			&expr.CtTimeout{},
			&expr.Fib{},
			&expr.Numgen{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	}
	// Must not panic; the trailing verdict guarantees a non-empty render.
	if got := ruleToHumanReadableWithSets(rule, nil); got == "" {
		t.Error("render returned empty for the todo-arm sweep")
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
