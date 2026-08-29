package nftserializer

// Unit tests for the netlink-free parts of the ruleset serializer. The
// SerializeRule dispatch is exercised through serializeRuleExprs with the
// sets slice passed in, so no live netlink connection (CAP_NET_ADMIN) is
// needed — the same seam the TUI's rule viewer and save-error path rely on.

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// commentUserData encodes a rule comment in the UserData TLV format
// (Type=0, Length, Value) that nft.ExtractComment expects.
func commentUserData(s string) []byte {
	return append([]byte{0, byte(len(s))}, []byte(s)...)
}

func TestIndent(t *testing.T) {
	if got := indent(0); got != "" {
		t.Errorf("indent(0) = %q, want empty", got)
	}
	if got := indent(2); got != "        " {
		t.Errorf("indent(2) = %q, want 8 spaces", got)
	}
}

func TestSerializeChain(t *testing.T) {
	accept := nftables.ChainPolicyAccept
	drop := nftables.ChainPolicyDrop

	tests := []struct {
		name  string
		chain nftables.Chain
		want  string
	}{
		{
			name: "base chain accept",
			chain: nftables.Chain{
				Name:     "input",
				Type:     nftables.ChainTypeFilter,
				Hooknum:  nftables.ChainHookInput,
				Priority: nftables.ChainPriorityFilter,
				Policy:   &accept,
			},
			want: "chain input { type filter hook input priority 0 policy accept }",
		},
		{
			name: "base chain drop",
			chain: nftables.Chain{
				Name:     "fw",
				Type:     nftables.ChainTypeFilter,
				Hooknum:  nftables.ChainHookForward,
				Priority: nftables.ChainPriorityFilter,
				Policy:   &drop,
			},
			want: "chain fw { type filter hook forward priority 0 policy drop }",
		},
		{
			name:  "regular chain",
			chain: nftables.Chain{Name: "dispatch"},
			want:  "chain dispatch { }",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := serializeChain(&tt.chain); got != tt.want {
				t.Errorf("serializeChain() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSerializeSet(t *testing.T) {
	set := nftables.Set{Name: "blocklist", KeyType: nftables.TypeIPAddr}
	want := "set blocklist { type ipv4_addr } timeout 0s "
	if got := serializeSet(&set); got != want {
		t.Errorf("serializeSet() = %q, want %q", got, want)
	}
}

// TestSerializeRuleExprs pins the dispatch + joining behavior for the common
// expression classes. Per-serializer formatting details are covered by the
// nft/expr unit tests — here a representative member per switch arm is
// enough to keep the dispatcher honest.
func TestSerializeRuleExprs(t *testing.T) {
	tests := []struct {
		name     string
		exprs    []expr.Any
		userData []byte
		sets     []*nftables.Set
		want     string
	}{
		{
			name:  "counter accept",
			exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictAccept}},
			want:  "counter accept",
		},
		{
			name:  "jump verdict",
			exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictJump, Chain: "dispatch"}},
			want:  "jump dispatch",
		},
		{
			name: "ip saddr cmp",
			exprs: []expr.Any{
				&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{10, 0, 0, 5}},
			},
			want: "ip saddr 10.0.0.5",
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
			want: "tcp dport 22 accept",
		},
		{
			// Transport offset 4 is `length` under UDP but the checksum
			// coverage under UDP-Lite, where nft calls it `csumcov` and
			// rejects `udplite length`. The serializer names it from the
			// l4proto context the meta match latched.
			name: "udplite csumcov via meta l4proto",
			exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{136}},
				&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 4, Len: 2, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 8}},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
			want: "udplite csumcov 8 accept",
		},
		{
			name: "udp length via meta l4proto",
			exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{17}},
				&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 4, Len: 2, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 64}},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
			want: "udp length 64 accept",
		},
		{
			// No l4proto match in the rule → the cell cannot be named, and
			// the raw @th form is what nft itself accepts back.
			name: "transport offset 4 without context stays raw",
			exprs: []expr.Any{
				&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 4, Len: 2, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 8}},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
			want: "@th,32,16 0x0008 accept",
		},
		{
			name:  "masquerade",
			exprs: []expr.Any{&expr.Masq{}},
			want:  "masquerade",
		},
		{
			name:  "reject tcp reset",
			exprs: []expr.Any{&expr.Reject{Type: 1}},
			want:  "reject with tcp reset",
		},
		{
			name:  "queue",
			exprs: []expr.Any{&expr.Queue{Num: 1}},
			want:  "queue num 1",
		},
		{
			name:  "log prefix",
			exprs: []expr.Any{&expr.Log{Data: []byte("audit")}},
			want:  `log prefix "audit"`,
		},
		{
			name: "limit",
			exprs: []expr.Any{&expr.Limit{
				Type: expr.LimitTypePkts, Rate: 10, Unit: expr.LimitTimeSecond, Burst: 5,
			}},
			want: "limit rate 10/second burst 5 packets",
		},
		{
			name:  "lookup falls back to set name when set is not in slice",
			exprs: []expr.Any{&expr.Lookup{SourceRegister: 1, SetName: "blocklist"}},
			want:  "@blocklist",
		},
		{
			name:  "lookup falls back to set_N for anonymous set",
			exprs: []expr.Any{&expr.Lookup{SourceRegister: 1, SetID: 9}},
			want:  "@set_9",
		},
		{
			name:  "lookup falls back when elements are unfetchable",
			exprs: []expr.Any{&expr.Lookup{SourceRegister: 1, SetName: "blocklist"}},
			sets: []*nftables.Set{{
				Name:  "blocklist",
				Table: &nftables.Table{Name: "nftui_serializer_unit_test", Family: nftables.TableFamilyIPv4},
			}},
			want: "@blocklist",
		},
		{
			name:  "objref counter",
			exprs: []expr.Any{&expr.Objref{Type: 1, Name: "cnt"}},
			want:  "counter name cnt",
		},
		{
			name:  "redirect",
			exprs: []expr.Any{&expr.Redir{}},
			want:  "redirect",
		},
		{
			name:  "nat snat",
			exprs: []expr.Any{&expr.NAT{Type: expr.NATTypeSourceNAT, RegAddrMin: 1}},
			want:  "snat to ADDRESS",
		},
		{
			name:  "quota",
			exprs: []expr.Any{&expr.Quota{Bytes: 5 * 1024 * 1024}},
			want:  "quota 5 mbytes",
		},
		{
			name:  "dynset",
			exprs: []expr.Any{&expr.Dynset{SetName: "flood"}},
			want:  "unknown @flood",
		},
		{
			name:  "match",
			exprs: []expr.Any{&expr.Match{Name: "limit"}},
			want:  "match limit",
		},
		{
			name:  "target",
			exprs: []expr.Any{&expr.Target{Name: "TRACE"}},
			want:  "target TRACE",
		},
		{
			name:  "connlimit over",
			exprs: []expr.Any{&expr.Connlimit{Count: 5, Flags: expr.NFT_CONNLIMIT_F_INV}},
			want:  "ct count over 5",
		},
		{
			name:  "flow offload",
			exprs: []expr.Any{&expr.FlowOffload{Name: "ft"}},
			want:  "flow add @ft",
		},
		{
			name:  "hash",
			exprs: []expr.Any{&expr.Hash{Modulus: 10, Offset: 2}},
			want:  "jhash mod 10 offset 2",
		},
		{
			name:  "synproxy",
			exprs: []expr.Any{&expr.SynProxy{Mss: 1460, Wscale: 7}},
			want:  "synproxy mss 1460 wscale 7",
		},
		{
			name:  "secmark",
			exprs: []expr.Any{&expr.SecMark{Ctx: "sshctx"}},
			want:  "meta secmark set sshctx",
		},
		{
			name:  "fib",
			exprs: []expr.Any{&expr.Fib{FlagSADDR: true, ResultOIFNAME: true}},
			want:  "fib  saddr oifname",
		},
		{
			name:  "numgen",
			exprs: []expr.Any{&expr.Numgen{Type: unix.NFT_NG_INCREMENTAL, Modulus: 2}},
			want:  "numgen inc mod 2 offset 0",
		},
		{
			name:  "rt",
			exprs: []expr.Any{&expr.Rt{Key: expr.RtTCPMSS}},
			want:  "rt tcpmss",
		},
		{
			name:  "dup",
			exprs: []expr.Any{&expr.Dup{}},
			want:  "dup to ADDR device DEV",
		},
		{
			name:  "notrack",
			exprs: []expr.Any{&expr.Notrack{}},
			want:  "notrack",
		},
		{
			name:  "tproxy",
			exprs: []expr.Any{&expr.TProxy{}},
			want:  "tproxy to ADDRESS:PORT",
		},
		{
			name:  "socket",
			exprs: []expr.Any{&expr.Socket{Key: expr.SocketKeyTransparent}},
			want:  "socket transparent",
		},
		{
			name: "bitwise standalone",
			exprs: []expr.Any{
				&expr.Bitwise{Mask: []byte{0xff, 0xff}, Xor: []byte{0x00, 0x00}},
			},
			want: "& 65535 ^ 0",
		},
		{
			name: "immediate non-empty",
			exprs: []expr.Any{
				&expr.Immediate{Data: []byte{0x00, 0x50}},
			},
			want: "80",
		},
		{
			name: "range from pending payload",
			exprs: []expr.Any{
				&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
				&expr.Range{Op: expr.CmpOpEq, FromData: []byte{0, 80}, ToData: []byte{0, 90}},
			},
			want: "dport 80-90",
		},
		{
			name: "ct state",
			exprs: []expr.Any{
				&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x02, 0, 0, 0}},
			},
			want: "ct state established",
		},
		{
			name:  "standalone cmp with no pending register",
			exprs: []expr.Any{&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 22}}},
			want:  "22",
		},
		{
			name: "exthdr frag field",
			exprs: []expr.Any{
				&expr.Exthdr{DestRegister: 1, Type: 44, Offset: 0, Len: 1, Op: expr.ExthdrOpIpv6},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
			},
			want: "frag field 6",
		},
		{
			name: "empty immediate is skipped",
			// SerializeImmediate returns "" for zero-length data; the dispatch
			// must drop it rather than emit a blank token.
			exprs: []expr.Any{&expr.Immediate{Register: 1}, &expr.Counter{}},
			want:  "counter",
		},
		{
			name:  "anonymous set matched by ID falls back when unfetchable",
			exprs: []expr.Any{&expr.Lookup{SourceRegister: 1, SetID: 7}},
			sets: []*nftables.Set{{
				ID:    7,
				Table: &nftables.Table{Name: "nftui_serializer_unit_test", Family: nftables.TableFamilyIPv4},
			}},
			want: "@set_7",
		},
		{
			name:  "unknown expr",
			exprs: []expr.Any{&expr.Byteorder{}},
			want:  "/* unknown expr: *expr.Byteorder */",
		},
		{
			name:     "comment is appended",
			exprs:    []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictAccept}},
			userData: commentUserData("ssh"),
			want:     `counter accept comment "ssh"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &nftables.Rule{Exprs: tt.exprs, UserData: tt.userData}
			if got := serializeRuleExprs(rule, tt.sets); got != tt.want {
				t.Errorf("serializeRuleExprs() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Regression pin for the Lookup infinite loop: the pre-v0.9.0 code re-fetched
// the set over netlink inside the dispatch loop and `continue`d WITHOUT
// advancing the expression index on error, so a rule with an unresolvable set
// lookup spun forever (and the element fetch could log.Fatal the process).
// This test hanging or killing the test binary is the regression signal.
func TestSerializeRuleExprs_LookupTerminates(t *testing.T) {
	rule := &nftables.Rule{
		Exprs: []expr.Any{
			&expr.Lookup{SourceRegister: 1, SetName: "no_such_set"},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	}
	want := "@no_such_set accept"
	if got := serializeRuleExprs(rule, nil); got != want {
		t.Errorf("serializeRuleExprs() = %q, want %q", got, want)
	}
}

// The public wrapper fetches the table's sets over netlink first. In a
// unit-test environment that fetch fails (EPERM unprivileged, ENOENT for the
// synthetic table as root), which must surface as the error text — never a
// hang or panic. The happy path is covered through serializeRuleExprs above.
func TestSerializeRule_Terminates(t *testing.T) {
	rule := &nftables.Rule{
		Table: &nftables.Table{Name: "nftui_serializer_unit_test", Family: nftables.TableFamilyIPv4},
		Exprs: []expr.Any{&expr.Counter{}},
	}
	if got := SerializeRule(rule); got == "" {
		t.Error("SerializeRule returned an empty string")
	}
}
