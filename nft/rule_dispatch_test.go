package nft

// Dispatch-arm sweep for NftablesToRuleDefinition. A single rule carrying one
// expression per dispatch case drives every arm of the big type switch in one
// pass (condition arms, action arms, register-loading arms and the unknown
// default), then a few targeted rules pin the arms whose output is easy to
// assert. All netlink-free: NftablesToRuleDefinition only reads the in-memory
// rule.

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	nftexpr "nftui/nft/expr"
)

func TestNftablesToRuleDefinition_DispatchSweep(t *testing.T) {
	rule := &nftables.Rule{
		Table: &nftables.Table{Name: "sweep", Family: nftables.TableFamilyINet},
		Exprs: []expr.Any{
			// register-loading arms
			&expr.Ct{Key: expr.CtKeyMARK, Register: 1},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}}, // latches l4proto tcp
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 2, Data: []byte{0, 22}},
			&expr.Exthdr{DestRegister: 3, Type: 44, Offset: 0, Len: 1, Op: expr.ExthdrOpIpv6},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 3, Data: []byte{6}},
			&expr.Immediate{Register: 4, Data: []byte{0x00, 0x50}},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Mask: []byte{0xff, 0xff, 0xff, 0xff}, Xor: []byte{0, 0, 0, 0}},
			&expr.Range{Op: expr.CmpOpEq, Register: 2, FromData: []byte{0, 80}, ToData: []byte{0, 90}},
			// LL ethertype latch (Payload LL/12/2 + Cmp), then a lookup.
			&expr.Payload{Base: expr.PayloadBaseLLHeader, Offset: 12, Len: 2, DestRegister: 5},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 5, Data: []byte{0x08, 0x06}},
			&expr.Lookup{SourceRegister: 2, SetName: "ports"},
			// condition arms
			&expr.Limit{Type: expr.LimitTypePkts, Rate: 10, Unit: expr.LimitTimeSecond},
			&expr.Connlimit{Count: 5, Flags: expr.NFT_CONNLIMIT_F_INV},
			// action arms
			&expr.Counter{Packets: 1, Bytes: 64},
			&expr.Objref{Type: 1, Name: "cnt"},
			&expr.Redir{RegisterProtoMin: 4},
			&expr.NAT{Type: expr.NATTypeSourceNAT, RegAddrMin: 4},
			&expr.Quota{Bytes: 1000},
			&expr.Dynset{Operation: 0, SetName: "flood"},
			&expr.Log{Data: []byte("swept")},
			&expr.Queue{Num: 0, Total: 1},
			&expr.Reject{Type: unix.NFT_REJECT_ICMP_UNREACH, Code: 3},
			&expr.Masq{},
			// unknown / default arm
			&expr.Byteorder{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	}

	rd, err := NftablesToRuleDefinition(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) == 0 {
		t.Error("expected at least one condition")
	}
	if len(rd.Actions) == 0 {
		t.Error("expected at least one action")
	}
}

func TestNftablesToRuleDefinition_ArmAssertions(t *testing.T) {
	// Connlimit becomes a condition carrying the original expression.
	t.Run("connlimit condition", func(t *testing.T) {
		rd, err := NftablesToRuleDefinition(makeRule(&expr.Connlimit{Count: 3, Flags: expr.NFT_CONNLIMIT_F_INV}))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, c := range rd.Conditions {
			if c.Type == ConditionTypeConnlimit && c.Connlimit != nil && c.Connlimit.Count == 3 {
				found = true
			}
		}
		if !found {
			t.Errorf("connlimit condition missing: %+v", rd.Conditions)
		}
	})

	// Quota becomes an action.
	t.Run("quota action", func(t *testing.T) {
		rd, err := NftablesToRuleDefinition(makeRule(&expr.Quota{Bytes: 4096}))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, a := range rd.Actions {
			if a.Type == ActionTypeQuota {
				found = true
			}
		}
		if !found {
			t.Errorf("quota action missing: %+v", rd.Actions)
		}
	})

	// Counter populates both rd.Counter and a counter action.
	t.Run("counter stats", func(t *testing.T) {
		rd, err := NftablesToRuleDefinition(makeRule(&expr.Counter{Packets: 7, Bytes: 700}))
		if err != nil {
			t.Fatal(err)
		}
		if rd.Counter == nil || rd.Counter.Packets != 7 || rd.Counter.Bytes != 700 {
			t.Errorf("counter stats = %+v, want 7/700", rd.Counter)
		}
	})

	// An unrecognized expression lands in a custom condition naming its type.
	t.Run("unknown → custom", func(t *testing.T) {
		rd, err := NftablesToRuleDefinition(makeRule(&expr.Byteorder{}))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, c := range rd.Conditions {
			if c.Type == ConditionTypeCustom && c.Custom != nil {
				found = true
			}
		}
		if !found {
			t.Errorf("custom condition missing for unknown expr: %+v", rd.Conditions)
		}
	})
}

// TestCompareToCondition_UnknownRegister exercises compareToCondition's default
// arm: a Cmp with no preceding loader gets a regTypeUnknown register, which
// produces a custom "unknown type" condition.
func TestCompareToCondition_UnknownRegister(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1, 2, 3, 4}},
	))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range rd.Conditions {
		if c.Type == ConditionTypeCustom {
			found = true
		}
	}
	if !found {
		t.Errorf("bare Cmp did not yield a custom condition: %+v", rd.Conditions)
	}
}

func TestRangeToCondition_CTAndUnsupported(t *testing.T) {
	// CT range arm: ct bytes loaded, then a Range over the register.
	t.Run("ct range", func(t *testing.T) {
		rd, err := NftablesToRuleDefinition(makeRule(
			&expr.Ct{Key: expr.CtKeyBYTES, Register: 1},
			&expr.Range{Op: expr.CmpOpEq, Register: 1,
				FromData: []byte{0, 0, 0, 0, 0, 0, 0, 10},
				ToData:   []byte{0, 0, 0, 0, 0, 0, 0, 99}},
		))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, c := range rd.Conditions {
			if c.Type == ConditionTypeCT && c.CT != nil {
				if _, ok := c.CT.Value.(*RangeValue); ok {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("ct range condition missing: %+v", rd.Conditions)
		}
	})

	// Unsupported range arm: a Range over a meta register returns an error
	// inside rangeToCondition, so no condition is appended.
	t.Run("meta range unsupported", func(t *testing.T) {
		rd, err := NftablesToRuleDefinition(makeRule(
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: []byte{0, 1}, ToData: []byte{0, 2}},
		))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range rd.Conditions {
			if c.Type == ConditionTypePayload || c.Type == ConditionTypeCT {
				t.Errorf("unexpected range condition for meta register: %+v", c)
			}
		}
	})
}

func TestCtCompareToCondition_BitwiseAndDirection(t *testing.T) {
	// Pattern B: Bitwise{mask} + Cmp{Neq, zeros} normalizes to Eq using the mask.
	t.Run("bitwise pattern B", func(t *testing.T) {
		rd, err := NftablesToRuleDefinition(makeRule(
			&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1,
				Mask: []byte{0x06, 0, 0, 0}, Xor: []byte{0, 0, 0, 0}},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
		))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, c := range rd.Conditions {
			if c.Type == ConditionTypeCT && c.Operation == CompareOpEq {
				found = true
			}
		}
		if !found {
			t.Errorf("pattern-B normalization to Eq missing: %+v", rd.Conditions)
		}
	})

	// Reply direction: a counter CT key with Direction=1 reports "reply".
	t.Run("reply direction", func(t *testing.T) {
		rd, err := NftablesToRuleDefinition(makeRule(
			&expr.Ct{Key: expr.CtKeyPKTS, Register: 1, Direction: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 0, 0, 0, 0, 0, 0, 5}},
		))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, c := range rd.Conditions {
			if c.Type == ConditionTypeCT && c.CT != nil && c.CT.Direction == nftexpr.CtDirectionReply {
				found = true
			}
		}
		if !found {
			t.Errorf("reply direction missing: %+v", rd.Conditions)
		}
	})
}

func TestSctpChunkCompareToCondition(t *testing.T) {
	mkChunk := func(typ uint8, off, length uint32, flags uint32, data []byte) *nftables.Rule {
		return makeRule(
			&expr.Exthdr{DestRegister: 1, Type: typ, Offset: off, Len: length,
				Op: expr.ExthdrOp(nftexpr.SctpExthdrOp), Flags: flags},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
		)
	}

	chunkCond := func(t *testing.T, rule *nftables.Rule) *SctpChunkCondition {
		t.Helper()
		rd, err := NftablesToRuleDefinition(rule)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range rd.Conditions {
			if c.Type == ConditionTypeSctpChunk && c.SctpChunk != nil {
				return c.SctpChunk
			}
		}
		t.Fatalf("no sctp chunk condition in %+v", rd.Conditions)
		return nil
	}

	// Bare presence: F_PRESENT set, empty field.
	t.Run("presence", func(t *testing.T) {
		sc := chunkCond(t, mkChunk(uint8(nftexpr.ChunkInit), 0, 0, nftexpr.SctpExthdrFlagPresent, []byte{0x01}))
		if sc.Field != "" {
			t.Errorf("presence field = %q, want empty", sc.Field)
		}
	})

	// Known field: DATA chunk tsn at offset 4 len 4.
	t.Run("known field", func(t *testing.T) {
		sc := chunkCond(t, mkChunk(uint8(nftexpr.ChunkData), 4, 4, 0, []byte{0, 0, 0, 1}))
		if sc.Field != "tsn" {
			t.Errorf("field = %q, want tsn", sc.Field)
		}
	})

	// Unknown field: off-layout offset/len renders as @off+len.
	t.Run("unknown field", func(t *testing.T) {
		sc := chunkCond(t, mkChunk(uint8(nftexpr.ChunkData), 99, 1, 0, []byte{0x7f}))
		if sc.Field != "@99+1" {
			t.Errorf("field = %q, want @99+1", sc.Field)
		}
	})
}
