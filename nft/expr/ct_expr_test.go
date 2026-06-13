package nftexpr

// Tests for ExprCtToCt (the expr.Ct + following-expr → Ct decoder) and the
// fillCtField dispatch it uses. Both are pure: the Lookup arm's element fetch
// uses a fresh nftables.Conn that simply errors out under test, leaving the
// field untouched, which is the path exercised here.

import (
	"reflect"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func TestExprCtToCt_CmpScalar(t *testing.T) {
	// ct mark 0xdead — Ct followed by a Cmp.
	exprs := []expr.Any{
		&expr.Ct{Key: expr.CtKeyMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: le(0xdead)},
	}
	got, skip := ExprCtToCt(exprs[0].(*expr.Ct), exprs, 0, nil)
	if skip != 2 {
		t.Errorf("skip = %d, want 2", skip)
	}
	if got.Mark != 0xdead {
		t.Errorf("Mark = %#x, want 0xdead", got.Mark)
	}
}

func TestExprCtToCt_ExpirationOp(t *testing.T) {
	exprs := []expr.Any{
		&expr.Ct{Key: expr.CtKeyEXPIRATION, Register: 1},
		&expr.Cmp{Op: expr.CmpOpGt, Register: 1, Data: beU32(30)},
	}
	got, _ := ExprCtToCt(exprs[0].(*expr.Ct), exprs, 0, nil)
	if got.Expiration != 30 || got.ExpirationOp == "" {
		t.Errorf("expiration = %d op = %q, want 30 with an op", got.Expiration, got.ExpirationOp)
	}
}

func TestExprCtToCt_BitwiseStates(t *testing.T) {
	// ct state {established, related} — Ct + Bitwise (zero Xor) + Cmp.
	mask := le(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED)
	exprs := []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Mask: mask, Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)},
	}
	got, skip := ExprCtToCt(exprs[0].(*expr.Ct), exprs, 0, nil)
	if skip != 3 {
		t.Errorf("skip = %d, want 3 (Ct+Bitwise+Cmp)", skip)
	}
	if !reflect.DeepEqual(got.State, []CtState{CtStateEstablished, CtStateRelated}) {
		t.Errorf("State = %v", got.State)
	}
}

func TestExprCtToCt_BitwiseStatusAndEvents(t *testing.T) {
	// Status via bitwise.
	exprs := []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATUS, Register: 1},
		&expr.Bitwise{Mask: le(CtStatusBitAssured), Xor: make([]byte, 4)},
	}
	got, _ := ExprCtToCt(exprs[0].(*expr.Ct), exprs, 0, nil)
	if !reflect.DeepEqual(got.Status, []CtStatus{CtStatusAssured}) {
		t.Errorf("Status = %v", got.Status)
	}

	// Non-zero Xor → the decoded value is discarded.
	exprs2 := []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{Mask: le(expr.CtStateBitNEW), Xor: le(1)},
	}
	got2, _ := ExprCtToCt(exprs2[0].(*expr.Ct), exprs2, 0, nil)
	if len(got2.State) != 0 {
		t.Errorf("non-zero Xor should drop the state, got %v", got2.State)
	}
}

func TestExprCtToCt_LookupNoElements(t *testing.T) {
	// ct mark @marks — the set is in the slice but the element fetch fails
	// under test (no netlink), so no value is filled. The branch still runs.
	set := &nftables.Set{Name: "marks", Table: &nftables.Table{Name: "t", Family: nftables.TableFamilyINet}}
	exprs := []expr.Any{
		&expr.Ct{Key: expr.CtKeyMARK, Register: 1},
		&expr.Lookup{SourceRegister: 1, SetName: "marks"},
	}
	got, skip := ExprCtToCt(exprs[0].(*expr.Ct), exprs, 0, []*nftables.Set{set})
	if skip != 2 {
		t.Errorf("skip = %d, want 2", skip)
	}
	if got.Mark != 0 {
		t.Errorf("Mark = %d, want 0 (no elements fetched)", got.Mark)
	}
}

func TestExprCtToCt_ExpirationRange(t *testing.T) {
	exprs := []expr.Any{
		&expr.Ct{Key: expr.CtKeyEXPIRATION, Register: 1},
		&expr.Range{Op: expr.CmpOpNeq, FromData: beU32(10), ToData: beU32(20)},
	}
	got, _ := ExprCtToCt(exprs[0].(*expr.Ct), exprs, 0, nil)
	if got.ExpirationRange == nil || got.ExpirationRange.From != 10 || got.ExpirationRange.To != 20 {
		t.Errorf("ExpirationRange = %+v, want {10 20}", got.ExpirationRange)
	}
	if got.ExpirationOp != "!=" {
		t.Errorf("ExpirationOp = %q, want !=", got.ExpirationOp)
	}
}

func TestExprCtToCt_CounterDirection(t *testing.T) {
	// Counter keys read the Direction field off the expr.Ct itself.
	for _, tc := range []struct {
		dir  uint32
		want CtDirection
	}{
		{0, CtDirectionOriginal},
		{1, CtDirectionReply},
		{255, CtDirectionNone},
	} {
		ctExpr := &expr.Ct{Key: expr.CtKeyBYTES, Register: 1, Direction: tc.dir}
		got, _ := ExprCtToCt(ctExpr, []expr.Any{ctExpr}, 0, nil)
		if got.Direction != tc.want {
			t.Errorf("direction %d → %q, want %q", tc.dir, got.Direction, tc.want)
		}
	}
}

func TestFillCtField_AllKeys(t *testing.T) {
	check := func(name string, key expr.CtKey, value interface{}, assert func(*Ct) bool) {
		t.Helper()
		ct := &Ct{}
		fillCtField(ct, key, value)
		if !assert(ct) {
			t.Errorf("%s: fillCtField did not set the expected field (ct=%+v)", name, ct)
		}
	}

	check("state scalar", expr.CtKeySTATE, CtStateNew, func(c *Ct) bool { return len(c.State) == 1 && c.State[0] == CtStateNew })
	check("state slice", expr.CtKeySTATE, []CtState{CtStateNew, CtStateRelated}, func(c *Ct) bool { return len(c.State) == 2 })
	check("direction typed", expr.CtKeyDIRECTION, CtDirectionReply, func(c *Ct) bool { return c.Direction == CtDirectionReply })
	check("direction string", expr.CtKeyDIRECTION, "original", func(c *Ct) bool { return c.Direction == CtDirection("original") })
	check("direction uint8", expr.CtKeyDIRECTION, uint8(1), func(c *Ct) bool { return c.Direction == CtDirectionReply })
	check("status slice", expr.CtKeySTATUS, []CtStatus{CtStatusAssured}, func(c *Ct) bool { return len(c.Status) == 1 })
	check("mark", expr.CtKeyMARK, uint32(7), func(c *Ct) bool { return c.Mark == 7 })
	check("secmark", expr.CtKeySECMARK, uint32(9), func(c *Ct) bool { return c.SecMark == 9 })
	check("expiration", expr.CtKeyEXPIRATION, uint32(30), func(c *Ct) bool { return c.Expiration == 30 })
	check("protocol typed", expr.CtKeyPROTOCOL, CtProtocolTCP, func(c *Ct) bool { return c.Protocol == 6 })
	check("protocol uint8", expr.CtKeyPROTOCOL, uint8(17), func(c *Ct) bool { return c.Protocol == 17 })
	check("protocol uint32", expr.CtKeyPROTOCOL, uint32(1), func(c *Ct) bool { return c.Protocol == 1 })
	check("l3proto typed", expr.CtKeyL3PROTOCOL, CtL3ProtoIPv4, func(c *Ct) bool { return c.L3Protocol == 2 })
	check("l3proto uint8", expr.CtKeyL3PROTOCOL, uint8(10), func(c *Ct) bool { return c.L3Protocol == 10 })
	check("l3proto uint32", expr.CtKeyL3PROTOCOL, uint32(2), func(c *Ct) bool { return c.L3Protocol == 2 })
	check("src", expr.CtKeySRC, "10.0.0.1", func(c *Ct) bool { return c.Src == "10.0.0.1" })
	check("dst", expr.CtKeyDST, "10.0.0.2", func(c *Ct) bool { return c.Dst == "10.0.0.2" })
	check("protosrc uint16", expr.CtKeyPROTOSRC, uint16(80), func(c *Ct) bool { return c.ProtoSrc == 80 })
	check("protosrc uint32", expr.CtKeyPROTOSRC, uint32(80), func(c *Ct) bool { return c.ProtoSrc == 80 })
	check("protodst uint16", expr.CtKeyPROTODST, uint16(443), func(c *Ct) bool { return c.ProtoDst == 443 })
	check("protodst uint32", expr.CtKeyPROTODST, uint32(443), func(c *Ct) bool { return c.ProtoDst == 443 })
	check("pkts uint64", expr.CtKeyPKTS, uint64(100), func(c *Ct) bool { return c.Pkts == 100 })
	check("pkts uint32", expr.CtKeyPKTS, uint32(100), func(c *Ct) bool { return c.Pkts == 100 })
	check("bytes uint64", expr.CtKeyBYTES, uint64(1024), func(c *Ct) bool { return c.Bytes == 1024 })
	check("bytes uint32", expr.CtKeyBYTES, uint32(1024), func(c *Ct) bool { return c.Bytes == 1024 })
	check("avgpkt uint64", expr.CtKeyAVGPKT, uint64(512), func(c *Ct) bool { return c.Avgpkt == 512 })
	check("avgpkt uint32", expr.CtKeyAVGPKT, uint32(512), func(c *Ct) bool { return c.Avgpkt == 512 })
	check("helper", expr.CtKeyHELPER, "ftp", func(c *Ct) bool { return c.Helper == "ftp" })
	check("zone uint16", expr.CtKeyZONE, uint16(4), func(c *Ct) bool { return c.Zone == 4 })
	check("zone uint32", expr.CtKeyZONE, uint32(4), func(c *Ct) bool { return c.Zone == 4 })
	check("labels slice", expr.CtKeyLABELS, []string{"0", "7"}, func(c *Ct) bool { return len(c.Labels) == 2 })
	check("labels string", expr.CtKeyLABELS, "5", func(c *Ct) bool { return len(c.Labels) == 1 && c.Labels[0] == "5" })
	check("events scalar", expr.CtKeyEVENTMASK, CtEventNew, func(c *Ct) bool { return len(c.Events) == 1 })
	check("events slice", expr.CtKeyEVENTMASK, []CtEvent{CtEventNew, CtEventDestroy}, func(c *Ct) bool { return len(c.Events) == 2 })

	// nil value is a no-op; mismatched type leaves the field zero.
	ct := &Ct{}
	fillCtField(ct, expr.CtKeyMARK, nil)
	fillCtField(ct, expr.CtKeyMARK, "not-a-number")
	if ct.Mark != 0 {
		t.Errorf("Mark = %d after nil/typed-mismatch, want 0", ct.Mark)
	}
}
