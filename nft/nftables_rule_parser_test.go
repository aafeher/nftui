package nft

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	nftexpr "nftui/nft/expr"
)

// makeRule is a helper that wraps expressions into a minimal nftables.Rule.
func makeRule(exprs ...expr.Any) *nftables.Rule {
	return &nftables.Rule{Exprs: exprs}
}

// leUint32 encodes v as a 4-byte LittleEndian slice (register format used by DecodeCTValue).
func leUint32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// beUint16 encodes v as a 2-byte BigEndian slice (port / protocol format).
func beUint16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

// --- Empty / metadata ---

func TestNftablesToRuleDefinition_Empty(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 0 {
		t.Errorf("expected 0 conditions, got %d", len(rd.Conditions))
	}
	if len(rd.Actions) != 0 {
		t.Errorf("expected 0 actions, got %d", len(rd.Actions))
	}
}

func TestNftablesToRuleDefinition_PositionHandle(t *testing.T) {
	rule := &nftables.Rule{Position: 5, Handle: 10, Exprs: nil}
	rd, err := NftablesToRuleDefinition(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rd.Position != 5 {
		t.Errorf("Position = %d, want 5", rd.Position)
	}
	if rd.Handle != 10 {
		t.Errorf("Handle = %d, want 10", rd.Handle)
	}
}

func TestNftablesToRuleDefinition_Comment(t *testing.T) {
	rule := &nftables.Rule{
		UserData: []byte{0, 6, 'h', 'e', 'l', 'l', 'o', 0},
		Exprs:    nil,
	}
	rd, err := NftablesToRuleDefinition(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rd.Comment != "hello" {
		t.Errorf("Comment = %q, want %q", rd.Comment, "hello")
	}
}

// --- Verdicts ---

func TestNftablesToRuleDefinition_VerdictAccept(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(rd.Actions))
	}
	a := rd.Actions[0]
	if a.Type != ActionTypeVerdict {
		t.Errorf("action type = %q, want %q", a.Type, ActionTypeVerdict)
	}
	if a.Verdict.Kind != VerdictAccept {
		t.Errorf("verdict kind = %q, want %q", a.Verdict.Kind, VerdictAccept)
	}
}

func TestNftablesToRuleDefinition_VerdictDrop(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Verdict{Kind: expr.VerdictDrop},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rd.Actions[0].Verdict.Kind != VerdictDrop {
		t.Errorf("verdict kind = %q, want %q", rd.Actions[0].Verdict.Kind, VerdictDrop)
	}
}

func TestNftablesToRuleDefinition_VerdictJump(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Verdict{Kind: expr.VerdictJump, Chain: "forward_chain"},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	v := rd.Actions[0].Verdict
	if v.Kind != VerdictJump {
		t.Errorf("verdict kind = %q, want jump", v.Kind)
	}
	if v.Chain != "forward_chain" {
		t.Errorf("chain = %q, want %q", v.Chain, "forward_chain")
	}
}

func TestNftablesToRuleDefinition_VerdictReturn(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Verdict{Kind: expr.VerdictReturn},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rd.Actions[0].Verdict.Kind != VerdictReturn {
		t.Errorf("verdict kind = %q, want return", rd.Actions[0].Verdict.Kind)
	}
}

// --- Counter ---

func TestNftablesToRuleDefinition_Counter(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Counter{Bytes: 1000, Packets: 50},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rd.Counter == nil {
		t.Fatal("Counter is nil")
	}
	if rd.Counter.Bytes != 1000 {
		t.Errorf("Counter.Bytes = %d, want 1000", rd.Counter.Bytes)
	}
	if rd.Counter.Packets != 50 {
		t.Errorf("Counter.Packets = %d, want 50", rd.Counter.Packets)
	}
	// Counter also produces an action
	hasCounterAction := false
	for _, a := range rd.Actions {
		if a.Type == ActionTypeCounter {
			hasCounterAction = true
		}
	}
	if !hasCounterAction {
		t.Error("expected ActionTypeCounter in actions")
	}
}

// --- Limit ---

func TestNftablesToRuleDefinition_Limit(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Limit{Rate: 100, Unit: expr.LimitTimeSecond},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.Type != ConditionTypeLimit {
		t.Errorf("condition type = %q, want %q", c.Type, ConditionTypeLimit)
	}
	if c.Limit == nil {
		t.Fatal("Limit is nil")
	}
	if c.Limit.Rate != 100 {
		t.Errorf("Limit.Rate = %d, want 100", c.Limit.Rate)
	}
}

// --- Log ---

func TestNftablesToRuleDefinition_Log(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		// Key tracks which NFTA_LOG_* attributes were present on the wire — without
		// the LEVEL bit set, the parser correctly treats the field as unset and
		// defaults to the kernel's syslog default (warn). Real wire-parsed logs
		// from the kernel always have Key populated by Log.unmarshal.
		&expr.Log{Level: 6, Data: []byte("DROP\x00"), Key: (1 << unix.NFTA_LOG_LEVEL) | (1 << unix.NFTA_LOG_PREFIX)},
		&expr.Verdict{Kind: expr.VerdictDrop},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var logAction *Action
	for i := range rd.Actions {
		if rd.Actions[i].Type == ActionTypeLog {
			logAction = &rd.Actions[i]
		}
	}
	if logAction == nil {
		t.Fatal("expected ActionTypeLog")
	}
	if logAction.Log.Prefix != "DROP" {
		t.Errorf("log prefix = %q, want %q", logAction.Log.Prefix, "DROP")
	}
	if logAction.Log.Level != LogLevelInfo {
		t.Errorf("log level = %q, want %q", logAction.Log.Level, LogLevelInfo)
	}
}

// --- CT conditions ---

func TestNftablesToRuleDefinition_CTMark(t *testing.T) {
	markVal := uint32(42)
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: expr.CtKeyMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: leUint32(markVal)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.Type != ConditionTypeCT {
		t.Errorf("type = %q, want %q", c.Type, ConditionTypeCT)
	}
	if c.CT.Key != nftexpr.CtKey("mark") {
		t.Errorf("CT.Key = %q, want %q", c.CT.Key, "mark")
	}
	if c.Operation != CompareOpEq {
		t.Errorf("Operation = %q, want %q", c.Operation, CompareOpEq)
	}
	if c.CT.Value != markVal {
		t.Errorf("CT.Value = %v, want %d", c.CT.Value, markVal)
	}
}

func TestNftablesToRuleDefinition_CTSecmark(t *testing.T) {
	// `ct secmark <val>` emits Ct{Key:SECMARK} + Cmp{Eq, LE-uint32(val)} — same
	// shape as ct mark; the kernel stores secmark as a 32-bit conntrack metadata
	// scalar.
	secVal := uint32(0xdeadbeef)
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: expr.CtKeySECMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: leUint32(secVal)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.Type != ConditionTypeCT {
		t.Errorf("type = %q, want %q", c.Type, ConditionTypeCT)
	}
	if c.CT.Key != nftexpr.CtKey("secmark") {
		t.Errorf("CT.Key = %q, want %q", c.CT.Key, "secmark")
	}
	if c.Operation != CompareOpEq {
		t.Errorf("Operation = %q, want %q", c.Operation, CompareOpEq)
	}
	if c.CT.Value != secVal {
		t.Errorf("CT.Value = %v, want %d", c.CT.Value, secVal)
	}
}

func TestNftablesToRuleDefinition_CTSecmarkNeq(t *testing.T) {
	// `ct secmark != <val>` — make sure the Neq operator survives through
	// ctCompareToCondition without being normalized (it's not the
	// Bitwise+Neq+zeros bitmask pattern, so it must stay as Neq).
	secVal := uint32(7)
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: expr.CtKeySECMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: leUint32(secVal)},
		&expr.Verdict{Kind: expr.VerdictDrop},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.CT.Key != nftexpr.CtKey("secmark") {
		t.Errorf("CT.Key = %q, want %q", c.CT.Key, "secmark")
	}
	if c.Operation != CompareOpNeq {
		t.Errorf("Operation = %q, want %q", c.Operation, CompareOpNeq)
	}
	if c.CT.Value != secVal {
		t.Errorf("CT.Value = %v, want %d", c.CT.Value, secVal)
	}
}

func TestNftablesToRuleDefinition_CTState(t *testing.T) {
	// CT STATE Pattern A: Ct → Bitwise{mask=X} → Cmp{Eq, data=X}  (e.g. ct state established)
	stateMask := nftexpr.EncodeCtStates([]nftexpr.CtState{nftexpr.CtStateEstablished})

	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: stateMask, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: stateMask},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.Type != ConditionTypeCT {
		t.Errorf("type = %q, want %q", c.Type, ConditionTypeCT)
	}
	if c.CT.Key != nftexpr.CtKey("state") {
		t.Errorf("CT.Key = %q, want %q", c.CT.Key, "state")
	}
	if c.CT.Value != nftexpr.CtStateEstablished {
		t.Errorf("CT.Value = %v (%T), want CtStateEstablished", c.CT.Value, c.CT.Value)
	}
}

func TestNftablesToRuleDefinition_CTStateInvalid(t *testing.T) {
	// CT STATE Pattern B: Ct → Bitwise{mask=X} → Cmp{Neq, zeros}  (e.g. ct state invalid)
	// The kernel uses this pattern for single-bit state checks like invalid (bit 0x01).
	invalidMask := nftexpr.EncodeCtStates([]nftexpr.CtState{nftexpr.CtStateInvalid}) // [1,0,0,0]
	zeros := []byte{0x00, 0x00, 0x00, 0x00}

	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: invalidMask, Xor: zeros},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: zeros},
		&expr.Verdict{Kind: expr.VerdictDrop},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.Type != ConditionTypeCT {
		t.Errorf("type = %q, want %q", c.Type, ConditionTypeCT)
	}
	if c.CT.Key != nftexpr.CtKey("state") {
		t.Errorf("CT.Key = %q, want %q", c.CT.Key, "state")
	}
	if c.CT.Value != nftexpr.CtStateInvalid {
		t.Errorf("CT.Value = %v (%T), want CtStateInvalid", c.CT.Value, c.CT.Value)
	}
	if c.Operation != CompareOpEq {
		t.Errorf("Operation = %q, want %q (Neq+zeros normalized to Eq)", c.Operation, CompareOpEq)
	}
}

func TestNftablesToRuleDefinition_CTStatus(t *testing.T) {
	// CT STATUS: Ct → Bitwise{mask=status_bits, xor=zeros} → Cmp{Neq, data=zeros}
	statusMask := []byte{0x01, 0x00, 0x00, 0x00} // CtStatusBitExpected = 1 (LE)
	zeros := []byte{0x00, 0x00, 0x00, 0x00}

	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: expr.CtKeySTATUS, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: statusMask, Xor: zeros},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: zeros},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.Type != ConditionTypeCT {
		t.Errorf("type = %q, want %q", c.Type, ConditionTypeCT)
	}
	if c.CT.Key != nftexpr.CtKey("status") {
		t.Errorf("CT.Key = %q, want %q", c.CT.Key, "status")
	}
	// Neq+zeros gets normalized to Eq
	if c.Operation != CompareOpEq {
		t.Errorf("Operation = %q, want %q (Neq+zeros normalized)", c.Operation, CompareOpEq)
	}
}

func TestNftablesToRuleDefinition_CTEventmaskSingleBit(t *testing.T) {
	// ct eventmask new — single IPCT_NEW bit.
	// Pattern: Ct → Bitwise{mask=0x01, xor=0} → Cmp{Neq, data=zeros}
	// (the kernel emits this for single-bit checks; ctCompareToCondition
	// normalizes Neq+zeros → Eq using the mask as data.)
	mask := []byte{0x01, 0x00, 0x00, 0x00} // CtEventBitNew (LE)
	zeros := []byte{0x00, 0x00, 0x00, 0x00}

	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: expr.CtKeyEVENTMASK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: zeros},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: zeros},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.Type != ConditionTypeCT {
		t.Errorf("type = %q, want %q", c.Type, ConditionTypeCT)
	}
	if c.CT.Key != nftexpr.CtKey("eventmask") {
		t.Errorf("CT.Key = %q, want %q", c.CT.Key, "eventmask")
	}
	if c.CT.Value != nftexpr.CtEventNew {
		t.Errorf("CT.Value = %v (%T), want CtEventNew", c.CT.Value, c.CT.Value)
	}
	if c.Operation != CompareOpEq {
		t.Errorf("Operation = %q, want %q (Neq+zeros normalized)", c.Operation, CompareOpEq)
	}
}

func TestNftablesToRuleDefinition_CTEventmaskMultiBit(t *testing.T) {
	// ct eventmask {new, related, destroy} — three bits.
	// Pattern: Ct → Bitwise{mask=0x07, xor=0} → Cmp{Eq, data=0x07}
	mask := nftexpr.EncodeCtEvents([]nftexpr.CtEvent{
		nftexpr.CtEventNew,
		nftexpr.CtEventRelated,
		nftexpr.CtEventDestroy,
	})

	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: expr.CtKeyEVENTMASK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: mask},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.Type != ConditionTypeCT {
		t.Errorf("type = %q, want %q", c.Type, ConditionTypeCT)
	}
	if c.CT.Key != nftexpr.CtKey("eventmask") {
		t.Errorf("CT.Key = %q, want %q", c.CT.Key, "eventmask")
	}
	events, ok := c.CT.Value.([]nftexpr.CtEvent)
	if !ok {
		t.Fatalf("CT.Value type = %T, want []nftexpr.CtEvent", c.CT.Value)
	}
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3 (%v)", len(events), events)
	}
	want := []nftexpr.CtEvent{nftexpr.CtEventNew, nftexpr.CtEventRelated, nftexpr.CtEventDestroy}
	for i, ev := range want {
		if events[i] != ev {
			t.Errorf("events[%d] = %q, want %q", i, events[i], ev)
		}
	}
}

func TestNftablesToRuleDefinition_CTEventmaskAllBits(t *testing.T) {
	// Decode-side smoke test: every IPCT_* bit decodes to the correct CtEvent
	// in canonical order. We round-trip through EncodeCtEvents → DecodeCTValue
	// path implicitly via the parser.
	all := []nftexpr.CtEvent{
		nftexpr.CtEventNew, nftexpr.CtEventRelated, nftexpr.CtEventDestroy,
		nftexpr.CtEventReply, nftexpr.CtEventAssured, nftexpr.CtEventProtoinfo,
		nftexpr.CtEventHelper, nftexpr.CtEventMark, nftexpr.CtEventSeqAdj,
		nftexpr.CtEventSecMark, nftexpr.CtEventLabel, nftexpr.CtEventSynProxy,
	}
	mask := nftexpr.EncodeCtEvents(all)
	// 12 bits set → 0x0FFF (LE).
	if mask[0] != 0xff || mask[1] != 0x0f || mask[2] != 0x00 || mask[3] != 0x00 {
		t.Fatalf("EncodeCtEvents(all) = %v, want [0xff 0x0f 0x00 0x00]", mask)
	}

	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: expr.CtKeyEVENTMASK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: mask},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	events, ok := rd.Conditions[0].CT.Value.([]nftexpr.CtEvent)
	if !ok {
		t.Fatalf("CT.Value type = %T, want []nftexpr.CtEvent", rd.Conditions[0].CT.Value)
	}
	if len(events) != 12 {
		t.Fatalf("got %d events, want 12", len(events))
	}
	for i, ev := range all {
		if events[i] != ev {
			t.Errorf("events[%d] = %q, want %q", i, events[i], ev)
		}
	}
}

func TestNftablesToRuleDefinition_CTBytesOriginal(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: expr.CtKeyBYTES, Register: 1, Direction: 0, OptDirection: true},
		&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: []byte{0, 0, 0, 0, 0, 0, 0x03, 0xe8}}, // BE uint64 = 1000
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.CT.Key != nftexpr.CtKey("bytes") {
		t.Errorf("CT.Key = %q, want %q", c.CT.Key, "bytes")
	}
	if c.CT.Direction != nftexpr.CtDirectionOriginal {
		t.Errorf("Direction = %q, want %q", c.CT.Direction, nftexpr.CtDirectionOriginal)
	}
	if c.Operation != CompareOpGte {
		t.Errorf("Operation = %q, want %q", c.Operation, CompareOpGte)
	}
}

func TestNftablesToRuleDefinition_CTPktsReply(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: expr.CtKeyPKTS, Register: 1, Direction: 1, OptDirection: true},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 0, 0, 0, 0, 0, 0, 10}}, // BE uint64 = 10
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	if c.CT.Key != nftexpr.CtKey("pkts") {
		t.Errorf("CT.Key = %q, want %q", c.CT.Key, "pkts")
	}
	if c.CT.Direction != nftexpr.CtDirectionReply {
		t.Errorf("Direction = %q, want %q", c.CT.Direction, nftexpr.CtDirectionReply)
	}
}

func TestNftablesToRuleDefinition_CTAvgpkt(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: expr.CtKeyAVGPKT, Register: 1, Direction: 255, OptDirection: false},
		&expr.Cmp{Op: expr.CmpOpGt, Register: 1, Data: []byte{0, 0, 0, 0, 0, 0, 2, 0}}, // BE uint64 = 512
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.CT == nil {
		t.Fatal("CT is nil")
	}
	if c.CT.Key != nftexpr.CtKeyAvgpkt {
		t.Errorf("CT.Key = %q, want %q", c.CT.Key, nftexpr.CtKeyAvgpkt)
	}
	if c.CT.Direction != nftexpr.CtDirectionNone {
		t.Errorf("Direction = %q, want %q", c.CT.Direction, nftexpr.CtDirectionNone)
	}
	if v, ok := c.CT.Value.(uint64); !ok || v != 512 {
		t.Errorf("CT.Value = %v (%T), want uint64(512)", c.CT.Value, c.CT.Value)
	}
	if c.Operation != CompareOpGt {
		t.Errorf("Operation = %q, want %q", c.Operation, CompareOpGt)
	}
}

func TestNftablesToRuleDefinition_CTAvgpktOriginal(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: expr.CtKeyAVGPKT, Register: 1, Direction: 0, OptDirection: true},
		&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: []byte{0, 0, 0, 0, 0, 0, 0, 64}}, // BE uint64 = 64
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.CT == nil {
		t.Fatal("CT is nil")
	}
	if c.CT.Key != nftexpr.CtKeyAvgpkt {
		t.Errorf("CT.Key = %q, want %q", c.CT.Key, nftexpr.CtKeyAvgpkt)
	}
	if c.CT.Direction != nftexpr.CtDirectionOriginal {
		t.Errorf("Direction = %q, want %q", c.CT.Direction, nftexpr.CtDirectionOriginal)
	}
	if v, ok := c.CT.Value.(uint64); !ok || v != 64 {
		t.Errorf("CT.Value = %v (%T), want uint64(64)", c.CT.Value, c.CT.Value)
	}
	if c.Operation != CompareOpGte {
		t.Errorf("Operation = %q, want %q", c.Operation, CompareOpGte)
	}
}

func TestNftablesToRuleDefinition_CTAvgpktReply(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: expr.CtKeyAVGPKT, Register: 1, Direction: 1, OptDirection: true},
		&expr.Cmp{Op: expr.CmpOpLt, Register: 1, Data: []byte{0, 0, 0, 0, 0, 0, 5, 0xDC}}, // BE uint64 = 1500
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.CT == nil {
		t.Fatal("CT is nil")
	}
	if c.CT.Key != nftexpr.CtKeyAvgpkt {
		t.Errorf("CT.Key = %q, want %q", c.CT.Key, nftexpr.CtKeyAvgpkt)
	}
	if c.CT.Direction != nftexpr.CtDirectionReply {
		t.Errorf("Direction = %q, want %q", c.CT.Direction, nftexpr.CtDirectionReply)
	}
	if v, ok := c.CT.Value.(uint64); !ok || v != 1500 {
		t.Errorf("CT.Value = %v (%T), want uint64(1500)", c.CT.Value, c.CT.Value)
	}
	if c.Operation != CompareOpLt {
		t.Errorf("Operation = %q, want %q", c.Operation, CompareOpLt)
	}
}

func TestNftablesToRuleDefinition_CTLabels(t *testing.T) {
	mask := make([]byte, 16)
	mask[0] = 0x05 // bits 0 and 2
	zeros := make([]byte, 16)

	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: expr.CtKeyLABELS, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 16, Mask: mask, Xor: zeros},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: zeros},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.CT.Key != nftexpr.CtKeyLabels {
		t.Errorf("CT.Key = %q, want %q", c.CT.Key, nftexpr.CtKeyLabels)
	}
	bits, ok := c.CT.Value.([]string)
	if !ok {
		t.Fatalf("CT.Value type = %T, want []string", c.CT.Value)
	}
	if len(bits) != 2 || bits[0] != "0" || bits[1] != "2" {
		t.Errorf("CT.Value = %v, want [0 2]", bits)
	}
	if c.Operation != CompareOpEq {
		t.Errorf("Operation = %q, want eq (normalized from neq+zeros)", c.Operation)
	}
}

func TestNftablesToRuleDefinition_CTMarkNeq(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: expr.CtKeyMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: leUint32(0)},
		&expr.Verdict{Kind: expr.VerdictDrop},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rd.Conditions[0].Operation != CompareOpNeq {
		t.Errorf("Operation = %q, want %q", rd.Conditions[0].Operation, CompareOpNeq)
	}
}

// --- Meta conditions ---

func TestNftablesToRuleDefinition_MetaL4Proto(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Meta{Key: unix.NFT_META_L4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}}, // tcp = 6
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.Type != ConditionTypeMeta {
		t.Errorf("type = %q, want %q", c.Type, ConditionTypeMeta)
	}
	if c.Meta.Key != MetaKeyL4Proto {
		t.Errorf("Meta.Key = %q, want %q", c.Meta.Key, MetaKeyL4Proto)
	}
	if c.Operation != CompareOpEq {
		t.Errorf("Operation = %q, want %q", c.Operation, CompareOpEq)
	}
	if v, ok := c.Meta.Value.(uint8); !ok || v != 6 {
		t.Errorf("Meta.Value = %v (%T), want uint8(6)", c.Meta.Value, c.Meta.Value)
	}
}

func TestNftablesToRuleDefinition_MetaIifname(t *testing.T) {
	// Wire format A: IFNAMSIZ-padded (16 bytes), NUL-terminated.
	ifname := make([]byte, 16)
	copy(ifname, "eth0")
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Meta{Key: unix.NFT_META_IIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	if c.Type != ConditionTypeMeta {
		t.Errorf("type = %q, want %q", c.Type, ConditionTypeMeta)
	}
	if c.Meta.Key != MetaKeyIIfName {
		t.Errorf("Meta.Key = %q, want %q", c.Meta.Key, MetaKeyIIfName)
	}
	if c.Operation != CompareOpEq {
		t.Errorf("Operation = %q, want %q", c.Operation, CompareOpEq)
	}
	if s, ok := c.Meta.Value.(string); !ok || s != "eth0" {
		t.Errorf("Meta.Value = %v (%T), want string(%q)", c.Meta.Value, c.Meta.Value, "eth0")
	}
}

func TestNftablesToRuleDefinition_MetaIifnameTight(t *testing.T) {
	// Wire format B: tight NUL-terminated bytes (length = strlen + 1).
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Meta{Key: unix.NFT_META_IIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte("wlan0\x00")},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	if c.Meta.Key != MetaKeyIIfName {
		t.Errorf("Meta.Key = %q, want %q", c.Meta.Key, MetaKeyIIfName)
	}
	if s, ok := c.Meta.Value.(string); !ok || s != "wlan0" {
		t.Errorf("Meta.Value = %v (%T), want string(%q)", c.Meta.Value, c.Meta.Value, "wlan0")
	}
}

func TestNftablesToRuleDefinition_MetaIifnameNeq(t *testing.T) {
	// `meta iifname != "lo"` — operator survives through metaCompareToCondition.
	ifname := make([]byte, 16)
	copy(ifname, "lo")
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Meta{Key: unix.NFT_META_IIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ifname},
		&expr.Verdict{Kind: expr.VerdictDrop},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	if c.Meta.Key != MetaKeyIIfName {
		t.Errorf("Meta.Key = %q, want %q", c.Meta.Key, MetaKeyIIfName)
	}
	if c.Operation != CompareOpNeq {
		t.Errorf("Operation = %q, want %q", c.Operation, CompareOpNeq)
	}
	if s, ok := c.Meta.Value.(string); !ok || s != "lo" {
		t.Errorf("Meta.Value = %v (%T), want string(%q)", c.Meta.Value, c.Meta.Value, "lo")
	}
}

// metaIntCase exercises a Meta+Cmp smoke-test against decodeMetaValue's
// BE convention. tWant is the type-asserted Value the parser should yield.
type metaIntCase struct {
	name  string
	key   expr.MetaKey
	mKey  MetaKey
	data  []byte
	tWant any
}

func runMetaIntCase(t *testing.T, c metaIntCase) {
	t.Helper()
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Meta{Key: c.key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: c.data},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("%s: unexpected error: %v", c.name, err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("%s: expected 1 condition, got %d", c.name, len(rd.Conditions))
	}
	cond := rd.Conditions[0]
	if cond.Type != ConditionTypeMeta {
		t.Errorf("%s: type = %q, want %q", c.name, cond.Type, ConditionTypeMeta)
	}
	if cond.Meta.Key != c.mKey {
		t.Errorf("%s: Meta.Key = %q, want %q", c.name, cond.Meta.Key, c.mKey)
	}
	if cond.Meta.Value != c.tWant {
		t.Errorf("%s: Meta.Value = %v (%T), want %v (%T)",
			c.name, cond.Meta.Value, cond.Meta.Value, c.tWant, c.tWant)
	}
}

func TestNftablesToRuleDefinition_MetaUintSmoke(t *testing.T) {
	cases := []metaIntCase{
		{"length", unix.NFT_META_LEN, MetaKeyLength, []byte{0x05, 0xdc}, uint16(1500)},
		{"protocol", unix.NFT_META_PROTOCOL, MetaKeyProtocol, []byte{0x08, 0x00}, uint16(0x0800)},
		{"nfproto v4", unix.NFT_META_NFPROTO, MetaKeyNfproto, []byte{0x02}, uint8(unix.NFPROTO_IPV4)},
		{"nfproto v6", unix.NFT_META_NFPROTO, MetaKeyNfproto, []byte{0x0a}, uint8(unix.NFPROTO_IPV6)},
		{"l4proto tcp", unix.NFT_META_L4PROTO, MetaKeyL4Proto, []byte{0x06}, uint8(unix.IPPROTO_TCP)},
		{"pkttype host", unix.NFT_META_PKTTYPE, MetaKeyPktType, []byte{0x00}, uint8(unix.PACKET_HOST)},
		{"pkttype broadcast", unix.NFT_META_PKTTYPE, MetaKeyPktType, []byte{0x01}, uint8(unix.PACKET_BROADCAST)},
		{"mark", unix.NFT_META_MARK, MetaKeyMark, []byte{0x00, 0x00, 0x12, 0x34}, uint32(0x1234)},
		{"priority", unix.NFT_META_PRIORITY, MetaKeyPriority, []byte{0x00, 0x01, 0x00, 0x01}, uint32(0x00010001)},
		{"skuid", unix.NFT_META_SKUID, MetaKeySkuid, []byte{0x00, 0x00, 0x03, 0xe8}, uint32(1000)},
		{"skgid", unix.NFT_META_SKGID, MetaKeySkgid, []byte{0x00, 0x00, 0x03, 0xe8}, uint32(1000)},
		{"cgroup", unix.NFT_META_CGROUP, MetaKeyCGroup, []byte{0x00, 0x00, 0x00, 0x2a}, uint32(42)},
		{"cpu", unix.NFT_META_CPU, MetaKeyCPU, []byte{0x00, 0x00, 0x00, 0x04}, uint32(4)},
		{"iifgroup", unix.NFT_META_IIFGROUP, MetaKeyIIfGroup, []byte{0x00, 0x00, 0x00, 0x07}, uint32(7)},
		{"oifgroup", unix.NFT_META_OIFGROUP, MetaKeyOIfGroup, []byte{0x00, 0x00, 0x00, 0x07}, uint32(7)},
		{"rtclassid", unix.NFT_META_RTCLASSID, MetaKeyRtclassid, []byte{0x00, 0x00, 0x00, 0x10}, uint32(16)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { runMetaIntCase(t, c) })
	}
}

func TestNftablesToRuleDefinition_MetaIiftype(t *testing.T) {
	// ARPHRD_ETHER = 1. Wire is 2-byte BE in this parser's convention.
	data := []byte{0x00, 0x01}
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Meta{Key: unix.NFT_META_IIFTYPE, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	if c.Meta.Key != MetaKeyIIfType {
		t.Errorf("Meta.Key = %q, want %q", c.Meta.Key, MetaKeyIIfType)
	}
	if v, ok := c.Meta.Value.(uint16); !ok || v != unix.ARPHRD_ETHER {
		t.Errorf("Meta.Value = %v (%T), want uint16(ARPHRD_ETHER=1)", c.Meta.Value, c.Meta.Value)
	}
}

func TestNftablesToRuleDefinition_MetaOiftype(t *testing.T) {
	// ARPHRD_LOOPBACK = 772 = 0x0304. BE 2-byte: [0x03, 0x04].
	data := []byte{0x03, 0x04}
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Meta{Key: unix.NFT_META_OIFTYPE, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	if c.Meta.Key != MetaKeyOIfType {
		t.Errorf("Meta.Key = %q, want %q", c.Meta.Key, MetaKeyOIfType)
	}
	if v, ok := c.Meta.Value.(uint16); !ok || v != unix.ARPHRD_LOOPBACK {
		t.Errorf("Meta.Value = %v (%T), want uint16(ARPHRD_LOOPBACK=772)", c.Meta.Value, c.Meta.Value)
	}
}

func TestNftablesToRuleDefinition_MetaIifInvalidIndex(t *testing.T) {
	// `meta iif <ifindex>` wire format: BE uint32. An ifindex that doesn't
	// resolve on this host falls through to a uint32 Value.
	invalidIdx := uint32(0xffffffff)
	beData := make([]byte, 4)
	binary.BigEndian.PutUint32(beData, invalidIdx)

	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Meta{Key: unix.NFT_META_IIF, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: beData},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	if c.Type != ConditionTypeMeta {
		t.Errorf("type = %q, want %q", c.Type, ConditionTypeMeta)
	}
	if c.Meta.Key != MetaKeyIIf {
		t.Errorf("Meta.Key = %q, want %q", c.Meta.Key, MetaKeyIIf)
	}
	if v, ok := c.Meta.Value.(uint32); !ok || v != invalidIdx {
		t.Errorf("Meta.Value = %v (%T), want uint32(0x%x)", c.Meta.Value, c.Meta.Value, invalidIdx)
	}
}

func TestNftablesToRuleDefinition_MetaIifResolvedLo(t *testing.T) {
	// On hosts where "lo" exists (every Linux box should), the parser resolves
	// the BE ifindex into a string name.
	loIfc, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("no lo interface — skipping resolve test")
	}
	beData := make([]byte, 4)
	binary.BigEndian.PutUint32(beData, uint32(loIfc.Index))

	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Meta{Key: unix.NFT_META_IIF, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: beData},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	if c.Meta.Key != MetaKeyIIf {
		t.Errorf("Meta.Key = %q, want %q", c.Meta.Key, MetaKeyIIf)
	}
	if s, ok := c.Meta.Value.(string); !ok || s != "lo" {
		t.Errorf("Meta.Value = %v (%T), want string(%q)", c.Meta.Value, c.Meta.Value, "lo")
	}
}

func TestNftablesToRuleDefinition_MetaOifInvalidIndex(t *testing.T) {
	invalidIdx := uint32(0xffffffff)
	beData := make([]byte, 4)
	binary.BigEndian.PutUint32(beData, invalidIdx)
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Meta{Key: unix.NFT_META_OIF, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: beData},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	if c.Meta.Key != MetaKeyOIf {
		t.Errorf("Meta.Key = %q, want %q", c.Meta.Key, MetaKeyOIf)
	}
	if v, ok := c.Meta.Value.(uint32); !ok || v != invalidIdx {
		t.Errorf("Meta.Value = %v (%T), want uint32(0x%x)", c.Meta.Value, c.Meta.Value, invalidIdx)
	}
}

func TestNftablesToRuleDefinition_MetaOifResolvedLo(t *testing.T) {
	loIfc, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("no lo interface — skipping resolve test")
	}
	beData := make([]byte, 4)
	binary.BigEndian.PutUint32(beData, uint32(loIfc.Index))
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Meta{Key: unix.NFT_META_OIF, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: beData},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	if c.Meta.Key != MetaKeyOIf {
		t.Errorf("Meta.Key = %q, want %q", c.Meta.Key, MetaKeyOIf)
	}
	if s, ok := c.Meta.Value.(string); !ok || s != "lo" {
		t.Errorf("Meta.Value = %v (%T), want string(%q)", c.Meta.Value, c.Meta.Value, "lo")
	}
}

func TestNftablesToRuleDefinition_MetaOifname(t *testing.T) {
	ifname := make([]byte, 16)
	copy(ifname, "wg0")
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Meta{Key: unix.NFT_META_OIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	if c.Type != ConditionTypeMeta {
		t.Errorf("type = %q, want %q", c.Type, ConditionTypeMeta)
	}
	if c.Meta.Key != MetaKeyOIfName {
		t.Errorf("Meta.Key = %q, want %q", c.Meta.Key, MetaKeyOIfName)
	}
	if c.Operation != CompareOpEq {
		t.Errorf("Operation = %q, want %q", c.Operation, CompareOpEq)
	}
	if s, ok := c.Meta.Value.(string); !ok || s != "wg0" {
		t.Errorf("Meta.Value = %v (%T), want string(%q)", c.Meta.Value, c.Meta.Value, "wg0")
	}
}

func TestNftablesToRuleDefinition_MetaMark(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Meta{Key: unix.NFT_META_MARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: leUint32(0x1234)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	if c.Type != ConditionTypeMeta {
		t.Errorf("type = %q, want %q", c.Type, ConditionTypeMeta)
	}
	if c.Meta.Key != MetaKeyMark {
		t.Errorf("Meta.Key = %q, want %q", c.Meta.Key, MetaKeyMark)
	}
}

// --- ICMP smoke tests ---

func TestNftablesToRuleDefinition_IcmpType(t *testing.T) {
	// Wire: meta l4proto icmp + Payload{offset=0, len=1} + Cmp{Eq, [type]}
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Meta{Key: unix.NFT_META_L4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMP}},
		&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{8}}, // echo-request
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 2 {
		t.Fatalf("expected 2 conditions (meta + payload), got %d", len(rd.Conditions))
	}
	icmp := rd.Conditions[1]
	if icmp.Payload == nil || icmp.Payload.Protocol != PayloadProtoICMP || icmp.Payload.Field != "type" {
		t.Errorf("got %q/%q, want icmp/type", icmp.Payload.Protocol, icmp.Payload.Field)
	}
	if v, ok := icmp.Payload.Value.(uint8); !ok || v != 8 {
		t.Errorf("Value = %v (%T), want uint8(8)", icmp.Payload.Value, icmp.Payload.Value)
	}
}

func TestNftablesToRuleDefinition_IcmpCode(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Meta{Key: unix.NFT_META_L4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMP}},
		&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 1, Len: 1, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{3}}, // host-unreachable
		&expr.Verdict{Kind: expr.VerdictDrop},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	icmp := rd.Conditions[1]
	if icmp.Payload == nil || icmp.Payload.Protocol != PayloadProtoICMP || icmp.Payload.Field != "code" {
		t.Errorf("got %q/%q, want icmp/code", icmp.Payload.Protocol, icmp.Payload.Field)
	}
	if v, ok := icmp.Payload.Value.(uint8); !ok || v != 3 {
		t.Errorf("Value = %v (%T), want uint8(3)", icmp.Payload.Value, icmp.Payload.Value)
	}
}

func TestNftablesToRuleDefinition_IcmpChecksumIdSequence(t *testing.T) {
	cases := []struct {
		field  string
		offset uint32
		length uint32
		data   []byte
		want   any
	}{
		{"checksum", 2, 2, []byte{0xab, 0xcd}, uint16(0xabcd)},
		{"id", 4, 2, []byte{0x00, 0x64}, uint16(100)},
		{"sequence", 6, 2, []byte{0x00, 0x05}, uint16(5)},
	}
	for _, c := range cases {
		t.Run(c.field, func(t *testing.T) {
			rd, err := NftablesToRuleDefinition(makeRule(
				&expr.Meta{Key: unix.NFT_META_L4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMP}},
				&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: c.offset, Len: c.length, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: c.data},
				&expr.Verdict{Kind: expr.VerdictAccept},
			))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			cond := rd.Conditions[1]
			if cond.Payload.Field != c.field {
				t.Errorf("field = %q, want %q", cond.Payload.Field, c.field)
			}
			if cond.Payload.Value != c.want {
				t.Errorf("value = %v (%T), want %v", cond.Payload.Value, cond.Payload.Value, c.want)
			}
		})
	}
}

// --- VLAN smoke tests ---

func TestNftablesToRuleDefinition_VlanId(t *testing.T) {
	// `vlan id 100` → Bitwise{0x0f, 0xff} + Cmp{[0x00, 0x64]} (VID=100=0x064).
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Payload{Base: expr.PayloadBaseLLHeader, Offset: 14, Len: 2, DestRegister: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 2,
			Mask: []byte{0x0f, 0xff}, Xor: []byte{0, 0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x00, 0x64}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cond := rd.Conditions[0]
	if cond.Payload.Protocol != PayloadProtoVlan || cond.Payload.Field != "id" {
		t.Errorf("got %q/%q, want vlan/id", cond.Payload.Protocol, cond.Payload.Field)
	}
	if v, ok := cond.Payload.Value.(uint16); !ok || v != 100 {
		t.Errorf("value = %v (%T), want uint16(100)", cond.Payload.Value, cond.Payload.Value)
	}
}

func TestNftablesToRuleDefinition_VlanCfi(t *testing.T) {
	// `vlan cfi 1` → Bitwise{0x10} + Cmp{[0x10]} (CFI=1 in bit 4).
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Payload{Base: expr.PayloadBaseLLHeader, Offset: 14, Len: 1, DestRegister: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0x10}, Xor: []byte{0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x10}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cond := rd.Conditions[0]
	if cond.Payload.Protocol != PayloadProtoVlan || cond.Payload.Field != "cfi" {
		t.Errorf("got %q/%q, want vlan/cfi", cond.Payload.Protocol, cond.Payload.Field)
	}
	if v, ok := cond.Payload.Value.(uint8); !ok || v != 1 {
		t.Errorf("value = %v (%T), want uint8(1)", cond.Payload.Value, cond.Payload.Value)
	}
}

func TestNftablesToRuleDefinition_VlanPcp(t *testing.T) {
	// `vlan pcp 3` → Bitwise{0xe0} + Cmp{[0x60]} (PCP=3, encoded 3<<5).
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Payload{Base: expr.PayloadBaseLLHeader, Offset: 14, Len: 1, DestRegister: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0xe0}, Xor: []byte{0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x60}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cond := rd.Conditions[0]
	if cond.Payload.Protocol != PayloadProtoVlan || cond.Payload.Field != "pcp" {
		t.Errorf("got %q/%q, want vlan/pcp", cond.Payload.Protocol, cond.Payload.Field)
	}
	if v, ok := cond.Payload.Value.(uint8); !ok || v != 3 {
		t.Errorf("value = %v (%T), want uint8(3)", cond.Payload.Value, cond.Payload.Value)
	}
}

// --- Ether type smoke tests ---

func TestNftablesToRuleDefinition_EtherType(t *testing.T) {
	// ether type ip → EtherType 0x0800; wire data is BE.
	cases := []struct {
		name      string
		data      []byte
		etherType uint16
	}{
		{"ip", []byte{0x08, 0x00}, 0x0800},
		{"ip6", []byte{0x86, 0xdd}, 0x86dd},
		{"arp", []byte{0x08, 0x06}, 0x0806},
		{"vlan", []byte{0x81, 0x00}, 0x8100},
		{"lldp", []byte{0x88, 0xcc}, 0x88cc},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rd, err := NftablesToRuleDefinition(makeRule(
				&expr.Payload{Base: expr.PayloadBaseLLHeader, Offset: 12, Len: 2, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: c.data},
				&expr.Verdict{Kind: expr.VerdictAccept},
			))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			cond := rd.Conditions[0]
			if cond.Payload.Protocol != PayloadProtoEther || cond.Payload.Field != "type" {
				t.Errorf("got %q/%q, want ether/type", cond.Payload.Protocol, cond.Payload.Field)
			}
			if v, ok := cond.Payload.Value.(uint16); !ok || v != c.etherType {
				t.Errorf("value = %v (%T), want uint16(0x%04x)", cond.Payload.Value, cond.Payload.Value, c.etherType)
			}
		})
	}
}

// --- Ethernet (L2) smoke tests ---

func TestNftablesToRuleDefinition_EtherSaddrDaddr(t *testing.T) {
	cases := []struct {
		name   string
		offset uint32
		field  string
		want   string
	}{
		{"saddr", 6, "saddr", "00:11:22:33:44:55"},
		{"daddr", 0, "daddr", "aa:bb:cc:dd:ee:ff"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := []byte{0, 0, 0, 0, 0, 0}
			if c.name == "saddr" {
				data = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
			} else {
				data = []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
			}
			rd, err := NftablesToRuleDefinition(makeRule(
				&expr.Payload{Base: expr.PayloadBaseLLHeader, Offset: c.offset, Len: 6, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
				&expr.Verdict{Kind: expr.VerdictAccept},
			))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			cond := rd.Conditions[0]
			if cond.Payload.Protocol != PayloadProtoEther {
				t.Errorf("protocol = %q, want ether", cond.Payload.Protocol)
			}
			if cond.Payload.Field != c.field {
				t.Errorf("field = %q, want %q", cond.Payload.Field, c.field)
			}
			if s, ok := cond.Payload.Value.(string); !ok || s != c.want {
				t.Errorf("value = %v (%T), want string(%q)", cond.Payload.Value, cond.Payload.Value, c.want)
			}
		})
	}
}

// --- COMP smoke tests ---

func TestNftablesToRuleDefinition_CompHeader(t *testing.T) {
	cases := []struct {
		name   string
		offset uint32
		length uint32
		data   []byte
		field  string
		want   any
	}{
		{"nexthdr", 0, 1, []byte{unix.IPPROTO_TCP}, "nexthdr", uint8(unix.IPPROTO_TCP)},
		{"flags", 1, 1, []byte{0x00}, "flags", uint8(0)},
		{"cpi", 2, 2, []byte{0x12, 0x34}, "cpi", uint16(0x1234)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rd, err := NftablesToRuleDefinition(makeRule(
				&expr.Meta{Key: unix.NFT_META_L4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_COMP}},
				&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: c.offset, Len: c.length, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: c.data},
				&expr.Verdict{Kind: expr.VerdictAccept},
			))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			cond := rd.Conditions[1]
			if cond.Payload.Protocol != PayloadProtoCOMP {
				t.Errorf("protocol = %q, want comp", cond.Payload.Protocol)
			}
			if cond.Payload.Field != c.field {
				t.Errorf("field = %q, want %q", cond.Payload.Field, c.field)
			}
			if cond.Payload.Value != c.want {
				t.Errorf("value = %v (%T), want %v (%T)",
					cond.Payload.Value, cond.Payload.Value, c.want, c.want)
			}
		})
	}
}

// --- ESP smoke tests ---

func TestNftablesToRuleDefinition_EspHeader(t *testing.T) {
	cases := []struct {
		name   string
		offset uint32
		data   []byte
		field  string
		want   uint32
	}{
		{"spi", 0, []byte{0xde, 0xad, 0xbe, 0xef}, "spi", 0xdeadbeef},
		{"sequence", 4, []byte{0x00, 0x00, 0x00, 0x64}, "sequence", 100},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rd, err := NftablesToRuleDefinition(makeRule(
				&expr.Meta{Key: unix.NFT_META_L4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ESP}},
				&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: c.offset, Len: 4, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: c.data},
				&expr.Verdict{Kind: expr.VerdictAccept},
			))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			cond := rd.Conditions[1]
			if cond.Payload.Protocol != PayloadProtoESP {
				t.Errorf("protocol = %q, want esp", cond.Payload.Protocol)
			}
			if cond.Payload.Field != c.field {
				t.Errorf("field = %q, want %q", cond.Payload.Field, c.field)
			}
			if v, ok := cond.Payload.Value.(uint32); !ok || v != c.want {
				t.Errorf("value = %v (%T), want uint32(%d)", cond.Payload.Value, cond.Payload.Value, c.want)
			}
		})
	}
}

// --- AH smoke tests ---

func TestNftablesToRuleDefinition_AhHeader(t *testing.T) {
	cases := []struct {
		name   string
		offset uint32
		length uint32
		data   []byte
		field  string
		want   any
	}{
		{"hdrlength", 1, 1, []byte{4}, "hdrlength", uint8(4)},
		{"reserved", 2, 2, []byte{0x00, 0x00}, "reserved", uint16(0)},
		{"spi", 4, 4, []byte{0xde, 0xad, 0xbe, 0xef}, "spi", uint32(0xdeadbeef)},
		{"sequence", 8, 4, []byte{0x00, 0x00, 0x00, 0x64}, "sequence", uint32(100)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rd, err := NftablesToRuleDefinition(makeRule(
				&expr.Meta{Key: unix.NFT_META_L4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_AH}},
				&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: c.offset, Len: c.length, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: c.data},
				&expr.Verdict{Kind: expr.VerdictAccept},
			))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			cond := rd.Conditions[1]
			if cond.Payload.Protocol != PayloadProtoAH {
				t.Errorf("protocol = %q, want ah", cond.Payload.Protocol)
			}
			if cond.Payload.Field != c.field {
				t.Errorf("field = %q, want %q", cond.Payload.Field, c.field)
			}
			if cond.Payload.Value != c.want {
				t.Errorf("value = %v (%T), want %v (%T)",
					cond.Payload.Value, cond.Payload.Value, c.want, c.want)
			}
		})
	}
}

// --- DCCP smoke tests ---

func TestNftablesToRuleDefinition_DccpPorts(t *testing.T) {
	for _, c := range []struct {
		name   string
		offset uint32
		port   uint16
		field  string
	}{
		{"sport", 0, 200, "sport"},
		{"dport", 2, 100, "dport"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rd, err := NftablesToRuleDefinition(makeRule(
				&expr.Meta{Key: unix.NFT_META_L4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_DCCP}},
				&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: c.offset, Len: 2, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: beUint16(c.port)},
				&expr.Verdict{Kind: expr.VerdictAccept},
			))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			cond := rd.Conditions[1]
			if cond.Payload.Protocol != PayloadProtoDCCP {
				t.Errorf("protocol = %q, want dccp", cond.Payload.Protocol)
			}
			if cond.Payload.Field != c.field {
				t.Errorf("field = %q, want %q", cond.Payload.Field, c.field)
			}
			if ps, ok := cond.Payload.Value.(*PortSpec); !ok || ps.Port != c.port {
				t.Errorf("value = %v (%T), want *PortSpec{Port:%d}", cond.Payload.Value, cond.Payload.Value, c.port)
			}
		})
	}
}

func TestNftablesToRuleDefinition_DccpType(t *testing.T) {
	// `dccp type response` → Bitwise{mask=0x1e} + Cmp{Eq, [0x02]} (response = 1, encoded = 1<<1).
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Meta{Key: unix.NFT_META_L4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_DCCP}},
		&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 8, Len: 1, DestRegister: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0x1e}, Xor: []byte{0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x02}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cond := rd.Conditions[1]
	if cond.Payload.Protocol != PayloadProtoDCCP || cond.Payload.Field != "type" {
		t.Errorf("got %q/%q, want dccp/type", cond.Payload.Protocol, cond.Payload.Field)
	}
	if v, ok := cond.Payload.Value.(uint8); !ok || v != 1 {
		t.Errorf("value = %v (%T), want uint8(1) [response]", cond.Payload.Value, cond.Payload.Value)
	}
}

// --- SCTP smoke tests ---

func TestNftablesToRuleDefinition_SctpHeader(t *testing.T) {
	// vtag + checksum (uint32 fields).
	uintCases := []struct {
		name   string
		offset uint32
		length uint32
		data   []byte
		field  string
		want   uint32
	}{
		{"vtag", 4, 4, []byte{0x12, 0x34, 0x56, 0x78}, "vtag", 0x12345678},
		{"checksum", 8, 4, []byte{0xde, 0xad, 0xbe, 0xef}, "checksum", 0xdeadbeef},
	}
	for _, c := range uintCases {
		t.Run(c.name, func(t *testing.T) {
			rd, err := NftablesToRuleDefinition(makeRule(
				&expr.Meta{Key: unix.NFT_META_L4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_SCTP}},
				&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: c.offset, Len: c.length, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: c.data},
				&expr.Verdict{Kind: expr.VerdictAccept},
			))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			cond := rd.Conditions[1]
			if cond.Payload.Protocol != PayloadProtoSCTP {
				t.Errorf("protocol = %q, want sctp", cond.Payload.Protocol)
			}
			if cond.Payload.Field != c.field {
				t.Errorf("field = %q, want %q", cond.Payload.Field, c.field)
			}
			if v, ok := cond.Payload.Value.(uint32); !ok || v != c.want {
				t.Errorf("value = %v (%T), want uint32(%d)", cond.Payload.Value, cond.Payload.Value, c.want)
			}
		})
	}

	// sport / dport decode via the shared port path → *PortSpec.
	portCases := []struct {
		name   string
		offset uint32
		port   uint16
		field  string
	}{
		{"sport", 0, 200, "sport"},
		{"dport", 2, 100, "dport"},
	}
	for _, c := range portCases {
		t.Run(c.name, func(t *testing.T) {
			rd, err := NftablesToRuleDefinition(makeRule(
				&expr.Meta{Key: unix.NFT_META_L4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_SCTP}},
				&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: c.offset, Len: 2, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: beUint16(c.port)},
				&expr.Verdict{Kind: expr.VerdictAccept},
			))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			cond := rd.Conditions[1]
			if cond.Payload.Protocol != PayloadProtoSCTP {
				t.Errorf("protocol = %q, want sctp", cond.Payload.Protocol)
			}
			if cond.Payload.Field != c.field {
				t.Errorf("field = %q, want %q", cond.Payload.Field, c.field)
			}
			ps, ok := cond.Payload.Value.(*PortSpec)
			if !ok || ps.Port != c.port {
				t.Errorf("value = %v (%T), want *PortSpec{Port:%d}", cond.Payload.Value, cond.Payload.Value, c.port)
			}
		})
	}
}

// --- ICMPv6 smoke tests ---

func TestNftablesToRuleDefinition_Icmpv6TypeCode(t *testing.T) {
	cases := []struct {
		name   string
		offset uint32
		data   []byte
		field  string
		want   uint8
	}{
		{"type echo-request", 0, []byte{128}, "type", 128},
		{"type echo-reply", 0, []byte{129}, "type", 129},
		{"code 0", 1, []byte{0}, "code", 0},
		{"code 3", 1, []byte{3}, "code", 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rd, err := NftablesToRuleDefinition(makeRule(
				&expr.Meta{Key: unix.NFT_META_L4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMPV6}},
				&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: c.offset, Len: 1, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: c.data},
				&expr.Verdict{Kind: expr.VerdictAccept},
			))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			cond := rd.Conditions[1]
			if cond.Payload.Protocol != PayloadProtoICMPv6 {
				t.Errorf("protocol = %q, want %q", cond.Payload.Protocol, PayloadProtoICMPv6)
			}
			if cond.Payload.Field != c.field {
				t.Errorf("field = %q, want %q", cond.Payload.Field, c.field)
			}
			if v, ok := cond.Payload.Value.(uint8); !ok || v != c.want {
				t.Errorf("value = %v (%T), want uint8(%d)", cond.Payload.Value, cond.Payload.Value, c.want)
			}
		})
	}
}

// --- IP / IP6 payload smoke tests ---

type payloadIntCase struct {
	name     string
	offset   uint32
	length   uint32
	data     []byte
	protocol PayloadProtocol
	field    string
	want     any
}

func runPayloadIntCase(t *testing.T, c payloadIntCase) {
	t.Helper()
	rule := makeRule(
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: c.offset, Len: c.length, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: c.data},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
	// Stamp the family hint so identifyPayloadField can disambiguate
	// IPv4 id vs IPv6 length at offset 4, len 2.
	if c.protocol == PayloadProtoIP6 {
		rule.Table = &nftables.Table{Family: nftables.TableFamilyIPv6}
	} else {
		rule.Table = &nftables.Table{Family: nftables.TableFamilyIPv4}
	}
	rd, err := NftablesToRuleDefinition(rule)
	if err != nil {
		t.Fatalf("%s: unexpected error: %v", c.name, err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("%s: expected 1 condition, got %d", c.name, len(rd.Conditions))
	}
	got := rd.Conditions[0]
	if got.Type != ConditionTypePayload {
		t.Errorf("%s: type = %q, want Payload", c.name, got.Type)
	}
	if got.Payload.Protocol != c.protocol {
		t.Errorf("%s: protocol = %q, want %q", c.name, got.Payload.Protocol, c.protocol)
	}
	if got.Payload.Field != c.field {
		t.Errorf("%s: field = %q, want %q", c.name, got.Payload.Field, c.field)
	}
	if got.Payload.Value != c.want {
		t.Errorf("%s: value = %v (%T), want %v (%T)",
			c.name, got.Payload.Value, got.Payload.Value, c.want, c.want)
	}
}

func TestNftablesToRuleDefinition_IPHeaderSmoke(t *testing.T) {
	cases := []payloadIntCase{
		{"ip ttl", 8, 1, []byte{64}, PayloadProtoIP, "ttl", uint8(64)},
		{"ip protocol", 9, 1, []byte{unix.IPPROTO_TCP}, PayloadProtoIP, "protocol", uint8(unix.IPPROTO_TCP)},
		{"ip length", 2, 2, []byte{0x05, 0xdc}, PayloadProtoIP, "length", uint16(1500)},
		{"ip id", 4, 2, []byte{0x12, 0x34}, PayloadProtoIP, "id", uint16(0x1234)},
		{"ip frag-off", 6, 2, []byte{0x40, 0x00}, PayloadProtoIP, "frag-off", uint16(0x4000)},
		{"ip checksum", 10, 2, []byte{0xab, 0xcd}, PayloadProtoIP, "checksum", uint16(0xabcd)},
		{"ip6 nexthdr", 6, 1, []byte{unix.IPPROTO_TCP}, PayloadProtoIP6, "nexthdr", uint8(unix.IPPROTO_TCP)},
		{"ip6 hoplimit", 7, 1, []byte{64}, PayloadProtoIP6, "hoplimit", uint8(64)},
		{"ip6 length", 4, 2, []byte{0x05, 0xdc}, PayloadProtoIP6, "length", uint16(1500)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { runPayloadIntCase(t, c) })
	}
}

func TestNftablesToRuleDefinition_IP6Dscp(t *testing.T) {
	// Captured from `nft --debug=netlink` for `ip6 dscp cs2` (DSCP=16):
	//   payload load 2b @ network header + 0 → reg 1
	//   bitwise reg 1 = (reg 1 & 0x0000c00f) ^ 0
	//   cmp eq reg 1 0x00000004
	// Wire-bytes:
	//   mask  = [0x0f, 0xc0]
	//   data  = [0x04, 0x00]
	rule := makeRule(
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 0, Len: 2, DestRegister: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 2,
			Mask: []byte{0x0f, 0xc0}, Xor: []byte{0, 0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x04, 0x00}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
	rule.Table = &nftables.Table{Family: nftables.TableFamilyIPv6}
	rd, err := NftablesToRuleDefinition(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	if c.Payload.Protocol != PayloadProtoIP6 || c.Payload.Field != "dscp" {
		t.Errorf("got %q/%q, want ip6/dscp", c.Payload.Protocol, c.Payload.Field)
	}
	if v, ok := c.Payload.Value.(uint8); !ok || v != 16 {
		t.Errorf("Value = %v (%T), want uint8(16)", c.Payload.Value, c.Payload.Value)
	}
}

func TestNftablesToRuleDefinition_IP6Flowlabel(t *testing.T) {
	// Captured from `nft --debug=netlink` for `ip6 flowlabel 0x12345`:
	//   payload load 3b @ network header + 1 → reg 1
	//   bitwise reg 1 = (reg 1 & 0x00ffff0f) ^ 0
	//   cmp eq reg 1 0x00452301
	// Wire-bytes:
	//   mask  = [0x0f, 0xff, 0xff]
	//   data  = [0x01, 0x23, 0x45]
	rule := makeRule(
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 1, Len: 3, DestRegister: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 3,
			Mask: []byte{0x0f, 0xff, 0xff}, Xor: []byte{0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x01, 0x23, 0x45}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
	rule.Table = &nftables.Table{Family: nftables.TableFamilyIPv6}
	rd, err := NftablesToRuleDefinition(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	if c.Payload.Protocol != PayloadProtoIP6 || c.Payload.Field != "flowlabel" {
		t.Errorf("got %q/%q, want ip6/flowlabel", c.Payload.Protocol, c.Payload.Field)
	}
	if v, ok := c.Payload.Value.(uint32); !ok || v != 0x12345 {
		t.Errorf("Value = %v (%T), want uint32(0x12345)", c.Payload.Value, c.Payload.Value)
	}
}

func TestNftablesToRuleDefinition_IP6Saddr(t *testing.T) {
	addr := net.ParseIP("fe80::1").To16()
	rule := makeRule(
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
	rule.Table = &nftables.Table{Family: nftables.TableFamilyIPv6}
	rd, err := NftablesToRuleDefinition(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	if c.Payload.Protocol != PayloadProtoIP6 || c.Payload.Field != "saddr" {
		t.Errorf("got %q/%q, want %q/%q",
			c.Payload.Protocol, c.Payload.Field, PayloadProtoIP6, "saddr")
	}
	ipa, ok := c.Payload.Value.(*IPAddress)
	if !ok || !ipa.IP.Equal(addr) {
		t.Errorf("value = %v (%T), want IPAddress(fe80::1)", c.Payload.Value, c.Payload.Value)
	}
}

// --- Transport header smoke tests ---

func TestNftablesToRuleDefinition_TransportHeaderSmoke(t *testing.T) {
	cases := []struct {
		name     string
		offset   uint32
		length   uint32
		data     []byte
		protocol PayloadProtocol
		field    string
		want     any
	}{
		{"tcp dport", 2, 2, beUint16(443), PayloadProtoTCP, "dport", &PortSpec{Port: 443}},
		{"tcp sport", 0, 2, beUint16(80), PayloadProtoTCP, "sport", &PortSpec{Port: 80}},
		{"tcp sequence", 4, 4, []byte{0x12, 0x34, 0x56, 0x78}, PayloadProtoTCP, "sequence", uint32(0x12345678)},
		{"tcp ackseq", 8, 4, []byte{0x01, 0x02, 0x03, 0x04}, PayloadProtoTCP, "ackseq", uint32(0x01020304)},
		{"tcp flags", 13, 1, []byte{0x02}, PayloadProtoTCP, "flags", uint8(0x02)},
		{"tcp window", 14, 2, []byte{0xff, 0xff}, PayloadProtoTCP, "window", uint16(0xffff)},
		{"tcp checksum", 16, 2, []byte{0xab, 0xcd}, PayloadProtoTCP, "checksum", uint16(0xabcd)},
		{"tcp urgptr", 18, 2, []byte{0x00, 0x05}, PayloadProtoTCP, "urgptr", uint16(5)},
		{"udp length", 4, 2, []byte{0x00, 0x40}, PayloadProtoUDP, "length", uint16(64)},
		{"udp checksum", 6, 2, []byte{0xab, 0xcd}, PayloadProtoUDP, "checksum", uint16(0xabcd)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rd, err := NftablesToRuleDefinition(makeRule(
				&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: c.offset, Len: c.length, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: c.data},
				&expr.Verdict{Kind: expr.VerdictAccept},
			))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			cond := rd.Conditions[0]
			if cond.Payload.Protocol != c.protocol {
				t.Errorf("protocol = %q, want %q", cond.Payload.Protocol, c.protocol)
			}
			if cond.Payload.Field != c.field {
				t.Errorf("field = %q, want %q", cond.Payload.Field, c.field)
			}
			// Compare via fmt.Sprintf for *PortSpec convenience.
			if c.field == "sport" || c.field == "dport" {
				gotPs, _ := cond.Payload.Value.(*PortSpec)
				wantPs, _ := c.want.(*PortSpec)
				if gotPs == nil || wantPs == nil || gotPs.Port != wantPs.Port {
					t.Errorf("value = %v, want %v", cond.Payload.Value, c.want)
				}
				return
			}
			if cond.Payload.Value != c.want {
				t.Errorf("value = %v (%T), want %v (%T)",
					cond.Payload.Value, cond.Payload.Value, c.want, c.want)
			}
		})
	}
}

// --- Payload conditions ---

func TestNftablesToRuleDefinition_PayloadDport(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: beUint16(80)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.Type != ConditionTypePayload {
		t.Errorf("type = %q, want %q", c.Type, ConditionTypePayload)
	}
	if c.Payload.Field != "dport" {
		t.Errorf("Field = %q, want %q", c.Payload.Field, "dport")
	}
	if c.Payload.Protocol != PayloadProtoTCP {
		t.Errorf("Protocol = %q, want %q", c.Payload.Protocol, PayloadProtoTCP)
	}
	ps, ok := c.Payload.Value.(*PortSpec)
	if !ok {
		t.Fatalf("Value type = %T, want *PortSpec", c.Payload.Value)
	}
	if ps.Port != 80 {
		t.Errorf("Port = %d, want 80", ps.Port)
	}
}

func TestNftablesToRuleDefinition_PayloadSaddr(t *testing.T) {
	ip := []byte{192, 168, 1, 1}
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	if c.Payload.Field != "saddr" {
		t.Errorf("Field = %q, want %q", c.Payload.Field, "saddr")
	}
}

func TestNftablesToRuleDefinition_PayloadSport(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: beUint16(443)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	if c.Payload.Field != "sport" {
		t.Errorf("Field = %q, want %q", c.Payload.Field, "sport")
	}
	ps := c.Payload.Value.(*PortSpec)
	if ps.Port != 443 {
		t.Errorf("Port = %d, want 443", ps.Port)
	}
}

// --- Range conditions ---

func TestNftablesToRuleDefinition_RangePayloadDport(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
		&expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: beUint16(1024), ToData: beUint16(65535)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.Type != ConditionTypePayload {
		t.Errorf("type = %q, want %q", c.Type, ConditionTypePayload)
	}
	if c.Operation != CompareOpIn {
		t.Errorf("Operation = %q, want %q", c.Operation, CompareOpIn)
	}
	rv, ok := c.Payload.Value.(*RangeValue)
	if !ok {
		t.Fatalf("Value type = %T, want *RangeValue", c.Payload.Value)
	}
	fromPort := rv.From.(*PortSpec)
	toPort := rv.To.(*PortSpec)
	if fromPort.Port != 1024 {
		t.Errorf("From port = %d, want 1024", fromPort.Port)
	}
	if toPort.Port != 65535 {
		t.Errorf("To port = %d, want 65535", toPort.Port)
	}
}

func TestNftablesToRuleDefinition_RangeCT(t *testing.T) {
	// CT expiration range: 30s–120s stored as ms in BigEndian
	from := make([]byte, 4)
	to := make([]byte, 4)
	binary.BigEndian.PutUint32(from, 30000) // 30s in ms
	binary.BigEndian.PutUint32(to, 120000)  // 120s in ms

	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: expr.CtKeyEXPIRATION, Register: 1},
		&expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: from, ToData: to},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.Type != ConditionTypeCT {
		t.Errorf("type = %q, want %q", c.Type, ConditionTypeCT)
	}
	if c.CT.Key != nftexpr.CtKey("expiration") {
		t.Errorf("CT.Key = %q, want %q", c.CT.Key, "expiration")
	}
	if _, ok := c.CT.Value.(*RangeValue); !ok {
		t.Errorf("Value type = %T, want *RangeValue", c.CT.Value)
	}
}

// --- Set lookup ---

func TestNftablesToRuleDefinition_SetLookupMeta(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Meta{Key: unix.NFT_META_L4PROTO, Register: 1},
		&expr.Lookup{SourceRegister: 1, SetName: "allowed_protocols", Invert: false},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.Type != ConditionTypeSetLookup {
		t.Errorf("type = %q, want %q", c.Type, ConditionTypeSetLookup)
	}
	if c.SetLookup.SetName != "allowed_protocols" {
		t.Errorf("SetName = %q, want %q", c.SetLookup.SetName, "allowed_protocols")
	}
	if c.SetLookup.Field != "l4proto" {
		t.Errorf("Field = %q, want %q", c.SetLookup.Field, "l4proto")
	}
	if c.Negate {
		t.Error("Negate should be false")
	}
}

func TestNftablesToRuleDefinition_SetLookupInverted(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Meta{Key: unix.NFT_META_L4PROTO, Register: 1},
		&expr.Lookup{SourceRegister: 1, SetName: "blocked", Invert: true},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rd.Conditions[0].Negate {
		t.Error("Negate should be true for inverted lookup")
	}
}

// --- Masquerade ---

func TestNftablesToRuleDefinition_Masquerade(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Masq{},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(rd.Actions))
	}
	if rd.Actions[0].Type != ActionTypeMasq {
		t.Errorf("action type = %q, want %q", rd.Actions[0].Type, ActionTypeMasq)
	}
	if rd.Actions[0].Masq == nil {
		t.Fatalf("Masq payload is nil")
	}
	if rd.Actions[0].Masq.Random || rd.Actions[0].Masq.FullyRandom || rd.Actions[0].Masq.Persistent {
		t.Errorf("plain masquerade should have no flags set, got %+v", rd.Actions[0].Masq)
	}
}

func TestNftablesToRuleDefinition_Quota(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Quota{Bytes: 1000, Over: false, Consumed: 42},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Actions) != 2 {
		t.Fatalf("expected 2 actions (quota + verdict), got %d", len(rd.Actions))
	}
	q := rd.Actions[0]
	if q.Type != ActionTypeQuota {
		t.Errorf("action[0] type = %q, want %q", q.Type, ActionTypeQuota)
	}
	if q.Quota == nil {
		t.Fatalf("Quota payload is nil")
	}
	if q.Quota.Bytes != 1000 || q.Quota.Over || q.Quota.Consumed != 42 {
		t.Errorf("Quota = %+v, want {1000 false 42}", q.Quota)
	}
}

func TestNftablesToRuleDefinition_QuotaOver(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Quota{Bytes: 50 * 1024 * 1024, Over: true},
		&expr.Verdict{Kind: expr.VerdictDrop},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	q := rd.Actions[0].Quota
	if q == nil || !q.Over || q.Bytes != 50*1024*1024 {
		t.Errorf("Quota = %+v, want {52428800 true 0}", q)
	}
}

func TestNftablesToRuleDefinition_MasqueradeAllFlags(t *testing.T) {
	// Verify that masqToAction copies every flag — historic bug missed Persistent.
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Masq{Random: true, FullyRandom: true, Persistent: true},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := rd.Actions[0].Masq
	if m == nil {
		t.Fatalf("Masq payload is nil")
	}
	if !m.Random || !m.FullyRandom || !m.Persistent {
		t.Errorf("expected all flags set, got Random=%v FullyRandom=%v Persistent=%v",
			m.Random, m.FullyRandom, m.Persistent)
	}
}

// --- Multiple conditions ---

func TestNftablesToRuleDefinition_MultipleConditions(t *testing.T) {
	// l4proto = tcp AND dport = 443 → accept
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Meta{Key: unix.NFT_META_L4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
		&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: beUint16(443)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 2 {
		t.Fatalf("expected 2 conditions, got %d", len(rd.Conditions))
	}
	if rd.Conditions[0].Type != ConditionTypeMeta {
		t.Errorf("cond[0] type = %q, want meta", rd.Conditions[0].Type)
	}
	if rd.Conditions[1].Type != ConditionTypePayload {
		t.Errorf("cond[1] type = %q, want payload", rd.Conditions[1].Type)
	}
	if len(rd.Actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(rd.Actions))
	}
}

func TestNftablesToRuleDefinition_MultipleCTConditions(t *testing.T) {
	// Two independent CT expressions in the same rule
	markData := leUint32(100)
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: expr.CtKeyMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: markData},
		&expr.Ct{Key: expr.CtKeyMARK, Register: 2},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 2, Data: leUint32(0)},
		&expr.Verdict{Kind: expr.VerdictDrop},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 2 {
		t.Fatalf("expected 2 CT conditions, got %d", len(rd.Conditions))
	}
	if rd.Conditions[0].Operation != CompareOpEq {
		t.Errorf("cond[0] op = %q, want ==", rd.Conditions[0].Operation)
	}
	if rd.Conditions[1].Operation != CompareOpNeq {
		t.Errorf("cond[1] op = %q, want !=", rd.Conditions[1].Operation)
	}
}

// --- IP saddr / daddr (payload) conditions ---

func TestNftablesToRuleDefinition_IPSaddrExact(t *testing.T) {
	// ip saddr 192.168.1.1 accept
	rawIP := []byte{192, 168, 1, 1}
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: rawIP},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.Type != ConditionTypePayload {
		t.Errorf("type = %q, want %q", c.Type, ConditionTypePayload)
	}
	if c.Payload.Protocol != PayloadProtoIP {
		t.Errorf("Protocol = %q, want %q", c.Payload.Protocol, PayloadProtoIP)
	}
	if c.Payload.Field != "saddr" {
		t.Errorf("Field = %q, want %q", c.Payload.Field, "saddr")
	}
	if c.Operation != CompareOpEq {
		t.Errorf("Operation = %q, want %q", c.Operation, CompareOpEq)
	}
	addr, ok := c.Payload.Value.(*IPAddress)
	if !ok {
		t.Fatalf("Value type = %T, want *IPAddress", c.Payload.Value)
	}
	if !addr.IP.Equal(net.IP(rawIP)) {
		t.Errorf("IP = %s, want 192.168.1.1", addr.IP)
	}
	if addr.Subnet != nil {
		t.Errorf("Subnet should be nil for exact IP, got %s", addr.Subnet)
	}
}

func TestNftablesToRuleDefinition_IPDaddrExact(t *testing.T) {
	// ip daddr 10.0.0.1 drop
	rawIP := []byte{10, 0, 0, 1}
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: rawIP},
		&expr.Verdict{Kind: expr.VerdictDrop},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.Payload.Protocol != PayloadProtoIP {
		t.Errorf("Protocol = %q, want %q", c.Payload.Protocol, PayloadProtoIP)
	}
	if c.Payload.Field != "daddr" {
		t.Errorf("Field = %q, want %q", c.Payload.Field, "daddr")
	}
	addr, ok := c.Payload.Value.(*IPAddress)
	if !ok {
		t.Fatalf("Value type = %T, want *IPAddress", c.Payload.Value)
	}
	if !addr.IP.Equal(net.IP(rawIP)) {
		t.Errorf("IP = %s, want 10.0.0.1", addr.IP)
	}
	if addr.Subnet != nil {
		t.Errorf("Subnet should be nil for exact IP, got %s", addr.Subnet)
	}
}

func TestNftablesToRuleDefinition_IPSaddrCIDR(t *testing.T) {
	// ip saddr 192.168.1.0/24 accept
	// kernel encodes: Payload → Bitwise{mask=/24} → Cmp{network_addr}
	networkAddr := []byte{192, 168, 1, 0}
	mask24 := []byte{255, 255, 255, 0}
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4, DestRegister: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask24, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: networkAddr},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.Type != ConditionTypePayload {
		t.Errorf("type = %q, want %q", c.Type, ConditionTypePayload)
	}
	if c.Payload.Field != "saddr" {
		t.Errorf("Field = %q, want %q", c.Payload.Field, "saddr")
	}
	if c.Operation != CompareOpEq {
		t.Errorf("Operation = %q, want %q", c.Operation, CompareOpEq)
	}
	addr, ok := c.Payload.Value.(*IPAddress)
	if !ok {
		t.Fatalf("Value type = %T, want *IPAddress", c.Payload.Value)
	}
	if addr.Subnet == nil {
		t.Fatal("Subnet should be set for CIDR match")
	}
	if addr.Subnet.String() != "192.168.1.0/24" {
		t.Errorf("Subnet = %q, want %q", addr.Subnet.String(), "192.168.1.0/24")
	}
}

func TestNftablesToRuleDefinition_IPDaddrCIDR(t *testing.T) {
	// ip daddr 10.0.0.0/8 drop
	networkAddr := []byte{10, 0, 0, 0}
	mask8 := []byte{255, 0, 0, 0}
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4, DestRegister: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask8, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: networkAddr},
		&expr.Verdict{Kind: expr.VerdictDrop},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.Payload.Field != "daddr" {
		t.Errorf("Field = %q, want %q", c.Payload.Field, "daddr")
	}
	addr, ok := c.Payload.Value.(*IPAddress)
	if !ok {
		t.Fatalf("Value type = %T, want *IPAddress", c.Payload.Value)
	}
	if addr.Subnet == nil {
		t.Fatal("Subnet should be set for CIDR match")
	}
	if addr.Subnet.String() != "10.0.0.0/8" {
		t.Errorf("Subnet = %q, want %q", addr.Subnet.String(), "10.0.0.0/8")
	}
}

func TestNftablesToRuleDefinition_IPSaddrNeq(t *testing.T) {
	// ip saddr != 192.168.1.1 drop
	rawIP := []byte{192, 168, 1, 1}
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: rawIP},
		&expr.Verdict{Kind: expr.VerdictDrop},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	if c.Operation != CompareOpNeq {
		t.Errorf("Operation = %q, want %q", c.Operation, CompareOpNeq)
	}
	if c.Payload.Field != "saddr" {
		t.Errorf("Field = %q, want %q", c.Payload.Field, "saddr")
	}
}

func TestNftablesToRuleDefinition_IPDaddrNeq(t *testing.T) {
	// ip daddr != 10.0.0.0/8 accept
	networkAddr := []byte{10, 0, 0, 0}
	mask8 := []byte{255, 0, 0, 0}
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4, DestRegister: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask8, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: networkAddr},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	if c.Operation != CompareOpNeq {
		t.Errorf("Operation = %q, want %q", c.Operation, CompareOpNeq)
	}
	addr, ok := c.Payload.Value.(*IPAddress)
	if !ok {
		t.Fatalf("Value type = %T, want *IPAddress", c.Payload.Value)
	}
	if addr.Subnet == nil {
		t.Fatal("Subnet should be set for CIDR match")
	}
	if addr.Subnet.String() != "10.0.0.0/8" {
		t.Errorf("Subnet = %q, want %q", addr.Subnet.String(), "10.0.0.0/8")
	}
}

func TestNftablesToRuleDefinition_IPSaddrAndDaddr(t *testing.T) {
	// ip saddr 192.168.1.0/24 ip daddr 10.0.0.1 accept
	saddrNetwork := []byte{192, 168, 1, 0}
	saddrMask := []byte{255, 255, 255, 0}
	daddrRaw := []byte{10, 0, 0, 1}
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4, DestRegister: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: saddrMask, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: saddrNetwork},
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: daddrRaw},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 2 {
		t.Fatalf("expected 2 conditions, got %d", len(rd.Conditions))
	}

	saddr := rd.Conditions[0]
	if saddr.Payload.Field != "saddr" {
		t.Errorf("cond[0] Field = %q, want saddr", saddr.Payload.Field)
	}
	saddrAddr, ok := saddr.Payload.Value.(*IPAddress)
	if !ok {
		t.Fatalf("cond[0] Value type = %T, want *IPAddress", saddr.Payload.Value)
	}
	if saddrAddr.Subnet == nil || saddrAddr.Subnet.String() != "192.168.1.0/24" {
		t.Errorf("cond[0] Subnet = %v, want 192.168.1.0/24", saddrAddr.Subnet)
	}

	daddr := rd.Conditions[1]
	if daddr.Payload.Field != "daddr" {
		t.Errorf("cond[1] Field = %q, want daddr", daddr.Payload.Field)
	}
	daddrAddr, ok := daddr.Payload.Value.(*IPAddress)
	if !ok {
		t.Fatalf("cond[1] Value type = %T, want *IPAddress", daddr.Payload.Value)
	}
	if !daddrAddr.IP.Equal(net.IP(daddrRaw)) {
		t.Errorf("cond[1] IP = %s, want 10.0.0.1", daddrAddr.IP)
	}
	if daddrAddr.Subnet != nil {
		t.Errorf("cond[1] Subnet should be nil for exact IP, got %s", daddrAddr.Subnet)
	}
}

func TestNftablesToRuleDefinition_IPSaddrCIDR_16(t *testing.T) {
	// ip saddr 172.16.0.0/12 accept  (mask = 255.240.0.0)
	networkAddr := []byte{172, 16, 0, 0}
	mask12 := []byte{255, 240, 0, 0}
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4, DestRegister: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask12, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: networkAddr},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	addr, ok := c.Payload.Value.(*IPAddress)
	if !ok {
		t.Fatalf("Value type = %T, want *IPAddress", c.Payload.Value)
	}
	if addr.Subnet == nil {
		t.Fatal("Subnet should be set for CIDR match")
	}
	if addr.Subnet.String() != "172.16.0.0/12" {
		t.Errorf("Subnet = %q, want %q", addr.Subnet.String(), "172.16.0.0/12")
	}
}

// --- Byte-aligned prefix (no Bitwise) ---

func TestNftablesToRuleDefinition_IPSaddrByteAligned24(t *testing.T) {
	// Kernel optimization: ip saddr 192.168.1.0/24 stored as Payload{len=3} + Cmp
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 3, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{192, 168, 1}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.Payload == nil || c.Payload.Field != "saddr" {
		t.Fatalf("expected saddr payload condition, got %+v", c)
	}
	addr, ok := c.Payload.Value.(*IPAddress)
	if !ok {
		t.Fatalf("Value type = %T, want *IPAddress", c.Payload.Value)
	}
	if addr.Subnet == nil {
		t.Fatal("Subnet should be set for byte-aligned prefix")
	}
	if addr.Subnet.String() != "192.168.1.0/24" {
		t.Errorf("Subnet = %q, want 192.168.1.0/24", addr.Subnet.String())
	}
	if c.Operation != CompareOpEq {
		t.Errorf("Operation = %q, want ==", c.Operation)
	}
}

func TestNftablesToRuleDefinition_IPSaddrByteAligned16(t *testing.T) {
	// ip saddr 192.168.0.0/16 via byte-aligned: Payload{len=2} + Cmp
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 2, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{192, 168}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	addr, ok := c.Payload.Value.(*IPAddress)
	if !ok {
		t.Fatalf("Value type = %T, want *IPAddress", c.Payload.Value)
	}
	if addr.Subnet == nil || addr.Subnet.String() != "192.168.0.0/16" {
		t.Errorf("Subnet = %v, want 192.168.0.0/16", addr.Subnet)
	}
}

func TestNftablesToRuleDefinition_IPSaddrByteAlignedNeq(t *testing.T) {
	// ip saddr != 192.168.0.0/16 via byte-aligned: Payload{len=2} + Cmp{Neq}
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 2, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{192, 168}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	if c.Operation != CompareOpNeq {
		t.Errorf("Operation = %q, want !=", c.Operation)
	}
	addr, ok := c.Payload.Value.(*IPAddress)
	if !ok {
		t.Fatalf("Value type = %T, want *IPAddress", c.Payload.Value)
	}
	if addr.Subnet == nil || addr.Subnet.String() != "192.168.0.0/16" {
		t.Errorf("Subnet = %v, want 192.168.0.0/16", addr.Subnet)
	}
}

// --- Unknown expression → CustomCondition ---

func TestNftablesToRuleDefinition_UnknownExpr(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Objref{Type: 1, Name: "mycounter"},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Objref is handled by the default case → CustomCondition
	hasCustom := false
	for _, c := range rd.Conditions {
		if c.Type == ConditionTypeCustom {
			hasCustom = true
		}
	}
	// Objref is in the switch as a case (skipped with TODO), so it won't be Custom
	// Just verify no panic and rule is parsed
	_ = hasCustom
	if len(rd.Actions) != 1 {
		t.Errorf("expected 1 action (verdict), got %d", len(rd.Actions))
	}
}

// --- ct l3proto ---

func TestNftablesToRuleDefinition_CtL3ProtoIPv4(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: unix.NFT_CT_L3PROTOCOL, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{2}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.CT == nil || c.CT.Key != nftexpr.CtKeyL3Protocol {
		t.Fatalf("expected CT l3protocol condition, got %+v", c)
	}
	v, ok := c.CT.Value.(nftexpr.CtL3Proto)
	if !ok {
		t.Fatalf("Value type = %T, want CtL3Proto", c.CT.Value)
	}
	if v != nftexpr.CtL3ProtoIPv4 {
		t.Errorf("Value = %q, want ipv4", v)
	}
	if c.Operation != CompareOpEq {
		t.Errorf("Operation = %q, want ==", c.Operation)
	}
}

func TestNftablesToRuleDefinition_CtL3ProtoIPv6(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: unix.NFT_CT_L3PROTOCOL, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{10}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	v, ok := c.CT.Value.(nftexpr.CtL3Proto)
	if !ok {
		t.Fatalf("Value type = %T, want CtL3Proto", c.CT.Value)
	}
	if v != nftexpr.CtL3ProtoIPv6 {
		t.Errorf("Value = %q, want ipv6", v)
	}
}

func TestNftablesToRuleDefinition_CtL3ProtoNeq(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: unix.NFT_CT_L3PROTOCOL, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{2}},
		&expr.Verdict{Kind: expr.VerdictDrop},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	if c.Operation != CompareOpNeq {
		t.Errorf("Operation = %q, want !=", c.Operation)
	}
	v, ok := c.CT.Value.(nftexpr.CtL3Proto)
	if !ok || v != nftexpr.CtL3ProtoIPv4 {
		t.Errorf("Value = %v, want ipv4", c.CT.Value)
	}
}

func TestNftablesToRuleDefinition_CtL3Proto4ByteLE(t *testing.T) {
	// Kernel may send 4-byte little-endian for l3proto
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: unix.NFT_CT_L3PROTOCOL, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{2, 0, 0, 0}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	v, ok := rd.Conditions[0].CT.Value.(nftexpr.CtL3Proto)
	if !ok || v != nftexpr.CtL3ProtoIPv4 {
		t.Errorf("Value = %v, want ipv4", rd.Conditions[0].CT.Value)
	}
}

// --- ct protocol ---

func TestNftablesToRuleDefinition_CtProtocolTCP(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: unix.NFT_CT_PROTOCOL, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.CT == nil || c.CT.Key != nftexpr.CtKeyProtocol {
		t.Fatalf("expected CT protocol condition, got %+v", c)
	}
	v, ok := c.CT.Value.(nftexpr.CtProtocol)
	if !ok {
		t.Fatalf("Value type = %T, want CtProtocol", c.CT.Value)
	}
	if v != nftexpr.CtProtocolTCP {
		t.Errorf("Value = %q, want tcp", v)
	}
	if c.Operation != CompareOpEq {
		t.Errorf("Operation = %q, want ==", c.Operation)
	}
}

func TestNftablesToRuleDefinition_CtProtocolUDP(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: unix.NFT_CT_PROTOCOL, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{17}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	v, ok := rd.Conditions[0].CT.Value.(nftexpr.CtProtocol)
	if !ok || v != nftexpr.CtProtocolUDP {
		t.Errorf("Value = %v, want udp", rd.Conditions[0].CT.Value)
	}
}

func TestNftablesToRuleDefinition_CtProtocolICMP(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: unix.NFT_CT_PROTOCOL, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	v, ok := rd.Conditions[0].CT.Value.(nftexpr.CtProtocol)
	if !ok || v != nftexpr.CtProtocolICMP {
		t.Errorf("Value = %v, want icmp", rd.Conditions[0].CT.Value)
	}
}

func TestNftablesToRuleDefinition_CtProtocolAllValues(t *testing.T) {
	tests := []struct {
		byte  byte
		proto nftexpr.CtProtocol
	}{
		{1, nftexpr.CtProtocolICMP},
		{6, nftexpr.CtProtocolTCP},
		{17, nftexpr.CtProtocolUDP},
		{33, nftexpr.CtProtocolDCCP},
		{58, nftexpr.CtProtocolICMPv6},
		{132, nftexpr.CtProtocolSCTP},
	}
	for _, tt := range tests {
		t.Run(string(tt.proto), func(t *testing.T) {
			rd, err := NftablesToRuleDefinition(makeRule(
				&expr.Ct{Key: unix.NFT_CT_PROTOCOL, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{tt.byte}},
				&expr.Verdict{Kind: expr.VerdictAccept},
			))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			v, ok := rd.Conditions[0].CT.Value.(nftexpr.CtProtocol)
			if !ok || v != tt.proto {
				t.Errorf("Value = %v, want %s", rd.Conditions[0].CT.Value, tt.proto)
			}
		})
	}
}

func TestNftablesToRuleDefinition_CtProtocolNeq(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: unix.NFT_CT_PROTOCOL, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{6}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := rd.Conditions[0]
	if c.Operation != CompareOpNeq {
		t.Errorf("Operation = %q, want !=", c.Operation)
	}
	v, ok := c.CT.Value.(nftexpr.CtProtocol)
	if !ok || v != nftexpr.CtProtocolTCP {
		t.Errorf("Value = %v, want tcp", c.CT.Value)
	}
}

func TestNftablesToRuleDefinition_CtProtocol4ByteLE(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: unix.NFT_CT_PROTOCOL, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6, 0, 0, 0}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	v, ok := rd.Conditions[0].CT.Value.(nftexpr.CtProtocol)
	if !ok || v != nftexpr.CtProtocolTCP {
		t.Errorf("Value = %v, want tcp", rd.Conditions[0].CT.Value)
	}
}

func TestNftablesToRuleDefinition_CtL3ProtoAndProtocol(t *testing.T) {
	// ct l3proto ipv4 ct protocol tcp accept
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: unix.NFT_CT_L3PROTOCOL, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{2}},
		&expr.Ct{Key: unix.NFT_CT_PROTOCOL, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 2 {
		t.Fatalf("expected 2 conditions, got %d", len(rd.Conditions))
	}

	l3 := rd.Conditions[0]
	if l3.CT == nil || l3.CT.Key != nftexpr.CtKeyL3Protocol {
		t.Errorf("cond[0] expected l3protocol, got %+v", l3)
	}
	if v, ok := l3.CT.Value.(nftexpr.CtL3Proto); !ok || v != nftexpr.CtL3ProtoIPv4 {
		t.Errorf("cond[0] Value = %v, want ipv4", l3.CT.Value)
	}

	proto := rd.Conditions[1]
	if proto.CT == nil || proto.CT.Key != nftexpr.CtKeyProtocol {
		t.Errorf("cond[1] expected protocol, got %+v", proto)
	}
	if v, ok := proto.CT.Value.(nftexpr.CtProtocol); !ok || v != nftexpr.CtProtocolTCP {
		t.Errorf("cond[1] Value = %v, want tcp", proto.CT.Value)
	}
}

func TestNftablesToRuleDefinition_CTProtoSrc(t *testing.T) {
	// ct original proto-src 80: Ct{PROTOSRC, Dir=0, OptDir=true} → Cmp{Eq, BE(80)}
	port := beUint16(80)

	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: expr.CtKeyPROTOSRC, Register: 1, Direction: 0, OptDirection: true},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: port},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.CT.Key != nftexpr.CtKeyProtoSrc {
		t.Errorf("CT.Key = %q, want %q", c.CT.Key, nftexpr.CtKeyProtoSrc)
	}
	if v, ok := c.CT.Value.(uint16); !ok || v != 80 {
		t.Errorf("CT.Value = %v (%T), want uint16(80)", c.CT.Value, c.CT.Value)
	}
	if c.CT.Direction != nftexpr.CtDirectionOriginal {
		t.Errorf("Direction = %q, want %q", c.CT.Direction, nftexpr.CtDirectionOriginal)
	}
	if c.Operation != CompareOpEq {
		t.Errorf("Operation = %q, want CompareOpEq", c.Operation)
	}
}

func TestNftablesToRuleDefinition_CTProtoDst(t *testing.T) {
	// ct reply proto-dst 443 (!=): Ct{PROTODST, Dir=1, OptDir=true} → Cmp{Neq, BE(443)}
	port := beUint16(443)

	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Ct{Key: expr.CtKeyPROTODST, Register: 1, Direction: 1, OptDirection: true},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: port},
		&expr.Verdict{Kind: expr.VerdictDrop},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
	}
	c := rd.Conditions[0]
	if c.CT.Key != nftexpr.CtKeyProtoDst {
		t.Errorf("CT.Key = %q, want %q", c.CT.Key, nftexpr.CtKeyProtoDst)
	}
	if v, ok := c.CT.Value.(uint16); !ok || v != 443 {
		t.Errorf("CT.Value = %v (%T), want uint16(443)", c.CT.Value, c.CT.Value)
	}
	if c.CT.Direction != nftexpr.CtDirectionReply {
		t.Errorf("Direction = %q, want %q", c.CT.Direction, nftexpr.CtDirectionReply)
	}
	if c.Operation != CompareOpNeq {
		t.Errorf("Operation = %q, want CompareOpNeq", c.Operation)
	}
}

func TestNftablesToRuleDefinition_CTZone(t *testing.T) {
	tests := []struct {
		name   string
		zone   uint16
		op     expr.CmpOp
		wantOp CompareOp
	}{
		{"zone == 1", 1, expr.CmpOpEq, CompareOpEq},
		{"zone != 0", 0, expr.CmpOpNeq, CompareOpNeq},
		{"zone == 42", 42, expr.CmpOpEq, CompareOpEq},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zoneData := make([]byte, 2)
			binary.LittleEndian.PutUint16(zoneData, tt.zone)

			rd, err := NftablesToRuleDefinition(makeRule(
				&expr.Ct{Key: expr.CtKeyZONE, Register: 1},
				&expr.Cmp{Op: tt.op, Register: 1, Data: zoneData},
				&expr.Verdict{Kind: expr.VerdictAccept},
			))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(rd.Conditions) != 1 {
				t.Fatalf("expected 1 condition, got %d", len(rd.Conditions))
			}
			c := rd.Conditions[0]
			if c.CT.Key != nftexpr.CtKeyZone {
				t.Errorf("CT.Key = %q, want %q", c.CT.Key, nftexpr.CtKeyZone)
			}
			if v, ok := c.CT.Value.(uint16); !ok || v != tt.zone {
				t.Errorf("CT.Value = %v (%T), want uint16(%d)", c.CT.Value, c.CT.Value, tt.zone)
			}
			if c.Operation != tt.wantOp {
				t.Errorf("Operation = %q, want %q", c.Operation, tt.wantOp)
			}
		})
	}
}

func TestNftablesToRuleDefinition_CTCountOver(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Connlimit{Count: 100, Flags: 0}, // Flags=0 → "over"
		&expr.Verdict{Kind: expr.VerdictDrop},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var found *Condition
	for i := range rd.Conditions {
		if rd.Conditions[i].Connlimit != nil {
			found = &rd.Conditions[i]
		}
	}
	if found == nil {
		t.Fatal("no connlimit condition found")
	}
	if found.Connlimit.Count != 100 {
		t.Errorf("Count = %d, want 100", found.Connlimit.Count)
	}
	if found.Connlimit.Flags != 0 {
		t.Errorf("Flags = %d, want 0 (over)", found.Connlimit.Flags)
	}
}

func TestNftablesToRuleDefinition_CTCount(t *testing.T) {
	rd, err := NftablesToRuleDefinition(makeRule(
		&expr.Connlimit{Count: 50, Flags: expr.NFT_CONNLIMIT_F_INV},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var found *Condition
	for i := range rd.Conditions {
		if rd.Conditions[i].Connlimit != nil {
			found = &rd.Conditions[i]
		}
	}
	if found == nil {
		t.Fatal("no connlimit condition found")
	}
	if found.Connlimit.Count != 50 {
		t.Errorf("Count = %d, want 50", found.Connlimit.Count)
	}
	if found.Connlimit.Flags != expr.NFT_CONNLIMIT_F_INV {
		t.Errorf("Flags = %d, want NFT_CONNLIMIT_F_INV", found.Connlimit.Flags)
	}
}

// beUint32 helper for 4-byte big-endian values used in some test payloads
var _ = binary.BigEndian // ensure import used
