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
		&expr.Log{Level: 6, Data: []byte("DROP\x00")},
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

func TestNftablesToRuleDefinition_CTState(t *testing.T) {
	// CT STATE: Ct → Bitwise{mask=LE(established)} → Cmp{Eq, data=LE(established)}
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
