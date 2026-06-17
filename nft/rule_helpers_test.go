package nft

// Tests for the pure expr→Action converters and small parse helpers in
// rule.go. All are called from NftablesToRuleDefinition's dispatch; testing
// them directly keeps the fixtures small and netlink-free.

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	nftexpr "nftui/nft/expr"
)

func TestExthdrProtoToType(t *testing.T) {
	tests := []struct {
		proto ExthdrProto
		want  uint8
	}{
		{ExthdrProtoHBH, 0},
		{ExthdrProtoDst, 60},
		{ExthdrProtoFrag, 44},
		{ExthdrProtoRt, 43},
		{ExthdrProtoMh, 135},
		{ExthdrProto("bogus"), 0},
	}
	for _, tt := range tests {
		if got := exthdrProtoToType(tt.proto); got != tt.want {
			t.Errorf("exthdrProtoToType(%q) = %d, want %d", tt.proto, got, tt.want)
		}
	}
}

func TestExthdrTypeToProto(t *testing.T) {
	tests := []struct {
		in   uint8
		want ExthdrProto
	}{
		{0, ExthdrProtoHBH},
		{60, ExthdrProtoDst},
		{44, ExthdrProtoFrag},
		{43, ExthdrProtoRt},
		{135, ExthdrProtoMh},
		{200, ExthdrProto("")}, // unmapped → empty
	}
	for _, tt := range tests {
		if got := exthdrTypeToProto(tt.in); got != tt.want {
			t.Errorf("exthdrTypeToProto(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDecodeExthdrValue(t *testing.T) {
	// len 1 → uint8
	if got := decodeExthdrValue(1, []byte{0x2a}); got != uint8(0x2a) {
		t.Errorf("len 1 = %v (%T), want uint8(42)", got, got)
	}
	// len 2 → uint16 BE
	if got := decodeExthdrValue(2, []byte{0x12, 0x34}); got != uint16(0x1234) {
		t.Errorf("len 2 = %v (%T), want uint16(0x1234)", got, got)
	}
	// len 4 → uint32 BE
	if got := decodeExthdrValue(4, []byte{0x12, 0x34, 0x56, 0x78}); got != uint32(0x12345678) {
		t.Errorf("len 4 = %v (%T), want uint32(0x12345678)", got, got)
	}
	// Short data for a known length falls through to the raw slice.
	short := []byte{0x01}
	if got := decodeExthdrValue(2, short); !bytesEqual(got, short) {
		t.Errorf("len 2 short = %v, want raw slice %v", got, short)
	}
	// Unhandled length returns the raw slice unchanged.
	raw := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	if got := decodeExthdrValue(8, raw); !bytesEqual(got, raw) {
		t.Errorf("len 8 = %v, want raw slice %v", got, raw)
	}
}

// bytesEqual compares an interface{} (expected to hold a []byte) against want.
func bytesEqual(got interface{}, want []byte) bool {
	b, ok := got.([]byte)
	if !ok || len(b) != len(want) {
		return false
	}
	for i := range b {
		if b[i] != want[i] {
			return false
		}
	}
	return true
}

func TestExtractValueFromCt(t *testing.T) {
	tests := []struct {
		name string
		ct   nftexpr.Ct
		want any
	}{
		{"states win", nftexpr.Ct{State: []nftexpr.CtState{nftexpr.CtStateNew}}, []nftexpr.CtState{nftexpr.CtStateNew}},
		{"direction", nftexpr.Ct{Direction: nftexpr.CtDirectionReply}, nftexpr.CtDirectionReply},
		{"status", nftexpr.Ct{Status: []nftexpr.CtStatus{nftexpr.CtStatusConfirmed}}, []nftexpr.CtStatus{nftexpr.CtStatusConfirmed}},
		{"mark", nftexpr.Ct{Mark: 7}, uint32(7)},
		{"expiration", nftexpr.Ct{Expiration: 30}, uint32(30)},
		{"zone", nftexpr.Ct{Zone: 4}, uint16(4)},
		{"helper", nftexpr.Ct{Helper: "ftp"}, "ftp"},
		{"empty", nftexpr.Ct{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractValueFromCt(tt.ct)
			switch want := tt.want.(type) {
			case nil:
				if got != nil {
					t.Errorf("got %v, want nil", got)
				}
			case []nftexpr.CtState:
				gs, ok := got.([]nftexpr.CtState)
				if !ok || len(gs) != len(want) || gs[0] != want[0] {
					t.Errorf("got %v, want %v", got, want)
				}
			case []nftexpr.CtStatus:
				gs, ok := got.([]nftexpr.CtStatus)
				if !ok || len(gs) != len(want) || gs[0] != want[0] {
					t.Errorf("got %v, want %v", got, want)
				}
			default:
				if got != tt.want {
					t.Errorf("got %v (%T), want %v (%T)", got, got, tt.want, tt.want)
				}
			}
		})
	}

	// proto-src/dst pair renders as "src->dst".
	if got := extractValueFromCt(nftexpr.Ct{ProtoSrc: 1, ProtoDst: 2}); got != "1->2" {
		t.Errorf("proto pair = %v, want 1->2", got)
	}

	// Expiration range → *RangeValue.
	if got := extractValueFromCt(nftexpr.Ct{ExpirationRange: &nftexpr.CtRange{From: 10, To: 20}}); got != nil {
		rv, ok := got.(*RangeValue)
		if !ok || rv.From != uint32(10) || rv.To != uint32(20) {
			t.Errorf("expiration range = %+v, want RangeValue{10,20}", got)
		}
	} else {
		t.Error("expiration range returned nil")
	}

	// Expiration set → *SetValue with the same elements.
	if got := extractValueFromCt(nftexpr.Ct{ExpirationSet: []string{"30", "60"}}); got != nil {
		sv, ok := got.(*SetValue)
		if !ok || len(sv.Elements) != 2 {
			t.Errorf("expiration set = %+v, want SetValue with 2 elements", got)
		}
	} else {
		t.Error("expiration set returned nil")
	}

	// Src / Dst addresses pass through verbatim.
	if got := extractValueFromCt(nftexpr.Ct{Src: "10.0.0.1"}); got != "10.0.0.1" {
		t.Errorf("src = %v, want 10.0.0.1", got)
	}
	if got := extractValueFromCt(nftexpr.Ct{Dst: "10.0.0.2"}); got != "10.0.0.2" {
		t.Errorf("dst = %v, want 10.0.0.2", got)
	}
}

func TestDecodeMetaValue(t *testing.T) {
	// iif/oif with a bogus 4-byte index: InterfaceByIndex fails, so the raw
	// index is returned.
	if got := decodeMetaValue(unix.NFT_META_IIF, []byte{0xff, 0xff, 0xff, 0xfe}); got != uint32(0xfffffffe) {
		t.Errorf("bogus iif = %v (%T), want raw index", got, got)
	}
	// iif success path: use a real interface index so the name comes back.
	if ifaces, err := net.Interfaces(); err == nil && len(ifaces) > 0 {
		idx := make([]byte, 4)
		binary.BigEndian.PutUint32(idx, uint32(ifaces[0].Index))
		if got := decodeMetaValue(unix.NFT_META_OIF, idx); got != ifaces[0].Name {
			t.Errorf("oif index %d = %v, want %q", ifaces[0].Index, got, ifaces[0].Name)
		}
	}
	// iifname: NUL-padded string is trimmed.
	if got := decodeMetaValue(unix.NFT_META_IIFNAME, []byte("eth0\x00\x00\x00\x00")); got != "eth0" {
		t.Errorf("iifname = %q, want eth0", got)
	}
	// Width-based fallbacks for generic keys.
	if got := decodeMetaValue(unix.NFT_META_MARK, []byte{0, 0, 0, 9}); got != uint32(9) {
		t.Errorf("len4 = %v, want uint32(9)", got)
	}
	if got := decodeMetaValue(unix.NFT_META_LEN, []byte{0x01, 0x02}); got != uint16(0x0102) {
		t.Errorf("len2 = %v, want uint16", got)
	}
	if got := decodeMetaValue(unix.NFT_META_PKTTYPE, []byte{0x03}); got != byte(0x03) {
		t.Errorf("len1 = %v, want byte(3)", got)
	}
	// Unusual length falls through to the raw slice.
	raw := []byte{1, 2, 3}
	if got, ok := decodeMetaValue(unix.NFT_META_MARK, raw).([]byte); !ok || len(got) != 3 {
		t.Errorf("len3 = %v, want raw slice", got)
	}
}

func TestNatToAction(t *testing.T) {
	regs := map[uint32]*registerValue{
		1: {immediateData: []byte{192, 0, 2, 1}},
		2: {immediateData: []byte{192, 0, 2, 9}},
		3: {immediateData: []byte{0x1F, 0x90}}, // port 8080
	}

	t.Run("snat with addr range and port", func(t *testing.T) {
		act, err := natToAction(&expr.NAT{
			Type: expr.NATTypeSourceNAT, RegAddrMin: 1, RegAddrMax: 2, RegProtoMin: 3,
		}, regs)
		if err != nil {
			t.Fatalf("natToAction: %v", err)
		}
		if act.Type != ActionTypeNAT || act.NAT == nil {
			t.Fatalf("action = %+v, want NAT", act)
		}
		if act.NAT.Type != NATTypeSNAT {
			t.Errorf("NAT type = %v, want SNAT", act.NAT.Type)
		}
		if act.NAT.AddressRange == nil || act.NAT.AddressRange.From.String() != "192.0.2.1" || act.NAT.AddressRange.To.String() != "192.0.2.9" {
			t.Errorf("addr range = %+v", act.NAT.AddressRange)
		}
		if act.NAT.PortRange == nil || act.NAT.PortRange.From != 8080 {
			t.Errorf("port range = %+v", act.NAT.PortRange)
		}
	})

	t.Run("dnat without registers", func(t *testing.T) {
		act, err := natToAction(&expr.NAT{Type: expr.NATTypeDestNAT}, nil)
		if err != nil {
			t.Fatalf("natToAction: %v", err)
		}
		if act.NAT.Type != NATTypeDNAT {
			t.Errorf("NAT type = %v, want DNAT", act.NAT.Type)
		}
		if act.NAT.AddressRange != nil || act.NAT.PortRange != nil {
			t.Errorf("ranges = %+v / %+v, want nil", act.NAT.AddressRange, act.NAT.PortRange)
		}
	})

	t.Run("all flags set", func(t *testing.T) {
		act, err := natToAction(&expr.NAT{
			Type: expr.NATTypeSourceNAT, RegAddrMin: 1,
			Random: true, FullyRandom: true, Persistent: true,
		}, regs)
		if err != nil {
			t.Fatalf("natToAction: %v", err)
		}
		if len(act.NAT.Flags) != 3 {
			t.Errorf("flags = %v, want random+fully-random+persistent", act.NAT.Flags)
		}
		// Single-register address: From and To collapse to the same IP.
		if act.NAT.AddressRange == nil || act.NAT.AddressRange.From.String() != act.NAT.AddressRange.To.String() {
			t.Errorf("addr range = %+v, want From==To", act.NAT.AddressRange)
		}
	})
}

func TestVerdictToAction(t *testing.T) {
	cases := []struct {
		kind expr.VerdictKind
		want VerdictKind
	}{
		{expr.VerdictAccept, VerdictAccept},
		{expr.VerdictDrop, VerdictDrop},
		{expr.VerdictReturn, VerdictReturn},
		{expr.VerdictJump, VerdictJump},
		{expr.VerdictGoto, VerdictGoto},
		{expr.VerdictKind(99), VerdictDrop}, // unknown falls back to drop
	}
	for _, tt := range cases {
		act := verdictToAction(&expr.Verdict{Kind: tt.kind, Chain: "tgt"})
		if act.Type != ActionTypeVerdict || act.Verdict == nil {
			t.Fatalf("kind %v: action = %+v", tt.kind, act)
		}
		if act.Verdict.Kind != tt.want {
			t.Errorf("kind %v → %v, want %v", tt.kind, act.Verdict.Kind, tt.want)
		}
		if act.Verdict.Chain != "tgt" {
			t.Errorf("chain = %q, want tgt", act.Verdict.Chain)
		}
	}
}

func TestRedirToAction(t *testing.T) {
	regs := map[uint32]*registerValue{
		1: {immediateData: []byte{0x00, 0x50}}, // port 80
		2: {immediateData: []byte{0x00, 0x60}}, // port 96
	}

	act := redirToAction(&expr.Redir{RegisterProtoMin: 1}, regs)
	if act.Type != ActionTypeRedirect || act.Redirect == nil {
		t.Fatalf("action = %+v", act)
	}
	if act.Redirect.PortRange == nil || act.Redirect.PortRange.From != 80 || act.Redirect.PortRange.To != 80 {
		t.Errorf("port range = %+v, want 80-80", act.Redirect.PortRange)
	}

	// Min+Max registers produce a distinct From..To port range.
	ranged := redirToAction(&expr.Redir{RegisterProtoMin: 1, RegisterProtoMax: 2}, regs)
	if ranged.Redirect.PortRange == nil || ranged.Redirect.PortRange.From != 80 || ranged.Redirect.PortRange.To != 96 {
		t.Errorf("ranged port = %+v, want 80-96", ranged.Redirect.PortRange)
	}

	bare := redirToAction(&expr.Redir{}, nil)
	if bare.Redirect.PortRange != nil {
		t.Errorf("bare redirect port range = %+v, want nil", bare.Redirect.PortRange)
	}
}

func TestRejectToAction(t *testing.T) {
	tests := []struct {
		kernelType uint32
		want       RejectType
	}{
		{unix.NFT_REJECT_ICMP_UNREACH, RejectTypeICMP},
		{unix.NFT_REJECT_TCP_RST, RejectTypeTCPReset},
		{unix.NFT_REJECT_ICMPX_UNREACH, RejectTypeICMPX},
	}
	for _, tt := range tests {
		act := rejectToAction(&expr.Reject{Type: tt.kernelType, Code: 13})
		if act.Type != ActionTypeReject || act.Reject == nil {
			t.Fatalf("action = %+v", act)
		}
		if act.Reject.Type != tt.want || act.Reject.Code != 13 {
			t.Errorf("reject = %+v, want type %v code 13", act.Reject, tt.want)
		}
	}
}

func TestQueueToAction(t *testing.T) {
	// Num=0 Total=1 → single queue, no range.
	single := queueToAction(&expr.Queue{Num: 0, Total: 1})
	if single.Queue == nil || single.Queue.NumRange != nil {
		t.Errorf("single queue = %+v, want no range", single.Queue)
	}

	// Num=3 Total=5 → range 3-7 (Num+Total-1).
	ranged := queueToAction(&expr.Queue{Num: 3, Total: 5})
	if ranged.Queue.NumRange == nil || ranged.Queue.NumRange.From != 3 || ranged.Queue.NumRange.To != 7 {
		t.Errorf("ranged queue = %+v, want 3-7", ranged.Queue.NumRange)
	}

	// Flags map to the string identifiers.
	flagged := queueToAction(&expr.Queue{
		Num: 0, Total: 1,
		Flag: unix.NFT_QUEUE_FLAG_BYPASS | unix.NFT_QUEUE_FLAG_CPU_FANOUT,
	})
	if len(flagged.Queue.Flags) != 2 {
		t.Fatalf("flags = %v, want bypass+fanout", flagged.Queue.Flags)
	}
}

func TestMasqToAction(t *testing.T) {
	// Bare masquerade (no port-range registers).
	act := masqToAction(&expr.Masq{Random: true, Persistent: true}, map[uint32]*registerValue{})
	if act.Type != ActionTypeMasq || act.Masq == nil {
		t.Fatalf("masqToAction type = %v", act.Type)
	}
	if act.Masq.PortRange != nil {
		t.Errorf("PortRange = %+v, want nil", act.Masq.PortRange)
	}
	if !act.Masq.Random || !act.Masq.Persistent || act.Masq.FullyRandom {
		t.Errorf("flags = %+v", act.Masq)
	}

	// masquerade to :1024-2048 — proto-min/max registers carry the ports.
	regMap := map[uint32]*registerValue{
		1: {immediateData: []byte{0x04, 0x00}}, // 1024
		2: {immediateData: []byte{0x08, 0x00}}, // 2048
	}
	act = masqToAction(&expr.Masq{RegProtoMin: 1, RegProtoMax: 2}, regMap)
	if act.Masq.PortRange == nil || act.Masq.PortRange.From != 1024 || act.Masq.PortRange.To != 2048 {
		t.Errorf("PortRange = %+v, want {1024 2048}", act.Masq.PortRange)
	}

	// Single port (min only): To collapses to From.
	act = masqToAction(&expr.Masq{RegProtoMin: 1}, map[uint32]*registerValue{
		1: {immediateData: []byte{0x00, 0x50}}, // 80
	})
	if act.Masq.PortRange == nil || act.Masq.PortRange.From != 80 || act.Masq.PortRange.To != 80 {
		t.Errorf("single-port PortRange = %+v, want {80 80}", act.Masq.PortRange)
	}
}

func TestDynsetOpToString(t *testing.T) {
	tests := []struct {
		op   uint32
		want string
	}{
		{uint32(unix.NFT_DYNSET_OP_ADD), "add"},
		{uint32(unix.NFT_DYNSET_OP_UPDATE), "update"},
		{2, "delete"},
		{99, "add"}, // default
	}
	for _, tt := range tests {
		if got := dynsetOpToString(tt.op); got != tt.want {
			t.Errorf("dynsetOpToString(%d) = %q, want %q", tt.op, got, tt.want)
		}
	}
}

func TestExthdrFieldName(t *testing.T) {
	tests := []struct {
		name    string
		hdrType uint8
		offset  uint32
		length  uint32
		want    string
	}{
		{"hbh nexthdr", 0, 0, 1, "nexthdr"},
		{"dst hdrlength", 60, 1, 1, "hdrlength"},
		{"frag nexthdr", 44, 0, 1, "nexthdr"},
		{"frag reserved", 44, 1, 1, "reserved"},
		{"frag frag-off", 44, 2, 2, "frag-off"},
		{"frag more-fragments", 44, 3, 1, "more-fragments"},
		{"frag id", 44, 4, 4, "id"},
		{"rt nexthdr", 43, 0, 1, "nexthdr"},
		{"rt hdrlength", 43, 1, 1, "hdrlength"},
		{"rt type", 43, 2, 1, "type"},
		{"rt seg-left", 43, 3, 1, "seg-left"},
		{"mh nexthdr", 135, 0, 1, "nexthdr"},
		{"mh hdrlength", 135, 1, 1, "hdrlength"},
		{"mh type", 135, 2, 1, "type"},
		{"mh reserved", 135, 3, 1, "reserved"},
		{"mh checksum", 135, 4, 2, "checksum"},
		// In-range type with an off-layout offset/length falls back too.
		{"frag off-layout fallback", 44, 9, 9, "offset_9_len_9"},
		{"unknown falls back", 200, 9, 9, "offset_9_len_9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exthdrFieldName(tt.hdrType, tt.offset, tt.length); got != tt.want {
				t.Errorf("exthdrFieldName(%d, %d, %d) = %q, want %q", tt.hdrType, tt.offset, tt.length, got, tt.want)
			}
		})
	}
}

func TestRegValueFieldLabel(t *testing.T) {
	if got := regValueFieldLabel(nil); got != "" {
		t.Errorf("nil regVal = %q, want empty", got)
	}
	// Meta type → meta key name.
	meta := &registerValue{valueType: regTypeMeta, metaKey: unix.NFT_META_MARK}
	if got := regValueFieldLabel(meta); got != "mark" {
		t.Errorf("meta mark = %q, want mark", got)
	}
	// CT type → ct key name.
	ct := &registerValue{valueType: regTypeCT, ctKey: expr.CtKeySTATE}
	if got := regValueFieldLabel(ct); got == "" {
		t.Error("ct key produced an empty label")
	}
	// Payload type → "<proto> <field>" (ip saddr).
	pay := &registerValue{
		valueType:     regTypePayload,
		payloadBase:   unix.NFT_PAYLOAD_NETWORK_HEADER,
		payloadOff:    12,
		payloadLen:    4,
		payloadFamily: payloadFamilyIPv4,
	}
	if got := regValueFieldLabel(pay); got != "ip saddr" {
		t.Errorf("payload saddr = %q, want \"ip saddr\"", got)
	}
	// Unknown type → empty.
	if got := regValueFieldLabel(&registerValue{valueType: regTypeImmediate}); got != "" {
		t.Errorf("immediate = %q, want empty", got)
	}
}

func TestFormatDynsetSimple(t *testing.T) {
	// Bare add with no key, no invert, no timeout → just "add @name".
	if got := formatDynsetSimple(&expr.Dynset{Operation: 0, SetName: "flood"}, ""); got != "add @flood" {
		t.Errorf("bare = %q, want \"add @flood\"", got)
	}
	// Key field, invert and a timeout populate the brace body.
	d := &expr.Dynset{
		Operation: 1, // update
		SetName:   "conns",
		Invert:    true,
		Timeout:   30 * time.Second,
	}
	got := formatDynsetSimple(d, "ip saddr")
	for _, want := range []string{"update @conns", "ip saddr", "!=", "timeout 30s", "{", "}"} {
		if !strings.Contains(got, want) {
			t.Errorf("formatDynsetSimple = %q, missing %q", got, want)
		}
	}
}

func TestTableFamilyHint(t *testing.T) {
	cases := []struct {
		name string
		rule *nftables.Rule
		want payloadFamilyHint
	}{
		{"nil rule", nil, payloadFamilyAny},
		{"nil table", &nftables.Rule{}, payloadFamilyAny},
		{"ipv4", &nftables.Rule{Table: &nftables.Table{Family: nftables.TableFamilyIPv4}}, payloadFamilyIPv4},
		{"ipv6", &nftables.Rule{Table: &nftables.Table{Family: nftables.TableFamilyIPv6}}, payloadFamilyIPv6},
		{"inet → any", &nftables.Rule{Table: &nftables.Table{Family: nftables.TableFamilyINet}}, payloadFamilyAny},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := tableFamilyHint(tt.rule); got != tt.want {
				t.Errorf("tableFamilyHint = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatMACBytes(t *testing.T) {
	if got := formatMACBytes([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}); got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("formatMACBytes = %q", got)
	}
	if got := formatMACBytes([]byte{0xaa, 0xbb}); got != "" {
		t.Errorf("short MAC = %q, want empty", got)
	}
}
