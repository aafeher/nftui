package nft

// Tests for the pure expr→Action converters and small parse helpers in
// rule.go. All are called from NftablesToRuleDefinition's dispatch; testing
// them directly keeps the fixtures small and netlink-free.

import (
	"testing"

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
}

func TestRedirToAction(t *testing.T) {
	regs := map[uint32]*registerValue{
		1: {immediateData: []byte{0x00, 0x50}}, // port 80
	}

	act := redirToAction(&expr.Redir{RegisterProtoMin: 1}, regs)
	if act.Type != ActionTypeRedirect || act.Redirect == nil {
		t.Fatalf("action = %+v", act)
	}
	if act.Redirect.PortRange == nil || act.Redirect.PortRange.From != 80 || act.Redirect.PortRange.To != 80 {
		t.Errorf("port range = %+v, want 80-80", act.Redirect.PortRange)
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
		{"rt type", 43, 2, 1, "type"},
		{"rt seg-left", 43, 3, 1, "seg-left"},
		{"mh checksum", 135, 4, 2, "checksum"},
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
	// Unknown type → empty.
	if got := regValueFieldLabel(&registerValue{valueType: regTypeImmediate}); got != "" {
		t.Errorf("immediate = %q, want empty", got)
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
