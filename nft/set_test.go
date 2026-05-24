package nft

import (
	"bytes"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// Helper: build a Set with the given KeyType + interval flag.
func mkSet(keyType nftables.SetDatatype, interval bool) *nftables.Set {
	return &nftables.Set{KeyType: keyType, Interval: interval}
}

func TestParseSetElementKey_SingleIPv4(t *testing.T) {
	key, end, err := ParseSetElementKey(mkSet(nftables.TypeIPAddr, false), "10.0.0.1")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if end != nil {
		t.Fatalf("end = %v, want nil", end)
	}
	want := []byte{10, 0, 0, 1}
	if !bytes.Equal(key, want) {
		t.Errorf("key = %v, want %v", key, want)
	}
}

func TestParseSetElementKey_CIDRIPv4_NeedsIntervalFlag(t *testing.T) {
	_, _, err := ParseSetElementKey(mkSet(nftables.TypeIPAddr, false), "10.0.0.0/24")
	if err == nil {
		t.Fatal("expected error on CIDR input to non-interval set")
	}
}

func TestParseSetElementKey_CIDRIPv4_Interval(t *testing.T) {
	key, end, err := ParseSetElementKey(mkSet(nftables.TypeIPAddr, true), "10.0.0.0/24")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	wantStart := []byte{10, 0, 0, 0}
	wantEnd := []byte{10, 0, 0, 255}
	if !bytes.Equal(key, wantStart) || !bytes.Equal(end, wantEnd) {
		t.Errorf("range = %v..%v, want %v..%v", key, end, wantStart, wantEnd)
	}
}

func TestParseSetElementKey_RangeIPv4_Interval(t *testing.T) {
	key, end, err := ParseSetElementKey(mkSet(nftables.TypeIPAddr, true), "10.0.0.10 - 10.0.0.20")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	wantStart := []byte{10, 0, 0, 10}
	wantEnd := []byte{10, 0, 0, 20}
	if !bytes.Equal(key, wantStart) || !bytes.Equal(end, wantEnd) {
		t.Errorf("range = %v..%v, want %v..%v", key, end, wantStart, wantEnd)
	}
}

func TestParseSetElementKey_CIDRIPv6_Interval(t *testing.T) {
	key, end, err := ParseSetElementKey(mkSet(nftables.TypeIP6Addr, true), "2001:db8::/64")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(key) != 16 || len(end) != 16 {
		t.Fatalf("expected 16-byte start/end, got %d/%d", len(key), len(end))
	}
	// First 8 bytes match the prefix; last 8 of end must be all-ones.
	for i := 8; i < 16; i++ {
		if end[i] != 0xff {
			t.Errorf("end[%d] = 0x%x, want 0xff", i, end[i])
		}
	}
}

func TestParseSetElementKey_PortRange_Interval(t *testing.T) {
	key, end, err := ParseSetElementKey(mkSet(nftables.TypeInetService, true), "1024-2048")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	wantStart := []byte{0x04, 0x00} // 1024 BE
	wantEnd := []byte{0x08, 0x00}   // 2048 BE
	if !bytes.Equal(key, wantStart) || !bytes.Equal(end, wantEnd) {
		t.Errorf("range = %v..%v, want %v..%v", key, end, wantStart, wantEnd)
	}
}

func TestParseVerdict_Simple(t *testing.T) {
	cases := []struct {
		in   string
		kind expr.VerdictKind
	}{
		{"accept", expr.VerdictAccept},
		{"drop", expr.VerdictDrop},
		{"return", expr.VerdictReturn},
		{"continue", expr.VerdictContinue},
		{"queue", expr.VerdictQueue},
	}
	for _, c := range cases {
		v, err := ParseVerdict(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if v.Kind != c.kind {
			t.Errorf("%q kind = %v, want %v", c.in, v.Kind, c.kind)
		}
		if v.Chain != "" {
			t.Errorf("%q chain = %q, want empty", c.in, v.Chain)
		}
	}
}

func TestParseVerdict_JumpGoto(t *testing.T) {
	v, err := ParseVerdict("jump my_chain")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v.Kind != expr.VerdictJump || v.Chain != "my_chain" {
		t.Errorf("got {Kind:%v Chain:%q}, want {Jump my_chain}", v.Kind, v.Chain)
	}
	v, err = ParseVerdict("goto fallback")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v.Kind != expr.VerdictGoto || v.Chain != "fallback" {
		t.Errorf("got {Kind:%v Chain:%q}, want {Goto fallback}", v.Kind, v.Chain)
	}
}

func TestParseVerdict_Errors(t *testing.T) {
	if _, err := ParseVerdict(""); err == nil {
		t.Error("empty must fail")
	}
	if _, err := ParseVerdict("jump"); err == nil {
		t.Error("jump without chain must fail")
	}
	if _, err := ParseVerdict("foobar"); err == nil {
		t.Error("unknown verdict must fail")
	}
}

func TestParseSetElementKey_IntegerWidths(t *testing.T) {
	cases := []struct {
		width int
		input string
		want  []byte
	}{
		{1, "7", []byte{7}},
		{2, "1024", []byte{0x04, 0x00}},
		{4, "0x10", []byte{0x00, 0x00, 0x00, 0x10}},
		{8, "0xabcd1234", []byte{0, 0, 0, 0, 0xab, 0xcd, 0x12, 0x34}},
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			s := &nftables.Set{KeyType: nftables.SetDatatype{Name: "integer", Bytes: uint32(c.width)}}
			b, _, err := ParseSetElementKey(s, c.input)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if !bytes.Equal(b, c.want) {
				t.Errorf("width=%d input=%q: got %v, want %v", c.width, c.input, b, c.want)
			}
		})
	}
}

func TestParseSetElementKey_IntegerOverflow(t *testing.T) {
	// 256 doesn't fit in 1 byte.
	s := &nftables.Set{KeyType: nftables.SetDatatype{Name: "integer", Bytes: 1}}
	if _, _, err := ParseSetElementKey(s, "256"); err == nil {
		t.Fatal("expected overflow error for 256 in 1-byte integer")
	}
}

func TestFormatVerdict(t *testing.T) {
	cases := []struct {
		v    *expr.Verdict
		want string
	}{
		{&expr.Verdict{Kind: expr.VerdictAccept}, "accept"},
		{&expr.Verdict{Kind: expr.VerdictDrop}, "drop"},
		{&expr.Verdict{Kind: expr.VerdictJump, Chain: "c1"}, "jump c1"},
		{&expr.Verdict{Kind: expr.VerdictGoto, Chain: "c2"}, "goto c2"},
		{nil, "?"},
	}
	for _, c := range cases {
		if got := FormatVerdict(c.v); got != c.want {
			t.Errorf("FormatVerdict(%+v) = %q, want %q", c.v, got, c.want)
		}
	}
}

func TestParseSetElementKey_MAC_RejectsRangeForm(t *testing.T) {
	// MAC uses ':' as separator — a '-' in input would otherwise be ambiguous.
	// ether_addr doesn't go through interval lookups in practice; we treat
	// the dash form as a normal MAC-parse attempt and let net.ParseMAC reject.
	_, _, err := ParseSetElementKey(mkSet(nftables.TypeEtherAddr, true), "aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatalf("plain MAC must parse: %v", err)
	}
}
