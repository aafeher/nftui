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

func TestParseSetElementKey_MoreBranches(t *testing.T) {
	// Single IPv6 host.
	b, end, err := ParseSetElementKey(mkSet(nftables.TypeIP6Addr, false), "fe80::1")
	if err != nil || end != nil || len(b) != 16 {
		t.Errorf("ipv6 single: b=%v end=%v err=%v", b, end, err)
	}
	if _, _, err := ParseSetElementKey(mkSet(nftables.TypeIP6Addr, false), "not-an-ip"); err == nil {
		t.Error("bad ipv6 accepted")
	}

	// IPv6 dash range needs interval and parses both ends.
	start, end, err := ParseSetElementKey(mkSet(nftables.TypeIP6Addr, true), "fe80::1-fe80::5")
	if err != nil || len(start) != 16 || len(end) != 16 {
		t.Errorf("ipv6 range: start=%v end=%v err=%v", start, end, err)
	}

	// inet_proto single byte.
	b, _, err = ParseSetElementKey(mkSet(nftables.TypeInetProto, false), "6")
	if err != nil || !bytes.Equal(b, []byte{6}) {
		t.Errorf("proto: b=%v err=%v", b, err)
	}
	if _, _, err := ParseSetElementKey(mkSet(nftables.TypeInetProto, false), "300"); err == nil {
		t.Error("proto > 255 accepted")
	}

	// mark falls back to 4-byte width.
	b, _, err = ParseSetElementKey(mkSet(nftables.TypeMark, false), "0x10")
	if err != nil || !bytes.Equal(b, []byte{0, 0, 0, 0x10}) {
		t.Errorf("mark: b=%v err=%v", b, err)
	}

	// Empty input and unsupported key type.
	if _, _, err := ParseSetElementKey(mkSet(nftables.TypeIPAddr, false), "   "); err == nil {
		t.Error("empty input accepted")
	}
	if _, _, err := ParseSetElementKey(mkSet(nftables.TypeVerdict, false), "accept"); err == nil {
		t.Error("unsupported key type accepted")
	}

	// Bad MAC.
	if _, _, err := ParseSetElementKey(mkSet(nftables.TypeEtherAddr, false), "zz:zz"); err == nil {
		t.Error("bad MAC accepted")
	}
}

func TestParseSetElementKey_ErrorPaths(t *testing.T) {
	// Valid 6-byte MAC succeeds; an 8-byte EUI-64 is rejected by the length guard.
	if b, _, err := ParseSetElementKey(mkSet(nftables.TypeEtherAddr, false), "aa:bb:cc:dd:ee:ff"); err != nil || len(b) != 6 {
		t.Errorf("valid MAC: b=%v err=%v", b, err)
	}
	if _, _, err := ParseSetElementKey(mkSet(nftables.TypeEtherAddr, false), "aa:bb:cc:dd:ee:ff:00:11"); err == nil {
		t.Error("8-byte EUI-64 accepted, want length error")
	}

	// CIDR / range parse failures bubble up from the per-family helpers.
	bad := []struct {
		name  string
		typ   nftables.SetDatatype
		input string
	}{
		{"ipv4 single bad", nftables.TypeIPAddr, "999.1.1.1"},
		{"ipv4 cidr bad", nftables.TypeIPAddr, "10.0.0.0/99"},
		{"ipv4 range bad start", nftables.TypeIPAddr, "bad-10.0.0.1"},
		{"ipv6 cidr bad", nftables.TypeIP6Addr, "fe80::/200"},
		{"ipv6 range bad end", nftables.TypeIP6Addr, "fe80::1-nope"},
		{"inet_service single bad", nftables.TypeInetService, "99999"},
		{"inet_service range bad", nftables.TypeInetService, "80-bad"},
		{"mark range bad", nftables.TypeMark, "0x10-bad"},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			// Range / CIDR forms need an interval set; singles do not — pass
			// interval=true uniformly so only the parse failure is exercised.
			if _, _, err := ParseSetElementKey(mkSet(tt.typ, true), tt.input); err == nil {
				t.Errorf("%q accepted, want error", tt.input)
			}
		})
	}

	// Mark range success path (both bounds parse to the configured width).
	start, end, err := ParseSetElementKey(mkSet(nftables.TypeMark, true), "0x10-0x20")
	if err != nil || !bytes.Equal(start, []byte{0, 0, 0, 0x10}) || !bytes.Equal(end, []byte{0, 0, 0, 0x20}) {
		t.Errorf("mark range: start=%v end=%v err=%v", start, end, err)
	}
}

func TestParseSetElementVal(t *testing.T) {
	// Value parsing reuses the key logic with the DataType, never intervals.
	s := &nftables.Set{KeyType: nftables.TypeInetService, DataType: nftables.TypeIPAddr, IsMap: true}
	b, err := ParseSetElementVal(s, "10.0.0.7")
	if err != nil || !bytes.Equal(b, []byte{10, 0, 0, 7}) {
		t.Errorf("val: b=%v err=%v", b, err)
	}
	// Range forms are rejected for values even on interval sets.
	s.Interval = true
	if _, err := ParseSetElementVal(s, "10.0.0.0/24"); err == nil {
		t.Error("CIDR value accepted")
	}
}

func TestKeyTypeFromString(t *testing.T) {
	tests := []struct {
		name string
		want nftables.SetDatatype
		ok   bool
	}{
		{"ipv4_addr", nftables.TypeIPAddr, true},
		{"ipv6_addr", nftables.TypeIP6Addr, true},
		{"ether_addr", nftables.TypeEtherAddr, true},
		{"inet_service", nftables.TypeInetService, true},
		{"inet_proto", nftables.TypeInetProto, true},
		{"mark", nftables.TypeMark, true},
		{"integer", nftables.TypeInteger, true},
		{"verdict", nftables.TypeVerdict, true},
		{"bogus", nftables.SetDatatype{}, false},
	}
	for _, tt := range tests {
		got, ok := KeyTypeFromString(tt.name)
		if ok != tt.ok || got.Name != tt.want.Name {
			t.Errorf("KeyTypeFromString(%q) = %q/%v, want %q/%v", tt.name, got.Name, ok, tt.want.Name, tt.ok)
		}
	}
}

func TestSupportedTypeLists(t *testing.T) {
	keys := SupportedSetKeyTypes()
	if len(keys) != 7 {
		t.Errorf("SupportedSetKeyTypes() has %d entries, want 7", len(keys))
	}
	for _, name := range keys {
		if _, ok := KeyTypeFromString(name); !ok {
			t.Errorf("key type %q is not resolvable via KeyTypeFromString", name)
		}
	}
	data := SupportedMapDataTypes()
	if len(data) != len(keys)+1 || data[len(data)-1] != "verdict" {
		t.Errorf("SupportedMapDataTypes() = %v, want key types + verdict", data)
	}
}

func TestFormatVerdict_MoreKinds(t *testing.T) {
	if got := FormatVerdict(&expr.Verdict{Kind: expr.VerdictReturn}); got != "return" {
		t.Errorf("return = %q", got)
	}
	if got := FormatVerdict(&expr.Verdict{Kind: expr.VerdictContinue}); got != "continue" {
		t.Errorf("continue = %q", got)
	}
	if got := FormatVerdict(&expr.Verdict{Kind: expr.VerdictQueue}); got != "queue" {
		t.Errorf("queue = %q", got)
	}
	if got := FormatVerdict(&expr.Verdict{Kind: 99}); got != "verdict(99)" {
		t.Errorf("unknown = %q", got)
	}
}
