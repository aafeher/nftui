package nft

// Direct tests for the low-level byte parsers in set.go. They are reached
// indirectly through ParseSetElementKey, but their error branches (invalid
// input, wrong family, unsupported width) are only exercised cleanly when
// called head-on. All are pure and netlink-free.

import (
	"bytes"
	"testing"
)

func TestParseIP4(t *testing.T) {
	got, err := parseIP4("10.0.0.5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := []byte{10, 0, 0, 5}; !bytes.Equal(got, want) {
		t.Errorf("parseIP4 = %v, want %v", got, want)
	}
	if _, err := parseIP4("not-an-ip"); err == nil {
		t.Error("expected error for garbage input")
	}
	// A valid IPv6 literal parses as an IP but has no 4-byte form.
	if _, err := parseIP4("2001:db8::1"); err == nil {
		t.Error("expected error for IPv6 passed to parseIP4")
	}
}

func TestParseIP6(t *testing.T) {
	got, err := parseIP6("2001:db8::1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 16 {
		t.Errorf("parseIP6 len = %d, want 16", len(got))
	}
	if _, err := parseIP6("nope"); err == nil {
		t.Error("expected error for garbage input")
	}
}

func TestParseInetService(t *testing.T) {
	got, err := parseInetService("443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := []byte{0x01, 0xbb}; !bytes.Equal(got, want) {
		t.Errorf("parseInetService(443) = %v, want %v", got, want)
	}
	// 0x-hex form is accepted by ParseUint base 0.
	if got, err := parseInetService("0x50"); err != nil || !bytes.Equal(got, []byte{0x00, 0x50}) {
		t.Errorf("parseInetService(0x50) = %v, err %v", got, err)
	}
	if _, err := parseInetService("99999"); err == nil {
		t.Error("expected overflow error for out-of-range port")
	}
	if _, err := parseInetService("ssh"); err == nil {
		t.Error("expected error for non-numeric port")
	}
}

func TestParseUintBE(t *testing.T) {
	cases := []struct {
		s     string
		width int
		want  []byte
	}{
		{"255", 1, []byte{0xff}},
		{"0x1234", 2, []byte{0x12, 0x34}},
		{"66051", 4, []byte{0, 1, 2, 3}},
		{"1", 8, []byte{0, 0, 0, 0, 0, 0, 0, 1}},
	}
	for _, c := range cases {
		got, err := parseUintBE(c.s, c.width)
		if err != nil {
			t.Errorf("parseUintBE(%q, %d) error: %v", c.s, c.width, err)
			continue
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("parseUintBE(%q, %d) = %v, want %v", c.s, c.width, got, c.want)
		}
	}

	// Unsupported widths (bits < 8 or > 64).
	if _, err := parseUintBE("1", 0); err == nil {
		t.Error("expected error for width 0")
	}
	if _, err := parseUintBE("1", 16); err == nil {
		t.Error("expected error for width 16")
	}
	// Value that overflows the chosen width.
	if _, err := parseUintBE("256", 1); err == nil {
		t.Error("expected overflow error for 256 in 1 byte")
	}
	// Non-numeric value.
	if _, err := parseUintBE("xyz", 4); err == nil {
		t.Error("expected error for non-numeric value")
	}
}

func TestCidrToRange(t *testing.T) {
	start, end, err := cidrToRange("10.0.0.0/24", 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(start, []byte{10, 0, 0, 0}) || !bytes.Equal(end, []byte{10, 0, 0, 255}) {
		t.Errorf("v4 /24 = %v..%v, want 10.0.0.0..10.0.0.255", start, end)
	}

	start, end, err = cidrToRange("2001:db8::/120", 16)
	if err != nil {
		t.Fatalf("unexpected v6 error: %v", err)
	}
	if len(start) != 16 || len(end) != 16 || end[15] != 0xff {
		t.Errorf("v6 /120 end byte = %#x, want 0xff", end[15])
	}

	if _, _, err := cidrToRange("not-a-cidr", 4); err == nil {
		t.Error("expected error for malformed CIDR")
	}
	// Family mismatch: an IPv6 CIDR requested as 4 bytes.
	if _, _, err := cidrToRange("2001:db8::/64", 4); err == nil {
		t.Error("expected error for IPv6 CIDR with nbytes=4")
	}
	// Family mismatch the other way: IPv4 CIDR requested as 16 bytes.
	if _, _, err := cidrToRange("10.0.0.0/24", 16); err == nil {
		t.Error("expected error for IPv4 CIDR with nbytes=16")
	}
}

func TestDashRangeToBytes(t *testing.T) {
	start, end, err := dashRangeToBytes("80-90", parseInetService)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(start, []byte{0, 80}) || !bytes.Equal(end, []byte{0, 90}) {
		t.Errorf("range = %v..%v, want 80..90", start, end)
	}

	if _, _, err := dashRangeToBytes("nodash", parseInetService); err == nil {
		t.Error("expected error when no dash present")
	}
	if _, _, err := dashRangeToBytes("bad-90", parseInetService); err == nil {
		t.Error("expected error for invalid range start")
	}
	if _, _, err := dashRangeToBytes("80-bad", parseInetService); err == nil {
		t.Error("expected error for invalid range end")
	}
}
