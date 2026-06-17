package ui

// Pure code<->name mapper and formatter tests for the field editors. These
// helpers (dccp / icmp / icmpv6 type names, arphrd / nfproto / pkttype meta
// codes, ethertype text parsing, the icmp/icmpv6 format helpers) are pure
// table lookups with a numeric / empty fallback — no Bubble Tea state, no
// netlink.

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestTcpFlagsByteRoundTrip(t *testing.T) {
	// Single-bit decode.
	if got := tcpFlagsByteToNames(tcpFlagSYN); len(got) != 1 || got[0] != "syn" {
		t.Errorf("syn byte = %v, want [syn]", got)
	}
	// Multi-bit decode preserves the canonical name order (fin,syn,...).
	got := tcpFlagsByteToNames(tcpFlagSYN | tcpFlagACK)
	if len(got) != 2 || got[0] != "syn" || got[1] != "ack" {
		t.Errorf("syn|ack = %v, want [syn ack]", got)
	}
	// Zero byte yields an empty (non-nil) slice.
	if got := tcpFlagsByteToNames(0); len(got) != 0 {
		t.Errorf("0 = %v, want empty", got)
	}
	// Round-trip: names → byte → names is stable.
	names := []string{"fin", "psh", "urg"}
	if back := tcpFlagsByteToNames(tcpFlagsNamesToByte(names)); len(back) != 3 {
		t.Errorf("round-trip = %v, want 3 flags", back)
	}
}

func TestDccpTypeCodeToName(t *testing.T) {
	cases := map[uint8]string{0: "request", 1: "response", 9: "syncack"}
	for code, want := range cases {
		if got := dccpTypeCodeToName(code); got != want {
			t.Errorf("dccpTypeCodeToName(%d) = %q, want %q", code, got, want)
		}
	}
	if got := dccpTypeCodeToName(99); got != "" {
		t.Errorf("unknown dccp = %q, want empty", got)
	}
}

func TestIcmpTypeCodeToName(t *testing.T) {
	cases := map[uint8]string{0: "echo-reply", 8: "echo-request", 3: "destination-unreachable"}
	for code, want := range cases {
		if got := icmpTypeCodeToName(code); got != want {
			t.Errorf("icmpTypeCodeToName(%d) = %q, want %q", code, got, want)
		}
	}
	if got := icmpTypeCodeToName(200); got != "" {
		t.Errorf("unknown icmp = %q, want empty", got)
	}
}

func TestIcmpv6TypeCodeToName(t *testing.T) {
	cases := map[uint8]string{1: "destination-unreachable", 128: "echo-request", 129: "echo-reply"}
	for code, want := range cases {
		if got := icmpv6TypeCodeToName(code); got != want {
			t.Errorf("icmpv6TypeCodeToName(%d) = %q, want %q", code, got, want)
		}
	}
	if got := icmpv6TypeCodeToName(250); got != "" {
		t.Errorf("unknown icmpv6 = %q, want empty", got)
	}
}

func TestFormatICMP(t *testing.T) {
	// Named type.
	if got := formatICMP("type", uint8(8)); !strings.Contains(got, "type") || !strings.Contains(got, "echo-request") {
		t.Errorf("formatICMP type 8 = %q, want icmp type echo-request", got)
	}
	// Unknown numeric type.
	if got := formatICMP("type", uint8(200)); !strings.Contains(got, "200") {
		t.Errorf("formatICMP type 200 = %q, want numeric", got)
	}
	// Non-type uint8 field (code).
	if got := formatICMP("code", uint8(3)); !strings.Contains(got, "code") || !strings.Contains(got, "3") {
		t.Errorf("formatICMP code = %q", got)
	}
	// uint16 value.
	if got := formatICMP("id", uint16(1234)); !strings.Contains(got, "1234") {
		t.Errorf("formatICMP uint16 = %q", got)
	}
	// Other type falls through to %v.
	if got := formatICMP("x", "raw"); !strings.Contains(got, "raw") {
		t.Errorf("formatICMP other = %q", got)
	}
}

func TestFormatICMPv6(t *testing.T) {
	if got := formatICMPv6("type", uint8(128)); !strings.Contains(got, "echo-request") {
		t.Errorf("formatICMPv6 type 128 = %q", got)
	}
	if got := formatICMPv6("type", uint8(250)); !strings.Contains(got, "250") {
		t.Errorf("formatICMPv6 type 250 = %q", got)
	}
	if got := formatICMPv6("code", uint8(0)); !strings.Contains(got, "code") {
		t.Errorf("formatICMPv6 code = %q", got)
	}
	if got := formatICMPv6("mtu", uint32(1280)); !strings.Contains(got, "1280") {
		t.Errorf("formatICMPv6 uint32 = %q", got)
	}
	if got := formatICMPv6("x", "raw"); !strings.Contains(got, "raw") {
		t.Errorf("formatICMPv6 other = %q", got)
	}
}

func TestArphrdCodeToName(t *testing.T) {
	if got := arphrdCodeToName(unix.ARPHRD_ETHER); got != "ether" {
		t.Errorf("arphrd ether = %q", got)
	}
	if got := arphrdCodeToName(unix.ARPHRD_LOOPBACK); got != "loopback" {
		t.Errorf("arphrd loopback = %q", got)
	}
	// Unknown code falls back to the decimal string.
	if got := arphrdCodeToName(9999); got != "9999" {
		t.Errorf("arphrd unknown = %q, want 9999", got)
	}
}

func TestNfprotoCodeToName(t *testing.T) {
	if got := nfprotoCodeToName(unix.NFPROTO_IPV4); got != "ipv4" {
		t.Errorf("nfproto ipv4 = %q", got)
	}
	if got := nfprotoCodeToName(unix.NFPROTO_IPV6); got != "ipv6" {
		t.Errorf("nfproto ipv6 = %q", got)
	}
	if got := nfprotoCodeToName(99); got != "99" {
		t.Errorf("nfproto unknown = %q, want 99", got)
	}
}

func TestPkttypeCodeToName(t *testing.T) {
	cases := map[uint8]string{
		unix.PACKET_HOST:      "host",
		unix.PACKET_BROADCAST: "broadcast",
		unix.PACKET_MULTICAST: "multicast",
		unix.PACKET_OTHERHOST: "other",
	}
	for code, want := range cases {
		if got := pkttypeCodeToName(code); got != want {
			t.Errorf("pkttypeCodeToName(%d) = %q, want %q", code, got, want)
		}
	}
	if got := pkttypeCodeToName(99); got != "99" {
		t.Errorf("pkttype unknown = %q, want 99", got)
	}
}

func TestParseEtherTypeText(t *testing.T) {
	cases := []struct {
		in   string
		want uint16
	}{
		{"2048", 2048},
		{"0x0800", 0x0800},
		{"0X86DD", 0x86dd},
		{"  0x806  ", 0x806},
	}
	for _, c := range cases {
		got, err := parseEtherTypeText(c.in)
		if err != nil || got != c.want {
			t.Errorf("parseEtherTypeText(%q) = %d, %v; want %d", c.in, got, err, c.want)
		}
	}

	for _, bad := range []string{"", "   ", "xyz", "0xZZ", "99999999"} {
		if _, err := parseEtherTypeText(bad); err == nil {
			t.Errorf("parseEtherTypeText(%q) accepted, want error", bad)
		}
	}
}
