package nftexpr

import (
	"testing"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestMetaKeyToString(t *testing.T) {
	tests := []struct {
		metaKey expr.MetaKey
		want    string
	}{
		{unix.NFT_META_LEN, "len"},
		{unix.NFT_META_PROTOCOL, "protocol"},
		{unix.NFT_META_PRIORITY, "priority"},
		{unix.NFT_META_MARK, "mark"},
		{unix.NFT_META_IIF, "iif"},
		{unix.NFT_META_OIF, "oif"},
		{unix.NFT_META_IIFNAME, "iifname"},
		{unix.NFT_META_OIFNAME, "oifname"},
		{unix.NFT_META_IIFTYPE, "iiftype"},
		{unix.NFT_META_OIFTYPE, "oiftype"},
		{unix.NFT_META_SKUID, "skuid"},
		{unix.NFT_META_SKGID, "skgid"},
		{unix.NFT_META_NFTRACE, "nftrace"},
		{unix.NFT_META_RTCLASSID, "rtclassid"},
		{unix.NFT_META_SECMARK, "secmark"},
		{unix.NFT_META_NFPROTO, "nfproto"},
		{unix.NFT_META_L4PROTO, "l4proto"},
		{unix.NFT_META_BRI_IIFNAME, "bri_iifname"},
		{unix.NFT_META_BRI_OIFNAME, "bri_oifname"},
		{unix.NFT_META_PKTTYPE, "pkttype"},
		{unix.NFT_META_CPU, "cpu"},
		{unix.NFT_META_IIFGROUP, "iifgroup"},
		{unix.NFT_META_OIFGROUP, "oifgroup"},
		{unix.NFT_META_CGROUP, "cgroup"},
		{unix.NFT_META_PRANDOM, "prandom"},
		{expr.MetaKey(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := MetaKeyToString(tt.metaKey)
			if got != tt.want {
				t.Errorf("MetaKeyToString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatMeta(t *testing.T) {
	tests := []struct {
		meta expr.Meta
		want string
	}{
		{expr.Meta{Key: unix.NFT_META_LEN, SourceRegister: true, Register: 1}, "key len sreg 1"},
		{expr.Meta{Key: unix.NFT_META_PRIORITY, SourceRegister: false, Register: 2}, "key priority dreg 2"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := FormatMeta(&tt.meta)
			if got != tt.want {
				t.Errorf("FormatMeta() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCmpOpToString(t *testing.T) {
	tests := []struct {
		cmpOp expr.CmpOp
		want  string
	}{
		{unix.NFT_CMP_EQ, "=="},
		{unix.NFT_CMP_NEQ, "!="},
		{unix.NFT_CMP_LT, "<"},
		{unix.NFT_CMP_LTE, "<="},
		{unix.NFT_CMP_GT, ">"},
		{unix.NFT_CMP_GTE, ">="},
		{expr.CmpOp(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := CmpOpToString(tt.cmpOp)
			if got != tt.want {
				t.Errorf("CmpOpToString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatCmp(t *testing.T) {
	tests := []struct {
		cmp  expr.Cmp
		want string
	}{
		{expr.Cmp{Register: 1, Op: unix.NFT_CMP_EQ, Data: []byte{127, 0, 0, 1}}, "cmp 1 == 127.0.0.1"},
		{expr.Cmp{Register: 2, Op: unix.NFT_CMP_GT, Data: []byte{123}}, "cmp 2 > 123"},
		{expr.Cmp{Register: 3, Op: expr.CmpOp(999), Data: []byte{255}}, "cmp 3 unknown 255"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := FormatCmp(&tt.cmp)
			if got != tt.want {
				t.Errorf("FormatCmp() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatData(t *testing.T) {
	tests := []struct {
		bytes []byte
		want  string
	}{
		{[]byte{127, 0, 0, 1}, "127.0.0.1"},
		{[]byte{255}, "255"},
		{[]byte{1, 2, 3, 4, 5}, "0x0102030405"},
		{[]byte{}, "0x"},
		{[]byte{0, 80}, "80"},
		// 4-byte data is always formatted as IPv4
		{[]byte{0, 0, 0, 100}, "0.0.0.100"},
		{[]byte{'h', 'e', 'l', 'l', 'o', 0}, `"hello"`},
		// 4-byte non-printable hex: treated as IPv4
		{[]byte{0x20, 0x21, 0x7e, 0x7f}, "32.33.126.127"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatData(tt.bytes)
			if got != tt.want {
				t.Errorf("formatData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsPrintable(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"empty", []byte{}, false},
		{"printable ascii", []byte("hello"), true},
		{"with null", []byte{'h', 'i', 0}, true},
		{"control char", []byte{0x01, 0x02}, false},
		{"high byte", []byte{0x80}, false},
		{"space", []byte{0x20}, true},
		{"tilde", []byte{0x7e}, true},
		{"del", []byte{0x7f}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPrintable(tt.data)
			if got != tt.want {
				t.Errorf("isPrintable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSerializeMasq(t *testing.T) {
	tests := []struct {
		name string
		masq expr.Masq
		want string
	}{
		{"plain", expr.Masq{}, "masquerade"},
		{"random", expr.Masq{Random: true}, "masquerade random"},
		{"fully-random", expr.Masq{FullyRandom: true}, "masquerade fully-random"},
		{"persistent", expr.Masq{Persistent: true}, "masquerade persistent"},
		{"all flags", expr.Masq{Random: true, FullyRandom: true, Persistent: true}, "masquerade random fully-random persistent"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SerializeMasq(&tt.masq)
			if got != tt.want {
				t.Errorf("SerializeMasq() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSerializeCmp(t *testing.T) {
	tests := []struct {
		name string
		cmp  expr.Cmp
		want string
	}{
		{"eq ip", expr.Cmp{Op: expr.CmpOpEq, Data: []byte{10, 0, 0, 1}}, "10.0.0.1"},
		{"neq port", expr.Cmp{Op: expr.CmpOpNeq, Data: []byte{0, 80}}, "!= 80"},
		{"lt single byte", expr.Cmp{Op: expr.CmpOpLt, Data: []byte{10}}, "< 10"},
		// 4-byte data is always formatted as IPv4
		{"gte ipv4", expr.Cmp{Op: expr.CmpOpGte, Data: []byte{0, 0, 0, 5}}, ">= 0.0.0.5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SerializeCmp(&tt.cmp, nil)
			if got != tt.want {
				t.Errorf("SerializeCmp() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDataToHumanReadable(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		context string
		want    string
	}{
		{"empty", []byte{}, "any", "0"},
		{"protocol tcp", []byte{6}, "l4proto", "tcp"},
		{"protocol udp", []byte{17}, "l4proto", "udp"},
		{"protocol icmp", []byte{1}, "l4proto", "icmp"},
		{"protocol icmpv6", []byte{58}, "l4proto", "icmpv6"},
		{"protocol unknown", []byte{99}, "l4proto", "99"},
		{"dport", []byte{0, 80}, "dport", "80"},
		{"sport", []byte{0x1f, 0x90}, "sport", "8080"},
		{"saddr", []byte{192, 168, 1, 1}, "saddr", "192.168.1.1"},
		{"daddr", []byte{10, 0, 0, 1}, "daddr", "10.0.0.1"},
		{"ifname", []byte{'e', 't', 'h', '0', 0}, "iifname", `"eth0"`},
		{"icmp echo-request", []byte{8}, "icmp type", "echo-request"},
		{"icmp echo-reply", []byte{0}, "icmp type", "echo-reply"},
		{"icmp unknown", []byte{5}, "icmp type", "5"},
		{"hex fallback", []byte{0xde, 0xad}, "other", "0xdead"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DataToHumanReadable(tt.data, tt.context)
			if got != tt.want {
				t.Errorf("DataToHumanReadable(%v, %q) = %q, want %q", tt.data, tt.context, got, tt.want)
			}
		})
	}
}
