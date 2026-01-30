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
