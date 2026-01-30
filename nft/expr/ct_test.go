package nftexpr

import (
	"testing"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestCtKeyToString(t *testing.T) {
	tests := []struct {
		ctKey expr.CtKey
		want  string
	}{
		{unix.NFT_CT_STATE, "state"},
		{unix.NFT_CT_DIRECTION, "direction"},
		{unix.NFT_CT_STATUS, "status"},
		{unix.NFT_CT_MARK, "mark"},
		{unix.NFT_CT_SECMARK, "secmark"},
		{unix.NFT_CT_EXPIRATION, "expiration"},
		{unix.NFT_CT_HELPER, "helper"},
		{unix.NFT_CT_L3PROTOCOL, "l3protocol"},
		{unix.NFT_CT_SRC, "src"},
		{unix.NFT_CT_DST, "dst"},
		{unix.NFT_CT_PROTOCOL, "protocol"},
		{unix.NFT_CT_PROTO_SRC, "proto_src"},
		{unix.NFT_CT_PROTO_DST, "proto_dst"},
		{unix.NFT_CT_LABELS, "labels"},
		{unix.NFT_CT_PKTS, "pkts"},
		{unix.NFT_CT_BYTES, "bytes"},
		{unix.NFT_CT_AVGPKT, "avgpkt"},
		{unix.NFT_CT_ZONE, "zone"},
		{unix.NFT_CT_EVENTMASK, "eventmask"},
		{expr.CtKey(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := CtKeyToString(tt.ctKey)
			if got != tt.want {
				t.Errorf("CtKeyToString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatCt(t *testing.T) {
	tests := []struct {
		ct   expr.Ct
		want string
	}{
		{expr.Ct{Register: 1, SourceRegister: true, Key: unix.NFT_CT_STATE, Direction: 0}, "ct 1 sreg state 0"},
		{expr.Ct{Register: 2, SourceRegister: false, Key: unix.NFT_CT_SRC, Direction: 1}, "ct 2 dreg src 1"},
		{expr.Ct{Register: 3, SourceRegister: true, Key: expr.CtKey(999), Direction: 2}, "ct 3 sreg unknown 2"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := FormatCt(&tt.ct)
			if got != tt.want {
				t.Errorf("FormatCt() = %v, want %v", got, tt.want)
			}
		})
	}
}
