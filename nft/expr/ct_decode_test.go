package nftexpr

// Branch sweep for DecodeCTValue, formatCtValue and FormatDuration. These
// decode register bytes into typed CT values and are pure (no netlink).

import (
	"reflect"
	"testing"

	"github.com/google/nftables/expr"
)

func TestDecodeCTValue_AllKeys(t *testing.T) {
	// state: single bit returns a scalar, multiple bits return a slice.
	if got := DecodeCTValue(expr.CtKeySTATE, le(expr.CtStateBitNEW)); got != CtStateNew {
		t.Errorf("state new = %v, want scalar CtStateNew", got)
	}
	if got := DecodeCTValue(expr.CtKeySTATE, le(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED)); !reflect.DeepEqual(got, []CtState{CtStateEstablished, CtStateRelated}) {
		t.Errorf("state est+rel = %v", got)
	}

	// direction: 0 = original, anything else = reply; 1-byte and 4-byte forms.
	if got := DecodeCTValue(expr.CtKeyDIRECTION, []byte{0}); got != CtDirectionOriginal {
		t.Errorf("dir 0 = %v, want original", got)
	}
	if got := DecodeCTValue(expr.CtKeyDIRECTION, le(1)); got != CtDirectionReply {
		t.Errorf("dir 1 = %v, want reply", got)
	}

	// eventmask: single + multi.
	if got := DecodeCTValue(expr.CtKeyEVENTMASK, le(CtEventBitNew)); got != CtEventNew {
		t.Errorf("event new = %v", got)
	}
	if got := DecodeCTValue(expr.CtKeyEVENTMASK, le(CtEventBitNew|CtEventBitDestroy)); !reflect.DeepEqual(got, []CtEvent{CtEventNew, CtEventDestroy}) {
		t.Errorf("event new+destroy = %v", got)
	}

	// status: single + multi.
	if got := DecodeCTValue(expr.CtKeySTATUS, le(CtStatusBitAssured)); got != CtStatusAssured {
		t.Errorf("status assured = %v", got)
	}
	if got := DecodeCTValue(expr.CtKeySTATUS, le(CtStatusBitConfirmed|CtStatusBitSnat)); !reflect.DeepEqual(got, []CtStatus{CtStatusConfirmed, CtStatusSnat}) {
		t.Errorf("status confirmed+snat = %v", got)
	}

	// expiration: ms→s division (>=1000), and small BE values pass through.
	if got := DecodeCTValue(expr.CtKeyEXPIRATION, beU32(30000)); got != uint32(30) {
		t.Errorf("expiration 30000ms = %v, want 30s", got)
	}
	if got := DecodeCTValue(expr.CtKeyEXPIRATION, beU32(30)); got != uint32(30) {
		t.Errorf("expiration 30 = %v, want 30", got)
	}
	if got := DecodeCTValue(expr.CtKeyEXPIRATION, []byte{1}); got != uint32(0) {
		t.Errorf("expiration short = %v, want 0", got)
	}

	// l3proto / protocol.
	if got := DecodeCTValue(expr.CtKeyL3PROTOCOL, []byte{2}); got != CtL3ProtoIPv4 {
		t.Errorf("l3proto 2 = %v, want ipv4", got)
	}
	if got := DecodeCTValue(expr.CtKeyPROTOCOL, []byte{6}); got != CtProtocolTCP {
		t.Errorf("protocol 6 = %v, want tcp", got)
	}

	// protosrc / protodst: 2-byte BE port.
	if got := DecodeCTValue(expr.CtKeyPROTOSRC, []byte{0x01, 0xbb}); got != uint16(443) {
		t.Errorf("protosrc = %v, want 443", got)
	}

	// src / dst: ipv4 + ipv6.
	if got := DecodeCTValue(expr.CtKeySRC, []byte{10, 0, 0, 1}); got != "10.0.0.1" {
		t.Errorf("src v4 = %v", got)
	}
	if got := DecodeCTValue(expr.CtKeyDST, []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}); got != "fe80::1" {
		t.Errorf("dst v6 = %v", got)
	}

	// counters: 8-byte LE/BE heuristic.
	if got := DecodeCTValue(expr.CtKeyBYTES, []byte{0, 0, 0, 0, 0, 0, 0, 100}); got != uint64(100) {
		t.Errorf("bytes BE = %v, want 100", got)
	}
	if got := DecodeCTValue(expr.CtKeyPKTS, []byte{5, 0, 0, 0}); got != uint64(5) {
		t.Errorf("pkts 4-byte = %v, want 5", got)
	}

	// helper: trimmed string.
	if got := DecodeCTValue(expr.CtKeyHELPER, []byte("ftp\x00\x00")); got != "ftp" {
		t.Errorf("helper = %q, want ftp", got)
	}

	// labels: bit-index list (empty mask → no indices).
	if got, ok := DecodeCTValue(expr.CtKeyLABELS, make([]byte, 16)).([]string); !ok || len(got) != 0 {
		t.Errorf("empty labels = %v, want empty []string", got)
	}
	if got := DecodeCTValue(expr.CtKeyLABELS, append([]byte{0x01}, make([]byte, 15)...)); !reflect.DeepEqual(got, []string{"0"}) {
		t.Errorf("labels bit 0 = %v, want [0]", got)
	}

	// zone: 2-byte LE.
	if got := DecodeCTValue(expr.CtKeyZONE, []byte{0x04, 0x00}); got != uint16(4) {
		t.Errorf("zone = %v, want 4", got)
	}

	// default fallback: 4 bytes → LE uint32.
	if got := DecodeCTValue(expr.CtKeyMARK, le(0xdead)); got != uint32(0xdead) {
		t.Errorf("mark fallback = %v", got)
	}
	// default fallback: non-4-byte → raw bytes.
	raw := []byte{1, 2, 3}
	if got := DecodeCTValue(expr.CtKeyMARK, raw); !reflect.DeepEqual(got, raw) {
		t.Errorf("raw fallback = %v", got)
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		seconds uint32
		want    string
	}{
		{0, "0s"},
		{45, "45s"},
		{90, "1m30s"},
		{3600, "1h"},
		{3661, "1h1m1s"},
		{86400, "1d"},
		{90061, "1d1h1m1s"},
		{120, "2m"},
	}
	for _, tt := range tests {
		if got := FormatDuration(tt.seconds); got != tt.want {
			t.Errorf("FormatDuration(%d) = %q, want %q", tt.seconds, got, tt.want)
		}
	}
}

// le builds a 4-byte little-endian buffer from a uint32.
func le(v uint32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

// beU32 builds a 4-byte big-endian buffer from a uint32.
func beU32(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func TestFormatCtValue(t *testing.T) {
	tests := []struct {
		name string
		key  expr.CtKey
		data []byte
		want string
	}{
		{"state single", expr.CtKeySTATE, le(expr.CtStateBitNEW), "new"},
		{"state multi", expr.CtKeySTATE, le(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED), "{established, related}"},
		{"direction", expr.CtKeyDIRECTION, []byte{0}, "original"},
		{"status single", expr.CtKeySTATUS, le(CtStatusBitAssured), "assured"},
		{"status multi", expr.CtKeySTATUS, le(CtStatusBitConfirmed | CtStatusBitSnat), "{confirmed, snat}"},
		{"mark", expr.CtKeyMARK, le(0xdead), "0x0000dead"},
		{"mark non-4-byte", expr.CtKeyMARK, []byte{0xab}, "0xab"},
		{"eventmask single", expr.CtKeyEVENTMASK, le(CtEventBitNew), "new"},
		{"eventmask multi", expr.CtKeyEVENTMASK, le(CtEventBitNew | CtEventBitDestroy), "{new, destroy}"},
		{"expiration", expr.CtKeyEXPIRATION, beU32(90), "1m30s"},
		{"helper string", expr.CtKeyHELPER, []byte("ftp\x00"), "ftp"},
		{"protocol", expr.CtKeyPROTOCOL, []byte{6}, "tcp"},
		{"l3proto", expr.CtKeyL3PROTOCOL, []byte{2}, "ipv4"},
		{"src ip", expr.CtKeySRC, []byte{10, 0, 0, 1}, "10.0.0.1"},
		{"zone uint", expr.CtKeyZONE, []byte{0x04, 0x00}, "4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatCtValue(tt.key, tt.data); got != tt.want {
				t.Errorf("formatCtValue(%v, %v) = %q, want %q", tt.key, tt.data, got, tt.want)
			}
		})
	}
}
