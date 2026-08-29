package nftexpr

import (
	"testing"

	"github.com/google/nftables/expr"
)

func TestPayloadBaseName(t *testing.T) {
	tests := []struct {
		base expr.PayloadBase
		want string
	}{
		{expr.PayloadBaseNetworkHeader, "nh"},
		{expr.PayloadBaseTransportHeader, "th"},
		{expr.PayloadBaseLLHeader, "ll"},
		{expr.PayloadBase(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := payloadBaseName(tt.base)
			if got != tt.want {
				t.Errorf("payloadBaseName(%d) = %q, want %q", tt.base, got, tt.want)
			}
		})
	}
}

func TestSerializeNetworkPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload expr.Payload
		want    string
	}{
		{"ip protocol", expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1}, "ip protocol"},
		{"ip saddr", expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, "ip saddr"},
		{"ip daddr", expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}, "ip daddr"},
		// The packed version/IHL byte has no nft keyword — nft exposes `ip version`
		// and `ip hdrlength` separately — so the serializer keeps the raw form.
		{"ip version_ihl packed byte", expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 0, Len: 1}, "@nh,0,8"},
		{"ip length", expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 2, Len: 2}, "ip length"},
		{"ip ttl", expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 1}, "ip ttl"},
		{"ip6 saddr", expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16}, "ip6 saddr"},
		{"ip6 daddr", expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16}, "ip6 daddr"},
		{"unknown offset", expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 99, Len: 2}, "@nh,792,16"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, _ := serializePayloadField(&tt.payload, "")
			if got != tt.want {
				t.Errorf("serializePayloadField() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSerializeTransportPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload expr.Payload
		l4proto string
		want    string
	}{
		// A single byte at transport offset 0 is an ICMP type even with no
		// l4proto match: nothing else reads one byte there.
		{"icmp type without context", expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1}, "", "icmp type"},
		{"icmp type", expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1}, "icmp", "type"},
		{"sport unqualified", expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2}, "", "tcp sport"},
		{"sport under udp", expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2}, "udp", "sport"},
		{"dport unqualified", expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}, "", "tcp dport"},
		{"tcp flags", expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1}, "", "tcp flags"},
		{"tcp flags under context", expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1}, "tcp", "flags"},
		{"unknown", expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 99, Len: 4}, "", "@th,792,32"},

		// Offset 4 is the cell UDP and UDP-Lite disagree about: `length` vs
		// the checksum coverage. Only the l4proto context can tell them
		// apart. The field name is returned bare — the protocol keyword is
		// emitted by the `meta l4proto` part, so the rule reads
		// `udplite csumcov 8`, not `udplite udplite csumcov 8`.
		{"udp length", expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 4, Len: 2}, "udp", "length"},
		{"udplite csumcov", expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 4, Len: 2}, "udplite", "csumcov"},
		{"offset 4 without context reads as udp", expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 4, Len: 2}, "", "udp length"},
		// `tcp length` does not exist, so a udp-tagged name must not be written
		// under a tcp keyword — raw form instead.
		{"offset 4 under tcp stays raw", expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 4, Len: 2}, "tcp", "@th,32,16"},

		{"udp checksum", expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 6, Len: 2}, "udp", "checksum"},
		{"udplite checksum", expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 6, Len: 2}, "udplite", "checksum"},
		{"offset 6 without context reads as udp", expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 6, Len: 2}, "", "udp checksum"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, _ := serializePayloadField(&tt.payload, tt.l4proto)
			if got != tt.want {
				t.Errorf("serializePayloadField() = %q, want %q", got, tt.want)
			}
		})
	}
}

// SerializeMeta hands the l4proto context back to the caller so a later
// Payload can be named. UDP-Lite must be recognised by number (136) and
// reported like the protocols already special-cased.
func TestSerializeMeta_UdpliteContext(t *testing.T) {
	exprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{136}},
	}
	str, skip, l4p := SerializeMeta(exprs[0].(*expr.Meta), exprs, 0)
	if l4p != "udplite" {
		t.Errorf("l4proto context = %q, want %q", l4p, "udplite")
	}
	if str != "udplite" {
		t.Errorf("rendered = %q, want the bare protocol keyword %q", str, "udplite")
	}
	if skip != 2 {
		t.Errorf("skip = %d, want 2", skip)
	}
}

func TestSerializeLinkPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload expr.Payload
		want    string
	}{
		{"ether daddr", expr.Payload{Base: expr.PayloadBaseLLHeader, Offset: 0, Len: 6}, "ether daddr"},
		{"ether saddr", expr.Payload{Base: expr.PayloadBaseLLHeader, Offset: 6, Len: 6}, "ether saddr"},
		{"ether type", expr.Payload{Base: expr.PayloadBaseLLHeader, Offset: 12, Len: 2}, "ether type"},
		{"unknown", expr.Payload{Base: expr.PayloadBaseLLHeader, Offset: 20, Len: 4}, "@ll,160,32"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, _ := serializePayloadField(&tt.payload, "")
			if got != tt.want {
				t.Errorf("serializePayloadField() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload expr.Payload
		want    string
	}{
		{
			name:    "transport with dest reg",
			payload: expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
			want:    "payload base 2 offset 2 len 2 => reg 1",
		},
		{
			name:    "network no dest reg",
			payload: expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			want:    "payload base 1 offset 12 len 4",
		},
		{
			name:    "base zero",
			payload: expr.Payload{Base: 0, Offset: 0, Len: 1, DestRegister: 2},
			want:    "payload offset 0 len 1 => reg 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatPayload(&tt.payload)
			if got != tt.want {
				t.Errorf("FormatPayload() = %q, want %q", got, tt.want)
			}
		})
	}
}
