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
		{"ip version", expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 0, Len: 1}, "ip version"},
		{"ip length", expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 2, Len: 2}, "ip length"},
		{"ip ttl", expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 1}, "ip ttl"},
		{"ip6 saddr", expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16}, "ip6 saddr"},
		{"ip6 daddr", expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16}, "ip6 daddr"},
		{"unknown offset", expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 99, Len: 2}, "@nh,792,16"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := serializeNetworkPayload(&tt.payload)
			if got != tt.want {
				t.Errorf("serializeNetworkPayload() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSerializeTransportPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload expr.Payload
		want    string
	}{
		{"icmp type", expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1}, "icmp type"},
		{"sport", expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2}, "sport"},
		{"dport", expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}, "dport"},
		{"tcp flags", expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1}, "tcp flags"},
		{"unknown", expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 99, Len: 4}, "@th,792,32"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := serializeTransportPayload(&tt.payload)
			if got != tt.want {
				t.Errorf("serializeTransportPayload() = %q, want %q", got, tt.want)
			}
		})
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
			got := serializeLinkPayload(&tt.payload)
			if got != tt.want {
				t.Errorf("serializeLinkPayload() = %q, want %q", got, tt.want)
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
