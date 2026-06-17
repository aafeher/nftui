package nft

// Direct tests for payloadCompareToCondition's bit-packed field refinements.
// These arms key off a Bitwise mask shape (version / hdrlength / dscp /
// flowlabel / doff / vlan id-cfi-pcp / dccp type) and the CIDR / prefix
// address forms. Calling the function head-on with a crafted registerValue
// pins each branch without assembling a full rule. Pure and netlink-free.

import (
	"testing"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestPayloadCompareToCondition_BitPacked(t *testing.T) {
	tests := []struct {
		name      string
		regVal    *registerValue
		data      []byte
		wantProto PayloadProtocol
		wantField string
	}{
		{
			name: "ipv4 version",
			regVal: &registerValue{
				valueType: regTypePayload, payloadBase: unix.NFT_PAYLOAD_NETWORK_HEADER,
				payloadOff: 0, payloadLen: 1, payloadFamily: payloadFamilyIPv4,
				hasBitwise: true, bitwiseMask: []byte{0xf0},
			},
			data: []byte{0x45}, wantProto: PayloadProtoIP, wantField: "version",
		},
		{
			name: "ipv4 hdrlength",
			regVal: &registerValue{
				valueType: regTypePayload, payloadBase: unix.NFT_PAYLOAD_NETWORK_HEADER,
				payloadOff: 0, payloadLen: 1, payloadFamily: payloadFamilyIPv4,
				hasBitwise: true, bitwiseMask: []byte{0x0f},
			},
			data: []byte{0x45}, wantProto: PayloadProtoIP, wantField: "hdrlength",
		},
		{
			name: "ipv4 dscp",
			regVal: &registerValue{
				valueType: regTypePayload, payloadBase: unix.NFT_PAYLOAD_NETWORK_HEADER,
				payloadOff: 1, payloadLen: 1, payloadFamily: payloadFamilyIPv4,
				hasBitwise: true, bitwiseMask: []byte{0xfc},
			},
			data: []byte{0x10}, wantProto: PayloadProtoIP, wantField: "dscp",
		},
		{
			name: "ipv6 dscp by mask shape",
			regVal: &registerValue{
				valueType: regTypePayload, payloadBase: unix.NFT_PAYLOAD_NETWORK_HEADER,
				payloadOff: 0, payloadLen: 2, payloadFamily: payloadFamilyIPv6,
				hasBitwise: true, bitwiseMask: []byte{0x0f, 0xc0},
			},
			data: []byte{0x0a, 0x80}, wantProto: PayloadProtoIP6, wantField: "dscp",
		},
		{
			name: "ipv6 flowlabel by mask shape",
			regVal: &registerValue{
				valueType: regTypePayload, payloadBase: unix.NFT_PAYLOAD_NETWORK_HEADER,
				payloadOff: 1, payloadLen: 3, payloadFamily: payloadFamilyIPv6,
				hasBitwise: true, bitwiseMask: []byte{0x0f, 0xff, 0xff},
			},
			data: []byte{0x01, 0x23, 0x45}, wantProto: PayloadProtoIP6, wantField: "flowlabel",
		},
		{
			name: "tcp doff",
			regVal: &registerValue{
				valueType: regTypePayload, payloadBase: unix.NFT_PAYLOAD_TRANSPORT_HEADER,
				payloadOff: 12, payloadLen: 1, l4Proto: unix.IPPROTO_TCP,
				hasBitwise: true, bitwiseMask: []byte{0xf0},
			},
			data: []byte{0x50}, wantProto: PayloadProtoTCP, wantField: "doff",
		},
		{
			name: "vlan id",
			regVal: &registerValue{
				valueType: regTypePayload, payloadBase: unix.NFT_PAYLOAD_LL_HEADER,
				payloadOff: 14, payloadLen: 2,
				hasBitwise: true, bitwiseMask: []byte{0x0f, 0xff},
			},
			data: []byte{0x00, 0x64}, wantProto: PayloadProtoVlan, wantField: "id",
		},
		{
			name: "vlan cfi",
			regVal: &registerValue{
				valueType: regTypePayload, payloadBase: unix.NFT_PAYLOAD_LL_HEADER,
				payloadOff: 14, payloadLen: 1,
				hasBitwise: true, bitwiseMask: []byte{0x10},
			},
			data: []byte{0x10}, wantProto: PayloadProtoVlan, wantField: "cfi",
		},
		{
			name: "vlan pcp",
			regVal: &registerValue{
				valueType: regTypePayload, payloadBase: unix.NFT_PAYLOAD_LL_HEADER,
				payloadOff: 14, payloadLen: 1,
				hasBitwise: true, bitwiseMask: []byte{0xe0},
			},
			data: []byte{0xa0}, wantProto: PayloadProtoVlan, wantField: "pcp",
		},
		{
			name: "dccp type",
			regVal: &registerValue{
				valueType: regTypePayload, payloadBase: unix.NFT_PAYLOAD_TRANSPORT_HEADER,
				payloadOff: 8, payloadLen: 1, l4Proto: unix.IPPROTO_DCCP,
				hasBitwise: true, bitwiseMask: []byte{0x1e},
			},
			data: []byte{0x04}, wantProto: PayloadProtoDCCP, wantField: "type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmp := &compareContext{op: expr.CmpOpEq, data: tt.data, register: tt.regVal}
			cond, err := payloadCompareToCondition(tt.regVal, cmp)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cond.Payload == nil {
				t.Fatalf("Payload condition is nil")
			}
			if cond.Payload.Protocol != tt.wantProto {
				t.Errorf("proto = %q, want %q", cond.Payload.Protocol, tt.wantProto)
			}
			if cond.Payload.Field != tt.wantField {
				t.Errorf("field = %q, want %q", cond.Payload.Field, tt.wantField)
			}
		})
	}
}

func TestPayloadCompareToCondition_AddressForms(t *testing.T) {
	// CIDR match: Bitwise mask same width as the compared data.
	cidr := &registerValue{
		valueType: regTypePayload, payloadBase: unix.NFT_PAYLOAD_NETWORK_HEADER,
		payloadOff: 12, payloadLen: 4, payloadFamily: payloadFamilyIPv4,
		hasBitwise: true, bitwiseMask: []byte{255, 255, 255, 0},
	}
	cond, err := payloadCompareToCondition(cidr, &compareContext{op: expr.CmpOpEq, data: []byte{10, 0, 0, 0}, register: cidr})
	if err != nil {
		t.Fatal(err)
	}
	if cond.Payload.Field != "saddr" {
		t.Errorf("cidr field = %q, want saddr", cond.Payload.Field)
	}
	if _, ok := cond.Payload.Value.(*IPAddress); !ok {
		t.Errorf("cidr value type = %T, want *IPAddress", cond.Payload.Value)
	}

	// Byte-aligned prefix: no Bitwise, payloadLen 1-3.
	prefix := &registerValue{
		valueType: regTypePayload, payloadBase: unix.NFT_PAYLOAD_NETWORK_HEADER,
		payloadOff: 12, payloadLen: 3, payloadFamily: payloadFamilyIPv4,
	}
	cond, err = payloadCompareToCondition(prefix, &compareContext{op: expr.CmpOpEq, data: []byte{192, 168, 1}, register: prefix})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cond.Payload.Value.(*IPAddress); !ok {
		t.Errorf("prefix value type = %T, want *IPAddress", cond.Payload.Value)
	}

	// Plain value: full 4-byte address falls through to decodePayloadValue.
	plain := &registerValue{
		valueType: regTypePayload, payloadBase: unix.NFT_PAYLOAD_NETWORK_HEADER,
		payloadOff: 16, payloadLen: 4, payloadFamily: payloadFamilyIPv4,
	}
	cond, err = payloadCompareToCondition(plain, &compareContext{op: expr.CmpOpEq, data: []byte{8, 8, 8, 8}, register: plain})
	if err != nil {
		t.Fatal(err)
	}
	if cond.Payload.Field != "daddr" {
		t.Errorf("plain field = %q, want daddr", cond.Payload.Field)
	}
}

func TestDecodePayloadValue(t *testing.T) {
	// Ethernet MAC + ethertype are dispatched before the generic field switch.
	if got := decodePayloadValue(PayloadProtoEther, "saddr", []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}); got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("ether saddr = %v, want MAC string", got)
	}
	if got := decodePayloadValue(PayloadProtoEther, "type", []byte{0x08, 0x00}); got != uint16(0x0800) {
		t.Errorf("ether type = %v, want uint16(0x0800)", got)
	}

	// IPv4 / IPv6 addresses.
	if _, ok := decodePayloadValue(PayloadProtoIP, "saddr", []byte{10, 0, 0, 1}).(*IPAddress); !ok {
		t.Error("ipv4 saddr did not decode to *IPAddress")
	}
	if _, ok := decodePayloadValue(PayloadProtoIP6, "daddr", make([]byte, 16)).(*IPAddress); !ok {
		t.Error("ipv6 daddr did not decode to *IPAddress")
	}

	// Ports.
	if ps, ok := decodePayloadValue(PayloadProtoTCP, "dport", []byte{0x01, 0xbb}).(*PortSpec); !ok || ps.Port != 443 {
		t.Errorf("dport = %v, want PortSpec{443}", decodePayloadValue(PayloadProtoTCP, "dport", []byte{0x01, 0xbb}))
	}

	// uint8 group.
	if got := decodePayloadValue(PayloadProtoIP, "ttl", []byte{64}); got != byte(64) {
		t.Errorf("ttl = %v, want byte(64)", got)
	}

	// uint16 / uint32 group (length is 2-or-4 wide).
	if got := decodePayloadValue(PayloadProtoIP, "length", []byte{0x05, 0xdc}); got != uint16(1500) {
		t.Errorf("length(2) = %v, want uint16(1500)", got)
	}
	if got := decodePayloadValue(PayloadProtoSCTP, "checksum", []byte{0, 0, 0, 9}); got != uint32(9) {
		t.Errorf("checksum(4) = %v, want uint32(9)", got)
	}

	// sequence group: uint16 (ICMP) and uint32 (TCP).
	if got := decodePayloadValue(PayloadProtoICMP, "sequence", []byte{0x00, 0x05}); got != uint16(5) {
		t.Errorf("icmp sequence = %v, want uint16(5)", got)
	}
	if got := decodePayloadValue(PayloadProtoTCP, "sequence", []byte{0, 0, 0, 7}); got != uint32(7) {
		t.Errorf("tcp sequence = %v, want uint32(7)", got)
	}

	// reserved (uint16).
	if got := decodePayloadValue(PayloadProtoAH, "reserved", []byte{0x00, 0x01}); got != uint16(1) {
		t.Errorf("reserved = %v, want uint16(1)", got)
	}

	// Unknown field falls through to the raw byte slice.
	raw := []byte{1, 2, 3, 4, 5}
	if got, ok := decodePayloadValue(PayloadProtoTCP, "mystery", raw).([]byte); !ok || len(got) != 5 {
		t.Errorf("unknown field = %v, want raw slice", got)
	}
}
