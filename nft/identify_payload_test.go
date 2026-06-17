package nft

// Exhaustive table for identifyPayloadField: one row per header-field cell
// it recognizes, across every payload base and l4proto dispatch. Pure and
// netlink-free — it just maps (base, offset, length, family, l4proto,
// ethertype) to a (protocol, field) label.

import (
	"testing"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestIdentifyPayloadField_AllCells(t *testing.T) {
	const (
		net  = unix.NFT_PAYLOAD_NETWORK_HEADER
		tran = unix.NFT_PAYLOAD_TRANSPORT_HEADER
		ll   = unix.NFT_PAYLOAD_LL_HEADER
	)

	tests := []struct {
		name        string
		base        expr.PayloadBase
		off, length uint32
		family      payloadFamilyHint
		l4          uint8
		ether       uint16
		proto       PayloadProtocol
		field       string
	}{
		// --- ARP (network header under ether type 0x0806) ---
		{"arp htype", net, 0, 2, payloadFamilyAny, 0, 0x0806, PayloadProtoARP, "htype"},
		{"arp ptype", net, 2, 2, payloadFamilyAny, 0, 0x0806, PayloadProtoARP, "ptype"},
		{"arp hlen", net, 4, 1, payloadFamilyAny, 0, 0x0806, PayloadProtoARP, "hlen"},
		{"arp plen", net, 5, 1, payloadFamilyAny, 0, 0x0806, PayloadProtoARP, "plen"},
		{"arp operation", net, 6, 2, payloadFamilyAny, 0, 0x0806, PayloadProtoARP, "operation"},

		// --- IPv6 unmistakable cells (any family) ---
		{"ip6 saddr", net, 8, 16, payloadFamilyAny, 0, 0, PayloadProtoIP6, "saddr"},
		{"ip6 daddr", net, 24, 16, payloadFamilyAny, 0, 0, PayloadProtoIP6, "daddr"},
		{"ip6 nexthdr", net, 6, 1, payloadFamilyAny, 0, 0, PayloadProtoIP6, "nexthdr"},
		{"ip6 hoplimit", net, 7, 1, payloadFamilyAny, 0, 0, PayloadProtoIP6, "hoplimit"},
		// offset 4 len 2 is ambiguous: IPv6 payload length only with the hint.
		{"ip6 length (hint)", net, 4, 2, payloadFamilyIPv6, 0, 0, PayloadProtoIP6, "length"},

		// --- IPv4 fixed header ---
		{"ip version_ihl", net, 0, 1, payloadFamilyIPv4, 0, 0, PayloadProtoIP, "version_ihl"},
		{"ip dscp_ecn", net, 1, 1, payloadFamilyIPv4, 0, 0, PayloadProtoIP, "dscp_ecn"},
		{"ip length", net, 2, 2, payloadFamilyIPv4, 0, 0, PayloadProtoIP, "length"},
		{"ip id", net, 4, 2, payloadFamilyAny, 0, 0, PayloadProtoIP, "id"},
		{"ip frag-off", net, 6, 2, payloadFamilyIPv4, 0, 0, PayloadProtoIP, "frag-off"},
		{"ip ttl", net, 8, 1, payloadFamilyIPv4, 0, 0, PayloadProtoIP, "ttl"},
		{"ip protocol", net, 9, 1, payloadFamilyIPv4, 0, 0, PayloadProtoIP, "protocol"},
		{"ip checksum", net, 10, 2, payloadFamilyIPv4, 0, 0, PayloadProtoIP, "checksum"},
		{"ip saddr", net, 12, 4, payloadFamilyIPv4, 0, 0, PayloadProtoIP, "saddr"},
		{"ip saddr /24", net, 12, 3, payloadFamilyIPv4, 0, 0, PayloadProtoIP, "saddr"},
		{"ip daddr", net, 16, 4, payloadFamilyIPv4, 0, 0, PayloadProtoIP, "daddr"},
		{"ip network fallback", net, 100, 7, payloadFamilyIPv4, 0, 0, PayloadProtoIP, "offset_100_len_7"},

		// --- ICMP ---
		{"icmp type", tran, 0, 1, payloadFamilyAny, unix.IPPROTO_ICMP, 0, PayloadProtoICMP, "type"},
		{"icmp code", tran, 1, 1, payloadFamilyAny, unix.IPPROTO_ICMP, 0, PayloadProtoICMP, "code"},
		{"icmp checksum", tran, 2, 2, payloadFamilyAny, unix.IPPROTO_ICMP, 0, PayloadProtoICMP, "checksum"},
		{"icmp id", tran, 4, 2, payloadFamilyAny, unix.IPPROTO_ICMP, 0, PayloadProtoICMP, "id"},
		{"icmp sequence", tran, 6, 2, payloadFamilyAny, unix.IPPROTO_ICMP, 0, PayloadProtoICMP, "sequence"},
		{"icmp gateway", tran, 4, 4, payloadFamilyAny, unix.IPPROTO_ICMP, 0, PayloadProtoICMP, "gateway"},

		// --- ICMPv6 ---
		{"icmp6 type", tran, 0, 1, payloadFamilyAny, unix.IPPROTO_ICMPV6, 0, PayloadProtoICMPv6, "type"},
		{"icmp6 code", tran, 1, 1, payloadFamilyAny, unix.IPPROTO_ICMPV6, 0, PayloadProtoICMPv6, "code"},
		{"icmp6 checksum", tran, 2, 2, payloadFamilyAny, unix.IPPROTO_ICMPV6, 0, PayloadProtoICMPv6, "checksum"},
		{"icmp6 id", tran, 4, 2, payloadFamilyAny, unix.IPPROTO_ICMPV6, 0, PayloadProtoICMPv6, "id"},
		{"icmp6 sequence", tran, 6, 2, payloadFamilyAny, unix.IPPROTO_ICMPV6, 0, PayloadProtoICMPv6, "sequence"},
		{"icmp6 mtu", tran, 4, 4, payloadFamilyAny, unix.IPPROTO_ICMPV6, 0, PayloadProtoICMPv6, "mtu"},

		// --- SCTP ---
		{"sctp sport", tran, 0, 2, payloadFamilyAny, unix.IPPROTO_SCTP, 0, PayloadProtoSCTP, "sport"},
		{"sctp dport", tran, 2, 2, payloadFamilyAny, unix.IPPROTO_SCTP, 0, PayloadProtoSCTP, "dport"},
		{"sctp vtag", tran, 4, 4, payloadFamilyAny, unix.IPPROTO_SCTP, 0, PayloadProtoSCTP, "vtag"},
		{"sctp checksum", tran, 8, 4, payloadFamilyAny, unix.IPPROTO_SCTP, 0, PayloadProtoSCTP, "checksum"},

		// --- DCCP ---
		{"dccp sport", tran, 0, 2, payloadFamilyAny, unix.IPPROTO_DCCP, 0, PayloadProtoDCCP, "sport"},
		{"dccp dport", tran, 2, 2, payloadFamilyAny, unix.IPPROTO_DCCP, 0, PayloadProtoDCCP, "dport"},

		// --- AH ---
		{"ah nexthdr", tran, 0, 1, payloadFamilyAny, unix.IPPROTO_AH, 0, PayloadProtoAH, "nexthdr"},
		{"ah hdrlength", tran, 1, 1, payloadFamilyAny, unix.IPPROTO_AH, 0, PayloadProtoAH, "hdrlength"},
		{"ah reserved", tran, 2, 2, payloadFamilyAny, unix.IPPROTO_AH, 0, PayloadProtoAH, "reserved"},
		{"ah spi", tran, 4, 4, payloadFamilyAny, unix.IPPROTO_AH, 0, PayloadProtoAH, "spi"},
		{"ah sequence", tran, 8, 4, payloadFamilyAny, unix.IPPROTO_AH, 0, PayloadProtoAH, "sequence"},

		// --- ESP ---
		{"esp spi", tran, 0, 4, payloadFamilyAny, unix.IPPROTO_ESP, 0, PayloadProtoESP, "spi"},
		{"esp sequence", tran, 4, 4, payloadFamilyAny, unix.IPPROTO_ESP, 0, PayloadProtoESP, "sequence"},

		// --- IPComp ---
		{"comp nexthdr", tran, 0, 1, payloadFamilyAny, unix.IPPROTO_COMP, 0, PayloadProtoCOMP, "nexthdr"},
		{"comp flags", tran, 1, 1, payloadFamilyAny, unix.IPPROTO_COMP, 0, PayloadProtoCOMP, "flags"},
		{"comp cpi", tran, 2, 2, payloadFamilyAny, unix.IPPROTO_COMP, 0, PayloadProtoCOMP, "cpi"},

		// --- TCP / UDP shared + TCP-specific cells (no special l4proto) ---
		{"tcp sport", tran, 0, 2, payloadFamilyAny, unix.IPPROTO_TCP, 0, PayloadProtoTCP, "sport"},
		{"tcp dport", tran, 2, 2, payloadFamilyAny, unix.IPPROTO_TCP, 0, PayloadProtoTCP, "dport"},
		{"udp length", tran, 4, 2, payloadFamilyAny, unix.IPPROTO_TCP, 0, PayloadProtoUDP, "length"},
		{"udp checksum", tran, 6, 2, payloadFamilyAny, unix.IPPROTO_TCP, 0, PayloadProtoUDP, "checksum"},
		{"tcp sequence", tran, 4, 4, payloadFamilyAny, unix.IPPROTO_TCP, 0, PayloadProtoTCP, "sequence"},
		{"tcp ackseq", tran, 8, 4, payloadFamilyAny, unix.IPPROTO_TCP, 0, PayloadProtoTCP, "ackseq"},
		{"tcp doff", tran, 12, 1, payloadFamilyAny, unix.IPPROTO_TCP, 0, PayloadProtoTCP, "doff"},
		{"tcp flags", tran, 13, 1, payloadFamilyAny, unix.IPPROTO_TCP, 0, PayloadProtoTCP, "flags"},
		{"tcp window", tran, 14, 2, payloadFamilyAny, unix.IPPROTO_TCP, 0, PayloadProtoTCP, "window"},
		{"tcp checksum", tran, 16, 2, payloadFamilyAny, unix.IPPROTO_TCP, 0, PayloadProtoTCP, "checksum"},
		{"tcp urgptr", tran, 18, 2, payloadFamilyAny, unix.IPPROTO_TCP, 0, PayloadProtoTCP, "urgptr"},
		{"tcp transport fallback", tran, 40, 9, payloadFamilyAny, unix.IPPROTO_TCP, 0, PayloadProtoTCP, "offset_40_len_9"},

		// --- Link-layer (Ethernet) header ---
		{"ether daddr", ll, 0, 6, payloadFamilyAny, 0, 0, PayloadProtoEther, "daddr"},
		{"ether saddr", ll, 6, 6, payloadFamilyAny, 0, 0, PayloadProtoEther, "saddr"},
		{"ether type", ll, 12, 2, payloadFamilyAny, 0, 0, PayloadProtoEther, "type"},
		{"ether fallback", ll, 20, 4, payloadFamilyAny, 0, 0, PayloadProtoEther, "offset_20_len_4"},

		// --- Unknown base falls through to the generic base_X form ---
		{"unknown base", expr.PayloadBase(0x7f), 1, 2, payloadFamilyAny, 0, 0, PayloadProtoIP, "base_127_offset_1_len_2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proto, field := identifyPayloadField(tt.base, tt.off, tt.length, tt.family, tt.l4, tt.ether)
			if proto != tt.proto {
				t.Errorf("proto = %q, want %q", proto, tt.proto)
			}
			if field != tt.field {
				t.Errorf("field = %q, want %q", field, tt.field)
			}
		})
	}
}
