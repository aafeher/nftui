package nftexpr

// Payload field naming — the single table that maps a payload load
// (base + offset + length, plus whatever protocol context the rule carries)
// to a protocol and field name.
//
// It lives here, in the lower layer, because all three consumers need it and
// nftui/nft imports nftui/nft/expr, never the other way round:
//
//   - nftui/nft's rule parser, which turns it into a PayloadCondition for the
//     rule view and the rule editor;
//   - nftui/nft's one-line renderer for the chain list;
//   - this package's rule serializer, which writes .nft text.
//
// They used to carry three separate tables that knew 67, 11 and 22 field names
// respectively, so the same fact had to be taught three times and usually was
// not: the serializer emitted `tcp @th,112,16` for `tcp window`, which nft
// rejects outright, and the chain list showed `payload[transport header+14:2]`
// for a rule the detail view labelled correctly. One table, three formatters.

import (
	"fmt"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// PayloadProtocol represents a specific protocol type used within payload data for networking and filtering operations.
type PayloadProtocol string

// PayloadProtoEther represents the payload protocol for Ethernet.
// PayloadProtoIP represents the payload protocol for IPv4.
// PayloadProtoIP6 represents the payload protocol for IPv6.
// PayloadProtoTCP represents the payload protocol for TCP.
// PayloadProtoUDP represents the payload protocol for UDP.
// PayloadProtoUDPLITE represents the payload protocol for UDP-Lite. It is only
// used for the fields where UDP-Lite genuinely differs from UDP (csumcov); the
// cells the two share keep their UDP/TCP labels.
// PayloadProtoICMP represents the payload protocol for ICMP.
// PayloadProtoICMPv6 represents the payload protocol for ICMPv6.
// PayloadProtoARP represents the payload protocol for ARP.
const (
	PayloadProtoEther   PayloadProtocol = "ether"
	PayloadProtoIP      PayloadProtocol = "ip"
	PayloadProtoIP6     PayloadProtocol = "ip6"
	PayloadProtoTCP     PayloadProtocol = "tcp"
	PayloadProtoUDP     PayloadProtocol = "udp"
	PayloadProtoUDPLITE PayloadProtocol = "udplite"
	PayloadProtoICMP    PayloadProtocol = "icmp"
	PayloadProtoICMPv6  PayloadProtocol = "icmpv6"
	PayloadProtoSCTP    PayloadProtocol = "sctp"
	PayloadProtoDCCP    PayloadProtocol = "dccp"
	PayloadProtoAH      PayloadProtocol = "ah"
	PayloadProtoESP     PayloadProtocol = "esp"
	PayloadProtoCOMP    PayloadProtocol = "comp"
	PayloadProtoVlan    PayloadProtocol = "vlan"
	PayloadProtoARP     PayloadProtocol = "arp"
)

// PayloadFamilyHint conveys the chain-family context to IdentifyPayloadField
// so it can resolve the offset/length conflict between IPv4 and IPv6 header
// fields (e.g. offset 4 len 2 = IPv4 id OR IPv6 payload length).
type PayloadFamilyHint int

const (
	PayloadFamilyAny  PayloadFamilyHint = iota // ambiguous — pick IPv4 by default
	PayloadFamilyIPv4                          // hint: this rule lives in an IPv4 (or inet w/ IPv4 ctx) chain
	PayloadFamilyIPv6                          // hint: this rule lives in an IPv6 (or inet w/ IPv6 ctx) chain
)

// IdentifyPayloadField determines the protocol and field name based on payload base, offset, and length values.
//
// IPv4 fixed-header layout (when length matches the byte-aligned size of a
// header field, we name it directly; otherwise we fall through to the generic
// "offset_X_len_Y" form so the user still sees the condition):
//
//	offset 0 len 1  → byte holding version (high nibble) + hdrlength (low)
//	offset 1 len 1  → DSCP (bits 7..2) + ECN (bits 1..0)
//	offset 2 len 2  → total length (uint16 BE)
//	offset 4 len 2  → id (uint16 BE)
//	offset 6 len 2  → flags + fragment offset
//	offset 8 len 1  → TTL
//	offset 9 len 1  → protocol
//	offset 10 len 2 → checksum
//	offset 12 len 4 → saddr (with /24 etc. byte-aligned shorts: len 1..4)
//	offset 16 len 4 → daddr
//
// IPv6 fixed-header layout:
//
//	offset 0..3       → version + traffic class + flow label (bit-packed)
//	offset 4 len 2    → payload length
//	offset 6 len 1    → next header
//	offset 7 len 1    → hop limit
//	offset 8 len 16   → saddr
//	offset 24 len 16  → daddr
//
// The TUI uses the same Base (PayloadBaseNetworkHeader) for IPv4 and IPv6 —
// the protocol family is determined by the chain/table family, not by the
// raw expression. Here we disambiguate on offset+length boundaries that are
// unambiguous between the two layouts.
func IdentifyPayloadField(base expr.PayloadBase, offset, length uint32, family PayloadFamilyHint, l4Proto uint8, etherType uint16) (PayloadProtocol, string) {
	switch base {
	case unix.NFT_PAYLOAD_NETWORK_HEADER:
		// ARP — NETWORK_HEADER reading layered under `ether type 0x0806`.
		// RFC 826: htype 0..2, ptype 2..4, hlen 4..5, plen 5..6,
		// operation 6..8.
		if etherType == 0x0806 {
			switch {
			case offset == 0 && length == 2:
				return PayloadProtoARP, "htype"
			case offset == 2 && length == 2:
				return PayloadProtoARP, "ptype"
			case offset == 4 && length == 1:
				return PayloadProtoARP, "hlen"
			case offset == 5 && length == 1:
				return PayloadProtoARP, "plen"
			case offset == 6 && length == 2:
				return PayloadProtoARP, "operation"
			}
		}
		// Unmistakably-IPv6 offsets (saddr/daddr, ip6 nexthdr/hoplimit).
		//
		// Byte-aligned prefix matches load fewer than 16 bytes, so the length
		// ranges are open: offset 24 is past the whole IPv4 header, so any
		// length there is v6, while at offset 8 only length > 4 rules out the
		// IPv4 fields that live there (ttl is offset 8 length 1). Shorter v6
		// prefixes at offset 8 stay unnamed rather than be mislabelled.
		switch {
		case offset == 8 && length >= 5 && length <= 16:
			return PayloadProtoIP6, "saddr"
		case offset == 24 && length >= 1 && length <= 16:
			return PayloadProtoIP6, "daddr"
		case offset == 6 && length == 1:
			return PayloadProtoIP6, "nexthdr"
		case offset == 7 && length == 1:
			return PayloadProtoIP6, "hoplimit"
		}
		// Ambiguous IPv4/IPv6 cells — only pick IPv6 when the rule's family
		// hint says so. Otherwise fall through to the IPv4 layout.
		if family == PayloadFamilyIPv6 {
			switch {
			case offset == 4 && length == 2:
				return PayloadProtoIP6, "length"
			}
		}
		// IPv4 layout.
		switch {
		case offset == 0 && length == 1:
			return PayloadProtoIP, "version_ihl"
		case offset == 1 && length == 1:
			return PayloadProtoIP, "dscp_ecn"
		case offset == 2 && length == 2:
			return PayloadProtoIP, "length"
		case offset == 4 && length == 2:
			return PayloadProtoIP, "id"
		case offset == 6 && length == 2:
			return PayloadProtoIP, "frag-off"
		case offset == 8 && length == 1:
			return PayloadProtoIP, "ttl"
		case offset == 9 && length == 1:
			return PayloadProtoIP, "protocol"
		case offset == 10 && length == 2:
			return PayloadProtoIP, "checksum"
		case offset == 12 && length >= 1 && length <= 4:
			return PayloadProtoIP, "saddr"
		case offset == 16 && length >= 1 && length <= 4:
			return PayloadProtoIP, "daddr"
		}
		return PayloadProtoIP, syntheticFieldName(offset, length)

	case unix.NFT_PAYLOAD_TRANSPORT_HEADER:
		// Protocol-specific layouts first. We dispatch on the l4Proto hint
		// (populated from the most recent `meta l4proto X` match) so the
		// same offset cells can mean different things across protocols.
		switch l4Proto {
		case unix.IPPROTO_ICMP:
			switch {
			case offset == 0 && length == 1:
				return PayloadProtoICMP, "type"
			case offset == 1 && length == 1:
				return PayloadProtoICMP, "code"
			case offset == 2 && length == 2:
				return PayloadProtoICMP, "checksum"
			case offset == 4 && length == 2:
				return PayloadProtoICMP, "id"
			case offset == 6 && length == 2:
				return PayloadProtoICMP, "sequence"
			case offset == 4 && length == 4:
				return PayloadProtoICMP, "gateway" // dest-unreach uses bytes 4..7 as gateway / mtu
			}
		case unix.IPPROTO_ICMPV6:
			// ICMPv6 fixed header layout matches ICMP byte-for-byte; see RFC 4443.
			switch {
			case offset == 0 && length == 1:
				return PayloadProtoICMPv6, "type"
			case offset == 1 && length == 1:
				return PayloadProtoICMPv6, "code"
			case offset == 2 && length == 2:
				return PayloadProtoICMPv6, "checksum"
			case offset == 4 && length == 2:
				return PayloadProtoICMPv6, "id"
			case offset == 6 && length == 2:
				return PayloadProtoICMPv6, "sequence"
			case offset == 4 && length == 4:
				return PayloadProtoICMPv6, "mtu" // packet-too-big uses bytes 4..7 as MTU
			}
		case unix.IPPROTO_SCTP:
			// SCTP fixed header (RFC 4960): sport 0..2, dport 2..4,
			// verification tag 4..8, checksum 8..12.
			switch {
			case offset == 0 && length == 2:
				return PayloadProtoSCTP, "sport"
			case offset == 2 && length == 2:
				return PayloadProtoSCTP, "dport"
			case offset == 4 && length == 4:
				return PayloadProtoSCTP, "vtag"
			case offset == 8 && length == 4:
				return PayloadProtoSCTP, "checksum"
			}
		case unix.IPPROTO_DCCP:
			// DCCP fixed header (RFC 4340): sport 0..2, dport 2..4,
			// type is 4 bits at byte 8 (bits 1..4 → mask 0x1e, shift 1);
			// the type recognizer lives in payloadCompareToCondition's
			// Bitwise dispatch since it needs the mask byte to confirm.
			switch {
			case offset == 0 && length == 2:
				return PayloadProtoDCCP, "sport"
			case offset == 2 && length == 2:
				return PayloadProtoDCCP, "dport"
			}
		case unix.IPPROTO_AH:
			// AH header (RFC 4302): nexthdr 0..1, hdrlength 1..2,
			// reserved 2..4, spi 4..8, sequence 8..12.
			switch {
			case offset == 0 && length == 1:
				return PayloadProtoAH, "nexthdr"
			case offset == 1 && length == 1:
				return PayloadProtoAH, "hdrlength"
			case offset == 2 && length == 2:
				return PayloadProtoAH, "reserved"
			case offset == 4 && length == 4:
				return PayloadProtoAH, "spi"
			case offset == 8 && length == 4:
				return PayloadProtoAH, "sequence"
			}
		case unix.IPPROTO_ESP:
			// ESP header (RFC 4303): spi 0..4, sequence 4..8.
			switch {
			case offset == 0 && length == 4:
				return PayloadProtoESP, "spi"
			case offset == 4 && length == 4:
				return PayloadProtoESP, "sequence"
			}
		case unix.IPPROTO_UDPLITE:
			// UDP-Lite (RFC 3828) reuses the UDP header layout, except that
			// UDP's `length` cell carries the checksum coverage instead.
			// `nft` names it `csumcov` and rejects `udplite length` outright,
			// so this is a different field, not another spelling of the same
			// one — hence the dedicated arm.
			//
			// Deliberately only offset 4: sport / dport / checksum mean the
			// same thing in both protocols and `nft` accepts either spelling,
			// so they fall through to the shared TCP/UDP labels below. That
			// convention is the one examples/example-nftables-01.conf's
			// section 25 documents ("wire = udp dport", "wire = udp checksum").
			if offset == 4 && length == 2 {
				return PayloadProtoUDPLITE, "csumcov"
			}
		case unix.IPPROTO_COMP:
			// IPComp header (RFC 3173): nexthdr 0..1, flags 1..2, cpi 2..4.
			switch {
			case offset == 0 && length == 1:
				return PayloadProtoCOMP, "nexthdr"
			case offset == 1 && length == 1:
				return PayloadProtoCOMP, "flags"
			case offset == 2 && length == 2:
				return PayloadProtoCOMP, "cpi"
			}
		}

		// A one-byte match at transport offset 0 is an ICMP type: nothing
		// else reads a single byte there (TCP and UDP start with a two-byte
		// source port). Rules carrying a `meta l4proto icmp` match are named
		// by the arm above; this catches the ones that do not.
		if offset == 0 && length == 1 {
			return PayloadProtoICMP, "type"
		}

		// TCP, UDP and UDPLITE share the first 4 bytes (sport, dport).
		// Beyond that the layouts diverge — we can disambiguate on
		// offset+length cells, except for sport/dport which we always tag
		// as TCP by convention (the meta l4proto context tells the user
		// whether it is actually udp/udplite).
		switch {
		case offset == 0 && length == 2:
			return PayloadProtoTCP, "sport"
		case offset == 2 && length == 2:
			return PayloadProtoTCP, "dport"

		// UDP / UDPLITE: length & checksum live in TCP-unused cells.
		case offset == 4 && length == 2:
			return PayloadProtoUDP, "length"
		case offset == 6 && length == 2:
			return PayloadProtoUDP, "checksum"

		// TCP-specific cells.
		case offset == 4 && length == 4:
			return PayloadProtoTCP, "sequence"
		case offset == 8 && length == 4:
			return PayloadProtoTCP, "ackseq"
		case offset == 12 && length == 1:
			return PayloadProtoTCP, "doff" // bit-packed (high 4 bits)
		case offset == 13 && length == 1:
			return PayloadProtoTCP, "flags"
		case offset == 14 && length == 2:
			return PayloadProtoTCP, "window"
		case offset == 16 && length == 2:
			return PayloadProtoTCP, "checksum"
		case offset == 18 && length == 2:
			return PayloadProtoTCP, "urgptr"
		}
		return PayloadProtoTCP, syntheticFieldName(offset, length)

	case unix.NFT_PAYLOAD_LL_HEADER:
		// Ethernet link-layer header: dst-mac 0..6, src-mac 6..12, ethertype 12..14.
		switch {
		case offset == 0 && length == 6:
			return PayloadProtoEther, "daddr"
		case offset == 6 && length == 6:
			return PayloadProtoEther, "saddr"
		case offset == 12 && length == 2:
			return PayloadProtoEther, "type"
		}
		return PayloadProtoEther, syntheticFieldName(offset, length)

	default:
		return PayloadProtoIP, syntheticBaseFieldName(base, offset, length)
	}
}

// syntheticFieldName and syntheticBaseFieldName are the labels
// IdentifyPayloadField falls back to when a cell is not a header field it
// knows. They exist as functions, not inline format strings, so
// NamePayloadField can recognise them exactly rather than sniffing a prefix.
func syntheticFieldName(offset, length uint32) string {
	return fmt.Sprintf("offset_%d_len_%d", offset, length)
}

func syntheticBaseFieldName(base expr.PayloadBase, offset, length uint32) string {
	return fmt.Sprintf("base_%d_offset_%d_len_%d", base, offset, length)
}

// NamePayloadField is IdentifyPayloadField plus an explicit "was this actually
// recognised" answer.
//
// IdentifyPayloadField always returns something — an unknown cell becomes a
// synthetic offset_X_len_Y label — because the rule view would rather show a
// placeholder than nothing. The serializers need the distinction: their
// fallback is the raw @base,offset,len form, which nft parses, whereas a
// synthetic label would be nonsense in a .nft file.
func NamePayloadField(base expr.PayloadBase, offset, length uint32, family PayloadFamilyHint, l4Proto uint8, etherType uint16) (PayloadProtocol, string, bool) {
	proto, field := IdentifyPayloadField(base, offset, length, family, l4Proto, etherType)
	if field == syntheticFieldName(offset, length) || field == syntheticBaseFieldName(base, offset, length) {
		return proto, field, false
	}
	return proto, field, true
}

// L4ProtoNumber maps the protocol keyword the meta serializer emits back to
// its IP protocol number, so a payload can be named from the same context.
// Unknown or absent keywords yield 0, which the field table treats as "no
// protocol context".
func L4ProtoNumber(name string) uint8 {
	switch name {
	case "icmp":
		return unix.IPPROTO_ICMP
	case "tcp":
		return unix.IPPROTO_TCP
	case "udp":
		return unix.IPPROTO_UDP
	case "icmpv6":
		return unix.IPPROTO_ICMPV6
	case "udplite":
		return unix.IPPROTO_UDPLITE
	case "sctp":
		return unix.IPPROTO_SCTP
	case "dccp":
		return unix.IPPROTO_DCCP
	case "ah":
		return unix.IPPROTO_AH
	case "esp":
		return unix.IPPROTO_ESP
	case "comp":
		return unix.IPPROTO_COMP
	}
	return 0
}
