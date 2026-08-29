package nftexpr

import (
	"fmt"
	"strings"

	"github.com/google/nftables/expr"
)

func FormatPayload(payload *expr.Payload) string {
	// payload{ offset X, len Y } load @ l3proto => reg 1 etc.
	parts := []string{"payload"}
	if payload.Base != 0 {
		parts = append(parts, fmt.Sprintf("base %d", payload.Base))
	}
	switch payload.Base {

	}
	parts = append(parts, fmt.Sprintf("offset %d", payload.Offset))
	parts = append(parts, fmt.Sprintf("len %d", payload.Len))
	if payload.DestRegister != 0 {
		parts = append(parts, fmt.Sprintf("=> reg %d", payload.DestRegister))
	}
	return strings.Join(parts, " ")
}

// SerializePayload renders a payload load (plus the Cmp that follows it, when
// there is one). l4proto is the protocol keyword latched from the rule's
// `meta l4proto` match, or "" when the rule carries none; it names the
// transport cells that offset+len alone cannot identify.
func SerializePayload(p *expr.Payload, exprs []expr.Any, pos int, l4proto string) (string, int) {
	var payloadStr string

	switch p.Base {
	case expr.PayloadBaseNetworkHeader:
		payloadStr = serializeNetworkPayload(p)
	case expr.PayloadBaseTransportHeader:
		payloadStr = serializeTransportPayload(p, l4proto)
	case expr.PayloadBaseLLHeader:
		payloadStr = serializeLinkPayload(p)
	default:
		payloadStr = fmt.Sprintf("@%s,%d,%d", payloadBaseName(p.Base), p.Offset, p.Len)
	}

	// If the next expression is a comparison, serialize it as well
	if pos+1 < len(exprs) {
		if cmp, ok := exprs[pos+1].(*expr.Cmp); ok {
			data := ""
			op := CmpOpToString(cmp.Op)

			value := DataToHumanReadable(cmp.Data, payloadStr)
			if op == "==" {
				data = value
			} else {
				data = fmt.Sprintf("%s %s", op, value)
			}
			return fmt.Sprintf("%s %s", payloadStr, data), 2
		}
	}

	return payloadStr, 1
}

func serializeNetworkPayload(p *expr.Payload) string {
	// IP header fields (based on offset)
	switch p.Offset {
	case 9: // Protocol
		if p.Len == 1 {
			return "ip protocol"
		}
	case 12: // Source address
		if p.Len == 4 {
			return "ip saddr"
		}
	case 16: // Destination address
		if p.Len == 4 {
			return "ip daddr"
		}
	case 0: // Version + IHL
		if p.Len == 1 {
			return "ip version"
		}
	case 2: // Total length
		if p.Len == 2 {
			return "ip length"
		}
	case 8: // TTL
		if p.Len == 1 {
			return "ip ttl"
		}
	}

	// IPv6
	if p.Offset == 8 && p.Len == 16 {
		return "ip6 saddr"
	}
	if p.Offset == 24 && p.Len == 16 {
		return "ip6 daddr"
	}

	return fmt.Sprintf("@nh,%d,%d", p.Offset*8, p.Len*8)
}

// serializeTransportPayload names a transport-header cell. Most cells follow
// from offset+len alone, but two need the protocol: transport offset 4 is
// `udp length` in UDP and `udplite csumcov` (the checksum coverage) in
// UDP-Lite — different fields sharing one cell, and `udplite length` is not
// even valid syntax. l4proto carries that context; without it those cells
// keep the raw @th form rather than guess at a name.
func serializeTransportPayload(p *expr.Payload, l4proto string) string {
	// TCP/UDP header fields
	switch p.Offset {
	case 0: // Source port
		if p.Len == 1 {
			return "icmp type"
		} else if p.Len == 2 {
			return "sport"
		}
	case 2: // Destination port
		if p.Len == 2 {
			return "dport"
		}
	case 4: // UDP length / UDP-Lite checksum coverage
		// Field name only: the protocol keyword is already emitted by the
		// `meta l4proto` part, so returning "udp length" here would render
		// `udp udp length 64`.
		if p.Len == 2 {
			switch l4proto {
			case "udp":
				return "length"
			case "udplite":
				return "csumcov"
			}
		}
	case 6: // UDP / UDP-Lite checksum
		// TCP's sequence number spans bytes 4..8, so a standalone 2-byte
		// match here only ever belongs to UDP or UDP-Lite.
		if p.Len == 2 && (l4proto == "udp" || l4proto == "udplite") {
			return "checksum"
		}
	case 13: // TCP flags
		if p.Len == 1 {
			return "tcp flags"
		}
	}

	return fmt.Sprintf("@th,%d,%d", p.Offset*8, p.Len*8)
}

func serializeLinkPayload(p *expr.Payload) string {
	// Ethernet header
	switch p.Offset {
	case 0: // Destination MAC
		if p.Len == 6 {
			return "ether daddr"
		}
	case 6: // Source MAC
		if p.Len == 6 {
			return "ether saddr"
		}
	case 12: // EtherType
		if p.Len == 2 {
			return "ether type"
		}
	}

	return fmt.Sprintf("@ll,%d,%d", p.Offset*8, p.Len*8)
}

func payloadBaseName(base expr.PayloadBase) string {
	switch base {
	case expr.PayloadBaseNetworkHeader:
		return "nh"
	case expr.PayloadBaseTransportHeader:
		return "th"
	case expr.PayloadBaseLLHeader:
		return "ll"
	default:
		return "unknown"
	}
}
