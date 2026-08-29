package nftexpr

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/google/nftables/expr"
)

// MetaKeyToString converts a MetaKey enum value to its corresponding string representation for easy identification.
func MetaKeyToString(metaKey expr.MetaKey) string {
	switch metaKey {
	case expr.MetaKeyLEN:
		return "len"
	case expr.MetaKeyPROTOCOL:
		return "protocol"
	case expr.MetaKeyPRIORITY:
		return "priority"
	case expr.MetaKeyMARK:
		return "mark"
	case expr.MetaKeyIIF:
		return "iif"
	case expr.MetaKeyOIF:
		return "oif"
	case expr.MetaKeyIIFNAME:
		return "iifname"
	case expr.MetaKeyOIFNAME:
		return "oifname"
	case expr.MetaKeyIIFTYPE:
		return "iiftype"
	case expr.MetaKeyOIFTYPE:
		return "oiftype"
	case expr.MetaKeySKUID:
		return "skuid"
	case expr.MetaKeySKGID:
		return "skgid"
	case expr.MetaKeyNFTRACE:
		return "nftrace"
	case expr.MetaKeyRTCLASSID:
		return "rtclassid"
	case expr.MetaKeySECMARK:
		return "secmark"
	case expr.MetaKeyNFPROTO:
		return "nfproto"
	case expr.MetaKeyL4PROTO:
		return "l4proto"
	case expr.MetaKeyBRIIIFNAME:
		return "bri_iifname"
	case expr.MetaKeyBRIOIFNAME:
		return "bri_oifname"
	case expr.MetaKeyPKTTYPE:
		return "pkttype"
	case expr.MetaKeyCPU:
		return "cpu"
	case expr.MetaKeyIIFGROUP:
		return "iifgroup"
	case expr.MetaKeyOIFGROUP:
		return "oifgroup"
	case expr.MetaKeyCGROUP:
		return "cgroup"
	case expr.MetaKeyPRANDOM:
		return "prandom"
	default:
		return "unknown"
	}
}

// SerializeMeta serializes a meta expression with its associated comparison and returns its string representation, step size, and data.
func SerializeMeta(m *expr.Meta, exprs []expr.Any, pos int) (string, int, string) {
	metaStr := MetaKeyToString(m.Key)

	// If next expression is a Cmp, serialize it as well
	if pos+1 < len(exprs) {
		if cmp, ok := exprs[pos+1].(*expr.Cmp); ok {
			data := ""
			op := CmpOpToString(cmp.Op)

			value := ""
			if len(cmp.Data) > 0 {
				if m.Key == expr.MetaKeyIIF {
					value = InterfaceIndexToName(cmp.Data)
				} else if m.Key == expr.MetaKeyL4PROTO {
					value = DataToHumanReadable(cmp.Data, metaStr)
				}
			}
			if op == "==" {
				data = value
			} else {
				data = fmt.Sprintf("%s %s", op, value)
			}

			if m.Key == expr.MetaKeyL4PROTO {
				switch data {
				// nft prints these as a bare protocol keyword — `tcp dport
				// 80`, not `meta l4proto tcp tcp dport 80`. The same string
				// is handed back as the l4proto context so a later Payload
				// can name cells that only the protocol disambiguates
				// (see serializeTransportPayload).
				case "icmpv6", "tcp", "udp", "udplite":
					return data, 2, data
				}
			}
			return fmt.Sprintf("%s %s", metaStr, data), 2, ""
		}
	}

	// Special case for set
	if m.Register == 1 && m.SourceRegister {
		return fmt.Sprintf("%s set", metaStr), 1, ""
	}

	return metaStr, 1, ""
}

// FormatMeta formats a Meta struct into a string representation indicating key, source/destination register, and register value.
func FormatMeta(m *expr.Meta) string {
	parts := []string{}

	// Key MetaKey
	parts = append(parts, fmt.Sprintf("key %s", MetaKeyToString(m.Key)))

	// SourceRegister bool
	if m.SourceRegister {
		parts = append(parts, fmt.Sprintf("sreg"))
	} else {
		parts = append(parts, fmt.Sprintf("dreg"))
	}

	// Register uint32
	parts = append(parts, fmt.Sprintf("%d", m.Register))

	return strings.Join(parts, " ")
}

// SerializeMasq serializes a Masq expression into a string representation based on its configuration flags.
func SerializeMasq(m *expr.Masq) string {
	result := "masquerade"

	if m.Random {
		result += " random"
	}
	if m.FullyRandom {
		result += " fully-random"
	}
	if m.Persistent {
		result += " persistent"
	}

	return result
}

// serializeCmpOp converts a comparison operator and value into its string representation based on the operator's type.
func serializeCmpOp(cmp *expr.Cmp, value string) string {
	op := CmpOpToString(cmp.Op)

	//value := formatData(cmp.Data)
	//fmt.Printf("serializeCmpOp: %s %s\n", op, value)
	if op == "==" {
		return value
	}
	return fmt.Sprintf("%s %s", op, value)
}

// SerializeCmp converts a comparison expression into its string representation using the provided comparison data.
func SerializeCmp(cmp *expr.Cmp, pending any) string {
	value := formatData(cmp.Data)
	return serializeCmpOp(cmp, value)
}

// CmpOpToString converts a comparison operator of type expr.CmpOp to its string representation.
func CmpOpToString(cmpOp expr.CmpOp) string {
	switch cmpOp {
	case expr.CmpOpEq:
		return "=="
	case expr.CmpOpNeq:
		return "!="
	case expr.CmpOpLt:
		return "<"
	case expr.CmpOpLte:
		return "<="
	case expr.CmpOpGt:
		return ">"
	case expr.CmpOpGte:
		return ">="
	default:
		return "unknown"
	}
}

// FormatCmp formats a comparison operation into a readable string by including the register, operator, and data.
func FormatCmp(cmp *expr.Cmp) string {
	fmt.Printf("FormatCmp: %+v", cmp)
	op := CmpOpToString(cmp.Op)

	val := formatData(cmp.Data)
	return fmt.Sprintf("cmp %d %s %s", cmp.Register, op, val)
}

// formatData formats a byte slice into a human-readable representation, handling various cases like IP, port, and strings.
func formatData(data []byte) string {
	if len(data) == 0 {
		return "0x"
	}

	// Handling CT Direction or other 1 byte zero values
	if len(data) == 1 {
		return fmt.Sprintf("%d", data[0])
	}

	// IP
	if l := len(data); l == 4 || l == 16 {
		return net.IP(data).String()
	}

	// Port
	if len(data) == 2 {
		port := binary.BigEndian.Uint16(data)

		return fmt.Sprintf("%d", port)
	}

	// Integer
	if len(data) == 4 {
		val := binary.BigEndian.Uint32(data)
		return fmt.Sprintf("%d", val)
	}

	// String
	if isPrintable(data) {
		return fmt.Sprintf("\"%s\"", strings.TrimRight(string(data), "\x00"))
	}

	// Hex
	return fmt.Sprintf("0x%x", data)
}

// isPrintable checks if all bytes in the given slice are printable ASCII characters or null (0x00). Returns true if so.
func isPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for _, b := range data {
		if b != 0 && (b < 32 || b > 126) {
			return false
		}
	}
	return true
}

// InterfaceIndexToName converts interface index (as byte array) to interface name.
// The byte array contains the 32 bit interface index in little-endian format.
// Source: https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation
// iif (interface index) is a 32 bit integer, which is faster than iifname string comparison.
func InterfaceIndexToName(data []byte) string {
	if len(data) != 4 {
		return ""
	}

	// Little-endian conversion: the smallest byte is first
	ifIndex := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24

	// Special cases
	if ifIndex == 0 {
		return "any"
	}

	// Get interface name from system
	iface, err := net.InterfaceByIndex(int(ifIndex))
	if err != nil {
		// If interface is not found, return the index number
		return fmt.Sprintf("%d", ifIndex)
	}

	return iface.Name
}

// DataToHumanReadable converts raw byte data to a human-readable string based on the provided context.
// It handles different data formats such as protocols, ports, IP addresses, and interface names.
func DataToHumanReadable(data []byte, context string) string {
	//fmt.Printf("\nDataToHumanReadable: %s, %s\n", data, context)
	if len(data) == 0 {
		return "0"
	}

	// Single byte - protocol number or port
	if len(data) == 1 {
		val := data[0]

		// If protocol, write it humanly
		if strings.Contains(context, "protocol") || context == "l4proto" {
			switch val {
			case 1:
				return "icmp"
			case 6:
				return "tcp"
			case 17:
				return "udp"
			case 58:
				return "icmpv6"
			case 136:
				return "udplite"
			default:
				return fmt.Sprintf("%d", val)
			}
		}

		// ICMP types
		if strings.Contains(context, "icmp type") {
			switch val {
			case 0:
				return "echo-reply"
			case 8:
				return "echo-request"
			default:
				return fmt.Sprintf("%d", val)
			}
		}

		//fmt.Printf("val: %+v", val)

		return fmt.Sprintf("%d", val)
	}

	// 2 bytes - port number
	if len(data) == 2 && (strings.Contains(context, "port") || strings.Contains(context, "sport") || strings.Contains(context, "dport")) {
		port := uint16(data[0])<<8 | uint16(data[1])

		return fmt.Sprintf("%d", port)
	}

	// 4 bytes - IP address
	// UDP `length` / UDP-Lite `csumcov` are plain byte counts and nft prints
	// them in decimal. Matched exactly, not with Contains: the network-header
	// context "ip length" also contains "length" and its hex rendering is
	// long-standing behaviour this change has no business altering.
	if len(data) == 2 && (context == "length" || context == "csumcov") {
		return fmt.Sprintf("%d", binary.BigEndian.Uint16(data))
	}

	if len(data) == 4 && (strings.Contains(context, "addr") || strings.Contains(context, "saddr") || strings.Contains(context, "daddr")) {
		return fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3])
	}

	// Interface name (null-terminated string)
	if strings.Contains(context, "ifname") {
		// Find null terminator
		end := len(data)
		for i, b := range data {
			if b == 0 {
				end = i
				break
			}
		}
		return fmt.Sprintf("\"%s\"", string(data[:end]))
	}

	// Otherwise in hex format
	return fmt.Sprintf("0x%x", data)
}
