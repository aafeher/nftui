package nftexpr

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/google/nftables/expr"
)

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

			if m.Key == expr.MetaKeyL4PROTO && data == "icmpv6" {
				return fmt.Sprintf("%s", data), 2, data
			} else if m.Key == expr.MetaKeyL4PROTO && data == "tcp" {
				return fmt.Sprintf("%s", data), 2, data
			} else if m.Key == expr.MetaKeyL4PROTO && data == "udp" {
				return fmt.Sprintf("%s", data), 2, data
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

func serializeCmpOp(cmp *expr.Cmp, value string) string {
	op := CmpOpToString(cmp.Op)

	//value := formatData(cmp.Data)
	//fmt.Printf("serializeCmpOp: %s %s\n", op, value)
	if op == "==" {
		return value
	}
	return fmt.Sprintf("%s %s", op, value)
}

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

func formatData(data []byte) string {
	if len(data) == 0 {
		return "0x"
	}

	// CT Direction vagy más 1 bájtos nulla érték kezelése
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

// InterfaceIndexToName konvertálja az interface indexet (byte tömbként) interface névre.
// A byte tömb little-endian formátumban tartalmazza a 32 bites interface indexet.
// Forrás: https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation
// Az iif (interface index) egy 32 bit integer, ami gyorsabb mint az iifname string összehasonlítás.
func InterfaceIndexToName(data []byte) string {
	if len(data) != 4 {
		return ""
	}

	// Little-endian konverzió: a legkisebb byte az első
	ifIndex := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24

	// Speciális esetek
	if ifIndex == 0 {
		return "any"
	}

	// Interface név lekérése a rendszerről
	iface, err := net.InterfaceByIndex(int(ifIndex))
	if err != nil {
		// Ha nem található az interface, akkor az index számot adjuk vissza
		return fmt.Sprintf("%d", ifIndex)
	}

	return iface.Name
}

func DataToHumanReadable(data []byte, context string) string {
	//fmt.Printf("\nDataToHumanReadable: %s, %s\n", data, context)
	if len(data) == 0 {
		return "0"
	}

	// Egyetlen byte - protokoll szám vagy port
	if len(data) == 1 {
		val := data[0]

		// Ha protokoll, akkor írjuk ki emberien
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
			default:
				return fmt.Sprintf("%d", val)
			}
		}

		// ICMP típusok
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

	// 2 byte - port szám
	if len(data) == 2 && (strings.Contains(context, "port") || strings.Contains(context, "sport") || strings.Contains(context, "dport")) {
		port := uint16(data[0])<<8 | uint16(data[1])

		return fmt.Sprintf("%d", port)
	}

	// 4 byte - IP cím
	if len(data) == 4 && (strings.Contains(context, "addr") || strings.Contains(context, "saddr") || strings.Contains(context, "daddr")) {
		return fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3])
	}

	// Interfész név (nullával végződő string)
	if strings.Contains(context, "ifname") {
		// Találjuk meg a null terminátort
		end := len(data)
		for i, b := range data {
			if b == 0 {
				end = i
				break
			}
		}
		return fmt.Sprintf("\"%s\"", string(data[:end]))
	}

	// Egyébként hex formátumban
	return fmt.Sprintf("0x%x", data)
}
