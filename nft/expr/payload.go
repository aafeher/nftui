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
	payloadStr, valueContext, _ := serializePayloadField(p, l4proto)

	// If the next expression is a comparison, serialize it as well
	if pos+1 < len(exprs) {
		if cmp, ok := exprs[pos+1].(*expr.Cmp); ok {
			data := ""
			op := CmpOpToString(cmp.Op)

			value := DataToHumanReadable(cmp.Data, valueContext)
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

// serializePayloadField renders one payload load as nft would name it, using
// the shared field table (payload_fields.go) rather than a private
// offset→name list. l4proto is the protocol keyword the meta serializer
// emitted, or "" when the rule carries none.
//
// It returns three things: the text to write, the *context* the value
// formatter should see, and whether the cell was recognised at all. Text and
// context differ on purpose — a transport cell in a rule that already wrote
// its protocol keyword renders bare (`flags`, not `tcp flags`, which nft
// rejects), but the value formatter still needs the qualified name to know
// that `icmp type 8` should print as `echo-request`.
//
// A cell the table cannot name falls back to the raw @base,off,len form,
// which nft parses as long as no protocol keyword precedes it —
// SerializeMeta's lookahead guarantees that.
func serializePayloadField(p *expr.Payload, l4proto string) (text, context string, ok bool) {
	raw := fmt.Sprintf("@%s,%d,%d", payloadBaseName(p.Base), p.Offset*8, p.Len*8)

	proto, field, named := NamePayloadField(p.Base, p.Offset, p.Len, PayloadFamilyAny, L4ProtoNumber(l4proto), 0)
	if !named || displayOnlyFields[field] {
		return raw, raw, false
	}

	qualified := string(proto) + " " + field
	if l4proto != "" && p.Base == expr.PayloadBaseTransportHeader {
		if !fieldFitsProtocol(proto, field, l4proto) {
			return raw, raw, false
		}
		return field, qualified, true
	}
	return qualified, qualified, true
}

// displayOnlyFields are labels the field table uses for packed bytes that nft
// has no keyword for: it exposes the sub-fields (`ip version`, `ip hdrlength`,
// `ip dscp`) but not the byte that carries them. The rule view is content to
// show the packed name; a .nft file must not, so the serializer writes the raw
// form for these instead.
var displayOnlyFields = map[string]bool{
	"version_ihl": true,
	"dscp_ecn":    true,
}

// fieldFitsProtocol reports whether `<l4proto keyword> <field>` is a pair nft
// accepts. An exact protocol match always is. Beyond that, the table tags a
// cell with the protocol that owns its canonical spelling, so two shared cells
// need an explicit pass:
//
//   - sport / dport are TCP-tagged but spelled identically by every L4
//     protocol the table knows;
//   - the offset-6 checksum is UDP-tagged and shared with UDP-Lite.
//
// Everything else must match, because the shared TCP/UDP fallthrough reads
// transport offset 4 as `udp length` even under a tcp context — and
// `tcp length` does not exist.
func fieldFitsProtocol(proto PayloadProtocol, field, l4proto string) bool {
	if string(proto) == l4proto {
		return true
	}
	switch field {
	case "sport", "dport":
		// The table tags the shared port cells TCP. Every port-bearing L4
		// protocol spells them the same, but AH / ESP / IPComp / ICMP have no
		// ports at all — the generic fallthrough would still offer them, and
		// `ah sport 22` is a syntax error.
		if proto != PayloadProtoTCP {
			return false
		}
		switch l4proto {
		case "tcp", "udp", "udplite", "sctp", "dccp":
			return true
		}
		return false
	case "checksum":
		return proto == PayloadProtoUDP && (l4proto == "udp" || l4proto == "udplite")
	}
	return false
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
