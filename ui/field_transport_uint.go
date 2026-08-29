package ui

import (
	"encoding/binary"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"nftui/nft"
)

// TransportUintField is the generic op+number editor for TCP/UDP/UDPLITE
// header fields whose value is a 2- or 4-byte unsigned integer (sport,
// dport, sequence, ackseq, window, checksum, urgptr, length).
//
// Like IPPayloadUintField but uses PayloadBaseTransportHeader. Each concrete
// factory below pins (protocol, field, offset, length, label).
type TransportUintField struct {
	protocol nft.PayloadProtocol
	field    string
	offset   uint32
	length   uint32 // 2 or 4
	label    string

	opInput    Select
	valueInput NumberInput

	originalOp    nft.CompareOp
	originalValue uint64
}

func newTransportUintField(rd *nft.Rule, proto nft.PayloadProtocol, field string,
	offset, length uint32, label string) *TransportUintField {

	opInput := NewSelect([]string{"==", "!=", "<", "<=", ">", ">="})
	opInput.Width = 6

	hi := 0xffff
	if length == 4 {
		hi = 1<<31 - 1 // NumberInput stores int; cap at MaxInt32 (covers typical edits)
	}
	valueInput := NewNumberInput(0, hi)
	valueInput.Placeholder = "0"
	valueInput.Width = 12
	if length == 4 {
		valueInput.CharLimit = 10
	} else {
		valueInput.CharLimit = 6
	}

	var originalOp nft.CompareOp = nft.CompareOpEq
	var originalValue uint64

	for _, condition := range rd.Conditions {
		if condition.Payload == nil {
			continue
		}
		if condition.Payload.Protocol != proto || condition.Payload.Field != field {
			continue
		}
		switch v := condition.Payload.Value.(type) {
		case *nft.PortSpec:
			originalValue = uint64(v.Port)
		case uint8:
			originalValue = uint64(v)
		case uint16:
			originalValue = uint64(v)
		case uint32:
			originalValue = uint64(v)
		}
		originalOp = condition.Operation
	}

	opInput.SetValue(string(originalOp))
	if originalValue > 0 {
		valueInput.SetValue(strconv.FormatUint(originalValue, 10))
	}

	return &TransportUintField{
		protocol:      proto,
		field:         field,
		offset:        offset,
		length:        length,
		label:         label,
		opInput:       opInput,
		valueInput:    valueInput,
		originalOp:    originalOp,
		originalValue: originalValue,
	}
}

func (f *TransportUintField) FocusSlots() int { return 2 }

func (f *TransportUintField) Focus(subIndex int) {
	if subIndex == 0 {
		f.opInput.Focus()
		f.valueInput.Blur()
	} else {
		f.opInput.Blur()
		f.valueInput.Focus()
	}
}

func (f *TransportUintField) Blur() {
	f.opInput.Blur()
	f.valueInput.Blur()
}

func (f *TransportUintField) currentValue() uint64 {
	v, _ := f.valueInput.GetUint64()
	return v
}

func (f *TransportUintField) Changed() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp ||
		f.currentValue() != f.originalValue
}

func (f *TransportUintField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.opInput.Focused {
		f.opInput, cmd = f.opInput.Update(msg)
	} else if f.valueInput.Focused() {
		f.valueInput, cmd = f.valueInput.Update(msg)
	}
	return cmd
}

func (f *TransportUintField) encode(v uint64) []byte {
	if f.length == 4 {
		out := make([]byte, 4)
		binary.BigEndian.PutUint32(out, uint32(v))
		return out
	}
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, uint16(v))
	return out
}

func (f *TransportUintField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	cleared := strings.TrimSpace(f.valueInput.Value()) == ""
	newVal := f.currentValue()
	newOp := compareOpToExprCmpOp(nft.CompareOp(f.opInput.Value()))

	for i, re := range rule.Exprs {
		p, ok := re.(*expr.Payload)
		if !ok || p.Base != expr.PayloadBaseTransportHeader ||
			p.Offset != f.offset || p.Len != f.length {
			continue
		}
		if i+1 >= len(rule.Exprs) {
			break
		}
		cmp, ok := rule.Exprs[i+1].(*expr.Cmp)
		if !ok {
			break
		}
		if cleared {
			rule.Exprs = append(rule.Exprs[:i], rule.Exprs[i+2:]...)
		} else {
			cmp.Op = newOp
			cmp.Data = f.encode(newVal)
		}
		f.originalOp = nft.CompareOp(f.opInput.Value())
		f.originalValue = newVal
		return
	}
	if cleared {
		f.originalValue = 0
		return
	}
	rule.Exprs = append(rule.Exprs,
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       f.offset,
			Len:          f.length,
		},
		&expr.Cmp{Op: newOp, Register: 1, Data: f.encode(newVal)},
	)
	f.originalOp = nft.CompareOp(f.opInput.Value())
	f.originalValue = newVal
}

func (f *TransportUintField) View() string {
	vOp := f.opInput.View()
	if nft.CompareOp(f.opInput.Value()) != f.originalOp {
		vOp = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vOp)
	}
	vVal := f.valueInput.View()
	if f.currentValue() != f.originalValue {
		vVal = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vVal)
	}
	inputs := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(8).Render(vOp),
		lipgloss.NewStyle().Width(14).Render(vVal),
	)
	return grayStyle.Render(f.label) + "\n" + inputs + "\n"
}

// --- Concrete factories ---

// TCP
func NewTcpSportField(rd *nft.Rule) *TransportUintField {
	return newTransportUintField(rd, nft.PayloadProtoTCP, "sport", 0, 2, "TCP sport")
}
func NewTcpDportField(rd *nft.Rule) *TransportUintField {
	return newTransportUintField(rd, nft.PayloadProtoTCP, "dport", 2, 2, "TCP dport")
}
func NewTcpSequenceField(rd *nft.Rule) *TransportUintField {
	return newTransportUintField(rd, nft.PayloadProtoTCP, "sequence", 4, 4, "TCP sequence")
}
func NewTcpAckseqField(rd *nft.Rule) *TransportUintField {
	return newTransportUintField(rd, nft.PayloadProtoTCP, "ackseq", 8, 4, "TCP ackseq")
}
func NewTcpWindowField(rd *nft.Rule) *TransportUintField {
	return newTransportUintField(rd, nft.PayloadProtoTCP, "window", 14, 2, "TCP window")
}
func NewTcpChecksumField(rd *nft.Rule) *TransportUintField {
	return newTransportUintField(rd, nft.PayloadProtoTCP, "checksum", 16, 2, "TCP checksum")
}
func NewTcpUrgptrField(rd *nft.Rule) *TransportUintField {
	return newTransportUintField(rd, nft.PayloadProtoTCP, "urgptr", 18, 2, "TCP urgptr")
}

// UDP / UDPLITE — same wire layout, l4proto context distinguishes them.
func NewUdpSportField(rd *nft.Rule) *TransportUintField {
	return newTransportUintField(rd, nft.PayloadProtoTCP, "sport", 0, 2, "UDP sport")
}
func NewUdpDportField(rd *nft.Rule) *TransportUintField {
	return newTransportUintField(rd, nft.PayloadProtoTCP, "dport", 2, 2, "UDP dport")
}

// ruleIsUdplite reports whether the rule's `meta l4proto` match selects
// UDP-Lite. Used only where UDP-Lite's header genuinely diverges from UDP's;
// the cells the two share keep their common label.
func ruleIsUdplite(rd *nft.Rule) bool {
	if rd == nil {
		return false
	}
	for _, c := range rd.Conditions {
		if c.Meta == nil || c.Meta.Key != nft.MetaKeyL4Proto {
			continue
		}
		if v, ok := c.Meta.Value.(uint8); ok && v == unix.IPPROTO_UDPLITE {
			return true
		}
	}
	return false
}

// NewUdpLengthField edits the 16-bit cell at transport offset 4. UDP calls it
// `length`; UDP-Lite carries the checksum coverage there and calls it
// `csumcov` (and rejects `udplite length` outright). One editor renames itself
// from the rule's l4proto context rather than the tab carrying two editors
// that would fight over the same wire cell — Save matches on offset+len, so
// two of them could not coexist.
func NewUdpLengthField(rd *nft.Rule) *TransportUintField {
	if ruleIsUdplite(rd) {
		return newTransportUintField(rd, nft.PayloadProtoUDPLITE, "csumcov", 4, 2, "UDPLITE csumcov")
	}
	return newTransportUintField(rd, nft.PayloadProtoUDP, "length", 4, 2, "UDP length")
}
func NewUdpChecksumField(rd *nft.Rule) *TransportUintField {
	return newTransportUintField(rd, nft.PayloadProtoUDP, "checksum", 6, 2, "UDP checksum")
}
