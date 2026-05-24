package ui

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
)

// IPPayloadUintField is a generic op+number editor for IPv4 / IPv6 header
// fields whose value is a 1- or 2-byte unsigned integer. One concrete
// factory per ROADMAP item drives this shared implementation.
//
// On save it overwrites the matching *expr.Payload + *expr.Cmp pair in
// place (uniquely identified by offset+length+base), or appends a new pair
// when none exists. Empty input deletes the match.
type IPPayloadUintField struct {
	protocol nft.PayloadProtocol
	field    string // matches identifyPayloadField output
	offset   uint32
	length   uint32 // 1 or 2
	label    string
	hexHint  bool

	opInput    Select
	valueInput NumberInput

	originalOp    nft.CompareOp
	originalValue uint64
}

func newIPPayloadUintField(rd *nft.Rule, proto nft.PayloadProtocol, field string,
	offset, length uint32, label string, hexHint bool) *IPPayloadUintField {

	opInput := NewSelect([]string{"==", "!=", "<", "<=", ">", ">="})
	opInput.Width = 6

	hi := 0xff
	if length == 2 {
		hi = 0xffff
	}
	valueInput := NewNumberInput(0, hi)
	valueInput.Placeholder = "0"
	valueInput.Width = 12
	if length == 2 {
		valueInput.CharLimit = 6
	} else {
		valueInput.CharLimit = 3
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

	return &IPPayloadUintField{
		protocol:      proto,
		field:         field,
		offset:        offset,
		length:        length,
		label:         label,
		hexHint:       hexHint,
		opInput:       opInput,
		valueInput:    valueInput,
		originalOp:    originalOp,
		originalValue: originalValue,
	}
}

func (f *IPPayloadUintField) FocusSlots() int { return 2 }

func (f *IPPayloadUintField) Focus(subIndex int) {
	if subIndex == 0 {
		f.opInput.Focus()
		f.valueInput.Blur()
	} else {
		f.opInput.Blur()
		f.valueInput.Focus()
	}
}

func (f *IPPayloadUintField) Blur() {
	f.opInput.Blur()
	f.valueInput.Blur()
}

func (f *IPPayloadUintField) currentValue() uint64 {
	v, _ := f.valueInput.GetUint64()
	return v
}

func (f *IPPayloadUintField) opChanged() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp
}

func (f *IPPayloadUintField) valueChanged() bool {
	return f.currentValue() != f.originalValue
}

func (f *IPPayloadUintField) Changed() bool {
	return f.opChanged() || f.valueChanged()
}

func (f *IPPayloadUintField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.opInput.Focused {
		f.opInput, cmd = f.opInput.Update(msg)
	} else if f.valueInput.Focused() {
		f.valueInput, cmd = f.valueInput.Update(msg)
	}
	return cmd
}

func (f *IPPayloadUintField) encode(v uint64) []byte {
	if f.length == 1 {
		return []byte{byte(v)}
	}
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, uint16(v))
	return out
}

func (f *IPPayloadUintField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	cleared := strings.TrimSpace(f.valueInput.Value()) == ""
	newVal := f.currentValue()
	newOp := compareOpToExprCmpOp(nft.CompareOp(f.opInput.Value()))

	for i, re := range rule.Exprs {
		p, ok := re.(*expr.Payload)
		if !ok || p.Base != expr.PayloadBaseNetworkHeader ||
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
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       f.offset,
			Len:          f.length,
		},
		&expr.Cmp{Op: newOp, Register: 1, Data: f.encode(newVal)},
	)
	f.originalOp = nft.CompareOp(f.opInput.Value())
	f.originalValue = newVal
}

func (f *IPPayloadUintField) View() string {
	vOp := f.opInput.View()
	if f.opChanged() {
		vOp = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vOp)
	}
	vVal := f.valueInput.View()
	if f.valueChanged() {
		vVal = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vVal)
	}
	var hex string
	if f.hexHint {
		if v, err := f.valueInput.GetUint64(); err == nil {
			if f.length == 1 {
				hex = grayStyle.Render(fmt.Sprintf(" (0x%02x)", uint8(v)))
			} else {
				hex = grayStyle.Render(fmt.Sprintf(" (0x%04x)", uint16(v)))
			}
		}
	}
	inputs := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(8).Render(vOp),
		lipgloss.NewStyle().Width(14).Render(vVal),
		hex,
	)
	return grayStyle.Render(f.label) + "\n" + inputs + "\n"
}

// --- Concrete factories --------------------------------------------------

// IPv4
func NewIPProtocolField(rd *nft.Rule) *IPPayloadUintField {
	return newIPPayloadUintField(rd, nft.PayloadProtoIP, "protocol", 9, 1, "IP protocol", false)
}
func NewIPTtlField(rd *nft.Rule) *IPPayloadUintField {
	return newIPPayloadUintField(rd, nft.PayloadProtoIP, "ttl", 8, 1, "IP ttl", false)
}
func NewIPLengthField(rd *nft.Rule) *IPPayloadUintField {
	return newIPPayloadUintField(rd, nft.PayloadProtoIP, "length", 2, 2, "IP length", false)
}
func NewIPIdField(rd *nft.Rule) *IPPayloadUintField {
	return newIPPayloadUintField(rd, nft.PayloadProtoIP, "id", 4, 2, "IP id", true)
}
func NewIPFragOffField(rd *nft.Rule) *IPPayloadUintField {
	return newIPPayloadUintField(rd, nft.PayloadProtoIP, "frag-off", 6, 2, "IP frag-off", true)
}
func NewIPChecksumField(rd *nft.Rule) *IPPayloadUintField {
	return newIPPayloadUintField(rd, nft.PayloadProtoIP, "checksum", 10, 2, "IP checksum", true)
}

// (IPVersionField, IPHdrlengthField, IPDscpField are now in field_ip_bitwise.go
//  because they need the Payload+Bitwise+Cmp triple pattern, not a plain
//  Payload+Cmp pair.)

// IPv6
func NewIP6NexthdrField(rd *nft.Rule) *IPPayloadUintField {
	return newIPPayloadUintField(rd, nft.PayloadProtoIP6, "nexthdr", 6, 1, "IP6 nexthdr", false)
}
func NewIP6HoplimitField(rd *nft.Rule) *IPPayloadUintField {
	return newIPPayloadUintField(rd, nft.PayloadProtoIP6, "hoplimit", 7, 1, "IP6 hoplimit", false)
}
func NewIP6LengthField(rd *nft.Rule) *IPPayloadUintField {
	return newIPPayloadUintField(rd, nft.PayloadProtoIP6, "length", 4, 2, "IP6 length", false)
}
