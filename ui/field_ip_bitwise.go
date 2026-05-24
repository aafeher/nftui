package ui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
)

// IPBitwiseField backs the bit-packed IPv4/IPv6 header sub-byte fields that
// the kernel emits as Payload+Bitwise+Cmp triples:
//
//	ip version       : offset 0 len 1, mask 0xf0, encoded = value<<4
//	ip hdrlength     : offset 0 len 1, mask 0x0f, encoded = value
//	ip dscp          : offset 1 len 1, mask 0xfc, encoded = value<<2
//	ip6 version      : offset 0 len 1, mask 0xf0, encoded = value<<4
//
// The user enters the *raw* field value (the high-nibble version, the
// hdrlength, or the DSCP code-point), the editor handles bit-shifting at
// save time and the Bitwise+Cmp wire encoding.
type IPBitwiseField struct {
	protocol nft.PayloadProtocol
	field    string
	offset   uint32
	mask     byte
	shift    uint
	maxValue uint8 // pre-shift upper bound (0xf for 4-bit, 0x3f for 6-bit DSCP)
	label    string

	opInput    Select
	valueInput NumberInput

	originalOp    nft.CompareOp
	originalValue uint64
}

func newIPBitwiseField(rd *nft.Rule, proto nft.PayloadProtocol, field string,
	offset uint32, mask byte, shift uint, maxValue uint8, label string) *IPBitwiseField {

	opInput := NewSelect([]string{"==", "!=", "<", "<=", ">", ">="})
	opInput.Width = 6

	valueInput := NewNumberInput(0, int(maxValue))
	valueInput.Placeholder = "0"
	valueInput.Width = 8
	valueInput.CharLimit = 3

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
		}
		originalOp = condition.Operation
	}

	opInput.SetValue(string(originalOp))
	if originalValue > 0 {
		valueInput.SetValue(strconv.FormatUint(originalValue, 10))
	}

	return &IPBitwiseField{
		protocol:      proto,
		field:         field,
		offset:        offset,
		mask:          mask,
		shift:         shift,
		maxValue:      maxValue,
		label:         label,
		opInput:       opInput,
		valueInput:    valueInput,
		originalOp:    originalOp,
		originalValue: originalValue,
	}
}

func (f *IPBitwiseField) FocusSlots() int { return 2 }

func (f *IPBitwiseField) Focus(subIndex int) {
	if subIndex == 0 {
		f.opInput.Focus()
		f.valueInput.Blur()
	} else {
		f.opInput.Blur()
		f.valueInput.Focus()
	}
}

func (f *IPBitwiseField) Blur() {
	f.opInput.Blur()
	f.valueInput.Blur()
}

func (f *IPBitwiseField) currentValue() uint64 {
	v, _ := f.valueInput.GetUint64()
	return v
}

func (f *IPBitwiseField) Changed() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp ||
		f.currentValue() != f.originalValue
}

func (f *IPBitwiseField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.opInput.Focused {
		f.opInput, cmd = f.opInput.Update(msg)
	} else if f.valueInput.Focused() {
		f.valueInput, cmd = f.valueInput.Update(msg)
	}
	return cmd
}

func (f *IPBitwiseField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	cleared := strings.TrimSpace(f.valueInput.Value()) == ""
	rawVal := f.currentValue()
	encoded := byte(rawVal) << f.shift
	newOp := compareOpToExprCmpOp(nft.CompareOp(f.opInput.Value()))

	for i, re := range rule.Exprs {
		p, ok := re.(*expr.Payload)
		if !ok || p.Base != expr.PayloadBaseNetworkHeader ||
			p.Offset != f.offset || p.Len != 1 {
			continue
		}
		if i+2 >= len(rule.Exprs) {
			break
		}
		bw, ok := rule.Exprs[i+1].(*expr.Bitwise)
		if !ok {
			break
		}
		cmp, ok := rule.Exprs[i+2].(*expr.Cmp)
		if !ok {
			break
		}
		if len(bw.Mask) != 1 || bw.Mask[0] != f.mask {
			continue
		}
		if cleared {
			rule.Exprs = append(rule.Exprs[:i], rule.Exprs[i+3:]...)
		} else {
			cmp.Op = newOp
			cmp.Data = []byte{encoded}
		}
		f.originalOp = nft.CompareOp(f.opInput.Value())
		f.originalValue = rawVal
		return
	}

	if cleared {
		f.originalValue = 0
		return
	}
	reg := uint32(1)
	rule.Exprs = append(rule.Exprs,
		&expr.Payload{
			DestRegister: reg,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       f.offset,
			Len:          1,
		},
		&expr.Bitwise{
			SourceRegister: reg,
			DestRegister:   reg,
			Len:            1,
			Mask:           []byte{f.mask},
			Xor:            []byte{0},
		},
		&expr.Cmp{Op: newOp, Register: reg, Data: []byte{encoded}},
	)
	f.originalOp = nft.CompareOp(f.opInput.Value())
	f.originalValue = rawVal
}

func (f *IPBitwiseField) View() string {
	vOp := f.opInput.View()
	if nft.CompareOp(f.opInput.Value()) != f.originalOp {
		vOp = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vOp)
	}
	vVal := f.valueInput.View()
	if f.currentValue() != f.originalValue {
		vVal = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vVal)
	}
	hint := ""
	if f.field == "dscp" {
		if v, err := f.valueInput.GetUint64(); err == nil && v > 0 {
			hint = grayStyle.Render(fmt.Sprintf(" (raw 0x%02x)", uint8(v)))
		}
	}
	inputs := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(8).Render(vOp),
		lipgloss.NewStyle().Width(10).Render(vVal),
		hint,
	)
	return grayStyle.Render(f.label) + "\n" + inputs + "\n"
}

// Concrete factories.

func NewIPVersionField(rd *nft.Rule) *IPBitwiseField {
	return newIPBitwiseField(rd, nft.PayloadProtoIP, "version", 0, 0xf0, 4, 0xf, "IP version")
}

func NewIPHdrlengthField(rd *nft.Rule) *IPBitwiseField {
	return newIPBitwiseField(rd, nft.PayloadProtoIP, "hdrlength", 0, 0x0f, 0, 0xf, "IP hdrlength")
}

func NewIPDscpField(rd *nft.Rule) *IPBitwiseField {
	return newIPBitwiseField(rd, nft.PayloadProtoIP, "dscp", 1, 0xfc, 2, 0x3f, "IP dscp")
}

func NewIP6VersionField(rd *nft.Rule) *IPBitwiseField {
	return newIPBitwiseField(rd, nft.PayloadProtoIP6, "version", 0, 0xf0, 4, 0xf, "IP6 version")
}
