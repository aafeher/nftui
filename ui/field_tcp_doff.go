package ui

import (
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
)

// TcpDoffField edits the `tcp doff` 4-bit data-offset field. Wire pattern is
// Payload{transport, offset=12, len=1} + Bitwise{mask=0xf0, xor=0} + Cmp with
// the raw value shifted left by 4 bits.
//
// The 4-bit doff is in units of 32-bit words; the standard 20-byte header is
// doff=5.
type TcpDoffField struct {
	opInput    Select
	valueInput NumberInput

	originalOp    nft.CompareOp
	originalValue uint64
}

func NewTcpDoffField(rd *nft.Rule) *TcpDoffField {
	opInput := NewSelect([]string{"==", "!=", "<", "<=", ">", ">="})
	opInput.Width = 6

	valueInput := NewNumberInput(0, 15)
	valueInput.Placeholder = "5"
	valueInput.Width = 8
	valueInput.CharLimit = 2

	var originalOp nft.CompareOp = nft.CompareOpEq
	var originalValue uint64

	for _, condition := range rd.Conditions {
		if condition.Payload == nil {
			continue
		}
		if condition.Payload.Protocol != nft.PayloadProtoTCP || condition.Payload.Field != "doff" {
			continue
		}
		if v, ok := condition.Payload.Value.(uint8); ok {
			originalValue = uint64(v)
		}
		originalOp = condition.Operation
	}
	opInput.SetValue(string(originalOp))
	if originalValue > 0 {
		valueInput.SetValue(strconv.FormatUint(originalValue, 10))
	}
	return &TcpDoffField{
		opInput: opInput, valueInput: valueInput,
		originalOp: originalOp, originalValue: originalValue,
	}
}

func (f *TcpDoffField) FocusSlots() int { return 2 }

func (f *TcpDoffField) Focus(subIndex int) {
	if subIndex == 0 {
		f.opInput.Focus()
		f.valueInput.Blur()
	} else {
		f.opInput.Blur()
		f.valueInput.Focus()
	}
}

func (f *TcpDoffField) Blur() {
	f.opInput.Blur()
	f.valueInput.Blur()
}

func (f *TcpDoffField) currentValue() uint64 {
	v, _ := f.valueInput.GetUint64()
	return v
}

func (f *TcpDoffField) Changed() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp ||
		f.currentValue() != f.originalValue
}

func (f *TcpDoffField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.opInput.Focused {
		f.opInput, cmd = f.opInput.Update(msg)
	} else if f.valueInput.Focused() {
		f.valueInput, cmd = f.valueInput.Update(msg)
	}
	return cmd
}

func (f *TcpDoffField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	cleared := strings.TrimSpace(f.valueInput.Value()) == ""
	rawVal := f.currentValue()
	encoded := byte(rawVal) << 4 // doff sits in the high 4 bits of byte 12
	newOp := compareOpToExprCmpOp(nft.CompareOp(f.opInput.Value()))

	for i, re := range rule.Exprs {
		p, ok := re.(*expr.Payload)
		if !ok || p.Base != expr.PayloadBaseTransportHeader ||
			p.Offset != 12 || p.Len != 1 {
			continue
		}
		if i+2 >= len(rule.Exprs) {
			break
		}
		bw, ok := rule.Exprs[i+1].(*expr.Bitwise)
		if !ok || len(bw.Mask) != 1 || bw.Mask[0] != 0xf0 {
			break
		}
		cmp, ok := rule.Exprs[i+2].(*expr.Cmp)
		if !ok {
			break
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
	rule.Exprs = append(rule.Exprs,
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 12, Len: 1},
		&expr.Bitwise{
			SourceRegister: 1, DestRegister: 1, Len: 1,
			Mask: []byte{0xf0}, Xor: []byte{0},
		},
		&expr.Cmp{Op: newOp, Register: 1, Data: []byte{encoded}},
	)
	f.originalOp = nft.CompareOp(f.opInput.Value())
	f.originalValue = rawVal
}

func (f *TcpDoffField) View() string {
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
		lipgloss.NewStyle().Width(10).Render(vVal),
	)
	return grayStyle.Render("TCP doff") + "\n" + inputs + "\n"
}
