package ui

import (
	"encoding/binary"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
	nftexpr "nftui/nft/expr"
)

// CtMarkField edits the ct mark condition.
// Mark is a uint32 value displayed and entered as decimal (hex hint shown).
// Supports all relational operators.
type CtMarkField struct {
	opInput       Select
	valueInput    NumberInput
	originalOp    nft.CompareOp
	originalValue uint32
}

func NewCtMarkField(rd *nft.Rule) *CtMarkField {
	opInput := NewSelect([]string{"==", "!=", "<", "<=", ">", ">="})
	opInput.Width = 6

	valueInput := NewNumberInput(0, 4_294_967_295)
	valueInput.Placeholder = "0"
	valueInput.CharLimit = 10
	valueInput.Width = 12

	var originalOp nft.CompareOp = nft.CompareOpEq
	var originalValue uint32

	for _, condition := range rd.Conditions {
		if condition.CT != nil && condition.CT.Key == nftexpr.CtKeyMark {
			if mark, ok := condition.CT.Value.(uint32); ok {
				originalValue = mark
			}
			originalOp = condition.Operation
		}
	}

	opInput.SetValue(string(originalOp))
	if originalValue > 0 {
		valueInput.SetValue(fmt.Sprint(originalValue))
	}

	return &CtMarkField{
		opInput:       opInput,
		valueInput:    valueInput,
		originalOp:    originalOp,
		originalValue: originalValue,
	}
}

func (f *CtMarkField) FocusSlots() int { return 2 }

func (f *CtMarkField) Focus(subIndex int) {
	if subIndex == 0 {
		f.opInput.Focus()
	} else {
		f.valueInput.Focus()
	}
}

func (f *CtMarkField) Blur() {
	f.opInput.Blur()
	f.valueInput.Blur()
}

func (f *CtMarkField) opChanged() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp
}

func (f *CtMarkField) valueChanged() bool {
	val, _ := f.valueInput.GetUint64()
	return uint32(val) != f.originalValue
}

func (f *CtMarkField) Changed() bool {
	return f.opChanged() || f.valueChanged()
}

func (f *CtMarkField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.opInput.Focused {
		f.opInput, cmd = f.opInput.Update(msg)
	} else if f.valueInput.Focused() {
		f.valueInput, cmd = f.valueInput.Update(msg)
	}
	return cmd
}

func (f *CtMarkField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	val, err := f.valueInput.GetUint64()
	if err != nil {
		return
	}
	newMark := uint32(val)
	newOp := compareOpToExprCmpOp(nft.CompareOp(f.opInput.Value()))
	markData := binary.LittleEndian.AppendUint32(nil, newMark)

	for i, re := range rule.Exprs {
		if e, ok := re.(*expr.Ct); ok && e.Key == expr.CtKeyMARK {
			if i+1 < len(rule.Exprs) {
				if cmp, ok := rule.Exprs[i+1].(*expr.Cmp); ok {
					cmp.Op = newOp
					cmp.Data = markData
				}
			}
		}
	}

	f.originalOp = nft.CompareOp(f.opInput.Value())
	f.originalValue = newMark
}

func (f *CtMarkField) View() string {
	vOp := f.opInput.View()
	if f.opChanged() {
		vOp = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vOp)
	}
	vVal := f.valueInput.View()
	if f.valueChanged() {
		vVal = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vVal)
	}
	var hexHint string
	if val, err := f.valueInput.GetUint64(); err == nil {
		hexHint = grayStyle.Render(fmt.Sprintf(" (0x%08x)", uint32(val)))
	}
	inputs := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(8).Render(vOp),
		lipgloss.NewStyle().Width(14).Render(vVal),
		hexHint,
	)
	return grayStyle.Render("CT Mark") + "\n" + inputs + "\n"
}
