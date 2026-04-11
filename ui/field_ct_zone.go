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

// CtZoneField edits the ct zone condition of a rule.
// Zone is a uint16 identifier (0-65535) with no direction qualifier.
// Supports == and != operators.
type CtZoneField struct {
	opInput       Select
	valueInput    NumberInput
	originalOp    nft.CompareOp
	originalValue uint16
}

func NewCtZoneField(rd *nft.Rule) *CtZoneField {
	opInput := NewSelect([]string{"==", "!=", "<", "<=", ">", ">="})
	opInput.Width = 6

	valueInput := NewNumberInput(0, 65535)
	valueInput.Placeholder = "0-65535"
	valueInput.CharLimit = 5
	valueInput.Width = 8

	var originalOp nft.CompareOp = nft.CompareOpEq
	var originalValue uint16

	for _, condition := range rd.Conditions {
		if condition.CT != nil && condition.CT.Key == nftexpr.CtKeyZone {
			if z, ok := condition.CT.Value.(uint16); ok {
				originalValue = z
			}
			originalOp = condition.Operation
		}
	}

	opInput.SetValue(string(originalOp))
	if originalValue > 0 {
		valueInput.SetValue(fmt.Sprint(originalValue))
	}

	return &CtZoneField{
		opInput:       opInput,
		valueInput:    valueInput,
		originalOp:    originalOp,
		originalValue: originalValue,
	}
}

func (f *CtZoneField) FocusSlots() int { return 2 }

func (f *CtZoneField) Focus(subIndex int) {
	if subIndex == 0 {
		f.opInput.Focus()
	} else {
		f.valueInput.Focus()
	}
}

func (f *CtZoneField) Blur() {
	f.opInput.Blur()
	f.valueInput.Blur()
}

func (f *CtZoneField) opChanged() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp
}

func (f *CtZoneField) valueChanged() bool {
	val, _ := f.valueInput.GetUint64()
	return uint16(val) != f.originalValue
}

func (f *CtZoneField) Changed() bool {
	return f.opChanged() || f.valueChanged()
}

func (f *CtZoneField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.opInput.Focused {
		f.opInput, cmd = f.opInput.Update(msg)
	} else if f.valueInput.Focused() {
		f.valueInput, cmd = f.valueInput.Update(msg)
	}
	return cmd
}

func (f *CtZoneField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	val, err := f.valueInput.GetUint64()
	if err != nil {
		return
	}
	newZone := uint16(val)
	newOp := compareOpToExprCmpOp(nft.CompareOp(f.opInput.Value()))
	// Zone is stored LittleEndian in the kernel
	zoneData := binary.LittleEndian.AppendUint16(nil, newZone)

	found := false
	for i, re := range rule.Exprs {
		if ct, ok := re.(*expr.Ct); ok && ct.Key == expr.CtKeyZONE {
			found = true
			if i+1 < len(rule.Exprs) {
				if cmp, ok := rule.Exprs[i+1].(*expr.Cmp); ok {
					cmp.Data = zoneData
					cmp.Op = newOp
				}
			}
		}
	}

	if !found && (newZone > 0 || f.opChanged()) {
		insertIdx := ctInsertIndex(rule.Exprs)
		newExprs := make([]expr.Any, 0, len(rule.Exprs)+2)
		newExprs = append(newExprs, rule.Exprs[:insertIdx]...)
		newExprs = append(newExprs,
			&expr.Ct{Key: expr.CtKeyZONE, Register: 1},
			&expr.Cmp{Op: newOp, Register: 1, Data: zoneData},
		)
		newExprs = append(newExprs, rule.Exprs[insertIdx:]...)
		rule.Exprs = newExprs
	}

	f.originalOp = nft.CompareOp(f.opInput.Value())
	f.originalValue = newZone
}

func (f *CtZoneField) View() string {
	vOp := f.opInput.View()
	if f.opChanged() {
		vOp = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vOp)
	}
	vVal := f.valueInput.View()
	if f.valueChanged() {
		vVal = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vVal)
	}
	inputs := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(8).Render(vOp),
		lipgloss.NewStyle().Render(vVal),
	)
	return grayStyle.Render("CT zone") + "\n" + inputs + "\n"
}
