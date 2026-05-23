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

// CtSecMarkField edits the ct secmark condition.
// Secmark is a uint32 SELinux/AppArmor-style label scalar; nft CLI cannot
// produce a `ct secmark <const>` rule (kernel-side feature), but the netlink
// wire format accepts it — so the TUI itself is the only practical way to
// author such a rule.
//
// Supports all relational operators (same shape as CtMarkField).
type CtSecMarkField struct {
	opInput       Select
	valueInput    NumberInput
	originalOp    nft.CompareOp
	originalValue uint32
}

func NewCtSecMarkField(rd *nft.Rule) *CtSecMarkField {
	opInput := NewSelect([]string{"==", "!=", "<", "<=", ">", ">="})
	opInput.Width = 6

	valueInput := NewNumberInput(0, 4_294_967_295)
	valueInput.Placeholder = "0"
	valueInput.CharLimit = 10
	valueInput.Width = 12

	var originalOp nft.CompareOp = nft.CompareOpEq
	var originalValue uint32

	for _, condition := range rd.Conditions {
		if condition.CT != nil && condition.CT.Key == nftexpr.CtKeySecMark {
			if v, ok := condition.CT.Value.(uint32); ok {
				originalValue = v
			}
			originalOp = condition.Operation
		}
	}

	opInput.SetValue(string(originalOp))
	if originalValue > 0 {
		valueInput.SetValue(fmt.Sprint(originalValue))
	}

	return &CtSecMarkField{
		opInput:       opInput,
		valueInput:    valueInput,
		originalOp:    originalOp,
		originalValue: originalValue,
	}
}

func (f *CtSecMarkField) FocusSlots() int { return 2 }

func (f *CtSecMarkField) Focus(subIndex int) {
	if subIndex == 0 {
		f.opInput.Focus()
	} else {
		f.valueInput.Focus()
	}
}

func (f *CtSecMarkField) Blur() {
	f.opInput.Blur()
	f.valueInput.Blur()
}

func (f *CtSecMarkField) opChanged() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp
}

func (f *CtSecMarkField) valueChanged() bool {
	val, _ := f.valueInput.GetUint64()
	return uint32(val) != f.originalValue
}

func (f *CtSecMarkField) Changed() bool {
	return f.opChanged() || f.valueChanged()
}

func (f *CtSecMarkField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.opInput.Focused {
		f.opInput, cmd = f.opInput.Update(msg)
	} else if f.valueInput.Focused() {
		f.valueInput, cmd = f.valueInput.Update(msg)
	}
	return cmd
}

func (f *CtSecMarkField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	val, err := f.valueInput.GetUint64()
	if err != nil {
		return
	}
	newSecMark := uint32(val)
	newOp := compareOpToExprCmpOp(nft.CompareOp(f.opInput.Value()))
	secMarkData := binary.LittleEndian.AppendUint32(nil, newSecMark)

	for i, re := range rule.Exprs {
		if e, ok := re.(*expr.Ct); ok && e.Key == expr.CtKeySECMARK {
			if i+1 < len(rule.Exprs) {
				if cmp, ok := rule.Exprs[i+1].(*expr.Cmp); ok {
					cmp.Op = newOp
					cmp.Data = secMarkData
				}
			}
		}
	}

	f.originalOp = nft.CompareOp(f.opInput.Value())
	f.originalValue = newSecMark
}

func (f *CtSecMarkField) View() string {
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
	return grayStyle.Render("CT Secmark") + "\n" + inputs + "\n"
}
