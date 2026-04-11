package ui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
	nftexpr "nftui/nft/expr"
)

// CtProtocolField edits the ct protocol condition (L4 protocol: tcp/udp/icmp/…).
// FocusSlots: 0=operator (==/!=), 1=value (protocol name/unset).
type CtProtocolField struct {
	opInput    Select
	valueInput Select
	originalOp nft.CompareOp
	original   nftexpr.CtProtocol
}

func NewCtProtocolField(rd *nft.Rule) *CtProtocolField {
	opInput := NewSelect([]string{"==", "!="})
	opInput.Width = 6
	valueInput := NewSelect(nftexpr.CtProtocolStrings)
	valueInput.Width = 10

	var original nftexpr.CtProtocol
	originalOp := nft.CompareOpEq

	for _, cond := range rd.Conditions {
		if cond.CT != nil && cond.CT.Key == nftexpr.CtKeyProtocol {
			if v, ok := cond.CT.Value.(nftexpr.CtProtocol); ok {
				original = v
				originalOp = cond.Operation
			}
		}
	}

	opInput.SetValue(string(originalOp))
	valueInput.SetValue(string(original))

	return &CtProtocolField{
		opInput:    opInput,
		valueInput: valueInput,
		originalOp: originalOp,
		original:   original,
	}
}

func (f *CtProtocolField) FocusSlots() int { return 2 }

func (f *CtProtocolField) Focus(subIndex int) {
	if subIndex == 0 {
		f.opInput.Focus()
	} else {
		f.valueInput.Focus()
	}
}

func (f *CtProtocolField) Blur() {
	f.opInput.Blur()
	f.valueInput.Blur()
}

func (f *CtProtocolField) opChanged() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp
}

func (f *CtProtocolField) valueChanged() bool {
	return nftexpr.CtProtocol(f.valueInput.Value()) != f.original
}

func (f *CtProtocolField) Changed() bool {
	return f.opChanged() || f.valueChanged()
}

func (f *CtProtocolField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.opInput.Focused {
		f.opInput, cmd = f.opInput.Update(msg)
	} else if f.valueInput.Focused {
		f.valueInput, cmd = f.valueInput.Update(msg)
	}
	return cmd
}

func (f *CtProtocolField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	newVal := nftexpr.CtProtocol(f.valueInput.Value())
	newOp := compareOpToExprCmpOp(nft.CompareOp(f.opInput.Value()))

	found := false
	for i, re := range rule.Exprs {
		e, ok := re.(*expr.Ct)
		if !ok || e.Key != expr.CtKeyPROTOCOL {
			continue
		}
		found = true
		if i+1 < len(rule.Exprs) {
			if cmp, ok2 := rule.Exprs[i+1].(*expr.Cmp); ok2 {
				cmp.Data = []byte{nftexpr.CtProtocolToUint8(newVal)}
				cmp.Op = newOp
			}
		}
		break
	}

	if !found && newVal != "" {
		insertIdx := 0
		for i, re := range rule.Exprs {
			if _, ok := re.(*expr.Ct); ok {
				insertIdx = i + 2
			}
		}
		newExprs := make([]expr.Any, 0, len(rule.Exprs)+2)
		newExprs = append(newExprs, rule.Exprs[:insertIdx]...)
		newExprs = append(newExprs, &expr.Ct{
			Key:      expr.CtKeyPROTOCOL,
			Register: 1,
		}, &expr.Cmp{
			Op:       newOp,
			Register: 1,
			Data:     []byte{nftexpr.CtProtocolToUint8(newVal)},
		})
		newExprs = append(newExprs, rule.Exprs[insertIdx:]...)
		rule.Exprs = newExprs
	}

	f.original = newVal
	f.originalOp = nft.CompareOp(f.opInput.Value())
}

func (f *CtProtocolField) View() string {
	vOp := f.opInput.View()
	if f.opChanged() {
		vOp = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vOp)
	}
	vVal := f.valueInput.View()
	if f.valueChanged() {
		vVal = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vVal)
	}
	inputs := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(10).Render(vOp),
		lipgloss.NewStyle().Render(vVal),
	)
	return grayStyle.Render("CT Protocol") + "\n" + inputs + "\n"
}
