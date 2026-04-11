package ui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
	nftexpr "nftui/nft/expr"
)

// CtL3ProtoField edits the ct l3proto condition (L3 protocol family: ipv4/ipv6).
// FocusSlots: 0=operator (==/!=), 1=value (ipv4/ipv6/unset).
type CtL3ProtoField struct {
	opInput    Select
	valueInput Select
	originalOp nft.CompareOp
	original   nftexpr.CtL3Proto
}

func NewCtL3ProtoField(rd *nft.Rule) *CtL3ProtoField {
	opInput := NewSelect([]string{"==", "!="})
	opInput.Width = 6
	valueInput := NewSelect(nftexpr.CtL3ProtoStrings)
	valueInput.Width = 8

	var original nftexpr.CtL3Proto
	originalOp := nft.CompareOpEq

	for _, cond := range rd.Conditions {
		if cond.CT != nil && cond.CT.Key == nftexpr.CtKeyL3Protocol {
			if v, ok := cond.CT.Value.(nftexpr.CtL3Proto); ok {
				original = v
				originalOp = cond.Operation
			}
		}
	}

	opInput.SetValue(string(originalOp))
	valueInput.SetValue(string(original))

	return &CtL3ProtoField{
		opInput:    opInput,
		valueInput: valueInput,
		originalOp: originalOp,
		original:   original,
	}
}

func (f *CtL3ProtoField) FocusSlots() int { return 2 }

func (f *CtL3ProtoField) Focus(subIndex int) {
	if subIndex == 0 {
		f.opInput.Focus()
	} else {
		f.valueInput.Focus()
	}
}

func (f *CtL3ProtoField) Blur() {
	f.opInput.Blur()
	f.valueInput.Blur()
}

func (f *CtL3ProtoField) opChanged() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp
}

func (f *CtL3ProtoField) valueChanged() bool {
	return nftexpr.CtL3Proto(f.valueInput.Value()) != f.original
}

func (f *CtL3ProtoField) Changed() bool {
	return f.opChanged() || f.valueChanged()
}

func (f *CtL3ProtoField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.opInput.Focused {
		f.opInput, cmd = f.opInput.Update(msg)
	} else if f.valueInput.Focused {
		f.valueInput, cmd = f.valueInput.Update(msg)
	}
	return cmd
}

func (f *CtL3ProtoField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	newVal := nftexpr.CtL3Proto(f.valueInput.Value())
	newOp := compareOpToExprCmpOp(nft.CompareOp(f.opInput.Value()))

	found := false
	for i, re := range rule.Exprs {
		e, ok := re.(*expr.Ct)
		if !ok || e.Key != expr.CtKeyL3PROTOCOL {
			continue
		}
		found = true
		if i+1 < len(rule.Exprs) {
			if cmp, ok2 := rule.Exprs[i+1].(*expr.Cmp); ok2 {
				cmp.Data = []byte{nftexpr.CtL3ProtoToUint8(newVal)}
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
			Key:      expr.CtKeyL3PROTOCOL,
			Register: 1,
		}, &expr.Cmp{
			Op:       newOp,
			Register: 1,
			Data:     []byte{nftexpr.CtL3ProtoToUint8(newVal)},
		})
		newExprs = append(newExprs, rule.Exprs[insertIdx:]...)
		rule.Exprs = newExprs
	}

	f.original = newVal
	f.originalOp = nft.CompareOp(f.opInput.Value())
}

func (f *CtL3ProtoField) View() string {
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
	return grayStyle.Render("CT L3 Proto") + "\n" + inputs + "\n"
}
