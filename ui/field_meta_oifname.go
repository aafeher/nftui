package ui

import (
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"nftui/nft"
)

// MetaOifnameField edits the `meta oifname "<name>"` condition.
// Same shape as MetaIifnameField — see padIfname / save semantics there.
type MetaOifnameField struct {
	opInput       Select
	valueInput    textinput.Model
	originalOp    nft.CompareOp
	originalValue string
}

func NewMetaOifnameField(rd *nft.Rule) *MetaOifnameField {
	opInput := NewSelect([]string{"==", "!="})
	opInput.Width = 4

	valueInput := textinput.New()
	valueInput.Placeholder = "e.g. eth0"
	valueInput.CharLimit = 16 // IFNAMSIZ
	valueInput.Width = 18

	var originalOp nft.CompareOp = nft.CompareOpEq
	var originalValue string

	for _, condition := range rd.Conditions {
		if condition.Meta != nil && condition.Meta.Key == nft.MetaKeyOIfName {
			if s, ok := condition.Meta.Value.(string); ok {
				originalValue = s
			}
			originalOp = condition.Operation
		}
	}

	opInput.SetValue(string(originalOp))
	valueInput.SetValue(originalValue)

	return &MetaOifnameField{
		opInput:       opInput,
		valueInput:    valueInput,
		originalOp:    originalOp,
		originalValue: originalValue,
	}
}

func (f *MetaOifnameField) FocusSlots() int { return 2 }

func (f *MetaOifnameField) Focus(subIndex int) {
	if subIndex == 0 {
		f.opInput.Focus()
		f.valueInput.Blur()
	} else {
		f.opInput.Blur()
		f.valueInput.Focus()
	}
}

func (f *MetaOifnameField) Blur() {
	f.opInput.Blur()
	f.valueInput.Blur()
}

func (f *MetaOifnameField) opChanged() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp
}

func (f *MetaOifnameField) valueChanged() bool {
	return f.valueInput.Value() != f.originalValue
}

func (f *MetaOifnameField) Changed() bool {
	return f.opChanged() || f.valueChanged()
}

func (f *MetaOifnameField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.opInput.Focused {
		f.opInput, cmd = f.opInput.Update(msg)
	} else if f.valueInput.Focused() {
		f.valueInput, cmd = f.valueInput.Update(msg)
	}
	return cmd
}

func (f *MetaOifnameField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	newName := f.valueInput.Value()
	newOp := compareOpToExprCmpOp(nft.CompareOp(f.opInput.Value()))

	for i, re := range rule.Exprs {
		m, ok := re.(*expr.Meta)
		if !ok || m.Key != unix.NFT_META_OIFNAME {
			continue
		}
		if i+1 >= len(rule.Exprs) {
			break
		}
		cmp, ok := rule.Exprs[i+1].(*expr.Cmp)
		if !ok {
			break
		}
		if newName == "" {
			rule.Exprs = append(rule.Exprs[:i], rule.Exprs[i+2:]...)
		} else {
			cmp.Op = newOp
			cmp.Data = padIfname(newName)
		}
		f.originalOp = nft.CompareOp(f.opInput.Value())
		f.originalValue = newName
		return
	}

	if newName == "" {
		f.originalValue = ""
		return
	}
	rule.Exprs = append(rule.Exprs,
		&expr.Meta{Key: unix.NFT_META_OIFNAME, Register: 1},
		&expr.Cmp{Op: newOp, Register: 1, Data: padIfname(newName)},
	)
	f.originalOp = nft.CompareOp(f.opInput.Value())
	f.originalValue = newName
}

func (f *MetaOifnameField) View() string {
	vOp := f.opInput.View()
	if f.opChanged() {
		vOp = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vOp)
	}
	vVal := f.valueInput.View()
	if f.valueChanged() {
		vVal = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vVal)
	}
	inputs := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(6).Render(vOp),
		lipgloss.NewStyle().Width(20).Render(vVal),
	)
	return grayStyle.Render("Meta oifname") + "\n" + inputs + "\n"
}
