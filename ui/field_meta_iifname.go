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

// MetaIifnameField edits the `meta iifname "<name>"` condition.
// Op selector supports == and != (the only relational operators that are
// meaningful on a string interface name in nftables).
//
// Save semantics:
//   - if the rule already has an *expr.Meta{Key:IIFNAME} + *expr.Cmp pair,
//     overwrite op + data in place;
//   - if not and the new value is non-empty, append a fresh pair (kernel
//     accepts 16-byte IFNAMSIZ-padded payloads; we emit NUL-terminated).
//   - if the field is cleared, the existing pair is removed.
type MetaIifnameField struct {
	opInput       Select
	valueInput    textinput.Model
	originalOp    nft.CompareOp
	originalValue string
}

func NewMetaIifnameField(rd *nft.Rule) *MetaIifnameField {
	opInput := NewSelect([]string{"==", "!="})
	opInput.Width = 4

	valueInput := textinput.New()
	valueInput.Placeholder = "e.g. eth0"
	valueInput.CharLimit = 16 // IFNAMSIZ
	valueInput.Width = 18

	var originalOp nft.CompareOp = nft.CompareOpEq
	var originalValue string

	for _, condition := range rd.Conditions {
		if condition.Meta != nil && condition.Meta.Key == nft.MetaKeyIIfName {
			if s, ok := condition.Meta.Value.(string); ok {
				originalValue = s
			}
			originalOp = condition.Operation
		}
	}

	opInput.SetValue(string(originalOp))
	valueInput.SetValue(originalValue)

	return &MetaIifnameField{
		opInput:       opInput,
		valueInput:    valueInput,
		originalOp:    originalOp,
		originalValue: originalValue,
	}
}

func (f *MetaIifnameField) FocusSlots() int { return 2 }

func (f *MetaIifnameField) Focus(subIndex int) {
	if subIndex == 0 {
		f.opInput.Focus()
		f.valueInput.Blur()
	} else {
		f.opInput.Blur()
		f.valueInput.Focus()
	}
}

func (f *MetaIifnameField) Blur() {
	f.opInput.Blur()
	f.valueInput.Blur()
}

func (f *MetaIifnameField) opChanged() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp
}

func (f *MetaIifnameField) valueChanged() bool {
	return f.valueInput.Value() != f.originalValue
}

func (f *MetaIifnameField) Changed() bool {
	return f.opChanged() || f.valueChanged()
}

func (f *MetaIifnameField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.opInput.Focused {
		f.opInput, cmd = f.opInput.Update(msg)
	} else if f.valueInput.Focused() {
		f.valueInput, cmd = f.valueInput.Update(msg)
	}
	return cmd
}

// padIfname returns an IFNAMSIZ-padded NUL-terminated byte slice (16 bytes).
// The kernel accepts both this and a tight strlen+1 form; we emit padded for
// consistency with what `nft` itself produces.
func padIfname(name string) []byte {
	buf := make([]byte, 16)
	copy(buf, name)
	return buf
}

func (f *MetaIifnameField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	newName := f.valueInput.Value()
	newOp := compareOpToExprCmpOp(nft.CompareOp(f.opInput.Value()))

	// 1) try to overwrite in place.
	for i, re := range rule.Exprs {
		m, ok := re.(*expr.Meta)
		if !ok || m.Key != unix.NFT_META_IIFNAME {
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
			// remove both expressions.
			rule.Exprs = append(rule.Exprs[:i], rule.Exprs[i+2:]...)
		} else {
			cmp.Op = newOp
			cmp.Data = padIfname(newName)
		}
		f.originalOp = nft.CompareOp(f.opInput.Value())
		f.originalValue = newName
		return
	}

	// 2) no existing pair — append one if we have a name.
	if newName == "" {
		f.originalValue = ""
		return
	}
	rule.Exprs = append(rule.Exprs,
		&expr.Meta{Key: unix.NFT_META_IIFNAME, Register: 1},
		&expr.Cmp{Op: newOp, Register: 1, Data: padIfname(newName)},
	)
	f.originalOp = nft.CompareOp(f.opInput.Value())
	f.originalValue = newName
}

func (f *MetaIifnameField) View() string {
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
	return grayStyle.Render("Meta iifname") + "\n" + inputs + "\n"
}
