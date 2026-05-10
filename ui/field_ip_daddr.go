package ui

import (
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"nftui/nft"
)

// IPDaddrField edits the ip daddr (IPv4 destination address) condition of a rule.
type IPDaddrField struct {
	opInput    Select
	input      textinput.Model
	originalOp nft.CompareOp
	original   string
}

func NewIPDaddrField(rd *nft.Rule) *IPDaddrField {
	opInput := NewSelect(ipAddrOpOptions)
	opInput.Width = 6

	input := textinput.New()
	input.Placeholder = "e.g. 10.0.0.1 or 10.0.0.0/8"
	input.CharLimit = 43
	input.Width = 30

	original := extractIPAddrString(rd, "daddr")
	originalOp := extractIPAddrOp(rd, "daddr")
	opInput.SetValue(string(originalOp))
	input.SetValue(original)

	return &IPDaddrField{opInput: opInput, input: input, originalOp: originalOp, original: original}
}

func (f *IPDaddrField) FocusSlots() int { return 2 }

func (f *IPDaddrField) Focus(subIndex int) {
	if subIndex == 0 {
		f.opInput.Focus()
	} else {
		f.input.Focus()
	}
}

func (f *IPDaddrField) Blur() {
	f.opInput.Blur()
	f.input.Blur()
}

func (f *IPDaddrField) opChanged() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp
}

func (f *IPDaddrField) ipChanged() bool {
	return f.input.Value() != f.original
}

func (f *IPDaddrField) Changed() bool {
	return f.opChanged() || f.ipChanged()
}

func (f *IPDaddrField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.opInput.Focused {
		f.opInput, cmd = f.opInput.Update(msg)
	} else if f.input.Focused() {
		f.input, cmd = f.input.Update(msg)
	}
	return cmd
}

func (f *IPDaddrField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	newOp := compareOpToExprCmpOp(nft.CompareOp(f.opInput.Value()))
	applyIPAddrSave(rule, 16, f.input.Value(), newOp)
	f.original = f.input.Value()
	f.originalOp = nft.CompareOp(f.opInput.Value())
}

func (f *IPDaddrField) View() string {
	vOp := f.opInput.View()
	if f.opChanged() {
		vOp = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vOp)
	}
	vIP := f.input.View()
	if f.ipChanged() {
		vIP = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vIP)
	}
	inputs := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(10).Render(vOp),
		lipgloss.NewStyle().Render(vIP),
	)
	return grayStyle.Render("IP dst") + "\n" + inputs + "\n"
}
