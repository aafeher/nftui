package ui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
)

// MasqueradeField edits the `masquerade` statement. Two sub-inputs:
//   - enable Select (on / off)
//   - flag MultiSelect (random / fully-random / persistent)
//
// Port-range handling (`masquerade to :<port>`) is intentionally out of scope
// for the MVP — it requires Register-based Immediate values which need a
// richer editor; tracked as a future v0.2.x refinement.
type MasqueradeField struct {
	enableInput Select
	flagsInput  MultiSelect

	originalEnabled bool
	originalFlags   []string
}

var masqFlagNames = []string{"random", "fully-random", "persistent"}

// formatMasquerade renders a MasqueradeAction as `masquerade [<flags...>]`.
// Used by both rule_view and rule_edit to keep the wording consistent.
func formatMasquerade(m *nft.MasqueradeAction) string {
	out := yellowBoldStyle.Render("masquerade")
	flags := []string{}
	if m.Random {
		flags = append(flags, "random")
	}
	if m.FullyRandom {
		flags = append(flags, "fully-random")
	}
	if m.Persistent {
		flags = append(flags, "persistent")
	}
	for _, f := range flags {
		out += " " + grayStyle.Render(f)
	}
	if m.PortRange != nil {
		out += grayStyle.Render(" to") +
			" :" + fmt.Sprintf("%d-%d", m.PortRange.From, m.PortRange.To)
	}
	return out
}

func extractMasqState(rd *nft.Rule) (enabled bool, flags []string) {
	for _, a := range rd.Actions {
		if a.Type != nft.ActionTypeMasq || a.Masq == nil {
			continue
		}
		enabled = true
		if a.Masq.Random {
			flags = append(flags, "random")
		}
		if a.Masq.FullyRandom {
			flags = append(flags, "fully-random")
		}
		if a.Masq.Persistent {
			flags = append(flags, "persistent")
		}
		return
	}
	return false, nil
}

func NewMasqueradeField(rd *nft.Rule) *MasqueradeField {
	enable := NewSelect([]string{"off", "on"})
	enable.Width = 6

	flagsInput := NewMultiSelect(masqFlagNames)

	enabled, flags := extractMasqState(rd)
	if enabled {
		enable.SetValue("on")
	} else {
		enable.SetValue("off")
	}
	flagsInput.SetValues(flags)

	return &MasqueradeField{
		enableInput:     enable,
		flagsInput:      flagsInput,
		originalEnabled: enabled,
		originalFlags:   flags,
	}
}

func (f *MasqueradeField) FocusSlots() int { return 2 }

func (f *MasqueradeField) Focus(subIndex int) {
	if subIndex == 0 {
		f.enableInput.Focus()
		f.flagsInput.Blur()
	} else {
		f.enableInput.Blur()
		f.flagsInput.Focus()
	}
}

func (f *MasqueradeField) Blur() {
	f.enableInput.Blur()
	f.flagsInput.Blur()
}

func (f *MasqueradeField) currentEnabled() bool {
	return f.enableInput.Value() == "on"
}

func (f *MasqueradeField) enableChanged() bool {
	return f.currentEnabled() != f.originalEnabled
}

func (f *MasqueradeField) flagsChanged() bool {
	return !sameStringSet(f.flagsInput.Values(), f.originalFlags)
}

func (f *MasqueradeField) Changed() bool {
	return f.enableChanged() || f.flagsChanged()
}

func (f *MasqueradeField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.enableInput.Focused {
		f.enableInput, cmd = f.enableInput.Update(msg)
	} else {
		f.flagsInput, cmd = f.flagsInput.Update(msg)
	}
	return cmd
}

func (f *MasqueradeField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	wantEnabled := f.currentEnabled()
	flags := f.flagsInput.Values()
	flagSet := map[string]bool{}
	for _, fl := range flags {
		flagSet[fl] = true
	}

	// Find existing *expr.Masq.
	idx := -1
	for i, re := range rule.Exprs {
		if _, ok := re.(*expr.Masq); ok {
			idx = i
			break
		}
	}

	if !wantEnabled {
		if idx >= 0 {
			rule.Exprs = append(rule.Exprs[:idx], rule.Exprs[idx+1:]...)
		}
		f.originalEnabled = false
		f.originalFlags = nil
		return
	}

	m := &expr.Masq{
		Random:      flagSet["random"],
		FullyRandom: flagSet["fully-random"],
		Persistent:  flagSet["persistent"],
	}
	if idx >= 0 {
		rule.Exprs[idx] = m
	} else {
		rule.Exprs = append(rule.Exprs, m)
	}
	f.originalEnabled = true
	f.originalFlags = flags
}

func (f *MasqueradeField) View() string {
	vEnable := f.enableInput.View()
	if f.enableChanged() {
		vEnable = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vEnable)
	}
	vFlags := f.flagsInput.View()
	if f.flagsChanged() {
		vFlags = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vFlags)
	}
	return grayStyle.Render("Masquerade") + "\n" +
		grayStyle.Render("enable: ") + vEnable + "\n" +
		grayStyle.Render("flags:  ") + vFlags + "\n"
}
