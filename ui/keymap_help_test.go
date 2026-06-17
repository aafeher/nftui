package ui

// Help-binding coverage for every dialog/view keymap. ShortHelp and FullHelp
// just assemble []key.Binding slices from the struct's fields, so a zero-value
// instance of each keymap exercises the method bodies without constructing the
// owning view. They're driven through the bubbletea help.KeyMap interface so a
// keymap that stops satisfying it is caught at compile time.

import (
	"testing"

	"github.com/charmbracelet/bubbles/help"
)

func TestKeyMapsImplementHelp(t *testing.T) {
	keymaps := map[string]help.KeyMap{
		"chainCreate": chainCreateKeyMap{},
		"chainEdit":   chainEditKeyMap{},
		"chainFilter": chainFilterKeyMap{},
		"chainView":   chainViewKeyMap{},
		"ruleEdit":    ruleEditKeyMap{},
		"ruleView":    ruleViewKeyMap{},
		"setCreate":   setCreateKeyMap{},
		"setView":     setViewKeyMap{},
		"tableCreate": tableCreateKeyMap{},
		"tableEdit":   tableEditKeyMap{},
		"treeSearch":  treeSearchKeyMap{},
	}

	for name, km := range keymaps {
		t.Run(name, func(t *testing.T) {
			if km.ShortHelp() == nil {
				t.Errorf("%s.ShortHelp() = nil, want a binding slice", name)
			}
			full := km.FullHelp()
			if full == nil {
				t.Errorf("%s.FullHelp() = nil, want binding columns", name)
			}
			for i, col := range full {
				if col == nil {
					t.Errorf("%s.FullHelp()[%d] = nil column", name, i)
				}
			}
		})
	}
}
