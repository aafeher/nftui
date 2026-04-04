package ui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/nftables"
)

// FieldEditor is a self-contained editable field for the rule editor.
// Each field manages its own input widget(s), original value, and save logic.
type FieldEditor interface {
	// FocusSlots returns how many tab stops this field occupies (1 for simple, 2 for compound).
	FocusSlots() int
	// Focus activates the sub-input at subIndex (0-based).
	Focus(subIndex int)
	// Blur deactivates all sub-inputs.
	Blur()
	// Update handles a Bubble Tea message and returns a command.
	Update(msg tea.Msg) tea.Cmd
	// Save applies current values to the rule if changed, then resets changed state.
	Save(rule *nftables.Rule)
	// Changed reports whether the current value differs from the original.
	Changed() bool
	// View renders this field's label(s) and input widget(s).
	View() string
}
