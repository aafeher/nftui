package ui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestNewMultiSelect(t *testing.T) {
	opts := []string{"a", "b", "c"}
	ms := NewMultiSelect(opts)

	if len(ms.Options) != 3 {
		t.Errorf("Options len = %d, want 3", len(ms.Options))
	}
	if ms.Cursor != 0 {
		t.Errorf("Cursor = %d, want 0", ms.Cursor)
	}
	if ms.Focused {
		t.Error("Focused should be false initially")
	}
	if ms.Changed {
		t.Error("Changed should be false initially")
	}
	if len(ms.Selected) != 0 {
		t.Errorf("Selected should be empty initially, got %v", ms.Selected)
	}
}

func TestMultiSelectValues(t *testing.T) {
	ms := NewMultiSelect([]string{"alpha", "beta", "gamma"})

	// Nothing selected
	if vals := ms.Values(); len(vals) != 0 {
		t.Errorf("Values() with nothing selected = %v, want empty", vals)
	}

	ms.Selected[0] = true
	ms.Selected[2] = true
	vals := ms.Values()
	if len(vals) != 2 {
		t.Errorf("Values() len = %d, want 2", len(vals))
	}
	if vals[0] != "alpha" || vals[1] != "gamma" {
		t.Errorf("Values() = %v, want [alpha gamma]", vals)
	}
}

func TestMultiSelectSetValues(t *testing.T) {
	ms := NewMultiSelect([]string{"established", "related", "new", "invalid"})

	ms.SetValues([]string{"established", "new"})

	if !ms.Selected[0] {
		t.Error("established should be selected")
	}
	if ms.Selected[1] {
		t.Error("related should not be selected")
	}
	if !ms.Selected[2] {
		t.Error("new should be selected")
	}
	if ms.Selected[3] {
		t.Error("invalid should not be selected")
	}

	// SetValues replaces existing selection
	ms.SetValues([]string{"invalid"})
	if ms.Selected[0] || ms.Selected[2] {
		t.Error("SetValues should clear previous selection")
	}
	if !ms.Selected[3] {
		t.Error("invalid should be selected after SetValues")
	}

	// Non-existent value is ignored
	ms.SetValues([]string{"nonexistent"})
	for i := range ms.Options {
		if ms.Selected[i] {
			t.Errorf("index %d should not be selected for unknown value", i)
		}
	}
}

func TestMultiSelectFocusBlur(t *testing.T) {
	ms := NewMultiSelect([]string{"x", "y"})

	ms.Focus()
	if !ms.Focused {
		t.Error("Focused should be true after Focus()")
	}

	ms.Blur()
	if ms.Focused {
		t.Error("Focused should be false after Blur()")
	}
}

func TestMultiSelectUpdateNavigation(t *testing.T) {
	tests := []struct {
		name       string
		initialCur int
		key        string
		wantCur    int
	}{
		{"right moves cursor", 0, "right", 1},
		{"l moves cursor", 0, "l", 1},
		{"left moves cursor back", 1, "left", 0},
		{"h moves cursor back", 2, "h", 1},
		{"right at end stays", 2, "right", 2},
		{"left at start stays", 0, "left", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := NewMultiSelect([]string{"a", "b", "c"})
			ms.Focus()
			ms.Cursor = tt.initialCur

			updated, _ := ms.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(tt.key)})
			if updated.Cursor != tt.wantCur {
				t.Errorf("Cursor = %d, want %d", updated.Cursor, tt.wantCur)
			}
		})
	}
}

func TestMultiSelectToggle(t *testing.T) {
	ms := NewMultiSelect([]string{"a", "b", "c"})
	ms.Focus()
	ms.Cursor = 1

	// Space toggles selection
	updated, _ := ms.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(" ")})
	if !updated.Selected[1] {
		t.Error("index 1 should be selected after space")
	}
	if !updated.Changed {
		t.Error("Changed should be true after toggle")
	}

	// Space again toggles off
	updated, _ = updated.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(" ")})
	if updated.Selected[1] {
		t.Error("index 1 should be deselected after second space")
	}
}

func TestMultiSelectUpdateUnfocused(t *testing.T) {
	ms := NewMultiSelect([]string{"a", "b", "c"})
	ms.Cursor = 1

	// Not focused — nothing should change
	updated, _ := ms.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(" ")})
	if updated.Selected[1] {
		t.Error("unfocused multiselect should not toggle on space")
	}
}
