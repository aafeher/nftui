package ui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestNewSelect(t *testing.T) {
	opts := []string{"a", "b", "c"}
	s := NewSelect(opts)

	if len(s.Options) != 3 {
		t.Errorf("Options len = %d, want 3", len(s.Options))
	}
	if s.Selected != 0 {
		t.Errorf("Selected = %d, want 0", s.Selected)
	}
	if s.Focused {
		t.Error("Focused should be false initially")
	}
	if s.Changed {
		t.Error("Changed should be false initially")
	}
}

func TestSelectValue(t *testing.T) {
	s := NewSelect([]string{"alpha", "beta", "gamma"})

	if s.Value() != "alpha" {
		t.Errorf("Value() = %q, want %q", s.Value(), "alpha")
	}

	s.Selected = 2
	if s.Value() != "gamma" {
		t.Errorf("Value() = %q, want %q", s.Value(), "gamma")
	}

	// Out of bounds
	s.Selected = 99
	if s.Value() != "" {
		t.Errorf("Value() out of bounds = %q, want empty", s.Value())
	}
}

func TestSelectSetValue(t *testing.T) {
	s := NewSelect([]string{"one", "two", "three"})

	s.SetValue("two")
	if s.Selected != 1 {
		t.Errorf("Selected = %d, want 1 after SetValue(two)", s.Selected)
	}

	s.SetValue("three")
	if s.Selected != 2 {
		t.Errorf("Selected = %d, want 2 after SetValue(three)", s.Selected)
	}

	// Non-existent value leaves selection unchanged
	prev := s.Selected
	s.SetValue("nonexistent")
	if s.Selected != prev {
		t.Errorf("Selected changed on unknown value: got %d, want %d", s.Selected, prev)
	}
}

func TestSelectFocusBlur(t *testing.T) {
	s := NewSelect([]string{"x", "y"})

	s.Focus()
	if !s.Focused {
		t.Error("Focused should be true after Focus()")
	}

	s.Blur()
	if s.Focused {
		t.Error("Focused should be false after Blur()")
	}
}

func TestSelectUpdateNavigation(t *testing.T) {
	tests := []struct {
		name        string
		initial     int
		key         string
		wantIdx     int
		wantChanged bool
	}{
		{"right moves forward", 0, "right", 1, true},
		{"l moves forward", 0, "l", 1, true},
		{"space moves forward", 0, " ", 1, true},
		{"left moves back", 1, "left", 0, true},
		{"h moves back", 2, "h", 1, true},
		{"right at end stays", 2, "right", 2, false},
		{"left at start stays", 0, "left", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSelect([]string{"a", "b", "c"})
			s.Focus()
			s.Selected = tt.initial

			updated, _ := s.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(tt.key)})
			if updated.Selected != tt.wantIdx {
				t.Errorf("Selected = %d, want %d", updated.Selected, tt.wantIdx)
			}
		})
	}
}

func TestSelectUpdateUnfocused(t *testing.T) {
	s := NewSelect([]string{"a", "b", "c"})
	// Not focused — navigation should be ignored
	updated, _ := s.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("right")})
	if updated.Selected != 0 {
		t.Errorf("unfocused select should not move, got %d", updated.Selected)
	}
}
