package ui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type MultiSelect struct {
	Options  []string
	Selected map[int]bool
	Cursor   int
	Focused  bool
	Changed  bool
	Width    int
}

func NewMultiSelect(options []string) MultiSelect {
	return MultiSelect{
		Options:  options,
		Selected: make(map[int]bool),
		Cursor:   0,
		Focused:  false,
		Changed:  false,
		Width:    20,
	}
}

func (s *MultiSelect) Focus() {
	s.Focused = true
}

func (s *MultiSelect) Blur() {
	s.Focused = false
}

func (s *MultiSelect) Values() []string {
	var selected []string
	for i, opt := range s.Options {
		if s.Selected[i] {
			selected = append(selected, opt)
		}
	}
	return selected
}

func (s *MultiSelect) SetValues(vals []string) {
	s.Selected = make(map[int]bool)
	valMap := make(map[string]bool)
	for _, v := range vals {
		valMap[v] = true
	}
	for i, opt := range s.Options {
		if valMap[opt] {
			s.Selected[i] = true
		}
	}
}

func (s MultiSelect) Update(msg tea.Msg) (MultiSelect, tea.Cmd) {
	if !s.Focused {
		return s, nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "left", "h":
			if s.Cursor > 0 {
				s.Cursor--
			}
		case "right", "l":
			if s.Cursor < len(s.Options)-1 {
				s.Cursor++
			}
		case " ", "enter":
			s.Selected[s.Cursor] = !s.Selected[s.Cursor]
			s.Changed = true
		}
	}

	return s, nil
}

func (s MultiSelect) View() string {
	var b strings.Builder

	for i, opt := range s.Options {
		style := lipgloss.NewStyle().Padding(0, 1)

		isSelected := s.Selected[i]
		isCursor := i == s.Cursor

		if isCursor {
			if s.Focused {
				style = style.Foreground(lipgloss.Color("15")).Bold(true).Reverse(true)
			} else {
				style = style.Foreground(lipgloss.Color("240")).Reverse(true)
			}
		} else {
			style = style.Foreground(lipgloss.Color("15"))
		}

		if isSelected {
			if !isCursor {
				//style = style.Foreground(lipgloss.Color("220")).Bold(true)
			} else {
				// If the cursor is on it and it's selected, give some indication
				// In Select.go, used color 220 (gold/yellow) for s.Changed
				//style = style.Foreground(lipgloss.Color("220"))
			}
		}

		if s.Changed {
			style = style.Foreground(lipgloss.Color("220"))
		}

		prefix := "[ ]"
		if isSelected {
			prefix = "[x]"
		}

		b.WriteString(style.Render(prefix + " " + opt))
		if i < len(s.Options)-1 {
			b.WriteString(" ")
		}
	}

	return b.String()
}
