package ui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type Select struct {
	Options  []string
	Selected int
	Focused  bool
	Changed  bool
	Width    int
}

func NewSelect(options []string) Select {
	return Select{
		Options:  options,
		Selected: 0,
		Focused:  false,
		Changed:  false,
		Width:    20,
	}
}

func (s *Select) Focus() {
	s.Focused = true
}

func (s *Select) Blur() {
	s.Focused = false
}

func (s *Select) Value() string {
	if s.Selected >= 0 && s.Selected < len(s.Options) {
		return s.Options[s.Selected]
	}
	return ""
}

func (s *Select) SetValue(val string) {
	for i, opt := range s.Options {
		if opt == val {
			s.Selected = i
			break
		}
	}
}

func (s Select) Update(msg tea.Msg) (Select, tea.Cmd) {
	if !s.Focused {
		return s, nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "left", "h":
			if s.Selected > 0 {
				s.Selected--
				s.Changed = true
			}
		case "right", "l", " ":
			if s.Selected < len(s.Options)-1 {
				s.Selected++
				s.Changed = true
			}
		}
	}

	return s, nil
}

func (s Select) View() string {
	var b strings.Builder

	for i, opt := range s.Options {
		style := lipgloss.NewStyle().Padding(0, 1)

		if i == s.Selected {
			if s.Focused {
				style = style.Foreground(lipgloss.Color("15")).Bold(true).Reverse(true)
			} else {
				style = style.Foreground(lipgloss.Color("240")).Reverse(true)
			}
			if s.Changed {
				style = style.Foreground(lipgloss.Color("220"))
			}
		} else {
			style = style.Foreground(lipgloss.Color("244"))
		}

		b.WriteString(style.Render(opt))
		if i < len(s.Options)-1 {
			b.WriteString(" ")
		}
	}

	return b.String()
}
