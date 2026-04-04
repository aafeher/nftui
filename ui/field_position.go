package ui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"nftui/nft"
)

type PositionField struct {
	input    NumberInput
	original uint64
}

func NewPositionField(rd *nft.Rule) *PositionField {
	input := NewNumberInput(0, 999_999_999)
	input.Placeholder = ""
	input.CharLimit = 10
	input.Width = 10
	input.SetValue(fmt.Sprint(rd.Position))
	return &PositionField{input: input, original: rd.Position}
}

func (f *PositionField) FocusSlots() int { return 1 }
func (f *PositionField) Focus(_ int)     { f.input.Focus() }
func (f *PositionField) Blur()           { f.input.Blur() }

func (f *PositionField) Changed() bool {
	val, err := f.input.GetUint64()
	if err != nil {
		return false
	}
	return val != f.original
}

func (f *PositionField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	return cmd
}

func (f *PositionField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	val, err := f.input.GetUint64()
	if err != nil {
		return
	}
	rule.Position = val
	f.original = val
}

func (f *PositionField) View() string {
	v := f.input.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	return grayStyle.Render("Position") + "\n" + v + "\n"
}
