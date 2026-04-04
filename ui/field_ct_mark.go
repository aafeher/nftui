package ui

import (
	"encoding/binary"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
	nftexpr "nftui/nft/expr"
)

type CtMarkField struct {
	input    NumberInput
	original uint32
}

func NewCtMarkField(rd *nft.Rule) *CtMarkField {
	input := NewNumberInput(0, 999_999_999)
	input.Placeholder = "0"
	input.CharLimit = 10
	input.Width = 10

	var original uint32
	for _, condition := range rd.Conditions {
		if condition.CT != nil && condition.CT.Key == nftexpr.CtKeyMark {
			if mark, ok := condition.CT.Value.(uint32); ok {
				original = mark
			}
		}
	}

	input.SetValue(fmt.Sprint(original))
	return &CtMarkField{input: input, original: original}
}

func (f *CtMarkField) FocusSlots() int { return 1 }
func (f *CtMarkField) Focus(_ int)     { f.input.Focus() }
func (f *CtMarkField) Blur()           { f.input.Blur() }

func (f *CtMarkField) Changed() bool {
	return f.input.GetValue() != int(f.original)
}

func (f *CtMarkField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	return cmd
}

func (f *CtMarkField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	val, err := f.input.GetUint64()
	if err != nil {
		return
	}
	newMark := uint32(val)
	for i, re := range rule.Exprs {
		switch e := re.(type) {
		case *expr.Ct:
			if e.Key == expr.CtKeyMARK {
				if i+1 < len(rule.Exprs) {
					if next, ok := rule.Exprs[i+1].(*expr.Cmp); ok {
						next.Data = binary.LittleEndian.AppendUint32(nil, newMark)
					}
				}
			}
		}
	}
	f.original = newMark
}

func (f *CtMarkField) View() string {
	v := f.input.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	return grayStyle.Render("CT Mark") + "\n" + v + "\n"
}
