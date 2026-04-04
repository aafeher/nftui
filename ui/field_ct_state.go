package ui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
	nftexpr "nftui/nft/expr"
)

type CtStateField struct {
	input    MultiSelect
	original []nftexpr.CtState
}

func NewCtStateField(rd *nft.Rule) *CtStateField {
	input := NewMultiSelect(nftexpr.CtStateStrings)
	var original []nftexpr.CtState

	for _, condition := range rd.Conditions {
		if condition.CT != nil && condition.CT.Key == nftexpr.CtKeyState {
			if states, ok := condition.CT.Value.([]nftexpr.CtState); ok {
				original = states
			} else if state, ok := condition.CT.Value.(nftexpr.CtState); ok {
				original = []nftexpr.CtState{state}
			}
		}
	}

	originalStrings := make([]string, 0, len(original))
	for _, state := range original {
		originalStrings = append(originalStrings, string(state))
	}
	input.SetValues(originalStrings)

	return &CtStateField{input: input, original: original}
}

func (f *CtStateField) FocusSlots() int { return 1 }
func (f *CtStateField) Focus(_ int)     { f.input.Focus() }
func (f *CtStateField) Blur()           { f.input.Blur() }

func (f *CtStateField) Changed() bool {
	origStrings := nftexpr.CtStateToStateStrings(f.original)
	return !nftexpr.CtStatesAreEqual(f.input.Values(), origStrings)
}

func (f *CtStateField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	return cmd
}

func (f *CtStateField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	newCtStates := nftexpr.CtStateStringToStates(f.input.Values())

	for i, re := range rule.Exprs {
		switch e := re.(type) {
		case *expr.Ct:
			if e.Key == expr.CtKeySTATE {
				if i+1 < len(rule.Exprs) {
					switch next := rule.Exprs[i+1].(type) {
					case *expr.Bitwise:
						next.Mask = nftexpr.EncodeCtStates(newCtStates)
					case *expr.Cmp:
						if len(newCtStates) == 1 {
							next.Data = nftexpr.EncodeCtStates(newCtStates)
						} else if len(newCtStates) > 1 {
							next.Data = nftexpr.EncodeCtStates(newCtStates)
						}
					}
				}
			}
		}
	}
	f.original = newCtStates
	f.input.Changed = false
}

func (f *CtStateField) View() string {
	v := f.input.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	return grayStyle.Render("CT States") + "\n" + v + "\n"
}
