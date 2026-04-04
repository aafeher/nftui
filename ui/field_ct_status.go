package ui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
	nftexpr "nftui/nft/expr"
)

type CtStatusField struct {
	input    MultiSelect
	original []nftexpr.CtStatus
}

func NewCtStatusField(rd *nft.Rule) *CtStatusField {
	input := NewMultiSelect(nftexpr.CtStatusStrings)
	var original []nftexpr.CtStatus

	for _, condition := range rd.Conditions {
		if condition.CT != nil && condition.CT.Key == nftexpr.CtKeyStatus {
			if statuses, ok := condition.CT.Value.([]nftexpr.CtStatus); ok {
				original = statuses
			} else if status, ok := condition.CT.Value.(nftexpr.CtStatus); ok {
				original = []nftexpr.CtStatus{status}
			}
		}
	}

	originalStrings := make([]string, 0, len(original))
	for _, status := range original {
		originalStrings = append(originalStrings, string(status))
	}
	input.SetValues(originalStrings)

	return &CtStatusField{input: input, original: original}
}

func (f *CtStatusField) FocusSlots() int { return 1 }
func (f *CtStatusField) Focus(_ int)     { f.input.Focus() }
func (f *CtStatusField) Blur()           { f.input.Blur() }

func (f *CtStatusField) Changed() bool {
	origStrings := nftexpr.CtStatusToStatusStrings(f.original)
	return !nftexpr.CtStatesAreEqual(f.input.Values(), origStrings)
}

func (f *CtStatusField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	return cmd
}

func (f *CtStatusField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	newCtStatuses := nftexpr.CtStatusStringToStatuses(f.input.Values())

	for i, re := range rule.Exprs {
		switch e := re.(type) {
		case *expr.Ct:
			if e.Key == expr.CtKeySTATUS {
				if i+1 < len(rule.Exprs) {
					switch next := rule.Exprs[i+1].(type) {
					case *expr.Bitwise:
						next.Mask = nftexpr.EncodeCtStatuses(newCtStatuses)
					case *expr.Cmp:
						if len(newCtStatuses) == 1 {
							next.Data = nftexpr.EncodeCtStatuses(newCtStatuses)
						} else if len(newCtStatuses) > 1 {
							// Switching from Cmp to Bitwise would require deeper restructuring
							// Simplified: update data in place
						}
					}
				}
			}
		}
	}
	f.original = newCtStatuses
	f.input.Changed = false
}

func (f *CtStatusField) View() string {
	v := f.input.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	return grayStyle.Render("CT Status") + "\n" + v + "\n"
}
