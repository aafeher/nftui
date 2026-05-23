package ui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
	nftexpr "nftui/nft/expr"
)

// CtEventmaskField edits the `ct eventmask` condition: a MultiSelect over the
// 12 IPCT_* event bits (new, related, destroy, reply, assured, protoinfo,
// helper, mark, seqadj, secmark, label, synproxy).
//
// Same shape as CtStatusField — bitmask uint32 with Bitwise+Cmp pattern.
// The MATCH form is not creatable from `nft` CLI (kernel returns
// "Operation not supported"), so the TUI is the only way to author such a
// rule via netlink.
type CtEventmaskField struct {
	input    MultiSelect
	original []nftexpr.CtEvent
}

func NewCtEventmaskField(rd *nft.Rule) *CtEventmaskField {
	input := NewMultiSelect(nftexpr.CtEventStrings)
	var original []nftexpr.CtEvent

	for _, condition := range rd.Conditions {
		if condition.CT != nil && condition.CT.Key == nftexpr.CtKeyEventMask {
			if events, ok := condition.CT.Value.([]nftexpr.CtEvent); ok {
				original = events
			} else if ev, ok := condition.CT.Value.(nftexpr.CtEvent); ok {
				original = []nftexpr.CtEvent{ev}
			}
		}
	}

	originalStrings := make([]string, 0, len(original))
	for _, ev := range original {
		originalStrings = append(originalStrings, string(ev))
	}
	input.SetValues(originalStrings)

	return &CtEventmaskField{input: input, original: original}
}

func (f *CtEventmaskField) FocusSlots() int { return 1 }
func (f *CtEventmaskField) Focus(_ int)     { f.input.Focus() }
func (f *CtEventmaskField) Blur()           { f.input.Blur() }

func (f *CtEventmaskField) Changed() bool {
	origStrings := nftexpr.CtEventToEventStrings(f.original)
	return !nftexpr.CtStatesAreEqual(f.input.Values(), origStrings)
}

func (f *CtEventmaskField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	return cmd
}

func (f *CtEventmaskField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	newCtEvents := nftexpr.CtEventStringToEvents(f.input.Values())

	for i, re := range rule.Exprs {
		switch e := re.(type) {
		case *expr.Ct:
			if e.Key == expr.CtKeyEVENTMASK {
				if i+1 < len(rule.Exprs) {
					switch next := rule.Exprs[i+1].(type) {
					case *expr.Bitwise:
						next.Mask = nftexpr.EncodeCtEvents(newCtEvents)
					case *expr.Cmp:
						if len(newCtEvents) == 1 {
							next.Data = nftexpr.EncodeCtEvents(newCtEvents)
						}
					}
				}
			}
		}
	}
	f.original = newCtEvents
	f.input.Changed = false
}

func (f *CtEventmaskField) View() string {
	v := f.input.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	return grayStyle.Render("CT Eventmask") + "\n" + v + "\n"
}
