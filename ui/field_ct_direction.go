package ui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
	nftexpr "nftui/nft/expr"
)

type CtDirectionField struct {
	input    Select
	original nftexpr.CtDirection
}

func NewCtDirectionField(rd *nft.Rule) *CtDirectionField {
	input := NewSelect(nftexpr.CtDirectionStrings)
	input.Width = 10
	var original nftexpr.CtDirection

	for _, condition := range rd.Conditions {
		if condition.CT != nil && condition.CT.Key == nftexpr.CtKeyDirection {
			if dir, ok := condition.CT.Value.(nftexpr.CtDirection); ok {
				original = dir
			}
		}
	}

	input.SetValue(string(original))
	return &CtDirectionField{input: input, original: original}
}

func (f *CtDirectionField) FocusSlots() int { return 1 }
func (f *CtDirectionField) Focus(_ int)     { f.input.Focus() }
func (f *CtDirectionField) Blur()           { f.input.Blur() }

func (f *CtDirectionField) Changed() bool {
	return f.input.Value() != string(f.original)
}

func (f *CtDirectionField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	return cmd
}

func (f *CtDirectionField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	newDirStr := f.input.Value()
	newDir := nftexpr.CtDirection(newDirStr)

	for i, re := range rule.Exprs {
		switch e := re.(type) {
		case *expr.Ct:
			if e.Key == expr.CtKeyDIRECTION {
				if i+1 < len(rule.Exprs) {
					if next, ok := rule.Exprs[i+1].(*expr.Cmp); ok {
						if newDir == nftexpr.CtDirectionOriginal {
							next.Data = []byte{0}
						} else {
							next.Data = []byte{1}
						}
					}
				}
			}
		}
	}
	f.original = newDir
	f.input.Changed = false
}

func (f *CtDirectionField) View() string {
	v := f.input.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	return grayStyle.Render("CT Direction") + "\n" + v + "\n"
}
