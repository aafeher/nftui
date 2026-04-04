package ui

import (
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
	nftexpr "nftui/nft/expr"
)

type CtHelperField struct {
	input    textinput.Model
	original string
}

func NewCtHelperField(rd *nft.Rule) *CtHelperField {
	input := textinput.New()
	input.Placeholder = "e.g. ftp"
	input.CharLimit = 32
	input.Width = 20

	var original string
	for _, condition := range rd.Conditions {
		if condition.CT != nil && condition.CT.Key == nftexpr.CtKeyHelper {
			if helper, ok := condition.CT.Value.(string); ok {
				original = helper
			}
		}
	}

	input.SetValue(original)
	return &CtHelperField{input: input, original: original}
}

func (f *CtHelperField) FocusSlots() int { return 1 }
func (f *CtHelperField) Focus(_ int)     { f.input.Focus() }
func (f *CtHelperField) Blur()           { f.input.Blur() }

func (f *CtHelperField) Changed() bool {
	return f.input.Value() != f.original
}

func (f *CtHelperField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	return cmd
}

func (f *CtHelperField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	newHelper := f.input.Value()

	found := false
	for i, re := range rule.Exprs {
		switch e := re.(type) {
		case *expr.Ct:
			if e.Key == expr.CtKeyHELPER {
				found = true
				if i+1 < len(rule.Exprs) {
					if cmp, ok := rule.Exprs[i+1].(*expr.Cmp); ok {
						cmp.Data = []byte(newHelper + "\x00")
					}
				}
			}
		}
	}
	if !found && newHelper != "" {
		// Add new CT helper - insert after other CT expressions
		insertIdx := 0
		for i, re := range rule.Exprs {
			if _, ok := re.(*expr.Ct); ok {
				insertIdx = i + 2
			}
		}
		newExprs := make([]expr.Any, 0, len(rule.Exprs)+2)
		newExprs = append(newExprs, rule.Exprs[:insertIdx]...)
		newExprs = append(newExprs, &expr.Ct{
			Key:      expr.CtKeyHELPER,
			Register: 1,
		}, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte(newHelper + "\x00"),
		})
		newExprs = append(newExprs, rule.Exprs[insertIdx:]...)
		rule.Exprs = newExprs
	}
	f.original = newHelper
	f.input.Blur()
}

func (f *CtHelperField) View() string {
	v := f.input.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	return grayStyle.Render("CT Helper") + "\n" + v + "\n"
}
