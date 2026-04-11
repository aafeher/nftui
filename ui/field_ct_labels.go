package ui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
	nftexpr "nftui/nft/expr"
)

type CtLabelsField struct {
	input    textinput.Model
	original string // comma-separated bit indices
}

func NewCtLabelsField(rd *nft.Rule) *CtLabelsField {
	input := textinput.New()
	input.Placeholder = "e.g. 0,3,7"
	input.CharLimit = 64
	input.Width = 30

	var originalStr string
	for _, condition := range rd.Conditions {
		if condition.CT != nil && condition.CT.Key == nftexpr.CtKeyLabels {
			if bits, ok := condition.CT.Value.([]string); ok {
				originalStr = strings.Join(bits, ",")
			}
		}
	}
	input.SetValue(originalStr)

	return &CtLabelsField{input: input, original: originalStr}
}

func (f *CtLabelsField) FocusSlots() int { return 1 }
func (f *CtLabelsField) Focus(_ int)     { f.input.Focus() }
func (f *CtLabelsField) Blur()           { f.input.Blur() }
func (f *CtLabelsField) Changed() bool   { return f.input.Value() != f.original }

func (f *CtLabelsField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	return cmd
}

func (f *CtLabelsField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	rawBits := strings.Split(f.input.Value(), ",")
	newMask := nftexpr.LabelBitIndicesToMask(rawBits)
	zeros := make([]byte, 16)

	found := false
	for i, re := range rule.Exprs {
		if ct, ok := re.(*expr.Ct); ok && ct.Key == expr.CtKeyLABELS {
			found = true
			if i+1 < len(rule.Exprs) {
				if bw, ok := rule.Exprs[i+1].(*expr.Bitwise); ok {
					bw.Mask = newMask
					bw.Xor = zeros
				}
			}
		}
	}

	if !found {
		insertIdx := ctInsertIndex(rule.Exprs)
		newExprs := make([]expr.Any, 0, len(rule.Exprs)+3)
		newExprs = append(newExprs, rule.Exprs[:insertIdx]...)
		newExprs = append(newExprs,
			&expr.Ct{Key: expr.CtKeyLABELS, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 16, Mask: newMask, Xor: zeros},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: zeros},
		)
		newExprs = append(newExprs, rule.Exprs[insertIdx:]...)
		rule.Exprs = newExprs
	}

	f.original = f.input.Value()
	f.input.Blur()
}

func (f *CtLabelsField) View() string {
	v := f.input.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	return grayStyle.Render("CT Labels (bits)") + "\n" + v + "\n"
}
