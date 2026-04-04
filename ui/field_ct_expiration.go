package ui

import (
	"encoding/binary"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
	nftexpr "nftui/nft/expr"
)

type CtExpirationField struct {
	input    textinput.Model
	original string
}

func NewCtExpirationField(rd *nft.Rule) *CtExpirationField {
	input := textinput.New()
	input.Placeholder = "e.g. 30s, 1m"
	input.CharLimit = 32
	input.Width = 20

	var originalStr string
	for _, condition := range rd.Conditions {
		if condition.CT != nil && condition.CT.Key == nftexpr.CtKeyExpiration {
			if exp, ok := condition.CT.Value.(uint32); ok && exp > 0 {
				originalStr = nftexpr.FormatDuration(exp)
			}
		}
	}

	input.SetValue(originalStr)

	return &CtExpirationField{input: input, original: originalStr}
}

func (f *CtExpirationField) FocusSlots() int { return 1 }
func (f *CtExpirationField) Focus(_ int)     { f.input.Focus() }
func (f *CtExpirationField) Blur()           { f.input.Blur() }

func (f *CtExpirationField) Changed() bool {
	return f.input.Value() != f.original
}

func (f *CtExpirationField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	return cmd
}

func (f *CtExpirationField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	newExpStr := f.input.Value()
	op, val1, val2, elements, isRange, isSet := parseComplexDuration(newExpStr)

	for i, re := range rule.Exprs {
		switch e := re.(type) {
		case *expr.Ct:
			if e.Key == expr.CtKeyEXPIRATION {
				if i+1 < len(rule.Exprs) {
					if isRange {
						bufFrom := make([]byte, 4)
						binary.BigEndian.PutUint32(bufFrom, val1*1000)
						bufTo := make([]byte, 4)
						binary.BigEndian.PutUint32(bufTo, val2*1000)
						rule.Exprs[i+1] = &expr.Range{
							Op:       op,
							Register: e.Register,
							FromData: bufFrom,
							ToData:   bufTo,
						}
					} else if isSet {
						if len(elements) == 1 {
							buf := make([]byte, 4)
							binary.BigEndian.PutUint32(buf, elements[0]*1000)
							rule.Exprs[i+1] = &expr.Cmp{
								Op:       op,
								Register: e.Register,
								Data:     buf,
							}
						} else {
							// Set handling (lookup) - limited update
							if _, ok := rule.Exprs[i+1].(*expr.Lookup); !ok {
								buf := make([]byte, 4)
								binary.BigEndian.PutUint32(buf, elements[0]*1000)
								rule.Exprs[i+1] = &expr.Cmp{
									Op:       op,
									Register: e.Register,
									Data:     buf,
								}
							}
						}
					} else {
						buf := make([]byte, 4)
						binary.BigEndian.PutUint32(buf, val1*1000)
						rule.Exprs[i+1] = &expr.Cmp{
							Op:       op,
							Register: e.Register,
							Data:     buf,
						}
					}
				}
			}
		}
	}
	f.original = f.input.Value()
	f.input.Blur()
}

func (f *CtExpirationField) View() string {
	v := f.input.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	return grayStyle.Render("CT Expiration") + "\n" + v + "\n"
}
