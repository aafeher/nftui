package ui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
	nftexpr "nftui/nft/expr"
)

// LimitOverField handles the limit "over" boolean toggle.
type LimitOverField struct {
	input    Select
	original bool
}

func NewLimitOverField(rd *nft.Rule) *LimitOverField {
	input := NewSelect([]string{"false", "true"})
	input.Width = 10
	original := false

	for _, condition := range rd.Conditions {
		if condition.Limit != nil {
			original = condition.Limit.Over
		}
	}

	overStr := "false"
	if original {
		overStr = "true"
	}
	input.SetValue(overStr)
	return &LimitOverField{input: input, original: original}
}

func (f *LimitOverField) FocusSlots() int { return 1 }
func (f *LimitOverField) Focus(_ int)     { f.input.Focus() }
func (f *LimitOverField) Blur()           { f.input.Blur() }

func (f *LimitOverField) Changed() bool {
	origStr := "false"
	if f.original {
		origStr = "true"
	}
	return f.input.Value() != origStr
}

func (f *LimitOverField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	return cmd
}

func (f *LimitOverField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	newLimitOverStr := f.input.Value()
	var newLimitOver bool
	switch newLimitOverStr {
	case "true":
		newLimitOver = true
	case "false":
		newLimitOver = false
	}
	for i, re := range rule.Exprs {
		switch re.(type) {
		case *expr.Limit:
			rule.Exprs[i].(*expr.Limit).Over = newLimitOver
		}
	}
	f.original = newLimitOver
	f.input.Changed = false
}

func (f *LimitOverField) View() string {
	v := f.input.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	return grayStyle.Render("Limit Over") + "\n" + v + "\n"
}

// LimitRateField handles the limit rate number input.
type LimitRateField struct {
	input    NumberInput
	original uint64
}

func NewLimitRateField(rd *nft.Rule) *LimitRateField {
	input := NewNumberInput(0, 999_999_999)
	input.Placeholder = ""
	input.CharLimit = 10
	input.Width = 10
	original := uint64(0)

	for _, condition := range rd.Conditions {
		if condition.Limit != nil {
			original = condition.Limit.Rate
		}
	}

	input.SetValue(fmt.Sprint(original))
	return &LimitRateField{input: input, original: original}
}

func (f *LimitRateField) FocusSlots() int { return 1 }
func (f *LimitRateField) Focus(_ int)     { f.input.Focus() }
func (f *LimitRateField) Blur()           { f.input.Blur() }

func (f *LimitRateField) Changed() bool {
	return f.input.Value() != fmt.Sprint(f.original)
}

func (f *LimitRateField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	return cmd
}

func (f *LimitRateField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	val, err := f.input.GetUint64()
	if err != nil {
		return
	}
	for i, re := range rule.Exprs {
		switch re.(type) {
		case *expr.Limit:
			rule.Exprs[i].(*expr.Limit).Rate = val
		}
	}
	f.original = val
}

func (f *LimitRateField) View() string {
	v := f.input.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	return grayStyle.Render("Limit Rate") + "\n" + v + "\n"
}

// LimitUnitField handles the limit time unit selection.
type LimitUnitField struct {
	input    Select
	original expr.LimitTime
}

func NewLimitUnitField(rd *nft.Rule) *LimitUnitField {
	input := NewSelect(nftexpr.LimitTimeStrings)
	input.Width = 10
	original := expr.LimitTimeSecond

	for _, condition := range rd.Conditions {
		if condition.Limit != nil {
			original = condition.Limit.Unit
		}
	}

	input.SetValue(nftexpr.LimitUnitToString(original))
	return &LimitUnitField{input: input, original: original}
}

func (f *LimitUnitField) FocusSlots() int { return 1 }
func (f *LimitUnitField) Focus(_ int)     { f.input.Focus() }
func (f *LimitUnitField) Blur()           { f.input.Blur() }

func (f *LimitUnitField) Changed() bool {
	return f.input.Value() != nftexpr.LimitUnitToString(f.original)
}

func (f *LimitUnitField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	return cmd
}

func (f *LimitUnitField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	newLimitUnit := nftexpr.StringToLimitUnit(f.input.Value())
	for i, re := range rule.Exprs {
		switch re.(type) {
		case *expr.Limit:
			rule.Exprs[i].(*expr.Limit).Unit = newLimitUnit
		}
	}
	f.original = newLimitUnit
	f.input.Changed = false
}

func (f *LimitUnitField) View() string {
	v := f.input.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	return grayStyle.Render("Limit Unit") + "\n" + v + "\n"
}

// LimitBurstField handles the limit burst number input.
type LimitBurstField struct {
	input    NumberInput
	original uint32
}

func NewLimitBurstField(rd *nft.Rule) *LimitBurstField {
	input := NewNumberInput(0, 999_999_999)
	input.Placeholder = ""
	input.CharLimit = 10
	input.Width = 10
	original := uint32(0)

	for _, condition := range rd.Conditions {
		if condition.Limit != nil {
			original = condition.Limit.Burst
		}
	}

	input.SetValue(fmt.Sprint(original))
	return &LimitBurstField{input: input, original: original}
}

func (f *LimitBurstField) FocusSlots() int { return 1 }
func (f *LimitBurstField) Focus(_ int)     { f.input.Focus() }
func (f *LimitBurstField) Blur()           { f.input.Blur() }

func (f *LimitBurstField) Changed() bool {
	return f.input.Value() != fmt.Sprint(f.original)
}

func (f *LimitBurstField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	return cmd
}

func (f *LimitBurstField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	val, err := f.input.GetUint64()
	if err != nil {
		return
	}
	for i, re := range rule.Exprs {
		switch re.(type) {
		case *expr.Limit:
			rule.Exprs[i].(*expr.Limit).Burst = uint32(val)
		}
	}
	f.original = uint32(val)
}

func (f *LimitBurstField) View() string {
	v := f.input.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	return grayStyle.Render("Limit Burst") + "\n" + v + "\n"
}

// LimitTypeField handles the limit type selection (packets/bytes).
type LimitTypeField struct {
	input    Select
	original expr.LimitType
}

func NewLimitTypeField(rd *nft.Rule) *LimitTypeField {
	input := NewSelect(nftexpr.LimitTypeStrings)
	input.Width = 10
	original := expr.LimitTypePkts

	for _, condition := range rd.Conditions {
		if condition.Limit != nil {
			original = condition.Limit.Type
		}
	}

	input.SetValue(nftexpr.LimitTypeToString(original))
	return &LimitTypeField{input: input, original: original}
}

func (f *LimitTypeField) FocusSlots() int { return 1 }
func (f *LimitTypeField) Focus(_ int)     { f.input.Focus() }
func (f *LimitTypeField) Blur()           { f.input.Blur() }

func (f *LimitTypeField) Changed() bool {
	return f.input.Value() != nftexpr.LimitTypeToString(f.original)
}

func (f *LimitTypeField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	return cmd
}

func (f *LimitTypeField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	newLimitType := nftexpr.StringToLimitType(f.input.Value())
	for i, re := range rule.Exprs {
		switch re.(type) {
		case *expr.Limit:
			rule.Exprs[i].(*expr.Limit).Type = newLimitType
		}
	}
	f.original = newLimitType
	f.input.Changed = false
}

func (f *LimitTypeField) View() string {
	v := f.input.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	return grayStyle.Render("Limit Type") + "\n" + v + "\n"
}
