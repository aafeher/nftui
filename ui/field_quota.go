package ui

import (
	"fmt"
	"strconv"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
)

// QuotaField edits the `quota [over] <n> [bytes|kbytes|mbytes]` statement.
//
// Sub-inputs:
//   - enable Select (off / on)
//   - amount NumberInput
//   - unit Select (bytes / kbytes / mbytes — kernel stores everything in
//     bytes; the unit is a presentation convenience and a multiplier at
//     save time)
//   - over Select (off / on — when on, the match inverts: rule applies
//     only AFTER the quota is exceeded)
//
// The Consumed field is read-only (live byte counter) and shown next to
// the editor in the View.
type QuotaField struct {
	enableInput Select
	amountInput NumberInput
	unitInput   Select
	overInput   Select

	originalEnable bool
	originalBytes  uint64
	originalUnit   string
	originalOver   bool
	consumed       uint64
}

var quotaUnitOptions = []string{"bytes", "kbytes", "mbytes"}

func quotaUnitMultiplier(unit string) uint64 {
	switch unit {
	case "kbytes":
		return 1024
	case "mbytes":
		return 1024 * 1024
	}
	return 1
}

// inferQuotaUnit picks the smallest CLI-friendly unit for a raw byte count.
// Prefers `mbytes` if the value is a clean MiB multiple, then `kbytes`,
// otherwise `bytes`.
func inferQuotaUnit(b uint64) (uint64, string) {
	if b > 0 && b%(1024*1024) == 0 {
		return b / (1024 * 1024), "mbytes"
	}
	if b > 0 && b%1024 == 0 {
		return b / 1024, "kbytes"
	}
	return b, "bytes"
}

func NewQuotaField(rd *nft.Rule) *QuotaField {
	enableInput := NewSelect([]string{"off", "on"})
	enableInput.Width = 6

	amountInput := NewNumberInput(0, 1<<31-1)
	amountInput.Placeholder = "0"
	amountInput.Width = 14
	amountInput.CharLimit = 10

	unitInput := NewSelect(quotaUnitOptions)
	unitInput.Width = 8

	overInput := NewSelect([]string{"off", "on"})
	overInput.Width = 6

	var origEnable, origOver bool
	var origBytes uint64
	var origAmount uint64
	origUnit := "bytes"
	var consumed uint64

	for _, a := range rd.Actions {
		if a.Type != nft.ActionTypeQuota || a.Quota == nil {
			continue
		}
		origEnable = true
		origBytes = a.Quota.Bytes
		origOver = a.Quota.Over
		consumed = a.Quota.Consumed
		origAmount, origUnit = inferQuotaUnit(origBytes)
	}

	if origEnable {
		enableInput.SetValue("on")
	} else {
		enableInput.SetValue("off")
	}
	if origAmount > 0 {
		amountInput.SetValue(strconv.FormatUint(origAmount, 10))
	}
	unitInput.SetValue(origUnit)
	if origOver {
		overInput.SetValue("on")
	} else {
		overInput.SetValue("off")
	}

	return &QuotaField{
		enableInput:    enableInput,
		amountInput:    amountInput,
		unitInput:      unitInput,
		overInput:      overInput,
		originalEnable: origEnable,
		originalBytes:  origBytes,
		originalUnit:   origUnit,
		originalOver:   origOver,
		consumed:       consumed,
	}
}

func (f *QuotaField) FocusSlots() int { return 4 }

func (f *QuotaField) Focus(subIndex int) {
	f.Blur()
	switch subIndex {
	case 0:
		f.enableInput.Focus()
	case 1:
		f.amountInput.Focus()
	case 2:
		f.unitInput.Focus()
	case 3:
		f.overInput.Focus()
	}
}

func (f *QuotaField) Blur() {
	f.enableInput.Blur()
	f.amountInput.Blur()
	f.unitInput.Blur()
	f.overInput.Blur()
}

func (f *QuotaField) currentEnabled() bool { return f.enableInput.Value() == "on" }
func (f *QuotaField) currentOver() bool    { return f.overInput.Value() == "on" }
func (f *QuotaField) currentAmount() uint64 {
	v, _ := f.amountInput.GetUint64()
	return v
}
func (f *QuotaField) currentBytes() uint64 {
	return f.currentAmount() * quotaUnitMultiplier(f.unitInput.Value())
}

func (f *QuotaField) Changed() bool {
	if f.currentEnabled() != f.originalEnable {
		return true
	}
	if f.currentOver() != f.originalOver {
		return true
	}
	if f.currentBytes() != f.originalBytes {
		return true
	}
	if f.unitInput.Value() != f.originalUnit {
		return true
	}
	return false
}

func (f *QuotaField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	switch {
	case f.enableInput.Focused:
		f.enableInput, cmd = f.enableInput.Update(msg)
	case f.amountInput.Focused():
		f.amountInput, cmd = f.amountInput.Update(msg)
	case f.unitInput.Focused:
		f.unitInput, cmd = f.unitInput.Update(msg)
	default:
		f.overInput, cmd = f.overInput.Update(msg)
	}
	return cmd
}

func (f *QuotaField) ValidateForSave() error {
	if !f.Changed() || !f.currentEnabled() {
		return nil
	}
	if f.currentAmount() == 0 {
		return fmt.Errorf("quota: amount must be > 0 when enabled")
	}
	return nil
}

func (f *QuotaField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}

	// Remove any existing *expr.Quota.
	for i := len(rule.Exprs) - 1; i >= 0; i-- {
		if _, ok := rule.Exprs[i].(*expr.Quota); ok {
			rule.Exprs = append(rule.Exprs[:i], rule.Exprs[i+1:]...)
		}
	}

	if !f.currentEnabled() {
		f.originalEnable = false
		f.originalBytes = 0
		f.originalUnit = "bytes"
		f.originalOver = false
		return
	}

	bytes := f.currentBytes()
	over := f.currentOver()
	rule.Exprs = append(rule.Exprs, &expr.Quota{
		Bytes: bytes,
		Over:  over,
	})

	f.originalEnable = true
	f.originalBytes = bytes
	f.originalUnit = f.unitInput.Value()
	f.originalOver = over
}

func (f *QuotaField) View() string {
	vEnable := f.enableInput.View()
	if f.currentEnabled() != f.originalEnable {
		vEnable = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vEnable)
	}
	vAmount := f.amountInput.View()
	if f.currentBytes() != f.originalBytes {
		vAmount = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vAmount)
	}
	vUnit := f.unitInput.View()
	if f.unitInput.Value() != f.originalUnit {
		vUnit = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vUnit)
	}
	vOver := f.overInput.View()
	if f.currentOver() != f.originalOver {
		vOver = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vOver)
	}

	row1 := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(8).Render(grayStyle.Render("enable:")),
		lipgloss.NewStyle().Width(8).Render(vEnable),
		lipgloss.NewStyle().Width(8).Render(grayStyle.Render("amount:")),
		lipgloss.NewStyle().Width(16).Render(vAmount),
		lipgloss.NewStyle().Width(7).Render(grayStyle.Render("unit:")),
		lipgloss.NewStyle().Width(10).Render(vUnit),
		lipgloss.NewStyle().Width(7).Render(grayStyle.Render("over:")),
		lipgloss.NewStyle().Render(vOver),
	)
	consumed := ""
	if f.originalEnable && f.consumed > 0 {
		consumed = grayStyle.Render(fmt.Sprintf("  (consumed: %d bytes)", f.consumed))
	}
	return grayStyle.Render("Quota") + consumed + "\n" + row1 + "\n"
}

// formatQuota renders a QuotaAction as `[over] quota <amount> <unit>`.
func formatQuota(q *nft.QuotaAction) string {
	if q == nil {
		return ""
	}
	amount, unit := inferQuotaUnit(q.Bytes)
	prefix := ""
	if q.Over {
		prefix = grayStyle.Render("over ")
	}
	out := yellowBoldStyle.Render("quota") + " " + prefix +
		fmt.Sprintf("%d %s", amount, unit)
	if q.Consumed > 0 {
		out += grayStyle.Render(fmt.Sprintf(" (consumed: %d bytes)", q.Consumed))
	}
	return out
}
