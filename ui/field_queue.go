package ui

import (
	"fmt"
	"strconv"

	"nftui/i18n"
	"nftui/nft"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// QueueField edits the `queue num <n>[-<m>] [flags]` statement.
//
// Sub-inputs:
//   - enable Select (off / on)
//   - num NumberInput (queue number, uint16)
//   - to NumberInput (range upper bound; 0 = no range)
//   - flags MultiSelect (bypass / fanout). The kernel requires `fanout` to
//     be paired with a range; ValidateForSave enforces this.
//
// Wire shape: a single *expr.Queue. Num + Total encode the range
// (Total = to - num + 1).
type QueueField struct {
	enableInput Select
	numInput    NumberInput
	toInput     NumberInput
	flagsInput  MultiSelect

	originalEnable bool
	originalNum    uint64
	originalTo     uint64
	originalFlags  []string
}

var queueFlagNames = []string{"bypass", "fanout"}

func NewQueueField(rd *nft.Rule) *QueueField {
	enableInput := NewSelect([]string{"off", "on"})
	enableInput.Width = 6

	numInput := NewNumberInput(0, 0xffff)
	numInput.Placeholder = "0"
	numInput.Width = 8
	numInput.CharLimit = 5

	toInput := NewNumberInput(0, 0xffff)
	toInput.Placeholder = "0"
	toInput.Width = 8
	toInput.CharLimit = 5

	flagsInput := NewMultiSelect(queueFlagNames)

	var origEnable bool
	var origNum, origTo uint64
	var origFlags []string

	for _, a := range rd.Actions {
		if a.Type != nft.ActionTypeQueue || a.Queue == nil {
			continue
		}
		origEnable = true
		origNum = uint64(a.Queue.Num)
		if a.Queue.NumRange != nil {
			origTo = uint64(a.Queue.NumRange.To)
		}
		for _, fl := range a.Queue.Flags {
			origFlags = append(origFlags, string(fl))
		}
	}

	if origEnable {
		enableInput.SetValue("on")
	} else {
		enableInput.SetValue("off")
	}
	if origNum > 0 {
		numInput.SetValue(strconv.FormatUint(origNum, 10))
	}
	if origTo > 0 {
		toInput.SetValue(strconv.FormatUint(origTo, 10))
	}
	flagsInput.SetValues(origFlags)

	return &QueueField{
		enableInput:    enableInput,
		numInput:       numInput,
		toInput:        toInput,
		flagsInput:     flagsInput,
		originalEnable: origEnable,
		originalNum:    origNum,
		originalTo:     origTo,
		originalFlags:  origFlags,
	}
}

func (f *QueueField) FocusSlots() int { return 4 }

func (f *QueueField) Focus(subIndex int) {
	f.Blur()
	switch subIndex {
	case 0:
		f.enableInput.Focus()
	case 1:
		f.numInput.Focus()
	case 2:
		f.toInput.Focus()
	case 3:
		f.flagsInput.Focus()
	}
}

func (f *QueueField) Blur() {
	f.enableInput.Blur()
	f.numInput.Blur()
	f.toInput.Blur()
	f.flagsInput.Blur()
}

func (f *QueueField) currentEnabled() bool { return f.enableInput.Value() == "on" }
func (f *QueueField) currentNum() uint64   { v, _ := f.numInput.GetUint64(); return v }
func (f *QueueField) currentTo() uint64    { v, _ := f.toInput.GetUint64(); return v }

func (f *QueueField) enableChanged() bool { return f.currentEnabled() != f.originalEnable }
func (f *QueueField) numChanged() bool    { return f.currentNum() != f.originalNum }
func (f *QueueField) toChanged() bool     { return f.currentTo() != f.originalTo }
func (f *QueueField) flagsChanged() bool {
	return !sameStringSet(f.flagsInput.Values(), f.originalFlags)
}

func (f *QueueField) Changed() bool {
	return f.enableChanged() || f.numChanged() || f.toChanged() || f.flagsChanged()
}

func (f *QueueField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	switch {
	case f.enableInput.Focused:
		f.enableInput, cmd = f.enableInput.Update(msg)
	case f.numInput.Focused():
		f.numInput, cmd = f.numInput.Update(msg)
	case f.toInput.Focused():
		f.toInput, cmd = f.toInput.Update(msg)
	default:
		f.flagsInput, cmd = f.flagsInput.Update(msg)
	}
	return cmd
}

func (f *QueueField) ValidateForSave() error {
	if !f.Changed() || !f.currentEnabled() {
		return nil
	}
	num := f.currentNum()
	to := f.currentTo()
	if to != 0 && to < num {
		return fmt.Errorf("queue: range upper bound (%d) must be ≥ num (%d)", to, num)
	}
	hasFanout := false
	for _, fl := range f.flagsInput.Values() {
		if fl == "fanout" {
			hasFanout = true
			break
		}
	}
	if hasFanout && to == 0 {
		return fmt.Errorf("queue: `fanout` flag requires a range — set the upper bound")
	}
	return nil
}

func (f *QueueField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}

	// Remove any existing *expr.Queue.
	for i := len(rule.Exprs) - 1; i >= 0; i-- {
		if _, ok := rule.Exprs[i].(*expr.Queue); ok {
			rule.Exprs = append(rule.Exprs[:i], rule.Exprs[i+1:]...)
		}
	}

	if !f.currentEnabled() {
		f.originalEnable = false
		f.originalNum = 0
		f.originalTo = 0
		f.originalFlags = nil
		return
	}

	num := uint16(f.currentNum())
	to := uint16(f.currentTo())
	total := uint16(1)
	if to > num {
		total = to - num + 1
	}

	flags := f.flagsInput.Values()
	flagSet := map[string]bool{}
	for _, fl := range flags {
		flagSet[fl] = true
	}
	var flagBits uint16
	if flagSet["bypass"] {
		flagBits |= unix.NFT_QUEUE_FLAG_BYPASS
	}
	if flagSet["fanout"] {
		flagBits |= unix.NFT_QUEUE_FLAG_CPU_FANOUT
	}

	rule.Exprs = append(rule.Exprs, &expr.Queue{
		Num:   num,
		Total: total,
		Flag:  expr.QueueFlag(flagBits),
	})

	f.originalEnable = true
	f.originalNum = uint64(num)
	if to > num {
		f.originalTo = uint64(to)
	} else {
		f.originalTo = 0
	}
	f.originalFlags = flags
}

func (f *QueueField) View() string {
	vEnable := f.enableInput.View()
	if f.enableChanged() {
		vEnable = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vEnable)
	}
	vNum := f.numInput.View()
	if f.numChanged() {
		vNum = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vNum)
	}
	vTo := f.toInput.View()
	if f.toChanged() {
		vTo = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vTo)
	}
	vFlags := f.flagsInput.View()
	if f.flagsChanged() {
		vFlags = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vFlags)
	}
	row1 := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(8).Render(grayStyle.Render(i18n.T("rule.field.enable"))),
		lipgloss.NewStyle().Width(8).Render(vEnable),
		lipgloss.NewStyle().Width(6).Render(grayStyle.Render("num:")),
		lipgloss.NewStyle().Width(10).Render(vNum),
		lipgloss.NewStyle().Width(6).Render(grayStyle.Render("to:")),
		lipgloss.NewStyle().Render(vTo),
	)
	return grayStyle.Render("Queue") + "\n" +
		row1 + "\n" +
		grayStyle.Render("flags: ") + vFlags + "\n"
}

// formatQueue renders a QueueAction as `queue num <n>[-<m>] [<flags>]`.
func formatQueue(q *nft.QueueAction) string {
	if q == nil {
		return ""
	}
	out := yellowBoldStyle.Render("queue num")
	if q.NumRange != nil {
		out += fmt.Sprintf(" %d-%d", q.NumRange.From, q.NumRange.To)
	} else {
		out += fmt.Sprintf(" %d", q.Num)
	}
	for _, fl := range q.Flags {
		out += " " + grayStyle.Render(string(fl))
	}
	return out
}
