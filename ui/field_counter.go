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
)

// CounterField edits an anonymous counter's packet and byte values.
// The kernel accepts arbitrary values on AddRule replace; the typical user
// intent is "reset to 0", but any non-negative uint64 is accepted.
//
// FocusSlots reports 2 when the rule has a counter expression (Packets + Bytes),
// 1 inert slot otherwise. Named counters (referenced via objref) are out of
// scope for this field — they live as separate named objects and need their
// own reset path.
type CounterField struct {
	hasCounter      bool
	packetsInput    NumberInput
	bytesInput      NumberInput
	originalPackets uint64
	originalBytes   uint64
}

func NewCounterField(rd *nft.Rule) *CounterField {
	packetsInput := NewNumberInput(0, 1<<31-1)
	bytesInput := NewNumberInput(0, 1<<31-1)

	hasCounter := false
	var origPackets, origBytes uint64
	if rd.Counter != nil {
		hasCounter = true
		origPackets = rd.Counter.Packets
		origBytes = rd.Counter.Bytes
		packetsInput.SetValue(strconv.FormatUint(origPackets, 10))
		bytesInput.SetValue(strconv.FormatUint(origBytes, 10))
	}

	return &CounterField{
		hasCounter:      hasCounter,
		packetsInput:    packetsInput,
		bytesInput:      bytesInput,
		originalPackets: origPackets,
		originalBytes:   origBytes,
	}
}

func (f *CounterField) FocusSlots() int {
	if !f.hasCounter {
		return 1
	}
	return 2
}

func (f *CounterField) Focus(subIndex int) {
	if !f.hasCounter {
		return
	}
	f.Blur()
	if subIndex == 0 {
		f.packetsInput.Focus()
		return
	}
	f.bytesInput.Focus()
}

func (f *CounterField) Blur() {
	f.packetsInput.Blur()
	f.bytesInput.Blur()
}

func (f *CounterField) currentPackets() uint64 {
	v, _ := f.packetsInput.GetUint64()
	return v
}

func (f *CounterField) currentBytes() uint64 {
	v, _ := f.bytesInput.GetUint64()
	return v
}

func (f *CounterField) Changed() bool {
	if !f.hasCounter {
		return false
	}
	return f.currentPackets() != f.originalPackets || f.currentBytes() != f.originalBytes
}

func (f *CounterField) Update(msg tea.Msg) tea.Cmd {
	if !f.hasCounter {
		return nil
	}
	var cmd tea.Cmd
	switch {
	case f.packetsInput.Focused():
		f.packetsInput, cmd = f.packetsInput.Update(msg)
	case f.bytesInput.Focused():
		f.bytesInput, cmd = f.bytesInput.Update(msg)
	}
	return cmd
}

func (f *CounterField) ValidateForSave() error {
	return nil
}

func (f *CounterField) Save(rule *nftables.Rule) {
	if !f.hasCounter || !f.Changed() {
		return
	}
	newPackets := f.currentPackets()
	newBytes := f.currentBytes()

	for _, re := range rule.Exprs {
		if c, ok := re.(*expr.Counter); ok {
			c.Packets = newPackets
			c.Bytes = newBytes
			break
		}
	}

	f.originalPackets = newPackets
	f.originalBytes = newBytes
}

func (f *CounterField) View() string {
	label := grayStyle.Render("Counter")
	if !f.hasCounter {
		return label + "\n" + grayStyle.Render(i18n.T("rule.field.no_counter")) + "\n"
	}

	vPackets := f.packetsInput.View()
	vBytes := f.bytesInput.View()
	if f.currentPackets() != f.originalPackets {
		vPackets = changedStyle.Render(vPackets)
	}
	if f.currentBytes() != f.originalBytes {
		vBytes = changedStyle.Render(vBytes)
	}

	preview := fmt.Sprintf("%d packets, %d bytes",
		f.currentPackets(), f.currentBytes())

	const cw = 28
	col := func(s string) string {
		return lipgloss.NewStyle().Width(cw).Render(s)
	}

	return label + "\n" +
		grayStyle.Render(i18n.T("rule.field.current")) + blueStyle.Render(preview) + "\n" +
		lipgloss.JoinHorizontal(lipgloss.Top,
			col(grayStyle.Render("Packets")+"\n"+vPackets),
			col(grayStyle.Render("Bytes")+"\n"+vBytes),
		) + "\n"
}
