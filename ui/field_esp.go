package ui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"golang.org/x/sys/unix"
	"nftui/nft"
)

// EspField backs the ESP header editors (spi / sequence). Wire layout per
// RFC 4303:
//
//	offset 0..4 : spi      (uint32 BE, hex hint)
//	offset 4..8 : sequence (uint32 BE)
//
// The `meta l4proto esp` (50) prefix is auto-injected on Save.
type EspField struct {
	label   string
	offset  uint32
	hexHint bool
	// fieldName matches identifyPayloadField's output.
	fieldName string

	valueInput    NumberInput
	originalValue uint64
	originalIsSet bool
}

func newEspField(rd *nft.Rule, label, fieldName string, offset uint32, hexHint bool) *EspField {
	valueInput := NewNumberInput(0, 1<<31-1)
	valueInput.Placeholder = "0"
	valueInput.Width = 14
	valueInput.CharLimit = 10

	var orig uint64
	var origSet bool
	for _, c := range rd.Conditions {
		if c.Payload == nil ||
			c.Payload.Protocol != nft.PayloadProtoESP ||
			c.Payload.Field != fieldName {
			continue
		}
		switch v := c.Payload.Value.(type) {
		case uint32:
			orig = uint64(v)
		}
		origSet = true
	}
	if origSet && orig > 0 {
		valueInput.SetValue(strconv.FormatUint(orig, 10))
	}
	return &EspField{
		label: label, fieldName: fieldName,
		offset: offset, hexHint: hexHint,
		valueInput: valueInput, originalValue: orig, originalIsSet: origSet,
	}
}

func (f *EspField) FocusSlots() int { return 1 }
func (f *EspField) Focus(_ int)     { f.valueInput.Focus() }
func (f *EspField) Blur()           { f.valueInput.Blur() }

func (f *EspField) currentValue() (uint64, bool) {
	s := strings.TrimSpace(f.valueInput.Value())
	if s == "" {
		return 0, false
	}
	v, _ := f.valueInput.GetUint64()
	return v, true
}

func (f *EspField) Changed() bool {
	cur, set := f.currentValue()
	if set != f.originalIsSet {
		return true
	}
	return set && cur != f.originalValue
}

func (f *EspField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.valueInput, cmd = f.valueInput.Update(msg)
	return cmd
}

func (f *EspField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	cur, set := f.currentValue()
	saveL4ProtoMatch(rule, unix.IPPROTO_ESP, f.offset, 4, cur, set)
	if set {
		f.originalValue = cur
		f.originalIsSet = true
	} else {
		f.originalValue = 0
		f.originalIsSet = false
	}
}

func (f *EspField) View() string {
	v := f.valueInput.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	hint := ""
	if f.hexHint {
		if val, err := f.valueInput.GetUint64(); err == nil && val > 0 {
			hint = grayStyle.Render(fmt.Sprintf(" (0x%08x)", uint32(val)))
		}
	}
	return grayStyle.Render(f.label) + "\n" + v + hint + "\n"
}

func NewEspSpiField(rd *nft.Rule) *EspField {
	return newEspField(rd, "ESP spi", "spi", 0, true)
}
func NewEspSequenceField(rd *nft.Rule) *EspField {
	return newEspField(rd, "ESP sequence", "sequence", 4, false)
}
