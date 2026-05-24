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

// AhField backs the AH header field editors (hdrlength / reserved / spi /
// sequence). Wire layout per RFC 4302:
//
//	offset 0..1  : nexthdr   (uint8) — not exposed (deferred)
//	offset 1..2  : hdrlength (uint8)
//	offset 2..4  : reserved  (uint16)
//	offset 4..8  : spi       (uint32, hex hint)
//	offset 8..12 : sequence  (uint32)
//
// The `meta l4proto ah` (51) prefix is auto-injected on Save.
type AhField struct {
	label   string
	offset  uint32
	length  uint32
	hexHint bool
	// fieldName matches identifyPayloadField's output.
	fieldName string

	valueInput    NumberInput
	originalValue uint64
	originalIsSet bool
}

func newAhField(rd *nft.Rule, label, fieldName string, offset, length uint32, hexHint bool) *AhField {
	hi := 0xff
	switch length {
	case 2:
		hi = 0xffff
	case 4:
		hi = 1<<31 - 1
	}
	valueInput := NewNumberInput(0, hi)
	valueInput.Placeholder = "0"
	switch length {
	case 4:
		valueInput.Width = 14
		valueInput.CharLimit = 10
	case 2:
		valueInput.Width = 10
		valueInput.CharLimit = 5
	default:
		valueInput.Width = 8
		valueInput.CharLimit = 3
	}

	var orig uint64
	var origSet bool
	for _, c := range rd.Conditions {
		if c.Payload == nil ||
			c.Payload.Protocol != nft.PayloadProtoAH ||
			c.Payload.Field != fieldName {
			continue
		}
		switch v := c.Payload.Value.(type) {
		case uint8:
			orig = uint64(v)
		case uint16:
			orig = uint64(v)
		case uint32:
			orig = uint64(v)
		}
		origSet = true
	}
	if origSet && orig > 0 {
		valueInput.SetValue(strconv.FormatUint(orig, 10))
	}

	return &AhField{
		label:         label,
		offset:        offset,
		length:        length,
		hexHint:       hexHint,
		fieldName:     fieldName,
		valueInput:    valueInput,
		originalValue: orig,
		originalIsSet: origSet,
	}
}

func (f *AhField) FocusSlots() int { return 1 }
func (f *AhField) Focus(_ int)     { f.valueInput.Focus() }
func (f *AhField) Blur()           { f.valueInput.Blur() }

func (f *AhField) currentValue() (uint64, bool) {
	s := strings.TrimSpace(f.valueInput.Value())
	if s == "" {
		return 0, false
	}
	v, _ := f.valueInput.GetUint64()
	return v, true
}

func (f *AhField) Changed() bool {
	cur, set := f.currentValue()
	if set != f.originalIsSet {
		return true
	}
	return set && cur != f.originalValue
}

func (f *AhField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.valueInput, cmd = f.valueInput.Update(msg)
	return cmd
}

func (f *AhField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	cur, set := f.currentValue()
	saveL4ProtoMatch(rule, unix.IPPROTO_AH, f.offset, f.length, cur, set)
	if set {
		f.originalValue = cur
		f.originalIsSet = true
	} else {
		f.originalValue = 0
		f.originalIsSet = false
	}
}

func (f *AhField) View() string {
	v := f.valueInput.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	hint := ""
	if f.hexHint {
		if val, err := f.valueInput.GetUint64(); err == nil && val > 0 {
			switch f.length {
			case 2:
				hint = grayStyle.Render(fmt.Sprintf(" (0x%04x)", uint16(val)))
			case 4:
				hint = grayStyle.Render(fmt.Sprintf(" (0x%08x)", uint32(val)))
			}
		}
	}
	return grayStyle.Render(f.label) + "\n" + v + hint + "\n"
}

func NewAhHdrlengthField(rd *nft.Rule) *AhField {
	return newAhField(rd, "AH hdrlength", "hdrlength", 1, 1, false)
}
func NewAhReservedField(rd *nft.Rule) *AhField {
	return newAhField(rd, "AH reserved", "reserved", 2, 2, true)
}
func NewAhSpiField(rd *nft.Rule) *AhField {
	return newAhField(rd, "AH spi", "spi", 4, 4, true)
}
func NewAhSequenceField(rd *nft.Rule) *AhField {
	return newAhField(rd, "AH sequence", "sequence", 8, 4, false)
}
