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

// CompField backs the IPComp header editors (nexthdr / flags / cpi). Wire
// layout per RFC 3173:
//
//	offset 0 : Next Header (uint8)
//	offset 1 : Flags (uint8)
//	offset 2 : CPI - Compression Parameter Index (uint16 BE, hex hint)
//
// The `meta l4proto comp` (108) prefix is auto-injected on Save.
type CompField struct {
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

func newCompField(rd *nft.Rule, label, fieldName string, offset, length uint32, hexHint bool) *CompField {
	hi := 0xff
	if length == 2 {
		hi = 0xffff
	}
	valueInput := NewNumberInput(0, hi)
	valueInput.Placeholder = "0"
	if length == 2 {
		valueInput.Width = 10
		valueInput.CharLimit = 5
	} else {
		valueInput.Width = 8
		valueInput.CharLimit = 3
	}

	var orig uint64
	var origSet bool
	for _, c := range rd.Conditions {
		if c.Payload == nil ||
			c.Payload.Protocol != nft.PayloadProtoCOMP ||
			c.Payload.Field != fieldName {
			continue
		}
		switch v := c.Payload.Value.(type) {
		case uint8:
			orig = uint64(v)
		case uint16:
			orig = uint64(v)
		}
		origSet = true
	}
	if origSet && orig > 0 {
		valueInput.SetValue(strconv.FormatUint(orig, 10))
	}
	return &CompField{
		label: label, fieldName: fieldName,
		offset: offset, length: length, hexHint: hexHint,
		valueInput: valueInput, originalValue: orig, originalIsSet: origSet,
	}
}

func (f *CompField) FocusSlots() int { return 1 }
func (f *CompField) Focus(_ int)     { f.valueInput.Focus() }
func (f *CompField) Blur()           { f.valueInput.Blur() }

func (f *CompField) currentValue() (uint64, bool) {
	s := strings.TrimSpace(f.valueInput.Value())
	if s == "" {
		return 0, false
	}
	v, _ := f.valueInput.GetUint64()
	return v, true
}

func (f *CompField) Changed() bool {
	cur, set := f.currentValue()
	if set != f.originalIsSet {
		return true
	}
	return set && cur != f.originalValue
}

func (f *CompField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.valueInput, cmd = f.valueInput.Update(msg)
	return cmd
}

func (f *CompField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	cur, set := f.currentValue()
	saveL4ProtoMatch(rule, unix.IPPROTO_COMP, f.offset, f.length, cur, set)
	if set {
		f.originalValue = cur
		f.originalIsSet = true
	} else {
		f.originalValue = 0
		f.originalIsSet = false
	}
}

func (f *CompField) View() string {
	v := f.valueInput.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	hint := ""
	if f.hexHint {
		if val, err := f.valueInput.GetUint64(); err == nil && val > 0 {
			if f.length == 2 {
				hint = grayStyle.Render(fmt.Sprintf(" (0x%04x)", uint16(val)))
			}
		}
	}
	return grayStyle.Render(f.label) + "\n" + v + hint + "\n"
}

func NewCompNexthdrField(rd *nft.Rule) *CompField {
	return newCompField(rd, "COMP nexthdr", "nexthdr", 0, 1, false)
}
func NewCompFlagsField(rd *nft.Rule) *CompField {
	return newCompField(rd, "COMP flags", "flags", 1, 1, true)
}
func NewCompCpiField(rd *nft.Rule) *CompField {
	return newCompField(rd, "COMP cpi", "cpi", 2, 2, true)
}
