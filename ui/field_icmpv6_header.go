package ui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"nftui/nft"
)

// Icmpv6HeaderField is the shared editor for the remaining ICMPv6 header
// fields: checksum, id, sequence, mtu, max-delay.
//
//   - `checksum`:  offset 2, len 2 (uint16, hex)
//   - `id`:        offset 4, len 2 (uint16) — meaningful for echo
//     request/reply (types 128/129); `nft` emits this label when paired
//     with a type-set match.
//   - `sequence`:  offset 6, len 2 (uint16) — same caveat as `id`.
//   - `mtu`:       offset 4, len 4 (uint32) — only under
//     `icmpv6 type packet-too-big` (type=2). The TUI does not auto-inject
//     the type match; the user edits the ICMPv6 type Select separately.
//   - `max-delay`: offset 4, len 2 (uint16) — wire-shared with `id`, but
//     only meaningful under `icmpv6 type mld-listener-query` (type=130).
//     The parser cannot disambiguate without the type context, so the
//     TUI exposes both labels as separate factories.
type Icmpv6HeaderField struct {
	label   string
	offset  uint32
	length  uint32
	hexHint bool
	// fieldName matches identifyPayloadField's output for read-back.
	fieldName string

	valueInput    NumberInput
	originalValue uint64
	originalIsSet bool
}

func newIcmpv6HeaderField(rd *nft.Rule, label, fieldName string, offset, length uint32, hexHint bool) *Icmpv6HeaderField {
	hi := 0xffff
	if length == 4 {
		hi = 1<<31 - 1
	}
	valueInput := NewNumberInput(0, hi)
	valueInput.Placeholder = "0"
	if length == 4 {
		valueInput.Width = 14
		valueInput.CharLimit = 10
	} else {
		valueInput.Width = 10
		valueInput.CharLimit = 5
	}

	var orig uint64
	var origSet bool
	for _, c := range rd.Conditions {
		if c.Payload == nil ||
			c.Payload.Protocol != nft.PayloadProtoICMPv6 ||
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

	return &Icmpv6HeaderField{
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

func (f *Icmpv6HeaderField) FocusSlots() int { return 1 }
func (f *Icmpv6HeaderField) Focus(_ int)     { f.valueInput.Focus() }
func (f *Icmpv6HeaderField) Blur()           { f.valueInput.Blur() }

func (f *Icmpv6HeaderField) currentValue() (uint64, bool) {
	s := strings.TrimSpace(f.valueInput.Value())
	if s == "" {
		return 0, false
	}
	v, _ := f.valueInput.GetUint64()
	return v, true
}

func (f *Icmpv6HeaderField) Changed() bool {
	cur, set := f.currentValue()
	if set != f.originalIsSet {
		return true
	}
	return set && cur != f.originalValue
}

func (f *Icmpv6HeaderField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.valueInput, cmd = f.valueInput.Update(msg)
	return cmd
}

func (f *Icmpv6HeaderField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	cur, set := f.currentValue()
	saveIcmpv6Match(rule, f.offset, f.length, cur, set)
	if set {
		f.originalValue = cur
		f.originalIsSet = true
	} else {
		f.originalValue = 0
		f.originalIsSet = false
	}
}

func (f *Icmpv6HeaderField) View() string {
	v := f.valueInput.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	hint := ""
	if f.hexHint {
		if val, err := f.valueInput.GetUint64(); err == nil && val > 0 {
			if f.length == 2 {
				hint = grayStyle.Render(fmt.Sprintf(" (0x%04x)", uint16(val)))
			} else {
				hint = grayStyle.Render(fmt.Sprintf(" (0x%08x)", uint32(val)))
			}
		}
	}
	return grayStyle.Render(f.label) + "\n" + v + hint + "\n"
}

// Concrete factories.

func NewIcmpv6ChecksumField(rd *nft.Rule) *Icmpv6HeaderField {
	return newIcmpv6HeaderField(rd, "ICMPv6 checksum", "checksum", 2, 2, true)
}
func NewIcmpv6IdField(rd *nft.Rule) *Icmpv6HeaderField {
	return newIcmpv6HeaderField(rd, "ICMPv6 id", "id", 4, 2, false)
}
func NewIcmpv6SequenceField(rd *nft.Rule) *Icmpv6HeaderField {
	return newIcmpv6HeaderField(rd, "ICMPv6 sequence", "sequence", 6, 2, false)
}
func NewIcmpv6MtuField(rd *nft.Rule) *Icmpv6HeaderField {
	// type=2 (packet-too-big), offset 4 len 4.
	return newIcmpv6HeaderField(rd, "ICMPv6 mtu", "mtu", 4, 4, false)
}
func NewIcmpv6MaxDelayField(rd *nft.Rule) *Icmpv6HeaderField {
	// type=130 (mld-listener-query), offset 4 len 2 (wire-shared with `id`).
	return newIcmpv6HeaderField(rd, "ICMPv6 max-delay", "id", 4, 2, false)
}
