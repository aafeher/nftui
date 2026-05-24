package ui

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
)

// IcmpHeaderField is the shared op-less, uint16/uint32 editor for the
// remaining ICMP header fields: checksum, id, sequence, mtu, gateway.
//
//   - `checksum`: offset 2, len 2 (uint16, hex)
//   - `id`:       offset 4, len 2 (uint16)
//   - `sequence`: offset 6, len 2 (uint16)
//   - `mtu`:      offset 6, len 2 (uint16) — wire-shared with `sequence`;
//     `nft` only emits this label when paired with `icmp type 3` (destination-
//     unreachable, code 4). The TUI does not auto-inject that type match;
//     edit the `ICMP type` Select in addition to this field to recreate the
//     full `icmp mtu` semantics.
//   - `gateway`:  offset 4, len 4 (uint32) — wire-shared with `id+sequence`;
//     `nft` only emits this label when paired with `icmp type 5` (redirect).
//     Same caveat as `mtu`.
//
// The `mtu` and `gateway` editors deliberately bypass the
// shared-offset disambiguation in identifyPayloadField — they are exposed
// for completeness of the milestone but are best edited only when the
// surrounding rule already targets the right ICMP type.
type IcmpHeaderField struct {
	label   string
	offset  uint32
	length  uint32 // 2 or 4
	hexHint bool
	// fieldName matches what identifyPayloadField returns for this offset
	// (used to read back the parsed value).
	fieldName string

	valueInput    NumberInput
	originalValue uint64
	originalIsSet bool
}

func newIcmpHeaderField(rd *nft.Rule, label, fieldName string, offset, length uint32, hexHint bool) *IcmpHeaderField {
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
			c.Payload.Protocol != nft.PayloadProtoICMP ||
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

	return &IcmpHeaderField{
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

func (f *IcmpHeaderField) FocusSlots() int { return 1 }
func (f *IcmpHeaderField) Focus(_ int)     { f.valueInput.Focus() }
func (f *IcmpHeaderField) Blur()           { f.valueInput.Blur() }

func (f *IcmpHeaderField) currentValue() (uint64, bool) {
	s := strings.TrimSpace(f.valueInput.Value())
	if s == "" {
		return 0, false
	}
	v, _ := f.valueInput.GetUint64()
	return v, true
}

func (f *IcmpHeaderField) Changed() bool {
	cur, set := f.currentValue()
	if set != f.originalIsSet {
		return true
	}
	if set && cur != f.originalValue {
		return true
	}
	return false
}

func (f *IcmpHeaderField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.valueInput, cmd = f.valueInput.Update(msg)
	return cmd
}

func (f *IcmpHeaderField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	cur, set := f.currentValue()
	saveIcmpHeaderMatch(rule, f.offset, f.length, cur, set)
	if set {
		f.originalValue = cur
		f.originalIsSet = true
	} else {
		f.originalValue = 0
		f.originalIsSet = false
	}
}

func (f *IcmpHeaderField) View() string {
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

// saveIcmpHeaderMatch is the multi-length variant of saveIcmpUintMatch —
// supports len=2 (BE uint16) and len=4 (BE uint32). Inserts the
// `meta l4proto icmp` prefix if not already present, then overwrites or
// removes the Payload+Cmp pair at (offset, length).
func saveIcmpHeaderMatch(rule *nftables.Rule, offset, length uint32, cur uint64, ok bool) {
	// Locate any existing Payload pair.
	idx := -1
	for i, re := range rule.Exprs {
		p, isP := re.(*expr.Payload)
		if !isP || p.Base != expr.PayloadBaseTransportHeader ||
			p.Offset != offset || p.Len != length {
			continue
		}
		idx = i
		break
	}

	if !ok {
		if idx >= 0 && idx+1 < len(rule.Exprs) {
			rule.Exprs = append(rule.Exprs[:idx], rule.Exprs[idx+2:]...)
		}
		return
	}

	if !hasIcmpL4Match(rule) {
		rule.Exprs = append(icmpL4Wire(), rule.Exprs...)
	}

	data := make([]byte, length)
	switch length {
	case 2:
		binary.BigEndian.PutUint16(data, uint16(cur))
	case 4:
		binary.BigEndian.PutUint32(data, uint32(cur))
	}

	// Re-locate (the prefix insertion may have shifted us).
	idx = -1
	for i, re := range rule.Exprs {
		p, isP := re.(*expr.Payload)
		if !isP || p.Base != expr.PayloadBaseTransportHeader ||
			p.Offset != offset || p.Len != length {
			continue
		}
		idx = i
		break
	}
	if idx >= 0 && idx+1 < len(rule.Exprs) {
		if cmp, ok := rule.Exprs[idx+1].(*expr.Cmp); ok {
			cmp.Op = expr.CmpOpEq
			cmp.Data = data
			return
		}
	}
	rule.Exprs = append(rule.Exprs,
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: length},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
	)
}

// Concrete factories.

func NewIcmpChecksumField(rd *nft.Rule) *IcmpHeaderField {
	return newIcmpHeaderField(rd, "ICMP checksum", "checksum", 2, 2, true)
}
func NewIcmpIdField(rd *nft.Rule) *IcmpHeaderField {
	return newIcmpHeaderField(rd, "ICMP id", "id", 4, 2, false)
}
func NewIcmpSequenceField(rd *nft.Rule) *IcmpHeaderField {
	return newIcmpHeaderField(rd, "ICMP sequence", "sequence", 6, 2, false)
}

// Note: `mtu` and `gateway` are documented as wire-shared with `sequence`
// and `gateway` — see the IcmpHeaderField godoc above. We deliberately
// expose them as separate factories so the milestone is feature-complete,
// but reads back into the same `sequence` / `gateway` payload-field name
// (the parser cannot distinguish them without ICMP-type context).
func NewIcmpMtuField(rd *nft.Rule) *IcmpHeaderField {
	// Wire-shared with `sequence` (offset 6, len 2). The kernel only
	// interprets the bytes as MTU when icmp type == 3 (destination-
	// unreachable); the TUI does not enforce that pairing.
	return newIcmpHeaderField(rd, "ICMP mtu", "sequence", 6, 2, false)
}
func NewIcmpGatewayField(rd *nft.Rule) *IcmpHeaderField {
	// Wire-shared with `gateway` (offset 4, len 4). Meaningful when icmp
	// type == 5 (redirect). User enters the gateway as a uint32 (raw IP
	// value); a future refinement could accept dotted-quad notation.
	return newIcmpHeaderField(rd, "ICMP gateway", "gateway", 4, 4, false)
}
