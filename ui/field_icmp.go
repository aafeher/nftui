package ui

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"nftui/i18n"
	"nftui/nft"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// ICMP type names (RFC 792 — what `nft` accepts in `icmp type`).
var icmpTypeNames = []string{
	"",
	"echo-reply",
	"destination-unreachable",
	"source-quench",
	"redirect",
	"echo-request",
	"router-advertisement",
	"router-solicitation",
	"time-exceeded",
	"parameter-problem",
	"timestamp-request",
	"timestamp-reply",
	"info-request",
	"info-reply",
	"address-mask-request",
	"address-mask-reply",
}

var icmpTypeNameToCode = map[string]uint8{
	"echo-reply":              0,
	"destination-unreachable": 3,
	"source-quench":           4,
	"redirect":                5,
	"echo-request":            8,
	"router-advertisement":    9,
	"router-solicitation":     10,
	"time-exceeded":           11,
	"parameter-problem":       12,
	"timestamp-request":       13,
	"timestamp-reply":         14,
	"info-request":            15,
	"info-reply":              16,
	"address-mask-request":    17,
	"address-mask-reply":      18,
}

func icmpTypeCodeToName(c uint8) string {
	for n, code := range icmpTypeNameToCode {
		if code == c {
			return n
		}
	}
	return ""
}

// icmpL4Wire returns the Meta+Cmp pair that sets the `meta l4proto icmp`
// context — the kernel demands it before any `icmp type/code/...` match
// can apply on a non-ip-family chain.
func icmpL4Wire() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: unix.NFT_META_L4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMP}},
	}
}

// hasIcmpL4Match returns true if the rule already starts with a
// `meta l4proto icmp` match pair (so a new icmp field can latch onto it).
func hasIcmpL4Match(rule *nftables.Rule) bool {
	for i := 0; i+1 < len(rule.Exprs); i++ {
		m, ok := rule.Exprs[i].(*expr.Meta)
		if !ok || m.Key != unix.NFT_META_L4PROTO {
			continue
		}
		c, ok := rule.Exprs[i+1].(*expr.Cmp)
		if !ok || c.Op != expr.CmpOpEq || len(c.Data) < 1 {
			continue
		}
		if c.Data[0] == unix.IPPROTO_ICMP {
			return true
		}
	}
	return false
}

// IcmpTypeField edits the `icmp type <name|N>` match (Select with numeric
// fallback). The match requires a `meta l4proto icmp` context — Save
// inserts the pair if missing.
type IcmpTypeField struct {
	typeSelect    Select
	customInput   NumberInput
	originalType  uint8
	originalIsSet bool
}

func NewIcmpTypeField(rd *nft.Rule) *IcmpTypeField {
	typeSelect := NewSelect(icmpTypeNames)
	typeSelect.Width = 24

	customInput := NewNumberInput(0, 255)
	customInput.Placeholder = "0..255 (numeric fallback)"
	customInput.Width = 12
	customInput.CharLimit = 3

	var origType uint8
	var origIsSet bool

	for _, c := range rd.Conditions {
		if c.Payload == nil ||
			c.Payload.Protocol != nft.PayloadProtoICMP ||
			c.Payload.Field != "type" {
			continue
		}
		if v, ok := c.Payload.Value.(uint8); ok {
			origType = v
			origIsSet = true
		}
	}

	if origIsSet {
		if name := icmpTypeCodeToName(origType); name != "" {
			typeSelect.SetValue(name)
		} else {
			customInput.SetValue(strconv.FormatUint(uint64(origType), 10))
		}
	}

	return &IcmpTypeField{
		typeSelect:    typeSelect,
		customInput:   customInput,
		originalType:  origType,
		originalIsSet: origIsSet,
	}
}

func (f *IcmpTypeField) FocusSlots() int { return 2 }
func (f *IcmpTypeField) Focus(i int) {
	f.Blur()
	if i == 0 {
		f.typeSelect.Focus()
	} else {
		f.customInput.Focus()
	}
}
func (f *IcmpTypeField) Blur() { f.typeSelect.Blur(); f.customInput.Blur() }

func (f *IcmpTypeField) currentType() (uint8, bool) {
	if v := f.typeSelect.Value(); v != "" {
		return icmpTypeNameToCode[v], true
	}
	if s := strings.TrimSpace(f.customInput.Value()); s != "" {
		if n, err := strconv.ParseUint(s, 10, 8); err == nil {
			return uint8(n), true
		}
	}
	return 0, false
}

func (f *IcmpTypeField) Changed() bool {
	cur, set := f.currentType()
	if set != f.originalIsSet {
		return true
	}
	if set && cur != f.originalType {
		return true
	}
	return false
}

func (f *IcmpTypeField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.typeSelect.Focused {
		f.typeSelect, cmd = f.typeSelect.Update(msg)
	} else {
		f.customInput, cmd = f.customInput.Update(msg)
	}
	return cmd
}

func (f *IcmpTypeField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	cur, set := f.currentType()
	saveIcmpUintMatch(rule, 0, 1, cur, set)
	if set {
		f.originalType = cur
		f.originalIsSet = true
	} else {
		f.originalType = 0
		f.originalIsSet = false
	}
}

func (f *IcmpTypeField) View() string {
	vSel := f.typeSelect.View()
	if f.Changed() {
		vSel = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vSel)
	}
	vCustom := f.customInput.View()
	row := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(28).Render(vSel),
		lipgloss.NewStyle().Width(6).Render(grayStyle.Render(i18n.T("rule.field.or"))),
		lipgloss.NewStyle().Render(vCustom),
	)
	return grayStyle.Render("ICMP type") + "\n" + row + "\n"
}

// IcmpCodeField edits the `icmp code <N>` match. The code's meaning is
// type-dependent (host-unreachable=3 under destination-unreachable, etc.),
// so we ship a plain uint8 NumberInput; named lookups can be a future
// refinement once type+code coupling is in scope.
type IcmpCodeField struct {
	valueInput    NumberInput
	originalValue uint8
	originalIsSet bool
}

func NewIcmpCodeField(rd *nft.Rule) *IcmpCodeField {
	valueInput := NewNumberInput(0, 255)
	valueInput.Placeholder = "0..255"
	valueInput.Width = 8
	valueInput.CharLimit = 3

	var orig uint8
	var origSet bool

	for _, c := range rd.Conditions {
		if c.Payload == nil ||
			c.Payload.Protocol != nft.PayloadProtoICMP ||
			c.Payload.Field != "code" {
			continue
		}
		if v, ok := c.Payload.Value.(uint8); ok {
			orig = v
			origSet = true
			valueInput.SetValue(strconv.FormatUint(uint64(v), 10))
		}
	}

	return &IcmpCodeField{
		valueInput:    valueInput,
		originalValue: orig,
		originalIsSet: origSet,
	}
}

func (f *IcmpCodeField) FocusSlots() int { return 1 }
func (f *IcmpCodeField) Focus(_ int)     { f.valueInput.Focus() }
func (f *IcmpCodeField) Blur()           { f.valueInput.Blur() }

func (f *IcmpCodeField) currentValue() (uint8, bool) {
	s := strings.TrimSpace(f.valueInput.Value())
	if s == "" {
		return 0, false
	}
	if n, err := strconv.ParseUint(s, 10, 8); err == nil {
		return uint8(n), true
	}
	return 0, false
}

func (f *IcmpCodeField) Changed() bool {
	cur, set := f.currentValue()
	if set != f.originalIsSet {
		return true
	}
	if set && cur != f.originalValue {
		return true
	}
	return false
}

func (f *IcmpCodeField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.valueInput, cmd = f.valueInput.Update(msg)
	return cmd
}

func (f *IcmpCodeField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	cur, set := f.currentValue()
	saveIcmpUintMatch(rule, 1, 1, cur, set)
	if set {
		f.originalValue = cur
		f.originalIsSet = true
	} else {
		f.originalValue = 0
		f.originalIsSet = false
	}
}

func (f *IcmpCodeField) View() string {
	v := f.valueInput.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	return grayStyle.Render("ICMP code") + "\n" + v + "\n"
}

// saveIcmpUintMatch is the shared write-back for icmp type/code (and later
// checksum/id/sequence): it finds or installs the meta-l4proto-icmp prefix,
// then replaces or removes the Payload+Cmp pair at (offset, length).
//
// `ok=false` means "cleared" — the Payload+Cmp pair is removed. The
// l4proto prefix is kept in case other icmp matches still need it.
func saveIcmpUintMatch(rule *nftables.Rule, offset, length uint32, cur uint8, ok bool) {

	// Locate any existing Payload{Transport, offset, length} pair.
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
		// Clear: remove the pair if present. (Leave the l4proto prefix —
		// other icmp matches may still be using it.)
		if idx >= 0 && idx+1 < len(rule.Exprs) {
			rule.Exprs = append(rule.Exprs[:idx], rule.Exprs[idx+2:]...)
		}
		return
	}

	// Set: ensure the l4proto-icmp prefix exists, then overwrite or insert
	// the Payload+Cmp pair.
	if !hasIcmpL4Match(rule) {
		rule.Exprs = append(icmpL4Wire(), rule.Exprs...)
	}

	data := make([]byte, length)
	if length == 1 {
		data[0] = cur
	} else if length == 2 {
		binary.BigEndian.PutUint16(data, uint16(cur))
	}

	// Re-locate (the prefix may have shifted us).
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
	// No pair yet — append.
	rule.Exprs = append(rule.Exprs,
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: length},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
	)
}

// formatICMP renders an icmp payload condition as `icmp <field> <value>`
// (named for type, raw uint for everything else).
func formatICMP(field string, value any) string {
	out := yellowBoldStyle.Render("icmp "+field) + " "
	switch v := value.(type) {
	case uint8:
		if field == "type" {
			if name := icmpTypeCodeToName(v); name != "" {
				return out + name
			}
		}
		return out + fmt.Sprintf("%d", v)
	case uint16:
		return out + fmt.Sprintf("%d", v)
	}
	return out + fmt.Sprintf("%v", value)
}
