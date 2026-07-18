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

// ICMPv6 type names (RFC 4443 + NDP/MLD; what `nft` accepts in `icmpv6 type`).
var icmpv6TypeNames = []string{
	"",
	"destination-unreachable",
	"packet-too-big",
	"time-exceeded",
	"parameter-problem",
	"echo-request",
	"echo-reply",
	"mld-listener-query",
	"mld-listener-report",
	"mld-listener-done",
	"nd-router-solicit",
	"nd-router-advert",
	"nd-neighbor-solicit",
	"nd-neighbor-advert",
	"nd-redirect",
	"ind-neighbor-solicit",
	"ind-neighbor-advert",
	"mld2-listener-report",
}

var icmpv6TypeNameToCode = map[string]uint8{
	"destination-unreachable": 1,
	"packet-too-big":          2,
	"time-exceeded":           3,
	"parameter-problem":       4,
	"echo-request":            128,
	"echo-reply":              129,
	"mld-listener-query":      130,
	"mld-listener-report":     131,
	"mld-listener-done":       132,
	"nd-router-solicit":       133,
	"nd-router-advert":        134,
	"nd-neighbor-solicit":     135,
	"nd-neighbor-advert":      136,
	"nd-redirect":             137,
	"ind-neighbor-solicit":    141,
	"ind-neighbor-advert":     142,
	"mld2-listener-report":    143,
}

func icmpv6TypeCodeToName(c uint8) string {
	for n, code := range icmpv6TypeNameToCode {
		if code == c {
			return n
		}
	}
	return ""
}

// icmpv6L4Wire returns the meta-l4proto-icmpv6 prefix pair.
func icmpv6L4Wire() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: unix.NFT_META_L4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMPV6}},
	}
}

func hasIcmpv6L4Match(rule *nftables.Rule) bool {
	for i := 0; i+1 < len(rule.Exprs); i++ {
		m, ok := rule.Exprs[i].(*expr.Meta)
		if !ok || m.Key != unix.NFT_META_L4PROTO {
			continue
		}
		c, ok := rule.Exprs[i+1].(*expr.Cmp)
		if !ok || c.Op != expr.CmpOpEq || len(c.Data) < 1 {
			continue
		}
		if c.Data[0] == unix.IPPROTO_ICMPV6 {
			return true
		}
	}
	return false
}

// Icmpv6TypeField — Select of named ICMPv6 types + numeric fallback.
type Icmpv6TypeField struct {
	typeSelect    Select
	customInput   NumberInput
	originalType  uint8
	originalIsSet bool
}

func NewIcmpv6TypeField(rd *nft.Rule) *Icmpv6TypeField {
	typeSelect := NewSelect(icmpv6TypeNames)
	typeSelect.Width = 26

	customInput := NewNumberInput(0, 255)
	customInput.Placeholder = "0..255 (numeric fallback)"
	customInput.Width = 12
	customInput.CharLimit = 3

	var orig uint8
	var origSet bool
	for _, c := range rd.Conditions {
		if c.Payload == nil ||
			c.Payload.Protocol != nft.PayloadProtoICMPv6 ||
			c.Payload.Field != "type" {
			continue
		}
		if v, ok := c.Payload.Value.(uint8); ok {
			orig = v
			origSet = true
		}
	}
	if origSet {
		if name := icmpv6TypeCodeToName(orig); name != "" {
			typeSelect.SetValue(name)
		} else {
			customInput.SetValue(strconv.FormatUint(uint64(orig), 10))
		}
	}
	return &Icmpv6TypeField{
		typeSelect: typeSelect, customInput: customInput,
		originalType: orig, originalIsSet: origSet,
	}
}

func (f *Icmpv6TypeField) FocusSlots() int { return 2 }
func (f *Icmpv6TypeField) Focus(i int) {
	f.Blur()
	if i == 0 {
		f.typeSelect.Focus()
	} else {
		f.customInput.Focus()
	}
}
func (f *Icmpv6TypeField) Blur() { f.typeSelect.Blur(); f.customInput.Blur() }

func (f *Icmpv6TypeField) currentType() (uint8, bool) {
	if v := f.typeSelect.Value(); v != "" {
		return icmpv6TypeNameToCode[v], true
	}
	if s := strings.TrimSpace(f.customInput.Value()); s != "" {
		if n, err := strconv.ParseUint(s, 10, 8); err == nil {
			return uint8(n), true
		}
	}
	return 0, false
}

func (f *Icmpv6TypeField) Changed() bool {
	cur, set := f.currentType()
	if set != f.originalIsSet {
		return true
	}
	return set && cur != f.originalType
}

func (f *Icmpv6TypeField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.typeSelect.Focused {
		f.typeSelect, cmd = f.typeSelect.Update(msg)
	} else {
		f.customInput, cmd = f.customInput.Update(msg)
	}
	return cmd
}

func (f *Icmpv6TypeField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	cur, set := f.currentType()
	saveIcmpv6Match(rule, 0, 1, uint64(cur), set)
	if set {
		f.originalType = cur
		f.originalIsSet = true
	} else {
		f.originalType = 0
		f.originalIsSet = false
	}
}

func (f *Icmpv6TypeField) View() string {
	vSel := f.typeSelect.View()
	if f.Changed() {
		vSel = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vSel)
	}
	vCustom := f.customInput.View()
	row := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(30).Render(vSel),
		lipgloss.NewStyle().Width(6).Render(grayStyle.Render(i18n.T("rule.field.or"))),
		lipgloss.NewStyle().Render(vCustom),
	)
	return grayStyle.Render("ICMPv6 type") + "\n" + row + "\n"
}

// Icmpv6CodeField — uint8 NumberInput (code meaning is type-dependent).
type Icmpv6CodeField struct {
	valueInput    NumberInput
	originalValue uint8
	originalIsSet bool
}

func NewIcmpv6CodeField(rd *nft.Rule) *Icmpv6CodeField {
	valueInput := NewNumberInput(0, 255)
	valueInput.Placeholder = "0..255"
	valueInput.Width = 8
	valueInput.CharLimit = 3

	var orig uint8
	var origSet bool
	for _, c := range rd.Conditions {
		if c.Payload == nil ||
			c.Payload.Protocol != nft.PayloadProtoICMPv6 ||
			c.Payload.Field != "code" {
			continue
		}
		if v, ok := c.Payload.Value.(uint8); ok {
			orig = v
			origSet = true
			valueInput.SetValue(strconv.FormatUint(uint64(v), 10))
		}
	}
	return &Icmpv6CodeField{
		valueInput:    valueInput,
		originalValue: orig, originalIsSet: origSet,
	}
}

func (f *Icmpv6CodeField) FocusSlots() int { return 1 }
func (f *Icmpv6CodeField) Focus(_ int)     { f.valueInput.Focus() }
func (f *Icmpv6CodeField) Blur()           { f.valueInput.Blur() }

func (f *Icmpv6CodeField) currentValue() (uint8, bool) {
	s := strings.TrimSpace(f.valueInput.Value())
	if s == "" {
		return 0, false
	}
	if n, err := strconv.ParseUint(s, 10, 8); err == nil {
		return uint8(n), true
	}
	return 0, false
}

func (f *Icmpv6CodeField) Changed() bool {
	cur, set := f.currentValue()
	if set != f.originalIsSet {
		return true
	}
	return set && cur != f.originalValue
}

func (f *Icmpv6CodeField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.valueInput, cmd = f.valueInput.Update(msg)
	return cmd
}

func (f *Icmpv6CodeField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	cur, set := f.currentValue()
	saveIcmpv6Match(rule, 1, 1, uint64(cur), set)
	if set {
		f.originalValue = cur
		f.originalIsSet = true
	} else {
		f.originalValue = 0
		f.originalIsSet = false
	}
}

func (f *Icmpv6CodeField) View() string {
	v := f.valueInput.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	return grayStyle.Render("ICMPv6 code") + "\n" + v + "\n"
}

// saveIcmpv6Match — shared write-back for all icmpv6 header fields (any
// length 1/2/4). Inserts the meta-l4proto-icmpv6 prefix if missing.
func saveIcmpv6Match(rule *nftables.Rule, offset, length uint32, cur uint64, ok bool) {
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

	if !hasIcmpv6L4Match(rule) {
		rule.Exprs = append(icmpv6L4Wire(), rule.Exprs...)
	}

	data := make([]byte, length)
	switch length {
	case 1:
		data[0] = uint8(cur)
	case 2:
		binary.BigEndian.PutUint16(data, uint16(cur))
	case 4:
		binary.BigEndian.PutUint32(data, uint32(cur))
	}

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

// formatICMPv6 renders an icmpv6 payload condition.
func formatICMPv6(field string, value any) string {
	out := yellowBoldStyle.Render("icmpv6 "+field) + " "
	switch v := value.(type) {
	case uint8:
		if field == "type" {
			if name := icmpv6TypeCodeToName(v); name != "" {
				return out + name
			}
		}
		return out + fmt.Sprintf("%d", v)
	case uint16, uint32:
		return out + fmt.Sprintf("%v", v)
	}
	return out + fmt.Sprintf("%v", value)
}
