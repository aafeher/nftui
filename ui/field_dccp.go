package ui

import (
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"nftui/nft"
)

// DCCP sport/dport — uint16, same shape as the SCTP port editors but with
// the DCCP l4proto prefix.
type DccpPortField struct {
	label         string
	fieldName     string
	offset        uint32
	valueInput    NumberInput
	originalValue uint64
	originalIsSet bool
}

func newDccpPortField(rd *nft.Rule, label, fieldName string, offset uint32) *DccpPortField {
	valueInput := NewNumberInput(0, 0xffff)
	valueInput.Placeholder = "0"
	valueInput.Width = 10
	valueInput.CharLimit = 5

	var orig uint64
	var origSet bool
	for _, c := range rd.Conditions {
		if c.Payload == nil ||
			c.Payload.Protocol != nft.PayloadProtoDCCP ||
			c.Payload.Field != fieldName {
			continue
		}
		switch v := c.Payload.Value.(type) {
		case uint16:
			orig = uint64(v)
		case *nft.PortSpec:
			orig = uint64(v.Port)
		}
		origSet = true
	}
	if origSet && orig > 0 {
		valueInput.SetValue(strconv.FormatUint(orig, 10))
	}
	return &DccpPortField{
		label: label, fieldName: fieldName, offset: offset,
		valueInput: valueInput, originalValue: orig, originalIsSet: origSet,
	}
}

func (f *DccpPortField) FocusSlots() int { return 1 }
func (f *DccpPortField) Focus(_ int)     { f.valueInput.Focus() }
func (f *DccpPortField) Blur()           { f.valueInput.Blur() }

func (f *DccpPortField) currentValue() (uint64, bool) {
	s := strings.TrimSpace(f.valueInput.Value())
	if s == "" {
		return 0, false
	}
	v, _ := f.valueInput.GetUint64()
	return v, true
}

func (f *DccpPortField) Changed() bool {
	cur, set := f.currentValue()
	if set != f.originalIsSet {
		return true
	}
	return set && cur != f.originalValue
}

func (f *DccpPortField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.valueInput, cmd = f.valueInput.Update(msg)
	return cmd
}

func (f *DccpPortField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	cur, set := f.currentValue()
	saveL4ProtoMatch(rule, unix.IPPROTO_DCCP, f.offset, 2, cur, set)
	if set {
		f.originalValue = cur
		f.originalIsSet = true
	} else {
		f.originalValue = 0
		f.originalIsSet = false
	}
}

func (f *DccpPortField) View() string {
	v := f.valueInput.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	return grayStyle.Render(f.label) + "\n" + v + "\n"
}

func NewDccpSportField(rd *nft.Rule) *DccpPortField {
	return newDccpPortField(rd, "DCCP sport", "sport", 0)
}
func NewDccpDportField(rd *nft.Rule) *DccpPortField {
	return newDccpPortField(rd, "DCCP dport", "dport", 2)
}

// DccpTypeField edits `dccp type <name|N>`. Wire pattern is Payload{8, 1}
// + Bitwise{mask=0x1e, xor=0} + Cmp{Eq, [type<<1]}: the 4-bit DCCP type
// sits in byte 8 bits 1..4, so the value is shifted left by 1.

var dccpTypeNames = []string{
	"", "request", "response", "data", "ack", "dataack",
	"closereq", "close", "reset", "sync", "syncack",
}
var dccpTypeNameToCode = map[string]uint8{
	"request":  0,
	"response": 1,
	"data":     2,
	"ack":      3,
	"dataack":  4,
	"closereq": 5,
	"close":    6,
	"reset":    7,
	"sync":     8,
	"syncack":  9,
}

func dccpTypeCodeToName(c uint8) string {
	for n, code := range dccpTypeNameToCode {
		if code == c {
			return n
		}
	}
	return ""
}

type DccpTypeField struct {
	typeSelect    Select
	customInput   NumberInput
	originalType  uint8
	originalIsSet bool
}

func NewDccpTypeField(rd *nft.Rule) *DccpTypeField {
	typeSelect := NewSelect(dccpTypeNames)
	typeSelect.Width = 14

	customInput := NewNumberInput(0, 15)
	customInput.Placeholder = "0..15"
	customInput.Width = 10
	customInput.CharLimit = 2

	var orig uint8
	var origSet bool
	for _, c := range rd.Conditions {
		if c.Payload == nil ||
			c.Payload.Protocol != nft.PayloadProtoDCCP ||
			c.Payload.Field != "type" {
			continue
		}
		if v, ok := c.Payload.Value.(uint8); ok {
			orig = v
			origSet = true
		}
	}
	if origSet {
		if name := dccpTypeCodeToName(orig); name != "" {
			typeSelect.SetValue(name)
		} else {
			customInput.SetValue(strconv.FormatUint(uint64(orig), 10))
		}
	}
	return &DccpTypeField{
		typeSelect: typeSelect, customInput: customInput,
		originalType: orig, originalIsSet: origSet,
	}
}

func (f *DccpTypeField) FocusSlots() int { return 2 }
func (f *DccpTypeField) Focus(i int) {
	f.Blur()
	if i == 0 {
		f.typeSelect.Focus()
	} else {
		f.customInput.Focus()
	}
}
func (f *DccpTypeField) Blur() { f.typeSelect.Blur(); f.customInput.Blur() }

func (f *DccpTypeField) currentType() (uint8, bool) {
	if v := f.typeSelect.Value(); v != "" {
		return dccpTypeNameToCode[v], true
	}
	if s := strings.TrimSpace(f.customInput.Value()); s != "" {
		if n, err := strconv.ParseUint(s, 10, 8); err == nil {
			return uint8(n), true
		}
	}
	return 0, false
}

func (f *DccpTypeField) Changed() bool {
	cur, set := f.currentType()
	if set != f.originalIsSet {
		return true
	}
	return set && cur != f.originalType
}

func (f *DccpTypeField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.typeSelect.Focused {
		f.typeSelect, cmd = f.typeSelect.Update(msg)
	} else {
		f.customInput, cmd = f.customInput.Update(msg)
	}
	return cmd
}

func (f *DccpTypeField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	cur, set := f.currentType()
	saveDccpTypeMatch(rule, cur, set)
	if set {
		f.originalType = cur
		f.originalIsSet = true
	} else {
		f.originalType = 0
		f.originalIsSet = false
	}
}

func (f *DccpTypeField) View() string {
	vSel := f.typeSelect.View()
	if f.Changed() {
		vSel = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vSel)
	}
	vCustom := f.customInput.View()
	row := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(18).Render(vSel),
		lipgloss.NewStyle().Width(6).Render(grayStyle.Render("or:")),
		lipgloss.NewStyle().Render(vCustom),
	)
	return grayStyle.Render("DCCP type") + "\n" + row + "\n"
}

// saveDccpTypeMatch — Payload{8, 1} + Bitwise{0x1e, xor=0} + Cmp{type<<1}.
// Inserts the meta-l4proto-dccp prefix if missing.
func saveDccpTypeMatch(rule *nftables.Rule, typeCode uint8, ok bool) {
	const offset = uint32(8)
	const length = uint32(1)

	// Locate existing Payload{8, 1}.
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
		// Remove Payload + Bitwise + Cmp.
		if idx >= 0 && idx+2 < len(rule.Exprs) {
			rule.Exprs = append(rule.Exprs[:idx], rule.Exprs[idx+3:]...)
		}
		return
	}

	if !hasL4ProtoMatch(rule, unix.IPPROTO_DCCP) {
		rule.Exprs = append([]expr.Any{
			&expr.Meta{Key: unix.NFT_META_L4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_DCCP}},
		}, rule.Exprs...)
	}

	encoded := []byte{(typeCode & 0x0f) << 1}

	// Re-locate after possible prefix insertion.
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
	if idx >= 0 && idx+2 < len(rule.Exprs) {
		if _, ok := rule.Exprs[idx+1].(*expr.Bitwise); ok {
			if cmp, ok := rule.Exprs[idx+2].(*expr.Cmp); ok {
				cmp.Op = expr.CmpOpEq
				cmp.Data = encoded
				return
			}
		}
	}
	// Append a fresh triple.
	rule.Exprs = append(rule.Exprs,
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: length},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0x1e}, Xor: []byte{0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: encoded},
	)
}
