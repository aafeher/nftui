package ui

import (
	"encoding/binary"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
)

// ArpField backs the 5 ARP header matches (RFC 826):
//
//	offset 0..2 : htype     (uint16 BE) — hardware type (1=Ethernet)
//	offset 2..4 : ptype     (uint16 BE) — protocol type (0x0800=IPv4)
//	offset 4..5 : hlen      (uint8)     — hardware address length (6 for MAC)
//	offset 5..6 : plen      (uint8)     — protocol address length (4 for IPv4)
//	offset 6..8 : operation (uint16 BE) — 1=request, 2=reply, 3..=other
//
// All five auto-inject an `ether type 0x0806` (ARP) prefix on Save —
// `nft` itself does this and the kernel requires the EtherType context to
// route the rule to the ARP layout. ARP matches only work in bridge / arp
// / netdev family tables.
type ArpField struct {
	label     string
	fieldName string
	offset    uint32
	length    uint32 // 1 or 2

	// Operation Select-mode: when non-nil, the editor offers a name Select
	// (request/reply/rrequest/rreply) in addition to numeric input.
	opNameSelect Select
	useOpSelect  bool

	valueInput    NumberInput
	originalValue uint64
	originalIsSet bool
}

var arpOperationNames = []string{
	"", "request", "reply", "rrequest", "rreply", "inrequest", "inreply", "nak",
}
var arpOperationNameToCode = map[string]uint16{
	"request":   1,
	"reply":     2,
	"rrequest":  3,
	"rreply":    4,
	"inrequest": 8,
	"inreply":   9,
	"nak":       10,
}

func arpOperationCodeToName(c uint16) string {
	for n, code := range arpOperationNameToCode {
		if code == c {
			return n
		}
	}
	return ""
}

func newArpField(rd *nft.Rule, label, fieldName string, offset, length uint32) *ArpField {
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
		valueInput.Width = 6
		valueInput.CharLimit = 3
	}

	useOpSelect := fieldName == "operation"
	var opSelect Select
	if useOpSelect {
		opSelect = NewSelect(arpOperationNames)
		opSelect.Width = 12
	}

	var orig uint64
	var origSet bool
	for _, c := range rd.Conditions {
		if c.Payload == nil ||
			c.Payload.Protocol != nft.PayloadProtoARP ||
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
	if origSet {
		if useOpSelect {
			if name := arpOperationCodeToName(uint16(orig)); name != "" {
				opSelect.SetValue(name)
			} else {
				valueInput.SetValue(strconv.FormatUint(orig, 10))
			}
		} else if orig > 0 {
			valueInput.SetValue(strconv.FormatUint(orig, 10))
		}
	}

	return &ArpField{
		label: label, fieldName: fieldName, offset: offset, length: length,
		opNameSelect: opSelect, useOpSelect: useOpSelect,
		valueInput: valueInput, originalValue: orig, originalIsSet: origSet,
	}
}

func (f *ArpField) FocusSlots() int {
	if f.useOpSelect {
		return 2
	}
	return 1
}
func (f *ArpField) Focus(i int) {
	f.Blur()
	if f.useOpSelect && i == 0 {
		f.opNameSelect.Focus()
	} else {
		f.valueInput.Focus()
	}
}
func (f *ArpField) Blur() {
	if f.useOpSelect {
		f.opNameSelect.Blur()
	}
	f.valueInput.Blur()
}

func (f *ArpField) currentValue() (uint64, bool) {
	if f.useOpSelect {
		if name := f.opNameSelect.Value(); name != "" {
			return uint64(arpOperationNameToCode[name]), true
		}
	}
	s := strings.TrimSpace(f.valueInput.Value())
	if s == "" {
		return 0, false
	}
	v, _ := f.valueInput.GetUint64()
	return v, true
}

func (f *ArpField) Changed() bool {
	cur, set := f.currentValue()
	if set != f.originalIsSet {
		return true
	}
	return set && cur != f.originalValue
}

func (f *ArpField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.useOpSelect && f.opNameSelect.Focused {
		f.opNameSelect, cmd = f.opNameSelect.Update(msg)
	} else {
		f.valueInput, cmd = f.valueInput.Update(msg)
	}
	return cmd
}

func (f *ArpField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	cur, set := f.currentValue()
	saveArpMatch(rule, f.offset, f.length, cur, set)
	if set {
		f.originalValue = cur
		f.originalIsSet = true
	} else {
		f.originalValue = 0
		f.originalIsSet = false
	}
}

func (f *ArpField) View() string {
	if f.useOpSelect {
		vSel := f.opNameSelect.View()
		if f.Changed() {
			vSel = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vSel)
		}
		vCustom := f.valueInput.View()
		row := lipgloss.JoinHorizontal(lipgloss.Top,
			lipgloss.NewStyle().Width(14).Render(vSel),
			lipgloss.NewStyle().Width(6).Render(grayStyle.Render("or:")),
			lipgloss.NewStyle().Render(vCustom),
		)
		return grayStyle.Render(f.label) + "\n" + row + "\n"
	}
	v := f.valueInput.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	return grayStyle.Render(f.label) + "\n" + v + "\n"
}

// hasEtherTypeARP — is `ether type 0x0806` already in the rule?
func hasEtherTypeARP(rule *nftables.Rule) bool {
	for i := 0; i+1 < len(rule.Exprs); i++ {
		p, ok := rule.Exprs[i].(*expr.Payload)
		if !ok || p.Base != expr.PayloadBaseLLHeader || p.Offset != 12 || p.Len != 2 {
			continue
		}
		c, ok := rule.Exprs[i+1].(*expr.Cmp)
		if !ok || c.Op != expr.CmpOpEq || len(c.Data) != 2 {
			continue
		}
		if c.Data[0] == 0x08 && c.Data[1] == 0x06 {
			return true
		}
	}
	return false
}

// saveArpMatch — Payload{NETWORK, offset, length} + Cmp{Eq, encoded}.
// Auto-injects `ether type 0x0806` (ARP) prefix if missing.
func saveArpMatch(rule *nftables.Rule, offset, length uint32, cur uint64, ok bool) {
	// Locate existing Payload{NETWORK, offset, length}.
	idx := -1
	for i, re := range rule.Exprs {
		p, isP := re.(*expr.Payload)
		if !isP || p.Base != expr.PayloadBaseNetworkHeader ||
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

	if !hasEtherTypeARP(rule) {
		rule.Exprs = append([]expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: 12, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x08, 0x06}},
		}, rule.Exprs...)
	}

	data := make([]byte, length)
	switch length {
	case 1:
		data[0] = byte(cur)
	case 2:
		binary.BigEndian.PutUint16(data, uint16(cur))
	}

	idx = -1
	for i, re := range rule.Exprs {
		p, isP := re.(*expr.Payload)
		if !isP || p.Base != expr.PayloadBaseNetworkHeader ||
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
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: length},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
	)
}

// Concrete factories.

func NewArpHtypeField(rd *nft.Rule) *ArpField {
	return newArpField(rd, "ARP htype", "htype", 0, 2)
}
func NewArpPtypeField(rd *nft.Rule) *ArpField {
	return newArpField(rd, "ARP ptype", "ptype", 2, 2)
}
func NewArpHlenField(rd *nft.Rule) *ArpField {
	return newArpField(rd, "ARP hlen", "hlen", 4, 1)
}
func NewArpPlenField(rd *nft.Rule) *ArpField {
	return newArpField(rd, "ARP plen", "plen", 5, 1)
}
func NewArpOperationField(rd *nft.Rule) *ArpField {
	return newArpField(rd, "ARP operation", "operation", 6, 2)
}
