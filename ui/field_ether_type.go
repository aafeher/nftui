package ui

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"nftui/i18n"
	"nftui/nft"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// EtherType names accepted by `nft` (matched against the wire EtherType
// uint16). The set we expose covers everything `nft list` emits as a
// keyword; for anything else the user enters raw 0xNNNN in the "or:" box.
var etherTypeNames = []string{
	"",
	"ip",     // 0x0800
	"ip6",    // 0x86dd
	"arp",    // 0x0806
	"8021q",  // 0x8100 (VLAN tag)
	"8021ad", // 0x88a8 (Q-in-Q)
	"mpls",   // 0x8847 (MPLS unicast)
	"lldp",   // 0x88cc
}

var etherTypeNameToCode = map[string]uint16{
	"ip":     0x0800,
	"ip6":    0x86dd,
	"arp":    0x0806,
	"8021q":  0x8100,
	"8021ad": 0x88a8,
	"mpls":   0x8847,
	"lldp":   0x88cc,
}

func etherTypeCodeToName(c uint16) string {
	for n, code := range etherTypeNameToCode {
		if code == c {
			return n
		}
	}
	return ""
}

// EtherTypeField edits `ether type <name|0xNNNN>` — uint16 EtherType match
// at Payload{LL, offset=12, len=2}.
//
// Two sub-inputs: a Select for the known names + a hex/decimal text input
// for arbitrary values.
type EtherTypeField struct {
	typeSelect    Select
	customInput   textinput.Model
	originalType  uint16
	originalIsSet bool
}

func NewEtherTypeField(rd *nft.Rule) *EtherTypeField {
	typeSelect := NewSelect(etherTypeNames)
	typeSelect.Width = 10

	customInput := textinput.New()
	customInput.Placeholder = "0xNNNN or decimal"
	customInput.CharLimit = 8
	customInput.Width = 14

	var orig uint16
	var origSet bool
	for _, c := range rd.Conditions {
		if c.Payload == nil ||
			c.Payload.Protocol != nft.PayloadProtoEther ||
			c.Payload.Field != "type" {
			continue
		}
		if v, ok := c.Payload.Value.(uint16); ok {
			orig = v
			origSet = true
		}
	}
	if origSet {
		if name := etherTypeCodeToName(orig); name != "" {
			typeSelect.SetValue(name)
		} else {
			customInput.SetValue(fmt.Sprintf("0x%04x", orig))
		}
	}
	return &EtherTypeField{
		typeSelect: typeSelect, customInput: customInput,
		originalType: orig, originalIsSet: origSet,
	}
}

func (f *EtherTypeField) FocusSlots() int { return 2 }
func (f *EtherTypeField) Focus(i int) {
	f.Blur()
	if i == 0 {
		f.typeSelect.Focus()
	} else {
		f.customInput.Focus()
	}
}
func (f *EtherTypeField) Blur() { f.typeSelect.Blur(); f.customInput.Blur() }

// parseEtherTypeText handles both "0x88cc" and "34952" — returns a uint16.
func parseEtherTypeText(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base = 16
		s = s[2:]
	}
	n, err := strconv.ParseUint(s, base, 16)
	if err != nil {
		return 0, err
	}
	return uint16(n), nil
}

func (f *EtherTypeField) currentType() (uint16, bool) {
	if v := f.typeSelect.Value(); v != "" {
		return etherTypeNameToCode[v], true
	}
	if s := strings.TrimSpace(f.customInput.Value()); s != "" {
		if n, err := parseEtherTypeText(s); err == nil {
			return n, true
		}
	}
	return 0, false
}

func (f *EtherTypeField) Changed() bool {
	cur, set := f.currentType()
	if set != f.originalIsSet {
		return true
	}
	return set && cur != f.originalType
}

func (f *EtherTypeField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.typeSelect.Focused {
		f.typeSelect, cmd = f.typeSelect.Update(msg)
	} else {
		f.customInput, cmd = f.customInput.Update(msg)
	}
	return cmd
}

func (f *EtherTypeField) ValidateForSave() error {
	if !f.Changed() {
		return nil
	}
	if f.typeSelect.Value() != "" {
		return nil
	}
	s := strings.TrimSpace(f.customInput.Value())
	if s == "" {
		return nil // empty = delete the match
	}
	if _, err := parseEtherTypeText(s); err != nil {
		return fmt.Errorf("Ether type: %q is not a valid EtherType (use 0xNNNN or decimal): %v", s, err)
	}
	return nil
}

func (f *EtherTypeField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	cur, set := f.currentType()

	// Locate existing Payload{LL, 12, 2}.
	idx := -1
	for i, re := range rule.Exprs {
		p, ok := re.(*expr.Payload)
		if !ok || p.Base != expr.PayloadBaseLLHeader ||
			p.Offset != 12 || p.Len != 2 {
			continue
		}
		idx = i
		break
	}

	if !set {
		if idx >= 0 && idx+1 < len(rule.Exprs) {
			rule.Exprs = append(rule.Exprs[:idx], rule.Exprs[idx+2:]...)
		}
		f.originalType = 0
		f.originalIsSet = false
		return
	}

	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, cur)

	if idx >= 0 && idx+1 < len(rule.Exprs) {
		if cmp, ok := rule.Exprs[idx+1].(*expr.Cmp); ok {
			cmp.Op = expr.CmpOpEq
			cmp.Data = data
			f.originalType = cur
			f.originalIsSet = true
			return
		}
	}
	rule.Exprs = append(rule.Exprs,
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: 12, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
	)
	f.originalType = cur
	f.originalIsSet = true
}

func (f *EtherTypeField) View() string {
	vSel := f.typeSelect.View()
	if f.Changed() {
		vSel = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vSel)
	}
	vCustom := f.customInput.View()
	hint := ""
	if v, set := f.currentType(); set {
		hint = grayStyle.Render(fmt.Sprintf(" (0x%04x)", v))
	}
	row := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(14).Render(vSel),
		lipgloss.NewStyle().Width(6).Render(grayStyle.Render(i18n.T("rule.field.or"))),
		lipgloss.NewStyle().Render(vCustom),
		hint,
	)
	return grayStyle.Render("Ether type") + "\n" + row + "\n"
}
