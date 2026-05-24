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

// VlanField backs the three VLAN tag matches:
//
//   - `id`  (12-bit) : Payload{LL, 14, 2} + Bitwise{[0x0f, 0xff]} + Cmp
//     encoded = [v>>8 & 0x0f, v & 0xff]
//   - `cfi` (1-bit)  : Payload{LL, 14, 1} + Bitwise{[0x10]} + Cmp
//     encoded = [(v & 1) << 4]
//   - `pcp` (3-bit)  : Payload{LL, 14, 1} + Bitwise{[0xe0]} + Cmp
//     encoded = [(v & 7) << 5]
//
// All three require an `ether type 8021q` (0x8100) match prefix on the
// wire. Save auto-injects that if missing — see saveVlanMatch.
type VlanField struct {
	label     string
	fieldName string
	// shape: 1 = id (12-bit, len 2), 2 = cfi (1-bit), 3 = pcp (3-bit)
	shape int

	valueInput    NumberInput
	originalValue uint64
	originalIsSet bool
}

func newVlanField(rd *nft.Rule, label, fieldName string, shape int, maxVal int) *VlanField {
	valueInput := NewNumberInput(0, maxVal)
	valueInput.Placeholder = "0"
	valueInput.Width = 8
	if maxVal >= 4096 {
		valueInput.Width = 10
		valueInput.CharLimit = 5
	} else {
		valueInput.CharLimit = 2
	}

	var orig uint64
	var origSet bool
	for _, c := range rd.Conditions {
		if c.Payload == nil ||
			c.Payload.Protocol != nft.PayloadProtoVlan ||
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
	return &VlanField{
		label: label, fieldName: fieldName, shape: shape,
		valueInput: valueInput, originalValue: orig, originalIsSet: origSet,
	}
}

func (f *VlanField) FocusSlots() int { return 1 }
func (f *VlanField) Focus(_ int)     { f.valueInput.Focus() }
func (f *VlanField) Blur()           { f.valueInput.Blur() }

func (f *VlanField) currentValue() (uint64, bool) {
	s := strings.TrimSpace(f.valueInput.Value())
	if s == "" {
		return 0, false
	}
	v, _ := f.valueInput.GetUint64()
	return v, true
}

func (f *VlanField) Changed() bool {
	cur, set := f.currentValue()
	if set != f.originalIsSet {
		return true
	}
	return set && cur != f.originalValue
}

func (f *VlanField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.valueInput, cmd = f.valueInput.Update(msg)
	return cmd
}

func (f *VlanField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	cur, set := f.currentValue()
	saveVlanMatch(rule, f.shape, cur, set)
	if set {
		f.originalValue = cur
		f.originalIsSet = true
	} else {
		f.originalValue = 0
		f.originalIsSet = false
	}
}

func (f *VlanField) View() string {
	v := f.valueInput.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	return grayStyle.Render(f.label) + "\n" + v + "\n"
}

// hasEtherType8021q reports whether the rule already starts with the
// `ether type 8021q` (0x8100) match required to anchor VLAN tag fields.
func hasEtherType8021q(rule *nftables.Rule) bool {
	for i := 0; i+1 < len(rule.Exprs); i++ {
		p, ok := rule.Exprs[i].(*expr.Payload)
		if !ok || p.Base != expr.PayloadBaseLLHeader || p.Offset != 12 || p.Len != 2 {
			continue
		}
		c, ok := rule.Exprs[i+1].(*expr.Cmp)
		if !ok || c.Op != expr.CmpOpEq || len(c.Data) != 2 {
			continue
		}
		// 0x8100 BE on the wire.
		if c.Data[0] == 0x81 && c.Data[1] == 0x00 {
			return true
		}
	}
	return false
}

// vlanShape returns the wire parameters of a given VLAN field.
//
//	(payloadLen, mask, encoder, expected-data-len)
func vlanShape(shape int, value uint64) (length uint32, mask []byte, encoded []byte) {
	switch shape {
	case 1: // id (12-bit)
		length = 2
		mask = []byte{0x0f, 0xff}
		encoded = make([]byte, 2)
		binary.BigEndian.PutUint16(encoded, uint16(value)&0x0fff)
	case 2: // cfi (1-bit, bit 4)
		length = 1
		mask = []byte{0x10}
		encoded = []byte{byte((value & 1) << 4)}
	case 3: // pcp (3-bit, bits 5..7)
		length = 1
		mask = []byte{0xe0}
		encoded = []byte{byte((value & 7) << 5)}
	}
	return
}

func saveVlanMatch(rule *nftables.Rule, shape int, value uint64, ok bool) {
	length, mask, encoded := vlanShape(shape, value)

	// Locate an existing Payload{LL, 14, length} with the matching Bitwise mask.
	idx := -1
	for i, re := range rule.Exprs {
		p, isP := re.(*expr.Payload)
		if !isP || p.Base != expr.PayloadBaseLLHeader ||
			p.Offset != 14 || p.Len != length {
			continue
		}
		if i+2 >= len(rule.Exprs) {
			continue
		}
		bw, isBW := rule.Exprs[i+1].(*expr.Bitwise)
		if !isBW || len(bw.Mask) != len(mask) {
			continue
		}
		matches := true
		for j := range mask {
			if bw.Mask[j] != mask[j] {
				matches = false
				break
			}
		}
		if !matches {
			continue
		}
		idx = i
		break
	}

	if !ok {
		if idx >= 0 && idx+2 < len(rule.Exprs) {
			rule.Exprs = append(rule.Exprs[:idx], rule.Exprs[idx+3:]...)
		}
		return
	}

	// Ensure the `ether type 8021q` (0x8100) prefix exists.
	if !hasEtherType8021q(rule) {
		etherTypeData := []byte{0x81, 0x00}
		rule.Exprs = append([]expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: 12, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: etherTypeData},
		}, rule.Exprs...)
	}

	// Re-locate after potential prefix insertion.
	idx = -1
	for i, re := range rule.Exprs {
		p, isP := re.(*expr.Payload)
		if !isP || p.Base != expr.PayloadBaseLLHeader ||
			p.Offset != 14 || p.Len != length {
			continue
		}
		if i+2 >= len(rule.Exprs) {
			continue
		}
		bw, isBW := rule.Exprs[i+1].(*expr.Bitwise)
		if !isBW || len(bw.Mask) != len(mask) {
			continue
		}
		matches := true
		for j := range mask {
			if bw.Mask[j] != mask[j] {
				matches = false
				break
			}
		}
		if !matches {
			continue
		}
		idx = i
		break
	}
	if idx >= 0 && idx+2 < len(rule.Exprs) {
		if cmp, ok := rule.Exprs[idx+2].(*expr.Cmp); ok {
			cmp.Op = expr.CmpOpEq
			cmp.Data = encoded
			return
		}
	}
	// Append a fresh triple.
	rule.Exprs = append(rule.Exprs,
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: 14, Len: length},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: length, Mask: mask, Xor: make([]byte, length)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: encoded},
	)
}

// Concrete factories.

func NewVlanIdField(rd *nft.Rule) *VlanField {
	return newVlanField(rd, "VLAN id", "id", 1, 4095)
}
func NewVlanCfiField(rd *nft.Rule) *VlanField {
	return newVlanField(rd, "VLAN cfi", "cfi", 2, 1)
}
func NewVlanPcpField(rd *nft.Rule) *VlanField {
	return newVlanField(rd, "VLAN pcp", "pcp", 3, 7)
}
