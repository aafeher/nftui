package ui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
)

// IP6 dscp / flowlabel are bit-packed across multiple bytes of the IPv6
// header. They need their own multi-byte Bitwise+Cmp encoding — the
// single-byte IPBitwiseField shape doesn't fit. Each editor below pins the
// payload offset/length/mask and the per-field encode/decode routines.

// IP6DscpField edits `ip6 dscp <value>` (6-bit DSCP code-point, value 0..63).
//
// Wire shape:
//
//	Payload{offset=0, len=2} + Bitwise{mask=[0x0f, 0xc0], xor=[0,0]} + Cmp
//	byte 0 = (dscp >> 2) & 0x0f
//	byte 1 = (dscp & 0x03) << 6
type IP6DscpField struct {
	opInput       Select
	valueInput    NumberInput
	originalOp    nft.CompareOp
	originalValue uint64
}

func NewIP6DscpField(rd *nft.Rule) *IP6DscpField {
	opInput := NewSelect([]string{"==", "!=", "<", "<=", ">", ">="})
	opInput.Width = 6
	valueInput := NewNumberInput(0, 63)
	valueInput.Placeholder = "0"
	valueInput.Width = 8
	valueInput.CharLimit = 3

	var originalOp nft.CompareOp = nft.CompareOpEq
	var originalValue uint64
	for _, c := range rd.Conditions {
		if c.Payload == nil || c.Payload.Protocol != nft.PayloadProtoIP6 || c.Payload.Field != "dscp" {
			continue
		}
		if v, ok := c.Payload.Value.(uint8); ok {
			originalValue = uint64(v)
		}
		originalOp = c.Operation
	}
	opInput.SetValue(string(originalOp))
	if originalValue > 0 {
		valueInput.SetValue(strconv.FormatUint(originalValue, 10))
	}
	return &IP6DscpField{
		opInput: opInput, valueInput: valueInput,
		originalOp: originalOp, originalValue: originalValue,
	}
}

func (f *IP6DscpField) FocusSlots() int { return 2 }
func (f *IP6DscpField) Focus(i int) {
	if i == 0 {
		f.opInput.Focus()
		f.valueInput.Blur()
	} else {
		f.opInput.Blur()
		f.valueInput.Focus()
	}
}
func (f *IP6DscpField) Blur() { f.opInput.Blur(); f.valueInput.Blur() }
func (f *IP6DscpField) currentValue() uint64 {
	v, _ := f.valueInput.GetUint64()
	return v
}
func (f *IP6DscpField) Changed() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp ||
		f.currentValue() != f.originalValue
}
func (f *IP6DscpField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.opInput.Focused {
		f.opInput, cmd = f.opInput.Update(msg)
	} else if f.valueInput.Focused() {
		f.valueInput, cmd = f.valueInput.Update(msg)
	}
	return cmd
}
func (f *IP6DscpField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	cleared := strings.TrimSpace(f.valueInput.Value()) == ""
	dscp := byte(f.currentValue())
	newOp := compareOpToExprCmpOp(nft.CompareOp(f.opInput.Value()))

	// Encode: split the 6-bit dscp across two bytes.
	encoded := []byte{(dscp >> 2) & 0x0f, (dscp & 0x03) << 6}
	mask := []byte{0x0f, 0xc0}

	for i, re := range rule.Exprs {
		p, ok := re.(*expr.Payload)
		if !ok || p.Base != expr.PayloadBaseNetworkHeader || p.Offset != 0 || p.Len != 2 {
			continue
		}
		if i+2 >= len(rule.Exprs) {
			break
		}
		bw, ok := rule.Exprs[i+1].(*expr.Bitwise)
		if !ok || len(bw.Mask) != 2 || bw.Mask[0] != 0x0f || bw.Mask[1] != 0xc0 {
			break
		}
		cmp, ok := rule.Exprs[i+2].(*expr.Cmp)
		if !ok {
			break
		}
		if cleared {
			rule.Exprs = append(rule.Exprs[:i], rule.Exprs[i+3:]...)
		} else {
			cmp.Op = newOp
			cmp.Data = encoded
		}
		f.originalOp = nft.CompareOp(f.opInput.Value())
		f.originalValue = uint64(dscp)
		return
	}

	if cleared {
		f.originalValue = 0
		return
	}
	rule.Exprs = append(rule.Exprs,
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 0, Len: 2},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 2, Mask: mask, Xor: []byte{0, 0}},
		&expr.Cmp{Op: newOp, Register: 1, Data: encoded},
	)
	f.originalOp = nft.CompareOp(f.opInput.Value())
	f.originalValue = uint64(dscp)
}
func (f *IP6DscpField) View() string {
	vOp := f.opInput.View()
	if nft.CompareOp(f.opInput.Value()) != f.originalOp {
		vOp = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vOp)
	}
	vVal := f.valueInput.View()
	if f.currentValue() != f.originalValue {
		vVal = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vVal)
	}
	hint := ""
	if v, err := f.valueInput.GetUint64(); err == nil && v > 0 {
		hint = grayStyle.Render(fmt.Sprintf(" (raw 0x%02x)", uint8(v)))
	}
	inputs := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(8).Render(vOp),
		lipgloss.NewStyle().Width(10).Render(vVal),
		hint,
	)
	return grayStyle.Render("IP6 dscp") + "\n" + inputs + "\n"
}

// IP6FlowlabelField edits `ip6 flowlabel <value>` (20-bit flow label).
//
// Wire shape:
//
//	Payload{offset=1, len=3} + Bitwise{mask=[0x0f, 0xff, 0xff], xor=[0,0,0]} + Cmp
//	byte 0 = (fl >> 16) & 0x0f
//	byte 1 = (fl >> 8) & 0xff
//	byte 2 = fl & 0xff
type IP6FlowlabelField struct {
	opInput       Select
	valueInput    NumberInput
	originalOp    nft.CompareOp
	originalValue uint64
}

func NewIP6FlowlabelField(rd *nft.Rule) *IP6FlowlabelField {
	opInput := NewSelect([]string{"==", "!=", "<", "<=", ">", ">="})
	opInput.Width = 6
	valueInput := NewNumberInput(0, 0xfffff) // 20-bit
	valueInput.Placeholder = "0"
	valueInput.Width = 12
	valueInput.CharLimit = 7

	var originalOp nft.CompareOp = nft.CompareOpEq
	var originalValue uint64
	for _, c := range rd.Conditions {
		if c.Payload == nil || c.Payload.Protocol != nft.PayloadProtoIP6 || c.Payload.Field != "flowlabel" {
			continue
		}
		if v, ok := c.Payload.Value.(uint32); ok {
			originalValue = uint64(v)
		}
		originalOp = c.Operation
	}
	opInput.SetValue(string(originalOp))
	if originalValue > 0 {
		valueInput.SetValue(strconv.FormatUint(originalValue, 10))
	}
	return &IP6FlowlabelField{
		opInput: opInput, valueInput: valueInput,
		originalOp: originalOp, originalValue: originalValue,
	}
}

func (f *IP6FlowlabelField) FocusSlots() int { return 2 }
func (f *IP6FlowlabelField) Focus(i int) {
	if i == 0 {
		f.opInput.Focus()
		f.valueInput.Blur()
	} else {
		f.opInput.Blur()
		f.valueInput.Focus()
	}
}
func (f *IP6FlowlabelField) Blur() { f.opInput.Blur(); f.valueInput.Blur() }
func (f *IP6FlowlabelField) currentValue() uint64 {
	v, _ := f.valueInput.GetUint64()
	return v
}
func (f *IP6FlowlabelField) Changed() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp ||
		f.currentValue() != f.originalValue
}
func (f *IP6FlowlabelField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.opInput.Focused {
		f.opInput, cmd = f.opInput.Update(msg)
	} else if f.valueInput.Focused() {
		f.valueInput, cmd = f.valueInput.Update(msg)
	}
	return cmd
}
func (f *IP6FlowlabelField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	cleared := strings.TrimSpace(f.valueInput.Value()) == ""
	fl := uint32(f.currentValue())
	newOp := compareOpToExprCmpOp(nft.CompareOp(f.opInput.Value()))

	encoded := []byte{
		byte((fl >> 16) & 0x0f),
		byte((fl >> 8) & 0xff),
		byte(fl & 0xff),
	}
	mask := []byte{0x0f, 0xff, 0xff}

	for i, re := range rule.Exprs {
		p, ok := re.(*expr.Payload)
		if !ok || p.Base != expr.PayloadBaseNetworkHeader || p.Offset != 1 || p.Len != 3 {
			continue
		}
		if i+2 >= len(rule.Exprs) {
			break
		}
		bw, ok := rule.Exprs[i+1].(*expr.Bitwise)
		if !ok || len(bw.Mask) != 3 ||
			bw.Mask[0] != 0x0f || bw.Mask[1] != 0xff || bw.Mask[2] != 0xff {
			break
		}
		cmp, ok := rule.Exprs[i+2].(*expr.Cmp)
		if !ok {
			break
		}
		if cleared {
			rule.Exprs = append(rule.Exprs[:i], rule.Exprs[i+3:]...)
		} else {
			cmp.Op = newOp
			cmp.Data = encoded
		}
		f.originalOp = nft.CompareOp(f.opInput.Value())
		f.originalValue = uint64(fl)
		return
	}

	if cleared {
		f.originalValue = 0
		return
	}
	rule.Exprs = append(rule.Exprs,
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 1, Len: 3},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 3, Mask: mask, Xor: []byte{0, 0, 0}},
		&expr.Cmp{Op: newOp, Register: 1, Data: encoded},
	)
	f.originalOp = nft.CompareOp(f.opInput.Value())
	f.originalValue = uint64(fl)
}
func (f *IP6FlowlabelField) View() string {
	vOp := f.opInput.View()
	if nft.CompareOp(f.opInput.Value()) != f.originalOp {
		vOp = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vOp)
	}
	vVal := f.valueInput.View()
	if f.currentValue() != f.originalValue {
		vVal = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vVal)
	}
	hint := ""
	if v, err := f.valueInput.GetUint64(); err == nil && v > 0 {
		hint = grayStyle.Render(fmt.Sprintf(" (0x%05x)", uint32(v)))
	}
	inputs := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(8).Render(vOp),
		lipgloss.NewStyle().Width(14).Render(vVal),
		hint,
	)
	return grayStyle.Render("IP6 flowlabel") + "\n" + inputs + "\n"
}
