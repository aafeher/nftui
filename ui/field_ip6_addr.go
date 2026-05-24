package ui

import (
	"net"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
)

// IP6AddrField edits an `ip6 saddr` or `ip6 daddr` condition. Backs both
// directions via stored offset (8 for saddr, 24 for daddr) and label.
//
// CIDR input ("fe80::/10") emits a Payload+Bitwise+Cmp triple with a 16-byte
// mask. Single-address ("fe80::1") emits a Payload+Cmp pair.
type IP6AddrField struct {
	offset uint32 // 8 = saddr, 24 = daddr
	field  string // "saddr" or "daddr"
	label  string

	opInput Select
	input   textinput.Model

	originalOp nft.CompareOp
	original   string
}

func NewIP6SaddrField(rd *nft.Rule) *IP6AddrField {
	return newIP6AddrField(rd, 8, "saddr", "IP6 src")
}
func NewIP6DaddrField(rd *nft.Rule) *IP6AddrField {
	return newIP6AddrField(rd, 24, "daddr", "IP6 dst")
}

func newIP6AddrField(rd *nft.Rule, offset uint32, field, label string) *IP6AddrField {
	opInput := NewSelect(ipAddrOpOptions)
	opInput.Width = 6

	input := textinput.New()
	input.Placeholder = "e.g. fe80::1 or 2001:db8::/32"
	input.CharLimit = 43
	input.Width = 30

	original := extractIP6AddrString(rd, field)
	originalOp := extractIP6AddrOp(rd, field)
	opInput.SetValue(string(originalOp))
	input.SetValue(original)

	return &IP6AddrField{
		offset:     offset,
		field:      field,
		label:      label,
		opInput:    opInput,
		input:      input,
		originalOp: originalOp,
		original:   original,
	}
}

func (f *IP6AddrField) FocusSlots() int { return 2 }

func (f *IP6AddrField) Focus(subIndex int) {
	if subIndex == 0 {
		f.opInput.Focus()
	} else {
		f.input.Focus()
	}
}

func (f *IP6AddrField) Blur() {
	f.opInput.Blur()
	f.input.Blur()
}

func (f *IP6AddrField) opChanged() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp
}

func (f *IP6AddrField) ipChanged() bool {
	return f.input.Value() != f.original
}

func (f *IP6AddrField) Changed() bool {
	return f.opChanged() || f.ipChanged()
}

func (f *IP6AddrField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.opInput.Focused {
		f.opInput, cmd = f.opInput.Update(msg)
	} else if f.input.Focused() {
		f.input, cmd = f.input.Update(msg)
	}
	return cmd
}

func (f *IP6AddrField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	newOp := compareOpToExprCmpOp(nft.CompareOp(f.opInput.Value()))
	applyIP6AddrSave(rule, f.offset, f.input.Value(), newOp)
	f.original = f.input.Value()
	f.originalOp = nft.CompareOp(f.opInput.Value())
}

func (f *IP6AddrField) View() string {
	vOp := f.opInput.View()
	if f.opChanged() {
		vOp = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vOp)
	}
	vIP := f.input.View()
	if f.ipChanged() {
		vIP = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vIP)
	}
	inputs := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(10).Render(vOp),
		lipgloss.NewStyle().Render(vIP),
	)
	return grayStyle.Render(f.label) + "\n" + inputs + "\n"
}

func extractIP6AddrOp(rd *nft.Rule, field string) nft.CompareOp {
	for _, cond := range rd.Conditions {
		if cond.Payload == nil {
			continue
		}
		if cond.Payload.Protocol != nft.PayloadProtoIP6 || cond.Payload.Field != field {
			continue
		}
		return cond.Operation
	}
	return nft.CompareOpEq
}

func extractIP6AddrString(rd *nft.Rule, field string) string {
	for _, cond := range rd.Conditions {
		if cond.Payload == nil {
			continue
		}
		if cond.Payload.Protocol != nft.PayloadProtoIP6 || cond.Payload.Field != field {
			continue
		}
		switch v := cond.Payload.Value.(type) {
		case *nft.IPAddress:
			if v.Subnet != nil {
				return v.Subnet.String()
			}
			return v.IP.String()
		}
	}
	return ""
}

// applyIP6AddrSave mirrors applyIPAddrSave for the IPv6 payload offsets
// (8 = saddr, 24 = daddr) with 16-byte values and 128-bit CIDR masks.
func applyIP6AddrSave(rule *nftables.Rule, payloadOffset uint32, newVal string, newOp expr.CmpOp) {
	if newVal == "" {
		return
	}
	var newIP net.IP
	var newMask net.IPMask
	isCIDR := false

	if _, ipnet, err := net.ParseCIDR(newVal); err == nil {
		newIP = ipnet.IP.To16()
		newMask = ipnet.Mask
		isCIDR = true
	} else if ip := net.ParseIP(newVal); ip != nil {
		newIP = ip.To16()
	}
	if newIP == nil {
		return
	}

	for i, re := range rule.Exprs {
		p, ok := re.(*expr.Payload)
		if !ok || p.Base != expr.PayloadBaseNetworkHeader || p.Offset != payloadOffset || p.Len != 16 {
			continue
		}
		reg := p.DestRegister
		if i+1 >= len(rule.Exprs) {
			return
		}
		switch next := rule.Exprs[i+1].(type) {
		case *expr.Cmp:
			if isCIDR {
				bw := &expr.Bitwise{
					SourceRegister: reg,
					DestRegister:   reg,
					Len:            16,
					Mask:           append([]byte{}, []byte(newMask)...),
					Xor:            make([]byte, 16),
				}
				newExprs := make([]expr.Any, 0, len(rule.Exprs)+1)
				newExprs = append(newExprs, rule.Exprs[:i+1]...)
				newExprs = append(newExprs, bw)
				newExprs = append(newExprs, rule.Exprs[i+1:]...)
				rule.Exprs = newExprs
				cmp := rule.Exprs[i+2].(*expr.Cmp)
				cmp.Data = []byte(newIP)
				cmp.Op = newOp
			} else {
				next.Data = []byte(newIP)
				next.Op = newOp
			}
		case *expr.Bitwise:
			if i+2 >= len(rule.Exprs) {
				return
			}
			cmp, ok := rule.Exprs[i+2].(*expr.Cmp)
			if !ok {
				return
			}
			if isCIDR {
				next.Mask = append([]byte{}, []byte(newMask)...)
				cmp.Data = []byte(newIP)
				cmp.Op = newOp
			} else {
				newExprs := make([]expr.Any, 0, len(rule.Exprs)-1)
				newExprs = append(newExprs, rule.Exprs[:i+1]...)
				newExprs = append(newExprs, rule.Exprs[i+2:]...)
				rule.Exprs = newExprs
				c := rule.Exprs[i+1].(*expr.Cmp)
				c.Data = []byte(newIP)
				c.Op = newOp
			}
		}
		return
	}

	payloadExpr := &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       payloadOffset,
		Len:          16,
	}
	var newHead []expr.Any
	if isCIDR {
		bw := &expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            16,
			Mask:           append([]byte{}, []byte(newMask)...),
			Xor:            make([]byte, 16),
		}
		newHead = []expr.Any{payloadExpr, bw, &expr.Cmp{Op: newOp, Register: 1, Data: []byte(newIP)}}
	} else {
		newHead = []expr.Any{payloadExpr, &expr.Cmp{Op: newOp, Register: 1, Data: []byte(newIP)}}
	}
	rule.Exprs = append(newHead, rule.Exprs...)
}
