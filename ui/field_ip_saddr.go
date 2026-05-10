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

var ipAddrOpOptions = []string{"==", "!="}

// IPSaddrField edits the ip saddr (IPv4 source address) condition of a rule.
type IPSaddrField struct {
	opInput    Select
	input      textinput.Model
	originalOp nft.CompareOp
	original   string
}

func NewIPSaddrField(rd *nft.Rule) *IPSaddrField {
	opInput := NewSelect(ipAddrOpOptions)
	opInput.Width = 6

	input := textinput.New()
	input.Placeholder = "e.g. 192.168.1.1 or 192.168.0.0/24"
	input.CharLimit = 43
	input.Width = 30

	original := extractIPAddrString(rd, "saddr")
	originalOp := extractIPAddrOp(rd, "saddr")
	opInput.SetValue(string(originalOp))
	input.SetValue(original)

	return &IPSaddrField{opInput: opInput, input: input, originalOp: originalOp, original: original}
}

func (f *IPSaddrField) FocusSlots() int { return 2 }

func (f *IPSaddrField) Focus(subIndex int) {
	if subIndex == 0 {
		f.opInput.Focus()
	} else {
		f.input.Focus()
	}
}

func (f *IPSaddrField) Blur() {
	f.opInput.Blur()
	f.input.Blur()
}

func (f *IPSaddrField) opChanged() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp
}

func (f *IPSaddrField) ipChanged() bool {
	return f.input.Value() != f.original
}

func (f *IPSaddrField) Changed() bool {
	return f.opChanged() || f.ipChanged()
}

func (f *IPSaddrField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.opInput.Focused {
		f.opInput, cmd = f.opInput.Update(msg)
	} else if f.input.Focused() {
		f.input, cmd = f.input.Update(msg)
	}
	return cmd
}

func (f *IPSaddrField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	newOp := compareOpToExprCmpOp(nft.CompareOp(f.opInput.Value()))
	applyIPAddrSave(rule, 12, f.input.Value(), newOp)
	f.original = f.input.Value()
	f.originalOp = nft.CompareOp(f.opInput.Value())
}

func (f *IPSaddrField) View() string {
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
	return grayStyle.Render("IP src") + "\n" + inputs + "\n"
}

// compareOpToExprCmpOp converts a nft.CompareOp to the expr.CmpOp used by the kernel.
func compareOpToExprCmpOp(op nft.CompareOp) expr.CmpOp {
	switch op {
	case nft.CompareOpNeq:
		return expr.CmpOpNeq
	case nft.CompareOpLt:
		return expr.CmpOpLt
	case nft.CompareOpLte:
		return expr.CmpOpLte
	case nft.CompareOpGt:
		return expr.CmpOpGt
	case nft.CompareOpGte:
		return expr.CmpOpGte
	default:
		return expr.CmpOpEq
	}
}

// extractIPAddrOp returns the comparison operator for the saddr or daddr condition.
// Returns CompareOpEq if no matching condition exists.
func extractIPAddrOp(rd *nft.Rule, field string) nft.CompareOp {
	for _, cond := range rd.Conditions {
		if cond.Payload == nil {
			continue
		}
		if cond.Payload.Protocol != nft.PayloadProtoIP || cond.Payload.Field != field {
			continue
		}
		return cond.Operation
	}
	return nft.CompareOpEq
}

// extractIPAddrString returns the current saddr or daddr value from the parsed
// rule as a human-readable string ("192.168.1.1" or "192.168.0.0/24").
// Returns "" if no matching condition exists.
func extractIPAddrString(rd *nft.Rule, field string) string {
	for _, cond := range rd.Conditions {
		if cond.Payload == nil {
			continue
		}
		if cond.Payload.Protocol != nft.PayloadProtoIP || cond.Payload.Field != field {
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

// applyIPAddrSave updates the Payload→[Bitwise→]Cmp expression sequence for the
// given payload offset (12=saddr, 16=daddr) with the new IPv4 or CIDR value and operator.
// If no matching Payload expression is found, a new one is prepended to the rule.
func applyIPAddrSave(rule *nftables.Rule, payloadOffset uint32, newVal string, newOp expr.CmpOp) {
	if newVal == "" {
		return
	}

	var newIP net.IP
	var newMask net.IPMask
	isCIDR := false

	if _, ipnet, err := net.ParseCIDR(newVal); err == nil {
		newIP = ipnet.IP.To4()
		newMask = ipnet.Mask
		isCIDR = true
	} else if ip := net.ParseIP(newVal); ip != nil {
		newIP = ip.To4()
	}

	if newIP == nil {
		return // invalid input or IPv6 (not supported for IPv4 payload fields)
	}

	for i, re := range rule.Exprs {
		p, ok := re.(*expr.Payload)
		if !ok || p.Base != expr.PayloadBaseNetworkHeader || p.Offset != payloadOffset || p.Len < 1 || p.Len > 4 {
			continue
		}
		p.Len = 4 // normalize byte-aligned prefix to standard 4-byte form

		reg := p.DestRegister

		if i+1 >= len(rule.Exprs) {
			return
		}

		switch next := rule.Exprs[i+1].(type) {
		case *expr.Cmp:
			if isCIDR {
				// Insert Bitwise between Payload and Cmp.
				bw := &expr.Bitwise{
					SourceRegister: reg,
					DestRegister:   reg,
					Len:            4,
					Mask:           append([]byte{}, []byte(newMask)...),
					Xor:            []byte{0, 0, 0, 0},
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
				// Remove the Bitwise, keep Cmp with exact IP.
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

	// No matching Payload found – prepend a new condition to the rule.
	payloadExpr := &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       payloadOffset,
		Len:          4,
	}
	var newHead []expr.Any
	if isCIDR {
		bw := &expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           append([]byte{}, []byte(newMask)...),
			Xor:            []byte{0, 0, 0, 0},
		}
		newHead = []expr.Any{payloadExpr, bw, &expr.Cmp{
			Op:       newOp,
			Register: 1,
			Data:     []byte(newIP),
		}}
	} else {
		newHead = []expr.Any{payloadExpr, &expr.Cmp{
			Op:       newOp,
			Register: 1,
			Data:     []byte(newIP),
		}}
	}
	rule.Exprs = append(newHead, rule.Exprs...)
}
