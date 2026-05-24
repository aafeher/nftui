package ui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
)

// TCP flag bits (linux/tcp.h, TCPHDR_*).
const (
	tcpFlagFIN byte = 0x01
	tcpFlagSYN byte = 0x02
	tcpFlagRST byte = 0x04
	tcpFlagPSH byte = 0x08
	tcpFlagACK byte = 0x10
	tcpFlagURG byte = 0x20
	tcpFlagECE byte = 0x40
	tcpFlagCWR byte = 0x80
)

var tcpFlagNames = []string{"fin", "syn", "rst", "psh", "ack", "urg", "ecn", "cwr"}
var tcpFlagNameToBit = map[string]byte{
	"fin": tcpFlagFIN, "syn": tcpFlagSYN, "rst": tcpFlagRST, "psh": tcpFlagPSH,
	"ack": tcpFlagACK, "urg": tcpFlagURG, "ecn": tcpFlagECE, "cwr": tcpFlagCWR,
}

// tcpFlagsByteToNames returns the flag names corresponding to set bits in b,
// in canonical order.
func tcpFlagsByteToNames(b byte) []string {
	out := []string{}
	for _, n := range tcpFlagNames {
		if b&tcpFlagNameToBit[n] != 0 {
			out = append(out, n)
		}
	}
	return out
}

// tcpFlagsNamesToByte ORs the bits of the given flag names.
func tcpFlagsNamesToByte(names []string) byte {
	var b byte
	for _, n := range names {
		b |= tcpFlagNameToBit[n]
	}
	return b
}

// TcpFlagsField is a MultiSelect over the 8 TCP flag bits. The MVP supports
// the "exact equality" match (Payload + Cmp without Bitwise) — the kernel's
// Bitwise+Cmp variant (`tcp flags & (mask) == X`) is a future refinement.
type TcpFlagsField struct {
	input    MultiSelect
	original []string
}

func NewTcpFlagsField(rd *nft.Rule) *TcpFlagsField {
	input := NewMultiSelect(tcpFlagNames)

	var original []string
	for _, condition := range rd.Conditions {
		if condition.Payload == nil {
			continue
		}
		if condition.Payload.Protocol != nft.PayloadProtoTCP || condition.Payload.Field != "flags" {
			continue
		}
		if v, ok := condition.Payload.Value.(uint8); ok {
			original = tcpFlagsByteToNames(v)
		}
	}
	input.SetValues(original)
	return &TcpFlagsField{input: input, original: original}
}

func (f *TcpFlagsField) FocusSlots() int { return 1 }
func (f *TcpFlagsField) Focus(_ int)     { f.input.Focus() }
func (f *TcpFlagsField) Blur()           { f.input.Blur() }

func (f *TcpFlagsField) Changed() bool {
	return !sameStringSet(f.input.Values(), f.original)
}

func (f *TcpFlagsField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	return cmd
}

func (f *TcpFlagsField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	names := f.input.Values()
	encoded := tcpFlagsNamesToByte(names)

	// Find existing Payload{transport, offset=13, len=1} + Cmp.
	for i, re := range rule.Exprs {
		p, ok := re.(*expr.Payload)
		if !ok || p.Base != expr.PayloadBaseTransportHeader || p.Offset != 13 || p.Len != 1 {
			continue
		}
		if i+1 >= len(rule.Exprs) {
			break
		}
		cmp, ok := rule.Exprs[i+1].(*expr.Cmp)
		if !ok {
			break
		}
		if encoded == 0 {
			rule.Exprs = append(rule.Exprs[:i], rule.Exprs[i+2:]...)
		} else {
			cmp.Op = expr.CmpOpEq
			cmp.Data = []byte{encoded}
		}
		f.original = names
		return
	}

	if encoded == 0 {
		f.original = nil
		return
	}
	rule.Exprs = append(rule.Exprs,
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{encoded}},
	)
	f.original = names
}

func (f *TcpFlagsField) View() string {
	v := f.input.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	return grayStyle.Render("TCP flags") + "\n" + v + "\n"
}

// sameStringSet reports whether a and b contain the same elements ignoring order.
func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, s := range a {
		counts[s]++
	}
	for _, s := range b {
		if counts[s] == 0 {
			return false
		}
		counts[s]--
	}
	return true
}
