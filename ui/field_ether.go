package ui

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
)

// EtherAddrField backs `ether saddr` and `ether daddr` matches. Wire format
// is a 6-byte MAC at the link-layer header (saddr at offset 6, daddr at 0).
// The user enters a colon-separated `aa:bb:cc:dd:ee:ff`; ValidateForSave
// rejects malformed input before the kernel sees it.
type EtherAddrField struct {
	label  string
	field  string // "saddr" or "daddr"
	offset uint32

	opInput    Select
	addrInput  textinput.Model
	originalOp nft.CompareOp
	original   string
}

func NewEtherSaddrField(rd *nft.Rule) *EtherAddrField {
	return newEtherAddrField(rd, "Ether saddr", "saddr", 6)
}
func NewEtherDaddrField(rd *nft.Rule) *EtherAddrField {
	return newEtherAddrField(rd, "Ether daddr", "daddr", 0)
}

func newEtherAddrField(rd *nft.Rule, label, field string, offset uint32) *EtherAddrField {
	opInput := NewSelect(ipAddrOpOptions) // ==, !=
	opInput.Width = 6

	addrInput := textinput.New()
	addrInput.Placeholder = "aa:bb:cc:dd:ee:ff"
	addrInput.CharLimit = 17
	addrInput.Width = 22

	var origOp nft.CompareOp = nft.CompareOpEq
	var orig string
	for _, c := range rd.Conditions {
		if c.Payload == nil ||
			c.Payload.Protocol != nft.PayloadProtoEther ||
			c.Payload.Field != field {
			continue
		}
		if s, ok := c.Payload.Value.(string); ok {
			orig = s
		}
		origOp = c.Operation
	}
	opInput.SetValue(string(origOp))
	addrInput.SetValue(orig)

	return &EtherAddrField{
		label: label, field: field, offset: offset,
		opInput: opInput, addrInput: addrInput,
		originalOp: origOp, original: orig,
	}
}

func (f *EtherAddrField) FocusSlots() int { return 2 }

func (f *EtherAddrField) Focus(i int) {
	f.Blur()
	if i == 0 {
		f.opInput.Focus()
	} else {
		f.addrInput.Focus()
	}
}

func (f *EtherAddrField) Blur() {
	f.opInput.Blur()
	f.addrInput.Blur()
}

func (f *EtherAddrField) opChanged() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp
}
func (f *EtherAddrField) addrChanged() bool {
	return f.addrInput.Value() != f.original
}
func (f *EtherAddrField) Changed() bool { return f.opChanged() || f.addrChanged() }

func (f *EtherAddrField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.opInput.Focused {
		f.opInput, cmd = f.opInput.Update(msg)
	} else if f.addrInput.Focused() {
		f.addrInput, cmd = f.addrInput.Update(msg)
	}
	return cmd
}

// parseMAC accepts colon-separated `aa:bb:cc:dd:ee:ff` (any case) and
// returns the 6 raw bytes. Returns an error for malformed input.
func parseMAC(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return nil, fmt.Errorf("expected 6 colon-separated octets, got %d", len(parts))
	}
	out := make([]byte, 6)
	for i, p := range parts {
		if len(p) != 2 {
			return nil, fmt.Errorf("octet %d %q must be 2 hex chars", i, p)
		}
		b, err := hex.DecodeString(p)
		if err != nil || len(b) != 1 {
			return nil, fmt.Errorf("octet %d %q is not hex", i, p)
		}
		out[i] = b[0]
	}
	return out, nil
}

func (f *EtherAddrField) ValidateForSave() error {
	if !f.Changed() {
		return nil
	}
	s := strings.TrimSpace(f.addrInput.Value())
	if s == "" {
		return nil // empty = delete the match
	}
	if _, err := parseMAC(s); err != nil {
		return fmt.Errorf("%s: %v", f.label, err)
	}
	return nil
}

func (f *EtherAddrField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	newAddr := strings.TrimSpace(f.addrInput.Value())
	newOp := compareOpToExprCmpOp(nft.CompareOp(f.opInput.Value()))

	// Locate existing Payload{LL, offset, 6}.
	idx := -1
	for i, re := range rule.Exprs {
		p, ok := re.(*expr.Payload)
		if !ok || p.Base != expr.PayloadBaseLLHeader ||
			p.Offset != f.offset || p.Len != 6 {
			continue
		}
		idx = i
		break
	}

	if newAddr == "" {
		if idx >= 0 && idx+1 < len(rule.Exprs) {
			rule.Exprs = append(rule.Exprs[:idx], rule.Exprs[idx+2:]...)
		}
		f.originalOp = nft.CompareOp(f.opInput.Value())
		f.original = ""
		return
	}

	data, err := parseMAC(newAddr)
	if err != nil {
		return
	}

	if idx >= 0 && idx+1 < len(rule.Exprs) {
		if cmp, ok := rule.Exprs[idx+1].(*expr.Cmp); ok {
			cmp.Op = newOp
			cmp.Data = data
			f.originalOp = nft.CompareOp(f.opInput.Value())
			f.original = newAddr
			return
		}
	}
	rule.Exprs = append(rule.Exprs,
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: f.offset, Len: 6},
		&expr.Cmp{Op: newOp, Register: 1, Data: data},
	)
	f.originalOp = nft.CompareOp(f.opInput.Value())
	f.original = newAddr
}

func (f *EtherAddrField) View() string {
	vOp := f.opInput.View()
	if f.opChanged() {
		vOp = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vOp)
	}
	vAddr := f.addrInput.View()
	if f.addrChanged() {
		vAddr = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vAddr)
	}
	row := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(8).Render(vOp),
		lipgloss.NewStyle().Render(vAddr),
	)
	return grayStyle.Render(f.label) + "\n" + row + "\n"
}
