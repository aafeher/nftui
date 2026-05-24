package ui

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
)

// NATField backs `snat to <addr>[:<port>]` and `dnat to <addr>[:<port>]`.
// Both wire shapes are identical aside from the *expr.NAT.Type field; the
// SnatField / DnatField factories pin that to nftexpr.NATTypeSourceNAT or
// NATTypeDestNAT respectively.
//
// Sub-inputs:
//   - enable Select (off / on)
//   - addr text input ("192.168.1.100" — single IP only; ranges are a future refinement)
//   - port NumberInput (0..65535, 0 = no port mapping)
//   - flags MultiSelect (random / fully-random / persistent — kernel-level;
//     `nft` CLI only accepts one at a time)
type NATField struct {
	natType        nft.NATType
	exprNATType    expr.NATType
	family         nftables.TableFamily
	label          string
	enableInput    Select
	addrInput      textinput.Model
	portInput      NumberInput
	flagsInput     MultiSelect
	originalEnable bool
	originalAddr   string
	originalPort   uint64
	originalFlags  []string
}

func tableFamilyToNATFamily(f nftables.TableFamily) nftables.TableFamily {
	switch f {
	case nftables.TableFamilyIPv6:
		return nftables.TableFamilyIPv6
	default:
		// IPv4 covers ip, inet, bridge, arp, netdev for NAT addresses.
		return nftables.TableFamilyIPv4
	}
}

func NewSnatField(rd *nft.Rule, tableFamily nftables.TableFamily) *NATField {
	return newNATField(rd, nft.NATTypeSNAT, expr.NATTypeSourceNAT, tableFamily, "SNAT")
}

func NewDnatField(rd *nft.Rule, tableFamily nftables.TableFamily) *NATField {
	return newNATField(rd, nft.NATTypeDNAT, expr.NATTypeDestNAT, tableFamily, "DNAT")
}

func newNATField(rd *nft.Rule, natType nft.NATType, exprNATType expr.NATType,
	tableFamily nftables.TableFamily, label string) *NATField {

	enableInput := NewSelect([]string{"off", "on"})
	enableInput.Width = 6

	addrInput := textinput.New()
	addrInput.Placeholder = "e.g. 192.168.1.100"
	addrInput.CharLimit = 45
	addrInput.Width = 22

	portInput := NewNumberInput(0, 65535)
	portInput.Placeholder = "0"
	portInput.Width = 8
	portInput.CharLimit = 5

	flagsInput := NewMultiSelect(masqFlagNames) // same flag set

	var origEnable bool
	var origAddr string
	var origPort uint64
	var origFlags []string

	for _, a := range rd.Actions {
		if a.Type != nft.ActionTypeNAT || a.NAT == nil || a.NAT.Type != natType {
			continue
		}
		origEnable = true
		if a.NAT.AddressRange != nil {
			origAddr = a.NAT.AddressRange.From.String()
		}
		if a.NAT.PortRange != nil {
			origPort = uint64(a.NAT.PortRange.From)
		}
		for _, fl := range a.NAT.Flags {
			origFlags = append(origFlags, string(fl))
		}
	}

	if origEnable {
		enableInput.SetValue("on")
	} else {
		enableInput.SetValue("off")
	}
	addrInput.SetValue(origAddr)
	if origPort > 0 {
		portInput.SetValue(strconv.FormatUint(origPort, 10))
	}
	flagsInput.SetValues(origFlags)

	return &NATField{
		natType:        natType,
		exprNATType:    exprNATType,
		family:         tableFamilyToNATFamily(tableFamily),
		label:          label,
		enableInput:    enableInput,
		addrInput:      addrInput,
		portInput:      portInput,
		flagsInput:     flagsInput,
		originalEnable: origEnable,
		originalAddr:   origAddr,
		originalPort:   origPort,
		originalFlags:  origFlags,
	}
}

func (f *NATField) FocusSlots() int { return 4 }

func (f *NATField) Focus(subIndex int) {
	f.Blur()
	switch subIndex {
	case 0:
		f.enableInput.Focus()
	case 1:
		f.addrInput.Focus()
	case 2:
		f.portInput.Focus()
	case 3:
		f.flagsInput.Focus()
	}
}

func (f *NATField) Blur() {
	f.enableInput.Blur()
	f.addrInput.Blur()
	f.portInput.Blur()
	f.flagsInput.Blur()
}

func (f *NATField) currentEnabled() bool { return f.enableInput.Value() == "on" }
func (f *NATField) currentPort() uint64 {
	v, _ := f.portInput.GetUint64()
	return v
}

func (f *NATField) enableChanged() bool { return f.currentEnabled() != f.originalEnable }
func (f *NATField) addrChanged() bool   { return f.addrInput.Value() != f.originalAddr }
func (f *NATField) portChanged() bool   { return f.currentPort() != f.originalPort }
func (f *NATField) flagsChanged() bool  { return !sameStringSet(f.flagsInput.Values(), f.originalFlags) }

func (f *NATField) Changed() bool {
	return f.enableChanged() || f.addrChanged() || f.portChanged() || f.flagsChanged()
}

func (f *NATField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	switch {
	case f.enableInput.Focused:
		f.enableInput, cmd = f.enableInput.Update(msg)
	case f.addrInput.Focused():
		f.addrInput, cmd = f.addrInput.Update(msg)
	case f.portInput.Focused():
		f.portInput, cmd = f.portInput.Update(msg)
	default:
		f.flagsInput, cmd = f.flagsInput.Update(msg)
	}
	return cmd
}

func (f *NATField) ValidateForSave() error {
	if !f.Changed() || !f.currentEnabled() {
		return nil
	}
	addr := strings.TrimSpace(f.addrInput.Value())
	if addr == "" {
		return fmt.Errorf("%s: address is required when enabled", f.label)
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("%s: %q is not a valid IP address", f.label, addr)
	}
	if f.family == nftables.TableFamilyIPv4 && ip.To4() == nil {
		return fmt.Errorf("%s: %q is not an IPv4 address (table family is IPv4)", f.label, addr)
	}
	return nil
}

func (f *NATField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}

	// Remove every existing expr pair belonging to this NAT direction: the
	// *expr.NAT and the preceding Immediate(s) that filled its registers.
	// We do this by deleting the *expr.NAT first, then walking back to also
	// drop the Immediates that referenced its registers if no one else uses them.
	for i := len(rule.Exprs) - 1; i >= 0; i-- {
		n, ok := rule.Exprs[i].(*expr.NAT)
		if !ok || n.Type != f.exprNATType {
			continue
		}
		toDrop := map[uint32]bool{}
		if n.RegAddrMin != 0 {
			toDrop[n.RegAddrMin] = true
		}
		if n.RegAddrMax != 0 {
			toDrop[n.RegAddrMax] = true
		}
		if n.RegProtoMin != 0 {
			toDrop[n.RegProtoMin] = true
		}
		if n.RegProtoMax != 0 {
			toDrop[n.RegProtoMax] = true
		}
		rule.Exprs = append(rule.Exprs[:i], rule.Exprs[i+1:]...)
		// Drop the Immediates that fed those registers.
		for j := i - 1; j >= 0 && len(toDrop) > 0; j-- {
			imm, ok := rule.Exprs[j].(*expr.Immediate)
			if !ok {
				continue
			}
			if toDrop[imm.Register] {
				rule.Exprs = append(rule.Exprs[:j], rule.Exprs[j+1:]...)
				delete(toDrop, imm.Register)
			}
		}
		break
	}

	if !f.currentEnabled() {
		f.originalEnable = false
		f.originalAddr = ""
		f.originalPort = 0
		f.originalFlags = nil
		return
	}

	addr := strings.TrimSpace(f.addrInput.Value())
	ip := net.ParseIP(addr)
	if ip == nil {
		return
	}
	var ipBytes []byte
	if f.family == nftables.TableFamilyIPv6 {
		ipBytes = ip.To16()
	} else {
		ipBytes = ip.To4()
	}
	if ipBytes == nil {
		return
	}

	// Allocate registers — pick low numbers (1, 2). The kernel uses these to
	// shuttle the immediate values into the NAT expr.
	addrReg := uint32(1)
	portReg := uint32(2)

	flags := f.flagsInput.Values()
	flagSet := map[string]bool{}
	for _, fl := range flags {
		flagSet[fl] = true
	}

	immediates := []expr.Any{
		&expr.Immediate{Register: addrReg, Data: append([]byte{}, ipBytes...)},
	}
	nat := &expr.NAT{
		Type:        f.exprNATType,
		Family:      uint32(f.family),
		RegAddrMin:  addrReg,
		Random:      flagSet["random"],
		FullyRandom: flagSet["fully-random"],
		Persistent:  flagSet["persistent"],
	}

	if port := f.currentPort(); port > 0 {
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, uint16(port))
		immediates = append(immediates,
			&expr.Immediate{Register: portReg, Data: portBytes},
		)
		nat.RegProtoMin = portReg
	}

	rule.Exprs = append(rule.Exprs, immediates...)
	rule.Exprs = append(rule.Exprs, nat)

	f.originalEnable = true
	f.originalAddr = addr
	f.originalPort = f.currentPort()
	f.originalFlags = flags
}

func (f *NATField) View() string {
	vEnable := f.enableInput.View()
	if f.enableChanged() {
		vEnable = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vEnable)
	}
	vAddr := f.addrInput.View()
	if f.addrChanged() {
		vAddr = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vAddr)
	}
	vPort := f.portInput.View()
	if f.portChanged() {
		vPort = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vPort)
	}
	vFlags := f.flagsInput.View()
	if f.flagsChanged() {
		vFlags = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vFlags)
	}
	row1 := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(8).Render(grayStyle.Render("enable:")),
		lipgloss.NewStyle().Width(8).Render(vEnable),
		lipgloss.NewStyle().Width(8).Render(grayStyle.Render("addr:")),
		lipgloss.NewStyle().Width(24).Render(vAddr),
		lipgloss.NewStyle().Width(7).Render(grayStyle.Render("port:")),
		lipgloss.NewStyle().Render(vPort),
	)
	return grayStyle.Render(f.label) + "\n" +
		row1 + "\n" +
		grayStyle.Render("flags: ") + vFlags + "\n"
}

// formatNAT renders a NATAction as `snat to <addr>[:<port>] [<flags>]`.
func formatNAT(n *nft.NATAction) string {
	if n == nil {
		return ""
	}
	out := yellowBoldStyle.Render(string(n.Type) + " to")
	if n.AddressRange != nil {
		out += " " + n.AddressRange.From.String()
		if n.PortRange != nil {
			out += ":" + fmt.Sprintf("%d", n.PortRange.From)
			if n.PortRange.To != n.PortRange.From {
				out += "-" + fmt.Sprintf("%d", n.PortRange.To)
			}
		}
	}
	for _, fl := range n.Flags {
		out += " " + grayStyle.Render(string(fl))
	}
	return out
}
