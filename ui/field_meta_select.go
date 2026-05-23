package ui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"nftui/nft"
)

// MetaSelectField backs the meta matches whose value is best represented as
// an enumeration: nfproto (ipv4/ipv6), pkttype (host/broadcast/multicast/
// other), l4proto (tcp/udp/icmp/…). All three are 1-byte uint8 on the wire
// (the kernel registers store the byte left-justified in a 4-byte slot).
//
// The Select offers the common names; if the user wants an unsupported
// numeric value they can type "" and the match is removed (the milestone
// only commits to the enumerated names — numeric fallback is a future item).
type MetaSelectField struct {
	metaKey expr.MetaKey
	mKey    nft.MetaKey
	label   string

	nameToCode map[string]uint8
	codeToName func(uint8) string
	options    []string

	opInput    Select
	valueInput Select

	originalOp    nft.CompareOp
	originalValue string
}

func newMetaSelectField(rd *nft.Rule, metaKey expr.MetaKey, mKey nft.MetaKey, label string,
	nameToCode map[string]uint8, options []string, codeToName func(uint8) string) *MetaSelectField {

	opInput := NewSelect([]string{"==", "!="})
	opInput.Width = 4

	valueInput := NewSelect(options)
	valueInput.Width = 14

	var originalOp nft.CompareOp = nft.CompareOpEq
	var originalValue string

	for _, condition := range rd.Conditions {
		if condition.Meta == nil || condition.Meta.Key != mKey {
			continue
		}
		switch v := condition.Meta.Value.(type) {
		case uint8:
			originalValue = codeToName(v)
		case uint32:
			originalValue = codeToName(uint8(v))
		case string:
			originalValue = v
		case nft.MetaKey:
			originalValue = string(v)
		}
		originalOp = condition.Operation
	}

	opInput.SetValue(string(originalOp))
	valueInput.SetValue(originalValue)

	return &MetaSelectField{
		metaKey:       metaKey,
		mKey:          mKey,
		label:         label,
		nameToCode:    nameToCode,
		codeToName:    codeToName,
		options:       options,
		opInput:       opInput,
		valueInput:    valueInput,
		originalOp:    originalOp,
		originalValue: originalValue,
	}
}

func (f *MetaSelectField) FocusSlots() int { return 2 }

func (f *MetaSelectField) Focus(subIndex int) {
	if subIndex == 0 {
		f.opInput.Focus()
		f.valueInput.Blur()
	} else {
		f.opInput.Blur()
		f.valueInput.Focus()
	}
}

func (f *MetaSelectField) Blur() {
	f.opInput.Blur()
	f.valueInput.Blur()
}

func (f *MetaSelectField) opChanged() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp
}

func (f *MetaSelectField) valueChanged() bool {
	return f.valueInput.Value() != f.originalValue
}

func (f *MetaSelectField) Changed() bool {
	return f.opChanged() || f.valueChanged()
}

func (f *MetaSelectField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.opInput.Focused {
		f.opInput, cmd = f.opInput.Update(msg)
	} else if f.valueInput.Focused {
		f.valueInput, cmd = f.valueInput.Update(msg)
	}
	return cmd
}

func (f *MetaSelectField) ValidateForSave() error {
	if !f.Changed() {
		return nil
	}
	name := strings.TrimSpace(f.valueInput.Value())
	if name == "" {
		return nil
	}
	if _, ok := f.nameToCode[name]; !ok {
		return fmt.Errorf("%s: %q is not a recognized value", f.label, name)
	}
	return nil
}

func (f *MetaSelectField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	name := strings.TrimSpace(f.valueInput.Value())
	newOp := compareOpToExprCmpOp(nft.CompareOp(f.opInput.Value()))

	for i, re := range rule.Exprs {
		m, ok := re.(*expr.Meta)
		if !ok || m.Key != f.metaKey {
			continue
		}
		if i+1 >= len(rule.Exprs) {
			break
		}
		cmp, ok := rule.Exprs[i+1].(*expr.Cmp)
		if !ok {
			break
		}
		if name == "" {
			rule.Exprs = append(rule.Exprs[:i], rule.Exprs[i+2:]...)
		} else {
			code, ok := f.nameToCode[name]
			if !ok {
				return
			}
			cmp.Op = newOp
			cmp.Data = []byte{code}
		}
		f.originalOp = nft.CompareOp(f.opInput.Value())
		f.originalValue = name
		return
	}

	if name == "" {
		f.originalValue = ""
		return
	}
	code, ok := f.nameToCode[name]
	if !ok {
		return
	}
	rule.Exprs = append(rule.Exprs,
		&expr.Meta{Key: f.metaKey, Register: 1},
		&expr.Cmp{Op: newOp, Register: 1, Data: []byte{code}},
	)
	f.originalOp = nft.CompareOp(f.opInput.Value())
	f.originalValue = name
}

func (f *MetaSelectField) View() string {
	vOp := f.opInput.View()
	if f.opChanged() {
		vOp = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vOp)
	}
	vVal := f.valueInput.View()
	if f.valueChanged() {
		vVal = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vVal)
	}
	inputs := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(6).Render(vOp),
		lipgloss.NewStyle().Width(16).Render(vVal),
	)
	return grayStyle.Render(f.label) + "\n" + inputs + "\n"
}

// --- Concrete factories --------------------------------------------------

// nfproto: NFPROTO_IPV4=2, NFPROTO_IPV6=10 (linux/netfilter.h).
var nfprotoNameToCode = map[string]uint8{
	"":     0,
	"ipv4": unix.NFPROTO_IPV4,
	"ipv6": unix.NFPROTO_IPV6,
}
var nfprotoOptions = []string{"", "ipv4", "ipv6"}

func nfprotoCodeToName(c uint8) string {
	switch c {
	case unix.NFPROTO_IPV4:
		return "ipv4"
	case unix.NFPROTO_IPV6:
		return "ipv6"
	}
	return strconv.FormatUint(uint64(c), 10)
}

func NewMetaNfprotoField(rd *nft.Rule) *MetaSelectField {
	return newMetaSelectField(rd, unix.NFT_META_NFPROTO, nft.MetaKeyNfproto,
		"Meta nfproto", nfprotoNameToCode, nfprotoOptions, nfprotoCodeToName)
}

// pkttype: linux/if_packet.h — PACKET_HOST=0, PACKET_BROADCAST=1,
// PACKET_MULTICAST=2, PACKET_OTHERHOST=3 (nft uses "other" for OTHERHOST).
var pkttypeNameToCode = map[string]uint8{
	"":          0xff, // empty sentinel — won't match anything; Save removes
	"host":      unix.PACKET_HOST,
	"broadcast": unix.PACKET_BROADCAST,
	"multicast": unix.PACKET_MULTICAST,
	"other":     unix.PACKET_OTHERHOST,
}
var pkttypeOptions = []string{"", "host", "broadcast", "multicast", "other"}

func pkttypeCodeToName(c uint8) string {
	switch c {
	case unix.PACKET_HOST:
		return "host"
	case unix.PACKET_BROADCAST:
		return "broadcast"
	case unix.PACKET_MULTICAST:
		return "multicast"
	case unix.PACKET_OTHERHOST:
		return "other"
	}
	return strconv.FormatUint(uint64(c), 10)
}

func NewMetaPkttypeField(rd *nft.Rule) *MetaSelectField {
	return newMetaSelectField(rd, unix.NFT_META_PKTTYPE, nft.MetaKeyPktType,
		"Meta pkttype", pkttypeNameToCode, pkttypeOptions, pkttypeCodeToName)
}

// l4proto: common IP transport protocols. The kernel stores the raw IP
// protocol number (IPPROTO_*); we accept the names that `nft` accepts in
// `meta l4proto`.
var l4protoNameToCode = map[string]uint8{
	"":        0,
	"tcp":     unix.IPPROTO_TCP,
	"udp":     unix.IPPROTO_UDP,
	"icmp":    unix.IPPROTO_ICMP,
	"icmpv6":  unix.IPPROTO_ICMPV6,
	"udplite": unix.IPPROTO_UDPLITE,
	"sctp":    unix.IPPROTO_SCTP,
	"dccp":    unix.IPPROTO_DCCP,
	"esp":     unix.IPPROTO_ESP,
	"ah":      unix.IPPROTO_AH,
	"gre":     unix.IPPROTO_GRE,
}
var l4protoOptions = []string{"", "tcp", "udp", "icmp", "icmpv6", "udplite", "sctp", "dccp", "esp", "ah", "gre"}

func l4protoCodeToName(c uint8) string {
	for n, code := range l4protoNameToCode {
		if n == "" {
			continue
		}
		if code == c {
			return n
		}
	}
	return strconv.FormatUint(uint64(c), 10)
}

func NewMetaL4protoField(rd *nft.Rule) *MetaSelectField {
	return newMetaSelectField(rd, unix.NFT_META_L4PROTO, nft.MetaKeyL4Proto,
		"Meta l4proto", l4protoNameToCode, l4protoOptions, l4protoCodeToName)
}
