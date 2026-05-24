package ui

import (
	"encoding/binary"
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

// SctpField backs the SCTP header field editors (sport / dport / vtag /
// checksum). All four are simple unsigned-int payload-equality matches that
// share the `meta l4proto sctp` prefix.
//
// The MVP intentionally omits `sctp chunk` — that match is chunk-type-
// scoped and needs a richer editor (RFC 4960 chunk types DATA / INIT / ACK
// / etc.), tracked as a future v0.3.x refinement.
type SctpField struct {
	label   string
	offset  uint32
	length  uint32
	hexHint bool
	// fieldName matches identifyPayloadField's output (sport/dport return
	// a *PortSpec; vtag/checksum return uint32).
	fieldName string

	valueInput    NumberInput
	originalValue uint64
	originalIsSet bool
}

func newSctpField(rd *nft.Rule, label, fieldName string, offset, length uint32, hexHint bool) *SctpField {
	hi := 0xffff
	if length == 4 {
		hi = 1<<31 - 1
	}
	valueInput := NewNumberInput(0, hi)
	valueInput.Placeholder = "0"
	if length == 4 {
		valueInput.Width = 14
		valueInput.CharLimit = 10
	} else {
		valueInput.Width = 10
		valueInput.CharLimit = 5
	}

	var orig uint64
	var origSet bool
	for _, c := range rd.Conditions {
		if c.Payload == nil ||
			c.Payload.Protocol != nft.PayloadProtoSCTP ||
			c.Payload.Field != fieldName {
			continue
		}
		switch v := c.Payload.Value.(type) {
		case uint16:
			orig = uint64(v)
		case uint32:
			orig = uint64(v)
		case *nft.PortSpec:
			orig = uint64(v.Port)
		}
		origSet = true
	}
	if origSet && orig > 0 {
		valueInput.SetValue(strconv.FormatUint(orig, 10))
	}

	return &SctpField{
		label:         label,
		offset:        offset,
		length:        length,
		hexHint:       hexHint,
		fieldName:     fieldName,
		valueInput:    valueInput,
		originalValue: orig,
		originalIsSet: origSet,
	}
}

func (f *SctpField) FocusSlots() int { return 1 }
func (f *SctpField) Focus(_ int)     { f.valueInput.Focus() }
func (f *SctpField) Blur()           { f.valueInput.Blur() }

func (f *SctpField) currentValue() (uint64, bool) {
	s := strings.TrimSpace(f.valueInput.Value())
	if s == "" {
		return 0, false
	}
	v, _ := f.valueInput.GetUint64()
	return v, true
}

func (f *SctpField) Changed() bool {
	cur, set := f.currentValue()
	if set != f.originalIsSet {
		return true
	}
	return set && cur != f.originalValue
}

func (f *SctpField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.valueInput, cmd = f.valueInput.Update(msg)
	return cmd
}

func (f *SctpField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	cur, set := f.currentValue()
	saveL4ProtoMatch(rule, unix.IPPROTO_SCTP, f.offset, f.length, cur, set)
	if set {
		f.originalValue = cur
		f.originalIsSet = true
	} else {
		f.originalValue = 0
		f.originalIsSet = false
	}
}

func (f *SctpField) View() string {
	v := f.valueInput.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	hint := ""
	if f.hexHint {
		if val, err := f.valueInput.GetUint64(); err == nil && val > 0 {
			if f.length == 2 {
				hint = grayStyle.Render(fmt.Sprintf(" (0x%04x)", uint16(val)))
			} else {
				hint = grayStyle.Render(fmt.Sprintf(" (0x%08x)", uint32(val)))
			}
		}
	}
	return grayStyle.Render(f.label) + "\n" + v + hint + "\n"
}

// saveL4ProtoMatch is the generic transport-protocol write-back: inserts a
// `meta l4proto <proto>` prefix if missing, then overwrites or removes the
// Payload+Cmp pair at (offset, length). Used by SCTP and the future DCCP/
// AH/ESP/COMP editors.
func saveL4ProtoMatch(rule *nftables.Rule, proto uint8, offset, length uint32, cur uint64, ok bool) {
	idx := -1
	for i, re := range rule.Exprs {
		p, isP := re.(*expr.Payload)
		if !isP || p.Base != expr.PayloadBaseTransportHeader ||
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

	if !hasL4ProtoMatch(rule, proto) {
		rule.Exprs = append([]expr.Any{
			&expr.Meta{Key: unix.NFT_META_L4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		}, rule.Exprs...)
	}

	data := make([]byte, length)
	switch length {
	case 1:
		data[0] = uint8(cur)
	case 2:
		binary.BigEndian.PutUint16(data, uint16(cur))
	case 4:
		binary.BigEndian.PutUint32(data, uint32(cur))
	}

	// Re-locate after potential prefix insertion.
	idx = -1
	for i, re := range rule.Exprs {
		p, isP := re.(*expr.Payload)
		if !isP || p.Base != expr.PayloadBaseTransportHeader ||
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
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: length},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
	)
}

// hasL4ProtoMatch returns true if the rule already starts with a
// `meta l4proto <proto>` match pair.
func hasL4ProtoMatch(rule *nftables.Rule, proto uint8) bool {
	for i := 0; i+1 < len(rule.Exprs); i++ {
		m, ok := rule.Exprs[i].(*expr.Meta)
		if !ok || m.Key != unix.NFT_META_L4PROTO {
			continue
		}
		c, ok := rule.Exprs[i+1].(*expr.Cmp)
		if !ok || c.Op != expr.CmpOpEq || len(c.Data) < 1 {
			continue
		}
		if c.Data[0] == proto {
			return true
		}
	}
	return false
}

// Concrete factories.

func NewSctpSportField(rd *nft.Rule) *SctpField {
	return newSctpField(rd, "SCTP sport", "sport", 0, 2, false)
}
func NewSctpDportField(rd *nft.Rule) *SctpField {
	return newSctpField(rd, "SCTP dport", "dport", 2, 2, false)
}
func NewSctpVtagField(rd *nft.Rule) *SctpField {
	return newSctpField(rd, "SCTP vtag", "vtag", 4, 4, true)
}
func NewSctpChecksumField(rd *nft.Rule) *SctpField {
	return newSctpField(rd, "SCTP checksum", "checksum", 8, 4, true)
}
