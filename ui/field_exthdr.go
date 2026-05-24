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

// ExthdrField is the generic editor for IPv6 extension-header sub-field
// matches: frag, hbh, dst, mh, rt families with 18 fields total. The wire
// shape is uniform — `*expr.Exthdr` + `*expr.Cmp`, no auto-injection prefix
// required (the kernel's exthdr machinery handles the dispatch based on
// the `Type` byte).
//
// One struct, one Save helper, eighteen factories.
type ExthdrField struct {
	label      string
	proto      nft.ExthdrProto
	fieldName  string
	exthdrType uint8
	offset     uint32
	length     uint32

	valueInput    NumberInput
	originalValue uint64
	originalIsSet bool
}

func newExthdrField(rd *nft.Rule, label string, proto nft.ExthdrProto, fieldName string,
	exthdrType uint8, offset, length uint32) *ExthdrField {

	hi := 0xff
	switch length {
	case 2:
		hi = 0xffff
	case 4:
		hi = 1<<31 - 1
	}
	valueInput := NewNumberInput(0, hi)
	valueInput.Placeholder = "0"
	switch length {
	case 4:
		valueInput.Width = 14
		valueInput.CharLimit = 10
	case 2:
		valueInput.Width = 10
		valueInput.CharLimit = 5
	default:
		valueInput.Width = 8
		valueInput.CharLimit = 3
	}

	var orig uint64
	var origSet bool
	for _, c := range rd.Conditions {
		if c.Exthdr == nil || c.Exthdr.Proto != proto || c.Exthdr.Field != fieldName {
			continue
		}
		switch v := c.Exthdr.Value.(type) {
		case uint8:
			orig = uint64(v)
		case uint16:
			orig = uint64(v)
		case uint32:
			orig = uint64(v)
		}
		origSet = true
	}
	if origSet && orig > 0 {
		valueInput.SetValue(strconv.FormatUint(orig, 10))
	}

	return &ExthdrField{
		label:         label,
		proto:         proto,
		fieldName:     fieldName,
		exthdrType:    exthdrType,
		offset:        offset,
		length:        length,
		valueInput:    valueInput,
		originalValue: orig,
		originalIsSet: origSet,
	}
}

func (f *ExthdrField) FocusSlots() int { return 1 }
func (f *ExthdrField) Focus(_ int)     { f.valueInput.Focus() }
func (f *ExthdrField) Blur()           { f.valueInput.Blur() }

func (f *ExthdrField) currentValue() (uint64, bool) {
	s := strings.TrimSpace(f.valueInput.Value())
	if s == "" {
		return 0, false
	}
	v, _ := f.valueInput.GetUint64()
	return v, true
}

func (f *ExthdrField) Changed() bool {
	cur, set := f.currentValue()
	if set != f.originalIsSet {
		return true
	}
	return set && cur != f.originalValue
}

func (f *ExthdrField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.valueInput, cmd = f.valueInput.Update(msg)
	return cmd
}

func (f *ExthdrField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	cur, set := f.currentValue()
	saveExthdrMatch(rule, f.exthdrType, f.offset, f.length, cur, set)
	if set {
		f.originalValue = cur
		f.originalIsSet = true
	} else {
		f.originalValue = 0
		f.originalIsSet = false
	}
}

func (f *ExthdrField) View() string {
	v := f.valueInput.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	return grayStyle.Render(f.label) + "\n" + v + "\n"
}

// saveExthdrMatch overwrites or inserts a *expr.Exthdr + *expr.Cmp pair
// uniquely identified by (type, offset, length).
func saveExthdrMatch(rule *nftables.Rule, exthdrType uint8, offset, length uint32, cur uint64, ok bool) {
	idx := -1
	for i, re := range rule.Exprs {
		e, isE := re.(*expr.Exthdr)
		if !isE || e.Type != exthdrType || e.Offset != offset || e.Len != length {
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

	data := make([]byte, length)
	switch length {
	case 1:
		data[0] = byte(cur)
	case 2:
		binary.BigEndian.PutUint16(data, uint16(cur))
	case 4:
		binary.BigEndian.PutUint32(data, uint32(cur))
	}

	if idx >= 0 && idx+1 < len(rule.Exprs) {
		if cmp, ok := rule.Exprs[idx+1].(*expr.Cmp); ok {
			cmp.Op = expr.CmpOpEq
			cmp.Data = data
			return
		}
	}
	rule.Exprs = append(rule.Exprs,
		&expr.Exthdr{DestRegister: 1, Type: exthdrType, Offset: offset, Len: length, Op: expr.ExthdrOpIpv6},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
	)
}

// --- Concrete factories — 18 fields across 5 protocols. ---

// Frag (IPPROTO_FRAGMENT=44)
func NewFragNexthdrField(rd *nft.Rule) *ExthdrField {
	return newExthdrField(rd, "Frag nexthdr", nft.ExthdrProtoFrag, "nexthdr", 44, 0, 1)
}
func NewFragReservedField(rd *nft.Rule) *ExthdrField {
	return newExthdrField(rd, "Frag reserved", nft.ExthdrProtoFrag, "reserved", 44, 1, 1)
}
func NewFragFragOffField(rd *nft.Rule) *ExthdrField {
	return newExthdrField(rd, "Frag frag-off", nft.ExthdrProtoFrag, "frag-off", 44, 2, 2)
}
func NewFragMoreFragmentsField(rd *nft.Rule) *ExthdrField {
	return newExthdrField(rd, "Frag more-fragments", nft.ExthdrProtoFrag, "more-fragments", 44, 3, 1)
}
func NewFragIdField(rd *nft.Rule) *ExthdrField {
	return newExthdrField(rd, "Frag id", nft.ExthdrProtoFrag, "id", 44, 4, 4)
}

// HBH (Hop-by-Hop Options, =0)
func NewHbhNexthdrField(rd *nft.Rule) *ExthdrField {
	return newExthdrField(rd, "HBH nexthdr", nft.ExthdrProtoHBH, "nexthdr", 0, 0, 1)
}
func NewHbhHdrlengthField(rd *nft.Rule) *ExthdrField {
	return newExthdrField(rd, "HBH hdrlength", nft.ExthdrProtoHBH, "hdrlength", 0, 1, 1)
}

// Dst (Destination Options, =60)
func NewDstNexthdrField(rd *nft.Rule) *ExthdrField {
	return newExthdrField(rd, "Dst nexthdr", nft.ExthdrProtoDst, "nexthdr", 60, 0, 1)
}
func NewDstHdrlengthField(rd *nft.Rule) *ExthdrField {
	return newExthdrField(rd, "Dst hdrlength", nft.ExthdrProtoDst, "hdrlength", 60, 1, 1)
}

// Mh (Mobility, =135)
func NewMhNexthdrField(rd *nft.Rule) *ExthdrField {
	return newExthdrField(rd, "MH nexthdr", nft.ExthdrProtoMh, "nexthdr", 135, 0, 1)
}
func NewMhHdrlengthField(rd *nft.Rule) *ExthdrField {
	return newExthdrField(rd, "MH hdrlength", nft.ExthdrProtoMh, "hdrlength", 135, 1, 1)
}
func NewMhTypeField(rd *nft.Rule) *ExthdrField {
	return newExthdrField(rd, "MH type", nft.ExthdrProtoMh, "type", 135, 2, 1)
}
func NewMhReservedField(rd *nft.Rule) *ExthdrField {
	return newExthdrField(rd, "MH reserved", nft.ExthdrProtoMh, "reserved", 135, 3, 1)
}
func NewMhChecksumField(rd *nft.Rule) *ExthdrField {
	return newExthdrField(rd, "MH checksum", nft.ExthdrProtoMh, "checksum", 135, 4, 2)
}

// Rt (Routing, =43)
func NewRtNexthdrField(rd *nft.Rule) *ExthdrField {
	return newExthdrField(rd, "Rt nexthdr", nft.ExthdrProtoRt, "nexthdr", 43, 0, 1)
}
func NewRtHdrlengthField(rd *nft.Rule) *ExthdrField {
	return newExthdrField(rd, "Rt hdrlength", nft.ExthdrProtoRt, "hdrlength", 43, 1, 1)
}
func NewRtTypeField(rd *nft.Rule) *ExthdrField {
	return newExthdrField(rd, "Rt type", nft.ExthdrProtoRt, "type", 43, 2, 1)
}
func NewRtSegLeftField(rd *nft.Rule) *ExthdrField {
	return newExthdrField(rd, "Rt seg-left", nft.ExthdrProtoRt, "seg-left", 43, 3, 1)
}
