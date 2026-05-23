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

// metaUintWidth selects the wire payload width for a Meta integer match.
type metaUintWidth int

const (
	metaUint8  metaUintWidth = 1
	metaUint16 metaUintWidth = 2
	metaUint32 metaUintWidth = 4
)

// MetaUintField is a generic op+number editor for the integer-valued meta
// matches that all share the same shape: an op selector plus a uint8/16/32
// value. The struct stores everything it needs to talk to the kernel and to
// the parser at runtime, so a single implementation backs every concrete
// MetaXxxField factory below.
type MetaUintField struct {
	metaKey expr.MetaKey // wire-level NFT_META_*
	mKey    nft.MetaKey  // user-facing key string (matches the parser output)
	label   string       // UI label
	width   metaUintWidth
	hexHint bool // display "(0x…)" hint next to a uint32 like mark/priority

	opInput    Select
	valueInput NumberInput

	originalOp    nft.CompareOp
	originalValue uint64
}

func newMetaUintField(rd *nft.Rule, metaKey expr.MetaKey, mKey nft.MetaKey,
	label string, width metaUintWidth, hexHint bool) *MetaUintField {

	opInput := NewSelect([]string{"==", "!=", "<", "<=", ">", ">="})
	opInput.Width = 6

	var hi int
	switch width {
	case metaUint8:
		hi = 0xff
	case metaUint16:
		hi = 0xffff
	default:
		hi = 1<<31 - 1 // NumberInput stores int — cap at MaxInt32 (sufficient for editing values)
	}
	valueInput := NewNumberInput(0, hi)
	valueInput.Placeholder = "0"
	valueInput.Width = 12
	if width == metaUint32 {
		valueInput.CharLimit = 10
	} else {
		valueInput.CharLimit = 6
	}

	var originalOp nft.CompareOp = nft.CompareOpEq
	var originalValue uint64

	for _, condition := range rd.Conditions {
		if condition.Meta == nil || condition.Meta.Key != mKey {
			continue
		}
		switch v := condition.Meta.Value.(type) {
		case uint8:
			originalValue = uint64(v)
		case uint16:
			originalValue = uint64(v)
		case uint32:
			originalValue = uint64(v)
		case uint64:
			originalValue = v
		}
		originalOp = condition.Operation
	}

	opInput.SetValue(string(originalOp))
	if originalValue > 0 {
		valueInput.SetValue(strconv.FormatUint(originalValue, 10))
	}

	return &MetaUintField{
		metaKey:       metaKey,
		mKey:          mKey,
		label:         label,
		width:         width,
		hexHint:       hexHint,
		opInput:       opInput,
		valueInput:    valueInput,
		originalOp:    originalOp,
		originalValue: originalValue,
	}
}

func (f *MetaUintField) FocusSlots() int { return 2 }

func (f *MetaUintField) Focus(subIndex int) {
	if subIndex == 0 {
		f.opInput.Focus()
		f.valueInput.Blur()
	} else {
		f.opInput.Blur()
		f.valueInput.Focus()
	}
}

func (f *MetaUintField) Blur() {
	f.opInput.Blur()
	f.valueInput.Blur()
}

func (f *MetaUintField) currentValue() uint64 {
	v, _ := f.valueInput.GetUint64()
	return v
}

func (f *MetaUintField) opChanged() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp
}

func (f *MetaUintField) valueChanged() bool {
	return f.currentValue() != f.originalValue
}

func (f *MetaUintField) Changed() bool {
	return f.opChanged() || f.valueChanged()
}

func (f *MetaUintField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.opInput.Focused {
		f.opInput, cmd = f.opInput.Update(msg)
	} else if f.valueInput.Focused() {
		f.valueInput, cmd = f.valueInput.Update(msg)
	}
	return cmd
}

// encodeMetaValue produces the BE wire payload for the given width.
// (The parser's decodeMetaValue reads BE for len==1/2/4 — we stay consistent.)
func (f *MetaUintField) encodeMetaValue(v uint64) []byte {
	switch f.width {
	case metaUint8:
		return []byte{byte(v)}
	case metaUint16:
		out := make([]byte, 2)
		binary.BigEndian.PutUint16(out, uint16(v))
		return out
	default:
		out := make([]byte, 4)
		binary.BigEndian.PutUint32(out, uint32(v))
		return out
	}
}

// IsZero reports whether the value input is empty/zero — used by the Save
// path to decide between "delete the match" and "edit in place".
func (f *MetaUintField) isCleared() bool {
	return strings.TrimSpace(f.valueInput.Value()) == "" || f.currentValue() == 0
}

func (f *MetaUintField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	newVal := f.currentValue()
	newOp := compareOpToExprCmpOp(nft.CompareOp(f.opInput.Value()))

	// 1) overwrite in place.
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
		// Treat zero as "remove the match" only when the input is empty.
		if strings.TrimSpace(f.valueInput.Value()) == "" {
			rule.Exprs = append(rule.Exprs[:i], rule.Exprs[i+2:]...)
		} else {
			cmp.Op = newOp
			cmp.Data = f.encodeMetaValue(newVal)
		}
		f.originalOp = nft.CompareOp(f.opInput.Value())
		f.originalValue = newVal
		return
	}

	// 2) append fresh pair.
	if strings.TrimSpace(f.valueInput.Value()) == "" {
		f.originalValue = 0
		return
	}
	rule.Exprs = append(rule.Exprs,
		&expr.Meta{Key: f.metaKey, Register: 1},
		&expr.Cmp{Op: newOp, Register: 1, Data: f.encodeMetaValue(newVal)},
	)
	f.originalOp = nft.CompareOp(f.opInput.Value())
	f.originalValue = newVal
}

func (f *MetaUintField) View() string {
	vOp := f.opInput.View()
	if f.opChanged() {
		vOp = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vOp)
	}
	vVal := f.valueInput.View()
	if f.valueChanged() {
		vVal = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vVal)
	}

	var hexHint string
	if f.hexHint {
		if v, err := f.valueInput.GetUint64(); err == nil {
			hexHint = grayStyle.Render(fmt.Sprintf(" (0x%08x)", uint32(v)))
		}
	}
	inputs := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(8).Render(vOp),
		lipgloss.NewStyle().Width(14).Render(vVal),
		hexHint,
	)
	return grayStyle.Render(f.label) + "\n" + inputs + "\n"
}

// Concrete factories — one per ROADMAP item.

func NewMetaLengthField(rd *nft.Rule) *MetaUintField {
	return newMetaUintField(rd, unix.NFT_META_LEN, nft.MetaKeyLength, "Meta length", metaUint16, false)
}

func NewMetaProtocolField(rd *nft.Rule) *MetaUintField {
	return newMetaUintField(rd, unix.NFT_META_PROTOCOL, nft.MetaKeyProtocol, "Meta protocol", metaUint16, true)
}

func NewMetaMarkField(rd *nft.Rule) *MetaUintField {
	return newMetaUintField(rd, unix.NFT_META_MARK, nft.MetaKeyMark, "Meta mark", metaUint32, true)
}

func NewMetaPriorityField(rd *nft.Rule) *MetaUintField {
	return newMetaUintField(rd, unix.NFT_META_PRIORITY, nft.MetaKeyPriority, "Meta priority", metaUint32, true)
}

func NewMetaSkuidField(rd *nft.Rule) *MetaUintField {
	return newMetaUintField(rd, unix.NFT_META_SKUID, nft.MetaKeySkuid, "Meta skuid", metaUint32, false)
}

func NewMetaSkgidField(rd *nft.Rule) *MetaUintField {
	return newMetaUintField(rd, unix.NFT_META_SKGID, nft.MetaKeySkgid, "Meta skgid", metaUint32, false)
}

func NewMetaCgroupField(rd *nft.Rule) *MetaUintField {
	return newMetaUintField(rd, unix.NFT_META_CGROUP, nft.MetaKeyCGroup, "Meta cgroup", metaUint32, false)
}

func NewMetaCpuField(rd *nft.Rule) *MetaUintField {
	return newMetaUintField(rd, unix.NFT_META_CPU, nft.MetaKeyCPU, "Meta cpu", metaUint32, false)
}

func NewMetaIifgroupField(rd *nft.Rule) *MetaUintField {
	return newMetaUintField(rd, unix.NFT_META_IIFGROUP, nft.MetaKeyIIfGroup, "Meta iifgroup", metaUint32, false)
}

func NewMetaOifgroupField(rd *nft.Rule) *MetaUintField {
	return newMetaUintField(rd, unix.NFT_META_OIFGROUP, nft.MetaKeyOIfGroup, "Meta oifgroup", metaUint32, false)
}

func NewMetaRtclassidField(rd *nft.Rule) *MetaUintField {
	return newMetaUintField(rd, unix.NFT_META_RTCLASSID, nft.MetaKeyRtclassid, "Meta rtclassid", metaUint32, false)
}
