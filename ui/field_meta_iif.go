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
	"golang.org/x/sys/unix"
	"nftui/nft"
)

// MetaIifField edits a `meta iif <name|index>` or `meta oif <name|index>`
// condition. The two variants share their wire format (BE uint32 ifindex)
// and UX (name input that resolves via net.InterfaceByName, with numeric
// ifindex fallback) — so a single struct backs both, distinguished by the
// metaKey it operates on.
//
// On read-back the parser produces a string when the index resolves at
// runtime, or a uint32 when the interface has been removed / never existed.
// We accept both representations as the "original" value.
type MetaIifField struct {
	metaKey       expr.MetaKey
	mKey          nft.MetaKey
	label         string
	opInput       Select
	valueInput    textinput.Model
	originalOp    nft.CompareOp
	originalValue string // canonical: name if resolvable, else "%d" of the ifindex
}

// metaIifResolveOriginal renders a stored MetaCondition.Value (string|uint32)
// into the canonical text shown / edited in the input.
func metaIifResolveOriginal(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case uint32:
		return strconv.FormatUint(uint64(x), 10)
	}
	return ""
}

func NewMetaIifField(rd *nft.Rule) *MetaIifField {
	return newMetaIifLike(rd, unix.NFT_META_IIF, nft.MetaKeyIIf, "Meta iif")
}

func NewMetaOifField(rd *nft.Rule) *MetaIifField {
	return newMetaIifLike(rd, unix.NFT_META_OIF, nft.MetaKeyOIf, "Meta oif")
}

func newMetaIifLike(rd *nft.Rule, metaKey expr.MetaKey, mKey nft.MetaKey, label string) *MetaIifField {
	opInput := NewSelect([]string{"==", "!="})
	opInput.Width = 4

	valueInput := textinput.New()
	valueInput.Placeholder = "e.g. eth0 or 2"
	valueInput.CharLimit = 16
	valueInput.Width = 18

	var originalOp nft.CompareOp = nft.CompareOpEq
	var originalValue string

	for _, condition := range rd.Conditions {
		if condition.Meta != nil && condition.Meta.Key == mKey {
			originalValue = metaIifResolveOriginal(condition.Meta.Value)
			originalOp = condition.Operation
		}
	}

	opInput.SetValue(string(originalOp))
	valueInput.SetValue(originalValue)

	return &MetaIifField{
		metaKey:       metaKey,
		mKey:          mKey,
		label:         label,
		opInput:       opInput,
		valueInput:    valueInput,
		originalOp:    originalOp,
		originalValue: originalValue,
	}
}

func (f *MetaIifField) FocusSlots() int { return 2 }

func (f *MetaIifField) Focus(subIndex int) {
	if subIndex == 0 {
		f.opInput.Focus()
		f.valueInput.Blur()
	} else {
		f.opInput.Blur()
		f.valueInput.Focus()
	}
}

func (f *MetaIifField) Blur() {
	f.opInput.Blur()
	f.valueInput.Blur()
}

func (f *MetaIifField) opChanged() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp
}

func (f *MetaIifField) valueChanged() bool {
	return f.valueInput.Value() != f.originalValue
}

func (f *MetaIifField) Changed() bool {
	return f.opChanged() || f.valueChanged()
}

func (f *MetaIifField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.opInput.Focused {
		f.opInput, cmd = f.opInput.Update(msg)
	} else if f.valueInput.Focused() {
		f.valueInput, cmd = f.valueInput.Update(msg)
	}
	return cmd
}

// resolveIifIndex turns user input ("eth0" or "5") into a 4-byte BE wire
// payload. Returns (data, ok). If the text cannot be resolved to either a
// known interface name or a parseable integer, ok=false and the field skips
// the save (no kernel error, no silent zero).
func resolveIifIndex(text string) ([]byte, bool) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, false
	}
	if iface, err := net.InterfaceByName(text); err == nil {
		out := make([]byte, 4)
		binary.BigEndian.PutUint32(out, uint32(iface.Index))
		return out, true
	}
	if n, err := strconv.ParseUint(text, 10, 32); err == nil {
		out := make([]byte, 4)
		binary.BigEndian.PutUint32(out, uint32(n))
		return out, true
	}
	return nil, false
}

func (f *MetaIifField) ValidateForSave() error {
	if !f.Changed() {
		return nil
	}
	text := strings.TrimSpace(f.valueInput.Value())
	if text == "" {
		// empty means "delete the match"
		return nil
	}
	if _, ok := resolveIifIndex(text); !ok {
		return fmt.Errorf("%s: %q is neither a known interface name nor a numeric ifindex", f.label, text)
	}
	return nil
}

func (f *MetaIifField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	newText := strings.TrimSpace(f.valueInput.Value())
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
		if newText == "" {
			rule.Exprs = append(rule.Exprs[:i], rule.Exprs[i+2:]...)
		} else {
			data, ok := resolveIifIndex(newText)
			if !ok {
				return
			}
			cmp.Op = newOp
			cmp.Data = data
		}
		f.originalOp = nft.CompareOp(f.opInput.Value())
		f.originalValue = newText
		return
	}

	// 2) append fresh pair if non-empty.
	if newText == "" {
		f.originalValue = ""
		return
	}
	data, ok := resolveIifIndex(newText)
	if !ok {
		return
	}
	rule.Exprs = append(rule.Exprs,
		&expr.Meta{Key: f.metaKey, Register: 1},
		&expr.Cmp{Op: newOp, Register: 1, Data: data},
	)
	f.originalOp = nft.CompareOp(f.opInput.Value())
	f.originalValue = newText
}

func (f *MetaIifField) View() string {
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
		lipgloss.NewStyle().Width(20).Render(vVal),
	)
	return grayStyle.Render(f.label) + "\n" + inputs + "\n"
}
