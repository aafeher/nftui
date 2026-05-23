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

// arphrdNameToCode maps the `nft` CLI's recognized network-interface-type
// names to their kernel ARPHRD_* numeric codes (see linux/if_arp.h).
// Only types accepted by the userland parser are listed — exotic ones like
// `tunnel` (ARPHRD_TUNNEL=768) or `ieee802` (ARPHRD_IEEE802=6) are rejected
// by `nft -c -f`, so we don't expose them in the Select.
var arphrdNameToCode = map[string]uint16{
	"":           0, // sentinel — "(unset)" / delete
	"ether":      unix.ARPHRD_ETHER,
	"loopback":   unix.ARPHRD_LOOPBACK,
	"ppp":        unix.ARPHRD_PPP,
	"ipgre":      unix.ARPHRD_IPGRE,
	"sit":        unix.ARPHRD_SIT,
	"ieee802154": unix.ARPHRD_IEEE802154,
}

var arphrdNames = []string{"", "ether", "loopback", "ppp", "ipgre", "sit", "ieee802154"}

func arphrdCodeToName(code uint16) string {
	for name, c := range arphrdNameToCode {
		if name == "" {
			continue
		}
		if c == code {
			return name
		}
	}
	return strconv.FormatUint(uint64(code), 10) // numeric fallback for unknowns
}

// MetaIftypeField edits `meta iiftype` / `meta oiftype` (uint16 ARPHRD_* code).
// Backs both NewMetaIiftypeField and NewMetaOiftypeField via stored metaKey.
type MetaIftypeField struct {
	metaKey       expr.MetaKey
	mKey          nft.MetaKey
	label         string
	opInput       Select
	valueInput    Select
	originalOp    nft.CompareOp
	originalValue string
}

func NewMetaIiftypeField(rd *nft.Rule) *MetaIftypeField {
	return newMetaIftypeLike(rd, unix.NFT_META_IIFTYPE, nft.MetaKeyIIfType, "Meta iiftype")
}

func NewMetaOiftypeField(rd *nft.Rule) *MetaIftypeField {
	return newMetaIftypeLike(rd, unix.NFT_META_OIFTYPE, nft.MetaKeyOIfType, "Meta oiftype")
}

func newMetaIftypeLike(rd *nft.Rule, metaKey expr.MetaKey, mKey nft.MetaKey, label string) *MetaIftypeField {
	opInput := NewSelect([]string{"==", "!="})
	opInput.Width = 4

	valueInput := NewSelect(arphrdNames)
	valueInput.Width = 12

	var originalOp nft.CompareOp = nft.CompareOpEq
	var originalValue string

	for _, condition := range rd.Conditions {
		if condition.Meta != nil && condition.Meta.Key == mKey {
			switch v := condition.Meta.Value.(type) {
			case uint16:
				originalValue = arphrdCodeToName(v)
			case uint32:
				originalValue = arphrdCodeToName(uint16(v))
			case uint8:
				originalValue = arphrdCodeToName(uint16(v))
			}
			originalOp = condition.Operation
		}
	}

	opInput.SetValue(string(originalOp))
	valueInput.SetValue(originalValue)

	return &MetaIftypeField{
		metaKey:       metaKey,
		mKey:          mKey,
		label:         label,
		opInput:       opInput,
		valueInput:    valueInput,
		originalOp:    originalOp,
		originalValue: originalValue,
	}
}

func (f *MetaIftypeField) FocusSlots() int { return 2 }

func (f *MetaIftypeField) Focus(subIndex int) {
	if subIndex == 0 {
		f.opInput.Focus()
		f.valueInput.Blur()
	} else {
		f.opInput.Blur()
		f.valueInput.Focus()
	}
}

func (f *MetaIftypeField) Blur() {
	f.opInput.Blur()
	f.valueInput.Blur()
}

func (f *MetaIftypeField) opChanged() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp
}

func (f *MetaIftypeField) valueChanged() bool {
	return f.valueInput.Value() != f.originalValue
}

func (f *MetaIftypeField) Changed() bool {
	return f.opChanged() || f.valueChanged()
}

func (f *MetaIftypeField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.opInput.Focused {
		f.opInput, cmd = f.opInput.Update(msg)
	} else if f.valueInput.Focused {
		f.valueInput, cmd = f.valueInput.Update(msg)
	}
	return cmd
}

func (f *MetaIftypeField) ValidateForSave() error {
	if !f.Changed() {
		return nil
	}
	name := strings.TrimSpace(f.valueInput.Value())
	if name == "" {
		return nil
	}
	if _, ok := arphrdNameToCode[name]; !ok {
		return fmt.Errorf("%s: %q is not a recognized iftype name", f.label, name)
	}
	return nil
}

func (f *MetaIftypeField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	name := strings.TrimSpace(f.valueInput.Value())
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
		if name == "" {
			rule.Exprs = append(rule.Exprs[:i], rule.Exprs[i+2:]...)
		} else {
			code := arphrdNameToCode[name]
			data := make([]byte, 2)
			binary.BigEndian.PutUint16(data, code)
			cmp.Op = newOp
			cmp.Data = data
		}
		f.originalOp = nft.CompareOp(f.opInput.Value())
		f.originalValue = name
		return
	}

	// 2) append fresh pair.
	if name == "" {
		f.originalValue = ""
		return
	}
	code := arphrdNameToCode[name]
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, code)
	rule.Exprs = append(rule.Exprs,
		&expr.Meta{Key: f.metaKey, Register: 1},
		&expr.Cmp{Op: newOp, Register: 1, Data: data},
	)
	f.originalOp = nft.CompareOp(f.opInput.Value())
	f.originalValue = name
}

func (f *MetaIftypeField) View() string {
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
