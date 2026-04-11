package ui

import (
	"encoding/binary"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
	nftexpr "nftui/nft/expr"
)

// CtProtoSrcField edits the ct proto-src (connection tracking source port) condition.
// Supports == / != operators and optional direction (original/reply).
type CtProtoSrcField struct {
	opInput        Select
	valueInput     NumberInput
	directionInput Select
	originalOp     nft.CompareOp
	originalValue  uint16
	originalDir    nftexpr.CtDirection
}

func NewCtProtoSrcField(rd *nft.Rule) *CtProtoSrcField {
	opInput := NewSelect([]string{"==", "!="})
	opInput.Width = 6

	valueInput := NewNumberInput(0, 65535)
	valueInput.Placeholder = "0-65535"
	valueInput.CharLimit = 5
	valueInput.Width = 8

	directionInput := NewSelect(append([]string{""}, nftexpr.CtDirectionStrings...))
	directionInput.Width = 12

	var originalOp nft.CompareOp = nft.CompareOpEq
	var originalValue uint16
	var originalDir nftexpr.CtDirection

	for _, condition := range rd.Conditions {
		if condition.CT != nil && condition.CT.Key == nftexpr.CtKeyProtoSrc {
			if p, ok := condition.CT.Value.(uint16); ok {
				originalValue = p
			}
			originalOp = condition.Operation
			originalDir = condition.CT.Direction
		}
	}

	opInput.SetValue(string(originalOp))
	if originalValue > 0 {
		valueInput.SetValue(fmt.Sprint(originalValue))
	}
	directionInput.SetValue(string(originalDir))

	return &CtProtoSrcField{
		opInput:        opInput,
		valueInput:     valueInput,
		directionInput: directionInput,
		originalOp:     originalOp,
		originalValue:  originalValue,
		originalDir:    originalDir,
	}
}

func (f *CtProtoSrcField) FocusSlots() int { return 3 }

func (f *CtProtoSrcField) Focus(subIndex int) {
	switch subIndex {
	case 0:
		f.opInput.Focus()
	case 1:
		f.valueInput.Focus()
	default:
		f.directionInput.Focus()
	}
}

func (f *CtProtoSrcField) Blur() {
	f.opInput.Blur()
	f.valueInput.Blur()
	f.directionInput.Blur()
}

func (f *CtProtoSrcField) opChanged() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp
}

func (f *CtProtoSrcField) valueChanged() bool {
	val, _ := f.valueInput.GetUint64()
	return uint16(val) != f.originalValue
}

func (f *CtProtoSrcField) dirChanged() bool {
	return nftexpr.CtDirection(f.directionInput.Value()) != f.originalDir
}

func (f *CtProtoSrcField) Changed() bool {
	return f.opChanged() || f.valueChanged() || f.dirChanged()
}

func (f *CtProtoSrcField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.opInput.Focused {
		f.opInput, cmd = f.opInput.Update(msg)
	} else if f.valueInput.Focused() {
		f.valueInput, cmd = f.valueInput.Update(msg)
	} else if f.directionInput.Focused {
		f.directionInput, cmd = f.directionInput.Update(msg)
	}
	return cmd
}

func (f *CtProtoSrcField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	val, err := f.valueInput.GetUint64()
	if err != nil {
		return
	}
	newPort := uint16(val)
	newOp := compareOpToExprCmpOp(nft.CompareOp(f.opInput.Value()))
	newDir := nftexpr.CtDirection(f.directionInput.Value())

	portData := binary.BigEndian.AppendUint16(nil, newPort)

	dir, optDir := ctDirectionToExpr(newDir)

	found := false
	for i, re := range rule.Exprs {
		if ct, ok := re.(*expr.Ct); ok && ct.Key == expr.CtKeyPROTOSRC {
			found = true
			ct.Direction = dir
			ct.OptDirection = optDir
			if i+1 < len(rule.Exprs) {
				if cmp, ok := rule.Exprs[i+1].(*expr.Cmp); ok {
					cmp.Data = portData
					cmp.Op = newOp
				}
			}
		}
	}

	if !found && newPort > 0 {
		insertIdx := ctInsertIndex(rule.Exprs)
		newExprs := make([]expr.Any, 0, len(rule.Exprs)+2)
		newExprs = append(newExprs, rule.Exprs[:insertIdx]...)
		newExprs = append(newExprs,
			&expr.Ct{Key: expr.CtKeyPROTOSRC, Register: 1, Direction: dir, OptDirection: optDir},
			&expr.Cmp{Op: newOp, Register: 1, Data: portData},
		)
		newExprs = append(newExprs, rule.Exprs[insertIdx:]...)
		rule.Exprs = newExprs
	}

	f.originalOp = nft.CompareOp(f.opInput.Value())
	f.originalValue = newPort
	f.originalDir = newDir
}

func (f *CtProtoSrcField) View() string {
	vOp := f.opInput.View()
	if f.opChanged() {
		vOp = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vOp)
	}
	vVal := f.valueInput.View()
	if f.valueChanged() {
		vVal = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vVal)
	}
	vDir := f.directionInput.View()
	if f.dirChanged() {
		vDir = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vDir)
	}
	inputs := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(8).Render(vOp),
		lipgloss.NewStyle().Width(12).Render(vVal),
		lipgloss.NewStyle().Render(vDir),
	)
	return grayStyle.Render("CT proto-src") + "\n" + inputs + "\n"
}
