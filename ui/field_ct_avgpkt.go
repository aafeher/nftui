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

// CtAvgpktField edits the ct avgpkt (average bytes per packet) condition.
// Supports all relational operators and optional direction (original/reply).
type CtAvgpktField struct {
	opInput        Select
	valueInput     NumberInput
	directionInput Select
	originalOp     nft.CompareOp
	originalValue  uint64
	originalDir    nftexpr.CtDirection
}

func NewCtAvgpktField(rd *nft.Rule) *CtAvgpktField {
	opInput := NewSelect([]string{"==", "!=", "<", "<=", ">", ">="})
	opInput.Width = 6

	valueInput := NewNumberInput(0, 9_223_372_036_854_775_807)
	valueInput.Placeholder = "0"
	valueInput.CharLimit = 20
	valueInput.Width = 20

	directionInput := NewSelect(append([]string{""}, nftexpr.CtDirectionStrings...))
	directionInput.Width = 10

	var originalOp nft.CompareOp = nft.CompareOpEq
	var originalValue uint64
	var originalDir nftexpr.CtDirection

	for _, condition := range rd.Conditions {
		if condition.CT != nil && condition.CT.Key == nftexpr.CtKeyAvgpkt {
			if b, ok := condition.CT.Value.(uint64); ok {
				originalValue = b
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

	return &CtAvgpktField{
		opInput:        opInput,
		valueInput:     valueInput,
		directionInput: directionInput,
		originalOp:     originalOp,
		originalValue:  originalValue,
		originalDir:    originalDir,
	}
}

func (f *CtAvgpktField) FocusSlots() int { return 3 }

func (f *CtAvgpktField) Focus(subIndex int) {
	switch subIndex {
	case 0:
		f.opInput.Focus()
	case 1:
		f.valueInput.Focus()
	default:
		f.directionInput.Focus()
	}
}

func (f *CtAvgpktField) Blur() {
	f.opInput.Blur()
	f.valueInput.Blur()
	f.directionInput.Blur()
}

func (f *CtAvgpktField) opChanged() bool {
	return nft.CompareOp(f.opInput.Value()) != f.originalOp
}

func (f *CtAvgpktField) valueChanged() bool {
	val, _ := f.valueInput.GetUint64()
	return val != f.originalValue
}

func (f *CtAvgpktField) dirChanged() bool {
	return f.directionInput.Value() != string(f.originalDir)
}

func (f *CtAvgpktField) Changed() bool {
	return f.opChanged() || f.valueChanged() || f.dirChanged()
}

func (f *CtAvgpktField) Update(msg tea.Msg) tea.Cmd {
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

func (f *CtAvgpktField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	val, err := f.valueInput.GetUint64()
	if err != nil {
		return
	}
	newAvgpkt := val
	newOp := compareOpToExprCmpOp(nft.CompareOp(f.opInput.Value()))
	newDirectionStr := f.directionInput.Value()
	var newDirection nftexpr.CtDirection
	if newDirectionStr != "" {
		newDirection = nftexpr.CtDirection(newDirectionStr)
	} else {
		newDirection = nftexpr.CtDirectionNone
	}
	avgpktData := binary.LittleEndian.AppendUint64(nil, newAvgpkt)

	found := false
	for i, re := range rule.Exprs {
		if e, ok := re.(*expr.Ct); ok && e.Key == expr.CtKeyAVGPKT {
			found = true
			if newDirection == nftexpr.CtDirectionOriginal {
				e.Direction = 0
				e.OptDirection = true
			} else if newDirection == nftexpr.CtDirectionReply {
				e.Direction = 1
				e.OptDirection = true
			} else {
				e.Direction = 255
				e.OptDirection = false
			}
			if i+1 < len(rule.Exprs) {
				if cmp, ok := rule.Exprs[i+1].(*expr.Cmp); ok {
					cmp.Op = newOp
					cmp.Data = avgpktData
				}
			}
		}
	}

	if !found && (newAvgpkt > 0 || f.opChanged()) {
		insertIdx := 0
		for i, re := range rule.Exprs {
			if _, ok := re.(*expr.Ct); ok {
				insertIdx = i + 2
			}
		}
		dir := uint32(255)
		optDir := false
		if newDirection == nftexpr.CtDirectionOriginal {
			dir = 0
			optDir = true
		} else if newDirection == nftexpr.CtDirectionReply {
			dir = 1
			optDir = true
		}
		newExprs := make([]expr.Any, 0, len(rule.Exprs)+2)
		newExprs = append(newExprs, rule.Exprs[:insertIdx]...)
		newExprs = append(newExprs,
			&expr.Ct{Key: expr.CtKeyAVGPKT, Register: 1, Direction: dir, OptDirection: optDir},
			&expr.Cmp{Op: newOp, Register: 1, Data: avgpktData},
		)
		newExprs = append(newExprs, rule.Exprs[insertIdx:]...)
		rule.Exprs = newExprs
	}

	f.originalOp = nft.CompareOp(f.opInput.Value())
	f.originalValue = newAvgpkt
	f.originalDir = newDirection
	f.valueInput.Blur()
	f.directionInput.Blur()
}

func (f *CtAvgpktField) View() string {
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
		lipgloss.NewStyle().Width(24).Render(vVal),
		lipgloss.NewStyle().Render(vDir),
	)
	return grayStyle.Render("CT avgpkt") + "\n" + inputs + "\n"
}
