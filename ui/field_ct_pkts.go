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

type CtPktsField struct {
	valueInput     NumberInput
	directionInput Select
	originalValue  uint64
	originalDir    nftexpr.CtDirection
}

func NewCtPktsField(rd *nft.Rule) *CtPktsField {
	valueInput := NewNumberInput(0, 9_223_372_036_854_775_807)
	valueInput.Placeholder = "0"
	valueInput.CharLimit = 20
	valueInput.Width = 20

	directionInput := NewSelect(append([]string{""}, nftexpr.CtDirectionStrings...))
	directionInput.Width = 10

	var originalValue uint64
	var originalDir nftexpr.CtDirection

	for _, condition := range rd.Conditions {
		if condition.CT != nil && condition.CT.Key == nftexpr.CtKeyPkts {
			if p, ok := condition.CT.Value.(uint64); ok {
				originalValue = p
			}
			originalDir = condition.CT.Direction
		}
	}

	if originalValue > 0 {
		valueInput.SetValue(fmt.Sprint(originalValue))
	} else {
		valueInput.SetValue("")
	}
	directionInput.SetValue(string(originalDir))

	return &CtPktsField{
		valueInput:     valueInput,
		directionInput: directionInput,
		originalValue:  originalValue,
		originalDir:    originalDir,
	}
}

func (f *CtPktsField) FocusSlots() int { return 2 }

func (f *CtPktsField) Focus(subIndex int) {
	if subIndex == 0 {
		f.valueInput.Focus()
	} else {
		f.directionInput.Focus()
	}
}

func (f *CtPktsField) Blur() {
	f.valueInput.Blur()
	f.directionInput.Blur()
}

func (f *CtPktsField) valueChanged() bool {
	val, _ := f.valueInput.GetUint64()
	return val != f.originalValue
}

func (f *CtPktsField) dirChanged() bool {
	return f.directionInput.Value() != string(f.originalDir)
}

func (f *CtPktsField) Changed() bool {
	return f.valueChanged() || f.dirChanged()
}

func (f *CtPktsField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.valueInput.Focused() {
		f.valueInput, cmd = f.valueInput.Update(msg)
	} else if f.directionInput.Focused {
		f.directionInput, cmd = f.directionInput.Update(msg)
	}
	return cmd
}

func (f *CtPktsField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	val, err := f.valueInput.GetUint64()
	if err != nil {
		return
	}
	newPkts := val
	newDirectionStr := f.directionInput.Value()
	var newDirection nftexpr.CtDirection
	if newDirectionStr != "" {
		newDirection = nftexpr.CtDirection(newDirectionStr)
	} else {
		newDirection = nftexpr.CtDirectionNone
	}

	found := false
	for i, re := range rule.Exprs {
		switch e := re.(type) {
		case *expr.Ct:
			if e.Key == expr.CtKeyPKTS {
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
						cmp.Data = binary.LittleEndian.AppendUint64(nil, newPkts)
					}
				}
			}
		}
	}
	if !found && newPkts > 0 {
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
		newExprs = append(newExprs, &expr.Ct{
			Key:          expr.CtKeyPKTS,
			Register:     1,
			Direction:    dir,
			OptDirection: optDir,
		}, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binary.LittleEndian.AppendUint64(nil, newPkts),
		})
		newExprs = append(newExprs, rule.Exprs[insertIdx:]...)
		rule.Exprs = newExprs
	}
	f.originalValue = newPkts
	f.originalDir = newDirection
	f.valueInput.Blur()
	f.directionInput.Blur()
}

func (f *CtPktsField) View() string {
	vVal := f.valueInput.View()
	if f.valueChanged() {
		vVal = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vVal)
	}
	vDir := f.directionInput.View()
	if f.dirChanged() {
		vDir = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vDir)
	}
	return grayStyle.Render("CT Packets") + "\n" + vVal + "\n" +
		grayStyle.Render("CT Packets Direction") + "\n" + vDir + "\n"
}
