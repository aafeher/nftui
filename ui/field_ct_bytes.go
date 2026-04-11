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

type CtBytesField struct {
	valueInput     NumberInput
	directionInput Select
	originalValue  uint64
	originalDir    nftexpr.CtDirection
}

func NewCtBytesField(rd *nft.Rule) *CtBytesField {
	valueInput := NewNumberInput(0, 9_223_372_036_854_775_807)
	valueInput.Placeholder = "0"
	valueInput.CharLimit = 20
	valueInput.Width = 20

	directionInput := NewSelect(append([]string{""}, nftexpr.CtDirectionStrings...))
	directionInput.Width = 10

	var originalValue uint64
	var originalDir nftexpr.CtDirection

	for _, condition := range rd.Conditions {
		if condition.CT != nil && condition.CT.Key == nftexpr.CtKeyBytes {
			if b, ok := condition.CT.Value.(uint64); ok {
				originalValue = b
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

	return &CtBytesField{
		valueInput:     valueInput,
		directionInput: directionInput,
		originalValue:  originalValue,
		originalDir:    originalDir,
	}
}

func (f *CtBytesField) FocusSlots() int { return 2 }

func (f *CtBytesField) Focus(subIndex int) {
	if subIndex == 0 {
		f.valueInput.Focus()
	} else {
		f.directionInput.Focus()
	}
}

func (f *CtBytesField) Blur() {
	f.valueInput.Blur()
	f.directionInput.Blur()
}

func (f *CtBytesField) valueChanged() bool {
	val, _ := f.valueInput.GetUint64()
	return val != f.originalValue
}

func (f *CtBytesField) dirChanged() bool {
	return f.directionInput.Value() != string(f.originalDir)
}

func (f *CtBytesField) Changed() bool {
	return f.valueChanged() || f.dirChanged()
}

func (f *CtBytesField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.valueInput.Focused() {
		f.valueInput, cmd = f.valueInput.Update(msg)
	} else if f.directionInput.Focused {
		f.directionInput, cmd = f.directionInput.Update(msg)
	}
	return cmd
}

func (f *CtBytesField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	val, err := f.valueInput.GetUint64()
	if err != nil {
		return
	}
	newBytes := val
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
			if e.Key == expr.CtKeyBYTES {
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
						cmp.Data = binary.LittleEndian.AppendUint64(nil, newBytes)
					}
				}
			}
		}
	}
	if !found && newBytes > 0 {
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
			Key:          expr.CtKeyBYTES,
			Register:     1,
			Direction:    dir,
			OptDirection: optDir,
		}, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binary.LittleEndian.AppendUint64(nil, newBytes),
		})
		newExprs = append(newExprs, rule.Exprs[insertIdx:]...)
		rule.Exprs = newExprs
	}
	f.originalValue = newBytes
	f.originalDir = newDirection
	f.valueInput.Blur()
	f.directionInput.Blur()
}

func (f *CtBytesField) View() string {
	vVal := f.valueInput.View()
	if f.valueChanged() {
		vVal = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vVal)
	}
	vDir := f.directionInput.View()
	if f.dirChanged() {
		vDir = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vDir)
	}
	inputs := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(24).Render(vVal),
		lipgloss.NewStyle().Render(vDir),
	)
	return grayStyle.Render("CT Bytes") + "\n" + inputs + "\n"
}
