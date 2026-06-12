package ui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/nft"
)

// CtCountField edits the ct count (connlimit) condition.
// nft CLI encoding (verified via `nft --debug=netlink`): "over" = Flags==NFT_CONNLIMIT_F_INV
// (matches when count > N); no "over" = Flags==0 (matches when count <= N).
type CtCountField struct {
	overInput     Select
	countInput    NumberInput
	originalOver  bool // true when Flags == NFT_CONNLIMIT_F_INV
	originalCount uint32
}

func NewCtCountField(rd *nft.Rule) *CtCountField {
	overInput := NewSelect([]string{"", "over"})
	overInput.Width = 6

	countInput := NewNumberInput(0, 4_294_967_295)
	countInput.Placeholder = "0"
	countInput.CharLimit = 10
	countInput.Width = 12

	var originalOver bool
	var originalCount uint32

	for _, condition := range rd.Conditions {
		if condition.Connlimit != nil {
			originalOver = condition.Connlimit.Flags&expr.NFT_CONNLIMIT_F_INV != 0
			originalCount = condition.Connlimit.Count
		}
	}

	if originalOver {
		overInput.SetValue("over")
	} else {
		overInput.SetValue("")
	}
	if originalCount > 0 {
		countInput.SetValue(fmt.Sprint(originalCount))
	}

	return &CtCountField{
		overInput:     overInput,
		countInput:    countInput,
		originalOver:  originalOver,
		originalCount: originalCount,
	}
}

func (f *CtCountField) FocusSlots() int { return 2 }

func (f *CtCountField) Focus(subIndex int) {
	switch subIndex {
	case 0:
		f.overInput.Focus()
	default:
		f.countInput.Focus()
	}
}

func (f *CtCountField) Blur() {
	f.overInput.Blur()
	f.countInput.Blur()
}

func (f *CtCountField) overChanged() bool {
	return (f.overInput.Value() == "over") != f.originalOver
}

func (f *CtCountField) countChanged() bool {
	val, _ := f.countInput.GetUint64()
	return uint32(val) != f.originalCount
}

func (f *CtCountField) Changed() bool {
	return f.overChanged() || f.countChanged()
}

func (f *CtCountField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	if f.overInput.Focused {
		f.overInput, cmd = f.overInput.Update(msg)
	} else if f.countInput.Focused() {
		f.countInput, cmd = f.countInput.Update(msg)
	}
	return cmd
}

func (f *CtCountField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	val, err := f.countInput.GetUint64()
	if err != nil {
		return
	}
	newCount := uint32(val)
	var newFlags uint32
	if f.overInput.Value() == "over" {
		newFlags = expr.NFT_CONNLIMIT_F_INV
	}

	found := false
	for _, re := range rule.Exprs {
		if cl, ok := re.(*expr.Connlimit); ok {
			found = true
			cl.Count = newCount
			cl.Flags = newFlags
		}
	}

	if !found && (newCount > 0 || f.overChanged()) {
		// Find verdict position to insert before it.
		insertIdx := len(rule.Exprs)
		for i, re := range rule.Exprs {
			if _, ok := re.(*expr.Verdict); ok {
				insertIdx = i
				break
			}
		}
		newExprs := make([]expr.Any, 0, len(rule.Exprs)+1)
		newExprs = append(newExprs, rule.Exprs[:insertIdx]...)
		newExprs = append(newExprs, &expr.Connlimit{Count: newCount, Flags: newFlags})
		newExprs = append(newExprs, rule.Exprs[insertIdx:]...)
		rule.Exprs = newExprs
	}

	f.originalOver = f.overInput.Value() == "over"
	f.originalCount = newCount
	f.countInput.Blur()
}

func (f *CtCountField) View() string {
	vOver := f.overInput.View()
	if f.overChanged() {
		vOver = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vOver)
	}
	vCount := f.countInput.View()
	if f.countChanged() {
		vCount = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vCount)
	}
	inputs := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(8).Render(vOver),
		lipgloss.NewStyle().Width(14).Render(vCount),
	)
	return grayStyle.Render("CT count") + "\n" + inputs + "\n"
}
