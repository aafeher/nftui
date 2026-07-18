package ui

import (
	"fmt"
	"strings"

	"nftui/i18n"
	"nftui/nft"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

var verdictKindOptions = []string{"accept", "drop", "return", "jump", "goto"}

// VerdictField edits a rule's verdict (the rule's final action).
// FocusSlots reports 2 when the selected kind is jump/goto (kind + chain target),
// 1 otherwise. If the rule does not contain a verdict the field is read-only and
// reports 1 inert slot.
type VerdictField struct {
	kindSelect    Select
	chainInput    textinput.Model
	hasVerdict    bool
	originalKind  nft.VerdictKind
	originalChain string
}

func NewVerdictField(rd *nft.Rule) *VerdictField {
	kindSelect := NewSelect(verdictKindOptions)
	kindSelect.Width = 36

	chainInput := textinput.New()
	chainInput.Placeholder = "target chain"
	chainInput.CharLimit = 256
	chainInput.Width = 32

	var origKind nft.VerdictKind
	var origChain string
	hasVerdict := false
	for _, a := range rd.Actions {
		if a.Type == nft.ActionTypeVerdict && a.Verdict != nil {
			origKind = a.Verdict.Kind
			origChain = a.Verdict.Chain
			hasVerdict = true
			break
		}
	}
	if hasVerdict {
		kindSelect.SetValue(string(origKind))
		chainInput.SetValue(origChain)
	}

	return &VerdictField{
		kindSelect:    kindSelect,
		chainInput:    chainInput,
		hasVerdict:    hasVerdict,
		originalKind:  origKind,
		originalChain: origChain,
	}
}

func (f *VerdictField) currentKind() nft.VerdictKind {
	return nft.VerdictKind(f.kindSelect.Value())
}

func (f *VerdictField) needsChain() bool {
	if !f.hasVerdict {
		return false
	}
	k := f.currentKind()
	return k == nft.VerdictJump || k == nft.VerdictGoto
}

func (f *VerdictField) FocusSlots() int {
	if f.needsChain() {
		return 2
	}
	return 1
}

func (f *VerdictField) Focus(subIndex int) {
	if !f.hasVerdict {
		return
	}
	if subIndex == 0 {
		f.kindSelect.Focus()
		f.chainInput.Blur()
		return
	}
	f.chainInput.Focus()
	f.kindSelect.Blur()
}

func (f *VerdictField) Blur() {
	f.kindSelect.Blur()
	f.chainInput.Blur()
}

func (f *VerdictField) Changed() bool {
	if !f.hasVerdict {
		return false
	}
	k := f.currentKind()
	if k != f.originalKind {
		return true
	}
	if (k == nft.VerdictJump || k == nft.VerdictGoto) && f.chainInput.Value() != f.originalChain {
		return true
	}
	return false
}

func (f *VerdictField) Update(msg tea.Msg) tea.Cmd {
	if !f.hasVerdict {
		return nil
	}
	var cmd tea.Cmd
	if f.kindSelect.Focused {
		f.kindSelect, cmd = f.kindSelect.Update(msg)
		if !f.needsChain() {
			f.chainInput.Blur()
		}
	} else if f.chainInput.Focused() {
		f.chainInput, cmd = f.chainInput.Update(msg)
	}
	return cmd
}

// ValidateForSave returns an error describing why the field cannot be saved.
// Called by rule_edit before any field's Save mutates the rule.
func (f *VerdictField) ValidateForSave() error {
	if !f.hasVerdict || !f.Changed() {
		return nil
	}
	k := f.currentKind()
	if k == nft.VerdictJump || k == nft.VerdictGoto {
		if strings.TrimSpace(f.chainInput.Value()) == "" {
			return fmt.Errorf("verdict %q requires a target chain name", k)
		}
	}
	return nil
}

func (f *VerdictField) Save(rule *nftables.Rule) {
	if !f.hasVerdict || !f.Changed() {
		return
	}
	newKind := f.currentKind()
	newChain := ""
	if newKind == nft.VerdictJump || newKind == nft.VerdictGoto {
		newChain = strings.TrimSpace(f.chainInput.Value())
	}

	newVerdict := &expr.Verdict{
		Kind:  verdictKindToExpr(newKind),
		Chain: newChain,
	}

	// Replace the existing verdict expression in place. Two shapes can appear in
	// rule.Exprs: a *expr.Verdict (the usual re-parsed form), or a *expr.Immediate
	// writing into the verdict register (NFT_REG_VERDICT) when re-parse didn't
	// trigger. Both are valid wire-level representations of the rule's final
	// verdict — replace whichever is present.
	replaced := false
	for i, re := range rule.Exprs {
		if _, ok := re.(*expr.Verdict); ok {
			rule.Exprs[i] = newVerdict
			replaced = true
			break
		}
		if imm, ok := re.(*expr.Immediate); ok && imm.Register == unix.NFT_REG_VERDICT {
			rule.Exprs[i] = newVerdict
			replaced = true
			break
		}
	}
	if !replaced {
		rule.Exprs = append(rule.Exprs, newVerdict)
	}

	f.originalKind = newKind
	f.originalChain = newChain
	f.kindSelect.Changed = false
}

func (f *VerdictField) View() string {
	label := grayStyle.Render("Verdict")
	if !f.hasVerdict {
		return label + "\n" + grayStyle.Render(i18n.T("rule.field.no_verdict")) + "\n"
	}

	vSel := f.kindSelect.View()
	if f.currentKind() != f.originalKind {
		vSel = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vSel)
	}
	current := renderVerdict(nft.VerdictAction{Kind: f.currentKind(), Chain: f.chainInput.Value()})
	left := label + "\n" + vSel + "\n" + grayStyle.Render(i18n.T("rule.field.current")) + current

	if !f.needsChain() {
		return left + "\n"
	}

	chainLabel := grayStyle.Render("Target chain")
	vChain := f.chainInput.View()
	if f.chainInput.Value() != f.originalChain {
		vChain = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vChain)
	}
	right := chainLabel + "\n" + vChain

	return lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(44).Render(left),
		lipgloss.NewStyle().Render(right),
	) + "\n"
}

func verdictKindToExpr(k nft.VerdictKind) expr.VerdictKind {
	switch k {
	case nft.VerdictAccept:
		return expr.VerdictAccept
	case nft.VerdictDrop:
		return expr.VerdictDrop
	case nft.VerdictReturn:
		return expr.VerdictReturn
	case nft.VerdictJump:
		return expr.VerdictJump
	case nft.VerdictGoto:
		return expr.VerdictGoto
	}
	return expr.VerdictDrop
}
