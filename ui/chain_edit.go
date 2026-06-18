package ui

import (
	"strconv"
	"strings"

	"nftui/nft"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
)

type chainEditKeyMap struct {
	NextField key.Binding
	PrevField key.Binding
	Save      key.Binding
	Back      key.Binding
	Quit      key.Binding
}

func (k chainEditKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.NextField, k.PrevField, k.Save, k.Back, k.Quit}
}

func (k chainEditKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.NextField, k.PrevField},
		{k.Save, k.Back, k.Quit},
	}
}

var chainPolicyOptions = []string{"accept", "drop"}

// chainEdit edits an existing chain. For base chains all of {name, type, hook,
// priority, policy} are editable; for regular chains only the name is editable.
type chainEdit struct {
	chain  *nftables.Chain // original, immutable while editing
	isBase bool

	nameInput    textinput.Model
	typeSelect   Select
	hookSelect   Select
	prioInput    NumberInput
	policySelect Select

	focusSlot int
	slotCount int

	statusMsg string
	width     int
	height    int
	keys      chainEditKeyMap
	help      help.Model
}

func newChainEdit(chain *nftables.Chain) chainEdit {
	isBase := chain.Hooknum != nil

	ti := textinput.New()
	ti.SetValue(chain.Name)
	ti.CharLimit = 64
	ti.Width = 40

	typeOpts := nft.ValidChainTypesForFamily(chain.Table.Family)
	ts := NewSelect(typeOpts)
	ts.Selected = indexOf(typeOpts, string(chain.Type))

	hookOpts := nft.ValidChainHooksForTypeFamily(string(chain.Type), chain.Table.Family)
	hs := NewSelect(hookOpts)
	if chain.Hooknum != nil {
		hs.Selected = indexOf(hookOpts, nft.ChainHookNumToString(*chain.Hooknum))
	}

	pri := NewNumberInput(-2147483648, 2147483647)
	if chain.Priority != nil {
		pri.SetValue(strconv.Itoa(int(*chain.Priority)))
	} else {
		pri.SetValue("0")
	}

	ps := NewSelect(chainPolicyOptions)
	if chain.Policy != nil {
		ps.Selected = indexOf(chainPolicyOptions, nft.ChainPolicyToString(*chain.Policy))
	}

	km := chainEditKeyMap{
		NextField: key.NewBinding(
			key.WithKeys("tab", "down"),
			key.WithHelp("tab/↓", "next field"),
		),
		PrevField: key.NewBinding(
			key.WithKeys("shift+tab", "up"),
			key.WithHelp("shift+tab/↑", "prev field"),
		),
		Save: key.NewBinding(
			key.WithKeys("f2"),
			key.WithHelp("f2", "save"),
		),
		Back: key.NewBinding(
			key.WithKeys("esc", "f3"),
			key.WithHelp("esc/f3", "cancel"),
		),
		Quit: key.NewBinding(
			key.WithKeys("ctrl+c"),
			key.WithHelp("ctrl+c", "quit"),
		),
	}

	slotCount := 1 // name
	if isBase {
		slotCount = 5 // name, type, hook, priority, policy
	}

	ce := chainEdit{
		chain:        chain,
		isBase:       isBase,
		nameInput:    ti,
		typeSelect:   ts,
		hookSelect:   hs,
		prioInput:    pri,
		policySelect: ps,
		focusSlot:    0,
		slotCount:    slotCount,
		keys:         km,
		help:         newHelpModel(),
	}
	ce.applyFocus()
	return ce
}

func (ce *chainEdit) applyFocus() {
	ce.nameInput.Blur()
	ce.typeSelect.Blur()
	ce.hookSelect.Blur()
	ce.prioInput.Blur()
	ce.policySelect.Blur()

	switch ce.focusSlot {
	case 0:
		ce.nameInput.Focus()
	case 1:
		ce.typeSelect.Focus()
	case 2:
		ce.hookSelect.Focus()
	case 3:
		ce.prioInput.Focus()
	case 4:
		ce.policySelect.Focus()
	}
}

func (ce chainEdit) Update(msg tea.Msg) (chainEdit, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		ce.width, ce.height = msg.Width, msg.Height
		return ce, nil

	case chainOpErrMsg:
		ce.statusMsg = msg.err.Error()
		return ce, nil

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, ce.keys.NextField):
			ce.focusSlot = (ce.focusSlot + 1) % ce.slotCount
			ce.applyFocus()
			return ce, nil
		case key.Matches(msg, ce.keys.PrevField):
			ce.focusSlot = (ce.focusSlot - 1 + ce.slotCount) % ce.slotCount
			ce.applyFocus()
			return ce, nil
		case key.Matches(msg, ce.keys.Save):
			name := strings.TrimSpace(ce.nameInput.Value())
			if err := nft.ValidateIdentifier(name); err != nil {
				ce.statusMsg = err.Error()
				return ce, nil
			}
			newSpec := ce.buildNewSpec(name)
			if !ce.hasChanges(name, newSpec) {
				// No-op save — just go back without hitting the kernel.
				return ce, func() tea.Msg { return chainUpdatedMsg{} }
			}
			ce.statusMsg = ""
			return ce, updateChainCmd(ce.chain, newSpec)
		}
	}

	var cmd tea.Cmd
	switch ce.focusSlot {
	case 0:
		ce.nameInput, cmd = ce.nameInput.Update(msg)
	case 1:
		prevType := ce.typeSelect.Value()
		ce.typeSelect, cmd = ce.typeSelect.Update(msg)
		if ce.typeSelect.Value() != prevType {
			ce.syncHookOptions()
		}
	case 2:
		ce.hookSelect, cmd = ce.hookSelect.Update(msg)
	case 3:
		ce.prioInput, cmd = ce.prioInput.Update(msg)
	case 4:
		ce.policySelect, cmd = ce.policySelect.Update(msg)
	}
	return ce, cmd
}

// syncHookOptions rebuilds the hook Select to contain only the hooks valid for
// the currently selected chain type and the chain's table family. The user's
// hook choice is preserved if it remains valid; otherwise it falls back to
// the first valid hook and the Select is marked Changed.
func (ce *chainEdit) syncHookOptions() {
	if !ce.isBase {
		return
	}
	validHooks := nft.ValidChainHooksForTypeFamily(ce.typeSelect.Value(), ce.chain.Table.Family)
	current := ce.hookSelect.Value()

	newSel := 0
	matched := false
	for i, h := range validHooks {
		if h == current {
			newSel = i
			matched = true
			break
		}
	}

	focused := ce.hookSelect.Focused
	ce.hookSelect = NewSelect(validHooks)
	ce.hookSelect.Selected = newSel
	if focused {
		ce.hookSelect.Focus()
	}
	if !matched {
		// User's previous hook is no longer valid for the new type; the
		// effective value has changed even though the user didn't touch
		// the hook field directly.
		ce.hookSelect.Changed = true
	}
}

// buildNewSpec constructs a *nftables.Chain reflecting the user's edits. For
// regular chains, all base-only fields are left zero/nil.
func (ce chainEdit) buildNewSpec(name string) *nftables.Chain {
	spec := &nftables.Chain{Name: name, Table: ce.chain.Table}
	if !ce.isBase {
		return spec
	}
	spec.Type = nft.ChainTypeFromString(ce.typeSelect.Value())
	spec.Hooknum = nft.ChainHookFromString(ce.hookSelect.Value())
	prio := nftables.ChainPriority(ce.prioInput.GetValue())
	spec.Priority = &prio
	if pol, ok := nft.ChainPolicyFromString(ce.policySelect.Value()); ok {
		spec.Policy = &pol
	}
	return spec
}

func (ce chainEdit) hasChanges(name string, spec *nftables.Chain) bool {
	if name != ce.chain.Name {
		return true
	}
	if !ce.isBase {
		return false
	}
	if spec.Type != ce.chain.Type {
		return true
	}
	if (spec.Hooknum == nil) != (ce.chain.Hooknum == nil) {
		return true
	}
	if spec.Hooknum != nil && ce.chain.Hooknum != nil && *spec.Hooknum != *ce.chain.Hooknum {
		return true
	}
	if (spec.Priority == nil) != (ce.chain.Priority == nil) {
		return true
	}
	if spec.Priority != nil && ce.chain.Priority != nil && *spec.Priority != *ce.chain.Priority {
		return true
	}
	if (spec.Policy == nil) != (ce.chain.Policy == nil) {
		return true
	}
	if spec.Policy != nil && ce.chain.Policy != nil && *spec.Policy != *ce.chain.Policy {
		return true
	}
	return false
}

func (ce chainEdit) View() string {
	header := blueBoldStyle.Render("nftui nftables manager")

	divider := grayStyle.
		Width(ce.width).
		Render(strings.Repeat("─", ce.width))

	var body strings.Builder
	body.WriteString(defaultBoldStyle.Render("Edit chain"))
	body.WriteString("\n\n")

	body.WriteString(grayStyle.Render("Table    : "))
	body.WriteString(blueStyle.Render(ce.chain.Table.Name))
	body.WriteString(grayStyle.Render(" ("))
	body.WriteString(nft.TableFamilyToString(ce.chain.Table.Family))
	body.WriteString(grayStyle.Render(")"))
	body.WriteString("\n\n")

	body.WriteString(grayStyle.Render("Name     : "))
	body.WriteString(ce.nameInput.View())
	body.WriteString("\n")

	if ce.isBase {
		body.WriteString("\n")
		body.WriteString(grayStyle.Render("Type     : "))
		body.WriteString(ce.typeSelect.View())
		body.WriteString("\n\n")

		body.WriteString(grayStyle.Render("Hook     : "))
		body.WriteString(ce.hookSelect.View())
		body.WriteString("\n\n")

		body.WriteString(grayStyle.Render("Priority : "))
		body.WriteString(ce.prioInput.View())
		body.WriteString("\n\n")

		body.WriteString(grayStyle.Render("Policy   : "))
		body.WriteString(ce.policySelect.View())
		body.WriteString("\n")
	} else {
		body.WriteString("\n")
		body.WriteString(grayStyle.Render("(regular chain — only the name can be edited)"))
		body.WriteString("\n")
	}

	if ce.statusMsg != "" {
		body.WriteString("\n")
		body.WriteString(redBoldStyle.Render("Error: " + ce.statusMsg))
	}

	contentBox := normalGrayBorder.
		Width(ce.width-2).
		Height(ce.height-8).
		Padding(1, 2).
		Render(body.String())

	footer := ce.help.View(ce.keys)

	return defaultStyle.Render(lipgloss.JoinVertical(lipgloss.Left,
		header,
		divider,
		contentBox,
		footer,
	))
}

// indexOf returns the index of s in opts, or 0 if not found.
func indexOf(opts []string, s string) int {
	for i, o := range opts {
		if o == s {
			return i
		}
	}
	return 0
}
