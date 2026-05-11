package ui

import (
	"strings"

	"nftui/nft"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
)

type chainCreateKeyMap struct {
	NextField key.Binding
	PrevField key.Binding
	Save      key.Binding
	Back      key.Binding
	Quit      key.Binding
}

func (k chainCreateKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.NextField, k.PrevField, k.Save, k.Back, k.Quit}
}

func (k chainCreateKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.NextField, k.PrevField},
		{k.Save, k.Back, k.Quit},
	}
}

var chainKindOptions = []string{"regular", "base"}

// chainCreate is the new-chain dialog. It hosts the same field set as
// chainEdit, plus a "kind" Select that toggles base-only fields. Slot layout:
//
//	0: name (always)
//	1: kind (always)
//	2: type     ┐
//	3: hook     │ only when kind == "base"
//	4: priority │
//	5: policy   ┘
type chainCreate struct {
	table *nftables.Table

	nameInput    textinput.Model
	kindSelect   Select
	typeSelect   Select
	hookSelect   Select
	prioInput    NumberInput
	policySelect Select

	focusSlot int

	statusMsg string
	width     int
	height    int
	keys      chainCreateKeyMap
	help      help.Model
}

func newChainCreate(table *nftables.Table) chainCreate {
	ti := textinput.New()
	ti.CharLimit = 64
	ti.Width = 40

	ks := NewSelect(chainKindOptions)
	ks.Selected = 1 // base by default — the common case for filter tables

	typeOpts := nft.ValidChainTypesForFamily(table.Family)
	ts := NewSelect(typeOpts)
	ts.Selected = indexOf(typeOpts, "filter")

	hookOpts := nft.ValidChainHooksForTypeFamily(ts.Value(), table.Family)
	hs := NewSelect(hookOpts)
	hs.Selected = indexOf(hookOpts, "input")

	pri := NewNumberInput(-2147483648, 2147483647)
	pri.SetValue("0")

	ps := NewSelect(chainPolicyOptions)
	ps.Selected = indexOf(chainPolicyOptions, "accept")

	km := chainCreateKeyMap{
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

	cc := chainCreate{
		table:        table,
		nameInput:    ti,
		kindSelect:   ks,
		typeSelect:   ts,
		hookSelect:   hs,
		prioInput:    pri,
		policySelect: ps,
		focusSlot:    0,
		keys:         km,
		help:         newHelpModel(),
	}
	cc.applyFocus()
	return cc
}

func (cc chainCreate) isBase() bool {
	return cc.kindSelect.Value() == "base"
}

func (cc chainCreate) slotCount() int {
	if cc.isBase() {
		return 6
	}
	return 2
}

func (cc *chainCreate) applyFocus() {
	cc.nameInput.Blur()
	cc.kindSelect.Blur()
	cc.typeSelect.Blur()
	cc.hookSelect.Blur()
	cc.prioInput.Blur()
	cc.policySelect.Blur()

	switch cc.focusSlot {
	case 0:
		cc.nameInput.Focus()
	case 1:
		cc.kindSelect.Focus()
	case 2:
		cc.typeSelect.Focus()
	case 3:
		cc.hookSelect.Focus()
	case 4:
		cc.prioInput.Focus()
	case 5:
		cc.policySelect.Focus()
	}
}

func (cc chainCreate) Update(msg tea.Msg) (chainCreate, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		cc.width, cc.height = msg.Width, msg.Height
		return cc, nil

	case chainOpErrMsg:
		cc.statusMsg = msg.err.Error()
		return cc, nil

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, cc.keys.NextField):
			cc.focusSlot = (cc.focusSlot + 1) % cc.slotCount()
			cc.applyFocus()
			return cc, nil
		case key.Matches(msg, cc.keys.PrevField):
			n := cc.slotCount()
			cc.focusSlot = (cc.focusSlot - 1 + n) % n
			cc.applyFocus()
			return cc, nil
		case key.Matches(msg, cc.keys.Save):
			name := strings.TrimSpace(cc.nameInput.Value())
			if name == "" {
				cc.statusMsg = "Name cannot be empty."
				return cc, nil
			}
			cc.statusMsg = ""
			return cc, createChainCmd(cc.table, cc.buildSpec(name))
		}
	}

	var cmd tea.Cmd
	switch cc.focusSlot {
	case 0:
		cc.nameInput, cmd = cc.nameInput.Update(msg)
	case 1:
		prevKind := cc.kindSelect.Value()
		cc.kindSelect, cmd = cc.kindSelect.Update(msg)
		if cc.kindSelect.Value() != prevKind {
			// If switching from base to regular we keep the focus on the
			// kind field; the slotCount shrinks so we don't need to move.
			// Going the other way also keeps focus on kind, which is fine.
		}
	case 2:
		prevType := cc.typeSelect.Value()
		cc.typeSelect, cmd = cc.typeSelect.Update(msg)
		if cc.typeSelect.Value() != prevType {
			cc.syncHookOptions()
		}
	case 3:
		cc.hookSelect, cmd = cc.hookSelect.Update(msg)
	case 4:
		cc.prioInput, cmd = cc.prioInput.Update(msg)
	case 5:
		cc.policySelect, cmd = cc.policySelect.Update(msg)
	}
	return cc, cmd
}

func (cc *chainCreate) syncHookOptions() {
	validHooks := nft.ValidChainHooksForTypeFamily(cc.typeSelect.Value(), cc.table.Family)
	current := cc.hookSelect.Value()

	newSel := 0
	for i, h := range validHooks {
		if h == current {
			newSel = i
			break
		}
	}

	focused := cc.hookSelect.Focused
	cc.hookSelect = NewSelect(validHooks)
	cc.hookSelect.Selected = newSel
	if focused {
		cc.hookSelect.Focus()
	}
}

// buildSpec constructs a *nftables.Chain from the current form state.
// Table is intentionally left nil here; nft.CreateChain takes the table as a
// separate argument.
func (cc chainCreate) buildSpec(name string) *nftables.Chain {
	spec := &nftables.Chain{Name: name}
	if !cc.isBase() {
		return spec
	}
	spec.Type = nft.ChainTypeFromString(cc.typeSelect.Value())
	spec.Hooknum = nft.ChainHookFromString(cc.hookSelect.Value())
	prio := nftables.ChainPriority(cc.prioInput.GetValue())
	spec.Priority = &prio
	if pol, ok := nft.ChainPolicyFromString(cc.policySelect.Value()); ok {
		spec.Policy = &pol
	}
	return spec
}

func (cc chainCreate) View() string {
	header := blueBoldStyle.Render("nftui nftables manager")

	divider := grayStyle.
		Width(cc.width).
		Render(strings.Repeat("─", cc.width))

	var body strings.Builder
	body.WriteString(defaultBoldStyle.Render("Create new chain"))
	body.WriteString("\n\n")

	body.WriteString(grayStyle.Render("Table    : "))
	body.WriteString(blueStyle.Render(cc.table.Name))
	body.WriteString(grayStyle.Render(" ("))
	body.WriteString(nft.TableFamilyToString(cc.table.Family))
	body.WriteString(grayStyle.Render(")"))
	body.WriteString("\n\n")

	body.WriteString(grayStyle.Render("Name     : "))
	body.WriteString(cc.nameInput.View())
	body.WriteString("\n\n")

	body.WriteString(grayStyle.Render("Kind     : "))
	body.WriteString(cc.kindSelect.View())
	body.WriteString("\n")

	if cc.isBase() {
		body.WriteString("\n")
		body.WriteString(grayStyle.Render("Type     : "))
		body.WriteString(cc.typeSelect.View())
		body.WriteString("\n\n")

		body.WriteString(grayStyle.Render("Hook     : "))
		body.WriteString(cc.hookSelect.View())
		body.WriteString("\n\n")

		body.WriteString(grayStyle.Render("Priority : "))
		body.WriteString(cc.prioInput.View())
		body.WriteString("\n\n")

		body.WriteString(grayStyle.Render("Policy   : "))
		body.WriteString(cc.policySelect.View())
		body.WriteString("\n")
	}

	if cc.statusMsg != "" {
		body.WriteString("\n")
		body.WriteString(redBoldStyle.Render("Error: " + cc.statusMsg))
	}

	contentBox := normalGrayBorder.
		Width(cc.width-2).
		Height(cc.height-8).
		Padding(1, 2).
		Render(body.String())

	footer := cc.help.View(cc.keys)

	return defaultStyle.Render(lipgloss.JoinVertical(lipgloss.Left,
		header,
		divider,
		contentBox,
		footer,
	))
}
