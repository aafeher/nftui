package ui

import (
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"

	"nftui/nft"
)

type tableCreateKeyMap struct {
	NextField key.Binding
	PrevField key.Binding
	Save      key.Binding
	Back      key.Binding
	Quit      key.Binding
}

func (k tableCreateKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.NextField, k.PrevField, k.Save, k.Back, k.Quit}
}

func (k tableCreateKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.NextField, k.PrevField},
		{k.Save, k.Back, k.Quit},
	}
}

const (
	tcSlotFamily = 0
	tcSlotName   = 1
	tcSlotCount  = 2
)

type tableCreate struct {
	familySelect Select
	nameInput    textinput.Model
	focusSlot    int
	statusMsg    string
	width        int
	height       int
	keys         tableCreateKeyMap
	help         help.Model
}

var familyOptions = []string{"ipv4", "ipv6", "inet", "arp", "bridge", "netdev"}

func familyFromOption(opt string) nftables.TableFamily {
	switch opt {
	case "ipv4":
		return nftables.TableFamilyIPv4
	case "ipv6":
		return nftables.TableFamilyIPv6
	case "inet":
		return nftables.TableFamilyINet
	case "arp":
		return nftables.TableFamilyARP
	case "bridge":
		return nftables.TableFamilyBridge
	case "netdev":
		return nftables.TableFamilyNetdev
	default:
		return nftables.TableFamilyINet
	}
}

func newTableCreate() tableCreate {
	fs := NewSelect(familyOptions)
	fs.Selected = 0
	fs.Focus()

	ti := textinput.New()
	ti.CharLimit = 64
	ti.Width = 40

	km := tableCreateKeyMap{
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

	return tableCreate{
		familySelect: fs,
		nameInput:    ti,
		focusSlot:    tcSlotFamily,
		keys:         km,
		help:         newHelpModel(),
	}
}

func (tc *tableCreate) applyFocus() {
	if tc.focusSlot == tcSlotFamily {
		tc.familySelect.Focus()
		tc.nameInput.Blur()
	} else {
		tc.familySelect.Blur()
		tc.nameInput.Focus()
	}
}

func (tc tableCreate) Update(msg tea.Msg) (tableCreate, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		tc.width, tc.height = msg.Width, msg.Height
		return tc, nil

	case tableOpErrMsg:
		tc.statusMsg = msg.err.Error()
		return tc, nil

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, tc.keys.NextField):
			tc.focusSlot = (tc.focusSlot + 1) % tcSlotCount
			tc.applyFocus()
			return tc, nil
		case key.Matches(msg, tc.keys.PrevField):
			tc.focusSlot = (tc.focusSlot - 1 + tcSlotCount) % tcSlotCount
			tc.applyFocus()
			return tc, nil
		case key.Matches(msg, tc.keys.Save):
			name := strings.TrimSpace(tc.nameInput.Value())
			if err := nft.ValidateIdentifier(name); err != nil {
				tc.statusMsg = err.Error()
				return tc, nil
			}
			family := familyFromOption(tc.familySelect.Value())
			tc.statusMsg = ""
			return tc, createTableCmd(family, name)
		}
	}

	var cmd tea.Cmd
	if tc.focusSlot == tcSlotFamily {
		tc.familySelect, cmd = tc.familySelect.Update(msg)
	} else {
		tc.nameInput, cmd = tc.nameInput.Update(msg)
	}
	return tc, cmd
}

func (tc tableCreate) View() string {
	header := blueBoldStyle.Render("nftui nftables manager")

	divider := grayStyle.
		Width(tc.width).
		Render(strings.Repeat("─", tc.width))

	var body strings.Builder
	body.WriteString(defaultBoldStyle.Render("Create new table"))
	body.WriteString("\n\n")

	body.WriteString(grayStyle.Render("Family : "))
	body.WriteString(tc.familySelect.View())
	body.WriteString("\n\n")

	body.WriteString(grayStyle.Render("Name   : "))
	body.WriteString(tc.nameInput.View())

	if tc.statusMsg != "" {
		body.WriteString("\n\n")
		body.WriteString(redBoldStyle.Render("Error: " + tc.statusMsg))
	}

	contentBox := normalGrayBorder.
		Width(tc.width-2).
		Height(tc.height-8).
		Padding(1, 2).
		Render(body.String())

	footer := tc.help.View(tc.keys)

	return defaultStyle.Render(lipgloss.JoinVertical(lipgloss.Left,
		header,
		divider,
		contentBox,
		footer,
	))
}
