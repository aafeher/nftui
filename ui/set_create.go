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

// setCreate is the new-set dialog. Slot layout:
//
//	0: name        (textinput)
//	1: key type    (Select — ipv4_addr / ipv6_addr / ether_addr / ...)
//	2: constant    (Select on/off)
//	3: interval    (Select on/off)
//	4: timeout     (Select on/off)
//
// Keeping flag selectors as on/off Selects matches the rest of the form
// idiom in this codebase (chain_create.go). Map / dynamic / counter
// flavors aren't exposed yet — they need extra fields to be useful.
type setCreate struct {
	table *nftables.Table

	nameInput      textinput.Model
	keyTypeSelect  Select
	constantSelect Select
	intervalSelect Select
	timeoutSelect  Select

	focusSlot int
	statusMsg string
	width     int
	height    int
	keys      setCreateKeyMap
	help      help.Model
}

type setCreateKeyMap struct {
	NextField key.Binding
	PrevField key.Binding
	Save      key.Binding
	Back      key.Binding
	Quit      key.Binding
}

func (k setCreateKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.NextField, k.PrevField, k.Save, k.Back, k.Quit}
}
func (k setCreateKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{k.NextField, k.PrevField}, {k.Save, k.Back, k.Quit}}
}

var setOnOffOptions = []string{"off", "on"}

func newSetCreate(table *nftables.Table) setCreate {
	ti := textinput.New()
	ti.CharLimit = 64
	ti.Width = 40

	kt := NewSelect(nft.SupportedSetKeyTypes())
	kt.Selected = 0

	cs := NewSelect(setOnOffOptions)
	is := NewSelect(setOnOffOptions)
	ts := NewSelect(setOnOffOptions)

	km := setCreateKeyMap{
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

	sc := setCreate{
		table:          table,
		nameInput:      ti,
		keyTypeSelect:  kt,
		constantSelect: cs,
		intervalSelect: is,
		timeoutSelect:  ts,
		focusSlot:      0,
		keys:           km,
		help:           newHelpModel(),
	}
	sc.applyFocus()
	return sc
}

func (sc *setCreate) applyFocus() {
	sc.nameInput.Blur()
	sc.keyTypeSelect.Blur()
	sc.constantSelect.Blur()
	sc.intervalSelect.Blur()
	sc.timeoutSelect.Blur()
	switch sc.focusSlot {
	case 0:
		sc.nameInput.Focus()
	case 1:
		sc.keyTypeSelect.Focus()
	case 2:
		sc.constantSelect.Focus()
	case 3:
		sc.intervalSelect.Focus()
	case 4:
		sc.timeoutSelect.Focus()
	}
}

func (sc setCreate) Update(msg tea.Msg) (setCreate, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		sc.width, sc.height = msg.Width, msg.Height
		return sc, nil
	case setOpErrMsg:
		sc.statusMsg = msg.err.Error()
		return sc, nil
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, sc.keys.NextField):
			sc.focusSlot = (sc.focusSlot + 1) % 5
			sc.applyFocus()
			return sc, nil
		case key.Matches(msg, sc.keys.PrevField):
			sc.focusSlot = (sc.focusSlot - 1 + 5) % 5
			sc.applyFocus()
			return sc, nil
		case key.Matches(msg, sc.keys.Save):
			name := strings.TrimSpace(sc.nameInput.Value())
			if name == "" {
				sc.statusMsg = "Name cannot be empty."
				return sc, nil
			}
			kt, ok := nft.KeyTypeFromString(sc.keyTypeSelect.Value())
			if !ok {
				sc.statusMsg = "Unknown key type."
				return sc, nil
			}
			var flags []string
			if sc.constantSelect.Value() == "on" {
				flags = append(flags, "constant")
			}
			if sc.intervalSelect.Value() == "on" {
				flags = append(flags, "interval")
			}
			if sc.timeoutSelect.Value() == "on" {
				flags = append(flags, "timeout")
			}
			sc.statusMsg = ""
			return sc, createSetCmd(sc.table, name, kt, flags)
		}
	}

	var cmd tea.Cmd
	switch sc.focusSlot {
	case 0:
		sc.nameInput, cmd = sc.nameInput.Update(msg)
	case 1:
		sc.keyTypeSelect, cmd = sc.keyTypeSelect.Update(msg)
	case 2:
		sc.constantSelect, cmd = sc.constantSelect.Update(msg)
	case 3:
		sc.intervalSelect, cmd = sc.intervalSelect.Update(msg)
	case 4:
		sc.timeoutSelect, cmd = sc.timeoutSelect.Update(msg)
	}
	return sc, cmd
}

func (sc setCreate) View() string {
	header := blueBoldStyle.Render("nftui nftables manager")
	divider := grayStyle.Width(sc.width).Render(strings.Repeat("─", sc.width))

	var body strings.Builder
	body.WriteString(defaultBoldStyle.Render("Create new set"))
	body.WriteString("\n\n")

	body.WriteString(grayStyle.Render("Table     : "))
	body.WriteString(blueStyle.Render(sc.table.Name))
	body.WriteString(grayStyle.Render(" ("))
	body.WriteString(nft.TableFamilyToString(sc.table.Family))
	body.WriteString(grayStyle.Render(")"))
	body.WriteString("\n\n")

	body.WriteString(grayStyle.Render("Name      : "))
	body.WriteString(sc.nameInput.View())
	body.WriteString("\n\n")

	body.WriteString(grayStyle.Render("Key type  : "))
	body.WriteString(sc.keyTypeSelect.View())
	body.WriteString("\n\n")

	body.WriteString(grayStyle.Render("Constant  : "))
	body.WriteString(sc.constantSelect.View())
	body.WriteString("\n\n")

	body.WriteString(grayStyle.Render("Interval  : "))
	body.WriteString(sc.intervalSelect.View())
	body.WriteString("\n\n")

	body.WriteString(grayStyle.Render("Timeout   : "))
	body.WriteString(sc.timeoutSelect.View())
	body.WriteString("\n")

	if sc.statusMsg != "" {
		body.WriteString("\n")
		body.WriteString(redBoldStyle.Render("Error: " + sc.statusMsg))
	}

	contentBox := normalGrayBorder.
		Width(sc.width-2).
		Height(sc.height-8).
		Padding(1, 2).
		Render(body.String())

	footer := sc.help.View(sc.keys)
	return defaultStyle.Render(lipgloss.JoinVertical(lipgloss.Left,
		header, divider, contentBox, footer,
	))
}
