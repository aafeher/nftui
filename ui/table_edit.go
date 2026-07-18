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
	"nftui/i18n"
)

type tableEditKeyMap struct {
	Save key.Binding
	Back key.Binding
	Quit key.Binding
}

func (k tableEditKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Save, k.Back, k.Quit}
}

func (k tableEditKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{k.Save, k.Back, k.Quit}}
}

type tableEdit struct {
	table     *nftables.Table
	input     textinput.Model
	statusMsg string
	width     int
	height    int
	keys      tableEditKeyMap
	help      help.Model
}

func newTableEdit(table *nftables.Table) tableEdit {
	ti := textinput.New()
	ti.SetValue(table.Name)
	ti.Focus()
	ti.CharLimit = 64
	ti.Width = 40

	km := tableEditKeyMap{
		Save: key.NewBinding(
			key.WithKeys("f2"),
			key.WithHelp("f2", i18n.T("key.save")),
		),
		Back: key.NewBinding(
			key.WithKeys("esc", "f3"),
			key.WithHelp("esc/f3", i18n.T("key.cancel")),
		),
		Quit: key.NewBinding(
			key.WithKeys("ctrl+c"),
			key.WithHelp("ctrl+c", i18n.T("key.quit")),
		),
	}

	return tableEdit{
		table: table,
		input: ti,
		keys:  km,
		help:  newHelpModel(),
	}
}

func (te tableEdit) Update(msg tea.Msg) (tableEdit, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		te.width, te.height = msg.Width, msg.Height
		return te, nil

	case tableOpErrMsg:
		te.statusMsg = msg.err.Error()
		return te, nil

	case tea.KeyMsg:
		if key.Matches(msg, te.keys.Save) {
			newName := strings.TrimSpace(te.input.Value())
			if err := nft.ValidateIdentifier(newName); err != nil {
				te.statusMsg = err.Error()
				return te, nil
			}
			if newName == te.table.Name {
				// No change — treat as cancel.
				return te, nil
			}
			te.statusMsg = ""
			return te, renameTableCmd(te.table, newName)
		}
	}

	var cmd tea.Cmd
	te.input, cmd = te.input.Update(msg)
	return te, cmd
}

func (te tableEdit) View() string {
	header := blueBoldStyle.Render("nftui nftables manager")

	divider := grayStyle.
		Width(te.width).
		Render(strings.Repeat("─", te.width))

	var body strings.Builder
	body.WriteString(defaultBoldStyle.Render(i18n.T("table.edit.title")))
	body.WriteString("\n\n")

	// Family / Name are the localized identifier labels; the family *value*
	// (ip/ip6/inet/…) stays English as an nft token.
	body.WriteString(grayStyle.Render(i18n.T("table.create.family_label")))
	body.WriteString(whiteStyle.Render(nft.TableFamilyToString(te.table.Family)))
	body.WriteString(grayStyle.Render(i18n.T("table.edit.family_readonly")))
	body.WriteString("\n\n")

	body.WriteString(grayStyle.Render(i18n.T("table.create.name_label")))
	body.WriteString(te.input.View())

	if te.statusMsg != "" {
		body.WriteString("\n\n")
		body.WriteString(redBoldStyle.Render(i18n.T("common.error") + te.statusMsg))
	}

	contentBox := normalGrayBorder.
		Width(te.width-2).
		Height(te.height-8).
		Padding(1, 2).
		Render(body.String())

	footer := te.help.View(te.keys)

	return defaultStyle.Render(lipgloss.JoinVertical(lipgloss.Left,
		header,
		divider,
		contentBox,
		footer,
	))
}
