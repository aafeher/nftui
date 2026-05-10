package ui

import (
	"fmt"
	"nftui/nft"
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
)

type errMsg error

type keyMap struct {
	Up        key.Binding
	Down      key.Binding
	Expand    key.Binding
	EditTable key.Binding
	OpenChain key.Binding
	Filter    key.Binding
	Refresh   key.Binding
	Quit      key.Binding
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Expand, k.EditTable, k.OpenChain, k.Refresh, k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Expand, k.EditTable, k.OpenChain},
		{k.Filter, k.Refresh, k.Quit},
	}
}

type MainWindow struct {
	loading         bool
	statTables      []*nftables.Table
	statChains      []*nftables.Chain
	statRules       []*nftables.Rule
	statRulesAccept []*nftables.Rule
	statRulesDrop   []*nftables.Rule
	cursor          int
	err             error

	// UI
	statTablesNumber      int
	statChainsNumber      int
	statRulesAcceptNumber int
	statRulesDropNumber   int
	tableTree             tableTreeModel
	chainView             *chainView
	ruleView              *ruleView
	ruleEdit              *ruleEdit
	tableEdit             *tableEdit
	activeView            string // "main", "chain", "ruleView", "ruleEdit", "tableEdit"
	help                  help.Model
	width                 int
	height                int
	ready                 bool
	keys                  keyMap
	showQuitConfirm       bool
}

type chainSelectedMsg struct {
	chain *nftables.Chain
	table *tableNode
}

type ruleViewSelectedMsg struct {
	rule *nftables.Rule
}

type ruleEditSelectedMsg struct {
	rule *nftables.Rule
}

func InitialMainWindow() MainWindow {
	ttm := initialTableTreeModel()

	km := keyMap{
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("↑/k", "up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("↓/j", "down"),
		),
		Expand: key.NewBinding(
			key.WithKeys("enter", "right"),
			key.WithHelp("enter/→", "expand/collapse"),
		),
		EditTable: key.NewBinding(
			key.WithKeys("e"),
			key.WithHelp("e", "edit table"),
		),
		OpenChain: key.NewBinding(
			key.WithKeys("f3"),
			key.WithHelp("f3", "open chain"),
		),
		Filter: key.NewBinding(
			key.WithKeys("/"),
			key.WithHelp("/", "search"),
		),
		Refresh: key.NewBinding(
			key.WithKeys("r"),
			key.WithHelp("r", "refresh"),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "esc", "ctrl+c"),
			key.WithHelp("q", "quit"),
		),
	}

	return MainWindow{
		loading:         true,
		tableTree:       ttm,
		activeView:      "main",
		help:            help.New(),
		keys:            km,
		showQuitConfirm: false,
	}
}

func (m MainWindow) Init() tea.Cmd {
	return tea.Batch(loadTablesCmd(), loadChainsCmd(), loadRulesAcceptCmd(), loadRulesDropCmd())
}

func (m MainWindow) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.ready = true
		m.tableTree.maxHeight = m.height - 9
		m.tableTree.width = m.width - 4
		// Popup méret beállítása
		if m.chainView != nil {
			m.chainView.width = m.width
			m.chainView.height = m.height
		}
		return m, nil

	case chainSelectedMsg:
		// Chain kiválasztva - váltunk chainView-ra
		cv := newChainView(msg.chain, msg.table)
		cv.width = m.width
		cv.height = m.height
		m.chainView = &cv
		m.activeView = "chain"
		return m, nil

	case ruleViewSelectedMsg:
		// Rule kiválasztva - váltunk ruleView-ra
		rv := newRuleView(msg.rule)
		rv.width = m.width
		rv.height = m.height
		m.ruleView = &rv
		m.activeView = "ruleView"
		return m, nil

	case ruleEditSelectedMsg:
		// Rule kiválasztva - váltunk ruleEdit-re
		rv := newRuleEdit(msg.rule)
		rv.width = m.width
		rv.height = m.height
		m.ruleEdit = &rv
		m.activeView = "ruleEdit"
		return m, nil

	case tableEditSelectedMsg:
		te := newTableEdit(msg.table)
		te.width = m.width
		te.height = m.height
		m.tableEdit = &te
		m.activeView = "tableEdit"
		return m, nil

	case tableRenamedMsg:
		m.tableEdit = nil
		m.activeView = "main"
		m.loading = true
		return m, tea.Batch(
			loadTableTreeCmd(),
			loadTablesCmd(), loadChainsCmd(), loadRulesAcceptCmd(), loadRulesDropCmd(),
		)

	case tableTreeRefreshedMsg:
		m.tableTree.nodes = msg.nodes
		return m, nil

	case tableOpErrMsg:
		if m.tableEdit != nil {
			updatedTE, cmd := m.tableEdit.Update(msg)
			m.tableEdit = &updatedTE
			return m, cmd
		}
		return m, nil

	case tea.KeyMsg:
		if m.activeView == "chain" && m.chainView != nil {
			// While a modal (e.g. delete confirm) is active, route all keys through chainView.
			if m.chainView.IsModal() {
				updatedChainView, cmd := m.chainView.Update(msg)
				m.chainView = &updatedChainView
				return m, cmd
			}
			switch {
			case key.Matches(msg, m.chainView.keys.Back):
				m.activeView = "main"
				m.chainView = nil
				return m, nil
			case key.Matches(msg, m.chainView.keys.Quit):
				m.showQuitConfirm = true
				return m, nil
			default:
				updatedChainView, cmd := m.chainView.Update(msg)
				m.chainView = &updatedChainView
				return m, cmd
			}
		}

		if m.activeView == "ruleView" && m.ruleView != nil {
			switch {
			case key.Matches(msg, m.ruleView.keys.Back):
				m.activeView = "chain"
				m.ruleView = nil
				if m.chainView != nil {
					m.chainView.RefreshRules()
				}
				return m, nil
			case key.Matches(msg, m.ruleView.keys.Quit):
				m.showQuitConfirm = true
				return m, nil
			default:
				updatedRuleView, cmd := m.ruleView.Update(msg)
				m.ruleView = &updatedRuleView
				return m, cmd
			}
		}

		if m.activeView == "tableEdit" && m.tableEdit != nil {
			switch {
			case key.Matches(msg, m.tableEdit.keys.Back):
				m.activeView = "main"
				m.tableEdit = nil
				return m, nil
			case key.Matches(msg, m.tableEdit.keys.Quit):
				m.showQuitConfirm = true
				return m, nil
			default:
				updatedTE, cmd := m.tableEdit.Update(msg)
				m.tableEdit = &updatedTE
				return m, cmd
			}
		}

		if m.activeView == "ruleEdit" && m.ruleEdit != nil {
			switch {
			case key.Matches(msg, m.ruleEdit.keys.Back):
				m.activeView = "chain"
				m.ruleEdit = nil
				if m.chainView != nil {
					m.chainView.RefreshRules()
				}
				return m, nil
			case key.Matches(msg, m.ruleEdit.keys.Quit):
				m.showQuitConfirm = true
				return m, nil
			default:
				updatedRuleEdit, cmd := m.ruleEdit.Update(msg)
				m.ruleEdit = &updatedRuleEdit
				return m, cmd
			}
		}

		if m.showQuitConfirm {
			switch msg.String() {
			case "y", "Y":
				if err := nft.FlushRules(); err != nil {
					m.showQuitConfirm = false
					m.err = err
					return m, nil
				}
				return m, tea.Quit
			case "n", "N", "esc":
				m.showQuitConfirm = false
				return m, nil
			}
			return m, nil
		}

		switch {
		case key.Matches(msg, m.keys.Quit):
			m.showQuitConfirm = true
			return m, nil
		case key.Matches(msg, m.keys.Refresh):
			m.loading = true
			m.err = nil
			return m, tea.Batch(loadTablesCmd(), loadChainsCmd(), loadRulesAcceptCmd(), loadRulesDropCmd())
		}
		if !m.loading && m.err == nil {
			var cmd tea.Cmd
			updatedTableTree, cmd := m.tableTree.Update(msg)
			// Type assertion hozzáadása
			if ttm, ok := updatedTableTree.(tableTreeModel); ok {
				m.tableTree = ttm
			}
			return m, cmd
		}

	case chainOpErrMsg:
		if m.chainView != nil {
			m.chainView.statusMsg = msg.err.Error()
		}
		return m, nil

	case ruleDeletedMsg:
		if m.chainView != nil {
			prevCursor := m.chainView.cursor
			m.chainView.RefreshRules()
			if prevCursor >= len(m.chainView.rules) && len(m.chainView.rules) > 0 {
				m.chainView.cursor = len(m.chainView.rules) - 1
			}
		}
		return m, nil

	case ruleMovedMsg:
		if m.chainView != nil {
			m.chainView.RefreshRules()
			if msg.newCursor >= 0 && msg.newCursor < len(m.chainView.rules) {
				m.chainView.cursor = msg.newCursor
			}
		}
		return m, nil

	case newRuleCreatedMsg:
		rv := newRuleEdit(msg.rule)
		rv.width = m.width
		rv.height = m.height
		m.ruleEdit = &rv
		m.activeView = "ruleEdit"
		return m, nil

	case statTablesMsg:
		m.loading = false
		m.err = nil
		m.statTables = msg
		m.statTablesNumber = len(m.statTables)

		return m, nil

	case statChainsMsg:
		m.statChains = msg
		m.statChainsNumber = len(m.statChains)
		return m, nil

	case statRulesAcceptMsg:
		m.statRulesAccept = msg
		m.statRulesAcceptNumber = len(m.statRulesAccept)
		return m, nil

	case statRulesDropMsg:
		m.statRulesDrop = msg
		m.statRulesDropNumber = len(m.statRulesDrop)
		return m, nil

	case errMsg:
		m.loading = false
		m.err = msg
		return m, nil
	}

	return m, nil
}

func (m MainWindow) View() string {
	if !m.ready {
		return "Initializing...\n"
	}

	if m.activeView == "tableEdit" && m.tableEdit != nil {
		teContent := m.tableEdit.View()
		if m.showQuitConfirm {
			confirmBox := lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("220")).
				Padding(1, 2).
				Width(40).
				Align(lipgloss.Center).
				Render("Valóban ki szeretnél lépni?\n\n[Y]es / [N]o")
			overlay := lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, confirmBox)
			return lipgloss.Place(m.width, m.height, lipgloss.Left, lipgloss.Top, teContent+"\n"+overlay)
		}
		return teContent
	}

	if m.activeView == "chain" && m.chainView != nil {
		chainViewContent := m.chainView.View()

		if m.showQuitConfirm {
			confirmBox := lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("220")).
				Padding(1, 2).
				Width(40).
				Align(lipgloss.Center).
				Render("Valóban ki szeretnél lépni?\n\n[Y]es / [N]o")

			overlay := lipgloss.Place(m.width, m.height,
				lipgloss.Center, lipgloss.Center,
				confirmBox,
			)

			return lipgloss.Place(m.width, m.height, lipgloss.Left, lipgloss.Top, chainViewContent+"\n"+overlay)
		}

		return chainViewContent
	}

	if m.activeView == "ruleView" && m.ruleView != nil {
		ruleViewContent := m.ruleView.View()

		if m.showQuitConfirm {
			confirmBox := lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("220")).
				Padding(1, 2).
				Width(40).
				Align(lipgloss.Center).
				Render("Valóban ki szeretnél lépni?\n\n[Y]es / [N]o")

			overlay := lipgloss.Place(m.width, m.height,
				lipgloss.Center, lipgloss.Center,
				confirmBox,
			)

			return lipgloss.Place(m.width, m.height, lipgloss.Left, lipgloss.Top, ruleViewContent+"\n"+overlay)
		}

		return ruleViewContent
	}

	if m.activeView == "ruleEdit" && m.ruleEdit != nil {
		ruleEditContent := m.ruleEdit.View()

		if m.showQuitConfirm {
			confirmBox := lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("220")).
				Padding(1, 2).
				Width(40).
				Align(lipgloss.Center).
				Render("Valóban ki szeretnél lépni?\n\n[Y]es / [N]o")

			overlay := lipgloss.Place(m.width, m.height,
				lipgloss.Center, lipgloss.Center,
				confirmBox,
			)

			return lipgloss.Place(m.width, m.height, lipgloss.Left, lipgloss.Top, ruleEditContent+"\n"+overlay)
		}

		return ruleEditContent
	}

	header := blueBoldStyle.Render("nftui nftables manager")

	divider := grayStyle.
		Width(m.width).
		Render(strings.Repeat("─", m.width))

	boxWidth := (m.width - 8) / 4
	if boxWidth < 20 {
		boxWidth = 20
	}

	statTablesNumber := blueBoldStyle.
		Render(fmt.Sprint(m.statTablesNumber))
	statTablesContent := statTablesNumber + " active tables"

	statTablesBox := normalGrayBorder.
		Width(boxWidth).
		Padding(0, 1).
		Render(statTablesContent)

	chainsNumber := yellowBoldStyle.
		Render(fmt.Sprint(m.statChainsNumber))
	chainsContent := chainsNumber + " active chains"

	chainsBox := normalGrayBorder.
		Width(boxWidth).
		Padding(0, 1).
		Render(chainsContent)

	acceptRulesNumber := greenBoldStyle.
		Render(fmt.Sprint(m.statRulesAcceptNumber))
	acceptRulesContent := acceptRulesNumber + " ACCEPT rules"

	acceptRulesBox := normalGrayBorder.
		Width(boxWidth).
		Padding(0, 1).
		Render(acceptRulesContent)

	dropRulesNumber := redBoldStyle.
		Render(fmt.Sprint(m.statRulesDropNumber))
	dropRulesContent := dropRulesNumber + " DROP rules"

	dropRulesBox := normalGrayBorder.
		Width(boxWidth).
		Padding(0, 1).
		Render(dropRulesContent)

	statBoxes := lipgloss.JoinHorizontal(lipgloss.Top, statTablesBox, chainsBox, acceptRulesBox, dropRulesBox)

	var tablesBoxContent string
	if m.loading {
		tablesBoxContent = "Loading..."
	} else if m.err != nil {
		tablesBoxContent = redBoldStyle.Render(fmt.Sprintf("Error: %v", m.err))
	} else {
		tablesBoxContent = m.tableTree.View()
	}

	tablesBox := normalGrayBorder.
		Width(m.width-2).
		Height(m.height-8).
		Padding(0, 1).
		Render(tablesBoxContent)

	footer := m.help.View(m.keys)

	content := lipgloss.JoinVertical(lipgloss.Left,
		header,
		divider,
		statBoxes,
		tablesBox,
		footer,
	)

	baseView := defaultStyle.Render(content)

	if m.showQuitConfirm {
		confirmBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("220")).
			Padding(1, 2).
			Width(40).
			Align(lipgloss.Center).
			Render("Valóban ki szeretnél lépni?\n\n[Y]es / [N]o")

		overlay := lipgloss.Place(m.width, m.height,
			lipgloss.Center, lipgloss.Center,
			confirmBox,
		)

		return lipgloss.Place(m.width, m.height, lipgloss.Left, lipgloss.Top, baseView+"\n"+overlay)
	}

	// Ha nincsenek látható rétegek, akkor csak a baseView-t adjuk vissza
	return baseView
}
