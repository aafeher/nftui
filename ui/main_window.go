package ui

import (
	"fmt"
	"nftui/nft"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
)

type errMsg error

// loadErrorView renders the tables-box content when an initial load fails.
// A netlink permission error (no CAP_NET_ADMIN / not root) gets actionable
// advice instead of the raw syscall text; any other error falls back to the
// generic red error line.
func loadErrorView(err error) string {
	if !nft.IsPermissionError(err) {
		return redBoldStyle.Render(fmt.Sprintf("Error: %v", err))
	}
	bin := os.Args[0]
	var b strings.Builder
	b.WriteString(redBoldStyle.Render("Permission denied - cannot read the nftables ruleset."))
	b.WriteString("\n\n")
	b.WriteString(whiteStyle.Render("nftui needs the CAP_NET_ADMIN capability. Either:"))
	b.WriteString("\n\n")
	b.WriteString(grayStyle.Render("  - run it with sudo:          "))
	b.WriteString(whiteStyle.Render("sudo " + bin))
	b.WriteString("\n")
	b.WriteString(grayStyle.Render("  - or grant the capability:   "))
	b.WriteString(whiteStyle.Render("sudo setcap cap_net_admin+ep " + bin))
	return b.String()
}

type keyMap struct {
	Up        key.Binding
	Down      key.Binding
	Expand    key.Binding
	Edit      key.Binding
	Delete    key.Binding
	NewTable  key.Binding
	NewChain  key.Binding
	NewSet    key.Binding
	Reset     key.Binding
	OpenChain key.Binding
	Filter    key.Binding
	Refresh   key.Binding
	Quit      key.Binding
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Expand, k.Edit, k.Delete, k.NewTable, k.NewChain, k.NewSet, k.Reset, k.OpenChain, k.Filter, k.Refresh, k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Expand, k.Edit, k.Delete},
		{k.NewTable, k.NewChain, k.NewSet, k.OpenChain},
		{k.Reset, k.Filter, k.Refresh, k.Quit},
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
	tableCreate           *tableCreate
	chainEdit             *chainEdit
	chainCreate           *chainCreate
	setView               *setView
	setCreate             *setCreate
	activeView            string // "main", "chain", "ruleView", "ruleEdit", "tableEdit", "tableCreate", "chainEdit", "chainCreate", "set", "setCreate"
	help                  help.Model
	width                 int
	height                int
	ready                 bool
	keys                  keyMap
	showQuitConfirm       bool
}

// applyContextualKeys toggles the Enabled state on cursor-sensitive
// MainWindow keybindings:
//
//	NewSet (`s`)   — needs at least one table in the tree
//	Reset  (`R`)   — needs cursor on a counter / quota object row
//
// Called from View just before help.View(m.keys); the help component
// reads the current Enabled flag at render time.
func (m *MainWindow) applyContextualKeys() {
	m.keys.NewSet.SetEnabled(len(m.tableTree.nodes) > 0)

	resettable := false
	items := m.tableTree.getFlattenedItems()
	if m.tableTree.cursor < len(items) {
		sel := items[m.tableTree.cursor]
		if sel.isObj && sel.obj != nil &&
			(sel.obj.Type == nftables.ObjTypeCounter ||
				sel.obj.Type == nftables.ObjTypeQuota) {
			resettable = true
		}
	}
	m.keys.Reset.SetEnabled(resettable)
}

type chainSelectedMsg struct {
	chain *nftables.Chain
	table *tableNode
}

type setSelectedMsg struct {
	set   *nftables.Set
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
			key.WithKeys("enter", "right", "left"),
			key.WithHelp("enter/→/←", "expand/collapse"),
		),
		Edit: key.NewBinding(
			key.WithKeys("e"),
			key.WithHelp("e", "edit"),
		),
		Delete: key.NewBinding(
			key.WithKeys("d"),
			key.WithHelp("d", "delete"),
		),
		NewTable: key.NewBinding(
			key.WithKeys("n"),
			key.WithHelp("n", "new table"),
		),
		NewChain: key.NewBinding(
			key.WithKeys("c"),
			key.WithHelp("c", "new chain"),
		),
		NewSet: key.NewBinding(
			key.WithKeys("s"),
			key.WithHelp("s", "new set"),
		),
		Reset: key.NewBinding(
			key.WithKeys("R"),
			key.WithHelp("R", "reset counter/quota"),
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
		help:            newHelpModel(),
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

	case setSelectedMsg:
		sv := newSetView(msg.set, msg.table)
		sv.width = m.width
		sv.height = m.height
		m.setView = &sv
		m.activeView = "set"
		return m, nil

	case setViewBackMsg:
		m.activeView = "main"
		m.setView = nil
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

	case chainEditSelectedMsg:
		ce := newChainEdit(msg.chain)
		ce.width = m.width
		ce.height = m.height
		m.chainEdit = &ce
		m.activeView = "chainEdit"
		return m, nil

	case chainCreateSelectedMsg:
		cc := newChainCreate(msg.table)
		cc.width = m.width
		cc.height = m.height
		m.chainCreate = &cc
		m.activeView = "chainCreate"
		return m, nil

	case tableRenamedMsg:
		m.tableEdit = nil
		m.activeView = "main"
		m.loading = true
		return m, tea.Batch(
			loadTableTreeCmd(),
			loadTablesCmd(), loadChainsCmd(), loadRulesAcceptCmd(), loadRulesDropCmd(),
		)

	case tableCreatedMsg:
		m.tableCreate = nil
		m.activeView = "main"
		m.loading = true
		return m, tea.Batch(
			loadTableTreeCmd(),
			loadTablesCmd(), loadChainsCmd(), loadRulesAcceptCmd(), loadRulesDropCmd(),
		)

	case chainUpdatedMsg:
		m.chainEdit = nil
		m.activeView = "main"
		m.loading = true
		return m, tea.Batch(
			loadTableTreeCmd(),
			loadTablesCmd(), loadChainsCmd(), loadRulesAcceptCmd(), loadRulesDropCmd(),
		)

	case chainCreatedMsg:
		m.chainCreate = nil
		m.activeView = "main"
		m.loading = true
		return m, tea.Batch(
			loadTableTreeCmd(),
			loadTablesCmd(), loadChainsCmd(), loadRulesAcceptCmd(), loadRulesDropCmd(),
		)

	case tableDeletedMsg, chainDeletedMsg:
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
		if m.tableCreate != nil {
			updatedTC, cmd := m.tableCreate.Update(msg)
			m.tableCreate = &updatedTC
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

		if m.activeView == "set" && m.setView != nil {
			updatedSetView, cmd := m.setView.Update(msg)
			m.setView = &updatedSetView
			return m, cmd
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

		if m.activeView == "tableCreate" && m.tableCreate != nil {
			switch {
			case key.Matches(msg, m.tableCreate.keys.Back):
				m.activeView = "main"
				m.tableCreate = nil
				return m, nil
			case key.Matches(msg, m.tableCreate.keys.Quit):
				m.showQuitConfirm = true
				return m, nil
			default:
				updatedTC, cmd := m.tableCreate.Update(msg)
				m.tableCreate = &updatedTC
				return m, cmd
			}
		}

		if m.activeView == "chainEdit" && m.chainEdit != nil {
			switch {
			case key.Matches(msg, m.chainEdit.keys.Back):
				m.activeView = "main"
				m.chainEdit = nil
				return m, nil
			case key.Matches(msg, m.chainEdit.keys.Quit):
				m.showQuitConfirm = true
				return m, nil
			default:
				updatedCE, cmd := m.chainEdit.Update(msg)
				m.chainEdit = &updatedCE
				return m, cmd
			}
		}

		if m.activeView == "chainCreate" && m.chainCreate != nil {
			switch {
			case key.Matches(msg, m.chainCreate.keys.Back):
				m.activeView = "main"
				m.chainCreate = nil
				return m, nil
			case key.Matches(msg, m.chainCreate.keys.Quit):
				m.showQuitConfirm = true
				return m, nil
			default:
				updatedCC, cmd := m.chainCreate.Update(msg)
				m.chainCreate = &updatedCC
				return m, cmd
			}
		}

		if m.activeView == "setCreate" && m.setCreate != nil {
			switch {
			case key.Matches(msg, m.setCreate.keys.Back):
				m.activeView = "main"
				m.setCreate = nil
				return m, nil
			case key.Matches(msg, m.setCreate.keys.Quit):
				m.showQuitConfirm = true
				return m, nil
			default:
				updatedSC, cmd := m.setCreate.Update(msg)
				m.setCreate = &updatedSC
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

		// If the table tree has a modal (e.g. delete confirmation) open, route
		// every key through the tree without consulting MainWindow's own
		// bindings — otherwise the modal's "n"/"y" answers would leak to
		// NewTable/Quit handlers and (e.g.) opening a new-table window.
		if m.tableTree.IsModal() {
			updatedTableTree, cmd := m.tableTree.Update(msg)
			if ttm, ok := updatedTableTree.(tableTreeModel); ok {
				m.tableTree = ttm
			}
			return m, cmd
		}

		switch {
		case key.Matches(msg, m.keys.Quit):
			m.showQuitConfirm = true
			return m, nil
		case key.Matches(msg, m.keys.Refresh):
			m.loading = true
			m.err = nil
			return m, tea.Batch(loadTablesCmd(), loadChainsCmd(), loadRulesAcceptCmd(), loadRulesDropCmd())
		case key.Matches(msg, m.keys.NewTable):
			tc := newTableCreate()
			tc.width, tc.height = m.width, m.height
			tc.applyFocus()
			m.tableCreate = &tc
			m.activeView = "tableCreate"
			return m, nil
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
		if m.activeView == "chainEdit" && m.chainEdit != nil {
			updatedCE, cmd := m.chainEdit.Update(msg)
			m.chainEdit = &updatedCE
			return m, cmd
		}
		if m.activeView == "chainCreate" && m.chainCreate != nil {
			updatedCC, cmd := m.chainCreate.Update(msg)
			m.chainCreate = &updatedCC
			return m, cmd
		}
		if m.chainView != nil {
			m.chainView.statusMsg = msg.err.Error()
		}
		return m, nil

	case setElementAddedMsg:
		if m.setView != nil {
			m.setView.RefreshElements()
		}
		return m, nil

	case setElementDeletedMsg:
		if m.setView != nil {
			m.setView.RefreshElements()
		}
		return m, nil

	case setCreateSelectedMsg:
		sc := newSetCreate(msg.table)
		sc.width = m.width
		sc.height = m.height
		m.setCreate = &sc
		m.activeView = "setCreate"
		return m, nil

	case setCreatedMsg:
		m.setCreate = nil
		m.activeView = "main"
		m.loading = true
		return m, tea.Batch(
			loadTableTreeCmd(),
			loadTablesCmd(), loadChainsCmd(), loadRulesAcceptCmd(), loadRulesDropCmd(),
		)

	case setDeletedMsg:
		m.loading = true
		return m, tea.Batch(
			loadTableTreeCmd(),
			loadTablesCmd(), loadChainsCmd(), loadRulesAcceptCmd(), loadRulesDropCmd(),
		)

	case namedObjectResetMsg:
		m.loading = true
		return m, tea.Batch(
			loadTableTreeCmd(),
			loadTablesCmd(), loadChainsCmd(), loadRulesAcceptCmd(), loadRulesDropCmd(),
		)

	case namedObjectDeletedMsg:
		m.loading = true
		return m, tea.Batch(
			loadTableTreeCmd(),
			loadTablesCmd(), loadChainsCmd(), loadRulesAcceptCmd(), loadRulesDropCmd(),
		)

	case statusFadeMsg:
		if msg.gen == m.tableTree.statusGen {
			m.tableTree.statusMsg = ""
		}
		return m, nil

	case namedObjectOpErrMsg:
		// Reset/Delete failures share the tree's yellow status line with the
		// no-op hint ("no resettable object under cursor") — one channel per
		// action result, instead of the global red tablesBox replacement.
		cmd := m.tableTree.setStatus(msg.err.Error())
		return m, cmd

	case setOpErrMsg:
		if m.setCreate != nil {
			updatedSC, cmd := m.setCreate.Update(msg)
			m.setCreate = &updatedSC
			return m, cmd
		}
		if m.setView != nil {
			// While the add prompt is open (bulk-add loop), surface the
			// kernel rejection inside the prompt — the user is operating
			// there, and an error means the previous "added X" hint is
			// no longer the truth. Wipe the hint to keep the overlay
			// honest. Outside the prompt the error goes to the regular
			// status line below the element list.
			if m.setView.showAddPrompt {
				m.setView.setAddErr(msg.err.Error())
			} else {
				m.setView.statusMsg = msg.err.Error()
			}
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
		if m.activeView == "ruleEdit" && m.ruleEdit != nil {
			m.ruleEdit.errStr = msg.Error()
		}
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

	if m.activeView == "tableCreate" && m.tableCreate != nil {
		tcContent := m.tableCreate.View()
		if m.showQuitConfirm {
			confirmBox := lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("220")).
				Padding(1, 2).
				Width(40).
				Align(lipgloss.Center).
				Render("Valóban ki szeretnél lépni?\n\n[Y]es / [N]o")
			overlay := lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, confirmBox)
			return lipgloss.Place(m.width, m.height, lipgloss.Left, lipgloss.Top, tcContent+"\n"+overlay)
		}
		return tcContent
	}

	if m.activeView == "chainEdit" && m.chainEdit != nil {
		ceContent := m.chainEdit.View()
		if m.showQuitConfirm {
			confirmBox := lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("220")).
				Padding(1, 2).
				Width(40).
				Align(lipgloss.Center).
				Render("Valóban ki szeretnél lépni?\n\n[Y]es / [N]o")
			overlay := lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, confirmBox)
			return lipgloss.Place(m.width, m.height, lipgloss.Left, lipgloss.Top, ceContent+"\n"+overlay)
		}
		return ceContent
	}

	if m.activeView == "chainCreate" && m.chainCreate != nil {
		ccContent := m.chainCreate.View()
		if m.showQuitConfirm {
			confirmBox := lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("220")).
				Padding(1, 2).
				Width(40).
				Align(lipgloss.Center).
				Render("Valóban ki szeretnél lépni?\n\n[Y]es / [N]o")
			overlay := lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, confirmBox)
			return lipgloss.Place(m.width, m.height, lipgloss.Left, lipgloss.Top, ccContent+"\n"+overlay)
		}
		return ccContent
	}

	if m.activeView == "setCreate" && m.setCreate != nil {
		scContent := m.setCreate.View()
		if m.showQuitConfirm {
			confirmBox := lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("220")).
				Padding(1, 2).
				Width(40).
				Align(lipgloss.Center).
				Render("Valóban ki szeretnél lépni?\n\n[Y]es / [N]o")
			overlay := lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, confirmBox)
			return lipgloss.Place(m.width, m.height, lipgloss.Left, lipgloss.Top, scContent+"\n"+overlay)
		}
		return scContent
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

	if m.activeView == "set" && m.setView != nil {
		return m.setView.View()
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
		tablesBoxContent = loadErrorView(m.err)
	} else {
		tablesBoxContent = m.tableTree.View()
	}

	tablesBox := normalGrayBorder.
		Width(m.width-2).
		Height(m.height-8).
		Padding(0, 1).
		Render(tablesBoxContent)

	// Context-aware footer: hide bindings whose action doesn't apply to
	// the cursor's current row. `help.View` honors SetEnabled, so a
	// disabled binding drops out of both ShortHelp and FullHelp output.
	m.applyContextualKeys()
	footer := m.help.View(m.keys)
	if !m.loading && m.err == nil && m.tableTree.searchMode {
		// In tree search mode the normal bindings don't apply — show the
		// search controls instead (footer-completeness invariant).
		footer = m.help.View(treeSearchKeys)
	}

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
