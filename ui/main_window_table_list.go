package ui

import (
	"fmt"
	"nftui/nft"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
)

type tableNode struct {
	Table    nftables.Table
	Chains   []*chainNode
	Rules    []*nftables.Rule
	Expanded bool
}

type chainNode struct {
	Chain nftables.Chain
	Rules []*nftables.Rule
}
type tableTreeModel struct {
	nodes             []*tableNode
	cursor            int
	activeRoot        *tableNode
	maxHeight         int
	scrollOffset      int
	width             int
	showDeleteConfirm bool
}

// IsModal reports whether the tree is currently showing a modal dialog (e.g.
// delete confirmation). Used by MainWindow to route all keys through the tree
// when modal, so that keys like "n" (no) don't escape to MainWindow's own
// bindings (e.g. NewTable).
func (tm tableTreeModel) IsModal() bool {
	return tm.showDeleteConfirm
}

type flatItem struct {
	tableFamily string
	tableName   string
	chainsCount int
	chainName   string
	rulesCount  int
	isRoot      bool
	table       *tableNode
	chain       *nftables.Chain
}

func initialTableTreeModel() tableTreeModel {
	tables, err := nft.ListTables()
	if err != nil {
		panic(err)
	}

	tableNodes := make([]*tableNode, len(tables))
	for t, table := range tables {
		chainsOfTable, err := nft.ListChainsOfTable(table)
		if err != nil {
			panic(err)
		}
		chains := make([]*chainNode, len(chainsOfTable))
		for c, chain := range chainsOfTable {
			rules, err := nft.ListRulesOfChain(table, chain)
			if err != nil {
				panic(err)
			}
			chains[c] = &chainNode{
				Chain: *chain,
				Rules: rules,
			}
		}

		rulesOfTable, err := nft.ListRulesOfTable(table)
		if err != nil {
			panic(err)
		}

		tableNodes[t] = &tableNode{
			Table:    *table,
			Expanded: false,
			Chains:   chains,
			Rules:    rulesOfTable,
		}
	}

	return tableTreeModel{
		nodes:  tableNodes,
		cursor: 0,
	}
}

func (tm tableTreeModel) Init() tea.Cmd {
	return nil
}

func (tm tableTreeModel) getFlattenedItems() []flatItem {
	var items []flatItem
	for _, table := range tm.nodes {
		items = append(items, flatItem{
			tableFamily: nft.TableFamilyToString(table.Table.Family),
			tableName:   table.Table.Name,
			chainsCount: len(table.Chains),
			rulesCount:  len(table.Rules),
			isRoot:      true,
			table:       table,
		})
		if table.Expanded {
			for _, chain := range table.Chains {
				items = append(items, flatItem{
					chainName:  chain.Chain.Name,
					isRoot:     false,
					table:      table,
					chain:      &chain.Chain,
					rulesCount: len(chain.Rules),
				})
			}
		}
	}
	return items
}

func (tm tableTreeModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if tm.showDeleteConfirm {
			switch msg.String() {
			case "y", "Y":
				items := tm.getFlattenedItems()
				if tm.cursor < len(items) {
					selected := items[tm.cursor]
					if selected.isRoot {
						tm.showDeleteConfirm = false
						return tm, deleteTableCmd(&selected.table.Table)
					}
					if selected.chain != nil {
						tm.showDeleteConfirm = false
						return tm, deleteChainCmd(selected.chain)
					}
				}
				tm.showDeleteConfirm = false
				return tm, nil
			case "n", "N", "esc":
				tm.showDeleteConfirm = false
				return tm, nil
			}
			return tm, nil
		}

		switch msg.String() {
		case "ctrl+c", "q":
			return tm, tea.Quit
		case "up", "k":
			if tm.cursor > 0 {
				tm.cursor--
				if tm.cursor < tm.scrollOffset {
					tm.scrollOffset = tm.cursor
				}
			}
		case "down", "j":
			items := tm.getFlattenedItems()
			if tm.cursor < len(items)-1 {
				tm.cursor++
				if tm.maxHeight > 0 && tm.cursor >= tm.scrollOffset+tm.maxHeight {
					tm.scrollOffset = tm.cursor - tm.maxHeight + 1
				}
			}
		case "d":
			items := tm.getFlattenedItems()
			if tm.cursor < len(items) {
				selected := items[tm.cursor]
				if selected.isRoot || selected.chain != nil {
					tm.showDeleteConfirm = true
				}
			}
		case "e":
			items := tm.getFlattenedItems()
			if tm.cursor < len(items) {
				selected := items[tm.cursor]
				if selected.isRoot {
					t := &selected.table.Table
					return tm, func() tea.Msg {
						return tableEditSelectedMsg{table: t}
					}
				}
				if selected.chain != nil {
					c := selected.chain
					return tm, func() tea.Msg {
						return chainEditSelectedMsg{chain: c}
					}
				}
			}
		case "c":
			items := tm.getFlattenedItems()
			if tm.cursor < len(items) {
				selected := items[tm.cursor]
				if selected.table != nil {
					t := &selected.table.Table
					return tm, func() tea.Msg {
						return chainCreateSelectedMsg{table: t}
					}
				}
			}
		case "f3":
			items := tm.getFlattenedItems()
			if tm.cursor < len(items) {
				selected := items[tm.cursor]
				if !selected.isRoot && selected.chain != nil {
					// Send message about chain selection
					return tm, func() tea.Msg {
						return chainSelectedMsg{
							chain: selected.chain,
							table: selected.table,
						}
					}
				}
			}
		case "enter", "right":
			items := tm.getFlattenedItems()
			if tm.cursor < len(items) {
				selected := items[tm.cursor]
				if selected.isRoot {
					selected.table.Expanded = !selected.table.Expanded
					if !selected.table.Expanded {
						if tm.cursor < len(items)-1 {
							nextItem := items[tm.cursor+1]
							if !nextItem.isRoot && nextItem.table == selected.table {
							}
						}
					}
				} else {
					//fmt.Printf("Selected item: %s/%s\n", selected.table.Table.Name, selected.chain.Name)
				}
			}
		case "left", "esc":
			items := tm.getFlattenedItems()
			if tm.cursor < len(items) {
				selected := items[tm.cursor]
				if selected.isRoot {
					if selected.table.Expanded {
						selected.table.Expanded = false
					}
				} else {
					for i, item := range items {
						if item.isRoot && item.table == selected.table {
							tm.cursor = i
							break
						}
					}
				}
			}
		}
	}
	return tm, nil
}

func (tm tableTreeModel) View() string {
	var b strings.Builder

	title := "| Tables and chains |"
	b.WriteString(blueStyle.Render(title))
	b.WriteString("\n\n")

	items := tm.getFlattenedItems()

	startIdx := tm.scrollOffset
	endIdx := len(items)
	if tm.maxHeight > 0 && endIdx > startIdx+tm.maxHeight {
		endIdx = startIdx + tm.maxHeight
	}

	terminalWidth := tm.width
	if terminalWidth == 0 {
		terminalWidth = 80
	}

	for i := startIdx; i < endIdx && i < len(items); i++ {
		item := items[i]
		cursor := " "
		if i == tm.cursor {
			cursor = ">"
		}

		isActive := i == tm.cursor

		if item.isRoot {
			expandIcon := "+"
			if item.table.Expanded {
				expandIcon = "-"
			}

			chainsLabel := "chain"
			if item.chainsCount > 1 {
				chainsLabel = "chains"
			}
			rulesLabel := "rule"
			if item.rulesCount > 1 {
				rulesLabel = "rules"
			}
			chainsCountLabel := fmt.Sprintf("[%d %s, %d %s]", item.chainsCount, chainsLabel, item.rulesCount, rulesLabel)

			var tableFamilyStyled, tableNameStyled, chainsCountStyled, space1, space2 string
			if isActive {
				tableFamilyStyled = blueBackgroundStyle.Render(item.tableFamily)
				tableNameStyled = blueBackgroundStyle.Inherit(blueStyle).Render(item.tableName)
				chainsCountStyled = blueBackgroundStyle.Inherit(grayStyle).Render(chainsCountLabel)
				space1 = blueBackgroundStyle.Render(" ")
				space2 = blueBackgroundStyle.Render(" ")
			} else {
				tableFamilyStyled = item.tableFamily
				tableNameStyled = blueStyle.Render(item.tableName)
				chainsCountStyled = grayStyle.Render(chainsCountLabel)
				space1 = " "
				space2 = " "
			}

			label := fmt.Sprintf("%s%s%s%s%s", tableFamilyStyled, space1, tableNameStyled, space2, chainsCountStyled)
			line := ""
			if len(item.table.Chains) > 0 {
				cursorStyled := cursor
				expandIconStyled := expandIcon
				space3 := " "
				if isActive {
					cursorStyled = blueBackgroundStyle.Render(cursor)
					expandIconStyled = blueBackgroundStyle.Render(expandIcon)
					space3 = blueBackgroundStyle.Render(" ")
				}
				line = fmt.Sprintf("%s%s%s%s%s", cursorStyled, space3, expandIconStyled, space3, label)
			} else {
				cursorStyled := cursor
				spaces := "   "
				if isActive {
					cursorStyled = blueBackgroundStyle.Render(cursor)
					spaces = blueBackgroundStyle.Render("   ")
				}
				line = fmt.Sprintf("%s%s%s", cursorStyled, spaces, label)
			}

			if isActive {
				// Calculate the number of visible characters (without ANSI codes)
				visibleLength := lipgloss.Width(line)
				padding := terminalWidth - visibleLength
				if padding > 0 {
					line += blueBackgroundStyle.Render(strings.Repeat(" ", padding))
				}
			}

			b.WriteString(line)
			b.WriteString("\n")
		} else {
			chainHookString := ""
			if item.chain.Hooknum != nil {
				hookStr := nft.ChainHookNumToString(*item.chain.Hooknum)
				if isActive {
					chainHookString = fmt.Sprintf("%s%s", blueBackgroundStyle.Render(", hook "), blueBackgroundStyle.Inherit(whiteStyle).Render(hookStr))
				} else {
					chainHookString = fmt.Sprintf(", hook %s", whiteStyle.Render(hookStr))
				}
			}
			chainPriorityString := ""
			if item.chain.Priority != nil {
				priorityStr := fmt.Sprintf("%v", *item.chain.Priority)
				if isActive {
					chainPriorityString = fmt.Sprintf("%s%s", blueBackgroundStyle.Render(", priority "), blueBackgroundStyle.Inherit(whiteStyle).Render(priorityStr))
				} else {
					chainPriorityString = fmt.Sprintf(", priority %s", whiteStyle.Render(priorityStr))
				}
			}
			chainPolicyString := ""
			if item.chain.Policy != nil {
				policyStr := nft.ChainPolicyToString(*item.chain.Policy)
				if *item.chain.Policy == nftables.ChainPolicyAccept {
					if isActive {
						chainPolicyString = fmt.Sprintf("%s%s", blueBackgroundStyle.Render(", policy "), blueBackgroundStyle.Inherit(greenStyle).Render(policyStr))
					} else {
						chainPolicyString = fmt.Sprintf(", policy %s", greenStyle.Render(policyStr))
					}
				} else if *item.chain.Policy == nftables.ChainPolicyDrop {
					if isActive {
						chainPolicyString = fmt.Sprintf("%s%s", blueBackgroundStyle.Render(", policy "), blueBackgroundStyle.Inherit(redStyle).Render(policyStr))
					} else {
						chainPolicyString = fmt.Sprintf(", policy %s", redStyle.Render(policyStr))
					}
				}
			}
			rulesCountLabel := fmt.Sprintf("[%d rules]", item.rulesCount)

			var chainNameStyled, typeStyled, rulesCountStyled, parenOpen, parenClose, space1, space2 string
			if isActive {
				chainNameStyled = blueBackgroundStyle.Inherit(yellowStyle).Render(item.chainName)
				typeStyled = blueBackgroundStyle.Inherit(whiteStyle).Render(fmt.Sprintf("%s", item.chain.Type))
				rulesCountStyled = blueBackgroundStyle.Inherit(grayStyle).Render(rulesCountLabel)
				parenOpen = blueBackgroundStyle.Render("(")
				parenClose = blueBackgroundStyle.Render(")")
				space1 = blueBackgroundStyle.Render(" ")
				space2 = blueBackgroundStyle.Render(" ")
			} else {
				chainNameStyled = yellowStyle.Render(item.chainName)
				typeStyled = whiteStyle.Render(fmt.Sprintf("%s", item.chain.Type))
				rulesCountStyled = grayStyle.Render(rulesCountLabel)
				parenOpen = "("
				parenClose = ")"
				space1 = " "
				space2 = " "
			}

			var typeWord string
			if isActive {
				typeWord = blueBackgroundStyle.Render("type")
			} else {
				typeWord = "type"
			}

			label := fmt.Sprintf("%s%s%stype%s%s%s%s%s%s%s", chainNameStyled, space1, parenOpen, space1, typeStyled, chainHookString, chainPriorityString, chainPolicyString, parenClose, space2)
			if isActive {
				label = fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s", chainNameStyled, space1, parenOpen, typeWord, space1, typeStyled, chainHookString, chainPriorityString, chainPolicyString, parenClose, space2)
			}
			label = label + rulesCountStyled

			var cursorStyled, dashStyled, spaces string
			if isActive {
				cursorStyled = blueBackgroundStyle.Render(cursor)
				dashStyled = blueBackgroundStyle.Render("-")
				spaces = blueBackgroundStyle.Render("   ")
			} else {
				cursorStyled = cursor
				dashStyled = "-"
				spaces = "   "
			}

			line := fmt.Sprintf("%s%s%s%s%s", cursorStyled, spaces, dashStyled, space1, label)

			if isActive {
				// Calculate the number of visible characters (without ANSI codes)
				visibleLength := lipgloss.Width(line)
				padding := terminalWidth - visibleLength
				if padding > 0 {
					line += blueBackgroundStyle.Render(strings.Repeat(" ", padding))
				}
			}

			b.WriteString(line)
			b.WriteString("\n")
		}
	}

	base := b.String()

	if tm.showDeleteConfirm {
		items := tm.getFlattenedItems()
		if tm.cursor < len(items) {
			selected := items[tm.cursor]
			var confirmText string
			switch {
			case selected.isRoot:
				warning := ""
				if selected.chainsCount > 0 || selected.rulesCount > 0 {
					warning = "\n\nWARNING: The table is not empty! Deleting it will delete all chains and rules inside."
				}
				confirmText = fmt.Sprintf("Are you sure you want to delete the '%s' table?%s\n\n[Y]es / [N]o", selected.tableName, warning)
			case selected.chain != nil:
				warning := ""
				if selected.rulesCount > 0 {
					warning = fmt.Sprintf("\n\nWARNING: The chain has %d rule(s). Deleting it will also delete all of them.", selected.rulesCount)
				}
				confirmText = fmt.Sprintf("Are you sure you want to delete the '%s' chain?%s\n\n[Y]es / [N]o", selected.chainName, warning)
			default:
				return base
			}

			confirmBox := lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("196")).
				Padding(1, 2).
				Width(60).
				Align(lipgloss.Center).
				Render(confirmText)

			overlay := lipgloss.Place(tm.width, tm.maxHeight,
				lipgloss.Center, lipgloss.Center,
				confirmBox,
			)
			return lipgloss.Place(tm.width, tm.maxHeight, lipgloss.Left, lipgloss.Top, base+"\n"+overlay)
		}
	}

	return base
}
