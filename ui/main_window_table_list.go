package ui

import (
	"fmt"
	"nftui/nft"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
)

type tableNode struct {
	Table    nftables.Table
	Chains   []*chainNode
	Rules    []*nftables.Rule
	Sets     []*nftables.Set
	Objects  []nft.NamedObject // counters, quotas, ct helpers, ...
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
	// statusMsg is a transient hint (e.g. "no resettable object under
	// cursor"). It auto-fades ~2s after it's set (see setStatus) rather
	// than clearing on the next key press, so an accidental cursor move
	// doesn't swallow it before the user reads it.
	statusMsg string
	// statusGen tags each statusMsg so a stale fade timer (from an earlier
	// message that was already replaced) can't clear a newer one.
	statusGen int

	// Incremental name search (entered with "/"). While searchMode is on,
	// every keypress is routed here (see IsModal) so typed characters build
	// the query instead of triggering tree actions. searchMatches holds the
	// flattened-row indices that match searchQuery; searchActive points at
	// the one the cursor is currently parked on.
	searchMode    bool
	searchQuery   string
	searchMatches []int
	searchActive  int

	// tableFilter (Options.TableFilter) restricts the tree to tables whose
	// Name matches this value. Empty = no filter. Applied at both initial
	// load and refresh, so the user's --table choice survives every reload.
	tableFilter string
}

// filterTables returns the subset of nodes whose Table.Name matches name.
// Empty name returns nodes unchanged. Family is intentionally ignored —
// tables can share names across families and we want all of them.
func filterTables(nodes []*tableNode, name string) []*tableNode {
	if name == "" {
		return nodes
	}
	out := make([]*tableNode, 0, len(nodes))
	for _, n := range nodes {
		if n.Table.Name == name {
			out = append(out, n)
		}
	}
	return out
}

// treeSearchKeyMap is the footer shown while the tree is in search mode.
type treeSearchKeyMap struct {
	Filter key.Binding
	Next   key.Binding
	Prev   key.Binding
	Exit   key.Binding
}

func (k treeSearchKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Filter, k.Next, k.Prev, k.Exit}
}
func (k treeSearchKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{k.Filter, k.Next, k.Prev, k.Exit}}
}

var treeSearchKeys = treeSearchKeyMap{
	Filter: key.NewBinding(key.WithKeys("a-z"), key.WithHelp("type", "filter")),
	Next:   key.NewBinding(key.WithKeys("enter", "down"), key.WithHelp("enter/↓", "next match")),
	Prev:   key.NewBinding(key.WithKeys("up"), key.WithHelp("↑", "prev match")),
	Exit:   key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "exit search")),
}

const statusFadeDelay = 2 * time.Second

// statusFadeMsg is delivered by the setStatus timer; the handler clears
// statusMsg only when gen still matches the current statusGen.
type statusFadeMsg struct{ gen int }

// setStatus records a transient hint and returns a tea.Cmd that fades it
// after statusFadeDelay. Bumping statusGen invalidates any in-flight timer
// from a previous message.
func (tm *tableTreeModel) setStatus(msg string) tea.Cmd {
	tm.statusMsg = msg
	tm.statusGen++
	gen := tm.statusGen
	return tea.Tick(statusFadeDelay, func(time.Time) tea.Msg {
		return statusFadeMsg{gen: gen}
	})
}

// IsModal reports whether the tree is currently showing a modal dialog (e.g.
// delete confirmation). Used by MainWindow to route all keys through the tree
// when modal, so that keys like "n" (no) don't escape to MainWindow's own
// bindings (e.g. NewTable).
func (tm tableTreeModel) IsModal() bool {
	return tm.showDeleteConfirm || tm.searchMode
}

// searchName returns the row's user-visible name for search matching.
func (it flatItem) searchName() string {
	switch {
	case it.isObj:
		return it.objName
	case it.isSet:
		return it.setName
	case it.chain != nil:
		return it.chainName
	case it.isRoot:
		return it.tableName
	}
	return ""
}

// enterSearch begins an incremental search. All tables are expanded so every
// chain / set / object row becomes a candidate (a match hidden inside a
// collapsed table would be unreachable otherwise).
func (tm *tableTreeModel) enterSearch() {
	tm.searchMode = true
	tm.searchQuery = ""
	tm.searchMatches = nil
	tm.searchActive = 0
	for _, n := range tm.nodes {
		n.Expanded = true
	}
}

func (tm *tableTreeModel) exitSearch() {
	tm.searchMode = false
	tm.searchQuery = ""
	tm.searchMatches = nil
	tm.searchActive = 0
}

// recomputeSearchMatches rebuilds searchMatches for the current query (case-
// insensitive substring on the row name) and resets the active match to the
// first hit.
func (tm *tableTreeModel) recomputeSearchMatches() {
	tm.searchMatches = nil
	tm.searchActive = 0
	q := strings.ToLower(strings.TrimSpace(tm.searchQuery))
	if q == "" {
		return
	}
	for i, it := range tm.getFlattenedItems() {
		if strings.Contains(strings.ToLower(it.searchName()), q) {
			tm.searchMatches = append(tm.searchMatches, i)
		}
	}
}

// jumpToActiveMatch parks the cursor on the active match and scrolls it into
// view. No-op when there are no matches.
func (tm *tableTreeModel) jumpToActiveMatch() {
	if len(tm.searchMatches) == 0 {
		return
	}
	tm.searchActive = (tm.searchActive%len(tm.searchMatches) + len(tm.searchMatches)) % len(tm.searchMatches)
	tm.cursor = tm.searchMatches[tm.searchActive]
	tm.ensureCursorVisible()
}

func (tm *tableTreeModel) ensureCursorVisible() {
	if tm.cursor < tm.scrollOffset {
		tm.scrollOffset = tm.cursor
	}
	if tm.maxHeight > 0 && tm.cursor >= tm.scrollOffset+tm.maxHeight {
		tm.scrollOffset = tm.cursor - tm.maxHeight + 1
	}
}

type flatItem struct {
	tableFamily string
	tableName   string
	chainsCount int
	setsCount   int
	objsCount   int
	chainName   string
	setName     string
	objName     string
	rulesCount  int
	isRoot      bool
	isSet       bool
	isObj       bool
	table       *tableNode
	chain       *nftables.Chain
	set         *nftables.Set
	obj         *nft.NamedObject
}

func initialTableTreeModel(filter string) tableTreeModel {
	tables, err := nft.ListTables()
	if err != nil {
		panic(err)
	}
	if filter != "" {
		kept := tables[:0]
		for _, t := range tables {
			if t.Name == filter {
				kept = append(kept, t)
			}
		}
		tables = kept
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

		// Sets and named objects are best-effort — failure to enumerate them
		// (e.g. unsupported kernel features) shouldn't crash the whole tree.
		setsOfTable, _ := nft.GetSets(table)
		objsOfTable, _ := nft.ListNamedObjects(table)

		tableNodes[t] = &tableNode{
			Table:    *table,
			Expanded: false,
			Chains:   chains,
			Rules:    rulesOfTable,
			Sets:     setsOfTable,
			Objects:  objsOfTable,
		}
	}

	return tableTreeModel{
		nodes:       tableNodes,
		cursor:      0,
		tableFilter: filter,
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
			setsCount:   len(table.Sets),
			objsCount:   len(table.Objects),
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
			for _, set := range table.Sets {
				items = append(items, flatItem{
					setName: set.Name,
					isRoot:  false,
					isSet:   true,
					table:   table,
					set:     set,
				})
			}
			for i := range table.Objects {
				o := &table.Objects[i]
				items = append(items, flatItem{
					objName: o.Name,
					isRoot:  false,
					isObj:   true,
					table:   table,
					obj:     o,
				})
			}
		}
	}
	return items
}

// updateSearch handles keys while the tree is in incremental-search mode.
// Printable runes extend the query (and re-jump to the first match); Enter /
// Down advance through matches, Up steps back, Esc leaves search mode.
func (tm tableTreeModel) updateSearch(msg tea.KeyMsg) (tableTreeModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		tm.exitSearch()
	case "ctrl+c":
		return tm, tea.Quit
	case "enter", "down":
		if len(tm.searchMatches) > 0 {
			tm.searchActive++
			tm.jumpToActiveMatch()
		}
	case "up":
		if len(tm.searchMatches) > 0 {
			tm.searchActive--
			tm.jumpToActiveMatch()
		}
	case "backspace":
		if tm.searchQuery != "" {
			tm.searchQuery = tm.searchQuery[:len(tm.searchQuery)-1]
			tm.recomputeSearchMatches()
			tm.jumpToActiveMatch()
		}
	default:
		if len(msg.Runes) == 1 {
			tm.searchQuery += string(msg.Runes)
			tm.recomputeSearchMatches()
			tm.jumpToActiveMatch()
		}
	}
	return tm, nil
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
					if selected.isSet && selected.set != nil {
						tm.showDeleteConfirm = false
						return tm, deleteSetCmd(selected.set)
					}
					if selected.isObj && selected.obj != nil {
						tm.showDeleteConfirm = false
						return tm, deleteNamedObjectCmd(*selected.obj)
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

		if tm.searchMode {
			return tm.updateSearch(msg)
		}

		switch msg.String() {
		case "ctrl+c", "q":
			return tm, tea.Quit
		case "/":
			tm.enterSearch()
			return tm, nil
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
				if selected.isRoot || selected.chain != nil ||
					(selected.isSet && selected.set != nil) ||
					(selected.isObj && selected.obj != nil) {
					tm.showDeleteConfirm = true
				}
			}
		case "s":
			items := tm.getFlattenedItems()
			if tm.cursor < len(items) {
				selected := items[tm.cursor]
				if selected.table != nil {
					t := &selected.table.Table
					return tm, func() tea.Msg {
						return setCreateSelectedMsg{table: t}
					}
				}
			}
		case "R":
			items := tm.getFlattenedItems()
			if tm.cursor < len(items) {
				selected := items[tm.cursor]
				if selected.isObj && selected.obj != nil &&
					(selected.obj.Type == nftables.ObjTypeCounter ||
						selected.obj.Type == nftables.ObjTypeQuota) {
					return tm, resetNamedObjectCmd(*selected.obj)
				}
				cmd := tm.setStatus("no resettable counter/quota under cursor")
				return tm, cmd
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
				if selected.isSet && selected.set != nil {
					s := selected.set
					t := selected.table
					return tm, func() tea.Msg {
						return setSelectedMsg{set: s, table: t}
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
			setsLabel := "set"
			if item.setsCount > 1 {
				setsLabel = "sets"
			}
			objsLabel := "obj"
			if item.objsCount > 1 {
				objsLabel = "objs"
			}
			chainsCountLabel := fmt.Sprintf("[%d %s, %d %s, %d %s, %d %s]",
				item.chainsCount, chainsLabel, item.rulesCount, rulesLabel,
				item.setsCount, setsLabel, item.objsCount, objsLabel)

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
			if len(item.table.Chains) > 0 || len(item.table.Sets) > 0 || len(item.table.Objects) > 0 {
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
		} else if item.isSet {
			// Set node:
			//   plain set: `  ~ <name> (<keytype>)`
			//   map:       `  = <name> (<keytype> → <datatype>)`
			//
			// ASCII-only icons so the tree renders identically on minimal
			// terminals (no UTF-8 dependency).
			isMapItem := item.set != nil && item.set.IsMap
			var typeStr string
			if item.set != nil {
				typeStr = nft.KeyTypeToString(item.set.KeyType)
				if isMapItem {
					typeStr = nft.KeyTypeToString(item.set.KeyType) + " → " + nft.KeyTypeToString(item.set.DataType)
				}
			}

			var setNameStyled, typeStyled, parenOpen, parenClose, space1, space2 string
			if isActive {
				setNameStyled = blueBackgroundStyle.Inherit(yellowStyle).Render(item.setName)
				typeStyled = blueBackgroundStyle.Inherit(whiteStyle).Render(typeStr)
				parenOpen = blueBackgroundStyle.Render("(")
				parenClose = blueBackgroundStyle.Render(")")
				space1 = blueBackgroundStyle.Render(" ")
				space2 = blueBackgroundStyle.Render(" ")
			} else {
				setNameStyled = yellowStyle.Render(item.setName)
				typeStyled = whiteStyle.Render(typeStr)
				parenOpen = "("
				parenClose = ")"
				space1 = " "
				space2 = " "
			}

			label := fmt.Sprintf("%s%s%s%s%s%s", setNameStyled, space1, parenOpen, typeStyled, parenClose, space2)

			icon := "~"
			if isMapItem {
				icon = "="
			}
			var cursorStyled, tildeStyled, spaces string
			if isActive {
				cursorStyled = blueBackgroundStyle.Render(cursor)
				tildeStyled = blueBackgroundStyle.Render(icon)
				spaces = blueBackgroundStyle.Render("   ")
			} else {
				cursorStyled = cursor
				tildeStyled = icon
				spaces = "   "
			}

			line := fmt.Sprintf("%s%s%s%s%s", cursorStyled, spaces, tildeStyled, space1, label)

			if isActive {
				visibleLength := lipgloss.Width(line)
				padding := terminalWidth - visibleLength
				if padding > 0 {
					line += blueBackgroundStyle.Render(strings.Repeat(" ", padding))
				}
			}

			b.WriteString(line)
			b.WriteString("\n")
		} else if item.isObj {
			// Named object row:
			//   counter   → `  # <name> (counter: P pkts, B bytes)`
			//   quota     → `  % <name> (quota: C / B bytes)`
			//   cthelper  → `  & <name> (cthelper: ftp l3=2 l4=6)`
			//   other     → `  * <name> (<type>)`
			obj := item.obj
			detail := obj.TypeStr
			icon := "*"
			switch obj.Type {
			case nftables.ObjTypeCounter:
				icon = "#"
				detail = fmt.Sprintf("counter: %d pkts, %d bytes", obj.Packets, obj.Bytes)
			case nftables.ObjTypeQuota:
				icon = "%"
				detail = fmt.Sprintf("quota: %d / %d bytes", obj.Consumed, obj.QuotaBytes)
			case nftables.ObjTypeCtHelper:
				icon = "&"
				detail = fmt.Sprintf("cthelper: %s l3=%d l4=%d",
					obj.HelperName, obj.L3Proto, obj.L4Proto)
			}

			var objNameStyled, detailStyled, parenOpen, parenClose, space1, space2 string
			if isActive {
				objNameStyled = blueBackgroundStyle.Inherit(yellowStyle).Render(obj.Name)
				detailStyled = blueBackgroundStyle.Inherit(grayStyle).Render(detail)
				parenOpen = blueBackgroundStyle.Render("(")
				parenClose = blueBackgroundStyle.Render(")")
				space1 = blueBackgroundStyle.Render(" ")
				space2 = blueBackgroundStyle.Render(" ")
			} else {
				objNameStyled = yellowStyle.Render(obj.Name)
				detailStyled = grayStyle.Render(detail)
				parenOpen = "("
				parenClose = ")"
				space1 = " "
				space2 = " "
			}

			label := fmt.Sprintf("%s%s%s%s%s%s", objNameStyled, space1, parenOpen, detailStyled, parenClose, space2)

			var cursorStyled, iconStyled, spaces string
			if isActive {
				cursorStyled = blueBackgroundStyle.Render(cursor)
				iconStyled = blueBackgroundStyle.Render(icon)
				spaces = blueBackgroundStyle.Render("   ")
			} else {
				cursorStyled = cursor
				iconStyled = icon
				spaces = "   "
			}

			line := fmt.Sprintf("%s%s%s%s%s", cursorStyled, spaces, iconStyled, space1, label)
			if isActive {
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

	if tm.searchMode {
		// Incremental-search prompt under the tree. The trailing "_" stands in
		// for the input cursor; the suffix reports match position / no-match.
		b.WriteString("\n")
		prompt := yellowBoldStyle.Render("  /" + tm.searchQuery + "_")
		var suffix string
		switch {
		case tm.searchQuery == "":
			suffix = grayStyle.Render("  type to filter by name")
		case len(tm.searchMatches) == 0:
			suffix = grayStyle.Render("  no match")
		default:
			suffix = grayStyle.Render(fmt.Sprintf("  match %d/%d", tm.searchActive+1, len(tm.searchMatches)))
		}
		b.WriteString(prompt + suffix)
		b.WriteString("\n")
	}

	if tm.statusMsg != "" && !tm.showDeleteConfirm && !tm.searchMode {
		// Yellow hint line under the tree — auto-fades ~2s after it's set
		// (see setStatus). Hidden while the delete-confirm overlay is up so
		// a still-fading hint doesn't sit above an unrelated modal. Indented
		// to align with table rows so it doesn't look like a separate widget.
		b.WriteString("\n")
		b.WriteString(yellowStyle.Render("  ! " + tm.statusMsg))
		b.WriteString("\n")
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
			case selected.isSet && selected.set != nil:
				confirmText = fmt.Sprintf("Are you sure you want to delete the '%s' set?\n\nWARNING: Deleting a set referenced by rules will fail at kernel level.\n\n[Y]es / [N]o", selected.setName)
			case selected.isObj && selected.obj != nil:
				confirmText = fmt.Sprintf("Are you sure you want to delete the '%s' %s?\n\nWARNING: Deleting an object referenced by rules will fail at kernel level (EBUSY).\n\n[Y]es / [N]o",
					selected.obj.Name, selected.obj.TypeStr)
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
