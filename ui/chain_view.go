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

type chainView struct {
	chain             *nftables.Chain
	table             *tableNode
	rules             []*nftables.Rule
	width             int
	height            int
	help              help.Model
	keys              chainViewKeyMap
	scrollOffset      int
	cursor            int
	showDeleteConfirm bool
	statusMsg         string // last error or status from an async chain operation

	// Inline rule filter (entered with "/"). While filterMode is on the view
	// is modal so printable keys build filterQuery instead of triggering rule
	// actions; the list narrows to rules whose text/comment match. cursor and
	// scrollOffset index the filtered slice (see activeRules).
	filterMode  bool
	filterQuery string

	// readOnly mirrors Options.ReadOnly. Disabled write bindings dim out
	// of the footer; key.Matches won't match a disabled binding either, so
	// the handlers below never fire on a write key when set.
	readOnly bool

	// matchCache memoizes the lowercase "rendered text + comment" haystack
	// per rule.Handle. Populated lazily by ruleMatchesFilter on first use,
	// cleared by RefreshRules when the rule list changes. Without it, typing
	// in the filter on a 1000-rule chain would re-serialize every rule on
	// every keystroke (activeRules walks the full slice each call, and View
	// + the filter handler both invoke it).
	matchCache map[uint64]string
}

// ruleEntryLines is the visual height of one rule entry in the chain view:
// the human-readable rule line plus two trailing blank lines (so the next rule
// has breathing room). Used by maxVisibleRules to translate the content-box
// pixel budget into a rule count.
const ruleEntryLines = 3

type chainViewKeyMap struct {
	Up           key.Binding
	Down         key.Binding
	OpenRuleView key.Binding
	OpenRuleEdit key.Binding
	Delete       key.Binding
	MoveUp       key.Binding
	MoveDown     key.Binding
	NewRule      key.Binding
	InsertRule   key.Binding
	Filter       key.Binding
	Back         key.Binding
	Quit         key.Binding
}

func (k chainViewKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.OpenRuleView, k.OpenRuleEdit, k.Delete, k.MoveUp, k.MoveDown, k.NewRule, k.InsertRule, k.Filter, k.Back, k.Quit}
}

func (k chainViewKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.OpenRuleView, k.OpenRuleEdit},
		{k.Delete, k.MoveUp, k.MoveDown, k.NewRule, k.InsertRule},
		{k.Filter, k.Back, k.Quit},
	}
}

// newChainView fetches the chain's rules over netlink and builds the view. A
// fetch failure is returned so the caller can surface it gracefully instead of
// crashing the TUI (audit E-3 / R2).
func newChainView(chain *nftables.Chain, table *tableNode, readOnly bool) (chainView, error) {
	rules, err := nft.ListRulesOfChain(&table.Table, chain)
	if err != nil {
		return chainView{}, err
	}
	return newChainViewWithRules(chain, table, rules, readOnly), nil
}

// newChainViewWithRules builds the view around an already-fetched rule list —
// the netlink-free core of newChainView, shared with the unit tests.
func newChainViewWithRules(chain *nftables.Chain, table *tableNode, rules []*nftables.Rule, readOnly bool) chainView {
	km := chainViewKeyMap{
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("↑/k", "up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("↓/j", "down"),
		),
		OpenRuleView: key.NewBinding(
			key.WithKeys("f3"),
			key.WithHelp("f3", "view rule"),
		),
		OpenRuleEdit: key.NewBinding(
			key.WithKeys("f4"),
			key.WithHelp("f4", "edit rule"),
		),
		Delete: key.NewBinding(
			key.WithKeys("d"),
			key.WithHelp("d", "delete rule"),
		),
		MoveUp: key.NewBinding(
			key.WithKeys("K"),
			key.WithHelp("K", "move up"),
		),
		MoveDown: key.NewBinding(
			key.WithKeys("J"),
			key.WithHelp("J", "move down"),
		),
		NewRule: key.NewBinding(
			key.WithKeys("a"),
			key.WithHelp("a", "add rule"),
		),
		InsertRule: key.NewBinding(
			key.WithKeys("i"),
			key.WithHelp("i", "insert rule"),
		),
		Filter: key.NewBinding(
			key.WithKeys("/"),
			key.WithHelp("/", "filter rules"),
		),
		Back: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "back"),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "quit"),
		),
	}

	if readOnly {
		// Footer dims; key.Matches on a disabled binding returns false too,
		// so the handlers in Update never fire on these keys.
		km.Delete.SetEnabled(false)
		km.MoveUp.SetEnabled(false)
		km.MoveDown.SetEnabled(false)
		km.NewRule.SetEnabled(false)
		km.InsertRule.SetEnabled(false)
		km.OpenRuleEdit.SetEnabled(false)
	}

	return chainView{
		chain:      chain,
		table:      table,
		rules:      rules,
		help:       newHelpModel(),
		keys:       km,
		readOnly:   readOnly,
		matchCache: make(map[uint64]string),
	}
}

// headerLines counts the lines rendered inside the content box before the
// first rule entry: the "Chain:" title + blank, the table/type lines, the
// optional hook/priority/policy lines, the rules-by-type summary, the
// optional filter prompt block, and the "Rules:" header line. Counted
// dynamically because the optional fields shift the budget for the rule
// list, and so does turning the filter prompt on or off.
func (c chainView) headerLines() int {
	// Compact header: "Chain: <name>" + one metadata line (table/type/hook/
	// priority/policy) + one "Rules by type" line + a trailing blank.
	n := 4
	if c.filterMode {
		n += 2 // filter prompt line + trailing blank
	}
	return n
}

// maxVisibleRules is how many rule entries fit inside the content box at the
// current terminal height. The window math (View loop bound, Down/Up scroll
// triggers) all routes through here so a 1000-rule chain renders the same
// fixed number of entries as a 10-rule chain — the cost is O(window), not
// O(N). Clamped to at least 1 so a tiny terminal still scrolls one rule at
// a time instead of locking the cursor.
func (c chainView) maxVisibleRules() int {
	inner := c.height - 9 // contentBox content height (must match View's Height(c.height-9))
	avail := inner - c.headerLines()
	if avail < ruleEntryLines {
		return 1
	}
	return avail / ruleEntryLines
}

// IsModal reports whether a confirmation dialog or the inline filter is
// active. Used by main_window to route all keys through Update when true so
// that filter typing (and Esc) doesn't escape to the global bindings.
func (c chainView) IsModal() bool {
	return c.showDeleteConfirm || c.filterMode
}

// activeRules is the rule slice the cursor and the rendered list operate on:
// the full chain rules normally, or just the matches while filtering.
func (c chainView) activeRules() []*nftables.Rule {
	if !c.filterMode || strings.TrimSpace(c.filterQuery) == "" {
		return c.rules
	}
	var out []*nftables.Rule
	for _, r := range c.rules {
		if c.ruleMatchesFilter(r) {
			out = append(out, r)
		}
	}
	return out
}

// ruleMatchesFilter reports whether rule matches the current filterQuery
// (case-insensitive substring over the rendered rule text and its comment —
// so verdict, condition keywords and comment text are all searchable). The
// lowercased haystack is memoized in matchCache so subsequent keystrokes
// don't re-serialize the rule.
func (c chainView) ruleMatchesFilter(rule *nftables.Rule) bool {
	q := strings.ToLower(strings.TrimSpace(c.filterQuery))
	if q == "" {
		return true
	}
	hay, ok := c.matchCache[rule.Handle]
	if !ok {
		hay = strings.ToLower(nft.RuleToHumanReadable(rule) + " " + nft.ExtractComment(rule))
		c.matchCache[rule.Handle] = hay
	}
	return strings.Contains(hay, q)
}

func (c *chainView) enterFilter() {
	c.filterMode = true
	c.filterQuery = ""
	c.cursor = 0
	c.scrollOffset = 0
}

func (c *chainView) exitFilter() {
	c.filterMode = false
	c.filterQuery = ""
	c.cursor = 0
	c.scrollOffset = 0
}

// ruleViewCmd / ruleEditCmd open the given rule (re-fetched fresh by handle)
// in the read-only viewer / editor. Shared by the normal key handlers and the
// filter handler so both open the rule under the cursor identically.
func (c chainView) ruleViewCmd(rule *nftables.Rule, cursor int) tea.Cmd {
	table, chain, handle := c.table, c.chain, rule.Handle
	return func() tea.Msg {
		return ruleViewSelectedMsg{rule: fetchFreshRule(table, chain, handle, cursor, rule)}
	}
}
func (c chainView) ruleEditCmd(rule *nftables.Rule, cursor int) tea.Cmd {
	table, chain, handle := c.table, c.chain, rule.Handle
	return func() tea.Msg {
		return ruleEditSelectedMsg{rule: fetchFreshRule(table, chain, handle, cursor, rule)}
	}
}

// updateFilter handles keys while the inline rule filter is active. Printable
// runes extend the query (narrowing the list); arrows navigate the filtered
// rules; f3/Enter open the selected rule, f4 edits it; Esc clears the filter.
func (c chainView) updateFilter(msg tea.KeyMsg) (chainView, tea.Cmd) {
	rules := c.activeRules()
	switch msg.String() {
	case "esc":
		c.exitFilter()
	case "ctrl+c":
		return c, tea.Quit
	case "up":
		if c.cursor > 0 {
			c.cursor--
			if c.cursor < c.scrollOffset {
				c.scrollOffset = c.cursor
			}
		}
	case "down":
		if c.cursor < len(rules)-1 {
			c.cursor++
			maxHeight := c.maxVisibleRules()
			if c.cursor >= c.scrollOffset+maxHeight {
				c.scrollOffset = c.cursor - maxHeight + 1
			}
		}
	case "f3", "enter":
		if c.cursor >= 0 && c.cursor < len(rules) {
			return c, c.ruleViewCmd(rules[c.cursor], c.cursor)
		}
	case "f4":
		if c.readOnly {
			return c, nil
		}
		if c.cursor >= 0 && c.cursor < len(rules) {
			return c, c.ruleEditCmd(rules[c.cursor], c.cursor)
		}
	case "backspace":
		if c.filterQuery != "" {
			c.filterQuery = c.filterQuery[:len(c.filterQuery)-1]
			c.cursor, c.scrollOffset = 0, 0
		}
	default:
		if len(msg.Runes) == 1 {
			c.filterQuery += string(msg.Runes)
			c.cursor, c.scrollOffset = 0, 0
		}
	}
	return c, nil
}

// chainFilterKeyMap is the footer shown while the rule filter is active.
type chainFilterKeyMap struct {
	Filter key.Binding
	Next   key.Binding
	Prev   key.Binding
	Open   key.Binding
	Edit   key.Binding
	Exit   key.Binding
}

func (k chainFilterKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Filter, k.Next, k.Prev, k.Open, k.Edit, k.Exit}
}
func (k chainFilterKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{k.Filter, k.Next, k.Prev}, {k.Open, k.Edit, k.Exit}}
}

var chainFilterKeys = chainFilterKeyMap{
	Filter: key.NewBinding(key.WithKeys("a-z"), key.WithHelp("type", "filter")),
	Next:   key.NewBinding(key.WithKeys("down"), key.WithHelp("↓", "next")),
	Prev:   key.NewBinding(key.WithKeys("up"), key.WithHelp("↑", "prev")),
	Open:   key.NewBinding(key.WithKeys("enter", "f3"), key.WithHelp("enter/f3", "view")),
	Edit:   key.NewBinding(key.WithKeys("f4"), key.WithHelp("f4", "edit")),
	Exit:   key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "clear filter")),
}

func (c chainView) Update(msg tea.Msg) (chainView, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		c.width, c.height = msg.Width, msg.Height
		return c, nil

	case tea.KeyMsg:
		c.statusMsg = "" // clear previous status on any key press

		// While the delete confirmation is shown, intercept y/n/esc only.
		if c.showDeleteConfirm {
			switch msg.String() {
			case "y", "Y":
				c.showDeleteConfirm = false
				if c.cursor >= 0 && c.cursor < len(c.rules) {
					rule := c.rules[c.cursor]
					return c, deleteRuleCmd(rule)
				}
			case "n", "N", "esc":
				c.showDeleteConfirm = false
			}
			return c, nil
		}

		if c.filterMode {
			return c.updateFilter(msg)
		}

		switch {
		case key.Matches(msg, c.keys.Filter):
			c.enterFilter()
			return c, nil
		case key.Matches(msg, c.keys.Up):
			if c.cursor > 0 {
				c.cursor--
				if c.cursor < c.scrollOffset {
					c.scrollOffset = c.cursor
				}
			}

		case key.Matches(msg, c.keys.Down):
			if c.cursor < len(c.rules)-1 {
				c.cursor++
				maxHeight := c.maxVisibleRules()
				if c.cursor >= c.scrollOffset+maxHeight {
					c.scrollOffset = c.cursor - maxHeight + 1
				}
			}

		case key.Matches(msg, c.keys.OpenRuleView):
			if c.cursor >= 0 && c.cursor < len(c.rules) {
				return c, c.ruleViewCmd(c.rules[c.cursor], c.cursor)
			}

		case key.Matches(msg, c.keys.OpenRuleEdit):
			if c.cursor >= 0 && c.cursor < len(c.rules) {
				return c, c.ruleEditCmd(c.rules[c.cursor], c.cursor)
			}

		case key.Matches(msg, c.keys.Delete):
			if len(c.rules) > 0 && c.cursor >= 0 && c.cursor < len(c.rules) {
				c.showDeleteConfirm = true
			}

		case key.Matches(msg, c.keys.MoveUp):
			if c.cursor > 0 && c.cursor < len(c.rules) {
				return c, moveRuleUpCmd(c.rules, c.cursor)
			}

		case key.Matches(msg, c.keys.MoveDown):
			if c.cursor >= 0 && c.cursor < len(c.rules)-1 {
				return c, moveRuleDownCmd(c.rules, c.cursor)
			}

		case key.Matches(msg, c.keys.NewRule):
			return c, addNewRuleToChainCmd(c.table, c.chain)

		case key.Matches(msg, c.keys.InsertRule):
			idx := c.cursor
			if idx < 0 {
				idx = 0
			}
			return c, insertNewRuleBeforeCmd(c.table, c.chain, c.rules, idx)
		}
	}
	return c, nil
}

func (c chainView) View() string {
	if c.chain == nil {
		return ""
	}

	// Header
	header := blueBoldStyle.Render("nftui nftables manager") + readOnlyBanner(c.readOnly)

	divider := grayStyle.
		Width(c.width).
		Render(strings.Repeat("─", c.width))

	// Statistics boxes
	boxWidth := (c.width - 8) / 4
	if boxWidth < 20 {
		boxWidth = 20
	}

	// Chain name
	chainNameContent := yellowBoldStyle.Render(c.chain.Name) + " chain details"
	chainNameBox := normalGrayBorder.
		Width(boxWidth).
		Padding(0, 1).
		Render(chainNameContent)

	// Table name
	tableContent := blueStyle.Render(c.table.Table.Name) + " table"
	tableBox := normalGrayBorder.
		Width(boxWidth).
		Padding(0, 1).
		Render(tableContent)

	// Rules count — from the already-fetched list. View must never hit
	// netlink: it runs on every keystroke (the previous re-fetch here cost a
	// full ListRulesOfChain per render and panicked the whole TUI on a
	// transient netlink error). RefreshRules keeps c.rules current after
	// every rule mutation.
	rulesCount := fmt.Sprintf("%d rules", len(c.rules))
	rulesBox := normalGrayBorder.
		Width(boxWidth).
		Padding(0, 1).
		Render(rulesCount)

	// Policy
	policyContent := "no policy"
	if c.chain.Policy != nil {
		if *c.chain.Policy == nftables.ChainPolicyAccept {
			policyContent = greenBoldStyle.Render("ACCEPT") + " policy"
		} else if *c.chain.Policy == nftables.ChainPolicyDrop {
			policyContent = redBoldStyle.Render("DROP") + " policy"
		}
	}
	policyBox := normalGrayBorder.
		Width(boxWidth).
		Padding(0, 1).
		Render(policyContent)

	statBoxes := lipgloss.JoinHorizontal(lipgloss.Top, chainNameBox, tableBox, rulesBox, policyBox)

	var content strings.Builder

	title := fmt.Sprintf("Chain"+": %s", yellowBoldStyle.Render(c.chain.Name))
	content.WriteString(defaultBoldStyle.Render(title))
	content.WriteString("\n")

	// Metadata on one compact line so small terminals keep room for rules.
	meta := grayStyle.Render("Table"+": ") + blueStyle.Render(c.table.Table.Name) +
		grayStyle.Render(" ("+nft.TableFamilyToString(c.table.Table.Family)+")") +
		grayStyle.Render("   Type"+": ") + whiteStyle.Render(fmt.Sprintf("%s", c.chain.Type))
	if c.chain.Hooknum != nil {
		meta += grayStyle.Render("   Hook"+": ") + whiteStyle.Render(nft.ChainHookNumToString(*c.chain.Hooknum))
	}
	if c.chain.Priority != nil {
		meta += grayStyle.Render("   Priority"+": ") + whiteStyle.Render(fmt.Sprintf("%d", *c.chain.Priority))
	}
	if c.chain.Policy != nil {
		pol := nft.ChainPolicyToString(*c.chain.Policy)
		polStyled := whiteStyle.Render(pol)
		if *c.chain.Policy == nftables.ChainPolicyAccept {
			polStyled = greenStyle.Render(pol)
		} else if *c.chain.Policy == nftables.ChainPolicyDrop {
			polStyled = redStyle.Render(pol)
		}
		meta += grayStyle.Render("   Policy"+": ") + polStyled
	}
	content.WriteString(meta)
	content.WriteString("\n")

	acceptCount, dropCount, otherCount := nft.CountRulesByType(c.rules)
	content.WriteString(grayStyle.Render("Rules by type"+": ") +
		greenStyle.Render(fmt.Sprintf("ACCEPT %d", acceptCount)) + grayStyle.Render("   ") +
		redStyle.Render(fmt.Sprintf("DROP %d", dropCount)) + grayStyle.Render("   ") +
		whiteStyle.Render(fmt.Sprintf("etc %d", otherCount)))
	content.WriteString("\n\n")

	if c.filterMode {
		// Filter prompt line — trailing "_" stands in for the input cursor,
		// suffix reports how many rules match the current query.
		prompt := yellowBoldStyle.Render("  /" + c.filterQuery + "_")
		var suffix string
		switch {
		case strings.TrimSpace(c.filterQuery) == "":
			suffix = grayStyle.Render("  type to filter rules (verdict / condition / comment)")
		case len(c.activeRules()) == 0:
			suffix = grayStyle.Render("  no match")
		default:
			suffix = grayStyle.Render(fmt.Sprintf("  %d match", len(c.activeRules())))
		}
		content.WriteString(prompt + suffix + "\n\n")
	}

	rules := c.activeRules()
	if len(rules) > 0 {
		// Render list with cursor. The window cap is computed from the live
		// terminal height so the loop iterates O(window), not O(N) — a chain
		// with 1000 rules costs the same to render as one with 10.
		maxHeight := c.maxVisibleRules()
		startIdx := c.scrollOffset
		endIdx := len(rules)
		if endIdx > startIdx+maxHeight {
			endIdx = startIdx + maxHeight
		}

		for i := startIdx; i < endIdx && i < len(rules); i++ {
			rule := rules[i]
			cursor := "  "
			if i == c.cursor {
				cursor = "> "
			}

			ruleText := fmt.Sprintf("%s%d. %s\n", cursor, rule.Position, nft.RuleToHumanReadable(rule))
			if i == c.cursor {
				ruleText = blueBackgroundStyle.Render(ruleText)
			}
			content.WriteString(ruleText)

			content.WriteString("\n\n")
		}
	}

	contentBox := normalGrayBorder.
		Width(c.width-2).
		Height(c.height-9).
		Padding(0, 1).
		Render(content.String())

	footer := c.help.View(c.keys)
	if c.filterMode {
		// Filter mode swaps in its own footer (footer-completeness invariant).
		footer = c.help.View(chainFilterKeys)
	}

	parts := []string{header, divider, statBoxes, contentBox}
	if c.statusMsg != "" {
		parts = append(parts, redBoldStyle.Render("Error: "+c.statusMsg))
	}
	parts = append(parts, footer)

	fullView := lipgloss.JoinVertical(lipgloss.Left, parts...)

	base := defaultStyle.Render(fullView)

	if c.showDeleteConfirm {
		confirmBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("196")).
			Padding(1, 2).
			Width(50).
			Align(lipgloss.Center).
			Render("Are you sure you want to delete the selected rule?\n\n[Y]es / [N]o")

		overlay := lipgloss.Place(c.width, c.height,
			lipgloss.Center, lipgloss.Center,
			confirmBox,
		)
		return lipgloss.Place(c.width, c.height, lipgloss.Left, lipgloss.Top, base+"\n"+overlay)
	}

	return base
}

// RefreshRules re-fetches the chain's rules from the kernel.
// Call this after a rule has been saved to ensure fresh data on next open.
// Cursor and scroll offset are clamped to the new (possibly filtered) list
// so they don't dangle past the end after a rule was added or removed.
// The filter-match cache is cleared too: handles survive a rule edit but
// the rendered text behind them does not.
func (c *chainView) RefreshRules() {
	rules, err := nft.ListRulesOfChain(&c.table.Table, c.chain)
	if err == nil {
		c.rules = rules
	}
	clear(c.matchCache)
	n := len(c.activeRules())
	if c.cursor >= n {
		c.cursor = n - 1
	}
	if c.cursor < 0 {
		c.cursor = 0
	}
	if c.scrollOffset > c.cursor {
		c.scrollOffset = c.cursor
	}
}

// fetchFreshRule re-fetches rules from the kernel and returns the rule matching
// the given handle. Falls back to the in-memory rule if fetching fails.
func fetchFreshRule(table *tableNode, chain *nftables.Chain, handle uint64, cursor int, fallback *nftables.Rule) *nftables.Rule {
	fresh, err := nft.ListRulesOfChain(&table.Table, chain)
	if err != nil {
		return fallback
	}
	for _, r := range fresh {
		if r.Handle == handle {
			return r
		}
	}
	if cursor < len(fresh) {
		return fresh[cursor]
	}
	return fallback
}
