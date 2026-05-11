package ui

import (
	"fmt"
	"nftui/nft"
	"nftui/nft/nftserializer"
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
}

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
	Back         key.Binding
	Quit         key.Binding
}

func (k chainViewKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.OpenRuleView, k.OpenRuleEdit, k.Delete, k.MoveUp, k.MoveDown, k.NewRule, k.InsertRule, k.Back, k.Quit}
}

func (k chainViewKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.OpenRuleView, k.OpenRuleEdit},
		{k.Delete, k.MoveUp, k.MoveDown, k.NewRule, k.InsertRule},
		{k.Back, k.Quit},
	}
}

func newChainView(chain *nftables.Chain, table *tableNode) chainView {
	rules, err := nft.ListRulesOfChain(&table.Table, chain)
	if err != nil {
		panic(err)
	}

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
		Back: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "back"),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "quit"),
		),
	}

	return chainView{
		chain: chain,
		table: table,
		rules: rules,
		help:  newHelpModel(),
		keys:  km,
	}
}

// IsModal reports whether a confirmation dialog is currently shown.
// Used by main_window to route all keys through Update when true.
func (c chainView) IsModal() bool {
	return c.showDeleteConfirm
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

		switch {
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
				maxHeight := c.height - 20
				if maxHeight > 0 && c.cursor >= c.scrollOffset+maxHeight {
					c.scrollOffset = c.cursor - maxHeight + 1
				}
			}

		case key.Matches(msg, c.keys.OpenRuleView):
			if c.cursor >= 0 && c.cursor < len(c.rules) {
				table := c.table
				chain := c.chain
				handle := c.rules[c.cursor].Handle
				cursor := c.cursor
				fallback := c.rules[c.cursor]
				return c, func() tea.Msg {
					return ruleViewSelectedMsg{rule: fetchFreshRule(table, chain, handle, cursor, fallback)}
				}
			}

		case key.Matches(msg, c.keys.OpenRuleEdit):
			if c.cursor >= 0 && c.cursor < len(c.rules) {
				table := c.table
				chain := c.chain
				handle := c.rules[c.cursor].Handle
				cursor := c.cursor
				fallback := c.rules[c.cursor]
				return c, func() tea.Msg {
					return ruleEditSelectedMsg{rule: fetchFreshRule(table, chain, handle, cursor, fallback)}
				}
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
	header := blueBoldStyle.Render("nftui nftables manager")

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

	// Rules count
	rulesForChain := c.getRulesForChain()
	rulesCount := fmt.Sprintf("%d rules", len(rulesForChain))
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
	content.WriteString("\n\n")

	content.WriteString(grayStyle.Render("Table" + ": "))
	content.WriteString(blueStyle.Render(c.table.Table.Name))
	content.WriteString(grayStyle.Render(" ("))
	content.WriteString(nft.TableFamilyToString(c.table.Table.Family))
	content.WriteString(grayStyle.Render(")"))
	content.WriteString("\n")

	content.WriteString(grayStyle.Render("Type" + ": "))
	content.WriteString(whiteStyle.Render(fmt.Sprintf("%s", c.chain.Type)))
	content.WriteString("\n")

	if c.chain.Hooknum != nil {
		content.WriteString(grayStyle.Render("Hook" + ": "))
		content.WriteString(whiteStyle.Render(nft.ChainHookNumToString(*c.chain.Hooknum)))
		content.WriteString("\n")
	}

	if c.chain.Priority != nil {
		content.WriteString(grayStyle.Render("Priority" + ": "))
		content.WriteString(whiteStyle.Render(fmt.Sprintf("%d", *c.chain.Priority)))
		content.WriteString("\n")
	}

	if c.chain.Policy != nil {
		content.WriteString(grayStyle.Render("Default policy" + ": "))
		if *c.chain.Policy == nftables.ChainPolicyAccept {
			content.WriteString(greenStyle.Render(nft.ChainPolicyToString(*c.chain.Policy)))
		} else if *c.chain.Policy == nftables.ChainPolicyDrop {
			content.WriteString(redStyle.Render(nft.ChainPolicyToString(*c.chain.Policy)))
		}
		content.WriteString("\n")
	}

	content.WriteString("\n")

	acceptCount, dropCount, otherCount := nft.CountRulesByType(rulesForChain)

	content.WriteString(grayStyle.Render("Rules by type" + ":"))
	content.WriteString("\n")
	content.WriteString(fmt.Sprintf("  • ACCEPT: %s\n", greenStyle.Render(fmt.Sprintf("%d", acceptCount))))
	content.WriteString(fmt.Sprintf("  • DROP: %s\n", redStyle.Render(fmt.Sprintf("%d", dropCount))))
	content.WriteString(fmt.Sprintf("  • etc: %s\n", whiteStyle.Render(fmt.Sprintf("%d", otherCount))))

	if len(c.rules) > 0 {
		content.WriteString(defaultBoldStyle.Render("Rules:"))
		content.WriteString("\n\n")

		// Render list with cursor
		maxHeight := c.height - 20
		startIdx := c.scrollOffset
		endIdx := len(c.rules)
		if maxHeight > 0 && endIdx > startIdx+maxHeight {
			endIdx = startIdx + maxHeight
		}

		for i := startIdx; i < endIdx && i < len(c.rules); i++ {
			rule := c.rules[i]
			cursor := "  "
			if i == c.cursor {
				cursor = "> "
			}

			ruleText := fmt.Sprintf("%s%d. %s\n", cursor, rule.Position, nft.RuleToHumanReadable(rule))
			ruleText += fmt.Sprintf("  %d. %s\n", rule.Position, nftserializer.SerializeRule(rule))
			if i == c.cursor {
				ruleText = blueBackgroundStyle.Render(ruleText)
			}
			content.WriteString(ruleText)

			content.WriteString("\n\n")
		}
	}

	contentBox := normalGrayBorder.
		Width(c.width-2).
		Height(c.height-8).
		Padding(0, 1).
		Render(content.String())

	footer := c.help.View(c.keys)

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

func (c chainView) getRulesForChain() []*nftables.Rule {
	rules, err := nft.ListRulesOfChain(&c.table.Table, c.chain)
	if err != nil {
		panic(err)
	}
	return rules
}

// RefreshRules re-fetches the chain's rules from the kernel.
// Call this after a rule has been saved to ensure fresh data on next open.
func (c *chainView) RefreshRules() {
	rules, err := nft.ListRulesOfChain(&c.table.Table, c.chain)
	if err == nil {
		c.rules = rules
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
