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
	chain        *nftables.Chain
	table        *tableNode
	rules        []*nftables.Rule
	width        int
	height       int
	help         help.Model
	keys         chainViewKeyMap
	scrollOffset int
	cursor       int
}

type chainViewKeyMap struct {
	Up           key.Binding
	Down         key.Binding
	OpenRuleView key.Binding
	OpenRuleEdit key.Binding
	Back         key.Binding
	Quit         key.Binding
}

func (k chainViewKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.OpenRuleView, k.OpenRuleEdit, k.Back, k.Quit}
}

func (k chainViewKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.OpenRuleView, k.OpenRuleEdit},
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
			key.WithHelp("f3", "open rule view"),
		),
		OpenRuleEdit: key.NewBinding(
			key.WithKeys("f4"),
			key.WithHelp("f4", "open rule edit"),
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
		help:  help.New(),
		keys:  km,
	}
}

func (c chainView) Update(msg tea.Msg) (chainView, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		c.width, c.height = msg.Width, msg.Height
		return c, nil
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, c.keys.Up):
			if c.cursor > 0 {
				c.cursor--
				if c.cursor < c.scrollOffset {
					c.scrollOffset = c.cursor
				}
			}
		case key.Matches(msg, c.keys.Down):
			maxItems := len(c.rules)
			if c.cursor < maxItems-1 {
				c.cursor++
				maxHeight := c.height - 20 // hozzávetőleges tartalom magasság
				if maxHeight > 0 && c.cursor >= c.scrollOffset+maxHeight {
					c.scrollOffset = c.cursor - maxHeight + 1
				}
			}
		case key.Matches(msg, c.keys.OpenRuleView):
			// F3 megnyomva - kiválasztott rule megnyitása
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
			return c, nil
		case key.Matches(msg, c.keys.OpenRuleEdit):
			// F4 megnyomva - kiválasztott rule megnyitása
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
			return c, nil
		}
	}
	return c, nil
}

func (c chainView) View() string {
	if c.chain == nil {
		return ""
	}

	// Fejléc
	header := blueBoldStyle.Render("nftui nftables manager")

	divider := grayStyle.
		Width(c.width).
		Render(strings.Repeat("─", c.width))

	// Statisztika dobozok
	boxWidth := (c.width - 8) / 4
	if boxWidth < 20 {
		boxWidth = 20
	}

	// Chain név
	chainNameContent := yellowBoldStyle.Render(c.chain.Name) + " chain details"
	chainNameBox := normalGrayBorder.
		Width(boxWidth).
		Padding(0, 1).
		Render(chainNameContent)

	// Table név
	tableContent := blueStyle.Render(c.table.Table.Name) + " table"
	tableBox := normalGrayBorder.
		Width(boxWidth).
		Padding(0, 1).
		Render(tableContent)

	// Rules szám
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

		// Lista renderelése kurzorral
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
			//ruleDefinition, _ := nft.NftablesToRuleDefinition(rule)
			//ruleText += fmt.Sprintf("%+v\n", ruleDefinition)
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

	fullView := lipgloss.JoinVertical(lipgloss.Left,
		header,
		divider,
		statBoxes,
		contentBox,
		footer,
	)

	return defaultStyle.Render(fullView)
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
	// Match by handle (most reliable)
	for _, r := range fresh {
		if r.Handle == handle {
			return r
		}
	}
	// Fall back to cursor position
	if cursor < len(fresh) {
		return fresh[cursor]
	}
	return fallback
}
