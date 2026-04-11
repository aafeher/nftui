package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"nftui/nft"
)

// ruleEditKeyMap defines key bindings for navigation and actions within the rule editing interface.
type ruleEditKeyMap struct {
	PrevTab key.Binding
	NextTab key.Binding
	Back    key.Binding
	Save    key.Binding
	Quit    key.Binding
}

// ShortHelp returns a slice of key bindings for primary actions.
func (k ruleEditKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.PrevTab, k.NextTab, k.Back, k.Save, k.Quit}
}

// FullHelp returns a matrix of key bindings for detailed interface navigation.
func (k ruleEditKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.PrevTab, k.NextTab, k.Back, k.Save, k.Quit},
	}
}

// editTab groups related FieldEditors under a named tab.
type editTab struct {
	name   string
	fields []FieldEditor
}

// ruleEdit represents a model for editing nftables rules using the FieldEditor interface pattern.
type ruleEdit struct {
	rule         *nftables.Rule
	tabs         []editTab
	activeTab    int
	tabFocusSlot []int // current focus slot within each tab
	width        int
	height       int
	keys         ruleEditKeyMap
	help         help.Model
}

// editTabTotalSlots returns the total number of focus slots in a tab.
func editTabTotalSlots(tab editTab) int {
	total := 0
	for _, f := range tab.fields {
		total += f.FocusSlots()
	}
	return total
}

// fieldAtTabSlot returns the FieldEditor and sub-index for a given tab and slot number.
func (r ruleEdit) fieldAtTabSlot(tabIdx, slot int) (FieldEditor, int) {
	if tabIdx >= len(r.tabs) {
		return nil, 0
	}
	s := 0
	for _, f := range r.tabs[tabIdx].fields {
		for sub := 0; sub < f.FocusSlots(); sub++ {
			if s == slot {
				return f, sub
			}
			s++
		}
	}
	return nil, 0
}

// newRuleEdit initializes and returns a ruleEdit structure for editing nftables rules.
func newRuleEdit(rule *nftables.Rule) ruleEdit {
	km := ruleEditKeyMap{
		PrevTab: key.NewBinding(
			key.WithKeys("f5"),
			key.WithHelp("f5", "előző fül"),
		),
		NextTab: key.NewBinding(
			key.WithKeys("f6"),
			key.WithHelp("f6", "következő fül"),
		),
		Back: key.NewBinding(
			key.WithKeys("esc", "f3"),
			key.WithHelp("esc/f3", "vissza"),
		),
		Save: key.NewBinding(
			key.WithKeys("f2"),
			key.WithHelp("f2", "mentés"),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "kilépés"),
		),
	}

	rd, _ := nft.NftablesToRuleDefinition(rule)

	tabs := []editTab{
		{
			name: "Általános",
			fields: []FieldEditor{
				NewPositionField(rd),
				NewCommentField(rd),
			},
		},
		{
			name: "CT",
			fields: []FieldEditor{
				NewCtL3ProtoField(rd),    // slots 0,1
				NewCtProtocolField(rd),   // slots 2,3
				NewCtStateField(rd),      // slot 4
				NewCtDirectionField(rd),  // slot 5
				NewCtStatusField(rd),     // slot 6
				NewCtMarkField(rd),       // slot 7
				NewCtExpirationField(rd), // slot 8
				NewCtHelperField(rd),     // slot 9
				NewCtBytesField(rd),      // slots 10,11
				NewCtPktsField(rd),       // slots 12,13
			},
		},
		{
			name: "Hálózat",
			fields: []FieldEditor{
				NewIPSaddrField(rd), // slots 0,1
				NewIPDaddrField(rd), // slots 2,3
			},
		},
		{
			name: "Limit",
			fields: []FieldEditor{
				NewLimitOverField(rd),
				NewLimitRateField(rd),
				NewLimitUnitField(rd),
				NewLimitBurstField(rd),
				NewLimitTypeField(rd),
			},
		},
	}

	// Focus first field of first tab
	if len(tabs) > 0 && len(tabs[0].fields) > 0 {
		tabs[0].fields[0].Focus(0)
	}

	return ruleEdit{
		rule:         rule,
		tabs:         tabs,
		activeTab:    0,
		tabFocusSlot: make([]int, len(tabs)),
		keys:         km,
		help:         help.New(),
	}
}

// Update processes user inputs and updates the state of the rule editor.
func (r ruleEdit) Update(msg tea.Msg) (ruleEdit, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		r.width, r.height = msg.Width, msg.Height
		return r, nil

	case tea.KeyMsg:
		// Tab switching
		switch {
		case key.Matches(msg, r.keys.PrevTab):
			cur, _ := r.fieldAtTabSlot(r.activeTab, r.tabFocusSlot[r.activeTab])
			if cur != nil {
				cur.Blur()
			}
			r.activeTab = (r.activeTab - 1 + len(r.tabs)) % len(r.tabs)
			next, sub := r.fieldAtTabSlot(r.activeTab, r.tabFocusSlot[r.activeTab])
			if next != nil {
				next.Focus(sub)
			}
			return r, nil

		case key.Matches(msg, r.keys.NextTab):
			cur, _ := r.fieldAtTabSlot(r.activeTab, r.tabFocusSlot[r.activeTab])
			if cur != nil {
				cur.Blur()
			}
			r.activeTab = (r.activeTab + 1) % len(r.tabs)
			next, sub := r.fieldAtTabSlot(r.activeTab, r.tabFocusSlot[r.activeTab])
			if next != nil {
				next.Focus(sub)
			}
			return r, nil
		}

		// Within-tab focus navigation
		switch msg.String() {
		case "tab", "shift+tab":
			cur, _ := r.fieldAtTabSlot(r.activeTab, r.tabFocusSlot[r.activeTab])
			if cur != nil {
				cur.Blur()
			}
			totalSlots := editTabTotalSlots(r.tabs[r.activeTab])
			if msg.String() == "tab" {
				r.tabFocusSlot[r.activeTab] = (r.tabFocusSlot[r.activeTab] + 1) % totalSlots
			} else {
				r.tabFocusSlot[r.activeTab] = (r.tabFocusSlot[r.activeTab] - 1 + totalSlots) % totalSlots
			}
			next, sub := r.fieldAtTabSlot(r.activeTab, r.tabFocusSlot[r.activeTab])
			if next != nil {
				next.Focus(sub)
			}
			return r, nil
		}

		// Save: applies all fields across all tabs
		if key.Matches(msg, r.keys.Save) {
			for _, tab := range r.tabs {
				for _, f := range tab.fields {
					f.Save(r.rule)
				}
			}
			saveCmd := func() tea.Msg {
				err := nft.ApplyRuleChange(r.rule)
				if err != nil {
					return fmt.Errorf("mentési hiba: %w", err)
				}
				return nil
			}
			return r, saveCmd
		}

		cur, _ := r.fieldAtTabSlot(r.activeTab, r.tabFocusSlot[r.activeTab])
		if cur != nil {
			return r, cur.Update(msg)
		}
		return r, nil

	default:
		cur, _ := r.fieldAtTabSlot(r.activeTab, r.tabFocusSlot[r.activeTab])
		if cur != nil {
			return r, cur.Update(msg)
		}
		return r, nil
	}
}

// renderTabBar renders the horizontal tab strip.
func (r ruleEdit) renderTabBar() string {
	var parts []string
	for i, tab := range r.tabs {
		label := "  " + tab.name + "  "
		if i == r.activeTab {
			parts = append(parts, whiteBoldStyle.Background(lipgloss.Color("#264f88")).Render(label))
		} else {
			parts = append(parts, grayStyle.Render(label))
		}
		if i < len(r.tabs)-1 {
			parts = append(parts, grayStyle.Render("│"))
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
}

// col2Width returns column width for 2-column layouts.
func (r ruleEdit) col2Width() int {
	w := (r.width - 6) / 2
	if w < 32 {
		w = 32
	}
	return w
}

// col3Width returns column width for 3-column layouts.
func (r ruleEdit) col3Width() int {
	w := (r.width - 8) / 3
	if w < 22 {
		w = 22
	}
	return w
}

// row2 renders two field views side by side.
func (r ruleEdit) row2(a, b string) string {
	cw := r.col2Width()
	return lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(cw).Render(a),
		lipgloss.NewStyle().Width(cw).Render(b),
	)
}

// row3 renders three field views side by side.
func (r ruleEdit) row3(a, b, c string) string {
	cw := r.col3Width()
	return lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(cw).Render(a),
		lipgloss.NewStyle().Width(cw).Render(b),
		lipgloss.NewStyle().Width(cw).Render(c),
	)
}

// renderGeneralTab renders the Általános (General) tab content.
func (r ruleEdit) renderGeneralTab(rd *nft.Rule) string {
	var sb strings.Builder

	// Position + Comment side by side
	posView := r.tabs[0].fields[0].View()
	comView := r.tabs[0].fields[1].View()
	posWidth := 24
	comWidth := r.width - posWidth - 6
	if comWidth < 20 {
		comWidth = 20
	}
	sb.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(posWidth).Render(posView),
		lipgloss.NewStyle().Width(comWidth).Render(comView),
	))
	sb.WriteString("\n")

	// Actions (read-only)
	if len(rd.Actions) > 0 {
		sb.WriteString("\n")
		sb.WriteString(grayBoldStyle.Render("Műveletek:"))
		sb.WriteString("\n")
		for _, action := range rd.Actions {
			switch action.Type {
			case nft.ActionTypeVerdict:
				if action.Verdict != nil {
					sb.WriteString(fmt.Sprintf("  verdict: %s\n", action.Verdict.Kind))
				}
			case nft.ActionTypeCounter:
				if action.Counter != nil && action.Counter.Name != "" {
					sb.WriteString(fmt.Sprintf("  counter: %s\n", action.Counter.Name))
				} else {
					sb.WriteString("  counter\n")
				}
			case nft.ActionTypeNAT:
				if action.NAT != nil {
					sb.WriteString(fmt.Sprintf("  nat: %+v\n", action.NAT))
				}
			case nft.ActionTypeLog:
				if action.Log != nil {
					sb.WriteString(fmt.Sprintf("  log: %+v\n", action.Log))
				}
			case nft.ActionTypeQueue:
				if action.Queue != nil {
					sb.WriteString(fmt.Sprintf("  queue: %+v\n", action.Queue))
				}
			case nft.ActionTypeReject:
				if action.Reject != nil {
					sb.WriteString(fmt.Sprintf("  reject: %+v\n", action.Reject))
				}
			case nft.ActionTypeSet:
				if action.Set != nil {
					sb.WriteString(fmt.Sprintf("  set: %+v\n", action.Set))
				}
			case nft.ActionTypeRedirect:
				if action.Redirect != nil {
					sb.WriteString(fmt.Sprintf("  redirect: %+v\n", action.Redirect))
				}
			case nft.ActionTypeMasq:
				if action.Masq != nil {
					sb.WriteString(fmt.Sprintf("  masquerade: %+v\n", action.Masq))
				}
			case nft.ActionTypeCustom:
				if action.Custom != nil {
					sb.WriteString(fmt.Sprintf("  custom: %+v\n", action.Custom))
				}
			}
		}
	}

	// Counter stats
	if rd.Counter != nil {
		sb.WriteString("\n")
		sb.WriteString(grayBoldStyle.Render("Számláló: "))
		sb.WriteString(fmt.Sprintf("%d packets, %d bytes\n", rd.Counter.Packets, rd.Counter.Bytes))
	}

	return sb.String()
}

// renderCTTab renders the CT (Connection Tracking) tab content.
func (r ruleEdit) renderCTTab() string {
	// tabs[1].fields indices:
	// 0=L3Proto, 1=Protocol, 2=State, 3=Direction,
	// 4=Status, 5=Mark, 6=Expiration, 7=Helper, 8=Bytes, 9=Pkts
	f := r.tabs[1].fields
	var sb strings.Builder

	// Row 1: L3Proto | Protocol
	sb.WriteString(r.row2(f[0].View(), f[1].View()))
	sb.WriteString("\n")

	// Row 2: State (full width — multiselect with many options)
	sb.WriteString(f[2].View())

	// Row 3: Direction | Status
	sb.WriteString(r.row2(f[3].View(), f[4].View()))
	sb.WriteString("\n")

	// Row 4: Mark | Expiration | Helper
	sb.WriteString(r.row3(f[5].View(), f[6].View(), f[7].View()))
	sb.WriteString("\n")

	// Row 5: Bytes | Pkts
	sb.WriteString(r.row2(f[8].View(), f[9].View()))
	sb.WriteString("\n")

	return sb.String()
}

// renderNetworkTab renders the Hálózat (Network) tab content.
func (r ruleEdit) renderNetworkTab(rd *nft.Rule) string {
	// tabs[2].fields: 0=IPSaddr, 1=IPDaddr
	f := r.tabs[2].fields
	var sb strings.Builder

	sb.WriteString(f[0].View())
	sb.WriteString(f[1].View())

	// Read-only conditions (meta, set lookup, custom)
	hasMisc := false
	for _, condition := range rd.Conditions {
		if condition.Meta != nil && condition.Meta.Key != "" {
			if !hasMisc {
				sb.WriteString("\n")
				sb.WriteString(grayBoldStyle.Render("Egyéb feltételek:"))
				sb.WriteString("\n")
				hasMisc = true
			}
			op := string(condition.Operation)
			if op == "==" {
				op = ""
			} else {
				op += " "
			}
			sb.WriteString(fmt.Sprintf("  meta %s %s%v\n",
				condition.Meta.Key, op, condition.Meta.Value))
		}
		if condition.SetLookup != nil {
			if !hasMisc {
				sb.WriteString("\n")
				sb.WriteString(grayBoldStyle.Render("Egyéb feltételek:"))
				sb.WriteString("\n")
				hasMisc = true
			}
			sb.WriteString(fmt.Sprintf("  set lookup: %+v\n", condition.SetLookup))
		}
		if condition.Custom != nil {
			if !hasMisc {
				sb.WriteString("\n")
				sb.WriteString(grayBoldStyle.Render("Egyéb feltételek:"))
				sb.WriteString("\n")
				hasMisc = true
			}
			sb.WriteString(fmt.Sprintf("  custom: %+v\n", condition.Custom))
		}
	}

	return sb.String()
}

// renderLimitTab renders the Limit tab content.
func (r ruleEdit) renderLimitTab() string {
	// tabs[3].fields: 0=Over, 1=Rate, 2=Unit, 3=Burst, 4=Type
	f := r.tabs[3].fields
	var sb strings.Builder

	// Row 1: Over | Rate | Unit
	sb.WriteString(r.row3(f[0].View(), f[1].View(), f[2].View()))
	sb.WriteString("\n")

	// Row 2: Burst | Type
	sb.WriteString(r.row2(f[3].View(), f[4].View()))
	sb.WriteString("\n")

	return sb.String()
}

// View renders the rule editor view.
func (r ruleEdit) View() string {
	header := blueBoldStyle.Render("nftui nftables manager")

	divider := grayStyle.
		Width(r.width).
		Render(strings.Repeat("─", r.width))

	ruleDefinition, _ := nft.NftablesToRuleDefinition(r.rule)

	var content strings.Builder
	content.WriteString(blueStyle.Render("| Szabály szerkesztése |"))
	content.WriteString("\n\n")

	// Tab bar
	content.WriteString(r.renderTabBar())
	content.WriteString("\n")
	tabBarDivider := r.width - 4
	if tabBarDivider < 1 {
		tabBarDivider = 1
	}
	content.WriteString(grayStyle.Render(strings.Repeat("─", tabBarDivider)))
	content.WriteString("\n")

	// Active tab content
	switch r.activeTab {
	case 0:
		content.WriteString(r.renderGeneralTab(ruleDefinition))
	case 1:
		content.WriteString(r.renderCTTab())
	case 2:
		content.WriteString(r.renderNetworkTab(ruleDefinition))
	case 3:
		content.WriteString(r.renderLimitTab())
	}

	contentBox := normalGrayBorder.
		Width(r.width-2).
		Height(r.height-8).
		Padding(0, 1).
		Render(content.String())

	footer := r.help.View(r.keys)

	fullView := lipgloss.JoinVertical(lipgloss.Left,
		header,
		divider,
		contentBox,
		footer,
	)

	return defaultStyle.Render(fullView)
}
