package ui

import (
	"fmt"
	"strings"

	"nftui/nft"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
)

// ruleEditKeyMap defines key bindings for navigation and actions within the rule editing interface.
type ruleEditKeyMap struct {
	PrevTab   key.Binding
	NextTab   key.Binding
	NextField key.Binding
	PrevField key.Binding
	Back      key.Binding
	Save      key.Binding
	Quit      key.Binding
}

// ShortHelp returns a slice of key bindings for primary actions.
func (k ruleEditKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.PrevTab, k.NextTab, k.NextField, k.PrevField, k.Save, k.Back, k.Quit}
}

// FullHelp returns a matrix of key bindings for detailed interface navigation.
func (k ruleEditKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.PrevTab, k.NextTab, k.NextField, k.PrevField},
		{k.Save, k.Back, k.Quit},
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
	errStr       string // last save/validation error, cleared on the next Save attempt
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
			key.WithHelp("f5", "prev tab"),
		),
		NextTab: key.NewBinding(
			key.WithKeys("f6"),
			key.WithHelp("f6", "next tab"),
		),
		NextField: key.NewBinding(
			key.WithKeys("tab"),
			key.WithHelp("tab", "next field"),
		),
		PrevField: key.NewBinding(
			key.WithKeys("shift+tab"),
			key.WithHelp("shift+tab", "prev field"),
		),
		Back: key.NewBinding(
			key.WithKeys("esc", "f3"),
			key.WithHelp("esc/f3", "back"),
		),
		Save: key.NewBinding(
			key.WithKeys("f2"),
			key.WithHelp("f2", "save"),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "quit"),
		),
	}

	rd, _ := nft.NftablesToRuleDefinition(rule)

	tabs := []editTab{
		{
			name: "General",
			fields: []FieldEditor{
				NewPositionField(rd),
				NewCommentField(rd),
				NewVerdictField(rd),
				NewRejectField(rd, rule.Table.Family),
				NewLogField(rd),
				NewCounterField(rd),
			},
		},
		{
			name: "CT",
			fields: []FieldEditor{
				NewCtL3ProtoField(rd),    // slots 0,1
				NewCtProtocolField(rd),   // slots 2,3
				NewCtProtoSrcField(rd),   // slots 4,5,6
				NewCtProtoDstField(rd),   // slots 7,8,9
				NewCtStateField(rd),      // slot 10
				NewCtDirectionField(rd),  // slot 11
				NewCtStatusField(rd),     // slot 12
				NewCtLabelsField(rd),     // slot 13
				NewCtEventmaskField(rd),  // slot 14
				NewCtMarkField(rd),       // slots 15,16
				NewCtSecMarkField(rd),    // slots 17,18
				NewCtExpirationField(rd), // slot 19
				NewCtHelperField(rd),     // slot 20
				NewCtZoneField(rd),       // slots 21,22
				NewCtBytesField(rd),      // slots 23,24,25
				NewCtPktsField(rd),       // slots 26,27,28
				NewCtAvgpktField(rd),     // slots 29,30,31
				NewCtCountField(rd),      // slots 32,33
			},
		},
		{
			name: "Network",
			fields: []FieldEditor{
				NewIPSaddrField(rd),     // slots 0,1
				NewIPDaddrField(rd),     // slots 2,3
				NewMetaIifnameField(rd), // slots 4,5
				NewMetaOifnameField(rd), // slots 6,7
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
		help:         newHelpModel(),
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
			r.errStr = ""
			// Pre-save validation — abort with a clear error before any field mutates the rule.
			for _, tab := range r.tabs {
				for _, f := range tab.fields {
					if v, ok := f.(interface{ ValidateForSave() error }); ok {
						if err := v.ValidateForSave(); err != nil {
							r.errStr = err.Error()
							return r, nil
						}
					}
				}
			}
			for _, tab := range r.tabs {
				for _, f := range tab.fields {
					f.Save(r.rule)
				}
			}
			saveCmd := func() tea.Msg {
				if err := nft.ApplyRuleChange(r.rule); err != nil {
					return errMsg(fmt.Errorf("save error: %w", err))
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

// renderGeneralTab renders the General tab content.
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

	// Verdict editor (full width — switches kind and optional target chain).
	sb.WriteString(r.tabs[0].fields[2].View())
	sb.WriteString("\n")

	// Reject editor (full width — switches type and optional ICMP code).
	sb.WriteString(r.tabs[0].fields[3].View())
	sb.WriteString("\n")

	// Log editor (full width — prefix, level, NFLOG group/snaplen/queue-threshold).
	sb.WriteString(r.tabs[0].fields[4].View())
	sb.WriteString("\n")

	// Counter editor (full width — Packets + Bytes; typical use is reset to 0).
	sb.WriteString(r.tabs[0].fields[5].View())
	sb.WriteString("\n")

	// Remaining actions (read-only — verdict, reject, log and counter are handled by the editors above).
	hasRemaining := false
	for _, action := range rd.Actions {
		switch action.Type {
		case nft.ActionTypeVerdict, nft.ActionTypeReject, nft.ActionTypeLog, nft.ActionTypeCounter:
			continue
		}
		hasRemaining = true
		break
	}
	if hasRemaining {
		sb.WriteString(grayBoldStyle.Render("Actions:"))
		sb.WriteString("\n")
		for _, action := range rd.Actions {
			switch action.Type {
			case nft.ActionTypeVerdict, nft.ActionTypeReject, nft.ActionTypeLog, nft.ActionTypeCounter:
				// editable — rendered above
			case nft.ActionTypeNAT:
				if action.NAT != nil {
					sb.WriteString(fmt.Sprintf("  nat: %+v\n", action.NAT))
				}
			case nft.ActionTypeQueue:
				if action.Queue != nil {
					sb.WriteString(fmt.Sprintf("  queue: %+v\n", action.Queue))
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

	return sb.String()
}

// renderCTTab renders the CT (Connection Tracking) tab content.
func (r ruleEdit) renderCTTab() string {
	// tabs[1].fields indices (by array position, not slot number):
	// 0=L3Proto, 1=Protocol, 2=ProtoSrc, 3=ProtoDst,
	// 4=State, 5=Direction, 6=Status, 7=Labels, 8=Eventmask,
	// 9=Mark, 10=Secmark, 11=Expiration, 12=Helper,
	// 13=Zone, 14=Bytes, 15=Pkts, 16=Avgpkt, 17=Count
	f := r.tabs[1].fields
	var sb strings.Builder

	// Row 1: L3Proto | Protocol
	sb.WriteString(r.row2(f[0].View(), f[1].View()))
	sb.WriteString("\n")

	// Row 2: proto-src | proto-dst
	sb.WriteString(r.row2(f[2].View(), f[3].View()))
	sb.WriteString("\n")

	// Row 3: State (full width — multiselect with many options)
	sb.WriteString(f[4].View())

	// Row 4: Direction | Status
	sb.WriteString(r.row2(f[5].View(), f[6].View()))
	sb.WriteString("\n")

	// Row 4b: Labels (full width — comma-separated bit indices)
	sb.WriteString(f[7].View())

	// Row 4c: Eventmask (full width — multiselect of 12 IPCT_* bits)
	sb.WriteString(f[8].View())

	// Row 5: Mark | Secmark | Expiration
	sb.WriteString(r.row3(f[9].View(), f[10].View(), f[11].View()))
	sb.WriteString("\n")

	// Row 6: Helper | Zone
	sb.WriteString(r.row2(f[12].View(), f[13].View()))
	sb.WriteString("\n")

	// Row 7: Bytes | Pkts | Avgpkt
	sb.WriteString(r.row3(f[14].View(), f[15].View(), f[16].View()))
	sb.WriteString("\n")

	// Row 8: Count (over + value)
	sb.WriteString(r.row2(f[17].View(), ""))
	sb.WriteString("\n")

	return sb.String()
}

// renderNetworkTab renders the Network tab content.
func (r ruleEdit) renderNetworkTab(rd *nft.Rule) string {
	// tabs[2].fields: 0=IPSaddr, 1=IPDaddr, 2=MetaIifname, 3=MetaOifname
	f := r.tabs[2].fields
	var sb strings.Builder

	sb.WriteString(f[0].View())
	sb.WriteString(f[1].View())
	sb.WriteString(f[2].View())
	sb.WriteString(f[3].View())

	// Read-only conditions (meta — excluding the ones we render above —
	// plus set lookup and custom).
	hasMisc := false
	for _, condition := range rd.Conditions {
		if condition.Meta != nil && condition.Meta.Key != "" {
			// Skip the meta keys we already render with dedicated editors.
			if condition.Meta.Key == nft.MetaKeyIIfName ||
				condition.Meta.Key == nft.MetaKeyOIfName {
				continue
			}
			if !hasMisc {
				sb.WriteString("\n")
				sb.WriteString(grayBoldStyle.Render("Other conditions:"))
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
				sb.WriteString(grayBoldStyle.Render("Other conditions:"))
				sb.WriteString("\n")
				hasMisc = true
			}
			sb.WriteString(fmt.Sprintf("  set lookup: %+v\n", condition.SetLookup))
		}
		if condition.Custom != nil {
			if !hasMisc {
				sb.WriteString("\n")
				sb.WriteString(grayBoldStyle.Render("Other conditions:"))
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
	content.WriteString(blueStyle.Render("| Edit rule |"))
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
	if r.errStr != "" {
		footer = redBoldStyle.Render("⚠ "+r.errStr) + "\n" + footer
	}

	fullView := lipgloss.JoinVertical(lipgloss.Left,
		header,
		divider,
		contentBox,
		footer,
	)

	return defaultStyle.Render(fullView)
}
