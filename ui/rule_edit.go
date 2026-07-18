package ui

import (
	"fmt"
	"strings"

	"nftui/nft"
	"nftui/nft/nftserializer"

	"nftui/i18n"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
)

// formatSaveError pairs the kernel's rejection reason with the nft CLI form
// of the rule we tried to push, so the editor's error line shows both *which*
// rule failed and *why*. The underlying error is wrapped (%w) so errors.Is
// still works downstream.
func formatSaveError(err error, rule *nftables.Rule) error {
	return fmt.Errorf("save failed: %w\nrule: %s", err, nftserializer.SerializeRule(rule))
}

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

	// readOnly mirrors Options.ReadOnly. F2 (Save) is disabled in the
	// keymap when set — the editor still opens (read for inspection) but
	// cannot push to the kernel.
	readOnly bool
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

// focusSentinel is a zero-width space prepended to the focused field's rendered
// output by fview. View finds the line carrying it to scroll the focused field
// into view; it is invisible (width 0) and stripped before display.
const focusSentinel = "​"

// fview renders field [tabIdx][fieldIdx], marking it with focusSentinel when it
// is the currently focused field, so View can locate it and scroll it into view.
func (r ruleEdit) fview(tabIdx, fieldIdx int) string {
	v := r.tabs[tabIdx].fields[fieldIdx].View()
	if tabIdx != r.activeTab {
		return v
	}
	focused, _ := r.fieldAtTabSlot(r.activeTab, r.tabFocusSlot[r.activeTab])
	if focused != nil && focused == r.tabs[tabIdx].fields[fieldIdx] {
		return focusSentinel + v
	}
	return v
}

// newRuleEdit initializes and returns a ruleEdit structure for editing nftables rules.
func newRuleEdit(rule *nftables.Rule, readOnly bool) ruleEdit {
	km := ruleEditKeyMap{
		PrevTab: key.NewBinding(
			key.WithKeys("f5"),
			key.WithHelp("f5", i18n.T("key.prev_tab")),
		),
		NextTab: key.NewBinding(
			key.WithKeys("f6"),
			key.WithHelp("f6", i18n.T("key.next_tab")),
		),
		NextField: key.NewBinding(
			key.WithKeys("tab"),
			key.WithHelp("tab", i18n.T("key.next_field")),
		),
		PrevField: key.NewBinding(
			key.WithKeys("shift+tab"),
			key.WithHelp("shift+tab", i18n.T("key.prev_field")),
		),
		Back: key.NewBinding(
			key.WithKeys("esc", "f3"),
			key.WithHelp("esc/f3", i18n.T("key.back")),
		),
		Save: key.NewBinding(
			key.WithKeys("f2"),
			key.WithHelp("f2", i18n.T("key.save")),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", i18n.T("key.quit")),
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
				NewMasqueradeField(rd),
				NewSnatField(rd, rule.Table.Family),
				NewDnatField(rd, rule.Table.Family),
				NewQueueField(rd),
				NewQuotaField(rd),
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
				NewMetaIifField(rd),     // slots 8,9
				NewMetaOifField(rd),     // slots 10,11
				NewEtherSaddrField(rd),  // slots 12,13
				NewEtherDaddrField(rd),  // slots 14,15
				NewEtherTypeField(rd),   // slots 16,17
				NewVlanIdField(rd),      // slot 18
				NewVlanCfiField(rd),     // slot 19
				NewVlanPcpField(rd),     // slot 20
				// ARP — needs `ether type 0x0806` prefix (auto-injected by Save)
				NewArpHtypeField(rd),     // slot 21
				NewArpPtypeField(rd),     // slot 22
				NewArpHlenField(rd),      // slot 23
				NewArpPlenField(rd),      // slot 24
				NewArpOperationField(rd), // slots 25,26
			},
		},
		{
			name: "IP",
			fields: []FieldEditor{
				// IPv4 header fields
				NewIPProtocolField(rd),  // 0
				NewIPTtlField(rd),       // 1
				NewIPLengthField(rd),    // 2
				NewIPDscpField(rd),      // 3
				NewIPVersionField(rd),   // 4
				NewIPHdrlengthField(rd), // 5
				NewIPIdField(rd),        // 6
				NewIPFragOffField(rd),   // 7
				NewIPChecksumField(rd),  // 8
				// IPv6 header fields
				NewIP6SaddrField(rd),     // 9
				NewIP6DaddrField(rd),     // 10
				NewIP6LengthField(rd),    // 11
				NewIP6NexthdrField(rd),   // 12
				NewIP6HoplimitField(rd),  // 13
				NewIP6VersionField(rd),   // 14
				NewIP6DscpField(rd),      // 15
				NewIP6FlowlabelField(rd), // 16
				// IPv6 extension headers — 18 fields across 5 protocols
				NewFragNexthdrField(rd),       // 17
				NewFragReservedField(rd),      // 18
				NewFragFragOffField(rd),       // 19
				NewFragMoreFragmentsField(rd), // 20
				NewFragIdField(rd),            // 21
				NewHbhNexthdrField(rd),        // 22
				NewHbhHdrlengthField(rd),      // 23
				NewDstNexthdrField(rd),        // 24
				NewDstHdrlengthField(rd),      // 25
				NewMhNexthdrField(rd),         // 26
				NewMhHdrlengthField(rd),       // 27
				NewMhTypeField(rd),            // 28
				NewMhReservedField(rd),        // 29
				NewMhChecksumField(rd),        // 30
				NewRtNexthdrField(rd),         // 31
				NewRtHdrlengthField(rd),       // 32
				NewRtTypeField(rd),            // 33
				NewRtSegLeftField(rd),         // 34
			},
		},
		{
			name: "Transport",
			fields: []FieldEditor{
				// TCP / UDP / UDPLITE share sport+dport on the wire — TCP
				// labels are used as the canonical name. The user's
				// `meta l4proto` match tells which transport this rule sits in.
				NewTcpSportField(rd),    // 0
				NewTcpDportField(rd),    // 1
				NewTcpFlagsField(rd),    // 2
				NewTcpSequenceField(rd), // 3
				NewTcpAckseqField(rd),   // 4
				NewTcpWindowField(rd),   // 5
				NewTcpChecksumField(rd), // 6
				NewTcpUrgptrField(rd),   // 7
				NewTcpDoffField(rd),     // 8
				NewUdpLengthField(rd),   // 9
				NewUdpChecksumField(rd), // 10
				// ICMP fields — these inject the `meta l4proto icmp`
				// prefix automatically on Save.
				NewIcmpTypeField(rd),     // 11
				NewIcmpCodeField(rd),     // 12
				NewIcmpChecksumField(rd), // 13
				NewIcmpIdField(rd),       // 14
				NewIcmpSequenceField(rd), // 15
				NewIcmpMtuField(rd),      // 16
				NewIcmpGatewayField(rd),  // 17
				// ICMPv6
				NewIcmpv6TypeField(rd),     // 18
				NewIcmpv6CodeField(rd),     // 19
				NewIcmpv6ChecksumField(rd), // 20
				NewIcmpv6IdField(rd),       // 21
				NewIcmpv6SequenceField(rd), // 22
				NewIcmpv6MtuField(rd),      // 23
				NewIcmpv6MaxDelayField(rd), // 24
				// SCTP
				NewSctpSportField(rd),    // 25
				NewSctpDportField(rd),    // 26
				NewSctpVtagField(rd),     // 27
				NewSctpChecksumField(rd), // 28
				NewSctpChunkField(rd),    // 29 — chunk-type + sub-field + value (3 slots)
				// DCCP
				NewDccpSportField(rd), // 30
				NewDccpDportField(rd), // 31
				NewDccpTypeField(rd),  // 32
				// AH
				NewAhHdrlengthField(rd), // 32
				NewAhReservedField(rd),  // 33
				NewAhSpiField(rd),       // 34
				NewAhSequenceField(rd),  // 35
				// ESP
				NewEspSpiField(rd),      // 36
				NewEspSequenceField(rd), // 37
				// COMP
				NewCompNexthdrField(rd), // 38
				NewCompFlagsField(rd),   // 39
				NewCompCpiField(rd),     // 40
			},
		},
		{
			name: "Meta",
			fields: []FieldEditor{
				NewMetaIiftypeField(rd),   // 0: slots 0,1
				NewMetaOiftypeField(rd),   // 1: slots 2,3
				NewMetaNfprotoField(rd),   // 2: slots 4,5
				NewMetaL4protoField(rd),   // 3: slots 6,7
				NewMetaProtocolField(rd),  // 4: slots 8,9
				NewMetaLengthField(rd),    // 5: slots 10,11
				NewMetaMarkField(rd),      // 6: slots 12,13
				NewMetaPriorityField(rd),  // 7: slots 14,15
				NewMetaRtclassidField(rd), // 8: slots 16,17
				NewMetaSkuidField(rd),     // 9: slots 18,19
				NewMetaSkgidField(rd),     // 10: slots 20,21
				NewMetaCgroupField(rd),    // 11: slots 22,23
				NewMetaCpuField(rd),       // 12: slots 24,25
				NewMetaIifgroupField(rd),  // 13: slots 26,27
				NewMetaOifgroupField(rd),  // 14: slots 28,29
				NewMetaPkttypeField(rd),   // 15: slots 30,31
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

	if readOnly {
		// Disable F2 save. Tab nav, focus, and read-only field viewing
		// stay on so the editor remains useful for inspection.
		km.Save.SetEnabled(false)
	}

	return ruleEdit{
		rule:         rule,
		tabs:         tabs,
		activeTab:    0,
		tabFocusSlot: make([]int, len(tabs)),
		keys:         km,
		help:         newHelpModel(),
		readOnly:     readOnly,
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
					return errMsg(formatSaveError(err, r.rule))
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

// editTabLabel resolves an editor tab's localized display label. Tab names are
// stored as their English canonical (used for indexing/debugging); the visible
// label is translated at render time — CT/IP/Meta are kept as nft abbreviations.
func editTabLabel(name string) string {
	switch name {
	case "General":
		return i18n.T("rule.tab.general")
	case "CT":
		return i18n.T("rule.tab.ct")
	case "Network":
		return i18n.T("rule.tab.network")
	case "IP":
		return i18n.T("rule.tab.ip")
	case "Transport":
		return i18n.T("rule.tab.transport")
	case "Meta":
		return i18n.T("rule.tab.meta")
	case "Limit":
		return i18n.T("rule.tab.limit")
	}
	return name
}

// renderTabBar renders the horizontal tab strip.
func (r ruleEdit) renderTabBar() string {
	var parts []string
	for i, tab := range r.tabs {
		label := "  " + editTabLabel(tab.name) + "  "
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
	posView := r.fview(0, 0)
	comView := r.fview(0, 1)
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
	sb.WriteString(r.fview(0, 2))
	sb.WriteString("\n")

	// Reject editor (full width — switches type and optional ICMP code).
	sb.WriteString(r.fview(0, 3))
	sb.WriteString("\n")

	// Log editor (full width — prefix, level, NFLOG group/snaplen/queue-threshold).
	sb.WriteString(r.fview(0, 4))
	sb.WriteString("\n")

	// Counter editor (full width — Packets + Bytes; typical use is reset to 0).
	sb.WriteString(r.fview(0, 5))
	sb.WriteString("\n")

	// Masquerade editor (full width — enable + flags).
	sb.WriteString(r.fview(0, 6))
	sb.WriteString("\n")

	// SNAT editor (full width — enable + addr + port + flags).
	sb.WriteString(r.fview(0, 7))
	sb.WriteString("\n")

	// DNAT editor (full width — enable + addr + port + flags).
	sb.WriteString(r.fview(0, 8))
	sb.WriteString("\n")

	// Queue editor (full width — enable + num + range + flags).
	sb.WriteString(r.fview(0, 9))
	sb.WriteString("\n")

	// Quota editor (full width — enable + amount + unit + over).
	sb.WriteString(r.fview(0, 10))
	sb.WriteString("\n")

	// Remaining actions (read-only — verdict, reject, log, counter, masquerade, snat, dnat, queue, quota are handled by the editors above).
	hasRemaining := false
	for _, action := range rd.Actions {
		switch action.Type {
		case nft.ActionTypeVerdict, nft.ActionTypeReject, nft.ActionTypeLog,
			nft.ActionTypeCounter, nft.ActionTypeMasq, nft.ActionTypeQueue,
			nft.ActionTypeQuota, nft.ActionTypeObjref:
			continue
		case nft.ActionTypeNAT:
			if action.NAT != nil &&
				(action.NAT.Type == nft.NATTypeSNAT || action.NAT.Type == nft.NATTypeDNAT) {
				continue
			}
		}
		hasRemaining = true
		break
	}
	if hasRemaining {
		sb.WriteString(grayBoldStyle.Render(i18n.T("rule.general.actions")))
		sb.WriteString("\n")
		for _, action := range rd.Actions {
			switch action.Type {
			case nft.ActionTypeVerdict, nft.ActionTypeReject, nft.ActionTypeLog,
				nft.ActionTypeCounter, nft.ActionTypeMasq:
				// editable — rendered above
			case nft.ActionTypeNAT:
				if action.NAT != nil &&
					(action.NAT.Type == nft.NATTypeSNAT || action.NAT.Type == nft.NATTypeDNAT) {
					// editable — rendered above
				} else if action.NAT != nil {
					sb.WriteString("  " + formatNAT(action.NAT) + "\n")
				}
			case nft.ActionTypeQueue, nft.ActionTypeQuota:
				// editable — rendered above
			case nft.ActionTypeObjref:
				if action.Objref != nil {
					sb.WriteString("  " + formatObjref(action.Objref) + "\n")
				}
			case nft.ActionTypeSet:
				if action.Set != nil {
					sb.WriteString("  " + formatSetAction(action.Set) + "\n")
				}
			case nft.ActionTypeRedirect:
				if action.Redirect != nil {
					sb.WriteString(fmt.Sprintf("  redirect: %+v\n", action.Redirect))
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
	var sb strings.Builder

	// Row 1: L3Proto | Protocol
	sb.WriteString(r.row2(r.fview(1, 0), r.fview(1, 1)))
	sb.WriteString("\n")

	// Row 2: proto-src | proto-dst
	sb.WriteString(r.row2(r.fview(1, 2), r.fview(1, 3)))
	sb.WriteString("\n")

	// Row 3: State (full width — multiselect with many options)
	sb.WriteString(r.fview(1, 4))

	// Row 4: Direction | Status
	sb.WriteString(r.row2(r.fview(1, 5), r.fview(1, 6)))
	sb.WriteString("\n")

	// Row 4b: Labels (full width — comma-separated bit indices)
	sb.WriteString(r.fview(1, 7))

	// Row 4c: Eventmask (full width — multiselect of 12 IPCT_* bits)
	sb.WriteString(r.fview(1, 8))

	// Row 5: Mark | Secmark | Expiration
	sb.WriteString(r.row3(r.fview(1, 9), r.fview(1, 10), r.fview(1, 11)))
	sb.WriteString("\n")

	// Row 6: Helper | Zone
	sb.WriteString(r.row2(r.fview(1, 12), r.fview(1, 13)))
	sb.WriteString("\n")

	// Row 7: Bytes | Pkts | Avgpkt
	sb.WriteString(r.row3(r.fview(1, 14), r.fview(1, 15), r.fview(1, 16)))
	sb.WriteString("\n")

	// Row 8: Count (over + value)
	sb.WriteString(r.row2(r.fview(1, 17), ""))
	sb.WriteString("\n")

	return sb.String()
}

// renderNetworkTab renders the Network tab content.
func (r ruleEdit) renderNetworkTab(rd *nft.Rule) string {
	// tabs[2].fields: 0=IPSaddr, 1=IPDaddr, 2=MetaIifname, 3=MetaOifname,
	//                 4=MetaIif, 5=MetaOif, 6=EtherSaddr, 7=EtherDaddr,
	//                 8=EtherType, 9=VlanId, 10=VlanCfi, 11=VlanPcp
	var sb strings.Builder

	sb.WriteString(r.fview(2, 0))
	sb.WriteString(r.fview(2, 1))
	sb.WriteString(r.fview(2, 2))
	sb.WriteString(r.fview(2, 3))
	sb.WriteString(r.fview(2, 4))
	sb.WriteString(r.fview(2, 5))
	sb.WriteString(r.fview(2, 6))
	sb.WriteString(r.fview(2, 7))
	sb.WriteString(r.fview(2, 8))
	sb.WriteString(grayBoldStyle.Render("VLAN tag"))
	sb.WriteString("\n")
	sb.WriteString(r.row3(r.fview(2, 9), r.fview(2, 10), r.fview(2, 11)))
	sb.WriteString("\n")

	sb.WriteString(grayBoldStyle.Render("ARP"))
	sb.WriteString("\n")
	sb.WriteString(r.row2(r.fview(2, 12), r.fview(2, 13)))
	sb.WriteString("\n")
	sb.WriteString(r.row2(r.fview(2, 14), r.fview(2, 15)))
	sb.WriteString("\n")
	sb.WriteString(r.fview(2, 16))

	// Read-only conditions (meta — excluding the ones we render above —
	// plus set lookup and custom).
	hasMisc := false
	for _, condition := range rd.Conditions {
		if condition.Meta != nil && condition.Meta.Key != "" {
			// Skip the meta keys we already render with dedicated editors
			// — either on this tab (iif/oif/iifname/oifname) or on the Meta
			// tab (the other 16 keys).
			if isMetaKeyHandledByEditor(condition.Meta.Key) {
				continue
			}
			if !hasMisc {
				sb.WriteString("\n")
				sb.WriteString(grayBoldStyle.Render(i18n.T("rule.edit.other_conditions")))
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
				sb.WriteString(grayBoldStyle.Render(i18n.T("rule.edit.other_conditions")))
				sb.WriteString("\n")
				hasMisc = true
			}
			sb.WriteString("  " + formatSetLookup(condition) + "\n")
		}
		if condition.Custom != nil {
			if !hasMisc {
				sb.WriteString("\n")
				sb.WriteString(grayBoldStyle.Render(i18n.T("rule.edit.other_conditions")))
				sb.WriteString("\n")
				hasMisc = true
			}
			sb.WriteString(fmt.Sprintf("  custom: %+v\n", condition.Custom))
		}
	}

	return sb.String()
}

// renderIPTab renders the IP (IPv4 + IPv6 header) tab content.
func (r ruleEdit) renderIPTab() string {
	// tabs[3].fields:
	//   IPv4: 0=Protocol, 1=Ttl, 2=Length, 3=Dscp, 4=Version, 5=Hdrlength,
	//         6=Id, 7=FragOff, 8=Checksum
	//   IPv6: 9=Saddr, 10=Daddr, 11=Length, 12=Nexthdr, 13=Hoplimit,
	//         14=Version, 15=Dscp, 16=Flowlabel
	var sb strings.Builder

	sb.WriteString(grayBoldStyle.Render(i18n.T("rule.edit.ipv4_header")))
	sb.WriteString("\n")
	sb.WriteString(r.row3(r.fview(3, 0), r.fview(3, 1), r.fview(3, 2)))
	sb.WriteString("\n")
	sb.WriteString(r.row3(r.fview(3, 3), r.fview(3, 4), r.fview(3, 5)))
	sb.WriteString("\n")
	sb.WriteString(r.row3(r.fview(3, 6), r.fview(3, 7), r.fview(3, 8)))
	sb.WriteString("\n")

	sb.WriteString(grayBoldStyle.Render(i18n.T("rule.edit.ipv6_header")))
	sb.WriteString("\n")
	sb.WriteString(r.fview(3, 9))
	sb.WriteString(r.fview(3, 10))
	sb.WriteString(r.row3(r.fview(3, 11), r.fview(3, 12), r.fview(3, 13)))
	sb.WriteString("\n")
	sb.WriteString(r.row3(r.fview(3, 14), r.fview(3, 15), r.fview(3, 16)))
	sb.WriteString("\n")

	sb.WriteString(grayBoldStyle.Render("IPv6 ext: Frag"))
	sb.WriteString("\n")
	sb.WriteString(r.row3(r.fview(3, 17), r.fview(3, 18), r.fview(3, 19)))
	sb.WriteString("\n")
	sb.WriteString(r.row2(r.fview(3, 20), r.fview(3, 21)))
	sb.WriteString("\n")

	sb.WriteString(grayBoldStyle.Render("IPv6 ext: HBH / Dst"))
	sb.WriteString("\n")
	sb.WriteString(r.row2(r.fview(3, 22), r.fview(3, 23)))
	sb.WriteString("\n")
	sb.WriteString(r.row2(r.fview(3, 24), r.fview(3, 25)))
	sb.WriteString("\n")

	sb.WriteString(grayBoldStyle.Render("IPv6 ext: MH"))
	sb.WriteString("\n")
	sb.WriteString(r.row3(r.fview(3, 26), r.fview(3, 27), r.fview(3, 28)))
	sb.WriteString("\n")
	sb.WriteString(r.row2(r.fview(3, 29), r.fview(3, 30)))
	sb.WriteString("\n")

	sb.WriteString(grayBoldStyle.Render("IPv6 ext: Rt"))
	sb.WriteString("\n")
	sb.WriteString(r.row2(r.fview(3, 31), r.fview(3, 32)))
	sb.WriteString("\n")
	sb.WriteString(r.row2(r.fview(3, 33), r.fview(3, 34)))
	sb.WriteString("\n")

	return sb.String()
}

// renderTransportTab renders the Transport (TCP/UDP/UDPLITE/ICMP header) tab.
func (r ruleEdit) renderTransportTab() string {
	// tabs[4].fields:
	//   0=TcpSport, 1=TcpDport, 2=TcpFlags, 3=TcpSequence, 4=TcpAckseq,
	//   5=TcpWindow, 6=TcpChecksum, 7=TcpUrgptr, 8=TcpDoff,
	//   9=UdpLength, 10=UdpChecksum,
	//   11=IcmpType, 12=IcmpCode, 13=IcmpChecksum, 14=IcmpId,
	//   15=IcmpSequence, 16=IcmpMtu, 17=IcmpGateway
	var sb strings.Builder

	sb.WriteString(grayBoldStyle.Render("TCP"))
	sb.WriteString("\n")
	sb.WriteString(r.row2(r.fview(4, 0), r.fview(4, 1)))
	sb.WriteString("\n")
	sb.WriteString(r.fview(4, 2))
	sb.WriteString(r.row2(r.fview(4, 3), r.fview(4, 4)))
	sb.WriteString("\n")
	sb.WriteString(r.row3(r.fview(4, 5), r.fview(4, 6), r.fview(4, 7)))
	sb.WriteString("\n")
	sb.WriteString(r.row2(r.fview(4, 8), ""))
	sb.WriteString("\n")

	sb.WriteString(grayBoldStyle.Render("UDP / UDPLITE"))
	sb.WriteString("\n")
	sb.WriteString(r.row2(r.fview(4, 9), r.fview(4, 10)))
	sb.WriteString("\n")

	sb.WriteString(grayBoldStyle.Render("ICMP"))
	sb.WriteString("\n")
	sb.WriteString(r.row2(r.fview(4, 11), r.fview(4, 12)))
	sb.WriteString("\n")
	sb.WriteString(r.row3(r.fview(4, 13), r.fview(4, 14), r.fview(4, 15)))
	sb.WriteString("\n")
	sb.WriteString(r.row2(r.fview(4, 16), r.fview(4, 17)))
	sb.WriteString("\n")

	sb.WriteString(grayBoldStyle.Render("ICMPv6"))
	sb.WriteString("\n")
	sb.WriteString(r.row2(r.fview(4, 18), r.fview(4, 19)))
	sb.WriteString("\n")
	sb.WriteString(r.row3(r.fview(4, 20), r.fview(4, 21), r.fview(4, 22)))
	sb.WriteString("\n")
	sb.WriteString(r.row2(r.fview(4, 23), r.fview(4, 24)))
	sb.WriteString("\n")

	sb.WriteString(grayBoldStyle.Render("SCTP"))
	sb.WriteString("\n")
	sb.WriteString(r.row2(r.fview(4, 25), r.fview(4, 26)))
	sb.WriteString("\n")
	sb.WriteString(r.row2(r.fview(4, 27), r.fview(4, 28)))
	sb.WriteString("\n")
	sb.WriteString(r.fview(4, 29)) // SctpChunkField — chunk-type Select
	sb.WriteString("\n")

	sb.WriteString(grayBoldStyle.Render("DCCP"))
	sb.WriteString("\n")
	sb.WriteString(r.row2(r.fview(4, 30), r.fview(4, 31)))
	sb.WriteString("\n")
	sb.WriteString(r.fview(4, 32))

	sb.WriteString(grayBoldStyle.Render("AH"))
	sb.WriteString("\n")
	sb.WriteString(r.row2(r.fview(4, 33), r.fview(4, 34)))
	sb.WriteString("\n")
	sb.WriteString(r.row2(r.fview(4, 35), r.fview(4, 36)))
	sb.WriteString("\n")

	sb.WriteString(grayBoldStyle.Render("ESP"))
	sb.WriteString("\n")
	sb.WriteString(r.row2(r.fview(4, 37), r.fview(4, 38)))
	sb.WriteString("\n")

	sb.WriteString(grayBoldStyle.Render("COMP"))
	sb.WriteString("\n")
	sb.WriteString(r.row3(r.fview(4, 39), r.fview(4, 40), r.fview(4, 41)))
	sb.WriteString("\n")

	return sb.String()
}

// renderMetaTab renders the Meta tab content (16 fields).
func (r ruleEdit) renderMetaTab() string {
	// tabs[5].fields: 0=Iiftype, 1=Oiftype, 2=Nfproto, 3=L4proto, 4=Protocol,
	//   5=Length, 6=Mark, 7=Priority, 8=Rtclassid, 9=Skuid, 10=Skgid,
	//   11=Cgroup, 12=Cpu, 13=Iifgroup, 14=Oifgroup, 15=Pkttype
	var sb strings.Builder

	// Row 1: iiftype | oiftype | nfproto
	sb.WriteString(r.row3(r.fview(5, 0), r.fview(5, 1), r.fview(5, 2)))
	sb.WriteString("\n")
	// Row 2: l4proto | protocol | length
	sb.WriteString(r.row3(r.fview(5, 3), r.fview(5, 4), r.fview(5, 5)))
	sb.WriteString("\n")
	// Row 3: mark | priority | rtclassid
	sb.WriteString(r.row3(r.fview(5, 6), r.fview(5, 7), r.fview(5, 8)))
	sb.WriteString("\n")
	// Row 4: skuid | skgid | cgroup
	sb.WriteString(r.row3(r.fview(5, 9), r.fview(5, 10), r.fview(5, 11)))
	sb.WriteString("\n")
	// Row 5: cpu | iifgroup | oifgroup
	sb.WriteString(r.row3(r.fview(5, 12), r.fview(5, 13), r.fview(5, 14)))
	sb.WriteString("\n")
	// Row 6: pkttype (full row)
	sb.WriteString(r.row2(r.fview(5, 15), ""))
	sb.WriteString("\n")

	return sb.String()
}

// isMetaKeyHandledByEditor reports whether a Meta condition key is already
// surfaced through a dedicated field editor (Network or Meta tab). Used to
// suppress duplicate rendering in the "Other conditions" generic dump.
func isMetaKeyHandledByEditor(k nft.MetaKey) bool {
	switch k {
	case nft.MetaKeyIIfName, nft.MetaKeyOIfName, nft.MetaKeyIIf, nft.MetaKeyOIf,
		nft.MetaKeyIIfType, nft.MetaKeyOIfType,
		nft.MetaKeyNfproto, nft.MetaKeyL4Proto, nft.MetaKeyProtocol, nft.MetaKeyLength,
		nft.MetaKeyMark, nft.MetaKeyPriority, nft.MetaKeyRtclassid,
		nft.MetaKeySkuid, nft.MetaKeySkgid,
		nft.MetaKeyCGroup, nft.MetaKeyCPU,
		nft.MetaKeyIIfGroup, nft.MetaKeyOIfGroup,
		nft.MetaKeyPktType:
		return true
	}
	return false
}

// renderLimitTab renders the Limit tab content.
func (r ruleEdit) renderLimitTab() string {
	// tabs[6].fields: 0=Over, 1=Rate, 2=Unit, 3=Burst, 4=Type
	var sb strings.Builder

	// Row 1: Over | Rate | Unit
	sb.WriteString(r.row3(r.fview(6, 0), r.fview(6, 1), r.fview(6, 2)))
	sb.WriteString("\n")

	// Row 2: Burst | Type
	sb.WriteString(r.row2(r.fview(6, 3), r.fview(6, 4)))
	sb.WriteString("\n")

	return sb.String()
}

// View renders the rule editor view.
func (r ruleEdit) View() string {
	header := blueBoldStyle.Render("nftui nftables manager") + readOnlyBanner(r.readOnly)

	divider := grayStyle.
		Width(r.width).
		Render(strings.Repeat("─", r.width))

	ruleDefinition, _ := nft.NftablesToRuleDefinition(r.rule)

	// Fixed top: title, tab bar, and its divider — these never scroll.
	var top strings.Builder
	top.WriteString(blueStyle.Render(i18n.T("rule.edit.title")))
	top.WriteString("\n\n")
	top.WriteString(r.renderTabBar())
	top.WriteString("\n")
	tabBarDivider := r.width - 4
	if tabBarDivider < 1 {
		tabBarDivider = 1
	}
	top.WriteString(grayStyle.Render(strings.Repeat("─", tabBarDivider)))
	topPart := top.String()

	// Scrollable body: the active tab's field area.
	var body string
	switch r.activeTab {
	case 0:
		body = r.renderGeneralTab(ruleDefinition)
	case 1:
		body = r.renderCTTab()
	case 2:
		body = r.renderNetworkTab(ruleDefinition)
	case 3:
		body = r.renderIPTab()
	case 4:
		body = r.renderTransportTab()
	case 5:
		body = r.renderMetaTab()
	case 6:
		body = r.renderLimitTab()
	}

	// Window the body so the Tab/Shift+Tab-focused field stays visible. The top
	// part is fixed, so the fields get the remaining height inside the box. The
	// focused field is located by focusSentinel (injected by fview); scroll the
	// minimum needed to keep its full height on screen.
	boxInner := r.height - 8
	if boxInner < 1 {
		boxInner = 1
	}
	bodyWindow := boxInner - lipgloss.Height(topPart)
	if bodyWindow < 1 {
		bodyWindow = 1
	}
	bodyLines := strings.Split(body, "\n")

	focusLine := 0
	for i, line := range bodyLines {
		if strings.Contains(line, focusSentinel) {
			focusLine = i
			break
		}
	}
	focusH := 1
	if focused, _ := r.fieldAtTabSlot(r.activeTab, r.tabFocusSlot[r.activeTab]); focused != nil {
		focusH = lipgloss.Height(focused.View())
	}

	scroll := 0
	if focusLine+focusH > bodyWindow {
		scroll = focusLine + focusH - bodyWindow
	}
	if maxScroll := len(bodyLines) - bodyWindow; scroll > maxScroll {
		scroll = maxScroll
	}
	if scroll < 0 {
		scroll = 0
	}
	end := scroll + bodyWindow
	if end > len(bodyLines) {
		end = len(bodyLines)
	}
	visible := strings.Join(bodyLines[scroll:end], "\n")

	innerContent := strings.ReplaceAll(topPart+"\n"+visible, focusSentinel, "")

	contentBox := normalGrayBorder.
		Width(r.width-2).
		Height(r.height-8).
		Padding(0, 1).
		Render(innerContent)

	footer := r.help.View(r.keys)
	if r.errStr != "" {
		footer = redBoldStyle.Render("! "+r.errStr) + "\n" + footer
	}

	fullView := lipgloss.JoinVertical(lipgloss.Left,
		header,
		divider,
		contentBox,
		footer,
	)

	return defaultStyle.Render(fullView)
}
