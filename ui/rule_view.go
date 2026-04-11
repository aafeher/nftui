package ui

import (
	"fmt"
	"nftui/nft"
	nftexpr "nftui/nft/expr"
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
)

type ruleView struct {
	rule      *nftables.Rule
	activeTab int
	width     int
	height    int
	help      help.Model
	keys      ruleViewKeyMap
}

type ruleViewKeyMap struct {
	PrevTab key.Binding
	NextTab key.Binding
	Back    key.Binding
	Quit    key.Binding
}

func (k ruleViewKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.PrevTab, k.NextTab, k.Back, k.Quit}
}

func (k ruleViewKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.PrevTab, k.NextTab, k.Back, k.Quit},
	}
}

const ruleViewTabCount = 4

func newRuleView(rule *nftables.Rule) ruleView {
	km := ruleViewKeyMap{
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
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "kilépés"),
		),
	}

	return ruleView{
		rule: rule,
		help: help.New(),
		keys: km,
	}
}

func (r ruleView) Update(msg tea.Msg) (ruleView, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		r.width, r.height = msg.Width, msg.Height
		return r, nil
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, r.keys.PrevTab):
			r.activeTab = (r.activeTab - 1 + ruleViewTabCount) % ruleViewTabCount
		case key.Matches(msg, r.keys.NextTab):
			r.activeTab = (r.activeTab + 1) % ruleViewTabCount
		}
	}
	return r, nil
}

// renderTabBar renders the horizontal tab strip.
func (r ruleView) renderTabBar() string {
	tabNames := []string{"Általános", "CT", "Hálózat", "Limit"}
	var parts []string
	for i, name := range tabNames {
		label := "  " + name + "  "
		if i == r.activeTab {
			parts = append(parts, whiteBoldStyle.Background(lipgloss.Color("#264f88")).Render(label))
		} else {
			parts = append(parts, grayStyle.Render(label))
		}
		if i < len(tabNames)-1 {
			parts = append(parts, grayStyle.Render("│"))
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
}

// renderGeneralTab renders Position, Comment, Actions, Counter.
func (r ruleView) renderGeneralTab(rd *nft.Rule) string {
	var sb strings.Builder

	sb.WriteString(grayBoldStyle.Render("Pozíció: "))
	sb.WriteString(fmt.Sprintf("%d\n", rd.Position))

	if rd.Comment != "" {
		sb.WriteString(grayBoldStyle.Render("Megjegyzés: "))
		sb.WriteString(rd.Comment + "\n")
	}

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

	if rd.Counter != nil {
		sb.WriteString("\n")
		sb.WriteString(grayBoldStyle.Render("Számláló: "))
		sb.WriteString(fmt.Sprintf("%d packets, %d bytes\n", rd.Counter.Packets, rd.Counter.Bytes))
	}

	return sb.String()
}

// renderCTTab renders all CT (Connection Tracking) condition fields.
func (r ruleView) renderCTTab(rd *nft.Rule) string {
	var sb strings.Builder

	keys := []nftexpr.CtKey{
		nftexpr.CtKeyL3Protocol,
		nftexpr.CtKeyProtocol,
		nftexpr.CtKeyProtoSrc,
		nftexpr.CtKeyProtoDst,
		nftexpr.CtKeyState,
		nftexpr.CtKeyDirection,
		nftexpr.CtKeyStatus,
		nftexpr.CtKeyLabels,
		nftexpr.CtKeyMark,
		nftexpr.CtKeySecMark,
		nftexpr.CtKeyExpiration,
		nftexpr.CtKeyHelper,
		nftexpr.CtKeyZone,
		nftexpr.CtKeyBytes,
		nftexpr.CtKeyPkts,
		nftexpr.CtKeyAvgpkt,
	}

	labelWidth := 18

	for _, ctKey := range keys {
		displayKey := strings.ReplaceAll(string(ctKey), "_", "-")
		label := fmt.Sprintf("CT %s", displayKey)
		found := false

		for _, condition := range rd.Conditions {
			if condition.CT == nil || condition.CT.Key != ctKey {
				continue
			}
			found = true
			val := condition.CT.Value
			op := string(condition.Operation)
			if op == "==" {
				op = ""
			} else {
				op += " "
			}

			dirPrefix := ""
			if condition.CT.Direction == nftexpr.CtDirectionOriginal {
				dirPrefix = "original "
			} else if condition.CT.Direction == nftexpr.CtDirectionReply {
				dirPrefix = "reply "
			}
			if dirPrefix != "" {
				label = fmt.Sprintf("CT %s%s", dirPrefix, displayKey)
			}

			labelPart := grayBoldStyle.Render(fmt.Sprintf("%-*s", labelWidth, label+":"))

			var valStr string
			if val == nil {
				valStr = "(nincs érték)"
			} else {
				switch v := val.(type) {
				case nftexpr.CtL3Proto:
					valStr = op + string(v)
				case nftexpr.CtProtocol:
					valStr = op + string(v)
				case nftexpr.CtState:
					valStr = op + string(v)
				case []nftexpr.CtState:
					var s []string
					for _, st := range v {
						s = append(s, string(st))
					}
					if len(s) == 1 {
						valStr = op + s[0]
					} else {
						valStr = op + "{" + strings.Join(s, ", ") + "}"
					}
				case nftexpr.CtDirection:
					valStr = op + string(v)
				case nftexpr.CtStatus:
					valStr = op + string(v)
				case []nftexpr.CtStatus:
					var s []string
					for _, st := range v {
						s = append(s, string(st))
					}
					if len(s) == 1 {
						valStr = op + s[0]
					} else {
						valStr = op + "{" + strings.Join(s, ", ") + "}"
					}
				case uint16:
					valStr = fmt.Sprintf("%s%d", op, v)
				case uint32:
					if ctKey == nftexpr.CtKeyMark {
						valStr = fmt.Sprintf("%s0x%08x", op, v)
					} else if ctKey == nftexpr.CtKeyExpiration {
						valStr = op + nftexpr.FormatDuration(v)
					} else {
						valStr = fmt.Sprintf("%s%d", op, v)
					}
				case uint64:
					valStr = fmt.Sprintf("%s%d", op, v)
				case *nft.RangeValue:
					fromStr := fmt.Sprintf("%v", v.From)
					toStr := fmt.Sprintf("%v", v.To)
					if f, ok := v.From.(uint32); ok && ctKey == nftexpr.CtKeyExpiration {
						fromStr = nftexpr.FormatDuration(f)
					}
					if t, ok := v.To.(uint32); ok && ctKey == nftexpr.CtKeyExpiration {
						toStr = nftexpr.FormatDuration(t)
					}
					valStr = op + fromStr + "-" + toStr
				case *nft.SetValue:
					var s []string
					for _, item := range v.Elements {
						if u, ok := item.(uint32); ok && ctKey == nftexpr.CtKeyExpiration {
							s = append(s, nftexpr.FormatDuration(u))
						} else {
							s = append(s, fmt.Sprintf("%v", item))
						}
					}
					valStr = op + "{" + strings.Join(s, ", ") + "}"
				case []string:
					if len(v) == 0 {
						valStr = op + "{}"
					} else {
						valStr = op + "bits {" + strings.Join(v, ",") + "}"
					}
				case []any:
					var s []string
					for _, item := range v {
						if u, ok := item.(uint32); ok && ctKey == nftexpr.CtKeyExpiration {
							s = append(s, nftexpr.FormatDuration(u))
						} else {
							s = append(s, fmt.Sprintf("%v", item))
						}
					}
					valStr = "{" + strings.Join(s, ", ") + "}"
				default:
					valStr = fmt.Sprintf("%v", v)
				}
			}

			sb.WriteString(labelPart + " " + valStr + "\n")
			break
		}

		if !found {
			labelPart := grayStyle.Render(fmt.Sprintf("%-*s", labelWidth, label+":"))
			sb.WriteString(labelPart + " " + grayStyle.Render("(üres)") + "\n")
		}
	}

	return sb.String()
}

// renderNetworkTab renders IP address and other payload/meta conditions.
func (r ruleView) renderNetworkTab(rd *nft.Rule) string {
	var sb strings.Builder
	labelWidth := 18

	// IP source address
	saddrFound := false
	daddrFound := false

	for _, condition := range rd.Conditions {
		if condition.Payload == nil {
			continue
		}
		p := condition.Payload
		if p.Protocol != nft.PayloadProtoIP && p.Protocol != nft.PayloadProtoIP6 {
			continue
		}
		op := string(condition.Operation)
		if op == "==" {
			op = ""
		} else {
			op += " "
		}
		var valStr string
		switch v := p.Value.(type) {
		case *nft.IPAddress:
			if v.Subnet != nil {
				valStr = v.Subnet.String()
			} else {
				valStr = v.IP.String()
			}
		default:
			valStr = fmt.Sprintf("%v", p.Value)
		}

		switch p.Field {
		case "saddr":
			saddrFound = true
			label := grayBoldStyle.Render(fmt.Sprintf("%-*s", labelWidth, "IP forrás:"))
			sb.WriteString(label + " " + fmt.Sprintf("%s%s %s\n", op, string(p.Protocol), valStr))
		case "daddr":
			daddrFound = true
			label := grayBoldStyle.Render(fmt.Sprintf("%-*s", labelWidth, "IP cél:"))
			sb.WriteString(label + " " + fmt.Sprintf("%s%s %s\n", op, string(p.Protocol), valStr))
		default:
			label := grayStyle.Render(fmt.Sprintf("%-*s", labelWidth, string(p.Protocol)+" "+p.Field+":"))
			sb.WriteString(label + " " + op + valStr + "\n")
		}
	}

	if !saddrFound {
		label := grayStyle.Render(fmt.Sprintf("%-*s", labelWidth, "IP forrás:"))
		sb.WriteString(label + " " + grayStyle.Render("(üres)") + "\n")
	}
	if !daddrFound {
		label := grayStyle.Render(fmt.Sprintf("%-*s", labelWidth, "IP cél:"))
		sb.WriteString(label + " " + grayStyle.Render("(üres)") + "\n")
	}

	// Meta conditions
	hasMeta := false
	for _, condition := range rd.Conditions {
		if condition.Meta == nil || condition.Meta.Key == "" {
			continue
		}
		if !hasMeta {
			sb.WriteString("\n")
			sb.WriteString(grayBoldStyle.Render("Meta feltételek:"))
			sb.WriteString("\n")
			hasMeta = true
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

	// SetLookup conditions
	for _, condition := range rd.Conditions {
		if condition.SetLookup == nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("  set lookup: %+v\n", condition.SetLookup))
	}

	// Custom conditions
	for _, condition := range rd.Conditions {
		if condition.Custom == nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("  custom: %+v\n", condition.Custom))
	}

	return sb.String()
}

// renderLimitTab renders limit condition fields.
func (r ruleView) renderLimitTab(rd *nft.Rule) string {
	var sb strings.Builder
	labelWidth := 10

	var limitCond *nft.Condition
	for i := range rd.Conditions {
		if rd.Conditions[i].Limit != nil {
			limitCond = &rd.Conditions[i]
			break
		}
	}

	if limitCond == nil {
		sb.WriteString(grayStyle.Render("(Nincsenek limit feltételek)"))
		sb.WriteString("\n")
		return sb.String()
	}

	lim := limitCond.Limit
	label := func(s string) string {
		return grayBoldStyle.Render(fmt.Sprintf("%-*s", labelWidth, s+":"))
	}

	overStr := "false"
	if lim.Over {
		overStr = "true"
	}

	sb.WriteString(label("Over") + " " + overStr + "\n")
	sb.WriteString(label("Rate") + " " + fmt.Sprintf("%d", lim.Rate) + "\n")
	sb.WriteString(label("Unit") + " " + nftexpr.LimitUnitToString(lim.Unit) + "\n")
	sb.WriteString(label("Burst") + " " + fmt.Sprintf("%d", lim.Burst) + "\n")
	sb.WriteString(label("Type") + " " + nftexpr.LimitTypeToString(lim.Type) + "\n")

	return sb.String()
}

func (r ruleView) View() string {
	header := blueBoldStyle.Render("nftui nftables manager")

	divider := grayStyle.
		Width(r.width).
		Render(strings.Repeat("─", r.width))

	ruleDefinition, _ := nft.NftablesToRuleDefinition(r.rule)

	var content strings.Builder
	content.WriteString(blueStyle.Render("| Szabály megtekintése |"))
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
		content.WriteString(r.renderCTTab(ruleDefinition))
	case 2:
		content.WriteString(r.renderNetworkTab(ruleDefinition))
	case 3:
		content.WriteString(r.renderLimitTab(ruleDefinition))
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
