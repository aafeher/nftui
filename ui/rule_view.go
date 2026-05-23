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
	"github.com/google/nftables/expr"
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
			key.WithHelp("f5", "prev tab"),
		),
		NextTab: key.NewBinding(
			key.WithKeys("f6"),
			key.WithHelp("f6", "next tab"),
		),
		Back: key.NewBinding(
			key.WithKeys("esc", "f3"),
			key.WithHelp("esc/f3", "back"),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "quit"),
		),
	}

	return ruleView{
		rule: rule,
		help: newHelpModel(),
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
	tabNames := []string{"General", "CT", "Network", "Limit"}
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

	sb.WriteString(grayBoldStyle.Render("Position: "))
	sb.WriteString(fmt.Sprintf("%d\n", rd.Position))

	if rd.Comment != "" {
		sb.WriteString(grayBoldStyle.Render("Comment: "))
		sb.WriteString(rd.Comment + "\n")
	}

	if len(rd.Actions) > 0 {
		sb.WriteString("\n")
		sb.WriteString(grayBoldStyle.Render("Actions:"))
		sb.WriteString("\n")
		for _, action := range rd.Actions {
			switch action.Type {
			case nft.ActionTypeVerdict:
				if action.Verdict != nil {
					sb.WriteString("  verdict: ")
					sb.WriteString(renderVerdict(*action.Verdict))
					sb.WriteString("\n")
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
					sb.WriteString("  ")
					sb.WriteString(renderLog(*action.Log))
					sb.WriteString("\n")
				}
			case nft.ActionTypeQueue:
				if action.Queue != nil {
					sb.WriteString(fmt.Sprintf("  queue: %+v\n", action.Queue))
				}
			case nft.ActionTypeReject:
				if action.Reject != nil {
					sb.WriteString("  ")
					sb.WriteString(renderReject(*action.Reject, r.rule.Table.Family))
					sb.WriteString("\n")
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
		sb.WriteString(grayBoldStyle.Render("Counter: "))
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
		nftexpr.CtKeyEventMask,
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
				valStr = "(no value)"
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
				case nftexpr.CtEvent:
					valStr = op + string(v)
				case []nftexpr.CtEvent:
					var s []string
					for _, ev := range v {
						s = append(s, string(ev))
					}
					if len(s) == 1 {
						valStr = op + s[0]
					} else {
						valStr = op + "{" + strings.Join(s, ", ") + "}"
					}
				case uint16:
					valStr = fmt.Sprintf("%s%d", op, v)
				case uint32:
					if ctKey == nftexpr.CtKeyMark || ctKey == nftexpr.CtKeySecMark {
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
			sb.WriteString(labelPart + " " + grayStyle.Render("(empty)") + "\n")
		}
	}

	// CT count (connlimit)
	for _, condition := range rd.Conditions {
		if condition.Connlimit == nil {
			continue
		}
		labelPart := grayBoldStyle.Render(fmt.Sprintf("%-*s", labelWidth, "CT count:"))
		over := condition.Connlimit.Flags&expr.NFT_CONNLIMIT_F_INV == 0
		var valStr string
		if over {
			valStr = fmt.Sprintf("over %d", condition.Connlimit.Count)
		} else {
			valStr = fmt.Sprintf("%d", condition.Connlimit.Count)
		}
		sb.WriteString(labelPart + " " + valStr + "\n")
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
			label := grayBoldStyle.Render(fmt.Sprintf("%-*s", labelWidth, "IP src:"))
			sb.WriteString(label + " " + fmt.Sprintf("%s%s %s\n", op, string(p.Protocol), valStr))
		case "daddr":
			daddrFound = true
			label := grayBoldStyle.Render(fmt.Sprintf("%-*s", labelWidth, "IP dst:"))
			sb.WriteString(label + " " + fmt.Sprintf("%s%s %s\n", op, string(p.Protocol), valStr))
		default:
			label := grayStyle.Render(fmt.Sprintf("%-*s", labelWidth, string(p.Protocol)+" "+p.Field+":"))
			sb.WriteString(label + " " + op + valStr + "\n")
		}
	}

	if !saddrFound {
		label := grayStyle.Render(fmt.Sprintf("%-*s", labelWidth, "IP src:"))
		sb.WriteString(label + " " + grayStyle.Render("(empty)") + "\n")
	}
	if !daddrFound {
		label := grayStyle.Render(fmt.Sprintf("%-*s", labelWidth, "IP dst:"))
		sb.WriteString(label + " " + grayStyle.Render("(empty)") + "\n")
	}

	// meta iifname / oifname — dedicated lines, always shown.
	iifFound, oifFound := false, false
	for _, condition := range rd.Conditions {
		if condition.Meta == nil {
			continue
		}
		switch condition.Meta.Key {
		case nft.MetaKeyIIfName:
			iifFound = true
			op := string(condition.Operation)
			if op == "==" {
				op = ""
			} else {
				op += " "
			}
			label := grayBoldStyle.Render(fmt.Sprintf("%-*s", labelWidth, "Meta iifname:"))
			sb.WriteString(label + " " + fmt.Sprintf("%s%q\n", op, fmt.Sprintf("%v", condition.Meta.Value)))
		case nft.MetaKeyOIfName:
			oifFound = true
			op := string(condition.Operation)
			if op == "==" {
				op = ""
			} else {
				op += " "
			}
			label := grayBoldStyle.Render(fmt.Sprintf("%-*s", labelWidth, "Meta oifname:"))
			sb.WriteString(label + " " + fmt.Sprintf("%s%q\n", op, fmt.Sprintf("%v", condition.Meta.Value)))
		}
	}
	if !iifFound {
		label := grayStyle.Render(fmt.Sprintf("%-*s", labelWidth, "Meta iifname:"))
		sb.WriteString(label + " " + grayStyle.Render("(empty)") + "\n")
	}
	if !oifFound {
		label := grayStyle.Render(fmt.Sprintf("%-*s", labelWidth, "Meta oifname:"))
		sb.WriteString(label + " " + grayStyle.Render("(empty)") + "\n")
	}

	// Meta conditions (everything except iifname/oifname rendered above)
	hasMeta := false
	for _, condition := range rd.Conditions {
		if condition.Meta == nil || condition.Meta.Key == "" {
			continue
		}
		if condition.Meta.Key == nft.MetaKeyIIfName ||
			condition.Meta.Key == nft.MetaKeyOIfName {
			continue
		}
		if !hasMeta {
			sb.WriteString("\n")
			sb.WriteString(grayBoldStyle.Render("Meta conditions:"))
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
		sb.WriteString(grayStyle.Render("(No limit conditions)"))
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
	content.WriteString(blueStyle.Render("| View rule |"))
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

// renderVerdict formats a VerdictAction for display in the rule view:
//   - accept → green
//   - drop / reject → red
//   - return / jump / goto / continue → yellow
//   - jump / goto include the target chain name (e.g. "jump my_chain")
//   - anything else falls back to the kind string as-is
func renderVerdict(v nft.VerdictAction) string {
	kind := string(v.Kind)
	switch v.Kind {
	case nft.VerdictAccept:
		return greenBoldStyle.Render(kind)
	case nft.VerdictDrop, nft.VerdictReject:
		return redBoldStyle.Render(kind)
	case nft.VerdictReturn, nft.VerdictContinue:
		return yellowBoldStyle.Render(kind)
	case nft.VerdictJump, nft.VerdictGoto:
		if v.Chain == "" {
			return yellowBoldStyle.Render(kind)
		}
		return yellowBoldStyle.Render(kind) + " " + blueStyle.Render(v.Chain)
	default:
		return whiteStyle.Render(kind)
	}
}

// ICMP destination-unreachable codes that nft's CLI knows by name (RFC 792 / 1812 §5.2.7.1).
var icmpRejectCodes = map[uint8]string{
	0:  "net-unreachable",
	1:  "host-unreachable",
	2:  "prot-unreachable",
	3:  "port-unreachable",
	5:  "net-redirect",
	9:  "net-prohibited",
	10: "host-prohibited",
	13: "admin-prohibited",
}

// ICMPv6 destination-unreachable codes (RFC 4443).
var icmpv6RejectCodes = map[uint8]string{
	0: "no-route",
	1: "admin-prohibited",
	3: "addr-unreachable",
	4: "port-unreachable",
	5: "policy-fail",
	6: "reject-route",
}

// ICMPX codes: family-agnostic abstraction used by inet/bridge rules
// (libnftnl NFT_REJECT_ICMPX_* mapping).
var icmpxRejectCodes = map[uint8]string{
	0: "no-route",
	1: "port-unreachable",
	2: "host-unreachable",
	3: "admin-prohibited",
}

// Default ICMP destination-unreachable code for each reject family — matches
// what `nft` elides in `list table` output (where a default-code reject is
// rendered as just "reject" without "with <type> <name>").
const (
	icmpDefaultRejectCode   = uint8(3) // port-unreachable
	icmpv6DefaultRejectCode = uint8(4) // port-unreachable
	icmpxDefaultRejectCode  = uint8(1) // port-unreachable
)

// renderReject formats a RejectAction for display in the rule view.
// Output mirrors nft CLI list syntax:
//   - "reject with tcp reset"
//   - "reject with icmp <code-name>" (omitted when code == default port-unreachable)
//   - "reject with icmpv6 <code-name>"
//   - "reject with icmpx <code-name>"
//
// The literal "reject" prefix is red bold; the type and code name are red.
// For ICMP-unreachable rejects the family decides between icmp (ip), icmpv6
// (ip6), and icmpx (inet/bridge — family-agnostic).
func renderReject(a nft.RejectAction, fam nftables.TableFamily) string {
	prefix := redBoldStyle.Render("reject")

	switch a.Type {
	case nft.RejectTypeTCPReset:
		return prefix + " " + redStyle.Render("with tcp reset")

	case nft.RejectTypeICMPX:
		return prefix + rejectSuffix("icmpx", a.Code, icmpxRejectCodes, icmpxDefaultRejectCode)

	case nft.RejectTypeICMPv6:
		return prefix + rejectSuffix("icmpv6", a.Code, icmpv6RejectCodes, icmpv6DefaultRejectCode)

	case nft.RejectTypeICMP:
		// The parser collapses both ICMP and ICMPv6 into RejectTypeICMP because
		// the wire format does not distinguish them. Decide based on table family.
		switch fam {
		case nftables.TableFamilyIPv6:
			return prefix + rejectSuffix("icmpv6", a.Code, icmpv6RejectCodes, icmpv6DefaultRejectCode)
		case nftables.TableFamilyINet, nftables.TableFamilyBridge:
			return prefix + rejectSuffix("icmpx", a.Code, icmpxRejectCodes, icmpxDefaultRejectCode)
		default:
			return prefix + rejectSuffix("icmp", a.Code, icmpRejectCodes, icmpDefaultRejectCode)
		}
	}

	return prefix
}

// rejectSuffix builds the " with <kind> <code-name>" tail, returning empty
// when code matches the family's default (which nft list elides).
func rejectSuffix(kind string, code uint8, table map[uint8]string, defaultCode uint8) string {
	if code == defaultCode {
		return ""
	}
	return " " + redStyle.Render("with "+kind+" "+lookupRejectCodeName(table, code))
}

// renderLog formats a LogAction for display in the rule view. Output mirrors
// nft CLI list syntax:
//
//	log [prefix "..."] [group N] [snaplen N] [queue-threshold N] [level NAME]
//
// The "log" keyword is yellow bold (informational, non-terminal). Argument
// keywords (prefix, level, group, snaplen, queue-threshold) are gray; values
// (the quoted prefix string, level name, numeric parameters) are blue. The
// default level (warn) is elided to match how nft renders it.
func renderLog(a nft.LogAction) string {
	parts := []string{yellowBoldStyle.Render("log")}

	if a.Prefix != "" {
		parts = append(parts,
			grayStyle.Render("prefix")+" "+blueStyle.Render("\""+a.Prefix+"\""),
		)
	}
	if a.Group != 0 {
		parts = append(parts,
			grayStyle.Render("group")+" "+blueStyle.Render(fmt.Sprintf("%d", a.Group)),
		)
	}
	if a.Snaplen != 0 {
		parts = append(parts,
			grayStyle.Render("snaplen")+" "+blueStyle.Render(fmt.Sprintf("%d", a.Snaplen)),
		)
	}
	if a.QThreshold != 0 {
		parts = append(parts,
			grayStyle.Render("queue-threshold")+" "+blueStyle.Render(fmt.Sprintf("%d", a.QThreshold)),
		)
	}
	if a.Level != "" && a.Level != nft.LogLevelWarn {
		parts = append(parts,
			grayStyle.Render("level")+" "+blueStyle.Render(string(a.Level)),
		)
	}

	return strings.Join(parts, " ")
}

func lookupRejectCodeName(table map[uint8]string, code uint8) string {
	if name, ok := table[code]; ok {
		return name
	}
	return fmt.Sprintf("%d", code)
}
