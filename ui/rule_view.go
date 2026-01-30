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
	rule   *nftables.Rule
	width  int
	height int
	help   help.Model
	keys   ruleViewKeyMap
}

type ruleViewKeyMap struct {
	Back key.Binding
	Quit key.Binding
}

func (k ruleViewKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Back, k.Quit}
}

func (k ruleViewKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Back, k.Quit},
	}
}

func newRuleView(rule *nftables.Rule) ruleView {
	km := ruleViewKeyMap{
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
		help: help.New(),
		keys: km,
	}
}

func (r ruleView) Update(msg tea.Msg) (ruleView, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		r.width, r.height = msg.Width, msg.Height
		return r, nil
	}
	return r, nil
}

func (r ruleView) View() string {
	header := blueBoldStyle.Render("nftui nftables manager")

	divider := grayStyle.
		Width(r.width).
		Render(strings.Repeat("─", r.width))

	var content strings.Builder

	title := "| View Rule |"
	content.WriteString(blueStyle.Render(title))
	content.WriteString("\n\n")

	ruleDefinition, _ := nft.NftablesToRuleDefinition(r.rule)
	content.WriteString(fmt.Sprintf("%+v\n", ruleDefinition))
	content.WriteString("\n")
	content.WriteString(fmt.Sprintf("Position: %d\n", ruleDefinition.Position))

	for _, condition := range ruleDefinition.Conditions {
		// Ct
		if condition.CT != nil {
			val := condition.CT.Value
			op := condition.Operation

			prefix := fmt.Sprintf("CT %s %s", condition.CT.Key, op)

			if val == nil {
				content.WriteString(fmt.Sprintf("%s: (nincs érték)\n", prefix))
				continue
			}

			// Robusztusabb típuskezelés a megjelenítéshez
			switch v := val.(type) {
			case nftexpr.CtState:
				content.WriteString(fmt.Sprintf("%s %s\n", prefix, string(v)))
			case []nftexpr.CtState:
				if len(v) == 1 {
					content.WriteString(fmt.Sprintf("%s %s\n", prefix, string(v[0])))
				} else {
					var s []string
					for _, state := range v {
						s = append(s, string(state))
					}
					content.WriteString(fmt.Sprintf("%s {%s}\n", prefix, strings.Join(s, ", ")))
				}
			case nftexpr.CtDirection:
				content.WriteString(fmt.Sprintf("%s %s\n", prefix, string(v)))
			case nftexpr.CtStatus:
				content.WriteString(fmt.Sprintf("%s %s\n", prefix, string(v)))
			case []nftexpr.CtStatus:
				if len(v) == 1 {
					content.WriteString(fmt.Sprintf("%s %s\n", prefix, string(v[0])))
				} else {
					var s []string
					for _, status := range v {
						s = append(s, string(status))
					}
					content.WriteString(fmt.Sprintf("%s {%s}\n", prefix, strings.Join(s, ", ")))
				}
			case uint32:
				if condition.CT.Key == nftexpr.CtKeyMark {
					content.WriteString(fmt.Sprintf("%s 0x%08x\n", prefix, v))
				} else {
					content.WriteString(fmt.Sprintf("%s %d\n", prefix, v))
				}
			default:
				content.WriteString(fmt.Sprintf("%s %v\n", prefix, v))
			}
		}
	}

	for _, condition := range ruleDefinition.Conditions {
		// Meta
		if condition.Meta != nil && condition.Meta.Key != "" {
			metaKey := condition.Meta.Key
			metaValue := condition.Meta.Value
			content.WriteString(fmt.Sprintf("Condition Meta: %+v %+v\n", metaKey, metaValue))
		}

		// Payload
		if condition.Payload != nil {
			content.WriteString(fmt.Sprintf("Condition Payload: %+v\n", condition.Payload))
		}

		// Limit
		if condition.Limit != nil {
			content.WriteString(fmt.Sprintf(" over: %v\n", condition.Limit.Over))
			content.WriteString(fmt.Sprintf(" rate: %d\n", condition.Limit.Rate))
			content.WriteString(fmt.Sprintf(" unit: %+v\n", nftexpr.LimitUnitToString(condition.Limit.Unit)))
			content.WriteString(fmt.Sprintf(" burst: %d\n", condition.Limit.Burst))
			content.WriteString(fmt.Sprintf(" type: %s\n", nftexpr.LimitTypeToString(condition.Limit.Type)))
		}

		// Setlookup
		if condition.SetLookup != nil {
			content.WriteString(fmt.Sprintf("Condition SetLookup: %+v\n", condition.SetLookup))
		}

		// Custom
		if condition.Custom != nil {
			content.WriteString(fmt.Sprintf("Condition Custom: %+v\n", condition.Custom))
		}
	}

	content.WriteString("\n")

	for _, action := range ruleDefinition.Actions {
		if action.Type != "" {
			content.WriteString(fmt.Sprintf("Action Type: %+v\n", action.Type))
		}

		if action.Type == nft.ActionTypeCounter && action.Counter != nil {
			content.WriteString(fmt.Sprintf("Action Counter: %+v\n", action.Counter))
		}

		if action.Type == nft.ActionTypeVerdict && action.Verdict != nil {
			content.WriteString(fmt.Sprintf("Action Verdict: %+v\n", action.Verdict))
		}

		if action.Type == nft.ActionTypeNAT && action.NAT != nil {
			content.WriteString(fmt.Sprintf("Action NAT: %+v\n", action.NAT))
		}

		if action.Type == nft.ActionTypeLog && action.Log != nil {
			content.WriteString(fmt.Sprintf("Action Log: %+v\n", action.Log))
		}

		if action.Type == nft.ActionTypeQueue && action.Queue != nil {
			content.WriteString(fmt.Sprintf("Action Queue: %+v\n", action.Queue))
		}

		if action.Type == nft.ActionTypeReject && action.Reject != nil {
			content.WriteString(fmt.Sprintf("Action Reject: %+v\n", action.Reject))
		}

		//content.WriteString(fmt.Sprintf("Action Limit: %+v\n", action.Limit))

		if action.Type == nft.ActionTypeSet && action.Set != nil {
			content.WriteString(fmt.Sprintf("Action Set: %+v\n", action.Set))
		}

		if action.Type == nft.ActionTypeRedirect && action.Redirect != nil {
			content.WriteString(fmt.Sprintf("Action Redirect: %+v\n", action.Redirect))
		}

		if action.Type == nft.ActionTypeMasq && action.Masq != nil {
			content.WriteString(fmt.Sprintf("Action Masquerade: %+v\n", action.Masq))
		}

		if action.Type == nft.ActionTypeCustom && action.Custom != nil {
			content.WriteString(fmt.Sprintf("Action Custom: %+v\n", action.Custom))
		}
	}

	content.WriteString("\n")

	content.WriteString(fmt.Sprintf("Counter: %+v\n", ruleDefinition.Counter))

	content.WriteString("\n")

	content.WriteString(fmt.Sprintf("Comment: %+v\n", ruleDefinition.Comment))

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
