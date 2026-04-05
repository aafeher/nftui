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
	Back key.Binding
	Save key.Binding
	Quit key.Binding
}

// ShortHelp returns a slice of key bindings for primary actions: back, save, and quit.
func (k ruleEditKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Back, k.Save, k.Quit}
}

// FullHelp returns a matrix of key bindings grouping actions for detailed interface navigation.
func (k ruleEditKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Back, k.Save, k.Quit},
	}
}

// ruleEdit represents a model for editing nftables rules using the FieldEditor interface pattern.
type ruleEdit struct {
	rule       *nftables.Rule
	fields     []FieldEditor
	totalSlots int
	focusIndex int
	width      int
	height     int
	keys       ruleEditKeyMap
	help       help.Model
}

// newRuleEdit initializes and returns a ruleEdit structure for editing nftables rules.
func newRuleEdit(rule *nftables.Rule) ruleEdit {
	km := ruleEditKeyMap{
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

	fields := []FieldEditor{
		NewPositionField(rd),
		NewIPSaddrField(rd),
		NewIPDaddrField(rd),
		NewCtStateField(rd),
		NewCtDirectionField(rd),
		NewCtStatusField(rd),
		NewCtMarkField(rd),
		NewCtExpirationField(rd),
		NewCtHelperField(rd),
		NewCtBytesField(rd), // 2 slots
		NewCtPktsField(rd),  // 2 slots
		NewLimitOverField(rd),
		NewLimitRateField(rd),
		NewLimitUnitField(rd),
		NewLimitBurstField(rd),
		NewLimitTypeField(rd),
		NewCommentField(rd),
	}

	totalSlots := 0
	for _, f := range fields {
		totalSlots += f.FocusSlots()
	}

	if len(fields) > 0 {
		fields[0].Focus(0)
	}

	return ruleEdit{
		rule:       rule,
		fields:     fields,
		totalSlots: totalSlots,
		focusIndex: 0,
		keys:       km,
		help:       help.New(),
	}
}

// fieldAtSlot returns the FieldEditor and sub-index for a given slot number.
func (r ruleEdit) fieldAtSlot(slot int) (FieldEditor, int) {
	s := 0
	for _, f := range r.fields {
		for sub := 0; sub < f.FocusSlots(); sub++ {
			if s == slot {
				return f, sub
			}
			s++
		}
	}
	return nil, 0
}

// Update processes user inputs and updates the state of the rule editor based on the received messages.
func (r ruleEdit) Update(msg tea.Msg) (ruleEdit, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		r.width, r.height = msg.Width, msg.Height
		return r, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "tab", "shift+tab":
			cur, _ := r.fieldAtSlot(r.focusIndex)
			if cur != nil {
				cur.Blur()
			}
			if msg.String() == "tab" {
				r.focusIndex = (r.focusIndex + 1) % r.totalSlots
			} else {
				r.focusIndex = (r.focusIndex - 1 + r.totalSlots) % r.totalSlots
			}
			next, sub := r.fieldAtSlot(r.focusIndex)
			if next != nil {
				next.Focus(sub)
			}
			return r, nil
		}

		if key.Matches(msg, r.keys.Save) {
			for _, f := range r.fields {
				f.Save(r.rule)
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

		cur, _ := r.fieldAtSlot(r.focusIndex)
		if cur != nil {
			return r, cur.Update(msg)
		}
		return r, nil

	default:
		cur, _ := r.fieldAtSlot(r.focusIndex)
		if cur != nil {
			return r, cur.Update(msg)
		}
		return r, nil
	}
}

// View renders the rule editor view.
func (r ruleEdit) View() string {
	header := blueBoldStyle.Render("nftui nftables manager")

	divider := grayStyle.
		Width(r.width).
		Render(strings.Repeat("─", r.width))

	var content strings.Builder

	title := "| Edit Rule |"
	content.WriteString(blueStyle.Render(title))
	content.WriteString("\n\n")

	ruleDefinition, _ := nft.NftablesToRuleDefinition(r.rule)
	content.WriteString(fmt.Sprintf("%+v\n", ruleDefinition))
	content.WriteString("\n")

	for _, f := range r.fields {
		content.WriteString(f.View())
	}

	for _, condition := range ruleDefinition.Conditions {
		if condition.Meta != nil {
			content.WriteString(fmt.Sprintf("Condition Meta: %+v\n", condition.Meta))
		}
		if condition.Payload != nil {
			content.WriteString(fmt.Sprintf("Condition Payload: %+v\n", condition.Payload))
		}
		if condition.Limit != nil {
			content.WriteString(fmt.Sprintf("Condition Limit: %+v\n", condition.Limit))
		}
		if condition.SetLookup != nil {
			content.WriteString(fmt.Sprintf("Condition SetLookup: %+v\n", condition.SetLookup))
		}
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
