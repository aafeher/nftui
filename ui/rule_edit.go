package ui

import (
	"fmt"
	"nftui/nft"
	nftexpr "nftui/nft/expr"
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

type ruleEdit struct {
	rule   *nftables.Rule
	width  int
	height int
	help   help.Model
	keys   ruleEditKeyMap

	// Position
	originalPosition uint64
	positionInput    NumberInput
	positionChanged  bool

	// Limit
	originalLimitOver bool
	limitOverInput    Select
	limitOverChanged  bool

	originalLimitRate uint64
	limitRateInput    NumberInput
	limitRateChanged  bool

	originalLimitUnit expr.LimitTime
	limitUnitInput    Select
	limitUnitChanged  bool

	originalLimitBurst uint32
	limitBurstInput    NumberInput
	limitBurstChanged  bool

	originalLimitType expr.LimitType
	limitTypeInput    Select
	limitTypeChanged  bool

	// Comment
	originalComment string
	commentInput    textinput.Model
	commentChanged  bool

	focusIndex int
}

type ruleEditKeyMap struct {
	Back key.Binding
	Save key.Binding
	Quit key.Binding
}

func (k ruleEditKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Back, k.Save, k.Quit}
}

func (k ruleEditKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Back, k.Save, k.Quit},
	}
}

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

	availableOvers := []string{"false", "true"}
	tiLimitOver := NewSelect(availableOvers)
	tiLimitOver.Width = 10

	tiPosition := NewNumberInput(0, 999_999_999)
	tiPosition.Placeholder = ""
	tiPosition.CharLimit = 10
	tiPosition.Width = 10

	tiLimitRate := NewNumberInput(0, 999_999_999)
	tiLimitRate.Placeholder = ""
	tiLimitRate.CharLimit = 10
	tiLimitRate.Width = 10

	tiLimitUnit := NewSelect(nftexpr.LimitTimeStrings)
	tiLimitUnit.Width = 10

	tiLimitBurst := NewNumberInput(0, 999_999_999)
	tiLimitBurst.Placeholder = ""
	tiLimitBurst.CharLimit = 10
	tiLimitBurst.Width = 10

	tiLimitType := NewSelect(nftexpr.LimitTypeStrings)
	tiLimitType.Width = 10

	tiComment := textinput.New()
	tiComment.Placeholder = "Comment"
	tiComment.CharLimit = 256
	tiComment.Width = 80

	ruleDefinition, _ := nft.NftablesToRuleDefinition(rule)

	tiPosition.SetValue(fmt.Sprint(ruleDefinition.Position))
	tiPosition.Focus()

	originalLimitOver := false
	originalLimitRate := uint64(0)
	originalLimitUnit := expr.LimitTimeSecond
	originalLimitBurst := uint32(0)
	originalLimitType := expr.LimitTypePkts
	for _, condition := range ruleDefinition.Conditions {
		if condition.Limit != nil {
			originalLimitOver = condition.Limit.Over
			originalLimitRate = condition.Limit.Rate
			originalLimitUnit = condition.Limit.Unit
			originalLimitBurst = condition.Limit.Burst
			originalLimitType = condition.Limit.Type
		}
	}

	overStr := "false"
	switch originalLimitOver {
	case false:
		overStr = "false"
	case true:
		overStr = "true"
	}
	tiLimitOver.SetValue(overStr)

	tiLimitRate.SetValue(fmt.Sprint(originalLimitRate))
	tiLimitUnit.SetValue(nftexpr.LimitUnitToString(originalLimitUnit))
	tiLimitBurst.SetValue(fmt.Sprint(originalLimitBurst))
	tiLimitType.SetValue(nftexpr.LimitTypeToString(originalLimitType))

	tiComment.SetValue(ruleDefinition.Comment)

	return ruleEdit{
		rule:               rule,
		help:               help.New(),
		keys:               km,
		positionInput:      tiPosition,
		limitOverInput:     tiLimitOver,
		limitRateInput:     tiLimitRate,
		limitUnitInput:     tiLimitUnit,
		limitBurstInput:    tiLimitBurst,
		limitTypeInput:     tiLimitType,
		commentInput:       tiComment,
		focusIndex:         0,
		originalPosition:   ruleDefinition.Position,
		originalLimitOver:  originalLimitOver,
		originalLimitRate:  originalLimitRate,
		originalLimitUnit:  originalLimitUnit,
		originalLimitBurst: originalLimitBurst,
		originalLimitType:  originalLimitType,
		originalComment:    ruleDefinition.Comment,
		positionChanged:    false,
		limitOverChanged:   false,
		limitRateChanged:   false,
		limitUnitChanged:   false,
		limitBurstChanged:  false,
		limitTypeChanged:   false,
		commentChanged:     false,
	}
}

func (r ruleEdit) Update(msg tea.Msg) (ruleEdit, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		r.width, r.height = msg.Width, msg.Height
		return r, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "tab", "shift+tab":
			// Tab billentyűvel váltás a mezők között
			if msg.String() == "tab" {
				r.focusIndex = (r.focusIndex + 1) % 7
			} else {
				r.focusIndex = (r.focusIndex - 1 + 7) % 7
			}

			r.positionInput.Blur()
			r.limitOverInput.Blur()
			r.limitRateInput.Blur()
			r.limitUnitInput.Blur()
			r.limitBurstInput.Blur()
			r.limitTypeInput.Blur()
			r.commentInput.Blur()

			// Fókusz beállítása
			if r.focusIndex == 0 {
				r.positionInput.Focus()
			} else if r.focusIndex == 1 {
				r.limitOverInput.Focus()
			} else if r.focusIndex == 2 {
				r.limitRateInput.Focus()
			} else if r.focusIndex == 3 {
				r.limitUnitInput.Focus()
			} else if r.focusIndex == 4 {
				r.limitBurstInput.Focus()
			} else if r.focusIndex == 5 {
				r.limitTypeInput.Focus()
			} else if r.focusIndex == 6 {
				r.commentInput.Focus()
			}
			return r, nil
		}

		switch {
		case key.Matches(msg, r.keys.Save):
			// Position mentése
			if r.positionChanged {
				if val, err := r.positionInput.GetUint64(); err == nil {
					r.rule.Position = val
					r.originalPosition = val
					r.positionChanged = false
				}
			}

			if r.limitOverChanged {
				newLimitOverStr := r.limitOverInput.Value()
				var newLimitOver bool
				switch newLimitOverStr {
				case "true":
					newLimitOver = true
				case "false":
					newLimitOver = false
				}
				for i, re := range r.rule.Exprs {
					switch re.(type) {
					case *expr.Limit:
						r.rule.Exprs[i].(*expr.Limit).Over = newLimitOver
					}
				}
				r.originalLimitOver = newLimitOver
				r.limitOverChanged = false
				r.limitOverInput.Changed = false
			}

			// Limit Rate mentése
			if r.limitRateChanged {
				if val, err := r.limitRateInput.GetUint64(); err == nil {
					for i, re := range r.rule.Exprs {
						switch re.(type) {
						case *expr.Limit:
							r.rule.Exprs[i].(*expr.Limit).Rate = val
						}
					}
					r.originalLimitRate = val
					r.limitRateChanged = false
				}
			}

			if r.limitUnitChanged {
				newLimitUnit := nftexpr.StringToLimitUnit(r.limitUnitInput.Value())
				for i, re := range r.rule.Exprs {
					switch re.(type) {
					case *expr.Limit:
						r.rule.Exprs[i].(*expr.Limit).Unit = newLimitUnit
					}
				}
				r.originalLimitUnit = newLimitUnit
				r.limitUnitChanged = false
				r.limitUnitInput.Changed = false
			}

			if r.limitBurstChanged {
				if val, err := r.limitBurstInput.GetUint64(); err == nil {
					for i, re := range r.rule.Exprs {
						switch re.(type) {
						case *expr.Limit:
							r.rule.Exprs[i].(*expr.Limit).Burst = uint32(val)
						}
					}
					r.originalLimitBurst = uint32(val)
					r.limitBurstChanged = false
				}
			}

			if r.limitTypeChanged {
				newLimitType := nftexpr.StringToLimitType(r.limitTypeInput.Value())
				for i, re := range r.rule.Exprs {
					switch re.(type) {
					case *expr.Limit:
						r.rule.Exprs[i].(*expr.Limit).Type = newLimitType
					}
				}
				r.originalLimitType = newLimitType
				r.limitTypeChanged = false
				r.limitTypeInput.Changed = false
			}

			// Comment mentése
			if r.commentChanged {
				newComment := r.commentInput.Value()
				r.rule.UserData = encodeCommentToUserData(newComment)
				r.originalComment = newComment
				r.commentChanged = false
			}

			saveCmd := func() tea.Msg {
				err := nft.ApplyRuleChange(r.rule)
				if err != nil {
					// Itt érdemes lehet egy hibaüzenet típust bevezetni
					return fmt.Errorf("mentési hiba: %w", err)
				}
				return nil // Vagy egy sikeres mentés üzenet
			}

			return r, saveCmd
		default:
			// Csak az aktív inputnak továbbítjuk az üzenetet
			if r.focusIndex == 0 {
				r.positionInput, cmd = r.positionInput.Update(msg)
				cmds = append(cmds, cmd)
				r.positionChanged = r.positionInput.Value() != fmt.Sprint(r.originalPosition)
			} else if r.focusIndex == 1 {
				r.limitOverInput, cmd = r.limitOverInput.Update(msg)
				cmds = append(cmds, cmd)

				overStr := "false"
				switch r.originalLimitOver {
				case false:
					overStr = "false"
				case true:
					overStr = "true"
				}
				r.limitOverChanged = r.limitOverInput.Value() != overStr
				r.limitOverInput.Changed = r.limitOverChanged
			} else if r.focusIndex == 2 {
				r.limitRateInput, cmd = r.limitRateInput.Update(msg)
				cmds = append(cmds, cmd)
				r.limitRateChanged = r.limitRateInput.Value() != fmt.Sprint(r.originalLimitRate)
			} else if r.focusIndex == 3 {
				r.limitUnitInput, cmd = r.limitUnitInput.Update(msg)
				cmds = append(cmds, cmd)

				unitStr := nftexpr.LimitUnitToString(r.originalLimitUnit)
				r.limitUnitChanged = r.limitUnitInput.Value() != unitStr
				r.limitUnitInput.Changed = r.limitUnitChanged
			} else if r.focusIndex == 4 {
				r.limitBurstInput, cmd = r.limitBurstInput.Update(msg)
				cmds = append(cmds, cmd)
				r.limitBurstChanged = r.limitBurstInput.Value() != fmt.Sprint(r.originalLimitBurst)
			} else if r.focusIndex == 5 {
				r.limitTypeInput, cmd = r.limitTypeInput.Update(msg)
				cmds = append(cmds, cmd)

				r.limitTypeChanged = r.limitTypeInput.Value() != nftexpr.LimitTypeToString(r.originalLimitType)
				r.limitTypeInput.Changed = r.limitTypeChanged
			} else if r.focusIndex == 6 {
				r.commentInput, cmd = r.commentInput.Update(msg)
				cmds = append(cmds, cmd)
				r.commentChanged = r.commentInput.Value() != r.originalComment
			}
			return r, tea.Batch(cmds...)
		}
	}

	// Egyéb üzenetek esetén is csak az aktív inputot frissítjük
	if r.focusIndex == 0 {
		r.positionInput, cmd = r.positionInput.Update(msg)
		cmds = append(cmds, cmd)
	} else if r.focusIndex == 1 {
		r.limitOverInput, cmd = r.limitOverInput.Update(msg)
		cmds = append(cmds, cmd)
	} else if r.focusIndex == 2 {
		r.limitRateInput, cmd = r.limitRateInput.Update(msg)
		cmds = append(cmds, cmd)
	} else if r.focusIndex == 3 {
		r.limitUnitInput, cmd = r.limitUnitInput.Update(msg)
		cmds = append(cmds, cmd)
	} else if r.focusIndex == 4 {
		r.limitBurstInput, cmd = r.limitBurstInput.Update(msg)
		cmds = append(cmds, cmd)
	} else if r.focusIndex == 5 {
		r.limitTypeInput, cmd = r.limitTypeInput.Update(msg)
		cmds = append(cmds, cmd)
	} else if r.focusIndex == 6 {
		r.commentInput, cmd = r.commentInput.Update(msg)
		cmds = append(cmds, cmd)
	}

	return r, tea.Batch(cmds...)
}

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

	content.WriteString(grayStyle.Render("Position"))
	content.WriteString("\n")
	// Ha módosítva van, sárga színnel jelenítjük meg
	positionView := r.positionInput.View()
	if r.positionChanged {
		positionView = lipgloss.NewStyle().
			Foreground(lipgloss.Color("220")).
			Render(positionView)
	}
	content.WriteString(positionView)
	content.WriteString("\n")

	for _, condition := range ruleDefinition.Conditions {
		// Ct
		if condition.CT != nil {
			content.WriteString(fmt.Sprintf("Condition CT: %+v\n", condition.CT))
		}
	}

	for _, condition := range ruleDefinition.Conditions {
		// Meta
		if condition.Meta != nil {
			content.WriteString(fmt.Sprintf("Condition Meta: %+v\n", condition.Meta))
		}

		// Payload
		if condition.Payload != nil {
			content.WriteString(fmt.Sprintf("Condition Payload: %+v\n", condition.Payload))
		}

		// Limit
		if condition.Limit != nil {
			// &{Rate:2 Unit:1m0s Burst:5 LimitType:packets Exceeded:false}
			content.WriteString(fmt.Sprintf("Condition Limit: %+v\n", condition.Limit))
			content.WriteString(grayStyle.Render("Limit Over"))
			content.WriteString("\n")
			limitOverView := r.limitOverInput.View()
			if r.limitOverChanged {
				limitOverView = lipgloss.NewStyle().
					Foreground(lipgloss.Color("220")).
					Render(limitOverView)
			}
			content.WriteString(limitOverView)
			content.WriteString("\n")

			content.WriteString(grayStyle.Render("Limit Rate"))
			content.WriteString("\n")
			limitRateView := r.limitRateInput.View()
			if r.limitRateChanged {
				limitRateView = lipgloss.NewStyle().
					Foreground(lipgloss.Color("220")).
					Render(limitRateView)
			}
			content.WriteString(limitRateView)
			content.WriteString("\n")

			content.WriteString(grayStyle.Render("Limit Unit"))
			content.WriteString("\n")
			limitUnitView := r.limitUnitInput.View()
			if r.limitUnitChanged {
				limitUnitView = lipgloss.NewStyle().
					Foreground(lipgloss.Color("220")).
					Render(limitUnitView)
			}
			content.WriteString(limitUnitView)
			content.WriteString("\n")

			content.WriteString(grayStyle.Render("Limit Burst"))
			content.WriteString("\n")
			limitBurstView := r.limitBurstInput.View()
			if r.limitBurstChanged {
				limitBurstView = lipgloss.NewStyle().
					Foreground(lipgloss.Color("220")).
					Render(limitBurstView)
			}
			content.WriteString(limitBurstView)
			content.WriteString("\n")

			content.WriteString(grayStyle.Render("Limit Type"))
			content.WriteString("\n")
			limitTypeView := r.limitTypeInput.View()
			if r.limitTypeChanged {
				limitTypeView = lipgloss.NewStyle().
					Foreground(lipgloss.Color("220")).
					Render(limitTypeView)
			}
			content.WriteString(limitTypeView)
			content.WriteString("\n")
		}

		// SetLookup
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

	content.WriteString(grayStyle.Render("Comment"))
	content.WriteString("\n")
	// Ha módosítva van, sárga színnel jelenítjük meg
	commentView := r.commentInput.View()
	if r.commentChanged {
		commentView = lipgloss.NewStyle().
			Foreground(lipgloss.Color("220")).
			Render(commentView)
	}
	content.WriteString(commentView)
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

// encodeCommentToUserData kódol egy comment stringet UserData TLV formátumba
// TLV formátum: [type (1 byte)][length (1 byte)][value (length bytes)]
// A comment típusa UDATA_TYPE_COMMENT = 0
func encodeCommentToUserData(comment string) []byte {
	if comment == "" {
		return nil
	}

	// Null terminátorral együtt
	commentBytes := []byte(comment)
	// TLV struktúra: type(1) + length(1) + value
	userData := make([]byte, 2+len(commentBytes)+1)
	userData[0] = 0                           // UDATA_TYPE_COMMENT
	userData[1] = byte(len(commentBytes) + 1) // length (null terminátorral)
	copy(userData[2:], commentBytes)
	userData[len(userData)-1] = 0 // null terminátor

	return userData
}
