package ui

import (
	"encoding/binary"
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

// ruleEdit represents a model for editing nftables rules with various properties and stateful inputs for user interaction.
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

	// CT State
	originalCtStates []nftexpr.CtState
	ctStateInputs    MultiSelect
	ctStatesChanged  bool

	// CT Direction
	originalCtDirection nftexpr.CtDirection
	ctDirectionInput    Select
	ctDirectionChanged  bool

	// CT Status
	originalCtStatuses []nftexpr.CtStatus
	ctStatusInputs     MultiSelect
	ctStatusesChanged  bool

	// CT Mark
	originalCtMark uint32
	ctMarkInput    NumberInput
	ctMarkChanged  bool

	// CT Expiration
	originalCtExpiration uint32
	ctExpirationInput    textinput.Model
	ctExpirationChanged  bool

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

// ruleEditKeyMap is a structure that defines key bindings for navigation and actions within the rule editing interface.
type ruleEditKeyMap struct {
	Back key.Binding
	Save key.Binding
	Quit key.Binding
}

// ShortHelp returns a slice of key bindings for primary actions: back, save, and quit.
func (k ruleEditKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Back, k.Save, k.Quit}
}

// FullHelp returns a matrix of key bindings, grouping actions such as back, save, and quit for detailed interface navigation.
func (k ruleEditKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Back, k.Save, k.Quit},
	}
}

// newRuleEdit initializes and returns a ruleEdit structure for editing nftables rules with pre-filled data and inputs.
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

	// position
	tiPosition := NewNumberInput(0, 999_999_999)
	tiPosition.Placeholder = ""
	tiPosition.CharLimit = 10
	tiPosition.Width = 10

	// ct state
	ctStateInputs := NewMultiSelect(nftexpr.CtStateStrings)

	// ct direction
	ctDirectionInput := NewSelect(nftexpr.CtDirectionStrings)
	ctDirectionInput.Width = 10

	// ct status
	ctStatusInputs := NewMultiSelect(nftexpr.CtStatusStrings)

	// ct mark
	ctMarkInput := NewNumberInput(0, 999_999_999)
	ctMarkInput.Placeholder = "0"
	ctMarkInput.CharLimit = 10
	ctMarkInput.Width = 10

	// ct expiration
	ctExpirationInput := textinput.New()
	ctExpirationInput.Placeholder = "e.g. 30s, 1m"
	ctExpirationInput.CharLimit = 32
	ctExpirationInput.Width = 20

	// limit over
	availableOvers := []string{"false", "true"}
	tiLimitOver := NewSelect(availableOvers)
	tiLimitOver.Width = 10

	// limit rate
	tiLimitRate := NewNumberInput(0, 999_999_999)
	tiLimitRate.Placeholder = ""
	tiLimitRate.CharLimit = 10
	tiLimitRate.Width = 10

	// limit unit
	tiLimitUnit := NewSelect(nftexpr.LimitTimeStrings)
	tiLimitUnit.Width = 10

	// limit burst
	tiLimitBurst := NewNumberInput(0, 999_999_999)
	tiLimitBurst.Placeholder = ""
	tiLimitBurst.CharLimit = 10
	tiLimitBurst.Width = 10

	// limit type
	tiLimitType := NewSelect(nftexpr.LimitTypeStrings)
	tiLimitType.Width = 10

	// comment
	tiComment := textinput.New()
	tiComment.Placeholder = "Comment"
	tiComment.CharLimit = 256
	tiComment.Width = 80

	ruleDefinition, _ := nft.NftablesToRuleDefinition(rule)

	// position
	tiPosition.SetValue(fmt.Sprint(ruleDefinition.Position))
	tiPosition.Focus()

	// ct state
	var originalCtStates []nftexpr.CtState

	// ct direction
	var originalCtDirection nftexpr.CtDirection

	// ct status
	var originalCtStatuses []nftexpr.CtStatus

	// ct mark
	var originalCtMark uint32

	// ct expiration
	var originalCtExpiration uint32

	// limit over
	originalLimitOver := false

	// limit rate
	originalLimitRate := uint64(0)

	// limit unit
	originalLimitUnit := expr.LimitTimeSecond

	// limit burst
	originalLimitBurst := uint32(0)

	// limit type
	originalLimitType := expr.LimitTypePkts

	for _, condition := range ruleDefinition.Conditions {
		if condition.CT != nil {
			if condition.CT.Key == nftexpr.CtKeyState {
				if states, ok := condition.CT.Value.([]nftexpr.CtState); ok {
					originalCtStates = states
				} else if state, ok := condition.CT.Value.(nftexpr.CtState); ok {
					originalCtStates = []nftexpr.CtState{state}
				}
			} else if condition.CT.Key == nftexpr.CtKeyDirection {
				if dir, ok := condition.CT.Value.(nftexpr.CtDirection); ok {
					originalCtDirection = dir
				}
			} else if condition.CT.Key == nftexpr.CtKeyStatus {
				if statuses, ok := condition.CT.Value.([]nftexpr.CtStatus); ok {
					originalCtStatuses = statuses
				} else if status, ok := condition.CT.Value.(nftexpr.CtStatus); ok {
					originalCtStatuses = []nftexpr.CtStatus{status}
				}
			} else if condition.CT.Key == nftexpr.CtKeyMark {
				if mark, ok := condition.CT.Value.(uint32); ok {
					originalCtMark = mark
				}
			} else if condition.CT.Key == nftexpr.CtKeyExpiration {
				if exp, ok := condition.CT.Value.(uint32); ok {
					originalCtExpiration = exp
				}
			}
		}
		if condition.Limit != nil {
			originalLimitOver = condition.Limit.Over
			originalLimitRate = condition.Limit.Rate
			originalLimitUnit = condition.Limit.Unit
			originalLimitBurst = condition.Limit.Burst
			originalLimitType = condition.Limit.Type
		}
	}

	// ct state
	originalCtStateStrings := make([]string, len(originalCtStates))
	for _, state := range originalCtStates {
		stateStr := string(state)
		originalCtStateStrings = append(originalCtStateStrings, stateStr)
	}
	ctStateInputs.SetValues(originalCtStateStrings)

	// ct direction
	ctDirectionInput.SetValue(string(originalCtDirection))

	// ct status
	originalCtStatusStrings := make([]string, 0, len(originalCtStatuses))
	for _, status := range originalCtStatuses {
		originalCtStatusStrings = append(originalCtStatusStrings, string(status))
	}
	ctStatusInputs.SetValues(originalCtStatusStrings)

	// ct mark
	ctMarkInput.SetValue(fmt.Sprint(originalCtMark))

	// ct expiration
	if originalCtExpiration > 0 {
		ctExpirationInput.SetValue(nftexpr.FormatDuration(originalCtExpiration))
	} else {
		ctExpirationInput.SetValue("")
	}

	// limit
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

	// comment
	tiComment.SetValue(ruleDefinition.Comment)

	return ruleEdit{
		rule:                 rule,
		help:                 help.New(),
		keys:                 km,
		positionInput:        tiPosition,
		ctStateInputs:        ctStateInputs,
		ctDirectionInput:     ctDirectionInput,
		ctStatusInputs:       ctStatusInputs,
		ctMarkInput:          ctMarkInput,
		ctExpirationInput:    ctExpirationInput,
		limitOverInput:       tiLimitOver,
		limitRateInput:       tiLimitRate,
		limitUnitInput:       tiLimitUnit,
		limitBurstInput:      tiLimitBurst,
		limitTypeInput:       tiLimitType,
		commentInput:         tiComment,
		focusIndex:           0,
		originalPosition:     ruleDefinition.Position,
		originalCtStates:     originalCtStates,
		originalCtDirection:  originalCtDirection,
		originalCtStatuses:   originalCtStatuses,
		originalCtMark:       originalCtMark,
		originalCtExpiration: originalCtExpiration,
		originalLimitOver:    originalLimitOver,
		originalLimitRate:    originalLimitRate,
		originalLimitUnit:    originalLimitUnit,
		originalLimitBurst:   originalLimitBurst,
		originalLimitType:    originalLimitType,
		originalComment:      ruleDefinition.Comment,
		positionChanged:      false,
		ctStatesChanged:      false,
		ctDirectionChanged:   false,
		ctStatusesChanged:    false,
		ctMarkChanged:        false,
		ctExpirationChanged:  false,
		limitOverChanged:     false,
		limitRateChanged:     false,
		limitUnitChanged:     false,
		limitBurstChanged:    false,
		limitTypeChanged:     false,
		commentChanged:       false,
	}
}

// Update processes user inputs and updates the state of the rule editor based on the received messages.
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
				r.focusIndex = (r.focusIndex + 1) % 12
			} else {
				r.focusIndex = (r.focusIndex - 1 + 12) % 12
			}

			r.positionInput.Blur()
			r.ctStateInputs.Blur()
			r.ctDirectionInput.Blur()
			r.ctStatusInputs.Blur()
			r.ctMarkInput.Blur()
			r.ctExpirationInput.Blur()
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
				r.ctStateInputs.Focus()
			} else if r.focusIndex == 2 {
				r.ctDirectionInput.Focus()
			} else if r.focusIndex == 3 {
				r.ctStatusInputs.Focus()
			} else if r.focusIndex == 4 {
				r.ctMarkInput.Focus()
			} else if r.focusIndex == 5 {
				r.ctExpirationInput.Focus()
			} else if r.focusIndex == 6 {
				r.limitOverInput.Focus()
			} else if r.focusIndex == 7 {
				r.limitRateInput.Focus()
			} else if r.focusIndex == 8 {
				r.limitUnitInput.Focus()
			} else if r.focusIndex == 9 {
				r.limitBurstInput.Focus()
			} else if r.focusIndex == 10 {
				r.limitTypeInput.Focus()
			} else if r.focusIndex == 11 {
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

			if r.ctStatesChanged {
				newCtStates := nftexpr.CtStateStringToStates(r.ctStateInputs.Values())

				for i, re := range r.rule.Exprs {
					switch e := re.(type) {
					case *expr.Ct:
						if e.Key == expr.CtKeySTATE {
							// Megkeressük a hozzá tartozó Bitwise-t vagy Cmp-t
							if i+1 < len(r.rule.Exprs) {
								switch next := r.rule.Exprs[i+1].(type) {
								case *expr.Bitwise:
									// Frissítjük a maszkot
									next.Mask = nftexpr.EncodeCtStates(newCtStates)
								case *expr.Cmp:
									// Ha egy elem van, Cmp-vé válhat, vagy Bitwise-szá
									if len(newCtStates) == 1 {
										next.Data = nftexpr.EncodeCtStates(newCtStates)
									} else if len(newCtStates) > 1 {
										// Itt bonyolultabb lehet a váltás Cmp és Bitwise között
										// Egyszerűség kedvéért feltételezzük a meglévő struktúrát
										next.Data = nftexpr.EncodeCtStates(newCtStates)
									}
								}
							}
						}
					}
				}
				r.originalCtStates = newCtStates
				r.ctStatesChanged = false
				r.ctStateInputs.Changed = false
			}

			if r.ctDirectionChanged {
				newDirStr := r.ctDirectionInput.Value()
				var newDir nftexpr.CtDirection = nftexpr.CtDirection(newDirStr)

				for i, re := range r.rule.Exprs {
					switch e := re.(type) {
					case *expr.Ct:
						if e.Key == expr.CtKeyDIRECTION {
							if i+1 < len(r.rule.Exprs) {
								if next, ok := r.rule.Exprs[i+1].(*expr.Cmp); ok {
									if newDir == nftexpr.CtDirectionOriginal {
										next.Data = []byte{0}
									} else {
										next.Data = []byte{1}
									}
								}
							}
						}
					}
				}
				r.originalCtDirection = newDir
				r.ctDirectionChanged = false
				r.ctDirectionInput.Changed = false
			}

			if r.ctStatusesChanged {
				newCtStatuses := nftexpr.CtStatusStringToStatuses(r.ctStatusInputs.Values())

				for i, re := range r.rule.Exprs {
					switch e := re.(type) {
					case *expr.Ct:
						if e.Key == expr.CtKeySTATUS {
							// Megkeressük a hozzá tartozó Bitwise-t vagy Cmp-t
							if i+1 < len(r.rule.Exprs) {
								switch next := r.rule.Exprs[i+1].(type) {
								case *expr.Bitwise:
									// Frissítjük a maszkot
									next.Mask = nftexpr.EncodeCtStatuses(newCtStatuses)
								case *expr.Cmp:
									// Ha egy elem van, Cmp-vé válhat, vagy Bitwise-szá
									if len(newCtStatuses) == 1 {
										next.Data = nftexpr.EncodeCtStatuses(newCtStatuses)
									} else if len(newCtStatuses) > 1 {
										// Itt bonyolultabb a helyzet, Cmp-t Bitwise-ra kellene cserélni
										// Egyelőre feltételezzük, hogy Bitwise volt, ha több van.
									}
								}
							}
						}
					}
				}
				r.originalCtStatuses = newCtStatuses
				r.ctStatusesChanged = false
				r.ctStatusInputs.Changed = false
			}

			if r.ctMarkChanged {
				val, err := r.ctMarkInput.GetUint64()
				if err == nil {
					newMark := uint32(val)
					for i, re := range r.rule.Exprs {
						switch e := re.(type) {
						case *expr.Ct:
							if e.Key == expr.CtKeyMARK {
								if i+1 < len(r.rule.Exprs) {
									if next, ok := r.rule.Exprs[i+1].(*expr.Cmp); ok {
										next.Data = binary.LittleEndian.AppendUint32(nil, newMark)
									}
								}
							}
						}
					}

					r.originalCtMark = newMark
					r.ctMarkChanged = false
				}
			}

			if r.ctExpirationChanged {
				newExpStr := r.ctExpirationInput.Value()
				op, val1, val2, elements, isRange, isSet := parseComplexDuration(newExpStr)

				found := false
				for i, re := range r.rule.Exprs {
					switch e := re.(type) {
					case *expr.Ct:
						if e.Key == expr.CtKeyEXPIRATION {
							found = true
							if i+1 < len(r.rule.Exprs) {
								if isRange {
									bufFrom := make([]byte, 4)
									binary.BigEndian.PutUint32(bufFrom, val1*1000)
									bufTo := make([]byte, 4)
									binary.BigEndian.PutUint32(bufTo, val2*1000)

									r.rule.Exprs[i+1] = &expr.Range{
										Op:       op,
										Register: e.Register,
										FromData: bufFrom,
										ToData:   bufTo,
									}
								} else if isSet {
									if len(elements) == 1 {
										buf := make([]byte, 4)
										binary.BigEndian.PutUint32(buf, elements[0]*1000)
										r.rule.Exprs[i+1] = &expr.Cmp{
											Op:       op,
											Register: e.Register,
											Data:     buf,
										}
									} else {
										// Halmaz kezelése (lookup) - korlátozott frissítés
										if _, ok := r.rule.Exprs[i+1].(*expr.Lookup); !ok {
											buf := make([]byte, 4)
											binary.BigEndian.PutUint32(buf, elements[0]*1000)
											r.rule.Exprs[i+1] = &expr.Cmp{
												Op:       op,
												Register: e.Register,
												Data:     buf,
											}
										}
									}
								} else {
									buf := make([]byte, 4)
									binary.BigEndian.PutUint32(buf, val1*1000)
									r.rule.Exprs[i+1] = &expr.Cmp{
										Op:       op,
										Register: e.Register,
										Data:     buf,
									}
								}
							}
						}
					}
				}
				if !found && val1 > 0 {
					// Add new CT expiration if not found (simplified)
				}
				r.originalCtExpiration = val1
				r.ctExpirationChanged = false
				r.ctExpirationInput.Blur()
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

			// limit rate
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

			// limit unit
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

			// limit burst
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

			// limit type
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

			// comment
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
				r.ctStateInputs, cmd = r.ctStateInputs.Update(msg)
				cmds = append(cmds, cmd)

				ctStateStrings := nftexpr.CtStateToStateStrings(r.originalCtStates)
				r.ctStatesChanged = !nftexpr.CtStatesAreEqual(r.ctStateInputs.Values(), ctStateStrings)
				r.ctStateInputs.Changed = r.ctStatesChanged
			} else if r.focusIndex == 2 {
				r.ctDirectionInput, cmd = r.ctDirectionInput.Update(msg)
				cmds = append(cmds, cmd)
				r.ctDirectionChanged = r.ctDirectionInput.Value() != string(r.originalCtDirection)
				r.ctDirectionInput.Changed = r.ctDirectionChanged
			} else if r.focusIndex == 3 {
				r.ctStatusInputs, cmd = r.ctStatusInputs.Update(msg)
				cmds = append(cmds, cmd)

				ctStatusStrings := nftexpr.CtStatusToStatusStrings(r.originalCtStatuses)
				r.ctStatusesChanged = !nftexpr.CtStatesAreEqual(r.ctStatusInputs.Values(), ctStatusStrings)
				r.ctStatusInputs.Changed = r.ctStatusesChanged
			} else if r.focusIndex == 4 {
				r.ctMarkInput, cmd = r.ctMarkInput.Update(msg)
				cmds = append(cmds, cmd)
				r.ctMarkChanged = r.ctMarkInput.GetValue() != int(r.originalCtMark)
			} else if r.focusIndex == 5 {
				r.ctExpirationInput, cmd = r.ctExpirationInput.Update(msg)
				cmds = append(cmds, cmd)
				r.ctExpirationChanged = r.ctExpirationInput.Value() != nftexpr.FormatDuration(r.originalCtExpiration)
			} else if r.focusIndex == 6 {
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
			} else if r.focusIndex == 7 {
				r.limitRateInput, cmd = r.limitRateInput.Update(msg)
				cmds = append(cmds, cmd)
				r.limitRateChanged = r.limitRateInput.Value() != fmt.Sprint(r.originalLimitRate)
			} else if r.focusIndex == 8 {
				r.limitUnitInput, cmd = r.limitUnitInput.Update(msg)
				cmds = append(cmds, cmd)

				unitStr := nftexpr.LimitUnitToString(r.originalLimitUnit)
				r.limitUnitChanged = r.limitUnitInput.Value() != unitStr
				r.limitUnitInput.Changed = r.limitUnitChanged
			} else if r.focusIndex == 9 {
				r.limitBurstInput, cmd = r.limitBurstInput.Update(msg)
				cmds = append(cmds, cmd)
				r.limitBurstChanged = r.limitBurstInput.Value() != fmt.Sprint(r.originalLimitBurst)
			} else if r.focusIndex == 10 {
				r.limitTypeInput, cmd = r.limitTypeInput.Update(msg)
				cmds = append(cmds, cmd)

				r.limitTypeChanged = r.limitTypeInput.Value() != nftexpr.LimitTypeToString(r.originalLimitType)
				r.limitTypeInput.Changed = r.limitTypeChanged
			} else if r.focusIndex == 11 {
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
		r.ctStateInputs, cmd = r.ctStateInputs.Update(msg)
		cmds = append(cmds, cmd)
	} else if r.focusIndex == 2 {
		r.ctDirectionInput, cmd = r.ctDirectionInput.Update(msg)
		cmds = append(cmds, cmd)
	} else if r.focusIndex == 3 {
		r.ctStatusInputs, cmd = r.ctStatusInputs.Update(msg)
		cmds = append(cmds, cmd)
	} else if r.focusIndex == 4 {
		r.ctMarkInput, cmd = r.ctMarkInput.Update(msg)
		cmds = append(cmds, cmd)
	} else if r.focusIndex == 5 {
		r.ctExpirationInput, cmd = r.ctExpirationInput.Update(msg)
		cmds = append(cmds, cmd)
	} else if r.focusIndex == 6 {
		r.limitOverInput, cmd = r.limitOverInput.Update(msg)
		cmds = append(cmds, cmd)
	} else if r.focusIndex == 7 {
		r.limitRateInput, cmd = r.limitRateInput.Update(msg)
		cmds = append(cmds, cmd)
	} else if r.focusIndex == 8 {
		r.limitUnitInput, cmd = r.limitUnitInput.Update(msg)
		cmds = append(cmds, cmd)
	} else if r.focusIndex == 9 {
		r.limitBurstInput, cmd = r.limitBurstInput.Update(msg)
		cmds = append(cmds, cmd)
	} else if r.focusIndex == 10 {
		r.limitTypeInput, cmd = r.limitTypeInput.Update(msg)
		cmds = append(cmds, cmd)
	} else if r.focusIndex == 11 {
		r.commentInput, cmd = r.commentInput.Update(msg)
		cmds = append(cmds, cmd)
	}

	// ct mark változás figyelése
	if r.ctMarkInput.GetValue() != int(r.originalCtMark) {
		r.ctMarkChanged = true
	} else {
		r.ctMarkChanged = false
	}

	// ct expiration változás figyelése
	if r.ctExpirationInput.Value() != nftexpr.FormatDuration(r.originalCtExpiration) {
		r.ctExpirationChanged = true
	} else {
		r.ctExpirationChanged = false
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

	// CT Mezők fix sorrendben
	content.WriteString(grayStyle.Render("CT States"))
	content.WriteString("\n")
	ctStatesView := r.ctStateInputs.View()
	if r.ctStatesChanged {
		ctStatesView = lipgloss.NewStyle().
			Foreground(lipgloss.Color("220")).
			Render(ctStatesView)
	}
	content.WriteString(ctStatesView)
	content.WriteString("\n")

	content.WriteString(grayStyle.Render("CT Direction"))
	content.WriteString("\n")
	ctDirectionView := r.ctDirectionInput.View()
	if r.ctDirectionChanged {
		ctDirectionView = lipgloss.NewStyle().
			Foreground(lipgloss.Color("220")).
			Render(ctDirectionView)
	}
	content.WriteString(ctDirectionView)
	content.WriteString("\n")

	content.WriteString(grayStyle.Render("CT Status"))
	content.WriteString("\n")
	ctStatusView := r.ctStatusInputs.View()
	if r.ctStatusesChanged {
		ctStatusView = lipgloss.NewStyle().
			Foreground(lipgloss.Color("220")).
			Render(ctStatusView)
	}
	content.WriteString(ctStatusView)
	content.WriteString("\n")

	content.WriteString(grayStyle.Render("CT Mark"))
	content.WriteString("\n")
	ctMarkView := r.ctMarkInput.View()
	if r.ctMarkChanged {
		ctMarkView = lipgloss.NewStyle().
			Foreground(lipgloss.Color("220")).
			Render(ctMarkView)
	}
	content.WriteString(ctMarkView)
	content.WriteString("\n")

	content.WriteString(grayStyle.Render("CT Expiration"))
	content.WriteString("\n")
	ctExpirationView := r.ctExpirationInput.View()
	if r.ctExpirationChanged {
		ctExpirationView = lipgloss.NewStyle().
			Foreground(lipgloss.Color("220")).
			Render(ctExpirationView)
	}
	content.WriteString(ctExpirationView)
	content.WriteString("\n")

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

func parseDuration(s string) uint32 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	var total uint32
	var current uint32
	var foundUnit bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			current = current*10 + uint32(c-'0')
		} else {
			switch c {
			case 'd':
				total += current * 86400
				foundUnit = true
			case 'h':
				total += current * 3600
				foundUnit = true
			case 'm':
				total += current * 60
				foundUnit = true
			case 's':
				total += current
				foundUnit = true
			}
			current = 0
		}
	}
	// Default to seconds if no unit provided
	if !foundUnit && current > 0 {
		total += current
	}
	return total
}

func parseComplexDuration(s string) (op expr.CmpOp, val1 uint32, val2 uint32, elements []uint32, isRange bool, isSet bool) {
	s = strings.TrimSpace(s)
	op = expr.CmpOpEq

	if strings.HasPrefix(s, "!= ") {
		op = expr.CmpOpNeq
		s = strings.TrimPrefix(s, "!= ")
	} else if strings.HasPrefix(s, "!=") {
		op = expr.CmpOpNeq
		s = strings.TrimPrefix(s, "!=")
	} else if strings.HasPrefix(s, "<= ") {
		op = expr.CmpOpLte
		s = strings.TrimPrefix(s, "<= ")
	} else if strings.HasPrefix(s, "<=") {
		op = expr.CmpOpLte
		s = strings.TrimPrefix(s, "<=")
	} else if strings.HasPrefix(s, ">= ") {
		op = expr.CmpOpGte
		s = strings.TrimPrefix(s, ">= ")
	} else if strings.HasPrefix(s, ">=") {
		op = expr.CmpOpGte
		s = strings.TrimPrefix(s, ">=")
	} else if strings.HasPrefix(s, "< ") {
		op = expr.CmpOpLt
		s = strings.TrimPrefix(s, "< ")
	} else if strings.HasPrefix(s, "<") {
		op = expr.CmpOpLt
		s = strings.TrimPrefix(s, "<")
	} else if strings.HasPrefix(s, "> ") {
		op = expr.CmpOpGt
		s = strings.TrimPrefix(s, "> ")
	} else if strings.HasPrefix(s, ">") {
		op = expr.CmpOpGt
		s = strings.TrimPrefix(s, ">")
	}

	s = strings.TrimSpace(s)

	if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
		isSet = true
		content := s[1 : len(s)-1]
		parts := strings.Split(content, ",")
		for _, p := range parts {
			elements = append(elements, parseDuration(p))
		}
		return
	}

	if strings.Contains(s, "-") {
		parts := strings.Split(s, "-")
		if len(parts) == 2 {
			isRange = true
			val1 = parseDuration(parts[0])
			val2 = parseDuration(parts[1])
			return
		}
	}

	val1 = parseDuration(s)
	return
}
