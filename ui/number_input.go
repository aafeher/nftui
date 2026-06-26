package ui

import (
	"fmt"
	"strconv"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type NumberInput struct {
	textinput.Model
	min, max int
}

func NewNumberInput(min, max int) NumberInput {
	ti := textinput.New()
	ti.CharLimit = 10
	ti.Width = 10
	ti.Validate = func(s string) error {
		if s == "" {
			return nil
		}
		_, err := strconv.Atoi(s)
		return err
	}

	return NumberInput{
		Model: ti,
		min:   min,
		max:   max,
	}
}

func (ni NumberInput) Update(msg tea.Msg) (NumberInput, tea.Cmd) {
	var cmd tea.Cmd

	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		currentVal, _ := strconv.Atoi(ni.Value())

		switch keyMsg.String() {
		case "up":
			if currentVal < ni.max {
				ni.SetValue(strconv.Itoa(currentVal + 1))
				return ni, nil
			}
		case "down":
			if currentVal > ni.min {
				ni.SetValue(strconv.Itoa(currentVal - 1))
				return ni, nil
			}
		}
	}

	ni.Model, cmd = ni.Model.Update(msg)
	return ni, cmd
}

func (ni NumberInput) GetValue() int {
	parsed, err := strconv.ParseInt(ni.Value(), 10, 32)
	if err != nil {
		return 0
	}
	return int(parsed)
}

// GetUint64 returns the numeric value as uint64
func (ni NumberInput) GetUint64() (uint64, error) {
	val := ni.Value()
	if val == "" {
		return 0, nil
	}
	var result uint64
	_, err := fmt.Sscanf(val, "%d", &result)
	return result, err
}
