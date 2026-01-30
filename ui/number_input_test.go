package ui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
)

func TestNewNumberInput(t *testing.T) {
	minValue := 0
	maxValue := 100

	ni := NewNumberInput(minValue, maxValue)

	assert.Equal(t, minValue, ni.min, "min should be set correctly")
	assert.Equal(t, maxValue, ni.max, "max should be set correctly")
	assert.Equal(t, 10, ni.CharLimit, "CharLimit should be set to 10")
	assert.Equal(t, 10, ni.Width, "Width should be set to 10")
	assert.Nil(t, ni.Validate(""), "Validation should not return an error for empty strings")
	assert.Error(t, ni.Validate("abc"), "Validation should fail for non-numeric input")
	assert.Nil(t, ni.Validate("123"), "Validation should not return an error for numeric input")
}

func TestNumberInput_Update(t *testing.T) {
	tests := []struct {
		name           string
		initialValue   string
		msg            tea.Msg
		min            int
		max            int
		expectedValue  string
		expectedCmdNil bool
	}{
		{
			name:          "increment within range",
			initialValue:  "5",
			msg:           tea.KeyMsg{Type: tea.KeyUp},
			min:           0,
			max:           10,
			expectedValue: "6",
		},
		{
			name:          "increment at max boundary",
			initialValue:  "10",
			msg:           tea.KeyMsg{Type: tea.KeyUp},
			min:           0,
			max:           10,
			expectedValue: "10",
		},
		{
			name:          "decrement within range",
			initialValue:  "5",
			msg:           tea.KeyMsg{Type: tea.KeyDown},
			min:           0,
			max:           10,
			expectedValue: "4",
		},
		{
			name:          "decrement at min boundary",
			initialValue:  "0",
			msg:           tea.KeyMsg{Type: tea.KeyDown},
			min:           0,
			max:           10,
			expectedValue: "0",
		},
		{
			name:           "non-key message does not change value",
			initialValue:   "5",
			msg:            "non-key message",
			min:            0,
			max:            10,
			expectedValue:  "5",
			expectedCmdNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ni := NewNumberInput(tt.min, tt.max)
			ni.SetValue(tt.initialValue)

			updatedNI, cmd := ni.Update(tt.msg)

			assert.Equal(t, tt.expectedValue, updatedNI.Value(), "value should be updated correctly")
			if tt.expectedCmdNil {
				assert.Nil(t, cmd, "expected command to be nil")
			}
		})
	}
}

func TestNumberInput_GetValue(t *testing.T) {
	tests := []struct {
		name          string
		inputValue    string
		expectedValue int
	}{
		{
			name:          "valid numeric input",
			inputValue:    "25",
			expectedValue: 25,
		},
		{
			name:          "invalid input defaults to 0",
			inputValue:    "abc",
			expectedValue: 0,
		},
		{
			name:          "empty input defaults to 0",
			inputValue:    "",
			expectedValue: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ni := NewNumberInput(0, 100)
			ni.SetValue(tt.inputValue)

			result := ni.GetValue()

			assert.Equal(t, tt.expectedValue, result, "GetValue should return the correct integer value")
		})
	}
}
