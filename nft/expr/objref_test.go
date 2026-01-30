package nftexpr

import (
	"testing"

	"github.com/google/nftables/expr"
)

func TestFormatObjref(t *testing.T) {
	tests := []struct {
		name     string
		input    *expr.Objref
		expected string
	}{
		{
			name: "basic",
			input: &expr.Objref{
				Type: 1,
				Name: "test",
			},
			expected: "objref type 1 name test",
		},
		{
			name: "empty name",
			input: &expr.Objref{
				Type: 2,
				Name: "",
			},
			expected: "objref type 2 name ",
		},
		{
			name: "zero type",
			input: &expr.Objref{
				Type: 0,
				Name: "zeroType",
			},
			expected: "objref type 0 name zeroType",
		},
		{
			name: "large values",
			input: &expr.Objref{
				Type: 99999,
				Name: "largeValueName",
			},
			expected: "objref type 99999 name largeValueName",
		},
		{
			name: "special characters",
			input: &expr.Objref{
				Type: 1,
				Name: "special!@#$%^&*()",
			},
			expected: "objref type 1 name special!@#$%^&*()",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatObjref(tt.input)
			if result != tt.expected {
				t.Errorf("FormatObjref(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
