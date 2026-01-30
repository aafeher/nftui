package nftexpr

import (
	"testing"

	"github.com/google/nftables/expr"
)

func TestFormatCounter(t *testing.T) {
	tests := []struct {
		name     string
		counter  *expr.Counter
		expected string
	}{
		{
			name: "standard values",
			counter: &expr.Counter{
				Bytes:   1000,
				Packets: 50,
			},
			expected: "counter bytes 1000 packets 50",
		},
		{
			name: "zero values",
			counter: &expr.Counter{
				Bytes:   0,
				Packets: 0,
			},
			expected: "counter bytes 0 packets 0",
		},
		{
			name: "large values",
			counter: &expr.Counter{
				Bytes:   9223372036854775807,
				Packets: 9223372036854775807,
			},
			expected: "counter bytes 9223372036854775807 packets 9223372036854775807",
		},
		{
			name: "only bytes non-zero",
			counter: &expr.Counter{
				Bytes:   12345,
				Packets: 0,
			},
			expected: "counter bytes 12345 packets 0",
		},
		{
			name: "only packets non-zero",
			counter: &expr.Counter{
				Bytes:   0,
				Packets: 67890,
			},
			expected: "counter bytes 0 packets 67890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatCounter(tt.counter)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}
