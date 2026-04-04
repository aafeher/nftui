// range_test.go
package nftexpr

import (
	"testing"

	"github.com/google/nftables/expr"
)

func TestFormatRange(t *testing.T) {
	tests := []struct {
		name string
		r    *expr.Range
		want string
	}{
		{
			name: "Normal range operation",
			r: &expr.Range{
				Op:       expr.CmpOpEq,
				Register: 1,
				FromData: []byte{0x01, 0x02},
				ToData:   []byte{0x03, 0x04},
			},
			want: "range op == register 1 fromdata [1 2] todata [3 4]",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FormatRange(tc.r)
			if got != tc.want {
				t.Errorf("FormatRange() = %q, want %q", got, tc.want)
			}
		})
	}

}

func TestSerializeRange(t *testing.T) {
	tests := []struct {
		name string
		r    *expr.Range
		want string
	}{
		{
			name: "eq range ports",
			r: &expr.Range{
				Op:       expr.CmpOpEq,
				Register: 1,
				FromData: []byte{0, 80},
				ToData:   []byte{0, 90},
			},
			want: "80-90",
		},
		{
			name: "neq range",
			r: &expr.Range{
				Op:       expr.CmpOpNeq,
				Register: 1,
				FromData: []byte{0, 80},
				ToData:   []byte{0, 90},
			},
			want: "!= 80-90",
		},
		{
			name: "eq range ipv4",
			r: &expr.Range{
				Op:       expr.CmpOpEq,
				Register: 1,
				FromData: []byte{10, 0, 0, 1},
				ToData:   []byte{10, 0, 0, 10},
			},
			want: "10.0.0.1-10.0.0.10",
		},
		{
			name: "eq range single byte",
			r: &expr.Range{
				Op:       expr.CmpOpEq,
				Register: 1,
				FromData: []byte{5},
				ToData:   []byte{10},
			},
			want: "5-10",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SerializeRange(tc.r, nil)
			if got != tc.want {
				t.Errorf("SerializeRange() = %q, want %q", got, tc.want)
			}
		})
	}
}
