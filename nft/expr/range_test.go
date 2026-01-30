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

	tests = append(tests, []struct {
		name string
		r    *expr.Range
		want string
	}{
		{
			name: "Invalid CmpOp",
			r: &expr.Range{
				Op:       99, // Assuming 99 is not a valid CmpOp
				Register: 2,
				FromData: []byte{0x01},
				ToData:   []byte{0x05, 0x06},
			},
			want: "range op unknown register 2 fromdata [1] todata [5 6]",
		},
		{
			name: "Nil FromData and ToData",
			r: &expr.Range{
				Op:       expr.CmpOpNeq,
				Register: 1,
				FromData: nil,
				ToData:   nil,
			},
			want: "range op neq register 1 fromdata [] todata []",
		},
		{
			name: "Register 0",
			r: &expr.Range{
				Op:       expr.CmpOpGt,
				Register: 0,
				FromData: []byte{0x00},
				ToData:   []byte{0x7F},
			},
			want: "range op gt register 0 fromdata [0] todata [127]",
		},
		{
			name: "Empty FromData and ToData",
			r: &expr.Range{
				Op:       expr.CmpOpLt,
				Register: 3,
				FromData: []byte{},
				ToData:   []byte{},
			},
			want: "range op lt register 3 fromdata [] todata []",
		},
	}...)
}
