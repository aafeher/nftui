package ui

import (
	"testing"

	"github.com/google/nftables/expr"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input string
		want  uint32
	}{
		{"", 0},
		{"0", 0},
		{"30s", 30},
		{"1m", 60},
		{"2m30s", 150},
		{"1h", 3600},
		{"1h30m", 5400},
		{"1d", 86400},
		{"1d2h3m4s", 93784},
		{"100", 100}, // no unit → seconds
		{"  30s  ", 30},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseDuration(tt.input)
			if got != tt.want {
				t.Errorf("parseDuration(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseComplexDuration(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantOp      expr.CmpOp
		wantVal1    uint32
		wantVal2    uint32
		wantIsRange bool
		wantIsSet   bool
		wantElems   []uint32
	}{
		{
			name:     "simple value",
			input:    "30s",
			wantOp:   expr.CmpOpEq,
			wantVal1: 30,
		},
		{
			name:     "no unit",
			input:    "60",
			wantOp:   expr.CmpOpEq,
			wantVal1: 60,
		},
		{
			name:     "neq operator",
			input:    "!= 30s",
			wantOp:   expr.CmpOpNeq,
			wantVal1: 30,
		},
		{
			name:     "neq no space",
			input:    "!=1m",
			wantOp:   expr.CmpOpNeq,
			wantVal1: 60,
		},
		{
			name:     "lte operator",
			input:    "<= 1h",
			wantOp:   expr.CmpOpLte,
			wantVal1: 3600,
		},
		{
			name:     "gte operator",
			input:    ">= 2m",
			wantOp:   expr.CmpOpGte,
			wantVal1: 120,
		},
		{
			name:     "lt operator",
			input:    "< 10s",
			wantOp:   expr.CmpOpLt,
			wantVal1: 10,
		},
		{
			name:     "gt operator",
			input:    "> 5m",
			wantOp:   expr.CmpOpGt,
			wantVal1: 300,
		},
		{
			name:        "range",
			input:       "30s-2m",
			wantOp:      expr.CmpOpEq,
			wantIsRange: true,
			wantVal1:    30,
			wantVal2:    120,
		},
		{
			name:      "set single",
			input:     "{30s}",
			wantOp:    expr.CmpOpEq,
			wantIsSet: true,
			wantElems: []uint32{30},
		},
		{
			name:      "set multiple",
			input:     "{30s,1m,2m}",
			wantOp:    expr.CmpOpEq,
			wantIsSet: true,
			wantElems: []uint32{30, 60, 120},
		},
		{
			name:     "empty",
			input:    "",
			wantOp:   expr.CmpOpEq,
			wantVal1: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op, val1, val2, elems, isRange, isSet := parseComplexDuration(tt.input)

			if op != tt.wantOp {
				t.Errorf("op = %v, want %v", op, tt.wantOp)
			}
			if !isRange && !isSet && val1 != tt.wantVal1 {
				t.Errorf("val1 = %d, want %d", val1, tt.wantVal1)
			}
			if isRange {
				if val1 != tt.wantVal1 {
					t.Errorf("range val1 = %d, want %d", val1, tt.wantVal1)
				}
				if val2 != tt.wantVal2 {
					t.Errorf("range val2 = %d, want %d", val2, tt.wantVal2)
				}
			}
			if isRange != tt.wantIsRange {
				t.Errorf("isRange = %v, want %v", isRange, tt.wantIsRange)
			}
			if isSet != tt.wantIsSet {
				t.Errorf("isSet = %v, want %v", isSet, tt.wantIsSet)
			}
			if isSet && len(elems) != len(tt.wantElems) {
				t.Errorf("elems len = %d, want %d", len(elems), len(tt.wantElems))
			} else if isSet {
				for i, e := range elems {
					if e != tt.wantElems[i] {
						t.Errorf("elems[%d] = %d, want %d", i, e, tt.wantElems[i])
					}
				}
			}
		})
	}
}

func TestEncodeCommentToUserData(t *testing.T) {
	tests := []struct {
		name    string
		comment string
		wantNil bool
		wantLen int
	}{
		{"empty returns nil", "", true, 0},
		{"hello", "hello", false, 8},   // 2 + 5 + 1(null)
		{"single char", "x", false, 4}, // 2 + 1 + 1(null)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encodeCommentToUserData(tt.comment)
			if tt.wantNil {
				if got != nil {
					t.Errorf("encodeCommentToUserData(%q) = %v, want nil", tt.comment, got)
				}
				return
			}
			if len(got) != tt.wantLen {
				t.Errorf("encodeCommentToUserData(%q) len = %d, want %d", tt.comment, len(got), tt.wantLen)
			}
			// TLV type must be 0
			if got[0] != 0 {
				t.Errorf("TLV type = %d, want 0", got[0])
			}
			// Length field must equal comment length + 1 (null terminator)
			if int(got[1]) != len(tt.comment)+1 {
				t.Errorf("TLV length = %d, want %d", got[1], len(tt.comment)+1)
			}
			// Last byte must be null terminator
			if got[len(got)-1] != 0 {
				t.Errorf("null terminator missing, last byte = %d", got[len(got)-1])
			}
		})
	}
}

func TestEncodeDecodeCommentRoundtrip(t *testing.T) {
	comments := []string{"hello", "test comment", "a", "nftables rule #1"}

	for _, comment := range comments {
		t.Run(comment, func(t *testing.T) {
			userData := encodeCommentToUserData(comment)
			// Verify decode via rule package's ExtractComment logic manually:
			// TLV type=0, length, value
			if len(userData) < 2 {
				t.Fatal("encoded data too short")
			}
			if userData[0] != 0 {
				t.Errorf("type = %d, want 0", userData[0])
			}
			tlvLen := int(userData[1])
			if 2+tlvLen > len(userData) {
				t.Fatal("TLV length exceeds data")
			}
			value := userData[2 : 2+tlvLen]
			// Strip null terminator
			result := ""
			for i, b := range value {
				if b == 0 {
					result = string(value[:i])
					break
				}
			}
			if result == "" {
				result = string(value)
			}
			if result != comment {
				t.Errorf("roundtrip: got %q, want %q", result, comment)
			}
		})
	}
}
