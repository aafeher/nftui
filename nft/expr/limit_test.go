package nftexpr

import (
	"testing"

	"github.com/google/nftables/expr"
)

func TestLimitUnitToString(t *testing.T) {
	tests := []struct {
		unit expr.LimitTime
		want string
	}{
		{expr.LimitTimeSecond, "second"},
		{expr.LimitTimeMinute, "minute"},
		{expr.LimitTimeHour, "hour"},
		{expr.LimitTimeDay, "day"},
		{expr.LimitTimeWeek, "week"},
		{expr.LimitTime(99), "second"}, // unknown defaults to second
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := LimitUnitToString(tt.unit)
			if got != tt.want {
				t.Errorf("LimitUnitToString(%d) = %q, want %q", tt.unit, got, tt.want)
			}
		})
	}
}

func TestStringToLimitUnit(t *testing.T) {
	tests := []struct {
		input string
		want  expr.LimitTime
	}{
		{"second", expr.LimitTimeSecond},
		{"minute", expr.LimitTimeMinute},
		{"hour", expr.LimitTimeHour},
		{"day", expr.LimitTimeDay},
		{"week", expr.LimitTimeWeek},
		{"unknown", expr.LimitTimeSecond}, // unknown defaults to second
		{"", expr.LimitTimeSecond},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := StringToLimitUnit(tt.input)
			if got != tt.want {
				t.Errorf("StringToLimitUnit(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestLimitTypeToString(t *testing.T) {
	tests := []struct {
		limitType expr.LimitType
		want      string
	}{
		{expr.LimitTypePkts, "packets"},
		{expr.LimitTypePktBytes, "bytes"},
		{expr.LimitType(99), "packets"}, // unknown defaults to packets
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := LimitTypeToString(tt.limitType)
			if got != tt.want {
				t.Errorf("LimitTypeToString(%d) = %q, want %q", tt.limitType, got, tt.want)
			}
		})
	}
}

func TestStringToLimitType(t *testing.T) {
	tests := []struct {
		input string
		want  expr.LimitType
	}{
		{"packets", expr.LimitTypePkts},
		{"bytes", expr.LimitTypePktBytes},
		{"unknown", expr.LimitTypePkts}, // unknown defaults to packets
		{"", expr.LimitTypePkts},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := StringToLimitType(tt.input)
			if got != tt.want {
				t.Errorf("StringToLimitType(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestSerializeLimit(t *testing.T) {
	tests := []struct {
		name  string
		limit expr.Limit
		want  string
	}{
		{
			name:  "rate per second no burst",
			limit: expr.Limit{Rate: 100, Unit: expr.LimitTimeSecond},
			want:  "limit rate 100/second",
		},
		{
			name:  "rate per minute no burst",
			limit: expr.Limit{Rate: 10, Unit: expr.LimitTimeMinute},
			want:  "limit rate 10/minute",
		},
		{
			name:  "rate with burst packets",
			limit: expr.Limit{Rate: 50, Unit: expr.LimitTimeSecond, Burst: 200, Type: expr.LimitTypePkts},
			want:  "limit rate 50/second burst 200 packets",
		},
		{
			name:  "rate with burst bytes",
			limit: expr.Limit{Rate: 1000, Unit: expr.LimitTimeHour, Burst: 5000, Type: expr.LimitTypePktBytes},
			want:  "limit rate 1000/hour burst 5000 bytes",
		},
		{
			name:  "zero burst not shown",
			limit: expr.Limit{Rate: 5, Unit: expr.LimitTimeDay, Burst: 0},
			want:  "limit rate 5/day",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SerializeLimit(&tt.limit)
			if got != tt.want {
				t.Errorf("SerializeLimit() = %q, want %q", got, tt.want)
			}
		})
	}
}
