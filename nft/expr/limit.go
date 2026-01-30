package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

type LimitTime string
type LimitType string

const (
	LimitTimeSecond LimitTime = "second"
	LimitTimeMinute LimitTime = "minute"
	LimitTimeHour   LimitTime = "hour"
	LimitTimeDay    LimitTime = "day"
	LimitTimeWeek   LimitTime = "week"

	LimitTypePackets LimitType = "packets"
	LimitTypeBytes   LimitType = "bytes"
)

// LimitTimeStrings defines a list of time units used for rate limiting, including "second", "minute", "hour", "day", and "week".
var LimitTimeStrings = []string{
	string(LimitTimeSecond),
	string(LimitTimeMinute),
	string(LimitTimeHour),
	string(LimitTimeDay),
	string(LimitTimeWeek),
}

// LimitTypeStrings defines valid limit types, including "packets" and "bytes", for configuring rate limiting options.
var LimitTypeStrings = []string{
	string(LimitTypePackets),
	string(LimitTypeBytes),
}

// LimitUnitToString converts a LimitTime value into its corresponding string representation.
func LimitUnitToString(limitUnit expr.LimitTime) string {
	switch limitUnit {
	case expr.LimitTimeSecond:
		return string(LimitTimeSecond)
	case expr.LimitTimeMinute:
		return string(LimitTimeMinute)
	case expr.LimitTimeHour:
		return string(LimitTimeHour)
	case expr.LimitTimeDay:
		return string(LimitTimeDay)
	case expr.LimitTimeWeek:
		return string(LimitTimeWeek)
	}
	return string(LimitTimeSecond)
}

// StringToLimitUnit converts a string representation of a time limit unit to its corresponding expr.LimitTime value.
func StringToLimitUnit(limitUnitString string) expr.LimitTime {
	switch limitUnitString {
	case string(LimitTimeSecond):
		return expr.LimitTimeSecond
	case string(LimitTimeMinute):
		return expr.LimitTimeMinute
	case string(LimitTimeHour):
		return expr.LimitTimeHour
	case string(LimitTimeDay):
		return expr.LimitTimeDay
	case string(LimitTimeWeek):
		return expr.LimitTimeWeek
	}
	return expr.LimitTimeSecond
}

// LimitTypeToString converts a LimitType value to its corresponding string representation.
func LimitTypeToString(limitType expr.LimitType) string {
	switch limitType {
	case expr.LimitTypePkts:
		return string(LimitTypePackets)
	case expr.LimitTypePktBytes:
		return string(LimitTypeBytes)
	}
	return string(LimitTypePackets)
}

// StringToLimitType converts a string representation of a limit type to its corresponding expr.LimitType value.
// Returns expr.LimitTypePkts by default if the input does not match known limit types.
func StringToLimitType(limitType string) expr.LimitType {
	switch limitType {
	case string(LimitTypePackets):
		return expr.LimitTypePkts
	case string(LimitTypeBytes):
		return expr.LimitTypePktBytes
	}
	return expr.LimitTypePkts
}

// SerializeLimit serializes an expr.Limit structure into a string representation for rule configuration.
func SerializeLimit(l *expr.Limit) string {
	result := fmt.Sprintf("limit rate %d/%s", l.Rate, LimitUnitToString(l.Unit))

	if l.Burst > 0 {
		result += fmt.Sprintf(" burst %d %s", l.Burst, LimitTypeToString(l.Type))
	}

	return result
}
