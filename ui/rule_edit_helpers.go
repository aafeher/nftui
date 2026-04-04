package ui

import (
	"strings"

	"github.com/google/nftables/expr"
)

// encodeCommentToUserData encodes a comment string into UserData TLV format.
// TLV format: [type (1 byte)][length (1 byte)][value (length bytes)]
// The comment type is UDATA_TYPE_COMMENT = 0
func encodeCommentToUserData(comment string) []byte {
	if comment == "" {
		return nil
	}

	// With null terminator
	commentBytes := []byte(comment)
	// TLV structure: type(1) + length(1) + value
	userData := make([]byte, 2+len(commentBytes)+1)
	userData[0] = 0                           // UDATA_TYPE_COMMENT
	userData[1] = byte(len(commentBytes) + 1) // length (with null terminator)
	copy(userData[2:], commentBytes)
	userData[len(userData)-1] = 0 // null terminator

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
