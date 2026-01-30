package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func SerializeSynProxy(s *expr.SynProxy) string {
	result := "synproxy"

	if s.Mss > 0 {
		result += fmt.Sprintf(" mss %d", s.Mss)
	}
	if s.Wscale > 0 {
		result += fmt.Sprintf(" wscale %d", s.Wscale)
	}

	return result
}
