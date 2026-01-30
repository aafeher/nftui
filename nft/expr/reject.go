package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func SerializeReject(r *expr.Reject) string {
	result := "reject"

	switch r.Type {
	case 0: // ICMP unreachable
		result += " with icmp type"
		switch r.Code {
		case 0:
			result += " net-unreachable"
		case 1:
			result += " host-unreachable"
		case 2:
			result += " prot-unreachable"
		case 3:
			result += " port-unreachable"
		case 9:
			result += " net-prohibited"
		case 10:
			result += " host-prohibited"
		case 13:
			result += " admin-prohibited"
		default:
			result += fmt.Sprintf(" %d", r.Code)
		}
	case 1: // TCP reset
		result += " with tcp reset"
	case 2: // ICMPv6
		result += " with icmpv6 type"
	}

	return result
}
