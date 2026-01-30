package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func SerializeRt(r *expr.Rt) string {
	key := rtKeyToString(r.Key)

	return fmt.Sprintf("rt %s", key)
}

func rtKeyToString(rtKey expr.RtKey) string {
	switch rtKey {
	case expr.RtClassid:
		return "classid"
	case expr.RtNexthop4:
		return "nexthop4"
	case expr.RtNexthop6:
		return "nexthop6"
	case expr.RtTCPMSS:
		return "tcpmss"
	default:
		return "unknown"
	}
}
