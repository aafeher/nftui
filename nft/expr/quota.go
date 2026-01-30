package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func FormatQuota(quota *expr.Quota) string {
	return fmt.Sprintf("quota TBD")
}

func SerializeQuota(q *expr.Quota) string {
	unit := "bytes"
	bytes := q.Bytes

	if bytes >= 1024*1024*1024 {
		return fmt.Sprintf("quota %d gbytes", bytes/(1024*1024*1024))
	} else if bytes >= 1024*1024 {
		return fmt.Sprintf("quota %d mbytes", bytes/(1024*1024))
	} else if bytes >= 1024 {
		return fmt.Sprintf("quota %d kbytes", bytes/1024)
	}

	consumed := ""
	if q.Consumed > 0 {
		consumed = fmt.Sprintf(" used %d", q.Consumed)
	}

	return fmt.Sprintf("quota %d %s%s", bytes, unit, consumed)
}
