package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func SerializeQueue(q *expr.Queue) string {
	result := fmt.Sprintf("queue num %d", q.Num)

	if q.Total > 1 {
		result = fmt.Sprintf("queue num %d-%d", q.Num, q.Num+q.Total-1)
	}

	if q.Flag == expr.QueueFlagBypass {
		result += " bypass"
	}

	return result
}
