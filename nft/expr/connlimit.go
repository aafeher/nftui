package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func SerializeConnlimit(c *expr.Connlimit) string {
	return fmt.Sprintf("ct count %d", c.Count)
}
