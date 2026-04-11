package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func SerializeConnlimit(c *expr.Connlimit) string {
	if c.Flags&expr.NFT_CONNLIMIT_F_INV == 0 {
		return fmt.Sprintf("ct count over %d", c.Count)
	}
	return fmt.Sprintf("ct count %d", c.Count)
}
