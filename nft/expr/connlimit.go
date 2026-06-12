package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

// nft CLI encoding (verified via `nft --debug=netlink`):
// "ct count over N" sets NFT_CONNLIMIT_F_INV; plain "ct count N" leaves flags 0.
func SerializeConnlimit(c *expr.Connlimit) string {
	if c.Flags&expr.NFT_CONNLIMIT_F_INV != 0 {
		return fmt.Sprintf("ct count over %d", c.Count)
	}
	return fmt.Sprintf("ct count %d", c.Count)
}
