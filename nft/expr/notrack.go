package nftexpr

import (
	"github.com/google/nftables/expr"
)

func SerializeNotrack(n *expr.Notrack) string {
	return "notrack"
}
