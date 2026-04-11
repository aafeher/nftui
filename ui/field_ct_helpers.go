package ui

import (
	"github.com/google/nftables/expr"
	nftexpr "nftui/nft/expr"
)

// ctDirectionToExpr converts a CtDirection to the Direction/OptDirection pair
// used in expr.Ct. Direction=255, OptDirection=false means "no direction filter".
func ctDirectionToExpr(dir nftexpr.CtDirection) (uint32, bool) {
	switch dir {
	case nftexpr.CtDirectionOriginal:
		return 0, true
	case nftexpr.CtDirectionReply:
		return 1, true
	default:
		return 255, false
	}
}

// ctInsertIndex returns the position in rule.Exprs after the last Ct+Cmp pair,
// suitable for inserting a new CT expression before non-CT expressions (Counter, Verdict).
func ctInsertIndex(exprs []expr.Any) int {
	idx := 0
	for i, re := range exprs {
		if _, ok := re.(*expr.Ct); ok {
			idx = i + 2
		}
	}
	return idx
}
