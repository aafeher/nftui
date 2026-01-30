package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func SerializeHash(h *expr.Hash) string {
	return fmt.Sprintf("jhash mod %d offset %d", h.Modulus, h.Offset)
}
