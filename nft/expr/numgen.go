package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func SerializeNumgen(n *expr.Numgen) string {
	if n == nil {
		return "/* invalid numgen: nil */"
	}

	if n.Modulus == 0 {
		return "/* invalid numgen: modulus is 0 */"
	}

	var ngType string
	switch n.Type {
	case unix.NFT_NG_INCREMENTAL:
		ngType = "inc"
	case unix.NFT_NG_RANDOM:
		ngType = "random"
	default:
		ngType = fmt.Sprintf("unknown (%d)", n.Type)
	}
	return fmt.Sprintf("numgen %s mod %d offset %d", ngType, n.Modulus, n.Offset)
}
