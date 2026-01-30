package nftexpr

import (
	"github.com/google/nftables/expr"
)

func SerializeDup(d *expr.Dup) string {
	return "dup to ADDR device DEV"
}
