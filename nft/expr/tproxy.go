package nftexpr

import (
	"github.com/google/nftables/expr"
)

func SerializeTproxy(t *expr.TProxy) string {
	return "tproxy to ADDRESS:PORT"
}
