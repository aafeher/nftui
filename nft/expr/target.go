package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func SerializeTarget(t *expr.Target) string {
	return fmt.Sprintf("target %s", t.Name)
}
