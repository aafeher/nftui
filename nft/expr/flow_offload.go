package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func SerializeFlowOffload(f *expr.FlowOffload) string {
	return fmt.Sprintf("flow add @%s", f.Name)
}
