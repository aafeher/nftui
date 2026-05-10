package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func FormatImmediate(immediate *expr.Immediate) string {
	return fmt.Sprintf("immediate TBD")
}

func SerializeImmediate(imm *expr.Immediate) string {
	// Load immediate value - usually appears with other expressions
	// used together (e.g. meta mark set 1)
	if len(imm.Data) > 0 {
		return formatData(imm.Data)
	}
	return ""
}
