package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func FormatImmediate(immediate *expr.Immediate) string {
	return fmt.Sprintf("immediate TBD")
}

func SerializeImmediate(imm *expr.Immediate) string {
	// Immediate érték betöltése - általában más expression-ökkel együtt
	// használva jelenik meg (pl. meta mark set 1)
	if len(imm.Data) > 0 {
		return formatData(imm.Data)
	}
	return ""
}
