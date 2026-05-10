package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func FormatExthdr(exthdr *expr.Exthdr) string {
	return fmt.Sprintf("exthdr TBD")
}

func SerializeExthdr(e *expr.Exthdr, exprs []expr.Any, pos int) (string, int) {
	hdrType := ""
	switch e.Type {
	case 0:
		hdrType = "hbh"
	case 43:
		hdrType = "rt"
	case 44:
		hdrType = "frag"
	case 60:
		hdrType = "dst"
	case 135:
		hdrType = "mh"
	default:
		hdrType = fmt.Sprintf("exthdr-%d", e.Type)
	}

	field := fmt.Sprintf("%s %s", hdrType, "field")

	// Next Cmp?
	if pos+1 < len(exprs) {
		if cmp, ok := exprs[pos+1].(*expr.Cmp); ok {
			value := formatData(cmp.Data)
			return fmt.Sprintf("%s %s", field, serializeCmpOp(cmp, value)), 2
		}
	}

	return field, 1
}
