package nftexpr

import (
	"fmt"
	"strings"

	"github.com/google/nftables/expr"
)

func FormatRange(r *expr.Range) string {
	parts := []string{"range"}

	// Op CmpOp
	parts = append(parts, fmt.Sprintf("op %s", CmpOpToString(r.Op)))

	// Register uint32
	parts = append(parts, fmt.Sprintf("register %d", r.Register))

	// FromData []byte
	parts = append(parts, fmt.Sprintf("fromdata %d", r.FromData))

	// ToData []byte
	parts = append(parts, fmt.Sprintf("todata %d", r.ToData))

	return strings.Join(parts, " ")
}

func SerializeRange(r *expr.Range, pending any) string {
	from := formatData(r.FromData)
	to := formatData(r.ToData)

	op := ""
	if r.Op == expr.CmpOpEq {
		op = ""
	} else if r.Op == expr.CmpOpNeq {
		op = "!= "
	}

	return fmt.Sprintf("%s%s-%s", op, from, to)
}
