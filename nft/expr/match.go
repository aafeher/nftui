package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func FormatMatch(match *expr.Match) string {
	return fmt.Sprintf("match TBD")
}

func SerializeMatch(m *expr.Match) string {
	return fmt.Sprintf("match %s", m.Name)
}
