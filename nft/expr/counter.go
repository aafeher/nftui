package nftexpr

import (
	"fmt"
	"strings"

	"github.com/google/nftables/expr"
)

func FormatCounter(c *expr.Counter) string {
	parts := []string{"counter"}

	// Bytes uint64
	parts = append(parts, fmt.Sprintf("bytes %d", c.Bytes))

	// Packets uint64
	parts = append(parts, fmt.Sprintf("packets %d", c.Packets))

	return strings.Join(parts, " ")
}
