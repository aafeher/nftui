package nftexpr

import (
	"fmt"
	"strings"

	"github.com/google/nftables/expr"
)

func FormatObjref(objref *expr.Objref) string {
	parts := []string{"objref"}

	// Type int
	parts = append(parts, fmt.Sprintf("type %d", objref.Type))

	// Name string
	parts = append(parts, fmt.Sprintf("name %s", objref.Name))

	return strings.Join(parts, " ")
}

func SerializeObjref(o *expr.Objref) string {
	// Named object reference
	switch o.Type {
	case 1: // Counter
		return fmt.Sprintf("counter name %s", o.Name)
	case 2: // Quota
		return fmt.Sprintf("quota name %s", o.Name)
	case 5: // Limit
		return fmt.Sprintf("limit name %s", o.Name)
	default:
		return fmt.Sprintf("objref %s", o.Name)
	}
}
