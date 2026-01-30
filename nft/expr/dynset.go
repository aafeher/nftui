package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func FormatDynset(dynset *expr.Dynset) string {
	return fmt.Sprintf("dynset TBD")
}

func SerializeDynset(d *expr.Dynset) string {
	op := ""
	switch d.Operation {
	//case expr.DynsetOpAdd:
	//	op = "add"
	//case expr.DynsetOpUpdate:
	//	op = "update"
	//case expr.DynsetOpDelete:
	//	op = "delete"
	default:
		op = "unknown"
	}

	return fmt.Sprintf("%s @%s", op, d.SetName)
}
