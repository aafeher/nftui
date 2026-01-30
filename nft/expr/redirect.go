package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func FormatRedir(redir *expr.Redir) string {
	return fmt.Sprintf("redirect TBD")
}

func SerializeRedirect(r *expr.Redir) string {
	result := "redirect"

	if r.RegisterProtoMin > 0 {
		result += " to :PORT"
	}

	if r.Flags != 0 {
		if r.Flags&1 != 0 {
			result += " random"
		}
		if r.Flags&2 != 0 {
			result += " fully-random"
		}
	}

	return result
}
