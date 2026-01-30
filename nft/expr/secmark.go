package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func SerializeSecMark(s *expr.SecMark) string {
	return fmt.Sprintf("meta secmark set %s", s.Ctx)
}
