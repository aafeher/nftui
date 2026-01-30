package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func SerializeVerdict(v *expr.Verdict) string {
	switch v.Kind {
	case expr.VerdictAccept:
		return "accept"
	case expr.VerdictDrop:
		return "drop"
	case expr.VerdictQueue:
		return "queue"
	case expr.VerdictContinue:
		return "continue"
	case expr.VerdictReturn:
		return "return"
	case expr.VerdictJump:
		return fmt.Sprintf("jump %s", v.Chain)
	case expr.VerdictGoto:
		return fmt.Sprintf("goto %s", v.Chain)
	case expr.VerdictBreak:
		return "break"
	default:
		return fmt.Sprintf("verdict %d", v.Kind)
	}
}
