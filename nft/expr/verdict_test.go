package nftexpr

import (
	"testing"

	"github.com/google/nftables/expr"
)

func TestSerializeVerdict(t *testing.T) {
	tests := []struct {
		name    string
		verdict expr.Verdict
		want    string
	}{
		{"accept", expr.Verdict{Kind: expr.VerdictAccept}, "accept"},
		{"drop", expr.Verdict{Kind: expr.VerdictDrop}, "drop"},
		{"queue", expr.Verdict{Kind: expr.VerdictQueue}, "queue"},
		{"continue", expr.Verdict{Kind: expr.VerdictContinue}, "continue"},
		{"return", expr.Verdict{Kind: expr.VerdictReturn}, "return"},
		{"break", expr.Verdict{Kind: expr.VerdictBreak}, "break"},
		{"jump", expr.Verdict{Kind: expr.VerdictJump, Chain: "forward"}, "jump forward"},
		{"goto", expr.Verdict{Kind: expr.VerdictGoto, Chain: "custom_chain"}, "goto custom_chain"},
		{"unknown kind", expr.Verdict{Kind: expr.VerdictKind(99)}, "verdict 99"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SerializeVerdict(&tt.verdict)
			if got != tt.want {
				t.Errorf("SerializeVerdict() = %q, want %q", got, tt.want)
			}
		})
	}
}
