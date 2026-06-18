package nft

import (
	"testing"

	"github.com/google/nftables"
)

// findRuleByHandle is the pure core of the TOCTOU guard added to DeleteRule /
// MoveRuleUp / MoveRuleDown (audit E-4 / R3): before a mutation those re-read
// the chain and match the target by its kernel handle. Handles are unique and
// never reused within a table's lifetime, so a match is an exact identity
// check and a miss means the rule is genuinely gone.

func ruleWithHandle(h uint64) *nftables.Rule {
	return &nftables.Rule{Handle: h}
}

func TestFindRuleByHandle_Found(t *testing.T) {
	rules := []*nftables.Rule{ruleWithHandle(10), ruleWithHandle(20), ruleWithHandle(30)}

	r, idx, ok := findRuleByHandle(rules, 20)
	if !ok {
		t.Fatal("handle 20 not found")
	}
	if idx != 1 || r.Handle != 20 {
		t.Errorf("got idx=%d handle=%d, want idx=1 handle=20", idx, r.Handle)
	}

	// Boundaries.
	if _, idx, ok := findRuleByHandle(rules, 10); !ok || idx != 0 {
		t.Errorf("first element: idx=%d ok=%v, want 0/true", idx, ok)
	}
	if _, idx, ok := findRuleByHandle(rules, 30); !ok || idx != 2 {
		t.Errorf("last element: idx=%d ok=%v, want 2/true", idx, ok)
	}
}

func TestFindRuleByHandle_NotFound(t *testing.T) {
	rules := []*nftables.Rule{ruleWithHandle(10), ruleWithHandle(20)}
	if r, idx, ok := findRuleByHandle(rules, 99); ok || r != nil || idx != 0 {
		t.Errorf("missing handle: got r=%v idx=%d ok=%v, want nil/0/false", r, idx, ok)
	}
}

func TestFindRuleByHandle_Empty(t *testing.T) {
	if _, _, ok := findRuleByHandle(nil, 1); ok {
		t.Error("nil slice must not match")
	}
	if _, _, ok := findRuleByHandle([]*nftables.Rule{}, 1); ok {
		t.Error("empty slice must not match")
	}
}
