package nft

import "github.com/google/nftables"

// findRuleByHandle returns the rule in rules with the given kernel handle, its
// index, and whether it was found. nftables rule handles are unique and are
// not reused within a table's lifetime, so a handle match is an exact identity
// check — the basis for the TOCTOU guard in DeleteRule / MoveRuleUp /
// MoveRuleDown, which re-read the chain and confirm the target handle is still
// present before mutating (audit E-4 / R3).
func findRuleByHandle(rules []*nftables.Rule, handle uint64) (*nftables.Rule, int, bool) {
	for i, r := range rules {
		if r.Handle == handle {
			return r, i, true
		}
	}
	return nil, 0, false
}
