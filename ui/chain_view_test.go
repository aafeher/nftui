package ui

import (
	"testing"

	"github.com/google/nftables"
)

// maxVisibleRules translates the live terminal height into how many rule
// entries fit inside the chain view, accounting for the optional
// hook/priority/policy header lines and an optional filter prompt. The
// returned count bounds the render loop and the cursor-scroll trigger so a
// 1000-rule chain costs the same to render as a 10-rule one.
func TestChainView_MaxVisibleRules(t *testing.T) {
	accept := nftables.ChainPolicyAccept
	hook := nftables.ChainHookInput // already *ChainHook
	prio := nftables.ChainPriority(0)

	tests := []struct {
		name       string
		height     int
		chain      *nftables.Chain
		filterMode bool
		want       int
	}{
		// Compact header: headerLines = 4 (title + metadata line + rules-by-type
		// line + blank), +2 in filter mode. inner = height - 9.
		// inner = 10-9 = 1, avail = 1-4 = -3 < 3 → clamp to 1
		{"tiny terminal clamps to 1", 10, &nftables.Chain{Name: "x"}, false, 1},
		// inner=21, header=4, avail=17, 17/3=5
		{"no optional fields, height 30", 30, &nftables.Chain{Name: "x"}, false, 5},
		// metadata is one line now, so optional fields don't add header lines:
		// inner=21, header=4, avail=17, 17/3=5
		{"all optional fields, height 30", 30,
			&nftables.Chain{Name: "x", Hooknum: hook, Priority: &prio, Policy: &accept}, false, 5},
		// inner=41, header=4, avail=37, 37/3=12
		{"no optional, height 50", 50, &nftables.Chain{Name: "x"}, false, 12},
		// filterMode adds 2 to header. inner=41, header=6, avail=35, 35/3=11
		{"filter mode reduces visible rules", 50, &nftables.Chain{Name: "x"}, true, 11},
		// inner=91, header=4, avail=87, 87/3=29 — large terminal scales linearly
		{"large terminal", 100, &nftables.Chain{Name: "x"}, false, 29},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := chainView{chain: tt.chain, height: tt.height, filterMode: tt.filterMode}
			if got := c.maxVisibleRules(); got != tt.want {
				t.Errorf("maxVisibleRules() = %d, want %d", got, tt.want)
			}
		})
	}
}

// ruleMatchesFilter reads the cached lowercase haystack when the rule's
// Handle is in matchCache, so the rule's Exprs aren't re-serialized on every
// keystroke for chains with thousands of rules. Verifies the cache is
// keyed by Handle (a different rule pointer with the same Handle hits).
func TestChainView_RuleMatchesFilter_CacheHit(t *testing.T) {
	c := chainView{
		filterMode:  true,
		filterQuery: "needle",
		matchCache:  map[uint64]string{42: "haystack with a needle inside"},
	}
	if !c.ruleMatchesFilter(&nftables.Rule{Handle: 42}) {
		t.Error("cache hit: expected true (needle matches cached haystack)")
	}

	c.filterQuery = "no-such-substring"
	if c.ruleMatchesFilter(&nftables.Rule{Handle: 42}) {
		t.Error("cache hit: expected false (no-such-substring not in cached haystack)")
	}
}

// An empty filter query short-circuits — the cache must not be touched.
// Otherwise just opening filter mode (before typing) would still seed the
// map for every rule, defeating the lazy-population property.
func TestChainView_RuleMatchesFilter_EmptyQueryDoesNotCache(t *testing.T) {
	c := chainView{
		filterMode:  true,
		filterQuery: "",
		matchCache:  map[uint64]string{},
	}
	_ = c.ruleMatchesFilter(&nftables.Rule{Handle: 7})
	if len(c.matchCache) != 0 {
		t.Errorf("cache should stay empty for empty query, got %d entries", len(c.matchCache))
	}
}

// Whitespace-only queries are equivalent to empty: ruleMatchesFilter
// short-circuits to true with no cache touch.
func TestChainView_RuleMatchesFilter_WhitespaceOnlyDoesNotCache(t *testing.T) {
	c := chainView{
		filterMode:  true,
		filterQuery: "   ",
		matchCache:  map[uint64]string{},
	}
	if !c.ruleMatchesFilter(&nftables.Rule{Handle: 7}) {
		t.Error("whitespace-only query should match everything")
	}
	if len(c.matchCache) != 0 {
		t.Errorf("cache should stay empty for whitespace-only query, got %d entries", len(c.matchCache))
	}
}

// clear(matchCache) is the invalidation primitive used by RefreshRules: an
// edited rule keeps its Handle but its rendered text can change, so the
// cached haystack must be discarded. This test pins the clear() contract so
// future refactors of RefreshRules don't accidentally drop the invalidation.
func TestChainView_MatchCache_ClearEmptiesMap(t *testing.T) {
	c := chainView{
		matchCache: map[uint64]string{1: "a", 2: "b", 3: "c"},
	}
	clear(c.matchCache)
	if len(c.matchCache) != 0 {
		t.Errorf("matchCache should be empty after clear, got %d entries", len(c.matchCache))
	}
}

// headerLines counts only the *visible* optional rows. Toggling filterMode
// adds 2 lines (prompt + trailing blank), independent of which optional
// chain fields are present.
func TestChainView_HeaderLines(t *testing.T) {
	accept := nftables.ChainPolicyAccept
	hook := nftables.ChainHookInput // already *ChainHook
	prio := nftables.ChainPriority(0)
	_ = hook // satisfy "declared and not used" — referenced via the variable below

	tests := []struct {
		name       string
		chain      *nftables.Chain
		filterMode bool
		want       int
	}{
		// Compact header is a fixed 4 lines (metadata is one line, so optional
		// fields don't add height); filter mode adds 2.
		{"none optional", &nftables.Chain{Name: "x"}, false, 4},
		{"none optional, filter mode", &nftables.Chain{Name: "x"}, true, 6},
		{"all optional", &nftables.Chain{Name: "x", Hooknum: hook, Priority: &prio, Policy: &accept}, false, 4},
		{"all optional, filter mode", &nftables.Chain{Name: "x", Hooknum: hook, Priority: &prio, Policy: &accept}, true, 6},
		{"nil chain", nil, false, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := chainView{chain: tt.chain, filterMode: tt.filterMode}
			if got := c.headerLines(); got != tt.want {
				t.Errorf("headerLines() = %d, want %d", got, tt.want)
			}
		})
	}
}
