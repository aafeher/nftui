package ui

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/nftables"
)

// namedObjectOpErrMsg must surface on the tree's yellow status line, not the
// global red m.err tablesBox replacement — one channel per action result.
func TestNamedObjectOpErr_RoutesToTreeStatus(t *testing.T) {
	m := MainWindow{} // zero value — the handler under test touches no netlink state
	wantErr := errors.New("reset counter c1: operation not permitted")

	updated, cmd := m.Update(namedObjectOpErrMsg{err: wantErr})
	mw, ok := updated.(MainWindow)
	if !ok {
		t.Fatalf("Update returned %T, want MainWindow", updated)
	}

	if mw.err != nil {
		t.Errorf("m.err = %v, want nil (error should not hit the red tablesBox)", mw.err)
	}
	if mw.tableTree.statusMsg != wantErr.Error() {
		t.Errorf("tableTree.statusMsg = %q, want %q", mw.tableTree.statusMsg, wantErr.Error())
	}
	// The error must also auto-fade like any tree hint, so the handler has
	// to route through setStatus and return its fade timer — not return nil.
	if cmd == nil {
		t.Error("error path must return a fade-timer cmd (setStatus), got nil")
	}
}

// setStatus records the hint, bumps the generation, and returns a fade timer.
func TestTableTree_SetStatus_BumpsGenAndReturnsCmd(t *testing.T) {
	var tm tableTreeModel
	cmd := tm.setStatus("hint one")
	if tm.statusMsg != "hint one" {
		t.Errorf("statusMsg = %q, want 'hint one'", tm.statusMsg)
	}
	if tm.statusGen != 1 {
		t.Errorf("statusGen = %d, want 1", tm.statusGen)
	}
	if cmd == nil {
		t.Error("setStatus must return a fade-timer cmd")
	}
	tm.setStatus("hint two")
	if tm.statusGen != 2 {
		t.Errorf("statusGen = %d after second set, want 2", tm.statusGen)
	}
}

// Pressing R on a non-resettable row (here a table root) must record the
// no-op hint on the returned model and return a fade-timer cmd. Guards the
// setStatus call inside tableTreeModel.Update against return-value ordering.
func TestTableTree_PressR_NonResettable_SetsStatus(t *testing.T) {
	tm := tableTreeModel{
		nodes: []*tableNode{
			{Table: nftables.Table{Name: "t", Family: nftables.TableFamilyINet}},
		},
	}
	updated, cmd := tm.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("R")})
	ttm := updated.(tableTreeModel)
	if ttm.statusMsg != "no resettable counter/quota under cursor" {
		t.Errorf("statusMsg = %q, want the no-op hint", ttm.statusMsg)
	}
	if ttm.statusGen == 0 {
		t.Error("statusGen should have been bumped on the returned model")
	}
	if cmd == nil {
		t.Error("expected a fade-timer cmd")
	}
}

// A stale fade timer (gen from a message that was already replaced) must not
// clear the current hint; only the matching generation clears it.
func TestStatusFade_OnlyMatchingGenClears(t *testing.T) {
	var tm tableTreeModel
	tm.setStatus("first")
	tm.setStatus("second") // statusGen now 2, statusMsg "second"
	m := MainWindow{tableTree: tm}

	updated, _ := m.Update(statusFadeMsg{gen: 1}) // stale
	mw := updated.(MainWindow)
	if mw.tableTree.statusMsg != "second" {
		t.Errorf("stale fade cleared current hint: %q", mw.tableTree.statusMsg)
	}

	updated, _ = mw.Update(statusFadeMsg{gen: 2}) // current
	mw = updated.(MainWindow)
	if mw.tableTree.statusMsg != "" {
		t.Errorf("matching fade did not clear hint: %q", mw.tableTree.statusMsg)
	}
}

// A netlink permission error must render actionable CAP_NET_ADMIN advice,
// not the raw syscall text; other errors fall back to the generic line.
func TestLoadErrorView(t *testing.T) {
	permErr := fmt.Errorf("list tables: %w", syscall.EPERM)
	got := loadErrorView(permErr)
	for _, want := range []string{"Permission denied", "CAP_NET_ADMIN", "sudo", "setcap cap_net_admin+ep"} {
		if !strings.Contains(got, want) {
			t.Errorf("permission advice missing %q\ngot:\n%s", want, got)
		}
	}
	if strings.Contains(got, "list tables") {
		t.Error("raw syscall text should be replaced, not shown")
	}

	other := loadErrorView(errors.New("malformed object"))
	if !strings.Contains(other, "Error: malformed object") {
		t.Errorf("generic error not rendered verbatim, got:\n%s", other)
	}
	if strings.Contains(other, "CAP_NET_ADMIN") {
		t.Error("non-permission error must not show the capability advice")
	}
}

// searchTree builds a small two-table tree. Flattened (when expanded):
// 0:filter 1:input 2:output 3:nat 4:prerouting
func searchTree() tableTreeModel {
	return tableTreeModel{
		nodes: []*tableNode{
			{Table: nftables.Table{Name: "filter", Family: nftables.TableFamilyINet},
				Chains: []*chainNode{
					{Chain: nftables.Chain{Name: "input"}},
					{Chain: nftables.Chain{Name: "output"}},
				}},
			{Table: nftables.Table{Name: "nat", Family: nftables.TableFamilyIPv4},
				Chains: []*chainNode{
					{Chain: nftables.Chain{Name: "prerouting"}},
				}},
		},
	}
}

func typeRunes(tm tableTreeModel, s string) tableTreeModel {
	for _, r := range s {
		got, _ := tm.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		tm = got.(tableTreeModel)
	}
	return tm
}

// "/" enters search mode, makes the tree modal, and expands every table so
// rows inside collapsed tables become searchable.
func TestTreeSearch_SlashEntersModeAndExpands(t *testing.T) {
	got, _ := searchTree().Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/")})
	tm := got.(tableTreeModel)
	if !tm.searchMode || !tm.IsModal() {
		t.Fatalf("searchMode=%v IsModal=%v, want both true", tm.searchMode, tm.IsModal())
	}
	for _, n := range tm.nodes {
		if !n.Expanded {
			t.Errorf("table %q not expanded on search entry", n.Table.Name)
		}
	}
}

// Typing filters incrementally and parks the cursor on the first match;
// Enter cycles forward (wrapping), Up steps back.
func TestTreeSearch_TypeAndCycle(t *testing.T) {
	got, _ := searchTree().Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/")})
	tm := got.(tableTreeModel)
	tm = typeRunes(tm, "out") // matches output(2), prerouting(4)

	if len(tm.searchMatches) != 2 {
		t.Fatalf("matches = %v, want 2 (output, prerouting)", tm.searchMatches)
	}
	if tm.cursor != 2 {
		t.Errorf("cursor = %d, want 2 (first match: output)", tm.cursor)
	}

	got, _ = tm.Update(tea.KeyMsg{Type: tea.KeyEnter})
	tm = got.(tableTreeModel)
	if tm.cursor != 4 {
		t.Errorf("after Enter cursor = %d, want 4 (prerouting)", tm.cursor)
	}

	got, _ = tm.Update(tea.KeyMsg{Type: tea.KeyEnter})
	tm = got.(tableTreeModel)
	if tm.cursor != 2 {
		t.Errorf("after wrap cursor = %d, want 2 (back to output)", tm.cursor)
	}

	got, _ = tm.Update(tea.KeyMsg{Type: tea.KeyUp})
	tm = got.(tableTreeModel)
	if tm.cursor != 4 {
		t.Errorf("after Up cursor = %d, want 4 (prev wraps to prerouting)", tm.cursor)
	}
}

// Esc leaves search mode and clears the query.
func TestTreeSearch_EscExits(t *testing.T) {
	got, _ := searchTree().Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/")})
	tm := typeRunes(got.(tableTreeModel), "in")
	got, _ = tm.Update(tea.KeyMsg{Type: tea.KeyEsc})
	tm = got.(tableTreeModel)
	if tm.searchMode || tm.searchQuery != "" || tm.IsModal() {
		t.Errorf("after Esc: searchMode=%v query=%q IsModal=%v, want cleared", tm.searchMode, tm.searchQuery, tm.IsModal())
	}
}

// chainViewWithComments builds a minimal chainView with rules that carry the
// given comments in UserData (TLV). RuleToHumanReadable hits netlink and
// returns "Error getting sets:" in tests — fine as long as the queries we
// use don't overlap that text.
func chainViewWithComments(comments ...string) chainView {
	tbl := &nftables.Table{Name: "filter", Family: nftables.TableFamilyINet}
	chn := &nftables.Chain{Name: "input"}
	var rules []*nftables.Rule
	for _, c := range comments {
		rules = append(rules, &nftables.Rule{
			Table:    tbl,
			Chain:    chn,
			UserData: encodeCommentToUserData(c),
		})
	}
	return chainView{
		rules: rules,
		table: &tableNode{Table: *tbl},
		chain: chn,
		// Only Filter is exercised by the tests; other bindings stay zero-value.
		keys: chainViewKeyMap{Filter: key.NewBinding(key.WithKeys("/"))},
	}
}

func typeIntoChainFilter(cv chainView, s string) chainView {
	for _, r := range s {
		cv, _ = cv.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	return cv
}

func TestChainView_SlashEntersFilter(t *testing.T) {
	cv := chainViewWithComments("a", "b")
	cv, _ = cv.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/")})
	if !cv.filterMode || !cv.IsModal() {
		t.Errorf("filterMode=%v IsModal=%v, want both true", cv.filterMode, cv.IsModal())
	}
	if cv.cursor != 0 || cv.scrollOffset != 0 {
		t.Errorf("cursor/scrollOffset = %d/%d, want 0/0 on filter entry", cv.cursor, cv.scrollOffset)
	}
}

func TestChainView_FilterNarrowsByComment(t *testing.T) {
	cv := chainViewWithComments("allow ssh", "block telnet", "allow https")
	cv, _ = cv.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/")})

	cv = typeIntoChainFilter(cv, "allow")
	if got := len(cv.activeRules()); got != 2 {
		t.Errorf("'allow' should match 2 rules, got %d", got)
	}

	// Replace query with 'ssh' (backspace 5 chars off, then type).
	for i := 0; i < 5; i++ {
		cv, _ = cv.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	}
	cv = typeIntoChainFilter(cv, "ssh")
	if got := len(cv.activeRules()); got != 1 {
		t.Errorf("'ssh' should match 1 rule, got %d", got)
	}
}

func TestChainView_EscClearsFilter(t *testing.T) {
	cv := chainViewWithComments("alpha", "beta", "gamma")
	cv, _ = cv.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/")})
	cv = typeIntoChainFilter(cv, "alp")
	cv, _ = cv.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cv.filterMode || cv.filterQuery != "" {
		t.Errorf("after Esc: filterMode=%v query=%q, want cleared", cv.filterMode, cv.filterQuery)
	}
	if got := len(cv.activeRules()); got != 3 {
		t.Errorf("full list not restored after Esc, got %d rules", got)
	}
}

func TestChainView_NoMatchEmptyActiveRules(t *testing.T) {
	cv := chainViewWithComments("alpha", "beta")
	cv, _ = cv.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/")})
	cv = typeIntoChainFilter(cv, "xyzqq")
	if got := len(cv.activeRules()); got != 0 {
		t.Errorf("no-match query should yield 0 rules, got %d", got)
	}
}

// In read-only mode, the tree's string-match write handlers (d, e, c, s, R)
// no-op without opening any modal or dispatching any cmd. These keys bypass
// key.Matches (the tree handles them via msg.String() switch), so the
// MainWindow keymap's SetEnabled doesn't help — the in-tree guard is what
// actually blocks the mutation.
func TestTreeReadOnly_BlocksWriteKeys(t *testing.T) {
	tm := tableTreeModel{
		readOnly: true,
		nodes: []*tableNode{
			{Table: nftables.Table{Name: "t", Family: nftables.TableFamilyINet}},
		},
	}
	for _, k := range []string{"d", "e", "c", "s", "R"} {
		t.Run(k, func(t *testing.T) {
			updated, cmd := tm.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)})
			ttm := updated.(tableTreeModel)
			if ttm.showDeleteConfirm {
				t.Errorf("%q opened delete-confirm in read-only mode", k)
			}
			if cmd != nil {
				t.Errorf("%q returned a non-nil cmd in read-only mode", k)
			}
		})
	}
}

// chainRulesLoadedMsg lands on the chain matching (family, table-name,
// chain-name) and flips Loaded=true. Messages for an unknown chain are
// ignored — that's the "chain was deleted between dispatch and reply"
// case (no-op) and the "stale batch after a refresh" case (still
// targets the right chain after refresh because the key is stable).
func TestChainRulesLoadedMsg_RoutesByFamilyTableChain(t *testing.T) {
	mw := MainWindow{
		tableTree: tableTreeModel{
			nodes: []*tableNode{
				{Table: nftables.Table{Name: "filter", Family: nftables.TableFamilyINet},
					Chains: []*chainNode{
						{Chain: nftables.Chain{Name: "input"}},  // unloaded
						{Chain: nftables.Chain{Name: "output"}}, // unloaded
					}},
				{Table: nftables.Table{Name: "nat", Family: nftables.TableFamilyIPv4},
					Chains: []*chainNode{
						{Chain: nftables.Chain{Name: "prerouting"}}, // unloaded
					}},
			},
		},
	}

	rules := []*nftables.Rule{{Handle: 7}}
	updated, _ := mw.Update(chainRulesLoadedMsg{
		tableFamily: nftables.TableFamilyINet,
		tableName:   "filter",
		chainName:   "input",
		rules:       rules,
	})
	mw = updated.(MainWindow)

	if !mw.tableTree.nodes[0].Chains[0].Loaded {
		t.Error("input chain not marked Loaded after its message")
	}
	if len(mw.tableTree.nodes[0].Chains[0].Rules) != 1 {
		t.Errorf("input.Rules = %v, want 1 rule", mw.tableTree.nodes[0].Chains[0].Rules)
	}
	if mw.tableTree.nodes[0].Chains[1].Loaded {
		t.Error("output chain incorrectly marked Loaded")
	}
	if mw.tableTree.nodes[1].Chains[0].Loaded {
		t.Error("nat/prerouting incorrectly marked Loaded")
	}

	// A stale / deleted-chain message is a no-op.
	updated, _ = mw.Update(chainRulesLoadedMsg{
		tableFamily: nftables.TableFamilyINet,
		tableName:   "filter",
		chainName:   "missing",
		rules:       []*nftables.Rule{{Handle: 99}},
	})
	mw2 := updated.(MainWindow)
	for ti, tn := range mw2.tableTree.nodes {
		for ci, cn := range tn.Chains {
			want := mw.tableTree.nodes[ti].Chains[ci].Loaded
			if cn.Loaded != want {
				t.Errorf("unknown-chain msg changed %s/%s Loaded from %v to %v",
					tn.Table.Name, cn.Chain.Name, want, cn.Loaded)
			}
		}
	}
}

// Family mismatch (same table name, different family) must NOT cross-route.
func TestChainRulesLoadedMsg_FamilyMismatchIsNoOp(t *testing.T) {
	mw := MainWindow{
		tableTree: tableTreeModel{
			nodes: []*tableNode{
				{Table: nftables.Table{Name: "filter", Family: nftables.TableFamilyINet},
					Chains: []*chainNode{{Chain: nftables.Chain{Name: "input"}}}},
				{Table: nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4},
					Chains: []*chainNode{{Chain: nftables.Chain{Name: "input"}}}},
			},
		},
	}
	updated, _ := mw.Update(chainRulesLoadedMsg{
		tableFamily: nftables.TableFamilyIPv4,
		tableName:   "filter",
		chainName:   "input",
		rules:       []*nftables.Rule{{Handle: 1}},
	})
	mw = updated.(MainWindow)
	if mw.tableTree.nodes[0].Chains[0].Loaded {
		t.Error("inet/filter/input incorrectly flipped by an ip-family message")
	}
	if !mw.tableTree.nodes[1].Chains[0].Loaded {
		t.Error("ip/filter/input not flipped despite being the actual target")
	}
}

// passes everything through unchanged. Family is intentionally ignored
// (tables can share names across families).
func TestFilterTables(t *testing.T) {
	nodes := []*tableNode{
		{Table: nftables.Table{Name: "filter", Family: nftables.TableFamilyINet}},
		{Table: nftables.Table{Name: "nat", Family: nftables.TableFamilyIPv4}},
		{Table: nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4}},
	}
	cases := []struct {
		name        string
		filterName  string
		wantLen     int
		wantFamily0 nftables.TableFamily
	}{
		{"empty filter passes all", "", 3, nftables.TableFamilyINet},
		{"name match across families", "filter", 2, nftables.TableFamilyINet},
		{"unique name", "nat", 1, nftables.TableFamilyIPv4},
		{"no match", "missing", 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := filterTables(nodes, c.filterName)
			if len(got) != c.wantLen {
				t.Errorf("len = %d, want %d", len(got), c.wantLen)
				return
			}
			if c.wantLen > 0 && got[0].Table.Family != c.wantFamily0 {
				t.Errorf("first family = %v, want %v", got[0].Table.Family, c.wantFamily0)
			}
		})
	}
}

// A query with no matches leaves the cursor where it was.
func TestTreeSearch_NoMatchKeepsCursor(t *testing.T) {
	got, _ := searchTree().Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/")})
	tm := typeRunes(got.(tableTreeModel), "zzz")
	if len(tm.searchMatches) != 0 {
		t.Errorf("matches = %v, want none", tm.searchMatches)
	}
	if tm.cursor != 0 {
		t.Errorf("cursor moved to %d on no-match, want 0", tm.cursor)
	}
}
