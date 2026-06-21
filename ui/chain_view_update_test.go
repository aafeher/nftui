package ui

// Update state-machine tests for chainView, built through the netlink-free
// newChainViewWithRules constructor. Kernel-touching cmds (delete / move /
// add / insert) are returned but never executed. The f3/f4 selection cmds ARE
// executed: fetchFreshRule degrades gracefully to the fallback rule when the
// netlink re-fetch fails (the unit-test case), so they emit their msgs.

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func chainViewFixture(ruleCount int, readOnly bool) chainView {
	table := &nftables.Table{Name: "t", Family: nftables.TableFamilyINet}
	accept := nftables.ChainPolicyAccept
	chain := &nftables.Chain{
		Name: "input", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter, Policy: &accept,
	}
	node := &tableNode{Table: *table}

	rules := make([]*nftables.Rule, ruleCount)
	for i := range rules {
		comment := "rule " + string(rune('a'+i))
		rules[i] = &nftables.Rule{
			Table:    table,
			Chain:    chain,
			Handle:   uint64(i + 1),
			Position: uint64(i),
			Exprs:    []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictAccept}},
			UserData: append([]byte{0, byte(len(comment) + 1)}, append([]byte(comment), 0)...),
		}
	}

	cv := newChainViewWithRules(chain, node, rules, readOnly)
	cv.width = 100
	cv.height = 40
	return cv
}

func TestChainView_Navigation(t *testing.T) {
	cv := chainViewFixture(12, false)

	for i := 0; i < 11; i++ {
		cv, _ = cv.Update(keyMsg(tea.KeyDown))
	}
	if cv.cursor != 11 {
		t.Errorf("cursor = %d after 11 downs, want 11", cv.cursor)
	}
	if cv.scrollOffset == 0 {
		t.Error("scrollOffset did not follow the cursor past the window")
	}

	// Down at the bottom is a no-op.
	cv, _ = cv.Update(keyMsg(tea.KeyDown))
	if cv.cursor != 11 {
		t.Errorf("cursor = %d after down at bottom, want 11", cv.cursor)
	}

	for i := 0; i < 11; i++ {
		cv, _ = cv.Update(keyMsg(tea.KeyUp))
	}
	if cv.cursor != 0 || cv.scrollOffset != 0 {
		t.Errorf("cursor/offset = %d/%d after scrolling back, want 0/0", cv.cursor, cv.scrollOffset)
	}
}

func TestChainView_DeleteConfirmFlow(t *testing.T) {
	cv := chainViewFixture(3, false)

	cv, _ = cv.Update(treeKey("d"))
	if !cv.showDeleteConfirm || !cv.IsModal() {
		t.Fatal("d did not open the delete confirm")
	}

	cv, _ = cv.Update(treeKey("n"))
	if cv.showDeleteConfirm {
		t.Fatal("n did not cancel")
	}

	cv, _ = cv.Update(treeKey("d"))
	cv, cmd := cv.Update(treeKey("y"))
	if cv.showDeleteConfirm {
		t.Error("y left the confirm open")
	}
	if cmd == nil {
		t.Error("y returned no delete cmd")
	}
	// deleteRuleCmd is netlink on execution — not run.
}

func TestChainView_DeleteOnEmptyChain(t *testing.T) {
	cv := chainViewFixture(0, false)
	cv, _ = cv.Update(treeKey("d"))
	if cv.showDeleteConfirm {
		t.Error("d on an empty chain opened the confirm modal")
	}
}

func TestChainView_MoveCmds(t *testing.T) {
	cv := chainViewFixture(3, false)

	// K at the top / J at the bottom are no-ops.
	if _, cmd := cv.Update(treeKey("K")); cmd != nil {
		t.Error("K at top returned a cmd")
	}
	cv.cursor = 2
	if _, cmd := cv.Update(treeKey("J")); cmd != nil {
		t.Error("J at bottom returned a cmd")
	}

	// Valid moves return the kernel cmd (not run).
	cv.cursor = 1
	if _, cmd := cv.Update(treeKey("K")); cmd == nil {
		t.Error("K mid-list returned no cmd")
	}
	if _, cmd := cv.Update(treeKey("J")); cmd == nil {
		t.Error("J mid-list returned no cmd")
	}
}

func TestChainView_AddInsertCmds(t *testing.T) {
	cv := chainViewFixture(2, false)
	if _, cmd := cv.Update(treeKey("a")); cmd == nil {
		t.Error("a returned no add cmd")
	}
	if _, cmd := cv.Update(treeKey("i")); cmd == nil {
		t.Error("i returned no insert cmd")
	}
	// Both are netlink on execution — not run.
}

func TestChainView_RuleSelectionMsgs(t *testing.T) {
	cv := chainViewFixture(2, false)
	cv.cursor = 1

	_, cmd := cv.Update(keyMsg(tea.KeyF3))
	if cmd == nil {
		t.Fatal("f3 returned no cmd")
	}
	if msg, ok := cmd().(ruleViewSelectedMsg); !ok {
		t.Errorf("f3 emitted %T, want ruleViewSelectedMsg", cmd())
	} else if msg.rule == nil {
		t.Error("ruleViewSelectedMsg carries a nil rule")
	}

	_, cmd = cv.Update(keyMsg(tea.KeyF4))
	if cmd == nil {
		t.Fatal("f4 returned no cmd")
	}
	if _, ok := cmd().(ruleEditSelectedMsg); !ok {
		t.Errorf("f4 emitted %T, want ruleEditSelectedMsg", cmd())
	}
}

func TestChainView_ReadOnlyDisablesWriteKeys(t *testing.T) {
	cv := chainViewFixture(3, true)
	cv.cursor = 1

	for _, k := range []string{"d", "K", "J", "a", "i"} {
		next, cmd := cv.Update(treeKey(k))
		if cmd != nil {
			t.Errorf("read-only %q returned a cmd", k)
		}
		if next.showDeleteConfirm {
			t.Errorf("read-only %q opened the delete confirm", k)
		}
	}

	// f4 (edit) is disabled too; f3 (view) stays available.
	if _, cmd := cv.Update(keyMsg(tea.KeyF4)); cmd != nil {
		t.Error("read-only f4 returned a cmd")
	}
	if _, cmd := cv.Update(keyMsg(tea.KeyF3)); cmd == nil {
		t.Error("read-only f3 returned no cmd (view must stay available)")
	}
}

func TestChainView_ViewRenders(t *testing.T) {
	cv := chainViewFixture(3, false)

	v := cv.View()
	for _, tok := range []string{"input", "t", "Rules"} {
		if !strings.Contains(v, tok) {
			t.Errorf("View() missing %q", tok)
		}
	}

	// Delete-confirm and status line variants.
	cv.showDeleteConfirm = true
	if v := cv.View(); !strings.Contains(strings.ToLower(v), "delete") {
		t.Error("View() with confirm modal does not mention delete")
	}
	cv.showDeleteConfirm = false
	cv.statusMsg = "kernel said no"
	if v := cv.View(); !strings.Contains(v, "kernel said no") {
		t.Error("View() does not render statusMsg")
	}

	// Filter mode renders the prompt and the narrowed list.
	cv.statusMsg = ""
	cv.enterFilter()
	cv.filterQuery = "rule a"
	if v := cv.View(); v == "" {
		t.Error("View() empty in filter mode")
	}

	// Nil chain renders nothing (router guard).
	empty := chainView{}
	if v := empty.View(); v != "" {
		t.Errorf("nil-chain View() = %q, want empty", v)
	}
}

// TestChainView_FitsTerminal pins ROADMAP B-3 Phase 2b: the compact chain
// header keeps the whole frame within the terminal height at the 80x24 minimum,
// so the footer is no longer clipped.
func TestChainView_FitsTerminal(t *testing.T) {
	cv := chainViewFixture(12, false)
	cv.width, cv.height = 80, 24
	if h := lipgloss.Height(cv.View()); h > cv.height {
		t.Errorf("chain view frame is %d lines at height 24, want <= 24 (footer would clip)", h)
	}
}

// TestChainView_RuleRenderedOnce pins bug B-1: the view loop used to print each
// rule twice (once via RuleToHumanReadable, once via nftserializer.SerializeRule).
// A rule with a distinctive position must appear on exactly one line.
func TestChainView_RuleRenderedOnce(t *testing.T) {
	table := &nftables.Table{Name: "t", Family: nftables.TableFamilyINet}
	accept := nftables.ChainPolicyAccept
	chain := &nftables.Chain{
		Name: "input", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter, Policy: &accept,
	}
	node := &tableNode{Table: *table}
	mk := func(pos, handle uint64) *nftables.Rule {
		return &nftables.Rule{
			Table: table, Chain: chain, Handle: handle, Position: pos,
			Exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictAccept}},
		}
	}
	// Rule 0 is under the cursor (styled); rule 99 is plain text, so counting its
	// position prefix is unaffected by cursor ANSI styling.
	rules := []*nftables.Rule{mk(0, 1), mk(99, 2)}
	cv := newChainViewWithRules(chain, node, rules, false)
	cv.width = 100
	cv.height = 40

	v := cv.View()
	if n := strings.Count(v, "99."); n != 1 {
		t.Fatalf("rule at position 99 rendered %d times, want exactly 1", n)
	}
}
