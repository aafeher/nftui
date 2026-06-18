//go:build integration

// Integration tests for the netlink read AND write (mutation) paths. Excluded
// from `go test ./...` by the build tag and skipped at runtime when not running
// as root (the netlink helpers and the `nft` binary both need CAP_NET_ADMIN).
//
// Run with:
//
//	sudo -E go test -tags=integration ./nft/ -v
//
// Each test creates a uniquely-named table, drives it through the same helpers
// the TUI uses — listing, creating/renaming/deleting tables and chains, and
// adding/inserting/moving/deleting rules — and asserts the kernel state read
// back through netlink. Every table is deleted in t.Cleanup so a failing
// assertion still leaves the host clean.
//
// Two helpers are deliberately NOT exercised here because they mutate state
// beyond the test's own uniquely-named table:
//   - FlushRules() runs `nft flush ruleset`, which would wipe the host's
//     entire firewall.
//   - LoadExamples() loads a bundled example ruleset (hard-coded relative
//     path) that would add tables the test cannot reliably clean up.
//
// LoadConfig() IS covered, since it applies a caller-supplied ruleset file —
// here one that only creates the test's own table.

package nft

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
)

// integrationTableName returns a host-unique inet table name. UnixNano makes
// collisions vanishingly unlikely so parallel runs (or a leftover table from a
// previous interrupted run) don't poison the test.
func integrationTableName() string {
	return fmt.Sprintf("nftui_it_%x", time.Now().UnixNano())
}

// requireRoot skips the test if the current effective UID isn't 0. Both
// `nft -f` (write) and netlink readback need CAP_NET_ADMIN, and dropping into
// the no-cap branch silently would make a "passing" run meaningless.
func requireRoot(t *testing.T) {
	t.Helper()
	if syscall.Geteuid() != 0 {
		t.Skip("integration test requires root (CAP_NET_ADMIN); run via `sudo -E go test -tags=integration ./nft/`")
	}
}

// applyRuleset writes content to a temp file and applies it with `nft -f`.
// On failure the assertion echoes the original ruleset and the nft output so
// the failure is debuggable without the test sandbox handy.
func applyRuleset(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ruleset.conf")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write tmp ruleset: %v", err)
	}
	out, err := exec.Command("nft", "-f", path).CombinedOutput()
	if err != nil {
		t.Fatalf("nft -f %s failed: %v\n--- ruleset ---\n%s\n--- nft output ---\n%s",
			path, err, content, out)
	}
}

// deleteTable removes the table after the test. Logged (not fatal) because
// cleanup runs after assertions — a noisy cleanup shouldn't mask the real
// failure. If a manual cleanup is needed, the table name is in the test log.
func deleteTable(t *testing.T, family, name string) {
	out, err := exec.Command("nft", "delete", "table", family, name).CombinedOutput()
	if err != nil {
		t.Logf("cleanup: nft delete table %s %s: %v\n%s", family, name, err, out)
	}
}

// findTable returns the nftables.Table* matching name + family in the live
// kernel state, or nil. Goes through ListTables on purpose — the whole point
// of the harness is to exercise nftui's own readback path.
func findTable(t *testing.T, name string, family nftables.TableFamily) *nftables.Table {
	t.Helper()
	tables, err := ListTables()
	if err != nil {
		t.Fatalf("ListTables: %v", err)
	}
	for _, tbl := range tables {
		if tbl.Name == name && tbl.Family == family {
			return tbl
		}
	}
	return nil
}

// findChain returns the chain with the given name inside table, or nil.
func findChain(t *testing.T, table *nftables.Table, name string) *nftables.Chain {
	t.Helper()
	chains, err := ListChainsOfTable(table)
	if err != nil {
		t.Fatalf("ListChainsOfTable: %v", err)
	}
	for _, ch := range chains {
		if ch.Name == name {
			return ch
		}
	}
	return nil
}

// TestIntegration_RuleRoundtrip applies a small inet ruleset via `nft -f`,
// reads it back with the same netlink-backed helpers the TUI uses, and asserts
// rules are present, ordered, and parse to the expected human-readable text.
//
// What it covers:
//   - Base chain creation (type filter hook input priority 0 policy accept)
//   - Regular chain creation
//   - CT state condition (set form)
//   - IP saddr CIDR condition
//   - TCP dport (scalar and anonymous-set forms)
//   - accept / drop / jump verdicts
//   - Counter action
//   - Comment preservation through UserData TLV
//
// The renderer's exact output is not pinned — assertions look for tokens
// ("ct state", "ip saddr", "tcp dport", "jump") so the test stays green
// across nft / kernel-renderer drift.
func TestIntegration_RuleRoundtrip(t *testing.T) {
	requireRoot(t)

	tableName := integrationTableName()
	t.Logf("table name: inet %s", tableName)

	ruleset := fmt.Sprintf(`
table inet %s {
    chain input {
        type filter hook input priority 0; policy accept;
        ct state established,related accept comment "established"
        ip saddr 10.0.0.0/8 drop comment "rfc1918-10"
        tcp dport 22 counter accept comment "ssh"
        tcp dport { 80, 443 } accept comment "web"
        jump dispatch comment "dispatch"
    }
    chain dispatch {
        accept comment "default"
    }
}
`, tableName)

	// Register cleanup BEFORE applying — if `nft -f` partially succeeds and
	// then something panics before we reach this line, the table would leak
	// on the host. `deleteTable` already tolerates a missing table (logs the
	// `nft delete table` error instead of failing the test) so running it
	// when the apply itself didn't create anything is harmless.
	t.Cleanup(func() { deleteTable(t, "inet", tableName) })
	applyRuleset(t, ruleset)

	target := findTable(t, tableName, nftables.TableFamilyINet)
	if target == nil {
		t.Fatalf("table %q not found after nft -f", tableName)
	}

	chains, err := ListChainsOfTable(target)
	if err != nil {
		t.Fatalf("ListChainsOfTable: %v", err)
	}
	if got, want := len(chains), 2; got != want {
		t.Errorf("chain count = %d, want %d", got, want)
	}

	input := findChain(t, target, "input")
	if input == nil {
		t.Fatal("input chain not found")
	}

	rules, err := ListRulesOfChain(target, input)
	if err != nil {
		t.Fatalf("ListRulesOfChain(input): %v", err)
	}
	if got, want := len(rules), 5; got != want {
		t.Fatalf("input rule count = %d, want %d (rules diverged from fixture)", got, want)
	}

	// Comments live in UserData (TLV) and round-trip cleanly, so they're the
	// most reliable per-rule identifier — pin them exactly.
	wantComments := []string{"established", "rfc1918-10", "ssh", "web", "dispatch"}
	for i, want := range wantComments {
		if got := ExtractComment(rules[i]); got != want {
			t.Errorf("rule[%d] comment = %q, want %q", i, got, want)
		}
	}

	// Rendered-text tokens — kept loose (the exact format shifts across nft
	// versions) but enough to verify the right expression class came back.
	wantTokens := []string{
		"ct state",  // rule 0
		"ip saddr",  // rule 1
		"tcp dport", // rule 2 (scalar port — ssh)
		"tcp dport", // rule 3 (anonymous set form — web ports)
		"jump",      // rule 4
	}
	for i, token := range wantTokens {
		rendered := RuleToHumanReadable(rules[i])
		if !strings.Contains(rendered, token) {
			t.Errorf("rule[%d] rendered %q does not contain %q", i, rendered, token)
		}
	}

	// dispatch chain — sanity-check regular (non-base) chain handling.
	dispatch := findChain(t, target, "dispatch")
	if dispatch == nil {
		t.Fatal("dispatch chain not found")
	}
	dRules, err := ListRulesOfChain(target, dispatch)
	if err != nil {
		t.Fatalf("ListRulesOfChain(dispatch): %v", err)
	}
	if got, want := len(dRules), 1; got != want {
		t.Errorf("dispatch rule count = %d, want %d", got, want)
	}
	if got := ExtractComment(dRules[0]); got != "default" {
		t.Errorf("dispatch rule[0] comment = %q, want %q", got, "default")
	}
}

// TestIntegration_NftBinaryAvailable is a smoke check that the nft binary is
// on PATH. Running the heavier round-trip test without nft would fail with a
// misleading "nft -f failed" — this one fails with a clear diagnostic.
func TestIntegration_NftBinaryAvailable(t *testing.T) {
	requireRoot(t)
	out, err := exec.Command("nft", "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("nft --version failed: %v\n%s\n(install the nftables package or fix PATH)", err, out)
	}
	t.Logf("nft version: %s", strings.TrimSpace(string(out)))
}

// baseChainSpec builds a base-chain spec (type filter, hook input, the given
// priority, policy accept) suitable for CreateChain. The Table field is left
// nil on purpose — CreateChain uses its own table argument.
func baseChainSpec(name string, priority int) *nftables.Chain {
	prio := nftables.ChainPriority(priority)
	pol := nftables.ChainPolicyAccept
	return &nftables.Chain{
		Name:     name,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: &prio,
		Policy:   &pol,
	}
}

// TestIntegration_TableLifecycle drives CreateTable → RenameTable → DeleteTable
// against the live kernel and asserts presence/absence through ListTables after
// each step. RenameTable goes through the `nft` CLI (dump + header rewrite +
// delete), so this also covers nftCLIFamily's inet branch.
func TestIntegration_TableLifecycle(t *testing.T) {
	requireRoot(t)
	name := integrationTableName()
	newName := name + "_renamed"
	t.Logf("table names: inet %s / %s", name, newName)
	t.Cleanup(func() {
		deleteTable(t, "inet", name)
		deleteTable(t, "inet", newName)
	})

	if err := CreateTable(nftables.TableFamilyINet, name); err != nil {
		t.Fatalf("CreateTable: %v", err)
	}
	tbl := findTable(t, name, nftables.TableFamilyINet)
	if tbl == nil {
		t.Fatal("table not found after CreateTable")
	}

	// Same-name rename is an early-return no-op.
	if err := RenameTable(tbl, name); err != nil {
		t.Errorf("RenameTable to same name = %v, want nil", err)
	}

	if err := RenameTable(tbl, newName); err != nil {
		t.Fatalf("RenameTable: %v", err)
	}
	if findTable(t, name, nftables.TableFamilyINet) != nil {
		t.Error("old table name still present after rename")
	}
	renamed := findTable(t, newName, nftables.TableFamilyINet)
	if renamed == nil {
		t.Fatal("renamed table not found")
	}

	if err := DeleteTable(renamed); err != nil {
		t.Fatalf("DeleteTable: %v", err)
	}
	if findTable(t, newName, nftables.TableFamilyINet) != nil {
		t.Error("table still present after DeleteTable")
	}
}

// TestIntegration_ChainLifecycle covers CreateChain (regular + base),
// DeleteChain, and all three UpdateChain paths: CLI rename, netlink policy-only
// update, and the recreateBaseChain dump/rewrite path triggered by a priority
// change.
func TestIntegration_ChainLifecycle(t *testing.T) {
	requireRoot(t)
	tableName := integrationTableName()
	t.Logf("table name: inet %s", tableName)
	t.Cleanup(func() { deleteTable(t, "inet", tableName) })

	if err := CreateTable(nftables.TableFamilyINet, tableName); err != nil {
		t.Fatalf("CreateTable: %v", err)
	}
	table := findTable(t, tableName, nftables.TableFamilyINet)
	if table == nil {
		t.Fatal("table not found")
	}

	// Regular (non-base) chain: no hook/type/priority/policy.
	if err := CreateChain(table, &nftables.Chain{Name: "reg"}); err != nil {
		t.Fatalf("CreateChain(regular): %v", err)
	}
	if findChain(t, table, "reg") == nil {
		t.Fatal("regular chain not found")
	}

	// Base chain.
	if err := CreateChain(table, baseChainSpec("base", 0)); err != nil {
		t.Fatalf("CreateChain(base): %v", err)
	}
	base := findChain(t, table, "base")
	if base == nil {
		t.Fatal("base chain not found")
	}

	// UpdateChain rename-only path (`nft rename chain`); every other attribute
	// is copied unchanged so the function returns after the rename.
	renamed := *base
	renamed.Name = "base2"
	if err := UpdateChain(base, &renamed); err != nil {
		t.Fatalf("UpdateChain(rename): %v", err)
	}
	if findChain(t, table, "base") != nil {
		t.Error("old chain name present after rename")
	}
	base2 := findChain(t, table, "base2")
	if base2 == nil {
		t.Fatal("renamed chain not found")
	}

	// Policy-only update (accept → drop) goes through the minimal netlink
	// NEWCHAIN path. Copying base2 keeps type/hook/priority identical, so only
	// policyChanged trips.
	dropPol := nftables.ChainPolicyDrop
	polSpec := *base2
	polSpec.Policy = &dropPol
	if err := UpdateChain(base2, &polSpec); err != nil {
		t.Fatalf("UpdateChain(policy): %v", err)
	}
	base2 = findChain(t, table, "base2")
	if base2 == nil || base2.Policy == nil || *base2.Policy != nftables.ChainPolicyDrop {
		t.Errorf("policy after update = %v, want drop", base2)
	}

	// Priority change forces recreateBaseChain (delete + re-add via `nft -f`).
	prioSpec := *base2
	newPrio := nftables.ChainPriority(10)
	prioSpec.Priority = &newPrio
	if err := UpdateChain(base2, &prioSpec); err != nil {
		t.Fatalf("UpdateChain(priority/recreate): %v", err)
	}
	base2 = findChain(t, table, "base2")
	if base2 == nil || base2.Priority == nil || *base2.Priority != nftables.ChainPriority(10) {
		t.Errorf("priority after recreate = %v, want 10", base2)
	}

	if err := DeleteChain(base2); err != nil {
		t.Fatalf("DeleteChain: %v", err)
	}
	if findChain(t, table, "base2") != nil {
		t.Error("chain present after DeleteChain")
	}

	// DeleteChain guard: a nil/Table-less chain returns an error, not a panic.
	if err := DeleteChain(&nftables.Chain{Name: "x"}); err == nil {
		t.Error("DeleteChain on a Table-less chain returned nil error")
	}
}

// TestIntegration_RuleLifecycle covers AddNewRuleToChain, InsertNewRuleBefore
// (both the idx==0 InsertRule path and the idx>0 Position+AddRule path),
// MoveRuleUp/MoveRuleDown (including the out-of-range guards) and DeleteRule.
func TestIntegration_RuleLifecycle(t *testing.T) {
	requireRoot(t)
	tableName := integrationTableName()
	t.Logf("table name: inet %s", tableName)
	t.Cleanup(func() { deleteTable(t, "inet", tableName) })

	if err := CreateTable(nftables.TableFamilyINet, tableName); err != nil {
		t.Fatalf("CreateTable: %v", err)
	}
	table := findTable(t, tableName, nftables.TableFamilyINet)
	if table == nil {
		t.Fatal("table not found")
	}
	if err := CreateChain(table, baseChainSpec("input", 0)); err != nil {
		t.Fatalf("CreateChain: %v", err)
	}
	chain := findChain(t, table, "input")
	if chain == nil {
		t.Fatal("chain not found")
	}

	// Append two rules; the first return value must carry a kernel handle.
	r1, err := AddNewRuleToChain(table, chain)
	if err != nil {
		t.Fatalf("AddNewRuleToChain: %v", err)
	}
	if r1 == nil || r1.Handle == 0 {
		t.Errorf("AddNewRuleToChain returned %+v, want a non-zero handle", r1)
	}
	if _, err := AddNewRuleToChain(table, chain); err != nil {
		t.Fatalf("AddNewRuleToChain #2: %v", err)
	}

	rules, err := ListRulesOfChain(table, chain)
	if err != nil {
		t.Fatalf("ListRulesOfChain: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("rule count after 2 adds = %d, want 2", len(rules))
	}

	// Insert before idx 0 → conn.InsertRule path.
	if _, err := InsertNewRuleBefore(table, chain, rules, 0); err != nil {
		t.Fatalf("InsertNewRuleBefore(0): %v", err)
	}
	rules, _ = ListRulesOfChain(table, chain)
	if len(rules) != 3 {
		t.Fatalf("rule count after insert@0 = %d, want 3", len(rules))
	}

	// Insert before idx 1 → Position + conn.AddRule path.
	if _, err := InsertNewRuleBefore(table, chain, rules, 1); err != nil {
		t.Fatalf("InsertNewRuleBefore(1): %v", err)
	}
	rules, _ = ListRulesOfChain(table, chain)
	if len(rules) != 4 {
		t.Fatalf("rule count after insert@1 = %d, want 4", len(rules))
	}

	// Reorder — the count is invariant, only handles/order change.
	if err := MoveRuleUp(rules, 2); err != nil {
		t.Fatalf("MoveRuleUp: %v", err)
	}
	rules, _ = ListRulesOfChain(table, chain)
	if len(rules) != 4 {
		t.Errorf("rule count after MoveRuleUp = %d, want 4", len(rules))
	}
	if err := MoveRuleDown(rules, 0); err != nil {
		t.Fatalf("MoveRuleDown: %v", err)
	}
	rules, _ = ListRulesOfChain(table, chain)
	if len(rules) != 4 {
		t.Errorf("rule count after MoveRuleDown = %d, want 4", len(rules))
	}

	// Out-of-range guards are silent no-ops.
	if err := MoveRuleUp(rules, 0); err != nil {
		t.Errorf("MoveRuleUp(0) guard = %v, want nil", err)
	}
	if err := MoveRuleDown(rules, len(rules)-1); err != nil {
		t.Errorf("MoveRuleDown(last) guard = %v, want nil", err)
	}

	// Delete every rule; the chain ends empty.
	for _, r := range rules {
		if err := DeleteRule(r); err != nil {
			t.Fatalf("DeleteRule: %v", err)
		}
	}
	rules, _ = ListRulesOfChain(table, chain)
	if len(rules) != 0 {
		t.Errorf("rule count after deletes = %d, want 0", len(rules))
	}
}

// TestIntegration_BulkReadersAndLoadConfig covers LoadConfig (the `nft -f`
// wrapper) plus the whole-host scanning readers: ListRulesOfTable, getAllRules
// (via GetAllRulesWithAccept / GetAllRulesWithDrop) and CountRulesByType.
func TestIntegration_BulkReadersAndLoadConfig(t *testing.T) {
	requireRoot(t)
	tableName := integrationTableName()
	t.Logf("table name: inet %s", tableName)
	t.Cleanup(func() { deleteTable(t, "inet", tableName) })

	ruleset := fmt.Sprintf(`
table inet %s {
    chain input {
        type filter hook input priority 0; policy accept;
        tcp dport 22 accept comment "ssh"
        tcp dport 23 accept comment "telnet"
        ip saddr 10.0.0.0/8 drop comment "rfc1918"
    }
}
`, tableName)

	path := filepath.Join(t.TempDir(), "rs.conf")
	if err := os.WriteFile(path, []byte(ruleset), 0o644); err != nil {
		t.Fatalf("write ruleset: %v", err)
	}
	if err := LoadConfig(path); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	table := findTable(t, tableName, nftables.TableFamilyINet)
	if table == nil {
		t.Fatal("table not found after LoadConfig")
	}

	// ListRulesOfTable aggregates across the table's chains.
	tblRules, err := ListRulesOfTable(table)
	if err != nil {
		t.Fatalf("ListRulesOfTable: %v", err)
	}
	if len(tblRules) != 3 {
		t.Errorf("ListRulesOfTable = %d rules, want 3", len(tblRules))
	}

	// CountRulesByType over our own rules is deterministic regardless of what
	// else is on the host.
	accept, drop, other := CountRulesByType(tblRules)
	if accept != 2 || drop != 1 || other != 0 {
		t.Errorf("CountRulesByType = (accept %d, drop %d, other %d), want (2, 1, 0)", accept, drop, other)
	}

	// The whole-host scanners include our rules, so our fixture is a lower
	// bound (the host may carry unrelated accept/drop rules too).
	acceptAll, err := GetAllRulesWithAccept()
	if err != nil {
		t.Fatalf("GetAllRulesWithAccept: %v", err)
	}
	if len(acceptAll) < 2 {
		t.Errorf("GetAllRulesWithAccept = %d, want >= 2", len(acceptAll))
	}
	dropAll, err := GetAllRulesWithDrop()
	if err != nil {
		t.Fatalf("GetAllRulesWithDrop: %v", err)
	}
	if len(dropAll) < 1 {
		t.Errorf("GetAllRulesWithDrop = %d, want >= 1", len(dropAll))
	}
}
