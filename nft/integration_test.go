//go:build integration

// Integration tests for the netlink readback path. Excluded from `go test ./...`
// by the build tag and skipped at runtime when not running as root (the netlink
// helpers and the `nft` binary both need CAP_NET_ADMIN).
//
// Run with:
//
//	sudo -E go test -tags=integration ./nft/ -v
//
// Each test creates a uniquely-named table, applies a small ruleset with
// `nft -f`, reads it back through the same helpers the TUI uses, and asserts
// the result. The table is deleted in t.Cleanup so a failing assertion still
// leaves the host clean.

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

	applyRuleset(t, ruleset)
	t.Cleanup(func() { deleteTable(t, "inet", tableName) })

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
