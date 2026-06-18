package ui

// E-3 (audit R2): the initial tree-load (initialTableTreeModel via
// InitialMainWindow) and the chain-view constructor (newChainView) must surface
// a netlink failure as a graceful error routed to loadErrorView — never a
// panic (which, at startup, prints a Go stack trace instead of the styled
// CAP_NET_ADMIN advice, and mid-run crashes the TUI).
//
// These run in the unprivileged unit environment where ListTables /
// ListRulesOfChain return EPERM, and skip when netlink happens to be readable
// (e.g. the suite is run as root) so they never go flaky.

import (
	"strings"
	"testing"

	"github.com/google/nftables"
)

func TestInitialMainWindow_LoadErrorDoesNotPanic(t *testing.T) {
	m := InitialMainWindow(Options{}) // must not panic on a netlink failure
	if m.err == nil {
		t.Skip("netlink readable here; load-error path not exercised")
	}
	if m.loading {
		t.Error("loading should be false when the initial load failed")
	}
	// The captured error must render as advice without crashing View().
	m.ready = true
	m.width = 100
	m.height = 40
	if v := m.View(); !strings.Contains(v, "Error") && !strings.Contains(v, "Permission") {
		t.Errorf("View() did not render the load error; got:\n%s", v)
	}
}

func TestNewChainView_ErrorDoesNotPanic(t *testing.T) {
	tbl := &tableNode{Table: nftables.Table{Name: "filter", Family: nftables.TableFamilyINet}}
	ch := &nftables.Chain{Name: "input"}
	_, err := newChainView(ch, tbl, false) // must not panic
	if err == nil {
		t.Skip("netlink readable here; chain-view error path not exercised")
	}
}
