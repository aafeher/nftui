package ui

import (
	"errors"
	"testing"

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
