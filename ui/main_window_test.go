package ui

import (
	"errors"
	"testing"
)

// namedObjectOpErrMsg must surface on the tree's yellow status line, not the
// global red m.err tablesBox replacement — one channel per action result.
func TestNamedObjectOpErr_RoutesToTreeStatus(t *testing.T) {
	m := MainWindow{} // zero value — the handler under test touches no netlink state
	wantErr := errors.New("reset counter c1: operation not permitted")

	updated, _ := m.Update(namedObjectOpErrMsg{err: wantErr})
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
}
