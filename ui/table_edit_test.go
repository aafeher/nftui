package ui

// State-machine tests for the table-rename dialog. renameTableCmd is netlink /
// `nft -f` on execution, so the F2 save cmd is returned but never run.
//
// RenameTable builds an `nft -f -` script by interpolating the new name into a
// `table <family> <name> {` header, so the rename target is the primary
// nft-script-injection vector (audit E-2 / S1) — hence the rejection test.

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/nftables"
)

func tableEditFixture() *nftables.Table {
	return &nftables.Table{Name: "filter", Family: nftables.TableFamilyINet}
}

func TestTableEdit_SaveRejectsInjectionName(t *testing.T) {
	te := newTableEdit(tableEditFixture())
	te.input.SetValue("pwned { }\ntable inet evil")

	te, cmd := te.Update(keyMsg(tea.KeyF2))
	if cmd != nil {
		t.Error("injection rename returned a kernel cmd, want nil")
	}
	if te.statusMsg == "" {
		t.Error("injection rename did not set a status message")
	}
}

func TestTableEdit_SaveValidNameReturnsCmd(t *testing.T) {
	te := newTableEdit(tableEditFixture())
	te.input.SetValue("filter_v2")

	te, cmd := te.Update(keyMsg(tea.KeyF2))
	if cmd == nil {
		t.Fatal("valid rename returned nil cmd, want the rename cmd")
	}
	if te.statusMsg != "" {
		t.Errorf("valid rename left statusMsg = %q, want empty", te.statusMsg)
	}
}

func TestTableEdit_SaveEmptyNameRejected(t *testing.T) {
	te := newTableEdit(tableEditFixture())
	te.input.SetValue("")

	te, cmd := te.Update(keyMsg(tea.KeyF2))
	if cmd != nil {
		t.Error("empty rename returned a cmd, want nil")
	}
	if te.statusMsg == "" {
		t.Error("empty rename did not set a status message")
	}
}
