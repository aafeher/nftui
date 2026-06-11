package ui

// Routing tests for MainWindow.Update: every view-switch message must select
// the right sub-view, and every "data changed" message must flip the loading
// flag and return the reload batch. The batch cmds (loadTableTreeCmd & co.)
// hit netlink when EXECUTED — these tests only assert they are returned.
//
// chainSelectedMsg and setSelectedMsg are deliberately absent: their view
// constructors (newChainView / newSetView) fetch rules / set elements over
// netlink, so they belong to the integration surface.

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/nftables"
)

// route runs one Update on MainWindow and unwraps the result.
func route(t *testing.T, m MainWindow, msg tea.Msg) (MainWindow, tea.Cmd) {
	t.Helper()
	model, cmd := m.Update(msg)
	out, ok := model.(MainWindow)
	if !ok {
		t.Fatalf("Update returned %T, want MainWindow", model)
	}
	return out, cmd
}

func sizedMainWindow(t *testing.T) MainWindow {
	t.Helper()
	m := MainWindow{activeView: "main"}
	m, _ = route(t, m, tea.WindowSizeMsg{Width: 110, Height: 40})
	return m
}

func TestMainWindow_WindowSize(t *testing.T) {
	m := sizedMainWindow(t)
	if !m.ready || m.width != 110 || m.height != 40 {
		t.Errorf("ready=%v size=%dx%d, want ready 110x40", m.ready, m.width, m.height)
	}
	if m.tableTree.maxHeight != 31 || m.tableTree.width != 106 {
		t.Errorf("tableTree sized %dx%d, want 106x31", m.tableTree.width, m.tableTree.maxHeight)
	}
}

func TestMainWindow_ViewSwitchMsgs(t *testing.T) {
	rule := harnessRule()
	table := &nftables.Table{Name: "t", Family: nftables.TableFamilyINet}
	accept := nftables.ChainPolicyAccept
	chain := &nftables.Chain{
		Name: "input", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter, Policy: &accept,
	}

	tests := []struct {
		name     string
		msg      tea.Msg
		wantView string
		check    func(m MainWindow) bool
	}{
		{"rule view", ruleViewSelectedMsg{rule: rule}, "ruleView", func(m MainWindow) bool { return m.ruleView != nil }},
		{"rule edit", ruleEditSelectedMsg{rule: rule}, "ruleEdit", func(m MainWindow) bool { return m.ruleEdit != nil }},
		{"table edit", tableEditSelectedMsg{table: table}, "tableEdit", func(m MainWindow) bool { return m.tableEdit != nil }},
		{"chain edit", chainEditSelectedMsg{chain: chain}, "chainEdit", func(m MainWindow) bool { return m.chainEdit != nil }},
		{"chain create", chainCreateSelectedMsg{table: table}, "chainCreate", func(m MainWindow) bool { return m.chainCreate != nil }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := sizedMainWindow(t)
			m, _ = route(t, m, tt.msg)
			if m.activeView != tt.wantView {
				t.Errorf("activeView = %q, want %q", m.activeView, tt.wantView)
			}
			if !tt.check(m) {
				t.Error("target sub-view is nil after the switch")
			}
			if v := m.View(); v == "" {
				t.Error("View() empty after the switch")
			}
		})
	}
}

func TestMainWindow_DataChangedMsgsReload(t *testing.T) {
	msgs := []struct {
		name string
		msg  tea.Msg
		// The dialog-close messages also flip back to the main view; the
		// delete messages arrive while already in the main view, so their
		// handler only triggers the reload.
		wantsMainView bool
	}{
		{"table renamed", tableRenamedMsg{}, true},
		{"table created", tableCreatedMsg{}, true},
		{"chain updated", chainUpdatedMsg{}, true},
		{"chain created", chainCreatedMsg{}, true},
		{"table deleted", tableDeletedMsg{}, false},
		{"chain deleted", chainDeletedMsg{}, false},
	}
	for _, tt := range msgs {
		t.Run(tt.name, func(t *testing.T) {
			m := sizedMainWindow(t)
			if tt.wantsMainView {
				m.activeView = "chainEdit"
			}
			m, cmd := route(t, m, tt.msg)
			if tt.wantsMainView && m.activeView != "main" {
				t.Errorf("activeView = %q, want main", m.activeView)
			}
			if !m.loading {
				t.Error("loading flag not set")
			}
			if cmd == nil {
				t.Error("no reload batch returned")
			}
			// The batch cmds hit netlink on execution — not run here.
		})
	}
}

func TestMainWindow_SetViewBack(t *testing.T) {
	m := sizedMainWindow(t)
	m.activeView = "set"
	m, _ = route(t, m, setViewBackMsg{})
	if m.activeView != "main" || m.setView != nil {
		t.Errorf("activeView=%q setView=%v, want main/nil", m.activeView, m.setView)
	}
}

func TestMainWindow_TreeRefreshAppliesFilterAndFansOut(t *testing.T) {
	tree := testTree()

	m := sizedMainWindow(t)
	m.tableTree.tableFilter = "filter"
	m, cmd := route(t, m, tableTreeRefreshedMsg{nodes: tree.nodes})

	if got := len(m.tableTree.nodes); got != 1 {
		t.Fatalf("filter survived refresh? nodes = %d, want 1", got)
	}
	if m.tableTree.nodes[0].Table.Name != "filter" {
		t.Errorf("kept table = %q, want filter", m.tableTree.nodes[0].Table.Name)
	}
	// The filter table has chains → a per-chain fan-out batch must come back.
	if cmd == nil {
		t.Error("no per-chain rule fetch batch returned")
	}

	// A refresh with zero chains returns no cmd at all.
	m2 := sizedMainWindow(t)
	m2, cmd2 := route(t, m2, tableTreeRefreshedMsg{nodes: []*tableNode{
		{Table: nftables.Table{Name: "empty", Family: nftables.TableFamilyINet}},
	}})
	if cmd2 != nil {
		t.Error("chainless refresh returned a cmd, want nil")
	}
	_ = m2
}

func TestMainWindow_TableOpErrRouting(t *testing.T) {
	wantErr := errors.New("table exists")

	t.Run("routes to open tableEdit", func(t *testing.T) {
		m := sizedMainWindow(t)
		m, _ = route(t, m, tableEditSelectedMsg{table: &nftables.Table{Name: "t"}})
		m, _ = route(t, m, tableOpErrMsg{err: wantErr})
		if m.tableEdit == nil {
			t.Fatal("tableEdit vanished")
		}
	})

	t.Run("no-op without an open dialog", func(t *testing.T) {
		m := sizedMainWindow(t)
		m, cmd := route(t, m, tableOpErrMsg{err: wantErr})
		if cmd != nil {
			t.Error("dialog-less tableOpErrMsg returned a cmd")
		}
		_ = m
	})
}

func TestMainWindow_ViewStates(t *testing.T) {
	t.Run("not ready", func(t *testing.T) {
		m := MainWindow{}
		if got := m.View(); !strings.Contains(got, "Initializing") {
			t.Errorf("View() before ready = %q, want Initializing", got)
		}
	})

	t.Run("main view renders the tree", func(t *testing.T) {
		m := sizedMainWindow(t)
		m.tableTree.nodes = testTree().nodes
		if v := m.View(); !strings.Contains(v, "filter") {
			t.Error("main View() does not render the tree tables")
		}
	})

	t.Run("quit confirm overlays the dialog views", func(t *testing.T) {
		m := sizedMainWindow(t)
		m, _ = route(t, m, tableEditSelectedMsg{table: &nftables.Table{Name: "t"}})
		m.showQuitConfirm = true
		if v := m.View(); !strings.Contains(v, "quit") {
			t.Error("quit confirm overlay missing from View()")
		}
	})
}
