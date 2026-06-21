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
	"github.com/charmbracelet/lipgloss"
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

// TestMainWindow_TooSmallGuard: below the supported minimum (80x24) the view is
// a resize prompt, not a broken top-clipped layout; at the minimum it is not.
func TestMainWindow_TooSmallGuard(t *testing.T) {
	m := sizedMainWindow(t)

	m, _ = route(t, m, tea.WindowSizeMsg{Width: 70, Height: 20})
	v := m.View()
	if !strings.Contains(v, "Terminal too small") || !strings.Contains(v, "80x24") {
		t.Errorf("small terminal did not show the resize prompt:\n%s", v)
	}

	m, _ = route(t, m, tea.WindowSizeMsg{Width: 80, Height: 24})
	if strings.Contains(m.View(), "Terminal too small") {
		t.Error("80x24 (the supported minimum) wrongly showed the resize prompt")
	}
}

// TestMainWindow_FrameFitsTerminal: the View clamps to the terminal height so an
// over-tall sub-view (here a 20-rule chain view, which renders ~27 lines at
// height 24) can never scroll its top off-screen.
func TestMainWindow_FrameFitsTerminal(t *testing.T) {
	cv := chainViewFixture(20, false)
	cv.width, cv.height = 80, 24
	m := sizedMainWindow(t)
	m, _ = route(t, m, tea.WindowSizeMsg{Width: 80, Height: 24})
	m.activeView = "chain"
	m.chainView = &cv

	if h := lipgloss.Height(m.View()); h > 24 {
		t.Errorf("frame is %d lines tall at height 24 — top would scroll off", h)
	}
}

// TestMainWindow_QuitConfirmVisible pins the regression where the frame clamp
// hid the quit dialog (the old base+"\n"+overlay frame was two screens tall, so
// clamping to the terminal height kept only the base and dropped the dialog —
// making `q` appear to do nothing). The dialog must be present and the frame
// must fit the terminal, at both a roomy and a minimum size.
func TestMainWindow_QuitConfirmVisible(t *testing.T) {
	for _, sz := range []struct{ w, h int }{{110, 40}, {80, 24}} {
		m := sizedMainWindow(t)
		m, _ = route(t, m, tea.WindowSizeMsg{Width: sz.w, Height: sz.h})
		m.showQuitConfirm = true

		v := m.View()
		if !strings.Contains(v, "Are you sure you want to quit?") {
			t.Errorf("%dx%d: quit dialog not visible", sz.w, sz.h)
		}
		if hgt := lipgloss.Height(v); hgt > sz.h {
			t.Errorf("%dx%d: quit frame is %d lines — dialog would be clipped", sz.w, sz.h, hgt)
		}
	}
}

// TestMainWindow_QuitDoesNotFlush pins bug B-2: confirming the quit dialog used
// to call nft.FlushRules() — wiping the live kernel ruleset on exit. Confirming
// must simply quit: return tea.Quit, touch no netlink, set no error. (This test
// is safe to run as root precisely because the fix removed the flush; before the
// fix it would have flushed the host's ruleset, so it must never be run red.)
func TestMainWindow_QuitDoesNotFlush(t *testing.T) {
	m := sizedMainWindow(t) // activeView "main"
	m.showQuitConfirm = true

	m, cmd := route(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})

	if m.err != nil {
		t.Fatalf("quit set an error (flush attempted?): %v", m.err)
	}
	if cmd == nil {
		t.Fatal("quit-confirm 'y' returned nil cmd, want tea.Quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatal("quit-confirm 'y' did not return tea.Quit")
	}
}
