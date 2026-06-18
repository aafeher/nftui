package ui

// Update state-machine tests for the table tree (tableTreeModel). The tree is
// built by hand instead of through initialTableTreeModel (which needs netlink
// and returns an error without CAP_NET_ADMIN), so navigation, expand/collapse, incremental search,
// read-only guards, and the delete-confirm modal are all exercised without
// CAP_NET_ADMIN. Kernel-touching cmds (delete*/reset*) are returned but never
// executed; the row-selection cmds (e/c/s/f3) are pure message wrappers and
// ARE executed to assert the emitted msg type.

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/nftables"

	"nftui/nft"
)

// testTree: two tables; the first carries 2 chains + 1 set + 2 named objects.
// Flattened collapsed: [filter, nat]. Flattened with filter expanded:
// [filter, input, output, blocklist, ctr1, q1, nat] — 7 rows.
func testTree() tableTreeModel {
	accept := nftables.ChainPolicyAccept
	filter := &tableNode{
		Table: nftables.Table{Name: "filter", Family: nftables.TableFamilyINet},
		Chains: []*chainNode{
			{Chain: nftables.Chain{Name: "input", Policy: &accept}, Loaded: true},
			{Chain: nftables.Chain{Name: "output"}}, // skeleton: rules still loading
		},
		Sets: []*nftables.Set{{Name: "blocklist"}},
		Objects: []nft.NamedObject{
			{Name: "ctr1", Type: nftables.ObjTypeCounter, TypeStr: "counter"},
			{Name: "q1", Type: nftables.ObjTypeQuota, TypeStr: "quota"},
		},
	}
	nat := &tableNode{Table: nftables.Table{Name: "nat", Family: nftables.TableFamilyIPv4}}
	return tableTreeModel{nodes: []*tableNode{filter, nat}}
}

func treeKey(s string) tea.KeyMsg {
	switch s {
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// step runs one Update and unwraps the tea.Model back to tableTreeModel.
func step(t *testing.T, tm tableTreeModel, msg tea.Msg) (tableTreeModel, tea.Cmd) {
	t.Helper()
	model, cmd := tm.Update(msg)
	out, ok := model.(tableTreeModel)
	if !ok {
		t.Fatalf("Update returned %T, want tableTreeModel", model)
	}
	return out, cmd
}

func TestGetFlattenedItems(t *testing.T) {
	tm := testTree()
	if got := len(tm.getFlattenedItems()); got != 2 {
		t.Fatalf("collapsed tree has %d rows, want 2", got)
	}

	tm.nodes[0].Expanded = true
	items := tm.getFlattenedItems()
	if got := len(items); got != 7 {
		t.Fatalf("expanded tree has %d rows, want 7", got)
	}
	if !items[0].isRoot || items[0].tableName != "filter" {
		t.Errorf("row 0 = %+v, want filter root", items[0])
	}
	if items[1].chainName != "input" || items[1].rulesLoading {
		t.Errorf("row 1 = %+v, want loaded chain input", items[1])
	}
	if items[2].chainName != "output" || !items[2].rulesLoading {
		t.Errorf("row 2 = %+v, want still-loading chain output", items[2])
	}
	if !items[3].isSet || items[3].setName != "blocklist" {
		t.Errorf("row 3 = %+v, want set blocklist", items[3])
	}
	if !items[4].isObj || items[4].objName != "ctr1" {
		t.Errorf("row 4 = %+v, want object ctr1", items[4])
	}
	if !items[6].isRoot || items[6].tableName != "nat" {
		t.Errorf("row 6 = %+v, want nat root", items[6])
	}
}

func TestTree_NavigationAndExpand(t *testing.T) {
	tm := testTree()

	// Enter on a root toggles expansion.
	tm, _ = step(t, tm, treeKey("enter"))
	if !tm.nodes[0].Expanded {
		t.Fatal("enter did not expand the table")
	}

	// Down walks into the children; up walks back.
	tm, _ = step(t, tm, treeKey("down"))
	tm, _ = step(t, tm, treeKey("down"))
	if tm.cursor != 2 {
		t.Errorf("cursor = %d after 2 downs, want 2", tm.cursor)
	}

	// Esc on a child jumps back to its root.
	tm, _ = step(t, tm, treeKey("esc"))
	if tm.cursor != 0 {
		t.Errorf("esc on child: cursor = %d, want 0 (root)", tm.cursor)
	}

	// Left on the expanded root collapses it.
	tm, _ = step(t, tm, treeKey("left"))
	if tm.nodes[0].Expanded {
		t.Error("left did not collapse the table")
	}

	// Up at the top is a no-op.
	tm, _ = step(t, tm, treeKey("up"))
	if tm.cursor != 0 {
		t.Errorf("up at top: cursor = %d, want 0", tm.cursor)
	}
}

func TestTree_ScrollOffsetFollowsCursor(t *testing.T) {
	tm := testTree()
	tm.nodes[0].Expanded = true
	tm.maxHeight = 3

	for i := 0; i < 6; i++ {
		tm, _ = step(t, tm, treeKey("down"))
	}
	if tm.cursor != 6 {
		t.Fatalf("cursor = %d, want 6", tm.cursor)
	}
	if tm.scrollOffset != 4 {
		t.Errorf("scrollOffset = %d, want 4 (cursor-maxHeight+1)", tm.scrollOffset)
	}

	for i := 0; i < 6; i++ {
		tm, _ = step(t, tm, treeKey("up"))
	}
	if tm.scrollOffset != 0 {
		t.Errorf("scrollOffset = %d after scrolling back up, want 0", tm.scrollOffset)
	}
}

func TestTree_SearchFlow(t *testing.T) {
	tm := testTree()

	tm, _ = step(t, tm, treeKey("/"))
	if !tm.searchMode || !tm.IsModal() {
		t.Fatal("/ did not enter search mode")
	}
	for _, n := range tm.nodes {
		if !n.Expanded {
			t.Fatal("entering search must expand all tables")
		}
	}

	// Type "block" — cursor jumps to the matching set row (index 3).
	for _, ch := range "block" {
		tm, _ = step(t, tm, treeKey(string(ch)))
	}
	if len(tm.searchMatches) != 1 || tm.cursor != 3 {
		t.Errorf("matches = %v cursor = %d, want [3] / 3", tm.searchMatches, tm.cursor)
	}

	// Clear the query and search "t" — multiple matches (filter, input,
	// output, ctr1, nat); enter cycles, up steps back.
	for i := 0; i < 5; i++ {
		tm, _ = step(t, tm, treeKey("backspace"))
	}
	if tm.searchQuery != "" {
		t.Fatalf("query = %q, want empty after clearing", tm.searchQuery)
	}
	tm, _ = step(t, tm, treeKey("t"))
	if len(tm.searchMatches) < 2 {
		t.Fatalf("query t matched %d rows, want >= 2", len(tm.searchMatches))
	}
	first := tm.cursor
	tm, _ = step(t, tm, treeKey("enter"))
	if tm.cursor == first {
		t.Error("enter did not advance to the next match")
	}
	tm, _ = step(t, tm, treeKey("up"))
	if tm.cursor != first {
		t.Error("up did not step back to the previous match")
	}

	tm, _ = step(t, tm, treeKey("esc"))
	if tm.searchMode || tm.IsModal() || tm.searchQuery != "" {
		t.Error("esc did not fully exit search mode")
	}
}

func TestTree_ReadOnlyGuards(t *testing.T) {
	for _, k := range []string{"d", "e", "c", "s", "R"} {
		tm := testTree()
		tm.readOnly = true
		tm, cmd := step(t, tm, treeKey(k))
		if cmd != nil {
			t.Errorf("read-only %q returned a cmd, want nil", k)
		}
		if tm.showDeleteConfirm {
			t.Errorf("read-only %q opened the delete confirm", k)
		}
	}
}

func TestTree_DeleteConfirmFlow(t *testing.T) {
	tm := testTree()

	tm, _ = step(t, tm, treeKey("d"))
	if !tm.showDeleteConfirm {
		t.Fatal("d on a table row did not open the confirm modal")
	}

	// While the modal is open, other keys are swallowed.
	tm, cmd := step(t, tm, treeKey("x"))
	if !tm.showDeleteConfirm || cmd != nil {
		t.Error("unrelated key must be ignored while the modal is open")
	}

	// n cancels.
	tm, _ = step(t, tm, treeKey("n"))
	if tm.showDeleteConfirm {
		t.Fatal("n did not cancel the confirm modal")
	}

	// y confirms and returns the delete cmd (netlink on execution — not run).
	tm, _ = step(t, tm, treeKey("d"))
	tm, cmd = step(t, tm, treeKey("y"))
	if tm.showDeleteConfirm {
		t.Error("y left the confirm modal open")
	}
	if cmd == nil {
		t.Error("y on a table row returned no delete cmd")
	}
}

func TestTree_RowSelectionMsgs(t *testing.T) {
	expanded := func() tableTreeModel {
		tm := testTree()
		tm.nodes[0].Expanded = true
		return tm
	}

	t.Run("e on root emits tableEditSelectedMsg", func(t *testing.T) {
		tm := expanded()
		_, cmd := step(t, tm, treeKey("e"))
		if cmd == nil {
			t.Fatal("no cmd")
		}
		if _, ok := cmd().(tableEditSelectedMsg); !ok {
			t.Errorf("msg = %T, want tableEditSelectedMsg", cmd())
		}
	})

	t.Run("e on chain emits chainEditSelectedMsg", func(t *testing.T) {
		tm := expanded()
		tm.cursor = 1
		_, cmd := step(t, tm, treeKey("e"))
		if cmd == nil {
			t.Fatal("no cmd")
		}
		if _, ok := cmd().(chainEditSelectedMsg); !ok {
			t.Errorf("msg = %T, want chainEditSelectedMsg", cmd())
		}
	})

	t.Run("c emits chainCreateSelectedMsg", func(t *testing.T) {
		tm := expanded()
		_, cmd := step(t, tm, treeKey("c"))
		if cmd == nil {
			t.Fatal("no cmd")
		}
		if _, ok := cmd().(chainCreateSelectedMsg); !ok {
			t.Errorf("msg = %T, want chainCreateSelectedMsg", cmd())
		}
	})

	t.Run("s emits setCreateSelectedMsg", func(t *testing.T) {
		tm := expanded()
		_, cmd := step(t, tm, treeKey("s"))
		if cmd == nil {
			t.Fatal("no cmd")
		}
		if _, ok := cmd().(setCreateSelectedMsg); !ok {
			t.Errorf("msg = %T, want setCreateSelectedMsg", cmd())
		}
	})

	t.Run("f3 on chain emits chainSelectedMsg", func(t *testing.T) {
		tm := expanded()
		tm.cursor = 1
		_, cmd := step(t, tm, treeKey("f3"))
		if cmd == nil {
			t.Fatal("no cmd")
		}
		if _, ok := cmd().(chainSelectedMsg); !ok {
			t.Errorf("msg = %T, want chainSelectedMsg", cmd())
		}
	})

	t.Run("f3 on set emits setSelectedMsg", func(t *testing.T) {
		tm := expanded()
		tm.cursor = 3
		_, cmd := step(t, tm, treeKey("f3"))
		if cmd == nil {
			t.Fatal("no cmd")
		}
		if _, ok := cmd().(setSelectedMsg); !ok {
			t.Errorf("msg = %T, want setSelectedMsg", cmd())
		}
	})

	t.Run("R on counter object returns reset cmd", func(t *testing.T) {
		tm := expanded()
		tm.cursor = 4 // ctr1
		_, cmd := step(t, tm, treeKey("R"))
		if cmd == nil {
			t.Error("R on a counter returned no cmd")
		}
		// resetNamedObjectCmd is netlink on execution — not run.
	})

	t.Run("R elsewhere sets the no-op hint", func(t *testing.T) {
		tm := expanded()
		tm.cursor = 1 // chain row
		tm, cmd := step(t, tm, treeKey("R"))
		if tm.statusMsg == "" {
			t.Error("R on a chain row did not set the statusMsg hint")
		}
		if cmd == nil {
			t.Error("statusMsg must come with its fade-timer cmd")
		}
	})
}

func TestTree_QuitKeys(t *testing.T) {
	for _, k := range []string{"q"} {
		tm := testTree()
		_, cmd := step(t, tm, treeKey(k))
		if cmd == nil {
			t.Fatalf("%q returned no cmd", k)
		}
		if _, ok := cmd().(tea.QuitMsg); !ok {
			t.Errorf("%q cmd emitted %T, want tea.QuitMsg", k, cmd())
		}
	}
}

func TestTree_View(t *testing.T) {
	tm := testTree()
	tm.width = 90
	tm.maxHeight = 20
	tm.nodes[0].Expanded = true

	v := tm.View()
	for _, tok := range []string{"filter", "input", "output", "blocklist", "ctr1", "nat"} {
		if !strings.Contains(v, tok) {
			t.Errorf("View() missing %q", tok)
		}
	}

	tm.showDeleteConfirm = true
	if v := tm.View(); !strings.Contains(strings.ToLower(v), "delete") {
		t.Error("View() with confirm modal does not mention delete")
	}
	tm.showDeleteConfirm = false

	tm.statusMsg = "transient hint"
	if v := tm.View(); !strings.Contains(v, "transient hint") {
		t.Error("View() does not render the statusMsg")
	}

	tm.statusMsg = ""
	tm.searchMode = true
	tm.searchQuery = "blo"
	if v := tm.View(); !strings.Contains(v, "blo") {
		t.Error("View() does not render the search query")
	}
}
