package ui

// State-machine and render tests for setView, built through the netlink-free
// newSetViewWithElements constructor. addSetElementCmd / deleteSetElementCmd
// are netlink on execution, so they are returned but never run; the pure
// back-msg closure IS executed to assert its type.

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func setViewTable() *tableNode {
	return &tableNode{Table: nftables.Table{Name: "t", Family: nftables.TableFamilyINet}}
}

func setViewFixture(readOnly bool) setView {
	node := setViewTable()
	set := &nftables.Set{
		Name:    "blocklist",
		Table:   &node.Table,
		KeyType: nftables.TypeIPAddr,
	}
	elements := []nftables.SetElement{
		{Key: []byte{10, 0, 0, 1}},
		{Key: []byte{10, 0, 0, 2}},
		{Key: []byte{10, 0, 0, 3}},
	}
	sv := newSetViewWithElements(set, node, elements, readOnly)
	sv.width = 100
	sv.height = 40
	return sv
}

func verdictMapFixture() setView {
	node := setViewTable()
	set := &nftables.Set{
		Name:     "dispatch",
		Table:    &node.Table,
		KeyType:  nftables.TypeInetService,
		DataType: nftables.TypeVerdict,
		IsMap:    true,
	}
	elements := []nftables.SetElement{
		{Key: []byte{0x00, 0x50}, VerdictData: &expr.Verdict{Kind: expr.VerdictAccept}},
	}
	sv := newSetViewWithElements(set, node, elements, false)
	sv.width = 100
	sv.height = 40
	return sv
}

func TestSetView_Navigation(t *testing.T) {
	sv := setViewFixture(false)

	sv, _ = sv.Update(treeKey("down"))
	sv, _ = sv.Update(treeKey("down"))
	if sv.cursor != 2 {
		t.Errorf("cursor = %d after 2 downs, want 2", sv.cursor)
	}
	sv, _ = sv.Update(treeKey("down"))
	if sv.cursor != 2 {
		t.Errorf("cursor = %d after down at bottom, want 2", sv.cursor)
	}
	for i := 0; i < 3; i++ {
		sv, _ = sv.Update(treeKey("up"))
	}
	if sv.cursor != 0 {
		t.Errorf("cursor = %d after scrolling back, want 0", sv.cursor)
	}
}

func TestSetView_AddPromptFlow(t *testing.T) {
	sv := setViewFixture(false)

	sv, _ = sv.Update(treeKey("a"))
	if !sv.showAddPrompt || !sv.IsModal() {
		t.Fatal("a did not open the add prompt")
	}

	// Empty key is rejected.
	sv, cmd := sv.Update(treeKey("enter"))
	if cmd != nil || sv.addErr != "key required" {
		t.Errorf("empty enter: cmd=%v addErr=%q", cmd != nil, sv.addErr)
	}

	// Unparseable key surfaces the parser error.
	sv, _ = sv.Update(treeKey("not-an-ip"))
	sv, cmd = sv.Update(treeKey("enter"))
	if cmd != nil || sv.addErr == "" {
		t.Error("bad key: expected a parse error and no cmd")
	}

	// Range input requires an interval set.
	sv.addInput.SetValue("10.0.0.1-10.0.0.5")
	sv, cmd = sv.Update(treeKey("enter"))
	if cmd != nil || !strings.Contains(sv.addErr, "interval") {
		t.Errorf("range on non-interval set: cmd=%v addErr=%q", cmd != nil, sv.addErr)
	}

	// Valid key returns the kernel cmd (not run), keeps the prompt open for
	// bulk entry, clears the input, and shows the "added" hint.
	sv.addInput.SetValue("10.0.0.9")
	sv, cmd = sv.Update(treeKey("enter"))
	if cmd == nil {
		t.Fatal("valid enter returned no cmd")
	}
	if !sv.showAddPrompt || sv.addInput.Value() != "" || sv.addLastHint != "added 10.0.0.9" || sv.addErr != "" {
		t.Errorf("post-add state: open=%v input=%q hint=%q err=%q",
			sv.showAddPrompt, sv.addInput.Value(), sv.addLastHint, sv.addErr)
	}

	// Esc closes the prompt and clears transient state.
	sv, _ = sv.Update(treeKey("esc"))
	if sv.showAddPrompt || sv.addErr != "" || sv.addLastHint != "" {
		t.Error("esc did not reset the add prompt")
	}
}

func TestSetView_MapAddFlow(t *testing.T) {
	sv := verdictMapFixture()

	sv, _ = sv.Update(treeKey("a"))
	if !sv.showAddPrompt {
		t.Fatal("a did not open the add prompt")
	}

	// Tab toggles key/value focus on maps.
	sv, _ = sv.Update(keyMsg(tea.KeyTab))
	if !sv.addFocusVal || !sv.addValInput.Focused() {
		t.Error("tab did not focus the value input")
	}
	sv, _ = sv.Update(keyMsg(tea.KeyTab))
	if sv.addFocusVal {
		t.Error("second tab did not focus the key input back")
	}

	// Key present, value missing.
	sv.addInput.SetValue("443")
	sv, cmd := sv.Update(treeKey("enter"))
	if cmd != nil || sv.addErr != "value required" {
		t.Errorf("missing value: cmd=%v addErr=%q", cmd != nil, sv.addErr)
	}

	// Bad verdict value.
	sv.addValInput.SetValue("frobnicate")
	sv, cmd = sv.Update(treeKey("enter"))
	if cmd != nil || sv.addErr == "" {
		t.Error("bad verdict: expected a parse error and no cmd")
	}

	// Valid key + verdict.
	sv.addValInput.SetValue("jump mychain")
	sv, cmd = sv.Update(treeKey("enter"))
	if cmd == nil {
		t.Fatal("valid map enter returned no cmd")
	}
	if sv.addLastHint != "added 443 → jump mychain" {
		t.Errorf("hint = %q", sv.addLastHint)
	}
	if sv.addFocusVal || sv.addValInput.Value() != "" {
		t.Error("post-add: focus/value not reset to the key input")
	}
}

func TestSetView_DeleteConfirmFlow(t *testing.T) {
	sv := setViewFixture(false)
	sv.cursor = 1

	sv, _ = sv.Update(treeKey("d"))
	if !sv.showDelete || !sv.IsModal() {
		t.Fatal("d did not open the delete confirm")
	}

	sv, _ = sv.Update(treeKey("n"))
	if sv.showDelete {
		t.Fatal("n did not cancel")
	}

	sv, _ = sv.Update(treeKey("d"))
	sv, cmd := sv.Update(treeKey("y"))
	if sv.showDelete || cmd == nil {
		t.Error("y did not close the confirm with a delete cmd")
	}
	// deleteSetElementCmd is netlink on execution — not run.

	// d with no elements is a no-op.
	empty := newSetViewWithElements(sv.set, sv.table, nil, false)
	empty, _ = empty.Update(treeKey("d"))
	if empty.showDelete {
		t.Error("d on an empty set opened the confirm")
	}
}

func TestSetView_BackAndQuit(t *testing.T) {
	sv := setViewFixture(false)

	_, cmd := sv.Update(treeKey("esc"))
	if cmd == nil {
		t.Fatal("esc returned no cmd")
	}
	if _, ok := cmd().(setViewBackMsg); !ok {
		t.Errorf("esc emitted %T, want setViewBackMsg", cmd())
	}

	if _, cmd := sv.Update(treeKey("q")); cmd == nil {
		t.Error("q returned no quit cmd")
	}
}

func TestSetView_ReadOnlyDisablesWriteKeys(t *testing.T) {
	sv := setViewFixture(true)

	sv, _ = sv.Update(treeKey("a"))
	if sv.showAddPrompt {
		t.Error("read-only a opened the add prompt")
	}
	sv, _ = sv.Update(treeKey("d"))
	if sv.showDelete {
		t.Error("read-only d opened the delete confirm")
	}
	// Navigation and back stay available.
	if _, cmd := sv.Update(treeKey("esc")); cmd == nil {
		t.Error("read-only esc returned no back cmd")
	}
}

func TestFormatSetElementKey(t *testing.T) {
	mk := func(kt nftables.SetDatatype) *nftables.Set { return &nftables.Set{KeyType: kt} }
	tests := []struct {
		name string
		set  *nftables.Set
		key  []byte
		want string
	}{
		{"ipv4", mk(nftables.TypeIPAddr), []byte{192, 168, 1, 1}, "192.168.1.1"},
		{"ipv6", mk(nftables.TypeIP6Addr), []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, "fe80::1"},
		{"ether", mk(nftables.TypeEtherAddr), []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, "aa:bb:cc:dd:ee:ff"},
		{"port", mk(nftables.TypeInetService), []byte{0x01, 0xbb}, "443"},
		{"proto", mk(nftables.TypeInetProto), []byte{6}, "6"},
		{"mark1", mk(nftables.TypeMark), []byte{7}, "7"},
		{"int2", mk(nftables.TypeInteger), []byte{0x01, 0x00}, "256"},
		{"int4", mk(nftables.TypeInteger), []byte{0, 1, 0, 0}, "65536"},
		{"int8", mk(nftables.TypeInteger), []byte{0, 0, 0, 0, 0, 0, 0, 9}, "9"},
		{"hex fallback", mk(nftables.TypeVerdict), []byte{0xde, 0xad}, "0xdead"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatSetElementKey(tt.set, tt.key); got != tt.want {
				t.Errorf("formatSetElementKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatSetElementVal(t *testing.T) {
	s := &nftables.Set{KeyType: nftables.TypeInetService, DataType: nftables.TypeIPAddr, IsMap: true}
	if got := formatSetElementVal(s, []byte{10, 0, 0, 7}); got != "10.0.0.7" {
		t.Errorf("formatSetElementVal() = %q, want 10.0.0.7", got)
	}
}

func TestSetFlagsLabel(t *testing.T) {
	if got := setFlagsLabel(&nftables.Set{}); got != "" {
		t.Errorf("no flags = %q, want empty", got)
	}
	s := &nftables.Set{
		Anonymous: true, Constant: true, Interval: true, HasTimeout: true,
		Dynamic: true, Counter: true, AutoMerge: true, IsMap: true, Concatenation: true,
	}
	got := setFlagsLabel(s)
	for _, tok := range []string{"anonymous", "constant", "interval", "timeout", "dynamic", "counter", "auto-merge", "map", "concat"} {
		if !strings.Contains(got, tok) {
			t.Errorf("setFlagsLabel() = %q, missing %q", got, tok)
		}
	}
}

func TestSetKeyTypeHints(t *testing.T) {
	tests := []struct {
		set  nftables.Set
		want string
	}{
		{nftables.Set{KeyType: nftables.TypeIPAddr}, "10.0.0.1"},
		{nftables.Set{KeyType: nftables.TypeIPAddr, Interval: true}, "10.0.0.1 | 10.0.0.0/24 | 10.0.0.1-10.0.0.5"},
		{nftables.Set{KeyType: nftables.TypeIP6Addr}, "fe80::1"},
		{nftables.Set{KeyType: nftables.TypeIP6Addr, Interval: true}, "fe80::1 | 2001:db8::/64"},
		{nftables.Set{KeyType: nftables.TypeEtherAddr}, "aa:bb:cc:dd:ee:ff"},
		{nftables.Set{KeyType: nftables.TypeInetService}, "443"},
		{nftables.Set{KeyType: nftables.TypeInetService, Interval: true}, "443 | 1024-2048"},
		{nftables.Set{KeyType: nftables.TypeInetProto}, "6"},
		{nftables.Set{KeyType: nftables.TypeMark}, "0 / 0x10"},
		{nftables.Set{KeyType: nftables.TypeInteger}, "0 / 0x10"},
	}
	for _, tt := range tests {
		if got := setKeyTypeHint(&tt.set); got != tt.want {
			t.Errorf("setKeyTypeHint(%s) = %q, want %q", tt.set.KeyType.Name, got, tt.want)
		}
	}

	// Data-type hints reuse the key-type logic; verdict maps get CLI forms.
	v := &nftables.Set{KeyType: nftables.TypeInetService, DataType: nftables.TypeVerdict}
	if got := setDataTypeHint(v); !strings.Contains(got, "jump <chain>") {
		t.Errorf("verdict hint = %q", got)
	}
	ip := &nftables.Set{KeyType: nftables.TypeInetService, DataType: nftables.TypeIPAddr}
	if got := setDataTypeHint(ip); got != "10.0.0.1" {
		t.Errorf("ip data hint = %q", got)
	}
}

func TestSetView_ViewRenders(t *testing.T) {
	sv := setViewFixture(false)
	v := sv.View()
	for _, tok := range []string{"| Set |", "blocklist", "Elements (3):", "10.0.0.1", "10.0.0.3"} {
		if !strings.Contains(v, tok) {
			t.Errorf("View() missing %q", tok)
		}
	}

	// Status message renders.
	sv.statusMsg = "kernel said no"
	if v := sv.View(); !strings.Contains(v, "kernel said no") {
		t.Error("View() does not render statusMsg")
	}
	sv.statusMsg = ""

	// Interval elements render as ranges; single-host KeyEnd pairs collapse.
	sv.set.Interval = true
	sv.elements = []nftables.SetElement{
		{Key: []byte{10, 0, 0, 1}, KeyEnd: []byte{10, 0, 0, 5}},
		{Key: []byte{10, 0, 0, 9}, KeyEnd: []byte{10, 0, 0, 9}},
	}
	v = sv.View()
	if !strings.Contains(v, "10.0.0.1-10.0.0.5") {
		t.Error("View() does not render the interval range")
	}
	if strings.Contains(v, "10.0.0.9-10.0.0.9") {
		t.Error("View() renders a single-host pair as a range")
	}

	// Empty set placeholder + flags/timeout rows.
	sv.elements = nil
	sv.set.HasTimeout = true
	sv.set.Timeout = 30 * time.Second
	v = sv.View()
	for _, tok := range []string{"(empty)", "Flags", "interval", "Timeout"} {
		if !strings.Contains(v, tok) {
			t.Errorf("empty View() missing %q", tok)
		}
	}

	// Add prompt overlay (set and map variants).
	plain := setViewFixture(false)
	plain, _ = plain.Update(treeKey("a"))
	if v := plain.View(); !strings.Contains(v, "Add element to blocklist") {
		t.Error("View() missing the add-prompt overlay")
	}
	m := verdictMapFixture()
	m, _ = m.Update(treeKey("a"))
	v = m.View()
	for _, tok := range []string{"Add entry to dispatch", "Key", "Value", "Tab: switch field"} {
		if !strings.Contains(v, tok) {
			t.Errorf("map add View() missing %q", tok)
		}
	}

	// Map element value arrow + verdict rendering on the main screen.
	m2 := verdictMapFixture()
	if v := m2.View(); !strings.Contains(v, "→") {
		t.Error("map View() missing the key → value arrow")
	}

	// Delete confirm overlay.
	d := setViewFixture(false)
	d, _ = d.Update(treeKey("d"))
	if v := d.View(); !strings.Contains(v, "Delete element 10.0.0.1") {
		t.Error("View() missing the delete-confirm overlay")
	}
}

func TestMaxIntSV(t *testing.T) {
	if maxIntSV(3, 5) != 5 || maxIntSV(5, 3) != 5 {
		t.Error("maxIntSV broken")
	}
}
