package ui

import (
	"testing"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/nftables"
)

// --- setView state-machine -------------------------------------------------

// mkSetView builds a setView without calling newSetView (which would hit
// the live netlink). The keymap matches the production constructor so
// Add/Delete/Esc dispatch identically.
func mkSetView(s *nftables.Set) setView {
	km := setViewKeyMap{
		Up:     key.NewBinding(key.WithKeys("up", "k")),
		Down:   key.NewBinding(key.WithKeys("down", "j")),
		Add:    key.NewBinding(key.WithKeys("a")),
		Delete: key.NewBinding(key.WithKeys("d")),
		Back:   key.NewBinding(key.WithKeys("esc", "f3")),
		Quit:   key.NewBinding(key.WithKeys("q", "ctrl+c")),
	}
	return setView{
		set:  s,
		keys: km,
		help: help.New(),
	}
}

func ipv4Set() *nftables.Set {
	return &nftables.Set{KeyType: nftables.TypeIPAddr}
}

func ipv4ToMarkMap() *nftables.Set {
	return &nftables.Set{
		KeyType:  nftables.TypeIPAddr,
		IsMap:    true,
		DataType: nftables.TypeMark,
	}
}

func runes(s string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }

func TestSetView_IsModal_StartsFalse(t *testing.T) {
	sv := mkSetView(ipv4Set())
	if sv.IsModal() {
		t.Fatal("fresh setView should not be modal")
	}
}

func TestSetView_PressA_OpensAddPrompt(t *testing.T) {
	sv := mkSetView(ipv4Set())
	updated, _ := sv.Update(runes("a"))
	if !updated.showAddPrompt {
		t.Fatal("press 'a' should open the add prompt")
	}
	if !updated.IsModal() {
		t.Fatal("add prompt open → IsModal should be true")
	}
	if !updated.addInput.Focused() {
		t.Error("addInput should be focused on open")
	}
	if updated.addLastHint != "" {
		t.Error("addLastHint must reset on fresh open")
	}
}

func TestSetView_EscClosesAddPrompt(t *testing.T) {
	sv := mkSetView(ipv4Set())
	sv, _ = sv.Update(runes("a"))
	sv.addLastHint = "added 10.0.0.1"
	updated, _ := sv.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if updated.showAddPrompt {
		t.Error("Esc should close the add prompt")
	}
	if updated.addLastHint != "" {
		t.Errorf("Esc should clear addLastHint, got %q", updated.addLastHint)
	}
}

func TestSetView_EnterEmptyKey_RetriesWithError(t *testing.T) {
	sv := mkSetView(ipv4Set())
	sv, _ = sv.Update(runes("a"))
	updated, _ := sv.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !updated.showAddPrompt {
		t.Error("empty key must not close the prompt")
	}
	if updated.addErr != "key required" {
		t.Errorf("addErr = %q, want 'key required'", updated.addErr)
	}
}

func TestSetView_EnterBadKey_RetriesWithError(t *testing.T) {
	sv := mkSetView(ipv4Set())
	sv, _ = sv.Update(runes("a"))
	sv.addInput.SetValue("not-an-ip")
	updated, _ := sv.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !updated.showAddPrompt {
		t.Error("bad input must keep prompt open for retry")
	}
	if updated.addErr == "" {
		t.Error("expected addErr to surface the parse error")
	}
}

func TestSetView_EnterValidKey_KeepsPromptOpenForLoop(t *testing.T) {
	sv := mkSetView(ipv4Set())
	sv, _ = sv.Update(runes("a"))
	sv.addInput.SetValue("10.0.0.1")
	updated, cmd := sv.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !updated.showAddPrompt {
		t.Error("valid input must keep prompt open (bulk-add loop)")
	}
	if updated.addInput.Value() != "" {
		t.Errorf("addInput should be cleared after dispatch, got %q", updated.addInput.Value())
	}
	if updated.addLastHint != "added 10.0.0.1" {
		t.Errorf("addLastHint = %q, want 'added 10.0.0.1'", updated.addLastHint)
	}
	if cmd == nil {
		t.Error("Enter on valid input must return a tea.Cmd")
	}
}

func TestSetView_Map_TabSwitchesFocus(t *testing.T) {
	sv := mkSetView(ipv4ToMarkMap())
	sv, _ = sv.Update(runes("a"))
	if sv.addFocusVal {
		t.Fatal("focus must start on the key field")
	}
	updated, _ := sv.Update(tea.KeyMsg{Type: tea.KeyTab})
	if !updated.addFocusVal {
		t.Error("Tab should move focus to the value input")
	}
	if !updated.addValInput.Focused() {
		t.Error("addValInput should be focused after Tab")
	}
	if updated.addInput.Focused() {
		t.Error("addInput should be blurred after Tab")
	}
}

func TestSetView_Map_EnterEmptyValue_RetriesWithError(t *testing.T) {
	sv := mkSetView(ipv4ToMarkMap())
	sv, _ = sv.Update(runes("a"))
	sv.addInput.SetValue("10.0.0.1")
	// addValInput left empty
	updated, _ := sv.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !updated.showAddPrompt {
		t.Error("missing value must not close the prompt")
	}
	if updated.addErr != "value required" {
		t.Errorf("addErr = %q, want 'value required'", updated.addErr)
	}
}

func TestSetView_PressD_OpensDeleteConfirm(t *testing.T) {
	sv := mkSetView(ipv4Set())
	sv.elements = []nftables.SetElement{{Key: []byte{10, 0, 0, 1}}}
	updated, _ := sv.Update(runes("d"))
	if !updated.showDelete {
		t.Error("'d' on a non-empty list should open delete confirmation")
	}
	if !updated.IsModal() {
		t.Error("delete confirm should make IsModal true")
	}
}

func TestSetView_DeleteConfirm_NCancels(t *testing.T) {
	sv := mkSetView(ipv4Set())
	sv.elements = []nftables.SetElement{{Key: []byte{10, 0, 0, 1}}}
	sv, _ = sv.Update(runes("d"))
	updated, _ := sv.Update(runes("n"))
	if updated.showDelete {
		t.Error("'n' should cancel delete confirmation")
	}
}

func TestSetView_DeleteConfirm_YDispatches(t *testing.T) {
	sv := mkSetView(ipv4Set())
	sv.elements = []nftables.SetElement{{Key: []byte{10, 0, 0, 1}}}
	sv, _ = sv.Update(runes("d"))
	updated, cmd := sv.Update(runes("y"))
	if updated.showDelete {
		t.Error("'y' should close delete confirmation")
	}
	if cmd == nil {
		t.Error("'y' should dispatch a delete command")
	}
}

func TestSetView_PressD_EmptyList_NoModal(t *testing.T) {
	sv := mkSetView(ipv4Set())
	updated, _ := sv.Update(runes("d"))
	if updated.showDelete {
		t.Error("delete confirm must not open on empty list")
	}
}

// Regression: after a successful Enter sets addLastHint, an async kernel
// rejection (setOpErrMsg routed through main_window) must wipe the hint
// so the overlay doesn't claim success and failure simultaneously.
//
// main_window's setOpErrMsg handler calls setAddErr when the prompt is
// open; this exercises that helper directly.
func TestSetView_KernelError_WipesAddLastHint(t *testing.T) {
	sv := mkSetView(ipv4Set())
	sv, _ = sv.Update(runes("a"))
	sv.addInput.SetValue("10.0.0.1")
	sv, _ = sv.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if sv.addLastHint == "" {
		t.Fatal("addLastHint should be set after a successful Enter")
	}

	sv.setAddErr("element with same key already exists")
	if sv.addLastHint != "" {
		t.Errorf("hint not wiped on kernel error: %q", sv.addLastHint)
	}
	if sv.addErr == "" {
		t.Error("addErr should carry the kernel rejection")
	}
}

// Regression: a local parse error on the next Enter (user typed bad input
// after a prior success) must also clear the stale "added X" hint — same
// mutual-exclusion invariant as the kernel path.
func TestSetView_BadKeyAfterSuccess_WipesAddLastHint(t *testing.T) {
	sv := mkSetView(ipv4Set())
	sv, _ = sv.Update(runes("a"))
	sv.addInput.SetValue("10.0.0.1")
	sv, _ = sv.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if sv.addLastHint == "" {
		t.Fatal("addLastHint should be set after the first successful Enter")
	}

	sv.addInput.SetValue("not-an-ip")
	sv, _ = sv.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if sv.addLastHint != "" {
		t.Errorf("stale hint survived a parse error: %q", sv.addLastHint)
	}
	if sv.addErr == "" {
		t.Error("addErr should surface the parse error")
	}
}

// --- setCreate state-machine ----------------------------------------------

// mkSetCreate builds via the production constructor; it has no live deps.
func mkSetCreate() setCreate {
	t := &nftables.Table{Name: "t", Family: nftables.TableFamilyINet}
	return newSetCreate(t)
}

func TestSetCreate_InitialFocus(t *testing.T) {
	sc := mkSetCreate()
	if sc.focusSlot != 0 {
		t.Errorf("focusSlot = %d, want 0 (name)", sc.focusSlot)
	}
	if !sc.nameInput.Focused() {
		t.Error("nameInput should be focused initially")
	}
}

func TestSetCreate_NextSlotSkipsHiddenSlots(t *testing.T) {
	sc := mkSetCreate()
	// isMap=off → slots 3 (data type) and 4 (data width) are hidden,
	// so from 2 (is map) we jump straight to 5 (constant).
	if sc.isMap() {
		t.Fatal("isMap should default to off")
	}
	got := sc.nextSlot(2)
	if got != 5 {
		t.Errorf("nextSlot(2) on non-map = %d, want 5 (skip data type + data width)", got)
	}
}

func TestSetCreate_NextSlotMapShowsDataType(t *testing.T) {
	sc := mkSetCreate()
	sc.isMapSelect.Selected = indexOf(setOnOffOptions, "on")
	if !sc.isMap() {
		t.Fatal("isMap toggle failed")
	}
	got := sc.nextSlot(2)
	if got != 3 {
		t.Errorf("nextSlot(2) on map = %d, want 3", got)
	}
}

func TestSetCreate_NextSlotSkipsDataWidthForNonInteger(t *testing.T) {
	sc := mkSetCreate()
	sc.isMapSelect.Selected = indexOf(setOnOffOptions, "on")
	// Default data type is `mark` (not integer), so slot 4 hidden.
	got := sc.nextSlot(3)
	if got != 5 {
		t.Errorf("nextSlot(3) with map+mark = %d, want 5 (skip data width)", got)
	}
}

func TestSetCreate_NextSlotShowsDataWidthForInteger(t *testing.T) {
	sc := mkSetCreate()
	sc.isMapSelect.Selected = indexOf(setOnOffOptions, "on")
	sc.dataTypeSelect.Selected = indexOf(sc.dataTypeSelect.Options, "integer")
	got := sc.nextSlot(3)
	if got != 4 {
		t.Errorf("nextSlot(3) with map+integer = %d, want 4 (data width visible)", got)
	}
}

func TestSetCreate_PrevSlotWrap(t *testing.T) {
	sc := mkSetCreate()
	got := sc.prevSlot(0)
	if got != 8 {
		t.Errorf("prevSlot(0) = %d, want 8 (wrap)", got)
	}
}

func TestSetCreate_SaveEmptyName_StatusErr(t *testing.T) {
	sc := mkSetCreate()
	updated, cmd := sc.Update(tea.KeyMsg{Type: tea.KeyF2})
	if cmd != nil {
		t.Error("save with empty name must not dispatch a command")
	}
	if updated.statusMsg != "Name cannot be empty." {
		t.Errorf("statusMsg = %q, want 'Name cannot be empty.'", updated.statusMsg)
	}
}

func TestSetCreate_SaveValid_DispatchesCmd(t *testing.T) {
	sc := mkSetCreate()
	sc.nameInput = textinput.New()
	sc.nameInput.SetValue("myset")
	updated, cmd := sc.Update(tea.KeyMsg{Type: tea.KeyF2})
	if cmd == nil {
		t.Error("save with non-empty name must dispatch createSetCmd")
	}
	if updated.statusMsg != "" {
		t.Errorf("statusMsg should be empty after successful save, got %q", updated.statusMsg)
	}
}
