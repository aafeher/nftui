package ui

// Update state-machine tests for the chain create / edit dialogs, following
// the set_dialog_test.go pattern. Everything stays netlink-free: the F2 save
// path only *returns* the kernel-touching tea.Cmd (createChainCmd /
// updateChainCmd), which these tests never execute. The one cmd that IS
// executed — chainEdit's no-op save — is a pure closure emitting
// chainUpdatedMsg.

import (
	"errors"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/nftables"
)

var errTest = errors.New("kernel said no")

func chainDialogTable() *nftables.Table {
	return &nftables.Table{Name: "testtbl", Family: nftables.TableFamilyINet}
}

func chainDialogBaseChain(hook *nftables.ChainHook) *nftables.Chain {
	accept := nftables.ChainPolicyAccept
	return &nftables.Chain{
		Name:     "input",
		Table:    chainDialogTable(),
		Type:     nftables.ChainTypeFilter,
		Hooknum:  hook,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &accept,
	}
}

func keyMsg(t tea.KeyType) tea.KeyMsg { return tea.KeyMsg{Type: t} }

// --- chainCreate ---

func TestChainCreate_Defaults(t *testing.T) {
	cc := newChainCreate(chainDialogTable())

	if !cc.isBase() {
		t.Error("default kind should be base")
	}
	if got, want := cc.slotCount(), 6; got != want {
		t.Errorf("slotCount() = %d, want %d", got, want)
	}
	if got := cc.typeSelect.Value(); got != "filter" {
		t.Errorf("default type = %q, want filter", got)
	}
	if got := cc.hookSelect.Value(); got != "input" {
		t.Errorf("default hook = %q, want input", got)
	}
	if got := cc.prioInput.GetValue(); got != 0 {
		t.Errorf("default priority = %d, want 0", got)
	}
	if got := cc.policySelect.Value(); got != "accept" {
		t.Errorf("default policy = %q, want accept", got)
	}
	if cc.focusSlot != 0 {
		t.Errorf("initial focusSlot = %d, want 0 (name)", cc.focusSlot)
	}
}

func TestChainCreate_TabWrapsAround(t *testing.T) {
	cc := newChainCreate(chainDialogTable())
	for i := 1; i <= 5; i++ {
		cc, _ = cc.Update(keyMsg(tea.KeyTab))
		if cc.focusSlot != i {
			t.Fatalf("after %d tabs focusSlot = %d, want %d", i, cc.focusSlot, i)
		}
	}
	cc, _ = cc.Update(keyMsg(tea.KeyTab))
	if cc.focusSlot != 0 {
		t.Errorf("tab past last slot: focusSlot = %d, want 0 (wrap)", cc.focusSlot)
	}
	cc, _ = cc.Update(keyMsg(tea.KeyShiftTab))
	if cc.focusSlot != 5 {
		t.Errorf("shift+tab from slot 0: focusSlot = %d, want 5 (wrap back)", cc.focusSlot)
	}
}

func TestChainCreate_KindToggleShrinksSlots(t *testing.T) {
	cc := newChainCreate(chainDialogTable())
	cc, _ = cc.Update(keyMsg(tea.KeyTab)) // focus kind select

	cc, _ = cc.Update(keyMsg(tea.KeyLeft)) // base -> regular
	if cc.isBase() {
		t.Fatal("kind should be regular after KeyLeft")
	}
	if got, want := cc.slotCount(), 2; got != want {
		t.Errorf("regular slotCount() = %d, want %d", got, want)
	}

	cc, _ = cc.Update(keyMsg(tea.KeyRight)) // regular -> base
	if !cc.isBase() {
		t.Fatal("kind should be base after KeyRight")
	}
	if got, want := cc.slotCount(), 6; got != want {
		t.Errorf("base slotCount() = %d, want %d", got, want)
	}
}

func TestChainCreate_SaveEmptyNameRejected(t *testing.T) {
	cc := newChainCreate(chainDialogTable())
	cc, cmd := cc.Update(keyMsg(tea.KeyF2))
	if cmd != nil {
		t.Error("empty-name save returned a cmd, want nil")
	}
	if cc.statusMsg == "" {
		t.Error("empty-name save did not set statusMsg")
	}
}

// A chain name carrying nft-script metacharacters is rejected before any
// kernel cmd is produced (audit E-2 / S1). recreateBaseChain interpolates the
// chain name into an `nft -f -` script, so this is the injection guard.
func TestChainCreate_SaveRejectsInjectionName(t *testing.T) {
	cc := newChainCreate(chainDialogTable())
	cc.nameInput.SetValue("c; add rule inet t c drop")

	cc, cmd := cc.Update(keyMsg(tea.KeyF2))
	if cmd != nil {
		t.Error("injection name returned a kernel cmd, want nil")
	}
	if cc.statusMsg == "" {
		t.Error("injection name did not set statusMsg")
	}
}

func TestChainCreate_SaveValidNameReturnsCmd(t *testing.T) {
	cc := newChainCreate(chainDialogTable())
	cc, _ = cc.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("mychain")})

	cc, cmd := cc.Update(keyMsg(tea.KeyF2))
	if cmd == nil {
		t.Error("valid save returned nil cmd, want the create cmd")
	}
	if cc.statusMsg != "" {
		t.Errorf("valid save left statusMsg = %q, want empty", cc.statusMsg)
	}
	// cmd is createChainCmd — netlink on execution, deliberately not run.
}

func TestChainCreate_BuildSpec(t *testing.T) {
	cc := newChainCreate(chainDialogTable())

	spec := cc.buildSpec("basechain")
	if spec.Name != "basechain" {
		t.Errorf("spec.Name = %q", spec.Name)
	}
	if spec.Type != nftables.ChainTypeFilter {
		t.Errorf("spec.Type = %q, want filter", spec.Type)
	}
	if spec.Hooknum == nil {
		t.Error("base spec.Hooknum is nil")
	}
	if spec.Priority == nil || *spec.Priority != 0 {
		t.Errorf("spec.Priority = %v, want 0", spec.Priority)
	}
	if spec.Policy == nil || *spec.Policy != nftables.ChainPolicyAccept {
		t.Errorf("spec.Policy = %v, want accept", spec.Policy)
	}

	// Switch kind to regular: base-only fields must stay zero.
	cc, _ = cc.Update(keyMsg(tea.KeyTab))
	cc, _ = cc.Update(keyMsg(tea.KeyLeft))
	spec = cc.buildSpec("regchain")
	if spec.Type != "" || spec.Hooknum != nil || spec.Priority != nil || spec.Policy != nil {
		t.Errorf("regular spec has base-only fields set: %+v", spec)
	}
}

func TestChainCreate_TypeChangeSyncsHooks(t *testing.T) {
	cc := newChainCreate(chainDialogTable())

	// Move the hook to "forward" (valid for filter, invalid for nat):
	// slot 3 is the hook select.
	for i := 0; i < 3; i++ {
		cc, _ = cc.Update(keyMsg(tea.KeyTab))
	}
	cc, _ = cc.Update(keyMsg(tea.KeyRight)) // input -> forward
	if got := cc.hookSelect.Value(); got != "forward" {
		t.Fatalf("hook = %q after KeyRight, want forward", got)
	}

	// Back to the type select and switch filter -> nat.
	cc, _ = cc.Update(keyMsg(tea.KeyShiftTab))
	cc, _ = cc.Update(keyMsg(tea.KeyRight))
	if got := cc.typeSelect.Value(); got != "nat" {
		t.Fatalf("type = %q after KeyRight, want nat", got)
	}
	// forward is not a nat hook — the select must fall back to a valid one.
	if got := cc.hookSelect.Value(); got != "prerouting" {
		t.Errorf("hook after type change = %q, want prerouting (fallback)", got)
	}
}

func TestChainCreate_ErrMsgResizeAndView(t *testing.T) {
	cc := newChainCreate(chainDialogTable())
	cc, _ = cc.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	if cc.width != 100 || cc.height != 30 {
		t.Errorf("size = %dx%d, want 100x30", cc.width, cc.height)
	}

	cc, _ = cc.Update(chainOpErrMsg{err: errTest})
	if cc.statusMsg != errTest.Error() {
		t.Errorf("statusMsg = %q, want %q", cc.statusMsg, errTest.Error())
	}
	if v := cc.View(); v == "" {
		t.Error("base View() with error is empty")
	}

	cc, _ = cc.Update(keyMsg(tea.KeyTab))
	cc, _ = cc.Update(keyMsg(tea.KeyLeft)) // regular
	if v := cc.View(); v == "" {
		t.Error("regular View() is empty")
	}
}

// --- chainEdit ---

func TestChainEdit_BaseChainInit(t *testing.T) {
	ce := newChainEdit(chainDialogBaseChain(nftables.ChainHookInput))

	if !ce.isBase {
		t.Fatal("chain with Hooknum should be base")
	}
	if got, want := ce.slotCount, 5; got != want {
		t.Errorf("slotCount = %d, want %d", got, want)
	}
	if got := ce.nameInput.Value(); got != "input" {
		t.Errorf("name = %q, want input", got)
	}
	if got := ce.typeSelect.Value(); got != "filter" {
		t.Errorf("type = %q, want filter", got)
	}
	if got := ce.hookSelect.Value(); got != "input" {
		t.Errorf("hook = %q, want input", got)
	}
	if got := ce.prioInput.GetValue(); got != 0 {
		t.Errorf("priority = %d, want 0", got)
	}
	if got := ce.policySelect.Value(); got != "accept" {
		t.Errorf("policy = %q, want accept", got)
	}
}

func TestChainEdit_RegularChainInit(t *testing.T) {
	ce := newChainEdit(&nftables.Chain{Name: "dispatch", Table: chainDialogTable()})
	if ce.isBase {
		t.Fatal("chain without Hooknum should not be base")
	}
	if got, want := ce.slotCount, 1; got != want {
		t.Errorf("slotCount = %d, want %d", got, want)
	}
	if v := ce.View(); v == "" {
		t.Error("regular View() is empty")
	}
}

func TestChainEdit_TabWrapsAround(t *testing.T) {
	ce := newChainEdit(chainDialogBaseChain(nftables.ChainHookInput))
	for i := 1; i <= 4; i++ {
		ce, _ = ce.Update(keyMsg(tea.KeyTab))
		if ce.focusSlot != i {
			t.Fatalf("after %d tabs focusSlot = %d, want %d", i, ce.focusSlot, i)
		}
	}
	ce, _ = ce.Update(keyMsg(tea.KeyTab))
	if ce.focusSlot != 0 {
		t.Errorf("tab past last slot: focusSlot = %d, want 0 (wrap)", ce.focusSlot)
	}
	ce, _ = ce.Update(keyMsg(tea.KeyShiftTab))
	if ce.focusSlot != 4 {
		t.Errorf("shift+tab from slot 0: focusSlot = %d, want 4 (wrap back)", ce.focusSlot)
	}
}

func TestChainEdit_SaveEmptyNameRejected(t *testing.T) {
	ce := newChainEdit(chainDialogBaseChain(nftables.ChainHookInput))
	ce.nameInput.SetValue("")
	ce, cmd := ce.Update(keyMsg(tea.KeyF2))
	if cmd != nil {
		t.Error("empty-name save returned a cmd, want nil")
	}
	if ce.statusMsg == "" {
		t.Error("empty-name save did not set statusMsg")
	}
}

func TestChainEdit_NoopSaveSkipsKernel(t *testing.T) {
	ce := newChainEdit(chainDialogBaseChain(nftables.ChainHookInput))
	ce, cmd := ce.Update(keyMsg(tea.KeyF2))
	if cmd == nil {
		t.Fatal("no-op save returned nil cmd, want the back-navigation cmd")
	}
	// The no-op path returns a pure closure (no kernel write) — safe to run.
	if msg := cmd(); msg != (chainUpdatedMsg{}) {
		t.Errorf("no-op save cmd emitted %T, want chainUpdatedMsg", msg)
	}
	_ = ce
}

func TestChainEdit_ChangedNameReturnsCmd(t *testing.T) {
	ce := newChainEdit(chainDialogBaseChain(nftables.ChainHookInput))
	ce.nameInput.SetValue("renamed")
	ce, cmd := ce.Update(keyMsg(tea.KeyF2))
	if cmd == nil {
		t.Error("changed save returned nil cmd, want the update cmd")
	}
	if ce.statusMsg != "" {
		t.Errorf("changed save left statusMsg = %q, want empty", ce.statusMsg)
	}
	// cmd is updateChainCmd — netlink on execution, deliberately not run.
}

func TestChainEdit_HasChanges(t *testing.T) {
	base := chainDialogBaseChain(nftables.ChainHookInput)

	t.Run("unchanged base chain", func(t *testing.T) {
		ce := newChainEdit(base)
		if ce.hasChanges("input", ce.buildNewSpec("input")) {
			t.Error("hasChanges = true for untouched form")
		}
	})

	t.Run("renamed", func(t *testing.T) {
		ce := newChainEdit(base)
		if !ce.hasChanges("renamed", ce.buildNewSpec("renamed")) {
			t.Error("hasChanges = false after rename")
		}
	})

	t.Run("policy flipped", func(t *testing.T) {
		ce := newChainEdit(base)
		for i := 0; i < 4; i++ { // slot 4 = policy
			ce, _ = ce.Update(keyMsg(tea.KeyTab))
		}
		ce, _ = ce.Update(keyMsg(tea.KeyRight)) // accept -> drop
		if !ce.hasChanges("input", ce.buildNewSpec("input")) {
			t.Error("hasChanges = false after policy flip")
		}
	})

	t.Run("regular chain ignores base fields", func(t *testing.T) {
		ce := newChainEdit(&nftables.Chain{Name: "dispatch", Table: chainDialogTable()})
		if ce.hasChanges("dispatch", ce.buildNewSpec("dispatch")) {
			t.Error("hasChanges = true for untouched regular chain")
		}
		if !ce.hasChanges("renamed", ce.buildNewSpec("renamed")) {
			t.Error("hasChanges = false for renamed regular chain")
		}
	})
}

func TestChainEdit_TypeChangeInvalidHookMarksChanged(t *testing.T) {
	// Start on hook "forward" (valid for filter, invalid for nat).
	ce := newChainEdit(chainDialogBaseChain(nftables.ChainHookForward))
	if got := ce.hookSelect.Value(); got != "forward" {
		t.Fatalf("initial hook = %q, want forward", got)
	}

	ce, _ = ce.Update(keyMsg(tea.KeyTab))   // slot 1 = type
	ce, _ = ce.Update(keyMsg(tea.KeyRight)) // filter -> nat
	if got := ce.typeSelect.Value(); got != "nat" {
		t.Fatalf("type = %q, want nat", got)
	}
	if got := ce.hookSelect.Value(); got != "prerouting" {
		t.Errorf("hook fallback = %q, want prerouting", got)
	}
	if !ce.hookSelect.Changed {
		t.Error("hookSelect.Changed = false; the effective hook changed and must be flagged")
	}
}

func TestChainEdit_ErrMsgResizeAndView(t *testing.T) {
	ce := newChainEdit(chainDialogBaseChain(nftables.ChainHookInput))
	ce, _ = ce.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	if ce.width != 100 || ce.height != 30 {
		t.Errorf("size = %dx%d, want 100x30", ce.width, ce.height)
	}
	ce, _ = ce.Update(chainOpErrMsg{err: errTest})
	if ce.statusMsg != errTest.Error() {
		t.Errorf("statusMsg = %q, want %q", ce.statusMsg, errTest.Error())
	}
	if v := ce.View(); v == "" {
		t.Error("base View() with error is empty")
	}
}
