package ui

// Generic FieldEditor contract harness. Every editor registered in
// newRuleEdit's tab list — all ~140 of them — is driven through the full
// FieldEditor interface (FocusSlots / Focus / Update / View / Blur / Changed
// / Save) twice: once constructed from a populated rule and once from an
// empty rule (the inert state). The harness asserts the structural contract
// (slots >= 1, View renders, no panic anywhere); per-editor value semantics
// are pinned by the targeted tests below and in the dedicated field tests.
//
// Everything here is netlink-free: newRuleEdit parses the rule in memory,
// and the F2 save path only *returns* the kernel-apply tea.Cmd — the harness
// never executes it.

import (
	"fmt"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// harnessRule returns a synthetic rule whose expressions populate the most
// common condition/action classes, so the editors constructed from it start
// in their "value present" state rather than all-inert.
func harnessRule() *nftables.Rule {
	comment := "harness"
	return &nftables.Rule{
		Table: &nftables.Table{Name: "harness", Family: nftables.TableFamilyINet},
		Exprs: []expr.Any{
			// ct state (cmp form)
			&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x02, 0x00, 0x00, 0x00}},
			// meta l4proto tcp
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
			// tcp dport 22
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 22}},
			// actions
			&expr.Counter{Packets: 1, Bytes: 64},
			&expr.Limit{Type: expr.LimitTypePkts, Rate: 10, Unit: expr.LimitTimeSecond, Burst: 5},
			&expr.Log{Data: []byte("harness")},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
		UserData: append([]byte{0, byte(len(comment) + 1)}, append([]byte(comment), 0)...),
	}
}

// driveEditor runs one FieldEditor through the full interface contract.
func driveEditor(t *testing.T, f FieldEditor, scratch *nftables.Rule) {
	t.Helper()

	if slots := f.FocusSlots(); slots < 1 {
		t.Fatalf("FocusSlots() = %d, want >= 1", slots)
	}
	if v := f.View(); v == "" {
		t.Error("View() returned empty string while blurred")
	}

	// FocusSlots can legitimately change while editing (e.g. VerdictField
	// grows a chain-target slot when the selection lands on jump/goto), so
	// re-read it every iteration instead of caching.
	for s := 0; s < f.FocusSlots(); s++ {
		f.Focus(s)
		_ = f.Update(tea.KeyMsg{Type: tea.KeyRight})
		_ = f.Update(tea.KeyMsg{Type: tea.KeyLeft})
		_ = f.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("1")})
		_ = f.Update(tea.KeyMsg{Type: tea.KeyBackspace})
		if v := f.View(); v == "" {
			t.Errorf("View() returned empty string while slot %d focused", s)
		}
	}

	f.Blur()
	_ = f.Changed()
	// Save must tolerate whatever state the key fuzzing above produced —
	// it either no-ops (not changed) or shapes exprs onto the scratch rule.
	f.Save(scratch)
}

func TestFieldEditors_Contract(t *testing.T) {
	scenarios := []struct {
		name string
		rule *nftables.Rule
	}{
		{"populated rule", harnessRule()},
		{"empty rule", &nftables.Rule{
			Table: &nftables.Table{Name: "harness", Family: nftables.TableFamilyINet},
		}},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			re := newRuleEdit(sc.rule, false)
			for ti, tab := range re.tabs {
				for fi, f := range tab.fields {
					name := fmt.Sprintf("%s/%02d_%T", tab.name, fi, f)
					t.Run(name, func(t *testing.T) {
						scratch := &nftables.Rule{Table: sc.rule.Table}
						driveEditor(t, f, scratch)
					})
				}
				_ = ti
			}
		})
	}
}

// TestRuleEdit_DriveTabsAndFields walks the whole editor shell: cycles every
// tab with F6, tabs through every focus slot (including the wrap-around),
// renders the View at each stop, and finishes with an F2 save. The tea.Cmd
// F2 returns (the kernel apply) is deliberately not executed.
func TestRuleEdit_DriveTabsAndFields(t *testing.T) {
	re := newRuleEdit(harnessRule(), false)
	re.width = 120
	re.height = 40

	if v := re.View(); v == "" {
		t.Fatal("initial View() is empty")
	}

	for range re.tabs {
		tab := re.tabs[re.activeTab]
		// +1 walks past the last slot to exercise the wrap-around.
		for s := 0; s <= editTabTotalSlots(tab); s++ {
			re, _ = re.Update(tea.KeyMsg{Type: tea.KeyTab})
			if v := re.View(); v == "" {
				t.Fatalf("View() empty on tab %q slot %d", tab.name, s)
			}
		}
		re, _ = re.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
		re, _ = re.Update(tea.KeyMsg{Type: tea.KeyF6})
	}

	var cmd tea.Cmd
	re, cmd = re.Update(tea.KeyMsg{Type: tea.KeyF2})
	if re.errStr != "" {
		t.Errorf("F2 save reported validation error: %s", re.errStr)
	}
	if cmd == nil {
		t.Error("F2 save returned no command (expected the apply cmd)")
	}
}

// TestVerdictField_SaveWritesVerdict pins one editor's full edit→save value
// path: moving the verdict Select one step (accept → drop) and saving must
// replace the rule's verdict expression.
func TestVerdictField_SaveWritesVerdict(t *testing.T) {
	rule := harnessRule()
	re := newRuleEdit(rule, false)

	var vf *VerdictField
	for _, tab := range re.tabs {
		for _, f := range tab.fields {
			if v, ok := f.(*VerdictField); ok {
				vf = v
			}
		}
	}
	if vf == nil {
		t.Fatal("no VerdictField registered in the editor tabs")
	}

	vf.Focus(0)
	_ = vf.Update(tea.KeyMsg{Type: tea.KeyRight}) // accept -> drop
	if !vf.Changed() {
		t.Fatal("Changed() = false after moving the verdict selection")
	}

	vf.Save(rule)

	found := false
	for _, e := range rule.Exprs {
		if v, ok := e.(*expr.Verdict); ok {
			found = true
			if v.Kind != expr.VerdictDrop {
				t.Errorf("saved verdict kind = %v, want VerdictDrop", v.Kind)
			}
		}
	}
	if !found {
		t.Error("no *expr.Verdict in rule.Exprs after Save")
	}
	if vf.Changed() {
		t.Error("Changed() = true after Save (should reset)")
	}
}
