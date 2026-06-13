package ui

// Save-path harness for the field editors. The contract harness in
// field_editor_harness_test.go fuzzes keys but undoes them (Right→Left,
// digit→Backspace), so most Save bodies short-circuit on !Changed(). This
// harness instead forces a net change on every slot and then Saves into a
// rule that carries the matching expressions, so each Save body's
// expr-finding loop actually runs. It asserts the contract (no panic, Save
// leaves a non-empty expr list) rather than exact bytes — the targeted tests
// pin the precise mutations.

import (
	"fmt"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// ctPair builds a Ct + Cmp pair for the given key and comparison data.
func ctPair(key expr.CtKey, data []byte) []expr.Any {
	return []expr.Any{
		&expr.Ct{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
	}
}

// allCtExprsRule returns a rule carrying one expression group per CT key the
// editors know about, so every CT field's Save loop finds its target. The
// bitwise-backed keys (state/status/eventmask/labels) use the Ct+Bitwise+Cmp
// shape; counters carry a Direction and 8-byte payload.
func allCtExprsRule() *nftables.Rule {
	exprs := []expr.Any{}

	exprs = append(exprs,
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Mask: []byte{0x06, 0, 0, 0}, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
	)
	exprs = append(exprs,
		&expr.Ct{Key: expr.CtKeySTATUS, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Mask: []byte{0x04, 0, 0, 0}, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
	)
	exprs = append(exprs,
		&expr.Ct{Key: expr.CtKeyEVENTMASK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Mask: []byte{0x01, 0, 0, 0}, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
	)
	exprs = append(exprs,
		&expr.Ct{Key: expr.CtKeyLABELS, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Mask: make([]byte, 16), Xor: make([]byte, 16)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 16)},
	)
	exprs = append(exprs, ctPair(expr.CtKeyDIRECTION, []byte{0})...)
	exprs = append(exprs, ctPair(expr.CtKeyMARK, []byte{0x10, 0, 0, 0})...)
	exprs = append(exprs, ctPair(expr.CtKeySECMARK, []byte{0x20, 0, 0, 0})...)
	exprs = append(exprs, ctPair(expr.CtKeyEXPIRATION, []byte{0, 0, 0, 30})...)
	exprs = append(exprs, ctPair(expr.CtKeyHELPER, []byte("ftp\x00"))...)
	exprs = append(exprs, ctPair(expr.CtKeyZONE, []byte{0x04, 0x00})...)
	exprs = append(exprs, ctPair(expr.CtKeyPROTOSRC, []byte{0x00, 0x50})...)
	exprs = append(exprs, ctPair(expr.CtKeyPROTODST, []byte{0x01, 0xbb})...)

	for _, key := range []expr.CtKey{expr.CtKeyBYTES, expr.CtKeyPKTS, expr.CtKeyAVGPKT} {
		exprs = append(exprs,
			&expr.Ct{Key: key, Register: 1, Direction: 0},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 0, 0, 0, 0, 0, 0, 100}},
		)
	}

	exprs = append(exprs,
		&expr.Connlimit{Count: 5, Flags: expr.NFT_CONNLIMIT_F_INV},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)

	return &nftables.Rule{
		Table: &nftables.Table{Name: "save_harness", Family: nftables.TableFamilyINet},
		Exprs: exprs,
	}
}

// forceChange drives every focus slot with keys that leave a net change:
// Right advances a Select, Space toggles a MultiSelect, the digit/letter runes
// append to a NumberInput / TextInput. None are undone.
func forceChange(f FieldEditor) {
	for s := 0; s < f.FocusSlots(); s++ {
		f.Focus(s)
		_ = f.Update(tea.KeyMsg{Type: tea.KeyRight})
		_ = f.Update(tea.KeyMsg{Type: tea.KeySpace})
		_ = f.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("9")})
		_ = f.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	}
	f.Blur()
}

func TestFieldEditors_SavePaths(t *testing.T) {
	rule := allCtExprsRule()
	re := newRuleEdit(rule, false)

	for _, tab := range re.tabs {
		for fi, f := range tab.fields {
			name := fmt.Sprintf("%s/%02d_%T", tab.name, fi, f)
			t.Run(name, func(t *testing.T) {
				forceChange(f)
				// Save into the shared CT-rich rule so the expr-finding loops
				// have a target. Different editors mutate different exprs, so
				// sharing the rule across sub-tests is safe.
				f.Save(rule)
			})
		}
	}

	if len(rule.Exprs) == 0 {
		t.Error("rule lost all expressions after the Save sweep")
	}
}

// TestCtMarkField_SaveMutatesCmp pins one numeric CT editor's full
// edit→save value path: typing a new mark and saving must rewrite the
// trailing Cmp's data and operator.
func TestCtMarkField_SaveMutatesCmp(t *testing.T) {
	rule := &nftables.Rule{
		Table: &nftables.Table{Name: "t", Family: nftables.TableFamilyINet},
		Exprs: ctPair(expr.CtKeyMARK, []byte{0x10, 0, 0, 0}),
	}
	re := newRuleEdit(rule, false)

	var mf *CtMarkField
	for _, tab := range re.tabs {
		for _, f := range tab.fields {
			if m, ok := f.(*CtMarkField); ok {
				mf = m
			}
		}
	}
	if mf == nil {
		t.Fatal("no CtMarkField registered")
	}

	mf.Focus(1) // value slot
	_ = mf.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("99")})
	if !mf.Changed() {
		t.Fatal("Changed() = false after typing a new mark")
	}

	mf.Save(rule)

	cmp, ok := rule.Exprs[1].(*expr.Cmp)
	if !ok {
		t.Fatal("second expr is no longer a Cmp")
	}
	// Mark is LE uint32; the value the editor read back must round-trip.
	got := uint32(cmp.Data[0]) | uint32(cmp.Data[1])<<8 | uint32(cmp.Data[2])<<16 | uint32(cmp.Data[3])<<24
	if got == 0x10 {
		t.Errorf("Cmp data unchanged (still 0x10) after Save")
	}
	if mf.Changed() {
		t.Error("Changed() = true after Save (should reset)")
	}
}
