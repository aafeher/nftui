package ui

// Localization coverage for the German (de) catalog (I18N-11): the chrome
// renders translated, and the highlighted "[J]a" confirm mnemonic works —
// but ONLY while German is the active language. Unlike the unconditional
// i/s/o aliases, "j" is language-gated (confirmYesJ): it is vim-down scroll
// muscle memory, so in every other language a stray "j" inside a confirm
// modal must stay inert instead of confirming. English is the default
// everywhere else, so each test restores it in t.Cleanup.

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/text/language"

	"nftui/i18n"
)

func TestI18n_MainChrome_German(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.German)

	if got := readOnlyBanner(true); !strings.Contains(got, "[NUR LESEN]") {
		t.Errorf("read-only banner not localized: %q", got)
	}
	if got := quitConfirmView(80, 24); !strings.Contains(got, "Möchten Sie wirklich beenden?") ||
		!strings.Contains(got, "[J]a / [N]ein") {
		t.Errorf("quit dialog not localized: %q", got)
	}
}

// With German active, the quit dialog highlights [J]a — pressing 'j' must
// confirm the quit (return tea.Quit).
func TestI18n_QuitConfirm_JKeyQuits_GermanOnly(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.German)

	m := sizedMainWindow(t)
	m.showQuitConfirm = true

	_, cmd := route(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	if cmd == nil {
		t.Fatal("German quit-confirm 'j' returned nil cmd, want tea.Quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("German quit-confirm 'j' returned %T, want tea.QuitMsg", cmd())
	}
}

// The language gate itself: in English (and every non-German language) 'j'
// inside the quit-confirm modal must stay inert — no quit, modal stays open.
// 'j' is vim-down muscle memory; an unconditional alias would let a stray
// scroll keystroke confirm the dialog.
func TestI18n_QuitConfirm_JKeyInert_WhenNotGerman(t *testing.T) {
	i18n.SetLanguage(i18n.English)

	m := sizedMainWindow(t)
	m.showQuitConfirm = true

	m2, cmd := route(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	if cmd != nil {
		t.Fatalf("English quit-confirm 'j' returned a cmd (%T), want nil (inert)", cmd())
	}
	if !m2.showQuitConfirm {
		t.Error("English quit-confirm 'j' closed the modal, want it left open")
	}
}

// The tree delete dialog renders in German, and its highlighted [J]a key
// confirms the delete; with English restored the same 'j' is inert again.
func TestI18n_DeleteConfirm_GermanJKey_AndGate(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.German)

	tm := testTree()
	tm.width, tm.maxHeight = 90, 20
	tm.showDeleteConfirm = true // cursor is at the first table (root)

	if v := tm.View(); !strings.Contains(v, "Möchten Sie die Tabelle") ||
		!strings.Contains(v, "[J]a / [N]ein") {
		t.Errorf("delete dialog not localized: %q", v)
	}

	tm2, cmd := step(t, tm, treeKey("j"))
	if cmd == nil {
		t.Fatal("German delete-confirm 'j' returned nil cmd, want a delete cmd")
	}
	if tm2.showDeleteConfirm {
		t.Error("German delete-confirm 'j' left the modal open")
	}

	// Gate check on the same modal: with English active, 'j' must be inert.
	i18n.SetLanguage(i18n.English)
	tm3 := testTree()
	tm3.width, tm3.maxHeight = 90, 20
	tm3.showDeleteConfirm = true

	tm4, cmd := step(t, tm3, treeKey("j"))
	if cmd != nil {
		t.Fatalf("English delete-confirm 'j' returned a cmd (%T), want nil (inert)", cmd())
	}
	if !tm4.showDeleteConfirm {
		t.Error("English delete-confirm 'j' closed the modal, want it left open")
	}
}
