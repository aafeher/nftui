package ui

// Localization coverage for the French (fr) catalog (I18N-10): the chrome
// renders translated, and the highlighted "[O]ui" confirm mnemonic actually
// works (the y/i/s/o handler alias). English is the default everywhere else,
// so each test restores it in t.Cleanup.

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/text/language"

	"nftui/i18n"
)

func TestI18n_MainChrome_French(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.French)

	if got := readOnlyBanner(true); !strings.Contains(got, "[LECTURE SEULE]") {
		t.Errorf("read-only banner not localized: %q", got)
	}
	if got := quitConfirmView(80, 24); !strings.Contains(got, "Voulez-vous vraiment quitter ?") ||
		!strings.Contains(got, "[O]ui / [N]on") {
		t.Errorf("quit dialog not localized: %q", got)
	}
}

// The quit dialog highlights [O]ui in French; pressing 'o' must therefore
// confirm the quit (return tea.Quit), not silently do nothing — the same
// handler alias as the Hungarian 'i' and the Spanish/Portuguese 's'.
func TestI18n_QuitConfirm_OKeyQuits(t *testing.T) {
	m := sizedMainWindow(t)
	m.showQuitConfirm = true

	_, cmd := route(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'o'}})
	if cmd == nil {
		t.Fatal("quit-confirm 'o' returned nil cmd, want tea.Quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("quit-confirm 'o' returned %T, want tea.QuitMsg", cmd())
	}
}

// The tree delete dialog renders in French, and its highlighted [O]ui key
// confirms the delete (returns a delete cmd) — the same y/i/s/o alias as quit.
func TestI18n_DeleteConfirm_FrenchAndOKey(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.French)

	tm := testTree()
	tm.width, tm.maxHeight = 90, 20
	tm.showDeleteConfirm = true // cursor is at the first table (root)

	if v := tm.View(); !strings.Contains(v, "Voulez-vous vraiment supprimer") ||
		!strings.Contains(v, "[O]ui / [N]on") {
		t.Errorf("delete dialog not localized: %q", v)
	}

	tm2, cmd := step(t, tm, treeKey("o"))
	if cmd == nil {
		t.Fatal("delete-confirm 'o' returned nil cmd, want a delete cmd")
	}
	if tm2.showDeleteConfirm {
		t.Error("delete-confirm 'o' left the modal open")
	}
}
