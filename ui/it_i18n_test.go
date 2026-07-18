package ui

// Localization coverage for the Italian (it) catalog (I18N-12): the chrome
// renders translated, and the highlighted "[S]ì" confirm mnemonic works via
// the existing unconditional s-alias (shared with Spanish [S]í and
// Portuguese [S]im) — no handler change was needed. English is the default
// everywhere else, so each test restores it in t.Cleanup.

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/text/language"

	"nftui/i18n"
)

func TestI18n_MainChrome_Italian(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.Italian)

	if got := readOnlyBanner(true); !strings.Contains(got, "[SOLA LETTURA]") {
		t.Errorf("read-only banner not localized: %q", got)
	}
	if got := quitConfirmView(80, 24); !strings.Contains(got, "Vuoi davvero uscire?") ||
		!strings.Contains(got, "[S]ì / [N]o") {
		t.Errorf("quit dialog not localized: %q", got)
	}
}

// With Italian active, the quit dialog highlights [S]ì — pressing 's' must
// confirm the quit (the shared s-alias, exercised under Italian).
func TestI18n_QuitConfirm_SKeyQuits_Italian(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.Italian)

	m := sizedMainWindow(t)
	m.showQuitConfirm = true

	_, cmd := route(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	if cmd == nil {
		t.Fatal("Italian quit-confirm 's' returned nil cmd, want tea.Quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("Italian quit-confirm 's' returned %T, want tea.QuitMsg", cmd())
	}
}

// The tree delete dialog renders in Italian, and its highlighted [S]ì key
// confirms the delete (returns a delete cmd).
func TestI18n_DeleteConfirm_ItalianAndSKey(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.Italian)

	tm := testTree()
	tm.width, tm.maxHeight = 90, 20
	tm.showDeleteConfirm = true // cursor is at the first table (root)

	if v := tm.View(); !strings.Contains(v, "Vuoi davvero eliminare") ||
		!strings.Contains(v, "[S]ì / [N]o") {
		t.Errorf("delete dialog not localized: %q", v)
	}

	tm2, cmd := step(t, tm, treeKey("s"))
	if cmd == nil {
		t.Fatal("delete-confirm 's' returned nil cmd, want a delete cmd")
	}
	if tm2.showDeleteConfirm {
		t.Error("delete-confirm 's' left the modal open")
	}
}
