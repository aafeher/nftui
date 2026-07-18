package ui

// Localization coverage for the Spanish (es) and Brazilian Portuguese (pt-BR)
// catalogs (I18N-9): the chrome renders translated, and both languages'
// highlighted "[S]í" / "[S]im" confirm mnemonic actually works (the y/i/s
// handler alias). English is the default everywhere else, so each test
// restores it in t.Cleanup.

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/text/language"

	"nftui/i18n"
)

func TestI18n_MainChrome_Spanish(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.Spanish)

	if got := readOnlyBanner(true); !strings.Contains(got, "[SOLO LECTURA]") {
		t.Errorf("read-only banner not localized: %q", got)
	}
	if got := quitConfirmView(80, 24); !strings.Contains(got, "¿Seguro que quieres salir?") ||
		!strings.Contains(got, "[S]í / [N]o") {
		t.Errorf("quit dialog not localized: %q", got)
	}
}

func TestI18n_MainChrome_Portuguese(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.BrazilianPortuguese)

	if got := readOnlyBanner(true); !strings.Contains(got, "[SOMENTE LEITURA]") {
		t.Errorf("read-only banner not localized: %q", got)
	}
	if got := quitConfirmView(80, 24); !strings.Contains(got, "Tem certeza de que deseja sair?") ||
		!strings.Contains(got, "[S]im / [N]ão") {
		t.Errorf("quit dialog not localized: %q", got)
	}
}

// The quit dialog highlights [S]í in Spanish and [S]im in Portuguese; pressing
// 's' must therefore confirm the quit (return tea.Quit), not silently do
// nothing — the same handler alias as the Hungarian 'i'.
func TestI18n_QuitConfirm_SKeyQuits(t *testing.T) {
	m := sizedMainWindow(t)
	m.showQuitConfirm = true

	_, cmd := route(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	if cmd == nil {
		t.Fatal("quit-confirm 's' returned nil cmd, want tea.Quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("quit-confirm 's' returned %T, want tea.QuitMsg", cmd())
	}
}

// The tree delete dialog renders in Spanish, and its highlighted [S]í key
// confirms the delete (returns a delete cmd) — the same y/i/s alias as quit.
func TestI18n_DeleteConfirm_SpanishAndSKey(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.Spanish)

	tm := testTree()
	tm.width, tm.maxHeight = 90, 20
	tm.showDeleteConfirm = true // cursor is at the first table (root)

	if v := tm.View(); !strings.Contains(v, "¿Seguro que quieres eliminar") ||
		!strings.Contains(v, "[S]í / [N]o") {
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
