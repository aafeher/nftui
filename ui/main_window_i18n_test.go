package ui

// Localization coverage for the main-window / tree chrome (I18N-3): the
// pure render helpers translate, and the Hungarian "[I]gen" confirm mnemonic
// actually works (the y/i handler alias). English is the default everywhere
// else, so each test restores it in t.Cleanup.

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/text/language"

	"nftui/i18n"
)

func TestI18n_MainChrome_Hungarian(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.Hungarian)

	if got := readOnlyBanner(true); !strings.Contains(got, "[CSAK OLVASHATÓ]") {
		t.Errorf("read-only banner not localized: %q", got)
	}
	if got := terminalTooSmallView(10, 10); !strings.Contains(got, "A terminál túl kicsi") {
		t.Errorf("terminal-too-small not localized: %q", got)
	}
	if got := quitConfirmView(80, 24); !strings.Contains(got, "Biztosan ki akarsz lépni?") ||
		!strings.Contains(got, "[I]gen / [N]em") {
		t.Errorf("quit dialog not localized: %q", got)
	}
	// The non-permission branch of loadErrorView uses the shared common.error
	// prefix ("Hiba: " in Hungarian).
	if got := loadErrorView(errors.New("boom")); !strings.Contains(got, "Hiba: ") {
		t.Errorf("generic error prefix not localized: %q", got)
	}
}

// The quit dialog highlights [I]gen in Hungarian; pressing 'i' must therefore
// confirm the quit (return tea.Quit), not silently do nothing.
func TestI18n_QuitConfirm_IKeyQuits(t *testing.T) {
	m := sizedMainWindow(t)
	m.showQuitConfirm = true

	_, cmd := route(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'i'}})
	if cmd == nil {
		t.Fatal("quit-confirm 'i' returned nil cmd, want tea.Quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("quit-confirm 'i' returned %T, want tea.QuitMsg", cmd())
	}
}

// The delete dialog renders in Hungarian, and its highlighted [I]gen key
// confirms the delete (returns a delete cmd) — the same y/i alias as quit.
func TestI18n_DeleteConfirm_HungarianAndIKey(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.Hungarian)

	tm := testTree()
	tm.width, tm.maxHeight = 90, 20
	tm.showDeleteConfirm = true // cursor is at the first table (root)

	if v := tm.View(); !strings.Contains(v, "Biztosan törölni akarod") ||
		!strings.Contains(v, "[I]gen / [N]em") {
		t.Errorf("delete dialog not localized: %q", v)
	}

	tm2, cmd := step(t, tm, treeKey("i"))
	if cmd == nil {
		t.Fatal("delete-confirm 'i' returned nil cmd, want a delete cmd")
	}
	if tm2.showDeleteConfirm {
		t.Error("delete-confirm 'i' left the modal open")
	}
}

// Byte-identical English default: with no SetLanguage call the chrome reads
// exactly as before, which is what keeps the other main-window render tests
// green.
func TestI18n_MainChrome_EnglishDefault(t *testing.T) {
	i18n.SetLanguage(i18n.English)

	if got := readOnlyBanner(true); !strings.Contains(got, "[READ-ONLY MODE]") {
		t.Errorf("English read-only banner changed: %q", got)
	}
	if got := quitConfirmView(80, 24); !strings.Contains(got, "Are you sure you want to quit?") ||
		!strings.Contains(got, "[Y]es / [N]o") {
		t.Errorf("English quit dialog changed: %q", got)
	}
}
