package ui

// Localization coverage for the view footers (I18N-2). The whole ui test suite
// otherwise runs under the default English catalog, so these tests set the
// language explicitly and always restore English in t.Cleanup — the language is
// a process-global (startup-only in production), and no ui test runs in
// parallel, so the restore keeps the rest of the suite on English.

import (
	"strings"
	"testing"

	"golang.org/x/text/language"

	"nftui/i18n"
)

// The filter- and search-mode footers are built by chainFilterKeys() /
// treeSearchKeys(). They MUST be functions so their i18n.T lookups resolve at
// render time against the startup-selected language. As package-level vars they
// would bind to English at package-init and silently ignore --lang. This pins
// that they honour the language set after init.
func TestFooter_ModeKeymapsHonorLanguageAtRenderTime(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })

	i18n.SetLanguage(language.Hungarian)
	if got := chainFilterKeys().Exit.Help().Desc; got != "szűrő törlése" {
		t.Errorf("chainFilterKeys Exit desc = %q, want the Hungarian translation", got)
	}
	if got := treeSearchKeys().Exit.Help().Desc; got != "keresés vége" {
		t.Errorf("treeSearchKeys Exit desc = %q, want the Hungarian translation", got)
	}

	// Switching back is reflected immediately — proving the lookup is live, not
	// frozen at first call.
	i18n.SetLanguage(i18n.English)
	if got := chainFilterKeys().Exit.Help().Desc; got != "clear filter" {
		t.Errorf("chainFilterKeys Exit desc = %q, want English after switch back", got)
	}
}

// A localized footer renders as a single line: help.Model never wraps its
// ShortHelp, so a longer Hungarian translation cannot add vertical lines and
// push the view's content off the top of the screen. Width is handled by the
// frame clamp (TestMainWindow_FrameFitsTerminal); this guards the height axis
// and confirms the descriptions are actually translated.
func TestFooter_HungarianSingleLineAndTranslated(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.Hungarian)

	// The keymap binds its help text at construction, so build it under hu.
	footer := newHelpModel().View(newTableCreate().keys)

	if strings.Contains(footer, "\n") {
		t.Errorf("footer is multi-line — it would grow vertically:\n%s", footer)
	}
	if !strings.Contains(footer, "mentés") { // "save"
		t.Errorf("footer was not localized to Hungarian: %q", footer)
	}
	if !strings.Contains(footer, "kilépés") { // "quit"
		t.Errorf("footer missing the Hungarian 'quit': %q", footer)
	}
}

// English is the default: with no SetLanguage call the footers read exactly as
// the pre-i18n code did (byte-for-byte), which is what keeps every other ui
// render test green.
func TestFooter_EnglishDefaultUnchanged(t *testing.T) {
	// Defensive: ensure a prior test's Cleanup left us on English.
	i18n.SetLanguage(i18n.English)

	footer := newHelpModel().View(newTableCreate().keys)
	for _, want := range []string{"next field", "prev field", "save", "cancel", "quit"} {
		if !strings.Contains(footer, want) {
			t.Errorf("English footer missing %q: %q", want, footer)
		}
	}
}
