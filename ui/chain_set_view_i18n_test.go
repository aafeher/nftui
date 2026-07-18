package ui

// Localization coverage for the chain view + set view (I18N-5). The metadata
// headers, prompts, bulk-add loop hints, and delete confirms translate under
// --lang hu — including the Hungarian "[I]gen" mnemonic (the y/i handler alias).
// The nft attribute field labels (Type/Hook/Policy/Key type/…) stay English, so
// each Hungarian test also asserts those survive. English is the default, so
// each test restores it in t.Cleanup.

import (
	"strings"
	"testing"

	"golang.org/x/text/language"

	"nftui/i18n"
)

func TestI18n_ChainView_Hungarian(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.Hungarian)

	cv := chainViewFixture(3, false)
	v := cv.View()

	// Metadata headers + stat boxes translate.
	assertContainsAll(t, v, []string{
		"Lánc: ", "lánc részletei", "tábla", "3 szabály",
		"Szabályok típus szerint:",
	})
	// nft attribute field labels stay English (same class as I18N-3).
	assertContainsAll(t, v, []string{"Table:", "Type:", "Hook:", "Policy:"})

	// Delete-rule confirm translates, and the highlighted [I]gen key confirms.
	cv.showDeleteConfirm = true
	assertContainsAll(t, cv.View(), []string{
		"Biztosan törölni akarod a kijelölt szabályt?", "[I]gen / [N]em",
	})
	cv2, cmd := cv.Update(treeKey("i"))
	if cmd == nil || cv2.showDeleteConfirm {
		t.Error("delete-confirm 'i' did not confirm in Hungarian")
	}
	cv.showDeleteConfirm = false

	// Filter-mode prompt suffixes: hint, no-match, and the match count.
	cv.enterFilter()
	if got := cv.View(); !strings.Contains(got, "gépelj a szabályok szűréséhez") {
		t.Errorf("filter hint not localized: %q", got)
	}
	cv.filterQuery = "zzzznomatch"
	if got := cv.View(); !strings.Contains(got, "nincs találat") {
		t.Errorf("no-match not localized: %q", got)
	}
	cv.filterQuery = "rule" // all three fixture rules carry a "rule x" comment
	if got := cv.View(); !strings.Contains(got, "3 találat") {
		t.Errorf("match count not localized: %q", got)
	}
}

func TestI18n_SetView_Hungarian(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.Hungarian)

	sv := setViewFixture(false)
	assertContainsAll(t, sv.View(), []string{"| Halmaz |", "Elemek (3):"})
	// nft attribute field labels stay English.
	assertContainsAll(t, sv.View(), []string{"Table:", "Name:", "Key type:"})

	// Empty set → localized element header + placeholder.
	empty := newSetViewWithElements(sv.set, sv.table, nil, false)
	empty.width, empty.height = 100, 40
	assertContainsAll(t, empty.View(), []string{"Elemek (0):", "(üres)"})

	// Add prompt (plain set): title + bulk-add hint translate.
	sv, _ = sv.Update(treeKey("a"))
	assertContainsAll(t, sv.View(), []string{"Elem hozzáadása:", "Enter: hozzáad (ciklus)"})
	// Enter with an empty key surfaces the localized validation error.
	sv, _ = sv.Update(treeKey("enter"))
	if sv.addErr != "kulcs kötelező" {
		t.Errorf("key-required not localized: %q", sv.addErr)
	}

	// Delete-element confirm translates, and [I]gen confirms.
	dsv := setViewFixture(false)
	dsv.showDelete = true // cursor at element 0
	assertContainsAll(t, dsv.View(), []string{"Törlöd a(z)", "[I]gen / [N]em"})
	dsv2, cmd := dsv.Update(treeKey("i"))
	if cmd == nil || dsv2.showDelete {
		t.Error("delete-confirm 'i' did not confirm in Hungarian (set)")
	}
}

func TestI18n_SetView_MapAddPrompt_Hungarian(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.Hungarian)

	mv := verdictMapFixture()
	mv, _ = mv.Update(treeKey("a"))
	assertContainsAll(t, mv.View(), []string{
		"Bejegyzés hozzáadása:", "Kulcs :", "Érték :", "Tab: mezőváltás",
	})

	// Key present, value empty → localized "value required".
	mv.addInput.SetValue("443")
	mv, _ = mv.Update(treeKey("enter"))
	if mv.addErr != "érték kötelező" {
		t.Errorf("value-required not localized: %q", mv.addErr)
	}
}

// Byte-identical English default: no SetLanguage call means the chain/set views
// read exactly as before (keeping the existing render tests green), and the
// original y/n confirm keys still work after adding the i/I alias.
func TestI18n_ChainSetView_EnglishDefault(t *testing.T) {
	i18n.SetLanguage(i18n.English)

	cv := chainViewFixture(3, false)
	assertContainsAll(t, cv.View(), []string{"Chain: ", " chain details", "Rules by type:", "3 rules"})

	cv.showDeleteConfirm = true
	if got := cv.View(); !strings.Contains(got, "[Y]es / [N]o") {
		t.Errorf("English rule confirm changed: %q", got)
	}
	cv2, cmd := cv.Update(treeKey("y"))
	if cmd == nil || cv2.showDeleteConfirm {
		t.Error("delete-confirm 'y' stopped working after adding the i alias")
	}

	sv := setViewFixture(false)
	assertContainsAll(t, sv.View(), []string{"| Set |", "Elements (3):"})
}
