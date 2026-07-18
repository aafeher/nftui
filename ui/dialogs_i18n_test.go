package ui

// Localization coverage for the create/edit dialogs (I18N-6). The dialog titles,
// read-only hint lines, the Name/Family/Kind identifier labels, the set-create
// validation errors, and the shared error prefix translate under --lang hu. The
// nft keyword/attribute labels (Table/Type/Hook/Priority/Policy, Key type/Is map/
// Constant/…) stay English, matching the views (I18N-3/5). English is the default,
// so each Hungarian test restores it in t.Cleanup.

import (
	"strings"
	"testing"

	"golang.org/x/text/language"

	"github.com/google/nftables"

	"nftui/i18n"
)

func TestI18n_TableDialogs_Hungarian(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.Hungarian)

	tc := newTableCreate()
	tc.width, tc.height = 100, 40
	assertContainsAll(t, tc.View(), []string{"Új tábla létrehozása", "Család", "Név"})

	te := newTableEdit(&nftables.Table{Name: "filter", Family: nftables.TableFamilyINet})
	te.width, te.height = 100, 40
	v := te.View()
	assertContainsAll(t, v, []string{
		"Tábla szerkesztése", "Család", "Név",
		"csak olvasható", // family read-only hint
		"inet",           // family value stays an English nft token
	})
}

func TestI18n_ChainDialogs_Hungarian(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.Hungarian)

	table := &nftables.Table{Name: "t", Family: nftables.TableFamilyINet}

	// Create dialog defaults to a base chain, so Type/Hook/Priority/Policy show.
	cc := newChainCreate(table)
	cc.width, cc.height = 100, 40
	v := cc.View()
	assertContainsAll(t, v, []string{"Új lánc létrehozása", "Név", "Fajta"}) // translated
	assertContainsAll(t, v, []string{"Type", "Hook", "Priority", "Policy"})  // nft keywords kept

	accept := nftables.ChainPolicyAccept
	base := &nftables.Chain{
		Name: "input", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter, Policy: &accept,
	}
	ceb := newChainEdit(base)
	ceb.width, ceb.height = 100, 40
	assertContainsAll(t, ceb.View(), []string{"Lánc szerkesztése", "Név", "Type", "Policy"})

	// A regular chain (no hook) shows the localized "name only" hint.
	reg := &nftables.Chain{Name: "fwd", Table: table}
	cer := newChainEdit(reg)
	cer.width, cer.height = 100, 40
	if got := cer.View(); !strings.Contains(got, "sima lánc — csak a név szerkeszthető") {
		t.Errorf("regular-chain hint not localized: %q", got)
	}
}

func TestI18n_SetCreate_Hungarian(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.Hungarian)

	sc := newSetCreate(&nftables.Table{Name: "t", Family: nftables.TableFamilyINet})
	sc.width, sc.height = 100, 40
	v := sc.View()
	assertContainsAll(t, v, []string{"Új halmaz / map létrehozása", "Név"})                 // translated
	assertContainsAll(t, v, []string{"Table", "Key type", "Is map", "Constant", "Timeout"}) // kept English

	// The inline validation errors resolve to the Hungarian catalog (their
	// Update-path triggers aren't reachable with the always-valid Select options).
	if got := i18n.T("set.create.err_keytype"); got != "Ismeretlen kulcstípus." {
		t.Errorf("err_keytype = %q", got)
	}
	if got := i18n.T("set.create.err_intwidth"); got != "Érvénytelen egész-szélesség." {
		t.Errorf("err_intwidth = %q", got)
	}
}

// Byte-identical English default: no SetLanguage call means the dialogs read
// exactly as before (keeping the chain_dialog / table_edit tests green).
func TestI18n_Dialogs_EnglishDefault(t *testing.T) {
	i18n.SetLanguage(i18n.English)

	tc := newTableCreate()
	tc.width, tc.height = 100, 40
	assertContainsAll(t, tc.View(), []string{"Create new table", "Family : ", "Name   : "})

	table := &nftables.Table{Name: "t", Family: nftables.TableFamilyINet}
	cc := newChainCreate(table)
	cc.width, cc.height = 100, 40
	assertContainsAll(t, cc.View(), []string{"Create new chain", "Name     : ", "Kind     : ", "Type     : "})

	sc := newSetCreate(table)
	sc.width, sc.height = 100, 40
	assertContainsAll(t, sc.View(), []string{"Create new set / map", "Name      : ", "Key type  : "})
}
