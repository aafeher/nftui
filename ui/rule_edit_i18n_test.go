package ui

// Localization coverage for the rule editor (I18N-7). The editor chrome — the
// title, the tab bar, the generic section headers, the "(no X in this rule)"
// empty states, and the current:/or:/enable: connectives — translates under
// --lang hu. The nft attribute field labels (Verdict/Counter/IP src/CT State/…)
// stay English, matching the read-only rule view (I18N-4). English is the
// default, so each Hungarian test restores it in t.Cleanup.

import (
	"strings"
	"testing"

	"golang.org/x/text/language"

	"github.com/google/nftables"

	"nftui/i18n"
	"nftui/nft"
)

func TestI18n_RuleEdit_Hungarian(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.Hungarian)

	rule := harnessRule()
	re := newRuleEdit(rule, false)
	re.width, re.height = 120, 40
	rd, _ := nft.NftablesToRuleDefinition(rule)

	// Title (rendered in the fixed top of View).
	if v := re.View(); !strings.Contains(v, "| Szabály szerkesztése |") {
		t.Errorf("editor title not localized: %q", firstLines(v, 4))
	}

	// Tab bar: navigation chrome translates; CT/IP/Meta kept as nft abbreviations.
	assertContainsAll(t, re.renderTabBar(), []string{
		"Általános", "CT", "Hálózat", "IP", "Szállítás", "Meta", "Korlát",
	})

	// General tab: the current: connective and the Masquerade enable: toggle
	// translate; the Reject empty-state shows (harnessRule has no reject). The nft
	// attribute field labels stay English. (The "Actions:" header is conditional —
	// only leftover uncovered actions — and reuses the I18N-4 rule.general.actions
	// key, so it is not exercised here.)
	gen := re.renderGeneralTab(rd)
	assertContainsAll(t, gen, []string{
		"jelenlegi:", "aktív:", "(nincs reject ebben a szabályban)",
		"Verdict", "Counter", "Log", // nft attribute labels kept English
	})

	// IP tab: the "IPv4/IPv6 header" section headers translate; the protocol
	// token stays.
	assertContainsAll(t, re.renderIPTab(), []string{"IPv4 fejléc", "IPv6 fejléc"})
}

// An expr-less rule shows every General-tab action empty-state at once.
func TestI18n_RuleEdit_EmptyStates_Hungarian(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.Hungarian)

	rule := &nftables.Rule{Table: &nftables.Table{Name: "t", Family: nftables.TableFamilyINet}}
	re := newRuleEdit(rule, false)
	re.width, re.height = 120, 40
	rd, _ := nft.NftablesToRuleDefinition(rule)

	assertContainsAll(t, re.renderGeneralTab(rd), []string{
		"(nincs verdict ebben a szabályban)",
		"(nincs reject ebben a szabályban)",
		"(nincs log ebben a szabályban)",
		"(nincs counter ebben a szabályban)",
	})
}

// Byte-identical English default: no SetLanguage call means the editor reads
// exactly as before, keeping the existing rule_edit render tests green.
func TestI18n_RuleEdit_EnglishDefault(t *testing.T) {
	i18n.SetLanguage(i18n.English)

	rule := harnessRule()
	re := newRuleEdit(rule, false)
	re.width, re.height = 120, 40
	rd, _ := nft.NftablesToRuleDefinition(rule)

	if v := re.View(); !strings.Contains(v, "| Edit rule |") {
		t.Errorf("English editor title changed: %q", firstLines(v, 4))
	}
	assertContainsAll(t, re.renderTabBar(), []string{"General", "CT", "Network", "IP", "Transport", "Meta", "Limit"})
	assertContainsAll(t, re.renderGeneralTab(rd), []string{"current: ", "(no reject in this rule)", "enable:"})
	assertContainsAll(t, re.renderIPTab(), []string{"IPv4 header", "IPv6 header"})
}

// firstLines returns the first n lines of s, for compact failure messages.
func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
