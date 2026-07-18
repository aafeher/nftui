package ui

// Localization coverage for the rule view (I18N-4). The render*Tab helpers,
// the tab bar, and the title translate under --lang hu, while the copy-pasteable
// nft syntax tokens (CT/address/meta descriptors, verdict/counter/reject values)
// stay English so a Hungarian user can still transcribe them into `nft`.
// English is the default, so each test restores it in t.Cleanup.

import (
	"strings"
	"testing"

	"golang.org/x/text/language"

	"nftui/i18n"
	"nftui/nft"
	nftexpr "nftui/nft/expr"

	"github.com/google/nftables/expr"
)

// A rule exercising every tab's translatable chrome and enough nft tokens to
// prove the domain terms are kept English.
func i18nRuleFixture() *nft.Rule {
	return &nft.Rule{
		Position: 7,
		Comment:  "audit me",
		Counter:  &nft.CounterStats{Packets: 12, Bytes: 3400},
		Actions: []nft.Action{
			{Type: nft.ActionTypeVerdict, Verdict: &nft.VerdictAction{Kind: nft.VerdictJump, Chain: "dispatch"}},
			{Type: nft.ActionTypeCounter, Counter: &nft.CounterAction{Name: "web_ctr"}},
		},
		Conditions: []nft.Condition{
			// CT: one present key; the rest render as the (empty) placeholder.
			{Operation: nft.CompareOpEq, CT: &nft.CTCondition{Key: nftexpr.CtKeyZone, Value: uint16(4)}},
			// Network group headers: an IP extra, a transport extra, an exthdr,
			// an sctp chunk, and a non-dedicated meta condition.
			{Operation: nft.CompareOpEq, Payload: &nft.PayloadCondition{Protocol: nft.PayloadProtoIP, Field: "ttl", Value: uint8(64)}},
			{Operation: nft.CompareOpEq, Payload: &nft.PayloadCondition{Protocol: nft.PayloadProtoTCP, Field: "dport", Value: &nft.PortSpec{Port: 443}}},
			{Operation: nft.CompareOpEq, Exthdr: &nft.ExthdrCondition{Proto: "frag", Field: "id", Value: uint32(7)}},
			{Operation: nft.CompareOpEq, SctpChunk: &nft.SctpChunkCondition{}},
			{Operation: nft.CompareOpEq, Meta: &nft.MetaCondition{Key: nft.MetaKeyMark, Value: uint32(2)}},
		},
	}
}

func TestI18n_RuleView_Hungarian(t *testing.T) {
	t.Cleanup(func() { i18n.SetLanguage(i18n.English) })
	i18n.SetLanguage(language.Hungarian)

	r := ruleViewFixture()
	r.width = 100
	rd := i18nRuleFixture()

	// Title + tab bar: navigation chrome translates; "CT" kept as an abbreviation.
	if got := r.topPart(); !strings.Contains(got, "| Szabály megtekintése |") {
		t.Errorf("title not localized: %q", got)
	}
	assertContainsAll(t, r.renderTabBar(), []string{"Általános", "CT", "Hálózat", "Korlát"})

	// General tab: metadata labels translate, nft action tokens stay English.
	gen := r.renderGeneralTab(rd)
	assertContainsAll(t, gen, []string{
		"Pozíció:", "7",
		"Megjegyzés:", "audit me",
		"Műveletek:",
		"Számláló:", "12 packets, 3400 bytes",
		"verdict:", "jump", "dispatch", // nft syntax kept
		"counter: web_ctr", // nft syntax kept
	})

	// CT tab: the (empty) placeholder translates; the `CT <key>` descriptor
	// (which mirrors `ct zone` nft syntax) stays English.
	ct := r.renderCTTab(rd)
	assertContainsAll(t, ct, []string{"CT zone:", "4", "(üres)"})

	// Network tab: group headers translate; the address / meta descriptors and
	// the copy-pasteable payload lines stay English.
	net := r.renderNetworkTab(rd)
	assertContainsAll(t, net, []string{
		"IP / IP6 fejléc:", "ip ttl 64", // header translated, token kept
		"Szállítási réteg", "tcp dport 443",
		"IPv6 kiterjesztésfejlécek:", "frag id 7",
		"SCTP chunk-ok:", "sctp chunk",
		"Meta feltételek:", "meta mark 2",
		"IP src:", "(üres)", // address descriptor + placeholder
		"Meta iifname:", // meta descriptor kept English
	})

	// Limit tab: the empty-state placeholder translates; when populated the
	// field labels (nft limit attributes) stay English.
	if empty := r.renderLimitTab(&nft.Rule{}); !strings.Contains(empty, "(Nincs korlát feltétel)") {
		t.Errorf("empty limit tab not localized: %q", empty)
	}
	limited := r.renderLimitTab(&nft.Rule{Conditions: []nft.Condition{
		{Limit: &expr.Limit{Over: true, Rate: 10, Unit: expr.LimitTimeMinute, Burst: 5, Type: expr.LimitTypePkts}},
	}})
	assertContainsAll(t, limited, []string{"Over", "Rate", "Unit", "Burst", "Type", "minute", "packets"})
}

// Byte-identical English default: with no SetLanguage call the rule view reads
// exactly as before, keeping the existing rule_view render tests green.
func TestI18n_RuleView_EnglishDefault(t *testing.T) {
	i18n.SetLanguage(i18n.English)

	r := ruleViewFixture()
	r.width = 100

	if got := r.topPart(); !strings.Contains(got, "| View rule |") {
		t.Errorf("English title changed: %q", got)
	}
	assertContainsAll(t, r.renderTabBar(), []string{"General", "CT", "Network", "Limit"})
	if got := r.renderLimitTab(&nft.Rule{}); !strings.Contains(got, "(No limit conditions)") {
		t.Errorf("English limit placeholder changed: %q", got)
	}
	if got := r.renderCTTab(&nft.Rule{}); !strings.Contains(got, "(empty)") {
		t.Errorf("English (empty) placeholder changed: %q", got)
	}
}
