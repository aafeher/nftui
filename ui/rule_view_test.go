package ui

// Rendering tests for ruleView. The render*Tab methods take the parsed
// *nft.Rule directly, so every branch is reachable with hand-built
// Condition/Action structs — no netlink, no parser dependency (the parser
// has its own tests in nft/). Assertions use strings.Contains on plain
// tokens because lipgloss styling may or may not emit ANSI codes depending
// on the terminal environment.

import (
	"net"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"nftui/nft"
	nftexpr "nftui/nft/expr"
)

func ruleViewFixture() ruleView {
	return newRuleView(&nftables.Rule{
		Table: &nftables.Table{Name: "t", Family: nftables.TableFamilyIPv4},
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
}

func assertContainsAll(t *testing.T, got string, tokens []string) {
	t.Helper()
	for _, tok := range tokens {
		if !strings.Contains(got, tok) {
			t.Errorf("output missing %q\n--- output ---\n%s", tok, got)
		}
	}
}

func TestRuleView_TabCyclingAndView(t *testing.T) {
	r := ruleViewFixture()
	r, _ = r.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
	if r.width != 100 || r.height != 40 {
		t.Fatalf("size = %dx%d, want 100x40", r.width, r.height)
	}

	// All four tabs render through View(); f6 wraps back to the first.
	for i := 0; i < ruleViewTabCount; i++ {
		if v := r.View(); v == "" {
			t.Fatalf("View() empty on tab %d", r.activeTab)
		}
		r, _ = r.Update(tea.KeyMsg{Type: tea.KeyF6})
	}
	if r.activeTab != 0 {
		t.Errorf("after %d f6 presses activeTab = %d, want 0 (wrap)", ruleViewTabCount, r.activeTab)
	}
	r, _ = r.Update(tea.KeyMsg{Type: tea.KeyF5})
	if r.activeTab != ruleViewTabCount-1 {
		t.Errorf("f5 from tab 0: activeTab = %d, want %d (wrap back)", r.activeTab, ruleViewTabCount-1)
	}

	bar := r.renderTabBar()
	assertContainsAll(t, bar, []string{"General", "CT", "Network", "Limit"})
}

// TestRuleView_Scroll pins ROADMAP B-3 Phase 2b rule-view scrolling: on a short
// terminal the read-only body scrolls with Up/Down, the frame stays within the
// terminal, the offset clamps at both ends, and switching tabs resets it.
func TestRuleView_Scroll(t *testing.T) {
	r := ruleViewFixture()
	r, _ = r.Update(tea.WindowSizeMsg{Width: 80, Height: 13}) // tiny → body overflows
	if r.maxScroll() <= 0 {
		t.Fatalf("expected the body to overflow at height 13, got maxScroll=%d", r.maxScroll())
	}
	max := r.maxScroll()

	// Scrolling down past the end clamps at maxScroll, and the frame still fits.
	for i := 0; i < max+5; i++ {
		r, _ = r.Update(tea.KeyMsg{Type: tea.KeyDown})
	}
	if r.scrollOffset != max {
		t.Errorf("scrollOffset = %d after scrolling down, want clamp at %d", r.scrollOffset, max)
	}
	if h := lipgloss.Height(r.View()); h > 13 {
		t.Errorf("frame is %d lines at height 13, want <= 13", h)
	}

	// Scrolling back up clamps at 0.
	for i := 0; i < max+5; i++ {
		r, _ = r.Update(tea.KeyMsg{Type: tea.KeyUp})
	}
	if r.scrollOffset != 0 {
		t.Errorf("scrollOffset = %d after scrolling up, want 0", r.scrollOffset)
	}

	// Switching tabs resets the scroll.
	r, _ = r.Update(tea.KeyMsg{Type: tea.KeyDown})
	r, _ = r.Update(tea.KeyMsg{Type: tea.KeyF6})
	if r.scrollOffset != 0 {
		t.Errorf("scrollOffset = %d after tab switch, want 0 (reset)", r.scrollOffset)
	}
}

func TestRenderGeneralTab(t *testing.T) {
	r := ruleViewFixture()
	rd := &nft.Rule{
		Position: 7,
		Comment:  "audit me",
		Counter:  &nft.CounterStats{Packets: 12, Bytes: 3400},
		Actions: []nft.Action{
			{Type: nft.ActionTypeVerdict, Verdict: &nft.VerdictAction{Kind: nft.VerdictJump, Chain: "dispatch"}},
			{Type: nft.ActionTypeCounter, Counter: &nft.CounterAction{Name: "web_ctr"}},
			{Type: nft.ActionTypeCounter, Counter: &nft.CounterAction{}},
			{Type: nft.ActionTypeNAT, NAT: &nft.NATAction{}},
			{Type: nft.ActionTypeLog, Log: &nft.LogAction{Prefix: "pfx"}},
			{Type: nft.ActionTypeQueue, Queue: &nft.QueueAction{Num: 3}},
			{Type: nft.ActionTypeReject, Reject: &nft.RejectAction{Type: nft.RejectTypeTCPReset}},
			{Type: nft.ActionTypeSet, Set: &nft.SetAction{SetName: "dynset"}},
			{Type: nft.ActionTypeRedirect, Redirect: &nft.RedirectAction{}},
			{Type: nft.ActionTypeMasq, Masq: &nft.MasqueradeAction{}},
			{Type: nft.ActionTypeQuota, Quota: &nft.QuotaAction{}},
			{Type: nft.ActionTypeObjref, Objref: &nft.ObjrefAction{Type: 1, Name: "ctr"}},
			{Type: nft.ActionTypeCustom, Custom: &nft.CustomAction{}},
		},
	}

	got := r.renderGeneralTab(rd)
	assertContainsAll(t, got, []string{
		"Position:", "7",
		"Comment:", "audit me",
		"Actions:",
		"verdict:", "jump", "dispatch",
		"counter: web_ctr",
		"log", "pfx",
		"reject",
		"@dynset",
		"redirect:",
		"counter name", "ctr",
		"custom:",
		"Counter:", "12 packets, 3400 bytes",
	})
}

func TestRenderCTTab(t *testing.T) {
	r := ruleViewFixture()
	rd := &nft.Rule{
		Conditions: []nft.Condition{
			{Operation: nft.CompareOpEq, CT: &nft.CTCondition{Key: nftexpr.CtKeyState, Value: []nftexpr.CtState{"established", "related"}}},
			{Operation: nft.CompareOpNeq, CT: &nft.CTCondition{Key: nftexpr.CtKeyDirection, Value: nftexpr.CtDirection("original")}},
			{Operation: nft.CompareOpEq, CT: &nft.CTCondition{Key: nftexpr.CtKeyMark, Value: uint32(0xdeadbeef)}},
			{Operation: nft.CompareOpEq, CT: &nft.CTCondition{Key: nftexpr.CtKeyZone, Value: uint16(4)}},
			{Operation: nft.CompareOpEq, CT: &nft.CTCondition{Key: nftexpr.CtKeyBytes, Value: uint64(1024), Direction: nftexpr.CtDirectionOriginal}},
			{Operation: nft.CompareOpEq, CT: &nft.CTCondition{Key: nftexpr.CtKeyPkts, Value: &nft.RangeValue{From: uint64(1), To: uint64(9)}, Direction: nftexpr.CtDirectionReply}},
			{Operation: nft.CompareOpEq, CT: &nft.CTCondition{Key: nftexpr.CtKeyExpiration, Value: uint32(30000)}},
			{Operation: nft.CompareOpEq, CT: &nft.CTCondition{Key: nftexpr.CtKeyEventMask, Value: []string{"new", "destroy"}}},
			{Operation: nft.CompareOpEq, CT: &nft.CTCondition{Key: nftexpr.CtKeyHelper, Value: "ftp"}},
			{Operation: nft.CompareOpEq, CT: &nft.CTCondition{Key: nftexpr.CtKeyAvgpkt, Value: &nft.SetValue{Elements: []any{uint64(100), uint64(200)}}}},
			{Operation: nft.CompareOpEq, Connlimit: &expr.Connlimit{Count: 5, Flags: expr.NFT_CONNLIMIT_F_INV}},
		},
	}

	got := r.renderCTTab(rd)
	assertContainsAll(t, got, []string{
		"{established, related}",
		"!= original",
		"0xdeadbeef",
		"CT zone:", "4",
		"CT original bytes:", "1024",
		"CT reply pkts:", "1-9",
		"CT expiration:",
		"bits {new,destroy}",
		"ftp",
		"{100, 200}",
		"CT count:", "over 5",
		"(empty)", // keys not present render as placeholders
	})

	// Plain connlimit (flags 0) renders without the "over" prefix —
	// "over" belongs to NFT_CONNLIMIT_F_INV, matching nft CLI encoding.
	plain := &nft.Rule{Conditions: []nft.Condition{
		{Connlimit: &expr.Connlimit{Count: 3}},
	}}
	if got := r.renderCTTab(plain); strings.Contains(got, "over 3") {
		t.Error("plain connlimit (flags 0) must not render as \"over\"")
	}
}

func TestRenderNetworkTab(t *testing.T) {
	r := ruleViewFixture()
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	rd := &nft.Rule{
		Conditions: []nft.Condition{
			{Operation: nft.CompareOpEq, Payload: &nft.PayloadCondition{Protocol: nft.PayloadProtoIP, Field: "saddr", Value: &nft.IPAddress{Subnet: cidr}}},
			{Operation: nft.CompareOpNeq, Payload: &nft.PayloadCondition{Protocol: nft.PayloadProtoIP, Field: "daddr", Value: &nft.IPAddress{IP: net.ParseIP("192.0.2.1")}}},
			{Operation: nft.CompareOpEq, Payload: &nft.PayloadCondition{Protocol: nft.PayloadProtoIP, Field: "ttl", Value: uint8(64)}},
			{Operation: nft.CompareOpEq, Payload: &nft.PayloadCondition{Protocol: nft.PayloadProtoTCP, Field: "dport", Value: &nft.PortSpec{Port: 443}}},
			{Operation: nft.CompareOpEq, Payload: &nft.PayloadCondition{Protocol: nft.PayloadProtoUDP, Field: "length", Value: uint16(512)}},
			{Operation: nft.CompareOpEq, Payload: &nft.PayloadCondition{Protocol: nft.PayloadProtoEther, Field: "type", Value: uint16(0x0806)}},
			{Operation: nft.CompareOpEq, Payload: &nft.PayloadCondition{Protocol: nft.PayloadProtoARP, Field: "operation", Value: uint16(1)}},
			{Operation: nft.CompareOpEq, Payload: &nft.PayloadCondition{Protocol: nft.PayloadProtoVlan, Field: "id", Value: uint16(100)}},
			{Operation: nft.CompareOpEq, Exthdr: &nft.ExthdrCondition{Proto: "frag", Field: "id", Value: uint32(7)}},
			{Operation: nft.CompareOpEq, SctpChunk: &nft.SctpChunkCondition{}},
			{Operation: nft.CompareOpEq, SctpChunk: &nft.SctpChunkCondition{Field: "tsn", Value: uint32(1000)}},
			{Operation: nft.CompareOpEq, Meta: &nft.MetaCondition{Key: nft.MetaKeyIIfName, Value: "eth0"}},
			{Operation: nft.CompareOpEq, Meta: &nft.MetaCondition{Key: nft.MetaKeyMark, Value: uint32(2)}},
			{Negate: true, SetLookup: &nft.SetLookupCondition{SetName: "blocklist", Field: "ip saddr"}},
			{Custom: &nft.CustomCondition{Expression: "weird"}},
		},
	}

	got := r.renderNetworkTab(rd)
	assertContainsAll(t, got, []string{
		"IP src:", "10.0.0.0/8",
		"IP dst:", "!= 192.0.2.1",
		"IP6 src:", "(empty)",
		"ip ttl 64",
		"tcp dport 443",
		"udp length 512",
		"Ether type:", "0x0806",
		"ARP operation:",
		"VLAN id:", "100",
		"IPv6 extension headers:", "frag id 7",
		"SCTP chunks:", "sctp chunk", "tsn 1000",
		"Meta iifname:", `"eth0"`,
		"Meta conditions:", "meta mark 2",
		"ip saddr", "!= @blocklist",
		"custom:",
	})
}

func TestRenderLimitTab(t *testing.T) {
	r := ruleViewFixture()

	empty := r.renderLimitTab(&nft.Rule{})
	if !strings.Contains(empty, "(No limit conditions)") {
		t.Errorf("empty limit tab = %q, want placeholder", empty)
	}

	rd := &nft.Rule{Conditions: []nft.Condition{
		{Limit: &expr.Limit{Over: true, Rate: 10, Unit: expr.LimitTimeMinute, Burst: 5, Type: expr.LimitTypePkts}},
	}}
	got := r.renderLimitTab(rd)
	assertContainsAll(t, got, []string{
		"Over", "true",
		"Rate", "10",
		"Unit", "minute",
		"Burst", "5",
		"Type", "packets",
	})
}

func TestRenderVerdict(t *testing.T) {
	tests := []struct {
		verdict nft.VerdictAction
		want    string
	}{
		{nft.VerdictAction{Kind: nft.VerdictAccept}, "accept"},
		{nft.VerdictAction{Kind: nft.VerdictDrop}, "drop"},
		{nft.VerdictAction{Kind: nft.VerdictReturn}, "return"},
		{nft.VerdictAction{Kind: nft.VerdictJump, Chain: "x"}, "jump x"},
		{nft.VerdictAction{Kind: nft.VerdictGoto}, "goto"},
		{nft.VerdictAction{Kind: nft.VerdictKind("mystery")}, "mystery"},
	}
	for _, tt := range tests {
		if got := renderVerdict(tt.verdict); !strings.Contains(got, tt.want) {
			t.Errorf("renderVerdict(%v) = %q, want containing %q", tt.verdict, got, tt.want)
		}
	}
}

func TestRenderReject(t *testing.T) {
	tests := []struct {
		name    string
		action  nft.RejectAction
		family  nftables.TableFamily
		want    string
		wantNot string
	}{
		{"tcp reset", nft.RejectAction{Type: nft.RejectTypeTCPReset}, nftables.TableFamilyIPv4, "with tcp reset", ""},
		{"icmp named code", nft.RejectAction{Type: nft.RejectTypeICMP, Code: 13}, nftables.TableFamilyIPv4, "with icmp admin-prohibited", ""},
		{"icmp default code elided", nft.RejectAction{Type: nft.RejectTypeICMP, Code: 3}, nftables.TableFamilyIPv4, "reject", "with"},
		{"icmp on ip6 family", nft.RejectAction{Type: nft.RejectTypeICMP, Code: 0}, nftables.TableFamilyIPv6, "with icmpv6 no-route", ""},
		{"icmp on inet family", nft.RejectAction{Type: nft.RejectTypeICMP, Code: 0}, nftables.TableFamilyINet, "with icmpx no-route", ""},
		{"explicit icmpv6", nft.RejectAction{Type: nft.RejectTypeICMPv6, Code: 5}, nftables.TableFamilyIPv6, "with icmpv6 policy-fail", ""},
		{"explicit icmpx", nft.RejectAction{Type: nft.RejectTypeICMPX, Code: 3}, nftables.TableFamilyINet, "with icmpx admin-prohibited", ""},
		{"unknown type", nft.RejectAction{Type: nft.RejectType("???")}, nftables.TableFamilyIPv4, "reject", "with"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := renderReject(tt.action, tt.family)
			if !strings.Contains(got, tt.want) {
				t.Errorf("renderReject() = %q, want containing %q", got, tt.want)
			}
			if tt.wantNot != "" && strings.Contains(got, tt.wantNot) {
				t.Errorf("renderReject() = %q, must not contain %q", got, tt.wantNot)
			}
		})
	}
}

func TestLookupRejectCodeName(t *testing.T) {
	if got := lookupRejectCodeName(icmpRejectCodes, 13); got != "admin-prohibited" {
		t.Errorf("known code = %q", got)
	}
	if got := lookupRejectCodeName(icmpRejectCodes, 200); got != "200" {
		t.Errorf("unknown code = %q, want numeric fallback", got)
	}
}

func TestRenderLog(t *testing.T) {
	full := renderLog(nft.LogAction{
		Prefix: "audit", Group: 2, Snaplen: 128, QThreshold: 10, Level: nft.LogLevelDebug,
	})
	assertContainsAll(t, full, []string{
		"log", `"audit"`, "group", "2", "snaplen", "128", "queue-threshold", "10", "level", "debug",
	})

	// The default level (warn) is elided, like nft list does.
	warned := renderLog(nft.LogAction{Level: nft.LogLevelWarn})
	if strings.Contains(warned, "level") {
		t.Errorf("renderLog with warn level = %q, level must be elided", warned)
	}
}

func TestFormatSetAction(t *testing.T) {
	bare := formatSetAction(&nft.SetAction{})
	assertContainsAll(t, bare, []string{"add", "@?"})

	full := formatSetAction(&nft.SetAction{
		Operation: "update", SetName: "tracker", KeyField: "ip saddr", Invert: true, Timeout: 60000000000,
	})
	assertContainsAll(t, full, []string{"update", "@", "tracker", "ip saddr", "!=", "timeout 1m"})
}

func TestFormatObjref(t *testing.T) {
	tests := []struct {
		objType int
		want    string
	}{
		{1, "counter name"},
		{2, "quota name"},
		{3, "ct helper set"},
		{5, "limit name"},
		{8, "ct expectation set"},
		{9, "objref"},
	}
	for _, tt := range tests {
		got := formatObjref(&nft.ObjrefAction{Type: tt.objType, Name: "x"})
		if !strings.Contains(got, tt.want) {
			t.Errorf("formatObjref(type=%d) = %q, want containing %q", tt.objType, got, tt.want)
		}
	}
}

func TestFormatSetLookup(t *testing.T) {
	if got := formatSetLookup(nft.Condition{}); got != "" {
		t.Errorf("nil SetLookup = %q, want empty", got)
	}

	bare := formatSetLookup(nft.Condition{SetLookup: &nft.SetLookupCondition{SetName: "s"}})
	if !strings.Contains(bare, "@") || !strings.Contains(bare, "s") {
		t.Errorf("field-less lookup = %q, want @s form", bare)
	}

	neg := formatSetLookup(nft.Condition{
		Negate:    true,
		SetLookup: &nft.SetLookupCondition{SetName: "lan_ifs", Field: "meta iif"},
	})
	assertContainsAll(t, neg, []string{"meta iif", "!=", "@", "lan_ifs"})
}
