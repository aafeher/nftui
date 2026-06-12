package ui

// Targeted tests for RejectField and the small CT field helpers — the generic
// FieldEditor harness only exercises the no-reject (read-only) path.

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"nftui/nft"
	nftexpr "nftui/nft/expr"
)

func rejectRule(t nft.RejectType, code uint8) *nft.Rule {
	return &nft.Rule{Actions: []nft.Action{
		{Type: nft.ActionTypeReject, Reject: &nft.RejectAction{Type: t, Code: code}},
	}}
}

func TestRejectTypeOptionsForFamily(t *testing.T) {
	tests := []struct {
		family nftables.TableFamily
		want   []string
	}{
		{nftables.TableFamilyIPv4, []string{rejectTypeICMP, rejectTypeTCPReset}},
		{nftables.TableFamilyIPv6, []string{rejectTypeICMPv6, rejectTypeTCPReset}},
		{nftables.TableFamilyINet, []string{rejectTypeICMPX, rejectTypeTCPReset}},
		{nftables.TableFamilyBridge, []string{rejectTypeICMPX, rejectTypeTCPReset}},
		{nftables.TableFamilyARP, []string{rejectTypeTCPReset}},
	}
	for _, tt := range tests {
		got := rejectTypeOptionsForFamily(tt.family)
		if len(got) != len(tt.want) {
			t.Errorf("family %v: options = %v, want %v", tt.family, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("family %v: options[%d] = %q, want %q", tt.family, i, got[i], tt.want[i])
			}
		}
	}
}

func TestMapWireTypeToDisplay(t *testing.T) {
	tests := []struct {
		typ    nft.RejectType
		family nftables.TableFamily
		want   string
	}{
		{nft.RejectTypeTCPReset, nftables.TableFamilyIPv4, rejectTypeTCPReset},
		{nft.RejectTypeICMPX, nftables.TableFamilyINet, rejectTypeICMPX},
		{nft.RejectTypeICMP, nftables.TableFamilyIPv4, rejectTypeICMP},
		{nft.RejectTypeICMP, nftables.TableFamilyIPv6, rejectTypeICMPv6},
		{nft.RejectTypeICMP, nftables.TableFamilyINet, rejectTypeICMPX},
		{nft.RejectTypeICMP, nftables.TableFamilyBridge, rejectTypeICMPX},
		{nft.RejectType("bogus"), nftables.TableFamilyIPv4, ""},
	}
	for _, tt := range tests {
		if got := mapWireTypeToDisplay(tt.typ, tt.family); got != tt.want {
			t.Errorf("mapWireTypeToDisplay(%q, %v) = %q, want %q", tt.typ, tt.family, got, tt.want)
		}
	}
}

func TestLookupCodeNameAndOrder(t *testing.T) {
	if got := lookupCodeName(rejectTypeICMP, 3); got != "port-unreachable" {
		t.Errorf("icmp code 3 = %q", got)
	}
	if got := lookupCodeName(rejectTypeICMPv6, 1); got != "admin-prohibited" {
		t.Errorf("icmpv6 code 1 = %q", got)
	}
	if got := lookupCodeName(rejectTypeICMPX, 2); got != "host-unreachable" {
		t.Errorf("icmpx code 2 = %q", got)
	}
	if got := lookupCodeName(rejectTypeTCPReset, 0); got != "" {
		t.Errorf("tcp reset code name = %q, want empty", got)
	}

	if order, m := codeOrderForDisplayType(rejectTypeTCPReset); order != nil || m != nil {
		t.Error("tcp reset returned a code order")
	}
	for _, dt := range []string{rejectTypeICMP, rejectTypeICMPv6, rejectTypeICMPX} {
		order, m := codeOrderForDisplayType(dt)
		if len(order) == 0 || len(m) != len(order) {
			t.Errorf("%s: order/map size mismatch (%d vs %d)", dt, len(order), len(m))
		}
	}
}

func TestRejectField_NoReject(t *testing.T) {
	f := NewRejectField(&nft.Rule{}, nftables.TableFamilyINet)
	if f.hasReject {
		t.Fatal("hasReject = true for a rule without reject")
	}
	if f.FocusSlots() != 1 {
		t.Errorf("FocusSlots = %d, want 1", f.FocusSlots())
	}
	f.Focus(0) // no-op
	if f.typeSelect.Focused {
		t.Error("Focus focused the select on a no-reject rule")
	}
	if f.Changed() {
		t.Error("Changed = true on a no-reject rule")
	}
	if cmd := f.Update(keyMsg(tea.KeyRight)); cmd != nil {
		t.Error("Update returned a cmd on a no-reject rule")
	}
	rule := &nftables.Rule{Exprs: []expr.Any{&expr.Verdict{}}}
	f.Save(rule) // no-op
	if !strings.Contains(f.View(), "no reject") {
		t.Error("View() does not show the no-reject placeholder")
	}
}

func TestRejectField_InitialStateFromRule(t *testing.T) {
	f := NewRejectField(rejectRule(nft.RejectTypeICMP, 3), nftables.TableFamilyIPv4)
	if !f.hasReject {
		t.Fatal("hasReject = false")
	}
	if f.currentType() != rejectTypeICMP {
		t.Errorf("type = %q, want icmp", f.currentType())
	}
	if f.codeSelect.Value() != "port-unreachable" {
		t.Errorf("code = %q, want port-unreachable", f.codeSelect.Value())
	}
	if f.FocusSlots() != 2 {
		t.Errorf("FocusSlots = %d, want 2 (type + code)", f.FocusSlots())
	}
	if f.Changed() {
		t.Error("Changed = true right after construction")
	}

	// tcp reset has no code slot.
	tr := NewRejectField(rejectRule(nft.RejectTypeTCPReset, 0), nftables.TableFamilyIPv4)
	if tr.FocusSlots() != 1 {
		t.Errorf("tcp reset FocusSlots = %d, want 1", tr.FocusSlots())
	}
}

func TestRejectField_TypeChangeRebuildsCodes(t *testing.T) {
	f := NewRejectField(rejectRule(nft.RejectTypeICMP, 3), nftables.TableFamilyIPv4)
	f.Focus(0)

	// icmp -> tcp reset: code slot disappears.
	if cmd := f.Update(keyMsg(tea.KeyRight)); cmd != nil {
		t.Error("select Update returned a cmd")
	}
	if f.currentType() != rejectTypeTCPReset {
		t.Fatalf("type after right = %q, want tcp reset", f.currentType())
	}
	if !f.Changed() || f.FocusSlots() != 1 {
		t.Error("tcp reset: Changed/FocusSlots wrong")
	}

	// Back to icmp: the original code is restored (round-trip safety).
	f.Update(keyMsg(tea.KeyLeft))
	if f.currentType() != rejectTypeICMP {
		t.Fatalf("type after left = %q, want icmp", f.currentType())
	}
	if f.codeSelect.Value() != "port-unreachable" {
		t.Errorf("round-trip code = %q, want the original port-unreachable", f.codeSelect.Value())
	}
	if f.Changed() {
		t.Error("Changed = true after a type round-trip")
	}
}

func TestRejectField_FocusAndCodeEdit(t *testing.T) {
	f := NewRejectField(rejectRule(nft.RejectTypeICMP, 0), nftables.TableFamilyIPv4)

	f.Focus(1)
	if !f.codeSelect.Focused || f.typeSelect.Focused {
		t.Fatal("Focus(1) did not focus the code select")
	}
	f.Update(keyMsg(tea.KeyRight)) // net-unreachable -> host-unreachable
	if f.codeSelect.Value() != "host-unreachable" {
		t.Errorf("code = %q after right, want host-unreachable", f.codeSelect.Value())
	}
	if !f.Changed() {
		t.Error("Changed = false after a code change")
	}
	f.Blur()
	if f.codeSelect.Focused || f.typeSelect.Focused {
		t.Error("Blur left a select focused")
	}
}

func TestRejectField_SaveVariants(t *testing.T) {
	tests := []struct {
		name     string
		family   nftables.TableFamily
		initial  nft.RejectType
		moves    int // right presses on the type select from slot 0
		codeName string
		wantType uint32
		wantCode uint8
	}{
		{"icmp code change", nftables.TableFamilyIPv4, nft.RejectTypeICMP, 0, "admin-prohibited", unix.NFT_REJECT_ICMP_UNREACH, 13},
		{"icmp to tcp reset", nftables.TableFamilyIPv4, nft.RejectTypeICMP, 1, "", unix.NFT_REJECT_TCP_RST, 0},
		{"icmpv6 code change", nftables.TableFamilyIPv6, nft.RejectTypeICMP, 0, "reject-route", unix.NFT_REJECT_ICMP_UNREACH, 6},
		{"icmpx code change", nftables.TableFamilyINet, nft.RejectTypeICMPX, 0, "admin-prohibited", unix.NFT_REJECT_ICMPX_UNREACH, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewRejectField(rejectRule(tt.initial, 0), tt.family)
			f.Focus(0)
			for i := 0; i < tt.moves; i++ {
				f.Update(keyMsg(tea.KeyRight))
			}
			if tt.codeName != "" {
				f.codeSelect.SetValue(tt.codeName)
			}
			if !f.Changed() {
				t.Fatal("Changed = false before Save")
			}

			rule := &nftables.Rule{Exprs: []expr.Any{&expr.Reject{}, &expr.Verdict{}}}
			f.Save(rule)

			rj, ok := rule.Exprs[0].(*expr.Reject)
			if !ok {
				t.Fatal("Save replaced the reject with something else")
			}
			if rj.Type != tt.wantType || rj.Code != tt.wantCode {
				t.Errorf("saved reject = type %d code %d, want type %d code %d", rj.Type, rj.Code, tt.wantType, tt.wantCode)
			}
			if f.Changed() {
				t.Error("Changed = true after Save (originals not refreshed)")
			}
		})
	}
}

func TestRejectField_ViewRenders(t *testing.T) {
	f := NewRejectField(rejectRule(nft.RejectTypeICMP, 3), nftables.TableFamilyIPv4)
	v := f.View()
	for _, tok := range []string{"Reject", "Code", "current:", "port-unreachable"} {
		if !strings.Contains(v, tok) {
			t.Errorf("View() missing %q", tok)
		}
	}
	if err := f.ValidateForSave(); err != nil {
		t.Errorf("ValidateForSave() = %v, want nil", err)
	}

	// previewAction mirrors the current selection per type.
	if a := f.previewAction(); a.Type != nft.RejectTypeICMP || a.Code != 3 {
		t.Errorf("previewAction = %+v", a)
	}
	f.typeSelect.SetValue(rejectTypeTCPReset)
	if a := f.previewAction(); a.Type != nft.RejectTypeTCPReset {
		t.Errorf("previewAction tcp reset = %+v", a)
	}
}

// --- field_ct_helpers.go ---

func TestCtDirectionToExpr(t *testing.T) {
	if dir, ok := ctDirectionToExpr(nftexpr.CtDirectionOriginal); dir != 0 || !ok {
		t.Errorf("original = %d/%v, want 0/true", dir, ok)
	}
	if dir, ok := ctDirectionToExpr(nftexpr.CtDirectionReply); dir != 1 || !ok {
		t.Errorf("reply = %d/%v, want 1/true", dir, ok)
	}
	if dir, ok := ctDirectionToExpr(nftexpr.CtDirection("")); dir != 255 || ok {
		t.Errorf("none = %d/%v, want 255/false", dir, ok)
	}
}

func TestCtInsertIndex(t *testing.T) {
	// No CT pair: insert at the front.
	if got := ctInsertIndex([]expr.Any{&expr.Counter{}, &expr.Verdict{}}); got != 0 {
		t.Errorf("no ct: index = %d, want 0", got)
	}
	// One Ct+Cmp pair followed by counter/verdict: insert after the pair.
	exprs := []expr.Any{
		&expr.Ct{}, &expr.Cmp{},
		&expr.Counter{}, &expr.Verdict{},
	}
	if got := ctInsertIndex(exprs); got != 2 {
		t.Errorf("one ct pair: index = %d, want 2", got)
	}
	// Two pairs: after the last one.
	exprs = []expr.Any{
		&expr.Ct{}, &expr.Cmp{},
		&expr.Ct{}, &expr.Cmp{},
		&expr.Verdict{},
	}
	if got := ctInsertIndex(exprs); got != 4 {
		t.Errorf("two ct pairs: index = %d, want 4", got)
	}
}
