package ui

// ValidateForSave coverage for the Select-driven action editors (verdict /
// queue / nat). Now that Select.SetValue and the embedded NumberInput's
// SetValue let a test set widget state directly, the validators' real branches
// (not just the unchanged short-circuit) run without a Bubble Tea event loop.
// All netlink-free: ValidateForSave only inspects in-memory widget values.

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"nftui/nft"
)

func TestVerdictKindToExpr(t *testing.T) {
	cases := map[nft.VerdictKind]expr.VerdictKind{
		nft.VerdictAccept:        expr.VerdictAccept,
		nft.VerdictDrop:          expr.VerdictDrop,
		nft.VerdictReturn:        expr.VerdictReturn,
		nft.VerdictJump:          expr.VerdictJump,
		nft.VerdictGoto:          expr.VerdictGoto,
		nft.VerdictKind("bogus"): expr.VerdictDrop, // unknown → drop
	}
	for in, want := range cases {
		if got := verdictKindToExpr(in); got != want {
			t.Errorf("verdictKindToExpr(%q) = %v, want %v", in, got, want)
		}
	}
}

// verdictRule builds an *nft.Rule carrying a single verdict action so the
// VerdictField constructs with hasVerdict = true.
func verdictRule(kind nft.VerdictKind) *nft.Rule {
	return &nft.Rule{Actions: []nft.Action{{
		Type:    nft.ActionTypeVerdict,
		Verdict: &nft.VerdictAction{Kind: kind},
	}}}
}

func TestVerdictField_ValidateForSave(t *testing.T) {
	f := NewVerdictField(verdictRule(nft.VerdictAccept))

	// jump with no chain target → error.
	f.kindSelect.SetValue("jump")
	f.chainInput.SetValue("")
	if err := f.ValidateForSave(); err == nil {
		t.Error("jump without a chain passed validation")
	}

	// jump with a chain → nil.
	f.chainInput.SetValue("dispatch")
	if err := f.ValidateForSave(); err != nil {
		t.Errorf("jump with chain = %v, want nil", err)
	}

	// drop needs no chain → nil even with an empty chain input.
	f.kindSelect.SetValue("drop")
	f.chainInput.SetValue("")
	if err := f.ValidateForSave(); err != nil {
		t.Errorf("drop = %v, want nil", err)
	}
}

func TestQueueField_ValidateForSave(t *testing.T) {
	f := NewQueueField(&nft.Rule{})
	f.enableInput.SetValue("on") // off→on flips Changed() and currentEnabled()

	// Upper bound below num → error.
	f.numInput.SetValue("5")
	f.toInput.SetValue("3")
	if err := f.ValidateForSave(); err == nil {
		t.Error("queue range to<num passed validation")
	}

	// Valid range → nil.
	f.toInput.SetValue("9")
	if err := f.ValidateForSave(); err != nil {
		t.Errorf("valid queue range = %v, want nil", err)
	}

	// fanout flag without a range → error.
	f.toInput.SetValue("0")
	f.flagsInput.SetValues([]string{"fanout"})
	if err := f.ValidateForSave(); err == nil {
		t.Error("fanout without a range passed validation")
	}
}

func TestNATField_ValidateForSave(t *testing.T) {
	f := NewSnatField(&nft.Rule{}, nftables.TableFamilyIPv4)
	f.enableInput.SetValue("on") // enabled + changed → validator body runs

	// Enabled but no address → error.
	f.addrInput.SetValue("")
	if err := f.ValidateForSave(); err == nil {
		t.Error("enabled NAT with no address passed validation")
	}

	// Garbage address → error.
	f.addrInput.SetValue("not-an-ip")
	if err := f.ValidateForSave(); err == nil {
		t.Error("invalid NAT address passed validation")
	}

	// IPv6 address in an IPv4-family table → error.
	f.addrInput.SetValue("2001:db8::1")
	if err := f.ValidateForSave(); err == nil {
		t.Error("IPv6 address in IPv4 table passed validation")
	}

	// Valid IPv4 → nil.
	f.addrInput.SetValue("192.168.1.100")
	if err := f.ValidateForSave(); err != nil {
		t.Errorf("valid IPv4 NAT = %v, want nil", err)
	}
}

func TestQuotaField_ValidateForSave(t *testing.T) {
	f := NewQuotaField(&nft.Rule{})
	f.enableInput.SetValue("on") // enabled + changed

	// Enabled with a zero amount → error.
	f.amountInput.SetValue("0")
	if err := f.ValidateForSave(); err == nil {
		t.Error("zero quota amount passed validation")
	}

	// Positive amount → nil.
	f.amountInput.SetValue("5")
	if err := f.ValidateForSave(); err != nil {
		t.Errorf("valid quota = %v, want nil", err)
	}
}

// The meta-select / meta-iftype validators run their recognized-value path
// (the unrecognized branch is unreachable through the fixed-option Select).
func TestMetaSelectField_ValidateForSave(t *testing.T) {
	f := NewMetaNfprotoField(&nft.Rule{})
	f.valueInput.SetValue("ipv4") // off original "" → changed, recognized
	if err := f.ValidateForSave(); err != nil {
		t.Errorf("nfproto ipv4 = %v, want nil", err)
	}
}

func TestMetaIftypeField_ValidateForSave(t *testing.T) {
	f := NewMetaIiftypeField(&nft.Rule{})
	f.valueInput.SetValue("ether")
	if err := f.ValidateForSave(); err != nil {
		t.Errorf("iiftype ether = %v, want nil", err)
	}
}
