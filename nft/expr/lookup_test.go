package nftexpr

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// SerializeLookup is the renderer for `expr.Lookup` — the building block used
// by RuleToHumanReadable to format `tcp dport @setname`, `ip saddr { … }`, and
// inverse-match forms. The helper falls back gracefully when set elements
// can't be fetched (live netlink unavailable in unit-test context), so the
// rendered string is always a syntactically valid nft-CLI form.

// Empty SourceRegister information falls back to a register_<n> placeholder,
// keeping the output debuggable when called with a malformed Lookup.
func TestSerializeLookup_EmptyRegister(t *testing.T) {
	lookup := &expr.Lookup{
		SourceRegister: 1,
		SetName:        "exp_set",
	}
	set := &nftables.Set{Name: "exp_set", ID: 0} // test escape hatch in SerializeLookup
	got := SerializeLookup(lookup, "", []*nftables.Set{set})
	want := "register_1 @exp_set"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// The common case: payload-derived register description ("tcp dport") + named
// set. The escape hatch (ID=0, Name=="exp_set") side-steps the netlink fetch
// so we test the formatting code, not the kernel connection.
func TestSerializeLookup_NamedSet(t *testing.T) {
	lookup := &expr.Lookup{
		SourceRegister: 1,
		SetName:        "exp_set",
	}
	set := &nftables.Set{Name: "exp_set", ID: 0}
	got := SerializeLookup(lookup, "tcp dport", []*nftables.Set{set})
	want := "tcp dport @exp_set"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Invert flag (`!=`) flips the relational operator between register and set.
func TestSerializeLookup_Invert(t *testing.T) {
	lookup := &expr.Lookup{
		SourceRegister: 1,
		SetName:        "exp_set",
		Invert:         true,
	}
	set := &nftables.Set{Name: "exp_set", ID: 0}
	got := SerializeLookup(lookup, "tcp dport", []*nftables.Set{set})
	want := "tcp dport != @exp_set"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// When SetName is empty (anonymous-set lookups produced by `{ 80, 443 }`
// directly inline, the kernel sometimes hands us SetID without SetName), the
// fallback names the set by ID so the rendered form is still unambiguous.
func TestSerializeLookup_AnonymousByID(t *testing.T) {
	lookup := &expr.Lookup{
		SourceRegister: 1,
		SetID:          42,
		SetName:        "",
	}
	got := SerializeLookup(lookup, "tcp dport", nil)
	want := "tcp dport @set_42" // setName fallback is "@set_<id>"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
