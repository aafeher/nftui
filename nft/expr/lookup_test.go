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
		SetName:        "__nftui_test_set__",
	}
	set := &nftables.Set{Name: "__nftui_test_set__", ID: 0} // test escape hatch in SerializeLookup
	got := SerializeLookup(lookup, "", []*nftables.Set{set})
	want := "register_1 @__nftui_test_set__"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// The common case: payload-derived register description ("tcp dport") + named
// set. The escape hatch (ID=0, Name=="__nftui_test_set__") side-steps the netlink fetch
// so we test the formatting code, not the kernel connection.
func TestSerializeLookup_NamedSet(t *testing.T) {
	lookup := &expr.Lookup{
		SourceRegister: 1,
		SetName:        "__nftui_test_set__",
	}
	set := &nftables.Set{Name: "__nftui_test_set__", ID: 0}
	got := SerializeLookup(lookup, "tcp dport", []*nftables.Set{set})
	want := "tcp dport @__nftui_test_set__"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Invert flag (`!=`) flips the relational operator between register and set.
func TestSerializeLookup_Invert(t *testing.T) {
	lookup := &expr.Lookup{
		SourceRegister: 1,
		SetName:        "__nftui_test_set__",
		Invert:         true,
	}
	set := &nftables.Set{Name: "__nftui_test_set__", ID: 0}
	got := SerializeLookup(lookup, "tcp dport", []*nftables.Set{set})
	want := "tcp dport != @__nftui_test_set__"
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

// SerializeLookupWithKey is the CT-typed sibling of SerializeLookup (used for
// `ct state @setname` style lookups, where elements decode through the CtKey).
// It must share the same fallback behavior: a set missing from the caller's
// `sets` slice renders as `@<setName>`, never as a register with trailing
// whitespace.
func TestSerializeLookupWithKey_NoMatchFallback(t *testing.T) {
	lookup := &expr.Lookup{
		SourceRegister: 1,
		SetName:        "ct_states",
	}
	got := SerializeLookupWithKey(lookup, "ct state", expr.CtKeySTATE, nil)
	want := "ct state @ct_states"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Empty SetName falls back to set_<id> — and the post-format "@" prefix must
// not double up (the fallback itself carried a stray leading "@" before the
// v0.9.0 pre-tag audit fix).
func TestSerializeLookupWithKey_AnonymousByID(t *testing.T) {
	lookup := &expr.Lookup{
		SourceRegister: 1,
		SetID:          7,
		SetName:        "",
	}
	got := SerializeLookupWithKey(lookup, "ct state", expr.CtKeySTATE, nil)
	want := "ct state @set_7"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Invert flag (`!=`) must survive the fallback path too.
func TestSerializeLookupWithKey_InvertFallback(t *testing.T) {
	lookup := &expr.Lookup{
		SourceRegister: 1,
		SetName:        "ct_states",
		Invert:         true,
	}
	got := SerializeLookupWithKey(lookup, "ct state", expr.CtKeySTATE, nil)
	want := "ct state != @ct_states"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
