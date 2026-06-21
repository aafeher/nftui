package nft

import (
	"strings"
	"testing"

	"github.com/google/nftables"
)

// Go native fuzz targets for the two string-parsing entry points that take the
// least-trusted input in the package: user-typed identifiers (table/chain/set
// names) and set-element keys. Both feed values that ultimately reach the kernel
// or a privileged `nft -f -` script, so a parser crash or a wrong-width/unsafe
// result is a real robustness/security concern (continues the E-series
// hardening). The seed corpus runs under plain `go test`; extended exploration
// runs with e.g. `go test -run='^$' -fuzz=FuzzParseSetElementKey ./nft/`.

// dangerousIdentifierBytes are the characters ValidateIdentifier exists to keep
// out of an identifier — anything that could break out of an identifier's
// context in an `nft -f` script (whitespace, braces, ';', '#', quotes,
// backslash, slash, newlines). The fuzzer asserts none of these can appear in a
// name ValidateIdentifier accepts.
const dangerousIdentifierBytes = " \t\r\n{};#\"'\\/"

// FuzzValidateIdentifier asserts the injection-safety invariant: any name the
// validator accepts must be non-empty, within the length bound, start with an
// ASCII letter, and contain none of the nft-script metacharacters. A failing
// case would be an input the validator calls "valid" that could nonetheless
// inject statements into the privileged rename/recreate scripts.
func FuzzValidateIdentifier(f *testing.F) {
	for _, s := range []string{
		"", "a", "filter", "my_table", "chain-1", "a.b.c",
		"1leading", "has space", "semi;colon", "brace{}", "quote\"",
		"slash/x", "hash#x", "new\nline", "tab\tx", "backslash\\x",
		strings.Repeat("a", 255), strings.Repeat("a", 256),
		"héllo", "naïve", "x; flush ruleset",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, name string) {
		if err := ValidateIdentifier(name); err != nil {
			return // rejected — nothing to assert about a rejected name
		}
		// Accepted: every safety property must hold.
		if name == "" {
			t.Fatalf("accepted an empty name")
		}
		if len(name) > nftIdentifierMax {
			t.Fatalf("accepted an over-length name (%d > %d): %q", len(name), nftIdentifierMax, name)
		}
		if c := name[0]; !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			t.Fatalf("accepted a name not starting with an ASCII letter: %q", name)
		}
		if i := strings.IndexAny(name, dangerousIdentifierBytes); i >= 0 {
			t.Fatalf("accepted a name containing a forbidden byte %q: %q", name[i], name)
		}
	})
}

// FuzzParseSetElementKey drives the set-element key parser across every key type
// with arbitrary input. The invariant: it must never panic, and when it returns
// no error the start (and end, for ranges/CIDRs) byte slices must have exactly
// the key type's element width — a wrong-width result would corrupt the kernel
// set element. Exercises the whole parser tree (parseIP4/parseIP6/
// parseInetService/parseUintBE/cidrToRange/dashRangeToBytes) in one target.
func FuzzParseSetElementKey(f *testing.F) {
	for _, s := range []string{
		"", "1.2.3.4", "10.0.0.0/8", "10.0.0.1-10.0.0.9",
		"2001:db8::1", "2001:db8::/32", "de:ad:be:ef:00:01",
		"80", "1024-2048", "6", "0x10", "4294967295",
		"not-an-ip", "::/0", "999.999.999.999", "garbage",
	} {
		f.Add(s)
	}

	// One representative set per key type; Interval=true where range/CIDR forms
	// are meaningful so those branches are reachable.
	type kt struct {
		name     string
		set      *nftables.Set
		width    int // expected element byte width when parsing succeeds
		variable bool
	}
	cases := []kt{
		{"ipv4", &nftables.Set{KeyType: nftables.TypeIPAddr, Interval: true}, 4, false},
		{"ipv6", &nftables.Set{KeyType: nftables.TypeIP6Addr, Interval: true}, 16, false},
		{"ether", &nftables.Set{KeyType: nftables.TypeEtherAddr}, 6, false},
		{"service", &nftables.Set{KeyType: nftables.TypeInetService, Interval: true}, 2, false},
		{"proto", &nftables.Set{KeyType: nftables.TypeInetProto}, 1, false},
		{"mark", &nftables.Set{KeyType: nftables.TypeMark, Interval: true}, 4, false},
		// integer width comes from KeyType.Bytes (0 → 4); treat as variable.
		{"integer", &nftables.Set{KeyType: nftables.TypeInteger, Interval: true}, 0, true},
	}

	f.Fuzz(func(t *testing.T, input string) {
		for _, c := range cases {
			start, end, err := ParseSetElementKey(c.set, input)
			if err != nil {
				continue
			}
			width := c.width
			if c.variable {
				width = int(c.set.KeyType.Bytes)
				if width == 0 {
					width = 4
				}
			}
			if len(start) != width {
				t.Fatalf("%s: input %q parsed to %d-byte start, want %d", c.name, input, len(start), width)
			}
			if end != nil && len(end) != width {
				t.Fatalf("%s: input %q parsed to %d-byte end, want %d", c.name, input, len(end), width)
			}
		}
	})
}
