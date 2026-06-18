package nft

import (
	"strings"
	"testing"
)

// ValidateIdentifier is the defense-in-depth gate the TUI dialogs call before a
// user-supplied table/chain/set name reaches the kernel or an `nft -f` script
// (audit E-2 / S1). These tests pin the allowlist and, crucially, that every
// nft-script-breaking character is rejected.

func TestValidateIdentifier_Valid(t *testing.T) {
	valid := []string{
		"filter", "input", "my_chain", "nat-prerouting", "v1.2",
		"a", "Z9", "A_b-c.d", strings.Repeat("a", 255),
	}
	for _, name := range valid {
		if err := ValidateIdentifier(name); err != nil {
			t.Errorf("ValidateIdentifier(%q) = %v, want nil", name, err)
		}
	}
}

func TestValidateIdentifier_Empty(t *testing.T) {
	if err := ValidateIdentifier(""); err == nil {
		t.Error("empty name accepted, want error")
	}
}

func TestValidateIdentifier_RejectsInjectionChars(t *testing.T) {
	// Each of these could break out of an identifier's context in an nft
	// script (RenameTable / recreateBaseChain pipe interpolated names into
	// `nft -f -`).
	bad := []string{
		"foo bar",                 // whitespace
		"foo\tbar",                // tab
		"foo\nbar",                // newline → new statement
		"evil{",                   // open brace
		"evil}",                   // close brace
		"a;b",                     // statement separator
		"a#comment",               // comment
		"a\"b",                    // double quote
		"a'b",                     // single quote
		"a\\b",                    // backslash (escape)
		"a/b",                     // slash
		"pwned { }\ntable inet x", // a realistic injection payload
	}
	for _, name := range bad {
		if err := ValidateIdentifier(name); err == nil {
			t.Errorf("ValidateIdentifier(%q) = nil, want rejection", name)
		}
	}
}

func TestValidateIdentifier_RejectsLeadingNonLetter(t *testing.T) {
	for _, name := range []string{"1table", "_foo", "-x", ".y", "9"} {
		if err := ValidateIdentifier(name); err == nil {
			t.Errorf("ValidateIdentifier(%q) = nil, want rejection (must start with a letter)", name)
		}
	}
}

func TestValidateIdentifier_RejectsTooLong(t *testing.T) {
	if err := ValidateIdentifier(strings.Repeat("a", 256)); err == nil {
		t.Error("256-char name accepted, want rejection (max 255)")
	}
}
