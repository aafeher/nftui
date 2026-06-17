package ui

// Tests for the Ethernet-address field: the pure parseMAC helper (all error
// branches) and ValidateForSave driven through a constructed field. Both are
// netlink-free — ValidateForSave only inspects the in-memory input value.

import (
	"testing"

	"nftui/nft"
)

func TestParseMAC(t *testing.T) {
	got, err := parseMAC("aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatalf("valid MAC errored: %v", err)
	}
	want := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parseMAC = %v, want %v", got, want)
		}
	}

	bad := map[string]string{
		"too few octets":   "aa:bb:cc",
		"too many octets":  "aa:bb:cc:dd:ee:ff:00",
		"octet not 2 wide": "a:bb:cc:dd:ee:ff",
		"octet not hex":    "zz:bb:cc:dd:ee:ff",
	}
	for name, in := range bad {
		if _, err := parseMAC(in); err == nil {
			t.Errorf("%s: parseMAC(%q) accepted, want error", name, in)
		}
	}
}

func TestEtherAddrField_ValidateForSave(t *testing.T) {
	// Built from an empty rule, the field starts with original = "" so any
	// non-empty value flips Changed() and runs the validator body.
	f := NewEtherSaddrField(&nft.Rule{})

	// Unchanged → nil.
	if err := f.ValidateForSave(); err != nil {
		t.Errorf("unchanged ValidateForSave = %v, want nil", err)
	}

	// Invalid MAC → error.
	f.addrInput.SetValue("zz:zz")
	if err := f.ValidateForSave(); err == nil {
		t.Error("invalid MAC passed ValidateForSave")
	}

	// Valid MAC → nil.
	f.addrInput.SetValue("aa:bb:cc:dd:ee:ff")
	if err := f.ValidateForSave(); err != nil {
		t.Errorf("valid MAC ValidateForSave = %v, want nil", err)
	}
}
