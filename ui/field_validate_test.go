package ui

// ValidateForSave / small-helper coverage for field editors that are driven
// purely through their text/number inputs (no Select manipulation, no
// netlink). Each field is built from an empty rule, then its input is set so
// Changed() flips and the validator body runs.

import (
	"testing"

	"nftui/nft"
)

func TestEtherTypeField_ValidateForSave(t *testing.T) {
	// Fresh field from an empty rule: unchanged → nil, valid custom → nil.
	f := NewEtherTypeField(&nft.Rule{})
	if err := f.ValidateForSave(); err != nil {
		t.Errorf("unchanged = %v, want nil", err)
	}
	f.customInput.SetValue("0x0800")
	if err := f.ValidateForSave(); err != nil {
		t.Errorf("valid ethertype = %v, want nil", err)
	}

	// The parse-error branch is only reachable when the field originally held
	// a value (so clearing it to garbage flips Changed despite the unparseable
	// text). Build from a rule carrying an unnamed ethertype, then overwrite
	// the custom input with garbage.
	withType := &nft.Rule{Conditions: []nft.Condition{{
		Payload: &nft.PayloadCondition{
			Protocol: nft.PayloadProtoEther, Field: "type", Value: uint16(0x1234),
		},
	}}}
	g := NewEtherTypeField(withType)
	g.customInput.SetValue("zzzz")
	if err := g.ValidateForSave(); err == nil {
		t.Error("invalid ethertype passed validation")
	}
}

func TestMetaUintField_IsCleared(t *testing.T) {
	f := NewMetaMarkField(&nft.Rule{})

	// Built from an empty rule the value input is blank → cleared.
	if !f.isCleared() {
		t.Error("fresh field reports not cleared")
	}

	// A non-zero value clears the cleared state.
	f.valueInput.SetValue("5")
	if f.isCleared() {
		t.Error("field with value 5 reports cleared")
	}

	// An explicit zero counts as cleared (the match would be a no-op).
	f.valueInput.SetValue("0")
	if !f.isCleared() {
		t.Error("field with value 0 reports not cleared")
	}
}

func TestUdpTransportConstructors(t *testing.T) {
	// These thin wrappers around newTransportUintField were otherwise
	// uncovered; constructing each pins the delegation.
	if NewUdpSportField(&nft.Rule{}) == nil {
		t.Error("NewUdpSportField returned nil")
	}
	if NewUdpDportField(&nft.Rule{}) == nil {
		t.Error("NewUdpDportField returned nil")
	}
}
