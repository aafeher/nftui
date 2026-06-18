package nft

// Tests for decodeSetElements — the netlink-free post-processing core extracted
// from GetSetElements (the vmap VerdictData fixup + interval pairing). Driving
// it directly pins both branches without a live kernel. The extraction is what
// lets GetSetElements return an error instead of log.Fatal'ing the whole TUI on
// a transient netlink read failure (audit E-1 / R1).
//
// encodeVerdictBytes / be32 are defined in named_objects_test.go (same package).

import (
	"bytes"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func TestDecodeSetElements_VmapDecodesVerdict(t *testing.T) {
	set := &nftables.Set{IsMap: true, DataType: nftables.TypeVerdict}
	raw := encodeVerdictBytes(t, expr.VerdictJump, "target")
	in := []nftables.SetElement{
		{Key: []byte{1, 2, 3, 4}, Val: raw},
	}
	got := decodeSetElements(set, in)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].VerdictData == nil {
		t.Fatal("VerdictData not populated for vmap element")
	}
	if got[0].VerdictData.Kind != expr.VerdictJump || got[0].VerdictData.Chain != "target" {
		t.Errorf("verdict = %+v, want {Jump target}", got[0].VerdictData)
	}
	if got[0].Val != nil {
		t.Errorf("Val should be cleared after decode, got %v", got[0].Val)
	}
}

func TestDecodeSetElements_VmapLeavesPopulatedVerdict(t *testing.T) {
	set := &nftables.Set{IsMap: true, DataType: nftables.TypeVerdict}
	in := []nftables.SetElement{
		{Key: []byte{1}, VerdictData: &expr.Verdict{Kind: expr.VerdictDrop}},
	}
	got := decodeSetElements(set, in)
	if got[0].VerdictData == nil || got[0].VerdictData.Kind != expr.VerdictDrop {
		t.Errorf("pre-populated verdict was altered: %+v", got[0].VerdictData)
	}
}

func TestDecodeSetElements_IntervalPaired(t *testing.T) {
	set := &nftables.Set{Interval: true}
	in := []nftables.SetElement{
		{Key: []byte{10, 0, 0, 0}},
		{Key: []byte{10, 0, 1, 0}, IntervalEnd: true},
	}
	got := decodeSetElements(set, in)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1 folded entry", len(got))
	}
	if !bytes.Equal(got[0].KeyEnd, []byte{10, 0, 0, 255}) {
		t.Errorf("KeyEnd = %v, want 10.0.0.255 (inclusive)", got[0].KeyEnd)
	}
}

func TestDecodeSetElements_PlainPassThrough(t *testing.T) {
	set := &nftables.Set{}
	in := []nftables.SetElement{
		{Key: []byte{1, 1, 1, 1}},
		{Key: []byte{2, 2, 2, 2}},
	}
	got := decodeSetElements(set, in)
	if len(got) != 2 {
		t.Fatalf("plain set mutated length: %d", len(got))
	}
	if !bytes.Equal(got[0].Key, []byte{1, 1, 1, 1}) || !bytes.Equal(got[1].Key, []byte{2, 2, 2, 2}) {
		t.Errorf("plain set elements altered: %+v", got)
	}
}
