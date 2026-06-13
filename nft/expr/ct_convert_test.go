package nftexpr

// Tests for the CT string<->value converters used by the eventmask / state /
// status / label field editors. All pure functions.

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/google/nftables/expr"
)

func TestCtEventStringToEvent(t *testing.T) {
	if got := CtEventStringToEvent("new"); got != CtEventNew {
		t.Errorf("new -> %q, want CtEventNew", got)
	}
	if got := CtEventStringToEvent("synproxy"); got != CtEventSynProxy {
		t.Errorf("synproxy -> %q", got)
	}
	if got := CtEventStringToEvent("bogus"); got != "" {
		t.Errorf("bogus -> %q, want empty", got)
	}
}

func TestCtEventStringToEvents_DropsUnknowns(t *testing.T) {
	got := CtEventStringToEvents([]string{"new", "bogus", "destroy"})
	want := []CtEvent{CtEventNew, CtEventDestroy}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCtEventToEventStrings_Roundtrip(t *testing.T) {
	events := []CtEvent{CtEventNew, CtEventLabel}
	got := CtEventToEventStrings(events)
	if !reflect.DeepEqual(got, []string{"new", "label"}) {
		t.Errorf("got %v", got)
	}
	if back := CtEventStringToEvents(got); !reflect.DeepEqual(back, events) {
		t.Errorf("roundtrip lost events: %v", back)
	}
}

func TestEncodeCtEvents(t *testing.T) {
	mask := EncodeCtEvents([]CtEvent{CtEventNew, CtEventDestroy})
	if len(mask) != 4 {
		t.Fatalf("mask length = %d, want 4", len(mask))
	}
	got := binary.LittleEndian.Uint32(mask)
	want := CtEventBitNew | CtEventBitDestroy
	if got != want {
		t.Errorf("mask = %#x, want %#x", got, want)
	}

	if got := binary.LittleEndian.Uint32(EncodeCtEvents(nil)); got != 0 {
		t.Errorf("empty events mask = %#x, want 0", got)
	}
}

func TestCtStateStringToState(t *testing.T) {
	if got := CtStateStringToState("established"); got != CtStateEstablished {
		t.Errorf("established -> %q", got)
	}
	// Unknown tokens collapse to "invalid" — the parser's safe default.
	if got := CtStateStringToState("bogus"); got != CtStateInvalid {
		t.Errorf("bogus -> %q, want CtStateInvalid", got)
	}
}

func TestCtStateStringToStates(t *testing.T) {
	got := CtStateStringToStates([]string{"new", "established"})
	if len(got) != 2 || got[0] != CtStateNew || got[1] != CtStateEstablished {
		t.Errorf("got %v", got)
	}
}

func TestCtStatusConverters(t *testing.T) {
	if got := CtStatusStringToStatus("confirmed"); got != CtStatusConfirmed {
		t.Errorf("confirmed -> %q", got)
	}
	if got := CtStatusStringToStatus("bogus"); got != "" {
		t.Errorf("bogus -> %q, want empty", got)
	}

	statuses := CtStatusStringToStatuses([]string{"confirmed", "bogus"})
	if len(statuses) != 1 || statuses[0] != CtStatusConfirmed {
		t.Errorf("statuses = %v", statuses)
	}

	back := CtStatusToStatusStrings(statuses)
	if !reflect.DeepEqual(back, []string{"confirmed"}) {
		t.Errorf("back = %v", back)
	}
}

func TestGetCtOp(t *testing.T) {
	exprs := []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1},
	}
	if got := GetCtOp(exprs, 0); got != expr.CmpOpNeq {
		t.Errorf("op = %v, want Neq", got)
	}
	// No following Cmp → defaults to Eq.
	if got := GetCtOp(exprs, 1); got != expr.CmpOpEq {
		t.Errorf("op without cmp = %v, want Eq (default)", got)
	}
}

func TestLabelBitMaskRoundtrip(t *testing.T) {
	mask := LabelBitIndicesToMask([]string{"0", "7", "64", "127", "bogus", "300"})
	if len(mask) != 16 {
		t.Fatalf("mask length = %d, want 16", len(mask))
	}
	got := LabelMaskToBitIndices(mask)
	want := []string{"0", "7", "64", "127"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("roundtrip = %v, want %v (invalid inputs dropped)", got, want)
	}

	if bits := LabelMaskToBitIndices(make([]byte, 16)); len(bits) != 0 {
		t.Errorf("zero mask produced bits %v", bits)
	}
}

// TestCtConverters_AllValues drives every string constant through its
// string→type→string roundtrip and asserts each sets a distinct, non-zero
// encode bit. This exhausts the switch arms in the converters and encoders.
func TestCtConverters_AllValues(t *testing.T) {
	t.Run("states", func(t *testing.T) {
		all := []string{"invalid", "established", "related", "new", "untracked"}
		seen := uint32(0)
		for _, s := range all {
			st := CtStateStringToState(s)
			if string(st) != s {
				t.Errorf("CtStateStringToState(%q) = %q", s, st)
			}
			mask := EncodeCtStates([]CtState{st})
			bits := le32(mask)
			if bits == 0 {
				t.Errorf("EncodeCtStates(%q) = 0", s)
			}
			if seen&bits != 0 {
				t.Errorf("state %q bit overlaps a previous one", s)
			}
			seen |= bits
		}
		if got := CtStateStringToState("bogus"); got != CtStateInvalid {
			t.Errorf("unknown state -> %q, want invalid", got)
		}
	})

	t.Run("statuses", func(t *testing.T) {
		// CtStatusStringToStatus has no arm for template/untracked, so those
		// two encodable statuses are not string-parseable (drop them here).
		parseable := []string{
			"expected", "seen-reply", "assured", "confirmed", "snat", "dnat",
			"seq-adjust", "snat-done", "dnat-done", "dying", "fixed-timeout",
			"helper", "offload", "hw-offload",
		}
		seen := uint32(0)
		for _, s := range parseable {
			st := CtStatusStringToStatus(s)
			if string(st) != s {
				t.Errorf("CtStatusStringToStatus(%q) = %q", s, st)
			}
			bits := le32(EncodeCtStatuses([]CtStatus{st}))
			if bits == 0 {
				t.Errorf("EncodeCtStatuses(%q) = 0", s)
			}
			if seen&bits != 0 {
				t.Errorf("status %q bit overlaps a previous one", s)
			}
			seen |= bits
		}
		// template/untracked encode to distinct bits even though they don't parse.
		for _, st := range []CtStatus{CtStatusTemplate, CtStatusUntracked} {
			if le32(EncodeCtStatuses([]CtStatus{st})) == 0 {
				t.Errorf("EncodeCtStatuses(%q) = 0", st)
			}
		}
	})

	t.Run("events", func(t *testing.T) {
		all := []string{
			"new", "related", "destroy", "reply", "assured", "protoinfo",
			"helper", "mark", "seqadj", "secmark", "label", "synproxy",
		}
		seen := uint32(0)
		for _, s := range all {
			ev := CtEventStringToEvent(s)
			if string(ev) != s {
				t.Errorf("CtEventStringToEvent(%q) = %q", s, ev)
			}
			bits := le32(EncodeCtEvents([]CtEvent{ev}))
			if bits == 0 {
				t.Errorf("EncodeCtEvents(%q) = 0", s)
			}
			if seen&bits != 0 {
				t.Errorf("event %q bit overlaps a previous one", s)
			}
			seen |= bits
		}
		if got := CtEventStringToEvent("bogus"); got != "" {
			t.Errorf("unknown event -> %q, want empty", got)
		}
	})
}

func le32(b []byte) uint32 {
	if len(b) != 4 {
		return 0
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func TestCtStatesAreEqual(t *testing.T) {
	if !CtStatesAreEqual([]string{"new", "established"}, []string{"established", "new"}) {
		t.Error("order-independent equality failed")
	}
	if CtStatesAreEqual([]string{"new"}, []string{"new", "related"}) {
		t.Error("different lengths reported equal")
	}
	if CtStatesAreEqual([]string{"new"}, []string{"related"}) {
		t.Error("different elements reported equal")
	}
}
