package ui

import (
	"bytes"
	"testing"

	"nftui/nft"
	nftexpr "nftui/nft/expr"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// encodeSubFieldValue is the inverse of the parser's decodeExthdrValue —
// values go in as uint64 and come out as big-endian byte slices sized to
// the sub-field's Len (1 / 2 / 4 / 8). The kernel stores SCTP fields BE
// per RFC 4960 §3.3, so anything else would mismatch on the read-back.
func TestEncodeSubFieldValue(t *testing.T) {
	cases := []struct {
		name string
		v    uint64
		len  uint32
		want []byte
	}{
		{"1B small", 0x07, 1, []byte{0x07}},
		{"1B truncates upper bytes", 0x123456, 1, []byte{0x56}},
		{"2B SACK num-gap-ack-blocks", 1024, 2, []byte{0x04, 0x00}},
		{"2B INIT os", 0xCAFE, 2, []byte{0xCA, 0xFE}},
		{"4B DATA tsn", 1000, 4, []byte{0x00, 0x00, 0x03, 0xE8}},
		{"4B INIT init-tag", 0x12345678, 4, []byte{0x12, 0x34, 0x56, 0x78}},
		{"8B (defensive — no documented field uses it but keep symmetric)",
			0x0102030405060708, 8,
			[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
		{"unknown length returns nil (caller fails kernel-side)", 1, 7, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := encodeSubFieldValue(c.v, c.len)
			if !bytes.Equal(got, c.want) {
				t.Errorf("encodeSubFieldValue(%#x, %d) = %#v, want %#v", c.v, c.len, got, c.want)
			}
		})
	}
}

// asUint64 normalises the parser's `any` typed sub-field value (uint8 /
// uint16 / uint32 / uint64 / int) into the editor's uint64. The parser
// picks the integer type from the Cmp's Len, so the editor sees varied
// concrete types depending on the original sub-field's width.
func TestAsUint64(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want uint64
	}{
		{"uint8", uint8(7), 7},
		{"uint16", uint16(0xCAFE), 0xCAFE},
		{"uint32", uint32(0x12345678), 0x12345678},
		{"uint64", uint64(0x0102030405060708), 0x0102030405060708},
		{"int", int(42), 42},
		{"unsupported -> 0 (defensive, never expected from the parser)", "not-a-number", 0},
		{"nil -> 0", nil, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := asUint64(c.in); got != c.want {
				t.Errorf("asUint64(%v) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}

// subFieldOptionsFor always leads with "off" (bare-presence) followed by
// each documented sub-field name in declaration order. Chunk types with
// no fixed sub-fields collapse to just ["off"].
func TestSubFieldOptionsFor(t *testing.T) {
	if got := subFieldOptionsFor(0xFE); len(got) != 1 || got[0] != "off" {
		t.Errorf("unknown chunk-type options = %v, want [off]", got)
	}
	// DATA: off + tsn / stream / ssn / ppid
	opts := subFieldOptionsFor(0x00) // ChunkData
	if len(opts) != 5 || opts[0] != "off" {
		t.Fatalf("DATA options = %v, want 5 entries starting with 'off'", opts)
	}
	for i, want := range []string{"off", "tsn", "stream", "ssn", "ppid"} {
		if opts[i] != want {
			t.Errorf("DATA opts[%d] = %q, want %q", i, opts[i], want)
		}
	}
}

// End-to-end roundtrip: SctpChunkField → Save → nft.NftablesToRuleDefinition
// must reconstruct what we put in. Catches wire-format / encoding drift
// between the encoder (this file) and the parser (nft/rule.go) — both
// sides are unit-tested separately, but a bug in either side wouldn't
// surface without an integration test that exercises the boundary.
func TestSctpChunkField_SaveParseRoundTrip(t *testing.T) {
	// Bare-presence first.
	emptyRule := &nft.Rule{} // no existing SCTP-chunk match
	f := NewSctpChunkField(emptyRule)
	// "off" + 21 chunk types → index 1 = "data".
	f.chunkSelect.Selected = 1
	f.activeChunkType = "data"
	f.rebuildSubFieldOptions()
	// sub-field stays "off" (slot 1 index 0) — bare presence.
	var rule nftables.Rule
	f.Save(&rule)

	parsed, err := nft.NftablesToRuleDefinition(&rule)
	if err != nil {
		t.Fatalf("parser failed on bare-presence rule: %v", err)
	}
	if len(parsed.Conditions) != 1 || parsed.Conditions[0].SctpChunk == nil {
		t.Fatalf("expected one SctpChunkCondition, got %+v", parsed.Conditions)
	}
	if got := parsed.Conditions[0].SctpChunk; got.ChunkType != nftexpr.ChunkData || got.Field != "" {
		t.Errorf("roundtrip bare-presence: ChunkType=%v Field=%q, want data / empty",
			got.ChunkType, got.Field)
	}

	// Sub-field roundtrip: data tsn 1000.
	emptyRule = &nft.Rule{}
	f = NewSctpChunkField(emptyRule)
	f.chunkSelect.Selected = 1 // "data"
	f.activeChunkType = "data"
	f.rebuildSubFieldOptions()
	// subFieldOptionsFor(ChunkData) = ["off", "tsn", "stream", "ssn", "ppid"].
	f.subFieldSelect.Selected = 1 // "tsn"
	f.valueInput.SetValue("1000")
	rule = nftables.Rule{}
	f.Save(&rule)

	parsed, err = nft.NftablesToRuleDefinition(&rule)
	if err != nil {
		t.Fatalf("parser failed on sub-field rule: %v", err)
	}
	if len(parsed.Conditions) != 1 || parsed.Conditions[0].SctpChunk == nil {
		t.Fatalf("expected one SctpChunkCondition, got %+v", parsed.Conditions)
	}
	sc := parsed.Conditions[0].SctpChunk
	if sc.ChunkType != nftexpr.ChunkData {
		t.Errorf("roundtrip ChunkType = %v, want data", sc.ChunkType)
	}
	if sc.Field != "tsn" {
		t.Errorf("roundtrip Field = %q, want tsn", sc.Field)
	}
	if v, ok := sc.Value.(uint32); !ok || v != 1000 {
		t.Errorf("roundtrip Value = %v (%T), want uint32(1000)", sc.Value, sc.Value)
	}

	// Switch to a 2-byte sub-field (SACK num-gap-ack-blocks). The encoder
	// must pick the 2-byte path, the parser must decode it as uint16.
	emptyRule = &nft.Rule{}
	f = NewSctpChunkField(emptyRule)
	// "sack" = offset of nftexpr.ChunkSack (0x03) in the names list +1 for the
	// leading "off" — easier to look up by name than to hard-code.
	chunkOpts := append([]string{"off"}, nftexpr.ChunkTypeNames()...)
	f.chunkSelect.Selected = indexOfString(chunkOpts, "sack")
	f.activeChunkType = "sack"
	f.rebuildSubFieldOptions()
	f.subFieldSelect.Selected = indexOfString(subFieldOptionsFor(nftexpr.ChunkSack), "num-gap-ack-blocks")
	f.valueInput.SetValue("1024")
	rule = nftables.Rule{}
	f.Save(&rule)

	parsed, err = nft.NftablesToRuleDefinition(&rule)
	if err != nil {
		t.Fatalf("parser failed on 2-byte sub-field rule: %v", err)
	}
	sc = parsed.Conditions[0].SctpChunk
	if v, ok := sc.Value.(uint16); !ok || v != 1024 {
		t.Errorf("2-byte roundtrip Value = %v (%T), want uint16(1024)", sc.Value, sc.Value)
	}
}

// stripSctpChunkExprs leaves unrelated expressions in place: a Cmp following
// the SCTP Exthdr that targets a *different* register belongs to another
// match (e.g. an earlier meta load) and must survive.
func TestStripSctpChunkExprs_PreservesUnrelatedCmp(t *testing.T) {
	// Build a slice with: SCTP Exthdr (reg 1) — Cmp on reg 2 (unrelated).
	in := []expr.Any{
		&expr.Exthdr{
			DestRegister: 1, Type: 0, Offset: 0, Len: 1,
			Flags: nftexpr.SctpExthdrFlagPresent,
			Op:    expr.ExthdrOp(nftexpr.SctpExthdrOp),
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 2, Data: []byte{17}},
	}
	out := stripSctpChunkExprs(in)
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1 (Exthdr stripped, unrelated Cmp kept)", len(out))
	}
	if _, ok := out[0].(*expr.Cmp); !ok {
		t.Errorf("out[0] = %T, want the preserved *expr.Cmp", out[0])
	}
}

// stripSctpChunkExprs handles back-to-back pairs (multiple SCTP-chunk matches
// in the same rule — the editor only writes one, but the kernel may have
// more from external tools).
func TestStripSctpChunkExprs_MultiplePairs(t *testing.T) {
	in := []expr.Any{
		&expr.Exthdr{DestRegister: 1, Type: 0, Op: expr.ExthdrOp(nftexpr.SctpExthdrOp)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x01}},
		&expr.Exthdr{DestRegister: 2, Type: 1, Op: expr.ExthdrOp(nftexpr.SctpExthdrOp)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 2, Data: []byte{0x01}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
	out := stripSctpChunkExprs(in)
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1 (Verdict only)", len(out))
	}
	if _, ok := out[0].(*expr.Verdict); !ok {
		t.Errorf("out[0] = %T, want *expr.Verdict", out[0])
	}
}
