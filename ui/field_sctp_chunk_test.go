package ui

import (
	"bytes"
	"testing"
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
