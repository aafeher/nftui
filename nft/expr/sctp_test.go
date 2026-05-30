package nftexpr

import "testing"

// Every chunk-type constant must round-trip through ChunkTypeName /
// ChunkTypeFromString. Catches typos and missing entries in the names table.
func TestChunkType_RoundTrip(t *testing.T) {
	all := []ChunkType{
		ChunkData, ChunkInit, ChunkInitAck, ChunkSack,
		ChunkHeartbeat, ChunkHeartbeatAck, ChunkAbort,
		ChunkShutdown, ChunkShutdownAck, ChunkError,
		ChunkCookieEcho, ChunkCookieAck, ChunkEcne, ChunkCwr,
		ChunkShutdownComplete, ChunkAuth,
		ChunkAsconfAck, ChunkIData,
		ChunkForwardTsn, ChunkAsconf, ChunkIForwardTsn,
	}
	for _, ct := range all {
		name := ChunkTypeName(ct)
		if name == "" {
			t.Errorf("ChunkType(0x%02X) has no name", uint8(ct))
			continue
		}
		got, ok := ChunkTypeFromString(name)
		if !ok || got != ct {
			t.Errorf("round-trip mismatch: 0x%02X -> %q -> (%d, ok=%v)", uint8(ct), name, got, ok)
		}
	}
}

// Unknown values produce ok=false / "" so the caller can fall back to a
// raw numeric render.
func TestChunkType_Unknown(t *testing.T) {
	if n := ChunkTypeName(0xFD); n != "" {
		t.Errorf("ChunkTypeName(0xFD) = %q, want empty", n)
	}
	if _, ok := ChunkTypeFromString("nonsense-chunk"); ok {
		t.Error("ChunkTypeFromString('nonsense-chunk') = ok, want not ok")
	}
}

// ChunkFields must return the documented fixed-offset sub-fields per type.
// Spot-check a few entries that the parser and editor depend on, including
// "no sub-fields" for variable-body chunks.
func TestChunkFields_Documented(t *testing.T) {
	cases := []struct {
		ct      ChunkType
		minLen  int    // require AT LEAST this many fields (so adding more later doesn't break the test)
		hasName string // a name that must be present (or "" to skip)
	}{
		{ChunkData, 4, "tsn"},
		{ChunkInit, 5, "init-tag"},
		{ChunkInitAck, 5, "init-tag"},
		{ChunkSack, 4, "cum-tsn-ack"},
		{ChunkShutdown, 1, "cum-tsn-ack"},
		{ChunkEcne, 1, "lowest-tsn"},
		{ChunkCwr, 1, "lowest-tsn"},
		{ChunkAuth, 2, "hmac-id"},
		{ChunkAsconfAck, 1, "serial-number"},
		{ChunkIData, 5, "mid"},
		{ChunkForwardTsn, 1, "new-cum-tsn"},
		{ChunkAsconf, 1, "serial-number"},
		{ChunkIForwardTsn, 1, "new-cum-tsn"},
		// Variable-body chunks have no fixed sub-fields.
		{ChunkHeartbeat, 0, ""},
		{ChunkAbort, 0, ""},
		{ChunkError, 0, ""},
		{ChunkCookieEcho, 0, ""},
		{ChunkCookieAck, 0, ""},
		{ChunkShutdownAck, 0, ""},
		{ChunkShutdownComplete, 0, ""},
	}
	for _, c := range cases {
		fields := ChunkFields(c.ct)
		if len(fields) < c.minLen {
			t.Errorf("ChunkFields(%s): len=%d, want >= %d", ChunkTypeName(c.ct), len(fields), c.minLen)
			continue
		}
		if c.hasName == "" {
			continue
		}
		found := false
		for _, f := range fields {
			if f.Name == c.hasName {
				found = true
				// Offset / Len must be > 0 — common header occupies offsets
				// 0..3, so every sub-field is at offset >= 4.
				if f.Offset < 4 {
					t.Errorf("ChunkFields(%s) field %q at offset %d (must be >= 4 past common header)",
						ChunkTypeName(c.ct), f.Name, f.Offset)
				}
				if f.Len == 0 {
					t.Errorf("ChunkFields(%s) field %q has zero Len", ChunkTypeName(c.ct), f.Name)
				}
				break
			}
		}
		if !found {
			t.Errorf("ChunkFields(%s) missing expected field %q", ChunkTypeName(c.ct), c.hasName)
		}
	}
}

// LookupChunkField is the inverse of ChunkFields[] indexing: from (offset,
// len) back to the named field. The parser uses it on Exthdr expressions.
func TestLookupChunkField(t *testing.T) {
	// Known DATA tsn @ offset 4, len 4.
	if f, ok := LookupChunkField(ChunkData, 4, 4); !ok || f.Name != "tsn" {
		t.Errorf("LookupChunkField(DATA, 4, 4) = (%q, ok=%v), want (tsn, ok=true)", f.Name, ok)
	}
	// Unknown (offset, len) pair returns ok=false.
	if _, ok := LookupChunkField(ChunkData, 99, 1); ok {
		t.Error("LookupChunkField(DATA, 99, 1) returned ok=true for an unknown field")
	}
	// Wrong-chunk lookup also returns ok=false even with valid offsets.
	if _, ok := LookupChunkField(ChunkHeartbeat, 4, 4); ok {
		t.Error("LookupChunkField(HEARTBEAT, 4, 4) returned ok=true (HEARTBEAT has no fixed sub-fields)")
	}
}
