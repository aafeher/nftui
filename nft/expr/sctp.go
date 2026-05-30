package nftexpr

import "golang.org/x/sys/unix"

// SctpExthdrOp is the `Op` value on an `expr.Exthdr` that targets an SCTP
// chunk — i.e. `NFT_EXTHDR_OP_SCTP` from the kernel header
// `linux/netfilter/nf_tables.h`. `golang.org/x/sys/unix` only exposes IPV6
// and TCPOPT from that enum, so the literal value lives here. The kernel
// has held SCTP at position 3 since the SCTP exthdr support landed (Linux
// 5.14, commit `c78d38f`), and `NFT_EXTHDR_OP_MAX = 0x4` in `unix` confirms
// the position stays stable.
const SctpExthdrOp uint32 = 3

// SctpExthdrFlagPresent is the F_PRESENT flag (`NFT_EXTHDR_F_PRESENT`) the
// kernel sets on the Exthdr expression when the match is "chunk type X is
// present" rather than "field at (offset, len) within chunk X equals …".
const SctpExthdrFlagPresent = unix.NFT_EXTHDR_F_PRESENT

// ChunkType is the SCTP chunk-type discriminator (RFC 4960 §3.2 + extensions).
// Stored as uint8 because that's how the kernel exposes it on `Exthdr.Type`.
type ChunkType uint8

// Chunk-type constants. Values are the on-the-wire chunk-type numbers — keep
// them stable; `nft list ruleset` and the kernel rely on these. RFC 4960
// covers 0x00–0x0E; the rest come from later RFCs (AUTH: RFC 4895, ASCONF /
// ASCONF_ACK: RFC 5061, FORWARD_TSN: RFC 3758, I_DATA / I_FORWARD_TSN: RFC 8260).
const (
	ChunkData             ChunkType = 0x00
	ChunkInit             ChunkType = 0x01
	ChunkInitAck          ChunkType = 0x02
	ChunkSack             ChunkType = 0x03
	ChunkHeartbeat        ChunkType = 0x04
	ChunkHeartbeatAck     ChunkType = 0x05
	ChunkAbort            ChunkType = 0x06
	ChunkShutdown         ChunkType = 0x07
	ChunkShutdownAck      ChunkType = 0x08
	ChunkError            ChunkType = 0x09
	ChunkCookieEcho       ChunkType = 0x0A
	ChunkCookieAck        ChunkType = 0x0B
	ChunkEcne             ChunkType = 0x0C
	ChunkCwr              ChunkType = 0x0D
	ChunkShutdownComplete ChunkType = 0x0E
	ChunkAuth             ChunkType = 0x0F
	ChunkAsconfAck        ChunkType = 0x80
	ChunkIData            ChunkType = 0x82
	ChunkForwardTsn       ChunkType = 0xC0
	ChunkAsconf           ChunkType = 0xC1
	ChunkIForwardTsn      ChunkType = 0xC2
)

// chunkTypeNames is the source of truth for the chunk-type ↔ name mapping
// used by both `ChunkTypeName` (decode) and `ChunkTypeFromString` (encode).
// Names match the tokens the `nft` CLI accepts (e.g. `sctp chunk init`,
// `sctp chunk init-ack`).
var chunkTypeNames = []struct {
	ct   ChunkType
	name string
}{
	{ChunkData, "data"},
	{ChunkInit, "init"},
	{ChunkInitAck, "init-ack"},
	{ChunkSack, "sack"},
	{ChunkHeartbeat, "heartbeat"},
	{ChunkHeartbeatAck, "heartbeat-ack"},
	{ChunkAbort, "abort"},
	{ChunkShutdown, "shutdown"},
	{ChunkShutdownAck, "shutdown-ack"},
	{ChunkError, "error"},
	{ChunkCookieEcho, "cookie-echo"},
	{ChunkCookieAck, "cookie-ack"},
	{ChunkEcne, "ecne"},
	{ChunkCwr, "cwr"},
	{ChunkShutdownComplete, "shutdown-complete"},
	{ChunkAuth, "auth"},
	{ChunkAsconfAck, "asconf-ack"},
	{ChunkIData, "i-data"},
	{ChunkForwardTsn, "forward-tsn"},
	{ChunkAsconf, "asconf"},
	{ChunkIForwardTsn, "i-forward-tsn"},
}

// ChunkTypeName returns the `nft` CLI token for ct, or "" for an unknown
// chunk-type number. The empty return lets callers distinguish "render the
// canonical name" from "render the raw number".
func ChunkTypeName(ct ChunkType) string {
	for _, e := range chunkTypeNames {
		if e.ct == ct {
			return e.name
		}
	}
	return ""
}

// ChunkTypeFromString looks up a chunk type by its `nft` CLI token (case-
// insensitive). Returns ok=false for unknown names so the caller can surface
// a clear error before constructing an Exthdr expression.
func ChunkTypeFromString(s string) (ChunkType, bool) {
	for _, e := range chunkTypeNames {
		if e.name == s {
			return e.ct, true
		}
	}
	return 0, false
}

// ChunkTypeNames returns every supported chunk-type token, in stable order
// (RFC 4960 sequence first, then the IETF extensions). Used by the UI Select
// editor and by tests that iterate the full set.
func ChunkTypeNames() []string {
	out := make([]string, 0, len(chunkTypeNames))
	for _, e := range chunkTypeNames {
		out = append(out, e.name)
	}
	return out
}

// ChunkField is one named field within a chunk's body, addressable by the
// `nft` CLI as `sctp chunk <type> <field>`. Offset and Len are in bytes and
// reference the kernel's `Exthdr.Offset` / `Exthdr.Len` directly — `nft -de
// list` prints these verbatim.
type ChunkField struct {
	Name   string // CLI token (e.g. "tsn", "init-tag")
	Offset uint32 // byte offset from chunk start
	Len    uint32 // byte length
}

// chunkBodyFields lists the fixed-offset named sub-fields per chunk type
// (i.e. everything past the 4-byte common header at offsets 0..3). Variable-
// length tails (parameters, error causes, the cookie blob, the HMAC payload)
// are intentionally omitted — they don't fit the `Exthdr{Offset, Len}` shape
// the way fixed-offset fields do, and the `nft` CLI doesn't expose them as
// scalar matches either.
//
// Sources: RFC 4960 §3.3 (DATA/INIT/INIT_ACK/SACK/…), RFC 4895 §4.4 (AUTH),
// RFC 3758 §3.2 (FORWARD_TSN), RFC 5061 §4 (ASCONF/ASCONF_ACK), RFC 8260 §2
// (I_DATA / I_FORWARD_TSN).
var chunkBodyFields = map[ChunkType][]ChunkField{
	ChunkData: {
		{Name: "tsn", Offset: 4, Len: 4},
		{Name: "stream", Offset: 8, Len: 2},
		{Name: "ssn", Offset: 10, Len: 2},
		{Name: "ppid", Offset: 12, Len: 4},
	},
	ChunkInit: {
		{Name: "init-tag", Offset: 4, Len: 4},
		{Name: "a-rwnd", Offset: 8, Len: 4},
		{Name: "os", Offset: 12, Len: 2},
		{Name: "mis", Offset: 14, Len: 2},
		{Name: "init-tsn", Offset: 16, Len: 4},
	},
	ChunkInitAck: {
		{Name: "init-tag", Offset: 4, Len: 4},
		{Name: "a-rwnd", Offset: 8, Len: 4},
		{Name: "os", Offset: 12, Len: 2},
		{Name: "mis", Offset: 14, Len: 2},
		{Name: "init-tsn", Offset: 16, Len: 4},
	},
	ChunkSack: {
		{Name: "cum-tsn-ack", Offset: 4, Len: 4},
		{Name: "a-rwnd", Offset: 8, Len: 4},
		{Name: "num-gap-ack-blocks", Offset: 12, Len: 2},
		{Name: "num-dup-tsns", Offset: 14, Len: 2},
	},
	ChunkShutdown: {
		{Name: "cum-tsn-ack", Offset: 4, Len: 4},
	},
	ChunkEcne: {
		{Name: "lowest-tsn", Offset: 4, Len: 4},
	},
	ChunkCwr: {
		{Name: "lowest-tsn", Offset: 4, Len: 4},
	},
	ChunkAuth: {
		{Name: "shared-key-id", Offset: 4, Len: 2},
		{Name: "hmac-id", Offset: 6, Len: 2},
	},
	ChunkAsconfAck: {
		{Name: "serial-number", Offset: 4, Len: 4},
	},
	ChunkIData: {
		{Name: "tsn", Offset: 4, Len: 4},
		{Name: "stream", Offset: 8, Len: 2},
		{Name: "reserved", Offset: 10, Len: 2},
		{Name: "mid", Offset: 12, Len: 4},
		{Name: "ppid-or-fsn", Offset: 16, Len: 4},
	},
	ChunkForwardTsn: {
		{Name: "new-cum-tsn", Offset: 4, Len: 4},
	},
	ChunkAsconf: {
		{Name: "serial-number", Offset: 4, Len: 4},
	},
	ChunkIForwardTsn: {
		{Name: "new-cum-tsn", Offset: 4, Len: 4},
	},
}

// ChunkFields returns the fixed-offset named sub-fields for ct, or an empty
// slice for chunks whose body is purely variable-length (HEARTBEAT, ABORT,
// ERROR, COOKIE_ECHO, COOKIE_ACK, SHUTDOWN_ACK, SHUTDOWN_COMPLETE). Callers
// can safely range over the result without nil checks.
func ChunkFields(ct ChunkType) []ChunkField {
	return chunkBodyFields[ct]
}

// LookupChunkField finds the named sub-field within a chunk type by its
// (offset, len) — the inverse of constructing an Exthdr from a name. Used
// by the parser when it sees `Exthdr{Op=SCTP, Type=N, Offset=X, Len=Y}`
// and needs to produce a human-readable `sctp chunk <type> <field>` form.
// Returns ok=false when offset/len don't match any documented field; the
// caller renders the raw (offset, len) pair in that case.
func LookupChunkField(ct ChunkType, offset, length uint32) (ChunkField, bool) {
	for _, f := range chunkBodyFields[ct] {
		if f.Offset == offset && f.Len == length {
			return f, true
		}
	}
	return ChunkField{}, false
}
