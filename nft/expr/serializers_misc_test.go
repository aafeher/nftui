package nftexpr

// Tests for the small pure serializers that previously had zero coverage.
// Expected strings follow nft CLI output where the serializer implements a
// real mapping, and pin the current placeholder text where it does not.

import (
	"strings"
	"testing"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestSerializeFixedStrings(t *testing.T) {
	if got := SerializeDup(&expr.Dup{}); got != "dup to ADDR device DEV" {
		t.Errorf("SerializeDup() = %q", got)
	}
	if got := SerializeNotrack(&expr.Notrack{}); got != "notrack" {
		t.Errorf("SerializeNotrack() = %q", got)
	}
	if got := SerializeTproxy(&expr.TProxy{}); got != "tproxy to ADDRESS:PORT" {
		t.Errorf("SerializeTproxy() = %q", got)
	}
}

func TestSerializeFlowOffload(t *testing.T) {
	if got := SerializeFlowOffload(&expr.FlowOffload{Name: "ft"}); got != "flow add @ft" {
		t.Errorf("SerializeFlowOffload() = %q", got)
	}
}

func TestSerializeHash(t *testing.T) {
	if got := SerializeHash(&expr.Hash{Modulus: 10, Offset: 2}); got != "jhash mod 10 offset 2" {
		t.Errorf("SerializeHash() = %q", got)
	}
}

func TestSerializeSecMark(t *testing.T) {
	if got := SerializeSecMark(&expr.SecMark{Ctx: "system_u:object_r:ssh_server_packet_t:s0"}); got != "meta secmark set system_u:object_r:ssh_server_packet_t:s0" {
		t.Errorf("SerializeSecMark() = %q", got)
	}
}

func TestSerializeTargetAndMatch(t *testing.T) {
	if got := SerializeTarget(&expr.Target{Name: "MASQUERADE"}); got != "target MASQUERADE" {
		t.Errorf("SerializeTarget() = %q", got)
	}
	if got := SerializeMatch(&expr.Match{Name: "limit"}); got != "match limit" {
		t.Errorf("SerializeMatch() = %q", got)
	}
	if got := FormatMatch(&expr.Match{}); got == "" {
		t.Error("FormatMatch() returned empty string")
	}
}

// nft CLI encoding, verified live via `nft --debug=netlink`:
//
//	ct count over 5 -> [ connlimit count 5 flags 1 ]  (NFT_CONNLIMIT_F_INV)
//	ct count 7      -> [ connlimit count 7 flags 0 ]
func TestSerializeConnlimit(t *testing.T) {
	inv := &expr.Connlimit{Count: 5, Flags: expr.NFT_CONNLIMIT_F_INV}
	if got := SerializeConnlimit(inv); got != "ct count over 5" {
		t.Errorf("SerializeConnlimit(INV) = %q, want \"ct count over 5\"", got)
	}
	plain := &expr.Connlimit{Count: 7}
	if got := SerializeConnlimit(plain); got != "ct count 7" {
		t.Errorf("SerializeConnlimit(flags=0) = %q, want \"ct count 7\"", got)
	}
}

func TestSerializeSocket(t *testing.T) {
	if got := SerializeSocket(&expr.Socket{Key: expr.SocketKeyTransparent}); got != "socket transparent" {
		t.Errorf("SerializeSocket(transparent) = %q", got)
	}
	if got := SerializeSocket(&expr.Socket{Key: expr.SocketKeyCgroupv2}); got != "socket cgroupv2" {
		t.Errorf("SerializeSocket(cgroupv2) = %q", got)
	}
}

func TestSerializeImmediate(t *testing.T) {
	if got := SerializeImmediate(&expr.Immediate{}); got != "" {
		t.Errorf("SerializeImmediate(empty) = %q, want \"\"", got)
	}
	if got := SerializeImmediate(&expr.Immediate{Data: []byte{0x00, 0x50}}); got != "80" {
		t.Errorf("SerializeImmediate(port bytes) = %q, want \"80\"", got)
	}
	if got := FormatImmediate(&expr.Immediate{}); got == "" {
		t.Error("FormatImmediate() returned empty string")
	}
}

func TestSerializeSynProxy(t *testing.T) {
	if got := SerializeSynProxy(&expr.SynProxy{}); got != "synproxy" {
		t.Errorf("SerializeSynProxy(bare) = %q", got)
	}
	if got := SerializeSynProxy(&expr.SynProxy{Mss: 1460, Wscale: 7}); got != "synproxy mss 1460 wscale 7" {
		t.Errorf("SerializeSynProxy(mss+wscale) = %q", got)
	}
}

func TestSerializeQueueExpr(t *testing.T) {
	if got := SerializeQueue(&expr.Queue{Num: 3}); got != "queue num 3" {
		t.Errorf("SerializeQueue(single) = %q", got)
	}
	if got := SerializeQueue(&expr.Queue{Num: 0, Total: 4}); got != "queue num 0-3" {
		t.Errorf("SerializeQueue(range) = %q", got)
	}
	if got := SerializeQueue(&expr.Queue{Num: 1, Flag: expr.QueueFlagBypass}); got != "queue num 1 bypass" {
		t.Errorf("SerializeQueue(bypass) = %q", got)
	}
}

func TestSerializeDynset(t *testing.T) {
	if got := SerializeDynset(&expr.Dynset{SetName: "blocklist"}); got != "unknown @blocklist" {
		t.Errorf("SerializeDynset() = %q", got)
	}
	if got := FormatDynset(&expr.Dynset{}); got == "" {
		t.Error("FormatDynset() returned empty string")
	}
}

func TestSerializeRt(t *testing.T) {
	tests := []struct {
		key  expr.RtKey
		want string
	}{
		{expr.RtClassid, "rt classid"},
		{expr.RtNexthop4, "rt nexthop4"},
		{expr.RtNexthop6, "rt nexthop6"},
		{expr.RtTCPMSS, "rt tcpmss"},
		{expr.RtKey(99), "rt unknown"},
	}
	for _, tt := range tests {
		if got := SerializeRt(&expr.Rt{Key: tt.key}); got != tt.want {
			t.Errorf("SerializeRt(%d) = %q, want %q", tt.key, got, tt.want)
		}
	}
}

func TestSerializeNumgen(t *testing.T) {
	if got := SerializeNumgen(nil); !strings.Contains(got, "invalid numgen: nil") {
		t.Errorf("SerializeNumgen(nil) = %q", got)
	}
	if got := SerializeNumgen(&expr.Numgen{}); !strings.Contains(got, "modulus is 0") {
		t.Errorf("SerializeNumgen(modulus 0) = %q", got)
	}
	if got := SerializeNumgen(&expr.Numgen{Type: unix.NFT_NG_INCREMENTAL, Modulus: 2}); got != "numgen inc mod 2 offset 0" {
		t.Errorf("SerializeNumgen(inc) = %q", got)
	}
	if got := SerializeNumgen(&expr.Numgen{Type: unix.NFT_NG_RANDOM, Modulus: 10, Offset: 1}); got != "numgen random mod 10 offset 1" {
		t.Errorf("SerializeNumgen(random) = %q", got)
	}
	if got := SerializeNumgen(&expr.Numgen{Type: 7, Modulus: 2}); !strings.Contains(got, "unknown (7)") {
		t.Errorf("SerializeNumgen(unknown type) = %q", got)
	}
}

func TestSerializeQuotaExpr(t *testing.T) {
	tests := []struct {
		name  string
		quota expr.Quota
		want  string
	}{
		{"gbytes", expr.Quota{Bytes: 2 * 1024 * 1024 * 1024}, "quota 2 gbytes"},
		{"mbytes", expr.Quota{Bytes: 5 * 1024 * 1024}, "quota 5 mbytes"},
		{"kbytes", expr.Quota{Bytes: 3 * 1024}, "quota 3 kbytes"},
		{"bytes", expr.Quota{Bytes: 512}, "quota 512 bytes"},
		{"bytes consumed", expr.Quota{Bytes: 512, Consumed: 10}, "quota 512 bytes used 10"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SerializeQuota(&tt.quota); got != tt.want {
				t.Errorf("SerializeQuota() = %q, want %q", got, tt.want)
			}
		})
	}
	if got := FormatQuota(&expr.Quota{}); got == "" {
		t.Error("FormatQuota() returned empty string")
	}
}

func TestSerializeLogExpr(t *testing.T) {
	if got := SerializeLog(&expr.Log{}); got != "log" {
		t.Errorf("SerializeLog(bare) = %q", got)
	}
	got := SerializeLog(&expr.Log{
		Key:   2,
		Data:  []byte("dropped: "),
		Level: 4, // warn
		Flags: 0x01 | 0x04 | 0x10,
	})
	for _, tok := range []string{"log", "group 2", `prefix "dropped: "`, "level warn", "tcp sequence", "ip options", "ether"} {
		if !strings.Contains(got, tok) {
			t.Errorf("SerializeLog(full) = %q, missing %q", got, tok)
		}
	}
	if got := FormatLog(&expr.Log{}); got == "" {
		t.Error("FormatLog() returned empty string")
	}
}

func TestSerializeExthdrExpr(t *testing.T) {
	frag := &expr.Exthdr{Type: 44}
	got, consumed := SerializeExthdr(frag, []expr.Any{frag}, 0)
	if got != "frag field" || consumed != 1 {
		t.Errorf("SerializeExthdr(frag, no cmp) = %q/%d", got, consumed)
	}

	cmp := &expr.Cmp{Op: expr.CmpOpEq, Data: []byte{0x00, 0x35}}
	got, consumed = SerializeExthdr(frag, []expr.Any{frag, cmp}, 0)
	if got != "frag field 53" || consumed != 2 {
		t.Errorf("SerializeExthdr(frag + cmp) = %q/%d", got, consumed)
	}

	unknown := &expr.Exthdr{Type: 99}
	if got, _ := SerializeExthdr(unknown, []expr.Any{unknown}, 0); got != "exthdr-99 field" {
		t.Errorf("SerializeExthdr(unknown) = %q", got)
	}
	if got := FormatExthdr(&expr.Exthdr{}); got == "" {
		t.Error("FormatExthdr() returned empty string")
	}
}

func TestSerializeFibExpr(t *testing.T) {
	got := SerializeFib(&expr.Fib{FlagSADDR: true, FlagDADDR: true, FlagMARK: true, FlagIIF: true, FlagOIF: true, ResultOIF: true})
	for _, tok := range []string{"fib", "saddr", "daddr", "mark", "iif", "oif"} {
		if !strings.Contains(got, tok) {
			t.Errorf("SerializeFib(all flags) = %q, missing %q", got, tok)
		}
	}
	if got := SerializeFib(&expr.Fib{FlagDADDR: true, ResultOIFNAME: true}); !strings.Contains(got, "oifname") {
		t.Errorf("SerializeFib(oifname) = %q", got)
	}
	if got := SerializeFib(&expr.Fib{FlagDADDR: true, ResultADDRTYPE: true}); !strings.Contains(got, "type") {
		t.Errorf("SerializeFib(addrtype) = %q", got)
	}
}

func TestSerializeBitwiseExpr(t *testing.T) {
	b := &expr.Bitwise{Mask: []byte{0xff, 0xff}, Xor: []byte{0x00, 0x00}}
	if got := SerializeBitwise(b); got != "& 65535 ^ 0" {
		t.Errorf("SerializeBitwise() = %q", got)
	}
	if got := FormatBitwise(b); got == "" {
		t.Error("FormatBitwise() returned empty string")
	}
}

func TestBitwiseToHumanReadable(t *testing.T) {
	// Unknown source register falls back to register_N and hex mask/xor.
	b := &expr.Bitwise{SourceRegister: 1, Mask: []byte{0x00, 0x08}, Xor: []byte{0x00, 0x00}}
	got := BitwiseToHumanReadable(b, map[uint32]string{})
	for _, tok := range []string{"register_1", "&", "^"} {
		if !strings.Contains(got, tok) {
			t.Errorf("BitwiseToHumanReadable(no regmap) = %q, missing %q", got, tok)
		}
	}

	// CT state source with zero Xor decodes the mask to state names.
	ct := &expr.Bitwise{SourceRegister: 1, Mask: []byte{0x08, 0x00, 0x00, 0x00}, Xor: []byte{0x00, 0x00, 0x00, 0x00}}
	got = BitwiseToHumanReadable(ct, map[uint32]string{1: string(CtKeyState)})
	if !strings.Contains(got, "state") || !strings.Contains(got, "new") {
		t.Errorf("BitwiseToHumanReadable(ct state) = %q, want state+new tokens", got)
	}

	// Non-zero Xor keeps the raw hex form even for ct state.
	ctXor := &expr.Bitwise{SourceRegister: 1, Mask: []byte{0x08}, Xor: []byte{0x01}}
	if got := BitwiseToHumanReadable(ctXor, map[uint32]string{1: string(CtKeyState)}); !strings.Contains(got, "0x") {
		t.Errorf("BitwiseToHumanReadable(ct state, xor) = %q, want hex form", got)
	}
}

func TestSerializeNATExpr(t *testing.T) {
	got := SerializeNAT(&expr.NAT{Type: expr.NATTypeSourceNAT, RegAddrMin: 1, RegProtoMin: 2, Random: true, FullyRandom: true, Persistent: true})
	for _, tok := range []string{"snat to", "ADDRESS", ":PORT", "random", "fully-random", "persistent"} {
		if !strings.Contains(got, tok) {
			t.Errorf("SerializeNAT(snat full) = %q, missing %q", got, tok)
		}
	}
	if got := SerializeNAT(&expr.NAT{Type: expr.NATTypeDestNAT}); !strings.Contains(got, "dnat to") {
		t.Errorf("SerializeNAT(dnat) = %q", got)
	}
	if got := FormatNAT(&expr.NAT{}); got == "" {
		t.Error("FormatNAT() returned empty string")
	}
}

func TestInterfaceIndexToName(t *testing.T) {
	if got := InterfaceIndexToName([]byte{0, 0, 0}); got != "" {
		t.Errorf("non-4-byte = %q, want empty", got)
	}
	if got := InterfaceIndexToName([]byte{0, 0, 0, 0}); got != "any" {
		t.Errorf("index 0 = %q, want any", got)
	}
	// A very high index is unlikely to resolve to a real interface, so the
	// helper falls back to the decimal index string.
	if got := InterfaceIndexToName([]byte{0xff, 0xff, 0x00, 0x00}); got == "" {
		t.Error("high index returned empty, want decimal fallback or a name")
	}
}

func TestSerializeMeta(t *testing.T) {
	// Bare meta (no following Cmp): just the key name, skip 1.
	s, skip, l4 := SerializeMeta(&expr.Meta{Key: expr.MetaKeyMARK}, []expr.Any{&expr.Meta{}}, 0)
	if s != "mark" || skip != 1 || l4 != "" {
		t.Errorf("bare meta = %q/%d/%q", s, skip, l4)
	}

	// meta l4proto tcp collapses to "tcp" and reports the l4proto context.
	exprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
	}
	s, skip, l4 = SerializeMeta(exprs[0].(*expr.Meta), exprs, 0)
	if s != "tcp" || skip != 2 || l4 != "tcp" {
		t.Errorf("meta l4proto tcp = %q/%d/%q", s, skip, l4)
	}

	// Non-collapsing key with a Cmp: "<key> <value>".
	exprs2 := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x10}},
	}
	s, skip, _ = SerializeMeta(exprs2[0].(*expr.Meta), exprs2, 0)
	if skip != 2 || !strings.Contains(s, "mark") {
		t.Errorf("meta mark neq = %q/%d", s, skip)
	}

	// Source-register "meta X set" form.
	s, skip, _ = SerializeMeta(&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true}, []expr.Any{&expr.Meta{}}, 0)
	if s != "mark set" || skip != 1 {
		t.Errorf("meta set = %q/%d", s, skip)
	}

	if got := FormatMeta(&expr.Meta{Key: expr.MetaKeyMARK, Register: 1}); got == "" {
		t.Error("FormatMeta returned empty")
	}
	if got := FormatMeta(&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true}); !strings.Contains(got, "sreg") {
		t.Errorf("FormatMeta sreg = %q", got)
	}
}

func TestSerializePayload(t *testing.T) {
	// transport dport 22 (transport header, offset 2, len 2) + Cmp.
	exprs := []expr.Any{
		&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 22}},
	}
	s, skip := SerializePayload(exprs[0].(*expr.Payload), exprs, 0)
	if skip != 2 || !strings.Contains(s, "dport") {
		t.Errorf("transport dport = %q/%d", s, skip)
	}

	// network saddr (offset 12, len 4), no Cmp → skip 1.
	s, skip = SerializePayload(&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4, DestRegister: 1}, []expr.Any{&expr.Payload{}}, 0)
	if skip != 1 || !strings.Contains(s, "saddr") {
		t.Errorf("network saddr = %q/%d", s, skip)
	}

	// link-layer header.
	s, _ = SerializePayload(&expr.Payload{Base: expr.PayloadBaseLLHeader, Offset: 0, Len: 6, DestRegister: 1}, []expr.Any{&expr.Payload{}}, 0)
	if s == "" {
		t.Error("link payload returned empty")
	}

	// unknown base → raw @base,off,len form.
	s, _ = SerializePayload(&expr.Payload{Base: 99, Offset: 4, Len: 2, DestRegister: 1}, []expr.Any{&expr.Payload{}}, 0)
	if !strings.Contains(s, "@") {
		t.Errorf("unknown base = %q, want @-form", s)
	}
}

func TestChunkTypeNames(t *testing.T) {
	names := ChunkTypeNames()
	if len(names) == 0 {
		t.Fatal("ChunkTypeNames() returned no entries")
	}
	for _, n := range names {
		if n == "" {
			t.Error("ChunkTypeNames() contains an empty entry")
		}
	}
}
