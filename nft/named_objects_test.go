package nft

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestObjTypeLabel(t *testing.T) {
	cases := []struct {
		in   nftables.ObjType
		want string
	}{
		{nftables.ObjTypeCounter, "counter"},
		{nftables.ObjTypeQuota, "quota"},
		{nftables.ObjTypeCtHelper, "cthelper"},
		{nftables.ObjTypeLimit, "limit"},
		{nftables.ObjTypeConnLimit, "connlimit"},
		{nftables.ObjTypeTunnel, "tunnel"},
		{nftables.ObjTypeCtTimeout, "cttimeout"},
		{nftables.ObjTypeSecMark, "secmark"},
		{nftables.ObjTypeCtExpect, "ctexpect"},
		{nftables.ObjTypeSynProxy, "synproxy"},
		{nftables.ObjType(999), "obj_999"},
	}
	for _, c := range cases {
		if got := ObjTypeLabel(c.in); got != c.want {
			t.Errorf("ObjTypeLabel(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSummarizeObj_Counter(t *testing.T) {
	raw := &nftables.NamedObj{
		Name: "web_traffic",
		Type: nftables.ObjTypeCounter,
		Obj:  &expr.Counter{Packets: 42, Bytes: 1024},
	}
	got := summarizeObj(raw)
	if got.Name != "web_traffic" {
		t.Errorf("Name = %q", got.Name)
	}
	if got.TypeStr != "counter" {
		t.Errorf("TypeStr = %q, want counter", got.TypeStr)
	}
	if got.Packets != 42 || got.Bytes != 1024 {
		t.Errorf("counter values = %d/%d, want 42/1024", got.Packets, got.Bytes)
	}
}

func TestSummarizeObj_Quota(t *testing.T) {
	raw := &nftables.NamedObj{
		Name: "dl_limit",
		Type: nftables.ObjTypeQuota,
		Obj:  &expr.Quota{Bytes: 1048576, Consumed: 256},
	}
	got := summarizeObj(raw)
	if got.TypeStr != "quota" {
		t.Errorf("TypeStr = %q, want quota", got.TypeStr)
	}
	if got.QuotaBytes != 1048576 || got.Consumed != 256 {
		t.Errorf("quota values = %d/%d, want 1048576/256",
			got.QuotaBytes, got.Consumed)
	}
}

func TestSummarizeObj_CtHelper(t *testing.T) {
	raw := &nftables.NamedObj{
		Name: "ftp_2121",
		Type: nftables.ObjTypeCtHelper,
		Obj:  &expr.CtHelper{Name: "ftp", L3Proto: 2, L4Proto: 6},
	}
	got := summarizeObj(raw)
	if got.TypeStr != "cthelper" {
		t.Errorf("TypeStr = %q", got.TypeStr)
	}
	if got.HelperName != "ftp" || got.L3Proto != 2 || got.L4Proto != 6 {
		t.Errorf("ct helper fields = {%q,%d,%d}, want {ftp,2,6}",
			got.HelperName, got.L3Proto, got.L4Proto)
	}
}

func TestSummarizeObj_UnknownTypeReturnsLabelOnly(t *testing.T) {
	raw := &nftables.NamedObj{
		Name: "extra",
		Type: nftables.ObjTypeSecMark,
	}
	got := summarizeObj(raw)
	if got.TypeStr != "secmark" {
		t.Errorf("TypeStr = %q, want secmark", got.TypeStr)
	}
	// No typed payload → counter/quota/helper fields stay zero.
	if got.Packets != 0 || got.Bytes != 0 || got.HelperName != "" {
		t.Error("untyped object must leave typed fields zero")
	}
}

// encodeVerdictBytes is the inverse of decodeVerdictBytes — wraps
// {CODE [, CHAIN]} as netlink attributes. Used to feed the decoder a
// realistic byte payload in tests.
func encodeVerdictBytes(t *testing.T, kind expr.VerdictKind, chain string) []byte {
	t.Helper()
	attrs := []netlink.Attribute{
		{Type: unix.NFTA_VERDICT_CODE, Data: be32(uint32(int32(kind)))},
	}
	if chain != "" {
		attrs = append(attrs, netlink.Attribute{
			Type: unix.NFTA_VERDICT_CHAIN,
			Data: []byte(chain + "\x00"),
		})
	}
	b, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func be32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func TestDecodeVerdictBytes_Accept(t *testing.T) {
	b := encodeVerdictBytes(t, expr.VerdictAccept, "")
	v, ok := decodeVerdictBytes(b)
	if !ok {
		t.Fatal("decode failed")
	}
	if v.Kind != expr.VerdictAccept || v.Chain != "" {
		t.Errorf("got {Kind:%v Chain:%q}, want {Accept ''}", v.Kind, v.Chain)
	}
}

func TestDecodeVerdictBytes_JumpChain(t *testing.T) {
	b := encodeVerdictBytes(t, expr.VerdictJump, "my_chain")
	v, ok := decodeVerdictBytes(b)
	if !ok {
		t.Fatal("decode failed")
	}
	if v.Kind != expr.VerdictJump || v.Chain != "my_chain" {
		t.Errorf("got {Kind:%v Chain:%q}, want {Jump my_chain}", v.Kind, v.Chain)
	}
}

func TestDecodeVerdictBytes_GotoChain(t *testing.T) {
	b := encodeVerdictBytes(t, expr.VerdictGoto, "fallback")
	v, ok := decodeVerdictBytes(b)
	if !ok || v.Kind != expr.VerdictGoto || v.Chain != "fallback" {
		t.Errorf("decode goto: got {%+v}, want {Goto fallback}", v)
	}
}

func TestDecodeVerdictBytes_Empty(t *testing.T) {
	_, ok := decodeVerdictBytes(nil)
	if ok {
		t.Error("nil bytes must not decode to a verdict")
	}
	_, ok = decodeVerdictBytes([]byte{})
	if ok {
		t.Error("empty bytes must not decode to a verdict")
	}
}

// --- buildSetElements (interval / map / verdict shaping) -----------------

func TestBuildSetElements_PlainSet(t *testing.T) {
	set := &nftables.Set{KeyType: nftables.TypeIPAddr}
	got := buildSetElements(set, []byte{10, 0, 0, 1}, nil, nil, nil)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if !bytes.Equal(got[0].Key, []byte{10, 0, 0, 1}) {
		t.Errorf("Key = %v", got[0].Key)
	}
	if got[0].IntervalEnd {
		t.Error("plain set element must not carry IntervalEnd")
	}
}

func TestBuildSetElements_PlainMap(t *testing.T) {
	set := &nftables.Set{
		KeyType:  nftables.TypeIPAddr,
		IsMap:    true,
		DataType: nftables.TypeMark,
	}
	val := []byte{0, 0, 0, 0x10}
	got := buildSetElements(set, []byte{10, 0, 0, 1}, nil, val, nil)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if !bytes.Equal(got[0].Val, val) {
		t.Errorf("Val = %v, want %v", got[0].Val, val)
	}
	if got[0].VerdictData != nil {
		t.Error("plain map element must not carry VerdictData")
	}
}

func TestBuildSetElements_VerdictMap(t *testing.T) {
	set := &nftables.Set{
		KeyType:  nftables.TypeInetService,
		IsMap:    true,
		DataType: nftables.TypeVerdict,
	}
	v := &expr.Verdict{Kind: expr.VerdictJump, Chain: "c1"}
	got := buildSetElements(set, []byte{0, 22}, nil, nil, v)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].VerdictData == nil || got[0].VerdictData.Kind != expr.VerdictJump {
		t.Errorf("VerdictData = %+v", got[0].VerdictData)
	}
	if got[0].Val != nil {
		t.Error("verdict map element must not carry Val bytes")
	}
}

func TestBuildSetElements_IntervalRangeIncrementsEnd(t *testing.T) {
	set := &nftables.Set{KeyType: nftables.TypeIPAddr, Interval: true}
	// Inclusive end 10.0.0.255 → exclusive end 10.0.1.0 on the wire.
	got := buildSetElements(set,
		[]byte{10, 0, 0, 0},
		[]byte{10, 0, 0, 255},
		nil, nil)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (start+end)", len(got))
	}
	if !got[1].IntervalEnd {
		t.Error("second element must have IntervalEnd=true")
	}
	want := []byte{10, 0, 1, 0}
	if !bytes.Equal(got[1].Key, want) {
		t.Errorf("end key = %v, want %v (exclusive +1)", got[1].Key, want)
	}
}

func TestBuildSetElements_IntervalSingleHostAutoCloses(t *testing.T) {
	set := &nftables.Set{KeyType: nftables.TypeIPAddr, Interval: true}
	// Single host on an interval set still emits a closing marker at +1
	// so adjacent ranges don't auto-merge.
	got := buildSetElements(set, []byte{10, 0, 0, 1}, nil, nil, nil)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (host+close)", len(got))
	}
	if !got[1].IntervalEnd {
		t.Error("auto-close marker must have IntervalEnd=true")
	}
	if !bytes.Equal(got[1].Key, []byte{10, 0, 0, 2}) {
		t.Errorf("close marker = %v, want 10.0.0.2", got[1].Key)
	}
}

// --- incrementBytes (used by interval encoding) --------------------------

func TestIncrementBytes(t *testing.T) {
	cases := []struct {
		in, want []byte
	}{
		{[]byte{0}, []byte{1}},
		{[]byte{10, 0, 0, 255}, []byte{10, 0, 1, 0}},
		{[]byte{0xff, 0xff}, []byte{0, 0}}, // wrap
		{[]byte{0x00, 0x01}, []byte{0x00, 0x02}},
	}
	for _, c := range cases {
		got := incrementBytes(c.in)
		if !bytes.Equal(got, c.want) {
			t.Errorf("incrementBytes(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}
