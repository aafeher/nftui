package ui

// Per-field Save() coverage. Each editor's Save mutates a *nftables.Rule's
// expression list: inserting a fresh expr group, overwriting an existing one
// in place, or removing it. The contract harness drives the editors but undoes
// its edits, so these tests instead set widget state directly (Select.SetValue
// / NumberInput.SetValue / textinput.SetValue), then Save into a rule shaped to
// hit each branch (empty → insert, pre-populated → overwrite/remove). All
// netlink-free: Save only rewrites the in-memory Exprs slice.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"nftui/nft"
)

func findConnlimit(exprs []expr.Any) *expr.Connlimit {
	for _, e := range exprs {
		if c, ok := e.(*expr.Connlimit); ok {
			return c
		}
	}
	return nil
}

func TestCtCountField_Save(t *testing.T) {
	// Insert: empty editor + a rule with only a verdict → Connlimit inserted
	// before the verdict.
	t.Run("insert before verdict", func(t *testing.T) {
		f := NewCtCountField(&nft.Rule{})
		f.countInput.SetValue("5")
		f.overInput.SetValue("over")

		rule := &nftables.Rule{Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}}
		f.Save(rule)

		cl := findConnlimit(rule.Exprs)
		if cl == nil || cl.Count != 5 || cl.Flags != expr.NFT_CONNLIMIT_F_INV {
			t.Fatalf("connlimit = %+v, want count 5 / INV", cl)
		}
		// It must sit before the verdict.
		if _, ok := rule.Exprs[len(rule.Exprs)-1].(*expr.Verdict); !ok {
			t.Error("verdict no longer last after insert")
		}
	})

	// Update: an existing Connlimit is rewritten in place.
	t.Run("update existing", func(t *testing.T) {
		f := NewCtCountField(&nft.Rule{})
		f.countInput.SetValue("9")

		rule := &nftables.Rule{Exprs: []expr.Any{&expr.Connlimit{Count: 1}}}
		f.Save(rule)

		if cl := findConnlimit(rule.Exprs); cl == nil || cl.Count != 9 {
			t.Fatalf("connlimit = %+v, want count 9", cl)
		}
	})
}

func TestCtProtocolField_Save(t *testing.T) {
	t.Run("insert tcp", func(t *testing.T) {
		f := NewCtProtocolField(&nft.Rule{})
		f.valueInput.SetValue("tcp")

		rule := &nftables.Rule{}
		f.Save(rule)

		if len(rule.Exprs) != 2 {
			t.Fatalf("exprs = %+v, want Ct+Cmp", rule.Exprs)
		}
		ct, ok := rule.Exprs[0].(*expr.Ct)
		if !ok || ct.Key != expr.CtKeyPROTOCOL {
			t.Fatalf("first expr = %+v, want ct protocol", rule.Exprs[0])
		}
		if cmp := rule.Exprs[1].(*expr.Cmp); !bytes.Equal(cmp.Data, []byte{6}) {
			t.Errorf("cmp data = %v, want tcp(6)", cmp.Data)
		}
	})

	t.Run("update to udp", func(t *testing.T) {
		f := NewCtProtocolField(&nft.Rule{})
		f.valueInput.SetValue("udp")

		rule := &nftables.Rule{Exprs: []expr.Any{
			&expr.Ct{Key: expr.CtKeyPROTOCOL, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
		}}
		f.Save(rule)

		if cmp := rule.Exprs[1].(*expr.Cmp); !bytes.Equal(cmp.Data, []byte{17}) {
			t.Errorf("cmp data = %v, want udp(17)", cmp.Data)
		}
	})
}

func TestMetaUintField_Save(t *testing.T) {
	t.Run("append fresh pair", func(t *testing.T) {
		f := NewMetaMarkField(&nft.Rule{})
		f.valueInput.SetValue("16")

		rule := &nftables.Rule{}
		f.Save(rule)

		if len(rule.Exprs) != 2 {
			t.Fatalf("exprs = %+v, want Meta+Cmp", rule.Exprs)
		}
		if m, ok := rule.Exprs[0].(*expr.Meta); !ok || m.Key != f.metaKey {
			t.Errorf("first expr = %+v, want meta mark", rule.Exprs[0])
		}
	})

	t.Run("overwrite in place", func(t *testing.T) {
		f := NewMetaMarkField(&nft.Rule{})
		f.valueInput.SetValue("99")

		rule := &nftables.Rule{Exprs: []expr.Any{
			&expr.Meta{Key: f.metaKey, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1, 0, 0, 0}},
		}}
		f.Save(rule)

		if len(rule.Exprs) != 2 {
			t.Fatalf("overwrite changed expr count: %+v", rule.Exprs)
		}
		cmp := rule.Exprs[1].(*expr.Cmp)
		if bytes.Equal(cmp.Data, []byte{1, 0, 0, 0}) {
			t.Error("cmp data unchanged after overwrite")
		}
	})

	t.Run("clearing the value removes the pair", func(t *testing.T) {
		// Build from a rule that carries the mark so original != 0; clearing
		// the input then flips Changed() and hits the remove branch.
		withMark := &nft.Rule{Conditions: []nft.Condition{{
			Type:      nft.ConditionTypeMeta,
			Operation: nft.CompareOpEq,
			Meta:      &nft.MetaCondition{Key: nft.MetaKeyMark, Value: uint32(16)},
		}}}
		f := NewMetaMarkField(withMark)
		f.valueInput.SetValue("")

		rule := &nftables.Rule{Exprs: []expr.Any{
			&expr.Meta{Key: f.metaKey, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{16, 0, 0, 0}},
		}}
		f.Save(rule)

		if len(rule.Exprs) != 0 {
			t.Errorf("clear did not remove the pair: %+v", rule.Exprs)
		}
	})
}

func TestQuotaField_Save(t *testing.T) {
	t.Run("enabled adds a Quota", func(t *testing.T) {
		f := NewQuotaField(&nft.Rule{})
		f.enableInput.SetValue("on")
		f.amountInput.SetValue("4096")

		rule := &nftables.Rule{}
		f.Save(rule)

		found := false
		for _, e := range rule.Exprs {
			if _, ok := e.(*expr.Quota); ok {
				found = true
			}
		}
		if !found {
			t.Errorf("no Quota added: %+v", rule.Exprs)
		}
	})

	t.Run("disabling removes the existing Quota", func(t *testing.T) {
		// hasQuota original via a quota-carrying rule would require the ctor's
		// extraction; simpler: an enabled→Changed field whose Save strips any
		// pre-existing Quota when not enabled. We force Changed by toggling the
		// amount, then disable.
		f := NewQuotaField(&nft.Rule{})
		f.amountInput.SetValue("10") // amount change → Changed()
		f.enableInput.SetValue("off")

		rule := &nftables.Rule{Exprs: []expr.Any{&expr.Quota{Bytes: 100}}}
		f.Save(rule)

		for _, e := range rule.Exprs {
			if _, ok := e.(*expr.Quota); ok {
				t.Errorf("Quota survived disable: %+v", rule.Exprs)
			}
		}
	})
}

func TestCtL3ProtoField_Save(t *testing.T) {
	t.Run("insert", func(t *testing.T) {
		f := NewCtL3ProtoField(&nft.Rule{})
		f.valueInput.SetValue("ipv4")

		rule := &nftables.Rule{}
		f.Save(rule)

		if len(rule.Exprs) != 2 {
			t.Fatalf("exprs = %+v, want Ct+Cmp", rule.Exprs)
		}
		if ct, ok := rule.Exprs[0].(*expr.Ct); !ok || ct.Key != expr.CtKeyL3PROTOCOL {
			t.Errorf("first expr = %+v, want ct l3proto", rule.Exprs[0])
		}
	})

	t.Run("update in place", func(t *testing.T) {
		f := NewCtL3ProtoField(&nft.Rule{})
		f.valueInput.SetValue("ipv6")

		rule := &nftables.Rule{Exprs: []expr.Any{
			&expr.Ct{Key: expr.CtKeyL3PROTOCOL, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{2}},
		}}
		f.Save(rule)
		if len(rule.Exprs) != 2 {
			t.Fatalf("update grew the rule: %+v", rule.Exprs)
		}
	})
}

func TestEtherAddrField_Save(t *testing.T) {
	const mac = "aa:bb:cc:dd:ee:ff"

	t.Run("append onto empty rule", func(t *testing.T) {
		f := NewEtherSaddrField(&nft.Rule{})
		f.addrInput.SetValue(mac)

		rule := &nftables.Rule{}
		f.Save(rule)
		if len(rule.Exprs) != 2 {
			t.Fatalf("exprs = %+v, want Payload+Cmp", rule.Exprs)
		}
		if p, ok := rule.Exprs[0].(*expr.Payload); !ok || p.Base != expr.PayloadBaseLLHeader || p.Offset != 6 {
			t.Errorf("payload = %+v, want LL/6", rule.Exprs[0])
		}
	})

	t.Run("update existing Cmp", func(t *testing.T) {
		f := NewEtherSaddrField(&nft.Rule{})
		f.addrInput.SetValue(mac)

		rule := &nftables.Rule{Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: 6, Len: 6},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 0, 0, 0, 0, 0}},
		}}
		f.Save(rule)
		cmp := rule.Exprs[1].(*expr.Cmp)
		if !bytes.Equal(cmp.Data, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}) {
			t.Errorf("cmp data = %v, want the new MAC", cmp.Data)
		}
	})
}

func TestMetaIifField_Save(t *testing.T) {
	t.Run("append fresh pair (numeric index)", func(t *testing.T) {
		f := NewMetaIifField(&nft.Rule{})
		f.valueInput.SetValue("1") // numeric ifindex resolves without netlink

		rule := &nftables.Rule{}
		f.Save(rule)
		if len(rule.Exprs) != 2 {
			t.Fatalf("exprs = %+v, want Meta+Cmp", rule.Exprs)
		}
		if m, ok := rule.Exprs[0].(*expr.Meta); !ok || m.Key != f.metaKey {
			t.Errorf("first expr = %+v, want meta iif", rule.Exprs[0])
		}
	})

	t.Run("overwrite in place", func(t *testing.T) {
		f := NewMetaIifField(&nft.Rule{})
		f.valueInput.SetValue("2")

		rule := &nftables.Rule{Exprs: []expr.Any{
			&expr.Meta{Key: f.metaKey, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 0, 0, 1}},
		}}
		f.Save(rule)
		cmp := rule.Exprs[1].(*expr.Cmp)
		if !bytes.Equal(cmp.Data, []byte{0, 0, 0, 2}) {
			t.Errorf("cmp data = %v, want index 2 BE", cmp.Data)
		}
	})
}

func be32(v uint32) []byte {
	b := make([]byte, 4)
	b[0], b[1], b[2], b[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
	return b
}

func TestCtExpirationField_Save(t *testing.T) {
	// Save only updates an existing Ct{EXPIRATION} pair; values are seconds*1000.
	expRule := func() *nftables.Rule {
		return &nftables.Rule{Exprs: []expr.Any{
			&expr.Ct{Key: expr.CtKeyEXPIRATION, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: make([]byte, 4)},
		}}
	}

	t.Run("single duration", func(t *testing.T) {
		f := NewCtExpirationField(&nft.Rule{})
		f.input.SetValue("30s")

		rule := expRule()
		f.Save(rule)
		cmp, ok := rule.Exprs[1].(*expr.Cmp)
		if !ok || !bytes.Equal(cmp.Data, be32(30000)) {
			t.Errorf("expiration cmp = %+v, want 30000ms BE", rule.Exprs[1])
		}
	})

	t.Run("range duration", func(t *testing.T) {
		f := NewCtExpirationField(&nft.Rule{})
		f.input.SetValue("10s-20s")

		rule := expRule()
		f.Save(rule)
		rng, ok := rule.Exprs[1].(*expr.Range)
		if !ok || !bytes.Equal(rng.FromData, be32(10000)) || !bytes.Equal(rng.ToData, be32(20000)) {
			t.Errorf("expiration range = %+v, want 10000..20000ms", rule.Exprs[1])
		}
	})

	t.Run("single-element set", func(t *testing.T) {
		f := NewCtExpirationField(&nft.Rule{})
		f.input.SetValue("{45s}")

		rule := expRule()
		f.Save(rule)
		cmp, ok := rule.Exprs[1].(*expr.Cmp)
		if !ok || !bytes.Equal(cmp.Data, be32(45000)) {
			t.Errorf("expiration set cmp = %+v, want 45000ms BE", rule.Exprs[1])
		}
	})
}

func TestMetaIifnameField_Save(t *testing.T) {
	t.Run("append", func(t *testing.T) {
		f := NewMetaIifnameField(&nft.Rule{})
		f.valueInput.SetValue("eth0")

		rule := &nftables.Rule{}
		f.Save(rule)
		if len(rule.Exprs) != 2 {
			t.Fatalf("exprs = %+v, want Meta+Cmp", rule.Exprs)
		}
		if m, ok := rule.Exprs[0].(*expr.Meta); !ok || m.Key != unix.NFT_META_IIFNAME {
			t.Errorf("first expr = %+v, want meta iifname", rule.Exprs[0])
		}
	})

	t.Run("overwrite in place", func(t *testing.T) {
		f := NewMetaIifnameField(&nft.Rule{})
		f.valueInput.SetValue("wlan0")

		rule := &nftables.Rule{Exprs: []expr.Any{
			&expr.Meta{Key: unix.NFT_META_IIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: padIfname("eth0")},
		}}
		f.Save(rule)
		if len(rule.Exprs) != 2 {
			t.Fatalf("overwrite grew the rule: %+v", rule.Exprs)
		}
		cmp := rule.Exprs[1].(*expr.Cmp)
		if !bytes.Equal(cmp.Data, padIfname("wlan0")) {
			t.Errorf("cmp data not updated to wlan0")
		}
	})
}

func TestMetaIftypeField_Save(t *testing.T) {
	f := NewMetaIiftypeField(&nft.Rule{})
	f.valueInput.SetValue("ether")

	rule := &nftables.Rule{}
	f.Save(rule)
	if len(rule.Exprs) != 2 {
		t.Fatalf("exprs = %+v, want Meta+Cmp", rule.Exprs)
	}
	if m, ok := rule.Exprs[0].(*expr.Meta); !ok || m.Key != f.metaKey {
		t.Errorf("first expr = %+v, want meta iiftype", rule.Exprs[0])
	}
	cmp := rule.Exprs[1].(*expr.Cmp)
	if len(cmp.Data) != 2 {
		t.Errorf("iftype cmp data len = %d, want 2 (uint16 BE)", len(cmp.Data))
	}
}

func TestTcpDoffField_Save(t *testing.T) {
	f := NewTcpDoffField(&nft.Rule{})
	f.valueInput.SetValue("5") // doff 5 → encoded 0x50 in the high nibble

	rule := &nftables.Rule{}
	f.Save(rule)

	// Expect Payload{transport,12,1} + Bitwise{0xf0} + Cmp{0x50}.
	if len(rule.Exprs) != 3 {
		t.Fatalf("exprs = %+v, want Payload+Bitwise+Cmp", rule.Exprs)
	}
	if bw, ok := rule.Exprs[1].(*expr.Bitwise); !ok || len(bw.Mask) != 1 || bw.Mask[0] != 0xf0 {
		t.Errorf("bitwise = %+v, want mask 0xf0", rule.Exprs[1])
	}
	if cmp := rule.Exprs[2].(*expr.Cmp); !bytes.Equal(cmp.Data, []byte{0x50}) {
		t.Errorf("cmp data = %v, want 0x50", cmp.Data)
	}
}

func TestEtherTypeField_Save(t *testing.T) {
	t.Run("append", func(t *testing.T) {
		f := NewEtherTypeField(&nft.Rule{})
		f.customInput.SetValue("0x0800")

		rule := &nftables.Rule{}
		f.Save(rule)
		if len(rule.Exprs) != 2 {
			t.Fatalf("exprs = %+v, want Payload+Cmp", rule.Exprs)
		}
		if cmp := rule.Exprs[1].(*expr.Cmp); !bytes.Equal(cmp.Data, []byte{0x08, 0x00}) {
			t.Errorf("cmp data = %v, want 0x0800 BE", cmp.Data)
		}
	})

	t.Run("update existing", func(t *testing.T) {
		f := NewEtherTypeField(&nft.Rule{})
		f.customInput.SetValue("0x86dd")

		rule := &nftables.Rule{Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: 12, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x08, 0x00}},
		}}
		f.Save(rule)
		if cmp := rule.Exprs[1].(*expr.Cmp); !bytes.Equal(cmp.Data, []byte{0x86, 0xdd}) {
			t.Errorf("cmp data = %v, want 0x86dd", cmp.Data)
		}
	})
}

func TestDccpTypeField_Save(t *testing.T) {
	f := NewDccpTypeField(&nft.Rule{})
	f.typeSelect.SetValue("ack") // code 3 → encoded (3<<1)=6 in the high nibble bits

	rule := &nftables.Rule{}
	f.Save(rule)

	if !hasL4ProtoMatch(rule, unix.IPPROTO_DCCP) {
		t.Error("l4proto dccp prefix missing after set")
	}
	// Payload{transport,8,1} + Bitwise + Cmp{6}.
	for i, e := range rule.Exprs {
		if p, ok := e.(*expr.Payload); ok && p.Offset == 8 && p.Len == 1 {
			cmp, ok := rule.Exprs[i+2].(*expr.Cmp)
			if !ok || !bytes.Equal(cmp.Data, []byte{6}) {
				t.Errorf("dccp type cmp = %+v, want [6]", rule.Exprs[i+2])
			}
			return
		}
	}
	t.Errorf("no dccp payload found: %+v", rule.Exprs)
}

func TestIP6DscpField_Save(t *testing.T) {
	t.Run("append", func(t *testing.T) {
		f := NewIP6DscpField(&nft.Rule{})
		f.valueInput.SetValue("10")

		rule := &nftables.Rule{}
		f.Save(rule)
		if len(rule.Exprs) != 3 {
			t.Fatalf("exprs = %+v, want Payload+Bitwise+Cmp", rule.Exprs)
		}
		// dscp 10 → encoded [(10>>2)&0x0f, (10&3)<<6] = [2, 0x80].
		if cmp := rule.Exprs[2].(*expr.Cmp); !bytes.Equal(cmp.Data, []byte{2, 0x80}) {
			t.Errorf("dscp cmp = %v, want [2 0x80]", cmp.Data)
		}
	})

	t.Run("update existing", func(t *testing.T) {
		f := NewIP6DscpField(&nft.Rule{})
		f.valueInput.SetValue("4")

		rule := &nftables.Rule{Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 0, Len: 2},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 2, Mask: []byte{0x0f, 0xc0}, Xor: []byte{0, 0}},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 0}},
		}}
		f.Save(rule)
		if len(rule.Exprs) != 3 {
			t.Fatalf("update grew the rule: %+v", rule.Exprs)
		}
	})
}

func TestExthdrField_Save(t *testing.T) {
	t.Run("append frag nexthdr", func(t *testing.T) {
		f := NewFragNexthdrField(&nft.Rule{}) // type 44, offset 0, len 1
		f.valueInput.SetValue("6")

		rule := &nftables.Rule{}
		f.Save(rule)
		if len(rule.Exprs) != 2 {
			t.Fatalf("exprs = %+v, want Exthdr+Cmp", rule.Exprs)
		}
		eh, ok := rule.Exprs[0].(*expr.Exthdr)
		if !ok || eh.Type != 44 {
			t.Fatalf("first expr = %+v, want exthdr type 44", rule.Exprs[0])
		}
		if cmp := rule.Exprs[1].(*expr.Cmp); !bytes.Equal(cmp.Data, []byte{6}) {
			t.Errorf("cmp data = %v, want [6]", cmp.Data)
		}
	})

	t.Run("update existing", func(t *testing.T) {
		f := NewFragNexthdrField(&nft.Rule{})
		f.valueInput.SetValue("17")

		rule := &nftables.Rule{Exprs: []expr.Any{
			&expr.Exthdr{DestRegister: 1, Type: 44, Offset: 0, Len: 1, Op: expr.ExthdrOpIpv6},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
		}}
		f.Save(rule)
		if cmp := rule.Exprs[1].(*expr.Cmp); !bytes.Equal(cmp.Data, []byte{17}) {
			t.Errorf("cmp data = %v, want [17]", cmp.Data)
		}
	})
}

func TestMetaIifField_ValidateForSave(t *testing.T) {
	f := NewMetaIifField(&nft.Rule{})

	// A non-numeric, non-existent interface name fails to resolve → error.
	f.valueInput.SetValue("no_such_iface_zzz")
	if err := f.ValidateForSave(); err == nil {
		t.Error("unresolvable iif name passed validation")
	}

	// A numeric ifindex always resolves → nil.
	f.valueInput.SetValue("1")
	if err := f.ValidateForSave(); err != nil {
		t.Errorf("numeric ifindex = %v, want nil", err)
	}
}

func TestExtractMasqState(t *testing.T) {
	enabled, flags := extractMasqState(&nft.Rule{Actions: []nft.Action{{
		Type: nft.ActionTypeMasq,
		Masq: &nft.MasqueradeAction{Random: true, Persistent: true},
	}}})
	if !enabled {
		t.Fatal("masq action not detected as enabled")
	}
	if len(flags) != 2 {
		t.Errorf("flags = %v, want random+persistent", flags)
	}

	// No masq action → disabled, no flags.
	if en, fl := extractMasqState(&nft.Rule{}); en || fl != nil {
		t.Errorf("empty rule = %v/%v, want false/nil", en, fl)
	}
}

func TestIP6FlowlabelField_Save(t *testing.T) {
	f := NewIP6FlowlabelField(&nft.Rule{})
	f.valueInput.SetValue("100")

	rule := &nftables.Rule{}
	f.Save(rule)
	if len(rule.Exprs) != 3 {
		t.Fatalf("exprs = %+v, want Payload+Bitwise+Cmp", rule.Exprs)
	}
	if p, ok := rule.Exprs[0].(*expr.Payload); !ok || p.Offset != 1 || p.Len != 3 {
		t.Errorf("payload = %+v, want offset 1 len 3", rule.Exprs[0])
	}
}

func TestMetaOifnameField_Save(t *testing.T) {
	f := NewMetaOifnameField(&nft.Rule{})
	f.valueInput.SetValue("eth1")

	rule := &nftables.Rule{}
	f.Save(rule)
	if len(rule.Exprs) != 2 {
		t.Fatalf("exprs = %+v, want Meta+Cmp", rule.Exprs)
	}
	if m, ok := rule.Exprs[0].(*expr.Meta); !ok || m.Key != unix.NFT_META_OIFNAME {
		t.Errorf("first expr = %+v, want meta oifname", rule.Exprs[0])
	}
}

func TestLogField_ValidateForSave(t *testing.T) {
	logRule := func() *nft.Rule {
		return &nft.Rule{Actions: []nft.Action{{
			Type: nft.ActionTypeLog,
			Log:  &nft.LogAction{Prefix: "x"},
		}}}
	}

	// level + group is invalid in NFLOG mode → error.
	t.Run("level with group", func(t *testing.T) {
		f := NewLogField(logRule())
		f.groupInput.SetValue("2")
		f.levelSelect.SetValue(string(nft.LogLevelInfo))
		if err := f.ValidateForSave(); err == nil {
			t.Error("level+group passed validation")
		}
	})

	// snaplen without a group is rejected.
	t.Run("snaplen without group", func(t *testing.T) {
		f := NewLogField(logRule())
		f.snaplenInput.SetValue("128")
		if err := f.ValidateForSave(); err == nil {
			t.Error("snaplen without group passed validation")
		}
	})
}

func TestNATField_Save(t *testing.T) {
	t.Run("enabled appends NAT", func(t *testing.T) {
		f := NewSnatField(&nft.Rule{}, nftables.TableFamilyIPv4)
		f.enableInput.SetValue("on")
		f.addrInput.SetValue("192.168.1.100")

		rule := &nftables.Rule{}
		f.Save(rule)

		found := false
		for _, e := range rule.Exprs {
			if n, ok := e.(*expr.NAT); ok && n.Type == expr.NATTypeSourceNAT {
				found = true
			}
		}
		if !found {
			t.Errorf("no SNAT appended: %+v", rule.Exprs)
		}
	})

	t.Run("disabled strips the existing NAT and its Immediate", func(t *testing.T) {
		f := NewSnatField(&nft.Rule{}, nftables.TableFamilyIPv4)
		f.addrInput.SetValue("10.0.0.1") // addr change → Changed(), still disabled

		rule := &nftables.Rule{Exprs: []expr.Any{
			&expr.Immediate{Register: 1, Data: []byte{10, 0, 0, 9}},
			&expr.NAT{Type: expr.NATTypeSourceNAT, RegAddrMin: 1},
		}}
		f.Save(rule)

		for _, e := range rule.Exprs {
			if _, ok := e.(*expr.NAT); ok {
				t.Errorf("NAT survived disable: %+v", rule.Exprs)
			}
		}
	})
}

func TestLogField_Save(t *testing.T) {
	// hasLog requires a log action in the source rule.
	logRule := func() *nft.Rule {
		return &nft.Rule{Actions: []nft.Action{{
			Type: nft.ActionTypeLog,
			Log:  &nft.LogAction{Prefix: "old"},
		}}}
	}

	t.Run("replaces existing Log with a new prefix", func(t *testing.T) {
		f := NewLogField(logRule())
		f.prefixInput.SetValue("blocked")

		rule := &nftables.Rule{Exprs: []expr.Any{&expr.Log{Data: []byte("old")}}}
		f.Save(rule)

		lg, ok := rule.Exprs[0].(*expr.Log)
		if !ok || string(lg.Data) != "blocked" {
			t.Errorf("log = %+v, want prefix blocked", rule.Exprs[0])
		}
	})

	t.Run("NFLOG group + snaplen branches", func(t *testing.T) {
		f := NewLogField(logRule())
		f.groupInput.SetValue("2")
		f.snaplenInput.SetValue("128")

		rule := &nftables.Rule{Exprs: []expr.Any{&expr.Log{}}}
		f.Save(rule)

		lg := rule.Exprs[0].(*expr.Log)
		if lg.Group != 2 || lg.Snaplen != 128 {
			t.Errorf("log = %+v, want group 2 / snaplen 128", lg)
		}
	})
}

// findPayloadCmp returns the Cmp that follows a transport-header Payload at the
// given offset/length, or nil.
func findPayloadCmp(exprs []expr.Any, offset, length uint32) *expr.Cmp {
	for i, e := range exprs {
		p, ok := e.(*expr.Payload)
		if !ok || p.Base != expr.PayloadBaseTransportHeader || p.Offset != offset || p.Len != length {
			continue
		}
		if i+1 < len(exprs) {
			if c, ok := exprs[i+1].(*expr.Cmp); ok {
				return c
			}
		}
	}
	return nil
}

func TestIcmpTypeField_Save(t *testing.T) {
	t.Run("set inserts l4proto prefix + payload pair", func(t *testing.T) {
		f := NewIcmpTypeField(&nft.Rule{})
		f.customInput.SetValue("8") // echo-request, numeric fallback

		rule := &nftables.Rule{}
		f.Save(rule)

		if !hasIcmpL4Match(rule) {
			t.Error("l4proto icmp prefix missing after set")
		}
		cmp := findPayloadCmp(rule.Exprs, 0, 1)
		if cmp == nil || !bytes.Equal(cmp.Data, []byte{8}) {
			t.Errorf("icmp type cmp = %+v, want [8]", cmp)
		}
	})

	t.Run("clear removes the payload pair", func(t *testing.T) {
		// Construct from a rule that already carries an icmp type so clearing
		// flips Changed() and hits the remove branch.
		withType := &nft.Rule{Conditions: []nft.Condition{{
			Payload: &nft.PayloadCondition{Protocol: nft.PayloadProtoICMP, Field: "type", Value: uint8(8)},
		}}}
		f := NewIcmpTypeField(withType)
		f.typeSelect.SetValue("")
		f.customInput.SetValue("")

		rule := &nftables.Rule{Exprs: append(icmpL4Wire(),
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{8}},
		)}
		f.Save(rule)
		if findPayloadCmp(rule.Exprs, 0, 1) != nil {
			t.Errorf("icmp type pair survived clear: %+v", rule.Exprs)
		}
	})
}

func findCt(exprs []expr.Any, key expr.CtKey) *expr.Ct {
	for _, e := range exprs {
		if c, ok := e.(*expr.Ct); ok && c.Key == key {
			return c
		}
	}
	return nil
}

func TestCtCounterFields_Save(t *testing.T) {
	// bytes: insert with reply direction → Direction 1, OptDirection true.
	t.Run("bytes insert reply", func(t *testing.T) {
		f := NewCtBytesField(&nft.Rule{})
		f.valueInput.SetValue("100")
		f.directionInput.SetValue("reply")

		rule := &nftables.Rule{}
		f.Save(rule)

		ct := findCt(rule.Exprs, expr.CtKeyBYTES)
		if ct == nil || ct.Direction != 1 || !ct.OptDirection {
			t.Fatalf("ct bytes = %+v, want Direction 1 / OptDirection", ct)
		}
		cmp := rule.Exprs[1].(*expr.Cmp)
		if !bytes.Equal(cmp.Data, []byte{100, 0, 0, 0, 0, 0, 0, 0}) {
			t.Errorf("cmp data = %v, want LE 100", cmp.Data)
		}
	})

	// pkts: insert with original direction → Direction 0, OptDirection true.
	t.Run("pkts insert original", func(t *testing.T) {
		f := NewCtPktsField(&nft.Rule{})
		f.valueInput.SetValue("5")
		f.directionInput.SetValue("original")

		rule := &nftables.Rule{}
		f.Save(rule)
		if ct := findCt(rule.Exprs, expr.CtKeyPKTS); ct == nil || ct.Direction != 0 || !ct.OptDirection {
			t.Fatalf("ct pkts = %+v, want Direction 0 / OptDirection", ct)
		}
	})

	// avgpkt: insert with no direction → Direction 255, OptDirection false.
	t.Run("avgpkt insert no direction", func(t *testing.T) {
		f := NewCtAvgpktField(&nft.Rule{})
		f.valueInput.SetValue("7")

		rule := &nftables.Rule{}
		f.Save(rule)
		if ct := findCt(rule.Exprs, expr.CtKeyAVGPKT); ct == nil || ct.Direction != 255 || ct.OptDirection {
			t.Fatalf("ct avgpkt = %+v, want Direction 255 / no OptDirection", ct)
		}
	})

	// bytes: update an existing Ct+Cmp pair in place.
	t.Run("bytes update existing", func(t *testing.T) {
		f := NewCtBytesField(&nft.Rule{})
		f.valueInput.SetValue("200")

		rule := &nftables.Rule{Exprs: []expr.Any{
			&expr.Ct{Key: expr.CtKeyBYTES, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: make([]byte, 8)},
		}}
		f.Save(rule)
		cmp := rule.Exprs[1].(*expr.Cmp)
		if !bytes.Equal(cmp.Data, []byte{200, 0, 0, 0, 0, 0, 0, 0}) {
			t.Errorf("cmp data = %v, want LE 200", cmp.Data)
		}
	})
}

func TestIcmpCodeField_Save(t *testing.T) {
	f := NewIcmpCodeField(&nft.Rule{})
	f.valueInput.SetValue("3") // code at transport offset 1

	rule := &nftables.Rule{}
	f.Save(rule)

	if !hasIcmpL4Match(rule) {
		t.Error("l4proto icmp prefix missing")
	}
	if cmp := findPayloadCmp(rule.Exprs, 1, 1); cmp == nil || !bytes.Equal(cmp.Data, []byte{3}) {
		t.Errorf("icmp code cmp = %+v, want [3]", cmp)
	}
}

func TestIcmpv6TypeField_Save(t *testing.T) {
	f := NewIcmpv6TypeField(&nft.Rule{})
	f.typeSelect.SetValue("echo-request") // 128

	rule := &nftables.Rule{}
	f.Save(rule)

	cmp := findPayloadCmp(rule.Exprs, 0, 1)
	if cmp == nil || !bytes.Equal(cmp.Data, []byte{128}) {
		t.Errorf("icmpv6 type cmp = %+v, want [128]", cmp)
	}
}

func TestIcmpv6CodeField_Save(t *testing.T) {
	f := NewIcmpv6CodeField(&nft.Rule{})
	f.valueInput.SetValue("1")

	rule := &nftables.Rule{}
	f.Save(rule)

	if cmp := findPayloadCmp(rule.Exprs, 1, 1); cmp == nil || !bytes.Equal(cmp.Data, []byte{1}) {
		t.Errorf("icmpv6 code cmp = %+v, want [1]", cmp)
	}
}

func TestTcpFlagsField_Save(t *testing.T) {
	t.Run("set appends payload pair", func(t *testing.T) {
		f := NewTcpFlagsField(&nft.Rule{})
		f.input.SetValues([]string{"syn", "ack"})

		rule := &nftables.Rule{}
		f.Save(rule)

		cmp := findPayloadCmp(rule.Exprs, 13, 1)
		if cmp == nil || cmp.Data[0] != (tcpFlagSYN|tcpFlagACK) {
			t.Errorf("tcp flags cmp = %+v, want syn|ack", cmp)
		}
	})

	t.Run("update existing pair", func(t *testing.T) {
		f := NewTcpFlagsField(&nft.Rule{})
		f.input.SetValues([]string{"rst"})

		rule := &nftables.Rule{Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{tcpFlagSYN}},
		}}
		f.Save(rule)
		if cmp := findPayloadCmp(rule.Exprs, 13, 1); cmp == nil || cmp.Data[0] != tcpFlagRST {
			t.Errorf("tcp flags update = %+v, want rst", cmp)
		}
	})
}

func TestTransportUintField_Save(t *testing.T) {
	t.Run("set appends dport pair", func(t *testing.T) {
		f := NewTcpDportField(&nft.Rule{})
		f.valueInput.SetValue("443")

		rule := &nftables.Rule{}
		f.Save(rule)

		cmp := findPayloadCmp(rule.Exprs, 2, 2)
		if cmp == nil || !bytes.Equal(cmp.Data, []byte{0x01, 0xbb}) {
			t.Errorf("dport cmp = %+v, want 443", cmp)
		}
	})

	t.Run("update existing dport", func(t *testing.T) {
		f := NewTcpDportField(&nft.Rule{})
		f.valueInput.SetValue("8080")

		rule := &nftables.Rule{Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 22}},
		}}
		f.Save(rule)
		if cmp := findPayloadCmp(rule.Exprs, 2, 2); cmp == nil || !bytes.Equal(cmp.Data, []byte{0x1f, 0x90}) {
			t.Errorf("dport update = %+v, want 8080", cmp)
		}
	})
}

// The 16-bit cell at transport offset 4 is `udp length` under a udp l4proto
// context but `udplite csumcov` under a udplite one — two different fields on
// one wire cell, so a single editor renames itself from the rule's context
// instead of the tab carrying two colliding editors for the same offset.
func TestUdpLengthField_RenamesUnderUdplite(t *testing.T) {
	udplite := &nft.Rule{Conditions: []nft.Condition{
		{Type: nft.ConditionTypeMeta, Operation: nft.CompareOpEq,
			Meta: &nft.MetaCondition{Key: nft.MetaKeyL4Proto, Value: uint8(unix.IPPROTO_UDPLITE)}},
		{Type: nft.ConditionTypePayload, Operation: nft.CompareOpEq,
			Payload: &nft.PayloadCondition{Protocol: nft.PayloadProtoUDPLITE, Field: "csumcov", Value: uint16(8)}},
	}}
	udp := &nft.Rule{Conditions: []nft.Condition{
		{Type: nft.ConditionTypeMeta, Operation: nft.CompareOpEq,
			Meta: &nft.MetaCondition{Key: nft.MetaKeyL4Proto, Value: uint8(unix.IPPROTO_UDP)}},
		{Type: nft.ConditionTypePayload, Operation: nft.CompareOpEq,
			Payload: &nft.PayloadCondition{Protocol: nft.PayloadProtoUDP, Field: "length", Value: uint16(1500)}},
	}}

	t.Run("udplite context", func(t *testing.T) {
		f := NewUdpLengthField(udplite)
		if !strings.Contains(f.View(), "UDPLITE csumcov") {
			t.Errorf("label = %q, want it to name UDPLITE csumcov", f.label)
		}
		if f.originalValue != 8 {
			t.Errorf("originalValue = %d, want 8 (the csumcov condition was not picked up)", f.originalValue)
		}
	})

	t.Run("udp context", func(t *testing.T) {
		f := NewUdpLengthField(udp)
		if !strings.Contains(f.View(), "UDP length") {
			t.Errorf("label = %q, want it to name UDP length", f.label)
		}
		if f.originalValue != 1500 {
			t.Errorf("originalValue = %d, want 1500", f.originalValue)
		}
	})

	t.Run("no context falls back to UDP length", func(t *testing.T) {
		f := NewUdpLengthField(&nft.Rule{})
		if !strings.Contains(f.View(), "UDP length") {
			t.Errorf("label = %q, want the UDP fallback", f.label)
		}
	})

	// Whichever name it wears, it edits the same wire cell.
	t.Run("saves to transport offset 4 under either name", func(t *testing.T) {
		for name, rd := range map[string]*nft.Rule{"udplite": udplite, "udp": udp} {
			f := NewUdpLengthField(rd)
			f.valueInput.SetValue("12")
			rule := &nftables.Rule{}
			f.Save(rule)
			if cmp := findPayloadCmp(rule.Exprs, 4, 2); cmp == nil || !bytes.Equal(cmp.Data, []byte{0, 12}) {
				t.Errorf("%s: cmp = %+v, want 12 at transport offset 4", name, cmp)
			}
		}
	})
}
