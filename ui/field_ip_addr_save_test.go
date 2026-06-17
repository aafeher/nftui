package ui

// Direct branch coverage for applyIPAddrSave / applyIP6AddrSave — the
// Payload→[Bitwise→]Cmp rewrite logic behind the ip/ip6 saddr/daddr editors.
// These are package-level functions taking a *nftables.Rule, so each rewrite
// shape (in-place Cmp, Bitwise insert/remove, prepend-new, the early-return
// guards) is reachable without driving the field through Bubble Tea.

import (
	"bytes"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func countType[T any](exprs []expr.Any) int {
	n := 0
	for _, e := range exprs {
		if _, ok := e.(T); ok {
			n++
		}
	}
	return n
}

func TestApplyIPAddrSave(t *testing.T) {
	const off = 12 // saddr

	t.Run("empty value is a no-op", func(t *testing.T) {
		r := &nftables.Rule{}
		applyIPAddrSave(r, off, "", expr.CmpOpEq)
		if len(r.Exprs) != 0 {
			t.Errorf("empty val mutated rule: %+v", r.Exprs)
		}
	})

	t.Run("invalid value is a no-op", func(t *testing.T) {
		r := &nftables.Rule{}
		applyIPAddrSave(r, off, "not-an-ip", expr.CmpOpEq)
		if len(r.Exprs) != 0 {
			t.Errorf("invalid val mutated rule: %+v", r.Exprs)
		}
	})

	t.Run("ipv6 value rejected for ipv4 field", func(t *testing.T) {
		r := &nftables.Rule{}
		applyIPAddrSave(r, off, "2001:db8::1", expr.CmpOpEq)
		if len(r.Exprs) != 0 {
			t.Errorf("ipv6 val mutated ipv4 field: %+v", r.Exprs)
		}
	})

	t.Run("prepend exact IP onto empty rule", func(t *testing.T) {
		r := &nftables.Rule{}
		applyIPAddrSave(r, off, "10.0.0.5", expr.CmpOpEq)
		if len(r.Exprs) != 2 || countType[*expr.Payload](r.Exprs) != 1 || countType[*expr.Cmp](r.Exprs) != 1 {
			t.Fatalf("prepend exact = %+v, want Payload+Cmp", r.Exprs)
		}
		cmp := r.Exprs[1].(*expr.Cmp)
		if !bytes.Equal(cmp.Data, []byte{10, 0, 0, 5}) {
			t.Errorf("cmp data = %v, want 10.0.0.5", cmp.Data)
		}
	})

	t.Run("prepend CIDR onto empty rule inserts Bitwise", func(t *testing.T) {
		r := &nftables.Rule{}
		applyIPAddrSave(r, off, "10.0.0.0/24", expr.CmpOpEq)
		if countType[*expr.Bitwise](r.Exprs) != 1 || len(r.Exprs) != 3 {
			t.Fatalf("prepend CIDR = %+v, want Payload+Bitwise+Cmp", r.Exprs)
		}
	})

	t.Run("existing Payload+Cmp exact updates in place", func(t *testing.T) {
		r := &nftables.Rule{Exprs: []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: 4, DestRegister: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1, 1, 1, 1}},
		}}
		applyIPAddrSave(r, off, "8.8.8.8", expr.CmpOpNeq)
		if len(r.Exprs) != 2 {
			t.Fatalf("in-place grew the rule: %+v", r.Exprs)
		}
		cmp := r.Exprs[1].(*expr.Cmp)
		if !bytes.Equal(cmp.Data, []byte{8, 8, 8, 8}) || cmp.Op != expr.CmpOpNeq {
			t.Errorf("cmp = %+v, want 8.8.8.8 neq", cmp)
		}
	})

	t.Run("existing Payload+Cmp CIDR inserts Bitwise", func(t *testing.T) {
		r := &nftables.Rule{Exprs: []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: 4, DestRegister: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1, 1, 1, 1}},
		}}
		applyIPAddrSave(r, off, "192.168.0.0/16", expr.CmpOpEq)
		if countType[*expr.Bitwise](r.Exprs) != 1 || len(r.Exprs) != 3 {
			t.Fatalf("CIDR onto exact = %+v, want Bitwise inserted", r.Exprs)
		}
	})

	t.Run("existing Payload+Bitwise+Cmp CIDR updates mask", func(t *testing.T) {
		r := &nftables.Rule{Exprs: []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: 4, DestRegister: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: []byte{255, 255, 255, 0}, Xor: []byte{0, 0, 0, 0}},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{10, 0, 0, 0}},
		}}
		applyIPAddrSave(r, off, "172.16.0.0/12", expr.CmpOpEq)
		if len(r.Exprs) != 3 || countType[*expr.Bitwise](r.Exprs) != 1 {
			t.Fatalf("CIDR update = %+v, want unchanged shape", r.Exprs)
		}
		cmp := r.Exprs[2].(*expr.Cmp)
		if !bytes.Equal(cmp.Data, []byte{172, 16, 0, 0}) {
			t.Errorf("cmp data = %v, want 172.16.0.0", cmp.Data)
		}
	})

	t.Run("existing Payload+Bitwise+Cmp exact removes Bitwise", func(t *testing.T) {
		r := &nftables.Rule{Exprs: []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: 4, DestRegister: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: []byte{255, 255, 255, 0}, Xor: []byte{0, 0, 0, 0}},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{10, 0, 0, 0}},
		}}
		applyIPAddrSave(r, off, "8.8.4.4", expr.CmpOpEq)
		if countType[*expr.Bitwise](r.Exprs) != 0 || len(r.Exprs) != 2 {
			t.Fatalf("exact onto CIDR = %+v, want Bitwise removed", r.Exprs)
		}
	})

	t.Run("Payload with no following expr is a no-op", func(t *testing.T) {
		r := &nftables.Rule{Exprs: []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: 4, DestRegister: 1},
		}}
		applyIPAddrSave(r, off, "8.8.8.8", expr.CmpOpEq)
		if len(r.Exprs) != 1 {
			t.Errorf("dangling Payload mutated: %+v", r.Exprs)
		}
	})
}

func TestApplyIP6AddrSave(t *testing.T) {
	const off = 8 // ip6 saddr

	t.Run("invalid value no-op", func(t *testing.T) {
		r := &nftables.Rule{}
		applyIP6AddrSave(r, off, "garbage", expr.CmpOpEq)
		if len(r.Exprs) != 0 {
			t.Errorf("invalid v6 mutated rule: %+v", r.Exprs)
		}
	})

	t.Run("prepend exact onto empty rule", func(t *testing.T) {
		r := &nftables.Rule{}
		applyIP6AddrSave(r, off, "2001:db8::1", expr.CmpOpEq)
		if len(r.Exprs) != 2 {
			t.Fatalf("prepend v6 = %+v, want Payload+Cmp", r.Exprs)
		}
		if cmp := r.Exprs[1].(*expr.Cmp); len(cmp.Data) != 16 {
			t.Errorf("v6 cmp data len = %d, want 16", len(cmp.Data))
		}
	})

	t.Run("prepend CIDR inserts Bitwise", func(t *testing.T) {
		r := &nftables.Rule{}
		applyIP6AddrSave(r, off, "2001:db8::/32", expr.CmpOpEq)
		if countType[*expr.Bitwise](r.Exprs) != 1 || len(r.Exprs) != 3 {
			t.Fatalf("v6 CIDR = %+v, want Payload+Bitwise+Cmp", r.Exprs)
		}
	})

	t.Run("existing Payload+Bitwise+Cmp exact removes Bitwise", func(t *testing.T) {
		r := &nftables.Rule{Exprs: []expr.Any{
			&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: 16, DestRegister: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 16, Mask: make([]byte, 16), Xor: make([]byte, 16)},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: make([]byte, 16)},
		}}
		applyIP6AddrSave(r, off, "2001:db8::99", expr.CmpOpEq)
		if countType[*expr.Bitwise](r.Exprs) != 0 || len(r.Exprs) != 2 {
			t.Fatalf("v6 exact onto CIDR = %+v, want Bitwise removed", r.Exprs)
		}
	})
}
