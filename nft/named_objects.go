package nft

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// NamedObject is a UI-friendly summary of a single nftables stateful named
// object (counter, quota, ct helper, …). Fields not relevant to a given
// type are left at their zero values.
//
// The Raw field retains the underlying Obj so callers that need the live
// counter/quota values (e.g. for reset) can downcast without re-fetching.
type NamedObject struct {
	Name    string
	Type    nftables.ObjType
	TypeStr string // human label: "counter", "quota", "cthelper", ...

	// Counter
	Packets uint64
	Bytes   uint64

	// Quota
	QuotaBytes uint64
	Consumed   uint64
	// nftables doesn't surface QuotaObj.Over via the legacy decoder for
	// every kernel build, so we don't expose it here.

	// CT helper
	HelperName string // e.g. "ftp"
	L3Proto    uint16
	L4Proto    uint8

	Raw nftables.Obj
}

// ListNamedObjects enumerates the stateful objects attached to the given
// table.
//
// Uses GetNamedObjects (the non-legacy path) — the legacy GetObjects
// returns "malformed stateful object" on kernels where it sees a type its
// hard-coded switch doesn't cover (e.g. cthelper), and that broke the
// whole call. The NamedObj path decodes the inner expr by name and we
// extract Counter / Quota / CtHelper details from there.
func ListNamedObjects(table *nftables.Table) ([]NamedObject, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to nftables: %v", err)
	}
	raws, err := conn.GetNamedObjects(table)
	if err != nil {
		return nil, fmt.Errorf("failed to list named objects: %v", err)
	}
	out := make([]NamedObject, 0, len(raws))
	for _, o := range raws {
		out = append(out, summarizeObj(o))
	}
	return out, nil
}

// ObjTypeLabel returns the short string for an nftables.ObjType (matches the
// nft CLI keyword: "counter", "quota", "cthelper", ...).
func ObjTypeLabel(t nftables.ObjType) string {
	switch t {
	case nftables.ObjTypeCounter:
		return "counter"
	case nftables.ObjTypeQuota:
		return "quota"
	case nftables.ObjTypeCtHelper:
		return "cthelper"
	case nftables.ObjTypeLimit:
		return "limit"
	case nftables.ObjTypeConnLimit:
		return "connlimit"
	case nftables.ObjTypeTunnel:
		return "tunnel"
	case nftables.ObjTypeCtTimeout:
		return "cttimeout"
	case nftables.ObjTypeSecMark:
		return "secmark"
	case nftables.ObjTypeCtExpect:
		return "ctexpect"
	case nftables.ObjTypeSynProxy:
		return "synproxy"
	}
	return fmt.Sprintf("obj_%d", uint32(t))
}

// ResetNamedObject zeros the live state of a stateful object on the
// kernel. For counters this clears Packets/Bytes; for quotas it clears
// Consumed. Other types are no-ops at the kernel side (the call still
// succeeds).
//
// `obj.Raw` must be the original nftables.Obj returned by
// ListNamedObjects — we pass it straight to Conn.ResetObject so the
// netlink request matches by table+name+type.
func ResetNamedObject(obj NamedObject) error {
	if obj.Raw == nil {
		return fmt.Errorf("reset: no underlying object reference")
	}
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %v", err)
	}
	if _, err := conn.ResetObject(obj.Raw); err != nil {
		return fmt.Errorf("failed to reset %s %q: %v", obj.TypeStr, obj.Name, err)
	}
	return nil
}

func summarizeObj(o nftables.Obj) NamedObject {
	v, ok := o.(*nftables.NamedObj)
	if !ok || v == nil {
		// GetNamedObjects always returns *NamedObj on this lib version; the
		// fallback exists only to avoid a panic if upstream changes.
		return NamedObject{Name: "?", TypeStr: "unknown", Raw: o}
	}
	no := NamedObject{
		Name:    v.Name,
		Type:    v.Type,
		TypeStr: ObjTypeLabel(v.Type),
		Raw:     o,
	}
	switch v.Type {
	case nftables.ObjTypeCounter:
		if c, ok := v.Obj.(*expr.Counter); ok && c != nil {
			no.Packets = c.Packets
			no.Bytes = c.Bytes
		}
	case nftables.ObjTypeQuota:
		if q, ok := v.Obj.(*expr.Quota); ok && q != nil {
			no.QuotaBytes = q.Bytes
			no.Consumed = q.Consumed
		}
	case nftables.ObjTypeCtHelper:
		if h, ok := v.Obj.(*expr.CtHelper); ok && h != nil {
			no.HelperName = h.Name
			no.L3Proto = h.L3Proto
			no.L4Proto = h.L4Proto
		}
	}
	return no
}
