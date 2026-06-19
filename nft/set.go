package nft

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type Set struct {
	Set      nftables.Set
	Elements []nftables.SetElement
}

type Sets []Set

func GetSets(table *nftables.Table) ([]*nftables.Set, error) {
	conn := &nftables.Conn{}
	sets, err := conn.GetSets(table)
	if err != nil {
		return nil, err
	}
	return sets, nil
}

func GetSetByName(table *nftables.Table, name string) (*nftables.Set, error) {
	conn := &nftables.Conn{}
	set, err := conn.GetSetByName(table, name)
	if err != nil {
		return nil, err
	}
	return set, nil
}

// GetSetElements fetches a set's elements over netlink and normalizes them for
// the renderers (see decodeSetElements). It returns the netlink error rather
// than terminating the process: a transient read failure must surface as a
// recoverable error in the caller, not kill the TUI (and leave the terminal in
// raw mode by skipping Bubble Tea's restore). Callers treat an error as an
// empty / unchanged element list — anonymous unreferenced sets legitimately
// return nothing.
func GetSetElements(set *nftables.Set) ([]nftables.SetElement, error) {
	conn := &nftables.Conn{}
	elements, err := conn.GetSetElements(set)
	if err != nil {
		return nil, err
	}
	return decodeSetElements(set, elements), nil
}

// decodeSetElements is the netlink-free post-processing core of
// GetSetElements: the vmap VerdictData fixup and the interval pairing. Kept
// separate from the fetch so both branches are unit-testable without a kernel.
func decodeSetElements(set *nftables.Set, elements []nftables.SetElement) []nftables.SetElement {
	// google/nftables (v0.3.1) doesn't populate SetElement.VerdictData on
	// reads for vmap elements — the verdict bytes land in Val instead.
	// Decode them ourselves so renderers can rely on VerdictData.
	if set.IsMap && set.DataType.Name == nftables.TypeVerdict.Name {
		for i := range elements {
			if elements[i].VerdictData == nil && len(elements[i].Val) > 0 {
				if v, ok := decodeVerdictBytes(elements[i].Val); ok {
					elements[i].VerdictData = v
					elements[i].Val = nil
				}
			}
		}
	}

	// Interval sets are stored on the wire as two physical elements per
	// logical entry: {Key=start} and {Key=end+1, IntervalEnd=true}. The
	// lib doesn't fold them back, so the bare list looks like every
	// other entry has a stray "marker" sibling. Pair them up so the UI
	// renders one row per range and Delete knows both halves to remove.
	if set.Interval {
		elements = pairIntervalElements(elements)
	}
	return elements
}

// pairIntervalElements walks the sorted physical element list and folds
// each `IntervalEnd=true` close-marker into the preceding start
// element's KeyEnd (inclusive end = marker_key - 1). Single-host
// entries collapse to KeyEnd == Key. Markers without a preceding start
// (orphans from a previous version's delete path) are dropped.
func pairIntervalElements(els []nftables.SetElement) []nftables.SetElement {
	if len(els) == 0 {
		return els
	}
	sorted := make([]nftables.SetElement, len(els))
	copy(sorted, els)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i].Key, sorted[j].Key) < 0
	})
	out := make([]nftables.SetElement, 0, len(sorted))
	for _, el := range sorted {
		if el.IntervalEnd {
			if n := len(out); n > 0 && out[n-1].KeyEnd == nil {
				out[n-1].KeyEnd = decrementBytes(el.Key)
			}
			continue
		}
		out = append(out, el)
	}
	return out
}

// decrementBytes returns a copy of b decremented by one as a BigEndian
// integer. Wraps to all-0xff on underflow. Inverse of incrementBytes.
func decrementBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	for i := len(out) - 1; i >= 0; i-- {
		if out[i] != 0 {
			out[i]--
			return out
		}
		out[i] = 0xff
	}
	return out
}

// decodeVerdictBytes parses the inner netlink-attribute payload of a
// vmap data field. Layout: NFTA_VERDICT_CODE (int32 BE) and optionally
// NFTA_VERDICT_CHAIN (NUL-terminated string).
func decodeVerdictBytes(b []byte) (*expr.Verdict, bool) {
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return nil, false
	}
	ad.ByteOrder = binary.BigEndian
	v := &expr.Verdict{}
	saw := false
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_VERDICT_CODE:
			v.Kind = expr.VerdictKind(int32(ad.Uint32()))
			saw = true
		case unix.NFTA_VERDICT_CHAIN:
			v.Chain = ad.String()
		}
	}
	if ad.Err() != nil || !saw {
		return nil, false
	}
	return v, true
}

// ParseSetElementKey converts a human-readable element string into raw bytes
// matching the set's KeyType. Returns (key, keyEnd, err); keyEnd is non-nil
// only for `flags interval` sets when the input is a CIDR or `start-end`
// range. Supported datatypes:
//
//	ipv4_addr    → 4 bytes  (dotted-quad; CIDR / `start-end` for interval sets)
//	ipv6_addr    → 16 bytes (CIDR / `start-end` for interval sets)
//	ether_addr   → 6 bytes  (colon-separated MAC)
//	inet_service → 2 bytes  (TCP/UDP port; `start-end` range for interval sets)
//	inet_proto   → 1 byte
//	mark/integer → 4 bytes  (uint32, decimal or 0x-hex; `start-end` for intervals)
//
// On non-interval sets a CIDR / range input is rejected so the user is
// warned rather than silently truncated to the start address.
func ParseSetElementKey(set *nftables.Set, input string) ([]byte, []byte, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, nil, fmt.Errorf("empty value")
	}

	// Detect range / CIDR forms; only valid for interval sets.
	hasCIDR := strings.Contains(input, "/")
	hasRange := strings.Contains(input, "-") &&
		// MAC addresses use ':'; ranges use '-'. IPv6 has neither.
		set.KeyType.Name != nftables.TypeEtherAddr.Name
	if (hasCIDR || hasRange) && !set.Interval {
		return nil, nil, fmt.Errorf("range/CIDR input requires a `flags interval` set")
	}

	switch set.KeyType.Name {
	case nftables.TypeIPAddr.Name:
		if hasCIDR {
			start, end, err := cidrToRange(input, 4)
			if err != nil {
				return nil, nil, err
			}
			return start, end, nil
		}
		if hasRange {
			start, end, err := dashRangeToBytes(input, parseIP4)
			if err != nil {
				return nil, nil, err
			}
			return start, end, nil
		}
		b, err := parseIP4(input)
		if err != nil {
			return nil, nil, err
		}
		return b, nil, nil

	case nftables.TypeIP6Addr.Name:
		if hasCIDR {
			start, end, err := cidrToRange(input, 16)
			if err != nil {
				return nil, nil, err
			}
			return start, end, nil
		}
		if hasRange {
			start, end, err := dashRangeToBytes(input, parseIP6)
			if err != nil {
				return nil, nil, err
			}
			return start, end, nil
		}
		b, err := parseIP6(input)
		if err != nil {
			return nil, nil, err
		}
		return b, nil, nil

	case nftables.TypeEtherAddr.Name:
		mac, err := net.ParseMAC(input)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid MAC address: %q", input)
		}
		if len(mac) != 6 {
			return nil, nil, fmt.Errorf("ether_addr requires a 6-byte MAC, got %d bytes", len(mac))
		}
		return []byte(mac), nil, nil

	case nftables.TypeInetService.Name:
		if hasRange {
			start, end, err := dashRangeToBytes(input, parseInetService)
			if err != nil {
				return nil, nil, err
			}
			return start, end, nil
		}
		b, err := parseInetService(input)
		if err != nil {
			return nil, nil, err
		}
		return b, nil, nil

	case nftables.TypeInetProto.Name:
		n, err := strconv.ParseUint(input, 0, 8)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid protocol number: %q", input)
		}
		return []byte{byte(n)}, nil, nil

	case nftables.TypeMark.Name, nftables.TypeInteger.Name:
		// `mark` is always 4 bytes; `integer` may be 1/2/4/8 depending on
		// the user-chosen width carried in set.KeyType.Bytes. A zero
		// Bytes value falls back to 4 (the lib default).
		width := int(set.KeyType.Bytes)
		if width == 0 {
			width = 4
		}
		parse := func(s string) ([]byte, error) { return parseUintBE(s, width) }
		if hasRange {
			start, end, err := dashRangeToBytes(input, parse)
			if err != nil {
				return nil, nil, err
			}
			return start, end, nil
		}
		b, err := parse(input)
		if err != nil {
			return nil, nil, err
		}
		return b, nil, nil
	}

	return nil, nil, fmt.Errorf("unsupported key type for add/remove: %s", set.KeyType.Name)
}

// parseIP4 parses a single IPv4 dotted-quad into 4-byte BigEndian bytes.
func parseIP4(s string) ([]byte, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid IPv4 address: %q", s)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("not an IPv4 address: %q", s)
	}
	return []byte(ip4), nil
}

// parseIP6 parses a single IPv6 address into 16-byte BigEndian bytes.
func parseIP6(s string) ([]byte, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid IPv6 address: %q", s)
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return nil, fmt.Errorf("not an IPv6 address: %q", s)
	}
	return []byte(ip16), nil
}

// parseInetService parses a TCP/UDP port (decimal or 0x-hex) into 2-byte
// BigEndian. Uniform signature so the dash-range helper can reuse it.
func parseInetService(s string) ([]byte, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 0, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %q", s)
	}
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(n))
	return b, nil
}

// parseUintBE parses a decimal / 0x-hex unsigned integer into a
// BigEndian byte slice of `width` bytes (1, 2, 4 or 8). Rejects values
// that don't fit the chosen width.
func parseUintBE(s string, width int) ([]byte, error) {
	bits := width * 8
	if bits < 8 || bits > 64 {
		return nil, fmt.Errorf("integer width %d unsupported (1/2/4/8 bytes only)", width)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(s), 0, bits)
	if err != nil {
		return nil, fmt.Errorf("invalid %d-byte integer: %q", width, s)
	}
	b := make([]byte, width)
	switch width {
	case 1:
		b[0] = byte(n)
	case 2:
		binary.BigEndian.PutUint16(b, uint16(n))
	case 4:
		binary.BigEndian.PutUint32(b, uint32(n))
	case 8:
		binary.BigEndian.PutUint64(b, n)
	}
	return b, nil
}

// cidrToRange converts "<addr>/<prefix>" into (start, end) byte slices of
// width nbytes (4 for IPv4, 16 for IPv6). End is the last inclusive
// address in the range (broadcast). Matches the KeyEnd semantics used by
// nftables (inclusive).
func cidrToRange(cidr string, nbytes int) ([]byte, []byte, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid CIDR: %q", cidr)
	}
	ip := ipnet.IP
	mask := ipnet.Mask
	if nbytes == 4 {
		ip = ip.To4()
		if ip == nil || len(mask) != 4 {
			return nil, nil, fmt.Errorf("expected IPv4 CIDR, got %q", cidr)
		}
	} else {
		ip = ip.To16()
		if ip == nil || len(mask) != 16 {
			return nil, nil, fmt.Errorf("expected IPv6 CIDR, got %q", cidr)
		}
	}
	start := make([]byte, nbytes)
	end := make([]byte, nbytes)
	for i := 0; i < nbytes; i++ {
		start[i] = ip[i] & mask[i]
		end[i] = start[i] | ^mask[i]
	}
	return start, end, nil
}

// dashRangeToBytes parses `<start>-<end>` form using the supplied
// single-value parser. Both bounds are returned inclusive.
func dashRangeToBytes(in string, parse func(string) ([]byte, error)) ([]byte, []byte, error) {
	idx := strings.Index(in, "-")
	if idx < 0 {
		return nil, nil, fmt.Errorf("not a range: %q", in)
	}
	lo := strings.TrimSpace(in[:idx])
	hi := strings.TrimSpace(in[idx+1:])
	start, err := parse(lo)
	if err != nil {
		return nil, nil, fmt.Errorf("range start: %v", err)
	}
	end, err := parse(hi)
	if err != nil {
		return nil, nil, fmt.Errorf("range end: %v", err)
	}
	return start, end, nil
}

// KeyTypeFromString maps a label produced by KeyTypeToString back to its
// nftables.SetDatatype constant. Returns ok=false on an unrecognized name.
// Recognizes `verdict` too (only valid as a map's DataType).
func KeyTypeFromString(name string) (nftables.SetDatatype, bool) {
	switch name {
	case "ipv4_addr":
		return nftables.TypeIPAddr, true
	case "ipv6_addr":
		return nftables.TypeIP6Addr, true
	case "ether_addr":
		return nftables.TypeEtherAddr, true
	case "inet_service":
		return nftables.TypeInetService, true
	case "inet_proto":
		return nftables.TypeInetProto, true
	case "mark":
		return nftables.TypeMark, true
	case "integer":
		return nftables.TypeInteger, true
	case "verdict":
		return nftables.TypeVerdict, true
	}
	return nftables.SetDatatype{}, false
}

// SupportedSetKeyTypes lists the key-type labels the create-set dialog
// offers. Restricted to the datatypes ParseSetElementKey can roundtrip.
func SupportedSetKeyTypes() []string {
	return []string{
		"ipv4_addr",
		"ipv6_addr",
		"ether_addr",
		"inet_service",
		"inet_proto",
		"mark",
		"integer",
	}
}

// SupportedMapDataTypes is the key-type list plus `verdict` — the latter
// is map-only (vmap pattern: `port → jump <chain>`).
func SupportedMapDataTypes() []string {
	return append(SupportedSetKeyTypes(), "verdict")
}

// ParseVerdict parses a CLI-form verdict string into an *expr.Verdict.
// Accepts the form `accept|drop|return|continue|queue|jump <chain>|
// goto <chain>`. Chain names are passed through verbatim — the kernel
// will reject unknown ones with EINVAL.
func ParseVerdict(input string) (*expr.Verdict, error) {
	fields := strings.Fields(strings.TrimSpace(input))
	if len(fields) == 0 {
		return nil, fmt.Errorf("empty verdict")
	}
	switch fields[0] {
	case "accept":
		return &expr.Verdict{Kind: expr.VerdictAccept}, nil
	case "drop":
		return &expr.Verdict{Kind: expr.VerdictDrop}, nil
	case "return":
		return &expr.Verdict{Kind: expr.VerdictReturn}, nil
	case "continue":
		return &expr.Verdict{Kind: expr.VerdictContinue}, nil
	case "queue":
		return &expr.Verdict{Kind: expr.VerdictQueue}, nil
	case "jump", "goto":
		if len(fields) < 2 {
			return nil, fmt.Errorf("%s requires a chain name", fields[0])
		}
		kind := expr.VerdictJump
		if fields[0] == "goto" {
			kind = expr.VerdictGoto
		}
		return &expr.Verdict{Kind: kind, Chain: fields[1]}, nil
	}
	return nil, fmt.Errorf("unknown verdict %q (accept/drop/return/continue/queue/jump <c>/goto <c>)", fields[0])
}

// FormatVerdict renders an *expr.Verdict in the form nft uses
// (`accept`, `jump foo`, etc.).
func FormatVerdict(v *expr.Verdict) string {
	if v == nil {
		return "?"
	}
	switch v.Kind {
	case expr.VerdictAccept:
		return "accept"
	case expr.VerdictDrop:
		return "drop"
	case expr.VerdictReturn:
		return "return"
	case expr.VerdictContinue:
		return "continue"
	case expr.VerdictQueue:
		return "queue"
	case expr.VerdictJump:
		return "jump " + v.Chain
	case expr.VerdictGoto:
		return "goto " + v.Chain
	}
	return fmt.Sprintf("verdict(%d)", v.Kind)
}

// CreateSetSpec carries the form values for CreateSet. Splitting it from
// CreateSet's signature keeps callers tidy as the option set grows
// (map flag and data type were added for v0.4 map support).
//
// DataTypeBytes overrides the default width of the `integer` datatype
// (1/2/4/8). Ignored for other types where the width is fixed.
type CreateSetSpec struct {
	Name          string
	KeyType       nftables.SetDatatype
	IsMap         bool
	DataType      nftables.SetDatatype
	DataTypeBytes uint32
	Flags         []string // "constant", "interval", "timeout"
}

// CreateSet adds a new named set (or map) to the kernel.
//
// For maps (spec.IsMap=true) the DataType is mandatory; it sets the value
// datatype. Anonymous / dynamic flags are not exposed in the UI form yet.
func CreateSet(table *nftables.Table, spec CreateSetSpec) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %v", err)
	}
	s := &nftables.Set{
		Table:   table,
		Name:    spec.Name,
		KeyType: spec.KeyType,
	}
	if spec.IsMap {
		s.IsMap = true
		s.DataType = spec.DataType
		// `integer` data type carries the requested width on the wire;
		// other types have a fixed Bytes value we leave intact.
		if spec.DataType.Name == nftables.TypeInteger.Name && spec.DataTypeBytes > 0 {
			s.DataType.Bytes = spec.DataTypeBytes
		}
	}
	for _, f := range spec.Flags {
		switch f {
		case "constant":
			s.Constant = true
		case "interval":
			s.Interval = true
		case "timeout":
			s.HasTimeout = true
		case "dynamic":
			// `dynamic` is required for sets fed by Dynset rules
			// (`add @setname { ... }`). The kernel surfaces it through
			// nftables.Set.Dynamic.
			s.Dynamic = true
		}
	}
	if err := conn.AddSet(s, nil); err != nil {
		return fmt.Errorf("failed to stage set: %v", err)
	}
	flushErr := conn.Flush()
	auditEvent("create-set", chainTarget(table, spec.Name), flushErr)
	if flushErr != nil {
		return fmt.Errorf("failed to create set: %v", flushErr)
	}
	return nil
}

// DeleteSet removes the named set from the kernel. The kernel refuses to
// delete a set that is referenced by rules — the error is surfaced verbatim.
func DeleteSet(set *nftables.Set) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %v", err)
	}
	conn.DelSet(set)
	flushErr := conn.Flush()
	auditEvent("delete-set", chainTarget(set.Table, set.Name), flushErr)
	if flushErr != nil {
		return fmt.Errorf("failed to delete set: %v", flushErr)
	}
	return nil
}

// ParseSetElementVal parses a value string into raw bytes using the set's
// DataType. Map values are never intervals, so the keyEnd return is
// discarded; callers receive just the value bytes.
func ParseSetElementVal(set *nftables.Set, input string) ([]byte, error) {
	tmp := *set
	tmp.KeyType = set.DataType
	tmp.Interval = false
	b, _, err := ParseSetElementKey(&tmp, input)
	return b, err
}

// AddSetElement adds a single element to the named set.
//
// For map-type sets pass either `val` (data-type bytes) OR `verdict`
// (vmap target). For plain sets pass nil for both. For interval sets
// `keyEnd` is the inclusive end of the range; nil for single-host.
//
// Intervals use the classic two-element wire encoding (start with
// IntervalEnd=false, exclusive end with IntervalEnd=true). The modern
// `KeyEnd` attribute path needs auto-merge / concat support that older
// kernels reject with EINVAL, so we stay on the broadly-compatible form.
func AddSetElement(set *nftables.Set, key, keyEnd, val []byte, verdict *expr.Verdict) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %v", err)
	}
	elements := buildSetElements(set, key, keyEnd, val, verdict)
	if err := conn.SetAddElements(set, elements); err != nil {
		return fmt.Errorf("failed to stage element: %v", err)
	}
	flushErr := conn.Flush()
	auditEvent("add-set-element", chainTarget(set.Table, set.Name), flushErr)
	if flushErr != nil {
		return fmt.Errorf("failed to add set element: %v", flushErr)
	}
	return nil
}

// buildSetElements assembles the SetElement slice an AddSetElement call
// should push to the kernel. Pure data shaping, no netlink — unit tests
// rely on this to cover the interval / map / verdict branches without
// needing CAP_NET_ADMIN.
//
// Cases:
//
//	range            (keyEnd != nil)   → 2 elements: {Key} + {Key=end+1, IntervalEnd}
//	single, interval (set.Interval)    → 2 elements: {Key} + {Key=key+1, IntervalEnd}
//	verdict map      (verdict != nil)  → 1 element : {Key, VerdictData}
//	plain map        (val     != nil)  → 1 element : {Key, Val}
//	plain set        (otherwise)       → 1 element : {Key}
func buildSetElements(set *nftables.Set, key, keyEnd, val []byte, verdict *expr.Verdict) []nftables.SetElement {
	switch {
	case keyEnd != nil:
		end := incrementBytes(keyEnd) // exclusive end = inclusive end + 1
		return []nftables.SetElement{
			{Key: key},
			{Key: end, IntervalEnd: true},
		}
	case set.Interval:
		end := incrementBytes(key)
		return []nftables.SetElement{
			{Key: key},
			{Key: end, IntervalEnd: true},
		}
	}
	el := nftables.SetElement{Key: key}
	switch {
	case verdict != nil:
		el.VerdictData = verdict
	case val != nil:
		el.Val = val
	}
	return []nftables.SetElement{el}
}

// incrementBytes returns a copy of b incremented by one as a BigEndian
// integer. Used to convert an inclusive interval end into the exclusive
// `IntervalEnd=true` form the kernel expects. Wraps to all-zeros on
// overflow — acceptable for our cidr / port bounds.
func incrementBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

// DeleteSetElement removes a single element identified by its raw key bytes.
//
// For interval sets `keyEnd` is the inclusive end of the range (the same
// value `GetSetElements` populates on returned elements). The kernel
// stored the range as start + `IntervalEnd=true` close marker at
// `end+1`; both must be removed together, otherwise the close marker
// stays behind and shows up as an orphan in the next read.
func DeleteSetElement(set *nftables.Set, key, keyEnd []byte) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %v", err)
	}
	elements := []nftables.SetElement{{Key: key}}
	if set.Interval {
		// Single-host elements on an interval set are also stored as
		// 2 physical elements (Add uses key+1 as the close marker), so
		// the delete must mirror that even when keyEnd is unset.
		end := keyEnd
		if end == nil {
			end = key
		}
		elements = append(elements, nftables.SetElement{
			Key:         incrementBytes(end),
			IntervalEnd: true,
		})
	}
	if err := conn.SetDeleteElements(set, elements); err != nil {
		return fmt.Errorf("failed to stage delete: %v", err)
	}
	flushErr := conn.Flush()
	auditEvent("delete-set-element", chainTarget(set.Table, set.Name), flushErr)
	if flushErr != nil {
		return fmt.Errorf("failed to delete set element: %v", flushErr)
	}
	return nil
}
