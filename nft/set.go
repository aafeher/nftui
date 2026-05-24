package nft

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/google/nftables"
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

func GetSetElements(set *nftables.Set) []nftables.SetElement {
	conn := &nftables.Conn{}
	elements, err := conn.GetSetElements(set)
	if err != nil {
		log.Fatal(err)
	}

	return elements
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
		if hasRange {
			start, end, err := dashRangeToBytes(input, parseUint32BE)
			if err != nil {
				return nil, nil, err
			}
			return start, end, nil
		}
		b, err := parseUint32BE(input)
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

// parseUint32BE parses a decimal / 0x-hex uint32 into 4 BigEndian bytes.
func parseUint32BE(s string) ([]byte, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 0, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid integer: %q", s)
	}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(n))
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

// CreateSetSpec carries the form values for CreateSet. Splitting it from
// CreateSet's signature keeps callers tidy as the option set grows
// (map flag and data type were added for v0.4 map support).
type CreateSetSpec struct {
	Name     string
	KeyType  nftables.SetDatatype
	IsMap    bool
	DataType nftables.SetDatatype
	Flags    []string // "constant", "interval", "timeout"
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
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to create set: %v", err)
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
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to delete set: %v", err)
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
// For map-type sets `val` carries the value bytes; for plain sets pass nil.
// For interval sets `keyEnd` is the inclusive end of the range; nil for
// single-host elements.
//
// Intervals use the classic two-element wire encoding (start with
// IntervalEnd=false, exclusive end with IntervalEnd=true). The modern
// `KeyEnd` attribute path needs auto-merge / concat support that older
// kernels reject with EINVAL, so we stay on the broadly-compatible form.
func AddSetElement(set *nftables.Set, key, keyEnd, val []byte) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %v", err)
	}
	var elements []nftables.SetElement
	switch {
	case keyEnd != nil:
		// Explicit range: start + exclusive end.
		end := incrementBytes(keyEnd) // exclusive end = inclusive end + 1
		elements = []nftables.SetElement{
			{Key: key},
			{Key: end, IntervalEnd: true},
		}
	case set.Interval:
		// Single host on an interval set: still needs a closing marker
		// at start+1, otherwise the kernel leaves the range open and
		// auto-merges into the next neighbouring entry.
		end := incrementBytes(key)
		elements = []nftables.SetElement{
			{Key: key},
			{Key: end, IntervalEnd: true},
		}
	default:
		el := nftables.SetElement{Key: key}
		if val != nil {
			el.Val = val
		}
		elements = []nftables.SetElement{el}
	}
	if err := conn.SetAddElements(set, elements); err != nil {
		return fmt.Errorf("failed to stage element: %v", err)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to add set element: %v", err)
	}
	return nil
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
func DeleteSetElement(set *nftables.Set, key []byte) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %v", err)
	}
	if err := conn.SetDeleteElements(set, []nftables.SetElement{{Key: key}}); err != nil {
		return fmt.Errorf("failed to stage delete: %v", err)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to delete set element: %v", err)
	}
	return nil
}
