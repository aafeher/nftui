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
// matching the set's KeyType. Supports the common datatypes:
//
//	ipv4_addr   → 4 bytes (dotted-quad or single-host CIDR)
//	ipv6_addr   → 16 bytes
//	ether_addr  → 6 bytes (colon-separated MAC)
//	inet_service → 2 bytes (TCP/UDP port)
//	inet_proto  → 1 byte
//	mark/integer → 4 bytes (uint32, decimal or 0x-hex)
//
// Returns an error if the input does not match the expected type.
func ParseSetElementKey(set *nftables.Set, input string) ([]byte, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("empty value")
	}

	switch set.KeyType.Name {
	case nftables.TypeIPAddr.Name:
		ip := net.ParseIP(input)
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv4 address: %q", input)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("not an IPv4 address: %q", input)
		}
		return []byte(ip4), nil

	case nftables.TypeIP6Addr.Name:
		ip := net.ParseIP(input)
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv6 address: %q", input)
		}
		ip16 := ip.To16()
		if ip16 == nil {
			return nil, fmt.Errorf("not an IPv6 address: %q", input)
		}
		return []byte(ip16), nil

	case nftables.TypeEtherAddr.Name:
		mac, err := net.ParseMAC(input)
		if err != nil {
			return nil, fmt.Errorf("invalid MAC address: %q", input)
		}
		if len(mac) != 6 {
			return nil, fmt.Errorf("ether_addr requires a 6-byte MAC, got %d bytes", len(mac))
		}
		return []byte(mac), nil

	case nftables.TypeInetService.Name:
		n, err := strconv.ParseUint(input, 0, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %q", input)
		}
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(n))
		return b, nil

	case nftables.TypeInetProto.Name:
		n, err := strconv.ParseUint(input, 0, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid protocol number: %q", input)
		}
		return []byte{byte(n)}, nil

	case nftables.TypeMark.Name, nftables.TypeInteger.Name:
		n, err := strconv.ParseUint(input, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid integer: %q", input)
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(n))
		return b, nil
	}

	return nil, fmt.Errorf("unsupported key type for add/remove: %s", set.KeyType.Name)
}

// AddSetElement adds a single element to the named set. For map-type sets the
// value argument is required; for plain sets it must be nil.
func AddSetElement(set *nftables.Set, key, val []byte) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %v", err)
	}
	el := nftables.SetElement{Key: key}
	if val != nil {
		el.Val = val
	}
	if err := conn.SetAddElements(set, []nftables.SetElement{el}); err != nil {
		return fmt.Errorf("failed to stage element: %v", err)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to add set element: %v", err)
	}
	return nil
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
