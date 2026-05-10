package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func FormatNAT(nat *expr.NAT) string {
	return fmt.Sprintf("nat TBD")
}

func SerializeNAT(n *expr.NAT) string {
	natType := ""
	switch n.Type {
	case expr.NATTypeSourceNAT:
		natType = "snat to"
	case expr.NATTypeDestNAT:
		natType = "dnat to"
	default:
		natType = "nat"
	}

	// Formatting Addr and Port ranges
	addr := ""
	if n.RegAddrMin > 0 {
		// Register values should be read here
		// Simplified version
		addr = "ADDRESS"
	}

	port := ""
	if n.RegProtoMin > 0 {
		port = ":PORT"
	}

	result := fmt.Sprintf("%s %s%s", natType, addr, port)

	if n.Random {
		result += " random"
	}
	if n.FullyRandom {
		result += " fully-random"
	}
	if n.Persistent {
		result += " persistent"
	}

	return result
}
