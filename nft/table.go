package nft

import "github.com/google/nftables"

func TableFamilyToString(f nftables.TableFamily) string {
	switch f {
	case nftables.TableFamilyUnspecified:
		return "unspecified"
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyIPv4:
		return "ipv4"
	case nftables.TableFamilyIPv6:
		return "ipv6"
	case nftables.TableFamilyARP:
		return "arp"
	case nftables.TableFamilyNetdev:
		return "netdev"
	case nftables.TableFamilyBridge:
		return "bridge"
	default:
		return "unknown"
	}
}
