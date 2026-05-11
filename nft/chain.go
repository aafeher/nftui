package nft

import (
	"fmt"
	"strings"

	"github.com/google/nftables"
)

func ChainHookNumToString(h nftables.ChainHook) string {
	switch h {
	case *nftables.ChainHookPrerouting:
		return "prerouting"
	case *nftables.ChainHookInput:
		return "input"
	case *nftables.ChainHookForward:
		return "forward"
	case *nftables.ChainHookOutput:
		return "output"
	case *nftables.ChainHookPostrouting:
		return "postrouting"
	case *nftables.ChainHookIngress:
		return "ingress"
	case *nftables.ChainHookEgress:
		return "egress"
	default:
		return "unknown"
	}
}

func ChainPolicyToString(p nftables.ChainPolicy) string {
	switch p {
	case nftables.ChainPolicyDrop:
		return "drop"
	case nftables.ChainPolicyAccept:
		return "accept"
	default:
		return "unknown"
	}
}

// ChainHookFromString returns the *ChainHook constant matching the given
// lowercase hook name, or nil if the name is empty or unrecognized.
func ChainHookFromString(name string) *nftables.ChainHook {
	switch name {
	case "prerouting":
		return nftables.ChainHookPrerouting
	case "input":
		return nftables.ChainHookInput
	case "forward":
		return nftables.ChainHookForward
	case "output":
		return nftables.ChainHookOutput
	case "postrouting":
		return nftables.ChainHookPostrouting
	case "ingress":
		return nftables.ChainHookIngress
	case "egress":
		return nftables.ChainHookEgress
	default:
		return nil
	}
}

// ChainPolicyFromString returns the ChainPolicy matching the given lowercase
// policy name, plus an ok flag. Empty / unknown names yield (Accept, false).
func ChainPolicyFromString(name string) (nftables.ChainPolicy, bool) {
	switch name {
	case "accept":
		return nftables.ChainPolicyAccept, true
	case "drop":
		return nftables.ChainPolicyDrop, true
	default:
		return nftables.ChainPolicyAccept, false
	}
}

// ChainTypeFromString returns the ChainType matching the given lowercase type
// name, or empty ChainType if the name is empty or unrecognized.
func ChainTypeFromString(name string) nftables.ChainType {
	switch name {
	case "filter":
		return nftables.ChainTypeFilter
	case "nat":
		return nftables.ChainTypeNAT
	case "route":
		return nftables.ChainTypeRoute
	default:
		return ""
	}
}

// extractChainRules pulls the rule lines out of an `nft list chain` dump for
// the named chain. Header lines (`type ... hook ...`, separate `policy ...`,
// chain-level `comment ...`) are dropped; empty lines and the wrapping
// `table {`, `chain {`, `}` braces are skipped.
//
// Each returned string is a single nft rule statement suitable for use after
// `add rule <family> <table> <chain>`.
func extractChainRules(dump, chainName string) ([]string, error) {
	lines := strings.Split(dump, "\n")
	var rules []string
	inChain := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if !inChain {
			if strings.HasPrefix(trimmed, "chain ") && strings.HasSuffix(trimmed, "{") {
				fields := strings.Fields(trimmed)
				if len(fields) >= 2 && fields[1] == chainName {
					inChain = true
				}
			}
			continue
		}

		if trimmed == "}" {
			break
		}
		if trimmed == "" {
			continue
		}
		// Skip chain header lines that we will reconstruct from newSpec.
		if strings.HasPrefix(trimmed, "type ") && strings.Contains(trimmed, " hook ") {
			continue
		}
		if strings.HasPrefix(trimmed, "policy ") {
			continue
		}
		if strings.HasPrefix(trimmed, "comment ") {
			// Chain-level comment — would need separate handling to preserve.
			// Drop it for now; rules with their own `comment "..."` clause
			// are unaffected since those appear inline in the rule line.
			continue
		}

		rules = append(rules, trimmed)
	}

	if !inChain && len(rules) == 0 {
		// We never entered the chain block — dump format wasn't recognised.
		return nil, fmt.Errorf("chain %q not found in nft dump", chainName)
	}
	return rules, nil
}

// ValidChainTypesForFamily returns the chain type strings that base chains can
// use in the given table family. ARP, bridge and netdev only support the
// "filter" type; ip/ip6/inet support all three.
func ValidChainTypesForFamily(family nftables.TableFamily) []string {
	switch family {
	case nftables.TableFamilyIPv4, nftables.TableFamilyIPv6, nftables.TableFamilyINet:
		return []string{"filter", "nat", "route"}
	case nftables.TableFamilyARP, nftables.TableFamilyBridge, nftables.TableFamilyNetdev:
		return []string{"filter"}
	default:
		return []string{"filter"}
	}
}

// ValidChainHooksForTypeFamily returns the hook names valid for the given
// chain type within the given table family. Constraints follow the nftables
// rules:
//   - `nat` only attaches to prerouting/input/output/postrouting.
//   - `route` only attaches to output.
//   - `filter` accepts all family-supported hooks.
//   - netdev family is ingress/egress only; arp is input/output only.
func ValidChainHooksForTypeFamily(chainType string, family nftables.TableFamily) []string {
	familyHooks := func() []string {
		switch family {
		case nftables.TableFamilyIPv4, nftables.TableFamilyIPv6, nftables.TableFamilyBridge:
			return []string{"prerouting", "input", "forward", "output", "postrouting"}
		case nftables.TableFamilyINet:
			return []string{"prerouting", "input", "forward", "output", "postrouting", "ingress"}
		case nftables.TableFamilyARP:
			return []string{"input", "output"}
		case nftables.TableFamilyNetdev:
			return []string{"ingress", "egress"}
		default:
			return []string{"prerouting", "input", "forward", "output", "postrouting"}
		}
	}()

	switch chainType {
	case "nat":
		return intersectStrings(familyHooks, []string{"prerouting", "input", "output", "postrouting"})
	case "route":
		return intersectStrings(familyHooks, []string{"output"})
	case "filter":
		return familyHooks
	default:
		return familyHooks
	}
}

func intersectStrings(a, b []string) []string {
	set := make(map[string]struct{}, len(b))
	for _, s := range b {
		set[s] = struct{}{}
	}
	out := make([]string, 0, len(a))
	for _, s := range a {
		if _, ok := set[s]; ok {
			out = append(out, s)
		}
	}
	return out
}
