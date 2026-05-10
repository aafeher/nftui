// nft_ruleset_serializer.go
// Go package to serialize an in-kernel nftables state (from github.com/google/nftables)
// back to a textual nft(8) configuration (ruleset) that can be applied with `nft -f`.
//
// This file aims to be a thorough, practical starting point: it walks tables, chains,
// sets and rules returned by a *nftables.Conn and turns them into a human-readable
// nft ruleset. It attempts to cover the most common expression types and attributes.
// It is NOT a perfect 1:1 roundtrip for every possible nft feature (which are many),
// but it is organized so you can extend support for missing expr types quickly.

package nftserializer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"nftui/nft"
	nftexpr "nftui/nft/expr"
	"sort"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// Serializer holds configuration for serializing a ruleset
type Serializer struct {
	Conn *nftables.Conn
	// FamilyOverride: if non-empty, force a certain family name in output (e.g. "inet").
	FamilyOverride string
}

// SerializeRuleset reads all tables/chains/sets/rules from the Conn and returns
// the nft ruleset text that can be passed to `nft -f` or written to a file.
func (s *Serializer) SerializeRuleset() (string, error) {
	buf := &bytes.Buffer{}
	// header
	buf.WriteString("#!/usr/sbin/nft -f\n\n")

	tables, err := s.Conn.ListTables()
	if err != nil {
		return "", err
	}

	// Sort tables by family+name to produce deterministic output
	sort.Slice(tables, func(i, j int) bool {
		iKey := fmt.Sprintf("%s/%s", nft.TableFamilyToString(tables[i].Family), tables[i].Name)
		jKey := fmt.Sprintf("%s/%s", nft.TableFamilyToString(tables[j].Family), tables[j].Name)
		return iKey < jKey
	})

	// Preload sets for fast lookup
	sets := []*nftables.Set{}
	rules := []*nftables.Rule{} // s.Conn.GetRules()

	// Group rules by table and chain for easy serialization
	rulesByTable := map[string][]*nftables.Rule{}
	for _, r := range rules {
		key := fmt.Sprintf("%s/%s", r.Table.Name, r.Chain.Name)
		rulesByTable[key] = append(rulesByTable[key], r)
	}

	for _, t := range tables {
		family := nft.TableFamilyToString(t.Family)
		if s.FamilyOverride != "" {
			family = s.FamilyOverride
		}
		buf.WriteString(fmt.Sprintf("table %s %s {\n", family, t.Name))

		// Serialize sets belonging to this table
		for _, st := range sets {
			if st.Table != nil && st.Table.Name == t.Name {
				buf.WriteString(indent(1) + serializeSet(st) + "\n")
			}
		}

		// Serialize chains
		chains, _ := s.Conn.ListChains()
		for _, ch := range chains {
			if ch.Table.Name != t.Name {
				continue
			}
			buf.WriteString(indent(1) + serializeChain(ch) + "\n")
			// serialize rules for this chain
			key := fmt.Sprintf("%s/%s", t.Name, ch.Name)
			if rs, ok := rulesByTable[key]; ok {
				sort.Slice(rs, func(i, j int) bool { return rs[i].Position < rs[j].Position })
				for _, r := range rs {
					buf.WriteString(indent(2) + SerializeRule(r) + "\n")
				}
			}
		}

		buf.WriteString("}\n\n")
	}

	return buf.String(), nil
}

// Helper: indent n tabs (4 spaces each)
func indent(level int) string {
	return strings.Repeat("    ", level)
}

// serializeSet creates a textual representation of an nft set declaration
func serializeSet(s *nftables.Set) string {
	b := &bytes.Buffer{}
	// header: set name
	b.WriteString("set ")
	b.WriteString(s.Name + " ")
	// type and flags
	b.WriteString(fmt.Sprintf("{ type %s } ", nft.KeyTypeToString(s.KeyType)))
	b.WriteString(fmt.Sprintf("timeout %s ", s.Timeout.String()))
	return b.String()
}

// serializeChain turns a nftables.Chain into a chain declaration
func serializeChain(ch *nftables.Chain) string {
	parts := []string{"chain", ch.Name}
	if ch.Type != "" {
		parts = append(parts, fmt.Sprintf("{ type %s", ch.Type))
	} else {
		parts = append(parts, "{")
	}
	if ch.Hooknum != nil {
		parts = append(parts, fmt.Sprintf("hook %s", nft.ChainHookNumToString(*ch.Hooknum)))
	}
	if ch.Priority != nil {
		parts = append(parts, fmt.Sprintf("priority %d", *ch.Priority))
	}
	if ch.Policy != nil {
		// policy is nftables.Accept/Drop/Continue mapping
		switch *ch.Policy {
		case nftables.ChainPolicyAccept:
			parts = append(parts, "policy accept")
		case nftables.ChainPolicyDrop:
			parts = append(parts, "policy drop")
		}
	}
	// close
	parts = append(parts, "}")
	return strings.Join(parts, " ")
}

// SerializeRule converts a rule to a one-line nft rule snippet (without leading indent)
func SerializeRule(rule *nftables.Rule) string {
	var parts []string
	var pendingData any // data loaded from register
	var l4proto string

	sets, err := nft.GetSets(rule.Table)
	if err != nil {
		return fmt.Sprintf("Error getting sets: %s", err)
	}

	i := 0
	for i < len(rule.Exprs) {
		e := rule.Exprs[i]

		switch v := e.(type) {
		case *expr.Ct:
			str, skip := nftexpr.SerializeCt(v, rule.Exprs, i, sets)
			parts = append(parts, str)
			i += skip

		case *expr.Range:
			str := nftexpr.SerializeRange(v, pendingData)
			parts = append(parts, str)
			pendingData = nil
			i++
		case *expr.Meta:
			str, skip, l4p := nftexpr.SerializeMeta(v, rule.Exprs, i)
			l4proto = l4p
			parts = append(parts, str)
			i += skip
		case *expr.Cmp:
			// standalone cmp
			str := nftexpr.SerializeCmp(v, pendingData)
			if str != "" {
				parts = append(parts, str)
			}
			pendingData = nil
			i++

		case *expr.Counter:
			parts = append(parts, "counter")
			i++

		case *expr.Objref:
			str := nftexpr.SerializeObjref(v)
			parts = append(parts, str)
			i++
		case *expr.Payload:
			str, skip := nftexpr.SerializePayload(v, rule.Exprs, i)
			parts = append(parts, str)
			i += skip
		case *expr.Lookup:
			//str := nftexpr.SerializeLookup(v)
			set, err := nft.GetSetByName(rule.Table, v.SetName)
			if err != nil {
				log.Printf("failed to get set ID=%d: %v", v.SetID, err)
				continue
			}
			elements := nft.GetSetElements(set)
			if err != nil {
				log.Printf("failed to get set elements: %v", err)
				continue
			}
			lookupParts := []string{}
			for _, el := range elements {
				if l4proto == "icmpv6" {
					lookupParts = append(lookupParts, fmt.Sprintf("%s", nft.Icmpv6TypeToString(el.Key[0])))
					continue
				}
				if len(el.Key) == 2 {
					port := binary.BigEndian.Uint16(el.Key)
					lookupParts = append(lookupParts, fmt.Sprintf("%d", port))
				}
			}
			lookupStr := "{" + strings.Join(lookupParts, ", ") + "}"

			parts = append(parts, lookupStr)
			i++
		case *expr.Immediate:
			str := nftexpr.SerializeImmediate(v)
			if str != "" {
				parts = append(parts, str)
			}
			i++
		case *expr.Bitwise:
			str := nftexpr.SerializeBitwise(v)
			parts = append(parts, str)
			i++
		case *expr.Redir:
			str := nftexpr.SerializeRedirect(v)
			parts = append(parts, str)
			i++
		case *expr.NAT:
			str := nftexpr.SerializeNAT(v)
			parts = append(parts, str)
			i++
		case *expr.Limit:
			str := nftexpr.SerializeLimit(v)
			parts = append(parts, str)
			i++
		case *expr.Quota:
			str := nftexpr.SerializeQuota(v)
			parts = append(parts, str)
			i++
		case *expr.Dynset:
			str := nftexpr.SerializeDynset(v)
			parts = append(parts, str)
			i++
		case *expr.Log:
			str := nftexpr.SerializeLog(v)
			parts = append(parts, str)
			i++
		case *expr.Exthdr:
			str, skip := nftexpr.SerializeExthdr(v, rule.Exprs, i)
			parts = append(parts, str)
			i += skip
		case *expr.Match:
			str := nftexpr.SerializeMatch(v)
			parts = append(parts, str)
			i++
		case *expr.Target:
			str := nftexpr.SerializeTarget(v)
			parts = append(parts, str)
			i++
		case *expr.Connlimit:
			str := nftexpr.SerializeConnlimit(v)
			parts = append(parts, str)
			i++
		case *expr.Queue:
			str := nftexpr.SerializeQueue(v)
			parts = append(parts, str)
			i++
		case *expr.FlowOffload:
			str := nftexpr.SerializeFlowOffload(v)
			parts = append(parts, str)
			i++
		case *expr.Reject:
			str := nftexpr.SerializeReject(v)
			parts = append(parts, str)
			i++
		case *expr.Masq:
			str := nftexpr.SerializeMasq(v)
			parts = append(parts, str)
			i++
		case *expr.Hash:
			str := nftexpr.SerializeHash(v)
			parts = append(parts, str)
			i++
		// cthelper?
		case *expr.SynProxy:
			str := nftexpr.SerializeSynProxy(v)
			parts = append(parts, str)
			i++
		// ctexpect?
		case *expr.SecMark:
			str := nftexpr.SerializeSecMark(v)
			parts = append(parts, str)
			i++
		// cttimeout?
		case *expr.Fib:
			str := nftexpr.SerializeFib(v)
			parts = append(parts, str)
			i++
		case *expr.Numgen:
			str := nftexpr.SerializeNumgen(v)
			parts = append(parts, str)
			i++

		// other
		case *expr.Verdict:
			str := nftexpr.SerializeVerdict(v)
			parts = append(parts, str)
			i++
		case *expr.Rt:
			str := nftexpr.SerializeRt(v)
			parts = append(parts, str)
			i++
		case *expr.Dup:
			str := nftexpr.SerializeDup(v)
			parts = append(parts, str)
			i++
		case *expr.Notrack:
			str := nftexpr.SerializeNotrack(v)
			parts = append(parts, str)
			i++
		case *expr.TProxy:
			str := nftexpr.SerializeTproxy(v)
			parts = append(parts, str)
			i++
		case *expr.Socket:
			str := nftexpr.SerializeSocket(v)
			parts = append(parts, str)
			i++
		default:
			parts = append(parts, fmt.Sprintf("/* unknown expr: %T */", e))
			i++
		}
	}

	result := strings.Join(parts, " ")

	if comment := nft.ExtractComment(rule); comment != "" {
		result += fmt.Sprintf(" comment \"%s\"", comment)
	}

	return result
}

// serializeExpr converts expr.Any to textual representation. This covers common expr types.
//func serializeExpr(e expr.Any) string {
//switch ex := e.(type) {
//case *expr.Ct:
//	return nftexpr.FormatCt(ex)
//case *expr.Range:
//	return nftexpr.FormatRange(ex)
//case *expr.Meta:
//	return nftexpr.FormatMeta(ex)
//case *expr.Cmp:
//	return nftexpr.FormatCmp(ex)
//case *expr.Counter:
//	return nftexpr.FormatCounter(ex)
//case *expr.Objref:
//	return nftexpr.FormatObjref(ex)
//case *expr.Payload:
//	return nftexpr.FormatPayload(ex)
//case *expr.Lookup:
//	return nftexpr.FormatLookup(ex)
//case *expr.Immediate:
//	return nftexpr.FormatImmediate(ex)
//case *expr.Bitwise:
//	return nftexpr.FormatBitwise(ex)
//case *expr.Redir:
//	return nftexpr.FormatRedir(ex)
//case *expr.NAT:
//	return nftexpr.FormatNAT(ex)
//case *expr.Limit:
//	return nftexpr.FormatLimit(ex)
//case *expr.Quota:
//	return nftexpr.FormatQuota(ex)
//case *expr.Dynset:
//	return nftexpr.FormatDynset(ex)
//case *expr.Log:
//	return nftexpr.FormatLog(ex)
//case *expr.Exthdr:
//	return nftexpr.FormatExthdr(ex)
//case *expr.Match:
//	return nftexpr.FormatMatch(ex)
//case *expr.Target:
//	return "target TBD"
//case *expr.Connlimit:
//	return "connlimit TBD"
//case *expr.Queue:
//	return "queue TBD"
//case *expr.FlowOffload:
//	return "flow_offload TBD"
//case *expr.Reject:
//	return "reject TBD"
//case *expr.Masq:
//	return "masq TBD"
//case *expr.Hash:
//	return "hash TBD"
//case *expr.CtHelper:
//	return "cthelper TBD"
//case *expr.SynProxy:
//	return "synproxy TBD"
//case *expr.CtExpect:
//	return "ctexpect TBD"
//case *expr.SecMark:
//	return "secmark TBD"
//case *expr.CtTimeout:
//	return "cttimeout TBD"
//case *expr.Fib:
//	return "fib TBD"
//case *expr.Numgen:
//	return "numgen TBD"
//default:
// Unknown expr: attempt best-effort string
//return fmt.Sprintf("# unsupported-expr %T", e)
//}
//}

// NOTE: The google/nftables and expr packages evolve; extend formatters for expr types
// you need. The structure of this file is intentionally modular: add new format*
// helpers for missing expr.Any concrete types and wire them in serializeExpr.

// Usage example (outside this package):
// conn := &nftables.Conn{}
// s := &nftserializer.Serializer{Conn: conn}
// rulesetText, err := s.SerializeRuleset()
// fmt.Println(rulesetText)
