//go:build linux

package nft

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func LoadExamples() error {
	cmd := exec.Command("nft", "-f", "examples/example-nftables-01.conf")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nftables konfiguráció betöltése sikertelen: %v\nKimenet: %s", err, string(output))
	}

	fmt.Printf("Nftables konfiguráció sikeresen betöltve: example-nftables-01.conf\n")
	return nil
}

func FlushRules() error {
	cmd := exec.Command("nft", "flush", "ruleset")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nftables konfiguráció ürítése sikertelen: %v\nKimenet: %s", err, string(output))
	}

	fmt.Printf("Nftables konfiguráció sikeresen ürítve\n")
	return nil
}

func ListTables() ([]*nftables.Table, error) {
	conn := &nftables.Conn{}
	tables, err := conn.ListTables()
	if err != nil {
		return nil, err
	}
	return tables, nil
}

func ListChains() ([]*nftables.Chain, error) {
	conn := &nftables.Conn{}
	chains, err := conn.ListChains()
	if err != nil {
		return nil, err
	}
	return chains, nil
}

func ListChainsOfTable(table *nftables.Table) ([]*nftables.Chain, error) {
	allChains, err := ListChains()
	if err != nil {
		return nil, err
	}

	chains := make([]*nftables.Chain, 0)
	for _, chain := range allChains {
		if chain.Table.Name == table.Name && chain.Table.Family == table.Family {
			chains = append(chains, chain)
		}
	}

	return chains, nil
}

func ListRulesOfTable(table *nftables.Table) ([]*nftables.Rule, error) {
	chains, err := ListChainsOfTable(table)
	if err != nil {
		return nil, err
	}

	rulesOfTable := make([]*nftables.Rule, 0)
	for _, chain := range chains {
		rules, err := ListRulesOfChain(table, chain)
		if err != nil {
			continue
		}
		rulesOfTable = append(rulesOfTable, rules...)
	}

	return rulesOfTable, nil
}

func ListRulesOfChain(table *nftables.Table, chain *nftables.Chain) ([]*nftables.Rule, error) {
	conn := &nftables.Conn{}
	rules, err := conn.GetRules(table, chain)
	if err != nil {
		return nil, err
	}
	//for _, rule := range rules {
	//	fmt.Printf("rule: %+v\n", rule)
	//	for _, expr := range rule.Exprs {
	//		fmt.Printf("expr: %+v\n", expr)
	//	}
	//	fmt.Printf("userData: %+v\n", string(rule.UserData))
	//}
	return rules, nil
}

func getAllRules() ([]*nftables.Rule, error) {
	tables, err := ListTables()
	if err != nil {
		return nil, err
	}

	allRules := make([]*nftables.Rule, 0)
	for _, table := range tables {
		rules, err := ListRulesOfTable(table)
		if err != nil {
			continue
		}
		allRules = append(allRules, rules...)
	}

	return allRules, nil
}

func GetAllRulesWithAccept() ([]*nftables.Rule, error) {
	allRules, err := getAllRules()
	if err != nil {
		return nil, err
	}
	acceptRules := make([]*nftables.Rule, 0)
	for _, rule := range allRules {
		for _, e := range rule.Exprs {
			if verdict, ok := e.(*expr.Verdict); ok {
				if verdict.Kind == expr.VerdictAccept {
					acceptRules = append(acceptRules, rule)
					break
				}
			}
		}
	}
	return acceptRules, nil
}

func GetAllRulesWithDrop() ([]*nftables.Rule, error) {
	allRules, err := getAllRules()
	if err != nil {
		return nil, err
	}
	acceptRules := make([]*nftables.Rule, 0)
	for _, rule := range allRules {
		for _, e := range rule.Exprs {
			if verdict, ok := e.(*expr.Verdict); ok {
				if verdict.Kind == expr.VerdictDrop {
					acceptRules = append(acceptRules, rule)
					break
				}
			}
		}
	}
	return acceptRules, nil
}

func CountRulesByType(rules []*nftables.Rule) (accept int, drop int, other int) {
	for _, rule := range rules {
		hasVerdict := false
		for _, e := range rule.Exprs {
			if verdict, ok := e.(*expr.Verdict); ok {
				hasVerdict = true
				if verdict.Kind == expr.VerdictAccept {
					accept++
				} else if verdict.Kind == expr.VerdictDrop {
					drop++
				} else {
					other++
				}
				break
			}
		}
		if !hasVerdict {
			other++
		}
	}
	return
}

// CreateTable creates a new empty table in the kernel with the given family and name.
func CreateTable(family nftables.TableFamily, name string) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %v", err)
	}
	conn.AddTable(&nftables.Table{Name: name, Family: family})
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to create table: %v", err)
	}
	return nil
}

// nftCLIFamily maps a TableFamily to the family name accepted by the nft(8)
// CLI tool, which differs from TableFamilyToString for ipv4/ipv6 ("ip"/"ip6"
// rather than "ipv4"/"ipv6").
func nftCLIFamily(f nftables.TableFamily) string {
	switch f {
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyARP:
		return "arp"
	case nftables.TableFamilyBridge:
		return "bridge"
	case nftables.TableFamilyNetdev:
		return "netdev"
	default:
		return TableFamilyToString(f)
	}
}

// RenameTable renames a table by shelling out to nft(8). It dumps the current
// table as nft script, rewrites the header to the new name, appends a delete of
// the old table, and applies the whole thing atomically with `nft -f -`.
//
// We use the nft CLI rather than constructing the rename via netlink because
// faithfully recreating every set property the kernel tracks (per-element
// stateful expressions, userdata flags, descriptor sizes for constant sets,
// concatenated key types, etc.) requires fields that google/nftables doesn't
// fully decode in NFT_MSG_GETSET responses. Round-tripping that incomplete
// state back into a fresh AddSet() reliably trips kernel EINVAL on the element
// stage. The nft CLI already gets all of this right.
func RenameTable(table *nftables.Table, newName string) error {
	if newName == table.Name {
		return nil
	}

	family := nftCLIFamily(table.Family)

	dump, err := exec.Command("nft", "list", "table", family, table.Name).Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("nft list table: %v: %s", err, exitErr.Stderr)
		}
		return fmt.Errorf("nft list table: %v", err)
	}

	oldHeader := fmt.Sprintf("table %s %s {", family, table.Name)
	newHeader := fmt.Sprintf("table %s %s {", family, newName)
	rewritten := strings.Replace(string(dump), oldHeader, newHeader, 1)
	if rewritten == string(dump) {
		return fmt.Errorf("could not rewrite table header (looked for %q)", oldHeader)
	}

	script := rewritten + fmt.Sprintf("\ndelete table %s %s\n", family, table.Name)

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft -f failed: %v\n%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// DeleteRule removes the given rule from the kernel.
func DeleteRule(rule *nftables.Rule) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %v", err)
	}
	conn.DelRule(rule)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to delete rule: %v", err)
	}
	return nil
}

// MoveRuleUp moves rules[idx] one position earlier in the chain.
// The operation is a delete + re-insert before the preceding rule.
func MoveRuleUp(rules []*nftables.Rule, idx int) error {
	if idx <= 0 || idx >= len(rules) {
		return nil
	}
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %v", err)
	}
	r := rules[idx]
	conn.DelRule(r)
	newRule := &nftables.Rule{
		Table:    r.Table,
		Chain:    r.Chain,
		Position: rules[idx-1].Handle,
		Exprs:    r.Exprs,
		UserData: r.UserData,
	}
	conn.InsertRule(newRule)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to move rule up: %v", err)
	}
	return nil
}

// MoveRuleDown moves rules[idx] one position later in the chain.
// The operation is a delete + re-insert after the following rule.
func MoveRuleDown(rules []*nftables.Rule, idx int) error {
	if idx < 0 || idx >= len(rules)-1 {
		return nil
	}
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %v", err)
	}
	r := rules[idx]
	conn.DelRule(r)
	newRule := &nftables.Rule{
		Table:    r.Table,
		Chain:    r.Chain,
		Position: rules[idx+1].Handle,
		Exprs:    r.Exprs,
		UserData: r.UserData,
	}
	conn.AddRule(newRule)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to move rule down: %v", err)
	}
	return nil
}

// AddNewRuleToChain appends a minimal accept rule at the end of the chain
// and returns the freshly created rule (with its kernel-assigned Handle).
func AddNewRuleToChain(table *nftables.Table, chain *nftables.Chain) (*nftables.Rule, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to nftables: %v", err)
	}
	newRule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	}
	conn.AddRule(newRule)
	if err := conn.Flush(); err != nil {
		return nil, fmt.Errorf("failed to add rule: %v", err)
	}
	fresh, err := ListRulesOfChain(table, chain)
	if err != nil || len(fresh) == 0 {
		return newRule, err
	}
	return fresh[len(fresh)-1], nil
}

// InsertNewRuleBefore inserts a minimal accept rule before rules[idx]
// and returns the freshly created rule (with its kernel-assigned Handle).
func InsertNewRuleBefore(table *nftables.Table, chain *nftables.Chain, rules []*nftables.Rule, idx int) (*nftables.Rule, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to nftables: %v", err)
	}
	newRule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	}
	if idx > 0 {
		newRule.Position = rules[idx-1].Handle
		conn.AddRule(newRule)
	} else {
		conn.InsertRule(newRule)
	}
	if err := conn.Flush(); err != nil {
		return nil, fmt.Errorf("failed to insert rule: %v", err)
	}
	fresh, err := ListRulesOfChain(table, chain)
	if err != nil {
		return newRule, err
	}
	if idx < len(fresh) {
		return fresh[idx], nil
	}
	if len(fresh) > 0 {
		return fresh[len(fresh)-1], nil
	}
	return newRule, nil
}

func logLevelToString(logLevel expr.LogLevel) string {
	switch logLevel {
	case expr.LogLevelEmerg:
		return "emerg"
	case expr.LogLevelAlert:
		return "alert"
	case expr.LogLevelCrit:
		return "crit"
	case expr.LogLevelErr:
		return "err"
	case expr.LogLevelWarning:
		return "warning"
	case expr.LogLevelNotice:
		return "notice"
	case expr.LogLevelInfo:
		return "info"
	case expr.LogLevelDebug:
		return "debug"
	case expr.LogLevelAudit:
		return "audit"
	default:
		return "unknown"

	}
}

func payloadBaseToString(payloadBase expr.PayloadBase) string {
	switch payloadBase {
	case unix.NFT_PAYLOAD_LL_HEADER:
		return "ll header"
	case unix.NFT_PAYLOAD_NETWORK_HEADER:
		return "network header"
	case unix.NFT_PAYLOAD_TRANSPORT_HEADER:
		return "transport header"
	default:
		return "unknown"
	}
}

func verdictKindToString(verdictKind expr.VerdictKind) string {
	switch verdictKind {
	case expr.VerdictReturn:
		return "return"
	case expr.VerdictGoto:
		return "goto"
	case expr.VerdictJump:
		return "jump"
	case expr.VerdictBreak:
		return "break"
	case expr.VerdictContinue:
		return "continue"
	case expr.VerdictDrop:
		return "drop"
	case expr.VerdictAccept:
		return "accept"
	case expr.VerdictStolen:
		return "stolen"
	case expr.VerdictQueue:
		return "queue"
	case expr.VerdictRepeat:
		return "repeat"
	case expr.VerdictStop:
		return "stop"
	default:
		return "unknown"
	}
}

func KeyTypeToString(kt nftables.SetDatatype) string {
	switch kt {
	case nftables.TypeIPAddr:
		return "ipv4_addr"
	case nftables.TypeIP6Addr:
		return "ipv6_addr"
	case nftables.TypeInetProto:
		return "inet_proto"
	case nftables.TypeInetService:
		return "inet_service"
	case nftables.TypeEtherAddr:
		return "ether_addr"
	default:
		return fmt.Sprintf("type_%s", kt.Name)
	}
}

func Icmpv6TypeToString(t uint8) string {
	switch t {
	case 1:
		return "destination-unreachable"
	case 2:
		return "packet-too-big"
	case 3:
		return "time-exceeded"
	case 4:
		return "parameter-problem"
	case 128:
		return "echo-request"
	case 129:
		return "echo-reply"
	case 130:
		return "mld-listener-query"
	case 131:
		return "mld-listener-report"
	case 132:
		return "mld-listener-done"
	case 133:
		return "nd-router-solicit"
	case 134:
		return "nd-router-advert"
	case 135:
		return "nd-neighbor-solicit"
	case 136:
		return "nd-neighbor-advert"
	case 137:
		return "nd-redirect"
	case 138:
		return "router-renumbering"
	case 141:
		return "ind-neighbor-solicit"
	case 142:
		return "ind-neighbor-advert"
	case 143:
		return "mld2-listener-report"
	default:
		return fmt.Sprintf("icmpv6_type_%d", t)
	}
}
