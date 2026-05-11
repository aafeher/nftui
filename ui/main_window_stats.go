package ui

import (
	"nftui/nft"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/nftables"
)

type ruleDeletedMsg struct{}
type ruleMovedMsg struct{ newCursor int }
type newRuleCreatedMsg struct{ rule *nftables.Rule }

// chainOpErrMsg carries errors from chain-level operations (delete, move, add).
// Displayed directly in the chain view as a status line, not in the main view.
type chainOpErrMsg struct{ err error }

type tableEditSelectedMsg struct{ table *nftables.Table }
type tableRenamedMsg struct{}
type tableCreatedMsg struct{}
type tableDeletedMsg struct{}
type tableOpErrMsg struct{ err error }
type tableTreeRefreshedMsg struct{ nodes []*tableNode }

type chainEditSelectedMsg struct{ chain *nftables.Chain }
type chainUpdatedMsg struct{}

type chainCreateSelectedMsg struct{ table *nftables.Table }
type chainCreatedMsg struct{}

type statTablesMsg []*nftables.Table
type statChainsMsg []*nftables.Chain
type statRulesAcceptMsg []*nftables.Rule
type statRulesDropMsg []*nftables.Rule

func loadTablesCmd() tea.Cmd {
	return func() tea.Msg {
		tables, err := nft.ListTables()
		if err != nil {
			return errMsg(err)
		}
		items := make([]*nftables.Table, len(tables))
		copy(items, tables)
		return statTablesMsg(items)
	}
}

func loadChainsCmd() tea.Cmd {
	return func() tea.Msg {
		chains, err := nft.ListChains()
		if err != nil {
			return errMsg(err)
		}
		items := make([]*nftables.Chain, len(chains))
		copy(items, chains)
		return statChainsMsg(items)
	}
}

func loadRulesAcceptCmd() tea.Cmd {
	return func() tea.Msg {
		rules, err := nft.GetAllRulesWithAccept()
		if err != nil {
			return errMsg(err)
		}
		items := make([]*nftables.Rule, len(rules))
		copy(items, rules)
		return statRulesAcceptMsg(items)
	}
}

func loadRulesDropCmd() tea.Cmd {
	return func() tea.Msg {
		rules, err := nft.GetAllRulesWithDrop()
		if err != nil {
			return errMsg(err)
		}
		items := make([]*nftables.Rule, len(rules))
		copy(items, rules)
		return statRulesDropMsg(items)
	}
}

func deleteRuleCmd(rule *nftables.Rule) tea.Cmd {
	return func() tea.Msg {
		if err := nft.DeleteRule(rule); err != nil {
			return chainOpErrMsg{err: err}
		}
		return ruleDeletedMsg{}
	}
}

func deleteTableCmd(table *nftables.Table) tea.Cmd {
	return func() tea.Msg {
		if err := nft.DeleteTable(table); err != nil {
			return tableOpErrMsg{err: err}
		}
		return tableDeletedMsg{}
	}
}

// moveRuleUpCmd moves rules[idx] one position up and reports newCursor = idx-1.
func moveRuleUpCmd(rules []*nftables.Rule, idx int) tea.Cmd {
	snapshot := make([]*nftables.Rule, len(rules))
	copy(snapshot, rules)
	return func() tea.Msg {
		if err := nft.MoveRuleUp(snapshot, idx); err != nil {
			return chainOpErrMsg{err: err}
		}
		return ruleMovedMsg{newCursor: idx - 1}
	}
}

// moveRuleDownCmd moves rules[idx] one position down and reports newCursor = idx+1.
func moveRuleDownCmd(rules []*nftables.Rule, idx int) tea.Cmd {
	snapshot := make([]*nftables.Rule, len(rules))
	copy(snapshot, rules)
	return func() tea.Msg {
		if err := nft.MoveRuleDown(snapshot, idx); err != nil {
			return chainOpErrMsg{err: err}
		}
		return ruleMovedMsg{newCursor: idx + 1}
	}
}

func addNewRuleToChainCmd(table *tableNode, chain *nftables.Chain) tea.Cmd {
	return func() tea.Msg {
		rule, err := nft.AddNewRuleToChain(&table.Table, chain)
		if err != nil {
			return chainOpErrMsg{err: err}
		}
		return newRuleCreatedMsg{rule: rule}
	}
}

func insertNewRuleBeforeCmd(table *tableNode, chain *nftables.Chain, rules []*nftables.Rule, idx int) tea.Cmd {
	snapshot := make([]*nftables.Rule, len(rules))
	copy(snapshot, rules)
	return func() tea.Msg {
		rule, err := nft.InsertNewRuleBefore(&table.Table, chain, snapshot, idx)
		if err != nil {
			return chainOpErrMsg{err: err}
		}
		return newRuleCreatedMsg{rule: rule}
	}
}

func renameTableCmd(table *nftables.Table, newName string) tea.Cmd {
	return func() tea.Msg {
		if err := nft.RenameTable(table, newName); err != nil {
			return tableOpErrMsg{err: err}
		}
		return tableRenamedMsg{}
	}
}

func createTableCmd(family nftables.TableFamily, name string) tea.Cmd {
	return func() tea.Msg {
		if err := nft.CreateTable(family, name); err != nil {
			return tableOpErrMsg{err: err}
		}
		return tableCreatedMsg{}
	}
}

func updateChainCmd(oldChain *nftables.Chain, newSpec *nftables.Chain) tea.Cmd {
	return func() tea.Msg {
		if err := nft.UpdateChain(oldChain, newSpec); err != nil {
			return chainOpErrMsg{err: err}
		}
		return chainUpdatedMsg{}
	}
}

func createChainCmd(table *nftables.Table, spec *nftables.Chain) tea.Cmd {
	return func() tea.Msg {
		if err := nft.CreateChain(table, spec); err != nil {
			return chainOpErrMsg{err: err}
		}
		return chainCreatedMsg{}
	}
}

// loadTableTreeCmd rebuilds the tableTreeModel from the kernel without panicking.
func loadTableTreeCmd() tea.Cmd {
	return func() tea.Msg {
		tables, err := nft.ListTables()
		if err != nil {
			return errMsg(err)
		}
		nodes := make([]*tableNode, 0, len(tables))
		for _, t := range tables {
			chains, err := nft.ListChainsOfTable(t)
			if err != nil {
				chains = nil
			}
			chainNodes := make([]*chainNode, 0, len(chains))
			for _, c := range chains {
				rules, _ := nft.ListRulesOfChain(t, c)
				chainNodes = append(chainNodes, &chainNode{Chain: *c, Rules: rules})
			}
			rulesOfTable, _ := nft.ListRulesOfTable(t)
			nodes = append(nodes, &tableNode{
				Table:  *t,
				Chains: chainNodes,
				Rules:  rulesOfTable,
			})
		}
		return tableTreeRefreshedMsg{nodes: nodes}
	}
}
