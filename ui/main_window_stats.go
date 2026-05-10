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
