package ui

import (
	"nftui/nft"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/nftables"
)

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
