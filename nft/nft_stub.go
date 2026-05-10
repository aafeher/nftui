//go:build !linux

package nft

import (
	"fmt"

	"github.com/google/nftables"
)

func ListTables() ([]*nftables.Table, error) {
	return nil, fmt.Errorf("Az nftables csak Linux rendszeren érhető el.")
}

func ListChains() ([]*nftables.Chain, error) {
	return nil, fmt.Errorf("Az nftables csak Linux rendszeren érhető el.")
}

func getAllRules() ([]*nftables.Rule, error) {
	return nil, fmt.Errorf("Az nftables csak Linux rendszeren érhető el.")
}

func DeleteRule(_ *nftables.Rule) error {
	return fmt.Errorf("Az nftables csak Linux rendszeren érhető el.")
}

func MoveRuleUp(_ []*nftables.Rule, _ int) error {
	return fmt.Errorf("Az nftables csak Linux rendszeren érhető el.")
}

func MoveRuleDown(_ []*nftables.Rule, _ int) error {
	return fmt.Errorf("Az nftables csak Linux rendszeren érhető el.")
}

func AddNewRuleToChain(_ *nftables.Table, _ *nftables.Chain) (*nftables.Rule, error) {
	return nil, fmt.Errorf("Az nftables csak Linux rendszeren érhető el.")
}

func InsertNewRuleBefore(_ *nftables.Table, _ *nftables.Chain, _ []*nftables.Rule, _ int) (*nftables.Rule, error) {
	return nil, fmt.Errorf("Az nftables csak Linux rendszeren érhető el.")
}
