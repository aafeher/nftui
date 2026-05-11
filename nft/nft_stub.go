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

func RenameTable(_ *nftables.Table, _ string) error {
	return fmt.Errorf("Az nftables csak Linux rendszeren érhető el.")
}

func CreateTable(_ nftables.TableFamily, _ string) error {
	return fmt.Errorf("nftables is only available on Linux.")
}

func DeleteTable(_ *nftables.Table) error {
	return fmt.Errorf("nftables is only available on Linux.")
}

func UpdateChain(_ *nftables.Chain, _ *nftables.Chain) error {
	return fmt.Errorf("nftables is only available on Linux.")
}

func CreateChain(_ *nftables.Table, _ *nftables.Chain) error {
	return fmt.Errorf("nftables is only available on Linux.")
}

func DeleteChain(_ *nftables.Chain) error {
	return fmt.Errorf("nftables is only available on Linux.")
}

func DeleteRule(_ *nftables.Rule) error {
	return fmt.Errorf("nftables is only available on Linux.")
}

func MoveRuleUp(_ []*nftables.Rule, _ int) error {
	return fmt.Errorf("nftables is only available on Linux.")
}

func MoveRuleDown(_ []*nftables.Rule, _ int) error {
	return fmt.Errorf("nftables is only available on Linux.")
}

func AddNewRuleToChain(_ *nftables.Table, _ *nftables.Chain) (*nftables.Rule, error) {
	return nil, fmt.Errorf("nftables is only available on Linux.")
}

func InsertNewRuleBefore(_ *nftables.Table, _ *nftables.Chain, _ []*nftables.Rule, _ int) (*nftables.Rule, error) {
	return nil, fmt.Errorf("nftables is only available on Linux.")
}
