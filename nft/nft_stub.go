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
