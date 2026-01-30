package nft

import (
	"log"

	"github.com/google/nftables"
)

type Set struct {
	Set      nftables.Set
	Elements []nftables.SetElement
}

type Sets []Set

func GetSets(table *nftables.Table) ([]*nftables.Set, error) {
	conn := &nftables.Conn{}
	sets, err := conn.GetSets(table)
	if err != nil {
		return nil, err
	}
	return sets, nil
}

func GetSetByName(table *nftables.Table, name string) (*nftables.Set, error) {
	conn := &nftables.Conn{}
	set, err := conn.GetSetByName(table, name)
	if err != nil {
		return nil, err
	}
	return set, nil
}

func GetSetElements(set *nftables.Set) []nftables.SetElement {
	conn := &nftables.Conn{}
	elements, err := conn.GetSetElements(set)
	if err != nil {
		log.Fatal(err)
	}

	return elements
}
