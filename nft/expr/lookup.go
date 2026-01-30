package nftexpr

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func SerializeLookup(lookup *expr.Lookup, register string, sets []*nftables.Set) string {
	if register == "" {
		register = fmt.Sprintf("register_%d", lookup.SourceRegister)
	}

	setName := lookup.SetName
	if setName == "" {
		setName = fmt.Sprintf("@set_%d", lookup.SetID)
	}

	var formattedElements []string
	var elementsString string
	for _, set := range sets {
		if set.Name == setName {
			//fmt.Printf("13. set: %+v\n", set)
			conn := &nftables.Conn{}
			elements, err := conn.GetSetElements(set)
			if err != nil {
				log.Fatal(err)
			}

			for _, el := range elements {
				formattedElements = append(formattedElements, formatElement(el, set))
			}
			//fmt.Printf("Set (%s) elemei: %v\n", set.Name, formattedElements)
		}
	}

	if len(formattedElements) > 0 {
		elementsString = fmt.Sprintf("{%s}", strings.Join(formattedElements, ", "))
	}

	if lookup.Invert {
		return fmt.Sprintf("%s != %s", register, elementsString)
	}
	return fmt.Sprintf("%s %s", register, elementsString)
}

func formatElement(el nftables.SetElement, set *nftables.Set) string {
	// A set típusától függően alakítjuk át a bájtokat
	switch set.KeyType {
	case nftables.TypeIPAddr:
		return net.IP(el.Key).String()
	case nftables.TypeIP6Addr:
		return net.IP(el.Key).String()
	case nftables.TypeInetService: // Portok (pl. TCP/UDP)
		if len(el.Key) >= 2 {
			return fmt.Sprintf("%d", binary.BigEndian.Uint16(el.Key))
		}
	}

	// CT State
	if len(el.Key) == 4 {
		ctStates := DecodeCTValue(expr.CtKeySTATE, el.Key)
		return fmt.Sprintf("%v", ctStates)
	}

	// Ha ismeretlen a típus, hexadecimális formátumban adjuk vissza
	return fmt.Sprintf("%x", el.Key)
}
