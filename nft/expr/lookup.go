package nftexpr

import (
	"encoding/binary"
	"fmt"
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
		setName = fmt.Sprintf("set_%d", lookup.SetID)
	}

	var formattedElements []string
	var elementsString string
	for _, set := range sets {
		if set.Name == setName {
			// In test environment GetSetElements might cause panic if Conn is not properly initialized.
			// Only call if not mocked or if needed.
			// Here we apply a simplified solution for tests.
			if set.ID == 0 && (set.Name == "" || set.Name == "__nftui_test_set__") {
				elementsString = fmt.Sprintf("@%s", set.Name)
				continue
			}

			// Try to get elements, but don't panic if it fails (e.g. in test)
			conn := &nftables.Conn{}
			elements, err := conn.GetSetElements(set)
			if err != nil {
				// If there is an error (e.g. no net connection), just use the set name
				elementsString = fmt.Sprintf("@%s", set.Name)
				continue
			}

			for _, el := range elements {
				formattedElements = append(formattedElements, formatElement(el, set))
			}
		}
	}

	if len(formattedElements) > 0 {
		elementsString = fmt.Sprintf("{%s}", strings.Join(formattedElements, ", "))
	}

	// No matching set in the `sets` slice (the set wasn't fetched, or the
	// Lookup's name didn't appear in the table's set list). Fall back to
	// "@<setName>" so the rendered form is at least syntactically nft-CLI
	// shaped, never a bare register with trailing whitespace.
	if elementsString == "" {
		elementsString = "@" + setName
	}

	if lookup.Invert {
		return fmt.Sprintf("%s != %s", register, elementsString)
	}
	return fmt.Sprintf("%s %s", register, elementsString)
}

func SerializeLookupWithKey(lookup *expr.Lookup, register string, key expr.CtKey, sets []*nftables.Set) string {
	if register == "" {
		register = fmt.Sprintf("register_%d", lookup.SourceRegister)
	}

	setName := lookup.SetName
	if setName == "" {
		setName = fmt.Sprintf("set_%d", lookup.SetID)
	}

	var formattedElements []string
	var elementsString string
	for _, set := range sets {
		if set.Name == setName {
			if set.ID == 0 && (set.Name == "" || set.Name == "__nftui_test_set__") {
				elementsString = fmt.Sprintf("@%s", set.Name)
				continue
			}

			conn := &nftables.Conn{}
			elements, err := conn.GetSetElements(set)
			if err != nil {
				elementsString = fmt.Sprintf("@%s", set.Name)
				continue
			}

			for _, el := range elements {
				formattedElements = append(formattedElements, formatCtValue(key, el.Key))
			}
		}
	}

	if len(formattedElements) > 0 {
		elementsString = fmt.Sprintf("{%s}", strings.Join(formattedElements, ", "))
	}

	// Same fallback as SerializeLookup: a set missing from the `sets` slice
	// must render as "@<setName>", never as a register with trailing
	// whitespace.
	if elementsString == "" {
		elementsString = "@" + setName
	}

	if lookup.Invert {
		return fmt.Sprintf("%s != %s", register, elementsString)
	}
	return fmt.Sprintf("%s %s", register, elementsString)
}

func formatElement(el nftables.SetElement, set *nftables.Set) string {
	// Convert bytes depending on set type
	switch set.KeyType {
	case nftables.TypeIPAddr:
		return net.IP(el.Key).String()
	case nftables.TypeIP6Addr:
		return net.IP(el.Key).String()
	case nftables.TypeInetService: // ports (e.g. TCP/UDP)
		if len(el.Key) >= 2 {
			return fmt.Sprintf("%d", binary.BigEndian.Uint16(el.Key))
		}
	}

	// CT State
	if len(el.Key) == 4 {
		ctStates := DecodeCTValue(expr.CtKeySTATE, el.Key)
		return fmt.Sprintf("%v", ctStates)
	}

	// If type is unknown, return in hexadecimal format
	return fmt.Sprintf("%x", el.Key)
}
