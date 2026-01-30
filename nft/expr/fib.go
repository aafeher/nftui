package nftexpr

import (
	"strings"

	"github.com/google/nftables/expr"
)

func SerializeFib(f *expr.Fib) string {
	flags := []string{}

	if f.FlagSADDR {
		flags = append(flags, "saddr")
	}
	if f.FlagDADDR {
		flags = append(flags, "daddr")
	}
	if f.FlagMARK {
		flags = append(flags, "mark")
	}
	if f.FlagIIF {
		flags = append(flags, "iif")
	}
	if f.FlagOIF {
		flags = append(flags, "oif")
	}

	result := "fib "
	if len(flags) > 0 {
		result += " " + strings.Join(flags, ".")
	}

	if f.ResultOIF {
		result += " oif"
	} else if f.ResultOIFNAME {
		result += " oifname"
	} else if f.ResultADDRTYPE {
		result += " type"
	}

	return result
}
