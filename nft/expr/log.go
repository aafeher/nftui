package nftexpr

import (
	"fmt"
	"strings"

	"github.com/google/nftables/expr"
)

func FormatLog(log *expr.Log) string {
	return fmt.Sprintf("log TBD")
}

func SerializeLog(l *expr.Log) string {
	result := "log"

	if l.Key != 0 {
		result += fmt.Sprintf(" group %d", l.Key)
	}

	if l.Data != nil && len(l.Data) > 0 {
		prefix := string(l.Data)
		result += fmt.Sprintf(" prefix \"%s\"", prefix)
	}

	if l.Level != 0 {
		levels := []string{"emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"}
		if int(l.Level) < len(levels) {
			result += fmt.Sprintf(" level %s", levels[l.Level])
		}
	}

	if l.Flags != 0 {
		flags := []string{}
		if l.Flags&0x01 != 0 {
			flags = append(flags, "tcp sequence")
		}
		if l.Flags&0x02 != 0 {
			flags = append(flags, "tcp options")
		}
		if l.Flags&0x04 != 0 {
			flags = append(flags, "ip options")
		}
		if l.Flags&0x08 != 0 {
			flags = append(flags, "skuid")
		}
		if l.Flags&0x10 != 0 {
			flags = append(flags, "ether")
		}
		if len(flags) > 0 {
			result += " flags " + strings.Join(flags, ",")
		}
	}

	return result
}
