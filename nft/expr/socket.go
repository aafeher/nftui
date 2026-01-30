package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func SerializeSocket(s *expr.Socket) string {
	key := ""
	switch s.Key {
	case expr.SocketKeyTransparent:
		key = "transparent"
	default:
		key = "cgroupv2"
	}

	return fmt.Sprintf("socket %s", key)
}
