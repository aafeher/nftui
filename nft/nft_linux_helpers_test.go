package nft

// Exhaustive coverage for the pure string-mapping helpers in nft_linux.go.
// These are netlink-free switch tables: every documented case plus the
// default fallback is asserted, so they reach (or pin the unreachable
// ceiling of) full statement coverage without touching the kernel.

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestLogLevelToString(t *testing.T) {
	cases := map[expr.LogLevel]string{
		expr.LogLevelEmerg:   "emerg",
		expr.LogLevelAlert:   "alert",
		expr.LogLevelCrit:    "crit",
		expr.LogLevelErr:     "err",
		expr.LogLevelWarning: "warning",
		expr.LogLevelNotice:  "notice",
		expr.LogLevelInfo:    "info",
		expr.LogLevelDebug:   "debug",
		expr.LogLevelAudit:   "audit",
		expr.LogLevel(0xff):  "unknown",
	}
	for in, want := range cases {
		if got := logLevelToString(in); got != want {
			t.Errorf("logLevelToString(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestPayloadBaseToString(t *testing.T) {
	cases := map[expr.PayloadBase]string{
		unix.NFT_PAYLOAD_LL_HEADER:        "ll header",
		unix.NFT_PAYLOAD_NETWORK_HEADER:   "network header",
		unix.NFT_PAYLOAD_TRANSPORT_HEADER: "transport header",
		expr.PayloadBase(0xff):            "unknown",
	}
	for in, want := range cases {
		if got := payloadBaseToString(in); got != want {
			t.Errorf("payloadBaseToString(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestVerdictKindToString(t *testing.T) {
	cases := map[expr.VerdictKind]string{
		expr.VerdictReturn:   "return",
		expr.VerdictGoto:     "goto",
		expr.VerdictJump:     "jump",
		expr.VerdictBreak:    "break",
		expr.VerdictContinue: "continue",
		expr.VerdictDrop:     "drop",
		expr.VerdictAccept:   "accept",
		expr.VerdictStolen:   "stolen",
		expr.VerdictQueue:    "queue",
		expr.VerdictRepeat:   "repeat",
		expr.VerdictStop:     "stop",
		expr.VerdictKind(99): "unknown",
	}
	for in, want := range cases {
		if got := verdictKindToString(in); got != want {
			t.Errorf("verdictKindToString(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestKeyTypeToString(t *testing.T) {
	cases := []struct {
		in   nftables.SetDatatype
		want string
	}{
		{nftables.TypeIPAddr, "ipv4_addr"},
		{nftables.TypeIP6Addr, "ipv6_addr"},
		{nftables.TypeInetProto, "inet_proto"},
		{nftables.TypeInetService, "inet_service"},
		{nftables.TypeEtherAddr, "ether_addr"},
		// Unknown datatype falls through to the type_<name> form.
		{nftables.SetDatatype{Name: "mark"}, "type_mark"},
	}
	for _, tt := range cases {
		if got := KeyTypeToString(tt.in); got != tt.want {
			t.Errorf("KeyTypeToString(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIcmpv6TypeToString(t *testing.T) {
	cases := map[uint8]string{
		1:   "destination-unreachable",
		2:   "packet-too-big",
		3:   "time-exceeded",
		4:   "parameter-problem",
		128: "echo-request",
		129: "echo-reply",
		130: "mld-listener-query",
		131: "mld-listener-report",
		132: "mld-listener-done",
		133: "nd-router-solicit",
		134: "nd-router-advert",
		135: "nd-neighbor-solicit",
		136: "nd-neighbor-advert",
		137: "nd-redirect",
		138: "router-renumbering",
		141: "ind-neighbor-solicit",
		142: "ind-neighbor-advert",
		143: "mld2-listener-report",
		// Unmapped value renders the numeric fallback.
		200: "icmpv6_type_200",
	}
	for in, want := range cases {
		if got := Icmpv6TypeToString(in); got != want {
			t.Errorf("Icmpv6TypeToString(%d) = %q, want %q", in, got, want)
		}
	}
}
