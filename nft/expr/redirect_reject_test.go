package nftexpr

import (
	"strings"
	"testing"

	"github.com/google/nftables/expr"
)

func TestSerializeRedirect(t *testing.T) {
	if got := SerializeRedirect(&expr.Redir{}); got != "redirect" {
		t.Errorf("bare redirect = %q", got)
	}
	got := SerializeRedirect(&expr.Redir{RegisterProtoMin: 1, Flags: 1 | 2})
	for _, tok := range []string{"redirect", "to :PORT"} {
		if !strings.Contains(got, tok) {
			t.Errorf("redirect with flags = %q, missing %q", got, tok)
		}
	}
}

func TestFormatRedir(t *testing.T) {
	if got := FormatRedir(&expr.Redir{}); got == "" {
		t.Error("FormatRedir returned empty string")
	}
}

func TestSerializeReject(t *testing.T) {
	tests := []struct {
		name   string
		reject expr.Reject
		want   string
	}{
		{"tcp reset", expr.Reject{Type: 1}, "reject with tcp reset"},
		{"icmp port-unreachable", expr.Reject{Type: 0, Code: 3}, "reject with icmp type port-unreachable"},
		{"icmp admin-prohibited", expr.Reject{Type: 0, Code: 13}, "reject with icmp type admin-prohibited"},
		{"icmp numeric fallback", expr.Reject{Type: 0, Code: 99}, "reject with icmp type 99"},
		{"icmpv6", expr.Reject{Type: 2}, "reject with icmpv6 type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SerializeReject(&tt.reject); got != tt.want {
				t.Errorf("SerializeReject() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSerializeReject_AllIcmpCodes(t *testing.T) {
	codes := map[uint8]string{
		0:  "net-unreachable",
		1:  "host-unreachable",
		2:  "prot-unreachable",
		3:  "port-unreachable",
		9:  "net-prohibited",
		10: "host-prohibited",
		13: "admin-prohibited",
		99: "99", // numeric fallback for unknown codes
	}
	for code, name := range codes {
		want := "reject with icmp type " + name
		if got := SerializeReject(&expr.Reject{Type: 0, Code: code}); got != want {
			t.Errorf("icmp code %d = %q, want %q", code, got, want)
		}
	}
}
