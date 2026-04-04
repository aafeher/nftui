package nft

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestExtractComment(t *testing.T) {
	tests := []struct {
		name     string
		userData []byte
		want     string
	}{
		{
			name:     "empty userdata",
			userData: []byte{},
			want:     "",
		},
		{
			name:     "too short",
			userData: []byte{0},
			want:     "",
		},
		{
			name:     "valid comment",
			userData: []byte{0, 6, 'h', 'e', 'l', 'l', 'o', 0},
			want:     "hello",
		},
		{
			name:     "comment without null terminator",
			userData: []byte{0, 3, 'f', 'o', 'o'},
			want:     "foo",
		},
		{
			name:     "wrong TLV type ignored",
			userData: []byte{1, 3, 'b', 'a', 'd'},
			want:     "",
		},
		{
			name:     "truncated TLV",
			userData: []byte{0, 10, 'a', 'b'},
			want:     "",
		},
		{
			name:     "empty comment value",
			userData: []byte{0, 1, 0},
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &nftables.Rule{UserData: tt.userData}
			got := ExtractComment(rule)
			if got != tt.want {
				t.Errorf("ExtractComment() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMetaKeyToString(t *testing.T) {
	tests := []struct {
		key  expr.MetaKey
		want string
	}{
		{unix.NFT_META_IIF, "iif"},
		{unix.NFT_META_OIF, "oif"},
		{unix.NFT_META_IIFNAME, "iifname"},
		{unix.NFT_META_OIFNAME, "oifname"},
		{unix.NFT_META_L4PROTO, "l4proto"},
		{unix.NFT_META_MARK, "mark"},
		{unix.NFT_META_PROTOCOL, "protocol"},
		{expr.MetaKey(255), "meta_255"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := metaKeyToString(tt.key)
			if got != tt.want {
				t.Errorf("metaKeyToString(%d) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestSyslogLevelToLogLevel(t *testing.T) {
	tests := []struct {
		level expr.LogLevel
		want  LogLevel
	}{
		{0, LogLevelEmerg},
		{1, LogLevelAlert},
		{2, LogLevelCrit},
		{3, LogLevelErr},
		{4, LogLevelWarn},
		{5, LogLevelNotice},
		{6, LogLevelInfo},
		{7, LogLevelDebug},
		{99, LogLevelInfo}, // unknown defaults to info
	}

	for _, tt := range tests {
		t.Run(string(tt.want), func(t *testing.T) {
			got := syslogLevelToLogLevel(tt.level)
			if got != tt.want {
				t.Errorf("syslogLevelToLogLevel(%d) = %q, want %q", tt.level, got, tt.want)
			}
		})
	}
}

func TestCmpOpToCompareOp(t *testing.T) {
	tests := []struct {
		op   expr.CmpOp
		want CompareOp
	}{
		{expr.CmpOpEq, CompareOpEq},
		{expr.CmpOpNeq, CompareOpNeq},
		{expr.CmpOpLt, CompareOpLt},
		{expr.CmpOpLte, CompareOpLte},
		{expr.CmpOpGt, CompareOpGt},
		{expr.CmpOpGte, CompareOpGte},
		{expr.CmpOp(99), CompareOpEq}, // unknown defaults to eq
	}

	for _, tt := range tests {
		t.Run(string(tt.want), func(t *testing.T) {
			got := cmpOpToCompareOp(tt.op)
			if got != tt.want {
				t.Errorf("cmpOpToCompareOp(%d) = %q, want %q", tt.op, got, tt.want)
			}
		})
	}
}

func TestVerdictToHumanReadable(t *testing.T) {
	tests := []struct {
		name    string
		verdict expr.Verdict
		want    string
	}{
		{"accept", expr.Verdict{Kind: expr.VerdictAccept}, "accept"},
		{"drop", expr.Verdict{Kind: expr.VerdictDrop}, "drop"},
		{"return", expr.Verdict{Kind: expr.VerdictReturn}, "return"},
		{"jump", expr.Verdict{Kind: expr.VerdictJump, Chain: "my_chain"}, "jump my_chain"},
		{"goto", expr.Verdict{Kind: expr.VerdictGoto, Chain: "target"}, "goto target"},
		{"unknown", expr.Verdict{Kind: expr.VerdictKind(99)}, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verdictToHumanReadable(&tt.verdict)
			if got != tt.want {
				t.Errorf("verdictToHumanReadable() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPayloadToHumanReadable(t *testing.T) {
	tests := []struct {
		name    string
		payload expr.Payload
		want    string
	}{
		{"sport", expr.Payload{Base: unix.NFT_PAYLOAD_TRANSPORT_HEADER, Offset: 0, Len: 2}, "sport"},
		{"dport", expr.Payload{Base: unix.NFT_PAYLOAD_TRANSPORT_HEADER, Offset: 2, Len: 2}, "dport"},
		{"icmp type", expr.Payload{Base: unix.NFT_PAYLOAD_TRANSPORT_HEADER, Offset: 0, Len: 1}, "icmp type"},
		{"ip protocol", expr.Payload{Base: unix.NFT_PAYLOAD_NETWORK_HEADER, Offset: 9, Len: 1}, "ip protocol"},
		{"saddr", expr.Payload{Base: unix.NFT_PAYLOAD_NETWORK_HEADER, Offset: 12, Len: 4}, "saddr"},
		{"daddr", expr.Payload{Base: unix.NFT_PAYLOAD_NETWORK_HEADER, Offset: 16, Len: 4}, "daddr"},
		{"unknown transport", expr.Payload{Base: unix.NFT_PAYLOAD_TRANSPORT_HEADER, Offset: 99, Len: 4}, "payload[transport header+99:4]"},
		{"unknown network", expr.Payload{Base: unix.NFT_PAYLOAD_NETWORK_HEADER, Offset: 99, Len: 4}, "payload[network header+99:4]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := payloadToHumanReadable(&tt.payload)
			if got != tt.want {
				t.Errorf("payloadToHumanReadable() = %q, want %q", got, tt.want)
			}
		})
	}
}
