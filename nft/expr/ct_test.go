package nftexpr

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestCtKeyToString(t *testing.T) {
	tests := []struct {
		ctKey expr.CtKey
		want  string
	}{
		{unix.NFT_CT_STATE, "state"},
		{unix.NFT_CT_DIRECTION, "direction"},
		{unix.NFT_CT_STATUS, "status"},
		{unix.NFT_CT_MARK, "mark"},
		{unix.NFT_CT_SECMARK, "secmark"},
		{unix.NFT_CT_EXPIRATION, "expiration"},
		{unix.NFT_CT_HELPER, "helper"},
		{unix.NFT_CT_L3PROTOCOL, "l3protocol"},
		{unix.NFT_CT_SRC, "src"},
		{unix.NFT_CT_DST, "dst"},
		{unix.NFT_CT_PROTOCOL, "protocol"},
		{unix.NFT_CT_PROTO_SRC, "proto_src"},
		{unix.NFT_CT_PROTO_DST, "proto_dst"},
		{unix.NFT_CT_LABELS, "labels"},
		{unix.NFT_CT_PKTS, "pkts"},
		{unix.NFT_CT_BYTES, "bytes"},
		{unix.NFT_CT_AVGPKT, "avgpkt"},
		{unix.NFT_CT_ZONE, "zone"},
		{unix.NFT_CT_EVENTMASK, "eventmask"},
		{expr.CtKey(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := CtKeyToString(tt.ctKey)
			if got != tt.want {
				t.Errorf("CtKeyToString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatCt(t *testing.T) {
	tests := []struct {
		ct   expr.Ct
		want string
	}{
		{expr.Ct{Register: 1, SourceRegister: true, Key: unix.NFT_CT_STATE, Direction: 0}, "ct 1 sreg state 0"},
		{expr.Ct{Register: 2, SourceRegister: false, Key: unix.NFT_CT_SRC, Direction: 1}, "ct 2 dreg src 1"},
		{expr.Ct{Register: 3, SourceRegister: true, Key: expr.CtKey(999), Direction: 2}, "ct 3 sreg unknown 2"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := FormatCt(&tt.ct)
			if got != tt.want {
				t.Errorf("FormatCt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSerializeCt(t *testing.T) {
	tests := []struct {
		name    string
		ct      *expr.Ct
		exprs   []expr.Any
		pos     int
		sets    []*nftables.Set
		wantStr string
		wantIdx int
	}{
		{
			name:    "Simple CT state",
			ct:      &expr.Ct{Key: unix.NFT_CT_STATE, Register: 1},
			exprs:   []expr.Any{&expr.Ct{Key: unix.NFT_CT_STATE, Register: 1}},
			pos:     0,
			wantStr: "ct state",
			wantIdx: 1,
		},
		{
			name: "CT state established",
			ct:   &expr.Ct{Key: unix.NFT_CT_STATE, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_STATE, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     EncodeCtStates([]CtState{CtStateEstablished}),
				},
			},
			pos:     0,
			wantStr: "ct state established",
			wantIdx: 2,
		},
		{
			name: "CT bytes",
			ct:   &expr.Ct{Key: unix.NFT_CT_BYTES, Register: 1, Direction: 255},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_BYTES, Register: 1, Direction: 255},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 1024 Little Endian
				},
			},
			pos:     0,
			wantStr: "ct bytes 1024",
			wantIdx: 2,
		},
		{
			name: "CT bytes 100000 Little Endian (Bug Reproducer)",
			ct:   &expr.Ct{Key: unix.NFT_CT_BYTES, Register: 1, Direction: 255},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_BYTES, Register: 1, Direction: 255},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{0xa0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}, // 100000 Little Endian
				},
			},
			pos:     0,
			wantStr: "ct bytes 100000",
			wantIdx: 2,
		},
		{
			name: "CT bytes 1024 Big Endian (Compatibility Check)",
			ct:   &expr.Ct{Key: unix.NFT_CT_BYTES, Register: 1, Direction: 255},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_BYTES, Register: 1, Direction: 255},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00}, // 1024 Big Endian
				},
			},
			pos:     0,
			wantStr: "ct bytes 1024",
			wantIdx: 2,
		},
		{
			name: "CT bytes > 1024",
			ct:   &expr.Ct{Key: unix.NFT_CT_BYTES, Register: 1, Direction: 255},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_BYTES, Register: 1, Direction: 255},
				&expr.Cmp{
					Op:       expr.CmpOpGt,
					Register: 1,
					Data:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00}, // 1024 Big Endian
				},
			},
			pos:     0,
			wantStr: "ct bytes > 1024",
			wantIdx: 2,
		},
		{
			name: "CT original bytes > 1024",
			ct:   &expr.Ct{Key: unix.NFT_CT_BYTES, Register: 1, Direction: 0},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_BYTES, Register: 1, Direction: 0},
				&expr.Cmp{
					Op:       expr.CmpOpGt,
					Register: 1,
					Data:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00},
				},
			},
			pos:     0,
			wantStr: "ct original bytes > 1024",
			wantIdx: 2,
		},
		{
			name: "CT reply bytes > 1024",
			ct:   &expr.Ct{Key: unix.NFT_CT_BYTES, Register: 1, Direction: 1}, // reply
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_BYTES, Register: 1, Direction: 1},
				&expr.Cmp{
					Op:       expr.CmpOpGt,
					Register: 1,
					Data:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00},
				},
			},
			pos:     0,
			wantStr: "ct reply bytes > 1024",
			wantIdx: 2,
		},
		{
			name: "CT packets",
			ct:   &expr.Ct{Key: unix.NFT_CT_PKTS, Register: 1, Direction: 255},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_PKTS, Register: 1, Direction: 255},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 10 Little Endian
				},
			},
			pos:     0,
			wantStr: "ct pkts 10",
			wantIdx: 2,
		},
		{
			name: "CT original packets > 100",
			ct:   &expr.Ct{Key: unix.NFT_CT_PKTS, Register: 1, Direction: 0},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_PKTS, Register: 1, Direction: 0},
				&expr.Cmp{
					Op:       expr.CmpOpGt,
					Register: 1,
					Data:     []byte{0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 100 Little Endian
				},
			},
			pos:     0,
			wantStr: "ct original pkts > 100",
			wantIdx: 2,
		},
		{
			name: "CT reply packets != 50",
			ct:   &expr.Ct{Key: unix.NFT_CT_PKTS, Register: 1, Direction: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_PKTS, Register: 1, Direction: 1},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     []byte{0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 50 Little Endian
				},
			},
			pos:     0,
			wantStr: "ct reply pkts != 50",
			wantIdx: 2,
		},
		{
			name: "CT helper",
			ct:   &expr.Ct{Key: unix.NFT_CT_HELPER, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_HELPER, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte("ftp\x00"),
				},
			},
			pos:     0,
			wantStr: "ct helper ftp",
			wantIdx: 2,
		},
		{
			name: "CT state multiple states (Bitwise)",
			ct:   &expr.Ct{Key: unix.NFT_CT_STATE, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_STATE, Register: 1},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            4,
					Mask:           EncodeCtStates([]CtState{CtStateEstablished, CtStateRelated}),
					Xor:            make([]byte, 4),
				},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     make([]byte, 4),
				},
			},
			pos:     0,
			wantStr: "ct state {established, related}",
			wantIdx: 3,
		},
		{
			name: "CT direction reply",
			ct:   &expr.Ct{Key: unix.NFT_CT_DIRECTION, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_DIRECTION, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{1},
				},
			},
			pos:     0,
			wantStr: "ct direction reply",
			wantIdx: 2,
		},
		{
			name: "CT direction original",
			ct:   &expr.Ct{Key: unix.NFT_CT_DIRECTION, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_DIRECTION, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{0},
				},
			},
			pos:     0,
			wantStr: "ct direction original",
			wantIdx: 2,
		},
		{
			name: "CT protocol TCP",
			ct:   &expr.Ct{Key: unix.NFT_CT_PROTOCOL, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_PROTOCOL, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{6},
				},
			},
			pos:     0,
			wantStr: "ct protocol 6",
			wantIdx: 2,
		},
		{
			name: "CT source IP",
			ct:   &expr.Ct{Key: unix.NFT_CT_SRC, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_SRC, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{192, 168, 1, 1},
				},
			},
			pos:     0,
			wantStr: "ct src 192.168.1.1",
			wantIdx: 2,
		},
		{
			name: "CT status expected",
			ct:   &expr.Ct{Key: unix.NFT_CT_STATUS, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_STATUS, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     EncodeCtStatuses([]CtStatus{CtStatusExpected}),
				},
			},
			pos:     0,
			wantStr: "ct status expected",
			wantIdx: 2,
		},
		{
			name: "CT status multiple (Bitwise)",
			ct:   &expr.Ct{Key: unix.NFT_CT_STATUS, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_STATUS, Register: 1},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            4,
					Mask:           EncodeCtStatuses([]CtStatus{CtStatusExpected, CtStatusSeenReply, CtStatusAssured, CtStatusConfirmed, CtStatusSnat, CtStatusDnat, CtStatusDying}),
					Xor:            make([]byte, 4),
				},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     make([]byte, 4),
				},
			},
			pos:     0,
			wantStr: "ct status {expected, seen-reply, assured, confirmed, snat, dnat, dying}",
			wantIdx: 3,
		},
		{
			name: "CT expiration 30s",
			ct:   &expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{0, 0, 0, 30}, // 30 seconds
				},
			},
			pos:     0,
			wantStr: "ct expiration 30s",
			wantIdx: 2,
		},
		{
			name: "CT expiration != 233s",
			ct:   &expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     []byte{0, 0, 0, 233}, // 233 seconds
				},
			},
			pos:     0,
			wantStr: "ct expiration != 3m53s",
			wantIdx: 2,
		},
		{
			name: "CT expiration 33s-45s",
			ct:   &expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
				&expr.Range{
					Op:       expr.CmpOpEq,
					Register: 1,
					FromData: []byte{0, 0, 0, 33},
					ToData:   []byte{0, 0, 0, 45},
				},
			},
			pos:     0,
			wantStr: "ct expiration 33s-45s",
			wantIdx: 2,
		},
		{
			name: "CT expiration != 33s-45s",
			ct:   &expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
				&expr.Range{
					Op:       expr.CmpOpNeq,
					Register: 1,
					FromData: []byte{0, 0, 0, 33},
					ToData:   []byte{0, 0, 0, 45},
				},
			},
			pos:     0,
			wantStr: "ct expiration != 33s-45s",
			wantIdx: 2,
		},
		{
			name: "CT expiration set",
			ct:   &expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
				&expr.Lookup{
					SourceRegister: 1,
					SetName:        "exp_set",
				},
			},
			pos: 0,
			sets: []*nftables.Set{
				{
					Name: "exp_set",
				},
			},
			wantStr: "ct expiration @exp_set",
			wantIdx: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStr, gotIdx := SerializeCt(tt.ct, tt.exprs, tt.pos, tt.sets)
			if gotStr != tt.wantStr {
				t.Errorf("SerializeCt() gotStr = %q, want %q", gotStr, tt.wantStr)
			}
			if gotIdx != tt.wantIdx {
				t.Errorf("SerializeCt() gotIdx = %d, want %d", gotIdx, tt.wantIdx)
			}
		})
	}
}

func ctStatusesAreEqual(a1 []CtStatus, a2 []CtStatus) bool {
	if len(a1) != len(a2) {
		return false
	}
	counts := make(map[CtStatus]int, len(a1))
	for _, s := range a1 {
		counts[s]++
	}
	for _, s := range a2 {
		n := counts[s]
		if n == 0 {
			return false
		}
		if n == 1 {
			delete(counts, s)
		} else {
			counts[s] = n - 1
		}
	}
	return len(counts) == 0
}

func TestExprCtToCt(t *testing.T) {
	tests := []struct {
		name    string
		ct      *expr.Ct
		exprs   []expr.Any
		pos     int
		sets    []*nftables.Set
		want    Ct
		wantIdx int
	}{
		{
			name: "Populate state",
			ct:   &expr.Ct{Key: unix.NFT_CT_STATE, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_STATE, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     EncodeCtStates([]CtState{CtStateEstablished}),
				},
			},
			pos: 0,
			want: Ct{
				State: []CtState{CtStateEstablished},
			},
			wantIdx: 2,
		},
		{
			name: "Populate multiple states via Bitwise",
			ct:   &expr.Ct{Key: unix.NFT_CT_STATE, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_STATE, Register: 1},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            4,
					Mask:           EncodeCtStates([]CtState{CtStateEstablished, CtStateRelated}),
					Xor:            make([]byte, 4),
				},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     make([]byte, 4),
				},
			},
			pos: 0,
			want: Ct{
				State: []CtState{CtStateEstablished, CtStateRelated},
			},
			wantIdx: 3,
		},
		{
			name: "Populate status (Expected and Assured)",
			ct:   &expr.Ct{Key: unix.NFT_CT_STATUS, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_STATUS, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					// status = CtStatusBitExpected (1) | CtStatusBitAssured (4) = 5
					Data: []byte{5, 0, 0, 0},
				},
			},
			pos: 0,
			want: Ct{
				Status: []CtStatus{CtStatusExpected, CtStatusAssured},
			},
			wantIdx: 2,
		},
		{
			name: "Populate mark",
			ct:   &expr.Ct{Key: unix.NFT_CT_MARK, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_MARK, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{0xde, 0xad, 0xbe, 0xef}, // Little endian: ef be ad de
				},
			},
			pos: 0,
			want: Ct{
				Mark: 0xefbeadde,
			},
			wantIdx: 2,
		},
		{
			name: "Populate expiration",
			ct:   &expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{0x00, 0x00, 0x00, 0x3c}, // 60 seconds (Big Endian)
				},
			},
			pos: 0,
			want: Ct{
				Expiration: 60,
			},
			wantIdx: 2,
		},
		{
			name: "Reproduce issue: expiration 30s as 30000ms (Big Endian)",
			ct:   &expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{0x00, 0x00, 0x75, 0x30}, // 30000 ms (Big Endian)
				},
			},
			pos: 0,
			want: Ct{
				Expiration: 30,
			},
			wantIdx: 2,
		},
		{
			name: "Populate bytes",
			ct:   &expr.Ct{Key: unix.NFT_CT_BYTES, Register: 1, Direction: 255},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_BYTES, Register: 1, Direction: 255},
				&expr.Cmp{
					Op:       expr.CmpOpGt,
					Register: 1,
					Data:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00}, // 1024 Big Endian
				},
			},
			pos: 0,
			want: Ct{
				Bytes:     1024,
				Direction: CtDirectionNone,
			},
			wantIdx: 2,
		},
		{
			name: "Populate original bytes",
			ct:   &expr.Ct{Key: unix.NFT_CT_BYTES, Register: 1, Direction: 0},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_BYTES, Register: 1, Direction: 0},
				&expr.Cmp{
					Op:       expr.CmpOpGt,
					Register: 1,
					Data:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00},
				},
			},
			pos: 0,
			want: Ct{
				Bytes:     1024,
				Direction: CtDirectionOriginal,
			},
			wantIdx: 2,
		},
		{
			name: "Populate reply bytes",
			ct:   &expr.Ct{Key: unix.NFT_CT_BYTES, Register: 1, Direction: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_BYTES, Register: 1, Direction: 1},
				&expr.Cmp{
					Op:       expr.CmpOpGt,
					Register: 1,
					Data:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00},
				},
			},
			pos: 0,
			want: Ct{
				Bytes:     1024,
				Direction: CtDirectionReply,
			},
			wantIdx: 2,
		},
		{
			name: "Populate packets",
			ct:   &expr.Ct{Key: unix.NFT_CT_PKTS, Register: 1, Direction: 255},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_PKTS, Register: 1, Direction: 255},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 10 Little Endian
				},
			},
			pos: 0,
			want: Ct{
				Pkts:      10,
				Direction: CtDirectionNone,
			},
			wantIdx: 2,
		},
		{
			name: "Populate original packets",
			ct:   &expr.Ct{Key: unix.NFT_CT_PKTS, Register: 1, Direction: 0},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_PKTS, Register: 1, Direction: 0},
				&expr.Cmp{
					Op:       expr.CmpOpGt,
					Register: 1,
					Data:     []byte{0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 100 Little Endian
				},
			},
			pos: 0,
			want: Ct{
				Pkts:      100,
				Direction: CtDirectionOriginal,
			},
			wantIdx: 2,
		},
		{
			name: "Populate reply packets",
			ct:   &expr.Ct{Key: unix.NFT_CT_PKTS, Register: 1, Direction: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_PKTS, Register: 1, Direction: 1},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     []byte{0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 50 Little Endian
				},
			},
			pos: 0,
			want: Ct{
				Pkts:      50,
				Direction: CtDirectionReply,
			},
			wantIdx: 2,
		},
		{
			name: "Populate direction reply",
			ct:   &expr.Ct{Key: unix.NFT_CT_DIRECTION, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_DIRECTION, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{1},
				},
			},
			pos: 0,
			want: Ct{
				Direction: CtDirectionReply,
			},
			wantIdx: 2,
		},
		{
			name: "Populate protocol",
			ct:   &expr.Ct{Key: unix.NFT_CT_PROTOCOL, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_PROTOCOL, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{6}, // TCP
				},
			},
			pos: 0,
			want: Ct{
				Protocol: 6,
			},
			wantIdx: 2,
		},
		{
			name: "Populate source IP",
			ct:   &expr.Ct{Key: unix.NFT_CT_SRC, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_SRC, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{192, 168, 1, 1},
				},
			},
			pos: 0,
			want: Ct{
				Src: "192.168.1.1",
			},
			wantIdx: 2,
		},
		{
			name: "Populate source port",
			ct:   &expr.Ct{Key: unix.NFT_CT_PROTO_SRC, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_PROTO_SRC, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{0x1f, 0x90}, // 8080 in Big Endian
				},
			},
			pos: 0,
			want: Ct{
				ProtoSrc: 8080,
			},
			wantIdx: 2,
		},
		{
			name: "Populate multiple statuses via Bitwise",
			ct:   &expr.Ct{Key: unix.NFT_CT_STATUS, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_STATUS, Register: 1},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            4,
					Mask:           EncodeCtStatuses([]CtStatus{CtStatusExpected, CtStatusSeenReply, CtStatusAssured, CtStatusConfirmed, CtStatusSnat, CtStatusDnat, CtStatusDying}),
					Xor:            make([]byte, 4),
				},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     make([]byte, 4),
				},
			},
			pos: 0,
			want: Ct{
				Status: []CtStatus{CtStatusExpected, CtStatusSeenReply, CtStatusAssured, CtStatusConfirmed, CtStatusSnat, CtStatusDnat, CtStatusDying},
			},
			wantIdx: 3,
		},
		{
			name: "Populate expiration range (Big Endian)",
			ct:   &expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
				&expr.Range{
					Op:       expr.CmpOpEq,
					Register: 1,
					FromData: []byte{0, 0, 0, 33}, // 33s Big Endian
					ToData:   []byte{0, 0, 0, 45}, // 45s Big Endian
				},
			},
			pos: 0,
			want: Ct{
				ExpirationRange: &CtRange{From: 33, To: 45},
				ExpirationOp:    "==",
			},
			wantIdx: 2,
		},
		{
			name: "Populate expiration range neq (Big Endian)",
			ct:   &expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
				&expr.Range{
					Op:       expr.CmpOpNeq,
					Register: 1,
					FromData: []byte{0, 0, 0, 33}, // 33s Big Endian
					ToData:   []byte{0, 0, 0, 45}, // 45s Big Endian
				},
			},
			pos: 0,
			want: Ct{
				ExpirationRange: &CtRange{From: 33, To: 45},
				ExpirationOp:    "!=",
			},
			wantIdx: 2,
		},
		{
			name: "Populate expiration from 16-byte data (Reproduce reported issue)",
			ct:   &expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1e}, // 30s at the end
				},
			},
			pos: 0,
			want: Ct{
				Expiration: 30,
			},
			wantIdx: 2,
		},
		{
			name: "CT expiration 30s as 48-bit (6 byte) register",
			ct:   &expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{0, 0, 0, 0, 0, 30},
				},
			},
			pos:     0,
			want:    Ct{Expiration: 30},
			wantIdx: 2,
		},
		{
			name: "CT expiration 30s as 4 byte Little Endian (should FAIL or be handled if nftables uses it)",
			ct:   &expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
			exprs: []expr.Any{
				&expr.Ct{Key: unix.NFT_CT_EXPIRATION, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{30, 0, 0, 0},
				},
			},
			pos:     0,
			want:    Ct{Expiration: 30},
			wantIdx: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotIdx := ExprCtToCt(tt.ct, tt.exprs, tt.pos, tt.sets)
			if !CtStatesAreEqual(CtStateToStateStrings(got.State), CtStateToStateStrings(tt.want.State)) {
				t.Errorf("ExprCtToCt() got.State = %v, want %v", got.State, tt.want.State)
			}
			if !ctStatusesAreEqual(got.Status, tt.want.Status) {
				t.Errorf("ExprCtToCt() got.Status = %v, want %v", got.Status, tt.want.Status)
			}
			if got.Mark != tt.want.Mark {
				t.Errorf("ExprCtToCt() got.Mark = %v, want %v", got.Mark, tt.want.Mark)
			}
			if got.Expiration != tt.want.Expiration {
				t.Errorf("ExprCtToCt() got.Expiration = %v, want %v", got.Expiration, tt.want.Expiration)
			}
			if got.Direction != tt.want.Direction {
				t.Errorf("ExprCtToCt() got.Direction = %v, want %v", got.Direction, tt.want.Direction)
			}
			if got.Protocol != tt.want.Protocol {
				t.Errorf("ExprCtToCt() got.Protocol = %v, want %v", got.Protocol, tt.want.Protocol)
			}
			if got.Src != tt.want.Src {
				t.Errorf("ExprCtToCt() got.Src = %v, want %v", got.Src, tt.want.Src)
			}
			if got.ProtoSrc != tt.want.ProtoSrc {
				t.Errorf("ExprCtToCt() got.ProtoSrc = %v, want %v", got.ProtoSrc, tt.want.ProtoSrc)
			}
			if gotIdx != tt.wantIdx {
				t.Errorf("ExprCtToCt() gotIdx = %d, want %d", gotIdx, tt.wantIdx)
			}
		})
	}
}
