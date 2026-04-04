package nft

import (
	"testing"

	"github.com/google/nftables"
)

func TestTableFamilyToString(t *testing.T) {
	tests := []struct {
		family nftables.TableFamily
		want   string
	}{
		{nftables.TableFamilyUnspecified, "unspecified"},
		{nftables.TableFamilyINet, "inet"},
		{nftables.TableFamilyIPv4, "ipv4"},
		{nftables.TableFamilyIPv6, "ipv6"},
		{nftables.TableFamilyARP, "arp"},
		{nftables.TableFamilyNetdev, "netdev"},
		{nftables.TableFamilyBridge, "bridge"},
		{nftables.TableFamily(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := TableFamilyToString(tt.family)
			if got != tt.want {
				t.Errorf("TableFamilyToString(%d) = %q, want %q", tt.family, got, tt.want)
			}
		})
	}
}
