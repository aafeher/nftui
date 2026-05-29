package nft

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
)

func TestIsPermissionError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"EPERM", syscall.EPERM, true},
		{"EACCES", syscall.EACCES, true},
		{"wrapped EPERM", fmt.Errorf("list tables: %w", syscall.EPERM), true},
		{"wrapped EACCES", fmt.Errorf("conn: %w", syscall.EACCES), true},
		{"other errno", syscall.ENOENT, false},
		{"plain error", errors.New("boom"), false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsPermissionError(c.err); got != c.want {
				t.Errorf("IsPermissionError(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}
