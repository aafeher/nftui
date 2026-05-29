package nft

import (
	"errors"
	"syscall"
)

// IsPermissionError reports whether err is a netlink permission failure
// (EPERM / EACCES) — i.e. nftui was started without CAP_NET_ADMIN or root,
// so it can't open the netfilter netlink socket. Used to swap the raw
// syscall error for actionable advice in the UI.
func IsPermissionError(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}
