package nft

import "github.com/google/nftables"

func ChainHookNumToString(h nftables.ChainHook) string {
	switch h {
	case *nftables.ChainHookPrerouting:
		return "prerouting"
	case *nftables.ChainHookInput:
		return "input"
	case *nftables.ChainHookForward:
		return "forward"
	case *nftables.ChainHookOutput:
		return "output"
	case *nftables.ChainHookPostrouting:
		return "postrouting"
	case *nftables.ChainHookIngress:
		return "ingress"
	case *nftables.ChainHookEgress:
		return "egress"
	default:
		return "unknown"
	}
}

func ChainPolicyToString(p nftables.ChainPolicy) string {
	switch p {
	case nftables.ChainPolicyDrop:
		return "drop"
	case nftables.ChainPolicyAccept:
		return "accept"
	default:
		return "unknown"
	}
}
