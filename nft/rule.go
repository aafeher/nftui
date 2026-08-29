package nft

import (
	"encoding/binary"
	"fmt"
	"net"
	nftexpr "nftui/nft/expr"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// Rule represents a single rule in the nftables ruleset, containing conditions, actions, metadata, and statistics.
type Rule struct {
	Position uint64
	Handle   uint64

	Conditions []Condition

	Actions []Action

	Counter *CounterStats

	Comment string
}

// Condition represents a logical rule component that defines criteria for filtering or matching operations.
type Condition struct {
	Type      ConditionType
	Negate    bool
	Operation CompareOp

	Meta      *MetaCondition
	Payload   *PayloadCondition
	CT        *CTCondition
	Exthdr    *ExthdrCondition
	SctpChunk *SctpChunkCondition
	SetLookup *SetLookupCondition
	Limit     *expr.Limit
	Connlimit *expr.Connlimit
	Custom    *CustomCondition
}

// SctpChunkCondition represents an `sctp chunk <type> [<field> <value>]`
// match. ChunkType names the chunk (data / init / sack / …). When Field is
// non-empty the match is "sub-field <Field> equals Value"; when empty the
// match is bare presence ("any chunk of this type is in the packet"), set
// from an `Exthdr` carrying `NFT_EXTHDR_F_PRESENT`.
type SctpChunkCondition struct {
	ChunkType nftexpr.ChunkType // resolve name via nftexpr.ChunkTypeName(ChunkType)
	Field     string            // empty for bare presence
	Value     any               // decoded sub-field value when Field != ""
}

// ExthdrCondition represents an IPv6 extension-header match. Proto names
// the extension header (frag / hbh / dst / mh / rt); Field names the
// sub-field; Value is the decoded payload (uint8 / uint16 / uint32).
type ExthdrCondition struct {
	Proto ExthdrProto
	Field string
	Value any
}

// ExthdrProto identifies an IPv6 extension header by its `nft` name.
type ExthdrProto string

const (
	ExthdrProtoHBH  ExthdrProto = "hbh"  // Hop-by-Hop Options (nexthdr=0)
	ExthdrProtoDst  ExthdrProto = "dst"  // Destination Options (nexthdr=60)
	ExthdrProtoFrag ExthdrProto = "frag" // Fragment header (nexthdr=44)
	ExthdrProtoRt   ExthdrProto = "rt"   // Routing header (nexthdr=43)
	ExthdrProtoMh   ExthdrProto = "mh"   // Mobility header (nexthdr=135)
)

// exthdrTypeToProto maps the kernel extension-header protocol number to
// the `nft` short name. Returns "" for unknown types.
func exthdrTypeToProto(t uint8) ExthdrProto {
	switch t {
	case 0:
		return ExthdrProtoHBH
	case 60:
		return ExthdrProtoDst
	case 44:
		return ExthdrProtoFrag
	case 43:
		return ExthdrProtoRt
	case 135:
		return ExthdrProtoMh
	}
	return ""
}

// exthdrProtoToType is the inverse of exthdrTypeToProto.
func exthdrProtoToType(p ExthdrProto) uint8 {
	switch p {
	case ExthdrProtoHBH:
		return 0
	case ExthdrProtoDst:
		return 60
	case ExthdrProtoFrag:
		return 44
	case ExthdrProtoRt:
		return 43
	case ExthdrProtoMh:
		return 135
	}
	return 0
}

// ConditionType represents the type of a condition used to define specific filtering or matching criteria.
type ConditionType string

// ConditionTypeMeta represents a condition type related to metadata processing.
// ConditionTypePayload represents a condition type related to payload processing.
// ConditionTypeCT represents a condition type related to content type processing.
// ConditionTypeSetLookup represents a condition type for set lookup operations.
// ConditionTypeLimit represents a condition type for limiting operations.
// ConditionTypeCustom represents a custom-defined condition type.
const (
	ConditionTypeMeta      ConditionType = "meta"
	ConditionTypePayload   ConditionType = "payload"
	ConditionTypeCT        ConditionType = "ct"
	ConditionTypeExthdr    ConditionType = "exthdr"
	ConditionTypeSctpChunk ConditionType = "sctp_chunk"
	ConditionTypeSetLookup ConditionType = "set_lookup"
	ConditionTypeLimit     ConditionType = "limit"
	ConditionTypeConnlimit ConditionType = "connlimit"
	ConditionTypeCustom    ConditionType = "custom"
)

// CompareOp represents a type for comparison operators used in conditional expressions.
type CompareOp string

// CompareOpEq represents the equality comparison operator "==".
// CompareOpNeq represents the inequality comparison operator "!=".
// CompareOpLt represents the less-than comparison operator "<".
// CompareOpLte represents the less-than-or-equal-to comparison operator "<=".
// CompareOpGt represents the greater-than comparison operator ">".
// CompareOpGte represents the greater-than-or-equal-to comparison operator ">=".
// CompareOpIn represents the inclusion operator "in".
// CompareOpNotIn represents the not-in operator "not in".
const (
	CompareOpEq    CompareOp = "=="
	CompareOpNeq   CompareOp = "!="
	CompareOpLt    CompareOp = "<"
	CompareOpLte   CompareOp = "<="
	CompareOpGt    CompareOp = ">"
	CompareOpGte   CompareOp = ">="
	CompareOpIn    CompareOp = "in"
	CompareOpNotIn CompareOp = "not in"
)

// MetaCondition represents a condition based on metadata with a specific key-value pair.
type MetaCondition struct {
	Key   MetaKey
	Value any
}

// MetaKey represents a string-based identifier used as a key in metadata structures.
type MetaKey string

// MetaKeyIIf represents the input interface ID.
// MetaKeyOIf represents the output interface ID.
// MetaKeyIIfName represents the input interface name.
// MetaKeyOIfName represents the output interface name.
// MetaKeyIIfType represents the input interface type.
// MetaKeyOIfType represents the output interface type.
// MetaKeyProtocol represents the protocol family.
// MetaKeyPriority represents the priority value.
// MetaKeyMark represents the packet marking.
// MetaKeyL4Proto represents the Layer 4 protocol, such as TCP, UDP, or ICMP.
// MetaKeyLength represents the packet length.
// MetaKeyCGroup represents the cgroup associated with the packet.
// MetaKeyPktType represents the type of packet, such as unicast, broadcast, or multicast.
// MetaKeyCPU represents the CPU handling the packet.
// MetaKeyIIfGroup represents the group ID of the input interface.
// MetaKeyOIfGroup represents the group ID of the output interface.
// MetaKeyTime represents the timestamp of the packet.
// MetaKeyDay represents the day-associated metadata of the packet.
// MetaKeyHour represents the hour-associated metadata of the packet.
const (
	MetaKeyIIf       MetaKey = "iif"
	MetaKeyOIf       MetaKey = "oif"
	MetaKeyIIfName   MetaKey = "iifname"
	MetaKeyOIfName   MetaKey = "oifname"
	MetaKeyIIfType   MetaKey = "iiftype"
	MetaKeyOIfType   MetaKey = "oiftype"
	MetaKeyProtocol  MetaKey = "protocol" // protocol family
	MetaKeyPriority  MetaKey = "priority"
	MetaKeyMark      MetaKey = "mark"
	MetaKeyL4Proto   MetaKey = "l4proto" // L4 protocol (tcp, udp, icmp)
	MetaKeyLength    MetaKey = "length"  // packet length
	MetaKeyCGroup    MetaKey = "cgroup"
	MetaKeyPktType   MetaKey = "pkttype" // unicast, broadcast, multicast
	MetaKeyCPU       MetaKey = "cpu"
	MetaKeyIIfGroup  MetaKey = "iifgroup"
	MetaKeyOIfGroup  MetaKey = "oifgroup"
	MetaKeyTime      MetaKey = "time"
	MetaKeyDay       MetaKey = "day"
	MetaKeyHour      MetaKey = "hour"
	MetaKeyNfproto   MetaKey = "nfproto"
	MetaKeySkuid     MetaKey = "skuid"
	MetaKeySkgid     MetaKey = "skgid"
	MetaKeyRtclassid MetaKey = "rtclassid"
)

// PayloadCondition represents a filtering or matching criterion based on protocol, field, and value in payload data.
type PayloadCondition struct {
	Protocol PayloadProtocol
	Field    string
	Value    any
}

// PayloadProtocol represents a specific protocol type used within payload data for networking and filtering operations.
type PayloadProtocol string

// PayloadProtoEther represents the payload protocol for Ethernet.
// PayloadProtoIP represents the payload protocol for IPv4.
// PayloadProtoIP6 represents the payload protocol for IPv6.
// PayloadProtoTCP represents the payload protocol for TCP.
// PayloadProtoUDP represents the payload protocol for UDP.
// PayloadProtoUDPLITE represents the payload protocol for UDP-Lite. It is only
// used for the fields where UDP-Lite genuinely differs from UDP (csumcov); the
// cells the two share keep their UDP/TCP labels.
// PayloadProtoICMP represents the payload protocol for ICMP.
// PayloadProtoICMPv6 represents the payload protocol for ICMPv6.
// PayloadProtoARP represents the payload protocol for ARP.
const (
	PayloadProtoEther   PayloadProtocol = "ether"
	PayloadProtoIP      PayloadProtocol = "ip"
	PayloadProtoIP6     PayloadProtocol = "ip6"
	PayloadProtoTCP     PayloadProtocol = "tcp"
	PayloadProtoUDP     PayloadProtocol = "udp"
	PayloadProtoUDPLITE PayloadProtocol = "udplite"
	PayloadProtoICMP    PayloadProtocol = "icmp"
	PayloadProtoICMPv6  PayloadProtocol = "icmpv6"
	PayloadProtoSCTP    PayloadProtocol = "sctp"
	PayloadProtoDCCP    PayloadProtocol = "dccp"
	PayloadProtoAH      PayloadProtocol = "ah"
	PayloadProtoESP     PayloadProtocol = "esp"
	PayloadProtoCOMP    PayloadProtocol = "comp"
	PayloadProtoVlan    PayloadProtocol = "vlan"
	PayloadProtoARP     PayloadProtocol = "arp"
)

// IPFields represents the structure to hold metadata fields for an IP packet.
// Version specifies the IP version (e.g., 4 or 6).
// Saddr denotes the source IP address.
// Daddr denotes the destination IP address.
// Protocol indicates the protocol type (e.g., TCP, UDP).
// DSCP represents the Differentiated Services Code Point for QoS.
// ECN defines the Explicit Congestion Notification value.
// Length specifies the total length of the IP packet.
// TTL represents the Time-to-Live value for the packet.
type IPFields struct {
	Version  *uint8
	Saddr    *IPAddress // source address
	Daddr    *IPAddress // destination address
	Protocol *uint8
	DSCP     *uint8
	ECN      *uint8
	Length   *uint16
	TTL      *uint8
}

// TCPFields represents the structure for TCP header fields used in packet filtering or manipulation.
type TCPFields struct {
	Sport *PortSpec // source port
	Dport *PortSpec // destination port
	Flags *TCPFlags
	Seq   *uint32
	Ack   *uint32
}

// UDPFields represents the structure for defining specific fields in the UDP protocol header.
// Sport specifies the source port using PortSpec.
// Dport specifies the destination port using PortSpec.
// Length indicates the total length of the UDP packet including the header and data.
type UDPFields struct {
	Sport  *PortSpec
	Dport  *PortSpec
	Length *uint16
}

// ICMPFields represents the fields of an ICMP message, including its type and code.
type ICMPFields struct {
	Type *ICMPType
	Code *uint8
}

// CTCondition represents a condition related to connection tracking in nftables.
// The Key field specifies the specific connection tracking attribute.
// The Value field contains the value associated with the connection tracking attribute.
type CTCondition struct {
	Key       nftexpr.CtKey
	Value     interface{}
	Direction nftexpr.CtDirection
}

// SetLookupCondition specifies a condition to match data within a named set using a specific field.
type SetLookupCondition struct {
	SetName string
	Field   string // which field to look for in the set
}

// CustomCondition represents a user-defined condition with an expression and associated data for custom logic.
type CustomCondition struct {
	Expression string      // the original expression
	Data       interface{} // extra data
}

// Action represents a rule action with a specific type and associated data for different action types.
type Action struct {
	Type ActionType

	// Type-specific fields
	Verdict *VerdictAction
	NAT     *NATAction
	Log     *LogAction
	Counter *CounterAction
	Queue   *QueueAction
	Reject  *RejectAction
	//Limit    *LimitAction
	Set      *SetAction
	Redirect *RedirectAction
	Masq     *MasqueradeAction
	Quota    *QuotaAction
	Objref   *ObjrefAction
	Custom   *CustomAction
}

// ActionType represents a string-based identifier for different types of actions in a networking or firewall system.
type ActionType string

// ActionTypeVerdict represents an action type for verdict processing.
// ActionTypeNAT represents an action type for Network Address Translation (NAT).
// ActionTypeLog represents an action type for logging events or packets.
// ActionTypeCounter represents an action type for counting matched rules or packets.
// ActionTypeQueue represents an action type for queuing packets for user-space processing.
// ActionTypeReject represents an action type for rejecting packets or connections.
// ActionTypeLimit represents an action type for restricting rates or limiting packets.
// ActionTypeSet represents an action type for modifying or setting attributes.
// ActionTypeRedirect represents an action type for redirecting traffic to a specified destination.
// ActionTypeMasq represents an action type for masquerading packets with source address translation.
// ActionTypeCustom represents a custom-defined action type for specific use cases.
const (
	ActionTypeVerdict  ActionType = "verdict"
	ActionTypeNAT      ActionType = "nat"
	ActionTypeLog      ActionType = "log"
	ActionTypeCounter  ActionType = "counter"
	ActionTypeQueue    ActionType = "queue"
	ActionTypeReject   ActionType = "reject"
	ActionTypeLimit    ActionType = "limit"
	ActionTypeSet      ActionType = "set"
	ActionTypeRedirect ActionType = "redirect"
	ActionTypeMasq     ActionType = "masquerade"
	ActionTypeQuota    ActionType = "quota"
	ActionTypeObjref   ActionType = "objref"
	ActionTypeCustom   ActionType = "custom"
)

// QuotaAction represents a `quota [over] <n> bytes` statement. The kernel
// stores the budget in raw bytes (the CLI's `kbytes`/`mbytes` are just
// multipliers); Consumed is the live counter of bytes already accounted
// against the quota (read-only on the wire).
type QuotaAction struct {
	Bytes    uint64
	Over     bool
	Consumed uint64
}

// VerdictAction represents an action with a specific verdict type and an optional target chain for jump/goto actions.
type VerdictAction struct {
	Kind  VerdictKind
	Chain string // target chain for jump/goto
}

// VerdictKind represents the type of verdict action to be taken in a networking or rule-checking context.
type VerdictKind string

// VerdictAccept represents a decision to accept the packet or operation.
// VerdictDrop represents a decision to drop the packet or operation.
// VerdictReject represents a decision to reject the packet or operation with an error or notification.
// VerdictReturn represents a decision to return to the previous context or caller.
// VerdictJump represents a decision to jump to a specified target or rule set.
// VerdictGoto represents a decision to go to a specified destination, bypassing further processing.
// VerdictContinue represents a decision to proceed with the next rule or operation in sequence.
const (
	VerdictAccept   VerdictKind = "accept"
	VerdictDrop     VerdictKind = "drop"
	VerdictReject   VerdictKind = "reject"
	VerdictReturn   VerdictKind = "return"
	VerdictJump     VerdictKind = "jump"
	VerdictGoto     VerdictKind = "goto"
	VerdictContinue VerdictKind = "continue"
)

// NATAction represents a network address translation (NAT) action configuration for packet processing rules.
type NATAction struct {
	Type         NATType
	AddressRange *AddressRange
	PortRange    *PortRange
	Flags        []NATFlag
	Persistent   bool
	Random       bool
	FullyRandom  bool
}

// NATType represents the type of Network Address Translation (NAT), such as SNAT, DNAT, or Masquerade.
type NATType string

// NATTypeSNAT represents the Source Network Address Translation (SNAT) type.
// NATTypeDNAT represents the Destination Network Address Translation (DNAT) type.
// NATTypeMasq represents the Masquerade NAT type.
const (
	NATTypeSNAT NATType = "snat"
	NATTypeDNAT NATType = "dnat"
	NATTypeMasq NATType = "masquerade"
)

// NATFlag represents a string-based flag used to specify NAT behaviors, such as randomization or persistence.
type NATFlag string

// NATFlagRandom represents a NAT behavior configuration for random port allocation.
// NATFlagFullyRandom represents a NAT behavior configuration for fully random port allocation.
// NATFlagPersistent represents a NAT behavior configuration for persistent port allocation.
// NATFlagNetmap represents a NAT behavior configuration for network address and port mapping (netmap).
const (
	NATFlagRandom      NATFlag = "random"
	NATFlagFullyRandom NATFlag = "fully-random"
	NATFlagPersistent  NATFlag = "persistent"
	NATFlagNetmap      NATFlag = "netmap"
)

// LogAction represents a logging action with configurable prefix, level, group, threshold, snap length, and flags.
type LogAction struct {
	Prefix     string
	Level      LogLevel
	Group      uint16
	QThreshold uint16
	Snaplen    uint32
	Flags      []LogFlag
}

// LogLevel represents the severity level of log messages.
type LogLevel string

// LogLevelEmerg represents the highest-priority log level for emergency messages.
// LogLevelAlert represents the log level for alert messages requiring immediate action.
// LogLevelCrit represents the log level for critical messages indicating serious issues.
// LogLevelErr represents the log level for error messages indicating failures.
// LogLevelWarn represents the log level for warning messages about potential issues.
// LogLevelNotice represents the log level for normal messages requiring attention.
// LogLevelInfo represents the log level for informational messages about normal operations.
// LogLevelDebug represents the log level for detailed debug messages used during development.
const (
	LogLevelEmerg  LogLevel = "emerg"
	LogLevelAlert  LogLevel = "alert"
	LogLevelCrit   LogLevel = "crit"
	LogLevelErr    LogLevel = "err"
	LogLevelWarn   LogLevel = "warn"
	LogLevelNotice LogLevel = "notice"
	LogLevelInfo   LogLevel = "info"
	LogLevelDebug  LogLevel = "debug"
)

// LogFlag represents a configurable string identifier used as flags for logging behaviors in the system.
type LogFlag string

// LogFlagTCPSequence represents a log flag for TCP sequence information.
// LogFlagTCPOptions represents a log flag for TCP options information.
// LogFlagIPOptions represents a log flag for IP options information.
// LogFlagUID represents a log flag for user identifier (UID) information.
// LogFlagAll represents a log flag to enable all logging options.
const (
	LogFlagTCPSequence LogFlag = "tcp sequence"
	LogFlagTCPOptions  LogFlag = "tcp options"
	LogFlagIPOptions   LogFlag = "ip options"
	LogFlagUID         LogFlag = "uid"
	LogFlagAll         LogFlag = "all"
)

// CounterAction represents an action for incrementing a counter.
type CounterAction struct {
	Name string
}

// ObjrefAction is a reference from a rule to a named stateful object
// (counter, quota, ct helper, limit, secmark, ...). Kernel-side it's an
// *expr.Objref whose Type carries the object class (NFT_OBJECT_*) and
// Name the identifier.
//
// The render layer turns this into the nft CLI form, e.g.
//
//	Type=1 Name="web_traffic"  → `counter name web_traffic`
//	Type=2 Name="dl_limit"     → `quota name dl_limit`
//	Type=3 Name="ftp_2121"     → `ct helper set "ftp_2121"`
//	default                    → `objref <name>`
type ObjrefAction struct {
	Type int
	Name string
}

// QueueAction represents a queue configuration, including queue number, optional range, and associated flags.
type QueueAction struct {
	Num      uint16
	NumRange *QueueRange
	Flags    []QueueFlag
}

// QueueRange represents a range of queue numbers, with a defined start (`From`) and end (`To`) value.
type QueueRange struct {
	From uint16
	To   uint16
}

// QueueFlag represents a string-based identifier for queue-related flags used to configure specific queue behaviors.
type QueueFlag string

// QueueFlagBypass represents a flag indicating that the queue should bypass certain processing steps.
// QueueFlagFanout represents a flag indicating that the queue should distribute messages to multiple subscribers.
const (
	QueueFlagBypass QueueFlag = "bypass"
	QueueFlagFanout QueueFlag = "fanout"
)

// RejectAction represents an action that rejects a packet with a specified type and ICMPv4/v6 code.
type RejectAction struct {
	Type RejectType
	Code uint8 // ICMPv4/v6 code
}

type RejectType string

// RejectTypeICMP represents the reject type for ICMP protocol messages.
// RejectTypeICMPv6 represents the reject type for ICMPv6 protocol messages.
// RejectTypeTCPReset represents the reject type for TCP reset messages.
// RejectTypeICMPX represents a custom reject type for extended ICMP messages.
const (
	RejectTypeICMP     RejectType = "icmp"
	RejectTypeICMPv6   RejectType = "icmpv6"
	RejectTypeTCPReset RejectType = "tcp reset"
	RejectTypeICMPX    RejectType = "icmpx"
)

// SetAction represents an `add @setname { ... }` / `update @setname { ... }`
// dynamic set update statement (Dynset expression). The kernel encodes
// the operation as a uint32 (NFT_DYNSET_OP_*); we keep the string form
// in Operation so renderers don't import the unix package.
type SetAction struct {
	SetName   string
	Operation string // "add" / "update" / "delete" (NFT_DYNSET_OP_*)
	KeyField  string // resolved from SrcRegKey via regMap (e.g. "ip saddr")
	Timeout   time.Duration
	Invert    bool
}

// RedirectAction represents an action that performs redirection, optionally specifying a range of destination ports.
type RedirectAction struct {
	PortRange *PortRange
}

// MasqueradeAction represents an action for source NAT with optional port range and randomization settings.
type MasqueradeAction struct {
	PortRange   *PortRange
	Random      bool
	FullyRandom bool
	Persistent  bool
}

// CustomAction represents a user-defined action that stores an expression and associated data for custom processing.
type CustomAction struct {
	Expression string
	Data       interface{}
}

// IPAddress represents an IP address and its associated subnet within a network configuration.
type IPAddress struct {
	IP     net.IP
	Subnet *net.IPNet // for CIDR
}

// PortSpec represents a specification for defining port configurations including single, ranged, or set-based ports.
type PortSpec struct {
	Port  uint16
	Range *PortRange
	Set   []uint16
}

// PortRange represents a range of network ports, defined by a starting port (From) and an ending port (To).
type PortRange struct {
	From uint16
	To   uint16
}

// AddressRange represents a range of IP addresses with a starting address (From) and an ending address (To).
type AddressRange struct {
	From net.IP
	To   net.IP
}

// TCPFlags represents a structure for matching TCP packet flags with a mask and value.
type TCPFlags struct {
	Mask  TCPFlagSet
	Value TCPFlagSet
}

// TCPFlagSet represents a set of TCP flags used to indicate specific control parameters in a TCP segment.
type TCPFlagSet struct {
	Fin bool
	Syn bool
	Rst bool
	Psh bool
	Ack bool
	Urg bool
	Ece bool
	Cwr bool
}

// ICMPType represents an ICMP message type with its numerical identifier and a descriptive name.
type ICMPType struct {
	Type uint8
	Name string // "echo-request", "echo-reply", stb.
}

// CounterStats represents statistics for a counter, including the number of packets and bytes.
type CounterStats struct {
	Packets uint64
	Bytes   uint64
}

// RangeValue represents a range with inclusive start and end values, defined by the From and To fields.
type RangeValue struct {
	From interface{}
	To   interface{}
}

// SetValue represents a collection of unique elements that can store values of any type.
type SetValue struct {
	Elements []interface{}
}

// extractValueFromCt inspects an nftexpr.Ct object and returns the first non-zero/non-empty attribute found as an interface{}.
func extractValueFromCt(ct nftexpr.Ct) interface{} {
	if len(ct.State) > 0 {
		return ct.State
	}
	if ct.Direction != "" {
		return ct.Direction
	}
	if len(ct.Status) > 0 {
		return ct.Status
	}
	if ct.Mark != 0 {
		return ct.Mark
	}
	if ct.ExpirationRange != nil {
		return &RangeValue{
			From: ct.ExpirationRange.From,
			To:   ct.ExpirationRange.To,
		}
	}
	if len(ct.ExpirationSet) > 0 {
		var elements []interface{}
		for _, e := range ct.ExpirationSet {
			elements = append(elements, e)
		}
		return &SetValue{
			Elements: elements,
		}
	}
	if ct.Expiration != 0 {
		return ct.Expiration
	}
	if ct.Zone != 0 {
		return ct.Zone
	}
	if ct.ProtoSrc != 0 || ct.ProtoDst != 0 {
		return fmt.Sprintf("%d->%d", ct.ProtoSrc, ct.ProtoDst)
	}
	if ct.Src != "" {
		return ct.Src
	}
	if ct.Dst != "" {
		return ct.Dst
	}
	if ct.Helper != "" {
		return ct.Helper
	}

	return nil
}

// NftablesToRuleDefinition converts an nftables.Rule into a Rule definition, translating expressions into conditions and actions.
func NftablesToRuleDefinition(rule *nftables.Rule) (*Rule, error) {
	rd := &Rule{
		Position:   rule.Position,
		Handle:     rule.Handle,
		Comment:    ExtractComment(rule),
		Conditions: []Condition{},
		Actions:    []Action{},
	}

	// Register tracking - store what is loaded into which register
	regMap := make(map[uint32]*registerValue)

	// Collecting comparisons (AND relation)
	var pendingCompares []*compareContext

	// Current L4 protocol context (latched from `meta l4proto X` matches).
	// Subsequent Payload+Transport-Header expressions inherit this so the
	// parser can name ICMP / SCTP / DCCP / etc. fields correctly.
	var currentL4Proto uint8
	// Current EtherType context (latched from `ether type X` matches).
	// Subsequent Payload+Network-Header expressions inherit this so the
	// parser can name ARP fields correctly.
	var currentEtherType uint16

	i := 0
	for i < len(rule.Exprs) {
		e := rule.Exprs[i]

		switch v := e.(type) {
		case *expr.Ct:
			//fmt.Printf("CT: %v\n", e)
			regMap[v.Register] = &registerValue{
				valueType:   regTypeCT,
				ctKey:       v.Key,
				ctDirection: uint8(v.Direction),
			}
			i++
		case *expr.Range:
			// Range check
			regVal := regMap[v.Register]
			if regVal != nil {
				cond, err := rangeToCondition(regVal, v)
				if err == nil {
					rd.Conditions = append(rd.Conditions, cond)
				}
			}
			i++
		case *expr.Meta:
			regMap[v.Register] = &registerValue{
				valueType: regTypeMeta,
				metaKey:   v.Key,
			}
			i++
		case *expr.Cmp:
			// Comparison - put in pending list
			regVal := regMap[v.Register]
			if regVal == nil {
				regVal = &registerValue{valueType: regTypeUnknown}
			}

			// Latch the l4proto context from `meta l4proto <X>` matches so
			// later Payload expressions can be disambiguated.
			if regVal.valueType == regTypeMeta &&
				regVal.metaKey == unix.NFT_META_L4PROTO &&
				v.Op == expr.CmpOpEq && len(v.Data) >= 1 {
				currentL4Proto = v.Data[0]
			}
			// Latch the EtherType context from `ether type <X>` matches
			// (Payload LL/12/2 + Cmp) so later NETWORK_HEADER Payload
			// expressions can disambiguate ARP (0x0806) from IPv4/IPv6.
			if regVal.valueType == regTypePayload &&
				regVal.payloadBase == unix.NFT_PAYLOAD_LL_HEADER &&
				regVal.payloadOff == 12 && regVal.payloadLen == 2 &&
				v.Op == expr.CmpOpEq && len(v.Data) == 2 {
				currentEtherType = (uint16(v.Data[0]) << 8) | uint16(v.Data[1])
			}

			pendingCompares = append(pendingCompares, &compareContext{
				op:       v.Op,
				data:     v.Data,
				register: regVal,
			})
			i++
		case *expr.Counter:
			rd.Counter = &CounterStats{
				Packets: v.Packets,
				Bytes:   v.Bytes,
			}
			rd.Actions = append(rd.Actions, Action{
				Type:    ActionTypeCounter,
				Counter: &CounterAction{},
			})
			i++
		case *expr.Objref:
			// Reference to a named stateful object (counter / quota /
			// ct helper / limit / secmark / ...). The kernel ships the
			// type code (NFT_OBJECT_*) and the name; we forward both
			// verbatim into an ObjrefAction.
			rd.Actions = append(rd.Actions, Action{
				Type:   ActionTypeObjref,
				Objref: &ObjrefAction{Type: v.Type, Name: v.Name},
			})
			i++
		case *expr.Payload:
			regMap[v.DestRegister] = &registerValue{
				valueType:     regTypePayload,
				payloadBase:   v.Base,
				payloadOff:    v.Offset,
				payloadLen:    v.Len,
				payloadFamily: tableFamilyHint(rule),
				l4Proto:       currentL4Proto,
				etherType:     currentEtherType,
			}
			i++
		case *expr.Exthdr:
			regMap[v.DestRegister] = &registerValue{
				valueType:   regTypeExthdr,
				exthdrOp:    uint32(v.Op),
				exthdrType:  v.Type,
				exthdrOff:   v.Offset,
				exthdrLen:   v.Len,
				exthdrFlags: v.Flags,
			}
			i++
		case *expr.Lookup:
			// Set lookup
			regVal := regMap[v.SourceRegister]
			if regVal != nil {
				cond := lookupToCondition(regVal, v)
				rd.Conditions = append(rd.Conditions, cond)
			}
			i++
		case *expr.Immediate:
			regMap[v.Register] = &registerValue{
				valueType:     regTypeImmediate,
				immediateData: v.Data,
			}
			i++
		case *expr.Bitwise:
			// Bitwise operation - modifies register value. Propagates the
			// upstream payload/meta context (family + l4Proto + etherType)
			// so later Cmp dispatching can still use them.
			if srcVal, ok := regMap[v.SourceRegister]; ok {
				regMap[v.DestRegister] = &registerValue{
					valueType:     srcVal.valueType,
					metaKey:       srcVal.metaKey,
					payloadBase:   srcVal.payloadBase,
					payloadOff:    srcVal.payloadOff,
					payloadLen:    srcVal.payloadLen,
					payloadFamily: srcVal.payloadFamily,
					l4Proto:       srcVal.l4Proto,
					etherType:     srcVal.etherType,
					ctKey:         srcVal.ctKey,
					bitwiseMask:   v.Mask,
					bitwiseXor:    v.Xor,
					hasBitwise:    true,
				}
			}
			i++
		case *expr.Redir:
			action := redirToAction(v, regMap)
			rd.Actions = append(rd.Actions, action)
			i++
		case *expr.NAT:
			action, err := natToAction(v, regMap)
			if err == nil {
				rd.Actions = append(rd.Actions, action)
			}
			i++
		case *expr.Limit:
			cond := limitToCondition(v)
			rd.Conditions = append(rd.Conditions, cond)
			i++
		case *expr.Connlimit:
			rd.Conditions = append(rd.Conditions, Condition{
				Type:      ConditionTypeConnlimit,
				Connlimit: v,
			})
			i++
		case *expr.Quota:
			rd.Actions = append(rd.Actions, quotaToAction(v))
			i++
		case *expr.Dynset:
			action := dynsetToAction(v, regMap)
			rd.Actions = append(rd.Actions, action)
			i++
		case *expr.Log:
			action := logToAction(v)
			rd.Actions = append(rd.Actions, action)
			i++
		case *expr.Queue:
			action := queueToAction(v)
			rd.Actions = append(rd.Actions, action)
			i++
		case *expr.Reject:
			action := rejectToAction(v)
			rd.Actions = append(rd.Actions, action)
			i++
		case *expr.Masq:
			action := masqToAction(v, regMap)
			rd.Actions = append(rd.Actions, action)
			i++
		case *expr.Verdict:
			action := verdictToAction(v)
			rd.Actions = append(rd.Actions, action)
			i++
		default:
			// Unknown expression - stored as custom condition
			rd.Conditions = append(rd.Conditions, Condition{
				Type: ConditionTypeCustom,
				Custom: &CustomCondition{
					Expression: fmt.Sprintf("%T", e),
					Data:       e,
				},
			})
			i++
		}
	}

	// Processing pending comparisons
	for _, cmp := range pendingCompares {
		cond, err := compareToCondition(cmp)
		if err == nil {
			rd.Conditions = append(rd.Conditions, cond)
		}
	}

	return rd, nil
}

// Helper types and structures

// registerValueType defines an enumeration of possible register value types used within the system for type differentiation.
type registerValueType int

// regTypeUnknown represents an unknown register value type.
// regTypeMeta represents a register value type for metadata.
// regTypePayload represents a register value type for payload data.
// regTypeCT represents a register value type for connection tracking data.
// regTypeImmediate represents a register value type for immediate values.
const (
	regTypeUnknown registerValueType = iota
	regTypeMeta
	regTypePayload
	regTypeCT
	regTypeImmediate
	regTypeExthdr
)

// registerValue represents a container holding metadata and context for register-based expressions in rule processing.
type registerValue struct {
	valueType registerValueType

	value any

	// CT
	ctKey       expr.CtKey
	ctDirection uint8

	// Meta
	metaKey expr.MetaKey

	// Payload
	payloadBase   expr.PayloadBase
	payloadOff    uint32
	payloadLen    uint32
	payloadFamily payloadFamilyHint
	// L4 protocol context — populated from the most recent
	// `meta l4proto X` match seen during parsing. Lets identifyPayloadField
	// disambiguate the transport-header layout: ICMP / ICMPv6 / SCTP / DCCP
	// / AH / ESP / COMP / TCP / UDP all share the same Base + Offset cells
	// but expose different fields. 0 = unknown (parser falls back to TCP).
	l4Proto uint8

	// EtherType context — populated from the most recent
	// `ether type X` match (Payload LL/12/2 + Cmp). Lets the NETWORK_HEADER
	// layout switch between IPv4 / IPv6 / ARP, which share offset cells but
	// expose different fields. 0 = unknown.
	etherType uint16

	// Immediate
	immediateData []byte

	// Exthdr — populated when an *expr.Exthdr is loaded into the register.
	// For IPv6 extension headers (Op=0): Type names the extension header
	// protocol (frag=44, hbh=0, dst=60, rt=43, mh=135). For SCTP chunk
	// matches (Op=nftexpr.SctpExthdrOp): Type is the chunk-type number.
	// off+len pin the field within; flags carries NFT_EXTHDR_F_PRESENT for
	// bare-presence matches.
	exthdrOp    uint32
	exthdrType  uint8
	exthdrOff   uint32
	exthdrLen   uint32
	exthdrFlags uint32

	// Bitwise
	hasBitwise  bool
	bitwiseMask []byte
	bitwiseXor  []byte
}

// compareContext represents a context for comparison operations, holding the comparison operator, data, and register reference.
type compareContext struct {
	op       expr.CmpOp
	data     []byte
	register *registerValue
}

// compareToCondition converts a comparison context into a corresponding Condition based on the register's value type.
func compareToCondition(cmp *compareContext) (Condition, error) {
	regVal := cmp.register

	switch regVal.valueType {
	case regTypeMeta:
		return metaCompareToCondition(regVal, cmp)
	case regTypePayload:
		return payloadCompareToCondition(regVal, cmp)
	case regTypeCT:
		return ctCompareToCondition(regVal, cmp)
	case regTypeExthdr:
		// Two distinct match families share regTypeExthdr — IPv6 extension
		// headers (Op=0, NFT_EXTHDR_OP_IPV6) and SCTP chunk matches (Op=3,
		// nftexpr.SctpExthdrOp). Dispatch on Op so the renderer surfaces
		// the right CLI form.
		if regVal.exthdrOp == nftexpr.SctpExthdrOp {
			return sctpChunkCompareToCondition(regVal, cmp)
		}
		return exthdrCompareToCondition(regVal, cmp)
	default:
		return Condition{
			Type: ConditionTypeCustom,
			Custom: &CustomCondition{
				Expression: fmt.Sprintf("compare register unknown type"),
			},
		}, nil
	}
}

// exthdrCompareToCondition converts an IPv6 extension-header comparison
// context into an ExthdrCondition. Decodes the value based on field
// length (1 byte → uint8, 2 → uint16, 4 → uint32).
func exthdrCompareToCondition(regVal *registerValue, cmp *compareContext) (Condition, error) {
	proto := exthdrTypeToProto(regVal.exthdrType)
	field := exthdrFieldName(regVal.exthdrType, regVal.exthdrOff, regVal.exthdrLen)
	value := decodeExthdrValue(regVal.exthdrLen, cmp.data)
	return Condition{
		Type:      ConditionTypeExthdr,
		Operation: cmpOpToCompareOp(cmp.op),
		Exthdr: &ExthdrCondition{
			Proto: proto,
			Field: field,
			Value: value,
		},
	}, nil
}

// sctpChunkCompareToCondition converts an SCTP-chunk comparison context into
// a SctpChunkCondition. Two shapes feed in:
//
//	bare presence:  Exthdr{Op=SCTP, Type=N, Offset=0, Len=0, Flags=F_PRESENT}
//	                Cmp{Op=Eq, Data=[0x01]}  → "sctp chunk <type>"
//	field match:    Exthdr{Op=SCTP, Type=N, Offset=O, Len=L}
//	                Cmp{Op=Eq, Data=<value>} → "sctp chunk <type> <field> <value>"
//
// Unknown (Type, Offset, Len) tuples fall through to the field name being
// rendered as `<offset>+<len>` so the user still sees something useful.
func sctpChunkCompareToCondition(regVal *registerValue, cmp *compareContext) (Condition, error) {
	ct := nftexpr.ChunkType(regVal.exthdrType)
	if regVal.exthdrFlags&nftexpr.SctpExthdrFlagPresent != 0 {
		// Bare presence — Field stays empty; the renderer prints just
		// `sctp chunk <type>`. cmp.data is the F_PRESENT result byte; we
		// don't surface it as a Value.
		return Condition{
			Type:      ConditionTypeSctpChunk,
			Operation: cmpOpToCompareOp(cmp.op),
			SctpChunk: &SctpChunkCondition{ChunkType: ct},
		}, nil
	}
	field, ok := nftexpr.LookupChunkField(ct, regVal.exthdrOff, regVal.exthdrLen)
	fieldName := field.Name
	if !ok {
		fieldName = fmt.Sprintf("@%d+%d", regVal.exthdrOff, regVal.exthdrLen)
	}
	value := decodeExthdrValue(regVal.exthdrLen, cmp.data)
	return Condition{
		Type:      ConditionTypeSctpChunk,
		Operation: cmpOpToCompareOp(cmp.op),
		SctpChunk: &SctpChunkCondition{ChunkType: ct, Field: fieldName, Value: value},
	}, nil
}

// exthdrFieldName resolves (type, offset, length) → field name. The list
// covers everything `nft` itself emits in `nft list`.
func exthdrFieldName(exthdrType uint8, offset, length uint32) string {
	switch exthdrType {
	case 0, 60: // hbh, dst — identical layout
		switch {
		case offset == 0 && length == 1:
			return "nexthdr"
		case offset == 1 && length == 1:
			return "hdrlength"
		}
	case 44: // frag
		switch {
		case offset == 0 && length == 1:
			return "nexthdr"
		case offset == 1 && length == 1:
			return "reserved"
		case offset == 2 && length == 2:
			return "frag-off"
		case offset == 3 && length == 1:
			return "more-fragments"
		case offset == 4 && length == 4:
			return "id"
		}
	case 43: // rt
		switch {
		case offset == 0 && length == 1:
			return "nexthdr"
		case offset == 1 && length == 1:
			return "hdrlength"
		case offset == 2 && length == 1:
			return "type"
		case offset == 3 && length == 1:
			return "seg-left"
		}
	case 135: // mh
		switch {
		case offset == 0 && length == 1:
			return "nexthdr"
		case offset == 1 && length == 1:
			return "hdrlength"
		case offset == 2 && length == 1:
			return "type"
		case offset == 3 && length == 1:
			return "reserved"
		case offset == 4 && length == 2:
			return "checksum"
		}
	}
	return fmt.Sprintf("offset_%d_len_%d", offset, length)
}

// decodeExthdrValue picks uint8 / uint16 / uint32 by data length.
func decodeExthdrValue(length uint32, data []byte) interface{} {
	switch length {
	case 1:
		if len(data) >= 1 {
			return data[0]
		}
	case 2:
		if len(data) >= 2 {
			return binary.BigEndian.Uint16(data)
		}
	case 4:
		if len(data) >= 4 {
			return binary.BigEndian.Uint32(data)
		}
	}
	return data
}

// metaCompareToCondition converts a register value and comparison context into a metadata-based Condition.
func metaCompareToCondition(regVal *registerValue, cmp *compareContext) (Condition, error) {
	metaKey := metaKeyToString(regVal.metaKey)
	value := decodeMetaValue(regVal.metaKey, cmp.data)

	return Condition{
		Type:      ConditionTypeMeta,
		Operation: cmpOpToCompareOp(cmp.op),
		Meta: &MetaCondition{
			Key:   MetaKey(metaKey),
			Value: value,
		},
	}, nil
}

// payloadCompareToCondition converts a payload comparison context into a Condition by interpreting protocol and field info.
func payloadCompareToCondition(regVal *registerValue, cmp *compareContext) (Condition, error) {
	protocol, field := identifyPayloadField(regVal.payloadBase, regVal.payloadOff, regVal.payloadLen, regVal.payloadFamily, regVal.l4Proto, regVal.etherType)

	// Refine bit-packed IPv4 header fields based on the Bitwise mask:
	//   offset 0 len 1, mask 0xf0 → version (high nibble; raw value = data>>4)
	//   offset 0 len 1, mask 0x0f → hdrlength (low nibble; raw value = data)
	//   offset 1 len 1, mask 0xfc → dscp (high 6 bits; raw value = data>>2)
	if regVal.hasBitwise && protocol == PayloadProtoIP &&
		regVal.payloadLen == 1 && len(cmp.data) == 1 && len(regVal.bitwiseMask) == 1 {
		mask := regVal.bitwiseMask[0]
		v := cmp.data[0]
		switch {
		case regVal.payloadOff == 0 && mask == 0xf0:
			return Condition{
				Type: ConditionTypePayload, Operation: cmpOpToCompareOp(cmp.op),
				Payload: &PayloadCondition{Protocol: protocol, Field: "version", Value: uint8(v >> 4)},
			}, nil
		case regVal.payloadOff == 0 && mask == 0x0f:
			return Condition{
				Type: ConditionTypePayload, Operation: cmpOpToCompareOp(cmp.op),
				Payload: &PayloadCondition{Protocol: protocol, Field: "hdrlength", Value: uint8(v & 0x0f)},
			}, nil
		case regVal.payloadOff == 1 && mask == 0xfc:
			return Condition{
				Type: ConditionTypePayload, Operation: cmpOpToCompareOp(cmp.op),
				Payload: &PayloadCondition{Protocol: protocol, Field: "dscp", Value: uint8(v >> 2)},
			}, nil
		}
	}
	// IPv6 version (offset 0 len 1, mask 0xf0; raw value = data>>4).
	if regVal.hasBitwise && protocol == PayloadProtoIP6 &&
		regVal.payloadLen == 1 && len(cmp.data) == 1 && len(regVal.bitwiseMask) == 1 &&
		regVal.payloadOff == 0 && regVal.bitwiseMask[0] == 0xf0 {
		return Condition{
			Type: ConditionTypePayload, Operation: cmpOpToCompareOp(cmp.op),
			Payload: &PayloadCondition{Protocol: protocol, Field: "version", Value: uint8(cmp.data[0] >> 4)},
		}, nil
	}
	// IPv6 dscp: Payload{offset=0, len=2} + Bitwise{mask=[0x0f, 0xc0]} + Cmp.
	// The 6-bit DSCP is split across byte 0 (low nibble) and byte 1 (high 2 bits):
	//   byte 0 = (dscp >> 2) & 0x0f
	//   byte 1 = (dscp & 0x03) << 6
	// Identified by mask shape — works regardless of family hint, since the
	// pattern is unique on the IPv6 header (IPv4 has no [0x0f, 0xc0] Bitwise
	// at offset 0 len 2).
	if regVal.hasBitwise &&
		regVal.payloadBase == unix.NFT_PAYLOAD_NETWORK_HEADER &&
		regVal.payloadOff == 0 && regVal.payloadLen == 2 &&
		len(cmp.data) == 2 && len(regVal.bitwiseMask) == 2 &&
		regVal.bitwiseMask[0] == 0x0f && regVal.bitwiseMask[1] == 0xc0 {
		dscp := uint8(((cmp.data[0] & 0x0f) << 2) | ((cmp.data[1] & 0xc0) >> 6))
		return Condition{
			Type: ConditionTypePayload, Operation: cmpOpToCompareOp(cmp.op),
			Payload: &PayloadCondition{Protocol: PayloadProtoIP6, Field: "dscp", Value: dscp},
		}, nil
	}
	// IPv6 flowlabel: Payload{offset=1, len=3} + Bitwise{mask=[0x0f, 0xff, 0xff]} + Cmp.
	// The 20-bit flow label spans the low 4 bits of byte 1 plus all of bytes 2 and 3:
	//   byte 1 = (fl >> 16) & 0x0f
	//   byte 2 = (fl >> 8) & 0xff
	//   byte 3 = fl & 0xff
	if regVal.hasBitwise &&
		regVal.payloadBase == unix.NFT_PAYLOAD_NETWORK_HEADER &&
		regVal.payloadOff == 1 && regVal.payloadLen == 3 &&
		len(cmp.data) == 3 && len(regVal.bitwiseMask) == 3 &&
		regVal.bitwiseMask[0] == 0x0f && regVal.bitwiseMask[1] == 0xff && regVal.bitwiseMask[2] == 0xff {
		fl := (uint32(cmp.data[0]&0x0f) << 16) | (uint32(cmp.data[1]) << 8) | uint32(cmp.data[2])
		return Condition{
			Type: ConditionTypePayload, Operation: cmpOpToCompareOp(cmp.op),
			Payload: &PayloadCondition{Protocol: PayloadProtoIP6, Field: "flowlabel", Value: fl},
		}, nil
	}
	// TCP doff (transport, offset 12 len 1, mask 0xf0; raw value = data>>4).
	if regVal.hasBitwise && regVal.payloadBase == unix.NFT_PAYLOAD_TRANSPORT_HEADER &&
		regVal.payloadOff == 12 && regVal.payloadLen == 1 &&
		len(cmp.data) == 1 && len(regVal.bitwiseMask) == 1 && regVal.bitwiseMask[0] == 0xf0 {
		return Condition{
			Type: ConditionTypePayload, Operation: cmpOpToCompareOp(cmp.op),
			Payload: &PayloadCondition{Protocol: PayloadProtoTCP, Field: "doff", Value: uint8(cmp.data[0] >> 4)},
		}, nil
	}
	// VLAN id (LL, offset 14 len 2, mask [0x0f, 0xff]) — 12-bit VID.
	if regVal.hasBitwise &&
		regVal.payloadBase == unix.NFT_PAYLOAD_LL_HEADER &&
		regVal.payloadOff == 14 && regVal.payloadLen == 2 &&
		len(cmp.data) == 2 && len(regVal.bitwiseMask) == 2 &&
		regVal.bitwiseMask[0] == 0x0f && regVal.bitwiseMask[1] == 0xff {
		vid := (uint16(cmp.data[0]&0x0f) << 8) | uint16(cmp.data[1])
		return Condition{
			Type: ConditionTypePayload, Operation: cmpOpToCompareOp(cmp.op),
			Payload: &PayloadCondition{Protocol: PayloadProtoVlan, Field: "id", Value: vid},
		}, nil
	}
	// VLAN cfi (LL, offset 14 len 1, mask 0x10) — 1-bit CFI/DEI flag.
	if regVal.hasBitwise &&
		regVal.payloadBase == unix.NFT_PAYLOAD_LL_HEADER &&
		regVal.payloadOff == 14 && regVal.payloadLen == 1 &&
		len(cmp.data) == 1 && len(regVal.bitwiseMask) == 1 && regVal.bitwiseMask[0] == 0x10 {
		return Condition{
			Type: ConditionTypePayload, Operation: cmpOpToCompareOp(cmp.op),
			Payload: &PayloadCondition{Protocol: PayloadProtoVlan, Field: "cfi", Value: uint8((cmp.data[0] & 0x10) >> 4)},
		}, nil
	}
	// VLAN pcp (LL, offset 14 len 1, mask 0xe0) — 3-bit Priority Code Point.
	if regVal.hasBitwise &&
		regVal.payloadBase == unix.NFT_PAYLOAD_LL_HEADER &&
		regVal.payloadOff == 14 && regVal.payloadLen == 1 &&
		len(cmp.data) == 1 && len(regVal.bitwiseMask) == 1 && regVal.bitwiseMask[0] == 0xe0 {
		return Condition{
			Type: ConditionTypePayload, Operation: cmpOpToCompareOp(cmp.op),
			Payload: &PayloadCondition{Protocol: PayloadProtoVlan, Field: "pcp", Value: uint8((cmp.data[0] & 0xe0) >> 5)},
		}, nil
	}
	// DCCP type (transport, offset 8 len 1, mask 0x1e; raw value = data>>1).
	// l4proto context lets us disambiguate from any future bit-1..4
	// matches in other transports.
	if regVal.hasBitwise && regVal.l4Proto == unix.IPPROTO_DCCP &&
		regVal.payloadBase == unix.NFT_PAYLOAD_TRANSPORT_HEADER &&
		regVal.payloadOff == 8 && regVal.payloadLen == 1 &&
		len(cmp.data) == 1 && len(regVal.bitwiseMask) == 1 && regVal.bitwiseMask[0] == 0x1e {
		return Condition{
			Type: ConditionTypePayload, Operation: cmpOpToCompareOp(cmp.op),
			Payload: &PayloadCondition{Protocol: PayloadProtoDCCP, Field: "type", Value: uint8((cmp.data[0] & 0x1e) >> 1)},
		}, nil
	}

	var value interface{}
	if regVal.hasBitwise && (field == "saddr" || field == "daddr") &&
		len(cmp.data) > 0 && len(regVal.bitwiseMask) == len(cmp.data) {
		// CIDR match: Payload{4} → Bitwise{mask} → Cmp{network_addr}
		ip := net.IP(append([]byte{}, cmp.data...))
		mask := net.IPMask(append([]byte{}, regVal.bitwiseMask...))
		value = &IPAddress{IP: ip, Subnet: &net.IPNet{IP: ip, Mask: mask}}
	} else if !regVal.hasBitwise && (field == "saddr" || field == "daddr") &&
		regVal.payloadLen >= 1 && regVal.payloadLen <= 3 &&
		len(cmp.data) == int(regVal.payloadLen) {
		// Byte-aligned prefix: Payload{1-3} → Cmp (no Bitwise)
		// e.g. /24 uses Payload{len=3} + Cmp{[192,168,1]}
		padded := make([]byte, 4)
		copy(padded, cmp.data)
		maskLen := int(regVal.payloadLen) * 8
		mask := net.CIDRMask(maskLen, 32)
		ip := net.IP(padded)
		value = &IPAddress{IP: ip, Subnet: &net.IPNet{IP: ip, Mask: mask}}
	} else {
		value = decodePayloadValue(protocol, field, cmp.data)
	}

	return Condition{
		Type:      ConditionTypePayload,
		Operation: cmpOpToCompareOp(cmp.op),
		Payload: &PayloadCondition{
			Protocol: protocol,
			Field:    field,
			Value:    value,
		},
	}, nil
}

// ctCompareToCondition converts a registerValue and compareContext into a CTCondition-based Condition or returns an error.
func ctCompareToCondition(regVal *registerValue, cmp *compareContext) (Condition, error) {
	ctKey := nftexpr.CtKeyToString(regVal.ctKey)

	// The kernel can encode bitmask CT conditions (STATE, STATUS) in two ways:
	//   Pattern A: Bitwise{mask=X} + Cmp{Eq, data=X}   — data equals mask
	//   Pattern B: Bitwise{mask=X} + Cmp{Neq, zeros}   — data is all zeros
	// Pattern B means "AND result != 0" which semantically is "bit is set" → normalize to Eq
	// using the Bitwise mask as data.
	// The kernel uses Pattern B for STATUS always, and also for STATE when the result
	// of the Bitwise AND with a single bit is checked (e.g. ct state invalid).
	data := cmp.data
	op := cmp.op
	if regVal.hasBitwise && op == expr.CmpOpNeq {
		allZeros := true
		for _, b := range cmp.data {
			if b != 0 {
				allZeros = false
				break
			}
		}
		if allZeros {
			data = regVal.bitwiseMask
			op = expr.CmpOpEq
		}
	}

	value := nftexpr.DecodeCTValue(regVal.ctKey, data)

	direction := nftexpr.CtDirectionNone
	if regVal.ctKey == expr.CtKeyBYTES || regVal.ctKey == expr.CtKeyPKTS || regVal.ctKey == expr.CtKeyAVGPKT ||
		regVal.ctKey == expr.CtKeyPROTOSRC || regVal.ctKey == expr.CtKeyPROTODST {
		if regVal.ctDirection == 0 {
			direction = nftexpr.CtDirectionOriginal
		} else if regVal.ctDirection == 1 {
			direction = nftexpr.CtDirectionReply
		}
	}

	return Condition{
		Type:      ConditionTypeCT,
		Operation: cmpOpToCompareOp(op),
		CT: &CTCondition{
			Key:       nftexpr.CtKey(ctKey),
			Value:     value,
			Direction: direction,
		},
	}, nil
}

// rangeToCondition converts a registerValue and Range expression into a Condition if the value type is supported.
func rangeToCondition(regVal *registerValue, rng *expr.Range) (Condition, error) {
	switch regVal.valueType {
	case regTypePayload:
		protocol, field := identifyPayloadField(regVal.payloadBase, regVal.payloadOff, regVal.payloadLen, regVal.payloadFamily, regVal.l4Proto, regVal.etherType)
		fromVal := decodePayloadValue(protocol, field, rng.FromData)
		toVal := decodePayloadValue(protocol, field, rng.ToData)

		return Condition{
			Type:      ConditionTypePayload,
			Operation: CompareOpIn,
			Payload: &PayloadCondition{
				Protocol: protocol,
				Field:    field,
				Value: &RangeValue{
					From: fromVal,
					To:   toVal,
				},
			},
		}, nil
	case regTypeCT:
		fromVal := nftexpr.DecodeCTValue(regVal.ctKey, rng.FromData)
		toVal := nftexpr.DecodeCTValue(regVal.ctKey, rng.ToData)

		return Condition{
			Type:      ConditionTypeCT,
			Operation: cmpOpToCompareOp(rng.Op),
			CT: &CTCondition{
				Key: nftexpr.CtKey(nftexpr.CtKeyToString(regVal.ctKey)),
				Value: &RangeValue{
					From: fromVal,
					To:   toVal,
				},
			},
		}, nil
	default:
		return Condition{}, fmt.Errorf("unsupported range type")
	}
}

// regValueFieldLabel resolves the human-readable field-name for the value
// currently held in a register. The form matches what `nft list` produces:
//
//	payload (ip saddr / ip6 daddr / tcp dport / arp htype / ...) → "<proto> <field>"
//	meta (mark / iif / oif / ...)                                → "<key>"   (no proto)
//	ct  (state / mark / ...)                                     → "<key>"   (no proto)
//
// Returns an empty string for unset / unsupported registers.
func regValueFieldLabel(regVal *registerValue) string {
	if regVal == nil {
		return ""
	}
	switch regVal.valueType {
	case regTypeMeta:
		return metaKeyToString(regVal.metaKey)
	case regTypePayload:
		proto, field := identifyPayloadField(
			regVal.payloadBase, regVal.payloadOff, regVal.payloadLen,
			regVal.payloadFamily, regVal.l4Proto, regVal.etherType)
		switch {
		case field == "":
			return ""
		case proto == "":
			return field
		default:
			return string(proto) + " " + field
		}
	case regTypeCT:
		return nftexpr.CtKeyToString(regVal.ctKey)
	}
	return ""
}

// lookupToCondition converts a registerValue and a Lookup expression into a Condition for set lookup operations.
func lookupToCondition(regVal *registerValue, lookup *expr.Lookup) Condition {
	field := regValueFieldLabel(regVal)

	return Condition{
		Type:   ConditionTypeSetLookup,
		Negate: lookup.Invert,
		SetLookup: &SetLookupCondition{
			SetName: lookup.SetName,
			Field:   field,
		},
	}
}

// limitToCondition converts a Limit expression into a Condition with a type of ConditionTypeLimit.
func limitToCondition(limit *expr.Limit) Condition {
	return Condition{
		Type:  ConditionTypeLimit,
		Limit: limit,
	}
}

// verdictToAction converts a Verdict expression into an Action object with the corresponding verdict type and optional chain.
func verdictToAction(v *expr.Verdict) Action {
	kind := VerdictDrop

	switch v.Kind {
	case expr.VerdictAccept:
		kind = VerdictAccept
	case expr.VerdictDrop:
		kind = VerdictDrop
	case expr.VerdictReturn:
		kind = VerdictReturn
	case expr.VerdictJump:
		kind = VerdictJump
	case expr.VerdictGoto:
		kind = VerdictGoto
	}

	return Action{
		Type: ActionTypeVerdict,
		Verdict: &VerdictAction{
			Kind:  kind,
			Chain: v.Chain,
		},
	}
}

// logToAction converts a Log expression to an Action object with type ActionTypeLog and associated LogAction data.
//
// Level is only honoured when the kernel actually emitted NFTA_LOG_LEVEL (tracked
// via the unmarshal-populated l.Key bitmask). Otherwise we report the syslog
// default of "warn" — without this guard the zero value of expr.LogLevel
// (== LogLevelEmerg) would be misreported on rules that never set a level,
// and re-serialising them would emit a bogus LEVEL attribute that is invalid
// in NFLOG mode and gets rejected with EINVAL by the kernel.
func logToAction(l *expr.Log) Action {
	prefix := string(l.Data)
	if len(prefix) > 0 && prefix[len(prefix)-1] == 0 {
		prefix = prefix[:len(prefix)-1]
	}

	level := LogLevelWarn
	if l.Key&(1<<unix.NFTA_LOG_LEVEL) != 0 {
		level = syslogLevelToLogLevel(l.Level)
	}

	return Action{
		Type: ActionTypeLog,
		Log: &LogAction{
			Prefix:     prefix,
			Level:      level,
			Group:      l.Group,
			QThreshold: l.QThreshold,
			Snaplen:    l.Snaplen,
		},
	}
}

// natToAction converts a NAT expression and register map to an Action object, decoding address/port ranges and NAT flags.
func natToAction(n *expr.NAT, regMap map[uint32]*registerValue) (Action, error) {
	natType := NATTypeSNAT
	if n.Type == expr.NATTypeDestNAT {
		natType = NATTypeDNAT
	}

	var addrRange *AddressRange
	var portRange *PortRange

	// Decode address range
	if n.RegAddrMin != 0 {
		if minReg, ok := regMap[n.RegAddrMin]; ok && minReg.immediateData != nil {
			fromIP := net.IP(minReg.immediateData)
			toIP := fromIP

			if n.RegAddrMax != 0 {
				if maxReg, ok := regMap[n.RegAddrMax]; ok && maxReg.immediateData != nil {
					toIP = net.IP(maxReg.immediateData)
				}
			}

			addrRange = &AddressRange{
				From: fromIP,
				To:   toIP,
			}
		}
	}

	// Decode port range
	if n.RegProtoMin != 0 {
		if minReg, ok := regMap[n.RegProtoMin]; ok && minReg.immediateData != nil {
			fromPort := binary.BigEndian.Uint16(minReg.immediateData)
			toPort := fromPort

			if n.RegProtoMax != 0 {
				if maxReg, ok := regMap[n.RegProtoMax]; ok && maxReg.immediateData != nil {
					toPort = binary.BigEndian.Uint16(maxReg.immediateData)
				}
			}

			portRange = &PortRange{
				From: fromPort,
				To:   toPort,
			}
		}
	}

	flags := []NATFlag{}
	if n.Random {
		flags = append(flags, NATFlagRandom)
	}
	if n.FullyRandom {
		flags = append(flags, NATFlagFullyRandom)
	}
	if n.Persistent {
		flags = append(flags, NATFlagPersistent)
	}

	return Action{
		Type: ActionTypeNAT,
		NAT: &NATAction{
			Type:         natType,
			AddressRange: addrRange,
			PortRange:    portRange,
			Flags:        flags,
		},
	}, nil
}

// masqToAction converts a Masq expression and associated register mappings into a Masquerade action with port range settings.
// It handles port ranges defined by register values, randomization options, and fully random masquerading.
func masqToAction(m *expr.Masq, regMap map[uint32]*registerValue) Action {
	var portRange *PortRange

	if m.RegProtoMin != 0 {
		if minReg, ok := regMap[m.RegProtoMin]; ok && minReg.immediateData != nil {
			fromPort := binary.BigEndian.Uint16(minReg.immediateData)
			toPort := fromPort

			if m.RegProtoMax != 0 {
				if maxReg, ok := regMap[m.RegProtoMax]; ok && maxReg.immediateData != nil {
					toPort = binary.BigEndian.Uint16(maxReg.immediateData)
				}
			}

			portRange = &PortRange{
				From: fromPort,
				To:   toPort,
			}
		}
	}

	return Action{
		Type: ActionTypeMasq,
		Masq: &MasqueradeAction{
			PortRange:   portRange,
			Random:      m.Random,
			FullyRandom: m.FullyRandom,
			Persistent:  m.Persistent,
		},
	}
}

// redirToAction converts a Redir expression and a register map into a Redirect Action, extracting port range if available.
func redirToAction(r *expr.Redir, regMap map[uint32]*registerValue) Action {
	var portRange *PortRange

	if r.RegisterProtoMin != 0 {
		if minReg, ok := regMap[r.RegisterProtoMin]; ok && minReg.immediateData != nil {
			fromPort := binary.BigEndian.Uint16(minReg.immediateData)
			toPort := fromPort

			if r.RegisterProtoMax != 0 {
				if maxReg, ok := regMap[r.RegisterProtoMax]; ok && maxReg.immediateData != nil {
					toPort = binary.BigEndian.Uint16(maxReg.immediateData)
				}
			}

			portRange = &PortRange{
				From: fromPort,
				To:   toPort,
			}
		}
	}

	return Action{
		Type: ActionTypeRedirect,
		Redirect: &RedirectAction{
			PortRange: portRange,
		},
	}
}

// rejectToAction converts an expr.Reject expression into an Action with type reject and appropriate RejectAction configuration.
func rejectToAction(r *expr.Reject) Action {
	rejectType := RejectTypeICMP

	switch r.Type {
	case unix.NFT_REJECT_ICMP_UNREACH:
		rejectType = RejectTypeICMP
	case unix.NFT_REJECT_TCP_RST:
		rejectType = RejectTypeTCPReset
	case unix.NFT_REJECT_ICMPX_UNREACH:
		rejectType = RejectTypeICMPX
	}

	return Action{
		Type: ActionTypeReject,
		Reject: &RejectAction{
			Type: rejectType,
			Code: r.Code,
		},
	}
}

// queueToAction converts a *expr.Queue into an Action of type ActionTypeQueue with queue-specific properties and flags.
// quotaToAction converts a *expr.Quota into an Action of type ActionTypeQuota.
// The kernel always stores the budget in raw bytes; the unit selection
// (bytes/kbytes/mbytes) is a CLI concern, surfaced again by the field
// editor at display time.
func quotaToAction(q *expr.Quota) Action {
	return Action{
		Type: ActionTypeQuota,
		Quota: &QuotaAction{
			Bytes:    q.Bytes,
			Over:     q.Over,
			Consumed: q.Consumed,
		},
	}
}

func queueToAction(q *expr.Queue) Action {
	var queueRange *QueueRange
	if q.Num != q.Total-1 {
		queueRange = &QueueRange{
			From: q.Num,
			To:   q.Num + q.Total - 1,
		}
	}

	flags := []QueueFlag{}
	if q.Flag&unix.NFT_QUEUE_FLAG_BYPASS != 0 {
		flags = append(flags, QueueFlagBypass)
	}
	if q.Flag&unix.NFT_QUEUE_FLAG_CPU_FANOUT != 0 {
		flags = append(flags, QueueFlagFanout)
	}

	return Action{
		Type: ActionTypeQueue,
		Queue: &QueueAction{
			Num:      q.Num,
			NumRange: queueRange,
			Flags:    flags,
		},
	}
}

// dynsetToAction converts a Dynset expression into a SetAction.
//
// The kernel side uses register-based plumbing: SrcRegKey points at the
// register that holds the element key (typically a Payload or Meta load
// emitted earlier in the rule). We resolve that register via the same
// regMap the lookup/cmp paths use, so the rendered form ends up like
//
//	add @blocklist { ip saddr timeout 1h }
//
// instead of just `set: blocklist`. SrcRegData (map value) is not yet
// surfaced; first pass focuses on the plain-set case.
func dynsetToAction(d *expr.Dynset, regMap map[uint32]*registerValue) Action {
	keyField := ""
	if regVal, ok := regMap[d.SrcRegKey]; ok {
		keyField = regValueFieldLabel(regVal)
	}

	return Action{
		Type: ActionTypeSet,
		Set: &SetAction{
			SetName:   d.SetName,
			Operation: dynsetOpToString(d.Operation),
			KeyField:  keyField,
			Timeout:   d.Timeout,
			Invert:    d.Invert,
		},
	}
}

// formatDynsetSimple renders a *expr.Dynset for the RuleToHumanReadable
// one-liner. keyField is the already-resolved field name (e.g. "ip saddr")
// pulled from the local string-typed regMap — that path doesn't track
// the richer registerValue context the parser does.
func formatDynsetSimple(d *expr.Dynset, keyField string) string {
	var inner []string
	if keyField != "" {
		inner = append(inner, keyField)
	}
	if d.Invert {
		inner = append(inner, "!=")
	}
	if d.Timeout > 0 {
		inner = append(inner, "timeout "+d.Timeout.String())
	}
	body := ""
	if len(inner) > 0 {
		body = " { " + strings.Join(inner, " ") + " }"
	}
	return dynsetOpToString(d.Operation) + " @" + d.SetName + body
}

// dynsetOpToString maps the kernel's uint32 op code (NFT_DYNSET_OP_*) to
// the nft CLI keyword. unix only exports ADD/UPDATE in older releases —
// 2 (DELETE) is a stable kernel value, hard-coded.
func dynsetOpToString(op uint32) string {
	switch op {
	case uint32(unix.NFT_DYNSET_OP_ADD):
		return "add"
	case uint32(unix.NFT_DYNSET_OP_UPDATE):
		return "update"
	case 2:
		return "delete"
	}
	return "add"
}

// tableFamilyHint derives the payloadFamilyHint from the rule's parent
// table family. Safe for rules with no Table set (test fixtures): returns
// payloadFamilyAny, which yields the IPv4 layout — consistent with the
// dominant case.
func tableFamilyHint(rule *nftables.Rule) payloadFamilyHint {
	if rule == nil || rule.Table == nil {
		return payloadFamilyAny
	}
	switch rule.Table.Family {
	case nftables.TableFamilyIPv6:
		return payloadFamilyIPv6
	case nftables.TableFamilyIPv4:
		return payloadFamilyIPv4
	}
	return payloadFamilyAny
}

// payloadFamilyHint conveys the chain-family context to identifyPayloadField
// so it can resolve the offset/length conflict between IPv4 and IPv6 header
// fields (e.g. offset 4 len 2 = IPv4 id OR IPv6 payload length).
type payloadFamilyHint int

const (
	payloadFamilyAny  payloadFamilyHint = iota // ambiguous — pick IPv4 by default
	payloadFamilyIPv4                          // hint: this rule lives in an IPv4 (or inet w/ IPv4 ctx) chain
	payloadFamilyIPv6                          // hint: this rule lives in an IPv6 (or inet w/ IPv6 ctx) chain
)

// identifyPayloadField determines the protocol and field name based on payload base, offset, and length values.
//
// IPv4 fixed-header layout (when length matches the byte-aligned size of a
// header field, we name it directly; otherwise we fall through to the generic
// "offset_X_len_Y" form so the user still sees the condition):
//
//	offset 0 len 1  → byte holding version (high nibble) + hdrlength (low)
//	offset 1 len 1  → DSCP (bits 7..2) + ECN (bits 1..0)
//	offset 2 len 2  → total length (uint16 BE)
//	offset 4 len 2  → id (uint16 BE)
//	offset 6 len 2  → flags + fragment offset
//	offset 8 len 1  → TTL
//	offset 9 len 1  → protocol
//	offset 10 len 2 → checksum
//	offset 12 len 4 → saddr (with /24 etc. byte-aligned shorts: len 1..4)
//	offset 16 len 4 → daddr
//
// IPv6 fixed-header layout:
//
//	offset 0..3       → version + traffic class + flow label (bit-packed)
//	offset 4 len 2    → payload length
//	offset 6 len 1    → next header
//	offset 7 len 1    → hop limit
//	offset 8 len 16   → saddr
//	offset 24 len 16  → daddr
//
// The TUI uses the same Base (PayloadBaseNetworkHeader) for IPv4 and IPv6 —
// the protocol family is determined by the chain/table family, not by the
// raw expression. Here we disambiguate on offset+length boundaries that are
// unambiguous between the two layouts.
func identifyPayloadField(base expr.PayloadBase, offset, length uint32, family payloadFamilyHint, l4Proto uint8, etherType uint16) (PayloadProtocol, string) {
	switch base {
	case unix.NFT_PAYLOAD_NETWORK_HEADER:
		// ARP — NETWORK_HEADER reading layered under `ether type 0x0806`.
		// RFC 826: htype 0..2, ptype 2..4, hlen 4..5, plen 5..6,
		// operation 6..8.
		if etherType == 0x0806 {
			switch {
			case offset == 0 && length == 2:
				return PayloadProtoARP, "htype"
			case offset == 2 && length == 2:
				return PayloadProtoARP, "ptype"
			case offset == 4 && length == 1:
				return PayloadProtoARP, "hlen"
			case offset == 5 && length == 1:
				return PayloadProtoARP, "plen"
			case offset == 6 && length == 2:
				return PayloadProtoARP, "operation"
			}
		}
		// Unmistakably-IPv6 offsets (len 16 saddr/daddr, ip6 nexthdr/hoplimit).
		switch {
		case offset == 8 && length == 16:
			return PayloadProtoIP6, "saddr"
		case offset == 24 && length == 16:
			return PayloadProtoIP6, "daddr"
		case offset == 6 && length == 1:
			return PayloadProtoIP6, "nexthdr"
		case offset == 7 && length == 1:
			return PayloadProtoIP6, "hoplimit"
		}
		// Ambiguous IPv4/IPv6 cells — only pick IPv6 when the rule's family
		// hint says so. Otherwise fall through to the IPv4 layout.
		if family == payloadFamilyIPv6 {
			switch {
			case offset == 4 && length == 2:
				return PayloadProtoIP6, "length"
			}
		}
		// IPv4 layout.
		switch {
		case offset == 0 && length == 1:
			return PayloadProtoIP, "version_ihl"
		case offset == 1 && length == 1:
			return PayloadProtoIP, "dscp_ecn"
		case offset == 2 && length == 2:
			return PayloadProtoIP, "length"
		case offset == 4 && length == 2:
			return PayloadProtoIP, "id"
		case offset == 6 && length == 2:
			return PayloadProtoIP, "frag-off"
		case offset == 8 && length == 1:
			return PayloadProtoIP, "ttl"
		case offset == 9 && length == 1:
			return PayloadProtoIP, "protocol"
		case offset == 10 && length == 2:
			return PayloadProtoIP, "checksum"
		case offset == 12 && length >= 1 && length <= 4:
			return PayloadProtoIP, "saddr"
		case offset == 16 && length >= 1 && length <= 4:
			return PayloadProtoIP, "daddr"
		}
		return PayloadProtoIP, fmt.Sprintf("offset_%d_len_%d", offset, length)

	case unix.NFT_PAYLOAD_TRANSPORT_HEADER:
		// Protocol-specific layouts first. We dispatch on the l4Proto hint
		// (populated from the most recent `meta l4proto X` match) so the
		// same offset cells can mean different things across protocols.
		switch l4Proto {
		case unix.IPPROTO_ICMP:
			switch {
			case offset == 0 && length == 1:
				return PayloadProtoICMP, "type"
			case offset == 1 && length == 1:
				return PayloadProtoICMP, "code"
			case offset == 2 && length == 2:
				return PayloadProtoICMP, "checksum"
			case offset == 4 && length == 2:
				return PayloadProtoICMP, "id"
			case offset == 6 && length == 2:
				return PayloadProtoICMP, "sequence"
			case offset == 4 && length == 4:
				return PayloadProtoICMP, "gateway" // dest-unreach uses bytes 4..7 as gateway / mtu
			}
		case unix.IPPROTO_ICMPV6:
			// ICMPv6 fixed header layout matches ICMP byte-for-byte; see RFC 4443.
			switch {
			case offset == 0 && length == 1:
				return PayloadProtoICMPv6, "type"
			case offset == 1 && length == 1:
				return PayloadProtoICMPv6, "code"
			case offset == 2 && length == 2:
				return PayloadProtoICMPv6, "checksum"
			case offset == 4 && length == 2:
				return PayloadProtoICMPv6, "id"
			case offset == 6 && length == 2:
				return PayloadProtoICMPv6, "sequence"
			case offset == 4 && length == 4:
				return PayloadProtoICMPv6, "mtu" // packet-too-big uses bytes 4..7 as MTU
			}
		case unix.IPPROTO_SCTP:
			// SCTP fixed header (RFC 4960): sport 0..2, dport 2..4,
			// verification tag 4..8, checksum 8..12.
			switch {
			case offset == 0 && length == 2:
				return PayloadProtoSCTP, "sport"
			case offset == 2 && length == 2:
				return PayloadProtoSCTP, "dport"
			case offset == 4 && length == 4:
				return PayloadProtoSCTP, "vtag"
			case offset == 8 && length == 4:
				return PayloadProtoSCTP, "checksum"
			}
		case unix.IPPROTO_DCCP:
			// DCCP fixed header (RFC 4340): sport 0..2, dport 2..4,
			// type is 4 bits at byte 8 (bits 1..4 → mask 0x1e, shift 1);
			// the type recognizer lives in payloadCompareToCondition's
			// Bitwise dispatch since it needs the mask byte to confirm.
			switch {
			case offset == 0 && length == 2:
				return PayloadProtoDCCP, "sport"
			case offset == 2 && length == 2:
				return PayloadProtoDCCP, "dport"
			}
		case unix.IPPROTO_AH:
			// AH header (RFC 4302): nexthdr 0..1, hdrlength 1..2,
			// reserved 2..4, spi 4..8, sequence 8..12.
			switch {
			case offset == 0 && length == 1:
				return PayloadProtoAH, "nexthdr"
			case offset == 1 && length == 1:
				return PayloadProtoAH, "hdrlength"
			case offset == 2 && length == 2:
				return PayloadProtoAH, "reserved"
			case offset == 4 && length == 4:
				return PayloadProtoAH, "spi"
			case offset == 8 && length == 4:
				return PayloadProtoAH, "sequence"
			}
		case unix.IPPROTO_ESP:
			// ESP header (RFC 4303): spi 0..4, sequence 4..8.
			switch {
			case offset == 0 && length == 4:
				return PayloadProtoESP, "spi"
			case offset == 4 && length == 4:
				return PayloadProtoESP, "sequence"
			}
		case unix.IPPROTO_UDPLITE:
			// UDP-Lite (RFC 3828) reuses the UDP header layout, except that
			// UDP's `length` cell carries the checksum coverage instead.
			// `nft` names it `csumcov` and rejects `udplite length` outright,
			// so this is a different field, not another spelling of the same
			// one — hence the dedicated arm.
			//
			// Deliberately only offset 4: sport / dport / checksum mean the
			// same thing in both protocols and `nft` accepts either spelling,
			// so they fall through to the shared TCP/UDP labels below. That
			// convention is the one examples/example-nftables-01.conf's
			// section 25 documents ("wire = udp dport", "wire = udp checksum").
			if offset == 4 && length == 2 {
				return PayloadProtoUDPLITE, "csumcov"
			}
		case unix.IPPROTO_COMP:
			// IPComp header (RFC 3173): nexthdr 0..1, flags 1..2, cpi 2..4.
			switch {
			case offset == 0 && length == 1:
				return PayloadProtoCOMP, "nexthdr"
			case offset == 1 && length == 1:
				return PayloadProtoCOMP, "flags"
			case offset == 2 && length == 2:
				return PayloadProtoCOMP, "cpi"
			}
		}

		// TCP, UDP and UDPLITE share the first 4 bytes (sport, dport).
		// Beyond that the layouts diverge — we can disambiguate on
		// offset+length cells, except for sport/dport which we always tag
		// as TCP by convention (the meta l4proto context tells the user
		// whether it is actually udp/udplite).
		switch {
		case offset == 0 && length == 2:
			return PayloadProtoTCP, "sport"
		case offset == 2 && length == 2:
			return PayloadProtoTCP, "dport"

		// UDP / UDPLITE: length & checksum live in TCP-unused cells.
		case offset == 4 && length == 2:
			return PayloadProtoUDP, "length"
		case offset == 6 && length == 2:
			return PayloadProtoUDP, "checksum"

		// TCP-specific cells.
		case offset == 4 && length == 4:
			return PayloadProtoTCP, "sequence"
		case offset == 8 && length == 4:
			return PayloadProtoTCP, "ackseq"
		case offset == 12 && length == 1:
			return PayloadProtoTCP, "doff" // bit-packed (high 4 bits)
		case offset == 13 && length == 1:
			return PayloadProtoTCP, "flags"
		case offset == 14 && length == 2:
			return PayloadProtoTCP, "window"
		case offset == 16 && length == 2:
			return PayloadProtoTCP, "checksum"
		case offset == 18 && length == 2:
			return PayloadProtoTCP, "urgptr"
		}
		return PayloadProtoTCP, fmt.Sprintf("offset_%d_len_%d", offset, length)

	case unix.NFT_PAYLOAD_LL_HEADER:
		// Ethernet link-layer header: dst-mac 0..6, src-mac 6..12, ethertype 12..14.
		switch {
		case offset == 0 && length == 6:
			return PayloadProtoEther, "daddr"
		case offset == 6 && length == 6:
			return PayloadProtoEther, "saddr"
		case offset == 12 && length == 2:
			return PayloadProtoEther, "type"
		}
		return PayloadProtoEther, fmt.Sprintf("offset_%d_len_%d", offset, length)

	default:
		return PayloadProtoIP, fmt.Sprintf("base_%d_offset_%d_len_%d", base, offset, length)
	}
}

// formatMACBytes renders a 6-byte MAC address as `aa:bb:cc:dd:ee:ff`.
func formatMACBytes(data []byte) string {
	if len(data) != 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		data[0], data[1], data[2], data[3], data[4], data[5])
}

// decodePayloadValue interprets a payload value from raw data based on protocol and field, returning an appropriate type.
func decodePayloadValue(protocol PayloadProtocol, field string, data []byte) interface{} {
	// Ethernet MAC addresses come in at the same field names as the IPv4
	// / IPv6 addresses (saddr/daddr) but with len 6 — render as colon-hex.
	if protocol == PayloadProtoEther && (field == "saddr" || field == "daddr") && len(data) == 6 {
		return formatMACBytes(data)
	}
	// Ether `type` is uint16 BE — distinct from ICMP/ICMPv6 `type` which is
	// uint8. Dispatch on protocol before the generic uint8 fallback below.
	if protocol == PayloadProtoEther && field == "type" && len(data) == 2 {
		return binary.BigEndian.Uint16(data)
	}
	switch field {
	case "saddr", "daddr":
		if len(data) == 4 {
			return &IPAddress{IP: net.IP(data)}
		}
		if len(data) == 16 {
			return &IPAddress{IP: net.IP(data)}
		}
	case "sport", "dport":
		if len(data) == 2 {
			return &PortSpec{Port: binary.BigEndian.Uint16(data)}
		}
	case "protocol", "type", "code", "ttl", "nexthdr", "hoplimit", "version_ihl", "dscp_ecn",
		"flags", "doff", "hdrlength", "hlen", "plen":
		if len(data) >= 1 {
			return data[0]
		}
	case "length", "csumcov", "id", "frag-off", "checksum", "window", "urgptr", "cpi",
		"htype", "ptype", "operation":
		// `checksum` is uint16 for TCP/UDP/ICMP/ICMPv6 but uint32 for SCTP —
		// pick by length.
		if len(data) == 2 {
			return binary.BigEndian.Uint16(data)
		}
		if len(data) == 4 {
			return binary.BigEndian.Uint32(data)
		}
	case "sequence", "ackseq", "gateway", "vtag", "spi":
		// `sequence` is uint16 for ICMP (len 2) but uint32 for TCP / AH /
		// SCTP (len 4) — we pick by length.
		if len(data) == 2 {
			return binary.BigEndian.Uint16(data)
		}
		if len(data) == 4 {
			return binary.BigEndian.Uint32(data)
		}
	case "reserved":
		if len(data) == 2 {
			return binary.BigEndian.Uint16(data)
		}
	}
	return data
}

// decodeMetaValue decodes a metadata value based on the key and raw binary data provided.
func decodeMetaValue(key expr.MetaKey, data []byte) interface{} {
	// Interface index handling
	if key == unix.NFT_META_IIF || key == unix.NFT_META_OIF {
		if len(data) == 4 {
			// Big-endian uint32
			ifIndex := binary.BigEndian.Uint32(data)
			// Interface index -> name conversion
			if iface, err := net.InterfaceByIndex(int(ifIndex)); err == nil {
				return iface.Name
			}
			// conversion failed — fall back to the raw index
			return ifIndex
		}
	}

	// Interface name (IFNAMSIZ-padded NUL-terminated string)
	// The kernel emits the register payload either padded to a 4-byte boundary
	// (typically 16 bytes total) or trimmed to the actual name length + NUL.
	// In both cases we want the readable name without trailing zeros.
	if key == unix.NFT_META_IIFNAME || key == unix.NFT_META_OIFNAME ||
		key == unix.NFT_META_BRI_IIFNAME || key == unix.NFT_META_BRI_OIFNAME {
		return strings.TrimRight(string(data), "\x00")
	}

	// simplified decoding
	if len(data) == 4 {
		return binary.BigEndian.Uint32(data)
	}
	if len(data) == 2 {
		return binary.BigEndian.Uint16(data)
	}
	if len(data) == 1 {
		return data[0]
	}
	return data
}

// cmpOpToCompareOp maps an expr.CmpOp to its corresponding CompareOp representation for conditional comparisons.
func cmpOpToCompareOp(op expr.CmpOp) CompareOp {
	switch op {
	case expr.CmpOpEq:
		return CompareOpEq
	case expr.CmpOpNeq:
		return CompareOpNeq
	case expr.CmpOpLt:
		return CompareOpLt
	case expr.CmpOpLte:
		return CompareOpLte
	case expr.CmpOpGt:
		return CompareOpGt
	case expr.CmpOpGte:
		return CompareOpGte
	default:
		return CompareOpEq
	}
}

// metaKeyToString converts a MetaKey constant to its corresponding string representation for better readability.
func metaKeyToString(key expr.MetaKey) string {
	switch key {
	case unix.NFT_META_IIF:
		return "iif"
	case unix.NFT_META_OIF:
		return "oif"
	case unix.NFT_META_IIFNAME:
		return "iifname"
	case unix.NFT_META_OIFNAME:
		return "oifname"
	case unix.NFT_META_IIFTYPE:
		return "iiftype"
	case unix.NFT_META_OIFTYPE:
		return "oiftype"
	case unix.NFT_META_LEN:
		return "length"
	case unix.NFT_META_PROTOCOL:
		return "protocol"
	case unix.NFT_META_NFPROTO:
		return "nfproto"
	case unix.NFT_META_L4PROTO:
		return "l4proto"
	case unix.NFT_META_MARK:
		return "mark"
	case unix.NFT_META_PRIORITY:
		return "priority"
	case unix.NFT_META_SKUID:
		return "skuid"
	case unix.NFT_META_SKGID:
		return "skgid"
	case unix.NFT_META_CGROUP:
		return "cgroup"
	case unix.NFT_META_PKTTYPE:
		return "pkttype"
	case unix.NFT_META_CPU:
		return "cpu"
	case unix.NFT_META_IIFGROUP:
		return "iifgroup"
	case unix.NFT_META_OIFGROUP:
		return "oifgroup"
	case unix.NFT_META_RTCLASSID:
		return "rtclassid"
	default:
		return fmt.Sprintf("meta_%d", key)
	}
}

// syslogLevelToLogLevel maps a syslog severity level to a corresponding internal LogLevel value.
func syslogLevelToLogLevel(level expr.LogLevel) LogLevel {
	switch level {
	case 0:
		return LogLevelEmerg
	case 1:
		return LogLevelAlert
	case 2:
		return LogLevelCrit
	case 3:
		return LogLevelErr
	case 4:
		return LogLevelWarn
	case 5:
		return LogLevelNotice
	case 6:
		return LogLevelInfo
	case 7:
		return LogLevelDebug
	default:
		return LogLevelInfo
	}
}

// RuleToHumanReadable converts an nftables.Rule object into a human-readable string representation.
func RuleToHumanReadable(rule *nftables.Rule) string {
	sets, err := GetSets(rule.Table)
	if err != nil {
		return fmt.Sprintf("Error getting sets: %s", err)
	}
	return ruleToHumanReadableWithSets(rule, sets)
}

// ruleToHumanReadableWithSets is the netlink-free core of RuleToHumanReadable:
// the caller supplies the table's sets, so the expression walk is unit-testable
// without a live connection (mirrors the serializeRuleExprs seam in
// nftserializer).
func ruleToHumanReadableWithSets(rule *nftables.Rule, sets []*nftables.Set) string {
	var parts []string
	regMap := make(map[uint32]string)

	// Protocol keyword latched from this rule's `meta l4proto` match. Payload
	// cells that offset+len alone cannot identify — transport offset 4 is
	// `udp length` but `udplite csumcov` — are named from it.
	var l4proto string

	i := 0
	for i < len(rule.Exprs) {
		e := rule.Exprs[i]

		switch v := e.(type) {
		case *expr.Ct:
			str, skip := nftexpr.SerializeCt(v, rule.Exprs, i, sets)
			parts = append(parts, str)
			i += skip

		case *expr.Range:
			// range check
			regContent := regMap[v.Register]
			if regContent == "" {
				regContent = fmt.Sprintf("register_%d", v.Register)
			}
			parts = append(parts, fmt.Sprintf("%s %s %v-%v",
				regContent, nftexpr.CmpOpToString(v.Op), v.FromData, v.ToData))
			i++
			//fmt.Printf("Range regMap: %v\n", regMap)
			//fmt.Printf("Range parts: %v\n", parts)

		case *expr.Meta:
			// Meta expression — loads a meta value into a register
			metaName := nftexpr.MetaKeyToString(v.Key)
			regMap[v.Register] = metaName
			i++
			//fmt.Printf("Meta regMap: %v\n", regMap)
			//fmt.Printf("Meta parts: %v\n", parts)

		case *expr.Cmp:
			//fmt.Printf("e cmp: %+v\n", e)
			// Cmp — look up what's being compared against the register
			regContent := regMap[v.Register]
			if regContent == "" {
				regContent = fmt.Sprintf("register_%d", v.Register)
			}

			//fmt.Printf("e.Data: %+v, regContent: %+v", e.Data, regContent)
			value := nftexpr.DataToHumanReadable(v.Data, regContent)
			if regContent == "icmp type" && nftexpr.CmpOpToString(v.Op) == "==" && value == "echo-request" {
				parts = append(parts, regContent+" "+value)
			} else if regContent == "iif" && nftexpr.CmpOpToString(v.Op) == "==" {
				parts = append(parts, regContent+" "+nftexpr.InterfaceIndexToName(v.Data))
			} else if regContent == "ip protocol" && nftexpr.CmpOpToString(v.Op) == "==" && value == "icmp" {
				parts = append(parts, regContent+" "+value)
			} else if regContent == "ip protocol" && nftexpr.CmpOpToString(v.Op) == "==" && value == "tcp" {
				parts = append(parts, "tcp")
			} else if regContent == "ip protocol" && nftexpr.CmpOpToString(v.Op) == "==" && value == "udp" {
				parts = append(parts, "udp")
			} else if regContent == "dport" && nftexpr.CmpOpToString(v.Op) == "==" {
				parts = append(parts, regContent+" "+value)
			} else if regContent == "l4proto" && nftexpr.CmpOpToString(v.Op) == "==" &&
				(value == "icmpv6" || value == "tcp" || value == "udp" || value == "udplite") {
				// Rendered as the bare protocol keyword, the way nft prints it
				// (`udp dport 53`, not `meta l4proto udp dport 53`). The same
				// value becomes the context for any Payload further down.
				l4proto = value
				parts = append(parts, value)
				//} else if regContent == "direction" {
				//	// special handling for CT Direction
				//	dirVal := nftexpr.DecodeCTValue(expr.CtKeyDIRECTION, v.Data)
				//	parts = append(parts, fmt.Sprintf("ct direction %s %v", nftexpr.CmpOpToString(v.Op), dirVal))
			} else if regContent == string(nftexpr.CtKeyState) {
				//fmt.Printf("Cmp parts: %+v", parts)
			} else if regContent == string(nftexpr.CtKeyMark) && nftexpr.CmpOpToString(v.Op) == "==" {
				parts = append(parts, "ct mark "+value)
			} else {
				//fmt.Printf("Cmp regContent: %s value: %s\n", regContent, value)
				part := fmt.Sprintf("%s %s %s", regContent, nftexpr.CmpOpToString(v.Op), value)
				//fmt.Printf("Cmp part: %s\n", part)
				parts = append(parts, part)
			}
			i++
			//fmt.Printf("Cmp regMap: %v\n", regMap)
			//fmt.Printf("Cmp parts: %v\n", parts)

		case *expr.Counter:
			parts = append(parts, "counter")
			i++

		case *expr.Objref:
			parts = append(parts, nftexpr.SerializeObjref(v))
			i++

		case *expr.Payload:
			// Payload — loads data from the packet body
			payloadDesc := payloadToHumanReadable(v, l4proto)
			if payloadDesc == "saddr" || payloadDesc == "daddr" {
				// Family from the payload offset: IPv4 saddr/daddr sit at 12/16,
				// IPv6 at 8/24. fullLen / ipBits drive the value formatting so a
				// 16-byte address renders as IPv6 and a 4-byte one as IPv4.
				ipProto := "ip"
				ipBits := 32
				fullLen := 4
				if v.Offset == 8 || v.Offset == 24 {
					ipProto = "ip6"
					ipBits = 128
					fullLen = 16
				}
				// CIDR: Payload → Bitwise → Cmp
				if i+2 < len(rule.Exprs) {
					if bw, ok1 := rule.Exprs[i+1].(*expr.Bitwise); ok1 {
						if cmp, ok2 := rule.Exprs[i+2].(*expr.Cmp); ok2 {
							ip := net.IP(cmp.Data)
							ipnet := &net.IPNet{IP: ip, Mask: net.IPMask(bw.Mask)}
							op := nftexpr.CmpOpToString(cmp.Op)
							if op == "==" {
								parts = append(parts, fmt.Sprintf("%s %s %s", ipProto, payloadDesc, ipnet.String()))
							} else {
								parts = append(parts, fmt.Sprintf("%s %s %s %s", ipProto, payloadDesc, op, ipnet.String()))
							}
							i += 3
							break
						}
					}
				}
				// Exact IP or byte-aligned prefix: Payload → Cmp
				if i+1 < len(rule.Exprs) {
					if cmp, ok := rule.Exprs[i+1].(*expr.Cmp); ok {
						var valStr string
						if len(cmp.Data) == fullLen {
							valStr = net.IP(cmp.Data).String()
						} else if len(cmp.Data) >= 1 && len(cmp.Data) < fullLen {
							// Byte-aligned prefix: pad to the full width and build CIDR
							padded := make([]byte, fullLen)
							copy(padded, cmp.Data)
							mask := net.CIDRMask(len(cmp.Data)*8, ipBits)
							valStr = (&net.IPNet{IP: net.IP(padded), Mask: mask}).String()
						} else {
							valStr = fmt.Sprintf("0x%x", cmp.Data)
						}
						op := nftexpr.CmpOpToString(cmp.Op)
						if op == "==" {
							parts = append(parts, fmt.Sprintf("%s %s %s", ipProto, payloadDesc, valStr))
						} else {
							parts = append(parts, fmt.Sprintf("%s %s %s %s", ipProto, payloadDesc, op, valStr))
						}
						i += 2
						break
					}
				}
				// Set lookup: Payload → Lookup. The Payload alone stores just
				// "saddr"/"daddr" in regMap (no "ip " prefix), so the standalone
				// Lookup case below would emit "saddr {…}". Catching the pair
				// inline preserves the "ip" qualifier in the rendered form.
				if i+1 < len(rule.Exprs) {
					if lookup, ok := rule.Exprs[i+1].(*expr.Lookup); ok {
						qualified := fmt.Sprintf("%s %s", ipProto, payloadDesc)
						parts = append(parts, nftexpr.SerializeLookup(lookup, qualified, sets))
						i += 2
						break
					}
				}
			}
			regMap[v.DestRegister] = payloadDesc
			i++
			//fmt.Printf("Payload regMap: %v\n", regMap)
			//fmt.Printf("Payload parts: %v\n", parts)

		case *expr.Lookup:
			// Standalone set lookup. The register description from regMap is
			// already what should appear before the set ("dport" for tcp/udp
			// ports — the protocol prefix is contributed by the upstream
			// meta-l4proto Cmp as a separate part; "saddr"/"daddr" are caught
			// inline above in the Payload case so we don't reach here with a
			// bare IP field name). For unknown register sources fall back to
			// "register_N" so the rendering still distinguishes the rule.
			regContent := regMap[v.SourceRegister]
			if regContent == "" {
				regContent = fmt.Sprintf("register_%d", v.SourceRegister)
			}
			parts = append(parts, nftexpr.SerializeLookup(v, regContent, sets))
			i++

		case *expr.Immediate:
			// Immediate — loads a constant value into a register
			regMap[v.Register] = fmt.Sprintf("0x%x", v.Data)
			i++
			//fmt.Printf("Immediate regMap: %v\n", regMap)
			//fmt.Printf("Immediate parts: %v\n", parts)

		case *expr.Bitwise:
			// Bitwise operation
			parts = append(parts, nftexpr.BitwiseToHumanReadable(v, regMap))
			i++
			//fmt.Printf("Bitwise regMap: %v\n", regMap)
			//fmt.Printf("Bitwise parts: %v\n", parts)

		case *expr.Redir:
			// TODO
			i++

		case *expr.NAT:
			// TODO
			i++

		case *expr.Limit:
			part := nftexpr.SerializeLimit(v)
			parts = append(parts, part)
			i++

		case *expr.Quota:
			// TODO
			i++

		case *expr.Dynset:
			parts = append(parts, formatDynsetSimple(v, regMap[v.SrcRegKey]))
			i++

		case *expr.Log:
			// Logging
			logStr := "log"
			if len(v.Data) > 0 {
				logStr += fmt.Sprintf(" prefix \"%s\"", string(v.Data))
			}
			if v.Level != 0 {
				logStr += fmt.Sprintf(" level %s", logLevelToString(v.Level))
			}
			parts = append(parts, logStr)
			i++

		case *expr.Exthdr:
			// TODO
			i++

		case *expr.Match:
			// TODO
			i++

		case *expr.Target:
			// TODO
			i++

		case *expr.Connlimit:
			parts = append(parts, nftexpr.SerializeConnlimit(v))
			i++

		case *expr.Queue:
			// TODO
			i++

		case *expr.FlowOffload:
			// TODO
			i++

		case *expr.Reject:
			// TODO
			i++

		case *expr.Masq:
			parts = append(parts, nftexpr.SerializeMasq(v))
			i++

		case *expr.Hash:
			// TODO
			i++

		case *expr.CtHelper:
			// TODO
			i++

		case *expr.SynProxy:
			// TODO
			i++

		case *expr.CtExpect:
			// TODO
			i++

		case *expr.SecMark:
			// TODO
			i++

		case *expr.CtTimeout:
			// TODO
			i++

		case *expr.Fib:
			// TODO
			i++

		case *expr.Numgen:
			// TODO
			i++

		case *expr.Verdict: // ?
			// Verdict - accept, drop, stb.
			parts = append(parts, verdictToHumanReadable(v))
			i++

		default:
			parts = append(parts, fmt.Sprintf("/* unknown expr: %T */", e))
			i++
		}

		// if the next element is also a Cmp, that's most likely an && chain
		if i < len(rule.Exprs)-1 {
			if _, nextIsCmp := rule.Exprs[i+1].(*expr.Cmp); nextIsCmp {
				if _, currentIsCmp := e.(*expr.Cmp); currentIsCmp {
					// no-op here — the next iteration handles it
				}
			}
		}
	}

	result := strings.Join(parts, " ")

	if comment := ExtractComment(rule); comment != "" {
		result += fmt.Sprintf(" comment \"%s\"", comment)
	}

	return result
}

// payloadToHumanReadable converts a network payload specification into a human-readable string representation.
// l4proto is the protocol keyword latched from the rule's `meta l4proto` match
// ("" when it carries none) and names the transport cells that offset and
// length alone cannot tell apart.
func payloadToHumanReadable(p *expr.Payload, l4proto string) string {
	// Transport header (TCP/UDP/ICMP)
	if p.Base == unix.NFT_PAYLOAD_TRANSPORT_HEADER {
		if p.Offset == 0 && p.Len == 2 {
			return "sport" // source port
		}
		if p.Offset == 2 && p.Len == 2 {
			return "dport" // destination port
		}
		if p.Offset == 0 && p.Len == 1 {
			return "icmp type"
		}
		// Offset 4 is `length` in UDP but the checksum coverage in UDP-Lite,
		// which nft names `csumcov` (and it rejects `udplite length`). Offset
		// 6 is the checksum in both — TCP's sequence number spans bytes 4..8,
		// so a standalone 2-byte match there is never TCP. Both need the
		// l4proto context; without it they keep the raw form below.
		// Field name only — the protocol keyword is already a part of its
		// own (the `meta l4proto` arm above), so "udp length" here would
		// render `udp udp length 64`.
		if p.Offset == 4 && p.Len == 2 {
			switch l4proto {
			case "udp":
				return "length"
			case "udplite":
				return "csumcov"
			}
		}
		if p.Offset == 6 && p.Len == 2 && (l4proto == "udp" || l4proto == "udplite") {
			return "checksum"
		}
	}

	// Network header (IP)
	if p.Base == unix.NFT_PAYLOAD_NETWORK_HEADER {
		if p.Offset == 9 && p.Len == 1 {
			return "ip protocol"
		}
		if p.Offset == 12 && p.Len >= 1 && p.Len <= 4 {
			return "saddr" // IPv4 source address (len 1-3: byte-aligned prefix, len 4: full)
		}
		if p.Offset == 16 && p.Len >= 1 && p.Len <= 4 {
			return "daddr" // IPv4 destination address
		}
		// IPv6 source/destination address (16-byte fields at offsets 8 / 24).
		// The caller infers the family from p.Offset (8/24 → ip6, 12/16 → ip)
		// and formats the value accordingly. Offset 24 is past the IPv4 header,
		// so any len there is v6; at offset 8 a len > 4 rules out the 1-byte
		// IPv4 fields (ttl at offset 8 is len 1) — so v6 byte-prefixes shorter
		// than /40 fall through to the raw form rather than be mislabelled.
		if p.Offset == 8 && p.Len >= 5 && p.Len <= 16 {
			return "saddr" // IPv6 source address
		}
		if p.Offset == 24 && p.Len >= 1 && p.Len <= 16 {
			return "daddr" // IPv6 destination address
		}
	}

	return fmt.Sprintf("payload[%s+%d:%d]", payloadBaseToString(p.Base), p.Offset, p.Len)
}

// verdictToHumanReadable converts a verdict object into a human-readable string representation.
func verdictToHumanReadable(v *expr.Verdict) string {
	switch v.Kind {
	case expr.VerdictAccept:
		return "accept"
	case expr.VerdictDrop:
		return "drop"
	case expr.VerdictReturn:
		return "return"
	case expr.VerdictJump:
		return fmt.Sprintf("jump %s", v.Chain)
	case expr.VerdictGoto:
		return fmt.Sprintf("goto %s", v.Chain)
	default:
		return verdictKindToString(v.Kind)
	}
}

// ExtractComment extracts a user-defined comment from the UserData field of an nftables.Rule.
// The comment is stored in TLV format, where Type=0 indicates a comment, followed by its Length and Value.
// If no comment is found, an empty string is returned.
// Null terminators within the comment are removed before returning the result.
func ExtractComment(rule *nftables.Rule) string {
	// UserData is encoded as TLV
	// Type=0, Length=N, Value=comment
	if len(rule.UserData) < 2 {
		return ""
	}

	offset := 0
	for offset < len(rule.UserData)-1 {
		tlvType := rule.UserData[offset]
		tlvLen := int(rule.UserData[offset+1])

		if offset+2+tlvLen > len(rule.UserData) {
			break
		}

		// UDATA_TYPE_COMMENT = 0
		if tlvType == 0 {
			comment := rule.UserData[offset+2 : offset+2+tlvLen]
			// strip null terminator
			for i, b := range comment {
				if b == 0 {
					return string(comment[:i])
				}
			}
			return string(comment)
		}

		offset += 2 + tlvLen
	}

	return ""
}

// ApplyRuleChange updates or adds the specified nftables rule and commits the changes to the kernel.
// Returns an error if the connection to nftables fails or the changes cannot be flushed.
func ApplyRuleChange(rule *nftables.Rule) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %v", err)
	}

	// Update the rule. In nftables, when Handle is set, AddRule
	// overwrites / updates the existing rule.
	conn.AddRule(rule)

	// commit the changes to the kernel
	flushErr := conn.Flush()
	auditEvent("apply-rule", ruleTarget(rule), flushErr)
	if flushErr != nil {
		return fmt.Errorf("failed to apply changes to kernel: %v", flushErr)
	}

	return nil
}
