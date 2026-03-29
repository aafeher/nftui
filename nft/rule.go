package nft

import (
	"encoding/binary"
	"fmt"
	"net"
	nftexpr "nftui/nft/expr"
	"strings"

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
	SetLookup *SetLookupCondition
	Limit     *expr.Limit
	Custom    *CustomCondition
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
	ConditionTypeSetLookup ConditionType = "set_lookup"
	ConditionTypeLimit     ConditionType = "limit"
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
	MetaKeyIIf      MetaKey = "iif"
	MetaKeyOIf      MetaKey = "oif"
	MetaKeyIIfName  MetaKey = "iifname"
	MetaKeyOIfName  MetaKey = "oifname"
	MetaKeyIIfType  MetaKey = "iiftype"
	MetaKeyOIfType  MetaKey = "oiftype"
	MetaKeyProtocol MetaKey = "protocol" // protocol family
	MetaKeyPriority MetaKey = "priority"
	MetaKeyMark     MetaKey = "mark"
	MetaKeyL4Proto  MetaKey = "l4proto" // L4 protokoll (tcp, udp, icmp)
	MetaKeyLength   MetaKey = "length"  // csomag hossz
	MetaKeyCGroup   MetaKey = "cgroup"
	MetaKeyPktType  MetaKey = "pkttype" // unicast, broadcast, multicast
	MetaKeyCPU      MetaKey = "cpu"
	MetaKeyIIfGroup MetaKey = "iifgroup"
	MetaKeyOIfGroup MetaKey = "oifgroup"
	MetaKeyTime     MetaKey = "time"
	MetaKeyDay      MetaKey = "day"
	MetaKeyHour     MetaKey = "hour"
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
// PayloadProtoICMP represents the payload protocol for ICMP.
// PayloadProtoICMPv6 represents the payload protocol for ICMPv6.
// PayloadProtoARP represents the payload protocol for ARP.
const (
	PayloadProtoEther  PayloadProtocol = "ether"
	PayloadProtoIP     PayloadProtocol = "ip"
	PayloadProtoIP6    PayloadProtocol = "ip6"
	PayloadProtoTCP    PayloadProtocol = "tcp"
	PayloadProtoUDP    PayloadProtocol = "udp"
	PayloadProtoICMP   PayloadProtocol = "icmp"
	PayloadProtoICMPv6 PayloadProtocol = "icmpv6"
	PayloadProtoARP    PayloadProtocol = "arp"
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
	Key   nftexpr.CtKey
	Value interface{}
}

// SetLookupCondition specifies a condition to match data within a named set using a specific field.
type SetLookupCondition struct {
	SetName string
	Field   string // melyik mezőt keressük a setben
}

// CustomCondition represents a user-defined condition with an expression and associated data for custom logic.
type CustomCondition struct {
	Expression string      // az eredeti kifejezés
	Data       interface{} // extra adatok
}

// Action represents a rule action with a specific type and associated data for different action types.
type Action struct {
	Type ActionType

	// Típus-specifikus mezők
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
	ActionTypeCustom   ActionType = "custom"
)

// VerdictAction represents an action with a specific verdict type and an optional target chain for jump/goto actions.
type VerdictAction struct {
	Kind  VerdictKind
	Chain string // jump/goto esetén a cél chain
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

// SetAction represents an action to modify or update a set with specific elements, target set names, and update flags.
type SetAction struct {
	SetName  string
	MapName  string
	Elements []SetElement
	Update   bool // add vagy update
}

// SetElement represents a single element in a set with a key and an optional associated value.
type SetElement struct {
	Key   interface{}
	Value interface{} // map esetén
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
	Subnet *net.IPNet // CIDR esetén
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

	// Regiszter követés - tároljuk, hogy melyik regiszterbe mit töltöttünk
	regMap := make(map[uint32]*registerValue)

	// Összehasonlítások összegyűjtése (AND kapcsolat)
	var pendingCompares []*compareContext

	sets, err := GetSets(rule.Table)
	if err != nil {
		return nil, fmt.Errorf("error getting sets: %s", err)
	}

	i := 0
	for i < len(rule.Exprs) {
		e := rule.Exprs[i]

		switch v := e.(type) {
		case *expr.Ct:
			//fmt.Printf("CT: %v\n", e)
			ct, skip := nftexpr.ExprCtToCt(v, rule.Exprs, i, sets)
			op := nftexpr.GetCtOp(rule.Exprs, i)

			actualOp := cmpOpToCompareOp(op)
			if ct.ExpirationOp != "" {
				actualOp = CompareOp(ct.ExpirationOp)
			}

			rd.Conditions = append(rd.Conditions, Condition{
				Type:      ConditionTypeCT,
				Operation: actualOp,
				CT: &CTCondition{
					Key:   nftexpr.CtKey(nftexpr.CtKeyToString(v.Key)),
					Value: extractValueFromCt(ct),
				},
			})
			i += skip
			continue
		case *expr.Range:
			// Tartomány ellenőrzés
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
			// Összehasonlítás - betesszük a pending listába
			regVal := regMap[v.Register]
			if regVal == nil {
				regVal = &registerValue{valueType: regTypeUnknown}
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
			// Objektum referencia (quota, counter, ct helper, stb.)
			// TODO: implementálás
			i++
		case *expr.Payload:
			regMap[v.DestRegister] = &registerValue{
				valueType:   regTypePayload,
				payloadBase: v.Base,
				payloadOff:  v.Offset,
				payloadLen:  v.Len,
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
			// Bitwise művelet - módosítja a regiszter értékét
			if srcVal, ok := regMap[v.SourceRegister]; ok {
				regMap[v.DestRegister] = &registerValue{
					valueType:   srcVal.valueType,
					metaKey:     srcVal.metaKey,
					payloadBase: srcVal.payloadBase,
					payloadOff:  srcVal.payloadOff,
					payloadLen:  srcVal.payloadLen,
					ctKey:       srcVal.ctKey,
					bitwiseMask: v.Mask,
					bitwiseXor:  v.Xor,
					hasBitwise:  true,
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
		case *expr.Quota:
			// TODO: quota kezelése
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
			// Ismeretlen expression - custom condition-ként tároljuk
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

	// Pending összehasonlítások feldolgozása
	for _, cmp := range pendingCompares {
		cond, err := compareToCondition(cmp)
		if err == nil {
			rd.Conditions = append(rd.Conditions, cond)
		}
	}

	return rd, nil
}

// Segédtípusok és struktúrák

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
)

// registerValue represents a container holding metadata and context for register-based expressions in rule processing.
type registerValue struct {
	valueType registerValueType

	value any

	// CT
	ctKey expr.CtKey

	// Meta
	metaKey expr.MetaKey

	// Payload
	payloadBase expr.PayloadBase
	payloadOff  uint32
	payloadLen  uint32

	// Immediate
	immediateData []byte

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
	default:
		return Condition{
			Type: ConditionTypeCustom,
			Custom: &CustomCondition{
				Expression: fmt.Sprintf("compare register unknown type"),
			},
		}, nil
	}
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
	protocol, field := identifyPayloadField(regVal.payloadBase, regVal.payloadOff, regVal.payloadLen)
	value := decodePayloadValue(protocol, field, cmp.data)

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
	value := nftexpr.DecodeCTValue(regVal.ctKey, cmp.data)

	// Ha a kulcs STATUS, akkor a DecodeCTValue visszaadhat egy []CtStatus-t
	if regVal.ctKey == expr.CtKeySTATUS {
		if statuses, ok := value.([]nftexpr.CtStatus); ok {
			return Condition{
				Type:      ConditionTypeCT,
				Operation: cmpOpToCompareOp(cmp.op),
				CT: &CTCondition{
					Key:   nftexpr.CtKey(ctKey),
					Value: statuses,
				},
			}, nil
		}
	}

	return Condition{
		Type:      ConditionTypeCT,
		Operation: cmpOpToCompareOp(cmp.op),
		CT: &CTCondition{
			Key:   nftexpr.CtKey(ctKey),
			Value: value,
		},
	}, nil
}

// rangeToCondition converts a registerValue and Range expression into a Condition if the value type is supported.
func rangeToCondition(regVal *registerValue, rng *expr.Range) (Condition, error) {
	switch regVal.valueType {
	case regTypePayload:
		protocol, field := identifyPayloadField(regVal.payloadBase, regVal.payloadOff, regVal.payloadLen)
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

// lookupToCondition converts a registerValue and a Lookup expression into a Condition for set lookup operations.
func lookupToCondition(regVal *registerValue, lookup *expr.Lookup) Condition {
	field := ""

	switch regVal.valueType {
	case regTypeMeta:
		field = metaKeyToString(regVal.metaKey)
	case regTypePayload:
		_, field = identifyPayloadField(regVal.payloadBase, regVal.payloadOff, regVal.payloadLen)
	case regTypeCT:
		field = nftexpr.CtKeyToString(regVal.ctKey)
	}

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
func logToAction(l *expr.Log) Action {
	prefix := string(l.Data)
	if len(prefix) > 0 && prefix[len(prefix)-1] == 0 {
		prefix = prefix[:len(prefix)-1]
	}

	return Action{
		Type: ActionTypeLog,
		Log: &LogAction{
			Prefix:     prefix,
			Level:      syslogLevelToLogLevel(l.Level),
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

	// Cím tartomány dekódolása
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

	// Port tartomány dekódolása
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

// dynsetToAction converts a Dynset expression into a corresponding Action with a SetAction type.
func dynsetToAction(d *expr.Dynset, regMap map[uint32]*registerValue) Action {
	// TODO: teljes implementáció
	return Action{
		Type: ActionTypeSet,
		Set: &SetAction{
			SetName: d.SetName,
		},
	}
}

// identifyPayloadField determines the protocol and field name based on payload base, offset, and length values.
func identifyPayloadField(base expr.PayloadBase, offset, length uint32) (PayloadProtocol, string) {
	switch base {
	case unix.NFT_PAYLOAD_NETWORK_HEADER:
		if offset == 9 && length == 1 {
			return PayloadProtoIP, "protocol"
		}
		if offset == 12 && length == 4 {
			return PayloadProtoIP, "saddr"
		}
		if offset == 16 && length == 4 {
			return PayloadProtoIP, "daddr"
		}
		return PayloadProtoIP, fmt.Sprintf("offset_%d_len_%d", offset, length)

	case unix.NFT_PAYLOAD_TRANSPORT_HEADER:
		if offset == 0 && length == 2 {
			return PayloadProtoTCP, "sport"
		}
		if offset == 2 && length == 2 {
			return PayloadProtoTCP, "dport"
		}
		if offset == 0 && length == 1 {
			return PayloadProtoICMP, "type"
		}
		return PayloadProtoTCP, fmt.Sprintf("offset_%d_len_%d", offset, length)

	default:
		return PayloadProtoIP, fmt.Sprintf("base_%d_offset_%d_len_%d", base, offset, length)
	}
}

// decodePayloadValue interprets a payload value from raw data based on protocol and field, returning an appropriate type.
func decodePayloadValue(protocol PayloadProtocol, field string, data []byte) interface{} {
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
	case "protocol", "type":
		if len(data) >= 1 {
			return data[0]
		}
	}
	return data
}

// decodeMetaValue decodes a metadata value based on the key and raw binary data provided.
func decodeMetaValue(key expr.MetaKey, data []byte) interface{} {
	// Interface index kezelése
	if key == unix.NFT_META_IIF || key == unix.NFT_META_OIF {
		if len(data) == 4 {
			// Big-endian uint32
			ifIndex := binary.BigEndian.Uint32(data)
			// Interface index -> név konverzió
			if iface, err := net.InterfaceByIndex(int(ifIndex)); err == nil {
				return iface.Name
			}
			// Ha nem sikerült a konverzió, visszaadjuk az indexet
			return ifIndex
		}
	}

	// Egyszerűsített dekódolás
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
	case unix.NFT_META_L4PROTO:
		return "l4proto"
	case unix.NFT_META_MARK:
		return "mark"
	case unix.NFT_META_PROTOCOL:
		return "protocol"
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
	var parts []string
	regMap := make(map[uint32]string)

	sets, err := GetSets(rule.Table)
	if err != nil {
		return fmt.Sprintf("Error getting sets: %s", err)
	}

	i := 0
	for i < len(rule.Exprs) {
		e := rule.Exprs[i]

		switch v := e.(type) {
		case *expr.Ct:
			str, skip := nftexpr.SerializeCt(v, rule.Exprs, i, sets)
			parts = append(parts, str)
			i += skip

		case *expr.Range:
			// Range ellenőrzés
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
			// Meta kifejezés - valami meta információt tölt be egy regiszterbe
			metaName := nftexpr.MetaKeyToString(v.Key)
			regMap[v.Register] = metaName
			i++
			//fmt.Printf("Meta regMap: %v\n", regMap)
			//fmt.Printf("Meta parts: %v\n", parts)

		case *expr.Cmp:
			//fmt.Printf("e cmp: %+v\n", e)
			// Összehasonlítás - nézzük meg, mit hasonlítunk össze
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
			} else if regContent == "l4proto" && nftexpr.CmpOpToString(v.Op) == "==" && value == "icmpv6" {
				parts = append(parts, value)
			} else if regContent == "l4proto" && nftexpr.CmpOpToString(v.Op) == "==" && value == "tcp" {
				parts = append(parts, value)
			} else if regContent == "l4proto" && nftexpr.CmpOpToString(v.Op) == "==" && value == "udp" {
				parts = append(parts, value)
				//} else if regContent == "direction" {
				//	// Speciális CT Direction kezelés
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
			// TODO
			i++

		case *expr.Payload:
			// Payload - csomag tartalmából tölt be adatot
			payloadDesc := payloadToHumanReadable(v)
			regMap[v.DestRegister] = payloadDesc
			i++
			//fmt.Printf("Payload regMap: %v\n", regMap)
			//fmt.Printf("Payload parts: %v\n", parts)

		case *expr.Lookup:
			// Set lookup
			//parts = append(parts, nftexpr.SerializeLookup(v, regMap))
			i++
			//fmt.Printf("Lookup regMap: %v\n", regMap)
			//fmt.Printf("Lookup parts: %v\n", parts)

		case *expr.Immediate:
			// Immediate - közvetlen érték betöltése regiszterbe
			regMap[v.Register] = fmt.Sprintf("0x%x", v.Data)
			i++
			//fmt.Printf("Immediate regMap: %v\n", regMap)
			//fmt.Printf("Immediate parts: %v\n", parts)

		case *expr.Bitwise:
			// Bitwise művelet
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
			// TODO
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
			// TODO
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
			// TODO
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

		// Ha van következő elem és az is Cmp, akkor valószínűleg && kapcsolat van
		if i < len(rule.Exprs)-1 {
			if _, nextIsCmp := rule.Exprs[i+1].(*expr.Cmp); nextIsCmp {
				if _, currentIsCmp := e.(*expr.Cmp); currentIsCmp {
					// Ne tegyünk semmit, majd a következő iterációban kezeljük
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
func payloadToHumanReadable(p *expr.Payload) string {
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
	}

	// Network header (IP)
	if p.Base == unix.NFT_PAYLOAD_NETWORK_HEADER {
		if p.Offset == 9 && p.Len == 1 {
			return "ip protocol"
		}
		if p.Offset == 12 && p.Len == 4 {
			return "saddr" // source address
		}
		if p.Offset == 16 && p.Len == 4 {
			return "daddr" // destination address
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
	// A UserData TLV formátumban van
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
			// Null terminátor eltávolítása
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

	// A szabály frissítése. Az nftables-ben ha meg van adva a Handle,
	// az AddRule felülírja/frissíti a létező szabályt.
	conn.AddRule(rule)

	// A módosítások véglegesítése a kernelben
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to apply changes to kernel: %v", err)
	}

	return nil
}
