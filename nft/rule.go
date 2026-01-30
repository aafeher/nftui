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

type Rule struct {
	Position uint64
	Handle   uint64

	Conditions []Condition

	Actions []Action

	Counter *CounterStats

	Comment string
}

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

type ConditionType string

const (
	ConditionTypeMeta      ConditionType = "meta"
	ConditionTypePayload   ConditionType = "payload"
	ConditionTypeCT        ConditionType = "ct"
	ConditionTypeSetLookup ConditionType = "set_lookup"
	ConditionTypeLimit     ConditionType = "limit"
	ConditionTypeCustom    ConditionType = "custom"
)

type CompareOp string

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

type MetaCondition struct {
	Key   MetaKey
	Value any
}

type MetaKey string

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

type PayloadCondition struct {
	Protocol PayloadProtocol
	Field    string
	Value    any
}

type PayloadProtocol string

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

// Konkrét payload mezők
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

type TCPFields struct {
	Sport *PortSpec // source port
	Dport *PortSpec // destination port
	Flags *TCPFlags
	Seq   *uint32
	Ack   *uint32
}

type UDPFields struct {
	Sport  *PortSpec
	Dport  *PortSpec
	Length *uint16
}

type ICMPFields struct {
	Type *ICMPType
	Code *uint8
}

// CTCondition - connection tracking
type CTCondition struct {
	Key   nftexpr.CtKey
	Value interface{}
}

// SetLookupCondition - set lookup
type SetLookupCondition struct {
	SetName string
	Field   string // melyik mezőt keressük a setben
}

// CustomCondition - egyedi/komplex feltételek
type CustomCondition struct {
	Expression string      // az eredeti kifejezés
	Data       interface{} // extra adatok
}

// Action - végrehajtandó művelet
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

type ActionType string

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

// VerdictAction - accept, drop, jump, goto, return
type VerdictAction struct {
	Kind  VerdictKind
	Chain string // jump/goto esetén a cél chain
}

type VerdictKind string

const (
	VerdictAccept   VerdictKind = "accept"
	VerdictDrop     VerdictKind = "drop"
	VerdictReject   VerdictKind = "reject"
	VerdictReturn   VerdictKind = "return"
	VerdictJump     VerdictKind = "jump"
	VerdictGoto     VerdictKind = "goto"
	VerdictContinue VerdictKind = "continue"
)

// NATAction - source/destination NAT
type NATAction struct {
	Type         NATType
	AddressRange *AddressRange
	PortRange    *PortRange
	Flags        []NATFlag
	Persistent   bool
	Random       bool
	FullyRandom  bool
}

type NATType string

const (
	NATTypeSNAT NATType = "snat"
	NATTypeDNAT NATType = "dnat"
	NATTypeMasq NATType = "masquerade"
)

type NATFlag string

const (
	NATFlagRandom      NATFlag = "random"
	NATFlagFullyRandom NATFlag = "fully-random"
	NATFlagPersistent  NATFlag = "persistent"
	NATFlagNetmap      NATFlag = "netmap"
)

// LogAction - logging
type LogAction struct {
	Prefix     string
	Level      LogLevel
	Group      uint16
	QThreshold uint16
	Snaplen    uint32
	Flags      []LogFlag
}

type LogLevel string

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

type LogFlag string

const (
	LogFlagTCPSequence LogFlag = "tcp sequence"
	LogFlagTCPOptions  LogFlag = "tcp options"
	LogFlagIPOptions   LogFlag = "ip options"
	LogFlagUID         LogFlag = "uid"
	LogFlagAll         LogFlag = "all"
)

// CounterAction - packet/byte counter
type CounterAction struct {
	Name string // opcionális név
}

// QueueAction - nfqueue
type QueueAction struct {
	Num      uint16
	NumRange *QueueRange
	Flags    []QueueFlag
}

type QueueRange struct {
	From uint16
	To   uint16
}

type QueueFlag string

const (
	QueueFlagBypass QueueFlag = "bypass"
	QueueFlagFanout QueueFlag = "fanout"
)

// RejectAction - reject with
type RejectAction struct {
	Type RejectType
	Code uint8 // ICMPv4/v6 code
}

type RejectType string

const (
	RejectTypeICMP     RejectType = "icmp"
	RejectTypeICMPv6   RejectType = "icmpv6"
	RejectTypeTCPReset RejectType = "tcp reset"
	RejectTypeICMPX    RejectType = "icmpx"
)

// SetAction - set/map update
type SetAction struct {
	SetName  string
	MapName  string
	Elements []SetElement
	Update   bool // add vagy update
}

type SetElement struct {
	Key   interface{}
	Value interface{} // map esetén
}

// RedirectAction - port redirect
type RedirectAction struct {
	PortRange *PortRange
}

// MasqueradeAction - masquerade
type MasqueradeAction struct {
	PortRange   *PortRange
	Random      bool
	FullyRandom bool
	Persistent  bool
}

// CustomAction - egyedi művelet
type CustomAction struct {
	Expression string
	Data       interface{}
}

// Segédtípusok

type IPAddress struct {
	IP     net.IP
	Subnet *net.IPNet // CIDR esetén
}

type PortSpec struct {
	Port  uint16
	Range *PortRange
	Set   []uint16
}

type PortRange struct {
	From uint16
	To   uint16
}

type AddressRange struct {
	From net.IP
	To   net.IP
}

type TCPFlags struct {
	Mask  TCPFlagSet
	Value TCPFlagSet
}

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

type ICMPType struct {
	Type uint8
	Name string // "echo-request", "echo-reply", stb.
}

type CounterStats struct {
	Packets uint64
	Bytes   uint64
}

// RangeValue generikus tartomány
type RangeValue struct {
	From interface{}
	To   interface{}
}

// SetValue - set elemek
type SetValue struct {
	Elements []interface{}
}

// extractValueFromCt kinyeri a beállított értéket az nftexpr.Ct struktúrából.
// Ez segít abban, hogy a CTCondition.Value mezője a GUI számára értelmezhető legyen.
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

// NftablesToRuleDefinition konvertál egy nftables.Rule-t RuleDefinition-né
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

			rd.Conditions = append(rd.Conditions, Condition{
				Type:      ConditionTypeCT,
				Operation: cmpOpToCompareOp(op),
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

type registerValueType int

const (
	regTypeUnknown registerValueType = iota
	regTypeMeta
	regTypePayload
	regTypeCT
	regTypeImmediate
)

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

type compareContext struct {
	op       expr.CmpOp
	data     []byte
	register *registerValue
}

// compareToCondition konvertál egy összehasonlítást Condition-né
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

// metaCompareToCondition konvertál meta összehasonlítást
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

// payloadCompareToCondition konvertál payload összehasonlítást
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

// ctCompareToCondition konvertál CT összehasonlítást
func ctCompareToCondition(regVal *registerValue, cmp *compareContext) (Condition, error) {
	ctKey := nftexpr.CtKeyToString(regVal.ctKey)
	value := nftexpr.DecodeCTValue(regVal.ctKey, cmp.data)

	return Condition{
		Type:      ConditionTypeCT,
		Operation: cmpOpToCompareOp(cmp.op),
		CT: &CTCondition{
			Key:   nftexpr.CtKey(ctKey),
			Value: value,
		},
	}, nil
}

// rangeToCondition konvertál tartomány ellenőrzést
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
	default:
		return Condition{}, fmt.Errorf("unsupported range type")
	}
}

// lookupToCondition konvertál set lookup-ot
func lookupToCondition(regVal *registerValue, lookup *expr.Lookup) Condition {
	field := ""

	switch regVal.valueType {
	case regTypeMeta:
		field = metaKeyToString(regVal.metaKey)
	case regTypePayload:
		_, field = identifyPayloadField(regVal.payloadBase, regVal.payloadOff, regVal.payloadLen)
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

func limitToCondition(limit *expr.Limit) Condition {
	return Condition{
		Type:  ConditionTypeLimit,
		Limit: limit,
	}
}

// verdictToAction konvertál verdict-et action-né
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

// logToAction konvertál log-ot action-né
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

// natToAction konvertál NAT-ot action-né
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

// masqToAction konvertál masquerade-ot action-né
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

// redirToAction konvertál redirect-et action-né
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

// rejectToAction konvertál reject-et action-né
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

// queueToAction konvertál queue-t action-né
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

// dynsetToAction konvertál dynset-et action-né
func dynsetToAction(d *expr.Dynset, regMap map[uint32]*registerValue) Action {
	// TODO: teljes implementáció
	return Action{
		Type: ActionTypeSet,
		Set: &SetAction{
			SetName: d.SetName,
		},
	}
}

// Segédfüggvények

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

// Segédfüggvények az emberi olvashatósághoz

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
