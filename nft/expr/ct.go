package nftexpr

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

type Ct struct {
	State           []CtState   `json:"state,omitzero"`
	Direction       CtDirection `json:"direction,omitzero"`
	Status          []CtStatus  `json:"status,omitzero"`
	Mark            uint32      `json:"mark,omitzero"`
	Expiration      uint32      `json:"expiration,omitzero"`
	ExpirationOp    string      `json:"expiration_op,omitzero"`
	ExpirationRange *CtRange    `json:"expiration_range,omitzero"`
	ExpirationSet   []string    `json:"expiration_set,omitzero"`
	Helper          string      `json:"helper,omitzero"`
	L3Protocol      uint8       `json:"l3protocol,omitzero"`
	Protocol        uint8       `json:"protocol,omitzero"`
	Src             string      `json:"src,omitzero"`
	Dst             string      `json:"dst,omitzero"`
	ProtoSrc        uint16      `json:"proto_src,omitzero"`
	ProtoDst        uint16      `json:"proto_dst,omitzero"`
	Labels          []string    `json:"labels,omitzero"`
	Bytes           uint64      `json:"bytes,omitzero"`
	Pkts            uint64      `json:"packets,omitzero"`
	Avgpkt          uint32      `json:"avgpkt,omitzero"`
	Zone            uint16      `json:"zone,omitzero"`
	Eventmask       uint32      `json:"eventmask,omitzero"`
}

type CtRange struct {
	From uint32 `json:"from"`
	To   uint32 `json:"to"`
}

type CtKey string

const (
	CtKeyState      CtKey = "state"
	CtKeyDirection  CtKey = "direction"
	CtKeyStatus     CtKey = "status"
	CtKeyMark       CtKey = "mark"
	CtKeySecMark    CtKey = "secmark"
	CtKeyExpiration CtKey = "expiration"
	CtKeyHelper     CtKey = "helper"
	CtKeyL3Protocol CtKey = "l3protocol"
	CtKeySrc        CtKey = "src"
	CtKeyDst        CtKey = "dst"
	CtKeyProtocol   CtKey = "protocol"
	CtKeyProtoSrc   CtKey = "proto_src"
	CtKeyProtoDst   CtKey = "proto_dst"
	CtKeyLabels     CtKey = "labels"
	CtKeyPkts       CtKey = "pkts"
	CtKeyBytes      CtKey = "bytes"
	CtKeyAvgpkt     CtKey = "avgpkt"
	CtKeyZone       CtKey = "zone"
	CtKeyEventMask  CtKey = "eventmask"
)

type CtState string

const (
	CtStateInvalid     CtState = "invalid"
	CtStateEstablished CtState = "established"
	CtStateRelated     CtState = "related"
	CtStateNew         CtState = "new"
	CtStateUntracked   CtState = "untracked"
)

type CtDirection string

const (
	CtDirectionOriginal CtDirection = "original"
	CtDirectionReply    CtDirection = "reply"
)

type CtStatus string

const (
	CtStatusBitExpected     uint32 = 1
	CtStatusBitSeenReply    uint32 = 2
	CtStatusBitAssured      uint32 = 4
	CtStatusBitConfirmed    uint32 = 8
	CtStatusBitSnat         uint32 = 16
	CtStatusBitDnat         uint32 = 32
	CtStatusBitSeqAdjust    uint32 = 64
	CtStatusBitSnatDone     uint32 = 128
	CtStatusBitDnatDone     uint32 = 256
	CtStatusBitDying        uint32 = 512
	CtStatusBitFixedTimeout uint32 = 1024
	CtStatusBitTemplate     uint32 = 2048
	CtStatusBitUntracked    uint32 = 4096
	CtStatusBitHelper       uint32 = 8192
	CtStatusBitOffload      uint32 = 16384
	CtStatusBitHWOffload    uint32 = 32768

	CtStatusExpected     CtStatus = "expected"
	CtStatusSeenReply    CtStatus = "seen-reply"
	CtStatusAssured      CtStatus = "assured"
	CtStatusConfirmed    CtStatus = "confirmed"
	CtStatusSnat         CtStatus = "snat"
	CtStatusDnat         CtStatus = "dnat"
	CtStatusSeqAdjust    CtStatus = "seq-adjust"
	CtStatusSNatDone     CtStatus = "snat-done"
	CtStatusDNatDone     CtStatus = "dnat-done"
	CtStatusDying        CtStatus = "dying"
	CtStatusFixedTimeout CtStatus = "fixed-timeout"
	CtStatusTemplate     CtStatus = "template"
	CtStatusUntracked    CtStatus = "untracked"
	CtStatusHelper       CtStatus = "helper"
	CtStatusOffload      CtStatus = "offload"
	CtStatusHWOffload    CtStatus = "hw-offload"
)

// CtKeyToString converts a CtKey enumeration value to its corresponding string representation.
// See also https://wiki.nftables.org/wiki-nftables/index.php/Matching_connection_tracking_stateful_metainformation
// nftables/expr/ct.go
func CtKeyToString(ctKey expr.CtKey) string {
	switch ctKey {
	case expr.CtKeySTATE:
		return string(CtKeyState)
	case expr.CtKeyDIRECTION:
		return string(CtKeyDirection)
	case expr.CtKeySTATUS:
		return string(CtKeyStatus)
	case expr.CtKeyMARK:
		return string(CtKeyMark)
	case expr.CtKeySECMARK:
		return string(CtKeySecMark)
	case expr.CtKeyEXPIRATION:
		return string(CtKeyExpiration)
	case expr.CtKeyHELPER:
		return string(CtKeyHelper)
	case expr.CtKeyL3PROTOCOL:
		return string(CtKeyL3Protocol)
	case expr.CtKeySRC:
		return string(CtKeySrc)
	case expr.CtKeyDST:
		return string(CtKeyDst)
	case expr.CtKeyPROTOCOL:
		return string(CtKeyProtocol)
	case expr.CtKeyPROTOSRC:
		return string(CtKeyProtoSrc)
	case expr.CtKeyPROTODST:
		return string(CtKeyProtoDst)
	case expr.CtKeyLABELS:
		return string(CtKeyLabels)
	case expr.CtKeyPKTS:
		return string(CtKeyPkts)
	case expr.CtKeyBYTES:
		return string(CtKeyBytes)
	case expr.CtKeyAVGPKT:
		return string(CtKeyAvgpkt)
	case expr.CtKeyZONE:
		return string(CtKeyZone)
	case expr.CtKeyEVENTMASK:
		return string(CtKeyEventMask)
	default:
		return "unknown"
	}
}

var CtStateStrings = []string{
	string(CtStateInvalid),
	string(CtStateEstablished),
	string(CtStateRelated),
	string(CtStateNew),
	string(CtStateUntracked),
}

var CtDirectionStrings = []string{
	string(CtDirectionOriginal),
	string(CtDirectionReply),
}

var CtStatusStrings = []string{
	string(CtStatusExpected),
	string(CtStatusSeenReply),
	string(CtStatusAssured),
	string(CtStatusConfirmed),
	string(CtStatusSnat),
	string(CtStatusDnat),
	string(CtStatusSeqAdjust),
	string(CtStatusSNatDone),
	string(CtStatusDNatDone),
	string(CtStatusDying),
	string(CtStatusFixedTimeout),
	string(CtStatusTemplate),
	string(CtStatusUntracked),
	string(CtStatusHelper),
	string(CtStatusOffload),
	string(CtStatusHWOffload),
}

// CtStateStringToState converts a string representation of a connection state to its corresponding CtState value.
func CtStateStringToState(ctStateString string) CtState {
	switch ctStateString {
	case string(CtStateInvalid):
		return CtStateInvalid
	case string(CtStateEstablished):
		return CtStateEstablished
	case string(CtStateRelated):
		return CtStateRelated
	case string(CtStateNew):
		return CtStateNew
	case string(CtStateUntracked):
		return CtStateUntracked
	}
	return CtStateInvalid
}

// CtStatusStringToStatus converts a string representation of a connection tracking status to its corresponding CtStatus value.
func CtStatusStringToStatus(ctStatusString string) CtStatus {
	switch ctStatusString {
	case string(CtStatusExpected):
		return CtStatusExpected
	case string(CtStatusSeenReply):
		return CtStatusSeenReply
	case string(CtStatusAssured):
		return CtStatusAssured
	case string(CtStatusConfirmed):
		return CtStatusConfirmed
	case string(CtStatusSnat):
		return CtStatusSnat
	case string(CtStatusDnat):
		return CtStatusDnat
	case string(CtStatusSeqAdjust):
		return CtStatusSeqAdjust
	case string(CtStatusSNatDone):
		return CtStatusSNatDone
	case string(CtStatusDNatDone):
		return CtStatusDNatDone
	case string(CtStatusDying):
		return CtStatusDying
	case string(CtStatusFixedTimeout):
		return CtStatusFixedTimeout
	case string(CtStatusHelper):
		return CtStatusHelper
	case string(CtStatusOffload):
		return CtStatusOffload
	case string(CtStatusHWOffload):
		return CtStatusHWOffload
	}
	return ""
}

// CtStateStringToStates converts a list of connection state strings to their corresponding CtState values.
func CtStateStringToStates(ctStateStrings []string) []CtState {
	states := []CtState{}
	for _, s := range ctStateStrings {
		states = append(states, CtStateStringToState(s))
	}
	return states
}

// CtStateToStateStrings converts a slice of CtState to a slice of their string representations.
func CtStateToStateStrings(ctStates []CtState) []string {
	stateStrings := []string{}
	for _, s := range ctStates {
		stateStrings = append(stateStrings, string(s))
	}
	return stateStrings
}

// EncodeCtStates converts a slice of CtState into a 4-byte bitmask representation of connection tracking states.
func EncodeCtStates(states []CtState) []byte {
	var mask uint32
	for _, s := range states {
		switch s {
		case CtStateInvalid:
			mask |= expr.CtStateBitINVALID
		case CtStateEstablished:
			mask |= expr.CtStateBitESTABLISHED
		case CtStateRelated:
			mask |= expr.CtStateBitRELATED
		case CtStateNew:
			mask |= expr.CtStateBitNEW
		case CtStateUntracked:
			mask |= expr.CtStateBitUNTRACKED
		}
	}
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, mask)
	return buf
}

// CtStatusStringToStatuses converts a slice of connection tracking status strings to a slice of CtStatus values.
func CtStatusStringToStatuses(ctStatusStrings []string) []CtStatus {
	statuses := []CtStatus{}
	for _, s := range ctStatusStrings {
		status := CtStatusStringToStatus(s)
		if status != "" {
			statuses = append(statuses, status)
		}
	}
	return statuses
}

// CtStatusToStatusStrings converts a slice of CtStatus to a slice of corresponding string representations.
func CtStatusToStatusStrings(ctStatuses []CtStatus) []string {
	statusStrings := []string{}
	for _, s := range ctStatuses {
		statusStrings = append(statusStrings, string(s))
	}
	return statusStrings
}

// EncodeCtStatuses encodes a slice of CtStatus into a binary representation using a bitmask.
func EncodeCtStatuses(statuses []CtStatus) []byte {
	var mask uint32
	for _, s := range statuses {
		switch s {
		case CtStatusExpected:
			mask |= CtStatusBitExpected
		case CtStatusSeenReply:
			mask |= CtStatusBitSeenReply
		case CtStatusAssured:
			mask |= CtStatusBitAssured
		case CtStatusConfirmed:
			mask |= CtStatusBitConfirmed
		case CtStatusSnat:
			mask |= CtStatusBitSnat
		case CtStatusDnat:
			mask |= CtStatusBitDnat
		case CtStatusSeqAdjust:
			mask |= CtStatusBitSeqAdjust
		case CtStatusSNatDone:
			mask |= CtStatusBitSnatDone
		case CtStatusDNatDone:
			mask |= CtStatusBitDnatDone
		case CtStatusDying:
			mask |= CtStatusBitDying
		case CtStatusFixedTimeout:
			mask |= CtStatusBitFixedTimeout
		case CtStatusTemplate:
			mask |= CtStatusBitTemplate
		case CtStatusUntracked:
			mask |= CtStatusBitUntracked
		case CtStatusHelper:
			mask |= CtStatusBitHelper
		case CtStatusOffload:
			mask |= CtStatusBitOffload
		case CtStatusHWOffload:
			mask |= CtStatusBitHWOffload
		}
	}
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, mask)
	return buf
}

// CtStatesAreEqual compares two slices of connection tracking states and returns true if they have identical elements.
func CtStatesAreEqual(a1 []string, a2 []string) bool {
	if len(a1) != len(a2) {
		return false
	}

	counts := make(map[string]int, len(a1))
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

// FormatCt converts a `Ct` expression into its string representation, including register, key, source/destination, and direction.
// nftables/expr/ct.go
func FormatCt(c *expr.Ct) string {
	parts := []string{"ct"}

	// Register uint32
	parts = append(parts, fmt.Sprintf("%d", c.Register))

	// SourceRegister bool
	if c.SourceRegister {
		parts = append(parts, fmt.Sprintf("sreg"))
	} else {
		parts = append(parts, fmt.Sprintf("dreg"))
	}

	// Key CtKey
	parts = append(parts, fmt.Sprintf("%s", CtKeyToString(c.Key)))

	// Direction uint32
	parts = append(parts, fmt.Sprintf("%d", c.Direction))

	//fmt.Printf("parts: %+v\n", parts)

	return strings.Join(parts, " ")
}

// SerializeCt serializes a connection tracking (ct) expression into a string representation and returns the string and position.
// It processes various cases like comparison (Cmp), bitwise operations, and lookups, handling them accordingly.
func SerializeCt(ct *expr.Ct, exprs []expr.Any, pos int, sets []*nftables.Set) (string, int) {
	ctStr := fmt.Sprintf("ct %s", CtKeyToString(ct.Key))

	//fmt.Printf("SerializeCT() exprs: %+v\n", exprs)
	//for _, e := range exprs {
	//	fmt.Printf("SerializeCT() e: %+v\n", e)
	//}

	if pos+1 < len(exprs) {
		// Ha következő Cmp
		if cmp, ok := exprs[pos+1].(*expr.Cmp); ok {
			//fmt.Printf("SerializeCT() cmp: %+v\n", cmp)
			value := formatCtValue(ct.Key, cmp.Data)
			op := serializeCmpOp(cmp, value)
			//fmt.Printf("177: value: %s - op: %+v\n", value, op)
			return fmt.Sprintf("%s %s", ctStr, op), 2
		}
		// Ha következő Bitwise
		if bitwise, ok := exprs[pos+1].(*expr.Bitwise); ok {
			//fmt.Printf("SerializeCT() bitwise: %+v\n", bitwise)
			value := formatCtValue(ct.Key, bitwise.Mask)

			isXorZero := true
			for _, v := range bitwise.Xor {
				if v != 0 {
					isXorZero = false
					break
				}
			}

			if isXorZero {
				return fmt.Sprintf("%s %s", ctStr, value), 3
			}
		}
		// Ha következő Lookup
		if lookup, ok := exprs[pos+1].(*expr.Lookup); ok {
			//fmt.Printf("SerializeCT() lookup: %+v\n", lookup)
			return SerializeLookupWithKey(lookup, ctStr, ct.Key, sets), 2
		}
		// Ha következő Range
		if rng, ok := exprs[pos+1].(*expr.Range); ok {
			from := formatCtValue(ct.Key, rng.FromData)
			to := formatCtValue(ct.Key, rng.ToData)
			if ct.Key == expr.CtKeyEXPIRATION && len(rng.FromData) >= 4 {
				from = formatCtValue(ct.Key, rng.FromData)
				to = formatCtValue(ct.Key, rng.ToData)
			}
			op := ""
			if rng.Op == expr.CmpOpNeq {
				op = "!= "
			}
			return fmt.Sprintf("%s %s%s-%s", ctStr, op, from, to), 2
		}
	}

	return ctStr, 1
}

// ExprCtToCt parses an expr.Ct object with additional expressions and sets to generate a Ct struct and skip count.
func ExprCtToCt(ct *expr.Ct, exprs []expr.Any, pos int, sets []*nftables.Set) (Ct, int) {
	ctObj := Ct{}
	skip := 1

	if pos+1 < len(exprs) {
		switch v := exprs[pos+1].(type) {
		case *expr.Cmp:
			// Egyszerű összehasonlítás (pl. ct direction original)
			value := DecodeCTValue(ct.Key, v.Data)
			fillCtField(&ctObj, ct.Key, value)
			if ct.Key == expr.CtKeyEXPIRATION {
				ctObj.ExpirationOp = CmpOpToString(v.Op)
			}
			skip = 2

		case *expr.Bitwise:
			// Maszkolt állapotok (pl. ct state {established, related} vagy ct status {expected})
			decoded := DecodeCTValue(ct.Key, v.Mask)

			isXorZero := true
			for _, val := range v.Xor {
				if val != 0 {
					isXorZero = false
					break
				}
			}

			if isXorZero {
				switch d := decoded.(type) {
				case CtState:
					ctObj.State = append(ctObj.State, d)
				case []CtState:
					ctObj.State = append(ctObj.State, d...)
				case CtStatus:
					ctObj.Status = append(ctObj.Status, d)
				case []CtStatus:
					ctObj.Status = append(ctObj.Status, d...)
				}
			}
			skip = 2

			// Ha a bitwise után van még egy CMP, azt is átugorjuk (általában a maszkolás eredményét nézi)
			if pos+2 < len(exprs) {
				if _, ok := exprs[pos+2].(*expr.Cmp); ok {
					skip = 3
				}
			}

		case *expr.Lookup:
			// Halmaz alapú keresés (pl. ct mark @trusted_marks)
			// A lookup-ból kinyerjük a set elemeit és betöltjük a megfelelő mezőbe
			if ct.Key == expr.CtKeyEXPIRATION && v.Invert {
				ctObj.ExpirationOp = "!="
			}
			for _, set := range sets {
				if set.Name == v.SetName || (v.SetName == "" && set.ID == v.SetID) {
					// Megjegyzés: Itt a TUI környezetben nem biztos, hogy le tudjuk kérni az elemeket
					// de a már meglévő set.Elements-et (ha van) használhatjuk.
					// A valódi nftables.Conn.GetSetElements hívás itt problémás lehet tesztekben.
					// Mivel nftables.Set-ben nincs közvetlen Elements mező.
					// In a real TUI environment, sets are usually pre-fetched.
					// For now, we keep the structure but avoid direct connection calls here if possible,
					// or use the provided sets.
					conn := &nftables.Conn{}
					elements, err := conn.GetSetElements(set)
					if err == nil {
						for _, el := range elements {
							val := DecodeCTValue(ct.Key, el.Key)
							if ct.Key == expr.CtKeyEXPIRATION {
								if u, ok := val.(uint32); ok {
									ctObj.ExpirationSet = append(ctObj.ExpirationSet, FormatDuration(u))
								}
							} else {
								fillCtField(&ctObj, ct.Key, val)
							}
						}
					}
				}
			}
			skip = 2

		case *expr.Range:
			if ct.Key == expr.CtKeyEXPIRATION {
				from := DecodeCTValue(ct.Key, v.FromData)
				to := DecodeCTValue(ct.Key, v.ToData)
				if f, ok := from.(uint32); ok {
					if t, ok := to.(uint32); ok {
						ctObj.ExpirationRange = &CtRange{From: f, To: t}
						if v.Op == expr.CmpOpNeq {
							ctObj.ExpirationOp = "!="
						}
					}
				}
			}
			skip = 2
		}
	}

	//fmt.Printf("240: ctObj: %+v", ctObj)

	return ctObj, skip
}

// GetCtOp retrieves the comparison operator from the exprs slice at the specified position or returns the default equal operator.
func GetCtOp(exprs []expr.Any, pos int) expr.CmpOp {
	if pos+1 < len(exprs) {
		if cmp, ok := exprs[pos+1].(*expr.Cmp); ok {
			return cmp.Op
		}
	}
	return expr.CmpOpEq // Alapértelmezett a ==
}

// fillCtField updates the specified field in the Ct struct based on the provided key and value.
func fillCtField(ct *Ct, key expr.CtKey, value interface{}) {
	if value == nil {
		return
	}

	switch key {
	case expr.CtKeySTATE:
		switch v := value.(type) {
		case CtState:
			ct.State = append(ct.State, v)
		case []CtState:
			ct.State = append(ct.State, v...)
		}
	case expr.CtKeyDIRECTION:
		if d, ok := value.(CtDirection); ok {
			ct.Direction = d
		} else if s, ok := value.(string); ok {
			ct.Direction = CtDirection(s)
		} else if u, ok := value.(uint8); ok {
			if u == 0 {
				ct.Direction = CtDirectionOriginal
			} else {
				ct.Direction = CtDirectionReply
			}
		}
	case expr.CtKeySTATUS:
		switch v := value.(type) {
		case CtStatus:
			ct.Status = append(ct.Status, v)
		case []CtStatus:
			ct.Status = append(ct.Status, v...)
		}
	case expr.CtKeyMARK:
		if v, ok := value.(uint32); ok {
			ct.Mark = v
		}
	case expr.CtKeyEXPIRATION:
		if v, ok := value.(uint32); ok {
			ct.Expiration = v
		}
	case expr.CtKeyPROTOCOL:
		if v, ok := value.(uint8); ok {
			ct.Protocol = v
		} else if v, ok := value.(uint32); ok {
			ct.Protocol = uint8(v)
		}
	case expr.CtKeyL3PROTOCOL:
		if v, ok := value.(uint8); ok {
			ct.L3Protocol = v
		} else if v, ok := value.(uint32); ok {
			ct.L3Protocol = uint8(v)
		}
	case expr.CtKeySRC:
		if v, ok := value.(string); ok {
			ct.Src = v
		}
	case expr.CtKeyDST:
		if v, ok := value.(string); ok {
			ct.Dst = v
		}
	case expr.CtKeyPROTOSRC:
		if v, ok := value.(uint16); ok {
			ct.ProtoSrc = v
		} else if v, ok := value.(uint32); ok {
			ct.ProtoSrc = uint16(v)
		}
	case expr.CtKeyPROTODST:
		if v, ok := value.(uint16); ok {
			ct.ProtoDst = v
		} else if v, ok := value.(uint32); ok {
			ct.ProtoDst = uint16(v)
		}
	case expr.CtKeyPKTS:
		if v, ok := value.(uint64); ok {
			ct.Pkts = v
		} else if v, ok := value.(uint32); ok {
			ct.Pkts = uint64(v)
		}
	case expr.CtKeyBYTES:
		if v, ok := value.(uint64); ok {
			ct.Bytes = v
		} else if v, ok := value.(uint32); ok {
			ct.Bytes = uint64(v)
		}
	case expr.CtKeyAVGPKT:
		if v, ok := value.(uint32); ok {
			ct.Avgpkt = v
		}
	case expr.CtKeyHELPER:
		if v, ok := value.(string); ok {
			ct.Helper = v
		}
	case expr.CtKeyZONE:
		if v, ok := value.(uint16); ok {
			ct.Zone = v
		} else if v, ok := value.(uint32); ok {
			ct.Zone = uint16(v)
		}
	case expr.CtKeyEVENTMASK:
		if v, ok := value.(uint32); ok {
			ct.Eventmask = v
		}
	}
}

// DecodeCTValue decodes connection tracking data based on the specified CtKey and byte slice. Returns a structured result.
func DecodeCTValue(key expr.CtKey, data []byte) interface{} {
	if key == expr.CtKeySTATE && len(data) >= 4 {
		state := binary.LittleEndian.Uint32(data[:4])
		states := []CtState{}
		if state&expr.CtStateBitINVALID != 0 {
			states = append(states, CtStateInvalid)
		}
		if state&expr.CtStateBitESTABLISHED != 0 {
			states = append(states, CtStateEstablished)
		}
		if state&expr.CtStateBitRELATED != 0 {
			states = append(states, CtStateRelated)
		}
		if state&expr.CtStateBitNEW != 0 {
			states = append(states, CtStateNew)
		}
		if state&expr.CtStateBitUNTRACKED != 0 {
			states = append(states, CtStateUntracked)
		}
		if len(states) == 1 {
			return states[0]
		}
		return states
	}
	if key == expr.CtKeyDIRECTION && len(data) >= 1 {
		var dir uint32
		if len(data) >= 4 {
			dir = binary.LittleEndian.Uint32(data[:4])
		} else {
			dir = uint32(data[0])
		}

		if dir == 0 {
			return CtDirectionOriginal
		}
		return CtDirectionReply
	}

	if key == expr.CtKeySTATUS && len(data) >= 4 {
		status := binary.LittleEndian.Uint32(data[:4])
		statuses := []CtStatus{}
		// Itt érdemes lenne a többi bitet is vizsgálni, ha szükséges
		if status&CtStatusBitExpected != 0 {
			statuses = append(statuses, CtStatusExpected)
		}
		if status&CtStatusBitSeenReply != 0 {
			statuses = append(statuses, CtStatusSeenReply)
		}
		if status&CtStatusBitAssured != 0 {
			statuses = append(statuses, CtStatusAssured)
		}
		if status&CtStatusBitConfirmed != 0 {
			statuses = append(statuses, CtStatusConfirmed)
		}
		if status&CtStatusBitSnat != 0 {
			statuses = append(statuses, CtStatusSnat)
		}
		if status&CtStatusBitDnat != 0 {
			statuses = append(statuses, CtStatusDnat)
		}
		if status&CtStatusBitSeqAdjust != 0 {
			statuses = append(statuses, CtStatusSeqAdjust)
		}
		if status&CtStatusBitSnatDone != 0 {
			statuses = append(statuses, CtStatusSNatDone)
		}
		if status&CtStatusBitDnatDone != 0 {
			statuses = append(statuses, CtStatusDNatDone)
		}
		if status&CtStatusBitDying != 0 {
			statuses = append(statuses, CtStatusDying)
		}
		if status&CtStatusBitFixedTimeout != 0 {
			statuses = append(statuses, CtStatusFixedTimeout)
		}
		if status&CtStatusBitHelper != 0 {
			statuses = append(statuses, CtStatusHelper)
		}
		if status&CtStatusBitOffload != 0 {
			statuses = append(statuses, CtStatusOffload)
		}
		if status&CtStatusBitHWOffload != 0 {
			statuses = append(statuses, CtStatusHWOffload)
		}
		if len(statuses) == 1 {
			return statuses[0]
		}
		return statuses
	}

	if key == expr.CtKeyEXPIRATION {
		if len(data) >= 4 {
			// A ct expiration általában BigEndian a kernelben, de néha LittleEndian-nek tűnik a regiszterekben
			// Megpróbáljuk mindkét irányból, ha az egyik túl nagy értéket ad
			valBE := binary.BigEndian.Uint32(data[len(data)-4:])
			valLE := binary.LittleEndian.Uint32(data[:4])

			//fmt.Printf("DecodeCTValue: key=%v len=%d BE=%v LE=%v\n", key, len(data), valBE, valLE)

			// Az nftables-ben az expiration általában ms-ben vagy s-ben van.
			// Ha a BE érték irreálisan nagy (pl. > 100 év s-ben), akkor próbáljuk a LE-t.
			// 100 év s-ben kb. 3,153,600,000. 2^32-1 kb. 4,294,967,295.
			// 30 s LE-ben: [30, 0, 0, 0], BE-ként olvasva 30 << 24 = 503,316,480.
			// 30 s BE-ben: [0, 0, 0, 30], BE-ként olvasva 30.
			// 30 s-nak megfelelő ms (30000) BE-ben: [0, 0, 117, 48]
			// 9409d10h8m az 812,964,480 s.
			// 812,964,480 BE-ben: [48, 116, 212, 0]
			// 812,964,480 LE-ben: [0, 212, 116, 48] -> BE-ként olvasva 13943856.

			var val uint32
			if valBE > 1000000 && valLE < 1000000 {
				val = valLE
			} else {
				val = valBE
			}

			// Az nftables a kernelből gyakran ms-ben kapja az expiration értéket, de s-ben jeleníti meg.
			// Ha az érték 30000, az valójában 30s.
			// A 8h20m pontosan 30000 másodperc, ami arra utal, hogy 30000 ms-t kaptunk, de s-ként kezeltük.
			// Ha az érték túl nagynak tűnik, de 1000-rel osztva értelmes, akkor ms-ben van.
			// Ugyanakkor az nftables forráskódja szerint bizonyos kernel verziók óta ez változhat.
			// A legegyszerűbb, ha a 1000-rel való osztást alkalmazzuk, ha az érték > 0 és osztható 1000-rel,
			// vagy ha egy bizonyos küszöb felett van.
			if val >= 1000 {
				// Az nftables CLI-ben is van hasonló logika:
				// div_round_up(timeout, 1000)
				return val / 1000
			}

			return val
		}
		return uint32(0)
	}

	switch key {
	case expr.CtKeyPROTOCOL, expr.CtKeyL3PROTOCOL:
		if len(data) == 1 {
			return data[0]
		}
		if len(data) >= 4 {
			return binary.LittleEndian.Uint32(data[:4])
		}
	case expr.CtKeyPROTOSRC, expr.CtKeyPROTODST:
		if len(data) == 2 {
			return binary.BigEndian.Uint16(data)
		}
		if len(data) >= 4 {
			return uint16(binary.LittleEndian.Uint32(data[:4]))
		}
	case expr.CtKeySRC, expr.CtKeyDST:
		if len(data) == 4 {
			return net.IP(data).String()
		}
		if len(data) == 16 {
			return net.IP(data).String()
		}
	case expr.CtKeyPKTS, expr.CtKeyBYTES:
		if len(data) == 8 {
			return binary.BigEndian.Uint64(data)
		}
		if len(data) >= 4 {
			return uint64(binary.LittleEndian.Uint32(data[:4]))
		}
	case expr.CtKeyHELPER:
		return strings.TrimRight(string(data), "\x00")
	case expr.CtKeyZONE:
		if len(data) == 2 {
			return binary.LittleEndian.Uint16(data)
		}
		if len(data) >= 4 {
			return uint16(binary.LittleEndian.Uint32(data[:4]))
		}
	}

	//fmt.Printf("444. data: %+v\n", data)
	if len(data) == 4 {
		return binary.LittleEndian.Uint32(data)
	}
	//fmt.Printf("448. data: %+v\n", data)
	return data
}

// formatCtValue formats a connection tracking value based on the key and data, returning a human-readable string representation.
func formatCtValue(key expr.CtKey, data []byte) string {
	//fmt.Printf("\n\n163: %s\n\n", data)
	if key == expr.CtKeySTATE && len(data) == 4 {
		state := binary.LittleEndian.Uint32(data)
		var states []string
		if state&expr.CtStateBitINVALID != 0 {
			states = append(states, string(CtStateInvalid))
		}
		if state&expr.CtStateBitESTABLISHED != 0 {
			states = append(states, string(CtStateEstablished))
		}
		if state&expr.CtStateBitRELATED != 0 {
			states = append(states, string(CtStateRelated))
		}
		if state&expr.CtStateBitNEW != 0 {
			states = append(states, string(CtStateNew))
		}
		if state&expr.CtStateBitUNTRACKED != 0 {
			states = append(states, string(CtStateUntracked))
		}
		if len(states) == 1 {
			return states[0]
		}
		if len(states) > 1 {
			return "{" + strings.Join(states, ", ") + "}"
		}
	}
	if key == expr.CtKeyDIRECTION {
		return fmt.Sprintf("%s", DecodeCTValue(key, data))
	}
	if key == expr.CtKeySTATUS && len(data) == 4 {
		status := binary.LittleEndian.Uint32(data)
		var statuses []string
		if status&CtStatusBitExpected != 0 {
			statuses = append(statuses, string(CtStatusExpected))
		}
		if status&CtStatusBitSeenReply != 0 {
			statuses = append(statuses, string(CtStatusSeenReply))
		}
		if status&CtStatusBitAssured != 0 {
			statuses = append(statuses, string(CtStatusAssured))
		}
		if status&CtStatusBitConfirmed != 0 {
			statuses = append(statuses, string(CtStatusConfirmed))
		}
		if status&CtStatusBitSnat != 0 {
			statuses = append(statuses, string(CtStatusSnat))
		}
		if status&CtStatusBitDnat != 0 {
			statuses = append(statuses, string(CtStatusDnat))
		}
		if status&CtStatusBitSeqAdjust != 0 {
			statuses = append(statuses, string(CtStatusSeqAdjust))
		}
		if status&CtStatusBitSnatDone != 0 {
			statuses = append(statuses, string(CtStatusSNatDone))
		}
		if status&CtStatusBitDnatDone != 0 {
			statuses = append(statuses, string(CtStatusDNatDone))
		}
		if status&CtStatusBitDying != 0 {
			statuses = append(statuses, string(CtStatusDying))
		}
		if status&CtStatusBitFixedTimeout != 0 {
			statuses = append(statuses, string(CtStatusFixedTimeout))
		}
		if status&CtStatusBitHelper != 0 {
			statuses = append(statuses, string(CtStatusHelper))
		}
		if status&CtStatusBitOffload != 0 {
			statuses = append(statuses, string(CtStatusOffload))
		}
		if status&CtStatusBitHWOffload != 0 {
			statuses = append(statuses, string(CtStatusHWOffload))
		}
		if len(statuses) == 1 {
			return statuses[0]
		}
		if len(statuses) > 1 {
			return "{" + strings.Join(statuses, ", ") + "}"
		}
	}
	if key == expr.CtKeyMARK {
		//fmt.Printf("535. mark data: %+v", data)
		if len(data) == 4 {
			val := binary.LittleEndian.Uint32(data)
			return fmt.Sprintf("0x%08x", val)
		}
		return fmt.Sprintf("0x%x", data)
	}

	if key == expr.CtKeyEXPIRATION && len(data) >= 4 {
		val := DecodeCTValue(key, data).(uint32)
		return FormatDuration(val)
	}

	decoded := DecodeCTValue(key, data)
	switch v := decoded.(type) {
	case string:
		return v
	case uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%v", v)
	}

	return formatData(data)
}

func FormatDuration(seconds uint32) string {
	if seconds == 0 {
		return "0s"
	}

	var parts []string
	days := seconds / 86400
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
		seconds %= 86400
	}
	hours := seconds / 3600
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
		seconds %= 3600
	}
	minutes := seconds / 60
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
		seconds %= 60
	}
	if seconds > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%ds", seconds))
	}

	return strings.Join(parts, "")
}
