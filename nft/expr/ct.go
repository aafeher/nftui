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
	State      []CtState   `json:"state,omitempty"`
	Direction  CtDirection `json:"direction,omitempty"`
	Status     []CtStatus  `json:"status,omitempty"`
	Mark       uint32      `json:"mark,omitempty"`
	Expiration uint32      `json:"expiration,omitempty"`
	Helper     string      `json:"helper,omitempty"`
	L3Protocol uint8       `json:"l3protocol,omitempty"`
	Protocol   uint8       `json:"protocol,omitempty"`
	Src        string      `json:"src,omitempty"`
	Dst        string      `json:"dst,omitempty"`
	ProtoSrc   uint16      `json:"proto_src,omitempty"`
	ProtoDst   uint16      `json:"proto_dst,omitempty"`
	Labels     []string    `json:"labels,omitempty"`
	Bytes      uint64      `json:"bytes,omitempty"`
	Pkts       uint64      `json:"packets,omitempty"`
	Avgpkt     uint32      `json:"avgpkt,omitempty"`
	Zone       uint16      `json:"zone,omitempty"`
	Eventmask  uint32      `json:"eventmask,omitempty"`
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

	/* template 2048 */
	/* untracked 4096 */

	CtStatusBitHelper    uint32 = 8192
	CtStatusBitOffload   uint32 = 16384
	CtStatusBitHWOffload uint32 = 32768

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

func CtStateStringToStates(ctStateStrings []string) []CtState {
	states := []CtState{}
	for _, s := range ctStateStrings {
		states = append(states, CtStateStringToState(s))
	}
	return states
}

func CtStateToStateStrings(ctStates []CtState) []string {
	stateStrings := []string{}
	for _, s := range ctStates {
		stateStrings = append(stateStrings, string(s))
	}
	return stateStrings
}

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
			return SerializeLookup(lookup, ctStr, sets), 2
		}
	}

	return ctStr, 1
}

func ExprCtToCt(ct *expr.Ct, exprs []expr.Any, pos int, sets []*nftables.Set) (Ct, int) {
	ctObj := Ct{}
	skip := 1

	if pos+1 < len(exprs) {
		switch v := exprs[pos+1].(type) {
		case *expr.Cmp:
			// Egyszerű összehasonlítás (pl. ct direction original)
			value := DecodeCTValue(ct.Key, v.Data)
			fillCtField(&ctObj, ct.Key, value)
			skip = 2

		case *expr.Bitwise:
			// Maszkolt állapotok (pl. ct state {established, related})
			decoded := DecodeCTValue(expr.CtKeySTATE, v.Mask)

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
							fillCtField(&ctObj, ct.Key, val)
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

func GetCtOp(exprs []expr.Any, pos int) expr.CmpOp {
	if pos+1 < len(exprs) {
		if cmp, ok := exprs[pos+1].(*expr.Cmp); ok {
			return cmp.Op
		}
	}
	return expr.CmpOpEq // Alapértelmezett a ==
}

// fillCtField egy segédfüggvény, ami a kulcs alapján a megfelelő mezőbe teszi az értéket
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

	decoded := DecodeCTValue(key, data)
	switch v := decoded.(type) {
	case string:
		return v
	case uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%v", v)
	}

	return formatData(data)
}
