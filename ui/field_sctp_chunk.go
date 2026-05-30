package ui

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"nftui/nft"
	nftexpr "nftui/nft/expr"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// SctpChunkField edits the `sctp chunk <type> [<field> <value>]` match.
//
// Three slots:
//
//	0 — chunk-type Select (off + 21 RFC 4960 / extension chunk types)
//	1 — sub-field Select   (options refresh from nftexpr.ChunkFields(ct)
//	                        whenever slot 0 changes; "off" = bare presence)
//	2 — value NumberInput  (BE-encoded into Len bytes for the kernel)
//
// Save emits either:
//
//	bare presence:  Exthdr{Op=SCTP, Type=N, Offset=0, Len=1, Flags=F_PRESENT}
//	                Cmp{Eq, [0x01]}
//	field match:    Exthdr{Op=SCTP, Type=N, Offset=O, Len=L}
//	                Cmp{Eq, BE-encoded value over L bytes}
//
// The parser path (`nft/rule.go::sctpChunkCompareToCondition`) decodes both.
type SctpChunkField struct {
	chunkSelect    Select
	subFieldSelect Select
	valueInput     NumberInput

	// activeChunkType lets us notice when the chunk-type Select changes
	// (slot 0) so we can rebuild the sub-field Select options (slot 1)
	// in lockstep. Re-derived on every Update.
	activeChunkType string

	// Snapshot of what landed in the rule when the editor opened, so
	// Changed() / Save() can be no-ops if the user didn't touch anything.
	originalChunk    *nftexpr.ChunkType
	originalField    string
	originalValue    uint64
	originalRendered string
}

// NewSctpChunkField builds the editor from the parsed Rule. If the rule
// carries an existing `sctp chunk` match, the Select / sub-field / value
// inputs are pre-populated so re-saving without edits is a no-op.
func NewSctpChunkField(rd *nft.Rule) *SctpChunkField {
	chunkOpts := append([]string{"off"}, nftexpr.ChunkTypeNames()...)
	chunkSel := NewSelect(chunkOpts)

	// Sub-field Select starts with just "off"; rebuilt on chunk-type change.
	subFieldSel := NewSelect([]string{"off"})

	// 8-byte upper bound — covers every documented field width (1, 2, 4).
	// Validation happens on Save when we know the actual sub-field's Len.
	valInput := NewNumberInput(0, 4_294_967_295)

	f := &SctpChunkField{
		chunkSelect:    chunkSel,
		subFieldSelect: subFieldSel,
		valueInput:     valInput,
	}

	for _, c := range rd.Conditions {
		if c.SctpChunk == nil {
			continue
		}
		ct := c.SctpChunk.ChunkType
		f.originalChunk = &ct
		f.originalField = c.SctpChunk.Field
		f.originalValue = asUint64(c.SctpChunk.Value)

		name := nftexpr.ChunkTypeName(ct)
		if name != "" {
			if idx := indexOfString(chunkOpts, name); idx >= 0 {
				f.chunkSelect.Selected = idx
			}
		}
		f.activeChunkType = name
		f.rebuildSubFieldOptions()

		// Pre-select the sub-field option matching the existing match.
		if c.SctpChunk.Field != "" {
			subOpts := subFieldOptionsFor(ct)
			if idx := indexOfString(subOpts, c.SctpChunk.Field); idx >= 0 {
				f.subFieldSelect.Selected = idx
			}
			f.valueInput.SetValue(strconv.FormatUint(f.originalValue, 10))
			f.originalRendered = fmt.Sprintf("sctp chunk %s %s %d", name, c.SctpChunk.Field, f.originalValue)
		} else {
			f.originalRendered = fmt.Sprintf("sctp chunk %s", name)
		}
		break
	}
	return f
}

// asUint64 normalises the parser's `any`-typed sub-field value (uint8 /
// uint16 / uint32 / uint64 / int, depending on the source Cmp's Len) into
// the uint64 form NumberInput uses.
func asUint64(v any) uint64 {
	switch x := v.(type) {
	case uint8:
		return uint64(x)
	case uint16:
		return uint64(x)
	case uint32:
		return uint64(x)
	case uint64:
		return x
	case int:
		return uint64(x)
	}
	return 0
}

// indexOfString returns the first index of s in xs, or -1.
func indexOfString(xs []string, s string) int {
	for i, x := range xs {
		if x == s {
			return i
		}
	}
	return -1
}

// subFieldOptionsFor returns the Select options for a chunk type: "off"
// (bare presence) followed by each documented fixed-offset sub-field's
// name. Chunk types with no fixed sub-fields (HEARTBEAT, ABORT, ERROR,
// COOKIE_*, SHUTDOWN_ACK, SHUTDOWN_COMPLETE) return just `["off"]`.
func subFieldOptionsFor(ct nftexpr.ChunkType) []string {
	fields := nftexpr.ChunkFields(ct)
	out := make([]string, 0, len(fields)+1)
	out = append(out, "off")
	for _, f := range fields {
		out = append(out, f.Name)
	}
	return out
}

// rebuildSubFieldOptions refreshes slot 1's Select to the options for the
// currently-selected chunk type. Called whenever the chunk-type Select's
// value changes (detected in Update). Resets the sub-field to "off" so
// stale Selected indices from a previous chunk type don't accidentally
// reference a wrong field.
func (f *SctpChunkField) rebuildSubFieldOptions() {
	chunkName := f.chunkSelect.Value()
	if chunkName == "off" {
		f.subFieldSelect = NewSelect([]string{"off"})
		f.valueInput.SetValue("")
		return
	}
	ct, ok := nftexpr.ChunkTypeFromString(chunkName)
	if !ok {
		f.subFieldSelect = NewSelect([]string{"off"})
		return
	}
	f.subFieldSelect = NewSelect(subFieldOptionsFor(ct))
}

func (f *SctpChunkField) FocusSlots() int { return 3 }

func (f *SctpChunkField) Focus(subIndex int) {
	f.Blur()
	switch subIndex {
	case 0:
		f.chunkSelect.Focus()
	case 1:
		f.subFieldSelect.Focus()
	case 2:
		f.valueInput.Focus()
	}
}

func (f *SctpChunkField) Blur() {
	f.chunkSelect.Blur()
	f.subFieldSelect.Blur()
	f.valueInput.Blur()
}

func (f *SctpChunkField) Changed() bool {
	chosen := f.chunkSelect.Value()
	if chosen == "off" {
		return f.originalChunk != nil
	}
	// Chunk type differs from original?
	if f.originalChunk == nil || nftexpr.ChunkTypeName(*f.originalChunk) != chosen {
		return true
	}
	// Same chunk type — check sub-field.
	subChosen := f.subFieldSelect.Value()
	if subChosen == "off" {
		// User wants bare presence; differs from original only if the
		// original had a sub-field constraint.
		return f.originalField != ""
	}
	if subChosen != f.originalField {
		return true
	}
	// Same chunk + same sub-field — check value.
	v, err := f.valueInput.GetUint64()
	if err != nil {
		return false
	}
	return v != f.originalValue
}

func (f *SctpChunkField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	// Route the keystroke to whichever sub-input is focused.
	switch {
	case f.chunkSelect.Focused:
		f.chunkSelect, cmd = f.chunkSelect.Update(msg)
		// If the chunk type changed, refresh slot 1's option list.
		if f.chunkSelect.Value() != f.activeChunkType {
			f.activeChunkType = f.chunkSelect.Value()
			f.rebuildSubFieldOptions()
		}
	case f.subFieldSelect.Focused:
		f.subFieldSelect, cmd = f.subFieldSelect.Update(msg)
	case f.valueInput.Focused():
		f.valueInput, cmd = f.valueInput.Update(msg)
	}
	return cmd
}

func (f *SctpChunkField) View() string {
	style := grayStyle
	if f.Changed() {
		style = yellowStyle
	}
	var b strings.Builder
	b.WriteString(style.Render("SCTP chunk: "))
	b.WriteString(f.chunkSelect.View())
	// Sub-field row only when a chunk type is selected; "off" mode hides
	// the noise (a single "[off]" Select would be misleading).
	if f.chunkSelect.Value() != "off" {
		b.WriteString("\n")
		b.WriteString(grayStyle.Render("           sub-field: "))
		b.WriteString(f.subFieldSelect.View())
		if f.subFieldSelect.Value() != "off" {
			b.WriteString("  value: ")
			b.WriteString(f.valueInput.View())
		}
	}
	return b.String()
}

// Save reconciles the editor state into rule.Exprs.
//
//   - "off" chunk-type             → strip every existing SCTP-chunk pair.
//   - chunk-type set, sub-field "off" → strip, append bare-presence pair.
//   - chunk-type set, sub-field set, valid value
//     → strip, append `Exthdr{Op=SCTP,
//     Offset=O, Len=L} + Cmp{Eq,
//     BE-encoded value}`.
//   - chunk-type set, sub-field set, invalid/empty value
//     → strip, append bare presence (we
//     refuse to emit an Exthdr with no
//     value rather than silently zero it).
func (f *SctpChunkField) Save(rule *nftables.Rule) {
	chosen := f.chunkSelect.Value()
	rule.Exprs = stripSctpChunkExprs(rule.Exprs)

	if chosen == "off" {
		f.originalChunk = nil
		f.originalField = ""
		f.originalValue = 0
		f.originalRendered = ""
		return
	}

	ct, ok := nftexpr.ChunkTypeFromString(chosen)
	if !ok {
		return // defensive — Select should never yield an unknown string
	}

	subChosen := f.subFieldSelect.Value()
	if subChosen == "off" || subChosen == "" {
		// Bare presence pair.
		rule.Exprs = append(rule.Exprs,
			&expr.Exthdr{
				DestRegister: 1,
				Type:         uint8(ct),
				Offset:       0,
				Len:          1,
				Flags:        nftexpr.SctpExthdrFlagPresent,
				Op:           expr.ExthdrOp(nftexpr.SctpExthdrOp),
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x01}},
		)
		c := ct
		f.originalChunk = &c
		f.originalField = ""
		f.originalValue = 0
		f.originalRendered = fmt.Sprintf("sctp chunk %s", chosen)
		return
	}

	// Sub-field match. Look up offset/len from the per-type metadata.
	var field nftexpr.ChunkField
	for _, cf := range nftexpr.ChunkFields(ct) {
		if cf.Name == subChosen {
			field = cf
			break
		}
	}
	if field.Name == "" {
		// Sub-field name not found — shouldn't happen because the Select
		// is built from ChunkFields(ct). Defensive bare-presence fallback.
		return
	}
	val, err := f.valueInput.GetUint64()
	if err != nil {
		// Empty / invalid input; degrade to bare presence rather than
		// emitting a zero-value match the user didn't ask for.
		rule.Exprs = append(rule.Exprs,
			&expr.Exthdr{
				DestRegister: 1,
				Type:         uint8(ct),
				Offset:       0,
				Len:          1,
				Flags:        nftexpr.SctpExthdrFlagPresent,
				Op:           expr.ExthdrOp(nftexpr.SctpExthdrOp),
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x01}},
		)
		c := ct
		f.originalChunk = &c
		f.originalField = ""
		f.originalValue = 0
		f.originalRendered = fmt.Sprintf("sctp chunk %s", chosen)
		return
	}

	rule.Exprs = append(rule.Exprs,
		&expr.Exthdr{
			DestRegister: 1,
			Type:         uint8(ct),
			Offset:       field.Offset,
			Len:          field.Len,
			Op:           expr.ExthdrOp(nftexpr.SctpExthdrOp),
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: encodeSubFieldValue(val, field.Len)},
	)

	c := ct
	f.originalChunk = &c
	f.originalField = subChosen
	f.originalValue = val
	f.originalRendered = fmt.Sprintf("sctp chunk %s %s %d", chosen, subChosen, val)
}

// encodeSubFieldValue encodes v big-endian into exactly length bytes. The
// kernel stores SCTP chunk fields BE (RFC 4960 §3.3); the parser's
// `decodeExthdrValue` reads BE too, so this is the inverse. length is one
// of 1 / 2 / 4 in practice (every documented sub-field).
func encodeSubFieldValue(v uint64, length uint32) []byte {
	switch length {
	case 1:
		return []byte{byte(v)}
	case 2:
		out := make([]byte, 2)
		binary.BigEndian.PutUint16(out, uint16(v))
		return out
	case 4:
		out := make([]byte, 4)
		binary.BigEndian.PutUint32(out, uint32(v))
		return out
	case 8:
		out := make([]byte, 8)
		binary.BigEndian.PutUint64(out, v)
		return out
	}
	// Defensive: every documented sub-field uses 1/2/4; anything else is
	// either a parser bug or an undocumented kernel addition. Return a
	// zero-length slice so the kernel rejects with a clear error rather
	// than silently truncating.
	return nil
}

// stripSctpChunkExprs returns exprs with every Exthdr{Op=SCTP} (and the Cmp
// it loads into the register, if it's the very next expression) removed.
// Conservative: if the Cmp that follows an SCTP Exthdr targets a different
// register, we leave the Cmp in place — it belongs to a different match.
func stripSctpChunkExprs(exprs []expr.Any) []expr.Any {
	out := make([]expr.Any, 0, len(exprs))
	for i := 0; i < len(exprs); i++ {
		eh, ok := exprs[i].(*expr.Exthdr)
		if !ok || uint32(eh.Op) != nftexpr.SctpExthdrOp {
			out = append(out, exprs[i])
			continue
		}
		if i+1 < len(exprs) {
			if c, ok := exprs[i+1].(*expr.Cmp); ok && c.Register == eh.DestRegister {
				i++ // skip the Cmp too
			}
		}
	}
	return out
}
