package ui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"nftui/nft"
)

// Reject type display strings shown in the Select. The "tcp reset" entry uses a
// space because that is the nft CLI's literal form ("reject with tcp reset").
const (
	rejectTypeICMP     = "icmp"
	rejectTypeICMPv6   = "icmpv6"
	rejectTypeICMPX    = "icmpx"
	rejectTypeTCPReset = "tcp reset"
)

// Ordered name slices used to populate the code Select. Wire codes are looked
// up via the reverse maps below. The first entry is the family default — when
// the user has not changed the code we keep that default selected.
var (
	icmpRejectCodeOrder = []string{
		"net-unreachable",
		"host-unreachable",
		"prot-unreachable",
		"port-unreachable",
		"net-redirect",
		"net-prohibited",
		"host-prohibited",
		"admin-prohibited",
	}
	icmpRejectNameToCode = map[string]uint8{
		"net-unreachable":  0,
		"host-unreachable": 1,
		"prot-unreachable": 2,
		"port-unreachable": 3,
		"net-redirect":     5,
		"net-prohibited":   9,
		"host-prohibited":  10,
		"admin-prohibited": 13,
	}

	icmpv6RejectCodeOrder = []string{
		"no-route",
		"admin-prohibited",
		"addr-unreachable",
		"port-unreachable",
		"policy-fail",
		"reject-route",
	}
	icmpv6RejectNameToCode = map[string]uint8{
		"no-route":         0,
		"admin-prohibited": 1,
		"addr-unreachable": 3,
		"port-unreachable": 4,
		"policy-fail":      5,
		"reject-route":     6,
	}

	icmpxRejectCodeOrder = []string{
		"no-route",
		"port-unreachable",
		"host-unreachable",
		"admin-prohibited",
	}
	icmpxRejectNameToCode = map[string]uint8{
		"no-route":         0,
		"port-unreachable": 1,
		"host-unreachable": 2,
		"admin-prohibited": 3,
	}
)

// RejectField edits a rule's reject statement (type + optional ICMP-style code).
// FocusSlots reports 2 when the selected type is an ICMP-family reject (kind + code),
// 1 when the selected type is "tcp reset" (code is not applicable).
// If the rule does not contain a reject statement the field is read-only.
type RejectField struct {
	family       nftables.TableFamily
	typeOptions  []string // depends on family
	typeSelect   Select
	codeSelect   Select // populated based on currently selected type
	hasReject    bool
	originalType nft.RejectType
	originalCode uint8
	originalName string // human name of the original code (for "current" preview)
}

// NewRejectField constructs the reject editor for the given rule (parsed view + family).
func NewRejectField(rd *nft.Rule, family nftables.TableFamily) *RejectField {
	typeOptions := rejectTypeOptionsForFamily(family)
	typeSelect := NewSelect(typeOptions)

	var origType nft.RejectType
	var origCode uint8
	hasReject := false
	for _, a := range rd.Actions {
		if a.Type == nft.ActionTypeReject && a.Reject != nil {
			origType = a.Reject.Type
			origCode = a.Reject.Code
			hasReject = true
			break
		}
	}

	displayType := mapWireTypeToDisplay(origType, family)
	if hasReject {
		typeSelect.SetValue(displayType)
	} else if len(typeOptions) > 0 {
		typeSelect.SetValue(typeOptions[0])
	}

	codeOptions, _ := codeOrderForDisplayType(displayType)
	codeSelect := NewSelect(codeOptions)
	origName := lookupCodeName(displayType, origCode)
	if hasReject && origName != "" {
		codeSelect.SetValue(origName)
	}

	return &RejectField{
		family:       family,
		typeOptions:  typeOptions,
		typeSelect:   typeSelect,
		codeSelect:   codeSelect,
		hasReject:    hasReject,
		originalType: origType,
		originalCode: origCode,
		originalName: origName,
	}
}

// rejectTypeOptionsForFamily returns the set of reject types the user can
// pick for a given table family. tcp reset is always present (requires the
// rule's existing tcp context to actually apply, but we don't gate the UI).
func rejectTypeOptionsForFamily(family nftables.TableFamily) []string {
	switch family {
	case nftables.TableFamilyIPv4:
		return []string{rejectTypeICMP, rejectTypeTCPReset}
	case nftables.TableFamilyIPv6:
		return []string{rejectTypeICMPv6, rejectTypeTCPReset}
	case nftables.TableFamilyINet, nftables.TableFamilyBridge:
		return []string{rejectTypeICMPX, rejectTypeTCPReset}
	default:
		return []string{rejectTypeTCPReset}
	}
}

// mapWireTypeToDisplay turns the parser's family-collapsed reject type into the
// display string we show in the Select. The parser collapses both ICMP and
// ICMPv6 into nft.RejectTypeICMP, so for ip6 we infer ICMPv6 from the family.
func mapWireTypeToDisplay(t nft.RejectType, family nftables.TableFamily) string {
	switch t {
	case nft.RejectTypeTCPReset:
		return rejectTypeTCPReset
	case nft.RejectTypeICMPX:
		return rejectTypeICMPX
	case nft.RejectTypeICMP:
		switch family {
		case nftables.TableFamilyIPv6:
			return rejectTypeICMPv6
		case nftables.TableFamilyINet, nftables.TableFamilyBridge:
			return rejectTypeICMPX
		default:
			return rejectTypeICMP
		}
	}
	return ""
}

// codeOrderForDisplayType returns the ordered code-name list (and reverse map)
// for the currently displayed reject type. Empty for "tcp reset".
func codeOrderForDisplayType(displayType string) ([]string, map[string]uint8) {
	switch displayType {
	case rejectTypeICMP:
		return icmpRejectCodeOrder, icmpRejectNameToCode
	case rejectTypeICMPv6:
		return icmpv6RejectCodeOrder, icmpv6RejectNameToCode
	case rejectTypeICMPX:
		return icmpxRejectCodeOrder, icmpxRejectNameToCode
	}
	return nil, nil
}

// lookupCodeName resolves a wire code value to its display name for the given
// display type. Empty if no match (e.g. tcp reset or an unknown code).
func lookupCodeName(displayType string, code uint8) string {
	var table map[uint8]string
	switch displayType {
	case rejectTypeICMP:
		table = icmpRejectCodes
	case rejectTypeICMPv6:
		table = icmpv6RejectCodes
	case rejectTypeICMPX:
		table = icmpxRejectCodes
	}
	if table == nil {
		return ""
	}
	return table[code]
}

func (f *RejectField) currentType() string {
	return f.typeSelect.Value()
}

func (f *RejectField) needsCode() bool {
	if !f.hasReject {
		return false
	}
	return f.currentType() != rejectTypeTCPReset
}

func (f *RejectField) FocusSlots() int {
	if f.needsCode() {
		return 2
	}
	return 1
}

func (f *RejectField) Focus(subIndex int) {
	if !f.hasReject {
		return
	}
	if subIndex == 0 {
		f.typeSelect.Focus()
		f.codeSelect.Blur()
		return
	}
	f.codeSelect.Focus()
	f.typeSelect.Blur()
}

func (f *RejectField) Blur() {
	f.typeSelect.Blur()
	f.codeSelect.Blur()
}

func (f *RejectField) Changed() bool {
	if !f.hasReject {
		return false
	}
	displayType := mapWireTypeToDisplay(f.originalType, f.family)
	if f.currentType() != displayType {
		return true
	}
	if f.needsCode() && f.codeSelect.Value() != f.originalName {
		return true
	}
	return false
}

func (f *RejectField) Update(msg tea.Msg) tea.Cmd {
	if !f.hasReject {
		return nil
	}
	var cmd tea.Cmd
	if f.typeSelect.Focused {
		prev := f.typeSelect.Value()
		f.typeSelect, cmd = f.typeSelect.Update(msg)
		if f.typeSelect.Value() != prev {
			// Type changed — rebuild the code Select to match the new type.
			f.rebuildCodeSelect()
		}
		if !f.needsCode() {
			f.codeSelect.Blur()
		}
	} else if f.codeSelect.Focused {
		f.codeSelect, cmd = f.codeSelect.Update(msg)
	}
	return cmd
}

// rebuildCodeSelect reconfigures the code Select for the currently selected type.
// On type change we default to the new family's first code (its default code).
// When the type matches the original type we restore the original code so a
// type→type→type round-trip doesn't silently change the code.
func (f *RejectField) rebuildCodeSelect() {
	displayType := f.currentType()
	codeOrder, _ := codeOrderForDisplayType(displayType)
	cs := NewSelect(codeOrder)

	origDisplayType := mapWireTypeToDisplay(f.originalType, f.family)
	if displayType == origDisplayType && f.originalName != "" {
		cs.SetValue(f.originalName)
	} else if len(codeOrder) > 0 {
		cs.SetValue(codeOrder[0])
	}
	f.codeSelect = cs
}

// ValidateForSave is currently a no-op — the kernel will reject "tcp reset"
// without a tcp context, and we surface that error via the rule_edit footer.
func (f *RejectField) ValidateForSave() error {
	return nil
}

func (f *RejectField) Save(rule *nftables.Rule) {
	if !f.hasReject || !f.Changed() {
		return
	}
	displayType := f.currentType()

	var newType uint32
	var newCode uint8
	switch displayType {
	case rejectTypeTCPReset:
		newType = unix.NFT_REJECT_TCP_RST
	case rejectTypeICMPX:
		newType = unix.NFT_REJECT_ICMPX_UNREACH
		newCode = icmpxRejectNameToCode[f.codeSelect.Value()]
	case rejectTypeICMP:
		newType = unix.NFT_REJECT_ICMP_UNREACH
		newCode = icmpRejectNameToCode[f.codeSelect.Value()]
	case rejectTypeICMPv6:
		newType = unix.NFT_REJECT_ICMP_UNREACH
		newCode = icmpv6RejectNameToCode[f.codeSelect.Value()]
	}

	newReject := &expr.Reject{Type: newType, Code: newCode}

	for i, re := range rule.Exprs {
		if _, ok := re.(*expr.Reject); ok {
			rule.Exprs[i] = newReject
			break
		}
	}

	// Update originals to reflect saved state.
	f.originalCode = newCode
	switch displayType {
	case rejectTypeTCPReset:
		f.originalType = nft.RejectTypeTCPReset
		f.originalName = ""
	case rejectTypeICMPX:
		f.originalType = nft.RejectTypeICMPX
		f.originalName = f.codeSelect.Value()
	case rejectTypeICMP, rejectTypeICMPv6:
		f.originalType = nft.RejectTypeICMP
		f.originalName = f.codeSelect.Value()
	}
	f.typeSelect.Changed = false
	f.codeSelect.Changed = false
}

func (f *RejectField) View() string {
	label := grayStyle.Render("Reject")
	if !f.hasReject {
		return label + "\n" + grayStyle.Render("(no reject in this rule)") + "\n"
	}

	vType := f.typeSelect.View()
	origDisplayType := mapWireTypeToDisplay(f.originalType, f.family)
	if f.currentType() != origDisplayType {
		vType = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vType)
	}
	preview := renderReject(f.previewAction(), f.family)
	left := label + "\n" + vType + "\n" + grayStyle.Render("current: ") + preview

	if !f.needsCode() {
		return left + "\n"
	}

	codeLabel := grayStyle.Render("Code")
	vCode := f.codeSelect.View()
	if f.codeSelect.Value() != f.originalName {
		vCode = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(vCode)
	}
	right := codeLabel + "\n" + vCode

	return lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(48).Render(left),
		lipgloss.NewStyle().Render(right),
	) + "\n"
}

// previewAction synthesizes a RejectAction matching the current Select values,
// used by View to render the styled "current:" line.
func (f *RejectField) previewAction() nft.RejectAction {
	displayType := f.currentType()
	switch displayType {
	case rejectTypeTCPReset:
		return nft.RejectAction{Type: nft.RejectTypeTCPReset}
	case rejectTypeICMPX:
		return nft.RejectAction{Type: nft.RejectTypeICMPX, Code: icmpxRejectNameToCode[f.codeSelect.Value()]}
	case rejectTypeICMP:
		return nft.RejectAction{Type: nft.RejectTypeICMP, Code: icmpRejectNameToCode[f.codeSelect.Value()]}
	case rejectTypeICMPv6:
		return nft.RejectAction{Type: nft.RejectTypeICMP, Code: icmpv6RejectNameToCode[f.codeSelect.Value()]}
	}
	return nft.RejectAction{}
}
