package ui

import (
	"fmt"
	"strconv"
	"strings"

	"nftui/i18n"
	"nftui/nft"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// Order of severities shown in the level Select — matches kernel/syslog severity
// numbering (emerg=0, debug=7). `warn` is the kernel default and gets elided
// from the wire on save (no NFTA_LOG_LEVEL attribute emitted), so picking warn
// produces the same wire shape as "log" without an explicit level.
var logLevelOptions = []string{
	string(nft.LogLevelEmerg),
	string(nft.LogLevelAlert),
	string(nft.LogLevelCrit),
	string(nft.LogLevelErr),
	string(nft.LogLevelWarn),
	string(nft.LogLevelNotice),
	string(nft.LogLevelInfo),
	string(nft.LogLevelDebug),
}

// Reverse map: nft.LogLevel → expr.LogLevel (kernel severity value).
var logLevelToExpr = map[nft.LogLevel]expr.LogLevel{
	nft.LogLevelEmerg:  expr.LogLevelEmerg,
	nft.LogLevelAlert:  expr.LogLevelAlert,
	nft.LogLevelCrit:   expr.LogLevelCrit,
	nft.LogLevelErr:    expr.LogLevelErr,
	nft.LogLevelWarn:   expr.LogLevelWarning,
	nft.LogLevelNotice: expr.LogLevelNotice,
	nft.LogLevelInfo:   expr.LogLevelInfo,
	nft.LogLevelDebug:  expr.LogLevelDebug,
}

// LogField edits a rule's log statement: prefix string, severity level, NFLOG
// group, snaplen, and queue-threshold. All five attributes are independently
// optional — empty/zero values are elided from the wire so the kernel applies
// its defaults.
//
// FocusSlots reports 5 when the rule has a log statement (one slot per input);
// when there is no log expression the field is read-only and reports 1 inert slot.
type LogField struct {
	hasLog bool

	prefixInput     textinput.Model
	levelSelect     Select
	groupInput      NumberInput
	snaplenInput    NumberInput
	qthresholdInput NumberInput

	originalPrefix     string
	originalLevel      nft.LogLevel
	originalGroup      uint16
	originalSnaplen    uint32
	originalQThreshold uint16
}

func NewLogField(rd *nft.Rule) *LogField {
	prefixInput := textinput.New()
	prefixInput.Placeholder = "log prefix"
	prefixInput.CharLimit = 128
	prefixInput.Width = 40

	levelSelect := NewSelect(logLevelOptions)
	levelSelect.Width = 60

	groupInput := NewNumberInput(0, 65535)
	snaplenInput := NewNumberInput(0, 4294967295)
	qthresholdInput := NewNumberInput(0, 65535)

	var (
		origPrefix     string
		origLevel      nft.LogLevel
		origGroup      uint16
		origSnaplen    uint32
		origQThreshold uint16
	)
	hasLog := false
	for _, a := range rd.Actions {
		if a.Type == nft.ActionTypeLog && a.Log != nil {
			origPrefix = a.Log.Prefix
			origLevel = a.Log.Level
			origGroup = a.Log.Group
			origSnaplen = a.Log.Snaplen
			origQThreshold = a.Log.QThreshold
			hasLog = true
			break
		}
	}
	if origLevel == "" {
		origLevel = nft.LogLevelWarn
	}

	if hasLog {
		prefixInput.SetValue(origPrefix)
		levelSelect.SetValue(string(origLevel))
		if origGroup != 0 {
			groupInput.SetValue(strconv.FormatUint(uint64(origGroup), 10))
		}
		if origSnaplen != 0 {
			snaplenInput.SetValue(strconv.FormatUint(uint64(origSnaplen), 10))
		}
		if origQThreshold != 0 {
			qthresholdInput.SetValue(strconv.FormatUint(uint64(origQThreshold), 10))
		}
	}

	return &LogField{
		hasLog:             hasLog,
		prefixInput:        prefixInput,
		levelSelect:        levelSelect,
		groupInput:         groupInput,
		snaplenInput:       snaplenInput,
		qthresholdInput:    qthresholdInput,
		originalPrefix:     origPrefix,
		originalLevel:      origLevel,
		originalGroup:      origGroup,
		originalSnaplen:    origSnaplen,
		originalQThreshold: origQThreshold,
	}
}

func (f *LogField) FocusSlots() int {
	if !f.hasLog {
		return 1
	}
	return 5
}

func (f *LogField) Focus(subIndex int) {
	if !f.hasLog {
		return
	}
	f.Blur()
	switch subIndex {
	case 0:
		f.prefixInput.Focus()
	case 1:
		f.levelSelect.Focus()
	case 2:
		f.groupInput.Focus()
	case 3:
		f.snaplenInput.Focus()
	case 4:
		f.qthresholdInput.Focus()
	}
}

func (f *LogField) Blur() {
	f.prefixInput.Blur()
	f.levelSelect.Blur()
	f.groupInput.Blur()
	f.snaplenInput.Blur()
	f.qthresholdInput.Blur()
}

func (f *LogField) currentLevel() nft.LogLevel {
	return nft.LogLevel(f.levelSelect.Value())
}

func (f *LogField) currentGroup() uint16 {
	v, _ := f.groupInput.GetUint64()
	return uint16(v)
}

func (f *LogField) currentSnaplen() uint32 {
	v, _ := f.snaplenInput.GetUint64()
	return uint32(v)
}

func (f *LogField) currentQThreshold() uint16 {
	v, _ := f.qthresholdInput.GetUint64()
	return uint16(v)
}

func (f *LogField) Changed() bool {
	if !f.hasLog {
		return false
	}
	if f.prefixInput.Value() != f.originalPrefix {
		return true
	}
	if f.currentLevel() != f.originalLevel {
		return true
	}
	if f.currentGroup() != f.originalGroup {
		return true
	}
	if f.currentSnaplen() != f.originalSnaplen {
		return true
	}
	if f.currentQThreshold() != f.originalQThreshold {
		return true
	}
	return false
}

func (f *LogField) Update(msg tea.Msg) tea.Cmd {
	if !f.hasLog {
		return nil
	}
	var cmd tea.Cmd
	switch {
	case f.prefixInput.Focused():
		f.prefixInput, cmd = f.prefixInput.Update(msg)
	case f.levelSelect.Focused:
		f.levelSelect, cmd = f.levelSelect.Update(msg)
	case f.groupInput.Focused():
		f.groupInput, cmd = f.groupInput.Update(msg)
	case f.snaplenInput.Focused():
		f.snaplenInput, cmd = f.snaplenInput.Update(msg)
	case f.qthresholdInput.Focused():
		f.qthresholdInput, cmd = f.qthresholdInput.Update(msg)
	}
	return cmd
}

func (f *LogField) ValidateForSave() error {
	if !f.hasLog || !f.Changed() {
		return nil
	}
	// The kernel rejects level + group with EINVAL — level is a syslog-mode
	// attribute, group switches the log to NFLOG mode. Surface this up-front
	// rather than letting the kernel return an opaque "invalid argument".
	if f.currentGroup() != 0 && f.currentLevel() != "" && f.currentLevel() != nft.LogLevelWarn {
		return fmt.Errorf("log level %q is not valid in NFLOG mode (group=%d); pick warn or set group=0",
			f.currentLevel(), f.currentGroup())
	}
	// snaplen/qthreshold are NFLOG-only — without a group they have no effect
	// and the kernel rejects them too on some kernels.
	if f.currentGroup() == 0 && (f.currentSnaplen() != 0 || f.currentQThreshold() != 0) {
		return fmt.Errorf("log snaplen/queue-threshold require NFLOG mode (group > 0)")
	}
	return nil
}

func (f *LogField) Save(rule *nftables.Rule) {
	if !f.hasLog || !f.Changed() {
		return
	}

	newPrefix := f.prefixInput.Value()
	newLevel := f.currentLevel()
	newGroup := f.currentGroup()
	newSnaplen := f.currentSnaplen()
	newQThreshold := f.currentQThreshold()

	newLog := &expr.Log{}
	if newPrefix != "" {
		newLog.Data = []byte(newPrefix)
		newLog.Key |= 1 << unix.NFTA_LOG_PREFIX
	}
	// level is only valid in syslog mode (group == 0). In NFLOG mode the kernel
	// rejects the rule with EINVAL if NFTA_LOG_LEVEL is set, so we suppress it.
	if newGroup == 0 && newLevel != "" && newLevel != nft.LogLevelWarn {
		newLog.Level = logLevelToExpr[newLevel]
		newLog.Key |= 1 << unix.NFTA_LOG_LEVEL
	}
	if newGroup != 0 {
		newLog.Group = newGroup
		newLog.Key |= 1 << unix.NFTA_LOG_GROUP
	}
	if newSnaplen != 0 {
		newLog.Snaplen = newSnaplen
		newLog.Key |= 1 << unix.NFTA_LOG_SNAPLEN
	}
	if newQThreshold != 0 {
		newLog.QThreshold = newQThreshold
		newLog.Key |= 1 << unix.NFTA_LOG_QTHRESHOLD
	}

	for i, re := range rule.Exprs {
		if _, ok := re.(*expr.Log); ok {
			rule.Exprs[i] = newLog
			break
		}
	}

	f.originalPrefix = newPrefix
	f.originalLevel = newLevel
	f.originalGroup = newGroup
	f.originalSnaplen = newSnaplen
	f.originalQThreshold = newQThreshold
}

// previewAction synthesizes a LogAction reflecting the current input values,
// used in the View for the styled "current:" preview.
func (f *LogField) previewAction() nft.LogAction {
	return nft.LogAction{
		Prefix:     f.prefixInput.Value(),
		Level:      f.currentLevel(),
		Group:      f.currentGroup(),
		Snaplen:    f.currentSnaplen(),
		QThreshold: f.currentQThreshold(),
	}
}

func (f *LogField) View() string {
	label := grayStyle.Render("Log")
	if !f.hasLog {
		return label + "\n" + grayStyle.Render(i18n.T("rule.field.no_log")) + "\n"
	}

	var (
		vPrefix     = f.prefixInput.View()
		vLevel      = f.levelSelect.View()
		vGroup      = f.groupInput.View()
		vSnaplen    = f.snaplenInput.View()
		vQThreshold = f.qthresholdInput.View()
	)
	if f.prefixInput.Value() != f.originalPrefix {
		vPrefix = changedStyle.Render(vPrefix)
	}
	if f.currentLevel() != f.originalLevel {
		vLevel = changedStyle.Render(vLevel)
	}
	if f.currentGroup() != f.originalGroup {
		vGroup = changedStyle.Render(vGroup)
	}
	if f.currentSnaplen() != f.originalSnaplen {
		vSnaplen = changedStyle.Render(vSnaplen)
	}
	if f.currentQThreshold() != f.originalQThreshold {
		vQThreshold = changedStyle.Render(vQThreshold)
	}

	var sb strings.Builder
	sb.WriteString(label)
	sb.WriteString("\n")
	sb.WriteString(grayStyle.Render(i18n.T("rule.field.current")))
	sb.WriteString(renderLog(f.previewAction()))
	sb.WriteString("\n")

	// Row 1: prefix (full width)
	sb.WriteString(grayStyle.Render("Prefix"))
	sb.WriteString("\n")
	sb.WriteString(vPrefix)
	sb.WriteString("\n")

	// Row 2: level | group | snaplen | qthreshold
	const cw = 22
	col := func(s string) string {
		return lipgloss.NewStyle().Width(cw).Render(s)
	}
	sb.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		col(grayStyle.Render("Level")+"\n"+vLevel),
		col(grayStyle.Render("Group")+"\n"+vGroup),
		col(grayStyle.Render("Snaplen")+"\n"+vSnaplen),
		col(grayStyle.Render("Queue-threshold")+"\n"+vQThreshold),
	))
	sb.WriteString("\n")

	return sb.String()
}

// changedStyle highlights an input value that has diverged from its original.
var changedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
