package ui

import (
	"bytes"
	"fmt"
	"net"
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"nftui/i18n"
	"nftui/nft"
)

// setView renders the metadata + elements of a single named set, and lets
// the user add or remove elements interactively.
//
// Element selection has a cursor (↑/↓). `a` opens a prompt for a new
// element value (parsed type-aware from the set's KeyType). `d` opens a
// y/N confirmation for deleting the selected element. The keys
// roundtrip to the kernel via nft.AddSetElement / nft.DeleteSetElement
// and the main_window refresh handler reloads the set so the new state
// is visible immediately.
type setView struct {
	set           *nftables.Set
	table         *tableNode
	elements      []nftables.SetElement
	width         int
	height        int
	help          help.Model
	keys          setViewKeyMap
	cursor        int
	scrollOffset  int
	statusMsg     string
	showAddPrompt bool
	addInput      textinput.Model
	addValInput   textinput.Model
	addFocusVal   bool // only true for map sets after Tab/Enter from key
	addErr        string
	addLastHint   string // "added <key>[ → <val>]" from the previous Enter
	showDelete    bool

	// readOnly mirrors Options.ReadOnly. Add / Delete bindings are
	// SetEnabled(false) when set; key.Matches won't fire on them either.
	readOnly bool
}

type setViewKeyMap struct {
	Up     key.Binding
	Down   key.Binding
	Add    key.Binding
	Delete key.Binding
	Back   key.Binding
	Quit   key.Binding
}

func (k setViewKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Add, k.Delete, k.Back, k.Quit}
}
func (k setViewKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{k.Up, k.Down, k.Add, k.Delete}, {k.Back, k.Quit}}
}

func newSetView(set *nftables.Set, table *tableNode, readOnly bool) setView {
	// Best-effort fetch — the kernel returns nothing for anonymous sets if
	// they're unreferenced, and a transient netlink error is tolerated as an
	// empty list rather than crashing the TUI (audit E-1 / R1).
	elements, err := nft.GetSetElements(set)
	if err != nil {
		elements = nil
	}
	return newSetViewWithElements(set, table, elements, readOnly)
}

// newSetViewWithElements is the netlink-free core of newSetView: the element
// list is injected instead of fetched, which keeps it unit-testable.
func newSetViewWithElements(set *nftables.Set, table *tableNode, elements []nftables.SetElement, readOnly bool) setView {
	km := setViewKeyMap{
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("↑/k", i18n.T("key.up")),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("↓/j", i18n.T("key.down")),
		),
		Add: key.NewBinding(
			key.WithKeys("a"),
			key.WithHelp("a", i18n.T("key.add_element")),
		),
		Delete: key.NewBinding(
			key.WithKeys("d"),
			key.WithHelp("d", i18n.T("key.delete_element")),
		),
		Back: key.NewBinding(
			key.WithKeys("esc", "f3"),
			key.WithHelp("esc/f3", i18n.T("key.back")),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", i18n.T("key.quit")),
		),
	}
	if readOnly {
		km.Add.SetEnabled(false)
		km.Delete.SetEnabled(false)
	}

	return setView{
		set:      set,
		table:    table,
		elements: elements,
		help:     newHelpModel(),
		keys:     km,
		readOnly: readOnly,
	}
}

// IsModal reports whether a prompt or confirmation overlay is shown; if so,
// main_window funnels every key through Update so nothing else intercepts.
func (sv setView) IsModal() bool {
	return sv.showAddPrompt || sv.showDelete
}

// setAddErr records a bulk-add prompt failure and drops the previous
// "added X" hint. The two are mutually exclusive: the last Enter either
// succeeded (addLastHint) or failed (addErr), never both — so a stale green
// hint never lingers next to a red error.
func (sv *setView) setAddErr(msg string) {
	sv.addErr = msg
	sv.addLastHint = ""
}

func (sv setView) Update(msg tea.Msg) (setView, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		sv.width, sv.height = msg.Width, msg.Height
	case tea.KeyMsg:
		sv.statusMsg = ""

		if sv.showAddPrompt {
			switch msg.String() {
			case "esc":
				sv.showAddPrompt = false
				sv.addErr = ""
				sv.addLastHint = ""
				return sv, nil
			case "tab", "shift+tab":
				// Tab toggles between key and value inputs (maps only).
				if sv.set.IsMap {
					sv.addFocusVal = !sv.addFocusVal
					if sv.addFocusVal {
						sv.addInput.Blur()
						sv.addValInput.Focus()
					} else {
						sv.addValInput.Blur()
						sv.addInput.Focus()
					}
				}
				return sv, nil
			case "enter":
				keyStr := strings.TrimSpace(sv.addInput.Value())
				if keyStr == "" {
					sv.setAddErr(i18n.T("set.add.key_required"))
					return sv, nil
				}
				keyBytes, keyEnd, err := nft.ParseSetElementKey(sv.set, keyStr)
				if err != nil {
					sv.setAddErr(err.Error())
					return sv, nil
				}
				var valBytes []byte
				var verdict *expr.Verdict
				valStr := ""
				if sv.set.IsMap {
					valStr = strings.TrimSpace(sv.addValInput.Value())
					if valStr == "" {
						sv.setAddErr(i18n.T("set.add.val_required"))
						return sv, nil
					}
					if sv.set.DataType.Name == nftables.TypeVerdict.Name {
						verdict, err = nft.ParseVerdict(valStr)
					} else {
						valBytes, err = nft.ParseSetElementVal(sv.set, valStr)
					}
					if err != nil {
						sv.setAddErr(err.Error())
						return sv, nil
					}
				}
				// Keep the prompt open for the next entry. Clearing the
				// inputs and surfacing a brief "added X" hint gives the
				// bulk-insert pattern (run nft list separately to verify
				// each one if needed); Esc exits the loop.
				sv.addErr = ""
				if sv.set.IsMap {
					sv.addLastHint = fmt.Sprintf(i18n.T("set.add.added_map"), keyStr, valStr)
				} else {
					sv.addLastHint = fmt.Sprintf(i18n.T("set.add.added"), keyStr)
				}
				sv.addInput.SetValue("")
				sv.addValInput.SetValue("")
				if sv.set.IsMap {
					sv.addFocusVal = false
					sv.addValInput.Blur()
					sv.addInput.Focus()
				}
				return sv, addSetElementCmd(sv.set, keyBytes, keyEnd, valBytes, verdict)
			}
			var cmd tea.Cmd
			if sv.set.IsMap && sv.addFocusVal {
				sv.addValInput, cmd = sv.addValInput.Update(msg)
			} else {
				sv.addInput, cmd = sv.addInput.Update(msg)
			}
			return sv, cmd
		}

		if sv.showDelete {
			key := msg.String()
			if confirmYesJ(key) { // German "[J]a" — only while German is active
				key = "y"
			}
			switch key {
			// "i"/"s"/"o" are the localized yes-mnemonics (hu [I]gen, es [S]í,
			// pt [S]im, fr [O]ui).
			case "y", "Y", "i", "I", "s", "S", "o", "O":
				sv.showDelete = false
				if sv.cursor >= 0 && sv.cursor < len(sv.elements) {
					el := sv.elements[sv.cursor]
					return sv, deleteSetElementCmd(sv.set, el.Key, el.KeyEnd)
				}
				return sv, nil
			case "n", "N", "esc":
				sv.showDelete = false
				return sv, nil
			}
			return sv, nil
		}

		switch {
		case key.Matches(msg, sv.keys.Up):
			if sv.cursor > 0 {
				sv.cursor--
				if sv.cursor < sv.scrollOffset {
					sv.scrollOffset = sv.cursor
				}
			}
		case key.Matches(msg, sv.keys.Down):
			if sv.cursor < len(sv.elements)-1 {
				sv.cursor++
			}
		case key.Matches(msg, sv.keys.Add):
			sv.showAddPrompt = true
			sv.addErr = ""
			sv.addLastHint = ""
			sv.addFocusVal = false
			ti := textinput.New()
			ti.Placeholder = setKeyTypeHint(sv.set)
			ti.Focus()
			ti.CharLimit = 64
			ti.Width = 40
			sv.addInput = ti
			if sv.set.IsMap {
				vi := textinput.New()
				vi.Placeholder = setDataTypeHint(sv.set)
				vi.CharLimit = 64
				vi.Width = 40
				sv.addValInput = vi
			}
		case key.Matches(msg, sv.keys.Delete):
			if len(sv.elements) > 0 && sv.cursor >= 0 && sv.cursor < len(sv.elements) {
				sv.showDelete = true
			}
		case key.Matches(msg, sv.keys.Back):
			return sv, func() tea.Msg { return setViewBackMsg{} }
		case key.Matches(msg, sv.keys.Quit):
			return sv, tea.Quit
		}
	}
	return sv, nil
}

// RefreshElements re-fetches the set's elements after a mutation.
// Cursor clamps to the new length so we never index out of range.
//
// A netlink read error keeps the previously-loaded elements and surfaces the
// reason in statusMsg rather than blanking the view or crashing the TUI
// (audit E-1 / R1).
func (sv *setView) RefreshElements() {
	elements, err := nft.GetSetElements(sv.set)
	if err != nil {
		sv.statusMsg = i18n.T("set.refresh_err") + err.Error()
		return
	}
	sv.statusMsg = ""
	sv.elements = elements
	if sv.cursor >= len(sv.elements) {
		sv.cursor = len(sv.elements) - 1
	}
	if sv.cursor < 0 {
		sv.cursor = 0
	}
}

// setViewBackMsg signals MainWindow to switch back to the tree.
type setViewBackMsg struct{}

// setDataTypeHint mirrors setKeyTypeHint but uses the map's DataType.
// Verdict maps get a CLI-form hint (`accept | jump <chain>`).
func setDataTypeHint(s *nftables.Set) string {
	if s.DataType.Name == nftables.TypeVerdict.Name {
		return "accept | drop | jump <chain> | goto <chain>"
	}
	tmp := *s
	tmp.KeyType = s.DataType
	return setKeyTypeHint(&tmp)
}

// setKeyTypeHint returns a short placeholder for the add-element prompt
// based on KeyType. Interval-flag sets get a CIDR / range suffix hint.
func setKeyTypeHint(s *nftables.Set) string {
	var base string
	switch s.KeyType.Name {
	case nftables.TypeIPAddr.Name:
		base = "10.0.0.1"
		if s.Interval {
			base = "10.0.0.1 | 10.0.0.0/24 | 10.0.0.1-10.0.0.5"
		}
	case nftables.TypeIP6Addr.Name:
		base = "fe80::1"
		if s.Interval {
			base = "fe80::1 | 2001:db8::/64"
		}
	case nftables.TypeEtherAddr.Name:
		base = "aa:bb:cc:dd:ee:ff"
	case nftables.TypeInetService.Name:
		base = "443"
		if s.Interval {
			base = "443 | 1024-2048"
		}
	case nftables.TypeInetProto.Name:
		base = "6"
	case nftables.TypeMark.Name, nftables.TypeInteger.Name:
		base = "0 / 0x10"
	default:
		base = s.KeyType.Name
	}
	return base
}

// setFlagsLabel collects the boolean flag-fields of a *nftables.Set into a
// human-readable list ("constant, interval, timeout, dynamic, ...").
func setFlagsLabel(s *nftables.Set) string {
	var flags []string
	if s.Anonymous {
		flags = append(flags, "anonymous")
	}
	if s.Constant {
		flags = append(flags, "constant")
	}
	if s.Interval {
		flags = append(flags, "interval")
	}
	if s.HasTimeout {
		flags = append(flags, "timeout")
	}
	if s.Dynamic {
		flags = append(flags, "dynamic")
	}
	if s.Counter {
		flags = append(flags, "counter")
	}
	if s.AutoMerge {
		flags = append(flags, "auto-merge")
	}
	if s.IsMap {
		flags = append(flags, "map")
	}
	if s.Concatenation {
		flags = append(flags, "concat")
	}
	if len(flags) == 0 {
		return ""
	}
	return strings.Join(flags, ", ")
}

// formatSetElementVal renders a map element's value bytes using the set's
// DataType. Same type coverage as formatSetElementKey, just dispatched on
// DataType.Name. Falls back to hex for unsupported types (e.g. verdict).
func formatSetElementVal(s *nftables.Set, val []byte) string {
	tmp := *s
	tmp.KeyType = s.DataType
	return formatSetElementKey(&tmp, val)
}

// formatSetElementKey renders an element key as a human-readable string.
// Type-aware for IPv4 / IPv6 / MAC / port datatypes; falls back to hex.
func formatSetElementKey(s *nftables.Set, key []byte) string {
	switch s.KeyType.Name {
	case nftables.TypeIPAddr.Name:
		if len(key) == 4 {
			return net.IP(key).String()
		}
	case nftables.TypeIP6Addr.Name:
		if len(key) == 16 {
			return net.IP(key).String()
		}
	case nftables.TypeEtherAddr.Name:
		if len(key) == 6 {
			return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
				key[0], key[1], key[2], key[3], key[4], key[5])
		}
	case nftables.TypeInetService.Name:
		if len(key) == 2 {
			return fmt.Sprintf("%d", uint16(key[0])<<8|uint16(key[1]))
		}
	case nftables.TypeInetProto.Name:
		if len(key) == 1 {
			return fmt.Sprintf("%d", key[0])
		}
	case nftables.TypeMark.Name, nftables.TypeInteger.Name:
		// Decimal render at the actual stored width (1/2/4/8). Mark is
		// always 4 bytes; integer matches the chosen DataTypeBytes.
		switch len(key) {
		case 1:
			return fmt.Sprintf("%d", key[0])
		case 2:
			return fmt.Sprintf("%d", uint16(key[0])<<8|uint16(key[1]))
		case 4:
			return fmt.Sprintf("%d",
				uint32(key[0])<<24|uint32(key[1])<<16|uint32(key[2])<<8|uint32(key[3]))
		case 8:
			var n uint64
			for i := 0; i < 8; i++ {
				n = (n << 8) | uint64(key[i])
			}
			return fmt.Sprintf("%d", n)
		}
	}
	// Hex fallback for unknown / variable types.
	return "0x" + strings.TrimSpace(strings.ReplaceAll(fmt.Sprintf("% x", key), " ", ""))
}

func (sv setView) View() string {
	var b strings.Builder
	b.WriteString(blueBoldStyle.Render("nftui nftables manager"))
	b.WriteString("\n")
	divider := grayStyle.Width(sv.width).Render(strings.Repeat("─", maxIntSV(sv.width, 1)))
	b.WriteString(divider)
	b.WriteString("\n")
	b.WriteString(blueStyle.Render(i18n.T("set.view.title")))
	b.WriteString("\n\n")

	labelWidth := 14
	row := func(label, value string) {
		lp := grayBoldStyle.Render(fmt.Sprintf("%-*s", labelWidth, label+":"))
		b.WriteString(lp + " " + value + "\n")
	}
	row("Table", nft.TableFamilyToString(sv.set.Table.Family)+" "+blueStyle.Render(sv.set.Table.Name))
	row("Name", yellowStyle.Render(sv.set.Name))
	row("Key type", whiteStyle.Render(nft.KeyTypeToString(sv.set.KeyType)))
	if sv.set.IsMap {
		row("Data type", whiteStyle.Render(nft.KeyTypeToString(sv.set.DataType)))
	}
	if fl := setFlagsLabel(sv.set); fl != "" {
		row("Flags", grayStyle.Render(fl))
	}
	if sv.set.HasTimeout && sv.set.Timeout > 0 {
		row("Timeout", whiteStyle.Render(sv.set.Timeout.String()))
	}

	b.WriteString("\n")
	header := fmt.Sprintf(i18n.T("set.view.elements"), len(sv.elements))
	b.WriteString(grayBoldStyle.Render(header))
	b.WriteString("\n")
	if len(sv.elements) == 0 {
		b.WriteString("  " + grayStyle.Render(i18n.T("common.empty")) + "\n")
	} else {
		for i, el := range sv.elements {
			cursor := "  "
			if i == sv.cursor {
				cursor = "> "
			}
			keyStr := formatSetElementKey(sv.set, el.Key)
			// Interval entries return with KeyEnd populated (see
			// nft.GetSetElements). Hide single-host pairs (KeyEnd == Key);
			// render true ranges as `start-end`.
			if len(el.KeyEnd) > 0 && !bytes.Equal(el.Key, el.KeyEnd) {
				keyStr += "-" + formatSetElementKey(sv.set, el.KeyEnd)
			}
			line := cursor + keyStr
			if sv.set.IsMap {
				switch {
				case el.VerdictData != nil:
					line += grayStyle.Render(" → ") + whiteStyle.Render(nft.FormatVerdict(el.VerdictData))
				case len(el.Val) > 0:
					line += grayStyle.Render(" → ") + formatSetElementVal(sv.set, el.Val)
				}
			}
			if i == sv.cursor {
				line = blueBackgroundStyle.Render(line)
			}
			b.WriteString(line)
			b.WriteString("\n")
		}
	}

	if sv.statusMsg != "" {
		b.WriteString("\n")
		b.WriteString(redBoldStyle.Render(i18n.T("common.error") + sv.statusMsg))
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(sv.help.View(sv.keys))

	out := b.String()
	contentBox := normalGrayBorder.
		Width(sv.width - 2).
		Render(out)
	base := lipgloss.NewStyle().Render(contentBox)

	if sv.showAddPrompt {
		var title, body string
		if sv.set.IsMap {
			title = fmt.Sprintf(i18n.T("set.add.map_title"),
				sv.set.Name,
				nft.KeyTypeToString(sv.set.KeyType),
				nft.KeyTypeToString(sv.set.DataType))
			body = title + "\n\n" +
				grayStyle.Render(i18n.T("set.add.key_label")) + sv.addInput.View() + "\n" +
				grayStyle.Render(i18n.T("set.add.val_label")) + sv.addValInput.View()
		} else {
			title = fmt.Sprintf(i18n.T("set.add.title"),
				sv.set.Name, nft.KeyTypeToString(sv.set.KeyType))
			body = title + "\n\n" + sv.addInput.View()
		}
		// addErr and addLastHint are mutually exclusive by construction
		// (see setAddErr), so the hint never shows next to an error.
		if sv.addLastHint != "" {
			body += "\n\n" + greenStyle.Render(sv.addLastHint)
		}
		if sv.addErr != "" {
			body += "\n\n" + redBoldStyle.Render(sv.addErr)
		}
		if sv.set.IsMap {
			body += "\n\n" + grayStyle.Render(i18n.T("set.add.hint_map"))
		} else {
			body += "\n\n" + grayStyle.Render(i18n.T("set.add.hint"))
		}
		prompt := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("39")).
			Padding(1, 2).
			Width(60).
			Render(body)
		overlay := lipgloss.Place(sv.width, sv.height,
			lipgloss.Center, lipgloss.Center, prompt)
		return lipgloss.Place(sv.width, sv.height, lipgloss.Left, lipgloss.Top, base+"\n"+overlay)
	}

	if sv.showDelete && sv.cursor >= 0 && sv.cursor < len(sv.elements) {
		el := sv.elements[sv.cursor]
		body := fmt.Sprintf(i18n.T("confirm.set_element"),
			formatSetElementKey(sv.set, el.Key), sv.set.Name)
		confirm := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("196")).
			Padding(1, 2).
			Width(60).
			Align(lipgloss.Center).
			Render(body)
		overlay := lipgloss.Place(sv.width, sv.height,
			lipgloss.Center, lipgloss.Center, confirm)
		return lipgloss.Place(sv.width, sv.height, lipgloss.Left, lipgloss.Top, base+"\n"+overlay)
	}

	return base
}

// maxIntSV is a tiny local helper — Go 1.25 has builtin max() but renaming
// avoids any chance of shadowing.
func maxIntSV(a, b int) int {
	if a > b {
		return a
	}
	return b
}
