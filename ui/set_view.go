package ui

import (
	"fmt"
	"net"
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
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
	showDelete    bool
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

func newSetView(set *nftables.Set, table *tableNode) setView {
	// Best-effort fetch — the kernel returns nothing for anonymous sets if
	// they're unreferenced, which we tolerate as an empty list.
	elements := nft.GetSetElements(set)

	km := setViewKeyMap{
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("↑/k", "up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("↓/j", "down"),
		),
		Add: key.NewBinding(
			key.WithKeys("a"),
			key.WithHelp("a", "add element"),
		),
		Delete: key.NewBinding(
			key.WithKeys("d"),
			key.WithHelp("d", "delete element"),
		),
		Back: key.NewBinding(
			key.WithKeys("esc", "f3"),
			key.WithHelp("esc/f3", "back"),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "quit"),
		),
	}
	return setView{
		set:      set,
		table:    table,
		elements: elements,
		help:     newHelpModel(),
		keys:     km,
	}
}

// IsModal reports whether a prompt or confirmation overlay is shown; if so,
// main_window funnels every key through Update so nothing else intercepts.
func (sv setView) IsModal() bool {
	return sv.showAddPrompt || sv.showDelete
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
					sv.addErr = "key required"
					return sv, nil
				}
				keyBytes, err := nft.ParseSetElementKey(sv.set, keyStr)
				if err != nil {
					sv.addErr = err.Error()
					return sv, nil
				}
				var valBytes []byte
				if sv.set.IsMap {
					valStr := strings.TrimSpace(sv.addValInput.Value())
					if valStr == "" {
						sv.addErr = "value required"
						return sv, nil
					}
					valBytes, err = nft.ParseSetElementVal(sv.set, valStr)
					if err != nil {
						sv.addErr = err.Error()
						return sv, nil
					}
				}
				sv.showAddPrompt = false
				sv.addErr = ""
				return sv, addSetElementCmd(sv.set, keyBytes, valBytes)
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
			switch msg.String() {
			case "y", "Y":
				sv.showDelete = false
				if sv.cursor >= 0 && sv.cursor < len(sv.elements) {
					el := sv.elements[sv.cursor]
					return sv, deleteSetElementCmd(sv.set, el.Key)
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
func (sv *setView) RefreshElements() {
	sv.elements = nft.GetSetElements(sv.set)
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
func setDataTypeHint(s *nftables.Set) string {
	tmp := *s
	tmp.KeyType = s.DataType
	return setKeyTypeHint(&tmp)
}

// setKeyTypeHint returns a short placeholder for the add-element prompt
// based on KeyType (e.g. "10.0.0.1" for ipv4_addr).
func setKeyTypeHint(s *nftables.Set) string {
	switch s.KeyType.Name {
	case nftables.TypeIPAddr.Name:
		return "10.0.0.1"
	case nftables.TypeIP6Addr.Name:
		return "fe80::1"
	case nftables.TypeEtherAddr.Name:
		return "aa:bb:cc:dd:ee:ff"
	case nftables.TypeInetService.Name:
		return "443"
	case nftables.TypeInetProto.Name:
		return "6"
	case nftables.TypeMark.Name, nftables.TypeInteger.Name:
		return "0 / 0x10"
	}
	return s.KeyType.Name
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
	b.WriteString(blueStyle.Render("| Set |"))
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
	header := fmt.Sprintf("Elements (%d):", len(sv.elements))
	b.WriteString(grayBoldStyle.Render(header))
	b.WriteString("\n")
	if len(sv.elements) == 0 {
		b.WriteString("  " + grayStyle.Render("(empty)") + "\n")
	} else {
		for i, el := range sv.elements {
			cursor := "  "
			if i == sv.cursor {
				cursor = "> "
			}
			line := cursor + formatSetElementKey(sv.set, el.Key)
			if sv.set.IsMap && len(el.Val) > 0 {
				line += grayStyle.Render(" → ") + formatSetElementVal(sv.set, el.Val)
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
		b.WriteString(redBoldStyle.Render("Error: " + sv.statusMsg))
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
			title = fmt.Sprintf("Add entry to %s (%s → %s)",
				sv.set.Name,
				nft.KeyTypeToString(sv.set.KeyType),
				nft.KeyTypeToString(sv.set.DataType))
			body = title + "\n\n" +
				grayStyle.Render("Key   : ") + sv.addInput.View() + "\n" +
				grayStyle.Render("Value : ") + sv.addValInput.View()
		} else {
			title = fmt.Sprintf("Add element to %s (%s)",
				sv.set.Name, nft.KeyTypeToString(sv.set.KeyType))
			body = title + "\n\n" + sv.addInput.View()
		}
		if sv.addErr != "" {
			body += "\n\n" + redBoldStyle.Render(sv.addErr)
		}
		if sv.set.IsMap {
			body += "\n\n" + grayStyle.Render("Tab: switch field  •  Enter: confirm  •  Esc: cancel")
		} else {
			body += "\n\n" + grayStyle.Render("Enter: confirm  •  Esc: cancel")
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
		body := fmt.Sprintf("Delete element %s from set %s?\n\n[Y]es / [N]o",
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
