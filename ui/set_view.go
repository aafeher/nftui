package ui

import (
	"fmt"
	"net"
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"nftui/nft"
)

// setView renders the metadata + elements of a single named set.
//
// Read-only for now: lists name, key type, flags and the current
// elements with one row per element. Add / remove operations land in
// a later milestone item.
type setView struct {
	set      *nftables.Set
	table    *tableNode
	elements []nftables.SetElement
	width    int
	height   int
	help     help.Model
	keys     setViewKeyMap
}

type setViewKeyMap struct {
	Back key.Binding
	Quit key.Binding
}

func (k setViewKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Back, k.Quit}
}
func (k setViewKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{k.Back, k.Quit}}
}

func newSetView(set *nftables.Set, table *tableNode) setView {
	// Best-effort fetch — the kernel returns nothing for anonymous sets if
	// they're unreferenced, which we tolerate as an empty list.
	elements := nft.GetSetElements(set)

	km := setViewKeyMap{
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

func (sv setView) IsModal() bool { return false }

func (sv setView) Update(msg tea.Msg) (setView, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		sv.width, sv.height = msg.Width, msg.Height
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, sv.keys.Back):
			return sv, func() tea.Msg { return setViewBackMsg{} }
		case key.Matches(msg, sv.keys.Quit):
			return sv, tea.Quit
		}
	}
	return sv, nil
}

// setViewBackMsg signals MainWindow to switch back to the tree.
type setViewBackMsg struct{}

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
		for _, el := range sv.elements {
			b.WriteString("  " + formatSetElementKey(sv.set, el.Key))
			if sv.set.IsMap && len(el.Val) > 0 {
				b.WriteString(grayStyle.Render(" → ") + formatSetElementKey(sv.set, el.Val))
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(sv.help.View(sv.keys))

	out := b.String()
	contentBox := normalGrayBorder.
		Width(sv.width - 2).
		Render(out)
	return lipgloss.NewStyle().Render(contentBox)
}

// maxIntSV is a tiny local helper — Go 1.25 has builtin max() but renaming
// avoids any chance of shadowing.
func maxIntSV(a, b int) int {
	if a > b {
		return a
	}
	return b
}
