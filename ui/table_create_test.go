package ui

// State-machine tests for the table-create dialog. createTableCmd is netlink
// on execution, so the F2 save cmd is returned but never run.

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/nftables"
)

func TestTableCreate_Defaults(t *testing.T) {
	tc := newTableCreate()
	if tc.focusSlot != tcSlotFamily {
		t.Errorf("focusSlot = %d, want family slot", tc.focusSlot)
	}
	if !tc.familySelect.Focused {
		t.Error("family select is not focused initially")
	}
	if tc.familySelect.Value() != "ipv4" {
		t.Errorf("default family = %q, want ipv4", tc.familySelect.Value())
	}
}

func TestFamilyFromOption(t *testing.T) {
	tests := []struct {
		opt  string
		want nftables.TableFamily
	}{
		{"ipv4", nftables.TableFamilyIPv4},
		{"ipv6", nftables.TableFamilyIPv6},
		{"inet", nftables.TableFamilyINet},
		{"arp", nftables.TableFamilyARP},
		{"bridge", nftables.TableFamilyBridge},
		{"netdev", nftables.TableFamilyNetdev},
		{"bogus", nftables.TableFamilyINet},
	}
	for _, tt := range tests {
		if got := familyFromOption(tt.opt); got != tt.want {
			t.Errorf("familyFromOption(%q) = %v, want %v", tt.opt, got, tt.want)
		}
	}
}

func TestTableCreate_FocusCycle(t *testing.T) {
	tc := newTableCreate()

	tc, _ = tc.Update(keyMsg(tea.KeyTab))
	if tc.focusSlot != tcSlotName || !tc.nameInput.Focused() || tc.familySelect.Focused {
		t.Error("tab did not move focus to the name input")
	}

	tc, _ = tc.Update(keyMsg(tea.KeyTab))
	if tc.focusSlot != tcSlotFamily || !tc.familySelect.Focused {
		t.Error("tab did not wrap focus back to the family select")
	}

	tc, _ = tc.Update(keyMsg(tea.KeyShiftTab))
	if tc.focusSlot != tcSlotName {
		t.Error("shift+tab did not wrap focus to the name input")
	}
}

func TestTableCreate_SaveValidatesName(t *testing.T) {
	tc := newTableCreate()

	tc, cmd := tc.Update(keyMsg(tea.KeyF2))
	if cmd != nil {
		t.Error("f2 with an empty name returned a cmd")
	}
	if tc.statusMsg == "" {
		t.Error("f2 with an empty name set no status message")
	}

	// Whitespace-only names are rejected too.
	tc.nameInput.SetValue("   ")
	tc, cmd = tc.Update(keyMsg(tea.KeyF2))
	if cmd != nil || tc.statusMsg == "" {
		t.Error("f2 with a whitespace name was accepted")
	}
}

func TestTableCreate_SaveReturnsCmd(t *testing.T) {
	tc := newTableCreate()
	tc.nameInput.SetValue("mytable")

	tc, cmd := tc.Update(keyMsg(tea.KeyF2))
	if cmd == nil {
		t.Fatal("f2 with a valid name returned no cmd")
	}
	if tc.statusMsg != "" {
		t.Errorf("statusMsg = %q after a valid save, want empty", tc.statusMsg)
	}
	// createTableCmd is netlink on execution — not run.
}

func TestTableCreate_ErrAndResize(t *testing.T) {
	tc := newTableCreate()

	tc, _ = tc.Update(tableOpErrMsg{err: errors.New("kernel said no")})
	if tc.statusMsg != "kernel said no" {
		t.Errorf("statusMsg = %q, want the op error", tc.statusMsg)
	}

	tc, _ = tc.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
	if tc.width != 100 || tc.height != 40 {
		t.Errorf("size = %dx%d, want 100x40", tc.width, tc.height)
	}
}

func TestTableCreate_InputRouting(t *testing.T) {
	tc := newTableCreate()

	// Family slot: right arrow advances the select; the name input is untouched.
	tc, _ = tc.Update(keyMsg(tea.KeyRight))
	if tc.familySelect.Value() != "ipv6" {
		t.Errorf("family = %q after right, want ipv6", tc.familySelect.Value())
	}
	if tc.nameInput.Value() != "" {
		t.Errorf("name input picked up family-slot keys: %q", tc.nameInput.Value())
	}

	// Name slot: runes land in the text input, not the select.
	tc, _ = tc.Update(keyMsg(tea.KeyTab))
	tc, _ = tc.Update(treeKey("x"))
	if tc.nameInput.Value() != "x" {
		t.Errorf("name input = %q after typing, want \"x\"", tc.nameInput.Value())
	}
	if tc.familySelect.Value() != "ipv6" {
		t.Error("family select changed while the name input was focused")
	}
}

func TestTableCreate_ViewRenders(t *testing.T) {
	tc := newTableCreate()
	tc.width = 100
	tc.height = 40

	v := tc.View()
	for _, tok := range []string{"Create new table", "Family", "Name"} {
		if !strings.Contains(v, tok) {
			t.Errorf("View() missing %q", tok)
		}
	}

	tc.statusMsg = "kernel said no"
	if v := tc.View(); !strings.Contains(v, "kernel said no") {
		t.Error("View() does not render the status message")
	}
}

// A name carrying nft-script metacharacters is rejected before any kernel cmd
// is produced (audit E-2 / S1). Without the validator this string would inject
// statements into the privileged `nft -f -` transaction the rename path builds.
func TestTableCreate_SaveRejectsInjectionName(t *testing.T) {
	tc := newTableCreate()
	tc.nameInput.SetValue("evil{ }\ntable inet pwned")

	tc, cmd := tc.Update(keyMsg(tea.KeyF2))
	if cmd != nil {
		t.Error("injection name returned a kernel cmd, want nil")
	}
	if tc.statusMsg == "" {
		t.Error("injection name did not set a status message")
	}
}
