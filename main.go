package main

import (
	"flag"
	"fmt"
	"nftui/nft"
	"nftui/ui"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	bin := filepath.Base(os.Args[0])

	// Explicit --help exits 0 to stdout (so users can pipe to less). Go's
	// flag package treats unknown -h/--help as an error and exits 2 to
	// stderr — that's the right behavior for *invalid* invocations but not
	// for an intentional help request. Pre-scan so the two paths split.
	for _, a := range os.Args[1:] {
		if a == "-h" || a == "--help" || a == "-help" {
			writeUsage(os.Stdout, bin)
			return
		}
	}

	tableFilter := flag.String("table", "", docFor("table"))
	configFile := flag.String("config", "", docFor("config"))
	readOnly := flag.Bool("read-only", false, docFor("read-only"))
	flag.Usage = func() { writeUsage(os.Stderr, bin) }
	flag.Parse()

	opts := ui.Options{
		TableFilter: *tableFilter,
		ConfigFile:  *configFile,
		ReadOnly:    *readOnly,
	}

	// Resolve startup options BEFORE the TUI starts: bad inputs deserve a
	// clear stderr message, not a half-initialised tree. --config runs
	// first because it can change which tables exist; --table validation
	// then runs against the post-load state.
	if err := applyStartupOptions(opts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	p := tea.NewProgram(ui.InitialMainWindow(opts))
	if _, err := p.Run(); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

// applyStartupOptions handles every flag whose effect needs to happen (or be
// checked against) the live kernel state, in the right order: --config
// mutations first, then --table validation against the resulting state.
func applyStartupOptions(opts ui.Options) error {
	if opts.ConfigFile != "" {
		if err := loadConfigFromFlag(opts.ConfigFile); err != nil {
			return err
		}
	}
	if opts.TableFilter != "" {
		if err := validateTableFilter(opts.TableFilter); err != nil {
			return err
		}
	}
	return nil
}

// loadConfigFromFlag validates the file exists and is readable, then applies
// it via nft.LoadConfig. File-not-found surfaces a focused message; the nft
// binary's own output (syntax error / kernel rejection / permission) flows
// through verbatim so the user sees the actual reason.
func loadConfigFromFlag(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("--config: cannot read file %q: %w", path, err)
	}
	if err := nft.LoadConfig(path); err != nil {
		return fmt.Errorf("--config: failed to apply %q:\n%w", path, err)
	}
	return nil
}

// validateTableFilter checks that the requested table actually exists in the
// running kernel and surfaces actionable advice on permission failures.
func validateTableFilter(name string) error {
	tables, err := nft.ListTables()
	if err != nil {
		if nft.IsPermissionError(err) {
			bin := os.Args[0]
			return fmt.Errorf(
				"Permission denied — cannot read nftables tables.\n\n"+
					"nftui needs the CAP_NET_ADMIN capability. Either:\n"+
					"  - run with sudo:           sudo %s --table %s\n"+
					"  - or grant the capability: sudo setcap cap_net_admin+ep %s",
				bin, name, bin)
		}
		return fmt.Errorf("cannot read nftables tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == name {
			return nil
		}
	}
	avail := make([]string, 0, len(tables))
	for _, t := range tables {
		avail = append(avail, fmt.Sprintf("%s (%s)", t.Name, nft.TableFamilyToString(t.Family)))
	}
	if len(avail) == 0 {
		return fmt.Errorf("table %q not found: the running kernel has no tables", name)
	}
	return fmt.Errorf("table %q not found. Available tables: %v", name, avail)
}
