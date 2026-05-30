package main

import (
	"flag"
	"fmt"
	"nftui/nft"
	"nftui/ui"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	tableFilter := flag.String("table", "", "restrict the tree to a single table (matched by name across all families)")
	flag.Parse()

	opts := ui.Options{TableFilter: *tableFilter}

	// Fast-fail BEFORE the TUI starts: bad inputs deserve a clear stderr
	// message, not a half-initialised tree. Missing CAP_NET_ADMIN surfaces
	// here too, with the same advice the TUI would render later.
	if err := validateOptions(opts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	p := tea.NewProgram(ui.InitialMainWindow(opts))
	if _, err := p.Run(); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

// validateOptions runs the pre-TUI checks for every flag that needs the live
// kernel state (today: --table). Returns a fully-formatted error suitable for
// fmt.Fprintln(os.Stderr, …) so main stays uncluttered.
func validateOptions(opts ui.Options) error {
	if opts.TableFilter == "" {
		return nil
	}
	tables, err := nft.ListTables()
	if err != nil {
		if nft.IsPermissionError(err) {
			bin := os.Args[0]
			return fmt.Errorf(
				"Permission denied — cannot read nftables tables.\n\n"+
					"nftui needs the CAP_NET_ADMIN capability. Either:\n"+
					"  - run with sudo:           sudo %s --table %s\n"+
					"  - or grant the capability: sudo setcap cap_net_admin+ep %s",
				bin, opts.TableFilter, bin)
		}
		return fmt.Errorf("cannot read nftables tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == opts.TableFilter {
			return nil
		}
	}
	// Build a hint with the available names (family-qualified, since tables
	// can share names across families).
	avail := make([]string, 0, len(tables))
	for _, t := range tables {
		avail = append(avail, fmt.Sprintf("%s (%s)", t.Name, nft.TableFamilyToString(t.Family)))
	}
	if len(avail) == 0 {
		return fmt.Errorf("table %q not found: the running kernel has no tables", opts.TableFilter)
	}
	return fmt.Errorf("table %q not found. Available tables: %v", opts.TableFilter, avail)
}
