package ui

// Options carries the values parsed from the command-line flags into the UI
// layer. Defaults to a zero value (everything off / unset) — pass it through
// even when no flags are set so call sites stay uniform.
//
// Each flag is documented in main.go's flag.* registrations and (eventually)
// in the nftui(1) man page. Keep this struct stable: it's the contract
// between the CLI bootstrap and the UI.
type Options struct {
	// TableFilter, when non-empty, restricts the tree to tables whose name
	// matches this value. Family is ignored — a name match in any family
	// passes (a few tables share names across `ip` / `ip6` / `inet`).
	TableFilter string
}
