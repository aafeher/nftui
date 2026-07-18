package main

import (
	"fmt"
	"io"
	"runtime/debug"
)

// version is the release version, injected at build time via
// -ldflags '-X main.version={{ .Version }}' (Goreleaser / the Nix build).
// It is empty in a plain `go build`; resolveVersion then supplies a fallback.
var version = ""

// resolveVersion picks the version string to display for `--version`. The
// ldflags-injected value wins; otherwise the Go build-info module version
// (set when the binary came from `go install <module>@vX.Y.Z`) is used —
// unless it is the "(devel)" placeholder a plain VCS checkout carries — and
// failing both it reports "dev". Kept pure (both inputs as args) so the
// precedence is unit-testable without build-time state.
func resolveVersion(injected, buildVersion string) string {
	if injected != "" {
		return injected
	}
	if buildVersion != "" && buildVersion != "(devel)" {
		return buildVersion
	}
	return "dev"
}

// currentVersion resolves the effective version from the injected var plus the
// runtime build info (the impure inputs), delegating the decision to the pure
// resolveVersion.
func currentVersion() string {
	buildVersion := ""
	if info, ok := debug.ReadBuildInfo(); ok {
		buildVersion = info.Main.Version
	}
	return resolveVersion(version, buildVersion)
}

// writeVersion renders the `--version` output: a single "<bin> <version>"
// line. Its own io.Writer-typed function (mirrors writeUsage) so tests assert
// the format without poking os.Stdout.
func writeVersion(w io.Writer, bin, ver string) {
	fmt.Fprintf(w, "%s %s\n", bin, ver)
}

// flagSpec describes a single CLI flag for *both* flag registration and the
// custom Usage handler. The upcoming nftui(1) man page will read from the
// same list (and the same summaries), so help text never drifts from what
// the binary actually accepts.
type flagSpec struct {
	name    string // canonical flag name (no leading dashes)
	arg     string // value placeholder shown in help (e.g. "<name>"); empty for booleans
	summary string // single-line description; same string passed to flag.String / flag.Bool
}

// flagDocs is the source of truth for every nftui CLI flag. New flags are
// added here once; flag registration in main() and writeUsage both consume
// this slice in order, which is also the order the man page will list them.
var flagDocs = []flagSpec{
	{
		name:    "table",
		arg:     "<name>",
		summary: "restrict the tree to a single table (matched by name across all families)",
	},
	{
		name:    "config",
		arg:     "<file>",
		summary: "apply the given nftables ruleset via `nft -f <file>` before starting (mutates the running ruleset)",
	},
	{
		name:    "read-only",
		arg:     "",
		summary: "disable every write path: no rule/chain/table/set add/insert/move/delete/edit/save (footer dims the blocked keys)",
	},
	{
		name:    "lang",
		arg:     "<code>",
		summary: "interface language code (e.g. en, hu, es, pt-BR, fr, de, it); overrides the LC_ALL/LC_MESSAGES/LANG locale (default: auto-detect, English fallback)",
	},
}

// docFor returns the summary for a flag name. Panics if the flag isn't
// registered in flagDocs — that's a programming error (silent miss would
// strip the description from --help).
func docFor(name string) string {
	for _, f := range flagDocs {
		if f.name == name {
			return f.summary
		}
	}
	panic("flagDocs is missing an entry for: " + name)
}

// writeUsage renders the --help output. Pulled into its own io.Writer-typed
// function so tests can capture and assert on the content without poking
// global state (os.Args, os.Stderr).
//
// Intentionally English-only (not routed through i18n.T — a documented I-9
// exception): --help is handled in main()'s pre-flag.Parse scan, before
// i18n.SetLanguage runs, so no language is selected yet; flagDocs is also the
// single source of truth shared with the nftui(1) man page, which is English.
func writeUsage(w io.Writer, bin string) {
	fmt.Fprintf(w, "nftui — a Terminal User Interface for Linux nftables\n\n")
	fmt.Fprintf(w, "Usage:\n  %s [flags]\n\n", bin)
	fmt.Fprintf(w, "Flags:\n")

	// Align summaries on a column wide enough for the longest "--flag <arg>".
	colWidth := 0
	for _, f := range flagDocs {
		w := len("--" + f.name)
		if f.arg != "" {
			w += 1 + len(f.arg)
		}
		if w > colWidth {
			colWidth = w
		}
	}
	if h := len("--help"); h > colWidth {
		colWidth = h
	}
	if v := len("--version"); v > colWidth {
		colWidth = v
	}
	colWidth += 4 // padding between the flag and its description

	for _, f := range flagDocs {
		prefix := "--" + f.name
		if f.arg != "" {
			prefix += " " + f.arg
		}
		fmt.Fprintf(w, "  %-*s%s\n", colWidth, prefix, f.summary)
	}
	fmt.Fprintf(w, "  %-*sshow this help and exit\n", colWidth, "--help")
	fmt.Fprintf(w, "  %-*sprint the version and exit\n", colWidth, "--version")

	fmt.Fprintf(w, "\nExamples:\n")
	fmt.Fprintf(w, "  sudo %s                                browse the live ruleset\n", bin)
	fmt.Fprintf(w, "  sudo %s --table filter                 show only table(s) named 'filter'\n", bin)
	fmt.Fprintf(w, "  sudo %s --config new.conf              apply new.conf before browsing\n", bin)
	fmt.Fprintf(w, "  sudo %s --read-only                    safe browsing (no writes)\n", bin)
	fmt.Fprintf(w, "  sudo %s --config new.conf --read-only  safe browsing of a pre-loaded fixture\n", bin)

	fmt.Fprintf(w, "\nRequires CAP_NET_ADMIN. Run with sudo, or grant the capability once:\n")
	fmt.Fprintf(w, "  sudo setcap cap_net_admin=ep %s\n", bin)
	fmt.Fprintf(w, "\nSee README.md and nftui(1) for full documentation.\n")
}
