# nftui

`nftui` is a Terminal User Interface for managing `nftables` on Linux. Browse
the live ruleset, edit rules with full structured editors for every condition
and action type, and apply changes back to the kernel — without ever touching
the `nft` CLI directly.

Built in Go with the [Bubble Tea](https://github.com/charmbracelet/bubbletea)
framework. Talks to the kernel over netlink via the
[`google/nftables`](https://github.com/google/nftables) library.

## Features

### Ruleset browsing & management

- Tree view of all tables and chains with live data fetched from the kernel.
  The skeleton (tables, chains, sets, named objects) renders immediately on
  startup; per-chain rule counts fill in asynchronously, so a ruleset with
  many chains stays interactive while the rule lists arrive in the
  background (each chain row briefly shows `[loading rules...]` until its
  fetch lands).
- Per-chain rule listing with human-readable rendering of every parsed
  expression. The list is windowed — only the rules that fit on screen are
  serialized and drawn, so a chain with 1000+ rules costs the same to scroll
  as one with 10. The inline filter (`/`) caches each rule's lowercase
  haystack the first time it's matched, so subsequent keystrokes stay
  responsive on large chains.
- Per-rule detail view organised into tabs by condition category.
- Full CRUD on tables, chains and rules: create, rename / edit properties,
  delete (with confirmation), reorder rules up / down within a chain, insert
  before / append at end.

### Rule editor — supported conditions

| Category | Matches |
|----------|---------|
| **CT (conntrack)** | state, direction, status, mark, secmark, expiration, helper, l3proto, protocol, proto-src, proto-dst, labels, eventmask, ip saddr / daddr, bytes, packets, avgpkt (with direction), zone, count |
| **IPv4 header** | saddr, daddr (CIDR), protocol, ttl, length, dscp, version, hdrlength, id, frag-off, checksum |
| **IPv6 header** | saddr, daddr (CIDR), length, nexthdr, hoplimit, version, dscp (6-bit), flowlabel (20-bit) |
| **TCP** | sport, dport, sequence, ackseq, flags (MultiSelect), window, checksum, urgptr, doff |
| **UDP / UDPLITE** | sport, dport, length, checksum |
| **SCTP** | sport, dport, vtag, checksum, **chunk** (RFC 4960 chunk-type match: data / init / init-ack / sack / heartbeat / heartbeat-ack / abort / shutdown / shutdown-ack / error / cookie-echo / cookie-ack / ecne / cwr / shutdown-complete / auth / asconf-ack / i-data / forward-tsn / asconf / i-forward-tsn — bare presence and per-type sub-field constraints both supported: chunk-type Select drives a sub-field Select (`tsn` / `stream` / `ssn` / `ppid` for DATA; `init-tag` / `a-rwnd` / `os` / `mis` / `init-tsn` for INIT; `cum-tsn-ack` / `a-rwnd` / `num-gap-ack-blocks` / `num-dup-tsns` for SACK; etc.) plus a value input that BE-encodes into the matching 1 / 2 / 4 byte width) |
| **Meta (interface)** | iifname, oifname, iif, oif, iiftype, oiftype, iifgroup, oifgroup |
| **Meta (proto / socket / packet)** | length, protocol (EtherType), nfproto, l4proto, mark, priority, skuid, skgid, cgroup, rtclassid, pkttype, cpu |

### Rule editor — supported actions

- **Verdicts**: `accept`, `drop`, `return`, `jump <chain>`, `goto <chain>` —
  with chain name input for jump / goto targets.
- **Reject**: `with icmp type`, `with icmpx type`, `with tcp reset` — family-
  aware (the ICMP type Select changes for ip / ip6 / inet / bridge tables).
- **Log**: prefix, level (emerg…debug), NFLOG group, snaplen, queue-threshold —
  with pre-save validation against kernel-rejected combinations (e.g. `level`
  forbidden in NFLOG mode).
- **Counter**: edit packet and byte counts on an anonymous counter (typical use
  is reset to 0).
- **Limit**: rate, unit (second/minute/hour/day/week), burst, type
  (packets/bytes), over.

### Editor UX

- Each tab groups related fields; **Tab** / **Shift+Tab** moves the focus
  between sub-inputs.
- Modified fields are highlighted; cleared inputs remove the underlying match.
- **F2** validates and applies all changes through netlink (`NLM_F_REPLACE`).
- A footer help line always lists every available key binding in the current
  view.

## Requirements

- **Linux** with a kernel that has `nftables` support.
- **Go 1.25+** to build from source.
- **`CAP_NET_ADMIN`** at runtime (run via `sudo` or grant the capability with
  `setcap`).

The runtime does **not** require the `nft` CLI for the core read / edit /
write path — communication is direct over netlink. The `nft` binary is only
used by a few targeted operations where round-tripping through the CLI is
safer than reconstructing kernel state (table rename, base-chain
recreation).

## Installation

```bash
git clone https://github.com/aafeher/nftui.git
cd nftui
go build -o nftui .
```

### Running

Either with `sudo`:

```bash
sudo ./nftui
```

…or grant the binary the required capability once:

```bash
sudo setcap cap_net_admin=ep ./nftui
./nftui
```

### Installing the man page (optional)

```bash
sudo install -m 0644 man/nftui.1 /usr/share/man/man1/
sudo mandb        # if your system uses man-db (Debian / Ubuntu / Fedora …)
man nftui         # then it's available everywhere
```

Preview it from the source tree without installing:

```bash
man -l man/nftui.1
```

## Command-line flags

| Flag | Description |
|------|-------------|
| `--table <name>` | Restrict the tree to a single table — its chains, sets, and named objects. The match is by name across every family, so `--table filter` will include both `inet filter` and `ip filter` if both exist. Unknown names exit before the TUI starts with the list of available tables. |
| `--config <file>` | Apply the given nftables ruleset via `nft -f <file>` **before** the TUI starts. **This mutates the running ruleset** — the file may contain `flush ruleset`. Use to bring up a known state for testing. Resolved before `--table` so the post-load kernel state is what `--table` validates against. |
| `--read-only` | Disable every write path: no rule add / insert / move / delete / edit / save, no chain / table / set create / delete, no counter reset. Blocked keys dim out of the footer (per the footer-completeness invariant) and a `[READ-ONLY MODE]` marker rides next to the title in every main view. Useful for safe browsing, auditing, or pairing with `--config` to inspect a fixture without risk of accidental edits. |
| `--help` (also `-h`) | Print the full flag list with one-line descriptions and usage examples, then exit. Goes to stdout (so you can pipe to `less`); explicit `--help` exits 0. Invalid flags emit the same usage to stderr and exit 2. |

Examples:

```bash
sudo ./nftui --table filter                              # show only table(s) named 'filter'
sudo ./nftui --table missing                             # exits: "table 'missing' not found. Available tables: …"
sudo ./nftui --config examples/example-nftables-01.conf  # load the manual-test fixture, then browse it
sudo ./nftui --read-only                                 # safe browsing — every write key is dimmed and inert
sudo ./nftui --config new.conf --table filter            # apply new.conf, then restrict the view to its 'filter' table
```

Without `--config`, the running ruleset is left untouched. Without `--table`, every table is shown. Without `--read-only`, every CRUD action is available.

## Key bindings

### Main tree view (tables + chains)

| Key | Action |
|-----|--------|
| `↑` / `k` | move selection up |
| `↓` / `j` | move selection down |
| `Enter` / `→` / `←` | expand / collapse |
| `F3` | open chain (rule list) |
| `n` | new table |
| `c` | new chain |
| `e` | edit selected table or chain |
| `d` | delete selected table or chain |
| `/` | search |
| `r` | refresh from kernel |
| `q` / `Esc` / `Ctrl+C` | quit |

### Chain view (rule list)

| Key | Action |
|-----|--------|
| `↑` / `k` | move selection up |
| `↓` / `j` | move selection down |
| `F3` | view rule |
| `F4` | edit rule |
| `a` | append rule at end |
| `i` | insert rule before selected |
| `K` (Shift+k) | move selected rule up |
| `J` (Shift+j) | move selected rule down |
| `d` | delete rule |
| `/` | filter rules by substring (verdict, condition keyword, comment) |
| `Esc` | back |
| `q` | quit |

While the filter is active, `↑` / `↓` navigate the filtered list, `Enter` /
`F3` open the selected rule for viewing, `F4` opens the editor, and `Esc`
clears the filter.

### Rule editor

| Key | Action |
|-----|--------|
| `F5` / `F6` | previous / next tab |
| `Tab` / `Shift+Tab` | next / previous field |
| `F2` | save (validate + apply to kernel) |
| `Esc` / `F3` | back |
| `q` / `Ctrl+C` | quit |

## Example ruleset

`examples/example-nftables-01.conf` is the canonical manual-test fixture. It
covers every feature documented above and is verified with `nft -c -f` against
the host kernel. Load it explicitly only on a system where overwriting the
nftables state is OK:

```bash
sudo nft -c -f examples/example-nftables-01.conf       # syntax check
sudo nft flush ruleset                                 # reset (DANGER on prod)
sudo nft -f examples/example-nftables-01.conf          # apply
```

> `nftui` itself does **not** mutate the running ruleset on startup — it only
> reads the current kernel state and writes changes the user explicitly makes.

## Project layout

```
main.go                        program entry point
nft/                           kernel-talking core
  rule.go                      expression → Rule structure parser
  nft_linux.go                 netlink CRUD operations (Linux build tag)
  nft_stub.go                  no-op stubs for non-Linux builds
  expr/                        per-expression format helpers
  nftserializer/               ruleset → human-readable output
ui/                            Bubble Tea TUI
  main_window.go               top-level model (tree view)
  chain_view.go                rule list
  rule_view.go                 rule detail (read-only)
  rule_edit.go                 rule editor with tabbed FieldEditors
  field_*.go                   one file per FieldEditor
examples/example-nftables-01.conf  manual-test fixture
man/nftui.1                    man page (groff/mandoc; see "Installation")
CHANGELOG.md                   per-version release notes (Keep a Changelog format)
```

## Testing

```bash
go test ./...                            # unit tests (no kernel required)
sudo nft -c -f examples/example-nftables-01.conf   # validate the fixture
```

### Integration tests

Tests under the `integration` build tag exercise the live netlink readback
path by applying a small ruleset via `nft -f`, reading it back with the same
helpers the TUI uses, and asserting on the result. They're excluded from the
default `go test ./...` and skip themselves when not running as root, so a
plain `go test` stays portable.

```bash
sudo -E go test -tags=integration ./nft/ -v
```

Each test creates a uniquely-named table (timestamp-suffixed, so concurrent
runs and leftover state don't collide) and tears it down in `t.Cleanup`, even
when assertions fail. The `nft` binary must be on PATH; install it from the
`nftables` package on your distro if missing.

### Continuous integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs the same checks
on every push and pull request to `main` / `develop`:

- **Build & unit tests** — `gofmt -l`, `go vet ./...` (default and `integration`
  build tags), `go build ./...`, and `go test -race ./...`.
- **Integration tests** — installs the `nftables` package, then runs
  `sudo -E go test -tags=integration -v ./nft/` so the harness has the
  `CAP_NET_ADMIN` it needs to apply a live ruleset. Runs only after the
  unit-test job is green.

The Go version comes from `go.mod` via `actions/setup-go@v5` with
`go-version-file: go.mod`, so bumping the module's Go version updates CI in
the same commit. Concurrent runs on the same ref cancel earlier in-flight
runs (`cancel-in-progress: true`).

## Release history

Per-version release notes live in [CHANGELOG.md](CHANGELOG.md) in
[Keep a Changelog](https://keepachangelog.com/) format. Major milestones
to date:

- **v0.1.0** (2026-05-24) — first publishable release: full CT / meta / IP / port
  matches, every verdict action, full ruleset CRUD.
- **v0.2.0** (2026-05-24) — NAT statements (`snat`, `dnat`, `masquerade`), `queue`, `quota`.
- **v0.3.0** (2026-05-24) — extended protocol matches (ICMP / ICMPv6, SCTP, DCCP,
  AH, ESP, COMP, Ethernet, VLAN, ARP, IPv6 extension headers).
- **v0.4.0** (2026-05-24) — sets, maps and named objects.
- **v0.5.0** (2026-05-25) — sets / maps / named objects polish & hardening
  (interval-set delete fix, dynset flag, CIDR support, verdict maps).
- **v0.6.0** (2026-05-29) — feedback-channel consistency and transient-hint
  UX: auto-fading tree hints, unified Reset / Delete error routing.
- **v0.7.0** (2026-05-29) — error messaging (`CAP_NET_ADMIN` advice, rejected-rule
  display) and navigation (`/` search in the tree, `/` filter in `chainView`).
- **v0.8.0** (in progress) — CLI flags (`--table`, `--config`, `--read-only`,
  `--help`), release polish (CHANGELOG, man page), `sctp chunk` editor, async
  incremental loading.
- **v1.0.0** — integration test harness, CI, virtualized rule list, goreleaser,
  packaging.

## License

MIT — see [LICENSE](LICENSE).
