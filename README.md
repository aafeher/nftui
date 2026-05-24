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
- Per-chain rule listing with human-readable rendering of every parsed
  expression.
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
| `Esc` | back |
| `q` | quit |

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
ROADMAP.md                     versioned milestone plan
```

## Testing

```bash
go test ./...                            # unit tests (no kernel required)
sudo nft -c -f examples/example-nftables-01.conf   # validate the fixture
```

## Roadmap

The full plan lives in [ROADMAP.md](ROADMAP.md). Highlights for releases
after v0.1.0:

- **v0.2.0** — NAT statements (`snat`, `dnat`, `masquerade`), `queue`,
  `quota`.
- **v0.3.0** — extended protocol matches (ICMP / ICMPv6 fields, SCTP, DCCP,
  AH, ESP, COMP, Ethernet, VLAN, ARP, IPv6 extension headers).
- **v0.4.0** — sets, maps and named objects.
- **v1.0.0** — CLI flags, integration test harness, packaging.

## License

MIT — see [LICENSE](LICENSE).
