# Changelog

All notable changes to nftui are documented in this file.

The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Work in progress on v1.0.0 — release infrastructure pulled forward from earlier stubs.

### Added

- Virtualized rule-list rendering in `chainView`. Replaces the off-by-many `maxHeight := c.height - 20` (which assumed 1 line per rule and let the cursor scroll off-screen with the rest of the entries below it clipped by the content box) with a dynamic `maxVisibleRules()` that divides the available content-box height by the actual `ruleEntryLines = 4` and subtracts a `headerLines()` count computed from the chain's optional hook / priority / policy fields and the optional filter-prompt block. The render loop, the Down handler, and the filter-mode Down handler all route through `maxVisibleRules()` so a 1000-rule chain iterates the same `~5–10` entries as a 10-rule one. New `matchCache map[uint64]string` on `chainView` memoizes the lowercase `RuleToHumanReadable + ExtractComment` haystack per `rule.Handle`; `ruleMatchesFilter` reads it on every keystroke and only re-serializes on a cache miss. `RefreshRules` clears the cache (handles survive a rule edit but the rendered text behind them does not). Manual-test fixture: `examples/example-nftables-01.conf` section 48 (`table inet large_chain_demo` → `chain many_rules`) carries 60 hookless rules with `rule NN — ...` comments for scroll and filter exercises. Unit tests pin the `maxVisibleRules` / `headerLines` math and the cache hit / no-cache-on-empty-query behavior.

## [0.8.0] - 2026-05-30 — CLI surface, release polish, deep feature & async load

### Added

- `--table <name>` CLI flag restricts the tree to a single table at startup. Matches by name across all families; unknown names exit before the TUI starts with the list of available tables. Family is intentionally ignored, so a name that exists in multiple families (e.g. `filter` in both `ip` and `inet`) returns every match.
- `--config <file>` CLI flag applies a nftables ruleset via `nft -f <file>` before the TUI starts. `os.Stat` validates the path up front so a missing file yields a clear file-level error; the `nft` binary's output flows through verbatim on a syntax / kernel error. Resolved before `--table` so the post-load kernel state is what `--table` validates against.
- `--read-only` CLI flag disables every write path (rule add / insert / move / delete / edit / save, chain & table & set create / delete, counter reset). Belt-and-suspenders implementation: write `key.Binding`s get `SetEnabled(false)` (footer dims them, `key.Matches` short-circuits) AND the tree's string-match write handlers (`d`/`e`/`c`/`s`/`R`) carry explicit `if tm.readOnly { return … }` guards. A red `[READ-ONLY MODE]` marker rides in the title area of every main view.
- `--help` / `-h` CLI flag prints a clean usage block, flag list with placeholders, and common-invocation examples to stdout (exit 0). Invalid flags emit the same usage to stderr (exit 2) per Go convention. New `flagDocs` registry in `flags.go` is the single source of truth — flag registration, custom `writeUsage`, and the upcoming `nftui(1)` man page all read from it.
- `CHANGELOG.md` (this file) covering v0.1.0 → v0.7.0 in Keep a Changelog v1.1.0 format.
- `nftui(1)` man page (`man/nftui.1`, groff macros, mandoc-clean) covering invocation, options, key bindings per view, examples, environment, files, exit status. README's Installation section gains an "Installing the man page" subsection (`install -m 0644 man/nftui.1 /usr/share/man/man1/`).
- Async incremental per-chain rule loading: the table skeleton (tables + chain names + sets + named objects) renders immediately on startup; each chain's rule list arrives via a separate `loadRulesOfChainCmd` emitting `chainRulesLoadedMsg{tableFamily, tableName, chainName, rules}`. `chainNode.Loaded` distinguishes "unfetched" from "empty". The render shows `[loading rules...]` on chain rows until their fetch lands. Reduces perceived startup latency on rulesets with many chains and is the prerequisite for the upcoming virtualized rule list rendering.
- `sctp chunk` field editor (RFC 4960). New `nft/expr/sctp.go` with 21 chunk-type constants (DATA / INIT / INIT_ACK / SACK / HEARTBEAT / HEARTBEAT_ACK / ABORT / SHUTDOWN / SHUTDOWN_ACK / ERROR / COOKIE_ECHO / COOKIE_ACK / ECNE / CWR / SHUTDOWN_COMPLETE / AUTH / ASCONF_ACK / I_DATA / FORWARD_TSN / ASCONF / I_FORWARD_TSN) plus per-type fixed-offset sub-field metadata. Parser path classifies `Exthdr{Op=SCTP}` into a new `SctpChunkCondition`. Editor `SctpChunkField` has three slots — chunk-type Select, sub-field Select (options refresh on chunk-type change), and a value NumberInput — and writes either the bare-presence pair (`Exthdr{Op=3, Flags=F_PRESENT} + Cmp{Eq, [0x01]}`) or the sub-field pair (`Exthdr{Op=3, Offset=O, Len=L} + Cmp{Eq, BE-encoded value}`). The rule viewer surfaces both forms in a dedicated "SCTP chunks:" block.

## [0.7.0] - 2026-05-29 — Error messaging & navigation

### Added

- Netlink permission error (`EPERM` / `EACCES`) on the initial load now produces actionable advice (`sudo nftui`, or `sudo setcap cap_net_admin+ep <bin>`) instead of the raw syscall text. New `nft.IsPermissionError` helper composes the check from `errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)`; the styled advice lives in `loadErrorView` in the UI.
- Rule save failure now surfaces both the rendered rule text (via `nftserializer.SerializeRule`) and the kernel error on `ruleEdit.errStr`, so the user sees *which* rule failed and *why*. The underlying error is wrapped with `%w` so `errors.Is` still works downstream. New `formatSaveError` helper makes the error-shaping testable without netlink.
- `/` opens incremental name search in the main tree (`tableTreeModel`): case-insensitive substring match on table / chain / set / object names; `Enter` / `↓` cycle to the next match (wrapping), `↑` to the previous, `Esc` exits. Entering search auto-expands every table so rows inside collapsed tables are reachable; the tree is modal during search so keys don't leak to the global bindings.
- `/` opens inline rule filter in `chainView`: substring match on `nft.RuleToHumanReadable(rule) + nft.ExtractComment(rule)` (covers verdict, condition keywords, comment text); `↑` / `↓` navigate the filtered list; `f3` / `Enter` open the selected match in the rule viewer, `f4` opens the editor; `Esc` clears the filter.
- Shared search / filter invariants documented in the agent guide: modal capture (`IsModal()` true while the mode is active so typed letters build the query instead of triggering rule actions), footer-completeness via mode-swap keymaps (`treeSearchKeys`, `chainFilterKeys`), and the `chainView.RefreshRules` cursor-clamp for the round-trip through the rule editor.

### Fixed

- ASCII-only-icons invariant — replaced `⚠` in `rule_edit.go` `errStr` footer with `!`, and the `•` bullets in `chain_view.go` "Rules by type" counts and `set_view.go` add-prompt hints with `-` and `|` respectively.
- `chainView.RefreshRules` now clamps `cursor` and `scrollOffset` against the post-refresh `activeRules()` length so the cursor doesn't dangle past the end after returning from the rule editor while a filter is still active.
- Footer-completeness: `/` filter / search is in the *Short* help of `keyMap` and `chainViewKeyMap` (not only FullHelp), so the binding is discoverable from the always-visible footer rather than only when `?` toggles the full help.
- Return-value evaluation ordering footgun in the tree's R-key path (carried over from v0.6.0's late fix): `return tm, tm.setStatus(...)` was relying on Go evaluation order for a pointer-receiver mutation on the same struct that was the first return value. Refactored to explicit `cmd := tm.setStatus(...); return tm, cmd`.

## [0.6.0] - 2026-05-29 — Feedback channel consistency & transient-hint UX

### Added

- `setStatus` helper on `tableTreeModel` records a transient hint and returns a `tea.Tick`-based fade timer (auto-fade ~2s instead of the previous clear-on-keypress behavior). A `statusGen` counter is bumped on every set, so an in-flight tick from an earlier message can't clear a newer one.
- Four-channel status / feedback convention documented (in the project's agent guide): `tableTreeModel.statusMsg` (yellow, auto-fade hint), `setView` / `chainView.statusMsg` (red, acknowledge-on-keypress error), create/edit dialogs' `statusMsg` (red, persists until the next save attempt), `MainWindow.err` (red, replaces the whole tables box for fatal / load-time failures).

### Changed

- Named-object Reset / Delete kernel errors are routed through `tableTreeModel.statusMsg` (yellow status line, same channel as the matching no-op hint) instead of the global `m.err` (full-box red replacement). One channel per action result, distinguishable by color.
- `setView.addErr` and `addLastHint` are now mutually exclusive by construction. New `setAddErr` helper sets the red error and drops the green "added X" hint at the state level, so the bulk-add overlay never claims success and failure at once. The simplified render guard reads `if sv.addLastHint != ""` because the invariant makes the previous `&& sv.addErr == ""` guard redundant.
- Audit conclusion on transient-hint sites: `setView` / `chainView.statusMsg` are *error* surfaces (red `Error:`) with a deliberately different lifecycle from the tree's informational hints. No shared abstraction was extracted — forcing one lifecycle across three semantically different surfaces would over-couple them. The two-lifecycle distinction is what landed in the project's status-channel convention.

### Fixed

- A stale "no resettable …" hint no longer renders above the delete-confirm modal when both are active for the same row — added a `!tm.showDeleteConfirm` render guard.
- Tree status line comment in `main_window_table_list.go` updated to describe the auto-fade lifecycle (was still claiming "visible until the next key press clears it" from the pre-v0.6 behavior).

## [0.5.0] - 2026-05-25 — Sets/Maps Polish & Hardening

### Added

- Set-lookup and dynset `KeyField` labels include the protocol prefix (`ip saddr`, not bare `saddr`) — matches `nft list` output so the rendered form copy-pastes to the CLI.
- `setCreate` form exposes the `dynamic` flag (required for Dynset target sets); the full flow runs through `nft.CreateSet` so a Dynset can be created entirely from the UI.
- Delete named counter / quota / CT helper from the tree via `d` (previously only table / chain / set were handled).
- CIDR support in `ParseSetElementKey` for `flags interval` sets (start + end byte encoding for IPv4 / IPv6 ranges).
- Verdict-typed map values: `port → jump <chain>` style map entries (`expr.Verdict` in `el.Val`) render and edit correctly.
- Integer `SetDatatype` with custom byte width (1 / 2 / 4 / 8 bytes) — the previous hard-coded 4-byte assumption broke priority / DSCP maps.
- `R` reset on a non-counter / non-quota row surfaces a `statusMsg` ("no resettable object under cursor") instead of a silent no-op.
- Context-aware footer hints: `R` / `s` bindings dim when the cursor row doesn't support them, via `key.Binding.SetEnabled(...)` in `MainWindow.applyContextualKeys()`.
- Bulk-insert loop in `setView`'s `a` (Add element) prompt: Enter to add, prompt stays open with a "added X" hint, Esc to finish.
- Unit tests for `setView` / `setCreate` dialog `Update` state-machines (modal open / close, Tab key↔value switch, retry on bad input, mutual exclusion of `addErr` and `addLastHint`).
- Unit tests for `nft.{Create,Delete,Reset}Set*`, `AddSetElement`, `ListNamedObjects` — pure data-shaping helpers (`buildSetElements`, `pairIntervalElements`, `incrementBytes`/`decrementBytes`) extracted and tested without the live netlink dependency.
- Tree count format documentation `[N chains, N rules, N sets, N objs]` and set / map / object icons codified in the project's agent guide.

### Changed

- Single source of truth for set actions: `SetAction.Operation` string (`add` / `update` / `delete`) is the only state field; removed `SetAction.Update bool` (could drift from `Operation`), `SetAction.MapName`, and `SetAction.Elements []SetElement` (never written or read).
- ASCII map icon (`=`) replaces the previous UTF-8 `≈` so column alignment stays predictable on minimal terminals.
- ASCII-only-icons rule refined to: "single-char column-aligned icons must be ASCII; arrows used as text decoration inside labels (e.g. `keytype → datatype`) are exempt because they aren't column-aligned icons."

### Fixed

- Interval set element delete used to leave the orphan `IntervalEnd=true` close-marker behind (only the start element was removed), causing "element exists" collisions on re-add. `DeleteSetElement` now sends the matching two-element shape used in `buildSetElements`.

## [0.4.0] - 2026-05-24 — Sets, Maps & Named Objects

### Added

- Sidebar tree lists all sets per table; set detail view shows name, type, flags, elements.
- Maps: per-table listing, detail view, add / remove map entries.
- Named objects: counters, quotas, CT helpers per table. Reset named counter values to zero.
- Set-lookup conditions display in rule view; `add @setname { … }` dynset expressions parse and display.
- Set / map create and delete from the TUI; set element add / remove.
- `Objref` display in rule view (named-object references in rule actions: `counter name X`, `quota name X`, `ct helper set "X"`, `limit name X`).

## [0.3.0] - 2026-05-24 — Extended Protocol Matches

### Added

- ICMP and ICMPv6: `type`, `code` (uint8 + named-value Selects), `checksum`, `id`, `sequence`, `mtu`, `gateway`, `max-delay`.
- SCTP: `sport`, `dport`, `checksum`, `vtag`. (`sctp chunk` deferred to v0.8.0 — the RFC 4960 chunk-scoped editor needs a richer per-type field set.)
- DCCP: `sport`, `dport`, `type`.
- AH: `hdrlength`, `reserved`, `spi`, `sequence`.
- ESP: `spi`, `sequence`.
- COMP: `nexthdr`, `flags`, `cpi`.
- Ethernet (L2): `saddr` (MAC), `type` (EtherType uint16 — Select with hex fallback).
- VLAN: `id`, `cfi`, `pcp`.
- ARP: `operation`, `ptype`, `htype`, `hlen`, `plen`.
- IPv6 extension headers: `dst`, `frag`, `hbh`, `mh`, `rt` field editors.

## [0.2.0] - 2026-05-24 — NAT & Advanced Statements

### Added

- `masquerade` statement: parsing, rule-view display, toggle field editor.
- `snat to <addr>[:<port>]`: parsing, display, `SnatField` editor.
- `dnat to <addr>[:<port>]`: parsing, display, `DnatField` editor.
- `queue num <n>` (and ranges): parsing, display, `QueueField` editor.
- `quota [over] <n> [bytes|kbytes|mbytes]`: parsing, display, `QuotaField` editor.

## [0.1.0] - 2026-05-24 — First Release

The first publishable release. Everything below was reached through several
pre-release milestones: Foundation, Ruleset CRUD, Table & Chain Management,
Verdict & Core Action Statements, Remaining CT Fields, Meta Matches, IP &
IP6 Matches, TCP & UDP Transport Matches.

### Added

#### Browsing & rendering

- Hierarchical tree view of every table and chain in the running ruleset, fetched over netlink via `github.com/google/nftables`.
- Per-chain rule listing with human-readable rendering of every parsed expression (`nft.RuleToHumanReadable`) plus the canonical `nft list` form (`nftserializer.SerializeRule`).
- Per-rule detail view organised into tabs by condition category.

#### Rule editor — conditions

- **CT (conntrack):** `state`, `direction`, `status`, `mark`, `expiration`, `helper`, `bytes`, `pkts`, `avgpkt` (with `original` / `reply` / no-direction qualifier), `ip saddr`, `ip daddr`, `l3proto`, `protocol`, `proto-src`, `proto-dst`, `zone`, `label`, `count`, `secmark`, `eventmask` (MultiSelect of `IPCT_*` event bits).
- **Meta (interface, protocol, socket):** `iifname` / `oifname`, `iif` / `oif`, `iiftype` / `oiftype`, `iifgroup` / `oifgroup`, `length`, `protocol` (EtherType), `nfproto`, `l4proto`, `mark`, `priority`, `skuid` / `skgid`, `cgroup`, `pkttype`, `cpu`, `rtclassid`.
- **IPv4 header:** `saddr` / `daddr` (CIDR), `protocol`, `ttl`, `dscp`, `length`, `id`, `frag-off`, `checksum`, `version`, `hdrlength`.
- **IPv6 header:** `saddr` / `daddr` (CIDR), `nexthdr`, `hoplimit`, `dscp` (6-bit), `flowlabel` (20-bit), `length`, `version`.
- **TCP:** `sport` / `dport` (uint16 or range), `flags` (MultiSelect: fin/syn/rst/psh/ack/urg/ecn/cwr), `sequence`, `ackseq`, `window`, `checksum`, `urgptr`, `doff`.
- **UDP / UDPLITE:** `sport` / `dport`, `length`, `checksum`.

#### Rule editor — actions

- Verdicts: `accept`, `drop`, `return`, `jump <chain>`, `goto <chain>` (with chain name input).
- `reject` with type selector (`icmp type`, `icmpx type`, `tcp reset`) — family-aware (the ICMP type Select changes for ip / ip6 / inet / bridge tables).
- `log` with prefix, level (`emerg` … `debug`), NFLOG group, snaplen, queue-threshold — with pre-save validation against kernel-rejected combinations (e.g. `level` forbidden in NFLOG mode).
- `counter`: edit packet and byte counts on an anonymous counter (typical use is reset to 0).
- `limit`: rate, unit (`second` / `minute` / `hour` / `day` / `week`), burst, type (`packets` / `bytes`), over.
- Comment field stored in `rule.UserData` (TLV format).

#### Ruleset CRUD

- Rule: create at end / insert before, move up / move down within a chain, delete (with confirmation), edit.
- Table: create (name + family), rename, delete (warns if non-empty).
- Chain: create regular or base chain (hook, policy, priority, type), edit, delete (warns if rules present).

#### UX foundations

- Footer help line always lists every available key binding in the current view — the "footer-completeness" invariant.
- Custom UI components: `NumberInput` (numeric textinput with min/max bounds), `Select` (horizontal single-select), `MultiSelect` (horizontal checkboxes).

[Unreleased]: https://github.com/aafeher/nftui/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/aafeher/nftui/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/aafeher/nftui/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/aafeher/nftui/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/aafeher/nftui/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/aafeher/nftui/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/aafeher/nftui/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/aafeher/nftui/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/aafeher/nftui/releases/tag/v0.1.0
