# Contributing to nftui

Thanks for your interest in improving **nftui** — a terminal UI for managing
the Linux nftables firewall. This guide covers getting set up, the conventions
the codebase follows, and what a good change looks like.

## Code of Conduct

This project follows its [Code of Conduct](CODE_OF_CONDUCT.md). By
participating, you agree to uphold it.

## Reporting bugs and security issues

- **Bugs / feature ideas** — open a GitHub issue with the nftui version or
  commit, your distribution and kernel version, and clear reproduction steps.
- **Security vulnerabilities** — do **not** open a public issue; follow
  [SECURITY.md](SECURITY.md).

## Development setup

nftui is a single Go module; the Go version is pinned in `go.mod`.

```bash
go build ./...
go test ./...
```

Driving the TUI against the live firewall needs `CAP_NET_ADMIN`:

```bash
sudo go run .        # or grant the capability: sudo setcap cap_net_admin+ep <binary>
```

The README documents the integration-test suite (root-only, behind the
`integration` build tag) and the checks CI runs.

## Before you open a pull request

Every change must pass the same gate CI enforces:

```bash
gofmt -l .                    # must print nothing
go vet ./...
go vet -tags=integration ./...
go test -race ./...
```

Conventions:

- **One change per pull request.** Keep each PR to a single feature or fix;
  don't bundle unrelated work.
- **Tests.** Write a failing test first for a bug fix, and add tests alongside
  new features. Pure logic gets plain unit tests; the netlink / `nft` write
  paths are covered by the root-only integration suite.
- **English** for all code, comments, UI strings, and documentation.
- **`gofmt` is non-negotiable** — CI fails on any unformatted file.
- **CHANGELOG.md** — for any user-visible change, add an entry under the
  `[Unreleased]` section. The file follows
  [Keep a Changelog](https://keepachangelog.com/) and is **append-only**: never
  rewrite or delete an already-released version's section.
- **nftables correctness** — when adding or changing a rule-expression type,
  confirm the exact netlink encoding (operators, direction, value type) against
  a real rule, e.g. with `nft --debug=netlink`. The in-kernel representation is
  the source of truth, not the CLI text.

## Commit messages and pull requests

- Use clear, imperative commit subjects ("Add X", "Fix Y").
- Explain *what* changed and *why* in the body or PR description.
- Reference the issue a PR closes, if any.

## Branches and merging

`develop` is the integration branch; `main` holds released history and is
**protected**:

- Changes reach `main` through a **pull request** (normally `develop` → `main`)
  — direct pushes are blocked. No approving review is required, so a solo
  maintainer can self-merge once the checks are green.
- All required CI checks must pass before a PR can merge — **Build & unit
  tests**, **Integration tests (CAP_NET_ADMIN)**, **Vulnerability scan
  (govulncheck)**, **Reproducible build check**, **Nix flake build**, and
  **CodeQL (Analyze (Go))** — and the PR branch must be up to date with `main`.
- Force-pushes and deletion of `main` are disabled.

## Licensing

nftui is released under the MIT License (see [LICENSE](LICENSE)). By
contributing, you agree that your contributions are licensed under the same
terms.
