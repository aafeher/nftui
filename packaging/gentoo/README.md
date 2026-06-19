# Gentoo packaging (reference)

These are **community-maintainable reference ebuilds**. nftui's release pipeline
does **not** publish to the Portage tree or a GURU overlay — they are a starting
point for a Gentoo (proxy-)maintainer. Both target `net-firewall/`.

| File | Package | Builds |
|------|---------|--------|
| `nftui-0.9.0.ebuild` | `net-firewall/nftui` | from source via `go-module.eclass` |
| `nftui-bin-0.9.0.ebuild` | `net-firewall/nftui-bin` | installs the prebuilt release binary |
| `metadata.xml` | (both) | upstream/maintainer metadata |

**Pick one.** Both install `/usr/bin/nftui`, so the ebuilds block each other
(`!!net-firewall/nftui` ↔ `!!net-firewall/nftui-bin`); Portage will not let both
be merged. The `-bin` package is fastest; the source package compiles locally.

## Using them in a local overlay

```bash
# 1. Place each ebuild in its package directory and add the metadata:
mkdir -p <overlay>/net-firewall/nftui-bin
cp nftui-bin-0.9.0.ebuild metadata.xml <overlay>/net-firewall/nftui-bin/

# 2. Generate the Manifest (Gentoo records distfile digests there, not in the
#    ebuild) and merge:
cd <overlay>/net-firewall/nftui-bin
pkgdev manifest          # or: ebuild nftui-bin-0.9.0.ebuild manifest
emerge net-firewall/nftui-bin
```

The source package (`net-firewall/nftui`) is identical except for the extra
dependency tarball described next.

## The source ebuild needs a dependency tarball

`go-module.eclass` forbids network access during the build, so the Go module
dependencies must be supplied as a separate tarball. nftui's release does not
attach one yet (tracked as a future candidate in `ROADMAP.md`), so generate and
host it yourself. From a clean checkout of the tag:

```bash
GOMODCACHE="${PWD}/go-mod" go mod download -modcacherw
tar caf nftui-0.9.0-deps.tar.xz go-mod
```

Then point the second `SRC_URI` entry at wherever you host it and regenerate the
Manifest.

## Per-release upkeep

Bump the ebuild version (rename the file), refresh checksums with
`pkgdev manifest`, regenerate the source deps tarball (source package only), and
re-verify the `LICENSE` set against `go.sum` if dependencies changed.
