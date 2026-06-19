# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

# Community-maintained reference ebuild for nftui (built FROM SOURCE via
# go-module.eclass). nftui does NOT publish this to the Portage tree or a GURU
# overlay — it is a starting point for a Gentoo (proxy-)maintainer. See
# nftui-bin-${PV}.ebuild in this directory for the prebuilt-binary alternative
# (the two install the same /usr/bin/nftui, so don't merge both).
#
# go-module.eclass forbids network access during the build, so the Go module
# dependencies must be supplied as a separate tarball. nftui's release pipeline
# does not (yet) attach one, so the maintainer generates and hosts it. From a
# clean checkout of the tag:
#   GOMODCACHE="${PWD}/go-mod" go mod download -modcacherw
#   tar caf nftui-${PV}-deps.tar.xz go-mod
# then point the second SRC_URI entry at wherever it is hosted, run
#   ebuild nftui-${PV}.ebuild manifest
# (Gentoo records distfile digests in Manifest, not the ebuild), and emerge.

EAPI=8

inherit go-module

DESCRIPTION="Terminal user interface for managing the Linux nftables firewall"
HOMEPAGE="https://github.com/aafeher/nftui"

SRC_URI="
	https://github.com/aafeher/nftui/archive/refs/tags/v${PV}.tar.gz -> ${P}.tar.gz
	https://github.com/aafeher/nftui/releases/download/v${PV}/${P}-deps.tar.xz
"

# MIT for nftui itself, plus the licenses of the bundled Go module dependencies
# (go-module.eclass expects every vendored module's license listed). The set
# below covers the current go.sum; re-verify against the deps tarball on bumps.
LICENSE="Apache-2.0 BSD ISC MIT"
SLOT="0"
KEYWORDS="~amd64 ~arm64"

# nftui shells out to nft(8) for --config load and table/chain rename. The -bin
# variant installs the same /usr/bin/nftui, so the two cannot be merged together.
RDEPEND="
	net-firewall/nftables
	!!net-firewall/nftui-bin
"

src_compile() {
	# Inject the version like the upstream Goreleaser build (V-1). go-module's
	# ego wrapper already passes -trimpath, and portage handles stripping.
	ego build -ldflags "-X main.version=${PV}" -o nftui .
}

src_install() {
	dobin nftui
	doman man/nftui.1
	dodoc README.md CHANGELOG.md
}
