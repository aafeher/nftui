# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

# Community-maintained reference ebuild for nftui (binary release). nftui's own
# release pipeline does NOT publish to the Portage tree or a GURU overlay — this
# is a starting point for a Gentoo (proxy-)maintainer. It installs the prebuilt
# binary from the GitHub release rather than compiling from source.
#
# To use it from a local overlay, place it as:
#   net-firewall/nftui-bin/nftui-bin-0.9.0.ebuild
# then generate the Manifest (Gentoo records distfile digests there, not in the
# ebuild) and merge:
#   pkgdev manifest        # or: ebuild nftui-bin-0.9.0.ebuild manifest
#   emerge net-firewall/nftui-bin
#
# Gentoo users who prefer building from source can skip this entirely — the repo
# is a standard Go module: `go build -o nftui .`

EAPI=8

DESCRIPTION="Terminal user interface for managing the Linux nftables firewall"
HOMEPAGE="https://github.com/aafeher/nftui"

BASE_URI="https://github.com/aafeher/nftui/releases/download/v${PV}"
SRC_URI="
	amd64? ( ${BASE_URI}/nftui_${PV}_linux_amd64.tar.gz )
	arm64? ( ${BASE_URI}/nftui_${PV}_linux_arm64.tar.gz )
"

LICENSE="MIT"
SLOT="0"
# Binary package: keyworded only on the arches the release ships.
KEYWORDS="-* amd64 arm64"

# nftui shells out to nft(8) for --config load and table/chain rename.
RDEPEND="net-firewall/nftables"

# Prebuilt, already stripped (-s -w) static CGO-free binary: nothing to compile,
# strip, or test.
RESTRICT="strip test"

# The release tarball unpacks flat (nftui, man/, LICENSE, README.md, ...).
S="${WORKDIR}"

src_install() {
	dobin nftui
	doman man/nftui.1
	dodoc README.md CHANGELOG.md
}
