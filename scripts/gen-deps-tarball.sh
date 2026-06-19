#!/usr/bin/env bash
#
# Generate a reproducible Go module dependency tarball for offline source
# builds — chiefly the from-source Gentoo ebuild (packaging/gentoo/), whose
# go-module.eclass forbids network access during the build. The module CONTENTS
# are content-addressed by go.sum, so two runs with the same go.sum and the same
# mtime produce a byte-identical archive (deterministic tar + single-threaded
# xz). Integrity is therefore rooted in go.sum, independent of checksums.txt.
#
# Usage: gen-deps-tarball.sh <output.tar.xz> [mtime-epoch]
#   mtime-epoch defaults to $SOURCE_DATE_EPOCH, then 0.
set -euo pipefail

out="${1:?usage: gen-deps-tarball.sh <output.tar.xz> [mtime-epoch]}"
epoch="${2:-${SOURCE_DATE_EPOCH:-0}}"

work="$(mktemp -d)"
# Module-cache files are written read-only; make them writable before rm.
trap 'chmod -R u+w "$work" 2>/dev/null || true; rm -rf "$work"' EXIT

# Populate a throwaway module cache from go.mod / go.sum. -modcacherw leaves the
# files writable so the cache can be archived and cleaned up afterwards.
GOMODCACHE="$work/go-mod" go mod download -modcacherw

# Drop transient lock files so repeated runs match byte-for-byte.
rm -f "$work/go-mod/cache/lock" 2>/dev/null || true
find "$work/go-mod" -type f -name '*.lock' -delete 2>/dev/null || true

mkdir -p "$(dirname "$out")"

# Deterministic archive: sorted entries, pinned mtime, numeric root ownership,
# GNU format. Single-threaded xz embeds no timestamp and no thread-dependent
# block splitting, so the .xz is reproducible across machines.
tar --sort=name \
	--mtime="@${epoch}" \
	--owner=0 --group=0 --numeric-owner \
	--format=gnu \
	-C "$work" -cf - go-mod \
	| xz -9 -c > "$out"

echo "wrote ${out} ($(wc -c < "$out") bytes)"
