#!/usr/bin/env bash
# Shared helpers for tebako-crypto's feedstock tools.
# Sourced by tools/publish. Hard rule (docs/conventions.md in
# tebako-packages/index): every download is sha256-verified; there are no
# silent fallbacks — every helper fails loudly.

set -euo pipefail

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# fetch URL DEST — plain download, no verification (internal).
fetch() {
  echo "fetch: $1" >&2
  curl -fSL --retry 3 --retry-delay 2 -o "$2" "$1"
}

# fetch_verified URL EXPECTED_SHA256 DEST — download + verify, else die.
fetch_verified() {
  fetch "$1" "$3"
  local got
  got="$(sha256_of "$3")"
  if [ "$got" != "$2" ]; then
    echo "SHA256 MISMATCH: $1" >&2
    echo "  expected: $2" >&2
    echo "  got:      $got" >&2
    return 1
  fi
  echo "verified: $3 (sha256 $got)" >&2
}

# download_signer DESTDIR REPO RELEASE SHA256
# Downloads tebako-pkg-<version>-linux-gnu-x86_64 from the tamatebako/tebako
# release as tebako-pkg (the signer for the publish job, which always runs
# on ubuntu-24.04). The asset name carries the version, so the digest pinned
# in the recipe (signing.tool.sha256) is the trust anchor.
download_signer() {
  local destdir="$1" repo="$2" release="$3" sha256="$4"
  local asset="tebako-pkg-${release#v}-linux-gnu-x86_64"
  mkdir -p "$destdir"
  fetch_verified "https://github.com/${repo}/releases/download/${release}/${asset}" \
    "$sha256" "${destdir}/tebako-pkg"
  chmod +x "${destdir}/tebako-pkg"
}
