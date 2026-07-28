# tebako-crypto feedstock — build notes (roadmap 72/73)

The crypto toolkit payload: `libtebako-crypto`, a shared library exposing
the versioned C ABI `tebako_crypto_v1_*` over librnp (OpenPGP) + Botan 3
with full PQC, packed as a dwarfs/tfs payload. **This feedstock is the
ONLY rnp compilation site in the tebako ecosystem** (owner-locked):
everything is built here, from source, with our flags; every consumer
dlopens the payload and compiles none of it.

## Source provenance (every fetch is sha256-verified by Tpkg.fetch)

| source | version | url | sha256 |
|---|---|---|---|
| rnpgp/rnp | 0.18.1 | https://github.com/rnpgp/rnp/archive/refs/tags/v0.18.1.tar.gz | `8133cb825e6672725b33f93b8f4185d702b7444c58240f00d9f3dc886f5b0aae` |
| rnpgp/sexpp | c641a2f3 (rnp v0.18.1 submodule pin) | https://github.com/rnpgp/sexpp/archive/c641a2f36520bab783657a58650d9fda548b9dec.tar.gz | `0a4efa2f1a2f89be9fbd268f3e48fc0ebfb5d32bb989ad5d1942b52de2f49ce5` |
| Botan | 3.12.0 | https://botan.randombit.net/releases/Botan-3.12.0.tar.xz | `5370f98dc15f8c222ee1ce52cd61c8756a53be0dc57cc4c1b0714d5a09ad74fb` |
| json-c | 0.18 | https://github.com/json-c/json-c/archive/refs/tags/json-c-0.18-20240915.tar.gz | `3112c1f25d39eca661fe3fc663431e130cc6e2f900c081738317fba49d29e298` |
| zlib | 1.3.1 | https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz | `9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23` |
| bzip2 | 1.0.8 | https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz | `ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269` |

All sha256 values were computed locally over the first fetch from the
official hosts (GitHub release/archive endpoints, botan.randombit.net,
sourceware.org) and pinned in `recipe.yml`. NEVER upstream prebuilts —
the feedstock exists precisely so upstream prebuilt correctness stops
mattering anywhere in the ecosystem (roadmap 72).

Version choices:

- **rnp 0.18.1** — the current stable line; the payload version tracks
  the librnp version (tags `0.18.1`, `0.18.1-N` for packaging
  re-releases). CRYPTO_BACKEND=botan3 requires Botan ≥ 3.0 and pulls in
  rnp's C++20 path; ≥ 3.7 additionally requires Botan's PCURVES modules
  (present in 3.12.0, asserted). **Submodule caveat:** `src/libsexpp`
  is a git submodule and GitHub's auto-generated tag archive ships it
  EMPTY — the build populates it from the separately sha256-pinned
  sexpp tarball at the exact commit the superproject's gitlink records
  at tag v0.18.1 (`c641a2f3`, retrieved via the GitHub API).
- **Botan 3.12.0** — owner-pinned; the same upstream release the
  botan-src 0.31200.0 crate vendors (the tebako-signer interim scaffold
  builds it via botan-sys). Chosen integration: the official
  botan.randombit.net tarball — canonical packaging, same content class
  as the crate, cleaner for a cmake/autotools-free build than the
  crates.io repack.
- **json-c 0.18** — newest stable; rnp requires ≥ 0.11.
- **zlib 1.3.1** — current stable.
- **bzip2 1.0.8** — the latest (and final) upstream release. See the
  shim note below; 1.0.8 is the version whose hole was proven.

## The flags (owner-locked — the whole point of the exercise)

- rnp: `-DCRYPTO_BACKEND=botan3 -DENABLE_PQC=ON` — rnp's cmake defaults
  ENABLE_PQC **OFF**; with PQC explicitly ON rnp FATALs unless the Botan
  build provides `KMAC;DILITHIUM;KYBER;SPHINCS_PLUS_WITH_SHA2;
  SPHINCS_PLUS_WITH_SHAKE`. Static `librnp.a` (`BUILD_SHARED_LIBS=OFF`),
  plus `libsexpp.a` (rnp's vendored SEXP parser — static clients link
  it). `ENABLE_CRYPTO_REFRESH=ON` for the v6/PQC wire formats.
  **Asserted at build time** in two independent witnesses: the cmake
  cache (`ENABLE_PQC=ON`) and the generated `config.h`
  (`#define ENABLE_PQC`).
- Botan: `--disable-shared-library --disable-modules=unsupported
  --build-targets=static` — FULL Botan (owner-locked: "minimal and pqc
  are mutually exclusive; size is irrelevant by design — the toolkit is
  a separate download"). Botan always emits `-fPIC` for its static lib
  (configure.py: "so that position independent executables can be
  created that link to the static library"), so no PIC knob is needed.
  **Asserted at build time**: `botan/build.h` of the installed tree must
  define `BOTAN_HAS_KYBER`, `BOTAN_HAS_DILITHIUM`, `BOTAN_HAS_KMAC`,
  `BOTAN_HAS_SPHINCS_PLUS_WITH_SHA2`, `BOTAN_HAS_SPHINCS_PLUS_WITH_SHAKE`
  (rnp's check set) AND the FIPS-standardized successors
  `BOTAN_HAS_ML_KEM`, `BOTAN_HAS_ML_DSA`, `BOTAN_HAS_SLH_DSA_WITH_SHA2`,
  `BOTAN_HAS_SLH_DSA_WITH_SHAKE` — Botan 3.12.0 carries both naming
  generations, so rnp 0.18.1's PQC check passes and ML-KEM/ML-DSA/
  SLH-DSA are present for future ABI growth.
- macOS: `-mmacosx-version-min=11.0`, exported ONCE as
  `MACOSX_DEPLOYMENT_TARGET=11.0` for the whole leg (covers Botan's
  configure.py, the manual bzip2 compile, and every cmake build; the
  cmake builds also get `-DCMAKE_OSX_DEPLOYMENT_TARGET=11.0`). The
  0.1.8-prebuilt-was-macOS-26 lesson: the floor is set by US, not by the
  build host. Asserted post-link with `vtool -show-build-version`.
- json-c: `BUILD_SHARED_LIBS=OFF BUILD_STATIC_LIBS=ON BUILD_APPS=OFF`.
- zlib: `BUILD_SHARED_LIBS=OFF` (any stray shared variant is deleted
  before the rnp link so nothing can pick it up).
- bzip2: no upstream build system of consequence (plain Makefile, no
  PIC/soname control) — compiled directly: `-O2 -fPIC
  -D_FILE_OFFSET_BITS=64`, the libbz2.a member set from bzip2's own
  Makefile, `ar rcs`.

## The bz_internal_error shim (REQUIRED)

bzip2 1.0.8 **declares but never defines** `bz_internal_error`
(`bzlib_private.h`, called by the `AssertH` macro) — proven against the
official tarball, the Debian pool, and all mirrors. Shared libbz2
tolerates the dangling reference; a static link resolves everything and
fails (`undefined symbol: bz_internal_error, referenced by
decompress.c:614`). The shim (`src/bz_internal_shim.c`, copied verbatim
from `crates/tebako-signer/src/bz_internal_shim.c` in tebako-rs where it
was proven against the rnp-rs static link) provides the trivial
ABI-compatible definition, matching upstream bzip2 1.0.6 behavior. It is
compiled INTO `libbz2.a` at this single compilation site and asserted
with `nm` (`T _bz_internal_error`) — the hole is fixed at the source,
once, for every consumer of the toolkit.

## Feedstock patches

`patches/` follows the conventions naming rule
(`tfs-<name>-<maj>-<min>-x-<slug>.patch`); every patch must pass
`git apply --check` before it is applied, else the build aborts.

- `tfs-rnp-0-18-x-botan-3-12-ec-includes.patch` — Botan 3.12 split the
  EC headers: `<botan/ecc_key.h>` (pulled in by `<botan/ecdh.h>`) now
  only forward-declares `Botan::EC_Group`/`Botan::EC_Point`; the full
  definitions live in `<botan/ec_group.h>`/`<botan/ec_point.h>`. rnp
  0.18.1's `ec.cpp` and the PQC hybrid `exdsa_ecdhkem.cpp` used both
  classes through the old transitive include and fail with
  "incomplete type" errors. Pure include additions (plus
  `<botan/bigint.h>` in the KEM file, same accident class), no code
  change, harmless against older Botan. Upstream rnp main carries the
  same implicit dependency and will need the same fix when it moves to
  Botan 3.12.
- `tfs-rnp-0-18-x-gcc13-mem-cstring.patch` — `crypto/mem.cpp` uses
  `strlen()` without `<cstring>`; macOS clang/libc++ leaks the
  declaration transitively, gcc 13/libstdc++ (ubuntu-24.04) does not.
  One-line include addition, identical to the fix upstream rnp main
  carries in the same file (found by the linux CI leg, rehearsed in a
  linux/amd64 docker container before re-push).

## The link (closure rule)

`src/CMakeLists.txt` links `libtebako-crypto` from
`src/tebako_crypto_v1.cpp` against the static archives ONLY
(`find_library(... NAMES librnp.a libsexpp.a libbotan-3.a libjson-c.a
libz.a libbz2.a NO_DEFAULT_PATH REQUIRED)` — no shared variant can sneak
in). Symbol visibility: `-fvisibility=hidden` +
`__attribute__((visibility("default")))` on the API — ONLY
`tebako_crypto_v1_*` is exported (no rnp/botan symbols leak into
consumers that load other crypto). Linux additionally gets
`-static-libstdc++ -static-libgcc -Wl,--exclude-libs,ALL`: the runtime
closure is libc/libm and nothing else.

Artifact identity:

- linux: `lib/libtebako-crypto.so.1`, soname `libtebako-crypto.so.1`
  (cmake VERSION/SOVERSION chain collapsed to the single shipped file —
  the payload is dlopen'd by absolute path, and the libtfs extractor
  cannot read symlink inodes).
- macOS: `lib/libtebako-crypto.1.dylib`, install name
  `@rpath/libtebako-crypto.1.dylib` (the `.1` leaf is the soname-
  equivalent ABI tag, matching `tebako_crypto_v1_abi_version()`). One
  real file, no symlinks, by construction.

The closure is **verified**, not assumed — a leak fails the build:
`otool -L` (macOS) / `readelf -d` (linux) on the artifact must show only
the OS family (`/usr/lib`, `/System/Library` on macOS;
`libc.so.6`/`libm.so.6`/loader on linux). The same sweep runs again in
`tools/boot_smoke` on the bytes as they ship inside the image.

## The ABI (derived from the actual consumers)

`include/tebako_crypto_v1.h` is the contract; its surface is derived
one-for-one from the real call sites, not invented:

| consumer (tebako-rs) | ABI function(s) |
|---|---|
| `sign.rs::sign_detached` | `tebako_crypto_v1_sign_detached` |
| `sign.rs::verify_detached{,_full}` | `tebako_crypto_v1_verify_detached` (Trusted/Untrusted/Invalid + keyid hint classification, incl. the bare-"invalid" keyring-membership disambiguation) |
| `sign.rs::signature_issuer_fingerprint` | `tebako_crypto_v1_signature_issuer_fingerprint` (same packet-dump JSON scrape) |
| `sign.rs::dearmor_bytes`, `root.rs::armor_bytes` | `tebako_crypto_v1_{de}armor_bytes` |
| `keys.rs::generate_and_cache` (Ed25519/SHA-256/sign) | `tebako_crypto_v1_generate_key` |
| `keys.rs::identify{,_secret}`, `envelope.rs::public_key_from_secret` | `tebako_crypto_v1_export_key` |
| `keys.rs::keyid_bytes_from_fingerprint` | `tebako_crypto_v1_keyid_from_fingerprint` |
| `keyring.rs::fingerprint_of`, `envelope.rs::public_key_keyid` | `tebako_crypto_v1_key_fingerprint` (primary-key walk) |
| `envelope.rs::wrap_dek` | `tebako_crypto_v1_encrypt` (PKESK per recipient, AES-256/SHA-256, armor flag) |
| `envelope.rs::unwrap_dek`, `backends_enc.rs` recipient mount | `tebako_crypto_v1_decrypt` (wrong key → `E_DECRYPT`, the EKEY class → ENOKEY 126) |
| `envelope.rs::envelope_recipients` | `tebako_crypto_v1_envelope_recipients` (same PKESK "keyid" scrape) |
| `envelope.rs` recipient pairs (Ed25519 + X25519 subkey) | `tebako_crypto_v1_generate_key` + `TEBAKO_CRYPTO_GENERATE_ENCRYPTION_SUBKEY` |
| roadmap 45/72 ABI negotiation | `tebako_crypto_v1_abi_version`, `tebako_crypto_rnp_version_string` |

Buffer convention: caller-provided `(out, cap, len)` triples, the
operation always runs internally, `E_BUFFER_TOO_SMALL` + required size
when too small — no library-owned allocation crosses the boundary.
Errors: errno-style negative ints + per-context last-error string.
Contexts are not thread-safe (one per thread); everything except the
context keyring (`load_keys`/`generate_key` → `export_key`) is
stateless — key material is passed per call and never retained.

## Image tooling

Same rules as the inkscape feedstock: linux legs build mkdwarfs-t from
the pinned dwarfs-t commit `05e31631` (tag `tebako-v0.14.1-18`; no
published dwarfs-t releases exist) against the feedstock's pinned vcpkg
baseline — the recipe's `build.vcpkg` pin exists for THIS only (its
ports list is empty; vcpkg is not a crypto-dependency supplier).
macOS legs download mkdwarfs + tebakofs from tamatebako/libtfs release
v0.13.0, sha256-pinned in `recipe.yml` (`image.libtfs`).

## Proof (aarch64-macos leg, native Apple Silicon host)

**Build: PROVEN end-to-end** (2026-07-28, macOS 14 arm64 host, no
emulation). `tools/build recipe.yml 0.18.1 aarch64-macos`:

- 6 sources fetched sha256-verified (rnp + sexpp submodule pin + Botan +
  json-c + zlib + bzip2), libsexpp populated, the Botan-3.12 EC-include
  patch applied (`git apply --check` first).
- Botan 3.12.0 full build (static): PQC assertion passed —
  `BOTAN_HAS_KYBER/DILITHIUM/KMAC/SPHINCS_PLUS_WITH_SHA2/SPHINCS_PLUS_WITH_SHAKE`
  AND `BOTAN_HAS_ML_KEM/ML_DSA/SLH_DSA_WITH_SHA2/SLH_DSA_WITH_SHAKE` all
  present in `botan/build.h`.
- bzip2: shim archived — `ar t libbz2.a` shows `bz_internal_shim.o`,
  `nm` shows `T _bz_internal_error`.
- librnp 0.18.1 (static, botan3): `ENABLE_PQC=ON` confirmed in two
  witnesses (CMakeCache + generated `config.h`).
- `libtebako-crypto.1.dylib` linked (all crypto deps static), strip -x,
  ad-hoc codesign. **5,223,296 bytes**.

**Closure: PROVEN.** `otool -L` on the artifact — the complete
non-install-name reference set:

```
@rpath/libtebako-crypto.1.dylib   (install name)
/usr/lib/libc++.1.dylib           (the OS C++ runtime — the libstdc++ equivalent)
/usr/lib/libSystem.B.dylib        (libc/libm — the OS)
```

No botan/json-c/bz2/rnp/zlib dylibs — none can exist, they are static.
`vtool -show-build-version`: `platform MACOS minos 11.0 sdk 14.0` — the
deployment floor is ours, not the host's.

**Export surface: PROVEN.** `nm -gU` on the artifact lists exactly the
18 ABI symbols (`_tebako_crypto_v1_*` + `_tebako_crypto_rnp_version_string`)
— ld64 `-exported_symbols_list` whitelist; nothing of Botan/rnp/bzip2
leaks into a consumer's namespace. (linux: `-Wl,--exclude-libs,ALL`.)

**Pre-image smoke: PROVEN** (dlopen harness, empty environment):

```
[smoke] abi_version=1, librnp 0.18.1
[smoke] generated key B1C69B51551B4D1823817153901E66E4AA947C5A
[smoke] exported public (659 B) + secret (759 B) keys
[smoke] verify own signature: Trusted (signer 901e66e4aa947c5a)
[smoke] verify tampered data: Invalid (signer 901e66e4aa947c5a)
[smoke] verify against empty keyring: Untrusted (signer 901e66e4aa947c5a)
[smoke] verify stranger signature: Untrusted (signer 6ca4596d2c735599)
[smoke] issuer fingerprint: B1C69B51551B4D1823817153901E66E4AA947C5A
[smoke] armor round-trip: 125 B binary -> 243 B armored -> identical
[smoke] envelope recipients: 1fd89d8600ff5f1c (the recipient's encryption subkey)
[smoke] envelope: 325 B armored message -> decrypt round-trip identical
[smoke] wrong-key decrypt: E_DECRYPT (the named EKEY class)
BOOT_SMOKE_OK
```

**Image + boot-smoke from the image: PROVEN.** mkdwarfs (libtfs v0.13.0
release asset, sha256-verified): `tebako-crypto-0.18.1-aarch64-macos.tfs`
= **1,865,255 bytes** (1.9 MB), payload manifest filled by tools/stage.
`tools/boot_smoke` — tebakofs extract (no macFUSE; the documented
degraded path), harness compiled against the header SHIPPED IN THE
IMAGE, run with `env -i` against the dylib in the image: full ABI
exercise green (same output shape as above), otool sweep on the
in-image artifact clean:

```
[tpkg] otool sweep: 2 refs, all /usr/lib|/System (install name @rpath/libtebako-crypto.1.dylib)
[tpkg] BOOT_SMOKE_OK tebako-crypto-0.18.1-aarch64-macos.tfs
```

**macOS quirks found (solved, zero source patches of our own beyond the
documented EC-include patch):**

- GitHub's auto-generated tag archive ships rnp's `src/libsexpp`
  submodule EMPTY (rnp's cmake then fails at
  `install TARGETS ... sexpp`): the feedstock fetches sexpp separately
  at the superproject's pinned commit (recipe `sources.sexpp`).
- Modern cmake's FindBZip2: pre-setting `BZIP2_LIBRARIES` leaves the
  `BZip2::BZip2` imported target without a location (CMP0111 →
  `BZip2::BZip2-NOTFOUND` at generate). The build passes
  `BZIP2_LIBRARY_RELEASE` instead.
- Botan 3.12's configure has no `--with-pic`/`--disable-shared` (2.x
  names): `--disable-shared-library`; PIC is unconditional ("so that
  position independent executables can be created that link to the
  static library").
- Re-staging over an existing `dwarfs-t-bin/` copy SIGKILLED
  tebakofs (`Killed: 9`): an in-place truncate-rewrite of a signed
  binary invalidates its code signature. tools/stage removes the
  destination before copying.

## Proof (x86_64-linux-gnu leg, ubuntu-24.04, CI)

PENDING — filled from the CI run (run ids, artifact sizes, closure
evidence, boot-smoke output).

## Known limitations (honest list)

- Phase A platforms: `x86_64-linux-gnu`, `aarch64-macos`.
  `aarch64-linux-gnu` and `x86_64-macos` are mechanical follow-ups
  (PLATFORM_MAP already maps their runners; x86_64-macos needs the
  libtfs `*-macos-x86_64` pins and a macos-13 runner leg).
- glibc floor on linux: the artifact links the build host's glibc
  symbol versions (ubuntu-24.04 on CI → glibc ≥ 2.39 at run time) —
  standard for the dynamic tier. The macOS floor is pinned at 11.0.
- The ABI is v1: ML-DSA/ML-KEM key generation lands by algorithm name
  through `tebako_crypto_v1_generate_key`'s string parameter when the
  consumers need it — the backend (Botan 3.12 + rnp ENABLE_PQC) is
  already in place and asserted.
- `tools/publish` and the release job are wired but untagged/unexercised
  until the first real tag.
