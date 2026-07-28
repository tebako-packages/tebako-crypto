# tebako-crypto feedstock

The tebako **crypto toolkit payload** (roadmap 72/73): `libtebako-crypto`,
a shared library exposing the versioned C ABI `tebako_crypto_v1_*` over
**librnp 0.18.1** (OpenPGP) + **Botan 3.12.0** (full, PQC), packed as a
tebako payload (dwarfs/tfs image + payload manifest) and published via
GitHub Releases like every tebako-packages feedstock.

**This feedstock is the ONLY rnp compilation site in the tebako
ecosystem** (owner-locked, roadmap 72): rnp/botan/json-c/zlib/bzip2 are
built once, here, from source with our flags — never upstream prebuilts.
Everything else (the bootstrap, runtimes, tebako-signer, tebako-pkg)
dlopens the payload and compiles none of it.

## The payload

- `lib/libtebako-crypto.so.1` (linux) / `lib/libtebako-crypto.1.dylib`
  (macOS) — soname `libtebako-crypto.so.1`, install name
  `@rpath/libtebako-crypto.1.dylib`. Runtime closure: libc/libm only
  (libstdc++/libgcc static on linux; libc++ is the OS on macOS) — proven
  by a hard otool/readelf sweep in both `tools/build` and
  `tools/boot_smoke`.
- `include/tebako_crypto_v1.h` — the ABI contract, shipped in the image.

The ABI (context, signatures with Trusted/Untrusted/Invalid
classification, ENC envelope encrypt/decrypt, key generation incl.
Ed25519+X25519 recipient pairs, armor, meta) is derived from the actual
consumers — tebako-signer (`sign.rs`, `keys.rs`, `keyring.rs`,
`root.rs`, `envelope.rs`) and the ENC transform (`backends_enc.rs`).
Buffer convention: caller-provided `(out, cap, len)` triples; errno-style
int returns plus a per-context last-error string; no library-owned
allocations cross the boundary.

## Flags that are the whole point

- rnp: `-DCRYPTO_BACKEND=botan3 -DENABLE_PQC=ON` (rnp's cmake defaults
  PQC **OFF**), static `librnp.a`.
- Botan: full build, only `--disable-modules=unsupported` — PQC modules
  (KYBER/DILITHIUM/SPHINCS+ and the FIPS-standardized
  ML-KEM/ML-DSA/SLH-DSA) are **asserted present** at build time.
- macOS: `-mmacosx-version-min=11.0` via `MACOSX_DEPLOYMENT_TARGET`
  (the 0.1.8-prebuilt-was-macOS-26 lesson).
- bzip2 1.0.8: built with the required `bz_internal_error` shim
  (`src/bz_internal_shim.c`, copied from tebako-signer where the missing
  symbol was proven) — archived into `libbz2.a` and asserted with `nm`.

## Feedstock flow (conventions: tebako-packages/index)

```
tools/build recipe.yml 0.18.1 aarch64-macos   # fetch+build+closure+pre-image smoke
tools/stage out/aarch64-macos aarch64-macos   # pack image + manifest
tools/boot_smoke out/aarch64-macos            # dlopen FROM the image, full ABI exercise
```

`tools/boot_smoke_harness.c` is the smoke: dlopen, keygen, export,
sign/verify (Trusted/tampered-Invalid/empty-keyring-Untrusted), issuer
fingerprint, armor round-trip, envelope encrypt/decrypt, wrong-key
EKEY class.

Platforms (phase A): `x86_64-linux-gnu`, `aarch64-macos`.

Releases carry per-platform images + payload manifests + SHA256SUMS +
`tpkg-registry.yaml` (tag `<rnp-version>` or `<rnp-version>-N` for
packaging re-releases).

Provenance, per-source sha256, closure rules, and boot-smoke evidence:
[docs/build-notes.md](docs/build-notes.md).
