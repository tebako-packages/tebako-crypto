/*
 * tebako_crypto_v1.h — the libtebako-crypto v1 C ABI (the contract).
 *
 * libtebako-crypto is the tebako crypto toolkit payload (roadmap 72): a
 * shared library backed by librnp (OpenPGP) over Botan 3 with full PQC,
 * dlopen'd on demand by the tebako bootstrap (install-time OpenPGP
 * verification), by runtimes (ENC decryption at file-I/O time), and by
 * the developer tools (tebako-signer, tebako-pkg) through the same path.
 * It is the ONLY compilation site for rnp in the ecosystem: everything
 * else consumes this ABI and never compiles rnp/botan.
 *
 * The engine is STATELESS: key material is passed per call as byte
 * strings (armored or binary OpenPGP exports) and never persists beyond
 * the call, except where a function is documented to accumulate into the
 * context keyring (tebako_crypto_v1_load_keys, tebako_crypto_v1_generate_key
 * — both exist so generated/imported keys can be re-exported by
 * fingerprint; destroying the context clears them).
 *
 * Rules of the ABI (binding on every client):
 *
 *  - Buffers: functions that produce bytes take a caller-provided
 *    (out, out_cap, out_len) triple. The operation always runs to
 *    completion internally; if out == NULL or out_cap is too small the
 *    function returns TEBAKO_CRYPTO_E_BUFFER_TOO_SMALL and stores the
 *    required capacity in *out_len. On success *out_len is the byte count
 *    written. No library-owned allocation ever crosses the boundary.
 *    Strings follow the same convention, capacity INCLUDING the trailing
 *    NUL (always written on success).
 *
 *  - Errors: every fallible function returns an int — TEBAKO_CRYPTO_OK
 *    (0) or a negative TEBAKO_CRYPTO_E_* code. A human-readable detail
 *    string is available per context via tebako_crypto_v1_last_error();
 *    the pointer is valid until the next call on the SAME context.
 *
 *  - Threads: a context is NOT thread-safe. Use one context per thread.
 *    Distinct contexts may be used concurrently.
 *
 *  - Versioning: the loader negotiates tebako_crypto_v1_abi_version()
 *    before resolving anything else. v1 == 1. The ABI versions like the
 *    runtime contract: a v2 library exports tebako_crypto_v2_* beside (or
 *    instead of) this surface; v1 symbols never change shape.
 *
 * Naming: every exported symbol carries the tebako_crypto_v1_ prefix.
 */

#ifndef TEBAKO_CRYPTO_V1_H
#define TEBAKO_CRYPTO_V1_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#  define TEBAKO_CRYPTO_CALL __cdecl
#  if defined(TEBAKO_CRYPTO_BUILD)
#    define TEBAKO_CRYPTO_API __declspec(dllexport)
#  else
#    define TEBAKO_CRYPTO_API __declspec(dllimport)
#  endif
#else
#  define TEBAKO_CRYPTO_CALL
#  define TEBAKO_CRYPTO_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Result codes (errno-style; 0 == success, negative == failure)       */
/* ------------------------------------------------------------------ */

#define TEBAKO_CRYPTO_OK 0
/* An argument is malformed or meaningless (bad fingerprint, empty key
 * blob where a key is required, NULL where not allowed, unknown index
 * type). Never a guess — the detail string names the argument. */
#define TEBAKO_CRYPTO_E_INVALID (-1)
/* out_cap is too small; *out_len carries the required capacity. */
#define TEBAKO_CRYPTO_E_BUFFER_TOO_SMALL (-2)
/* A required key is absent (signing key not found after load, no primary
 * key in an export) or an iteration index ran past the end. */
#define TEBAKO_CRYPTO_E_NO_KEY (-3)
/* The EKEY class: decryption failed because no envelope recipient slot
 * opens with the presented key (wrong key or tampered ciphertext — the
 * two are indistinguishable by construction). Maps to ENOKEY (126) on
 * the tebako side. */
#define TEBAKO_CRYPTO_E_DECRYPT (-4)
/* The verification itself could not run (unparsable signature, unreadable
 * keyring). A verification that RAN is not an error — see the outcome
 * codes of tebako_crypto_v1_verify_detached. */
#define TEBAKO_CRYPTO_E_VERIFY (-5)
/* Signing failed (unusable secret key, backend refusal). */
#define TEBAKO_CRYPTO_E_SIGN (-6)
/* Key generation failed. */
#define TEBAKO_CRYPTO_E_KEYGEN (-7)
/* The request names something v1 does not implement (unknown algorithm,
 * key format, or armor type). Named, never guessed. */
#define TEBAKO_CRYPTO_E_UNSUPPORTED (-8)
/* Anything else (backend failure without a better code); the detail
 * string carries the librnp error. */
#define TEBAKO_CRYPTO_E_INTERNAL (-9)

/* ------------------------------------------------------------------ */
/* Verification outcomes (a verification that ran is TEBAKO_CRYPTO_OK) */
/* ------------------------------------------------------------------ */

/* The signature is valid AND the signer's key is in the trusted keyring. */
#define TEBAKO_CRYPTO_VERIFY_TRUSTED 0
/* The signature is well-formed but the signer's key is NOT in the
 * trusted keyring (TOFU candidates: register the key, then re-verify). */
#define TEBAKO_CRYPTO_VERIFY_UNTRUSTED 1
/* The signature does not validate (tampered data or signature). */
#define TEBAKO_CRYPTO_VERIFY_INVALID 2

/* ------------------------------------------------------------------ */
/* Flags                                                               */
/* ------------------------------------------------------------------ */

/* tebako_crypto_v1_load_keys: which halves to import. */
#define TEBAKO_CRYPTO_KEY_PUBLIC 0x01u
#define TEBAKO_CRYPTO_KEY_SECRET 0x02u

/* tebako_crypto_v1_export_key. */
#define TEBAKO_CRYPTO_EXPORT_ARMORED 0x01u /* ASCII-armor the export     */
#define TEBAKO_CRYPTO_EXPORT_PUBLIC  0x02u /* public key material        */
#define TEBAKO_CRYPTO_EXPORT_SECRET  0x04u /* secret key material        */
#define TEBAKO_CRYPTO_EXPORT_SUBKEYS 0x08u /* include subkeys            */

/* tebako_crypto_v1_generate_key. */
#define TEBAKO_CRYPTO_GENERATE_SIGN_ONLY 0x00u
/* Add an encryption subkey (X25519 for Ed25519 primaries — the SUITE-1
 * recipient pair shape of the ENC envelope grants). */
#define TEBAKO_CRYPTO_GENERATE_ENCRYPTION_SUBKEY 0x01u

/* tebako_crypto_v1_encrypt: ASCII-armor the message (envelope grants
 * embed in YAML; binary is for channel use). */
#define TEBAKO_CRYPTO_ENCRYPT_ARMORED 0x01u

/* ------------------------------------------------------------------ */
/* Well-known sizes                                                    */
/* ------------------------------------------------------------------ */

/* OpenPGP v4 fingerprint: 40 uppercase hex chars, excl. NUL. */
#define TEBAKO_CRYPTO_FINGERPRINT_LEN 40
#define TEBAKO_CRYPTO_FINGERPRINT_CAP (TEBAKO_CRYPTO_FINGERPRINT_LEN + 1)
/* Signer keyid: low 64 bits of the fingerprint, raw bytes. */
#define TEBAKO_CRYPTO_KEYID_LEN 8
/* Keyid as 16 lowercase hex chars, excl. NUL. */
#define TEBAKO_CRYPTO_KEYID_HEX_CAP (2 * TEBAKO_CRYPTO_KEYID_LEN + 1)

typedef struct tebako_crypto_v1_ctx_st tebako_crypto_v1_ctx;

/* The version of this ABI surface (tebako_crypto_v1_abi_version()
 * returns it). The loader negotiates before resolving anything else. */
#define TEBAKO_CRYPTO_V1_ABI_VERSION 1u

/* ------------------------------------------------------------------ */
/* Meta                                                                */
/* ------------------------------------------------------------------ */

/* The ABI version this library exports. Always 1 for the v1 surface;
 * the loader calls this first and refuses anything it does not know. */
TEBAKO_CRYPTO_API uint32_t TEBAKO_CRYPTO_CALL tebako_crypto_v1_abi_version(void);

/* The librnp version string backing this build (e.g. "0.18.1") —
 * provenance for logs and bug reports, never for feature negotiation. */
TEBAKO_CRYPTO_API const char *TEBAKO_CRYPTO_CALL tebako_crypto_rnp_version_string(void);

/* ------------------------------------------------------------------ */
/* Context                                                             */
/* ------------------------------------------------------------------ */

/* Create a context. *ctx_out is set on TEBAKO_CRYPTO_OK. */
TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL tebako_crypto_v1_create(tebako_crypto_v1_ctx **ctx_out);

/* Destroy a context (NULL is a no-op). Clears any key material the
 * context accumulated via load_keys / generate_key. */
TEBAKO_CRYPTO_API void TEBAKO_CRYPTO_CALL tebako_crypto_v1_destroy(tebako_crypto_v1_ctx *ctx);

/* The detail string of the most recent error on this context ("" when
 * none). Valid until the next call on the SAME context. Never NULL for
 * a valid context; NULL when ctx is NULL. */
TEBAKO_CRYPTO_API const char *TEBAKO_CRYPTO_CALL tebako_crypto_v1_last_error(const tebako_crypto_v1_ctx *ctx);

/* Import key material into the CONTEXT keyring (armored or binary
 * transferable keys; concatenation of several is fine).
 *   format: "GPG" (the only format v1 reads; anything else is
 *           TEBAKO_CRYPTO_E_UNSUPPORTED).
 *   flags:  TEBAKO_CRYPTO_KEY_PUBLIC | TEBAKO_CRYPTO_KEY_SECRET (at
 *           least one required).
 * The context keyring exists so generated/imported keys can be
 * re-exported by fingerprint; the stateless per-call operations below
 * never read it. */
TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL tebako_crypto_v1_load_keys(
    tebako_crypto_v1_ctx *ctx,
    const uint8_t *key_bytes, size_t key_len,
    const char *format, uint32_t flags);

/* ------------------------------------------------------------------ */
/* Keys                                                                */
/* ------------------------------------------------------------------ */

/* Generate a key pair INTO the context keyring and return the primary
 * key fingerprint (40 uppercase hex + NUL; fp_cap >=
 * TEBAKO_CRYPTO_FINGERPRINT_CAP). Export the halves afterwards with
 * tebako_crypto_v1_export_key.
 *   algo:   "Ed25519" (the v1 algorithm; SHA-256 self-signatures, sign
 *           usage). PQC algorithms (ML-DSA family) join by name when the
 *           backend exposes them — anything unknown is
 *           TEBAKO_CRYPTO_E_UNSUPPORTED, never a silent substitution.
 *   userid: the primary uid embedded in the certificate.
 *   flags:  TEBAKO_CRYPTO_GENERATE_SIGN_ONLY, or
 *           TEBAKO_CRYPTO_GENERATE_ENCRYPTION_SUBKEY to add an X25519
 *           encryption subkey (the SUITE-1 recipient pair). */
TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL tebako_crypto_v1_generate_key(
    tebako_crypto_v1_ctx *ctx,
    const char *algo, const char *userid, uint32_t flags,
    char *fingerprint_out, size_t fingerprint_cap);

/* Export the key named by fingerprint from the context keyring.
 *   flags: EXPORT_PUBLIC|EXPORT_SECRET (exactly one), optionally
 *          EXPORT_ARMORED | EXPORT_SUBKEYS.
 * Secret exports never include private-key protection beyond what the
 * key already carries (tebako keys are generated unprotected — key
 * material protection is the $TEBAKO_HOME store's business). */
TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL tebako_crypto_v1_export_key(
    tebako_crypto_v1_ctx *ctx,
    const char *fingerprint, uint32_t flags,
    uint8_t *out, size_t out_cap, size_t *out_len);

/* The fingerprint (40 uppercase hex + NUL) of the index-th PRIMARY key
 * in a standalone key blob (armored or binary; concatenations allowed).
 * Iterate index from 0; TEBAKO_CRYPTO_E_NO_KEY terminates the walk.
 * Stateless: the blob is parsed per call, nothing is retained. */
TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL tebako_crypto_v1_key_fingerprint(
    tebako_crypto_v1_ctx *ctx,
    const uint8_t *key_bytes, size_t key_len, size_t index,
    char *fingerprint_out, size_t fingerprint_cap);

/* The signer keyid (low 64 bits of the fingerprint) as
 * TEBAKO_CRYPTO_KEYID_LEN raw bytes — the value written into the tpkg
 * v2 trailer. Pure function: no context, no error string; whitespace in
 * the fingerprint is ignored. TEBAKO_CRYPTO_E_INVALID on a short or
 * non-hex fingerprint. */
TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL tebako_crypto_v1_keyid_from_fingerprint(
    const char *fingerprint, uint8_t keyid_out[TEBAKO_CRYPTO_KEYID_LEN]);

/* ------------------------------------------------------------------ */
/* Signatures (detached OpenPGP over byte strings — the tpkg v2        */
/* trailer's signature block is produced and checked here)             */
/* ------------------------------------------------------------------ */

/* Produce a detached OpenPGP signature (binary, unarmored — armor it
 * with tebako_crypto_v1_armor_bytes when the wire format wants text).
 *   secret_key: armored or binary secret key export (loaded per call;
 *               nothing is retained).
 *   fingerprint: selects the signing key inside the export.
 * SHA-256 over the data; the signature carries the issuer fingerprint. */
TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL tebako_crypto_v1_sign_detached(
    tebako_crypto_v1_ctx *ctx,
    const uint8_t *secret_key, size_t secret_key_len,
    const char *fingerprint,
    const uint8_t *data, size_t data_len,
    uint8_t *sig_out, size_t sig_cap, size_t *sig_len);

/* Verify a detached signature against a trusted keyring with the full
 * Trusted/Untrusted/Invalid classification.
 *   trusted_keyring: concatenated binary (or armored) public keys;
 *                    empty (len 0) is valid and trusts nobody.
 *   signer_keyid_hint: the signer keyid recorded alongside the signature
 *                    (the tpkg v2 trailer carries it); NULL or all-zero
 *                    when unknown. It classifies an unknown signer
 *                    (UNTRUSTED) apart from a bad signature (INVALID)
 *                    when the backend reports a bare "invalid".
 *   outcome:  TEBAKO_CRYPTO_VERIFY_TRUSTED / _UNTRUSTED / _INVALID
 *             (written on TEBAKO_CRYPTO_OK).
 *   signer_keyid_out: the signer keyid as 16 lowercase hex + NUL
 *             (cap >= TEBAKO_CRYPTO_KEYID_HEX_CAP), when one is known
 *             (from the signature, else from the hint); "" for INVALID
 *             with no known signer. Pass NULL with cap 0 to skip.
 * Returns TEBAKO_CRYPTO_OK whenever the verification RAN (the outcome
 * carries the classification); TEBAKO_CRYPTO_E_VERIFY when it could not
 * run; TEBAKO_CRYPTO_E_INVALID on malformed arguments. */
TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL tebako_crypto_v1_verify_detached(
    tebako_crypto_v1_ctx *ctx,
    const uint8_t *trusted_keyring, size_t keyring_len,
    const uint8_t *data, size_t data_len,
    const uint8_t *sig, size_t sig_len,
    const uint8_t signer_keyid_hint[TEBAKO_CRYPTO_KEYID_LEN],
    int *outcome,
    char *signer_keyid_out, size_t signer_keyid_cap);

/* The issuer fingerprint (40 uppercase hex + NUL) of a detached
 * signature, read off the signature packet — no keyring needed. */
TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL tebako_crypto_v1_signature_issuer_fingerprint(
    tebako_crypto_v1_ctx *ctx,
    const uint8_t *sig, size_t sig_len,
    char *fingerprint_out, size_t fingerprint_cap);

/* ------------------------------------------------------------------ */
/* Encryption (the ENC transform's DEK grant envelopes: one OpenPGP    */
/* message — PKESK per recipient over the payload — AES-256/SHA-256)   */
/* ------------------------------------------------------------------ */

/* Encrypt data to one or more recipient public keys (>= 1 required).
 *   recipients / recipient_lens: recipient_count armored-or-binary
 *                    public key exports; each must contain a primary key
 *                    (encryption-capable subkeys ride along in the
 *                    export, recipients are named by their primary).
 *   flags:  TEBAKO_CRYPTO_ENCRYPT_ARMORED for an ASCII-armored message
 *           (envelope grants), 0 for binary.
 * The message is one PKESK packet per recipient over the data —
 * tebako-signer's wrap_dek wire shape. */
TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL tebako_crypto_v1_encrypt(
    tebako_crypto_v1_ctx *ctx,
    const uint8_t *data, size_t data_len,
    const uint8_t *const *recipients, const size_t *recipient_lens,
    size_t recipient_count, uint32_t flags,
    uint8_t *out, size_t out_cap, size_t *out_len);

/* Decrypt an OpenPGP message with a secret key (armored or binary
 * export; loaded per call, nothing retained). Any failure to open a
 * recipient slot is TEBAKO_CRYPTO_E_DECRYPT — the named EKEY class,
 * never garbage, never a partial plaintext. */
TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL tebako_crypto_v1_decrypt(
    tebako_crypto_v1_ctx *ctx,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *secret_key, size_t secret_key_len,
    uint8_t *out, size_t out_cap, size_t *out_len);

/* The recipient keyids (16 lowercase hex + NUL each) an envelope is
 * wrapped to, read off the PKESK packets — no keyring needed. Iterate
 * index from 0; TEBAKO_CRYPTO_E_NO_KEY terminates the walk.
 * Identification only; decrypt is the authority on what a key opens. */
TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL tebako_crypto_v1_envelope_recipients(
    tebako_crypto_v1_ctx *ctx,
    const uint8_t *envelope, size_t envelope_len, size_t index,
    char *keyid_out, size_t keyid_cap);

/* ------------------------------------------------------------------ */
/* Armor                                                               */
/* ------------------------------------------------------------------ */

/* ASCII-armor a binary OpenPGP blob.
 *   armor_type: "signature", "public key", "secret key", or "message"
 *               (anything else: TEBAKO_CRYPTO_E_UNSUPPORTED). */
TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL tebako_crypto_v1_armor_bytes(
    tebako_crypto_v1_ctx *ctx,
    const uint8_t *data, size_t data_len, const char *armor_type,
    uint8_t *out, size_t out_cap, size_t *out_len);

/* Dearmor an ASCII-armored OpenPGP blob (detached signatures, key
 * material, messages). */
TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL tebako_crypto_v1_dearmor_bytes(
    tebako_crypto_v1_ctx *ctx,
    const uint8_t *data, size_t data_len,
    uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TEBAKO_CRYPTO_V1_H */
