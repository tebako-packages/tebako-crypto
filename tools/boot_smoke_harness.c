/*
 * boot_smoke_harness.c — the libtebako-crypto boot smoke.
 *
 * dlopens the built library (argv[1]) and exercises the v1 ABI end to
 * end: ABI version, key generation (Ed25519 + X25519 subkey), export,
 * detached sign/verify with the full Trusted/Untrusted/Invalid
 * classification, issuer fingerprint, armor round-trip, and the ENC
 * envelope encrypt/decrypt round-trip including the wrong-key EKEY
 * class. Every function is resolved with dlsym — a missing symbol is a
 * failure, proving the export surface.
 *
 * Exit 0 + "BOOT_SMOKE_OK" on success; any check failure prints
 * "BOOT_SMOKE_FAIL: <what>" to stderr and exits 1.
 */

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tebako_crypto_v1.h"

/* ---- dlsym'd v1 surface ------------------------------------------- */

typedef uint32_t (*abi_version_fn)(void);
typedef const char *(*version_string_fn)(void);
typedef int (*create_fn)(tebako_crypto_v1_ctx **);
typedef void (*destroy_fn)(tebako_crypto_v1_ctx *);
typedef const char *(*last_error_fn)(const tebako_crypto_v1_ctx *);
typedef int (*load_keys_fn)(tebako_crypto_v1_ctx *, const uint8_t *, size_t, const char *, uint32_t);
typedef int (*generate_key_fn)(tebako_crypto_v1_ctx *, const char *, const char *, uint32_t, char *, size_t);
typedef int (*export_key_fn)(tebako_crypto_v1_ctx *, const char *, uint32_t, uint8_t *, size_t, size_t *);
typedef int (*key_fingerprint_fn)(tebako_crypto_v1_ctx *, const uint8_t *, size_t, size_t, char *, size_t);
typedef int (*keyid_from_fingerprint_fn)(const char *, uint8_t *);
typedef int (*sign_detached_fn)(tebako_crypto_v1_ctx *, const uint8_t *, size_t, const char *,
                                const uint8_t *, size_t, uint8_t *, size_t, size_t *);
typedef int (*verify_detached_fn)(tebako_crypto_v1_ctx *, const uint8_t *, size_t,
                                  const uint8_t *, size_t, const uint8_t *, size_t,
                                  const uint8_t *, int *, char *, size_t);
typedef int (*issuer_fingerprint_fn)(tebako_crypto_v1_ctx *, const uint8_t *, size_t, char *, size_t);
typedef int (*encrypt_fn)(tebako_crypto_v1_ctx *, const uint8_t *, size_t,
                          const uint8_t *const *, const size_t *, size_t, uint32_t,
                          uint8_t *, size_t, size_t *);
typedef int (*decrypt_fn)(tebako_crypto_v1_ctx *, const uint8_t *, size_t,
                          const uint8_t *, size_t, uint8_t *, size_t, size_t *);
typedef int (*envelope_recipients_fn)(tebako_crypto_v1_ctx *, const uint8_t *, size_t, size_t, char *, size_t);
typedef int (*armor_fn)(tebako_crypto_v1_ctx *, const uint8_t *, size_t, const char *, uint8_t *, size_t, size_t *);
typedef int (*dearmor_fn)(tebako_crypto_v1_ctx *, const uint8_t *, size_t, uint8_t *, size_t, size_t *);

static abi_version_fn p_abi_version;
static version_string_fn p_rnp_version;
static create_fn p_create;
static destroy_fn p_destroy;
static last_error_fn p_last_error;
static load_keys_fn p_load_keys;
static generate_key_fn p_generate_key;
static export_key_fn p_export_key;
static key_fingerprint_fn p_key_fingerprint;
static keyid_from_fingerprint_fn p_keyid_from_fingerprint;
static sign_detached_fn p_sign_detached;
static verify_detached_fn p_verify_detached;
static issuer_fingerprint_fn p_issuer_fingerprint;
static encrypt_fn p_encrypt;
static decrypt_fn p_decrypt;
static envelope_recipients_fn p_envelope_recipients;
static armor_fn p_armor;
static dearmor_fn p_dearmor;

static void *g_lib;
static tebako_crypto_v1_ctx *g_ctx;

static void fail(const char *what)
{
    const char *err = g_ctx ? p_last_error(g_ctx) : NULL;
    fprintf(stderr, "BOOT_SMOKE_FAIL: %s%s%s\n", what, err ? ": " : "", err ? err : "");
    if (g_ctx)
        p_destroy(g_ctx);
    if (g_lib)
        dlclose(g_lib);
    exit(1);
}

static void *resolve(const char *name)
{
    void *sym = dlsym(g_lib, name);
    if (!sym) {
        fprintf(stderr, "BOOT_SMOKE_FAIL: missing export %s\n", name);
        if (g_lib)
            dlclose(g_lib);
        exit(1);
    }
    return sym;
}

/* resolve every export up front: the surface is the contract */
static void resolve_all(void)
{
    p_abi_version = (abi_version_fn) resolve("tebako_crypto_v1_abi_version");
    p_rnp_version = (version_string_fn) resolve("tebako_crypto_rnp_version_string");
    p_create = (create_fn) resolve("tebako_crypto_v1_create");
    p_destroy = (destroy_fn) resolve("tebako_crypto_v1_destroy");
    p_last_error = (last_error_fn) resolve("tebako_crypto_v1_last_error");
    p_load_keys = (load_keys_fn) resolve("tebako_crypto_v1_load_keys");
    p_generate_key = (generate_key_fn) resolve("tebako_crypto_v1_generate_key");
    p_export_key = (export_key_fn) resolve("tebako_crypto_v1_export_key");
    p_key_fingerprint = (key_fingerprint_fn) resolve("tebako_crypto_v1_key_fingerprint");
    p_keyid_from_fingerprint = (keyid_from_fingerprint_fn) resolve("tebako_crypto_v1_keyid_from_fingerprint");
    p_sign_detached = (sign_detached_fn) resolve("tebako_crypto_v1_sign_detached");
    p_verify_detached = (verify_detached_fn) resolve("tebako_crypto_v1_verify_detached");
    p_issuer_fingerprint = (issuer_fingerprint_fn) resolve("tebako_crypto_v1_signature_issuer_fingerprint");
    p_encrypt = (encrypt_fn) resolve("tebako_crypto_v1_encrypt");
    p_decrypt = (decrypt_fn) resolve("tebako_crypto_v1_decrypt");
    p_envelope_recipients = (envelope_recipients_fn) resolve("tebako_crypto_v1_envelope_recipients");
    p_armor = (armor_fn) resolve("tebako_crypto_v1_armor_bytes");
    p_dearmor = (dearmor_fn) resolve("tebako_crypto_v1_dearmor_bytes");
}

/* generous fixed buffers (armored Ed25519+X25519 exports are ~1 KB;
 * messages a few hundred bytes over the payload) */
#define CAP 65536
static uint8_t g_buf_a[CAP];

static const char *outcome_name(int outcome)
{
    switch (outcome) {
    case TEBAKO_CRYPTO_VERIFY_TRUSTED: return "Trusted";
    case TEBAKO_CRYPTO_VERIFY_UNTRUSTED: return "Untrusted";
    case TEBAKO_CRYPTO_VERIFY_INVALID: return "Invalid";
    default: return "?";
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <path-to-libtebako-crypto>\n", argv[0]);
        return 2;
    }
    g_lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!g_lib) {
        fprintf(stderr, "BOOT_SMOKE_FAIL: dlopen: %s\n", dlerror());
        return 1;
    }
    resolve_all();

    /* meta */
    if (p_abi_version() != 1)
        fail("tebako_crypto_v1_abi_version() != 1");
    printf("[smoke] abi_version=1, librnp %s\n", p_rnp_version());

    if (p_create(&g_ctx) != TEBAKO_CRYPTO_OK || !g_ctx)
        fail("context create");

    /* key generation: two SUITE-1 pairs (Ed25519 + X25519 subkey) */
    char fp1[TEBAKO_CRYPTO_FINGERPRINT_CAP], fp2[TEBAKO_CRYPTO_FINGERPRINT_CAP];
    if (p_generate_key(g_ctx, "Ed25519", "tebako boot smoke <smoke@tebako>",
                       TEBAKO_CRYPTO_GENERATE_ENCRYPTION_SUBKEY, fp1, sizeof(fp1)) != TEBAKO_CRYPTO_OK)
        fail("generate_key #1");
    if (strlen(fp1) != TEBAKO_CRYPTO_FINGERPRINT_LEN)
        fail("fingerprint length != 40");
    if (p_generate_key(g_ctx, "Ed25519", "tebako boot smoke stranger <smoke2@tebako>",
                       TEBAKO_CRYPTO_GENERATE_ENCRYPTION_SUBKEY, fp2, sizeof(fp2)) != TEBAKO_CRYPTO_OK)
        fail("generate_key #2");
    printf("[smoke] generated key %s\n", fp1);

    /* export: exercise the two-call sizing convention (NULL -> size) */
    size_t pub1_len = 0, sec1_len = 0, sec2_len = 0;
    int rc = p_export_key(g_ctx, fp1,
                          TEBAKO_CRYPTO_EXPORT_ARMORED | TEBAKO_CRYPTO_EXPORT_PUBLIC | TEBAKO_CRYPTO_EXPORT_SUBKEYS,
                          NULL, 0, &pub1_len);
    if (rc != TEBAKO_CRYPTO_E_BUFFER_TOO_SMALL || pub1_len == 0)
        fail("export sizing call did not report the required capacity");
    uint8_t *pub1 = malloc(pub1_len), *sec1, *sec2;
    if (p_export_key(g_ctx, fp1,
                     TEBAKO_CRYPTO_EXPORT_ARMORED | TEBAKO_CRYPTO_EXPORT_PUBLIC | TEBAKO_CRYPTO_EXPORT_SUBKEYS,
                     pub1, pub1_len, &pub1_len) != TEBAKO_CRYPTO_OK)
        fail("export public key");
    if (p_export_key(g_ctx, fp1,
                     TEBAKO_CRYPTO_EXPORT_ARMORED | TEBAKO_CRYPTO_EXPORT_SECRET | TEBAKO_CRYPTO_EXPORT_SUBKEYS,
                     NULL, 0, &sec1_len) != TEBAKO_CRYPTO_E_BUFFER_TOO_SMALL)
        fail("export secret sizing call");
    sec1 = malloc(sec1_len);
    if (p_export_key(g_ctx, fp1,
                     TEBAKO_CRYPTO_EXPORT_ARMORED | TEBAKO_CRYPTO_EXPORT_SECRET | TEBAKO_CRYPTO_EXPORT_SUBKEYS,
                     sec1, sec1_len, &sec1_len) != TEBAKO_CRYPTO_OK)
        fail("export secret key");
    if (p_export_key(g_ctx, fp2,
                     TEBAKO_CRYPTO_EXPORT_ARMORED | TEBAKO_CRYPTO_EXPORT_SECRET | TEBAKO_CRYPTO_EXPORT_SUBKEYS,
                     NULL, 0, &sec2_len) != TEBAKO_CRYPTO_E_BUFFER_TOO_SMALL)
        fail("export secret #2 sizing call");
    sec2 = malloc(sec2_len);
    if (p_export_key(g_ctx, fp2,
                     TEBAKO_CRYPTO_EXPORT_ARMORED | TEBAKO_CRYPTO_EXPORT_SECRET | TEBAKO_CRYPTO_EXPORT_SUBKEYS,
                     sec2, sec2_len, &sec2_len) != TEBAKO_CRYPTO_OK)
        fail("export secret key #2");
    printf("[smoke] exported public (%zu B) + secret (%zu B) keys\n", pub1_len, sec1_len);

    /* key_fingerprint walk: index 0 is the primary, index 1 terminates */
    char fp_walk[TEBAKO_CRYPTO_FINGERPRINT_CAP];
    if (p_key_fingerprint(g_ctx, pub1, pub1_len, 0, fp_walk, sizeof(fp_walk)) != TEBAKO_CRYPTO_OK)
        fail("key_fingerprint index 0");
    if (strcmp(fp_walk, fp1) != 0)
        fail("key_fingerprint != generated fingerprint");
    if (p_key_fingerprint(g_ctx, pub1, pub1_len, 1, fp_walk, sizeof(fp_walk)) != TEBAKO_CRYPTO_E_NO_KEY)
        fail("key_fingerprint walk did not terminate with E_NO_KEY");

    /* keyid_from_fingerprint: low 64 bits of the fingerprint hex */
    uint8_t keyid1[TEBAKO_CRYPTO_KEYID_LEN], keyid2[TEBAKO_CRYPTO_KEYID_LEN];
    if (p_keyid_from_fingerprint(fp1, keyid1) != TEBAKO_CRYPTO_OK)
        fail("keyid_from_fingerprint #1");
    if (p_keyid_from_fingerprint(fp2, keyid2) != TEBAKO_CRYPTO_OK)
        fail("keyid_from_fingerprint #2");
    for (int i = 0; i < TEBAKO_CRYPTO_KEYID_LEN; i++) {
        unsigned want;
        if (sscanf(fp1 + 24 + 2 * i, "%2x", &want) != 1 || want != keyid1[i])
            fail("keyid != low 64 bits of the fingerprint");
    }

    /* sign + verify: the full classification */
    const char *message = "tebako crypto toolkit boot smoke — sign me";
    size_t data_len = strlen(message);
    size_t sig_len = 0;
    if (p_sign_detached(g_ctx, sec1, sec1_len, fp1, (const uint8_t *) message, data_len,
                        NULL, 0, &sig_len) != TEBAKO_CRYPTO_E_BUFFER_TOO_SMALL)
        fail("sign sizing call");
    uint8_t *sig = malloc(sig_len);
    if (p_sign_detached(g_ctx, sec1, sec1_len, fp1, (const uint8_t *) message, data_len,
                        sig, sig_len, &sig_len) != TEBAKO_CRYPTO_OK)
        fail("sign_detached");

    int outcome = -1;
    char signer[TEBAKO_CRYPTO_KEYID_HEX_CAP];
    if (p_verify_detached(g_ctx, pub1, pub1_len, (const uint8_t *) message, data_len,
                          sig, sig_len, keyid1, &outcome, signer, sizeof(signer)) != TEBAKO_CRYPTO_OK)
        fail("verify_detached (trusted)");
    if (outcome != TEBAKO_CRYPTO_VERIFY_TRUSTED)
        fail("own signature is not Trusted");
    printf("[smoke] verify own signature: %s (signer %s)\n", outcome_name(outcome), signer);

    const char *tampered = "tebako crypto toolkit boot smoke — tampered";
    if (p_verify_detached(g_ctx, pub1, pub1_len, (const uint8_t *) tampered, strlen(tampered),
                          sig, sig_len, keyid1, &outcome, signer, sizeof(signer)) != TEBAKO_CRYPTO_OK)
        fail("verify_detached (tampered)");
    if (outcome != TEBAKO_CRYPTO_VERIFY_INVALID)
        fail("tampered data is not Invalid");
    printf("[smoke] verify tampered data: %s (signer %s)\n", outcome_name(outcome), signer);

    if (p_verify_detached(g_ctx, NULL, 0, (const uint8_t *) message, data_len,
                          sig, sig_len, keyid1, &outcome, signer, sizeof(signer)) != TEBAKO_CRYPTO_OK)
        fail("verify_detached (empty keyring)");
    if (outcome != TEBAKO_CRYPTO_VERIFY_UNTRUSTED)
        fail("empty keyring is not Untrusted");
    printf("[smoke] verify against empty keyring: %s (signer %s)\n", outcome_name(outcome), signer);

    /* stranger's signature against key1's keyring: Untrusted */
    size_t sig2_len = 0;
    if (p_sign_detached(g_ctx, sec2, sec2_len, fp2, (const uint8_t *) message, data_len,
                        NULL, 0, &sig2_len) != TEBAKO_CRYPTO_E_BUFFER_TOO_SMALL)
        fail("sign #2 sizing call");
    uint8_t *sig2 = malloc(sig2_len);
    if (p_sign_detached(g_ctx, sec2, sec2_len, fp2, (const uint8_t *) message, data_len,
                        sig2, sig2_len, &sig2_len) != TEBAKO_CRYPTO_OK)
        fail("sign_detached #2");
    if (p_verify_detached(g_ctx, pub1, pub1_len, (const uint8_t *) message, data_len,
                          sig2, sig2_len, keyid2, &outcome, signer, sizeof(signer)) != TEBAKO_CRYPTO_OK)
        fail("verify_detached (stranger)");
    if (outcome != TEBAKO_CRYPTO_VERIFY_UNTRUSTED)
        fail("stranger signature is not Untrusted");
    printf("[smoke] verify stranger signature: %s (signer %s)\n", outcome_name(outcome), signer);

    /* issuer fingerprint off the signature packet */
    char issuer[TEBAKO_CRYPTO_FINGERPRINT_CAP];
    if (p_issuer_fingerprint(g_ctx, sig, sig_len, issuer, sizeof(issuer)) != TEBAKO_CRYPTO_OK)
        fail("signature_issuer_fingerprint");
    if (strcmp(issuer, fp1) != 0)
        fail("issuer fingerprint != signer fingerprint");
    printf("[smoke] issuer fingerprint: %s\n", issuer);

    /* armor round-trip */
    size_t arm_len = 0, back_len = 0;
    if (p_armor(g_ctx, sig, sig_len, "signature", NULL, 0, &arm_len) != TEBAKO_CRYPTO_E_BUFFER_TOO_SMALL)
        fail("armor sizing call");
    uint8_t *armored = malloc(arm_len);
    if (p_armor(g_ctx, sig, sig_len, "signature", armored, arm_len, &arm_len) != TEBAKO_CRYPTO_OK)
        fail("armor_bytes");
    if (strstr((const char *) armored, "-----BEGIN PGP SIGNATURE-----") == NULL)
        fail("armored signature lacks the PGP SIGNATURE header");
    if (p_dearmor(g_ctx, armored, arm_len, NULL, 0, &back_len) != TEBAKO_CRYPTO_E_BUFFER_TOO_SMALL)
        fail("dearmor sizing call");
    uint8_t *back = malloc(back_len);
    if (p_dearmor(g_ctx, armored, arm_len, back, back_len, &back_len) != TEBAKO_CRYPTO_OK)
        fail("dearmor_bytes");
    if (back_len != sig_len || memcmp(back, sig, sig_len) != 0)
        fail("armor/dearmor round-trip mismatch");
    printf("[smoke] armor round-trip: %zu B binary -> %zu B armored -> identical\n", sig_len, arm_len);

    /* the ENC envelope: encrypt to recipient, recipients listing,
     * decrypt round-trip, wrong key = the EKEY class */
    const char *secret_msg = "wrapped DEK: 32 bytes of image key......";
    const uint8_t *recipients[] = {pub1};
    size_t recipient_lens[] = {pub1_len};
    size_t env_len = 0;
    if (p_encrypt(g_ctx, (const uint8_t *) secret_msg, strlen(secret_msg),
                  recipients, recipient_lens, 1, TEBAKO_CRYPTO_ENCRYPT_ARMORED,
                  NULL, 0, &env_len) != TEBAKO_CRYPTO_E_BUFFER_TOO_SMALL)
        fail("encrypt sizing call");
    uint8_t *envelope = malloc(env_len);
    if (p_encrypt(g_ctx, (const uint8_t *) secret_msg, strlen(secret_msg),
                  recipients, recipient_lens, 1, TEBAKO_CRYPTO_ENCRYPT_ARMORED,
                  envelope, env_len, &env_len) != TEBAKO_CRYPTO_OK)
        fail("encrypt");
    if (strstr((const char *) envelope, "-----BEGIN PGP MESSAGE-----") == NULL)
        fail("envelope lacks the PGP MESSAGE header");

    char recipient_keyid[TEBAKO_CRYPTO_KEYID_HEX_CAP];
    if (p_envelope_recipients(g_ctx, envelope, env_len, 0, recipient_keyid,
                              sizeof(recipient_keyid)) != TEBAKO_CRYPTO_OK)
        fail("envelope_recipients index 0");
    /* the PKESK slot names the recipient's ENCRYPTION SUBKEY (not the
     * primary) — assert the 16-lowercase-hex shape, not a value */
    if (strlen(recipient_keyid) != 16)
        fail("envelope recipient keyid is not 16 hex chars");
    for (const char *p = recipient_keyid; *p; p++)
        if (!(*p >= '0' && *p <= '9') && !(*p >= 'a' && *p <= 'f'))
            fail("envelope recipient keyid is not lowercase hex");
    if (p_envelope_recipients(g_ctx, envelope, env_len, 1, recipient_keyid,
                              sizeof(recipient_keyid)) != TEBAKO_CRYPTO_E_NO_KEY)
        fail("envelope_recipients walk did not terminate with E_NO_KEY");
    printf("[smoke] envelope recipients: %s (the recipient's encryption subkey)\n",
           recipient_keyid);

    size_t plain_len = 0;
    if (p_decrypt(g_ctx, envelope, env_len, sec1, sec1_len, NULL, 0, &plain_len) != TEBAKO_CRYPTO_E_BUFFER_TOO_SMALL)
        fail("decrypt sizing call");
    uint8_t *plain = malloc(plain_len);
    if (p_decrypt(g_ctx, envelope, env_len, sec1, sec1_len, plain, plain_len, &plain_len) != TEBAKO_CRYPTO_OK)
        fail("decrypt");
    if (plain_len != strlen(secret_msg) || memcmp(plain, secret_msg, plain_len) != 0)
        fail("encrypt/decrypt round-trip mismatch");
    printf("[smoke] envelope: %zu B armored message -> decrypt round-trip identical\n", env_len);

    rc = p_decrypt(g_ctx, envelope, env_len, sec2, sec2_len, g_buf_a, sizeof(g_buf_a), &plain_len);
    if (rc != TEBAKO_CRYPTO_E_DECRYPT)
        fail("wrong-key decrypt is not the EKEY class (E_DECRYPT)");
    printf("[smoke] wrong-key decrypt: E_DECRYPT (the named EKEY class)\n");

    /* the trusted keyring path via load_keys: register key1, stranger
     * sig stays Untrusted; context keyring is independent of stateless
     * per-call verification above */
    if (p_load_keys(g_ctx, pub1, pub1_len, "GPG", TEBAKO_CRYPTO_KEY_PUBLIC) != TEBAKO_CRYPTO_OK)
        fail("load_keys");

    free(pub1);
    free(sec1);
    free(sec2);
    free(sig);
    free(sig2);
    free(armored);
    free(back);
    free(envelope);
    free(plain);

    p_destroy(g_ctx);
    g_ctx = NULL;
    dlclose(g_lib);
    g_lib = NULL;
    printf("BOOT_SMOKE_OK\n");
    return 0;
}
