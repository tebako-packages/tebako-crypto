// tebako_crypto_v1.cpp — the libtebako-crypto v1 ABI over the librnp FFI.
//
// The contract lives in include/tebako_crypto_v1.h; this translation unit
// is its only implementation. The logic mirrors the proven consumers —
// tebako-signer (crates/tebako-signer/src/{sign,keys,keyring,envelope}.rs)
// and the ENC envelope (crates/tfs/src/backends_enc.rs) — one-for-one:
// same classification rules, same JSON scraping of the packet dump, same
// fingerprint-diff recipient identification.
//
// Everything but the context keyring is stateless: each operation builds
// a fresh rnp FFI context, loads the keys it was handed, operates, and
// tears down. Key material never outlives a call unless the caller put it
// in the context keyring (load_keys/generate_key → export_key).

#define TEBAKO_CRYPTO_BUILD 1
#include "tebako_crypto_v1.h"

#include <rnp/rnp.h>
#include <rnp/rnp_err.h> /* RNP_SUCCESS / RNP_ERROR_* — not pulled in by rnp.h */

#include <cstdarg>
#include <cstdio>
#include <cstring>

#include <algorithm>
#include <cctype>
#include <memory>
#include <new>
#include <string>
#include <utility>
#include <vector>

/* ------------------------------------------------------------------ */
/* Context                                                             */
/* ------------------------------------------------------------------ */

struct tebako_crypto_v1_ctx_st {
    rnp_ffi_t   ffi = nullptr; // context keyring (load_keys/generate/export)
    std::string error;
};

namespace {

/* RAII guard for rnp handles. */
template <typename T, rnp_result_t (*Destroy)(T)>
struct RnpGuard {
    T h = nullptr;
    ~RnpGuard()
    {
        if (h)
            Destroy(h);
    }
    RnpGuard() = default;
    RnpGuard(const RnpGuard &) = delete;
    RnpGuard &operator=(const RnpGuard &) = delete;
    RnpGuard(RnpGuard &&other) noexcept : h(other.h) { other.h = nullptr; }
    RnpGuard &operator=(RnpGuard &&other) noexcept
    {
        if (this != &other) {
            if (h)
                Destroy(h);
            h = other.h;
            other.h = nullptr;
        }
        return *this;
    }
    T *out() { return &h; }
        operator T() const { return h; }
    T   get() const { return h; }
};

using FfiGuard    = RnpGuard<rnp_ffi_t, rnp_ffi_destroy>;
using InputGuard  = RnpGuard<rnp_input_t, rnp_input_destroy>;
using OutputGuard = RnpGuard<rnp_output_t, rnp_output_destroy>;
using KeyGuard    = RnpGuard<rnp_key_handle_t, rnp_key_handle_destroy>;
using SignOpGuard = RnpGuard<rnp_op_sign_t, rnp_op_sign_destroy>;
using VerifyOpGuard = RnpGuard<rnp_op_verify_t, rnp_op_verify_destroy>;
using EncryptOpGuard = RnpGuard<rnp_op_encrypt_t, rnp_op_encrypt_destroy>;

struct BufferGuard {
    char *p = nullptr;
    ~BufferGuard()
    {
        if (p)
            rnp_buffer_destroy(p);
    }
    char **out() { return &p; }
};

int set_error(tebako_crypto_v1_ctx *ctx, int code, const char *fmt, ...)
{
    if (ctx) {
        char    buf[1024];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        ctx->error = buf;
    }
    return code;
}

int ok(tebako_crypto_v1_ctx *ctx)
{
    if (ctx)
        ctx->error.clear();
    return TEBAKO_CRYPTO_OK;
}

/* Compose "<what>: <rnp error string>" and return `code`. */
int rnp_err(tebako_crypto_v1_ctx *ctx, int code, const char *what, rnp_result_t rc)
{
    return set_error(ctx, code, "%s: %s", what, rnp_result_to_string(rc));
}

/* A fresh FFI context for one stateless operation (both keyrings GPG). */
int temp_ffi(tebako_crypto_v1_ctx *ctx, FfiGuard &ffi)
{
    rnp_result_t rc = rnp_ffi_create(ffi.out(), "GPG", "GPG");
    if (rc != RNP_SUCCESS)
        return rnp_err(ctx, TEBAKO_CRYPTO_E_INTERNAL, "cannot create an rnp context", rc);
    return TEBAKO_CRYPTO_OK;
}

int mem_input(tebako_crypto_v1_ctx *ctx, const uint8_t *buf, size_t len, InputGuard &input)
{
    rnp_result_t rc = rnp_input_from_memory(input.out(), buf, len, true);
    if (rc != RNP_SUCCESS)
        return rnp_err(ctx, TEBAKO_CRYPTO_E_INVALID, "cannot read the input bytes", rc);
    return TEBAKO_CRYPTO_OK;
}

int mem_output(tebako_crypto_v1_ctx *ctx, OutputGuard &output)
{
    /* max_alloc 0: unlimited growth (the two-call size convention bounds
     * what ever reaches the caller). */
    rnp_result_t rc = rnp_output_to_memory(output.out(), 0);
    if (rc != RNP_SUCCESS)
        return rnp_err(ctx, TEBAKO_CRYPTO_E_INTERNAL, "cannot allocate the output", rc);
    return TEBAKO_CRYPTO_OK;
}

/* Read an rnp memory output into a std::vector. */
int output_bytes(tebako_crypto_v1_ctx *ctx, rnp_output_t output, std::vector<uint8_t> &bytes)
{
    uint8_t *    buf = nullptr;
    size_t       len = 0;
    rnp_result_t rc = rnp_output_memory_get_buf(output, &buf, &len, false);
    if (rc != RNP_SUCCESS)
        return rnp_err(ctx, TEBAKO_CRYPTO_E_INTERNAL, "cannot collect the output", rc);
    bytes.assign(buf, buf + len);
    return TEBAKO_CRYPTO_OK;
}

/* The two-call buffer convention: always sets *out_len. */
int copy_out(tebako_crypto_v1_ctx *ctx,
             uint8_t *out, size_t out_cap, size_t *out_len,
             const void *data, size_t data_len)
{
    if (!out_len)
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "out_len must not be NULL");
    *out_len = data_len;
    if (!out || out_cap < data_len)
        return set_error(ctx, TEBAKO_CRYPTO_E_BUFFER_TOO_SMALL,
                         "output buffer too small: need %zu bytes", data_len);
    if (data_len)
        memcpy(out, data, data_len);
    return ok(ctx);
}

/* Load keys into `ffi` from a byte blob. `what` names the blob in errors. */
int load_blob(tebako_crypto_v1_ctx *ctx, rnp_ffi_t ffi,
              const uint8_t *bytes, size_t len, uint32_t flags, const char *what)
{
    InputGuard input;
    int        rc = mem_input(ctx, bytes, len, input);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    rnp_result_t rrc = rnp_load_keys(ffi, "GPG", input, flags);
    if (rrc != RNP_SUCCESS)
        return rnp_err(ctx, TEBAKO_CRYPTO_E_INVALID, what, rrc);
    return TEBAKO_CRYPTO_OK;
}

/* Every fingerprint currently in the context's keyrings (load order).
 * The iterator owns the returned identifiers (no free); exhaustion is
 * RNP_SUCCESS with NULL. */
int all_fingerprints(tebako_crypto_v1_ctx *ctx, rnp_ffi_t ffi, std::vector<std::string> &fps)
{
    rnp_identifier_iterator_t it = nullptr;
    rnp_result_t              rc = rnp_identifier_iterator_create(ffi, &it, "fingerprint");
    if (rc != RNP_SUCCESS)
        return rnp_err(ctx, TEBAKO_CRYPTO_E_INTERNAL, "cannot list the keyring", rc);
    for (;;) {
        const char *ident = nullptr;
        rc = rnp_identifier_iterator_next(it, &ident);
        if (rc != RNP_SUCCESS) {
            rnp_identifier_iterator_destroy(it);
            return rnp_err(ctx, TEBAKO_CRYPTO_E_INTERNAL, "cannot list the keyring", rc);
        }
        if (ident == nullptr)
            break;
        fps.emplace_back(ident);
    }
    rnp_identifier_iterator_destroy(it);
    return TEBAKO_CRYPTO_OK;
}

/* Whether the ffi keyring holds a key with this keyid (16 hex, any case)
 * — sign.rs's keyring_has_keyid. */
int keyring_has_keyid(rnp_ffi_t ffi, const std::string &keyid_hex, bool &present)
{
    present = false;
    rnp_identifier_iterator_t it = nullptr;
    if (rnp_identifier_iterator_create(ffi, &it, "keyid") != RNP_SUCCESS)
        return TEBAKO_CRYPTO_E_INTERNAL;
    std::string want = keyid_hex;
    std::transform(want.begin(), want.end(), want.begin(), ::toupper);
    for (;;) {
        const char *ident = nullptr;
        if (rnp_identifier_iterator_next(it, &ident) != RNP_SUCCESS || ident == nullptr)
            break;
        std::string have = ident;
        std::transform(have.begin(), have.end(), have.begin(), ::toupper);
        if (have == want) {
            present = true;
            break;
        }
    }
    rnp_identifier_iterator_destroy(it);
    return TEBAKO_CRYPTO_OK;
}

std::string hex_lower(const uint8_t *bytes, size_t len)
{
    static const char digits[] = "0123456789abcdef";
    std::string       s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        s.push_back(digits[bytes[i] >> 4]);
        s.push_back(digits[bytes[i] & 15]);
    }
    return s;
}

std::string to_upper(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), ::toupper);
    return s;
}

/* The keyid (16 lowercase hex) of a key handle, "" when unavailable. */
std::string keyid_of(rnp_key_handle_t key)
{
    if (!key)
        return "";
    char *id = nullptr;
    if (rnp_key_get_keyid(key, &id) != RNP_SUCCESS || !id)
        return "";
    std::string out = id;
    rnp_buffer_destroy(id);
    std::transform(out.begin(), out.end(), out.begin(), ::tolower);
    return out;
}

/* Locate the freshly added PRIMARY key after loading a blob — envelope.rs's
 * load_recipient: recipients are named by their primary, exports may carry
 * encryption subkeys. */
int find_new_primary(tebako_crypto_v1_ctx *ctx, rnp_ffi_t ffi,
                     const std::vector<std::string> &before,
                     const char *what, KeyGuard &key_out)
{
    std::vector<std::string> after;
    int                      rc = all_fingerprints(ctx, ffi, after);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    for (const std::string &fp : after) {
        if (std::find(before.begin(), before.end(), fp) != before.end())
            continue;
        KeyGuard key;
        rnp_locate_key(ffi, "fingerprint", fp.c_str(), key.out());
        if (!key.get())
            continue;
        bool primary = false;
        if (rnp_key_is_primary(key, &primary) == RNP_SUCCESS && primary) {
            key_out = std::move(key);
            return TEBAKO_CRYPTO_OK;
        }
    }
    return set_error(ctx, TEBAKO_CRYPTO_E_NO_KEY,
                     "%s: the key export contains no primary key", what);
}

/* Escape a string for embedding in a JSON string literal. */
std::string json_escape(const char *s)
{
    std::string out;
    for (const unsigned char *p = reinterpret_cast<const unsigned char *>(s); *p; p++) {
        switch (*p) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (*p < 0x20) {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", *p);
                out += buf;
            } else {
                out.push_back(static_cast<char>(*p));
            }
        }
    }
    return out;
}

/* Dump packets of an in-memory blob to JSON (rnp's packet parser). */
int dump_json(tebako_crypto_v1_ctx *ctx, const uint8_t *bytes, size_t len,
              const char *what, std::string &json)
{
    InputGuard input;
    int        rc = mem_input(ctx, bytes, len, input);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    BufferGuard  j;
    rnp_result_t rrc = rnp_dump_packets_to_json(input, 0, j.out());
    if (rrc != RNP_SUCCESS)
        return rnp_err(ctx, TEBAKO_CRYPTO_E_INVALID, what, rrc);
    json = j.p ? j.p : "";
    return TEBAKO_CRYPTO_OK;
}

} // namespace

/* ------------------------------------------------------------------ */
/* Meta                                                                */
/* ------------------------------------------------------------------ */

extern "C" TEBAKO_CRYPTO_API uint32_t TEBAKO_CRYPTO_CALL
tebako_crypto_v1_abi_version(void)
{
    return TEBAKO_CRYPTO_V1_ABI_VERSION;
}

extern "C" TEBAKO_CRYPTO_API const char *TEBAKO_CRYPTO_CALL
tebako_crypto_rnp_version_string(void)
{
    return rnp_version_string();
}

/* ------------------------------------------------------------------ */
/* Context                                                             */
/* ------------------------------------------------------------------ */

extern "C" TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL
tebako_crypto_v1_create(tebako_crypto_v1_ctx **ctx_out)
{
    if (!ctx_out)
        return TEBAKO_CRYPTO_E_INVALID;
    *ctx_out = nullptr;
    std::unique_ptr<tebako_crypto_v1_ctx> ctx(new (std::nothrow) tebako_crypto_v1_ctx);
    if (!ctx)
        return TEBAKO_CRYPTO_E_INTERNAL;
    rnp_result_t rc = rnp_ffi_create(&ctx->ffi, "GPG", "GPG");
    if (rc != RNP_SUCCESS)
        return TEBAKO_CRYPTO_E_INTERNAL;
    *ctx_out = ctx.release();
    return TEBAKO_CRYPTO_OK;
}

extern "C" TEBAKO_CRYPTO_API void TEBAKO_CRYPTO_CALL
tebako_crypto_v1_destroy(tebako_crypto_v1_ctx *ctx)
{
    if (!ctx)
        return;
    if (ctx->ffi)
        rnp_ffi_destroy(ctx->ffi);
    delete ctx;
}

extern "C" TEBAKO_CRYPTO_API const char *TEBAKO_CRYPTO_CALL
tebako_crypto_v1_last_error(const tebako_crypto_v1_ctx *ctx)
{
    return ctx ? ctx->error.c_str() : nullptr;
}

extern "C" TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL
tebako_crypto_v1_load_keys(tebako_crypto_v1_ctx *ctx,
                           const uint8_t *key_bytes, size_t key_len,
                           const char *format, uint32_t flags)
{
    if (!ctx)
        return TEBAKO_CRYPTO_E_INVALID;
    if (!key_bytes || key_len == 0)
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "load_keys: empty key material");
    if (!format || strcmp(format, "GPG") != 0)
        return set_error(ctx, TEBAKO_CRYPTO_E_UNSUPPORTED,
                         "load_keys: unsupported key format (v1 reads \"GPG\")");
    if (!(flags & (TEBAKO_CRYPTO_KEY_PUBLIC | TEBAKO_CRYPTO_KEY_SECRET)))
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID,
                         "load_keys: at least one of KEY_PUBLIC/KEY_SECRET is required");
    uint32_t rnp_flags = 0;
    if (flags & TEBAKO_CRYPTO_KEY_PUBLIC)
        rnp_flags |= RNP_LOAD_SAVE_PUBLIC_KEYS;
    if (flags & TEBAKO_CRYPTO_KEY_SECRET)
        rnp_flags |= RNP_LOAD_SAVE_SECRET_KEYS;
    int rc = load_blob(ctx, ctx->ffi, key_bytes, key_len, rnp_flags,
                       "cannot load the key material");
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    return ok(ctx);
}

/* ------------------------------------------------------------------ */
/* Keys                                                                */
/* ------------------------------------------------------------------ */

extern "C" TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL
tebako_crypto_v1_generate_key(tebako_crypto_v1_ctx *ctx,
                              const char *algo, const char *userid, uint32_t flags,
                              char *fingerprint_out, size_t fingerprint_cap)
{
    if (!ctx)
        return TEBAKO_CRYPTO_E_INVALID;
    if (!algo || strcmp(algo, "Ed25519") != 0)
        return set_error(ctx, TEBAKO_CRYPTO_E_UNSUPPORTED,
                         "generate_key: unsupported algorithm (v1 generates \"Ed25519\")");
    if (!userid || !*userid)
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "generate_key: userid must not be empty");
    if (!fingerprint_out || fingerprint_cap < TEBAKO_CRYPTO_FINGERPRINT_CAP)
        return set_error(ctx, TEBAKO_CRYPTO_E_BUFFER_TOO_SMALL,
                         "generate_key: fingerprint buffer needs %u bytes",
                         (unsigned) TEBAKO_CRYPTO_FINGERPRINT_CAP);
    if (flags & ~static_cast<uint32_t>(TEBAKO_CRYPTO_GENERATE_ENCRYPTION_SUBKEY))
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "generate_key: unknown flags");

    /* The SUITE-1 recipient pair: Ed25519 primary (sign) + optional
     * X25519 encryption subkey — tebako-signer's keys.rs / envelope.rs. */
    std::string json = "{\"primary\":{\"type\":\"EDDSA\",\"userid\":\"" + json_escape(userid) +
                       "\",\"usage\":\"sign\",\"hash\":\"SHA256\"}";
    if (flags & TEBAKO_CRYPTO_GENERATE_ENCRYPTION_SUBKEY)
        json += ",\"sub\":{\"type\":\"ECDH\",\"curve\":\"Curve25519\",\"usage\":\"encrypt\","
                "\"hash\":\"SHA256\"}";
    json += "}";

    std::vector<std::string> before;
    int                      rc = all_fingerprints(ctx, ctx->ffi, before);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;

    BufferGuard  results;
    rnp_result_t rrc = rnp_generate_key_json(ctx->ffi, json.c_str(), results.out());
    if (rrc != RNP_SUCCESS)
        return rnp_err(ctx, TEBAKO_CRYPTO_E_KEYGEN, "key generation failed", rrc);

    KeyGuard primary;
    rc = find_new_primary(ctx, ctx->ffi, before, "generate_key", primary);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    char *fp = nullptr;
    rrc = rnp_key_get_fprint(primary, &fp);
    if (rrc != RNP_SUCCESS || !fp)
        return rnp_err(ctx, TEBAKO_CRYPTO_E_KEYGEN, "cannot read the new key's fingerprint",
                       rrc);
    std::string fingerprint = to_upper(fp);
    rnp_buffer_destroy(fp);
    memcpy(fingerprint_out, fingerprint.c_str(), fingerprint.size() + 1);
    return ok(ctx);
}

extern "C" TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL
tebako_crypto_v1_export_key(tebako_crypto_v1_ctx *ctx,
                            const char *fingerprint, uint32_t flags,
                            uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!ctx)
        return TEBAKO_CRYPTO_E_INVALID;
    if (!fingerprint || !*fingerprint)
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "export_key: empty fingerprint");
    bool pub = (flags & TEBAKO_CRYPTO_EXPORT_PUBLIC) != 0;
    bool sec = (flags & TEBAKO_CRYPTO_EXPORT_SECRET) != 0;
    if (pub == sec)
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID,
                         "export_key: exactly one of EXPORT_PUBLIC/EXPORT_SECRET is required");
    if (flags & ~(TEBAKO_CRYPTO_EXPORT_ARMORED | TEBAKO_CRYPTO_EXPORT_PUBLIC |
                  TEBAKO_CRYPTO_EXPORT_SECRET | TEBAKO_CRYPTO_EXPORT_SUBKEYS))
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "export_key: unknown flags");

    KeyGuard key;
    rnp_locate_key(ctx->ffi, "fingerprint", fingerprint, key.out());
    if (!key.get())
        return set_error(ctx, TEBAKO_CRYPTO_E_NO_KEY,
                         "export_key: no key with this fingerprint in the context keyring");

    uint32_t rnp_flags = 0;
    if (flags & TEBAKO_CRYPTO_EXPORT_ARMORED)
        rnp_flags |= RNP_KEY_EXPORT_ARMORED;
    rnp_flags |= pub ? RNP_KEY_EXPORT_PUBLIC : RNP_KEY_EXPORT_SECRET;
    if (flags & TEBAKO_CRYPTO_EXPORT_SUBKEYS)
        rnp_flags |= RNP_KEY_EXPORT_SUBKEYS;

    OutputGuard output;
    int         rc = mem_output(ctx, output);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    rnp_result_t rrc = rnp_key_export(key, output, rnp_flags);
    if (rrc != RNP_SUCCESS)
        return rnp_err(ctx, TEBAKO_CRYPTO_E_INTERNAL, "key export failed", rrc);
    std::vector<uint8_t> bytes;
    rc = output_bytes(ctx, output, bytes);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    return copy_out(ctx, out, out_cap, out_len, bytes.data(), bytes.size());
}

extern "C" TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL
tebako_crypto_v1_key_fingerprint(tebako_crypto_v1_ctx *ctx,
                                 const uint8_t *key_bytes, size_t key_len, size_t index,
                                 char *fingerprint_out, size_t fingerprint_cap)
{
    if (!ctx)
        return TEBAKO_CRYPTO_E_INVALID;
    if (!key_bytes || key_len == 0)
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "key_fingerprint: empty key material");
    if (!fingerprint_out || fingerprint_cap < TEBAKO_CRYPTO_FINGERPRINT_CAP)
        return set_error(ctx, TEBAKO_CRYPTO_E_BUFFER_TOO_SMALL,
                         "key_fingerprint: fingerprint buffer needs %u bytes",
                         (unsigned) TEBAKO_CRYPTO_FINGERPRINT_CAP);

    FfiGuard ffi;
    int      rc = temp_ffi(ctx, ffi);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    rc = load_blob(ctx, ffi, key_bytes, key_len, RNP_LOAD_SAVE_PUBLIC_KEYS,
                   "not a usable public key");
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;

    std::vector<std::string> fps;
    rc = all_fingerprints(ctx, ffi, fps);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    size_t seen = 0;
    for (const std::string &fp : fps) {
        KeyGuard key;
        rnp_locate_key(ffi, "fingerprint", fp.c_str(), key.out());
        if (!key.get())
            continue;
        bool primary = false;
        if (rnp_key_is_primary(key, &primary) != RNP_SUCCESS || !primary)
            continue;
        if (seen++ == index) {
            std::string fingerprint = to_upper(fp);
            memcpy(fingerprint_out, fingerprint.c_str(), fingerprint.size() + 1);
            return ok(ctx);
        }
    }
    return set_error(ctx, TEBAKO_CRYPTO_E_NO_KEY,
                     "key_fingerprint: no primary key at index %zu", index);
}

extern "C" TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL
tebako_crypto_v1_keyid_from_fingerprint(const char *fingerprint,
                                        uint8_t     keyid_out[TEBAKO_CRYPTO_KEYID_LEN])
{
    if (!fingerprint || !keyid_out)
        return TEBAKO_CRYPTO_E_INVALID;
    /* whitespace-stripped hex; the keyid is the low 64 bits (last 16 hex
     * chars) — keys.rs's keyid_bytes_from_fingerprint. */
    std::string hex;
    for (const char *p = fingerprint; *p; p++)
        if (!isspace(static_cast<unsigned char>(*p)))
            hex.push_back(*p);
    if (hex.size() < 16)
        return TEBAKO_CRYPTO_E_INVALID;
    const std::string keyid_hex = hex.substr(hex.size() - 16);
    for (size_t i = 0; i < TEBAKO_CRYPTO_KEYID_LEN; i++) {
        unsigned int byte = 0;
        if (sscanf(keyid_hex.c_str() + 2 * i, "%2x", &byte) != 1)
            return TEBAKO_CRYPTO_E_INVALID;
        keyid_out[i] = static_cast<uint8_t>(byte);
    }
    return TEBAKO_CRYPTO_OK;
}

/* ------------------------------------------------------------------ */
/* Signatures                                                          */
/* ------------------------------------------------------------------ */

extern "C" TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL
tebako_crypto_v1_sign_detached(tebako_crypto_v1_ctx *ctx,
                               const uint8_t *secret_key, size_t secret_key_len,
                               const char *fingerprint,
                               const uint8_t *data, size_t data_len,
                               uint8_t *sig_out, size_t sig_cap, size_t *sig_len)
{
    if (!ctx)
        return TEBAKO_CRYPTO_E_INVALID;
    if (!secret_key || secret_key_len == 0)
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "sign_detached: empty secret key");
    if (!fingerprint || !*fingerprint)
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "sign_detached: empty fingerprint");
    if (!data && data_len)
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "sign_detached: NULL data");

    FfiGuard ffi;
    int      rc = temp_ffi(ctx, ffi);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    rc = load_blob(ctx, ffi, secret_key, secret_key_len, RNP_LOAD_SAVE_SECRET_KEYS,
                   "cannot load the signing key");
    if (rc != TEBAKO_CRYPTO_OK)
        return set_error(ctx, TEBAKO_CRYPTO_E_SIGN, "%s", ctx->error.c_str());

    KeyGuard key;
    rnp_locate_key(ffi, "fingerprint", fingerprint, key.out());
    if (!key.get())
        return set_error(ctx, TEBAKO_CRYPTO_E_NO_KEY, "signing key not found after load");

    InputGuard input;
    rc = mem_input(ctx, data, data_len, input);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    OutputGuard output;
    rc = mem_output(ctx, output);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;

    SignOpGuard op;
    rnp_result_t rrc = rnp_op_sign_detached_create(op.out(), ffi, input, output);
    if (rrc != RNP_SUCCESS)
        return rnp_err(ctx, TEBAKO_CRYPTO_E_SIGN, "cannot create the signature", rrc);
    rrc = rnp_op_sign_set_hash(op, "SHA256");
    if (rrc != RNP_SUCCESS)
        return rnp_err(ctx, TEBAKO_CRYPTO_E_SIGN, "cannot set the hash", rrc);
    rrc = rnp_op_sign_add_signature(op, key, nullptr);
    if (rrc != RNP_SUCCESS)
        return rnp_err(ctx, TEBAKO_CRYPTO_E_SIGN, "cannot sign with this key", rrc);
    rrc = rnp_op_sign_execute(op);
    if (rrc != RNP_SUCCESS)
        return rnp_err(ctx, TEBAKO_CRYPTO_E_SIGN, "signing failed", rrc);

    std::vector<uint8_t> sig;
    rc = output_bytes(ctx, output, sig);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    return copy_out(ctx, sig_out, sig_cap, sig_len, sig.data(), sig.size());
}

extern "C" TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL
tebako_crypto_v1_verify_detached(tebako_crypto_v1_ctx *ctx,
                                 const uint8_t *trusted_keyring, size_t keyring_len,
                                 const uint8_t *data, size_t data_len,
                                 const uint8_t *sig, size_t sig_len,
                                 const uint8_t  signer_keyid_hint[TEBAKO_CRYPTO_KEYID_LEN],
                                 int *outcome,
                                 char *signer_keyid_out, size_t signer_keyid_cap)
{
    if (!ctx)
        return TEBAKO_CRYPTO_E_INVALID;
    if (!outcome)
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "verify_detached: NULL outcome");
    if (!data && data_len)
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "verify_detached: NULL data");
    if (!sig || sig_len == 0)
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "verify_detached: empty signature");
    if (signer_keyid_out && signer_keyid_cap < TEBAKO_CRYPTO_KEYID_HEX_CAP)
        return set_error(ctx, TEBAKO_CRYPTO_E_BUFFER_TOO_SMALL,
                         "verify_detached: keyid buffer needs %u bytes",
                         (unsigned) TEBAKO_CRYPTO_KEYID_HEX_CAP);

    FfiGuard ffi;
    int      rc = temp_ffi(ctx, ffi);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    if (trusted_keyring && keyring_len) {
        rc = load_blob(ctx, ffi, trusted_keyring, keyring_len, RNP_LOAD_SAVE_PUBLIC_KEYS,
                       "cannot load the trusted keyring");
        if (rc != TEBAKO_CRYPTO_OK)
            return set_error(ctx, TEBAKO_CRYPTO_E_VERIFY, "%s", ctx->error.c_str());
    }

    std::string hint_hex;
    if (signer_keyid_hint) {
        bool zero = true;
        for (size_t i = 0; i < TEBAKO_CRYPTO_KEYID_LEN; i++)
            zero &= signer_keyid_hint[i] == 0;
        if (!zero)
            hint_hex = hex_lower(signer_keyid_hint, TEBAKO_CRYPTO_KEYID_LEN);
    }

    InputGuard data_input, sig_input;
    rc = mem_input(ctx, data, data_len, data_input);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    rc = mem_input(ctx, sig, sig_len, sig_input);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;

    VerifyOpGuard op;
    rnp_result_t rrc = rnp_op_verify_detached_create(op.out(), ffi, data_input, sig_input);
    if (rrc != RNP_SUCCESS)
        return rnp_err(ctx, TEBAKO_CRYPTO_E_VERIFY, "cannot parse the signature", rrc);

    int         cls = TEBAKO_CRYPTO_VERIFY_INVALID;
    std::string keyid;
    rrc = rnp_op_verify_execute(op);
    if (rrc == RNP_SUCCESS) {
        size_t count = 0;
        if (rnp_op_verify_get_signature_count(op, &count) != RNP_SUCCESS || count == 0) {
            cls = TEBAKO_CRYPTO_VERIFY_INVALID; // no signature at all
        } else {
            rnp_op_verify_signature_t vsig = nullptr;
            if (rnp_op_verify_get_signature_at(op, 0, &vsig) != RNP_SUCCESS || !vsig) {
                cls = TEBAKO_CRYPTO_VERIFY_INVALID;
            } else {
                KeyGuard skey;
                rnp_op_verify_signature_get_key(vsig, skey.out());
                keyid = keyid_of(skey);
                rnp_result_t status = rnp_op_verify_signature_get_status(vsig);
                if (status == RNP_SUCCESS) {
                    cls = TEBAKO_CRYPTO_VERIFY_TRUSTED;
                } else if (status == RNP_ERROR_SIGNATURE_UNKNOWN ||
                           status == RNP_ERROR_KEY_NOT_FOUND) {
                    cls = TEBAKO_CRYPTO_VERIFY_UNTRUSTED;
                    if (keyid.empty())
                        keyid = hint_hex;
                } else {
                    cls = TEBAKO_CRYPTO_VERIFY_INVALID;
                }
            }
        }
    } else if (rrc == RNP_ERROR_SIG_NO_SIGNER_KEY || rrc == RNP_ERROR_SIG_NO_SIGNER_ID ||
               rrc == RNP_ERROR_SIGNATURE_UNKNOWN) {
        /* librnp knows the signer is missing from the keyring. */
        cls = TEBAKO_CRYPTO_VERIFY_UNTRUSTED;
        keyid = hint_hex;
    } else if (rrc == RNP_ERROR_SIGNATURE_INVALID) {
        /* Bare "invalid": an unknown signer and a tampered message look
         * alike to librnp — the keyring membership of the hinted keyid
         * tells them apart (sign.rs). */
        bool present = false;
        if (!hint_hex.empty() && keyring_has_keyid(ffi, hint_hex, present) == TEBAKO_CRYPTO_OK &&
            present) {
            cls = TEBAKO_CRYPTO_VERIFY_INVALID;
            keyid = hint_hex;
        } else {
            cls = TEBAKO_CRYPTO_VERIFY_UNTRUSTED;
            keyid = hint_hex;
        }
    } else if (rrc == RNP_ERROR_NO_SIGNATURES_FOUND) {
        cls = TEBAKO_CRYPTO_VERIFY_INVALID;
    } else {
        return rnp_err(ctx, TEBAKO_CRYPTO_E_VERIFY, "verification failed to run", rrc);
    }

    *outcome = cls;
    if (signer_keyid_out)
        memcpy(signer_keyid_out, keyid.c_str(), keyid.size() + 1);
    return ok(ctx);
}

extern "C" TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL
tebako_crypto_v1_signature_issuer_fingerprint(tebako_crypto_v1_ctx *ctx,
                                              const uint8_t *sig, size_t sig_len,
                                              char *fingerprint_out, size_t fingerprint_cap)
{
    if (!ctx)
        return TEBAKO_CRYPTO_E_INVALID;
    if (!sig || sig_len == 0)
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID,
                         "signature_issuer_fingerprint: empty signature");
    if (!fingerprint_out || fingerprint_cap < TEBAKO_CRYPTO_FINGERPRINT_CAP)
        return set_error(ctx, TEBAKO_CRYPTO_E_BUFFER_TOO_SMALL,
                         "signature_issuer_fingerprint: fingerprint buffer needs %u bytes",
                         (unsigned) TEBAKO_CRYPTO_FINGERPRINT_CAP);

    std::string json;
    int         rc = dump_json(ctx, sig, sig_len, "cannot parse the signature", json);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;

    /* sign.rs's scrape: the issuer-fingerprint subpacket, then its value. */
    const std::string needle = "\"issuer fingerprint\"";
    size_t            pos = json.find(needle);
    if (pos == std::string::npos)
        return set_error(ctx, TEBAKO_CRYPTO_E_VERIFY,
                         "no issuer fingerprint subpacket in the signature");
    const std::string tag = "\"fingerprint\":\"";
    size_t            fp_pos = json.find(tag, pos);
    if (fp_pos == std::string::npos)
        return set_error(ctx, TEBAKO_CRYPTO_E_VERIFY, "no fingerprint value in the signature");
    size_t start = fp_pos + tag.size();
    size_t end = json.find('"', start);
    if (end == std::string::npos)
        return set_error(ctx, TEBAKO_CRYPTO_E_VERIFY,
                         "malformed fingerprint value in the signature");
    std::string fp = to_upper(json.substr(start, end - start));
    memcpy(fingerprint_out, fp.c_str(), fp.size() + 1);
    return ok(ctx);
}

/* ------------------------------------------------------------------ */
/* Encryption                                                          */
/* ------------------------------------------------------------------ */

extern "C" TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL
tebako_crypto_v1_encrypt(tebako_crypto_v1_ctx *ctx,
                         const uint8_t *data, size_t data_len,
                         const uint8_t *const *recipients, const size_t *recipient_lens,
                         size_t recipient_count, uint32_t flags,
                         uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!ctx)
        return TEBAKO_CRYPTO_E_INVALID;
    if (!data && data_len)
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "encrypt: NULL data");
    if (data_len == 0)
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "cannot wrap an empty payload");
    if (!recipients || !recipient_lens || recipient_count == 0)
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID,
                         "cannot encrypt to zero recipients");
    if (flags & ~static_cast<uint32_t>(TEBAKO_CRYPTO_ENCRYPT_ARMORED))
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "encrypt: unknown flags");

    FfiGuard ffi;
    int      rc = temp_ffi(ctx, ffi);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;

    /* Load every recipient first (the encryptor borrows the handles). */
    std::vector<KeyGuard> keys;
    keys.reserve(recipient_count);
    for (size_t i = 0; i < recipient_count; i++) {
        if (!recipients[i] || recipient_lens[i] == 0)
            return set_error(ctx, TEBAKO_CRYPTO_E_INVALID,
                             "recipient %zu: empty public key", i);
        std::vector<std::string> before;
        rc = all_fingerprints(ctx, ffi, before);
        if (rc != TEBAKO_CRYPTO_OK)
            return rc;
        char what[64];
        snprintf(what, sizeof(what), "recipient %zu: cannot load the public key", i);
        rc = load_blob(ctx, ffi, recipients[i], recipient_lens[i], RNP_LOAD_SAVE_PUBLIC_KEYS,
                       what);
        if (rc != TEBAKO_CRYPTO_OK)
            return rc;
        KeyGuard key;
        snprintf(what, sizeof(what), "recipient %zu", i);
        rc = find_new_primary(ctx, ffi, before, what, key);
        if (rc != TEBAKO_CRYPTO_OK)
            return rc;
        keys.push_back(std::move(key));
    }

    InputGuard input;
    rc = mem_input(ctx, data, data_len, input);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    OutputGuard output;
    rc = mem_output(ctx, output);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;

    /* wrap_dek's wire shape: PKESK per recipient, AES-256/SHA-256. */
    EncryptOpGuard op;
    rnp_result_t   rrc = rnp_op_encrypt_create(op.out(), ffi, input, output);
    if (rrc != RNP_SUCCESS)
        return rnp_err(ctx, TEBAKO_CRYPTO_E_INTERNAL, "cannot create the encryptor", rrc);
    rnp_op_encrypt_set_cipher(op, "AES256");
    rnp_op_encrypt_set_hash(op, "SHA256");
    rnp_op_encrypt_set_armor(op, (flags & TEBAKO_CRYPTO_ENCRYPT_ARMORED) != 0);
    for (const KeyGuard &key : keys) {
        rrc = rnp_op_encrypt_add_recipient(op, key);
        if (rrc != RNP_SUCCESS)
            return rnp_err(ctx, TEBAKO_CRYPTO_E_INVALID, "cannot add a recipient", rrc);
    }
    rrc = rnp_op_encrypt_execute(op);
    if (rrc != RNP_SUCCESS)
        return rnp_err(ctx, TEBAKO_CRYPTO_E_INTERNAL, "encryption failed", rrc);

    std::vector<uint8_t> bytes;
    rc = output_bytes(ctx, output, bytes);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    return copy_out(ctx, out, out_cap, out_len, bytes.data(), bytes.size());
}

extern "C" TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL
tebako_crypto_v1_decrypt(tebako_crypto_v1_ctx *ctx,
                         const uint8_t *ciphertext, size_t ciphertext_len,
                         const uint8_t *secret_key, size_t secret_key_len,
                         uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!ctx)
        return TEBAKO_CRYPTO_E_INVALID;
    if (!ciphertext || ciphertext_len == 0)
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "decrypt: empty ciphertext");
    if (!secret_key || secret_key_len == 0)
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "decrypt: empty secret key");

    FfiGuard ffi;
    int      rc = temp_ffi(ctx, ffi);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    rc = load_blob(ctx, ffi, secret_key, secret_key_len,
                   RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS,
                   "cannot load the recipient secret key");
    if (rc != TEBAKO_CRYPTO_OK)
        return set_error(ctx, TEBAKO_CRYPTO_E_DECRYPT, "%s", ctx->error.c_str());

    InputGuard input;
    rc = mem_input(ctx, ciphertext, ciphertext_len, input);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    OutputGuard output;
    rc = mem_output(ctx, output);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;

    rnp_result_t rrc = rnp_decrypt(ffi, input, output);
    if (rrc != RNP_SUCCESS)
        return rnp_err(ctx, TEBAKO_CRYPTO_E_DECRYPT,
                       "no envelope recipient slot opens with the given key", rrc);

    std::vector<uint8_t> bytes;
    rc = output_bytes(ctx, output, bytes);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    return copy_out(ctx, out, out_cap, out_len, bytes.data(), bytes.size());
}

extern "C" TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL
tebako_crypto_v1_envelope_recipients(tebako_crypto_v1_ctx *ctx,
                                     const uint8_t *envelope, size_t envelope_len,
                                     size_t index,
                                     char *keyid_out, size_t keyid_cap)
{
    if (!ctx)
        return TEBAKO_CRYPTO_E_INVALID;
    if (!envelope || envelope_len == 0)
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "envelope_recipients: empty envelope");
    if (!keyid_out || keyid_cap < TEBAKO_CRYPTO_KEYID_HEX_CAP)
        return set_error(ctx, TEBAKO_CRYPTO_E_BUFFER_TOO_SMALL,
                         "envelope_recipients: keyid buffer needs %u bytes",
                         (unsigned) TEBAKO_CRYPTO_KEYID_HEX_CAP);

    std::string json;
    int         rc = dump_json(ctx, envelope, envelope_len, "cannot parse the envelope", json);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;

    /* envelope.rs's scrape: the PKESK packet's recipient field is named
     * plainly "keyid" (an envelope carries no other keyid-bearing
     * packets). */
    std::vector<std::string> keyids;
    const std::string        needle = "\"keyid\":\"";
    size_t                   pos = 0;
    while ((pos = json.find(needle, pos)) != std::string::npos) {
        size_t start = pos + needle.size();
        size_t end = json.find('"', start);
        if (end == std::string::npos)
            return set_error(ctx, TEBAKO_CRYPTO_E_INVALID,
                             "malformed recipient keyid in the packet dump");
        std::string id = json.substr(start, end - start);
        std::transform(id.begin(), id.end(), id.begin(), ::tolower);
        keyids.push_back(id);
        pos = end;
    }
    if (keyids.empty())
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "the envelope carries no PKESK recipient");
    if (index >= keyids.size())
        return set_error(ctx, TEBAKO_CRYPTO_E_NO_KEY,
                         "envelope_recipients: no recipient at index %zu", index);
    memcpy(keyid_out, keyids[index].c_str(), keyids[index].size() + 1);
    return ok(ctx);
}

/* ------------------------------------------------------------------ */
/* Armor                                                               */
/* ------------------------------------------------------------------ */

extern "C" TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL
tebako_crypto_v1_armor_bytes(tebako_crypto_v1_ctx *ctx,
                             const uint8_t *data, size_t data_len, const char *armor_type,
                             uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!ctx)
        return TEBAKO_CRYPTO_E_INVALID;
    if (!data || data_len == 0)
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "armor_bytes: empty input");
    if (!armor_type)
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "armor_bytes: NULL armor type");
    static const char *const known[] = {"signature", "public key", "secret key", "message"};
    bool supported = false;
    for (const char *t : known)
        supported |= strcmp(armor_type, t) == 0;
    if (!supported)
        return set_error(ctx, TEBAKO_CRYPTO_E_UNSUPPORTED,
                         "armor_bytes: unsupported armor type \"%s\"", armor_type);

    InputGuard input;
    int        rc = mem_input(ctx, data, data_len, input);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    OutputGuard output;
    rc = mem_output(ctx, output);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    rnp_result_t rrc = rnp_enarmor(input, output, armor_type);
    if (rrc != RNP_SUCCESS)
        return rnp_err(ctx, TEBAKO_CRYPTO_E_INTERNAL, "armoring failed", rrc);
    std::vector<uint8_t> bytes;
    rc = output_bytes(ctx, output, bytes);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    return copy_out(ctx, out, out_cap, out_len, bytes.data(), bytes.size());
}

extern "C" TEBAKO_CRYPTO_API int TEBAKO_CRYPTO_CALL
tebako_crypto_v1_dearmor_bytes(tebako_crypto_v1_ctx *ctx,
                               const uint8_t *data, size_t data_len,
                               uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!ctx)
        return TEBAKO_CRYPTO_E_INVALID;
    if (!data || data_len == 0)
        return set_error(ctx, TEBAKO_CRYPTO_E_INVALID, "dearmor_bytes: empty input");

    InputGuard input;
    int        rc = mem_input(ctx, data, data_len, input);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    OutputGuard output;
    rc = mem_output(ctx, output);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    rnp_result_t rrc = rnp_dearmor(input, output);
    if (rrc != RNP_SUCCESS)
        return rnp_err(ctx, TEBAKO_CRYPTO_E_INVALID, "the input does not dearmor", rrc);
    std::vector<uint8_t> bytes;
    rc = output_bytes(ctx, output, bytes);
    if (rc != TEBAKO_CRYPTO_OK)
        return rc;
    return copy_out(ctx, out, out_cap, out_len, bytes.data(), bytes.size());
}
