/*
 * R7 portable crypto wrapper — validation, alias, candidate publish, zeroize.
 * Private C11. No heap, VLA, OS, or crypto-library headers.
 * No hand-written AES/GHASH.
 *
 * Failure-path contract (docs/31 §6–7):
 *   - prevalidate all inputs before any copy
 *   - copy bounded caller inputs into wrapper-owned fixed buffers
 *   - pass only copies to raw callbacks
 *   - publish caller outputs only after RAW_OK + exact produced_len
 *   - volatile-zero all copies/candidates/temps on every post-copy path
 */

#include "r7_crypto_provider.h"

#include <stdatomic.h>

/* -------------------------------------------------------------------------- */
/* Internal helpers                                                           */
/* -------------------------------------------------------------------------- */

static void ninlil_r7_crypto_secure_zero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    size_t i;

    for (i = 0u; i < n; i++) {
        v[i] = 0u;
    }
    atomic_signal_fence(memory_order_seq_cst);
}

static void ninlil_r7_crypto_copy(uint8_t *dst, const uint8_t *src, size_t n)
{
    size_t i;

    for (i = 0u; i < n; i++) {
        dst[i] = src[i];
    }
}

/*
 * Non-empty span pair overlap / overflow check.
 * Empty spans never alias. Adjacent (end == begin) is allowed.
 * uintptr end overflow => reject (treat as forbidden).
 * Returns 1 if forbidden overlap or overflow, 0 if ok.
 */
static int ninlil_r7_spans_forbidden(const void *a, size_t a_len, const void *b, size_t b_len)
{
    uintptr_t aa;
    uintptr_t bb;
    uintptr_t ae;
    uintptr_t be;

    if (a_len == 0u || b_len == 0u) {
        return 0;
    }
    if (a == NULL || b == NULL) {
        /* Non-empty with NULL is a caller shape error handled elsewhere;
         * treat as forbidden if we reach here. */
        return 1;
    }

    aa = (uintptr_t)a;
    bb = (uintptr_t)b;

    /* size_t may be wider than uintptr_t on a conforming implementation. */
    if (a_len > (size_t)UINTPTR_MAX || b_len > (size_t)UINTPTR_MAX) {
        return 1;
    }
    if (aa > (UINTPTR_MAX - a_len)) {
        return 1;
    }
    if (bb > (UINTPTR_MAX - b_len)) {
        return 1;
    }

    ae = aa + a_len;
    be = bb + b_len;

    /* Overlap if ranges intersect; adjacent is not overlap. */
    if (aa < be && bb < ae) {
        return 1;
    }
    return 0;
}

#ifdef NINLIL_R7_CRYPTO_TEST_BUILD
int ninlil_r7_crypto_test_spans_forbidden(
    const void *a, size_t a_len, const void *b, size_t b_len)
{
    return ninlil_r7_spans_forbidden(a, a_len, b, b_len);
}
#endif

static ninlil_r7_crypto_status ninlil_r7_map_raw_non_aead(ninlil_r7_crypto_raw_status raw)
{
    if (raw == NINLIL_R7_CRYPTO_RAW_OK) {
        return NINLIL_R7_CRYPTO_OK;
    }
    if (raw == NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED) {
        return NINLIL_R7_CRYPTO_BACKEND_FAILED;
    }
    /* AUTH or any unknown value is not valid for non-AEAD ops. */
    if (raw == NINLIL_R7_CRYPTO_RAW_AUTH_FAILED) {
        return NINLIL_R7_CRYPTO_INTERNAL_CONTRACT;
    }
    return NINLIL_R7_CRYPTO_BACKEND_FAILED;
}

/*
 * Pairwise forbidden-span check over n spans (skip empty lens).
 * Returns ALIAS if any pair overlaps; OK otherwise.
 */
static ninlil_r7_crypto_status ninlil_r7_check_pairwise(
    const void *const *spans, const size_t *lens, size_t n)
{
    size_t i;
    size_t j;

    for (i = 0u; i < n; i++) {
        for (j = i + 1u; j < n; j++) {
            if (ninlil_r7_spans_forbidden(spans[i], lens[i], spans[j], lens[j])) {
                return NINLIL_R7_CRYPTO_ALIAS;
            }
        }
    }
    return NINLIL_R7_CRYPTO_OK;
}

/* -------------------------------------------------------------------------- */
/* Provider validate                                                          */
/* -------------------------------------------------------------------------- */

ninlil_r7_crypto_status ninlil_r7_crypto_provider_validate(
    const ninlil_r7_crypto_provider *provider)
{
    if (provider == NULL) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (provider->abi_version != NINLIL_R7_CRYPTO_PROVIDER_ABI_VERSION) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (provider->struct_size != (uint32_t)sizeof(ninlil_r7_crypto_provider)) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (provider->reserved_zero != 0u) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (provider->sha256 == NULL || provider->hkdf_extract_sha256 == NULL ||
        provider->hkdf_expand_sha256 == NULL || provider->aes128_gcm_seal == NULL ||
        provider->aes128_gcm_open == NULL) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    return NINLIL_R7_CRYPTO_OK;
}

/* -------------------------------------------------------------------------- */
/* SHA-256                                                                    */
/* -------------------------------------------------------------------------- */

ninlil_r7_crypto_status ninlil_r7_crypto_sha256(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t *msg,
    size_t msg_len,
    uint8_t out_digest[NINLIL_R7_CRYPTO_SHA256_LEN])
{
    uint8_t msg_copy[NINLIL_R7_CRYPTO_SHA256_MSG_MAX];
    uint8_t candidate[NINLIL_R7_CRYPTO_SHA256_LEN];
    ninlil_r7_crypto_raw_status raw;
    ninlil_r7_crypto_status st;
    const void *spans[3];
    size_t lens[3];
    size_t nspans;
    const uint8_t *msg_arg;

    /* ---- prevalidation (early return only before copies) ---- */
    if (ninlil_r7_crypto_provider_validate(provider) != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (out_digest == NULL) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (msg_len > NINLIL_R7_CRYPTO_SHA256_MSG_MAX) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (msg_len > 0u && msg == NULL) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }

    nspans = 0u;
    spans[nspans] = provider;
    lens[nspans] = sizeof(*provider);
    nspans++;
    if (msg_len > 0u) {
        spans[nspans] = msg;
        lens[nspans] = msg_len;
        nspans++;
    }
    spans[nspans] = out_digest;
    lens[nspans] = NINLIL_R7_CRYPTO_SHA256_LEN;
    nspans++;

    if (ninlil_r7_check_pairwise(spans, lens, nspans) != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_CRYPTO_ALIAS;
    }

    /* ---- copies (callback sees only copies) ---- */
    if (msg_len > 0u) {
        ninlil_r7_crypto_copy(msg_copy, msg, msg_len);
        msg_arg = msg_copy;
    } else {
        msg_arg = NULL;
    }

    {
        size_t zi;
        for (zi = 0u; zi < NINLIL_R7_CRYPTO_SHA256_LEN; zi++) {
            candidate[zi] = 0u;
        }
    }

    raw = provider->sha256(provider->ctx, msg_arg, msg_len, candidate);
    st = ninlil_r7_map_raw_non_aead(raw);
    if (st == NINLIL_R7_CRYPTO_OK) {
        ninlil_r7_crypto_copy(out_digest, candidate, NINLIL_R7_CRYPTO_SHA256_LEN);
    }

    ninlil_r7_crypto_secure_zero(candidate, sizeof(candidate));
    ninlil_r7_crypto_secure_zero(msg_copy, sizeof(msg_copy));
    return st;
}

/* -------------------------------------------------------------------------- */
/* HKDF-Extract                                                               */
/* -------------------------------------------------------------------------- */

ninlil_r7_crypto_status ninlil_r7_crypto_hkdf_extract_sha256(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *ikm,
    size_t ikm_len,
    uint8_t out_prk[NINLIL_R7_CRYPTO_HKDF_PRK_LEN])
{
    uint8_t salt_copy[NINLIL_R7_CRYPTO_HKDF_SALT_LEN];
    uint8_t ikm_copy[NINLIL_R7_CRYPTO_HKDF_IKM_LEN];
    uint8_t candidate[NINLIL_R7_CRYPTO_HKDF_PRK_LEN];
    ninlil_r7_crypto_raw_status raw;
    ninlil_r7_crypto_status st;
    const void *spans[4];
    size_t lens[4];

    if (ninlil_r7_crypto_provider_validate(provider) != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (out_prk == NULL || salt == NULL || ikm == NULL) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (salt_len != NINLIL_R7_CRYPTO_HKDF_SALT_LEN ||
        ikm_len != NINLIL_R7_CRYPTO_HKDF_IKM_LEN) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }

    spans[0] = provider;
    lens[0] = sizeof(*provider);
    spans[1] = salt;
    lens[1] = salt_len;
    spans[2] = ikm;
    lens[2] = ikm_len;
    spans[3] = out_prk;
    lens[3] = NINLIL_R7_CRYPTO_HKDF_PRK_LEN;

    if (ninlil_r7_check_pairwise(spans, lens, 4u) != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_CRYPTO_ALIAS;
    }

    ninlil_r7_crypto_copy(salt_copy, salt, NINLIL_R7_CRYPTO_HKDF_SALT_LEN);
    ninlil_r7_crypto_copy(ikm_copy, ikm, NINLIL_R7_CRYPTO_HKDF_IKM_LEN);
    {
        size_t zi;
        for (zi = 0u; zi < NINLIL_R7_CRYPTO_HKDF_PRK_LEN; zi++) {
            candidate[zi] = 0u;
        }
    }

    raw = provider->hkdf_extract_sha256(
        provider->ctx,
        salt_copy,
        NINLIL_R7_CRYPTO_HKDF_SALT_LEN,
        ikm_copy,
        NINLIL_R7_CRYPTO_HKDF_IKM_LEN,
        candidate);
    st = ninlil_r7_map_raw_non_aead(raw);
    if (st == NINLIL_R7_CRYPTO_OK) {
        ninlil_r7_crypto_copy(out_prk, candidate, NINLIL_R7_CRYPTO_HKDF_PRK_LEN);
    }

    ninlil_r7_crypto_secure_zero(candidate, sizeof(candidate));
    ninlil_r7_crypto_secure_zero(salt_copy, sizeof(salt_copy));
    ninlil_r7_crypto_secure_zero(ikm_copy, sizeof(ikm_copy));
    return st;
}

/* -------------------------------------------------------------------------- */
/* HKDF-Expand                                                                */
/* -------------------------------------------------------------------------- */

ninlil_r7_crypto_status ninlil_r7_crypto_hkdf_expand_sha256(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t prk[NINLIL_R7_CRYPTO_HKDF_PRK_LEN],
    const uint8_t *info,
    size_t info_len,
    uint8_t *out_okm,
    size_t okm_len)
{
    uint8_t prk_copy[NINLIL_R7_CRYPTO_HKDF_PRK_LEN];
    uint8_t info_copy[NINLIL_R7_CRYPTO_HKDF_INFO_MAX];
    uint8_t candidate[NINLIL_R7_CRYPTO_HKDF_OKM_MAX];
    ninlil_r7_crypto_raw_status raw;
    ninlil_r7_crypto_status st;
    const void *spans[4];
    size_t lens[4];
    size_t nspans;
    const uint8_t *info_arg;

    if (ninlil_r7_crypto_provider_validate(provider) != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (prk == NULL || out_okm == NULL) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (okm_len != NINLIL_R7_CRYPTO_HKDF_OKM_IV_LEN &&
        okm_len != NINLIL_R7_CRYPTO_HKDF_OKM_KEY_LEN) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (info_len > NINLIL_R7_CRYPTO_HKDF_INFO_MAX) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (info_len > 0u && info == NULL) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }

    nspans = 0u;
    spans[nspans] = provider;
    lens[nspans] = sizeof(*provider);
    nspans++;
    spans[nspans] = prk;
    lens[nspans] = NINLIL_R7_CRYPTO_HKDF_PRK_LEN;
    nspans++;
    if (info_len > 0u) {
        spans[nspans] = info;
        lens[nspans] = info_len;
        nspans++;
    }
    spans[nspans] = out_okm;
    lens[nspans] = okm_len;
    nspans++;

    if (ninlil_r7_check_pairwise(spans, lens, nspans) != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_CRYPTO_ALIAS;
    }

    ninlil_r7_crypto_copy(prk_copy, prk, NINLIL_R7_CRYPTO_HKDF_PRK_LEN);
    if (info_len > 0u) {
        ninlil_r7_crypto_copy(info_copy, info, info_len);
        info_arg = info_copy;
    } else {
        info_arg = NULL;
    }
    {
        size_t zi;
        for (zi = 0u; zi < NINLIL_R7_CRYPTO_HKDF_OKM_MAX; zi++) {
            candidate[zi] = 0u;
        }
    }

    raw = provider->hkdf_expand_sha256(
        provider->ctx, prk_copy, info_arg, info_len, candidate, okm_len);
    st = ninlil_r7_map_raw_non_aead(raw);
    if (st == NINLIL_R7_CRYPTO_OK) {
        ninlil_r7_crypto_copy(out_okm, candidate, okm_len);
    }

    ninlil_r7_crypto_secure_zero(candidate, sizeof(candidate));
    ninlil_r7_crypto_secure_zero(prk_copy, sizeof(prk_copy));
    ninlil_r7_crypto_secure_zero(info_copy, sizeof(info_copy));
    return st;
}

/* -------------------------------------------------------------------------- */
/* AEAD pairwise alias                                                        */
/* provider + key + nonce + aad + input + out + out_len (all non-empty)       */
/* -------------------------------------------------------------------------- */

static ninlil_r7_crypto_status ninlil_r7_aead_check_aliases(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *input,
    size_t input_len,
    const uint8_t *out,
    size_t out_cap,
    const size_t *out_len)
{
    const void *spans[7];
    size_t lens[7];
    size_t n = 0u;

    spans[n] = provider;
    lens[n] = sizeof(*provider);
    n++;
    spans[n] = key;
    lens[n] = NINLIL_R7_CRYPTO_AES128_KEY_LEN;
    n++;
    spans[n] = nonce;
    lens[n] = NINLIL_R7_CRYPTO_AES128_NONCE_LEN;
    n++;
    if (aad_len > 0u) {
        spans[n] = aad;
        lens[n] = aad_len;
        n++;
    }
    if (input_len > 0u) {
        spans[n] = input;
        lens[n] = input_len;
        n++;
    }
    if (out_cap > 0u) {
        spans[n] = out;
        lens[n] = out_cap;
        n++;
    }
    /* out_len storage is always a non-empty size_t object when non-NULL. */
    spans[n] = out_len;
    lens[n] = sizeof(size_t);
    n++;

    return ninlil_r7_check_pairwise(spans, lens, n);
}

/* -------------------------------------------------------------------------- */
/* AES-128-GCM seal                                                           */
/* -------------------------------------------------------------------------- */

ninlil_r7_crypto_status ninlil_r7_crypto_aes128_gcm_seal(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key[NINLIL_R7_CRYPTO_AES128_KEY_LEN],
    const uint8_t nonce[NINLIL_R7_CRYPTO_AES128_NONCE_LEN],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    uint8_t key_copy[NINLIL_R7_CRYPTO_AES128_KEY_LEN];
    uint8_t nonce_copy[NINLIL_R7_CRYPTO_AES128_NONCE_LEN];
    uint8_t aad_copy[NINLIL_R7_CRYPTO_AAD_MAX];
    uint8_t pt_copy[NINLIL_R7_CRYPTO_BODY_MAX];
    uint8_t candidate[NINLIL_R7_CRYPTO_SEALED_MAX];
    size_t produced_len;
    size_t need;
    ninlil_r7_crypto_raw_status raw;
    ninlil_r7_crypto_status st;
    const uint8_t *aad_arg;
    const uint8_t *pt_arg;

    if (ninlil_r7_crypto_provider_validate(provider) != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (key == NULL || nonce == NULL || out == NULL || out_len == NULL) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (aad_len > NINLIL_R7_CRYPTO_AAD_MAX || plaintext_len > NINLIL_R7_CRYPTO_BODY_MAX) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (aad_len > 0u && aad == NULL) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (plaintext_len > 0u && plaintext == NULL) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }

    /* need = plaintext_len + TAG; overflow-safe (BODY_MAX + TAG fits size_t). */
    if (plaintext_len > (SIZE_MAX - NINLIL_R7_CRYPTO_AES128_TAG_LEN)) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    need = plaintext_len + NINLIL_R7_CRYPTO_AES128_TAG_LEN;
    if (out_capacity != need) {
        return NINLIL_R7_CRYPTO_CAPACITY;
    }

    st = ninlil_r7_aead_check_aliases(
        provider,
        key,
        nonce,
        aad,
        aad_len,
        plaintext,
        plaintext_len,
        out,
        out_capacity,
        out_len);
    if (st != NINLIL_R7_CRYPTO_OK) {
        return st;
    }

    /* ---- bounded input copies; callback never sees caller pointers ---- */
    ninlil_r7_crypto_copy(key_copy, key, NINLIL_R7_CRYPTO_AES128_KEY_LEN);
    ninlil_r7_crypto_copy(nonce_copy, nonce, NINLIL_R7_CRYPTO_AES128_NONCE_LEN);
    if (aad_len > 0u) {
        ninlil_r7_crypto_copy(aad_copy, aad, aad_len);
        aad_arg = aad_copy;
    } else {
        aad_arg = NULL;
    }
    if (plaintext_len > 0u) {
        ninlil_r7_crypto_copy(pt_copy, plaintext, plaintext_len);
        pt_arg = pt_copy;
    } else {
        pt_arg = NULL;
    }
    {
        size_t zi;
        for (zi = 0u; zi < NINLIL_R7_CRYPTO_SEALED_MAX; zi++) {
            candidate[zi] = 0u;
        }
    }

    /* Sentinel: RAW_OK with unchanged produced_len => INTERNAL_CONTRACT. */
    produced_len = SIZE_MAX;

    raw = provider->aes128_gcm_seal(
        provider->ctx,
        key_copy,
        nonce_copy,
        aad_arg,
        aad_len,
        pt_arg,
        plaintext_len,
        candidate,
        need,
        &produced_len);

    if (raw == NINLIL_R7_CRYPTO_RAW_OK) {
        if (produced_len != need) {
            /* Short / long / unchanged / any mismatch: no publish. */
            st = NINLIL_R7_CRYPTO_INTERNAL_CONTRACT;
        } else {
            ninlil_r7_crypto_copy(out, candidate, need);
            *out_len = need;
            st = NINLIL_R7_CRYPTO_OK;
        }
    } else if (raw == NINLIL_R7_CRYPTO_RAW_AUTH_FAILED) {
        /* Seal must not report AUTH_FAILED. */
        st = NINLIL_R7_CRYPTO_INTERNAL_CONTRACT;
    } else if (raw == NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED) {
        st = NINLIL_R7_CRYPTO_BACKEND_FAILED;
    } else {
        /* Unknown raw result. */
        st = NINLIL_R7_CRYPTO_BACKEND_FAILED;
    }

    ninlil_r7_crypto_secure_zero(candidate, sizeof(candidate));
    ninlil_r7_crypto_secure_zero(key_copy, sizeof(key_copy));
    ninlil_r7_crypto_secure_zero(nonce_copy, sizeof(nonce_copy));
    ninlil_r7_crypto_secure_zero(aad_copy, sizeof(aad_copy));
    ninlil_r7_crypto_secure_zero(pt_copy, sizeof(pt_copy));
    {
        volatile size_t *vp = (volatile size_t *)&produced_len;
        *vp = 0u;
    }
    return st;
}

/* -------------------------------------------------------------------------- */
/* AES-128-GCM open                                                           */
/* -------------------------------------------------------------------------- */

ninlil_r7_crypto_status ninlil_r7_crypto_aes128_gcm_open(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key[NINLIL_R7_CRYPTO_AES128_KEY_LEN],
    const uint8_t nonce[NINLIL_R7_CRYPTO_AES128_NONCE_LEN],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *sealed,
    size_t sealed_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    uint8_t key_copy[NINLIL_R7_CRYPTO_AES128_KEY_LEN];
    uint8_t nonce_copy[NINLIL_R7_CRYPTO_AES128_NONCE_LEN];
    uint8_t aad_copy[NINLIL_R7_CRYPTO_AAD_MAX];
    uint8_t sealed_copy[NINLIL_R7_CRYPTO_SEALED_MAX];
    uint8_t candidate[NINLIL_R7_CRYPTO_BODY_MAX];
    size_t produced_len;
    size_t pt_len;
    ninlil_r7_crypto_raw_status raw;
    ninlil_r7_crypto_status st;
    const uint8_t *aad_arg;

    if (ninlil_r7_crypto_provider_validate(provider) != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (key == NULL || nonce == NULL || out == NULL || out_len == NULL) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (aad_len > NINLIL_R7_CRYPTO_AAD_MAX) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (aad_len > 0u && aad == NULL) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (sealed_len < NINLIL_R7_CRYPTO_SEALED_MIN ||
        sealed_len > NINLIL_R7_CRYPTO_SEALED_MAX) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (sealed == NULL) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }

    pt_len = sealed_len - NINLIL_R7_CRYPTO_AES128_TAG_LEN;
    if (pt_len > NINLIL_R7_CRYPTO_BODY_MAX) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (out_capacity != pt_len) {
        return NINLIL_R7_CRYPTO_CAPACITY;
    }

    st = ninlil_r7_aead_check_aliases(
        provider,
        key,
        nonce,
        aad,
        aad_len,
        sealed,
        sealed_len,
        out,
        out_capacity,
        out_len);
    if (st != NINLIL_R7_CRYPTO_OK) {
        return st;
    }

    ninlil_r7_crypto_copy(key_copy, key, NINLIL_R7_CRYPTO_AES128_KEY_LEN);
    ninlil_r7_crypto_copy(nonce_copy, nonce, NINLIL_R7_CRYPTO_AES128_NONCE_LEN);
    if (aad_len > 0u) {
        ninlil_r7_crypto_copy(aad_copy, aad, aad_len);
        aad_arg = aad_copy;
    } else {
        aad_arg = NULL;
    }
    ninlil_r7_crypto_copy(sealed_copy, sealed, sealed_len);
    {
        size_t zi;
        for (zi = 0u; zi < NINLIL_R7_CRYPTO_BODY_MAX; zi++) {
            candidate[zi] = 0u;
        }
    }

    produced_len = SIZE_MAX;

    raw = provider->aes128_gcm_open(
        provider->ctx,
        key_copy,
        nonce_copy,
        aad_arg,
        aad_len,
        sealed_copy,
        sealed_len,
        candidate,
        pt_len,
        &produced_len);

    if (raw == NINLIL_R7_CRYPTO_RAW_OK) {
        if (produced_len != pt_len) {
            st = NINLIL_R7_CRYPTO_INTERNAL_CONTRACT;
        } else {
            if (pt_len > 0u) {
                ninlil_r7_crypto_copy(out, candidate, pt_len);
            }
            *out_len = pt_len;
            st = NINLIL_R7_CRYPTO_OK;
        }
    } else if (raw == NINLIL_R7_CRYPTO_RAW_AUTH_FAILED) {
        st = NINLIL_R7_CRYPTO_AUTH_FAILED;
    } else if (raw == NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED) {
        st = NINLIL_R7_CRYPTO_BACKEND_FAILED;
    } else {
        st = NINLIL_R7_CRYPTO_BACKEND_FAILED;
    }

    ninlil_r7_crypto_secure_zero(candidate, sizeof(candidate));
    ninlil_r7_crypto_secure_zero(key_copy, sizeof(key_copy));
    ninlil_r7_crypto_secure_zero(nonce_copy, sizeof(nonce_copy));
    ninlil_r7_crypto_secure_zero(aad_copy, sizeof(aad_copy));
    ninlil_r7_crypto_secure_zero(sealed_copy, sizeof(sealed_copy));
    {
        volatile size_t *vp = (volatile size_t *)&produced_len;
        *vp = 0u;
    }
    return st;
}
