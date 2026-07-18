/*
 * N6 host crypto ops: domain_store SHA-256 + HMAC/HKDF-SHA-256 (RFC 5869).
 *
 * SEMANTIC: N6_PRIVATE_ONLY_NO_PUBLIC_ABI
 * SEMANTIC: N6_HKDF_SHA256_LABELS_EXACT
 * SEMANTIC: N6_CRYPTO_ALIAS_REJECT_OR_LOCAL_COPY
 * SEMANTIC: N6_CRYPTO_SECURE_ZERO_ALL_PATHS
 * SEMANTIC: N6_CHUNK_D_PRIVATE_HOST_CANDIDATE
 *
 * Host candidate only. Not R6 complete / not production radio.
 */

#include "n6_crypto_provider.h"

#include "../model/domain_store_codec.h"

#include <stdint.h>
#include <string.h>

/* Layer / direction / alloc closed domains (docs/30 §5.3.0). */
#define N6C_LAYER_HOP ((uint8_t)1u)
#define N6C_LAYER_E2E ((uint8_t)2u)
#define N6C_DIR_IR ((uint8_t)0u)
#define N6C_DIR_RI ((uint8_t)1u)
#define N6C_ALLOC_IN ((uint8_t)1u)
#define N6C_ALLOC_OUT ((uint8_t)2u)

/* ---- secure zero ---- */

void ninlil_n6_secure_zero(void *p, size_t n)
{
    volatile uint8_t *vp;
    size_t i;

    if (p == NULL || n == 0u) {
        return;
    }
    vp = (volatile uint8_t *)p;
    for (i = 0u; i < n; ++i) {
        vp[i] = 0u;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

static int n6c_ranges_disjoint(
    const void *a, size_t alen, const void *b, size_t blen)
{
    uintptr_t au, bu, ae, be;
    if (alen == 0u || blen == 0u) {
        return 1;
    }
    if (a == NULL || b == NULL) {
        return 0;
    }
    au = (uintptr_t)a;
    bu = (uintptr_t)b;
    if (au > UINTPTR_MAX - alen || bu > UINTPTR_MAX - blen) {
        return 0;
    }
    ae = au + alen;
    be = bu + blen;
    return (ae <= bu) || (be <= au);
}

static int n6c_layer_ok(uint8_t layer)
{
    return layer == N6C_LAYER_HOP || layer == N6C_LAYER_E2E;
}

static int n6c_dir_ok(uint8_t d)
{
    return d == N6C_DIR_IR || d == N6C_DIR_RI;
}

static int n6c_alloc_ok(uint8_t a)
{
    return a == N6C_ALLOC_IN || a == N6C_ALLOC_OUT;
}

static int n6c_epoch_ok(uint64_t e)
{
    return e >= 1u;
}

/* ---- BE helpers (local) ---- */

static void n6c_put_u16_be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)((v >> 8) & 0xffu);
    p[1] = (uint8_t)(v & 0xffu);
}

static void n6c_put_u64_be(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)((v >> 56) & 0xffu);
    p[1] = (uint8_t)((v >> 48) & 0xffu);
    p[2] = (uint8_t)((v >> 40) & 0xffu);
    p[3] = (uint8_t)((v >> 32) & 0xffu);
    p[4] = (uint8_t)((v >> 24) & 0xffu);
    p[5] = (uint8_t)((v >> 16) & 0xffu);
    p[6] = (uint8_t)((v >> 8) & 0xffu);
    p[7] = (uint8_t)(v & 0xffu);
}

/* ---- SHA-256 via domain_store (dig always secure_zero'd) ---- */

static int n6_host_sha256(
    void *ctx, const uint8_t *in, size_t n, uint8_t out32[32])
{
    ninlil_model_domain_digest_t dig;
    ninlil_status_t st;
    uint32_t len32;
    int rc = -1;

    (void)ctx;
    ninlil_n6_secure_zero(&dig, sizeof(dig));
    if (out32 == NULL) {
        goto cleanup;
    }
    if (n > 0xffffffffu) {
        goto cleanup_out;
    }
    /* domain_store: NULL+len0 ok; non-NULL+len0 reject. Normalize. */
    len32 = (uint32_t)n;
    if (len32 == 0u) {
        in = NULL;
    } else if (in == NULL) {
        goto cleanup_out;
    }
    /* out must not alias input span */
    if (len32 > 0u && !n6c_ranges_disjoint(in, (size_t)len32, out32, 32u)) {
        goto cleanup_out;
    }
    st = ninlil_model_domain_sha256(in, len32, &dig);
    if (st != NINLIL_OK) {
        goto cleanup_out;
    }
    (void)memcpy(out32, dig.bytes, 32u);
    rc = 0;
    goto cleanup;

cleanup_out:
    ninlil_n6_secure_zero(out32, 32u);
cleanup:
    ninlil_n6_secure_zero(&dig, sizeof(dig));
    return rc;
}

/* ---- HMAC-SHA256 (key any length; block=64); single cleanup ---- */

static int n6_hmac_sha256(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *msg,
    size_t msg_len,
    uint8_t out32[32])
{
    uint8_t k0[64];
    uint8_t ipad[64];
    uint8_t opad[64];
    uint8_t inner[32];
    uint8_t block[64 + 256];
    size_t i;
    int rc = -1;

    ninlil_n6_secure_zero(k0, sizeof(k0));
    ninlil_n6_secure_zero(ipad, sizeof(ipad));
    ninlil_n6_secure_zero(opad, sizeof(opad));
    ninlil_n6_secure_zero(inner, sizeof(inner));
    ninlil_n6_secure_zero(block, sizeof(block));

    if (out32 == NULL) {
        goto cleanup;
    }
    if (msg_len > 256u) {
        goto cleanup_out;
    }
    if ((key_len > 0u && key == NULL) || (msg_len > 0u && msg == NULL)) {
        goto cleanup_out;
    }
    if (msg_len > 0u && !n6c_ranges_disjoint(msg, msg_len, out32, 32u)) {
        goto cleanup_out;
    }
    if (key_len > 0u && key_len <= 64u
        && !n6c_ranges_disjoint(key, key_len, out32, 32u)) {
        goto cleanup_out;
    }

    if (key_len > 64u) {
        if (n6_host_sha256(NULL, key, key_len, k0) != 0) {
            goto cleanup_out;
        }
    } else if (key_len > 0u) {
        (void)memcpy(k0, key, key_len);
    }

    for (i = 0u; i < 64u; ++i) {
        ipad[i] = (uint8_t)(k0[i] ^ 0x36u);
        opad[i] = (uint8_t)(k0[i] ^ 0x5cu);
    }

    (void)memcpy(block, ipad, 64u);
    if (msg_len > 0u) {
        (void)memcpy(block + 64u, msg, msg_len);
    }
    if (n6_host_sha256(NULL, block, 64u + msg_len, inner) != 0) {
        goto cleanup_out;
    }

    (void)memcpy(block, opad, 64u);
    (void)memcpy(block + 64u, inner, 32u);
    if (n6_host_sha256(NULL, block, 96u, out32) != 0) {
        goto cleanup_out;
    }
    rc = 0;
    goto cleanup;

cleanup_out:
    if (out32 != NULL) {
        ninlil_n6_secure_zero(out32, 32u);
    }
cleanup:
    ninlil_n6_secure_zero(k0, sizeof(k0));
    ninlil_n6_secure_zero(ipad, sizeof(ipad));
    ninlil_n6_secure_zero(opad, sizeof(opad));
    ninlil_n6_secure_zero(inner, sizeof(inner));
    ninlil_n6_secure_zero(block, sizeof(block));
    return rc;
}

/*
 * HKDF-Extract + Expand (RFC 5869). Single cleanup for prk/t/msg/default_salt.
 * Extract failure does not bypass secure_zero.
 */
static int n6_host_hkdf_sha256(
    void *ctx,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *ikm,
    size_t ikm_len,
    const uint8_t *info,
    size_t info_len,
    uint8_t *okm,
    size_t okm_len)
{
    uint8_t default_salt[32];
    uint8_t prk[32];
    uint8_t t[32];
    uint8_t msg[32 + 64 + 1];
    size_t generated;
    uint8_t counter;
    size_t t_len;
    size_t copy_n;
    int rc = -1;

    (void)ctx;
    ninlil_n6_secure_zero(default_salt, sizeof(default_salt));
    ninlil_n6_secure_zero(prk, sizeof(prk));
    ninlil_n6_secure_zero(t, sizeof(t));
    ninlil_n6_secure_zero(msg, sizeof(msg));

    if (okm == NULL || okm_len == 0u) {
        goto cleanup;
    }
    if (okm_len > 255u * 32u || info_len > 64u) {
        goto cleanup_out;
    }
    if ((ikm_len > 0u && ikm == NULL)
        || (info_len > 0u && info == NULL)
        || (salt_len > 0u && salt == NULL)) {
        goto cleanup_out;
    }
    if (ikm_len > 0u && !n6c_ranges_disjoint(ikm, ikm_len, okm, okm_len)) {
        goto cleanup_out;
    }
    if (salt_len > 0u && !n6c_ranges_disjoint(salt, salt_len, okm, okm_len)) {
        goto cleanup_out;
    }
    if (info_len > 0u && !n6c_ranges_disjoint(info, info_len, okm, okm_len)) {
        goto cleanup_out;
    }

    if (salt == NULL || salt_len == 0u) {
        salt = default_salt;
        salt_len = 32u;
    }

    if (n6_hmac_sha256(salt, salt_len, ikm, ikm_len, prk) != 0) {
        goto cleanup_out;
    }

    generated = 0u;
    counter = 1u;
    t_len = 0u;
    while (generated < okm_len) {
        size_t off = 0u;
        if (t_len > 0u) {
            (void)memcpy(msg + off, t, t_len);
            off += t_len;
        }
        if (info_len > 0u) {
            (void)memcpy(msg + off, info, info_len);
            off += info_len;
        }
        msg[off] = counter;
        off += 1u;
        if (n6_hmac_sha256(prk, 32u, msg, off, t) != 0) {
            goto cleanup_out;
        }
        ninlil_n6_secure_zero(msg, sizeof(msg));
        t_len = 32u;
        copy_n = okm_len - generated;
        if (copy_n > 32u) {
            copy_n = 32u;
        }
        (void)memcpy(okm + generated, t, copy_n);
        generated += copy_n;
        if (counter == 255u && generated < okm_len) {
            goto cleanup_out;
        }
        counter = (uint8_t)(counter + 1u);
    }
    rc = 0;
    goto cleanup;

cleanup_out:
    if (okm != NULL && okm_len > 0u) {
        ninlil_n6_secure_zero(okm, okm_len);
    }
cleanup:
    ninlil_n6_secure_zero(default_salt, sizeof(default_salt));
    ninlil_n6_secure_zero(prk, sizeof(prk));
    ninlil_n6_secure_zero(t, sizeof(t));
    ninlil_n6_secure_zero(msg, sizeof(msg));
    return rc;
}

static const ninlil_n6_crypto_ops_t g_n6_host_ops = {
    NULL,
    n6_host_sha256,
    n6_host_hkdf_sha256,
};

const ninlil_n6_crypto_ops_t *ninlil_n6_crypto_host_ops(void)
{
    return &g_n6_host_ops;
}

/* ---- Digests / fingerprints ---- */

int ninlil_n6_scope_digest28(
    const ninlil_n6_crypto_ops_t *ops,
    const uint8_t local_node_id[16],
    uint8_t layer_code,
    uint8_t direction_code,
    uint64_t membership_epoch,
    const uint8_t receiver_node_id[16],
    uint8_t out28[28])
{
    uint8_t buf[16u + 1u + 1u + 8u + 16u];
    uint8_t dig[32];
    size_t off;
    int rc = -1;

    ninlil_n6_secure_zero(buf, sizeof(buf));
    ninlil_n6_secure_zero(dig, sizeof(dig));

    if (out28 == NULL) {
        goto cleanup;
    }
    if (ops == NULL || ops->sha256 == NULL || local_node_id == NULL
        || receiver_node_id == NULL || !n6c_layer_ok(layer_code)
        || !n6c_dir_ok(direction_code) || !n6c_epoch_ok(membership_epoch)) {
        goto cleanup_out;
    }
    if (!n6c_ranges_disjoint(local_node_id, 16u, out28, 28u)
        || !n6c_ranges_disjoint(receiver_node_id, 16u, out28, 28u)) {
        goto cleanup_out;
    }
    off = 0u;
    (void)memcpy(buf + off, local_node_id, 16u);
    off += 16u;
    buf[off++] = layer_code;
    buf[off++] = direction_code;
    n6c_put_u64_be(buf + off, membership_epoch);
    off += 8u;
    (void)memcpy(buf + off, receiver_node_id, 16u);
    off += 16u;
    if (ops->sha256(ops->ctx, buf, off, dig) != 0) {
        goto cleanup_out;
    }
    (void)memcpy(out28, dig, 28u);
    rc = 0;
    goto cleanup;

cleanup_out:
    if (out28 != NULL) {
        ninlil_n6_secure_zero(out28, 28u);
    }
cleanup:
    ninlil_n6_secure_zero(buf, sizeof(buf));
    ninlil_n6_secure_zero(dig, sizeof(dig));
    return rc;
}

int ninlil_n6_ns_fingerprint12(
    const ninlil_n6_crypto_ops_t *ops,
    const uint8_t receiver_node_id[16],
    uint8_t layer_code,
    uint64_t membership_epoch,
    uint8_t alloc_side,
    uint8_t out12[12])
{
    uint8_t buf[16u + 1u + 8u + 1u];
    uint8_t dig[32];
    size_t off;
    int rc = -1;

    ninlil_n6_secure_zero(buf, sizeof(buf));
    ninlil_n6_secure_zero(dig, sizeof(dig));

    if (out12 == NULL) {
        goto cleanup;
    }
    if (ops == NULL || ops->sha256 == NULL || receiver_node_id == NULL
        || !n6c_layer_ok(layer_code) || !n6c_epoch_ok(membership_epoch)
        || !n6c_alloc_ok(alloc_side)) {
        goto cleanup_out;
    }
    if (!n6c_ranges_disjoint(receiver_node_id, 16u, out12, 12u)) {
        goto cleanup_out;
    }
    off = 0u;
    (void)memcpy(buf + off, receiver_node_id, 16u);
    off += 16u;
    buf[off++] = layer_code;
    n6c_put_u64_be(buf + off, membership_epoch);
    off += 8u;
    buf[off++] = alloc_side;
    if (ops->sha256(ops->ctx, buf, off, dig) != 0) {
        goto cleanup_out;
    }
    (void)memcpy(out12, dig, 12u);
    rc = 0;
    goto cleanup;

cleanup_out:
    if (out12 != NULL) {
        ninlil_n6_secure_zero(out12, 12u);
    }
cleanup:
    ninlil_n6_secure_zero(buf, sizeof(buf));
    ninlil_n6_secure_zero(dig, sizeof(dig));
    return rc;
}

int ninlil_n6_node_id16_from_stable(
    const ninlil_n6_crypto_ops_t *ops,
    const uint8_t *stable_id,
    size_t stable_id_len,
    uint8_t out16[16])
{
    uint8_t buf[22u + 2u + 32u];
    uint8_t dig[32];
    size_t label_len;
    size_t off;
    int rc = -1;

    ninlil_n6_secure_zero(buf, sizeof(buf));
    ninlil_n6_secure_zero(dig, sizeof(dig));

    if (out16 == NULL) {
        goto cleanup;
    }
    /* empty stable_id forbidden (docs/30 canonical node id domain) */
    if (ops == NULL || ops->sha256 == NULL || stable_id_len == 0u
        || stable_id_len > 32u || stable_id == NULL) {
        goto cleanup_out;
    }
    if (!n6c_ranges_disjoint(stable_id, stable_id_len, out16, 16u)) {
        goto cleanup_out;
    }
    label_len = sizeof(NINLIL_N6_LABEL_NODE_ID) - 1u;
    off = 0u;
    (void)memcpy(buf + off, NINLIL_N6_LABEL_NODE_ID, label_len);
    off += label_len;
    n6c_put_u16_be(buf + off, (uint16_t)stable_id_len);
    off += 2u;
    (void)memcpy(buf + off, stable_id, stable_id_len);
    off += stable_id_len;
    if (ops->sha256(ops->ctx, buf, off, dig) != 0) {
        goto cleanup_out;
    }
    (void)memcpy(out16, dig, 16u);
    rc = 0;
    goto cleanup;

cleanup_out:
    if (out16 != NULL) {
        ninlil_n6_secure_zero(out16, 16u);
    }
cleanup:
    ninlil_n6_secure_zero(buf, sizeof(buf));
    ninlil_n6_secure_zero(dig, sizeof(dig));
    return rc;
}

/* ---- Key derivation: local-copy inputs → local candidate → publish ---- */

int ninlil_n6_derive_hop_keys(
    const ninlil_n6_crypto_ops_t *ops,
    const uint8_t binding_digest32[32],
    const uint8_t traffic_secret32[32],
    ninlil_n6_hop_derived_keys_t *out)
{
    static const uint8_t k_data_key[] = NINLIL_N6_LABEL_HOP_DATA_KEY;
    static const uint8_t k_data_iv[] = NINLIL_N6_LABEL_HOP_DATA_IV;
    static const uint8_t k_ack_key[] = NINLIL_N6_LABEL_HOP_ACK_KEY;
    static const uint8_t k_ack_iv[] = NINLIL_N6_LABEL_HOP_ACK_IV;
    uint8_t salt[32];
    uint8_t ikm[32];
    ninlil_n6_hop_derived_keys_t cand;
    int rc = -1;
    int zero_out = 0;

    ninlil_n6_secure_zero(salt, sizeof(salt));
    ninlil_n6_secure_zero(ikm, sizeof(ikm));
    ninlil_n6_secure_zero(&cand, sizeof(cand));

    if (out == NULL) {
        goto cleanup;
    }
    if (ops == NULL || ops->hkdf_sha256 == NULL || binding_digest32 == NULL
        || traffic_secret32 == NULL) {
        zero_out = 1;
        goto cleanup_out;
    }
    /*
     * Complete/partial out↔input overlap: pre-reject with provider calls = 0
     * and do NOT zero overlapping out (would corrupt input). Mutation 0 on
     * shared arena.
     */
    if (!n6c_ranges_disjoint(binding_digest32, 32u, out, sizeof(*out))
        || !n6c_ranges_disjoint(traffic_secret32, 32u, out, sizeof(*out))) {
        zero_out = 0;
        goto cleanup_out;
    }
    (void)memcpy(salt, binding_digest32, 32u);
    (void)memcpy(ikm, traffic_secret32, 32u);

    if (ops->hkdf_sha256(
            ops->ctx, salt, 32u, ikm, 32u, k_data_key,
            sizeof(k_data_key) - 1u, cand.data_key16, 16u)
        != 0) {
        zero_out = 1;
        goto cleanup_out;
    }
    if (ops->hkdf_sha256(
            ops->ctx, salt, 32u, ikm, 32u, k_data_iv,
            sizeof(k_data_iv) - 1u, cand.data_iv12, 12u)
        != 0) {
        zero_out = 1;
        goto cleanup_out;
    }
    if (ops->hkdf_sha256(
            ops->ctx, salt, 32u, ikm, 32u, k_ack_key,
            sizeof(k_ack_key) - 1u, cand.ack_key16, 16u)
        != 0) {
        zero_out = 1;
        goto cleanup_out;
    }
    if (ops->hkdf_sha256(
            ops->ctx, salt, 32u, ikm, 32u, k_ack_iv,
            sizeof(k_ack_iv) - 1u, cand.ack_iv12, 12u)
        != 0) {
        zero_out = 1;
        goto cleanup_out;
    }
    *out = cand;
    rc = 0;
    goto cleanup;

cleanup_out:
    if (zero_out != 0 && out != NULL) {
        ninlil_n6_secure_zero(out, sizeof(*out));
    }
cleanup:
    ninlil_n6_secure_zero(salt, sizeof(salt));
    ninlil_n6_secure_zero(ikm, sizeof(ikm));
    ninlil_n6_secure_zero(&cand, sizeof(cand));
    return rc;
}

int ninlil_n6_derive_e2e_keys(
    const ninlil_n6_crypto_ops_t *ops,
    const uint8_t binding_digest32[32],
    const uint8_t traffic_secret32[32],
    ninlil_n6_e2e_derived_keys_t *out)
{
    static const uint8_t k_e2e_key[] = NINLIL_N6_LABEL_E2E_KEY;
    static const uint8_t k_e2e_iv[] = NINLIL_N6_LABEL_E2E_IV;
    uint8_t salt[32];
    uint8_t ikm[32];
    ninlil_n6_e2e_derived_keys_t cand;
    int rc = -1;
    int zero_out = 0;

    ninlil_n6_secure_zero(salt, sizeof(salt));
    ninlil_n6_secure_zero(ikm, sizeof(ikm));
    ninlil_n6_secure_zero(&cand, sizeof(cand));

    if (out == NULL) {
        goto cleanup;
    }
    if (ops == NULL || ops->hkdf_sha256 == NULL || binding_digest32 == NULL
        || traffic_secret32 == NULL) {
        zero_out = 1;
        goto cleanup_out;
    }
    if (!n6c_ranges_disjoint(binding_digest32, 32u, out, sizeof(*out))
        || !n6c_ranges_disjoint(traffic_secret32, 32u, out, sizeof(*out))) {
        zero_out = 0;
        goto cleanup_out;
    }
    (void)memcpy(salt, binding_digest32, 32u);
    (void)memcpy(ikm, traffic_secret32, 32u);

    if (ops->hkdf_sha256(
            ops->ctx, salt, 32u, ikm, 32u, k_e2e_key,
            sizeof(k_e2e_key) - 1u, cand.key16, 16u)
        != 0) {
        zero_out = 1;
        goto cleanup_out;
    }
    if (ops->hkdf_sha256(
            ops->ctx, salt, 32u, ikm, 32u, k_e2e_iv,
            sizeof(k_e2e_iv) - 1u, cand.iv12, 12u)
        != 0) {
        zero_out = 1;
        goto cleanup_out;
    }
    *out = cand;
    rc = 0;
    goto cleanup;

cleanup_out:
    if (zero_out != 0 && out != NULL) {
        ninlil_n6_secure_zero(out, sizeof(*out));
    }
cleanup:
    ninlil_n6_secure_zero(salt, sizeof(salt));
    ninlil_n6_secure_zero(ikm, sizeof(ikm));
    ninlil_n6_secure_zero(&cand, sizeof(cand));
    return rc;
}
