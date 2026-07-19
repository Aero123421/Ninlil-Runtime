/*
 * R7 T1b portable context binding + verified HKDF schedule (docs/33).
 *
 * Private C11. No heap, VLA, OS, platform crypto, N6/R2/R5/W1/radio/KGuard.
 * SHA/HKDF only via ninlil_r7_crypto_* T0 portable wrappers.
 *
 * Validation priority (docs/33 §6): shape → opaque shape → structural →
 * capacity (encode) → alias → local encode → crypto/compare → atomic publish.
 * Failure: caller input/output/out_len/digest/bundle mutation zero.
 * All local canonical/digest/secret/PRK/OKM candidates zeroized on every path.
 */

#include "r7_context_binding.h"

#include <stdatomic.h>

/* -------------------------------------------------------------------------- */
/* Constants                                                                  */
/* -------------------------------------------------------------------------- */

static const uint8_t k_hop_label[20] = {
    'N', 'I', 'N', 'L', 'I', 'L', '-', 'R', '6', '-',
    'H', 'O', 'P', '-', 'C', 'T', 'X', '-', 'v', '1'
};

static const uint8_t k_e2e_label[20] = {
    'N', 'I', 'N', 'L', 'I', 'L', '-', 'R', '6', '-',
    'E', '2', 'E', '-', 'C', 'T', 'X', '-', 'v', '1'
};

/* HKDF Expand info labels (ASCII, no NUL); lengths 25/24/24/23/20/19 */
static const uint8_t k_hop_data_key_info[25] = {
    'N', 'I', 'N', 'L', 'I', 'L', '-', 'R', '6', '-',
    'H', 'O', 'P', '-', 'D', 'A', 'T', 'A', '-', 'K',
    'E', 'Y', '-', 'v', '1'
};
static const uint8_t k_hop_data_iv_info[24] = {
    'N', 'I', 'N', 'L', 'I', 'L', '-', 'R', '6', '-',
    'H', 'O', 'P', '-', 'D', 'A', 'T', 'A', '-', 'I',
    'V', '-', 'v', '1'
};
static const uint8_t k_hop_ack_key_info[24] = {
    'N', 'I', 'N', 'L', 'I', 'L', '-', 'R', '6', '-',
    'H', 'O', 'P', '-', 'A', 'C', 'K', '-', 'K', 'E',
    'Y', '-', 'v', '1'
};
static const uint8_t k_hop_ack_iv_info[23] = {
    'N', 'I', 'N', 'L', 'I', 'L', '-', 'R', '6', '-',
    'H', 'O', 'P', '-', 'A', 'C', 'K', '-', 'I', 'V',
    '-', 'v', '1'
};
static const uint8_t k_e2e_key_info[20] = {
    'N', 'I', 'N', 'L', 'I', 'L', '-', 'R', '6', '-',
    'E', '2', 'E', '-', 'K', 'E', 'Y', '-', 'v', '1'
};
static const uint8_t k_e2e_iv_info[19] = {
    'N', 'I', 'N', 'L', 'I', 'L', '-', 'R', '6', '-',
    'E', '2', 'E', '-', 'I', 'V', '-', 'v', '1'
};

/* Hop fixed overhead excluding opaque bodies: 63 = 20+1+1+2+8+2+8+2+2+2+8+4+1+2 */
#define NINLIL_R7_BINDING_HOP_FIXED ((size_t)63u)
/* E2E fixed overhead excluding opaque bodies: 61 = 20+1+1+2+8+2+8+2+2+2+8+4+1 */
#define NINLIL_R7_BINDING_E2E_FIXED ((size_t)61u)

/* -------------------------------------------------------------------------- */
/* Secure zero / copy / span helpers                                          */
/* -------------------------------------------------------------------------- */

#ifdef NINLIL_R7_BINDING_TEST_BUILD
static ninlil_r7_binding_test_secret_probe *g_secret_probe;
#endif

static void ninlil_r7_binding_secure_zero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    size_t i;

    for (i = 0u; i < n; i++) {
        v[i] = 0u;
    }
    atomic_signal_fence(memory_order_seq_cst);

#ifdef NINLIL_R7_BINDING_TEST_BUILD
    if (g_secret_probe != NULL) {
        g_secret_probe->zero_calls++;
        g_secret_probe->zero_bytes += n;
        g_secret_probe->last_len = n;
        if (g_secret_probe->log_count < NINLIL_R7_BINDING_TEST_ZERO_LOG_MAX) {
            g_secret_probe->log_sizes[g_secret_probe->log_count] = n;
            g_secret_probe->log_count++;
        }
        if (g_secret_probe->region != NULL && g_secret_probe->capacity >= n) {
            size_t j;
            for (j = 0u; j < n; j++) {
                g_secret_probe->region[j] = ((const uint8_t *)p)[j];
            }
        }
    }
#endif
}

static void ninlil_r7_binding_copy(uint8_t *dst, const uint8_t *src, size_t n)
{
    size_t i;
    for (i = 0u; i < n; i++) {
        dst[i] = src[i];
    }
}

static int ninlil_r7_binding_spans_forbidden(
    const void *a, size_t a_len, const void *b, size_t b_len)
{
    uintptr_t aa;
    uintptr_t bb;
    uintptr_t ae;
    uintptr_t be;

    if (a_len == 0u || b_len == 0u) {
        return 0;
    }
    if (a == NULL || b == NULL) {
        return 1;
    }
    if (a_len > (size_t)UINTPTR_MAX || b_len > (size_t)UINTPTR_MAX) {
        return 1;
    }
    aa = (uintptr_t)a;
    bb = (uintptr_t)b;
    if (aa > (UINTPTR_MAX - (uintptr_t)a_len)
        || bb > (UINTPTR_MAX - (uintptr_t)b_len)) {
        return 1;
    }
    ae = aa + (uintptr_t)a_len;
    be = bb + (uintptr_t)b_len;
    if (aa < be && bb < ae) {
        return 1;
    }
    return 0;
}

#ifdef NINLIL_R7_BINDING_TEST_BUILD
int ninlil_r7_binding_test_spans_forbidden(
    const void *a, size_t a_len, const void *b, size_t b_len)
{
    return ninlil_r7_binding_spans_forbidden(a, a_len, b, b_len);
}

void ninlil_r7_binding_test_set_secret_probe(
    ninlil_r7_binding_test_secret_probe *probe)
{
    g_secret_probe = probe;
}
#endif

/*
 * Mutable outputs must be pairwise-disjoint from each other and from every
 * read-only span. Read-only / read-only overlap is allowed (docs/33 §6).
 * mut_spans[0..mut_n) are mutable; ro_spans[0..ro_n) are read-only.
 */
static int32_t ninlil_r7_binding_check_mut_alias(
    const void *const *mut_spans,
    const size_t *mut_lens,
    size_t mut_n,
    const void *const *ro_spans,
    const size_t *ro_lens,
    size_t ro_n)
{
    size_t i;
    size_t j;

    for (i = 0u; i < mut_n; i++) {
        for (j = i + 1u; j < mut_n; j++) {
            if (ninlil_r7_binding_spans_forbidden(
                    mut_spans[i], mut_lens[i], mut_spans[j], mut_lens[j])) {
                return NINLIL_R7_BINDING_ALIAS;
            }
        }
        for (j = 0u; j < ro_n; j++) {
            if (ninlil_r7_binding_spans_forbidden(
                    mut_spans[i], mut_lens[i], ro_spans[j], ro_lens[j])) {
                return NINLIL_R7_BINDING_ALIAS;
            }
        }
    }
    return NINLIL_R7_BINDING_OK;
}

/* -------------------------------------------------------------------------- */
/* BE encode helpers                                                          */
/* -------------------------------------------------------------------------- */

static void ninlil_r7_binding_store_u16_be(uint8_t *out, uint16_t v)
{
    out[0] = (uint8_t)((v >> 8) & 0xffu);
    out[1] = (uint8_t)(v & 0xffu);
}

static void ninlil_r7_binding_store_u32_be(uint8_t *out, uint32_t v)
{
    out[0] = (uint8_t)((v >> 24) & 0xffu);
    out[1] = (uint8_t)((v >> 16) & 0xffu);
    out[2] = (uint8_t)((v >> 8) & 0xffu);
    out[3] = (uint8_t)(v & 0xffu);
}

static void ninlil_r7_binding_store_u64_be(uint8_t *out, uint64_t v)
{
    out[0] = (uint8_t)((v >> 56) & 0xffu);
    out[1] = (uint8_t)((v >> 48) & 0xffu);
    out[2] = (uint8_t)((v >> 40) & 0xffu);
    out[3] = (uint8_t)((v >> 32) & 0xffu);
    out[4] = (uint8_t)((v >> 24) & 0xffu);
    out[5] = (uint8_t)((v >> 16) & 0xffu);
    out[6] = (uint8_t)((v >> 8) & 0xffu);
    out[7] = (uint8_t)(v & 0xffu);
}

/* -------------------------------------------------------------------------- */
/* Shape / structural validation                                              */
/* -------------------------------------------------------------------------- */

static int ninlil_r7_binding_span_shape_ok(const ninlil_r7_binding_bytes *s)
{
    if (s == NULL) {
        return 0;
    }
    if (s->length == 0u) {
        return s->bytes == NULL;
    }
    return s->bytes != NULL;
}

static int ninlil_r7_binding_all_zero(const uint8_t *p, uint16_t n)
{
    uint16_t i;
    for (i = 0u; i < n; i++) {
        if (p[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int ninlil_r7_binding_context_ok(uint32_t id)
{
    return id >= 1u && id <= (UINT32_MAX - 1u);
}

static int ninlil_r7_binding_direction_ok(uint8_t d)
{
    return d == NINLIL_R7_BINDING_DIR_IR || d == NINLIL_R7_BINDING_DIR_RI;
}

/*
 * Validate opaque shape only (step 2). Returns INVALID_ARGUMENT or OK.
 * Does not inspect length domains.
 */
static int32_t ninlil_r7_binding_hop_opaque_shape(
    const ninlil_r7_hop_binding_input *in)
{
    if (!ninlil_r7_binding_span_shape_ok(&in->site_domain)
        || !ninlil_r7_binding_span_shape_ok(&in->attachment_id)
        || !ninlil_r7_binding_span_shape_ok(&in->initiator_stable_id)
        || !ninlil_r7_binding_span_shape_ok(&in->responder_stable_id)
        || !ninlil_r7_binding_span_shape_ok(&in->controller_authority_id)) {
        return NINLIL_R7_BINDING_INVALID_ARGUMENT;
    }
    return NINLIL_R7_BINDING_OK;
}

static int32_t ninlil_r7_binding_e2e_opaque_shape(
    const ninlil_r7_e2e_binding_input *in)
{
    if (!ninlil_r7_binding_span_shape_ok(&in->site_domain)
        || !ninlil_r7_binding_span_shape_ok(&in->e2e_security_id)
        || !ninlil_r7_binding_span_shape_ok(&in->sender_stable_id)
        || !ninlil_r7_binding_span_shape_ok(&in->receiver_stable_id)
        || !ninlil_r7_binding_span_shape_ok(&in->authority_id)) {
        return NINLIL_R7_BINDING_INVALID_ARGUMENT;
    }
    return NINLIL_R7_BINDING_OK;
}

/*
 * Authority ID length + term must be both zero (LAB no-controller) or both
 * non-zero domains. Mixed is STRUCTURAL.
 */
static int32_t ninlil_r7_binding_authority_matrix(
    uint8_t env,
    const ninlil_r7_binding_bytes *auth,
    uint64_t term)
{
    int auth_empty = (auth->length == 0u);

    if (env == NINLIL_R7_BINDING_ENV_FIELD) {
        if (auth_empty || term == 0u) {
            return NINLIL_R7_BINDING_STRUCTURAL;
        }
        if (auth->length < 1u || auth->length > NINLIL_R7_BINDING_ID_MAX) {
            return NINLIL_R7_BINDING_STRUCTURAL;
        }
        return NINLIL_R7_BINDING_OK;
    }

    if (env == NINLIL_R7_BINDING_ENV_LAB) {
        if (auth_empty && term == 0u) {
            /* LAB no-controller */
            return NINLIL_R7_BINDING_OK;
        }
        if (!auth_empty && term > 0u) {
            /* LAB controller */
            if (auth->length < 1u || auth->length > NINLIL_R7_BINDING_ID_MAX) {
                return NINLIL_R7_BINDING_STRUCTURAL;
            }
            return NINLIL_R7_BINDING_OK;
        }
        /* mixed zero */
        return NINLIL_R7_BINDING_STRUCTURAL;
    }

    return NINLIL_R7_BINDING_STRUCTURAL;
}

static int32_t ninlil_r7_binding_id_len_ok(uint16_t len)
{
    if (len < 1u || len > NINLIL_R7_BINDING_ID_MAX) {
        return NINLIL_R7_BINDING_STRUCTURAL;
    }
    return NINLIL_R7_BINDING_OK;
}

static int32_t ninlil_r7_binding_site_ok(
    uint8_t env, const ninlil_r7_binding_bytes *site)
{
    if (env == NINLIL_R7_BINDING_ENV_FIELD) {
        if (site->length != NINLIL_R7_BINDING_SITE_MAX) {
            return NINLIL_R7_BINDING_STRUCTURAL;
        }
        if (ninlil_r7_binding_all_zero(site->bytes, site->length)) {
            return NINLIL_R7_BINDING_STRUCTURAL;
        }
        return NINLIL_R7_BINDING_OK;
    }
    if (env == NINLIL_R7_BINDING_ENV_LAB) {
        if (site->length < 1u || site->length > NINLIL_R7_BINDING_SITE_MAX) {
            return NINLIL_R7_BINDING_STRUCTURAL;
        }
        return NINLIL_R7_BINDING_OK;
    }
    return NINLIL_R7_BINDING_STRUCTURAL;
}

static int32_t ninlil_r7_binding_hop_structural(
    const ninlil_r7_hop_binding_input *in)
{
    int32_t st;

    if (in->environment_code != NINLIL_R7_BINDING_ENV_LAB
        && in->environment_code != NINLIL_R7_BINDING_ENV_FIELD) {
        return NINLIL_R7_BINDING_STRUCTURAL;
    }
    if (!ninlil_r7_binding_direction_ok(in->direction_code)) {
        return NINLIL_R7_BINDING_STRUCTURAL;
    }
    if (!ninlil_r7_binding_context_ok(in->hop_context_id)) {
        return NINLIL_R7_BINDING_STRUCTURAL;
    }

    st = ninlil_r7_binding_site_ok(in->environment_code, &in->site_domain);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }

    if (in->membership_epoch == 0u || in->attachment_epoch == 0u) {
        return NINLIL_R7_BINDING_STRUCTURAL;
    }

    st = ninlil_r7_binding_id_len_ok(in->attachment_id.length);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }
    st = ninlil_r7_binding_id_len_ok(in->initiator_stable_id.length);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }
    st = ninlil_r7_binding_id_len_ok(in->responder_stable_id.length);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }

    st = ninlil_r7_binding_authority_matrix(
        in->environment_code,
        &in->controller_authority_id,
        in->controller_term);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }

    /* FIELD and LAB-controller require controller_term > 0 (already enforced).
     * LAB no-controller has term == 0. No extra epoch for controller beyond
     * term matrix. */
    return NINLIL_R7_BINDING_OK;
}

static int32_t ninlil_r7_binding_e2e_structural(
    const ninlil_r7_e2e_binding_input *in)
{
    int32_t st;

    if (in->environment_code != NINLIL_R7_BINDING_ENV_LAB
        && in->environment_code != NINLIL_R7_BINDING_ENV_FIELD) {
        return NINLIL_R7_BINDING_STRUCTURAL;
    }
    if (!ninlil_r7_binding_direction_ok(in->direction_code)) {
        return NINLIL_R7_BINDING_STRUCTURAL;
    }
    if (!ninlil_r7_binding_context_ok(in->e2e_context_id)) {
        return NINLIL_R7_BINDING_STRUCTURAL;
    }

    st = ninlil_r7_binding_site_ok(in->environment_code, &in->site_domain);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }

    if (in->membership_epoch == 0u || in->e2e_security_epoch == 0u) {
        return NINLIL_R7_BINDING_STRUCTURAL;
    }

    st = ninlil_r7_binding_id_len_ok(in->e2e_security_id.length);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }
    st = ninlil_r7_binding_id_len_ok(in->sender_stable_id.length);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }
    st = ninlil_r7_binding_id_len_ok(in->receiver_stable_id.length);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }

    st = ninlil_r7_binding_authority_matrix(
        in->environment_code, &in->authority_id, in->authority_term);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }

    return NINLIL_R7_BINDING_OK;
}

static size_t ninlil_r7_binding_hop_required_len(
    const ninlil_r7_hop_binding_input *in)
{
    return NINLIL_R7_BINDING_HOP_FIXED
        + (size_t)in->site_domain.length
        + (size_t)in->attachment_id.length
        + (size_t)in->initiator_stable_id.length
        + (size_t)in->responder_stable_id.length
        + (size_t)in->controller_authority_id.length;
}

static size_t ninlil_r7_binding_e2e_required_len(
    const ninlil_r7_e2e_binding_input *in)
{
    return NINLIL_R7_BINDING_E2E_FIXED
        + (size_t)in->site_domain.length
        + (size_t)in->e2e_security_id.length
        + (size_t)in->sender_stable_id.length
        + (size_t)in->receiver_stable_id.length
        + (size_t)in->authority_id.length;
}

/* -------------------------------------------------------------------------- */
/* Local encode into candidate (no publish)                                   */
/* -------------------------------------------------------------------------- */

static size_t ninlil_r7_binding_put_opaque(
    uint8_t *dst, const ninlil_r7_binding_bytes *s)
{
    ninlil_r7_binding_store_u16_be(dst, s->length);
    if (s->length > 0u) {
        ninlil_r7_binding_copy(dst + 2u, s->bytes, (size_t)s->length);
    }
    return 2u + (size_t)s->length;
}

static size_t ninlil_r7_binding_encode_hop_into(
    const ninlil_r7_hop_binding_input *in, uint8_t *dst)
{
    size_t o = 0u;

    ninlil_r7_binding_copy(dst + o, k_hop_label, 20u);
    o += 20u;
    dst[o++] = NINLIL_R7_BINDING_PROFILE_ID;
    dst[o++] = in->environment_code;
    o += ninlil_r7_binding_put_opaque(dst + o, &in->site_domain);
    ninlil_r7_binding_store_u64_be(dst + o, in->membership_epoch);
    o += 8u;
    o += ninlil_r7_binding_put_opaque(dst + o, &in->attachment_id);
    ninlil_r7_binding_store_u64_be(dst + o, in->attachment_epoch);
    o += 8u;
    o += ninlil_r7_binding_put_opaque(dst + o, &in->initiator_stable_id);
    o += ninlil_r7_binding_put_opaque(dst + o, &in->responder_stable_id);
    o += ninlil_r7_binding_put_opaque(dst + o, &in->controller_authority_id);
    ninlil_r7_binding_store_u64_be(dst + o, in->controller_term);
    o += 8u;
    ninlil_r7_binding_store_u32_be(dst + o, in->hop_context_id);
    o += 4u;
    dst[o++] = in->direction_code;
    ninlil_r7_binding_store_u16_be(dst + o, NINLIL_R7_BINDING_ALLOWED_KIND_MASK);
    o += 2u;
    return o;
}

static size_t ninlil_r7_binding_encode_e2e_into(
    const ninlil_r7_e2e_binding_input *in, uint8_t *dst)
{
    size_t o = 0u;

    ninlil_r7_binding_copy(dst + o, k_e2e_label, 20u);
    o += 20u;
    dst[o++] = NINLIL_R7_BINDING_PROFILE_ID;
    dst[o++] = in->environment_code;
    o += ninlil_r7_binding_put_opaque(dst + o, &in->site_domain);
    ninlil_r7_binding_store_u64_be(dst + o, in->membership_epoch);
    o += 8u;
    o += ninlil_r7_binding_put_opaque(dst + o, &in->e2e_security_id);
    ninlil_r7_binding_store_u64_be(dst + o, in->e2e_security_epoch);
    o += 8u;
    o += ninlil_r7_binding_put_opaque(dst + o, &in->sender_stable_id);
    o += ninlil_r7_binding_put_opaque(dst + o, &in->receiver_stable_id);
    o += ninlil_r7_binding_put_opaque(dst + o, &in->authority_id);
    ninlil_r7_binding_store_u64_be(dst + o, in->authority_term);
    o += 8u;
    ninlil_r7_binding_store_u32_be(dst + o, in->e2e_context_id);
    o += 4u;
    dst[o++] = in->direction_code;
    return o;
}

/* -------------------------------------------------------------------------- */
/* T0 status mapping (docs/33 §8)                                             */
/* -------------------------------------------------------------------------- */

static int32_t ninlil_r7_binding_map_t0(ninlil_r7_crypto_status st)
{
    if (st == NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_BINDING_OK;
    }
    if (st == NINLIL_R7_CRYPTO_BACKEND_FAILED) {
        return NINLIL_R7_BINDING_BACKEND_FAILED;
    }
    /* INVALID_ARGUMENT, CAPACITY, ALIAS, AUTH_FAILED, INTERNAL_CONTRACT,
     * unknown → INTERNAL_CONTRACT. Never degrade unknown to success. */
    return NINLIL_R7_BINDING_INTERNAL_CONTRACT;
}

/* Fixed-iteration constant-time-ish 32-byte compare; reads all bytes. */
static int ninlil_r7_binding_digest_equal(
    const uint8_t a[32], const uint8_t b[32])
{
    uint8_t diff = 0u;
    size_t i;
    for (i = 0u; i < 32u; i++) {
        diff = (uint8_t)(diff | (uint8_t)(a[i] ^ b[i]));
    }
    return diff == 0u;
}

/* -------------------------------------------------------------------------- */
/* Alias helpers for hop/e2e mutable outputs                                  */
/* -------------------------------------------------------------------------- */

static void ninlil_r7_binding_hop_ro_spans(
    const ninlil_r7_hop_binding_input *in,
    const ninlil_r7_crypto_provider *provider,
    const uint8_t *expected_digest32,
    const uint8_t *traffic_secret32,
    const void **ro,
    size_t *ro_lens,
    size_t *ro_n_out)
{
    size_t n = 0u;

    if (provider != NULL) {
        ro[n] = provider;
        ro_lens[n] = sizeof(*provider);
        n++;
    }
    ro[n] = in;
    ro_lens[n] = sizeof(*in);
    n++;
    if (in->site_domain.length > 0u) {
        ro[n] = in->site_domain.bytes;
        ro_lens[n] = (size_t)in->site_domain.length;
        n++;
    }
    if (in->attachment_id.length > 0u) {
        ro[n] = in->attachment_id.bytes;
        ro_lens[n] = (size_t)in->attachment_id.length;
        n++;
    }
    if (in->initiator_stable_id.length > 0u) {
        ro[n] = in->initiator_stable_id.bytes;
        ro_lens[n] = (size_t)in->initiator_stable_id.length;
        n++;
    }
    if (in->responder_stable_id.length > 0u) {
        ro[n] = in->responder_stable_id.bytes;
        ro_lens[n] = (size_t)in->responder_stable_id.length;
        n++;
    }
    if (in->controller_authority_id.length > 0u) {
        ro[n] = in->controller_authority_id.bytes;
        ro_lens[n] = (size_t)in->controller_authority_id.length;
        n++;
    }
    if (expected_digest32 != NULL) {
        ro[n] = expected_digest32;
        ro_lens[n] = 32u;
        n++;
    }
    if (traffic_secret32 != NULL) {
        ro[n] = traffic_secret32;
        ro_lens[n] = 32u;
        n++;
    }
    *ro_n_out = n;
}

static void ninlil_r7_binding_e2e_ro_spans(
    const ninlil_r7_e2e_binding_input *in,
    const ninlil_r7_crypto_provider *provider,
    const uint8_t *expected_digest32,
    const uint8_t *traffic_secret32,
    const void **ro,
    size_t *ro_lens,
    size_t *ro_n_out)
{
    size_t n = 0u;

    if (provider != NULL) {
        ro[n] = provider;
        ro_lens[n] = sizeof(*provider);
        n++;
    }
    ro[n] = in;
    ro_lens[n] = sizeof(*in);
    n++;
    if (in->site_domain.length > 0u) {
        ro[n] = in->site_domain.bytes;
        ro_lens[n] = (size_t)in->site_domain.length;
        n++;
    }
    if (in->e2e_security_id.length > 0u) {
        ro[n] = in->e2e_security_id.bytes;
        ro_lens[n] = (size_t)in->e2e_security_id.length;
        n++;
    }
    if (in->sender_stable_id.length > 0u) {
        ro[n] = in->sender_stable_id.bytes;
        ro_lens[n] = (size_t)in->sender_stable_id.length;
        n++;
    }
    if (in->receiver_stable_id.length > 0u) {
        ro[n] = in->receiver_stable_id.bytes;
        ro_lens[n] = (size_t)in->receiver_stable_id.length;
        n++;
    }
    if (in->authority_id.length > 0u) {
        ro[n] = in->authority_id.bytes;
        ro_lens[n] = (size_t)in->authority_id.length;
        n++;
    }
    if (expected_digest32 != NULL) {
        ro[n] = expected_digest32;
        ro_lens[n] = 32u;
        n++;
    }
    if (traffic_secret32 != NULL) {
        ro[n] = traffic_secret32;
        ro_lens[n] = 32u;
        n++;
    }
    *ro_n_out = n;
}

static int32_t ninlil_r7_binding_hop_alias_encode(
    const ninlil_r7_hop_binding_input *in,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    const void *mut[2];
    size_t mut_lens[2];
    const void *ro[8];
    size_t ro_lens[8];
    size_t ro_n = 0u;

    mut[0] = out;
    mut_lens[0] = out_capacity;
    mut[1] = out_len;
    mut_lens[1] = sizeof(*out_len);
    ninlil_r7_binding_hop_ro_spans(in, NULL, NULL, NULL, ro, ro_lens, &ro_n);
    return ninlil_r7_binding_check_mut_alias(
        mut, mut_lens, 2u, ro, ro_lens, ro_n);
}

static int32_t ninlil_r7_binding_e2e_alias_encode(
    const ninlil_r7_e2e_binding_input *in,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    const void *mut[2];
    size_t mut_lens[2];
    const void *ro[8];
    size_t ro_lens[8];
    size_t ro_n = 0u;

    mut[0] = out;
    mut_lens[0] = out_capacity;
    mut[1] = out_len;
    mut_lens[1] = sizeof(*out_len);
    ninlil_r7_binding_e2e_ro_spans(in, NULL, NULL, NULL, ro, ro_lens, &ro_n);
    return ninlil_r7_binding_check_mut_alias(
        mut, mut_lens, 2u, ro, ro_lens, ro_n);
}

static int32_t ninlil_r7_binding_hop_alias_digest(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_hop_binding_input *in,
    uint8_t out_digest32[32])
{
    const void *mut[1];
    size_t mut_lens[1];
    const void *ro[8];
    size_t ro_lens[8];
    size_t ro_n = 0u;

    mut[0] = out_digest32;
    mut_lens[0] = 32u;
    ninlil_r7_binding_hop_ro_spans(
        in, provider, NULL, NULL, ro, ro_lens, &ro_n);
    return ninlil_r7_binding_check_mut_alias(
        mut, mut_lens, 1u, ro, ro_lens, ro_n);
}

static int32_t ninlil_r7_binding_e2e_alias_digest(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_e2e_binding_input *in,
    uint8_t out_digest32[32])
{
    const void *mut[1];
    size_t mut_lens[1];
    const void *ro[8];
    size_t ro_lens[8];
    size_t ro_n = 0u;

    mut[0] = out_digest32;
    mut_lens[0] = 32u;
    ninlil_r7_binding_e2e_ro_spans(
        in, provider, NULL, NULL, ro, ro_lens, &ro_n);
    return ninlil_r7_binding_check_mut_alias(
        mut, mut_lens, 1u, ro, ro_lens, ro_n);
}

static int32_t ninlil_r7_binding_hop_alias_derive(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_hop_binding_input *in,
    const uint8_t expected_digest32[32],
    const uint8_t traffic_secret32[32],
    ninlil_r7_hop_key_bundle *out_bundle)
{
    const void *mut[1];
    size_t mut_lens[1];
    const void *ro[10];
    size_t ro_lens[10];
    size_t ro_n = 0u;

    mut[0] = out_bundle;
    mut_lens[0] = sizeof(*out_bundle);
    ninlil_r7_binding_hop_ro_spans(
        in, provider, expected_digest32, traffic_secret32, ro, ro_lens, &ro_n);
    return ninlil_r7_binding_check_mut_alias(
        mut, mut_lens, 1u, ro, ro_lens, ro_n);
}

static int32_t ninlil_r7_binding_e2e_alias_derive(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_e2e_binding_input *in,
    const uint8_t expected_digest32[32],
    const uint8_t traffic_secret32[32],
    ninlil_r7_e2e_key_bundle *out_bundle)
{
    const void *mut[1];
    size_t mut_lens[1];
    const void *ro[10];
    size_t ro_lens[10];
    size_t ro_n = 0u;

    mut[0] = out_bundle;
    mut_lens[0] = sizeof(*out_bundle);
    ninlil_r7_binding_e2e_ro_spans(
        in, provider, expected_digest32, traffic_secret32, ro, ro_lens, &ro_n);
    return ninlil_r7_binding_check_mut_alias(
        mut, mut_lens, 1u, ro, ro_lens, ro_n);
}

/* -------------------------------------------------------------------------- */
/* Public: encode                                                             */
/* -------------------------------------------------------------------------- */

int32_t ninlil_r7_encode_hop_binding(
    const ninlil_r7_hop_binding_input *input,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    uint8_t candidate[NINLIL_R7_BINDING_HOP_CANON_MAX];
    size_t need;
    size_t got;
    int32_t st;

    if (input == NULL || out == NULL || out_len == NULL) {
        return NINLIL_R7_BINDING_INVALID_ARGUMENT;
    }
    st = ninlil_r7_binding_hop_opaque_shape(input);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }
    st = ninlil_r7_binding_hop_structural(input);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }
    need = ninlil_r7_binding_hop_required_len(input);
    if (need > NINLIL_R7_BINDING_HOP_CANON_MAX || out_capacity != need) {
        return NINLIL_R7_BINDING_CAPACITY;
    }
    st = ninlil_r7_binding_hop_alias_encode(input, out, out_capacity, out_len);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }

    got = ninlil_r7_binding_encode_hop_into(input, candidate);
    if (got != need) {
        ninlil_r7_binding_secure_zero(candidate, sizeof(candidate));
        return NINLIL_R7_BINDING_INTERNAL_CONTRACT;
    }

    ninlil_r7_binding_copy(out, candidate, need);
    *out_len = need;
    ninlil_r7_binding_secure_zero(candidate, sizeof(candidate));
    return NINLIL_R7_BINDING_OK;
}

int32_t ninlil_r7_encode_e2e_binding(
    const ninlil_r7_e2e_binding_input *input,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    uint8_t candidate[NINLIL_R7_BINDING_E2E_CANON_MAX];
    size_t need;
    size_t got;
    int32_t st;

    if (input == NULL || out == NULL || out_len == NULL) {
        return NINLIL_R7_BINDING_INVALID_ARGUMENT;
    }
    st = ninlil_r7_binding_e2e_opaque_shape(input);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }
    st = ninlil_r7_binding_e2e_structural(input);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }
    need = ninlil_r7_binding_e2e_required_len(input);
    if (need > NINLIL_R7_BINDING_E2E_CANON_MAX || out_capacity != need) {
        return NINLIL_R7_BINDING_CAPACITY;
    }
    st = ninlil_r7_binding_e2e_alias_encode(input, out, out_capacity, out_len);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }

    got = ninlil_r7_binding_encode_e2e_into(input, candidate);
    if (got != need) {
        ninlil_r7_binding_secure_zero(candidate, sizeof(candidate));
        return NINLIL_R7_BINDING_INTERNAL_CONTRACT;
    }

    ninlil_r7_binding_copy(out, candidate, need);
    *out_len = need;
    ninlil_r7_binding_secure_zero(candidate, sizeof(candidate));
    return NINLIL_R7_BINDING_OK;
}

/* -------------------------------------------------------------------------- */
/* Public: digest                                                             */
/* -------------------------------------------------------------------------- */

int32_t ninlil_r7_digest_hop_binding(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_hop_binding_input *input,
    uint8_t out_digest32[32])
{
    uint8_t candidate_canon[NINLIL_R7_BINDING_HOP_CANON_MAX];
    uint8_t candidate_digest[32];
    size_t need;
    size_t got;
    int32_t st;
    ninlil_r7_crypto_status cst;

    if (provider == NULL || input == NULL || out_digest32 == NULL) {
        return NINLIL_R7_BINDING_INVALID_ARGUMENT;
    }
    if (ninlil_r7_crypto_provider_validate(provider) != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_BINDING_INVALID_ARGUMENT;
    }
    st = ninlil_r7_binding_hop_opaque_shape(input);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }
    st = ninlil_r7_binding_hop_structural(input);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }
    need = ninlil_r7_binding_hop_required_len(input);
    if (need > NINLIL_R7_BINDING_HOP_CANON_MAX) {
        return NINLIL_R7_BINDING_INTERNAL_CONTRACT;
    }
    st = ninlil_r7_binding_hop_alias_digest(provider, input, out_digest32);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }

    got = ninlil_r7_binding_encode_hop_into(input, candidate_canon);
    if (got != need) {
        ninlil_r7_binding_secure_zero(candidate_canon, sizeof(candidate_canon));
        ninlil_r7_binding_secure_zero(candidate_digest, sizeof(candidate_digest));
        return NINLIL_R7_BINDING_INTERNAL_CONTRACT;
    }

    cst = ninlil_r7_crypto_sha256(
        provider, candidate_canon, need, candidate_digest);
    st = ninlil_r7_binding_map_t0(cst);
    if (st == NINLIL_R7_BINDING_OK) {
        ninlil_r7_binding_copy(out_digest32, candidate_digest, 32u);
    }

    ninlil_r7_binding_secure_zero(candidate_canon, sizeof(candidate_canon));
    ninlil_r7_binding_secure_zero(candidate_digest, sizeof(candidate_digest));
    return st;
}

int32_t ninlil_r7_digest_e2e_binding(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_e2e_binding_input *input,
    uint8_t out_digest32[32])
{
    uint8_t candidate_canon[NINLIL_R7_BINDING_E2E_CANON_MAX];
    uint8_t candidate_digest[32];
    size_t need;
    size_t got;
    int32_t st;
    ninlil_r7_crypto_status cst;

    if (provider == NULL || input == NULL || out_digest32 == NULL) {
        return NINLIL_R7_BINDING_INVALID_ARGUMENT;
    }
    if (ninlil_r7_crypto_provider_validate(provider) != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_BINDING_INVALID_ARGUMENT;
    }
    st = ninlil_r7_binding_e2e_opaque_shape(input);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }
    st = ninlil_r7_binding_e2e_structural(input);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }
    need = ninlil_r7_binding_e2e_required_len(input);
    if (need > NINLIL_R7_BINDING_E2E_CANON_MAX) {
        return NINLIL_R7_BINDING_INTERNAL_CONTRACT;
    }
    st = ninlil_r7_binding_e2e_alias_digest(provider, input, out_digest32);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }

    got = ninlil_r7_binding_encode_e2e_into(input, candidate_canon);
    if (got != need) {
        ninlil_r7_binding_secure_zero(candidate_canon, sizeof(candidate_canon));
        ninlil_r7_binding_secure_zero(candidate_digest, sizeof(candidate_digest));
        return NINLIL_R7_BINDING_INTERNAL_CONTRACT;
    }

    cst = ninlil_r7_crypto_sha256(
        provider, candidate_canon, need, candidate_digest);
    st = ninlil_r7_binding_map_t0(cst);
    if (st == NINLIL_R7_BINDING_OK) {
        ninlil_r7_binding_copy(out_digest32, candidate_digest, 32u);
    }

    ninlil_r7_binding_secure_zero(candidate_canon, sizeof(candidate_canon));
    ninlil_r7_binding_secure_zero(candidate_digest, sizeof(candidate_digest));
    return st;
}

/* -------------------------------------------------------------------------- */
/* Public: verified derive                                                    */
/* -------------------------------------------------------------------------- */

int32_t ninlil_r7_derive_hop_key_bundle_verified(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_hop_binding_input *input,
    const uint8_t expected_digest32[32],
    const uint8_t traffic_secret32[32],
    ninlil_r7_hop_key_bundle *out_bundle)
{
    uint8_t candidate_canon[NINLIL_R7_BINDING_HOP_CANON_MAX];
    uint8_t local_digest[32];
    uint8_t secret_copy[32];
    uint8_t prk[32];
    uint8_t data_key[16];
    uint8_t data_iv[12];
    uint8_t ack_key[16];
    uint8_t ack_iv[12];
    size_t need;
    size_t got;
    int32_t st;
    ninlil_r7_crypto_status cst;

    if (provider == NULL || input == NULL || expected_digest32 == NULL
        || traffic_secret32 == NULL || out_bundle == NULL) {
        return NINLIL_R7_BINDING_INVALID_ARGUMENT;
    }
    if (ninlil_r7_crypto_provider_validate(provider) != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_BINDING_INVALID_ARGUMENT;
    }
    st = ninlil_r7_binding_hop_opaque_shape(input);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }
    st = ninlil_r7_binding_hop_structural(input);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }
    need = ninlil_r7_binding_hop_required_len(input);
    if (need > NINLIL_R7_BINDING_HOP_CANON_MAX) {
        return NINLIL_R7_BINDING_INTERNAL_CONTRACT;
    }
    st = ninlil_r7_binding_hop_alias_derive(
        provider, input, expected_digest32, traffic_secret32, out_bundle);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }

    got = ninlil_r7_binding_encode_hop_into(input, candidate_canon);
    if (got != need) {
        st = NINLIL_R7_BINDING_INTERNAL_CONTRACT;
        goto zero_return;
    }

    cst = ninlil_r7_crypto_sha256(
        provider, candidate_canon, need, local_digest);
    st = ninlil_r7_binding_map_t0(cst);
    if (st != NINLIL_R7_BINDING_OK) {
        goto zero_return;
    }

    if (!ninlil_r7_binding_digest_equal(local_digest, expected_digest32)) {
        st = NINLIL_R7_BINDING_MISMATCH;
        goto zero_return;
    }

    ninlil_r7_binding_copy(secret_copy, traffic_secret32, 32u);

    cst = ninlil_r7_crypto_hkdf_extract_sha256(
        provider, local_digest, 32u, secret_copy, 32u, prk);
    st = ninlil_r7_binding_map_t0(cst);
    if (st != NINLIL_R7_BINDING_OK) {
        goto zero_return;
    }

    cst = ninlil_r7_crypto_hkdf_expand_sha256(
        provider, prk, k_hop_data_key_info, 25u, data_key, 16u);
    st = ninlil_r7_binding_map_t0(cst);
    if (st != NINLIL_R7_BINDING_OK) {
        goto zero_return;
    }

    cst = ninlil_r7_crypto_hkdf_expand_sha256(
        provider, prk, k_hop_data_iv_info, 24u, data_iv, 12u);
    st = ninlil_r7_binding_map_t0(cst);
    if (st != NINLIL_R7_BINDING_OK) {
        goto zero_return;
    }

    cst = ninlil_r7_crypto_hkdf_expand_sha256(
        provider, prk, k_hop_ack_key_info, 24u, ack_key, 16u);
    st = ninlil_r7_binding_map_t0(cst);
    if (st != NINLIL_R7_BINDING_OK) {
        goto zero_return;
    }

    cst = ninlil_r7_crypto_hkdf_expand_sha256(
        provider, prk, k_hop_ack_iv_info, 23u, ack_iv, 12u);
    st = ninlil_r7_binding_map_t0(cst);
    if (st != NINLIL_R7_BINDING_OK) {
        goto zero_return;
    }

    /* Atomic typed bundle publish after all Expand success. */
    ninlil_r7_binding_copy(out_bundle->data_key16, data_key, 16u);
    ninlil_r7_binding_copy(out_bundle->data_iv12, data_iv, 12u);
    ninlil_r7_binding_copy(out_bundle->ack_key16, ack_key, 16u);
    ninlil_r7_binding_copy(out_bundle->ack_iv12, ack_iv, 12u);
    st = NINLIL_R7_BINDING_OK;

zero_return:
    ninlil_r7_binding_secure_zero(candidate_canon, sizeof(candidate_canon));
    ninlil_r7_binding_secure_zero(local_digest, sizeof(local_digest));
    ninlil_r7_binding_secure_zero(secret_copy, sizeof(secret_copy));
    ninlil_r7_binding_secure_zero(prk, sizeof(prk));
    ninlil_r7_binding_secure_zero(data_key, sizeof(data_key));
    ninlil_r7_binding_secure_zero(data_iv, sizeof(data_iv));
    ninlil_r7_binding_secure_zero(ack_key, sizeof(ack_key));
    ninlil_r7_binding_secure_zero(ack_iv, sizeof(ack_iv));
    return st;
}

int32_t ninlil_r7_derive_e2e_key_bundle_verified(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_e2e_binding_input *input,
    const uint8_t expected_digest32[32],
    const uint8_t traffic_secret32[32],
    ninlil_r7_e2e_key_bundle *out_bundle)
{
    uint8_t candidate_canon[NINLIL_R7_BINDING_E2E_CANON_MAX];
    uint8_t local_digest[32];
    uint8_t secret_copy[32];
    uint8_t prk[32];
    uint8_t key16[16];
    uint8_t iv12[12];
    size_t need;
    size_t got;
    int32_t st;
    ninlil_r7_crypto_status cst;

    if (provider == NULL || input == NULL || expected_digest32 == NULL
        || traffic_secret32 == NULL || out_bundle == NULL) {
        return NINLIL_R7_BINDING_INVALID_ARGUMENT;
    }
    if (ninlil_r7_crypto_provider_validate(provider) != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_BINDING_INVALID_ARGUMENT;
    }
    st = ninlil_r7_binding_e2e_opaque_shape(input);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }
    st = ninlil_r7_binding_e2e_structural(input);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }
    need = ninlil_r7_binding_e2e_required_len(input);
    if (need > NINLIL_R7_BINDING_E2E_CANON_MAX) {
        return NINLIL_R7_BINDING_INTERNAL_CONTRACT;
    }
    st = ninlil_r7_binding_e2e_alias_derive(
        provider, input, expected_digest32, traffic_secret32, out_bundle);
    if (st != NINLIL_R7_BINDING_OK) {
        return st;
    }

    got = ninlil_r7_binding_encode_e2e_into(input, candidate_canon);
    if (got != need) {
        st = NINLIL_R7_BINDING_INTERNAL_CONTRACT;
        goto zero_return;
    }

    cst = ninlil_r7_crypto_sha256(
        provider, candidate_canon, need, local_digest);
    st = ninlil_r7_binding_map_t0(cst);
    if (st != NINLIL_R7_BINDING_OK) {
        goto zero_return;
    }

    if (!ninlil_r7_binding_digest_equal(local_digest, expected_digest32)) {
        st = NINLIL_R7_BINDING_MISMATCH;
        goto zero_return;
    }

    ninlil_r7_binding_copy(secret_copy, traffic_secret32, 32u);

    cst = ninlil_r7_crypto_hkdf_extract_sha256(
        provider, local_digest, 32u, secret_copy, 32u, prk);
    st = ninlil_r7_binding_map_t0(cst);
    if (st != NINLIL_R7_BINDING_OK) {
        goto zero_return;
    }

    cst = ninlil_r7_crypto_hkdf_expand_sha256(
        provider, prk, k_e2e_key_info, 20u, key16, 16u);
    st = ninlil_r7_binding_map_t0(cst);
    if (st != NINLIL_R7_BINDING_OK) {
        goto zero_return;
    }

    cst = ninlil_r7_crypto_hkdf_expand_sha256(
        provider, prk, k_e2e_iv_info, 19u, iv12, 12u);
    st = ninlil_r7_binding_map_t0(cst);
    if (st != NINLIL_R7_BINDING_OK) {
        goto zero_return;
    }

    ninlil_r7_binding_copy(out_bundle->key16, key16, 16u);
    ninlil_r7_binding_copy(out_bundle->iv12, iv12, 12u);
    st = NINLIL_R7_BINDING_OK;

zero_return:
    ninlil_r7_binding_secure_zero(candidate_canon, sizeof(candidate_canon));
    ninlil_r7_binding_secure_zero(local_digest, sizeof(local_digest));
    ninlil_r7_binding_secure_zero(secret_copy, sizeof(secret_copy));
    ninlil_r7_binding_secure_zero(prk, sizeof(prk));
    ninlil_r7_binding_secure_zero(key16, sizeof(key16));
    ninlil_r7_binding_secure_zero(iv12, sizeof(iv12));
    return st;
}
