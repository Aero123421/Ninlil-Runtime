/*
 * R7 T1 NRW1 SINGLE pure wire codec (docs/32, ADR-0012).
 *
 * Production-private C11. Stateless dual-envelope codec only.
 * No heap, VLA, OS, OpenSSL, mbedTLS, N6, R2, R5, or HAL.
 * AES-GCM / nonce only via ninlil_r7_crypto_* (docs/31).
 *
 * Failure: caller output/input/length mutation zero; no output zero-fill.
 * Success: layer-local candidate then atomic publish of that layer only.
 * No composite Seal/Open production API.
 */

#include "r7_wire_codec.h"

#include <stdatomic.h>

/* -------------------------------------------------------------------------- */
/* Internal helpers                                                           */
/* -------------------------------------------------------------------------- */

static void ninlil_r7_wire_secure_zero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    size_t i;

    for (i = 0u; i < n; i++) {
        v[i] = 0u;
    }
    atomic_signal_fence(memory_order_seq_cst);
}

static void ninlil_r7_wire_copy(uint8_t *dst, const uint8_t *src, size_t n)
{
    size_t i;

    for (i = 0u; i < n; i++) {
        dst[i] = src[i];
    }
}

static int ninlil_r7_wire_spans_forbidden(
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
    if (aa > (UINTPTR_MAX - a_len) || bb > (UINTPTR_MAX - b_len)) {
        return 1;
    }
    ae = aa + a_len;
    be = bb + b_len;
    if (aa < be && bb < ae) {
        return 1;
    }
    return 0;
}

#ifdef NINLIL_R7_WIRE_TEST_BUILD
int ninlil_r7_wire_test_spans_forbidden(
    const void *a, size_t a_len, const void *b, size_t b_len)
{
    return ninlil_r7_wire_spans_forbidden(a, a_len, b, b_len);
}
#endif

static ninlil_r7_wire_status ninlil_r7_wire_check_pairwise(
    const void *const *spans, const size_t *lens, size_t n)
{
    size_t i;
    size_t j;

    for (i = 0u; i < n; i++) {
        for (j = i + 1u; j < n; j++) {
            if (ninlil_r7_wire_spans_forbidden(
                    spans[i], lens[i], spans[j], lens[j])) {
                return NINLIL_R7_WIRE_ALIAS;
            }
        }
    }
    return NINLIL_R7_WIRE_OK;
}

static void ninlil_r7_wire_store_u16_be(uint8_t *out, uint16_t v)
{
    out[0] = (uint8_t)((v >> 8) & 0xffu);
    out[1] = (uint8_t)(v & 0xffu);
}

static void ninlil_r7_wire_store_u32_be(uint8_t *out, uint32_t v)
{
    out[0] = (uint8_t)((v >> 24) & 0xffu);
    out[1] = (uint8_t)((v >> 16) & 0xffu);
    out[2] = (uint8_t)((v >> 8) & 0xffu);
    out[3] = (uint8_t)(v & 0xffu);
}

static void ninlil_r7_wire_store_u64_be(uint8_t *out, uint64_t v)
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

static uint16_t ninlil_r7_wire_load_u16_be(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

static uint32_t ninlil_r7_wire_load_u32_be(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static uint64_t ninlil_r7_wire_load_u64_be(const uint8_t *in)
{
    return ((uint64_t)in[0] << 56) | ((uint64_t)in[1] << 48)
        | ((uint64_t)in[2] << 40) | ((uint64_t)in[3] << 32)
        | ((uint64_t)in[4] << 24) | ((uint64_t)in[5] << 16)
        | ((uint64_t)in[6] << 8) | (uint64_t)in[7];
}

static int ninlil_r7_wire_context_ok(uint32_t context_id)
{
    return context_id != 0u && context_id != UINT32_MAX;
}

static int ninlil_r7_wire_counter_ok(uint64_t counter)
{
    return counter != 0u && counter != UINT64_MAX;
}

static ninlil_r7_wire_status ninlil_r7_wire_validate_outer_fields(
    const ninlil_r7_wire_outer_data_fields *fields)
{
    if (fields == NULL) {
        return NINLIL_R7_WIRE_INVALID_ARGUMENT;
    }
    if (fields->ack_requested != 0u && fields->ack_requested != 1u) {
        return NINLIL_R7_WIRE_STRUCTURAL;
    }
    if (!ninlil_r7_wire_context_ok(fields->hop_context_id)
        || !ninlil_r7_wire_counter_ok(fields->hop_counter)) {
        return NINLIL_R7_WIRE_STRUCTURAL;
    }
    if (fields->route_handle == 0u && fields->route_generation == 0u
        && fields->hop_remaining == 0u) {
        return NINLIL_R7_WIRE_OK;
    }
    if (fields->route_handle != 0u && fields->route_generation != 0u
        && fields->hop_remaining >= 1u) {
        /* hop_remaining is u8 so upper bound is already 255. */
        return NINLIL_R7_WIRE_OK;
    }
    return NINLIL_R7_WIRE_STRUCTURAL;
}

static ninlil_r7_wire_status ninlil_r7_wire_validate_e2e_fields(
    const ninlil_r7_wire_e2e_single_fields *fields)
{
    if (fields == NULL) {
        return NINLIL_R7_WIRE_INVALID_ARGUMENT;
    }
    if (!ninlil_r7_wire_context_ok(fields->e2e_context_id)
        || !ninlil_r7_wire_counter_ok(fields->e2e_counter)) {
        return NINLIL_R7_WIRE_STRUCTURAL;
    }
    return NINLIL_R7_WIRE_OK;
}

/*
 * Structural-only parse of visible E2E AAD14 + SINGLE length domain.
 * Does not prove tag authenticity.
 */
static ninlil_r7_wire_status ninlil_r7_wire_structural_e2e_blob(
    const uint8_t *blob, size_t blob_len)
{
    uint8_t type_flags;
    uint32_t ctx;
    uint64_t ctr;
    size_t n;

    if (blob == NULL) {
        return NINLIL_R7_WIRE_INVALID_ARGUMENT;
    }
    if (blob_len < NINLIL_R7_WIRE_E2E_BLOB_MIN
        || blob_len > NINLIL_R7_WIRE_E2E_BLOB_MAX) {
        return NINLIL_R7_WIRE_LENGTH_CLASS;
    }
    /* N = blob_len - 30; domain already implies N in 1..190. */
    if (blob_len < (NINLIL_R7_WIRE_E2E_AAD_LEN + NINLIL_R7_WIRE_TAG_LEN
                    + NINLIL_R7_WIRE_APP_MIN)) {
        return NINLIL_R7_WIRE_LENGTH_CLASS;
    }
    n = blob_len - (NINLIL_R7_WIRE_E2E_AAD_LEN + NINLIL_R7_WIRE_TAG_LEN);
    if (n < NINLIL_R7_WIRE_APP_MIN || n > NINLIL_R7_WIRE_APP_MAX) {
        return NINLIL_R7_WIRE_LENGTH_CLASS;
    }
    if (blob[0] != NINLIL_R7_WIRE_PROFILE_ID) {
        return NINLIL_R7_WIRE_STRUCTURAL;
    }
    type_flags = blob[1];
    if ((type_flags & 0x0fu) != 0u) {
        return NINLIL_R7_WIRE_STRUCTURAL;
    }
    if ((uint8_t)((type_flags >> 4) & 0x0fu) != NINLIL_R7_WIRE_E2E_TYPE_SINGLE) {
        return NINLIL_R7_WIRE_STRUCTURAL;
    }
    ctx = ninlil_r7_wire_load_u32_be(blob + 2);
    ctr = ninlil_r7_wire_load_u64_be(blob + 6);
    if (!ninlil_r7_wire_context_ok(ctx) || !ninlil_r7_wire_counter_ok(ctr)) {
        return NINLIL_R7_WIRE_STRUCTURAL;
    }
    return NINLIL_R7_WIRE_OK;
}

static ninlil_r7_wire_status ninlil_r7_wire_map_crypto(
    ninlil_r7_crypto_status st, int is_open)
{
    if (st == NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_WIRE_OK;
    }
    if (is_open && st == NINLIL_R7_CRYPTO_AUTH_FAILED) {
        return NINLIL_R7_WIRE_AUTH_FAILED;
    }
    if (st == NINLIL_R7_CRYPTO_BACKEND_FAILED) {
        return NINLIL_R7_WIRE_BACKEND_FAILED;
    }
    if (st == NINLIL_R7_CRYPTO_INTERNAL_CONTRACT) {
        return NINLIL_R7_WIRE_INTERNAL_CONTRACT;
    }
    /* After wire prevalidation, caller-shape crypto errors are wire contracts. */
    if (st == NINLIL_R7_CRYPTO_INVALID_ARGUMENT
        || st == NINLIL_R7_CRYPTO_CAPACITY
        || st == NINLIL_R7_CRYPTO_ALIAS) {
        return NINLIL_R7_WIRE_INTERNAL_CONTRACT;
    }
    return NINLIL_R7_WIRE_INTERNAL_CONTRACT;
}

static ninlil_r7_wire_status ninlil_r7_wire_map_nonce(
    ninlil_r7_crypto_status st)
{
    if (st == NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_WIRE_OK;
    }
    if (st == NINLIL_R7_CRYPTO_INVALID_ARGUMENT) {
        /* Counter domain already wire-validated; residual is contract/shape. */
        return NINLIL_R7_WIRE_INTERNAL_CONTRACT;
    }
    if (st == NINLIL_R7_CRYPTO_ALIAS) {
        return NINLIL_R7_WIRE_INTERNAL_CONTRACT;
    }
    return NINLIL_R7_WIRE_INTERNAL_CONTRACT;
}

/* -------------------------------------------------------------------------- */
/* AAD pack / parse                                                           */
/* -------------------------------------------------------------------------- */

ninlil_r7_wire_status ninlil_r7_wire_pack_outer_data_aad(
    const ninlil_r7_wire_outer_data_fields *fields,
    uint8_t *out_aad19,
    size_t out_capacity)
{
    uint8_t candidate[NINLIL_R7_WIRE_OUTER_AAD_LEN] = {0};
    ninlil_r7_wire_status st = NINLIL_R7_WIRE_OK;
    const void *spans[2];
    size_t lens[2];

    if (fields == NULL || out_aad19 == NULL) {
        st = NINLIL_R7_WIRE_INVALID_ARGUMENT;
        goto done;
    }
    st = ninlil_r7_wire_validate_outer_fields(fields);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }
    if (out_capacity != NINLIL_R7_WIRE_OUTER_AAD_LEN) {
        st = NINLIL_R7_WIRE_CAPACITY;
        goto done;
    }
    spans[0] = fields;
    lens[0] = sizeof(*fields);
    spans[1] = out_aad19;
    lens[1] = out_capacity;
    st = ninlil_r7_wire_check_pairwise(spans, lens, 2u);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }

    candidate[0] = NINLIL_R7_WIRE_PROFILE_ID;
    candidate[1] = (uint8_t)((NINLIL_R7_WIRE_OUTER_KIND_DATA << 4)
                             | (fields->ack_requested & 1u));
    candidate[2] = fields->hop_remaining;
    ninlil_r7_wire_store_u32_be(candidate + 3, fields->hop_context_id);
    ninlil_r7_wire_store_u64_be(candidate + 7, fields->hop_counter);
    ninlil_r7_wire_store_u16_be(candidate + 15, fields->route_handle);
    ninlil_r7_wire_store_u16_be(candidate + 17, fields->route_generation);

    ninlil_r7_wire_copy(out_aad19, candidate, NINLIL_R7_WIRE_OUTER_AAD_LEN);
    st = NINLIL_R7_WIRE_OK;
done:
    ninlil_r7_wire_secure_zero(candidate, sizeof(candidate));
    return st;
}

ninlil_r7_wire_status ninlil_r7_wire_parse_outer_data_aad(
    const uint8_t *aad19,
    size_t aad_len,
    ninlil_r7_wire_outer_data_fields *out_fields)
{
    ninlil_r7_wire_outer_data_fields candidate = {0};
    ninlil_r7_wire_status st = NINLIL_R7_WIRE_OK;
    uint8_t kind_flags;
    uint8_t kind;
    const void *spans[2];
    size_t lens[2];

    if (aad19 == NULL || out_fields == NULL) {
        st = NINLIL_R7_WIRE_INVALID_ARGUMENT;
        goto done;
    }
    if (aad_len != NINLIL_R7_WIRE_OUTER_AAD_LEN) {
        st = NINLIL_R7_WIRE_LENGTH_CLASS;
        goto done;
    }
    if (aad19[0] != NINLIL_R7_WIRE_PROFILE_ID) {
        st = NINLIL_R7_WIRE_STRUCTURAL;
        goto done;
    }
    kind_flags = aad19[1];
    kind = (uint8_t)((kind_flags >> 4) & 0x0fu);
    if (kind != NINLIL_R7_WIRE_OUTER_KIND_DATA) {
        st = NINLIL_R7_WIRE_STRUCTURAL;
        goto done;
    }
    if ((kind_flags & 0x0eu) != 0u) {
        st = NINLIL_R7_WIRE_STRUCTURAL;
        goto done;
    }
    candidate.ack_requested = (uint8_t)(kind_flags & 0x01u);
    candidate.hop_remaining = aad19[2];
    candidate.hop_context_id = ninlil_r7_wire_load_u32_be(aad19 + 3);
    candidate.hop_counter = ninlil_r7_wire_load_u64_be(aad19 + 7);
    candidate.route_handle = ninlil_r7_wire_load_u16_be(aad19 + 15);
    candidate.route_generation = ninlil_r7_wire_load_u16_be(aad19 + 17);
    st = ninlil_r7_wire_validate_outer_fields(&candidate);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }
    spans[0] = aad19;
    lens[0] = aad_len;
    spans[1] = out_fields;
    lens[1] = sizeof(*out_fields);
    st = ninlil_r7_wire_check_pairwise(spans, lens, 2u);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }
    *out_fields = candidate;
    st = NINLIL_R7_WIRE_OK;
done:
    ninlil_r7_wire_secure_zero(&candidate, sizeof(candidate));
    return st;
}

ninlil_r7_wire_status ninlil_r7_wire_pack_e2e_single_aad(
    const ninlil_r7_wire_e2e_single_fields *fields,
    uint8_t *out_aad14,
    size_t out_capacity)
{
    uint8_t candidate[NINLIL_R7_WIRE_E2E_AAD_LEN] = {0};
    ninlil_r7_wire_status st = NINLIL_R7_WIRE_OK;
    const void *spans[2];
    size_t lens[2];

    if (fields == NULL || out_aad14 == NULL) {
        st = NINLIL_R7_WIRE_INVALID_ARGUMENT;
        goto done;
    }
    st = ninlil_r7_wire_validate_e2e_fields(fields);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }
    if (out_capacity != NINLIL_R7_WIRE_E2E_AAD_LEN) {
        st = NINLIL_R7_WIRE_CAPACITY;
        goto done;
    }
    spans[0] = fields;
    lens[0] = sizeof(*fields);
    spans[1] = out_aad14;
    lens[1] = out_capacity;
    st = ninlil_r7_wire_check_pairwise(spans, lens, 2u);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }

    candidate[0] = NINLIL_R7_WIRE_PROFILE_ID;
    candidate[1] = (uint8_t)(NINLIL_R7_WIRE_E2E_TYPE_SINGLE << 4);
    ninlil_r7_wire_store_u32_be(candidate + 2, fields->e2e_context_id);
    ninlil_r7_wire_store_u64_be(candidate + 6, fields->e2e_counter);

    ninlil_r7_wire_copy(out_aad14, candidate, NINLIL_R7_WIRE_E2E_AAD_LEN);
    st = NINLIL_R7_WIRE_OK;
done:
    ninlil_r7_wire_secure_zero(candidate, sizeof(candidate));
    return st;
}

ninlil_r7_wire_status ninlil_r7_wire_parse_e2e_single_aad(
    const uint8_t *aad14,
    size_t aad_len,
    ninlil_r7_wire_e2e_single_fields *out_fields)
{
    ninlil_r7_wire_e2e_single_fields candidate = {0};
    ninlil_r7_wire_status st = NINLIL_R7_WIRE_OK;
    uint8_t type_flags;
    const void *spans[2];
    size_t lens[2];

    if (aad14 == NULL || out_fields == NULL) {
        st = NINLIL_R7_WIRE_INVALID_ARGUMENT;
        goto done;
    }
    if (aad_len != NINLIL_R7_WIRE_E2E_AAD_LEN) {
        st = NINLIL_R7_WIRE_LENGTH_CLASS;
        goto done;
    }
    if (aad14[0] != NINLIL_R7_WIRE_PROFILE_ID) {
        st = NINLIL_R7_WIRE_STRUCTURAL;
        goto done;
    }
    type_flags = aad14[1];
    if ((type_flags & 0x0fu) != 0u) {
        st = NINLIL_R7_WIRE_STRUCTURAL;
        goto done;
    }
    if ((uint8_t)((type_flags >> 4) & 0x0fu) != NINLIL_R7_WIRE_E2E_TYPE_SINGLE) {
        st = NINLIL_R7_WIRE_STRUCTURAL;
        goto done;
    }
    candidate.e2e_context_id = ninlil_r7_wire_load_u32_be(aad14 + 2);
    candidate.e2e_counter = ninlil_r7_wire_load_u64_be(aad14 + 6);
    st = ninlil_r7_wire_validate_e2e_fields(&candidate);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }
    spans[0] = aad14;
    lens[0] = aad_len;
    spans[1] = out_fields;
    lens[1] = sizeof(*out_fields);
    st = ninlil_r7_wire_check_pairwise(spans, lens, 2u);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }
    *out_fields = candidate;
    st = NINLIL_R7_WIRE_OK;
done:
    ninlil_r7_wire_secure_zero(&candidate, sizeof(candidate));
    return st;
}

/* -------------------------------------------------------------------------- */
/* E2E SINGLE Seal / Open                                                     */
/* -------------------------------------------------------------------------- */

ninlil_r7_wire_status ninlil_r7_wire_seal_e2e_single(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16],
    const uint8_t static_iv12[12],
    const ninlil_r7_wire_e2e_single_fields *fields,
    const uint8_t *app,
    size_t app_len,
    uint8_t *out_blob,
    size_t out_capacity,
    size_t *out_len)
{
    uint8_t aad14[NINLIL_R7_WIRE_E2E_AAD_LEN] = {0};
    uint8_t nonce12[NINLIL_R7_CRYPTO_AES128_NONCE_LEN] = {0};
    uint8_t sealed[NINLIL_R7_WIRE_APP_MAX + NINLIL_R7_WIRE_TAG_LEN] = {0};
    uint8_t blob_cand[NINLIL_R7_WIRE_E2E_BLOB_MAX] = {0};
    size_t sealed_need = 0u;
    size_t blob_need = 0u;
    size_t sealed_len = 0u;
    ninlil_r7_crypto_status cst;
    ninlil_r7_wire_status st = NINLIL_R7_WIRE_OK;
    const void *spans[7];
    size_t lens[7];
    size_t nspans;

    /* 1. provider exact shape + required pointer shape (docs/32 §5.2) */
    if (ninlil_r7_crypto_provider_validate(provider) != NINLIL_R7_CRYPTO_OK) {
        st = NINLIL_R7_WIRE_INVALID_ARGUMENT;
        goto done;
    }
    if (key16 == NULL || static_iv12 == NULL || fields == NULL || app == NULL
        || out_blob == NULL || out_len == NULL) {
        st = NINLIL_R7_WIRE_INVALID_ARGUMENT;
        goto done;
    }

    /* 2. field domain + application length 1..190 */
    st = ninlil_r7_wire_validate_e2e_fields(fields);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }
    if (app_len < NINLIL_R7_WIRE_APP_MIN || app_len > NINLIL_R7_WIRE_APP_MAX) {
        st = NINLIL_R7_WIRE_LENGTH_CLASS;
        goto done;
    }

    /* 3. exact capacity 30+N */
    if (app_len > (SIZE_MAX - (NINLIL_R7_WIRE_E2E_AAD_LEN + NINLIL_R7_WIRE_TAG_LEN))) {
        st = NINLIL_R7_WIRE_LENGTH_CLASS;
        goto done;
    }
    blob_need = NINLIL_R7_WIRE_E2E_AAD_LEN + app_len + NINLIL_R7_WIRE_TAG_LEN;
    if (out_capacity != blob_need) {
        st = NINLIL_R7_WIRE_CAPACITY;
        goto done;
    }

    /* 4. pairwise alias */
    nspans = 0u;
    spans[nspans] = provider;
    lens[nspans] = sizeof(*provider);
    nspans++;
    spans[nspans] = key16;
    lens[nspans] = NINLIL_R7_CRYPTO_AES128_KEY_LEN;
    nspans++;
    spans[nspans] = static_iv12;
    lens[nspans] = NINLIL_R7_CRYPTO_AES128_NONCE_LEN;
    nspans++;
    spans[nspans] = fields;
    lens[nspans] = sizeof(*fields);
    nspans++;
    spans[nspans] = app;
    lens[nspans] = app_len;
    nspans++;
    spans[nspans] = out_blob;
    lens[nspans] = out_capacity;
    nspans++;
    spans[nspans] = out_len;
    lens[nspans] = sizeof(size_t);
    nspans++;
    st = ninlil_r7_wire_check_pairwise(spans, lens, nspans);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }

    /* 5. AAD14 local pack */
    st = ninlil_r7_wire_pack_e2e_single_aad(
        fields, aad14, NINLIL_R7_WIRE_E2E_AAD_LEN);
    if (st != NINLIL_R7_WIRE_OK) {
        st = NINLIL_R7_WIRE_INTERNAL_CONTRACT;
        goto done;
    }

    /* 6. sole nonce helper (provider callback 0 on failure) */
    cst = ninlil_r7_crypto_nonce_from_counter(
        static_iv12, fields->e2e_counter, nonce12);
    st = ninlil_r7_wire_map_nonce(cst);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }

    /* 7–8. AES-GCM Seal exact 1 + produced shape */
    sealed_need = app_len + NINLIL_R7_WIRE_TAG_LEN;
    cst = ninlil_r7_crypto_aes128_gcm_seal(
        provider,
        key16,
        nonce12,
        aad14,
        NINLIL_R7_WIRE_E2E_AAD_LEN,
        app,
        app_len,
        sealed,
        sealed_need,
        &sealed_len);
    st = ninlil_r7_wire_map_crypto(cst, 0);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }
    if (sealed_len != sealed_need) {
        st = NINLIL_R7_WIRE_INTERNAL_CONTRACT;
        goto done;
    }

    /* 9. assemble AAD14||CT||TAG16, publish */
    ninlil_r7_wire_copy(blob_cand, aad14, NINLIL_R7_WIRE_E2E_AAD_LEN);
    ninlil_r7_wire_copy(
        blob_cand + NINLIL_R7_WIRE_E2E_AAD_LEN, sealed, sealed_need);
    if (blob_need != (NINLIL_R7_WIRE_E2E_AAD_LEN + sealed_need)) {
        st = NINLIL_R7_WIRE_INTERNAL_CONTRACT;
        goto done;
    }
    ninlil_r7_wire_copy(out_blob, blob_cand, blob_need);
    *out_len = blob_need;
    st = NINLIL_R7_WIRE_OK;
done:
    ninlil_r7_wire_secure_zero(aad14, sizeof(aad14));
    ninlil_r7_wire_secure_zero(nonce12, sizeof(nonce12));
    ninlil_r7_wire_secure_zero(sealed, sizeof(sealed));
    ninlil_r7_wire_secure_zero(blob_cand, sizeof(blob_cand));
    {
        volatile size_t *vp = (volatile size_t *)&sealed_len;
        *vp = 0u;
    }
    return st;
}

ninlil_r7_wire_status ninlil_r7_wire_open_e2e_single(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16],
    const uint8_t static_iv12[12],
    const uint8_t *blob,
    size_t blob_len,
    ninlil_r7_wire_e2e_single_fields *out_fields,
    uint8_t *out_app,
    size_t out_capacity,
    size_t *out_len)
{
    ninlil_r7_wire_e2e_single_fields fields_cand = {0};
    uint8_t aad14[NINLIL_R7_WIRE_E2E_AAD_LEN] = {0};
    uint8_t nonce12[NINLIL_R7_CRYPTO_AES128_NONCE_LEN] = {0};
    uint8_t app_cand[NINLIL_R7_WIRE_APP_MAX] = {0};
    size_t app_len = 0u;
    size_t sealed_len = 0u;
    size_t produced = 0u;
    ninlil_r7_crypto_status cst;
    ninlil_r7_wire_status st = NINLIL_R7_WIRE_OK;
    const void *spans[7];
    size_t lens[7];
    size_t nspans;

    /* 1. provider exact shape + required pointer shape (docs/32 §5.3) */
    if (ninlil_r7_crypto_provider_validate(provider) != NINLIL_R7_CRYPTO_OK) {
        st = NINLIL_R7_WIRE_INVALID_ARGUMENT;
        goto done;
    }
    if (key16 == NULL || static_iv12 == NULL || blob == NULL
        || out_fields == NULL || out_app == NULL || out_len == NULL) {
        st = NINLIL_R7_WIRE_INVALID_ARGUMENT;
        goto done;
    }

    /* 2. blob length domain + checked N = blob_len - 30 (underflow-safe) */
    if (blob_len < NINLIL_R7_WIRE_E2E_BLOB_MIN
        || blob_len > NINLIL_R7_WIRE_E2E_BLOB_MAX) {
        st = NINLIL_R7_WIRE_LENGTH_CLASS;
        goto done;
    }
    app_len = blob_len - (NINLIL_R7_WIRE_E2E_AAD_LEN + NINLIL_R7_WIRE_TAG_LEN);
    if (app_len < NINLIL_R7_WIRE_APP_MIN || app_len > NINLIL_R7_WIRE_APP_MAX) {
        st = NINLIL_R7_WIRE_LENGTH_CLASS;
        goto done;
    }

    /* 3. visible AAD structural (before capacity / alias) */
    st = ninlil_r7_wire_parse_e2e_single_aad(
        blob, NINLIL_R7_WIRE_E2E_AAD_LEN, &fields_cand);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }

    /* 4. capacity exact N */
    if (out_capacity != app_len) {
        st = NINLIL_R7_WIRE_CAPACITY;
        goto done;
    }

    /* 5. alias */
    nspans = 0u;
    spans[nspans] = provider;
    lens[nspans] = sizeof(*provider);
    nspans++;
    spans[nspans] = key16;
    lens[nspans] = NINLIL_R7_CRYPTO_AES128_KEY_LEN;
    nspans++;
    spans[nspans] = static_iv12;
    lens[nspans] = NINLIL_R7_CRYPTO_AES128_NONCE_LEN;
    nspans++;
    spans[nspans] = blob;
    lens[nspans] = blob_len;
    nspans++;
    spans[nspans] = out_fields;
    lens[nspans] = sizeof(*out_fields);
    nspans++;
    spans[nspans] = out_app;
    lens[nspans] = out_capacity;
    nspans++;
    spans[nspans] = out_len;
    lens[nspans] = sizeof(size_t);
    nspans++;
    st = ninlil_r7_wire_check_pairwise(spans, lens, nspans);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }

    ninlil_r7_wire_copy(aad14, blob, NINLIL_R7_WIRE_E2E_AAD_LEN);

    /* 6. nonce helper */
    cst = ninlil_r7_crypto_nonce_from_counter(
        static_iv12, fields_cand.e2e_counter, nonce12);
    st = ninlil_r7_wire_map_nonce(cst);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }

    /* 7–8. Open + produced shape */
    sealed_len = app_len + NINLIL_R7_WIRE_TAG_LEN;
    cst = ninlil_r7_crypto_aes128_gcm_open(
        provider,
        key16,
        nonce12,
        aad14,
        NINLIL_R7_WIRE_E2E_AAD_LEN,
        blob + NINLIL_R7_WIRE_E2E_AAD_LEN,
        sealed_len,
        app_cand,
        app_len,
        &produced);
    st = ninlil_r7_wire_map_crypto(cst, 1);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }
    if (produced != app_len) {
        st = NINLIL_R7_WIRE_INTERNAL_CONTRACT;
        goto done;
    }

    /* 9. atomic publish */
    *out_fields = fields_cand;
    ninlil_r7_wire_copy(out_app, app_cand, app_len);
    *out_len = app_len;
    st = NINLIL_R7_WIRE_OK;
done:
    ninlil_r7_wire_secure_zero(&fields_cand, sizeof(fields_cand));
    ninlil_r7_wire_secure_zero(aad14, sizeof(aad14));
    ninlil_r7_wire_secure_zero(nonce12, sizeof(nonce12));
    ninlil_r7_wire_secure_zero(app_cand, sizeof(app_cand));
    {
        volatile size_t *vp = (volatile size_t *)&produced;
        *vp = 0u;
    }
    return st;
}

/* -------------------------------------------------------------------------- */
/* Outer DATA/SINGLE Seal / Open                                              */
/* -------------------------------------------------------------------------- */

ninlil_r7_wire_status ninlil_r7_wire_seal_outer_single(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16],
    const uint8_t static_iv12[12],
    const ninlil_r7_wire_outer_data_fields *fields,
    const uint8_t *e2e_blob,
    size_t e2e_blob_len,
    uint8_t *out_frame,
    size_t out_capacity,
    size_t *out_len)
{
    uint8_t aad19[NINLIL_R7_WIRE_OUTER_AAD_LEN] = {0};
    uint8_t nonce12[NINLIL_R7_CRYPTO_AES128_NONCE_LEN] = {0};
    uint8_t sealed[NINLIL_R7_WIRE_E2E_BLOB_MAX + NINLIL_R7_WIRE_TAG_LEN] = {0};
    uint8_t frame_cand[NINLIL_R7_WIRE_FRAME_MAX] = {0};
    size_t sealed_need = 0u;
    size_t frame_need = 0u;
    size_t sealed_len = 0u;
    ninlil_r7_crypto_status cst;
    ninlil_r7_wire_status st = NINLIL_R7_WIRE_OK;
    const void *spans[7];
    size_t lens[7];
    size_t nspans;

    /* 1. provider exact shape + required pointer shape (docs/32 §5.4) */
    if (ninlil_r7_crypto_provider_validate(provider) != NINLIL_R7_CRYPTO_OK) {
        st = NINLIL_R7_WIRE_INVALID_ARGUMENT;
        goto done;
    }
    if (key16 == NULL || static_iv12 == NULL || fields == NULL || e2e_blob == NULL
        || out_frame == NULL || out_len == NULL) {
        st = NINLIL_R7_WIRE_INVALID_ARGUMENT;
        goto done;
    }

    /* 2. outer field domain */
    st = ninlil_r7_wire_validate_outer_fields(fields);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }

    /* 3. E2E blob length 31..220 (before structural / capacity / alias) */
    if (e2e_blob_len < NINLIL_R7_WIRE_E2E_BLOB_MIN
        || e2e_blob_len > NINLIL_R7_WIRE_E2E_BLOB_MAX) {
        st = NINLIL_R7_WIRE_LENGTH_CLASS;
        goto done;
    }

    /* 4. visible SINGLE E2E structural guard (not tag authenticity) */
    st = ninlil_r7_wire_structural_e2e_blob(e2e_blob, e2e_blob_len);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }

    /* 5. capacity exact 35+blob_len */
    if (e2e_blob_len
        > (SIZE_MAX - (NINLIL_R7_WIRE_OUTER_AAD_LEN + NINLIL_R7_WIRE_TAG_LEN))) {
        st = NINLIL_R7_WIRE_LENGTH_CLASS;
        goto done;
    }
    frame_need =
        NINLIL_R7_WIRE_OUTER_AAD_LEN + e2e_blob_len + NINLIL_R7_WIRE_TAG_LEN;
    if (frame_need < NINLIL_R7_WIRE_FRAME_MIN
        || frame_need > NINLIL_R7_WIRE_FRAME_MAX) {
        st = NINLIL_R7_WIRE_LENGTH_CLASS;
        goto done;
    }
    if (out_capacity != frame_need) {
        st = NINLIL_R7_WIRE_CAPACITY;
        goto done;
    }

    /* 6. alias */
    nspans = 0u;
    spans[nspans] = provider;
    lens[nspans] = sizeof(*provider);
    nspans++;
    spans[nspans] = key16;
    lens[nspans] = NINLIL_R7_CRYPTO_AES128_KEY_LEN;
    nspans++;
    spans[nspans] = static_iv12;
    lens[nspans] = NINLIL_R7_CRYPTO_AES128_NONCE_LEN;
    nspans++;
    spans[nspans] = fields;
    lens[nspans] = sizeof(*fields);
    nspans++;
    spans[nspans] = e2e_blob;
    lens[nspans] = e2e_blob_len;
    nspans++;
    spans[nspans] = out_frame;
    lens[nspans] = out_capacity;
    nspans++;
    spans[nspans] = out_len;
    lens[nspans] = sizeof(size_t);
    nspans++;
    st = ninlil_r7_wire_check_pairwise(spans, lens, nspans);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }

    /* 7. outer AAD + nonce (still provider callback 0) */
    st = ninlil_r7_wire_pack_outer_data_aad(
        fields, aad19, NINLIL_R7_WIRE_OUTER_AAD_LEN);
    if (st != NINLIL_R7_WIRE_OK) {
        st = NINLIL_R7_WIRE_INTERNAL_CONTRACT;
        goto done;
    }
    cst = ninlil_r7_crypto_nonce_from_counter(
        static_iv12, fields->hop_counter, nonce12);
    st = ninlil_r7_wire_map_nonce(cst);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }

    /* 8–9. Seal callback exact 1 + shape */
    sealed_need = e2e_blob_len + NINLIL_R7_WIRE_TAG_LEN;
    cst = ninlil_r7_crypto_aes128_gcm_seal(
        provider,
        key16,
        nonce12,
        aad19,
        NINLIL_R7_WIRE_OUTER_AAD_LEN,
        e2e_blob,
        e2e_blob_len,
        sealed,
        sealed_need,
        &sealed_len);
    st = ninlil_r7_wire_map_crypto(cst, 0);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }
    if (sealed_len != sealed_need) {
        st = NINLIL_R7_WIRE_INTERNAL_CONTRACT;
        goto done;
    }

    /* 10. AAD19||CT||TAG16 publish */
    ninlil_r7_wire_copy(frame_cand, aad19, NINLIL_R7_WIRE_OUTER_AAD_LEN);
    ninlil_r7_wire_copy(
        frame_cand + NINLIL_R7_WIRE_OUTER_AAD_LEN, sealed, sealed_need);
    if (frame_need != (NINLIL_R7_WIRE_OUTER_AAD_LEN + sealed_need)) {
        st = NINLIL_R7_WIRE_INTERNAL_CONTRACT;
        goto done;
    }
    ninlil_r7_wire_copy(out_frame, frame_cand, frame_need);
    *out_len = frame_need;
    st = NINLIL_R7_WIRE_OK;
done:
    ninlil_r7_wire_secure_zero(aad19, sizeof(aad19));
    ninlil_r7_wire_secure_zero(nonce12, sizeof(nonce12));
    ninlil_r7_wire_secure_zero(sealed, sizeof(sealed));
    ninlil_r7_wire_secure_zero(frame_cand, sizeof(frame_cand));
    {
        volatile size_t *vp = (volatile size_t *)&sealed_len;
        *vp = 0u;
    }
    return st;
}

ninlil_r7_wire_status ninlil_r7_wire_open_outer_single(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16],
    const uint8_t static_iv12[12],
    const uint8_t *frame,
    size_t frame_len,
    ninlil_r7_wire_outer_data_fields *out_fields,
    uint8_t *out_e2e_blob,
    size_t out_capacity,
    size_t *out_len)
{
    ninlil_r7_wire_outer_data_fields fields_cand = {0};
    uint8_t aad19[NINLIL_R7_WIRE_OUTER_AAD_LEN] = {0};
    uint8_t nonce12[NINLIL_R7_CRYPTO_AES128_NONCE_LEN] = {0};
    uint8_t blob_cand[NINLIL_R7_WIRE_E2E_BLOB_MAX] = {0};
    size_t blob_len = 0u;
    size_t sealed_len = 0u;
    size_t produced = 0u;
    ninlil_r7_crypto_status cst;
    ninlil_r7_wire_status st = NINLIL_R7_WIRE_OK;
    const void *spans[7];
    size_t lens[7];
    size_t nspans;

    if (ninlil_r7_crypto_provider_validate(provider) != NINLIL_R7_CRYPTO_OK) {
        st = NINLIL_R7_WIRE_INVALID_ARGUMENT;
        goto done;
    }
    if (key16 == NULL || static_iv12 == NULL || frame == NULL
        || out_fields == NULL || out_e2e_blob == NULL || out_len == NULL) {
        st = NINLIL_R7_WIRE_INVALID_ARGUMENT;
        goto done;
    }

    /* 2. packet length 66..255; blob_len = frame_len - 35 */
    if (frame_len < NINLIL_R7_WIRE_FRAME_MIN
        || frame_len > NINLIL_R7_WIRE_FRAME_MAX) {
        st = NINLIL_R7_WIRE_LENGTH_CLASS;
        goto done;
    }
    if (frame_len
        < (NINLIL_R7_WIRE_OUTER_AAD_LEN + NINLIL_R7_WIRE_TAG_LEN
           + NINLIL_R7_WIRE_E2E_BLOB_MIN)) {
        st = NINLIL_R7_WIRE_LENGTH_CLASS;
        goto done;
    }
    blob_len =
        frame_len - (NINLIL_R7_WIRE_OUTER_AAD_LEN + NINLIL_R7_WIRE_TAG_LEN);
    if (blob_len < NINLIL_R7_WIRE_E2E_BLOB_MIN
        || blob_len > NINLIL_R7_WIRE_E2E_BLOB_MAX) {
        st = NINLIL_R7_WIRE_LENGTH_CLASS;
        goto done;
    }

    /* 3. visible outer AAD structural */
    st = ninlil_r7_wire_parse_outer_data_aad(
        frame, NINLIL_R7_WIRE_OUTER_AAD_LEN, &fields_cand);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }

    /* 4. capacity */
    if (out_capacity != blob_len) {
        st = NINLIL_R7_WIRE_CAPACITY;
        goto done;
    }

    /* 5. alias */
    nspans = 0u;
    spans[nspans] = provider;
    lens[nspans] = sizeof(*provider);
    nspans++;
    spans[nspans] = key16;
    lens[nspans] = NINLIL_R7_CRYPTO_AES128_KEY_LEN;
    nspans++;
    spans[nspans] = static_iv12;
    lens[nspans] = NINLIL_R7_CRYPTO_AES128_NONCE_LEN;
    nspans++;
    spans[nspans] = frame;
    lens[nspans] = frame_len;
    nspans++;
    spans[nspans] = out_fields;
    lens[nspans] = sizeof(*out_fields);
    nspans++;
    spans[nspans] = out_e2e_blob;
    lens[nspans] = out_capacity;
    nspans++;
    spans[nspans] = out_len;
    lens[nspans] = sizeof(size_t);
    nspans++;
    st = ninlil_r7_wire_check_pairwise(spans, lens, nspans);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }

    ninlil_r7_wire_copy(aad19, frame, NINLIL_R7_WIRE_OUTER_AAD_LEN);

    /* 6. nonce helper */
    cst = ninlil_r7_crypto_nonce_from_counter(
        static_iv12, fields_cand.hop_counter, nonce12);
    st = ninlil_r7_wire_map_nonce(cst);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }

    /* 7–8. Open + shape */
    sealed_len = blob_len + NINLIL_R7_WIRE_TAG_LEN;
    cst = ninlil_r7_crypto_aes128_gcm_open(
        provider,
        key16,
        nonce12,
        aad19,
        NINLIL_R7_WIRE_OUTER_AAD_LEN,
        frame + NINLIL_R7_WIRE_OUTER_AAD_LEN,
        sealed_len,
        blob_cand,
        blob_len,
        &produced);
    st = ninlil_r7_wire_map_crypto(cst, 1);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }
    if (produced != blob_len) {
        st = NINLIL_R7_WIRE_INTERNAL_CONTRACT;
        goto done;
    }

    /* 9. outer-authenticated E2E structural (callback already 1) */
    st = ninlil_r7_wire_structural_e2e_blob(blob_cand, blob_len);
    if (st != NINLIL_R7_WIRE_OK) {
        goto done;
    }

    /* 10. atomic publish */
    *out_fields = fields_cand;
    ninlil_r7_wire_copy(out_e2e_blob, blob_cand, blob_len);
    *out_len = blob_len;
    st = NINLIL_R7_WIRE_OK;
done:
    ninlil_r7_wire_secure_zero(&fields_cand, sizeof(fields_cand));
    ninlil_r7_wire_secure_zero(aad19, sizeof(aad19));
    ninlil_r7_wire_secure_zero(nonce12, sizeof(nonce12));
    ninlil_r7_wire_secure_zero(blob_cand, sizeof(blob_cand));
    {
        volatile size_t *vp = (volatile size_t *)&produced;
        *vp = 0u;
    }
    return st;
}
