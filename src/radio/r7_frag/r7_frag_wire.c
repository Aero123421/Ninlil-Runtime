/* SPDX-License-Identifier: Apache-2.0 */
/*
 * R7 private NRW1 FRAG/LINK wire materialization.
 * AEAD/nonce/SHA only via ninlil_r7_crypto_* (docs/31). No bypass.
 * Failure: caller mutation zero; no partial publish.
 */

#include "r7_frag_internal.h"

/* E2E sealed blob domains (docs/30 §1.1.1.2 / §12). */
#define FRAG_START_BLOB_MIN ((size_t)95u)
#define FRAG_START_BLOB_MAX ((size_t)220u)
#define FRAG_CONT_BLOB_MIN ((size_t)41u)
#define FRAG_CONT_BLOB_MAX ((size_t)220u)
#define FRAG_ACK_BLOB_EXACT ((size_t)44u)
#define FRAG_OUTER_MAX ((size_t)255u)

/* -------------------------------------------------------------------------- */
/* Plan                                                                       */
/* -------------------------------------------------------------------------- */

ninlil_r7_frag_status ninlil_r7_frag_plan_validate(
    uint32_t total_len,
    uint16_t first_chunk_len,
    uint16_t frag_count,
    uint16_t continuation_unit)
{
    uint32_t rem;
    uint16_t expected;
    uint32_t ceil_div;

    if (continuation_unit != NINLIL_R7_FRAG_CONT_UNIT) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (first_chunk_len < NINLIL_R7_FRAG_S_MIN
        || first_chunk_len > NINLIL_R7_FRAG_S_MAX) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    if (total_len <= (uint32_t)first_chunk_len
        || total_len > NINLIL_R7_FRAG_TOTAL_LEN_MAX) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    if (frag_count < NINLIL_R7_FRAG_COUNT_MIN
        || frag_count > NINLIL_R7_FRAG_COUNT_MAX) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    rem = total_len - (uint32_t)first_chunk_len;
    ceil_div = (rem + (uint32_t)NINLIL_R7_FRAG_CONT_UNIT - 1u)
        / (uint32_t)NINLIL_R7_FRAG_CONT_UNIT;
    expected = (uint16_t)(1u + ceil_div);
    if (frag_count != expected) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    return NINLIL_R7_FRAG_OK;
}

ninlil_r7_frag_status ninlil_r7_frag_plan_build(
    uint32_t total_len,
    ninlil_r7_frag_plan *out_plan)
{
    ninlil_r7_frag_plan cand;
    uint16_t s;
    uint32_t rem;
    uint32_t ceil_div;
    uint16_t fc;
    uint16_t i;
    uint32_t off;
    ninlil_r7_frag_status st;

    if (out_plan == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (total_len < 2u || total_len > NINLIL_R7_FRAG_TOTAL_LEN_MAX) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }

    memset(&cand, 0, sizeof(cand));
    /* Maximal first chunk under S < total_len and S <= 126. */
    if (total_len - 1u < (uint32_t)NINLIL_R7_FRAG_S_MAX) {
        s = (uint16_t)(total_len - 1u);
    } else {
        s = NINLIL_R7_FRAG_S_MAX;
    }
    if (s < NINLIL_R7_FRAG_S_MIN) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }

    rem = total_len - (uint32_t)s;
    ceil_div = (rem + (uint32_t)NINLIL_R7_FRAG_CONT_UNIT - 1u)
        / (uint32_t)NINLIL_R7_FRAG_CONT_UNIT;
    fc = (uint16_t)(1u + ceil_div);
    st = ninlil_r7_frag_plan_validate(
        total_len, s, fc, NINLIL_R7_FRAG_CONT_UNIT);
    if (st != NINLIL_R7_FRAG_OK) {
        return st;
    }

    cand.total_len = total_len;
    cand.frag_count = fc;
    cand.first_chunk_len = s;
    cand.cont_unit = NINLIL_R7_FRAG_CONT_UNIT;
    cand.chunks[0].frag_index = 0u;
    cand.chunks[0].offset = 0u;
    cand.chunks[0].length = s;

    off = s;
    for (i = 1u; i < fc; i++) {
        uint32_t left = total_len - off;
        uint16_t clen = (left > (uint32_t)NINLIL_R7_FRAG_CONT_UNIT)
            ? NINLIL_R7_FRAG_CONT_UNIT
            : (uint16_t)left;
        if (i + 1u < fc && clen != NINLIL_R7_FRAG_CONT_UNIT) {
            return NINLIL_R7_FRAG_INTERNAL_CONTRACT;
        }
        if (clen < NINLIL_R7_FRAG_C_MIN || clen > NINLIL_R7_FRAG_C_MAX) {
            return NINLIL_R7_FRAG_LENGTH_CLASS;
        }
        cand.chunks[i].frag_index = i;
        cand.chunks[i].offset = (uint16_t)off;
        cand.chunks[i].length = clen;
        off = (uint32_t)((uint16_t)off + clen);
    }
    if (off != total_len) {
        return NINLIL_R7_FRAG_INTERNAL_CONTRACT;
    }

    *out_plan = cand;
    ninlil_r7_frag_secure_zero(&cand, sizeof(cand));
    return NINLIL_R7_FRAG_OK;
}

/* -------------------------------------------------------------------------- */
/* LINK_ACK body                                                              */
/* -------------------------------------------------------------------------- */

ninlil_r7_frag_status ninlil_r7_frag_link_ack_body_validate(
    const ninlil_r7_frag_link_ack_body *body)
{
    uint16_t i;

    if (body == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (!ninlil_r7_frag_context_ok(body->acked_hop_context_id)) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (!ninlil_r7_frag_counter_ok(body->ack_base_counter)) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (body->ack_code != NINLIL_R7_FRAG_ACK_CODE_ACCEPTED_BATCH) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    /* bit0 MUST be 1 */
    if ((body->ack_bitmap & 0x0001u) == 0u) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    for (i = 0u; i < 16u; i++) {
        if (i >= body->ack_base_counter) {
            if ((body->ack_bitmap & (uint16_t)(1u << i)) != 0u) {
                return NINLIL_R7_FRAG_STRUCTURAL;
            }
        }
    }
    return NINLIL_R7_FRAG_OK;
}

ninlil_r7_frag_status ninlil_r7_frag_pack_link_ack_body(
    const ninlil_r7_frag_link_ack_body *body,
    uint8_t out16[NINLIL_R7_FRAG_LINK_ACK_PT_LEN])
{
    uint8_t cand[NINLIL_R7_FRAG_LINK_ACK_PT_LEN];
    ninlil_r7_frag_status st;

    if (body == NULL || out16 == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    st = ninlil_r7_frag_link_ack_body_validate(body);
    if (st != NINLIL_R7_FRAG_OK) {
        return st;
    }
    if (ninlil_r7_frag_spans_forbidden(
            body, sizeof(*body), out16, NINLIL_R7_FRAG_LINK_ACK_PT_LEN)) {
        return NINLIL_R7_FRAG_ALIAS;
    }
    memset(cand, 0, sizeof(cand));
    ninlil_r7_frag_store_u32_be(cand + 0, body->acked_hop_context_id);
    ninlil_r7_frag_store_u64_be(cand + 4, body->ack_base_counter);
    ninlil_r7_frag_store_u16_be(cand + 12, body->ack_bitmap);
    cand[14] = body->ack_code;
    cand[15] = 0u;
    ninlil_r7_frag_copy(out16, cand, NINLIL_R7_FRAG_LINK_ACK_PT_LEN);
    ninlil_r7_frag_secure_zero(cand, sizeof(cand));
    return NINLIL_R7_FRAG_OK;
}

ninlil_r7_frag_status ninlil_r7_frag_parse_link_ack_body(
    const uint8_t in16[NINLIL_R7_FRAG_LINK_ACK_PT_LEN],
    ninlil_r7_frag_link_ack_body *out_body)
{
    ninlil_r7_frag_link_ack_body cand;
    ninlil_r7_frag_status st;

    if (in16 == NULL || out_body == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (ninlil_r7_frag_spans_forbidden(
            in16, NINLIL_R7_FRAG_LINK_ACK_PT_LEN, out_body, sizeof(*out_body))) {
        return NINLIL_R7_FRAG_ALIAS;
    }
    memset(&cand, 0, sizeof(cand));
    cand.acked_hop_context_id = ninlil_r7_frag_load_u32_be(in16 + 0);
    cand.ack_base_counter = ninlil_r7_frag_load_u64_be(in16 + 4);
    cand.ack_bitmap = ninlil_r7_frag_load_u16_be(in16 + 12);
    cand.ack_code = in16[14];
    if (in16[15] != 0u) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    st = ninlil_r7_frag_link_ack_body_validate(&cand);
    if (st != NINLIL_R7_FRAG_OK) {
        ninlil_r7_frag_secure_zero(&cand, sizeof(cand));
        return st;
    }
    *out_body = cand;
    ninlil_r7_frag_secure_zero(&cand, sizeof(cand));
    return NINLIL_R7_FRAG_OK;
}

/* -------------------------------------------------------------------------- */
/* PT pack/parse START/CONT/ACK                                               */
/* -------------------------------------------------------------------------- */

ninlil_r7_frag_status ninlil_r7_frag_pack_start_pt(
    const ninlil_r7_frag_start_body *body,
    const uint8_t *first_chunk,
    size_t first_chunk_len,
    uint8_t *out_pt,
    size_t out_capacity,
    size_t *out_len)
{
    size_t need;
    ninlil_r7_frag_status st;

    if (body == NULL || first_chunk == NULL || out_pt == NULL || out_len == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    st = ninlil_r7_frag_plan_validate(
        body->total_len,
        (uint16_t)first_chunk_len,
        body->frag_count,
        body->continuation_unit);
    if (st != NINLIL_R7_FRAG_OK) {
        return st;
    }
    if (!ninlil_r7_frag_handle_ok(body->transfer_handle)) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (first_chunk_len != (size_t)body->total_len
        && first_chunk_len != (size_t)((uint16_t)first_chunk_len)) {
        /* always true path for domain already checked */
    }
    need = NINLIL_R7_FRAG_START_HDR_LEN + first_chunk_len;
    if (out_capacity < need) {
        return NINLIL_R7_FRAG_CAPACITY;
    }
    if (ninlil_r7_frag_spans_forbidden(
            first_chunk, first_chunk_len, out_pt, out_capacity)
        || ninlil_r7_frag_spans_forbidden(
            body, sizeof(*body), out_pt, out_capacity)) {
        return NINLIL_R7_FRAG_ALIAS;
    }

    ninlil_r7_frag_copy(out_pt + 0, body->transfer_id, 16u);
    ninlil_r7_frag_store_u64_be(out_pt + 16, body->transfer_handle);
    ninlil_r7_frag_store_u32_be(out_pt + 24, body->total_len);
    ninlil_r7_frag_store_u16_be(out_pt + 28, body->frag_count);
    ninlil_r7_frag_store_u16_be(out_pt + 30, body->continuation_unit);
    ninlil_r7_frag_copy(out_pt + 32, body->content_digest, 32u);
    ninlil_r7_frag_copy(out_pt + 64, first_chunk, first_chunk_len);
    *out_len = need;
    return NINLIL_R7_FRAG_OK;
}

ninlil_r7_frag_status ninlil_r7_frag_parse_start_pt(
    const uint8_t *pt,
    size_t pt_len,
    ninlil_r7_frag_start_body *out_body,
    const uint8_t **out_chunk,
    size_t *out_chunk_len)
{
    ninlil_r7_frag_start_body cand;
    size_t s;
    ninlil_r7_frag_status st;

    if (pt == NULL || out_body == NULL || out_chunk == NULL
        || out_chunk_len == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (pt_len < NINLIL_R7_FRAG_START_HDR_LEN + NINLIL_R7_FRAG_S_MIN) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    s = pt_len - NINLIL_R7_FRAG_START_HDR_LEN;
    if (s < NINLIL_R7_FRAG_S_MIN || s > NINLIL_R7_FRAG_S_MAX) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    memset(&cand, 0, sizeof(cand));
    ninlil_r7_frag_copy(cand.transfer_id, pt + 0, 16u);
    cand.transfer_handle = ninlil_r7_frag_load_u64_be(pt + 16);
    cand.total_len = ninlil_r7_frag_load_u32_be(pt + 24);
    cand.frag_count = ninlil_r7_frag_load_u16_be(pt + 28);
    cand.continuation_unit = ninlil_r7_frag_load_u16_be(pt + 30);
    ninlil_r7_frag_copy(cand.content_digest, pt + 32, 32u);
    if (!ninlil_r7_frag_handle_ok(cand.transfer_handle)) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    st = ninlil_r7_frag_plan_validate(
        cand.total_len, (uint16_t)s, cand.frag_count, cand.continuation_unit);
    if (st != NINLIL_R7_FRAG_OK) {
        ninlil_r7_frag_secure_zero(&cand, sizeof(cand));
        return st;
    }
    *out_body = cand;
    *out_chunk = pt + 64;
    *out_chunk_len = s;
    ninlil_r7_frag_secure_zero(&cand, sizeof(cand));
    return NINLIL_R7_FRAG_OK;
}

ninlil_r7_frag_status ninlil_r7_frag_pack_cont_pt(
    const ninlil_r7_frag_cont_body *body,
    const uint8_t *chunk,
    size_t chunk_len,
    uint8_t *out_pt,
    size_t out_capacity,
    size_t *out_len)
{
    size_t need;

    if (body == NULL || chunk == NULL || out_pt == NULL || out_len == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (!ninlil_r7_frag_handle_ok(body->transfer_handle)) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (body->frag_index < 1u
        || body->frag_index >= NINLIL_R7_FRAG_COUNT_MAX) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (chunk_len < NINLIL_R7_FRAG_C_MIN || chunk_len > NINLIL_R7_FRAG_C_MAX) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    need = NINLIL_R7_FRAG_CONT_HDR_LEN + chunk_len;
    if (out_capacity < need) {
        return NINLIL_R7_FRAG_CAPACITY;
    }
    if (ninlil_r7_frag_spans_forbidden(chunk, chunk_len, out_pt, out_capacity)) {
        return NINLIL_R7_FRAG_ALIAS;
    }
    ninlil_r7_frag_store_u64_be(out_pt + 0, body->transfer_handle);
    ninlil_r7_frag_store_u16_be(out_pt + 8, body->frag_index);
    ninlil_r7_frag_copy(out_pt + 10, chunk, chunk_len);
    *out_len = need;
    return NINLIL_R7_FRAG_OK;
}

ninlil_r7_frag_status ninlil_r7_frag_parse_cont_pt(
    const uint8_t *pt,
    size_t pt_len,
    ninlil_r7_frag_cont_body *out_body,
    const uint8_t **out_chunk,
    size_t *out_chunk_len)
{
    ninlil_r7_frag_cont_body cand;
    size_t c;

    if (pt == NULL || out_body == NULL || out_chunk == NULL
        || out_chunk_len == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (pt_len < NINLIL_R7_FRAG_CONT_HDR_LEN + NINLIL_R7_FRAG_C_MIN) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    c = pt_len - NINLIL_R7_FRAG_CONT_HDR_LEN;
    if (c < NINLIL_R7_FRAG_C_MIN || c > NINLIL_R7_FRAG_C_MAX) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    memset(&cand, 0, sizeof(cand));
    cand.transfer_handle = ninlil_r7_frag_load_u64_be(pt + 0);
    cand.frag_index = ninlil_r7_frag_load_u16_be(pt + 8);
    if (!ninlil_r7_frag_handle_ok(cand.transfer_handle)) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (cand.frag_index < 1u) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    *out_body = cand;
    *out_chunk = pt + 10;
    *out_chunk_len = c;
    ninlil_r7_frag_secure_zero(&cand, sizeof(cand));
    return NINLIL_R7_FRAG_OK;
}

ninlil_r7_frag_status ninlil_r7_frag_pack_ack_pt(
    const ninlil_r7_frag_ack_body *body,
    uint8_t out14[NINLIL_R7_FRAG_ACK_PT_LEN])
{
    if (body == NULL || out14 == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (!ninlil_r7_frag_handle_ok(body->transfer_handle)) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (body->frag_count < NINLIL_R7_FRAG_COUNT_MIN
        || body->frag_count > NINLIL_R7_FRAG_COUNT_MAX) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    /* high bits beyond frag_count must be 0 */
    if ((body->received_bitmap
            & (uint16_t)~((uint16_t)((1u << body->frag_count) - 1u)))
        != 0u) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (body->status == NINLIL_R7_FRAG_STATUS_PARTIAL) {
        if (body->reason != NINLIL_R7_FRAG_REASON_NONE) {
            return NINLIL_R7_FRAG_STRUCTURAL;
        }
        if ((body->received_bitmap & 0x0001u) == 0u) {
            return NINLIL_R7_FRAG_STRUCTURAL;
        }
        if (body->received_bitmap
            == ninlil_r7_frag_full_bitmap(body->frag_count)) {
            return NINLIL_R7_FRAG_STRUCTURAL;
        }
    } else if (body->status == NINLIL_R7_FRAG_STATUS_COMPLETE) {
        if (body->reason != NINLIL_R7_FRAG_REASON_NONE) {
            return NINLIL_R7_FRAG_STRUCTURAL;
        }
        if (body->received_bitmap
            != ninlil_r7_frag_full_bitmap(body->frag_count)) {
            return NINLIL_R7_FRAG_STRUCTURAL;
        }
    } else if (body->status == NINLIL_R7_FRAG_STATUS_ABORT) {
        if (body->reason < NINLIL_R7_FRAG_REASON_CONFLICT
            || body->reason > NINLIL_R7_FRAG_REASON_FENCED) {
            return NINLIL_R7_FRAG_STRUCTURAL;
        }
        if (body->received_bitmap != 0u) {
            return NINLIL_R7_FRAG_STRUCTURAL;
        }
    } else {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }

    ninlil_r7_frag_store_u64_be(out14 + 0, body->transfer_handle);
    ninlil_r7_frag_store_u16_be(out14 + 8, body->frag_count);
    ninlil_r7_frag_store_u16_be(out14 + 10, body->received_bitmap);
    out14[12] = body->status;
    out14[13] = body->reason;
    return NINLIL_R7_FRAG_OK;
}

ninlil_r7_frag_status ninlil_r7_frag_parse_ack_pt(
    const uint8_t in14[NINLIL_R7_FRAG_ACK_PT_LEN],
    ninlil_r7_frag_ack_body *out_body)
{
    ninlil_r7_frag_ack_body cand;
    uint8_t tmp[NINLIL_R7_FRAG_ACK_PT_LEN];
    ninlil_r7_frag_status st;

    if (in14 == NULL || out_body == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    memset(&cand, 0, sizeof(cand));
    cand.transfer_handle = ninlil_r7_frag_load_u64_be(in14 + 0);
    cand.frag_count = ninlil_r7_frag_load_u16_be(in14 + 8);
    cand.received_bitmap = ninlil_r7_frag_load_u16_be(in14 + 10);
    cand.status = in14[12];
    cand.reason = in14[13];
    st = ninlil_r7_frag_pack_ack_pt(&cand, tmp); /* re-validate via pack rules */
    ninlil_r7_frag_secure_zero(tmp, sizeof(tmp));
    if (st != NINLIL_R7_FRAG_OK) {
        ninlil_r7_frag_secure_zero(&cand, sizeof(cand));
        return st;
    }
    *out_body = cand;
    ninlil_r7_frag_secure_zero(&cand, sizeof(cand));
    return NINLIL_R7_FRAG_OK;
}

/* -------------------------------------------------------------------------- */
/* Common E2E seal/open                                                       */
/* -------------------------------------------------------------------------- */

ninlil_r7_frag_status ninlil_r7_frag_seal_e2e_common(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16],
    const uint8_t static_iv12[12],
    uint8_t e2e_type,
    uint32_t e2e_context_id,
    uint64_t e2e_counter,
    const uint8_t *pt,
    size_t pt_len,
    size_t blob_min,
    size_t blob_max,
    uint8_t *out_blob,
    size_t out_capacity,
    size_t *out_len)
{
    uint8_t aad14[NINLIL_R7_FRAG_E2E_AAD_LEN];
    uint8_t nonce12[12];
    uint8_t sealed[220u + 16u];
    uint8_t blob_cand[220u];
    size_t sealed_need;
    size_t blob_need;
    size_t sealed_len = 0u;
    ninlil_r7_crypto_status cst;
    ninlil_r7_frag_status st = NINLIL_R7_FRAG_OK;
    const void *spans[6];
    size_t lens[6];
    size_t nspans = 0u;

    if (ninlil_r7_crypto_provider_validate(provider) != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (key16 == NULL || static_iv12 == NULL || pt == NULL || out_blob == NULL
        || out_len == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (!ninlil_r7_frag_context_ok(e2e_context_id)
        || !ninlil_r7_frag_counter_ok(e2e_counter)) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (e2e_type < NINLIL_R7_FRAG_E2E_TYPE_START
        || e2e_type > NINLIL_R7_FRAG_E2E_TYPE_ACK) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (pt_len > 190u) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    blob_need = NINLIL_R7_FRAG_E2E_AAD_LEN + pt_len + NINLIL_R7_FRAG_TAG_LEN;
    if (blob_need < blob_min || blob_need > blob_max) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    if (out_capacity != blob_need) {
        return NINLIL_R7_FRAG_CAPACITY;
    }
    sealed_need = pt_len + NINLIL_R7_FRAG_TAG_LEN;

    spans[nspans] = key16;
    lens[nspans] = 16u;
    nspans++;
    spans[nspans] = static_iv12;
    lens[nspans] = 12u;
    nspans++;
    spans[nspans] = pt;
    lens[nspans] = pt_len;
    nspans++;
    spans[nspans] = out_blob;
    lens[nspans] = out_capacity;
    nspans++;
    st = ninlil_r7_frag_check_pairwise(spans, lens, nspans);
    if (st != NINLIL_R7_FRAG_OK) {
        return st;
    }

    memset(aad14, 0, sizeof(aad14));
    aad14[0] = NINLIL_R7_FRAG_PROFILE_ID;
    aad14[1] = (uint8_t)(e2e_type << 4);
    ninlil_r7_frag_store_u32_be(aad14 + 2, e2e_context_id);
    ninlil_r7_frag_store_u64_be(aad14 + 6, e2e_counter);

    cst = ninlil_r7_crypto_nonce_from_counter(static_iv12, e2e_counter, nonce12);
    st = ninlil_r7_frag_map_crypto(cst, 0);
    if (st != NINLIL_R7_FRAG_OK) {
        goto done;
    }
    cst = ninlil_r7_crypto_aes128_gcm_seal(
        provider, key16, nonce12, aad14, NINLIL_R7_FRAG_E2E_AAD_LEN, pt, pt_len,
        sealed, sealed_need, &sealed_len);
    st = ninlil_r7_frag_map_crypto(cst, 0);
    if (st != NINLIL_R7_FRAG_OK || sealed_len != sealed_need) {
        if (st == NINLIL_R7_FRAG_OK) {
            st = NINLIL_R7_FRAG_INTERNAL_CONTRACT;
        }
        goto done;
    }
    memset(blob_cand, 0, sizeof(blob_cand));
    ninlil_r7_frag_copy(blob_cand, aad14, NINLIL_R7_FRAG_E2E_AAD_LEN);
    ninlil_r7_frag_copy(blob_cand + NINLIL_R7_FRAG_E2E_AAD_LEN, sealed, sealed_len);
    ninlil_r7_frag_copy(out_blob, blob_cand, blob_need);
    *out_len = blob_need;
    st = NINLIL_R7_FRAG_OK;
done:
    ninlil_r7_frag_secure_zero(aad14, sizeof(aad14));
    ninlil_r7_frag_secure_zero(nonce12, sizeof(nonce12));
    ninlil_r7_frag_secure_zero(sealed, sizeof(sealed));
    ninlil_r7_frag_secure_zero(blob_cand, sizeof(blob_cand));
    return st;
}

ninlil_r7_frag_status ninlil_r7_frag_open_e2e_common(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16],
    const uint8_t static_iv12[12],
    uint8_t expect_type,
    const uint8_t *blob,
    size_t blob_len,
    size_t blob_min,
    size_t blob_max,
    ninlil_r7_frag_e2e_fields *out_fields,
    uint8_t *out_pt,
    size_t out_capacity,
    size_t *out_pt_len)
{
    uint8_t aad14[NINLIL_R7_FRAG_E2E_AAD_LEN];
    uint8_t nonce12[12];
    uint8_t pt_cand[190u];
    size_t pt_len;
    size_t sealed_len;
    size_t produced = 0u;
    uint8_t type_flags;
    uint32_t ctx;
    uint64_t ctr;
    ninlil_r7_crypto_status cst;
    ninlil_r7_frag_status st = NINLIL_R7_FRAG_OK;

    if (ninlil_r7_crypto_provider_validate(provider) != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (key16 == NULL || static_iv12 == NULL || blob == NULL || out_fields == NULL
        || out_pt == NULL || out_pt_len == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (blob_len < blob_min || blob_len > blob_max) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    if (blob_len < NINLIL_R7_FRAG_E2E_AAD_LEN + NINLIL_R7_FRAG_TAG_LEN) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    pt_len = blob_len - NINLIL_R7_FRAG_E2E_AAD_LEN - NINLIL_R7_FRAG_TAG_LEN;
    if (out_capacity != pt_len) {
        return NINLIL_R7_FRAG_CAPACITY;
    }
    if (blob[0] != NINLIL_R7_FRAG_PROFILE_ID) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    type_flags = blob[1];
    if ((type_flags & 0x0fu) != 0u) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if ((uint8_t)((type_flags >> 4) & 0x0fu) != expect_type) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    ctx = ninlil_r7_frag_load_u32_be(blob + 2);
    ctr = ninlil_r7_frag_load_u64_be(blob + 6);
    if (!ninlil_r7_frag_context_ok(ctx) || !ninlil_r7_frag_counter_ok(ctr)) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (ninlil_r7_frag_spans_forbidden(blob, blob_len, out_pt, out_capacity)
        || ninlil_r7_frag_spans_forbidden(
            blob, blob_len, out_fields, sizeof(*out_fields))) {
        return NINLIL_R7_FRAG_ALIAS;
    }

    ninlil_r7_frag_copy(aad14, blob, NINLIL_R7_FRAG_E2E_AAD_LEN);
    sealed_len = pt_len + NINLIL_R7_FRAG_TAG_LEN;
    cst = ninlil_r7_crypto_nonce_from_counter(static_iv12, ctr, nonce12);
    st = ninlil_r7_frag_map_crypto(cst, 0);
    if (st != NINLIL_R7_FRAG_OK) {
        goto done;
    }
    memset(pt_cand, 0, sizeof(pt_cand));
    cst = ninlil_r7_crypto_aes128_gcm_open(
        provider, key16, nonce12, aad14, NINLIL_R7_FRAG_E2E_AAD_LEN,
        blob + NINLIL_R7_FRAG_E2E_AAD_LEN, sealed_len, pt_cand, pt_len,
        &produced);
    st = ninlil_r7_frag_map_crypto(cst, 1);
    if (st != NINLIL_R7_FRAG_OK || produced != pt_len) {
        if (st == NINLIL_R7_FRAG_OK) {
            st = NINLIL_R7_FRAG_INTERNAL_CONTRACT;
        }
        goto done;
    }
    /* Publish only after verify. */
    out_fields->e2e_type = expect_type;
    out_fields->e2e_context_id = ctx;
    out_fields->e2e_counter = ctr;
    ninlil_r7_frag_copy(out_pt, pt_cand, pt_len);
    *out_pt_len = pt_len;
    st = NINLIL_R7_FRAG_OK;
done:
    ninlil_r7_frag_secure_zero(aad14, sizeof(aad14));
    ninlil_r7_frag_secure_zero(nonce12, sizeof(nonce12));
    ninlil_r7_frag_secure_zero(pt_cand, sizeof(pt_cand));
    return st;
}

/* -------------------------------------------------------------------------- */
/* Public FRAG E2E APIs                                                       */
/* -------------------------------------------------------------------------- */

ninlil_r7_frag_status ninlil_r7_frag_seal_e2e_start(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16],
    const uint8_t static_iv12[12],
    const ninlil_r7_frag_e2e_fields *fields,
    const ninlil_r7_frag_start_body *body,
    const uint8_t *first_chunk,
    size_t first_chunk_len,
    uint8_t *out_blob,
    size_t out_capacity,
    size_t *out_len)
{
    uint8_t pt[64u + 126u];
    size_t pt_len = 0u;
    ninlil_r7_frag_status st;

    if (fields == NULL || fields->e2e_type != NINLIL_R7_FRAG_E2E_TYPE_START) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    st = ninlil_r7_frag_pack_start_pt(
        body, first_chunk, first_chunk_len, pt, sizeof(pt), &pt_len);
    if (st != NINLIL_R7_FRAG_OK) {
        return st;
    }
    st = ninlil_r7_frag_seal_e2e_common(
        provider, key16, static_iv12, NINLIL_R7_FRAG_E2E_TYPE_START,
        fields->e2e_context_id, fields->e2e_counter, pt, pt_len,
        FRAG_START_BLOB_MIN, FRAG_START_BLOB_MAX, out_blob, out_capacity,
        out_len);
    ninlil_r7_frag_secure_zero(pt, sizeof(pt));
    return st;
}

ninlil_r7_frag_status ninlil_r7_frag_open_e2e_start(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16],
    const uint8_t static_iv12[12],
    const uint8_t *blob,
    size_t blob_len,
    ninlil_r7_frag_e2e_fields *out_fields,
    ninlil_r7_frag_start_body *out_body,
    uint8_t *out_first_chunk,
    size_t out_capacity,
    size_t *out_first_len)
{
    uint8_t pt[64u + 126u];
    size_t pt_len = 0u;
    size_t expect_pt;
    const uint8_t *chunk = NULL;
    size_t chunk_len = 0u;
    ninlil_r7_frag_status st;

    if (out_body == NULL || out_first_chunk == NULL || out_first_len == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (blob == NULL || blob_len < FRAG_START_BLOB_MIN) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    expect_pt = blob_len - NINLIL_R7_FRAG_E2E_AAD_LEN - NINLIL_R7_FRAG_TAG_LEN;
    if (expect_pt > sizeof(pt)) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    st = ninlil_r7_frag_open_e2e_common(
        provider, key16, static_iv12, NINLIL_R7_FRAG_E2E_TYPE_START, blob,
        blob_len, FRAG_START_BLOB_MIN, FRAG_START_BLOB_MAX, out_fields, pt,
        expect_pt, &pt_len);
    if (st != NINLIL_R7_FRAG_OK) {
        ninlil_r7_frag_secure_zero(pt, sizeof(pt));
        return st;
    }
    st = ninlil_r7_frag_parse_start_pt(pt, pt_len, out_body, &chunk, &chunk_len);
    if (st != NINLIL_R7_FRAG_OK) {
        ninlil_r7_frag_secure_zero(pt, sizeof(pt));
        return st;
    }
    if (out_capacity < chunk_len) {
        ninlil_r7_frag_secure_zero(pt, sizeof(pt));
        return NINLIL_R7_FRAG_CAPACITY;
    }
    ninlil_r7_frag_copy(out_first_chunk, chunk, chunk_len);
    *out_first_len = chunk_len;
    ninlil_r7_frag_secure_zero(pt, sizeof(pt));
    return NINLIL_R7_FRAG_OK;
}

ninlil_r7_frag_status ninlil_r7_frag_seal_e2e_cont(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16],
    const uint8_t static_iv12[12],
    const ninlil_r7_frag_e2e_fields *fields,
    const ninlil_r7_frag_cont_body *body,
    const uint8_t *chunk,
    size_t chunk_len,
    uint8_t *out_blob,
    size_t out_capacity,
    size_t *out_len)
{
    uint8_t pt[10u + 180u];
    size_t pt_len = 0u;
    ninlil_r7_frag_status st;

    if (fields == NULL || fields->e2e_type != NINLIL_R7_FRAG_E2E_TYPE_CONT) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    st = ninlil_r7_frag_pack_cont_pt(
        body, chunk, chunk_len, pt, sizeof(pt), &pt_len);
    if (st != NINLIL_R7_FRAG_OK) {
        return st;
    }
    st = ninlil_r7_frag_seal_e2e_common(
        provider, key16, static_iv12, NINLIL_R7_FRAG_E2E_TYPE_CONT,
        fields->e2e_context_id, fields->e2e_counter, pt, pt_len,
        FRAG_CONT_BLOB_MIN, FRAG_CONT_BLOB_MAX, out_blob, out_capacity,
        out_len);
    ninlil_r7_frag_secure_zero(pt, sizeof(pt));
    return st;
}

ninlil_r7_frag_status ninlil_r7_frag_open_e2e_cont(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16],
    const uint8_t static_iv12[12],
    const uint8_t *blob,
    size_t blob_len,
    ninlil_r7_frag_e2e_fields *out_fields,
    ninlil_r7_frag_cont_body *out_body,
    uint8_t *out_chunk,
    size_t out_capacity,
    size_t *out_chunk_len)
{
    uint8_t pt[10u + 180u];
    size_t pt_len = 0u;
    size_t expect_pt;
    const uint8_t *chunk = NULL;
    size_t chunk_len = 0u;
    ninlil_r7_frag_status st;

    if (out_body == NULL || out_chunk == NULL || out_chunk_len == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (blob == NULL || blob_len < FRAG_CONT_BLOB_MIN) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    expect_pt = blob_len - NINLIL_R7_FRAG_E2E_AAD_LEN - NINLIL_R7_FRAG_TAG_LEN;
    if (expect_pt > sizeof(pt)) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    st = ninlil_r7_frag_open_e2e_common(
        provider, key16, static_iv12, NINLIL_R7_FRAG_E2E_TYPE_CONT, blob,
        blob_len, FRAG_CONT_BLOB_MIN, FRAG_CONT_BLOB_MAX, out_fields, pt,
        expect_pt, &pt_len);
    if (st != NINLIL_R7_FRAG_OK) {
        ninlil_r7_frag_secure_zero(pt, sizeof(pt));
        return st;
    }
    st = ninlil_r7_frag_parse_cont_pt(pt, pt_len, out_body, &chunk, &chunk_len);
    if (st != NINLIL_R7_FRAG_OK) {
        ninlil_r7_frag_secure_zero(pt, sizeof(pt));
        return st;
    }
    if (out_capacity < chunk_len) {
        ninlil_r7_frag_secure_zero(pt, sizeof(pt));
        return NINLIL_R7_FRAG_CAPACITY;
    }
    ninlil_r7_frag_copy(out_chunk, chunk, chunk_len);
    *out_chunk_len = chunk_len;
    ninlil_r7_frag_secure_zero(pt, sizeof(pt));
    return NINLIL_R7_FRAG_OK;
}

ninlil_r7_frag_status ninlil_r7_frag_seal_e2e_ack(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16],
    const uint8_t static_iv12[12],
    const ninlil_r7_frag_e2e_fields *fields,
    const ninlil_r7_frag_ack_body *body,
    uint8_t *out_blob,
    size_t out_capacity,
    size_t *out_len)
{
    uint8_t pt[NINLIL_R7_FRAG_ACK_PT_LEN];
    ninlil_r7_frag_status st;

    if (fields == NULL || fields->e2e_type != NINLIL_R7_FRAG_E2E_TYPE_ACK) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (body == NULL || out_blob == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (ninlil_r7_frag_spans_forbidden(
            body, sizeof(*body), out_blob, out_capacity)) {
        return NINLIL_R7_FRAG_ALIAS;
    }
    st = ninlil_r7_frag_pack_ack_pt(body, pt);
    if (st != NINLIL_R7_FRAG_OK) {
        return st;
    }
    st = ninlil_r7_frag_seal_e2e_common(
        provider, key16, static_iv12, NINLIL_R7_FRAG_E2E_TYPE_ACK,
        fields->e2e_context_id, fields->e2e_counter, pt,
        NINLIL_R7_FRAG_ACK_PT_LEN, FRAG_ACK_BLOB_EXACT, FRAG_ACK_BLOB_EXACT,
        out_blob, out_capacity, out_len);
    ninlil_r7_frag_secure_zero(pt, sizeof(pt));
    return st;
}

ninlil_r7_frag_status ninlil_r7_frag_open_e2e_ack(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16],
    const uint8_t static_iv12[12],
    const uint8_t *blob,
    size_t blob_len,
    ninlil_r7_frag_e2e_fields *out_fields,
    ninlil_r7_frag_ack_body *out_body)
{
    uint8_t pt[NINLIL_R7_FRAG_ACK_PT_LEN];
    size_t pt_len = 0u;
    ninlil_r7_frag_status st;

    if (out_body == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    st = ninlil_r7_frag_open_e2e_common(
        provider, key16, static_iv12, NINLIL_R7_FRAG_E2E_TYPE_ACK, blob,
        blob_len, FRAG_ACK_BLOB_EXACT, FRAG_ACK_BLOB_EXACT, out_fields, pt,
        NINLIL_R7_FRAG_ACK_PT_LEN, &pt_len);
    if (st != NINLIL_R7_FRAG_OK) {
        ninlil_r7_frag_secure_zero(pt, sizeof(pt));
        return st;
    }
    if (pt_len != NINLIL_R7_FRAG_ACK_PT_LEN) {
        ninlil_r7_frag_secure_zero(pt, sizeof(pt));
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    st = ninlil_r7_frag_parse_ack_pt(pt, out_body);
    ninlil_r7_frag_secure_zero(pt, sizeof(pt));
    return st;
}

/* -------------------------------------------------------------------------- */
/* Outer DATA / LINK_ACK                                                      */
/* -------------------------------------------------------------------------- */

static ninlil_r7_frag_status ninlil_r7_frag_validate_outer_data(
    const ninlil_r7_frag_outer_data_fields *fields)
{
    if (fields == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (fields->ack_requested != 0u && fields->ack_requested != 1u) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (!ninlil_r7_frag_context_ok(fields->hop_context_id)
        || !ninlil_r7_frag_counter_ok(fields->hop_counter)) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (fields->route_handle == 0u && fields->route_generation == 0u
        && fields->hop_remaining == 0u) {
        return NINLIL_R7_FRAG_OK;
    }
    if (fields->route_handle != 0u && fields->route_generation != 0u
        && fields->hop_remaining >= 1u) {
        return NINLIL_R7_FRAG_OK;
    }
    return NINLIL_R7_FRAG_STRUCTURAL;
}

ninlil_r7_frag_status ninlil_r7_frag_seal_outer_data(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t data_key16[16],
    const uint8_t data_iv12[12],
    const ninlil_r7_frag_outer_data_fields *fields,
    const uint8_t *e2e_blob,
    size_t e2e_blob_len,
    uint8_t *out_frame,
    size_t out_capacity,
    size_t *out_len)
{
    uint8_t aad19[NINLIL_R7_FRAG_OUTER_AAD_LEN];
    uint8_t nonce12[12];
    uint8_t sealed[220u + 16u];
    uint8_t frame_cand[255u];
    size_t sealed_need;
    size_t frame_need;
    size_t sealed_len = 0u;
    ninlil_r7_crypto_status cst;
    ninlil_r7_frag_status st;

    if (ninlil_r7_crypto_provider_validate(provider) != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (data_key16 == NULL || data_iv12 == NULL || fields == NULL
        || e2e_blob == NULL || out_frame == NULL || out_len == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    st = ninlil_r7_frag_validate_outer_data(fields);
    if (st != NINLIL_R7_FRAG_OK) {
        return st;
    }
    /* E2E sealed blob domain for DATA carriers: 31..220 (includes FRAG). */
    if (e2e_blob_len < 31u || e2e_blob_len > 220u) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    frame_need = NINLIL_R7_FRAG_OUTER_AAD_LEN + e2e_blob_len
        + NINLIL_R7_FRAG_TAG_LEN;
    if (frame_need < 66u || frame_need > FRAG_OUTER_MAX) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    if (out_capacity != frame_need) {
        return NINLIL_R7_FRAG_CAPACITY;
    }
    sealed_need = e2e_blob_len + NINLIL_R7_FRAG_TAG_LEN;

    memset(aad19, 0, sizeof(aad19));
    aad19[0] = NINLIL_R7_FRAG_PROFILE_ID;
    aad19[1] = (uint8_t)((NINLIL_R7_FRAG_OUTER_KIND_DATA << 4)
        | (fields->ack_requested & 1u));
    aad19[2] = fields->hop_remaining;
    ninlil_r7_frag_store_u32_be(aad19 + 3, fields->hop_context_id);
    ninlil_r7_frag_store_u64_be(aad19 + 7, fields->hop_counter);
    ninlil_r7_frag_store_u16_be(aad19 + 15, fields->route_handle);
    ninlil_r7_frag_store_u16_be(aad19 + 17, fields->route_generation);

    cst = ninlil_r7_crypto_nonce_from_counter(
        data_iv12, fields->hop_counter, nonce12);
    st = ninlil_r7_frag_map_crypto(cst, 0);
    if (st != NINLIL_R7_FRAG_OK) {
        goto done;
    }
    cst = ninlil_r7_crypto_aes128_gcm_seal(
        provider, data_key16, nonce12, aad19, NINLIL_R7_FRAG_OUTER_AAD_LEN,
        e2e_blob, e2e_blob_len, sealed, sealed_need, &sealed_len);
    st = ninlil_r7_frag_map_crypto(cst, 0);
    if (st != NINLIL_R7_FRAG_OK || sealed_len != sealed_need) {
        if (st == NINLIL_R7_FRAG_OK) {
            st = NINLIL_R7_FRAG_INTERNAL_CONTRACT;
        }
        goto done;
    }
    memset(frame_cand, 0, sizeof(frame_cand));
    ninlil_r7_frag_copy(frame_cand, aad19, NINLIL_R7_FRAG_OUTER_AAD_LEN);
    ninlil_r7_frag_copy(
        frame_cand + NINLIL_R7_FRAG_OUTER_AAD_LEN, sealed, sealed_len);
    ninlil_r7_frag_copy(out_frame, frame_cand, frame_need);
    *out_len = frame_need;
    st = NINLIL_R7_FRAG_OK;
done:
    ninlil_r7_frag_secure_zero(aad19, sizeof(aad19));
    ninlil_r7_frag_secure_zero(nonce12, sizeof(nonce12));
    ninlil_r7_frag_secure_zero(sealed, sizeof(sealed));
    ninlil_r7_frag_secure_zero(frame_cand, sizeof(frame_cand));
    return st;
}

ninlil_r7_frag_status ninlil_r7_frag_open_outer_data(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t data_key16[16],
    const uint8_t data_iv12[12],
    const uint8_t *frame,
    size_t frame_len,
    ninlil_r7_frag_outer_data_fields *out_fields,
    uint8_t *out_e2e_blob,
    size_t out_capacity,
    size_t *out_len)
{
    uint8_t aad19[NINLIL_R7_FRAG_OUTER_AAD_LEN];
    uint8_t nonce12[12];
    uint8_t blob_cand[220u];
    ninlil_r7_frag_outer_data_fields cand;
    size_t hop_ct_len;
    size_t produced = 0u;
    uint8_t kind_flags;
    uint8_t kind;
    ninlil_r7_crypto_status cst;
    ninlil_r7_frag_status st;

    if (ninlil_r7_crypto_provider_validate(provider) != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (data_key16 == NULL || data_iv12 == NULL || frame == NULL
        || out_fields == NULL || out_e2e_blob == NULL || out_len == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (frame_len < 66u || frame_len > FRAG_OUTER_MAX) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    if (frame_len < NINLIL_R7_FRAG_OUTER_AAD_LEN + NINLIL_R7_FRAG_TAG_LEN) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    hop_ct_len = frame_len - NINLIL_R7_FRAG_OUTER_AAD_LEN
        - NINLIL_R7_FRAG_TAG_LEN;
    if (hop_ct_len < 31u || hop_ct_len > 220u) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    if (out_capacity != hop_ct_len) {
        return NINLIL_R7_FRAG_CAPACITY;
    }
    if (frame[0] != NINLIL_R7_FRAG_PROFILE_ID) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    kind_flags = frame[1];
    kind = (uint8_t)((kind_flags >> 4) & 0x0fu);
    if (kind != NINLIL_R7_FRAG_OUTER_KIND_DATA) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if ((kind_flags & 0x0eu) != 0u) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    memset(&cand, 0, sizeof(cand));
    cand.ack_requested = (uint8_t)(kind_flags & 0x01u);
    cand.hop_remaining = frame[2];
    cand.hop_context_id = ninlil_r7_frag_load_u32_be(frame + 3);
    cand.hop_counter = ninlil_r7_frag_load_u64_be(frame + 7);
    cand.route_handle = ninlil_r7_frag_load_u16_be(frame + 15);
    cand.route_generation = ninlil_r7_frag_load_u16_be(frame + 17);
    st = ninlil_r7_frag_validate_outer_data(&cand);
    if (st != NINLIL_R7_FRAG_OK) {
        return st;
    }

    ninlil_r7_frag_copy(aad19, frame, NINLIL_R7_FRAG_OUTER_AAD_LEN);
    cst = ninlil_r7_crypto_nonce_from_counter(
        data_iv12, cand.hop_counter, nonce12);
    st = ninlil_r7_frag_map_crypto(cst, 0);
    if (st != NINLIL_R7_FRAG_OK) {
        goto done;
    }
    memset(blob_cand, 0, sizeof(blob_cand));
    cst = ninlil_r7_crypto_aes128_gcm_open(
        provider, data_key16, nonce12, aad19, NINLIL_R7_FRAG_OUTER_AAD_LEN,
        frame + NINLIL_R7_FRAG_OUTER_AAD_LEN,
        hop_ct_len + NINLIL_R7_FRAG_TAG_LEN, blob_cand, hop_ct_len, &produced);
    st = ninlil_r7_frag_map_crypto(cst, 1);
    if (st != NINLIL_R7_FRAG_OK || produced != hop_ct_len) {
        if (st == NINLIL_R7_FRAG_OK) {
            st = NINLIL_R7_FRAG_INTERNAL_CONTRACT;
        }
        goto done;
    }
    *out_fields = cand;
    ninlil_r7_frag_copy(out_e2e_blob, blob_cand, hop_ct_len);
    *out_len = hop_ct_len;
    st = NINLIL_R7_FRAG_OK;
done:
    ninlil_r7_frag_secure_zero(aad19, sizeof(aad19));
    ninlil_r7_frag_secure_zero(nonce12, sizeof(nonce12));
    ninlil_r7_frag_secure_zero(blob_cand, sizeof(blob_cand));
    ninlil_r7_frag_secure_zero(&cand, sizeof(cand));
    return st;
}

ninlil_r7_frag_status ninlil_r7_frag_seal_outer_link_ack(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t ack_key16[16],
    const uint8_t ack_iv12[12],
    const ninlil_r7_frag_outer_link_ack_fields *outer,
    const ninlil_r7_frag_link_ack_body *body,
    uint8_t out_frame[NINLIL_R7_FRAG_LINK_ACK_OUTER_LEN],
    size_t *out_len)
{
    uint8_t aad19[NINLIL_R7_FRAG_OUTER_AAD_LEN];
    uint8_t nonce12[12];
    uint8_t pt16[NINLIL_R7_FRAG_LINK_ACK_PT_LEN];
    uint8_t sealed[16u + 16u];
    uint8_t frame_cand[NINLIL_R7_FRAG_LINK_ACK_OUTER_LEN];
    size_t sealed_len = 0u;
    ninlil_r7_crypto_status cst;
    ninlil_r7_frag_status st;

    if (ninlil_r7_crypto_provider_validate(provider) != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (ack_key16 == NULL || ack_iv12 == NULL || outer == NULL || body == NULL
        || out_frame == NULL || out_len == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (!ninlil_r7_frag_context_ok(outer->hop_context_id)
        || !ninlil_r7_frag_counter_ok(outer->hop_counter)) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    st = ninlil_r7_frag_pack_link_ack_body(body, pt16);
    if (st != NINLIL_R7_FRAG_OK) {
        return st;
    }

    /* LINK_ACK outer: kind=2, ack_requested=0, route=0/0, remaining=0 */
    memset(aad19, 0, sizeof(aad19));
    aad19[0] = NINLIL_R7_FRAG_PROFILE_ID;
    aad19[1] = (uint8_t)(NINLIL_R7_FRAG_OUTER_KIND_LINK_ACK << 4);
    aad19[2] = 0u;
    ninlil_r7_frag_store_u32_be(aad19 + 3, outer->hop_context_id);
    ninlil_r7_frag_store_u64_be(aad19 + 7, outer->hop_counter);
    /* route fields already 0 */

    cst = ninlil_r7_crypto_nonce_from_counter(
        ack_iv12, outer->hop_counter, nonce12);
    st = ninlil_r7_frag_map_crypto(cst, 0);
    if (st != NINLIL_R7_FRAG_OK) {
        goto done;
    }
    cst = ninlil_r7_crypto_aes128_gcm_seal(
        provider, ack_key16, nonce12, aad19, NINLIL_R7_FRAG_OUTER_AAD_LEN,
        pt16, NINLIL_R7_FRAG_LINK_ACK_PT_LEN, sealed, 32u, &sealed_len);
    st = ninlil_r7_frag_map_crypto(cst, 0);
    if (st != NINLIL_R7_FRAG_OK || sealed_len != 32u) {
        if (st == NINLIL_R7_FRAG_OK) {
            st = NINLIL_R7_FRAG_INTERNAL_CONTRACT;
        }
        goto done;
    }
    memset(frame_cand, 0, sizeof(frame_cand));
    ninlil_r7_frag_copy(frame_cand, aad19, 19u);
    ninlil_r7_frag_copy(frame_cand + 19, sealed, 32u);
    ninlil_r7_frag_copy(out_frame, frame_cand, NINLIL_R7_FRAG_LINK_ACK_OUTER_LEN);
    *out_len = NINLIL_R7_FRAG_LINK_ACK_OUTER_LEN;
    st = NINLIL_R7_FRAG_OK;
done:
    ninlil_r7_frag_secure_zero(aad19, sizeof(aad19));
    ninlil_r7_frag_secure_zero(nonce12, sizeof(nonce12));
    ninlil_r7_frag_secure_zero(pt16, sizeof(pt16));
    ninlil_r7_frag_secure_zero(sealed, sizeof(sealed));
    ninlil_r7_frag_secure_zero(frame_cand, sizeof(frame_cand));
    return st;
}

ninlil_r7_frag_status ninlil_r7_frag_open_outer_link_ack(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t ack_key16[16],
    const uint8_t ack_iv12[12],
    const uint8_t *frame,
    size_t frame_len,
    ninlil_r7_frag_outer_link_ack_fields *out_outer,
    ninlil_r7_frag_link_ack_body *out_body)
{
    uint8_t aad19[NINLIL_R7_FRAG_OUTER_AAD_LEN];
    uint8_t nonce12[12];
    uint8_t pt16[NINLIL_R7_FRAG_LINK_ACK_PT_LEN];
    ninlil_r7_frag_outer_link_ack_fields ocand;
    size_t produced = 0u;
    uint8_t kind_flags;
    uint8_t kind;
    ninlil_r7_crypto_status cst;
    ninlil_r7_frag_status st;

    if (ninlil_r7_crypto_provider_validate(provider) != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (ack_key16 == NULL || ack_iv12 == NULL || frame == NULL
        || out_outer == NULL || out_body == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (frame_len != NINLIL_R7_FRAG_LINK_ACK_OUTER_LEN) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    if (frame[0] != NINLIL_R7_FRAG_PROFILE_ID) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    kind_flags = frame[1];
    kind = (uint8_t)((kind_flags >> 4) & 0x0fu);
    if (kind != NINLIL_R7_FRAG_OUTER_KIND_LINK_ACK) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if ((kind_flags & 0x0fu) != 0u) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (frame[2] != 0u) {
        return NINLIL_R7_FRAG_STRUCTURAL; /* hop_remaining */
    }
    if (ninlil_r7_frag_load_u16_be(frame + 15) != 0u
        || ninlil_r7_frag_load_u16_be(frame + 17) != 0u) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    memset(&ocand, 0, sizeof(ocand));
    ocand.hop_context_id = ninlil_r7_frag_load_u32_be(frame + 3);
    ocand.hop_counter = ninlil_r7_frag_load_u64_be(frame + 7);
    if (!ninlil_r7_frag_context_ok(ocand.hop_context_id)
        || !ninlil_r7_frag_counter_ok(ocand.hop_counter)) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }

    ninlil_r7_frag_copy(aad19, frame, 19u);
    cst = ninlil_r7_crypto_nonce_from_counter(
        ack_iv12, ocand.hop_counter, nonce12);
    st = ninlil_r7_frag_map_crypto(cst, 0);
    if (st != NINLIL_R7_FRAG_OK) {
        goto done;
    }
    memset(pt16, 0, sizeof(pt16));
    cst = ninlil_r7_crypto_aes128_gcm_open(
        provider, ack_key16, nonce12, aad19, 19u, frame + 19, 32u, pt16, 16u,
        &produced);
    st = ninlil_r7_frag_map_crypto(cst, 1);
    if (st != NINLIL_R7_FRAG_OK || produced != 16u) {
        if (st == NINLIL_R7_FRAG_OK) {
            st = NINLIL_R7_FRAG_INTERNAL_CONTRACT;
        }
        goto done;
    }
    st = ninlil_r7_frag_parse_link_ack_body(pt16, out_body);
    if (st != NINLIL_R7_FRAG_OK) {
        goto done;
    }
    *out_outer = ocand;
    st = NINLIL_R7_FRAG_OK;
done:
    ninlil_r7_frag_secure_zero(aad19, sizeof(aad19));
    ninlil_r7_frag_secure_zero(nonce12, sizeof(nonce12));
    ninlil_r7_frag_secure_zero(pt16, sizeof(pt16));
    ninlil_r7_frag_secure_zero(&ocand, sizeof(ocand));
    return st;
}

ninlil_r7_frag_status ninlil_r7_frag_structural_e2e_header(
    const uint8_t *blob,
    size_t blob_len,
    ninlil_r7_frag_e2e_fields *out_fields)
{
    uint8_t type_flags;
    uint8_t type;
    uint32_t ctx;
    uint64_t ctr;
    ninlil_r7_frag_e2e_fields cand;

    if (blob == NULL || out_fields == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (blob_len < 31u || blob_len > 220u) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    if (blob[0] != NINLIL_R7_FRAG_PROFILE_ID) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    type_flags = blob[1];
    if ((type_flags & 0x0fu) != 0u) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    type = (uint8_t)((type_flags >> 4) & 0x0fu);
    if (type < NINLIL_R7_FRAG_E2E_TYPE_SINGLE
        || type > NINLIL_R7_FRAG_E2E_TYPE_ACK) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    ctx = ninlil_r7_frag_load_u32_be(blob + 2);
    ctr = ninlil_r7_frag_load_u64_be(blob + 6);
    if (!ninlil_r7_frag_context_ok(ctx) || !ninlil_r7_frag_counter_ok(ctr)) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    /* Type-specific length domains. */
    if (type == NINLIL_R7_FRAG_E2E_TYPE_SINGLE) {
        if (blob_len < 31u || blob_len > 220u) {
            return NINLIL_R7_FRAG_LENGTH_CLASS;
        }
    } else if (type == NINLIL_R7_FRAG_E2E_TYPE_START) {
        if (blob_len < FRAG_START_BLOB_MIN || blob_len > FRAG_START_BLOB_MAX) {
            return NINLIL_R7_FRAG_LENGTH_CLASS;
        }
    } else if (type == NINLIL_R7_FRAG_E2E_TYPE_CONT) {
        if (blob_len < FRAG_CONT_BLOB_MIN || blob_len > FRAG_CONT_BLOB_MAX) {
            return NINLIL_R7_FRAG_LENGTH_CLASS;
        }
    } else if (type == NINLIL_R7_FRAG_E2E_TYPE_ACK) {
        if (blob_len != FRAG_ACK_BLOB_EXACT) {
            return NINLIL_R7_FRAG_LENGTH_CLASS;
        }
    }
    memset(&cand, 0, sizeof(cand));
    cand.e2e_type = type;
    cand.e2e_context_id = ctx;
    cand.e2e_counter = ctr;
    *out_fields = cand;
    return NINLIL_R7_FRAG_OK;
}

ninlil_r7_frag_status ninlil_r7_frag_start_fingerprint(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_frag_start_body *body,
    const uint8_t *first_chunk,
    size_t first_chunk_len,
    uint8_t out_fp32[32])
{
    uint8_t domain[16u + 8u + 4u + 2u + 2u + 32u + 126u];
    size_t n = 0u;
    ninlil_r7_crypto_status cst;

    if (ninlil_r7_crypto_provider_validate(provider) != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (body == NULL || first_chunk == NULL || out_fp32 == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (first_chunk_len < NINLIL_R7_FRAG_S_MIN
        || first_chunk_len > NINLIL_R7_FRAG_S_MAX) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    ninlil_r7_frag_copy(domain + n, body->transfer_id, 16u);
    n += 16u;
    ninlil_r7_frag_store_u64_be(domain + n, body->transfer_handle);
    n += 8u;
    ninlil_r7_frag_store_u32_be(domain + n, body->total_len);
    n += 4u;
    ninlil_r7_frag_store_u16_be(domain + n, body->frag_count);
    n += 2u;
    ninlil_r7_frag_store_u16_be(domain + n, body->continuation_unit);
    n += 2u;
    ninlil_r7_frag_copy(domain + n, body->content_digest, 32u);
    n += 32u;
    ninlil_r7_frag_copy(domain + n, first_chunk, first_chunk_len);
    n += first_chunk_len;

    cst = ninlil_r7_crypto_sha256(provider, domain, n, out_fp32);
    ninlil_r7_frag_secure_zero(domain, sizeof(domain));
    return ninlil_r7_frag_map_crypto(cst, 0);
}

ninlil_r7_frag_status ninlil_r7_frag_content_digest(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t *payload,
    size_t total_len,
    uint8_t out_digest32[32])
{
    ninlil_r7_crypto_status cst;

    if (ninlil_r7_crypto_provider_validate(provider) != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (out_digest32 == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (total_len == 0u || total_len > NINLIL_R7_FRAG_TOTAL_LEN_MAX) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    if (payload == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    cst = ninlil_r7_crypto_sha256(provider, payload, total_len, out_digest32);
    return ninlil_r7_frag_map_crypto(cst, 0);
}
