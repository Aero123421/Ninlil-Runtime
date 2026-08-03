#ifndef NINLIL_R7_FRAG_INTERNAL_H
#define NINLIL_R7_FRAG_INTERNAL_H

/*
 * Private helpers for r7_frag TU set. Not installed. Not public ABI.
 */

#include "r7_frag.h"

#include <stdatomic.h>
#include <string.h>

static inline void ninlil_r7_frag_secure_zero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    size_t i;
    for (i = 0u; i < n; i++) {
        v[i] = 0u;
    }
    atomic_signal_fence(memory_order_seq_cst);
}

static inline void ninlil_r7_frag_copy(uint8_t *dst, const uint8_t *src, size_t n)
{
    size_t i;
    for (i = 0u; i < n; i++) {
        dst[i] = src[i];
    }
}

static inline int ninlil_r7_frag_spans_forbidden(
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

static inline ninlil_r7_frag_status ninlil_r7_frag_check_pairwise(
    const void *const *spans, const size_t *lens, size_t n)
{
    size_t i;
    size_t j;
    for (i = 0u; i < n; i++) {
        for (j = i + 1u; j < n; j++) {
            if (ninlil_r7_frag_spans_forbidden(
                    spans[i], lens[i], spans[j], lens[j])) {
                return NINLIL_R7_FRAG_ALIAS;
            }
        }
    }
    return NINLIL_R7_FRAG_OK;
}

static inline void ninlil_r7_frag_store_u16_be(uint8_t *out, uint16_t v)
{
    out[0] = (uint8_t)((v >> 8) & 0xffu);
    out[1] = (uint8_t)(v & 0xffu);
}

static inline void ninlil_r7_frag_store_u32_be(uint8_t *out, uint32_t v)
{
    out[0] = (uint8_t)((v >> 24) & 0xffu);
    out[1] = (uint8_t)((v >> 16) & 0xffu);
    out[2] = (uint8_t)((v >> 8) & 0xffu);
    out[3] = (uint8_t)(v & 0xffu);
}

static inline void ninlil_r7_frag_store_u64_be(uint8_t *out, uint64_t v)
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

static inline uint16_t ninlil_r7_frag_load_u16_be(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

static inline uint32_t ninlil_r7_frag_load_u32_be(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static inline uint64_t ninlil_r7_frag_load_u64_be(const uint8_t *in)
{
    return ((uint64_t)in[0] << 56) | ((uint64_t)in[1] << 48)
        | ((uint64_t)in[2] << 40) | ((uint64_t)in[3] << 32)
        | ((uint64_t)in[4] << 24) | ((uint64_t)in[5] << 16)
        | ((uint64_t)in[6] << 8) | (uint64_t)in[7];
}

static inline int ninlil_r7_frag_context_ok(uint32_t id)
{
    return id != 0u && id != UINT32_MAX;
}

static inline int ninlil_r7_frag_counter_ok(uint64_t c)
{
    return c != 0u && c != UINT64_MAX;
}

static inline int ninlil_r7_frag_handle_ok(uint64_t h)
{
    return h != 0u && h != UINT64_MAX;
}

static inline ninlil_r7_frag_status ninlil_r7_frag_map_crypto(
    ninlil_r7_crypto_status st, int is_open)
{
    if (st == NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_FRAG_OK;
    }
    if (is_open && st == NINLIL_R7_CRYPTO_AUTH_FAILED) {
        return NINLIL_R7_FRAG_AUTH_FAILED;
    }
    if (st == NINLIL_R7_CRYPTO_BACKEND_FAILED) {
        return NINLIL_R7_FRAG_BACKEND_FAILED;
    }
    return NINLIL_R7_FRAG_INTERNAL_CONTRACT;
}

static inline int ninlil_r7_frag_checked_add_u64(
    uint64_t a, uint64_t b, uint64_t *out)
{
    if (a > (UINT64_MAX - b)) {
        return 0;
    }
    *out = a + b;
    return 1;
}

/* docs/30 §9.2: shared TX exclusive grow (session/core/N6). */
#include "tx_exclusive_tranche.h"

static inline int ninlil_r7_frag_tx_exclusive_grow(
    uint64_t ram_limit,
    uint64_t block,
    uint64_t *out_U)
{
    return ninlil_tx_exclusive_grow(ram_limit, block, out_U);
}

static inline int ninlil_r7_frag_tx_counter_assignable(uint64_t c)
{
    return ninlil_tx_counter_assignable(c);
}

static inline uint16_t ninlil_r7_frag_full_bitmap(uint16_t frag_count)
{
    if (frag_count == 0u || frag_count > 16u) {
        return 0u;
    }
    return (uint16_t)((1u << frag_count) - 1u);
}

/* PT packing for START/CONT/ACK (no AEAD). */
ninlil_r7_frag_status ninlil_r7_frag_pack_start_pt(
    const ninlil_r7_frag_start_body *body,
    const uint8_t *first_chunk,
    size_t first_chunk_len,
    uint8_t *out_pt,
    size_t out_capacity,
    size_t *out_len);

ninlil_r7_frag_status ninlil_r7_frag_parse_start_pt(
    const uint8_t *pt,
    size_t pt_len,
    ninlil_r7_frag_start_body *out_body,
    const uint8_t **out_chunk,
    size_t *out_chunk_len);

ninlil_r7_frag_status ninlil_r7_frag_pack_cont_pt(
    const ninlil_r7_frag_cont_body *body,
    const uint8_t *chunk,
    size_t chunk_len,
    uint8_t *out_pt,
    size_t out_capacity,
    size_t *out_len);

ninlil_r7_frag_status ninlil_r7_frag_parse_cont_pt(
    const uint8_t *pt,
    size_t pt_len,
    ninlil_r7_frag_cont_body *out_body,
    const uint8_t **out_chunk,
    size_t *out_chunk_len);

ninlil_r7_frag_status ninlil_r7_frag_pack_ack_pt(
    const ninlil_r7_frag_ack_body *body,
    uint8_t out14[NINLIL_R7_FRAG_ACK_PT_LEN]);

ninlil_r7_frag_status ninlil_r7_frag_parse_ack_pt(
    const uint8_t in14[NINLIL_R7_FRAG_ACK_PT_LEN],
    ninlil_r7_frag_ack_body *out_body);

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
    size_t *out_len);

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
    size_t *out_pt_len);

#endif /* NINLIL_R7_FRAG_INTERNAL_H */
