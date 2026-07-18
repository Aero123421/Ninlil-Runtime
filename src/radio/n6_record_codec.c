/*
 * N6 durable record pure BE codec (docs/30 §5.3).
 *
 * SEMANTIC: N6_PRIVATE_ONLY_NO_PUBLIC_ABI
 * SEMANTIC: N6_BE_ENCODING_ONLY
 * SEMANTIC: N6_VALUE_CRC32C_CANONICAL
 * SEMANTIC: N6_CODEC_EXACT_LENGTH_AND_CLOSED_DOMAIN
 * SEMANTIC: N6_CODEC_TEMP_THEN_PUBLISH
 * SEMANTIC: N6_CODEC_RANGE_DISJOINT_REQUIRED
 * SEMANTIC: N6_CHUNK_D_PRIVATE_HOST_CANDIDATE
 *
 * Decode: parse+validate into local temporary; publish to *out only on full
 * success. Failure leaves *out unmodified (mutation 0).
 * Encode: validate input; build wire in local temporary; reject in/out range
 * overlap; publish to out only on success.
 *
 * CRC32C: wrapper over ninlil_model_domain_crc32c only (no second poly).
 */

#include "n6_record_codec.h"

#include "../model/domain_store_codec.h"

#include <stdint.h>
#include <string.h>

_Static_assert(NINLIL_N6_LANE_KEY_BYTES == 48u, "lane key wire size");
_Static_assert(NINLIL_N6_TX_VALUE_BYTES == 68u, "N6TX wire size");
_Static_assert(NINLIL_N6_RX_VALUE_BYTES == 68u, "N6RX wire size");
_Static_assert(NINLIL_N6_HW_KEY_BYTES == 32u, "N6HW key wire size");
_Static_assert(NINLIL_N6_HW_VALUE_BYTES == 28u, "N6HW value wire size");
_Static_assert(NINLIL_N6_AL_KEY_BYTES == 24u, "N6AL key wire size");
_Static_assert(NINLIL_N6_AL_VALUE_BYTES == 56u, "N6AL value wire size");
_Static_assert(NINLIL_N6_RT_KEY_BYTES == 28u, "N6RT key wire size");
_Static_assert(NINLIL_N6_RT_VALUE_BYTES == 48u, "N6RT value wire size");
_Static_assert(NINLIL_N6_CF_KEY_BYTES == 28u, "N6CF key wire size");
_Static_assert(NINLIL_N6_CF_VALUE_BYTES == 64u, "N6CF value wire size");

/* ---- BE helpers ---- */

static void n6_put_u16_be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)((v >> 8) & 0xffu);
    p[1] = (uint8_t)(v & 0xffu);
}

static void n6_put_u32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xffu);
    p[1] = (uint8_t)((v >> 16) & 0xffu);
    p[2] = (uint8_t)((v >> 8) & 0xffu);
    p[3] = (uint8_t)(v & 0xffu);
}

static void n6_put_u64_be(uint8_t *p, uint64_t v)
{
    n6_put_u32_be(p, (uint32_t)((v >> 32) & 0xffffffffu));
    n6_put_u32_be(p + 4, (uint32_t)(v & 0xffffffffu));
}

static uint16_t n6_get_u16_be(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t n6_get_u32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
        | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t n6_get_u64_be(const uint8_t *p)
{
    return ((uint64_t)n6_get_u32_be(p) << 32)
        | (uint64_t)n6_get_u32_be(p + 4);
}

static int n6_all_zero(const uint8_t *p, size_t n)
{
    size_t i;
    if (p == NULL) {
        return 1;
    }
    for (i = 0u; i < n; ++i) {
        if (p[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

/*
 * Closed half-open ranges [a, a+alen) and [b, b+blen) must not overlap.
 * Zero-length ranges are treated as non-overlapping.
 * Overflow of pointer+length is fail-closed (not disjoint).
 */
static int n6_ranges_disjoint(
    const void *a, size_t alen, const void *b, size_t blen)
{
    const uint8_t *ap;
    const uint8_t *bp;
    uintptr_t au;
    uintptr_t bu;
    uintptr_t a_end;
    uintptr_t b_end;

    if (alen == 0u || blen == 0u) {
        return 1;
    }
    if (a == NULL || b == NULL) {
        return 0;
    }
    ap = (const uint8_t *)a;
    bp = (const uint8_t *)b;
    au = (uintptr_t)ap;
    bu = (uintptr_t)bp;
    if (au > UINTPTR_MAX - alen || bu > UINTPTR_MAX - blen) {
        return 0;
    }
    a_end = au + alen;
    b_end = bu + blen;
    return (a_end <= bu) || (b_end <= au);
}

static int n6_layer_ok(uint8_t layer)
{
    return layer == NINLIL_N6_LAYER_HOP || layer == NINLIL_N6_LAYER_E2E;
}

static int n6_dir_ok(uint8_t d)
{
    return d == NINLIL_N6_DIR_IR || d == NINLIL_N6_DIR_RI;
}

static int n6_alloc_ok(uint8_t a)
{
    return a == NINLIL_N6_ALLOC_INBOUND_RX || a == NINLIL_N6_ALLOC_OUTBOUND_TX;
}

static int n6_lane_kind_ok(uint8_t layer, uint8_t kind)
{
    if (layer == NINLIL_N6_LAYER_HOP) {
        return kind == NINLIL_N6_LANE_HOP_DATA || kind == NINLIL_N6_LANE_HOP_ACK;
    }
    if (layer == NINLIL_N6_LAYER_E2E) {
        return kind == NINLIL_N6_LANE_E2E;
    }
    return 0;
}

static int n6_fence_reason_ok(uint8_t r)
{
    return r >= NINLIL_N6_FENCE_REASON_DIGEST
        && r <= NINLIL_N6_FENCE_REASON_OPERATOR;
}

static int n6_context_id_ok(uint32_t id)
{
    return id != 0u && id != UINT32_MAX;
}

static int n6_kgen_ok(uint64_t k)
{
    return k != 0u;
}

/* docs/30 §5.3.0: membership_epoch ≥ 1 */
static int n6_epoch_ok(uint64_t e)
{
    return e >= 1u;
}

/* docs/30 §9: reserved_exclusive initial 1; 0 is out-of-domain */
static int n6_tx_reserved_ok(uint64_t reserved_exclusive)
{
    return reserved_exclusive != 0u;
}

uint32_t ninlil_n6_crc32c(const uint8_t *bytes, size_t len)
{
    if (bytes == NULL && len != 0u) {
        return 0u;
    }
    if (len > (size_t)UINT32_MAX) {
        return 0u;
    }
    return ninlil_model_domain_crc32c(bytes, (uint32_t)len);
}

static ninlil_n6_codec_status_t n6_need_exact(
    const uint8_t *in, size_t in_len, size_t exact)
{
    if (in == NULL) {
        return NINLIL_N6_CODEC_INVALID_ARGUMENT;
    }
    if (in_len != exact) {
        return NINLIL_N6_CODEC_REJECT;
    }
    return NINLIL_N6_CODEC_OK;
}

/*
 * Encode prep: require capacity; reject in/out and out_len span alias.
 * Does NOT write *out_len (failure must leave out_len mutation 0).
 * Caller publishes *out_len = exact only after full success.
 */
static ninlil_n6_codec_status_t n6_encode_prep(
    const void *in_obj,
    size_t in_obj_size,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len,
    size_t exact)
{
    if (out_len == NULL || in_obj == NULL || out == NULL) {
        return NINLIL_N6_CODEC_INVALID_ARGUMENT;
    }
    if (out_cap < exact) {
        return NINLIL_N6_CODEC_INVALID_ARGUMENT;
    }
    /* out_len must not live inside out[] or logical input */
    if (!n6_ranges_disjoint(out_len, sizeof(*out_len), out, exact)) {
        return NINLIL_N6_CODEC_INVALID_ARGUMENT;
    }
    if (!n6_ranges_disjoint(out_len, sizeof(*out_len), in_obj, in_obj_size)) {
        return NINLIL_N6_CODEC_INVALID_ARGUMENT;
    }
    /* Reject logical-input ↔ wire-output range overlap. */
    if (!n6_ranges_disjoint(in_obj, in_obj_size, out, exact)) {
        return NINLIL_N6_CODEC_INVALID_ARGUMENT;
    }
    return NINLIL_N6_CODEC_OK;
}

static void n6_encode_publish(
    uint8_t *out, size_t *out_len, const uint8_t *tmp, size_t exact)
{
    (void)memcpy(out, tmp, exact);
    *out_len = exact;
}

/* Decode prep: exact length + in/out disjoint. out unmodified on fail later. */
static ninlil_n6_codec_status_t n6_decode_prep(
    const uint8_t *in,
    size_t in_len,
    size_t exact,
    void *out_obj,
    size_t out_obj_size)
{
    ninlil_n6_codec_status_t st;

    if (out_obj == NULL) {
        return NINLIL_N6_CODEC_INVALID_ARGUMENT;
    }
    st = n6_need_exact(in, in_len, exact);
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    if (!n6_ranges_disjoint(in, exact, out_obj, out_obj_size)) {
        return NINLIL_N6_CODEC_INVALID_ARGUMENT;
    }
    return NINLIL_N6_CODEC_OK;
}

/* ---- Lane key ---- */

ninlil_n6_codec_status_t ninlil_n6_encode_lane_key(
    const ninlil_n6_lane_key_t *in,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len)
{
    uint8_t tmp[NINLIL_N6_LANE_KEY_BYTES];
    ninlil_n6_codec_status_t st;

    st = n6_encode_prep(in, sizeof(*in), out, out_cap, out_len,
        NINLIL_N6_LANE_KEY_BYTES);
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    if (in->reserved0 != 0u
        || !n6_layer_ok(in->layer_code)
        || !n6_dir_ok(in->direction_code)
        || !n6_lane_kind_ok(in->layer_code, in->kind_or_lane)
        || !n6_context_id_ok(in->context_id)
        || !n6_kgen_ok(in->key_generation)) {
        return NINLIL_N6_CODEC_REJECT;
    }
    (void)memset(tmp, 0, sizeof(tmp));
    tmp[0] = in->layer_code;
    tmp[1] = in->kind_or_lane;
    tmp[2] = in->direction_code;
    tmp[3] = 0u;
    n6_put_u32_be(tmp + 4, in->context_id);
    (void)memcpy(tmp + 8, in->binding_digest32, 32u);
    n6_put_u64_be(tmp + 40, in->key_generation);
    n6_encode_publish(out, out_len, tmp, NINLIL_N6_LANE_KEY_BYTES);
    return NINLIL_N6_CODEC_OK;
}

ninlil_n6_codec_status_t ninlil_n6_decode_lane_key(
    const uint8_t *in,
    size_t in_len,
    ninlil_n6_lane_key_t *out)
{
    ninlil_n6_lane_key_t tmp;
    ninlil_n6_codec_status_t st;

    st = n6_decode_prep(in, in_len, NINLIL_N6_LANE_KEY_BYTES, out, sizeof(*out));
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.layer_code = in[0];
    tmp.kind_or_lane = in[1];
    tmp.direction_code = in[2];
    tmp.reserved0 = in[3];
    tmp.context_id = n6_get_u32_be(in + 4);
    (void)memcpy(tmp.binding_digest32, in + 8, 32u);
    tmp.key_generation = n6_get_u64_be(in + 40);
    if (tmp.reserved0 != 0u
        || !n6_layer_ok(tmp.layer_code)
        || !n6_dir_ok(tmp.direction_code)
        || !n6_lane_kind_ok(tmp.layer_code, tmp.kind_or_lane)
        || !n6_context_id_ok(tmp.context_id)
        || !n6_kgen_ok(tmp.key_generation)) {
        return NINLIL_N6_CODEC_REJECT; /* out unmodified */
    }
    *out = tmp;
    return NINLIL_N6_CODEC_OK;
}

/* ---- N6TX ---- */

ninlil_n6_codec_status_t ninlil_n6_encode_n6tx_value(
    const ninlil_n6_tx_value_t *in,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len)
{
    uint8_t tmp[NINLIL_N6_TX_VALUE_BYTES];
    uint32_t crc;
    ninlil_n6_codec_status_t st;

    st = n6_encode_prep(in, sizeof(*in), out, out_cap, out_len,
        NINLIL_N6_TX_VALUE_BYTES);
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    if (in->magic != NINLIL_N6_MAGIC_TX || in->schema != NINLIL_N6_SCHEMA_LANE
        || in->reserved0 != 0u || in->alloc_side != NINLIL_N6_ALLOC_OUTBOUND_TX
        || !n6_all_zero(in->reserved1, 3u)
        || !n6_kgen_ok(in->key_generation)
        || !n6_epoch_ok(in->membership_epoch)
        || !n6_tx_reserved_ok(in->reserved_exclusive)) {
        return NINLIL_N6_CODEC_REJECT;
    }
    (void)memset(tmp, 0, sizeof(tmp));
    n6_put_u32_be(tmp + 0, NINLIL_N6_MAGIC_TX);
    n6_put_u16_be(tmp + 4, NINLIL_N6_SCHEMA_LANE);
    n6_put_u16_be(tmp + 6, 0u);
    n6_put_u64_be(tmp + 8, in->reserved_exclusive);
    n6_put_u64_be(tmp + 16, in->key_generation);
    (void)memcpy(tmp + 24, in->binding_digest_prefix16, 16u);
    n6_put_u64_be(tmp + 40, in->membership_epoch);
    tmp[48] = NINLIL_N6_ALLOC_OUTBOUND_TX;
    (void)memcpy(tmp + 52, in->ns_fingerprint12, 12u);
    crc = ninlil_n6_crc32c(tmp, 64u);
    n6_put_u32_be(tmp + 64, crc);
    n6_encode_publish(out, out_len, tmp, NINLIL_N6_TX_VALUE_BYTES);
    return NINLIL_N6_CODEC_OK;
}

ninlil_n6_codec_status_t ninlil_n6_decode_n6tx_value(
    const uint8_t *in,
    size_t in_len,
    ninlil_n6_tx_value_t *out)
{
    ninlil_n6_tx_value_t tmp;
    uint32_t crc_wire;
    uint32_t crc_calc;
    ninlil_n6_codec_status_t st;

    st = n6_decode_prep(in, in_len, NINLIL_N6_TX_VALUE_BYTES, out, sizeof(*out));
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.magic = n6_get_u32_be(in + 0);
    tmp.schema = n6_get_u16_be(in + 4);
    tmp.reserved0 = n6_get_u16_be(in + 6);
    tmp.reserved_exclusive = n6_get_u64_be(in + 8);
    tmp.key_generation = n6_get_u64_be(in + 16);
    (void)memcpy(tmp.binding_digest_prefix16, in + 24, 16u);
    tmp.membership_epoch = n6_get_u64_be(in + 40);
    tmp.alloc_side = in[48];
    tmp.reserved1[0] = in[49];
    tmp.reserved1[1] = in[50];
    tmp.reserved1[2] = in[51];
    (void)memcpy(tmp.ns_fingerprint12, in + 52, 12u);
    crc_wire = n6_get_u32_be(in + 64);
    tmp.value_crc32c = crc_wire;
    crc_calc = ninlil_n6_crc32c(in, 64u);
    if (tmp.magic != NINLIL_N6_MAGIC_TX || tmp.schema != NINLIL_N6_SCHEMA_LANE
        || tmp.reserved0 != 0u
        || tmp.alloc_side != NINLIL_N6_ALLOC_OUTBOUND_TX
        || tmp.reserved1[0] != 0u || tmp.reserved1[1] != 0u
        || tmp.reserved1[2] != 0u || !n6_kgen_ok(tmp.key_generation)
        || !n6_epoch_ok(tmp.membership_epoch)
        || !n6_tx_reserved_ok(tmp.reserved_exclusive)
        || crc_wire != crc_calc) {
        return NINLIL_N6_CODEC_REJECT;
    }
    *out = tmp;
    return NINLIL_N6_CODEC_OK;
}

/* ---- N6RX ---- */

ninlil_n6_codec_status_t ninlil_n6_encode_n6rx_value(
    const ninlil_n6_rx_value_t *in,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len)
{
    uint8_t tmp[NINLIL_N6_RX_VALUE_BYTES];
    uint32_t crc;
    ninlil_n6_codec_status_t st;

    st = n6_encode_prep(in, sizeof(*in), out, out_cap, out_len,
        NINLIL_N6_RX_VALUE_BYTES);
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    if (in->magic != NINLIL_N6_MAGIC_RX || in->schema != NINLIL_N6_SCHEMA_LANE
        || in->reserved0 != 0u || in->alloc_side != NINLIL_N6_ALLOC_INBOUND_RX
        || !n6_all_zero(in->reserved1, 3u)
        || !n6_kgen_ok(in->key_generation)
        || !n6_epoch_ok(in->membership_epoch)) {
        return NINLIL_N6_CODEC_REJECT;
    }
    (void)memset(tmp, 0, sizeof(tmp));
    n6_put_u32_be(tmp + 0, NINLIL_N6_MAGIC_RX);
    n6_put_u16_be(tmp + 4, NINLIL_N6_SCHEMA_LANE);
    n6_put_u16_be(tmp + 6, 0u);
    n6_put_u64_be(tmp + 8, in->accept_reserved_through);
    n6_put_u64_be(tmp + 16, in->key_generation);
    (void)memcpy(tmp + 24, in->binding_digest_prefix16, 16u);
    n6_put_u64_be(tmp + 40, in->membership_epoch);
    tmp[48] = NINLIL_N6_ALLOC_INBOUND_RX;
    (void)memcpy(tmp + 52, in->ns_fingerprint12, 12u);
    crc = ninlil_n6_crc32c(tmp, 64u);
    n6_put_u32_be(tmp + 64, crc);
    n6_encode_publish(out, out_len, tmp, NINLIL_N6_RX_VALUE_BYTES);
    return NINLIL_N6_CODEC_OK;
}

ninlil_n6_codec_status_t ninlil_n6_decode_n6rx_value(
    const uint8_t *in,
    size_t in_len,
    ninlil_n6_rx_value_t *out)
{
    ninlil_n6_rx_value_t tmp;
    uint32_t crc_wire;
    uint32_t crc_calc;
    ninlil_n6_codec_status_t st;

    st = n6_decode_prep(in, in_len, NINLIL_N6_RX_VALUE_BYTES, out, sizeof(*out));
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.magic = n6_get_u32_be(in + 0);
    tmp.schema = n6_get_u16_be(in + 4);
    tmp.reserved0 = n6_get_u16_be(in + 6);
    tmp.accept_reserved_through = n6_get_u64_be(in + 8);
    tmp.key_generation = n6_get_u64_be(in + 16);
    (void)memcpy(tmp.binding_digest_prefix16, in + 24, 16u);
    tmp.membership_epoch = n6_get_u64_be(in + 40);
    tmp.alloc_side = in[48];
    tmp.reserved1[0] = in[49];
    tmp.reserved1[1] = in[50];
    tmp.reserved1[2] = in[51];
    (void)memcpy(tmp.ns_fingerprint12, in + 52, 12u);
    crc_wire = n6_get_u32_be(in + 64);
    tmp.value_crc32c = crc_wire;
    crc_calc = ninlil_n6_crc32c(in, 64u);
    if (tmp.magic != NINLIL_N6_MAGIC_RX || tmp.schema != NINLIL_N6_SCHEMA_LANE
        || tmp.reserved0 != 0u
        || tmp.alloc_side != NINLIL_N6_ALLOC_INBOUND_RX
        || tmp.reserved1[0] != 0u || tmp.reserved1[1] != 0u
        || tmp.reserved1[2] != 0u || !n6_kgen_ok(tmp.key_generation)
        || !n6_epoch_ok(tmp.membership_epoch)
        || crc_wire != crc_calc) {
        return NINLIL_N6_CODEC_REJECT;
    }
    *out = tmp;
    return NINLIL_N6_CODEC_OK;
}

/* ---- N6HW ---- */

ninlil_n6_codec_status_t ninlil_n6_encode_n6hw_key(
    const ninlil_n6_hw_key_t *in,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len)
{
    uint8_t tmp[NINLIL_N6_HW_KEY_BYTES];
    ninlil_n6_codec_status_t st;

    st = n6_encode_prep(in, sizeof(*in), out, out_cap, out_len,
        NINLIL_N6_HW_KEY_BYTES);
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    if (in->rec_kind != NINLIL_N6_REC_KIND_HW || in->reserved0 != 0u
        || !n6_layer_ok(in->layer_code) || !n6_dir_ok(in->direction_code)) {
        return NINLIL_N6_CODEC_REJECT;
    }
    (void)memset(tmp, 0, sizeof(tmp));
    tmp[0] = NINLIL_N6_REC_KIND_HW;
    tmp[1] = in->layer_code;
    tmp[2] = in->direction_code;
    tmp[3] = 0u;
    (void)memcpy(tmp + 4, in->scope_digest28, 28u);
    n6_encode_publish(out, out_len, tmp, NINLIL_N6_HW_KEY_BYTES);
    return NINLIL_N6_CODEC_OK;
}

ninlil_n6_codec_status_t ninlil_n6_decode_n6hw_key(
    const uint8_t *in,
    size_t in_len,
    ninlil_n6_hw_key_t *out)
{
    ninlil_n6_hw_key_t tmp;
    ninlil_n6_codec_status_t st;

    st = n6_decode_prep(in, in_len, NINLIL_N6_HW_KEY_BYTES, out, sizeof(*out));
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.rec_kind = in[0];
    tmp.layer_code = in[1];
    tmp.direction_code = in[2];
    tmp.reserved0 = in[3];
    (void)memcpy(tmp.scope_digest28, in + 4, 28u);
    if (tmp.rec_kind != NINLIL_N6_REC_KIND_HW || tmp.reserved0 != 0u
        || !n6_layer_ok(tmp.layer_code) || !n6_dir_ok(tmp.direction_code)) {
        return NINLIL_N6_CODEC_REJECT;
    }
    *out = tmp;
    return NINLIL_N6_CODEC_OK;
}

ninlil_n6_codec_status_t ninlil_n6_encode_n6hw_value(
    const ninlil_n6_hw_value_t *in,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len)
{
    uint8_t tmp[NINLIL_N6_HW_VALUE_BYTES];
    uint32_t crc;
    ninlil_n6_codec_status_t st;

    st = n6_encode_prep(in, sizeof(*in), out, out_cap, out_len,
        NINLIL_N6_HW_VALUE_BYTES);
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    if (in->magic != NINLIL_N6_MAGIC_HW || in->schema != NINLIL_N6_SCHEMA_HW
        || in->reserved0 != 0u
        || !n6_kgen_ok(in->high_water_key_generation)) {
        return NINLIL_N6_CODEC_REJECT;
    }
    (void)memset(tmp, 0, sizeof(tmp));
    n6_put_u32_be(tmp + 0, NINLIL_N6_MAGIC_HW);
    n6_put_u16_be(tmp + 4, NINLIL_N6_SCHEMA_HW);
    n6_put_u16_be(tmp + 6, 0u);
    n6_put_u64_be(tmp + 8, in->high_water_key_generation);
    n6_put_u64_be(tmp + 16, in->last_update_authority_now_ms);
    crc = ninlil_n6_crc32c(tmp, 24u);
    n6_put_u32_be(tmp + 24, crc);
    n6_encode_publish(out, out_len, tmp, NINLIL_N6_HW_VALUE_BYTES);
    return NINLIL_N6_CODEC_OK;
}

ninlil_n6_codec_status_t ninlil_n6_decode_n6hw_value(
    const uint8_t *in,
    size_t in_len,
    ninlil_n6_hw_value_t *out)
{
    ninlil_n6_hw_value_t tmp;
    uint32_t crc_wire;
    uint32_t crc_calc;
    ninlil_n6_codec_status_t st;

    st = n6_decode_prep(in, in_len, NINLIL_N6_HW_VALUE_BYTES, out, sizeof(*out));
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.magic = n6_get_u32_be(in + 0);
    tmp.schema = n6_get_u16_be(in + 4);
    tmp.reserved0 = n6_get_u16_be(in + 6);
    tmp.high_water_key_generation = n6_get_u64_be(in + 8);
    tmp.last_update_authority_now_ms = n6_get_u64_be(in + 16);
    crc_wire = n6_get_u32_be(in + 24);
    tmp.value_crc32c = crc_wire;
    crc_calc = ninlil_n6_crc32c(in, 24u);
    if (tmp.magic != NINLIL_N6_MAGIC_HW || tmp.schema != NINLIL_N6_SCHEMA_HW
        || tmp.reserved0 != 0u
        || !n6_kgen_ok(tmp.high_water_key_generation)
        || crc_wire != crc_calc) {
        return NINLIL_N6_CODEC_REJECT;
    }
    *out = tmp;
    return NINLIL_N6_CODEC_OK;
}

/* ---- N6AL ---- */

ninlil_n6_codec_status_t ninlil_n6_encode_n6al_key(
    const ninlil_n6_al_key_t *in,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len)
{
    uint8_t tmp[NINLIL_N6_AL_KEY_BYTES];
    ninlil_n6_codec_status_t st;

    st = n6_encode_prep(in, sizeof(*in), out, out_cap, out_len,
        NINLIL_N6_AL_KEY_BYTES);
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    if (in->rec_kind != NINLIL_N6_REC_KIND_AL || in->reserved0 != 0u
        || !n6_layer_ok(in->layer_code) || !n6_alloc_ok(in->alloc_side)
        || !n6_epoch_ok(in->membership_epoch)) {
        return NINLIL_N6_CODEC_REJECT;
    }
    (void)memset(tmp, 0, sizeof(tmp));
    tmp[0] = NINLIL_N6_REC_KIND_AL;
    tmp[1] = in->layer_code;
    tmp[2] = in->alloc_side;
    tmp[3] = 0u;
    n6_put_u64_be(tmp + 4, in->membership_epoch);
    (void)memcpy(tmp + 12, in->ns_fingerprint12, 12u);
    n6_encode_publish(out, out_len, tmp, NINLIL_N6_AL_KEY_BYTES);
    return NINLIL_N6_CODEC_OK;
}

ninlil_n6_codec_status_t ninlil_n6_decode_n6al_key(
    const uint8_t *in,
    size_t in_len,
    ninlil_n6_al_key_t *out)
{
    ninlil_n6_al_key_t tmp;
    ninlil_n6_codec_status_t st;

    st = n6_decode_prep(in, in_len, NINLIL_N6_AL_KEY_BYTES, out, sizeof(*out));
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.rec_kind = in[0];
    tmp.layer_code = in[1];
    tmp.alloc_side = in[2];
    tmp.reserved0 = in[3];
    tmp.membership_epoch = n6_get_u64_be(in + 4);
    (void)memcpy(tmp.ns_fingerprint12, in + 12, 12u);
    if (tmp.rec_kind != NINLIL_N6_REC_KIND_AL || tmp.reserved0 != 0u
        || !n6_layer_ok(tmp.layer_code) || !n6_alloc_ok(tmp.alloc_side)
        || !n6_epoch_ok(tmp.membership_epoch)) {
        return NINLIL_N6_CODEC_REJECT;
    }
    *out = tmp;
    return NINLIL_N6_CODEC_OK;
}

ninlil_n6_codec_status_t ninlil_n6_encode_n6al_value(
    const ninlil_n6_al_value_t *in,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len)
{
    uint8_t tmp[NINLIL_N6_AL_VALUE_BYTES];
    uint32_t crc;
    ninlil_n6_codec_status_t st;

    st = n6_encode_prep(in, sizeof(*in), out, out_cap, out_len,
        NINLIL_N6_AL_VALUE_BYTES);
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    if (in->magic != NINLIL_N6_MAGIC_AL || in->schema != NINLIL_N6_SCHEMA_AL
        || in->reserved0 != 0u || in->reserved1 != 0u
        || in->next_free_or_peer_floor == 0u
        || !n6_epoch_ok(in->membership_epoch)) {
        return NINLIL_N6_CODEC_REJECT;
    }
    (void)memset(tmp, 0, sizeof(tmp));
    n6_put_u32_be(tmp + 0, NINLIL_N6_MAGIC_AL);
    n6_put_u16_be(tmp + 4, NINLIL_N6_SCHEMA_AL);
    n6_put_u16_be(tmp + 6, 0u);
    n6_put_u32_be(tmp + 8, in->next_free_or_peer_floor);
    n6_put_u16_be(tmp + 12, in->active_count);
    n6_put_u16_be(tmp + 14, in->retired_tombstone_count);
    n6_put_u32_be(tmp + 16, 0u);
    n6_put_u64_be(tmp + 20, in->membership_epoch);
    n6_put_u64_be(tmp + 28, in->last_alloc_authority_now_ms);
    (void)memcpy(tmp + 36, in->receiver_node_id, 16u);
    crc = ninlil_n6_crc32c(tmp, 52u);
    n6_put_u32_be(tmp + 52, crc);
    n6_encode_publish(out, out_len, tmp, NINLIL_N6_AL_VALUE_BYTES);
    return NINLIL_N6_CODEC_OK;
}

ninlil_n6_codec_status_t ninlil_n6_decode_n6al_value(
    const uint8_t *in,
    size_t in_len,
    ninlil_n6_al_value_t *out)
{
    ninlil_n6_al_value_t tmp;
    uint32_t crc_wire;
    uint32_t crc_calc;
    ninlil_n6_codec_status_t st;

    st = n6_decode_prep(in, in_len, NINLIL_N6_AL_VALUE_BYTES, out, sizeof(*out));
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.magic = n6_get_u32_be(in + 0);
    tmp.schema = n6_get_u16_be(in + 4);
    tmp.reserved0 = n6_get_u16_be(in + 6);
    tmp.next_free_or_peer_floor = n6_get_u32_be(in + 8);
    tmp.active_count = n6_get_u16_be(in + 12);
    tmp.retired_tombstone_count = n6_get_u16_be(in + 14);
    tmp.reserved1 = n6_get_u32_be(in + 16);
    tmp.membership_epoch = n6_get_u64_be(in + 20);
    tmp.last_alloc_authority_now_ms = n6_get_u64_be(in + 28);
    (void)memcpy(tmp.receiver_node_id, in + 36, 16u);
    crc_wire = n6_get_u32_be(in + 52);
    tmp.value_crc32c = crc_wire;
    crc_calc = ninlil_n6_crc32c(in, 52u);
    if (tmp.magic != NINLIL_N6_MAGIC_AL || tmp.schema != NINLIL_N6_SCHEMA_AL
        || tmp.reserved0 != 0u || tmp.reserved1 != 0u
        || tmp.next_free_or_peer_floor == 0u
        || !n6_epoch_ok(tmp.membership_epoch) || crc_wire != crc_calc) {
        return NINLIL_N6_CODEC_REJECT;
    }
    *out = tmp;
    return NINLIL_N6_CODEC_OK;
}

/* ---- N6RT ---- */

ninlil_n6_codec_status_t ninlil_n6_encode_n6rt_key(
    const ninlil_n6_rt_key_t *in,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len)
{
    uint8_t tmp[NINLIL_N6_RT_KEY_BYTES];
    ninlil_n6_codec_status_t st;

    st = n6_encode_prep(in, sizeof(*in), out, out_cap, out_len,
        NINLIL_N6_RT_KEY_BYTES);
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    if (in->rec_kind != NINLIL_N6_REC_KIND_RT
        || !n6_layer_ok(in->layer_code) || !n6_dir_ok(in->direction_code)
        || !n6_alloc_ok(in->alloc_side) || !n6_context_id_ok(in->context_id)
        || !n6_epoch_ok(in->membership_epoch)) {
        return NINLIL_N6_CODEC_REJECT;
    }
    (void)memset(tmp, 0, sizeof(tmp));
    tmp[0] = NINLIL_N6_REC_KIND_RT;
    tmp[1] = in->layer_code;
    tmp[2] = in->direction_code;
    tmp[3] = in->alloc_side;
    n6_put_u32_be(tmp + 4, in->context_id);
    n6_put_u64_be(tmp + 8, in->membership_epoch);
    (void)memcpy(tmp + 16, in->ns_fingerprint12, 12u);
    n6_encode_publish(out, out_len, tmp, NINLIL_N6_RT_KEY_BYTES);
    return NINLIL_N6_CODEC_OK;
}

ninlil_n6_codec_status_t ninlil_n6_decode_n6rt_key(
    const uint8_t *in,
    size_t in_len,
    ninlil_n6_rt_key_t *out)
{
    ninlil_n6_rt_key_t tmp;
    ninlil_n6_codec_status_t st;

    st = n6_decode_prep(in, in_len, NINLIL_N6_RT_KEY_BYTES, out, sizeof(*out));
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.rec_kind = in[0];
    tmp.layer_code = in[1];
    tmp.direction_code = in[2];
    tmp.alloc_side = in[3];
    tmp.context_id = n6_get_u32_be(in + 4);
    tmp.membership_epoch = n6_get_u64_be(in + 8);
    (void)memcpy(tmp.ns_fingerprint12, in + 16, 12u);
    if (tmp.rec_kind != NINLIL_N6_REC_KIND_RT
        || !n6_layer_ok(tmp.layer_code) || !n6_dir_ok(tmp.direction_code)
        || !n6_alloc_ok(tmp.alloc_side)
        || !n6_context_id_ok(tmp.context_id)
        || !n6_epoch_ok(tmp.membership_epoch)) {
        return NINLIL_N6_CODEC_REJECT;
    }
    *out = tmp;
    return NINLIL_N6_CODEC_OK;
}

ninlil_n6_codec_status_t ninlil_n6_encode_n6rt_value(
    const ninlil_n6_rt_value_t *in,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len)
{
    uint8_t tmp[NINLIL_N6_RT_VALUE_BYTES];
    uint32_t crc;
    ninlil_n6_codec_status_t st;

    st = n6_encode_prep(in, sizeof(*in), out, out_cap, out_len,
        NINLIL_N6_RT_VALUE_BYTES);
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    if (in->magic != NINLIL_N6_MAGIC_RT || in->schema != NINLIL_N6_SCHEMA_RT
        || in->flags != NINLIL_N6_RT_FLAGS_LANE_ERASED
        || in->reserved0 != 0u
        || !n6_layer_ok(in->layer_code) || !n6_dir_ok(in->direction_code)
        || !n6_alloc_ok(in->alloc_side) || !n6_context_id_ok(in->context_id)
        || !n6_epoch_ok(in->membership_epoch)
        || !n6_kgen_ok(in->last_key_generation_high_water)) {
        return NINLIL_N6_CODEC_REJECT;
    }
    (void)memset(tmp, 0, sizeof(tmp));
    n6_put_u32_be(tmp + 0, NINLIL_N6_MAGIC_RT);
    n6_put_u16_be(tmp + 4, NINLIL_N6_SCHEMA_RT);
    n6_put_u16_be(tmp + 6, NINLIL_N6_RT_FLAGS_LANE_ERASED);
    n6_put_u32_be(tmp + 8, in->context_id);
    n6_put_u64_be(tmp + 12, in->membership_epoch);
    n6_put_u64_be(tmp + 20, in->last_key_generation_high_water);
    (void)memcpy(tmp + 28, in->binding_digest12, 12u);
    tmp[40] = in->alloc_side;
    tmp[41] = in->direction_code;
    tmp[42] = in->layer_code;
    tmp[43] = 0u;
    crc = ninlil_n6_crc32c(tmp, 44u);
    n6_put_u32_be(tmp + 44, crc);
    n6_encode_publish(out, out_len, tmp, NINLIL_N6_RT_VALUE_BYTES);
    return NINLIL_N6_CODEC_OK;
}

ninlil_n6_codec_status_t ninlil_n6_decode_n6rt_value(
    const uint8_t *in,
    size_t in_len,
    ninlil_n6_rt_value_t *out)
{
    ninlil_n6_rt_value_t tmp;
    uint32_t crc_wire;
    uint32_t crc_calc;
    ninlil_n6_codec_status_t st;

    st = n6_decode_prep(in, in_len, NINLIL_N6_RT_VALUE_BYTES, out, sizeof(*out));
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.magic = n6_get_u32_be(in + 0);
    tmp.schema = n6_get_u16_be(in + 4);
    tmp.flags = n6_get_u16_be(in + 6);
    tmp.context_id = n6_get_u32_be(in + 8);
    tmp.membership_epoch = n6_get_u64_be(in + 12);
    tmp.last_key_generation_high_water = n6_get_u64_be(in + 20);
    (void)memcpy(tmp.binding_digest12, in + 28, 12u);
    tmp.alloc_side = in[40];
    tmp.direction_code = in[41];
    tmp.layer_code = in[42];
    tmp.reserved0 = in[43];
    crc_wire = n6_get_u32_be(in + 44);
    tmp.value_crc32c = crc_wire;
    crc_calc = ninlil_n6_crc32c(in, 44u);
    if (tmp.magic != NINLIL_N6_MAGIC_RT || tmp.schema != NINLIL_N6_SCHEMA_RT
        || tmp.flags != NINLIL_N6_RT_FLAGS_LANE_ERASED
        || tmp.reserved0 != 0u
        || !n6_layer_ok(tmp.layer_code) || !n6_dir_ok(tmp.direction_code)
        || !n6_alloc_ok(tmp.alloc_side) || !n6_context_id_ok(tmp.context_id)
        || !n6_epoch_ok(tmp.membership_epoch)
        || !n6_kgen_ok(tmp.last_key_generation_high_water)
        || crc_wire != crc_calc) {
        return NINLIL_N6_CODEC_REJECT;
    }
    *out = tmp;
    return NINLIL_N6_CODEC_OK;
}

/* ---- N6CF ---- */

ninlil_n6_codec_status_t ninlil_n6_encode_n6cf_key(
    const ninlil_n6_cf_key_t *in,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len)
{
    uint8_t tmp[NINLIL_N6_CF_KEY_BYTES];
    ninlil_n6_codec_status_t st;

    st = n6_encode_prep(in, sizeof(*in), out, out_cap, out_len,
        NINLIL_N6_CF_KEY_BYTES);
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    if (in->rec_kind != NINLIL_N6_REC_KIND_CF
        || !n6_layer_ok(in->layer_code) || !n6_dir_ok(in->direction_code)
        || !n6_alloc_ok(in->alloc_side) || !n6_context_id_ok(in->context_id)
        || !n6_epoch_ok(in->membership_epoch)) {
        return NINLIL_N6_CODEC_REJECT;
    }
    (void)memset(tmp, 0, sizeof(tmp));
    tmp[0] = NINLIL_N6_REC_KIND_CF;
    tmp[1] = in->layer_code;
    tmp[2] = in->direction_code;
    tmp[3] = in->alloc_side;
    n6_put_u32_be(tmp + 4, in->context_id);
    n6_put_u64_be(tmp + 8, in->membership_epoch);
    (void)memcpy(tmp + 16, in->ns_fingerprint12, 12u);
    n6_encode_publish(out, out_len, tmp, NINLIL_N6_CF_KEY_BYTES);
    return NINLIL_N6_CODEC_OK;
}

ninlil_n6_codec_status_t ninlil_n6_decode_n6cf_key(
    const uint8_t *in,
    size_t in_len,
    ninlil_n6_cf_key_t *out)
{
    ninlil_n6_cf_key_t tmp;
    ninlil_n6_codec_status_t st;

    st = n6_decode_prep(in, in_len, NINLIL_N6_CF_KEY_BYTES, out, sizeof(*out));
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.rec_kind = in[0];
    tmp.layer_code = in[1];
    tmp.direction_code = in[2];
    tmp.alloc_side = in[3];
    tmp.context_id = n6_get_u32_be(in + 4);
    tmp.membership_epoch = n6_get_u64_be(in + 8);
    (void)memcpy(tmp.ns_fingerprint12, in + 16, 12u);
    if (tmp.rec_kind != NINLIL_N6_REC_KIND_CF
        || !n6_layer_ok(tmp.layer_code) || !n6_dir_ok(tmp.direction_code)
        || !n6_alloc_ok(tmp.alloc_side)
        || !n6_context_id_ok(tmp.context_id)
        || !n6_epoch_ok(tmp.membership_epoch)) {
        return NINLIL_N6_CODEC_REJECT;
    }
    *out = tmp;
    return NINLIL_N6_CODEC_OK;
}

ninlil_n6_codec_status_t ninlil_n6_encode_n6cf_value(
    const ninlil_n6_cf_value_t *in,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len)
{
    uint8_t tmp[NINLIL_N6_CF_VALUE_BYTES];
    uint32_t crc;
    ninlil_n6_codec_status_t st;

    st = n6_encode_prep(in, sizeof(*in), out, out_cap, out_len,
        NINLIL_N6_CF_VALUE_BYTES);
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    if (in->magic != NINLIL_N6_MAGIC_CF || in->schema != NINLIL_N6_SCHEMA_CF
        || in->flags != NINLIL_N6_CF_FLAGS_FENCE_ACTIVE
        || !n6_fence_reason_ok(in->reason)
        || !n6_layer_ok(in->layer_code) || !n6_dir_ok(in->direction_code)
        || !n6_alloc_ok(in->alloc_side) || !n6_context_id_ok(in->context_id)
        || !n6_epoch_ok(in->membership_epoch)) {
        return NINLIL_N6_CODEC_REJECT;
    }
    (void)memset(tmp, 0, sizeof(tmp));
    n6_put_u32_be(tmp + 0, NINLIL_N6_MAGIC_CF);
    n6_put_u16_be(tmp + 4, NINLIL_N6_SCHEMA_CF);
    n6_put_u16_be(tmp + 6, NINLIL_N6_CF_FLAGS_FENCE_ACTIVE);
    n6_put_u32_be(tmp + 8, in->context_id);
    n6_put_u64_be(tmp + 12, in->membership_epoch);
    (void)memcpy(tmp + 20, in->fence_stamp_epoch_id, 16u);
    n6_put_u64_be(tmp + 36, in->fence_stamp_now_ms);
    (void)memcpy(tmp + 44, in->binding_digest12, 12u);
    tmp[56] = in->alloc_side;
    tmp[57] = in->direction_code;
    tmp[58] = in->layer_code;
    tmp[59] = in->reason;
    crc = ninlil_n6_crc32c(tmp, 60u);
    n6_put_u32_be(tmp + 60, crc);
    n6_encode_publish(out, out_len, tmp, NINLIL_N6_CF_VALUE_BYTES);
    return NINLIL_N6_CODEC_OK;
}

ninlil_n6_codec_status_t ninlil_n6_decode_n6cf_value(
    const uint8_t *in,
    size_t in_len,
    ninlil_n6_cf_value_t *out)
{
    ninlil_n6_cf_value_t tmp;
    uint32_t crc_wire;
    uint32_t crc_calc;
    ninlil_n6_codec_status_t st;

    st = n6_decode_prep(in, in_len, NINLIL_N6_CF_VALUE_BYTES, out, sizeof(*out));
    if (st != NINLIL_N6_CODEC_OK) {
        return st;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.magic = n6_get_u32_be(in + 0);
    tmp.schema = n6_get_u16_be(in + 4);
    tmp.flags = n6_get_u16_be(in + 6);
    tmp.context_id = n6_get_u32_be(in + 8);
    tmp.membership_epoch = n6_get_u64_be(in + 12);
    (void)memcpy(tmp.fence_stamp_epoch_id, in + 20, 16u);
    tmp.fence_stamp_now_ms = n6_get_u64_be(in + 36);
    (void)memcpy(tmp.binding_digest12, in + 44, 12u);
    tmp.alloc_side = in[56];
    tmp.direction_code = in[57];
    tmp.layer_code = in[58];
    tmp.reason = in[59];
    crc_wire = n6_get_u32_be(in + 60);
    tmp.value_crc32c = crc_wire;
    crc_calc = ninlil_n6_crc32c(in, 60u);
    if (tmp.magic != NINLIL_N6_MAGIC_CF || tmp.schema != NINLIL_N6_SCHEMA_CF
        || tmp.flags != NINLIL_N6_CF_FLAGS_FENCE_ACTIVE
        || !n6_fence_reason_ok(tmp.reason)
        || !n6_layer_ok(tmp.layer_code) || !n6_dir_ok(tmp.direction_code)
        || !n6_alloc_ok(tmp.alloc_side) || !n6_context_id_ok(tmp.context_id)
        || !n6_epoch_ok(tmp.membership_epoch)
        || crc_wire != crc_calc) {
        return NINLIL_N6_CODEC_REJECT;
    }
    *out = tmp;
    return NINLIL_N6_CODEC_OK;
}
