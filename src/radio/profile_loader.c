/*
 * R5 LAB_ONLY profile loader + full §9.3 permit bind (host candidate).
 * docs/29 + ADR-0009. No Japan production claims. R2 durable schema1 unchanged.
 *
 * SEMANTIC: R5_HOST_CANDIDATE_ONLY
 * SEMANTIC: LAB_ONLY_FAIL_CLOSED
 * SEMANTIC: FULL_BIND_MATRIX_ISSUE_AND_CONSUME
 * SEMANTIC: NO_JAPAN_PRODUCTION_NUMERIC_CLAIM
 * SEMANTIC: R2_DURABLE_SCHEMA1_UNCHANGED
 * SEMANTIC: BIND_ITEM_SINGLE_MISMATCH_DENY
 * SEMANTIC: R2_ASSIGNMENT_GENERATION_SYNC
 */

#include "profile_loader.h"

#include <string.h>

#define R5_LC_ZERO ((uint32_t)0u)
#define R5_LC_ACTIVE ((uint32_t)1u)
#define R5_LC_SHUTDOWN ((uint32_t)2u)

/* ---- LE helpers / CRC (same family as R2) ---- */

static void r5_put_u16_le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
}

static void r5_put_u32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}

static void r5_put_u64_le(uint8_t *p, uint64_t v)
{
    r5_put_u32_le(p, (uint32_t)(v & 0xffffffffu));
    r5_put_u32_le(p + 4, (uint32_t)((v >> 32) & 0xffffffffu));
}

static void r5_put_i32_le(uint8_t *p, int32_t v)
{
    r5_put_u32_le(p, (uint32_t)v);
}

static uint16_t r5_get_u16_le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t r5_get_u32_le(const uint8_t *p)
{
    return (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

static uint64_t r5_get_u64_le(const uint8_t *p)
{
    return (uint64_t)r5_get_u32_le(p)
        | ((uint64_t)r5_get_u32_le(p + 4) << 32);
}

static int32_t r5_get_i32_le(const uint8_t *p)
{
    return (int32_t)r5_get_u32_le(p);
}

static uint32_t r5_crc32(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xffffffffu;
    size_t i;
    unsigned b;

    for (i = 0u; i < len; ++i) {
        crc ^= (uint32_t)data[i];
        for (b = 0u; b < 8u; ++b) {
            uint32_t mask = (uint32_t)-(int32_t)(crc & 1u);
            crc = (crc >> 1) ^ (0xedb88320u & mask);
        }
    }
    return crc ^ 0xffffffffu;
}

static void r5_sat_inc(uint64_t *c)
{
    if (*c != UINT64_MAX) {
        *c += 1u;
    }
}

static int r5_id_is_zero(const ninlil_radio_hal_id_t *id)
{
    size_t i;
    for (i = 0u; i < NINLIL_R5_ID_BYTES; ++i) {
        if (id->bytes[i] != 0u) {
            return 0;
        }
    }
    return 1;
}


static int r5_ranges_overlap_u(uintptr_t a, size_t asz, uintptr_t b, size_t bsz)
{
    uintptr_t a_end;
    uintptr_t b_end;

    if (asz == 0u || bsz == 0u) {
        return 0;
    }
    if (a > UINTPTR_MAX - (uintptr_t)(asz - 1u)) {
        return 1;
    }
    if (b > UINTPTR_MAX - (uintptr_t)(bsz - 1u)) {
        return 1;
    }
    a_end = a + (uintptr_t)(asz - 1u);
    b_end = b + (uintptr_t)(bsz - 1u);
    return !(a_end < b || b_end < a);
}

static int r5_ranges_overlap_ptr(const void *a, size_t asz, const void *b, size_t bsz)
{
    if (a == NULL || b == NULL) {
        return 0;
    }
    return r5_ranges_overlap_u((uintptr_t)a, asz, (uintptr_t)b, bsz);
}

/*
 * Fixed-length profile docs (HW/REG): geometric alias length for untrusted
 * doc_len. Cap at expected_bytes+1 so SIZE_MAX / pure oversize does not
 * overflow-fail into ALIAS; decoder still returns STRUCT+OVERSIZE for oversize.
 */
static size_t r5_doc_alias_check_len(size_t expected_bytes, size_t doc_len)
{
    if (doc_len == 0u || expected_bytes == 0u) {
        return 0u;
    }
    if (doc_len > expected_bytes) {
        return expected_bytes + 1u;
    }
    return doc_len;
}

static int r5_out_error_safe(
    const ninlil_r5_t *r5,
    ninlil_r5_error_t *out_error)
{
    if (out_error == NULL) {
        return 0;
    }
    if (r5 != NULL
        && r5_ranges_overlap_ptr(r5, sizeof(*r5), out_error, sizeof(*out_error))) {
        return 0;
    }
    return 1;
}

static int r5_id_equal(
    const ninlil_radio_hal_id_t *a,
    const ninlil_radio_hal_id_t *b)
{
    return memcmp(a->bytes, b->bytes, NINLIL_R5_ID_BYTES) == 0;
}

static int r5_phy_equal(
    const ninlil_radio_hal_phy_t *a,
    const ninlil_radio_hal_phy_t *b)
{
    return a->bandwidth_hz == b->bandwidth_hz
        && a->spreading_factor == b->spreading_factor
        && a->coding_rate_denom == b->coding_rate_denom
        && a->preamble_symbols == b->preamble_symbols
        && a->tx_power_mdb == b->tx_power_mdb
        && a->phy_flags == b->phy_flags;
}

static int r5_digest_equal(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, NINLIL_R5_DIGEST_BYTES) == 0;
}

/* Exact full-struct equality (canonical profiles are zero-filled on decode). */
static int r5_hw_full_equal(
    const ninlil_r5_hardware_profile_t *a,
    const ninlil_r5_hardware_profile_t *b)
{
    return memcmp(a, b, sizeof(*a)) == 0;
}

static int r5_reg_full_equal(
    const ninlil_r5_regulatory_profile_t *a,
    const ninlil_r5_regulatory_profile_t *b)
{
    return memcmp(a, b, sizeof(*a)) == 0;
}

/*
 * Global R5 ALIAS rejection contract (public APIs returning NINLIL_R5_ALIAS):
 * On ANY alias reject return NINLIL_R5_ALIAS only — zero mutation of owner
 * (last_error/stats/registry/in_api), full const inputs/candidates, referenced
 * bounded bytes, and unsafe out_error canaries. Prefer zero mutation of all
 * outputs on ALIAS; a safe disjoint out_error may receive a diagnostic only
 * when that write cannot touch aliased input (issue/compose gates write none).
 * Fixed-size containers first; then bounded frame/doc bytes where applicable.
 * Const-input↔const-input (plan↔proposed) is not rejected.
 */

static void r5_set_error(
    ninlil_r5_t *r5,
    ninlil_r5_error_t *out_error,
    int out_safe,
    ninlil_r5_status_t status,
    ninlil_r5_stage_t stage,
    ninlil_r5_reason_t reason,
    ninlil_r5_bind_item_t bind_item,
    const char *hint)
{
    ninlil_r5_error_t *err = &r5->last_error;
    size_t i;

    (void)memset(err, 0, sizeof(*err));
    err->status = status;
    err->stage = stage;
    err->reason = reason;
    err->bind_item = bind_item;
    if (hint != NULL) {
        for (i = 0u; i + 1u < NINLIL_R5_HINT_BYTES && hint[i] != '\0'; ++i) {
            err->hint[i] = hint[i];
        }
        err->hint[i] = '\0';
    }
    if (out_safe != 0 && out_error != NULL) {
        *out_error = *err;
    }
}

static int r5_guard_active(
    ninlil_r5_t *r5,
    ninlil_r5_error_t *out_error,
    int *out_safe,
    ninlil_r5_stage_t stage)
{
    *out_safe = 0;
    if (r5 == NULL) {
        return 0;
    }
    *out_safe = r5_out_error_safe(r5, out_error);
    if (r5->magic != NINLIL_R5_MAGIC_VALUE || r5->lifecycle != R5_LC_ACTIVE) {
        r5_set_error(
            r5, out_error, *out_safe, NINLIL_R5_INVALID_STATE, stage,
            NINLIL_R5_REASON_SHUTDOWN, NINLIL_R5_BIND_NONE, "not_active");
        return 0;
    }
    if (r5->in_api != 0u) {
        r5_set_error(
            r5, out_error, *out_safe, NINLIL_R5_BUSY_REENTRY, stage,
            NINLIL_R5_REASON_REENTRY, NINLIL_R5_BIND_NONE, "reentry");
        return 0;
    }
    return 1;
}

/* ---- Encode / decode profiles ---- */

ninlil_r5_status_t ninlil_r5_encode_hardware_profile(
    const ninlil_r5_hardware_profile_t *hw,
    uint8_t out_doc[NINLIL_R5_HW_DOC_BYTES])
{
    if (hw == NULL || out_doc == NULL) {
        return NINLIL_R5_INVALID_ARGUMENT;
    }
    if (r5_ranges_overlap_ptr(hw, sizeof(*hw), out_doc, NINLIL_R5_HW_DOC_BYTES)) {
        return NINLIL_R5_ALIAS;
    }
    if (r5_id_is_zero(&hw->profile_id) || hw->profile_rev == 0u
        || r5_id_is_zero(&hw->device_model_id)
        || r5_id_is_zero(&hw->radio_sku_id) || hw->hardware_revision == 0u
        || r5_id_is_zero(&hw->antenna_model_id)
        || hw->available_bearer_count == 0u
        || hw->available_bearer_count > 4u) {
        return NINLIL_R5_STRUCT;
    }
    (void)memset(out_doc, 0, NINLIL_R5_HW_DOC_BYTES);
    r5_put_u32_le(out_doc + 0, NINLIL_R5_HW_MAGIC);
    r5_put_u16_le(out_doc + 4, NINLIL_R5_SCHEMA_VERSION);
    r5_put_u16_le(out_doc + 6, 0u);
    (void)memcpy(out_doc + 8, hw->profile_id.bytes, 16u);
    r5_put_u32_le(out_doc + 24, hw->profile_rev);
    (void)memcpy(out_doc + 28, hw->device_model_id.bytes, 16u);
    (void)memcpy(out_doc + 44, hw->radio_sku_id.bytes, 16u);
    r5_put_u32_le(out_doc + 60, hw->hardware_revision);
    (void)memcpy(out_doc + 64, hw->antenna_model_id.bytes, 16u);
    r5_put_i32_le(out_doc + 80, hw->antenna_gain_mdb);
    r5_put_u32_le(out_doc + 84, hw->available_bearer_count);
    r5_put_u32_le(out_doc + 124, r5_crc32(out_doc, 124u));
    return NINLIL_R5_OK;
}

ninlil_r5_status_t ninlil_r5_encode_regulatory_profile(
    const ninlil_r5_regulatory_profile_t *reg,
    uint8_t out_doc[NINLIL_R5_REG_DOC_BYTES])
{
    if (reg == NULL || out_doc == NULL) {
        return NINLIL_R5_INVALID_ARGUMENT;
    }
    if (r5_ranges_overlap_ptr(
            reg, sizeof(*reg), out_doc, NINLIL_R5_REG_DOC_BYTES)) {
        return NINLIL_R5_ALIAS;
    }
    if (r5_id_is_zero(&reg->profile_id) || reg->profile_rev == 0u
        || reg->approval_state != NINLIL_R5_APPROVAL_LAB_ONLY
        || reg->reserved_zero != 0u || reg->reserved_zero2 != 0u
        || r5_id_is_zero(&reg->applicable_hardware_profile_id)
        || reg->applicable_hw_rev_min == 0u
        || reg->applicable_hw_rev_max < reg->applicable_hw_rev_min
        || reg->channel_id_min == 0u
        || reg->channel_id_max < reg->channel_id_min
        || reg->max_airtime_ceiling_us == 0u
        || reg->airtime_formula_version != NINLIL_AIRTIME_FORMULA_VERSION
        || reg->bw_hz == 0u || reg->sf_min < NINLIL_AIRTIME_SF_MIN
        || reg->sf_max > NINLIL_AIRTIME_SF_MAX || reg->sf_max < reg->sf_min
        || reg->cr_denom_min < 5u || reg->cr_denom_max > 8u
        || reg->cr_denom_max < reg->cr_denom_min
        || reg->preamble_symbols_min < NINLIL_AIRTIME_PREAMBLE_MIN
        || reg->preamble_symbols_max < reg->preamble_symbols_min
        || reg->tx_power_mdb_max < reg->tx_power_mdb_min
        || (reg->profile_expiry_ms != 0u
            && reg->profile_expiry_ms <= reg->effective_not_before_ms)) {
        return NINLIL_R5_STRUCT;
    }
    (void)memset(out_doc, 0, NINLIL_R5_REG_DOC_BYTES);
    r5_put_u32_le(out_doc + 0, NINLIL_R5_REG_MAGIC);
    r5_put_u16_le(out_doc + 4, NINLIL_R5_SCHEMA_VERSION);
    out_doc[6] = reg->approval_state;
    out_doc[7] = 0u;
    (void)memcpy(out_doc + 8, reg->profile_id.bytes, 16u);
    r5_put_u32_le(out_doc + 24, reg->profile_rev);
    r5_put_u32_le(out_doc + 28, reg->region_code);
    r5_put_u32_le(out_doc + 32, reg->service_category);
    (void)memcpy(out_doc + 36, reg->applicable_hardware_profile_id.bytes, 16u);
    r5_put_u32_le(out_doc + 52, reg->applicable_hw_rev_min);
    r5_put_u32_le(out_doc + 56, reg->applicable_hw_rev_max);
    r5_put_u32_le(out_doc + 60, reg->channel_id_min);
    r5_put_u32_le(out_doc + 64, reg->channel_id_max);
    r5_put_u32_le(out_doc + 68, reg->max_airtime_ceiling_us);
    r5_put_u32_le(out_doc + 72, reg->airtime_formula_version);
    r5_put_u32_le(out_doc + 76, reg->bw_hz);
    out_doc[80] = reg->sf_min;
    out_doc[81] = reg->sf_max;
    out_doc[82] = reg->cr_denom_min;
    out_doc[83] = reg->cr_denom_max;
    r5_put_u16_le(out_doc + 84, reg->preamble_symbols_min);
    r5_put_u16_le(out_doc + 86, reg->preamble_symbols_max);
    r5_put_i32_le(out_doc + 88, reg->tx_power_mdb_min);
    r5_put_i32_le(out_doc + 92, reg->tx_power_mdb_max);
    r5_put_u64_le(out_doc + 96, reg->effective_not_before_ms);
    r5_put_u64_le(out_doc + 104, reg->profile_expiry_ms);
    r5_put_u32_le(out_doc + 156, r5_crc32(out_doc, 156u));
    return NINLIL_R5_OK;
}

static int r5_bw_in_closed_set(uint32_t bw_hz)
{
    static const uint32_t k_bw[NINLIL_AIRTIME_BW_COUNT] = {
        NINLIL_AIRTIME_BW_HZ_0,
        NINLIL_AIRTIME_BW_HZ_1,
        NINLIL_AIRTIME_BW_HZ_2,
        NINLIL_AIRTIME_BW_HZ_3,
        NINLIL_AIRTIME_BW_HZ_4,
        NINLIL_AIRTIME_BW_HZ_5,
        NINLIL_AIRTIME_BW_HZ_6,
        NINLIL_AIRTIME_BW_HZ_7,
        NINLIL_AIRTIME_BW_HZ_8,
        NINLIL_AIRTIME_BW_HZ_9,
    };
    size_t i;
    for (i = 0u; i < NINLIL_AIRTIME_BW_COUNT; ++i) {
        if (k_bw[i] == bw_hz) {
            return 1;
        }
    }
    return 0;
}

static ninlil_r5_status_t r5_decode_hw(
    const uint8_t *doc,
    size_t doc_len,
    ninlil_r5_hardware_profile_t *out,
    ninlil_r5_reason_t *out_reason)
{
    uint32_t magic;
    uint16_t schema;
    uint16_t reserved0;
    uint32_t crc_got;
    uint32_t crc_exp;
    size_t i;

    *out_reason = NINLIL_R5_REASON_STRUCT;
    (void)memset(out, 0, sizeof(*out));
    if (doc == NULL) {
        *out_reason = NINLIL_R5_REASON_NULL_ARG;
        return NINLIL_R5_INVALID_ARGUMENT;
    }
    if (doc_len < NINLIL_R5_HW_DOC_BYTES) {
        *out_reason = NINLIL_R5_REASON_TRUNCATION;
        return NINLIL_R5_STRUCT;
    }
    if (doc_len > NINLIL_R5_HW_DOC_BYTES) {
        *out_reason = NINLIL_R5_REASON_OVERSIZE;
        return NINLIL_R5_STRUCT;
    }
    magic = r5_get_u32_le(doc + 0);
    schema = r5_get_u16_le(doc + 4);
    reserved0 = r5_get_u16_le(doc + 6);
    if (magic != NINLIL_R5_HW_MAGIC || schema != NINLIL_R5_SCHEMA_VERSION
        || reserved0 != 0u) {
        return NINLIL_R5_STRUCT;
    }
    for (i = 88u; i < 124u; ++i) {
        if (doc[i] != 0u) {
            return NINLIL_R5_STRUCT;
        }
    }
    crc_got = r5_get_u32_le(doc + 124);
    crc_exp = r5_crc32(doc, 124u);
    if (crc_got != crc_exp) {
        *out_reason = NINLIL_R5_REASON_CRC;
        return NINLIL_R5_STRUCT;
    }
    (void)memcpy(out->profile_id.bytes, doc + 8, 16u);
    out->profile_rev = r5_get_u32_le(doc + 24);
    (void)memcpy(out->device_model_id.bytes, doc + 28, 16u);
    (void)memcpy(out->radio_sku_id.bytes, doc + 44, 16u);
    out->hardware_revision = r5_get_u32_le(doc + 60);
    (void)memcpy(out->antenna_model_id.bytes, doc + 64, 16u);
    out->antenna_gain_mdb = r5_get_i32_le(doc + 80);
    out->available_bearer_count = r5_get_u32_le(doc + 84);
    if (r5_id_is_zero(&out->profile_id) || out->profile_rev == 0u
        || r5_id_is_zero(&out->device_model_id)
        || r5_id_is_zero(&out->radio_sku_id) || out->hardware_revision == 0u
        || r5_id_is_zero(&out->antenna_model_id)
        || out->available_bearer_count == 0u
        || out->available_bearer_count > 4u) {
        *out_reason = NINLIL_R5_REASON_ZERO_ID;
        return NINLIL_R5_STRUCT;
    }
    *out_reason = NINLIL_R5_REASON_NONE;
    return NINLIL_R5_OK;
}

static ninlil_r5_status_t r5_decode_reg(
    const uint8_t *doc,
    size_t doc_len,
    ninlil_r5_regulatory_profile_t *out,
    ninlil_r5_reason_t *out_reason)
{
    uint32_t magic;
    uint16_t schema;
    uint8_t approval;
    uint8_t reserved0;
    uint32_t crc_got;
    uint32_t crc_exp;
    size_t i;

    *out_reason = NINLIL_R5_REASON_STRUCT;
    (void)memset(out, 0, sizeof(*out));
    if (doc == NULL) {
        *out_reason = NINLIL_R5_REASON_NULL_ARG;
        return NINLIL_R5_INVALID_ARGUMENT;
    }
    if (doc_len < NINLIL_R5_REG_DOC_BYTES) {
        *out_reason = NINLIL_R5_REASON_TRUNCATION;
        return NINLIL_R5_STRUCT;
    }
    if (doc_len > NINLIL_R5_REG_DOC_BYTES) {
        *out_reason = NINLIL_R5_REASON_OVERSIZE;
        return NINLIL_R5_STRUCT;
    }
    magic = r5_get_u32_le(doc + 0);
    schema = r5_get_u16_le(doc + 4);
    approval = doc[6];
    reserved0 = doc[7];
    if (magic != NINLIL_R5_REG_MAGIC || schema != NINLIL_R5_SCHEMA_VERSION
        || reserved0 != 0u) {
        return NINLIL_R5_STRUCT;
    }
    /* SEMANTIC: LAB_ONLY_FAIL_CLOSED */
    if (approval != NINLIL_R5_APPROVAL_LAB_ONLY) {
        if (approval == NINLIL_R5_APPROVAL_CANDIDATE
            || approval == NINLIL_R5_APPROVAL_DEPLOYMENT_APPROVED
            || approval == NINLIL_R5_APPROVAL_REVOKED) {
            *out_reason = NINLIL_R5_REASON_NOT_LAB_ONLY;
        } else {
            *out_reason = NINLIL_R5_REASON_UNKNOWN_APPROVAL;
        }
        return NINLIL_R5_PROFILE_DENIED;
    }
    for (i = 112u; i < 156u; ++i) {
        if (doc[i] != 0u) {
            return NINLIL_R5_STRUCT;
        }
    }
    crc_got = r5_get_u32_le(doc + 156);
    crc_exp = r5_crc32(doc, 156u);
    if (crc_got != crc_exp) {
        *out_reason = NINLIL_R5_REASON_CRC;
        return NINLIL_R5_STRUCT;
    }
    out->approval_state = approval;
    (void)memcpy(out->profile_id.bytes, doc + 8, 16u);
    out->profile_rev = r5_get_u32_le(doc + 24);
    out->region_code = r5_get_u32_le(doc + 28);
    out->service_category = r5_get_u32_le(doc + 32);
    (void)memcpy(out->applicable_hardware_profile_id.bytes, doc + 36, 16u);
    out->applicable_hw_rev_min = r5_get_u32_le(doc + 52);
    out->applicable_hw_rev_max = r5_get_u32_le(doc + 56);
    out->channel_id_min = r5_get_u32_le(doc + 60);
    out->channel_id_max = r5_get_u32_le(doc + 64);
    out->max_airtime_ceiling_us = r5_get_u32_le(doc + 68);
    out->airtime_formula_version = r5_get_u32_le(doc + 72);
    out->bw_hz = r5_get_u32_le(doc + 76);
    out->sf_min = doc[80];
    out->sf_max = doc[81];
    out->cr_denom_min = doc[82];
    out->cr_denom_max = doc[83];
    out->preamble_symbols_min = r5_get_u16_le(doc + 84);
    out->preamble_symbols_max = r5_get_u16_le(doc + 86);
    out->tx_power_mdb_min = r5_get_i32_le(doc + 88);
    out->tx_power_mdb_max = r5_get_i32_le(doc + 92);
    out->effective_not_before_ms = r5_get_u64_le(doc + 96);
    out->profile_expiry_ms = r5_get_u64_le(doc + 104);

    if (r5_id_is_zero(&out->profile_id) || out->profile_rev == 0u
        || r5_id_is_zero(&out->applicable_hardware_profile_id)
        || out->applicable_hw_rev_min == 0u
        || out->applicable_hw_rev_max < out->applicable_hw_rev_min
        || out->channel_id_min == 0u
        || out->channel_id_max < out->channel_id_min
        || out->max_airtime_ceiling_us == 0u) {
        *out_reason = NINLIL_R5_REASON_ZERO_ID;
        return NINLIL_R5_STRUCT;
    }
    if (out->airtime_formula_version != NINLIL_AIRTIME_FORMULA_VERSION) {
        *out_reason = NINLIL_R5_REASON_FORMULA_VERSION;
        return NINLIL_R5_UNSUPPORTED;
    }
    if (!r5_bw_in_closed_set(out->bw_hz) || out->sf_min < NINLIL_AIRTIME_SF_MIN
        || out->sf_max > NINLIL_AIRTIME_SF_MAX || out->sf_max < out->sf_min
        || out->cr_denom_min < 5u || out->cr_denom_max > 8u
        || out->cr_denom_max < out->cr_denom_min
        || out->preamble_symbols_min < NINLIL_AIRTIME_PREAMBLE_MIN
        || out->preamble_symbols_max < out->preamble_symbols_min
        || out->tx_power_mdb_max < out->tx_power_mdb_min
        || (out->profile_expiry_ms != 0u
            && out->profile_expiry_ms <= out->effective_not_before_ms)) {
        *out_reason = NINLIL_R5_REASON_RANGE;
        return NINLIL_R5_STRUCT;
    }
    *out_reason = NINLIL_R5_REASON_NONE;
    return NINLIL_R5_OK;
}

/* ---- Lifecycle ---- */

ninlil_r5_status_t ninlil_r5_init_object(
    ninlil_r5_object_t *object,
    ninlil_r5_t **out_r5)
{
    if (object == NULL || out_r5 == NULL) {
        return NINLIL_R5_INVALID_ARGUMENT;
    }
    if (r5_ranges_overlap_ptr(object, sizeof(*object), out_r5, sizeof(*out_r5))) {
        return NINLIL_R5_ALIAS;
    }
    if (object->magic == NINLIL_R5_MAGIC_VALUE
        && object->lifecycle == R5_LC_ACTIVE) {
        return NINLIL_R5_INVALID_STATE;
    }
    (void)memset(object, 0, sizeof(*object));
    object->magic = NINLIL_R5_MAGIC_VALUE;
    object->lifecycle = R5_LC_ACTIVE;
    *out_r5 = object;
    return NINLIL_R5_OK;
}

ninlil_r5_status_t ninlil_r5_shutdown(
    ninlil_r5_t *r5,
    ninlil_r5_error_t *out_error)
{
    int out_safe = 0;

    if (r5 == NULL) {
        return NINLIL_R5_INVALID_ARGUMENT;
    }
    if (r5->magic != NINLIL_R5_MAGIC_VALUE) {
        return NINLIL_R5_INVALID_STATE;
    }
    out_safe = r5_out_error_safe(r5, out_error);
    if (r5->lifecycle == R5_LC_SHUTDOWN) {
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_OK, NINLIL_R5_STAGE_SHUTDOWN,
            NINLIL_R5_REASON_NONE, NINLIL_R5_BIND_NONE, NULL);
        return NINLIL_R5_OK;
    }
    if (r5->in_api != 0u) {
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_BUSY_REENTRY,
            NINLIL_R5_STAGE_SHUTDOWN, NINLIL_R5_REASON_REENTRY,
            NINLIL_R5_BIND_NONE, "busy");
        return NINLIL_R5_BUSY_REENTRY;
    }
    (void)memset(r5->registry, 0, sizeof(r5->registry));
    r5->registry_count = 0u;
    r5->pcp = NULL;
    r5->pcp_bound = 0u;
    r5->lifecycle = R5_LC_SHUTDOWN;
    r5_set_error(
        r5, out_error, out_safe, NINLIL_R5_OK, NINLIL_R5_STAGE_SHUTDOWN,
        NINLIL_R5_REASON_NONE, NINLIL_R5_BIND_NONE, NULL);
    return NINLIL_R5_OK;
}

/*
 * Call commit_live under R5 in_api so hostile storage callbacks cannot reenter
 * R5 mid-transition. Not a thread-safety claim — single-owner reentry only.
 */
static ninlil_pcp_status_t r5_pcp_commit_live_guarded(
    ninlil_r5_t *r5,
    ninlil_pcp_t *pcp,
    const ninlil_pcp_live_profile_t *live,
    uint64_t generation,
    ninlil_pcp_error_t *perr)
{
    ninlil_pcp_status_t pst;

    r5->in_api = 1u;
    pst = ninlil_pcp_commit_live_binding(pcp, live, generation, perr);
    r5->in_api = 0u;
    return pst;
}

ninlil_r5_status_t ninlil_r5_bind_pcp(
    ninlil_r5_t *r5,
    ninlil_pcp_t *pcp,
    ninlil_r5_error_t *out_error)
{
    int out_safe = 1;
    ninlil_pcp_t *prev_pcp;
    uint32_t prev_bound;

    if (r5 == NULL) {
        return NINLIL_R5_INVALID_ARGUMENT;
    }
    /*
     * Alias before guard / any owner write: owner↔pcp, pcp↔out_error,
     * owner↔out_error → ALIAS with zero mutation.
     */
    if (pcp != NULL
        && (r5_ranges_overlap_ptr(r5, sizeof(*r5), pcp, sizeof(*pcp))
            || (out_error != NULL
                && (r5_ranges_overlap_ptr(
                        pcp, sizeof(*pcp), out_error, sizeof(*out_error))
                    || r5_ranges_overlap_ptr(
                        r5, sizeof(*r5), out_error, sizeof(*out_error)))))) {
        return NINLIL_R5_ALIAS;
    }
    if (pcp == NULL && out_error != NULL
        && r5_ranges_overlap_ptr(
            r5, sizeof(*r5), out_error, sizeof(*out_error))) {
        return NINLIL_R5_ALIAS;
    }
    if (!r5_guard_active(r5, out_error, &out_safe, NINLIL_R5_STAGE_INIT)) {
        return r5->last_error.status;
    }
    out_safe = r5_out_error_safe(r5, out_error);
    prev_pcp = r5->pcp;
    prev_bound = r5->pcp_bound;
    if (pcp == NULL) {
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_INVALID_ARGUMENT,
            NINLIL_R5_STAGE_INIT, NINLIL_R5_REASON_NULL_ARG, NINLIL_R5_BIND_NONE,
            "null_pcp");
        return NINLIL_R5_INVALID_ARGUMENT;
    }
    /*
     * fence_pending: fail-closed before any pointer swap / commit_live.
     * Recovery is recover original PCP then fence_after_revoke retry at the
     * stored target — not rebind to a peer or retarget gen via assignment.
     */
    if (r5->fence_pending != 0u) {
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_INVALID_STATE,
            NINLIL_R5_STAGE_INIT, NINLIL_R5_REASON_PCP,
            NINLIL_R5_BIND_PERMIT_GEN, "fence_pend");
        return NINLIL_R5_INVALID_STATE;
    }
    /*
     * Require ACTIVE PCP. ACTIVE + unpublished allowed (pre-publish).
     * Invalid candidate: preserve previous pcp/pcp_bound.
     */
    if (pcp->magic != NINLIL_PCP_MAGIC_VALUE
        || pcp->lifecycle != NINLIL_PCP_LC_ACTIVE) {
        r5->pcp = prev_pcp;
        r5->pcp_bound = prev_bound;
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_INVALID_ARGUMENT,
            NINLIL_R5_STAGE_INIT, NINLIL_R5_REASON_STRUCT, NINLIL_R5_BIND_NONE,
            "pcp_lc");
        return NINLIL_R5_INVALID_ARGUMENT;
    }
    /* Sync durable generation if assignment already bound — before publish. */
    if (r5->assignment_bound != 0u && r5->profiles_active != 0u) {
        ninlil_pcp_error_t perr;
        ninlil_pcp_status_t pst;
        ninlil_pcp_live_profile_t live;

        (void)memset(&live, 0, sizeof(live));
        live.hardware_profile_id = r5->hw.profile_id;
        live.hardware_profile_rev = r5->hw.profile_rev;
        live.regulatory_profile_id = r5->reg.profile_id;
        live.regulatory_profile_rev = r5->reg.profile_rev;
        live.site_assignment_id = r5->assignment.site_assignment_id;
        live.site_assignment_rev = r5->assignment.site_assignment_rev;
        live.site_assignment_epoch = r5->assignment.site_assignment_epoch;
        live.transmitter_id = r5->assignment.transmitter_id;
        live.channel_id = r5->assignment.channel_id;
        live.phy = r5->assignment.phy;
        live.max_airtime_us = r5->reg.max_airtime_ceiling_us;
        (void)memset(&perr, 0, sizeof(perr));
        pst = r5_pcp_commit_live_guarded(
            r5, pcp, &live, r5->assignment.permit_bind_generation, &perr);
        if (pst != NINLIL_PCP_OK) {
            if (pst == NINLIL_PCP_INVALID_STATE
                && pcp->lifecycle == NINLIL_PCP_LC_ACTIVE
                && pcp->published == 0u) {
                /* pre-publish defer: accept new pointer */
            } else {
                /* Definite/unknown failure: keep previous good authority. */
                r5->pcp = prev_pcp;
                r5->pcp_bound = prev_bound;
                r5_set_error(
                    r5, out_error, out_safe, NINLIL_R5_PCP, NINLIL_R5_STAGE_INIT,
                    NINLIL_R5_REASON_PCP, NINLIL_R5_BIND_PERMIT_GEN, "rebind");
                return NINLIL_R5_PCP;
            }
        }
    }
    /* Publish new non-owning pointer only after accept. */
    r5->pcp = pcp;
    r5->pcp_bound = 1u;
    r5_set_error(
        r5, out_error, out_safe, NINLIL_R5_OK, NINLIL_R5_STAGE_INIT,
        NINLIL_R5_REASON_NONE, NINLIL_R5_BIND_NONE, NULL);
    return NINLIL_R5_OK;
}

/* ---- Load / activate ---- */

ninlil_r5_status_t ninlil_r5_load_hardware_profile(
    ninlil_r5_t *r5,
    const uint8_t *doc,
    size_t doc_len,
    ninlil_r5_error_t *out_error)
{
    int out_safe = 1;
    ninlil_r5_hardware_profile_t hw;
    ninlil_r5_reason_t reason = NINLIL_R5_REASON_NONE;
    ninlil_r5_status_t st;

    if (r5 == NULL) {
        return NINLIL_R5_INVALID_ARGUMENT;
    }
    /* Alias before guard — geometric only (capped); pure oversize is not ALIAS. */
    if (doc != NULL && doc_len > 0u) {
        size_t clen = r5_doc_alias_check_len(NINLIL_R5_HW_DOC_BYTES, doc_len);
        if (clen > 0u
            && (r5_ranges_overlap_ptr(r5, sizeof(*r5), doc, clen)
                || (out_error != NULL
                    && r5_ranges_overlap_ptr(
                        doc, clen, out_error, sizeof(*out_error))))) {
            return NINLIL_R5_ALIAS;
        }
    }
    if (out_error != NULL
        && r5_ranges_overlap_ptr(
            r5, sizeof(*r5), out_error, sizeof(*out_error))) {
        return NINLIL_R5_ALIAS;
    }
    if (!r5_guard_active(r5, out_error, &out_safe, NINLIL_R5_STAGE_LOAD)) {
        return r5->last_error.status;
    }
    st = r5_decode_hw(doc, doc_len, &hw, &reason);
    if (st != NINLIL_R5_OK) {
        r5_sat_inc(&r5->stats.load_hw_deny);
        r5_set_error(
            r5, out_error, out_safe, st, NINLIL_R5_STAGE_LOAD, reason,
            NINLIL_R5_BIND_NONE, "hw_load");
        return st;
    }
    r5->hw_staged = hw;
    r5->hw_staged_loaded = 1u;
    /* staged only — do not clobber active profiles or assignment */
    r5_sat_inc(&r5->stats.load_hw_ok);
    r5_set_error(
        r5, out_error, out_safe, NINLIL_R5_OK, NINLIL_R5_STAGE_LOAD,
        NINLIL_R5_REASON_NONE, NINLIL_R5_BIND_NONE, NULL);
    return NINLIL_R5_OK;
}

ninlil_r5_status_t ninlil_r5_load_regulatory_profile(
    ninlil_r5_t *r5,
    const uint8_t *doc,
    size_t doc_len,
    ninlil_r5_error_t *out_error)
{
    int out_safe = 1;
    ninlil_r5_regulatory_profile_t reg;
    ninlil_r5_reason_t reason = NINLIL_R5_REASON_NONE;
    ninlil_r5_status_t st;

    if (r5 == NULL) {
        return NINLIL_R5_INVALID_ARGUMENT;
    }
    /* Alias before guard — geometric only (capped); pure oversize is not ALIAS. */
    if (doc != NULL && doc_len > 0u) {
        size_t clen = r5_doc_alias_check_len(NINLIL_R5_REG_DOC_BYTES, doc_len);
        if (clen > 0u
            && (r5_ranges_overlap_ptr(r5, sizeof(*r5), doc, clen)
                || (out_error != NULL
                    && r5_ranges_overlap_ptr(
                        doc, clen, out_error, sizeof(*out_error))))) {
            return NINLIL_R5_ALIAS;
        }
    }
    if (out_error != NULL
        && r5_ranges_overlap_ptr(
            r5, sizeof(*r5), out_error, sizeof(*out_error))) {
        return NINLIL_R5_ALIAS;
    }
    if (!r5_guard_active(r5, out_error, &out_safe, NINLIL_R5_STAGE_LOAD)) {
        return r5->last_error.status;
    }
    st = r5_decode_reg(doc, doc_len, &reg, &reason);
    if (st != NINLIL_R5_OK) {
        r5_sat_inc(&r5->stats.load_reg_deny);
        r5_set_error(
            r5, out_error, out_safe, st, NINLIL_R5_STAGE_LOAD, reason,
            NINLIL_R5_BIND_NONE, "reg_load");
        return st;
    }
    r5->reg_staged = reg;
    r5->reg_staged_loaded = 1u;
    r5_sat_inc(&r5->stats.load_reg_ok);
    r5_set_error(
        r5, out_error, out_safe, NINLIL_R5_OK, NINLIL_R5_STAGE_LOAD,
        NINLIL_R5_REASON_NONE, NINLIL_R5_BIND_NONE, NULL);
    return NINLIL_R5_OK;
}

ninlil_r5_status_t ninlil_r5_activate_profiles(
    ninlil_r5_t *r5,
    ninlil_r5_error_t *out_error)
{
    int out_safe = 1;
    ninlil_r5_hardware_profile_t cand_hw;
    ninlil_r5_regulatory_profile_t cand_reg;
    uint64_t target_gen = 0u;
    ninlil_radio_hal_live_binding_t live;
    ninlil_pcp_live_profile_t plive;
    ninlil_pcp_error_t perr;
    ninlil_pcp_status_t pst;
    uint64_t r2_gen = 0u;

    if (!r5_guard_active(r5, out_error, &out_safe, NINLIL_R5_STAGE_ACTIVATE)) {
        return r5 != NULL ? r5->last_error.status : NINLIL_R5_INVALID_ARGUMENT;
    }
    out_safe = r5_out_error_safe(r5, out_error);
    if (r5->hw_staged_loaded == 0u || r5->reg_staged_loaded == 0u) {
        r5_sat_inc(&r5->stats.activate_deny);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_INVALID_STATE,
            NINLIL_R5_STAGE_ACTIVATE, NINLIL_R5_REASON_UNBOUND,
            NINLIL_R5_BIND_NONE, "not_staged");
        return NINLIL_R5_INVALID_STATE;
    }
    if (r5->registry_count != 0u) {
        r5_sat_inc(&r5->stats.activate_deny);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_BUSY_OUTSTANDING,
            NINLIL_R5_STAGE_ACTIVATE, NINLIL_R5_REASON_OUTSTANDING,
            NINLIL_R5_BIND_NONE, "outstanding");
        return NINLIL_R5_BUSY_OUTSTANDING;
    }
    if (r5->fence_pending != 0u) {
        r5_sat_inc(&r5->stats.activate_deny);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_INVALID_STATE,
            NINLIL_R5_STAGE_ACTIVATE, NINLIL_R5_REASON_PCP,
            NINLIL_R5_BIND_PERMIT_GEN, "fence_pend");
        return NINLIL_R5_INVALID_STATE;
    }
    cand_hw = r5->hw_staged;
    cand_reg = r5->reg_staged;
    if (!r5_id_equal(&cand_hw.profile_id, &cand_reg.applicable_hardware_profile_id)
        || cand_hw.profile_rev < cand_reg.applicable_hw_rev_min
        || cand_hw.profile_rev > cand_reg.applicable_hw_rev_max) {
        r5_sat_inc(&r5->stats.activate_deny);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_PROFILE_DENIED,
            NINLIL_R5_STAGE_ACTIVATE, NINLIL_R5_REASON_HW_REG_MISMATCH,
            NINLIL_R5_BIND_NONE, "hw_reg");
        return NINLIL_R5_PROFILE_DENIED;
    }
    if (cand_reg.approval_state != NINLIL_R5_APPROVAL_LAB_ONLY) {
        r5_sat_inc(&r5->stats.activate_deny);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_PROFILE_DENIED,
            NINLIL_R5_STAGE_ACTIVATE, NINLIL_R5_REASON_NOT_LAB_ONLY,
            NINLIL_R5_BIND_NONE, "not_lab");
        return NINLIL_R5_PROFILE_DENIED;
    }
    /* same-id revision rollback fail-closed (docs/29 §2.1) */
    if (r5->profiles_active != 0u) {
        int hw_id_rev_match;
        int reg_id_rev_match;
        int hw_full;
        int reg_full;

        if (r5_id_equal(&r5->hw.profile_id, &cand_hw.profile_id)
            && cand_hw.profile_rev < r5->hw.profile_rev) {
            r5_sat_inc(&r5->stats.activate_deny);
            r5_set_error(
                r5, out_error, out_safe, NINLIL_R5_PROFILE_DENIED,
                NINLIL_R5_STAGE_ACTIVATE, NINLIL_R5_REASON_ROLLBACK,
                NINLIL_R5_BIND_NONE, "hw_rollback");
            return NINLIL_R5_PROFILE_DENIED;
        }
        if (r5_id_equal(&r5->reg.profile_id, &cand_reg.profile_id)
            && cand_reg.profile_rev < r5->reg.profile_rev) {
            r5_sat_inc(&r5->stats.activate_deny);
            r5_set_error(
                r5, out_error, out_safe, NINLIL_R5_PROFILE_DENIED,
                NINLIL_R5_STAGE_ACTIVATE, NINLIL_R5_REASON_ROLLBACK,
                NINLIL_R5_BIND_NONE, "reg_rollback");
            return NINLIL_R5_PROFILE_DENIED;
        }
        /*
         * Same identity+revision requires exact full-struct equality.
         * Same id+rev with different content is a conflicting duplicate.
         * Only exact full HW+REG equality is idempotent.
         */
        hw_id_rev_match =
            r5_id_equal(&r5->hw.profile_id, &cand_hw.profile_id)
            && r5->hw.profile_rev == cand_hw.profile_rev;
        reg_id_rev_match =
            r5_id_equal(&r5->reg.profile_id, &cand_reg.profile_id)
            && r5->reg.profile_rev == cand_reg.profile_rev;
        hw_full = r5_hw_full_equal(&r5->hw, &cand_hw);
        reg_full = r5_reg_full_equal(&r5->reg, &cand_reg);
        if ((hw_id_rev_match != 0 && hw_full == 0)
            || (reg_id_rev_match != 0 && reg_full == 0)) {
            r5_sat_inc(&r5->stats.activate_deny);
            r5_set_error(
                r5, out_error, out_safe, NINLIL_R5_PROFILE_DENIED,
                NINLIL_R5_STAGE_ACTIVATE, NINLIL_R5_REASON_DUPLICATE,
                NINLIL_R5_BIND_NONE, "id_content");
            return NINLIL_R5_PROFILE_DENIED;
        }
        if (hw_full != 0 && reg_full != 0) {
            r5_sat_inc(&r5->stats.activate_ok);
            r5_set_error(
                r5, out_error, out_safe, NINLIL_R5_OK, NINLIL_R5_STAGE_ACTIVATE,
                NINLIL_R5_REASON_IDEMPOTENT, NINLIL_R5_BIND_NONE, "idem");
            return NINLIL_R5_OK;
        }
    }

    /*
     * Assignment-bound profile replacement: durable full L_core rebind +
     * strict generation bump first; only then swap active.
     * On definite durable failure: preserve local active (no local mixed
     * active/assignment). On COMMIT_UNKNOWN: local active still preserved;
     * durable outcome is unknown until recover — do not claim mixed-free
     * atomicity across the unknown boundary.
     */
    if (r5->assignment_bound != 0u) {
        if (r5->assignment.permit_bind_generation == UINT64_MAX) {
            r5_sat_inc(&r5->stats.activate_deny);
            r5_set_error(
                r5, out_error, out_safe, NINLIL_R5_CAPACITY,
                NINLIL_R5_STAGE_ACTIVATE, NINLIL_R5_REASON_STRUCT,
                NINLIL_R5_BIND_PERMIT_GEN, "gen_max");
            return NINLIL_R5_CAPACITY;
        }
        target_gen = r5->assignment.permit_bind_generation + 1u;
        if (r5->pcp_bound != 0u && r5->pcp != NULL) {
            (void)memset(&live, 0, sizeof(live));
            live.hardware_profile_id = cand_hw.profile_id;
            live.hardware_profile_rev = cand_hw.profile_rev;
            live.regulatory_profile_id = cand_reg.profile_id;
            live.regulatory_profile_rev = cand_reg.profile_rev;
            live.site_assignment_id = r5->assignment.site_assignment_id;
            live.site_assignment_rev = r5->assignment.site_assignment_rev;
            live.site_assignment_epoch = r5->assignment.site_assignment_epoch;
            live.transmitter_id = r5->assignment.transmitter_id;
            live.channel_id = r5->assignment.channel_id;
            live.phy = r5->assignment.phy;
            live.max_airtime_us = cand_reg.max_airtime_ceiling_us;
            live.reserved_zero = 0u;
            plive = live;
            (void)memset(&perr, 0, sizeof(perr));
            pst = r5_pcp_commit_live_guarded(
                r5, r5->pcp, &plive, target_gen, &perr);
            if (pst != NINLIL_PCP_OK) {
                /* Preserve prior active + assignment gen; no mixed state. */
                r5_sat_inc(&r5->stats.activate_deny);
                r5_set_error(
                    r5, out_error, out_safe, NINLIL_R5_PCP,
                    NINLIL_R5_STAGE_ACTIVATE, NINLIL_R5_REASON_PCP,
                    NINLIL_R5_BIND_PERMIT_GEN, "act_rebind");
                return NINLIL_R5_PCP;
            }
            pst = ninlil_pcp_get_assignment_generation(r5->pcp, &r2_gen);
            if (pst != NINLIL_PCP_OK || r2_gen != target_gen) {
                r5_sat_inc(&r5->stats.activate_deny);
                r5_set_error(
                    r5, out_error, out_safe, NINLIL_R5_PCP,
                    NINLIL_R5_STAGE_ACTIVATE, NINLIL_R5_REASON_PCP,
                    NINLIL_R5_BIND_PERMIT_GEN, "act_gen");
                return NINLIL_R5_PCP;
            }
        }
        r5->hw = cand_hw;
        r5->reg = cand_reg;
        r5->profiles_active = 1u;
        r5->assignment.permit_bind_generation = target_gen;
        r5->fence_pending = 0u;
        r5->fence_target_generation = 0u;
        r5_sat_inc(&r5->stats.activate_ok);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_OK, NINLIL_R5_STAGE_ACTIVATE,
            NINLIL_R5_REASON_NONE, NINLIL_R5_BIND_NONE, NULL);
        return NINLIL_R5_OK;
    }

    /* No assignment yet: staged → active only (no durable gen). */
    r5->hw = cand_hw;
    r5->reg = cand_reg;
    r5->profiles_active = 1u;
    r5_sat_inc(&r5->stats.activate_ok);
    r5_set_error(
        r5, out_error, out_safe, NINLIL_R5_OK, NINLIL_R5_STAGE_ACTIVATE,
        NINLIL_R5_REASON_NONE, NINLIL_R5_BIND_NONE, NULL);
    return NINLIL_R5_OK;
}

/* ---- Assignment ---- */

static int r5_phy_in_reg(
    const ninlil_r5_regulatory_profile_t *reg,
    const ninlil_radio_hal_phy_t *phy)
{
    if (phy->phy_flags != 0u) {
        return 0;
    }
    if (phy->bandwidth_hz != reg->bw_hz) {
        return 0;
    }
    if (phy->spreading_factor < reg->sf_min
        || phy->spreading_factor > reg->sf_max) {
        return 0;
    }
    if (phy->coding_rate_denom < reg->cr_denom_min
        || phy->coding_rate_denom > reg->cr_denom_max) {
        return 0;
    }
    if (phy->preamble_symbols < reg->preamble_symbols_min
        || phy->preamble_symbols > reg->preamble_symbols_max) {
        return 0;
    }
    if (phy->tx_power_mdb < reg->tx_power_mdb_min
        || phy->tx_power_mdb > reg->tx_power_mdb_max) {
        return 0;
    }
    return 1;
}

ninlil_r5_status_t ninlil_r5_bind_site_assignment(
    ninlil_r5_t *r5,
    const ninlil_r5_site_assignment_t *assignment,
    ninlil_r5_error_t *out_error)
{
    int out_safe = 1;
    ninlil_r5_site_assignment_t cand;
    ninlil_r5_site_assignment_t prev;
    uint32_t prev_bound;
    ninlil_radio_hal_live_binding_t live;
    ninlil_pcp_live_profile_t plive;
    ninlil_pcp_error_t perr;
    ninlil_pcp_status_t pst;
    uint64_t new_gen;
    int identical;

    if (r5 == NULL) {
        return NINLIL_R5_INVALID_ARGUMENT;
    }
    /* Alias before guard / stats / last_error — zero mutation on ALIAS. */
    if (assignment != NULL
        && (r5_ranges_overlap_ptr(
                r5, sizeof(*r5), assignment, sizeof(*assignment))
            || (out_error != NULL
                && (r5_ranges_overlap_ptr(
                        assignment, sizeof(*assignment), out_error,
                        sizeof(*out_error))
                    || r5_ranges_overlap_ptr(
                        r5, sizeof(*r5), out_error, sizeof(*out_error)))))) {
        return NINLIL_R5_ALIAS;
    }
    if (assignment == NULL && out_error != NULL
        && r5_ranges_overlap_ptr(
            r5, sizeof(*r5), out_error, sizeof(*out_error))) {
        return NINLIL_R5_ALIAS;
    }
    if (!r5_guard_active(r5, out_error, &out_safe, NINLIL_R5_STAGE_ASSIGN)) {
        return r5->last_error.status;
    }
    out_safe = r5_out_error_safe(r5, out_error);
    if (assignment == NULL) {
        r5_sat_inc(&r5->stats.assign_deny);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_INVALID_ARGUMENT,
            NINLIL_R5_STAGE_ASSIGN, NINLIL_R5_REASON_NULL_ARG,
            NINLIL_R5_BIND_NONE, "null");
        return NINLIL_R5_INVALID_ARGUMENT;
    }
    if (r5->profiles_active == 0u) {
        r5_sat_inc(&r5->stats.assign_deny);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_INVALID_STATE,
            NINLIL_R5_STAGE_ASSIGN, NINLIL_R5_REASON_UNBOUND,
            NINLIL_R5_BIND_NONE, "profiles");
        return NINLIL_R5_INVALID_STATE;
    }
    if (r5->registry_count != 0u) {
        r5_sat_inc(&r5->stats.assign_deny);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_BUSY_OUTSTANDING,
            NINLIL_R5_STAGE_ASSIGN, NINLIL_R5_REASON_OUTSTANDING,
            NINLIL_R5_BIND_NONE, "outstanding");
        return NINLIL_R5_BUSY_OUTSTANDING;
    }
    /*
     * fence_pending: fail-closed before durable/local assignment change.
     * Even idempotent same-assignment must not clear or retarget the fence.
     * Recovery: original PCP + fence_after_revoke at stored target only.
     */
    if (r5->fence_pending != 0u) {
        r5_sat_inc(&r5->stats.assign_deny);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_INVALID_STATE,
            NINLIL_R5_STAGE_ASSIGN, NINLIL_R5_REASON_PCP,
            NINLIL_R5_BIND_PERMIT_GEN, "fence_pend");
        return NINLIL_R5_INVALID_STATE;
    }
    cand = *assignment;
    if (cand.reserved_zero != 0u
        || r5_id_is_zero(&cand.site_assignment_id)
        || cand.site_assignment_rev == 0u
        || cand.site_assignment_epoch == 0u
        || cand.controller_term == 0u
        || cand.permit_bind_generation == 0u
        || r5_id_is_zero(&cand.transmitter_id)
        || cand.channel_id < r5->reg.channel_id_min
        || cand.channel_id > r5->reg.channel_id_max
        || !r5_phy_in_reg(&r5->reg, &cand.phy)) {
        r5_sat_inc(&r5->stats.assign_deny);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_STRUCT, NINLIL_R5_STAGE_ASSIGN,
            NINLIL_R5_REASON_RANGE, NINLIL_R5_BIND_NONE, "assign_struct");
        return NINLIL_R5_STRUCT;
    }
    if (r5->assignment_bound != 0u
        && r5_id_equal(&r5->assignment.site_assignment_id, &cand.site_assignment_id)
        && cand.site_assignment_rev < r5->assignment.site_assignment_rev) {
        r5_sat_inc(&r5->stats.assign_deny);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_PROFILE_DENIED,
            NINLIL_R5_STAGE_ASSIGN, NINLIL_R5_REASON_ROLLBACK,
            NINLIL_R5_BIND_NONE, "rollback");
        return NINLIL_R5_PROFILE_DENIED;
    }

    identical = 0;
    if (r5->assignment_bound != 0u
        && r5_id_equal(&r5->assignment.site_assignment_id, &cand.site_assignment_id)
        && r5->assignment.site_assignment_rev == cand.site_assignment_rev
        && r5->assignment.site_assignment_epoch == cand.site_assignment_epoch
        && r5->assignment.controller_term == cand.controller_term
        && r5_digest_equal(r5->assignment.assignment_digest, cand.assignment_digest)
        && r5->assignment.permit_bind_generation == cand.permit_bind_generation
        && r5_id_equal(&r5->assignment.transmitter_id, &cand.transmitter_id)
        && r5->assignment.channel_id == cand.channel_id
        && r5_phy_equal(&r5->assignment.phy, &cand.phy)) {
        identical = 1;
    }
    if (identical != 0) {
        r5_sat_inc(&r5->stats.assign_ok);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_OK, NINLIL_R5_STAGE_ASSIGN,
            NINLIL_R5_REASON_IDEMPOTENT, NINLIL_R5_BIND_NONE, "idem");
        return NINLIL_R5_OK;
    }

    /* Non-identical change requires strict generation increase when rebinding. */
    if (r5->assignment_bound != 0u
        && cand.permit_bind_generation <= r5->assignment.permit_bind_generation) {
        r5_sat_inc(&r5->stats.assign_deny);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_STRUCT, NINLIL_R5_STAGE_ASSIGN,
            NINLIL_R5_REASON_GEN_REQUIRED, NINLIL_R5_BIND_PERMIT_GEN,
            "gen_inc");
        return NINLIL_R5_STRUCT;
    }
    new_gen = cand.permit_bind_generation;

    /* Build live from active profiles + candidate assignment (no local commit yet). */
    (void)memset(&live, 0, sizeof(live));
    live.hardware_profile_id = r5->hw.profile_id;
    live.hardware_profile_rev = r5->hw.profile_rev;
    live.regulatory_profile_id = r5->reg.profile_id;
    live.regulatory_profile_rev = r5->reg.profile_rev;
    live.site_assignment_id = cand.site_assignment_id;
    live.site_assignment_rev = cand.site_assignment_rev;
    live.site_assignment_epoch = cand.site_assignment_epoch;
    live.transmitter_id = cand.transmitter_id;
    live.channel_id = cand.channel_id;
    live.phy = cand.phy;
    live.max_airtime_us = r5->reg.max_airtime_ceiling_us;
    live.reserved_zero = 0u;

    prev = r5->assignment;
    prev_bound = r5->assignment_bound;

    if (r5->pcp_bound != 0u && r5->pcp != NULL) {
        plive = live;
        (void)memset(&perr, 0, sizeof(perr));
        pst = r5_pcp_commit_live_guarded(
            r5, r5->pcp, &plive, new_gen, &perr);
        if (pst != NINLIL_PCP_OK) {
            /* Fully preserve old local assignment. */
            r5->assignment = prev;
            r5->assignment_bound = prev_bound;
            r5_sat_inc(&r5->stats.assign_deny);
            r5_set_error(
                r5, out_error, out_safe, NINLIL_R5_PCP, NINLIL_R5_STAGE_ASSIGN,
                NINLIL_R5_REASON_PCP, NINLIL_R5_BIND_PERMIT_GEN, "rebind");
            return NINLIL_R5_PCP;
        }
    }

    /* Local commit only after durable success (or no pcp yet). */
    r5->assignment = cand;
    r5->assignment_bound = 1u;
    r5->fence_pending = 0u;
    r5->fence_target_generation = 0u;
    r5_sat_inc(&r5->stats.assign_ok);
    r5_set_error(
        r5, out_error, out_safe, NINLIL_R5_OK, NINLIL_R5_STAGE_ASSIGN,
        NINLIL_R5_REASON_NONE, NINLIL_R5_BIND_NONE, NULL);
    return NINLIL_R5_OK;
}

ninlil_r5_status_t ninlil_r5_build_live_binding(
    const ninlil_r5_t *r5,
    ninlil_radio_hal_live_binding_t *out_live,
    ninlil_r5_error_t *out_error)
{
    int out_safe = 0;
    int live_safe = 0;

    if (r5 == NULL || out_live == NULL) {
        return NINLIL_R5_INVALID_ARGUMENT;
    }
    /* Alias gates before any destructive output write. */
    if (r5_ranges_overlap_ptr(r5, sizeof(*r5), out_live, sizeof(*out_live))) {
        return NINLIL_R5_ALIAS;
    }
    if (out_error != NULL
        && r5_ranges_overlap_ptr(r5, sizeof(*r5), out_error, sizeof(*out_error))) {
        return NINLIL_R5_ALIAS;
    }
    if (out_error != NULL
        && r5_ranges_overlap_ptr(
            out_live, sizeof(*out_live), out_error, sizeof(*out_error))) {
        return NINLIL_R5_ALIAS;
    }
    out_safe = (out_error != NULL) ? 1 : 0;
    live_safe = 1;
    if (r5->magic != NINLIL_R5_MAGIC_VALUE || r5->lifecycle != R5_LC_ACTIVE
        || r5->profiles_active == 0u || r5->assignment_bound == 0u) {
        if (out_safe != 0) {
            (void)memset(out_error, 0, sizeof(*out_error));
            out_error->status = NINLIL_R5_INVALID_STATE;
            out_error->stage = NINLIL_R5_STAGE_ASSIGN;
            out_error->reason = NINLIL_R5_REASON_UNBOUND;
        }
        if (live_safe != 0) {
            (void)memset(out_live, 0, sizeof(*out_live));
        }
        return NINLIL_R5_INVALID_STATE;
    }
    (void)memset(out_live, 0, sizeof(*out_live));
    out_live->hardware_profile_id = r5->hw.profile_id;
    out_live->hardware_profile_rev = r5->hw.profile_rev;
    out_live->regulatory_profile_id = r5->reg.profile_id;
    out_live->regulatory_profile_rev = r5->reg.profile_rev;
    out_live->site_assignment_id = r5->assignment.site_assignment_id;
    out_live->site_assignment_rev = r5->assignment.site_assignment_rev;
    out_live->site_assignment_epoch = r5->assignment.site_assignment_epoch;
    out_live->transmitter_id = r5->assignment.transmitter_id;
    out_live->channel_id = r5->assignment.channel_id;
    out_live->phy = r5->assignment.phy;
    /* R2 bind_live: max_airtime_us is ceiling. */
    out_live->max_airtime_us = r5->reg.max_airtime_ceiling_us;
    out_live->reserved_zero = 0u;
    if (out_safe != 0) {
        (void)memset(out_error, 0, sizeof(*out_error));
    }
    return NINLIL_R5_OK;
}

/* ---- Registry ---- */

static ninlil_r5_registry_slot_t *r5_registry_find(
    ninlil_r5_t *r5,
    uint64_t seq)
{
    uint32_t i;
    for (i = 0u; i < NINLIL_R5_MAX_OUTSTANDING; ++i) {
        if (r5->registry[i].occupied != 0u
            && r5->registry[i].plan.permit_sequence == seq) {
            return &r5->registry[i];
        }
    }
    return NULL;
}

static ninlil_r5_status_t r5_registry_insert(
    ninlil_r5_t *r5,
    const ninlil_r5_bind_plan_t *plan)
{
    uint32_t i;

    if (r5->registry_count >= NINLIL_R5_MAX_OUTSTANDING) {
        return NINLIL_R5_CAPACITY;
    }
    if (r5_registry_find(r5, plan->permit_sequence) != NULL) {
        return NINLIL_R5_STRUCT;
    }
    for (i = 0u; i < NINLIL_R5_MAX_OUTSTANDING; ++i) {
        if (r5->registry[i].occupied == 0u) {
            r5->registry[i].occupied = 1u;
            r5->registry[i].reserved_zero = 0u;
            r5->registry[i].plan = *plan;
            r5->registry_count += 1u;
            return NINLIL_R5_OK;
        }
    }
    return NINLIL_R5_CAPACITY;
}

static void r5_registry_remove(ninlil_r5_t *r5, uint64_t seq)
{
    ninlil_r5_registry_slot_t *slot = r5_registry_find(r5, seq);
    if (slot != NULL) {
        (void)memset(slot, 0, sizeof(*slot));
        if (r5->registry_count > 0u) {
            r5->registry_count -= 1u;
        }
    }
}

/* ---- Full bind compare (SEMANTIC: FULL_BIND_MATRIX_ISSUE_AND_CONSUME) ---- */

static ninlil_r5_bind_item_t r5_compare_plan(
    const ninlil_r5_bind_plan_t *a,
    const ninlil_r5_bind_plan_t *b,
    int compare_seq)
{
    if (!r5_id_equal(&a->hardware_profile_id, &b->hardware_profile_id)) {
        return NINLIL_R5_BIND_HW_ID;
    }
    if (a->hardware_profile_rev != b->hardware_profile_rev) {
        return NINLIL_R5_BIND_HW_REV;
    }
    if (!r5_id_equal(&a->regulatory_profile_id, &b->regulatory_profile_id)) {
        return NINLIL_R5_BIND_REG_ID;
    }
    if (a->regulatory_profile_rev != b->regulatory_profile_rev) {
        return NINLIL_R5_BIND_REG_REV;
    }
    if (!r5_id_equal(&a->site_assignment_id, &b->site_assignment_id)) {
        return NINLIL_R5_BIND_SITE_ID;
    }
    if (a->site_assignment_rev != b->site_assignment_rev) {
        return NINLIL_R5_BIND_SITE_REV;
    }
    if (a->site_assignment_epoch != b->site_assignment_epoch) {
        return NINLIL_R5_BIND_SITE_EPOCH;
    }
    if (a->controller_term != b->controller_term) {
        return NINLIL_R5_BIND_CONTROLLER_TERM;
    }
    if (!r5_digest_equal(a->assignment_digest, b->assignment_digest)) {
        return NINLIL_R5_BIND_ASSIGNMENT_DIGEST;
    }
    if (a->permit_bind_generation != b->permit_bind_generation) {
        return NINLIL_R5_BIND_PERMIT_GEN;
    }
    if (!r5_id_equal(&a->transmitter_id, &b->transmitter_id)) {
        return NINLIL_R5_BIND_TX_ID;
    }
    if (a->channel_id != b->channel_id) {
        return NINLIL_R5_BIND_CHANNEL;
    }
    if (!r5_phy_equal(&a->phy, &b->phy)) {
        return NINLIL_R5_BIND_PHY;
    }
    if (!r5_digest_equal(a->frame_digest, b->frame_digest)) {
        return NINLIL_R5_BIND_FRAME_DIGEST;
    }
    if (a->frame_digest_algorithm != b->frame_digest_algorithm) {
        return NINLIL_R5_BIND_FRAME_DIGEST_ALG;
    }
    if (a->frame_byte_length != b->frame_byte_length) {
        return NINLIL_R5_BIND_FRAME_LEN;
    }
    if (a->max_airtime_us != b->max_airtime_us) {
        return NINLIL_R5_BIND_AIRTIME;
    }
    if (a->not_before_ms != b->not_before_ms) {
        return NINLIL_R5_BIND_NOT_BEFORE;
    }
    if (a->expiry_ms != b->expiry_ms) {
        return NINLIL_R5_BIND_EXPIRY;
    }
    if (compare_seq != 0 && a->permit_sequence != b->permit_sequence) {
        return NINLIL_R5_BIND_PERMIT_SEQ;
    }
    return NINLIL_R5_BIND_NONE;
}

static void r5_fill_active_core(const ninlil_r5_t *r5, ninlil_r5_bind_plan_t *p)
{
    (void)memset(p, 0, sizeof(*p));
    p->hardware_profile_id = r5->hw.profile_id;
    p->hardware_profile_rev = r5->hw.profile_rev;
    p->regulatory_profile_id = r5->reg.profile_id;
    p->regulatory_profile_rev = r5->reg.profile_rev;
    p->site_assignment_id = r5->assignment.site_assignment_id;
    p->site_assignment_rev = r5->assignment.site_assignment_rev;
    p->site_assignment_epoch = r5->assignment.site_assignment_epoch;
    p->controller_term = r5->assignment.controller_term;
    (void)memcpy(
        p->assignment_digest, r5->assignment.assignment_digest,
        NINLIL_R5_DIGEST_BYTES);
    p->permit_bind_generation = r5->assignment.permit_bind_generation;
    p->transmitter_id = r5->assignment.transmitter_id;
    p->channel_id = r5->assignment.channel_id;
    p->phy = r5->assignment.phy;
}

static void r5_hal_from_full(
    ninlil_radio_hal_permit_snapshot_t *hal,
    const ninlil_r5_bind_plan_t *full)
{
    (void)memset(hal, 0, sizeof(*hal));
    hal->hardware_profile_id = full->hardware_profile_id;
    hal->hardware_profile_rev = full->hardware_profile_rev;
    hal->regulatory_profile_id = full->regulatory_profile_id;
    hal->regulatory_profile_rev = full->regulatory_profile_rev;
    hal->site_assignment_id = full->site_assignment_id;
    hal->site_assignment_rev = full->site_assignment_rev;
    hal->site_assignment_epoch = full->site_assignment_epoch;
    hal->transmitter_id = full->transmitter_id;
    hal->channel_id = full->channel_id;
    hal->phy = full->phy;
    (void)memcpy(hal->frame_digest, full->frame_digest, 32u);
    hal->frame_digest_algorithm = full->frame_digest_algorithm;
    hal->frame_byte_length = full->frame_byte_length;
    hal->max_airtime_us = full->max_airtime_us;
    hal->not_before_ms = full->not_before_ms;
    hal->expiry_ms = full->expiry_ms;
    hal->permit_sequence = full->permit_sequence;
    hal->reserved_zero = 0u;
}

/* ---- Issue ---- */

/*
 * Length used for frame-bytes geometric alias checks.
 * ALIAS means actual range overlap only — pure oversize (no geometric overlap
 * within MAX+1 of the base) is NOT ALIAS; callers return STRUCT/OVERSIZE.
 * Cap at MAX+1 so huge lengths do not span the whole address space as "overlap".
 */
static size_t r5_frame_alias_check_len(uint32_t flen)
{
    if (flen == 0u) {
        return 0u;
    }
    if (flen > NINLIL_RADIO_HAL_MAX_FRAME_BYTES) {
        return (size_t)NINLIL_RADIO_HAL_MAX_FRAME_BYTES + 1u;
    }
    return (size_t)flen;
}

/*
 * compose/issue alias gate: ALIAS only on actual overlaps; zero mutation of
 * owner, inputs, and all outputs (including out_error). Pure oversize is not
 * ALIAS (compose returns STRUCT after this gate).
 */
static ninlil_r5_status_t r5_compose_alias_gate(
    ninlil_r5_t *r5,
    const ninlil_r5_issue_plan_t *plan,
    ninlil_r5_bind_plan_t *out_expected,
    ninlil_r5_error_t *out_error,
    int *out_safe_io)
{
    const uint8_t *fb = NULL;
    uint32_t flen = 0u;
    size_t clen = 0u;

    *out_safe_io = r5_out_error_safe(r5, out_error);

    /* Fixed containers only — never load plan->frame_* yet. */
    if (r5_ranges_overlap_ptr(r5, sizeof(*r5), plan, sizeof(*plan))
        || r5_ranges_overlap_ptr(
            r5, sizeof(*r5), out_expected, sizeof(*out_expected))
        || r5_ranges_overlap_ptr(
            plan, sizeof(*plan), out_expected, sizeof(*out_expected))
        || (out_error != NULL
            && (r5_ranges_overlap_ptr(
                    r5, sizeof(*r5), out_error, sizeof(*out_error))
                || r5_ranges_overlap_ptr(
                    plan, sizeof(*plan), out_error, sizeof(*out_error))
                || r5_ranges_overlap_ptr(
                    out_expected, sizeof(*out_expected), out_error,
                    sizeof(*out_error))))) {
        return NINLIL_R5_ALIAS;
    }

    /* Containers safe — snapshot frame fields; geometric alias only. */
    fb = plan->frame_bytes;
    flen = plan->frame_byte_length;
    clen = r5_frame_alias_check_len(flen);
    if (fb != NULL && clen > 0u) {
        if (r5_ranges_overlap_ptr(r5, sizeof(*r5), fb, clen)
            || r5_ranges_overlap_ptr(
                out_expected, sizeof(*out_expected), fb, clen)
            || r5_ranges_overlap_ptr(plan, sizeof(*plan), fb, clen)
            || (out_error != NULL
                && r5_ranges_overlap_ptr(
                    out_error, sizeof(*out_error), fb, clen))) {
            return NINLIL_R5_ALIAS;
        }
    }
    return NINLIL_R5_OK;
}

static ninlil_r5_status_t r5_issue_alias_gate(
    ninlil_r5_t *r5,
    const ninlil_r5_issue_plan_t *plan,
    const ninlil_r5_bind_plan_t *proposed,
    ninlil_r5_bind_plan_t *out_full_bind,
    ninlil_radio_hal_permit_snapshot_t *out_hal_snapshot,
    ninlil_r5_error_t *out_error,
    int *out_safe_io)
{
    const uint8_t *fb = NULL;
    uint32_t flen = 0u;
    size_t clen = 0u;

    *out_safe_io = r5_out_error_safe(r5, out_error);

    /* Fixed containers only — never load plan->frame_* yet. */
    if (r5_ranges_overlap_ptr(r5, sizeof(*r5), plan, sizeof(*plan))
        || r5_ranges_overlap_ptr(r5, sizeof(*r5), proposed, sizeof(*proposed))
        || r5_ranges_overlap_ptr(
            r5, sizeof(*r5), out_full_bind, sizeof(*out_full_bind))
        || r5_ranges_overlap_ptr(
            r5, sizeof(*r5), out_hal_snapshot, sizeof(*out_hal_snapshot))
        || r5_ranges_overlap_ptr(
            plan, sizeof(*plan), out_full_bind, sizeof(*out_full_bind))
        || r5_ranges_overlap_ptr(
            plan, sizeof(*plan), out_hal_snapshot, sizeof(*out_hal_snapshot))
        || r5_ranges_overlap_ptr(
            proposed, sizeof(*proposed), out_full_bind, sizeof(*out_full_bind))
        || r5_ranges_overlap_ptr(
            proposed, sizeof(*proposed), out_hal_snapshot,
            sizeof(*out_hal_snapshot))
        || r5_ranges_overlap_ptr(
            out_full_bind, sizeof(*out_full_bind), out_hal_snapshot,
            sizeof(*out_hal_snapshot))
        || (out_error != NULL
            && (r5_ranges_overlap_ptr(
                    r5, sizeof(*r5), out_error, sizeof(*out_error))
                || r5_ranges_overlap_ptr(
                    plan, sizeof(*plan), out_error, sizeof(*out_error))
                || r5_ranges_overlap_ptr(
                    proposed, sizeof(*proposed), out_error, sizeof(*out_error))
                || r5_ranges_overlap_ptr(
                    out_full_bind, sizeof(*out_full_bind), out_error,
                    sizeof(*out_error))
                || r5_ranges_overlap_ptr(
                    out_hal_snapshot, sizeof(*out_hal_snapshot), out_error,
                    sizeof(*out_error))))) {
        return NINLIL_R5_ALIAS;
    }

    fb = plan->frame_bytes;
    flen = plan->frame_byte_length;
    clen = r5_frame_alias_check_len(flen);
    if (fb != NULL && clen > 0u) {
        if (r5_ranges_overlap_ptr(r5, sizeof(*r5), fb, clen)
            || r5_ranges_overlap_ptr(
                out_full_bind, sizeof(*out_full_bind), fb, clen)
            || r5_ranges_overlap_ptr(
                out_hal_snapshot, sizeof(*out_hal_snapshot), fb, clen)
            || r5_ranges_overlap_ptr(plan, sizeof(*plan), fb, clen)
            || r5_ranges_overlap_ptr(proposed, sizeof(*proposed), fb, clen)
            || (out_error != NULL
                && r5_ranges_overlap_ptr(
                    out_error, sizeof(*out_error), fb, clen))) {
            return NINLIL_R5_ALIAS;
        }
    }
    return NINLIL_R5_OK;
}

ninlil_r5_status_t ninlil_r5_compose_issue_bind(
    ninlil_r5_t *r5,
    const ninlil_r5_issue_plan_t *plan,
    ninlil_r5_bind_plan_t *out_expected,
    ninlil_r5_error_t *out_error)
{
    int out_safe = 1;
    ninlil_airtime_result_t air;
    ninlil_airtime_status_t ast;
    ninlil_r5_bind_plan_t full;
    ninlil_r5_status_t alias_st;

    if (r5 == NULL) {
        return NINLIL_R5_INVALID_ARGUMENT;
    }
    if (plan == NULL || out_expected == NULL) {
        out_safe = r5_out_error_safe(r5, out_error);
        if (r5->magic == NINLIL_R5_MAGIC_VALUE
            && r5->lifecycle == R5_LC_ACTIVE && r5->in_api == 0u) {
            r5_set_error(
                r5, out_error, out_safe, NINLIL_R5_INVALID_ARGUMENT,
                NINLIL_R5_STAGE_ISSUE, NINLIL_R5_REASON_NULL_ARG,
                NINLIL_R5_BIND_NONE, "null");
            return NINLIL_R5_INVALID_ARGUMENT;
        }
        return NINLIL_R5_INVALID_ARGUMENT;
    }
    /* Owner↔inputs and outs before any last_error / out write. */
    alias_st = r5_compose_alias_gate(
        r5, plan, out_expected, out_error, &out_safe);
    if (alias_st != NINLIL_R5_OK) {
        return alias_st;
    }
    if (!r5_guard_active(r5, out_error, &out_safe, NINLIL_R5_STAGE_ISSUE)) {
        return r5->last_error.status;
    }
    out_safe = r5_out_error_safe(r5, out_error);
    (void)memset(out_expected, 0, sizeof(*out_expected));
    if (r5->profiles_active == 0u || r5->assignment_bound == 0u) {
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_INVALID_STATE,
            NINLIL_R5_STAGE_ISSUE, NINLIL_R5_REASON_UNBOUND, NINLIL_R5_BIND_NONE,
            "unbound");
        return NINLIL_R5_INVALID_STATE;
    }
    if (plan->reserved_zero != 0u || plan->frame_bytes == NULL
        || plan->frame_byte_length == 0u
        || plan->frame_byte_length > NINLIL_RADIO_HAL_MAX_FRAME_BYTES
        || plan->expiry_ms <= plan->not_before_ms) {
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_STRUCT, NINLIL_R5_STAGE_ISSUE,
            NINLIL_R5_REASON_STRUCT, NINLIL_R5_BIND_NONE, "plan");
        return NINLIL_R5_STRUCT;
    }

    (void)memset(&air, 0, sizeof(air));
    ast = ninlil_airtime_lora_us(&plan->airtime_in, &air);
    if (ast != NINLIL_AIRTIME_OK) {
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_AIRTIME, NINLIL_R5_STAGE_ISSUE,
            NINLIL_R5_REASON_AIRTIME, NINLIL_R5_BIND_NONE, "r3");
        return NINLIL_R5_AIRTIME;
    }
    if (air.airtime_us == 0u
        || air.airtime_us > r5->reg.max_airtime_ceiling_us) {
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_AIRTIME, NINLIL_R5_STAGE_ISSUE,
            NINLIL_R5_REASON_CEILING, NINLIL_R5_BIND_AIRTIME, "ceiling");
        return NINLIL_R5_AIRTIME;
    }
    /* Profile effective/expiry vs permit window (docs/29). */
    if (plan->not_before_ms < r5->reg.effective_not_before_ms) {
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_PROFILE_NOT_EFFECTIVE,
            NINLIL_R5_STAGE_ISSUE, NINLIL_R5_REASON_PROFILE_NOT_EFFECTIVE,
            NINLIL_R5_BIND_NOT_BEFORE, "not_eff");
        return NINLIL_R5_PROFILE_NOT_EFFECTIVE;
    }
    if (r5->reg.profile_expiry_ms != 0u
        && plan->expiry_ms > r5->reg.profile_expiry_ms) {
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_PROFILE_EXPIRED,
            NINLIL_R5_STAGE_ISSUE, NINLIL_R5_REASON_PROFILE_EXPIRED,
            NINLIL_R5_BIND_EXPIRY, "prof_exp");
        return NINLIL_R5_PROFILE_EXPIRED;
    }
    if (plan->airtime_in.bw_hz != r5->assignment.phy.bandwidth_hz
        || plan->airtime_in.sf != r5->assignment.phy.spreading_factor
        || (uint8_t)(4u + (uint32_t)plan->airtime_in.cr)
            != r5->assignment.phy.coding_rate_denom
        || plan->airtime_in.preamble_len_symbols
            != r5->assignment.phy.preamble_symbols) {
        r5_sat_inc(&r5->stats.bind_mismatch);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_BIND_MISMATCH,
            NINLIL_R5_STAGE_ISSUE, NINLIL_R5_REASON_BIND_ITEM,
            NINLIL_R5_BIND_PHY, "phy_airtime");
        return NINLIL_R5_BIND_MISMATCH;
    }
    if ((uint32_t)plan->airtime_in.payload_len_bytes != plan->frame_byte_length) {
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_STRUCT, NINLIL_R5_STAGE_ISSUE,
            NINLIL_R5_REASON_STRUCT, NINLIL_R5_BIND_FRAME_LEN, "payload_len");
        return NINLIL_R5_STRUCT;
    }

    r5_fill_active_core(r5, &full);
    (void)memcpy(full.frame_digest, plan->frame_digest, 32u);
    full.frame_digest_algorithm = plan->frame_digest_algorithm;
    full.frame_byte_length = plan->frame_byte_length;
    full.max_airtime_us = air.airtime_us;
    full.not_before_ms = plan->not_before_ms;
    full.expiry_ms = plan->expiry_ms;
    full.permit_sequence = 0u;
    full.reserved_zero = 0u;

    if (full.channel_id < r5->reg.channel_id_min
        || full.channel_id > r5->reg.channel_id_max
        || !r5_phy_in_reg(&r5->reg, &full.phy)) {
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_BIND_MISMATCH,
            NINLIL_R5_STAGE_ISSUE, NINLIL_R5_REASON_RANGE, NINLIL_R5_BIND_CHANNEL,
            "range");
        return NINLIL_R5_BIND_MISMATCH;
    }
    *out_expected = full;
    r5_set_error(
        r5, out_error, out_safe, NINLIL_R5_OK, NINLIL_R5_STAGE_ISSUE,
        NINLIL_R5_REASON_NONE, NINLIL_R5_BIND_NONE, NULL);
    return NINLIL_R5_OK;
}

ninlil_r5_status_t ninlil_r5_issue_with_bind(
    ninlil_r5_t *r5,
    const ninlil_r5_issue_plan_t *plan,
    const ninlil_r5_bind_plan_t *proposed,
    ninlil_r5_bind_plan_t *out_full_bind,
    ninlil_radio_hal_permit_snapshot_t *out_hal_snapshot,
    ninlil_r5_error_t *out_error)
{
    int out_safe = 1;
    ninlil_r5_bind_plan_t expected;
    ninlil_r5_bind_plan_t full;
    ninlil_r5_bind_item_t item;
    ninlil_pcp_issue_request_t req;
    ninlil_radio_hal_permit_snapshot_t snap;
    ninlil_pcp_error_t pcp_err;
    ninlil_pcp_status_t pst;
    ninlil_r5_status_t rst;
    uint64_t r2_gen = 0u;

    if (r5 == NULL) {
        return NINLIL_R5_INVALID_ARGUMENT;
    }
    if (plan == NULL || proposed == NULL || out_full_bind == NULL
        || out_hal_snapshot == NULL) {
        out_safe = r5_out_error_safe(r5, out_error);
        if (r5->magic == NINLIL_R5_MAGIC_VALUE && r5->lifecycle == R5_LC_ACTIVE
            && r5->in_api == 0u) {
            r5_sat_inc(&r5->stats.issue_deny);
            r5_set_error(
                r5, out_error, out_safe, NINLIL_R5_INVALID_ARGUMENT,
                NINLIL_R5_STAGE_ISSUE, NINLIL_R5_REASON_NULL_ARG,
                NINLIL_R5_BIND_NONE, "null");
            return NINLIL_R5_INVALID_ARGUMENT;
        }
        return NINLIL_R5_INVALID_ARGUMENT;
    }
    {
        ninlil_r5_status_t alias_st = r5_issue_alias_gate(
            r5, plan, proposed, out_full_bind, out_hal_snapshot, out_error,
            &out_safe);
        if (alias_st != NINLIL_R5_OK) {
            return alias_st;
        }
    }
    if (!r5_guard_active(r5, out_error, &out_safe, NINLIL_R5_STAGE_ISSUE)) {
        return r5->last_error.status;
    }
    out_safe = r5_out_error_safe(r5, out_error);
    (void)memset(out_full_bind, 0, sizeof(*out_full_bind));
    (void)memset(out_hal_snapshot, 0, sizeof(*out_hal_snapshot));
    if (r5->profiles_active == 0u || r5->assignment_bound == 0u
        || r5->pcp_bound == 0u || r5->pcp == NULL) {
        r5_sat_inc(&r5->stats.issue_deny);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_INVALID_STATE,
            NINLIL_R5_STAGE_ISSUE, NINLIL_R5_REASON_UNBOUND, NINLIL_R5_BIND_NONE,
            "unbound");
        return NINLIL_R5_INVALID_STATE;
    }

    rst = ninlil_r5_compose_issue_bind(r5, plan, &expected, out_error);
    if (rst != NINLIL_R5_OK) {
        r5_sat_inc(&r5->stats.issue_deny);
        return rst;
    }

    /* Issue-time full bind matrix (all fields except seq; both 0). */
    item = r5_compare_plan(proposed, &expected, 0);
    if (item != NINLIL_R5_BIND_NONE) {
        r5_sat_inc(&r5->stats.issue_deny);
        r5_sat_inc(&r5->stats.bind_mismatch);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_BIND_MISMATCH,
            NINLIL_R5_STAGE_ISSUE, NINLIL_R5_REASON_BIND_ITEM, item,
            "issue_bind");
        return NINLIL_R5_BIND_MISMATCH;
    }
    if (proposed->reserved_zero != 0u || proposed->permit_sequence != 0u) {
        r5_sat_inc(&r5->stats.issue_deny);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_STRUCT, NINLIL_R5_STAGE_ISSUE,
            NINLIL_R5_REASON_STRUCT, NINLIL_R5_BIND_PERMIT_SEQ, "preseq");
        return NINLIL_R5_STRUCT;
    }

    /* SEMANTIC: R2_ASSIGNMENT_GENERATION_SYNC */
    pst = ninlil_pcp_get_assignment_generation(r5->pcp, &r2_gen);
    if (pst != NINLIL_PCP_OK
        || r2_gen != proposed->permit_bind_generation) {
        r5_sat_inc(&r5->stats.issue_deny);
        r5_sat_inc(&r5->stats.bind_mismatch);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_BIND_MISMATCH,
            NINLIL_R5_STAGE_ISSUE, NINLIL_R5_REASON_BIND_ITEM,
            NINLIL_R5_BIND_PERMIT_GEN, "r2_gen");
        return NINLIL_R5_BIND_MISMATCH;
    }

    /* Preflight registry capacity — issue only if insert cannot fail. */
    if (r5->registry_count >= NINLIL_R5_MAX_OUTSTANDING) {
        r5_sat_inc(&r5->stats.issue_deny);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_CAPACITY, NINLIL_R5_STAGE_ISSUE,
            NINLIL_R5_REASON_REGISTRY_FULL, NINLIL_R5_BIND_NONE, "preflight");
        return NINLIL_R5_CAPACITY;
    }
    {
        uint32_t free_slots = 0u;
        uint32_t si;
        for (si = 0u; si < NINLIL_R5_MAX_OUTSTANDING; ++si) {
            if (r5->registry[si].occupied == 0u) {
                free_slots += 1u;
            }
        }
        if (free_slots == 0u) {
            r5_sat_inc(&r5->stats.issue_deny);
            r5_set_error(
                r5, out_error, out_safe, NINLIL_R5_CAPACITY, NINLIL_R5_STAGE_ISSUE,
                NINLIL_R5_REASON_REGISTRY_FULL, NINLIL_R5_BIND_NONE, "noslot");
            return NINLIL_R5_CAPACITY;
        }
    }
    if (r5->fence_pending != 0u) {
        r5_sat_inc(&r5->stats.issue_deny);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_INVALID_STATE,
            NINLIL_R5_STAGE_ISSUE, NINLIL_R5_REASON_PCP, NINLIL_R5_BIND_PERMIT_GEN,
            "fence_pend");
        return NINLIL_R5_INVALID_STATE;
    }

    full = *proposed;
    (void)memset(&req, 0, sizeof(req));
    req.hardware_profile_id = full.hardware_profile_id;
    req.hardware_profile_rev = full.hardware_profile_rev;
    req.regulatory_profile_id = full.regulatory_profile_id;
    req.regulatory_profile_rev = full.regulatory_profile_rev;
    req.site_assignment_id = full.site_assignment_id;
    req.site_assignment_rev = full.site_assignment_rev;
    req.site_assignment_epoch = full.site_assignment_epoch;
    req.transmitter_id = full.transmitter_id;
    req.channel_id = full.channel_id;
    req.phy = full.phy;
    req.max_airtime_us = full.max_airtime_us;
    (void)memcpy(req.frame_digest, full.frame_digest, 32u);
    req.frame_digest_algorithm = full.frame_digest_algorithm;
    req.frame_byte_length = full.frame_byte_length;
    req.not_before_ms = full.not_before_ms;
    req.expiry_ms = full.expiry_ms;
    req.reserved_zero = 0u;

    (void)memset(&snap, 0, sizeof(snap));
    (void)memset(&pcp_err, 0, sizeof(pcp_err));
    r5->in_api = 1u;
    pst = ninlil_pcp_issue(r5->pcp, &req, &snap, &pcp_err);
    r5->in_api = 0u;
    if (pst != NINLIL_PCP_OK) {
        r5_sat_inc(&r5->stats.issue_deny);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_PCP, NINLIL_R5_STAGE_ISSUE,
            NINLIL_R5_REASON_PCP, NINLIL_R5_BIND_NONE, "pcp_issue");
        return NINLIL_R5_PCP;
    }
    full.permit_sequence = snap.permit_sequence;
    if (full.permit_sequence == 0u) {
        r5_sat_inc(&r5->stats.issue_deny);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_PCP, NINLIL_R5_STAGE_ISSUE,
            NINLIL_R5_REASON_PCP, NINLIL_R5_BIND_PERMIT_SEQ, "seq0");
        return NINLIL_R5_PCP;
    }

    rst = r5_registry_insert(r5, &full);
    if (rst != NINLIL_R5_OK) {
        r5_sat_inc(&r5->stats.issue_deny);
        r5_set_error(
            r5, out_error, out_safe, rst, NINLIL_R5_STAGE_ISSUE,
            NINLIL_R5_REASON_REGISTRY_FULL, NINLIL_R5_BIND_NONE, "registry");
        return rst;
    }

    *out_full_bind = full;
    r5_hal_from_full(out_hal_snapshot, &full);
    r5_sat_inc(&r5->stats.issue_ok);
    r5_set_error(
        r5, out_error, out_safe, NINLIL_R5_OK, NINLIL_R5_STAGE_ISSUE,
        NINLIL_R5_REASON_NONE, NINLIL_R5_BIND_NONE, NULL);
    return NINLIL_R5_OK;
}

ninlil_r5_status_t ninlil_r5_issue(
    ninlil_r5_t *r5,
    const ninlil_r5_issue_plan_t *plan,
    ninlil_r5_bind_plan_t *out_full_bind,
    ninlil_radio_hal_permit_snapshot_t *out_hal_snapshot,
    ninlil_r5_error_t *out_error)
{
    ninlil_r5_bind_plan_t expected;
    ninlil_r5_status_t st;
    int out_safe = 0;
    ninlil_r5_bind_plan_t *dummy_proposed;

    if (r5 == NULL) {
        return NINLIL_R5_INVALID_ARGUMENT;
    }
    if (plan == NULL || out_full_bind == NULL || out_hal_snapshot == NULL) {
        out_safe = r5_out_error_safe(r5, out_error);
        if (r5->magic == NINLIL_R5_MAGIC_VALUE && r5->lifecycle == R5_LC_ACTIVE
            && r5->in_api == 0u) {
            r5_set_error(
                r5, out_error, out_safe, NINLIL_R5_INVALID_ARGUMENT,
                NINLIL_R5_STAGE_ISSUE, NINLIL_R5_REASON_NULL_ARG,
                NINLIL_R5_BIND_NONE, "null");
            return NINLIL_R5_INVALID_ARGUMENT;
        }
        return NINLIL_R5_INVALID_ARGUMENT;
    }
    /* Wrapper gate before compose: ALIAS-only, zero mutation. */
    {
        ninlil_r5_bind_plan_t proposed_placeholder;
        ninlil_r5_status_t alias_st;

        (void)memset(&proposed_placeholder, 0, sizeof(proposed_placeholder));
        dummy_proposed = &proposed_placeholder;
        alias_st = r5_issue_alias_gate(
            r5, plan, dummy_proposed, out_full_bind, out_hal_snapshot, out_error,
            &out_safe);
        if (alias_st != NINLIL_R5_OK) {
            return alias_st;
        }
    }
    st = ninlil_r5_compose_issue_bind(r5, plan, &expected, out_error);
    if (st != NINLIL_R5_OK) {
        /* compose already gated owner↔plan; stats only if owner not aliased. */
        if (r5->magic == NINLIL_R5_MAGIC_VALUE && r5->lifecycle == R5_LC_ACTIVE
            && r5->in_api == 0u
            && !r5_ranges_overlap_ptr(r5, sizeof(*r5), plan, sizeof(*plan))) {
            r5_sat_inc(&r5->stats.issue_deny);
        }
        return st;
    }
    return ninlil_r5_issue_with_bind(
        r5, plan, &expected, out_full_bind, out_hal_snapshot, out_error);
}

static ninlil_r5_status_t r5_check_hal_against_registry(
    ninlil_r5_t *r5,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    const ninlil_radio_hal_frame_view_t *frame,
    ninlil_r5_stage_t stage,
    ninlil_r5_error_t *out_error,
    int out_safe,
    ninlil_r5_bind_item_t *out_item)
{
    ninlil_r5_registry_slot_t *slot;
    ninlil_r5_bind_plan_t live_view;
    ninlil_r5_bind_item_t item;

    *out_item = NINLIL_R5_BIND_NONE;
    if (permit == NULL || frame == NULL) {
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_INVALID_ARGUMENT, stage,
            NINLIL_R5_REASON_NULL_ARG, NINLIL_R5_BIND_NONE, "null");
        return NINLIL_R5_INVALID_ARGUMENT;
    }
    if (r5->assignment_bound == 0u || r5->profiles_active == 0u) {
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_INVALID_STATE, stage,
            NINLIL_R5_REASON_UNBOUND, NINLIL_R5_BIND_NONE, "unbound");
        return NINLIL_R5_INVALID_STATE;
    }
    slot = r5_registry_find(r5, permit->permit_sequence);
    if (slot == NULL) {
        r5_sat_inc(&r5->stats.registry_miss);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_REGISTRY_MISS, stage,
            NINLIL_R5_REASON_REGISTRY_MISS, NINLIL_R5_BIND_PERMIT_SEQ,
            "registry_miss");
        return NINLIL_R5_REGISTRY_MISS;
    }

    r5_fill_active_core(r5, &live_view);
    live_view.frame_digest_algorithm = slot->plan.frame_digest_algorithm;
    (void)memcpy(live_view.frame_digest, slot->plan.frame_digest, 32u);
    live_view.frame_byte_length = slot->plan.frame_byte_length;
    live_view.max_airtime_us = slot->plan.max_airtime_us;
    live_view.not_before_ms = slot->plan.not_before_ms;
    live_view.expiry_ms = slot->plan.expiry_ms;
    live_view.permit_sequence = slot->plan.permit_sequence;

    item = r5_compare_plan(&slot->plan, &live_view, 1);
    if (item != NINLIL_R5_BIND_NONE) {
        *out_item = item;
        r5_sat_inc(&r5->stats.bind_mismatch);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_BIND_MISMATCH, stage,
            NINLIL_R5_REASON_BIND_ITEM, item, "live_vs_registry");
        return NINLIL_R5_BIND_MISMATCH;
    }

    if (!r5_id_equal(
            &permit->hardware_profile_id, &slot->plan.hardware_profile_id)) {
        item = NINLIL_R5_BIND_HW_ID;
    } else if (permit->hardware_profile_rev != slot->plan.hardware_profile_rev) {
        item = NINLIL_R5_BIND_HW_REV;
    } else if (!r5_id_equal(
                   &permit->regulatory_profile_id,
                   &slot->plan.regulatory_profile_id)) {
        item = NINLIL_R5_BIND_REG_ID;
    } else if (
        permit->regulatory_profile_rev != slot->plan.regulatory_profile_rev) {
        item = NINLIL_R5_BIND_REG_REV;
    } else if (!r5_id_equal(
                   &permit->site_assignment_id, &slot->plan.site_assignment_id)) {
        item = NINLIL_R5_BIND_SITE_ID;
    } else if (permit->site_assignment_rev != slot->plan.site_assignment_rev) {
        item = NINLIL_R5_BIND_SITE_REV;
    } else if (permit->site_assignment_epoch != slot->plan.site_assignment_epoch) {
        item = NINLIL_R5_BIND_SITE_EPOCH;
    } else if (!r5_id_equal(&permit->transmitter_id, &slot->plan.transmitter_id)) {
        item = NINLIL_R5_BIND_TX_ID;
    } else if (permit->channel_id != slot->plan.channel_id) {
        item = NINLIL_R5_BIND_CHANNEL;
    } else if (!r5_phy_equal(&permit->phy, &slot->plan.phy)) {
        item = NINLIL_R5_BIND_PHY;
    } else if (!r5_digest_equal(permit->frame_digest, slot->plan.frame_digest)) {
        item = NINLIL_R5_BIND_FRAME_DIGEST;
    } else if (permit->frame_digest_algorithm != slot->plan.frame_digest_algorithm) {
        item = NINLIL_R5_BIND_FRAME_DIGEST_ALG;
    } else if (permit->frame_byte_length != slot->plan.frame_byte_length) {
        item = NINLIL_R5_BIND_FRAME_LEN;
    } else if (permit->max_airtime_us != slot->plan.max_airtime_us) {
        item = NINLIL_R5_BIND_AIRTIME;
    } else if (permit->not_before_ms != slot->plan.not_before_ms) {
        item = NINLIL_R5_BIND_NOT_BEFORE;
    } else if (permit->expiry_ms != slot->plan.expiry_ms) {
        item = NINLIL_R5_BIND_EXPIRY;
    } else if (permit->permit_sequence != slot->plan.permit_sequence) {
        item = NINLIL_R5_BIND_PERMIT_SEQ;
    } else {
        item = NINLIL_R5_BIND_NONE;
    }
    if (item != NINLIL_R5_BIND_NONE) {
        *out_item = item;
        r5_sat_inc(&r5->stats.bind_mismatch);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_BIND_MISMATCH, stage,
            NINLIL_R5_REASON_BIND_ITEM, item, "hal_vs_registry");
        return NINLIL_R5_BIND_MISMATCH;
    }

    if (frame->bytes == NULL
        || frame->length != slot->plan.frame_byte_length) {
        *out_item = NINLIL_R5_BIND_FRAME_LEN;
        r5_sat_inc(&r5->stats.bind_mismatch);
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_BIND_MISMATCH, stage,
            NINLIL_R5_REASON_BIND_ITEM, NINLIL_R5_BIND_FRAME_LEN, "frame_len");
        return NINLIL_R5_BIND_MISMATCH;
    }
    return NINLIL_R5_OK;
}

static ninlil_radio_hal_status_t r5_map_to_hal_status(ninlil_r5_status_t st)
{
    switch (st) {
    case NINLIL_R5_OK:
        return NINLIL_RADIO_HAL_OK;
    case NINLIL_R5_BIND_MISMATCH:
    case NINLIL_R5_REGISTRY_MISS:
    case NINLIL_R5_PROFILE_DENIED:
        return NINLIL_RADIO_HAL_PERMIT_DENIED;
    case NINLIL_R5_INVALID_ARGUMENT:
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    case NINLIL_R5_INVALID_STATE:
        return NINLIL_RADIO_HAL_INVALID_STATE;
    default:
        return NINLIL_RADIO_HAL_PERMIT_ERROR;
    }
}

static void r5_fill_hal_error(
    ninlil_radio_hal_error_t *out_error,
    int out_safe,
    ninlil_radio_hal_status_t status,
    ninlil_radio_hal_stage_t stage,
    ninlil_radio_hal_reason_t reason,
    const char *hint)
{
    size_t i;
    if (out_error == NULL || out_safe == 0) {
        return;
    }
    (void)memset(out_error, 0, sizeof(*out_error));
    out_error->status = status;
    out_error->stage = stage;
    out_error->reason = reason;
    if (hint != NULL) {
        for (i = 0u; i + 1u < NINLIL_RADIO_HAL_HINT_BYTES && hint[i] != '\0';
             ++i) {
            out_error->hint[i] = hint[i];
        }
        out_error->hint[i] = '\0';
    }
}

/*
 * Permit alias reject-before-dereference (R1/R5 order):
 *   A) fixed-size container overlaps only (never read frame->bytes/length)
 *   B) snapshot frame bytes/length after containers are safe
 *   C) geometric frame-bytes overlaps (capped length; pure oversize ≠ ALIAS)
 * Returns 1 = ALIAS reject. Caller returns INVALID_ARGUMENT + REASON_ALIAS with
 * ZERO mutation of owner (stats/last_error/in_api/registry), const permit,
 * frame container, bounded frame bytes, and unsafe out_error canaries.
 * Pure oversize is not returned here — caller uses REASON_OVERSIZE after.
 * *out_safe_io is 1 only when out_error is non-NULL and disjoint from
 * owner/inputs so HAL may write there; otherwise 0 (no write).
 */
static int r5_permit_alias_reject(
    ninlil_r5_t *r5,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    const ninlil_radio_hal_frame_view_t *frame,
    ninlil_radio_hal_error_t *out_error,
    int *out_safe_io)
{
    int out_safe = (out_error != NULL) ? 1 : 0;
    const uint8_t *frame_bytes = NULL;
    uint32_t frame_len = 0u;
    size_t clen = 0u;

    *out_safe_io = 0;

    /*
     * Phase A — fixed container ranges only. Do not load frame->bytes or
     * frame->length: the frame view may alias r5/permit, so those fields are
     * not trusted until containers are proven disjoint.
     */
    if (r5 != NULL && out_error != NULL
        && r5_ranges_overlap_ptr(
            r5, sizeof(*r5), out_error, sizeof(*out_error))) {
        return 1;
    }
    if (permit != NULL && out_error != NULL
        && r5_ranges_overlap_ptr(
            permit, sizeof(*permit), out_error, sizeof(*out_error))) {
        return 1;
    }
    if (frame != NULL && out_error != NULL
        && r5_ranges_overlap_ptr(
            frame, sizeof(*frame), out_error, sizeof(*out_error))) {
        return 1;
    }
    if (permit != NULL && frame != NULL
        && r5_ranges_overlap_ptr(
            permit, sizeof(*permit), frame, sizeof(*frame))) {
        *out_safe_io = out_safe;
        return 1;
    }
    if (r5 != NULL && permit != NULL
        && r5_ranges_overlap_ptr(r5, sizeof(*r5), permit, sizeof(*permit))) {
        *out_safe_io = out_safe;
        return 1;
    }
    if (r5 != NULL && frame != NULL
        && r5_ranges_overlap_ptr(r5, sizeof(*r5), frame, sizeof(*frame))) {
        *out_safe_io = out_safe;
        return 1;
    }

    /* Phase B — containers pairwise safe; snapshot frame fields locally. */
    if (frame != NULL) {
        frame_bytes = frame->bytes;
        frame_len = frame->length;
    }

    /* Phase C — geometric frame-bytes overlaps only (capped; not pure oversize). */
    clen = r5_frame_alias_check_len(frame_len);
    if (frame_bytes != NULL && clen > 0u) {
        if (r5 != NULL
            && r5_ranges_overlap_ptr(r5, sizeof(*r5), frame_bytes, clen)) {
            *out_safe_io = out_safe;
            return 1;
        }
        if (permit != NULL
            && r5_ranges_overlap_ptr(
                permit, sizeof(*permit), frame_bytes, clen)) {
            *out_safe_io = out_safe;
            return 1;
        }
        if (frame != NULL
            && r5_ranges_overlap_ptr(
                frame, sizeof(*frame), frame_bytes, clen)) {
            *out_safe_io = out_safe;
            return 1;
        }
        if (out_error != NULL
            && r5_ranges_overlap_ptr(
                out_error, sizeof(*out_error), frame_bytes, clen)) {
            return 1; /* out_error overlaps frame bytes: never write it */
        }
    }

    *out_safe_io = out_safe;
    return 0;
}

/*
 * Disjoint frame structural reject (not ALIAS). Returns HAL reason or 0.
 * NULL bytes + nonzero length, or length > MAX → fail-closed before work.
 */
static ninlil_radio_hal_reason_t r5_permit_frame_struct_reason(
    const ninlil_radio_hal_frame_view_t *frame)
{
    if (frame == NULL) {
        return NINLIL_RADIO_HAL_REASON_NONE;
    }
    if (frame->bytes == NULL) {
        return (frame->length != 0u) ? NINLIL_RADIO_HAL_REASON_STRUCT_INVALID
                                     : NINLIL_RADIO_HAL_REASON_NONE;
    }
    if (frame->length > NINLIL_RADIO_HAL_MAX_FRAME_BYTES) {
        return NINLIL_RADIO_HAL_REASON_OVERSIZE;
    }
    return NINLIL_RADIO_HAL_REASON_NONE;
}

ninlil_radio_hal_status_t ninlil_r5_permit_validate(
    void *ctx,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    const ninlil_radio_hal_frame_view_t *frame,
    ninlil_radio_hal_error_t *out_error)
{
    ninlil_r5_t *r5 = (ninlil_r5_t *)ctx;
    ninlil_r5_error_t err;
    ninlil_r5_bind_item_t item = NINLIL_R5_BIND_NONE;
    ninlil_r5_status_t st;
    ninlil_radio_hal_status_t hst;
    int out_safe = 0;
    ninlil_radio_hal_error_t *pcp_out = NULL;

    if (r5_permit_alias_reject(r5, permit, frame, out_error, &out_safe) != 0) {
        /* Alias reject: zero owner/input mutation; write safe out_error only. */
        r5_fill_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_INVALID_ARGUMENT,
            NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
            NINLIL_RADIO_HAL_REASON_ALIAS, "alias");
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    {
        ninlil_radio_hal_reason_t fr = r5_permit_frame_struct_reason(frame);
        if (fr != NINLIL_RADIO_HAL_REASON_NONE) {
            /* Disjoint oversize / NULL+nonzero: not ALIAS; no validate work. */
            r5_fill_hal_error(
                out_error, out_safe, NINLIL_RADIO_HAL_INVALID_ARGUMENT,
                NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE, fr, "frame_len");
            return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
        }
    }
    if (r5 == NULL || r5->magic != NINLIL_R5_MAGIC_VALUE
        || r5->lifecycle != R5_LC_ACTIVE || r5->pcp == NULL) {
        r5_fill_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_DEFAULT_DENY,
            NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
            NINLIL_RADIO_HAL_REASON_UNBOUND_PERMIT, "r5");
        return NINLIL_RADIO_HAL_DEFAULT_DENY;
    }
    if (r5->in_api != 0u) {
        r5_fill_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_BUSY,
            NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
            NINLIL_RADIO_HAL_REASON_REENTRANT, "reentry");
        return NINLIL_RADIO_HAL_BUSY;
    }
    r5->in_api = 1u;
    (void)memset(&err, 0, sizeof(err));
    st = r5_check_hal_against_registry(
        r5, permit, frame, NINLIL_R5_STAGE_VALIDATE, &err, 1, &item);
    if (st != NINLIL_R5_OK) {
        r5->in_api = 0u;
        r5_sat_inc(&r5->stats.validate_deny);
        r5_fill_hal_error(
            out_error, out_safe, r5_map_to_hal_status(st),
            NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
            NINLIL_RADIO_HAL_REASON_VALIDATOR_DENY, err.hint);
        return r5_map_to_hal_status(st);
    }
    /* Only pass out_error to R2 when proven non-aliasing. */
    pcp_out = (out_safe != 0) ? out_error : NULL;
    hst = ninlil_pcp_validate(r5->pcp, permit, frame, pcp_out);
    r5->in_api = 0u;
    if (hst != NINLIL_RADIO_HAL_OK) {
        r5_sat_inc(&r5->stats.validate_deny);
        return hst;
    }
    r5_sat_inc(&r5->stats.validate_ok);
    return NINLIL_RADIO_HAL_OK;
}

ninlil_radio_hal_status_t ninlil_r5_permit_consume(
    void *ctx,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    const ninlil_radio_hal_frame_view_t *frame,
    ninlil_radio_hal_error_t *out_error)
{
    ninlil_r5_t *r5 = (ninlil_r5_t *)ctx;
    ninlil_r5_error_t err;
    ninlil_r5_bind_item_t item = NINLIL_R5_BIND_NONE;
    ninlil_r5_status_t st;
    ninlil_radio_hal_status_t hst;
    int out_safe = 0;
    ninlil_radio_hal_error_t *pcp_out = NULL;

    if (r5_permit_alias_reject(r5, permit, frame, out_error, &out_safe) != 0) {
        /* Alias reject: zero owner/input mutation; write safe out_error only. */
        r5_fill_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_INVALID_ARGUMENT,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_ALIAS, "alias");
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    {
        ninlil_radio_hal_reason_t fr = r5_permit_frame_struct_reason(frame);
        if (fr != NINLIL_RADIO_HAL_REASON_NONE) {
            r5_fill_hal_error(
                out_error, out_safe, NINLIL_RADIO_HAL_INVALID_ARGUMENT,
                NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME, fr, "frame_len");
            return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
        }
    }
    if (r5 == NULL || r5->magic != NINLIL_R5_MAGIC_VALUE
        || r5->lifecycle != R5_LC_ACTIVE || r5->pcp == NULL) {
        r5_fill_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_DEFAULT_DENY,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_UNBOUND_PERMIT, "r5");
        return NINLIL_RADIO_HAL_DEFAULT_DENY;
    }
    if (r5->in_api != 0u) {
        r5_fill_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_BUSY,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_REENTRANT, "reentry");
        return NINLIL_RADIO_HAL_BUSY;
    }
    r5->in_api = 1u;
    (void)memset(&err, 0, sizeof(err));
    st = r5_check_hal_against_registry(
        r5, permit, frame, NINLIL_R5_STAGE_CONSUME, &err, 1, &item);
    if (st != NINLIL_R5_OK) {
        r5->in_api = 0u;
        r5_sat_inc(&r5->stats.consume_deny);
        if (st == NINLIL_R5_REGISTRY_MISS) {
            r5_fill_hal_error(
                out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_FENCED,
                NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
                NINLIL_RADIO_HAL_REASON_CONSUME_FENCED, "registry_miss");
            return NINLIL_RADIO_HAL_CONSUME_FENCED;
        }
        r5_fill_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_DENIED,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_CONSUME_DENY, err.hint);
        return NINLIL_RADIO_HAL_CONSUME_DENIED;
    }
    pcp_out = (out_safe != 0) ? out_error : NULL;
    hst = ninlil_pcp_consume(r5->pcp, permit, frame, pcp_out);
    if (hst != NINLIL_RADIO_HAL_OK) {
        r5->in_api = 0u;
        r5_sat_inc(&r5->stats.consume_deny);
        return hst;
    }
    r5_registry_remove(r5, permit->permit_sequence);
    r5->in_api = 0u;
    r5_sat_inc(&r5->stats.consume_ok);
    return NINLIL_RADIO_HAL_OK;
}

void ninlil_r5_permit_ops(ninlil_radio_hal_permit_ops_t *out_ops)
{
    if (out_ops == NULL) {
        return;
    }
    out_ops->validate = ninlil_r5_permit_validate;
    out_ops->consume = ninlil_r5_permit_consume;
}

ninlil_r5_status_t ninlil_r5_fence_after_revoke(
    ninlil_r5_t *r5,
    ninlil_r5_error_t *out_error)
{
    int out_safe = 1;
    uint64_t target_gen;
    uint64_t r2_gen = 0u;
    ninlil_pcp_error_t perr;
    ninlil_pcp_status_t pst;
    ninlil_radio_hal_live_binding_t live;
    ninlil_pcp_live_profile_t plive;

    if (!r5_guard_active(r5, out_error, &out_safe, NINLIL_R5_STAGE_FENCE)) {
        return r5 != NULL ? r5->last_error.status : NINLIL_R5_INVALID_ARGUMENT;
    }
    out_safe = r5_out_error_safe(r5, out_error);
    if (r5->assignment_bound == 0u || r5->profiles_active == 0u) {
        r5_set_error(
            r5, out_error, out_safe, NINLIL_R5_INVALID_STATE,
            NINLIL_R5_STAGE_FENCE, NINLIL_R5_REASON_UNBOUND, NINLIL_R5_BIND_NONE,
            "unbound");
        return NINLIL_R5_INVALID_STATE;
    }
    /*
     * Caller MUST have revoked R2 outstanding first. Local registry may still
     * hold entries; they are cleared only after durable gen commit succeeds.
     */

    /*
     * Two-phase target gen: first attempt stores fence_target_generation =
     * old+1 with fence_pending. Retry MUST use stored target (never the
     * current assignment.permit_bind_generation, which stays old until
     * verified durable success).
     */
    if (r5->fence_pending != 0u) {
        if (r5->fence_target_generation == 0u
            || r5->fence_target_generation
                <= r5->assignment.permit_bind_generation) {
            r5_set_error(
                r5, out_error, out_safe, NINLIL_R5_INVALID_STATE,
                NINLIL_R5_STAGE_FENCE, NINLIL_R5_REASON_STRUCT,
                NINLIL_R5_BIND_PERMIT_GEN, "pend_tgt");
            return NINLIL_R5_INVALID_STATE;
        }
        target_gen = r5->fence_target_generation;
    } else {
        if (r5->assignment.permit_bind_generation == UINT64_MAX) {
            r5_set_error(
                r5, out_error, out_safe, NINLIL_R5_CAPACITY, NINLIL_R5_STAGE_FENCE,
                NINLIL_R5_REASON_STRUCT, NINLIL_R5_BIND_PERMIT_GEN, "gen_max");
            return NINLIL_R5_CAPACITY;
        }
        target_gen = r5->assignment.permit_bind_generation + 1u;
        r5->fence_pending = 1u;
        r5->fence_target_generation = target_gen;
        /* Do NOT clear registry/gen locally until durable OK. */
    }

    if (r5->pcp_bound != 0u && r5->pcp != NULL) {
        (void)memset(&live, 0, sizeof(live));
        live.hardware_profile_id = r5->hw.profile_id;
        live.hardware_profile_rev = r5->hw.profile_rev;
        live.regulatory_profile_id = r5->reg.profile_id;
        live.regulatory_profile_rev = r5->reg.profile_rev;
        live.site_assignment_id = r5->assignment.site_assignment_id;
        live.site_assignment_rev = r5->assignment.site_assignment_rev;
        live.site_assignment_epoch = r5->assignment.site_assignment_epoch;
        live.transmitter_id = r5->assignment.transmitter_id;
        live.channel_id = r5->assignment.channel_id;
        live.phy = r5->assignment.phy;
        live.max_airtime_us = r5->reg.max_airtime_ceiling_us;
        live.reserved_zero = 0u;
        plive = live;
        (void)memset(&perr, 0, sizeof(perr));
        pst = r5_pcp_commit_live_guarded(
            r5, r5->pcp, &plive, target_gen, &perr);
        if (pst == NINLIL_PCP_COMMIT_UNKNOWN) {
            /* Durable unknown: leave fence_pending+target; do not destroy local. */
            r5_set_error(
                r5, out_error, out_safe, NINLIL_R5_PCP, NINLIL_R5_STAGE_FENCE,
                NINLIL_R5_REASON_PCP, NINLIL_R5_BIND_PERMIT_GEN, "cu");
            return NINLIL_R5_PCP;
        }
        if (pst != NINLIL_PCP_OK) {
            /* Ordinary put/commit fail: keep pending target for retry. */
            r5_set_error(
                r5, out_error, out_safe, NINLIL_R5_PCP, NINLIL_R5_STAGE_FENCE,
                NINLIL_R5_REASON_PCP, NINLIL_R5_BIND_PERMIT_GEN, "fence_set");
            return NINLIL_R5_PCP;
        }
        pst = ninlil_pcp_get_assignment_generation(r5->pcp, &r2_gen);
        if (pst != NINLIL_PCP_OK || r2_gen != target_gen) {
            r5_set_error(
                r5, out_error, out_safe, NINLIL_R5_PCP, NINLIL_R5_STAGE_FENCE,
                NINLIL_R5_REASON_PCP, NINLIL_R5_BIND_PERMIT_GEN, "gen_chk");
            return NINLIL_R5_PCP;
        }
    }

    /* Durable success (or no pcp): local commit only after verified target. */
    (void)memset(r5->registry, 0, sizeof(r5->registry));
    r5->registry_count = 0u;
    r5->assignment.permit_bind_generation = target_gen;
    r5->fence_pending = 0u;
    r5->fence_target_generation = 0u;
    r5_sat_inc(&r5->stats.fence_ok);
    r5_set_error(
        r5, out_error, out_safe, NINLIL_R5_OK, NINLIL_R5_STAGE_FENCE,
        NINLIL_R5_REASON_NONE, NINLIL_R5_BIND_NONE, NULL);
    return NINLIL_R5_OK;
}

void ninlil_r5_stats(const ninlil_r5_t *r5, ninlil_r5_stats_t *out_stats)
{
    if (out_stats == NULL) {
        return;
    }
    if (r5 != NULL
        && r5_ranges_overlap_ptr(r5, sizeof(*r5), out_stats, sizeof(*out_stats))) {
        return; /* alias: leave out_stats unchanged */
    }
    if (r5 == NULL) {
        (void)memset(out_stats, 0, sizeof(*out_stats));
        return;
    }
    *out_stats = r5->stats;
}

void ninlil_r5_last_error(const ninlil_r5_t *r5, ninlil_r5_error_t *out_error)
{
    if (out_error == NULL) {
        return;
    }
    if (r5 != NULL
        && r5_ranges_overlap_ptr(r5, sizeof(*r5), out_error, sizeof(*out_error))) {
        return; /* alias: leave out_error unchanged */
    }
    if (r5 == NULL) {
        (void)memset(out_error, 0, sizeof(*out_error));
        return;
    }
    *out_error = r5->last_error;
}
