/*
 * R2 Physical Compliance Permit authority — production-private portable Core.
 *
 * Normative: docs/24-r2-physical-compliance-permit-authority.md
 *            docs/adr/0004-r2-durable-permit-authority.md
 *            src/radio/pcp_authority.h
 *
 * Nonclaims: legal / Japan / R3–R10 / RF HIL / SX1262 TX / public ABI /
 * independent re-review GO. R3 airtime calculator is not integrated here;
 * per-permit max_airtime_us is taken from the issue request only.
 *
 * C11 strict, no heap, no VLA, no exceptions. Sole owner; reentry closed.
 */

#include "pcp_authority.h"

#include <string.h>

/* ---- Internal record constants ---- */

#define PCP_META_STATE_ACTIVE ((uint8_t)1u)
#define PCP_META_STATE_FENCED ((uint8_t)2u)
#define PCP_ISS_STATE_ISSUED ((uint8_t)1u)
#define PCP_ISS_STATE_CONSUMED ((uint8_t)2u)
#define PCP_ISS_STATE_REVOKED ((uint8_t)3u)

/*
 * Scan key index ceiling (seq+state only in scan struct — not full bodies).
 * Full ISSUED body decode uses:
 *   - scan loop: automatic val_buf[NINLIL_PCP_ISSUED_VALUE_BYTES] (one record)
 *   - I6/I11 body re-verify: pcp->iss_scratch[NINLIL_PCP_ISSUED_VALUE_BYTES]
 *     sole use for the duration of pcp_verify_iss_bodies (not concurrent with
 *     put_iss encode). Does not enlarge ninlil_pcp_t (≤ OBJECT_BYTES).
 */
#define PCP_SCAN_MAX_ISS ((size_t)256u)

static const uint8_t k_pcp_namespace[NINLIL_PCP_NAMESPACE_BYTES] = {
    'n', 'i', 'n', 'l', 'i', 'l', '.', 'p', 'c', 'p', '.', 'v', '1'
};
static const uint8_t k_meta_key[NINLIL_PCP_META_KEY_BYTES] = {
    'm', 'e', 't', 'a'
};
static const char k_hex[] = "0123456789abcdef";

/* ---- LE codec ---- */

static void pcp_put_u16_le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
}

static void pcp_put_u32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}

static void pcp_put_u64_le(uint8_t *p, uint64_t v)
{
    uint32_t i;

    for (i = 0u; i < 8u; ++i) {
        p[i] = (uint8_t)((v >> (i * 8u)) & 0xffu);
    }
}

static void pcp_put_i32_le(uint8_t *p, int32_t v)
{
    pcp_put_u32_le(p, (uint32_t)v);
}

static uint16_t pcp_get_u16_le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t pcp_get_u32_le(const uint8_t *p)
{
    return (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

static uint64_t pcp_get_u64_le(const uint8_t *p)
{
    uint64_t v = 0u;
    uint32_t i;

    for (i = 0u; i < 8u; ++i) {
        v |= ((uint64_t)p[i]) << (i * 8u);
    }
    return v;
}

static int32_t pcp_get_i32_le(const uint8_t *p)
{
    return (int32_t)pcp_get_u32_le(p);
}

/* ---- CRC32 (IEEE; poly 0xEDB88320, init/xorout 0xFFFFFFFF, refin/refout) ---- */

static uint32_t pcp_crc32(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xffffffffu;
    size_t i;

    if (data == NULL && len != 0u) {
        return 0u;
    }
    for (i = 0u; i < len; ++i) {
        uint32_t b;
        crc ^= (uint32_t)data[i];
        for (b = 0u; b < 8u; ++b) {
            uint32_t mask = (uint32_t)(-(int32_t)(crc & 1u));
            crc = (crc >> 1) ^ (0xedb88320u & mask);
        }
    }
    return ~crc;
}

/* ---- ID / mem helpers ---- */

static int pcp_id_is_zero(const uint8_t *id, size_t n)
{
    size_t i;

    for (i = 0u; i < n; ++i) {
        if (id[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int pcp_id_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

static int pcp_hal_id_is_zero(const ninlil_radio_hal_id_t *id)
{
    return pcp_id_is_zero(id->bytes, NINLIL_RADIO_HAL_ID_BYTES);
}

static int pcp_hal_id_equal(
    const ninlil_radio_hal_id_t *a,
    const ninlil_radio_hal_id_t *b)
{
    return memcmp(a->bytes, b->bytes, NINLIL_RADIO_HAL_ID_BYTES) == 0;
}

static int pcp_phy_equal(
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

static void pcp_sat_inc(uint64_t *c)
{
    if (c == NULL) {
        return;
    }
    if (*c != UINT64_MAX) {
        *c += 1u;
    }
}

static int pcp_ranges_overlap(
    const void *a,
    size_t asz,
    const void *b,
    size_t bsz)
{
    const uintptr_t aa = (uintptr_t)a;
    const uintptr_t bb = (uintptr_t)b;
    const uintptr_t ae = aa + asz;
    const uintptr_t be = bb + bsz;

    if (a == NULL || b == NULL || asz == 0u || bsz == 0u) {
        return 0;
    }
    if (ae < aa || be < bb) {
        return 1; /* overflow: treat as unsafe */
    }
    return aa < be && bb < ae;
}

/* ---- Error / stage helpers ---- */

static void pcp_clear_error(ninlil_pcp_error_t *err)
{
    if (err == NULL) {
        return;
    }
    (void)memset(err, 0, sizeof(*err));
}

static void pcp_set_error(
    ninlil_pcp_t *pcp,
    ninlil_pcp_error_t *out_error,
    int out_safe,
    ninlil_pcp_status_t status,
    ninlil_pcp_stage_t stage,
    ninlil_pcp_reason_t reason,
    const char *hint)
{
    ninlil_pcp_error_t local;

    pcp_clear_error(&local);
    local.status = status;
    local.stage = stage;
    local.reason = reason;
    if (hint != NULL) {
        size_t i;
        for (i = 0u; i + 1u < NINLIL_PCP_HINT_BYTES && hint[i] != '\0'; ++i) {
            local.hint[i] = hint[i];
        }
        local.hint[i] = '\0';
    }
    if (pcp != NULL) {
        pcp->last_error = local;
    }
    if (out_error != NULL && out_safe != 0) {
        *out_error = local;
    }
}

/* Defined once early (C11 single definition; no late redeclare). */
static void pcp_set_hal_error(
    ninlil_radio_hal_error_t *out_error,
    int out_safe,
    ninlil_radio_hal_status_t status,
    ninlil_radio_hal_stage_t stage,
    ninlil_radio_hal_reason_t reason,
    const char *hint)
{
    if (out_error == NULL || out_safe == 0) {
        return;
    }
    (void)memset(out_error, 0, sizeof(*out_error));
    out_error->status = status;
    out_error->stage = stage;
    out_error->reason = reason;
    if (hint != NULL) {
        size_t i;
        for (i = 0u; i + 1u < NINLIL_RADIO_HAL_HINT_BYTES && hint[i] != '\0';
             ++i) {
            out_error->hint[i] = hint[i];
        }
        out_error->hint[i] = '\0';
    }
}

/*
 * Consume fence fail-closed (docs/24 §10.10 + F_s semantics).
 * Priority: CORRUPT → ERROR; STORAGE → FENCED; CLOCK → FENCED@TIME.
 * Returns 1 if rejected (out_* filled); 0 if no fence bits.
 */
static int pcp_consume_fence_reject(
    uint32_t fence_bits,
    ninlil_radio_hal_status_t *out_hs,
    ninlil_radio_hal_stage_t *out_stage,
    ninlil_radio_hal_reason_t *out_reason,
    const char **out_hint)
{
    if ((fence_bits & NINLIL_PCP_FENCE_BIT_CORRUPT) != 0u) {
        *out_hs = NINLIL_RADIO_HAL_CONSUME_ERROR;
        *out_stage = NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME;
        *out_reason = NINLIL_RADIO_HAL_REASON_CONSUME_ERROR;
        *out_hint = "pcp_storage";
        return 1;
    }
    if ((fence_bits & NINLIL_PCP_FENCE_BIT_STORAGE) != 0u) {
        *out_hs = NINLIL_RADIO_HAL_CONSUME_FENCED;
        *out_stage = NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME;
        *out_reason = NINLIL_RADIO_HAL_REASON_CONSUME_FENCED;
        *out_hint = "pcp_commit_unknown";
        return 1;
    }
    if ((fence_bits & NINLIL_PCP_FENCE_BIT_CLOCK) != 0u) {
        *out_hs = NINLIL_RADIO_HAL_CONSUME_FENCED;
        *out_stage = NINLIL_RADIO_HAL_STAGE_TIME;
        *out_reason = NINLIL_RADIO_HAL_REASON_CONSUME_FENCED;
        *out_hint = "pcp_clock_fault";
        return 1;
    }
    return 0;
}

/* ---- Fence RAM helpers ---- */

static void pcp_clear_ram_validate(ninlil_pcp_t *pcp)
{
    if (pcp == NULL) {
        return;
    }
    (void)memset(&pcp->ram_validate, 0, sizeof(pcp->ram_validate));
}

static void pcp_set_ram_trust(
    ninlil_pcp_t *pcp,
    const uint8_t epoch[NINLIL_PCP_ID_BYTES],
    uint64_t now_ms)
{
    (void)memcpy(pcp->ram_trust.clock_epoch_id, epoch, NINLIL_PCP_ID_BYTES);
    pcp->ram_trust.now_ms = now_ms;
    pcp->ram_trust.valid = 1u;
    pcp->ram_trust.reserved_zero = 0u;
}

static void pcp_set_fence_storage(ninlil_pcp_t *pcp)
{
    pcp->fence_bits |= NINLIL_PCP_FENCE_BIT_STORAGE;
    if ((pcp->fence_bits & NINLIL_PCP_FENCE_BIT_CORRUPT) == 0u) {
        pcp->fence_code = NINLIL_PCP_FC_STORAGE;
    }
    pcp_sat_inc(&pcp->stats.fence_set);
    pcp_sat_inc(&pcp->stats.storage_commit_unknown);
}

static void pcp_set_fence_corrupt(ninlil_pcp_t *pcp)
{
    pcp->fence_bits |= NINLIL_PCP_FENCE_BIT_CORRUPT;
    pcp->fence_code = NINLIL_PCP_FC_CORRUPT;
    pcp_sat_inc(&pcp->stats.fence_set);
}

static void pcp_set_fence_clock(ninlil_pcp_t *pcp, ninlil_pcp_fence_code_t code)
{
    pcp->fence_bits |= NINLIL_PCP_FENCE_BIT_CLOCK;
    pcp->fence_code = code;
    pcp_sat_inc(&pcp->stats.fence_set);
}

/* ---- Meta / issued decode structs ---- */

typedef struct pcp_meta {
    uint32_t magic;
    uint16_t schema;
    uint8_t meta_state;
    uint8_t fence_bits;
    uint8_t authority_instance_id[NINLIL_PCP_ID_BYTES];
    uint64_t next_issue_seq;
    uint64_t last_consumed_seq;
    uint32_t outstanding_count;
    uint32_t fence_code;
    ninlil_radio_hal_id_t bound_hardware_profile_id;
    uint32_t bound_hardware_profile_rev;
    ninlil_radio_hal_id_t bound_regulatory_profile_id;
    uint32_t bound_regulatory_profile_rev;
    ninlil_radio_hal_id_t bound_site_assignment_id;
    uint32_t bound_site_assignment_rev;
    uint64_t bound_site_assignment_epoch;
    ninlil_radio_hal_id_t bound_transmitter_id;
    uint32_t bound_channel_id;
    ninlil_radio_hal_phy_t bound_phy;
    uint32_t bound_max_airtime_ceiling_us;
    uint64_t assignment_generation;
    uint8_t last_trusted_epoch_id[NINLIL_PCP_ID_BYTES];
    uint64_t last_trusted_now_ms;
    uint64_t reserved_zero;
    uint32_t crc32;
} pcp_meta_t;

typedef struct pcp_issued {
    uint32_t magic;
    uint16_t schema;
    uint8_t state;
    uint8_t flags;
    uint64_t permit_sequence;
    uint8_t clock_epoch_id[NINLIL_PCP_ID_BYTES];
    uint64_t not_before_ms;
    uint64_t expiry_ms;
    ninlil_radio_hal_id_t hardware_profile_id;
    uint32_t hardware_profile_rev;
    ninlil_radio_hal_id_t regulatory_profile_id;
    uint32_t regulatory_profile_rev;
    ninlil_radio_hal_id_t site_assignment_id;
    uint32_t site_assignment_rev;
    uint64_t site_assignment_epoch;
    ninlil_radio_hal_id_t transmitter_id;
    uint32_t channel_id;
    ninlil_radio_hal_phy_t phy;
    uint8_t frame_digest[NINLIL_PCP_DIGEST_BYTES];
    uint32_t frame_digest_algorithm;
    uint32_t frame_byte_length;
    uint32_t max_airtime_us;
    uint8_t authority_instance_id[NINLIL_PCP_ID_BYTES];
    uint64_t issue_generation;
    uint64_t reserved_zero;
    uint32_t crc32;
} pcp_issued_t;

/*
 * Per-key index only (compact). Body semantics are re-validated via get into
 * pcp->iss_scratch after the namespace walk (I6/I11/deadline/state).
 */
typedef struct pcp_scan_iss {
    uint64_t seq;
    uint8_t state;
    uint8_t valid;
} pcp_scan_iss_t;

typedef struct pcp_scan {
    int meta_present;
    pcp_meta_t meta;
    pcp_scan_iss_t iss[PCP_SCAN_MAX_ISS];
    size_t iss_count;
    uint32_t issued_count;
    int foreign;
    int corrupt;
} pcp_scan_t;

static int pcp_lcore_equal_iss_meta(const pcp_issued_t *iss, const pcp_meta_t *m);

static ninlil_pcp_status_t pcp_txn_get_iss(
    ninlil_pcp_t *pcp,
    ninlil_storage_txn_t txn,
    uint64_t seq,
    pcp_issued_t *out,
    int *out_absent,
    ninlil_pcp_stage_t stage,
    ninlil_pcp_error_t *out_error,
    int out_safe);

static ninlil_pcp_status_t pcp_txn_get_meta(
    ninlil_pcp_t *pcp,
    ninlil_storage_txn_t txn,
    pcp_meta_t *out,
    int *out_absent,
    ninlil_pcp_stage_t stage,
    ninlil_pcp_error_t *out_error,
    int out_safe);

static ninlil_pcp_status_t pcp_txn_put_meta(
    ninlil_pcp_t *pcp,
    ninlil_storage_txn_t txn,
    const pcp_meta_t *meta,
    ninlil_pcp_stage_t stage,
    ninlil_pcp_error_t *out_error,
    int out_safe);

static ninlil_pcp_status_t pcp_rw_scan_check(
    ninlil_pcp_t *pcp,
    ninlil_storage_txn_t txn,
    pcp_scan_t *scan,
    ninlil_pcp_stage_t stage,
    ninlil_pcp_error_t *out_error,
    int out_safe);

/* ---- Encode / decode meta & issued ---- */

static void pcp_encode_phy(uint8_t *buf /* 16 bytes at off 136 relative */,
    const ninlil_radio_hal_phy_t *phy)
{
    pcp_put_u32_le(buf + 0, phy->bandwidth_hz);
    buf[4] = phy->spreading_factor;
    buf[5] = phy->coding_rate_denom;
    pcp_put_u16_le(buf + 6, phy->preamble_symbols);
    pcp_put_i32_le(buf + 8, phy->tx_power_mdb);
    pcp_put_u32_le(buf + 12, phy->phy_flags);
}

static void pcp_decode_phy(const uint8_t *buf, ninlil_radio_hal_phy_t *phy)
{
    phy->bandwidth_hz = pcp_get_u32_le(buf + 0);
    phy->spreading_factor = buf[4];
    phy->coding_rate_denom = buf[5];
    phy->preamble_symbols = pcp_get_u16_le(buf + 6);
    phy->tx_power_mdb = pcp_get_i32_le(buf + 8);
    phy->phy_flags = pcp_get_u32_le(buf + 12);
}

static void pcp_encode_meta(const pcp_meta_t *m, uint8_t out[NINLIL_PCP_META_VALUE_BYTES])
{
    (void)memset(out, 0, NINLIL_PCP_META_VALUE_BYTES);
    pcp_put_u32_le(out + 0, m->magic);
    pcp_put_u16_le(out + 4, m->schema);
    out[6] = m->meta_state;
    out[7] = m->fence_bits;
    (void)memcpy(out + 8, m->authority_instance_id, 16u);
    pcp_put_u64_le(out + 24, m->next_issue_seq);
    pcp_put_u64_le(out + 32, m->last_consumed_seq);
    pcp_put_u32_le(out + 40, m->outstanding_count);
    pcp_put_u32_le(out + 44, m->fence_code);
    (void)memcpy(out + 48, m->bound_hardware_profile_id.bytes, 16u);
    pcp_put_u32_le(out + 64, m->bound_hardware_profile_rev);
    (void)memcpy(out + 68, m->bound_regulatory_profile_id.bytes, 16u);
    pcp_put_u32_le(out + 84, m->bound_regulatory_profile_rev);
    (void)memcpy(out + 88, m->bound_site_assignment_id.bytes, 16u);
    pcp_put_u32_le(out + 104, m->bound_site_assignment_rev);
    pcp_put_u64_le(out + 108, m->bound_site_assignment_epoch);
    (void)memcpy(out + 116, m->bound_transmitter_id.bytes, 16u);
    pcp_put_u32_le(out + 132, m->bound_channel_id);
    pcp_encode_phy(out + 136, &m->bound_phy);
    pcp_put_u32_le(out + 152, m->bound_max_airtime_ceiling_us);
    pcp_put_u64_le(out + 156, m->assignment_generation);
    (void)memcpy(out + 164, m->last_trusted_epoch_id, 16u);
    pcp_put_u64_le(out + 180, m->last_trusted_now_ms);
    pcp_put_u64_le(out + 188, m->reserved_zero);
    pcp_put_u32_le(out + 196, pcp_crc32(out, 196u));
}

static int pcp_decode_meta(const uint8_t in[NINLIL_PCP_META_VALUE_BYTES], pcp_meta_t *m)
{
    uint32_t crc;

    (void)memset(m, 0, sizeof(*m));
    m->magic = pcp_get_u32_le(in + 0);
    m->schema = pcp_get_u16_le(in + 4);
    m->meta_state = in[6];
    m->fence_bits = in[7];
    (void)memcpy(m->authority_instance_id, in + 8, 16u);
    m->next_issue_seq = pcp_get_u64_le(in + 24);
    m->last_consumed_seq = pcp_get_u64_le(in + 32);
    m->outstanding_count = pcp_get_u32_le(in + 40);
    m->fence_code = pcp_get_u32_le(in + 44);
    (void)memcpy(m->bound_hardware_profile_id.bytes, in + 48, 16u);
    m->bound_hardware_profile_rev = pcp_get_u32_le(in + 64);
    (void)memcpy(m->bound_regulatory_profile_id.bytes, in + 68, 16u);
    m->bound_regulatory_profile_rev = pcp_get_u32_le(in + 84);
    (void)memcpy(m->bound_site_assignment_id.bytes, in + 88, 16u);
    m->bound_site_assignment_rev = pcp_get_u32_le(in + 104);
    m->bound_site_assignment_epoch = pcp_get_u64_le(in + 108);
    (void)memcpy(m->bound_transmitter_id.bytes, in + 116, 16u);
    m->bound_channel_id = pcp_get_u32_le(in + 132);
    pcp_decode_phy(in + 136, &m->bound_phy);
    m->bound_max_airtime_ceiling_us = pcp_get_u32_le(in + 152);
    m->assignment_generation = pcp_get_u64_le(in + 156);
    (void)memcpy(m->last_trusted_epoch_id, in + 164, 16u);
    m->last_trusted_now_ms = pcp_get_u64_le(in + 180);
    m->reserved_zero = pcp_get_u64_le(in + 188);
    m->crc32 = pcp_get_u32_le(in + 196);
    crc = pcp_crc32(in, 196u);
    if (crc != m->crc32) {
        return 0;
    }
    if (m->magic != NINLIL_PCP_MAGIC || m->schema != NINLIL_PCP_SCHEMA_VERSION) {
        return 0;
    }
    if (m->reserved_zero != 0u) {
        return 0;
    }
    return 1;
}

static void pcp_encode_issued(
    const pcp_issued_t *iss,
    uint8_t out[NINLIL_PCP_ISSUED_VALUE_BYTES])
{
    (void)memset(out, 0, NINLIL_PCP_ISSUED_VALUE_BYTES);
    pcp_put_u32_le(out + 0, iss->magic);
    pcp_put_u16_le(out + 4, iss->schema);
    out[6] = iss->state;
    out[7] = iss->flags;
    pcp_put_u64_le(out + 8, iss->permit_sequence);
    (void)memcpy(out + 16, iss->clock_epoch_id, 16u);
    pcp_put_u64_le(out + 32, iss->not_before_ms);
    pcp_put_u64_le(out + 40, iss->expiry_ms);
    (void)memcpy(out + 48, iss->hardware_profile_id.bytes, 16u);
    pcp_put_u32_le(out + 64, iss->hardware_profile_rev);
    (void)memcpy(out + 68, iss->regulatory_profile_id.bytes, 16u);
    pcp_put_u32_le(out + 84, iss->regulatory_profile_rev);
    (void)memcpy(out + 88, iss->site_assignment_id.bytes, 16u);
    pcp_put_u32_le(out + 104, iss->site_assignment_rev);
    pcp_put_u64_le(out + 108, iss->site_assignment_epoch);
    (void)memcpy(out + 116, iss->transmitter_id.bytes, 16u);
    pcp_put_u32_le(out + 132, iss->channel_id);
    pcp_encode_phy(out + 136, &iss->phy);
    (void)memcpy(out + 152, iss->frame_digest, 32u);
    pcp_put_u32_le(out + 184, iss->frame_digest_algorithm);
    pcp_put_u32_le(out + 188, iss->frame_byte_length);
    pcp_put_u32_le(out + 192, iss->max_airtime_us);
    (void)memcpy(out + 196, iss->authority_instance_id, 16u);
    pcp_put_u64_le(out + 212, iss->issue_generation);
    pcp_put_u64_le(out + 220, iss->reserved_zero);
    pcp_put_u32_le(out + 228, pcp_crc32(out, 228u));
}

static int pcp_decode_issued(
    const uint8_t in[NINLIL_PCP_ISSUED_VALUE_BYTES],
    pcp_issued_t *iss)
{
    uint32_t crc;

    (void)memset(iss, 0, sizeof(*iss));
    iss->magic = pcp_get_u32_le(in + 0);
    iss->schema = pcp_get_u16_le(in + 4);
    iss->state = in[6];
    iss->flags = in[7];
    iss->permit_sequence = pcp_get_u64_le(in + 8);
    (void)memcpy(iss->clock_epoch_id, in + 16, 16u);
    iss->not_before_ms = pcp_get_u64_le(in + 32);
    iss->expiry_ms = pcp_get_u64_le(in + 40);
    (void)memcpy(iss->hardware_profile_id.bytes, in + 48, 16u);
    iss->hardware_profile_rev = pcp_get_u32_le(in + 64);
    (void)memcpy(iss->regulatory_profile_id.bytes, in + 68, 16u);
    iss->regulatory_profile_rev = pcp_get_u32_le(in + 84);
    (void)memcpy(iss->site_assignment_id.bytes, in + 88, 16u);
    iss->site_assignment_rev = pcp_get_u32_le(in + 104);
    iss->site_assignment_epoch = pcp_get_u64_le(in + 108);
    (void)memcpy(iss->transmitter_id.bytes, in + 116, 16u);
    iss->channel_id = pcp_get_u32_le(in + 132);
    pcp_decode_phy(in + 136, &iss->phy);
    (void)memcpy(iss->frame_digest, in + 152, 32u);
    iss->frame_digest_algorithm = pcp_get_u32_le(in + 184);
    iss->frame_byte_length = pcp_get_u32_le(in + 188);
    iss->max_airtime_us = pcp_get_u32_le(in + 192);
    (void)memcpy(iss->authority_instance_id, in + 196, 16u);
    iss->issue_generation = pcp_get_u64_le(in + 212);
    iss->reserved_zero = pcp_get_u64_le(in + 220);
    iss->crc32 = pcp_get_u32_le(in + 228);
    crc = pcp_crc32(in, 228u);
    if (crc != iss->crc32) {
        return 0;
    }
    if (iss->magic != NINLIL_PCP_MAGIC || iss->schema != NINLIL_PCP_SCHEMA_VERSION) {
        return 0;
    }
    if (iss->flags != 0u || iss->reserved_zero != 0u) {
        return 0;
    }
    return 1;
}

/* ---- Key builders ---- */

static void pcp_meta_key_view(ninlil_bytes_view_t *view)
{
    view->data = k_meta_key;
    view->length = (uint32_t)NINLIL_PCP_META_KEY_BYTES;
}

static int pcp_iss_key_build(uint8_t out[NINLIL_PCP_ISS_KEY_BYTES], uint64_t seq)
{
    uint32_t i;

    out[0] = (uint8_t)'i';
    out[1] = (uint8_t)'s';
    out[2] = (uint8_t)'s';
    out[3] = (uint8_t)'/';
    for (i = 0u; i < 16u; ++i) {
        uint32_t shift = (15u - i) * 4u;
        out[4u + i] = (uint8_t)k_hex[(seq >> shift) & 0xfu];
    }
    return 1;
}

static int pcp_iss_key_parse(const uint8_t *key, uint32_t len, uint64_t *out_seq)
{
    uint64_t seq = 0u;
    uint32_t i;

    if (len != (uint32_t)NINLIL_PCP_ISS_KEY_BYTES) {
        return 0;
    }
    if (key[0] != (uint8_t)'i' || key[1] != (uint8_t)'s'
        || key[2] != (uint8_t)'s' || key[3] != (uint8_t)'/') {
        return 0;
    }
    for (i = 0u; i < 16u; ++i) {
        uint8_t c = key[4u + i];
        uint8_t v;
        if (c >= (uint8_t)'0' && c <= (uint8_t)'9') {
            v = (uint8_t)(c - (uint8_t)'0');
        } else if (c >= (uint8_t)'a' && c <= (uint8_t)'f') {
            v = (uint8_t)(10u + (c - (uint8_t)'a'));
        } else {
            return 0; /* uppercase/other → corrupt */
        }
        seq = (seq << 4) | (uint64_t)v;
    }
    *out_seq = seq;
    return 1;
}

/* ---- Clock sample (§3) ---- */

typedef enum {
    PCP_CLK_OK_TRUSTED = 0,
    PCP_CLK_OK_UNCERTAIN,
    PCP_CLK_TEMP,
    PCP_CLK_FAULT_PERM,
    PCP_CLK_FAULT_ILLFORMED,
    PCP_CLK_FAULT_UNKNOWN,
    PCP_CLK_FAULT_REGRESSION
} pcp_clk_class_t;

typedef struct pcp_clk_result {
    pcp_clk_class_t klass;
    ninlil_time_sample_t sample; /* valid only for OK_* */
} pcp_clk_result_t;

static pcp_clk_result_t pcp_sample_clock(ninlil_pcp_t *pcp)
{
    pcp_clk_result_t r;
    ninlil_port_status_t st;
    ninlil_time_sample_t *s;

    (void)memset(&r, 0, sizeof(r));
    s = &r.sample;
    /*
     * Zero/poison the entire sample before callback. The port MUST write a
     * complete OK sample (V1–V5). Pre-filling abi_version/struct_size would
     * accept incomplete callbacks that only touch epoch/trust/now.
     * TEMP/PERM/unknown: fields ignored (§3.3); residual zeros are not
     * treated as ill-formed on those paths.
     */
    (void)memset(s, 0, sizeof(*s));

    st = pcp->clock_ops.now(pcp->clock_ops.user, s);
    if (st == NINLIL_PORT_TEMPORARY_FAILURE) {
        r.klass = PCP_CLK_TEMP;
        return r;
    }
    if (st == NINLIL_PORT_PERMANENT_FAILURE) {
        r.klass = PCP_CLK_FAULT_PERM;
        return r;
    }
    if (st != NINLIL_PORT_OK) {
        r.klass = PCP_CLK_FAULT_UNKNOWN;
        return r;
    }

    /* OK path: full V1–V5 must come from callback output (not pre-init). */
    if (s->abi_version != NINLIL_ABI_VERSION
        || s->struct_size < (uint16_t)sizeof(ninlil_time_sample_t)
        || s->reserved_zero != 0u
        || (s->trust != NINLIL_CLOCK_TRUSTED && s->trust != NINLIL_CLOCK_UNCERTAIN)
        || pcp_id_is_zero(s->clock_epoch_id.bytes, 16u)) {
        r.klass = PCP_CLK_FAULT_ILLFORMED;
        return r;
    }

    if (s->trust == NINLIL_CLOCK_UNCERTAIN) {
        r.klass = PCP_CLK_OK_UNCERTAIN;
        return r;
    }

    /* TRUSTED: regression vs ram_trust */
    if (pcp->ram_trust.valid != 0u
        && pcp_id_equal(
            s->clock_epoch_id.bytes, pcp->ram_trust.clock_epoch_id, 16u)
        && s->now_ms < pcp->ram_trust.now_ms) {
        r.klass = PCP_CLK_FAULT_REGRESSION;
        return r;
    }

    r.klass = PCP_CLK_OK_TRUSTED;
    return r;
}

static void pcp_apply_clock_fault_fence(ninlil_pcp_t *pcp, pcp_clk_class_t k)
{
    ninlil_pcp_fence_code_t code = NINLIL_PCP_FC_CLOCK_UNKNOWN;
    if (k == PCP_CLK_FAULT_PERM) {
        code = NINLIL_PCP_FC_CLOCK_PERM;
    } else if (k == PCP_CLK_FAULT_ILLFORMED) {
        code = NINLIL_PCP_FC_CLOCK_ILLFORMED;
    } else if (k == PCP_CLK_FAULT_REGRESSION) {
        code = NINLIL_PCP_FC_CLOCK_REGRESSION;
    } else if (k == PCP_CLK_FAULT_UNKNOWN) {
        code = NINLIL_PCP_FC_CLOCK_UNKNOWN;
    }
    pcp_set_fence_clock(pcp, code);
}

static int pcp_valid_time(const ninlil_time_sample_t *s, const pcp_issued_t *iss)
{
    return s->trust == NINLIL_CLOCK_TRUSTED
        && pcp_id_equal(s->clock_epoch_id.bytes, iss->clock_epoch_id, 16u)
        && iss->not_before_ms <= s->now_ms
        && s->now_ms < iss->expiry_ms;
}

static int pcp_expired_time(const ninlil_time_sample_t *s, const pcp_issued_t *iss)
{
    return s->trust == NINLIL_CLOCK_TRUSTED
        && pcp_id_equal(s->clock_epoch_id.bytes, iss->clock_epoch_id, 16u)
        && s->now_ms >= iss->expiry_ms;
}

/* ---- Storage mapping helpers ---- */

typedef struct pcp_map {
    ninlil_pcp_status_t status;
    ninlil_pcp_reason_t reason;
    int fence_storage;
    int fence_corrupt;
    int zero_mut;
} pcp_map_t;

static pcp_map_t pcp_map_open(ninlil_storage_status_t st)
{
    pcp_map_t m;
    (void)memset(&m, 0, sizeof(m));
    m.zero_mut = 1;
    switch (st) {
    case NINLIL_STORAGE_OK:
        m.status = NINLIL_PCP_OK;
        break;
    case NINLIL_STORAGE_NOT_FOUND:
        m.status = NINLIL_PCP_STORAGE_UNSUPPORTED;
        m.reason = NINLIL_PCP_REASON_STORAGE_UNSUPPORTED;
        break;
    case NINLIL_STORAGE_BUFFER_TOO_SMALL:
        m.status = NINLIL_PCP_CORRUPT_FENCE;
        m.reason = NINLIL_PCP_REASON_CORRUPT_FENCE;
        m.fence_corrupt = 1;
        break;
    case NINLIL_STORAGE_NO_SPACE:
        m.status = NINLIL_PCP_STORAGE_IO;
        m.reason = NINLIL_PCP_REASON_STORAGE_IO;
        break;
    case NINLIL_STORAGE_IO_ERROR:
        m.status = NINLIL_PCP_STORAGE_IO;
        m.reason = NINLIL_PCP_REASON_STORAGE_IO;
        m.fence_storage = 1;
        break;
    case NINLIL_STORAGE_CORRUPT:
        m.status = NINLIL_PCP_CORRUPT_FENCE;
        m.reason = NINLIL_PCP_REASON_CORRUPT_FENCE;
        m.fence_corrupt = 1;
        break;
    case NINLIL_STORAGE_COMMIT_UNKNOWN:
        m.status = NINLIL_PCP_COMMIT_UNKNOWN;
        m.reason = NINLIL_PCP_REASON_COMMIT_UNKNOWN;
        m.fence_storage = 1;
        break;
    case NINLIL_STORAGE_BUSY:
        m.status = NINLIL_PCP_BUSY;
        m.reason = NINLIL_PCP_REASON_STORAGE_IO;
        break;
    case NINLIL_STORAGE_UNSUPPORTED_SCHEMA:
        m.status = NINLIL_PCP_STORAGE_UNSUPPORTED;
        m.reason = NINLIL_PCP_REASON_STORAGE_UNSUPPORTED;
        break;
    default:
        m.status = NINLIL_PCP_CORRUPT_FENCE;
        m.reason = NINLIL_PCP_REASON_CORRUPT_FENCE;
        m.fence_corrupt = 1;
        break;
    }
    return m;
}

static pcp_map_t pcp_map_begin(ninlil_storage_status_t st)
{
    pcp_map_t m;
    (void)memset(&m, 0, sizeof(m));
    m.zero_mut = 1;
    switch (st) {
    case NINLIL_STORAGE_OK:
        m.status = NINLIL_PCP_OK;
        break;
    case NINLIL_STORAGE_NOT_FOUND:
    case NINLIL_STORAGE_BUFFER_TOO_SMALL:
    case NINLIL_STORAGE_CORRUPT:
    case NINLIL_STORAGE_UNSUPPORTED_SCHEMA:
        m.status = NINLIL_PCP_CORRUPT_FENCE;
        m.reason = NINLIL_PCP_REASON_CORRUPT_FENCE;
        m.fence_corrupt = 1;
        break;
    case NINLIL_STORAGE_NO_SPACE:
        m.status = NINLIL_PCP_STORAGE_IO;
        m.reason = NINLIL_PCP_REASON_STORAGE_IO;
        break;
    case NINLIL_STORAGE_IO_ERROR:
        m.status = NINLIL_PCP_STORAGE_IO;
        m.reason = NINLIL_PCP_REASON_STORAGE_IO;
        m.fence_storage = 1;
        break;
    case NINLIL_STORAGE_COMMIT_UNKNOWN:
        m.status = NINLIL_PCP_COMMIT_UNKNOWN;
        m.reason = NINLIL_PCP_REASON_COMMIT_UNKNOWN;
        m.fence_storage = 1;
        break;
    case NINLIL_STORAGE_BUSY:
        m.status = NINLIL_PCP_BUSY;
        m.reason = NINLIL_PCP_REASON_STORAGE_IO;
        break;
    default:
        m.status = NINLIL_PCP_CORRUPT_FENCE;
        m.reason = NINLIL_PCP_REASON_CORRUPT_FENCE;
        m.fence_corrupt = 1;
        break;
    }
    return m;
}

static pcp_map_t pcp_map_get(ninlil_storage_status_t st)
{
    return pcp_map_begin(st); /* same fence pattern for generic get failures */
}

static pcp_map_t pcp_map_put(ninlil_storage_status_t st)
{
    pcp_map_t m;
    (void)memset(&m, 0, sizeof(m));
    switch (st) {
    case NINLIL_STORAGE_OK:
        m.status = NINLIL_PCP_OK;
        break;
    case NINLIL_STORAGE_NO_SPACE:
        m.status = NINLIL_PCP_CAPACITY;
        m.reason = NINLIL_PCP_REASON_CAPACITY;
        m.zero_mut = 1;
        break;
    case NINLIL_STORAGE_IO_ERROR:
        m.status = NINLIL_PCP_STORAGE_IO;
        m.reason = NINLIL_PCP_REASON_STORAGE_IO;
        m.fence_storage = 1;
        m.zero_mut = 1;
        break;
    case NINLIL_STORAGE_COMMIT_UNKNOWN:
        m.status = NINLIL_PCP_COMMIT_UNKNOWN;
        m.reason = NINLIL_PCP_REASON_COMMIT_UNKNOWN;
        m.fence_storage = 1;
        break;
    case NINLIL_STORAGE_BUSY:
        m.status = NINLIL_PCP_BUSY;
        m.reason = NINLIL_PCP_REASON_STORAGE_IO;
        m.zero_mut = 1;
        break;
    case NINLIL_STORAGE_NOT_FOUND:
    case NINLIL_STORAGE_BUFFER_TOO_SMALL:
    case NINLIL_STORAGE_CORRUPT:
    case NINLIL_STORAGE_UNSUPPORTED_SCHEMA:
    default:
        m.status = NINLIL_PCP_CORRUPT_FENCE;
        m.reason = NINLIL_PCP_REASON_CORRUPT_FENCE;
        m.fence_corrupt = 1;
        m.zero_mut = 1;
        break;
    }
    return m;
}

static pcp_map_t pcp_map_commit(ninlil_storage_status_t st)
{
    pcp_map_t m;
    (void)memset(&m, 0, sizeof(m));
    switch (st) {
    case NINLIL_STORAGE_OK:
        m.status = NINLIL_PCP_OK;
        break;
    case NINLIL_STORAGE_COMMIT_UNKNOWN:
        m.status = NINLIL_PCP_COMMIT_UNKNOWN;
        m.reason = NINLIL_PCP_REASON_COMMIT_UNKNOWN;
        m.fence_storage = 1;
        break;
    case NINLIL_STORAGE_BUSY:
        /* BUSY on commit → F_s (ambiguous) */
        m.status = NINLIL_PCP_COMMIT_UNKNOWN;
        m.reason = NINLIL_PCP_REASON_COMMIT_UNKNOWN;
        m.fence_storage = 1;
        break;
    case NINLIL_STORAGE_NO_SPACE:
        m.status = NINLIL_PCP_STORAGE_IO;
        m.reason = NINLIL_PCP_REASON_STORAGE_IO;
        m.zero_mut = 1;
        break;
    case NINLIL_STORAGE_IO_ERROR:
        m.status = NINLIL_PCP_STORAGE_IO;
        m.reason = NINLIL_PCP_REASON_STORAGE_IO;
        m.fence_storage = 1;
        m.zero_mut = 1;
        break;
    case NINLIL_STORAGE_NOT_FOUND:
    case NINLIL_STORAGE_BUFFER_TOO_SMALL:
    case NINLIL_STORAGE_CORRUPT:
    case NINLIL_STORAGE_UNSUPPORTED_SCHEMA:
    default:
        m.status = NINLIL_PCP_CORRUPT_FENCE;
        m.reason = NINLIL_PCP_REASON_CORRUPT_FENCE;
        m.fence_corrupt = 1;
        m.zero_mut = 1;
        break;
    }
    return m;
}

static pcp_map_t pcp_map_erase(ninlil_storage_status_t st)
{
    pcp_map_t m;
    (void)memset(&m, 0, sizeof(m));
    switch (st) {
    case NINLIL_STORAGE_OK:
    case NINLIL_STORAGE_NOT_FOUND: /* idempotent GC */
        m.status = NINLIL_PCP_OK;
        break;
    case NINLIL_STORAGE_NO_SPACE:
        m.status = NINLIL_PCP_STORAGE_IO;
        m.reason = NINLIL_PCP_REASON_STORAGE_IO;
        break;
    case NINLIL_STORAGE_IO_ERROR:
        m.status = NINLIL_PCP_STORAGE_IO;
        m.reason = NINLIL_PCP_REASON_STORAGE_IO;
        m.fence_storage = 1;
        break;
    case NINLIL_STORAGE_COMMIT_UNKNOWN:
        m.status = NINLIL_PCP_COMMIT_UNKNOWN;
        m.reason = NINLIL_PCP_REASON_COMMIT_UNKNOWN;
        m.fence_storage = 1;
        break;
    case NINLIL_STORAGE_BUSY:
        m.status = NINLIL_PCP_BUSY;
        m.reason = NINLIL_PCP_REASON_STORAGE_IO;
        break;
    default:
        m.status = NINLIL_PCP_CORRUPT_FENCE;
        m.reason = NINLIL_PCP_REASON_CORRUPT_FENCE;
        m.fence_corrupt = 1;
        break;
    }
    return m;
}

static pcp_map_t pcp_map_iter_open(ninlil_storage_status_t st)
{
    return pcp_map_begin(st);
}

static pcp_map_t pcp_map_iter_next(ninlil_storage_status_t st)
{
    pcp_map_t m;
    (void)memset(&m, 0, sizeof(m));
    switch (st) {
    case NINLIL_STORAGE_OK:
        m.status = NINLIL_PCP_OK;
        break;
    case NINLIL_STORAGE_NOT_FOUND:
        m.status = NINLIL_PCP_EMPTY_OK; /* end-of-iteration sentinel */
        break;
    case NINLIL_STORAGE_NO_SPACE:
        m.status = NINLIL_PCP_CORRUPT_FENCE;
        m.reason = NINLIL_PCP_REASON_CORRUPT_FENCE;
        m.fence_corrupt = 1;
        break;
    case NINLIL_STORAGE_IO_ERROR:
        m.status = NINLIL_PCP_STORAGE_IO;
        m.reason = NINLIL_PCP_REASON_STORAGE_IO;
        m.fence_storage = 1;
        break;
    case NINLIL_STORAGE_COMMIT_UNKNOWN:
        m.status = NINLIL_PCP_COMMIT_UNKNOWN;
        m.reason = NINLIL_PCP_REASON_COMMIT_UNKNOWN;
        m.fence_storage = 1;
        break;
    case NINLIL_STORAGE_BUSY:
        m.status = NINLIL_PCP_BUSY;
        m.reason = NINLIL_PCP_REASON_STORAGE_IO;
        break;
    default:
        m.status = NINLIL_PCP_CORRUPT_FENCE;
        m.reason = NINLIL_PCP_REASON_CORRUPT_FENCE;
        m.fence_corrupt = 1;
        break;
    }
    return m;
}

static void pcp_apply_map_fence(ninlil_pcp_t *pcp, const pcp_map_t *m)
{
    if (m->fence_corrupt != 0) {
        pcp_set_fence_corrupt(pcp);
    } else if (m->fence_storage != 0) {
        pcp_set_fence_storage(pcp);
    }
}

/* ---- Storage open / handle ownership ---- */

static ninlil_pcp_status_t pcp_ensure_open(
    ninlil_pcp_t *pcp,
    ninlil_pcp_stage_t stage,
    ninlil_pcp_error_t *out_error,
    int out_safe)
{
    ninlil_bytes_view_t ns;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_status_t st;
    pcp_map_t m;

    if (pcp->storage_bound == 0u) {
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_UNBOUND_STORAGE, stage,
            NINLIL_PCP_REASON_UNBOUND_STORAGE, "unbound_storage");
        return NINLIL_PCP_UNBOUND_STORAGE;
    }
    if (pcp->storage_handle_live != 0u) {
        return NINLIL_PCP_OK;
    }

    ns.data = k_pcp_namespace;
    ns.length = (uint32_t)NINLIL_PCP_NAMESPACE_BYTES;
    st = pcp->storage_ops.open(
        pcp->storage_ops.user, ns, (uint32_t)NINLIL_PCP_SCHEMA_VERSION, &handle);
    m = pcp_map_open(st);
    if (st == NINLIL_STORAGE_OK) {
        if (handle == NULL) {
            /* OPEN_OK_NULL_REJECT */
            pcp_set_fence_corrupt(pcp);
            pcp_set_error(
                pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE, stage,
                NINLIL_PCP_REASON_CORRUPT_FENCE, "open_ok_null");
            return NINLIL_PCP_CORRUPT_FENCE;
        }
        pcp->storage_handle = handle;
        pcp->storage_handle_live = 1u;
        return NINLIL_PCP_OK;
    }
    /* non-OK with handle → close exactly once */
    if (handle != NULL) {
        pcp->storage_ops.close(pcp->storage_ops.user, handle);
    }
    pcp_apply_map_fence(pcp, &m);
    pcp_set_error(
        pcp, out_error, out_safe, m.status, stage, m.reason, "open_fail");
    return m.status;
}

static void pcp_close_handle(ninlil_pcp_t *pcp)
{
    if (pcp == NULL || pcp->storage_handle_live == 0u) {
        return;
    }
    pcp->storage_ops.close(pcp->storage_ops.user, pcp->storage_handle);
    pcp->storage_handle = NULL;
    pcp->storage_handle_live = 0u;
}

/* ---- Txn helpers ---- */

static ninlil_pcp_status_t pcp_begin(
    ninlil_pcp_t *pcp,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn,
    ninlil_pcp_stage_t stage,
    ninlil_pcp_error_t *out_error,
    int out_safe)
{
    ninlil_storage_status_t st;
    ninlil_storage_txn_t txn = NULL;
    pcp_map_t m;

    *out_txn = NULL;
    st = pcp->storage_ops.begin(
        pcp->storage_ops.user, pcp->storage_handle, mode, &txn);
    m = pcp_map_begin(st);
    if (st == NINLIL_STORAGE_OK) {
        if (txn == NULL) {
            pcp_set_fence_corrupt(pcp);
            pcp_set_error(
                pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE, stage,
                NINLIL_PCP_REASON_CORRUPT_FENCE, "begin_ok_null");
            return NINLIL_PCP_CORRUPT_FENCE;
        }
        *out_txn = txn;
        return NINLIL_PCP_OK;
    }
    if (txn != NULL) {
        (void)pcp->storage_ops.rollback(pcp->storage_ops.user, txn);
    }
    pcp_apply_map_fence(pcp, &m);
    pcp_set_error(
        pcp, out_error, out_safe, m.status, stage, m.reason, "begin_fail");
    return m.status;
}

static ninlil_pcp_status_t pcp_rollback_map(
    ninlil_pcp_t *pcp,
    ninlil_storage_txn_t txn,
    ninlil_pcp_stage_t stage,
    ninlil_pcp_error_t *out_error,
    int out_safe)
{
    ninlil_storage_status_t st;
    pcp_map_t m;

    st = pcp->storage_ops.rollback(pcp->storage_ops.user, txn);
    if (st == NINLIL_STORAGE_OK) {
        return NINLIL_PCP_OK;
    }
    (void)memset(&m, 0, sizeof(m));
    switch (st) {
    case NINLIL_STORAGE_NOT_FOUND:
    case NINLIL_STORAGE_NO_SPACE:
    case NINLIL_STORAGE_IO_ERROR:
    case NINLIL_STORAGE_BUSY:
        m.status = NINLIL_PCP_STORAGE_IO;
        m.reason = NINLIL_PCP_REASON_STORAGE_IO;
        m.fence_storage = 1;
        break;
    case NINLIL_STORAGE_COMMIT_UNKNOWN:
        m.status = NINLIL_PCP_COMMIT_UNKNOWN;
        m.reason = NINLIL_PCP_REASON_COMMIT_UNKNOWN;
        m.fence_storage = 1;
        break;
    default:
        m.status = NINLIL_PCP_CORRUPT_FENCE;
        m.reason = NINLIL_PCP_REASON_CORRUPT_FENCE;
        m.fence_corrupt = 1;
        break;
    }
    pcp_apply_map_fence(pcp, &m);
    pcp_set_error(
        pcp, out_error, out_safe, m.status, stage, m.reason, "rollback_fail");
    return m.status;
}

static ninlil_pcp_status_t pcp_commit_full(
    ninlil_pcp_t *pcp,
    ninlil_storage_txn_t txn,
    ninlil_pcp_stage_t stage,
    ninlil_pcp_error_t *out_error,
    int out_safe)
{
    ninlil_storage_status_t st;
    pcp_map_t m;

    st = pcp->storage_ops.commit(
        pcp->storage_ops.user, txn, NINLIL_DURABILITY_FULL);
    m = pcp_map_commit(st);
    if (st == NINLIL_STORAGE_OK) {
        return NINLIL_PCP_OK;
    }
    pcp_apply_map_fence(pcp, &m);
    pcp_set_error(
        pcp, out_error, out_safe, m.status, stage, m.reason, "commit_fail");
    return m.status;
}

/*
 * Best-effort durable STORAGE fence sticky (consume/issue UNKNOWN convergence).
 * Max one attempt; retains RAM F_s on secondary UNKNOWN/fail. No live txn left.
 */
static void pcp_sticky_storage_fence_best_effort(ninlil_pcp_t *pcp)
{
    ninlil_storage_txn_t tf = NULL;
    ninlil_storage_status_t st;
    pcp_meta_t meta;

    ninlil_pcp_status_t pst;

    if (pcp == NULL || pcp->storage_bound == 0u) {
        return;
    }
    pcp->fence_bits |= NINLIL_PCP_FENCE_BIT_STORAGE;
    if ((pcp->fence_bits & NINLIL_PCP_FENCE_BIT_CORRUPT) == 0u) {
        pcp->fence_code = NINLIL_PCP_FC_STORAGE;
    }
    pcp_clear_ram_validate(pcp);

    if (pcp->storage_handle_live == 0u) {
        return;
    }
    /* every RW begin: full I1–I14 (best-effort sticky; fail keeps RAM F_s) */
    pst = pcp_begin(
        pcp, NINLIL_STORAGE_READ_WRITE, &tf, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
    if (pst != NINLIL_PCP_OK || tf == NULL) {
        return;
    }
    {
        pcp_scan_t scan_s;

        pst = pcp_rw_scan_check(
            pcp, tf, &scan_s, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
        if (pst != NINLIL_PCP_OK) {
            (void)pcp_rollback_map(
                pcp, tf, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
            return;
        }
        meta = scan_s.meta;
    }
    meta.fence_bits =
        (uint8_t)(meta.fence_bits | (uint8_t)NINLIL_PCP_FENCE_BIT_STORAGE);
    if ((meta.fence_bits & (uint8_t)NINLIL_PCP_FENCE_BIT_CORRUPT) == 0u) {
        meta.fence_code = NINLIL_PCP_FC_STORAGE;
    }
    pst = pcp_txn_put_meta(
        pcp, tf, &meta, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
    if (pst != NINLIL_PCP_OK) {
        (void)pcp_rollback_map(
            pcp, tf, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
        return;
    }
    st = pcp->storage_ops.commit(
        pcp->storage_ops.user, tf, NINLIL_DURABILITY_FULL);
    if (st != NINLIL_STORAGE_OK) {
        /* secondary UNKNOWN/fail: retain RAM F_s only; no infinite loop */
        return;
    }
}

/*
 * Consume post-put-intent failure classification (docs/24 §7.5 / §7.11 / §10.10):
 *   COMMIT_UNKNOWN → CONSUME_FENCED + F_s (never DENIED / OK / ERROR)
 *   BUSY on put → CONSUME_DENIED (retryable; pre-commit)
 *   other → CONSUME_ERROR + fence as mapped
 * txn: if still live, rollback for definite non-commit failures; COMMIT_UNKNOWN
 * after commit has already consumed the txn (caller passes txn_live=0).
 */
static ninlil_radio_hal_status_t pcp_consume_fail_after_put_intent(
    ninlil_pcp_t *pcp,
    ninlil_storage_txn_t txn,
    int txn_live,
    ninlil_pcp_status_t st,
    ninlil_radio_hal_error_t *out_error,
    int out_safe)
{
    if (txn_live != 0 && txn != NULL) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
    }

    if (st == NINLIL_PCP_COMMIT_UNKNOWN) {
        /* Ensure F_s (map may already have set it on put/commit). */
        if ((pcp->fence_bits & NINLIL_PCP_FENCE_BIT_STORAGE) == 0u) {
            pcp_set_fence_storage(pcp);
        } else if ((pcp->fence_bits & NINLIL_PCP_FENCE_BIT_CORRUPT) == 0u) {
            pcp->fence_code = NINLIL_PCP_FC_STORAGE;
        }
        pcp_sticky_storage_fence_best_effort(pcp);
        pcp_sat_inc(&pcp->stats.consume_fenced);
        pcp_clear_ram_validate(pcp);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_FENCED,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_CONSUME_FENCED, "pcp_commit_unknown");
        return NINLIL_RADIO_HAL_CONSUME_FENCED;
    }
    if (st == NINLIL_PCP_BUSY) {
        pcp_sat_inc(&pcp->stats.consume_denied);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_DENIED,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_CONSUME_UNCONSUMED, "pcp_retry");
        return NINLIL_RADIO_HAL_CONSUME_DENIED;
    }
    pcp_sat_inc(&pcp->stats.consume_error);
    pcp_clear_ram_validate(pcp);
    pcp->in_api = 0u;
    pcp_set_hal_error(
        out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_ERROR,
        NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
        NINLIL_RADIO_HAL_REASON_CONSUME_ERROR, "pcp_storage");
    return NINLIL_RADIO_HAL_CONSUME_ERROR;
}

static ninlil_pcp_status_t pcp_get_value(
    ninlil_pcp_t *pcp,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    uint8_t *buf,
    uint32_t expect_len,
    uint32_t *out_len,
    int *out_not_found,
    ninlil_pcp_stage_t stage,
    ninlil_pcp_error_t *out_error,
    int out_safe)
{
    ninlil_mut_bytes_t mb;
    ninlil_storage_status_t st;
    pcp_map_t m;

    *out_not_found = 0;
    *out_len = 0u;
    mb.data = buf;
    mb.capacity = expect_len;
    mb.length = 0u;
    st = pcp->storage_ops.get(pcp->storage_ops.user, txn, key, &mb);
    if (st == NINLIL_STORAGE_NOT_FOUND) {
        *out_not_found = 1;
        return NINLIL_PCP_OK;
    }
    if (st == NINLIL_STORAGE_OK) {
        if (mb.length != expect_len) {
            pcp_set_fence_corrupt(pcp);
            pcp_set_error(
                pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE, stage,
                NINLIL_PCP_REASON_CORRUPT_FENCE, "get_len");
            return NINLIL_PCP_CORRUPT_FENCE;
        }
        *out_len = mb.length;
        return NINLIL_PCP_OK;
    }
    m = pcp_map_get(st);
    pcp_apply_map_fence(pcp, &m);
    pcp_set_error(
        pcp, out_error, out_safe, m.status, stage, m.reason, "get_fail");
    return m.status;
}

static ninlil_pcp_status_t pcp_put_value(
    ninlil_pcp_t *pcp,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    const uint8_t *val,
    uint32_t val_len,
    ninlil_pcp_stage_t stage,
    ninlil_pcp_error_t *out_error,
    int out_safe)
{
    ninlil_bytes_view_t vv;
    ninlil_storage_status_t st;
    pcp_map_t m;

    vv.data = val;
    vv.length = val_len;
    st = pcp->storage_ops.put(pcp->storage_ops.user, txn, key, vv);
    m = pcp_map_put(st);
    if (st == NINLIL_STORAGE_OK) {
        return NINLIL_PCP_OK;
    }
    pcp_apply_map_fence(pcp, &m);
    pcp_set_error(
        pcp, out_error, out_safe, m.status, stage, m.reason, "put_fail");
    return m.status;
}

/* ---- Full namespace scan (CANONICAL_SCAN_MODE_A) ---- */

static ninlil_pcp_status_t pcp_scan_namespace(
    ninlil_pcp_t *pcp,
    ninlil_storage_txn_t txn,
    pcp_scan_t *scan,
    ninlil_pcp_stage_t stage,
    ninlil_pcp_error_t *out_error,
    int out_safe)
{
    ninlil_storage_iter_t iter = NULL;
    ninlil_bytes_view_t empty_prefix;
    ninlil_storage_status_t st;
    pcp_map_t m;
    uint8_t key_buf[32];
    uint8_t val_buf[NINLIL_PCP_ISSUED_VALUE_BYTES];
    ninlil_mut_bytes_t mk;
    ninlil_mut_bytes_t mv;

    (void)memset(scan, 0, sizeof(*scan));
    empty_prefix.data = NULL;
    empty_prefix.length = 0u;

    st = pcp->storage_ops.iter_open(
        pcp->storage_ops.user, txn, empty_prefix, &iter);
    m = pcp_map_iter_open(st);
    if (st != NINLIL_STORAGE_OK) {
        if (iter != NULL) {
            pcp->storage_ops.iter_close(pcp->storage_ops.user, iter);
        }
        pcp_apply_map_fence(pcp, &m);
        pcp_set_error(
            pcp, out_error, out_safe, m.status, stage, m.reason, "iter_open");
        return m.status;
    }
    if (iter == NULL) {
        pcp_set_fence_corrupt(pcp);
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE, stage,
            NINLIL_PCP_REASON_CORRUPT_FENCE, "iter_ok_null");
        return NINLIL_PCP_CORRUPT_FENCE;
    }

    for (;;) {
        mk.data = key_buf;
        mk.capacity = (uint32_t)sizeof(key_buf);
        mk.length = 0u;
        mv.data = val_buf;
        mv.capacity = (uint32_t)sizeof(val_buf);
        mv.length = 0u;
        st = pcp->storage_ops.iter_next(
            pcp->storage_ops.user, iter, &mk, &mv);
        m = pcp_map_iter_next(st);
        if (st == NINLIL_STORAGE_NOT_FOUND) {
            break;
        }
        if (st != NINLIL_STORAGE_OK) {
            pcp->storage_ops.iter_close(pcp->storage_ops.user, iter);
            pcp_apply_map_fence(pcp, &m);
            pcp_set_error(
                pcp, out_error, out_safe, m.status, stage, m.reason,
                "iter_next");
            return m.status;
        }

        /* KEY_META */
        if (mk.length == (uint32_t)NINLIL_PCP_META_KEY_BYTES
            && memcmp(mk.data, k_meta_key, NINLIL_PCP_META_KEY_BYTES) == 0) {
            if (scan->meta_present != 0) {
                scan->corrupt = 1;
                pcp->storage_ops.iter_close(pcp->storage_ops.user, iter);
                pcp_set_fence_corrupt(pcp);
                pcp_set_error(
                    pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE, stage,
                    NINLIL_PCP_REASON_CONTRACT, "dup_meta");
                return NINLIL_PCP_CORRUPT_FENCE;
            }
            if (mv.length != (uint32_t)NINLIL_PCP_META_VALUE_BYTES
                || !pcp_decode_meta(mv.data, &scan->meta)) {
                scan->corrupt = 1;
                pcp->storage_ops.iter_close(pcp->storage_ops.user, iter);
                pcp_set_fence_corrupt(pcp);
                pcp_set_error(
                    pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE, stage,
                    NINLIL_PCP_REASON_CORRUPT_FENCE, "meta_crc");
                return NINLIL_PCP_CORRUPT_FENCE;
            }
            scan->meta_present = 1;
            continue;
        }

        /* KEY_ISS */
        {
            uint64_t seq = 0u;
            pcp_issued_t body;
            size_t i;

            if (pcp_iss_key_parse(mk.data, mk.length, &seq)) {
                if (mv.length != (uint32_t)NINLIL_PCP_ISSUED_VALUE_BYTES
                    || !pcp_decode_issued(mv.data, &body)) {
                    pcp->storage_ops.iter_close(pcp->storage_ops.user, iter);
                    pcp_set_fence_corrupt(pcp);
                    pcp_set_error(
                        pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE,
                        stage, NINLIL_PCP_REASON_CORRUPT_FENCE, "iss_crc");
                    return NINLIL_PCP_CORRUPT_FENCE;
                }
                /* I7: key charset enforced by pcp_iss_key_parse (lowercase hex).
                 * I9 / I12 / key_seq==body.seq (I6 key half): */
                if (body.permit_sequence != seq
                    || body.issue_generation != body.permit_sequence
                    || body.permit_sequence == 0u
                    || body.permit_sequence == UINT64_MAX) {
                    pcp->storage_ops.iter_close(pcp->storage_ops.user, iter);
                    pcp_set_fence_corrupt(pcp);
                    pcp_set_error(
                        pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE,
                        stage, NINLIL_PCP_REASON_CONTRACT, "iss_seq");
                    return NINLIL_PCP_CORRUPT_FENCE;
                }
                /* Body structural semantics (no meta required yet). */
                if (body.state != PCP_ISS_STATE_ISSUED
                    && body.state != PCP_ISS_STATE_CONSUMED
                    && body.state != PCP_ISS_STATE_REVOKED) {
                    pcp->storage_ops.iter_close(pcp->storage_ops.user, iter);
                    pcp_set_fence_corrupt(pcp);
                    pcp_set_error(
                        pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE,
                        stage, NINLIL_PCP_REASON_CONTRACT, "iss_state");
                    return NINLIL_PCP_CORRUPT_FENCE;
                }
                if (body.expiry_ms <= body.not_before_ms) {
                    pcp->storage_ops.iter_close(pcp->storage_ops.user, iter);
                    pcp_set_fence_corrupt(pcp);
                    pcp_set_error(
                        pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE,
                        stage, NINLIL_PCP_REASON_CONTRACT, "iss_deadline");
                    return NINLIL_PCP_CORRUPT_FENCE;
                }
                if (body.state == PCP_ISS_STATE_ISSUED
                    && body.max_airtime_us == 0u) {
                    pcp->storage_ops.iter_close(pcp->storage_ops.user, iter);
                    pcp_set_fence_corrupt(pcp);
                    pcp_set_error(
                        pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE,
                        stage, NINLIL_PCP_REASON_CONTRACT, "iss_airtime0");
                    return NINLIL_PCP_CORRUPT_FENCE;
                }
                /* If meta already seen, apply I6/I11 immediately on this body. */
                if (scan->meta_present != 0) {
                    if (!pcp_id_equal(
                            body.authority_instance_id,
                            scan->meta.authority_instance_id,
                            NINLIL_PCP_ID_BYTES)) {
                        pcp->storage_ops.iter_close(
                            pcp->storage_ops.user, iter);
                        pcp_set_fence_corrupt(pcp);
                        pcp_set_error(
                            pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE,
                            stage, NINLIL_PCP_REASON_INSTANCE_MISMATCH,
                            "iss_instance");
                        return NINLIL_PCP_CORRUPT_FENCE;
                    }
                    if (body.state == PCP_ISS_STATE_ISSUED) {
                        if (!pcp_lcore_equal_iss_meta(&body, &scan->meta)
                            || body.max_airtime_us
                                > scan->meta.bound_max_airtime_ceiling_us) {
                            pcp->storage_ops.iter_close(
                                pcp->storage_ops.user, iter);
                            pcp_set_fence_corrupt(pcp);
                            pcp_set_error(
                                pcp, out_error, out_safe,
                                NINLIL_PCP_CORRUPT_FENCE, stage,
                                NINLIL_PCP_REASON_CONTRACT, "iss_i11");
                            return NINLIL_PCP_CORRUPT_FENCE;
                        }
                    }
                }
                for (i = 0u; i < scan->iss_count; ++i) {
                    if (scan->iss[i].seq == seq) {
                        pcp->storage_ops.iter_close(
                            pcp->storage_ops.user, iter);
                        pcp_set_fence_corrupt(pcp);
                        pcp_set_error(
                            pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE,
                            stage, NINLIL_PCP_REASON_CONTRACT, "dup_seq");
                        return NINLIL_PCP_CORRUPT_FENCE;
                    }
                }
                if (scan->iss_count >= PCP_SCAN_MAX_ISS) {
                    pcp->storage_ops.iter_close(pcp->storage_ops.user, iter);
                    pcp_set_fence_corrupt(pcp);
                    pcp_set_error(
                        pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE,
                        stage, NINLIL_PCP_REASON_CAPACITY, "scan_cap");
                    return NINLIL_PCP_CORRUPT_FENCE;
                }
                scan->iss[scan->iss_count].seq = seq;
                scan->iss[scan->iss_count].state = body.state;
                scan->iss[scan->iss_count].valid = 1u;
                scan->iss_count += 1u;
                if (body.state == PCP_ISS_STATE_ISSUED) {
                    scan->issued_count += 1u;
                }
                continue;
            }
        }

        /* KEY_FOREIGN */
        scan->foreign = 1;
        pcp->storage_ops.iter_close(pcp->storage_ops.user, iter);
        pcp_set_fence_corrupt(pcp);
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE, stage,
            NINLIL_PCP_REASON_FOREIGN_KEY, "foreign_key");
        return NINLIL_PCP_CORRUPT_FENCE;
    }

    pcp->storage_ops.iter_close(pcp->storage_ops.user, iter);
    return NINLIL_PCP_OK;
}

/* ---- I1–I14 verification on scan ---- */

static int pcp_scan_has_seq(const pcp_scan_t *scan, uint64_t seq, uint8_t *out_state)
{
    size_t i;
    for (i = 0u; i < scan->iss_count; ++i) {
        if (scan->iss[i].seq == seq) {
            if (out_state != NULL) {
                *out_state = scan->iss[i].state;
            }
            return 1;
        }
    }
    return 0;
}

static int pcp_verify_invariants(const pcp_scan_t *scan)
{
    const pcp_meta_t *m;
    size_t i;
    uint64_t max_seq = 0u;
    int any_iss = 0;
    uint32_t issued = 0u;

    if (scan == NULL || scan->foreign != 0 || scan->corrupt != 0) {
        return 0;
    }
    if (scan->meta_present == 0) {
        return scan->iss_count == 0u; /* empty only */
    }
    m = &scan->meta;

    /* I1 */
    for (i = 0u; i < scan->iss_count; ++i) {
        if (scan->iss[i].state == PCP_ISS_STATE_ISSUED) {
            issued += 1u;
        }
        any_iss = 1;
        if (scan->iss[i].seq > max_seq) {
            max_seq = scan->iss[i].seq;
        }
    }
    if (m->outstanding_count != issued) {
        return 0;
    }

    /* I2 */
    if (m->outstanding_count > 0u) {
        uint64_t lo = m->last_consumed_seq + 1u;
        uint64_t hi;
        uint64_t s;
        if (m->next_issue_seq == 0u || m->next_issue_seq <= lo) {
            return 0;
        }
        hi = m->next_issue_seq - 1u;
        if ((hi - lo + 1u) != (uint64_t)m->outstanding_count) {
            return 0;
        }
        for (s = lo; s <= hi; ++s) {
            uint8_t st = 0u;
            if (!pcp_scan_has_seq(scan, s, &st) || st != PCP_ISS_STATE_ISSUED) {
                return 0;
            }
        }
        /* no extra ISSUED outside range */
        for (i = 0u; i < scan->iss_count; ++i) {
            if (scan->iss[i].state == PCP_ISS_STATE_ISSUED) {
                if (scan->iss[i].seq < lo || scan->iss[i].seq > hi) {
                    return 0;
                }
            }
        }
    } else {
        for (i = 0u; i < scan->iss_count; ++i) {
            if (scan->iss[i].state == PCP_ISS_STATE_ISSUED) {
                return 0;
            }
        }
    }

    /* I3 */
    for (i = 0u; i < scan->iss_count; ++i) {
        if (scan->iss[i].state == PCP_ISS_STATE_ISSUED
            && scan->iss[i].seq <= m->last_consumed_seq) {
            return 0;
        }
    }

    /* I4 */
    for (i = 0u; i < scan->iss_count; ++i) {
        if ((scan->iss[i].state == PCP_ISS_STATE_CONSUMED
                || scan->iss[i].state == PCP_ISS_STATE_REVOKED)
            && scan->iss[i].seq > m->last_consumed_seq) {
            return 0;
        }
    }

    /* I5 */
    if (m->next_issue_seq == 0u) {
        return 0;
    }
    if (any_iss != 0) {
        if (m->next_issue_seq != max_seq + 1u) {
            return 0;
        }
    } else {
        if (m->next_issue_seq != m->last_consumed_seq + 1u) {
            return 0;
        }
    }

    /* I6 meta half: instance id must be nonzero (body match in body-verify). */
    if (pcp_id_is_zero(m->authority_instance_id, 16u)) {
        return 0;
    }

    /* I8: distinct seq — ensured by scan insert; I9/I12 on decode path. */

    /* I10: meta present here (caller path); meta-absent+iss handled by recover. */

    /* I13: for every present key with 1<=s<=last_consumed: terminal only
     * (sparse absence allowed; no ISSUED at s). */
    for (i = 0u; i < scan->iss_count; ++i) {
        uint64_t s = scan->iss[i].seq;
        if (s >= 1u && s <= m->last_consumed_seq) {
            if (scan->iss[i].state == PCP_ISS_STATE_ISSUED) {
                return 0;
            }
        }
    }

    /* I14 */
    if (m->outstanding_count == 0u) {
        if (m->next_issue_seq != m->last_consumed_seq + 1u) {
            return 0;
        }
    }

    return 1;
}

/*
 * Full body re-get for every scanned iss key (I6 instance, I11 L_core/airtime
 * for ISSUED, deadline/state/generation re-check).
 *
 * Scratch: pcp->iss_scratch holds one decoded 232B value at a time; live only
 * for this function's loop iteration. Caller must not interleave put_iss.
 * Index cap: scan->iss_count <= PCP_SCAN_MAX_ISS.
 */
static ninlil_pcp_status_t pcp_verify_iss_bodies(
    ninlil_pcp_t *pcp,
    ninlil_storage_txn_t txn,
    const pcp_scan_t *scan,
    ninlil_pcp_stage_t stage,
    ninlil_pcp_error_t *out_error,
    int out_safe)
{
    size_t i;

    if (pcp == NULL || scan == NULL) {
        return NINLIL_PCP_CORRUPT_FENCE;
    }
    if (scan->meta_present == 0) {
        /* EMPTY or meta-absent paths: no body/meta binding to check. */
        return NINLIL_PCP_OK;
    }
    if (pcp_id_is_zero(scan->meta.authority_instance_id, NINLIL_PCP_ID_BYTES)) {
        pcp_set_fence_corrupt(pcp);
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE, stage,
            NINLIL_PCP_REASON_CORRUPT_FENCE, "meta_instance0");
        return NINLIL_PCP_CORRUPT_FENCE;
    }

    for (i = 0u; i < scan->iss_count; ++i) {
        pcp_issued_t body;
        int absent = 0;
        ninlil_pcp_status_t st;

        st = pcp_txn_get_iss(
            pcp, txn, scan->iss[i].seq, &body, &absent, stage, out_error,
            out_safe);
        if (st != NINLIL_PCP_OK) {
            return st;
        }
        if (absent != 0) {
            pcp_set_fence_corrupt(pcp);
            pcp_set_error(
                pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE, stage,
                NINLIL_PCP_REASON_CORRUPT_FENCE, "iss_missing");
            return NINLIL_PCP_CORRUPT_FENCE;
        }
        /* Key identity: body.permit_sequence must match index seq (I6). */
        if (body.permit_sequence != scan->iss[i].seq
            || body.state != scan->iss[i].state) {
            pcp_set_fence_corrupt(pcp);
            pcp_set_error(
                pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE, stage,
                NINLIL_PCP_REASON_CONTRACT, "iss_index");
            return NINLIL_PCP_CORRUPT_FENCE;
        }
        if (body.issue_generation != body.permit_sequence) {
            pcp_set_fence_corrupt(pcp);
            pcp_set_error(
                pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE, stage,
                NINLIL_PCP_REASON_CONTRACT, "iss_gen");
            return NINLIL_PCP_CORRUPT_FENCE;
        }
        if (body.state != PCP_ISS_STATE_ISSUED
            && body.state != PCP_ISS_STATE_CONSUMED
            && body.state != PCP_ISS_STATE_REVOKED) {
            pcp_set_fence_corrupt(pcp);
            pcp_set_error(
                pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE, stage,
                NINLIL_PCP_REASON_CONTRACT, "iss_state");
            return NINLIL_PCP_CORRUPT_FENCE;
        }
        if (body.expiry_ms <= body.not_before_ms) {
            pcp_set_fence_corrupt(pcp);
            pcp_set_error(
                pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE, stage,
                NINLIL_PCP_REASON_CONTRACT, "iss_deadline");
            return NINLIL_PCP_CORRUPT_FENCE;
        }
        /* I6: authority_instance_id exact-equal meta. */
        if (!pcp_id_equal(
                body.authority_instance_id,
                scan->meta.authority_instance_id,
                NINLIL_PCP_ID_BYTES)) {
            pcp_set_fence_corrupt(pcp);
            pcp_set_error(
                pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE, stage,
                NINLIL_PCP_REASON_INSTANCE_MISMATCH, "iss_instance");
            return NINLIL_PCP_CORRUPT_FENCE;
        }
        /* I11: every ISSUED — L_core exact + 0 < airtime <= ceiling. */
        if (body.state == PCP_ISS_STATE_ISSUED) {
            if (!pcp_lcore_equal_iss_meta(&body, &scan->meta)
                || body.max_airtime_us == 0u
                || body.max_airtime_us
                    > scan->meta.bound_max_airtime_ceiling_us) {
                pcp_set_fence_corrupt(pcp);
                pcp_set_error(
                    pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE, stage,
                    NINLIL_PCP_REASON_CONTRACT, "iss_i11");
                return NINLIL_PCP_CORRUPT_FENCE;
            }
        }
    }
    return NINLIL_PCP_OK;
}

static void pcp_load_meta_to_ram(ninlil_pcp_t *pcp, const pcp_meta_t *m)
{
    (void)memcpy(
        pcp->authority_instance_id, m->authority_instance_id, NINLIL_PCP_ID_BYTES);
    pcp->next_issue_seq_cache = m->next_issue_seq;
    pcp->last_consumed_seq_cache = m->last_consumed_seq;
    pcp->outstanding_count_cache = m->outstanding_count;
    pcp->fence_bits = m->fence_bits;
    pcp->fence_code = m->fence_code;

    pcp->bound_live.hardware_profile_id = m->bound_hardware_profile_id;
    pcp->bound_live.hardware_profile_rev = m->bound_hardware_profile_rev;
    pcp->bound_live.regulatory_profile_id = m->bound_regulatory_profile_id;
    pcp->bound_live.regulatory_profile_rev = m->bound_regulatory_profile_rev;
    pcp->bound_live.site_assignment_id = m->bound_site_assignment_id;
    pcp->bound_live.site_assignment_rev = m->bound_site_assignment_rev;
    pcp->bound_live.site_assignment_epoch = m->bound_site_assignment_epoch;
    pcp->bound_live.transmitter_id = m->bound_transmitter_id;
    pcp->bound_live.channel_id = m->bound_channel_id;
    pcp->bound_live.phy = m->bound_phy;
    pcp->bound_live.max_airtime_ceiling_us = m->bound_max_airtime_ceiling_us;
    pcp->bound_live.assignment_generation = m->assignment_generation;
    pcp->bound_live.bound = 1u;
    pcp->live_bound = 1u;

    pcp_set_ram_trust(pcp, m->last_trusted_epoch_id, m->last_trusted_now_ms);
    pcp->published = 1u;
}

/* ---- Get meta / issued by key inside txn ---- */

static ninlil_pcp_status_t pcp_txn_get_meta(
    ninlil_pcp_t *pcp,
    ninlil_storage_txn_t txn,
    pcp_meta_t *out,
    int *out_absent,
    ninlil_pcp_stage_t stage,
    ninlil_pcp_error_t *out_error,
    int out_safe)
{
    ninlil_bytes_view_t key;
    uint32_t len = 0u;
    int nf = 0;
    ninlil_pcp_status_t st;

    pcp_meta_key_view(&key);
    st = pcp_get_value(
        pcp, txn, key, pcp->meta_scratch,
        (uint32_t)NINLIL_PCP_META_VALUE_BYTES, &len, &nf, stage, out_error,
        out_safe);
    if (st != NINLIL_PCP_OK) {
        return st;
    }
    if (nf != 0) {
        *out_absent = 1;
        return NINLIL_PCP_OK;
    }
    *out_absent = 0;
    if (!pcp_decode_meta(pcp->meta_scratch, out)) {
        pcp_set_fence_corrupt(pcp);
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE, stage,
            NINLIL_PCP_REASON_CORRUPT_FENCE, "meta_crc");
        return NINLIL_PCP_CORRUPT_FENCE;
    }
    return NINLIL_PCP_OK;
}

static ninlil_pcp_status_t pcp_txn_get_iss(
    ninlil_pcp_t *pcp,
    ninlil_storage_txn_t txn,
    uint64_t seq,
    pcp_issued_t *out,
    int *out_absent,
    ninlil_pcp_stage_t stage,
    ninlil_pcp_error_t *out_error,
    int out_safe)
{
    ninlil_bytes_view_t key;
    uint32_t len = 0u;
    int nf = 0;
    ninlil_pcp_status_t st;

    (void)pcp_iss_key_build(pcp->key_scratch, seq);
    key.data = pcp->key_scratch;
    key.length = (uint32_t)NINLIL_PCP_ISS_KEY_BYTES;
    st = pcp_get_value(
        pcp, txn, key, pcp->iss_scratch,
        (uint32_t)NINLIL_PCP_ISSUED_VALUE_BYTES, &len, &nf, stage, out_error,
        out_safe);
    if (st != NINLIL_PCP_OK) {
        return st;
    }
    if (nf != 0) {
        *out_absent = 1;
        return NINLIL_PCP_OK;
    }
    *out_absent = 0;
    if (!pcp_decode_issued(pcp->iss_scratch, out)
        || out->permit_sequence != seq) {
        pcp_set_fence_corrupt(pcp);
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE, stage,
            NINLIL_PCP_REASON_CORRUPT_FENCE, "iss_crc");
        return NINLIL_PCP_CORRUPT_FENCE;
    }
    return NINLIL_PCP_OK;
}

static ninlil_pcp_status_t pcp_txn_put_meta(
    ninlil_pcp_t *pcp,
    ninlil_storage_txn_t txn,
    const pcp_meta_t *meta,
    ninlil_pcp_stage_t stage,
    ninlil_pcp_error_t *out_error,
    int out_safe)
{
    ninlil_bytes_view_t key;
    pcp_encode_meta(meta, pcp->meta_scratch);
    pcp_meta_key_view(&key);
    return pcp_put_value(
        pcp, txn, key, pcp->meta_scratch,
        (uint32_t)NINLIL_PCP_META_VALUE_BYTES, stage, out_error, out_safe);
}

static ninlil_pcp_status_t pcp_txn_put_iss(
    ninlil_pcp_t *pcp,
    ninlil_storage_txn_t txn,
    const pcp_issued_t *iss,
    ninlil_pcp_stage_t stage,
    ninlil_pcp_error_t *out_error,
    int out_safe)
{
    ninlil_bytes_view_t key;
    (void)pcp_iss_key_build(pcp->key_scratch, iss->permit_sequence);
    key.data = pcp->key_scratch;
    key.length = (uint32_t)NINLIL_PCP_ISS_KEY_BYTES;
    pcp_encode_issued(iss, pcp->iss_scratch);
    return pcp_put_value(
        pcp, txn, key, pcp->iss_scratch,
        (uint32_t)NINLIL_PCP_ISSUED_VALUE_BYTES, stage, out_error, out_safe);
}

/* ---- L_core compare ---- */

static int pcp_lcore_equal_meta_req(
    const pcp_meta_t *m,
    const ninlil_pcp_issue_request_t *req)
{
    return pcp_hal_id_equal(&m->bound_hardware_profile_id, &req->hardware_profile_id)
        && m->bound_hardware_profile_rev == req->hardware_profile_rev
        && pcp_hal_id_equal(
            &m->bound_regulatory_profile_id, &req->regulatory_profile_id)
        && m->bound_regulatory_profile_rev == req->regulatory_profile_rev
        && pcp_hal_id_equal(&m->bound_site_assignment_id, &req->site_assignment_id)
        && m->bound_site_assignment_rev == req->site_assignment_rev
        && m->bound_site_assignment_epoch == req->site_assignment_epoch
        && pcp_hal_id_equal(&m->bound_transmitter_id, &req->transmitter_id)
        && m->bound_channel_id == req->channel_id
        && pcp_phy_equal(&m->bound_phy, &req->phy);
}

static int pcp_lcore_equal_iss_meta(const pcp_issued_t *iss, const pcp_meta_t *m)
{
    return pcp_hal_id_equal(&iss->hardware_profile_id, &m->bound_hardware_profile_id)
        && iss->hardware_profile_rev == m->bound_hardware_profile_rev
        && pcp_hal_id_equal(
            &iss->regulatory_profile_id, &m->bound_regulatory_profile_id)
        && iss->regulatory_profile_rev == m->bound_regulatory_profile_rev
        && pcp_hal_id_equal(&iss->site_assignment_id, &m->bound_site_assignment_id)
        && iss->site_assignment_rev == m->bound_site_assignment_rev
        && iss->site_assignment_epoch == m->bound_site_assignment_epoch
        && pcp_hal_id_equal(&iss->transmitter_id, &m->bound_transmitter_id)
        && iss->channel_id == m->bound_channel_id
        && pcp_phy_equal(&iss->phy, &m->bound_phy);
}

static int pcp_snapshot_matches_iss(
    const ninlil_radio_hal_permit_snapshot_t *p,
    const pcp_issued_t *iss)
{
    return p->permit_sequence == iss->permit_sequence
        && pcp_hal_id_equal(&p->hardware_profile_id, &iss->hardware_profile_id)
        && p->hardware_profile_rev == iss->hardware_profile_rev
        && pcp_hal_id_equal(
            &p->regulatory_profile_id, &iss->regulatory_profile_id)
        && p->regulatory_profile_rev == iss->regulatory_profile_rev
        && pcp_hal_id_equal(&p->site_assignment_id, &iss->site_assignment_id)
        && p->site_assignment_rev == iss->site_assignment_rev
        && p->site_assignment_epoch == iss->site_assignment_epoch
        && pcp_hal_id_equal(&p->transmitter_id, &iss->transmitter_id)
        && p->channel_id == iss->channel_id
        && pcp_phy_equal(&p->phy, &iss->phy)
        && memcmp(p->frame_digest, iss->frame_digest, 32u) == 0
        && p->frame_digest_algorithm == iss->frame_digest_algorithm
        && p->frame_byte_length == iss->frame_byte_length
        && p->max_airtime_us == iss->max_airtime_us
        && p->not_before_ms == iss->not_before_ms
        && p->expiry_ms == iss->expiry_ms
        && p->reserved_zero == 0u;
}

static void pcp_fill_snapshot_from_iss(
    ninlil_radio_hal_permit_snapshot_t *out,
    const pcp_issued_t *iss)
{
    (void)memset(out, 0, sizeof(*out));
    out->hardware_profile_id = iss->hardware_profile_id;
    out->hardware_profile_rev = iss->hardware_profile_rev;
    out->regulatory_profile_id = iss->regulatory_profile_id;
    out->regulatory_profile_rev = iss->regulatory_profile_rev;
    out->site_assignment_id = iss->site_assignment_id;
    out->site_assignment_rev = iss->site_assignment_rev;
    out->site_assignment_epoch = iss->site_assignment_epoch;
    out->transmitter_id = iss->transmitter_id;
    out->channel_id = iss->channel_id;
    out->phy = iss->phy;
    (void)memcpy(out->frame_digest, iss->frame_digest, 32u);
    out->frame_digest_algorithm = iss->frame_digest_algorithm;
    out->frame_byte_length = iss->frame_byte_length;
    out->max_airtime_us = iss->max_airtime_us;
    out->not_before_ms = iss->not_before_ms;
    out->expiry_ms = iss->expiry_ms;
    out->permit_sequence = iss->permit_sequence;
    out->reserved_zero = 0u;
}

/* ---- RW txn with I* check via full scan ---- */

static ninlil_pcp_status_t pcp_rw_scan_check(
    ninlil_pcp_t *pcp,
    ninlil_storage_txn_t txn,
    pcp_scan_t *scan,
    ninlil_pcp_stage_t stage,
    ninlil_pcp_error_t *out_error,
    int out_safe)
{
    ninlil_pcp_status_t st;

    st = pcp_scan_namespace(pcp, txn, scan, stage, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        return st;
    }
    if (scan->meta_present == 0) {
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_INVALID_STATE, stage,
            NINLIL_PCP_REASON_INVALID_STATE, "not_published");
        return NINLIL_PCP_INVALID_STATE;
    }
    if (!pcp_verify_invariants(scan)) {
        pcp_set_fence_corrupt(pcp);
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE, stage,
            NINLIL_PCP_REASON_CORRUPT_FENCE, "invariants");
        return NINLIL_PCP_CORRUPT_FENCE;
    }
    /* I6/I11 full body re-get (fail-closed on CRC-valid semantic forgery). */
    st = pcp_verify_iss_bodies(pcp, txn, scan, stage, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        return st;
    }
    return NINLIL_PCP_OK;
}

/* ---- API: init / shutdown ---- */

ninlil_pcp_status_t ninlil_pcp_init_object(
    ninlil_pcp_object_t *object,
    ninlil_pcp_t **out_pcp)
{
    if (object == NULL || out_pcp == NULL) {
        return NINLIL_PCP_INVALID_ARGUMENT;
    }
    if (pcp_ranges_overlap(object, sizeof(*object), out_pcp, sizeof(*out_pcp))) {
        return NINLIL_PCP_ALIAS;
    }

    if (object->magic == NINLIL_PCP_MAGIC_VALUE
        && object->lifecycle == NINLIL_PCP_LC_ACTIVE) {
        return NINLIL_PCP_INVALID_STATE;
    }

    if (object->magic == NINLIL_PCP_MAGIC_VALUE
        && object->lifecycle == NINLIL_PCP_LC_SHUTDOWN) {
        /* re-init after shutdown */
        (void)memset(object, 0, sizeof(*object));
    } else if (object->magic != 0u || object->lifecycle != NINLIL_PCP_LC_ZERO) {
        return NINLIL_PCP_INVALID_STATE;
    } else {
        (void)memset(object, 0, sizeof(*object));
    }

    object->magic = NINLIL_PCP_MAGIC_VALUE;
    object->lifecycle = NINLIL_PCP_LC_ACTIVE;
    *out_pcp = object;
    return NINLIL_PCP_OK;
}

ninlil_pcp_status_t ninlil_pcp_shutdown(
    ninlil_pcp_t *pcp,
    ninlil_pcp_error_t *out_error)
{
    int out_safe = 1;

    if (pcp == NULL) {
        return NINLIL_PCP_INVALID_ARGUMENT;
    }
    if (out_error != NULL
        && pcp_ranges_overlap(pcp, sizeof(*pcp), out_error, sizeof(*out_error))) {
        out_safe = 0;
        pcp_sat_inc(&pcp->stats.alias_reject);
    }
    if (pcp->magic != NINLIL_PCP_MAGIC_VALUE) {
        return NINLIL_PCP_INVALID_ARGUMENT;
    }
    if (pcp->lifecycle == NINLIL_PCP_LC_SHUTDOWN) {
        return NINLIL_PCP_OK;
    }
    if (pcp->in_api != 0u) {
        pcp_sat_inc(&pcp->stats.reentry_reject);
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_BUSY_REENTRY,
            NINLIL_PCP_STAGE_SHUTDOWN, NINLIL_PCP_REASON_BUSY_REENTRY,
            "reentry");
        return NINLIL_PCP_BUSY_REENTRY;
    }

    pcp_close_handle(pcp);
    pcp_clear_ram_validate(pcp);
    (void)memset(&pcp->storage_ops, 0, sizeof(pcp->storage_ops));
    (void)memset(&pcp->clock_ops, 0, sizeof(pcp->clock_ops));
    (void)memset(&pcp->entropy_ops, 0, sizeof(pcp->entropy_ops));
    (void)memset(&pcp->bound_live, 0, sizeof(pcp->bound_live));
    (void)memset(&pcp->ram_trust, 0, sizeof(pcp->ram_trust));
    pcp->storage_bound = 0u;
    pcp->clock_bound = 0u;
    pcp->entropy_bound = 0u;
    pcp->live_bound = 0u;
    pcp->published = 0u;
    pcp->fence_bits = 0u;
    pcp->fence_code = NINLIL_PCP_FC_NONE;
    pcp->lifecycle = NINLIL_PCP_LC_SHUTDOWN;
    pcp_set_error(
        pcp, out_error, out_safe, NINLIL_PCP_OK, NINLIL_PCP_STAGE_SHUTDOWN,
        NINLIL_PCP_REASON_NONE, NULL);
    return NINLIL_PCP_OK;
}

/* ---- Bind APIs (ops only; ops->user sole) ---- */

static int pcp_guard_active(
    ninlil_pcp_t *pcp,
    ninlil_pcp_error_t *out_error,
    int *out_safe,
    ninlil_pcp_stage_t stage)
{
    *out_safe = 1;
    if (pcp == NULL) {
        return 0;
    }
    if (out_error != NULL
        && pcp_ranges_overlap(pcp, sizeof(*pcp), out_error, sizeof(*out_error))) {
        *out_safe = 0;
        pcp_sat_inc(&pcp->stats.alias_reject);
        pcp_set_error(
            pcp, NULL, 0, NINLIL_PCP_ALIAS, stage, NINLIL_PCP_REASON_ALIAS,
            "alias");
        return 0;
    }
    if (pcp->magic != NINLIL_PCP_MAGIC_VALUE
        || pcp->lifecycle != NINLIL_PCP_LC_ACTIVE) {
        pcp_set_error(
            pcp, out_error, *out_safe, NINLIL_PCP_SHUTDOWN, stage,
            NINLIL_PCP_REASON_SHUTDOWN, "shutdown");
        return 0;
    }
    if (pcp->in_api != 0u) {
        pcp_sat_inc(&pcp->stats.reentry_reject);
        pcp_set_error(
            pcp, out_error, *out_safe, NINLIL_PCP_BUSY_REENTRY, stage,
            NINLIL_PCP_REASON_BUSY_REENTRY, "reentry");
        return 0;
    }
    return 1;
}

ninlil_pcp_status_t ninlil_pcp_bind_storage(
    ninlil_pcp_t *pcp,
    const ninlil_storage_ops_t *ops,
    ninlil_pcp_error_t *out_error)
{
    int out_safe = 1;

    if (!pcp_guard_active(pcp, out_error, &out_safe, NINLIL_PCP_STAGE_BIND)) {
        return pcp != NULL ? pcp->last_error.status : NINLIL_PCP_INVALID_ARGUMENT;
    }
    if (ops == NULL || ops->open == NULL || ops->close == NULL
        || ops->begin == NULL || ops->get == NULL || ops->put == NULL
        || ops->erase == NULL || ops->iter_open == NULL || ops->iter_next == NULL
        || ops->iter_close == NULL || ops->commit == NULL
        || ops->rollback == NULL) {
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_INVALID_ARGUMENT,
            NINLIL_PCP_STAGE_BIND, NINLIL_PCP_REASON_NULL_ARG, "null_ops");
        return NINLIL_PCP_INVALID_ARGUMENT;
    }
    if (pcp->storage_handle_live != 0u) {
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_INVALID_STATE,
            NINLIL_PCP_STAGE_BIND, NINLIL_PCP_REASON_INVALID_STATE,
            "handle_live");
        return NINLIL_PCP_INVALID_STATE;
    }
    pcp->storage_ops = *ops;
    pcp->storage_bound = 1u;
    pcp_set_error(
        pcp, out_error, out_safe, NINLIL_PCP_OK, NINLIL_PCP_STAGE_BIND,
        NINLIL_PCP_REASON_NONE, NULL);
    return NINLIL_PCP_OK;
}

ninlil_pcp_status_t ninlil_pcp_bind_clock(
    ninlil_pcp_t *pcp,
    const ninlil_clock_ops_t *ops,
    ninlil_pcp_error_t *out_error)
{
    int out_safe = 1;

    if (!pcp_guard_active(pcp, out_error, &out_safe, NINLIL_PCP_STAGE_BIND)) {
        return pcp != NULL ? pcp->last_error.status : NINLIL_PCP_INVALID_ARGUMENT;
    }
    if (ops == NULL || ops->now == NULL) {
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_INVALID_ARGUMENT,
            NINLIL_PCP_STAGE_BIND, NINLIL_PCP_REASON_NULL_ARG, "null_clock");
        return NINLIL_PCP_INVALID_ARGUMENT;
    }
    pcp->clock_ops = *ops;
    pcp->clock_bound = 1u;
    pcp_set_error(
        pcp, out_error, out_safe, NINLIL_PCP_OK, NINLIL_PCP_STAGE_BIND,
        NINLIL_PCP_REASON_NONE, NULL);
    return NINLIL_PCP_OK;
}

ninlil_pcp_status_t ninlil_pcp_bind_entropy(
    ninlil_pcp_t *pcp,
    const ninlil_entropy_ops_t *ops,
    ninlil_pcp_error_t *out_error)
{
    int out_safe = 1;

    if (!pcp_guard_active(pcp, out_error, &out_safe, NINLIL_PCP_STAGE_BIND)) {
        return pcp != NULL ? pcp->last_error.status : NINLIL_PCP_INVALID_ARGUMENT;
    }
    if (ops == NULL || ops->fill == NULL) {
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_INVALID_ARGUMENT,
            NINLIL_PCP_STAGE_BIND, NINLIL_PCP_REASON_NULL_ARG, "null_entropy");
        return NINLIL_PCP_INVALID_ARGUMENT;
    }
    pcp->entropy_ops = *ops;
    pcp->entropy_bound = 1u;
    pcp_set_error(
        pcp, out_error, out_safe, NINLIL_PCP_OK, NINLIL_PCP_STAGE_BIND,
        NINLIL_PCP_REASON_NONE, NULL);
    return NINLIL_PCP_OK;
}

ninlil_pcp_status_t ninlil_pcp_bind_live_profile(
    ninlil_pcp_t *pcp,
    const ninlil_pcp_live_profile_t *live,
    ninlil_pcp_error_t *out_error)
{
    int out_safe = 1;

    if (!pcp_guard_active(pcp, out_error, &out_safe, NINLIL_PCP_STAGE_BIND)) {
        return pcp != NULL ? pcp->last_error.status : NINLIL_PCP_INVALID_ARGUMENT;
    }
    if (live == NULL) {
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_INVALID_ARGUMENT,
            NINLIL_PCP_STAGE_BIND, NINLIL_PCP_REASON_NULL_ARG, "null_live");
        return NINLIL_PCP_INVALID_ARGUMENT;
    }
    if (pcp_hal_id_is_zero(&live->hardware_profile_id)
        || pcp_hal_id_is_zero(&live->regulatory_profile_id)
        || pcp_hal_id_is_zero(&live->site_assignment_id)
        || pcp_hal_id_is_zero(&live->transmitter_id)
        || live->max_airtime_us == 0u
        || live->phy.bandwidth_hz == 0u
        || live->phy.spreading_factor == 0u
        || live->phy.coding_rate_denom == 0u
        || live->phy.phy_flags != 0u
        || live->reserved_zero != 0u) {
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_STRUCT, NINLIL_PCP_STAGE_BIND,
            NINLIL_PCP_REASON_STRUCT_INVALID, "zero_l");
        return NINLIL_PCP_STRUCT;
    }
    if (pcp->published != 0u && pcp->outstanding_count_cache != 0u) {
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_BUSY_OUTSTANDING,
            NINLIL_PCP_STAGE_BIND, NINLIL_PCP_REASON_BUSY_OUTSTANDING,
            "outstanding");
        return NINLIL_PCP_BUSY_OUTSTANDING;
    }

    pcp->bound_live.hardware_profile_id = live->hardware_profile_id;
    pcp->bound_live.hardware_profile_rev = live->hardware_profile_rev;
    pcp->bound_live.regulatory_profile_id = live->regulatory_profile_id;
    pcp->bound_live.regulatory_profile_rev = live->regulatory_profile_rev;
    pcp->bound_live.site_assignment_id = live->site_assignment_id;
    pcp->bound_live.site_assignment_rev = live->site_assignment_rev;
    pcp->bound_live.site_assignment_epoch = live->site_assignment_epoch;
    pcp->bound_live.transmitter_id = live->transmitter_id;
    pcp->bound_live.channel_id = live->channel_id;
    pcp->bound_live.phy = live->phy;
    pcp->bound_live.max_airtime_ceiling_us = live->max_airtime_us;
    pcp->bound_live.assignment_generation =
        pcp->published != 0u ? pcp->bound_live.assignment_generation : 0u;
    pcp->bound_live.bound = 1u;
    pcp->bound_live.reserved_zero = 0u;
    pcp->live_bound = 1u;
    pcp_clear_ram_validate(pcp);
    pcp_set_error(
        pcp, out_error, out_safe, NINLIL_PCP_OK, NINLIL_PCP_STAGE_BIND,
        NINLIL_PCP_REASON_NONE, NULL);
    return NINLIL_PCP_OK;
}

/* ---- publish_initial_meta ---- */

ninlil_pcp_status_t ninlil_pcp_publish_initial_meta(
    ninlil_pcp_t *pcp,
    const ninlil_pcp_instance_seed_t *seed,
    ninlil_pcp_error_t *out_error)
{
    int out_safe = 1;
    ninlil_pcp_status_t st;
    ninlil_storage_txn_t txn = NULL;
    pcp_scan_t scan;
    pcp_clk_result_t clk;
    pcp_meta_t meta;
    uint8_t instance[NINLIL_PCP_ID_BYTES];

    if (!pcp_guard_active(pcp, out_error, &out_safe, NINLIL_PCP_STAGE_PUBLISH)) {
        return pcp != NULL ? pcp->last_error.status : NINLIL_PCP_INVALID_ARGUMENT;
    }
    if (pcp->storage_bound == 0u) {
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_UNBOUND_STORAGE,
            NINLIL_PCP_STAGE_PUBLISH, NINLIL_PCP_REASON_UNBOUND_STORAGE,
            "unbound_storage");
        return NINLIL_PCP_UNBOUND_STORAGE;
    }
    if (pcp->clock_bound == 0u) {
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_UNBOUND_CLOCK,
            NINLIL_PCP_STAGE_PUBLISH, NINLIL_PCP_REASON_UNBOUND_CLOCK,
            "unbound_clock");
        return NINLIL_PCP_UNBOUND_CLOCK;
    }
    if (pcp->live_bound == 0u || pcp->bound_live.bound == 0u) {
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_UNBOUND_ASSIGNMENT,
            NINLIL_PCP_STAGE_PUBLISH, NINLIL_PCP_REASON_UNBOUND_ASSIGNMENT,
            "unbound_live");
        return NINLIL_PCP_UNBOUND_ASSIGNMENT;
    }
    if (pcp->published != 0u) {
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_INVALID_STATE,
            NINLIL_PCP_STAGE_PUBLISH, NINLIL_PCP_REASON_INVALID_STATE,
            "already_pub");
        return NINLIL_PCP_INVALID_STATE;
    }

    pcp->in_api = 1u;
    st = pcp_ensure_open(pcp, NINLIL_PCP_STAGE_PUBLISH, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        pcp->in_api = 0u;
        return st;
    }

    /* P1 RO full-namespace scan */
    st = pcp_begin(
        pcp, NINLIL_STORAGE_READ_ONLY, &txn, NINLIL_PCP_STAGE_PUBLISH,
        out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        pcp->in_api = 0u;
        return st;
    }
    st = pcp_scan_namespace(
        pcp, txn, &scan, NINLIL_PCP_STAGE_PUBLISH, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_PUBLISH, out_error, out_safe);
        pcp->in_api = 0u;
        return st;
    }
    if (scan.meta_present != 0) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_PUBLISH, out_error, out_safe);
        pcp->in_api = 0u;
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_INVALID_STATE,
            NINLIL_PCP_STAGE_PUBLISH, NINLIL_PCP_REASON_INVALID_STATE,
            "meta_exists");
        return NINLIL_PCP_INVALID_STATE;
    }
    if (scan.iss_count > 0u) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_PUBLISH, out_error, out_safe);
        pcp_set_fence_corrupt(pcp);
        pcp->in_api = 0u;
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE,
            NINLIL_PCP_STAGE_PUBLISH, NINLIL_PCP_REASON_CORRUPT_FENCE,
            "iss_without_meta");
        return NINLIL_PCP_CORRUPT_FENCE;
    }
    st = pcp_rollback_map(
        pcp, txn, NINLIL_PCP_STAGE_PUBLISH, out_error, out_safe);
    txn = NULL;
    if (st != NINLIL_PCP_OK) {
        pcp->in_api = 0u;
        return st;
    }

    /* P3 clock */
    clk = pcp_sample_clock(pcp);
    if (clk.klass == PCP_CLK_TEMP || clk.klass == PCP_CLK_OK_UNCERTAIN) {
        pcp->in_api = 0u;
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_CLOCK_UNCERTAIN,
            NINLIL_PCP_STAGE_PUBLISH, NINLIL_PCP_REASON_CLOCK_UNCERTAIN,
            "clock_uncertain");
        return NINLIL_PCP_CLOCK_UNCERTAIN;
    }
    if (clk.klass != PCP_CLK_OK_TRUSTED) {
        pcp_apply_clock_fault_fence(pcp, clk.klass);
        pcp->in_api = 0u;
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_CLOCK_FAULT,
            NINLIL_PCP_STAGE_PUBLISH, NINLIL_PCP_REASON_CLOCK_FAULT,
            "clock_fault");
        return NINLIL_PCP_CLOCK_FAULT;
    }

    /* P4 instance id */
    if (seed != NULL && !pcp_id_is_zero(seed->bytes, 16u)) {
        (void)memcpy(instance, seed->bytes, 16u);
    } else {
        ninlil_port_status_t es;
        if (pcp->entropy_bound == 0u) {
            pcp->in_api = 0u;
            pcp_set_error(
                pcp, out_error, out_safe, NINLIL_PCP_INVALID_ARGUMENT,
                NINLIL_PCP_STAGE_PUBLISH, NINLIL_PCP_REASON_NULL_ARG,
                "need_entropy");
            return NINLIL_PCP_INVALID_ARGUMENT;
        }
        es = pcp->entropy_ops.fill(
            pcp->entropy_ops.user, instance, 16u);
        if (es != NINLIL_PORT_OK || pcp_id_is_zero(instance, 16u)) {
            pcp->in_api = 0u;
            pcp_set_error(
                pcp, out_error, out_safe, NINLIL_PCP_INVALID_ARGUMENT,
                NINLIL_PCP_STAGE_PUBLISH, NINLIL_PCP_REASON_STRUCT_INVALID,
                "zero_instance");
            return NINLIL_PCP_INVALID_ARGUMENT;
        }
    }

    (void)memset(&meta, 0, sizeof(meta));
    meta.magic = NINLIL_PCP_MAGIC;
    meta.schema = NINLIL_PCP_SCHEMA_VERSION;
    meta.meta_state = PCP_META_STATE_ACTIVE;
    meta.fence_bits = 0u;
    meta.fence_code = NINLIL_PCP_FC_NONE;
    (void)memcpy(meta.authority_instance_id, instance, 16u);
    meta.next_issue_seq = 1u;
    meta.last_consumed_seq = 0u;
    meta.outstanding_count = 0u;
    meta.bound_hardware_profile_id = pcp->bound_live.hardware_profile_id;
    meta.bound_hardware_profile_rev = pcp->bound_live.hardware_profile_rev;
    meta.bound_regulatory_profile_id = pcp->bound_live.regulatory_profile_id;
    meta.bound_regulatory_profile_rev = pcp->bound_live.regulatory_profile_rev;
    meta.bound_site_assignment_id = pcp->bound_live.site_assignment_id;
    meta.bound_site_assignment_rev = pcp->bound_live.site_assignment_rev;
    meta.bound_site_assignment_epoch = pcp->bound_live.site_assignment_epoch;
    meta.bound_transmitter_id = pcp->bound_live.transmitter_id;
    meta.bound_channel_id = pcp->bound_live.channel_id;
    meta.bound_phy = pcp->bound_live.phy;
    meta.bound_max_airtime_ceiling_us = pcp->bound_live.max_airtime_ceiling_us;
    meta.assignment_generation = 1u;
    (void)memcpy(
        meta.last_trusted_epoch_id, clk.sample.clock_epoch_id.bytes, 16u);
    meta.last_trusted_now_ms = clk.sample.now_ms;
    meta.reserved_zero = 0u;

    st = pcp_begin(
        pcp, NINLIL_STORAGE_READ_WRITE, &txn, NINLIL_PCP_STAGE_PUBLISH,
        out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        pcp->in_api = 0u;
        return st;
    }
    /* every RW begin: reconfirm EMPTY full-namespace (publish-only evidence) */
    {
        pcp_scan_t scan_pub;

        st = pcp_scan_namespace(
            pcp, txn, &scan_pub, NINLIL_PCP_STAGE_PUBLISH, out_error, out_safe);
        if (st != NINLIL_PCP_OK) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_PUBLISH, out_error, out_safe);
            pcp->in_api = 0u;
            return st;
        }
        if (scan_pub.meta_present != 0 || scan_pub.iss_count > 0u
            || scan_pub.foreign != 0) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_PUBLISH, out_error, out_safe);
            pcp->in_api = 0u;
            pcp_set_error(
                pcp, out_error, out_safe, NINLIL_PCP_INVALID_STATE,
                NINLIL_PCP_STAGE_PUBLISH, NINLIL_PCP_REASON_INVALID_STATE,
                "not_empty");
            return NINLIL_PCP_INVALID_STATE;
        }
    }
    st = pcp_txn_put_meta(
        pcp, txn, &meta, NINLIL_PCP_STAGE_PUBLISH, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_PUBLISH, out_error, out_safe);
        pcp->in_api = 0u;
        return st;
    }
    st = pcp_commit_full(
        pcp, txn, NINLIL_PCP_STAGE_PUBLISH, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        pcp->in_api = 0u;
        return st;
    }

    pcp_load_meta_to_ram(pcp, &meta);
    pcp_set_ram_trust(
        pcp, clk.sample.clock_epoch_id.bytes, clk.sample.now_ms);
    pcp_clear_ram_validate(pcp);
    pcp->in_api = 0u;
    pcp_set_error(
        pcp, out_error, out_safe, NINLIL_PCP_OK, NINLIL_PCP_STAGE_PUBLISH,
        NINLIL_PCP_REASON_NONE, NULL);
    return NINLIL_PCP_OK;
}

/* Continued in next section of file — recover / issue / advance / revoke / gc /
 * validate / consume — appended below to keep structure clear. */

/* ---- recover_storage ---- */

ninlil_pcp_status_t ninlil_pcp_recover_storage(
    ninlil_pcp_t *pcp,
    ninlil_pcp_error_t *out_error)
{
    int out_safe = 1;
    ninlil_pcp_status_t st;
    ninlil_storage_txn_t txn = NULL;
    pcp_scan_t scan;

    if (!pcp_guard_active(pcp, out_error, &out_safe, NINLIL_PCP_STAGE_RECOVER)) {
        return pcp != NULL ? pcp->last_error.status : NINLIL_PCP_INVALID_ARGUMENT;
    }
    pcp->in_api = 1u;
    pcp_clear_ram_validate(pcp);

    if (pcp->storage_handle_live != 0u) {
        pcp_close_handle(pcp);
    }
    st = pcp_ensure_open(pcp, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        pcp_sat_inc(&pcp->stats.recover_fail);
        pcp->in_api = 0u;
        return st;
    }

    st = pcp_begin(
        pcp, NINLIL_STORAGE_READ_ONLY, &txn, NINLIL_PCP_STAGE_RECOVER,
        out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        pcp_sat_inc(&pcp->stats.recover_fail);
        pcp->in_api = 0u;
        return st;
    }
    st = pcp_scan_namespace(
        pcp, txn, &scan, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
        pcp_sat_inc(&pcp->stats.recover_fail);
        pcp->in_api = 0u;
        return st == NINLIL_PCP_CORRUPT_FENCE ? NINLIL_PCP_RECOVER_FAIL : st;
    }
    if (scan.meta_present == 0 && scan.iss_count == 0u) {
        st = pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
        pcp->published = 0u;
        pcp->in_api = 0u;
        if (st != NINLIL_PCP_OK) {
            pcp_sat_inc(&pcp->stats.recover_fail);
            return st;
        }
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_EMPTY_OK,
            NINLIL_PCP_STAGE_RECOVER, NINLIL_PCP_REASON_NONE, "empty");
        return NINLIL_PCP_EMPTY_OK;
    }
    if (scan.meta_present == 0 && scan.iss_count > 0u) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
        pcp_set_fence_corrupt(pcp);
        pcp_sat_inc(&pcp->stats.recover_fail);
        pcp->in_api = 0u;
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_RECOVER_FAIL,
            NINLIL_PCP_STAGE_RECOVER, NINLIL_PCP_REASON_CORRUPT_FENCE,
            "meta_absent_iss");
        return NINLIL_PCP_RECOVER_FAIL;
    }
    if (!pcp_verify_invariants(&scan)) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
        pcp_set_fence_corrupt(pcp);
        pcp_sat_inc(&pcp->stats.recover_fail);
        pcp->in_api = 0u;
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_RECOVER_FAIL,
            NINLIL_PCP_STAGE_RECOVER, NINLIL_PCP_REASON_CORRUPT_FENCE,
            "invariants");
        return NINLIL_PCP_RECOVER_FAIL;
    }
    st = pcp_verify_iss_bodies(
        pcp, txn, &scan, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
        pcp_sat_inc(&pcp->stats.recover_fail);
        pcp->in_api = 0u;
        if (st == NINLIL_PCP_CORRUPT_FENCE) {
            pcp_set_error(
                pcp, out_error, out_safe, NINLIL_PCP_RECOVER_FAIL,
                NINLIL_PCP_STAGE_RECOVER, NINLIL_PCP_REASON_CORRUPT_FENCE,
                "body_i6_i11");
            return NINLIL_PCP_RECOVER_FAIL;
        }
        return st;
    }
    st = pcp_rollback_map(
        pcp, txn, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        pcp_sat_inc(&pcp->stats.recover_fail);
        pcp->in_api = 0u;
        return st;
    }

    /* STORAGE clear if clean I* and no CORRUPT */
    if ((scan.meta.fence_bits & NINLIL_PCP_FENCE_BIT_STORAGE) != 0u
        && (scan.meta.fence_bits & NINLIL_PCP_FENCE_BIT_CORRUPT) == 0u) {
        pcp_meta_t m;
        pcp_scan_t scan_rw;

        st = pcp_begin(
            pcp, NINLIL_STORAGE_READ_WRITE, &txn, NINLIL_PCP_STAGE_RECOVER,
            out_error, out_safe);
        if (st != NINLIL_PCP_OK) {
            pcp_sat_inc(&pcp->stats.recover_fail);
            pcp->in_api = 0u;
            return st;
        }
        /* every RW begin: re-verify I1–I14 before fence-clear mutation */
        st = pcp_rw_scan_check(
            pcp, txn, &scan_rw, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
        if (st != NINLIL_PCP_OK) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
            pcp_sat_inc(&pcp->stats.recover_fail);
            pcp->in_api = 0u;
            return st == NINLIL_PCP_CORRUPT_FENCE ? NINLIL_PCP_RECOVER_FAIL : st;
        }
        m = scan_rw.meta;
        m.fence_bits =
            (uint8_t)(m.fence_bits & (uint8_t)~NINLIL_PCP_FENCE_BIT_STORAGE);
        if ((m.fence_bits & NINLIL_PCP_FENCE_BIT_CLOCK) == 0u) {
            m.fence_code = NINLIL_PCP_FC_NONE;
        }
        st = pcp_txn_put_meta(
            pcp, txn, &m, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
        if (st != NINLIL_PCP_OK) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
            pcp_sat_inc(&pcp->stats.recover_fail);
            pcp->in_api = 0u;
            return st;
        }
        st = pcp_commit_full(
            pcp, txn, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
        if (st != NINLIL_PCP_OK) {
            pcp_sat_inc(&pcp->stats.recover_fail);
            pcp->in_api = 0u;
            return NINLIL_PCP_RECOVER_FAIL;
        }
        scan.meta = m;
        pcp->fence_bits =
            (uint32_t)(pcp->fence_bits & ~NINLIL_PCP_FENCE_BIT_STORAGE);
    }

    pcp_load_meta_to_ram(pcp, &scan.meta);
    pcp_clear_ram_validate(pcp);
    pcp_sat_inc(&pcp->stats.recover_ok);
    pcp->in_api = 0u;
    pcp_set_error(
        pcp, out_error, out_safe, NINLIL_PCP_OK, NINLIL_PCP_STAGE_RECOVER,
        NINLIL_PCP_REASON_NONE, NULL);
    return NINLIL_PCP_OK;
}

/* ---- recover_clock (Algorithm C) ---- */

ninlil_pcp_status_t ninlil_pcp_recover_clock(
    ninlil_pcp_t *pcp,
    ninlil_pcp_error_t *out_error)
{
    int out_safe = 1;
    ninlil_pcp_status_t st;
    pcp_clk_result_t clk;
    ninlil_storage_txn_t txn = NULL;
    pcp_meta_t meta;
    int need_revoke = 0;

    if (!pcp_guard_active(pcp, out_error, &out_safe, NINLIL_PCP_STAGE_RECOVER)) {
        return pcp != NULL ? pcp->last_error.status : NINLIL_PCP_INVALID_ARGUMENT;
    }
    if (pcp->clock_bound == 0u) {
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_UNBOUND_CLOCK,
            NINLIL_PCP_STAGE_RECOVER, NINLIL_PCP_REASON_UNBOUND_CLOCK,
            "unbound_clock");
        return NINLIL_PCP_UNBOUND_CLOCK;
    }
    if ((pcp->fence_bits & NINLIL_PCP_FENCE_BIT_CLOCK) == 0u) {
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_OK, NINLIL_PCP_STAGE_RECOVER,
            NINLIL_PCP_REASON_NONE, NULL);
        return NINLIL_PCP_OK;
    }

    pcp->in_api = 1u;
    st = pcp_ensure_open(pcp, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        pcp->in_api = 0u;
        return st;
    }

    clk = pcp_sample_clock(pcp);
    if (clk.klass != PCP_CLK_OK_TRUSTED) {
        /* do not clear fence */
        pcp->in_api = 0u;
        if (clk.klass == PCP_CLK_TEMP || clk.klass == PCP_CLK_OK_UNCERTAIN) {
            pcp_set_error(
                pcp, out_error, out_safe, NINLIL_PCP_CLOCK_UNCERTAIN,
                NINLIL_PCP_STAGE_RECOVER, NINLIL_PCP_REASON_CLOCK_UNCERTAIN,
                "uncertain");
            return NINLIL_PCP_CLOCK_UNCERTAIN;
        }
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_CLOCK_FAULT,
            NINLIL_PCP_STAGE_RECOVER, NINLIL_PCP_REASON_CLOCK_FAULT, "fault");
        return NINLIL_PCP_CLOCK_FAULT;
    }

    /* fresh_epoch: nonzero, != ram_trust, != meta.last_trusted */
    if (pcp->ram_trust.valid != 0u
        && pcp_id_equal(
            clk.sample.clock_epoch_id.bytes, pcp->ram_trust.clock_epoch_id,
            16u)) {
        pcp->in_api = 0u;
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_CLOCK_FAULT,
            NINLIL_PCP_STAGE_RECOVER, NINLIL_PCP_REASON_CLOCK_FAULT,
            "same_epoch");
        return NINLIL_PCP_CLOCK_FAULT;
    }

    st = pcp_begin(
        pcp, NINLIL_STORAGE_READ_WRITE, &txn, NINLIL_PCP_STAGE_RECOVER,
        out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        pcp->in_api = 0u;
        return st;
    }
    {
        pcp_scan_t scan_c;

        /* every RW begin: full I1–I14 before clock-fence mutation */
        st = pcp_rw_scan_check(
            pcp, txn, &scan_c, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
        if (st != NINLIL_PCP_OK) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
            pcp->in_api = 0u;
            return st;
        }
        meta = scan_c.meta;
    }
    if (pcp_id_equal(
            clk.sample.clock_epoch_id.bytes, meta.last_trusted_epoch_id, 16u)) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
        pcp->in_api = 0u;
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_CLOCK_FAULT,
            NINLIL_PCP_STAGE_RECOVER, NINLIL_PCP_REASON_CLOCK_FAULT,
            "same_meta_epoch");
        return NINLIL_PCP_CLOCK_FAULT;
    }

    /* outstanding with different epoch → BUSY_OUTSTANDING (caller uses R) */
    if (meta.outstanding_count > 0u) {
        uint64_t head = meta.last_consumed_seq + 1u;
        uint32_t n;
        for (n = 0u; n < meta.outstanding_count; ++n) {
            pcp_issued_t iss;
            int nf = 0;
            st = pcp_txn_get_iss(
                pcp, txn, head + n, &iss, &nf, NINLIL_PCP_STAGE_RECOVER,
                out_error, out_safe);
            if (st != NINLIL_PCP_OK || nf != 0
                || iss.state != PCP_ISS_STATE_ISSUED) {
                (void)pcp_rollback_map(
                    pcp, txn, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
                pcp_set_fence_corrupt(pcp);
                pcp->in_api = 0u;
                return NINLIL_PCP_CORRUPT_FENCE;
            }
            if (!pcp_id_equal(
                    iss.clock_epoch_id, clk.sample.clock_epoch_id.bytes, 16u)) {
                need_revoke = 1;
                break;
            }
        }
    }
    if (need_revoke != 0) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
        pcp->in_api = 0u;
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_BUSY_OUTSTANDING,
            NINLIL_PCP_STAGE_RECOVER, NINLIL_PCP_REASON_BUSY_OUTSTANDING,
            "need_revoke");
        return NINLIL_PCP_BUSY_OUTSTANDING;
    }

    (void)memcpy(
        meta.last_trusted_epoch_id, clk.sample.clock_epoch_id.bytes, 16u);
    meta.last_trusted_now_ms = clk.sample.now_ms;
    meta.fence_bits =
        (uint8_t)(meta.fence_bits & (uint8_t)~NINLIL_PCP_FENCE_BIT_CLOCK);
    if ((meta.fence_bits
            & (uint8_t)(NINLIL_PCP_FENCE_BIT_STORAGE | NINLIL_PCP_FENCE_BIT_CORRUPT))
        == 0u) {
        meta.fence_code = NINLIL_PCP_FC_NONE;
    }
    st = pcp_txn_put_meta(
        pcp, txn, &meta, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
        pcp->in_api = 0u;
        return st;
    }
    st = pcp_commit_full(
        pcp, txn, NINLIL_PCP_STAGE_RECOVER, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        pcp->in_api = 0u;
        return st;
    }

    pcp->fence_bits &= ~NINLIL_PCP_FENCE_BIT_CLOCK;
    if ((pcp->fence_bits
            & (NINLIL_PCP_FENCE_BIT_STORAGE | NINLIL_PCP_FENCE_BIT_CORRUPT))
        == 0u) {
        pcp->fence_code = NINLIL_PCP_FC_NONE;
    }
    pcp_set_ram_trust(
        pcp, clk.sample.clock_epoch_id.bytes, clk.sample.now_ms);
    pcp_clear_ram_validate(pcp);
    pcp->in_api = 0u;
    pcp_set_error(
        pcp, out_error, out_safe, NINLIL_PCP_OK, NINLIL_PCP_STAGE_RECOVER,
        NINLIL_PCP_REASON_NONE, NULL);
    return NINLIL_PCP_OK;
}

ninlil_pcp_status_t ninlil_pcp_recover(
    ninlil_pcp_t *pcp,
    ninlil_pcp_error_t *out_error)
{
    ninlil_pcp_status_t st;

    st = ninlil_pcp_recover_storage(pcp, out_error);
    if (st != NINLIL_PCP_OK && st != NINLIL_PCP_EMPTY_OK) {
        return st;
    }
    if (pcp != NULL && pcp->clock_bound != 0u
        && (pcp->fence_bits & NINLIL_PCP_FENCE_BIT_CLOCK) != 0u) {
        ninlil_pcp_status_t cst = ninlil_pcp_recover_clock(pcp, out_error);
        if (cst != NINLIL_PCP_OK) {
            return cst;
        }
    }
    return st;
}

/* File continues with issue / advance / revoke / gc / validate / consume in
 * the remainder of this translation unit. */

/* ---- Algorithm R: revoke_all_outstanding (clockless) ---- */

ninlil_pcp_status_t ninlil_pcp_revoke_all_outstanding(
    ninlil_pcp_t *pcp,
    ninlil_pcp_error_t *out_error)
{
    int out_safe = 1;
    ninlil_pcp_status_t st;

    if (!pcp_guard_active(pcp, out_error, &out_safe, NINLIL_PCP_STAGE_REVOKE)) {
        return pcp != NULL ? pcp->last_error.status : NINLIL_PCP_INVALID_ARGUMENT;
    }
    pcp->in_api = 1u;
    st = pcp_ensure_open(pcp, NINLIL_PCP_STAGE_REVOKE, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        pcp->in_api = 0u;
        return st;
    }

    for (;;) {
        ninlil_storage_txn_t txn = NULL;
        pcp_scan_t scan;
        pcp_meta_t meta;
        pcp_issued_t iss;
        int absent = 0;
        uint64_t head;

        st = pcp_begin(
            pcp, NINLIL_STORAGE_READ_WRITE, &txn, NINLIL_PCP_STAGE_REVOKE,
            out_error, out_safe);
        if (st != NINLIL_PCP_OK) {
            pcp->in_api = 0u;
            return st;
        }
        /* every RW begin: full I1–I14 + body semantics (docs/24 §4.3) */
        st = pcp_rw_scan_check(
            pcp, txn, &scan, NINLIL_PCP_STAGE_REVOKE, out_error, out_safe);
        if (st != NINLIL_PCP_OK) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_REVOKE, out_error, out_safe);
            pcp->in_api = 0u;
            return st;
        }
        meta = scan.meta;
        if (meta.outstanding_count == 0u) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_REVOKE, out_error, out_safe);
            pcp->outstanding_count_cache = 0u;
            pcp->last_consumed_seq_cache = meta.last_consumed_seq;
            pcp->next_issue_seq_cache = meta.next_issue_seq;
            pcp_clear_ram_validate(pcp);
            pcp_sat_inc(&pcp->stats.revoke_ok);
            pcp->in_api = 0u;
            pcp_set_error(
                pcp, out_error, out_safe, NINLIL_PCP_OK,
                NINLIL_PCP_STAGE_REVOKE, NINLIL_PCP_REASON_NONE, NULL);
            return NINLIL_PCP_OK;
        }

        head = meta.last_consumed_seq + 1u;
        st = pcp_txn_get_iss(
            pcp, txn, head, &iss, &absent, NINLIL_PCP_STAGE_REVOKE, out_error,
            out_safe);
        if (st != NINLIL_PCP_OK || absent != 0
            || iss.state != PCP_ISS_STATE_ISSUED) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_REVOKE, out_error, out_safe);
            pcp_set_fence_corrupt(pcp);
            pcp->in_api = 0u;
            pcp_set_error(
                pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE,
                NINLIL_PCP_STAGE_REVOKE, NINLIL_PCP_REASON_CORRUPT_FENCE,
                "head");
            return NINLIL_PCP_CORRUPT_FENCE;
        }
        iss.state = PCP_ISS_STATE_REVOKED;
        st = pcp_txn_put_iss(
            pcp, txn, &iss, NINLIL_PCP_STAGE_REVOKE, out_error, out_safe);
        if (st != NINLIL_PCP_OK) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_REVOKE, out_error, out_safe);
            pcp->in_api = 0u;
            return st;
        }
        meta.outstanding_count -= 1u;
        meta.last_consumed_seq = head;
        /* last_trusted_* unchanged (clockless) */
        st = pcp_txn_put_meta(
            pcp, txn, &meta, NINLIL_PCP_STAGE_REVOKE, out_error, out_safe);
        if (st != NINLIL_PCP_OK) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_REVOKE, out_error, out_safe);
            pcp->in_api = 0u;
            return st;
        }
        st = pcp_commit_full(
            pcp, txn, NINLIL_PCP_STAGE_REVOKE, out_error, out_safe);
        if (st != NINLIL_PCP_OK) {
            pcp->in_api = 0u;
            return st;
        }
        pcp->outstanding_count_cache = meta.outstanding_count;
        pcp->last_consumed_seq_cache = meta.last_consumed_seq;
        pcp_clear_ram_validate(pcp);
    }
}

/* ---- Algorithm A: advance_expired_heads ---- */

ninlil_pcp_status_t ninlil_pcp_advance_expired_heads(
    ninlil_pcp_t *pcp,
    ninlil_pcp_error_t *out_error)
{
    int out_safe = 1;
    ninlil_pcp_status_t st;
    pcp_clk_result_t clk;
    int advanced_any = 0;

    if (!pcp_guard_active(pcp, out_error, &out_safe, NINLIL_PCP_STAGE_ADVANCE)) {
        return pcp != NULL ? pcp->last_error.status : NINLIL_PCP_INVALID_ARGUMENT;
    }
    if (pcp->clock_bound == 0u) {
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_UNBOUND_CLOCK,
            NINLIL_PCP_STAGE_ADVANCE, NINLIL_PCP_REASON_UNBOUND_CLOCK,
            "unbound_clock");
        return NINLIL_PCP_UNBOUND_CLOCK;
    }
    if (pcp->storage_bound == 0u) {
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_UNBOUND_STORAGE,
            NINLIL_PCP_STAGE_ADVANCE, NINLIL_PCP_REASON_UNBOUND_STORAGE,
            "unbound_storage");
        return NINLIL_PCP_UNBOUND_STORAGE;
    }

    pcp->in_api = 1u;
    st = pcp_ensure_open(pcp, NINLIL_PCP_STAGE_ADVANCE, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        pcp->in_api = 0u;
        return st;
    }

    /* A0 sample once */
    clk = pcp_sample_clock(pcp);
    if (clk.klass == PCP_CLK_TEMP || clk.klass == PCP_CLK_OK_UNCERTAIN) {
        pcp->in_api = 0u;
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_CLOCK_UNCERTAIN,
            NINLIL_PCP_STAGE_ADVANCE, NINLIL_PCP_REASON_CLOCK_UNCERTAIN,
            "uncertain");
        return NINLIL_PCP_CLOCK_UNCERTAIN;
    }
    if (clk.klass != PCP_CLK_OK_TRUSTED) {
        pcp_apply_clock_fault_fence(pcp, clk.klass);
        pcp->in_api = 0u;
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_CLOCK_FAULT,
            NINLIL_PCP_STAGE_ADVANCE, NINLIL_PCP_REASON_CLOCK_FAULT, "fault");
        return NINLIL_PCP_CLOCK_FAULT;
    }

    for (;;) {
        ninlil_storage_txn_t txn = NULL;
        pcp_scan_t scan;
        pcp_meta_t meta;
        pcp_issued_t iss;
        int absent = 0;
        uint64_t head;

        st = pcp_begin(
            pcp, NINLIL_STORAGE_READ_WRITE, &txn, NINLIL_PCP_STAGE_ADVANCE,
            out_error, out_safe);
        if (st != NINLIL_PCP_OK) {
            if (advanced_any != 0) {
                pcp_set_ram_trust(
                    pcp, clk.sample.clock_epoch_id.bytes, clk.sample.now_ms);
                pcp_clear_ram_validate(pcp);
            }
            pcp->in_api = 0u;
            return st;
        }
        st = pcp_rw_scan_check(
            pcp, txn, &scan, NINLIL_PCP_STAGE_ADVANCE, out_error, out_safe);
        if (st != NINLIL_PCP_OK) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_ADVANCE, out_error, out_safe);
            if (advanced_any != 0) {
                pcp_set_ram_trust(
                    pcp, clk.sample.clock_epoch_id.bytes, clk.sample.now_ms);
                pcp_clear_ram_validate(pcp);
            }
            pcp->in_api = 0u;
            return st;
        }
        meta = scan.meta;
        if ((meta.fence_bits
                & (uint8_t)(NINLIL_PCP_FENCE_BIT_STORAGE
                    | NINLIL_PCP_FENCE_BIT_CLOCK
                    | NINLIL_PCP_FENCE_BIT_CORRUPT))
            != 0u) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_ADVANCE, out_error, out_safe);
            pcp->in_api = 0u;
            if ((meta.fence_bits & NINLIL_PCP_FENCE_BIT_CORRUPT) != 0u) {
                pcp_set_error(
                    pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE,
                    NINLIL_PCP_STAGE_ADVANCE, NINLIL_PCP_REASON_CORRUPT_FENCE,
                    "fence");
                return NINLIL_PCP_CORRUPT_FENCE;
            }
            if ((meta.fence_bits & NINLIL_PCP_FENCE_BIT_CLOCK) != 0u) {
                pcp_set_error(
                    pcp, out_error, out_safe, NINLIL_PCP_CLOCK_FAULT,
                    NINLIL_PCP_STAGE_ADVANCE, NINLIL_PCP_REASON_CLOCK_FAULT,
                    "fence_clock");
                return NINLIL_PCP_CLOCK_FAULT;
            }
            pcp_set_error(
                pcp, out_error, out_safe, NINLIL_PCP_STORAGE_FENCE,
                NINLIL_PCP_STAGE_ADVANCE, NINLIL_PCP_REASON_STORAGE_FENCE,
                "fence_storage");
            return NINLIL_PCP_STORAGE_FENCE;
        }

        if (meta.outstanding_count == 0u) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_ADVANCE, out_error, out_safe);
            if (advanced_any != 0) {
                pcp_set_ram_trust(
                    pcp, meta.last_trusted_epoch_id, meta.last_trusted_now_ms);
                pcp_clear_ram_validate(pcp);
                pcp_sat_inc(&pcp->stats.advance_ok);
            } else {
                pcp_sat_inc(&pcp->stats.advance_nop);
            }
            pcp->in_api = 0u;
            pcp_set_error(
                pcp, out_error, out_safe, NINLIL_PCP_OK,
                NINLIL_PCP_STAGE_ADVANCE, NINLIL_PCP_REASON_NONE, NULL);
            return NINLIL_PCP_OK;
        }

        head = meta.last_consumed_seq + 1u;
        st = pcp_txn_get_iss(
            pcp, txn, head, &iss, &absent, NINLIL_PCP_STAGE_ADVANCE, out_error,
            out_safe);
        if (st != NINLIL_PCP_OK || absent != 0
            || iss.state != PCP_ISS_STATE_ISSUED) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_ADVANCE, out_error, out_safe);
            pcp_set_fence_corrupt(pcp);
            pcp->in_api = 0u;
            return NINLIL_PCP_CORRUPT_FENCE;
        }

        if (!pcp_expired_time(&clk.sample, &iss)) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_ADVANCE, out_error, out_safe);
            if (advanced_any != 0) {
                pcp_set_ram_trust(
                    pcp, meta.last_trusted_epoch_id, meta.last_trusted_now_ms);
                pcp_clear_ram_validate(pcp);
                pcp_sat_inc(&pcp->stats.advance_ok);
            } else {
                pcp_sat_inc(&pcp->stats.advance_nop);
            }
            pcp->in_api = 0u;
            pcp_set_error(
                pcp, out_error, out_safe, NINLIL_PCP_OK,
                NINLIL_PCP_STAGE_ADVANCE, NINLIL_PCP_REASON_NONE, NULL);
            return NINLIL_PCP_OK;
        }

        iss.state = PCP_ISS_STATE_REVOKED;
        st = pcp_txn_put_iss(
            pcp, txn, &iss, NINLIL_PCP_STAGE_ADVANCE, out_error, out_safe);
        if (st != NINLIL_PCP_OK) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_ADVANCE, out_error, out_safe);
            if (advanced_any != 0) {
                pcp_set_ram_trust(
                    pcp, clk.sample.clock_epoch_id.bytes, clk.sample.now_ms);
                pcp_clear_ram_validate(pcp);
            }
            pcp->in_api = 0u;
            return st;
        }
        meta.outstanding_count -= 1u;
        meta.last_consumed_seq = head;
        (void)memcpy(
            meta.last_trusted_epoch_id, clk.sample.clock_epoch_id.bytes, 16u);
        meta.last_trusted_now_ms = clk.sample.now_ms;
        st = pcp_txn_put_meta(
            pcp, txn, &meta, NINLIL_PCP_STAGE_ADVANCE, out_error, out_safe);
        if (st != NINLIL_PCP_OK) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_ADVANCE, out_error, out_safe);
            if (advanced_any != 0) {
                pcp_set_ram_trust(
                    pcp, clk.sample.clock_epoch_id.bytes, clk.sample.now_ms);
                pcp_clear_ram_validate(pcp);
            }
            pcp->in_api = 0u;
            return st;
        }
        st = pcp_commit_full(
            pcp, txn, NINLIL_PCP_STAGE_ADVANCE, out_error, out_safe);
        if (st == NINLIL_PCP_COMMIT_UNKNOWN) {
            pcp_clear_ram_validate(pcp);
            pcp->in_api = 0u;
            return st;
        }
        if (st != NINLIL_PCP_OK) {
            if (advanced_any != 0) {
                pcp_set_ram_trust(
                    pcp, clk.sample.clock_epoch_id.bytes, clk.sample.now_ms);
                pcp_clear_ram_validate(pcp);
            }
            pcp->in_api = 0u;
            return st;
        }
        advanced_any = 1;
        pcp->outstanding_count_cache = meta.outstanding_count;
        pcp->last_consumed_seq_cache = meta.last_consumed_seq;
        pcp_set_ram_trust(
            pcp, clk.sample.clock_epoch_id.bytes, clk.sample.now_ms);
        pcp_clear_ram_validate(pcp);
    }
}

/* ---- GC terminal records ---- */

ninlil_pcp_status_t ninlil_pcp_gc_terminal_records(
    ninlil_pcp_t *pcp,
    const uint64_t *seqs,
    uint32_t seq_count,
    ninlil_pcp_error_t *out_error)
{
    int out_safe = 1;
    ninlil_pcp_status_t st;
    ninlil_storage_txn_t txn = NULL;
    pcp_scan_t scan;
    pcp_meta_t meta;
    uint32_t i;
    uint32_t erased = 0u;
    int absent = 0;

    if (!pcp_guard_active(pcp, out_error, &out_safe, NINLIL_PCP_STAGE_GC)) {
        return pcp != NULL ? pcp->last_error.status : NINLIL_PCP_INVALID_ARGUMENT;
    }
    if (seqs == NULL || seq_count == 0u
        || seq_count > NINLIL_PCP_MAX_OUTSTANDING) {
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_INVALID_ARGUMENT,
            NINLIL_PCP_STAGE_GC, NINLIL_PCP_REASON_NULL_ARG, "gc_args");
        return NINLIL_PCP_INVALID_ARGUMENT;
    }

    pcp->in_api = 1u;
    st = pcp_ensure_open(pcp, NINLIL_PCP_STAGE_GC, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        pcp->in_api = 0u;
        return st;
    }

    st = pcp_begin(
        pcp, NINLIL_STORAGE_READ_WRITE, &txn, NINLIL_PCP_STAGE_GC, out_error,
        out_safe);
    if (st != NINLIL_PCP_OK) {
        pcp->in_api = 0u;
        return st;
    }
    st = pcp_rw_scan_check(
        pcp, txn, &scan, NINLIL_PCP_STAGE_GC, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_GC, out_error, out_safe);
        pcp->in_api = 0u;
        return st;
    }
    meta = scan.meta;

    for (i = 0u; i < seq_count; ++i) {
        uint64_t seq = seqs[i];
        pcp_issued_t iss;

        ninlil_bytes_view_t key;
        ninlil_storage_status_t est;
        pcp_map_t em;

        if (seq == 0u || seq == UINT64_MAX || seq > meta.last_consumed_seq) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_GC, out_error, out_safe);
            pcp->in_api = 0u;
            pcp_set_error(
                pcp, out_error, out_safe, NINLIL_PCP_INVALID_ARGUMENT,
                NINLIL_PCP_STAGE_GC, NINLIL_PCP_REASON_STRUCT_INVALID,
                "gc_ineligible");
            return NINLIL_PCP_INVALID_ARGUMENT;
        }
        st = pcp_txn_get_iss(
            pcp, txn, seq, &iss, &absent, NINLIL_PCP_STAGE_GC, out_error,
            out_safe);
        if (st != NINLIL_PCP_OK) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_GC, out_error, out_safe);
            pcp->in_api = 0u;
            return st;
        }
        if (absent != 0) {
            continue; /* already gone */
        }
        if (iss.state == PCP_ISS_STATE_ISSUED) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_GC, out_error, out_safe);
            pcp->in_api = 0u;
            pcp_set_error(
                pcp, out_error, out_safe, NINLIL_PCP_INVALID_ARGUMENT,
                NINLIL_PCP_STAGE_GC, NINLIL_PCP_REASON_STRUCT_INVALID,
                "gc_issued");
            return NINLIL_PCP_INVALID_ARGUMENT;
        }
        if (iss.state != PCP_ISS_STATE_CONSUMED
            && iss.state != PCP_ISS_STATE_REVOKED) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_GC, out_error, out_safe);
            pcp->in_api = 0u;
            pcp_set_error(
                pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE,
                NINLIL_PCP_STAGE_GC, NINLIL_PCP_REASON_CORRUPT_FENCE,
                "gc_state");
            return NINLIL_PCP_CORRUPT_FENCE;
        }
        (void)pcp_iss_key_build(pcp->key_scratch, seq);
        key.data = pcp->key_scratch;
        key.length = (uint32_t)NINLIL_PCP_ISS_KEY_BYTES;
        est = pcp->storage_ops.erase(pcp->storage_ops.user, txn, key);
        em = pcp_map_erase(est);
        if (est != NINLIL_STORAGE_OK && est != NINLIL_STORAGE_NOT_FOUND) {
            pcp_apply_map_fence(pcp, &em);
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_GC, out_error, out_safe);
            pcp->in_api = 0u;
            pcp_set_error(
                pcp, out_error, out_safe, em.status, NINLIL_PCP_STAGE_GC,
                em.reason, "erase");
            return em.status;
        }
        erased += 1u;
    }

    /* meta counters MUST NOT change */
    st = pcp_txn_put_meta(
        pcp, txn, &meta, NINLIL_PCP_STAGE_GC, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_GC, out_error, out_safe);
        pcp->in_api = 0u;
        return st;
    }
    st = pcp_commit_full(
        pcp, txn, NINLIL_PCP_STAGE_GC, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        pcp->in_api = 0u;
        return st;
    }
    {
        uint32_t e;
        for (e = 0u; e < erased; ++e) {
            pcp_sat_inc(&pcp->stats.gc_erased);
        }
    }
    pcp->in_api = 0u;
    pcp_set_error(
        pcp, out_error, out_safe, NINLIL_PCP_OK, NINLIL_PCP_STAGE_GC,
        NINLIL_PCP_REASON_NONE, NULL);
    return NINLIL_PCP_OK;
}

/* ---- Algorithm E helpers + issue ---- */

static ninlil_pcp_status_t pcp_algorithm_e_body(
    ninlil_pcp_t *pcp,
    const ninlil_time_sample_t *s,
    const pcp_meta_t *m_snap,
    ninlil_pcp_error_t *out_error,
    int out_safe)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_pcp_status_t st;
    pcp_scan_t scan;
    pcp_meta_t m_live;

    st = pcp_begin(
        pcp, NINLIL_STORAGE_READ_WRITE, &txn, NINLIL_PCP_STAGE_ISSUE, out_error,
        out_safe);
    if (st != NINLIL_PCP_OK) {
        return st;
    }
    /* every RW begin: full namespace I1–I14 + body verify */
    st = pcp_rw_scan_check(
        pcp, txn, &scan, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
        return st;
    }
    m_live = scan.meta;
    if (m_live.next_issue_seq != m_snap->next_issue_seq
        || m_live.last_consumed_seq != m_snap->last_consumed_seq
        || m_live.outstanding_count != m_snap->outstanding_count
        || m_live.fence_bits != m_snap->fence_bits
        || !pcp_id_equal(
            m_live.last_trusted_epoch_id, m_snap->last_trusted_epoch_id, 16u)) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
        pcp_set_fence_corrupt(pcp);
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_CORRUPT_FENCE,
            NINLIL_PCP_STAGE_ISSUE, NINLIL_PCP_REASON_CONTRACT, "e_snap");
        return NINLIL_PCP_CORRUPT_FENCE;
    }

    while (m_live.outstanding_count > 0u) {
        uint64_t head = m_live.last_consumed_seq + 1u;
        pcp_issued_t iss;
        int nf = 0;
        st = pcp_txn_get_iss(
            pcp, txn, head, &iss, &nf, NINLIL_PCP_STAGE_ISSUE, out_error,
            out_safe);
        if (st != NINLIL_PCP_OK || nf != 0
            || iss.state != PCP_ISS_STATE_ISSUED) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
            pcp_set_fence_corrupt(pcp);
            return NINLIL_PCP_CORRUPT_FENCE;
        }
        iss.state = PCP_ISS_STATE_REVOKED;
        st = pcp_txn_put_iss(
            pcp, txn, &iss, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
        if (st != NINLIL_PCP_OK) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
            return st;
        }
        m_live.outstanding_count -= 1u;
        m_live.last_consumed_seq = head;
    }
    (void)memcpy(
        m_live.last_trusted_epoch_id, s->clock_epoch_id.bytes, 16u);
    m_live.last_trusted_now_ms = s->now_ms;
    st = pcp_txn_put_meta(
        pcp, txn, &m_live, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
        return st;
    }
    st = pcp_commit_full(
        pcp, txn, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
    if (st == NINLIL_PCP_COMMIT_UNKNOWN) {
        /* U0 sticky fence attempt once */
        ninlil_storage_txn_t tf = NULL;
        pcp_meta_t mf;
        ninlil_pcp_status_t st2;
        pcp_clear_ram_validate(pcp);
        st2 = pcp_begin(
            pcp, NINLIL_STORAGE_READ_WRITE, &tf, NINLIL_PCP_STAGE_ISSUE,
            out_error, out_safe);
        if (st2 == NINLIL_PCP_OK) {
            pcp_scan_t scan_f;
            /* sticky fence RW begin still evaluates I* when possible */
            st2 = pcp_rw_scan_check(
                pcp, tf, &scan_f, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
            if (st2 == NINLIL_PCP_OK) {
                mf = scan_f.meta;
                mf.fence_bits =
                    (uint8_t)(mf.fence_bits | (uint8_t)NINLIL_PCP_FENCE_BIT_STORAGE);
                if ((mf.fence_bits & NINLIL_PCP_FENCE_BIT_CORRUPT) == 0u) {
                    mf.fence_code = NINLIL_PCP_FC_STORAGE;
                }
                if (pcp_txn_put_meta(
                        pcp, tf, &mf, NINLIL_PCP_STAGE_ISSUE, out_error,
                        out_safe)
                    == NINLIL_PCP_OK) {
                    (void)pcp_commit_full(
                        pcp, tf, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
                } else {
                    (void)pcp_rollback_map(
                        pcp, tf, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
                }
            } else if (tf != NULL) {
                (void)pcp_rollback_map(
                    pcp, tf, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
            }
        }
        return NINLIL_PCP_COMMIT_UNKNOWN;
    }
    if (st != NINLIL_PCP_OK) {
        return st;
    }
    pcp->outstanding_count_cache = 0u;
    pcp->last_consumed_seq_cache = m_live.last_consumed_seq;
    pcp->next_issue_seq_cache = m_live.next_issue_seq;
    pcp_set_ram_trust(pcp, s->clock_epoch_id.bytes, s->now_ms);
    pcp_clear_ram_validate(pcp);
    return NINLIL_PCP_OK;
}

ninlil_pcp_status_t ninlil_pcp_issue(
    ninlil_pcp_t *pcp,
    const ninlil_pcp_issue_request_t *request,
    ninlil_radio_hal_permit_snapshot_t *out_snapshot,
    ninlil_pcp_error_t *out_error)
{
    int out_safe = 1;
    ninlil_pcp_status_t st;
    pcp_clk_result_t clk;
    ninlil_storage_txn_t txn = NULL;
    pcp_meta_t meta;
    pcp_scan_t scan;
    pcp_issued_t iss;
    int absent = 0;
    int new_epoch = 0;
    pcp_meta_t m_snap;

    if (out_snapshot != NULL) {
        (void)memset(out_snapshot, 0, sizeof(*out_snapshot));
    }
    if (!pcp_guard_active(pcp, out_error, &out_safe, NINLIL_PCP_STAGE_ISSUE)) {
        return pcp != NULL ? pcp->last_error.status : NINLIL_PCP_INVALID_ARGUMENT;
    }
    if (request == NULL || out_snapshot == NULL) {
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_INVALID_ARGUMENT,
            NINLIL_PCP_STAGE_ISSUE, NINLIL_PCP_REASON_NULL_ARG, "null");
        return NINLIL_PCP_INVALID_ARGUMENT;
    }
    if (pcp->storage_bound == 0u) {
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_UNBOUND_STORAGE,
            NINLIL_PCP_STAGE_ISSUE, NINLIL_PCP_REASON_UNBOUND_STORAGE,
            "storage");
        return NINLIL_PCP_UNBOUND_STORAGE;
    }
    if (pcp->clock_bound == 0u) {
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_UNBOUND_CLOCK,
            NINLIL_PCP_STAGE_ISSUE, NINLIL_PCP_REASON_UNBOUND_CLOCK, "clock");
        return NINLIL_PCP_UNBOUND_CLOCK;
    }
    if (pcp->live_bound == 0u || pcp->published == 0u) {
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_UNBOUND_ASSIGNMENT,
            NINLIL_PCP_STAGE_ISSUE, NINLIL_PCP_REASON_UNBOUND_ASSIGNMENT,
            "live");
        return NINLIL_PCP_UNBOUND_ASSIGNMENT;
    }
    if ((pcp->fence_bits
            & (NINLIL_PCP_FENCE_BIT_STORAGE | NINLIL_PCP_FENCE_BIT_CLOCK
                | NINLIL_PCP_FENCE_BIT_CORRUPT))
        != 0u) {
        ninlil_pcp_status_t fs = NINLIL_PCP_STORAGE_FENCE;
        ninlil_pcp_reason_t fr = NINLIL_PCP_REASON_STORAGE_FENCE;
        if ((pcp->fence_bits & NINLIL_PCP_FENCE_BIT_CORRUPT) != 0u) {
            fs = NINLIL_PCP_CORRUPT_FENCE;
            fr = NINLIL_PCP_REASON_CORRUPT_FENCE;
        } else if ((pcp->fence_bits & NINLIL_PCP_FENCE_BIT_CLOCK) != 0u) {
            fs = NINLIL_PCP_CLOCK_FAULT;
            fr = NINLIL_PCP_REASON_CLOCK_FAULT;
        }
        pcp_sat_inc(&pcp->stats.issue_deny);
        pcp_set_error(
            pcp, out_error, out_safe, fs, NINLIL_PCP_STAGE_ISSUE, fr, "fence");
        return fs;
    }

    pcp->in_api = 1u;
    st = pcp_ensure_open(pcp, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        pcp_sat_inc(&pcp->stats.issue_deny);
        pcp->in_api = 0u;
        return st;
    }

    /* I1 sample once */
    clk = pcp_sample_clock(pcp);
    if (clk.klass == PCP_CLK_TEMP || clk.klass == PCP_CLK_OK_UNCERTAIN) {
        pcp_sat_inc(&pcp->stats.issue_deny);
        pcp->in_api = 0u;
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_CLOCK_UNCERTAIN,
            NINLIL_PCP_STAGE_ISSUE, NINLIL_PCP_REASON_CLOCK_UNCERTAIN,
            "uncertain");
        return NINLIL_PCP_CLOCK_UNCERTAIN;
    }
    if (clk.klass != PCP_CLK_OK_TRUSTED) {
        pcp_apply_clock_fault_fence(pcp, clk.klass);
        pcp_sat_inc(&pcp->stats.issue_deny);
        pcp->in_api = 0u;
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_CLOCK_FAULT,
            NINLIL_PCP_STAGE_ISSUE, NINLIL_PCP_REASON_CLOCK_FAULT, "fault");
        return NINLIL_PCP_CLOCK_FAULT;
    }

    /* I2–I4 RO snapshot for E */
    st = pcp_begin(
        pcp, NINLIL_STORAGE_READ_ONLY, &txn, NINLIL_PCP_STAGE_ISSUE, out_error,
        out_safe);
    if (st != NINLIL_PCP_OK) {
        pcp_sat_inc(&pcp->stats.issue_deny);
        pcp->in_api = 0u;
        return st;
    }
    st = pcp_txn_get_meta(
        pcp, txn, &m_snap, &absent, NINLIL_PCP_STAGE_ISSUE, out_error,
        out_safe);
    if (st != NINLIL_PCP_OK || absent != 0) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
        pcp_sat_inc(&pcp->stats.issue_deny);
        pcp->in_api = 0u;
        if (st != NINLIL_PCP_OK) {
            return st;
        }
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_INVALID_STATE,
            NINLIL_PCP_STAGE_ISSUE, NINLIL_PCP_REASON_INVALID_STATE,
            "not_pub");
        return NINLIL_PCP_INVALID_STATE;
    }
    st = pcp_rollback_map(
        pcp, txn, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
    txn = NULL;
    if (st != NINLIL_PCP_OK) {
        pcp_sat_inc(&pcp->stats.issue_deny);
        pcp->in_api = 0u;
        return st;
    }

    if ((m_snap.fence_bits & (uint8_t)NINLIL_PCP_FENCE_BIT_CLOCK) != 0u) {
        pcp_sat_inc(&pcp->stats.issue_deny);
        pcp->in_api = 0u;
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_CLOCK_FAULT,
            NINLIL_PCP_STAGE_ISSUE, NINLIL_PCP_REASON_CLOCK_FAULT,
            "clock_fence");
        return NINLIL_PCP_CLOCK_FAULT;
    }

    new_epoch = !pcp_id_equal(
        clk.sample.clock_epoch_id.bytes, m_snap.last_trusted_epoch_id, 16u);
    if (new_epoch != 0) {
        st = pcp_algorithm_e_body(
            pcp, &clk.sample, &m_snap, out_error, out_safe);
        if (st != NINLIL_PCP_OK) {
            pcp_sat_inc(&pcp->stats.issue_deny);
            pcp->in_api = 0u;
            return st;
        }
    }

    /* Structural request */
    if (request->reserved_zero != 0u
        || request->expiry_ms <= request->not_before_ms
        || (request->expiry_ms - request->not_before_ms)
            > NINLIL_PCP_MAX_PERMIT_TTL_MS
        || request->max_airtime_us == 0u) {
        pcp_sat_inc(&pcp->stats.issue_deny);
        pcp->in_api = 0u;
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_STRUCT,
            NINLIL_PCP_STAGE_ISSUE, NINLIL_PCP_REASON_STRUCT_INVALID,
            "struct");
        return NINLIL_PCP_STRUCT;
    }
    if (request->expiry_ms <= clk.sample.now_ms) {
        pcp_sat_inc(&pcp->stats.issue_deny);
        pcp->in_api = 0u;
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_INVALID_ARGUMENT,
            NINLIL_PCP_STAGE_ISSUE, NINLIL_PCP_REASON_EXPIRED, "closed_window");
        return NINLIL_PCP_INVALID_ARGUMENT;
    }

    /* Issue put txn */
    st = pcp_begin(
        pcp, NINLIL_STORAGE_READ_WRITE, &txn, NINLIL_PCP_STAGE_ISSUE, out_error,
        out_safe);
    if (st != NINLIL_PCP_OK) {
        pcp_sat_inc(&pcp->stats.issue_deny);
        pcp->in_api = 0u;
        return st;
    }
    st = pcp_rw_scan_check(
        pcp, txn, &scan, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
        pcp_sat_inc(&pcp->stats.issue_deny);
        pcp->in_api = 0u;
        return st;
    }
    meta = scan.meta;
    if ((meta.fence_bits
            & (uint8_t)(NINLIL_PCP_FENCE_BIT_STORAGE
                | NINLIL_PCP_FENCE_BIT_CLOCK
                | NINLIL_PCP_FENCE_BIT_CORRUPT))
        != 0u) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
        pcp_sat_inc(&pcp->stats.issue_deny);
        pcp->in_api = 0u;
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_STORAGE_FENCE,
            NINLIL_PCP_STAGE_ISSUE, NINLIL_PCP_REASON_STORAGE_FENCE, "fence");
        return NINLIL_PCP_STORAGE_FENCE;
    }
    if (!pcp_lcore_equal_meta_req(&meta, request)) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
        pcp_sat_inc(&pcp->stats.issue_deny);
        pcp->in_api = 0u;
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_PROFILE_MISMATCH,
            NINLIL_PCP_STAGE_ISSUE, NINLIL_PCP_REASON_PROFILE_MISMATCH,
            "lcore");
        return NINLIL_PCP_PROFILE_MISMATCH;
    }
    if (request->max_airtime_us > meta.bound_max_airtime_ceiling_us) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
        pcp_sat_inc(&pcp->stats.issue_deny);
        pcp->in_api = 0u;
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_PROFILE_MISMATCH,
            NINLIL_PCP_STAGE_ISSUE, NINLIL_PCP_REASON_PROFILE_MISMATCH,
            "airtime");
        return NINLIL_PCP_PROFILE_MISMATCH;
    }
    if (meta.outstanding_count >= NINLIL_PCP_MAX_OUTSTANDING) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
        pcp_sat_inc(&pcp->stats.issue_deny);
        pcp->in_api = 0u;
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_CAPACITY,
            NINLIL_PCP_STAGE_ISSUE, NINLIL_PCP_REASON_CAPACITY, "cap");
        return NINLIL_PCP_CAPACITY;
    }
    if (meta.next_issue_seq >= UINT64_MAX) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
        pcp_sat_inc(&pcp->stats.issue_deny);
        pcp->in_api = 0u;
        pcp_set_error(
            pcp, out_error, out_safe, NINLIL_PCP_SEQ_EXHAUSTED,
            NINLIL_PCP_STAGE_ISSUE, NINLIL_PCP_REASON_SEQ_EXHAUSTED, "seq");
        return NINLIL_PCP_SEQ_EXHAUSTED;
    }

    (void)memset(&iss, 0, sizeof(iss));
    iss.magic = NINLIL_PCP_MAGIC;
    iss.schema = NINLIL_PCP_SCHEMA_VERSION;
    iss.state = PCP_ISS_STATE_ISSUED;
    iss.flags = 0u;
    iss.permit_sequence = meta.next_issue_seq;
    (void)memcpy(
        iss.clock_epoch_id, clk.sample.clock_epoch_id.bytes, 16u);
    iss.not_before_ms = request->not_before_ms;
    iss.expiry_ms = request->expiry_ms;
    iss.hardware_profile_id = request->hardware_profile_id;
    iss.hardware_profile_rev = request->hardware_profile_rev;
    iss.regulatory_profile_id = request->regulatory_profile_id;
    iss.regulatory_profile_rev = request->regulatory_profile_rev;
    iss.site_assignment_id = request->site_assignment_id;
    iss.site_assignment_rev = request->site_assignment_rev;
    iss.site_assignment_epoch = request->site_assignment_epoch;
    iss.transmitter_id = request->transmitter_id;
    iss.channel_id = request->channel_id;
    iss.phy = request->phy;
    (void)memcpy(iss.frame_digest, request->frame_digest, 32u);
    iss.frame_digest_algorithm = request->frame_digest_algorithm;
    iss.frame_byte_length = request->frame_byte_length;
    iss.max_airtime_us = request->max_airtime_us;
    (void)memcpy(
        iss.authority_instance_id, meta.authority_instance_id, 16u);
    iss.issue_generation = iss.permit_sequence;
    iss.reserved_zero = 0u;

    st = pcp_txn_put_iss(
        pcp, txn, &iss, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
        pcp_sat_inc(&pcp->stats.issue_deny);
        pcp->in_api = 0u;
        return st;
    }
    meta.next_issue_seq += 1u;
    meta.outstanding_count += 1u;
    (void)memcpy(
        meta.last_trusted_epoch_id, clk.sample.clock_epoch_id.bytes, 16u);
    meta.last_trusted_now_ms = clk.sample.now_ms;
    st = pcp_txn_put_meta(
        pcp, txn, &meta, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
        pcp_sat_inc(&pcp->stats.issue_deny);
        pcp->in_api = 0u;
        return st;
    }
    st = pcp_commit_full(
        pcp, txn, NINLIL_PCP_STAGE_ISSUE, out_error, out_safe);
    if (st != NINLIL_PCP_OK) {
        pcp_sat_inc(&pcp->stats.issue_deny);
        pcp->in_api = 0u;
        return st;
    }

    pcp->next_issue_seq_cache = meta.next_issue_seq;
    pcp->outstanding_count_cache = meta.outstanding_count;
    pcp_set_ram_trust(
        pcp, clk.sample.clock_epoch_id.bytes, clk.sample.now_ms);
    pcp_fill_snapshot_from_iss(out_snapshot, &iss);
    pcp_sat_inc(&pcp->stats.issue_ok);
    pcp->in_api = 0u;
    pcp_set_error(
        pcp, out_error, out_safe, NINLIL_PCP_OK, NINLIL_PCP_STAGE_ISSUE,
        NINLIL_PCP_REASON_NONE, NULL);
    return NINLIL_PCP_OK;
}

/* ---- R1 validate / consume ---- */

ninlil_radio_hal_status_t ninlil_pcp_validate(
    void *ctx,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    const ninlil_radio_hal_frame_view_t *frame,
    ninlil_radio_hal_error_t *out_error)
{
    ninlil_pcp_t *pcp = (ninlil_pcp_t *)ctx;
    int out_safe = 1;
    ninlil_pcp_status_t st;
    pcp_clk_result_t clk;
    ninlil_storage_txn_t txn = NULL;
    pcp_meta_t meta;
    pcp_issued_t iss;
    int absent = 0;

    (void)frame;
    if (pcp == NULL || permit == NULL) {
        pcp_set_hal_error(
            out_error, 1, NINLIL_RADIO_HAL_PERMIT_ERROR,
            NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
            NINLIL_RADIO_HAL_REASON_NULL_ARG, "pcp_struct");
        return NINLIL_RADIO_HAL_PERMIT_ERROR;
    }
    if (out_error != NULL
        && pcp_ranges_overlap(
            pcp, sizeof(*pcp), out_error, sizeof(*out_error))) {
        out_safe = 0;
        pcp_sat_inc(&pcp->stats.alias_reject);
    }
    if (pcp->magic != NINLIL_PCP_MAGIC_VALUE
        || pcp->lifecycle != NINLIL_PCP_LC_ACTIVE) {
        pcp_sat_inc(&pcp->stats.validate_error);
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_PERMIT_ERROR,
            NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
            NINLIL_RADIO_HAL_REASON_SHUTDOWN, "pcp_fence");
        return NINLIL_RADIO_HAL_PERMIT_ERROR;
    }
    if (pcp->in_api != 0u) {
        pcp_sat_inc(&pcp->stats.reentry_reject);
        pcp_sat_inc(&pcp->stats.validate_error);
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_BUSY,
            NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
            NINLIL_RADIO_HAL_REASON_REENTRANT, "pcp_busy");
        return NINLIL_RADIO_HAL_BUSY;
    }
    if (pcp->storage_bound == 0u || pcp->clock_bound == 0u
        || pcp->published == 0u
        || (pcp->fence_bits
            & (NINLIL_PCP_FENCE_BIT_STORAGE | NINLIL_PCP_FENCE_BIT_CLOCK
                | NINLIL_PCP_FENCE_BIT_CORRUPT))
            != 0u) {
        pcp_sat_inc(&pcp->stats.validate_error);
        pcp_clear_ram_validate(pcp);
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_PERMIT_ERROR,
            NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
            NINLIL_RADIO_HAL_REASON_UNBOUND_PERMIT, "pcp_fence");
        return NINLIL_RADIO_HAL_PERMIT_ERROR;
    }

    pcp->in_api = 1u;
    st = pcp_ensure_open(
        pcp, NINLIL_PCP_STAGE_VALIDATE, NULL, 0);
    if (st != NINLIL_PCP_OK) {
        pcp_sat_inc(&pcp->stats.validate_error);
        pcp_clear_ram_validate(pcp);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_PERMIT_ERROR,
            NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
            NINLIL_RADIO_HAL_REASON_VALIDATOR_ERROR, "pcp_storage");
        return NINLIL_RADIO_HAL_PERMIT_ERROR;
    }

    clk = pcp_sample_clock(pcp);
    if (clk.klass == PCP_CLK_TEMP || clk.klass == PCP_CLK_OK_UNCERTAIN) {
        pcp_sat_inc(&pcp->stats.validate_deny);
        pcp_clear_ram_validate(pcp);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_PERMIT_DENIED,
            NINLIL_RADIO_HAL_STAGE_TIME,
            NINLIL_RADIO_HAL_REASON_VALIDATOR_DENY, "pcp_clock_uncertain");
        return NINLIL_RADIO_HAL_PERMIT_DENIED;
    }
    if (clk.klass != PCP_CLK_OK_TRUSTED) {
        pcp_apply_clock_fault_fence(pcp, clk.klass);
        pcp_sat_inc(&pcp->stats.validate_error);
        pcp_clear_ram_validate(pcp);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_PERMIT_ERROR,
            NINLIL_RADIO_HAL_STAGE_TIME,
            NINLIL_RADIO_HAL_REASON_VALIDATOR_ERROR, "pcp_clock_fault");
        return NINLIL_RADIO_HAL_PERMIT_ERROR;
    }

    if (permit->permit_sequence == 0u || permit->reserved_zero != 0u) {
        pcp_sat_inc(&pcp->stats.validate_error);
        pcp_clear_ram_validate(pcp);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_PERMIT_ERROR,
            NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
            NINLIL_RADIO_HAL_REASON_STRUCT_INVALID, "pcp_struct");
        return NINLIL_RADIO_HAL_PERMIT_ERROR;
    }

    st = pcp_begin(
        pcp, NINLIL_STORAGE_READ_ONLY, &txn, NINLIL_PCP_STAGE_VALIDATE, NULL,
        0);
    if (st != NINLIL_PCP_OK) {
        pcp_sat_inc(&pcp->stats.validate_error);
        pcp_clear_ram_validate(pcp);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_PERMIT_ERROR,
            NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
            NINLIL_RADIO_HAL_REASON_VALIDATOR_ERROR, "pcp_storage");
        return NINLIL_RADIO_HAL_PERMIT_ERROR;
    }
    st = pcp_txn_get_meta(
        pcp, txn, &meta, &absent, NINLIL_PCP_STAGE_VALIDATE, NULL, 0);
    if (st != NINLIL_PCP_OK || absent != 0) {
        (void)pcp->storage_ops.rollback(pcp->storage_ops.user, txn);
        pcp_sat_inc(&pcp->stats.validate_error);
        pcp_clear_ram_validate(pcp);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_PERMIT_ERROR,
            NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
            NINLIL_RADIO_HAL_REASON_VALIDATOR_ERROR, "pcp_storage");
        return NINLIL_RADIO_HAL_PERMIT_ERROR;
    }
    st = pcp_txn_get_iss(
        pcp, txn, permit->permit_sequence, &iss, &absent,
        NINLIL_PCP_STAGE_VALIDATE, NULL, 0);
    if (st != NINLIL_PCP_OK) {
        (void)pcp->storage_ops.rollback(pcp->storage_ops.user, txn);
        pcp_sat_inc(&pcp->stats.validate_error);
        pcp_clear_ram_validate(pcp);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_PERMIT_ERROR,
            NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
            NINLIL_RADIO_HAL_REASON_VALIDATOR_ERROR, "pcp_storage");
        return NINLIL_RADIO_HAL_PERMIT_ERROR;
    }
    if (absent != 0) {
        (void)pcp->storage_ops.rollback(pcp->storage_ops.user, txn);
        pcp_sat_inc(&pcp->stats.validate_deny);
        pcp_clear_ram_validate(pcp);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_PERMIT_DENIED,
            NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
            NINLIL_RADIO_HAL_REASON_VALIDATOR_DENY, "pcp_deny");
        return NINLIL_RADIO_HAL_PERMIT_DENIED;
    }
    if (iss.state != PCP_ISS_STATE_ISSUED
        || !pcp_snapshot_matches_iss(permit, &iss)
        || !pcp_lcore_equal_iss_meta(&iss, &meta)
        || !pcp_id_equal(
            iss.authority_instance_id, meta.authority_instance_id, 16u)) {
        (void)pcp->storage_ops.rollback(pcp->storage_ops.user, txn);
        pcp_sat_inc(&pcp->stats.validate_deny);
        pcp_clear_ram_validate(pcp);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_PERMIT_DENIED,
            NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
            NINLIL_RADIO_HAL_REASON_VALIDATOR_DENY, "pcp_deny");
        return NINLIL_RADIO_HAL_PERMIT_DENIED;
    }
    if (!pcp_id_equal(
            clk.sample.clock_epoch_id.bytes, iss.clock_epoch_id, 16u)) {
        (void)pcp->storage_ops.rollback(pcp->storage_ops.user, txn);
        pcp_sat_inc(&pcp->stats.validate_deny);
        pcp_clear_ram_validate(pcp);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_PERMIT_DENIED,
            NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
            NINLIL_RADIO_HAL_REASON_VALIDATOR_DENY, "pcp_deny");
        return NINLIL_RADIO_HAL_PERMIT_DENIED;
    }
    if (clk.sample.now_ms < iss.not_before_ms) {
        (void)pcp->storage_ops.rollback(pcp->storage_ops.user, txn);
        pcp_sat_inc(&pcp->stats.validate_deny);
        pcp_clear_ram_validate(pcp);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_NOT_BEFORE,
            NINLIL_RADIO_HAL_STAGE_TIME, NINLIL_RADIO_HAL_REASON_NOT_BEFORE,
            "pcp_not_before");
        return NINLIL_RADIO_HAL_NOT_BEFORE;
    }
    if (pcp_expired_time(&clk.sample, &iss)) {
        (void)pcp->storage_ops.rollback(pcp->storage_ops.user, txn);
        pcp_sat_inc(&pcp->stats.validate_deny);
        pcp_clear_ram_validate(pcp);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_EXPIRED,
            NINLIL_RADIO_HAL_STAGE_TIME, NINLIL_RADIO_HAL_REASON_EXPIRED,
            "pcp_expired");
        return NINLIL_RADIO_HAL_EXPIRED;
    }
    if (!pcp_valid_time(&clk.sample, &iss)) {
        (void)pcp->storage_ops.rollback(pcp->storage_ops.user, txn);
        pcp_sat_inc(&pcp->stats.validate_deny);
        pcp_clear_ram_validate(pcp);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_PERMIT_DENIED,
            NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
            NINLIL_RADIO_HAL_REASON_VALIDATOR_DENY, "pcp_deny");
        return NINLIL_RADIO_HAL_PERMIT_DENIED;
    }

    {
        ninlil_storage_status_t rst =
            pcp->storage_ops.rollback(pcp->storage_ops.user, txn);
        if (rst != NINLIL_STORAGE_OK) {
            pcp_set_fence_storage(pcp);
            pcp_sat_inc(&pcp->stats.validate_error);
            pcp_clear_ram_validate(pcp);
            pcp->in_api = 0u;
            pcp_set_hal_error(
                out_error, out_safe, NINLIL_RADIO_HAL_PERMIT_ERROR,
                NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
                NINLIL_RADIO_HAL_REASON_VALIDATOR_ERROR, "pcp_storage");
            return NINLIL_RADIO_HAL_PERMIT_ERROR;
        }
    }

    /* Set ram_validate bind */
    pcp->ram_validate.valid = 1u;
    pcp->ram_validate.reserved_zero = 0u;
    pcp->ram_validate.permit_sequence = iss.permit_sequence;
    (void)memcpy(
        pcp->ram_validate.frame_digest, iss.frame_digest, 32u);
    (void)memcpy(
        pcp->ram_validate.clock_epoch_id, clk.sample.clock_epoch_id.bytes,
        16u);
    pcp->ram_validate.now_ms = clk.sample.now_ms;
    pcp_sat_inc(&pcp->stats.validate_ok);
    pcp->in_api = 0u;
    /* success: out_error call-entry unchanged */
    return NINLIL_RADIO_HAL_OK;
}

ninlil_radio_hal_status_t ninlil_pcp_consume(
    void *ctx,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    const ninlil_radio_hal_frame_view_t *frame,
    ninlil_radio_hal_error_t *out_error)
{
    ninlil_pcp_t *pcp = (ninlil_pcp_t *)ctx;
    int out_safe = 1;
    ninlil_pcp_status_t st;
    pcp_clk_result_t clk;
    ninlil_storage_txn_t txn = NULL;
    pcp_meta_t meta;
    pcp_issued_t iss;
    int absent = 0;
    uint64_t seq;

    (void)frame;
    if (pcp == NULL || permit == NULL) {
        pcp_set_hal_error(
            out_error, 1, NINLIL_RADIO_HAL_CONSUME_ERROR,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_NULL_ARG, "pcp_struct");
        return NINLIL_RADIO_HAL_CONSUME_ERROR;
    }
    if (out_error != NULL
        && pcp_ranges_overlap(
            pcp, sizeof(*pcp), out_error, sizeof(*out_error))) {
        out_safe = 0;
        pcp_sat_inc(&pcp->stats.alias_reject);
    }
    if (pcp->magic != NINLIL_PCP_MAGIC_VALUE
        || pcp->lifecycle != NINLIL_PCP_LC_ACTIVE) {
        pcp_sat_inc(&pcp->stats.consume_error);
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_ERROR,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_SHUTDOWN, "pcp_storage");
        return NINLIL_RADIO_HAL_CONSUME_ERROR;
    }
    if (pcp->in_api != 0u) {
        pcp_sat_inc(&pcp->stats.reentry_reject);
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_BUSY,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_REENTRANT, "pcp_busy");
        return NINLIL_RADIO_HAL_BUSY;
    }
    if (pcp->storage_bound == 0u || pcp->clock_bound == 0u
        || pcp->published == 0u) {
        pcp_sat_inc(&pcp->stats.consume_error);
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_ERROR,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_CONSUME_ERROR, "pcp_storage");
        return NINLIL_RADIO_HAL_CONSUME_ERROR;
    }
    /* RAM fence (CORRUPT > STORAGE > CLOCK): fail-closed before any storage. */
    {
        ninlil_radio_hal_status_t fhs;
        ninlil_radio_hal_stage_t fstage;
        ninlil_radio_hal_reason_t freason;
        const char *fhint;

        if (pcp_consume_fence_reject(
                pcp->fence_bits, &fhs, &fstage, &freason, &fhint)
            != 0) {
            if (fhs == NINLIL_RADIO_HAL_CONSUME_ERROR) {
                pcp_sat_inc(&pcp->stats.consume_error);
            } else {
                pcp_sat_inc(&pcp->stats.consume_fenced);
            }
            pcp_set_hal_error(
                out_error, out_safe, fhs, fstage, freason, fhint);
            return fhs;
        }
    }

    pcp->in_api = 1u;
    st = pcp_ensure_open(pcp, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
    if (st != NINLIL_PCP_OK) {
        pcp_sat_inc(&pcp->stats.consume_error);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_ERROR,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_CONSUME_ERROR, "pcp_storage");
        return NINLIL_RADIO_HAL_CONSUME_ERROR;
    }

    clk = pcp_sample_clock(pcp);
    if (clk.klass == PCP_CLK_TEMP || clk.klass == PCP_CLK_OK_UNCERTAIN) {
        pcp_sat_inc(&pcp->stats.consume_denied);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_DENIED,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_CONSUME_UNCONSUMED, "pcp_retry");
        return NINLIL_RADIO_HAL_CONSUME_DENIED;
    }
    if (clk.klass != PCP_CLK_OK_TRUSTED) {
        pcp_apply_clock_fault_fence(pcp, clk.klass);
        pcp_sat_inc(&pcp->stats.consume_fenced);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_FENCED,
            NINLIL_RADIO_HAL_STAGE_TIME,
            NINLIL_RADIO_HAL_REASON_CONSUME_FENCED, "pcp_clock_fault");
        return NINLIL_RADIO_HAL_CONSUME_FENCED;
    }

    /* rollback check vs ram_validate */
    if (pcp->ram_validate.valid != 0u
        && permit->permit_sequence == pcp->ram_validate.permit_sequence
        && memcmp(
            permit->frame_digest, pcp->ram_validate.frame_digest, 32u)
            == 0
        && pcp_id_equal(
            clk.sample.clock_epoch_id.bytes, pcp->ram_validate.clock_epoch_id,
            16u)
        && clk.sample.now_ms < pcp->ram_validate.now_ms) {
        pcp_apply_clock_fault_fence(pcp, PCP_CLK_FAULT_REGRESSION);
        pcp_sat_inc(&pcp->stats.consume_fenced);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_FENCED,
            NINLIL_RADIO_HAL_STAGE_TIME,
            NINLIL_RADIO_HAL_REASON_CONSUME_FENCED, "pcp_clock_fault");
        return NINLIL_RADIO_HAL_CONSUME_FENCED;
    }

    seq = permit->permit_sequence;
    st = pcp_begin(
        pcp, NINLIL_STORAGE_READ_WRITE, &txn, NINLIL_PCP_STAGE_CONSUME, NULL,
        0);
    if (st != NINLIL_PCP_OK) {
        if (st == NINLIL_PCP_BUSY) {
            pcp_sat_inc(&pcp->stats.consume_denied);
            pcp->in_api = 0u;
            pcp_set_hal_error(
                out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_DENIED,
                NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
                NINLIL_RADIO_HAL_REASON_CONSUME_UNCONSUMED, "pcp_retry");
            return NINLIL_RADIO_HAL_CONSUME_DENIED;
        }
        pcp_sat_inc(&pcp->stats.consume_error);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_ERROR,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_CONSUME_ERROR, "pcp_storage");
        return NINLIL_RADIO_HAL_CONSUME_ERROR;
    }

    /* §4.5 step3: begin RW then I1–I14 full scan + body semantics */
    {
        pcp_scan_t scan_c;

        st = pcp_rw_scan_check(
            pcp, txn, &scan_c, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
        if (st != NINLIL_PCP_OK) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
            pcp_sat_inc(&pcp->stats.consume_error);
            pcp->in_api = 0u;
            pcp_set_hal_error(
                out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_ERROR,
                NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
                NINLIL_RADIO_HAL_REASON_CONSUME_ERROR, "pcp_storage");
            return NINLIL_RADIO_HAL_CONSUME_ERROR;
        }
        meta = scan_c.meta;
        absent = 0;
    }

    /* Durable meta fence before put intent (sync into RAM). */
    {
        ninlil_radio_hal_status_t fhs;
        ninlil_radio_hal_stage_t fstage;
        ninlil_radio_hal_reason_t freason;
        const char *fhint;
        uint32_t durable = (uint32_t)meta.fence_bits;

        if (pcp_consume_fence_reject(
                durable, &fhs, &fstage, &freason, &fhint)
            != 0) {
            pcp->fence_bits |= durable;
            if ((durable & NINLIL_PCP_FENCE_BIT_CORRUPT) != 0u) {
                pcp->fence_code = NINLIL_PCP_FC_CORRUPT;
            } else if ((durable & NINLIL_PCP_FENCE_BIT_STORAGE) != 0u) {
                pcp->fence_code = NINLIL_PCP_FC_STORAGE;
            } else if ((durable & NINLIL_PCP_FENCE_BIT_CLOCK) != 0u) {
                pcp->fence_code = NINLIL_PCP_FC_CLOCK_PERM;
            }
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
            if (fhs == NINLIL_RADIO_HAL_CONSUME_ERROR) {
                pcp_sat_inc(&pcp->stats.consume_error);
            } else {
                pcp_sat_inc(&pcp->stats.consume_fenced);
            }
            pcp->in_api = 0u;
            pcp_set_hal_error(
                out_error, out_safe, fhs, fstage, freason, fhint);
            return fhs;
        }
    }

    /* classify seq */
    if (seq <= meta.last_consumed_seq) {
        st = pcp_txn_get_iss(
            pcp, txn, seq, &iss, &absent, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
        pcp_sat_inc(&pcp->stats.consume_fenced);
        pcp->in_api = 0u;
        if (st != NINLIL_PCP_OK) {
            pcp_set_hal_error(
                out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_ERROR,
                NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
                NINLIL_RADIO_HAL_REASON_CONSUME_ERROR, "pcp_storage");
            return NINLIL_RADIO_HAL_CONSUME_ERROR;
        }
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_FENCED,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_CONSUME_FENCED,
            absent != 0 ? "pcp_fabricated" : "pcp_terminal");
        return NINLIL_RADIO_HAL_CONSUME_FENCED;
    }

    if (seq != meta.last_consumed_seq + 1u) {
        st = pcp_txn_get_iss(
            pcp, txn, seq, &iss, &absent, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
        if (st != NINLIL_PCP_OK) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
            pcp_sat_inc(&pcp->stats.consume_error);
            pcp->in_api = 0u;
            pcp_set_hal_error(
                out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_ERROR,
                NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
                NINLIL_RADIO_HAL_REASON_CONSUME_ERROR, "pcp_storage");
            return NINLIL_RADIO_HAL_CONSUME_ERROR;
        }
        if (absent == 0 && iss.state == PCP_ISS_STATE_ISSUED
            && seq > meta.last_consumed_seq + 1u
            && seq < meta.next_issue_seq) {
            (void)pcp_rollback_map(
                pcp, txn, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
            pcp_sat_inc(&pcp->stats.consume_denied);
            pcp_sat_inc(&pcp->stats.fifo_out_of_order);
            pcp->in_api = 0u;
            pcp_set_hal_error(
                out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_DENIED,
                NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
                NINLIL_RADIO_HAL_REASON_CONSUME_UNCONSUMED, "pcp_ooo");
            return NINLIL_RADIO_HAL_CONSUME_DENIED;
        }
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
        pcp_sat_inc(&pcp->stats.consume_fenced);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_FENCED,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_CONSUME_FENCED, "pcp_fabricated");
        return NINLIL_RADIO_HAL_CONSUME_FENCED;
    }

    /* head */
    st = pcp_txn_get_iss(
        pcp, txn, seq, &iss, &absent, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
    if (st != NINLIL_PCP_OK || absent != 0
        || iss.state != PCP_ISS_STATE_ISSUED
        || !pcp_snapshot_matches_iss(permit, &iss)) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
        pcp_set_fence_corrupt(pcp);
        pcp_sat_inc(&pcp->stats.consume_error);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_ERROR,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_CONSUME_ERROR, "pcp_storage");
        return NINLIL_RADIO_HAL_CONSUME_ERROR;
    }

    if (clk.sample.now_ms < iss.not_before_ms) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
        pcp_sat_inc(&pcp->stats.consume_denied);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_DENIED,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_CONSUME_UNCONSUMED, "pcp_retry");
        return NINLIL_RADIO_HAL_CONSUME_DENIED;
    }
    if (pcp_expired_time(&clk.sample, &iss)) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
        pcp_sat_inc(&pcp->stats.consume_fenced);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_FENCED,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_CONSUME_FENCED, "pcp_expired_head");
        return NINLIL_RADIO_HAL_CONSUME_FENCED;
    }
    if (!pcp_valid_time(&clk.sample, &iss)) {
        (void)pcp_rollback_map(
            pcp, txn, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
        pcp_sat_inc(&pcp->stats.consume_denied);
        pcp->in_api = 0u;
        pcp_set_hal_error(
            out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_DENIED,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_CONSUME_UNCONSUMED, "pcp_retry");
        return NINLIL_RADIO_HAL_CONSUME_DENIED;
    }

    /* ---- post-put-intent zone: no CONSUME_DENIED except BUSY on put ---- */
    iss.state = PCP_ISS_STATE_CONSUMED;
    st = pcp_txn_put_iss(
        pcp, txn, &iss, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
    if (st != NINLIL_PCP_OK) {
        /* ISS put boundary (§7.5): COMMIT_UNKNOWN → FENCED; BUSY → DENIED */
        return pcp_consume_fail_after_put_intent(
            pcp, txn, 1, st, out_error, out_safe);
    }
    meta.outstanding_count -= 1u;
    meta.last_consumed_seq = seq;
    (void)memcpy(
        meta.last_trusted_epoch_id, clk.sample.clock_epoch_id.bytes, 16u);
    meta.last_trusted_now_ms = clk.sample.now_ms;
    st = pcp_txn_put_meta(
        pcp, txn, &meta, NINLIL_PCP_STAGE_CONSUME, NULL, 0);
    if (st != NINLIL_PCP_OK) {
        /* meta put boundary: same post-put classification (P1 audit) */
        return pcp_consume_fail_after_put_intent(
            pcp, txn, 1, st, out_error, out_safe);
    }
    /* commit boundary (§7.11): all statuses consume txn; UNKNOWN → FENCED */
    {
        ninlil_storage_status_t cst;
        pcp_map_t cm;

        cst = pcp->storage_ops.commit(
            pcp->storage_ops.user, txn, NINLIL_DURABILITY_FULL);
        txn = NULL; /* consumed for every status */
        if (cst == NINLIL_STORAGE_OK) {
            /* fall through to success */
        } else if (cst == NINLIL_STORAGE_COMMIT_UNKNOWN) {
            return pcp_consume_fail_after_put_intent(
                pcp, NULL, 0, NINLIL_PCP_COMMIT_UNKNOWN, out_error, out_safe);
        } else if (cst == NINLIL_STORAGE_BUSY) {
            /* BUSY on commit → F_s + CONSUME_ERROR (not FENCED, not DENIED) */
            pcp_set_fence_storage(pcp);
            pcp_sat_inc(&pcp->stats.consume_error);
            pcp_clear_ram_validate(pcp);
            pcp->in_api = 0u;
            pcp_set_hal_error(
                out_error, out_safe, NINLIL_RADIO_HAL_CONSUME_ERROR,
                NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
                NINLIL_RADIO_HAL_REASON_CONSUME_ERROR, "pcp_storage");
            return NINLIL_RADIO_HAL_CONSUME_ERROR;
        } else {
            cm = pcp_map_commit(cst);
            pcp_apply_map_fence(pcp, &cm);
            if (cm.status == NINLIL_PCP_COMMIT_UNKNOWN) {
                return pcp_consume_fail_after_put_intent(
                    pcp, NULL, 0, NINLIL_PCP_COMMIT_UNKNOWN, out_error,
                    out_safe);
            }
            return pcp_consume_fail_after_put_intent(
                pcp, NULL, 0, cm.status, out_error, out_safe);
        }
    }

    pcp->outstanding_count_cache = meta.outstanding_count;
    pcp->last_consumed_seq_cache = meta.last_consumed_seq;
    pcp_set_ram_trust(
        pcp, clk.sample.clock_epoch_id.bytes, clk.sample.now_ms);
    pcp_clear_ram_validate(pcp);
    pcp_sat_inc(&pcp->stats.consume_ok);
    pcp->in_api = 0u;
    return NINLIL_RADIO_HAL_OK;
}

void ninlil_pcp_permit_ops(ninlil_radio_hal_permit_ops_t *out_ops)
{
    if (out_ops == NULL) {
        return;
    }
    out_ops->validate = ninlil_pcp_validate;
    out_ops->consume = ninlil_pcp_consume;
}

void ninlil_pcp_stats(
    const ninlil_pcp_t *pcp,
    ninlil_pcp_r2_stats_t *out_stats)
{
    if (out_stats == NULL) {
        return;
    }
    if (pcp == NULL) {
        (void)memset(out_stats, 0, sizeof(*out_stats));
        return;
    }
    *out_stats = pcp->stats;
}

void ninlil_pcp_last_error(
    const ninlil_pcp_t *pcp,
    ninlil_pcp_error_t *out_error)
{
    if (out_error == NULL) {
        return;
    }
    if (pcp == NULL) {
        (void)memset(out_error, 0, sizeof(*out_error));
        return;
    }
    *out_error = pcp->last_error;
}
