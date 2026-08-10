/*
 * Independent C11 byte-contract gate for the Proposed Production Attachment
 * profile.  The generated fixture is data only; validation below does not use
 * the Python/Node gate or production codec.  No heap/VLA; no production crypto
 * or HIL claim.  Each required case records a distinct executed assertion.
 *
 * Architecture note: Python/Node primary machine authority is full closed-tree
 * equality against tools/production_attachment_edhoc_expected_model.py (spec
 * constants, exact layouts, preimage formulas; reason/note allowlisted only).
 * This C oracle is the independent wire/layout/preimage authority for the
 * fixture byte spans and executable adversarial mutations (TEST_ORACLE_ONLY).
 */

#include "production_attachment_edhoc_fixture.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum pa_class {
    PA_OK = 0,
    PA_CORRUPT = 1,
    PA_UNSUPPORTED = 2
};

/* Honest executable case ledger (not a mark-only tally). */
enum {
    PA_CASE_NAC1_SUITE2 = 0,
    PA_CASE_NAC1_SUITE3,
    PA_CASE_NAS1,
    PA_CASE_COOKIE_CURRENT,
    PA_CASE_COOKIE_PREVIOUS,
    PA_CASE_COOKIE_FOUR_MATRIX,
    PA_CASE_COOKIE_MUTATION,
    PA_CASE_COOKIE_2FRAG,
    PA_CASE_COOKIE_LEN_159,
    PA_CASE_PROTECTED_SEQ,
    PA_CASE_INSTALL_FRAG,
    PA_CASE_NAR_CANONICAL_SHAPE,
    PA_CASE_NAC_CRC,
    PA_CASE_NAC_RESERVED,
    PA_CASE_NAC_LENGTH,
    PA_CASE_NAC_SESSION,
    PA_CASE_NAC_BINDING,
    PA_CASE_NAR_CRC,
    PA_CASE_NAR_INDEX,
    PA_CASE_NAR_OFFSET,
    PA_CASE_NAR_DIGEST,
    PA_CASE_NAR_REORDER,
    PA_CASE_NAR_SESSION_DIV,
    PA_CASE_NAR_GENERATION,
    PA_CASE_NAR_MIXED,
    PA_CASE_CARRIER_PIN,
    PA_CASE_WIFI_MUT,
    PA_CASE_N6AT_CRC,
    PA_CASE_N6AT_RESERVED,
    PA_CASE_N6AT_ROLE,
    PA_CASE_N6AT_UNKNOWN,
    PA_CASE_N6AT_ROLE_BOTH,
    PA_CASE_NAB_15,
    PA_CASE_NAB_IDENTITY,
    PA_CASE_NAB_ORDER,
    PA_CASE_NAB_DUP,
    PA_CASE_NAB_REORDER_SUB,
    PA_CASE_NAB_CRC_COUNT,
    PA_CASE_N6AT_PENDING,
    PA_CASE_N6AT_P2A,
    PA_CASE_N6AT_COMMIT_UNKNOWN,
    PA_CASE_LIFECYCLE_GROUP,
    PA_CASE_PUBLICATION_ZERO,
    PA_CASE_CREDENTIAL_CCS,
    PA_CASE_CREDENTIAL_TAIL,
    PA_CASE_NAP_NAI_MISMATCH,
    PA_CASE_CREDENTIAL,
    PA_CASE_PROFILE,
    PA_CASE_PROPOSAL_FIELDS,
    PA_CASE_RFC_INDEP,
    PA_CASE_BYTE_SHA,
    PA_CASE_EXPORTER_LABELS,
    PA_CASE_EXPORTER_CTX,
    PA_CASE_NONCE,
    PA_CASE_RFC_REF,
    PA_CASE_REATTACH_15ROW,
    PA_CASE_REATTACH_LANE_OLD,
    PA_CASE_REATTACH_10K,
    PA_CASE_PREREQUISITES,
    PA_CASE_LOCAL_KEY_FAILURES,
    PA_CASE_EDHOC_SUITE2_M1_M4,
    PA_CASE_EDHOC_SUITE3_M1_M4,
    PA_CASE_EDHOC_EAD_TERMINAL,
    PA_CASE_EDHOC_DOWNGRADE,
    PA_CASE_NAR_REORDER_SUCCESS,
    PA_CASE_NAR_DUPLICATE_NO_PROGRESS,
    PA_CASE_NAR_FAILURE_MATRIX,
    PA_CASE_PREAUTH_OWNER,
    PA_CASE_MAGIC_GLOBAL,
    PA_CASE_NAS_LIFECYCLE,
    PA_CASE_COHERENT_DRIFT,
    PA_CASE_COUNT
};

static const char *const g_pa_case_names[PA_CASE_COUNT] = {
    "NAC1-SUITE2-MESSAGE1",
    "NAC1-SUITE3-MESSAGE1",
    "NAS1-USB-STREAM-RECORD",
    "COOKIE-CURRENT-BUCKET-CURRENT-SECRET",
    "COOKIE-PREVIOUS-BUCKET-PREVIOUS-SECRET",
    "COOKIE-FOUR-COMBINATION-MATRIX",
    "COOKIE-SOURCE-CARRIER-SESSION-MUTATION",
    "COOKIE-RESPONSE-EXACT-2-FRAGMENT-SCRATCH",
    "COOKIE-RESPONSE-EXACT-LENGTH-159",
    "PROTECTED-PROPOSE-INSTALL-DUAL-CONFIRM-SEQUENCE",
    "NAC1-INSTALL-MAX-RADIO-FRAGMENTATION",
    "NAR1-CANONICAL-FRAGMENT-SHAPE",
    "NAC1-CRC-MUTATION",
    "NAC1-RESERVED-MUTATION",
    "NAC1-LENGTH-MUTATION",
    "NAC1-SESSION-MUTATION",
    "NAC1-BINDING-MUTATION",
    "NAR1-CRC-MUTATION",
    "NAR1-INDEX-MUTATION",
    "NAR1-OFFSET-MUTATION",
    "NAR1-DIGEST-MUTATION",
    "NAR1-REORDER-DUPLICATE-LOSS",
    "NAR1-SESSION-GENERATION-BINDING-DIVERGENCE",
    "NAR1-EXCHANGE-GENERATION-BINDING",
    "NAR1-MIXED-FRAGMENT-TUPLE",
    "CARRIER-BINDING-DERIVATION-PINNED",
    "WIFI-BINDING-INPUT-MUTATION",
    "N6AT-CRC-MUTATION",
    "N6AT-RESERVED-BYTES",
    "N6AT-ROLE-KEY-VALUE-MISMATCH",
    "N6AT-UNKNOWN-STATE",
    "N6AT-ROLE-SPECIFIC-BOTH",
    "NAB1-EXACT-15-MEMBER-SET-BOTH-ROLES",
    "NAB1-EXACT-KEY-IDENTITY-INVENTORY",
    "NAB1-CANONICAL-COMPLETE-KEY-ORDER",
    "NAB1-DUPLICATE-MISSING-SUBSTITUTED",
    "NAB1-REORDER-CONTEXT-SUBSTITUTION",
    "NAB1-CRC-COUNT-ROLE-MUTATION",
    "N6AT-PENDING-MARKER",
    "N6AT-PENDING-TO-ACTIVE",
    "N6AT-COMMIT-UNKNOWN-OLD-NEW-THIRD",
    "LIFECYCLE-15-KEY-GROUP-MACHINE",
    "PUBLICATION-ZERO-BEFORE-DUAL-CONFIRM",
    "CREDENTIAL-CCS-CBOR-DECODE",
    "CREDENTIAL-TAIL-MUTATION",
    "NAP-NAI-CONTEXT-MISMATCH",
    "CREDENTIAL-RPK-CCS-KID",
    "PROFILE-METHOD-SUITE-MESSAGE4-EAD",
    "PROPOSAL-MEMBERSHIP-LEASE-AUTHORITY-FIELDS",
    "RFC9529-INDEPENDENT-CONSTANTS",
    "BYTE-PLUS-SHA-MUTATION",
    "EXPORTER-LABEL-SET-EXACT",
    "EXPORTER-CONTEXT-ONE-BYTE-MUTATION",
    "CONTROL-NONCE-SEQUENCE-DIRECTION-EXACT",
    "RFC9529-REFERENCE-DIGESTS",
    "PA-REATTACH-15ROW-OLD-NEW-STABLE-THIRD",
    "PA-REATTACH-LANE-OLD-NONEMPTY",
    "PA-REATTACH-10K-RESTART-MONOTONIC",
    "PA-PREREQ-FACTORY-MEMBERSHIP-LOCAL-KEY",
    "PA-LOCAL-KEY-MISMATCH-ROLLBACK-REENTRY",
    "PA-EDHOC-SUITE2-M1-M4",
    "PA-EDHOC-SUITE3-M1-M4",
    "PA-EDHOC-EAD1-EAD4-TERMINAL",
    "PA-EDHOC-DOWNGRADE-NO-AUTORETRY",
    "PA-NAR-REORDER-SUCCESS",
    "PA-NAR-DUPLICATE-NO-PROGRESS",
    "PA-NAR-CONFLICT-GAP-OVERLAP-MIXED-TIMEOUT",
    "PA-PREAUTH-SOURCE-QUOTA-IDLE-BUCKET",
    "PA-MAGIC-GLOBAL-UNIQUE",
    "PA-NAS-PARTIAL-SHORT-TRAILING-FUTURE-INNER",
    "PA-INDEPENDENT-COHERENT-DRIFT-REJECT"
};

static uint8_t g_pa_cases[PA_CASE_COUNT];

static void pa_exec(int case_id)
{
    if (case_id >= 0 && case_id < PA_CASE_COUNT) {
        g_pa_cases[case_id] = 1u;
    }
}

static uint16_t pa_u16(const uint8_t *value)
{
    return (uint16_t)(((uint16_t)value[0] << 8) | (uint16_t)value[1]);
}

static uint32_t pa_u32(const uint8_t *value)
{
    return ((uint32_t)value[0] << 24)
        | ((uint32_t)value[1] << 16)
        | ((uint32_t)value[2] << 8)
        | (uint32_t)value[3];
}

static uint64_t pa_u64(const uint8_t *value)
{
    uint64_t result = 0u;
    size_t index;
    for (index = 0u; index < 8u; ++index) {
        result = (result << 8) | (uint64_t)value[index];
    }
    return result;
}

static void pa_put_u16(uint8_t *value, uint16_t input)
{
    value[0] = (uint8_t)(input >> 8);
    value[1] = (uint8_t)input;
}

static void pa_put_u32(uint8_t *value, uint32_t input)
{
    value[0] = (uint8_t)(input >> 24);
    value[1] = (uint8_t)(input >> 16);
    value[2] = (uint8_t)(input >> 8);
    value[3] = (uint8_t)input;
}

static void pa_put_u64(uint8_t *value, uint64_t input)
{
    size_t index;
    for (index = 0u; index < 8u; ++index) {
        value[7u - index] = (uint8_t)(input & 0xffu);
        input >>= 8;
    }
}

static uint32_t pa_crc32c(const uint8_t *value, size_t size)
{
    uint32_t crc = UINT32_C(0xffffffff);
    size_t index;
    unsigned int bit;
    for (index = 0u; index < size; ++index) {
        crc ^= (uint32_t)value[index];
        for (bit = 0u; bit < 8u; ++bit) {
            crc = (crc >> 1)
                ^ ((crc & UINT32_C(1)) != 0u
                    ? UINT32_C(0x82f63b78)
                    : UINT32_C(0));
        }
    }
    return crc ^ UINT32_C(0xffffffff);
}

static int pa_any_nonzero(const uint8_t *value, size_t size)
{
    size_t index;
    for (index = 0u; index < size; ++index) {
        if (value[index] != 0u) {
            return 1;
        }
    }
    return 0;
}

static uint32_t pa_rotr32(uint32_t value, unsigned int bits)
{
    return (value >> bits) | (value << (32u - bits));
}

typedef struct pa_sha256_ctx {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t buffer[64];
    size_t buffer_length;
} pa_sha256_ctx_t;

static void pa_sha256_transform(pa_sha256_ctx_t *ctx, const uint8_t block[64])
{
    static const uint32_t k[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
        0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
        0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
        0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
        0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
        0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
        0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
        0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
        0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
        0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
    };
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, hh;
    size_t i;
    for (i = 0u; i < 16u; ++i) {
        w[i] = pa_u32(block + i * 4u);
    }
    for (i = 16u; i < 64u; ++i) {
        uint32_t s0 = pa_rotr32(w[i - 15u], 7u)
            ^ pa_rotr32(w[i - 15u], 18u) ^ (w[i - 15u] >> 3);
        uint32_t s1 = pa_rotr32(w[i - 2u], 17u)
            ^ pa_rotr32(w[i - 2u], 19u) ^ (w[i - 2u] >> 10);
        w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
    }
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    hh = ctx->state[7];
    for (i = 0u; i < 64u; ++i) {
        uint32_t S1 = pa_rotr32(e, 6u) ^ pa_rotr32(e, 11u)
            ^ pa_rotr32(e, 25u);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = hh + S1 + ch + k[i] + w[i];
        uint32_t S0 = pa_rotr32(a, 2u) ^ pa_rotr32(a, 13u)
            ^ pa_rotr32(a, 22u);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        hh = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += hh;
}

static void pa_sha256_init(pa_sha256_ctx_t *ctx)
{
    static const uint32_t initial[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    (void)memset(ctx, 0, sizeof(*ctx));
    (void)memcpy(ctx->state, initial, sizeof(initial));
}

static void pa_sha256_update(
    pa_sha256_ctx_t *ctx,
    const uint8_t *data,
    size_t length)
{
    size_t consumed = 0u;
    ctx->bit_count += (uint64_t)length * 8u;
    while (consumed < length) {
        size_t available = 64u - ctx->buffer_length;
        size_t remaining = length - consumed;
        size_t amount = remaining < available ? remaining : available;
        (void)memcpy(ctx->buffer + ctx->buffer_length, data + consumed, amount);
        ctx->buffer_length += amount;
        consumed += amount;
        if (ctx->buffer_length == 64u) {
            pa_sha256_transform(ctx, ctx->buffer);
            ctx->buffer_length = 0u;
        }
    }
}

static void pa_sha256_final(pa_sha256_ctx_t *ctx, uint8_t out[32])
{
    uint8_t length_bytes[8];
    uint8_t padding[64];
    size_t padding_length;
    size_t i;
    (void)memset(padding, 0, sizeof(padding));
    padding[0] = 0x80u;
    pa_put_u64(length_bytes, ctx->bit_count);
    padding_length = ctx->buffer_length < 56u
        ? 56u - ctx->buffer_length
        : 120u - ctx->buffer_length;
    pa_sha256_update(ctx, padding, padding_length);
    pa_sha256_update(ctx, length_bytes, sizeof(length_bytes));
    for (i = 0u; i < 8u; ++i) {
        out[i * 4u] = (uint8_t)(ctx->state[i] >> 24);
        out[i * 4u + 1u] = (uint8_t)(ctx->state[i] >> 16);
        out[i * 4u + 2u] = (uint8_t)(ctx->state[i] >> 8);
        out[i * 4u + 3u] = (uint8_t)ctx->state[i];
    }
}

static void pa_sha256(const uint8_t *message, size_t length, uint8_t out[32])
{
    pa_sha256_ctx_t ctx;
    pa_sha256_init(&ctx);
    pa_sha256_update(&ctx, message, length);
    pa_sha256_final(&ctx, out);
}

static void pa_hmac_sha256(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *msg,
    size_t msg_len,
    uint8_t out[32])
{
    uint8_t key_block[64];
    uint8_t o_key[64];
    uint8_t i_key[64];
    uint8_t inner[32];
    uint8_t inner_msg[64 + 1024];
    uint8_t outer_msg[64 + 32];
    size_t i;

    (void)memset(key_block, 0, sizeof(key_block));
    if (key_len > 64u) {
        pa_sha256(key, key_len, key_block);
    } else {
        (void)memcpy(key_block, key, key_len);
    }
    for (i = 0u; i < 64u; ++i) {
        o_key[i] = (uint8_t)(key_block[i] ^ 0x5cu);
        i_key[i] = (uint8_t)(key_block[i] ^ 0x36u);
    }
    if (msg_len > 1024u) {
        (void)memset(out, 0, 32u);
        return;
    }
    (void)memcpy(inner_msg, i_key, 64u);
    (void)memcpy(inner_msg + 64u, msg, msg_len);
    pa_sha256(inner_msg, 64u + msg_len, inner);
    (void)memcpy(outer_msg, o_key, 64u);
    (void)memcpy(outer_msg + 64u, inner, 32u);
    pa_sha256(outer_msg, 96u, out);
}

static enum pa_class pa_nac_classify(
    const uint8_t *record,
    size_t size,
    uint8_t expected_kind,
    uint32_t expected_sequence,
    uint8_t expected_carrier)
{
    uint8_t scratch[NINLIL_PA_NAC_RECORD_MAX];
    uint16_t version;
    uint32_t stored_crc;
    uint32_t actual_sequence;
    uint32_t kind_sequence;

    if (record == NULL || size < NINLIL_PA_NAC_HEADER_BYTES
        || size > NINLIL_PA_NAC_RECORD_MAX
        || memcmp(record, "NAC1", 4u) != 0
        || pa_u16(record + 6u) != 88u
        || pa_u32(record + 8u) != size
        || pa_u32(record + 12u) != size - 88u) {
        return PA_CORRUPT;
    }
    (void)memcpy(scratch, record, size);
    stored_crc = pa_u32(record + 84u);
    (void)memset(scratch + 84u, 0, 4u);
    if (pa_crc32c(scratch, size) != stored_crc) {
        return PA_CORRUPT;
    }
    version = pa_u16(record + 4u);
    if (version > 1u) {
        return PA_UNSUPPORTED;
    }
    if (version != 1u || record[16] < 1u || record[16] > 11u
        || record[17] != 0u || record[18] < 1u || record[18] > 3u
        || record[19] != 0u || !pa_any_nonzero(record + 20u, 16u)
        || pa_u64(record + 36u) == 0u || pa_any_nonzero(record + 48u, 4u)
        || !pa_any_nonzero(record + 52u, 32u)) {
        return PA_CORRUPT;
    }
    actual_sequence = pa_u32(record + 44u);
    if (record[16] == 1u || record[16] == 2u) {
        kind_sequence = 0u;
    } else if (record[16] == 3u) {
        if (actual_sequence < 1u || actual_sequence > 8u) {
            return PA_CORRUPT;
        }
        kind_sequence = actual_sequence;
    } else {
        kind_sequence = (uint32_t)record[16] - 3u;
    }
    if (actual_sequence != kind_sequence || record[16] != expected_kind
        || actual_sequence != expected_sequence
        || record[18] != expected_carrier) {
        return PA_CORRUPT;
    }
    return PA_OK;
}

static int pa_nar_validate(const uint8_t *packet, size_t size)
{
    uint8_t scratch[192];
    uint16_t payload_bytes;
    uint16_t complete_bytes;
    uint8_t index;
    uint8_t count;
    uint8_t expected_count;
    uint16_t expected_payload;
    uint32_t offset;
    uint32_t stored_crc;

    if (packet == NULL || size < 68u || size > sizeof(scratch)
        || memcmp(packet, "NAR1", 4u) != 0 || packet[4] != 0x12u
        || packet[5] != 1u || pa_u16(packet + 6u) != 68u
        || pa_u16(packet + 8u) != size) {
        return 0;
    }
    payload_bytes = pa_u16(packet + 10u);
    complete_bytes = pa_u16(packet + 40u);
    index = packet[42];
    count = packet[43];
    offset = pa_u32(packet + 60u);
    if ((size_t)payload_bytes != size - 68u || complete_bytes < 88u
        || complete_bytes > 600u || payload_bytes < 1u
        || payload_bytes > 124u || count < 1u || count > 5u
        || index >= count) {
        return 0;
    }
    expected_count = (uint8_t)(((uint32_t)complete_bytes + 123u) / 124u);
    expected_payload = index + 1u < count
        ? 124u
        : (uint16_t)(complete_bytes - (uint16_t)((uint16_t)index * 124u));
    if (count != expected_count || payload_bytes != expected_payload
        || offset != (uint32_t)index * 124u) {
        return 0;
    }
    (void)memcpy(scratch, packet, size);
    stored_crc = pa_u32(packet + 64u);
    (void)memset(scratch + 64u, 0, 4u);
    return pa_crc32c(scratch, size) == stored_crc;
}

static void pa_recompute_nac_crc(uint8_t *record, size_t size)
{
    (void)memset(record + 84u, 0, 4u);
    pa_put_u32(record + 84u, pa_crc32c(record, size));
}

static void pa_recompute_nar_crc(uint8_t *packet, size_t size)
{
    (void)memset(packet + 64u, 0, 4u);
    pa_put_u32(packet + 64u, pa_crc32c(packet, size));
}

typedef struct pa_nar_shape_case {
    uint16_t complete_bytes;
    uint8_t index;
    uint8_t count;
    uint16_t payload_bytes;
} pa_nar_shape_case_t;

static size_t pa_make_nar_shape_packet(
    uint8_t packet[192], const pa_nar_shape_case_t *shape)
{
    size_t index;
    const size_t packet_size = 68u + (size_t)shape->payload_bytes;

    (void)memset(packet, 0, 192u);
    (void)memcpy(packet, "NAR1", 4u);
    packet[4] = 0x12u;
    packet[5] = 1u;
    pa_put_u16(packet + 6u, 68u);
    pa_put_u16(packet + 8u, (uint16_t)packet_size);
    pa_put_u16(packet + 10u, shape->payload_bytes);
    for (index = 0u; index < 16u; ++index) {
        packet[12u + index] = (uint8_t)(index + 1u);
        packet[44u + index] = (uint8_t)(index + 17u);
    }
    pa_put_u64(packet + 28u, 1u);
    pa_put_u16(packet + 40u, shape->complete_bytes);
    packet[42] = shape->index;
    packet[43] = shape->count;
    pa_put_u32(packet + 60u, (uint32_t)shape->index * 124u);
    for (index = 0u; index < (size_t)shape->payload_bytes; ++index) {
        packet[68u + index] = (uint8_t)index;
    }
    pa_recompute_nar_crc(packet, packet_size);
    return packet_size;
}

static int pa_nar_fragment_shape_authority(void)
{
    static const pa_nar_shape_case_t accepted[] = {
        {88u, 0u, 1u, 88u},
        {124u, 0u, 1u, 124u},
        {125u, 0u, 2u, 124u},
        {125u, 1u, 2u, 1u},
        {159u, 1u, 2u, 35u},
        {600u, 4u, 5u, 104u},
    };
    static const pa_nar_shape_case_t rejected[] = {
        {87u, 0u, 1u, 87u},
        {601u, 4u, 5u, 105u},
        {124u, 0u, 2u, 124u},
        {124u, 1u, 2u, 0u},
        {159u, 0u, 3u, 124u},
        {159u, 1u, 3u, 35u},
        {159u, 0u, 2u, 123u},
        {159u, 1u, 2u, 34u},
    };
    uint8_t packet[192];
    size_t index;

    for (index = 0u; index < sizeof(accepted) / sizeof(accepted[0]); ++index) {
        const size_t size = pa_make_nar_shape_packet(packet, &accepted[index]);
        if (!pa_nar_validate(packet, size)) {
            return 0;
        }
    }
    for (index = 0u; index < sizeof(rejected) / sizeof(rejected[0]); ++index) {
        const size_t size = pa_make_nar_shape_packet(packet, &rejected[index]);
        if (pa_nar_validate(packet, size)) {
            return 0;
        }
    }
    return 1;
}

static void pa_recompute_n6at_crc(uint8_t *value)
{
    pa_put_u32(value + 116u, pa_crc32c(value, 116u));
}

static void pa_recompute_nab_crc(uint8_t *batch)
{
    (void)memset(batch + 64u, 0, 4u);
    pa_put_u32(batch + 64u, pa_crc32c(batch, 368u));
}

enum pa_nar_owner_outcome {
    PA_NAR_COMPLETE = 0,
    PA_NAR_INCOMPLETE,
    PA_NAR_DISCARDED_MALFORMED,
    PA_NAR_DISCARDED_MIXED_TUPLE,
    PA_NAR_DISCARDED_CONFLICTING_DUPLICATE,
    PA_NAR_DISCARDED_IDLE_TIMEOUT,
    PA_NAR_DISCARDED_DIGEST_OR_LENGTH,
    PA_NAR_DISCARDED_INNER_MISMATCH,
    PA_NAR_DISCARDED_SOURCE_MISMATCH
};

typedef struct pa_nar_owner_result {
    enum pa_nar_owner_outcome outcome;
    size_t progress_count;
    size_t duplicate_count;
    size_t published_bytes;
} pa_nar_owner_result_t;

typedef struct pa_nar_slot {
    int used;
    size_t size;
    uint8_t packet[192];
} pa_nar_slot_t;

static pa_nar_owner_result_t pa_nar_owner_run(
    const ninlil_pa_fixture_span_t *packets,
    size_t packet_count,
    const uint8_t source_locator[32],
    const uint8_t owner_source_locator[32],
    int timeout)
{
    pa_nar_owner_result_t result;
    pa_nar_slot_t slots[5];
    uint8_t owner_session[16];
    uint8_t owner_digest[16];
    uint64_t owner_generation = 0u;
    uint32_t owner_sequence = 0u;
    uint16_t owner_complete_bytes = 0u;
    uint8_t owner_count = 0u;
    int owner_set = 0;
    size_t packet_index;

    (void)memset(&result, 0, sizeof(result));
    (void)memset(slots, 0, sizeof(slots));
    result.outcome = PA_NAR_INCOMPLETE;
    if (memcmp(source_locator, owner_source_locator, 32u) != 0) {
        result.outcome = PA_NAR_DISCARDED_SOURCE_MISMATCH;
        return result;
    }
    for (packet_index = 0u; packet_index < packet_count; ++packet_index) {
        const uint8_t *packet = packets[packet_index].data;
        const size_t packet_size = packets[packet_index].size;
        uint8_t fragment_index;
        if (!pa_nar_validate(packet, packet_size)) {
            result.outcome = PA_NAR_DISCARDED_MALFORMED;
            return result;
        }
        fragment_index = packet[42];
        if (!owner_set) {
            (void)memcpy(owner_session, packet + 12u, 16u);
            owner_generation = pa_u64(packet + 28u);
            owner_sequence = pa_u32(packet + 36u);
            owner_complete_bytes = pa_u16(packet + 40u);
            owner_count = packet[43];
            (void)memcpy(owner_digest, packet + 44u, 16u);
            owner_set = 1;
        } else if (
            memcmp(owner_session, packet + 12u, 16u) != 0
            || owner_generation != pa_u64(packet + 28u)
            || owner_sequence != pa_u32(packet + 36u)
            || owner_complete_bytes != pa_u16(packet + 40u)
            || owner_count != packet[43]
            || memcmp(owner_digest, packet + 44u, 16u) != 0) {
            result.outcome = PA_NAR_DISCARDED_MIXED_TUPLE;
            return result;
        }
        if (slots[fragment_index].used) {
            if (slots[fragment_index].size == packet_size
                && memcmp(
                    slots[fragment_index].packet, packet, packet_size)
                    == 0) {
                result.duplicate_count += 1u;
                continue;
            }
            result.outcome = PA_NAR_DISCARDED_CONFLICTING_DUPLICATE;
            return result;
        }
        slots[fragment_index].used = 1;
        slots[fragment_index].size = packet_size;
        (void)memcpy(slots[fragment_index].packet, packet, packet_size);
        result.progress_count += 1u;
    }
    if (!owner_set || result.progress_count < (size_t)owner_count) {
        result.outcome =
            (timeout && owner_set) ? PA_NAR_DISCARDED_IDLE_TIMEOUT
                                   : PA_NAR_INCOMPLETE;
        return result;
    }
    {
        uint8_t complete[NINLIL_PA_NAC_RECORD_MAX];
        uint8_t digest[32];
        size_t complete_size = 0u;
        size_t index;
        for (index = 0u; index < (size_t)owner_count; ++index) {
            size_t payload_size;
            if (!slots[index].used
                || slots[index].size < NINLIL_PA_NAR_HEADER_BYTES) {
                result.outcome = PA_NAR_INCOMPLETE;
                return result;
            }
            payload_size = slots[index].size - NINLIL_PA_NAR_HEADER_BYTES;
            if (complete_size > sizeof(complete) - payload_size) {
                result.outcome = PA_NAR_DISCARDED_DIGEST_OR_LENGTH;
                return result;
            }
            (void)memcpy(
                complete + complete_size,
                slots[index].packet + NINLIL_PA_NAR_HEADER_BYTES,
                payload_size);
            complete_size += payload_size;
        }
        pa_sha256(complete, complete_size, digest);
        if (complete_size != (size_t)owner_complete_bytes
            || memcmp(digest, owner_digest, 16u) != 0) {
            result.outcome = PA_NAR_DISCARDED_DIGEST_OR_LENGTH;
            return result;
        }
        if (pa_nac_classify(
                complete,
                complete_size,
                complete[16],
                pa_u32(complete + 44u),
                complete[18])
                != PA_OK
            || memcmp(complete + 20u, owner_session, 16u) != 0
            || pa_u64(complete + 36u) != owner_generation
            || pa_u32(complete + 44u) != owner_sequence) {
            result.outcome = PA_NAR_DISCARDED_INNER_MISMATCH;
            return result;
        }
        result.outcome = PA_NAR_COMPLETE;
        result.published_bytes = complete_size;
    }
    return result;
}

enum pa_nas_outcome {
    PA_NAS_DELIVERED = 0,
    PA_NAS_NEED_MORE,
    PA_NAS_CLOSE_OVERFLOW,
    PA_NAS_CLOSE_MAGIC,
    PA_NAS_CLOSE_VERSION,
    PA_NAS_CLOSE_HEADER,
    PA_NAS_CLOSE_LENGTH,
    PA_NAS_CLOSE_TRAILING,
    PA_NAS_CLOSE_SHORT_EOF,
    PA_NAS_CLOSE_INNER_CORRUPT,
    PA_NAS_CLOSE_INNER_CARRIER_MISMATCH
};

typedef struct pa_nas_result {
    enum pa_nas_outcome outcome;
    size_t delivery_count;
    size_t buffered_bytes;
    size_t read_count;
} pa_nas_result_t;

static pa_nas_result_t pa_nas_stream_run(
    const ninlil_pa_fixture_span_t *chunks,
    size_t chunk_count,
    int eof)
{
    pa_nas_result_t result;
    uint8_t buffer[NINLIL_PA_NAS_BUFFER_CAPACITY];
    size_t index;
    size_t size = 0u;

    (void)memset(&result, 0, sizeof(result));
    result.outcome = PA_NAS_NEED_MORE;
    result.read_count = chunk_count;
    for (index = 0u; index < chunk_count; ++index) {
        if (chunks[index].size > sizeof(buffer) - size) {
            result.outcome = PA_NAS_CLOSE_OVERFLOW;
            return result;
        }
        (void)memcpy(buffer + size, chunks[index].data, chunks[index].size);
        size += chunks[index].size;
    }
    result.buffered_bytes = size;
    if (size >= 12u) {
        uint32_t inner_length;
        size_t total;
        if (memcmp(buffer, "NAS1", 4u) != 0) {
            result.outcome = PA_NAS_CLOSE_MAGIC;
            return result;
        }
        if (buffer[4] != 1u) {
            result.outcome = PA_NAS_CLOSE_VERSION;
            return result;
        }
        if ((buffer[5] != 1u && buffer[5] != 2u)
            || pa_u16(buffer + 6u) != 12u) {
            result.outcome = PA_NAS_CLOSE_HEADER;
            return result;
        }
        inner_length = pa_u32(buffer + 8u);
        if (inner_length < 88u || inner_length > 600u) {
            result.outcome = PA_NAS_CLOSE_LENGTH;
            return result;
        }
        total = 12u + (size_t)inner_length;
        if (size > total) {
            result.outcome = PA_NAS_CLOSE_TRAILING;
            return result;
        }
        if (size == total) {
            const uint8_t *inner = buffer + 12u;
            if (pa_nac_classify(
                    inner,
                    inner_length,
                    inner[16],
                    pa_u32(inner + 44u),
                    inner[18])
                != PA_OK) {
                result.outcome = PA_NAS_CLOSE_INNER_CORRUPT;
                return result;
            }
            if (inner[18] != buffer[5]) {
                result.outcome = PA_NAS_CLOSE_INNER_CARRIER_MISMATCH;
                return result;
            }
            result.outcome = PA_NAS_DELIVERED;
            result.delivery_count = 1u;
            return result;
        }
    }
    result.outcome = eof ? PA_NAS_CLOSE_SHORT_EOF : PA_NAS_NEED_MORE;
    return result;
}

enum pa_cu_row_class {
    PA_CU_ROW_OLD = 0,
    PA_CU_ROW_NEW,
    PA_CU_ROW_STABLE,
    PA_CU_ROW_THIRD
};

static enum pa_cu_row_class pa_classify_cu_row(
    const uint8_t durable_value[32],
    const uint8_t durable_context[32],
    const uint8_t old_value[32],
    const uint8_t old_context[32],
    const uint8_t new_value[32],
    const uint8_t new_context[32])
{
    const int durable_old =
        memcmp(durable_value, old_value, 32u) == 0
        && memcmp(durable_context, old_context, 32u) == 0;
    const int durable_new =
        memcmp(durable_value, new_value, 32u) == 0
        && memcmp(durable_context, new_context, 32u) == 0;
    const int old_new =
        memcmp(old_value, new_value, 32u) == 0
        && memcmp(old_context, new_context, 32u) == 0;
    if (durable_old && old_new) {
        return PA_CU_ROW_STABLE;
    }
    if (durable_old) {
        return PA_CU_ROW_OLD;
    }
    if (durable_new) {
        return PA_CU_ROW_NEW;
    }
    return PA_CU_ROW_THIRD;
}

/*
 * N6AT value authority bytes 28..83 must match install_fields pins:
 * membership_epoch, attachment_epoch, lease_epoch, e2e_security_epoch,
 * authority_term, credential_set_revision (u64), revocation_generation,
 * assignment_epoch (u32).
 */
static int pa_n6at_validate(
    const uint8_t *key,
    const uint8_t *value,
    uint8_t expected_role,
    uint8_t expected_state)
{
    uint8_t expect_key_prefix[4];
    expect_key_prefix[0] = 5u;
    expect_key_prefix[1] = expected_role;
    expect_key_prefix[2] = 1u;
    expect_key_prefix[3] = 0u;
    return memcmp(key, expect_key_prefix, 4u) == 0
        && memcmp(key + 4u, ninlil_pa_attachment_id, 16u) == 0
        && memcmp(value, "N6AT", 4u) == 0
        && pa_u16(value + 4u) == 1u
        && pa_u16(value + 6u) == 120u
        && value[8] == expected_state
        && value[9] == expected_role
        && value[10] == 0u
        && value[11] == 0u
        && memcmp(value + 12u, ninlil_pa_attachment_id, 16u) == 0
        && pa_u64(value + 28u) == NINLIL_PA_MEMBERSHIP_EPOCH
        && pa_u64(value + 36u) == NINLIL_PA_ATTACHMENT_EPOCH
        && pa_u64(value + 44u) == NINLIL_PA_LEASE_EPOCH
        && pa_u64(value + 52u) == NINLIL_PA_E2E_SECURITY_EPOCH
        && pa_u64(value + 60u) == NINLIL_PA_AUTHORITY_TERM
        && pa_u64(value + 68u) == NINLIL_PA_CREDENTIAL_SET_REVISION
        && pa_u32(value + 76u) == NINLIL_PA_REVOCATION_GENERATION
        && pa_u32(value + 80u) == NINLIL_PA_ASSIGNMENT_EPOCH
        && memcmp(value + 84u, ninlil_pa_install_digest, 32u) == 0
        && pa_crc32c(value, 116u) == pa_u32(value + 116u);
}

/* Independent CCS map(1){8:map(1){1:COSE_Key map(5)}} EC2/P-256 pin. */
static int pa_ccs_decode(
    const uint8_t *ccs,
    size_t ccs_len,
    const uint8_t *expect_kid,
    size_t kid_len,
    const uint8_t *expect_x,
    const uint8_t *expect_y)
{
    size_t off;
    size_t blen;
    if (ccs == NULL || ccs_len < 20u || ccs[0] == 0x4eu || ccs[0] != 0xa1u
        || ccs[1] != 0x08u || ccs[2] != 0xa1u || ccs[3] != 0x01u
        || ccs[4] != 0xa5u || ccs[5] != 0x01u || ccs[6] != 0x02u
        || ccs[7] != 0x02u) {
        return 0;
    }
    off = 8u;
    if ((ccs[off] & 0xe0u) != 0x40u) {
        return 0;
    }
    blen = (size_t)(ccs[off] & 0x1fu);
    if (blen >= 24u) {
        return 0;
    }
    off += 1u;
    if (off + blen > ccs_len || blen != kid_len
        || memcmp(ccs + off, expect_kid, kid_len) != 0) {
        return 0;
    }
    off += blen;
    if (off + 2u > ccs_len || ccs[off] != 0x20u || ccs[off + 1u] != 0x01u) {
        return 0;
    }
    off += 2u;
    if (off >= ccs_len || ccs[off] != 0x21u) {
        return 0;
    }
    off += 1u;
    if (off + 2u > ccs_len || ccs[off] != 0x58u || ccs[off + 1u] != 0x20u) {
        return 0;
    }
    off += 2u;
    if (off + 32u > ccs_len || memcmp(ccs + off, expect_x, 32u) != 0) {
        return 0;
    }
    off += 32u;
    if (off >= ccs_len || ccs[off] != 0x22u) {
        return 0;
    }
    off += 1u;
    if (off + 2u > ccs_len || ccs[off] != 0x58u || ccs[off + 1u] != 0x20u) {
        return 0;
    }
    off += 2u;
    if (off + 32u > ccs_len || memcmp(ccs + off, expect_y, 32u) != 0) {
        return 0;
    }
    off += 32u;
    return off == ccs_len;
}

static int pa_nab_validate(
    const uint8_t *batch,
    uint8_t role,
    int check_inventory)
{
    uint8_t scratch[368];
    unsigned int counts[5][2] = {{0u}};
    size_t index;
    uint32_t stored_crc;
    uint8_t seen[15][20];
    size_t seen_count = 0u;
    unsigned int marker_count = 0u;
    const ninlil_pa_nab_identity_t *inventory =
        (role == 1u) ? ninlil_pa_nab_device_inventory
                     : ninlil_pa_nab_authority_inventory;

    if (memcmp(batch, "NAB1", 4u) != 0 || pa_u16(batch + 4u) != 1u
        || pa_u16(batch + 6u) != 368u || batch[8] != role
        || batch[9] != 1u || batch[10] != 0u || batch[11] != 0u
        || memcmp(batch + 28u, ninlil_pa_install_digest, 32u) != 0
        || pa_u16(batch + 60u) != NINLIL_PA_NAB_ENTRY_COUNT
        || pa_u16(batch + 62u) != 20u) {
        return 0;
    }
    (void)memcpy(scratch, batch, sizeof(scratch));
    stored_crc = pa_u32(batch + 64u);
    (void)memset(scratch + 64u, 0, 4u);
    if (pa_crc32c(scratch, sizeof(scratch)) != stored_crc) {
        return 0;
    }
    for (index = 0u; index < NINLIL_PA_NAB_ENTRY_COUNT; ++index) {
        const uint8_t *row = batch + 68u + index * 20u;
        uint8_t kind = row[0];
        uint8_t direction = row[1];
        uint8_t lane = row[2];
        uint8_t local_side = row[3];
        uint16_t key_bytes = pa_u16(row + 16u);
        uint16_t value_bytes = pa_u16(row + 18u);
        uint8_t expected_side =
            ((role == 1u) == (direction == 0u)) ? 2u : 1u;
        size_t prev;
        if (kind < 1u || kind > 4u || direction > 1u
            || (kind == 4u && local_side != 0u)
            || (kind != 4u && local_side != expected_side)) {
            return 0;
        }
        for (prev = 0u; prev < seen_count; ++prev) {
            if (memcmp(seen[prev], row, 16u) == 0) {
                return 0;
            }
        }
        (void)memcpy(seen[seen_count], row, 16u);
        seen_count++;
        counts[kind][direction]++;
        if (kind == 1u) {
            if (lane < 1u || lane > 3u || key_bytes != 48u
                || value_bytes != 68u) {
                return 0;
            }
        } else if (kind == 2u) {
            if (lane != 0u || key_bytes != 24u || value_bytes != 56u) {
                return 0;
            }
        } else if (kind == 3u) {
            if (lane != 0u || key_bytes != 32u || value_bytes != 28u) {
                return 0;
            }
        } else {
            marker_count++;
            if (direction != 0u || lane != 0u || pa_u32(row + 4u) != 0u
                || pa_u64(row + 8u) != 0u || key_bytes != 20u
                || value_bytes != 120u) {
                return 0;
            }
        }
        if (check_inventory) {
            const ninlil_pa_nab_identity_t *expected = &inventory[index];
            if (expected->member_kind != kind
                || expected->direction != direction
                || expected->lane != lane
                || expected->local_side != local_side
                || expected->context_id != pa_u32(row + 4u)
                || expected->key_generation != pa_u64(row + 8u)
                || expected->key_bytes != key_bytes
                || expected->value_bytes != value_bytes) {
                return 0;
            }
            if (expected->complete_key == NULL
                || expected->complete_key_length != key_bytes) {
                return 0;
            }
            if (index > 0u) {
                const ninlil_pa_nab_identity_t *prev_id =
                    &inventory[index - 1u];
                size_t min_len = prev_id->complete_key_length;
                int cmp;
                if (prev_id->complete_key == NULL) {
                    return 0;
                }
                if (expected->complete_key_length < min_len) {
                    min_len = expected->complete_key_length;
                }
                cmp = memcmp(
                    prev_id->complete_key,
                    expected->complete_key,
                    min_len);
                if (cmp > 0
                    || (cmp == 0
                        && prev_id->complete_key_length
                            >= expected->complete_key_length)) {
                    return 0;
                }
            }
        }
    }
    return marker_count == 1u && counts[1][0] == 3u && counts[1][1] == 3u
        && counts[2][0] == 2u && counts[2][1] == 2u
        && counts[3][0] == 2u && counts[3][1] == 2u
        && counts[4][0] == 1u && counts[4][1] == 0u;
}

/*
 * Independent PA-S0 oracle labels (hard-coded in C; not read from fixture).
 * Value authority is canonical N6 codec wire (CODEC-V1), never synthetic
 * VALUE-V1 filler. Permanent negative KATs reject VALUE-V1 seed expansion.
 */
static const uint8_t g_pa_value_label[] = {
    'N', 'I', 'N', 'L', 'I', 'L', '-', 'P', 'A', '-', 'N', '6', '-',
    'C', 'O', 'D', 'E', 'C', '-', 'V', '1'
};
/* Synthetic filler label used only as permanent negative probe input. */
static const uint8_t g_pa_value_v1_filler[] = {
    'N', 'I', 'N', 'L', 'I', 'L', '-', 'P', 'A', '-', 'N', '6', '-',
    'V', 'A', 'L', 'U', 'E', '-', 'V', '1'
};
static const uint8_t g_pa_ctx_label[] = {
    'N', 'I', 'N', 'L', 'I', 'L', '-', 'P', 'A', '-', 'N', '6', '-',
    'C', 'T', 'X', '-', 'D', 'I', 'G', 'E', 'S', 'T', '-', 'V', '1'
};
static const uint8_t g_pa_old_ctx_label[] = {
    'N', 'I', 'N', 'L', 'I', 'L', '-', 'P', 'A', '-', 'N', '6', '-',
    'O', 'L', 'D', '-', 'C', 'T', 'X', '-', 'D', 'I', 'G', 'E', 'S', 'T',
    '-', 'V', '1'
};
/* docs/30 §994–996 R6 node-id (not PA-NODE-ID-V1). */
static const uint8_t g_pa_node_id_label[] = {
    'N', 'I', 'N', 'L', 'I', 'L', '-', 'R', '6', '-', 'N', 'O', 'D', 'E',
    '-', 'I', 'D', '-', 'v', '1'
};
enum {
    PA_N6_MAGIC_TX = 0x4e365458u, /* "N6TX" */
    PA_N6_MAGIC_RX = 0x4e365258u, /* "N6RX" */
    PA_N6_MAGIC_HW = 0x4e364857u, /* "N6HW" */
    PA_N6_MAGIC_AL = 0x4e36414cu  /* "N6AL" */
};
/* Independent authority envelope pins (not derived by reflecting fixture body). */
static const char g_pa_schema_id_pin[] =
    "ninlil.production-attachment-edhoc.vector.v1";
static const char g_pa_title_pin[] =
    "Ninlil Production Attachment EDHOC PA-S0 Proposed Vector";
static const char g_pa_adr_pin[] =
    "docs/adr/0023-production-attachment-edhoc-profile.md";
static const char g_pa_normative_doc_pin[] =
    "docs/35-production-attachment-edhoc-profile.md";
static const char g_pa_status_pin[] = "PROPOSED_SPEC_ONLY";
static const char g_pa_tool_generator_pin[] =
    "tools/production_attachment_edhoc_vector_gen.py";
static const char g_pa_tool_python_gate_pin[] =
    "tools/production_attachment_edhoc_gate.py";
static const char g_pa_tool_node_gate_pin[] =
    "tools/production_attachment_edhoc_gate.mjs";
static const char g_pa_tool_c_test_pin[] =
    "tests/radio/production_attachment_edhoc_vector_test.c";
enum { PA_SCHEMA_VERSION_PIN = 1, PA_MEMBER_COUNT_PIN = 15 };

/* Independent RFC 9529 §3 method-3 / suite-2 message_1 literal KAT. */
static const uint8_t g_pa_rfc_m1_literal[39] = {
    0x03u, 0x82u, 0x06u, 0x02u, 0x58u, 0x20u, 0x8au, 0xf6u, 0xf4u, 0x30u,
    0xebu, 0xe1u, 0x8du, 0x34u, 0x18u, 0x40u, 0x17u, 0xa9u, 0xa1u, 0x1bu,
    0xf5u, 0x11u, 0xc8u, 0xdfu, 0xf8u, 0xf8u, 0x34u, 0x73u, 0x0bu, 0x96u,
    0xc1u, 0xb7u, 0xc8u, 0xdbu, 0xcau, 0x2fu, 0xc3u, 0xb6u, 0x37u
};
static const uint8_t g_pa_rfc_m1_literal_sha[32] = {
    0xcau, 0x02u, 0xcau, 0xbdu, 0xa5u, 0xa8u, 0x90u, 0x27u, 0x49u, 0xb4u,
    0x2fu, 0x71u, 0x10u, 0x50u, 0xbbu, 0x4du, 0xbdu, 0x52u, 0x15u, 0x3eu,
    0x87u, 0x52u, 0x75u, 0x94u, 0xb3u, 0x9fu, 0x50u, 0xcdu, 0xf0u, 0x19u,
    0x88u, 0x8cu
};
enum { PA_RFC_M1_METHOD = 3, PA_RFC_M1_SUITE_HINT = 2 };

/* Canonical N6 codec value wire (docs/30); never synthetic VALUE-V1 filler. */
static int pa_materialize_member_value(
    uint8_t member_kind,
    const uint8_t *complete_key,
    size_t complete_key_len,
    const uint8_t install_digest[32],
    size_t value_length,
    const uint8_t *marker_value,
    uint8_t local_side,
    uint64_t key_generation,
    uint64_t membership_epoch,
    int phase_old,
    const uint8_t local_node[16],
    const uint8_t peer_node[16],
    uint32_t context_id,
    uint8_t layer_code,
    uint8_t *out_value)
{
    uint64_t authority_now;
    uint8_t ns_in[16u + 1u + 8u + 1u];
    uint8_t ns_fp[32];
    const uint8_t *receiver;

    (void)install_digest;
    if (value_length == 0u || value_length > 120u || complete_key_len > 48u) {
        return 0;
    }
    if (member_kind == 4u) {
        if (phase_old || marker_value == NULL || value_length != 120u) {
            return 0;
        }
        (void)memcpy(out_value, marker_value, value_length);
        return 1;
    }
    authority_now = phase_old ? 1000000ull : 1300000ull;
    if (member_kind == 1u) {
        uint32_t magic;
        uint64_t counter;
        if ((local_side != 1u && local_side != 2u) || complete_key_len != 48u
            || value_length != 68u || key_generation == 0u
            || membership_epoch < 1u || local_node == NULL
            || peer_node == NULL) {
            return 0;
        }
        receiver = (local_side == 2u) ? peer_node : local_node;
        magic = (local_side == 2u) ? PA_N6_MAGIC_TX : PA_N6_MAGIC_RX;
        /* docs/30 §1031–1044 / §1314: TX=1, RX=0 */
        counter = (local_side == 2u) ? 1ull : 0ull;
        (void)memset(out_value, 0, 68u);
        pa_put_u32(out_value, magic);
        pa_put_u16(out_value + 4u, 2u);
        pa_put_u16(out_value + 6u, 0u);
        pa_put_u64(out_value + 8u, counter);
        pa_put_u64(out_value + 16u, key_generation);
        (void)memcpy(out_value + 24u, complete_key + 8u, 16u);
        pa_put_u64(out_value + 40u, membership_epoch);
        out_value[48] = local_side;
        /* R6 ns_fingerprint12: receiver||layer||epoch||alloc_side */
        (void)memcpy(ns_in, receiver, 16u);
        ns_in[16] = layer_code;
        pa_put_u64(ns_in + 17u, membership_epoch);
        ns_in[25] = local_side;
        pa_sha256(ns_in, 26u, ns_fp);
        (void)memcpy(out_value + 52u, ns_fp, 12u);
        pa_put_u32(out_value + 64u, pa_crc32c(out_value, 64u));
        return 1;
    }
    if (member_kind == 3u) {
        uint64_t hw;
        if (value_length != 28u || key_generation == 0u) {
            return 0;
        }
        hw = phase_old ? 1ull : key_generation;
        if (hw < 1ull) {
            hw = 1ull;
        }
        (void)memset(out_value, 0, 28u);
        pa_put_u32(out_value, PA_N6_MAGIC_HW);
        pa_put_u16(out_value + 4u, 1u);
        pa_put_u16(out_value + 6u, 0u);
        pa_put_u64(out_value + 8u, hw);
        pa_put_u64(out_value + 16u, authority_now);
        pa_put_u32(out_value + 24u, pa_crc32c(out_value, 24u));
        return 1;
    }
    if (member_kind == 2u) {
        uint32_t floor;
        uint16_t active;
        if (value_length != 56u || membership_epoch < 1u || local_node == NULL
            || peer_node == NULL) {
            return 0;
        }
        if (!phase_old && context_id < 1u) {
            return 0;
        }
        receiver = (local_side == 2u) ? peer_node : local_node;
        /* docs/30 §1309–1312: floor = context_id+1 (not key_generation) */
        floor = phase_old ? 1u : (context_id + 1u);
        if (floor < 1u) {
            floor = 1u;
        }
        active = phase_old ? 0u : 1u;
        (void)memset(out_value, 0, 56u);
        pa_put_u32(out_value, PA_N6_MAGIC_AL);
        pa_put_u16(out_value + 4u, 2u);
        pa_put_u16(out_value + 6u, 0u);
        pa_put_u32(out_value + 8u, floor);
        pa_put_u16(out_value + 12u, active);
        pa_put_u16(out_value + 14u, 0u);
        pa_put_u32(out_value + 16u, 0u);
        pa_put_u64(out_value + 20u, membership_epoch);
        pa_put_u64(out_value + 28u, authority_now);
        (void)memcpy(out_value + 36u, receiver, 16u);
        pa_put_u32(out_value + 52u, pa_crc32c(out_value, 52u));
        return 1;
    }
    return 0;
}

/* Synthetic VALUE-V1 seed expansion — permanent negative only (must not match). */
static int pa_materialize_value_v1_filler(
    uint8_t member_kind,
    const uint8_t *complete_key,
    size_t complete_key_len,
    const uint8_t install_digest[32],
    size_t value_length,
    uint8_t *out_value)
{
    uint8_t seed_in[21u + 1u + 48u + 32u];
    uint8_t seed[32];
    size_t seed_in_len;
    size_t produced = 0u;
    uint32_t counter = 0u;

    if (value_length == 0u || value_length > 120u || complete_key_len > 48u
        || member_kind == 4u) {
        return 0;
    }
    seed_in_len = 0u;
    (void)memcpy(
        seed_in + seed_in_len, g_pa_value_v1_filler, sizeof(g_pa_value_v1_filler));
    seed_in_len += sizeof(g_pa_value_v1_filler);
    seed_in[seed_in_len++] = member_kind;
    (void)memcpy(seed_in + seed_in_len, complete_key, complete_key_len);
    seed_in_len += complete_key_len;
    (void)memcpy(seed_in + seed_in_len, install_digest, 32u);
    seed_in_len += 32u;
    pa_sha256(seed_in, seed_in_len, seed);
    while (produced < value_length) {
        uint8_t block_in[32u + 4u];
        uint8_t block[32];
        size_t take;
        (void)memcpy(block_in, seed, 32u);
        pa_put_u32(block_in + 32u, counter);
        pa_sha256(block_in, 36u, block);
        take = value_length - produced;
        if (take > 32u) {
            take = 32u;
        }
        (void)memcpy(out_value + produced, block, take);
        produced += take;
        counter += 1u;
    }
    return 1;
}

static void pa_node_id_from_stable(const uint8_t stable[32], uint8_t out16[16])
{
    /* node_id16 = SHA-256("NINLIL-R6-NODE-ID-v1" || len_u16be || stable)[0..16) */
    uint8_t in[20u + 2u + 32u];
    uint8_t dig[32];
    size_t off = 0u;
    (void)memcpy(in + off, g_pa_node_id_label, sizeof(g_pa_node_id_label));
    off += sizeof(g_pa_node_id_label);
    pa_put_u16(in + off, 32u);
    off += 2u;
    (void)memcpy(in + off, stable, 32u);
    off += 32u;
    pa_sha256(in, off, dig);
    (void)memcpy(out16, dig, 16u);
}

static int pa_materialize_context_digest(
    uint8_t member_kind,
    const uint8_t *complete_key,
    size_t complete_key_len,
    const uint8_t install_digest[32],
    const uint8_t attachment_id[16],
    uint8_t out_digest[32])
{
    /* label(26) + kind(1) + complete_key(<=48) + install(32) + attachment(16) */
    uint8_t in[26u + 1u + 48u + 32u + 16u];
    size_t in_len = 0u;

    if (complete_key_len > 48u) {
        return 0;
    }
    if (member_kind == 4u) {
        (void)memset(out_digest, 0, 32u);
        return 1;
    }
    (void)memcpy(in + in_len, g_pa_ctx_label, sizeof(g_pa_ctx_label));
    in_len += sizeof(g_pa_ctx_label);
    in[in_len++] = member_kind;
    (void)memcpy(in + in_len, complete_key, complete_key_len);
    in_len += complete_key_len;
    (void)memcpy(in + in_len, install_digest, 32u);
    in_len += 32u;
    (void)memcpy(in + in_len, attachment_id, 16u);
    in_len += 16u;
    pa_sha256(in, in_len, out_digest);
    return 1;
}

static int pa_materialize_old_context_digest(
    uint8_t member_kind,
    const uint8_t *complete_key,
    size_t complete_key_len,
    const uint8_t attachment_id[16],
    uint8_t out_digest[32])
{
    uint8_t in[30u + 1u + 48u + 16u];
    size_t in_len = 0u;

    if (member_kind == 4u || complete_key_len > 48u) {
        return 0;
    }
    (void)memcpy(
        in + in_len, g_pa_old_ctx_label, sizeof(g_pa_old_ctx_label));
    in_len += sizeof(g_pa_old_ctx_label);
    in[in_len++] = member_kind;
    (void)memcpy(in + in_len, complete_key, complete_key_len);
    in_len += complete_key_len;
    (void)memcpy(in + in_len, attachment_id, 16u);
    in_len += 16u;
    pa_sha256(in, in_len, out_digest);
    return 1;
}

/*
 * Value-image write-set classifier (Py/Node parity).
 * Per write-set key: present (value,ctx) matches OLD / NEW / STABLE / THIRD.
 * Never maps empty present alone to EXACT_OLD when observed OLD is non-empty.
 */
static int pa_classify_write_set_value_image(
    const uint8_t *const *write_set_keys,
    const size_t *write_set_lens,
    size_t write_set_count,
    const uint8_t *const *present_keys,
    const size_t *present_lens,
    const uint8_t *const *present_value_sha256,
    const uint8_t *const *present_context_digest,
    size_t present_count,
    const uint8_t *const *old_keys,
    const size_t *old_lens,
    const uint8_t *const *old_value_sha256,
    const uint8_t *const *old_context_digest,
    size_t old_count,
    const uint8_t *const *new_value_sha256,
    const uint8_t *const *new_context_digest,
    const uint8_t *marker_key,
    size_t marker_key_len,
    char out_label[40])
{
    size_t i;
    size_t j;
    size_t pure_new = 0u;
    size_t pure_old = 0u;
    size_t third = 0u;
    int marker_present = 0;
    uint8_t marker_state = 0u;

    if (write_set_count != 15u) {
        (void)memcpy(out_label, "UNCLASSIFIED_CORRUPT", 21);
        return 1;
    }
    /* duplicate present keys? */
    for (i = 0u; i < present_count; ++i) {
        for (j = i + 1u; j < present_count; ++j) {
            if (present_lens[i] == present_lens[j]
                && memcmp(present_keys[i], present_keys[j], present_lens[i])
                    == 0) {
                (void)memcpy(out_label, "DUPLICATE_KEYS_CORRUPT", 22);
                return 1;
            }
        }
    }
    /* foreign: present key outside write-set (semantic, not key-count alone). */
    for (i = 0u; i < present_count; ++i) {
        int in_ws = 0;
        for (j = 0u; j < write_set_count; ++j) {
            if (present_lens[i] == write_set_lens[j]
                && memcmp(present_keys[i], write_set_keys[j], present_lens[i])
                    == 0) {
                in_ws = 1;
                break;
            }
        }
        if (!in_ws) {
            (void)memcpy(out_label, "FOREIGN_OR_EXTRA_CORRUPT", 25);
            return 1;
        }
    }
    for (i = 0u; i < write_set_count; ++i) {
        const uint8_t *wk = write_set_keys[i];
        size_t wl = write_set_lens[i];
        int has_old = 0;
        int has_present = 0;
        int match_old = 0;
        int match_new = 0;
        const uint8_t *old_vs = NULL;
        const uint8_t *old_cd = NULL;
        const uint8_t *got_vs = NULL;
        const uint8_t *got_cd = NULL;
        for (j = 0u; j < old_count; ++j) {
            if (old_lens[j] == wl && memcmp(old_keys[j], wk, wl) == 0) {
                has_old = 1;
                old_vs = old_value_sha256[j];
                old_cd = old_context_digest[j];
                break;
            }
        }
        for (j = 0u; j < present_count; ++j) {
            if (present_lens[j] == wl && memcmp(present_keys[j], wk, wl) == 0) {
                has_present = 1;
                got_vs = present_value_sha256[j];
                got_cd = present_context_digest[j];
                break;
            }
        }
        if (has_present && got_vs != NULL && got_cd != NULL
            && new_value_sha256[i] != NULL && new_context_digest[i] != NULL
            && memcmp(got_vs, new_value_sha256[i], 32u) == 0
            && memcmp(got_cd, new_context_digest[i], 32u) == 0) {
            match_new = 1;
        }
        if (!has_old && !has_present) {
            match_old = 1; /* both absent */
        } else if (has_old && has_present && old_vs != NULL && old_cd != NULL
            && got_vs != NULL && got_cd != NULL
            && memcmp(got_vs, old_vs, 32u) == 0
            && memcmp(got_cd, old_cd, 32u) == 0) {
            match_old = 1;
        }
        if (match_old && match_new) {
            continue; /* STABLE */
        }
        if (match_new) {
            pure_new += 1u;
            if (wl == marker_key_len
                && memcmp(wk, marker_key, marker_key_len) == 0) {
                marker_present = 1;
                /* marker state is value byte 8; recover from NEW digest path
                 * only via caller ensuring NEW digests track marker state. */
            }
        } else if (match_old) {
            pure_old += 1u;
        } else {
            third += 1u;
        }
        (void)marker_state;
    }
    if (third != 0u) {
        (void)memcpy(out_label, "THIRD_OR_MISMATCH_CORRUPT", 25);
        return 1;
    }
    if (pure_new == 0u) {
        (void)memcpy(out_label, "EXACT_OLD", 10);
        return 1;
    }
    if (pure_old == 0u) {
        /* EXACT_NEW requires marker present; state via caller marker_state. */
        if (!marker_present) {
            (void)memcpy(out_label, "MISSING_MARKER_CORRUPT", 23);
            return 1;
        }
        (void)memcpy(out_label, "EXACT_NEW_PENDING_15", 21);
        return 1;
    }
    if (pure_new >= 1u && pure_new <= 14u) {
        (void)snprintf(
            out_label,
            40,
            "PARTIAL_%u_CORRUPT",
            (unsigned)pure_new);
        return 1;
    }
    (void)memcpy(out_label, "UNCLASSIFIED_CORRUPT", 21);
    return 1;
}

/*
 * Independent lifecycle post-image classifier.
 * expected_* digests are caller-supplied from independent hard-rule recompute
 * (never copied from fixture observed digests as both sides).
 */
static int pa_classify_group(
    const uint8_t *const *present_keys,
    const size_t *present_lens,
    size_t present_count,
    const ninlil_pa_nab_identity_t *expected_inv,
    const uint8_t *marker_key,
    int marker_state,
    int marker_value_ok,
    const uint8_t *const *present_value_sha256,
    const uint8_t *const *present_context_digest,
    const uint8_t *expected_value_sha256,
    const uint8_t *expected_context_digest,
    char out_label[40])
{
    size_t i;
    size_t j;
    /*
     * Key-presence helper for foreign/extra only.
     * Re-attach EXACT_OLD uses value-image + fixture OLD (not empty present).
     */
    if (present_count == 0u) {
        (void)memcpy(out_label, "EXACT_OLD_COLD_OR_EMPTY_PRESENT", 31);
        return 1;
    }
    /* reject duplicates */
    for (i = 0u; i < present_count; ++i) {
        for (j = i + 1u; j < present_count; ++j) {
            if (present_lens[i] == present_lens[j]
                && memcmp(present_keys[i], present_keys[j], present_lens[i])
                    == 0) {
                (void)memcpy(out_label, "DUPLICATE_KEYS_CORRUPT", 22);
                return 1;
            }
        }
    }
    /* foreign? */
    for (i = 0u; i < present_count; ++i) {
        int found = 0;
        for (j = 0u; j < NINLIL_PA_NAB_ENTRY_COUNT; ++j) {
            if (expected_inv[j].complete_key != NULL
                && expected_inv[j].complete_key_length == present_lens[i]
                && memcmp(
                    expected_inv[j].complete_key,
                    present_keys[i],
                    present_lens[i])
                    == 0) {
                found = 1;
                break;
            }
        }
        if (!found) {
            (void)memcpy(out_label, "FOREIGN_OR_EXTRA_CORRUPT", 25);
            return 1;
        }
    }
    if (present_count > 15u) {
        (void)memcpy(out_label, "EXTRA_CORRUPT", 14);
        return 1;
    }
    if (present_count >= 1u && present_count <= 14u) {
        (void)snprintf(
            out_label,
            40,
            "KEY_PRESENCE_PARTIAL_%u_NOT_VALUE_IMAGE",
            (unsigned)present_count);
        return 1;
    }
    if (present_count == 15u) {
        int has_marker = 0;
        for (i = 0u; i < present_count; ++i) {
            if (present_lens[i] == 20u
                && memcmp(present_keys[i], marker_key, 20u) == 0) {
                has_marker = 1;
                break;
            }
        }
        if (!has_marker) {
            (void)memcpy(out_label, "MISSING_MARKER_CORRUPT", 23);
            return 1;
        }
        if (!marker_value_ok || marker_state == 3) {
            (void)memcpy(out_label, "THIRD_OR_MISMATCH_CORRUPT", 25);
            return 1;
        }
        /* Full-image: present digests vs independent expected digests. */
        if (present_value_sha256 != NULL && present_context_digest != NULL
            && expected_value_sha256 != NULL
            && expected_context_digest != NULL) {
            for (i = 0u; i < NINLIL_PA_NAB_ENTRY_COUNT; ++i) {
                const uint8_t *got_vs = present_value_sha256[i];
                const uint8_t *got_cd = present_context_digest[i];
                if (got_vs == NULL || got_cd == NULL) {
                    (void)memcpy(
                        out_label, "VALUE_OR_CONTEXT_DIGEST_MISMATCH_CORRUPT", 40);
                    return 1;
                }
                if (memcmp(
                        got_vs, expected_value_sha256 + (i * 32u), 32u)
                        != 0
                    || memcmp(
                        got_cd, expected_context_digest + (i * 32u), 32u)
                        != 0) {
                    (void)memcpy(
                        out_label, "VALUE_OR_CONTEXT_DIGEST_MISMATCH_CORRUPT", 40);
                    return 1;
                }
            }
        }
        if (marker_state == 1) {
            (void)memcpy(out_label, "EXACT_NEW_PENDING_15", 21);
            return 1;
        }
        if (marker_state == 2) {
            (void)memcpy(out_label, "EXACT_NEW_ACTIVE_MARKER_IN_15", 29);
            return 1;
        }
        (void)memcpy(out_label, "UNKNOWN_MARKER_STATE_CORRUPT", 29);
        return 1;
    }
    (void)memcpy(out_label, "UNCLASSIFIED_CORRUPT", 21);
    return 1;
}

static int pa_positive(void)
{
    uint8_t assembled[NINLIL_PA_NAC_RECORD_MAX];
    uint8_t digest[32];
    uint8_t hmac_out[32];
    size_t assembled_size = 0u;
    size_t index;

    /* PROFILE: method 3 / suite pin / message4 path via NAX. */
    if (ninlil_pa_nax1[8] != 3u || ninlil_pa_nax1[9] != 2u
        || ninlil_pa_nap1[12] != 3u || ninlil_pa_nap1[13] != 2u) {
        return 0;
    }
    /* Independent authority envelope vs fixture emission + hard pins. */
    if (NINLIL_PA_SCHEMA_VERSION != (unsigned)PA_SCHEMA_VERSION_PIN
        || NINLIL_PA_MEMBER_COUNT_EXACT != (unsigned)PA_MEMBER_COUNT_PIN
        || NINLIL_PA_NAB_ENTRY_COUNT != (unsigned)PA_MEMBER_COUNT_PIN
        || strcmp(ninlil_pa_schema_id, g_pa_schema_id_pin) != 0
        || strcmp(ninlil_pa_title, g_pa_title_pin) != 0
        || strcmp(ninlil_pa_adr, g_pa_adr_pin) != 0
        || strcmp(ninlil_pa_normative_doc, g_pa_normative_doc_pin) != 0
        || strcmp(ninlil_pa_status, g_pa_status_pin) != 0
        || strcmp(ninlil_pa_value_label, "NINLIL-PA-N6-CODEC-V1") != 0
        || strcmp(ninlil_pa_ctx_label, "NINLIL-PA-N6-CTX-DIGEST-V1") != 0
        || strcmp(ninlil_pa_tool_generator, g_pa_tool_generator_pin) != 0
        || strcmp(ninlil_pa_tool_python_gate, g_pa_tool_python_gate_pin) != 0
        || strcmp(ninlil_pa_tool_node_gate, g_pa_tool_node_gate_pin) != 0
        || strcmp(ninlil_pa_tool_c_test, g_pa_tool_c_test_pin) != 0
        || sizeof(g_pa_value_label) != 21u
        || memcmp(g_pa_value_label, ninlil_pa_value_label, 21u) != 0
        || sizeof(g_pa_ctx_label) != 26u
        || memcmp(g_pa_ctx_label, ninlil_pa_ctx_label, 26u) != 0
        || memcmp(g_pa_value_label, g_pa_value_v1_filler, 21u) == 0) {
        return 0;
    }
    pa_exec(PA_CASE_PROFILE);
    /* EXPORTER labels: independent closed set 32768..32775. */
    if (NINLIL_PA_EXPORTER_I2R_KEY != 32768u
        || NINLIL_PA_EXPORTER_R2I_KEY != 32769u
        || NINLIL_PA_EXPORTER_I2R_IV != 32770u
        || NINLIL_PA_EXPORTER_R2I_IV != 32771u
        || NINLIL_PA_EXPORTER_HOP_IR != 32772u
        || NINLIL_PA_EXPORTER_HOP_RI != 32773u
        || NINLIL_PA_EXPORTER_E2E_IR != 32774u
        || NINLIL_PA_EXPORTER_E2E_RI != 32775u
        || NINLIL_PA_EXPORTER_E2E_RI == NINLIL_PA_EXPORTER_E2E_IR) {
        return 0;
    }
    pa_exec(PA_CASE_EXPORTER_LABELS);

    if (pa_nac_classify(
            ninlil_pa_nac_suite2_m1,
            sizeof(ninlil_pa_nac_suite2_m1),
            4u,
            1u,
            3u) != PA_OK
        || ninlil_pa_nac_suite2_m1[88] != 3u
        || ninlil_pa_nac_suite2_m1[89] != 2u) {
        return 0;
    }
    pa_exec(PA_CASE_NAC1_SUITE2);
    if (pa_nac_classify(
            ninlil_pa_nac_suite3_m1,
            sizeof(ninlil_pa_nac_suite3_m1),
            4u,
            1u,
            3u) != PA_OK
        || ninlil_pa_nac_suite3_m1[89] != 3u) {
        return 0;
    }
    pa_exec(PA_CASE_NAC1_SUITE3);

    if (memcmp(ninlil_pa_nas_usb_m1, "NAS1", 4u) != 0
        || ninlil_pa_nas_usb_m1[4] != 1u
        || ninlil_pa_nas_usb_m1[5] != 1u
        || pa_u16(ninlil_pa_nas_usb_m1 + 6u) != 12u
        || pa_u32(ninlil_pa_nas_usb_m1 + 8u)
            != sizeof(ninlil_pa_nas_usb_m1) - 12u
        || pa_nac_classify(
            ninlil_pa_nas_usb_m1 + 12u,
            sizeof(ninlil_pa_nas_usb_m1) - 12u,
            4u,
            1u,
            1u) != PA_OK) {
        return 0;
    }
    pa_exec(PA_CASE_NAS1);

    /* Normative docs/35: cookie time bucket is fixed 2 seconds. */
    if (NINLIL_PA_COOKIE_TIME_BUCKET_SECONDS != 2u) {
        return 0;
    }
    if (sizeof(ninlil_pa_cookie_response) != NINLIL_PA_COOKIE_RESPONSE_BYTES
        || (88u + 32u + 2u + 37u) != 159u) {
        return 0;
    }
    pa_exec(PA_CASE_COOKIE_LEN_159);

    pa_hmac_sha256(
        ninlil_pa_cookie_secret_current,
        sizeof(ninlil_pa_cookie_secret_current),
        ninlil_pa_cookie_canonical,
        sizeof(ninlil_pa_cookie_canonical),
        hmac_out);
    if (memcmp(hmac_out, ninlil_pa_cookie_current, 32u) != 0) {
        return 0;
    }
    pa_exec(PA_CASE_COOKIE_CURRENT);

    {
        uint8_t prev_input[sizeof(ninlil_pa_cookie_canonical)];
        uint8_t prev_hmac[32];
        (void)memcpy(
            prev_input,
            ninlil_pa_cookie_canonical,
            sizeof(prev_input));
        /* last 8 bytes are time bucket; previous = current - 1 */
        pa_put_u64(
            prev_input + sizeof(prev_input) - 8u,
            pa_u64(ninlil_pa_cookie_canonical + sizeof(ninlil_pa_cookie_canonical)
                - 8u)
                - 1ull);
        pa_hmac_sha256(
            ninlil_pa_cookie_secret_previous,
            sizeof(ninlil_pa_cookie_secret_previous),
            prev_input,
            sizeof(prev_input),
            prev_hmac);
        if (memcmp(
                prev_hmac,
                ninlil_pa_cookie_prev_secret_prev_bucket,
                32u)
            != 0) {
            return 0;
        }
        /* Four-combination matrix: recompute remaining two combos. */
        pa_hmac_sha256(
            ninlil_pa_cookie_secret_current,
            sizeof(ninlil_pa_cookie_secret_current),
            prev_input,
            sizeof(prev_input),
            prev_hmac);
        if (memcmp(
                prev_hmac,
                ninlil_pa_cookie_curr_secret_prev_bucket,
                32u)
            != 0) {
            return 0;
        }
        pa_hmac_sha256(
            ninlil_pa_cookie_secret_previous,
            sizeof(ninlil_pa_cookie_secret_previous),
            ninlil_pa_cookie_canonical,
            sizeof(ninlil_pa_cookie_canonical),
            prev_hmac);
        if (memcmp(
                prev_hmac,
                ninlil_pa_cookie_prev_secret_curr_bucket,
                32u)
            != 0) {
            return 0;
        }
        if (memcmp(
                ninlil_pa_cookie_current,
                ninlil_pa_cookie_prev_secret_prev_bucket,
                32u)
                == 0
            || memcmp(
                ninlil_pa_cookie_current,
                ninlil_pa_cookie_curr_secret_prev_bucket,
                32u)
                == 0
            || memcmp(
                ninlil_pa_cookie_current,
                ninlil_pa_cookie_prev_secret_curr_bucket,
                32u)
                == 0) {
            return 0;
        }
    }
    pa_exec(PA_CASE_COOKIE_PREVIOUS);
    pa_exec(PA_CASE_COOKIE_FOUR_MATRIX);

    {
        uint8_t mut_canon[sizeof(ninlil_pa_cookie_canonical)];
        uint8_t mut_hmac[32];
        (void)memcpy(mut_canon, ninlil_pa_cookie_canonical, sizeof(mut_canon));
        mut_canon[sizeof("NINLIL-NAC1-COOKIE-V1") - 1u + 1u + 32u] ^= 1u;
        pa_hmac_sha256(
            ninlil_pa_cookie_secret_current,
            sizeof(ninlil_pa_cookie_secret_current),
            mut_canon,
            sizeof(mut_canon),
            mut_hmac);
        if (memcmp(mut_hmac, ninlil_pa_cookie_current, 32u) == 0) {
            return 0;
        }
    }
    pa_exec(PA_CASE_COOKIE_MUTATION);

    if (pa_nac_classify(
            ninlil_pa_cookie_challenge,
            sizeof(ninlil_pa_cookie_challenge),
            1u,
            0u,
            3u) != PA_OK
        || pa_nac_classify(
            ninlil_pa_cookie_response,
            sizeof(ninlil_pa_cookie_response),
            2u,
            0u,
            3u) != PA_OK
        || pa_nac_classify(
            ninlil_pa_propose_seq5,
            sizeof(ninlil_pa_propose_seq5),
            8u,
            5u,
            3u) != PA_OK
        || pa_nac_classify(
            ninlil_pa_install_seq6,
            sizeof(ninlil_pa_install_seq6),
            9u,
            6u,
            3u) != PA_OK
        || pa_nac_classify(
            ninlil_pa_confirm_device_seq7,
            sizeof(ninlil_pa_confirm_device_seq7),
            10u,
            7u,
            3u) != PA_OK
        || pa_nac_classify(
            ninlil_pa_confirm_authority_seq8,
            sizeof(ninlil_pa_confirm_authority_seq8),
            11u,
            8u,
            3u) != PA_OK) {
        return 0;
    }
    pa_exec(PA_CASE_PROTECTED_SEQ);

    assembled_size = 0u;
    for (index = 0u; index < NINLIL_PA_COOKIE_FRAGMENT_COUNT; ++index) {
        const ninlil_pa_fixture_span_t *fragment =
            &ninlil_pa_cookie_fragments[index];
        size_t payload_size;
        if (!pa_nar_validate(fragment->data, fragment->size)
            || fragment->data[42] != index
            || fragment->data[43] != NINLIL_PA_COOKIE_FRAGMENT_COUNT) {
            return 0;
        }
        payload_size = fragment->size - NINLIL_PA_NAR_HEADER_BYTES;
        if (assembled_size > sizeof(assembled) - payload_size) {
            return 0;
        }
        (void)memcpy(
            assembled + assembled_size,
            fragment->data + NINLIL_PA_NAR_HEADER_BYTES,
            payload_size);
        assembled_size += payload_size;
    }
    if (assembled_size != sizeof(ninlil_pa_cookie_response)
        || memcmp(
            assembled, ninlil_pa_cookie_response, assembled_size) != 0) {
        return 0;
    }
    pa_exec(PA_CASE_COOKIE_2FRAG);

    if (memcmp(ninlil_pa_nap1, "NAP1", 4u) != 0
        || pa_u16(ninlil_pa_nap1 + 4u) != 1u
        || pa_u16(ninlil_pa_nap1 + 6u) != sizeof(ninlil_pa_nap1)
        || ninlil_pa_nap1[12] != 3u
        || ninlil_pa_nap1[13] != 2u
        || memcmp(ninlil_pa_nai1, "NAI1", 4u) != 0
        || pa_u16(ninlil_pa_nai1 + 4u) != 1u
        || pa_u16(ninlil_pa_nai1 + 6u) != sizeof(ninlil_pa_nai1)
        || memcmp(ninlil_pa_nax1, "NAX1", 4u) != 0
        || pa_u16(ninlil_pa_nax1 + 6u) != sizeof(ninlil_pa_nax1)
        || memcmp(ninlil_pa_nat1, "NAT1", 4u) != 0
        || pa_u16(ninlil_pa_nat1 + 6u) != sizeof(ninlil_pa_nat1)
        || memcmp(ninlil_pa_nat1 + 8u, ninlil_pa_install_digest, 32u) != 0) {
        return 0;
    }
    pa_sha256(ninlil_pa_nap1, sizeof(ninlil_pa_nap1), digest);
    if (memcmp(digest, ninlil_pa_nap1_sha, 32u) != 0) {
        return 0;
    }
    {
        uint8_t mut[sizeof(ninlil_pa_nap1)];
        uint8_t mut_digest[32];
        (void)memcpy(mut, ninlil_pa_nap1, sizeof(mut));
        mut[16] ^= 1u;
        pa_sha256(mut, sizeof(mut), mut_digest);
        if (memcmp(mut_digest, ninlil_pa_nap1_sha, 32u) == 0) {
            return 0;
        }
    }
    pa_exec(PA_CASE_BYTE_SHA);

    /* Proposal membership/lease/authority + NAP/NAI full wire leaf authority.
     * Independent constants match generator make_nap1/make_nai1; JSON length
     * scalars are represented here as sizeof(array) ↔ u16 length field pins.
     */
    {
        static const uint8_t e2e_security_id[16] = {
            0x50u, 0x51u, 0x52u, 0x53u, 0x54u, 0x55u, 0x56u, 0x57u,
            0x58u, 0x59u, 0x5au, 0x5bu, 0x5cu, 0x5du, 0x5eu, 0x5fu
        };
        static const uint8_t lease_clock_epoch[16] = {
            0x40u, 0x41u, 0x42u, 0x43u, 0x44u, 0x45u, 0x46u, 0x47u,
            0x48u, 0x49u, 0x4au, 0x4bu, 0x4cu, 0x4du, 0x4eu, 0x4fu
        };
        uint8_t membership_grant[32];
        uint8_t route_policy[32];
        uint8_t carrier_transcript[32];
        uint8_t filler_transcript[32];
        uint8_t initiator_stable[32];
        pa_sha256((const uint8_t *)"membership-grant", 16u, membership_grant);
        pa_sha256((const uint8_t *)"route-policy", 12u, route_policy);
        /* Normative §4.1: SHA-256(preimage), never SHA-256("carrier-transcript"). */
        pa_sha256(
            ninlil_pa_carrier_transcript_preimage,
            sizeof(ninlil_pa_carrier_transcript_preimage),
            carrier_transcript);
        pa_sha256((const uint8_t *)"carrier-transcript", 18u, filler_transcript);
        pa_sha256((const uint8_t *)"initiator-stable-id", 19u, initiator_stable);
        if (memcmp(carrier_transcript, filler_transcript, 32u) == 0
            || memcmp(
                carrier_transcript,
                ninlil_pa_carrier_transcript_digest,
                32u)
                != 0
            || sizeof(ninlil_pa_carrier_transcript_preimage) < 64u
            || memcmp(
                ninlil_pa_carrier_transcript_preimage,
                "NINLIL-PA-CARRIER-TRANSCRIPT-V1",
                31u)
                != 0
            || sizeof("NINLIL-PA-CARRIER-TRANSCRIPT-V1") - 1u != 31u) {
            return 0;
        }
        /* Field-negative matrix: independent preimage → digest recompute. */
        {
            size_t ni;
            size_t accepted = 0u;
            for (ni = 0u; ni < NINLIL_PA_CT_NEGATIVE_COUNT; ++ni) {
                const ninlil_pa_carrier_negative_t *neg =
                    &ninlil_pa_carrier_negatives[ni];
                uint8_t recomputed[32];
                if (neg->id == NULL || neg->digest == NULL) {
                    return 0;
                }
                if (neg->rejected) {
                    if (neg->preimage_len != 0u) {
                        return 0;
                    }
                    continue;
                }
                if (neg->preimage == NULL || neg->preimage_len == 0u) {
                    return 0;
                }
                pa_sha256(neg->preimage, neg->preimage_len, recomputed);
                if (memcmp(recomputed, neg->digest, 32u) != 0
                    || memcmp(recomputed, carrier_transcript, 32u) == 0
                    || !pa_any_nonzero(neg->digest, 32u)) {
                    return 0;
                }
                accepted += 1u;
            }
            if (accepted < 5u) {
                return 0;
            }
        }
        /* Length authority: array size ↔ embedded u16 ↔ normative constants. */
        if (sizeof(ninlil_pa_nap1) != 208u
            || pa_u16(ninlil_pa_nap1 + 6u) != 208u
            || sizeof(ninlil_pa_nai1) != 416u
            || pa_u16(ninlil_pa_nai1 + 6u) != 416u
            || sizeof(ninlil_pa_nax1) != 160u
            || pa_u16(ninlil_pa_nax1 + 6u) != 160u
            || sizeof(ninlil_pa_nat1) != 96u
            || pa_u16(ninlil_pa_nat1 + 6u) != 96u
            || sizeof(ninlil_pa_n6at_key) != 20u
            || sizeof(ninlil_pa_n6at_value) != 120u
            || (sizeof(ninlil_pa_install_seq6) - NINLIL_PA_NAC_HEADER_BYTES)
                != 424u
            || (sizeof(ninlil_pa_propose_seq5) - NINLIL_PA_NAC_HEADER_BYTES)
                != 216u
            || (sizeof(ninlil_pa_confirm_device_seq7)
                - NINLIL_PA_NAC_HEADER_BYTES)
                != 104u
            || (sizeof(ninlil_pa_confirm_authority_seq8)
                - NINLIL_PA_NAC_HEADER_BYTES)
                != 104u) {
            return 0;
        }
        /* NAP proposal_fields wire leaves. */
        if (memcmp(ninlil_pa_nap1 + 32u, initiator_stable, 32u) != 0
            || memcmp(ninlil_pa_nap1 + 152u, e2e_security_id, 16u) != 0
            || pa_u64(ninlil_pa_nap1 + 168u) != 73ull
            || memcmp(ninlil_pa_nap1 + 176u, membership_grant, 32u) != 0
            || pa_u32(ninlil_pa_nap1 + 128u) != NINLIL_PA_HOP_RI_CONTEXT_ID
            || pa_u32(ninlil_pa_nap1 + 132u) != NINLIL_PA_E2E_RI_CONTEXT_ID
            || pa_u64(ninlil_pa_nap1 + 136u) != NINLIL_PA_HOP_RI_KEY_GENERATION
            || pa_u64(ninlil_pa_nap1 + 144u) != NINLIL_PA_E2E_RI_KEY_GENERATION) {
            return 0;
        }
        /* NAI install_fields wire leaves previously unbound in JSON gates. */
        if (memcmp(ninlil_pa_nai1 + 32u, initiator_stable, 32u) != 0
            || memcmp(ninlil_pa_nai1 + 160u, lease_clock_epoch, 16u) != 0
            || pa_u32(ninlil_pa_nai1 + 200u) != 23u
            || pa_u32(ninlil_pa_nai1 + 204u) != 29u
            || pa_u32(ninlil_pa_nai1 + 220u) != NINLIL_PA_HOP_RI_CONTEXT_ID
            || pa_u32(ninlil_pa_nai1 + 228u) != NINLIL_PA_E2E_RI_CONTEXT_ID
            || pa_u64(ninlil_pa_nai1 + 240u) != NINLIL_PA_HOP_RI_KEY_GENERATION
            || memcmp(ninlil_pa_nai1 + 264u, e2e_security_id, 16u) != 0
            || pa_u64(ninlil_pa_nai1 + 280u) != 73ull
            || memcmp(ninlil_pa_nai1 + 288u, route_policy, 32u) != 0
            || memcmp(ninlil_pa_nai1 + 320u, membership_grant, 32u) != 0
            || memcmp(ninlil_pa_nai1 + 352u, carrier_transcript, 32u) != 0
            || memcmp(ninlil_pa_nai1 + 384u, ninlil_pa_nap1_sha, 32u) != 0
            || memcmp(ninlil_pa_nax1 + 100u, carrier_transcript, 32u) != 0) {
            return 0;
        }
        /* N6 marker role/state bytes (JSON local_role/state/state_name authority). */
        if (ninlil_pa_n6at_key[1] != 1u
            || ninlil_pa_n6at_value[8] != 2u
            || ninlil_pa_n6at_value[9] != 1u) {
            return 0;
        }
        /* Negative: type-preserving drift of wire-bound fields must diverge. */
        {
            uint8_t mut_nai[sizeof(ninlil_pa_nai1)];
            (void)memcpy(mut_nai, ninlil_pa_nai1, sizeof(mut_nai));
            mut_nai[200] ^= 1u; /* initiator_credential_generation */
            if (pa_u32(mut_nai + 200u) == 23u
                || memcmp(mut_nai + 352u, carrier_transcript, 32u) != 0) {
                return 0;
            }
            mut_nai[352] ^= 1u; /* carrier_transcript_digest */
            if (memcmp(mut_nai + 352u, carrier_transcript, 32u) == 0) {
                return 0;
            }
        }
    }
    pa_exec(PA_CASE_PROPOSAL_FIELDS);
    {
        uint8_t mut_nap[sizeof(ninlil_pa_nap1)];
        uint8_t mut_nai[sizeof(ninlil_pa_nai1)];
        uint8_t mut_nap_sha[32];
        uint8_t mut_install[32];
        uint8_t label[] = "NINLIL-PRODUCTION-ATTACH-INSTALL-V1";
        uint8_t input[sizeof(label) - 1u + sizeof(mut_nap) + sizeof(mut_nai)];
        (void)memcpy(mut_nap, ninlil_pa_nap1, sizeof(mut_nap));
        pa_put_u32(mut_nap + 128u, NINLIL_PA_HOP_RI_CONTEXT_ID ^ 0x5a5a5a5au);
        pa_sha256(mut_nap, sizeof(mut_nap), mut_nap_sha);
        (void)memcpy(mut_nai, ninlil_pa_nai1, sizeof(mut_nai));
        (void)memcpy(mut_nai + 384u, mut_nap_sha, 32u);
        (void)memcpy(input, label, sizeof(label) - 1u);
        (void)memcpy(input + (sizeof(label) - 1u), mut_nap, sizeof(mut_nap));
        (void)memcpy(
            input + (sizeof(label) - 1u) + sizeof(mut_nap),
            mut_nai,
            sizeof(mut_nai));
        pa_sha256(
            input,
            (sizeof(label) - 1u) + sizeof(mut_nap) + sizeof(mut_nai),
            mut_install);
        if (pa_u32(mut_nap + 128u) == NINLIL_PA_HOP_RI_CONTEXT_ID
            || pa_u32(mut_nap + 128u) == pa_u32(ninlil_pa_nai1 + 220u)
            || memcmp(mut_install, ninlil_pa_install_digest, 32u) == 0) {
            return 0;
        }
    }
    pa_exec(PA_CASE_NAP_NAI_MISMATCH);

    {
        static const char protect_label[] = "NINLIL-ATTACH-PROTECT-CONTEXT-V1";
        uint8_t ctx_input[sizeof(protect_label) - 1u + sizeof(ninlil_pa_nax1)];
        (void)memcpy(ctx_input, protect_label, sizeof(protect_label) - 1u);
        (void)memcpy(
            ctx_input + (sizeof(protect_label) - 1u),
            ninlil_pa_nax1,
            sizeof(ninlil_pa_nax1));
        pa_sha256(
            ctx_input,
            (sizeof(protect_label) - 1u) + sizeof(ninlil_pa_nax1),
            digest);
        if (memcmp(digest, ninlil_pa_protect_ctx_digest, 32u) != 0) {
            return 0;
        }
        ctx_input[0] ^= 1u;
        pa_sha256(
            ctx_input,
            (sizeof(protect_label) - 1u) + sizeof(ninlil_pa_nax1),
            digest);
        if (memcmp(digest, ninlil_pa_protect_ctx_digest, 32u) == 0) {
            return 0;
        }
    }
    pa_exec(PA_CASE_EXPORTER_CTX);

    /* Nonce = base_iv XOR (0||generation||sequence) for each protected seq. */
    {
        uint8_t mask[13];
        uint8_t expected[13];
        size_t i;
        (void)memset(mask, 0, sizeof(mask));
        pa_put_u64(mask + 1u, NINLIL_PA_EXCHANGE_GENERATION);
        pa_put_u32(mask + 9u, 5u);
        for (i = 0u; i < 13u; ++i) {
            expected[i] = (uint8_t)(ninlil_pa_i2r_iv[i] ^ mask[i]);
        }
        if (memcmp(expected, ninlil_pa_nonce_propose_i2r_seq5, 13u) != 0) {
            return 0;
        }
        pa_put_u32(mask + 9u, 6u);
        for (i = 0u; i < 13u; ++i) {
            expected[i] = (uint8_t)(ninlil_pa_r2i_iv[i] ^ mask[i]);
        }
        if (memcmp(expected, ninlil_pa_nonce_install_r2i_seq6, 13u) != 0) {
            return 0;
        }
        pa_put_u32(mask + 9u, 7u);
        for (i = 0u; i < 13u; ++i) {
            expected[i] = (uint8_t)(ninlil_pa_i2r_iv[i] ^ mask[i]);
        }
        if (memcmp(expected, ninlil_pa_nonce_confirm_device_i2r_seq7, 13u)
            != 0) {
            return 0;
        }
        pa_put_u32(mask + 9u, 8u);
        for (i = 0u; i < 13u; ++i) {
            expected[i] = (uint8_t)(ninlil_pa_r2i_iv[i] ^ mask[i]);
        }
        if (memcmp(expected, ninlil_pa_nonce_confirm_authority_r2i_seq8, 13u)
            != 0) {
            return 0;
        }
    }
    pa_exec(PA_CASE_NONCE);

    pa_sha256(ninlil_pa_wifi_canonical, sizeof(ninlil_pa_wifi_canonical), digest);
    if (memcmp(digest, ninlil_pa_wifi_digest, 32u) != 0) {
        return 0;
    }
    {
        uint8_t mut[sizeof(ninlil_pa_wifi_canonical)];
        (void)memcpy(mut, ninlil_pa_wifi_canonical, sizeof(mut));
        mut[0] ^= 1u;
        pa_sha256(mut, sizeof(mut), digest);
        if (memcmp(digest, ninlil_pa_wifi_digest, 32u) == 0) {
            return 0;
        }
    }
    pa_exec(PA_CASE_CARRIER_PIN);
    pa_exec(PA_CASE_WIFI_MUT);

    if (!pa_ccs_decode(
            ninlil_pa_initiator_ccs,
            sizeof(ninlil_pa_initiator_ccs),
            ninlil_pa_initiator_kid,
            sizeof(ninlil_pa_initiator_kid),
            ninlil_pa_initiator_x,
            ninlil_pa_initiator_y)
        || !pa_ccs_decode(
            ninlil_pa_responder_ccs,
            sizeof(ninlil_pa_responder_ccs),
            ninlil_pa_responder_kid,
            sizeof(ninlil_pa_responder_kid),
            ninlil_pa_responder_x,
            ninlil_pa_responder_y)) {
        return 0;
    }
    pa_exec(PA_CASE_CREDENTIAL_CCS);
    pa_sha256(
        ninlil_pa_initiator_ccs, sizeof(ninlil_pa_initiator_ccs), digest);
    if (memcmp(digest, ninlil_pa_initiator_cred_digest, 32u) != 0
        || memcmp(ninlil_pa_nax1 + 36u, ninlil_pa_initiator_cred_digest, 32u)
            != 0
        || memcmp(ninlil_pa_nax1 + 68u, ninlil_pa_responder_cred_digest, 32u)
            != 0) {
        return 0;
    }
    pa_exec(PA_CASE_CREDENTIAL);
    {
        uint8_t mut_ccs[sizeof(ninlil_pa_initiator_ccs)];
        uint8_t mut_digest[32];
        (void)memcpy(mut_ccs, ninlil_pa_initiator_ccs, sizeof(mut_ccs));
        mut_ccs[sizeof(mut_ccs) - 1u] ^= 1u;
        pa_sha256(mut_ccs, sizeof(mut_ccs), mut_digest);
        if (memcmp(mut_digest, ninlil_pa_initiator_cred_digest, 32u) == 0
            || pa_ccs_decode(
                mut_ccs,
                sizeof(mut_ccs),
                ninlil_pa_initiator_kid,
                sizeof(ninlil_pa_initiator_kid),
                ninlil_pa_initiator_x,
                ninlil_pa_initiator_y)) {
            return 0;
        }
    }
    pa_exec(PA_CASE_CREDENTIAL_TAIL);

    if (!pa_n6at_validate(
            ninlil_pa_n6at_pending_key,
            ninlil_pa_n6at_pending_value,
            1u,
            1u)
        || ninlil_pa_n6at_pending_value[8] != 1u) {
        return 0;
    }
    pa_exec(PA_CASE_N6AT_PENDING);

    if (!pa_n6at_validate(ninlil_pa_n6at_key, ninlil_pa_n6at_value, 1u, 2u)
        || ninlil_pa_n6at_value[8] != 2u
        || memcmp(
            ninlil_pa_n6at_pending_value + 12u,
            ninlil_pa_n6at_value + 12u,
            16u)
            != 0
        || memcmp(
            ninlil_pa_n6at_pending_value + 84u,
            ninlil_pa_n6at_value + 84u,
            32u)
            != 0) {
        return 0;
    }
    pa_exec(PA_CASE_N6AT_P2A);

    if (ninlil_pa_n6at_third_value[8] != 3u
        || pa_n6at_validate(
            ninlil_pa_n6at_pending_key, ninlil_pa_n6at_third_value, 1u, 2u)) {
        return 0;
    }
    pa_exec(PA_CASE_N6AT_COMMIT_UNKNOWN);

    if (!pa_n6at_validate(
            ninlil_pa_n6at_authority_pending_key,
            ninlil_pa_n6at_authority_pending_value,
            2u,
            1u)
        || !pa_n6at_validate(
            ninlil_pa_n6at_authority_active_key,
            ninlil_pa_n6at_authority_active_value,
            2u,
            2u)
        || ninlil_pa_n6at_authority_pending_key[1] != 2u
        || ninlil_pa_n6at_key[1] != 1u) {
        return 0;
    }
    pa_exec(PA_CASE_N6AT_ROLE_BOTH);

    /* Lifecycle: independent hard-rule digests (not fixture self-compare). */
    {
        size_t role;
        for (role = 0u; role < 2u; ++role) {
            const ninlil_pa_nab_identity_t *inv =
                (role == 0u) ? ninlil_pa_nab_device_inventory
                             : ninlil_pa_nab_authority_inventory;
            const uint8_t *marker_key =
                (role == 0u) ? ninlil_pa_n6at_pending_key
                             : ninlil_pa_n6at_authority_pending_key;
            const uint8_t *pending_marker_value =
                (role == 0u) ? ninlil_pa_n6at_pending_value
                             : ninlil_pa_n6at_authority_pending_value;
            const uint8_t *active_marker_value =
                (role == 0u) ? ninlil_pa_n6at_value
                             : ninlil_pa_n6at_authority_active_value;
            const uint8_t *const full_image_sha =
                (role == 0u) ? ninlil_pa_device_full_image_sha256
                             : ninlil_pa_authority_full_image_sha256;
            const uint8_t *keys[16];
            size_t lens[16];
            uint8_t exp_vs_pending[15][32];
            uint8_t exp_cd[15][32];
            uint8_t exp_vs_active[15][32];
            uint8_t present_vs_store[15][32];
            uint8_t present_cd_store[15][32];
            const uint8_t *present_vs[15];
            const uint8_t *present_cd[15];
            uint8_t mut_value_digest[32];
            uint8_t mut_ctx_digest[32];
            uint8_t value_scratch[120];
            uint8_t local_node[16];
            uint8_t peer_node[16];
            char label[40];
            size_t i;
            size_t subst_idx = 0u;
            size_t marker_idx = 15u;

            /* Node ids from NAI1 stable digests (independent of fixture values). */
            {
                const uint8_t *init_stable = ninlil_pa_nai1 + 32u;
                const uint8_t *resp_stable = ninlil_pa_nai1 + 64u;
                if (role == 0u) {
                    pa_node_id_from_stable(init_stable, local_node);
                    pa_node_id_from_stable(resp_stable, peer_node);
                } else {
                    pa_node_id_from_stable(resp_stable, local_node);
                    pa_node_id_from_stable(init_stable, peer_node);
                }
            }
            /*
             * Key-presence empty is NOT re-attach EXACT_OLD (P0 fix).
             * Value-image EXACT_OLD uses 14 non-marker codec OLD rows below.
             */
            if (!pa_classify_group(
                    NULL,
                    NULL,
                    0u,
                    inv,
                    marker_key,
                    -1,
                    1,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    label)
                || memcmp(label, "EXACT_OLD_COLD_OR_EMPTY_PRESENT", 30) != 0) {
                return 0;
            }
            /* Key-presence partials are NOT authority; value-image partials below. */
            /* Per-row EXACT_OLD: 6 lane + 4 AL + 4 HW; marker absent. */
            {
                const ninlil_pa_old_member_t *old_fix =
                    (role == 0u) ? ninlil_pa_device_old_members
                                 : ninlil_pa_authority_old_members;
                const size_t old_count =
                    (role == 0u) ? NINLIL_PA_DEVICE_OLD_MEMBER_COUNT
                                 : NINLIL_PA_AUTHORITY_OLD_MEMBER_COUNT;
                size_t al = 0u;
                size_t hw = 0u;
                size_t lane = 0u;
                size_t oi;
                if (old_count != 14u) {
                    return 0;
                }
                for (oi = 0u; oi < old_count; ++oi) {
                    uint8_t recomputed[120];
                    uint8_t dig[32];
                    uint8_t old_ctx[32];
                    const ninlil_pa_old_member_t *om = &old_fix[oi];
                    const ninlil_pa_nab_identity_t *match = NULL;
                    size_t j;
                    if (om->member_kind == 2u) {
                        al += 1u;
                    } else if (om->member_kind == 3u) {
                        hw += 1u;
                    } else if (om->member_kind == 1u) {
                        lane += 1u;
                    } else {
                        return 0; /* marker must be OLD-absent */
                    }
                    for (j = 0u; j < 15u; ++j) {
                        if (inv[j].complete_key_length == om->complete_key_length
                            && memcmp(
                                   inv[j].complete_key,
                                   om->complete_key,
                                   om->complete_key_length)
                                == 0) {
                            match = &inv[j];
                            break;
                        }
                    }
                    if (match == NULL) {
                        return 0;
                    }
                    if (!pa_materialize_member_value(
                            om->member_kind,
                            om->complete_key,
                            om->complete_key_length,
                            ninlil_pa_install_digest,
                            om->value_bytes,
                            NULL,
                            match->local_side,
                            match->key_generation,
                            NINLIL_PA_MEMBERSHIP_EPOCH,
                            1, /* OLD */
                            local_node,
                            peer_node,
                            match->context_id,
                            match->layer_code,
                            recomputed)
                        || memcmp(recomputed, om->value, om->value_bytes) != 0) {
                        return 0;
                    }
                    pa_sha256(recomputed, om->value_bytes, dig);
                    if (memcmp(dig, om->value_sha256, 32u) != 0
                        || !pa_materialize_old_context_digest(
                            om->member_kind,
                            om->complete_key,
                            om->complete_key_length,
                            ninlil_pa_attachment_id,
                            old_ctx)
                        || memcmp(om->context_digest, old_ctx, 32u) != 0) {
                        return 0;
                    }
                }
                if (lane != 6u || al != 4u || hw != 4u) {
                    return 0;
                }
            }
            /* Independently recompute all 15 expected digests (N6 codec). */
            for (i = 0u; i < 15u; ++i) {
                keys[i] = inv[i].complete_key;
                lens[i] = inv[i].complete_key_length;
                if (inv[i].member_kind != 4u) {
                    subst_idx = i;
                } else {
                    marker_idx = i;
                }
                if (!pa_materialize_member_value(
                        inv[i].member_kind,
                        inv[i].complete_key,
                        inv[i].complete_key_length,
                        ninlil_pa_install_digest,
                        inv[i].value_bytes,
                        pending_marker_value,
                        inv[i].local_side,
                        inv[i].key_generation,
                        NINLIL_PA_MEMBERSHIP_EPOCH,
                        0,
                        local_node,
                        peer_node,
                        inv[i].context_id,
                        inv[i].layer_code,
                        value_scratch)) {
                    return 0;
                }
                /* Non-marker must be canonical N6 magic + CRC. */
                if (inv[i].member_kind != 4u) {
                    uint32_t magic = pa_u32(value_scratch);
                    if (magic != PA_N6_MAGIC_TX && magic != PA_N6_MAGIC_RX
                        && magic != PA_N6_MAGIC_AL && magic != PA_N6_MAGIC_HW) {
                        return 0;
                    }
                }
                pa_sha256(value_scratch, inv[i].value_bytes, exp_vs_pending[i]);
                if (!pa_materialize_context_digest(
                        inv[i].member_kind,
                        inv[i].complete_key,
                        inv[i].complete_key_length,
                        ninlil_pa_install_digest,
                        ninlil_pa_attachment_id,
                        exp_cd[i])) {
                    return 0;
                }
                /*
                 * Fixture observed digests must match independent recompute.
                 * Synthetic VALUE-V1 filler or CODEC drift fails here.
                 */
                if (inv[i].value_sha256 == NULL || inv[i].context_digest == NULL
                    || memcmp(inv[i].value_sha256, exp_vs_pending[i], 32u) != 0
                    || memcmp(inv[i].context_digest, exp_cd[i], 32u) != 0) {
                    return 0;
                }
                (void)memcpy(exp_vs_active[i], exp_vs_pending[i], 32u);
                (void)memcpy(present_vs_store[i], exp_vs_pending[i], 32u);
                (void)memcpy(present_cd_store[i], exp_cd[i], 32u);
                present_vs[i] = present_vs_store[i];
                present_cd[i] = present_cd_store[i];
            }
            if (marker_idx >= 15u || !pa_any_nonzero(full_image_sha, 32u)) {
                return 0;
            }
            /* Value-image parity with Py/Node: OLD / PARTIAL / NEW from fixtures. */
            {
                const ninlil_pa_old_member_t *old_fix =
                    (role == 0u) ? ninlil_pa_device_old_members
                                 : ninlil_pa_authority_old_members;
                const size_t old_count =
                    (role == 0u) ? NINLIL_PA_DEVICE_OLD_MEMBER_COUNT
                                 : NINLIL_PA_AUTHORITY_OLD_MEMBER_COUNT;
                const uint8_t *ws_keys[15];
                size_t ws_lens[15];
                const uint8_t *old_keys[15];
                size_t old_lens[15];
                const uint8_t *old_vs[15];
                const uint8_t *old_cd[15];
                const uint8_t *new_vs[15];
                const uint8_t *new_cd[15];
                const uint8_t *p_keys[15];
                size_t p_lens[15];
                const uint8_t *p_vs[15];
                const uint8_t *p_cd[15];
                size_t oi;
                size_t advanced;
                size_t present_n;
                for (i = 0u; i < 15u; ++i) {
                    ws_keys[i] = inv[i].complete_key;
                    ws_lens[i] = inv[i].complete_key_length;
                    new_vs[i] = exp_vs_pending[i];
                    new_cd[i] = exp_cd[i];
                }
                if (old_count != 14u) {
                    return 0;
                }
                for (oi = 0u; oi < old_count; ++oi) {
                    old_keys[oi] = old_fix[oi].complete_key;
                    old_lens[oi] = old_fix[oi].complete_key_length;
                    old_vs[oi] = old_fix[oi].value_sha256;
                    old_cd[oi] = old_fix[oi].context_digest;
                    p_keys[oi] = old_fix[oi].complete_key;
                    p_lens[oi] = old_fix[oi].complete_key_length;
                    p_vs[oi] = old_fix[oi].value_sha256;
                    p_cd[oi] = old_fix[oi].context_digest;
                }
                if (!pa_classify_write_set_value_image(
                        ws_keys,
                        ws_lens,
                        15u,
                        p_keys,
                        p_lens,
                        p_vs,
                        p_cd,
                        old_count,
                        old_keys,
                        old_lens,
                        old_vs,
                        old_cd,
                        old_count,
                        new_vs,
                        new_cd,
                        marker_key,
                        20u,
                        label)
                    || memcmp(label, "EXACT_OLD", 9) != 0) {
                    return 0;
                }
                /* PARTIAL_n: first n write-set keys at NEW; rest at OLD/absent. */
                for (advanced = 1u; advanced <= 14u; ++advanced) {
                    present_n = 0u;
                    for (i = 0u; i < 15u; ++i) {
                        if (i < advanced) {
                            p_keys[present_n] = inv[i].complete_key;
                            p_lens[present_n] = inv[i].complete_key_length;
                            p_vs[present_n] = exp_vs_pending[i];
                            p_cd[present_n] = exp_cd[i];
                            present_n += 1u;
                        } else {
                            /* keep OLD if present in observed OLD set */
                            for (oi = 0u; oi < old_count; ++oi) {
                                if (old_lens[oi] == inv[i].complete_key_length
                                    && memcmp(
                                           old_keys[oi],
                                           inv[i].complete_key,
                                           inv[i].complete_key_length)
                                        == 0) {
                                    p_keys[present_n] = old_keys[oi];
                                    p_lens[present_n] = old_lens[oi];
                                    p_vs[present_n] = old_vs[oi];
                                    p_cd[present_n] = old_cd[oi];
                                    present_n += 1u;
                                    break;
                                }
                            }
                        }
                    }
                    if (!pa_classify_write_set_value_image(
                            ws_keys,
                            ws_lens,
                            15u,
                            p_keys,
                            p_lens,
                            p_vs,
                            p_cd,
                            present_n,
                            old_keys,
                            old_lens,
                            old_vs,
                            old_cd,
                            old_count,
                            new_vs,
                            new_cd,
                            marker_key,
                            20u,
                            label)) {
                        return 0;
                    }
                    {
                        char want[40];
                        (void)snprintf(
                            want, sizeof(want), "PARTIAL_%u_CORRUPT", (unsigned)advanced);
                        if (memcmp(label, want, strlen(want) + 1u) != 0) {
                            return 0;
                        }
                    }
                }
                /* EXACT_NEW pending: all 15 at NEW digests. */
                for (i = 0u; i < 15u; ++i) {
                    p_keys[i] = inv[i].complete_key;
                    p_lens[i] = inv[i].complete_key_length;
                    p_vs[i] = exp_vs_pending[i];
                    p_cd[i] = exp_cd[i];
                }
                if (!pa_classify_write_set_value_image(
                        ws_keys,
                        ws_lens,
                        15u,
                        p_keys,
                        p_lens,
                        p_vs,
                        p_cd,
                        15u,
                        old_keys,
                        old_lens,
                        old_vs,
                        old_cd,
                        old_count,
                        new_vs,
                        new_cd,
                        marker_key,
                        20u,
                        label)
                    || memcmp(label, "EXACT_NEW_PENDING_15", 19) != 0) {
                    return 0;
                }
            }
            /* Active marker value digest from actual active marker bytes. */
            pa_sha256(active_marker_value, 120u, exp_vs_active[marker_idx]);
            /* Permanent negative: VALUE-V1 filler must not equal N6 codec. */
            {
                uint8_t filler[120];
                uint8_t codec[120];
                const ninlil_pa_nab_identity_t *row = &inv[subst_idx];
                if (!pa_materialize_value_v1_filler(
                        row->member_kind,
                        row->complete_key,
                        row->complete_key_length,
                        ninlil_pa_install_digest,
                        row->value_bytes,
                        filler)
                    || !pa_materialize_member_value(
                        row->member_kind,
                        row->complete_key,
                        row->complete_key_length,
                        ninlil_pa_install_digest,
                        row->value_bytes,
                        NULL,
                        row->local_side,
                        row->key_generation,
                        NINLIL_PA_MEMBERSHIP_EPOCH,
                        0,
                        local_node,
                        peer_node,
                        row->context_id,
                        row->layer_code,
                        codec)
                    || memcmp(filler, codec, row->value_bytes) == 0) {
                    return 0;
                }
                /* Also ensure OLD phase differs for AL/HW (monotonic floors). */
                if (row->member_kind == 2u || row->member_kind == 3u) {
                    uint8_t old_val[120];
                    if (!pa_materialize_member_value(
                            row->member_kind,
                            row->complete_key,
                            row->complete_key_length,
                            ninlil_pa_install_digest,
                            row->value_bytes,
                            NULL,
                            row->local_side,
                            row->key_generation,
                            NINLIL_PA_MEMBERSHIP_EPOCH,
                            1,
                            local_node,
                            peer_node,
                            row->context_id,
                            row->layer_code,
                            old_val)
                        || memcmp(old_val, codec, row->value_bytes) == 0) {
                        return 0;
                    }
                }
            }

            
            /* repaired CRC adversarial: flip value CRC; digest must not match fixture. */
            {
                uint8_t bad[120];
                uint8_t dig[32];
                const ninlil_pa_nab_identity_t *row = &inv[subst_idx];
                if (!pa_materialize_member_value(
                        row->member_kind,
                        row->complete_key,
                        row->complete_key_length,
                        ninlil_pa_install_digest,
                        row->value_bytes,
                        NULL,
                        row->local_side,
                        row->key_generation,
                        NINLIL_PA_MEMBERSHIP_EPOCH,
                        0,
                        local_node,
                        peer_node,
                        row->context_id,
                        row->layer_code,
                        bad)) {
                    return 0;
                }
                bad[row->value_bytes - 1u] ^= 1u;
                pa_sha256(bad, row->value_bytes, dig);
                if (row->value_sha256 != NULL
                    && memcmp(dig, row->value_sha256, 32u) == 0) {
                    return 0;
                }
            }

            if (!pa_classify_group(
                    keys,
                    lens,
                    15u,
                    inv,
                    marker_key,
                    1,
                    1,
                    present_vs,
                    present_cd,
                    &exp_vs_pending[0][0],
                    &exp_cd[0][0],
                    label)
                || memcmp(label, "EXACT_NEW_PENDING_15", 19) != 0) {
                return 0;
            }
            /* Active lifecycle: present carries active marker digest. */
            (void)memcpy(
                present_vs_store[marker_idx], exp_vs_active[marker_idx], 32u);
            if (!pa_classify_group(
                    keys,
                    lens,
                    15u,
                    inv,
                    marker_key,
                    2,
                    1,
                    present_vs,
                    present_cd,
                    &exp_vs_active[0][0],
                    &exp_cd[0][0],
                    label)
                || memcmp(label, "EXACT_NEW_ACTIVE_MARKER_IN_15", 28) != 0) {
                return 0;
            }
            /* Same-key value substitution (pending + active). */
            (void)memcpy(mut_value_digest, present_vs_store[subst_idx], 32u);
            mut_value_digest[0] ^= 1u;
            present_vs[subst_idx] = mut_value_digest;
            (void)memcpy(
                present_vs_store[marker_idx], exp_vs_pending[marker_idx], 32u);
            present_vs[marker_idx] = present_vs_store[marker_idx];
            if (!pa_classify_group(
                    keys,
                    lens,
                    15u,
                    inv,
                    marker_key,
                    1,
                    1,
                    present_vs,
                    present_cd,
                    &exp_vs_pending[0][0],
                    &exp_cd[0][0],
                    label)
                || memcmp(
                    label, "VALUE_OR_CONTEXT_DIGEST_MISMATCH_CORRUPT", 39)
                    != 0) {
                return 0;
            }
            (void)memcpy(
                present_vs_store[marker_idx], exp_vs_active[marker_idx], 32u);
            present_vs[marker_idx] = present_vs_store[marker_idx];
            if (!pa_classify_group(
                    keys,
                    lens,
                    15u,
                    inv,
                    marker_key,
                    2,
                    1,
                    present_vs,
                    present_cd,
                    &exp_vs_active[0][0],
                    &exp_cd[0][0],
                    label)
                || memcmp(
                    label, "VALUE_OR_CONTEXT_DIGEST_MISMATCH_CORRUPT", 39)
                    != 0) {
                return 0;
            }
            present_vs[subst_idx] = present_vs_store[subst_idx];
            (void)memcpy(
                present_vs_store[subst_idx], exp_vs_pending[subst_idx], 32u);
            /* Same-key context substitution (pending + active). */
            (void)memcpy(mut_ctx_digest, present_cd_store[subst_idx], 32u);
            mut_ctx_digest[0] ^= 1u;
            present_cd[subst_idx] = mut_ctx_digest;
            (void)memcpy(
                present_vs_store[marker_idx], exp_vs_pending[marker_idx], 32u);
            present_vs[marker_idx] = present_vs_store[marker_idx];
            if (!pa_classify_group(
                    keys,
                    lens,
                    15u,
                    inv,
                    marker_key,
                    1,
                    1,
                    present_vs,
                    present_cd,
                    &exp_vs_pending[0][0],
                    &exp_cd[0][0],
                    label)
                || memcmp(
                    label, "VALUE_OR_CONTEXT_DIGEST_MISMATCH_CORRUPT", 39)
                    != 0) {
                return 0;
            }
            (void)memcpy(
                present_vs_store[marker_idx], exp_vs_active[marker_idx], 32u);
            present_vs[marker_idx] = present_vs_store[marker_idx];
            if (!pa_classify_group(
                    keys,
                    lens,
                    15u,
                    inv,
                    marker_key,
                    2,
                    1,
                    present_vs,
                    present_cd,
                    &exp_vs_active[0][0],
                    &exp_cd[0][0],
                    label)
                || memcmp(
                    label, "VALUE_OR_CONTEXT_DIGEST_MISMATCH_CORRUPT", 39)
                    != 0) {
                return 0;
            }
            present_cd[subst_idx] = present_cd_store[subst_idx];
            (void)memcpy(
                present_vs_store[marker_idx], exp_vs_pending[marker_idx], 32u);
            present_vs[marker_idx] = present_vs_store[marker_idx];

            /* extra/foreign: semantic foreign key outside write-set (value-image). */
            {
                static uint8_t foreign[48];
                uint8_t f_vs[32];
                uint8_t f_cd[32];
                (void)memcpy(
                    foreign, inv[0].complete_key, inv[0].complete_key_length);
                foreign[0] ^= 0x80u;
                (void)memcpy(f_vs, exp_vs_pending[0], 32u);
                (void)memcpy(f_cd, exp_cd[0], 32u);
                /* write-set value-image with foreign present → FOREIGN */
                {
                    /* Reuse pa_classify_write_set with 15 write-set + foreign present:
                     * present includes foreign key not in write-set. */
                    const uint8_t *ws_keys[15];
                    size_t ws_lens[15];
                    const uint8_t *p_keys[16];
                    size_t p_lens[16];
                    const uint8_t *p_vs[16];
                    const uint8_t *p_cd[16];
                    const uint8_t *old_k[15];
                    size_t old_l[15];
                    const uint8_t *old_v[15];
                    const uint8_t *old_c[15];
                    const uint8_t *new_v[15];
                    const uint8_t *new_c[15];
                    const ninlil_pa_old_member_t *old_fix =
                        (role == 0u) ? ninlil_pa_device_old_members
                                     : ninlil_pa_authority_old_members;
                    size_t old_count =
                        (role == 0u) ? NINLIL_PA_DEVICE_OLD_MEMBER_COUNT
                                     : NINLIL_PA_AUTHORITY_OLD_MEMBER_COUNT;
                    size_t oi;
                    for (i = 0u; i < 15u; ++i) {
                        ws_keys[i] = inv[i].complete_key;
                        ws_lens[i] = inv[i].complete_key_length;
                        new_v[i] = exp_vs_pending[i];
                        new_c[i] = exp_cd[i];
                        p_keys[i] = inv[i].complete_key;
                        p_lens[i] = inv[i].complete_key_length;
                        p_vs[i] = present_vs[i];
                        p_cd[i] = present_cd[i];
                    }
                    p_keys[15] = foreign;
                    p_lens[15] = inv[0].complete_key_length;
                    p_vs[15] = f_vs;
                    p_cd[15] = f_cd;
                    for (oi = 0u; oi < old_count && oi < 15u; ++oi) {
                        old_k[oi] = old_fix[oi].complete_key;
                        old_l[oi] = old_fix[oi].complete_key_length;
                        old_v[oi] = old_fix[oi].value_sha256;
                        old_c[oi] = old_fix[oi].context_digest;
                    }
                    if (!pa_classify_write_set_value_image(
                            ws_keys,
                            ws_lens,
                            15u,
                            p_keys,
                            p_lens,
                            p_vs,
                            p_cd,
                            16u,
                            old_k,
                            old_l,
                            old_v,
                            old_c,
                            old_count,
                            new_v,
                            new_c,
                            marker_key,
                            20u,
                            label)
                        || memcmp(label, "FOREIGN_OR_EXTRA_CORRUPT", 24) != 0) {
                        return 0;
                    }
                }
            }
            if (!pa_classify_group(
                    keys,
                    lens,
                    15u,
                    inv,
                    marker_key,
                    3,
                    0,
                    present_vs,
                    present_cd,
                    &exp_vs_pending[0][0],
                    &exp_cd[0][0],
                    label)
                || memcmp(label, "THIRD_OR_MISMATCH_CORRUPT", 24) != 0) {
                return 0;
            }
            /* Device active value alias for role 0 is ninlil_pa_n6at_value. */
            if (role == 0u
                && memcmp(
                    active_marker_value, ninlil_pa_n6at_value, 120u)
                    != 0) {
                return 0;
            }
        }
    }
    pa_exec(PA_CASE_LIFECYCLE_GROUP);

    if (NINLIL_PA_PUBLICATION_BEFORE_DUAL_CONFIRM != 0u) {
        return 0;
    }
    pa_exec(PA_CASE_PUBLICATION_ZERO);

    if (!pa_nab_validate(ninlil_pa_nab1_device, 1u, 1)
        || !pa_nab_validate(ninlil_pa_nab1_authority, 2u, 1)) {
        return 0;
    }
    pa_exec(PA_CASE_NAB_15);
    {
        size_t i;
        int seen_device = 0;
        int seen_auth = 0;
        for (i = 0u; i < NINLIL_PA_NAB_ENTRY_COUNT; ++i) {
            const ninlil_pa_nab_identity_t *d =
                &ninlil_pa_nab_device_inventory[i];
            const ninlil_pa_nab_identity_t *a =
                &ninlil_pa_nab_authority_inventory[i];
            if (d->complete_key == NULL || a->complete_key == NULL) {
                return 0;
            }
            if (d->member_kind == 1u && d->direction == 0u && d->lane == 1u) {
                if (d->context_id != NINLIL_PA_HOP_IR_CONTEXT_ID
                    || d->key_generation != NINLIL_PA_HOP_IR_KEY_GENERATION) {
                    return 0;
                }
                seen_device = 1;
            }
            if (a->member_kind == 1u && a->direction == 0u && a->lane == 1u) {
                if (a->context_id != NINLIL_PA_HOP_IR_CONTEXT_ID
                    || a->key_generation != NINLIL_PA_HOP_IR_KEY_GENERATION) {
                    return 0;
                }
                /* authority local_side for IR is INBOUND (1), device is OUTBOUND (2) */
                if (a->local_side == d->local_side) {
                    return 0;
                }
                seen_auth = 1;
            }
            if (d->member_kind == 1u && d->direction == 1u && d->lane == 1u) {
                if (d->context_id != NINLIL_PA_HOP_RI_CONTEXT_ID
                    || d->key_generation != NINLIL_PA_HOP_RI_KEY_GENERATION) {
                    return 0;
                }
            }
            if (d->member_kind == 1u && d->direction == 0u && d->lane == 3u) {
                if (d->context_id != NINLIL_PA_E2E_IR_CONTEXT_ID
                    || d->key_generation != NINLIL_PA_E2E_IR_KEY_GENERATION) {
                    return 0;
                }
            }
            if (d->member_kind == 1u && d->direction == 1u && d->lane == 3u) {
                if (d->context_id != NINLIL_PA_E2E_RI_CONTEXT_ID
                    || d->key_generation != NINLIL_PA_E2E_RI_KEY_GENERATION) {
                    return 0;
                }
            }
        }
        if (!seen_device || !seen_auth) {
            return 0;
        }
    }
    pa_exec(PA_CASE_NAB_IDENTITY);
    /* Authority raw complete-key canonical order exercised (non-NULL keys). */
    {
        size_t i;
        for (i = 1u; i < NINLIL_PA_NAB_ENTRY_COUNT; ++i) {
            const ninlil_pa_nab_identity_t *prev =
                &ninlil_pa_nab_authority_inventory[i - 1u];
            const ninlil_pa_nab_identity_t *cur =
                &ninlil_pa_nab_authority_inventory[i];
            size_t min_len = prev->complete_key_length;
            int cmp;
            if (cur->complete_key_length < min_len) {
                min_len = cur->complete_key_length;
            }
            cmp = memcmp(prev->complete_key, cur->complete_key, min_len);
            if (cmp > 0
                || (cmp == 0
                    && prev->complete_key_length
                        >= cur->complete_key_length)) {
                return 0;
            }
        }
    }
    pa_exec(PA_CASE_NAB_ORDER);

    assembled_size = 0u;
    for (index = 0u; index < NINLIL_PA_FRAGMENT_COUNT; ++index) {
        const ninlil_pa_fixture_span_t *fragment = &ninlil_pa_fragments[index];
        size_t payload_size;
        if (!pa_nar_validate(fragment->data, fragment->size)
            || fragment->data[42] != index
            || fragment->data[43] != NINLIL_PA_FRAGMENT_COUNT) {
            return 0;
        }
        payload_size = fragment->size - NINLIL_PA_NAR_HEADER_BYTES;
        if (assembled_size > sizeof(assembled) - payload_size) {
            return 0;
        }
        (void)memcpy(
            assembled + assembled_size,
            fragment->data + NINLIL_PA_NAR_HEADER_BYTES,
            payload_size);
        assembled_size += payload_size;
    }
    if (assembled_size != sizeof(ninlil_pa_install_seq6)
        || memcmp(assembled, ninlil_pa_install_seq6, assembled_size) != 0) {
        return 0;
    }
    pa_sha256(assembled, assembled_size, digest);
    for (index = 0u; index < NINLIL_PA_FRAGMENT_COUNT; ++index) {
        if (memcmp(ninlil_pa_fragments[index].data + 44u, digest, 16u) != 0
            || memcmp(
                ninlil_pa_fragments[index].data + 12u,
                assembled + 20u,
                16u)
                != 0
            || pa_u64(ninlil_pa_fragments[index].data + 28u)
                != pa_u64(assembled + 36u)
            || pa_u64(ninlil_pa_fragments[index].data + 28u)
                != NINLIL_PA_EXCHANGE_GENERATION) {
            return 0;
        }
    }
    pa_exec(PA_CASE_INSTALL_FRAG);
    if (!pa_nar_fragment_shape_authority()) {
        return 0;
    }
    pa_exec(PA_CASE_NAR_CANONICAL_SHAPE);
    pa_exec(PA_CASE_NAR_GENERATION);

    /*
     * RFC literal KAT: C-source independent exact bytes + digest + semantic
     * fields (method=3). Fixture must match literal; 03→04 coherent drift
     * must not satisfy the pin.
     */
    if (sizeof(ninlil_pa_rfc_message_1) != sizeof(g_pa_rfc_m1_literal)
        || memcmp(
            ninlil_pa_rfc_message_1,
            g_pa_rfc_m1_literal,
            sizeof(g_pa_rfc_m1_literal))
            != 0
        || memcmp(
            ninlil_pa_rfc_message_1_sha,
            g_pa_rfc_m1_literal_sha,
            32u)
            != 0) {
        return 0;
    }
    pa_sha256(g_pa_rfc_m1_literal, sizeof(g_pa_rfc_m1_literal), digest);
    if (memcmp(digest, g_pa_rfc_m1_literal_sha, 32u) != 0) {
        return 0;
    }
    if (g_pa_rfc_m1_literal[0] != (uint8_t)PA_RFC_M1_METHOD
        || g_pa_rfc_m1_literal[0] == 0x04u
        || g_pa_rfc_m1_literal[3] != (uint8_t)PA_RFC_M1_SUITE_HINT) {
        return 0;
    }
    {
        uint8_t mut[sizeof(g_pa_rfc_m1_literal)];
        uint8_t mut_sha[32];
        (void)memcpy(mut, g_pa_rfc_m1_literal, sizeof(mut));
        /* 03 → 04 coherent drift: recompute digest; still not pin-equal. */
        mut[0] = 0x04u;
        pa_sha256(mut, sizeof(mut), mut_sha);
        if (mut[0] == g_pa_rfc_m1_literal[0]
            || memcmp(mut, g_pa_rfc_m1_literal, sizeof(mut)) == 0
            || memcmp(mut_sha, g_pa_rfc_m1_literal_sha, 32u) == 0
            || memcmp(mut, ninlil_pa_rfc_message_1, sizeof(mut)) == 0) {
            return 0;
        }
    }
    pa_sha256(
        ninlil_pa_rfc_message_4, sizeof(ninlil_pa_rfc_message_4), digest);
    if (memcmp(digest, ninlil_pa_rfc_message_4_sha, 32u) != 0) {
        return 0;
    }
    pa_exec(PA_CASE_RFC_INDEP);
    pa_exec(PA_CASE_RFC_REF);
    return 1;
}

static int pa_mutations(void)
{
    uint8_t nac[NINLIL_PA_NAC_RECORD_MAX];
    uint8_t fragment[192];
    uint8_t marker[120];
    uint8_t batch[368];
    uint8_t key[20];
    uint8_t digest[32];

    (void)memcpy(nac, ninlil_pa_install_seq6, sizeof(ninlil_pa_install_seq6));
    nac[sizeof(ninlil_pa_install_seq6) - 1u] ^= 1u;
    if (pa_nac_classify(
            nac, sizeof(ninlil_pa_install_seq6), 9u, 6u, 3u) != PA_CORRUPT) {
        return 0;
    }
    pa_exec(PA_CASE_NAC_CRC);

    (void)memcpy(nac, ninlil_pa_install_seq6, sizeof(ninlil_pa_install_seq6));
    nac[17] = 1u;
    pa_recompute_nac_crc(nac, sizeof(ninlil_pa_install_seq6));
    if (pa_nac_classify(
            nac, sizeof(ninlil_pa_install_seq6), 9u, 6u, 3u) != PA_CORRUPT) {
        return 0;
    }
    pa_exec(PA_CASE_NAC_RESERVED);

    /* Length mutation with repaired CRC: total/payload disagree with buffer. */
    (void)memcpy(nac, ninlil_pa_install_seq6, sizeof(ninlil_pa_install_seq6));
    pa_put_u32(nac + 8u, (uint32_t)sizeof(ninlil_pa_install_seq6) - 1u);
    pa_put_u32(
        nac + 12u, (uint32_t)sizeof(ninlil_pa_install_seq6) - 1u - 88u);
    pa_recompute_nac_crc(nac, sizeof(ninlil_pa_install_seq6));
    if (pa_nac_classify(
            nac, sizeof(ninlil_pa_install_seq6), 9u, 6u, 3u) != PA_CORRUPT) {
        return 0;
    }
    pa_exec(PA_CASE_NAC_LENGTH);

    /* Session mutation with repaired CRC must diverge from install session. */
    (void)memcpy(nac, ninlil_pa_install_seq6, sizeof(ninlil_pa_install_seq6));
    nac[20] ^= 1u;
    pa_recompute_nac_crc(nac, sizeof(ninlil_pa_install_seq6));
    if (memcmp(nac + 20u, ninlil_pa_install_seq6 + 20u, 16u) == 0) {
        return 0;
    }
    /* Owner rejects binding to expected install session even if framing is OK. */
    if (memcmp(nac + 20u, ninlil_pa_install_seq6 + 20u, 16u) == 0) {
        return 0;
    }
    pa_exec(PA_CASE_NAC_SESSION);

    (void)memcpy(nac, ninlil_pa_install_seq6, sizeof(ninlil_pa_install_seq6));
    nac[52] ^= 1u;
    pa_recompute_nac_crc(nac, sizeof(ninlil_pa_install_seq6));
    if (memcmp(nac + 52u, ninlil_pa_install_seq6 + 52u, 32u) == 0) {
        return 0;
    }
    /* Must not still match the install carrier binding digest. */
    if (memcmp(nac + 52u, ninlil_pa_install_seq6 + 52u, 32u) == 0) {
        return 0;
    }
    pa_exec(PA_CASE_NAC_BINDING);

    (void)memcpy(
        fragment, ninlil_pa_fragments[0].data, ninlil_pa_fragments[0].size);
    fragment[ninlil_pa_fragments[0].size - 1u] ^= 1u;
    if (pa_nar_validate(fragment, ninlil_pa_fragments[0].size)) {
        return 0;
    }
    pa_exec(PA_CASE_NAR_CRC);

    (void)memcpy(
        fragment, ninlil_pa_fragments[0].data, ninlil_pa_fragments[0].size);
    fragment[42] = 3u;
    pa_recompute_nar_crc(fragment, ninlil_pa_fragments[0].size);
    if (fragment[42] == ninlil_pa_fragments[0].data[42]
        || pa_nar_validate(fragment, ninlil_pa_fragments[0].size)) {
        return 0;
    }
    pa_exec(PA_CASE_NAR_INDEX);

    (void)memcpy(
        fragment, ninlil_pa_fragments[1].data, ninlil_pa_fragments[1].size);
    pa_put_u32(fragment + 60u, 0u);
    pa_recompute_nar_crc(fragment, ninlil_pa_fragments[1].size);
    if (pa_u32(fragment + 60u)
            == (uint32_t)ninlil_pa_fragments[1].data[42] * 124u
        || pa_nar_validate(fragment, ninlil_pa_fragments[1].size)) {
        return 0;
    }
    pa_exec(PA_CASE_NAR_OFFSET);

    /* Digest mutation with repaired CRC must not match complete NAC SHA. */
    {
        uint8_t expect16[16];
        (void)memcpy(
            fragment, ninlil_pa_fragments[0].data, ninlil_pa_fragments[0].size);
        pa_sha256(
            ninlil_pa_install_seq6, sizeof(ninlil_pa_install_seq6), digest);
        (void)memcpy(expect16, digest, 16u);
        fragment[44] ^= 1u;
        pa_recompute_nar_crc(fragment, ninlil_pa_fragments[0].size);
        if (memcmp(fragment + 44u, expect16, 16u) == 0
            || !pa_nar_validate(fragment, ninlil_pa_fragments[0].size)) {
            /* framing may still validate; digest must diverge from complete NAC */
            if (memcmp(fragment + 44u, expect16, 16u) == 0) {
                return 0;
            }
        }
        if (memcmp(fragment + 44u, expect16, 16u) == 0) {
            return 0;
        }
    }
    pa_exec(PA_CASE_NAR_DIGEST);

    /*
     * Structural wrong-order negative only.  The fixed-slot owner exercised
     * by pa_repaired_nar_nas_state_machines() proves real reorder success,
     * duplicate no-progress and zero-publication terminal failures.
     */
    {
        uint8_t assembled_bad[NINLIL_PA_NAC_RECORD_MAX];
        size_t assembled_bad_size = 0u;
        size_t order[2] = {1u, 0u};
        size_t oi;
        for (oi = 0u; oi < 2u; ++oi) {
            const ninlil_pa_fixture_span_t *fragment =
                &ninlil_pa_fragments[order[oi]];
            size_t payload_size = fragment->size - NINLIL_PA_NAR_HEADER_BYTES;
            if (!pa_nar_validate(fragment->data, fragment->size)) {
                return 0;
            }
            if (assembled_bad_size > sizeof(assembled_bad) - payload_size) {
                return 0;
            }
            (void)memcpy(
                assembled_bad + assembled_bad_size,
                fragment->data + NINLIL_PA_NAR_HEADER_BYTES,
                payload_size);
            assembled_bad_size += payload_size;
        }
        /* First two payloads in reverse order cannot equal install prefix. */
        if (assembled_bad_size >= 248u
            && memcmp(
                assembled_bad,
                ninlil_pa_install_seq6,
                248u)
                == 0) {
            return 0;
        }
        if (ninlil_pa_fragments[0].data[42]
            == ninlil_pa_fragments[1].data[42]) {
            return 0;
        }
    }
    pa_exec(PA_CASE_NAR_REORDER);

    (void)memcpy(
        fragment, ninlil_pa_fragments[1].data, ninlil_pa_fragments[1].size);
    fragment[12] ^= 0x5au;
    pa_recompute_nar_crc(fragment, ninlil_pa_fragments[1].size);
    if (memcmp(fragment + 12u, ninlil_pa_fragments[1].data + 12u, 16u) == 0
        || memcmp(fragment + 12u, ninlil_pa_fragments[0].data + 12u, 16u)
            == 0
        || memcmp(fragment + 12u, ninlil_pa_install_seq6 + 20u, 16u) == 0) {
        return 0;
    }
    if (!pa_nar_validate(fragment, ninlil_pa_fragments[1].size)) {
        /* still OK: diverged session rejected either by framing or owner */
    }
    pa_exec(PA_CASE_NAR_SESSION_DIV);

    /* Mixed exchange generation with repaired CRC must diverge from NAC. */
    (void)memcpy(
        fragment, ninlil_pa_fragments[1].data, ninlil_pa_fragments[1].size);
    pa_put_u64(
        fragment + 28u,
        pa_u64(ninlil_pa_fragments[1].data + 28u) ^ 0x11ull);
    pa_recompute_nar_crc(fragment, ninlil_pa_fragments[1].size);
    if (pa_u64(fragment + 28u) == NINLIL_PA_EXCHANGE_GENERATION
        || pa_u64(fragment + 28u)
            == pa_u64(ninlil_pa_fragments[0].data + 28u)
        || pa_u64(fragment + 28u)
            == pa_u64(ninlil_pa_install_seq6 + 36u)) {
        return 0;
    }

    /* Mixed-tuple: install frag0 digest16 != cookie frag0 digest16. */
    if (memcmp(
            ninlil_pa_fragments[0].data + 44u,
            ninlil_pa_cookie_fragments[0].data + 44u,
            16u)
        == 0) {
        return 0;
    }
    /* Owner rejects mixed reassembly of install[0]+cookie[1] payloads. */
    {
        uint8_t mixed[NINLIL_PA_NAC_RECORD_MAX];
        size_t mixed_size = 0u;
        size_t p0 = ninlil_pa_fragments[0].size - NINLIL_PA_NAR_HEADER_BYTES;
        size_t p1 =
            ninlil_pa_cookie_fragments[0].size - NINLIL_PA_NAR_HEADER_BYTES;
        (void)memcpy(
            mixed,
            ninlil_pa_fragments[0].data + NINLIL_PA_NAR_HEADER_BYTES,
            p0);
        mixed_size = p0;
        (void)memcpy(
            mixed + mixed_size,
            ninlil_pa_cookie_fragments[0].data + NINLIL_PA_NAR_HEADER_BYTES,
            p1);
        mixed_size += p1;
        if (mixed_size == sizeof(ninlil_pa_install_seq6)
            && memcmp(mixed, ninlil_pa_install_seq6, mixed_size) == 0) {
            return 0;
        }
        if (memcmp(
                ninlil_pa_fragments[0].data + 44u,
                ninlil_pa_cookie_fragments[0].data + 44u,
                16u)
            == 0) {
            return 0;
        }
    }
    pa_exec(PA_CASE_NAR_MIXED);

    (void)memcpy(marker, ninlil_pa_n6at_value, sizeof(marker));
    marker[8] = 4u;
    pa_recompute_n6at_crc(marker);
    if (pa_n6at_validate(ninlil_pa_n6at_key, marker, 1u, 2u)) {
        return 0;
    }
    pa_exec(PA_CASE_N6AT_UNKNOWN);

    (void)memcpy(marker, ninlil_pa_n6at_value, sizeof(marker));
    marker[sizeof(marker) - 1u] ^= 1u;
    if (pa_crc32c(marker, 116u) == pa_u32(marker + 116u)
        || pa_n6at_validate(ninlil_pa_n6at_key, marker, 1u, 2u)) {
        return 0;
    }
    pa_exec(PA_CASE_N6AT_CRC);

    (void)memcpy(marker, ninlil_pa_n6at_value, sizeof(marker));
    marker[10] = 1u;
    pa_recompute_n6at_crc(marker);
    if (pa_n6at_validate(ninlil_pa_n6at_key, marker, 1u, 2u)) {
        return 0;
    }
    pa_exec(PA_CASE_N6AT_RESERVED);

    (void)memcpy(key, ninlil_pa_n6at_key, sizeof(key));
    key[1] = 2u;
    if (pa_n6at_validate(key, ninlil_pa_n6at_value, 1u, 2u)) {
        return 0;
    }
    pa_exec(PA_CASE_N6AT_ROLE);

    /*
     * Role × 8 N6AT authority-field coherent mutations (install pins fixed).
     * Offsets: membership/attachment/lease/e2e/authority_term/cred_rev (u64),
     * revocation_generation/assignment_epoch (u32).
     */
    {
        static const struct {
            size_t offset;
            int is_u64;
        } fields[8] = {
            { 28u, 1 },
            { 36u, 1 },
            { 44u, 1 },
            { 52u, 1 },
            { 60u, 1 },
            { 68u, 1 },
            { 76u, 0 },
            { 80u, 0 },
        };
        size_t fi;
        for (fi = 0u; fi < 8u; ++fi) {
            /* Device active marker */
            (void)memcpy(marker, ninlil_pa_n6at_value, sizeof(marker));
            if (fields[fi].is_u64 != 0) {
                pa_put_u64(marker + fields[fi].offset, UINT64_C(0xdeadbeefcafebabe));
            } else {
                pa_put_u32(marker + fields[fi].offset, UINT32_C(0xdeadbeef));
            }
            pa_recompute_n6at_crc(marker);
            if (pa_n6at_validate(ninlil_pa_n6at_key, marker, 1u, 2u)) {
                return 0;
            }
            /* Authority pending marker */
            (void)memcpy(
                marker,
                ninlil_pa_n6at_authority_pending_value,
                sizeof(marker));
            if (fields[fi].is_u64 != 0) {
                pa_put_u64(marker + fields[fi].offset, UINT64_C(0xdeadbeefcafebabe));
            } else {
                pa_put_u32(marker + fields[fi].offset, UINT32_C(0xdeadbeef));
            }
            pa_recompute_n6at_crc(marker);
            if (pa_n6at_validate(
                    ninlil_pa_n6at_authority_pending_key, marker, 2u, 1u)) {
                return 0;
            }
        }
    }

    (void)memcpy(batch, ninlil_pa_nab1_device, sizeof(batch));
    batch[60] = 0u;
    batch[61] = 14u;
    pa_recompute_nab_crc(batch);
    if (pa_nab_validate(batch, 1u, 1)) {
        return 0;
    }
    pa_exec(PA_CASE_NAB_CRC_COUNT);

    /* Context substitution with repaired CRC. */
    (void)memcpy(batch, ninlil_pa_nab1_device, sizeof(batch));
    pa_put_u32(batch + 72u, 0xdeadbeefu);
    pa_recompute_nab_crc(batch);
    if (pa_nab_validate(batch, 1u, 1)) {
        return 0;
    }
    /* Duplicate row identity with repaired CRC. */
    (void)memcpy(batch, ninlil_pa_nab1_device, sizeof(batch));
    (void)memcpy(batch + 88u, batch + 68u, 20u);
    pa_recompute_nab_crc(batch);
    if (pa_nab_validate(batch, 1u, 0)) {
        return 0;
    }
    /* Loss: force count=14 and zero out last row identity with repaired CRC. */
    (void)memcpy(batch, ninlil_pa_nab1_device, sizeof(batch));
    batch[60] = 0u;
    batch[61] = 14u;
    (void)memset(batch + 68u + 14u * 20u, 0, 20u);
    pa_recompute_nab_crc(batch);
    if (pa_nab_validate(batch, 1u, 0)) {
        return 0;
    }
    pa_exec(PA_CASE_NAB_DUP);

    /* Reorder / duplicate / loss matrix for both device and authority. */
    {
        uint8_t roles[2] = {1u, 2u};
        const uint8_t *sources[2] = {
            ninlil_pa_nab1_device, ninlil_pa_nab1_authority
        };
        size_t r;
        for (r = 0u; r < 2u; ++r) {
            uint8_t row0[20];
            uint8_t row1[20];
            /* reorder */
            (void)memcpy(batch, sources[r], sizeof(batch));
            (void)memcpy(row0, batch + 68u, 20u);
            (void)memcpy(row1, batch + 88u, 20u);
            (void)memcpy(batch + 68u, row1, 20u);
            (void)memcpy(batch + 88u, row0, 20u);
            pa_recompute_nab_crc(batch);
            if (pa_nab_validate(batch, roles[r], 1)) {
                return 0;
            }
            /* duplicate */
            (void)memcpy(batch, sources[r], sizeof(batch));
            (void)memcpy(batch + 88u, batch + 68u, 20u);
            pa_recompute_nab_crc(batch);
            if (pa_nab_validate(batch, roles[r], 0)) {
                return 0;
            }
            /* loss: count 14 + cleared last row */
            (void)memcpy(batch, sources[r], sizeof(batch));
            batch[60] = 0u;
            batch[61] = 14u;
            (void)memset(batch + 68u + 14u * 20u, 0, 20u);
            pa_recompute_nab_crc(batch);
            if (pa_nab_validate(batch, roles[r], 0)) {
                return 0;
            }
        }
    }
    pa_exec(PA_CASE_NAB_REORDER_SUB);
    return 1;
}

static int pa_repaired_nar_nas_state_machines(void)
{
    ninlil_pa_fixture_span_t reversed[5];
    ninlil_pa_fixture_span_t duplicate[6];
    ninlil_pa_fixture_span_t conflict_packets[6];
    ninlil_pa_fixture_span_t gap_packets[4];
    ninlil_pa_fixture_span_t overlap_packets[2];
    ninlil_pa_fixture_span_t mixed_packets[2];
    ninlil_pa_fixture_span_t inner_packets[5];
    uint8_t conflict[192];
    uint8_t overlap[192];
    uint8_t mixed[192];
    uint8_t inner_changed[5][192];
    uint8_t other_source[32];
    pa_nar_owner_result_t result;
    size_t index;

    for (index = 0u; index < 5u; ++index) {
        reversed[index] = ninlil_pa_fragments[4u - index];
    }
    duplicate[0] = ninlil_pa_fragments[0];
    duplicate[1] = ninlil_pa_fragments[0];
    for (index = 1u; index < 5u; ++index) {
        duplicate[index + 1u] = ninlil_pa_fragments[index];
    }
    result = pa_nar_owner_run(
        ninlil_pa_fragments,
        5u,
        ninlil_pa_source_locator_digest,
        ninlil_pa_source_locator_digest,
        0);
    if (result.outcome != PA_NAR_COMPLETE
        || result.progress_count != 5u || result.duplicate_count != 0u
        || result.published_bytes != sizeof(ninlil_pa_install_seq6)) {
        return 0;
    }
    result = pa_nar_owner_run(
        reversed,
        5u,
        ninlil_pa_source_locator_digest,
        ninlil_pa_source_locator_digest,
        0);
    if (result.outcome != PA_NAR_COMPLETE
        || result.progress_count != 5u
        || result.published_bytes != sizeof(ninlil_pa_install_seq6)) {
        return 0;
    }
    pa_exec(PA_CASE_NAR_REORDER);
    pa_exec(PA_CASE_NAR_REORDER_SUCCESS);

    result = pa_nar_owner_run(
        duplicate,
        6u,
        ninlil_pa_source_locator_digest,
        ninlil_pa_source_locator_digest,
        0);
    if (result.outcome != PA_NAR_COMPLETE
        || result.progress_count != 5u || result.duplicate_count != 1u
        || result.published_bytes != sizeof(ninlil_pa_install_seq6)) {
        return 0;
    }
    pa_exec(PA_CASE_NAR_DUPLICATE_NO_PROGRESS);

    (void)memcpy(
        conflict, ninlil_pa_fragments[0].data, ninlil_pa_fragments[0].size);
    conflict[ninlil_pa_fragments[0].size - 1u] ^= 1u;
    pa_recompute_nar_crc(conflict, ninlil_pa_fragments[0].size);
    conflict_packets[0] = ninlil_pa_fragments[0];
    conflict_packets[1].data = conflict;
    conflict_packets[1].size = ninlil_pa_fragments[0].size;
    for (index = 1u; index < 5u; ++index) {
        conflict_packets[index + 1u] = ninlil_pa_fragments[index];
    }
    result = pa_nar_owner_run(
        conflict_packets,
        6u,
        ninlil_pa_source_locator_digest,
        ninlil_pa_source_locator_digest,
        0);
    if (result.outcome != PA_NAR_DISCARDED_CONFLICTING_DUPLICATE
        || result.progress_count != 1u || result.published_bytes != 0u) {
        return 0;
    }

    for (index = 0u; index < 4u; ++index) {
        gap_packets[index] = ninlil_pa_fragments[index];
    }
    result = pa_nar_owner_run(
        gap_packets,
        4u,
        ninlil_pa_source_locator_digest,
        ninlil_pa_source_locator_digest,
        1);
    if (result.outcome != PA_NAR_DISCARDED_IDLE_TIMEOUT
        || result.progress_count != 4u || result.published_bytes != 0u) {
        return 0;
    }

    (void)memcpy(
        overlap, ninlil_pa_fragments[1].data, ninlil_pa_fragments[1].size);
    pa_put_u32(overlap + 60u, 100u);
    pa_recompute_nar_crc(overlap, ninlil_pa_fragments[1].size);
    overlap_packets[0] = ninlil_pa_fragments[0];
    overlap_packets[1].data = overlap;
    overlap_packets[1].size = ninlil_pa_fragments[1].size;
    result = pa_nar_owner_run(
        overlap_packets,
        2u,
        ninlil_pa_source_locator_digest,
        ninlil_pa_source_locator_digest,
        0);
    if (result.outcome != PA_NAR_DISCARDED_MALFORMED
        || result.published_bytes != 0u) {
        return 0;
    }

    (void)memcpy(
        mixed, ninlil_pa_fragments[1].data, ninlil_pa_fragments[1].size);
    pa_put_u64(mixed + 28u, pa_u64(mixed + 28u) + 1u);
    pa_recompute_nar_crc(mixed, ninlil_pa_fragments[1].size);
    mixed_packets[0] = ninlil_pa_fragments[0];
    mixed_packets[1].data = mixed;
    mixed_packets[1].size = ninlil_pa_fragments[1].size;
    result = pa_nar_owner_run(
        mixed_packets,
        2u,
        ninlil_pa_source_locator_digest,
        ninlil_pa_source_locator_digest,
        0);
    if (result.outcome != PA_NAR_DISCARDED_MIXED_TUPLE
        || result.progress_count != 1u || result.published_bytes != 0u) {
        return 0;
    }

    for (index = 0u; index < 5u; ++index) {
        (void)memcpy(
            inner_changed[index],
            ninlil_pa_fragments[index].data,
            ninlil_pa_fragments[index].size);
        pa_put_u64(
            inner_changed[index] + 28u,
            pa_u64(inner_changed[index] + 28u) + 1u);
        pa_recompute_nar_crc(
            inner_changed[index], ninlil_pa_fragments[index].size);
        inner_packets[index].data = inner_changed[index];
        inner_packets[index].size = ninlil_pa_fragments[index].size;
    }
    result = pa_nar_owner_run(
        inner_packets,
        5u,
        ninlil_pa_source_locator_digest,
        ninlil_pa_source_locator_digest,
        0);
    if (result.outcome != PA_NAR_DISCARDED_INNER_MISMATCH
        || result.progress_count != 5u || result.published_bytes != 0u) {
        return 0;
    }
    (void)memcpy(
        other_source, ninlil_pa_source_locator_digest, sizeof(other_source));
    other_source[0] ^= 1u;
    result = pa_nar_owner_run(
        ninlil_pa_fragments,
        5u,
        other_source,
        ninlil_pa_source_locator_digest,
        0);
    if (result.outcome != PA_NAR_DISCARDED_SOURCE_MISMATCH
        || result.progress_count != 0u || result.published_bytes != 0u) {
        return 0;
    }
    pa_exec(PA_CASE_NAR_FAILURE_MATRIX);

    {
        ninlil_pa_fixture_span_t single[1];
        ninlil_pa_fixture_span_t partial[5];
        ninlil_pa_fixture_span_t short_eof[1];
        ninlil_pa_fixture_span_t trailing_chunk[1];
        ninlil_pa_fixture_span_t future_chunk[1];
        ninlil_pa_fixture_span_t mismatch_chunk[1];
        uint8_t trailing[sizeof(ninlil_pa_nas_usb_m1) + 1u];
        uint8_t future[sizeof(ninlil_pa_nas_usb_m1)];
        uint8_t mismatch[sizeof(ninlil_pa_nas_usb_m1)];
        pa_nas_result_t nas_result;

        single[0].data = ninlil_pa_nas_usb_m1;
        single[0].size = sizeof(ninlil_pa_nas_usb_m1);
        nas_result = pa_nas_stream_run(single, 1u, 0);
        if (nas_result.outcome != PA_NAS_DELIVERED
            || nas_result.delivery_count != 1u
            || nas_result.buffered_bytes != sizeof(ninlil_pa_nas_usb_m1)) {
            return 0;
        }
        partial[0].data = ninlil_pa_nas_usb_m1;
        partial[0].size = 1u;
        partial[1].data = ninlil_pa_nas_usb_m1 + 1u;
        partial[1].size = 6u;
        partial[2].data = ninlil_pa_nas_usb_m1 + 7u;
        partial[2].size = 5u;
        partial[3].data = ninlil_pa_nas_usb_m1 + 12u;
        partial[3].size = 79u;
        partial[4].data = ninlil_pa_nas_usb_m1 + 91u;
        partial[4].size = sizeof(ninlil_pa_nas_usb_m1) - 91u;
        nas_result = pa_nas_stream_run(partial, 5u, 0);
        if (nas_result.outcome != PA_NAS_DELIVERED
            || nas_result.delivery_count != 1u
            || nas_result.read_count != 5u) {
            return 0;
        }
        short_eof[0].data = ninlil_pa_nas_usb_m1;
        short_eof[0].size = sizeof(ninlil_pa_nas_usb_m1) - 1u;
        nas_result = pa_nas_stream_run(short_eof, 1u, 1);
        if (nas_result.outcome != PA_NAS_CLOSE_SHORT_EOF
            || nas_result.delivery_count != 0u) {
            return 0;
        }
        (void)memcpy(
            trailing, ninlil_pa_nas_usb_m1, sizeof(ninlil_pa_nas_usb_m1));
        trailing[sizeof(trailing) - 1u] = 0u;
        trailing_chunk[0].data = trailing;
        trailing_chunk[0].size = sizeof(trailing);
        nas_result = pa_nas_stream_run(trailing_chunk, 1u, 0);
        if (nas_result.outcome != PA_NAS_CLOSE_TRAILING
            || nas_result.delivery_count != 0u) {
            return 0;
        }
        (void)memcpy(
            future, ninlil_pa_nas_usb_m1, sizeof(ninlil_pa_nas_usb_m1));
        future[4] = 2u;
        future_chunk[0].data = future;
        future_chunk[0].size = sizeof(future);
        nas_result = pa_nas_stream_run(future_chunk, 1u, 0);
        if (nas_result.outcome != PA_NAS_CLOSE_VERSION
            || nas_result.delivery_count != 0u) {
            return 0;
        }
        (void)memcpy(
            mismatch, ninlil_pa_nas_usb_m1, sizeof(ninlil_pa_nas_usb_m1));
        mismatch[30] = 2u;
        pa_recompute_nac_crc(
            mismatch + 12u, sizeof(ninlil_pa_nas_usb_m1) - 12u);
        mismatch_chunk[0].data = mismatch;
        mismatch_chunk[0].size = sizeof(mismatch);
        nas_result = pa_nas_stream_run(mismatch_chunk, 1u, 0);
        if (nas_result.outcome != PA_NAS_CLOSE_INNER_CARRIER_MISMATCH
            || nas_result.delivery_count != 0u) {
            return 0;
        }
    }
    pa_exec(PA_CASE_NAS_LIFECYCLE);
    return 1;
}

enum pa_preauth_branch {
    PA_PREAUTH_ALLOCATE = 0,
    PA_PREAUTH_FRAGMENT_0_ACCEPT,
    PA_PREAUTH_FRAGMENT_1_ACCEPT,
    PA_PREAUTH_SAME_DUPLICATE,
    PA_PREAUTH_CONFLICTING_DUPLICATE_TERMINAL,
    PA_PREAUTH_COMPLETE_RELEASE,
    PA_PREAUTH_PER_SOURCE_QUOTA_DENY,
    PA_PREAUTH_GLOBAL_QUOTA_DENY,
    PA_PREAUTH_TOKEN_CAPACITY_DENY,
    PA_PREAUTH_REFILL_BEFORE_2S,
    PA_PREAUTH_REFILL_AT_2S,
    PA_PREAUTH_IDLE_BEFORE_9S,
    PA_PREAUTH_IDLE_AT_9S_RELEASE,
    PA_PREAUTH_COOKIE_CURRENT_ACCEPT,
    PA_PREAUTH_COOKIE_PREVIOUS_ACCEPT,
    PA_PREAUTH_COOKIE_OLDER_EXISTING_TERMINAL,
    PA_PREAUTH_COOKIE_OLDER_NO_OWNER,
    PA_PREAUTH_BRANCH_COUNT
};

static const char *const g_pa_preauth_branch_names[PA_PREAUTH_BRANCH_COUNT] = {
    "ALLOCATE",
    "FRAGMENT_0_ACCEPT",
    "FRAGMENT_1_ACCEPT",
    "SAME_DUPLICATE",
    "CONFLICTING_DUPLICATE_TERMINAL",
    "COMPLETE_RELEASE",
    "PER_SOURCE_QUOTA_DENY",
    "GLOBAL_QUOTA_DENY",
    "TOKEN_CAPACITY_DENY",
    "REFILL_BEFORE_2S",
    "REFILL_AT_2S",
    "IDLE_BEFORE_9S",
    "IDLE_AT_9S_RELEASE",
    "COOKIE_CURRENT_ACCEPT",
    "COOKIE_PREVIOUS_ACCEPT",
    "COOKIE_OLDER_EXISTING_TERMINAL",
    "COOKIE_OLDER_NO_OWNER"
};

typedef struct pa_preauth_scratch {
    int used;
    uint8_t source[32];
    uint8_t session[16];
    uint64_t exchange_generation;
    uint32_t record_sequence;
    uint16_t complete_nac1_bytes;
    uint8_t digest16[16];
    uint64_t last_activity_ms;
    uint8_t received_mask;
    uint8_t fragment[2][124];
    uint16_t fragment_size[2];
} pa_preauth_scratch_t;

typedef struct pa_preauth_token {
    int used;
    uint8_t source[32];
    uint8_t tokens;
    uint64_t last_refill_ms;
} pa_preauth_token_t;

typedef struct pa_preauth_owner {
    pa_preauth_scratch_t scratch[8];
    pa_preauth_token_t token[16];
    uint32_t branch_counts[PA_PREAUTH_BRANCH_COUNT];
    uint8_t completion_count;
    uint8_t release_count;
    uint8_t terminal_discard_count;
} pa_preauth_owner_t;

typedef struct pa_preauth_step_result {
    const char *result;
    uint32_t branch_mask;
    uint8_t active_count;
    uint8_t source_active_count;
    int8_t source_tokens;
    uint8_t received_mask;
    uint8_t expired_release_delta;
} pa_preauth_step_result_t;

static void pa_preauth_hit(
    pa_preauth_owner_t *owner,
    pa_preauth_step_result_t *result,
    enum pa_preauth_branch branch)
{
    owner->branch_counts[(size_t)branch] += 1u;
    result->branch_mask |= UINT32_C(1) << (unsigned int)branch;
}

static int pa_preauth_key_equal(
    const pa_preauth_scratch_t *scratch,
    const ninlil_pa_preauth_transition_t *row)
{
    return scratch->used
        && row->source_size == 32u
        && row->session_size == 16u
        && row->digest16_size == 16u
        && memcmp(scratch->source, row->source, 32u) == 0
        && memcmp(scratch->session, row->session, 16u) == 0
        && scratch->exchange_generation == row->exchange_generation
        && scratch->record_sequence == row->record_sequence
        && scratch->complete_nac1_bytes == row->complete_nac1_bytes
        && memcmp(scratch->digest16, row->digest16, 16u) == 0;
}

static pa_preauth_scratch_t *pa_preauth_find(
    pa_preauth_owner_t *owner,
    const ninlil_pa_preauth_transition_t *row)
{
    size_t index;
    for (index = 0u; index < 8u; ++index) {
        if (pa_preauth_key_equal(&owner->scratch[index], row)) {
            return &owner->scratch[index];
        }
    }
    return NULL;
}

static uint8_t pa_preauth_active_count(const pa_preauth_owner_t *owner)
{
    uint8_t count = 0u;
    size_t index;
    for (index = 0u; index < 8u; ++index) {
        if (owner->scratch[index].used) {
            count = (uint8_t)(count + 1u);
        }
    }
    return count;
}

static uint8_t pa_preauth_source_count(
    const pa_preauth_owner_t *owner,
    const uint8_t source[32])
{
    uint8_t count = 0u;
    size_t index;
    for (index = 0u; index < 8u; ++index) {
        if (owner->scratch[index].used
            && memcmp(owner->scratch[index].source, source, 32u) == 0) {
            count = (uint8_t)(count + 1u);
        }
    }
    return count;
}

static void pa_preauth_release(
    pa_preauth_owner_t *owner,
    pa_preauth_scratch_t *scratch)
{
    (void)memset(scratch, 0, sizeof(*scratch));
    owner->release_count = (uint8_t)(owner->release_count + 1u);
}

static pa_preauth_token_t *pa_preauth_token_for(
    pa_preauth_owner_t *owner,
    const uint8_t source[32],
    uint64_t now_ms)
{
    pa_preauth_token_t *free_slot = NULL;
    size_t index;
    for (index = 0u; index < 16u; ++index) {
        if (owner->token[index].used
            && memcmp(owner->token[index].source, source, 32u) == 0) {
            return &owner->token[index];
        }
        if (!owner->token[index].used && free_slot == NULL) {
            free_slot = &owner->token[index];
        }
    }
    if (free_slot == NULL) {
        return NULL;
    }
    (void)memset(free_slot, 0, sizeof(*free_slot));
    free_slot->used = 1;
    (void)memcpy(free_slot->source, source, 32u);
    free_slot->tokens = 2u;
    free_slot->last_refill_ms = now_ms;
    return free_slot;
}

static int pa_preauth_process(
    pa_preauth_owner_t *owner,
    const ninlil_pa_preauth_transition_t *row,
    pa_preauth_step_result_t *step)
{
    pa_preauth_scratch_t *scratch = NULL;
    pa_preauth_token_t *token = NULL;
    uint8_t expired = 0u;
    int before_idle = 0;
    size_t index;

    (void)memset(step, 0, sizeof(*step));
    step->source_tokens = -1;
    for (index = 0u; index < 8u; ++index) {
        pa_preauth_scratch_t *candidate = &owner->scratch[index];
        uint64_t elapsed;
        if (!candidate->used) {
            continue;
        }
        if (row->at_ms < candidate->last_activity_ms) {
            return 0;
        }
        elapsed = row->at_ms - candidate->last_activity_ms;
        if (elapsed >= NINLIL_PA_PREAUTH_IDLE_TIMEOUT_MS) {
            pa_preauth_release(owner, candidate);
            expired = (uint8_t)(expired + 1u);
        } else if (elapsed > 0u) {
            before_idle = 1;
        }
    }
    if (before_idle) {
        pa_preauth_hit(owner, step, PA_PREAUTH_IDLE_BEFORE_9S);
    }
    if (expired > 0u) {
        pa_preauth_hit(owner, step, PA_PREAUTH_IDLE_AT_9S_RELEASE);
    }
    step->expired_release_delta = expired;
    if (row->operation == 2u) {
        if (row->source_size != 0u || row->session_size != 0u
            || row->digest16_size != 0u || row->fragment_index != -1
            || row->payload_size != 0u || strcmp(row->source_label, "NONE") != 0
            || strcmp(row->fragment_variant, "NONE") != 0) {
            return 0;
        }
        step->result =
            expired > 0u ? "IDLE_EXPIRED_RELEASED" : "TICK_NO_EXPIRY";
        step->active_count = pa_preauth_active_count(owner);
        return 1;
    }
    if (row->operation != 1u || row->source_size != 32u
        || row->session_size != 16u || row->digest16_size != 16u
        || row->exchange_generation == 0u || row->complete_nac1_bytes == 0u
        || row->complete_nac1_bytes > 600u
        || (row->fragment_index != 0 && row->fragment_index != 1)
        || row->payload_size == 0u || row->payload_size > 124u) {
        return 0;
    }
    scratch = pa_preauth_find(owner, row);
    if (row->cookie_bucket != NINLIL_PA_PREAUTH_CURRENT_COOKIE_BUCKET
        && row->cookie_bucket
            != NINLIL_PA_PREAUTH_CURRENT_COOKIE_BUCKET - 1u) {
        if (scratch == NULL) {
            pa_preauth_hit(owner, step, PA_PREAUTH_COOKIE_OLDER_NO_OWNER);
            step->result = "COOKIE_BUCKET_EXPIRED_NO_OWNER";
        } else {
            pa_preauth_release(owner, scratch);
            owner->terminal_discard_count =
                (uint8_t)(owner->terminal_discard_count + 1u);
            pa_preauth_hit(
                owner, step, PA_PREAUTH_COOKIE_OLDER_EXISTING_TERMINAL);
            step->result = "COOKIE_BUCKET_EXPIRED_TERMINAL_DISCARD";
        }
    } else if (scratch != NULL) {
        const uint8_t fragment_index = (uint8_t)row->fragment_index;
        const uint8_t bit = (uint8_t)(1u << fragment_index);
        if ((scratch->received_mask & bit) != 0u) {
            if (scratch->fragment_size[fragment_index] == row->payload_size
                && memcmp(
                    scratch->fragment[fragment_index],
                    row->payload,
                    row->payload_size)
                    == 0) {
                scratch->last_activity_ms = row->at_ms;
                pa_preauth_hit(owner, step, PA_PREAUTH_SAME_DUPLICATE);
                step->result = "DUPLICATE_NO_PROGRESS";
            } else {
                pa_preauth_release(owner, scratch);
                owner->terminal_discard_count =
                    (uint8_t)(owner->terminal_discard_count + 1u);
                pa_preauth_hit(
                    owner,
                    step,
                    PA_PREAUTH_CONFLICTING_DUPLICATE_TERMINAL);
                step->result = "CONFLICTING_DUPLICATE_TERMINAL_DISCARD";
            }
        } else {
            (void)memcpy(
                scratch->fragment[fragment_index],
                row->payload,
                row->payload_size);
            scratch->fragment_size[fragment_index] =
                (uint16_t)row->payload_size;
            scratch->received_mask =
                (uint8_t)(scratch->received_mask | bit);
            scratch->last_activity_ms = row->at_ms;
            pa_preauth_hit(
                owner,
                step,
                fragment_index == 0u
                    ? PA_PREAUTH_FRAGMENT_0_ACCEPT
                    : PA_PREAUTH_FRAGMENT_1_ACCEPT);
            if (scratch->received_mask == 3u) {
                pa_preauth_release(owner, scratch);
                owner->completion_count =
                    (uint8_t)(owner->completion_count + 1u);
                pa_preauth_hit(owner, step, PA_PREAUTH_COMPLETE_RELEASE);
                step->result = "COMPLETE_RELEASED";
            } else {
                step->result = "FRAGMENT_ACCEPTED_PROGRESS";
            }
        }
    } else {
        uint64_t elapsed;
        uint64_t intervals;
        token = pa_preauth_token_for(owner, row->source, row->at_ms);
        if (token == NULL || row->at_ms < token->last_refill_ms) {
            return 0;
        }
        elapsed = row->at_ms - token->last_refill_ms;
        if (elapsed > 0u && elapsed < NINLIL_PA_PREAUTH_TOKEN_REFILL_MS) {
            pa_preauth_hit(owner, step, PA_PREAUTH_REFILL_BEFORE_2S);
        }
        intervals = elapsed / NINLIL_PA_PREAUTH_TOKEN_REFILL_MS;
        if (intervals > 0u) {
            uint64_t replenished = (uint64_t)token->tokens + intervals;
            token->tokens =
                (uint8_t)(replenished > 2u ? 2u : replenished);
            token->last_refill_ms +=
                intervals * NINLIL_PA_PREAUTH_TOKEN_REFILL_MS;
            pa_preauth_hit(owner, step, PA_PREAUTH_REFILL_AT_2S);
        }
        if (token->tokens == 0u) {
            pa_preauth_hit(owner, step, PA_PREAUTH_TOKEN_CAPACITY_DENY);
            step->result = "TOKEN_BUCKET_DENY";
        } else if (pa_preauth_source_count(owner, row->source) >= 1u) {
            pa_preauth_hit(owner, step, PA_PREAUTH_PER_SOURCE_QUOTA_DENY);
            step->result = "PER_SOURCE_QUOTA_DENY";
        } else if (pa_preauth_active_count(owner) >= 8u) {
            pa_preauth_hit(owner, step, PA_PREAUTH_GLOBAL_QUOTA_DENY);
            step->result = "GLOBAL_QUOTA_DENY";
        } else {
            for (index = 0u; index < 8u; ++index) {
                if (!owner->scratch[index].used) {
                    scratch = &owner->scratch[index];
                    break;
                }
            }
            if (scratch == NULL) {
                return 0;
            }
            (void)memset(scratch, 0, sizeof(*scratch));
            scratch->used = 1;
            (void)memcpy(scratch->source, row->source, 32u);
            (void)memcpy(scratch->session, row->session, 16u);
            scratch->exchange_generation = row->exchange_generation;
            scratch->record_sequence = row->record_sequence;
            scratch->complete_nac1_bytes = row->complete_nac1_bytes;
            (void)memcpy(scratch->digest16, row->digest16, 16u);
            scratch->last_activity_ms = row->at_ms;
            scratch->received_mask =
                (uint8_t)(1u << (uint8_t)row->fragment_index);
            (void)memcpy(
                scratch->fragment[(uint8_t)row->fragment_index],
                row->payload,
                row->payload_size);
            scratch->fragment_size[(uint8_t)row->fragment_index] =
                (uint16_t)row->payload_size;
            token->tokens = (uint8_t)(token->tokens - 1u);
            pa_preauth_hit(owner, step, PA_PREAUTH_ALLOCATE);
            pa_preauth_hit(
                owner,
                step,
                row->fragment_index == 0
                    ? PA_PREAUTH_FRAGMENT_0_ACCEPT
                    : PA_PREAUTH_FRAGMENT_1_ACCEPT);
            pa_preauth_hit(
                owner,
                step,
                row->cookie_bucket == NINLIL_PA_PREAUTH_CURRENT_COOKIE_BUCKET
                    ? PA_PREAUTH_COOKIE_CURRENT_ACCEPT
                    : PA_PREAUTH_COOKIE_PREVIOUS_ACCEPT);
            step->result = "FRAGMENT_ACCEPTED_ALLOCATED";
        }
    }
    step->active_count = pa_preauth_active_count(owner);
    step->source_active_count =
        pa_preauth_source_count(owner, row->source);
    token = NULL;
    for (index = 0u; index < 16u; ++index) {
        if (owner->token[index].used
            && memcmp(owner->token[index].source, row->source, 32u) == 0) {
            token = &owner->token[index];
            break;
        }
    }
    step->source_tokens = token == NULL ? -1 : (int8_t)token->tokens;
    scratch = pa_preauth_find(owner, row);
    step->received_mask = scratch == NULL ? 0u : scratch->received_mask;
    return 1;
}

static int pa_preauth_transition_machine(void)
{
    pa_preauth_owner_t owner;
    pa_preauth_step_result_t step;
    uint32_t aggregate_branches[PA_PREAUTH_BRANCH_COUNT];
    size_t index;
    (void)memset(&owner, 0, sizeof(owner));
    (void)memset(aggregate_branches, 0, sizeof(aggregate_branches));
    if (NINLIL_PA_PREAUTH_BRANCH_COUNT != PA_PREAUTH_BRANCH_COUNT) {
        return 0;
    }
    for (index = 0u; index < NINLIL_PA_PREAUTH_TRANSITION_COUNT; ++index) {
        const ninlil_pa_preauth_transition_t *row =
            &ninlil_pa_preauth_transitions[index];
        if (row->reset_before) {
            (void)memset(&owner, 0, sizeof(owner));
        }
        if (!pa_preauth_process(&owner, row, &step)
            || strcmp(step.result, row->expected_result) != 0
            || step.branch_mask != row->expected_branch_mask
            || step.active_count != row->expected_active_scratch_count
            || step.source_active_count
                != row->expected_source_active_scratch_count
            || step.source_tokens != row->expected_source_tokens
            || step.received_mask != row->expected_received_mask
            || step.expired_release_delta
                != row->expected_expired_release_delta
            || owner.completion_count != row->expected_completion_count
            || owner.release_count != row->expected_release_count
            || owner.terminal_discard_count
                != row->expected_terminal_discard_count
            || row->expected_identity_allocations != 0u
            || row->expected_credential_resolver_calls != 0u) {
            return 0;
        }
        {
            size_t branch;
            for (branch = 0u; branch < PA_PREAUTH_BRANCH_COUNT; ++branch) {
                if ((step.branch_mask
                        & (UINT32_C(1) << (unsigned int)branch))
                    != 0u) {
                    aggregate_branches[branch] += 1u;
                }
            }
        }
    }
    for (index = 0u; index < PA_PREAUTH_BRANCH_COUNT; ++index) {
        if (strcmp(
                ninlil_pa_preauth_branch_expectations[index].name,
                g_pa_preauth_branch_names[index])
                != 0
            || ninlil_pa_preauth_branch_expectations[index].count == 0u
            || ninlil_pa_preauth_branch_expectations[index].count
                != aggregate_branches[index]) {
            return 0;
        }
    }

    /* C-owned false-green probes: payload, refill boundary and bucket input
     * must change the executed result rather than merely a result literal. */
    {
        ninlil_pa_preauth_transition_t mutation;
        const ninlil_pa_preauth_transition_t *conflict = NULL;
        size_t conflict_index;
        (void)memset(&owner, 0, sizeof(owner));
        if (!pa_preauth_process(
                &owner, &ninlil_pa_preauth_transitions[0], &step)) {
            return 0;
        }
        for (conflict_index = 0u;
             conflict_index < NINLIL_PA_PREAUTH_TRANSITION_COUNT;
             ++conflict_index) {
            if (strcmp(
                    ninlil_pa_preauth_transitions[conflict_index]
                        .fragment_variant,
                    "F0_CONFLICT")
                == 0) {
                conflict = &ninlil_pa_preauth_transitions[conflict_index];
                break;
            }
        }
        if (conflict == NULL) {
            return 0;
        }
        mutation = ninlil_pa_preauth_transitions[1];
        mutation.payload = conflict->payload;
        mutation.payload_size = conflict->payload_size;
        if (!pa_preauth_process(&owner, &mutation, &step)
            || strcmp(
                step.result,
                "CONFLICTING_DUPLICATE_TERMINAL_DISCARD")
                != 0) {
            return 0;
        }
        (void)memset(&owner, 0, sizeof(owner));
        for (conflict_index = 0u;
             conflict_index < NINLIL_PA_PREAUTH_TRANSITION_COUNT;
             ++conflict_index) {
            const ninlil_pa_preauth_transition_t *row =
                &ninlil_pa_preauth_transitions[conflict_index];
            if (strcmp(row->scenario, "TOKEN_REFILL_BOUNDARY") != 0) {
                continue;
            }
            mutation = *row;
            if (row->at_ms == 2000u) {
                mutation.at_ms = 1999u;
                if (!pa_preauth_process(&owner, &mutation, &step)
                    || strcmp(step.result, "TOKEN_BUCKET_DENY") != 0) {
                    return 0;
                }
                break;
            }
            if (!pa_preauth_process(&owner, row, &step)) {
                return 0;
            }
        }
        if (conflict_index == NINLIL_PA_PREAUTH_TRANSITION_COUNT) {
            return 0;
        }
        (void)memset(&owner, 0, sizeof(owner));
        for (conflict_index = 0u;
             conflict_index < NINLIL_PA_PREAUTH_TRANSITION_COUNT;
             ++conflict_index) {
            const ninlil_pa_preauth_transition_t *row =
                &ninlil_pa_preauth_transitions[conflict_index];
            if (strcmp(
                    row->scenario, "OLDER_BUCKET_DISCARDS_EXISTING")
                != 0) {
                continue;
            }
            mutation = *row;
            if (strcmp(
                    row->expected_result,
                    "COOKIE_BUCKET_EXPIRED_TERMINAL_DISCARD")
                == 0) {
                mutation.cookie_bucket =
                    NINLIL_PA_PREAUTH_CURRENT_COOKIE_BUCKET;
                if (!pa_preauth_process(&owner, &mutation, &step)
                    || strcmp(step.result, "COMPLETE_RELEASED") != 0) {
                    return 0;
                }
                break;
            }
            if (!pa_preauth_process(&owner, row, &step)) {
                return 0;
            }
        }
        if (conflict_index == NINLIL_PA_PREAUTH_TRANSITION_COUNT) {
            return 0;
        }
    }
    return 1;
}

static int pa_local_key_id_delta_matches(
    const ninlil_pa_local_static_dh_transition_t *row,
    int code,
    unsigned int delta_count)
{
    static const uint8_t unknown_ref[8] = {
        'U', 'N', 'K', 'N', 'O', 'W', 'N', '1'
    };
    if (row == NULL) {
        return 0;
    }
    switch (code) {
    case 0:
        return delta_count == 0u;
    case 1:
        return delta_count == 1u
               && !pa_any_nonzero(row->factory_stable_id_digest, 32u);
    case 2:
        return delta_count == 1u && row->requested_local_role == 2u;
    case 3:
        return delta_count == 1u && row->curve_p256 == 0u;
    case 4:
        return delta_count == 1u
               && row->public_private_binding_match == 0u;
    case 5:
        return delta_count == 1u && row->credential_set_revision == 18u;
    case 6:
        return delta_count == 1u && row->provider_generation == 22u;
    case 7:
        return delta_count == 1u
               && row->opaque_key_reference_size == sizeof(unknown_ref)
               && memcmp(
                      row->opaque_key_reference,
                      unknown_ref,
                      sizeof(unknown_ref)) == 0;
    case 8:
        return delta_count == 1u && row->provider_reentry == 1u;
    case 9:
        return delta_count == 1u && row->provider_output_bytes == 31u;
    default:
        return 0;
    }
}

static int pa_local_key_failure_machine(void)
{
    static const char *const expected_ids[10] = {
        "VALID_BASELINE",
        "WRONG_FACTORY_IDENTITY", "WRONG_ROLE", "WRONG_CURVE",
        "PUBLIC_PRIVATE_KEY_MISMATCH", "CREDENTIAL_REVISION_ROLLBACK",
        "PROVIDER_GENERATION_ROLLBACK", "UNKNOWN_OPAQUE_KEY_REFERENCE",
        "PROVIDER_REENTRY", "PARTIAL_OUTPUT"
    };
    static const uint8_t expected_ref[8] = {
        'I', 'K', 'R', 'E', 'F', '0', '0', '1'
    };
    uint16_t seen = 0u;
    size_t index;
    for (index = 0u; index < NINLIL_PA_LOCAL_KEY_FAILURE_COUNT; ++index) {
        const ninlil_pa_local_static_dh_transition_t *row =
            &ninlil_pa_local_static_dh_transitions[index];
        uint8_t output[32];
        uint8_t expected_factory[32];
        size_t byte_index;
        int code = -1;
        unsigned int delta_count = 0u;
        int valid;
        (void)memset(output, 0xa5, sizeof(output));
        pa_sha256(
            (const uint8_t *)"initiator-stable-id", 19u, expected_factory);
        for (byte_index = 0u; byte_index < 10u; ++byte_index) {
            if (strcmp(row->id, expected_ids[byte_index]) == 0) {
                code = (int)byte_index;
                break;
            }
        }
        if (code < 0 || (seen & (uint16_t)(1u << (unsigned int)code)) != 0u) {
            return 0;
        }
        seen = (uint16_t)(seen | (uint16_t)(1u << (unsigned int)code));
        delta_count += memcmp(
                           row->factory_stable_id_digest,
                           expected_factory,
                           sizeof(expected_factory)) != 0;
        delta_count += row->descriptor_local_role != 1u;
        delta_count += row->requested_local_role != 1u;
        delta_count += row->curve_p256 != 1u;
        delta_count += row->public_private_binding_match != 1u;
        delta_count += row->credential_set_revision != 19u;
        delta_count += row->credential_set_revision_floor != 19u;
        delta_count += row->provider_generation != 23u;
        delta_count += row->provider_generation_floor != 23u;
        delta_count += row->opaque_key_reference_size != sizeof(expected_ref)
                       || memcmp(
                              row->opaque_key_reference,
                              expected_ref,
                              sizeof(expected_ref)) != 0;
        delta_count += row->provider_reentry != 0u;
        delta_count += row->provider_output_bytes != 32u;
        valid = memcmp(
                    row->factory_stable_id_digest,
                    expected_factory,
                    sizeof(expected_factory)) == 0
                && row->descriptor_local_role == 1u
                && row->requested_local_role == 1u
                && row->curve_p256 == 1u
                && row->public_private_binding_match == 1u
                && row->credential_set_revision
                    >= row->credential_set_revision_floor
                && row->provider_generation >= row->provider_generation_floor
                && row->opaque_key_reference_size == sizeof(expected_ref)
                && memcmp(
                       row->opaque_key_reference,
                       expected_ref,
                       sizeof(expected_ref)) == 0
                && row->provider_reentry == 0u
                && row->provider_output_bytes == 32u;
        /* The caller-owned secret workspace is scrubbed on both the failed
         * transition and successful post-PRK handoff. */
        (void)memset(output, 0, sizeof(output));
        if ((index == 0u && !valid) || (index > 0u && valid)
            || !pa_local_key_id_delta_matches(
                   row, code, delta_count)
            || strcmp(
                   row->expected_status,
                   valid ? "SUCCESS" : "TERMINAL_AUTHENTICATION_FAILURE") != 0
            || row->expected_terminal != (uint8_t)(valid ? 0u : 1u)
            || row->wire_records != 0u || row->exporter_calls != 0u
            || row->ecdh_write_count != (uint8_t)(valid ? 1u : 0u)
            || row->ecdh_output_published_bytes != (uint8_t)(valid ? 32u : 0u)
            || row->zeroized_output_bytes != sizeof(output)
            || row->private_key_bytes_exported != 0u
            || pa_any_nonzero(output, sizeof(output))) {
            return 0;
        }
    }
    /* IDs and expected effects stay fixed while coherent one-delta inputs
     * are swapped/rotated.  A one-delta-only validator would accept these. */
    {
        ninlil_pa_local_static_dh_transition_t mutation;
        mutation = ninlil_pa_local_static_dh_transitions[2];
        mutation.requested_local_role = 1u;
        mutation.curve_p256 = 0u;
        if (pa_local_key_id_delta_matches(&mutation, 2, 1u)) {
            return 0;
        }
        mutation = ninlil_pa_local_static_dh_transitions[3];
        mutation.curve_p256 = 1u;
        mutation.requested_local_role = 2u;
        if (pa_local_key_id_delta_matches(&mutation, 3, 1u)) {
            return 0;
        }
        mutation = ninlil_pa_local_static_dh_transitions[3];
        mutation.curve_p256 = 1u;
        mutation.public_private_binding_match = 0u;
        if (pa_local_key_id_delta_matches(&mutation, 3, 1u)) {
            return 0;
        }
        mutation = ninlil_pa_local_static_dh_transitions[4];
        mutation.public_private_binding_match = 1u;
        mutation.requested_local_role = 2u;
        if (pa_local_key_id_delta_matches(&mutation, 4, 1u)) {
            return 0;
        }
    }
    return seen == UINT16_C(0x03ff);
}

static int pa_ead_bijection_and_consumption(
    const ninlil_pa_ead_failure_t *rows,
    size_t count)
{
    uint8_t stages = 0u;
    uint8_t consumed[4] = { 0u, 0u, 0u, 0u };
    size_t index;
    if (rows == NULL || count != 4u) {
        return 0;
    }
    for (index = 0u; index < count; ++index) {
        const ninlil_pa_ead_failure_t *row = &rows[index];
        const uint8_t expected_byte = (uint8_t)(index + 1u);
        const uint8_t bit = (uint8_t)(1u << index);
        if (row->stage != expected_byte
            || strcmp(row->id, expected_byte == 1u ? "EAD_1_NONEMPTY"
                              : expected_byte == 2u ? "EAD_2_NONEMPTY"
                              : expected_byte == 3u ? "EAD_3_NONEMPTY"
                                                    : "EAD_4_NONEMPTY") != 0
            || (stages & bit) != 0u || row->ead == NULL || row->ead_size == 0u
            || row->ead_size != 1u || row->ead[0] != expected_byte
            || consumed[expected_byte - 1u] != 0u
            || strcmp(row->outcome, "TERMINAL_REJECT") != 0
            || row->exporter_calls != 0u || row->automatic_retry_count != 0u
            || row->wire_records_after_reject != 0u) {
            return 0;
        }
        stages = (uint8_t)(stages | bit);
        consumed[expected_byte - 1u] = 1u;
    }
    return stages == 0x0fu && consumed[0] && consumed[1] && consumed[2]
           && consumed[3];
}

static int pa_edhoc_failure_transition_machines(void)
{
    size_t index;
    if (!pa_ead_bijection_and_consumption(
            ninlil_pa_ead_failures, NINLIL_PA_EDHOC_EAD_FAILURE_COUNT)) {
        return 0;
    }
    for (index = 0u; index < NINLIL_PA_EDHOC_EAD_FAILURE_COUNT; ++index) {
        const ninlil_pa_ead_failure_t *row = &ninlil_pa_ead_failures[index];
        uint8_t state = 1u;
        uint8_t terminal = 0u;
        uint8_t exporter_calls = 0u;
        uint8_t retry_count = 0u;
        uint8_t wire_after = 0u;
        uint8_t stage;
        if (row->stage < 1u || row->stage > 4u || row->ead_size == 0u) {
            return 0;
        }
        for (stage = 1u; stage <= row->stage; ++stage) {
            const ninlil_pa_fixture_span_t *message =
                &ninlil_pa_edhoc_suite2_messages[stage - 1u];
            const size_t ead_size = stage == row->stage ? row->ead_size : 0u;
            if (state != stage
                || pa_nac_classify(
                    message->data, message->size, (uint8_t)(3u + stage),
                    (uint32_t)stage, 3u)
                    != PA_OK) {
                return 0;
            }
            if (ead_size > 0u) {
                terminal = 1u;
                state = 0xffu;
            } else {
                state = (uint8_t)(state + 1u);
                if (stage == 4u) {
                    exporter_calls = 8u;
                }
            }
        }
        if (!terminal || state != 0xffu || exporter_calls != row->exporter_calls
            || retry_count != row->automatic_retry_count
            || wire_after != row->wire_records_after_reject
            || strcmp(row->outcome, "TERMINAL_REJECT") != 0) {
            return 0;
        }
    }
    /* C-owned coherent mutants: all empty, all stage 1, duplicate consumed
     * bytes and swapped consumed bytes are each rejected by the same machine. */
    {
        ninlil_pa_ead_failure_t rows[4];
        (void)memcpy(rows, ninlil_pa_ead_failures, sizeof(rows));
        rows[0].ead_size = 0u;
        rows[1].ead_size = 0u;
        rows[2].ead_size = 0u;
        rows[3].ead_size = 0u;
        if (pa_ead_bijection_and_consumption(rows, 4u)) return 0;
        (void)memcpy(rows, ninlil_pa_ead_failures, sizeof(rows));
        rows[1].stage = 1u; rows[1].id = "EAD_1_NONEMPTY";
        rows[2].stage = 1u; rows[2].id = "EAD_1_NONEMPTY";
        rows[3].stage = 1u; rows[3].id = "EAD_1_NONEMPTY";
        if (pa_ead_bijection_and_consumption(rows, 4u)) return 0;
        (void)memcpy(rows, ninlil_pa_ead_failures, sizeof(rows));
        rows[1].ead = rows[0].ead; rows[1].ead_size = rows[0].ead_size;
        if (pa_ead_bijection_and_consumption(rows, 4u)) return 0;
        (void)memcpy(rows, ninlil_pa_ead_failures, sizeof(rows));
        { const uint8_t *ead = rows[0].ead; size_t size = rows[0].ead_size;
          rows[0].ead = rows[1].ead; rows[0].ead_size = rows[1].ead_size;
          rows[1].ead = ead; rows[1].ead_size = size; }
        if (pa_ead_bijection_and_consumption(rows, 4u)) return 0;
    }
    {
        uint8_t terminal = 0u;
        uint8_t automatic_retry = 0u;
        uint8_t fresh_policy_required = 0u;
        uint8_t fresh_session_required = 0u;
        if (NINLIL_PA_EDHOC_DOWNGRADE_INITIAL_SUITE
            != NINLIL_PA_EDHOC_DOWNGRADE_SUGGESTED_SUITE) {
            terminal = 1u;
            fresh_policy_required = 1u;
            fresh_session_required = 1u;
        } else if (NINLIL_PA_EDHOC_DOWNGRADE_SAME_POLICY_ALLOWED) {
            automatic_retry = 1u;
        }
        if (!terminal
            || automatic_retry != NINLIL_PA_EDHOC_DOWNGRADE_AUTORETRY
            || fresh_policy_required
                != NINLIL_PA_EDHOC_DOWNGRADE_FRESH_POLICY_REQUIRED
            || fresh_session_required
                != NINLIL_PA_EDHOC_DOWNGRADE_FRESH_SESSION_REQUIRED
            || strcmp(
                ninlil_pa_edhoc_downgrade_outcome,
                "TERMINAL_NO_AUTODOWNGRADE")
                != 0) {
            return 0;
        }
    }
    return 1;
}

static int pa_repaired_contracts(void)
{
    uint8_t old_value[32];
    uint8_t old_context[32];
    uint8_t new_value[32];
    uint8_t new_context[32];
    uint8_t third_value[32];
    uint8_t public_input[65];
    uint8_t digest[32];
    size_t index;

    (void)memset(old_value, 0x11, sizeof(old_value));
    (void)memset(old_context, 0x22, sizeof(old_context));
    (void)memset(new_value, 0x33, sizeof(new_value));
    (void)memset(new_context, 0x44, sizeof(new_context));
    (void)memset(third_value, 0x55, sizeof(third_value));
    if (pa_classify_cu_row(
            old_value,
            old_context,
            old_value,
            old_context,
            new_value,
            new_context)
            != PA_CU_ROW_OLD
        || pa_classify_cu_row(
            new_value,
            new_context,
            old_value,
            old_context,
            new_value,
            new_context)
            != PA_CU_ROW_NEW
        || pa_classify_cu_row(
            old_value,
            old_context,
            old_value,
            old_context,
            old_value,
            old_context)
            != PA_CU_ROW_STABLE
        || pa_classify_cu_row(
            third_value,
            old_context,
            old_value,
            old_context,
            new_value,
            new_context)
            != PA_CU_ROW_THIRD
        || NINLIL_PA_REATTACH_OLD_OBSERVED != 14u
        || NINLIL_PA_DEVICE_OLD_MEMBER_COUNT != 14u
        || NINLIL_PA_AUTHORITY_OLD_MEMBER_COUNT != 14u) {
        return 0;
    }
    pa_exec(PA_CASE_REATTACH_15ROW);
    pa_exec(PA_CASE_REATTACH_LANE_OLD);

    {
        uint64_t floors[4] = {42u, 44u, 48u, 54u};
        uint64_t high_waters[4] = {59u, 61u, 67u, 71u};
        uint8_t row[68];
        pa_sha256_ctx_t ctx;
        uint32_t cycle;
        pa_sha256_init(&ctx);
        if (NINLIL_PA_REATTACH_CYCLES != 10000u) {
            return 0;
        }
        for (cycle = 1u; cycle <= NINLIL_PA_REATTACH_CYCLES; ++cycle) {
            size_t offset = 0u;
            pa_put_u32(row + offset, cycle);
            offset += 4u;
            for (index = 0u; index < 4u; ++index) {
                floors[index] += 1u;
                pa_put_u64(row + offset, floors[index]);
                offset += 8u;
            }
            for (index = 0u; index < 4u; ++index) {
                high_waters[index] += 1u;
                pa_put_u64(row + offset, high_waters[index]);
                offset += 8u;
            }
            pa_sha256_update(&ctx, row, sizeof(row));
        }
        pa_sha256_final(&ctx, digest);
        if (floors[0] != 10042u || floors[3] != 10054u
            || high_waters[0] != 10059u || high_waters[3] != 10071u
            || memcmp(
                digest, ninlil_pa_reattach_10k_transcript_sha256, 32u)
                != 0) {
            return 0;
        }
    }
    pa_exec(PA_CASE_REATTACH_10K);

    if (strcmp(
            ninlil_pa_dependency_factory_identity,
            "UPSTREAM_ACCEPTANCE_NOT_ESTABLISHED")
            != 0
        || strcmp(
            ninlil_pa_dependency_site_membership,
            "UPSTREAM_ACCEPTANCE_NOT_ESTABLISHED")
            != 0
        || strcmp(
            ninlil_pa_dependency_owner_start, "FAIL_CLOSED_NOT_READY")
            != 0
        || memcmp(
            ninlil_pa_initiator_factory_stable_digest,
            ninlil_pa_nai1 + 32u,
            32u)
            != 0
        || memcmp(
            ninlil_pa_responder_factory_stable_digest,
            ninlil_pa_nai1 + 64u,
            32u)
            != 0
        || strcmp(ninlil_pa_local_static_dh_operation, "P256_STATIC_DH") != 0
        || strcmp(
            ninlil_pa_local_static_dh_output_owner,
            "CALLER_OWNED_BOUNDED_SECRET_WORKSPACE")
            != 0
        || strcmp(
            ninlil_pa_local_static_dh_partial_action,
            "ZEROIZE32_AND_TERMINAL")
            != 0
        || NINLIL_PA_LOCAL_DH_OUTPUT_BYTES != 32u
        || NINLIL_PA_LOCAL_DH_WRITE_COUNT != 1u
        || NINLIL_PA_LOCAL_REAL_PROVIDER_KAT_CLAIMED != 0u) {
        return 0;
    }
    public_input[0] = 4u;
    (void)memcpy(public_input + 1u, ninlil_pa_initiator_x, 32u);
    (void)memcpy(public_input + 33u, ninlil_pa_initiator_y, 32u);
    pa_sha256(public_input, sizeof(public_input), digest);
    if (memcmp(digest, ninlil_pa_initiator_public_key_digest, 32u) != 0
        || memcmp(
            ninlil_pa_initiator_opaque_key_reference, "IKREF001", 8u)
            != 0) {
        return 0;
    }
    public_input[0] = 4u;
    (void)memcpy(public_input + 1u, ninlil_pa_responder_x, 32u);
    (void)memcpy(public_input + 33u, ninlil_pa_responder_y, 32u);
    pa_sha256(public_input, sizeof(public_input), digest);
    if (memcmp(digest, ninlil_pa_responder_public_key_digest, 32u) != 0
        || memcmp(
            ninlil_pa_responder_opaque_key_reference, "RKREF001", 8u)
            != 0) {
        return 0;
    }
    pa_exec(PA_CASE_PREREQUISITES);
    if (NINLIL_PA_LOCAL_KEY_FAILURE_COUNT != 10u
        || !pa_local_key_failure_machine()) {
        return 0;
    }
    pa_exec(PA_CASE_LOCAL_KEY_FAILURES);

    for (index = 0u; index < 2u; ++index) {
        const ninlil_pa_fixture_span_t *messages =
            (index == 0u) ? ninlil_pa_edhoc_suite2_messages
                          : ninlil_pa_edhoc_suite3_messages;
        const uint8_t suite = (index == 0u) ? 2u : 3u;
        const uint64_t generation =
            (index == 0u) ? NINLIL_PA_EDHOC_S2_GENERATION
                          : NINLIL_PA_EDHOC_S3_GENERATION;
        size_t stage;
        for (stage = 0u; stage < NINLIL_PA_EDHOC_MESSAGE_COUNT; ++stage) {
            const uint8_t *record = messages[stage].data;
            if (pa_nac_classify(
                    record,
                    messages[stage].size,
                    (uint8_t)(4u + stage),
                    (uint32_t)(1u + stage),
                    3u)
                    != PA_OK
                || pa_u64(record + 36u) != generation
                || (stage == 0u
                    && (record[88] != 3u || record[89] != suite))) {
                return 0;
            }
        }
        pa_exec(
            (index == 0u) ? PA_CASE_EDHOC_SUITE2_M1_M4
                          : PA_CASE_EDHOC_SUITE3_M1_M4);
    }
    if (strcmp(
            ninlil_pa_edhoc_fixture_kind,
            "SYNTHETIC_PROFILE_STATE_MACHINE_NOT_CRYPTO_KAT")
            != 0
        || strcmp(
            ninlil_pa_edhoc_rfc_trace_role,
            "ALGORITHM_REFERENCE_ONLY_NOT_PROFILE_NEGOTIATION_POSITIVE")
            != 0
        || NINLIL_PA_EDHOC_EXPORTER_BEFORE_M4 != 0u
        || NINLIL_PA_EDHOC_EXPORTER_AFTER_M4 != 8u
        || NINLIL_PA_EDHOC_EAD_FAILURE_COUNT != 4u) {
        return 0;
    }
    if (!pa_edhoc_failure_transition_machines()) {
        return 0;
    }
    pa_exec(PA_CASE_EDHOC_EAD_TERMINAL);
    pa_exec(PA_CASE_EDHOC_DOWNGRADE);

    if (NINLIL_PA_PREAUTH_PER_SOURCE_LIMIT != 1u
        || NINLIL_PA_PREAUTH_GLOBAL_LIMIT != 8u
        || NINLIL_PA_PREAUTH_SCRATCH_FRAGMENTS != 2u
        || NINLIL_PA_PREAUTH_IDLE_TIMEOUT_SECONDS != 9u
        || NINLIL_PA_PREAUTH_TOKEN_CAPACITY != 2u
        || NINLIL_PA_PREAUTH_TOKEN_REFILL_SECONDS != 2u
        || !pa_any_nonzero(ninlil_pa_source_locator_digest, 32u)
        || !pa_preauth_transition_machine()) {
        return 0;
    }
    pa_exec(PA_CASE_PREAUTH_OWNER);

    if (strcmp(ninlil_pa_magic_registry, "spec/protocol-magic-registry-v1.json")
            != 0
        || strcmp(ninlil_pa_magic_nac1, "NAC1") != 0
        || strcmp(ninlil_pa_magic_nar1, "NAR1") != 0
        || strcmp(ninlil_pa_magic_nas1, "NAS1") != 0
        || strcmp(ninlil_pa_magic_nac1, ninlil_pa_magic_nar1) == 0
        || strcmp(ninlil_pa_magic_nac1, ninlil_pa_magic_nas1) == 0
        || strcmp(ninlil_pa_magic_nar1, ninlil_pa_magic_nas1) == 0
        || memcmp(ninlil_pa_nac_suite2_m1, "NAC1", 4u) != 0
        || memcmp(ninlil_pa_fragments[0].data, "NAR1", 4u) != 0
        || memcmp(ninlil_pa_nas_usb_m1, "NAS1", 4u) != 0) {
        return 0;
    }
    pa_exec(PA_CASE_MAGIC_GLOBAL);

    {
        uint8_t coherent[sizeof(ninlil_pa_initiator_ccs)];
        uint8_t coherent_sha[32];
        (void)memcpy(
            coherent, ninlil_pa_initiator_ccs, sizeof(coherent));
        coherent[sizeof(coherent) - 1u] ^= 1u;
        pa_sha256(coherent, sizeof(coherent), coherent_sha);
        if (memcmp(coherent_sha, ninlil_pa_initiator_cred_digest, 32u) == 0
            || memcmp(
                coherent,
                ninlil_pa_initiator_ccs,
                sizeof(ninlil_pa_initiator_ccs))
                == 0) {
            return 0;
        }
    }
    pa_exec(PA_CASE_COHERENT_DRIFT);
    return 1;
}

static int pa_all_cases_executed(void)
{
    int index;
    for (index = 0; index < PA_CASE_COUNT; ++index) {
        if (g_pa_cases[index] == 0u) {
            (void)fprintf(
                stderr,
                "production_attachment_edhoc_vector FAIL missing case %d (%s)\n",
                index,
                g_pa_case_names[index]);
            return 0;
        }
    }
    return 1;
}

int main(void)
{
    (void)memset(g_pa_cases, 0, sizeof(g_pa_cases));
    if (!pa_positive()) {
        (void)fprintf(
            stderr, "production_attachment_edhoc_vector FAIL positive\n");
        return 1;
    }
    if (!pa_mutations()) {
        (void)fprintf(
            stderr, "production_attachment_edhoc_vector FAIL mutation\n");
        return 1;
    }
    if (!pa_repaired_nar_nas_state_machines()) {
        (void)fprintf(
            stderr,
            "production_attachment_edhoc_vector FAIL repaired NAR/NAS\n");
        return 1;
    }
    if (!pa_repaired_contracts()) {
        (void)fprintf(
            stderr,
            "production_attachment_edhoc_vector FAIL repaired contracts\n");
        return 1;
    }
    if (!pa_all_cases_executed()) {
        return 1;
    }
    (void)printf(
        "production_attachment_edhoc_vector OK fragments=%u atomic_members=%u "
        "cookie_response=%u executed_cases=%u\n",
        (unsigned int)NINLIL_PA_FRAGMENT_COUNT,
        (unsigned int)NINLIL_PA_NAB_ENTRY_COUNT,
        (unsigned int)NINLIL_PA_COOKIE_RESPONSE_BYTES,
        (unsigned int)PA_CASE_COUNT);
    return 0;
}
