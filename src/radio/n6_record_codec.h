#ifndef NINLIL_RADIO_N6_RECORD_CODEC_H
#define NINLIL_RADIO_N6_RECORD_CODEC_H

/*
 * N6 durable record pure BE codec (docs/30 §5.3).
 *
 * SEMANTIC: N6_PRIVATE_ONLY_NO_PUBLIC_ABI
 * SEMANTIC: N6_BE_ENCODING_ONLY
 * SEMANTIC: N6_VALUE_CRC32C_CANONICAL
 * SEMANTIC: N6_NO_PERSIST_C_STRUCTS
 * SEMANTIC: N6_CHUNK_D_PRIVATE_HOST_CANDIDATE
 * SEMANTIC: N6_CODEC_EXACT_LENGTH_AND_CLOSED_DOMAIN
 *
 * Decode takes (const uint8_t *in, size_t in_len) — C array parameters
 * decay to pointers and cannot enforce exact length. Wrong/truncated/
 * oversize length ⇒ REJECT. Parse+validate into a local temporary; publish
 * to *out only on full success. Failure leaves *out unmodified (mutation 0).
 * Encode builds wire in a local temporary; rejects in/out range overlap
 * (alias); publishes to out only after full input validation. CRC32C is the
 * domain-store Castagnoli implementation (wrapper only).
 *
 * Production-private under src/radio/. Not installed. Not R6 complete.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Exact wire sizes (docs/30 §5.3) ---- */

#define NINLIL_N6_LANE_KEY_BYTES ((size_t)48u)
#define NINLIL_N6_TX_VALUE_BYTES ((size_t)68u)
#define NINLIL_N6_RX_VALUE_BYTES ((size_t)68u)
#define NINLIL_N6_HW_KEY_BYTES ((size_t)32u)
#define NINLIL_N6_HW_VALUE_BYTES ((size_t)28u)
#define NINLIL_N6_AL_KEY_BYTES ((size_t)24u)
#define NINLIL_N6_AL_VALUE_BYTES ((size_t)56u)
#define NINLIL_N6_RT_KEY_BYTES ((size_t)28u)
#define NINLIL_N6_RT_VALUE_BYTES ((size_t)48u)
#define NINLIL_N6_CF_KEY_BYTES ((size_t)28u)
#define NINLIL_N6_CF_VALUE_BYTES ((size_t)64u)

#define NINLIL_N6_BINDING_DIGEST_BYTES ((size_t)32u)
#define NINLIL_N6_BINDING_PREFIX_BYTES ((size_t)16u)
#define NINLIL_N6_NS_FINGERPRINT_BYTES ((size_t)12u)
#define NINLIL_N6_SCOPE_DIGEST_BYTES ((size_t)28u)
#define NINLIL_N6_NODE_ID_BYTES ((size_t)16u)
#define NINLIL_N6_BINDING_DIGEST12_BYTES ((size_t)12u)
#define NINLIL_N6_FENCE_STAMP_EPOCH_BYTES ((size_t)16u)

/* Magics (u32 BE on wire) */
#define NINLIL_N6_MAGIC_TX ((uint32_t)0x4E365458u) /* "N6TX" */
#define NINLIL_N6_MAGIC_RX ((uint32_t)0x4E365258u) /* "N6RX" */
#define NINLIL_N6_MAGIC_HW ((uint32_t)0x4E364857u) /* "N6HW" */
#define NINLIL_N6_MAGIC_AL ((uint32_t)0x4E36414Cu) /* "N6AL" */
#define NINLIL_N6_MAGIC_RT ((uint32_t)0x4E365254u) /* "N6RT" */
#define NINLIL_N6_MAGIC_CF ((uint32_t)0x4E364346u) /* "N6CF" */

#define NINLIL_N6_SCHEMA_LANE ((uint16_t)2u)
#define NINLIL_N6_SCHEMA_HW ((uint16_t)1u)
#define NINLIL_N6_SCHEMA_AL ((uint16_t)2u)
#define NINLIL_N6_SCHEMA_RT ((uint16_t)2u)
#define NINLIL_N6_SCHEMA_CF ((uint16_t)2u)

/* Closed domains (codec-enforced) */
#define NINLIL_N6_LAYER_HOP ((uint8_t)1u)
#define NINLIL_N6_LAYER_E2E ((uint8_t)2u)

#define NINLIL_N6_LANE_HOP_DATA ((uint8_t)1u)
#define NINLIL_N6_LANE_HOP_ACK ((uint8_t)2u)
#define NINLIL_N6_LANE_E2E ((uint8_t)3u)

#define NINLIL_N6_DIR_IR ((uint8_t)0u)
#define NINLIL_N6_DIR_RI ((uint8_t)1u)

#define NINLIL_N6_ALLOC_INBOUND_RX ((uint8_t)1u)
#define NINLIL_N6_ALLOC_OUTBOUND_TX ((uint8_t)2u)

#define NINLIL_N6_REC_KIND_HW ((uint8_t)1u)
#define NINLIL_N6_REC_KIND_AL ((uint8_t)2u)
#define NINLIL_N6_REC_KIND_RT ((uint8_t)3u)
#define NINLIL_N6_REC_KIND_CF ((uint8_t)4u)

#define NINLIL_N6_RT_FLAGS_LANE_ERASED ((uint16_t)0x0001u)
#define NINLIL_N6_CF_FLAGS_FENCE_ACTIVE ((uint16_t)0x0001u)

#define NINLIL_N6_FENCE_REASON_DIGEST ((uint8_t)1u)
#define NINLIL_N6_FENCE_REASON_KGEN_ROLLBACK ((uint8_t)2u)
#define NINLIL_N6_FENCE_REASON_CORRUPT ((uint8_t)3u)
#define NINLIL_N6_FENCE_REASON_MEMBERSHIP ((uint8_t)4u)
#define NINLIL_N6_FENCE_REASON_OPERATOR ((uint8_t)5u)

/* Codec status: 0 = ok; nonzero reject (mutation 0 on caller durable path). */
typedef int32_t ninlil_n6_codec_status_t;
#define NINLIL_N6_CODEC_OK ((ninlil_n6_codec_status_t)0)
#define NINLIL_N6_CODEC_INVALID_ARGUMENT ((ninlil_n6_codec_status_t)1)
#define NINLIL_N6_CODEC_REJECT ((ninlil_n6_codec_status_t)2)

/* ---- Host logical structs (never persist these layouts) ---- */

typedef struct ninlil_n6_lane_key {
    uint8_t layer_code;
    uint8_t kind_or_lane;
    uint8_t direction_code;
    uint8_t reserved0;
    uint32_t context_id;
    uint8_t binding_digest32[NINLIL_N6_BINDING_DIGEST_BYTES];
    uint64_t key_generation;
} ninlil_n6_lane_key_t;

typedef struct ninlil_n6_tx_value {
    uint32_t magic;
    uint16_t schema;
    uint16_t reserved0;
    uint64_t reserved_exclusive;
    uint64_t key_generation;
    uint8_t binding_digest_prefix16[NINLIL_N6_BINDING_PREFIX_BYTES];
    uint64_t membership_epoch;
    uint8_t alloc_side;
    uint8_t reserved1[3];
    uint8_t ns_fingerprint12[NINLIL_N6_NS_FINGERPRINT_BYTES];
    uint32_t value_crc32c;
} ninlil_n6_tx_value_t;

typedef struct ninlil_n6_rx_value {
    uint32_t magic;
    uint16_t schema;
    uint16_t reserved0;
    uint64_t accept_reserved_through;
    uint64_t key_generation;
    uint8_t binding_digest_prefix16[NINLIL_N6_BINDING_PREFIX_BYTES];
    uint64_t membership_epoch;
    uint8_t alloc_side;
    uint8_t reserved1[3];
    uint8_t ns_fingerprint12[NINLIL_N6_NS_FINGERPRINT_BYTES];
    uint32_t value_crc32c;
} ninlil_n6_rx_value_t;

typedef struct ninlil_n6_hw_key {
    uint8_t rec_kind;
    uint8_t layer_code;
    uint8_t direction_code;
    uint8_t reserved0;
    uint8_t scope_digest28[NINLIL_N6_SCOPE_DIGEST_BYTES];
} ninlil_n6_hw_key_t;

typedef struct ninlil_n6_hw_value {
    uint32_t magic;
    uint16_t schema;
    uint16_t reserved0;
    uint64_t high_water_key_generation;
    uint64_t last_update_authority_now_ms;
    uint32_t value_crc32c;
} ninlil_n6_hw_value_t;

typedef struct ninlil_n6_al_key {
    uint8_t rec_kind;
    uint8_t layer_code;
    uint8_t alloc_side;
    uint8_t reserved0;
    uint64_t membership_epoch;
    uint8_t ns_fingerprint12[NINLIL_N6_NS_FINGERPRINT_BYTES];
} ninlil_n6_al_key_t;

typedef struct ninlil_n6_al_value {
    uint32_t magic;
    uint16_t schema;
    uint16_t reserved0;
    uint32_t next_free_or_peer_floor;
    uint16_t active_count;
    uint16_t retired_tombstone_count;
    uint32_t reserved1;
    uint64_t membership_epoch;
    uint64_t last_alloc_authority_now_ms;
    uint8_t receiver_node_id[NINLIL_N6_NODE_ID_BYTES];
    uint32_t value_crc32c;
} ninlil_n6_al_value_t;

typedef struct ninlil_n6_rt_key {
    uint8_t rec_kind;
    uint8_t layer_code;
    uint8_t direction_code;
    uint8_t alloc_side;
    uint32_t context_id;
    uint64_t membership_epoch;
    uint8_t ns_fingerprint12[NINLIL_N6_NS_FINGERPRINT_BYTES];
} ninlil_n6_rt_key_t;

typedef struct ninlil_n6_rt_value {
    uint32_t magic;
    uint16_t schema;
    uint16_t flags;
    uint32_t context_id;
    uint64_t membership_epoch;
    uint64_t last_key_generation_high_water;
    uint8_t binding_digest12[NINLIL_N6_BINDING_DIGEST12_BYTES];
    uint8_t alloc_side;
    uint8_t direction_code;
    uint8_t layer_code;
    uint8_t reserved0;
    uint32_t value_crc32c;
} ninlil_n6_rt_value_t;

typedef struct ninlil_n6_cf_key {
    uint8_t rec_kind;
    uint8_t layer_code;
    uint8_t direction_code;
    uint8_t alloc_side;
    uint32_t context_id;
    uint64_t membership_epoch;
    uint8_t ns_fingerprint12[NINLIL_N6_NS_FINGERPRINT_BYTES];
} ninlil_n6_cf_key_t;

typedef struct ninlil_n6_cf_value {
    uint32_t magic;
    uint16_t schema;
    uint16_t flags;
    uint32_t context_id;
    uint64_t membership_epoch;
    uint8_t fence_stamp_epoch_id[NINLIL_N6_FENCE_STAMP_EPOCH_BYTES];
    uint64_t fence_stamp_now_ms;
    uint8_t binding_digest12[NINLIL_N6_BINDING_DIGEST12_BYTES];
    uint8_t alloc_side;
    uint8_t direction_code;
    uint8_t layer_code;
    uint8_t reason;
    uint32_t value_crc32c;
} ninlil_n6_cf_value_t;

/*
 * CRC32C Castagnoli — thin wrapper over ninlil_model_domain_crc32c
 * (poly 0x82f63b78, init/xorout 0xffffffff). No second poly implementation.
 */
uint32_t ninlil_n6_crc32c(const uint8_t *bytes, size_t len);

/*
 * Encode: on success *out_len = exact wire size; on failure *out_len is
 * unchanged (when out_len non-NULL). Requires out_cap >= exact; rejects
 * NULL / capacity / in↔out range alias / out_len span alias into out[] or
 * logical input. Wire is assembled in a temporary; out is written only
 * after full success (failure: out arena mutation 0).
 *
 * Decode: requires in_len == exact size (truncated/oversize ⇒ REJECT).
 * Rejects in↔out range alias. Parses into temporary; *out published only
 * after magic/schema/reserved/domain/CRC success. Failure: *out mutation 0.
 */

ninlil_n6_codec_status_t ninlil_n6_encode_lane_key(
    const ninlil_n6_lane_key_t *in,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len);
ninlil_n6_codec_status_t ninlil_n6_decode_lane_key(
    const uint8_t *in,
    size_t in_len,
    ninlil_n6_lane_key_t *out);

ninlil_n6_codec_status_t ninlil_n6_encode_n6tx_value(
    const ninlil_n6_tx_value_t *in,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len);
ninlil_n6_codec_status_t ninlil_n6_decode_n6tx_value(
    const uint8_t *in,
    size_t in_len,
    ninlil_n6_tx_value_t *out);

ninlil_n6_codec_status_t ninlil_n6_encode_n6rx_value(
    const ninlil_n6_rx_value_t *in,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len);
ninlil_n6_codec_status_t ninlil_n6_decode_n6rx_value(
    const uint8_t *in,
    size_t in_len,
    ninlil_n6_rx_value_t *out);

ninlil_n6_codec_status_t ninlil_n6_encode_n6hw_key(
    const ninlil_n6_hw_key_t *in,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len);
ninlil_n6_codec_status_t ninlil_n6_decode_n6hw_key(
    const uint8_t *in,
    size_t in_len,
    ninlil_n6_hw_key_t *out);

ninlil_n6_codec_status_t ninlil_n6_encode_n6hw_value(
    const ninlil_n6_hw_value_t *in,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len);
ninlil_n6_codec_status_t ninlil_n6_decode_n6hw_value(
    const uint8_t *in,
    size_t in_len,
    ninlil_n6_hw_value_t *out);

ninlil_n6_codec_status_t ninlil_n6_encode_n6al_key(
    const ninlil_n6_al_key_t *in,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len);
ninlil_n6_codec_status_t ninlil_n6_decode_n6al_key(
    const uint8_t *in,
    size_t in_len,
    ninlil_n6_al_key_t *out);

ninlil_n6_codec_status_t ninlil_n6_encode_n6al_value(
    const ninlil_n6_al_value_t *in,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len);
ninlil_n6_codec_status_t ninlil_n6_decode_n6al_value(
    const uint8_t *in,
    size_t in_len,
    ninlil_n6_al_value_t *out);

ninlil_n6_codec_status_t ninlil_n6_encode_n6rt_key(
    const ninlil_n6_rt_key_t *in,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len);
ninlil_n6_codec_status_t ninlil_n6_decode_n6rt_key(
    const uint8_t *in,
    size_t in_len,
    ninlil_n6_rt_key_t *out);

ninlil_n6_codec_status_t ninlil_n6_encode_n6rt_value(
    const ninlil_n6_rt_value_t *in,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len);
ninlil_n6_codec_status_t ninlil_n6_decode_n6rt_value(
    const uint8_t *in,
    size_t in_len,
    ninlil_n6_rt_value_t *out);

ninlil_n6_codec_status_t ninlil_n6_encode_n6cf_key(
    const ninlil_n6_cf_key_t *in,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len);
ninlil_n6_codec_status_t ninlil_n6_decode_n6cf_key(
    const uint8_t *in,
    size_t in_len,
    ninlil_n6_cf_key_t *out);

ninlil_n6_codec_status_t ninlil_n6_encode_n6cf_value(
    const ninlil_n6_cf_value_t *in,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len);
ninlil_n6_codec_status_t ninlil_n6_decode_n6cf_value(
    const uint8_t *in,
    size_t in_len,
    ninlil_n6_cf_value_t *out);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RADIO_N6_RECORD_CODEC_H */
