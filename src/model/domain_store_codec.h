#ifndef NINLIL_MODEL_DOMAIN_STORE_CODEC_H
#define NINLIL_MODEL_DOMAIN_STORE_CODEC_H

#include <stddef.h>
#include <stdint.h>

#include <ninlil/runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Domain Store v1 pure codec — D1-A framing/primitive slice only.
 * Production-private; not installed. Does not complete full docs17 D1
 * (semantic body codecs, builders, recovery scan remain later).
 *
 * Output / alias contract:
 * - All participating input and output ranges must be pairwise disjoint.
 * - Alias / address overflow: return NINLIL_E_INVALID_ARGUMENT without
 *   modifying any participating range.
 * - After alias is ruled out and an output pointer is valid, non-alias
 *   failures zero all output objects/digests and set *out_length = 0
 *   (except NINLIL_E_BUFFER_TOO_SMALL, which sets only the documented
 *   required length). This includes NINLIL_E_UNSUPPORTED.
 * - NULL output pointers cannot be zeroed (trivial exception).
 *
 * Witness header encode/decode enforce the section 10.0 metadata matrix
 * for constraints decidable from (kind, identity, subject, retention):
 * - Locally derivable subject_id (kinds 4/7/13 ORDERED_INGRESS key digest
 *   prefix; kind 17 family-4 capacity key digest prefix; kind 20 BEARER_STATE
 *   singleton key digest prefix) are checked exactly.
 * - Relations needing external builder/snapshot state (e.g. TRANSACTION_ANCHOR
 *   KEY_DIGEST from bare transaction ID; DELIVERY key for kinds 8–12; kind 6
 *   send/reply owner; kind 18 cleanup subject) enforce only closed retention
 *   sets and zero/nonzero digest consistency, not full equality.
 */

/* --- section 2 bounded format constants --- */
#define NINLIL_MODEL_DOMAIN_FORMAT_VERSION ((uint16_t)1u)
#define NINLIL_MODEL_DOMAIN_RECORD_VERSION ((uint16_t)1u)
#define NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES ((uint32_t)4096u)
#define NINLIL_MODEL_DOMAIN_PRIVATE_BODY_MAX_BYTES ((uint32_t)3984u)
#define NINLIL_MODEL_DOMAIN_BLOB_CHUNK_DATA_MAX_BYTES ((uint32_t)3072u)
#define NINLIL_MODEL_DOMAIN_WITNESS_MEMBER_MAX ((uint32_t)256u)
#define NINLIL_MODEL_DOMAIN_WITNESS_ENTRIES_PER_CHUNK ((uint32_t)8u)
#define NINLIL_MODEL_DOMAIN_WITNESS_CHUNK_MAX ((uint32_t)32u)
#define NINLIL_MODEL_DOMAIN_RAW_IDEMPOTENCY_KEY_MAX ((uint32_t)64u)
#define NINLIL_MODEL_DOMAIN_AUDIT_METADATA_MAX ((uint32_t)128u)
#define NINLIL_MODEL_DOMAIN_EVIDENCE_BYTES_MAX ((uint32_t)128u)

#define NINLIL_MODEL_DOMAIN_KEY_ROOT_BYTES ((uint32_t)8u)
#define NINLIL_MODEL_DOMAIN_KEY_MIN_BYTES ((uint32_t)13u)
#define NINLIL_MODEL_DOMAIN_KEY_MAX_CURRENT_BYTES ((uint32_t)45u)
#define NINLIL_MODEL_DOMAIN_KEY_MAX_BYTES ((uint32_t)255u)
#define NINLIL_MODEL_DOMAIN_COMMON_HEADER_BYTES ((uint32_t)96u)
#define NINLIL_MODEL_DOMAIN_ENVELOPE_OVERHEAD ((uint32_t)16u)
#define NINLIL_MODEL_DOMAIN_DIGEST_BYTES ((uint32_t)32u)
#define NINLIL_MODEL_DOMAIN_ID_BYTES ((uint32_t)16u)
#define NINLIL_MODEL_DOMAIN_OPERATION_IDENTITY_MAX ((uint32_t)128u)
#define NINLIL_MODEL_DOMAIN_MANIFEST_CHUNK_BODY_MAX ((uint32_t)3000u)
#define NINLIL_MODEL_DOMAIN_WITNESS_HEADER_BODY_MAX ((uint32_t)384u)

/* Families and record types */
#define NINLIL_MODEL_DOMAIN_FAMILY_HEALTH ((uint8_t)0x05u)
#define NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN ((uint8_t)0x06u)
#define NINLIL_MODEL_DOMAIN_RECORD_TYPE_HEALTH ((uint16_t)5u)
#define NINLIL_MODEL_DOMAIN_RECORD_TYPE_DOMAIN ((uint16_t)6u)

/* Key format and identity kinds (section 5) */
#define NINLIL_MODEL_DOMAIN_KEY_FORMAT_V1 ((uint8_t)1u)
#define NINLIL_MODEL_DOMAIN_ID_KIND_SINGLETON ((uint8_t)1u)
#define NINLIL_MODEL_DOMAIN_ID_KIND_ID128 ((uint8_t)2u)
#define NINLIL_MODEL_DOMAIN_ID_KIND_U64 ((uint8_t)3u)
#define NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_RAW ((uint8_t)4u)
#define NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE ((uint8_t)5u)

/* Family 5 subtype */
#define NINLIL_MODEL_DOMAIN_SUBTYPE_INTERNAL_INVARIANT ((uint8_t)0x01u)

/* Family 6 closed subtype catalog (section 7) */
#define NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE ((uint8_t)0x10u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE_QUOTA ((uint8_t)0x11u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR ((uint8_t)0x20u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_SEQUENCE_INDEX ((uint8_t)0x21u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE ((uint8_t)0x22u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION ((uint8_t)0x23u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP ((uint8_t)0x24u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_ID_MAP ((uint8_t)0x25u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_SCHEDULER_OWNER ((uint8_t)0x26u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS ((uint8_t)0x27u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB ((uint8_t)0x30u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT ((uint8_t)0x31u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_EVIDENCE_CELL ((uint8_t)0x32u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_CANCEL_STATE ((uint8_t)0x33u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX ((uint8_t)0x34u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY ((uint8_t)0x40u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE ((uint8_t)0x41u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY ((uint8_t)0x42u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_SPOOL ((uint8_t)0x50u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_RETRY_SUMMARY ((uint8_t)0x51u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_MANAGEMENT_LEDGER ((uint8_t)0x52u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_BEARER_STATE ((uint8_t)0x60u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_RETENTION_BASIS ((uint8_t)0x61u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE ((uint8_t)0x62u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_CLEANUP_PLAN ((uint8_t)0x63u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_REUSE_FENCE ((uint8_t)0x64u)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX ((uint8_t)0x7du)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK ((uint8_t)0x7eu)
#define NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER ((uint8_t)0x7fu)

/* BLOB common flags (section 4) */
#define NINLIL_MODEL_DOMAIN_FLAG_BLOB_MANIFEST ((uint8_t)0x01u)
#define NINLIL_MODEL_DOMAIN_FLAG_BLOB_CHUNK ((uint8_t)0x02u)

/* Witness action / state (section 10) */
#define NINLIL_MODEL_DOMAIN_WITNESS_ACTION_CREATE ((uint8_t)1u)
#define NINLIL_MODEL_DOMAIN_WITNESS_ACTION_REPLACE ((uint8_t)2u)
#define NINLIL_MODEL_DOMAIN_WITNESS_ACTION_ERASE ((uint8_t)3u)
#define NINLIL_MODEL_DOMAIN_WITNESS_ACTION_SUPERSEDE ((uint8_t)4u)
#define NINLIL_MODEL_DOMAIN_WITNESS_STATE_ACTIVE ((uint16_t)1u)
#define NINLIL_MODEL_DOMAIN_WITNESS_STATE_SUPERSEDED ((uint16_t)2u)
#define NINLIL_MODEL_DOMAIN_WITNESS_STATE_RETIRED ((uint16_t)3u)

/* Health / fence private registries (section 14) */
#define NINLIL_MODEL_DOMAIN_HEALTH_KIND_CREATE_STORAGE_FAILURE ((uint16_t)1u)
#define NINLIL_MODEL_DOMAIN_HEALTH_KIND_COMMIT_UNKNOWN ((uint16_t)2u)
#define NINLIL_MODEL_DOMAIN_HEALTH_KIND_DELIVERY_CALLBACK_CONTRACT ((uint16_t)3u)
#define NINLIL_MODEL_DOMAIN_HEALTH_KIND_DELIVERY_APPLICATION_FATAL ((uint16_t)4u)
#define NINLIL_MODEL_DOMAIN_HEALTH_KIND_CLOCK_FENCE ((uint16_t)5u)
#define NINLIL_MODEL_DOMAIN_HEALTH_KIND_FAMILY3_COUNTER ((uint16_t)6u)
#define NINLIL_MODEL_DOMAIN_HEALTH_KIND_FAMILY4_CAPACITY ((uint16_t)7u)
#define NINLIL_MODEL_DOMAIN_HEALTH_KIND_EVENT_COUNTER ((uint16_t)8u)
#define NINLIL_MODEL_DOMAIN_HEALTH_KIND_RETENTION_OVERFLOW ((uint16_t)9u)
#define NINLIL_MODEL_DOMAIN_HEALTH_KIND_DELIVERY_COUNTER ((uint16_t)10u)
#define NINLIL_MODEL_DOMAIN_HEALTH_KIND_INTERNAL_INVARIANT ((uint16_t)11u)
#define NINLIL_MODEL_DOMAIN_HEALTH_KIND_SEND_COUNTER ((uint16_t)12u)

#define NINLIL_MODEL_DOMAIN_FENCE_KIND_WITNESS ((uint16_t)1u)
#define NINLIL_MODEL_DOMAIN_FENCE_KIND_BOOTSTRAP ((uint16_t)2u)
#define NINLIL_MODEL_DOMAIN_FENCE_KIND_CLOCK_BASELINE ((uint16_t)3u)
#define NINLIL_MODEL_DOMAIN_FENCE_KIND_IDENTITY_ROTATION ((uint16_t)4u)

typedef enum ninlil_model_domain_key_class {
    NINLIL_MODEL_DOMAIN_KEY_CLASS_CURRENT = 1,
    NINLIL_MODEL_DOMAIN_KEY_CLASS_RECOGNIZABLE_FUTURE = 2,
    NINLIL_MODEL_DOMAIN_KEY_CLASS_MALFORMED = 3
} ninlil_model_domain_key_class_t;

typedef struct ninlil_model_domain_key {
    uint8_t bytes[NINLIL_MODEL_DOMAIN_KEY_MAX_BYTES];
    uint32_t length;
} ninlil_model_domain_key_t;

typedef struct ninlil_model_domain_key_view {
    uint8_t family;
    uint8_t subtype;
    uint8_t key_format;
    uint8_t identity_kind;
    uint8_t identity_length;
    const uint8_t *identity; /* borrows encoded key when from parse */
} ninlil_model_domain_key_view_t;

typedef struct ninlil_model_domain_common_header {
    uint16_t domain_format;
    uint8_t subtype;
    uint8_t flags;
    uint64_t record_revision;
    uint8_t primary_id[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint8_t head_witness_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint8_t primary_value_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint32_t body_length;
} ninlil_model_domain_common_header_t;

typedef struct ninlil_model_domain_envelope {
    uint16_t record_type;
    uint16_t record_version;
    ninlil_model_domain_common_header_t header;
    ninlil_bytes_view_t body; /* borrows encoded value payload body */
    uint32_t crc32c;
} ninlil_model_domain_envelope_t;

typedef struct ninlil_model_domain_digest {
    uint8_t bytes[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
} ninlil_model_domain_digest_t;

/*
 * Streaming SHA-256 context (no heap; fixed 64-byte block buffer).
 * Callers must treat fields as opaque: only init/update/final/one-shot
 * may mutate. Malformed contexts (buffer_length > 63, non-block-aligned
 * bit_length) are rejected safely by update/final.
 */
typedef struct ninlil_model_domain_sha256_ctx {
    uint64_t bit_length;
    uint32_t state[8];
    uint8_t buffer[64];
    uint32_t buffer_length;
} ninlil_model_domain_sha256_ctx_t;

typedef struct ninlil_model_domain_witness_header {
    uint16_t operation_kind;
    uint16_t witness_state;
    uint16_t operation_identity_length;
    uint8_t operation_identity[NINLIL_MODEL_DOMAIN_OPERATION_IDENTITY_MAX];
    uint8_t subject_id[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint8_t canonical_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint16_t member_count;
    uint16_t chunk_count;
    uint8_t manifest_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint16_t retention_kind;
    uint8_t retention_subject_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint8_t successor_witness_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
} ninlil_model_domain_witness_header_t;

typedef struct ninlil_model_domain_witness_entry {
    uint16_t record_role;
    uint8_t action;
    uint16_t key_length;
    const uint8_t *key_bytes; /* encode: caller; decode: borrow */
    uint8_t old_present;
    uint8_t new_present;
    uint8_t prior_head_witness_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint8_t old_value_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint8_t new_value_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
} ninlil_model_domain_witness_entry_t;

typedef struct ninlil_model_domain_witness_chunk {
    uint8_t witness_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint16_t chunk_index;
    uint16_t chunk_count;
    uint16_t entry_count;
    ninlil_model_domain_witness_entry_t entries[
        NINLIL_MODEL_DOMAIN_WITNESS_ENTRIES_PER_CHUNK];
} ninlil_model_domain_witness_chunk_t;

/* --- SHA-256 --- */
void ninlil_model_domain_sha256_init(ninlil_model_domain_sha256_ctx_t *ctx);
ninlil_status_t ninlil_model_domain_sha256_update(
    ninlil_model_domain_sha256_ctx_t *ctx,
    const uint8_t *data,
    uint32_t length);
ninlil_status_t ninlil_model_domain_sha256_final(
    ninlil_model_domain_sha256_ctx_t *ctx,
    ninlil_model_domain_digest_t *out_digest);
ninlil_status_t ninlil_model_domain_sha256(
    const uint8_t *data,
    uint32_t length,
    ninlil_model_domain_digest_t *out_digest);

/* --- CRC32C (Castagnoli; same polynomial as Runtime Store envelope) --- */
uint32_t ninlil_model_domain_crc32c(const uint8_t *bytes, uint32_t length);

/* --- Key grammar --- */
ninlil_status_t ninlil_model_domain_expected_identity_kind(
    uint8_t family,
    uint8_t subtype,
    uint8_t *out_kind);

/* Exact subtype body upper bound (section 6/7). */
ninlil_status_t ninlil_model_domain_max_body_bytes(
    uint8_t family,
    uint8_t subtype,
    uint32_t *out_max_body);

/*
 * Key-only structural classification (section 5 key grammar / future prefix).
 * Does not inspect value envelope; full future-row predicate is classify_row.
 */
ninlil_status_t ninlil_model_domain_classify_key(
    ninlil_bytes_view_t encoded_key,
    ninlil_model_domain_key_class_t *out_class);

/*
 * Full section-5 future-row predicate: key length/prefix/version plus complete
 * NLR1 value framing (magic, declared length, CRC32C). Does not interpret
 * future record_type/record_version or payload.
 */
ninlil_status_t ninlil_model_domain_classify_row(
    ninlil_bytes_view_t encoded_key,
    ninlil_bytes_view_t encoded_value,
    ninlil_model_domain_key_class_t *out_class);

/* Exact operation_identity RAW16 contents length for kind 1..21. */
ninlil_status_t ninlil_model_domain_operation_identity_length(
    uint16_t operation_kind,
    uint16_t *out_length);

/* Validate closed health (priority, source_kind, identity length) registry. */
ninlil_status_t ninlil_model_domain_health_registry_validate(
    uint8_t priority,
    uint16_t source_kind,
    uint16_t source_identity_length);

/* Validate closed commit-fence kind and identity length. */
ninlil_status_t ninlil_model_domain_fence_registry_validate(
    uint16_t fence_kind,
    uint16_t fence_identity_length);

ninlil_status_t ninlil_model_domain_build_key(
    uint8_t family,
    uint8_t subtype,
    uint8_t identity_kind,
    ninlil_bytes_view_t identity,
    ninlil_model_domain_key_t *out_key);

ninlil_status_t ninlil_model_domain_parse_key(
    ninlil_bytes_view_t encoded_key,
    ninlil_model_domain_key_view_t *out_view);

/* COMPOSITE(subtype, components) identity digest (kind 5 preimage). */
ninlil_status_t ninlil_model_domain_composite_digest(
    uint8_t subtype,
    ninlil_bytes_view_t components,
    ninlil_model_domain_digest_t *out_digest);

/* KEY_DIGEST(complete encoded key). */
ninlil_status_t ninlil_model_domain_key_digest(
    ninlil_bytes_view_t complete_key,
    ninlil_model_domain_digest_t *out_digest);

/*
 * Encode an identity kind/bytes into the 16-byte primary_id form (docs17 §4):
 * ID128 as-is, u64/singleton left-zero-padded, digest identity first 16 bytes.
 * This is the encoding helper only; secondary records must not use their own
 * key identity as primary_id — typed validation derives the referenced primary.
 */
ninlil_status_t ninlil_model_domain_primary_id_from_identity(
    uint8_t identity_kind,
    ninlil_bytes_view_t identity,
    uint8_t out_primary_id[NINLIL_MODEL_DOMAIN_ID_BYTES]);

/*
 * Domain envelope + 96-byte common header (4096-byte bound).
 * Success proves NLR1 framing, CRC, common-header local invariants, and
 * subtype body-length ceiling only. For BLOB (flags manifest/chunk), D1-B
 * must still validate body shape vs flags before accepting semantic validity;
 * envelope success is not full record validity.
 */
ninlil_status_t ninlil_model_domain_encode_envelope(
    uint16_t record_type,
    const ninlil_model_domain_common_header_t *header,
    ninlil_bytes_view_t body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

ninlil_status_t ninlil_model_domain_decode_envelope(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_envelope_t *out_envelope);

/* --- Pure digests (section 5 / 14) --- */
ninlil_status_t ninlil_model_domain_value_digest(
    ninlil_bytes_view_t complete_encoded_value,
    ninlil_model_domain_digest_t *out_digest);

ninlil_status_t ninlil_model_domain_health_source_id(
    uint8_t priority,
    uint16_t source_kind,
    ninlil_bytes_view_t source_identity,
    ninlil_model_domain_digest_t *out_digest);

ninlil_status_t ninlil_model_domain_commit_fence_digest(
    uint16_t fence_kind,
    ninlil_bytes_view_t fence_identity,
    ninlil_model_domain_digest_t *out_digest);

/* Witness identity / operation digests (section 5.1 / 10). */
ninlil_status_t ninlil_model_domain_witness_identity_digest(
    uint16_t operation_kind,
    ninlil_bytes_view_t operation_identity,
    ninlil_model_domain_digest_t *out_digest);

ninlil_status_t ninlil_model_domain_canonical_operation_digest(
    uint16_t operation_kind,
    ninlil_bytes_view_t operation_identity,
    const uint8_t subject_id[NINLIL_MODEL_DOMAIN_ID_BYTES],
    const uint8_t manifest_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES],
    uint16_t retention_kind,
    const uint8_t retention_subject_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES],
    ninlil_model_domain_digest_t *out_digest);

/* Streaming manifest digest over complete chunk bodies. */
typedef struct ninlil_model_domain_manifest_digest_ctx {
    ninlil_model_domain_sha256_ctx_t sha;
    uint32_t chunk_bodies_seen;
} ninlil_model_domain_manifest_digest_ctx_t;

ninlil_status_t ninlil_model_domain_manifest_digest_init(
    ninlil_model_domain_manifest_digest_ctx_t *ctx);
ninlil_status_t ninlil_model_domain_manifest_digest_update(
    ninlil_model_domain_manifest_digest_ctx_t *ctx,
    ninlil_bytes_view_t chunk_body);
ninlil_status_t ninlil_model_domain_manifest_digest_final(
    ninlil_model_domain_manifest_digest_ctx_t *ctx,
    ninlil_model_domain_digest_t *out_digest);

/* --- Witness framing (section 10) --- */
uint32_t ninlil_model_domain_witness_header_encoded_length(
    uint16_t operation_identity_length);
uint32_t ninlil_model_domain_witness_entry_encoded_length(uint16_t key_length);
uint32_t ninlil_model_domain_witness_chunk_encoded_length(
    const ninlil_model_domain_witness_chunk_t *chunk);

ninlil_status_t ninlil_model_domain_encode_witness_header(
    const ninlil_model_domain_witness_header_t *header,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

ninlil_status_t ninlil_model_domain_decode_witness_header(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_witness_header_t *out_header);

ninlil_status_t ninlil_model_domain_encode_witness_chunk(
    const ninlil_model_domain_witness_chunk_t *chunk,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

/*
 * Decode borrows entry key_bytes from encoded body. Entries remain valid
 * only while encoded is alive. out_chunk->entries[i].key_bytes points into
 * encoded.
 */
ninlil_status_t ninlil_model_domain_decode_witness_chunk(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_witness_chunk_t *out_chunk);

/* Helper: ceil(member_count / 8), 1..32 for member_count 1..256. */
ninlil_status_t ninlil_model_domain_witness_chunk_count_for_members(
    uint16_t member_count,
    uint16_t *out_chunk_count);

/*
 * Generic BLOB logical data/view length bound (section 2): 0..3072.
 * Zero represents an empty logical view/zero-length manifest and is not a
 * valid stored BLOB chunk row; subtype 0x30 body validation rejects a chunk
 * field length of 0 because zero-length blobs have no chunk rows.
 */
ninlil_status_t ninlil_model_domain_blob_chunk_data_length_validate(
    uint32_t chunk_data_length);

#ifdef __cplusplus
}
#endif

#endif
