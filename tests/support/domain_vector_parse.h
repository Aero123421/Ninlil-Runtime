#ifndef NINLIL_DOMAIN_VECTOR_PARSE_H
#define NINLIL_DOMAIN_VECTOR_PARSE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_DV_MAX_ID 96u
#define NINLIL_DV_MAX_SUITE 16u
#define NINLIL_DV_MAX_OP 48u
#define NINLIL_DV_MAX_STATUS 32u
#define NINLIL_DV_MAX_NOTES 256u
#define NINLIL_DV_MAX_HEX_CHARS 65536u
#define NINLIL_DV_MAX_CHUNKS 32u
#define NINLIL_DV_MAX_VECTORS 1024u

/*
 * Large/optional hex and notes are exactly-sized heap strings (NULL if
 * absent). Chunk bodies are a heap array of heap strings. Small identity
 * fields remain fixed-size. sizeof(ninlil_dv_vector_t) stays modest.
 */
typedef struct ninlil_dv_vector {
    char id[NINLIL_DV_MAX_ID];
    char suite[NINLIL_DV_MAX_SUITE];
    char op[NINLIL_DV_MAX_OP];
    char expected_status[NINLIL_DV_MAX_STATUS];
    uint32_t required_workspace_bytes;
    uint32_t family;
    uint32_t subtype;
    uint32_t identity_kind;
    uint32_t record_type;
    uint32_t flags;
    uint32_t revision;
    uint32_t priority;
    uint32_t source_kind;
    uint32_t fence_kind;
    uint32_t operation_kind;
    uint32_t member_count;
    uint32_t chunk_count;
    uint32_t body_length;
    uint32_t key_length;
    uint64_t sha_bit_length;
    uint32_t sha_buffer_length;
    uint32_t witness_state;
    uint32_t retention_kind;
    char *identity_hex;
    char *key_hex;
    char *value_hex;
    char *body_hex;
    char *head_hex;
    char *pvd_hex;
    char *digest_hex;
    char *digest2_hex;
    char *crc_hex;
    char *notes;
    char *subject_hex;
    char *retention_hex;
    char *manifest_hex;
    char *successor_hex;
    char **chunk_bodies_hex;
    uint32_t chunk_bodies_count;
    uint32_t chunk_bodies_cap;
    uint64_t str_bits;
    uint64_t num_bits;
    uint32_t mand_bits;
} ninlil_dv_vector_t;

/* Mandatory field presence */
enum {
    NINLIL_DV_MAND_ID = 1u << 0,
    NINLIL_DV_MAND_SUITE = 1u << 1,
    NINLIL_DV_MAND_OP = 1u << 2,
    NINLIL_DV_MAND_STATUS = 1u << 3,
    NINLIL_DV_MAND_WORKSPACE = 1u << 4
};

/* Optional string field presence (duplicate detect even for empty "") */
enum {
    NINLIL_DV_STR_IDENTITY = 1u << 0,
    NINLIL_DV_STR_KEY = 1u << 1,
    NINLIL_DV_STR_VALUE = 1u << 2,
    NINLIL_DV_STR_BODY = 1u << 3,
    NINLIL_DV_STR_HEAD = 1u << 4,
    NINLIL_DV_STR_PVD = 1u << 5,
    NINLIL_DV_STR_DIGEST = 1u << 6,
    NINLIL_DV_STR_DIGEST2 = 1u << 7,
    NINLIL_DV_STR_CRC = 1u << 8,
    NINLIL_DV_STR_NOTES = 1u << 9,
    NINLIL_DV_STR_SUBJECT = 1u << 10,
    NINLIL_DV_STR_RETENTION = 1u << 11,
    NINLIL_DV_STR_MANIFEST = 1u << 12,
    NINLIL_DV_STR_SUCCESSOR = 1u << 13,
    NINLIL_DV_STR_CHUNKS = 1u << 14
};

enum {
    NINLIL_DV_NUM_WORKSPACE = 1u << 0,
    NINLIL_DV_NUM_FAMILY = 1u << 1,
    NINLIL_DV_NUM_SUBTYPE = 1u << 2,
    NINLIL_DV_NUM_IDENTITY_KIND = 1u << 3,
    NINLIL_DV_NUM_RECORD_TYPE = 1u << 4,
    NINLIL_DV_NUM_FLAGS = 1u << 5,
    NINLIL_DV_NUM_REVISION = 1u << 6,
    NINLIL_DV_NUM_PRIORITY = 1u << 7,
    NINLIL_DV_NUM_SOURCE_KIND = 1u << 8,
    NINLIL_DV_NUM_FENCE_KIND = 1u << 9,
    NINLIL_DV_NUM_OPERATION_KIND = 1u << 10,
    NINLIL_DV_NUM_MEMBER_COUNT = 1u << 11,
    NINLIL_DV_NUM_CHUNK_COUNT = 1u << 12,
    NINLIL_DV_NUM_BODY_LENGTH = 1u << 13,
    NINLIL_DV_NUM_KEY_LENGTH = 1u << 14,
    NINLIL_DV_NUM_SHA_BUFFER = 1u << 15,
    NINLIL_DV_NUM_WITNESS_STATE = 1u << 16,
    NINLIL_DV_NUM_RETENTION_KIND = 1u << 17,
    NINLIL_DV_NUM_SHA_BIT = 1u << 18
};

typedef struct ninlil_dv_catalog {
    uint32_t dsk1_positive_keys;
    uint32_t dsv1_body_exact;
    uint32_t dsv1_body_plus1;
    uint32_t dsh2_health_positive;
    uint32_t dsh2_fence_positive;
    uint32_t dso2_kind_positive;
    uint32_t dso2_canonical_positive;
    uint32_t dsw1_member_stream;
    uint32_t dsw1_header_positive;
    uint32_t dsk1_primary_id_positive;
    uint32_t dsv1_encode_decode_positive;
    uint32_t dsb1_subtype_01_positive;
    uint32_t dsb1_subtype_60_positive;
    uint32_t dsb1_subtype_62_positive;
    uint32_t dsb1_subtype_64_positive;
    uint32_t dsb1_subtype_7d_positive;
    uint32_t dsb1_total_positive;
    uint32_t dsb1_total_negative;
    uint32_t dsb2_subtype_10_positive;
    uint32_t dsb2_subtype_11_positive;
    uint32_t dsb2_subtype_20_positive;
    uint32_t dsb2_subtype_21_positive;
    uint32_t dsb2_subtype_22_positive;
    uint32_t dsb2_subtype_23_positive;
    uint32_t dsb2_subtype_24_positive;
    uint32_t dsb2_subtype_25_positive;
    uint32_t dsb2_total_positive;
    uint32_t dsb2_total_negative;
    uint32_t dsb3_subtype_26_positive;
    uint32_t dsb3_total_positive;
    uint32_t dsb3_total_negative;
} ninlil_dv_catalog_t;

/*
 * Catalog presence mask is uint64_t. Portable UINT64_C(1) shifts keep bits
 * 32..63 well-defined for B3b+ growth; do not use 1u<<n (UB past bit 31 on
 * 32-bit unsigned int). Top-level presence (top_bits) remains uint32_t.
 */
#define NINLIL_DV_CAT_BIT(n) (UINT64_C(1) << (n))

#define NINLIL_DV_CAT_DSK1_KEYS NINLIL_DV_CAT_BIT(0)
#define NINLIL_DV_CAT_DSV1_EXACT NINLIL_DV_CAT_BIT(1)
#define NINLIL_DV_CAT_DSV1_PLUS1 NINLIL_DV_CAT_BIT(2)
#define NINLIL_DV_CAT_DSH2_HEALTH NINLIL_DV_CAT_BIT(3)
#define NINLIL_DV_CAT_DSH2_FENCE NINLIL_DV_CAT_BIT(4)
#define NINLIL_DV_CAT_DSO2_KIND NINLIL_DV_CAT_BIT(5)
#define NINLIL_DV_CAT_DSO2_CANON NINLIL_DV_CAT_BIT(6)
#define NINLIL_DV_CAT_DSW1_STREAM NINLIL_DV_CAT_BIT(7)
#define NINLIL_DV_CAT_DSW1_HEADER NINLIL_DV_CAT_BIT(8)
#define NINLIL_DV_CAT_DSK1_PRIMARY NINLIL_DV_CAT_BIT(9)
#define NINLIL_DV_CAT_DSV1_ENCDEC NINLIL_DV_CAT_BIT(10)
#define NINLIL_DV_CAT_DSB1_01 NINLIL_DV_CAT_BIT(11)
#define NINLIL_DV_CAT_DSB1_60 NINLIL_DV_CAT_BIT(12)
#define NINLIL_DV_CAT_DSB1_62 NINLIL_DV_CAT_BIT(13)
#define NINLIL_DV_CAT_DSB1_64 NINLIL_DV_CAT_BIT(14)
#define NINLIL_DV_CAT_DSB1_7D NINLIL_DV_CAT_BIT(15)
#define NINLIL_DV_CAT_DSB1_POS NINLIL_DV_CAT_BIT(16)
#define NINLIL_DV_CAT_DSB1_NEG NINLIL_DV_CAT_BIT(17)
#define NINLIL_DV_CAT_DSB2_10 NINLIL_DV_CAT_BIT(18)
#define NINLIL_DV_CAT_DSB2_11 NINLIL_DV_CAT_BIT(19)
#define NINLIL_DV_CAT_DSB2_20 NINLIL_DV_CAT_BIT(20)
#define NINLIL_DV_CAT_DSB2_21 NINLIL_DV_CAT_BIT(21)
#define NINLIL_DV_CAT_DSB2_22 NINLIL_DV_CAT_BIT(22)
#define NINLIL_DV_CAT_DSB2_23 NINLIL_DV_CAT_BIT(23)
#define NINLIL_DV_CAT_DSB2_24 NINLIL_DV_CAT_BIT(24)
#define NINLIL_DV_CAT_DSB2_25 NINLIL_DV_CAT_BIT(25)
#define NINLIL_DV_CAT_DSB2_POS NINLIL_DV_CAT_BIT(26)
#define NINLIL_DV_CAT_DSB2_NEG NINLIL_DV_CAT_BIT(27)
#define NINLIL_DV_CAT_DSB3_26 NINLIL_DV_CAT_BIT(28)
#define NINLIL_DV_CAT_DSB3_POS NINLIL_DV_CAT_BIT(29)
#define NINLIL_DV_CAT_DSB3_NEG NINLIL_DV_CAT_BIT(30)

#define NINLIL_DV_CAT_REQUIRED_MASK                                            \
    (NINLIL_DV_CAT_DSK1_KEYS | NINLIL_DV_CAT_DSV1_EXACT                         \
        | NINLIL_DV_CAT_DSV1_PLUS1 | NINLIL_DV_CAT_DSH2_HEALTH                   \
        | NINLIL_DV_CAT_DSH2_FENCE | NINLIL_DV_CAT_DSO2_KIND                     \
        | NINLIL_DV_CAT_DSO2_CANON | NINLIL_DV_CAT_DSW1_STREAM                   \
        | NINLIL_DV_CAT_DSW1_HEADER | NINLIL_DV_CAT_DSK1_PRIMARY                 \
        | NINLIL_DV_CAT_DSV1_ENCDEC | NINLIL_DV_CAT_DSB1_01                      \
        | NINLIL_DV_CAT_DSB1_60 | NINLIL_DV_CAT_DSB1_62                          \
        | NINLIL_DV_CAT_DSB1_64 | NINLIL_DV_CAT_DSB1_7D                          \
        | NINLIL_DV_CAT_DSB1_POS | NINLIL_DV_CAT_DSB1_NEG                        \
        | NINLIL_DV_CAT_DSB2_10 | NINLIL_DV_CAT_DSB2_11                          \
        | NINLIL_DV_CAT_DSB2_20 | NINLIL_DV_CAT_DSB2_21                          \
        | NINLIL_DV_CAT_DSB2_22 | NINLIL_DV_CAT_DSB2_23                          \
        | NINLIL_DV_CAT_DSB2_24 | NINLIL_DV_CAT_DSB2_25                          \
        | NINLIL_DV_CAT_DSB2_POS | NINLIL_DV_CAT_DSB2_NEG                        \
        | NINLIL_DV_CAT_DSB3_26 | NINLIL_DV_CAT_DSB3_POS                        \
        | NINLIL_DV_CAT_DSB3_NEG)

enum {
    NINLIL_DV_TOP_VERSION = 1u << 0,
    NINLIL_DV_TOP_FORMAT = 1u << 1,
    NINLIL_DV_TOP_SCOPE = 1u << 2,
    NINLIL_DV_TOP_WS_DEF = 1u << 3,
    NINLIL_DV_TOP_CATALOG = 1u << 4,
    NINLIL_DV_TOP_VECTORS = 1u << 5
};

#define NINLIL_DV_TOP_REQUIRED_MASK                                            \
    (NINLIL_DV_TOP_VERSION | NINLIL_DV_TOP_FORMAT | NINLIL_DV_TOP_SCOPE         \
        | NINLIL_DV_TOP_WS_DEF | NINLIL_DV_TOP_CATALOG | NINLIL_DV_TOP_VECTORS)

#define NINLIL_DV_FORMAT_REQUIRED "ninlil-domain-store-v1-d1b3a"
#define NINLIL_DV_SCOPE_REQUIRED                                               \
    "D1-A framing + D1-B1 bodies (01/60/62/64/7d) + D1-B2 bodies "              \
    "(10/11/20-25 service+txn admission) + D1-B3a body "                        \
    "(26 SCHEDULER_OWNER); not full D1 catalog"

typedef struct ninlil_dv_file {
    uint32_t version;
    char format[64];
    char scope[256];
    ninlil_dv_catalog_t catalog;
    uint64_t catalog_bits;
    uint32_t top_bits;
    ninlil_dv_vector_t *vectors;
    size_t vector_count;
    size_t vector_capacity;
} ninlil_dv_file_t;

int ninlil_dv_load_file(
    const char *path,
    ninlil_dv_file_t *out,
    char *err,
    size_t err_cap);

void ninlil_dv_free(ninlil_dv_file_t *file);

void ninlil_dv_vector_clear(ninlil_dv_vector_t *v);

int ninlil_dv_hex_decode(
    const char *hex,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len,
    char *err,
    size_t err_cap);

int ninlil_dv_parse_text(
    const char *text,
    size_t text_len,
    ninlil_dv_file_t *out,
    char *err,
    size_t err_cap);

/* Empty-string-safe accessors for optional heap strings. */
static inline const char *ninlil_dv_str(const char *p)
{
    return p != NULL ? p : "";
}

#ifdef __cplusplus
}
#endif

#endif
