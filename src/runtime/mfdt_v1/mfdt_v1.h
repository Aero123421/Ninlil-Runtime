/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ADR-0021 Multi-frame Durable Transfer — source-only private API candidate.
 *
 * SEMANTIC: MFDT_V1_PRIVATE_DEFAULT_OFF
 * SEMANTIC: NOT_PUBLIC_ABI
 * SEMANTIC: NOT_INSTALLED
 * SEMANTIC: NOT_HIL_CLAIM
 * SEMANTIC: NOT_IMPLEMENTATION_COMPLETE_CLAIM
 * SEMANTIC: WORKSPACE_65536_FIXED
 * SEMANTIC: NRC1_RETAINED_UNTIL_GC
 *
 * Prefix: ninlil_mfdt_v1_
 * Default policy OFF.  Admission requires a completed private MFN1
 * transcript; it never uses HELLO selected_control_version=3.
 * After startup/bind, the engine's operational paths are allocation-free and
 * use caller-owned fixed workspaces. Target adapters may allocate owner bulk
 * only at startup/bind and release it at finalization. No VLA; C11. Does not
 * alter public/installed ABI.
 */
#ifndef NINLIL_MFDT_V1_H
#define NINLIL_MFDT_V1_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Closed constants (ADR-0021 machine authority) ---------------------- */

#define NINLIL_MFDT_V1_MAX_CONTENT           ((uint32_t)32768u)
#define NINLIL_MFDT_V1_CHUNK_SIZE            ((uint16_t)896u)
#define NINLIL_MFDT_V1_MAX_CHUNKS            ((uint16_t)37u)
#define NINLIL_MFDT_V1_ENTRIES_PER_PAGE      ((uint16_t)22u)
#define NINLIL_MFDT_V1_MAX_PAGES             ((uint16_t)2u)
#define NINLIL_MFDT_V1_ENTRY_BYTES           ((uint16_t)40u)
#define NINLIL_MFDT_V1_HEADER_BYTES          ((uint16_t)308u)
#define NINLIL_MFDT_V1_NM30_SCHEMA1_BYTES    ((uint16_t)164u)
#define NINLIL_MFDT_V1_NM30_BYTES            ((uint16_t)180u)
#define NINLIL_MFDT_V1_NRC1_SLOT_BYTES       ((uint16_t)208u)
#define NINLIL_MFDT_V1_NRC1_SLOT_COUNT       ((uint16_t)72u)
#define NINLIL_MFDT_V1_NRC1_VALUE_BYTES      ((uint16_t)15020u)
#define NINLIL_MFDT_V1_NRC1_LOGICAL_BYTES    ((uint32_t)15056u)
#define NINLIL_MFDT_V1_KEY_BYTES             ((uint16_t)20u)
#define NINLIL_MFDT_V1_WORKSPACE_BYTES       ((uint32_t)65536u)
#define NINLIL_MFDT_V1_ACTIVE_HEADER_BYTES   ((uint16_t)308u)
#define NINLIL_MFDT_V1_ACTIVE_SCHEMA         ((uint16_t)2u)
#define NINLIL_MFDT_V1_ACTIVE_VALUE_MAX      ((uint32_t)35211u)
#define NINLIL_MFDT_V1_ADMISSION_VERSION     ((uint16_t)2u)
#define NINLIL_MFDT_V1_OPEN_HEAD_BYTES       ((uint16_t)202u)
#define NINLIL_MFDT_V1_OPEN_BASE_BYTES       ((uint16_t)234u)
#define NINLIL_MFDT_V1_OPEN_BINDING_BYTES    ((uint16_t)228u)
#define NINLIL_MFDT_V1_OPEN_TEXT_OFFSET      ((uint16_t)462u)
#define NINLIL_MFDT_V1_OPEN_BODY_MIN         ((uint16_t)465u)
#define NINLIL_MFDT_V1_OPEN_BODY_MAX         ((uint16_t)651u)
#define NINLIL_MFDT_V1_RESUME_MAX            ((uint8_t)8u)
#define NINLIL_MFDT_V1_ABORT_GEN_MAX         ((uint8_t)8u)
#define NINLIL_MFDT_V1_RETRY_BUDGET_MAX      ((uint8_t)8u)
#define NINLIL_MFDT_V1_HOST_ACTIVE_MAX       ((uint8_t)4u)
#define NINLIL_MFDT_V1_ESP_ACTIVE_MAX        ((uint8_t)1u)
#define NINLIL_MFDT_V1_RECEIVER_FULLS_MAX    ((uint16_t)77u)
#define NINLIL_MFDT_V1_SENDER_FULLS_MAX      ((uint16_t)67u)
#define NINLIL_MFDT_V1_SESSION_GENERATIONS_MAX_PER_TRANSFER ((uint8_t)2u)
#define NINLIL_MFDT_V1_RETENTION_MS_DEFAULT  ((uint64_t)86400000ull)
#define NINLIL_MFDT_V1_RESERVATION_MS        ((uint64_t)300000ull)

/* Message types */
#define NINLIL_MFDT_V1_MSG_OPEN              ((uint8_t)0x36u)
#define NINLIL_MFDT_V1_MSG_OPEN_ACCEPT       ((uint8_t)0x37u)
#define NINLIL_MFDT_V1_MSG_MANIFEST_PAGE     ((uint8_t)0x38u)
#define NINLIL_MFDT_V1_MSG_PAGE_ACCEPT       ((uint8_t)0x39u)
#define NINLIL_MFDT_V1_MSG_REJECT            ((uint8_t)0x3Au)
#define NINLIL_MFDT_V1_MSG_BUSY              ((uint8_t)0x3Bu)
#define NINLIL_MFDT_V1_MSG_CHUNK_OFFER       ((uint8_t)0x3Cu)
#define NINLIL_MFDT_V1_MSG_CHUNK_ACCEPT      ((uint8_t)0x3Du)
#define NINLIL_MFDT_V1_MSG_RESUME_QUERY      ((uint8_t)0x3Eu)
#define NINLIL_MFDT_V1_MSG_RESUME_STATE      ((uint8_t)0x3Fu)
#define NINLIL_MFDT_V1_MSG_FINALIZE          ((uint8_t)0x40u)
#define NINLIL_MFDT_V1_MSG_TRANSFER_ACCEPT   ((uint8_t)0x41u)
#define NINLIL_MFDT_V1_MSG_ABORT             ((uint8_t)0x42u)
#define NINLIL_MFDT_V1_MSG_ABORT_ACK         ((uint8_t)0x43u)

/* Reject codes */
#define NINLIL_MFDT_V1_REJ_LAYOUT            ((uint16_t)1u)
#define NINLIL_MFDT_V1_REJ_DIGEST            ((uint16_t)2u)
#define NINLIL_MFDT_V1_REJ_DUPLICATE         ((uint16_t)3u)
#define NINLIL_MFDT_V1_REJ_UNSUPPORTED       ((uint16_t)4u)
#define NINLIL_MFDT_V1_REJ_CAPACITY          ((uint16_t)5u)
#define NINLIL_MFDT_V1_REJ_STORAGE           ((uint16_t)6u)
#define NINLIL_MFDT_V1_REJ_EXPIRED           ((uint16_t)7u)
#define NINLIL_MFDT_V1_REJ_STATE             ((uint16_t)8u)
#define NINLIL_MFDT_V1_REJ_AUTHORITY         ((uint16_t)9u)
#define NINLIL_MFDT_V1_REJ_ABORT_DENIED      ((uint16_t)10u)

/* Status */
#define NINLIL_MFDT_V1_OK                    ((int)0)
#define NINLIL_MFDT_V1_ERR_PARAM             ((int)-1)
#define NINLIL_MFDT_V1_ERR_POLICY_OFF        ((int)-2)
#define NINLIL_MFDT_V1_ERR_VERSION           ((int)-3)
#define NINLIL_MFDT_V1_ERR_CAPACITY          ((int)-4)
#define NINLIL_MFDT_V1_ERR_STATE             ((int)-5)
#define NINLIL_MFDT_V1_ERR_DIGEST            ((int)-6)
#define NINLIL_MFDT_V1_ERR_LAYOUT            ((int)-7)
#define NINLIL_MFDT_V1_ERR_STORAGE           ((int)-8)
#define NINLIL_MFDT_V1_ERR_EXPIRED           ((int)-9)
#define NINLIL_MFDT_V1_ERR_ABORT_DENIED      ((int)-10)
#define NINLIL_MFDT_V1_ERR_BUSY              ((int)-11)
#define NINLIL_MFDT_V1_ERR_CORRUPT           ((int)-12)
/* Durable FULL returned COMMIT_UNKNOWN: fence / no external success. */
#define NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN    ((int)-13)
/*
 * Raw adapter classified durable image as exact NEW after CU read-back, but
 * ADR-0021 forbids promoting that to engine/wire external success until
 * power-cut HIL attestation. Default release path stays fail-closed.
 */
#define NINLIL_MFDT_V1_ERR_CU_NEW_NOT_PROMOTED ((int)-14)

/* Terminal states */
#define NINLIL_MFDT_V1_TERM_COMPLETE         ((uint16_t)1u)
#define NINLIL_MFDT_V1_TERM_ABORTED          ((uint16_t)2u)
#define NINLIL_MFDT_V1_TERM_CORRUPT_FENCED   ((uint16_t)3u)

/* NM30 terminal reasons. Values 1..4 are the only wire ABORT reasons. */
#define NINLIL_MFDT_V1_TERM_REASON_NONE       ((uint16_t)0u)
#define NINLIL_MFDT_V1_TERM_REASON_OPERATOR   ((uint16_t)1u)
#define NINLIL_MFDT_V1_TERM_REASON_SUPERSEDED ((uint16_t)2u)
#define NINLIL_MFDT_V1_TERM_REASON_DEADLINE   ((uint16_t)3u)
#define NINLIL_MFDT_V1_TERM_REASON_POLICY     ((uint16_t)4u)
#define NINLIL_MFDT_V1_TERM_REASON_EXPIRED    ((uint16_t)5u)
#define NINLIL_MFDT_V1_TERM_REASON_CORRUPT    ((uint16_t)0x8001u)
#define NINLIL_MFDT_V1_TERM_REASON_EPOCH      ((uint16_t)0x8002u)

/* Active state codes (non-terminal durable) */
#define NINLIL_MFDT_V1_S_OPEN_PENDING        ((uint8_t)1u)
#define NINLIL_MFDT_V1_S_OPEN_ACCEPTED       ((uint8_t)2u)
#define NINLIL_MFDT_V1_S_MANIFEST_ACCEPTED   ((uint8_t)3u)
#define NINLIL_MFDT_V1_S_CHUNKS_PARTIAL      ((uint8_t)4u)
#define NINLIL_MFDT_V1_S_FINAL_WAIT          ((uint8_t)5u)
#define NINLIL_MFDT_V1_S_ACCEPT_RX           ((uint8_t)6u)
#define NINLIL_MFDT_V1_S_ABORT_PENDING       ((uint8_t)8u)
#define NINLIL_MFDT_V1_S_COMMIT_UNKNOWN      ((uint8_t)10u)
#define NINLIL_MFDT_V1_R_RESERVED_OPEN       ((uint8_t)32u)
#define NINLIL_MFDT_V1_R_MANIFEST_PARTIAL    ((uint8_t)33u)
#define NINLIL_MFDT_V1_R_MANIFEST_ACCEPTED   ((uint8_t)34u)
#define NINLIL_MFDT_V1_R_CHUNKS_PARTIAL      ((uint8_t)35u)
#define NINLIL_MFDT_V1_R_CONTENT_VERIFIED    ((uint8_t)36u)
#define NINLIL_MFDT_V1_R_ACCEPT_NOTIFIED     ((uint8_t)37u)
#define NINLIL_MFDT_V1_R_HANDED_OFF          ((uint8_t)38u)
#define NINLIL_MFDT_V1_R_COMMIT_UNKNOWN      ((uint8_t)40u)
#define NINLIL_MFDT_V1_R_ABORT_PENDING       ((uint8_t)41u)

/* COMMIT_UNKNOWN classification */
typedef enum ninlil_mfdt_v1_cu_class {
    NINLIL_MFDT_V1_CU_OLD = 0,
    NINLIL_MFDT_V1_CU_NEW = 1,
    NINLIL_MFDT_V1_CU_PARTIAL = 2,
    NINLIL_MFDT_V1_CU_EXTRA = 3,
    NINLIL_MFDT_V1_CU_THIRD = 4,
    NINLIL_MFDT_V1_CU_ABSENT = 5,
    NINLIL_MFDT_V1_CU_BOTH = 6
} ninlil_mfdt_v1_cu_class_t;

/* Policy */
typedef enum ninlil_mfdt_v1_policy {
    NINLIL_MFDT_V1_POLICY_OFF = 0,
    NINLIL_MFDT_V1_POLICY_ON = 1
} ninlil_mfdt_v1_policy_t;

typedef struct ninlil_mfdt_v1_id16 {
    uint8_t bytes[16];
} ninlil_mfdt_v1_id16_t;

typedef struct ninlil_mfdt_v1_digest32 {
    uint8_t bytes[32];
} ninlil_mfdt_v1_digest32_t;

typedef struct ninlil_mfdt_v1_geometry {
    uint32_t total_length;
    uint16_t chunk_count;
    uint16_t page_count;
    uint16_t chunk_size;
    uint16_t final_chunk_length;
} ninlil_mfdt_v1_geometry_t;

typedef struct ninlil_mfdt_v1_wire_view {
    uint8_t message_type;
    uint64_t request_id;
    const uint8_t *body;
    uint16_t body_len;
} ninlil_mfdt_v1_wire_view_t;

typedef struct ninlil_mfdt_v1_response {
    uint8_t message_type;
    uint8_t body[160];
    uint16_t body_len;
    uint16_t reject_code;
    uint8_t from_nrc1_hit;
    uint8_t state_mutation;
    uint8_t full_count;
} ninlil_mfdt_v1_response_t;

/* In-memory durable row for lab/host FULL simulator (not ESP flash driver). */
typedef struct ninlil_mfdt_v1_kv_row {
    uint8_t key[20];
    uint16_t key_len;
    uint8_t *value; /* points into workspace or static lab arena */
    uint32_t value_len;
    uint8_t occupied;
} ninlil_mfdt_v1_kv_row_t;

#define NINLIL_MFDT_V1_LAB_MAX_ROWS ((size_t)16u)
/* Co-located FULL: active+NRC1, or active-erase+NM30, or NM30+NRC1 GC (≤3). */
#define NINLIL_MFDT_V1_LAB_MAX_OPS  ((size_t)4u)
/*
 * Host lab: full WORKSPACE value pool + staging for max multi-key FULL.
 * ESP: thinner pools (single-active, process-local mirror). Full 32KiB content
 * still fits in ACTIVE_VALUE_MAX-sized pool; saves ~50KB DRAM vs host.
 */
#if defined(ESP_PLATFORM)
#define NINLIL_MFDT_V1_LAB_VALUE_POOL_BYTES \
    ((uint32_t)(NINLIL_MFDT_V1_ACTIVE_VALUE_MAX + 512u))
#define NINLIL_MFDT_V1_LAB_STAGING_POOL_BYTES \
    ((uint32_t)(NINLIL_MFDT_V1_ACTIVE_VALUE_MAX + NINLIL_MFDT_V1_NRC1_VALUE_BYTES + \
                NINLIL_MFDT_V1_NM30_BYTES))
#else
#define NINLIL_MFDT_V1_LAB_VALUE_POOL_BYTES NINLIL_MFDT_V1_WORKSPACE_BYTES
#define NINLIL_MFDT_V1_LAB_STAGING_POOL_BYTES \
    ((uint32_t)(NINLIL_MFDT_V1_ACTIVE_VALUE_MAX + NINLIL_MFDT_V1_NRC1_VALUE_BYTES + \
                NINLIL_MFDT_V1_NM30_BYTES))
#endif

typedef struct ninlil_mfdt_v1_lab_op {
    uint8_t valid;
    uint8_t op; /* 0=put 1=del */
    uint8_t key[20];
    uint32_t value_len;
    uint32_t pool_off;
} ninlil_mfdt_v1_lab_op_t;

struct ninlil_storage_ops;

/*
 * Source-private ESP durable-store state. It is embedded in the exact
 * caller-owned lab store so binding, transaction and read-back state cannot
 * cross Runtime/prototype owners. Bulk buffers are allocated only by bind and
 * released by lab_store_fini.
 */
typedef struct ninlil_mfdt_v1_esp_store_owner {
    const struct ninlil_storage_ops *ops;
    void *handle;
    void *txn;
    uint8_t *readback;
    uint8_t *old_pool;
    uint32_t old_pool_cap;
    uint32_t old_len[NINLIL_MFDT_V1_LAB_MAX_OPS];
    uint32_t old_off[NINLIL_MFDT_V1_LAB_MAX_OPS];
    uint32_t old_used;
    int32_t last_cu_class;
    uint8_t old_present[NINLIL_MFDT_V1_LAB_MAX_OPS];
    uint8_t bound;
    uint8_t active;
} ninlil_mfdt_v1_esp_store_owner_t;

typedef struct ninlil_mfdt_v1_lab_store {
    ninlil_mfdt_v1_kv_row_t rows[NINLIL_MFDT_V1_LAB_MAX_ROWS];
    uint8_t value_pool[NINLIL_MFDT_V1_LAB_VALUE_POOL_BYTES];
    uint32_t pool_used;
    uint32_t full_count;
    uint32_t crash_after_fulls; /* 0 = no inject; else fail after N successful FULLs */
    uint32_t crash_armed;
    /*
     * Host lab only: next full_commit applies ops then returns
     * ERR_CU_NEW_NOT_PROMOTED (ESP_UNPROVEN simulation). Cleared on fire.
     * Not a physical HIL claim.
     */
    uint8_t force_cu_new_not_promoted;
    /* Transactional multi-key FULL: ops stage until commit; crash rolls back all. */
    uint8_t txn_open;
    uint8_t op_count;
    ninlil_mfdt_v1_lab_op_t ops[NINLIL_MFDT_V1_LAB_MAX_OPS];
    uint8_t staging_pool[NINLIL_MFDT_V1_LAB_STAGING_POOL_BYTES];
    uint32_t staging_pool_used;
    ninlil_mfdt_v1_esp_store_owner_t esp;
} ninlil_mfdt_v1_lab_store_t;

typedef struct ninlil_mfdt_v1_config {
    ninlil_mfdt_v1_policy_t policy;
    uint16_t mfdt_admission_version;
    /*
     * 1 = Host FULL-capable storage/replay profile, 0 = ESP profile.
     * Every engine remains exact-one-transfer; the Host four-transfer
     * reference profile is four caller-owned engines behind a coordinator.
     */
    uint8_t host_mode;
    uint32_t session_generation; /* CTRL session gen at OPEN bind (NRC1) */
    uint8_t mfdt_capability;     /* private_mfdt_admission_v2 bit; 0=absent */
    uint64_t retention_ms;
    uint64_t now_ms;
    ninlil_mfdt_v1_id16_t local_clock_epoch;
} ninlil_mfdt_v1_config_t;

/*
 * Caller-owned ApplicationData identity carried byte-exact in TRANSFER_OPEN.
 * Text fields are canonical ASCII IDs (namespace: [a-z0-9.-], service/schema:
 * [a-z0-9._-]), each 1..63 bytes and not NUL terminated on wire.
 */
typedef struct ninlil_mfdt_v1_open_metadata {
    uint8_t origin_transaction_id[16];
    uint8_t origin_event_id[16]; /* all-zero only when the application permits */
    uint8_t source_runtime_id[16];
    uint8_t target_runtime_id[16];
    uint64_t service_descriptor_revision; /* >= 1 */
    uint8_t service_descriptor_digest[32];
    uint8_t deadline_clock_epoch_id[16];
    /* zero epoch + UINT64_MAX is the exact Foundation NO_DEADLINE shape */
    uint64_t absolute_effect_deadline_ms;
    uint8_t original_attempt_id[16];
    uint32_t target_ordinal;
    uint8_t source_application_instance_id[16];
    uint8_t source_device_id[16];
    uint8_t source_installation_id[16];
    uint8_t source_site_id[16];
    uint64_t source_binding_epoch;
    uint64_t source_membership_epoch;
    uint32_t source_identity_flags;
    uint32_t source_reserved;
    uint8_t target_application_instance_id[16];
    uint8_t target_device_id[16];
    uint8_t target_installation_id[16];
    uint8_t target_site_id[16];
    uint64_t target_binding_epoch;
    uint64_t target_membership_epoch;
    uint32_t target_identity_flags;
    uint32_t target_reserved;
    uint16_t service_schema_major;
    uint16_t service_schema_minor;
    uint32_t service_family;
    uint64_t application_generation;
    uint64_t evidence_grace_ms;
    uint32_t required_evidence;
    uint32_t application_binding_flags;
    const uint8_t *namespace_bytes;
    uint16_t namespace_length;
    const uint8_t *service_bytes;
    uint16_t service_length;
    const uint8_t *schema_bytes;
    uint16_t schema_length;
} ninlil_mfdt_v1_open_metadata_t;

/*
 * Fixed per-transfer workspace: exactly 65536 bytes, caller-owned, 8-byte
 * aligned, and never shared between simultaneously active Host slots.
 *
 * The single-engine and Host coordinator layouts both keep the canonical
 * active record, NRC1, and temporary projection inside this exact arena.
 * No record/NRC1 process-global scratch is shared between owners.
 */
typedef struct ninlil_mfdt_v1_workspace {
    uint8_t bytes[NINLIL_MFDT_V1_WORKSPACE_BYTES];
} ninlil_mfdt_v1_workspace_t
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((aligned(8)))
#endif
    ;

struct ninlil_mfdt_v1_store_port;

/*
 * Source-private, fixed-memory binding used only by the Host coordinator.
 * The encoded active record is canonical in record_memory after the first
 * durable pack.  open/entries/content then point into that encoded record;
 * xfer_memory holds only the engine's volatile projection.
 */
typedef struct ninlil_mfdt_v1_engine_slot_memory {
    uint8_t *record_memory;
    uint32_t record_memory_bytes;
    uint8_t *nrc1_memory;
    uint32_t nrc1_memory_bytes;
    uint8_t *xfer_memory;
    uint32_t xfer_memory_bytes;
    uint8_t *open_staging;
    uint32_t open_staging_bytes;
    uint8_t *entries_staging;
    uint32_t entries_staging_bytes;
} ninlil_mfdt_v1_engine_slot_memory_t;

typedef struct ninlil_mfdt_v1_engine {
    ninlil_mfdt_v1_config_t cfg;
    ninlil_mfdt_v1_lab_store_t *store; /* non-owning; host lab only */
    ninlil_mfdt_v1_workspace_t *ws;    /* non-owning */
    struct ninlil_mfdt_v1_store_port *store_port; /* Host coordinator only */
    uint8_t *slot_record_memory;
    uint8_t *slot_nrc1_memory;
    uint8_t *slot_xfer_memory;
    uint8_t *slot_open_staging;
    uint8_t *slot_entries_staging;
    uint32_t slot_record_memory_bytes;
    uint32_t slot_nrc1_memory_bytes;
    uint32_t slot_xfer_memory_bytes;
    uint32_t slot_open_staging_bytes;
    uint32_t slot_entries_staging_bytes;
    uint32_t *host_committed_keys;
    uint64_t *host_committed_logical_bytes;
    uint8_t *host_full_locked;
    uint8_t *host_inventory_uncertain;
    uint8_t active_count;
    uint32_t fulls_this_transfer;
    uint32_t durable_active_value_len;
    int32_t host_pending_key_delta;
    int64_t host_pending_logical_delta;
    uint8_t publication_token[16];
    uint8_t publication_ready;
    uint8_t handoff_complete;
    /* Fairness: at most one unpaid CHUNK_OFFER per peer quantum. */
    uint8_t unpaid_chunk_offer;
    uint8_t upper_dedupe_token[16];
    uint8_t upper_dedupe_valid;
    uint8_t slot_layout;
    uint8_t slot_record_packed;
} ninlil_mfdt_v1_engine_t;

/* ---- Crypto / util ------------------------------------------------------ */

void ninlil_mfdt_v1_sha256(const uint8_t *in, size_t len, uint8_t out[32]);
uint32_t ninlil_mfdt_v1_crc32c(const uint8_t *in, size_t len);
void ninlil_mfdt_v1_put_u16(uint8_t *o, uint16_t v);
void ninlil_mfdt_v1_put_u32(uint8_t *o, uint32_t v);
void ninlil_mfdt_v1_put_u64(uint8_t *o, uint64_t v);
uint16_t ninlil_mfdt_v1_get_u16(const uint8_t *i);
uint32_t ninlil_mfdt_v1_get_u32(const uint8_t *i);
uint64_t ninlil_mfdt_v1_get_u64(const uint8_t *i);
int ninlil_mfdt_v1_memeq(const void *a, const void *b, size_t n);
void ninlil_mfdt_v1_memzero(void *p, size_t n);

/* Geometry + digests */
int ninlil_mfdt_v1_geometry(uint32_t total_length, ninlil_mfdt_v1_geometry_t *out);
void ninlil_mfdt_v1_request_body_digest(uint8_t message_type, const uint8_t *body,
                                        uint16_t body_len, uint8_t out[32]);
/* domain || open[0,202) || open[234,462) || text || entries */
void ninlil_mfdt_v1_manifest_digest(const uint8_t *open_head202,
                                    const uint8_t *open_binding228,
                                    const uint8_t *open_text, uint16_t text_len,
                                    const uint8_t *entries, uint16_t chunk_count,
                                    uint8_t out[32]);
/* Canonical: index_u16 | length_u16 | offset_u32 | digest[32] */
void ninlil_mfdt_v1_chunk_entry(const uint8_t *chunk, uint16_t chunk_len,
                                uint32_t offset, uint16_t chunk_index,
                                uint8_t entry_out[40]);

/* CU classifier (exact ADR-0021) */
ninlil_mfdt_v1_cu_class_t ninlil_mfdt_v1_classify_cu(
    int has_old, int has_new, int partial, int extra, int third, int both,
    int absent);
/* Compare durable image(s) against expected old/new for one FULL group key. */
ninlil_mfdt_v1_cu_class_t ninlil_mfdt_v1_classify_cu_bytes(
    const uint8_t *observed, uint32_t observed_len, int observed_present,
    const uint8_t *old_bytes, uint32_t old_len, int has_old_intent,
    const uint8_t *new_bytes, uint32_t new_len, int has_new_intent);

/* publication_token = SHA-256("NM3-PUBLISH-V1"||BIND52||whole||len||evidence)[0..15] */
void ninlil_mfdt_v1_publication_token(const uint8_t transfer_id[16],
                                      uint32_t revision,
                                      const uint8_t manifest_digest[32],
                                      const uint8_t whole[32],
                                      uint32_t total_length,
                                      const uint8_t evidence_id[16],
                                      uint8_t token_out[16]);

/* Lab store */
void ninlil_mfdt_v1_lab_store_init(ninlil_mfdt_v1_lab_store_t *st);
void ninlil_mfdt_v1_lab_store_fini(ninlil_mfdt_v1_lab_store_t *st);
int ninlil_mfdt_v1_lab_put(ninlil_mfdt_v1_lab_store_t *st, const uint8_t key[20],
                           const uint8_t *value, uint32_t value_len);
/*
 * Get key. value_out may be NULL for length-only probe (ABI: *value_len_out set,
 * no copy). Used by engine restart_scan.
 */
int ninlil_mfdt_v1_lab_get(const ninlil_mfdt_v1_lab_store_t *st,
                           const uint8_t key[20], uint8_t *value_out,
                           uint32_t value_cap, uint32_t *value_len_out);
int ninlil_mfdt_v1_lab_del(ninlil_mfdt_v1_lab_store_t *st, const uint8_t key[20]);
int ninlil_mfdt_v1_lab_full_begin(ninlil_mfdt_v1_lab_store_t *st);
int ninlil_mfdt_v1_lab_full_commit(ninlil_mfdt_v1_lab_store_t *st);
int ninlil_mfdt_v1_lab_full_rollback(ninlil_mfdt_v1_lab_store_t *st);

/*
 * HIL full-promotion gate (ADR-0021 §738-740). Portable PRODUCTION TU
 * (mfdt_v1_hil_gate.c) — always linked with engine; default OFF / fail-closed.
 * No public mutable setter. The target attestation verifier is intentionally
 * unavailable until a platform-rooted format and physical power-cut HIL
 * acceptance process exist; CI cannot forge enable.
 */
int ninlil_mfdt_v1_hil_full_promotion_enabled(void);
/*
 * Reserved target-only authority path. It does not parse or recognize a magic
 * prefix. Returns ERR_PARAM / ERR_STATE and leaves the gate OFF while the
 * platform-rooted verifier and physical HIL remain unavailable.
 */
int ninlil_mfdt_v1_hil_full_promotion_apply_target_attestation(
    const uint8_t *sealed_evidence, size_t sealed_len);

/*
 * Last raw CU classification latched by ESP adapter full_commit.
 * Returns -1 when unset (host lab / before commit); else ninlil_mfdt_v1_cu_class_t.
 * For raw NEW proof without release promotion. Portable setter is port-hook only.
 */
int ninlil_mfdt_v1_esp_last_cu_class(
    const ninlil_mfdt_v1_lab_store_t *st);
int ninlil_mfdt_v1_on_reservation_expired(ninlil_mfdt_v1_engine_t *eng);

/* Engine lifecycle */
int ninlil_mfdt_v1_engine_init(ninlil_mfdt_v1_engine_t *eng,
                               ninlil_mfdt_v1_workspace_t *ws,
                               ninlil_mfdt_v1_lab_store_t *store,
                               const ninlil_mfdt_v1_config_t *cfg);
/* Zero every engine-owned scratch byte and invalidate the private handle. */
void ninlil_mfdt_v1_engine_fini(ninlil_mfdt_v1_engine_t *eng);
/*
 * Host-only fixed arena initializer. It never calls the target allocator.
 * Shared inventory and FULL-lock pointers remain owned by the coordinator.
 */
int ninlil_mfdt_v1_engine_init_slot(
    ninlil_mfdt_v1_engine_t *eng,
    const ninlil_mfdt_v1_engine_slot_memory_t *memory,
    struct ninlil_mfdt_v1_store_port *store_port,
    uint32_t *committed_keys,
    uint64_t *committed_logical_bytes,
    uint8_t *full_locked,
    uint8_t *inventory_uncertain,
    const ninlil_mfdt_v1_config_t *cfg);
/*
 * Host recovery from one already-validated snapshot image. This performs no
 * store read and therefore cannot create a post-snapshot TOCTOU window.
 */
int ninlil_mfdt_v1_engine_rehydrate_captured(
    ninlil_mfdt_v1_engine_t *eng,
    const uint8_t *active_record,
    uint32_t active_record_len,
    const uint8_t *nrc1_record,
    uint32_t nrc1_record_len,
    const ninlil_mfdt_v1_config_t *cfg);
/* Compatibility no-op: operational scratch is caller-owned by engine_init. */
int ninlil_mfdt_v1_engine_preallocate(void);
void ninlil_mfdt_v1_engine_set_now(ninlil_mfdt_v1_engine_t *eng, uint64_t now_ms);
int ninlil_mfdt_v1_engine_observe_time(
    ninlil_mfdt_v1_engine_t *eng,
    const uint8_t local_clock_epoch[16],
    uint64_t now_ms,
    uint8_t *epoch_changed_out);
void ninlil_mfdt_v1_engine_set_policy(ninlil_mfdt_v1_engine_t *eng,
                                      ninlil_mfdt_v1_policy_t policy);
void ninlil_mfdt_v1_engine_set_admission_version(ninlil_mfdt_v1_engine_t *eng,
                                       uint16_t mfdt_admission_version);

/* Sender path */
int ninlil_mfdt_v1_sender_open_with_metadata(
    ninlil_mfdt_v1_engine_t *eng, const uint8_t transfer_id[16],
    const uint8_t *content, uint32_t content_len,
    const ninlil_mfdt_v1_open_metadata_t *metadata,
    uint8_t *open_body_out, uint16_t *open_body_len_out, uint64_t request_id);
/*
 * Compatibility convenience wrapper. It uses private deterministic metadata;
 * application/foundation callers should use sender_open_with_metadata().
 */
int ninlil_mfdt_v1_sender_open(ninlil_mfdt_v1_engine_t *eng,
                               const uint8_t transfer_id[16],
                               const uint8_t *content, uint32_t content_len,
                               uint8_t *open_body_out, uint16_t *open_body_len_out,
                               uint64_t request_id);
/* Accept handlers take NCL1 request_id for outstanding-request correlation. */
int ninlil_mfdt_v1_sender_on_open_accept(ninlil_mfdt_v1_engine_t *eng,
                                         const uint8_t *accept_body,
                                         uint16_t accept_len,
                                         uint64_t request_id);
int ninlil_mfdt_v1_sender_offer_page(ninlil_mfdt_v1_engine_t *eng,
                                     uint16_t page_index, uint64_t request_id,
                                     uint8_t *page_body_out,
                                     uint16_t *page_body_len_out);
int ninlil_mfdt_v1_sender_on_page_accept(ninlil_mfdt_v1_engine_t *eng,
                                         const uint8_t *body, uint16_t len,
                                         uint64_t request_id);
int ninlil_mfdt_v1_sender_offer_chunk(ninlil_mfdt_v1_engine_t *eng,
                                      uint16_t chunk_index, uint64_t request_id,
                                      uint8_t *offer_out, uint16_t *offer_len_out);
int ninlil_mfdt_v1_sender_on_chunk_accept(ninlil_mfdt_v1_engine_t *eng,
                                          const uint8_t *body, uint16_t len,
                                          uint64_t request_id);
int ninlil_mfdt_v1_sender_finalize(ninlil_mfdt_v1_engine_t *eng,
                                   uint64_t request_id, uint8_t *fin_out,
                                   uint16_t *fin_len_out);
int ninlil_mfdt_v1_sender_on_transfer_accept(ninlil_mfdt_v1_engine_t *eng,
                                             const uint8_t *body, uint16_t len,
                                             uint64_t request_id);

/* Receiver path */
int ninlil_mfdt_v1_receiver_on_open(ninlil_mfdt_v1_engine_t *eng,
                                    const uint8_t *open_body, uint16_t open_len,
                                    uint64_t request_id,
                                    ninlil_mfdt_v1_response_t *resp);
int ninlil_mfdt_v1_receiver_on_page(ninlil_mfdt_v1_engine_t *eng,
                                    const uint8_t *page_body, uint16_t page_len,
                                    uint64_t request_id,
                                    ninlil_mfdt_v1_response_t *resp);
int ninlil_mfdt_v1_receiver_on_chunk(ninlil_mfdt_v1_engine_t *eng,
                                     const uint8_t *offer_body, uint16_t offer_len,
                                     uint64_t request_id,
                                     ninlil_mfdt_v1_response_t *resp);
int ninlil_mfdt_v1_receiver_on_finalize(ninlil_mfdt_v1_engine_t *eng,
                                        const uint8_t *fin_body, uint16_t fin_len,
                                        uint64_t request_id,
                                        ninlil_mfdt_v1_response_t *resp);
int ninlil_mfdt_v1_receiver_on_resume(ninlil_mfdt_v1_engine_t *eng,
                                      const uint8_t *query_body, uint16_t query_len,
                                      uint64_t request_id,
                                      ninlil_mfdt_v1_response_t *resp);
int ninlil_mfdt_v1_receiver_on_abort(ninlil_mfdt_v1_engine_t *eng,
                                     const uint8_t *abort_body, uint16_t abort_len,
                                     uint64_t request_id,
                                     ninlil_mfdt_v1_response_t *resp);

/*
 * Compatibility-only Host/LAB handoff helper. Production code must use
 * receiver_publication_view + receiver_commit_publication with upper durable
 * evidence. This helper is never called by pipeline terminalization/worker.
 */
int ninlil_mfdt_v1_receiver_complete_handoff(ninlil_mfdt_v1_engine_t *eng);
/* GC / restart */
int ninlil_mfdt_v1_terminal_complete(ninlil_mfdt_v1_engine_t *eng);
int ninlil_mfdt_v1_retention_gc(ninlil_mfdt_v1_engine_t *eng);
int ninlil_mfdt_v1_restart_scan(ninlil_mfdt_v1_engine_t *eng);
/*
 * Cold-process rehydrate: seed transfer identity then load durable NM3S/NM3R
 * via restart_scan only. No RAM struct copy from a previous process.
 * role: 1=sender 2=receiver.
 */
int ninlil_mfdt_v1_restart_scan_transfer(ninlil_mfdt_v1_engine_t *eng,
                                         const uint8_t transfer_id[16],
                                         uint8_t role);

/* Durable active snapshot for pipeline rehydrate (no RAM process image). */
typedef struct ninlil_mfdt_v1_active_snapshot {
    uint8_t role;
    uint8_t state_code;
    uint8_t page_bitmap;
    uint8_t publication_state;
    uint16_t page_count;
    uint16_t chunk_count;
    uint32_t total_length;
    uint64_t chunk_bitmap;
    uint64_t record_generation;
    uint64_t acceptance_record_generation;
    uint8_t transfer_id[16];
    uint8_t publication_token[16];
    uint8_t publication_evidence_digest[32];
} ninlil_mfdt_v1_active_snapshot_t;

int ninlil_mfdt_v1_engine_active_snapshot(
    const ninlil_mfdt_v1_engine_t *eng, ninlil_mfdt_v1_active_snapshot_t *out);

/* Host restart semantic validators; source-private and allocation-free. */
int ninlil_mfdt_v1_validate_active_record(
    const uint8_t *record, uint32_t record_len,
    const uint8_t transfer_id[16], uint8_t expected_role,
    uint32_t *session_generation_out,
    uint8_t peer_endpoint_id_out[16]);
int ninlil_mfdt_v1_validate_nrc1_record(
    const uint8_t *record, uint32_t record_len,
    const uint8_t transfer_id[16], uint32_t expected_session_generation);
/*
 * Host retained-terminal helpers over one caller-owned raw NRC1 image.
 * Lookup validates the complete row before exposing an immutable response.
 * Insert accepts only a true miss, recomputes both CRCs, and validates the
 * resulting canonical image before returning it to the serialized FULL owner.
 */
int ninlil_mfdt_v1_nrc1_raw_find_response(
    const uint8_t *record, uint32_t record_len,
    const uint8_t transfer_id[16], uint32_t expected_session_generation,
    uint64_t request_id, const uint8_t request_digest[32],
    ninlil_mfdt_v1_response_t *response_out);
int ninlil_mfdt_v1_nrc1_raw_insert_response(
    uint8_t *record, uint32_t record_len,
    const uint8_t transfer_id[16], uint32_t expected_session_generation,
    uint64_t request_id, const uint8_t request_digest[32],
    uint8_t response_type, const uint8_t *response_body,
    uint16_t response_body_len);
int ninlil_mfdt_v1_validate_nm30_record(
    const uint8_t *record, uint32_t record_len,
    const uint8_t transfer_id[16]);
/*
 * Recovery-only NM30 validator. Canonical schema 2 is replay eligible and
 * returns its durable peer/role. Legacy schema 1 remains chargeable and
 * GC-eligible, but never authorizes rebind or a wire response.
 */
int ninlil_mfdt_v1_validate_nm30_recovery_record(
    const uint8_t *record, uint32_t record_len,
    const uint8_t transfer_id[16],
    uint8_t *replay_eligible_out,
    uint8_t peer_endpoint_id_out[16],
    uint8_t *owner_role_out);

/*
 * Allocation-free fresh OPEN precheck used by the Host control route. OK
 * means durable admission may proceed. A semantic refusal is returned with an
 * exact response only when the OPEN carries a safe non-zero BIND52 authority.
 */
int ninlil_mfdt_v1_fresh_open_precheck(
    const ninlil_mfdt_v1_config_t *config,
    const uint8_t *open_body, uint16_t open_body_len,
    ninlil_mfdt_v1_response_t *response_out);

/* Retry budget SM (ADR-0021): charge BEFORE wire of timeout new-ID. */
int ninlil_mfdt_v1_owner_timeout_retry_charge(ninlil_mfdt_v1_engine_t *eng);
uint8_t ninlil_mfdt_v1_retry_budget_remaining(const ninlil_mfdt_v1_engine_t *eng);

/*
 * Re-encode the exact durable sender OPEN after a cold restart. This performs
 * no durable mutation and never allocates a new transfer.
 */
int ninlil_mfdt_v1_sender_reissue_open(ninlil_mfdt_v1_engine_t *eng,
                                       uint8_t *open_body_out,
                                       uint16_t *open_body_len_out);

/*
 * Receiver publication handoff. publication_view is read-only and may be
 * called repeatedly after restart. commit_publication requires an upper-layer
 * durable evidence digest; token mismatches and all-zero evidence fail closed.
 */
int ninlil_mfdt_v1_receiver_publication_view(
    const ninlil_mfdt_v1_engine_t *eng, const uint8_t **content_out,
    uint32_t *content_len_out, uint8_t publication_token_out[16],
    uint64_t *acceptance_generation_out);
int ninlil_mfdt_v1_receiver_commit_publication(
    ninlil_mfdt_v1_engine_t *eng, const uint8_t publication_token[16],
    const uint8_t publication_evidence_digest[32]);

/*
 * Session generation advance: arbitrary non-zero u32 initial value, then at
 * most its exact successor. Reclaims RESUME-class NRC1 slots only.
 */
int ninlil_mfdt_v1_advance_session_generation(ninlil_mfdt_v1_engine_t *eng);

/* Private MFDT admission profile revision 2: policy ON + capability + MFN1. */
int ninlil_mfdt_v1_admission_check(const ninlil_mfdt_v1_config_t *cfg);

/* CU on a durable store key against intended old/new images. */
ninlil_mfdt_v1_cu_class_t ninlil_mfdt_v1_cu_observe_key(
    const ninlil_mfdt_v1_lab_store_t *st, uint8_t *scratch,
    uint32_t scratch_bytes, const uint8_t key[20],
    const uint8_t *old_bytes, uint32_t old_len, int has_old,
    const uint8_t *new_bytes, uint32_t new_len, int has_new);

/* ESP storage_ops bind (store_esp.c). Host lab store ignores the binding. */
int ninlil_mfdt_v1_esp_store_bind(ninlil_mfdt_v1_lab_store_t *st,
                                  const void *storage_ops,
                                  void *storage_handle);
void ninlil_mfdt_v1_esp_store_unbind(ninlil_mfdt_v1_lab_store_t *st);

/* NRC1 late-duplicate (active or post-terminal pre-GC) */
int ninlil_mfdt_v1_nrc1_lookup(ninlil_mfdt_v1_engine_t *eng,
                               const uint8_t transfer_id[16], uint64_t request_id,
                               const uint8_t req_digest[32],
                               ninlil_mfdt_v1_response_t *resp);

/* Budget pins for wear gates */
uint16_t ninlil_mfdt_v1_receiver_fulls_max(void);
uint16_t ninlil_mfdt_v1_sender_fulls_max(void);


/* ---- Exact wire (ADR-0021 / vector authority) ---------------------------- */
void ninlil_mfdt_v1_bind52(const uint8_t transfer_id[16], uint32_t revision,
                           const uint8_t manifest_digest[32], uint8_t out[52]);
int ninlil_mfdt_v1_encode_open(
    const uint8_t transfer_id[16], uint32_t total_length, const uint8_t *content,
    const ninlil_mfdt_v1_open_metadata_t *metadata,
    uint8_t *open_out, uint16_t *open_len_out,
    uint8_t *entries_out, uint16_t *entry_bytes_out, uint8_t manifest_out[32],
    uint8_t whole_out[32]);
/* Validate the complete Accepted revision-2 OPEN layout and binding. */
int ninlil_mfdt_v1_validate_open(const uint8_t *open, uint16_t open_len,
                                 const uint8_t *entries,
                                 uint16_t entry_bytes,
                                 const uint8_t *content,
                                 uint32_t content_len,
                                 uint8_t require_manifest);
/*
 * page_out provides the exact final body capacity (max 972 bytes) and is also
 * the encoder scratch. entries may be disjoint or exactly page_out + 92;
 * every other input/output overlap is rejected before output mutation.
 */
int ninlil_mfdt_v1_encode_page(const uint8_t transfer_id[16], uint32_t revision,
                               const uint8_t manifest_digest[32],
                               uint16_t page_index, uint16_t page_count,
                               uint16_t first_chunk_index, uint16_t entry_count,
                               const uint8_t *entries, uint8_t *page_out,
                               uint16_t *page_len_out);
int ninlil_mfdt_v1_encode_chunk_offer(const uint8_t transfer_id[16],
                                      uint32_t revision,
                                      const uint8_t manifest_digest[32],
                                      uint16_t chunk_index, uint16_t chunk_count,
                                      uint32_t chunk_offset, uint16_t chunk_len,
                                      const uint8_t *chunk_bytes, uint8_t *out,
                                      uint16_t *out_len);
int ninlil_mfdt_v1_encode_open_accept(const uint8_t transfer_id[16],
                                      uint32_t revision,
                                      const uint8_t manifest_digest[32],
                                      const uint8_t reservation_id[16],
                                      uint32_t reserved_total,
                                      const uint8_t res_epoch[16],
                                      uint64_t not_after_ms,
                                      uint8_t manifest_complete, uint8_t *out,
                                      uint16_t *out_len);
int ninlil_mfdt_v1_encode_page_accept(const uint8_t transfer_id[16],
                                      uint32_t revision,
                                      const uint8_t manifest_digest[32],
                                      uint16_t page_index,
                                      uint16_t received_page_count,
                                      const uint8_t page_digest[32],
                                      const uint8_t reservation_id[16],
                                      uint8_t manifest_complete, uint8_t *out,
                                      uint16_t *out_len);
int ninlil_mfdt_v1_encode_chunk_accept(const uint8_t transfer_id[16],
                                       uint32_t revision,
                                       const uint8_t manifest_digest[32],
                                       uint16_t chunk_index,
                                       const uint8_t chunk_sha[32], uint8_t *out,
                                       uint16_t *out_len);
int ninlil_mfdt_v1_encode_finalize(const uint8_t transfer_id[16],
                                   uint32_t revision,
                                   const uint8_t manifest_digest[32],
                                   const uint8_t whole[32], uint32_t total_len,
                                   uint8_t *out, uint16_t *out_len);
int ninlil_mfdt_v1_encode_transfer_accept(
    const uint8_t transfer_id[16], uint32_t revision,
    const uint8_t manifest_digest[32], const uint8_t whole[32],
    uint32_t total_len, const uint8_t evidence[16], uint64_t acc_gen,
    const uint8_t reservation_id[16], const uint8_t acc_digest[32], uint8_t *out,
    uint16_t *out_len);

/* Durable NM3S/NM3R: header 308 + open + entries + content + crc */
int ninlil_mfdt_v1_record_pack(uint8_t owner_side, uint8_t state_code,
                               const uint8_t transfer_id[16], uint32_t revision,
                               const uint8_t manifest_digest[32],
                               const uint8_t *open_body, uint16_t open_len,
                               const uint8_t *entries, uint16_t entry_bytes,
                               const uint8_t *content, uint32_t content_len,
                               uint64_t record_generation, uint8_t page_bitmap,
                               uint64_t chunk_bitmap, uint8_t retry_budget,
                               uint8_t publication_state, uint8_t handoff_state,
                               const uint8_t reservation_id[16],
                               const uint8_t res_epoch[16], uint64_t not_after,
                               const uint8_t publication_token[16],
                               uint32_t session_generation,
                               uint8_t *out, uint32_t out_cap, uint32_t *out_len);
int ninlil_mfdt_v1_record_unpack(const uint8_t *rec, uint32_t rec_len,
                                 uint8_t *owner_side, uint8_t *state_code,
                                 uint8_t transfer_id[16], uint32_t *revision,
                                 uint8_t manifest_digest[32],
                                 const uint8_t **open_body, uint16_t *open_len,
                                 const uint8_t **entries, uint16_t *entry_bytes,
                                 const uint8_t **content, uint32_t *content_len,
                                 uint64_t *record_generation, uint8_t *page_bitmap,
                                 uint64_t *chunk_bitmap, uint8_t *retry_budget,
                                 uint8_t *publication_state, uint8_t *handoff_state);


#ifdef __cplusplus
}
#endif

#endif /* NINLIL_MFDT_V1_H */
