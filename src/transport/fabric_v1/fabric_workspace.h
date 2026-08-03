/*
 * Exact profile-1 198,656-byte workspace partition (ADR-0017).
 * Region budgets are the real live object sizes (sizeof/offsetof), not
 * count-only body estimates. Regions do not loan capacity across boundaries.
 */
#ifndef NINLIL_TRANSPORT_FABRIC_V1_FABRIC_WORKSPACE_H
#define NINLIL_TRANSPORT_FABRIC_V1_FABRIC_WORKSPACE_H

#include "fabric_private_util.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Exact region sizes (bytes). Sum must equal 198656.
 * Derived from live fabric_private_t placement (no cross-region loan):
 *   packet_pool 32×1936=61952, codec 2×2048=4096, registry objects 11136,
 *   policy slots 64×136=8704, authority slots 64×320=20480,
 *   attempt slots 64×816=52224, trigger slots 64×240=15360,
 *   rx_queue 32×752=24064; residual 640 split timers/metrics/control.
 */
#define NINLIL_FABRIC_WS_NFL1_QUEUE_BYTES ((uint32_t)61952u)
#define NINLIL_FABRIC_WS_CODEC_SCRATCH_BYTES ((uint32_t)4096u)
#define NINLIL_FABRIC_WS_REGISTRY_BYTES ((uint32_t)11136u)
#define NINLIL_FABRIC_WS_POLICY_INDEX_BYTES ((uint32_t)8704u)
#define NINLIL_FABRIC_WS_AUTHORITY_INDEX_BYTES ((uint32_t)20480u)
#define NINLIL_FABRIC_WS_ATTEMPT_BYTES ((uint32_t)52224u)
#define NINLIL_FABRIC_WS_TRIGGER_BYTES ((uint32_t)15360u)
#define NINLIL_FABRIC_WS_QUEUE_DESC_BYTES ((uint32_t)24064u)
#define NINLIL_FABRIC_WS_TIMERS_BYTES ((uint32_t)128u)
#define NINLIL_FABRIC_WS_REG_METRICS_BYTES ((uint32_t)128u)
#define NINLIL_FABRIC_WS_CONTROL_BYTES ((uint32_t)384u)

#define NINLIL_FABRIC_WS_TOTAL_BYTES                                         \
    (NINLIL_FABRIC_WS_NFL1_QUEUE_BYTES + NINLIL_FABRIC_WS_CODEC_SCRATCH_BYTES \
     + NINLIL_FABRIC_WS_REGISTRY_BYTES + NINLIL_FABRIC_WS_POLICY_INDEX_BYTES \
     + NINLIL_FABRIC_WS_AUTHORITY_INDEX_BYTES                                \
     + NINLIL_FABRIC_WS_ATTEMPT_BYTES + NINLIL_FABRIC_WS_TRIGGER_BYTES       \
     + NINLIL_FABRIC_WS_QUEUE_DESC_BYTES + NINLIL_FABRIC_WS_TIMERS_BYTES     \
     + NINLIL_FABRIC_WS_REG_METRICS_BYTES + NINLIL_FABRIC_WS_CONTROL_BYTES)

_Static_assert(
    NINLIL_FABRIC_WS_TOTAL_BYTES == 198656u,
    "profile-1 workspace must be exact 198656");
_Static_assert(
    NINLIL_FABRIC_WS_TOTAL_BYTES == NINLIL_FABRIC_WORKSPACE_BYTES,
    "WORKSPACE_BYTES must match partition sum");
/* Body floor: structural NFL1 max still fits inside slot-header-inclusive region. */
_Static_assert(
    NINLIL_FABRIC_SHARED_QUEUE_MAX * NINLIL_FABRIC_NFL1_STRUCTURAL_MAX
        <= NINLIL_FABRIC_WS_NFL1_QUEUE_BYTES,
    "NFL1 structural body must fit NFL1 queue region");
_Static_assert(
    NINLIL_FABRIC_POLICY_MAX * 128u <= NINLIL_FABRIC_WS_POLICY_INDEX_BYTES,
    "policy index body must fit policy region");
_Static_assert(
    NINLIL_FABRIC_AUTHORITY_MAX * 160u
        <= NINLIL_FABRIC_WS_AUTHORITY_INDEX_BYTES,
    "authority index body must fit authority region");
_Static_assert(
    NINLIL_FABRIC_TRIGGER_MAX * 240u <= NINLIL_FABRIC_WS_TRIGGER_BYTES,
    "trigger slots must fit trigger region");
_Static_assert(
    NINLIL_FABRIC_ATTEMPT_MAX * 816u <= NINLIL_FABRIC_WS_ATTEMPT_BYTES,
    "attempt slots must fit attempt region");

/* Absolute offsets from workspace base. */
#define NINLIL_FABRIC_WS_OFF_NFL1_QUEUE ((uint32_t)0u)
#define NINLIL_FABRIC_WS_OFF_CODEC_SCRATCH \
    (NINLIL_FABRIC_WS_OFF_NFL1_QUEUE + NINLIL_FABRIC_WS_NFL1_QUEUE_BYTES)
#define NINLIL_FABRIC_WS_OFF_REGISTRY \
    (NINLIL_FABRIC_WS_OFF_CODEC_SCRATCH + NINLIL_FABRIC_WS_CODEC_SCRATCH_BYTES)
#define NINLIL_FABRIC_WS_OFF_POLICY_INDEX \
    (NINLIL_FABRIC_WS_OFF_REGISTRY + NINLIL_FABRIC_WS_REGISTRY_BYTES)
#define NINLIL_FABRIC_WS_OFF_AUTHORITY_INDEX \
    (NINLIL_FABRIC_WS_OFF_POLICY_INDEX + NINLIL_FABRIC_WS_POLICY_INDEX_BYTES)
#define NINLIL_FABRIC_WS_OFF_ATTEMPT \
    (NINLIL_FABRIC_WS_OFF_AUTHORITY_INDEX \
     + NINLIL_FABRIC_WS_AUTHORITY_INDEX_BYTES)
#define NINLIL_FABRIC_WS_OFF_TRIGGER \
    (NINLIL_FABRIC_WS_OFF_ATTEMPT + NINLIL_FABRIC_WS_ATTEMPT_BYTES)
#define NINLIL_FABRIC_WS_OFF_QUEUE_DESC \
    (NINLIL_FABRIC_WS_OFF_TRIGGER + NINLIL_FABRIC_WS_TRIGGER_BYTES)
#define NINLIL_FABRIC_WS_OFF_TIMERS \
    (NINLIL_FABRIC_WS_OFF_QUEUE_DESC + NINLIL_FABRIC_WS_QUEUE_DESC_BYTES)
#define NINLIL_FABRIC_WS_OFF_REG_METRICS \
    (NINLIL_FABRIC_WS_OFF_TIMERS + NINLIL_FABRIC_WS_TIMERS_BYTES)
#define NINLIL_FABRIC_WS_OFF_CONTROL \
    (NINLIL_FABRIC_WS_OFF_REG_METRICS + NINLIL_FABRIC_WS_REG_METRICS_BYTES)

_Static_assert(
    NINLIL_FABRIC_WS_OFF_CONTROL + NINLIL_FABRIC_WS_CONTROL_BYTES
        == NINLIL_FABRIC_WS_TOTAL_BYTES,
    "last region ends at workspace end");

/* Compact index entry sizes (exact, natural alignment, no packing pragma). */
typedef struct ninlil_fabric_policy_index_entry {
    uint64_t revision;
    uint64_t deadline_guard_ms;
    uint32_t family;
    uint32_t direction;
    uint32_t required_capability_flags;
    uint32_t required_security_flags;
    uint32_t minimum_packet_bytes;
    uint16_t traffic_class;
    uint16_t scope_selector;
    uint16_t maximum_latency_class;
    uint16_t maximum_cost_class;
    uint8_t policy_id[16];
    uint8_t canonical_digest[32];
    uint8_t service_identity_digest[32];
    uint8_t used;
    uint8_t authority_mode;
    uint8_t candidate_count;
    uint8_t reserved0;
} ninlil_fabric_policy_index_entry_t;

_Static_assert(
    sizeof(ninlil_fabric_policy_index_entry_t) == 128u,
    "policy index entry must be 128");

typedef struct ninlil_fabric_authority_index_entry {
    uint64_t policy_revision;
    uint32_t used;
    uint32_t family;
    uint32_t direction;
    uint16_t traffic_class;
    uint16_t scope_selector;
    uint8_t binding_id[16];
    uint8_t service_identity_digest[32];
    uint8_t endpoint_runtime_id[16];
    uint8_t target_runtime_id[16];
    uint8_t target_application_id[16];
    uint8_t policy_id[16];
    uint8_t reserved_pad[24]; /* exact 160; full FBC1 from storage */
} ninlil_fabric_authority_index_entry_t;

_Static_assert(
    sizeof(ninlil_fabric_authority_index_entry_t) == 160u,
    "authority index entry must be 160");

typedef struct ninlil_fabric_ws_region_info {
    uint32_t offset;
    uint32_t size;
    uint32_t alignment;
    const char *name;
} ninlil_fabric_ws_region_info_t;

#define NINLIL_FABRIC_WS_REGION_COUNT 11u

/* Runtime proof: no overlap, exact ceiling, alignment. */
uint32_t ninlil_fabric_private_workspace_layout_proof_v1(
    uint32_t *out_total,
    ninlil_fabric_ws_region_info_t out_regions[NINLIL_FABRIC_WS_REGION_COUNT]);
#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_FABRIC_V1_FABRIC_WORKSPACE_H */
