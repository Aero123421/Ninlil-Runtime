/* SPDX-License-Identifier: Apache-2.0
 * ADR-0021 exact four-slot Host coordinator.
 */
#include "mfdt_v1_host_coordinator.h"

#include <stddef.h>
#include <string.h>

#define MFDT_HOST_MAGIC ((uint32_t)0x4d463448u) /* "MF4H" */
#define MFDT_HOST_XFER_REGION_BYTES    ((size_t)512u)
#define MFDT_HOST_OPEN_REGION_BYTES    ((size_t)656u)
#define MFDT_HOST_ENTRIES_REGION_BYTES \
    ((size_t)NINLIL_MFDT_V1_MAX_CHUNKS * \
     (size_t)NINLIL_MFDT_V1_ENTRY_BYTES)
#define MFDT_HOST_TEMP_USED_BYTES \
    (MFDT_HOST_XFER_REGION_BYTES + MFDT_HOST_OPEN_REGION_BYTES + \
     MFDT_HOST_ENTRIES_REGION_BYTES)

typedef union mfdt_host_header {
    uint64_t align8;
    uint8_t opaque[NINLIL_MFDT_V1_HOST_HEADER_BYTES];
    struct {
        ninlil_mfdt_v1_store_port_t *store;
        ninlil_mfdt_v1_config_t base_config;
        uint64_t now_ms;
        uint64_t committed_logical_bytes;
        uint32_t tracked_groups;
        uint32_t committed_keys;
        uint32_t magic;
        uint8_t active_count;
        uint8_t next_slot;
        uint8_t full_locked;
        uint8_t started;
        uint8_t recovered;
        uint8_t inventory_uncertain;
        uint8_t terminal_count;
    } f;
} mfdt_host_header_t;

typedef union mfdt_host_slot_desc {
    uint64_t align8;
    uint8_t opaque[NINLIL_MFDT_V1_HOST_SLOT_DESC_BYTES];
    struct {
        uint8_t transfer_id[16];
        uint8_t peer_endpoint_id[16];
        uint64_t session_cookie;
        uint32_t session_generation;
        uint32_t fulls_this_transfer;
        uint8_t publication_token[16];
        uint8_t upper_dedupe_token[16];
        uint8_t role;
        uint8_t occupied;
        uint8_t bind_valid;
        uint8_t unpaid_chunk_offer;
        uint8_t publication_ready;
        uint8_t handoff_complete;
        uint8_t upper_dedupe_valid;
        uint8_t active_accounted;
        uint8_t durable_group;
        uint8_t terminal_published;
        uint8_t reserved1[6];
    } f;
} mfdt_host_slot_desc_t;

typedef union mfdt_host_terminal_desc {
    uint64_t align8;
    uint8_t opaque[NINLIL_MFDT_V1_HOST_TERMINAL_DESC_BYTES];
    struct {
        uint8_t transfer_id[16];
        uint8_t peer_endpoint_id[16];
        uint64_t session_cookie;
        uint32_t session_generation;
        uint8_t role;
        uint8_t nm30_schema;
        uint8_t replay_eligible;
        uint8_t bind_valid;
        uint8_t occupied;
        uint8_t reserved[15];
    } f;
} mfdt_host_terminal_desc_t;

typedef union mfdt_host_control_meta {
    uint64_t align8;
    uint8_t opaque[NINLIL_MFDT_V1_HOST_CONTROL_META_BYTES];
    struct {
        uint64_t session_cookie;
        uint8_t peer_endpoint_id[16];
        uint32_t session_generation;
        uint16_t frame_length;
        uint8_t route;
        uint8_t role;
        uint8_t owned;
        uint8_t reserved[31];
    } f;
} mfdt_host_control_meta_t;

typedef union mfdt_host_slot_arena {
    uint64_t align8;
    uint8_t opaque[NINLIL_MFDT_V1_WORKSPACE_BYTES];
    struct {
        uint8_t active_record[NINLIL_MFDT_V1_HOST_ACTIVE_REGION_BYTES];
        uint8_t nrc1[NINLIL_MFDT_V1_HOST_NRC1_REGION_BYTES];
        uint8_t pipeline[NINLIL_MFDT_V1_HOST_PIPELINE_REGION_BYTES];
        uint8_t engine[NINLIL_MFDT_V1_HOST_ENGINE_REGION_BYTES];
        uint8_t temporary[NINLIL_MFDT_V1_HOST_TEMP_REGION_BYTES];
    } f;
} mfdt_host_slot_arena_t;

typedef struct mfdt_host_owner_layout {
    mfdt_host_header_t header;
    mfdt_host_slot_desc_t slots[NINLIL_MFDT_V1_HOST_SLOT_COUNT];
    mfdt_host_terminal_desc_t
        terminals[NINLIL_MFDT_V1_HOST_TERMINAL_COUNT_MAX];
    mfdt_host_control_meta_t control_meta;
    uint8_t control_outbox[NINLIL_MFDT_V1_HOST_CONTROL_OUTBOX_BYTES];
    uint8_t control_nrc1[NINLIL_MFDT_V1_HOST_CONTROL_NRC1_BYTES];
    uint8_t control_nm30[NINLIL_MFDT_V1_HOST_CONTROL_NM30_BYTES];
    uint8_t control_reserved[NINLIL_MFDT_V1_HOST_CONTROL_RESERVED_BYTES];
    mfdt_host_slot_arena_t arenas[NINLIL_MFDT_V1_HOST_SLOT_COUNT];
} mfdt_host_owner_layout_t;

typedef struct mfdt_host_group_summary {
    uint8_t transfer_id[16];
    uint8_t peer_endpoint_id[16];
    uint32_t session_generation;
    uint32_t nrc1_session_generation;
    uint32_t active_value_len;
    uint8_t flags;
    uint8_t role;
    uint8_t capture_slot;
    uint8_t nrc1_captured;
    uint8_t nm30_schema;
    uint8_t replay_eligible;
} mfdt_host_group_summary_t;

#define MFDT_GROUP_SENDER   ((uint8_t)1u << 0)
#define MFDT_GROUP_RECEIVER ((uint8_t)1u << 1)
#define MFDT_GROUP_TERMINAL ((uint8_t)1u << 2)
#define MFDT_GROUP_NRC1     ((uint8_t)1u << 3)

static int tid_compare(const uint8_t left[16], const uint8_t right[16]);
static int coordinator_full_begin(mfdt_host_owner_layout_t *layout);
static int coordinator_full_rollback(mfdt_host_owner_layout_t *layout);
static int coordinator_full_commit(mfdt_host_owner_layout_t *layout);
static int coordinator_full_get(
    mfdt_host_owner_layout_t *layout,
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES],
    uint8_t *value_out, uint32_t value_cap,
    uint32_t *value_len_out);
static int wire_is_request(uint8_t type);

_Static_assert(
    NINLIL_MFDT_V1_HOST_HEADER_BYTES +
            NINLIL_MFDT_V1_HOST_SLOT_COUNT *
                NINLIL_MFDT_V1_HOST_SLOT_DESC_BYTES ==
        NINLIL_MFDT_V1_HOST_METADATA_BYTES,
    "Host metadata must be exact 512");
_Static_assert(
    NINLIL_MFDT_V1_HOST_METADATA_BYTES +
            NINLIL_MFDT_V1_HOST_TERMINAL_CATALOG_BYTES +
            NINLIL_MFDT_V1_HOST_CONTROL_META_BYTES +
            NINLIL_MFDT_V1_HOST_CONTROL_OUTBOX_BYTES +
            NINLIL_MFDT_V1_HOST_CONTROL_NRC1_BYTES +
            NINLIL_MFDT_V1_HOST_CONTROL_NM30_BYTES +
            NINLIL_MFDT_V1_HOST_CONTROL_RESERVED_BYTES ==
        NINLIL_MFDT_V1_HOST_CONTROL_AREA_BYTES,
    "Host control arena must be exact 17920");
_Static_assert(
    NINLIL_MFDT_V1_HOST_CONTROL_AREA_BYTES +
            NINLIL_MFDT_V1_HOST_SLOT_COUNT *
                NINLIL_MFDT_V1_WORKSPACE_BYTES ==
        NINLIL_MFDT_V1_HOST_OWNER_BYTES,
    "Host owner must be exact 280064");
_Static_assert(
    NINLIL_MFDT_V1_HOST_ACTIVE_REGION_BYTES +
            NINLIL_MFDT_V1_HOST_NRC1_REGION_BYTES +
            NINLIL_MFDT_V1_HOST_PIPELINE_REGION_BYTES +
            NINLIL_MFDT_V1_HOST_ENGINE_REGION_BYTES +
            NINLIL_MFDT_V1_HOST_TEMP_REGION_BYTES ==
        NINLIL_MFDT_V1_WORKSPACE_BYTES,
    "Host slot regions must be exact 65536");
_Static_assert(
    MFDT_HOST_TEMP_USED_BYTES <= NINLIL_MFDT_V1_HOST_TEMP_REGION_BYTES,
    "Host temporary projection must fit");
_Static_assert(sizeof(ninlil_mfdt_v1_host_owner_t) ==
        NINLIL_MFDT_V1_HOST_OWNER_BYTES,
    "Host opaque owner size");
_Static_assert(_Alignof(ninlil_mfdt_v1_host_owner_t) >= 8u,
    "Host opaque owner alignment");
_Static_assert(
    sizeof(mfdt_host_header_t) == NINLIL_MFDT_V1_HOST_HEADER_BYTES,
    "Host header size");
_Static_assert(
    sizeof(mfdt_host_slot_desc_t) ==
        NINLIL_MFDT_V1_HOST_SLOT_DESC_BYTES,
    "Host descriptor size");
_Static_assert(
    sizeof(mfdt_host_terminal_desc_t) ==
        NINLIL_MFDT_V1_HOST_TERMINAL_DESC_BYTES,
    "Host terminal descriptor size");
_Static_assert(
    sizeof(mfdt_host_control_meta_t) ==
        NINLIL_MFDT_V1_HOST_CONTROL_META_BYTES,
    "Host control metadata size");
_Static_assert(
    sizeof(mfdt_host_slot_arena_t) == NINLIL_MFDT_V1_WORKSPACE_BYTES,
    "Host slot arena size");
_Static_assert(offsetof(mfdt_host_owner_layout_t, arenas) ==
        NINLIL_MFDT_V1_HOST_CONTROL_AREA_BYTES,
    "Host arena offset");
_Static_assert(
    offsetof(mfdt_host_owner_layout_t, terminals) ==
        NINLIL_MFDT_V1_HOST_METADATA_BYTES,
    "Host terminal catalog offset");
_Static_assert(
    offsetof(mfdt_host_owner_layout_t, control_meta) ==
        NINLIL_MFDT_V1_HOST_METADATA_BYTES +
            NINLIL_MFDT_V1_HOST_TERMINAL_CATALOG_BYTES,
    "Host control metadata offset");
_Static_assert(sizeof(mfdt_host_owner_layout_t) ==
        NINLIL_MFDT_V1_HOST_OWNER_BYTES,
    "Host layout size");
_Static_assert(
    sizeof(ninlil_mfdt_v1_pipeline_t) <=
        NINLIL_MFDT_V1_HOST_PIPELINE_REGION_BYTES,
    "Pipeline must fit its slot region");
_Static_assert(
    sizeof(ninlil_mfdt_v1_engine_t) <=
        NINLIL_MFDT_V1_HOST_ENGINE_REGION_BYTES,
    "Engine must fit its slot region");
_Static_assert(
    offsetof(mfdt_host_slot_arena_t, f.active_record) == 0u,
    "active record offset");
_Static_assert(
    offsetof(mfdt_host_slot_arena_t, f.nrc1) ==
        NINLIL_MFDT_V1_HOST_ACTIVE_REGION_BYTES,
    "NRC1 offset");
_Static_assert(
    offsetof(mfdt_host_slot_arena_t, f.pipeline) ==
        NINLIL_MFDT_V1_HOST_ACTIVE_REGION_BYTES +
            NINLIL_MFDT_V1_HOST_NRC1_REGION_BYTES,
    "pipeline offset");
_Static_assert(
    offsetof(mfdt_host_slot_arena_t, f.engine) ==
        NINLIL_MFDT_V1_HOST_ACTIVE_REGION_BYTES +
            NINLIL_MFDT_V1_HOST_NRC1_REGION_BYTES +
            NINLIL_MFDT_V1_HOST_PIPELINE_REGION_BYTES,
    "engine offset");
_Static_assert(
    offsetof(mfdt_host_slot_arena_t, f.temporary) ==
        NINLIL_MFDT_V1_HOST_ACTIVE_REGION_BYTES +
            NINLIL_MFDT_V1_HOST_NRC1_REGION_BYTES +
            NINLIL_MFDT_V1_HOST_PIPELINE_REGION_BYTES +
            NINLIL_MFDT_V1_HOST_ENGINE_REGION_BYTES,
    "temporary offset");

static mfdt_host_owner_layout_t *owner_layout(
    ninlil_mfdt_v1_host_owner_t *owner)
{
    return (mfdt_host_owner_layout_t *)(void *)owner->opaque;
}

static const mfdt_host_owner_layout_t *owner_layout_const(
    const ninlil_mfdt_v1_host_owner_t *owner)
{
    return (const mfdt_host_owner_layout_t *)(const void *)owner->opaque;
}

static ninlil_mfdt_v1_engine_t *slot_engine(
    mfdt_host_owner_layout_t *layout, uint8_t slot)
{
    return (ninlil_mfdt_v1_engine_t *)(void *)
        layout->arenas[slot].f.engine;
}

static const ninlil_mfdt_v1_engine_t *slot_engine_const(
    const mfdt_host_owner_layout_t *layout, uint8_t slot)
{
    return (const ninlil_mfdt_v1_engine_t *)(const void *)
        layout->arenas[slot].f.engine;
}

static ninlil_mfdt_v1_pipeline_t *slot_pipeline(
    mfdt_host_owner_layout_t *layout, uint8_t slot)
{
    return (ninlil_mfdt_v1_pipeline_t *)(void *)
        layout->arenas[slot].f.pipeline;
}

static const ninlil_mfdt_v1_pipeline_t *slot_pipeline_const(
    const mfdt_host_owner_layout_t *layout, uint8_t slot)
{
    return (const ninlil_mfdt_v1_pipeline_t *)(const void *)
        layout->arenas[slot].f.pipeline;
}

static int bytes_zero(const uint8_t *bytes, size_t length)
{
    uint8_t any = 0u;
    size_t index;
    if (bytes == NULL) {
        return 1;
    }
    for (index = 0u; index < length; ++index) {
        any = (uint8_t)(any | bytes[index]);
    }
    return any == 0u;
}

static int ranges_overlap(
    const void *left, size_t left_len,
    const void *right, size_t right_len)
{
    const uintptr_t lb = (uintptr_t)left;
    const uintptr_t rb = (uintptr_t)right;
    if (left == NULL || right == NULL || left_len == 0u || right_len == 0u ||
        lb > UINTPTR_MAX - left_len || rb > UINTPTR_MAX - right_len) {
        return 1;
    }
    return lb < rb + right_len && rb < lb + left_len;
}

static int owner_is_valid(const ninlil_mfdt_v1_host_owner_t *owner)
{
    const mfdt_host_owner_layout_t *layout;
    if (owner == NULL || ((uintptr_t)owner & 7u) != 0u) {
        return 0;
    }
    layout = owner_layout_const(owner);
    return layout->header.f.magic == MFDT_HOST_MAGIC &&
           layout->header.f.store != NULL;
}

static int bind_is_valid(const ninlil_mfdt_v1_host_bind_t *bind)
{
    return bind != NULL &&
           !bytes_zero(bind->peer_endpoint_id, 16u) &&
           bind->session_generation > 0u &&
           bind->session_cookie != 0ull &&
           (bind->role == NINLIL_MFDT_V1_HOST_ROLE_SENDER ||
            bind->role == NINLIL_MFDT_V1_HOST_ROLE_RECEIVER);
}

static int store_port_is_usable(
    const ninlil_mfdt_v1_store_port_t *store)
{
    const ninlil_storage_ops_t *ops;
    if (store == NULL ||
        ((uintptr_t)store %
         (uintptr_t)_Alignof(ninlil_mfdt_v1_store_port_t)) != 0u ||
        store->handle == NULL || store->ops == NULL ||
        store->full_open != 0u || store->snapshot_open != 0u ||
        store->rw_txn != NULL || store->staged_ops != 0u ||
        store->staged_put_images != 0u ||
        store->staged_logical_bytes != 0u ||
        store->poison_status != NINLIL_MFDT_V1_OK ||
        ninlil_mfdt_v1_store_guarantees_validate(
            &store->guarantees) != NINLIL_MFDT_V1_OK) {
        return 0;
    }
    ops = store->ops;
    return ops->abi_version == NINLIL_ABI_VERSION &&
           ops->struct_size >= sizeof(*ops) &&
           ops->begin != NULL && ops->get != NULL &&
           ops->put != NULL && ops->erase != NULL &&
           ops->iter_open != NULL && ops->iter_next != NULL &&
           ops->iter_close != NULL && ops->commit != NULL &&
           ops->rollback != NULL;
}

static int initialize_slot_runtime(
    mfdt_host_owner_layout_t *layout, uint8_t slot,
    const ninlil_mfdt_v1_config_t *config)
{
    mfdt_host_slot_arena_t *arena;
    ninlil_mfdt_v1_engine_slot_memory_t memory;
    ninlil_mfdt_v1_engine_t *engine;
    ninlil_mfdt_v1_pipeline_t *pipeline;
    int rc;
    if (layout == NULL || slot >= NINLIL_MFDT_V1_HOST_SLOT_COUNT ||
        config == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    arena = &layout->arenas[slot];
    engine = slot_engine(layout, slot);
    pipeline = slot_pipeline(layout, slot);
    ninlil_mfdt_v1_memzero(&memory, sizeof(memory));
    memory.record_memory = arena->f.active_record;
    memory.record_memory_bytes =
        (uint32_t)sizeof(arena->f.active_record);
    memory.nrc1_memory = arena->f.nrc1;
    memory.nrc1_memory_bytes = (uint32_t)sizeof(arena->f.nrc1);
    memory.xfer_memory = arena->f.temporary;
    memory.xfer_memory_bytes = (uint32_t)MFDT_HOST_XFER_REGION_BYTES;
    memory.open_staging =
        arena->f.temporary + MFDT_HOST_XFER_REGION_BYTES;
    memory.open_staging_bytes = (uint32_t)MFDT_HOST_OPEN_REGION_BYTES;
    memory.entries_staging =
        arena->f.temporary + MFDT_HOST_XFER_REGION_BYTES +
        MFDT_HOST_OPEN_REGION_BYTES;
    memory.entries_staging_bytes =
        (uint32_t)MFDT_HOST_ENTRIES_REGION_BYTES;
    rc = ninlil_mfdt_v1_engine_init_slot(
        engine, &memory, layout->header.f.store,
        &layout->header.f.committed_keys,
        &layout->header.f.committed_logical_bytes,
        &layout->header.f.full_locked,
        &layout->header.f.inventory_uncertain, config);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    ninlil_mfdt_v1_pipeline_init(
        pipeline, NULL, NULL, NULL, NULL,
        config->session_generation, 0ull);
    return NINLIL_MFDT_V1_OK;
}

static int reset_slot(
    mfdt_host_owner_layout_t *layout, uint8_t slot)
{
    ninlil_mfdt_v1_config_t config;
    if (layout == NULL || slot >= NINLIL_MFDT_V1_HOST_SLOT_COUNT) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    config = layout->header.f.base_config;
    config.now_ms = layout->header.f.now_ms;
    ninlil_mfdt_v1_memzero(
        &layout->slots[slot], sizeof(layout->slots[slot]));
    return initialize_slot_runtime(layout, slot, &config);
}

static int find_slot_by_tid(
    const mfdt_host_owner_layout_t *layout,
    const uint8_t transfer_id[16])
{
    uint8_t slot;
    for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
        if (layout->slots[slot].f.occupied != 0u &&
            layout->slots[slot].f.terminal_published == 0u &&
            ninlil_mfdt_v1_memeq(
                layout->slots[slot].f.transfer_id, transfer_id, 16u)) {
            return (int)slot;
        }
    }
    return -1;
}

static int find_terminal_by_tid(
    const mfdt_host_owner_layout_t *layout,
    const uint8_t transfer_id[16])
{
    uint8_t index;
    for (index = 0u; index < layout->header.f.terminal_count; ++index) {
        if (layout->terminals[index].f.occupied != 0u &&
            ninlil_mfdt_v1_memeq(
                layout->terminals[index].f.transfer_id,
                transfer_id, 16u)) {
            return (int)index;
        }
    }
    return -1;
}

static int terminal_catalog_insert(
    mfdt_host_owner_layout_t *layout,
    const mfdt_host_terminal_desc_t *terminal)
{
    uint8_t position;
    uint8_t count;
    if (layout == NULL || terminal == NULL ||
        terminal->f.occupied == 0u ||
        bytes_zero(terminal->f.transfer_id, 16u)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    count = layout->header.f.terminal_count;
    if (count >= NINLIL_MFDT_V1_HOST_TERMINAL_COUNT_MAX) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    for (position = 0u; position < count; ++position) {
        const int order = tid_compare(
            terminal->f.transfer_id,
            layout->terminals[position].f.transfer_id);
        if (order == 0) {
            return NINLIL_MFDT_V1_ERR_CORRUPT;
        }
        if (order < 0) {
            break;
        }
    }
    if (position < count) {
        (void)memmove(
            &layout->terminals[position + 1u],
            &layout->terminals[position],
            (size_t)(count - position) *
                sizeof(layout->terminals[0]));
    }
    layout->terminals[position] = *terminal;
    layout->header.f.terminal_count = (uint8_t)(count + 1u);
    return NINLIL_MFDT_V1_OK;
}

static int terminal_catalog_remove(
    mfdt_host_owner_layout_t *layout,
    const uint8_t transfer_id[16])
{
    const int found = find_terminal_by_tid(layout, transfer_id);
    uint8_t count;
    if (found < 0) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    count = layout->header.f.terminal_count;
    if ((uint8_t)found + 1u < count) {
        (void)memmove(
            &layout->terminals[found],
            &layout->terminals[found + 1],
            (size_t)(count - (uint8_t)found - 1u) *
                sizeof(layout->terminals[0]));
    }
    ninlil_mfdt_v1_memzero(
        &layout->terminals[count - 1u],
        sizeof(layout->terminals[0]));
    layout->header.f.terminal_count = (uint8_t)(count - 1u);
    return NINLIL_MFDT_V1_OK;
}

static int find_lowest_free_slot(
    const mfdt_host_owner_layout_t *layout)
{
    uint8_t slot;
    for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
        if (layout->slots[slot].f.occupied == 0u) {
            return (int)slot;
        }
    }
    return -1;
}

static int descriptor_bind_matches(
    const mfdt_host_slot_desc_t *descriptor,
    const ninlil_mfdt_v1_host_bind_t *bind)
{
    return descriptor != NULL && bind_is_valid(bind) &&
           descriptor->f.role == bind->role &&
           descriptor->f.session_generation == bind->session_generation &&
           descriptor->f.session_cookie == bind->session_cookie &&
           ninlil_mfdt_v1_memeq(
               descriptor->f.peer_endpoint_id,
               bind->peer_endpoint_id, 16u);
}

static int terminal_bind_matches(
    const mfdt_host_terminal_desc_t *terminal,
    const ninlil_mfdt_v1_host_bind_t *bind)
{
    return terminal != NULL && bind_is_valid(bind) &&
           terminal->f.replay_eligible != 0u &&
           terminal->f.nm30_schema == 2u &&
           terminal->f.role == bind->role &&
           terminal->f.session_generation == bind->session_generation &&
           terminal->f.session_cookie == bind->session_cookie &&
           ninlil_mfdt_v1_memeq(
               terminal->f.peer_endpoint_id,
               bind->peer_endpoint_id, 16u);
}

static int port_key_exists(
    ninlil_mfdt_v1_store_port_t *port,
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES],
    int *present_out)
{
    ninlil_storage_txn_t transaction = NULL;
    ninlil_bytes_view_t key_view;
    ninlil_mut_bytes_t value;
    ninlil_storage_status_t status;
    ninlil_storage_status_t end_status;
    if (port == NULL || key == NULL || present_out == NULL ||
        port->ops == NULL || port->handle == NULL ||
        port->full_open != 0u || port->snapshot_open != 0u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    *present_out = 0;
    status = port->ops->begin(
        port->ops->user, port->handle, NINLIL_STORAGE_READ_ONLY,
        &transaction);
    if ((status == NINLIL_STORAGE_OK) != (transaction != NULL)) {
        ninlil_storage_status_t rollback_status = NINLIL_STORAGE_OK;
        if (transaction != NULL) {
            rollback_status =
                port->ops->rollback(port->ops->user, transaction);
        }
        return rollback_status != NINLIL_STORAGE_OK
                   ? ninlil_mfdt_v1_store_map_status(rollback_status)
                   : NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (status != NINLIL_STORAGE_OK) {
        return ninlil_mfdt_v1_store_map_status(status);
    }
    key_view.data = key;
    key_view.length = NINLIL_MFDT_V1_KEY_BYTES;
    value.data = NULL;
    value.capacity = 0u;
    value.length = 0u;
    status = port->ops->get(
        port->ops->user, transaction, key_view, &value);
    end_status = port->ops->rollback(port->ops->user, transaction);
    if (end_status != NINLIL_STORAGE_OK) {
        return ninlil_mfdt_v1_store_map_status(end_status);
    }
    if (value.data != NULL || value.capacity != 0u ||
        (status == NINLIL_STORAGE_OK && value.length != 0u) ||
        (status == NINLIL_STORAGE_NOT_FOUND && value.length != 0u) ||
        (status == NINLIL_STORAGE_BUFFER_TOO_SMALL &&
         value.length == 0u) ||
        (status != NINLIL_STORAGE_OK &&
         status != NINLIL_STORAGE_NOT_FOUND &&
         status != NINLIL_STORAGE_BUFFER_TOO_SMALL &&
         value.length != 0u)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (status == NINLIL_STORAGE_OK ||
        status == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
        *present_out = 1;
        return NINLIL_MFDT_V1_OK;
    }
    if (status == NINLIL_STORAGE_NOT_FOUND) {
        return NINLIL_MFDT_V1_OK;
    }
    return ninlil_mfdt_v1_store_map_status(status);
}

static void make_key(
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES],
    const char magic[4], const uint8_t transfer_id[16])
{
    (void)memcpy(key, magic, 4u);
    (void)memcpy(key + 4, transfer_id, 16u);
}

static int transfer_id_is_unused(
    mfdt_host_owner_layout_t *layout,
    const uint8_t transfer_id[16])
{
    static const char kinds[4][4] = {
        {'N', 'M', '3', 'S'}, {'N', 'M', '3', 'R'},
        {'N', 'M', '3', '0'}, {'N', 'R', 'C', '1'}};
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];
    size_t kind;
    for (kind = 0u; kind < 4u; ++kind) {
        int present = 0;
        int rc;
        make_key(key, kinds[kind], transfer_id);
        rc = port_key_exists(layout->header.f.store, key, &present);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc;
        }
        if (present != 0) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
    }
    return NINLIL_MFDT_V1_OK;
}

static int admission_preflight(
    mfdt_host_owner_layout_t *layout,
    const uint8_t transfer_id[16])
{
    int rc;
    if (layout->header.f.inventory_uncertain != 0u) {
        return NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN;
    }
    if (layout->header.f.active_count >=
            NINLIL_MFDT_V1_HOST_SLOT_COUNT ||
        layout->header.f.tracked_groups >= 16u ||
        layout->header.f.committed_keys > 30u ||
        layout->header.f.committed_logical_bytes >
            NINLIL_MFDT_V1_HOST_COMMITTED_LOGICAL_BYTES_MAX -
                NINLIL_MFDT_V1_HOST_FULL_STAGING_LOGICAL_BYTES_MAX ||
        layout->header.f.committed_keys + 2u >
            NINLIL_MFDT_V1_HOST_BEGIN_FINAL_ROW_IMAGES_MAX ||
        layout->header.f.committed_logical_bytes >
            NINLIL_MFDT_V1_HOST_BEGIN_FINAL_UNION_LOGICAL_BYTES_MAX -
                NINLIL_MFDT_V1_HOST_FULL_STAGING_LOGICAL_BYTES_MAX) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    if (find_lowest_free_slot(layout) < 0) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    rc = transfer_id_is_unused(layout, transfer_id);
    return rc;
}

static void descriptor_publish(
    mfdt_host_owner_layout_t *layout, uint8_t slot,
    const uint8_t transfer_id[16],
    const ninlil_mfdt_v1_host_bind_t *bind)
{
    mfdt_host_slot_desc_t *descriptor = &layout->slots[slot];
    ninlil_mfdt_v1_engine_t *engine = slot_engine(layout, slot);
    ninlil_mfdt_v1_memzero(descriptor, sizeof(*descriptor));
    (void)memcpy(descriptor->f.transfer_id, transfer_id, 16u);
    (void)memcpy(
        descriptor->f.peer_endpoint_id, bind->peer_endpoint_id, 16u);
    descriptor->f.session_cookie = bind->session_cookie;
    descriptor->f.session_generation = bind->session_generation;
    descriptor->f.role = bind->role;
    descriptor->f.occupied = 1u;
    descriptor->f.bind_valid = 1u;
    descriptor->f.active_accounted = 1u;
    descriptor->f.durable_group = 1u;
    descriptor->f.fulls_this_transfer = engine->fulls_this_transfer;
    layout->header.f.active_count =
        (uint8_t)(layout->header.f.active_count + 1u);
    layout->header.f.tracked_groups += 1u;
}

static int publish_terminal_from_slot(
    mfdt_host_owner_layout_t *layout, uint8_t slot)
{
    mfdt_host_slot_desc_t *descriptor = &layout->slots[slot];
    mfdt_host_terminal_desc_t terminal;
    uint8_t nm30_key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t nrc1_key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t peer[16];
    uint32_t nm30_len = 0u;
    uint32_t nrc1_len = 0u;
    uint8_t replay_eligible = 0u;
    uint8_t role = 0u;
    int nm30_present = 0;
    int nrc1_present = 0;
    int rc;
    if (descriptor->f.occupied == 0u ||
        descriptor->f.durable_group == 0u ||
        descriptor->f.active_accounted != 0u) {
        return NINLIL_MFDT_V1_OK;
    }
    if (descriptor->f.terminal_published != 0u) {
        return NINLIL_MFDT_V1_OK;
    }
    if (layout->header.f.terminal_count >=
            NINLIL_MFDT_V1_HOST_TERMINAL_COUNT_MAX ||
        layout->header.f.tracked_groups == 0u ||
        layout->header.f.terminal_count >=
            layout->header.f.tracked_groups) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    make_key(nm30_key, "NM30", descriptor->f.transfer_id);
    rc = ninlil_mfdt_v1_store_read(
        layout->header.f.store, nm30_key,
        layout->control_nm30, NINLIL_MFDT_V1_HOST_CONTROL_NM30_BYTES,
        &nm30_len, &nm30_present);
    if (rc != NINLIL_MFDT_V1_OK || nm30_present == 0) {
        return rc != NINLIL_MFDT_V1_OK
                   ? rc : NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    rc = ninlil_mfdt_v1_validate_nm30_recovery_record(
        layout->control_nm30, nm30_len, descriptor->f.transfer_id,
        &replay_eligible, peer, &role);
    if (rc != NINLIL_MFDT_V1_OK || replay_eligible == 0u ||
        ninlil_mfdt_v1_get_u16(layout->control_nm30 + 4) != 2u ||
        role != descriptor->f.role ||
        !ninlil_mfdt_v1_memeq(
            peer, descriptor->f.peer_endpoint_id, 16u)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    make_key(nrc1_key, "NRC1", descriptor->f.transfer_id);
    rc = ninlil_mfdt_v1_store_read(
        layout->header.f.store, nrc1_key,
        layout->control_nrc1, NINLIL_MFDT_V1_HOST_CONTROL_NRC1_BYTES,
        &nrc1_len, &nrc1_present);
    if (rc != NINLIL_MFDT_V1_OK || nrc1_present == 0 ||
        ninlil_mfdt_v1_validate_nrc1_record(
            layout->control_nrc1, nrc1_len,
            descriptor->f.transfer_id,
            descriptor->f.session_generation) != NINLIL_MFDT_V1_OK) {
        return rc != NINLIL_MFDT_V1_OK
                   ? rc : NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    ninlil_mfdt_v1_memzero(&terminal, sizeof(terminal));
    (void)memcpy(
        terminal.f.transfer_id, descriptor->f.transfer_id, 16u);
    (void)memcpy(terminal.f.peer_endpoint_id, peer, 16u);
    terminal.f.session_cookie = descriptor->f.session_cookie;
    terminal.f.session_generation =
        ninlil_mfdt_v1_get_u32(layout->control_nrc1 + 24);
    terminal.f.role = role;
    terminal.f.nm30_schema = 2u;
    terminal.f.replay_eligible = 1u;
    terminal.f.bind_valid = descriptor->f.bind_valid;
    terminal.f.occupied = 1u;
    rc = terminal_catalog_insert(layout, &terminal);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    descriptor->f.terminal_published = 1u;
    return NINLIL_MFDT_V1_OK;
}

static int descriptor_sync_runtime(
    mfdt_host_owner_layout_t *layout, uint8_t slot)
{
    mfdt_host_slot_desc_t *descriptor = &layout->slots[slot];
    ninlil_mfdt_v1_engine_t *engine = slot_engine(layout, slot);
    int rc;
    if (descriptor->f.occupied == 0u) {
        return NINLIL_MFDT_V1_OK;
    }
    descriptor->f.fulls_this_transfer = engine->fulls_this_transfer;
    descriptor->f.publication_ready = engine->publication_ready;
    descriptor->f.handoff_complete = engine->handoff_complete;
    descriptor->f.upper_dedupe_valid = engine->upper_dedupe_valid;
    (void)memcpy(
        descriptor->f.publication_token, engine->publication_token, 16u);
    (void)memcpy(
        descriptor->f.upper_dedupe_token,
        engine->upper_dedupe_token, 16u);
    if (descriptor->f.active_accounted != 0u &&
        engine->active_count == 0u) {
        descriptor->f.active_accounted = 0u;
        descriptor->f.unpaid_chunk_offer = 0u;
        if (layout->header.f.active_count != 0u) {
            layout->header.f.active_count =
                (uint8_t)(layout->header.f.active_count - 1u);
        }
    }
    rc = publish_terminal_from_slot(layout, slot);
    if (rc != NINLIL_MFDT_V1_OK &&
        descriptor->f.durable_group != 0u &&
        engine->active_count == 0u) {
        /*
         * The terminal FULL is already durable.  If its live retained-route
         * identity cannot be published exactly, no active or terminal wire
         * route may remain usable under a partial in-memory projection.
         */
        layout->header.f.inventory_uncertain = 1u;
    }
    return rc;
}

static int cleanup_terminal_slot_if_drained(
    mfdt_host_owner_layout_t *layout, uint8_t slot)
{
    ninlil_mfdt_v1_pipeline_t *pipeline = slot_pipeline(layout, slot);
    int rc = descriptor_sync_runtime(layout, slot);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    if (layout->slots[slot].f.occupied != 0u &&
        layout->slots[slot].f.active_accounted == 0u &&
        pipeline->outbox_valid == 0u) {
        return reset_slot(layout, slot);
    }
    return NINLIL_MFDT_V1_OK;
}

static int response_from_outbox(
    const ninlil_mfdt_v1_pipeline_t *pipeline,
    ninlil_mfdt_v1_response_t *response)
{
    uint8_t type = 0u;
    uint32_t request_id = 0u;
    uint32_t generation = 0u;
    uint64_t cookie = 0ull;
    const uint8_t *body = NULL;
    uint16_t body_len = 0u;
    int rc;
    if (response == NULL) {
        return NINLIL_MFDT_V1_OK;
    }
    ninlil_mfdt_v1_memzero(response, sizeof(*response));
    if (pipeline->last_ingress_response_valid == 0u) {
        return NINLIL_MFDT_V1_OK;
    }
    if (pipeline->outbox_valid == 0u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    rc = ninlil_mfdt_v1_ncl1_decode(
        pipeline->outbox, pipeline->outbox_len,
        NINLIL_MFDT_V1_NCG1_DATA, &type, &request_id, &generation,
        &cookie, &body, &body_len);
    if (rc != NINLIL_MFDT_V1_OK || body_len > sizeof(response->body)) {
        return rc != NINLIL_MFDT_V1_OK
                   ? rc : NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    response->message_type = type;
    response->body_len = body_len;
    (void)memcpy(response->body, body, body_len);
    if ((type == NINLIL_MFDT_V1_MSG_REJECT ||
         type == NINLIL_MFDT_V1_MSG_BUSY) &&
        body_len == 60u) {
        response->reject_code = ninlil_mfdt_v1_get_u16(body + 54);
    }
    response->full_count =
        pipeline->last_ingress_response_full_count;
    response->state_mutation =
        pipeline->last_ingress_response_state_mutation;
    response->from_nrc1_hit =
        pipeline->last_ingress_response_from_nrc1_hit;
    return NINLIL_MFDT_V1_OK;
}

static uint16_t request_stage(uint8_t message_type)
{
    switch (message_type) {
    case NINLIL_MFDT_V1_MSG_OPEN:
        return 1u;
    case NINLIL_MFDT_V1_MSG_MANIFEST_PAGE:
        return 2u;
    case NINLIL_MFDT_V1_MSG_CHUNK_OFFER:
        return 3u;
    case NINLIL_MFDT_V1_MSG_FINALIZE:
        return 4u;
    case NINLIL_MFDT_V1_MSG_RESUME_QUERY:
        return 5u;
    case NINLIL_MFDT_V1_MSG_ABORT:
        return 6u;
    default:
        return 0u;
    }
}

static void response_bind_from_open(
    const uint8_t *open_body, uint8_t bind52[52])
{
    (void)memcpy(bind52, open_body, 16u);
    (void)memcpy(bind52 + 16, open_body + 16, 4u);
    (void)memcpy(bind52 + 20, open_body + 202, 32u);
}

static void response_bind_from_nm30(
    const uint8_t *nm30, uint8_t bind52[52])
{
    (void)memcpy(bind52, nm30 + 8, 52u);
}

static void fill_bound_reject(
    const uint8_t bind52[52], uint16_t stage, uint16_t reject_code,
    ninlil_mfdt_v1_response_t *response)
{
    ninlil_mfdt_v1_memzero(response, sizeof(*response));
    (void)memcpy(response->body, bind52, 52u);
    ninlil_mfdt_v1_put_u16(response->body + 52, stage);
    ninlil_mfdt_v1_put_u16(response->body + 54, reject_code);
    ninlil_mfdt_v1_put_u32(response->body + 56, 0u);
    response->message_type = NINLIL_MFDT_V1_MSG_REJECT;
    response->reject_code = reject_code;
    response->body_len = 60u;
}

static void fill_bound_busy(
    const uint8_t bind52[52], uint16_t stage,
    ninlil_mfdt_v1_response_t *response)
{
    ninlil_mfdt_v1_memzero(response, sizeof(*response));
    (void)memcpy(response->body, bind52, 52u);
    ninlil_mfdt_v1_put_u16(response->body + 52, stage);
    ninlil_mfdt_v1_put_u16(response->body + 54, 0u);
    ninlil_mfdt_v1_put_u32(response->body + 56, 0u);
    response->message_type = NINLIL_MFDT_V1_MSG_BUSY;
    response->reject_code = NINLIL_MFDT_V1_REJ_CAPACITY;
    response->body_len = 60u;
}

static int control_outbox_publish(
    mfdt_host_owner_layout_t *layout,
    const ninlil_mfdt_v1_host_bind_t *bind,
    const ninlil_mfdt_v1_wire_view_t *wire,
    const ninlil_mfdt_v1_response_t *exact,
    ninlil_mfdt_v1_response_t *response_out,
    uint8_t *slot_out)
{
    mfdt_host_control_meta_t metadata;
    size_t frame_length = 0u;
    int rc;
    if (layout == NULL || !bind_is_valid(bind) || wire == NULL ||
        exact == NULL || exact->body_len == 0u ||
        exact->body_len > sizeof(exact->body)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (layout->control_meta.f.owned != 0u) {
        return NINLIL_MFDT_V1_ERR_BUSY;
    }
    rc = ninlil_mfdt_v1_ncl1_encode(
        exact->message_type, (uint32_t)wire->request_id,
        bind->session_generation, bind->session_cookie,
        exact->body, exact->body_len, layout->control_outbox,
        sizeof(layout->control_outbox), &frame_length);
    if (rc != NINLIL_MFDT_V1_OK) {
        ninlil_mfdt_v1_memzero(
            layout->control_outbox, sizeof(layout->control_outbox));
        return rc;
    }
    ninlil_mfdt_v1_memzero(&metadata, sizeof(metadata));
    metadata.f.session_cookie = bind->session_cookie;
    (void)memcpy(
        metadata.f.peer_endpoint_id, bind->peer_endpoint_id, 16u);
    metadata.f.session_generation = bind->session_generation;
    metadata.f.frame_length = (uint16_t)frame_length;
    metadata.f.route = NINLIL_MFDT_V1_HOST_CONTROL_ROUTE;
    metadata.f.role = bind->role;
    metadata.f.owned = 1u;
    layout->control_meta = metadata;
    if (response_out != NULL) {
        *response_out = *exact;
    }
    if (slot_out != NULL) {
        *slot_out = NINLIL_MFDT_V1_HOST_CONTROL_ROUTE;
    }
    return NINLIL_MFDT_V1_OK;
}

static int terminal_request_bind_matches(
    const uint8_t nm30[NINLIL_MFDT_V1_NM30_BYTES],
    const ninlil_mfdt_v1_wire_view_t *wire)
{
    if (wire->message_type == NINLIL_MFDT_V1_MSG_OPEN) {
        return wire->body_len >= NINLIL_MFDT_V1_OPEN_BODY_MIN &&
               !bytes_zero(wire->body, 16u) &&
               ninlil_mfdt_v1_get_u32(wire->body + 16) != 0u &&
               !bytes_zero(wire->body + 202, 32u) &&
               ninlil_mfdt_v1_memeq(wire->body, nm30 + 8, 16u) &&
               ninlil_mfdt_v1_memeq(wire->body + 16, nm30 + 24, 4u) &&
               ninlil_mfdt_v1_memeq(wire->body + 202, nm30 + 28, 32u);
    }
    return wire->body_len >= 52u &&
           ninlil_mfdt_v1_memeq(wire->body, nm30 + 8, 52u);
}

static int terminal_nm30_load_validate(
    mfdt_host_owner_layout_t *layout,
    const mfdt_host_terminal_desc_t *terminal)
{
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t peer[16];
    uint32_t length = 0u;
    uint8_t replay_eligible = 0u;
    uint8_t role = 0u;
    int present = 0;
    int rc;
    make_key(key, "NM30", terminal->f.transfer_id);
    rc = ninlil_mfdt_v1_store_read(
        layout->header.f.store, key, layout->control_nm30,
        sizeof(layout->control_nm30), &length, &present);
    if (rc != NINLIL_MFDT_V1_OK || present == 0) {
        return rc != NINLIL_MFDT_V1_OK
                   ? rc : NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    rc = ninlil_mfdt_v1_validate_nm30_recovery_record(
        layout->control_nm30, length, terminal->f.transfer_id,
        &replay_eligible, peer, &role);
    if (rc != NINLIL_MFDT_V1_OK ||
        ninlil_mfdt_v1_get_u16(layout->control_nm30 + 4) !=
            terminal->f.nm30_schema ||
        replay_eligible != terminal->f.replay_eligible ||
        role != terminal->f.role ||
        !ninlil_mfdt_v1_memeq(
            peer, terminal->f.peer_endpoint_id, 16u)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    return NINLIL_MFDT_V1_OK;
}

static int terminal_nrc1_read(
    mfdt_host_owner_layout_t *layout,
    const mfdt_host_terminal_desc_t *terminal)
{
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];
    uint32_t length = 0u;
    int present = 0;
    int rc;
    make_key(key, "NRC1", terminal->f.transfer_id);
    rc = ninlil_mfdt_v1_store_read(
        layout->header.f.store, key, layout->control_nrc1,
        sizeof(layout->control_nrc1), &length, &present);
    if (rc != NINLIL_MFDT_V1_OK || present == 0 ||
        ninlil_mfdt_v1_validate_nrc1_record(
            layout->control_nrc1, length, terminal->f.transfer_id,
            terminal->f.session_generation) != NINLIL_MFDT_V1_OK) {
        return rc != NINLIL_MFDT_V1_OK
                   ? rc : NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_host_terminal_view(
    ninlil_mfdt_v1_host_owner_t *owner,
    const uint8_t transfer_id[16],
    ninlil_mfdt_v1_host_terminal_view_t *out)
{
    mfdt_host_owner_layout_t *layout;
    const mfdt_host_terminal_desc_t *terminal;
    uint8_t open_request_digest[32];
    uint16_t index;
    uint8_t open_request_found = 0u;
    int found;
    int rc;

    if (!owner_is_valid(owner) || transfer_id == NULL || out == NULL ||
        bytes_zero(transfer_id, 16u)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_memzero(out, sizeof(*out));
    layout = owner_layout(owner);
    if (layout->header.f.started == 0u ||
        layout->header.f.recovered == 0u ||
        layout->header.f.inventory_uncertain != 0u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    found = find_terminal_by_tid(layout, transfer_id);
    if (found < 0) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    terminal = &layout->terminals[found];
    rc = terminal_nm30_load_validate(layout, terminal);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = terminal_nrc1_read(layout, terminal);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    for (index = 0u; index < NINLIL_MFDT_V1_NRC1_SLOT_COUNT; ++index) {
        const uint8_t *slot =
            layout->control_nrc1 + 40u +
            (size_t)index * NINLIL_MFDT_V1_NRC1_SLOT_BYTES;

        if (ninlil_mfdt_v1_get_u16(slot + 44u) !=
            (uint16_t)NINLIL_MFDT_V1_MSG_OPEN_ACCEPT) {
            continue;
        }
        if (open_request_found != 0u &&
            !ninlil_mfdt_v1_memeq(
                open_request_digest, slot + 12u,
                sizeof(open_request_digest))) {
            return NINLIL_MFDT_V1_ERR_CORRUPT;
        }
        (void)memcpy(
            open_request_digest, slot + 12u,
            sizeof(open_request_digest));
        open_request_found = 1u;
    }
    if (open_request_found == 0u) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    (void)memcpy(out->transfer_id, terminal->f.transfer_id, 16u);
    (void)memcpy(
        out->peer_endpoint_id, terminal->f.peer_endpoint_id, 16u);
    out->stored_session_generation = terminal->f.session_generation;
    out->transfer_revision =
        ninlil_mfdt_v1_get_u32(layout->control_nm30 + 24u);
    (void)memcpy(
        out->manifest_digest, layout->control_nm30 + 28u,
        sizeof(out->manifest_digest));
    (void)memcpy(
        out->open_request_body_digest, open_request_digest,
        sizeof(out->open_request_body_digest));
    out->terminal_state =
        ninlil_mfdt_v1_get_u16(layout->control_nm30 + 60u);
    out->terminal_reason =
        ninlil_mfdt_v1_get_u16(layout->control_nm30 + 62u);
    out->role = terminal->f.role;
    out->replay_eligible = terminal->f.replay_eligible;
    return NINLIL_MFDT_V1_OK;
}

static int terminal_on_wire(
    mfdt_host_owner_layout_t *layout,
    const mfdt_host_terminal_desc_t *terminal,
    const ninlil_mfdt_v1_host_bind_t *bind,
    const ninlil_mfdt_v1_wire_view_t *wire,
    ninlil_mfdt_v1_response_t *response,
    uint8_t *slot_out)
{
    ninlil_mfdt_v1_response_t exact;
    uint8_t request_digest[32];
    uint8_t bind52[52];
    uint8_t nrc1_key[NINLIL_MFDT_V1_KEY_BYTES];
    uint32_t nrc1_length = 0u;
    uint16_t stage;
    int rc;
    if (layout->control_meta.f.owned != 0u) {
        return NINLIL_MFDT_V1_ERR_BUSY;
    }
    if (terminal->f.replay_eligible == 0u ||
        terminal->f.nm30_schema != 2u ||
        terminal->f.bind_valid == 0u ||
        !terminal_bind_matches(terminal, bind)) {
        return NINLIL_MFDT_V1_ERR_VERSION;
    }
    if (!wire_is_request(wire->message_type)) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    stage = request_stage(wire->message_type);
    if (stage == 0u) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    rc = terminal_nm30_load_validate(layout, terminal);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    if (!terminal_request_bind_matches(layout->control_nm30, wire)) {
        return wire->body_len <
                       (wire->message_type == NINLIL_MFDT_V1_MSG_OPEN
                            ? NINLIL_MFDT_V1_OPEN_BODY_MIN : 52u)
                   ? NINLIL_MFDT_V1_ERR_LAYOUT
                   : NINLIL_MFDT_V1_ERR_VERSION;
    }
    response_bind_from_nm30(layout->control_nm30, bind52);
    ninlil_mfdt_v1_request_body_digest(
        wire->message_type, wire->body, wire->body_len, request_digest);
    rc = terminal_nrc1_read(layout, terminal);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = ninlil_mfdt_v1_nrc1_raw_find_response(
        layout->control_nrc1, NINLIL_MFDT_V1_NRC1_VALUE_BYTES,
        terminal->f.transfer_id, terminal->f.session_generation,
        wire->request_id, request_digest, &exact);
    if (rc == NINLIL_MFDT_V1_OK) {
        return control_outbox_publish(
            layout, bind, wire, &exact, response, slot_out);
    }
    if (rc == NINLIL_MFDT_V1_ERR_DIGEST) {
        fill_bound_reject(
            bind52, stage, NINLIL_MFDT_V1_REJ_DUPLICATE, &exact);
        return control_outbox_publish(
            layout, bind, wire, &exact, response, slot_out);
    }
    if (rc != NINLIL_MFDT_V1_ERR_STATE) {
        return rc;
    }
    if (ninlil_mfdt_v1_get_u16(layout->control_nrc1 + 30) >=
        NINLIL_MFDT_V1_NRC1_SLOT_COUNT) {
        fill_bound_busy(bind52, stage, &exact);
        return control_outbox_publish(
            layout, bind, wire, &exact, response, slot_out);
    }
    fill_bound_reject(
        bind52, stage, NINLIL_MFDT_V1_REJ_STATE, &exact);
    make_key(nrc1_key, "NRC1", terminal->f.transfer_id);
    rc = coordinator_full_begin(layout);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = coordinator_full_get(
        layout, nrc1_key, layout->control_nrc1,
        sizeof(layout->control_nrc1), &nrc1_length);
    if (rc == NINLIL_MFDT_V1_OK) {
        rc = ninlil_mfdt_v1_nrc1_raw_find_response(
            layout->control_nrc1, nrc1_length,
            terminal->f.transfer_id, terminal->f.session_generation,
            wire->request_id, request_digest, &exact);
    }
    if (rc == NINLIL_MFDT_V1_OK ||
        rc == NINLIL_MFDT_V1_ERR_DIGEST) {
        const int lookup_rc = rc;
        const int rollback_rc = coordinator_full_rollback(layout);
        if (rollback_rc != NINLIL_MFDT_V1_OK) {
            return rollback_rc;
        }
        if (lookup_rc == NINLIL_MFDT_V1_ERR_DIGEST) {
            fill_bound_reject(
                bind52, stage, NINLIL_MFDT_V1_REJ_DUPLICATE, &exact);
        }
        return control_outbox_publish(
            layout, bind, wire, &exact, response, slot_out);
    }
    if (rc == NINLIL_MFDT_V1_ERR_STATE) {
        fill_bound_reject(
            bind52, stage, NINLIL_MFDT_V1_REJ_STATE, &exact);
        rc = ninlil_mfdt_v1_nrc1_raw_insert_response(
            layout->control_nrc1, nrc1_length,
            terminal->f.transfer_id, terminal->f.session_generation,
            wire->request_id, request_digest, exact.message_type,
            exact.body, exact.body_len);
    }
    if (rc == NINLIL_MFDT_V1_OK) {
        rc = ninlil_mfdt_v1_store_full_put(
            layout->header.f.store, nrc1_key, layout->control_nrc1,
            NINLIL_MFDT_V1_NRC1_VALUE_BYTES);
    }
    if (rc != NINLIL_MFDT_V1_OK) {
        const int rollback_rc = coordinator_full_rollback(layout);
        if (rollback_rc != NINLIL_MFDT_V1_OK) {
            return rollback_rc;
        }
        if (rc == NINLIL_MFDT_V1_ERR_CAPACITY) {
            fill_bound_busy(bind52, stage, &exact);
            return control_outbox_publish(
                layout, bind, wire, &exact, response, slot_out);
        }
        return rc;
    }
    rc = coordinator_full_commit(layout);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    exact.from_nrc1_hit = 0u;
    exact.state_mutation = 0u;
    exact.full_count = 1u;
    return control_outbox_publish(
        layout, bind, wire, &exact, response, slot_out);
}

static void capacity_busy_response(
    const ninlil_mfdt_v1_wire_view_t *wire,
    ninlil_mfdt_v1_response_t *response)
{
    uint8_t bind52[52];
    if (wire == NULL || response == NULL || wire->body == NULL ||
        wire->body_len < NINLIL_MFDT_V1_OPEN_BODY_MIN) {
        return;
    }
    response_bind_from_open(wire->body, bind52);
    fill_bound_busy(bind52, 1u, response);
}

int ninlil_mfdt_v1_host_owner_init(
    ninlil_mfdt_v1_host_owner_t *owner,
    ninlil_mfdt_v1_store_port_t *store,
    const ninlil_mfdt_v1_config_t *base_config)
{
    mfdt_host_owner_layout_t *layout;
    ninlil_mfdt_v1_config_t config;
    ninlil_mfdt_v1_config_t admission_config;
    uint8_t slot;
    int rc;
    if (owner == NULL || store == NULL || base_config == NULL ||
        ((uintptr_t)owner & 7u) != 0u ||
        ((uintptr_t)base_config %
         (uintptr_t)_Alignof(ninlil_mfdt_v1_config_t)) != 0u ||
        ranges_overlap(owner, sizeof(*owner), store, sizeof(*store)) ||
        ranges_overlap(owner, sizeof(*owner),
                       base_config, sizeof(*base_config)) ||
        ranges_overlap(store, sizeof(*store),
                       base_config, sizeof(*base_config)) ||
        !store_port_is_usable(store)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    config = *base_config;
    config.host_mode = 1u;
    admission_config = config;
    if (admission_config.policy == NINLIL_MFDT_V1_POLICY_OFF) {
        /*
         * The Host owner remains a valid transport/control owner while fresh
         * MFDT admission is disabled.  Validate every other negotiated
         * prerequisite with a temporary ON view, but retain OFF in the owner
         * so a safe fresh OPEN receives the stateless UNSUPPORTED refusal.
         */
        admission_config.policy = NINLIL_MFDT_V1_POLICY_ON;
    }
    rc = ninlil_mfdt_v1_admission_check(&admission_config);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    ninlil_mfdt_v1_memzero(owner, sizeof(*owner));
    layout = owner_layout(owner);
    layout->header.f.store = store;
    layout->header.f.base_config = config;
    layout->header.f.now_ms = config.now_ms;
    layout->header.f.magic = MFDT_HOST_MAGIC;
    for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
        rc = initialize_slot_runtime(layout, slot, &config);
        if (rc != NINLIL_MFDT_V1_OK) {
            ninlil_mfdt_v1_memzero(owner, sizeof(*owner));
            return rc;
        }
    }
    return NINLIL_MFDT_V1_OK;
}

static int group_find_or_add(
    mfdt_host_group_summary_t groups[16], uint8_t *group_count,
    const uint8_t transfer_id[16])
{
    uint8_t index;
    for (index = 0u; index < *group_count; ++index) {
        if (ninlil_mfdt_v1_memeq(
                groups[index].transfer_id, transfer_id, 16u)) {
            return (int)index;
        }
    }
    if (*group_count >= 16u) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    index = *group_count;
    ninlil_mfdt_v1_memzero(&groups[index], sizeof(groups[index]));
    (void)memcpy(groups[index].transfer_id, transfer_id, 16u);
    groups[index].capture_slot = 0xffu;
    *group_count = (uint8_t)(*group_count + 1u);
    return (int)index;
}

static int tid_compare(const uint8_t left[16], const uint8_t right[16])
{
    size_t index;
    for (index = 0u; index < 16u; ++index) {
        if (left[index] < right[index]) {
            return -1;
        }
        if (left[index] > right[index]) {
            return 1;
        }
    }
    return 0;
}

static int key_compare(
    const uint8_t left[NINLIL_MFDT_V1_KEY_BYTES],
    const uint8_t right[NINLIL_MFDT_V1_KEY_BYTES])
{
    size_t index;
    for (index = 0u; index < NINLIL_MFDT_V1_KEY_BYTES; ++index) {
        if (left[index] < right[index]) {
            return -1;
        }
        if (left[index] > right[index]) {
            return 1;
        }
    }
    return 0;
}

static void swap_bytes(uint8_t *left, uint8_t *right, size_t length)
{
    size_t index;
    for (index = 0u; index < length; ++index) {
        const uint8_t byte = left[index];
        left[index] = right[index];
        right[index] = byte;
    }
}

static int recovery_zero_candidate(mfdt_host_owner_layout_t *layout)
{
    uint8_t slot;
    int rc;
    if (layout == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    layout->header.f.active_count = 0u;
    layout->header.f.next_slot = 0u;
    layout->header.f.committed_keys = 0u;
    layout->header.f.committed_logical_bytes = 0u;
    layout->header.f.tracked_groups = 0u;
    layout->header.f.started = 0u;
    layout->header.f.recovered = 0u;
    layout->header.f.inventory_uncertain = 0u;
    layout->header.f.terminal_count = 0u;
    ninlil_mfdt_v1_memzero(
        layout->terminals, sizeof(layout->terminals));
    ninlil_mfdt_v1_memzero(
        &layout->control_meta, sizeof(layout->control_meta));
    ninlil_mfdt_v1_memzero(
        layout->control_outbox, sizeof(layout->control_outbox));
    ninlil_mfdt_v1_memzero(
        layout->control_nrc1, sizeof(layout->control_nrc1));
    ninlil_mfdt_v1_memzero(
        layout->control_nm30, sizeof(layout->control_nm30));
    ninlil_mfdt_v1_memzero(
        layout->control_reserved, sizeof(layout->control_reserved));
    for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
        rc = reset_slot(layout, slot);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc;
        }
    }
    return NINLIL_MFDT_V1_OK;
}

static void bind_slot_engine_for_recovery(
    mfdt_host_owner_layout_t *layout, uint8_t slot,
    const ninlil_mfdt_v1_config_t *config)
{
    mfdt_host_slot_arena_t *arena = &layout->arenas[slot];
    ninlil_mfdt_v1_engine_t *engine = slot_engine(layout, slot);
    ninlil_mfdt_v1_memzero(engine, sizeof(*engine));
    engine->cfg = *config;
    engine->cfg.host_mode = 1u;
    engine->store_port = layout->header.f.store;
    engine->slot_record_memory = arena->f.active_record;
    engine->slot_nrc1_memory = arena->f.nrc1;
    engine->slot_xfer_memory = arena->f.temporary;
    engine->slot_open_staging =
        arena->f.temporary + MFDT_HOST_XFER_REGION_BYTES;
    engine->slot_entries_staging =
        arena->f.temporary + MFDT_HOST_XFER_REGION_BYTES +
        MFDT_HOST_OPEN_REGION_BYTES;
    engine->host_committed_keys =
        &layout->header.f.committed_keys;
    engine->host_committed_logical_bytes =
        &layout->header.f.committed_logical_bytes;
    engine->host_full_locked = &layout->header.f.full_locked;
    engine->host_inventory_uncertain =
        &layout->header.f.inventory_uncertain;
    engine->slot_layout = 1u;
}

int ninlil_mfdt_v1_host_owner_recover(
    ninlil_mfdt_v1_host_owner_t *owner)
{
    mfdt_host_owner_layout_t *layout;
    mfdt_host_group_summary_t groups[16];
    uint8_t active_indices[NINLIL_MFDT_V1_HOST_SLOT_COUNT];
    uint8_t terminal_indices[NINLIL_MFDT_V1_HOST_TERMINAL_COUNT_MAX];
    ninlil_mfdt_v1_store_snapshot_t snapshot;
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t previous_key[NINLIL_MFDT_V1_KEY_BYTES];
    uint32_t value_len = 0u;
    uint64_t committed_bytes = 0ull;
    uint32_t committed_keys = 0u;
    uint8_t group_count = 0u;
    uint8_t active_count = 0u;
    uint8_t terminal_count = 0u;
    uint8_t captured_count = 0u;
    uint8_t have_previous_key = 0u;
    int done = 0;
    int rc;
    uint8_t index;
    if (!owner_is_valid(owner)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    layout = owner_layout(owner);
    if (layout->header.f.full_locked != 0u ||
        layout->header.f.started != 0u) {
        return NINLIL_MFDT_V1_ERR_BUSY;
    }
    rc = recovery_zero_candidate(layout);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    ninlil_mfdt_v1_memzero(groups, sizeof(groups));
    ninlil_mfdt_v1_memzero(active_indices, sizeof(active_indices));
    ninlil_mfdt_v1_memzero(terminal_indices, sizeof(terminal_indices));
    ninlil_mfdt_v1_memzero(previous_key, sizeof(previous_key));
    rc = ninlil_mfdt_v1_store_snapshot_begin(
        layout->header.f.store, NULL, 0u, &snapshot);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    while (!done) {
        uint8_t *value;
        uint32_t value_cap;
        int group_index;
        mfdt_host_group_summary_t *group;
        uint8_t kind_flag;
        uint8_t role = 0u;
        uint32_t session_generation = 0u;
        uint8_t peer[16];
        if (captured_count < NINLIL_MFDT_V1_HOST_SLOT_COUNT) {
            value =
                layout->arenas[captured_count].f.active_record;
            value_cap =
                (uint32_t)NINLIL_MFDT_V1_HOST_ACTIVE_REGION_BYTES;
        } else {
            /*
             * Strict key order means only NRC1 rows remain after four active
             * rows.  Pipeline+engine+temporary is one 15528-byte recovery
             * scratch region and is rebuilt before any slot is published.
             */
            value = layout->arenas[0].f.pipeline;
            value_cap = (uint32_t)(
                NINLIL_MFDT_V1_HOST_PIPELINE_REGION_BYTES +
                NINLIL_MFDT_V1_HOST_ENGINE_REGION_BYTES +
                NINLIL_MFDT_V1_HOST_TEMP_REGION_BYTES);
        }
        rc = ninlil_mfdt_v1_store_snapshot_next(
            &snapshot, key, value, value_cap, &value_len, &done);
        if (rc != NINLIL_MFDT_V1_OK || done) {
            if (rc == NINLIL_MFDT_V1_ERR_CAPACITY &&
                captured_count >=
                    NINLIL_MFDT_V1_HOST_SLOT_COUNT) {
                rc = NINLIL_MFDT_V1_ERR_CAPACITY;
            }
            break;
        }
        if (have_previous_key != 0u &&
            key_compare(previous_key, key) >= 0) {
            rc = NINLIL_MFDT_V1_ERR_CORRUPT;
            break;
        }
        (void)memcpy(previous_key, key, sizeof(previous_key));
        have_previous_key = 1u;
        if (bytes_zero(key + 4, 16u)) {
            rc = NINLIL_MFDT_V1_ERR_CORRUPT;
            break;
        }
        if (ninlil_mfdt_v1_memeq(key, "NM3S", 4u)) {
            kind_flag = MFDT_GROUP_SENDER;
            role = NINLIL_MFDT_V1_HOST_ROLE_SENDER;
        } else if (ninlil_mfdt_v1_memeq(key, "NM3R", 4u)) {
            kind_flag = MFDT_GROUP_RECEIVER;
            role = NINLIL_MFDT_V1_HOST_ROLE_RECEIVER;
        } else if (ninlil_mfdt_v1_memeq(key, "NM30", 4u)) {
            kind_flag = MFDT_GROUP_TERMINAL;
        } else if (ninlil_mfdt_v1_memeq(key, "NRC1", 4u)) {
            kind_flag = MFDT_GROUP_NRC1;
        } else {
            rc = NINLIL_MFDT_V1_ERR_CORRUPT;
            break;
        }
        group_index = group_find_or_add(
            groups, &group_count, key + 4);
        if (group_index < 0) {
            rc = group_index;
            break;
        }
        group = &groups[group_index];
        if ((group->flags & kind_flag) != 0u) {
            rc = NINLIL_MFDT_V1_ERR_CORRUPT;
            break;
        }
        if (role != 0u) {
            ninlil_mfdt_v1_memzero(peer, sizeof(peer));
            rc = ninlil_mfdt_v1_validate_active_record(
                value, value_len, key + 4, role, &session_generation, peer);
            if (rc != NINLIL_MFDT_V1_OK ||
                !ninlil_mfdt_v1_memeq(
                    value + 200,
                    layout->header.f.base_config.local_clock_epoch.bytes,
                    16u)) {
                rc = NINLIL_MFDT_V1_ERR_CORRUPT;
                break;
            }
            group->role = role;
            group->session_generation = session_generation;
            group->active_value_len = value_len;
            (void)memcpy(group->peer_endpoint_id, peer, 16u);
            if (group->capture_slot != 0xffu ||
                captured_count >= NINLIL_MFDT_V1_HOST_SLOT_COUNT) {
                rc = captured_count >= NINLIL_MFDT_V1_HOST_SLOT_COUNT
                         ? NINLIL_MFDT_V1_ERR_CAPACITY
                         : NINLIL_MFDT_V1_ERR_CORRUPT;
                break;
            }
            group->capture_slot = captured_count;
            captured_count = (uint8_t)(captured_count + 1u);
        } else if (kind_flag == MFDT_GROUP_TERMINAL) {
            uint8_t replay_eligible = 0u;
            uint8_t terminal_role = 0u;
            ninlil_mfdt_v1_memzero(peer, sizeof(peer));
            rc = ninlil_mfdt_v1_validate_nm30_recovery_record(
                value, value_len, key + 4, &replay_eligible,
                peer, &terminal_role);
            if (rc != NINLIL_MFDT_V1_OK) {
                break;
            }
            group->nm30_schema =
                (uint8_t)ninlil_mfdt_v1_get_u16(value + 4);
            group->replay_eligible = replay_eligible;
            group->role = terminal_role;
            (void)memcpy(group->peer_endpoint_id, peer, 16u);
        } else {
            if (value_len < 28u) {
                rc = NINLIL_MFDT_V1_ERR_CORRUPT;
                break;
            }
            session_generation = ninlil_mfdt_v1_get_u32(value + 24);
            rc = ninlil_mfdt_v1_validate_nrc1_record(
                value, value_len, key + 4, session_generation);
            if (rc != NINLIL_MFDT_V1_OK) {
                break;
            }
            group->nrc1_session_generation = session_generation;
            if ((group->flags &
                 (MFDT_GROUP_SENDER | MFDT_GROUP_RECEIVER)) != 0u) {
                if (group->capture_slot >=
                    NINLIL_MFDT_V1_HOST_SLOT_COUNT) {
                    rc = NINLIL_MFDT_V1_ERR_CORRUPT;
                    break;
                }
                (void)memcpy(
                    layout->arenas[group->capture_slot].f.nrc1,
                    value, value_len);
                group->nrc1_captured = 1u;
            }
        }
        group->flags = (uint8_t)(group->flags | kind_flag);
        if (committed_keys >= NINLIL_MFDT_V1_HOST_COMMITTED_KEYS_MAX ||
            committed_bytes >
                NINLIL_MFDT_V1_HOST_COMMITTED_LOGICAL_BYTES_MAX -
                    ((uint64_t)value_len +
                     NINLIL_MFDT_V1_STORE_ROW_LOGICAL_FIXED_BYTES)) {
            rc = NINLIL_MFDT_V1_ERR_CAPACITY;
            break;
        }
        committed_keys += 1u;
        committed_bytes +=
            (uint64_t)value_len +
            NINLIL_MFDT_V1_STORE_ROW_LOGICAL_FIXED_BYTES;
    }
    {
        const int end_rc =
            ninlil_mfdt_v1_store_snapshot_end(&snapshot);
        if (rc == NINLIL_MFDT_V1_OK &&
            end_rc != NINLIL_MFDT_V1_OK) {
            rc = end_rc;
        }
    }
    if (rc != NINLIL_MFDT_V1_OK) {
        (void)recovery_zero_candidate(layout);
        return rc;
    }
    for (index = 0u; index < group_count; ++index) {
        const uint8_t active_flags =
            (uint8_t)(groups[index].flags &
                      (MFDT_GROUP_SENDER | MFDT_GROUP_RECEIVER));
        if (active_flags != 0u) {
            if ((active_flags != MFDT_GROUP_SENDER &&
                 active_flags != MFDT_GROUP_RECEIVER) ||
                (groups[index].flags &
                 (MFDT_GROUP_TERMINAL | MFDT_GROUP_NRC1)) !=
                    MFDT_GROUP_NRC1 ||
                groups[index].nrc1_captured == 0u ||
                groups[index].session_generation !=
                    groups[index].nrc1_session_generation ||
                active_count >= NINLIL_MFDT_V1_HOST_SLOT_COUNT) {
                rc = active_count >=
                             NINLIL_MFDT_V1_HOST_SLOT_COUNT
                         ? NINLIL_MFDT_V1_ERR_CAPACITY
                         : NINLIL_MFDT_V1_ERR_CORRUPT;
                (void)recovery_zero_candidate(layout);
                return rc;
            }
            active_indices[active_count++] = index;
        } else if (groups[index].flags !=
                   (MFDT_GROUP_TERMINAL | MFDT_GROUP_NRC1)) {
            (void)recovery_zero_candidate(layout);
            return NINLIL_MFDT_V1_ERR_CORRUPT;
        } else {
            if ((groups[index].nm30_schema == 2u &&
                 (groups[index].replay_eligible == 0u ||
                  (groups[index].role !=
                       NINLIL_MFDT_V1_HOST_ROLE_SENDER &&
                   groups[index].role !=
                       NINLIL_MFDT_V1_HOST_ROLE_RECEIVER) ||
                  bytes_zero(groups[index].peer_endpoint_id, 16u))) ||
                (groups[index].nm30_schema == 1u &&
                 (groups[index].replay_eligible != 0u ||
                  groups[index].role != 0u ||
                  !bytes_zero(
                      groups[index].peer_endpoint_id, 16u))) ||
                (groups[index].nm30_schema != 1u &&
                 groups[index].nm30_schema != 2u) ||
                terminal_count >=
                    NINLIL_MFDT_V1_HOST_TERMINAL_COUNT_MAX) {
                (void)recovery_zero_candidate(layout);
                return NINLIL_MFDT_V1_ERR_CORRUPT;
            }
            terminal_indices[terminal_count++] = index;
        }
    }
    /*
     * Policy OFF is a valid Host control-owner state for an empty or wholly
     * retained-terminal inventory, but rollback forbids carrying an active
     * transfer across that policy boundary.
     */
    if (active_count != 0u &&
        layout->header.f.base_config.policy !=
            NINLIL_MFDT_V1_POLICY_ON) {
        (void)recovery_zero_candidate(layout);
        return NINLIL_MFDT_V1_ERR_POLICY_OFF;
    }
    for (index = 0u; index < active_count; ++index) {
        uint8_t other;
        uint8_t smallest = index;
        for (other = (uint8_t)(index + 1u);
             other < active_count; ++other) {
            if (tid_compare(
                    groups[active_indices[other]].transfer_id,
                    groups[active_indices[smallest]].transfer_id) < 0) {
                smallest = other;
            }
        }
        if (smallest != index) {
            const uint8_t temporary = active_indices[index];
            active_indices[index] = active_indices[smallest];
            active_indices[smallest] = temporary;
        }
    }
    for (index = 0u; index < terminal_count; ++index) {
        uint8_t other;
        uint8_t smallest = index;
        for (other = (uint8_t)(index + 1u);
             other < terminal_count; ++other) {
            if (tid_compare(
                    groups[terminal_indices[other]].transfer_id,
                    groups[terminal_indices[smallest]].transfer_id) < 0) {
                smallest = other;
            }
        }
        if (smallest != index) {
            const uint8_t temporary = terminal_indices[index];
            terminal_indices[index] = terminal_indices[smallest];
            terminal_indices[smallest] = temporary;
        }
    }
    /* Canonicalize both captured rows in-place without a large stack frame. */
    for (index = 0u; index < active_count; ++index) {
        mfdt_host_group_summary_t *selected =
            &groups[active_indices[index]];
        const uint8_t source = selected->capture_slot;
        if (source != index) {
            uint8_t group_index;
            swap_bytes(
                layout->arenas[index].f.active_record,
                layout->arenas[source].f.active_record,
                NINLIL_MFDT_V1_HOST_ACTIVE_REGION_BYTES);
            swap_bytes(
                layout->arenas[index].f.nrc1,
                layout->arenas[source].f.nrc1,
                NINLIL_MFDT_V1_HOST_NRC1_REGION_BYTES);
            for (group_index = 0u; group_index < group_count;
                 ++group_index) {
                if (groups[group_index].capture_slot == index) {
                    groups[group_index].capture_slot = source;
                    break;
                }
            }
            selected->capture_slot = index;
        }
    }
    for (index = 0u; index < active_count; ++index) {
        const mfdt_host_group_summary_t *group =
            &groups[active_indices[index]];
        ninlil_mfdt_v1_config_t config =
            layout->header.f.base_config;
        ninlil_mfdt_v1_engine_t *engine;
        config.session_generation = group->session_generation;
        config.now_ms = layout->header.f.now_ms;
        engine = slot_engine(layout, index);
        bind_slot_engine_for_recovery(
            layout, index, &config);
        rc = ninlil_mfdt_v1_engine_rehydrate_captured(
            engine, layout->arenas[index].f.active_record,
            group->active_value_len,
            layout->arenas[index].f.nrc1,
            NINLIL_MFDT_V1_NRC1_VALUE_BYTES, &config);
        if (rc != NINLIL_MFDT_V1_OK || engine->active_count != 1u ||
            engine->durable_active_value_len !=
                group->active_value_len) {
            rc = rc != NINLIL_MFDT_V1_OK
                     ? rc : NINLIL_MFDT_V1_ERR_CORRUPT;
            break;
        }
        {
            ninlil_mfdt_v1_active_snapshot_t active;

            rc = ninlil_mfdt_v1_engine_active_snapshot(engine, &active);
            if (rc != NINLIL_MFDT_V1_OK ||
                active.record_generation > UINT32_MAX) {
                rc = rc != NINLIL_MFDT_V1_OK
                         ? rc : NINLIL_MFDT_V1_ERR_CORRUPT;
                break;
            }
            /* record_generation is exact +1 per semantic active FULL. */
            engine->fulls_this_transfer =
                (uint32_t)active.record_generation;
        }
    }
    for (index = active_count;
         rc == NINLIL_MFDT_V1_OK &&
         index < NINLIL_MFDT_V1_HOST_SLOT_COUNT;
         ++index) {
        rc = reset_slot(layout, index);
    }
    if (rc != NINLIL_MFDT_V1_OK) {
        (void)recovery_zero_candidate(layout);
        return rc;
    }
    /* Publish routing descriptors only after every captured row rehydrates. */
    for (index = 0u; index < active_count; ++index) {
        const mfdt_host_group_summary_t *group =
            &groups[active_indices[index]];
        ninlil_mfdt_v1_engine_t *engine =
            slot_engine(layout, index);
        (void)memcpy(
            layout->slots[index].f.transfer_id,
            group->transfer_id, 16u);
        (void)memcpy(
            layout->slots[index].f.peer_endpoint_id,
            group->peer_endpoint_id, 16u);
        layout->slots[index].f.session_generation =
            group->session_generation;
        layout->slots[index].f.role = group->role;
        layout->slots[index].f.occupied = 1u;
        layout->slots[index].f.bind_valid = 0u;
        layout->slots[index].f.active_accounted = 1u;
        layout->slots[index].f.durable_group = 1u;
        layout->slots[index].f.fulls_this_transfer =
            engine->fulls_this_transfer;
        ninlil_mfdt_v1_pipeline_init(
            slot_pipeline(layout, index), NULL, NULL, NULL, NULL,
            group->session_generation, 0ull);
    }
    for (index = 0u; index < terminal_count; ++index) {
        const mfdt_host_group_summary_t *group =
            &groups[terminal_indices[index]];
        mfdt_host_terminal_desc_t terminal;
        ninlil_mfdt_v1_memzero(&terminal, sizeof(terminal));
        (void)memcpy(
            terminal.f.transfer_id, group->transfer_id, 16u);
        (void)memcpy(
            terminal.f.peer_endpoint_id,
            group->peer_endpoint_id, 16u);
        terminal.f.session_generation =
            group->nrc1_session_generation;
        terminal.f.role = group->role;
        terminal.f.nm30_schema = group->nm30_schema;
        terminal.f.replay_eligible = group->replay_eligible;
        terminal.f.occupied = 1u;
        rc = terminal_catalog_insert(layout, &terminal);
        if (rc != NINLIL_MFDT_V1_OK) {
            (void)recovery_zero_candidate(layout);
            return rc;
        }
    }
    layout->header.f.active_count = active_count;
    layout->header.f.next_slot = 0u;
    layout->header.f.committed_keys = committed_keys;
    layout->header.f.committed_logical_bytes = committed_bytes;
    layout->header.f.tracked_groups = group_count;
    layout->header.f.inventory_uncertain = 0u;
    layout->header.f.recovered = 1u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_host_owner_start(
    ninlil_mfdt_v1_host_owner_t *owner)
{
    mfdt_host_owner_layout_t *layout;
    if (!owner_is_valid(owner)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    layout = owner_layout(owner);
    if (layout->header.f.recovered == 0u ||
        layout->header.f.full_locked != 0u ||
        layout->header.f.inventory_uncertain != 0u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    layout->header.f.started = 1u;
    return NINLIL_MFDT_V1_OK;
}

static int recovered_open_matches_expectation(
    const uint8_t *open,
    uint16_t open_len,
    const uint8_t *entries,
    uint16_t entry_bytes,
    const uint8_t *content,
    uint32_t content_len,
    const ninlil_mfdt_v1_host_sender_expectation_t *expected,
    uint8_t *scratch,
    uint32_t scratch_capacity)
{
    const uint32_t entries_capacity =
        (uint32_t)NINLIL_MFDT_V1_MAX_CHUNKS *
        NINLIL_MFDT_V1_ENTRY_BYTES;
    const uint32_t required =
        NINLIL_MFDT_V1_OPEN_BODY_MAX + entries_capacity;
    uint8_t manifest[32];
    uint8_t whole[32];
    uint16_t encoded_open_len = 0u;
    uint16_t encoded_entry_bytes = 0u;
    int rc;

    if (open == NULL || entries == NULL || content == NULL ||
        expected == NULL || scratch == NULL ||
        scratch_capacity < required ||
        expected->content_length != content_len) {
        return 0;
    }
    rc = ninlil_mfdt_v1_encode_open(
        expected->transfer_id,
        content_len,
        content,
        &expected->metadata,
        scratch,
        &encoded_open_len,
        scratch + NINLIL_MFDT_V1_OPEN_BODY_MAX,
        &encoded_entry_bytes,
        manifest,
        whole);
    return rc == NINLIL_MFDT_V1_OK &&
        encoded_open_len == open_len &&
        encoded_entry_bytes == entry_bytes &&
        ninlil_mfdt_v1_memeq(
            whole, expected->content_digest, sizeof(whole)) &&
        ninlil_mfdt_v1_memeq(scratch, open, open_len) &&
        ninlil_mfdt_v1_memeq(
            scratch + NINLIL_MFDT_V1_OPEN_BODY_MAX,
            entries,
            entry_bytes);
}

int ninlil_mfdt_v1_host_recovered_sender_view(
    const ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot,
    const ninlil_mfdt_v1_host_sender_expectation_t *expected,
    uint8_t *scratch,
    uint32_t scratch_capacity,
    ninlil_mfdt_v1_host_recovered_sender_view_t *out)
{
    const mfdt_host_owner_layout_t *layout;
    const mfdt_host_slot_desc_t *descriptor;
    const ninlil_mfdt_v1_engine_t *engine;
    const ninlil_mfdt_v1_pipeline_t *pipeline;
    ninlil_mfdt_v1_active_snapshot_t active;
    const uint8_t *open = NULL;
    const uint8_t *entries = NULL;
    const uint8_t *content = NULL;
    uint16_t open_len = 0u;
    uint16_t entry_bytes = 0u;
    uint32_t content_len = 0u;
    uint8_t role = 0u;
    uint8_t transfer_id[16];
    uint8_t peer[16];
    uint32_t stored_generation = 0u;
    int rc;

    if (!owner_is_valid(owner) || out == NULL || scratch == NULL ||
        scratch_capacity < NINLIL_MFDT_V1_OPEN_BODY_MAX +
            (uint32_t)NINLIL_MFDT_V1_MAX_CHUNKS *
                NINLIL_MFDT_V1_ENTRY_BYTES ||
        ranges_overlap(scratch, scratch_capacity, owner, sizeof(*owner)) ||
        slot >= NINLIL_MFDT_V1_HOST_SLOT_COUNT) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_memzero(out, sizeof(*out));
    layout = owner_layout_const(owner);
    descriptor = &layout->slots[slot];
    engine = slot_engine_const(layout, slot);
    pipeline = slot_pipeline_const(layout, slot);
    if (layout->header.f.started == 0u ||
        layout->header.f.recovered == 0u ||
        layout->header.f.inventory_uncertain != 0u ||
        descriptor->f.occupied == 0u ||
        descriptor->f.terminal_published != 0u ||
        descriptor->f.role != NINLIL_MFDT_V1_HOST_ROLE_SENDER ||
        descriptor->f.bind_valid != 0u ||
        descriptor->f.session_cookie != 0ull ||
        descriptor->f.active_accounted != 1u ||
        descriptor->f.durable_group != 1u ||
        engine->slot_layout != 1u ||
        engine->slot_record_packed != 1u ||
        engine->active_count != 1u ||
        pipeline->tx != NULL || pipeline->rx != NULL ||
        pipeline->outbox_valid != 0u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    rc = ninlil_mfdt_v1_record_unpack(
        engine->slot_record_memory,
        engine->durable_active_value_len,
        &role,
        NULL,
        transfer_id,
        NULL,
        NULL,
        &open,
        &open_len,
        &entries,
        &entry_bytes,
        &content,
        &content_len,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);
    if (rc != NINLIL_MFDT_V1_OK ||
        role != NINLIL_MFDT_V1_HOST_ROLE_SENDER ||
        content == NULL || open_len < 80u ||
        !ninlil_mfdt_v1_memeq(
            transfer_id, descriptor->f.transfer_id, 16u) ||
        ninlil_mfdt_v1_validate_active_record(
            engine->slot_record_memory,
            engine->durable_active_value_len,
            transfer_id,
            NINLIL_MFDT_V1_HOST_ROLE_SENDER,
            &stored_generation,
            peer) != NINLIL_MFDT_V1_OK ||
        stored_generation != descriptor->f.session_generation ||
        !ninlil_mfdt_v1_memeq(
            peer, descriptor->f.peer_endpoint_id, 16u) ||
        ninlil_mfdt_v1_validate_nrc1_record(
            engine->slot_nrc1_memory,
            NINLIL_MFDT_V1_NRC1_VALUE_BYTES,
            transfer_id,
            stored_generation) != NINLIL_MFDT_V1_OK ||
        ninlil_mfdt_v1_engine_active_snapshot(engine, &active) !=
            NINLIL_MFDT_V1_OK) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (expected != NULL &&
        (!recovered_open_matches_expectation(
             open, open_len, entries, entry_bytes, content, content_len,
             expected, scratch, scratch_capacity) ||
         !ninlil_mfdt_v1_memeq(
             expected->transfer_id, transfer_id, 16u))) {
        return NINLIL_MFDT_V1_ERR_VERSION;
    }
    (void)memcpy(out->transfer_id, transfer_id, 16u);
    (void)memcpy(out->origin_transaction_id, open + 64u, 16u);
    (void)memcpy(out->peer_endpoint_id, peer, 16u);
    out->stored_session_generation = stored_generation;
    out->slot = slot;
    out->state_code = active.state_code;
    out->fresh_open_arm =
        active.state_code == NINLIL_MFDT_V1_S_OPEN_PENDING &&
        active.record_generation == 1ull &&
        active.acceptance_record_generation == 0ull &&
        active.page_bitmap == 0u && active.chunk_bitmap == 0ull &&
        active.publication_state == 0u &&
        engine->fulls_this_transfer == 1u &&
        descriptor->f.fulls_this_transfer == 1u &&
        ninlil_mfdt_v1_get_u16(engine->slot_nrc1_memory + 30u) == 0u &&
        ninlil_mfdt_v1_get_u32(engine->slot_nrc1_memory + 32u) == 0u
            ? 1u : 0u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_host_receiver_ready_view(
    const ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot,
    ninlil_mfdt_v1_host_receiver_ready_view_t *out)
{
    const mfdt_host_owner_layout_t *layout;
    const mfdt_host_slot_desc_t *descriptor;
    const ninlil_mfdt_v1_engine_t *engine;
    ninlil_mfdt_v1_active_snapshot_t active;
    const uint8_t *open = NULL;
    const uint8_t *entries = NULL;
    const uint8_t *content = NULL;
    uint16_t open_len = 0u;
    uint16_t entry_bytes = 0u;
    uint32_t content_len = 0u;
    uint32_t stored_generation = 0u;
    uint8_t role = 0u;
    uint8_t state_code = 0u;
    uint8_t transfer_id[16];
    uint8_t peer[16];
    uint8_t publication_state = 0u;
    uint8_t handoff_state = 0u;
    int rc;

    if (!owner_is_valid(owner) || out == NULL ||
        slot >= NINLIL_MFDT_V1_HOST_SLOT_COUNT) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_memzero(out, sizeof(*out));
    layout = owner_layout_const(owner);
    descriptor = &layout->slots[slot];
    engine = slot_engine_const(layout, slot);
    if (layout->header.f.started == 0u ||
        layout->header.f.recovered == 0u ||
        layout->header.f.inventory_uncertain != 0u ||
        descriptor->f.occupied == 0u ||
        descriptor->f.terminal_published != 0u ||
        descriptor->f.role != NINLIL_MFDT_V1_HOST_ROLE_RECEIVER ||
        descriptor->f.active_accounted != 1u ||
        descriptor->f.durable_group != 1u ||
        engine->slot_layout != 1u ||
        engine->slot_record_packed != 1u ||
        engine->active_count != 1u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    rc = ninlil_mfdt_v1_record_unpack(
        engine->slot_record_memory,
        engine->durable_active_value_len,
        &role,
        &state_code,
        transfer_id,
        NULL,
        NULL,
        &open,
        &open_len,
        &entries,
        &entry_bytes,
        &content,
        &content_len,
        NULL,
        NULL,
        NULL,
        NULL,
        &publication_state,
        &handoff_state);
    if (rc != NINLIL_MFDT_V1_OK ||
        role != NINLIL_MFDT_V1_HOST_ROLE_RECEIVER ||
        open == NULL || entries == NULL || content == NULL ||
        !ninlil_mfdt_v1_memeq(
            transfer_id, descriptor->f.transfer_id, 16u) ||
        ninlil_mfdt_v1_validate_active_record(
            engine->slot_record_memory,
            engine->durable_active_value_len,
            transfer_id,
            NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
            &stored_generation,
            peer) != NINLIL_MFDT_V1_OK ||
        stored_generation != descriptor->f.session_generation ||
        !ninlil_mfdt_v1_memeq(
            peer, descriptor->f.peer_endpoint_id, 16u) ||
        ninlil_mfdt_v1_validate_nrc1_record(
            engine->slot_nrc1_memory,
            NINLIL_MFDT_V1_NRC1_VALUE_BYTES,
            transfer_id,
            stored_generation) != NINLIL_MFDT_V1_OK) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (!(((state_code == NINLIL_MFDT_V1_R_CONTENT_VERIFIED ||
            state_code == NINLIL_MFDT_V1_R_ACCEPT_NOTIFIED) &&
           publication_state == 1u && handoff_state == 0u) ||
          (state_code == NINLIL_MFDT_V1_R_HANDED_OFF &&
           publication_state == 2u && handoff_state == 1u))) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (ninlil_mfdt_v1_validate_open(
            open, open_len, entries, entry_bytes,
            content, content_len, 1u) != NINLIL_MFDT_V1_OK ||
        ninlil_mfdt_v1_engine_active_snapshot(engine, &active) !=
            NINLIL_MFDT_V1_OK ||
        active.role != NINLIL_MFDT_V1_HOST_ROLE_RECEIVER ||
        active.state_code != state_code ||
        active.publication_state != publication_state ||
        active.acceptance_record_generation == 0ull ||
        bytes_zero(active.publication_token, 16u) ||
        (handoff_state == 0u
             ? !bytes_zero(active.publication_evidence_digest, 32u)
             : bytes_zero(active.publication_evidence_digest, 32u)) ||
        !ninlil_mfdt_v1_memeq(
            active.transfer_id, transfer_id, 16u)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    out->open_body = open;
    out->content = content;
    out->open_body_length = open_len;
    out->content_length = content_len;
    (void)memcpy(out->transfer_id, transfer_id, 16u);
    (void)memcpy(out->peer_endpoint_id, peer, 16u);
    (void)memcpy(
        out->publication_token, active.publication_token, 16u);
    out->acceptance_generation =
        active.acceptance_record_generation;
    out->stored_session_generation = stored_generation;
    out->slot = slot;
    out->state_code = state_code;
    out->publication_state = publication_state;
    out->handoff_state = handoff_state;
    (void)memcpy(
        out->publication_evidence_digest,
        active.publication_evidence_digest,
        32u);
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_host_rebind_recovered(
    ninlil_mfdt_v1_host_owner_t *owner,
    const uint8_t transfer_id[16],
    const ninlil_mfdt_v1_host_bind_t *bind)
{
    mfdt_host_owner_layout_t *layout;
    mfdt_host_slot_desc_t *descriptor;
    ninlil_mfdt_v1_pipeline_t *pipeline;
    ninlil_mfdt_v1_engine_t *engine;
    int slot;
    int terminal_index;
    int rc;
    if (!owner_is_valid(owner) || transfer_id == NULL ||
        bytes_zero(transfer_id, 16u) || !bind_is_valid(bind)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    layout = owner_layout(owner);
    if (layout->header.f.started == 0u ||
        layout->header.f.inventory_uncertain != 0u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    slot = find_slot_by_tid(layout, transfer_id);
    terminal_index = find_terminal_by_tid(layout, transfer_id);
    if (slot >= 0 && terminal_index >= 0) {
        layout->header.f.inventory_uncertain = 1u;
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (slot < 0) {
        mfdt_host_terminal_desc_t *terminal;
        if (terminal_index < 0) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        terminal = &layout->terminals[terminal_index];
        if (terminal->f.replay_eligible == 0u ||
            terminal->f.nm30_schema != 2u) {
            return NINLIL_MFDT_V1_ERR_VERSION;
        }
        if (terminal->f.role != bind->role ||
            terminal->f.session_generation != bind->session_generation ||
            !ninlil_mfdt_v1_memeq(
                terminal->f.peer_endpoint_id,
                bind->peer_endpoint_id, 16u)) {
            return NINLIL_MFDT_V1_ERR_VERSION;
        }
        if (terminal->f.bind_valid != 0u) {
            return terminal_bind_matches(terminal, bind)
                       ? NINLIL_MFDT_V1_OK
                       : NINLIL_MFDT_V1_ERR_VERSION;
        }
        terminal->f.session_cookie = bind->session_cookie;
        terminal->f.bind_valid = 1u;
        return NINLIL_MFDT_V1_OK;
    }
    descriptor = &layout->slots[slot];
    if (descriptor->f.role != bind->role ||
        descriptor->f.session_generation != bind->session_generation ||
        !ninlil_mfdt_v1_memeq(
            descriptor->f.peer_endpoint_id,
            bind->peer_endpoint_id, 16u)) {
        return NINLIL_MFDT_V1_ERR_VERSION;
    }
    if (descriptor->f.bind_valid != 0u) {
        return descriptor_bind_matches(descriptor, bind)
                   ? NINLIL_MFDT_V1_OK
                   : NINLIL_MFDT_V1_ERR_VERSION;
    }
    pipeline = slot_pipeline(layout, (uint8_t)slot);
    engine = slot_engine(layout, (uint8_t)slot);
    if (bind->role == NINLIL_MFDT_V1_HOST_ROLE_SENDER) {
        rc = ninlil_mfdt_v1_pipeline_sender_rehydrate(
            pipeline, engine, transfer_id, bind->session_generation,
            bind->session_cookie);
    } else {
        ninlil_mfdt_v1_pipeline_init(
            pipeline, NULL, engine, NULL, NULL,
            bind->session_generation, bind->session_cookie);
        rc = NINLIL_MFDT_V1_OK;
    }
    if (rc != NINLIL_MFDT_V1_OK) {
        ninlil_mfdt_v1_pipeline_init(
            pipeline, NULL, NULL, NULL, NULL,
            bind->session_generation, 0ull);
        return rc;
    }
    descriptor->f.session_cookie = bind->session_cookie;
    descriptor->f.bind_valid = 1u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_host_sender_open_with_metadata(
    ninlil_mfdt_v1_host_owner_t *owner,
    const ninlil_mfdt_v1_host_bind_t *bind,
    const uint8_t transfer_id[16],
    const uint8_t *content,
    uint32_t content_len,
    const ninlil_mfdt_v1_open_metadata_t *metadata,
    uint64_t request_id,
    uint8_t *slot_out)
{
    mfdt_host_owner_layout_t *layout;
    ninlil_mfdt_v1_config_t config;
    ninlil_mfdt_v1_pipeline_t *pipeline;
    int slot;
    int existing;
    int rc;
    if (!owner_is_valid(owner) || !bind_is_valid(bind) ||
        bind->role != NINLIL_MFDT_V1_HOST_ROLE_SENDER ||
        transfer_id == NULL || bytes_zero(transfer_id, 16u) ||
        metadata == NULL || slot_out == NULL ||
        request_id == 0ull || request_id > UINT32_MAX ||
        (content_len != 0u && content == NULL)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    layout = owner_layout(owner);
    if (layout->header.f.started == 0u ||
        layout->header.f.recovered == 0u ||
        layout->header.f.inventory_uncertain != 0u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    existing = find_slot_by_tid(layout, transfer_id);
    if (existing >= 0) {
        return descriptor_bind_matches(
                   &layout->slots[existing], bind)
                   ? NINLIL_MFDT_V1_ERR_BUSY
                   : NINLIL_MFDT_V1_ERR_VERSION;
    }
    rc = admission_preflight(layout, transfer_id);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    slot = find_lowest_free_slot(layout);
    config = layout->header.f.base_config;
    config.session_generation = bind->session_generation;
    config.now_ms = layout->header.f.now_ms;
    rc = initialize_slot_runtime(layout, (uint8_t)slot, &config);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    pipeline = slot_pipeline(layout, (uint8_t)slot);
    ninlil_mfdt_v1_pipeline_init(
        pipeline, slot_engine(layout, (uint8_t)slot), NULL, NULL, NULL,
        bind->session_generation, bind->session_cookie);
    pipeline->next_request_id = request_id;
    rc = ninlil_mfdt_v1_pipeline_sender_begin_with_metadata(
        pipeline, transfer_id, content, content_len, metadata);
    if (rc != NINLIL_MFDT_V1_OK) {
        (void)reset_slot(layout, (uint8_t)slot);
        return rc;
    }
    descriptor_publish(
        layout, (uint8_t)slot, transfer_id, bind);
    *slot_out = (uint8_t)slot;
    return NINLIL_MFDT_V1_OK;
}

static int fresh_sender_disarm_shape_is_exact(
    const mfdt_host_owner_layout_t *layout,
    uint8_t slot,
    const uint8_t transfer_id[16])
{
    const mfdt_host_slot_desc_t *descriptor = &layout->slots[slot];
    const mfdt_host_slot_arena_t *arena = &layout->arenas[slot];
    const ninlil_mfdt_v1_engine_t *engine =
        slot_engine_const(layout, slot);
    const ninlil_mfdt_v1_pipeline_t *pipeline =
        slot_pipeline_const(layout, slot);
    const uint8_t *record = engine->slot_record_memory;
    const uint8_t *nrc1 = engine->slot_nrc1_memory;
    ninlil_mfdt_v1_active_snapshot_t active;
    uint8_t record_peer[16];
    uint32_t record_session_generation = 0u;

    if (descriptor->f.occupied == 0u ||
        descriptor->f.terminal_published != 0u ||
        descriptor->f.role != NINLIL_MFDT_V1_HOST_ROLE_SENDER ||
        descriptor->f.bind_valid == 0u ||
        descriptor->f.session_generation == 0u ||
        descriptor->f.session_cookie == 0ull ||
        bytes_zero(descriptor->f.peer_endpoint_id, 16u) ||
        descriptor->f.active_accounted != 1u ||
        descriptor->f.durable_group != 1u ||
        descriptor->f.fulls_this_transfer != 1u ||
        descriptor->f.unpaid_chunk_offer != 0u ||
        descriptor->f.publication_ready != 0u ||
        descriptor->f.handoff_complete != 0u ||
        descriptor->f.upper_dedupe_valid != 0u ||
        !ninlil_mfdt_v1_memeq(
            descriptor->f.transfer_id, transfer_id, 16u) ||
        engine->slot_layout != 1u ||
        engine->slot_record_packed != 1u ||
        engine->active_count != 1u ||
        engine->fulls_this_transfer != 1u ||
        engine->durable_active_value_len <
            NINLIL_MFDT_V1_ACTIVE_HEADER_BYTES + 4u ||
        engine->durable_active_value_len >
            NINLIL_MFDT_V1_ACTIVE_VALUE_MAX ||
        engine->publication_ready != 0u ||
        engine->handoff_complete != 0u ||
        engine->unpaid_chunk_offer != 0u ||
        engine->upper_dedupe_valid != 0u ||
        record != arena->f.active_record ||
        nrc1 != arena->f.nrc1 ||
        engine->slot_xfer_memory != arena->f.temporary ||
        pipeline->tx != engine || pipeline->rx != NULL ||
        pipeline->complete != 0u || pipeline->aborted != 0u ||
        pipeline->phase != NINLIL_MFDT_V1_PHASE_WAIT_OPEN_ACC ||
        pipeline->outbox_valid != 1u || pipeline->outbox_len == 0u ||
        pipeline->outbox_len > sizeof(pipeline->outbox) ||
        pipeline->has_outstanding != 1u ||
        pipeline->outstanding_type != NINLIL_MFDT_V1_MSG_OPEN ||
        pipeline->outstanding_index != 0u ||
        pipeline->outstanding_rid == 0ull ||
        pipeline->next_page != 0u || pipeline->next_chunk != 0u ||
        !ninlil_mfdt_v1_memeq(
            pipeline->transfer_id, transfer_id, 16u)) {
        return 0;
    }
    if (ninlil_mfdt_v1_engine_active_snapshot(engine, &active) !=
            NINLIL_MFDT_V1_OK ||
        active.role != NINLIL_MFDT_V1_HOST_ROLE_SENDER ||
        active.state_code != NINLIL_MFDT_V1_S_OPEN_PENDING ||
        active.record_generation != 1ull ||
        active.acceptance_record_generation != 0ull ||
        active.page_bitmap != 0u || active.chunk_bitmap != 0ull ||
        active.publication_state != 0u ||
        !ninlil_mfdt_v1_memeq(active.transfer_id, transfer_id, 16u) ||
        ninlil_mfdt_v1_validate_active_record(
            record, engine->durable_active_value_len, transfer_id,
            NINLIL_MFDT_V1_HOST_ROLE_SENDER,
            &record_session_generation, record_peer) !=
                NINLIL_MFDT_V1_OK ||
        record_session_generation != descriptor->f.session_generation ||
        !ninlil_mfdt_v1_memeq(
            record_peer, descriptor->f.peer_endpoint_id, 16u) ||
        ninlil_mfdt_v1_validate_nrc1_record(
            nrc1, NINLIL_MFDT_V1_NRC1_VALUE_BYTES, transfer_id,
            descriptor->f.session_generation) != NINLIL_MFDT_V1_OK ||
        ninlil_mfdt_v1_get_u16(nrc1 + 30u) != 0u ||
        ninlil_mfdt_v1_get_u32(nrc1 + 32u) != 0u) {
        return 0;
    }
    return 1;
}

static int disarm_fresh_sender_rows(
    mfdt_host_owner_layout_t *layout,
    uint8_t slot,
    const uint8_t transfer_id[16],
    uint8_t *scratch,
    uint32_t scratch_capacity)
{
    ninlil_mfdt_v1_engine_t *engine;
    uint8_t active_key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t nrc1_key[NINLIL_MFDT_V1_KEY_BYTES];
    uint32_t current_len = 0u;
    uint32_t active_len;
    uint64_t logical_charge;
    int rc;

    engine = slot_engine(layout, slot);
    active_len = engine->durable_active_value_len;
    logical_charge = (uint64_t)active_len +
        NINLIL_MFDT_V1_NRC1_VALUE_BYTES +
        2u * NINLIL_MFDT_V1_STORE_ROW_LOGICAL_FIXED_BYTES;
    if (layout->header.f.committed_keys < 2u ||
        layout->header.f.committed_logical_bytes < logical_charge ||
        layout->header.f.tracked_groups == 0u ||
        layout->header.f.active_count == 0u) {
        layout->header.f.inventory_uncertain = 1u;
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }

    make_key(active_key, "NM3S", transfer_id);
    make_key(nrc1_key, "NRC1", transfer_id);
    rc = coordinator_full_begin(layout);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = coordinator_full_get(
        layout, active_key, scratch, scratch_capacity, &current_len);
    if (rc == NINLIL_MFDT_V1_OK &&
        (current_len != active_len ||
         !ninlil_mfdt_v1_memeq(
             scratch, engine->slot_record_memory, active_len))) {
        rc = NINLIL_MFDT_V1_ERR_BUSY;
    }
    if (rc == NINLIL_MFDT_V1_OK) {
        rc = coordinator_full_get(
            layout, nrc1_key, scratch, scratch_capacity, &current_len);
    }
    if (rc == NINLIL_MFDT_V1_OK &&
        (current_len != NINLIL_MFDT_V1_NRC1_VALUE_BYTES ||
         !ninlil_mfdt_v1_memeq(
             scratch, engine->slot_nrc1_memory,
             NINLIL_MFDT_V1_NRC1_VALUE_BYTES))) {
        rc = NINLIL_MFDT_V1_ERR_BUSY;
    }
    if (rc == NINLIL_MFDT_V1_OK) {
        rc = ninlil_mfdt_v1_store_full_erase(
            layout->header.f.store, active_key);
    }
    if (rc == NINLIL_MFDT_V1_OK) {
        rc = ninlil_mfdt_v1_store_full_erase(
            layout->header.f.store, nrc1_key);
    }
    if (rc != NINLIL_MFDT_V1_OK) {
        const int rollback_rc = coordinator_full_rollback(layout);
        return rollback_rc != NINLIL_MFDT_V1_OK ? rollback_rc : rc;
    }
    rc = coordinator_full_commit(layout);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }

    layout->header.f.committed_keys -= 2u;
    layout->header.f.committed_logical_bytes -= logical_charge;
    layout->header.f.tracked_groups -= 1u;
    layout->header.f.active_count =
        (uint8_t)(layout->header.f.active_count - 1u);
    rc = reset_slot(layout, slot);
    if (rc != NINLIL_MFDT_V1_OK) {
        layout->header.f.inventory_uncertain = 1u;
        return rc;
    }
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_host_disarm_fresh_sender(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot,
    const uint8_t transfer_id[16],
    uint8_t *scratch,
    uint32_t scratch_capacity)
{
    mfdt_host_owner_layout_t *layout;

    if (!owner_is_valid(owner) || transfer_id == NULL || scratch == NULL ||
        bytes_zero(transfer_id, 16u) ||
        slot >= NINLIL_MFDT_V1_HOST_SLOT_COUNT ||
        scratch_capacity < NINLIL_MFDT_V1_ACTIVE_VALUE_MAX ||
        ranges_overlap(scratch, scratch_capacity, owner, sizeof(*owner)) ||
        ranges_overlap(scratch, scratch_capacity, transfer_id, 16u)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    layout = owner_layout(owner);
    if (ranges_overlap(
            scratch,
            scratch_capacity,
            layout->header.f.store,
            sizeof(*layout->header.f.store))) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (layout->header.f.started == 0u ||
        layout->header.f.recovered == 0u ||
        layout->header.f.inventory_uncertain != 0u ||
        !fresh_sender_disarm_shape_is_exact(layout, slot, transfer_id)) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    return disarm_fresh_sender_rows(
        layout, slot, transfer_id, scratch, scratch_capacity);
}

int ninlil_mfdt_v1_host_disarm_recovered_fresh_sender(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot,
    const uint8_t transfer_id[16],
    uint8_t *scratch,
    uint32_t scratch_capacity)
{
    mfdt_host_owner_layout_t *layout;
    ninlil_mfdt_v1_host_recovered_sender_view_t view;
    int rc;

    if (!owner_is_valid(owner) || transfer_id == NULL || scratch == NULL ||
        bytes_zero(transfer_id, 16u) ||
        slot >= NINLIL_MFDT_V1_HOST_SLOT_COUNT ||
        scratch_capacity < NINLIL_MFDT_V1_ACTIVE_VALUE_MAX ||
        ranges_overlap(scratch, scratch_capacity, owner, sizeof(*owner)) ||
        ranges_overlap(scratch, scratch_capacity, transfer_id, 16u)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    layout = owner_layout(owner);
    if (ranges_overlap(
            scratch,
            scratch_capacity,
            layout->header.f.store,
            sizeof(*layout->header.f.store))) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    rc = ninlil_mfdt_v1_host_recovered_sender_view(
        owner, slot, NULL, scratch, scratch_capacity, &view);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    if (view.fresh_open_arm == 0u ||
        !ninlil_mfdt_v1_memeq(view.transfer_id, transfer_id, 16u)) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    return disarm_fresh_sender_rows(
        layout, slot, transfer_id, scratch, scratch_capacity);
}

static int wire_is_request(uint8_t type)
{
    return type == NINLIL_MFDT_V1_MSG_OPEN ||
           type == NINLIL_MFDT_V1_MSG_MANIFEST_PAGE ||
           type == NINLIL_MFDT_V1_MSG_CHUNK_OFFER ||
           type == NINLIL_MFDT_V1_MSG_RESUME_QUERY ||
           type == NINLIL_MFDT_V1_MSG_FINALIZE ||
           type == NINLIL_MFDT_V1_MSG_ABORT;
}

static int wire_is_response(uint8_t type)
{
    return type == NINLIL_MFDT_V1_MSG_OPEN_ACCEPT ||
           type == NINLIL_MFDT_V1_MSG_PAGE_ACCEPT ||
           type == NINLIL_MFDT_V1_MSG_REJECT ||
           type == NINLIL_MFDT_V1_MSG_BUSY ||
           type == NINLIL_MFDT_V1_MSG_CHUNK_ACCEPT ||
           type == NINLIL_MFDT_V1_MSG_RESUME_STATE ||
           type == NINLIL_MFDT_V1_MSG_TRANSFER_ACCEPT ||
           type == NINLIL_MFDT_V1_MSG_ABORT_ACK;
}

int ninlil_mfdt_v1_host_on_wire(
    ninlil_mfdt_v1_host_owner_t *owner,
    const ninlil_mfdt_v1_host_bind_t *bind,
    const ninlil_mfdt_v1_wire_view_t *wire,
    ninlil_mfdt_v1_response_t *response,
    uint8_t *slot_out)
{
    mfdt_host_owner_layout_t *layout;
    ninlil_mfdt_v1_pipeline_t *pipeline;
    ninlil_mfdt_v1_engine_t *engine;
    ninlil_mfdt_v1_config_t config;
    ninlil_mfdt_v1_response_t exact;
    uint8_t ncl1[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    size_t ncl1_len = 0u;
    int fresh = 0;
    int ingress_called = 0;
    int slot;
    int terminal_index;
    int rc;
    if (!owner_is_valid(owner) || !bind_is_valid(bind) || wire == NULL ||
        wire->body == NULL ||
        wire->request_id == 0ull || wire->request_id > UINT32_MAX ||
        !ninlil_mfdt_v1_ncl1_is_transfer_type(wire->message_type)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (response != NULL) {
        ninlil_mfdt_v1_memzero(response, sizeof(*response));
    }
    if (wire->body_len < 16u) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    layout = owner_layout(owner);
    if (layout->header.f.started == 0u ||
        layout->header.f.recovered == 0u ||
        layout->header.f.inventory_uncertain != 0u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    slot = find_slot_by_tid(layout, wire->body);
    terminal_index = find_terminal_by_tid(layout, wire->body);
    if (slot >= 0 && terminal_index >= 0) {
        layout->header.f.inventory_uncertain = 1u;
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (terminal_index >= 0) {
        return terminal_on_wire(
            layout, &layout->terminals[terminal_index], bind, wire,
            response, slot_out);
    }
    if (slot < 0) {
        if (wire->message_type != NINLIL_MFDT_V1_MSG_OPEN ||
            bind->role != NINLIL_MFDT_V1_HOST_ROLE_RECEIVER) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        if (wire->body_len < NINLIL_MFDT_V1_OPEN_BODY_MIN) {
            return NINLIL_MFDT_V1_ERR_PARAM;
        }
        if (layout->control_meta.f.owned != 0u) {
            return NINLIL_MFDT_V1_ERR_BUSY;
        }
        config = layout->header.f.base_config;
        config.session_generation = bind->session_generation;
        config.now_ms = layout->header.f.now_ms;
        rc = ninlil_mfdt_v1_fresh_open_precheck(
            &config, wire->body, wire->body_len, &exact);
        if (rc != NINLIL_MFDT_V1_OK) {
            if (exact.body_len == 0u) {
                return rc;
            }
            return control_outbox_publish(
                layout, bind, wire, &exact, response, slot_out);
        }
        rc = admission_preflight(layout, wire->body);
        if (rc != NINLIL_MFDT_V1_OK) {
            if (rc == NINLIL_MFDT_V1_ERR_CAPACITY) {
                ninlil_mfdt_v1_memzero(&exact, sizeof(exact));
                capacity_busy_response(wire, &exact);
                if (exact.body_len == 0u) {
                    return NINLIL_MFDT_V1_ERR_LAYOUT;
                }
                return control_outbox_publish(
                    layout, bind, wire, &exact, response, slot_out);
            }
            return rc;
        }
        slot = find_lowest_free_slot(layout);
        fresh = 1;
        rc = initialize_slot_runtime(layout, (uint8_t)slot, &config);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc;
        }
        ninlil_mfdt_v1_pipeline_init(
            slot_pipeline(layout, (uint8_t)slot), NULL,
            slot_engine(layout, (uint8_t)slot), NULL, NULL,
            bind->session_generation, bind->session_cookie);
    } else {
        if ((bind->role == NINLIL_MFDT_V1_HOST_ROLE_RECEIVER &&
             !wire_is_request(wire->message_type)) ||
            (bind->role == NINLIL_MFDT_V1_HOST_ROLE_SENDER &&
             !wire_is_response(wire->message_type))) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        if (!descriptor_bind_matches(&layout->slots[slot], bind)) {
            return NINLIL_MFDT_V1_ERR_VERSION;
        }
        if (layout->slots[slot].f.bind_valid == 0u) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
    }
    pipeline = slot_pipeline(layout, (uint8_t)slot);
    engine = slot_engine(layout, (uint8_t)slot);
    rc = ninlil_mfdt_v1_ncl1_encode(
        wire->message_type, (uint32_t)wire->request_id,
        bind->session_generation, bind->session_cookie,
        wire->body, wire->body_len, ncl1, sizeof(ncl1), &ncl1_len);
    if (rc == NINLIL_MFDT_V1_OK) {
        ingress_called = 1;
        rc = ninlil_mfdt_v1_pipeline_on_ncl1_ingress(
            pipeline, ncl1, ncl1_len);
    }
    if (rc != NINLIL_MFDT_V1_OK) {
        if (ingress_called != 0 &&
            wire_is_request(wire->message_type) &&
            pipeline->last_ingress_response_valid != 0u) {
            ninlil_mfdt_v1_response_t discarded_response;
            const int response_rc =
                response_from_outbox(
                    pipeline,
                    response != NULL ? response : &discarded_response);
            if (response_rc == NINLIL_MFDT_V1_OK) {
                if (fresh != 0) {
                    layout->header.f.inventory_uncertain = 1u;
                    (void)reset_slot(layout, (uint8_t)slot);
                    if (response != NULL) {
                        ninlil_mfdt_v1_memzero(
                            response, sizeof(*response));
                    }
                    return NINLIL_MFDT_V1_ERR_CORRUPT;
                } else {
                    rc = descriptor_sync_runtime(
                        layout, (uint8_t)slot);
                    if (rc != NINLIL_MFDT_V1_OK) {
                        return rc;
                    }
                }
                if (slot_out != NULL) {
                    *slot_out = (uint8_t)slot;
                }
                /*
                 * Transport processing succeeded: the protocol outcome is
                 * carried by the exact REJECT/BUSY body, not by this return
                 * code.  Only an unformed/unowned response returns semantic
                 * or internal failure below.
                 */
                return NINLIL_MFDT_V1_OK;
            }
            rc = response_rc;
        }
        if (fresh != 0) {
            (void)reset_slot(layout, (uint8_t)slot);
        } else {
            const int sync_rc =
                descriptor_sync_runtime(layout, (uint8_t)slot);
            if (sync_rc != NINLIL_MFDT_V1_OK) {
                return sync_rc;
            }
        }
        return rc;
    }
    if (fresh != 0) {
        descriptor_publish(
            layout, (uint8_t)slot, wire->body, bind);
    }
    if (wire->message_type == NINLIL_MFDT_V1_MSG_CHUNK_ACCEPT) {
        layout->slots[slot].f.unpaid_chunk_offer = 0u;
    } else if (pipeline->last_chunk_fence_released != 0u) {
        layout->slots[slot].f.unpaid_chunk_offer = 0u;
        engine->unpaid_chunk_offer = 0u;
    }
    if (wire->message_type == NINLIL_MFDT_V1_MSG_TRANSFER_ACCEPT &&
        pipeline->complete != 0u) {
        rc = ninlil_mfdt_v1_pipeline_finish_terminal(pipeline);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc;
        }
    }
    if (wire_is_request(wire->message_type)) {
        rc = response_from_outbox(pipeline, response);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc;
        }
    }
    rc = descriptor_sync_runtime(layout, (uint8_t)slot);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    if (slot_out != NULL) {
        *slot_out = (uint8_t)slot;
    }
    if (!wire_is_request(wire->message_type) &&
        pipeline->outbox_valid == 0u) {
        return cleanup_terminal_slot_if_drained(
            layout, (uint8_t)slot);
    }
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_host_pump_control(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot)
{
    mfdt_host_owner_layout_t *layout;
    int rc;
    if (!owner_is_valid(owner) ||
        slot >= NINLIL_MFDT_V1_HOST_SLOT_COUNT) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    layout = owner_layout(owner);
    if (layout->header.f.started == 0u ||
        layout->header.f.inventory_uncertain != 0u ||
        layout->slots[slot].f.occupied == 0u ||
        layout->slots[slot].f.terminal_published != 0u ||
        layout->slots[slot].f.bind_valid == 0u ||
        layout->slots[slot].f.role !=
            NINLIL_MFDT_V1_HOST_ROLE_SENDER) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    rc = ninlil_mfdt_v1_pipeline_pump_control(
        slot_pipeline(layout, slot));
    {
        const int sync_rc = descriptor_sync_runtime(layout, slot);
        if (sync_rc != NINLIL_MFDT_V1_OK) {
            return sync_rc;
        }
    }
    return rc;
}

static int peer_has_unpaid(
    const mfdt_host_owner_layout_t *layout,
    const uint8_t peer_endpoint_id[16])
{
    uint8_t slot;
    for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
        if (layout->slots[slot].f.occupied != 0u &&
            layout->slots[slot].f.unpaid_chunk_offer != 0u &&
            ninlil_mfdt_v1_memeq(
                layout->slots[slot].f.peer_endpoint_id,
                peer_endpoint_id, 16u)) {
            return 1;
        }
    }
    return 0;
}

int ninlil_mfdt_v1_host_schedule_one_chunk(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t *selected_slot_out)
{
    mfdt_host_owner_layout_t *layout;
    uint8_t offset;
    if (!owner_is_valid(owner) || selected_slot_out == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    layout = owner_layout(owner);
    *selected_slot_out = 0xffu;
    if (layout->header.f.started == 0u ||
        layout->header.f.inventory_uncertain != 0u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    for (offset = 0u; offset < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++offset) {
        const uint8_t slot =
            (uint8_t)((layout->header.f.next_slot + offset) %
                      NINLIL_MFDT_V1_HOST_SLOT_COUNT);
        mfdt_host_slot_desc_t *descriptor = &layout->slots[slot];
        ninlil_mfdt_v1_pipeline_t *pipeline =
            slot_pipeline(layout, slot);
        int rc;
        if (descriptor->f.occupied == 0u ||
            descriptor->f.terminal_published != 0u ||
            descriptor->f.bind_valid == 0u ||
            descriptor->f.role != NINLIL_MFDT_V1_HOST_ROLE_SENDER ||
            ninlil_mfdt_v1_pipeline_next_action(pipeline) !=
                NINLIL_MFDT_V1_PIPE_ACTION_CHUNK ||
            peer_has_unpaid(layout, descriptor->f.peer_endpoint_id)) {
            continue;
        }
        rc = ninlil_mfdt_v1_pipeline_emit_selected_chunk(pipeline);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc;
        }
        descriptor->f.unpaid_chunk_offer = 1u;
        layout->header.f.next_slot =
            (uint8_t)((slot + 1u) %
                      NINLIL_MFDT_V1_HOST_SLOT_COUNT);
        *selected_slot_out = slot;
        rc = descriptor_sync_runtime(layout, slot);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc;
        }
        return NINLIL_MFDT_V1_OK;
    }
    return NINLIL_MFDT_V1_ERR_BUSY;
}

int ninlil_mfdt_v1_host_peek_outbound_ncl1(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot,
    const uint8_t **out,
    size_t *out_len)
{
    mfdt_host_owner_layout_t *layout;
    ninlil_mfdt_v1_pipeline_t *pipeline;

    if (!owner_is_valid(owner) || out == NULL || out_len == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    *out = NULL;
    *out_len = 0u;
    layout = owner_layout(owner);
    if (layout->header.f.started == 0u
        || layout->header.f.inventory_uncertain != 0u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (slot == NINLIL_MFDT_V1_HOST_CONTROL_ROUTE) {
        const uint16_t frame_length = layout->control_meta.f.frame_length;
        if (layout->control_meta.f.owned == 0u) {
            return NINLIL_MFDT_V1_OK;
        }
        if (layout->control_meta.f.route
                != NINLIL_MFDT_V1_HOST_CONTROL_ROUTE
            || frame_length == 0u
            || frame_length > sizeof(layout->control_outbox)) {
            layout->header.f.inventory_uncertain = 1u;
            return NINLIL_MFDT_V1_ERR_CORRUPT;
        }
        *out = layout->control_outbox;
        *out_len = frame_length;
        return NINLIL_MFDT_V1_OK;
    }
    if (slot >= NINLIL_MFDT_V1_HOST_SLOT_COUNT
        || layout->slots[slot].f.occupied == 0u
        || layout->slots[slot].f.bind_valid == 0u) {
        return slot >= NINLIL_MFDT_V1_HOST_SLOT_COUNT
            ? NINLIL_MFDT_V1_ERR_PARAM : NINLIL_MFDT_V1_ERR_STATE;
    }
    pipeline = slot_pipeline(layout, slot);
    if (pipeline->outbox_valid == 0u) {
        return NINLIL_MFDT_V1_OK;
    }
    if (pipeline->outbox_len == 0u
        || pipeline->outbox_len > sizeof(pipeline->outbox)) {
        layout->header.f.inventory_uncertain = 1u;
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    *out = pipeline->outbox;
    *out_len = pipeline->outbox_len;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_host_take_outbound_ncl1(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot,
    uint8_t *out,
    size_t cap,
    size_t *out_len)
{
    mfdt_host_owner_layout_t *layout;
    int rc;
    if (!owner_is_valid(owner) || out_len == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    layout = owner_layout(owner);
    if (slot == NINLIL_MFDT_V1_HOST_CONTROL_ROUTE) {
        const uint16_t frame_length =
            layout->control_meta.f.frame_length;
        if (layout->header.f.started == 0u ||
            layout->header.f.inventory_uncertain != 0u) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        if (layout->control_meta.f.owned == 0u) {
            *out_len = 0u;
            return NINLIL_MFDT_V1_OK;
        }
        if (layout->control_meta.f.route !=
                NINLIL_MFDT_V1_HOST_CONTROL_ROUTE ||
            frame_length == 0u ||
            frame_length > sizeof(layout->control_outbox)) {
            layout->header.f.inventory_uncertain = 1u;
            return NINLIL_MFDT_V1_ERR_CORRUPT;
        }
        if (out == NULL || cap < frame_length) {
            return NINLIL_MFDT_V1_ERR_CAPACITY;
        }
        (void)memcpy(out, layout->control_outbox, frame_length);
        *out_len = frame_length;
        ninlil_mfdt_v1_memzero(
            layout->control_outbox, sizeof(layout->control_outbox));
        ninlil_mfdt_v1_memzero(
            &layout->control_meta, sizeof(layout->control_meta));
        return NINLIL_MFDT_V1_OK;
    }
    if (slot >= NINLIL_MFDT_V1_HOST_SLOT_COUNT) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (layout->header.f.started == 0u ||
        layout->header.f.inventory_uncertain != 0u ||
        layout->slots[slot].f.occupied == 0u ||
        layout->slots[slot].f.bind_valid == 0u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    rc = ninlil_mfdt_v1_pipeline_take_outbound(
        slot_pipeline(layout, slot), out, cap, out_len);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    return cleanup_terminal_slot_if_drained(layout, slot);
}

int ninlil_mfdt_v1_host_observe_time(
    ninlil_mfdt_v1_host_owner_t *owner,
    const uint8_t local_clock_epoch[16],
    uint64_t now_ms,
    uint8_t *epoch_changed_out)
{
    mfdt_host_owner_layout_t *layout;
    uint8_t slot;
    int changed;

    if (!owner_is_valid(owner) || local_clock_epoch == NULL
        || epoch_changed_out == NULL || bytes_zero(local_clock_epoch, 16u)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    layout = owner_layout(owner);
    if (layout->header.f.started == 0u
        || layout->header.f.inventory_uncertain != 0u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    changed = !ninlil_mfdt_v1_memeq(
        layout->header.f.base_config.local_clock_epoch.bytes,
        local_clock_epoch,
        16u);
    *epoch_changed_out = changed != 0 ? 1u : 0u;
    if (changed == 0 && now_ms < layout->header.f.now_ms) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (changed != 0) {
        (void)memcpy(
            layout->header.f.base_config.local_clock_epoch.bytes,
            local_clock_epoch,
            16u);
        ninlil_mfdt_v1_memzero(
            layout->control_outbox, sizeof(layout->control_outbox));
        ninlil_mfdt_v1_memzero(
            &layout->control_meta, sizeof(layout->control_meta));
    }
    layout->header.f.now_ms = now_ms;
    layout->header.f.base_config.now_ms = now_ms;

    for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
        uint8_t engine_changed = 0u;
        int rc;

        if (layout->slots[slot].f.occupied == 0u
            || layout->slots[slot].f.terminal_published != 0u) {
            continue;
        }
        rc = ninlil_mfdt_v1_engine_observe_time(
            slot_engine(layout, slot),
            local_clock_epoch,
            now_ms,
            &engine_changed);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc;
        }
        rc = descriptor_sync_runtime(layout, slot);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc;
        }
        if (engine_changed != 0u
            && layout->slots[slot].f.active_accounted == 0u) {
            rc = reset_slot(layout, slot);
            if (rc != NINLIL_MFDT_V1_OK) {
                return rc;
            }
            continue;
        }
        if (layout->slots[slot].f.bind_valid == 0u) {
            continue;
        }
        rc = ninlil_mfdt_v1_pipeline_tick(
            slot_pipeline(layout, slot), now_ms);
        {
            const int sync_rc = descriptor_sync_runtime(layout, slot);
            if (sync_rc != NINLIL_MFDT_V1_OK) {
                return sync_rc;
            }
        }
        if (rc != NINLIL_MFDT_V1_OK
            && rc != NINLIL_MFDT_V1_ERR_BUSY) {
            return rc;
        }
    }
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_host_tick(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint64_t now_ms)
{
    mfdt_host_owner_layout_t *layout;
    uint8_t slot;
    if (!owner_is_valid(owner)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    layout = owner_layout(owner);
    if (layout->header.f.started == 0u ||
        layout->header.f.inventory_uncertain != 0u ||
        now_ms < layout->header.f.now_ms) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    layout->header.f.now_ms = now_ms;
    layout->header.f.base_config.now_ms = now_ms;
    for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
        int rc;
        if (layout->slots[slot].f.occupied == 0u) {
            continue;
        }
        if (layout->slots[slot].f.terminal_published != 0u) {
            continue;
        }
        ninlil_mfdt_v1_engine_set_now(slot_engine(layout, slot), now_ms);
        if (layout->slots[slot].f.bind_valid == 0u) {
            continue;
        }
        rc = ninlil_mfdt_v1_pipeline_tick(
            slot_pipeline(layout, slot), now_ms);
        {
            const int sync_rc =
                descriptor_sync_runtime(layout, slot);
            if (sync_rc != NINLIL_MFDT_V1_OK) {
                return sync_rc;
            }
        }
        if (rc != NINLIL_MFDT_V1_OK &&
            rc != NINLIL_MFDT_V1_ERR_BUSY) {
            return rc;
        }
    }
    return NINLIL_MFDT_V1_OK;
}

static int coordinator_full_begin(mfdt_host_owner_layout_t *layout)
{
    int rc;
    if (layout->header.f.full_locked != 0u ||
        layout->header.f.inventory_uncertain != 0u) {
        return NINLIL_MFDT_V1_ERR_BUSY;
    }
    layout->header.f.full_locked = 1u;
    rc = ninlil_mfdt_v1_store_full_begin(
        layout->header.f.store, layout->header.f.committed_keys,
        layout->header.f.committed_logical_bytes);
    if (rc != NINLIL_MFDT_V1_OK) {
        layout->header.f.full_locked = 0u;
    }
    return rc;
}

static int coordinator_full_rollback(mfdt_host_owner_layout_t *layout)
{
    const int rc = ninlil_mfdt_v1_store_full_rollback(
        layout->header.f.store);
    layout->header.f.full_locked = 0u;
    if (rc != NINLIL_MFDT_V1_OK) {
        layout->header.f.inventory_uncertain = 1u;
    }
    return rc;
}

static int coordinator_full_commit(mfdt_host_owner_layout_t *layout)
{
    int rc = ninlil_mfdt_v1_store_full_commit(
        layout->header.f.store);
    layout->header.f.full_locked = 0u;
    if (rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN ||
        rc == NINLIL_MFDT_V1_ERR_CU_NEW_NOT_PROMOTED) {
        layout->header.f.inventory_uncertain = 1u;
        rc = NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN;
    }
    return rc;
}

static int coordinator_snapshot_reopen(
    mfdt_host_owner_layout_t *layout,
    ninlil_mfdt_v1_store_snapshot_t *snapshot,
    const uint8_t *prefix, uint32_t prefix_len)
{
    ninlil_mfdt_v1_store_port_t *port;
    ninlil_storage_iter_t iterator = NULL;
    ninlil_bytes_view_t prefix_view;
    ninlil_storage_status_t status;
    if (layout == NULL || snapshot == NULL || snapshot->open == 0u ||
        snapshot->port == NULL || snapshot->txn == NULL ||
        snapshot->iter == NULL || prefix == NULL ||
        prefix_len == 0u ||
        prefix_len > NINLIL_MFDT_V1_KEY_BYTES) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    port = snapshot->port;
    port->ops->iter_close(port->ops->user, snapshot->iter);
    snapshot->iter = NULL;
    prefix_view.data = prefix;
    prefix_view.length = prefix_len;
    status = port->ops->iter_open(
        port->ops->user, snapshot->txn, prefix_view, &iterator);
    if ((status == NINLIL_STORAGE_OK) != (iterator != NULL)) {
        ninlil_storage_status_t rollback_status;
        if (iterator != NULL) {
            port->ops->iter_close(port->ops->user, iterator);
        }
        rollback_status =
            port->ops->rollback(port->ops->user, snapshot->txn);
        port->snapshot_open = 0u;
        ninlil_mfdt_v1_memzero(snapshot, sizeof(*snapshot));
        if (rollback_status != NINLIL_STORAGE_OK) {
            layout->header.f.inventory_uncertain = 1u;
            return ninlil_mfdt_v1_store_map_status(
                rollback_status);
        }
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (status != NINLIL_STORAGE_OK) {
        const ninlil_storage_status_t rollback_status =
            port->ops->rollback(port->ops->user, snapshot->txn);
        port->snapshot_open = 0u;
        ninlil_mfdt_v1_memzero(snapshot, sizeof(*snapshot));
        if (rollback_status != NINLIL_STORAGE_OK ||
            status == NINLIL_STORAGE_COMMIT_UNKNOWN) {
            layout->header.f.inventory_uncertain = 1u;
        }
        return rollback_status != NINLIL_STORAGE_OK
                   ? ninlil_mfdt_v1_store_map_status(rollback_status)
                   : ninlil_mfdt_v1_store_map_status(status);
    }
    snapshot->iter = iterator;
    return NINLIL_MFDT_V1_OK;
}

static int coordinator_snapshot_end(
    mfdt_host_owner_layout_t *layout,
    ninlil_mfdt_v1_store_snapshot_t *snapshot)
{
    const int rc = ninlil_mfdt_v1_store_snapshot_end(snapshot);
    if (rc != NINLIL_MFDT_V1_OK) {
        layout->header.f.inventory_uncertain = 1u;
    }
    return rc;
}

static int coordinator_full_get(
    mfdt_host_owner_layout_t *layout,
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES],
    uint8_t *value_out, uint32_t value_cap,
    uint32_t *value_len_out)
{
    ninlil_mfdt_v1_store_port_t *port;
    ninlil_bytes_view_t key_view;
    ninlil_mut_bytes_t value;
    ninlil_storage_status_t status;
    if (layout == NULL || key == NULL || value_out == NULL ||
        value_len_out == NULL || value_cap == 0u) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    port = layout->header.f.store;
    if (port == NULL || port->ops == NULL ||
        port->full_open == 0u || port->rw_txn == NULL) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    key_view.data = key;
    key_view.length = NINLIL_MFDT_V1_KEY_BYTES;
    value.data = value_out;
    value.capacity = value_cap;
    value.length = 0u;
    /*
     * Private same-RW-transaction read: mirror the store-port mutable-buffer
     * shape checks exactly.  This direct call exists only because the frozen
     * adapter has no FULL-get entry point; no provider-controlled repoint,
     * capacity rewrite, impossible length, or status/length pair is trusted.
     */
    status = port->ops->get(
        port->ops->user, port->rw_txn, key_view, &value);
    *value_len_out = value.length;
    if (value.data != value_out || value.capacity != value_cap ||
        (status == NINLIL_STORAGE_OK && value.length > value_cap) ||
        (status == NINLIL_STORAGE_NOT_FOUND && value.length != 0u) ||
        (status == NINLIL_STORAGE_BUFFER_TOO_SMALL &&
         value.length <= value_cap) ||
        (status != NINLIL_STORAGE_OK &&
         status != NINLIL_STORAGE_NOT_FOUND &&
         status != NINLIL_STORAGE_BUFFER_TOO_SMALL &&
         value.length != 0u)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (status == NINLIL_STORAGE_NOT_FOUND) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    return ninlil_mfdt_v1_store_map_status(status);
}

static int gc_compare_and_erase(
    mfdt_host_owner_layout_t *layout,
    const uint8_t transfer_id[16],
    const uint8_t *expected_nm30,
    uint32_t expected_nm30_len,
    const uint8_t expected_nrc1[NINLIL_MFDT_V1_NRC1_VALUE_BYTES])
{
    uint8_t current_nm30[NINLIL_MFDT_V1_NM30_BYTES];
    uint8_t current_nrc1[NINLIL_MFDT_V1_NRC1_VALUE_BYTES];
    uint8_t terminal_key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t nrc1_key[NINLIL_MFDT_V1_KEY_BYTES];
    uint32_t current_nm30_len = 0u;
    uint32_t current_nrc1_len = 0u;
    int rc;
    make_key(terminal_key, "NM30", transfer_id);
    make_key(nrc1_key, "NRC1", transfer_id);
    rc = coordinator_full_begin(layout);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = coordinator_full_get(
        layout, terminal_key, current_nm30,
        sizeof(current_nm30), &current_nm30_len);
    if (rc == NINLIL_MFDT_V1_OK) {
        rc = coordinator_full_get(
            layout, nrc1_key, current_nrc1,
            sizeof(current_nrc1), &current_nrc1_len);
    }
    if (rc == NINLIL_MFDT_V1_OK &&
        (current_nm30_len != expected_nm30_len ||
         current_nrc1_len != NINLIL_MFDT_V1_NRC1_VALUE_BYTES ||
         !ninlil_mfdt_v1_memeq(
             current_nm30, expected_nm30,
             expected_nm30_len) ||
         !ninlil_mfdt_v1_memeq(
             current_nrc1, expected_nrc1,
             NINLIL_MFDT_V1_NRC1_VALUE_BYTES))) {
        rc = NINLIL_MFDT_V1_ERR_BUSY;
    }
    if (rc == NINLIL_MFDT_V1_OK) {
        rc = ninlil_mfdt_v1_store_full_erase(
            layout->header.f.store, terminal_key);
    }
    if (rc == NINLIL_MFDT_V1_OK) {
        rc = ninlil_mfdt_v1_store_full_erase(
            layout->header.f.store, nrc1_key);
    }
    if (rc != NINLIL_MFDT_V1_OK) {
        const int rollback_rc = coordinator_full_rollback(layout);
        return rollback_rc != NINLIL_MFDT_V1_OK
                   ? rollback_rc : rc;
    }
    return coordinator_full_commit(layout);
}

int ninlil_mfdt_v1_host_gc(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint64_t now_ms)
{
    mfdt_host_owner_layout_t *layout;
    ninlil_mfdt_v1_store_snapshot_t snapshot;
    uint8_t transfer_id[16];
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t previous_key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t nm30[NINLIL_MFDT_V1_NM30_BYTES];
    uint8_t expected_nrc1[NINLIL_MFDT_V1_NRC1_VALUE_BYTES];
    uint32_t value_len = 0u;
    uint32_t selected_nm30_len = 0u;
    uint8_t removed = 0u;
    int rc;
    uint64_t retention;
    static const uint8_t prefix[4] = {'N', 'M', '3', '0'};
    if (!owner_is_valid(owner)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    layout = owner_layout(owner);
    if (layout->header.f.started == 0u ||
        layout->header.f.inventory_uncertain != 0u ||
        now_ms < layout->header.f.now_ms) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (layout->control_meta.f.owned != 0u) {
        return NINLIL_MFDT_V1_ERR_BUSY;
    }
    retention = layout->header.f.base_config.retention_ms;
    if (retention < NINLIL_MFDT_V1_RETENTION_MS_DEFAULT) {
        retention = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    }
    layout->header.f.now_ms = now_ms;
    layout->header.f.base_config.now_ms = now_ms;
    for (;;) {
        uint8_t selected = 0u;
        uint8_t have_previous_key = 0u;
        int done = 0;
        ninlil_mfdt_v1_memzero(
            previous_key, sizeof(previous_key));
        rc = ninlil_mfdt_v1_store_snapshot_begin(
            layout->header.f.store, prefix, sizeof(prefix), &snapshot);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc;
        }
        while (!done) {
            uint64_t anchor;
            uint64_t boundary;
            rc = ninlil_mfdt_v1_store_snapshot_next(
                &snapshot, key, nm30, sizeof(nm30),
                &value_len, &done);
            if (rc != NINLIL_MFDT_V1_OK || done) {
                break;
            }
            if (!ninlil_mfdt_v1_memeq(key, prefix, sizeof(prefix))) {
                rc = NINLIL_MFDT_V1_ERR_CORRUPT;
                break;
            }
            if (have_previous_key != 0u &&
                key_compare(previous_key, key) >= 0) {
                rc = NINLIL_MFDT_V1_ERR_CORRUPT;
                break;
            }
            (void)memcpy(
                previous_key, key, sizeof(previous_key));
            have_previous_key = 1u;
            {
                uint8_t replay_eligible = 0u;
                uint8_t peer[16];
                uint8_t role = 0u;
                int terminal_index;
                if (ninlil_mfdt_v1_validate_nm30_recovery_record(
                        nm30, value_len, key + 4,
                        &replay_eligible, peer, &role) !=
                    NINLIL_MFDT_V1_OK) {
                    rc = NINLIL_MFDT_V1_ERR_CORRUPT;
                    break;
                }
                terminal_index = find_terminal_by_tid(layout, key + 4);
                if (terminal_index < 0 ||
                    layout->terminals[terminal_index].f.nm30_schema !=
                        (uint8_t)ninlil_mfdt_v1_get_u16(nm30 + 4) ||
                    layout->terminals[terminal_index].f.replay_eligible !=
                        replay_eligible ||
                    layout->terminals[terminal_index].f.role != role ||
                    !ninlil_mfdt_v1_memeq(
                        layout->terminals[terminal_index]
                            .f.peer_endpoint_id,
                        peer, 16u)) {
                    rc = NINLIL_MFDT_V1_ERR_CORRUPT;
                    break;
                }
            }
            if (!ninlil_mfdt_v1_memeq(
                    nm30 + 132,
                    layout->header.f.base_config
                        .local_clock_epoch.bytes,
                    16u)) {
                continue;
            }
            anchor = ninlil_mfdt_v1_get_u64(nm30 + 148);
            if (anchor > UINT64_MAX - retention) {
                rc = NINLIL_MFDT_V1_ERR_CORRUPT;
                break;
            }
            boundary = anchor + retention;
            if (now_ms < anchor || now_ms < boundary) {
                continue;
            }
            (void)memcpy(transfer_id, key + 4, 16u);
            {
                uint8_t slot;
                for (slot = 0u;
                     slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
                    if (layout->slots[slot].f.occupied != 0u &&
                        layout->slots[slot].f.terminal_published != 0u &&
                        ninlil_mfdt_v1_memeq(
                            layout->slots[slot].f.transfer_id,
                            transfer_id, 16u) &&
                        slot_pipeline(layout, slot)->outbox_valid != 0u) {
                        rc = NINLIL_MFDT_V1_ERR_BUSY;
                        break;
                    }
                }
                if (rc != NINLIL_MFDT_V1_OK) {
                    break;
                }
            }
            selected_nm30_len = value_len;
            selected = 1u;
            break;
        }
        if (rc != NINLIL_MFDT_V1_OK) {
            const int end_rc =
                coordinator_snapshot_end(layout, &snapshot);
            return end_rc != NINLIL_MFDT_V1_OK ? end_rc : rc;
        }
        if (selected == 0u) {
            rc = coordinator_snapshot_end(layout, &snapshot);
            return rc;
        }
        /*
         * Admission and recovery cap the complete tracked inventory at sixteen
         * groups.  Detect an impossible seventeenth retained group before the
         * compare-and-erase transaction can mutate durable state.
         */
        if (removed >= 16u) {
            const int end_rc =
                coordinator_snapshot_end(layout, &snapshot);
            layout->header.f.inventory_uncertain = 1u;
            return end_rc != NINLIL_MFDT_V1_OK
                       ? end_rc : NINLIL_MFDT_V1_ERR_CORRUPT;
        }
        /*
         * Keep the same READ_ONLY transaction and replace only its iterator:
         * expected NM30 and NRC1 therefore come from one immutable snapshot.
         */
        make_key(key, "NRC1", transfer_id);
        rc = coordinator_snapshot_reopen(
            layout, &snapshot, key, NINLIL_MFDT_V1_KEY_BYTES);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc; /* reopen failure already closed the snapshot */
        }
        done = 0;
        rc = ninlil_mfdt_v1_store_snapshot_next(
            &snapshot, previous_key, expected_nrc1,
            sizeof(expected_nrc1), &value_len, &done);
        if (rc != NINLIL_MFDT_V1_OK || done != 0 ||
            !ninlil_mfdt_v1_memeq(
                previous_key, key, sizeof(previous_key)) ||
            ninlil_mfdt_v1_validate_nrc1_record(
                expected_nrc1, value_len, transfer_id,
                ninlil_mfdt_v1_get_u32(expected_nrc1 + 24)) !=
                NINLIL_MFDT_V1_OK) {
            const int primary =
                rc != NINLIL_MFDT_V1_OK
                    ? rc : NINLIL_MFDT_V1_ERR_CORRUPT;
            const int end_rc =
                coordinator_snapshot_end(layout, &snapshot);
            return end_rc != NINLIL_MFDT_V1_OK
                       ? end_rc : primary;
        }
        {
            const int terminal_index =
                find_terminal_by_tid(layout, transfer_id);
            if (terminal_index < 0 ||
                layout->terminals[terminal_index].f.session_generation !=
                    ninlil_mfdt_v1_get_u32(expected_nrc1 + 24)) {
                const int end_rc =
                    coordinator_snapshot_end(layout, &snapshot);
                return end_rc != NINLIL_MFDT_V1_OK
                           ? end_rc : NINLIL_MFDT_V1_ERR_CORRUPT;
            }
        }
        rc = ninlil_mfdt_v1_store_snapshot_next(
            &snapshot, previous_key, NULL, 0u,
            &value_len, &done);
        if (rc != NINLIL_MFDT_V1_OK || done == 0) {
            const int primary =
                rc == NINLIL_MFDT_V1_OK
                    ? NINLIL_MFDT_V1_ERR_CORRUPT
                    : (rc == NINLIL_MFDT_V1_ERR_CAPACITY
                           ? NINLIL_MFDT_V1_ERR_CORRUPT
                           : rc);
            const int end_rc =
                coordinator_snapshot_end(layout, &snapshot);
            return end_rc != NINLIL_MFDT_V1_OK
                       ? end_rc : primary;
        }
        rc = coordinator_snapshot_end(layout, &snapshot);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc;
        }
        if (layout->header.f.committed_keys < 2u ||
            layout->header.f.committed_logical_bytes <
                (uint64_t)selected_nm30_len +
                    NINLIL_MFDT_V1_NRC1_VALUE_BYTES +
                    2u *
                        NINLIL_MFDT_V1_STORE_ROW_LOGICAL_FIXED_BYTES ||
            layout->header.f.tracked_groups == 0u ||
            layout->header.f.terminal_count == 0u) {
            layout->header.f.inventory_uncertain = 1u;
            return NINLIL_MFDT_V1_ERR_CORRUPT;
        }
        rc = gc_compare_and_erase(
            layout, transfer_id, nm30, selected_nm30_len,
            expected_nrc1);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc;
        }
        rc = terminal_catalog_remove(layout, transfer_id);
        if (rc != NINLIL_MFDT_V1_OK) {
            layout->header.f.inventory_uncertain = 1u;
            return rc;
        }
        layout->header.f.committed_keys -= 2u;
        layout->header.f.committed_logical_bytes -=
            (uint64_t)selected_nm30_len +
                NINLIL_MFDT_V1_NRC1_VALUE_BYTES +
            2u * NINLIL_MFDT_V1_STORE_ROW_LOGICAL_FIXED_BYTES;
        layout->header.f.tracked_groups -= 1u;
        removed = (uint8_t)(removed + 1u);
    }
}

int ninlil_mfdt_v1_host_receiver_publication_view(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot,
    const uint8_t **content_out,
    uint32_t *content_len_out,
    uint8_t publication_token_out[16],
    uint64_t *acceptance_generation_out)
{
    mfdt_host_owner_layout_t *layout;
    if (!owner_is_valid(owner) ||
        slot >= NINLIL_MFDT_V1_HOST_SLOT_COUNT) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    layout = owner_layout(owner);
    if (layout->header.f.started == 0u ||
        layout->header.f.inventory_uncertain != 0u ||
        layout->slots[slot].f.occupied == 0u ||
        layout->slots[slot].f.terminal_published != 0u ||
        layout->slots[slot].f.bind_valid == 0u ||
        layout->slots[slot].f.role !=
            NINLIL_MFDT_V1_HOST_ROLE_RECEIVER) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    return ninlil_mfdt_v1_receiver_publication_view(
        slot_engine(layout, slot), content_out, content_len_out,
        publication_token_out, acceptance_generation_out);
}

int ninlil_mfdt_v1_host_receiver_commit_publication(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot,
    const uint8_t publication_token[16],
    const uint8_t publication_evidence_digest[32])
{
    mfdt_host_owner_layout_t *layout;
    int rc;
    if (!owner_is_valid(owner) ||
        slot >= NINLIL_MFDT_V1_HOST_SLOT_COUNT) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    layout = owner_layout(owner);
    if (layout->header.f.started == 0u ||
        layout->header.f.inventory_uncertain != 0u ||
        layout->slots[slot].f.occupied == 0u ||
        layout->slots[slot].f.role !=
            NINLIL_MFDT_V1_HOST_ROLE_RECEIVER) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    rc = ninlil_mfdt_v1_receiver_commit_publication(
        slot_engine(layout, slot), publication_token,
        publication_evidence_digest);
    {
        const int sync_rc = descriptor_sync_runtime(layout, slot);
        if (sync_rc != NINLIL_MFDT_V1_OK) {
            return sync_rc;
        }
    }
    return rc;
}

int ninlil_mfdt_v1_host_finish_terminal(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot)
{
    mfdt_host_owner_layout_t *layout;
    int rc;
    if (!owner_is_valid(owner) ||
        slot >= NINLIL_MFDT_V1_HOST_SLOT_COUNT) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    layout = owner_layout(owner);
    if (layout->header.f.started == 0u ||
        layout->header.f.inventory_uncertain != 0u ||
        layout->slots[slot].f.occupied == 0u ||
        layout->slots[slot].f.terminal_published != 0u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (layout->slots[slot].f.role ==
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER) {
        rc = ninlil_mfdt_v1_terminal_complete(
            slot_engine(layout, slot));
    } else if (layout->slots[slot].f.bind_valid != 0u) {
        rc = ninlil_mfdt_v1_pipeline_finish_terminal(
            slot_pipeline(layout, slot));
    } else {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = descriptor_sync_runtime(layout, slot);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    return cleanup_terminal_slot_if_drained(layout, slot);
}

int ninlil_mfdt_v1_host_snapshot(
    const ninlil_mfdt_v1_host_owner_t *owner,
    ninlil_mfdt_v1_host_header_snapshot_t *header_out,
    ninlil_mfdt_v1_host_slot_snapshot_t
        slots_out[NINLIL_MFDT_V1_HOST_SLOT_COUNT])
{
    const mfdt_host_owner_layout_t *layout;
    uint8_t slot;
    if (!owner_is_valid(owner) || header_out == NULL ||
        slots_out == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    layout = owner_layout_const(owner);
    ninlil_mfdt_v1_memzero(header_out, sizeof(*header_out));
    ninlil_mfdt_v1_memzero(
        slots_out,
        sizeof(*slots_out) * NINLIL_MFDT_V1_HOST_SLOT_COUNT);
    header_out->now_ms = layout->header.f.now_ms;
    header_out->committed_logical_bytes =
        layout->header.f.committed_logical_bytes;
    header_out->tracked_groups = layout->header.f.tracked_groups;
    header_out->committed_keys = layout->header.f.committed_keys;
    header_out->active_count = layout->header.f.active_count;
    header_out->next_slot = layout->header.f.next_slot;
    header_out->full_locked = layout->header.f.full_locked;
    header_out->started = layout->header.f.started;
    header_out->recovered = layout->header.f.recovered;
    header_out->inventory_uncertain =
        layout->header.f.inventory_uncertain;
    header_out->terminal_count =
        layout->header.f.terminal_count;
    header_out->control_outbox_pending =
        layout->control_meta.f.owned;
    for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
        const mfdt_host_slot_desc_t *descriptor =
            &layout->slots[slot];
        const ninlil_mfdt_v1_engine_t *engine =
            slot_engine_const(layout, slot);
        const ninlil_mfdt_v1_pipeline_t *pipeline =
            slot_pipeline_const(layout, slot);
        (void)memcpy(
            slots_out[slot].transfer_id,
            descriptor->f.transfer_id, 16u);
        (void)memcpy(
            slots_out[slot].peer_endpoint_id,
            descriptor->f.peer_endpoint_id, 16u);
        slots_out[slot].session_cookie =
            descriptor->f.session_cookie;
        slots_out[slot].session_generation =
            descriptor->f.session_generation;
        slots_out[slot].fulls_this_transfer =
            engine->fulls_this_transfer;
        slots_out[slot].role = descriptor->f.role;
        slots_out[slot].occupied = descriptor->f.occupied;
        slots_out[slot].bind_valid = descriptor->f.bind_valid;
        slots_out[slot].unpaid_chunk_offer =
            descriptor->f.unpaid_chunk_offer;
        slots_out[slot].active_accounted =
            descriptor->f.active_accounted;
        slots_out[slot].engine_active = engine->active_count;
        slots_out[slot].pipeline_phase = pipeline->phase;
        slots_out[slot].outbox_pending = pipeline->outbox_valid;
    }
    return NINLIL_MFDT_V1_OK;
}
