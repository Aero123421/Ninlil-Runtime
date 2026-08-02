/*
 * Private Fabric v1 core: lifecycle, registry, policy/authority, dispatch,
 * and single ninlil_bearer_ops_t adapter. Default-OFF source candidate.
 */
#include "fabric_private_api.h"
#include "fabric_rrmp_select_hook.h"
#include "fabric_workspace.h"

#include <stddef.h>
#if defined(NINLIL_FABRIC_HOST_DIAGNOSTICS)
#include <stdio.h>
#endif

#define FABRIC_LIFECYCLE_ZERO 0u
#define FABRIC_LIFECYCLE_OPEN 1u
#define FABRIC_LIFECYCLE_CLOSING 2u
#define FABRIC_LIFECYCLE_CLOSED 3u
#define FABRIC_LIFECYCLE_DESTROYED 4u

#define FABRIC_REG_ACTIVE 1u
#define FABRIC_REG_DRAINING 2u
#define FABRIC_REG_CONSUMED 3u

/* Profile-1 index caps match schema maximum (ADR-0017). */
#define FABRIC_RAM_POLICY_MAX NINLIL_FABRIC_POLICY_MAX
#define FABRIC_RAM_AUTHORITY_MAX NINLIL_FABRIC_AUTHORITY_MAX
#define FABRIC_RAM_TRIGGER_MAX NINLIL_FABRIC_TRIGGER_MAX

typedef struct fabric_reg_slot {
    uint32_t used;
    uint32_t lifecycle;
    uint64_t record_revision; /* FBR1 envelope revision; availability strict +1 */
    ninlil_fabric_link_descriptor_v1_t descriptor;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_packet_link_handle_t handle;
    ninlil_fabric_link_state_v1_t state;
    ninlil_fabric_link_metrics_v1_t metrics;
    uint32_t retained_tokens;
    uint32_t queued_items;
    ninlil_fabric_registration_private_t *public_handle;
} fabric_reg_slot_t;

/* Compact durable FBR1 pins for restart join (workspace-bounded). */
typedef struct fabric_fbr1_pin {
    uint8_t used;
    uint8_t available;
    uint8_t reserved0[6];
    uint64_t record_revision;
    uint64_t availability_epoch;
    uint64_t availability_expires_at_ms;
    uint8_t instance_id[16];
    uint8_t registry_digest[32];
    uint8_t descriptor_digest[32];
} fabric_fbr1_pin_t;

/* Compact slots sized for profile-1 regions (ADR-0017). */
typedef struct fabric_policy_slot {
    ninlil_fabric_policy_index_entry_t index;
    uint64_t record_revision;
} fabric_policy_slot_t;

typedef struct fabric_authority_slot {
    ninlil_fabric_authority_index_entry_t index;
    uint64_t record_revision;
    /* owner-scope pin for reverse (not full 488 FBC1). */
    uint32_t authority_state;
    uint32_t assignment_epoch;
    uint64_t authority_term;
    uint8_t authority_id[16];
    uint8_t owner_scope_id[16];
    uint8_t owner_tuple_digest[32];
    uint8_t policy_digest[32];
    uint8_t endpoint_runtime_id[16];
    uint8_t authority_clock_epoch_id[16];
    uint64_t lease_expires_at_ms;
} fabric_authority_slot_t;

typedef struct fabric_packet_slot {
    uint32_t used;
    uint32_t length;
    uint8_t bytes[NINLIL_FABRIC_NFL1_STRUCTURAL_MAX];
} fabric_packet_slot_t;

typedef struct fabric_attempt_slot {
    uint32_t used;
    uint32_t packet_slot;
    uint32_t has_token;
    uint32_t reg_index;
    uint64_t record_revision;
    ninlil_fabric_packet_token_t token;
    uint8_t key[76];
    ninlil_fabric_private_fba1_t attempt;
} fabric_attempt_slot_t;

typedef struct fabric_trigger_slot {
    uint32_t used;
    uint32_t reserved0;
    uint64_t record_revision;
    ninlil_fabric_private_fbt1_t trigger;
} fabric_trigger_slot_t;

typedef struct fabric_rx_slot {
    uint32_t used;
    uint32_t packet_slot;
    uint32_t loaned;
    uint32_t reserved0;
    ninlil_bearer_message_t projected;
} fabric_rx_slot_t;

struct ninlil_fabric_link_registration_v1 {
    uint32_t magic;
    uint32_t slot_index;
    ninlil_fabric_private_t *fabric;
};

struct ninlil_fabric_v1 {
    /* --- NFL1 queue region (61600): 32 × structural max --- */
    fabric_packet_slot_t packet_pool[NINLIL_FABRIC_SHARED_QUEUE_MAX];
    /* --- codec scratch (4096): 2 × 2048 --- */
    uint8_t encode_scratch[NINLIL_FABRIC_NFL1_CODEC_CEILING];
    uint8_t decode_scratch[NINLIL_FABRIC_NFL1_CODEC_CEILING];
    /* --- registry + handles + FBR1 pins (registry region budget) --- */
    fabric_reg_slot_t regs[NINLIL_FABRIC_REGISTRY_MAX];
    struct ninlil_fabric_link_registration_v1 reg_handles[NINLIL_FABRIC_REGISTRY_MAX];
    fabric_fbr1_pin_t fbr1_pins[NINLIL_FABRIC_REGISTRY_MAX];
    /* --- policy index 64 --- */
    fabric_policy_slot_t policies[NINLIL_FABRIC_POLICY_MAX];
    /* --- authority index 64 --- */
    fabric_authority_slot_t authorities[NINLIL_FABRIC_AUTHORITY_MAX];
    /* --- attempts 64 --- */
    fabric_attempt_slot_t attempts[NINLIL_FABRIC_ATTEMPT_MAX];
    /* --- triggers 64 --- */
    fabric_trigger_slot_t triggers[NINLIL_FABRIC_TRIGGER_MAX];
    /* --- queue descriptors / rx --- */
    fabric_rx_slot_t rx_queue[NINLIL_FABRIC_SHARED_QUEUE_MAX];
    /* --- control fields --- */
    uint32_t magic;
    uint32_t lifecycle;
    uint64_t owner_context_id;
    uint32_t reentrant;
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t execution;
    ninlil_storage_handle_t storage_handle;
    uint32_t storage_open;
    struct ninlil_rrmp_owner *rrmp_owner;
    ninlil_fabric_private_fbm1_t meta;
    uint64_t meta_revision;
    uint64_t path_selection_epoch;
    uint32_t rx_head;
    uint32_t rx_count;
    uint32_t attempt_gc_cursor;
    uint32_t trigger_gc_cursor;
    uint32_t terminal_gc_prefer_trigger;
    /* Exact-1 outer receive loan generation (ADR-0017). */
    uint32_t outer_rx_loan_generation;
    uint32_t outer_rx_loan_live; /* 0 = none; else generation of outstanding loan */
    uint32_t outer_open;
    ninlil_bearer_handle_t outer_handle_token;
    ninlil_bearer_ops_t bearer_ops;
};

/* Strict no-loan: live objects fit declared region budgets (not count-only). */
_Static_assert(
    sizeof(((struct ninlil_fabric_v1 *)0)->packet_pool)
        <= NINLIL_FABRIC_WS_NFL1_QUEUE_BYTES,
    "packet_pool must fit NFL1 queue region");
_Static_assert(
    sizeof(((struct ninlil_fabric_v1 *)0)->encode_scratch)
            + sizeof(((struct ninlil_fabric_v1 *)0)->decode_scratch)
        <= NINLIL_FABRIC_WS_CODEC_SCRATCH_BYTES,
    "codec scratch exact ceiling pair");
_Static_assert(
    sizeof(((struct ninlil_fabric_v1 *)0)->regs)
            + sizeof(((struct ninlil_fabric_v1 *)0)->reg_handles)
            + sizeof(((struct ninlil_fabric_v1 *)0)->fbr1_pins)
        <= NINLIL_FABRIC_WS_REGISTRY_BYTES,
    "registry objects must fit registry region");
_Static_assert(
    sizeof(((struct ninlil_fabric_v1 *)0)->policies)
        <= NINLIL_FABRIC_WS_POLICY_INDEX_BYTES,
    "policy slots must fit policy region");
_Static_assert(
    sizeof(((struct ninlil_fabric_v1 *)0)->authorities)
        <= NINLIL_FABRIC_WS_AUTHORITY_INDEX_BYTES,
    "authority slots must fit authority region");
_Static_assert(
    sizeof(((struct ninlil_fabric_v1 *)0)->attempts)
        <= NINLIL_FABRIC_WS_ATTEMPT_BYTES,
    "attempt slots must fit attempt region");
_Static_assert(
    sizeof(((struct ninlil_fabric_v1 *)0)->triggers)
        <= NINLIL_FABRIC_WS_TRIGGER_BYTES,
    "trigger slots must fit trigger region");
_Static_assert(
    sizeof(((struct ninlil_fabric_v1 *)0)->rx_queue)
        <= NINLIL_FABRIC_WS_QUEUE_DESC_BYTES,
    "rx_queue must fit queue-desc region");
_Static_assert(
    sizeof(struct ninlil_fabric_v1) <= NINLIL_FABRIC_WS_TOTAL_BYTES,
    "fabric object must fit profile-1 workspace");

#define FABRIC_MAGIC 0x46425631u /* FBV1 */
#define REG_MAGIC 0x46525631u /* FRV1 */

static int fabric_is_recognized_magic(const uint8_t *key, uint32_t key_len);
static int fabric_key_magic_eq(
    const uint8_t *key, uint32_t key_len, const char magic[4], uint32_t expect_len);

static int header_ok(uint16_t api_version, uint16_t struct_size, uint16_t expected)
{
    return api_version == NINLIL_FABRIC_PRIVATE_API_VERSION
        && struct_size == expected;
}

/*
 * ADR-0017 private API precedence after outer NULL/header/size/reserved:
 * owner thread -> re-entry -> lifecycle. Owner is checked before reentry so a
 * wrong-thread caller never observes reentry status, and execution.current is
 * never invoked until the fabric pointer/magic are already validated by the
 * caller (or by fabric_null_magic below).
 */
static ninlil_fabric_private_status_t fabric_null_magic(
    const ninlil_fabric_private_t *fabric)
{
    if (fabric == NULL || fabric->magic != FABRIC_MAGIC) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    return NINLIL_FABRIC_PRIVATE_OK;
}

static ninlil_fabric_private_status_t owner_then_reentry(
    ninlil_fabric_private_t *fabric)
{
    uint64_t current;
    current = fabric->execution.current_context_id(fabric->execution.user);
    if (current != fabric->owner_context_id) {
        return NINLIL_FABRIC_PRIVATE_WRONG_THREAD;
    }
    if (fabric->reentrant != 0u) {
        return NINLIL_FABRIC_PRIVATE_REENTRANT;
    }
    if (fabric->lifecycle == FABRIC_LIFECYCLE_DESTROYED
        || fabric->lifecycle == FABRIC_LIFECYCLE_ZERO) {
        return NINLIL_FABRIC_PRIVATE_CLOSED;
    }
    return NINLIL_FABRIC_PRIVATE_OK;
}

/* Combined helper for APIs that already validated outer NULL/ABI. */
static ninlil_fabric_private_status_t owner_check(
    ninlil_fabric_private_t *fabric)
{
    ninlil_fabric_private_status_t st = fabric_null_magic(fabric);
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    return owner_then_reentry(fabric);
}

/*
 * P1: checked u64 next-revision before durable FULL.
 * Wrap (UINT64_MAX) => fail closed, no storage mutation.
 * Returns 1 and writes *out_next on success; 0 on wrap.
 */
static int fabric_checked_next_u64(uint64_t cur, uint64_t *out_next)
{
    if (out_next == NULL || cur == UINT64_MAX) {
        return 0;
    }
    *out_next = cur + 1u;
    return 1;
}

/*
 * P1: checked u64 duration addition before durable FULL/provider side effect.
 * Returns 1 and writes *out_sum on success; 0 leaves *out_sum unchanged.
 */
static int fabric_checked_add_u64(
    uint64_t base, uint64_t duration, uint64_t *out_sum)
{
    if (out_sum == NULL || UINT64_MAX - base < duration) {
        return 0;
    }
    *out_sum = base + duration;
    return 1;
}

/* Volatile counter: wrap fails closed (no wrap-around mutation). */
static int fabric_checked_inc_u64(uint64_t *v)
{
    if (v == NULL || *v == UINT64_MAX) {
        return 0;
    }
    (*v) += 1u;
    return 1;
}

/* Metrics revision: fail closed on wrap (fence path uses return 0). */
static void fabric_metrics_bump(fabric_reg_slot_t *reg)
{
    if (reg == NULL) {
        return;
    }
    if (fabric_checked_inc_u64(&reg->metrics.metrics_revision) == 0) {
        /* Wrap: freeze counter at MAX; instance becomes unusable for metrics. */
        reg->lifecycle = FABRIC_REG_DRAINING;
    }
}

/* ---------- storage transcript helpers (FULL first, fail-closed) ---------- */

static ninlil_fabric_private_status_t map_storage_status(
    ninlil_storage_status_t st)
{
    if (st == NINLIL_STORAGE_OK) {
        return NINLIL_FABRIC_PRIVATE_OK;
    }
    if (st == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        return NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN;
    }
    if (st == NINLIL_STORAGE_NO_SPACE) {
        return NINLIL_FABRIC_PRIVATE_CAPACITY;
    }
    if (st == NINLIL_STORAGE_NOT_FOUND) {
        return NINLIL_FABRIC_PRIVATE_UNAVAILABLE;
    }
    if (st == NINLIL_STORAGE_BUSY) {
        return NINLIL_FABRIC_PRIVATE_WOULD_BLOCK;
    }
    return NINLIL_FABRIC_PRIVATE_CORRUPT;
}

/* ---------- workspace / create ---------- */

ninlil_fabric_private_status_t ninlil_fabric_private_workspace_required_v1(
    uint32_t profile_id, uint32_t *out_bytes, uint32_t *out_alignment)
{
    if (out_bytes == NULL || out_alignment == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (profile_id != NINLIL_FABRIC_PROFILE_1) {
        return NINLIL_FABRIC_PRIVATE_UNSUPPORTED;
    }
    {
        uint32_t need = NINLIL_FABRIC_WORKSPACE_BYTES;
        if ((uint32_t)sizeof(ninlil_fabric_private_t) > need) {
            need = (uint32_t)sizeof(ninlil_fabric_private_t);
        }
        *out_bytes = need;
        *out_alignment = (uint32_t)_Alignof(max_align_t);
    }
    return NINLIL_FABRIC_PRIVATE_OK;
}

/*
 * ADR-0017 COMMIT_UNKNOWN: close/reopen namespace, READ_ONLY exact key
 * readback, classify OLD/NEW/ABSENT/third. No provider side-effect here.
 */
static ninlil_fabric_private_status_t storage_reopen_namespace(
    ninlil_fabric_private_t *fabric)
{
    ninlil_storage_status_t st;
    ninlil_bytes_view_t ns;
    static const uint8_t ns_bytes[] = {
        'n', 'i', 'n', 'l', 'i', 'l', '.', 'f', 'a', 'b', 'r', 'i', 'c', '.',
        'v', '1'
    };

    if (fabric->storage_open != 0u && fabric->storage_handle != NULL) {
        fabric->storage.close(fabric->storage.user, fabric->storage_handle);
        fabric->storage_handle = NULL;
        fabric->storage_open = 0u;
    }
    ns.data = ns_bytes;
    ns.length = (uint32_t)sizeof(ns_bytes);
    st = fabric->storage.open(
        fabric->storage.user, ns, NINLIL_FABRIC_STORAGE_SCHEMA_1,
        &fabric->storage_handle);
    if (st != NINLIL_STORAGE_OK) {
        return st == NINLIL_STORAGE_UNSUPPORTED_SCHEMA
            ? NINLIL_FABRIC_PRIVATE_UNSUPPORTED
            : NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    fabric->storage_open = 1u;
    return NINLIL_FABRIC_PRIVATE_OK;
}

static ninlil_fabric_private_status_t storage_read_key_readonly(
    ninlil_fabric_private_t *fabric,
    const uint8_t *key,
    uint32_t key_len,
    uint8_t *value_buf,
    uint32_t value_cap,
    uint32_t *out_value_len,
    int *out_present)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t st;
    ninlil_bytes_view_t key_view;
    ninlil_mut_bytes_t value_mut;

    if (out_value_len != NULL) {
        *out_value_len = 0u;
    }
    if (out_present != NULL) {
        *out_present = 0;
    }
    st = fabric->storage.begin(
        fabric->storage.user, fabric->storage_handle,
        NINLIL_STORAGE_READ_ONLY, &txn);
    if (st != NINLIL_STORAGE_OK) {
        return map_storage_status(st);
    }
    key_view.data = key;
    key_view.length = key_len;
    value_mut.data = value_buf;
    value_mut.capacity = value_cap;
    value_mut.length = 0u;
    st = fabric->storage.get(fabric->storage.user, txn, key_view, &value_mut);
    {
        ninlil_storage_status_t rb =
            fabric->storage.rollback(fabric->storage.user, txn);
        if (rb != NINLIL_STORAGE_OK) {
            /* Uncertain RO closure: never classify OLD/NEW on this handle. */
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
    }
    if (st == NINLIL_STORAGE_NOT_FOUND) {
        return NINLIL_FABRIC_PRIVATE_OK;
    }
    if (st != NINLIL_STORAGE_OK) {
        return map_storage_status(st);
    }
    if (out_present != NULL) {
        *out_present = 1;
    }
    if (out_value_len != NULL) {
        *out_value_len = value_mut.length;
    }
    return NINLIL_FABRIC_PRIVATE_OK;
}

/* Returns OK / COMMIT_UNKNOWN / CORRUPT (third) / other definite errors. */
static ninlil_fabric_private_status_t storage_commit_unknown_resolve(
    ninlil_fabric_private_t *fabric,
    const uint8_t *key,
    uint32_t key_len,
    const uint8_t *old_value,
    uint32_t old_value_len,
    const uint8_t *new_value,
    uint32_t new_value_len,
    uint32_t *out_class)
{
    ninlil_fabric_private_status_t rc;
    uint8_t observed[NINLIL_FABRIC_VALUE_CEILING];
    uint32_t observed_len = 0u;
    int present = 0;
    uint32_t klass;

    if (out_class != NULL) {
        *out_class = NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_CORRUPT;
    }
    rc = storage_reopen_namespace(fabric);
    if (rc != NINLIL_FABRIC_PRIVATE_OK) {
        return rc;
    }
    rc = storage_read_key_readonly(
        fabric, key, key_len, observed, sizeof(observed), &observed_len,
        &present);
    if (rc != NINLIL_FABRIC_PRIVATE_OK) {
        return rc;
    }
    if (new_value == NULL || new_value_len == 0u) {
        /* Erase intent: NEW = ABSENT, OLD = prior value. */
        if (!present) {
            klass = (old_value != NULL && old_value_len > 0u)
                ? NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_NEW
                : NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_ABSENT;
        } else if (
            old_value != NULL && old_value_len > 0u
            && observed_len == old_value_len
            && ninlil_fabric_private_memeq(
                   observed, old_value, old_value_len)) {
            klass = NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_OLD;
        } else {
            klass = NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_CORRUPT;
        }
    } else {
        klass = ninlil_fabric_private_commit_unknown_classify(
            key,
            (old_value != NULL && old_value_len > 0u) ? key_len : 0u,
            old_value,
            old_value_len,
            key,
            key_len,
            new_value,
            new_value_len,
            present ? key : NULL,
            present ? key_len : 0u,
            present ? observed : NULL,
            observed_len,
            present);
    }
    if (out_class != NULL) {
        *out_class = klass;
    }
    if (klass == NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_CORRUPT) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    /* OLD / NEW / ABSENT: outer LOST path via COMMIT_UNKNOWN status. */
    return NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN;
}

static ninlil_fabric_private_status_t storage_put_full_ex(
    ninlil_fabric_private_t *fabric,
    const uint8_t *key,
    uint32_t key_len,
    const uint8_t *value,
    uint32_t value_len,
    const uint8_t *old_value,
    uint32_t old_value_len,
    uint32_t *out_cu_class)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t st;
    ninlil_bytes_view_t key_view;
    ninlil_bytes_view_t value_view;
    uint8_t auto_old[NINLIL_FABRIC_VALUE_CEILING];
    uint32_t auto_old_len = 0u;
    int auto_present = 0;

    if (out_cu_class != NULL) {
        *out_cu_class = 0u;
    }
    /* Capture prior exact row for CU OLD classify on replacements. */
    if (old_value == NULL) {
        ninlil_fabric_private_status_t pre = storage_read_key_readonly(
            fabric, key, key_len, auto_old, sizeof(auto_old), &auto_old_len,
            &auto_present);
        if (pre != NINLIL_FABRIC_PRIVATE_OK) {
            return pre;
        }
        if (auto_present != 0) {
            old_value = auto_old;
            old_value_len = auto_old_len;
        }
    }
    st = fabric->storage.begin(
        fabric->storage.user, fabric->storage_handle,
        NINLIL_STORAGE_READ_WRITE, &txn);
    if (st != NINLIL_STORAGE_OK) {
        return map_storage_status(st);
    }
    key_view.data = key;
    key_view.length = key_len;
    value_view.data = value;
    value_view.length = value_len;
    st = fabric->storage.put(fabric->storage.user, txn, key_view, value_view);
    if (st != NINLIL_STORAGE_OK) {
        (void)fabric->storage.rollback(fabric->storage.user, txn);
        return map_storage_status(st);
    }
    st = fabric->storage.commit(
        fabric->storage.user, txn, NINLIL_DURABILITY_FULL);
    if (st == NINLIL_STORAGE_OK) {
        return NINLIL_FABRIC_PRIVATE_OK;
    }
    if (st != NINLIL_STORAGE_COMMIT_UNKNOWN) {
        return map_storage_status(st);
    }
    /* COMMIT_UNKNOWN: txn consumed; classify via fresh close/reopen. */
    return storage_commit_unknown_resolve(
        fabric, key, key_len, old_value, old_value_len, value, value_len,
        out_cu_class);
}

static ninlil_fabric_private_status_t storage_put_full(
    ninlil_fabric_private_t *fabric,
    const uint8_t *key,
    uint32_t key_len,
    const uint8_t *value,
    uint32_t value_len)
{
    return storage_put_full_ex(
        fabric, key, key_len, value, value_len, NULL, 0u, NULL);
}

/* Multi-key same FULL transaction (FBR1+FBM1 group, etc.). */
typedef struct fabric_kv_put {
    const uint8_t *key;
    uint32_t key_len;
    const uint8_t *value;
    uint32_t value_len;
} fabric_kv_put_t;

static ninlil_fabric_private_status_t storage_put_multi_full(
    ninlil_fabric_private_t *fabric,
    const fabric_kv_put_t *items,
    uint32_t item_count)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t st;
    uint32_t i;
    /* Capture OLD exact rows for CU classify (create = absent). */
    uint8_t old_vals[8][NINLIL_FABRIC_VALUE_CEILING];
    uint32_t old_lens[8];
    int old_present[8];

    if (items == NULL || item_count == 0u || item_count > 8u) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    ninlil_fabric_private_memzero(old_vals, sizeof(old_vals));
    ninlil_fabric_private_memzero(old_lens, sizeof(old_lens));
    ninlil_fabric_private_memzero(old_present, sizeof(old_present));
    for (i = 0u; i < item_count; ++i) {
        ninlil_fabric_private_status_t pre;
        if (items[i].key == NULL || items[i].value == NULL
            || items[i].key_len == 0u || items[i].value_len == 0u) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
        pre = storage_read_key_readonly(
            fabric,
            items[i].key,
            items[i].key_len,
            old_vals[i],
            sizeof(old_vals[i]),
            &old_lens[i],
            &old_present[i]);
        if (pre != NINLIL_FABRIC_PRIVATE_OK) {
            return pre;
        }
    }
    st = fabric->storage.begin(
        fabric->storage.user, fabric->storage_handle,
        NINLIL_STORAGE_READ_WRITE, &txn);
    if (st != NINLIL_STORAGE_OK) {
        return map_storage_status(st);
    }
    for (i = 0u; i < item_count; ++i) {
        ninlil_bytes_view_t kv;
        ninlil_bytes_view_t vv;
        kv.data = items[i].key;
        kv.length = items[i].key_len;
        vv.data = items[i].value;
        vv.length = items[i].value_len;
        st = fabric->storage.put(fabric->storage.user, txn, kv, vv);
        if (st != NINLIL_STORAGE_OK) {
            (void)fabric->storage.rollback(fabric->storage.user, txn);
            return map_storage_status(st);
        }
    }
    st = fabric->storage.commit(
        fabric->storage.user, txn, NINLIL_DURABILITY_FULL);
    if (st == NINLIL_STORAGE_OK) {
        return NINLIL_FABRIC_PRIVATE_OK;
    }
    if (st != NINLIL_STORAGE_COMMIT_UNKNOWN) {
        return map_storage_status(st);
    }
    /* Multi-key CU: reopen; all-NEW or all-OLD/ABSENT only. */
    {
        uint32_t new_count = 0u;
        uint32_t oldish_count = 0u;
        ninlil_fabric_private_status_t rc = storage_reopen_namespace(fabric);
        if (rc != NINLIL_FABRIC_PRIVATE_OK) {
            return rc;
        }
        for (i = 0u; i < item_count; ++i) {
            uint8_t obs[NINLIL_FABRIC_VALUE_CEILING];
            uint32_t obs_len = 0u;
            int present = 0;
            uint32_t klass;
            rc = storage_read_key_readonly(
                fabric, items[i].key, items[i].key_len, obs, sizeof(obs),
                &obs_len, &present);
            if (rc != NINLIL_FABRIC_PRIVATE_OK) {
                return rc;
            }
            klass = ninlil_fabric_private_commit_unknown_classify(
                old_present[i] ? items[i].key : NULL,
                old_present[i] ? items[i].key_len : 0u,
                old_present[i] ? old_vals[i] : NULL,
                old_present[i] ? old_lens[i] : 0u,
                items[i].key,
                items[i].key_len,
                items[i].value,
                items[i].value_len,
                present ? items[i].key : NULL,
                present ? items[i].key_len : 0u,
                present ? obs : NULL,
                obs_len,
                present);
            if (klass == NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_NEW) {
                new_count++;
            } else if (klass == NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_OLD
                || klass == NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_ABSENT) {
                oldish_count++;
            } else {
                return NINLIL_FABRIC_PRIVATE_CORRUPT;
            }
        }
        if (new_count == item_count) {
            return NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN; /* all-NEW */
        }
        if (oldish_count == item_count) {
            return NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN; /* all-OLD/ABSENT */
        }
        return NINLIL_FABRIC_PRIVATE_CORRUPT; /* mixed */
    }
}

static ninlil_fabric_private_status_t storage_erase_full_ex(
    ninlil_fabric_private_t *fabric,
    const uint8_t *key,
    uint32_t key_len,
    uint32_t *out_cu_class)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t st;
    ninlil_bytes_view_t key_view;
    uint8_t old_value[NINLIL_FABRIC_VALUE_CEILING];
    uint32_t old_len = 0u;
    int old_present = 0;
    ninlil_fabric_private_status_t pre;

    if (out_cu_class != NULL) {
        *out_cu_class = 0u;
    }
    if (fabric->storage.erase == NULL) {
        return NINLIL_FABRIC_PRIVATE_UNSUPPORTED;
    }
    /* Capture OLD exact row for CU classify (erase new = ABSENT). */
    pre = storage_read_key_readonly(
        fabric, key, key_len, old_value, sizeof(old_value), &old_len,
        &old_present);
    if (pre != NINLIL_FABRIC_PRIVATE_OK) {
        return pre;
    }
    st = fabric->storage.begin(
        fabric->storage.user, fabric->storage_handle,
        NINLIL_STORAGE_READ_WRITE, &txn);
    if (st != NINLIL_STORAGE_OK) {
        return map_storage_status(st);
    }
    key_view.data = key;
    key_view.length = key_len;
    st = fabric->storage.erase(fabric->storage.user, txn, key_view);
    if (st != NINLIL_STORAGE_OK && st != NINLIL_STORAGE_NOT_FOUND) {
        (void)fabric->storage.rollback(fabric->storage.user, txn);
        return map_storage_status(st);
    }
    st = fabric->storage.commit(
        fabric->storage.user, txn, NINLIL_DURABILITY_FULL);
    if (st == NINLIL_STORAGE_OK) {
        return NINLIL_FABRIC_PRIVATE_OK;
    }
    if (st != NINLIL_STORAGE_COMMIT_UNKNOWN) {
        return map_storage_status(st);
    }
    return storage_commit_unknown_resolve(
        fabric,
        key,
        key_len,
        old_present ? old_value : NULL,
        old_present ? old_len : 0u,
        NULL,
        0u,
        out_cu_class);
}

static ninlil_fabric_private_status_t fba1_persist_full_ex(
    ninlil_fabric_private_t *fabric,
    const ninlil_fabric_private_fba1_t *rec,
    const uint8_t key[76],
    uint64_t envelope_revision,
    const uint8_t *old_value,
    uint32_t old_value_len,
    uint32_t *out_cu_class,
    uint8_t *out_new_value,
    uint32_t *out_new_value_len)
{
    uint8_t payload[NINLIL_FABRIC_FBA1_PAYLOAD_BYTES];
    uint8_t value[NINLIL_FABRIC_FBA1_VALUE_BYTES];
    uint32_t vlen = 0u;

    if (envelope_revision == 0u) {
        envelope_revision = 1u;
    }
    if (ninlil_fabric_private_fba1_encode(rec, payload)
        != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    if (ninlil_fabric_private_record_encode_envelope(
            (const uint8_t *)"FBA1",
            envelope_revision,
            payload,
            NINLIL_FABRIC_FBA1_PAYLOAD_BYTES,
            value,
            NINLIL_FABRIC_FBA1_VALUE_BYTES,
            &vlen)
        != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    if (out_new_value != NULL && out_new_value_len != NULL
        && *out_new_value_len >= vlen) {
        (void)memcpy(out_new_value, value, vlen);
        *out_new_value_len = vlen;
    } else if (out_new_value_len != NULL) {
        *out_new_value_len = vlen;
    }
    return storage_put_full_ex(
        fabric, key, 76u, value, vlen, old_value, old_value_len, out_cu_class);
}

static ninlil_fabric_private_status_t fba1_persist_full(
    ninlil_fabric_private_t *fabric,
    const ninlil_fabric_private_fba1_t *rec,
    const uint8_t key[76],
    uint64_t envelope_revision)
{
    return fba1_persist_full_ex(
        fabric, rec, key, envelope_revision, NULL, 0u, NULL, NULL, NULL);
}

/*
 * Persist FBA1 FULL with checked revision = current+1.
 * On wrap: no put, return CAPACITY (fail closed, mutation 0).
 * On OK: *inout_revision becomes next.
 */
static ninlil_fabric_private_status_t fba1_persist_full_next(
    ninlil_fabric_private_t *fabric,
    const ninlil_fabric_private_fba1_t *rec,
    const uint8_t key[76],
    uint64_t *inout_revision)
{
    uint64_t next;
    ninlil_fabric_private_status_t st;
    if (fabric == NULL || rec == NULL || key == NULL || inout_revision == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (fabric_checked_next_u64(*inout_revision, &next) == 0) {
        return NINLIL_FABRIC_PRIVATE_CAPACITY;
    }
    st = fba1_persist_full(fabric, rec, key, next);
    if (st == NINLIL_FABRIC_PRIVATE_OK) {
        *inout_revision = next;
    }
    return st;
}

/*
 * Exact FBA1 replacement with OLD/NEW CU classification. The caller supplies
 * the complete immutable OLD image and the intended NEW image; a mismatching
 * durable OLD row is corruption, never an overwrite. On CU-NEW the revision is
 * advanced because read-back proved the NEW row, while the CU status remains
 * visible so the caller can apply operation-specific promotion rules.
 */
static ninlil_fabric_private_status_t fba1_replace_full_classified(
    ninlil_fabric_private_t *fabric,
    const ninlil_fabric_private_fba1_t *old_rec,
    const ninlil_fabric_private_fba1_t *new_rec,
    const uint8_t key[76],
    uint64_t *inout_revision,
    uint32_t *out_cu_class,
    uint32_t *out_mutation_attempted)
{
    uint8_t old_payload[NINLIL_FABRIC_FBA1_PAYLOAD_BYTES];
    uint8_t old_expect[NINLIL_FABRIC_FBA1_VALUE_BYTES];
    uint8_t old_actual[NINLIL_FABRIC_FBA1_VALUE_BYTES];
    uint32_t old_expect_len = 0u;
    uint32_t old_actual_len = 0u;
    uint32_t cu_class = 0u;
    int present = 0;
    uint64_t next_revision;
    ninlil_fabric_private_status_t st;

    if (fabric == NULL || old_rec == NULL || new_rec == NULL || key == NULL
        || inout_revision == NULL || *inout_revision == 0u) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (out_cu_class != NULL) {
        *out_cu_class = 0u;
    }
    if (out_mutation_attempted != NULL) {
        *out_mutation_attempted = 0u;
    }
    if (fabric_checked_next_u64(*inout_revision, &next_revision) == 0) {
        return NINLIL_FABRIC_PRIVATE_CAPACITY;
    }
    if (ninlil_fabric_private_fba1_encode(old_rec, old_payload)
            != NINLIL_FABRIC_PRIVATE_RECORD_OK
        || ninlil_fabric_private_record_encode_envelope(
               (const uint8_t *)"FBA1",
               *inout_revision,
               old_payload,
               NINLIL_FABRIC_FBA1_PAYLOAD_BYTES,
               old_expect,
               sizeof(old_expect),
               &old_expect_len)
            != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    st = storage_read_key_readonly(
        fabric,
        key,
        76u,
        old_actual,
        sizeof(old_actual),
        &old_actual_len,
        &present);
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    if (present == 0 || old_actual_len != old_expect_len
        || !ninlil_fabric_private_memeq(
               old_actual, old_expect, old_expect_len)) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    if (out_mutation_attempted != NULL) {
        *out_mutation_attempted = 1u;
    }
    st = fba1_persist_full_ex(
        fabric,
        new_rec,
        key,
        next_revision,
        old_actual,
        old_actual_len,
        &cu_class,
        NULL,
        NULL);
    if (st == NINLIL_FABRIC_PRIVATE_OK
        || (st == NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN
            && cu_class == NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_NEW)) {
        *inout_revision = next_revision;
    }
    if (out_cu_class != NULL) {
        *out_cu_class = cu_class;
    }
    return st;
}

static ninlil_fabric_private_status_t fbt1_persist_full_ex(
    ninlil_fabric_private_t *fabric,
    const ninlil_fabric_private_fbt1_t *rec,
    const uint8_t key[40],
    uint64_t envelope_revision,
    const uint8_t *old_value,
    uint32_t old_value_len,
    uint32_t *out_cu_class)
{
    uint8_t payload[224];
    uint8_t value[248];
    uint32_t vlen = 0u;

    if (envelope_revision == 0u) {
        envelope_revision = 1u;
    }
    if (ninlil_fabric_private_fbt1_encode(rec, payload)
        != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    if (ninlil_fabric_private_record_encode_envelope(
            (const uint8_t *)"FBT1",
            envelope_revision,
            payload,
            224u,
            value,
            248u,
            &vlen)
        != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    return storage_put_full_ex(
        fabric, key, 40u, value, vlen, old_value, old_value_len, out_cu_class);
}

/* Retention complete when epoch matches trusted clock and now past until. */
static int fabric_retention_complete(
    const uint8_t retention_clock_epoch_id[16],
    uint64_t retention_until_ms,
    const ninlil_time_sample_t *now)
{
    if (now == NULL || now->trust != NINLIL_CLOCK_TRUSTED) {
        return 0;
    }
    if (retention_until_ms == 0u
        || ninlil_fabric_private_id_is_zero(retention_clock_epoch_id)) {
        return 0;
    }
    if (!ninlil_fabric_private_memeq(
            retention_clock_epoch_id, now->clock_epoch_id.bytes, 16u)) {
        return 0;
    }
    return now->now_ms >= retention_until_ms ? 1 : 0;
}

static int fabric_policy_is_current(
    ninlil_fabric_private_t *fabric,
    const uint8_t policy_id[16],
    uint64_t revision)
{
    uint32_t i;
    uint64_t max_rev = 0u;
    for (i = 0u; i < FABRIC_RAM_POLICY_MAX; ++i) {
        if (fabric->policies[i].index.used == 0u) {
            continue;
        }
        if (!ninlil_fabric_private_memeq(
                fabric->policies[i].index.policy_id, policy_id, 16u)) {
            continue;
        }
        if (fabric->policies[i].index.revision > max_rev) {
            max_rev = fabric->policies[i].index.revision;
        }
    }
    return max_rev != 0u && revision == max_rev ? 1 : 0;
}

static int fabric_policy_has_blocking_ref(
    ninlil_fabric_private_t *fabric,
    const uint8_t policy_id[16],
    uint64_t revision,
    const ninlil_time_sample_t *now)
{
    uint32_t i;
    (void)now;
    for (i = 0u; i < NINLIL_FABRIC_ATTEMPT_MAX; ++i) {
        const fabric_attempt_slot_t *at = &fabric->attempts[i];
        if (at->used == 0u) {
            continue;
        }
        if (!ninlil_fabric_private_memeq(at->attempt.policy_id, policy_id, 16u)
            || at->attempt.policy_revision != revision) {
            continue;
        }
        /*
         * An FBA1 is a durable reference until its exact FULL erase has
         * completed. Eligibility alone is not absence: allowing removal here
         * could leave a dangling policy reference if the process stops before
         * the bounded GC step.
         */
        return 1;
    }
    for (i = 0u; i < FABRIC_RAM_TRIGGER_MAX; ++i) {
        const fabric_trigger_slot_t *ts = &fabric->triggers[i];
        if (ts->used == 0u) {
            continue;
        }
        if (!ninlil_fabric_private_memeq(ts->trigger.policy_id, policy_id, 16u)
            || ts->trigger.policy_revision != revision) {
            continue;
        }
        /* FBT1 remains a durable reference until bounded GC proves absence. */
        return 1;
    }
    return 0;
}

static int fabric_authority_has_blocking_ref(
    ninlil_fabric_private_t *fabric,
    const fabric_authority_slot_t *auth,
    const ninlil_time_sample_t *now)
{
    uint32_t i;
    (void)now;
    for (i = 0u; i < NINLIL_FABRIC_ATTEMPT_MAX; ++i) {
        const fabric_attempt_slot_t *at = &fabric->attempts[i];
        if (at->used == 0u) {
            continue;
        }
        if (at->attempt.authority_state != auth->authority_state
            || !ninlil_fabric_private_memeq(
                   at->attempt.authority_id, auth->authority_id, 16u)
            || at->attempt.authority_term != auth->authority_term
            || at->attempt.assignment_epoch != auth->assignment_epoch) {
            continue;
        }
        /* See the policy-reference case above: only durable absence unblocks. */
        return 1;
    }
    for (i = 0u; i < FABRIC_RAM_TRIGGER_MAX; ++i) {
        const fabric_trigger_slot_t *ts = &fabric->triggers[i];
        if (ts->used == 0u) {
            continue;
        }
        if (ts->trigger.authority_state != auth->authority_state
            || !ninlil_fabric_private_memeq(
                   ts->trigger.authority_id, auth->authority_id, 16u)
            || ts->trigger.authority_term != auth->authority_term
            || ts->trigger.assignment_epoch != auth->assignment_epoch) {
            continue;
        }
        /* See the policy-reference case: only durable absence unblocks. */
        return 1;
    }
    return 0;
}

static int fabric_sample_now(
    ninlil_fabric_private_t *fabric, ninlil_time_sample_t *out_now)
{
    ninlil_fabric_private_memzero(out_now, sizeof(*out_now));
    out_now->abi_version = NINLIL_ABI_VERSION;
    out_now->struct_size = (uint16_t)sizeof(*out_now);
    if (fabric->clock.now(fabric->clock.user, out_now) != NINLIL_PORT_OK
        || out_now->trust != NINLIL_CLOCK_TRUSTED) {
        return 0;
    }
    return 1;
}

/*
 * ADR-0017 adoption: full RO scan. Accept only empty namespace or existing
 * snapshot with FBM1 exact-1. FBM1-absent with other records = CORRUPT.
 * Empty: RW re-scan still empty, put only FBM1 rev1 FULL, then reopen.
 */
static ninlil_fabric_private_status_t namespace_scan_counts(
    ninlil_fabric_private_t *fabric,
    ninlil_storage_txn_t txn,
    uint32_t *out_total,
    uint32_t *out_fbm1,
    uint8_t *out_fbm1_value,
    uint32_t *out_fbm1_vlen,
    ninlil_fabric_private_common_envelope_t *out_fbm1_env,
    ninlil_fabric_private_fbm1_t *out_fbm1_meta)
{
    ninlil_storage_iter_t iter = NULL;
    ninlil_storage_status_t st;
    ninlil_bytes_view_t prefix;
    uint8_t key_buf[80];
    uint8_t value_buf[NINLIL_FABRIC_VALUE_CEILING];
    ninlil_mut_bytes_t key_mut;
    ninlil_mut_bytes_t value_mut;
    uint32_t total = 0u;
    uint32_t fbm1 = 0u;
    uint8_t prev_key[80];
    uint32_t prev_len = 0u;
    int have_prev = 0;

    *out_total = 0u;
    *out_fbm1 = 0u;
    *out_fbm1_vlen = 0u;
    prefix.data = NULL;
    prefix.length = 0u;
    st = fabric->storage.iter_open(
        fabric->storage.user, txn, prefix, &iter);
    if (st != NINLIL_STORAGE_OK) {
        return map_storage_status(st);
    }
    for (;;) {
        key_mut.data = key_buf;
        key_mut.capacity = sizeof(key_buf);
        key_mut.length = 0u;
        value_mut.data = value_buf;
        value_mut.capacity = sizeof(value_buf);
        value_mut.length = 0u;
        st = fabric->storage.iter_next(
            fabric->storage.user, iter, &key_mut, &value_mut);
        if (st == NINLIL_STORAGE_NOT_FOUND) {
            break;
        }
        if (st != NINLIL_STORAGE_OK) {
            fabric->storage.iter_close(fabric->storage.user, iter);
            return map_storage_status(st);
        }
        if (!fabric_is_recognized_magic(key_buf, key_mut.length)) {
            /* Foreign keys allowed only if no recognized fabric rows mixed
             * in a way that breaks empty detection; count them as total. */
            total++;
            continue;
        }
        total++;
        if (have_prev != 0) {
            /* unsigned-lexicographic order: non-decreasing */
            uint32_t n =
                prev_len < key_mut.length ? prev_len : key_mut.length;
            int cmp = 0;
            uint32_t k;
            for (k = 0u; k < n; ++k) {
                if (prev_key[k] < key_buf[k]) {
                    cmp = -1;
                    break;
                }
                if (prev_key[k] > key_buf[k]) {
                    cmp = 1;
                    break;
                }
            }
            if (cmp == 0) {
                if (prev_len < key_mut.length) {
                    cmp = -1;
                } else if (prev_len > key_mut.length) {
                    cmp = 1;
                }
            }
            if (cmp > 0
                || (cmp == 0 && prev_len == key_mut.length
                    && ninlil_fabric_private_memeq(
                           prev_key, key_buf, prev_len))) {
                fabric->storage.iter_close(fabric->storage.user, iter);
                return NINLIL_FABRIC_PRIVATE_CORRUPT;
            }
        }
        if (key_mut.length <= sizeof(prev_key)) {
            (void)memcpy(prev_key, key_buf, key_mut.length);
            prev_len = key_mut.length;
            have_prev = 1;
        }
        if (key_buf[2] == (uint8_t)'M' && key_buf[3] == (uint8_t)'1') {
            ninlil_fabric_private_common_envelope_t env;
            const uint8_t *pl = NULL;
            ninlil_fabric_private_fbm1_t meta;
            if (key_mut.length != 4u || value_mut.length > 64u) {
                fabric->storage.iter_close(fabric->storage.user, iter);
                return NINLIL_FABRIC_PRIVATE_CORRUPT;
            }
            if (ninlil_fabric_private_record_decode_envelope(
                    value_buf, value_mut.length, key_buf, 40u, &env, &pl)
                    != NINLIL_FABRIC_PRIVATE_RECORD_OK
                || ninlil_fabric_private_fbm1_decode(pl, &meta)
                    != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
                fabric->storage.iter_close(fabric->storage.user, iter);
                return NINLIL_FABRIC_PRIVATE_CORRUPT;
            }
            fbm1++;
            if (fbm1 == 1u) {
                (void)memcpy(out_fbm1_value, value_buf, value_mut.length);
                *out_fbm1_vlen = value_mut.length;
                *out_fbm1_env = env;
                *out_fbm1_meta = meta;
            }
        }
    }
    fabric->storage.iter_close(fabric->storage.user, iter);
    *out_total = total;
    *out_fbm1 = fbm1;
    return NINLIL_FABRIC_PRIVATE_OK;
}

static ninlil_fabric_private_status_t adopt_or_open_meta(
    ninlil_fabric_private_t *fabric)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t st;
    uint8_t key[4];
    uint8_t value[64];
    uint8_t payload[40];
    uint8_t fbm1_value[64];
    uint32_t fbm1_vlen = 0u;
    uint32_t total = 0u;
    uint32_t fbm1 = 0u;
    ninlil_fabric_private_common_envelope_t fbm1_env;
    ninlil_fabric_private_fbm1_t meta;
    ninlil_fabric_private_status_t rc;

    ninlil_fabric_private_memzero(&fbm1_env, sizeof(fbm1_env));
    ninlil_fabric_private_memzero(&meta, sizeof(meta));
    ninlil_fabric_private_key_fbm1(key);

    st = fabric->storage.begin(
        fabric->storage.user, fabric->storage_handle,
        NINLIL_STORAGE_READ_ONLY, &txn);
    if (st != NINLIL_STORAGE_OK) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    rc = namespace_scan_counts(
        fabric, txn, &total, &fbm1, fbm1_value, &fbm1_vlen, &fbm1_env, &meta);
    {
        ninlil_storage_status_t rb =
            fabric->storage.rollback(fabric->storage.user, txn);
        txn = NULL;
        if (rc != NINLIL_FABRIC_PRIVATE_OK) {
            return rc;
        }
        if (rb != NINLIL_STORAGE_OK) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
    }

    if (fbm1 > 1u) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    if (fbm1 == 1u) {
        /* Existing snapshot: FBM1 exact-1; reload validates the rest. */
        fabric->meta = meta;
        fabric->meta_revision = fbm1_env.revision;
        return NINLIL_FABRIC_PRIVATE_OK;
    }
    /* fbm1 == 0 */
    if (total != 0u) {
        /* Other records without FBM1: not a repairable fresh adopt. */
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }

    /* Fresh adoption: RW full-scan still empty, put only FBM1 rev1 FULL. */
    st = fabric->storage.begin(
        fabric->storage.user, fabric->storage_handle,
        NINLIL_STORAGE_READ_WRITE, &txn);
    if (st != NINLIL_STORAGE_OK) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    rc = namespace_scan_counts(
        fabric, txn, &total, &fbm1, fbm1_value, &fbm1_vlen, &fbm1_env, &meta);
    if (rc != NINLIL_FABRIC_PRIVATE_OK) {
        (void)fabric->storage.rollback(fabric->storage.user, txn);
        return rc;
    }
    if (total != 0u || fbm1 != 0u) {
        /* Concurrent init: do not overwrite. */
        (void)fabric->storage.rollback(fabric->storage.user, txn);
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }

    ninlil_fabric_private_memzero(&meta, sizeof(meta));
    meta.source_schema = 1u;
    meta.target_schema = 1u;
    meta.migration_state = NINLIL_FABRIC_PRIVATE_MIGRATION_CLEAN;
    meta.migration_generation = 1u;
    meta.rollback_floor_generation = 0u;
    meta.outer_availability_epoch = 1u;
    meta.outer_available = 0u;
    if (ninlil_fabric_private_fbm1_encode(&meta, payload)
        != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
        (void)fabric->storage.rollback(fabric->storage.user, txn);
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    {
        uint32_t vlen = 0u;
        ninlil_bytes_view_t kv;
        ninlil_bytes_view_t vv;
        if (ninlil_fabric_private_record_encode_envelope(
                key, 1u, payload, 40u, value, 64u, &vlen)
            != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
            (void)fabric->storage.rollback(fabric->storage.user, txn);
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
        kv.data = key;
        kv.length = 4u;
        vv.data = value;
        vv.length = vlen;
        st = fabric->storage.put(fabric->storage.user, txn, kv, vv);
        if (st != NINLIL_STORAGE_OK) {
            (void)fabric->storage.rollback(fabric->storage.user, txn);
            return map_storage_status(st);
        }
        st = fabric->storage.commit(
            fabric->storage.user, txn, NINLIL_DURABILITY_FULL);
        txn = NULL;
        if (st == NINLIL_STORAGE_COMMIT_UNKNOWN) {
            /* Close/reopen classify ABSENT or exact new FBM1 only. */
            uint8_t obs[64];
            uint32_t obs_len = 0u;
            int present = 0;
            uint32_t klass;
            rc = storage_reopen_namespace(fabric);
            if (rc != NINLIL_FABRIC_PRIVATE_OK) {
                return rc;
            }
            rc = storage_read_key_readonly(
                fabric, key, 4u, obs, sizeof(obs), &obs_len, &present);
            if (rc != NINLIL_FABRIC_PRIVATE_OK) {
                return rc;
            }
            klass = ninlil_fabric_private_commit_unknown_classify(
                NULL, 0u, NULL, 0u, key, 4u, value, vlen,
                present ? key : NULL, present ? 4u : 0u,
                present ? obs : NULL, obs_len, present);
            if (klass == NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_CORRUPT) {
                return NINLIL_FABRIC_PRIVATE_CORRUPT;
            }
            /* ABSENT or NEW: create call returns CU; no publish. */
            return NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN;
        }
        if (st != NINLIL_STORAGE_OK) {
            return map_storage_status(st);
        }
    }

    /* Commit OK: reopen and accept only existing FBM1 exact-1 snapshot. */
    rc = storage_reopen_namespace(fabric);
    if (rc != NINLIL_FABRIC_PRIVATE_OK) {
        return rc;
    }
    st = fabric->storage.begin(
        fabric->storage.user, fabric->storage_handle,
        NINLIL_STORAGE_READ_ONLY, &txn);
    if (st != NINLIL_STORAGE_OK) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    rc = namespace_scan_counts(
        fabric, txn, &total, &fbm1, fbm1_value, &fbm1_vlen, &fbm1_env, &meta);
    {
        ninlil_storage_status_t rb =
            fabric->storage.rollback(fabric->storage.user, txn);
        if (rc != NINLIL_FABRIC_PRIVATE_OK) {
            return rc;
        }
        if (rb != NINLIL_STORAGE_OK) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
    }
    if (fbm1 != 1u) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    fabric->meta = meta;
    fabric->meta_revision = fbm1_env.revision;
    return NINLIL_FABRIC_PRIVATE_OK;
}

static void fbr1_fill_from_descriptor_state(
    ninlil_fabric_private_fbr1_t *rec,
    const ninlil_fabric_link_descriptor_v1_t *d,
    const ninlil_fabric_link_state_v1_t *state,
    uint8_t lifecycle)
{
    ninlil_fabric_private_memzero(rec, sizeof(*rec));
    (void)memcpy(rec->instance_id, d->instance_id.bytes, 16u);
    rec->link_kind = d->link_kind;
    rec->direction_mask = d->direction_mask;
    rec->capability_flags = d->capability_flags;
    rec->descriptor_revision = d->descriptor_revision;
    (void)memcpy(rec->descriptor_digest, d->descriptor_digest, 32u);
    (void)memcpy(rec->security_profile_id, d->security_profile_id.bytes, 16u);
    rec->security_capability_flags = d->security_capability_flags;
    (void)memcpy(rec->security_binding_digest, d->security_binding_digest, 32u);
    rec->attestation_epoch = d->attestation_epoch;
    (void)memcpy(
        rec->attestation_clock_epoch_id,
        d->attestation_clock_epoch_id.bytes,
        16u);
    rec->attestation_expires_at_ms = d->attestation_expires_at_ms;
    (void)memcpy(rec->attestation_digest, d->attestation_digest, 32u);
    (void)memcpy(
        rec->authenticated_peer_runtime_id,
        d->authenticated_peer_runtime_id.bytes,
        16u);
    (void)memcpy(
        rec->attachment_authority_id, d->attachment_authority_id.bytes, 16u);
    (void)memcpy(
        rec->attachment_binding_digest, d->attachment_binding_digest, 32u);
    rec->maximum_packet_bytes = d->maximum_packet_bytes;
    rec->maximum_transfer_bytes = d->maximum_transfer_bytes;
    rec->latency_class = d->latency_class;
    rec->cost_class = d->cost_class;
    rec->reservation_capacity = d->reservation_capacity;
    rec->availability_epoch = state->availability_epoch;
    (void)memcpy(
        rec->availability_clock_epoch_id,
        state->availability_clock_epoch_id.bytes,
        16u);
    rec->available = (uint8_t)state->available;
    rec->lifecycle = lifecycle;
    rec->availability_expires_at_ms = state->available_until_ms;
    rec->peer_nfl1_version = d->peer_nfl1_version;
    rec->peer_fabric_capability_flags = d->peer_fabric_capability_flags;
    rec->configuration_revision = d->configuration_revision;
    (void)memcpy(rec->configuration_digest, d->configuration_digest, 32u);
}

static int packet_link_ops_exact(
    const ninlil_fabric_packet_link_ops_v1_t *a,
    const ninlil_fabric_packet_link_ops_v1_t *b)
{
    return a->open == b->open && a->close == b->close
        && a->start_send == b->start_send && a->poll_send == b->poll_send
        && a->cancel_send == b->cancel_send
        && a->release_send == b->release_send
        && a->receive_next == b->receive_next
        && a->release_received == b->release_received
        && a->state == b->state && a->user == b->user;
}

static fabric_fbr1_pin_t *fbr1_pin_find(
    ninlil_fabric_private_t *fabric, const uint8_t instance_id[16])
{
    uint32_t i;
    for (i = 0u; i < NINLIL_FABRIC_REGISTRY_MAX; ++i) {
        if (fabric->fbr1_pins[i].used != 0u
            && ninlil_fabric_private_memeq(
                   fabric->fbr1_pins[i].instance_id, instance_id, 16u)) {
            return &fabric->fbr1_pins[i];
        }
    }
    return NULL;
}

static fabric_fbr1_pin_t *fbr1_pin_alloc(ninlil_fabric_private_t *fabric)
{
    uint32_t i;
    for (i = 0u; i < NINLIL_FABRIC_REGISTRY_MAX; ++i) {
        if (fabric->fbr1_pins[i].used == 0u) {
            return &fabric->fbr1_pins[i];
        }
    }
    return NULL;
}

static void fbr1_pin_store(
    fabric_fbr1_pin_t *pin,
    uint64_t record_revision,
    const ninlil_fabric_private_fbr1_t *body,
    const uint8_t key[20],
    const uint8_t value[372])
{
    ninlil_fabric_private_memzero(pin, sizeof(*pin));
    pin->used = 1u;
    pin->record_revision = record_revision;
    (void)memcpy(pin->instance_id, body->instance_id, 16u);
    ninlil_fabric_private_registry_record_digest(
        key, value, pin->registry_digest);
    (void)memcpy(pin->descriptor_digest, body->descriptor_digest, 32u);
    pin->availability_epoch = body->availability_epoch;
    pin->availability_expires_at_ms = body->availability_expires_at_ms;
    pin->available = body->available;
}

/*
 * FBA1 keeps the exact FBR1 selected at dispatch time, while schema 1 keeps
 * only the current FBR1 row. Prove that a newer row is availability-only by
 * rebuilding the historical value from current immutable fields plus FBA1's
 * saved availability tuple and comparing the original full-record digest.
 */
static ninlil_fabric_private_status_t fba1_registry_pin_matches(
    ninlil_fabric_private_t *fabric,
    const fabric_attempt_slot_t *attempt,
    const fabric_fbr1_pin_t *pin)
{
    ninlil_fabric_private_common_envelope_t env;
    ninlil_fabric_private_fbr1_t current;
    ninlil_fabric_private_fbr1_t historical;
    ninlil_fabric_private_status_t st;
    const uint8_t *payload = NULL;
    uint8_t key[20];
    uint8_t digest[32];
    uint32_t value_len = 0u;
    uint32_t historical_len = 0u;
    int present = 0;

    if (fabric == NULL || attempt == NULL || pin == NULL) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    if (!ninlil_fabric_private_memeq(
            pin->descriptor_digest,
            attempt->attempt.descriptor_digest,
            32u)
        || pin->record_revision < attempt->attempt.registry_record_revision) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    if (pin->record_revision == attempt->attempt.registry_record_revision) {
        return ninlil_fabric_private_memeq(
                   pin->registry_digest,
                   attempt->attempt.registry_record_digest,
                   32u)
            ? NINLIL_FABRIC_PRIVATE_OK
            : NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    if (pin->availability_epoch <= attempt->attempt.availability_epoch
        || pin->record_revision - attempt->attempt.registry_record_revision
            != pin->availability_epoch - attempt->attempt.availability_epoch) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }

    ninlil_fabric_private_key_fbr1(
        attempt->attempt.selected_path_id, key);
    st = storage_read_key_readonly(
        fabric,
        key,
        sizeof(key),
        fabric->decode_scratch,
        sizeof(fabric->decode_scratch),
        &value_len,
        &present);
    if (st != NINLIL_FABRIC_PRIVATE_OK || present == 0 || value_len != 372u) {
        return st == NINLIL_FABRIC_PRIVATE_OK
            ? NINLIL_FABRIC_PRIVATE_CORRUPT
            : st;
    }
    ninlil_fabric_private_registry_record_digest(
        key, fabric->decode_scratch, digest);
    if (!ninlil_fabric_private_memeq(digest, pin->registry_digest, 32u)
        || ninlil_fabric_private_record_decode_envelope(
               fabric->decode_scratch,
               value_len,
               (const uint8_t *)"FBR1",
               NINLIL_FABRIC_FBR1_PAYLOAD_BYTES,
               &env,
               &payload)
            != NINLIL_FABRIC_PRIVATE_RECORD_OK
        || ninlil_fabric_private_fbr1_decode(payload, &current)
            != NINLIL_FABRIC_PRIVATE_RECORD_OK
        || env.revision != pin->record_revision
        || !ninlil_fabric_private_memeq(
               current.instance_id,
               attempt->attempt.selected_path_id,
               16u)
        || current.availability_epoch != pin->availability_epoch
        || !ninlil_fabric_private_memeq(
               current.availability_clock_epoch_id,
               attempt->attempt.availability_clock_epoch_id,
               16u)
        || current.available != pin->available
        || current.lifecycle != NINLIL_FABRIC_PRIVATE_LIFECYCLE_ACTIVE
        || current.availability_expires_at_ms
            != pin->availability_expires_at_ms
        || !ninlil_fabric_private_memeq(
               current.descriptor_digest, pin->descriptor_digest, 32u)) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }

    historical = current;
    historical.availability_epoch = attempt->attempt.availability_epoch;
    (void)memcpy(
        historical.availability_clock_epoch_id,
        attempt->attempt.availability_clock_epoch_id,
        16u);
    historical.available = attempt->attempt.availability_state;
    historical.lifecycle = NINLIL_FABRIC_PRIVATE_LIFECYCLE_ACTIVE;
    historical.availability_expires_at_ms =
        attempt->attempt.availability_expires_at_ms;
    if (ninlil_fabric_private_fbr1_encode(
            &historical, fabric->encode_scratch)
            != NINLIL_FABRIC_PRIVATE_RECORD_OK
        || ninlil_fabric_private_record_encode_envelope(
               (const uint8_t *)"FBR1",
               attempt->attempt.registry_record_revision,
               fabric->encode_scratch,
               NINLIL_FABRIC_FBR1_PAYLOAD_BYTES,
               fabric->decode_scratch,
               sizeof(fabric->decode_scratch),
               &historical_len)
            != NINLIL_FABRIC_PRIVATE_RECORD_OK
        || historical_len != 372u) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    ninlil_fabric_private_registry_record_digest(
        key, fabric->decode_scratch, digest);
    return ninlil_fabric_private_memeq(
               digest, attempt->attempt.registry_record_digest, 32u)
        ? NINLIL_FABRIC_PRIVATE_OK
        : NINLIL_FABRIC_PRIVATE_CORRUPT;
}

#define FABRIC_KNOWN_CAP_MASK                                              \
    (NINLIL_FABRIC_CAP_SLEEP_COMPATIBLE | NINLIL_FABRIC_CAP_UNICAST        \
        | NINLIL_FABRIC_CAP_BROADCAST | NINLIL_FABRIC_CAP_RESERVATION     \
        | NINLIL_FABRIC_CAP_REGULATED_RF | NINLIL_FABRIC_CAP_CUSTODY       \
        | NINLIL_FABRIC_CAP_EVIDENCE)
#define FABRIC_KNOWN_SEC_MASK                                              \
    (NINLIL_FABRIC_SECURITY_INTEGRITY                                      \
        | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY                           \
        | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION                         \
        | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS)

static int fabric_key_magic_eq(
    const uint8_t *key, uint32_t key_len, const char magic[4], uint32_t expect_len)
{
    return key_len == expect_len && key[0] == (uint8_t)magic[0]
        && key[1] == (uint8_t)magic[1] && key[2] == (uint8_t)magic[2]
        && key[3] == (uint8_t)magic[3];
}

static int fabric_is_recognized_magic(const uint8_t *key, uint32_t key_len)
{
    if (key_len < 4u || key[0] != (uint8_t)'F' || key[1] != (uint8_t)'B') {
        return 0;
    }
    return (key[2] == (uint8_t)'M' && key[3] == (uint8_t)'1')
        || (key[2] == (uint8_t)'R' && key[3] == (uint8_t)'1')
        || (key[2] == (uint8_t)'P' && key[3] == (uint8_t)'1')
        || (key[2] == (uint8_t)'C' && key[3] == (uint8_t)'1')
        || (key[2] == (uint8_t)'A' && key[3] == (uint8_t)'1')
        || (key[2] == (uint8_t)'T' && key[3] == (uint8_t)'1');
}

static ninlil_fabric_private_status_t reload_close_ro(
    ninlil_fabric_private_t *fabric,
    ninlil_storage_iter_t *iter,
    ninlil_storage_txn_t *txn,
    ninlil_fabric_private_status_t status)
{
    ninlil_storage_status_t st;
    if (iter != NULL && *iter != NULL) {
        fabric->storage.iter_close(fabric->storage.user, *iter);
        *iter = NULL;
    }
    if (txn != NULL && *txn != NULL) {
        st = fabric->storage.rollback(fabric->storage.user, *txn);
        *txn = NULL;
        if (status == NINLIL_FABRIC_PRIVATE_OK && st != NINLIL_STORAGE_OK) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
    }
    return status;
}

static ninlil_fabric_private_status_t validate_fbp1_semantics(
    const ninlil_fabric_private_fbp1_t *full)
{
    uint32_t i;
    uint32_t j;
    uint8_t expected[32];
    ninlil_fabric_private_fbp1_t tmp;

    if (ninlil_fabric_private_id_is_zero(full->policy_id)
        || full->revision == 0u
        || ninlil_fabric_private_is_zero(full->service_identity_digest, 32u)
        || full->candidate_count == 0u || full->candidate_count > 8u) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    if (full->direction != NINLIL_FABRIC_POLICY_DIRECTION_FORWARD
        && full->direction != NINLIL_FABRIC_POLICY_DIRECTION_REVERSE) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    if (full->traffic_class != NINLIL_FABRIC_TRAFFIC_APPLICATION
        && full->traffic_class != NINLIL_FABRIC_TRAFFIC_CONTROL) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    if (full->scope_selector != NINLIL_FABRIC_SCOPE_SOURCE_RUNTIME
        && full->scope_selector != NINLIL_FABRIC_SCOPE_TARGET_RUNTIME) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    if (full->authority_mode != NINLIL_FABRIC_AUTHORITY_MODE_ABSENT_ALLOWED
        && full->authority_mode != NINLIL_FABRIC_AUTHORITY_MODE_BOUND_REQUIRED) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    if ((full->required_capability_flags & ~FABRIC_KNOWN_CAP_MASK) != 0u
        || (full->required_security_flags & ~FABRIC_KNOWN_SEC_MASK) != 0u) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    for (i = 0u; i < full->candidate_count; ++i) {
        if (ninlil_fabric_private_id_is_zero(full->candidates[i].instance_id)
            || full->candidates[i].flags != 0u
            || full->candidates[i].reservation_units == 0u
            || full->candidates[i].reserved_zero != 0u) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
        for (j = 0u; j < i; ++j) {
            if (ninlil_fabric_private_memeq(
                    full->candidates[i].instance_id,
                    full->candidates[j].instance_id,
                    16u)) {
                return NINLIL_FABRIC_PRIVATE_CORRUPT;
            }
        }
    }
    for (i = full->candidate_count; i < 8u; ++i) {
        if (!ninlil_fabric_private_is_zero(
                (const uint8_t *)&full->candidates[i],
                sizeof(full->candidates[i]))) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
    }
    tmp = *full;
    ninlil_fabric_private_fbp1_compute_digest(&tmp);
    if (!ninlil_fabric_private_memeq(
            tmp.canonical_digest, full->canonical_digest, 32u)) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    (void)expected;
    return NINLIL_FABRIC_PRIVATE_OK;
}

static ninlil_fabric_private_status_t validate_fbc1_semantics(
    const ninlil_fabric_private_fbc1_t *full)
{
    uint8_t expected[32];

    if (ninlil_fabric_private_id_is_zero(full->binding_id)
        || full->assignment_revision == 0u
        || ninlil_fabric_private_is_zero(full->service_identity_digest, 32u)
        || ninlil_fabric_private_id_is_zero(full->policy_id)
        || full->policy_revision == 0u
        || ninlil_fabric_private_is_zero(full->policy_digest, 32u)
        || full->reserved_zero_u32 != 0u || full->reserved_zero_u64 != 0u) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    if (full->direction != NINLIL_FABRIC_POLICY_DIRECTION_FORWARD
        && full->direction != NINLIL_FABRIC_POLICY_DIRECTION_REVERSE) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    if (full->traffic_class != NINLIL_FABRIC_TRAFFIC_APPLICATION
        && full->traffic_class != NINLIL_FABRIC_TRAFFIC_CONTROL) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    if (full->scope_selector != NINLIL_FABRIC_SCOPE_SOURCE_RUNTIME
        && full->scope_selector != NINLIL_FABRIC_SCOPE_TARGET_RUNTIME) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    if (full->authority_state == NINLIL_FABRIC_AUTHORITY_ABSENT) {
        if (!ninlil_fabric_private_id_is_zero(full->authority_id)
            || full->authority_term != 0u || full->assignment_epoch != 0u) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
    } else if (full->authority_state == NINLIL_FABRIC_AUTHORITY_BOUND) {
        if (ninlil_fabric_private_id_is_zero(full->authority_id)
            || full->authority_term == 0u || full->assignment_epoch == 0u
            || ninlil_fabric_private_id_is_zero(full->owner_scope_id)
            || ninlil_fabric_private_is_zero(full->owner_tuple_digest, 32u)) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
        ninlil_fabric_private_owner_tuple_digest(
            full->owner_tuple_canonical, expected);
        if (!ninlil_fabric_private_memeq(
                expected, full->owner_tuple_digest, 32u)) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
    } else {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    return NINLIL_FABRIC_PRIVATE_OK;
}

static ninlil_fabric_private_status_t validate_fba1_semantics(
    const ninlil_fabric_private_fba1_t *full, const uint8_t key[76])
{
    uint8_t expect_key[76];
    uint8_t expect_ld[32];

    if (full->state < NINLIL_FABRIC_PRIVATE_ATTEMPT_PREPARED
        || full->state > NINLIL_FABRIC_PRIVATE_ATTEMPT_DRAINED) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    if (ninlil_fabric_private_id_is_zero(full->transaction_id)
        || ninlil_fabric_private_id_is_zero(full->attempt_id)
        || ninlil_fabric_private_is_zero(full->foundation_message_digest, 32u)
        || ninlil_fabric_private_id_is_zero(full->policy_id)
        || full->policy_revision == 0u
        || ninlil_fabric_private_is_zero(full->policy_digest, 32u)
        || ninlil_fabric_private_id_is_zero(full->selected_path_id)
        || full->nfl1_length < NINLIL_FABRIC_NFL1_STRUCTURAL_MIN
        || full->nfl1_length > NINLIL_FABRIC_NFL1_STRUCTURAL_MAX
        || ninlil_fabric_private_is_zero(full->nfl1_sha256, 32u)
        || ninlil_fabric_private_id_is_zero(
               full->retry_lifetime_clock_epoch_id)
        || ninlil_fabric_private_id_is_zero(full->permit_id)
        || full->permit_expires_at_ms == 0u
        || (full->permit_claim_state != NINLIL_FABRIC_PRIVATE_PERMIT_CLEAR
            && full->permit_claim_state
                != NINLIL_FABRIC_PRIVATE_PERMIT_CLAIMED)) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    if (full->state == NINLIL_FABRIC_PRIVATE_ATTEMPT_DRAINED
        && (full->runtime_terminal_revision == 0u
            || ninlil_fabric_private_id_is_zero(
                   full->retention_clock_epoch_id)
            || full->retention_until_ms == 0u)) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    if (full->state
            == NINLIL_FABRIC_PRIVATE_ATTEMPT_RETRYABLE_NO_ACCEPT
        && full->permit_claim_state
            != NINLIL_FABRIC_PRIVATE_PERMIT_CLEAR) {
        /* A retryable row proves a definite provider non-accept. */
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    ninlil_fabric_private_key_fba1(
        full->transaction_id,
        full->attempt_id,
        full->message_kind,
        full->response_slot,
        full->foundation_message_digest,
        expect_key);
    if (!ninlil_fabric_private_memeq(expect_key, key, 76u)) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    ninlil_fabric_private_local_dispatch_id(key, expect_ld);
    if (!ninlil_fabric_private_memeq(expect_ld, full->local_dispatch_id, 32u)) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    return NINLIL_FABRIC_PRIVATE_OK;
}

static ninlil_fabric_private_status_t validate_fbt1_semantics(
    const ninlil_fabric_private_fbt1_t *full, const uint8_t key[40])
{
    uint8_t expect_key[40];

    if (ninlil_fabric_private_id_is_zero(full->transaction_id)
        || ninlil_fabric_private_id_is_zero(full->triggering_attempt_id)
        || full->reserved_zero_u32 != 0u) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    ninlil_fabric_private_key_fbt1(
        full->transaction_id,
        full->triggering_attempt_id,
        full->triggering_kind,
        expect_key);
    if (!ninlil_fabric_private_memeq(expect_key, key, 40u)) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    return NINLIL_FABRIC_PRIVATE_OK;
}

/*
 * Restart reconciliation: reload durable FBP1/FBC1/FBA1/FBT1 into RAM.
 * Recognized current Fabric rows that fail validation fail CORRUPT (no silent drop).
 * PREPARED/LINK_RETAINED become FENCED_UNKNOWN via FULL replacement after RO close.
 */
static ninlil_fabric_private_status_t reload_durable_state(
    ninlil_fabric_private_t *fabric)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_iter_t iter = NULL;
    ninlil_storage_status_t st;
    ninlil_bytes_view_t prefix;
    uint8_t key_buf[80];
    uint8_t value_buf[NINLIL_FABRIC_VALUE_CEILING];
    ninlil_mut_bytes_t key_mut;
    ninlil_mut_bytes_t value_mut;
    uint32_t fence_slots[NINLIL_FABRIC_ATTEMPT_MAX];
    uint32_t fence_count = 0u;
    uint32_t ai;
    uint32_t i;
    ninlil_fabric_private_status_t rc;
    prefix.data = NULL;
    prefix.length = 0u;
    st = fabric->storage.begin(
        fabric->storage.user, fabric->storage_handle,
        NINLIL_STORAGE_READ_ONLY, &txn);
    if (st != NINLIL_STORAGE_OK) {
        return map_storage_status(st);
    }
    st = fabric->storage.iter_open(
        fabric->storage.user, txn, prefix, &iter);
    if (st != NINLIL_STORAGE_OK) {
        return reload_close_ro(fabric, &iter, &txn, map_storage_status(st));
    }

    for (;;) {
        key_mut.data = key_buf;
        key_mut.capacity = sizeof(key_buf);
        key_mut.length = 0u;
        value_mut.data = value_buf;
        value_mut.capacity = sizeof(value_buf);
        value_mut.length = 0u;
        st = fabric->storage.iter_next(
            fabric->storage.user, iter, &key_mut, &value_mut);
        if (st == NINLIL_STORAGE_NOT_FOUND) {
            break;
        }
        if (st != NINLIL_STORAGE_OK) {
            return reload_close_ro(
                fabric, &iter, &txn, map_storage_status(st));
        }
        if (!fabric_is_recognized_magic(key_buf, key_mut.length)) {
            continue; /* foreign namespace keys only */
        }
        /* Recognized magic with wrong key length is durable corruption. */
        if (key_buf[2] == (uint8_t)'M' && key_buf[3] == (uint8_t)'1') {
            if (key_mut.length != 4u) {
                return reload_close_ro(
                    fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
            }
            continue; /* meta already adopted */
        }
        if (key_buf[2] == (uint8_t)'R' && key_buf[3] == (uint8_t)'1') {
            ninlil_fabric_private_common_envelope_t env;
            const uint8_t *pl = NULL;
            ninlil_fabric_private_fbr1_t full;
            uint8_t expect_key[20];
            fabric_fbr1_pin_t *pin;
            if (key_mut.length != 20u || value_mut.length > 372u) {
                return reload_close_ro(
                    fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
            }
            if (ninlil_fabric_private_record_decode_envelope(
                    value_buf,
                    value_mut.length,
                    (const uint8_t *)"FBR1",
                    348u,
                    &env,
                    &pl)
                    != NINLIL_FABRIC_PRIVATE_RECORD_OK
                || ninlil_fabric_private_fbr1_decode(pl, &full)
                    != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
                return reload_close_ro(
                    fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
            }
            ninlil_fabric_private_key_fbr1(full.instance_id, expect_key);
            if (!ninlil_fabric_private_memeq(expect_key, key_buf, 20u)
                || ninlil_fabric_private_id_is_zero(full.instance_id)
                || full.availability_epoch == 0u
                || (full.available != 0u && full.available != 1u)
                || (full.lifecycle != NINLIL_FABRIC_PRIVATE_LIFECYCLE_ACTIVE
                    && full.lifecycle
                        != NINLIL_FABRIC_PRIVATE_LIFECYCLE_DRAINING)
                || env.revision == 0u) {
                return reload_close_ro(
                    fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
            }
            if (fbr1_pin_find(fabric, full.instance_id) != NULL) {
                return reload_close_ro(
                    fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
            }
            pin = fbr1_pin_alloc(fabric);
            if (pin == NULL) {
                return reload_close_ro(
                    fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
            }
            if (value_mut.length != 372u) {
                return reload_close_ro(
                    fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
            }
            fbr1_pin_store(pin, env.revision, &full, key_buf, value_buf);
            continue;
        }

        if (fabric_key_magic_eq(key_buf, key_mut.length, "FBP1", 28u)) {
            ninlil_fabric_private_common_envelope_t env;
            const uint8_t *pl = NULL;
            ninlil_fabric_private_fbp1_t full;
            uint8_t expect_key[28];
            uint32_t free_slot = FABRIC_RAM_POLICY_MAX;
            if (ninlil_fabric_private_record_decode_envelope(
                    value_buf,
                    value_mut.length,
                    (const uint8_t *)"FBP1",
                    328u,
                    &env,
                    &pl)
                    != NINLIL_FABRIC_PRIVATE_RECORD_OK
                || ninlil_fabric_private_fbp1_decode(pl, &full)
                    != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
                return reload_close_ro(
                    fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
            }
            if (validate_fbp1_semantics(&full) != NINLIL_FABRIC_PRIVATE_OK) {
                return reload_close_ro(
                    fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
            }
            ninlil_fabric_private_key_fbp1(
                full.policy_id, full.revision, expect_key);
            if (!ninlil_fabric_private_memeq(expect_key, key_buf, 28u)) {
                return reload_close_ro(
                    fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
            }
            for (i = 0u; i < FABRIC_RAM_POLICY_MAX; ++i) {
                if (fabric->policies[i].index.used != 0u
                    && ninlil_fabric_private_memeq(
                           fabric->policies[i].index.policy_id,
                           full.policy_id,
                           16u)
                    && fabric->policies[i].index.revision == full.revision) {
                    return reload_close_ro(
                        fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
                }
                if (fabric->policies[i].index.used == 0u
                    && free_slot == FABRIC_RAM_POLICY_MAX) {
                    free_slot = i;
                }
            }
            if (free_slot == FABRIC_RAM_POLICY_MAX) {
                return reload_close_ro(
                    fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
            }
            {
                fabric_policy_slot_t *slot = &fabric->policies[free_slot];
                ninlil_fabric_private_memzero(slot, sizeof(*slot));
                slot->index.used = 1u;
                slot->index.revision = full.revision;
                slot->index.deadline_guard_ms = full.deadline_guard_ms;
                slot->index.family = full.family;
                slot->index.direction = full.direction;
                slot->index.required_capability_flags =
                    full.required_capability_flags;
                slot->index.required_security_flags =
                    full.required_security_flags;
                slot->index.minimum_packet_bytes = full.minimum_packet_bytes;
                slot->index.traffic_class = full.traffic_class;
                slot->index.scope_selector = full.scope_selector;
                slot->index.maximum_latency_class = full.maximum_latency_class;
                slot->index.maximum_cost_class = full.maximum_cost_class;
                (void)memcpy(slot->index.policy_id, full.policy_id, 16u);
                (void)memcpy(
                    slot->index.canonical_digest, full.canonical_digest, 32u);
                (void)memcpy(
                    slot->index.service_identity_digest,
                    full.service_identity_digest,
                    32u);
                slot->index.authority_mode = full.authority_mode;
                slot->index.candidate_count = (uint8_t)full.candidate_count;
                slot->record_revision = env.revision;
            }
        } else if (fabric_key_magic_eq(key_buf, key_mut.length, "FBC1", 20u)) {
            ninlil_fabric_private_common_envelope_t env;
            const uint8_t *pl = NULL;
            ninlil_fabric_private_fbc1_t full;
            uint8_t expect_key[20];
            uint32_t free_slot = FABRIC_RAM_AUTHORITY_MAX;
            if (ninlil_fabric_private_record_decode_envelope(
                    value_buf,
                    value_mut.length,
                    (const uint8_t *)"FBC1",
                    488u,
                    &env,
                    &pl)
                    != NINLIL_FABRIC_PRIVATE_RECORD_OK
                || ninlil_fabric_private_fbc1_decode(pl, &full)
                    != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
                return reload_close_ro(
                    fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
            }
            if (validate_fbc1_semantics(&full) != NINLIL_FABRIC_PRIVATE_OK) {
                return reload_close_ro(
                    fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
            }
            ninlil_fabric_private_key_fbc1(full.binding_id, expect_key);
            if (!ninlil_fabric_private_memeq(expect_key, key_buf, 20u)) {
                return reload_close_ro(
                    fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
            }
            for (i = 0u; i < FABRIC_RAM_AUTHORITY_MAX; ++i) {
                if (fabric->authorities[i].index.used != 0u
                    && ninlil_fabric_private_memeq(
                           fabric->authorities[i].index.binding_id,
                           full.binding_id,
                           16u)) {
                    return reload_close_ro(
                        fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
                }
                if (fabric->authorities[i].index.used == 0u
                    && free_slot == FABRIC_RAM_AUTHORITY_MAX) {
                    free_slot = i;
                }
            }
            if (free_slot == FABRIC_RAM_AUTHORITY_MAX) {
                return reload_close_ro(
                    fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
            }
            {
                fabric_authority_slot_t *slot =
                    &fabric->authorities[free_slot];
                ninlil_fabric_private_memzero(slot, sizeof(*slot));
                slot->index.used = 1u;
                slot->record_revision = full.assignment_revision;
                (void)memcpy(slot->index.binding_id, full.binding_id, 16u);
                (void)memcpy(
                    slot->index.service_identity_digest,
                    full.service_identity_digest,
                    32u);
                slot->index.family = full.family;
                slot->index.direction = full.direction;
                slot->index.traffic_class = full.traffic_class;
                slot->index.scope_selector = full.scope_selector;
                (void)memcpy(
                    slot->index.endpoint_runtime_id,
                    full.endpoint_runtime_id,
                    16u);
                (void)memcpy(
                    slot->index.target_runtime_id,
                    full.target_runtime_id,
                    16u);
                (void)memcpy(
                    slot->index.target_application_id,
                    full.target_application_id,
                    16u);
                (void)memcpy(slot->index.policy_id, full.policy_id, 16u);
                slot->index.policy_revision = full.policy_revision;
                slot->authority_state = full.authority_state;
                slot->assignment_epoch = full.assignment_epoch;
                slot->authority_term = full.authority_term;
                (void)memcpy(slot->authority_id, full.authority_id, 16u);
                (void)memcpy(slot->owner_scope_id, full.owner_scope_id, 16u);
                (void)memcpy(
                    slot->owner_tuple_digest, full.owner_tuple_digest, 32u);
                (void)memcpy(slot->policy_digest, full.policy_digest, 32u);
                (void)memcpy(
                    slot->endpoint_runtime_id, full.endpoint_runtime_id, 16u);
                (void)memcpy(
                    slot->authority_clock_epoch_id,
                    full.authority_clock_epoch_id,
                    16u);
                slot->lease_expires_at_ms = full.lease_expires_at_ms;
            }
        } else if (fabric_key_magic_eq(key_buf, key_mut.length, "FBA1", 76u)) {
            ninlil_fabric_private_common_envelope_t env;
            const uint8_t *pl = NULL;
            ninlil_fabric_private_fba1_t full;
            fabric_attempt_slot_t *attempt = NULL;
            uint32_t need_fence = 0u;
            if (ninlil_fabric_private_record_decode_envelope(
                    value_buf,
                    value_mut.length,
                    (const uint8_t *)"FBA1",
                    NINLIL_FABRIC_FBA1_PAYLOAD_BYTES,
                    &env,
                    &pl)
                    != NINLIL_FABRIC_PRIVATE_RECORD_OK
                || ninlil_fabric_private_fba1_decode(pl, &full)
                    != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
                return reload_close_ro(
                    fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
            }
            if (validate_fba1_semantics(&full, key_buf)
                != NINLIL_FABRIC_PRIVATE_OK) {
                return reload_close_ro(
                    fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
            }
            /*
             * Every committed FBA1 occupies one of the exact 64 profile slots,
             * including DRAINED rows. Eligible rows are erased only by the
             * deterministic step GC (one erase is one unit of work); reload
             * must not hide durable rows and accidentally admit entry 65.
             */
            {
                uint64_t next_epoch =
                    full.path_selection_epoch == UINT64_MAX
                    ? UINT64_MAX
                    : full.path_selection_epoch + 1u;
                if (next_epoch > fabric->path_selection_epoch) {
                    fabric->path_selection_epoch = next_epoch;
                }
            }
            for (ai = 0u; ai < NINLIL_FABRIC_ATTEMPT_MAX; ++ai) {
                if (fabric->attempts[ai].used != 0u
                    && ninlil_fabric_private_memeq(
                           fabric->attempts[ai].key, key_buf, 76u)) {
                    return reload_close_ro(
                        fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
                }
                if (fabric->attempts[ai].used != 0u
                    && ninlil_fabric_private_memeq(
                           fabric->attempts[ai]
                               .attempt.retry_lifetime_clock_epoch_id,
                           full.retry_lifetime_clock_epoch_id,
                           16u)
                    && ninlil_fabric_private_memeq(
                           fabric->attempts[ai].attempt.permit_id,
                           full.permit_id,
                           16u)) {
                    /* TxGate must never reissue an epoch/permit pair. */
                    return reload_close_ro(
                        fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
                }
                if (fabric->attempts[ai].used == 0u && attempt == NULL) {
                    attempt = &fabric->attempts[ai];
                }
            }
            if (attempt == NULL) {
                return reload_close_ro(
                    fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
            }
            /*
             * Restart: PREPARED/LINK_RETAINED => FENCED (no volatile restore).
             * RETRYABLE_NO_ACCEPT: keep only if retry_lifetime epoch matches
             * trusted current clock and now < expiry; else CLOSED/FENCED.
             */
            if (full.state == NINLIL_FABRIC_PRIVATE_ATTEMPT_PREPARED
                || full.state
                    == NINLIL_FABRIC_PRIVATE_ATTEMPT_LINK_RETAINED) {
                full.state = NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
                need_fence = 1u;
            } else if (
                full.state
                == NINLIL_FABRIC_PRIVATE_ATTEMPT_RETRYABLE_NO_ACCEPT) {
                ninlil_time_sample_t now_r;
                ninlil_fabric_private_memzero(&now_r, sizeof(now_r));
                now_r.abi_version = NINLIL_ABI_VERSION;
                now_r.struct_size = (uint16_t)sizeof(now_r);
                if (fabric->clock.now(fabric->clock.user, &now_r)
                        != NINLIL_PORT_OK
                    || now_r.trust != NINLIL_CLOCK_TRUSTED
                    || !ninlil_fabric_private_memeq(
                           full.retry_lifetime_clock_epoch_id,
                           now_r.clock_epoch_id.bytes,
                           16u)) {
                    /* epoch mismatch / clock unknown: not expired-guess. */
                    full.state =
                        NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
                    need_fence = 1u;
                } else if (now_r.now_ms >= full.retry_expires_at_ms) {
                    full.state = NINLIL_FABRIC_PRIVATE_ATTEMPT_CLOSED;
                    need_fence = 1u; /* persist CLOSED replacement */
                }
                /* else keep RETRYABLE; packet restored by exact re-enrich. */
            }
            ninlil_fabric_private_memzero(attempt, sizeof(*attempt));
            attempt->used = 1u;
            (void)memcpy(attempt->key, key_buf, 76u);
            attempt->attempt = full;
            attempt->record_revision = env.revision;
            attempt->packet_slot = UINT32_MAX;
            attempt->has_token = 0u;
            attempt->token = NULL;
            /* Durable path_selection_epoch: restore next after max seen. */
            {
                uint64_t next_epoch =
                    full.path_selection_epoch == UINT64_MAX
                    ? UINT64_MAX
                    : full.path_selection_epoch + 1u;
                if (next_epoch > fabric->path_selection_epoch) {
                    fabric->path_selection_epoch = next_epoch;
                }
            }
            if (need_fence != 0u && fence_count < NINLIL_FABRIC_ATTEMPT_MAX) {
                fence_slots[fence_count++] =
                    (uint32_t)(attempt - fabric->attempts);
            }
        } else if (fabric_key_magic_eq(key_buf, key_mut.length, "FBT1", 40u)) {
            ninlil_fabric_private_common_envelope_t env;
            const uint8_t *pl = NULL;
            ninlil_fabric_private_fbt1_t full;
            fabric_trigger_slot_t *ts = NULL;
            uint32_t ti;
            if (ninlil_fabric_private_record_decode_envelope(
                    value_buf,
                    value_mut.length,
                    (const uint8_t *)"FBT1",
                    224u,
                    &env,
                    &pl)
                    != NINLIL_FABRIC_PRIVATE_RECORD_OK
                || ninlil_fabric_private_fbt1_decode(pl, &full)
                    != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
                return reload_close_ro(
                    fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
            }
            if (validate_fbt1_semantics(&full, key_buf)
                != NINLIL_FABRIC_PRIVATE_OK) {
                return reload_close_ro(
                    fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
            }
            for (ti = 0u; ti < FABRIC_RAM_TRIGGER_MAX; ++ti) {
                if (fabric->triggers[ti].used != 0u
                    && ninlil_fabric_private_memeq(
                           fabric->triggers[ti].trigger.transaction_id,
                           full.transaction_id,
                           16u)
                    && ninlil_fabric_private_memeq(
                           fabric->triggers[ti].trigger.triggering_attempt_id,
                           full.triggering_attempt_id,
                           16u)
                    && fabric->triggers[ti].trigger.triggering_kind
                        == full.triggering_kind) {
                    return reload_close_ro(
                        fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
                }
                if (fabric->triggers[ti].used == 0u && ts == NULL) {
                    ts = &fabric->triggers[ti];
                }
            }
            if (ts == NULL) {
                return reload_close_ro(
                    fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
            }
            ninlil_fabric_private_memzero(ts, sizeof(*ts));
            ts->used = 1u;
            ts->record_revision = env.revision;
            ts->trigger = full;
        } else {
            /* Recognized FB* magic with non-canonical key length. */
            return reload_close_ro(
                fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_CORRUPT);
        }
    }

    rc = reload_close_ro(fabric, &iter, &txn, NINLIL_FABRIC_PRIVATE_OK);
    if (rc != NINLIL_FABRIC_PRIVATE_OK) {
        return rc;
    }

    /* Cross-record: FBC1 must pin an exact loaded FBP1 digest/tuple. */
    for (i = 0u; i < FABRIC_RAM_AUTHORITY_MAX; ++i) {
        const fabric_authority_slot_t *auth;
        int found = 0;
        if (fabric->authorities[i].index.used == 0u) {
            continue;
        }
        auth = &fabric->authorities[i];
        for (ai = 0u; ai < FABRIC_RAM_POLICY_MAX; ++ai) {
            const fabric_policy_slot_t *pol = &fabric->policies[ai];
            if (pol->index.used == 0u) {
                continue;
            }
            if (ninlil_fabric_private_memeq(
                    pol->index.policy_id, auth->index.policy_id, 16u)
                && pol->index.revision == auth->index.policy_revision
                && ninlil_fabric_private_memeq(
                       pol->index.canonical_digest, auth->policy_digest, 32u)
                && ninlil_fabric_private_memeq(
                       pol->index.service_identity_digest,
                       auth->index.service_identity_digest,
                       32u)
                && pol->index.family == auth->index.family
                && pol->index.direction == auth->index.direction
                && pol->index.traffic_class == auth->index.traffic_class
                && pol->index.scope_selector == auth->index.scope_selector) {
                found = 1;
                break;
            }
        }
        if (found == 0) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
    }
    for (i = 0u; i < NINLIL_FABRIC_ATTEMPT_MAX; ++i) {
        const fabric_attempt_slot_t *at;
        int found = 0;
        const fabric_fbr1_pin_t *pin;
        if (fabric->attempts[i].used == 0u) {
            continue;
        }
        at = &fabric->attempts[i];
        /* FBA1 → FBP1 policy pin */
        for (ai = 0u; ai < FABRIC_RAM_POLICY_MAX; ++ai) {
            const fabric_policy_slot_t *pol = &fabric->policies[ai];
            if (pol->index.used == 0u) {
                continue;
            }
            if (ninlil_fabric_private_memeq(
                    pol->index.policy_id, at->attempt.policy_id, 16u)
                && pol->index.revision == at->attempt.policy_revision
                && ninlil_fabric_private_memeq(
                       pol->index.canonical_digest,
                       at->attempt.policy_digest,
                       32u)) {
                found = 1;
                break;
            }
        }
        if (found == 0) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
        /* FBA1 → FBR1 registry pin (revision + full record digest). */
        pin = fbr1_pin_find(fabric, at->attempt.selected_path_id);
        if (pin == NULL) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
        if (fba1_registry_pin_matches(fabric, at, pin)
            != NINLIL_FABRIC_PRIVATE_OK) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
        /* FBA1 → FBC1 authority pin when BOUND (ABSENT still needs FBC1). */
        {
            int auth_found = 0;
            uint32_t auth_matches = 0u;
            for (ai = 0u; ai < FABRIC_RAM_AUTHORITY_MAX; ++ai) {
                const fabric_authority_slot_t *auth =
                    &fabric->authorities[ai];
                if (auth->index.used == 0u) {
                    continue;
                }
                if (auth->authority_state != at->attempt.authority_state) {
                    continue;
                }
                if (!ninlil_fabric_private_memeq(
                        auth->index.policy_id, at->attempt.policy_id, 16u)
                    || auth->index.policy_revision
                        != at->attempt.policy_revision
                    || !ninlil_fabric_private_memeq(
                           auth->policy_digest, at->attempt.policy_digest, 32u)) {
                    continue;
                }
                if (at->attempt.authority_state
                    == NINLIL_FABRIC_AUTHORITY_BOUND) {
                    if (!ninlil_fabric_private_memeq(
                            auth->authority_id, at->attempt.authority_id, 16u)
                        || auth->authority_term != at->attempt.authority_term
                        || auth->assignment_epoch
                            != at->attempt.assignment_epoch
                        || !ninlil_fabric_private_memeq(
                               auth->owner_scope_id,
                               at->attempt.owner_scope_id,
                               16u)
                        || !ninlil_fabric_private_memeq(
                               auth->owner_tuple_digest,
                               at->attempt.owner_tuple_digest,
                               32u)) {
                        continue;
                    }
                } else if (at->attempt.authority_state
                    == NINLIL_FABRIC_AUTHORITY_ABSENT) {
                    if (!ninlil_fabric_private_id_is_zero(
                            at->attempt.authority_id)
                        || at->attempt.authority_term != 0u
                        || at->attempt.assignment_epoch != 0u) {
                        return NINLIL_FABRIC_PRIVATE_CORRUPT;
                    }
                } else {
                    return NINLIL_FABRIC_PRIVATE_CORRUPT;
                }
                auth_matches++;
                auth_found = 1;
            }
            if (auth_found == 0 || auth_matches != 1u) {
                return NINLIL_FABRIC_PRIVATE_CORRUPT;
            }
        }
    }
    /* FBT1 → policy + authority pins (restart reverse correlation). */
    for (i = 0u; i < FABRIC_RAM_TRIGGER_MAX; ++i) {
        const fabric_trigger_slot_t *ts;
        int pol_found = 0;
        int auth_found = 0;
        uint32_t auth_matches = 0u;
        if (fabric->triggers[i].used == 0u) {
            continue;
        }
        ts = &fabric->triggers[i];
        for (ai = 0u; ai < FABRIC_RAM_POLICY_MAX; ++ai) {
            const fabric_policy_slot_t *pol = &fabric->policies[ai];
            if (pol->index.used == 0u) {
                continue;
            }
            if (ninlil_fabric_private_memeq(
                    pol->index.policy_id, ts->trigger.policy_id, 16u)
                && pol->index.revision == ts->trigger.policy_revision
                && ninlil_fabric_private_memeq(
                       pol->index.canonical_digest,
                       ts->trigger.policy_digest,
                       32u)) {
                pol_found = 1;
                break;
            }
        }
        if (pol_found == 0) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
        for (ai = 0u; ai < FABRIC_RAM_AUTHORITY_MAX; ++ai) {
            const fabric_authority_slot_t *auth = &fabric->authorities[ai];
            if (auth->index.used == 0u) {
                continue;
            }
            if (auth->authority_state != ts->trigger.authority_state) {
                continue;
            }
            if (!ninlil_fabric_private_memeq(
                    auth->index.policy_id, ts->trigger.policy_id, 16u)
                || auth->index.policy_revision != ts->trigger.policy_revision
                || !ninlil_fabric_private_memeq(
                       auth->policy_digest, ts->trigger.policy_digest, 32u)) {
                continue;
            }
            if (ts->trigger.authority_state == NINLIL_FABRIC_AUTHORITY_BOUND) {
                if (!ninlil_fabric_private_memeq(
                        auth->authority_id, ts->trigger.authority_id, 16u)
                    || auth->authority_term != ts->trigger.authority_term
                    || auth->assignment_epoch != ts->trigger.assignment_epoch
                    || !ninlil_fabric_private_memeq(
                           auth->owner_scope_id,
                           ts->trigger.owner_scope_id,
                           16u)
                    || !ninlil_fabric_private_memeq(
                           auth->owner_tuple_digest,
                           ts->trigger.owner_tuple_digest,
                           32u)
                    || !ninlil_fabric_private_memeq(
                           auth->endpoint_runtime_id,
                           ts->trigger.endpoint_runtime_id,
                           16u)) {
                    continue;
                }
            }
            auth_matches++;
            auth_found = 1;
        }
        if (auth_found == 0 || auth_matches != 1u) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
    }

    /* Mutations only after RO transaction is fully closed. */
    for (ai = 0u; ai < fence_count; ++ai) {
        fabric_attempt_slot_t *at = &fabric->attempts[fence_slots[ai]];
        ninlil_fabric_private_status_t pst;
        if (at->used == 0u) {
            continue;
        }
        pst = fba1_persist_full_next(
            fabric, &at->attempt, at->key, &at->record_revision);
        if (pst == NINLIL_FABRIC_PRIVATE_OK) {
        } else {
            return pst;
        }
    }
    return NINLIL_FABRIC_PRIVATE_OK;
}

ninlil_fabric_private_status_t ninlil_fabric_private_create_v1(
    const ninlil_fabric_config_v1_t *config,
    void *workspace,
    uint32_t workspace_bytes,
    ninlil_fabric_private_t **out_fabric)
{
    ninlil_fabric_private_t *fabric;
    ninlil_storage_status_t st;
    ninlil_bytes_view_t ns;
    static const uint8_t ns_bytes[] = {
        'n', 'i', 'n', 'l', 'i', 'l', '.', 'f', 'a', 'b', 'r', 'i', 'c', '.',
        'v', '1'
    };
    ninlil_fabric_private_status_t rc;

    if (out_fabric == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    *out_fabric = NULL;
    if (config == NULL || workspace == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (!header_ok(config->api_version, config->struct_size,
            (uint16_t)sizeof(*config))) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (config->profile_id != NINLIL_FABRIC_PROFILE_1 || config->flags != 0u
        || config->storage == NULL || config->clock == NULL
        || config->execution == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (config->storage->open == NULL || config->storage->close == NULL
        || config->storage->begin == NULL || config->storage->get == NULL
        || config->storage->put == NULL || config->storage->erase == NULL
        || config->storage->commit == NULL || config->storage->rollback == NULL
        || config->storage->iter_open == NULL
        || config->storage->iter_next == NULL
        || config->storage->iter_close == NULL
        || config->clock->now == NULL
        || config->execution->current_context_id == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (workspace_bytes < NINLIL_FABRIC_WORKSPACE_BYTES
        || workspace_bytes < (uint32_t)sizeof(ninlil_fabric_private_t)) {
        return NINLIL_FABRIC_PRIVATE_CAPACITY;
    }
    if (((uintptr_t)workspace % _Alignof(max_align_t)) != 0u) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }

    fabric = (ninlil_fabric_private_t *)workspace;
    ninlil_fabric_private_memzero(fabric, sizeof(*fabric));
    fabric->magic = FABRIC_MAGIC;
    fabric->lifecycle = FABRIC_LIFECYCLE_OPEN;
    fabric->storage = *config->storage;
    fabric->clock = *config->clock;
    fabric->execution = *config->execution;
    fabric->owner_context_id =
        fabric->execution.current_context_id(fabric->execution.user);
    if (fabric->owner_context_id == 0u) {
        ninlil_fabric_private_memzero(fabric, sizeof(*fabric));
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    fabric->path_selection_epoch = 1u;

    ns.data = ns_bytes;
    ns.length = (uint32_t)sizeof(ns_bytes);
    st = fabric->storage.open(
        fabric->storage.user, ns, NINLIL_FABRIC_STORAGE_SCHEMA_1,
        &fabric->storage_handle);
    if (st != NINLIL_STORAGE_OK) {
        ninlil_fabric_private_memzero(fabric, sizeof(*fabric));
        return st == NINLIL_STORAGE_UNSUPPORTED_SCHEMA
            ? NINLIL_FABRIC_PRIVATE_UNSUPPORTED
            : NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    fabric->storage_open = 1u;
    rc = adopt_or_open_meta(fabric);
    if (rc != NINLIL_FABRIC_PRIVATE_OK) {
        fabric->storage.close(fabric->storage.user, fabric->storage_handle);
        ninlil_fabric_private_memzero(fabric, sizeof(*fabric));
        return rc;
    }
    rc = reload_durable_state(fabric);
    if (rc != NINLIL_FABRIC_PRIVATE_OK) {
        fabric->storage.close(fabric->storage.user, fabric->storage_handle);
        ninlil_fabric_private_memzero(fabric, sizeof(*fabric));
        return rc;
    }

    fabric->bearer_ops.abi_version = NINLIL_ABI_VERSION;
    fabric->bearer_ops.struct_size = (uint16_t)sizeof(ninlil_bearer_ops_t);
    fabric->bearer_ops.user = fabric;
    /* Function pointers installed on first bearer_ops_v1 call. */
    *out_fabric = fabric;
    return NINLIL_FABRIC_PRIVATE_OK;
}

/* Forward bearer ops implemented later. */
static ninlil_bearer_status_t fabric_bearer_open(
    void *user,
    const ninlil_id128_t *runtime_id,
    ninlil_role_t role,
    ninlil_bearer_handle_t *out_handle);
static void fabric_bearer_close(void *user, ninlil_bearer_handle_t handle);
static ninlil_bearer_status_t fabric_bearer_send(
    void *user,
    ninlil_bearer_handle_t handle,
    const ninlil_tx_permit_t *permit,
    const ninlil_bearer_message_t *message,
    ninlil_bearer_send_result_t *out_result);
static ninlil_bearer_status_t fabric_bearer_receive_next(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_message_t *out_message);
static void fabric_bearer_release_received(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_message_t *message);
static ninlil_bearer_status_t fabric_bearer_state(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_state_t *out_state);

static void install_bearer_ops(ninlil_fabric_private_t *fabric)
{
    fabric->bearer_ops.open = fabric_bearer_open;
    fabric->bearer_ops.close = fabric_bearer_close;
    fabric->bearer_ops.send = fabric_bearer_send;
    fabric->bearer_ops.receive_next = fabric_bearer_receive_next;
    fabric->bearer_ops.release_received = fabric_bearer_release_received;
    fabric->bearer_ops.state = fabric_bearer_state;
}

ninlil_fabric_private_status_t ninlil_fabric_private_bind_rrmp_owner_v1(
    ninlil_fabric_private_t *fabric, struct ninlil_rrmp_owner *owner)
{
    ninlil_fabric_private_status_t st = owner_check(fabric);
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    /* Attach only while sends are possible; detach remains valid for teardown. */
    if (owner != NULL && fabric->lifecycle != FABRIC_LIFECYCLE_OPEN) {
        return NINLIL_FABRIC_PRIVATE_CLOSED;
    }
    if (owner != NULL && fabric->rrmp_owner != NULL
        && fabric->rrmp_owner != owner) {
        return NINLIL_FABRIC_PRIVATE_CONFLICT;
    }
    fabric->rrmp_owner = owner;
    return NINLIL_FABRIC_PRIVATE_OK;
}

ninlil_fabric_private_status_t ninlil_fabric_private_bearer_ops_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_bearer_ops_t **out_bearer_ops)
{
    ninlil_fabric_private_status_t st;
    /* Outer NULL first — no owner callback before ABI checks. */
    if (out_bearer_ops == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    st = owner_check(fabric);
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    install_bearer_ops(fabric);
    *out_bearer_ops = &fabric->bearer_ops;
    return NINLIL_FABRIC_PRIVATE_OK;
}

/* ---------- registration ---------- */

#define FABRIC_KNOWN_PEER_CAP_MASK (NINLIL_FABRIC_PEER_CAP_NFL1_V1)

static int descriptor_valid(
    const ninlil_fabric_link_descriptor_v1_t *d)
{
    if (!header_ok(d->api_version, d->struct_size, (uint16_t)sizeof(*d))) {
        return 0;
    }
    if (ninlil_fabric_private_id_is_zero(d->instance_id.bytes)) {
        return 0;
    }
    if (d->link_kind < 1u || d->link_kind > 4u) {
        return 0;
    }
    if (d->direction_mask == 0u
        || (d->direction_mask
            & ~(NINLIL_FABRIC_LINK_DIRECTION_SEND
                | NINLIL_FABRIC_LINK_DIRECTION_RECEIVE))
            != 0u) {
        return 0;
    }
    /* Unknown capability / security / peer bits: reject, no silent mask. */
    if ((d->capability_flags & ~FABRIC_KNOWN_CAP_MASK) != 0u
        || (d->security_capability_flags & ~FABRIC_KNOWN_SEC_MASK) != 0u
        || (d->peer_fabric_capability_flags & ~FABRIC_KNOWN_PEER_CAP_MASK)
            != 0u) {
        return 0;
    }
    if (d->link_kind == NINLIL_FABRIC_LINK_KIND_WIFI
        && (d->capability_flags & NINLIL_FABRIC_CAP_CUSTODY) != 0u) {
        return 0;
    }
    if (d->descriptor_revision == 0u
        || ninlil_fabric_private_is_zero(d->descriptor_digest, 32u)) {
        return 0;
    }
    if (ninlil_fabric_private_id_is_zero(d->security_profile_id.bytes)
        || ninlil_fabric_private_is_zero(d->security_binding_digest, 32u)
        || d->attestation_epoch == 0u
        || ninlil_fabric_private_id_is_zero(
               d->attestation_clock_epoch_id.bytes)
        || ninlil_fabric_private_is_zero(d->attestation_digest, 32u)
        || d->attestation_expires_at_ms == 0u) {
        return 0;
    }
    if (ninlil_fabric_private_id_is_zero(
            d->authenticated_peer_runtime_id.bytes)
        || ninlil_fabric_private_id_is_zero(
               d->attachment_authority_id.bytes)
        || ninlil_fabric_private_is_zero(d->attachment_binding_digest, 32u)) {
        return 0;
    }
    if (d->maximum_packet_bytes < NINLIL_FABRIC_NFL1_STRUCTURAL_MIN
        || d->maximum_packet_bytes > NINLIL_FABRIC_NFL1_STRUCTURAL_MAX
        || d->maximum_transfer_bytes < d->maximum_packet_bytes
        || d->maximum_transfer_bytes > NINLIL_FABRIC_NFL1_STRUCTURAL_MAX) {
        return 0;
    }
    if (d->latency_class == UINT16_MAX || d->cost_class == UINT16_MAX) {
        return 0;
    }
    if (d->reserved_zero_u16 != 0u || d->reserved_zero_peer_u16 != 0u) {
        return 0;
    }
    if (d->peer_nfl1_version != 1u
        || (d->peer_fabric_capability_flags & NINLIL_FABRIC_PEER_CAP_NFL1_V1)
            == 0u) {
        return 0;
    }
    if (d->link_kind == NINLIL_FABRIC_LINK_KIND_RF) {
        if ((d->capability_flags & NINLIL_FABRIC_CAP_REGULATED_RF) == 0u) {
            return 0;
        }
    } else if ((d->capability_flags & NINLIL_FABRIC_CAP_REGULATED_RF) != 0u) {
        return 0;
    }
    if ((d->capability_flags & NINLIL_FABRIC_CAP_RESERVATION) == 0u
        && d->reservation_capacity != 0u) {
        return 0;
    }
    if (d->configuration_revision == 0u
        || ninlil_fabric_private_is_zero(d->configuration_digest, 32u)) {
        return 0;
    }
    return 1;
}

static int packet_link_ops_header_valid(
    const ninlil_fabric_packet_link_ops_v1_t *ops)
{
    if (ops == NULL) {
        return 0;
    }
    if (!header_ok(
            ops->api_version, ops->struct_size, (uint16_t)sizeof(*ops))) {
        return 0;
    }
    if (ops->open == NULL || ops->close == NULL || ops->start_send == NULL
        || ops->poll_send == NULL || ops->cancel_send == NULL
        || ops->release_send == NULL || ops->receive_next == NULL
        || ops->release_received == NULL || ops->state == NULL) {
        return 0;
    }
    return 1;
}

ninlil_fabric_private_status_t ninlil_fabric_private_register_link_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_fabric_link_descriptor_v1_t *descriptor,
    const ninlil_fabric_packet_link_ops_v1_t *ops,
    ninlil_fabric_registration_private_t **out_registration)
{
    ninlil_fabric_private_status_t st;
    uint32_t i;
    uint32_t free_slot;
    fabric_reg_slot_t *slot;
    fabric_fbr1_pin_t *pin;
    ninlil_fabric_packet_link_handle_t handle = NULL;
    ninlil_fabric_link_status_t ls;
    ninlil_fabric_link_state_v1_t state;
    ninlil_fabric_private_fbr1_t rec;
    ninlil_fabric_private_fbm1_t new_meta;
    uint8_t fbr1_key[20];
    uint8_t fbr1_payload[348];
    uint8_t fbr1_value[372];
    uint32_t fbr1_vlen = 0u;
    uint8_t fbm1_key[4];
    uint8_t fbm1_payload[40];
    uint8_t fbm1_value[64];
    uint32_t fbm1_vlen = 0u;
    uint32_t need_fbm1 = 0u;
    fabric_kv_put_t puts[2];
    uint32_t put_count = 0u;
    uint64_t fbr1_rev = 1u;
    ninlil_time_sample_t now;

    /*
     * Precedence: NULL/header/size/reserved -> owner -> reentry -> lifecycle.
     * No owner callback before outer ABI checks.
     */
    if (descriptor == NULL || ops == NULL || out_registration == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    *out_registration = NULL;
    if (!header_ok(
            descriptor->api_version,
            descriptor->struct_size,
            (uint16_t)sizeof(*descriptor))) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (!packet_link_ops_header_valid(ops)) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    st = fabric_null_magic(fabric);
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    st = owner_then_reentry(fabric);
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    if (fabric->lifecycle != FABRIC_LIFECYCLE_OPEN) {
        return NINLIL_FABRIC_PRIVATE_UNAVAILABLE;
    }
    if (!descriptor_valid(descriptor)) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    /* Expired / epoch-mismatch attestation: DENIED before provider open. */
    ninlil_fabric_private_memzero(&now, sizeof(now));
    if (fabric->clock.now(fabric->clock.user, &now) != NINLIL_PORT_OK) {
        return NINLIL_FABRIC_PRIVATE_UNAVAILABLE;
    }
    if (!ninlil_fabric_private_memeq(
            descriptor->attestation_clock_epoch_id.bytes,
            now.clock_epoch_id.bytes,
            16u)) {
        return NINLIL_FABRIC_PRIVATE_DENIED;
    }
    if (now.now_ms >= descriptor->attestation_expires_at_ms) {
        return NINLIL_FABRIC_PRIVATE_DENIED;
    }

    free_slot = NINLIL_FABRIC_REGISTRY_MAX;
    for (i = 0u; i < NINLIL_FABRIC_REGISTRY_MAX; ++i) {
        if (fabric->regs[i].used != 0u
            && fabric->regs[i].lifecycle != FABRIC_REG_CONSUMED
            && ninlil_fabric_private_memeq(
                   fabric->regs[i].descriptor.instance_id.bytes,
                   descriptor->instance_id.bytes,
                   16u)) {
            /* Idempotent: descriptor + full vtable (all 9 funcs + user). */
            if (ninlil_fabric_private_memeq(
                    &fabric->regs[i].descriptor,
                    descriptor,
                    sizeof(*descriptor))
                && packet_link_ops_exact(&fabric->regs[i].ops, ops)) {
                *out_registration = fabric->regs[i].public_handle;
                return NINLIL_FABRIC_PRIVATE_OK;
            }
            return NINLIL_FABRIC_PRIVATE_CONFLICT;
        }
        if (fabric->regs[i].used == 0u && free_slot == NINLIL_FABRIC_REGISTRY_MAX) {
            free_slot = i;
        }
    }
    if (free_slot == NINLIL_FABRIC_REGISTRY_MAX) {
        return NINLIL_FABRIC_PRIVATE_CAPACITY;
    }
    pin = fbr1_pin_find(fabric, descriptor->instance_id.bytes);
    if (pin != NULL) {
        /* Restart re-attach: descriptor digest must match durable FBR1 pin. */
        if (!ninlil_fabric_private_memeq(
                pin->descriptor_digest, descriptor->descriptor_digest, 32u)) {
            return NINLIL_FABRIC_PRIVATE_CONFLICT;
        }
    } else {
        pin = fbr1_pin_alloc(fabric);
        if (pin == NULL) {
            return NINLIL_FABRIC_PRIVATE_CAPACITY;
        }
    }

    /* Provider open under reentrancy guard. */
    fabric->reentrant = 1u;
    ls = ops->open(ops->user, &handle);
    fabric->reentrant = 0u;
    if (ls != NINLIL_FABRIC_LINK_OK) {
        /* Non-OK must be NULL handle; non-NULL is contradiction → close. */
        if (handle != NULL) {
            fabric->reentrant = 1u;
            ops->close(ops->user, handle);
            fabric->reentrant = 0u;
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
        return NINLIL_FABRIC_PRIVATE_UNAVAILABLE;
    }
    if (handle == NULL) {
        return NINLIL_FABRIC_PRIVATE_UNAVAILABLE;
    }
    ninlil_fabric_private_memzero(&state, sizeof(state));
    state.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    state.struct_size = (uint16_t)sizeof(state);
    fabric->reentrant = 1u;
    ls = ops->state(ops->user, handle, &state);
    fabric->reentrant = 0u;
    if (ls != NINLIL_FABRIC_LINK_OK || state.availability_epoch == 0u
        || (state.available != 0u && state.available != 1u)) {
        /* State failure close stays under reentrancy guard. */
        fabric->reentrant = 1u;
        ops->close(ops->user, handle);
        fabric->reentrant = 0u;
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }

    fbr1_fill_from_descriptor_state(
        &rec, descriptor, &state, (uint8_t)NINLIL_FABRIC_PRIVATE_LIFECYCLE_ACTIVE);
    ninlil_fabric_private_key_fbr1(descriptor->instance_id.bytes, fbr1_key);

    if (pin->used != 0u) {
        /* Durable FBR1 already present: re-attach live only. */
        if (pin->availability_epoch != state.availability_epoch
            || pin->available != (uint8_t)state.available
            || pin->availability_expires_at_ms != state.available_until_ms) {
            /* Provider state differs: require strict +1 via availability API. */
            fabric->reentrant = 1u;
            ops->close(ops->user, handle);
            fabric->reentrant = 0u;
            return NINLIL_FABRIC_PRIVATE_CONFLICT;
        }
        fbr1_rev = pin->record_revision;
        state.availability_epoch = pin->availability_epoch;
        state.available_until_ms = pin->availability_expires_at_ms;
        state.available = pin->available;
    } else {
        /* First durable publish: FBR1 (+ FBM1 if first ACTIVE) same FULL. */
        fbr1_rev = 1u;
        if (ninlil_fabric_private_fbr1_encode(&rec, fbr1_payload)
            != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
            fabric->reentrant = 1u;
            ops->close(ops->user, handle);
            fabric->reentrant = 0u;
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
        if (ninlil_fabric_private_record_encode_envelope(
                (const uint8_t *)"FBR1",
                fbr1_rev,
                fbr1_payload,
                348u,
                fbr1_value,
                372u,
                &fbr1_vlen)
            != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
            fabric->reentrant = 1u;
            ops->close(ops->user, handle);
            fabric->reentrant = 0u;
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
        puts[0].key = fbr1_key;
        puts[0].key_len = 20u;
        puts[0].value = fbr1_value;
        puts[0].value_len = fbr1_vlen;
        put_count = 1u;

        {
            uint64_t next_epoch = 0u;
            uint64_t next_meta_rev = 0u;
            if (fabric->meta.outer_available == 0u) {
                need_fbm1 = 1u;
                new_meta = fabric->meta;
                new_meta.outer_available = 1u;
                /* Non-zero strict increment; wrap fail-closed. */
                if (fabric->meta.outer_availability_epoch == 0u
                    || fabric_checked_next_u64(
                           fabric->meta.outer_availability_epoch, &next_epoch)
                        == 0
                    || fabric_checked_next_u64(
                           fabric->meta_revision, &next_meta_rev)
                        == 0) {
                    fabric->reentrant = 1u;
                    ops->close(ops->user, handle);
                    fabric->reentrant = 0u;
                    return NINLIL_FABRIC_PRIVATE_CORRUPT;
                }
                new_meta.outer_availability_epoch = next_epoch;
                ninlil_fabric_private_key_fbm1(fbm1_key);
                if (ninlil_fabric_private_fbm1_encode(&new_meta, fbm1_payload)
                    != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
                    fabric->reentrant = 1u;
                    ops->close(ops->user, handle);
                    fabric->reentrant = 0u;
                    return NINLIL_FABRIC_PRIVATE_CORRUPT;
                }
                if (ninlil_fabric_private_record_encode_envelope(
                        fbm1_key,
                        next_meta_rev,
                        fbm1_payload,
                        40u,
                        fbm1_value,
                        64u,
                        &fbm1_vlen)
                    != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
                    fabric->reentrant = 1u;
                    ops->close(ops->user, handle);
                    fabric->reentrant = 0u;
                    return NINLIL_FABRIC_PRIVATE_CORRUPT;
                }
                puts[1].key = fbm1_key;
                puts[1].key_len = 4u;
                puts[1].value = fbm1_value;
                puts[1].value_len = fbm1_vlen;
                put_count = 2u;
            }

            st = storage_put_multi_full(fabric, puts, put_count);
            if (st != NINLIL_FABRIC_PRIVATE_OK) {
                fabric->reentrant = 1u;
                ops->close(ops->user, handle);
                fabric->reentrant = 0u;
                return st;
            }
            fbr1_pin_store(pin, fbr1_rev, &rec, fbr1_key, fbr1_value);
            if (need_fbm1 != 0u) {
                fabric->meta = new_meta;
                fabric->meta_revision = next_meta_rev;
            }
        }
    }

    /* FULL OK / re-attach: publish live RAM registration. */
    slot = &fabric->regs[free_slot];
    ninlil_fabric_private_memzero(slot, sizeof(*slot));
    slot->used = 1u;
    slot->lifecycle = FABRIC_REG_ACTIVE;
    slot->record_revision = fbr1_rev;
    slot->descriptor = *descriptor;
    slot->ops = *ops;
    slot->handle = handle;
    slot->state = state;
    slot->metrics.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    slot->metrics.struct_size = (uint16_t)sizeof(slot->metrics);
    slot->metrics.metrics_revision = 1u;
    fabric->reg_handles[free_slot].magic = REG_MAGIC;
    fabric->reg_handles[free_slot].slot_index = free_slot;
    fabric->reg_handles[free_slot].fabric = fabric;
    slot->public_handle = &fabric->reg_handles[free_slot];
    *out_registration = slot->public_handle;
    return NINLIL_FABRIC_PRIVATE_OK;
}

ninlil_fabric_private_status_t ninlil_fabric_private_unregister_begin_v1(
    ninlil_fabric_private_t *fabric,
    ninlil_fabric_registration_private_t *registration)
{
    ninlil_fabric_private_status_t st;
    fabric_reg_slot_t *slot;
    /* NULL/header before owner callback. */
    if (registration == NULL || registration->magic != REG_MAGIC
        || registration->slot_index >= NINLIL_FABRIC_REGISTRY_MAX) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    st = owner_check(fabric);
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    if (registration->fabric != fabric) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    slot = &fabric->regs[registration->slot_index];
    if (slot->used == 0u || slot->public_handle != registration) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (slot->lifecycle == FABRIC_REG_DRAINING) {
        return NINLIL_FABRIC_PRIVATE_CONFLICT;
    }
    if (slot->lifecycle != FABRIC_REG_ACTIVE) {
        return NINLIL_FABRIC_PRIVATE_CLOSED;
    }
    slot->lifecycle = FABRIC_REG_DRAINING;
    return NINLIL_FABRIC_PRIVATE_OK;
}

ninlil_fabric_private_status_t ninlil_fabric_private_unregister_poll_v1(
    ninlil_fabric_private_t *fabric,
    ninlil_fabric_registration_private_t *registration,
    uint32_t *out_done)
{
    ninlil_fabric_private_status_t st;
    fabric_reg_slot_t *slot;
    if (out_done == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    *out_done = 0u;
    if (registration == NULL || registration->magic != REG_MAGIC
        || registration->slot_index >= NINLIL_FABRIC_REGISTRY_MAX) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    st = owner_check(fabric);
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    if (registration->fabric != fabric) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    slot = &fabric->regs[registration->slot_index];
    if (slot->used == 0u || slot->lifecycle != FABRIC_REG_DRAINING) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (slot->retained_tokens != 0u || slot->queued_items != 0u) {
        return NINLIL_FABRIC_PRIVATE_OK;
    }
    fabric->reentrant = 1u;
    slot->ops.close(slot->ops.user, slot->handle);
    fabric->reentrant = 0u;
    ninlil_fabric_private_memzero(registration, sizeof(*registration));
    ninlil_fabric_private_memzero(slot, sizeof(*slot));
    slot->lifecycle = FABRIC_REG_CONSUMED;
    *out_done = 1u;
    return NINLIL_FABRIC_PRIVATE_OK;
}

/* ---------- policy / authority ---------- */

ninlil_fabric_private_status_t ninlil_fabric_private_policy_put_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_fabric_path_policy_v1_t *policy)
{
    ninlil_fabric_private_status_t st = owner_check(fabric);
    uint32_t i;
    uint32_t free_slot;
    fabric_policy_slot_t *slot;
    ninlil_fabric_private_fbp1_t encoded;

    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    if (policy == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (!header_ok(policy->api_version, policy->struct_size,
            (uint16_t)sizeof(*policy))) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (ninlil_fabric_private_id_is_zero(policy->policy_id.bytes)
        || policy->revision == 0u
        || !ninlil_fabric_private_is_zero(
               policy->canonical_digest_zero_on_input, 32u)
        || ninlil_fabric_private_is_zero(policy->service_identity_digest, 32u)
        || policy->candidate_count == 0u || policy->candidate_count > 8u
        || policy->reserved_zero_u16 != 0u || policy->reserved_zero_u32 != 0u
        || policy->reserved_zero_u8[0] != 0u
        || policy->reserved_zero_u8[1] != 0u
        || policy->reserved_zero_u8[2] != 0u) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (policy->direction != NINLIL_FABRIC_POLICY_DIRECTION_FORWARD
        && policy->direction != NINLIL_FABRIC_POLICY_DIRECTION_REVERSE) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (policy->traffic_class != NINLIL_FABRIC_TRAFFIC_APPLICATION
        && policy->traffic_class != NINLIL_FABRIC_TRAFFIC_CONTROL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (policy->scope_selector != NINLIL_FABRIC_SCOPE_SOURCE_RUNTIME
        && policy->scope_selector != NINLIL_FABRIC_SCOPE_TARGET_RUNTIME) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }

    ninlil_fabric_private_memzero(&encoded, sizeof(encoded));
    (void)memcpy(encoded.policy_id, policy->policy_id.bytes, 16u);
    encoded.revision = policy->revision;
    (void)memcpy(
        encoded.service_identity_digest, policy->service_identity_digest, 32u);
    encoded.family = policy->family;
    encoded.direction = policy->direction;
    encoded.traffic_class = policy->traffic_class;
    encoded.scope_selector = policy->scope_selector;
    encoded.required_capability_flags = policy->required_capability_flags;
    encoded.required_security_flags = policy->required_security_flags;
    encoded.maximum_latency_class = policy->maximum_latency_class;
    encoded.maximum_cost_class = policy->maximum_cost_class;
    encoded.minimum_packet_bytes = policy->minimum_packet_bytes;
    encoded.authority_mode = policy->authority_mode;
    encoded.deadline_guard_ms = policy->deadline_guard_ms;
    encoded.candidate_count = policy->candidate_count;
    for (i = 0u; i < policy->candidate_count; ++i) {
        uint32_t j;
        (void)memcpy(
            encoded.candidates[i].instance_id,
            policy->candidates[i].instance_id.bytes,
            16u);
        encoded.candidates[i].rank = policy->candidates[i].rank;
        encoded.candidates[i].flags = policy->candidates[i].flags;
        encoded.candidates[i].reservation_units =
            policy->candidates[i].reservation_units;
        if (encoded.candidates[i].reservation_units == 0u
            || encoded.candidates[i].flags != 0u
            || ninlil_fabric_private_id_is_zero(
                   encoded.candidates[i].instance_id)) {
            return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
        }
        for (j = 0u; j < i; ++j) {
            if (ninlil_fabric_private_memeq(
                    encoded.candidates[i].instance_id,
                    encoded.candidates[j].instance_id,
                    16u)) {
                return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
            }
        }
    }
    if ((encoded.required_capability_flags & ~FABRIC_KNOWN_CAP_MASK) != 0u
        || (encoded.required_security_flags & ~FABRIC_KNOWN_SEC_MASK) != 0u
        || (encoded.authority_mode
                != NINLIL_FABRIC_AUTHORITY_MODE_ABSENT_ALLOWED
            && encoded.authority_mode
                != NINLIL_FABRIC_AUTHORITY_MODE_BOUND_REQUIRED)) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    ninlil_fabric_private_fbp1_compute_digest(&encoded);

    /* SAME vs CONFLICT for exact policy_id+revision; new rev = current+1. */
    free_slot = FABRIC_RAM_POLICY_MAX;
    {
        uint64_t max_rev = 0u;
        int have_policy = 0;
        for (i = 0u; i < FABRIC_RAM_POLICY_MAX; ++i) {
            if (fabric->policies[i].index.used != 0u
                && ninlil_fabric_private_memeq(
                       fabric->policies[i].index.policy_id,
                       policy->policy_id.bytes,
                       16u)) {
                have_policy = 1;
                if (fabric->policies[i].index.revision > max_rev) {
                    max_rev = fabric->policies[i].index.revision;
                }
                if (fabric->policies[i].index.revision == policy->revision) {
                    if (ninlil_fabric_private_memeq(
                            fabric->policies[i].index.canonical_digest,
                            encoded.canonical_digest,
                            32u)) {
                        return NINLIL_FABRIC_PRIVATE_OK; /* SAME */
                    }
                    return NINLIL_FABRIC_PRIVATE_CONFLICT;
                }
            }
            if (fabric->policies[i].index.used == 0u
                && free_slot == FABRIC_RAM_POLICY_MAX) {
                free_slot = i;
            }
        }
        if (have_policy != 0
            && policy->revision != max_rev + 1u) {
            /* gap / rollback / wrap: not current+1 */
            return NINLIL_FABRIC_PRIVATE_CONFLICT;
        }
    }
    if (free_slot == FABRIC_RAM_POLICY_MAX) {
        return NINLIL_FABRIC_PRIVATE_CAPACITY;
    }

    /* FULL-first: encode and durable commit before any RAM publication. */
    {
        uint8_t key[28];
        uint8_t payload[328];
        uint8_t value[352];
        uint32_t vlen = 0u;
        ninlil_fabric_private_key_fbp1(
            encoded.policy_id, encoded.revision, key);
        if (ninlil_fabric_private_fbp1_encode(&encoded, payload)
            != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
        if (ninlil_fabric_private_record_encode_envelope(
                (const uint8_t *)"FBP1",
                1u,
                payload,
                328u,
                value,
                352u,
                &vlen)
            != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
        st = storage_put_full(fabric, key, 28u, value, vlen);
        if (st != NINLIL_FABRIC_PRIVATE_OK) {
            /* COMMIT_UNKNOWN / definite failure: no RAM mutation. */
            return st;
        }
    }

    slot = &fabric->policies[free_slot];
    ninlil_fabric_private_memzero(slot, sizeof(*slot));
    slot->index.used = 1u;
    slot->index.revision = encoded.revision;
    slot->index.deadline_guard_ms = encoded.deadline_guard_ms;
    slot->index.family = encoded.family;
    slot->index.direction = encoded.direction;
    slot->index.required_capability_flags = encoded.required_capability_flags;
    slot->index.required_security_flags = encoded.required_security_flags;
    slot->index.minimum_packet_bytes = encoded.minimum_packet_bytes;
    slot->index.traffic_class = encoded.traffic_class;
    slot->index.scope_selector = encoded.scope_selector;
    slot->index.maximum_latency_class = encoded.maximum_latency_class;
    slot->index.maximum_cost_class = encoded.maximum_cost_class;
    (void)memcpy(slot->index.policy_id, encoded.policy_id, 16u);
    (void)memcpy(slot->index.canonical_digest, encoded.canonical_digest, 32u);
    (void)memcpy(
        slot->index.service_identity_digest,
        encoded.service_identity_digest,
        32u);
    slot->index.authority_mode = encoded.authority_mode;
    slot->index.candidate_count = (uint8_t)encoded.candidate_count;
    slot->record_revision = 1u;
    return NINLIL_FABRIC_PRIVATE_OK;
}

ninlil_fabric_private_status_t ninlil_fabric_private_policy_remove_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *policy_id,
    uint64_t revision)
{
    ninlil_fabric_private_status_t st = owner_check(fabric);
    uint32_t i;
    uint8_t key[28];
    uint32_t cu_class = 0u;
    ninlil_time_sample_t now;
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    if (policy_id == NULL || revision == 0u) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (fabric_sample_now(fabric, &now) == 0) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    for (i = 0u; i < FABRIC_RAM_POLICY_MAX; ++i) {
        if (fabric->policies[i].index.used != 0u
            && ninlil_fabric_private_memeq(
                   fabric->policies[i].index.policy_id,
                   policy_id->bytes,
                   16u)
            && fabric->policies[i].index.revision == revision) {
            /* ADR-0017: not current; zero FBA1/FBT1 refs; retention complete. */
            if (fabric_policy_is_current(fabric, policy_id->bytes, revision)
                != 0) {
                return NINLIL_FABRIC_PRIVATE_CONFLICT;
            }
            if (fabric_policy_has_blocking_ref(
                    fabric, policy_id->bytes, revision, &now)
                != 0) {
                return NINLIL_FABRIC_PRIVATE_CONFLICT;
            }
            ninlil_fabric_private_key_fbp1(policy_id->bytes, revision, key);
            st = storage_erase_full_ex(fabric, key, 28u, &cu_class);
            if (st == NINLIL_FABRIC_PRIVATE_OK) {
                ninlil_fabric_private_memzero(
                    &fabric->policies[i], sizeof(fabric->policies[i]));
                return NINLIL_FABRIC_PRIVATE_OK;
            }
            if (st == NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN) {
                /*
                 * NEW = durable erase applied under CU: drop RAM so selection
                 * cannot resurrect. OLD = keep RAM until classified durable.
                 */
                if (cu_class == NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_NEW) {
                    ninlil_fabric_private_memzero(
                        &fabric->policies[i], sizeof(fabric->policies[i]));
                }
                return NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN;
            }
            return st;
        }
    }
    return NINLIL_FABRIC_PRIVATE_UNAVAILABLE;
}

ninlil_fabric_private_status_t ninlil_fabric_private_authority_put_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_fabric_authority_binding_v1_t *binding)
{
    ninlil_fabric_private_status_t st = owner_check(fabric);
    uint32_t i;
    uint32_t free_slot;
    fabric_authority_slot_t *slot;

    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    if (binding == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (!header_ok(binding->api_version, binding->struct_size,
            (uint16_t)sizeof(*binding))) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (ninlil_fabric_private_id_is_zero(binding->binding_id.bytes)
        || binding->assignment_revision == 0u
        || binding->reserved_zero_u32 != 0u
        || binding->reserved_zero_u64 != 0u) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (binding->authority_state == NINLIL_FABRIC_AUTHORITY_ABSENT) {
        if (!ninlil_fabric_private_id_is_zero(binding->authority_id.bytes)
            || binding->authority_term != 0u
            || binding->assignment_epoch != 0u) {
            return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
        }
    } else if (binding->authority_state == NINLIL_FABRIC_AUTHORITY_BOUND) {
        uint8_t expected_owner[32];
        if (ninlil_fabric_private_id_is_zero(binding->authority_id.bytes)
            || binding->authority_term == 0u
            || binding->assignment_epoch == 0u
            || ninlil_fabric_private_id_is_zero(binding->owner_scope_id.bytes)
            || ninlil_fabric_private_is_zero(binding->owner_tuple_digest, 32u)) {
            return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
        }
        ninlil_fabric_private_owner_tuple_digest(
            binding->owner_tuple_canonical, expected_owner);
        if (!ninlil_fabric_private_memeq(
                expected_owner, binding->owner_tuple_digest, 32u)) {
            return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
        }
    } else {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (binding->direction != NINLIL_FABRIC_POLICY_DIRECTION_FORWARD
        && binding->direction != NINLIL_FABRIC_POLICY_DIRECTION_REVERSE) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (binding->traffic_class != NINLIL_FABRIC_TRAFFIC_APPLICATION
        && binding->traffic_class != NINLIL_FABRIC_TRAFFIC_CONTROL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (binding->scope_selector != NINLIL_FABRIC_SCOPE_SOURCE_RUNTIME
        && binding->scope_selector != NINLIL_FABRIC_SCOPE_TARGET_RUNTIME) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (ninlil_fabric_private_is_zero(binding->service_identity_digest, 32u)
        || ninlil_fabric_private_id_is_zero(binding->policy_id.bytes)
        || binding->policy_revision == 0u
        || ninlil_fabric_private_is_zero(binding->policy_digest, 32u)) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }

    free_slot = FABRIC_RAM_AUTHORITY_MAX;
    for (i = 0u; i < FABRIC_RAM_AUTHORITY_MAX; ++i) {
        if (fabric->authorities[i].index.used != 0u
            && ninlil_fabric_private_memeq(
                   fabric->authorities[i].index.binding_id,
                   binding->binding_id.bytes,
                   16u)) {
            const fabric_authority_slot_t *ex = &fabric->authorities[i];
            /* SAME assignment_revision: full content bit-match or CONFLICT. */
            if (ex->record_revision == binding->assignment_revision) {
                if (ninlil_fabric_private_memeq(
                        ex->index.service_identity_digest,
                        binding->service_identity_digest,
                        32u)
                    && ex->index.family == binding->family
                    && ex->index.direction == binding->direction
                    && ex->index.traffic_class == binding->traffic_class
                    && ex->index.scope_selector == binding->scope_selector
                    && ninlil_fabric_private_memeq(
                           ex->index.policy_id, binding->policy_id.bytes, 16u)
                    && ex->index.policy_revision == binding->policy_revision
                    && ninlil_fabric_private_memeq(
                           ex->policy_digest, binding->policy_digest, 32u)
                    && ex->authority_state == binding->authority_state
                    && ninlil_fabric_private_memeq(
                           ex->authority_id, binding->authority_id.bytes, 16u)
                    && ex->authority_term == binding->authority_term
                    && ex->assignment_epoch == binding->assignment_epoch
                    && ninlil_fabric_private_memeq(
                           ex->owner_scope_id,
                           binding->owner_scope_id.bytes,
                           16u)
                    && ninlil_fabric_private_memeq(
                           ex->owner_tuple_digest,
                           binding->owner_tuple_digest,
                           32u)
                    && ninlil_fabric_private_memeq(
                           ex->endpoint_runtime_id,
                           binding->endpoint_runtime_id.bytes,
                           16u)
                    && ninlil_fabric_private_memeq(
                           ex->index.target_runtime_id,
                           binding->target_runtime_id.bytes,
                           16u)
                    && ninlil_fabric_private_memeq(
                           ex->index.target_application_id,
                           binding->target_application_id.bytes,
                           16u)
                    && ex->lease_expires_at_ms
                        == binding->lease_expires_at_ms) {
                    return NINLIL_FABRIC_PRIVATE_OK; /* SAME */
                }
                return NINLIL_FABRIC_PRIVATE_CONFLICT;
            }
            /* Replacement: assignment_revision must be exact current+1. */
            if (binding->assignment_revision != ex->record_revision + 1u) {
                return NINLIL_FABRIC_PRIVATE_CONFLICT;
            }
            /* Lookup identity immutable across assignment revisions. */
            if (!ninlil_fabric_private_memeq(
                    ex->index.service_identity_digest,
                    binding->service_identity_digest,
                    32u)
                || ex->index.family != binding->family
                || ex->index.direction != binding->direction
                || ex->index.traffic_class != binding->traffic_class
                || ex->index.scope_selector != binding->scope_selector
                || !ninlil_fabric_private_memeq(
                       ex->endpoint_runtime_id,
                       binding->endpoint_runtime_id.bytes,
                       16u)
                || !ninlil_fabric_private_memeq(
                       ex->index.target_runtime_id,
                       binding->target_runtime_id.bytes,
                       16u)
                || !ninlil_fabric_private_memeq(
                       ex->index.target_application_id,
                       binding->target_application_id.bytes,
                       16u)
                || !ninlil_fabric_private_memeq(
                       ex->index.policy_id, binding->policy_id.bytes, 16u)) {
                return NINLIL_FABRIC_PRIVATE_CONFLICT;
            }
            free_slot = i;
            break;
        }
        if (fabric->authorities[i].index.used == 0u
            && free_slot == FABRIC_RAM_AUTHORITY_MAX) {
            free_slot = i;
        }
    }
    if (free_slot == FABRIC_RAM_AUTHORITY_MAX) {
        return NINLIL_FABRIC_PRIVATE_CAPACITY;
    }
    /* FULL-first: durable FBC1 before RAM publication. */
    {
        ninlil_fabric_private_fbc1_t full;
        uint8_t key[20];
        uint8_t payload[488];
        uint8_t value[512];
        uint32_t vlen = 0u;
        ninlil_fabric_private_memzero(&full, sizeof(full));
        (void)memcpy(full.binding_id, binding->binding_id.bytes, 16u);
        (void)memcpy(
            full.service_identity_digest,
            binding->service_identity_digest,
            32u);
        full.family = binding->family;
        full.direction = binding->direction;
        full.traffic_class = binding->traffic_class;
        full.scope_selector = binding->scope_selector;
        (void)memcpy(
            full.endpoint_runtime_id,
            binding->endpoint_runtime_id.bytes,
            16u);
        (void)memcpy(
            full.target_runtime_id, binding->target_runtime_id.bytes, 16u);
        (void)memcpy(
            full.target_application_id,
            binding->target_application_id.bytes,
            16u);
        (void)memcpy(full.policy_id, binding->policy_id.bytes, 16u);
        full.policy_revision = binding->policy_revision;
        (void)memcpy(full.policy_digest, binding->policy_digest, 32u);
        full.authority_state = binding->authority_state;
        (void)memcpy(full.authority_id, binding->authority_id.bytes, 16u);
        full.authority_term = binding->authority_term;
        full.assignment_epoch = binding->assignment_epoch;
        (void)memcpy(
            full.owner_scope_id, binding->owner_scope_id.bytes, 16u);
        (void)memcpy(
            full.owner_tuple_digest, binding->owner_tuple_digest, 32u);
        (void)memcpy(
            full.owner_tuple_canonical, binding->owner_tuple_canonical, 200u);
        (void)memcpy(
            full.authority_clock_epoch_id,
            binding->authority_clock_epoch_id.bytes,
            16u);
        full.lease_expires_at_ms = binding->lease_expires_at_ms;
        full.assignment_revision = binding->assignment_revision;
        ninlil_fabric_private_key_fbc1(full.binding_id, key);
        if (ninlil_fabric_private_fbc1_encode(&full, payload)
            != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
        if (ninlil_fabric_private_record_encode_envelope(
                (const uint8_t *)"FBC1",
                binding->assignment_revision,
                payload,
                488u,
                value,
                512u,
                &vlen)
            != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
        st = storage_put_full(fabric, key, 20u, value, vlen);
        if (st != NINLIL_FABRIC_PRIVATE_OK) {
            return st;
        }
    }
    slot = &fabric->authorities[free_slot];
    ninlil_fabric_private_memzero(slot, sizeof(*slot));
    slot->index.used = 1u;
    slot->record_revision = binding->assignment_revision;
    (void)memcpy(slot->index.binding_id, binding->binding_id.bytes, 16u);
    (void)memcpy(
        slot->index.service_identity_digest,
        binding->service_identity_digest,
        32u);
    slot->index.family = binding->family;
    slot->index.direction = binding->direction;
    slot->index.traffic_class = binding->traffic_class;
    slot->index.scope_selector = binding->scope_selector;
    (void)memcpy(
        slot->index.endpoint_runtime_id,
        binding->endpoint_runtime_id.bytes,
        16u);
    (void)memcpy(
        slot->index.target_runtime_id,
        binding->target_runtime_id.bytes,
        16u);
    (void)memcpy(
        slot->index.target_application_id,
        binding->target_application_id.bytes,
        16u);
    (void)memcpy(slot->index.policy_id, binding->policy_id.bytes, 16u);
    slot->index.policy_revision = binding->policy_revision;
    slot->authority_state = binding->authority_state;
    slot->assignment_epoch = binding->assignment_epoch;
    slot->authority_term = binding->authority_term;
    (void)memcpy(slot->authority_id, binding->authority_id.bytes, 16u);
    (void)memcpy(slot->owner_scope_id, binding->owner_scope_id.bytes, 16u);
    (void)memcpy(slot->owner_tuple_digest, binding->owner_tuple_digest, 32u);
    (void)memcpy(slot->policy_digest, binding->policy_digest, 32u);
    (void)memcpy(
        slot->endpoint_runtime_id, binding->endpoint_runtime_id.bytes, 16u);
    (void)memcpy(
        slot->authority_clock_epoch_id,
        binding->authority_clock_epoch_id.bytes,
        16u);
    slot->lease_expires_at_ms = binding->lease_expires_at_ms;
    return NINLIL_FABRIC_PRIVATE_OK;
}

ninlil_fabric_private_status_t ninlil_fabric_private_authority_remove_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *binding_id,
    uint64_t assignment_revision)
{
    ninlil_fabric_private_status_t st = owner_check(fabric);
    uint32_t i;
    uint8_t key[20];
    uint32_t cu_class = 0u;
    ninlil_time_sample_t now;
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    if (binding_id == NULL || assignment_revision == 0u) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (fabric_sample_now(fabric, &now) == 0) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    for (i = 0u; i < FABRIC_RAM_AUTHORITY_MAX; ++i) {
        if (fabric->authorities[i].index.used != 0u
            && ninlil_fabric_private_memeq(
                   fabric->authorities[i].index.binding_id,
                   binding_id->bytes,
                   16u)
            && fabric->authorities[i].record_revision
                == assignment_revision) {
            /* FBA/FBT active or pre-retention: remove forbidden. */
            if (fabric_authority_has_blocking_ref(
                    fabric, &fabric->authorities[i], &now)
                != 0) {
                return NINLIL_FABRIC_PRIVATE_CONFLICT;
            }
            ninlil_fabric_private_key_fbc1(binding_id->bytes, key);
            st = storage_erase_full_ex(fabric, key, 20u, &cu_class);
            if (st == NINLIL_FABRIC_PRIVATE_OK) {
                ninlil_fabric_private_memzero(
                    &fabric->authorities[i],
                    sizeof(fabric->authorities[i]));
                return NINLIL_FABRIC_PRIVATE_OK;
            }
            if (st == NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN) {
                if (cu_class == NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_NEW) {
                    ninlil_fabric_private_memzero(
                        &fabric->authorities[i],
                        sizeof(fabric->authorities[i]));
                }
                return NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN;
            }
            return st;
        }
    }
    return NINLIL_FABRIC_PRIVATE_UNAVAILABLE;
}

ninlil_fabric_private_status_t ninlil_fabric_private_authority_snapshot_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *binding_id,
    ninlil_fabric_authority_binding_v1_t *out_binding)
{
    ninlil_fabric_private_status_t st = owner_check(fabric);
    uint32_t i;
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    if (binding_id == NULL || out_binding == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    for (i = 0u; i < FABRIC_RAM_AUTHORITY_MAX; ++i) {
        if (fabric->authorities[i].index.used != 0u
            && ninlil_fabric_private_memeq(
                   fabric->authorities[i].index.binding_id,
                   binding_id->bytes,
                   16u)) {
            const fabric_authority_slot_t *s = &fabric->authorities[i];
            ninlil_fabric_private_memzero(out_binding, sizeof(*out_binding));
            out_binding->api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
            out_binding->struct_size = (uint16_t)sizeof(*out_binding);
            (void)memcpy(out_binding->binding_id.bytes, s->index.binding_id, 16u);
            (void)memcpy(
                out_binding->service_identity_digest,
                s->index.service_identity_digest,
                32u);
            out_binding->family = s->index.family;
            out_binding->direction = s->index.direction;
            out_binding->traffic_class = s->index.traffic_class;
            out_binding->scope_selector = s->index.scope_selector;
            (void)memcpy(
                out_binding->endpoint_runtime_id.bytes,
                s->index.endpoint_runtime_id,
                16u);
            (void)memcpy(
                out_binding->target_runtime_id.bytes,
                s->index.target_runtime_id,
                16u);
            (void)memcpy(
                out_binding->target_application_id.bytes,
                s->index.target_application_id,
                16u);
            (void)memcpy(out_binding->policy_id.bytes, s->index.policy_id, 16u);
            out_binding->policy_revision = s->index.policy_revision;
            (void)memcpy(out_binding->policy_digest, s->policy_digest, 32u);
            out_binding->authority_state = s->authority_state;
            (void)memcpy(out_binding->authority_id.bytes, s->authority_id, 16u);
            out_binding->authority_term = s->authority_term;
            out_binding->assignment_epoch = s->assignment_epoch;
            (void)memcpy(out_binding->owner_scope_id.bytes, s->owner_scope_id, 16u);
            (void)memcpy(out_binding->owner_tuple_digest, s->owner_tuple_digest, 32u);
            (void)memcpy(
                out_binding->endpoint_runtime_id.bytes,
                s->endpoint_runtime_id,
                16u);
            out_binding->assignment_revision = s->record_revision;
            return NINLIL_FABRIC_PRIVATE_OK;
        }
    }
    return NINLIL_FABRIC_PRIVATE_UNAVAILABLE;
}

ninlil_fabric_private_status_t ninlil_fabric_private_link_snapshot_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *instance_id,
    ninlil_fabric_link_descriptor_v1_t *out_descriptor,
    ninlil_fabric_link_state_v1_t *out_state)
{
    ninlil_fabric_private_status_t st = owner_check(fabric);
    uint32_t i;
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    if (instance_id == NULL || out_descriptor == NULL || out_state == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    for (i = 0u; i < NINLIL_FABRIC_REGISTRY_MAX; ++i) {
        if (fabric->regs[i].used != 0u
            && fabric->regs[i].lifecycle != FABRIC_REG_CONSUMED
            && ninlil_fabric_private_memeq(
                   fabric->regs[i].descriptor.instance_id.bytes,
                   instance_id->bytes,
                   16u)) {
            *out_descriptor = fabric->regs[i].descriptor;
            *out_state = fabric->regs[i].state;
            return NINLIL_FABRIC_PRIVATE_OK;
        }
    }
    return NINLIL_FABRIC_PRIVATE_UNAVAILABLE;
}

ninlil_fabric_private_status_t ninlil_fabric_private_policy_snapshot_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *policy_id,
    uint64_t revision,
    ninlil_fabric_path_policy_v1_t *out_policy)
{
    ninlil_fabric_private_status_t st = owner_check(fabric);
    uint32_t i;
    uint32_t c;
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    if (policy_id == NULL || revision == 0u || out_policy == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    for (i = 0u; i < FABRIC_RAM_POLICY_MAX; ++i) {
        if (fabric->policies[i].index.used != 0u
            && ninlil_fabric_private_memeq(
                   fabric->policies[i].index.policy_id,
                   policy_id->bytes,
                   16u)
            && fabric->policies[i].index.revision == revision) {
            const fabric_policy_slot_t *pslot = &fabric->policies[i];
            ninlil_fabric_private_memzero(out_policy, sizeof(*out_policy));
            out_policy->api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
            out_policy->struct_size = (uint16_t)sizeof(*out_policy);
            (void)memcpy(
                out_policy->policy_id.bytes, pslot->index.policy_id, 16u);
            out_policy->revision = pslot->index.revision;
            (void)memcpy(
                out_policy->canonical_digest_zero_on_input,
                pslot->index.canonical_digest,
                32u);
            (void)memcpy(
                out_policy->service_identity_digest,
                pslot->index.service_identity_digest,
                32u);
            out_policy->family = pslot->index.family;
            out_policy->direction = pslot->index.direction;
            out_policy->traffic_class = pslot->index.traffic_class;
            out_policy->scope_selector = pslot->index.scope_selector;
            out_policy->required_capability_flags =
                pslot->index.required_capability_flags;
            out_policy->required_security_flags =
                pslot->index.required_security_flags;
            out_policy->maximum_latency_class =
                pslot->index.maximum_latency_class;
            out_policy->maximum_cost_class = pslot->index.maximum_cost_class;
            out_policy->minimum_packet_bytes =
                pslot->index.minimum_packet_bytes;
            out_policy->authority_mode = pslot->index.authority_mode;
            out_policy->deadline_guard_ms = pslot->index.deadline_guard_ms;
            out_policy->candidate_count = pslot->index.candidate_count;
            {
                uint8_t key[28];
                uint8_t value[352];
                ninlil_storage_txn_t txn = NULL;
                ninlil_bytes_view_t kv;
                ninlil_mut_bytes_t mv;
                ninlil_fabric_private_key_fbp1(
                    pslot->index.policy_id, pslot->index.revision, key);
                kv.data = key;
                kv.length = 28u;
                mv.data = value;
                mv.capacity = 352u;
                mv.length = 0u;
                if (fabric->storage.begin(
                        fabric->storage.user,
                        fabric->storage_handle,
                        NINLIL_STORAGE_READ_ONLY,
                        &txn)
                    == NINLIL_STORAGE_OK) {
                    if (fabric->storage.get(
                            fabric->storage.user, txn, kv, &mv)
                        == NINLIL_STORAGE_OK) {
                        ninlil_fabric_private_common_envelope_t env;
                        const uint8_t *pl = NULL;
                        if (ninlil_fabric_private_record_decode_envelope(
                                value,
                                mv.length,
                                (const uint8_t *)"FBP1",
                                328u,
                                &env,
                                &pl)
                            == NINLIL_FABRIC_PRIVATE_RECORD_OK) {
                            ninlil_fabric_private_fbp1_t full;
                            if (ninlil_fabric_private_fbp1_decode(pl, &full)
                                == NINLIL_FABRIC_PRIVATE_RECORD_OK) {
                                for (c = 0u;
                                     c < full.candidate_count && c < 8u;
                                     ++c) {
                                    (void)memcpy(
                                        out_policy->candidates[c]
                                            .instance_id.bytes,
                                        full.candidates[c].instance_id,
                                        16u);
                                    out_policy->candidates[c].rank =
                                        full.candidates[c].rank;
                                    out_policy->candidates[c]
                                        .reservation_units =
                                        full.candidates[c].reservation_units;
                                }
                            }
                        }
                    }
                    if (fabric->storage.rollback(fabric->storage.user, txn)
                        != NINLIL_STORAGE_OK) {
                        return NINLIL_FABRIC_PRIVATE_CORRUPT;
                    }
                }
            }
            return NINLIL_FABRIC_PRIVATE_OK;
        }
    }
    return NINLIL_FABRIC_PRIVATE_UNAVAILABLE;
}


ninlil_fabric_private_status_t ninlil_fabric_private_link_availability_update_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *instance_id,
    const ninlil_fabric_link_state_v1_t *new_state)
{
    ninlil_fabric_private_status_t st = owner_check(fabric);
    uint32_t i;
    fabric_reg_slot_t *slot = NULL;
    ninlil_time_sample_t now;

    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    if (instance_id == NULL || new_state == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (!header_ok(new_state->api_version, new_state->struct_size,
            (uint16_t)sizeof(*new_state))) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (new_state->availability_epoch == 0u
        || (new_state->available != 0u && new_state->available != 1u)
        || new_state->reserved_zero != 0u) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    for (i = 0u; i < NINLIL_FABRIC_REGISTRY_MAX; ++i) {
        if (fabric->regs[i].used != 0u
            && fabric->regs[i].lifecycle != FABRIC_REG_CONSUMED
            && ninlil_fabric_private_memeq(
                   fabric->regs[i].descriptor.instance_id.bytes,
                   instance_id->bytes,
                   16u)) {
            slot = &fabric->regs[i];
            break;
        }
    }
    if (slot == NULL) {
        return NINLIL_FABRIC_PRIVATE_UNAVAILABLE;
    }
    if (slot->lifecycle != FABRIC_REG_ACTIVE) {
        return NINLIL_FABRIC_PRIVATE_CONFLICT;
    }
    /* Same-epoch exact re-read: idempotent OK without write. */
    if (new_state->availability_epoch == slot->state.availability_epoch
        && new_state->available == slot->state.available
        && new_state->available_until_ms == slot->state.available_until_ms
        && ninlil_fabric_private_memeq(
               new_state->availability_clock_epoch_id.bytes,
               slot->state.availability_clock_epoch_id.bytes,
               16u)) {
        return NINLIL_FABRIC_PRIVATE_OK;
    }
    /* strict +1 epoch; same/older epoch without exact match = CONFLICT */
    if (new_state->availability_epoch != slot->state.availability_epoch + 1u) {
        return NINLIL_FABRIC_PRIVATE_CONFLICT;
    }
    if (!ninlil_fabric_private_memeq(
            new_state->availability_clock_epoch_id.bytes,
            slot->state.availability_clock_epoch_id.bytes,
            16u)
        && slot->state.availability_epoch != 0u) {
        /* allow first publish any epoch id; later must match for hot update */
        if (slot->state.availability_epoch > 0u
            && !ninlil_fabric_private_is_zero(
                   slot->state.availability_clock_epoch_id.bytes, 16u)) {
            return NINLIL_FABRIC_PRIVATE_DENIED;
        }
    }
    ninlil_fabric_private_memzero(&now, sizeof(now));
    now.abi_version = NINLIL_ABI_VERSION;
    now.struct_size = (uint16_t)sizeof(now);
    if (fabric->clock.now(fabric->clock.user, &now) != NINLIL_PORT_OK
        || now.trust != NINLIL_CLOCK_TRUSTED) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    /* FULL FBR1: record revision + availability epoch both strict +1. */
    {
        uint8_t key[20];
        uint8_t payload[348];
        uint8_t value[372];
        uint32_t vlen = 0u;
        uint64_t new_rev;
        ninlil_fabric_private_fbr1_t rec;
        fabric_fbr1_pin_t *pin =
            fbr1_pin_find(fabric, instance_id->bytes);
        if (slot->record_revision == 0u) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
        if (fabric_checked_next_u64(slot->record_revision, &new_rev) == 0) {
            return NINLIL_FABRIC_PRIVATE_CAPACITY;
        }
        fbr1_fill_from_descriptor_state(
            &rec,
            &slot->descriptor,
            new_state,
            (uint8_t)NINLIL_FABRIC_PRIVATE_LIFECYCLE_ACTIVE);
        ninlil_fabric_private_key_fbr1(instance_id->bytes, key);
        if (ninlil_fabric_private_fbr1_encode(&rec, payload)
                != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
        if (ninlil_fabric_private_record_encode_envelope(
                (const uint8_t *)"FBR1",
                new_rev,
                payload,
                348u,
                value,
                372u,
                &vlen)
            != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
        st = storage_put_full(fabric, key, 20u, value, vlen);
        if (st == NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN) {
            /* fence: do not publish new availability for selection */
            return NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN;
        }
        if (st != NINLIL_FABRIC_PRIVATE_OK) {
            return st;
        }
        slot->record_revision = new_rev;
        slot->state = *new_state;
        if (pin != NULL) {
            fbr1_pin_store(pin, new_rev, &rec, key, value);
        } else {
            pin = fbr1_pin_alloc(fabric);
            if (pin != NULL) {
                fbr1_pin_store(pin, new_rev, &rec, key, value);
            }
        }
    }
    return NINLIL_FABRIC_PRIVATE_OK;
}

ninlil_fabric_private_status_t ninlil_fabric_private_metrics_snapshot_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *instance_id,
    ninlil_fabric_link_metrics_v1_t *out_metrics)
{
    ninlil_fabric_private_status_t st = owner_check(fabric);
    uint32_t i;
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    if (instance_id == NULL || out_metrics == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    for (i = 0u; i < NINLIL_FABRIC_REGISTRY_MAX; ++i) {
        if (fabric->regs[i].used != 0u
            && ninlil_fabric_private_memeq(
                   fabric->regs[i].descriptor.instance_id.bytes,
                   instance_id->bytes,
                   16u)) {
            *out_metrics = fabric->regs[i].metrics;
            return NINLIL_FABRIC_PRIVATE_OK;
        }
    }
    return NINLIL_FABRIC_PRIVATE_UNAVAILABLE;
}

/* ---------- enrich / project ---------- */

static void text_from_bearer(
    const ninlil_text_id_t *text,
    ninlil_fabric_private_nfl1_var_view_t *out)
{
    out->bytes = text->bytes;
    out->length = text->length;
}

ninlil_fabric_private_status_t ninlil_fabric_private_enrich_nfl1_v1(
    const ninlil_bearer_message_t *message,
    const uint8_t authority_id[16],
    uint64_t authority_term,
    uint32_t assignment_epoch,
    const uint8_t route_policy_id[16],
    uint64_t route_policy_revision,
    const uint8_t route_policy_digest[32],
    const uint8_t selected_path_id[16],
    uint64_t path_selection_epoch,
    uint8_t *out_packet,
    uint32_t out_capacity,
    uint32_t *out_length)
{
    ninlil_fabric_private_nfl1_envelope_t env;
    ninlil_fabric_private_nfl1_status_t ns;

    if (message == NULL || authority_id == NULL || route_policy_id == NULL
        || route_policy_digest == NULL || selected_path_id == NULL
        || out_packet == NULL || out_length == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (message->abi_version != NINLIL_ABI_VERSION) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }

    ninlil_fabric_private_memzero(&env, sizeof(env));
    env.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    env.struct_size = (uint16_t)sizeof(env);
    env.message_kind = message->kind;
    env.message_flags = message->flags;
    (void)memcpy(env.transaction_id.bytes, message->transaction_id.bytes, 16u);
    (void)memcpy(env.attempt_id.bytes, message->attempt_id.bytes, 16u);
    (void)memcpy(env.event_id.bytes, message->event_id.bytes, 16u);
    (void)memcpy(
        env.source_runtime_id.bytes, message->source.runtime_id.bytes, 16u);
    (void)memcpy(
        env.source_application_id.bytes,
        message->source.application_instance_id.bytes,
        16u);
    (void)memcpy(
        env.source_device_id.bytes,
        message->source.local_identity.device_id.bytes,
        16u);
    (void)memcpy(
        env.source_installation_id.bytes,
        message->source.local_identity.installation_id.bytes,
        16u);
    (void)memcpy(
        env.source_site_id.bytes,
        message->source.local_identity.site_domain_id.bytes,
        16u);
    env.source_binding_epoch = message->source.local_identity.binding_epoch;
    env.source_membership_epoch =
        message->source.local_identity.membership_epoch;
    env.source_flags = message->source.local_identity.flags;
    (void)memcpy(
        env.target_runtime_id.bytes, message->target.target_runtime_id.bytes, 16u);
    (void)memcpy(
        env.target_application_id.bytes,
        message->target.target_application_instance_id.bytes,
        16u);
    (void)memcpy(
        env.target_device_id.bytes, message->target.device_id.bytes, 16u);
    (void)memcpy(
        env.target_installation_id.bytes,
        message->target.installation_id.bytes,
        16u);
    (void)memcpy(
        env.target_site_id.bytes, message->target.site_domain_id.bytes, 16u);
    env.target_binding_epoch = message->target.binding_epoch;
    env.target_membership_epoch = message->target.membership_epoch;
    env.target_flags = message->target.flags;
    (void)memcpy(env.authority_id.bytes, authority_id, 16u);
    env.authority_term = authority_term;
    env.assignment_epoch = assignment_epoch;
    env.descriptor_revision = message->service.descriptor_revision;
    env.descriptor_digest.algorithm = message->service.descriptor_digest.algorithm;
    (void)memcpy(
        env.descriptor_digest.bytes, message->service.descriptor_digest.bytes, 32u);
    env.schema_major = message->service.schema_major;
    env.schema_minor = message->service.schema_minor;
    env.family = message->service.family;
    env.content_digest.algorithm = message->content_digest.algorithm;
    (void)memcpy(
        env.content_digest.bytes, message->content_digest.bytes, 32u);
    env.generation = message->generation;
    (void)memcpy(
        env.deadline_clock_epoch_id.bytes,
        message->deadline_clock_epoch_id.bytes,
        16u);
    env.absolute_effect_deadline_ms = message->absolute_effect_deadline_ms;
    env.evidence_grace_ms = message->evidence_grace_ms;
    env.required_evidence = message->required_evidence;
    env.receipt_stage = message->receipt_stage;
    env.disposition = message->disposition;
    env.effect_certainty = message->effect_certainty;
    env.retry_guidance = message->retry_guidance;
    env.cancel_kind = message->cancel_kind;
    env.retry_delay_ms = message->retry_delay_ms;
    (void)memcpy(
        env.evidence_time_clock_epoch_id.bytes,
        message->evidence_time.clock_epoch_id.bytes,
        16u);
    env.evidence_time_now_ms = message->evidence_time.now_ms;
    env.evidence_time_trust = message->evidence_time.trust;
    (void)memcpy(env.route_policy_id.bytes, route_policy_id, 16u);
    env.route_policy_revision = route_policy_revision;
    env.route_policy_digest.algorithm = 1u;
    (void)memcpy(env.route_policy_digest.bytes, route_policy_digest, 32u);
    (void)memcpy(env.selected_path_id.bytes, selected_path_id, 16u);
    env.path_selection_epoch = path_selection_epoch;
    env.route_flags = 0u;
    text_from_bearer(&message->service.namespace_id, &env.namespace_id);
    text_from_bearer(&message->service.service_id, &env.service_id);
    text_from_bearer(&message->service.schema_id, &env.schema_id);
    env.payload.bytes = message->payload.data;
    env.payload.length = message->payload.length;
    env.evidence.bytes = message->evidence.data;
    env.evidence.length = message->evidence.length;

    ns = ninlil_fabric_private_nfl1_encode(
        &env, out_packet, out_capacity, out_length);
    if (ns == NINLIL_FABRIC_PRIVATE_NFL1_OK) {
        return NINLIL_FABRIC_PRIVATE_OK;
    }
    if (ns == NINLIL_FABRIC_PRIVATE_NFL1_BUFFER_TOO_SMALL) {
        return NINLIL_FABRIC_PRIVATE_CAPACITY;
    }
    if (ns == NINLIL_FABRIC_PRIVATE_NFL1_INVALID_ARGUMENT) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (ns == NINLIL_FABRIC_PRIVATE_NFL1_UNSUPPORTED) {
        return NINLIL_FABRIC_PRIVATE_UNSUPPORTED;
    }
    return NINLIL_FABRIC_PRIVATE_CORRUPT;
}

ninlil_fabric_private_status_t ninlil_fabric_private_project_bearer_v1(
    const uint8_t *packet,
    uint32_t packet_length,
    ninlil_fabric_private_nfl1_workspace_t *workspace,
    ninlil_bearer_message_t *out_message)
{
    ninlil_fabric_private_nfl1_envelope_t env;
    ninlil_fabric_private_nfl1_status_t ns;
    uint32_t required = 0u;

    if (packet == NULL || workspace == NULL || out_message == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    ns = ninlil_fabric_private_nfl1_decode(
        packet, packet_length, workspace, &env, &required);
    if (ns != NINLIL_FABRIC_PRIVATE_NFL1_OK) {
        return ns == NINLIL_FABRIC_PRIVATE_NFL1_UNSUPPORTED
            ? NINLIL_FABRIC_PRIVATE_UNSUPPORTED
            : NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    ninlil_fabric_private_memzero(out_message, sizeof(*out_message));
    out_message->abi_version = NINLIL_ABI_VERSION;
    out_message->struct_size = (uint16_t)sizeof(*out_message);
    out_message->kind = env.message_kind;
    out_message->flags = env.message_flags;
    (void)memcpy(out_message->transaction_id.bytes, env.transaction_id.bytes, 16u);
    (void)memcpy(out_message->attempt_id.bytes, env.attempt_id.bytes, 16u);
    (void)memcpy(out_message->event_id.bytes, env.event_id.bytes, 16u);
    out_message->source.abi_version = NINLIL_ABI_VERSION;
    out_message->source.struct_size = (uint16_t)sizeof(out_message->source);
    (void)memcpy(
        out_message->source.runtime_id.bytes, env.source_runtime_id.bytes, 16u);
    (void)memcpy(
        out_message->source.application_instance_id.bytes,
        env.source_application_id.bytes,
        16u);
    out_message->source.local_identity.abi_version = NINLIL_ABI_VERSION;
    out_message->source.local_identity.struct_size =
        (uint16_t)sizeof(out_message->source.local_identity);
    (void)memcpy(
        out_message->source.local_identity.device_id.bytes,
        env.source_device_id.bytes,
        16u);
    (void)memcpy(
        out_message->source.local_identity.installation_id.bytes,
        env.source_installation_id.bytes,
        16u);
    (void)memcpy(
        out_message->source.local_identity.site_domain_id.bytes,
        env.source_site_id.bytes,
        16u);
    out_message->source.local_identity.binding_epoch = env.source_binding_epoch;
    out_message->source.local_identity.membership_epoch =
        env.source_membership_epoch;
    out_message->source.local_identity.flags = env.source_flags;
    out_message->target.abi_version = NINLIL_ABI_VERSION;
    out_message->target.struct_size = (uint16_t)sizeof(out_message->target);
    (void)memcpy(
        out_message->target.target_runtime_id.bytes,
        env.target_runtime_id.bytes,
        16u);
    (void)memcpy(
        out_message->target.target_application_instance_id.bytes,
        env.target_application_id.bytes,
        16u);
    (void)memcpy(
        out_message->target.device_id.bytes, env.target_device_id.bytes, 16u);
    (void)memcpy(
        out_message->target.installation_id.bytes,
        env.target_installation_id.bytes,
        16u);
    (void)memcpy(
        out_message->target.site_domain_id.bytes, env.target_site_id.bytes, 16u);
    out_message->target.binding_epoch = env.target_binding_epoch;
    out_message->target.membership_epoch = env.target_membership_epoch;
    out_message->target.flags = env.target_flags;
    out_message->service.abi_version = NINLIL_ABI_VERSION;
    out_message->service.struct_size = (uint16_t)sizeof(out_message->service);
    out_message->service.namespace_id.length = (uint8_t)env.namespace_id.length;
    (void)memcpy(
        out_message->service.namespace_id.bytes,
        env.namespace_id.bytes,
        env.namespace_id.length);
    out_message->service.service_id.length = (uint8_t)env.service_id.length;
    (void)memcpy(
        out_message->service.service_id.bytes,
        env.service_id.bytes,
        env.service_id.length);
    out_message->service.schema_id.length = (uint8_t)env.schema_id.length;
    (void)memcpy(
        out_message->service.schema_id.bytes,
        env.schema_id.bytes,
        env.schema_id.length);
    out_message->service.descriptor_revision = env.descriptor_revision;
    out_message->service.descriptor_digest.algorithm =
        env.descriptor_digest.algorithm;
    (void)memcpy(
        out_message->service.descriptor_digest.bytes,
        env.descriptor_digest.bytes,
        32u);
    out_message->service.schema_major = env.schema_major;
    out_message->service.schema_minor = env.schema_minor;
    out_message->service.family = env.family;
    out_message->content_digest.algorithm = env.content_digest.algorithm;
    (void)memcpy(
        out_message->content_digest.bytes, env.content_digest.bytes, 32u);
    out_message->generation = env.generation;
    (void)memcpy(
        out_message->deadline_clock_epoch_id.bytes,
        env.deadline_clock_epoch_id.bytes,
        16u);
    out_message->absolute_effect_deadline_ms = env.absolute_effect_deadline_ms;
    out_message->evidence_grace_ms = env.evidence_grace_ms;
    out_message->required_evidence = env.required_evidence;
    out_message->receipt_stage = env.receipt_stage;
    out_message->disposition = env.disposition;
    out_message->effect_certainty = env.effect_certainty;
    out_message->retry_guidance = env.retry_guidance;
    out_message->cancel_kind = env.cancel_kind;
    out_message->retry_delay_ms = env.retry_delay_ms;
    /*
     * The public bearer ABI requires unused kind-specific fields to remain
     * canonical zero, including the nested ABI header. NFL1 permits evidence
     * time only on RECEIPT, so do not manufacture a non-zero header for the
     * other five message kinds.
     */
    if (env.message_kind == NINLIL_BEARER_MESSAGE_RECEIPT) {
        out_message->evidence_time.abi_version = NINLIL_ABI_VERSION;
        out_message->evidence_time.struct_size =
            (uint16_t)sizeof(out_message->evidence_time);
        (void)memcpy(
            out_message->evidence_time.clock_epoch_id.bytes,
            env.evidence_time_clock_epoch_id.bytes,
            16u);
        out_message->evidence_time.now_ms = env.evidence_time_now_ms;
        out_message->evidence_time.trust = env.evidence_time_trust;
    }
    out_message->payload.data = env.payload.bytes;
    out_message->payload.length = env.payload.length;
    out_message->evidence.data = env.evidence.bytes;
    out_message->evidence.length = env.evidence.length;
    (void)required;
    return NINLIL_FABRIC_PRIVATE_OK;
}

/* ---------- bearer adapter send path ---------- */

static fabric_reg_slot_t *find_reg_by_id(
    ninlil_fabric_private_t *fabric, const uint8_t id[16])
{
    uint32_t i;
    for (i = 0u; i < NINLIL_FABRIC_REGISTRY_MAX; ++i) {
        if (fabric->regs[i].used != 0u
            && fabric->regs[i].lifecycle == FABRIC_REG_ACTIVE
            && ninlil_fabric_private_memeq(
                   fabric->regs[i].descriptor.instance_id.bytes, id, 16u)) {
            return &fabric->regs[i];
        }
    }
    return NULL;
}

/* ACTIVE or DRAINING: needed for token reclaim after unregister_begin. */
static fabric_reg_slot_t *find_reg_by_id_for_token(
    ninlil_fabric_private_t *fabric, const uint8_t id[16])
{
    uint32_t i;
    for (i = 0u; i < NINLIL_FABRIC_REGISTRY_MAX; ++i) {
        if (fabric->regs[i].used != 0u
            && (fabric->regs[i].lifecycle == FABRIC_REG_ACTIVE
                || fabric->regs[i].lifecycle == FABRIC_REG_DRAINING)
            && ninlil_fabric_private_memeq(
                   fabric->regs[i].descriptor.instance_id.bytes, id, 16u)) {
            return &fabric->regs[i];
        }
    }
    return NULL;
}

/*
 * Identity index: same {transaction, attempt, kind, response_slot} regardless
 * of foundation digest / 76-byte FBA1 key. Used before new-key creation so a
 * one-byte message change cannot bypass conflict checks via a new key.
 */
static fabric_attempt_slot_t *find_attempt_by_identity(
    ninlil_fabric_private_t *fabric,
    const uint8_t transaction_id[16],
    const uint8_t attempt_id[16],
    uint32_t message_kind,
    uint32_t response_slot)
{
    uint32_t i;
    if (fabric == NULL || transaction_id == NULL || attempt_id == NULL) {
        return NULL;
    }
    for (i = 0u; i < NINLIL_FABRIC_ATTEMPT_MAX; ++i) {
        fabric_attempt_slot_t *cand = &fabric->attempts[i];
        if (cand->used == 0u) {
            continue;
        }
        if (cand->attempt.message_kind != message_kind
            || cand->attempt.response_slot != response_slot) {
            continue;
        }
        if (ninlil_fabric_private_memeq(
                cand->attempt.transaction_id, transaction_id, 16u)
            && ninlil_fabric_private_memeq(
                   cand->attempt.attempt_id, attempt_id, 16u)) {
            return cand;
        }
    }
    return NULL;
}

static fabric_attempt_slot_t *find_attempt_slot(
    ninlil_fabric_private_t *fabric,
    const uint8_t *key)
{
    uint32_t i;
    for (i = 0u; i < NINLIL_FABRIC_ATTEMPT_MAX; ++i) {
        if (fabric->attempts[i].used != 0u
            && ninlil_fabric_private_memeq(fabric->attempts[i].key, key, 76u)) {
            return &fabric->attempts[i];
        }
    }
    return NULL;
}

/*
 * Durable identity guard for RAM-evicted DRAINED attempts.
 *
 * FBA1 keys begin with:
 *   "FBA1" || transaction_id || attempt_id || kind || response_slot
 * and end with the foundation digest.  A prefix lookup therefore preserves
 * the same-attempt conflict rule even after retention-complete volatile
 * state has been reclaimed.  The durable FBA1 row is never erased here.
 */
static ninlil_fabric_private_status_t
fabric_durable_attempt_identity_exists(
    ninlil_fabric_private_t *fabric,
    const uint8_t transaction_id[16],
    const uint8_t attempt_id[16],
    uint32_t message_kind,
    uint32_t response_slot,
    int *out_exists)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_iter_t iter = NULL;
    ninlil_storage_status_t st;
    ninlil_bytes_view_t prefix;
    uint8_t prefix_bytes[44];
    uint8_t key_buf[80];
    uint8_t value_buf[NINLIL_FABRIC_VALUE_CEILING];
    ninlil_mut_bytes_t key_mut;
    ninlil_mut_bytes_t value_mut;
    ninlil_fabric_private_status_t rc;

    if (fabric == NULL || transaction_id == NULL || attempt_id == NULL
        || out_exists == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    *out_exists = 0;
    prefix_bytes[0] = (uint8_t)'F';
    prefix_bytes[1] = (uint8_t)'B';
    prefix_bytes[2] = (uint8_t)'A';
    prefix_bytes[3] = (uint8_t)'1';
    (void)memcpy(prefix_bytes + 4u, transaction_id, 16u);
    (void)memcpy(prefix_bytes + 20u, attempt_id, 16u);
    ninlil_fabric_private_put_u32_be(prefix_bytes + 36u, message_kind);
    ninlil_fabric_private_put_u32_be(prefix_bytes + 40u, response_slot);

    st = fabric->storage.begin(
        fabric->storage.user,
        fabric->storage_handle,
        NINLIL_STORAGE_READ_ONLY,
        &txn);
    if (st != NINLIL_STORAGE_OK) {
        return map_storage_status(st);
    }
    prefix.data = prefix_bytes;
    prefix.length = (uint32_t)sizeof(prefix_bytes);
    st = fabric->storage.iter_open(
        fabric->storage.user, txn, prefix, &iter);
    if (st != NINLIL_STORAGE_OK) {
        return reload_close_ro(
            fabric, &iter, &txn, map_storage_status(st));
    }

    for (;;) {
        key_mut.data = key_buf;
        key_mut.capacity = (uint32_t)sizeof(key_buf);
        key_mut.length = 0u;
        value_mut.data = value_buf;
        value_mut.capacity = (uint32_t)sizeof(value_buf);
        value_mut.length = 0u;
        st = fabric->storage.iter_next(
            fabric->storage.user, iter, &key_mut, &value_mut);
        if (st == NINLIL_STORAGE_NOT_FOUND) {
            rc = NINLIL_FABRIC_PRIVATE_OK;
            break;
        }
        if (st != NINLIL_STORAGE_OK) {
            rc = map_storage_status(st);
            break;
        }
        /*
         * The Storage ABI requires prefix filtering.  Re-check it anyway so
         * a non-conforming port cannot create a false identity match.
         */
        if (key_mut.length < sizeof(prefix_bytes)
            || !ninlil_fabric_private_memeq(
                   key_buf, prefix_bytes, sizeof(prefix_bytes))) {
            continue;
        }
        if (key_mut.length != 76u) {
            rc = NINLIL_FABRIC_PRIVATE_CORRUPT;
            break;
        }
        *out_exists = 1;
        rc = NINLIL_FABRIC_PRIVATE_OK;
        break;
    }
    return reload_close_ro(fabric, &iter, &txn, rc);
}


static uint32_t alloc_packet_slot(ninlil_fabric_private_t *fabric)
{
    uint32_t i;
    for (i = 0u; i < NINLIL_FABRIC_SHARED_QUEUE_MAX; ++i) {
        if (fabric->packet_pool[i].used == 0u) {
            ninlil_fabric_private_memzero(
                &fabric->packet_pool[i], sizeof(fabric->packet_pool[i]));
            fabric->packet_pool[i].used = 1u;
            return i;
        }
    }
    return UINT32_MAX;
}

static void free_packet_slot(ninlil_fabric_private_t *fabric, uint32_t slot)
{
    if (slot >= NINLIL_FABRIC_SHARED_QUEUE_MAX) {
        return;
    }
    ninlil_fabric_private_memzero(
        &fabric->packet_pool[slot], sizeof(fabric->packet_pool[slot]));
}

/*
 * Provider token drain (ADR-0017 / Sol P0).
 * Release only after terminal cancel (or cancel_first=0 for already-terminal
 * poll). cancel return is observed: LOST_UNKNOWN keeps LINK_RETAINED token
 * retained and does not release/decrement. Returns 1 if fully released,
 * 0 if token remains retained.
 */
static int attempt_drop_provider_token(
    ninlil_fabric_private_t *fabric,
    fabric_attempt_slot_t *at,
    int cancel_first)
{
    fabric_reg_slot_t *reg;
    ninlil_fabric_packet_token_t tok;
    ninlil_fabric_link_status_t cs;

    if (fabric == NULL || at == NULL || at->has_token == 0u) {
        if (at != NULL) {
            at->has_token = 0u;
            at->token = NULL;
        }
        return 1;
    }
    tok = at->token;
    if (tok == NULL) {
        at->has_token = 0u;
        at->token = NULL;
        return 1;
    }
    reg = find_reg_by_id_for_token(fabric, at->attempt.selected_path_id);
    if (reg == NULL || reg->ops.release_send == NULL) {
        /* No provider path: drop local tracking only (cannot release). */
        at->has_token = 0u;
        at->token = NULL;
        return 1;
    }
    if (cancel_first != 0) {
        if (reg->ops.cancel_send == NULL) {
            return 0;
        }
        fabric->reentrant = 1u;
        cs = reg->ops.cancel_send(reg->ops.user, reg->handle, tok);
        fabric->reentrant = 0u;
        if (cs == NINLIL_FABRIC_LINK_LOST_UNKNOWN) {
            /* Keep retained token; step must re-drive; close never done=1. */
            return 0;
        }
        if (cs != NINLIL_FABRIC_LINK_OK) {
            /* Non-terminal cancel: do not release, do not decrement. */
            return 0;
        }
        /* Terminal cancel OK — fall through to release. */
    }
    /* Terminal path: clear local token then release exactly once. */
    at->has_token = 0u;
    at->token = NULL;
    fabric->reentrant = 1u;
    reg->ops.release_send(reg->ops.user, reg->handle, tok);
    fabric->reentrant = 0u;
    if (reg->retained_tokens > 0u) {
        reg->retained_tokens--;
    }
    return 1;
}

/* Persist FENCED_UNKNOWN for LINK_RETAINED LOST_UNKNOWN (FULL, fail-closed). */
static void attempt_fence_lost_unknown(
    ninlil_fabric_private_t *fabric, fabric_attempt_slot_t *at)
{
    ninlil_fabric_private_fba1_t next;
    ninlil_fabric_private_status_t pst;
    if (fabric == NULL || at == NULL || at->used == 0u) {
        return;
    }
    next = at->attempt;
    next.state = NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
    pst = fba1_persist_full_next(
        fabric, &next, at->key, &at->record_revision);
    if (pst == NINLIL_FABRIC_PRIVATE_OK) {
        at->attempt = next;
    } else {
        /* COMMIT_UNKNOWN or failure: keep durable fence class in RAM. */
        at->attempt.state = NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
    }
}

static fabric_attempt_slot_t *alloc_attempt_slot(
    ninlil_fabric_private_t *fabric)
{
    uint32_t i;
    for (i = 0u; i < NINLIL_FABRIC_ATTEMPT_MAX; ++i) {
        if (fabric->attempts[i].used == 0u) {
            ninlil_fabric_private_memzero(
                &fabric->attempts[i], sizeof(fabric->attempts[i]));
            fabric->attempts[i].used = 1u;
            fabric->attempts[i].packet_slot = UINT32_MAX;
            return &fabric->attempts[i];
        }
    }
    return NULL;
}

static void free_attempt_slot(
    ninlil_fabric_private_t *fabric, fabric_attempt_slot_t *attempt)
{
    if (fabric == NULL || attempt == NULL) {
        return;
    }
    ninlil_fabric_private_memzero(attempt, sizeof(*attempt));
}

/*
 * FBA1 deterministic GC eligibility:
 * - Runtime has released the DRAINED attempt (terminal revision non-zero);
 * - no provider token remains;
 * - the permit epoch is old, OR the trusted current epoch matches both permit
 *   and retention epochs and now >= max(retention_until, permit_expiry).
 */
static int fabric_attempt_gc_eligible(
    const fabric_attempt_slot_t *at, const ninlil_time_sample_t *now)
{
    uint64_t not_before;
    if (at == NULL || now == NULL || at->used == 0u
        || at->attempt.state != NINLIL_FABRIC_PRIVATE_ATTEMPT_DRAINED
        || at->attempt.runtime_terminal_revision == 0u || at->has_token != 0u
        || now->trust != NINLIL_CLOCK_TRUSTED) {
        return 0;
    }
    if (!ninlil_fabric_private_memeq(
            at->attempt.retry_lifetime_clock_epoch_id,
            now->clock_epoch_id.bytes,
            16u)) {
        return 1;
    }
    if (!ninlil_fabric_private_memeq(
            at->attempt.retention_clock_epoch_id,
            now->clock_epoch_id.bytes,
            16u)) {
        return 0;
    }
    not_before = at->attempt.retention_until_ms;
    if (at->attempt.permit_expires_at_ms > not_before) {
        not_before = at->attempt.permit_expires_at_ms;
    }
    return now->now_ms >= not_before ? 1 : 0;
}

/*
 * At most one erase per invocation. One attempted FULL erase consumes exactly
 * one step work unit. CU-NEW proves absence and frees RAM; CU-OLD retains the
 * row fail-closed; partial/third/error is surfaced.
 */
static ninlil_fabric_private_status_t fabric_gc_one_attempt(
    ninlil_fabric_private_t *fabric,
    const ninlil_time_sample_t *now,
    uint32_t *inout_work)
{
    uint32_t n;
    if (fabric == NULL || now == NULL || inout_work == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    for (n = 0u; n < NINLIL_FABRIC_ATTEMPT_MAX; ++n) {
        uint32_t i =
            (fabric->attempt_gc_cursor + n) % NINLIL_FABRIC_ATTEMPT_MAX;
        fabric_attempt_slot_t *at = &fabric->attempts[i];
        uint32_t cu_class = 0u;
        ninlil_fabric_private_status_t st;
        if (fabric_attempt_gc_eligible(at, now) == 0) {
            continue;
        }
        fabric->attempt_gc_cursor = (i + 1u) % NINLIL_FABRIC_ATTEMPT_MAX;
        st = storage_erase_full_ex(fabric, at->key, 76u, &cu_class);
        *inout_work += 1u;
        if (st == NINLIL_FABRIC_PRIVATE_OK
            || (st == NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN
                && cu_class == NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_NEW)) {
            if (at->packet_slot < NINLIL_FABRIC_SHARED_QUEUE_MAX) {
                free_packet_slot(fabric, at->packet_slot);
                at->packet_slot = UINT32_MAX;
            }
            free_attempt_slot(fabric, at);
            return NINLIL_FABRIC_PRIVATE_OK;
        }
        if (st == NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN
            && cu_class == NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_OLD) {
            return NINLIL_FABRIC_PRIVATE_OK;
        }
        return st;
    }
    return NINLIL_FABRIC_PRIVATE_OK;
}

/*
 * FBT1 is retained until Runtime terminal authority has been persisted and
 * its same-epoch retention window has completed.  Unlike FBA1 there is no
 * provider token or permit-expiry fence on a trigger.
 */
static int fabric_trigger_gc_eligible(
    const fabric_trigger_slot_t *trigger,
    const ninlil_time_sample_t *now)
{
    return trigger != NULL && trigger->used != 0u
        && trigger->trigger.runtime_terminal_revision != 0u
        && fabric_retention_complete(
               trigger->trigger.retention_clock_epoch_id,
               trigger->trigger.retention_until_ms,
               now)
            != 0;
}

/* At most one exact FBT1 FULL erase per invocation. */
static ninlil_fabric_private_status_t fabric_gc_one_trigger(
    ninlil_fabric_private_t *fabric,
    const ninlil_time_sample_t *now,
    uint32_t *inout_work)
{
    uint32_t n;
    if (fabric == NULL || now == NULL || inout_work == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    for (n = 0u; n < FABRIC_RAM_TRIGGER_MAX; ++n) {
        uint32_t i =
            (fabric->trigger_gc_cursor + n) % FABRIC_RAM_TRIGGER_MAX;
        fabric_trigger_slot_t *trigger = &fabric->triggers[i];
        uint8_t key[40];
        uint32_t cu_class = 0u;
        ninlil_fabric_private_status_t st;
        if (fabric_trigger_gc_eligible(trigger, now) == 0) {
            continue;
        }
        fabric->trigger_gc_cursor = (i + 1u) % FABRIC_RAM_TRIGGER_MAX;
        ninlil_fabric_private_key_fbt1(
            trigger->trigger.transaction_id,
            trigger->trigger.triggering_attempt_id,
            trigger->trigger.triggering_kind,
            key);
        st = storage_erase_full_ex(fabric, key, 40u, &cu_class);
        *inout_work += 1u;
        if (st == NINLIL_FABRIC_PRIVATE_OK
            || (st == NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN
                && cu_class == NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_NEW)) {
            ninlil_fabric_private_memzero(trigger, sizeof(*trigger));
            return NINLIL_FABRIC_PRIVATE_OK;
        }
        if (st == NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN
            && cu_class == NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_OLD) {
            return NINLIL_FABRIC_PRIVATE_OK;
        }
        return st;
    }
    return NINLIL_FABRIC_PRIVATE_OK;
}

/* TX admission: unique FBC1 by the same hard-filter predicate as selector. */
static fabric_authority_slot_t *fabric_resolve_unique_tx_authority(
    ninlil_fabric_private_t *fabric,
    const fabric_policy_slot_t *policy,
    const uint8_t service_digest[32],
    uint32_t family,
    uint32_t direction,
    uint16_t traffic_class,
    const uint8_t source_runtime_id[16],
    const uint8_t target_runtime_id[16],
    const uint8_t target_application_id[16])
{
    uint32_t i;
    uint32_t matches = 0u;
    fabric_authority_slot_t *found = NULL;
    const uint8_t *endpoint;

    if (fabric == NULL || policy == NULL || service_digest == NULL
        || source_runtime_id == NULL || target_runtime_id == NULL
        || target_application_id == NULL) {
        return NULL;
    }
    if (policy->index.scope_selector == NINLIL_FABRIC_SCOPE_SOURCE_RUNTIME) {
        endpoint = source_runtime_id;
    } else if (policy->index.scope_selector
        == NINLIL_FABRIC_SCOPE_TARGET_RUNTIME) {
        endpoint = target_runtime_id;
    } else {
        return NULL;
    }
    for (i = 0u; i < FABRIC_RAM_AUTHORITY_MAX; ++i) {
        fabric_authority_slot_t *auth = &fabric->authorities[i];
        if (auth->index.used == 0u) {
            continue;
        }
        if (!ninlil_fabric_private_memeq(
                auth->index.service_identity_digest, service_digest, 32u)
            || auth->index.family != family
            || auth->index.direction != direction
            || auth->index.traffic_class != traffic_class
            || auth->index.scope_selector != policy->index.scope_selector
            || !ninlil_fabric_private_memeq(
                   auth->endpoint_runtime_id, endpoint, 16u)
            || !ninlil_fabric_private_memeq(
                   auth->index.target_runtime_id, target_runtime_id, 16u)
            || !ninlil_fabric_private_memeq(
                   auth->index.target_application_id,
                   target_application_id,
                   16u)
            || !ninlil_fabric_private_memeq(
                   auth->index.policy_id, policy->index.policy_id, 16u)
            || auth->index.policy_revision != policy->index.revision
            || !ninlil_fabric_private_memeq(
                   auth->policy_digest, policy->index.canonical_digest, 32u)) {
            continue;
        }
        matches++;
        found = auth;
        if (matches > 1u) {
            return NULL;
        }
    }
    return matches == 1u ? found : NULL;
}

static void fabric_fence_reg_instance(
    ninlil_fabric_private_t *fabric, fabric_reg_slot_t *reg)
{
    (void)fabric;
    if (reg == NULL || reg->used == 0u) {
        return;
    }
    /* Shape/output contradictions fence instance from further selection. */
    if (reg->lifecycle == FABRIC_REG_ACTIVE) {
        reg->lifecycle = FABRIC_REG_DRAINING;
    }
    reg->metrics.corrupt_count++;
    fabric_metrics_bump(reg);
}

static void fabric_provider_release_rx(
    ninlil_fabric_private_t *fabric,
    fabric_reg_slot_t *reg,
    void *rx_token)
{
    if (fabric == NULL || reg == NULL || rx_token == NULL
        || reg->ops.release_received == NULL) {
        return;
    }
    fabric->reentrant = 1u;
    reg->ops.release_received(reg->ops.user, reg->handle, rx_token);
    fabric->reentrant = 0u;
}

static uint32_t direction_for_kind(uint32_t kind)
{
    return (kind == 1u || kind == 4u)
        ? NINLIL_FABRIC_POLICY_DIRECTION_FORWARD
        : NINLIL_FABRIC_POLICY_DIRECTION_REVERSE;
}

static uint16_t traffic_for_kind(uint32_t kind)
{
    return (kind == 4u || kind == 6u)
        ? (uint16_t)NINLIL_FABRIC_TRAFFIC_CONTROL
        : (uint16_t)NINLIL_FABRIC_TRAFFIC_APPLICATION;
}

static uint32_t triggering_kind_for_reverse(uint32_t kind)
{
    if (kind == NINLIL_BEARER_MESSAGE_RECEIPT
        || kind == NINLIL_BEARER_MESSAGE_DISPOSITION
        || kind == NINLIL_BEARER_MESSAGE_CUSTODY_ACCEPTED) {
        return NINLIL_BEARER_MESSAGE_APPLICATION;
    }
    if (kind == NINLIL_BEARER_MESSAGE_CANCEL_RESULT) {
        return NINLIL_BEARER_MESSAGE_CANCEL_REQUEST;
    }
    return 0u;
}

/*
 * A reverse send is authorized by the exact FBT1 written before the triggering
 * forward message was published to Runtime.  The lookup intentionally does not
 * consult the current route assignment: missing or duplicate saved context is
 * fail-closed.
 */
static int fabric_find_unique_reverse_send_trigger(
    ninlil_fabric_private_t *fabric,
    const ninlil_bearer_message_t *message,
    const ninlil_fabric_private_fbt1_t **out_trigger)
{
    const ninlil_fabric_private_fbt1_t *found = NULL;
    uint32_t expected_kind;
    uint32_t matches = 0u;
    uint32_t i;

    if (out_trigger != NULL) {
        *out_trigger = NULL;
    }
    if (fabric == NULL || message == NULL) {
        return 0;
    }
    expected_kind = triggering_kind_for_reverse(message->kind);
    if (expected_kind == 0u) {
        return 0;
    }
    for (i = 0u; i < FABRIC_RAM_TRIGGER_MAX; ++i) {
        const fabric_trigger_slot_t *slot = &fabric->triggers[i];
        const ninlil_fabric_private_fbt1_t *trigger;
        if (slot->used == 0u) {
            continue;
        }
        trigger = &slot->trigger;
        if (trigger->triggering_kind != expected_kind
            || !ninlil_fabric_private_memeq(
                trigger->transaction_id,
                message->transaction_id.bytes,
                16u)
            || !ninlil_fabric_private_memeq(
                trigger->triggering_attempt_id,
                message->attempt_id.bytes,
                16u)
            || !ninlil_fabric_private_memeq(
                trigger->endpoint_runtime_id,
                message->source.runtime_id.bytes,
                16u)) {
            continue;
        }
        matches++;
        found = trigger;
        if (matches > 1u) {
            return 0;
        }
    }
    if (matches != 1u || found == NULL) {
        return 0;
    }
    if (out_trigger != NULL) {
        *out_trigger = found;
    }
    return 1;
}

static int fabric_authority_matches_saved_trigger(
    const fabric_authority_slot_t *authority,
    const ninlil_fabric_private_fbt1_t *trigger)
{
    if (authority == NULL || trigger == NULL) {
        return 0;
    }
    return authority->authority_state == trigger->authority_state
        && authority->authority_term == trigger->authority_term
        && authority->assignment_epoch == trigger->assignment_epoch
        && ninlil_fabric_private_memeq(
            authority->authority_id, trigger->authority_id, 16u)
        && ninlil_fabric_private_memeq(
            authority->endpoint_runtime_id,
            trigger->endpoint_runtime_id,
            16u)
        && ninlil_fabric_private_memeq(
            authority->owner_scope_id, trigger->owner_scope_id, 16u)
        && ninlil_fabric_private_memeq(
            authority->owner_tuple_digest,
            trigger->owner_tuple_digest,
            32u)
        && ninlil_fabric_private_memeq(
            authority->index.policy_id, trigger->policy_id, 16u)
        && authority->index.policy_revision == trigger->policy_revision
        && ninlil_fabric_private_memeq(
            authority->policy_digest, trigger->policy_digest, 32u);
}

static ninlil_bearer_status_t fabric_bearer_open(
    void *user,
    const ninlil_id128_t *runtime_id,
    ninlil_role_t role,
    ninlil_bearer_handle_t *out_handle)
{
    ninlil_fabric_private_t *fabric = (ninlil_fabric_private_t *)user;
    ninlil_fabric_private_status_t st;
    (void)role;
    if (fabric == NULL || runtime_id == NULL || out_handle == NULL) {
        return NINLIL_BEARER_CORRUPT;
    }
    st = owner_check(fabric);
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st == NINLIL_FABRIC_PRIVATE_WRONG_THREAD
            ? NINLIL_BEARER_CORRUPT
            : NINLIL_BEARER_UNAVAILABLE;
    }
    if (fabric->outer_open != 0u) {
        return NINLIL_BEARER_WOULD_BLOCK;
    }
    fabric->outer_open = 1u;
    fabric->outer_handle_token = (ninlil_bearer_handle_t)(uintptr_t)1;
    *out_handle = fabric->outer_handle_token;
    return NINLIL_BEARER_OK;
}

static void fabric_bearer_close(void *user, ninlil_bearer_handle_t handle)
{
    ninlil_fabric_private_t *fabric = (ninlil_fabric_private_t *)user;
    if (fabric == NULL || fabric->magic != FABRIC_MAGIC) {
        return;
    }
    if (handle != fabric->outer_handle_token) {
        return;
    }
    fabric->outer_open = 0u;
    fabric->outer_handle_token = NULL;
}

/* Nested text_id: length must fit bytes[63] and be non-zero for service IDs. */
static int fabric_text_id_ok(const ninlil_text_id_t *t, int require_nonzero)
{
    if (t == NULL) {
        return 0;
    }
    if (t->length > NINLIL_FABRIC_NFL1_TEXT_ID_MAX) {
        return 0;
    }
    if (require_nonzero != 0 && t->length == 0u) {
        return 0;
    }
    return 1;
}

/*
 * ADR-0021 exact private Foundation owner-plane mapping.  This is not a
 * public application Service and it must never become a generic escape hatch
 * for reserved families.  Keep every identity/version field closed here so a
 * caller cannot smuggle arbitrary TRANSFER_RESERVED traffic through Fabric.
 */
static int fabric_mfdt_owner_plane_message_ok(
    const ninlil_bearer_message_t *message)
{
    static const uint8_t ns[] = "org.ninlil.private";
    static const uint8_t service[] = "mfdt-control";
    static const uint8_t schema[] = "ncl1-mfdt-v1";
    static const uint8_t digest_domain[] =
        "NINLIL-MFDT-FOUNDATION-CARRIER-V1";
    uint8_t expected_digest[32];

    if (message == NULL
        || message->kind != NINLIL_BEARER_MESSAGE_APPLICATION
        || message->service.family != NINLIL_FAMILY_TRANSFER_RESERVED
        || message->service.namespace_id.length != sizeof(ns) - 1u
        || message->service.service_id.length != sizeof(service) - 1u
        || message->service.schema_id.length != sizeof(schema) - 1u
        || memcmp(
               message->service.namespace_id.bytes, ns, sizeof(ns) - 1u)
            != 0
        || memcmp(
               message->service.service_id.bytes,
               service,
               sizeof(service) - 1u)
            != 0
        || memcmp(
               message->service.schema_id.bytes,
               schema,
               sizeof(schema) - 1u)
            != 0
        || message->service.descriptor_revision != 1u
        || message->service.descriptor_digest.algorithm
            != NINLIL_DIGEST_SHA256
        || message->service.schema_major != 1u
        || message->service.schema_minor != 0u
        || message->generation == 0u
        || message->payload.length < 26u
        || message->payload.length > NINLIL_FABRIC_NFL1_PAYLOAD_MAX
        || message->absolute_effect_deadline_ms == NINLIL_NO_DEADLINE
        || ninlil_fabric_private_id_is_zero(
            message->deadline_clock_epoch_id.bytes)) {
        return 0;
    }
    ninlil_fabric_private_sha256(
        digest_domain, sizeof(digest_domain) - 1u, expected_digest);
    return ninlil_fabric_private_memeq(
        expected_digest,
        message->service.descriptor_digest.bytes,
        sizeof(expected_digest));
}

/*
 * P0: exact public message shape before any digest/storage/provider.
 * length 64..255 on text_id must never reach service_identity_digest.
 */
static ninlil_bearer_status_t fabric_validate_send_message(
    const ninlil_bearer_message_t *message)
{
    if (message == NULL) {
        return NINLIL_BEARER_CORRUPT;
    }
    if (message->abi_version != NINLIL_ABI_VERSION
        || message->struct_size != (uint16_t)sizeof(*message)) {
        return NINLIL_BEARER_CORRUPT;
    }
    if (message->source.abi_version != NINLIL_ABI_VERSION
        || message->source.struct_size != (uint16_t)sizeof(message->source)
        || message->source.local_identity.abi_version != NINLIL_ABI_VERSION
        || message->source.local_identity.struct_size
            != (uint16_t)sizeof(message->source.local_identity)
        || message->target.abi_version != NINLIL_ABI_VERSION
        || message->target.struct_size != (uint16_t)sizeof(message->target)
        || message->service.abi_version != NINLIL_ABI_VERSION
        || message->service.struct_size
            != (uint16_t)sizeof(message->service)) {
        return NINLIL_BEARER_CORRUPT;
    }
    if (!fabric_text_id_ok(&message->service.namespace_id, 1)
        || !fabric_text_id_ok(&message->service.service_id, 1)
        || !fabric_text_id_ok(&message->service.schema_id, 1)) {
        return NINLIL_BEARER_CORRUPT;
    }
    if (message->kind < NINLIL_BEARER_MESSAGE_APPLICATION
        || message->kind > NINLIL_BEARER_MESSAGE_CANCEL_RESULT) {
        return NINLIL_BEARER_CORRUPT;
    }
    if (ninlil_fabric_private_id_is_zero(message->transaction_id.bytes)
        || ninlil_fabric_private_id_is_zero(message->attempt_id.bytes)) {
        return NINLIL_BEARER_CORRUPT;
    }
    if (message->payload.data == NULL && message->payload.length != 0u) {
        return NINLIL_BEARER_CORRUPT;
    }
    if (message->evidence.data == NULL && message->evidence.length != 0u) {
        return NINLIL_BEARER_CORRUPT;
    }
    if (message->payload.length > NINLIL_FABRIC_NFL1_PAYLOAD_MAX
        || message->evidence.length > NINLIL_FABRIC_NFL1_EVIDENCE_MAX) {
        return NINLIL_BEARER_CORRUPT;
    }
    /*
     * The Bearer message always echoes the original admission deadline
     * binding, including reverse kinds.  DesiredState has a finite deadline
     * bound to a non-zero clock epoch; EventFact has NO_DEADLINE and an
     * all-zero deadline epoch.  Reject malformed family/deadline tuples before
     * clock, storage, permit, selector, or provider activity.
     */
    if (message->service.family == NINLIL_FAMILY_DESIRED_STATE) {
        if (message->absolute_effect_deadline_ms == NINLIL_NO_DEADLINE
            || ninlil_fabric_private_id_is_zero(
                message->deadline_clock_epoch_id.bytes)) {
            return NINLIL_BEARER_CORRUPT;
        }
    } else if (message->service.family == NINLIL_FAMILY_EVENT_FACT) {
        if (message->absolute_effect_deadline_ms != NINLIL_NO_DEADLINE
            || !ninlil_fabric_private_id_is_zero(
                message->deadline_clock_epoch_id.bytes)) {
            return NINLIL_BEARER_CORRUPT;
        }
    } else if (!fabric_mfdt_owner_plane_message_ok(message)) {
        return NINLIL_BEARER_CORRUPT;
    }
    return NINLIL_BEARER_OK;
}

/*
 * TxPermit one-shot authority is co-located in its FBA1. There is no FBPC
 * namespace and therefore no record outside the exact 273-entry profile.
 * TxGate MUST never reissue the same (clock_epoch_id, permit_id); while an
 * FBA1 remains retained, Fabric also enforces that pair across all attempts.
 */
static int fabric_permit_pair_matches_attempt(
    const fabric_attempt_slot_t *at,
    const ninlil_tx_permit_t *permit)
{
    return at != NULL && at->used != 0u && permit != NULL
        && ninlil_fabric_private_memeq(
               at->attempt.retry_lifetime_clock_epoch_id,
               permit->clock_epoch_id.bytes,
               16u)
        && ninlil_fabric_private_memeq(
               at->attempt.permit_id, permit->permit_id.bytes, 16u);
}

static int fabric_permit_pair_in_use_by_other(
    ninlil_fabric_private_t *fabric,
    const fabric_attempt_slot_t *self,
    const ninlil_tx_permit_t *permit)
{
    uint32_t i;
    if (fabric == NULL || permit == NULL) {
        return 1;
    }
    for (i = 0u; i < NINLIL_FABRIC_ATTEMPT_MAX; ++i) {
        const fabric_attempt_slot_t *at = &fabric->attempts[i];
        if (at != self && fabric_permit_pair_matches_attempt(at, permit) != 0) {
            return 1;
        }
    }
    return 0;
}

/*
 * Provider-side effects are authorized only after CLEAR -> CLAIMED is durably
 * replaced in the same FBA1. CU-NEW proves the claim landed but remains an
 * uncertain external result; OLD/PARTIAL/THIRD never call the provider.
 */
static ninlil_fabric_private_status_t fabric_permit_claim(
    ninlil_fabric_private_t *fabric,
    fabric_attempt_slot_t *attempt,
    const ninlil_tx_permit_t *permit,
    uint32_t *out_cu_class)
{
    ninlil_fabric_private_fba1_t next;
    ninlil_fabric_private_status_t st;
    uint32_t cu_class = 0u;

    if (fabric == NULL || attempt == NULL || attempt->used == 0u
        || permit == NULL
        || attempt->attempt.permit_claim_state
            != NINLIL_FABRIC_PRIVATE_PERMIT_CLEAR) {
        return NINLIL_FABRIC_PRIVATE_DENIED;
    }
    next = attempt->attempt;
    if (attempt->attempt.state == NINLIL_FABRIC_PRIVATE_ATTEMPT_PREPARED) {
        if (fabric_permit_pair_matches_attempt(attempt, permit) == 0
            || attempt->attempt.permit_expires_at_ms
                != permit->expires_at_ms) {
            return NINLIL_FABRIC_PRIVATE_DENIED;
        }
    } else if (
        attempt->attempt.state
        == NINLIL_FABRIC_PRIVATE_ATTEMPT_RETRYABLE_NO_ACCEPT) {
        /*
         * A retry requires a freshly issued call-scoped permit. The prior
         * clear pair stays in OLD until this same replacement claims NEW.
         */
        if (fabric_permit_pair_matches_attempt(attempt, permit) != 0
            || fabric_permit_pair_in_use_by_other(fabric, attempt, permit)
                != 0) {
            return NINLIL_FABRIC_PRIVATE_DENIED;
        }
        (void)memcpy(next.permit_id, permit->permit_id.bytes, 16u);
        next.permit_expires_at_ms = permit->expires_at_ms;
        next.state = NINLIL_FABRIC_PRIVATE_ATTEMPT_PREPARED;
    } else {
        return NINLIL_FABRIC_PRIVATE_DENIED;
    }
    next.permit_claim_state = NINLIL_FABRIC_PRIVATE_PERMIT_CLAIMED;
    st = fba1_replace_full_classified(
        fabric,
        &attempt->attempt,
        &next,
        attempt->key,
        &attempt->record_revision,
        &cu_class,
        NULL);
    if (st == NINLIL_FABRIC_PRIVATE_OK
        || (st == NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN
            && cu_class == NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_NEW)) {
        attempt->attempt = next;
    }
    if (out_cu_class != NULL) {
        *out_cu_class = cu_class;
    }
    return st;
}

/*
 * Definite provider non-accept performs state transition and claim clear in
 * one FBA1 replacement FULL. CU-NEW is exactly the intended durable result and
 * may be promoted by the caller; OLD/PARTIAL/THIRD remain fail-closed.
 */
static ninlil_fabric_private_status_t fabric_permit_clear_with_state(
    ninlil_fabric_private_t *fabric,
    fabric_attempt_slot_t *attempt,
    uint32_t next_state,
    uint32_t *out_cu_class)
{
    ninlil_fabric_private_fba1_t next;
    ninlil_fabric_private_status_t st;
    uint32_t cu_class = 0u;

    if (fabric == NULL || attempt == NULL || attempt->used == 0u
        || attempt->attempt.permit_claim_state
            != NINLIL_FABRIC_PRIVATE_PERMIT_CLAIMED) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    next = attempt->attempt;
    next.state = next_state;
    next.permit_claim_state = NINLIL_FABRIC_PRIVATE_PERMIT_CLEAR;
    st = fba1_replace_full_classified(
        fabric,
        &attempt->attempt,
        &next,
        attempt->key,
        &attempt->record_revision,
        &cu_class,
        NULL);
    if (st == NINLIL_FABRIC_PRIVATE_OK
        || (st == NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN
            && cu_class == NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_NEW)) {
        attempt->attempt = next;
    }
    if (out_cu_class != NULL) {
        *out_cu_class = cu_class;
    }
    return st;
}

/*
 * ADR-0017 outer TxPermit authority gate (Fabric side, before any path/
 * storage/provider mutation). Provider start_send must re-check the same
 * structural rules via view.permit (see fabric_private_api.h).
 * Invalid => BEARER_DENIED, provider start_calls unchanged, storage put 0.
 * One-shot: FBA1's co-located claim is the durable authority. A definite
 * non-accept clears it in the same FBA1 state-transition FULL.
 */
static ninlil_bearer_status_t fabric_validate_tx_permit(
    ninlil_fabric_private_t *fabric,
    const ninlil_tx_permit_t *permit,
    const ninlil_bearer_message_t *message,
    const ninlil_time_sample_t *now)
{
    if (fabric == NULL || permit == NULL || message == NULL || now == NULL) {
        return NINLIL_BEARER_DENIED;
    }
    if (permit->abi_version != NINLIL_ABI_VERSION
        || permit->struct_size != (uint16_t)sizeof(*permit)) {
        return NINLIL_BEARER_DENIED;
    }
    if (ninlil_fabric_private_id_is_zero(permit->permit_id.bytes)) {
        return NINLIL_BEARER_DENIED;
    }
    if (!ninlil_fabric_private_memeq(
            permit->attempt_id.bytes, message->attempt_id.bytes, 16u)) {
        return NINLIL_BEARER_DENIED;
    }
    if (!ninlil_fabric_private_memeq(
            permit->clock_epoch_id.bytes, now->clock_epoch_id.bytes, 16u)) {
        return NINLIL_BEARER_DENIED;
    }
    if (now->now_ms >= permit->expires_at_ms || permit->expires_at_ms == 0u) {
        return NINLIL_BEARER_DENIED;
    }
    if (now->trust != NINLIL_CLOCK_TRUSTED) {
        return NINLIL_BEARER_DENIED;
    }
    return NINLIL_BEARER_OK;
}

/*
 * RETRYABLE exact-dispatch identity: re-enrich caller message with FBA1 pins
 * and require bit-exact foundation/NFL1 digests + current FBC1 authority pin.
 * Mismatch (mutated same IDs) => CORRUPT, TX 0.
 */
static ninlil_bearer_status_t fabric_retryable_exact_identity(
    ninlil_fabric_private_t *fabric,
    const fabric_attempt_slot_t *cand,
    const ninlil_bearer_message_t *message,
    const ninlil_time_sample_t *now,
    uint8_t *out_packet,
    uint32_t out_packet_cap,
    uint32_t *out_packet_len)
{
    uint8_t foundation[32];
    uint8_t nfl1_sha[32];
    uint8_t service_digest[32];
    uint32_t packet_len = 0u;
    ninlil_fabric_private_status_t st;
    fabric_authority_slot_t *auth;
    fabric_policy_slot_t *policy = NULL;
    const ninlil_fabric_private_fbt1_t *reverse_trigger = NULL;
    const uint8_t *selection_source_runtime;
    const uint8_t *selection_target_runtime;
    const uint8_t *selection_target_application;
    uint32_t selection_direction;
    uint16_t selection_traffic;
    uint32_t i;

    if (fabric == NULL || cand == NULL || message == NULL || now == NULL
        || out_packet == NULL || out_packet_len == NULL) {
        return NINLIL_BEARER_CORRUPT;
    }
    *out_packet_len = 0u;

    /* Re-resolve policy pin exact match to FBA1. */
    for (i = 0u; i < FABRIC_RAM_POLICY_MAX; ++i) {
        if (fabric->policies[i].index.used == 0u) {
            continue;
        }
        if (ninlil_fabric_private_memeq(
                fabric->policies[i].index.policy_id,
                cand->attempt.policy_id,
                16u)
            && fabric->policies[i].index.revision
                == cand->attempt.policy_revision
            && ninlil_fabric_private_memeq(
                   fabric->policies[i].index.canonical_digest,
                   cand->attempt.policy_digest,
                   32u)) {
            policy = &fabric->policies[i];
            break;
        }
    }
    if (policy == NULL) {
        return NINLIL_BEARER_CORRUPT;
    }

    ninlil_fabric_private_nfl1_service_identity_digest(
        message->service.namespace_id.bytes,
        message->service.namespace_id.length,
        message->service.service_id.bytes,
        message->service.service_id.length,
        message->service.schema_id.bytes,
        message->service.schema_id.length,
        message->service.descriptor_revision,
        message->service.descriptor_digest.bytes,
        message->service.schema_major,
        message->service.schema_minor,
        message->service.family,
        service_digest);

    selection_direction = direction_for_kind(message->kind);
    selection_traffic = traffic_for_kind(message->kind);
    selection_source_runtime = message->source.runtime_id.bytes;
    selection_target_runtime = message->target.target_runtime_id.bytes;
    selection_target_application =
        message->target.target_application_instance_id.bytes;
    if (triggering_kind_for_reverse(message->kind) != 0u) {
        if (fabric_find_unique_reverse_send_trigger(
                fabric, message, &reverse_trigger)
            == 0
            || !ninlil_fabric_private_memeq(
                reverse_trigger->policy_id,
                cand->attempt.policy_id,
                16u)
            || reverse_trigger->policy_revision
                != cand->attempt.policy_revision
            || !ninlil_fabric_private_memeq(
                reverse_trigger->policy_digest,
                cand->attempt.policy_digest,
                32u)) {
            return NINLIL_BEARER_CORRUPT;
        }
        selection_direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
        selection_traffic =
            traffic_for_kind(reverse_trigger->triggering_kind);
        selection_source_runtime =
            message->target.target_runtime_id.bytes;
        selection_target_runtime = message->source.runtime_id.bytes;
        selection_target_application =
            message->source.application_instance_id.bytes;
    }

    auth = fabric_resolve_unique_tx_authority(
        fabric,
        policy,
        service_digest,
        message->service.family,
        selection_direction,
        selection_traffic,
        selection_source_runtime,
        selection_target_runtime,
        selection_target_application);
    if (auth == NULL) {
        return NINLIL_BEARER_CORRUPT;
    }
    if (reverse_trigger != NULL
        && fabric_authority_matches_saved_trigger(auth, reverse_trigger) == 0) {
        return NINLIL_BEARER_CORRUPT;
    }
    /* Current FBC1 must bit-exact match FBA1 authority snapshot. */
    if (auth->authority_state != cand->attempt.authority_state
        || auth->authority_term != cand->attempt.authority_term
        || auth->assignment_epoch != cand->attempt.assignment_epoch
        || !ninlil_fabric_private_memeq(
               auth->authority_id, cand->attempt.authority_id, 16u)
        || !ninlil_fabric_private_memeq(
               auth->owner_scope_id, cand->attempt.owner_scope_id, 16u)
        || !ninlil_fabric_private_memeq(
               auth->owner_tuple_digest,
               cand->attempt.owner_tuple_digest,
               32u)) {
        return NINLIL_BEARER_CORRUPT;
    }
    if (auth->authority_state == NINLIL_FABRIC_AUTHORITY_BOUND) {
        if (!ninlil_fabric_private_memeq(
                auth->authority_clock_epoch_id,
                now->clock_epoch_id.bytes,
                16u)
            || now->now_ms >= auth->lease_expires_at_ms) {
            return NINLIL_BEARER_CORRUPT;
        }
    }

    /* Re-enrich with FBA1 pins; foundation digest must match saved. */
    st = ninlil_fabric_private_enrich_nfl1_v1(
        message,
        cand->attempt.authority_id,
        cand->attempt.authority_term,
        cand->attempt.assignment_epoch,
        cand->attempt.policy_id,
        cand->attempt.policy_revision,
        cand->attempt.policy_digest,
        cand->attempt.selected_path_id,
        cand->attempt.path_selection_epoch,
        out_packet,
        out_packet_cap,
        &packet_len);
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return NINLIL_BEARER_CORRUPT;
    }
    ninlil_fabric_private_nfl1_foundation_message_digest(
        out_packet, packet_len, foundation);
    ninlil_fabric_private_sha256(out_packet, packet_len, nfl1_sha);
    if (!ninlil_fabric_private_memeq(
            foundation, cand->attempt.foundation_message_digest, 32u)
        || !ninlil_fabric_private_memeq(
               nfl1_sha, cand->attempt.nfl1_sha256, 32u)
        || packet_len != cand->attempt.nfl1_length) {
        /* Same attempt ID, different immutable message/snapshot. */
        return NINLIL_BEARER_CORRUPT;
    }
    /*
     * If volatile packet still present, it must match re-enrichment.
     * After restart RETRYABLE, packet_slot is empty — digest match is enough;
     * caller restores packet into a free slot.
     */
    if (cand->packet_slot < NINLIL_FABRIC_SHARED_QUEUE_MAX) {
        if (fabric->packet_pool[cand->packet_slot].length != packet_len
            || !ninlil_fabric_private_memeq(
                   fabric->packet_pool[cand->packet_slot].bytes,
                   out_packet,
                   packet_len)) {
            return NINLIL_BEARER_CORRUPT;
        }
    }
    *out_packet_len = packet_len;
    return NINLIL_BEARER_OK;
}

static ninlil_bearer_status_t fabric_bearer_send(
    void *user,
    ninlil_bearer_handle_t handle,
    const ninlil_tx_permit_t *permit,
    const ninlil_bearer_message_t *message,
    ninlil_bearer_send_result_t *out_result)
{
    ninlil_fabric_private_t *fabric = (ninlil_fabric_private_t *)user;
    ninlil_fabric_private_status_t st;
    /* Bounded admission snapshot (~9KiB; not full 64-policy 52KiB). */
    ninlil_fabric_private_select_snapshot_t snap_storage;
    ninlil_fabric_private_select_snapshot_t *snap = &snap_storage;
    ninlil_fabric_private_select_result_t sel;
    uint8_t service_digest[32];
    uint32_t i;
    uint32_t pcount;
    fabric_reg_slot_t *reg;
    fabric_policy_slot_t *policy_slot;
    fabric_authority_slot_t *auth_slot;
    uint8_t packet[NINLIL_FABRIC_NFL1_STRUCTURAL_MAX];
    uint32_t packet_len = 0u;
    uint8_t foundation_digest[32];
    uint8_t fba_key[76];
    fabric_attempt_slot_t *attempt;
    ninlil_fabric_packet_view_v1_t view;
    ninlil_fabric_packet_token_t token = NULL;
    ninlil_fabric_link_status_t ls;
    uint32_t response_slot;
    ninlil_time_sample_t now;
    ninlil_port_status_t cs;
    const ninlil_fabric_private_fbt1_t *reverse_trigger = NULL;
    const uint8_t *selection_source_runtime;
    const uint8_t *selection_target_runtime;
    const uint8_t *selection_target_application;
    uint32_t selection_direction;
    uint16_t selection_traffic;
    uint64_t first_admit_retry_cap = 0u;

    if (fabric == NULL || message == NULL || out_result == NULL) {
        return NINLIL_BEARER_CORRUPT;
    }
    ninlil_fabric_private_memzero(out_result, sizeof(*out_result));
    out_result->abi_version = NINLIL_ABI_VERSION;
    out_result->struct_size = (uint16_t)sizeof(*out_result);

    st = owner_check(fabric);
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return NINLIL_BEARER_CORRUPT;
    }
    if (handle != fabric->outer_handle_token || fabric->outer_open == 0u) {
        return NINLIL_BEARER_CORRUPT;
    }
    if (fabric->lifecycle != FABRIC_LIFECYCLE_OPEN) {
        return NINLIL_BEARER_UNAVAILABLE;
    }
    if (fabric->meta.outer_available != 1u) {
        return NINLIL_BEARER_UNAVAILABLE;
    }

    /* P0: message header/nested lengths before digest or storage. */
    {
        ninlil_bearer_status_t ms = fabric_validate_send_message(message);
        if (ms != NINLIL_BEARER_OK) {
            return ms;
        }
    }

    ninlil_fabric_private_memzero(&now, sizeof(now));
    now.abi_version = NINLIL_ABI_VERSION;
    now.struct_size = (uint16_t)sizeof(now);
    cs = fabric->clock.now(fabric->clock.user, &now);
    if (cs != NINLIL_PORT_OK || now.trust != NINLIL_CLOCK_TRUSTED) {
        return NINLIL_BEARER_CORRUPT;
    }
    /*
     * Same-attempt conflict (CORRUPT) before permit DENIED (ADR outer
     * precedence). Identity index runs first so LINK_RETAINED/CLOSED/FENCED
     * replay is CORRUPT even when permit was already one-shot consumed.
     */
    response_slot = ninlil_fabric_private_nfl1_response_slot(
        message->kind,
        message->receipt_stage,
        message->disposition,
        message->cancel_kind);
    {
        fabric_attempt_slot_t *pre_id = find_attempt_by_identity(
            fabric,
            message->transaction_id.bytes,
            message->attempt_id.bytes,
            message->kind,
            response_slot);
        if (pre_id != NULL) {
            ninlil_bearer_status_t id_st;
            uint8_t id_packet[NINLIL_FABRIC_NFL1_STRUCTURAL_MAX];
            uint32_t id_packet_len = 0u;
            id_st = fabric_retryable_exact_identity(
                fabric,
                pre_id,
                message,
                &now,
                id_packet,
                sizeof(id_packet),
                &id_packet_len);
            if (id_st != NINLIL_BEARER_OK) {
                return NINLIL_BEARER_CORRUPT;
            }
            /*
             * For RETRYABLE, immutable attempt identity is checked before the
             * fresh-permit gate. A mutated replay is CORRUPT/TX0 even if it
             * also presents the previously spent permit.
             */
            if (pre_id->attempt.state
                != NINLIL_FABRIC_PRIVATE_ATTEMPT_RETRYABLE_NO_ACCEPT) {
                if (pre_id->attempt.state
                    == NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN) {
                    return NINLIL_BEARER_LOST_UNKNOWN;
                }
                return NINLIL_BEARER_CORRUPT;
            }
        }
    }
    if (find_attempt_by_identity(
            fabric,
            message->transaction_id.bytes,
            message->attempt_id.bytes,
            message->kind,
            response_slot)
        == NULL) {
        int durable_identity = 0;
        st = fabric_durable_attempt_identity_exists(
            fabric,
            message->transaction_id.bytes,
            message->attempt_id.bytes,
            message->kind,
            response_slot,
            &durable_identity);
        if (st != NINLIL_FABRIC_PRIVATE_OK) {
            return NINLIL_BEARER_CORRUPT;
        }
        if (durable_identity != 0) {
            return NINLIL_BEARER_CORRUPT;
        }
    }

    /* TxPermit gate (structural + co-located durable one-shot). */
    {
        fabric_attempt_slot_t *permit_self = find_attempt_by_identity(
            fabric,
            message->transaction_id.bytes,
            message->attempt_id.bytes,
            message->kind,
            response_slot);
        ninlil_bearer_status_t ps =
            fabric_validate_tx_permit(fabric, permit, message, &now);
        if (ps != NINLIL_BEARER_OK) {
            return ps;
        }
        if (permit_self != NULL) {
            if (permit_self->attempt.state
                    != NINLIL_FABRIC_PRIVATE_ATTEMPT_RETRYABLE_NO_ACCEPT
                || fabric_permit_pair_matches_attempt(permit_self, permit) != 0
                || permit_self->attempt.permit_claim_state
                    != NINLIL_FABRIC_PRIVATE_PERMIT_CLEAR
                || fabric_permit_pair_in_use_by_other(
                       fabric, permit_self, permit)
                    != 0) {
                return NINLIL_BEARER_DENIED;
            }
        } else if (
            fabric_permit_pair_in_use_by_other(fabric, NULL, permit) != 0) {
            return NINLIL_BEARER_DENIED;
        }
    }

    /*
     * RETRYABLE exact retry path (after permit gate: needs fresh permit).
     */
    {
        fabric_attempt_slot_t *id_cand = find_attempt_by_identity(
            fabric,
            message->transaction_id.bytes,
            message->attempt_id.bytes,
            message->kind,
            response_slot);
        ninlil_bearer_status_t id_st;
        uint8_t id_packet[NINLIL_FABRIC_NFL1_STRUCTURAL_MAX];
        uint32_t id_packet_len = 0u;

        if (id_cand != NULL
            && id_cand->attempt.state
                == NINLIL_FABRIC_PRIVATE_ATTEMPT_RETRYABLE_NO_ACCEPT) {
        fabric_attempt_slot_t *cand = id_cand;
        (void)id_packet;
        (void)id_packet_len;
        (void)id_st;
        /* retry_lifetime epoch must match trusted current (fail-closed). */
        if (!ninlil_fabric_private_memeq(
                cand->attempt.retry_lifetime_clock_epoch_id,
                now.clock_epoch_id.bytes,
                16u)) {
            cand->attempt.state =
                NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
            st = fba1_persist_full_next(
                fabric, &cand->attempt, cand->key, &cand->record_revision);
            if (st != NINLIL_FABRIC_PRIVATE_OK) {
                cand->attempt.state =
                    NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
                return st == NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN
                    ? NINLIL_BEARER_LOST_UNKNOWN
                    : NINLIL_BEARER_CORRUPT;
            }
            return NINLIL_BEARER_CORRUPT;
        }
        if (now.now_ms >= cand->attempt.retry_expires_at_ms) {
            /* CLOSED FULL first; no provider start on expired retry. */
            cand->attempt.state = NINLIL_FABRIC_PRIVATE_ATTEMPT_CLOSED;
            st = fba1_persist_full_next(
                fabric, &cand->attempt, cand->key, &cand->record_revision);
            if (st == NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN) {
                cand->attempt.state =
                    NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
                return NINLIL_BEARER_LOST_UNKNOWN;
            }
            if (st != NINLIL_FABRIC_PRIVATE_OK) {
                cand->attempt.state =
                    NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
                return NINLIL_BEARER_CORRUPT;
            }
            return NINLIL_BEARER_UNAVAILABLE;
        }
        reg = find_reg_by_id(fabric, cand->attempt.selected_path_id);
        if (reg == NULL || reg->lifecycle != FABRIC_REG_ACTIVE) {
            cand->attempt.state = NINLIL_FABRIC_PRIVATE_ATTEMPT_CLOSED;
            st = fba1_persist_full_next(
                fabric, &cand->attempt, cand->key, &cand->record_revision);
            if (st != NINLIL_FABRIC_PRIVATE_OK) {
                cand->attempt.state =
                    NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
                return st == NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN
                    ? NINLIL_BEARER_LOST_UNKNOWN
                    : NINLIL_BEARER_CORRUPT;
            }
            return NINLIL_BEARER_UNAVAILABLE;
        }
        /*
         * Exact identity: re-enrich message with FBA pins; match digests.
         * Restart RETRYABLE has no volatile packet — restore into free slot.
         * Digest mismatch => CORRUPT, storage mutation 0, provider start 0.
         */
        id_st = fabric_retryable_exact_identity(
            fabric,
            cand,
            message,
            &now,
            packet,
            sizeof(packet),
            &packet_len);
        if (id_st != NINLIL_BEARER_OK) {
            return id_st;
        }
        if (cand->packet_slot >= NINLIL_FABRIC_SHARED_QUEUE_MAX) {
            uint32_t pslot_r = alloc_packet_slot(fabric);
            if (pslot_r == UINT32_MAX) {
                return NINLIL_BEARER_WOULD_BLOCK;
            }
            (void)memcpy(
                fabric->packet_pool[pslot_r].bytes, packet, packet_len);
            fabric->packet_pool[pslot_r].length = packet_len;
            cand->packet_slot = pslot_r;
        } else if (
            fabric->packet_pool[cand->packet_slot].length != packet_len
            || !ninlil_fabric_private_memeq(
                   fabric->packet_pool[cand->packet_slot].bytes,
                   packet,
                   packet_len)) {
            return NINLIL_BEARER_CORRUPT;
        }
        attempt = cand;
        /*
         * RETRYABLE/CLEAR -> PREPARED/CLAIMED is one exact FBA1 FULL in
         * fabric_permit_claim().  There must be no durable PREPARED window
         * containing the old, already-spent permit pair.
         */
        goto fabric_start_provider;
        } /* RETRYABLE same-identity path */
    } /* identity index */

    /*
     * This is a new attempt.  Freeze the first-admit retry cap before route
     * selection notification, RAM reservation, durable PREPARED, or provider
     * start.  Overflow is temporary capacity pressure: the call-scoped permit
     * remains unconsumed and an exact later retry may proceed.
     */
    if (fabric_checked_add_u64(
            now.now_ms,
            NINLIL_FABRIC_RETRY_LIFETIME_MS,
            &first_admit_retry_cap)
        == 0) {
        return NINLIL_BEARER_WOULD_BLOCK;
    }

    ninlil_fabric_private_nfl1_service_identity_digest(
        message->service.namespace_id.bytes,
        message->service.namespace_id.length,
        message->service.service_id.bytes,
        message->service.service_id.length,
        message->service.schema_id.bytes,
        message->service.schema_id.length,
        message->service.descriptor_revision,
        message->service.descriptor_digest.bytes,
        message->service.schema_major,
        message->service.schema_minor,
        message->service.family,
        service_digest);

    selection_direction = direction_for_kind(message->kind);
    selection_traffic = traffic_for_kind(message->kind);
    selection_source_runtime = message->source.runtime_id.bytes;
    selection_target_runtime = message->target.target_runtime_id.bytes;
    selection_target_application =
        message->target.target_application_instance_id.bytes;
    if (triggering_kind_for_reverse(message->kind) != 0u) {
        if (fabric_find_unique_reverse_send_trigger(
                fabric, message, &reverse_trigger)
            == 0) {
            return NINLIL_BEARER_CORRUPT;
        }
        /*
         * Resolve the saved triggering forward contract in its original
         * orientation.  A reverse message echoes that policy/authority; it
         * does not require or synthesize an independent reverse policy.
         */
        selection_direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
        selection_traffic =
            traffic_for_kind(reverse_trigger->triggering_kind);
        selection_source_runtime =
            message->target.target_runtime_id.bytes;
        selection_target_runtime = message->source.runtime_id.bytes;
        selection_target_application =
            message->source.application_instance_id.bytes;
    }

    /* Bounded admission snapshot (shrunk ABI; not 52KiB full-table). */
    ninlil_fabric_private_memzero(snap, sizeof(*snap));
    snap->outer_available = fabric->meta.outer_available;
    (void)memcpy(
        snap->query.service_identity_digest, service_digest, 32u);
    snap->query.family = message->service.family;
    snap->query.direction = selection_direction;
    snap->query.traffic_class = selection_traffic;
    (void)memcpy(
        snap->query.source_runtime_id, selection_source_runtime, 16u);
    (void)memcpy(
        snap->query.target_runtime_id,
        selection_target_runtime,
        16u);
    (void)memcpy(
        snap->query.target_application_id,
        selection_target_application,
        16u);
    if (reverse_trigger != NULL) {
        /*
         * The return link must authenticate the original source Runtime, now
         * the reverse target. This turns multi-link selection into an explicit
         * peer join rather than registry enumeration order.
         */
        (void)memcpy(
            snap->query.authenticated_peer_runtime_id,
            message->target.target_runtime_id.bytes,
            16u);
    }
    /* packet length estimate: use structural min until enrich; refined later */
    snap->query.packet_bytes = NINLIL_FABRIC_NFL1_STRUCTURAL_MIN
        + message->service.namespace_id.length
        + message->service.service_id.length
        + message->service.schema_id.length + message->payload.length
        + message->evidence.length - 3u
        + 3u; /* text already counted */
    snap->query.transfer_bytes = snap->query.packet_bytes;
    snap->query.now_ms = now.now_ms;
    snap->query.deadline_ms = message->absolute_effect_deadline_ms;
    /*
     * The selector field is the retry-lifetime clock authority. Commands
     * bind it to the finite message deadline epoch. EventFact deliberately
     * carries an all-zero deadline epoch with NO_DEADLINE, so its attempt
     * admission sample supplies this non-zero authority (ADR-0017).
     */
    if (message->service.family == NINLIL_FAMILY_EVENT_FACT
        && message->absolute_effect_deadline_ms == NINLIL_NO_DEADLINE
        && ninlil_fabric_private_id_is_zero(
            message->deadline_clock_epoch_id.bytes)) {
        (void)memcpy(
            snap->query.deadline_clock_epoch_id,
            now.clock_epoch_id.bytes,
            16u);
    } else {
        (void)memcpy(
            snap->query.deadline_clock_epoch_id,
            message->deadline_clock_epoch_id.bytes,
            16u);
    }
    (void)memcpy(
        snap->query.admission_clock_epoch_id, now.clock_epoch_id.bytes, 16u);
    (void)memcpy(
        snap->query.availability_clock_epoch_id, now.clock_epoch_id.bytes, 16u);
    (void)memcpy(
        snap->query.attestation_clock_epoch_id, now.clock_epoch_id.bytes, 16u);
    (void)memcpy(
        snap->query.authority_clock_epoch_id, now.clock_epoch_id.bytes, 16u);

    /*
     * P0: bind every message/authority requirement into the immutable select
     * query so hard filters cannot be bypassed by a zeroed snapshot.
     * required_evidence nonzero => evidence only; transport custody remains
     * an independent explicit requirement. Profile-1 always
     * requires sleep-compatible + unicast + full security binding set.
     */
    snap->query.required_capability_flags = NINLIL_FABRIC_CAP_UNICAST;
    snap->query.required_security_flags =
        NINLIL_FABRIC_SECURITY_INTEGRITY
        | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY
        | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION
        | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS;
    snap->query.requires_sleep_compatible = 1u;
    if (message->required_evidence != NINLIL_EVIDENCE_NONE) {
        snap->query.requires_evidence = 1u;
        snap->query.required_capability_flags |= NINLIL_FABRIC_CAP_EVIDENCE;
    }
    if (message->kind == NINLIL_BEARER_MESSAGE_CUSTODY_ACCEPTED) {
        snap->query.requires_custody = 1u;
        snap->query.required_capability_flags |= NINLIL_FABRIC_CAP_CUSTODY;
    }
    /*
     * RF: v1 Host has no compact RF mapping acceptance — mark unsupported so
     * RF candidates fail hard-filter RF_MAPPING_UNSUPPORTED (no fallback).
     * Permit presence still gates RF_PERMIT for RF kinds that pass mapping.
     */
    snap->query.rf_permit_valid = (permit != NULL) ? 1u : 0u;
    snap->query.rf_mapping_accepted = 0u;
    /*
     * Peer / Attachment pins: when exactly one ACTIVE registration exists,
     * pin its peer/attachment so mismatch is fail-closed (not first-row
     * seed across multi-peer registries). Multi-reg: leave zero => presence
     * only (no enumeration-order seed).
     */
    {
        uint32_t active_n = 0u;
        uint32_t active_i = NINLIL_FABRIC_REGISTRY_MAX;
        uint32_t ri;
        for (ri = 0u; ri < NINLIL_FABRIC_REGISTRY_MAX; ++ri) {
            if (fabric->regs[ri].used != 0u
                && fabric->regs[ri].lifecycle == FABRIC_REG_ACTIVE) {
                active_n++;
                active_i = ri;
            }
        }
        if (active_n == 1u && active_i < NINLIL_FABRIC_REGISTRY_MAX
            && ninlil_fabric_private_id_is_zero(
                snap->query.authenticated_peer_runtime_id)) {
            const ninlil_fabric_link_descriptor_v1_t *d =
                &fabric->regs[active_i].descriptor;
            (void)memcpy(
                snap->query.authenticated_peer_runtime_id,
                d->authenticated_peer_runtime_id.bytes,
                16u);
            (void)memcpy(
                snap->query.attachment_authority_id,
                d->attachment_authority_id.bytes,
                16u);
            (void)memcpy(
                snap->query.attachment_binding_digest,
                d->attachment_binding_digest,
                32u);
        }
    }

    /*
     * New forward dispatches use only the current maximum revision. Reverse
     * dispatches use the exact retained revision pinned by FBT1; a later
     * policy revision must not rewrite an in-flight conversation.
     */
    pcount = 0u;
    policy_slot = NULL;
    for (i = 0u; i < FABRIC_RAM_POLICY_MAX; ++i) {
        uint32_t j;
        int is_max;
        if (fabric->policies[i].index.used == 0u) {
            continue;
        }
        if (!ninlil_fabric_private_memeq(
                fabric->policies[i].index.service_identity_digest,
                service_digest,
                32u)
            || fabric->policies[i].index.family != message->service.family
            || fabric->policies[i].index.direction
                != selection_direction
            || fabric->policies[i].index.traffic_class
                != selection_traffic
            || (reverse_trigger != NULL
                && (!ninlil_fabric_private_memeq(
                        fabric->policies[i].index.policy_id,
                        reverse_trigger->policy_id,
                        16u)
                    || fabric->policies[i].index.revision
                        != reverse_trigger->policy_revision
                    || !ninlil_fabric_private_memeq(
                        fabric->policies[i].index.canonical_digest,
                        reverse_trigger->policy_digest,
                        32u)))) {
            continue;
        }
        is_max = 1;
        for (j = 0u; reverse_trigger == NULL && j < FABRIC_RAM_POLICY_MAX;
             ++j) {
            if (fabric->policies[j].index.used == 0u || j == i) {
                continue;
            }
            if (ninlil_fabric_private_memeq(
                    fabric->policies[j].index.policy_id,
                    fabric->policies[i].index.policy_id,
                    16u)
                && fabric->policies[j].index.revision
                    > fabric->policies[i].index.revision) {
                is_max = 0;
                break;
            }
        }
        if (is_max == 0) {
            continue;
        }
        if (pcount >= NINLIL_FABRIC_PRIVATE_SELECT_MAX_POLICIES) {
            return NINLIL_BEARER_CORRUPT;
        }
        {
            ninlil_fabric_private_select_policy_t *sp =
                &snap->policies[pcount];
            const fabric_policy_slot_t *pslot = &fabric->policies[i];
            uint32_t c;
            (void)memcpy(sp->policy_id, pslot->index.policy_id, 16u);
            sp->revision = pslot->index.revision;
            (void)memcpy(
                sp->canonical_digest, pslot->index.canonical_digest, 32u);
            (void)memcpy(
                sp->service_identity_digest,
                pslot->index.service_identity_digest,
                32u);
            sp->family = pslot->index.family;
            sp->direction = pslot->index.direction;
            sp->traffic_class = pslot->index.traffic_class;
            sp->scope_selector = pslot->index.scope_selector;
            sp->required_capability_flags =
                pslot->index.required_capability_flags;
            sp->required_security_flags =
                pslot->index.required_security_flags;
            sp->maximum_latency_class = pslot->index.maximum_latency_class;
            sp->maximum_cost_class = pslot->index.maximum_cost_class;
            sp->minimum_packet_bytes = pslot->index.minimum_packet_bytes;
            sp->authority_mode = pslot->index.authority_mode;
            sp->deadline_guard_ms = pslot->index.deadline_guard_ms;
            sp->candidate_count = pslot->index.candidate_count;
            {
                uint8_t key[28];
                uint8_t value[352];
                ninlil_storage_txn_t txn = NULL;
                ninlil_bytes_view_t kv;
                ninlil_mut_bytes_t mv;
                ninlil_fabric_private_key_fbp1(
                    pslot->index.policy_id, pslot->index.revision, key);
                kv.data = key;
                kv.length = 28u;
                mv.data = value;
                mv.capacity = 352u;
                mv.length = 0u;
                if (fabric->storage.begin(
                        fabric->storage.user,
                        fabric->storage_handle,
                        NINLIL_STORAGE_READ_ONLY,
                        &txn)
                    == NINLIL_STORAGE_OK) {
                    if (fabric->storage.get(
                            fabric->storage.user, txn, kv, &mv)
                        == NINLIL_STORAGE_OK) {
                        ninlil_fabric_private_common_envelope_t env;
                        const uint8_t *pl = NULL;
                        if (ninlil_fabric_private_record_decode_envelope(
                                value,
                                mv.length,
                                (const uint8_t *)"FBP1",
                                328u,
                                &env,
                                &pl)
                            == NINLIL_FABRIC_PRIVATE_RECORD_OK) {
                            ninlil_fabric_private_fbp1_t full;
                            if (ninlil_fabric_private_fbp1_decode(pl, &full)
                                == NINLIL_FABRIC_PRIVATE_RECORD_OK) {
                                for (c = 0u;
                                     c < full.candidate_count && c < 8u;
                                     ++c) {
                                    sp->candidates[c] = full.candidates[c];
                                }
                            }
                        }
                    }
                    if (fabric->storage.rollback(fabric->storage.user, txn)
                        != NINLIL_STORAGE_OK) {
                        return NINLIL_BEARER_CORRUPT;
                    }
                }
            }
            sp->revision_chain_len = 1u;
            sp->revision_chain[0] = pslot->index.revision;
            policy_slot = &fabric->policies[i];
            pcount++;
        }
    }
    snap->policy_count = pcount;

    /*
     * P1: no first-registry peer/Attachment seed. Query peer/attachment stay
     * zero unless caller supplies independent expectations (non-zero match).
     * Each candidate is judged on its own non-zero peer/Attachment pins.
     */
    for (i = 0u;
         i < NINLIL_FABRIC_REGISTRY_MAX
         && snap->registry_count < NINLIL_FABRIC_PRIVATE_SELECT_MAX_REGISTRY;
         ++i) {
        fabric_reg_slot_t *r = &fabric->regs[i];
        ninlil_fabric_private_select_registry_row_t *row;
        if (r->used == 0u || r->lifecycle != FABRIC_REG_ACTIVE) {
            continue;
        }
        row = &snap->registry[snap->registry_count++];
        (void)memcpy(row->instance_id, r->descriptor.instance_id.bytes, 16u);
        row->link_kind = r->descriptor.link_kind;
        row->direction_mask = r->descriptor.direction_mask;
        row->capability_flags = r->descriptor.capability_flags;
        row->security_capability_flags =
            r->descriptor.security_capability_flags;
        row->maximum_packet_bytes = r->descriptor.maximum_packet_bytes;
        row->maximum_transfer_bytes = r->descriptor.maximum_transfer_bytes;
        row->latency_class = r->descriptor.latency_class;
        row->cost_class = r->descriptor.cost_class;
        row->reservation_capacity = r->descriptor.reservation_capacity;
        row->lifecycle = NINLIL_FABRIC_PRIVATE_LIFECYCLE_ACTIVE;
        row->peer_nfl1_version = r->descriptor.peer_nfl1_version;
        row->peer_fabric_capability_flags =
            r->descriptor.peer_fabric_capability_flags;
        (void)memcpy(
            row->authenticated_peer_runtime_id,
            r->descriptor.authenticated_peer_runtime_id.bytes,
            16u);
        (void)memcpy(
            row->attachment_authority_id,
            r->descriptor.attachment_authority_id.bytes,
            16u);
        (void)memcpy(
            row->attachment_binding_digest,
            r->descriptor.attachment_binding_digest,
            32u);
        (void)memcpy(
            row->attestation_clock_epoch_id,
            r->descriptor.attestation_clock_epoch_id.bytes,
            16u);
        row->attestation_expires_at_ms =
            r->descriptor.attestation_expires_at_ms;
        (void)memcpy(
            row->availability_clock_epoch_id,
            r->state.availability_clock_epoch_id.bytes,
            16u);
        row->availability_state = (uint8_t)r->state.available;
        row->availability_expires_at_ms = r->state.available_until_ms;
    }

    /* Policy-matching authorities only (exact-1 join; not full 64 stack). */
    for (i = 0u;
         i < FABRIC_RAM_AUTHORITY_MAX
         && snap->authority_count
             < NINLIL_FABRIC_PRIVATE_SELECT_MAX_AUTHORITIES;
         ++i) {
        if (fabric->authorities[i].index.used == 0u) {
            continue;
        }
        if (!ninlil_fabric_private_memeq(
                fabric->authorities[i].index.service_identity_digest,
                service_digest,
                32u)
            || fabric->authorities[i].index.family != message->service.family
            || fabric->authorities[i].index.direction
                != selection_direction
            || fabric->authorities[i].index.traffic_class
                != selection_traffic) {
            continue;
        }
        {
            ninlil_fabric_private_select_authority_row_t *ar =
                &snap->authorities[snap->authority_count];
            const fabric_authority_slot_t *b = &fabric->authorities[i];
            (void)memcpy(
                ar->service_identity_digest,
                b->index.service_identity_digest,
                32u);
            ar->family = b->index.family;
            ar->direction = b->index.direction;
            ar->traffic_class = b->index.traffic_class;
            ar->scope_selector = b->index.scope_selector;
            (void)memcpy(
                ar->endpoint_runtime_id, b->index.endpoint_runtime_id, 16u);
            (void)memcpy(
                ar->target_runtime_id, b->index.target_runtime_id, 16u);
            (void)memcpy(
                ar->target_application_id,
                b->index.target_application_id,
                16u);
            (void)memcpy(ar->policy_id, b->index.policy_id, 16u);
            ar->policy_revision = b->index.policy_revision;
            (void)memcpy(ar->policy_digest, b->policy_digest, 32u);
            ar->authority_state = b->authority_state;
            (void)memcpy(
                ar->authority_clock_epoch_id, b->authority_clock_epoch_id, 16u);
            ar->lease_expires_at_ms = b->lease_expires_at_ms;
            snap->authority_count++;
        }
    }

    for (i = 0u;
         i < NINLIL_FABRIC_ATTEMPT_MAX
         && snap->active_attempt_count
             < NINLIL_FABRIC_PRIVATE_SELECT_MAX_ACTIVE_ATTEMPTS;
         ++i) {
        if (fabric->attempts[i].used == 0u) {
            continue;
        }
        if (fabric->attempts[i].attempt.state
                == NINLIL_FABRIC_PRIVATE_ATTEMPT_PREPARED
            || fabric->attempts[i].attempt.state
                == NINLIL_FABRIC_PRIVATE_ATTEMPT_LINK_RETAINED) {
            ninlil_fabric_private_select_active_attempt_t *aa =
                &snap->active_attempts[snap->active_attempt_count++];
            uint16_t units = 1u;
            uint32_t pi;
            uint32_t ci;
            (void)memcpy(
                aa->instance_id,
                fabric->attempts[i].attempt.selected_path_id,
                16u);
            aa->state = fabric->attempts[i].attempt.state;
            /* Reservation usage from pinned policy candidate units. */
            for (pi = 0u; pi < snap->policy_count; ++pi) {
                if (!ninlil_fabric_private_memeq(
                        snap->policies[pi].policy_id,
                        fabric->attempts[i].attempt.policy_id,
                        16u)
                    || snap->policies[pi].revision
                        != fabric->attempts[i].attempt.policy_revision) {
                    continue;
                }
                for (ci = 0u; ci < snap->policies[pi].candidate_count
                     && ci < 8u;
                     ++ci) {
                    if (ninlil_fabric_private_memeq(
                            snap->policies[pi].candidates[ci].instance_id,
                            fabric->attempts[i].attempt.selected_path_id,
                            16u)) {
                        units =
                            snap->policies[pi].candidates[ci].reservation_units;
                        break;
                    }
                }
                break;
            }
            aa->reservation_units = units;
        }
    }

    ninlil_fabric_private_select(snap, &sel);
    /* RRMP must NOT run here: reject paths (corrupt/unavailable/auth/RF/enrich)
     * would otherwise mutate path pin / custody queue. Hook is after enrich. */
    if (sel.resolution == NINLIL_FABRIC_PRIVATE_SEL_CORRUPT) {
#if defined(NINLIL_FABRIC_HOST_DIAGNOSTICS)
        (void)fprintf(
            stderr,
            "fabric selection corrupt reason=%s\n",
            sel.primary_rejection != NULL ? sel.primary_rejection : "NONE");
#endif
        return NINLIL_BEARER_CORRUPT;
    }
    if (sel.resolution != NINLIL_FABRIC_PRIVATE_SEL_SELECTED) {
#if defined(NINLIL_FABRIC_HOST_DIAGNOSTICS)
        (void)fprintf(
            stderr,
            "fabric selection unavailable reason=%s now=%llu deadline=%llu\n",
            sel.primary_rejection != NULL ? sel.primary_rejection : "NONE",
            (unsigned long long)now.now_ms,
            (unsigned long long)message->absolute_effect_deadline_ms);
#endif
        return NINLIL_BEARER_UNAVAILABLE;
    }
    reg = find_reg_by_id(fabric, sel.selected_instance_id);
    if (reg == NULL || policy_slot == NULL) {
        return NINLIL_BEARER_UNAVAILABLE;
    }
    /*
     * P0: re-resolve unique authority with selector predicate after path
     * selection. Never use "last loaded" RAM authority for NFL1/FBA1 pins.
     */
    auth_slot = fabric_resolve_unique_tx_authority(
        fabric,
        policy_slot,
        service_digest,
        message->service.family,
        selection_direction,
        selection_traffic,
        selection_source_runtime,
        selection_target_runtime,
        selection_target_application);
    if (auth_slot == NULL) {
        return reverse_trigger != NULL ? NINLIL_BEARER_CORRUPT
                                       : NINLIL_BEARER_UNAVAILABLE;
    }
    if (reverse_trigger != NULL
        && fabric_authority_matches_saved_trigger(auth_slot, reverse_trigger)
            == 0) {
        return NINLIL_BEARER_CORRUPT;
    }

    /* RF mapping not accepted in v1. */
    if (reg->descriptor.link_kind == NINLIL_FABRIC_LINK_KIND_RF) {
        return NINLIL_BEARER_DENIED;
    }

    st = ninlil_fabric_private_enrich_nfl1_v1(
        message,
        reverse_trigger != NULL ? reverse_trigger->authority_id
                                : auth_slot->authority_id,
        reverse_trigger != NULL ? reverse_trigger->authority_term
                                : auth_slot->authority_term,
        reverse_trigger != NULL ? reverse_trigger->assignment_epoch
                                : auth_slot->assignment_epoch,
        reverse_trigger != NULL ? reverse_trigger->policy_id
                                : policy_slot->index.policy_id,
        reverse_trigger != NULL ? reverse_trigger->policy_revision
                                : policy_slot->index.revision,
        reverse_trigger != NULL ? reverse_trigger->policy_digest
                                : policy_slot->index.canonical_digest,
        sel.selected_instance_id,
        fabric->path_selection_epoch,
        packet,
        sizeof(packet),
        &packet_len);
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st == NINLIL_FABRIC_PRIVATE_CAPACITY
            ? NINLIL_BEARER_WOULD_BLOCK
            : NINLIL_BEARER_CORRUPT;
    }

    /* Final selection + enrichment success: pin path / optional custody. */
    ninlil_fabric_rrmp_on_path_selected(
        fabric->rrmp_owner,
        sel.selected_instance_id,
        1u,
        snap->query.requires_custody,
        fabric->path_selection_epoch,
        snap->query.now_ms);

    ninlil_fabric_private_nfl1_foundation_message_digest(
        packet, packet_len, foundation_digest);
    response_slot = ninlil_fabric_private_nfl1_response_slot(
        message->kind,
        message->receipt_stage,
        message->disposition,
        message->cancel_kind);
    ninlil_fabric_private_key_fba1(
        message->transaction_id.bytes,
        message->attempt_id.bytes,
        message->kind,
        response_slot,
        foundation_digest,
        fba_key);

    attempt = find_attempt_slot(fabric, fba_key);
    if (attempt != NULL) {
        /* FENCED/prior CU: same-attempt provider start 0. */
        if (attempt->attempt.state
            == NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN) {
            return NINLIL_BEARER_LOST_UNKNOWN;
        }
        /* RETRYABLE handled earlier; any other live same key is conflict. */
        return NINLIL_BEARER_CORRUPT;
    } else {
        ninlil_fabric_private_fba1_t prepared;
        uint32_t pslot;
        uint64_t expires;
        uint64_t avail_exp;
        uint64_t msg_dl;
        uint32_t cu_class = 0u;

        /*
         * ADR-0017: reserve all RAM (attempt + packet) before PREPARED FULL.
         * Durable-only PREPARED with no RAM slot must not occur.
         */
        attempt = alloc_attempt_slot(fabric);
        if (attempt == NULL) {
            return NINLIL_BEARER_WOULD_BLOCK;
        }
        pslot = alloc_packet_slot(fabric);
        if (pslot == UINT32_MAX) {
            free_attempt_slot(fabric, attempt);
            return NINLIL_BEARER_WOULD_BLOCK;
        }
        (void)memcpy(fabric->packet_pool[pslot].bytes, packet, packet_len);
        fabric->packet_pool[pslot].length = packet_len;

        ninlil_fabric_private_memzero(&prepared, sizeof(prepared));
        (void)memcpy(
            prepared.transaction_id, message->transaction_id.bytes, 16u);
        (void)memcpy(prepared.attempt_id, message->attempt_id.bytes, 16u);
        prepared.message_kind = message->kind;
        prepared.response_slot = response_slot;
        prepared.state = NINLIL_FABRIC_PRIVATE_ATTEMPT_PREPARED;
        (void)memcpy(
            prepared.foundation_message_digest, foundation_digest, 32u);
        (void)memcpy(prepared.policy_id, policy_slot->index.policy_id, 16u);
        prepared.policy_revision = policy_slot->index.revision;
        (void)memcpy(
            prepared.policy_digest, policy_slot->index.canonical_digest, 32u);
        (void)memcpy(
            prepared.selected_path_id, sel.selected_instance_id, 16u);
        prepared.path_selection_epoch = fabric->path_selection_epoch;
        prepared.authority_state = auth_slot->authority_state;
        (void)memcpy(prepared.authority_id, auth_slot->authority_id, 16u);
        prepared.authority_term = auth_slot->authority_term;
        prepared.assignment_epoch = auth_slot->assignment_epoch;
        (void)memcpy(prepared.owner_scope_id, auth_slot->owner_scope_id, 16u);
        (void)memcpy(
            prepared.owner_tuple_digest, auth_slot->owner_tuple_digest, 32u);
        /* FBR1 registry pins for restart exact join. */
        {
            fabric_fbr1_pin_t *pin =
                fbr1_pin_find(fabric, sel.selected_instance_id);
            if (pin == NULL || reg->record_revision == 0u) {
                free_packet_slot(fabric, pslot);
                free_attempt_slot(fabric, attempt);
                return NINLIL_BEARER_CORRUPT;
            }
            prepared.registry_record_revision = reg->record_revision;
            (void)memcpy(
                prepared.registry_record_digest, pin->registry_digest, 32u);
            (void)memcpy(
                prepared.descriptor_digest,
                reg->descriptor.descriptor_digest,
                32u);
            (void)memcpy(
                prepared.security_profile_id,
                reg->descriptor.security_profile_id.bytes,
                16u);
            prepared.attestation_epoch = reg->descriptor.attestation_epoch;
            (void)memcpy(
                prepared.attestation_clock_epoch_id,
                reg->descriptor.attestation_clock_epoch_id.bytes,
                16u);
            (void)memcpy(
                prepared.attestation_digest,
                reg->descriptor.attestation_digest,
                32u);
            prepared.attestation_expires_at_ms =
                reg->descriptor.attestation_expires_at_ms;
            (void)memcpy(
                prepared.peer_runtime_id,
                reg->descriptor.authenticated_peer_runtime_id.bytes,
                16u);
            (void)memcpy(
                prepared.attachment_authority_id,
                reg->descriptor.attachment_authority_id.bytes,
                16u);
            (void)memcpy(
                prepared.attachment_binding_digest,
                reg->descriptor.attachment_binding_digest,
                32u);
            prepared.availability_epoch = reg->state.availability_epoch;
            (void)memcpy(
                prepared.availability_clock_epoch_id,
                reg->state.availability_clock_epoch_id.bytes,
                16u);
            prepared.availability_state = (uint8_t)reg->state.available;
            prepared.availability_expires_at_ms =
                reg->state.available_until_ms;
        }
        (void)memcpy(
            prepared.reservation_id, message->attempt_id.bytes, 16u);
        (void)memcpy(
            prepared.deadline_clock_epoch_id,
            message->deadline_clock_epoch_id.bytes,
            16u);
        prepared.deadline_ms = message->absolute_effect_deadline_ms;
        prepared.nfl1_length = packet_len;
        ninlil_fabric_private_sha256(packet, packet_len, prepared.nfl1_sha256);
        (void)memcpy(
            prepared.retry_lifetime_clock_epoch_id,
            now.clock_epoch_id.bytes,
            16u);
        (void)memcpy(prepared.permit_id, permit->permit_id.bytes, 16u);
        prepared.permit_expires_at_ms = permit->expires_at_ms;
        prepared.permit_claim_state = NINLIL_FABRIC_PRIVATE_PERMIT_CLEAR;
        avail_exp = reg->state.available_until_ms;
        msg_dl = message->absolute_effect_deadline_ms;
        expires = first_admit_retry_cap;
        if (msg_dl < expires) {
            expires = msg_dl;
        }
        if (avail_exp < expires) {
            expires = avail_exp;
        }
        prepared.retry_expires_at_ms = expires;
        ninlil_fabric_private_local_dispatch_id(
            fba_key, prepared.local_dispatch_id);

        /*
         * ADR-0017: checked epoch wrap BEFORE durable PREPARED FULL.
         * Wrap => no storage mutation, free RAM reservation.
         */
        if (fabric->path_selection_epoch == UINT64_MAX) {
            free_packet_slot(fabric, pslot);
            free_attempt_slot(fabric, attempt);
            return NINLIL_BEARER_CORRUPT;
        }
        /*
         * ADR-0017: FBA1 PREPARED FULL before start_send.
         * COMMIT_UNKNOWN: close/reopen classify; NEW => fence RAM, never start.
         */
        st = fba1_persist_full_ex(
            fabric, &prepared, fba_key, 1u, NULL, 0u, &cu_class, NULL, NULL);
        if (st == NINLIL_FABRIC_PRIVATE_OK) {
            (void)memcpy(attempt->key, fba_key, 76u);
            attempt->attempt = prepared;
            attempt->packet_slot = pslot;
            attempt->record_revision = 1u;
            /* Epoch advances only after FULL commit OK (checked above). */
            if (fabric_checked_inc_u64(&fabric->path_selection_epoch) == 0) {
                /* Concurrent wrap impossible after pre-check; fail closed. */
                return NINLIL_BEARER_CORRUPT;
            }
        } else if (st == NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN) {
            free_packet_slot(fabric, pslot);
            if (cu_class == NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_NEW) {
                /*
                 * Durable NEW PREPARED under CU: reserved RAM becomes FENCED
                 * so same-process re-send cannot start_send again.
                 */
                ninlil_fabric_private_fba1_t fenced = prepared;
                fenced.state = NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
                (void)memcpy(attempt->key, fba_key, 76u);
                attempt->attempt = fenced;
                attempt->packet_slot = UINT32_MAX;
                attempt->record_revision = 2u;
                (void)fba1_persist_full_ex(
                    fabric, &fenced, fba_key, 2u, NULL, 0u, NULL, NULL, NULL);
            } else {
                /* OLD/ABSENT: release reserved RAM; fully retryable. */
                free_attempt_slot(fabric, attempt);
            }
            return NINLIL_BEARER_LOST_UNKNOWN;
        } else {
            free_packet_slot(fabric, pslot);
            free_attempt_slot(fabric, attempt);
            return NINLIL_BEARER_CORRUPT;
        }
    }

fabric_start_provider:
    /*
     * ADR-0017 step 5: revalidate lifecycle/availability epoch/authority/
     * security pins/TxPermit. On failure: CLOSED FULL, free packet/attempt,
     * provider call 0 (no start_send).
     */
    {
        ninlil_bearer_status_t ps;
        ninlil_time_sample_t now2;
        ninlil_bearer_status_t fail_st = NINLIL_BEARER_OK;
        ninlil_fabric_private_memzero(&now2, sizeof(now2));
        now2.abi_version = NINLIL_ABI_VERSION;
        now2.struct_size = (uint16_t)sizeof(now2);
        if (fabric->clock.now(fabric->clock.user, &now2) != NINLIL_PORT_OK
            || now2.trust != NINLIL_CLOCK_TRUSTED) {
            fail_st = NINLIL_BEARER_CORRUPT;
        } else {
            ps = fabric_validate_tx_permit(fabric, permit, message, &now2);
            if (ps != NINLIL_BEARER_OK) {
                fail_st = ps;
            } else if (reg == NULL || reg->lifecycle != FABRIC_REG_ACTIVE
                || reg->state.available != 1u
                || now2.now_ms >= reg->state.available_until_ms
                || reg->state.availability_epoch
                    != attempt->attempt.availability_epoch
                || !ninlil_fabric_private_memeq(
                       reg->state.availability_clock_epoch_id.bytes,
                       attempt->attempt.availability_clock_epoch_id,
                       16u)
                || !ninlil_fabric_private_memeq(
                       reg->descriptor.descriptor_digest,
                       attempt->attempt.descriptor_digest,
                       32u)
                || !ninlil_fabric_private_memeq(
                       reg->descriptor.security_profile_id.bytes,
                       attempt->attempt.security_profile_id,
                       16u)
                || !ninlil_fabric_private_memeq(
                       reg->descriptor.attestation_digest,
                       attempt->attempt.attestation_digest,
                       32u)) {
                fail_st = NINLIL_BEARER_UNAVAILABLE;
            }
        }
        if (fail_st != NINLIL_BEARER_OK) {
            ninlil_fabric_private_fba1_t closed = attempt->attempt;
            ninlil_fabric_private_status_t cst;
            closed.state = NINLIL_FABRIC_PRIVATE_ATTEMPT_CLOSED;
            cst = fba1_persist_full_next(
                fabric, &closed, attempt->key, &attempt->record_revision);
            if (cst == NINLIL_FABRIC_PRIVATE_OK) {
                attempt->attempt = closed;
            } else if (cst == NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN) {
                attempt->attempt.state =
                    NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
                fail_st = NINLIL_BEARER_LOST_UNKNOWN;
            } else {
                attempt->attempt.state =
                    NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
                fail_st = NINLIL_BEARER_CORRUPT;
            }
            if (attempt->packet_slot < NINLIL_FABRIC_SHARED_QUEUE_MAX) {
                free_packet_slot(fabric, attempt->packet_slot);
                attempt->packet_slot = UINT32_MAX;
            }
            /* Reservation released by CLOSED (not counted for capacity). */
            return fail_st;
        }
    }
    ninlil_fabric_private_memzero(&view, sizeof(view));
    view.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    view.struct_size = (uint16_t)sizeof(view);
    view.reserved_zero = 0u;
    if (attempt->packet_slot >= NINLIL_FABRIC_SHARED_QUEUE_MAX) {
        return NINLIL_BEARER_CORRUPT;
    }
    view.bytes = fabric->packet_pool[attempt->packet_slot].bytes;
    view.length = fabric->packet_pool[attempt->packet_slot].length;
    (void)memcpy(
        view.transaction_id.bytes, message->transaction_id.bytes, 16u);
    (void)memcpy(view.attempt_id.bytes, message->attempt_id.bytes, 16u);
    (void)memcpy(
        view.selected_path_id.bytes, attempt->attempt.selected_path_id, 16u);
    view.path_selection_epoch = attempt->attempt.path_selection_epoch;
    /*
     * Call-scoped TxPermit borrow only. Fabric already validated; provider
     * must re-validate before I/O. Never store permit for later step/poll.
     */
    if (permit == NULL) {
        return NINLIL_BEARER_DENIED;
    }
    view.permit = permit;

    /*
     * Durable co-located one-shot claim before provider I/O. On any uncertain
     * claim outcome provider start remains zero. CU-NEW leaves CLAIMED in the
     * FBA1; OLD leaves CLEAR; both are fenced in RAM and restart fencing turns
     * durable PREPARED into FENCED_UNKNOWN without authorizing I/O.
     */
    {
        uint32_t claim_cu_class = 0u;
        ninlil_fabric_private_status_t claim_st =
            fabric_permit_claim(fabric, attempt, permit, &claim_cu_class);
        if (claim_st != NINLIL_FABRIC_PRIVATE_OK) {
            (void)claim_cu_class;
            attempt->attempt.state =
                NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
            if (attempt->packet_slot < NINLIL_FABRIC_SHARED_QUEUE_MAX) {
                free_packet_slot(fabric, attempt->packet_slot);
                attempt->packet_slot = UINT32_MAX;
            }
            reg->metrics.lost_unknown_count++;
            fabric_metrics_bump(reg);
            return NINLIL_BEARER_LOST_UNKNOWN;
        }
    }

    fabric->reentrant = 1u;
    ls = reg->ops.start_send(reg->ops.user, reg->handle, &view, &token);
    fabric->reentrant = 0u;

    /* Valid shapes: RETAINED+non-NULL, or non-RETAINED+NULL only. */
    if (ls == NINLIL_FABRIC_LINK_RETAINED) {
        if (token == NULL) {
            ninlil_fabric_private_fba1_t next = attempt->attempt;
            next.state = NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
            st = fba1_persist_full_next(
                fabric, &next, attempt->key, &attempt->record_revision);
            if (st == NINLIL_FABRIC_PRIVATE_OK) {
                attempt->attempt = next;
            } else {
                attempt->attempt.state =
                    NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
            }
            reg->metrics.corrupt_count++;
            fabric_metrics_bump(reg);
            return NINLIL_BEARER_CORRUPT;
        }
        {
            ninlil_fabric_private_fba1_t next = attempt->attempt;
            next.state = NINLIL_FABRIC_PRIVATE_ATTEMPT_LINK_RETAINED;
            st = fba1_persist_full_next(
                fabric, &next, attempt->key, &attempt->record_revision);
            if (st != NINLIL_FABRIC_PRIVATE_OK) {
                /*
                 * Provider side-effect: fence FBA1, cancel+release token
                 * exactly once so step/close cannot hang on retained_tokens.
                 */
                attempt->token = token;
                attempt->has_token = 1u;
                reg->retained_tokens++;
                attempt_drop_provider_token(fabric, attempt, 1);
                {
                    ninlil_fabric_private_fba1_t fenced = attempt->attempt;
                    fenced.state =
                        NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
                    st = fba1_persist_full_next(
                        fabric, &fenced, attempt->key, &attempt->record_revision);
                    if (st == NINLIL_FABRIC_PRIVATE_OK) {
                        attempt->attempt = fenced;
                    } else {
                        attempt->attempt.state =
                            NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
                    }
                }
                reg->metrics.lost_unknown_count++;
                fabric_metrics_bump(reg);
                return NINLIL_BEARER_LOST_UNKNOWN;
            }
            attempt->attempt = next;
            attempt->token = token;
            attempt->has_token = 1u;
            reg->retained_tokens++;
            /* Co-located FBA1 CLAIMED stays consumed through retention/GC. */
            reg->metrics.accepted_count++;
            fabric_metrics_bump(reg);
            out_result->kind = NINLIL_BEARER_SEND_ACCEPTED;
            out_result->availability_epoch =
                fabric->meta.outer_availability_epoch;
            return NINLIL_BEARER_OK;
        }
    }

    if (token != NULL) {
        /* Contradiction: non-RETAINED must not return a token. Drain once. */
        attempt->token = token;
        attempt->has_token = 1u;
        reg->retained_tokens++;
        attempt_drop_provider_token(fabric, attempt, 1);
        {
            ninlil_fabric_private_fba1_t next = attempt->attempt;
            next.state = NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
            st = fba1_persist_full_next(
                fabric, &next, attempt->key, &attempt->record_revision);
            if (st == NINLIL_FABRIC_PRIVATE_OK) {
                attempt->attempt = next;
            } else {
                attempt->attempt.state =
                    NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
            }
        }
        reg->metrics.corrupt_count++;
        fabric_metrics_bump(reg);
        return NINLIL_BEARER_CORRUPT;
    }

    /*
     * Definite non-accept: state transition + CLAIMED -> CLEAR are one FBA1
     * replacement FULL. CU-NEW proves the exact intended row and is promotable;
     * OLD/PARTIAL/THIRD retain/fence the claim fail-closed.
     */
    if (ls == NINLIL_FABRIC_LINK_WOULD_BLOCK
        || ls == NINLIL_FABRIC_LINK_UNAVAILABLE
        || ls == NINLIL_FABRIC_LINK_DENIED) {
        uint32_t clear_cu_class = 0u;
        uint32_t next_state =
            ls == NINLIL_FABRIC_LINK_WOULD_BLOCK
            ? NINLIL_FABRIC_PRIVATE_ATTEMPT_RETRYABLE_NO_ACCEPT
            : NINLIL_FABRIC_PRIVATE_ATTEMPT_CLOSED;
        ninlil_fabric_private_status_t clear_st =
            fabric_permit_clear_with_state(
                fabric, attempt, next_state, &clear_cu_class);
        if (clear_st != NINLIL_FABRIC_PRIVATE_OK
            && !(clear_st == NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN
                && clear_cu_class
                    == NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_NEW)) {
            attempt->attempt.state =
                NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
            if (attempt->packet_slot < NINLIL_FABRIC_SHARED_QUEUE_MAX) {
                free_packet_slot(fabric, attempt->packet_slot);
                attempt->packet_slot = UINT32_MAX;
            }
            reg->metrics.lost_unknown_count++;
            fabric_metrics_bump(reg);
            return NINLIL_BEARER_LOST_UNKNOWN;
        }
        if (ls == NINLIL_FABRIC_LINK_WOULD_BLOCK) {
            reg->metrics.would_block_count++;
            fabric_metrics_bump(reg);
            return NINLIL_BEARER_WOULD_BLOCK;
        }
        if (ls == NINLIL_FABRIC_LINK_UNAVAILABLE) {
            reg->metrics.unavailable_count++;
            fabric_metrics_bump(reg);
            return NINLIL_BEARER_UNAVAILABLE;
        }
        reg->metrics.denied_count++;
        fabric_metrics_bump(reg);
        return NINLIL_BEARER_DENIED;
    }
    {
        ninlil_fabric_private_fba1_t next = attempt->attempt;
        next.state = NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
        st = fba1_persist_full_next(
            fabric, &next, attempt->key, &attempt->record_revision);
        if (st != NINLIL_FABRIC_PRIVATE_OK) {
            attempt->attempt.state =
                NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
            reg->metrics.lost_unknown_count++;
            fabric_metrics_bump(reg);
            return NINLIL_BEARER_LOST_UNKNOWN;
        }
        attempt->attempt = next;
        if (ls == NINLIL_FABRIC_LINK_LOST_UNKNOWN) {
            reg->metrics.lost_unknown_count++;
            fabric_metrics_bump(reg);
            return NINLIL_BEARER_LOST_UNKNOWN;
        }
        reg->metrics.corrupt_count++;
        fabric_metrics_bump(reg);
        return NINLIL_BEARER_CORRUPT;
    }
}

static ninlil_bearer_status_t fabric_bearer_receive_next(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_message_t *out_message)
{
    ninlil_fabric_private_t *fabric = (ninlil_fabric_private_t *)user;
    fabric_rx_slot_t *slot;
    if (fabric == NULL || out_message == NULL) {
        return NINLIL_BEARER_CORRUPT;
    }
    if (owner_check(fabric) != NINLIL_FABRIC_PRIVATE_OK) {
        return NINLIL_BEARER_CORRUPT;
    }
    if (handle != fabric->outer_handle_token) {
        return NINLIL_BEARER_CORRUPT;
    }
    if (fabric->rx_count == 0u) {
        return NINLIL_BEARER_EMPTY;
    }
    slot = &fabric->rx_queue[fabric->rx_head];
    /* Exact-1 outer loan: second receive before release => WOULD_BLOCK. */
    if (slot->loaned != 0u || fabric->outer_rx_loan_live != 0u) {
        return NINLIL_BEARER_WOULD_BLOCK;
    }
    if (fabric->outer_rx_loan_generation == UINT32_MAX) {
        return NINLIL_BEARER_CORRUPT; /* wrap fail-closed */
    }
    *out_message = slot->projected;
    slot->loaned = 1u;
    fabric->outer_rx_loan_generation += 1u;
    fabric->outer_rx_loan_live = fabric->outer_rx_loan_generation;
    return NINLIL_BEARER_OK;
}

static void fabric_bearer_release_received(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_message_t *message)
{
    ninlil_fabric_private_t *fabric = (ninlil_fabric_private_t *)user;
    fabric_rx_slot_t *slot;
    (void)message;
    /* Outer NULL/magic first; then owner then reentry. */
    if (fabric == NULL || fabric->magic != FABRIC_MAGIC) {
        return;
    }
    if (owner_then_reentry(fabric) != NINLIL_FABRIC_PRIVATE_OK) {
        return;
    }
    if (handle != fabric->outer_handle_token || fabric->rx_count == 0u) {
        return;
    }
    slot = &fabric->rx_queue[fabric->rx_head];
    /* Exact-once release: no live generation => no-op (no double free). */
    if (slot->loaned == 0u || fabric->outer_rx_loan_live == 0u) {
        return;
    }
    fabric->outer_rx_loan_live = 0u;
    free_packet_slot(fabric, slot->packet_slot);
    ninlil_fabric_private_memzero(slot, sizeof(*slot));
    fabric->rx_head = (fabric->rx_head + 1u) % NINLIL_FABRIC_SHARED_QUEUE_MAX;
    fabric->rx_count--;
}

static ninlil_bearer_status_t fabric_bearer_state(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_state_t *out_state)
{
    ninlil_fabric_private_t *fabric = (ninlil_fabric_private_t *)user;
    if (fabric == NULL || out_state == NULL) {
        return NINLIL_BEARER_CORRUPT;
    }
    if (owner_check(fabric) != NINLIL_FABRIC_PRIVATE_OK) {
        return NINLIL_BEARER_CORRUPT;
    }
    if (handle != fabric->outer_handle_token) {
        return NINLIL_BEARER_CORRUPT;
    }
    ninlil_fabric_private_memzero(out_state, sizeof(*out_state));
    out_state->abi_version = NINLIL_ABI_VERSION;
    out_state->struct_size = (uint16_t)sizeof(*out_state);
    out_state->availability_epoch = fabric->meta.outer_availability_epoch;
    out_state->available = fabric->meta.outer_available;
    return NINLIL_BEARER_OK;
}

/* ---------- ingress authorization (before RX publish) ---------- */

static int fabric_authority_matches_forward_env(
    const fabric_authority_slot_t *auth,
    const ninlil_fabric_private_nfl1_envelope_t *env,
    const uint8_t service_digest[32],
    uint32_t direction,
    uint16_t traffic_class)
{
    const uint8_t *scope_endpoint;

    if (auth == NULL || env == NULL || service_digest == NULL
        || auth->index.used == 0u) {
        return 0;
    }
    if (!ninlil_fabric_private_memeq(
            auth->index.service_identity_digest, service_digest, 32u)
        || auth->index.family != env->family
        || auth->index.direction != direction
        || auth->index.traffic_class != traffic_class) {
        return 0;
    }
    if (!ninlil_fabric_private_memeq(
            auth->index.target_runtime_id, env->target_runtime_id.bytes, 16u)
        || !ninlil_fabric_private_memeq(
               auth->index.target_application_id,
               env->target_application_id.bytes,
               16u)) {
        return 0;
    }
    if (!ninlil_fabric_private_memeq(
            auth->index.policy_id, env->route_policy_id.bytes, 16u)
        || auth->index.policy_revision != env->route_policy_revision
        || !ninlil_fabric_private_memeq(
               auth->policy_digest, env->route_policy_digest.bytes, 32u)) {
        return 0;
    }
    if (auth->index.scope_selector == NINLIL_FABRIC_SCOPE_TARGET_RUNTIME) {
        scope_endpoint = env->target_runtime_id.bytes;
    } else if (auth->index.scope_selector
        == NINLIL_FABRIC_SCOPE_SOURCE_RUNTIME) {
        scope_endpoint = env->source_runtime_id.bytes;
    } else {
        return 0;
    }
    if (!ninlil_fabric_private_memeq(
            auth->endpoint_runtime_id, scope_endpoint, 16u)
        || !ninlil_fabric_private_memeq(
               auth->index.endpoint_runtime_id, scope_endpoint, 16u)) {
        return 0;
    }
    if (auth->authority_state == NINLIL_FABRIC_AUTHORITY_ABSENT) {
        if (!ninlil_fabric_private_id_is_zero(env->authority_id.bytes)
            || env->authority_term != 0u || env->assignment_epoch != 0u) {
            return 0;
        }
    } else if (auth->authority_state == NINLIL_FABRIC_AUTHORITY_BOUND) {
        if (!ninlil_fabric_private_memeq(
                auth->authority_id, env->authority_id.bytes, 16u)
            || auth->authority_term != env->authority_term
            || auth->assignment_epoch != env->assignment_epoch) {
            return 0;
        }
    } else {
        return 0;
    }
    return 1;
}

/* Exactly one matching FBC1 pin, else NULL (0 or ambiguous). */
static const fabric_authority_slot_t *fabric_resolve_unique_forward_authority(
    ninlil_fabric_private_t *fabric,
    const ninlil_fabric_private_nfl1_envelope_t *env,
    const uint8_t service_digest[32],
    uint32_t direction,
    uint16_t traffic_class)
{
    const fabric_authority_slot_t *found = NULL;
    uint32_t matches = 0u;
    uint32_t ai;

    for (ai = 0u; ai < FABRIC_RAM_AUTHORITY_MAX; ++ai) {
        const fabric_authority_slot_t *auth = &fabric->authorities[ai];
        if (auth->index.used == 0u) {
            continue;
        }
        if (fabric_authority_matches_forward_env(
                auth, env, service_digest, direction, traffic_class)
            == 0) {
            continue;
        }
        matches++;
        found = auth;
        if (matches > 1u) {
            return NULL;
        }
    }
    return matches == 1u ? found : NULL;
}

/*
 * Reverse kind must bit-exact echo the saved FBT1 pin:
 * transaction, triggering attempt, authority group, policy, endpoint.
 * owner_scope/owner_tuple are FBT1 pins verified against unique current FBC1.
 */
static int fabric_reverse_trigger_echo_ok(
    ninlil_fabric_private_t *fabric,
    const ninlil_fabric_private_fbt1_t *trig,
    const ninlil_fabric_private_nfl1_envelope_t *env,
    uint32_t expect_kind)
{
    uint32_t ai;
    uint32_t fbc_matches = 0u;
    const fabric_authority_slot_t *fbc = NULL;

    if (trig == NULL || env == NULL) {
        return 0;
    }
    if (trig->triggering_kind != expect_kind) {
        return 0;
    }
    if (!ninlil_fabric_private_memeq(
            trig->transaction_id, env->transaction_id.bytes, 16u)
        || !ninlil_fabric_private_memeq(
               trig->triggering_attempt_id, env->attempt_id.bytes, 16u)) {
        return 0;
    }
    /* Policy pin from forward ingress must echo on reverse NFL1. */
    if (!ninlil_fabric_private_memeq(
            trig->policy_id, env->route_policy_id.bytes, 16u)
        || trig->policy_revision != env->route_policy_revision
        || !ninlil_fabric_private_memeq(
               trig->policy_digest, env->route_policy_digest.bytes, 32u)) {
        return 0;
    }
    /* Authority 3-field group bit-exact echo. */
    if (trig->authority_state == NINLIL_FABRIC_AUTHORITY_ABSENT) {
        if (!ninlil_fabric_private_id_is_zero(env->authority_id.bytes)
            || env->authority_term != 0u || env->assignment_epoch != 0u
            || !ninlil_fabric_private_id_is_zero(trig->authority_id)
            || trig->authority_term != 0u || trig->assignment_epoch != 0u) {
            return 0;
        }
    } else if (trig->authority_state == NINLIL_FABRIC_AUTHORITY_BOUND) {
        if (!ninlil_fabric_private_memeq(
                trig->authority_id, env->authority_id.bytes, 16u)
            || trig->authority_term != env->authority_term
            || trig->assignment_epoch != env->assignment_epoch
            || ninlil_fabric_private_id_is_zero(trig->owner_scope_id)
            || ninlil_fabric_private_is_zero(trig->owner_tuple_digest, 32u)
            || ninlil_fabric_private_id_is_zero(trig->endpoint_runtime_id)) {
            return 0;
        }
    } else {
        return 0;
    }
    /*
     * Reverse may swap source/target; scope endpoint is not re-derived.
     * Saved endpoint must appear as reverse source runtime (original target).
     */
    if (!ninlil_fabric_private_memeq(
            trig->endpoint_runtime_id, env->source_runtime_id.bytes, 16u)) {
        return 0;
    }
    /* Unique FBC1 must still pin owner_scope / tuple digest / endpoint. */
    for (ai = 0u; ai < FABRIC_RAM_AUTHORITY_MAX; ++ai) {
        const fabric_authority_slot_t *auth = &fabric->authorities[ai];
        if (auth->index.used == 0u) {
            continue;
        }
        if (auth->authority_state != trig->authority_state) {
            continue;
        }
        if (!ninlil_fabric_private_memeq(
                auth->authority_id, trig->authority_id, 16u)
            || auth->authority_term != trig->authority_term
            || auth->assignment_epoch != trig->assignment_epoch) {
            continue;
        }
        if (!ninlil_fabric_private_memeq(
                auth->index.policy_id, trig->policy_id, 16u)
            || auth->index.policy_revision != trig->policy_revision
            || !ninlil_fabric_private_memeq(
                   auth->policy_digest, trig->policy_digest, 32u)) {
            continue;
        }
        if (!ninlil_fabric_private_memeq(
                auth->endpoint_runtime_id, trig->endpoint_runtime_id, 16u)
            || !ninlil_fabric_private_memeq(
                   auth->owner_scope_id, trig->owner_scope_id, 16u)
            || !ninlil_fabric_private_memeq(
                   auth->owner_tuple_digest, trig->owner_tuple_digest, 32u)) {
            continue;
        }
        fbc_matches++;
        fbc = auth;
        if (fbc_matches > 1u) {
            return 0;
        }
    }
    if (trig->authority_state == NINLIL_FABRIC_AUTHORITY_BOUND) {
        if (fbc_matches != 1u || fbc == NULL) {
            return 0;
        }
    }
    (void)fbc;
    return 1;
}

/*
 * Match a reverse ingress against the outbound forward FBA1 retained by the
 * original sender.  The reverse envelope must echo the immutable policy and
 * authority group and must originate from the peer pinned by that attempt.
 */
static int fabric_reverse_attempt_echo_ok(
    ninlil_fabric_private_t *fabric,
    const fabric_attempt_slot_t *attempt_slot,
    const ninlil_fabric_private_nfl1_envelope_t *env,
    const uint8_t service_digest[32],
    uint32_t expect_kind,
    const fabric_reg_slot_t *ingress_reg)
{
    const ninlil_fabric_private_fba1_t *attempt;
    fabric_policy_slot_t *policy = NULL;
    fabric_authority_slot_t *authority;
    uint32_t policy_matches = 0u;
    uint32_t i;

    if (fabric == NULL || attempt_slot == NULL || env == NULL
        || service_digest == NULL || ingress_reg == NULL
        || attempt_slot->used == 0u) {
        return 0;
    }
    attempt = &attempt_slot->attempt;
    if (attempt->message_kind != expect_kind
        || !ninlil_fabric_private_memeq(
            attempt->transaction_id, env->transaction_id.bytes, 16u)
        || !ninlil_fabric_private_memeq(
            attempt->attempt_id, env->attempt_id.bytes, 16u)
        || !ninlil_fabric_private_memeq(
            attempt->peer_runtime_id, env->source_runtime_id.bytes, 16u)
        || !ninlil_fabric_private_memeq(
            ingress_reg->descriptor.authenticated_peer_runtime_id.bytes,
            env->source_runtime_id.bytes,
            16u)) {
        return 0;
    }
    if (!ninlil_fabric_private_memeq(
            attempt->policy_id, env->route_policy_id.bytes, 16u)
        || attempt->policy_revision != env->route_policy_revision
        || !ninlil_fabric_private_memeq(
            attempt->policy_digest, env->route_policy_digest.bytes, 32u)) {
        return 0;
    }
    if (attempt->authority_state == NINLIL_FABRIC_AUTHORITY_ABSENT) {
        if (!ninlil_fabric_private_id_is_zero(attempt->authority_id)
            || attempt->authority_term != 0u
            || attempt->assignment_epoch != 0u
            || !ninlil_fabric_private_id_is_zero(env->authority_id.bytes)
            || env->authority_term != 0u || env->assignment_epoch != 0u) {
            return 0;
        }
    } else if (attempt->authority_state == NINLIL_FABRIC_AUTHORITY_BOUND) {
        if (!ninlil_fabric_private_memeq(
                attempt->authority_id, env->authority_id.bytes, 16u)
            || attempt->authority_term != env->authority_term
            || attempt->assignment_epoch != env->assignment_epoch) {
            return 0;
        }
    } else {
        return 0;
    }

    for (i = 0u; i < FABRIC_RAM_POLICY_MAX; ++i) {
        fabric_policy_slot_t *candidate = &fabric->policies[i];
        if (candidate->index.used == 0u) {
            continue;
        }
        if (!ninlil_fabric_private_memeq(
                candidate->index.policy_id, attempt->policy_id, 16u)
            || candidate->index.revision != attempt->policy_revision
            || !ninlil_fabric_private_memeq(
                candidate->index.canonical_digest,
                attempt->policy_digest,
                32u)) {
            continue;
        }
        policy_matches++;
        policy = candidate;
        if (policy_matches > 1u) {
            return 0;
        }
    }
    if (policy_matches != 1u || policy == NULL
        || !ninlil_fabric_private_memeq(
            policy->index.service_identity_digest, service_digest, 32u)
        || policy->index.family != env->family
        || policy->index.direction != NINLIL_FABRIC_POLICY_DIRECTION_FORWARD
        || policy->index.traffic_class != traffic_for_kind(expect_kind)) {
        return 0;
    }

    /*
     * Reconstruct the triggering forward orientation from the reverse
     * envelope: reverse target was forward source, reverse source was forward
     * concrete target.
     */
    authority = fabric_resolve_unique_tx_authority(
        fabric,
        policy,
        service_digest,
        env->family,
        NINLIL_FABRIC_POLICY_DIRECTION_FORWARD,
        traffic_for_kind(expect_kind),
        env->target_runtime_id.bytes,
        env->source_runtime_id.bytes,
        env->source_application_id.bytes);
    if (authority == NULL
        || authority->authority_state != attempt->authority_state
        || authority->authority_term != attempt->authority_term
        || authority->assignment_epoch != attempt->assignment_epoch
        || !ninlil_fabric_private_memeq(
            authority->authority_id, attempt->authority_id, 16u)
        || !ninlil_fabric_private_memeq(
            authority->owner_scope_id, attempt->owner_scope_id, 16u)
        || !ninlil_fabric_private_memeq(
            authority->owner_tuple_digest,
            attempt->owner_tuple_digest,
            32u)) {
        return 0;
    }
    return 1;
}

/*
 * ADR-0017 permits exactly one saved correlation source: FBT1 at a receiver of
 * the forward trigger, or FBA1 at its original sender.  Ambiguity across or
 * within those stores fails closed.
 */
static int fabric_has_unique_reverse_context(
    ninlil_fabric_private_t *fabric,
    const ninlil_fabric_private_nfl1_envelope_t *env,
    const uint8_t service_digest[32],
    uint32_t expect_kind,
    const fabric_reg_slot_t *ingress_reg)
{
    uint32_t matches = 0u;
    uint32_t i;

    for (i = 0u; i < FABRIC_RAM_TRIGGER_MAX; ++i) {
        const fabric_trigger_slot_t *trigger = &fabric->triggers[i];
        if (trigger->used != 0u
            && fabric_reverse_trigger_echo_ok(
                   fabric, &trigger->trigger, env, expect_kind)
                != 0) {
            matches++;
            if (matches > 1u) {
                return 0;
            }
        }
    }
    for (i = 0u; i < NINLIL_FABRIC_ATTEMPT_MAX; ++i) {
        const fabric_attempt_slot_t *attempt = &fabric->attempts[i];
        if (attempt->used != 0u
            && fabric_reverse_attempt_echo_ok(
                   fabric,
                   attempt,
                   env,
                   service_digest,
                   expect_kind,
                   ingress_reg)
                != 0) {
            matches++;
            if (matches > 1u) {
                return 0;
            }
        }
    }
    return matches == 1u;
}

/* ---------- step / release / close ---------- */

ninlil_fabric_private_status_t ninlil_fabric_private_step_v1(
    ninlil_fabric_private_t *fabric,
    uint32_t work_budget,
    uint32_t *out_work_done)
{
    ninlil_fabric_private_status_t st;
    uint32_t work = 0u;
    uint32_t i;
    ninlil_time_sample_t gc_now;

    /* Outer NULL/budget before owner callback. */
    if (out_work_done == NULL || work_budget == 0u || work_budget > 64u) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    *out_work_done = 0u;
    st = owner_check(fabric);
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }

    /*
     * Deterministic durable GC: at most one FBA1 or FBT1 erase per step.
     * The instance-local preference flips after every attempted erase so a
     * continuous stream of one record kind cannot starve the other.
     */
    if (work < work_budget && fabric_sample_now(fabric, &gc_now) != 0) {
        uint32_t work_before = work;
        if (fabric->terminal_gc_prefer_trigger != 0u) {
            st = fabric_gc_one_trigger(fabric, &gc_now, &work);
            if (work != work_before) {
                fabric->terminal_gc_prefer_trigger = 0u;
            } else if (st == NINLIL_FABRIC_PRIVATE_OK) {
                st = fabric_gc_one_attempt(fabric, &gc_now, &work);
                if (work != work_before) {
                    fabric->terminal_gc_prefer_trigger = 1u;
                }
            }
        } else {
            st = fabric_gc_one_attempt(fabric, &gc_now, &work);
            if (work != work_before) {
                fabric->terminal_gc_prefer_trigger = 1u;
            } else if (st == NINLIL_FABRIC_PRIVATE_OK) {
                st = fabric_gc_one_trigger(fabric, &gc_now, &work);
                if (work != work_before) {
                    fabric->terminal_gc_prefer_trigger = 0u;
                }
            }
        }
        if (st != NINLIL_FABRIC_PRIVATE_OK) {
            *out_work_done = work;
            return st;
        }
    }

    for (i = 0u; i < NINLIL_FABRIC_ATTEMPT_MAX && work < work_budget; ++i) {
        fabric_attempt_slot_t *at = &fabric->attempts[i];
        fabric_reg_slot_t *reg;
        ninlil_fabric_link_completion_v1_t completion;
        ninlil_fabric_link_status_t ls;
        if (at->used == 0u || at->has_token == 0u) {
            continue;
        }
        /* Orphan/fenced tokens must still converge via cancel+release. */
        if (at->attempt.state
            != NINLIL_FABRIC_PRIVATE_ATTEMPT_LINK_RETAINED) {
            if (attempt_drop_provider_token(fabric, at, 1) == 0) {
                /* LOST_UNKNOWN cancel: keep retained; only step re-drives. */
                work++;
                continue;
            }
            work++;
            continue;
        }
        reg = find_reg_by_id_for_token(fabric, at->attempt.selected_path_id);
        if (reg == NULL || reg->lifecycle == FABRIC_REG_DRAINING) {
            /* Unregister drain: cancel then release only on terminal cancel. */
            attempt_fence_lost_unknown(fabric, at);
            if (attempt_drop_provider_token(fabric, at, 1) == 0) {
                work++;
                continue;
            }
            work++;
            continue;
        }
        ninlil_fabric_private_memzero(&completion, sizeof(completion));
        completion.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
        completion.struct_size = (uint16_t)sizeof(completion);
        fabric->reentrant = 1u;
        ls = reg->ops.poll_send(
            reg->ops.user, reg->handle, at->token, &completion);
        fabric->reentrant = 0u;
        work++;
        if (ls != NINLIL_FABRIC_LINK_OK) {
            /*
             * LOST_UNKNOWN / non-OK: durably fence LINK_RETAINED with FULL
             * (or COMMIT_UNKNOWN class) before any CLOSED transition.
             * Release only after terminal cancel; never drop retained on LOST.
             */
            attempt_fence_lost_unknown(fabric, at);
            if (attempt_drop_provider_token(fabric, at, 1) == 0) {
                /* Token still retained; close_poll must not done=1. */
                continue;
            }
            continue;
        }
        if (completion.kind == NINLIL_FABRIC_LINK_COMPLETION_PENDING) {
            continue;
        }
        /*
         * Terminal: FULL durable first. On FULL fail / COMMIT_UNKNOWN do NOT
         * release token (close_poll done stays 0 until durable confirms).
         */
        {
            ninlil_fabric_private_fba1_t next = at->attempt;
            ninlil_fabric_private_status_t pst;
            if (completion.kind == NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE
                || completion.kind
                    == NINLIL_FABRIC_LINK_COMPLETION_DEFINITE_FAILURE) {
                next.state = NINLIL_FABRIC_PRIVATE_ATTEMPT_CLOSED;
            } else {
                next.state = NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
            }
            pst = fba1_persist_full_next(
                fabric, &next, at->key, &at->record_revision);
            if (pst == NINLIL_FABRIC_PRIVATE_OK) {
                at->attempt = next;
                /* Durable confirmed: release exactly once (no cancel). */
                (void)attempt_drop_provider_token(fabric, at, 0);
            } else {
                /* CU / FULL fail: fence RAM, keep token, no close done. */
                at->attempt.state =
                    NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
            }
        }
    }

    /* Pull receive from active links when RX queue has capacity. */
    for (i = 0u; i < NINLIL_FABRIC_REGISTRY_MAX && work < work_budget; ++i) {
        fabric_reg_slot_t *reg = &fabric->regs[i];
        const uint8_t *bytes = NULL;
        uint32_t length = 0u;
        void *rx_token = NULL;
        ninlil_fabric_link_status_t ls;
        fabric_rx_slot_t *slot;
        uint32_t idx;
        uint32_t pslot;
        if (reg->used == 0u || reg->lifecycle != FABRIC_REG_ACTIVE) {
            continue;
        }
        if (fabric->rx_count >= NINLIL_FABRIC_SHARED_QUEUE_MAX) {
            break;
        }
        /*
         * P0: reserve shared packet slot BEFORE provider receive_next.
         * Full pool => pull 0 (no receive_next, no loan).
         */
        pslot = alloc_packet_slot(fabric);
        if (pslot == UINT32_MAX) {
            break;
        }
        fabric->reentrant = 1u;
        ls = reg->ops.receive_next(
            reg->ops.user, reg->handle, &bytes, &length, &rx_token);
        fabric->reentrant = 0u;
        work++;
        /*
         * Exact provider output-shape contract:
         * - EMPTY/WOULD_BLOCK/UNAVAILABLE: bytes=NULL, len=0, token=NULL
         * - OK: bytes non-NULL, structural len, token non-NULL
         * Dirty non-success outputs: release token if any + fence instance.
         */
        if (ls == NINLIL_FABRIC_LINK_EMPTY
            || ls == NINLIL_FABRIC_LINK_WOULD_BLOCK
            || ls == NINLIL_FABRIC_LINK_UNAVAILABLE) {
            free_packet_slot(fabric, pslot);
            if (bytes != NULL || length != 0u || rx_token != NULL) {
                fabric_provider_release_rx(fabric, reg, rx_token);
                fabric_fence_reg_instance(fabric, reg);
            }
            continue;
        }
        if (ls != NINLIL_FABRIC_LINK_OK) {
            free_packet_slot(fabric, pslot);
            /* Other non-OK: any dirty outputs cleaned; instance fenced. */
            if (bytes != NULL || length != 0u || rx_token != NULL) {
                fabric_provider_release_rx(fabric, reg, rx_token);
                fabric_fence_reg_instance(fabric, reg);
            }
            continue;
        }
        /* OK shape: require non-NULL bytes/token and valid length. */
        if (bytes == NULL || rx_token == NULL || length == 0u
            || length > NINLIL_FABRIC_NFL1_STRUCTURAL_MAX) {
            free_packet_slot(fabric, pslot);
            fabric_provider_release_rx(fabric, reg, rx_token);
            fabric_fence_reg_instance(fabric, reg);
            continue;
        }
        {
            idx = (fabric->rx_head + fabric->rx_count)
                % NINLIL_FABRIC_SHARED_QUEUE_MAX;
            slot = &fabric->rx_queue[idx];
            ninlil_fabric_private_memzero(slot, sizeof(*slot));
            (void)memcpy(fabric->packet_pool[pslot].bytes, bytes, length);
            fabric->packet_pool[pslot].length = length;
            slot->packet_slot = pslot;
            fabric_provider_release_rx(fabric, reg, rx_token);
            {
                ninlil_fabric_private_nfl1_workspace_t ws;
                ninlil_fabric_private_nfl1_envelope_t env;
                uint32_t required = 0u;
                ninlil_fabric_private_nfl1_status_t ns;
                uint8_t service_digest[32];
                uint32_t direction;
                uint16_t traffic;

                ninlil_fabric_private_memzero(&ws, sizeof(ws));
                ninlil_fabric_private_memzero(&env, sizeof(env));
                ns = ninlil_fabric_private_nfl1_decode(
                    fabric->packet_pool[pslot].bytes,
                    fabric->packet_pool[pslot].length,
                    &ws,
                    &env,
                    &required);
                if (ns != NINLIL_FABRIC_PRIVATE_NFL1_OK) {
                    free_packet_slot(fabric, pslot);
                    ninlil_fabric_private_memzero(slot, sizeof(*slot));
                    continue;
                }
                direction = direction_for_kind(env.message_kind);
                traffic = traffic_for_kind(env.message_kind);
                ninlil_fabric_private_nfl1_service_identity_digest(
                    env.namespace_id.bytes,
                    env.namespace_id.length,
                    env.service_id.bytes,
                    env.service_id.length,
                    env.schema_id.bytes,
                    env.schema_id.length,
                    env.descriptor_revision,
                    env.descriptor_digest.bytes,
                    env.schema_major,
                    env.schema_minor,
                    env.family,
                    service_digest);

                /*
                 * Authorization boundary before any Runtime-visible publish.
                 * Missing/ambiguous/mismatch => drop, no RX callback.
                 */
                if (env.message_kind == NINLIL_BEARER_MESSAGE_APPLICATION
                    || env.message_kind
                        == NINLIL_BEARER_MESSAGE_CANCEL_REQUEST) {
                    const fabric_authority_slot_t *auth;
                    fabric_trigger_slot_t *ts = NULL;
                    ninlil_fabric_private_fbt1_t prepared_trig;
                    uint8_t key[40];
                    ninlil_fabric_private_status_t pst;
                    uint32_t ti;

                    auth = fabric_resolve_unique_forward_authority(
                        fabric, &env, service_digest, direction, traffic);
                    if (auth == NULL) {
                        free_packet_slot(fabric, pslot);
                        ninlil_fabric_private_memzero(slot, sizeof(*slot));
                        continue;
                    }
                    for (ti = 0u; ti < FABRIC_RAM_TRIGGER_MAX; ++ti) {
                        if (fabric->triggers[ti].used == 0u) {
                            ts = &fabric->triggers[ti];
                            break;
                        }
                    }
                    if (ts == NULL) {
                        free_packet_slot(fabric, pslot);
                        ninlil_fabric_private_memzero(slot, sizeof(*slot));
                        continue;
                    }
                    ninlil_fabric_private_memzero(
                        &prepared_trig, sizeof(prepared_trig));
                    (void)memcpy(
                        prepared_trig.transaction_id,
                        env.transaction_id.bytes,
                        16u);
                    (void)memcpy(
                        prepared_trig.triggering_attempt_id,
                        env.attempt_id.bytes,
                        16u);
                    prepared_trig.triggering_kind = env.message_kind;
                    prepared_trig.authority_state = auth->authority_state;
                    (void)memcpy(
                        prepared_trig.endpoint_runtime_id,
                        auth->endpoint_runtime_id,
                        16u);
                    (void)memcpy(
                        prepared_trig.owner_scope_id,
                        auth->owner_scope_id,
                        16u);
                    (void)memcpy(
                        prepared_trig.authority_id, auth->authority_id, 16u);
                    prepared_trig.authority_term = auth->authority_term;
                    prepared_trig.assignment_epoch = auth->assignment_epoch;
                    (void)memcpy(
                        prepared_trig.owner_tuple_digest,
                        auth->owner_tuple_digest,
                        32u);
                    (void)memcpy(
                        prepared_trig.policy_id, auth->index.policy_id, 16u);
                    prepared_trig.policy_revision = auth->index.policy_revision;
                    (void)memcpy(
                        prepared_trig.policy_digest, auth->policy_digest, 32u);
                    ninlil_fabric_private_key_fbt1(
                        prepared_trig.transaction_id,
                        prepared_trig.triggering_attempt_id,
                        prepared_trig.triggering_kind,
                        key);
                    /*
                     * Exactly-once: same (txn,attempt,kind) is SAME only when
                     * envelope/body bit-exact match prepared_trig. Key presence
                     * alone is not enough — third-value is CORRUPT + no publish.
                     */
                    {
                        uint32_t ei;
                        uint8_t exist_val[NINLIL_FABRIC_FBT1_VALUE_BYTES];
                        uint32_t exist_len = 0u;
                        int exist_durable = 0;
                        fabric_trigger_slot_t *ram_hit = NULL;
                        for (ei = 0u; ei < FABRIC_RAM_TRIGGER_MAX; ++ei) {
                            if (fabric->triggers[ei].used != 0u
                                && ninlil_fabric_private_memeq(
                                       fabric->triggers[ei]
                                           .trigger.transaction_id,
                                       prepared_trig.transaction_id,
                                       16u)
                                && ninlil_fabric_private_memeq(
                                       fabric->triggers[ei]
                                           .trigger.triggering_attempt_id,
                                       prepared_trig.triggering_attempt_id,
                                       16u)
                                && fabric->triggers[ei]
                                        .trigger.triggering_kind
                                    == prepared_trig.triggering_kind) {
                                ram_hit = &fabric->triggers[ei];
                                break;
                            }
                        }
                        if (ram_hit != NULL) {
                            if (!ninlil_fabric_private_memeq(
                                    &ram_hit->trigger,
                                    &prepared_trig,
                                    sizeof(prepared_trig))) {
                                /* Third-value collision vs current authority. */
                                free_packet_slot(fabric, pslot);
                                ninlil_fabric_private_memzero(
                                    slot, sizeof(*slot));
                                continue;
                            }
                            /* SAME RAM: no re-publish. */
                            free_packet_slot(fabric, pslot);
                            ninlil_fabric_private_memzero(
                                slot, sizeof(*slot));
                            continue;
                        }
                        pst = storage_read_key_readonly(
                            fabric,
                            key,
                            40u,
                            exist_val,
                            sizeof(exist_val),
                            &exist_len,
                            &exist_durable);
                        if (pst != NINLIL_FABRIC_PRIVATE_OK) {
                            free_packet_slot(fabric, pslot);
                            ninlil_fabric_private_memzero(
                                slot, sizeof(*slot));
                            continue;
                        }
                        if (exist_durable != 0) {
                            ninlil_fabric_private_common_envelope_t env_tr;
                            const uint8_t *pl = NULL;
                            ninlil_fabric_private_fbt1_t durable_trig;
                            if (ninlil_fabric_private_record_decode_envelope(
                                    exist_val,
                                    exist_len,
                                    (const uint8_t *)"FBT1",
                                    224u,
                                    &env_tr,
                                    &pl)
                                    != NINLIL_FABRIC_PRIVATE_RECORD_OK
                                || ninlil_fabric_private_fbt1_decode(
                                       pl, &durable_trig)
                                    != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
                                free_packet_slot(fabric, pslot);
                                ninlil_fabric_private_memzero(
                                    slot, sizeof(*slot));
                                continue;
                            }
                            if (!ninlil_fabric_private_memeq(
                                    &durable_trig,
                                    &prepared_trig,
                                    sizeof(prepared_trig))) {
                                /* Durable third-value vs synthesized body. */
                                free_packet_slot(fabric, pslot);
                                ninlil_fabric_private_memzero(
                                    slot, sizeof(*slot));
                                continue;
                            }
                            /* SAME durable: pin exact durable body into RAM. */
                            ninlil_fabric_private_memzero(ts, sizeof(*ts));
                            ts->used = 1u;
                            ts->record_revision = env_tr.revision;
                            ts->trigger = durable_trig;
                            free_packet_slot(fabric, pslot);
                            ninlil_fabric_private_memzero(
                                slot, sizeof(*slot));
                            continue;
                        }
                    }
                    {
                        uint32_t cu_class = 0u;
                        uint8_t old_v[NINLIL_FABRIC_FBT1_VALUE_BYTES];
                        uint32_t old_len = 0u;
                        pst = fbt1_persist_full_ex(
                            fabric,
                            &prepared_trig,
                            key,
                            1u,
                            NULL,
                            0u,
                            &cu_class);
                        (void)old_v;
                        (void)old_len;
                        if (pst == NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN) {
                            /*
                             * ADR: no RX publish on CU. NEW may be durable —
                             * adopt RAM trigger only, still no callback.
                             */
                            if (cu_class
                                == NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_NEW) {
                                ninlil_fabric_private_memzero(ts, sizeof(*ts));
                                ts->used = 1u;
                                ts->record_revision = 1u;
                                ts->trigger = prepared_trig;
                            }
                            free_packet_slot(fabric, pslot);
                            ninlil_fabric_private_memzero(
                                slot, sizeof(*slot));
                            continue;
                        }
                        if (pst != NINLIL_FABRIC_PRIVATE_OK) {
                            free_packet_slot(fabric, pslot);
                            ninlil_fabric_private_memzero(
                                slot, sizeof(*slot));
                            continue;
                        }
                    }
                    ninlil_fabric_private_memzero(ts, sizeof(*ts));
                    ts->used = 1u;
                    ts->record_revision = 1u;
                    ts->trigger = prepared_trig;
                } else if (
                    env.message_kind == NINLIL_BEARER_MESSAGE_RECEIPT
                    || env.message_kind == NINLIL_BEARER_MESSAGE_DISPOSITION
                    || env.message_kind
                        == NINLIL_BEARER_MESSAGE_CUSTODY_ACCEPTED
                    || env.message_kind
                        == NINLIL_BEARER_MESSAGE_CANCEL_RESULT) {
                    uint32_t expect_kind =
                        (env.message_kind
                             == NINLIL_BEARER_MESSAGE_CANCEL_RESULT)
                        ? NINLIL_BEARER_MESSAGE_CANCEL_REQUEST
                        : NINLIL_BEARER_MESSAGE_APPLICATION;
                    if (fabric_has_unique_reverse_context(
                            fabric,
                            &env,
                            service_digest,
                            expect_kind,
                            reg)
                        == 0) {
                        free_packet_slot(fabric, pslot);
                        ninlil_fabric_private_memzero(slot, sizeof(*slot));
                        continue;
                    }
                } else {
                    free_packet_slot(fabric, pslot);
                    ninlil_fabric_private_memzero(slot, sizeof(*slot));
                    continue;
                }

                /* Authorized only: project to bearer message for outer RX. */
                ninlil_fabric_private_memzero(&ws, sizeof(ws));
                if (ninlil_fabric_private_project_bearer_v1(
                        fabric->packet_pool[pslot].bytes,
                        fabric->packet_pool[pslot].length,
                        &ws,
                        &slot->projected)
                    != NINLIL_FABRIC_PRIVATE_OK) {
                    free_packet_slot(fabric, pslot);
                    ninlil_fabric_private_memzero(slot, sizeof(*slot));
                    continue;
                }
                if (slot->projected.payload.length > 0u) {
                    uint32_t off = NINLIL_FABRIC_NFL1_HEADER_BYTES
                        + slot->projected.service.namespace_id.length
                        + slot->projected.service.service_id.length
                        + slot->projected.service.schema_id.length;
                    slot->projected.payload.data =
                        fabric->packet_pool[pslot].bytes + off;
                }
                if (slot->projected.evidence.length > 0u) {
                    uint32_t off = NINLIL_FABRIC_NFL1_HEADER_BYTES
                        + slot->projected.service.namespace_id.length
                        + slot->projected.service.service_id.length
                        + slot->projected.service.schema_id.length
                        + slot->projected.payload.length;
                    slot->projected.evidence.data =
                        fabric->packet_pool[pslot].bytes + off;
                }
                slot->used = 1u;
                fabric->rx_count++;
            }
        }
    }

    *out_work_done = work;
    return NINLIL_FABRIC_PRIVATE_OK;
}

static int fabric_terminal_release_more(
    const ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *transaction_id,
    uint64_t runtime_terminal_revision)
{
    uint32_t i;
    for (i = 0u; i < NINLIL_FABRIC_ATTEMPT_MAX; ++i) {
        const fabric_attempt_slot_t *at = &fabric->attempts[i];
        if (at->used == 0u
            || !ninlil_fabric_private_memeq(
                at->attempt.transaction_id, transaction_id->bytes, 16u)) {
            continue;
        }
        if (at->attempt.runtime_terminal_revision
                != runtime_terminal_revision
            || at->attempt.state != NINLIL_FABRIC_PRIVATE_ATTEMPT_DRAINED
            || at->has_token != 0u) {
            return 1;
        }
    }
    for (i = 0u; i < FABRIC_RAM_TRIGGER_MAX; ++i) {
        const fabric_trigger_slot_t *trigger = &fabric->triggers[i];
        if (trigger->used != 0u
            && ninlil_fabric_private_memeq(
                trigger->trigger.transaction_id,
                transaction_id->bytes,
                16u)
            && trigger->trigger.runtime_terminal_revision
                != runtime_terminal_revision) {
            return 1;
        }
    }
    return 0;
}

/*
 * Transaction-level terminal release.  The complete 64+64 RAM preflight is
 * mutation-free; one invocation then performs at most one durable row
 * transition.  Provider tokens remain owned by the existing bounded step.
 */
ninlil_fabric_private_status_t ninlil_fabric_private_terminal_release_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *transaction_id,
    uint64_t runtime_terminal_revision,
    uint32_t *out_work_done,
    uint32_t *out_more)
{
    ninlil_fabric_private_status_t st;
    fabric_attempt_slot_t *action_attempt = NULL;
    fabric_trigger_slot_t *action_trigger = NULL;
    uint32_t i;

    if (out_work_done == NULL || out_more == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    *out_work_done = 0u;
    *out_more = 0u;
    st = owner_check(fabric);
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    if (transaction_id == NULL
        || ninlil_fabric_private_id_is_zero(transaction_id->bytes)
        || runtime_terminal_revision == 0u) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }

    /* Full preflight: any different non-zero token conflicts before writes. */
    for (i = 0u; i < NINLIL_FABRIC_ATTEMPT_MAX; ++i) {
        fabric_attempt_slot_t *at = &fabric->attempts[i];
        uint64_t token;
        if (at->used == 0u
            || !ninlil_fabric_private_memeq(
                at->attempt.transaction_id, transaction_id->bytes, 16u)) {
            continue;
        }
        token = at->attempt.runtime_terminal_revision;
        if (token != 0u && token != runtime_terminal_revision) {
            return NINLIL_FABRIC_PRIVATE_CONFLICT;
        }
        if (at->attempt.state == NINLIL_FABRIC_PRIVATE_ATTEMPT_DRAINED
            && token == runtime_terminal_revision && at->has_token == 0u) {
            continue;
        }
        if (at->has_token != 0u
            && token == runtime_terminal_revision) {
            continue;
        }
        if (action_attempt == NULL) {
            action_attempt = at;
        }
    }
    for (i = 0u; i < FABRIC_RAM_TRIGGER_MAX; ++i) {
        fabric_trigger_slot_t *trigger = &fabric->triggers[i];
        uint64_t token;
        if (trigger->used == 0u
            || !ninlil_fabric_private_memeq(
                trigger->trigger.transaction_id,
                transaction_id->bytes,
                16u)) {
            continue;
        }
        token = trigger->trigger.runtime_terminal_revision;
        if (token != 0u && token != runtime_terminal_revision) {
            return NINLIL_FABRIC_PRIVATE_CONFLICT;
        }
        if (token == 0u && action_attempt == NULL
            && action_trigger == NULL) {
            action_trigger = trigger;
        }
    }

    *out_more = fabric_terminal_release_more(
        fabric, transaction_id, runtime_terminal_revision);
    if (action_attempt == NULL && action_trigger == NULL) {
        return NINLIL_FABRIC_PRIVATE_OK;
    }

    if (action_attempt != NULL) {
        ninlil_fabric_private_fba1_t old = action_attempt->attempt;
        ninlil_fabric_private_fba1_t next = old;
        uint32_t cu_class = 0u;
        uint32_t mutation_attempted = 0u;

        if (next.runtime_terminal_revision == 0u) {
            ninlil_time_sample_t now;
            if (fabric_sample_now(fabric, &now) == 0) {
                return NINLIL_FABRIC_PRIVATE_CORRUPT;
            }
            next.runtime_terminal_revision = runtime_terminal_revision;
            (void)memcpy(
                next.retention_clock_epoch_id,
                now.clock_epoch_id.bytes,
                16u);
            if (fabric_checked_add_u64(
                    now.now_ms,
                    NINLIL_FABRIC_RETRY_LIFETIME_MS,
                    &next.retention_until_ms)
                == 0) {
                return NINLIL_FABRIC_PRIVATE_CAPACITY;
            }
        }
        if (old.state == NINLIL_FABRIC_PRIVATE_ATTEMPT_PREPARED
            || old.state
                == NINLIL_FABRIC_PRIVATE_ATTEMPT_RETRYABLE_NO_ACCEPT) {
            next.state = NINLIL_FABRIC_PRIVATE_ATTEMPT_CLOSED;
        } else if (
            old.state == NINLIL_FABRIC_PRIVATE_ATTEMPT_LINK_RETAINED) {
            next.state = NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN;
        } else if (
            old.state == NINLIL_FABRIC_PRIVATE_ATTEMPT_CLOSED
            || old.state
                == NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN) {
            if (action_attempt->has_token != 0u) {
                if (old.runtime_terminal_revision != 0u) {
                    *out_more = 1u;
                    return NINLIL_FABRIC_PRIVATE_OK;
                }
                next.state = old.state;
            } else {
                next.state = NINLIL_FABRIC_PRIVATE_ATTEMPT_DRAINED;
            }
        } else {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
        st = fba1_replace_full_classified(
            fabric,
            &old,
            &next,
            action_attempt->key,
            &action_attempt->record_revision,
            &cu_class,
            &mutation_attempted);
        *out_work_done = mutation_attempted;
        if (st == NINLIL_FABRIC_PRIVATE_OK
            || (st == NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN
                && cu_class == NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_NEW)) {
            action_attempt->attempt = next;
            if (next.state == NINLIL_FABRIC_PRIVATE_ATTEMPT_DRAINED
                && action_attempt->has_token == 0u
                && action_attempt->packet_slot
                    < NINLIL_FABRIC_SHARED_QUEUE_MAX) {
                free_packet_slot(fabric, action_attempt->packet_slot);
                action_attempt->packet_slot = UINT32_MAX;
            }
        }
        *out_more = st == NINLIL_FABRIC_PRIVATE_OK
            ? (uint32_t)fabric_terminal_release_more(
                  fabric, transaction_id, runtime_terminal_revision)
            : 1u;
        return st;
    }

    {
        ninlil_fabric_private_fbt1_t next = action_trigger->trigger;
        ninlil_time_sample_t now;
        uint8_t key[40];
        uint8_t old_value[NINLIL_FABRIC_FBT1_VALUE_BYTES];
        uint32_t old_len = 0u;
        int old_present = 0;
        uint32_t cu_class = 0u;
        uint64_t next_revision;

        if (fabric_sample_now(fabric, &now) == 0) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
        next.runtime_terminal_revision = runtime_terminal_revision;
        (void)memcpy(
            next.retention_clock_epoch_id, now.clock_epoch_id.bytes, 16u);
        if (fabric_checked_add_u64(
                now.now_ms,
                NINLIL_FABRIC_RETRY_LIFETIME_MS,
                &next.retention_until_ms)
                == 0
            || fabric_checked_next_u64(
                   action_trigger->record_revision, &next_revision)
                == 0) {
            return NINLIL_FABRIC_PRIVATE_CAPACITY;
        }
        ninlil_fabric_private_key_fbt1(
            next.transaction_id,
            next.triggering_attempt_id,
            next.triggering_kind,
            key);
        st = storage_read_key_readonly(
            fabric,
            key,
            40u,
            old_value,
            sizeof(old_value),
            &old_len,
            &old_present);
        if (st != NINLIL_FABRIC_PRIVATE_OK) {
            return st;
        }
        if (old_present == 0) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
        st = fbt1_persist_full_ex(
            fabric,
            &next,
            key,
            next_revision,
            old_value,
            old_len,
            &cu_class);
        *out_work_done = 1u;
        if (st == NINLIL_FABRIC_PRIVATE_OK
            || (st == NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN
                && cu_class == NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_NEW)) {
            action_trigger->trigger = next;
            action_trigger->record_revision = next_revision;
        }
        *out_more = st == NINLIL_FABRIC_PRIVATE_OK
            ? (uint32_t)fabric_terminal_release_more(
                  fabric, transaction_id, runtime_terminal_revision)
            : 1u;
        return st;
    }
}

ninlil_fabric_private_status_t ninlil_fabric_private_dispatch_release_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *transaction_id,
    const ninlil_id128_t *attempt_id,
    uint32_t message_kind,
    uint32_t response_slot,
    const uint8_t foundation_message_digest[32],
    uint64_t runtime_terminal_revision)
{
    ninlil_fabric_private_status_t st = owner_check(fabric);
    uint8_t key[76];
    fabric_attempt_slot_t *attempt;
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    if (transaction_id == NULL || attempt_id == NULL
        || foundation_message_digest == NULL
        || runtime_terminal_revision == 0u) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    ninlil_fabric_private_key_fba1(
        transaction_id->bytes,
        attempt_id->bytes,
        message_kind,
        response_slot,
        foundation_message_digest,
        key);
    attempt = find_attempt_slot(fabric, key);
    if (attempt == NULL) {
        return NINLIL_FABRIC_PRIVATE_UNAVAILABLE;
    }
    if (attempt->attempt.state == NINLIL_FABRIC_PRIVATE_ATTEMPT_PREPARED) {
        ninlil_fabric_private_fba1_t next = attempt->attempt;
        next.state = NINLIL_FABRIC_PRIVATE_ATTEMPT_CLOSED;
        st = fba1_persist_full_next(
            fabric, &next, attempt->key, &attempt->record_revision);
        if (st != NINLIL_FABRIC_PRIVATE_OK) {
            return st;
        }
        attempt->attempt = next;
    }
    if (attempt->attempt.state == NINLIL_FABRIC_PRIVATE_ATTEMPT_CLOSED
        || attempt->attempt.state
            == NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN) {
        ninlil_fabric_private_fba1_t next = attempt->attempt;
        ninlil_time_sample_t now;
        if (fabric_sample_now(fabric, &now) == 0) {
            return NINLIL_FABRIC_PRIVATE_CORRUPT;
        }
        next.state = NINLIL_FABRIC_PRIVATE_ATTEMPT_DRAINED;
        next.runtime_terminal_revision = runtime_terminal_revision;
        (void)memcpy(
            next.retention_clock_epoch_id, now.clock_epoch_id.bytes, 16u);
        if (fabric_checked_add_u64(
                now.now_ms,
                NINLIL_FABRIC_RETRY_LIFETIME_MS,
                &next.retention_until_ms)
            == 0) {
            return NINLIL_FABRIC_PRIVATE_CAPACITY;
        }
        st = fba1_persist_full_next(
            fabric, &next, attempt->key, &attempt->record_revision);
        if (st != NINLIL_FABRIC_PRIVATE_OK) {
            return st;
        }
        attempt->attempt = next;
        if (attempt->packet_slot < NINLIL_FABRIC_SHARED_QUEUE_MAX) {
            free_packet_slot(fabric, attempt->packet_slot);
            attempt->packet_slot = UINT32_MAX;
        }
        return NINLIL_FABRIC_PRIVATE_OK;
    }
    return NINLIL_FABRIC_PRIVATE_CONFLICT;
}

ninlil_fabric_private_status_t ninlil_fabric_private_trigger_release_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *transaction_id,
    const ninlil_id128_t *triggering_attempt_id,
    uint32_t triggering_kind,
    uint64_t runtime_terminal_revision)
{
    ninlil_fabric_private_status_t st = owner_check(fabric);
    uint32_t i;
    ninlil_time_sample_t now;
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    if (transaction_id == NULL || triggering_attempt_id == NULL
        || runtime_terminal_revision == 0u) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (fabric_sample_now(fabric, &now) == 0) {
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    for (i = 0u; i < FABRIC_RAM_TRIGGER_MAX; ++i) {
        if (fabric->triggers[i].used != 0u
            && ninlil_fabric_private_memeq(
                   fabric->triggers[i].trigger.transaction_id,
                   transaction_id->bytes,
                   16u)
            && ninlil_fabric_private_memeq(
                   fabric->triggers[i].trigger.triggering_attempt_id,
                   triggering_attempt_id->bytes,
                   16u)
            && fabric->triggers[i].trigger.triggering_kind
                == triggering_kind) {
            ninlil_fabric_private_fbt1_t next = fabric->triggers[i].trigger;
            uint8_t key[40];
            uint8_t old_value[NINLIL_FABRIC_FBT1_VALUE_BYTES];
            uint32_t old_len = 0u;
            int old_present = 0;
            uint32_t cu_class = 0u;

            /* Idempotent exact same terminal revision. */
            if (next.runtime_terminal_revision == runtime_terminal_revision
                && next.runtime_terminal_revision != 0u) {
                return NINLIL_FABRIC_PRIVATE_OK;
            }
            if (next.runtime_terminal_revision != 0u) {
                return NINLIL_FABRIC_PRIVATE_CONFLICT;
            }
            if (fabric_checked_add_u64(
                    now.now_ms,
                    NINLIL_FABRIC_RETRY_LIFETIME_MS,
                    &next.retention_until_ms)
                == 0) {
                return NINLIL_FABRIC_PRIVATE_CAPACITY;
            }
            next.runtime_terminal_revision = runtime_terminal_revision;
            (void)memcpy(
                next.retention_clock_epoch_id, now.clock_epoch_id.bytes, 16u);
            ninlil_fabric_private_key_fbt1(
                next.transaction_id,
                next.triggering_attempt_id,
                next.triggering_kind,
                key);
            st = storage_read_key_readonly(
                fabric, key, 40u, old_value, sizeof(old_value), &old_len,
                &old_present);
            if (st != NINLIL_FABRIC_PRIVATE_OK) {
                return st;
            }
            {
                uint64_t next_rev = 0u;
                if (fabric_checked_next_u64(
                        fabric->triggers[i].record_revision, &next_rev)
                    == 0) {
                    return NINLIL_FABRIC_PRIVATE_CAPACITY;
                }
                st = fbt1_persist_full_ex(
                    fabric,
                    &next,
                    key,
                    next_rev,
                    old_present ? old_value : NULL,
                    old_present ? old_len : 0u,
                    &cu_class);
                if (st == NINLIL_FABRIC_PRIVATE_OK) {
                    fabric->triggers[i].trigger = next;
                    fabric->triggers[i].record_revision = next_rev;
                    return NINLIL_FABRIC_PRIVATE_OK;
                }
                if (st == NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN) {
                    if (cu_class == NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_NEW) {
                        /* Durable NEW: adopt terminal into RAM. */
                        fabric->triggers[i].trigger = next;
                        fabric->triggers[i].record_revision = next_rev;
                    }
                    /* OLD: leave pre-release RAM; third already CORRUPT. */
                    return NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN;
                }
                return st;
            }
        }
    }
    return NINLIL_FABRIC_PRIVATE_UNAVAILABLE;
}

ninlil_fabric_private_status_t
ninlil_fabric_private_has_link_registrations_v1(
    ninlil_fabric_private_t *fabric, uint32_t *out_present)
{
    ninlil_fabric_private_status_t st;
    uint32_t i;

    if (out_present == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    *out_present = 0u;
    st = owner_check(fabric);
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    for (i = 0u; i < NINLIL_FABRIC_REGISTRY_MAX; ++i) {
        if (fabric->regs[i].used != 0u) {
            *out_present = 1u;
            break;
        }
    }
    return NINLIL_FABRIC_PRIVATE_OK;
}

ninlil_fabric_private_status_t ninlil_fabric_private_has_pending_work_v1(
    ninlil_fabric_private_t *fabric, uint32_t *out_present)
{
    ninlil_fabric_private_status_t st;
    uint32_t i;

    if (out_present == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    *out_present = 0u;
    st = owner_check(fabric);
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    if (fabric->rx_count != 0u) {
        *out_present = 1u;
        return NINLIL_FABRIC_PRIVATE_OK;
    }
    for (i = 0u; i < NINLIL_FABRIC_ATTEMPT_MAX; ++i) {
        if (fabric->attempts[i].used != 0u
            && fabric->attempts[i].has_token != 0u) {
            *out_present = 1u;
            return NINLIL_FABRIC_PRIVATE_OK;
        }
    }
    for (i = 0u; i < NINLIL_FABRIC_REGISTRY_MAX; ++i) {
        if (fabric->regs[i].used != 0u
            && fabric->regs[i].lifecycle == FABRIC_REG_DRAINING
            && (fabric->regs[i].retained_tokens != 0u
                || fabric->regs[i].queued_items != 0u)) {
            *out_present = 1u;
            return NINLIL_FABRIC_PRIVATE_OK;
        }
    }
    return NINLIL_FABRIC_PRIVATE_OK;
}

ninlil_fabric_private_status_t ninlil_fabric_private_close_begin_v1(
    ninlil_fabric_private_t *fabric)
{
    ninlil_fabric_private_status_t st;
    uint32_t i;
    st = owner_check(fabric);
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    if (fabric->lifecycle == FABRIC_LIFECYCLE_CLOSED) {
        return NINLIL_FABRIC_PRIVATE_CLOSED;
    }
    if (fabric->lifecycle == FABRIC_LIFECYCLE_CLOSING) {
        return NINLIL_FABRIC_PRIVATE_OK;
    }
    if (fabric->lifecycle != FABRIC_LIFECYCLE_OPEN) {
        return NINLIL_FABRIC_PRIVATE_CLOSED;
    }
    fabric->lifecycle = FABRIC_LIFECYCLE_CLOSING;
    for (i = 0u; i < NINLIL_FABRIC_REGISTRY_MAX; ++i) {
        if (fabric->regs[i].used != 0u
            && fabric->regs[i].lifecycle == FABRIC_REG_ACTIVE) {
            fabric->regs[i].lifecycle = FABRIC_REG_DRAINING;
        }
    }
    return NINLIL_FABRIC_PRIVATE_OK;
}

ninlil_fabric_private_status_t ninlil_fabric_private_close_poll_v1(
    ninlil_fabric_private_t *fabric, uint32_t *out_done)
{
    ninlil_fabric_private_status_t st;
    uint32_t i;
    uint32_t pending;
    /* Outer NULL first — no owner callback before out pointer check. */
    if (out_done == NULL) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    *out_done = 0u;
    st = owner_check(fabric);
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    if (fabric->lifecycle != FABRIC_LIFECYCLE_CLOSING) {
        return fabric->lifecycle == FABRIC_LIFECYCLE_CLOSED
            ? NINLIL_FABRIC_PRIVATE_CLOSED
            : NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    if (fabric->outer_open != 0u) {
        return NINLIL_FABRIC_PRIVATE_OK;
    }
    /*
     * P0: close_poll must NOT self-cancel/release retained tokens.
     * Only step may progress cancel/release. LOST_UNKNOWN keeps
     * has_token/retained so done stays 0 until terminal cancel+release.
     */
    pending = 0u;
    for (i = 0u; i < NINLIL_FABRIC_ATTEMPT_MAX; ++i) {
        if (fabric->attempts[i].used != 0u
            && fabric->attempts[i].has_token != 0u) {
            pending = 1u;
        }
    }
    for (i = 0u; i < NINLIL_FABRIC_REGISTRY_MAX; ++i) {
        if (fabric->regs[i].used != 0u
            && fabric->regs[i].lifecycle == FABRIC_REG_DRAINING) {
            if (fabric->regs[i].retained_tokens != 0u
                || fabric->regs[i].queued_items != 0u) {
                pending = 1u;
                continue;
            }
            fabric->reentrant = 1u;
            fabric->regs[i].ops.close(
                fabric->regs[i].ops.user, fabric->regs[i].handle);
            fabric->reentrant = 0u;
            ninlil_fabric_private_memzero(
                &fabric->regs[i], sizeof(fabric->regs[i]));
        } else if (
            fabric->regs[i].used != 0u
            && fabric->regs[i].lifecycle == FABRIC_REG_ACTIVE) {
            pending = 1u;
        }
    }
    if (fabric->rx_count != 0u) {
        pending = 1u;
    }
    if (pending != 0u) {
        /* Never done=1 while retained LOST/LINK tokens remain. */
        return NINLIL_FABRIC_PRIVATE_OK;
    }
    if (fabric->storage_open != 0u) {
        fabric->storage.close(fabric->storage.user, fabric->storage_handle);
        fabric->storage_handle = NULL;
        fabric->storage_open = 0u;
    }
    fabric->lifecycle = FABRIC_LIFECYCLE_CLOSED;
    *out_done = 1u;
    return NINLIL_FABRIC_PRIVATE_OK;
}

ninlil_fabric_private_status_t ninlil_fabric_private_destroy_v1(
    ninlil_fabric_private_t *fabric)
{
    ninlil_fabric_private_status_t st;
    st = fabric_null_magic(fabric);
    if (st != NINLIL_FABRIC_PRIVATE_OK) {
        return st;
    }
    /* Current-context contract: owner then reentry before destroy. */
    st = owner_then_reentry(fabric);
    if (st == NINLIL_FABRIC_PRIVATE_WRONG_THREAD
        || st == NINLIL_FABRIC_PRIVATE_REENTRANT) {
        return st;
    }
    /* CLOSED is allowed for destroy even though owner_then_reentry treats
     * DESTROYED/ZERO as CLOSED status; accept CLOSED lifecycle explicitly. */
    if (fabric->lifecycle != FABRIC_LIFECYCLE_CLOSED) {
        if (fabric->lifecycle == FABRIC_LIFECYCLE_DESTROYED
            || fabric->lifecycle == FABRIC_LIFECYCLE_ZERO) {
            return NINLIL_FABRIC_PRIVATE_CLOSED;
        }
        return NINLIL_FABRIC_PRIVATE_WOULD_BLOCK;
    }
    ninlil_fabric_private_memzero(fabric, sizeof(*fabric));
    return NINLIL_FABRIC_PRIVATE_OK;
}

size_t ninlil_fabric_private_core_sizeof(void);
size_t ninlil_fabric_private_core_sizeof(void)
{
    return sizeof(ninlil_fabric_private_t);
}

/*
 * ADR-0017 P1: real fabric_private_t object placement inside exact 198656.
 * Abstract region table is the capacity ledger (no cross-region loan).
 * Object proof: live sizeof/offsetof must fit declared region sizes;
 * independent sequential no-overlap; not count-only.
 */
uint32_t ninlil_fabric_private_object_partition_proof_v1(
    uint32_t *out_object_bytes,
    uint32_t *out_workspace_bytes,
    ninlil_fabric_ws_region_info_t out_objects[11])
{
    ninlil_fabric_private_t *base = (ninlil_fabric_private_t *)0;
    ninlil_fabric_ws_region_info_t abstract[NINLIL_FABRIC_WS_REGION_COUNT];
    uint32_t object_bytes;
    uint32_t abstract_total = 0u;
    uint32_t i;
    uint32_t cursor;
    uint32_t object_sum = 0u;
    uint32_t live_size[8];
    uint32_t live_off[8];
    uint32_t region_budget[8];

    if (out_object_bytes == NULL || out_workspace_bytes == NULL
        || out_objects == NULL) {
        return 1u;
    }

    /* Abstract partition ledger must already prove exact 198656. */
    if (ninlil_fabric_private_workspace_layout_proof_v1(
            &abstract_total, abstract)
        != 0u
        || abstract_total != NINLIL_FABRIC_WS_TOTAL_BYTES) {
        return 7u;
    }

    object_bytes = (uint32_t)sizeof(ninlil_fabric_private_t);
    if (object_bytes == 0u
        || object_bytes > NINLIL_FABRIC_WS_TOTAL_BYTES
        || object_bytes > NINLIL_FABRIC_WORKSPACE_BYTES) {
        return 7u;
    }

    /* Live object regions from real offsetof/sizeof (not a stack loan copy). */
    out_objects[0].offset =
        (uint32_t)offsetof(ninlil_fabric_private_t, packet_pool);
    out_objects[0].size = (uint32_t)sizeof(base->packet_pool);
    out_objects[0].alignment = (uint32_t)_Alignof(fabric_packet_slot_t);
    out_objects[0].name = "packet_pool";

    out_objects[1].offset =
        (uint32_t)offsetof(ninlil_fabric_private_t, encode_scratch);
    out_objects[1].size = (uint32_t)(
        sizeof(base->encode_scratch) + sizeof(base->decode_scratch));
    out_objects[1].alignment = 1u;
    out_objects[1].name = "codec_scratch";

    out_objects[2].offset =
        (uint32_t)offsetof(ninlil_fabric_private_t, regs);
    out_objects[2].size = (uint32_t)(
        sizeof(base->regs) + sizeof(base->reg_handles)
        + sizeof(base->fbr1_pins));
    out_objects[2].alignment = 8u;
    out_objects[2].name = "registry_objects";

    out_objects[3].offset =
        (uint32_t)offsetof(ninlil_fabric_private_t, policies);
    out_objects[3].size = (uint32_t)sizeof(base->policies);
    out_objects[3].alignment = 8u;
    out_objects[3].name = "policy_slots";

    out_objects[4].offset =
        (uint32_t)offsetof(ninlil_fabric_private_t, authorities);
    out_objects[4].size = (uint32_t)sizeof(base->authorities);
    out_objects[4].alignment = 8u;
    out_objects[4].name = "authority_slots";

    out_objects[5].offset =
        (uint32_t)offsetof(ninlil_fabric_private_t, attempts);
    out_objects[5].size = (uint32_t)sizeof(base->attempts);
    out_objects[5].alignment = 8u;
    out_objects[5].name = "attempt_slots";

    out_objects[6].offset =
        (uint32_t)offsetof(ninlil_fabric_private_t, triggers);
    out_objects[6].size = (uint32_t)sizeof(base->triggers);
    out_objects[6].alignment = 8u;
    out_objects[6].name = "trigger_slots";

    out_objects[7].offset =
        (uint32_t)offsetof(ninlil_fabric_private_t, rx_queue);
    out_objects[7].size = (uint32_t)sizeof(base->rx_queue);
    out_objects[7].alignment = 8u;
    out_objects[7].name = "rx_queue";

    /* Timers/metrics: capacity-reserved abstract regions; no live objects. */
    out_objects[8].offset = NINLIL_FABRIC_WS_OFF_TIMERS;
    out_objects[8].size = 0u;
    out_objects[8].alignment = 8u;
    out_objects[8].name = "timers_reserved";

    out_objects[9].offset = NINLIL_FABRIC_WS_OFF_REG_METRICS;
    out_objects[9].size = 0u;
    out_objects[9].alignment = 8u;
    out_objects[9].name = "reg_metrics_reserved";

    out_objects[10].offset =
        (uint32_t)offsetof(ninlil_fabric_private_t, magic);
    if (out_objects[10].offset > object_bytes) {
        return 7u;
    }
    out_objects[10].size =
        (uint32_t)(object_bytes - out_objects[10].offset);
    out_objects[10].alignment = (uint32_t)_Alignof(max_align_t);
    out_objects[10].name = "control_fields";

    /*
     * Strict no-loan: each live object size must fit its declared region
     * budget (byte sizes, not count-only). Regions 0..7 map 1:1.
     */
    live_off[0] = out_objects[0].offset;
    live_size[0] = out_objects[0].size;
    region_budget[0] = NINLIL_FABRIC_WS_NFL1_QUEUE_BYTES;
    live_off[1] = out_objects[1].offset;
    live_size[1] = out_objects[1].size;
    region_budget[1] = NINLIL_FABRIC_WS_CODEC_SCRATCH_BYTES;
    live_off[2] = out_objects[2].offset;
    live_size[2] = out_objects[2].size;
    region_budget[2] = NINLIL_FABRIC_WS_REGISTRY_BYTES;
    live_off[3] = out_objects[3].offset;
    live_size[3] = out_objects[3].size;
    region_budget[3] = NINLIL_FABRIC_WS_POLICY_INDEX_BYTES;
    live_off[4] = out_objects[4].offset;
    live_size[4] = out_objects[4].size;
    region_budget[4] = NINLIL_FABRIC_WS_AUTHORITY_INDEX_BYTES;
    live_off[5] = out_objects[5].offset;
    live_size[5] = out_objects[5].size;
    region_budget[5] = NINLIL_FABRIC_WS_ATTEMPT_BYTES;
    live_off[6] = out_objects[6].offset;
    live_size[6] = out_objects[6].size;
    region_budget[6] = NINLIL_FABRIC_WS_TRIGGER_BYTES;
    live_off[7] = out_objects[7].offset;
    live_size[7] = out_objects[7].size;
    region_budget[7] = NINLIL_FABRIC_WS_QUEUE_DESC_BYTES;

    for (i = 0u; i < 8u; ++i) {
        if (live_size[i] == 0u || live_size[i] > region_budget[i]) {
            return 7u; /* live object exceeds / loans past region budget */
        }
        if (live_off[i] != abstract[i].offset) {
            return 7u; /* object not anchored at region base */
        }
        if (live_off[i] + live_size[i]
            > abstract[i].offset + abstract[i].size) {
            return 7u; /* no-loan: must stay inside region */
        }
        if (abstract[i].size != region_budget[i]) {
            return 7u;
        }
    }
    /* Control lives in residual timers+metrics+control capacity. */
    if (out_objects[10].size
        > NINLIL_FABRIC_WS_TIMERS_BYTES + NINLIL_FABRIC_WS_REG_METRICS_BYTES
            + NINLIL_FABRIC_WS_CONTROL_BYTES) {
        return 7u;
    }
    if (out_objects[10].offset < NINLIL_FABRIC_WS_OFF_TIMERS) {
        return 7u;
    }

    /* Sequential non-overlap of non-zero object regions inside workspace. */
    cursor = 0u;
    for (i = 0u; i < 11u; ++i) {
        if (out_objects[i].size == 0u) {
            continue;
        }
        if (out_objects[i].offset < cursor) {
            return 7u; /* overlap or reverse order */
        }
        if (out_objects[i].offset
            > NINLIL_FABRIC_WS_TOTAL_BYTES - out_objects[i].size) {
            return 7u; /* would require loan past workspace end */
        }
        cursor = out_objects[i].offset + out_objects[i].size;
        if (cursor > object_bytes || cursor > NINLIL_FABRIC_WS_TOTAL_BYTES) {
            return 7u;
        }
        object_sum += out_objects[i].size;
    }
    if (object_sum > NINLIL_FABRIC_WS_TOTAL_BYTES
        || object_sum > object_bytes) {
        return 7u;
    }

    /* Codec pair exact; structural body still fits packet region. */
    if (out_objects[1].size != NINLIL_FABRIC_WS_CODEC_SCRATCH_BYTES) {
        return 7u;
    }
    if ((uint32_t)(
            NINLIL_FABRIC_SHARED_QUEUE_MAX
            * NINLIL_FABRIC_NFL1_STRUCTURAL_MAX)
        > NINLIL_FABRIC_WS_NFL1_QUEUE_BYTES) {
        return 7u;
    }

    *out_object_bytes = object_bytes;
    *out_workspace_bytes = NINLIL_FABRIC_WS_TOTAL_BYTES;
    (void)base;
    return 0u;
}
