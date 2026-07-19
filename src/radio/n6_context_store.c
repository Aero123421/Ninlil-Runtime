/*
 * N6 private durable context store — PRODUCTION object only.
 * docs/30 §5.3 / §9 / §20. No fixture/test binder symbols or branches.
 *
 * SEMANTIC: N6_DURABLE_TX_RX_FULL_REQUIRED
 * SEMANTIC: N6_CU_INTERNAL_CLASSIFY
 * SEMANTIC: N6_FULL_OK_BEFORE_RAM_HANDLE
 * SEMANTIC: N6_M4_REQUIRED_WITHOUT_AUTHENTICATED_CAPSULE
 * SEMANTIC: N6_NO_HEAP_NO_VLA
 * SEMANTIC: N6_NO_TEST_SYMBOLS_IN_PRODUCTION
 */

#include "n6_context_store.h"

#include "ninlil/version.h"

#include <string.h>

_Static_assert(
    sizeof(ninlil_n6_local_identity_claim_t) == 24u,
    "local identity claim ABI v1 is exact 24 bytes");

#define N6_MAGIC ((uint32_t)0x4E365354u)
#define N6_CANARY ((uint32_t)0xC4A4A4C4u)

typedef enum n6_cu_phase {
    N6_CU_PHASE_NONE = 0,
    N6_CU_PHASE_NEED_CLOSE_OLD = 1,
    N6_CU_PHASE_NEED_OPEN = 2,
    N6_CU_PHASE_READ_CLASSIFY = 3
} n6_cu_phase_t;

typedef enum n6_cu_op {
    N6_CU_OP_PUT = 1,
    N6_CU_OP_DELETE = 2
} n6_cu_op_t;

typedef enum n6_cu_post {
    N6_CU_POST_NONE = 0,
    N6_CU_POST_INSTALL_HANDLE = 1,
    N6_CU_POST_TX_LIMIT = 2,
    N6_CU_POST_RX_ACCEPT = 3
} n6_cu_post_t;

typedef struct n6_slot {
    uint32_t canary0;
    uint8_t live;
    uint8_t fenced;
    uint8_t layer_code;
    uint8_t direction_code;
    uint8_t alloc_side;
    uint8_t reserved0;
    uint16_t reserved1;
    uint32_t context_id;
    uint64_t membership_epoch;
    uint64_t key_generation;
    uint8_t binding_digest32[32];
    uint8_t traffic_secret32[32];
    uint8_t ns_fingerprint12[12];
    uint8_t local_node_id[16];
    uint8_t receiver_node_id[16];
    /* Durable-covered counter window [ram_next, ram_limit) — one counter per burn */
    uint64_t tx_ram_next[3];
    uint64_t tx_ram_limit[3];
    /* RX sliding-64 (docs/30 §10): RAM-only bitmap; durable live_reserved */
    uint64_t rx_live_reserved[3];
    uint64_t rx_boot_floor[3];
    uint64_t rx_ram_highest[3];
    uint64_t rx_bitmap[3]; /* bit0=ram_highest, bit k = ram_highest-k */
    ninlil_n6_handle_t handle;
    uint32_t canary1;
} n6_slot_t;

/* Boot pack (docs/30 §20.4.1): fits in live slot (304 B). Layout budget:
 * 2×AL(48) + active payload(40) + 4×HW(40) + active meta(8) = 304.
 * Pool capacity: actives ≤C, AL slots ≤2C, HW req slots ≤4C. No casts.
 */
/* Field order chosen for exact sizes under natural alignment (no packed attr). */
typedef struct n6_boot_al {
    uint64_t membership_epoch;
    uint32_t floor;
    uint16_t active_count;
    uint16_t retired_count;
    uint8_t nsfp[12];
    uint8_t receiver_node_id[16];
    uint8_t used;
    uint8_t layer_code;
    uint8_t alloc_side;
    uint8_t pad0;
} n6_boot_al_t;

/*
 * Active payload (exactly 40 B): full binding_digest32 + key_generation.
 * Per-cell meta (exactly 8 B, replaces pad_to_slot): identity not in payload.
 * AL index supplies epoch/layer/side/nsfp/receiver. Pack: 2*48+40+4*40+8=304.
 */
typedef struct n6_boot_active {
    uint8_t binding_digest32[32];
    uint64_t key_generation;
} n6_boot_active_t;

typedef struct n6_boot_active_meta {
    uint32_t context_id;
    uint16_t al_index;
    uint8_t direction_code;
    uint8_t flags; /* b0 used b1 data b2 ack b3 e2e b4 al b5 hw b6 complete b7 cf */
} n6_boot_active_meta_t;

typedef struct n6_boot_hw_req {
    uint64_t min_kgen;
    uint8_t scope28[28];
    uint8_t used;
    uint8_t layer_code;
    uint8_t direction_code;
    uint8_t sat;
} n6_boot_hw_req_t;

typedef struct n6_boot_pack {
    n6_boot_al_t al[2];
    n6_boot_active_t active;
    n6_boot_hw_req_t hw[4];
    n6_boot_active_meta_t active_meta;
} n6_boot_pack_t;

/*
 * Public pool stride: one union cell per slot. Access live via cells[i].live.
 * Forbidden: casting n6_slot_t* to an unrelated boot type.
 */
typedef union n6_pool_cell {
    n6_slot_t live;
    n6_boot_pack_t boot;
} n6_pool_cell_t;

_Static_assert(sizeof(n6_boot_al_t) == 48u, "AL compact ≤48");
_Static_assert(sizeof(n6_boot_active_t) == 40u, "active payload ==40");
_Static_assert(sizeof(n6_boot_active_meta_t) == 8u, "active meta ==8");
_Static_assert(sizeof(n6_boot_hw_req_t) == 40u, "HW req ≤40");
_Static_assert(sizeof(n6_boot_pack_t) == 304u, "boot pack == slot (304)");
_Static_assert(2u * 48u + 40u + 4u * 40u + 8u == 304u, "pack budget exact");
_Static_assert(sizeof(n6_boot_pack_t) == sizeof(n6_slot_t),
    "boot pack size equals live slot");
_Static_assert(sizeof(n6_pool_cell_t) == sizeof(n6_slot_t),
    "pool cell stride equals live slot (public pool byte contract)");
_Static_assert(_Alignof(n6_pool_cell_t) == _Alignof(n6_slot_t),
    "pool cell alignment equals live slot");
_Static_assert(_Alignof(n6_pool_cell_t) <= NINLIL_N6_OBJECT_ALIGN,
    "pool cell align within public pool alignment");

/* C = slot_count ∈ 1..128. Global N6 namespace ceilings (exact). */
/* H+E ≤ C; L=2H+E ≤ 2C; A ≤ 2C; T ≤ 2C; F ≤ C; W ≤ 2A ∧ W ≤ 4C; R ≤ 11C */
/* logical key+value bytes ≤ 876C (C128: 1408 rows / 112128 B; C8: 88 / 7008). */
#define N6_KV_LANE ((uint64_t)116u) /* 48+68 */
#define N6_KV_AL ((uint64_t)80u)    /* 24+56 */
#define N6_KV_RT ((uint64_t)76u)    /* 28+48 */
#define N6_KV_CF ((uint64_t)92u)    /* 28+64 */
#define N6_KV_HW ((uint64_t)60u)    /* 32+28 */
#define N6_BOOT_PASS_COUNT ((uint32_t)4u)
/* iter_next ≤ 4*(11C+1); at C=128 → 5636 */
#define N6_BOOT_ITER_NEXT_BOUND_C(C) \
    (N6_BOOT_PASS_COUNT * ((uint32_t)11u * (uint32_t)(C) + 1u))
#define N6_BOOT_ITER_NEXT_BOUND N6_BOOT_ITER_NEXT_BOUND_C(NINLIL_N6_POOL_MAX_SLOTS)

#define N6_BA_USED ((uint8_t)0x01u)
#define N6_BA_DATA ((uint8_t)0x02u)
#define N6_BA_ACK ((uint8_t)0x04u)
#define N6_BA_E2E ((uint8_t)0x08u)
#define N6_BA_AL ((uint8_t)0x10u)
#define N6_BA_HW ((uint8_t)0x20u)
#define N6_BA_COMPLETE ((uint8_t)0x40u)
#define N6_BA_CF ((uint8_t)0x80u) /* active context fence joined once */

/* Internal immutable RX token — admit/abort use only this, not caller fields. */
typedef struct n6_rx_token {
    uint64_t ticket_id;
    ninlil_n6_handle_t handle;
    uint8_t lane_kind;
    uint8_t layer_code;
    uint8_t direction_code;
    uint8_t live;
    uint32_t context_id;
    uint32_t slot_index;
    uint64_t counter;
    uint8_t key16[16];
    uint8_t iv12[12];
} n6_rx_token_t;

typedef struct n6_cu_entry {
    n6_cu_op_t op;
    n6_cu_post_t post;
    uint32_t slot_index; /* UINT32_MAX if none */
    uint8_t lane_kind;
    uint8_t lane_idx;
    uint8_t reserved0[2];
    uint8_t key[48];
    size_t klen;
    uint8_t old_val[68];
    size_t old_vlen;
    int old_present;
    uint8_t prop_val[68];
    size_t prop_vlen;
    uint64_t post_u64_a; /* e.g. new limit or accept_through */
    uint64_t post_u64_b; /* e.g. new next after reserve */
} n6_cu_entry_t;

typedef struct n6_cu_plan {
    int live;
    n6_cu_phase_t phase;
    uint32_t n_keys;
    n6_cu_entry_t entries[NINLIL_N6_CU_PLAN_MAX_KEYS];
    /* pending install slot material if POST_INSTALL_HANDLE */
    int pending_install;
    n6_slot_t pending_slot;
} n6_cu_plan_t;

/* Boot decode scratch — per-object only (not process-global). */
typedef struct n6_boot_scratch {
    uint8_t kbuf[64];
    uint8_t vbuf[80];
    ninlil_n6_lane_key_t lk;
    ninlil_n6_al_key_t ak;
    ninlil_n6_hw_key_t hk;
    ninlil_n6_rt_key_t rk;
    ninlil_n6_cf_key_t ck;
    union {
        ninlil_n6_tx_value_t tv;
        ninlil_n6_rx_value_t rv;
        ninlil_n6_al_value_t av;
        ninlil_n6_hw_value_t hv;
        ninlil_n6_rt_value_t rtv;
        ninlil_n6_cf_value_t cfv;
    } u;
    uint8_t re_nsfp[12];
    uint8_t want_scope[28];
    /* O(1) previous-key for P0 strict unsigned lexicographic order */
    uint8_t prev_key[48];
    uint8_t prev_klen;
    uint8_t has_prev;
    uint8_t pad_sc[2];
} n6_boot_scratch_t;

struct ninlil_n6 {
    uint32_t magic;
    uint32_t canary0;
    uint32_t reentry;
    ninlil_n6_state_t state;
    ninlil_n6_error_t last_error;
    ninlil_n6_stats_t stats;
    ninlil_storage_ops_t storage;
    int storage_bound;
    ninlil_storage_handle_t storage_handle;
    int storage_open;
    ninlil_n6_crypto_ops_t crypto;
    int crypto_bound;
    int stamp_bound;
    ninlil_n6_authority_stamp_t stamp;
    uint64_t stamp_last_now_ms;
    int local_id_bound;
    uint8_t local_node_id[16];
    ninlil_n6_context_pool_t pool;
    n6_pool_cell_t *cells;
    uint32_t slot_count;
    uint64_t next_handle;
    uint64_t next_lease_id;
    uint64_t next_ticket_id;
    ninlil_n6_tx_lease_t leases[NINLIL_N6_MAX_LIVE_LEASES];
    n6_rx_token_t tickets[NINLIL_N6_MAX_LIVE_TICKETS];
    n6_cu_plan_t cu;
    n6_boot_scratch_t boot_scratch; /* per-object; never file-static */
    uint32_t canary1;
};

_Static_assert(sizeof(struct ninlil_n6) <= NINLIL_N6_OBJECT_BYTES,
    "ninlil_n6_t must fit NINLIL_N6_OBJECT_BYTES");
_Static_assert(sizeof(n6_boot_scratch_t) <= 1024u, "boot scratch bound");
/* size pins for test report - keep as expressions */
enum { N6_SIZEOF_OBJECT_PIN = (int)sizeof(struct ninlil_n6),
       N6_SIZEOF_SCRATCH_PIN = (int)sizeof(n6_boot_scratch_t) };
size_t ninlil_n6_context_pool_bytes(uint32_t max_slots)
{
    if (max_slots < NINLIL_N6_POOL_MIN_SLOTS
        || max_slots > NINLIL_N6_POOL_MAX_SLOTS) {
        return 0u;
    }
    return (size_t)max_slots * sizeof(n6_pool_cell_t);
}

static void n6_set_err(
    ninlil_n6_t *n6, ninlil_n6_status_t st, ninlil_n6_reason_t reason,
    const char *hint)
{
    size_t i;
    if (n6 == NULL) {
        return;
    }
    n6->last_error.status = st;
    n6->last_error.reason = reason;
    n6->last_error.state = n6->state;
    ninlil_n6_secure_zero(n6->last_error.hint, sizeof(n6->last_error.hint));
    if (hint != NULL) {
        for (i = 0u; i + 1u < NINLIL_N6_HINT_BYTES && hint[i] != 0; ++i) {
            n6->last_error.hint[i] = hint[i];
        }
    }
}

static int n6_obj_ok(const ninlil_n6_t *n6)
{
    return n6 != NULL && n6->magic == N6_MAGIC && n6->canary0 == N6_CANARY
        && n6->canary1 == N6_CANARY;
}

static ninlil_n6_status_t n6_enter(ninlil_n6_t *n6)
{
    if (!n6_obj_ok(n6)) {
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    if (n6->state == NINLIL_N6_STATE_SHUTDOWN) {
        n6_set_err(n6, NINLIL_N6_SHUTDOWN, NINLIL_N6_REASON_SHUTDOWN, "shutdown");
        return NINLIL_N6_SHUTDOWN;
    }
    if (n6->reentry != 0u) {
        n6->stats.reentry_reject += 1u;
        n6_set_err(n6, NINLIL_N6_BUSY_REENTRY, NINLIL_N6_REASON_REENTRY, "reentry");
        return NINLIL_N6_BUSY_REENTRY;
    }
    n6->reentry = 1u;
    return NINLIL_N6_OK;
}

static void n6_leave(ninlil_n6_t *n6)
{
    if (n6 != NULL) {
        n6->reentry = 0u;
    }
}

/*
 * Sole FENCED transition (docs/30 §20.3 fence hygiene).
 * Secure-zeros every live/pending traffic_secret32, all leases/tickets, and the
 * complete CU plan (including pending_slot). Marks live slots fenced.
 * Retains object-level bound local identity and storage/crypto provider bindings
 * (read-only continuity). Identity material is zeroed only on shutdown.
 */
static void n6_enter_fenced(ninlil_n6_t *n6)
{
    uint32_t i;
    if (n6 == NULL) {
        return;
    }
    for (i = 0u; i < n6->slot_count; ++i) {
        n6_slot_t *s = &n6->cells[i].live;
        ninlil_n6_secure_zero(s->traffic_secret32, sizeof(s->traffic_secret32));
        if (s->live != 0u) {
            s->fenced = 1u;
        }
    }
    for (i = 0u; i < NINLIL_N6_MAX_LIVE_LEASES; ++i) {
        ninlil_n6_secure_zero(&n6->leases[i], sizeof(n6->leases[i]));
    }
    for (i = 0u; i < NINLIL_N6_MAX_LIVE_TICKETS; ++i) {
        ninlil_n6_secure_zero(&n6->tickets[i], sizeof(n6->tickets[i]));
    }
    /* Full CU plan including pending_slot.traffic_secret32 */
    ninlil_n6_secure_zero(&n6->cu, sizeof(n6->cu));
    n6->state = NINLIL_N6_STATE_FENCED;
    n6->stats.fence_count += 1u;
    /* local_id_bound / local_node_id / storage / crypto retained */
}

static void n6_refresh_bound(ninlil_n6_t *n6)
{
    if (n6->storage_bound != 0 && n6->crypto_bound != 0
        && n6->local_id_bound != 0 && n6->state == NINLIL_N6_STATE_INIT) {
        n6->state = NINLIL_N6_STATE_BOUND;
    }
}


static int n6_ptr_add_ok(uintptr_t base, size_t len, uintptr_t *out_end)
{
    if (len > UINTPTR_MAX - base) {
        return 0;
    }
    *out_end = base + len;
    return 1;
}

static int n6_ranges_disjoint(const void *a, size_t alen, const void *b, size_t blen)
{
    uintptr_t au, bu, ae, be;
    if (alen == 0u || blen == 0u) {
        return 1;
    }
    if (a == NULL || b == NULL) {
        return 0;
    }
    au = (uintptr_t)a;
    bu = (uintptr_t)b;
    if (!n6_ptr_add_ok(au, alen, &ae) || !n6_ptr_add_ok(bu, blen, &be)) {
        return 0;
    }
    return (ae <= bu) || (be <= au);
}

static void n6_cu_clear(n6_cu_plan_t *p)
{
    ninlil_n6_secure_zero(p, sizeof(*p));
}

static void n6_storage_force_close(ninlil_n6_t *n6)
{
    if (n6->storage_open != 0 && n6->storage.close != NULL) {
        n6->storage.close(n6->storage.user, n6->storage_handle);
    }
    n6->storage_open = 0;
    n6->storage_handle = NULL;
}

/* ---- Strict Storage provider adapter (docs/12 §5.3 / docs/30 §9.3, §20.4) ---- */

typedef struct n6_txn {
    ninlil_storage_txn_t h;
    int live;
} n6_txn_t;

/* Immediate fence (no live child txn ownership). */
static void n6_shape_fence(ninlil_n6_t *n6, const char *hint)
{
    n6->stats.storage_fail += 1u;
    n6_enter_fenced(n6);
    n6_set_err(n6, NINLIL_N6_CORRUPT, NINLIL_N6_REASON_CORRUPT,
        hint != NULL ? hint : "shape");
}

/* Record CORRUPT without fence/close — live txn still owned by caller fail path. */
static void n6_note_corrupt(ninlil_n6_t *n6, const char *hint)
{
    n6->stats.storage_fail += 1u;
    n6_set_err(n6, NINLIL_N6_CORRUPT, NINLIL_N6_REASON_CORRUPT,
        hint != NULL ? hint : "shape");
}

static ninlil_n6_status_t n6_open_storage(ninlil_n6_t *n6);
static ninlil_n6_status_t n6_cu_open_storage(ninlil_n6_t *n6);

/* Propagate open_storage: CORRUPT always fences for non-boot / non-CU callers. */
static ninlil_n6_status_t n6_need_storage(ninlil_n6_t *n6)
{
    ninlil_n6_status_t st = n6_open_storage(n6);
    if (st == NINLIL_N6_CORRUPT) {
        if (n6->state != NINLIL_N6_STATE_FENCED) {
            n6_enter_fenced(n6);
        }
    }
    return st;
}

/*
 * rollback: child txn always consumed exactly once. Does NOT close shared handle
 * and does NOT fence — caller's fail/boot/cu helper maps status and owns
 * close→fence order after inspecting the rollback result.
 */
static ninlil_n6_status_t n6_prov_rollback(ninlil_n6_t *n6, n6_txn_t *t)
{
    ninlil_storage_status_t ss;
    if (t == NULL || t->live == 0) {
        return NINLIL_N6_OK;
    }
    t->live = 0;
    ss = n6->storage.rollback(n6->storage.user, t->h);
    t->h = NULL;
    if (ss == NINLIL_STORAGE_OK) {
        return NINLIL_N6_OK;
    }
    if (ss == NINLIL_STORAGE_IO_ERROR || ss == NINLIL_STORAGE_BUSY) {
        n6->stats.storage_fail += 1u;
        n6_set_err(n6, NINLIL_N6_STORAGE, NINLIL_N6_REASON_STORAGE, "rb");
        return NINLIL_N6_STORAGE;
    }
    /* NO_SPACE/BTS/NOT_FOUND/CORRUPT/COMMIT_UNKNOWN/UNSUPPORTED/unknown */
    n6->stats.storage_fail += 1u;
    n6_set_err(n6, NINLIL_N6_CORRUPT, NINLIL_N6_REASON_CORRUPT, "rb");
    return NINLIL_N6_CORRUPT;
}

/*
 * begin: preseed NULL. OK+nonnull only. OK+NULL/unknown/nonOK+nonnull → CORRUPT
 * (nonnull consumed via rollback once + inspect). BUSY/IO → STORAGE; NO_SPACE/BTS → CAPACITY.
 */
static ninlil_n6_status_t n6_prov_begin(
    ninlil_n6_t *n6, ninlil_storage_mode_t mode, n6_txn_t *t)
{
    ninlil_storage_status_t ss;
    if (t == NULL) {
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    t->h = NULL;
    t->live = 0;
    ss = n6->storage.begin(n6->storage.user, n6->storage_handle, mode, &t->h);
    if (ss != NINLIL_STORAGE_OK) {
        if (t->h != NULL) {
            ninlil_storage_status_t rbs =
                n6->storage.rollback(n6->storage.user, t->h);
            t->h = NULL;
            if (rbs != NINLIL_STORAGE_OK) {
                n6_storage_force_close(n6);
            } else {
                n6_storage_force_close(n6);
            }
            n6_shape_fence(n6, "begin");
            return NINLIL_N6_CORRUPT;
        }
        if (ss == NINLIL_STORAGE_IO_ERROR || ss == NINLIL_STORAGE_BUSY) {
            n6->stats.storage_fail += 1u;
            n6_set_err(n6, NINLIL_N6_STORAGE, NINLIL_N6_REASON_STORAGE, "begin");
            return NINLIL_N6_STORAGE;
        }
        if (ss == NINLIL_STORAGE_NO_SPACE
            || ss == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
            n6->stats.storage_fail += 1u;
            n6_set_err(n6, NINLIL_N6_CAPACITY, NINLIL_N6_REASON_CAPACITY, "begin");
            return NINLIL_N6_CAPACITY;
        }
        n6_shape_fence(n6, "begin");
        return NINLIL_N6_CORRUPT;
    }
    if (t->h == NULL) {
        n6_shape_fence(n6, "begin_null");
        return NINLIL_N6_CORRUPT;
    }
    t->live = 1;
    return NINLIL_N6_OK;
}

#define N6_GET_ALLOW_MISS 1
#define N6_GET_REQUIRE_PRESENT 0

/*
 * get: N6 fixed-length record read. pointer/cap immutable; full-buffer sentinel.
 * allow_miss: NOT_FOUND ok; else NOT_FOUND → CORRUPT.
 * BUFFER_TOO_SMALL and NO_SPACE are always provider contract violations → CORRUPT
 * (never CAPACITY). CORRUPT does not fence here: caller fail helper rollbacks
 * child txn, then force-close + fence.
 * Returns OK / NOT_FOUND (miss allowed) / STORAGE / CORRUPT.
 */
static ninlil_n6_status_t n6_prov_get(
    ninlil_n6_t *n6,
    n6_txn_t *t,
    ninlil_bytes_view_t key,
    uint8_t *buf,
    uint32_t cap,
    uint32_t *out_len,
    int allow_miss)
{
    ninlil_mut_bytes_t vb;
    ninlil_storage_status_t ss;
    uint8_t *data_pre;
    uint32_t cap_pre;
    uint32_t i;
    const uint8_t sent = 0xA5u;

    if (out_len != NULL) {
        *out_len = 0u;
    }
    if (t == NULL || t->live == 0 || buf == NULL || cap == 0u) {
        n6_note_corrupt(n6, "get_arg");
        return NINLIL_N6_CORRUPT;
    }
    for (i = 0u; i < cap; ++i) {
        buf[i] = sent;
    }
    data_pre = buf;
    cap_pre = cap;
    vb.data = buf;
    vb.capacity = cap;
    vb.length = 0u;
    ss = n6->storage.get(n6->storage.user, t->h, key, &vb);
    if (vb.data != data_pre || vb.capacity != cap_pre) {
        n6_note_corrupt(n6, "get_ptr");
        return NINLIL_N6_CORRUPT;
    }
    if (ss == NINLIL_STORAGE_OK) {
        if (vb.length == 0u || vb.length > cap) {
            n6_note_corrupt(n6, "get_len");
            return NINLIL_N6_CORRUPT;
        }
        for (i = vb.length; i < cap; ++i) {
            if (buf[i] != sent) {
                n6_note_corrupt(n6, "get_tail");
                return NINLIL_N6_CORRUPT;
            }
        }
        if (out_len != NULL) {
            *out_len = vb.length;
        }
        return NINLIL_N6_OK;
    }
    if (ss == NINLIL_STORAGE_NOT_FOUND) {
        if (vb.length != 0u) {
            n6_note_corrupt(n6, "get_miss");
            return NINLIL_N6_CORRUPT;
        }
        for (i = 0u; i < cap; ++i) {
            if (buf[i] != sent) {
                n6_note_corrupt(n6, "get_miss");
                return NINLIL_N6_CORRUPT;
            }
        }
        if (allow_miss == 0) {
            n6_note_corrupt(n6, "get_req");
            return NINLIL_N6_CORRUPT;
        }
        return NINLIL_N6_NOT_FOUND;
    }
    /*
     * Fixed-length N6 records: BTS is always contract violation (never CAPACITY),
     * any length/sentinel/shape still ends CORRUPT for the fail helper.
     */
    if (ss == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
        for (i = 0u; i < cap; ++i) {
            if (buf[i] != sent) {
                n6_note_corrupt(n6, "get_bts");
                return NINLIL_N6_CORRUPT;
            }
        }
        n6_note_corrupt(n6, "get_bts");
        return NINLIL_N6_CORRUPT;
    }
    if (ss == NINLIL_STORAGE_IO_ERROR || ss == NINLIL_STORAGE_BUSY) {
        if (vb.length != 0u) {
            n6_note_corrupt(n6, "get_err");
            return NINLIL_N6_CORRUPT;
        }
        for (i = 0u; i < cap; ++i) {
            if (buf[i] != sent) {
                n6_note_corrupt(n6, "get_err");
                return NINLIL_N6_CORRUPT;
            }
        }
        n6->stats.storage_fail += 1u;
        n6_set_err(n6, NINLIL_N6_STORAGE, NINLIL_N6_REASON_STORAGE, "get");
        return NINLIL_N6_STORAGE;
    }
    /*
     * NO_SPACE on fixed-length get is contract violation (never CAPACITY).
     * Full-buffer sentinel must remain intact for any form.
     */
    if (ss == NINLIL_STORAGE_NO_SPACE) {
        if (vb.length != 0u) {
            n6_note_corrupt(n6, "get_ns");
            return NINLIL_N6_CORRUPT;
        }
        for (i = 0u; i < cap; ++i) {
            if (buf[i] != sent) {
                n6_note_corrupt(n6, "get_ns");
                return NINLIL_N6_CORRUPT;
            }
        }
        n6_note_corrupt(n6, "get_ns");
        return NINLIL_N6_CORRUPT;
    }
    /* COMMIT_UNKNOWN / CORRUPT / UNSUPPORTED / unknown on get */
    n6_note_corrupt(n6, "get_unk");
    return NINLIL_N6_CORRUPT;
}

/* put: closed-map; unexpected statuses → CORRUPT (fence via fail helper). */
static ninlil_n6_status_t n6_prov_put(
    ninlil_n6_t *n6, n6_txn_t *t, ninlil_bytes_view_t key, ninlil_bytes_view_t val)
{
    ninlil_storage_status_t ss;
    if (t == NULL || t->live == 0) {
        n6_note_corrupt(n6, "put");
        return NINLIL_N6_CORRUPT;
    }
    ss = n6->storage.put(n6->storage.user, t->h, key, val);
    if (ss == NINLIL_STORAGE_OK) {
        return NINLIL_N6_OK;
    }
    if (ss == NINLIL_STORAGE_NO_SPACE) {
        n6->stats.storage_fail += 1u;
        n6_set_err(n6, NINLIL_N6_CAPACITY, NINLIL_N6_REASON_CAPACITY, "put");
        return NINLIL_N6_CAPACITY;
    }
    if (ss == NINLIL_STORAGE_IO_ERROR || ss == NINLIL_STORAGE_BUSY) {
        n6->stats.storage_fail += 1u;
        n6_set_err(n6, NINLIL_N6_STORAGE, NINLIL_N6_REASON_STORAGE, "put");
        return NINLIL_N6_STORAGE;
    }
    /* NOT_FOUND/BTS/UNSUPPORTED/COMMIT_UNKNOWN/unknown/CORRUPT */
    n6_note_corrupt(n6, "put");
    return NINLIL_N6_CORRUPT;
}

static ninlil_n6_status_t n6_prov_erase(
    ninlil_n6_t *n6, n6_txn_t *t, ninlil_bytes_view_t key)
    __attribute__((unused));
static ninlil_n6_status_t n6_prov_erase(
    ninlil_n6_t *n6, n6_txn_t *t, ninlil_bytes_view_t key)
{
    ninlil_storage_status_t ss;
    if (t == NULL || t->live == 0) {
        n6_note_corrupt(n6, "erase");
        return NINLIL_N6_CORRUPT;
    }
    ss = n6->storage.erase(n6->storage.user, t->h, key);
    if (ss == NINLIL_STORAGE_OK || ss == NINLIL_STORAGE_NOT_FOUND) {
        return NINLIL_N6_OK; /* erase miss is ok for some plans; N6 install rarely erase */
    }
    if (ss == NINLIL_STORAGE_NO_SPACE) {
        n6->stats.storage_fail += 1u;
        n6_set_err(n6, NINLIL_N6_CAPACITY, NINLIL_N6_REASON_CAPACITY, "erase");
        return NINLIL_N6_CAPACITY;
    }
    if (ss == NINLIL_STORAGE_IO_ERROR || ss == NINLIL_STORAGE_BUSY) {
        n6->stats.storage_fail += 1u;
        n6_set_err(n6, NINLIL_N6_STORAGE, NINLIL_N6_REASON_STORAGE, "erase");
        return NINLIL_N6_STORAGE;
    }
    n6_note_corrupt(n6, "erase");
    return NINLIL_N6_CORRUPT;
}

/*
 * commit: txn always consumed; never rollback after. OK=ok.
 * COMMIT_UNKNOWN: state=CU_PENDING, phase=NEED_CLOSE_OLD, handle STILL OPEN
 * (recover_cu closes exactly once). Definite fail: clear CU, no rollback.
 * CORRUPT/unexpected: clear CU + fence (txn already consumed).
 */
static ninlil_n6_status_t n6_prov_commit(ninlil_n6_t *n6, n6_txn_t *t)
{
    ninlil_storage_status_t ss;
    if (t == NULL || t->live == 0) {
        n6_shape_fence(n6, "commit");
        return NINLIL_N6_CORRUPT;
    }
    t->live = 0;
    ss = n6->storage.commit(n6->storage.user, t->h, NINLIL_DURABILITY_FULL);
    t->h = NULL;
    if (ss == NINLIL_STORAGE_OK) {
        n6_cu_clear(&n6->cu);
        return NINLIL_N6_OK;
    }
    if (ss == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        n6->stats.commit_unknown += 1u;
        /* Do NOT close storage here — NEED_CLOSE_OLD owns the single close. */
        n6->state = NINLIL_N6_STATE_CU_PENDING;
        n6->cu.phase = N6_CU_PHASE_NEED_CLOSE_OLD;
        n6_set_err(n6, NINLIL_N6_COMMIT_UNKNOWN, NINLIL_N6_REASON_COMMIT_UNKNOWN,
            "FULL_CU");
        return NINLIL_N6_COMMIT_UNKNOWN;
    }
    if (ss == NINLIL_STORAGE_NO_SPACE) {
        n6->stats.storage_fail += 1u;
        n6_cu_clear(&n6->cu);
        n6_set_err(n6, NINLIL_N6_CAPACITY, NINLIL_N6_REASON_CAPACITY, "commit");
        return NINLIL_N6_CAPACITY;
    }
    if (ss == NINLIL_STORAGE_IO_ERROR || ss == NINLIL_STORAGE_BUSY) {
        n6->stats.storage_fail += 1u;
        n6_cu_clear(&n6->cu);
        n6_set_err(n6, NINLIL_N6_STORAGE, NINLIL_N6_REASON_STORAGE, "commit");
        return NINLIL_N6_STORAGE;
    }
    /* CORRUPT / NOT_FOUND / BTS / UNSUPPORTED / unknown — no rollback after commit */
    n6->stats.storage_fail += 1u;
    n6_cu_clear(&n6->cu);
    n6_enter_fenced(n6);
    n6_set_err(n6, NINLIL_N6_CORRUPT, NINLIL_N6_REASON_CORRUPT, "commit");
    return NINLIL_N6_CORRUPT;
}

/*
 * Fail path ownership: rollback child txn → inspect → on CORRUPT/rb-fail
 * force-close shared handle then fence. Operational STORAGE/CAPACITY leave
 * handle open for retry. clear_cu on definite non-CU failures.
 */
static ninlil_n6_status_t n6_prov_fail(
    ninlil_n6_t *n6, n6_txn_t *t, ninlil_n6_status_t st, int clear_cu)
{
    ninlil_n6_status_t rbs = n6_prov_rollback(n6, t);
    if (clear_cu != 0 && st != NINLIL_N6_COMMIT_UNKNOWN) {
        n6_cu_clear(&n6->cu);
    }
    if (rbs != NINLIL_N6_OK) {
        n6_storage_force_close(n6);
        if (n6->state != NINLIL_N6_STATE_FENCED) {
            n6_enter_fenced(n6);
        }
        n6_set_err(n6, NINLIL_N6_CORRUPT, NINLIL_N6_REASON_CORRUPT, "rb");
        return NINLIL_N6_CORRUPT;
    }
    if (st == NINLIL_N6_CORRUPT) {
        n6_storage_force_close(n6);
        if (n6->state != NINLIL_N6_STATE_FENCED) {
            n6_enter_fenced(n6);
        }
        return NINLIL_N6_CORRUPT;
    }
    return st;
}


static ninlil_n6_status_t n6_validate_ops(const ninlil_storage_ops_t *ops)
{
    uint16_t abi;
    uint16_t sz;
    if (ops == NULL) {
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    /* Header first — never touch function pointers until size bounds hold. */
    abi = ops->abi_version;
    sz = ops->struct_size;
    if (abi != NINLIL_ABI_VERSION) {
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    if (sz < (uint16_t)sizeof(ninlil_storage_ops_t)) {
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    if (ops->open == NULL || ops->close == NULL || ops->begin == NULL
        || ops->get == NULL || ops->put == NULL || ops->commit == NULL
        || ops->rollback == NULL || ops->capacity == NULL
        || ops->iter_open == NULL || ops->iter_next == NULL
        || ops->iter_close == NULL || ops->erase == NULL) {
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    return NINLIL_N6_OK;
}

/* Map storage status to N6 closed set — retained for rare non-adapter paths. */
static ninlil_n6_status_t n6_map_storage_status(ninlil_storage_status_t ss)
    __attribute__((unused));
static ninlil_n6_status_t n6_map_storage_status(ninlil_storage_status_t ss)
{
    if (ss == NINLIL_STORAGE_OK) {
        return NINLIL_N6_OK;
    }
    if (ss == NINLIL_STORAGE_NOT_FOUND) {
        return NINLIL_N6_NOT_FOUND;
    }
    if (ss == NINLIL_STORAGE_NO_SPACE || ss == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
        return NINLIL_N6_CAPACITY;
    }
    if (ss == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        return NINLIL_N6_COMMIT_UNKNOWN;
    }
    if (ss == NINLIL_STORAGE_CORRUPT) {
        return NINLIL_N6_CORRUPT;
    }
    return NINLIL_N6_STORAGE;
}

static ninlil_n6_status_t n6_id_alloc(uint64_t *next_id, uint64_t *out_id)
{
    if (next_id == NULL || out_id == NULL) {
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    if (*next_id == 0u || *next_id == UINT64_MAX) {
        /* wrap / zero: fail-closed, never reuse 1 */
        return NINLIL_N6_CAPACITY;
    }
    *out_id = *next_id;
    *next_id += 1u;
    if (*next_id == 0u) {
        /* would wrap on next call — mark exhausted */
        *next_id = UINT64_MAX;
    }
    return NINLIL_N6_OK;
}

/*
 * Strict capacity provider shape (shared by open and install admission).
 * Preseed: exact ABI header + zero numerics.
 * OK: exact abi_version/struct_size, max_entries>0, max_bytes>0, used<=max.
 * non-OK: header must remain preseed, numerics all zero (else poison→CORRUPT);
 *   known IO_ERROR/BUSY→STORAGE; NO_SPACE/BTS→CAPACITY; unknown→CORRUPT.
 * Fills *out only on OK. Does not close the storage handle.
 */
static ninlil_n6_status_t n6_storage_capacity_query(
    ninlil_n6_t *n6, ninlil_storage_capacity_t *out, const char *hint)
{
    ninlil_storage_capacity_t cap;
    ninlil_storage_status_t ss;
    const uint16_t want_abi = NINLIL_ABI_VERSION;
    const uint16_t want_sz = (uint16_t)sizeof(ninlil_storage_capacity_t);

    if (out != NULL) {
        ninlil_n6_secure_zero(out, sizeof(*out));
    }
    ninlil_n6_secure_zero(&cap, sizeof(cap));
    cap.abi_version = want_abi;
    cap.struct_size = want_sz;
    ss = n6->storage.capacity(n6->storage.user, n6->storage_handle, &cap);
    if (ss != NINLIL_STORAGE_OK) {
        int hdr_ok = (cap.abi_version == want_abi && cap.struct_size == want_sz);
        int nums_zero = (cap.max_entries == 0u && cap.used_entries == 0u
            && cap.max_bytes == 0u && cap.used_bytes == 0u);
        if (hdr_ok == 0 || nums_zero == 0) {
            n6->stats.storage_fail += 1u;
            n6_set_err(n6, NINLIL_N6_CORRUPT, NINLIL_N6_REASON_CORRUPT, "cap_shape");
            return NINLIL_N6_CORRUPT;
        }
        if (ss == NINLIL_STORAGE_IO_ERROR || ss == NINLIL_STORAGE_BUSY) {
            n6->stats.storage_fail += 1u;
            n6_set_err(n6, NINLIL_N6_STORAGE, NINLIL_N6_REASON_STORAGE,
                hint != NULL ? hint : "capacity");
            return NINLIL_N6_STORAGE;
        }
        if (ss == NINLIL_STORAGE_NO_SPACE
            || ss == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
            n6->stats.storage_fail += 1u;
            n6_set_err(n6, NINLIL_N6_CAPACITY, NINLIL_N6_REASON_CAPACITY,
                hint != NULL ? hint : "capacity");
            return NINLIL_N6_CAPACITY;
        }
        n6->stats.storage_fail += 1u;
        n6_set_err(n6, NINLIL_N6_CORRUPT, NINLIL_N6_REASON_CORRUPT,
            hint != NULL ? hint : "capacity");
        return NINLIL_N6_CORRUPT;
    }
    if (cap.abi_version != want_abi || cap.struct_size != want_sz
        || cap.max_entries == 0u || cap.max_bytes == 0u
        || cap.used_entries > cap.max_entries
        || cap.used_bytes > cap.max_bytes) {
        n6->stats.storage_fail += 1u;
        n6_set_err(n6, NINLIL_N6_CORRUPT, NINLIL_N6_REASON_CORRUPT, "cap_abi");
        return NINLIL_N6_CORRUPT;
    }
    if (out != NULL) {
        *out = cap;
    }
    return NINLIL_N6_OK;
}

/*
 * Install-only capacity admission (HOP=4 / E2E=3 free entries worst case).
 * Provider shape CORRUPT / unknown / OK-malformed → close open handle + FENCE.
 * Operational IO/BUSY and legitimate insufficient free stay non-fence.
 */
static ninlil_n6_status_t n6_require_install_capacity(
    ninlil_n6_t *n6, uint32_t need_free)
{
    ninlil_storage_capacity_t cap;
    ninlil_n6_status_t st;
    if (n6->storage_open == 0) {
        return NINLIL_N6_STORAGE;
    }
    st = n6_storage_capacity_query(n6, &cap, "install");
    if (st == NINLIL_N6_CORRUPT) {
        n6_storage_force_close(n6);
        if (n6->state != NINLIL_N6_STATE_FENCED) {
            n6_enter_fenced(n6);
        }
        return NINLIL_N6_CORRUPT;
    }
    if (st != NINLIL_N6_OK) {
        /* STORAGE (IO/BUSY) or CAPACITY (provider clean NO_SPACE/BTS) — no fence */
        return st;
    }
    if (cap.used_entries > cap.max_entries
        || (cap.max_entries - cap.used_entries) < (uint64_t)need_free
        || cap.max_bytes < 512u) {
        n6_set_err(n6, NINLIL_N6_CAPACITY, NINLIL_N6_REASON_CAPACITY, "install");
        return NINLIL_N6_CAPACITY;
    }
    return NINLIL_N6_OK;
}

/*
 * CU recovery NEED_OPEN: dedicated open map (not n6_need_storage).
 * non-OK+NULL: BUSY/IO → retryable STORAGE (handle stays closed).
 * NO_SPACE/BTS/NOT_FOUND/CORRUPT/COMMIT_UNKNOWN/UNSUPPORTED/unknown,
 * OK+NULL, non-OK+nonnull → close once if needed + FENCED/CORRUPT.
 */
static ninlil_n6_status_t n6_cu_open_storage(ninlil_n6_t *n6)
{
    ninlil_storage_status_t ss;
    static const uint8_t ns[12] = {
        'n', 'i', 'n', 'l', 'i', 'l', '.', 'n', '6', '.', 'v', '1'
    };
    ninlil_bytes_view_t nv;

    if (n6->storage_open != 0) {
        return NINLIL_N6_OK;
    }
    nv.data = ns;
    nv.length = 12u;
    n6->storage_handle = NULL;
    ss = n6->storage.open(
        n6->storage.user, nv, NINLIL_N6_STORAGE_SCHEMA, &n6->storage_handle);
    if (ss != NINLIL_STORAGE_OK) {
        if (n6->storage_handle != NULL) {
            n6->storage.close(n6->storage.user, n6->storage_handle);
            n6->storage_handle = NULL;
            n6_shape_fence(n6, "cu_open");
            return NINLIL_N6_CORRUPT;
        }
        if (ss == NINLIL_STORAGE_IO_ERROR || ss == NINLIL_STORAGE_BUSY) {
            n6->stats.storage_fail += 1u;
            n6_set_err(n6, NINLIL_N6_STORAGE, NINLIL_N6_REASON_STORAGE, "cu_open");
            return NINLIL_N6_STORAGE;
        }
        /* NO_SPACE/BTS/NOT_FOUND/CORRUPT/COMMIT_UNKNOWN/UNSUPPORTED/unknown */
        n6_shape_fence(n6, "cu_open");
        return NINLIL_N6_CORRUPT;
    }
    if (n6->storage_handle == NULL) {
        n6_shape_fence(n6, "cu_open_null");
        return NINLIL_N6_CORRUPT;
    }
    n6->storage_open = 1;
    return NINLIL_N6_OK;
}

/*
 * Open storage: strict provider-shape closed set (docs/30 §20.4.1 style).
 * open: preseed *out_handle=NULL; only OK+nonnull continues.
 * non-OK+nonnull → close once → CORRUPT. OK+NULL / unknown → CORRUPT.
 * Known non-OK+NULL → operational STORAGE/CAPACITY.
 * capacity via n6_storage_capacity_query; close handle on every capacity failure.
 */
static ninlil_n6_status_t n6_open_storage(ninlil_n6_t *n6)
{
    ninlil_storage_status_t ss;
    static const uint8_t ns[12] = {
        'n', 'i', 'n', 'l', 'i', 'l', '.', 'n', '6', '.', 'v', '1'
    };
    ninlil_bytes_view_t nv;
    ninlil_storage_capacity_t cap;
    ninlil_n6_status_t cst;

    if (n6->storage_open != 0) {
        return NINLIL_N6_OK;
    }
    nv.data = ns;
    nv.length = 12u;
    n6->storage_handle = NULL; /* preseed out_handle NULL */
    ss = n6->storage.open(
        n6->storage.user, nv, NINLIL_N6_STORAGE_SCHEMA, &n6->storage_handle);
    if (ss != NINLIL_STORAGE_OK) {
        if (n6->storage_handle != NULL) {
            n6->storage.close(n6->storage.user, n6->storage_handle);
            n6->storage_handle = NULL;
            n6->stats.storage_fail += 1u;
            n6_set_err(n6, NINLIL_N6_CORRUPT, NINLIL_N6_REASON_CORRUPT, "open");
            return NINLIL_N6_CORRUPT;
        }
        if (ss == NINLIL_STORAGE_IO_ERROR || ss == NINLIL_STORAGE_BUSY) {
            n6->stats.storage_fail += 1u;
            n6_set_err(n6, NINLIL_N6_STORAGE, NINLIL_N6_REASON_STORAGE, "open");
            return NINLIL_N6_STORAGE;
        }
        if (ss == NINLIL_STORAGE_NO_SPACE
            || ss == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
            n6->stats.storage_fail += 1u;
            n6_set_err(n6, NINLIL_N6_CAPACITY, NINLIL_N6_REASON_CAPACITY, "open");
            return NINLIL_N6_CAPACITY;
        }
        n6->stats.storage_fail += 1u;
        n6_set_err(n6, NINLIL_N6_CORRUPT, NINLIL_N6_REASON_CORRUPT, "open");
        return NINLIL_N6_CORRUPT;
    }
    if (n6->storage_handle == NULL) {
        n6->stats.storage_fail += 1u;
        n6_set_err(n6, NINLIL_N6_CORRUPT, NINLIL_N6_REASON_CORRUPT, "open_null");
        return NINLIL_N6_CORRUPT;
    }

    cst = n6_storage_capacity_query(n6, &cap, "capacity");
    if (cst != NINLIL_N6_OK) {
        n6->storage.close(n6->storage.user, n6->storage_handle);
        n6->storage_handle = NULL;
        n6->storage_open = 0;
        return cst;
    }
    n6->storage_open = 1;
    return NINLIL_N6_OK;
}



int ninlil_n6_esp_ready(void)
{
    return 0;
}

ninlil_n6_state_t ninlil_n6_state(const ninlil_n6_t *n6)
{
    if (!n6_obj_ok(n6)) {
        return NINLIL_N6_STATE_UNINIT;
    }
    return n6->state;
}

ninlil_n6_status_t ninlil_n6_init(
    void *obj_bytes, size_t obj_size, ninlil_n6_context_pool_t *pool,
    ninlil_n6_t **out_n6)
{
    ninlil_n6_t *n6;
    size_t need;
    uintptr_t oe;
    uintptr_t pe;

    if (out_n6 == NULL || obj_bytes == NULL || pool == NULL
        || pool->bytes == NULL || pool->reserved_zero != 0u) {
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    need = ninlil_n6_context_pool_bytes(pool->max_slots);
    if (need == 0u || pool->bytes_size < need) {
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    if (obj_size < sizeof(ninlil_n6_t)
        || ((uintptr_t)obj_bytes % NINLIL_N6_OBJECT_ALIGN) != 0u) {
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    if (((uintptr_t)pool->bytes % NINLIL_N6_OBJECT_ALIGN) != 0u) {
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    if (!n6_ptr_add_ok((uintptr_t)obj_bytes, obj_size, &oe)
        || !n6_ptr_add_ok((uintptr_t)pool->bytes, pool->bytes_size, &pe)) {
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    /* Full alias matrix: obj ↔ pool_bytes ↔ pool struct ↔ out_n6 */
    if (!n6_ranges_disjoint(obj_bytes, obj_size, pool->bytes, pool->bytes_size)
        || !n6_ranges_disjoint(obj_bytes, obj_size, pool, sizeof(*pool))
        || !n6_ranges_disjoint(pool->bytes, pool->bytes_size, pool, sizeof(*pool))
        || !n6_ranges_disjoint(obj_bytes, obj_size, out_n6, sizeof(*out_n6))
        || !n6_ranges_disjoint(pool->bytes, pool->bytes_size, out_n6, sizeof(*out_n6))
        || !n6_ranges_disjoint(pool, sizeof(*pool), out_n6, sizeof(*out_n6))) {
        return NINLIL_N6_ALIAS;
    }
    ninlil_n6_secure_zero(obj_bytes, obj_size);
    ninlil_n6_secure_zero(pool->bytes, pool->bytes_size);
    n6 = (ninlil_n6_t *)obj_bytes;
    n6->magic = N6_MAGIC;
    n6->canary0 = N6_CANARY;
    n6->canary1 = N6_CANARY;
    n6->state = NINLIL_N6_STATE_INIT;
    n6->pool = *pool;
    n6->cells = (n6_pool_cell_t *)pool->bytes;
    n6->slot_count = pool->max_slots;
    /* Every cell: canaries on .live; free = live0 with valid canaries. */
    {
        uint32_t si;
        for (si = 0u; si < n6->slot_count; ++si) {
            ninlil_n6_secure_zero(&n6->cells[si], sizeof(n6->cells[si]));
            n6->cells[si].live.canary0 = N6_CANARY;
            n6->cells[si].live.canary1 = N6_CANARY;
            n6->cells[si].live.live = 0u;
        }
    }
    n6->next_handle = 1u;
    n6->next_lease_id = 1u;
    n6->next_ticket_id = 1u;
    *out_n6 = n6;
    return NINLIL_N6_OK;
}

ninlil_n6_status_t ninlil_n6_bind_storage(
    ninlil_n6_t *n6, const ninlil_storage_ops_t *ops)
{
    ninlil_n6_status_t st = n6_enter(n6);
    if (st != NINLIL_N6_OK) {
        return st;
    }
    /* One-shot: successful bind cannot be replaced (even identical). */
    if (n6->storage_bound != 0 || n6->state != NINLIL_N6_STATE_INIT) {
        n6_set_err(n6, NINLIL_N6_INVALID_STATE, NINLIL_N6_REASON_STATE, "storage_once");
        n6_leave(n6);
        return NINLIL_N6_INVALID_STATE;
    }
    if (n6_validate_ops(ops) != NINLIL_N6_OK) {
        n6_set_err(n6, NINLIL_N6_INVALID_ARGUMENT, NINLIL_N6_REASON_NULL, "ops");
        n6_leave(n6);
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    /* Copy ops only — open/close call count 0. */
    n6->storage = *ops;
    n6->storage_bound = 1;
    n6_refresh_bound(n6);
    n6_leave(n6);
    return NINLIL_N6_OK;
}

ninlil_n6_status_t ninlil_n6_bind_crypto(
    ninlil_n6_t *n6, const ninlil_n6_crypto_ops_t *ops)
{
    ninlil_n6_status_t st = n6_enter(n6);
    if (st != NINLIL_N6_OK) {
        return st;
    }
    if (n6->crypto_bound != 0 || n6->state != NINLIL_N6_STATE_INIT) {
        n6_set_err(n6, NINLIL_N6_INVALID_STATE, NINLIL_N6_REASON_STATE, "crypto_once");
        n6_leave(n6);
        return NINLIL_N6_INVALID_STATE;
    }
    if (ops == NULL || ops->sha256 == NULL || ops->hkdf_sha256 == NULL) {
        n6_leave(n6);
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    /* Copy ops only — hash/HKDF call count 0. */
    n6->crypto = *ops;
    n6->crypto_bound = 1;
    n6_refresh_bound(n6);
    n6_leave(n6);
    return NINLIL_N6_OK;
}

/*
 * Production: R2 accepted-token verifier is not implemented → fail-closed.
 * NINLIL_N6_TEST_BUILD only: accept typed fixture stamp (epoch/trust/regression).
 */
ninlil_n6_status_t ninlil_n6_bind_authority_stamp(
    ninlil_n6_t *n6, const ninlil_n6_authority_stamp_t *stamp)
{
    ninlil_n6_status_t st = n6_enter(n6);
    if (st != NINLIL_N6_OK) {
        return st;
    }
#if !defined(NINLIL_N6_TEST_BUILD)
    (void)stamp;
    n6_set_err(n6, NINLIL_N6_M4_REQUIRED, NINLIL_N6_REASON_STAMP, "no_r2_verifier");
    n6_leave(n6);
    return NINLIL_N6_M4_REQUIRED;
#else
    size_t i;
    int all0;
    if (stamp == NULL) {
        n6_leave(n6);
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    if (stamp->trusted_class_d != 1u || stamp->reserved0 != 0u) {
        n6_set_err(n6, NINLIL_N6_INVALID_ARGUMENT, NINLIL_N6_REASON_STAMP, "trust");
        n6_leave(n6);
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    all0 = 1;
    for (i = 0u; i < 16u; ++i) {
        if (stamp->clock_epoch_id[i] != 0u) {
            all0 = 0;
            break;
        }
    }
    if (all0 != 0) {
        n6_leave(n6);
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    if (n6->stamp_bound != 0) {
        if (memcmp(n6->stamp.clock_epoch_id, stamp->clock_epoch_id, 16u) != 0) {
            n6_leave(n6);
            return NINLIL_N6_INVALID_ARGUMENT;
        }
        if (stamp->now_ms < n6->stamp_last_now_ms) {
            n6_leave(n6);
            return NINLIL_N6_INVALID_ARGUMENT;
        }
    }
    n6->stamp = *stamp;
    n6->stamp_last_now_ms = stamp->now_ms;
    n6->stamp_bound = 1;
    n6_leave(n6);
    return NINLIL_N6_OK;
#endif
}

/*
 * Sole production local-identity binder (docs/30 §20.4.1 exact ABI).
 */
ninlil_n6_status_t ninlil_n6_bind_local_identity_accepted(
    ninlil_n6_t *n6,
    const ninlil_n6_local_identity_ops_t *ops,
    ninlil_n6_accepted_local_identity_token_t *mutable_token)
{
    ninlil_n6_status_t st;
    ninlil_n6_local_identity_claim_t claim;
    ninlil_n6_local_identity_accept_status_t acc;
    size_t i;
    int all0;

    st = n6_enter(n6);
    if (st != NINLIL_N6_OK) {
        return st;
    }
    /* Second bind / wrong lifecycle: callback 0; token unconsumed */
    if (n6->state != NINLIL_N6_STATE_INIT || n6->local_id_bound != 0) {
        n6_set_err(n6, NINLIL_N6_INVALID_STATE, NINLIL_N6_REASON_STATE, "id_once");
        n6_leave(n6);
        return NINLIL_N6_INVALID_STATE;
    }
    if (ops == NULL || mutable_token == NULL) {
        n6_set_err(n6, NINLIL_N6_INVALID_ARGUMENT, NINLIL_N6_REASON_LOCAL_IDENTITY,
            "id_ops");
        n6_leave(n6);
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    /*
     * Staged ops ABI parse (exact size): header only before user/consume.
     * Undersize/oversize reject with callback 0 (ASan-safe on partial provider).
     */
    {
        uint16_t ops_abi = ops->abi_version;
        uint16_t ops_sz = ops->struct_size;
        uint32_t ops_rz = ops->reserved_zero;
        if (ops_abi != NINLIL_N6_LOCAL_ID_OPS_ABI
            || ops_sz != (uint16_t)sizeof(ninlil_n6_local_identity_ops_t)
            || ops_rz != 0u) {
            n6_set_err(n6, NINLIL_N6_INVALID_ARGUMENT,
                NINLIL_N6_REASON_LOCAL_IDENTITY, "id_ops");
            n6_leave(n6);
            return NINLIL_N6_INVALID_ARGUMENT;
        }
    }
    if (ops->consume == NULL) {
        n6_set_err(n6, NINLIL_N6_INVALID_ARGUMENT, NINLIL_N6_REASON_LOCAL_IDENTITY,
            "id_ops");
        n6_leave(n6);
        return NINLIL_N6_INVALID_ARGUMENT;
    }

    /* Claim all-zero before callback — do not pre-fill ABI fields. */
    ninlil_n6_secure_zero(&claim, sizeof(claim));
    /* consume exactly once under reentry guard; token terminal regardless */
    acc = ops->consume(ops->user, mutable_token, &claim);
    /* Exact shape only: struct_size == 24, not >= / not larger-than-v1. */
    if (acc != NINLIL_N6_LOCAL_ID_ACCEPT_OK
        || claim.abi_version != NINLIL_N6_LOCAL_ID_CLAIM_ABI
        || claim.struct_size != NINLIL_N6_LOCAL_ID_CLAIM_BYTES
        || claim.reserved_zero != 0u) {
        ninlil_n6_secure_zero(&claim, sizeof(claim));
        n6_set_err(n6, NINLIL_N6_M4_REQUIRED, NINLIL_N6_REASON_LOCAL_IDENTITY, "id_accept");
        n6_leave(n6);
        return NINLIL_N6_M4_REQUIRED;
    }
    all0 = 1;
    for (i = 0u; i < 16u; ++i) {
        if (claim.local_node_id[i] != 0u) {
            all0 = 0;
            break;
        }
    }
    if (all0 != 0) {
        ninlil_n6_secure_zero(&claim, sizeof(claim));
        n6_set_err(n6, NINLIL_N6_M4_REQUIRED, NINLIL_N6_REASON_LOCAL_IDENTITY, "id_zero");
        n6_leave(n6);
        return NINLIL_N6_M4_REQUIRED;
    }
    (void)memcpy(n6->local_node_id, claim.local_node_id, 16u);
    n6->local_id_bound = 1;
    ninlil_n6_secure_zero(&claim, sizeof(claim));
    n6_refresh_bound(n6);
    n6_leave(n6);
    return NINLIL_N6_OK;
}

/* ---- boot scan: exact 4-pass single snapshot (docs/30 §20.4.1) ---- */



typedef struct n6_boot_ctx {
    ninlil_n6_t *n6;
    ninlil_storage_txn_t txn;
    ninlil_storage_iter_t it;
    int txn_live;
    int it_live;
    uint32_t iter_next_count;
    uint32_t pass_count;
    int corrupt;
    int any;
    uint32_t n_active; /* complete H+E */
    uint32_t n_lane;
    uint32_t n_al;
    uint32_t n_hw;
    uint32_t n_rt;
    uint32_t n_cf;
    uint32_t n_total;
    uint64_t n_bytes; /* checked logical key+value bytes */
    uint32_t n_al_loaded;
    uint32_t n_hw_req;
    ninlil_n6_status_t semantic;
} n6_boot_ctx_t;

static uint32_t n6_load_u32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
        | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int n6_u64_add_ok(uint64_t a, uint64_t b, uint64_t *out)
{
    if (a > UINT64_MAX - b) {
        return 0;
    }
    *out = a + b;
    return 1;
}

static uint32_t n6_cap_lane(uint32_t c) { return 2u * c; }
static uint32_t n6_cap_al(uint32_t c) { return 2u * c; }
static uint32_t n6_cap_rt(uint32_t c) { return 2u * c; }
static uint32_t n6_cap_cf(uint32_t c) { return c; }
static uint32_t n6_cap_hw(uint32_t c, uint32_t a)
{
    uint32_t w2a = 2u * a;
    uint32_t w4c = 4u * c;
    return (w2a < w4c) ? w2a : w4c;
}
static uint32_t n6_cap_total(uint32_t c) { return 11u * c; }
static uint64_t n6_cap_bytes(uint32_t c)
{
    return 876ull * (uint64_t)c;
}

static void n6_boot_cells_to_empty_live(ninlil_n6_t *n6)
{
    uint32_t si;
    for (si = 0u; si < n6->slot_count; ++si) {
        ninlil_n6_secure_zero(&n6->cells[si], sizeof(n6->cells[si]));
        n6->cells[si].live.canary0 = N6_CANARY;
        n6->cells[si].live.canary1 = N6_CANARY;
        n6->cells[si].live.live = 0u;
    }
}

static int n6_boot_volatile_empty(const ninlil_n6_t *n6)
{
    uint32_t i;
    if (n6->cu.live != 0) {
        return 0;
    }
    for (i = 0u; i < n6->slot_count; ++i) {
        if (n6->cells[i].live.live != 0u) {
            return 0;
        }
    }
    for (i = 0u; i < NINLIL_N6_MAX_LIVE_LEASES; ++i) {
        if (n6->leases[i].live != 0u) {
            return 0;
        }
    }
    for (i = 0u; i < NINLIL_N6_MAX_LIVE_TICKETS; ++i) {
        if (n6->tickets[i].live != 0u) {
            return 0;
        }
    }
    return 1;
}

/*
 * Boot final RO cleanup: separate from generic n6_prov_rollback mapping.
 * rollback consumes txn exactly once. IO/BUSY → close handle → STORAGE (BOUND).
 * CORRUPT/NOT_FOUND/NO_SPACE/BTS/COMMIT_UNKNOWN/UNSUPPORTED/unknown →
 * close handle → CORRUPT (finish fences).
 */
static ninlil_n6_status_t n6_boot_cleanup(n6_boot_ctx_t *b)
{
    if (b->it_live != 0) {
        b->n6->storage.iter_close(b->n6->storage.user, b->it);
        b->it = NULL;
        b->it_live = 0;
    }
    if (b->txn_live != 0) {
        ninlil_storage_status_t ss;
        ninlil_storage_txn_t th = b->txn;
        b->txn = NULL;
        b->txn_live = 0;
        ss = b->n6->storage.rollback(b->n6->storage.user, th);
        n6_storage_force_close(b->n6);
        if (ss == NINLIL_STORAGE_OK) {
            return NINLIL_N6_OK;
        }
        if (ss == NINLIL_STORAGE_IO_ERROR || ss == NINLIL_STORAGE_BUSY) {
            b->n6->stats.storage_fail += 1u;
            return NINLIL_N6_STORAGE;
        }
        b->n6->stats.storage_fail += 1u;
        return NINLIL_N6_CORRUPT;
    }
    return NINLIL_N6_OK;
}

/*
 * Map begin/iter_open/iter_next status when handle is NULL (no shape fault).
 * Known operational → STORAGE/CAPACITY (retryable BOUND). Unknown/invalid → CORRUPT.
 */
static ninlil_n6_status_t n6_boot_map_op_status(ninlil_storage_status_t ss)
{
    if (ss == NINLIL_STORAGE_IO_ERROR || ss == NINLIL_STORAGE_BUSY) {
        return NINLIL_N6_STORAGE;
    }
    if (ss == NINLIL_STORAGE_NO_SPACE
        || ss == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
        return NINLIL_N6_CAPACITY;
    }
    if (ss == NINLIL_STORAGE_CORRUPT) {
        return NINLIL_N6_CORRUPT;
    }
    /* NOT_FOUND/COMMIT_UNKNOWN/UNSUPPORTED_SCHEMA/unknown: invalid for this op */
    return NINLIL_N6_CORRUPT;
}

static ninlil_n6_status_t n6_boot_txn_begin(n6_boot_ctx_t *b)
{
    n6_txn_t t;
    ninlil_n6_status_t st;
    st = n6_prov_begin(b->n6, NINLIL_STORAGE_READ_ONLY, &t);
    if (st != NINLIL_N6_OK) {
        return st;
    }
    b->txn = t.h;
    b->txn_live = 1;
    return NINLIL_N6_OK;
}

static ninlil_n6_status_t n6_boot_iter_open(n6_boot_ctx_t *b)
{
    ninlil_storage_status_t ss;
    ninlil_bytes_view_t prefix;
    if (b->it_live != 0) {
        return NINLIL_N6_CORRUPT;
    }
    if (b->pass_count >= N6_BOOT_PASS_COUNT) {
        return NINLIL_N6_CORRUPT;
    }
    b->it = NULL;
    prefix.data = NULL;
    prefix.length = 0u;
    ss = b->n6->storage.iter_open(
        b->n6->storage.user, b->txn, prefix, &b->it);
    if (ss != NINLIL_STORAGE_OK) {
        if (b->it != NULL) {
            /* Consume malformed non-NULL iter handle exactly once. */
            b->n6->storage.iter_close(b->n6->storage.user, b->it);
            b->it = NULL;
            return NINLIL_N6_CORRUPT;
        }
        return n6_boot_map_op_status(ss);
    }
    if (b->it == NULL) {
        return NINLIL_N6_CORRUPT; /* OK+NULL */
    }
    b->it_live = 1;
    b->pass_count += 1u;
    return NINLIL_N6_OK;
}

static void n6_boot_iter_close(n6_boot_ctx_t *b)
{
    if (b->it_live != 0) {
        b->n6->storage.iter_close(b->n6->storage.user, b->it);
        b->it = NULL;
        b->it_live = 0;
    }
}

/*
 * 1 = row, 0 = end (NOT_FOUND), -1 = fail (*out_fail set).
 * Full mutable-buffer ABI after iter_next (pointer/capacity stable; length/tail rules).
 */
static int n6_boot_next(
    n6_boot_ctx_t *b, n6_boot_scratch_t *sc, ninlil_mut_bytes_t *key,
    ninlil_mut_bytes_t *val, ninlil_n6_status_t *out_fail)
{
    ninlil_storage_status_t ss;
    uint32_t bound = N6_BOOT_ITER_NEXT_BOUND_C(b->n6->slot_count);
    uint8_t *kdata;
    uint8_t *vdata;
    uint32_t kcap;
    uint32_t vcap;
    uint32_t i;
    const uint8_t ksent = 0xA5u;
    const uint8_t vsent = 0x5Au;

    if (out_fail != NULL) {
        *out_fail = NINLIL_N6_CORRUPT;
    }
    if (b->iter_next_count >= bound) {
        if (out_fail != NULL) {
            *out_fail = NINLIL_N6_CORRUPT;
        }
        return -1;
    }
    b->iter_next_count += 1u;

    kdata = sc->kbuf;
    vdata = sc->vbuf;
    kcap = (uint32_t)sizeof(sc->kbuf);
    vcap = (uint32_t)sizeof(sc->vbuf);
    /* Deterministic pre-call sentinel across full buffers. */
    for (i = 0u; i < kcap; ++i) {
        kdata[i] = ksent;
    }
    for (i = 0u; i < vcap; ++i) {
        vdata[i] = vsent;
    }
    key->data = kdata;
    key->capacity = kcap;
    key->length = 0u;
    val->data = vdata;
    val->capacity = vcap;
    val->length = 0u;

    ss = b->n6->storage.iter_next(b->n6->storage.user, b->it, key, val);

    /* Pointer / capacity must be unchanged for both descriptors. */
    if (key->data != kdata || val->data != vdata
        || key->capacity != kcap || val->capacity != vcap) {
        if (out_fail != NULL) {
            *out_fail = NINLIL_N6_CORRUPT;
        }
        return -1;
    }

    if (ss == NINLIL_STORAGE_NOT_FOUND) {
        if (key->length != 0u || val->length != 0u) {
            if (out_fail != NULL) {
                *out_fail = NINLIL_N6_CORRUPT;
            }
            return -1;
        }
        for (i = 0u; i < kcap; ++i) {
            if (kdata[i] != ksent) {
                if (out_fail != NULL) {
                    *out_fail = NINLIL_N6_CORRUPT;
                }
                return -1;
            }
        }
        for (i = 0u; i < vcap; ++i) {
            if (vdata[i] != vsent) {
                if (out_fail != NULL) {
                    *out_fail = NINLIL_N6_CORRUPT;
                }
                return -1;
            }
        }
        return 0;
    }

    if (ss == NINLIL_STORAGE_OK) {
        if (key->length == 0u || key->length > kcap || val->length > vcap) {
            if (out_fail != NULL) {
                *out_fail = NINLIL_N6_CORRUPT;
            }
            return -1;
        }
        for (i = key->length; i < kcap; ++i) {
            if (kdata[i] != ksent) {
                if (out_fail != NULL) {
                    *out_fail = NINLIL_N6_CORRUPT;
                }
                return -1;
            }
        }
        for (i = val->length; i < vcap; ++i) {
            if (vdata[i] != vsent) {
                if (out_fail != NULL) {
                    *out_fail = NINLIL_N6_CORRUPT;
                }
                return -1;
            }
        }
        return 1;
    }

    if (ss == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
        /*
         * Contract: both required lengths returned (neither zero), at least
         * one > capacity, data buffers unchanged (sentinel) → CAPACITY.
         * key length 0 or val length 0 or missing oversize → CORRUPT.
         */
        for (i = 0u; i < kcap; ++i) {
            if (kdata[i] != ksent) {
                if (out_fail != NULL) {
                    *out_fail = NINLIL_N6_CORRUPT;
                }
                return -1;
            }
        }
        for (i = 0u; i < vcap; ++i) {
            if (vdata[i] != vsent) {
                if (out_fail != NULL) {
                    *out_fail = NINLIL_N6_CORRUPT;
                }
                return -1;
            }
        }
        if (key->length == 0u || val->length == 0u
            || ((key->length <= kcap) && (val->length <= vcap))) {
            if (out_fail != NULL) {
                *out_fail = NINLIL_N6_CORRUPT;
            }
            return -1;
        }
        if (out_fail != NULL) {
            *out_fail = NINLIL_N6_CAPACITY;
        }
        return -1;
    }

    /* Ordinary errors: lengths zero + full buffers unchanged. */
    if (ss == NINLIL_STORAGE_IO_ERROR || ss == NINLIL_STORAGE_BUSY
        || ss == NINLIL_STORAGE_NO_SPACE) {
        if (key->length != 0u || val->length != 0u) {
            if (out_fail != NULL) {
                *out_fail = NINLIL_N6_CORRUPT;
            }
            return -1;
        }
        for (i = 0u; i < kcap; ++i) {
            if (kdata[i] != ksent) {
                if (out_fail != NULL) {
                    *out_fail = NINLIL_N6_CORRUPT;
                }
                return -1;
            }
        }
        for (i = 0u; i < vcap; ++i) {
            if (vdata[i] != vsent) {
                if (out_fail != NULL) {
                    *out_fail = NINLIL_N6_CORRUPT;
                }
                return -1;
            }
        }
        if (out_fail != NULL) {
            *out_fail = n6_boot_map_op_status(ss);
        }
        return -1;
    }

    /* unknown / shape poison */
    if (out_fail != NULL) {
        *out_fail = NINLIL_N6_CORRUPT;
    }
    return -1;
}

static ninlil_n6_status_t n6_boot_finish(
    n6_boot_ctx_t *b, ninlil_n6_status_t semantic)
{
    ninlil_n6_status_t cst;
    b->semantic = semantic;
    cst = n6_boot_cleanup(b);
    n6_boot_cells_to_empty_live(b->n6);
    /* Every exit: zero per-object boot scratch (no residue). */
    ninlil_n6_secure_zero(&b->n6->boot_scratch, sizeof(b->n6->boot_scratch));
    if (semantic == NINLIL_N6_CORRUPT || cst == NINLIL_N6_CORRUPT) {
        n6_enter_fenced(b->n6);
        b->n6->stats.corrupt_boot += 1u;
        n6_set_err(b->n6, NINLIL_N6_CORRUPT, NINLIL_N6_REASON_CORRUPT,
            cst == NINLIL_N6_CORRUPT ? "boot_rb" : "boot");
        n6_leave(b->n6);
        return NINLIL_N6_CORRUPT;
    }
    if (cst != NINLIL_N6_OK) {
        /* cleanup STORAGE (IO/BUSY after close): remain BOUND, retryable */
        b->n6->state = NINLIL_N6_STATE_BOUND;
        n6_set_err(b->n6, cst, NINLIL_N6_REASON_STORAGE, "boot_rb");
        n6_leave(b->n6);
        return cst;
    }
    if (semantic == NINLIL_N6_OK) {
        b->n6->state = NINLIL_N6_STATE_BOOTED;
        n6_leave(b->n6);
        return NINLIL_N6_OK;
    }
    if (semantic == NINLIL_N6_BOOT_DORMANT) {
        b->n6->state = NINLIL_N6_STATE_DORMANT_DURABLE_NO_SECRET;
        b->n6->stats.dormant_boot += 1u;
        n6_set_err(b->n6, NINLIL_N6_BOOT_DORMANT, NINLIL_N6_REASON_DORMANT, "m5");
        n6_leave(b->n6);
        return NINLIL_N6_BOOT_DORMANT;
    }
    /* Operational STORAGE/CAPACITY: remain BOUND (retryable); do not fence. */
    if (semantic == NINLIL_N6_STORAGE || semantic == NINLIL_N6_CAPACITY) {
        b->n6->state = NINLIL_N6_STATE_BOUND;
        n6_set_err(b->n6, semantic, NINLIL_N6_REASON_STORAGE, "boot_op");
        n6_leave(b->n6);
        return semantic;
    }
    n6_set_err(b->n6, semantic, NINLIL_N6_REASON_STORAGE, "boot");
    n6_leave(b->n6);
    return semantic;
}

static n6_boot_al_t *n6_boot_al_slot(ninlil_n6_t *n6, uint32_t idx)
{
    uint32_t cell = idx / 2u;
    uint32_t slot = idx % 2u;
    if (cell >= n6->slot_count) {
        return NULL;
    }
    return &n6->cells[cell].boot.al[slot];
}

static n6_boot_hw_req_t *n6_boot_hw_slot(ninlil_n6_t *n6, uint32_t idx)
{
    uint32_t cell = idx / 4u;
    uint32_t slot = idx % 4u;
    if (cell >= n6->slot_count) {
        return NULL;
    }
    return &n6->cells[cell].boot.hw[slot];
}

static n6_boot_active_meta_t *n6_boot_active_meta_at(ninlil_n6_t *n6, uint32_t i)
{
    return &n6->cells[i].boot.active_meta;
}

static n6_boot_active_t *n6_boot_active_payload_at(ninlil_n6_t *n6, uint32_t i)
{
    return &n6->cells[i].boot.active;
}

/* Resolve AL for an active via meta.al_index. */
static n6_boot_al_t *n6_boot_active_al(
    ninlil_n6_t *n6, uint32_t n_al, const n6_boot_active_meta_t *m)
{
    if (m == NULL || (m->flags & N6_BA_USED) == 0u) {
        return NULL;
    }
    if ((uint32_t)m->al_index >= n_al) {
        return NULL;
    }
    return n6_boot_al_slot(n6, (uint32_t)m->al_index);
}

/*
 * Find/create active by assembly identity:
 * (context_id, direction, al_index) — AL supplies epoch/layer/side/nsfp.
 * out_idx receives cell index of the active.
 */
static n6_boot_active_t *n6_boot_find_active(
    ninlil_n6_t *n6, uint32_t *n_used, uint32_t cid, uint16_t al_index,
    uint8_t dir, uint32_t *out_idx)
{
    uint32_t i;
    n6_boot_active_meta_t *m;
    n6_boot_active_t *a;
    for (i = 0u; i < *n_used; ++i) {
        m = n6_boot_active_meta_at(n6, i);
        if ((m->flags & N6_BA_USED) != 0u && m->context_id == cid
            && m->al_index == al_index && m->direction_code == dir) {
            if (out_idx != NULL) {
                *out_idx = i;
            }
            return n6_boot_active_payload_at(n6, i);
        }
    }
    if (*n_used >= n6->slot_count) {
        return NULL;
    }
    i = *n_used;
    a = n6_boot_active_payload_at(n6, i);
    m = n6_boot_active_meta_at(n6, i);
    ninlil_n6_secure_zero(a, sizeof(*a));
    ninlil_n6_secure_zero(m, sizeof(*m));
    m->flags = N6_BA_USED;
    m->context_id = cid;
    m->al_index = al_index;
    m->direction_code = dir;
    *n_used += 1u;
    if (out_idx != NULL) {
        *out_idx = i;
    }
    return a;
}

static n6_boot_al_t *n6_boot_find_al(
    ninlil_n6_t *n6,
    uint32_t n_al,
    uint8_t layer,
    uint8_t side,
    uint64_t epoch,
    const uint8_t nsfp[12])
{
    uint32_t i;
    for (i = 0u; i < n_al; ++i) {
        n6_boot_al_t *al = n6_boot_al_slot(n6, i);
        if (al != NULL && al->used != 0u && al->layer_code == layer
            && al->alloc_side == side && al->membership_epoch == epoch
            && memcmp(al->nsfp, nsfp, 12u) == 0) {
            return al;
        }
    }
    return NULL;
}

static int n6_boot_find_al_index(
    ninlil_n6_t *n6,
    uint32_t n_al,
    uint8_t layer,
    uint8_t side,
    uint64_t epoch,
    const uint8_t nsfp[12],
    uint16_t *out_idx)
{
    uint32_t i;
    for (i = 0u; i < n_al; ++i) {
        n6_boot_al_t *al = n6_boot_al_slot(n6, i);
        if (al != NULL && al->used != 0u && al->layer_code == layer
            && al->alloc_side == side && al->membership_epoch == epoch
            && memcmp(al->nsfp, nsfp, 12u) == 0) {
            if (i > 0xFFFFu) {
                return 0;
            }
            if (out_idx != NULL) {
                *out_idx = (uint16_t)i;
            }
            return 1;
        }
    }
    return 0;
}

/* Strict unsigned lexicographic key order: <0 a before b, 0 equal, >0 a after b. */
static int n6_boot_key_cmp(
    const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
    size_t n;
    int c;
    if (a == NULL || b == NULL) {
        return 0;
    }
    n = (alen < blen) ? alen : blen;
    if (n > 0u) {
        c = memcmp(a, b, n);
        if (c != 0) {
            return c;
        }
    }
    if (alen < blen) {
        return -1;
    }
    if (alen > blen) {
        return 1;
    }
    return 0;
}

static int n6_boot_active_complete(
    ninlil_n6_t *n6, uint32_t n_al, const n6_boot_active_meta_t *m)
{
    n6_boot_al_t *al;
    if (m == NULL || (m->flags & N6_BA_USED) == 0u) {
        return 0;
    }
    al = n6_boot_active_al(n6, n_al, m);
    if (al == NULL) {
        return 0;
    }
    if (al->layer_code == NINLIL_N6_LAYER_HOP) {
        return ((m->flags & N6_BA_DATA) != 0u && (m->flags & N6_BA_ACK) != 0u
            && (m->flags & N6_BA_E2E) == 0u)
            ? 1
            : 0;
    }
    if (al->layer_code == NINLIL_N6_LAYER_E2E) {
        return ((m->flags & N6_BA_E2E) != 0u && (m->flags & N6_BA_DATA) == 0u
            && (m->flags & N6_BA_ACK) == 0u)
            ? 1
            : 0;
    }
    return 0;
}

/* Dispatch RT/CF by kind byte — both keys are 28 B; length alone is forbidden. */
static int n6_boot_is_rt_key(const uint8_t *k, size_t klen)
{
    return (klen == NINLIL_N6_RT_KEY_BYTES && k != NULL
        && k[0] == NINLIL_N6_REC_KIND_RT)
        ? 1
        : 0;
}

static int n6_boot_is_cf_key(const uint8_t *k, size_t klen)
{
    return (klen == NINLIL_N6_CF_KEY_BYTES && k != NULL
        && k[0] == NINLIL_N6_REC_KIND_CF)
        ? 1
        : 0;
}

ninlil_n6_status_t ninlil_n6_boot_scan(ninlil_n6_t *n6)
{
    /* Per-object scratch only — never process-global. Keeps frame ≤1024. */
    n6_boot_scratch_t *sc;
    ninlil_n6_status_t st = n6_enter(n6);
    n6_boot_ctx_t b;
    ninlil_mut_bytes_t key, val;
    uint32_t i, j;
    uint32_t C;
    int rc;
    ninlil_n6_status_t fail_st;

    ninlil_n6_secure_zero(&b, sizeof(b));
    b.n6 = n6;

    if (st != NINLIL_N6_OK) {
        return st;
    }
    sc = &n6->boot_scratch;
    ninlil_n6_secure_zero(sc, sizeof(*sc));
    if (n6->storage_bound == 0 || n6->crypto_bound == 0) {
        n6_set_err(n6, NINLIL_N6_INVALID_STATE, NINLIL_N6_REASON_STATE, "boot_bind");
        n6_leave(n6);
        return NINLIL_N6_INVALID_STATE;
    }
    if (n6->local_id_bound == 0) {
        n6_set_err(n6, NINLIL_N6_M4_REQUIRED, NINLIL_N6_REASON_LOCAL_IDENTITY, "boot_id");
        n6_leave(n6);
        return NINLIL_N6_M4_REQUIRED;
    }
    if (n6->state != NINLIL_N6_STATE_BOUND) {
        n6_set_err(n6, NINLIL_N6_INVALID_STATE, NINLIL_N6_REASON_STATE, "boot_state");
        n6_leave(n6);
        return NINLIL_N6_INVALID_STATE;
    }
    if (n6_boot_volatile_empty(n6) == 0) {
        n6_set_err(n6, NINLIL_N6_INVALID_STATE, NINLIL_N6_REASON_STATE, "boot_busy");
        n6_leave(n6);
        return NINLIL_N6_INVALID_STATE;
    }

    st = n6_open_storage(n6);
    if (st != NINLIL_N6_OK) {
        /* Boot open/capacity shape corruption must FENCE, not stay BOUND. */
        ninlil_n6_secure_zero(&n6->boot_scratch, sizeof(n6->boot_scratch));
        if (st == NINLIL_N6_CORRUPT) {
            n6_enter_fenced(n6);
            n6->stats.corrupt_boot += 1u;
        }
        n6_leave(n6);
        return st;
    }

    C = n6->slot_count;
    {
        uint32_t si;
        for (si = 0u; si < C; ++si) {
            ninlil_n6_secure_zero(&n6->cells[si], sizeof(n6->cells[si]));
        }
    }

    st = n6_boot_txn_begin(&b);
    if (st != NINLIL_N6_OK) {
        /* Propagate mapped status: CORRUPT fences; STORAGE/CAPACITY stay BOUND. */
        return n6_boot_finish(&b, st);
    }

    /* ========== P0: census + decode + ceilings + load AL (fp/epoch) ========== */
    st = n6_boot_iter_open(&b);
    if (st != NINLIL_N6_OK) {
        return n6_boot_finish(&b, st);
    }
    for (;;) {
        uint64_t addb = 0u;
        rc = n6_boot_next(&b, sc, &key, &val, &fail_st);
        if (rc == 0) {
            break;
        }
        if (rc < 0) {
            n6_boot_iter_close(&b);
            return n6_boot_finish(&b, fail_st);
        }
        /* Strict unsigned lex increasing + duplicate-free provider keys. */
        if (key.length == 0u || key.length > sizeof(sc->prev_key)) {
            b.corrupt = 1;
            break;
        }
        if (sc->has_prev != 0u) {
            int kc = n6_boot_key_cmp(
                sc->prev_key, (size_t)sc->prev_klen, sc->kbuf, (size_t)key.length);
            if (kc >= 0) {
                b.corrupt = 1;
                break;
            }
        }
        (void)memcpy(sc->prev_key, sc->kbuf, (size_t)key.length);
        sc->prev_klen = (uint8_t)key.length;
        sc->has_prev = 1u;

        b.any = 1;
        b.n_total += 1u;
        if (b.n_total > n6_cap_total(C)) {
            b.corrupt = 1;
            break;
        }
        if (key.length == NINLIL_N6_LANE_KEY_BYTES) {
            b.n_lane += 1u;
            addb = N6_KV_LANE;
            if (b.n_lane > n6_cap_lane(C)
                || ninlil_n6_decode_lane_key(sc->kbuf, key.length, &sc->lk)
                    != NINLIL_N6_CODEC_OK) {
                b.corrupt = 1;
            } else if (val.length < 4u) {
                b.corrupt = 1;
            } else {
                /* TX/RX values share wire length; dispatch by exact 4-byte BE magic. */
                uint32_t lane_magic = n6_load_u32_be(sc->vbuf);
                if (val.length == NINLIL_N6_TX_VALUE_BYTES
                    && lane_magic == NINLIL_N6_MAGIC_TX) {
                    if (ninlil_n6_decode_n6tx_value(
                            sc->vbuf, val.length, &sc->u.tv)
                        != NINLIL_N6_CODEC_OK) {
                        b.corrupt = 1;
                    }
                } else if (val.length == NINLIL_N6_RX_VALUE_BYTES
                    && lane_magic == NINLIL_N6_MAGIC_RX) {
                    if (ninlil_n6_decode_n6rx_value(
                            sc->vbuf, val.length, &sc->u.rv)
                        != NINLIL_N6_CODEC_OK) {
                        b.corrupt = 1;
                    }
                } else {
                    b.corrupt = 1; /* wrong/unknown magic or length */
                }
            }
        } else if (key.length == NINLIL_N6_AL_KEY_BYTES) {
            n6_boot_al_t *al;
            b.n_al += 1u;
            addb = N6_KV_AL;
            if (b.n_al > n6_cap_al(C)
                || ninlil_n6_decode_n6al_key(sc->kbuf, key.length, &sc->ak)
                    != NINLIL_N6_CODEC_OK
                || ninlil_n6_decode_n6al_value(sc->vbuf, val.length, &sc->u.av)
                    != NINLIL_N6_CODEC_OK) {
                b.corrupt = 1;
            } else if (sc->u.av.membership_epoch != sc->ak.membership_epoch
                || ninlil_n6_ns_fingerprint12(
                       &n6->crypto, sc->u.av.receiver_node_id, sc->ak.layer_code,
                       sc->ak.membership_epoch, sc->ak.alloc_side, sc->re_nsfp)
                    != 0
                || memcmp(sc->re_nsfp, sc->ak.ns_fingerprint12, 12u) != 0) {
                b.corrupt = 1;
            } else {
                al = n6_boot_al_slot(n6, b.n_al_loaded);
                if (al == NULL) {
                b.corrupt = 1;
                } else {
                    ninlil_n6_secure_zero(al, sizeof(*al));
                    al->used = 1u;
                    al->layer_code = sc->ak.layer_code;
                    al->alloc_side = sc->ak.alloc_side;
                    al->membership_epoch = sc->ak.membership_epoch;
                    al->floor = sc->u.av.next_free_or_peer_floor;
                    al->active_count = sc->u.av.active_count;
                    al->retired_count = sc->u.av.retired_tombstone_count;
                    (void)memcpy(al->nsfp, sc->ak.ns_fingerprint12, 12u);
                    (void)memcpy(
                        al->receiver_node_id, sc->u.av.receiver_node_id, 16u);
                    b.n_al_loaded += 1u;
                }
            }
        } else if (key.length == NINLIL_N6_HW_KEY_BYTES) {
            b.n_hw += 1u;
            addb = N6_KV_HW;
            if (b.n_hw > 4u * C
                || ninlil_n6_decode_n6hw_key(sc->kbuf, key.length, &sc->hk)
                    != NINLIL_N6_CODEC_OK
                || ninlil_n6_decode_n6hw_value(sc->vbuf, val.length, &sc->u.hv)
                    != NINLIL_N6_CODEC_OK) {
                b.corrupt = 1;
            }
        } else if (n6_boot_is_rt_key(sc->kbuf, key.length) != 0) {
            b.n_rt += 1u;
            addb = N6_KV_RT;
            if (b.n_rt > n6_cap_rt(C)
                || ninlil_n6_decode_n6rt_key(sc->kbuf, key.length, &sc->rk)
                    != NINLIL_N6_CODEC_OK
                || ninlil_n6_decode_n6rt_value(sc->vbuf, val.length, &sc->u.rtv)
                    != NINLIL_N6_CODEC_OK) {
                b.corrupt = 1;
            } else if (sc->rk.context_id != sc->u.rtv.context_id
                || sc->rk.membership_epoch != sc->u.rtv.membership_epoch
                || sc->rk.layer_code != sc->u.rtv.layer_code
                || sc->rk.direction_code != sc->u.rtv.direction_code
                || sc->rk.alloc_side != sc->u.rtv.alloc_side) {
                b.corrupt = 1;
            }
        } else if (n6_boot_is_cf_key(sc->kbuf, key.length) != 0) {
            b.n_cf += 1u;
            addb = N6_KV_CF;
            if (b.n_cf > n6_cap_cf(C)
                || ninlil_n6_decode_n6cf_key(sc->kbuf, key.length, &sc->ck)
                    != NINLIL_N6_CODEC_OK
                || ninlil_n6_decode_n6cf_value(sc->vbuf, val.length, &sc->u.cfv)
                    != NINLIL_N6_CODEC_OK) {
                b.corrupt = 1;
            } else if (sc->ck.context_id != sc->u.cfv.context_id
                || sc->ck.membership_epoch != sc->u.cfv.membership_epoch
                || sc->ck.layer_code != sc->u.cfv.layer_code
                || sc->ck.direction_code != sc->u.cfv.direction_code
                || sc->ck.alloc_side != sc->u.cfv.alloc_side) {
                b.corrupt = 1;
            }
        } else {
            b.corrupt = 1;
        }
        if (b.corrupt == 0 && addb != 0u) {
            if (n6_u64_add_ok(b.n_bytes, addb, &b.n_bytes) == 0
                || b.n_bytes > n6_cap_bytes(C)) {
                b.corrupt = 1;
            }
        }
        if (b.corrupt != 0) {
            break;
        }
    }
    n6_boot_iter_close(&b);
    if (b.corrupt != 0) {
        return n6_boot_finish(&b, NINLIL_N6_CORRUPT);
    }
    /* HW ceiling also vs 2A after AL census */
    if (b.n_hw > n6_cap_hw(C, b.n_al)) {
        return n6_boot_finish(&b, NINLIL_N6_CORRUPT);
    }
    /* Empty AL (active=0 and retired=0) reject; empty durable continues P1–P3. */
    for (i = 0u; i < b.n_al_loaded; ++i) {
        n6_boot_al_t *al = n6_boot_al_slot(n6, i);
        if (al != NULL && al->used != 0u && al->active_count == 0u
            && al->retired_count == 0u) {
            return n6_boot_finish(&b, NINLIL_N6_CORRUPT);
        }
    }

    /* ========== P1: lanes exact AL join / active / floor / live-live / HW req ========== */
    st = n6_boot_iter_open(&b);
    if (st != NINLIL_N6_OK) {
        return n6_boot_finish(&b, st);
    }
    for (;;) {
        n6_boot_active_t *a;
        n6_boot_active_meta_t *am;
        n6_boot_al_t *al;
        uint8_t side;
        const uint8_t *nsfp;
        uint64_t epoch;
        uint64_t kgen;
        uint16_t al_idx = 0u;
        uint32_t aidx = 0u;
        rc = n6_boot_next(&b, sc, &key, &val, &fail_st);
        if (rc == 0) {
            break;
        }
        if (rc < 0) {
            n6_boot_iter_close(&b);
            return n6_boot_finish(&b, fail_st);
        }
        if (key.length != NINLIL_N6_LANE_KEY_BYTES) {
            continue;
        }
        if (ninlil_n6_decode_lane_key(sc->kbuf, key.length, &sc->lk)
            != NINLIL_N6_CODEC_OK) {
            b.corrupt = 1;
            break;
        }
        if (val.length < 4u) {
            b.corrupt = 1;
            break;
        }
        {
            /* TX/RX share length; dispatch by exact 4-byte BE magic, not length. */
            uint32_t lane_magic = n6_load_u32_be(sc->vbuf);
            if (val.length == NINLIL_N6_TX_VALUE_BYTES
                && lane_magic == NINLIL_N6_MAGIC_TX) {
                if (ninlil_n6_decode_n6tx_value(sc->vbuf, val.length, &sc->u.tv)
                        != NINLIL_N6_CODEC_OK
                    || sc->u.tv.key_generation != sc->lk.key_generation
                    || sc->u.tv.alloc_side != NINLIL_N6_ALLOC_OUTBOUND_TX
                    || memcmp(sc->u.tv.binding_digest_prefix16, sc->lk.binding_digest32,
                           16u)
                        != 0) {
                    b.corrupt = 1;
                    break;
                }
                side = NINLIL_N6_ALLOC_OUTBOUND_TX;
                nsfp = sc->u.tv.ns_fingerprint12;
                epoch = sc->u.tv.membership_epoch;
                kgen = sc->lk.key_generation;
            } else if (val.length == NINLIL_N6_RX_VALUE_BYTES
                && lane_magic == NINLIL_N6_MAGIC_RX) {
                if (ninlil_n6_decode_n6rx_value(sc->vbuf, val.length, &sc->u.rv)
                        != NINLIL_N6_CODEC_OK
                    || sc->u.rv.key_generation != sc->lk.key_generation
                    || sc->u.rv.alloc_side != NINLIL_N6_ALLOC_INBOUND_RX
                    || memcmp(sc->u.rv.binding_digest_prefix16, sc->lk.binding_digest32,
                           16u)
                        != 0) {
                    b.corrupt = 1;
                    break;
                }
                side = NINLIL_N6_ALLOC_INBOUND_RX;
                nsfp = sc->u.rv.ns_fingerprint12;
                epoch = sc->u.rv.membership_epoch;
                kgen = sc->lk.key_generation;
            } else {
                b.corrupt = 1; /* wrong/unknown magic or length */
                break;
            }
        }
        if (n6_boot_find_al_index(
                n6, b.n_al_loaded, sc->lk.layer_code, side, epoch, nsfp, &al_idx)
            == 0) {
            b.corrupt = 1; /* orphan lane / no AL join */
            break;
        }
        al = n6_boot_al_slot(n6, (uint32_t)al_idx);
        if (al == NULL) {
            b.corrupt = 1;
            break;
        }
        if (al->floor != 0u && sc->lk.context_id >= al->floor) {
            b.corrupt = 1;
            break;
        }
        a = n6_boot_find_active(
            n6, &b.n_active, sc->lk.context_id, al_idx, sc->lk.direction_code,
            &aidx);
        if (a == NULL) {
            b.corrupt = 1; /* H+E > C */
            break;
        }
        am = n6_boot_active_meta_at(n6, aidx);
        /* Full 32-byte binding equality across lanes of one assembly. */
        if (a->key_generation == 0u
            && (am->flags & (N6_BA_DATA | N6_BA_ACK | N6_BA_E2E)) == 0u) {
            (void)memcpy(a->binding_digest32, sc->lk.binding_digest32, 32u);
            a->key_generation = kgen;
        } else {
            if (a->key_generation != kgen
                || memcmp(a->binding_digest32, sc->lk.binding_digest32, 32u)
                    != 0) {
                b.corrupt = 1; /* DATA/ACK binding or kgen mismatch */
                break;
            }
        }
        am->flags |= N6_BA_AL;
        if (sc->lk.kind_or_lane == NINLIL_N6_LANE_HOP_DATA) {
            if ((am->flags & (N6_BA_DATA | N6_BA_E2E)) != 0u) {
                b.corrupt = 1;
                break;
            }
            am->flags |= N6_BA_DATA;
        } else if (sc->lk.kind_or_lane == NINLIL_N6_LANE_HOP_ACK) {
            if ((am->flags & N6_BA_ACK) != 0u) {
                b.corrupt = 1;
                break;
            }
            am->flags |= N6_BA_ACK;
        } else if (sc->lk.kind_or_lane == NINLIL_N6_LANE_E2E) {
            if ((am->flags & (N6_BA_E2E | N6_BA_DATA | N6_BA_ACK)) != 0u) {
                b.corrupt = 1;
                break;
            }
            am->flags |= N6_BA_E2E;
        } else {
            b.corrupt = 1;
            break;
        }
    }
    n6_boot_iter_close(&b);
    if (b.corrupt != 0) {
        return n6_boot_finish(&b, NINLIL_N6_CORRUPT);
    }
    /* Complete sets + live-live M collision + HW requirements */
    for (i = 0u; i < b.n_active; ++i) {
        n6_boot_active_t *ai = n6_boot_active_payload_at(n6, i);
        n6_boot_active_meta_t *mi = n6_boot_active_meta_at(n6, i);
        n6_boot_al_t *al;
        n6_boot_hw_req_t *hr;
        if (n6_boot_active_complete(n6, b.n_al_loaded, mi) == 0) {
            return n6_boot_finish(&b, NINLIL_N6_CORRUPT);
        }
        mi->flags |= N6_BA_COMPLETE;
        al = n6_boot_active_al(n6, b.n_al_loaded, mi);
        if (al == NULL) {
            return n6_boot_finish(&b, NINLIL_N6_CORRUPT);
        }
        for (j = i + 1u; j < b.n_active; ++j) {
            n6_boot_active_meta_t *mj = n6_boot_active_meta_at(n6, j);
            n6_boot_al_t *alj;
            if (mi->context_id != mj->context_id) {
                continue;
            }
            alj = n6_boot_active_al(n6, b.n_al_loaded, mj);
            if (alj == NULL) {
                continue;
            }
            /* Same epoch+layer via ALs + same receiver ⇒ M collision if side/dir differ */
            if (al->membership_epoch != alj->membership_epoch
                || al->layer_code != alj->layer_code) {
                continue;
            }
            if (memcmp(al->receiver_node_id, alj->receiver_node_id, 16u) == 0
                && (al->alloc_side != alj->alloc_side
                    || mi->direction_code != mj->direction_code)) {
                return n6_boot_finish(&b, NINLIL_N6_CORRUPT);
            }
        }
        if (ninlil_n6_scope_digest28(
                &n6->crypto, n6->local_node_id, al->layer_code,
                mi->direction_code, al->membership_epoch, al->receiver_node_id,
                sc->want_scope)
            != 0) {
            return n6_boot_finish(&b, NINLIL_N6_CORRUPT);
        }
        /* Dedupe HW req by digest only when full scope fields match.
         * Same digest with different layer/direction is a collision → CORRUPT. */
        {
            int found = 0;
            for (j = 0u; j < b.n_hw_req; ++j) {
                hr = n6_boot_hw_slot(n6, j);
                if (hr == NULL || hr->used == 0u
                    || memcmp(hr->scope28, sc->want_scope, 28u) != 0) {
                    continue;
                }
                if (hr->layer_code != al->layer_code
                    || hr->direction_code != mi->direction_code) {
                    return n6_boot_finish(&b, NINLIL_N6_CORRUPT);
                }
                if (ai->key_generation > hr->min_kgen) {
                    hr->min_kgen = ai->key_generation;
                }
                found = 1;
                break;
            }
            if (found == 0) {
                hr = n6_boot_hw_slot(n6, b.n_hw_req);
                if (hr == NULL) {
                    return n6_boot_finish(&b, NINLIL_N6_CORRUPT);
                }
                ninlil_n6_secure_zero(hr, sizeof(*hr));
                hr->used = 1u;
                hr->layer_code = al->layer_code;
                hr->direction_code = mi->direction_code;
                hr->min_kgen = ai->key_generation;
                (void)memcpy(hr->scope28, sc->want_scope, 28u);
                b.n_hw_req += 1u;
            }
        }
    }
    /*
     * P1 complete: compare AL active_count directly against observed completes.
     * No retired_obs[] array (A ≤ 2C=256); retired handled by decrement on AL.
     */
    for (i = 0u; i < b.n_al_loaded; ++i) {
        n6_boot_al_t *al = n6_boot_al_slot(n6, i);
        uint16_t act = 0u;
        if (al == NULL || al->used == 0u) {
            continue;
        }
        for (j = 0u; j < b.n_active; ++j) {
            n6_boot_active_meta_t *m = n6_boot_active_meta_at(n6, j);
            n6_boot_al_t *aal;
            if ((m->flags & N6_BA_COMPLETE) == 0u) {
                continue;
            }
            aal = n6_boot_active_al(n6, b.n_al_loaded, m);
            if (aal == al) {
                act = (uint16_t)(act + 1u);
            }
        }
        if (act != al->active_count) {
            return n6_boot_finish(&b, NINLIL_N6_CORRUPT);
        }
    }

    /* ========== P2: RT+CF join / floor / live-RT M / CF / counts / HW min ========== */
    st = n6_boot_iter_open(&b);
    if (st != NINLIL_N6_OK) {
        return n6_boot_finish(&b, st);
    }
    {
        for (;;) {
            rc = n6_boot_next(&b, sc, &key, &val, &fail_st);
            if (rc == 0) {
                break;
            }
            if (rc < 0) {
                n6_boot_iter_close(&b);
                return n6_boot_finish(&b, fail_st);
            }
            if (n6_boot_is_rt_key(sc->kbuf, key.length) != 0) {
                n6_boot_al_t *al;
                if (ninlil_n6_decode_n6rt_key(sc->kbuf, key.length, &sc->rk)
                        != NINLIL_N6_CODEC_OK
                    || ninlil_n6_decode_n6rt_value(sc->vbuf, val.length, &sc->u.rtv)
                        != NINLIL_N6_CODEC_OK
                    || sc->rk.context_id != sc->u.rtv.context_id
                    || sc->rk.membership_epoch != sc->u.rtv.membership_epoch
                    || sc->rk.layer_code != sc->u.rtv.layer_code
                    || sc->rk.direction_code != sc->u.rtv.direction_code
                    || sc->rk.alloc_side != sc->u.rtv.alloc_side) {
                    b.corrupt = 1;
                    break;
                }
                al = n6_boot_find_al(
                    n6, b.n_al_loaded, sc->rk.layer_code, sc->rk.alloc_side,
                    sc->rk.membership_epoch, sc->rk.ns_fingerprint12);
                if (al == NULL) {
                    b.corrupt = 1; /* orphan RT */
                    break;
                }
                if (al->floor != 0u && sc->rk.context_id >= al->floor) {
                    b.corrupt = 1;
                    break;
                }
                /* Decrement declared retired_count on each matching RT. */
                if (al->retired_count == 0u) {
                    b.corrupt = 1; /* more RT than declared */
                    break;
                }
                al->retired_count = (uint16_t)(al->retired_count - 1u);
                /* live↔RT same M (any side/dir) after AL receiver join */
                for (i = 0u; i < b.n_active; ++i) {
                    n6_boot_active_meta_t *m = n6_boot_active_meta_at(n6, i);
                    n6_boot_al_t *aal;
                    if ((m->flags & N6_BA_COMPLETE) == 0u
                        || m->context_id != sc->rk.context_id) {
                        continue;
                    }
                    aal = n6_boot_active_al(n6, b.n_al_loaded, m);
                    if (aal == NULL
                        || aal->membership_epoch != sc->rk.membership_epoch
                        || aal->layer_code != sc->rk.layer_code) {
                        continue;
                    }
                    if (ninlil_n6_ns_fingerprint12(
                            &n6->crypto, aal->receiver_node_id, sc->rk.layer_code,
                            sc->rk.membership_epoch, sc->rk.alloc_side, sc->re_nsfp)
                        != 0) {
                        b.corrupt = 1;
                        break;
                    }
                    if (memcmp(sc->re_nsfp, sc->rk.ns_fingerprint12, 12u) == 0) {
                        b.corrupt = 1; /* same M live + RT */
                        break;
                    }
                }
                if (b.corrupt != 0) {
                    break;
                }
                /*
                 * RT last_kgen → HW requirement: raise existing or create new
                 * for retired-only scopes that P1 never saw (no live lanes).
                 * scope_digest28 provider failure is CORRUPT (never silent skip).
                 */
                if (ninlil_n6_scope_digest28(
                        &n6->crypto, n6->local_node_id, sc->rk.layer_code,
                        sc->rk.direction_code, sc->rk.membership_epoch,
                        al->receiver_node_id, sc->want_scope)
                    != 0) {
                    b.corrupt = 1;
                    break;
                }
                {
                    int found_hr = 0;
                    for (j = 0u; j < b.n_hw_req; ++j) {
                        n6_boot_hw_req_t *hr = n6_boot_hw_slot(n6, j);
                        if (hr == NULL || hr->used == 0u
                            || memcmp(hr->scope28, sc->want_scope, 28u)
                                != 0) {
                            continue;
                        }
                        /* Digest collision across distinct layer/direction. */
                        if (hr->layer_code != sc->rk.layer_code
                            || hr->direction_code != sc->rk.direction_code) {
                            b.corrupt = 1;
                            break;
                        }
                        if (sc->u.rtv.last_key_generation_high_water
                            > hr->min_kgen) {
                            hr->min_kgen =
                                sc->u.rtv.last_key_generation_high_water;
                        }
                        found_hr = 1;
                        break;
                    }
                    if (b.corrupt != 0) {
                        break;
                    }
                    if (found_hr == 0) {
                        n6_boot_hw_req_t *hr = n6_boot_hw_slot(n6, b.n_hw_req);
                        if (hr == NULL) {
                            b.corrupt = 1;
                            break;
                        }
                        ninlil_n6_secure_zero(hr, sizeof(*hr));
                        hr->used = 1u;
                        hr->layer_code = sc->rk.layer_code;
                        hr->direction_code = sc->rk.direction_code;
                        hr->min_kgen = sc->u.rtv.last_key_generation_high_water;
                        (void)memcpy(hr->scope28, sc->want_scope, 28u);
                        b.n_hw_req += 1u;
                    }
                }
            } else if (n6_boot_is_cf_key(sc->kbuf, key.length) != 0) {
                /*
                 * N6CF is an active context fence: coexists with complete live
                 * lane set until reclaim. Require exact joined live active,
                 * mark once (bit7); reject orphan / duplicate CF. live_hit is
                 * required — do not reject it.
                 */
                n6_boot_active_meta_t *hit = NULL;
                n6_boot_active_t *hit_pay = NULL;
                if (ninlil_n6_decode_n6cf_key(sc->kbuf, key.length, &sc->ck)
                        != NINLIL_N6_CODEC_OK
                    || ninlil_n6_decode_n6cf_value(sc->vbuf, val.length, &sc->u.cfv)
                        != NINLIL_N6_CODEC_OK
                    || sc->ck.context_id != sc->u.cfv.context_id
                    || sc->ck.membership_epoch != sc->u.cfv.membership_epoch
                    || sc->ck.layer_code != sc->u.cfv.layer_code
                    || sc->ck.direction_code != sc->u.cfv.direction_code
                    || sc->ck.alloc_side != sc->u.cfv.alloc_side) {
                    b.corrupt = 1;
                    break;
                }
                if (n6_boot_find_al(
                        n6, b.n_al_loaded, sc->ck.layer_code, sc->ck.alloc_side,
                        sc->ck.membership_epoch, sc->ck.ns_fingerprint12)
                    == NULL) {
                    b.corrupt = 1; /* CF outside any AL */
                    break;
                }
                for (i = 0u; i < b.n_active; ++i) {
                    n6_boot_active_meta_t *m = n6_boot_active_meta_at(n6, i);
                    n6_boot_al_t *aal;
                    n6_boot_active_t *ap;
                    if ((m->flags & N6_BA_COMPLETE) == 0u
                        || m->context_id != sc->ck.context_id
                        || m->direction_code != sc->ck.direction_code) {
                        continue;
                    }
                    aal = n6_boot_active_al(n6, b.n_al_loaded, m);
                    if (aal == NULL
                        || aal->membership_epoch != sc->ck.membership_epoch
                        || aal->layer_code != sc->ck.layer_code
                        || aal->alloc_side != sc->ck.alloc_side
                        || memcmp(aal->nsfp, sc->ck.ns_fingerprint12, 12u)
                            != 0) {
                        continue;
                    }
                    ap = n6_boot_active_payload_at(n6, i);
                    /* CF binding_digest12 must equal complete live set prefix. */
                    if (memcmp(
                            sc->u.cfv.binding_digest12, ap->binding_digest32, 12u)
                        != 0) {
                        b.corrupt = 1;
                        break;
                    }
                    hit = m;
                    hit_pay = ap;
                    break;
                }
                if (b.corrupt != 0) {
                    break;
                }
                if (hit == NULL || hit_pay == NULL) {
                    b.corrupt = 1; /* orphan CF (no complete live set) */
                    break;
                }
                if ((hit->flags & N6_BA_CF) != 0u) {
                    b.corrupt = 1; /* duplicate CF for same live active */
                    break;
                }
                hit->flags |= N6_BA_CF;
            }
        }
        n6_boot_iter_close(&b);
        if (b.corrupt != 0) {
            return n6_boot_finish(&b, NINLIL_N6_CORRUPT);
        }
        /* Every AL retired_count decremented to 0 (exact declared match). */
        for (i = 0u; i < b.n_al_loaded; ++i) {
            n6_boot_al_t *al = n6_boot_al_slot(n6, i);
            if (al != NULL && al->used != 0u && al->retired_count != 0u) {
                return n6_boot_finish(&b, NINLIL_N6_CORRUPT);
            }
        }
    }

    /* ========== P3: HW exact requirement join / highwater / orphan0 / collision ========== */
    st = n6_boot_iter_open(&b);
    if (st != NINLIL_N6_OK) {
        return n6_boot_finish(&b, st);
    }
    {
        for (;;) {
            rc = n6_boot_next(&b, sc, &key, &val, &fail_st);
            if (rc == 0) {
                break;
            }
            if (rc < 0) {
                n6_boot_iter_close(&b);
                return n6_boot_finish(&b, fail_st);
            }
            if (key.length != NINLIL_N6_HW_KEY_BYTES) {
                continue;
            }
            if (ninlil_n6_decode_n6hw_key(sc->kbuf, key.length, &sc->hk)
                    != NINLIL_N6_CODEC_OK
                || ninlil_n6_decode_n6hw_value(sc->vbuf, val.length, &sc->u.hv)
                    != NINLIL_N6_CODEC_OK) {
                b.corrupt = 1;
                break;
            }
            {
                int matched = 0;
                int scope_owner = 0;
                for (j = 0u; j < b.n_hw_req; ++j) {
                    n6_boot_hw_req_t *hr = n6_boot_hw_slot(n6, j);
                    if (hr == NULL || hr->used == 0u) {
                        continue;
                    }
                    if (memcmp(hr->scope28, sc->hk.scope_digest28, 28u) == 0) {
                        if (hr->layer_code != sc->hk.layer_code
                            || hr->direction_code != sc->hk.direction_code) {
                            b.corrupt = 1; /* scope hash collision across scopes */
                            break;
                        }
                        if (sc->u.hv.high_water_key_generation < hr->min_kgen) {
                            b.corrupt = 1;
                            break;
                        }
                        if (hr->sat != 0u) {
                            b.corrupt = 1; /* required exactly 1 */
                            break;
                        }
                        hr->sat = 1u;
                        matched = 1;
                        break;
                    }
                }
                if (b.corrupt != 0) {
                    break;
                }
                /*
                 * Distinct full HW scopes must not share digest.
                 * Full scope = (local, layer, direction, epoch, receiver); excludes
                 * alloc_side — opposite-side AL rows with same receiver/epoch/layer/dir
                 * are one scope (dedupe), not a collision.
                 */
                for (i = 0u; i < b.n_al_loaded; ++i) {
                    n6_boot_al_t *al = n6_boot_al_slot(n6, i);
                    int seen_scope;
                    uint32_t pi;
                    if (al == NULL || al->used == 0u) {
                        continue;
                    }
                    if (al->layer_code != sc->hk.layer_code) {
                        continue;
                    }
                    if (ninlil_n6_scope_digest28(
                            &n6->crypto, n6->local_node_id, al->layer_code,
                            sc->hk.direction_code, al->membership_epoch,
                            al->receiver_node_id, sc->want_scope)
                        != 0) {
                        continue;
                    }
                    if (memcmp(sc->want_scope, sc->hk.scope_digest28, 28u) != 0) {
                        continue;
                    }
                    /* Dedupe identical full scopes across AL rows (e.g. both sides). */
                    seen_scope = 0;
                    for (pi = 0u; pi < i; ++pi) {
                        n6_boot_al_t *prev = n6_boot_al_slot(n6, pi);
                        if (prev == NULL || prev->used == 0u) {
                            continue;
                        }
                        if (prev->layer_code == al->layer_code
                            && prev->membership_epoch == al->membership_epoch
                            && memcmp(prev->receiver_node_id, al->receiver_node_id,
                                   16u)
                                == 0) {
                            seen_scope = 1;
                            break;
                        }
                    }
                    if (seen_scope == 0) {
                        scope_owner += 1;
                    }
                }
                if (scope_owner > 1) {
                    b.corrupt = 1;
                    break;
                }
                if (matched == 0) {
                    b.corrupt = 1;
                    break;
                }
            }
        }
        n6_boot_iter_close(&b);
        if (b.corrupt != 0) {
            return n6_boot_finish(&b, NINLIL_N6_CORRUPT);
        }
        for (j = 0u; j < b.n_hw_req; ++j) {
            n6_boot_hw_req_t *hr = n6_boot_hw_slot(n6, j);
            if (hr != NULL && hr->used != 0u && hr->sat == 0u) {
                return n6_boot_finish(&b, NINLIL_N6_CORRUPT); /* missing required HW */
            }
        }
    }

    /*
     * Retired-only durable (no live actives, only AL+RT+HW) is valid DORMANT.
     * Reject non-empty scan that never joined any AL (garbage / incomplete).
     * Empty durable (any==0) is happy path BOOTED after all four passes.
     */
    if (b.any != 0 && b.n_al_loaded == 0u) {
        return n6_boot_finish(&b, NINLIL_N6_CORRUPT);
    }
    if (b.any == 0) {
        return n6_boot_finish(&b, NINLIL_N6_OK);
    }
    return n6_boot_finish(&b, NINLIL_N6_BOOT_DORMANT);
}

/* install/tx/rx: see dual-compile block after recover */

/* ---- recover_cu with correct classification ---- */

static void n6_apply_cu_post(ninlil_n6_t *n6, ninlil_n6_cu_class_t cls)
{
    uint32_t i;
    if (cls == NINLIL_N6_CU_ALL_PROPOSED) {
        for (i = 0u; i < n6->cu.n_keys; ++i) {
            n6_cu_entry_t *e = &n6->cu.entries[i];
            if (e->slot_index >= n6->slot_count) {
                continue;
            }
            n6_slot_t *s = &n6->cells[e->slot_index].live;
            if (e->post == N6_CU_POST_TX_LIMIT && e->lane_idx < 3u) {
                s->tx_ram_next[e->lane_idx] = e->post_u64_b;
                s->tx_ram_limit[e->lane_idx] = e->post_u64_a;
            }
            if (e->post == N6_CU_POST_RX_ACCEPT && e->lane_idx < 3u) {
                /* post_a = live_reserved; post_b = ram_highest; bitmap cleared on
                 * proposed reservation advance (docs/30 §10 CU committed path). */
                s->rx_live_reserved[e->lane_idx] = e->post_u64_a;
                s->rx_boot_floor[e->lane_idx] = e->post_u64_a;
                s->rx_ram_highest[e->lane_idx] = e->post_u64_a;
                s->rx_bitmap[e->lane_idx] = 0u;
            }
        }
        if (n6->cu.pending_install != 0) {
            /*
             * Install CU ALL_PROPOSED: durable applied, secrets must not be
             * discarded into READY. Drop pending handle/secret material and
             * leave DORMANT_DURABLE_NO_SECRET (M5 resume required).
             */
            ninlil_n6_secure_zero(&n6->cu.pending_slot, sizeof(n6->cu.pending_slot));
            n6->cu.pending_install = 0;
            n6->state = NINLIL_N6_STATE_DORMANT_DURABLE_NO_SECRET;
        }
    } else if (cls == NINLIL_N6_CU_ALL_OLD) {
        /* RAM stays at pre-image; clear pending install → prior boot state */
        if (n6->cu.pending_install != 0) {
            ninlil_n6_secure_zero(&n6->cu.pending_slot, sizeof(n6->cu.pending_slot));
            n6->cu.pending_install = 0;
            n6->state = NINLIL_N6_STATE_BOOTED;
        }
    }
}

/* recover_cu: rollback child → close shared → fence (CORRUPT path). */
static ninlil_n6_status_t n6_cu_rb_close_corrupt(
    ninlil_n6_t *n6, n6_txn_t *t, const char *hint)
{
    ninlil_n6_status_t rbs = n6_prov_rollback(n6, t);
    n6_storage_force_close(n6);
    if (n6->state != NINLIL_N6_STATE_FENCED) {
        n6_enter_fenced(n6);
    }
    /* Primary is always CORRUPT; rb failure is absorbed into same fence. */
    n6_set_err(n6, NINLIL_N6_CORRUPT, NINLIL_N6_REASON_CORRUPT,
        rbs != NINLIL_N6_OK ? "cu_rb" : hint);
    n6_leave(n6);
    return NINLIL_N6_CORRUPT;
}

/* Operational get/begin: rollback → close → NEED_OPEN (no fence). */
static ninlil_n6_status_t n6_cu_rb_close_retry(ninlil_n6_t *n6, n6_txn_t *t)
{
    ninlil_n6_status_t rbs = n6_prov_rollback(n6, t);
    n6_storage_force_close(n6);
    if (rbs != NINLIL_N6_OK) {
        if (n6->state != NINLIL_N6_STATE_FENCED) {
            n6_enter_fenced(n6);
        }
        n6_set_err(n6, NINLIL_N6_CORRUPT, NINLIL_N6_REASON_CORRUPT, "cu_rb");
        n6_leave(n6);
        return NINLIL_N6_CORRUPT;
    }
    n6->cu.phase = N6_CU_PHASE_NEED_OPEN;
    n6_set_err(n6, NINLIL_N6_STORAGE, NINLIL_N6_REASON_STORAGE, "cu_retry");
    n6_leave(n6);
    return NINLIL_N6_STORAGE;
}

/*
 * CU recovery RO begin — docs/30 §9.3 recover_namespace_commit_unknown.
 * Does NOT use generic n6_prov_begin (which maps NO_SPACE→CAPACITY and
 * OK+NULL fences without closing the shared handle).
 *
 * - BUSY/IO_ERROR + out_txn==NULL only: close handle once, NEED_OPEN, plan
 *   retained, STORAGE retry.
 * - Else (NO_SPACE/BTS/NOT_FOUND/CORRUPT/UNSUPPORTED/COMMIT_UNKNOWN/unknown,
 *   OK+NULL, nonOK+nonnull): if txn nonnull, rollback once and inspect; then
 *   close handle once, wipe plan/secrets via fence, CORRUPT.
 * - OK + valid txn only continues (t->live=1).
 * Does not n6_leave — caller owns leave.
 */
static ninlil_n6_status_t n6_cu_begin_ro(ninlil_n6_t *n6, n6_txn_t *t)
{
    ninlil_storage_status_t ss;

    if (t == NULL) {
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    t->h = NULL;
    t->live = 0;
    ss = n6->storage.begin(
        n6->storage.user, n6->storage_handle, NINLIL_STORAGE_READ_ONLY, &t->h);

    /* Retryable: operational + NULL txn only. */
    if ((ss == NINLIL_STORAGE_IO_ERROR || ss == NINLIL_STORAGE_BUSY)
        && t->h == NULL) {
        n6_storage_force_close(n6);
        n6->cu.phase = N6_CU_PHASE_NEED_OPEN;
        n6->stats.storage_fail += 1u;
        n6_set_err(n6, NINLIL_N6_STORAGE, NINLIL_N6_REASON_STORAGE, "cu_begin");
        return NINLIL_N6_STORAGE;
    }

    /* Success only when OK + non-NULL txn. */
    if (ss == NINLIL_STORAGE_OK && t->h != NULL) {
        t->live = 1;
        return NINLIL_N6_OK;
    }

    /*
     * All other shapes/statuses → CORRUPT fence after optional rollback.
     * Includes: OK+NULL, nonOK+nonnull, NO_SPACE/BTS/NOT_FOUND/CORRUPT/
     * UNSUPPORTED/COMMIT_UNKNOWN/unknown with NULL txn.
     */
    if (t->h != NULL) {
        ninlil_storage_status_t rbs =
            n6->storage.rollback(n6->storage.user, t->h);
        t->h = NULL;
        t->live = 0;
        if (rbs != NINLIL_STORAGE_OK) {
            n6_storage_force_close(n6);
            if (n6->state != NINLIL_N6_STATE_FENCED) {
                n6_enter_fenced(n6);
            }
            n6_set_err(n6, NINLIL_N6_CORRUPT, NINLIL_N6_REASON_CORRUPT,
                "cu_begin_rb");
            return NINLIL_N6_CORRUPT;
        }
    }
    n6_storage_force_close(n6);
    if (n6->state != NINLIL_N6_STATE_FENCED) {
        n6_enter_fenced(n6);
    }
    n6_set_err(n6, NINLIL_N6_CORRUPT, NINLIL_N6_REASON_CORRUPT, "cu_begin");
    return NINLIL_N6_CORRUPT;
}

ninlil_n6_status_t ninlil_n6_recover_cu(ninlil_n6_t *n6)
{
    ninlil_n6_status_t st = n6_enter(n6);
    n6_txn_t txn;
    uint32_t i;
    uint32_t n_old = 0u, n_prop = 0u, n_third = 0u;
    ninlil_n6_cu_class_t cls;
    ninlil_n6_status_t pst;
    uint32_t olen = 0u;

    if (st != NINLIL_N6_OK) {
        return st;
    }
    if (n6->cu.live == 0 || n6->cu.n_keys == 0u) {
        n6_leave(n6);
        return NINLIL_N6_INVALID_STATE;
    }

    /* COMMIT_UNKNOWN left handle open at NEED_CLOSE_OLD — close exactly once. */
    if (n6->cu.phase == N6_CU_PHASE_NONE
        || n6->cu.phase == N6_CU_PHASE_NEED_CLOSE_OLD) {
        n6->cu.phase = N6_CU_PHASE_NEED_CLOSE_OLD;
        n6_storage_force_close(n6);
        n6->cu.phase = N6_CU_PHASE_NEED_OPEN;
    }

    if (n6->cu.phase == N6_CU_PHASE_NEED_OPEN) {
        /* Dedicated CU open map — not generic n6_need_storage. */
        st = n6_cu_open_storage(n6);
        if (st != NINLIL_N6_OK) {
            n6_leave(n6);
            return st;
        }
        n6->cu.phase = N6_CU_PHASE_READ_CLASSIFY;
    }

    /* CU-specific begin (docs/30 §9.3) — not generic n6_prov_begin. */
    pst = n6_cu_begin_ro(n6, &txn);
    if (pst != NINLIL_N6_OK) {
        n6_leave(n6);
        return pst;
    }

    for (i = 0u; i < n6->cu.n_keys; ++i) {
        n6_cu_entry_t *e = &n6->cu.entries[i];
        uint8_t cur[68];
        ninlil_bytes_view_t kb;
        kb.data = e->key;
        kb.length = (uint32_t)e->klen;
        pst = n6_prov_get(n6, &txn, kb, cur, (uint32_t)sizeof(cur), &olen,
            N6_GET_ALLOW_MISS);
        if (pst == NINLIL_N6_NOT_FOUND) {
            if (e->op == N6_CU_OP_DELETE) {
                if (e->old_present != 0) {
                    n_prop += 1u;
                } else {
                    n_old += 1u;
                }
            } else if (e->old_present == 0) {
                n_old += 1u;
            } else {
                n_third += 1u;
            }
            continue;
        }
        if (pst == NINLIL_N6_OK) {
            if (e->old_present != 0 && olen == e->old_vlen
                && memcmp(cur, e->old_val, e->old_vlen) == 0) {
                n_old += 1u;
            } else if (e->op == N6_CU_OP_PUT && olen == e->prop_vlen
                && memcmp(cur, e->prop_val, e->prop_vlen) == 0) {
                n_prop += 1u;
            } else {
                n_third += 1u;
            }
            continue;
        }
        if (pst == NINLIL_N6_STORAGE) {
            return n6_cu_rb_close_retry(n6, &txn);
        }
        /* CAPACITY/BTS and other non-OK on CU classify re-read → CORRUPT */
        return n6_cu_rb_close_corrupt(n6, &txn, "cu_get");
    }

    pst = n6_prov_rollback(n6, &txn);
    if (pst != NINLIL_N6_OK) {
        n6_storage_force_close(n6);
        if (n6->state != NINLIL_N6_STATE_FENCED) {
            n6_enter_fenced(n6);
        }
        n6_set_err(n6, NINLIL_N6_CORRUPT, NINLIL_N6_REASON_CORRUPT, "cu_final_rb");
        n6_leave(n6);
        return NINLIL_N6_CORRUPT;
    }

    if (n_third > 0u) {
        cls = NINLIL_N6_CU_THIRD;
    } else if (n_old > 0u && n_prop > 0u) {
        cls = NINLIL_N6_CU_MIXED;
    } else if (n_prop > 0u) {
        cls = NINLIL_N6_CU_ALL_PROPOSED;
    } else {
        cls = NINLIL_N6_CU_ALL_OLD;
    }
    n6->last_error.last_cu_class = cls;

    if (cls == NINLIL_N6_CU_MIXED || cls == NINLIL_N6_CU_THIRD) {
        n6_storage_force_close(n6);
        n6_enter_fenced(n6);
        n6_set_err(n6, NINLIL_N6_FENCED, NINLIL_N6_REASON_CU_CLASS, "mixed_third");
        n6_leave(n6);
        return NINLIL_N6_FENCED;
    }

    n6_apply_cu_post(n6, cls);
    if (cls == NINLIL_N6_CU_ALL_PROPOSED) {
        uint32_t j;
        for (j = 0u; j < NINLIL_N6_MAX_LIVE_TICKETS; ++j) {
            ninlil_n6_secure_zero(&n6->tickets[j], sizeof(n6->tickets[j]));
        }
        for (j = 0u; j < NINLIL_N6_MAX_LIVE_LEASES; ++j) {
            ninlil_n6_secure_zero(&n6->leases[j], sizeof(n6->leases[j]));
        }
    }
    n6_cu_clear(&n6->cu);
    if (n6->state != NINLIL_N6_STATE_DORMANT_DURABLE_NO_SECRET
        && n6->state != NINLIL_N6_STATE_BOOTED) {
        n6->state = NINLIL_N6_STATE_READY;
    }
    n6->stats.cu_recover_ok += 1u;
    n6_leave(n6);
    return NINLIL_N6_OK;
}


/* ===== Durable install/TX/RX engine (production-compiled; fixture provenance gated) ===== */

/* Returns NULL; if canary broken sets *out_corrupt=1 (CORRUPT fence, not NOT_FOUND). */
static n6_slot_t *n6_find_handle(
    ninlil_n6_t *n6, ninlil_n6_handle_t h, int *out_corrupt)
{
    uint32_t i;
    if (out_corrupt != NULL) {
        *out_corrupt = 0;
    }
    if (h == 0u) {
        return NULL;
    }
    for (i = 0u; i < n6->slot_count; ++i) {
        if (n6->cells[i].live.canary0 != N6_CANARY
            || n6->cells[i].live.canary1 != N6_CANARY) {
            if (out_corrupt != NULL) {
                *out_corrupt = 1;
            }
            n6_enter_fenced(n6);
            return NULL;
        }
        if (n6->cells[i].live.live != 0u && n6->cells[i].live.handle == h) {
            return &n6->cells[i].live;
        }
    }
    return NULL;
}

static uint32_t n6_slot_index(ninlil_n6_t *n6, n6_slot_t *s)
{
    uintptr_t base = (uintptr_t)n6->cells;
    uintptr_t p = (uintptr_t)s;
    return (uint32_t)((p - base) / sizeof(n6_pool_cell_t));
}


static void n6_slot_clear_free(n6_slot_t *s)
{
    ninlil_n6_secure_zero(s, sizeof(*s));
    s->canary0 = N6_CANARY;
    s->canary1 = N6_CANARY;
    s->live = 0u;
}

/*
 * Free slot: live=0 with valid canaries (init/reclaim). Broken canary → CORRUPT
 * fence, never treated as NOT_FOUND. Never zero-hide corruption.
 */
static n6_slot_t *n6_alloc_slot(ninlil_n6_t *n6, int *out_corrupt)
{
    uint32_t i;
    if (out_corrupt != NULL) {
        *out_corrupt = 0;
    }
    for (i = 0u; i < n6->slot_count; ++i) {
        if (n6->cells[i].live.canary0 != N6_CANARY
            || n6->cells[i].live.canary1 != N6_CANARY) {
            if (out_corrupt != NULL) {
                *out_corrupt = 1;
            }
            n6_enter_fenced(n6);
            return NULL;
        }
        if (n6->cells[i].live.live != 0u) {
            continue;
        }
        n6_slot_clear_free(&n6->cells[i].live);
        return &n6->cells[i].live;
    }
    return NULL;
}

static int n6_lane_idx(uint8_t lane_kind)
{
    if (lane_kind == NINLIL_N6_LANE_HOP_DATA || lane_kind == NINLIL_N6_LANE_E2E) {
        return 0;
    }
    if (lane_kind == NINLIL_N6_LANE_HOP_ACK) {
        return 1;
    }
    return -1;
}

static int n6_lane_ok_for_slot(const n6_slot_t *s, uint8_t lane_kind)
{
    if (s->layer_code == NINLIL_N6_LAYER_HOP) {
        return lane_kind == NINLIL_N6_LANE_HOP_DATA
            || lane_kind == NINLIL_N6_LANE_HOP_ACK;
    }
    if (s->layer_code == NINLIL_N6_LAYER_E2E) {
        return lane_kind == NINLIL_N6_LANE_E2E;
    }
    return 0;
}

static void n6_make_lane_key(
    const n6_slot_t *s, uint8_t lane_kind, ninlil_n6_lane_key_t *lk)
{
    ninlil_n6_secure_zero(lk, sizeof(*lk));
    lk->layer_code = s->layer_code;
    lk->kind_or_lane = lane_kind;
    lk->direction_code = s->direction_code;
    lk->context_id = s->context_id;
    (void)memcpy(lk->binding_digest32, s->binding_digest32, 32u);
    lk->key_generation = s->key_generation;
}

static ninlil_n6_status_t n6_cu_capture(
    ninlil_n6_t *n6,
    n6_cu_op_t op,
    n6_cu_post_t post,
    uint32_t slot_index,
    uint8_t lane_kind,
    uint8_t lane_idx,
    const uint8_t *key,
    size_t klen,
    const uint8_t *old_val,
    size_t old_vlen,
    int old_present,
    const uint8_t *prop_val,
    size_t prop_vlen,
    uint64_t post_a,
    uint64_t post_b)
{
    n6_cu_entry_t *e;
    if (n6->cu.n_keys >= NINLIL_N6_CU_PLAN_MAX_KEYS) {
        return NINLIL_N6_CAPACITY;
    }
    if (klen > 48u || prop_vlen > 68u || old_vlen > 68u) {
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    e = &n6->cu.entries[n6->cu.n_keys];
    ninlil_n6_secure_zero(e, sizeof(*e));
    e->op = op;
    e->post = post;
    e->slot_index = slot_index;
    e->lane_kind = lane_kind;
    e->lane_idx = lane_idx;
    (void)memcpy(e->key, key, klen);
    e->klen = klen;
    e->old_present = old_present;
    if (old_present != 0 && old_val != NULL) {
        (void)memcpy(e->old_val, old_val, old_vlen);
        e->old_vlen = old_vlen;
    }
    (void)memcpy(e->prop_val, prop_val, prop_vlen);
    e->prop_vlen = prop_vlen;
    e->post_u64_a = post_a;
    e->post_u64_b = post_b;
    n6->cu.n_keys += 1u;
    n6->cu.live = 1;
    n6->cu.phase = N6_CU_PHASE_NEED_CLOSE_OLD;
    return NINLIL_N6_OK;
}

static ninlil_n6_status_t n6_derive_lane_keys(
    ninlil_n6_t *n6, const n6_slot_t *slot, uint8_t lane_kind,
    uint8_t key16[16], uint8_t iv12[12])
{
    if (slot->layer_code == NINLIL_N6_LAYER_HOP) {
        ninlil_n6_hop_derived_keys_t hk;
        if (ninlil_n6_derive_hop_keys(
                &n6->crypto, slot->binding_digest32, slot->traffic_secret32, &hk)
            != 0) {
            return NINLIL_N6_CRYPTO;
        }
        if (lane_kind == NINLIL_N6_LANE_HOP_DATA) {
            (void)memcpy(key16, hk.data_key16, 16u);
            (void)memcpy(iv12, hk.data_iv12, 12u);
        } else if (lane_kind == NINLIL_N6_LANE_HOP_ACK) {
            (void)memcpy(key16, hk.ack_key16, 16u);
            (void)memcpy(iv12, hk.ack_iv12, 12u);
        } else {
            ninlil_n6_secure_zero(&hk, sizeof(hk));
            return NINLIL_N6_INVALID_ARGUMENT;
        }
        ninlil_n6_secure_zero(&hk, sizeof(hk));
        return NINLIL_N6_OK;
    }
    if (slot->layer_code == NINLIL_N6_LAYER_E2E
        && lane_kind == NINLIL_N6_LANE_E2E) {
        ninlil_n6_e2e_derived_keys_t ek;
        if (ninlil_n6_derive_e2e_keys(
                &n6->crypto, slot->binding_digest32, slot->traffic_secret32, &ek)
            != 0) {
            return NINLIL_N6_CRYPTO;
        }
        (void)memcpy(key16, ek.key16, 16u);
        (void)memcpy(iv12, ek.iv12, 12u);
        ninlil_n6_secure_zero(&ek, sizeof(ek));
        return NINLIL_N6_OK;
    }
    return NINLIL_N6_INVALID_ARGUMENT;
}

static void n6_nonce_apply_counter(uint8_t iv12[12], uint64_t counter)
{
    int i;
    for (i = 0; i < 8; ++i) {
        iv12[4 + i] ^= (uint8_t)((counter >> (56 - 8 * i)) & 0xffu);
    }
}

static int n6_capsule_ok(const ninlil_n6_install_capsule_t *c)
{
    if (c == NULL) return 0;
    if (c->layer_code != NINLIL_N6_LAYER_HOP && c->layer_code != NINLIL_N6_LAYER_E2E)
        return 0;
    if (c->direction_code > NINLIL_N6_DIR_RI) return 0;
    if (c->alloc_side != NINLIL_N6_ALLOC_INBOUND_RX
        && c->alloc_side != NINLIL_N6_ALLOC_OUTBOUND_TX) return 0;
    if (c->context_id == 0u || c->context_id == UINT32_MAX || c->key_generation == 0u)
        return 0;
    return 1;
}

static ninlil_n6_status_t n6_install_engine(
    ninlil_n6_t *n6, const ninlil_n6_install_capsule_t *cap, int hop,
    ninlil_n6_handle_t *out_h)
{
    n6_slot_t *slot;
    n6_txn_t wtxn;
    uint8_t nsfp[12], scope28[28], key[48], val[68], oldbuf[68];
    size_t klen = 0, vlen = 0;
    ninlil_bytes_view_t kb, vb;
    ninlil_n6_status_t cst, pst;
    uint32_t olen = 0u;
    int lanes, li;
    uint8_t kinds[2];
    uint32_t si;

    if (out_h == NULL || !n6_capsule_ok(cap)) return NINLIL_N6_INVALID_ARGUMENT;
    *out_h = 0u;
    if (n6->state != NINLIL_N6_STATE_BOOTED && n6->state != NINLIL_N6_STATE_READY)
        return NINLIL_N6_INVALID_STATE;
    if (n6->stamp_bound == 0) return NINLIL_N6_INVALID_STATE;
    if (cap->provenance == NINLIL_N6_PROVENANCE_M4_AUTHENTICATED) {
        /* No production M4 capsule adapter yet — fail closed at boundary. */
        n6->stats.install_fail++;
        n6_set_err(n6, NINLIL_N6_M4_REQUIRED, NINLIL_N6_REASON_M4, "m4");
        return NINLIL_N6_M4_REQUIRED;
    }
    if (cap->provenance != NINLIL_N6_PROVENANCE_FIXTURE_ONLY) {
        n6->stats.install_fail++;
        return NINLIL_N6_INVALID_ARGUMENT;
    }
#if !defined(NINLIL_N6_TEST_BUILD)
    /* FIXTURE_ONLY rejected outside test-build TU. */
    n6->stats.install_fail++;
    n6_set_err(n6, NINLIL_N6_INVALID_ARGUMENT, NINLIL_N6_REASON_PROVENANCE,
        "no_fixture_in_production");
    return NINLIL_N6_INVALID_ARGUMENT;
#endif
    /* Fixture install requires bound local identity matching capsule. */
    if (n6->local_id_bound == 0
        || memcmp(n6->local_node_id, cap->local_node_id, 16u) != 0) {
        n6->stats.install_fail++;
        n6_set_err(n6, NINLIL_N6_M4_REQUIRED, NINLIL_N6_REASON_LOCAL_IDENTITY, "local_id");
        return NINLIL_N6_M4_REQUIRED;
    }
    if ((hop && cap->layer_code != NINLIL_N6_LAYER_HOP)
        || (!hop && cap->layer_code != NINLIL_N6_LAYER_E2E))
        return NINLIL_N6_INVALID_ARGUMENT;
    if (ninlil_n6_ns_fingerprint12(&n6->crypto, cap->receiver_node_id,
            cap->layer_code, cap->membership_epoch, cap->alloc_side, nsfp) != 0
        || ninlil_n6_scope_digest28(&n6->crypto, cap->local_node_id,
            cap->layer_code, cap->direction_code, cap->membership_epoch,
            cap->receiver_node_id, scope28) != 0)
        return NINLIL_N6_CRYPTO;
    /* RAM collision: full NS identity (nsfp, epoch, alloc_side, layer, cid) */
    {
        uint32_t i;
        for (i = 0; i < n6->slot_count; ++i) {
            if (n6->cells[i].live.live && n6->cells[i].live.context_id == cap->context_id
                && n6->cells[i].live.membership_epoch == cap->membership_epoch
                && n6->cells[i].live.layer_code == cap->layer_code
                && n6->cells[i].live.alloc_side == cap->alloc_side
                && memcmp(n6->cells[i].live.ns_fingerprint12, nsfp, 12u) == 0) {
                return NINLIL_N6_INVALID_ARGUMENT;
            }
        }
    }
    {
        ninlil_n6_status_t ost = n6_need_storage(n6);
        if (ost != NINLIL_N6_OK) return ost;
    }
    n6_cu_clear(&n6->cu);

    if (hop) { lanes = 2; kinds[0] = NINLIL_N6_LANE_HOP_DATA; kinds[1] = NINLIL_N6_LANE_HOP_ACK; }
    else { lanes = 1; kinds[0] = NINLIL_N6_LANE_E2E; kinds[1] = 0; }

    {
        uint32_t need_free = hop ? 4u : 3u;
        ninlil_n6_status_t capst = n6_require_install_capacity(n6, need_free);
        if (capst != NINLIL_N6_OK) return capst;
    }

    /*
     * §5.3.1.8 RO precheck (mutation 0) BEFORE slot allocation so fail paths
     * never leave a half-initialized canary'd free slot.
     */
    {
        n6_txn_t ro;
        ninlil_n6_al_value_t av_pre;
        ninlil_n6_hw_value_t hv_pre;
        int al_present = 0, hw_present = 0;
        uint64_t hw_floor = 0u;
        pst = n6_prov_begin(n6, NINLIL_STORAGE_READ_ONLY, &ro);
        if (pst != NINLIL_N6_OK) {
            return pst;
        }
        for (li = 0; li < lanes; ++li) {
            ninlil_n6_lane_key_t lk;
            ninlil_n6_secure_zero(&lk, sizeof(lk));
            lk.layer_code = cap->layer_code;
            lk.kind_or_lane = kinds[li];
            lk.direction_code = cap->direction_code;
            lk.context_id = cap->context_id;
            memcpy(lk.binding_digest32, cap->binding_digest32, 32);
            lk.key_generation = cap->key_generation;
            if (ninlil_n6_encode_lane_key(&lk, key, sizeof(key), &klen)
                != NINLIL_N6_CODEC_OK) {
                return n6_prov_fail(n6, &ro, NINLIL_N6_CORRUPT, 0);
            }
            kb.data = key;
            kb.length = (uint32_t)klen;
            pst = n6_prov_get(n6, &ro, kb, oldbuf, (uint32_t)sizeof(oldbuf),
                &olen, N6_GET_ALLOW_MISS);
            if (pst == NINLIL_N6_OK) {
                return n6_prov_fail(n6, &ro, NINLIL_N6_INVALID_ARGUMENT, 0);
            }
            if (pst != NINLIL_N6_NOT_FOUND) {
                return n6_prov_fail(n6, &ro, pst, 0);
            }
        }
        {
            ninlil_n6_al_key_t ak;
            ninlil_n6_secure_zero(&ak, sizeof(ak));
            ak.rec_kind = NINLIL_N6_REC_KIND_AL;
            ak.layer_code = cap->layer_code;
            ak.alloc_side = cap->alloc_side;
            ak.membership_epoch = cap->membership_epoch;
            memcpy(ak.ns_fingerprint12, nsfp, 12);
            if (ninlil_n6_encode_n6al_key(&ak, key, sizeof(key), &klen)
                != NINLIL_N6_CODEC_OK) {
                return n6_prov_fail(n6, &ro, NINLIL_N6_CORRUPT, 0);
            }
            kb.data = key;
            kb.length = (uint32_t)klen;
            pst = n6_prov_get(n6, &ro, kb, oldbuf, (uint32_t)sizeof(oldbuf),
                &olen, N6_GET_ALLOW_MISS);
            if (pst == NINLIL_N6_OK) {
                al_present = 1;
                if (ninlil_n6_decode_n6al_value(oldbuf, olen, &av_pre)
                    != NINLIL_N6_CODEC_OK) {
                    return n6_prov_fail(n6, &ro, NINLIL_N6_CORRUPT, 0);
                }
                if (av_pre.active_count >= 0xffffu
                    || (uint32_t)av_pre.active_count + 1u > n6->slot_count) {
                    return n6_prov_fail(n6, &ro, NINLIL_N6_CAPACITY, 0);
                }
                if (cap->alloc_side == NINLIL_N6_ALLOC_INBOUND_RX) {
                    if (av_pre.next_free_or_peer_floor == 0u
                        || cap->context_id != av_pre.next_free_or_peer_floor) {
                        return n6_prov_fail(
                            n6, &ro, NINLIL_N6_INVALID_ARGUMENT, 0);
                    }
                } else {
                    if (av_pre.next_free_or_peer_floor != 0u
                        && cap->context_id < av_pre.next_free_or_peer_floor) {
                        return n6_prov_fail(
                            n6, &ro, NINLIL_N6_INVALID_ARGUMENT, 0);
                    }
                    if (cap->context_id == UINT32_MAX) {
                        return n6_prov_fail(
                            n6, &ro, NINLIL_N6_INVALID_ARGUMENT, 0);
                    }
                }
            } else if (pst == NINLIL_N6_NOT_FOUND) {
                if (cap->alloc_side == NINLIL_N6_ALLOC_INBOUND_RX
                    && cap->context_id != 1u) {
                    return n6_prov_fail(n6, &ro, NINLIL_N6_INVALID_ARGUMENT, 0);
                }
            } else {
                return n6_prov_fail(n6, &ro, pst, 0);
            }
        }
        {
            ninlil_n6_hw_key_t hk;
            ninlil_n6_secure_zero(&hk, sizeof(hk));
            hk.rec_kind = NINLIL_N6_REC_KIND_HW;
            hk.layer_code = cap->layer_code;
            hk.direction_code = cap->direction_code;
            memcpy(hk.scope_digest28, scope28, 28);
            if (ninlil_n6_encode_n6hw_key(&hk, key, sizeof(key), &klen)
                != NINLIL_N6_CODEC_OK) {
                return n6_prov_fail(n6, &ro, NINLIL_N6_CORRUPT, 0);
            }
            kb.data = key;
            kb.length = (uint32_t)klen;
            pst = n6_prov_get(n6, &ro, kb, oldbuf, (uint32_t)sizeof(oldbuf),
                &olen, N6_GET_ALLOW_MISS);
            if (pst == NINLIL_N6_OK) {
                hw_present = 1;
                if (ninlil_n6_decode_n6hw_value(oldbuf, olen, &hv_pre)
                    != NINLIL_N6_CODEC_OK) {
                    return n6_prov_fail(n6, &ro, NINLIL_N6_CORRUPT, 0);
                }
                hw_floor = hv_pre.high_water_key_generation;
                if (cap->key_generation <= hw_floor) {
                    return n6_prov_fail(n6, &ro, NINLIL_N6_INVALID_ARGUMENT, 0);
                }
            } else if (pst != NINLIL_N6_NOT_FOUND) {
                return n6_prov_fail(n6, &ro, pst, 0);
            }
        }
        pst = n6_prov_rollback(n6, &ro);
        if (pst != NINLIL_N6_OK) {
            n6_storage_force_close(n6);
            if (n6->state != NINLIL_N6_STATE_FENCED) {
                n6_enter_fenced(n6);
            }
            n6_set_err(n6, NINLIL_N6_CORRUPT, NINLIL_N6_REASON_CORRUPT, "install_ro_rb");
            return NINLIL_N6_CORRUPT;
        }
        (void)al_present;
        (void)hw_present;
    }

    {
        {
            uint32_t li_c = 0u, si_c;
            for (si_c = 0u; si_c < n6->slot_count; ++si_c) {
                if (n6->cells[si_c].live.live != 0u) {
                    li_c += 1u;
                }
            }
            if (li_c + 1u > n6->slot_count) {
                n6_set_err(n6, NINLIL_N6_CAPACITY, NINLIL_N6_REASON_CAPACITY,
                    "ns_active");
                return NINLIL_N6_CAPACITY;
            }
        }
        int corrupt_slot = 0;
        slot = n6_alloc_slot(n6, &corrupt_slot);
        if (corrupt_slot != 0) {
            n6_set_err(n6, NINLIL_N6_CORRUPT, NINLIL_N6_REASON_CORRUPT, "canary");
            return NINLIL_N6_CORRUPT;
        }
        if (!slot) return NINLIL_N6_CAPACITY;
    }
    si = n6_slot_index(n6, slot);

    pst = n6_prov_begin(n6, NINLIL_STORAGE_READ_WRITE, &wtxn);
    if (pst != NINLIL_N6_OK) {
        n6_slot_clear_free(slot);
        return pst;
    }

#define N6_INSTALL_FAIL(code)                                                  \
    do {                                                                       \
        ninlil_n6_status_t _ifst = n6_prov_fail(n6, &wtxn, (code), 1);         \
        n6_slot_clear_free(slot);                                              \
        return _ifst;                                                          \
    } while (0)

    for (li = 0; li < lanes; ++li) {
        ninlil_n6_lane_key_t lk;
        ninlil_n6_secure_zero(&lk, sizeof(lk));
        lk.layer_code = cap->layer_code;
        lk.kind_or_lane = kinds[li];
        lk.direction_code = cap->direction_code;
        lk.context_id = cap->context_id;
        memcpy(lk.binding_digest32, cap->binding_digest32, 32);
        lk.key_generation = cap->key_generation;
        if (ninlil_n6_encode_lane_key(&lk, key, sizeof(key), &klen) != NINLIL_N6_CODEC_OK) {
            N6_INSTALL_FAIL(NINLIL_N6_CORRUPT);
        }
        if (cap->alloc_side == NINLIL_N6_ALLOC_OUTBOUND_TX) {
            ninlil_n6_tx_value_t tv;
            ninlil_n6_secure_zero(&tv, sizeof(tv));
            tv.magic = NINLIL_N6_MAGIC_TX; tv.schema = NINLIL_N6_SCHEMA_LANE;
            tv.reserved_exclusive = 1; tv.key_generation = cap->key_generation;
            memcpy(tv.binding_digest_prefix16, cap->binding_digest32, 16);
            tv.membership_epoch = cap->membership_epoch;
            tv.alloc_side = NINLIL_N6_ALLOC_OUTBOUND_TX;
            memcpy(tv.ns_fingerprint12, nsfp, 12);
            if (ninlil_n6_encode_n6tx_value(&tv, val, sizeof(val), &vlen) != NINLIL_N6_CODEC_OK) {
                N6_INSTALL_FAIL(NINLIL_N6_CORRUPT);
            }
        } else {
            ninlil_n6_rx_value_t rv;
            ninlil_n6_secure_zero(&rv, sizeof(rv));
            rv.magic = NINLIL_N6_MAGIC_RX; rv.schema = NINLIL_N6_SCHEMA_LANE;
            rv.accept_reserved_through = 0; rv.key_generation = cap->key_generation;
            memcpy(rv.binding_digest_prefix16, cap->binding_digest32, 16);
            rv.membership_epoch = cap->membership_epoch;
            rv.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
            memcpy(rv.ns_fingerprint12, nsfp, 12);
            if (ninlil_n6_encode_n6rx_value(&rv, val, sizeof(val), &vlen) != NINLIL_N6_CODEC_OK) {
                N6_INSTALL_FAIL(NINLIL_N6_CORRUPT);
            }
        }
        kb.data = key; kb.length = (uint32_t)klen;
        pst = n6_prov_get(n6, &wtxn, kb, oldbuf, (uint32_t)sizeof(oldbuf),
            &olen, N6_GET_ALLOW_MISS);
        if (pst == NINLIL_N6_OK) {
            N6_INSTALL_FAIL(NINLIL_N6_INVALID_ARGUMENT);
        } else if (pst != NINLIL_N6_NOT_FOUND) {
            N6_INSTALL_FAIL(pst);
        }
        vb.data = val; vb.length = (uint32_t)vlen;
        pst = n6_prov_put(n6, &wtxn, kb, vb);
        if (pst != NINLIL_N6_OK) {
            N6_INSTALL_FAIL(pst);
        }
        if (n6_cu_capture(n6, N6_CU_OP_PUT, N6_CU_POST_NONE, si, kinds[li],
                (uint8_t)n6_lane_idx(kinds[li]), key, klen, NULL, 0,
                0, val, vlen, 0, 0) != NINLIL_N6_OK) {
            N6_INSTALL_FAIL(NINLIL_N6_CAPACITY);
        }
    }
    /* AL: checked increment / floor raise only (no reset/regress) */
    {
        ninlil_n6_al_key_t ak; ninlil_n6_al_value_t av;
        int old_present = 0;
        ninlil_n6_secure_zero(&ak, sizeof(ak));
        ak.rec_kind = NINLIL_N6_REC_KIND_AL;
        ak.layer_code = cap->layer_code;
        ak.alloc_side = cap->alloc_side;
        ak.membership_epoch = cap->membership_epoch;
        memcpy(ak.ns_fingerprint12, nsfp, 12);
        if (ninlil_n6_encode_n6al_key(&ak, key, sizeof(key), &klen) != NINLIL_N6_CODEC_OK) {
            N6_INSTALL_FAIL(NINLIL_N6_CORRUPT);
        }
        kb.data = key; kb.length = (uint32_t)klen;
        pst = n6_prov_get(n6, &wtxn, kb, oldbuf, (uint32_t)sizeof(oldbuf),
            &olen, N6_GET_ALLOW_MISS);
        if (pst == NINLIL_N6_OK) {
            old_present = 1;
            if (ninlil_n6_decode_n6al_value(oldbuf, olen, &av) != NINLIL_N6_CODEC_OK) {
                N6_INSTALL_FAIL(NINLIL_N6_CORRUPT);
            }
            if (av.active_count >= 0xffffu) {
                N6_INSTALL_FAIL(NINLIL_N6_CAPACITY);
            }
            av.active_count = (uint16_t)(av.active_count + 1u);
            if (cap->context_id + 1u > av.next_free_or_peer_floor)
                av.next_free_or_peer_floor = cap->context_id + 1u;
            if (av.next_free_or_peer_floor == 0) av.next_free_or_peer_floor = 1;
            av.last_alloc_authority_now_ms = n6->stamp.now_ms;
        } else if (pst == NINLIL_N6_NOT_FOUND) {
            ninlil_n6_secure_zero(&av, sizeof(av));
            av.magic = NINLIL_N6_MAGIC_AL; av.schema = NINLIL_N6_SCHEMA_AL;
            av.next_free_or_peer_floor = cap->context_id + 1u;
            if (av.next_free_or_peer_floor == 0) av.next_free_or_peer_floor = 1;
            av.active_count = 1;
            av.membership_epoch = cap->membership_epoch;
            av.last_alloc_authority_now_ms = n6->stamp.now_ms;
            memcpy(av.receiver_node_id, cap->receiver_node_id, 16);
            olen = 0u;
        } else {
            N6_INSTALL_FAIL(pst);
        }
        if (ninlil_n6_encode_n6al_value(&av, val, sizeof(val), &vlen) != NINLIL_N6_CODEC_OK) {
            N6_INSTALL_FAIL(NINLIL_N6_CORRUPT);
        }
        vb.data = val; vb.length = (uint32_t)vlen;
        pst = n6_prov_put(n6, &wtxn, kb, vb);
        if (pst != NINLIL_N6_OK) {
            N6_INSTALL_FAIL(pst);
        }
        if (n6_cu_capture(n6, N6_CU_OP_PUT, N6_CU_POST_NONE, si, 0, 0, key, klen,
                oldbuf, (size_t)olen, old_present, val, vlen, 0, 0) != NINLIL_N6_OK) {
            N6_INSTALL_FAIL(NINLIL_N6_CAPACITY);
        }
    }
    /* HW high-water: max only, never lower */
    {
        ninlil_n6_hw_key_t hk; ninlil_n6_hw_value_t hv;
        int old_present = 0;
        ninlil_n6_secure_zero(&hk, sizeof(hk));
        hk.rec_kind = NINLIL_N6_REC_KIND_HW;
        hk.layer_code = cap->layer_code;
        hk.direction_code = cap->direction_code;
        memcpy(hk.scope_digest28, scope28, 28);
        if (ninlil_n6_encode_n6hw_key(&hk, key, sizeof(key), &klen) != NINLIL_N6_CODEC_OK) {
            N6_INSTALL_FAIL(NINLIL_N6_CORRUPT);
        }
        kb.data = key; kb.length = (uint32_t)klen;
        pst = n6_prov_get(n6, &wtxn, kb, oldbuf, (uint32_t)sizeof(oldbuf),
            &olen, N6_GET_ALLOW_MISS);
        if (pst == NINLIL_N6_OK) {
            old_present = 1;
            if (ninlil_n6_decode_n6hw_value(oldbuf, olen, &hv) != NINLIL_N6_CODEC_OK) {
                N6_INSTALL_FAIL(NINLIL_N6_CORRUPT);
            }
            if (cap->key_generation > hv.high_water_key_generation)
                hv.high_water_key_generation = cap->key_generation;
            hv.last_update_authority_now_ms = n6->stamp.now_ms;
        } else if (pst == NINLIL_N6_NOT_FOUND) {
            ninlil_n6_secure_zero(&hv, sizeof(hv));
            hv.magic = NINLIL_N6_MAGIC_HW; hv.schema = NINLIL_N6_SCHEMA_HW;
            hv.high_water_key_generation = cap->key_generation;
            hv.last_update_authority_now_ms = n6->stamp.now_ms;
            olen = 0u;
        } else {
            N6_INSTALL_FAIL(pst);
        }
        if (ninlil_n6_encode_n6hw_value(&hv, val, sizeof(val), &vlen) != NINLIL_N6_CODEC_OK) {
            N6_INSTALL_FAIL(NINLIL_N6_CORRUPT);
        }
        vb.data = val; vb.length = (uint32_t)vlen;
        pst = n6_prov_put(n6, &wtxn, kb, vb);
        if (pst != NINLIL_N6_OK) {
            N6_INSTALL_FAIL(pst);
        }
        if (n6_cu_capture(n6, N6_CU_OP_PUT, N6_CU_POST_INSTALL_HANDLE, si, 0, 0,
                key, klen, oldbuf, (size_t)olen, old_present, val, vlen, 0, 0)
            != NINLIL_N6_OK) {
            N6_INSTALL_FAIL(NINLIL_N6_CAPACITY);
        }
    }
    /* pending slot material for CU (no publish until FULL) */
    n6->cu.pending_install = 1;
    n6->cu.pending_slot = *slot;
    n6->cu.pending_slot.live = 1;
    n6->cu.pending_slot.layer_code = cap->layer_code;
    n6->cu.pending_slot.direction_code = cap->direction_code;
    n6->cu.pending_slot.alloc_side = cap->alloc_side;
    n6->cu.pending_slot.context_id = cap->context_id;
    n6->cu.pending_slot.membership_epoch = cap->membership_epoch;
    n6->cu.pending_slot.key_generation = cap->key_generation;
    memcpy(n6->cu.pending_slot.binding_digest32, cap->binding_digest32, 32);
    memcpy(n6->cu.pending_slot.traffic_secret32, cap->traffic_secret32, 32);
    memcpy(n6->cu.pending_slot.ns_fingerprint12, nsfp, 12);
    memcpy(n6->cu.pending_slot.local_node_id, cap->local_node_id, 16);
    memcpy(n6->cu.pending_slot.receiver_node_id, cap->receiver_node_id, 16);
    n6->cu.pending_slot.tx_ram_next[0] = 1;
    n6->cu.pending_slot.tx_ram_limit[0] = 1;
    n6->cu.pending_slot.tx_ram_next[1] = 1;
    n6->cu.pending_slot.tx_ram_limit[1] = 1;
    n6->cu.pending_slot.tx_ram_next[2] = 1;
    n6->cu.pending_slot.tx_ram_limit[2] = 1;

    /* Commit clears CU plan on success; copy-own pending before FULL_OK publish. */
    {
        n6_slot_t pending_copy = n6->cu.pending_slot;
        cst = n6_prov_commit(n6, &wtxn);
        if (cst != NINLIL_N6_OK) {
            ninlil_n6_secure_zero(&pending_copy, sizeof(pending_copy));
            n6->stats.install_fail++;
            n6_slot_clear_free(slot);
            if (cst != NINLIL_N6_COMMIT_UNKNOWN) {
                n6_cu_clear(&n6->cu);
            }
            return cst;
        }
        *slot = pending_copy;
        slot->canary0 = N6_CANARY;
        slot->canary1 = N6_CANARY;
        /* Stack traffic_secret32 residual must not survive publish. */
        ninlil_n6_secure_zero(&pending_copy, sizeof(pending_copy));
    }
#undef N6_INSTALL_FAIL
    n6->cu.pending_install = 0;
    {
        uint64_t hid = 0u;
        if (n6_id_alloc(&n6->next_handle, &hid) != NINLIL_N6_OK) {
            n6_slot_clear_free(slot);
            return NINLIL_N6_CAPACITY;
        }
        slot->handle = hid;
    }
    /* RX sliding-64 RAM init from durable 0 */
    slot->rx_live_reserved[0] = 0u;
    slot->rx_boot_floor[0] = 0u;
    slot->rx_ram_highest[0] = 0u;
    slot->rx_bitmap[0] = 0u;
    slot->rx_live_reserved[1] = 0u;
    slot->rx_boot_floor[1] = 0u;
    slot->rx_ram_highest[1] = 0u;
    slot->rx_bitmap[1] = 0u;
    *out_h = slot->handle;
    n6->state = NINLIL_N6_STATE_READY;
    n6->stats.install_ok++;
    return NINLIL_N6_OK;
}

ninlil_n6_status_t ninlil_n6_install_hop(
    ninlil_n6_t *n6, const ninlil_n6_install_capsule_t *c, ninlil_n6_handle_t *h)
{
    ninlil_n6_status_t st = n6_enter(n6), r;
    if (st != NINLIL_N6_OK) return st;
    r = n6_install_engine(n6, c, 1, h);
    n6_leave(n6);
    return r;
}
ninlil_n6_status_t ninlil_n6_install_e2e(
    ninlil_n6_t *n6, const ninlil_n6_install_capsule_t *c, ninlil_n6_handle_t *h)
{
    ninlil_n6_status_t st = n6_enter(n6), r;
    if (st != NINLIL_N6_OK) return st;
    r = n6_install_engine(n6, c, 0, h);
    n6_leave(n6);
    return r;
}

/* TX: reserve block only when ram window exhausted */
ninlil_n6_status_t ninlil_n6_tx_burn(
    ninlil_n6_t *n6, ninlil_n6_handle_t handle, uint8_t lane_kind,
    ninlil_n6_tx_lease_t *out_lease)
{
    ninlil_n6_status_t st = n6_enter(n6);
    n6_slot_t *slot;
    int idx, li;
    if (st != NINLIL_N6_OK) return st;
    if (out_lease != NULL) {
        ninlil_n6_secure_zero(out_lease, sizeof(*out_lease));
    }
    if (!out_lease) { n6_leave(n6); return NINLIL_N6_INVALID_ARGUMENT; }
    if (n6->state != NINLIL_N6_STATE_READY) {
        n6_leave(n6); return NINLIL_N6_INVALID_STATE;
    }
    {
        int corrupt = 0;
        slot = n6_find_handle(n6, handle, &corrupt);
        if (corrupt != 0) {
            n6_leave(n6); return NINLIL_N6_CORRUPT;
        }
    }
    if (!slot || slot->fenced || slot->alloc_side != NINLIL_N6_ALLOC_OUTBOUND_TX) {
        n6_leave(n6); return NINLIL_N6_NOT_FOUND;
    }
    if (!n6_lane_ok_for_slot(slot, lane_kind)) {
        n6_leave(n6); return NINLIL_N6_INVALID_ARGUMENT;
    }
    idx = n6_lane_idx(lane_kind);
    for (li = 0; li < (int)NINLIL_N6_MAX_LIVE_LEASES; ++li)
        if (!n6->leases[li].live) break;
    if (li >= (int)NINLIL_N6_MAX_LIVE_LEASES) {
        n6_leave(n6); return NINLIL_N6_CAPACITY;
    }

    /* Reserve durable block if window empty; partial final tranche near MAX-1 */
    if (slot->tx_ram_next[idx] >= slot->tx_ram_limit[idx]) {
        ninlil_n6_lane_key_t lk;
        ninlil_n6_tx_value_t tv;
        uint8_t key[48], val[68], oldbuf[68];
        size_t klen=0, vlen=0;
        ninlil_bytes_view_t kb, vb;
        uint64_t c0, c1, room, grow;
        ninlil_n6_status_t cst;
        /* exclusive end may be UINT64_MAX so last counter is MAX-1 */
        const uint64_t max_ex = UINT64_MAX;
        n6_make_lane_key(slot, lane_kind, &lk);
        if (ninlil_n6_encode_lane_key(&lk, key, sizeof(key), &klen) != NINLIL_N6_CODEC_OK) {
            n6_leave(n6); return NINLIL_N6_CORRUPT;
        }
        {
            ninlil_n6_status_t ost = n6_need_storage(n6);
            if (ost != NINLIL_N6_OK) { n6_leave(n6); return ost; }
        }
        n6_cu_clear(&n6->cu);
        {
            n6_txn_t w;
            uint32_t olen = 0u;
            ninlil_n6_status_t pst;
            pst = n6_prov_begin(n6, NINLIL_STORAGE_READ_WRITE, &w);
            if (pst != NINLIL_N6_OK) { n6_leave(n6); return pst; }
            kb.data=key; kb.length=(uint32_t)klen;
            pst = n6_prov_get(n6, &w, kb, oldbuf, (uint32_t)sizeof(oldbuf),
                &olen, N6_GET_REQUIRE_PRESENT);
            if (pst != NINLIL_N6_OK) {
                pst = n6_prov_fail(n6, &w, pst, 1);
                n6_leave(n6); return pst;
            }
            if (ninlil_n6_decode_n6tx_value(oldbuf, olen, &tv) != NINLIL_N6_CODEC_OK) {
                pst = n6_prov_fail(n6, &w, NINLIL_N6_CORRUPT, 1);
                n6_leave(n6); return pst;
            }
            c0 = tv.reserved_exclusive;
            if (c0 == 0u || c0 >= max_ex) {
                pst = n6_prov_fail(n6, &w, NINLIL_N6_CAPACITY, 1);
                n6_leave(n6); return pst;
            }
            room = max_ex - c0;
            grow = (room < NINLIL_N6_TX_BLOCK_SIZE) ? room : NINLIL_N6_TX_BLOCK_SIZE;
            c1 = c0 + grow;
            tv.reserved_exclusive = c1;
            if (ninlil_n6_encode_n6tx_value(&tv, val, sizeof(val), &vlen) != NINLIL_N6_CODEC_OK) {
                pst = n6_prov_fail(n6, &w, NINLIL_N6_CORRUPT, 1);
                n6_leave(n6); return pst;
            }
            vb.data=val; vb.length=(uint32_t)vlen;
            pst = n6_prov_put(n6, &w, kb, vb);
            if (pst != NINLIL_N6_OK) {
                pst = n6_prov_fail(n6, &w, pst, 1);
                n6_leave(n6); return pst;
            }
            if (n6_cu_capture(n6, N6_CU_OP_PUT, N6_CU_POST_TX_LIMIT,
                    n6_slot_index(n6, slot), lane_kind, (uint8_t)idx,
                    key, klen, oldbuf, (size_t)olen, 1, val, vlen, c1, c0)
                != NINLIL_N6_OK) {
                pst = n6_prov_fail(n6, &w, NINLIL_N6_CAPACITY, 1);
                n6_leave(n6); return pst;
            }
            cst = n6_prov_commit(n6, &w);
            if (cst != NINLIL_N6_OK) {
                n6->stats.tx_burn_fail++;
                n6_leave(n6); return cst;
            }
        }
        slot->tx_ram_next[idx] = c0;
        slot->tx_ram_limit[idx] = c1;
    }
    {
        ninlil_n6_tx_lease_t *L = &n6->leases[li];
        uint64_t c = slot->tx_ram_next[idx];
        if (c >= slot->tx_ram_limit[idx]) {
            n6_leave(n6); return NINLIL_N6_CAPACITY;
        }
        ninlil_n6_secure_zero(L, sizeof(*L));
        {
            uint64_t lid = 0u;
            if (n6_id_alloc(&n6->next_lease_id, &lid) != NINLIL_N6_OK) {
                n6_leave(n6); return NINLIL_N6_CAPACITY;
            }
            L->lease_id = lid;
        }
        L->handle = handle;
        L->lane_kind = lane_kind;
        L->layer_code = slot->layer_code;
        L->direction_code = slot->direction_code;
        L->live = 1;
        L->context_id = slot->context_id;
        L->counter = c;
        L->block_end = slot->tx_ram_limit[idx];
        if (n6_derive_lane_keys(n6, slot, lane_kind, L->key16, L->iv12) != NINLIL_N6_OK) {
            ninlil_n6_secure_zero(L, sizeof(*L));
            n6_leave(n6); return NINLIL_N6_CRYPTO;
        }
        n6_nonce_apply_counter(L->iv12, c);
        slot->tx_ram_next[idx] = c + 1u;
        *out_lease = *L;
    }
    n6->stats.tx_burn_ok++;
    n6_leave(n6);
    return NINLIL_N6_OK;
}

ninlil_n6_status_t ninlil_n6_tx_lease_release(
    ninlil_n6_t *n6, ninlil_n6_tx_lease_t *lease)
{
    uint32_t i;
    ninlil_n6_status_t st = n6_enter(n6);
    if (st != NINLIL_N6_OK) return st;
    if (!lease || !lease->live || !lease->lease_id) {
        n6_leave(n6); return NINLIL_N6_INVALID_ARGUMENT;
    }
    for (i = 0; i < NINLIL_N6_MAX_LIVE_LEASES; ++i) {
        if (n6->leases[i].live && n6->leases[i].lease_id == lease->lease_id) {
            /* full field match — stale/tampered lease cannot release another */
            if (n6->leases[i].handle != lease->handle
                || n6->leases[i].counter != lease->counter
                || n6->leases[i].lane_kind != lease->lane_kind) {
                n6_leave(n6); return NINLIL_N6_TICKET;
            }
            ninlil_n6_secure_zero(&n6->leases[i], sizeof(n6->leases[i]));
            ninlil_n6_secure_zero(lease, sizeof(*lease));
            n6->stats.lease_release++;
            n6_leave(n6); return NINLIL_N6_OK;
        }
    }
    n6_leave(n6); return NINLIL_N6_NOT_FOUND;
}

/* docs/30 §10 RX sliding-64 precheck (mutation 0) */
static int n6_rx_precheck_window(const n6_slot_t *slot, int idx, uint64_t c)
{
    uint64_t boot_floor = slot->rx_boot_floor[idx];
    uint64_t ram_highest = slot->rx_ram_highest[idx];
    uint64_t bm = slot->rx_bitmap[idx];
    uint64_t delta;
    if (c == 0u || c == UINT64_MAX) {
        return 0;
    }
    if (c <= boot_floor) {
        return 0;
    }
    if (c <= ram_highest) {
        delta = ram_highest - c;
        if (delta >= 64u) {
            return 0;
        }
        if (((bm >> delta) & UINT64_C(1)) != 0u) {
            return 0; /* already admitted */
        }
    }
    return 1;
}

static void n6_rx_mark_bitmap(n6_slot_t *slot, int idx, uint64_t c)
{
    uint64_t *rh = &slot->rx_ram_highest[idx];
    uint64_t *bm = &slot->rx_bitmap[idx];
    uint64_t delta;
    if (c > *rh) {
        delta = c - *rh;
        if (delta >= 64u) {
            *bm = UINT64_C(1);
        } else {
            *bm = (*bm << delta) | UINT64_C(1);
        }
        *rh = c;
    } else {
        delta = *rh - c;
        *bm |= (UINT64_C(1) << delta);
    }
}

/*
 * ticket_id resolved: consume internal slot + caller ticket + local tok
 * exactly once (success, field mismatch, storage fail, canary, encode).
 * Retry requires a fresh precheck; orphan internals must not starve the pool.
 */
static void n6_rx_consume_ticket_pair(
    ninlil_n6_t *n6, uint32_t i, ninlil_n6_rx_ticket_t *ticket,
    n6_rx_token_t *tok)
{
    if (n6 != NULL && i < NINLIL_N6_MAX_LIVE_TICKETS) {
        ninlil_n6_secure_zero(&n6->tickets[i], sizeof(n6->tickets[i]));
    }
    if (ticket != NULL) {
        ninlil_n6_secure_zero(ticket, sizeof(*ticket));
    }
    if (tok != NULL) {
        ninlil_n6_secure_zero(tok, sizeof(*tok));
    }
}

ninlil_n6_status_t ninlil_n6_rx_precheck(
    ninlil_n6_t *n6, ninlil_n6_handle_t handle, uint8_t lane_kind,
    uint64_t counter, ninlil_n6_rx_ticket_t *out_ticket)
{
    ninlil_n6_status_t st = n6_enter(n6);
    n6_slot_t *slot;
    int idx, ti;
    if (st != NINLIL_N6_OK) return st;
    if (out_ticket != NULL) {
        ninlil_n6_secure_zero(out_ticket, sizeof(*out_ticket));
    }
    if (!out_ticket || !counter || counter == UINT64_MAX) {
        n6_leave(n6); return NINLIL_N6_INVALID_ARGUMENT;
    }
    if (n6->state != NINLIL_N6_STATE_READY) {
        n6_leave(n6); return NINLIL_N6_INVALID_STATE;
    }
    {
        int corrupt = 0;
        slot = n6_find_handle(n6, handle, &corrupt);
        if (corrupt != 0) {
            n6_leave(n6); return NINLIL_N6_CORRUPT;
        }
    }
    if (!slot || slot->fenced || slot->alloc_side != NINLIL_N6_ALLOC_INBOUND_RX) {
        n6_leave(n6); return NINLIL_N6_NOT_FOUND;
    }
    if (!n6_lane_ok_for_slot(slot, lane_kind)) {
        n6_leave(n6); return NINLIL_N6_INVALID_ARGUMENT;
    }
    idx = n6_lane_idx(lane_kind);
    if (!n6_rx_precheck_window(slot, idx, counter)) {
        n6_leave(n6); return NINLIL_N6_TICKET;
    }
    /* no live ticket for same handle/lane/counter */
    for (ti = 0; ti < (int)NINLIL_N6_MAX_LIVE_TICKETS; ++ti) {
        if (n6->tickets[ti].live != 0u
            && n6->tickets[ti].handle == handle
            && n6->tickets[ti].lane_kind == lane_kind
            && n6->tickets[ti].counter == counter) {
            n6_leave(n6); return NINLIL_N6_TICKET;
        }
    }
    for (ti = 0; ti < (int)NINLIL_N6_MAX_LIVE_TICKETS; ++ti)
        if (!n6->tickets[ti].live) break;
    if (ti >= (int)NINLIL_N6_MAX_LIVE_TICKETS) {
        n6_leave(n6); return NINLIL_N6_CAPACITY;
    }
    {
        n6_rx_token_t *T = &n6->tickets[ti];
        uint64_t tid = 0u;
        ninlil_n6_secure_zero(T, sizeof(*T));
        if (n6_id_alloc(&n6->next_ticket_id, &tid) != NINLIL_N6_OK) {
            n6_leave(n6); return NINLIL_N6_CAPACITY;
        }
        T->ticket_id = tid;
        T->handle = handle;
        T->lane_kind = lane_kind;
        T->layer_code = slot->layer_code;
        T->direction_code = slot->direction_code;
        T->live = 1;
        T->context_id = slot->context_id;
        T->slot_index = n6_slot_index(n6, slot);
        T->counter = counter;
        if (n6_derive_lane_keys(n6, slot, lane_kind, T->key16, T->iv12) != NINLIL_N6_OK) {
            ninlil_n6_secure_zero(T, sizeof(*T));
            n6_leave(n6); return NINLIL_N6_CRYPTO;
        }
        n6_nonce_apply_counter(T->iv12, counter);
        /* public copy for AEAD open; admit ignores caller fields */
        out_ticket->ticket_id = T->ticket_id;
        out_ticket->handle = T->handle;
        out_ticket->lane_kind = T->lane_kind;
        out_ticket->layer_code = T->layer_code;
        out_ticket->direction_code = T->direction_code;
        out_ticket->live = 1u;
        out_ticket->context_id = T->context_id;
        out_ticket->counter = T->counter;
        (void)memcpy(out_ticket->key16, T->key16, 16u);
        (void)memcpy(out_ticket->iv12, T->iv12, 12u);
    }
    n6->stats.rx_precheck_ok++;
    n6_leave(n6);
    return NINLIL_N6_OK;
}

/*
 * Admit: only internal immutable token is authoritative.
 * Caller handle/lane/counter/key/iv tamper is rejected (full field match) and
 * never used for durable mutation. ticket_id resolution always consumes
 * internal+caller+local tok exactly once (success or any failure).
 */
ninlil_n6_status_t ninlil_n6_rx_admit_after_aead(
    ninlil_n6_t *n6, ninlil_n6_rx_ticket_t *ticket)
{
    ninlil_n6_status_t st = n6_enter(n6);
    n6_slot_t *slot;
    int idx;
    uint32_t i;
    n6_rx_token_t tok;
    ninlil_n6_lane_key_t lk;
    uint8_t key[48], val[68], oldbuf[68];
    size_t klen=0, vlen=0;
    ninlil_n6_rx_value_t rv;
    ninlil_bytes_view_t kb, vb;
    ninlil_n6_status_t cst;
    uint64_t c;
    uint64_t new_through;
    const uint64_t B = NINLIL_N6_RX_WINDOW;

    ninlil_n6_secure_zero(&tok, sizeof(tok));
    if (st != NINLIL_N6_OK) return st;
    if (!ticket || !ticket->live || !ticket->ticket_id) {
        n6_leave(n6); return NINLIL_N6_INVALID_ARGUMENT;
    }
    for (i = 0; i < NINLIL_N6_MAX_LIVE_TICKETS; ++i)
        if (n6->tickets[i].live && n6->tickets[i].ticket_id == ticket->ticket_id)
            break;
    if (i >= NINLIL_N6_MAX_LIVE_TICKETS) {
        /* unresolved ticket_id: wipe caller only (no internal to free) */
        ninlil_n6_secure_zero(ticket, sizeof(*ticket));
        n6_leave(n6); return NINLIL_N6_TICKET;
    }
    /* Snapshot internal; all exits from here consume pair exactly once. */
    tok = n6->tickets[i];
    /* full field match against internal token */
    if (ticket->handle != tok.handle || ticket->lane_kind != tok.lane_kind
        || ticket->counter != tok.counter || ticket->context_id != tok.context_id
        || ticket->layer_code != tok.layer_code
        || ticket->direction_code != tok.direction_code
        || memcmp(ticket->key16, tok.key16, 16u) != 0
        || memcmp(ticket->iv12, tok.iv12, 12u) != 0) {
        n6_rx_consume_ticket_pair(n6, i, ticket, &tok);
        n6_leave(n6); return NINLIL_N6_TICKET;
    }
    /* use only internal copy from here */
    c = tok.counter;
    idx = n6_lane_idx(tok.lane_kind);
    if (tok.slot_index >= n6->slot_count) {
        n6_rx_consume_ticket_pair(n6, i, ticket, &tok);
        n6_leave(n6); return NINLIL_N6_CORRUPT;
    }
    slot = &n6->cells[tok.slot_index].live;
    if (slot->canary0 != N6_CANARY || slot->canary1 != N6_CANARY) {
        /* Canary corruption: CORRUPT/fence — never hide as NOT_FOUND. */
        n6_enter_fenced(n6);
        n6_rx_consume_ticket_pair(n6, i, ticket, &tok);
        n6_set_err(n6, NINLIL_N6_CORRUPT, NINLIL_N6_REASON_CORRUPT, "canary");
        n6_leave(n6);
        return NINLIL_N6_CORRUPT;
    }
    if (slot->live == 0u || slot->handle != tok.handle) {
        n6_rx_consume_ticket_pair(n6, i, ticket, &tok);
        n6_leave(n6);
        return NINLIL_N6_NOT_FOUND;
    }
    if (!n6_rx_precheck_window(slot, idx, c)) {
        n6_rx_consume_ticket_pair(n6, i, ticket, &tok);
        n6_leave(n6); return NINLIL_N6_TICKET;
    }
    n6_make_lane_key(slot, tok.lane_kind, &lk);
    if (ninlil_n6_encode_lane_key(&lk, key, sizeof(key), &klen) != NINLIL_N6_CODEC_OK) {
        n6_rx_consume_ticket_pair(n6, i, ticket, &tok);
        n6_leave(n6); return NINLIL_N6_CORRUPT;
    }
    {
        ninlil_n6_status_t ost = n6_need_storage(n6);
        if (ost != NINLIL_N6_OK) {
            n6_rx_consume_ticket_pair(n6, i, ticket, &tok);
            n6_leave(n6); return ost;
        }
    }
    n6_cu_clear(&n6->cu);
    {
        n6_txn_t w;
        uint32_t olen = 0u;
        ninlil_n6_status_t pst;
        pst = n6_prov_begin(n6, NINLIL_STORAGE_READ_WRITE, &w);
        if (pst != NINLIL_N6_OK) {
            n6_rx_consume_ticket_pair(n6, i, ticket, &tok);
            n6_leave(n6); return pst;
        }
        kb.data=key; kb.length=(uint32_t)klen;
        pst = n6_prov_get(n6, &w, kb, oldbuf, (uint32_t)sizeof(oldbuf),
            &olen, N6_GET_REQUIRE_PRESENT);
        if (pst != NINLIL_N6_OK) {
            pst = n6_prov_fail(n6, &w, pst, 1);
            n6_rx_consume_ticket_pair(n6, i, ticket, &tok);
            n6_leave(n6); return pst;
        }
        if (ninlil_n6_decode_n6rx_value(oldbuf, olen, &rv) != NINLIL_N6_CODEC_OK) {
            pst = n6_prov_fail(n6, &w, NINLIL_N6_CORRUPT, 1);
            n6_rx_consume_ticket_pair(n6, i, ticket, &tok);
            n6_leave(n6); return pst;
        }
        new_through = rv.accept_reserved_through;
        if (c > slot->rx_live_reserved[idx]) {
            if (c > (UINT64_MAX - 1u) - (B - 1u)) {
                new_through = UINT64_MAX - 1u;
            } else {
                new_through = c + B - 1u;
            }
            rv.accept_reserved_through = new_through;
        }
        if (ninlil_n6_encode_n6rx_value(&rv, val, sizeof(val), &vlen) != NINLIL_N6_CODEC_OK) {
            pst = n6_prov_fail(n6, &w, NINLIL_N6_CORRUPT, 1);
            n6_rx_consume_ticket_pair(n6, i, ticket, &tok);
            n6_leave(n6); return pst;
        }
        vb.data=val; vb.length=(uint32_t)vlen;
        pst = n6_prov_put(n6, &w, kb, vb);
        if (pst != NINLIL_N6_OK) {
            pst = n6_prov_fail(n6, &w, pst, 1);
            n6_rx_consume_ticket_pair(n6, i, ticket, &tok);
            n6_leave(n6); return pst;
        }
        if (n6_cu_capture(n6, N6_CU_OP_PUT, N6_CU_POST_RX_ACCEPT,
                tok.slot_index, tok.lane_kind, (uint8_t)idx,
                key, klen, oldbuf, (size_t)olen, 1, val, vlen, new_through, 0)
            != NINLIL_N6_OK) {
            pst = n6_prov_fail(n6, &w, NINLIL_N6_CAPACITY, 1);
            n6_rx_consume_ticket_pair(n6, i, ticket, &tok);
            n6_leave(n6); return pst;
        }
        cst = n6_prov_commit(n6, &w);
        if (cst != NINLIL_N6_OK) {
            n6_rx_consume_ticket_pair(n6, i, ticket, &tok);
            n6_leave(n6); return cst;
        }
    }
    if (c > slot->rx_live_reserved[idx]) {
        slot->rx_live_reserved[idx] = new_through;
    }
    n6_rx_mark_bitmap(slot, idx, c);
    n6_rx_consume_ticket_pair(n6, i, ticket, &tok);
    n6->stats.rx_admit_ok++;
    n6_leave(n6);
    return NINLIL_N6_OK;
}

ninlil_n6_status_t ninlil_n6_rx_abort(ninlil_n6_t *n6, ninlil_n6_rx_ticket_t *ticket)
{
    uint32_t i;
    ninlil_n6_status_t st = n6_enter(n6);
    if (st != NINLIL_N6_OK) return st;
    if (!ticket) { n6_leave(n6); return NINLIL_N6_INVALID_ARGUMENT; }
    /*
     * ticket_id resolution always frees the internal slot (field match is not
     * required). Wrong ticket_id never touches another live token. Caller is
     * always wiped; retry needs a fresh precheck.
     */
    for (i = 0; i < NINLIL_N6_MAX_LIVE_TICKETS; ++i) {
        if (n6->tickets[i].live && ticket->ticket_id
            && n6->tickets[i].ticket_id == ticket->ticket_id) {
            ninlil_n6_secure_zero(&n6->tickets[i], sizeof(n6->tickets[i]));
            break;
        }
    }
    ninlil_n6_secure_zero(ticket, sizeof(*ticket));
    n6->stats.rx_abort++;
    n6_leave(n6);
    return NINLIL_N6_OK;
}




ninlil_n6_status_t ninlil_n6_fence(
    ninlil_n6_t *n6, ninlil_n6_handle_t handle, uint8_t reason)
{
    ninlil_n6_status_t st = n6_enter(n6);
    (void)handle;
    (void)reason;
    if (st != NINLIL_N6_OK) {
        return st;
    }
    n6_set_err(n6, NINLIL_N6_M4_REQUIRED, NINLIL_N6_REASON_M4, "fence");
    n6_leave(n6);
    return NINLIL_N6_M4_REQUIRED;
}

ninlil_n6_status_t ninlil_n6_restamp(ninlil_n6_t *n6, ninlil_n6_handle_t handle)
{
    ninlil_n6_status_t st = n6_enter(n6);
    (void)handle;
    if (st != NINLIL_N6_OK) {
        return st;
    }
    n6_set_err(n6, NINLIL_N6_M4_REQUIRED, NINLIL_N6_REASON_M4, "restamp");
    n6_leave(n6);
    return NINLIL_N6_M4_REQUIRED;
}

ninlil_n6_status_t ninlil_n6_reclaim(ninlil_n6_t *n6, ninlil_n6_handle_t handle)
{
    ninlil_n6_status_t st = n6_enter(n6);
    (void)handle;
    if (st != NINLIL_N6_OK) {
        return st;
    }
    n6_set_err(n6, NINLIL_N6_M4_REQUIRED, NINLIL_N6_REASON_M4, "reclaim");
    n6_leave(n6);
    return NINLIL_N6_M4_REQUIRED;
}

ninlil_n6_status_t ninlil_n6_gc(ninlil_n6_t *n6)
{
    ninlil_n6_status_t st = n6_enter(n6);
    if (st != NINLIL_N6_OK) {
        return st;
    }
    n6_set_err(n6, NINLIL_N6_M4_REQUIRED, NINLIL_N6_REASON_M4, "gc");
    n6_leave(n6);
    return NINLIL_N6_M4_REQUIRED;
}

ninlil_n6_status_t ninlil_n6_stats(
    const ninlil_n6_t *n6, ninlil_n6_stats_t *out_stats)
{
    if (!n6_obj_ok(n6) || out_stats == NULL) {
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    *out_stats = n6->stats;
    return NINLIL_N6_OK;
}

ninlil_n6_status_t ninlil_n6_last_error(
    const ninlil_n6_t *n6, ninlil_n6_error_t *out_error)
{
    if (!n6_obj_ok(n6) || out_error == NULL) {
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    *out_error = n6->last_error;
    return NINLIL_N6_OK;
}

ninlil_n6_status_t ninlil_n6_shutdown(ninlil_n6_t *n6)
{
    uint32_t i;
    if (!n6_obj_ok(n6)) {
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    if (n6->reentry != 0u) {
        return NINLIL_N6_BUSY_REENTRY;
    }
    n6->reentry = 1u;
    for (i = 0u; i < n6->slot_count; ++i) {
        ninlil_n6_secure_zero(&n6->cells[i].live, sizeof(n6->cells[i].live));
    }
    for (i = 0u; i < NINLIL_N6_MAX_LIVE_LEASES; ++i) {
        ninlil_n6_secure_zero(&n6->leases[i], sizeof(n6->leases[i]));
    }
    for (i = 0u; i < NINLIL_N6_MAX_LIVE_TICKETS; ++i) {
        ninlil_n6_secure_zero(&n6->tickets[i], sizeof(n6->tickets[i]));
    }
    n6_cu_clear(&n6->cu);
    ninlil_n6_secure_zero(&n6->boot_scratch, sizeof(n6->boot_scratch));
    ninlil_n6_secure_zero(&n6->stamp, sizeof(n6->stamp));
    ninlil_n6_secure_zero(n6->local_node_id, sizeof(n6->local_node_id));
    n6->local_id_bound = 0;
    n6->stamp_bound = 0;
    /* Close live handle exactly once, then zeroize provider ops/user. */
    n6_storage_force_close(n6);
    ninlil_n6_secure_zero(&n6->storage, sizeof(n6->storage));
    ninlil_n6_secure_zero(&n6->crypto, sizeof(n6->crypto));
    n6->storage_bound = 0;
    n6->crypto_bound = 0;
    n6->state = NINLIL_N6_STATE_SHUTDOWN;
    n6->reentry = 0u;
    return NINLIL_N6_OK;
}


#if defined(NINLIL_N6_TEST_BUILD)
/* Test-only object inspection — not present in production archive path semantics. */
void ninlil_n6_test_paint_boot_scratch(ninlil_n6_t *n6, uint8_t byte)
{
    if (n6 == NULL) {
        return;
    }
    (void)memset(&n6->boot_scratch, (int)byte, sizeof(n6->boot_scratch));
}

int ninlil_n6_test_boot_scratch_is_zero(const ninlil_n6_t *n6)
{
    const uint8_t *p;
    size_t i;
    if (n6 == NULL) {
        return 0;
    }
    p = (const uint8_t *)&n6->boot_scratch;
    for (i = 0u; i < sizeof(n6->boot_scratch); ++i) {
        if (p[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

uint8_t ninlil_n6_test_cu_phase(const ninlil_n6_t *n6)
{
    if (n6 == NULL) {
        return 0u;
    }
    return (uint8_t)n6->cu.phase;
}

int ninlil_n6_test_cu_live(const ninlil_n6_t *n6)
{
    if (n6 == NULL) {
        return 0;
    }
    return n6->cu.live;
}

uint32_t ninlil_n6_test_live_ticket_count(const ninlil_n6_t *n6)
{
    uint32_t i;
    uint32_t n = 0u;
    if (n6 == NULL) {
        return 0u;
    }
    for (i = 0u; i < NINLIL_N6_MAX_LIVE_TICKETS; ++i) {
        if (n6->tickets[i].live != 0u) {
            n++;
        }
    }
    return n;
}

int ninlil_n6_test_any_ticket_key_or_iv_nonzero(const ninlil_n6_t *n6)
{
    uint32_t i;
    size_t j;
    if (n6 == NULL) {
        return 0;
    }
    for (i = 0u; i < NINLIL_N6_MAX_LIVE_TICKETS; ++i) {
        for (j = 0u; j < sizeof(n6->tickets[i].key16); ++j) {
            if (n6->tickets[i].key16[j] != 0u) {
                return 1;
            }
        }
        for (j = 0u; j < sizeof(n6->tickets[i].iv12); ++j) {
            if (n6->tickets[i].iv12[j] != 0u) {
                return 1;
            }
        }
    }
    return 0;
}
#endif /* NINLIL_N6_TEST_BUILD */
