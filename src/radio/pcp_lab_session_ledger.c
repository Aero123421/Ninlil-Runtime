/*
 * LAB session durable ledger for R2 PCP (production-private composition).
 * No heap/VLA. Session-scoped durability only — not power-cut HIL.
 */

#include "pcp_lab_session_ledger.h"

#include "ninlil/version.h"

#include <string.h>

#define LEDGER_MAGIC ((uint32_t)0x4c445250u) /* 'PRDL' */

typedef struct {
    uint32_t live;
    uint32_t key_len;
    uint32_t val_len;
    uint8_t key[NINLIL_PCP_LAB_LEDGER_MAX_KEY];
    uint8_t val[NINLIL_PCP_LAB_LEDGER_MAX_VAL];
} ledger_entry_t;

typedef struct {
    uint32_t open;
    uint32_t schema;
    uint32_t ns_len;
    uint8_t ns_name[NINLIL_PCP_LAB_LEDGER_MAX_NS_NAME];
    ledger_entry_t entries[NINLIL_PCP_LAB_LEDGER_MAX_ENTRIES];
    uint32_t entry_count;
} ledger_ns_t;

typedef struct {
    uint32_t live;
    uint32_t mode; /* READ_ONLY / READ_WRITE */
    uint32_t ns_index;
    /* Staging for RW txn: full ns snapshot. */
    ledger_entry_t staging[NINLIL_PCP_LAB_LEDGER_MAX_ENTRIES];
    uint32_t staging_count;
    uint32_t dirty;
} ledger_txn_t;

typedef struct {
    uint32_t live;
    uint32_t ns_index;
    uint32_t txn_id;
    uint32_t prefix_len;
    uint8_t prefix[NINLIL_PCP_LAB_LEDGER_MAX_KEY];
    uint32_t cursor;
} ledger_iter_t;

typedef struct {
    uint32_t magic;
    uint32_t lifecycle; /* 0 zero, 1 active, 2 shutdown */
    ledger_ns_t namespaces[NINLIL_PCP_LAB_LEDGER_MAX_NS];
    ledger_txn_t txns[2];
    ledger_iter_t iters[2];
    ninlil_storage_ops_t ops;
} ledger_impl_t;

_Static_assert(
    sizeof(ledger_impl_t)
        <= NINLIL_PCP_LAB_SESSION_LEDGER_OPAQUE_BYTES,
    "lab session ledger opaque too small for ledger_impl_t");
_Static_assert(
    sizeof(((ninlil_pcp_lab_session_ledger_t *)0)->opaque)
        == NINLIL_PCP_LAB_SESSION_LEDGER_OPAQUE_BYTES,
    "lab session ledger opaque size must match OPAQUE_BYTES");
/* Guard against silent BSS bloat: keep ceiling exact 24 KiB. */
_Static_assert(
    NINLIL_PCP_LAB_SESSION_LEDGER_OPAQUE_BYTES == 24576u,
    "lab session ledger opaque ceiling drift");

static ledger_impl_t *impl_of(void *user)
{
    ninlil_pcp_lab_session_ledger_t *ledger =
        (ninlil_pcp_lab_session_ledger_t *)user;
    ledger_impl_t *impl;

    if (ledger == NULL) {
        return NULL;
    }
    impl = (ledger_impl_t *)(void *)ledger->opaque;
    if (impl->magic != LEDGER_MAGIC || impl->lifecycle != 1u) {
        return NULL;
    }
    return impl;
}

static int bytes_eq(
    const uint8_t *a,
    uint32_t alen,
    const uint8_t *b,
    uint32_t blen)
{
    uint32_t i;

    if (alen != blen) {
        return 0;
    }
    for (i = 0u; i < alen; ++i) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

static int has_prefix(
    const uint8_t *key,
    uint32_t key_len,
    const uint8_t *prefix,
    uint32_t prefix_len)
{
    uint32_t i;

    if (prefix_len > key_len) {
        return 0;
    }
    for (i = 0u; i < prefix_len; ++i) {
        if (key[i] != prefix[i]) {
            return 0;
        }
    }
    return 1;
}

static ninlil_storage_status_t ledger_open(
    void *user,
    ninlil_bytes_view_t storage_namespace,
    uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle)
{
    ledger_impl_t *impl = impl_of(user);
    uint32_t i;
    uint32_t free_slot = NINLIL_PCP_LAB_LEDGER_MAX_NS;
    ledger_ns_t *ns;

    if (impl == NULL || out_handle == NULL || storage_namespace.data == NULL
        || storage_namespace.length == 0u
        || storage_namespace.length > NINLIL_PCP_LAB_LEDGER_MAX_NS_NAME) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (expected_schema != NINLIL_STORAGE_SCHEMA_M1A) {
        return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    }
    for (i = 0u; i < NINLIL_PCP_LAB_LEDGER_MAX_NS; ++i) {
        ns = &impl->namespaces[i];
        if (ns->open != 0u
            && bytes_eq(
                   ns->ns_name,
                   ns->ns_len,
                   storage_namespace.data,
                   storage_namespace.length)
            && ns->schema == expected_schema) {
            *out_handle = (ninlil_storage_handle_t)(uintptr_t)(i + 1u);
            return NINLIL_STORAGE_OK;
        }
        if (ns->open == 0u && free_slot == NINLIL_PCP_LAB_LEDGER_MAX_NS) {
            free_slot = i;
        }
    }
    if (free_slot >= NINLIL_PCP_LAB_LEDGER_MAX_NS) {
        return NINLIL_STORAGE_NO_SPACE;
    }
    ns = &impl->namespaces[free_slot];
    (void)memset(ns, 0, sizeof(*ns));
    ns->open = 1u;
    ns->schema = expected_schema;
    ns->ns_len = storage_namespace.length;
    for (i = 0u; i < storage_namespace.length; ++i) {
        ns->ns_name[i] = storage_namespace.data[i];
    }
    *out_handle = (ninlil_storage_handle_t)(uintptr_t)(free_slot + 1u);
    return NINLIL_STORAGE_OK;
}

static void ledger_close(void *user, ninlil_storage_handle_t handle)
{
    ledger_impl_t *impl = impl_of(user);
    uintptr_t idx;

    if (impl == NULL || handle == NULL) {
        return;
    }
    idx = (uintptr_t)handle;
    if (idx == 0u || idx > NINLIL_PCP_LAB_LEDGER_MAX_NS) {
        return;
    }
    /* Keep durable entries; mark not open only for capacity reuse of empty. */
    (void)idx;
}

static ledger_ns_t *ns_from_handle(
    ledger_impl_t *impl,
    ninlil_storage_handle_t handle)
{
    uintptr_t idx;

    if (impl == NULL || handle == NULL) {
        return NULL;
    }
    idx = (uintptr_t)handle;
    if (idx == 0u || idx > NINLIL_PCP_LAB_LEDGER_MAX_NS) {
        return NULL;
    }
    if (impl->namespaces[idx - 1u].open == 0u) {
        return NULL;
    }
    return &impl->namespaces[idx - 1u];
}

static ledger_txn_t *txn_from(
    ledger_impl_t *impl,
    ninlil_storage_txn_t txn)
{
    uintptr_t idx;

    if (impl == NULL || txn == NULL) {
        return NULL;
    }
    idx = (uintptr_t)txn;
    if (idx == 0u || idx > 2u) {
        return NULL;
    }
    if (impl->txns[idx - 1u].live == 0u) {
        return NULL;
    }
    return &impl->txns[idx - 1u];
}

static ninlil_storage_status_t ledger_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    ledger_impl_t *impl = impl_of(user);
    ledger_ns_t *ns;
    uint32_t i;
    uint32_t slot = 2u;
    ledger_txn_t *t;
    uintptr_t ns_idx;

    if (impl == NULL || out_txn == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    ns = ns_from_handle(impl, handle);
    if (ns == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (mode != NINLIL_STORAGE_READ_ONLY && mode != NINLIL_STORAGE_READ_WRITE) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    for (i = 0u; i < 2u; ++i) {
        if (impl->txns[i].live == 0u) {
            slot = i;
            break;
        }
    }
    if (slot >= 2u) {
        return NINLIL_STORAGE_BUSY;
    }
    ns_idx = (uintptr_t)handle - 1u;
    t = &impl->txns[slot];
    (void)memset(t, 0, sizeof(*t));
    t->live = 1u;
    t->mode = mode;
    t->ns_index = (uint32_t)ns_idx;
    t->staging_count = ns->entry_count;
    for (i = 0u; i < ns->entry_count; ++i) {
        t->staging[i] = ns->entries[i];
    }
    t->dirty = 0u;
    *out_txn = (ninlil_storage_txn_t)(uintptr_t)(slot + 1u);
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t ledger_get(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value)
{
    ledger_impl_t *impl = impl_of(user);
    ledger_txn_t *t;
    uint32_t i;
    uint32_t j;

    if (impl == NULL || inout_value == NULL || key.data == NULL
        || key.length == 0u || key.length > NINLIL_PCP_LAB_LEDGER_MAX_KEY) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    t = txn_from(impl, txn);
    if (t == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    for (i = 0u; i < t->staging_count; ++i) {
        if (t->staging[i].live != 0u
            && bytes_eq(
                   t->staging[i].key,
                   t->staging[i].key_len,
                   key.data,
                   key.length)) {
            if (inout_value->capacity < t->staging[i].val_len) {
                inout_value->length = t->staging[i].val_len;
                return NINLIL_STORAGE_BUFFER_TOO_SMALL;
            }
            if (inout_value->data == NULL && t->staging[i].val_len > 0u) {
                return NINLIL_STORAGE_IO_ERROR;
            }
            for (j = 0u; j < t->staging[i].val_len; ++j) {
                inout_value->data[j] = t->staging[i].val[j];
            }
            inout_value->length = t->staging[i].val_len;
            return NINLIL_STORAGE_OK;
        }
    }
    inout_value->length = 0u;
    return NINLIL_STORAGE_NOT_FOUND;
}

static ninlil_storage_status_t ledger_put(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    ledger_impl_t *impl = impl_of(user);
    ledger_txn_t *t;
    uint32_t i;
    uint32_t free_slot = NINLIL_PCP_LAB_LEDGER_MAX_ENTRIES;

    if (impl == NULL || key.data == NULL || key.length == 0u
        || key.length > NINLIL_PCP_LAB_LEDGER_MAX_KEY
        || value.length > NINLIL_PCP_LAB_LEDGER_MAX_VAL
        || (value.length > 0u && value.data == NULL)) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    t = txn_from(impl, txn);
    if (t == NULL || t->mode != NINLIL_STORAGE_READ_WRITE) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    for (i = 0u; i < t->staging_count; ++i) {
        if (t->staging[i].live != 0u
            && bytes_eq(
                   t->staging[i].key,
                   t->staging[i].key_len,
                   key.data,
                   key.length)) {
            free_slot = i;
            break;
        }
        if (t->staging[i].live == 0u && free_slot == NINLIL_PCP_LAB_LEDGER_MAX_ENTRIES) {
            free_slot = i;
        }
    }
    if (free_slot >= NINLIL_PCP_LAB_LEDGER_MAX_ENTRIES) {
        if (t->staging_count >= NINLIL_PCP_LAB_LEDGER_MAX_ENTRIES) {
            return NINLIL_STORAGE_NO_SPACE;
        }
        free_slot = t->staging_count;
        t->staging_count += 1u;
    }
    (void)memset(&t->staging[free_slot], 0, sizeof(t->staging[free_slot]));
    t->staging[free_slot].live = 1u;
    t->staging[free_slot].key_len = key.length;
    for (i = 0u; i < key.length; ++i) {
        t->staging[free_slot].key[i] = key.data[i];
    }
    t->staging[free_slot].val_len = value.length;
    for (i = 0u; i < value.length; ++i) {
        t->staging[free_slot].val[i] = value.data[i];
    }
    t->dirty = 1u;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t ledger_erase(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key)
{
    ledger_impl_t *impl = impl_of(user);
    ledger_txn_t *t;
    uint32_t i;

    if (impl == NULL || key.data == NULL || key.length == 0u) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    t = txn_from(impl, txn);
    if (t == NULL || t->mode != NINLIL_STORAGE_READ_WRITE) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    for (i = 0u; i < t->staging_count; ++i) {
        if (t->staging[i].live != 0u
            && bytes_eq(
                   t->staging[i].key,
                   t->staging[i].key_len,
                   key.data,
                   key.length)) {
            t->staging[i].live = 0u;
            t->dirty = 1u;
            return NINLIL_STORAGE_OK;
        }
    }
    return NINLIL_STORAGE_NOT_FOUND;
}

static ninlil_storage_status_t ledger_iter_open(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter)
{
    ledger_impl_t *impl = impl_of(user);
    ledger_txn_t *t;
    uint32_t i;
    uint32_t slot = 2u;
    ledger_iter_t *it;

    if (impl == NULL || out_iter == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (prefix.length > NINLIL_PCP_LAB_LEDGER_MAX_KEY
        || (prefix.length > 0u && prefix.data == NULL)) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    t = txn_from(impl, txn);
    if (t == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    for (i = 0u; i < 2u; ++i) {
        if (impl->iters[i].live == 0u) {
            slot = i;
            break;
        }
    }
    if (slot >= 2u) {
        return NINLIL_STORAGE_BUSY;
    }
    it = &impl->iters[slot];
    (void)memset(it, 0, sizeof(*it));
    it->live = 1u;
    it->ns_index = t->ns_index;
    it->txn_id = (uint32_t)(uintptr_t)txn;
    it->prefix_len = prefix.length;
    for (i = 0u; i < prefix.length; ++i) {
        it->prefix[i] = prefix.data[i];
    }
    it->cursor = 0u;
    *out_iter = (ninlil_storage_iter_t)(uintptr_t)(slot + 1u);
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t ledger_iter_next(
    void *user,
    ninlil_storage_iter_t iter,
    ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value)
{
    ledger_impl_t *impl = impl_of(user);
    ledger_iter_t *it;
    ledger_txn_t *t;
    uintptr_t idx;
    uint32_t i;
    uint32_t j;

    if (impl == NULL || iter == NULL || inout_key == NULL || inout_value == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    idx = (uintptr_t)iter;
    if (idx == 0u || idx > 2u || impl->iters[idx - 1u].live == 0u) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    it = &impl->iters[idx - 1u];
    t = txn_from(impl, (ninlil_storage_txn_t)(uintptr_t)it->txn_id);
    if (t == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    while (it->cursor < t->staging_count) {
        i = it->cursor;
        it->cursor += 1u;
        if (t->staging[i].live == 0u) {
            continue;
        }
        if (!has_prefix(
                t->staging[i].key,
                t->staging[i].key_len,
                it->prefix,
                it->prefix_len)) {
            continue;
        }
        if (inout_key->capacity < t->staging[i].key_len
            || inout_value->capacity < t->staging[i].val_len) {
            inout_key->length = t->staging[i].key_len;
            inout_value->length = t->staging[i].val_len;
            return NINLIL_STORAGE_BUFFER_TOO_SMALL;
        }
        if ((t->staging[i].key_len > 0u && inout_key->data == NULL)
            || (t->staging[i].val_len > 0u && inout_value->data == NULL)) {
            return NINLIL_STORAGE_IO_ERROR;
        }
        for (j = 0u; j < t->staging[i].key_len; ++j) {
            inout_key->data[j] = t->staging[i].key[j];
        }
        inout_key->length = t->staging[i].key_len;
        for (j = 0u; j < t->staging[i].val_len; ++j) {
            inout_value->data[j] = t->staging[i].val[j];
        }
        inout_value->length = t->staging[i].val_len;
        return NINLIL_STORAGE_OK;
    }
    inout_key->length = 0u;
    inout_value->length = 0u;
    return NINLIL_STORAGE_NOT_FOUND;
}

static void ledger_iter_close(void *user, ninlil_storage_iter_t iter)
{
    ledger_impl_t *impl = impl_of(user);
    uintptr_t idx;

    if (impl == NULL || iter == NULL) {
        return;
    }
    idx = (uintptr_t)iter;
    if (idx == 0u || idx > 2u) {
        return;
    }
    impl->iters[idx - 1u].live = 0u;
}

static ninlil_storage_status_t ledger_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *out_capacity)
{
    ledger_impl_t *impl = impl_of(user);
    ledger_ns_t *ns;
    uint32_t i;
    uint64_t used_e = 0u;
    uint64_t used_b = 0u;

    if (impl == NULL || out_capacity == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    ns = ns_from_handle(impl, handle);
    if (ns == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    for (i = 0u; i < ns->entry_count; ++i) {
        if (ns->entries[i].live != 0u) {
            used_e += 1u;
            used_b += ns->entries[i].val_len;
        }
    }
    (void)memset(out_capacity, 0, sizeof(*out_capacity));
    out_capacity->abi_version = NINLIL_ABI_VERSION;
    out_capacity->struct_size = (uint16_t)sizeof(*out_capacity);
    out_capacity->max_entries = NINLIL_PCP_LAB_LEDGER_MAX_ENTRIES;
    out_capacity->used_entries = used_e;
    out_capacity->max_bytes =
        (uint64_t)NINLIL_PCP_LAB_LEDGER_MAX_ENTRIES * NINLIL_PCP_LAB_LEDGER_MAX_VAL;
    out_capacity->used_bytes = used_b;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t ledger_commit(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_durability_t durability)
{
    ledger_impl_t *impl = impl_of(user);
    ledger_txn_t *t;
    ledger_ns_t *ns;
    uint32_t i;
    uint32_t w;

    (void)durability;
    if (impl == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    t = txn_from(impl, txn);
    if (t == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    ns = &impl->namespaces[t->ns_index];
    if (t->mode == NINLIL_STORAGE_READ_WRITE && t->dirty != 0u) {
        w = 0u;
        for (i = 0u; i < t->staging_count; ++i) {
            if (t->staging[i].live != 0u) {
                ns->entries[w] = t->staging[i];
                w += 1u;
            }
        }
        for (i = w; i < NINLIL_PCP_LAB_LEDGER_MAX_ENTRIES; ++i) {
            (void)memset(&ns->entries[i], 0, sizeof(ns->entries[i]));
        }
        ns->entry_count = w;
    }
    t->live = 0u;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t ledger_rollback(
    void *user,
    ninlil_storage_txn_t txn)
{
    ledger_impl_t *impl = impl_of(user);
    ledger_txn_t *t;

    if (impl == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    t = txn_from(impl, txn);
    if (t == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    t->live = 0u;
    return NINLIL_STORAGE_OK;
}

size_t ninlil_pcp_lab_session_ledger_object_bytes(void)
{
    return sizeof(ledger_impl_t);
}

int ninlil_pcp_lab_session_ledger_init(
    ninlil_pcp_lab_session_ledger_t *ledger,
    const ninlil_storage_ops_t **out_ops)
{
    ledger_impl_t *impl;

    if (ledger == NULL || out_ops == NULL) {
        return 1;
    }
    if (sizeof(ledger_impl_t) > sizeof(ledger->opaque)) {
        return 1;
    }
    (void)memset(ledger->opaque, 0, sizeof(ledger->opaque));
    impl = (ledger_impl_t *)(void *)ledger->opaque;
    impl->magic = LEDGER_MAGIC;
    impl->lifecycle = 1u;
    impl->ops.abi_version = NINLIL_ABI_VERSION;
    impl->ops.struct_size = (uint16_t)sizeof(impl->ops);
    impl->ops.user = ledger;
    impl->ops.open = ledger_open;
    impl->ops.close = ledger_close;
    impl->ops.begin = ledger_begin;
    impl->ops.get = ledger_get;
    impl->ops.put = ledger_put;
    impl->ops.erase = ledger_erase;
    impl->ops.iter_open = ledger_iter_open;
    impl->ops.iter_next = ledger_iter_next;
    impl->ops.iter_close = ledger_iter_close;
    impl->ops.capacity = ledger_capacity;
    impl->ops.commit = ledger_commit;
    impl->ops.rollback = ledger_rollback;
    *out_ops = &impl->ops;
    return 0;
}

void ninlil_pcp_lab_session_ledger_shutdown(
    ninlil_pcp_lab_session_ledger_t *ledger)
{
    ledger_impl_t *impl;

    if (ledger == NULL) {
        return;
    }
    impl = (ledger_impl_t *)(void *)ledger->opaque;
    if (impl->magic != LEDGER_MAGIC) {
        return;
    }
    impl->lifecycle = 2u;
    (void)memset(&impl->ops, 0, sizeof(impl->ops));
}
