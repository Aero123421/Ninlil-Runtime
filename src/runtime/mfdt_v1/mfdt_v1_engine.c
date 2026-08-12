/* SPDX-License-Identifier: Apache-2.0 */
/*
 * MFDT v1 private engine: default-OFF, fixed workspace, durable multi-key FULL.
 * ADR-0021 production state machine (host lab store adapter; not ESP flash).
 */
#include "mfdt_v1.h"
#include "mfdt_v1_store_port.h"
#include <string.h>
#if defined(NINLIL_MFDT_V1_HOST_DIAGNOSTICS)
#include <stdio.h>
#endif

/* ---- Caller-owned 64 KiB arena; custody lives in durable store ---------- */
#define MFDT_WS_RECORD_BYTES ((size_t)35216u)
#define MFDT_WS_NRC1_BYTES   ((size_t)15024u)
#define MFDT_WS_XFER_BYTES   ((size_t)512u)
#define MFDT_WS_OPEN_MAX     ((size_t)656u)
#define MFDT_WS_ENTRIES_BYTES \
    ((size_t)NINLIL_MFDT_V1_MAX_CHUNKS * \
     (size_t)NINLIL_MFDT_V1_ENTRY_BYTES)
#define MFDT_WS_RECORD_OFF   ((size_t)0u)
#define MFDT_WS_NRC1_OFF     (MFDT_WS_RECORD_OFF + MFDT_WS_RECORD_BYTES)
#define MFDT_WS_XFER_OFF     (MFDT_WS_NRC1_OFF + MFDT_WS_NRC1_BYTES)
#define MFDT_WS_OPEN_OFF     (MFDT_WS_XFER_OFF + MFDT_WS_XFER_BYTES)
#define MFDT_WS_ENTRIES_OFF  (MFDT_WS_OPEN_OFF + MFDT_WS_OPEN_MAX)

typedef struct mfdt_xfer {
    uint8_t transfer_id[16];
    uint8_t occupied;
    uint8_t role; /* 1=sender 2=receiver */
    uint8_t state_code;
    uint8_t retry_budget;
    uint8_t terminal;
    uint16_t chunk_count;
    uint16_t page_count;
    uint32_t total_length;
    uint64_t chunk_bitmap;
    uint8_t page_bitmap;
    uint8_t manifest_digest[32];
    uint8_t whole_digest[32];
    uint8_t reservation_id[16];
    uint8_t res_epoch[16];
    uint64_t not_after_ms;
    uint8_t durable_local_epoch[16];
    uint64_t durable_local_mono_ms;
    uint64_t record_generation;
    uint64_t acceptance_record_generation;
    uint32_t last_resume_gen;
    uint32_t abort_generation;
    uint32_t revision;
    uint16_t open_len;
    uint8_t publication_state;
    uint8_t handoff_state;
    uint8_t accept_notified;
    uint8_t publication_token[16];
    uint8_t evidence_id[16];
    uint8_t acceptance_record_digest[32];
    uint8_t publication_evidence_digest[32];
    uint8_t unpaid_chunk; /* fairness */
} mfdt_xfer_t;

_Static_assert(sizeof(mfdt_xfer_t) <= MFDT_WS_XFER_BYTES,
               "xfer meta must fit owner arena");
_Static_assert(MFDT_WS_ENTRIES_OFF + MFDT_WS_ENTRIES_BYTES <=
                   NINLIL_MFDT_V1_WORKSPACE_BYTES,
               "owner scratch must fit exact 64 KiB workspace");
_Static_assert(MFDT_WS_RECORD_BYTES >=
                   (size_t)NINLIL_MFDT_V1_ACTIVE_VALUE_MAX + 1u,
               "record region capacity");
_Static_assert(MFDT_WS_NRC1_BYTES >=
                   (size_t)NINLIL_MFDT_V1_NRC1_VALUE_BYTES,
               "NRC1 region capacity");

static mfdt_xfer_t *xfer_ptr(ninlil_mfdt_v1_engine_t *eng)
{
    if (eng != NULL && eng->slot_layout != 0u) {
        return (mfdt_xfer_t *)(void *)eng->slot_xfer_memory;
    }
    return NULL;
}

static uint8_t *content_ptr(ninlil_mfdt_v1_engine_t *eng)
{
    if (eng != NULL && eng->slot_layout != 0u) {
        mfdt_xfer_t *x = xfer_ptr(eng);
        if (eng->slot_record_packed != 0u) {
            const size_t off =
                (size_t)NINLIL_MFDT_V1_ACTIVE_HEADER_BYTES +
                (size_t)x->open_len +
                (size_t)x->chunk_count * NINLIL_MFDT_V1_ENTRY_BYTES;
            return eng->slot_record_memory + off;
        }
        return eng->slot_record_memory;
    }
    return NULL;
}

static uint8_t *entries_ptr(ninlil_mfdt_v1_engine_t *eng)
{
    if (eng != NULL && eng->slot_layout != 0u) {
        mfdt_xfer_t *x = xfer_ptr(eng);
        if (eng->slot_record_packed != 0u) {
            return eng->slot_record_memory +
                   NINLIL_MFDT_V1_ACTIVE_HEADER_BYTES + x->open_len;
        }
        return eng->slot_entries_staging;
    }
    return NULL;
}

static uint8_t *open_ptr(ninlil_mfdt_v1_engine_t *eng)
{
    if (eng != NULL && eng->slot_layout != 0u) {
        if (eng->slot_record_packed != 0u) {
            return eng->slot_record_memory +
                   NINLIL_MFDT_V1_ACTIVE_HEADER_BYTES;
        }
        return eng->slot_open_staging;
    }
    return NULL;
}

static uint8_t *engine_record_scratch(ninlil_mfdt_v1_engine_t *eng)
{
    return eng != NULL && eng->slot_layout != 0u
               ? eng->slot_record_memory : NULL;
}

static uint8_t *engine_nrc1_scratch(ninlil_mfdt_v1_engine_t *eng)
{
    return eng != NULL && eng->slot_layout != 0u
               ? eng->slot_nrc1_memory : NULL;
}

static void make_key(uint8_t key[20], const char magic[4], const uint8_t tid[16])
{
    (void)memcpy(key, magic, 4u);
    (void)memcpy(key + 4, tid, 16u);
}

static int policy_ok(const ninlil_mfdt_v1_engine_t *eng)
{
    if (eng->cfg.policy != NINLIL_MFDT_V1_POLICY_ON) {
        return NINLIL_MFDT_V1_ERR_POLICY_OFF;
    }
    if (eng->cfg.mfdt_admission_version !=
        NINLIL_MFDT_V1_ADMISSION_VERSION) {
        return NINLIL_MFDT_V1_ERR_VERSION;
    }
    if (eng->cfg.mfdt_capability == 0u ||
        eng->cfg.session_generation == 0u) {
        return NINLIL_MFDT_V1_ERR_VERSION;
    }
    return NINLIL_MFDT_V1_OK;
}

static uint8_t active_max(const ninlil_mfdt_v1_engine_t *eng)
{
    /*
     * This type is deliberately a single-transfer primitive.  The Host
     * reference profile reaches four active transfers by owning four engines
     * in its coordinator; host_mode only selects Host storage/replay policy.
     * Treating one engine as four slots would alias every transfer onto the
     * single mfdt_xfer_t embedded in its workspace.
     */
    (void)eng;
    return NINLIL_MFDT_V1_ESP_ACTIVE_MAX;
}

/*
 * NRC1 proves which first response bytes were stored; it does not prove that
 * an ESP FULL was physically attested.  Until the HIL gate is enabled, target
 * profile replay must remain fail-closed across both warm retry and restart.
 * Host FULL-capable storage keeps the normal bit-exact replay contract.
 */
static int nrc1_replay_eligible(const ninlil_mfdt_v1_engine_t *eng)
{
    if (eng == NULL) {
        return 0;
    }
#if defined(ESP_PLATFORM)
    /*
     * On the real target, storage trust is a build property rather than a
     * caller-controlled profile bit.  This prevents host_mode from becoming
     * an attestation bypass if target configuration is corrupted.
     */
    return ninlil_mfdt_v1_hil_full_promotion_enabled() != 0;
#else
    return eng->cfg.host_mode != 0u ||
           ninlil_mfdt_v1_hil_full_promotion_enabled() != 0;
#endif
}

static int is_zero16(const uint8_t *p)
{
    static const uint8_t z[16] = {0};
    return ninlil_mfdt_v1_memeq(p, z, 16u);
}

static int is_zero32(const uint8_t *p)
{
    static const uint8_t z[32] = {0};
    return ninlil_mfdt_v1_memeq(p, z, 32u);
}

static uint16_t request_stage_for_type(uint8_t request_type)
{
    switch (request_type) {
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

static int fill_reject_for_active(
    ninlil_mfdt_v1_engine_t *eng, uint16_t stage, uint16_t code,
    uint32_t detail, ninlil_mfdt_v1_response_t *resp)
{
    mfdt_xfer_t *x;
    if (eng == NULL || resp == NULL || stage < 1u || stage > 6u ||
        code < NINLIL_MFDT_V1_REJ_LAYOUT ||
        code > NINLIL_MFDT_V1_REJ_ABORT_DENIED) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    x = xfer_ptr(eng);
    if (x == NULL || x->occupied == 0u || x->terminal != 0u ||
        is_zero16(x->transfer_id) || x->revision == 0u ||
        is_zero32(x->manifest_digest)) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    ninlil_mfdt_v1_memzero(resp, sizeof(*resp));
    ninlil_mfdt_v1_bind52(
        x->transfer_id, x->revision, x->manifest_digest, resp->body);
    ninlil_mfdt_v1_put_u16(resp->body + 52, stage);
    ninlil_mfdt_v1_put_u16(resp->body + 54, code);
    ninlil_mfdt_v1_put_u32(resp->body + 56, detail);
    resp->message_type = NINLIL_MFDT_V1_MSG_REJECT;
    resp->reject_code = code;
    resp->body_len = 60u;
    return NINLIL_MFDT_V1_OK;
}

static int manifest_text_id_ok(const uint8_t *bytes, uint16_t len,
                               int namespace_rules)
{
    uint16_t i;
    if (bytes == NULL || len == 0u || len > 63u ||
        !((bytes[0] >= (uint8_t)'a' && bytes[0] <= (uint8_t)'z') ||
          (bytes[0] >= (uint8_t)'0' && bytes[0] <= (uint8_t)'9'))) {
        return 0;
    }
    for (i = 0u; i < len; ++i) {
        const uint8_t c = bytes[i];
        if ((c >= (uint8_t)'a' && c <= (uint8_t)'z') ||
            (c >= (uint8_t)'0' && c <= (uint8_t)'9') ||
            c == (uint8_t)'.' || c == (uint8_t)'-' ||
            (!namespace_rules && c == (uint8_t)'_')) {
            continue;
        }
        return 0;
    }
    return 1;
}

/* ---- Multi-key FULL helpers --------------------------------------------- */

static void host_pending_delta_clear(ninlil_mfdt_v1_engine_t *eng)
{
    if (eng != NULL) {
        eng->host_pending_key_delta = 0;
        eng->host_pending_logical_delta = 0;
    }
}

static void host_pending_delta_set(ninlil_mfdt_v1_engine_t *eng,
                                   int32_t key_delta,
                                   int64_t logical_delta)
{
    if (eng != NULL && eng->store_port != NULL) {
        eng->host_pending_key_delta = key_delta;
        eng->host_pending_logical_delta = logical_delta;
    }
}

static int host_pending_delta_preflight(const ninlil_mfdt_v1_engine_t *eng)
{
    uint64_t next_bytes;
    uint32_t next_keys;
    if (eng == NULL || eng->store_port == NULL) {
        return NINLIL_MFDT_V1_OK;
    }
    if (eng->host_committed_keys == NULL ||
        eng->host_committed_logical_bytes == NULL ||
        eng->host_full_locked == NULL ||
        eng->host_inventory_uncertain == NULL) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (*eng->host_inventory_uncertain != 0u) {
        return NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN;
    }
    if (eng->host_pending_key_delta < 0) {
        const uint32_t magnitude =
            (uint32_t)(-eng->host_pending_key_delta);
        if (*eng->host_committed_keys < magnitude) {
            return NINLIL_MFDT_V1_ERR_CORRUPT;
        }
        next_keys = *eng->host_committed_keys - magnitude;
    } else {
        const uint32_t magnitude =
            (uint32_t)eng->host_pending_key_delta;
        if (*eng->host_committed_keys >
            NINLIL_MFDT_V1_HOST_COMMITTED_KEYS_MAX - magnitude) {
            return NINLIL_MFDT_V1_ERR_CAPACITY;
        }
        next_keys = *eng->host_committed_keys + magnitude;
    }
    if (eng->host_pending_logical_delta < 0) {
        const uint64_t magnitude =
            (uint64_t)(-eng->host_pending_logical_delta);
        if (*eng->host_committed_logical_bytes < magnitude) {
            return NINLIL_MFDT_V1_ERR_CORRUPT;
        }
        next_bytes = *eng->host_committed_logical_bytes - magnitude;
    } else {
        const uint64_t magnitude =
            (uint64_t)eng->host_pending_logical_delta;
        if (*eng->host_committed_logical_bytes >
            NINLIL_MFDT_V1_HOST_COMMITTED_LOGICAL_BYTES_MAX - magnitude) {
            return NINLIL_MFDT_V1_ERR_CAPACITY;
        }
        next_bytes = *eng->host_committed_logical_bytes + magnitude;
    }
    if (next_keys > NINLIL_MFDT_V1_HOST_COMMITTED_KEYS_MAX ||
        next_bytes > NINLIL_MFDT_V1_HOST_COMMITTED_LOGICAL_BYTES_MAX) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    return NINLIL_MFDT_V1_OK;
}

static void host_pending_delta_publish(ninlil_mfdt_v1_engine_t *eng)
{
    if (eng == NULL || eng->store_port == NULL) {
        return;
    }
    if (eng->host_pending_key_delta < 0) {
        *eng->host_committed_keys -=
            (uint32_t)(-eng->host_pending_key_delta);
    } else {
        *eng->host_committed_keys +=
            (uint32_t)eng->host_pending_key_delta;
    }
    if (eng->host_pending_logical_delta < 0) {
        *eng->host_committed_logical_bytes -=
            (uint64_t)(-eng->host_pending_logical_delta);
    } else {
        *eng->host_committed_logical_bytes +=
            (uint64_t)eng->host_pending_logical_delta;
    }
}

static int full_begin(ninlil_mfdt_v1_engine_t *eng)
{
    int rc;
    if (eng != NULL && eng->store_port != NULL) {
        rc = host_pending_delta_preflight(eng);
        if (rc != NINLIL_MFDT_V1_OK) {
            host_pending_delta_clear(eng);
            return rc;
        }
        if (*eng->host_full_locked != 0u) {
            host_pending_delta_clear(eng);
            return NINLIL_MFDT_V1_ERR_BUSY;
        }
        *eng->host_full_locked = 1u;
        rc = ninlil_mfdt_v1_store_full_begin(
            eng->store_port, *eng->host_committed_keys,
            *eng->host_committed_logical_bytes);
        if (rc != NINLIL_MFDT_V1_OK) {
            *eng->host_full_locked = 0u;
            host_pending_delta_clear(eng);
        }
        return rc;
    }
    return ninlil_mfdt_v1_lab_full_begin(eng->store);
}

static int full_commit(ninlil_mfdt_v1_engine_t *eng)
{
    int rc;
    if (eng != NULL && eng->store_port != NULL) {
        rc = ninlil_mfdt_v1_store_full_commit(eng->store_port);
        if (rc == NINLIL_MFDT_V1_OK) {
            host_pending_delta_publish(eng);
            eng->fulls_this_transfer += 1u;
        } else if (rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN ||
                   rc == NINLIL_MFDT_V1_ERR_CU_NEW_NOT_PROMOTED) {
            *eng->host_inventory_uncertain = 1u;
            rc = NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN;
        }
        *eng->host_full_locked = 0u;
        host_pending_delta_clear(eng);
        return rc;
    }
    rc = ninlil_mfdt_v1_lab_full_commit(eng->store);
    /*
     * ADR-0021: CU read-back NEW must not become external/wire success until
     * HIL attestation gate is enabled (default fail-closed).
     */
    if (rc == NINLIL_MFDT_V1_ERR_CU_NEW_NOT_PROMOTED) {
        if (ninlil_mfdt_v1_hil_full_promotion_enabled() != 0) {
            eng->fulls_this_transfer += 1u;
            return NINLIL_MFDT_V1_OK;
        }
        return NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN;
    }
    if (rc == NINLIL_MFDT_V1_OK) {
        eng->fulls_this_transfer += 1u;
    }
    return rc;
}

static int full_rollback(ninlil_mfdt_v1_engine_t *eng)
{
    int rc;
    if (eng != NULL && eng->store_port != NULL) {
        rc = ninlil_mfdt_v1_store_full_rollback(eng->store_port);
        if (rc != NINLIL_MFDT_V1_OK) {
            *eng->host_inventory_uncertain = 1u;
        }
        *eng->host_full_locked = 0u;
        host_pending_delta_clear(eng);
        return rc;
    }
    return ninlil_mfdt_v1_lab_full_rollback(eng->store);
}

static int store_put(ninlil_mfdt_v1_engine_t *eng, const uint8_t key[20],
                     const uint8_t *value, uint32_t value_len)
{
    if (eng != NULL && eng->store_port != NULL) {
        return ninlil_mfdt_v1_store_full_put(
            eng->store_port, key, value, value_len);
    }
    return ninlil_mfdt_v1_lab_put(eng->store, key, value, value_len);
}

static int store_erase(ninlil_mfdt_v1_engine_t *eng, const uint8_t key[20])
{
    if (eng != NULL && eng->store_port != NULL) {
        return ninlil_mfdt_v1_store_full_erase(eng->store_port, key);
    }
    return ninlil_mfdt_v1_lab_del(eng->store, key);
}

static int store_get(ninlil_mfdt_v1_engine_t *eng, const uint8_t key[20],
                     uint8_t *value_out, uint32_t value_cap,
                     uint32_t *value_len_out)
{
    int present = 0;
    int rc;
    if (eng == NULL || key == NULL || value_len_out == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (eng->store_port == NULL) {
        return ninlil_mfdt_v1_lab_get(
            eng->store, key, value_out, value_cap, value_len_out);
    }
    if (value_out == NULL && value_cap == 0u) {
        ninlil_storage_txn_t txn = NULL;
        ninlil_mut_bytes_t probe;
        ninlil_bytes_view_t key_view;
        ninlil_storage_status_t status;
        ninlil_storage_status_t end_status;
        if (eng->store_port->full_open != 0u ||
            eng->store_port->snapshot_open != 0u) {
            return NINLIL_MFDT_V1_ERR_BUSY;
        }
        status = eng->store_port->ops->begin(
            eng->store_port->ops->user, eng->store_port->handle,
            NINLIL_STORAGE_READ_ONLY, &txn);
        if ((status == NINLIL_STORAGE_OK) != (txn != NULL)) {
            ninlil_storage_status_t rollback_status =
                NINLIL_STORAGE_OK;
            if (txn != NULL) {
                rollback_status =
                    eng->store_port->ops->rollback(
                        eng->store_port->ops->user, txn);
            }
            if (rollback_status != NINLIL_STORAGE_OK &&
                eng->host_inventory_uncertain != NULL) {
                *eng->host_inventory_uncertain = 1u;
            }
            return rollback_status != NINLIL_STORAGE_OK
                       ? ninlil_mfdt_v1_store_map_status(
                             rollback_status)
                       : NINLIL_MFDT_V1_ERR_CORRUPT;
        }
        if (status != NINLIL_STORAGE_OK) {
            return ninlil_mfdt_v1_store_map_status(status);
        }
        key_view.data = key;
        key_view.length = NINLIL_MFDT_V1_KEY_BYTES;
        probe.data = NULL;
        probe.capacity = 0u;
        probe.length = 0u;
        status = eng->store_port->ops->get(
            eng->store_port->ops->user, txn, key_view, &probe);
        *value_len_out = probe.length;
        end_status = eng->store_port->ops->rollback(
            eng->store_port->ops->user, txn);
        if (end_status != NINLIL_STORAGE_OK) {
            if (eng->host_inventory_uncertain != NULL) {
                *eng->host_inventory_uncertain = 1u;
            }
            return ninlil_mfdt_v1_store_map_status(end_status);
        }
        if (probe.data != NULL || probe.capacity != 0u ||
            (status == NINLIL_STORAGE_OK && probe.length != 0u) ||
            (status == NINLIL_STORAGE_NOT_FOUND &&
             probe.length != 0u) ||
            (status == NINLIL_STORAGE_BUFFER_TOO_SMALL &&
             probe.length == 0u) ||
            (status != NINLIL_STORAGE_OK &&
            status != NINLIL_STORAGE_NOT_FOUND &&
             status != NINLIL_STORAGE_BUFFER_TOO_SMALL &&
             probe.length != 0u)) {
            if (eng->host_inventory_uncertain != NULL) {
                *eng->host_inventory_uncertain = 1u;
            }
            return NINLIL_MFDT_V1_ERR_CORRUPT;
        }
        if (status == NINLIL_STORAGE_OK ||
            status == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
            return NINLIL_MFDT_V1_OK;
        }
        if (status == NINLIL_STORAGE_NOT_FOUND) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        return ninlil_mfdt_v1_store_map_status(status);
    }
    rc = ninlil_mfdt_v1_store_read(
        eng->store_port, key, value_out, value_cap, value_len_out, &present);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    return present != 0 ? NINLIL_MFDT_V1_OK : NINLIL_MFDT_V1_ERR_STATE;
}

/* Single-key FULL (put only). */
static int full_put_one(ninlil_mfdt_v1_engine_t *eng, const uint8_t key[20],
                        const uint8_t *val, uint32_t vlen)
{
    int rc;
    host_pending_delta_set(eng, 0, 0);
    rc = full_begin(eng);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = store_put(eng, key, val, vlen);
    if (rc != NINLIL_MFDT_V1_OK) {
        (void)full_rollback(eng);
        return rc;
    }
    return full_commit(eng);
}

/* Co-located put active + put NRC1 (ADR §On request step 3). */
static int full_put_active_and_nrc1(ninlil_mfdt_v1_engine_t *eng,
                                    const uint8_t akey[20],
                                    const uint8_t *aval, uint32_t alen,
                                    const uint8_t nkey[20],
                                    const uint8_t *nval, uint32_t nlen)
{
    int rc;
    const int fresh =
        eng != NULL && eng->store_port != NULL &&
        eng->durable_active_value_len == 0u;
    if (fresh) {
        host_pending_delta_set(
            eng, 2,
            (int64_t)alen + NINLIL_MFDT_V1_STORE_ROW_LOGICAL_FIXED_BYTES +
                (int64_t)nlen +
                NINLIL_MFDT_V1_STORE_ROW_LOGICAL_FIXED_BYTES);
    } else {
        host_pending_delta_set(eng, 0, 0);
    }
    rc = full_begin(eng);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = store_put(eng, akey, aval, alen);
    if (rc != NINLIL_MFDT_V1_OK) {
        (void)full_rollback(eng);
        return rc;
    }
    rc = store_put(eng, nkey, nval, nlen);
    if (rc != NINLIL_MFDT_V1_OK) {
        (void)full_rollback(eng);
        return rc;
    }
    rc = full_commit(eng);
    if (rc == NINLIL_MFDT_V1_OK && eng->store_port != NULL) {
        eng->durable_active_value_len = alen;
    }
    return rc;
}

/* Terminal: erase active + put NM30 in one FULL; NRC1 retained. */
static int full_terminal(ninlil_mfdt_v1_engine_t *eng, const uint8_t akey[20],
                         const uint8_t nkey[20], const uint8_t *nm30,
                         uint32_t nlen)
{
    int rc;
    if (eng != NULL && eng->store_port != NULL) {
        if (eng->durable_active_value_len == 0u) {
            return NINLIL_MFDT_V1_ERR_CORRUPT;
        }
        host_pending_delta_set(
            eng, 0, (int64_t)nlen -
                        (int64_t)eng->durable_active_value_len);
    }
    rc = full_begin(eng);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = store_erase(eng, akey);
    if (rc != NINLIL_MFDT_V1_OK) {
        (void)full_rollback(eng);
        return rc;
    }
    rc = store_put(eng, nkey, nm30, nlen);
    if (rc != NINLIL_MFDT_V1_OK) {
        (void)full_rollback(eng);
        return rc;
    }
    rc = full_commit(eng);
    if (rc == NINLIL_MFDT_V1_OK && eng->store_port != NULL) {
        eng->durable_active_value_len = 0u;
    }
    return rc;
}

/* Terminal response: active erase + NM30 put + NRC1 response in one FULL. */
static int full_terminal_with_nrc1(
    ninlil_mfdt_v1_engine_t *eng, const uint8_t akey[20],
    const uint8_t tkey[20], const uint8_t *nm30, uint32_t nm30_len,
    const uint8_t nkey[20], const uint8_t *nrc1, uint32_t nrc1_len)
{
    int rc;
    if (eng != NULL && eng->store_port != NULL) {
        if (eng->durable_active_value_len == 0u) {
            return NINLIL_MFDT_V1_ERR_CORRUPT;
        }
        host_pending_delta_set(
            eng, 0, (int64_t)nm30_len -
                        (int64_t)eng->durable_active_value_len);
    }
    rc = full_begin(eng);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = store_erase(eng, akey);
    if (rc == NINLIL_MFDT_V1_OK) {
        rc = store_put(eng, tkey, nm30, nm30_len);
    }
    if (rc == NINLIL_MFDT_V1_OK) {
        rc = store_put(eng, nkey, nrc1, nrc1_len);
    }
    if (rc != NINLIL_MFDT_V1_OK) {
        (void)full_rollback(eng);
        return rc;
    }
    rc = full_commit(eng);
    if (rc == NINLIL_MFDT_V1_OK && eng->store_port != NULL) {
        eng->durable_active_value_len = 0u;
    }
    return rc;
}

/* Retention GC: erase NM30 + NRC1 together. */
static int full_gc(ninlil_mfdt_v1_engine_t *eng, const uint8_t k30[20],
                   const uint8_t kn[20])
{
    int rc;
    if (eng != NULL && eng->store_port != NULL) {
        host_pending_delta_set(
            eng, -2,
            -(int64_t)(NINLIL_MFDT_V1_NM30_BYTES +
                       NINLIL_MFDT_V1_NRC1_VALUE_BYTES +
                       2u * NINLIL_MFDT_V1_STORE_ROW_LOGICAL_FIXED_BYTES));
    }
    rc = full_begin(eng);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = store_erase(eng, k30);
    if (rc != NINLIL_MFDT_V1_OK) {
        (void)full_rollback(eng);
        return rc;
    }
    rc = store_erase(eng, kn);
    if (rc != NINLIL_MFDT_V1_OK) {
        (void)full_rollback(eng);
        return rc;
    }
    return full_commit(eng);
}

/* ---- NRC1 exact ADR layout (15020, big-endian fields) ------------------- */
/* offset: magic4 schema2 vlen2 tid16 sess4 slot2 occ2 seq4 hcrc4 | slots | rcrc4 */

#define MFDT_NRC1_SLOTS_OFF ((size_t)40u)
#define MFDT_NRC1_RECORD_CRC_OFF ((size_t)15016u)

static void nrc1_recompute_crc(uint8_t *blob)
{
    ninlil_mfdt_v1_put_u32(blob + 36, ninlil_mfdt_v1_crc32c(blob, 36u));
    ninlil_mfdt_v1_put_u32(blob + MFDT_NRC1_RECORD_CRC_OFF,
                           ninlil_mfdt_v1_crc32c(
                               blob, MFDT_NRC1_RECORD_CRC_OFF));
}

static void nrc1_init_empty(uint8_t *blob, const uint8_t tid[16],
                            uint32_t session_gen)
{
    ninlil_mfdt_v1_memzero(blob, NINLIL_MFDT_V1_NRC1_VALUE_BYTES);
    (void)memcpy(blob + 0, "NRC1", 4u);
    ninlil_mfdt_v1_put_u16(blob + 4, 1u);
    ninlil_mfdt_v1_put_u16(blob + 6, NINLIL_MFDT_V1_NRC1_VALUE_BYTES);
    (void)memcpy(blob + 8, tid, 16u);
    ninlil_mfdt_v1_put_u32(blob + 24, session_gen);
    ninlil_mfdt_v1_put_u16(blob + 28, NINLIL_MFDT_V1_NRC1_SLOT_COUNT);
    ninlil_mfdt_v1_put_u16(blob + 30, 0u);
    ninlil_mfdt_v1_put_u32(blob + 32, 0u);
    nrc1_recompute_crc(blob);
}

static int nrc1_response_body_length_ok(uint16_t type, uint16_t len)
{
    switch (type) {
    case NINLIL_MFDT_V1_MSG_OPEN_ACCEPT:
        return len == 100u;
    case NINLIL_MFDT_V1_MSG_PAGE_ACCEPT:
        return len == 108u;
    case NINLIL_MFDT_V1_MSG_REJECT:
    case NINLIL_MFDT_V1_MSG_BUSY:
        return len == 60u;
    case NINLIL_MFDT_V1_MSG_CHUNK_ACCEPT:
        return len == 88u;
    case NINLIL_MFDT_V1_MSG_RESUME_STATE:
        return len == 108u;
    case NINLIL_MFDT_V1_MSG_TRANSFER_ACCEPT:
        return len == 160u;
    case NINLIL_MFDT_V1_MSG_ABORT_ACK:
        return len == 92u;
    default:
        return 0;
    }
}

static int nrc1_validate(const uint8_t *blob, uint32_t len,
                         const uint8_t tid[16])
{
    uint16_t schema;
    uint16_t vlen;
    uint16_t slots;
    uint16_t occ;
    uint16_t counted = 0u;
    uint16_t i;
    uint32_t current_generation;
    uint32_t anchor_generation = 0u;
    uint8_t distinct_generation_count = 1u;
    uint8_t has_prior_generation = 0u;
    uint32_t seq;
    if (blob == NULL || len != NINLIL_MFDT_V1_NRC1_VALUE_BYTES) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (!ninlil_mfdt_v1_memeq(blob, "NRC1", 4u)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    schema = ninlil_mfdt_v1_get_u16(blob + 4);
    vlen = ninlil_mfdt_v1_get_u16(blob + 6);
    slots = ninlil_mfdt_v1_get_u16(blob + 28);
    occ = ninlil_mfdt_v1_get_u16(blob + 30);
    current_generation = ninlil_mfdt_v1_get_u32(blob + 24);
    seq = ninlil_mfdt_v1_get_u32(blob + 32);
    if (schema != 1u || vlen != NINLIL_MFDT_V1_NRC1_VALUE_BYTES ||
        slots != NINLIL_MFDT_V1_NRC1_SLOT_COUNT ||
        occ > NINLIL_MFDT_V1_NRC1_SLOT_COUNT ||
        current_generation == 0u ||
        seq < (uint32_t)occ) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (tid != NULL && !ninlil_mfdt_v1_memeq(blob + 8, tid, 16u)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (ninlil_mfdt_v1_get_u32(blob + 36) != ninlil_mfdt_v1_crc32c(blob, 36u)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (ninlil_mfdt_v1_get_u32(blob + MFDT_NRC1_RECORD_CRC_OFF) !=
        ninlil_mfdt_v1_crc32c(blob, MFDT_NRC1_RECORD_CRC_OFF)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    for (i = 0u; i < NINLIL_MFDT_V1_NRC1_SLOT_COUNT; ++i) {
        const uint8_t *s =
            blob + MFDT_NRC1_SLOTS_OFF +
            (size_t)i * NINLIL_MFDT_V1_NRC1_SLOT_BYTES;
        const uint64_t rid = ninlil_mfdt_v1_get_u64(s + 0);
        const uint32_t generation = ninlil_mfdt_v1_get_u32(s + 8);
        const uint16_t type = ninlil_mfdt_v1_get_u16(s + 44);
        const uint16_t body_len = ninlil_mfdt_v1_get_u16(s + 46);
        uint16_t j;
        if (rid == 0ull) {
            static const uint8_t zero_slot[NINLIL_MFDT_V1_NRC1_SLOT_BYTES] =
                {0};
            if (!ninlil_mfdt_v1_memeq(
                    s, zero_slot, NINLIL_MFDT_V1_NRC1_SLOT_BYTES)) {
                return NINLIL_MFDT_V1_ERR_CORRUPT;
            }
            continue;
        }
        counted = (uint16_t)(counted + 1u);
        if (generation == 0u ||
            (generation != current_generation &&
             (current_generation == 1u ||
              generation != current_generation - 1u)) ||
            is_zero32(s + 12) ||
            !nrc1_response_body_length_ok(type, body_len)) {
            return NINLIL_MFDT_V1_ERR_CORRUPT;
        }
        if (generation != current_generation) {
            has_prior_generation = 1u;
            if (type == (uint16_t)NINLIL_MFDT_V1_MSG_RESUME_STATE) {
                /* Advance must reclaim every prior-generation RESUME slot. */
                return NINLIL_MFDT_V1_ERR_CORRUPT;
            }
        }
        if (type == (uint16_t)NINLIL_MFDT_V1_MSG_OPEN_ACCEPT &&
            (anchor_generation == 0u ||
             generation < anchor_generation)) {
            anchor_generation = generation;
        }
        for (j = body_len; j < 160u; ++j) {
            if (s[48u + j] != 0u) {
                return NINLIL_MFDT_V1_ERR_CORRUPT;
            }
        }
        for (j = (uint16_t)(i + 1u);
             j < NINLIL_MFDT_V1_NRC1_SLOT_COUNT; ++j) {
            const uint8_t *other =
                blob + MFDT_NRC1_SLOTS_OFF +
                (size_t)j * NINLIL_MFDT_V1_NRC1_SLOT_BYTES;
            if (ninlil_mfdt_v1_get_u64(other + 0) == rid &&
                ninlil_mfdt_v1_get_u32(other + 8) == generation) {
                return NINLIL_MFDT_V1_ERR_CORRUPT;
            }
        }
    }
    if (counted != occ) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (has_prior_generation != 0u) {
        distinct_generation_count = 2u;
    }
    if (distinct_generation_count >
            NINLIL_MFDT_V1_SESSION_GENERATIONS_MAX_PER_TRANSFER ||
        (has_prior_generation != 0u &&
         (anchor_generation == 0u ||
          anchor_generation != current_generation - 1u))) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    return NINLIL_MFDT_V1_OK;
}

static uint8_t *nrc1_slot_at(uint8_t *blob, uint16_t i)
{
    return blob + MFDT_NRC1_SLOTS_OFF +
           (size_t)i * NINLIL_MFDT_V1_NRC1_SLOT_BYTES;
}

static int nrc1_load(ninlil_mfdt_v1_engine_t *eng, const uint8_t tid[16],
                     uint8_t *blob, int *present)
{
    uint8_t key[20];
    uint32_t len = 0u;
    int rc;
    make_key(key, "NRC1", tid);
    *present = 0;
    rc = store_get(eng, key, blob,
                   NINLIL_MFDT_V1_NRC1_VALUE_BYTES, &len);
    if (rc != NINLIL_MFDT_V1_OK) {
        nrc1_init_empty(blob, tid, eng->cfg.session_generation);
        return NINLIL_MFDT_V1_OK;
    }
    *present = 1;
    rc = nrc1_validate(blob, len, tid);
    if (rc != NINLIL_MFDT_V1_OK ||
        ninlil_mfdt_v1_get_u32(blob + 24) !=
            eng->cfg.session_generation) {
#if defined(NINLIL_MFDT_V1_HOST_DIAGNOSTICS)
        (void)fprintf(
            stderr,
            "mfdt nrc1 load corrupt rc=%d len=%u schema=%u vlen=%u "
            "generation=%u expected_generation=%u slots=%u occupied=%u "
            "sequence=%u header_crc=%08x/%08x record_crc=%08x/%08x "
            "slot0_rid=%llu slot0_generation=%u slot0_type=%u "
            "slot0_len=%u\n",
            rc,
            (unsigned)len,
            (unsigned)ninlil_mfdt_v1_get_u16(blob + 4),
            (unsigned)ninlil_mfdt_v1_get_u16(blob + 6),
            (unsigned)ninlil_mfdt_v1_get_u32(blob + 24),
            (unsigned)eng->cfg.session_generation,
            (unsigned)ninlil_mfdt_v1_get_u16(blob + 28),
            (unsigned)ninlil_mfdt_v1_get_u16(blob + 30),
            (unsigned)ninlil_mfdt_v1_get_u32(blob + 32),
            (unsigned)ninlil_mfdt_v1_get_u32(blob + 36),
            (unsigned)ninlil_mfdt_v1_crc32c(blob, 36u),
            (unsigned)ninlil_mfdt_v1_get_u32(
                blob + MFDT_NRC1_RECORD_CRC_OFF),
            (unsigned)ninlil_mfdt_v1_crc32c(
                blob, MFDT_NRC1_RECORD_CRC_OFF),
            (unsigned long long)ninlil_mfdt_v1_get_u64(
                blob + MFDT_NRC1_SLOTS_OFF),
            (unsigned)ninlil_mfdt_v1_get_u32(
                blob + MFDT_NRC1_SLOTS_OFF + 8u),
            (unsigned)ninlil_mfdt_v1_get_u16(
                blob + MFDT_NRC1_SLOTS_OFF + 44u),
            (unsigned)ninlil_mfdt_v1_get_u16(
                blob + MFDT_NRC1_SLOTS_OFF + 46u));
#endif
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    return NINLIL_MFDT_V1_OK;
}

static int nrc1_find(const uint8_t *blob, uint32_t generation, uint64_t rid)
{
    uint16_t i;
    if (generation == 0u || rid == 0ull) {
        return -1;
    }
    for (i = 0; i < NINLIL_MFDT_V1_NRC1_SLOT_COUNT; ++i) {
        const uint8_t *s =
            blob + MFDT_NRC1_SLOTS_OFF +
            (size_t)i * NINLIL_MFDT_V1_NRC1_SLOT_BYTES;
        if (ninlil_mfdt_v1_get_u64(s + 0) == rid &&
            ninlil_mfdt_v1_get_u32(s + 8) == generation) {
            return (int)i;
        }
    }
    return -1;
}

static int nrc1_insert(uint8_t *blob, uint32_t generation, uint64_t rid,
                       const uint8_t dig[32], uint16_t rtype,
                       const uint8_t *rbody, uint16_t rlen)
{
    uint16_t occ;
    uint16_t i;
    uint32_t seq;
    if (generation == 0u || rid == 0ull || dig == NULL || is_zero32(dig) ||
        rbody == NULL || !nrc1_response_body_length_ok(rtype, rlen) ||
        generation != ninlil_mfdt_v1_get_u32(blob + 24)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    occ = ninlil_mfdt_v1_get_u16(blob + 30);
    if (occ >= NINLIL_MFDT_V1_NRC1_SLOT_COUNT) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    for (i = 0; i < NINLIL_MFDT_V1_NRC1_SLOT_COUNT; ++i) {
        uint8_t *s = nrc1_slot_at(blob, i);
        if (ninlil_mfdt_v1_get_u64(s + 0) == 0ull) {
            ninlil_mfdt_v1_memzero(s, NINLIL_MFDT_V1_NRC1_SLOT_BYTES);
            ninlil_mfdt_v1_put_u64(s + 0, rid);
            ninlil_mfdt_v1_put_u32(s + 8, generation);
            (void)memcpy(s + 12, dig, 32u);
            ninlil_mfdt_v1_put_u16(s + 44, rtype);
            ninlil_mfdt_v1_put_u16(s + 46, rlen);
            (void)memcpy(s + 48, rbody, rlen);
            ninlil_mfdt_v1_put_u16(blob + 30, (uint16_t)(occ + 1u));
            seq = ninlil_mfdt_v1_get_u32(blob + 32);
            ninlil_mfdt_v1_put_u32(blob + 32, seq + 1u);
            nrc1_recompute_crc(blob);
            return NINLIL_MFDT_V1_OK;
        }
    }
    return NINLIL_MFDT_V1_ERR_CAPACITY;
}

int ninlil_mfdt_v1_nrc1_lookup(ninlil_mfdt_v1_engine_t *eng,
                               const uint8_t transfer_id[16], uint64_t request_id,
                               const uint8_t req_digest[32],
                               ninlil_mfdt_v1_response_t *resp)
{
    uint8_t *blob = engine_nrc1_scratch(eng);
    if (blob == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    uint8_t key[20];
    uint32_t len = 0u;
    int has_nrc1;
    int has_nm30;
    int present = 0;
    int idx;
    int rc;
    if (eng == NULL || transfer_id == NULL || resp == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_memzero(resp, sizeof(*resp));
    make_key(key, "NRC1", transfer_id);
    has_nrc1 = store_get(eng, key, NULL, 0u, &len) ==
               NINLIL_MFDT_V1_OK;
    make_key(key, "NM30", transfer_id);
    has_nm30 = store_get(eng, key, NULL, 0u, &len) ==
               NINLIL_MFDT_V1_OK;
    if (!has_nrc1 && !has_nm30) {
        resp->message_type = NINLIL_MFDT_V1_MSG_REJECT;
        resp->reject_code = NINLIL_MFDT_V1_REJ_EXPIRED;
        return NINLIL_MFDT_V1_ERR_EXPIRED;
    }
    if (!has_nrc1 && has_nm30) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    rc = nrc1_load(eng, transfer_id, blob, &present);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    idx = nrc1_find(blob, eng->cfg.session_generation, request_id);
    if (idx < 0) {
        if (has_nm30) {
            resp->message_type = NINLIL_MFDT_V1_MSG_REJECT;
            resp->reject_code = NINLIL_MFDT_V1_REJ_STATE;
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        return NINLIL_MFDT_V1_ERR_STATE; /* miss, caller may insert */
    }
    {
        uint8_t *s = nrc1_slot_at(blob, (uint16_t)idx);
        uint16_t rtype = ninlil_mfdt_v1_get_u16(s + 44);
        uint16_t rlen = ninlil_mfdt_v1_get_u16(s + 46);
        if (req_digest != NULL &&
            !ninlil_mfdt_v1_memeq(s + 12, req_digest, 32u)) {
            resp->message_type = NINLIL_MFDT_V1_MSG_REJECT;
            resp->reject_code = NINLIL_MFDT_V1_REJ_DUPLICATE;
            return NINLIL_MFDT_V1_ERR_DIGEST;
        }
        if (rlen > 160u) {
            return NINLIL_MFDT_V1_ERR_CORRUPT;
        }
        if (!nrc1_replay_eligible(eng)) {
            ninlil_mfdt_v1_memzero(resp, sizeof(*resp));
            return NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN;
        }
        resp->message_type = (uint8_t)rtype;
        resp->body_len = rlen;
        (void)memcpy(resp->body, s + 48, rlen);
        if (rtype == NINLIL_MFDT_V1_MSG_REJECT && rlen == 60u) {
            resp->reject_code = ninlil_mfdt_v1_get_u16(s + 48 + 54);
        }
        resp->from_nrc1_hit = 1u;
        resp->state_mutation = 0u;
        resp->full_count = 0u;
    }
    return NINLIL_MFDT_V1_OK;
}

/* Lookup-first helper: returns 1 if hit filled resp, 0 if miss, <0 error */
static int nrc1_try_hit(ninlil_mfdt_v1_engine_t *eng, const uint8_t tid[16],
                        uint64_t request_id, uint8_t req_type,
                        const uint8_t *req_body, uint16_t req_len,
                        ninlil_mfdt_v1_response_t *resp)
{
    uint8_t dig[32];
    uint8_t key[20];
    uint32_t len = 0u;
    int has_nrc1;
    int has_nm30;
    int rc;
    ninlil_mfdt_v1_request_body_digest(req_type, req_body, req_len, dig);
    make_key(key, "NRC1", tid);
    has_nrc1 = store_get(eng, key, NULL, 0u, &len) ==
               NINLIL_MFDT_V1_OK;
    make_key(key, "NM30", tid);
    has_nm30 = store_get(eng, key, NULL, 0u, &len) ==
               NINLIL_MFDT_V1_OK;
    if (!has_nrc1 && !has_nm30) {
        /* first-attempt, no cache — not EXPIRED */
        ninlil_mfdt_v1_memzero(resp, sizeof(*resp));
        return 0;
    }
    rc = ninlil_mfdt_v1_nrc1_lookup(eng, tid, request_id, dig, resp);
    if (rc == NINLIL_MFDT_V1_OK && resp->from_nrc1_hit) {
        return 1;
    }
    if (rc == NINLIL_MFDT_V1_ERR_DIGEST) {
        const uint16_t stage = request_stage_for_type(req_type);
        /*
         * The occupied NRC1 slot is immutable.  A same-request-ID body
         * conflict is therefore an exact, stateless REJECT and must never
         * overwrite the cached first response.
         */
        if (stage != 0u) {
            (void)fill_reject_for_active(
                eng, stage, NINLIL_MFDT_V1_REJ_DUPLICATE, 0u, resp);
        }
        return rc;
    }
    if (rc == NINLIL_MFDT_V1_ERR_EXPIRED ||
        rc == NINLIL_MFDT_V1_ERR_CORRUPT) {
        return rc;
    }
    /* miss with live NRC1 (active transfer) */
    ninlil_mfdt_v1_memzero(resp, sizeof(*resp));
    return 0;
}

/* ---- Active record pack helpers ----------------------------------------- */

static int slot_pack_active_base(
    ninlil_mfdt_v1_engine_t *eng, const mfdt_xfer_t *x,
    const uint8_t *open_body, const uint8_t *entries,
    uint16_t entry_bytes, const uint8_t *content,
    uint8_t *rec, uint32_t *rec_len)
{
    uint32_t content_off;
    uint32_t body_len;
    uint32_t total;
    const int first_pack = eng->slot_record_packed == 0u;
    if (eng == NULL || x == NULL || open_body == NULL || rec == NULL ||
        rec_len == NULL || rec != eng->slot_record_memory ||
        (x->role != 1u && x->role != 2u) ||
        x->open_len < NINLIL_MFDT_V1_OPEN_BODY_MIN ||
        x->open_len > NINLIL_MFDT_V1_OPEN_BODY_MAX ||
        (entry_bytes != 0u && entries == NULL) ||
        (x->total_length != 0u && content == NULL)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    content_off =
        (uint32_t)NINLIL_MFDT_V1_ACTIVE_HEADER_BYTES +
        (uint32_t)x->open_len + (uint32_t)entry_bytes;
    if (content_off > NINLIL_MFDT_V1_ACTIVE_VALUE_MAX ||
        x->total_length >
            NINLIL_MFDT_V1_ACTIVE_VALUE_MAX - content_off - 4u) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    total = content_off + x->total_length + 4u;
    /*
     * First-pack ranges are disjoint after content was moved to its final
     * high address. Packed refresh never copies body bytes at all.
     */
    if (first_pack) {
        (void)memcpy(rec + NINLIL_MFDT_V1_ACTIVE_HEADER_BYTES,
                     open_body, x->open_len);
        if (entry_bytes != 0u) {
            (void)memcpy(
                rec + NINLIL_MFDT_V1_ACTIVE_HEADER_BYTES + x->open_len,
                entries, entry_bytes);
        }
    }
    ninlil_mfdt_v1_memzero(rec, NINLIL_MFDT_V1_ACTIVE_HEADER_BYTES);
    (void)memcpy(rec, x->role == 1u ? "NM3S" : "NM3R", 4u);
    ninlil_mfdt_v1_put_u16(rec + 4, NINLIL_MFDT_V1_ACTIVE_SCHEMA);
    ninlil_mfdt_v1_put_u16(
        rec + 6, NINLIL_MFDT_V1_ACTIVE_HEADER_BYTES);
    ninlil_mfdt_v1_put_u32(rec + 8, total);
    rec[12] = x->role;
    rec[13] = x->state_code;
    (void)memcpy(rec + 16, x->transfer_id, 16u);
    ninlil_mfdt_v1_put_u32(rec + 32, x->revision);
    (void)memcpy(rec + 36, x->manifest_digest, 32u);
    ninlil_mfdt_v1_put_u64(rec + 68, x->record_generation);
    ninlil_mfdt_v1_put_u16(rec + 84, x->open_len);
    ninlil_mfdt_v1_put_u16(rec + 86, entry_bytes);
    ninlil_mfdt_v1_put_u32(rec + 88, x->total_length);
    ninlil_mfdt_v1_put_u16(rec + 92, x->chunk_count);
    ninlil_mfdt_v1_put_u16(rec + 94, x->page_count);
    ninlil_mfdt_v1_put_u64(rec + 96, x->chunk_bitmap);
    rec[104] = x->page_bitmap;
    rec[105] = x->retry_budget;
    rec[106] = 0u;
    rec[107] = x->publication_state;
    rec[108] = x->handoff_state;
    if (!is_zero16(x->reservation_id)) {
        (void)memcpy(rec + 112, x->reservation_id, 16u);
    }
    if (!is_zero16(x->res_epoch)) {
        (void)memcpy(rec + 128, x->res_epoch, 16u);
    }
    ninlil_mfdt_v1_put_u64(rec + 144, x->not_after_ms);
    if (x->publication_state != 0u) {
        (void)memcpy(rec + 248, x->publication_token, 16u);
    }
    ninlil_mfdt_v1_put_u32(rec + 300, eng->cfg.session_generation);
    ninlil_mfdt_v1_put_u32(
        rec + 304, ninlil_mfdt_v1_crc32c(rec, 304u));
    body_len = total - 4u;
    ninlil_mfdt_v1_put_u32(
        rec + body_len, ninlil_mfdt_v1_crc32c(rec, body_len));
    *rec_len = total;
    eng->slot_record_packed = 1u;
    return NINLIL_MFDT_V1_OK;
}

static int pack_active(ninlil_mfdt_v1_engine_t *eng, mfdt_xfer_t *x,
                       uint8_t *rec, uint32_t *rec_len)
{
    int rc;
    uint32_t body_len;
    uint8_t *open_body;
    uint8_t *entries;
    uint8_t *content;
    uint16_t entry_bytes;

    if (is_zero16(x->durable_local_epoch)) {
        if (is_zero16(eng->cfg.local_clock_epoch.bytes)) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        (void)memcpy(x->durable_local_epoch,
                     eng->cfg.local_clock_epoch.bytes, 16u);
    } else if (!ninlil_mfdt_v1_memeq(
                   x->durable_local_epoch,
                   eng->cfg.local_clock_epoch.bytes, 16u)) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    x->durable_local_mono_ms = eng->cfg.now_ms;
    entry_bytes = (uint16_t)(x->chunk_count * 40u);
    open_body = open_ptr(eng);
    entries = entries_ptr(eng);
    content = x->total_length ? content_ptr(eng) : NULL;
    if (eng->slot_layout != 0u) {
        const uint32_t content_off =
            (uint32_t)NINLIL_MFDT_V1_ACTIVE_HEADER_BYTES +
            (uint32_t)x->open_len + (uint32_t)entry_bytes;
        const uint32_t total =
            content_off + x->total_length + (uint32_t)sizeof(uint32_t);
        if (rec != eng->slot_record_memory ||
            x->open_len > MFDT_WS_OPEN_MAX ||
            entry_bytes > (uint16_t)(40u * NINLIL_MFDT_V1_MAX_CHUNKS) ||
            total > NINLIL_MFDT_V1_ACTIVE_VALUE_MAX) {
            return NINLIL_MFDT_V1_ERR_CAPACITY;
        }
        /*
         * On the first pack content starts at record_memory[0]. Move it to
         * its canonical encoded offset before record_pack writes the header.
         * open/entries still live in disjoint bounded staging regions.
         * Later packs already use exact encoded-body pointers, so every
         * record_pack memcpy is either disjoint or source == destination.
         */
        if (eng->slot_record_packed == 0u && x->total_length != 0u) {
            (void)memmove(rec + content_off, content, x->total_length);
            content = rec + content_off;
        }
    }
    if (eng->slot_layout != 0u) {
        rc = slot_pack_active_base(
            eng, x, open_body, entries, entry_bytes, content, rec, rec_len);
    } else {
        rc = ninlil_mfdt_v1_record_pack(
            x->role, x->state_code, x->transfer_id, x->revision,
            x->manifest_digest, open_body, x->open_len, entries, entry_bytes,
            content, x->total_length, x->record_generation, x->page_bitmap,
            x->chunk_bitmap, x->retry_budget, x->publication_state,
            x->handoff_state, x->reservation_id, x->res_epoch,
            x->not_after_ms,
            x->publication_state ? x->publication_token : NULL,
            eng->cfg.session_generation, rec,
            NINLIL_MFDT_V1_ACTIVE_VALUE_MAX, rec_len);
    }
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    /*
     * Fill the closed ADR-0021 header fields not exposed by the legacy private
     * record helper, then refresh both CRCs. Reserved bytes stay canonical zero.
     */
    ninlil_mfdt_v1_put_u64(rec + 76, x->acceptance_record_generation);
    rec[109] = x->accept_notified;
    (void)memcpy(rec + 152, x->evidence_id, 16u);
    (void)memcpy(rec + 168, x->acceptance_record_digest, 32u);
    (void)memcpy(rec + 200, x->durable_local_epoch, 16u);
    ninlil_mfdt_v1_put_u64(rec + 216, x->durable_local_mono_ms);
    ninlil_mfdt_v1_put_u32(rec + 224, x->abort_generation);
    (void)memcpy(rec + 264, x->publication_evidence_digest, 32u);
    ninlil_mfdt_v1_put_u32(rec + 296, x->last_resume_gen);
    ninlil_mfdt_v1_put_u32(rec + 300, eng->cfg.session_generation);
    ninlil_mfdt_v1_put_u32(rec + 304,
                           ninlil_mfdt_v1_crc32c(rec, 304u));
    body_len = *rec_len - 4u;
    ninlil_mfdt_v1_put_u32(rec + body_len,
                           ninlil_mfdt_v1_crc32c(rec, body_len));
    return NINLIL_MFDT_V1_OK;
}

static int project_active_record(
    ninlil_mfdt_v1_engine_t *eng, mfdt_xfer_t *x,
    uint8_t *rec, uint32_t len)
{
    int rc;
    uint8_t owner = 0, state = 0;
    uint8_t tid[16];
    uint32_t rev = 0;
    uint8_t md[32];
    const uint8_t *openb = NULL, *ents = NULL, *cont = NULL;
    uint16_t openl = 0, eb = 0;
    uint32_t cl = 0;
    uint64_t rgen = 0, cb = 0;
    uint8_t pb = 0, rb = 0, pub = 0, ho = 0;
    if (eng == NULL || x == NULL || rec == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    rc = ninlil_mfdt_v1_record_unpack(rec, len, &owner, &state, tid, &rev, md,
                                      &openb, &openl, &ents, &eb, &cont, &cl,
                                      &rgen, &pb, &cb, &rb, &pub, &ho);
    if (rc != NINLIL_MFDT_V1_OK) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (owner != x->role ||
        !ninlil_mfdt_v1_memeq(tid, x->transfer_id, 16u) ||
        ninlil_mfdt_v1_get_u32(rec + 300) !=
            eng->cfg.session_generation) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (eng->slot_layout != 0u) {
        eng->slot_record_packed = 1u;
    }
    x->state_code = state;
    x->revision = rev;
    x->record_generation = rgen;
    x->acceptance_record_generation = ninlil_mfdt_v1_get_u64(rec + 76);
    x->page_bitmap = pb;
    x->chunk_bitmap = cb;
    x->retry_budget = rb;
    x->publication_state = pub;
    x->handoff_state = ho;
    x->open_len = openl;
    (void)memcpy(x->manifest_digest, md, 32u);
    if (openb != NULL && openl > 0u && openl <= MFDT_WS_OPEN_MAX) {
        if (eng->slot_layout == 0u) {
            (void)memcpy(open_ptr(eng), openb, openl);
        }
        (void)memcpy(x->whole_digest, openb + 32, 32u);
        x->total_length = ninlil_mfdt_v1_get_u32(openb + 20);
        x->chunk_count = ninlil_mfdt_v1_get_u16(openb + 26);
        x->page_count = ninlil_mfdt_v1_get_u16(openb + 28);
    }
    if (eng->slot_layout == 0u && ents != NULL && eb > 0u) {
        (void)memcpy(entries_ptr(eng), ents, eb);
    }
    if (eng->slot_layout == 0u &&
        cont != NULL && cl > 0u && cl <= NINLIL_MFDT_V1_MAX_CONTENT) {
        (void)memcpy(content_ptr(eng), cont, cl);
    }
    /* header reservation fields */
    (void)memcpy(x->reservation_id, rec + 112, 16u);
    (void)memcpy(x->res_epoch, rec + 128, 16u);
    x->not_after_ms = ninlil_mfdt_v1_get_u64(rec + 144);
    (void)memcpy(x->durable_local_epoch, rec + 200, 16u);
    x->durable_local_mono_ms = ninlil_mfdt_v1_get_u64(rec + 216);
    (void)memcpy(x->evidence_id, rec + 152, 16u);
    (void)memcpy(x->acceptance_record_digest, rec + 168, 32u);
    (void)memcpy(x->publication_token, rec + 248, 16u);
    (void)memcpy(x->publication_evidence_digest, rec + 264, 32u);
    x->last_resume_gen = ninlil_mfdt_v1_get_u32(rec + 296);
    x->abort_generation = ninlil_mfdt_v1_get_u32(rec + 224);
    x->accept_notified = rec[109];
    if (pub == 1u || pub == 2u) {
        eng->publication_ready = 1u;
        (void)memcpy(eng->publication_token, x->publication_token, 16u);
    }
    if (ho == 1u) {
        eng->handoff_complete = 1u;
    }
    if (eng->store_port != NULL) {
        eng->durable_active_value_len = len;
    }
    return NINLIL_MFDT_V1_OK;
}

static int load_active_from_store(ninlil_mfdt_v1_engine_t *eng, mfdt_xfer_t *x)
{
    uint8_t key[20];
    uint8_t *nrc1 = engine_nrc1_scratch(eng);
    uint8_t *rec = engine_record_scratch(eng);
    uint32_t len = 0u;
    uint32_t nrc1_len = 0u;
    int rc;
    if (rec == NULL || nrc1 == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    make_key(key, x->role == 1u ? "NM3S" : "NM3R", x->transfer_id);
    rc = store_get(eng, key, rec,
                   NINLIL_MFDT_V1_ACTIVE_VALUE_MAX, &len);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    make_key(key, "NRC1", x->transfer_id);
    rc = store_get(
        eng, key, nrc1, NINLIL_MFDT_V1_NRC1_VALUE_BYTES, &nrc1_len);
    if (rc != NINLIL_MFDT_V1_OK ||
        nrc1_validate(nrc1, nrc1_len, x->transfer_id) !=
            NINLIL_MFDT_V1_OK ||
        ninlil_mfdt_v1_get_u32(nrc1 + 24) !=
            eng->cfg.session_generation) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    return project_active_record(eng, x, rec, len);
}

static void restore_active_from_durable(ninlil_mfdt_v1_engine_t *eng,
                                        mfdt_xfer_t *x)
{
    /*
     * Reset every volatile projection before reading OLD/NEW. load_active only
     * raises these flags when the durable image says so; without the reset a
     * failed FULL could leave publication/handoff state ahead of storage.
     */
    eng->publication_ready = 0u;
    eng->handoff_complete = 0u;
    eng->unpaid_chunk_offer = 0u;
    x->unpaid_chunk = 0u;
    if (load_active_from_store(eng, x) == NINLIL_MFDT_V1_OK) {
        eng->active_count = 1u;
        return;
    }
    ninlil_mfdt_v1_memzero(x, sizeof(*x));
    eng->active_count = 0u;
    eng->durable_active_value_len = 0u;
    if (eng->slot_layout != 0u) {
        eng->slot_record_packed = 0u;
    }
}

static int full_put_active_reload_on_failure(
    ninlil_mfdt_v1_engine_t *eng, mfdt_xfer_t *x, const uint8_t key[20],
    const uint8_t *record, uint32_t record_len)
{
    int rc = full_put_one(eng, key, record, record_len);
    if (rc == NINLIL_MFDT_V1_OK) {
        return rc;
    }
    restore_active_from_durable(eng, x);
    return rc;
}

/* ---- OPEN validation (mandatory fields) --------------------------------- */

static int validate_open_body(const uint8_t *b, uint16_t len,
                              ninlil_mfdt_v1_geometry_t *geo)
{
    uint32_t total;
    int rc;
    if (b == NULL || geo == NULL ||
        len < NINLIL_MFDT_V1_OPEN_BODY_MIN ||
        len > NINLIL_MFDT_V1_OPEN_BODY_MAX) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    total = ninlil_mfdt_v1_get_u32(b + 20);
    rc = ninlil_mfdt_v1_geometry(total, geo);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    return ninlil_mfdt_v1_validate_open(
        b, len, NULL,
        (uint16_t)(geo->chunk_count * NINLIL_MFDT_V1_ENTRY_BYTES), NULL,
        total, 0u);
}

static void fill_reject_for_open_bind(
    const uint8_t *open_body, uint16_t code, uint32_t detail,
    ninlil_mfdt_v1_response_t *resp)
{
    ninlil_mfdt_v1_memzero(resp, sizeof(*resp));
    ninlil_mfdt_v1_bind52(
        open_body, ninlil_mfdt_v1_get_u32(open_body + 16),
        open_body + 202, resp->body);
    ninlil_mfdt_v1_put_u16(resp->body + 52, 1u);
    ninlil_mfdt_v1_put_u16(resp->body + 54, code);
    ninlil_mfdt_v1_put_u32(resp->body + 56, detail);
    resp->message_type = NINLIL_MFDT_V1_MSG_REJECT;
    resp->reject_code = code;
    resp->body_len = 60u;
}

static int expired_now(const ninlil_mfdt_v1_engine_t *eng, const mfdt_xfer_t *x)
{
    if (x->not_after_ms == 0ull) {
        return 0;
    }
    /*
     * The receiver creates the reservation in its local clock domain.  A
     * sender may persist that peer epoch, but must never compare the remote
     * monotonic value with its own clock unless the epoch IDs are identical.
     */
    if (is_zero16(x->res_epoch) ||
        !ninlil_mfdt_v1_memeq(
            x->res_epoch, eng->cfg.local_clock_epoch.bytes, 16u)) {
        return 0;
    }
    /* sole same-epoch predicate: now_ms >= reservation_not_after_ms */
    return eng->cfg.now_ms >= x->not_after_ms;
}

static int nm30_terminal_semantics_validate(const uint8_t *nm30)
{
    uint16_t state;
    uint16_t reason;
    uint32_t abort_generation;
    int evidence_zero;
    int acceptance_zero;
    int actor_zero;
    if (nm30 == NULL) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    state = ninlil_mfdt_v1_get_u16(nm30 + 60);
    reason = ninlil_mfdt_v1_get_u16(nm30 + 62);
    abort_generation = ninlil_mfdt_v1_get_u32(nm30 + 64);
    evidence_zero = is_zero16(nm30 + 68);
    acceptance_zero = is_zero32(nm30 + 84);
    actor_zero = is_zero16(nm30 + 116);
    if (state == NINLIL_MFDT_V1_TERM_COMPLETE) {
        if (reason != NINLIL_MFDT_V1_TERM_REASON_NONE ||
            abort_generation != 0u || actor_zero == 0 || evidence_zero != 0 ||
            acceptance_zero != 0) {
            return NINLIL_MFDT_V1_ERR_CORRUPT;
        }
    } else if (state == NINLIL_MFDT_V1_TERM_ABORTED) {
        if (reason >= NINLIL_MFDT_V1_TERM_REASON_OPERATOR &&
            reason <= NINLIL_MFDT_V1_TERM_REASON_POLICY) {
            if (abort_generation == 0u ||
                abort_generation > NINLIL_MFDT_V1_ABORT_GEN_MAX ||
                actor_zero != 0 || evidence_zero == 0 ||
                acceptance_zero == 0) {
                return NINLIL_MFDT_V1_ERR_CORRUPT;
            }
        } else if (reason == NINLIL_MFDT_V1_TERM_REASON_EXPIRED) {
            if (abort_generation != 0u || actor_zero == 0 ||
                evidence_zero == 0 || acceptance_zero == 0) {
                return NINLIL_MFDT_V1_ERR_CORRUPT;
            }
        } else {
            return NINLIL_MFDT_V1_ERR_CORRUPT;
        }
    } else if (state == NINLIL_MFDT_V1_TERM_CORRUPT_FENCED) {
        if ((reason != NINLIL_MFDT_V1_TERM_REASON_CORRUPT &&
             reason != NINLIL_MFDT_V1_TERM_REASON_EPOCH) ||
            abort_generation != 0u || actor_zero == 0 ||
            evidence_zero != acceptance_zero) {
            return NINLIL_MFDT_V1_ERR_CORRUPT;
        }
    } else {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    return NINLIL_MFDT_V1_OK;
}

static int nm30_schema2_validate(
    const uint8_t nm30[NINLIL_MFDT_V1_NM30_BYTES], uint32_t len,
    const uint8_t expected_tid[16])
{
    const uint8_t role =
        nm30 != NULL && len > 172u ? nm30[172] : 0u;
    if (nm30 == NULL || len != NINLIL_MFDT_V1_NM30_BYTES ||
        !ninlil_mfdt_v1_memeq(nm30, "NM30", 4u) ||
        ninlil_mfdt_v1_get_u16(nm30 + 4) != 2u ||
        ninlil_mfdt_v1_get_u16(nm30 + 6) !=
            NINLIL_MFDT_V1_NM30_BYTES ||
        is_zero16(nm30 + 8) ||
        (expected_tid != NULL &&
         !ninlil_mfdt_v1_memeq(nm30 + 8, expected_tid, 16u)) ||
        ninlil_mfdt_v1_get_u32(nm30 + 24) == 0u ||
        is_zero32(nm30 + 28) || is_zero16(nm30 + 132) ||
        ninlil_mfdt_v1_get_u64(nm30 + 148) == 0ull ||
        is_zero16(nm30 + 156) ||
        (role != 1u && role != 2u) ||
        nm30[173] != 0u || nm30[174] != 0u || nm30[175] != 0u ||
        ninlil_mfdt_v1_get_u32(nm30 + 176) !=
            ninlil_mfdt_v1_crc32c(nm30, 176u)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    return nm30_terminal_semantics_validate(nm30);
}

static int nm30_schema1_validate(
    const uint8_t nm30[NINLIL_MFDT_V1_NM30_SCHEMA1_BYTES], uint32_t len,
    const uint8_t expected_tid[16])
{
    if (nm30 == NULL || len != NINLIL_MFDT_V1_NM30_SCHEMA1_BYTES ||
        !ninlil_mfdt_v1_memeq(nm30, "NM30", 4u) ||
        ninlil_mfdt_v1_get_u16(nm30 + 4) != 1u ||
        ninlil_mfdt_v1_get_u16(nm30 + 6) !=
            NINLIL_MFDT_V1_NM30_SCHEMA1_BYTES ||
        is_zero16(nm30 + 8) ||
        (expected_tid != NULL &&
         !ninlil_mfdt_v1_memeq(nm30 + 8, expected_tid, 16u)) ||
        ninlil_mfdt_v1_get_u32(nm30 + 24) == 0u ||
        is_zero32(nm30 + 28) || is_zero16(nm30 + 132) ||
        ninlil_mfdt_v1_get_u64(nm30 + 148) == 0ull ||
        ninlil_mfdt_v1_get_u32(nm30 + 156) != 0u ||
        ninlil_mfdt_v1_get_u32(nm30 + 160) !=
            ninlil_mfdt_v1_crc32c(nm30, 160u)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    return nm30_terminal_semantics_validate(nm30);
}

int ninlil_mfdt_v1_validate_active_record(
    const uint8_t *record, uint32_t record_len,
    const uint8_t transfer_id[16], uint8_t expected_role,
    uint32_t *session_generation_out,
    uint8_t peer_endpoint_id_out[16])
{
    uint8_t owner = 0u;
    uint8_t state = 0u;
    uint8_t tid[16];
    uint32_t revision = 0u;
    uint8_t manifest[32];
    const uint8_t *open_body = NULL;
    const uint8_t *entries = NULL;
    const uint8_t *content = NULL;
    uint16_t open_len = 0u;
    uint16_t entry_bytes = 0u;
    uint32_t content_len = 0u;
    uint64_t generation = 0u;
    uint8_t page_bitmap = 0u;
    uint64_t chunk_bitmap = 0u;
    uint8_t retry = 0u;
    uint8_t publication = 0u;
    uint8_t handoff = 0u;
    uint32_t session_generation;
    int rc;
    if (record == NULL || transfer_id == NULL ||
        (expected_role != 1u && expected_role != 2u)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    rc = ninlil_mfdt_v1_record_unpack(
        record, record_len, &owner, &state, tid, &revision, manifest,
        &open_body, &open_len, &entries, &entry_bytes, &content, &content_len,
        &generation, &page_bitmap, &chunk_bitmap, &retry, &publication,
        &handoff);
    if (rc != NINLIL_MFDT_V1_OK || owner != expected_role ||
        !ninlil_mfdt_v1_memeq(tid, transfer_id, 16u) ||
        open_body == NULL || open_len < 128u) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    session_generation = ninlil_mfdt_v1_get_u32(record + 300);
    if (session_generation == 0u) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (session_generation_out != NULL) {
        *session_generation_out = session_generation;
    }
    if (peer_endpoint_id_out != NULL) {
        (void)memcpy(
            peer_endpoint_id_out,
            open_body + (expected_role == 1u ? 112u : 96u), 16u);
        if (is_zero16(peer_endpoint_id_out)) {
            return NINLIL_MFDT_V1_ERR_CORRUPT;
        }
    }
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_validate_nrc1_record(
    const uint8_t *record, uint32_t record_len,
    const uint8_t transfer_id[16], uint32_t expected_session_generation)
{
    int rc = nrc1_validate(record, record_len, transfer_id);
    if (rc != NINLIL_MFDT_V1_OK ||
        expected_session_generation == 0u ||
        ninlil_mfdt_v1_get_u32(record + 24) !=
            expected_session_generation) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_nrc1_raw_find_response(
    const uint8_t *record, uint32_t record_len,
    const uint8_t transfer_id[16], uint32_t expected_session_generation,
    uint64_t request_id, const uint8_t request_digest[32],
    ninlil_mfdt_v1_response_t *response_out)
{
    const uint8_t *slot;
    uint16_t response_type;
    uint16_t response_len;
    int index;
    int rc;
    if (record == NULL || transfer_id == NULL || request_id == 0ull ||
        request_digest == NULL || response_out == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_memzero(response_out, sizeof(*response_out));
    rc = ninlil_mfdt_v1_validate_nrc1_record(
        record, record_len, transfer_id, expected_session_generation);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    index = nrc1_find(record, expected_session_generation, request_id);
    if (index < 0) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    slot = record + MFDT_NRC1_SLOTS_OFF +
           (size_t)(uint16_t)index * NINLIL_MFDT_V1_NRC1_SLOT_BYTES;
    if (!ninlil_mfdt_v1_memeq(slot + 12, request_digest, 32u)) {
        response_out->message_type = NINLIL_MFDT_V1_MSG_REJECT;
        response_out->reject_code = NINLIL_MFDT_V1_REJ_DUPLICATE;
        return NINLIL_MFDT_V1_ERR_DIGEST;
    }
    response_type = ninlil_mfdt_v1_get_u16(slot + 44);
    response_len = ninlil_mfdt_v1_get_u16(slot + 46);
    if (!nrc1_response_body_length_ok(response_type, response_len)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    response_out->message_type = (uint8_t)response_type;
    response_out->body_len = response_len;
    (void)memcpy(response_out->body, slot + 48, response_len);
    if ((response_type == NINLIL_MFDT_V1_MSG_REJECT ||
         response_type == NINLIL_MFDT_V1_MSG_BUSY) &&
        response_len == 60u) {
        response_out->reject_code =
            ninlil_mfdt_v1_get_u16(slot + 48 + 54);
    }
    response_out->from_nrc1_hit = 1u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_nrc1_raw_insert_response(
    uint8_t *record, uint32_t record_len,
    const uint8_t transfer_id[16], uint32_t expected_session_generation,
    uint64_t request_id, const uint8_t request_digest[32],
    uint8_t response_type, const uint8_t *response_body,
    uint16_t response_body_len)
{
    int rc;
    if (record == NULL || transfer_id == NULL || request_id == 0ull ||
        request_digest == NULL || response_body == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    rc = ninlil_mfdt_v1_validate_nrc1_record(
        record, record_len, transfer_id, expected_session_generation);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    if (nrc1_find(record, expected_session_generation, request_id) >= 0) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    rc = nrc1_insert(
        record, expected_session_generation, request_id, request_digest,
        response_type, response_body, response_body_len);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    return ninlil_mfdt_v1_validate_nrc1_record(
        record, record_len, transfer_id, expected_session_generation);
}

int ninlil_mfdt_v1_validate_nm30_record(
    const uint8_t *record, uint32_t record_len,
    const uint8_t transfer_id[16])
{
    return nm30_schema2_validate(record, record_len, transfer_id);
}

int ninlil_mfdt_v1_validate_nm30_recovery_record(
    const uint8_t *record, uint32_t record_len,
    const uint8_t transfer_id[16],
    uint8_t *replay_eligible_out,
    uint8_t peer_endpoint_id_out[16],
    uint8_t *owner_role_out)
{
    int rc;
    if (record == NULL || transfer_id == NULL ||
        replay_eligible_out == NULL || peer_endpoint_id_out == NULL ||
        owner_role_out == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    *replay_eligible_out = 0u;
    *owner_role_out = 0u;
    ninlil_mfdt_v1_memzero(peer_endpoint_id_out, 16u);
    if (record_len == NINLIL_MFDT_V1_NM30_BYTES &&
        ninlil_mfdt_v1_get_u16(record + 4) == 2u) {
        rc = nm30_schema2_validate(record, record_len, transfer_id);
        if (rc == NINLIL_MFDT_V1_OK) {
            *replay_eligible_out = 1u;
            *owner_role_out = record[172];
            (void)memcpy(peer_endpoint_id_out, record + 156, 16u);
        }
        return rc;
    }
    if (record_len == NINLIL_MFDT_V1_NM30_SCHEMA1_BYTES &&
        ninlil_mfdt_v1_get_u16(record + 4) == 1u) {
        return nm30_schema1_validate(record, record_len, transfer_id);
    }
    return NINLIL_MFDT_V1_ERR_CORRUPT;
}

int ninlil_mfdt_v1_fresh_open_precheck(
    const ninlil_mfdt_v1_config_t *config,
    const uint8_t *open_body, uint16_t open_body_len,
    ninlil_mfdt_v1_response_t *response_out)
{
    ninlil_mfdt_v1_geometry_t geometry;
    uint64_t reservation_not_after;
    uint64_t effect_deadline;
    int rc;
    if (config == NULL || open_body == NULL || response_out == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_memzero(response_out, sizeof(*response_out));
    rc = ninlil_mfdt_v1_admission_check(config);
    if (rc != NINLIL_MFDT_V1_OK) {
        if (validate_open_body(open_body, open_body_len, &geometry) ==
            NINLIL_MFDT_V1_OK) {
            fill_reject_for_open_bind(
                open_body, NINLIL_MFDT_V1_REJ_UNSUPPORTED, 0u,
                response_out);
        }
        return rc;
    }
    rc = validate_open_body(open_body, open_body_len, &geometry);
    if (rc != NINLIL_MFDT_V1_OK) {
        if (open_body_len >= 234u && !is_zero16(open_body) &&
            ninlil_mfdt_v1_get_u32(open_body + 16) != 0u &&
            !is_zero32(open_body + 202)) {
            fill_reject_for_open_bind(
                open_body,
                rc == NINLIL_MFDT_V1_ERR_DIGEST
                    ? NINLIL_MFDT_V1_REJ_DIGEST
                    : NINLIL_MFDT_V1_REJ_LAYOUT,
                0u, response_out);
        }
        return rc;
    }
    if (is_zero16(config->local_clock_epoch.bytes)) {
        fill_reject_for_open_bind(
            open_body, NINLIL_MFDT_V1_REJ_STATE, 0u, response_out);
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (config->now_ms >
        UINT64_MAX - NINLIL_MFDT_V1_RESERVATION_MS) {
        fill_reject_for_open_bind(
            open_body, NINLIL_MFDT_V1_REJ_EXPIRED, 0u, response_out);
        return NINLIL_MFDT_V1_ERR_EXPIRED;
    }
    reservation_not_after =
        config->now_ms + NINLIL_MFDT_V1_RESERVATION_MS;
    effect_deadline = ninlil_mfdt_v1_get_u64(open_body + 194);
    if (!is_zero16(open_body + 178)) {
        if (!ninlil_mfdt_v1_memeq(
                open_body + 178,
                config->local_clock_epoch.bytes, 16u)) {
            fill_reject_for_open_bind(
                open_body, NINLIL_MFDT_V1_REJ_STATE, 0u, response_out);
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        if (effect_deadline <= config->now_ms) {
            fill_reject_for_open_bind(
                open_body, NINLIL_MFDT_V1_REJ_EXPIRED, 0u,
                response_out);
            return NINLIL_MFDT_V1_ERR_EXPIRED;
        }
        if (effect_deadline < reservation_not_after) {
            reservation_not_after = effect_deadline;
        }
    }
    (void)reservation_not_after;
    return NINLIL_MFDT_V1_OK;
}

static int build_nm30(uint8_t nm30[NINLIL_MFDT_V1_NM30_BYTES],
                      ninlil_mfdt_v1_engine_t *eng,
                      const mfdt_xfer_t *x, uint16_t terminal_state,
                      uint16_t terminal_reason, uint32_t abort_generation,
                      const uint8_t evidence[16],
                      const uint8_t acceptance_digest[32],
                      const uint8_t actor[16], const uint8_t anchor_epoch[16],
                      uint64_t anchor_ms)
{
    const uint8_t *open_body;
    const uint8_t *peer;
    if (nm30 == NULL || eng == NULL || x == NULL || anchor_epoch == NULL ||
        is_zero16(anchor_epoch) || anchor_ms == 0ull ||
        (x->role != 1u && x->role != 2u) || x->open_len < 128u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    open_body = open_ptr(eng);
    peer = open_body + (x->role == 1u ? 112u : 96u);
    if (is_zero16(peer)) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    ninlil_mfdt_v1_memzero(nm30, NINLIL_MFDT_V1_NM30_BYTES);
    (void)memcpy(nm30, "NM30", 4u);
    ninlil_mfdt_v1_put_u16(nm30 + 4, 2u);
    ninlil_mfdt_v1_put_u16(nm30 + 6, NINLIL_MFDT_V1_NM30_BYTES);
    (void)memcpy(nm30 + 8, x->transfer_id, 16u);
    ninlil_mfdt_v1_put_u32(nm30 + 24, x->revision);
    (void)memcpy(nm30 + 28, x->manifest_digest, 32u);
    ninlil_mfdt_v1_put_u16(nm30 + 60, terminal_state);
    ninlil_mfdt_v1_put_u16(nm30 + 62, terminal_reason);
    ninlil_mfdt_v1_put_u32(nm30 + 64, abort_generation);
    if (evidence != NULL) {
        (void)memcpy(nm30 + 68, evidence, 16u);
    }
    if (acceptance_digest != NULL) {
        (void)memcpy(nm30 + 84, acceptance_digest, 32u);
    }
    if (actor != NULL) {
        (void)memcpy(nm30 + 116, actor, 16u);
    }
    (void)memcpy(nm30 + 132, anchor_epoch, 16u);
    ninlil_mfdt_v1_put_u64(nm30 + 148, anchor_ms);
    (void)memcpy(nm30 + 156, peer, 16u);
    nm30[172] = x->role;
    ninlil_mfdt_v1_put_u32(
        nm30 + 176, ninlil_mfdt_v1_crc32c(nm30, 176u));
    return nm30_schema2_validate(
        nm30, NINLIL_MFDT_V1_NM30_BYTES, x->transfer_id);
}

/*
 * A local monotonic epoch change invalidates every active reservation.  The
 * old trusted sample, never a numeric comparison across epochs, anchors the
 * terminal tombstone.
 */
static int fence_if_local_epoch_changed(
    ninlil_mfdt_v1_engine_t *eng, mfdt_xfer_t *x, uint16_t rejected_stage,
    ninlil_mfdt_v1_response_t *resp)
{
    uint8_t akey[20];
    uint8_t tkey[20];
    uint8_t nm30[NINLIL_MFDT_V1_NM30_BYTES];
    const uint8_t *evidence = NULL;
    const uint8_t *acceptance = NULL;
    int rc;
    if (eng == NULL || x == NULL || !x->occupied || x->terminal) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (is_zero16(x->durable_local_epoch) ||
        ninlil_mfdt_v1_memeq(x->durable_local_epoch,
                             eng->cfg.local_clock_epoch.bytes, 16u)) {
        return NINLIL_MFDT_V1_OK;
    }
    if (!is_zero16(x->evidence_id) &&
        !is_zero32(x->acceptance_record_digest)) {
        evidence = x->evidence_id;
        acceptance = x->acceptance_record_digest;
    }
    rc = build_nm30(
        nm30, eng, x, NINLIL_MFDT_V1_TERM_CORRUPT_FENCED,
        NINLIL_MFDT_V1_TERM_REASON_EPOCH, 0u, evidence, acceptance, NULL,
        x->durable_local_epoch, x->durable_local_mono_ms);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    make_key(akey, x->role == 1u ? "NM3S" : "NM3R", x->transfer_id);
    make_key(tkey, "NM30", x->transfer_id);
    rc = full_terminal(eng, akey, tkey, nm30,
                       NINLIL_MFDT_V1_NM30_BYTES);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    x->terminal = 1u;
    eng->active_count = 0u;
    if (x->handoff_state == 0u) {
        x->publication_state = 0u;
        eng->publication_ready = 0u;
    }
    if (resp != NULL) {
        ninlil_mfdt_v1_memzero(resp, sizeof(*resp));
        resp->message_type = NINLIL_MFDT_V1_MSG_REJECT;
        resp->reject_code = NINLIL_MFDT_V1_REJ_STATE;
        resp->state_mutation = 1u;
        resp->full_count = 1u;
        if (rejected_stage != 0u) {
            ninlil_mfdt_v1_bind52(x->transfer_id, x->revision,
                                  x->manifest_digest, resp->body);
            ninlil_mfdt_v1_put_u16(resp->body + 52, rejected_stage);
            ninlil_mfdt_v1_put_u16(resp->body + 54,
                                   NINLIL_MFDT_V1_REJ_STATE);
            resp->body_len = 60u;
        }
    }
    return NINLIL_MFDT_V1_ERR_STATE;
}

/* Commit response + optional active mutation in ONE multi-key FULL. */
static int commit_resp_with_active(
    ninlil_mfdt_v1_engine_t *eng, mfdt_xfer_t *x, int mutate_active,
    uint8_t req_type, const uint8_t *req_body, uint16_t req_len,
    uint64_t request_id, uint8_t resp_type, const uint8_t *resp_body,
    uint16_t resp_len, ninlil_mfdt_v1_response_t *resp)
{
    uint8_t *nblob = engine_nrc1_scratch(eng);
    uint8_t dig[32];
    uint8_t akey[20], nkey[20];
    uint8_t *rec = engine_record_scratch(eng);
    if (rec == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    uint32_t rec_len = 0u;
    int present = 0;
    int idx;
    int rc;
    if (nblob == NULL || rec == NULL) {
        if (mutate_active != 0) {
            restore_active_from_durable(eng, x);
        }
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    ninlil_mfdt_v1_request_body_digest(req_type, req_body, req_len, dig);
    rc = nrc1_load(eng, x->transfer_id, nblob, &present);
    if (rc != NINLIL_MFDT_V1_OK) {
        if (mutate_active != 0) {
            restore_active_from_durable(eng, x);
        }
        return rc;
    }
    if (mutate_active == 0 && present == 0) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    idx = nrc1_find(nblob, eng->cfg.session_generation, request_id);
    if (idx >= 0) {
        uint8_t *s = nrc1_slot_at(nblob, (uint16_t)idx);
        uint16_t rtype = ninlil_mfdt_v1_get_u16(s + 44);
        uint16_t rlen = ninlil_mfdt_v1_get_u16(s + 46);
        if (!ninlil_mfdt_v1_memeq(s + 12, dig, 32u)) {
            resp->message_type = NINLIL_MFDT_V1_MSG_REJECT;
            resp->reject_code = NINLIL_MFDT_V1_REJ_DUPLICATE;
            return NINLIL_MFDT_V1_ERR_DIGEST;
        }
        if (rlen > 160u) {
            return NINLIL_MFDT_V1_ERR_CORRUPT;
        }
        if (!nrc1_replay_eligible(eng)) {
            ninlil_mfdt_v1_memzero(resp, sizeof(*resp));
            return NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN;
        }
        resp->message_type = (uint8_t)rtype;
        resp->body_len = rlen;
        (void)memcpy(resp->body, s + 48, rlen);
        if (rtype == NINLIL_MFDT_V1_MSG_REJECT && rlen == 60u) {
            resp->reject_code = ninlil_mfdt_v1_get_u16(s + 48 + 54);
        }
        resp->from_nrc1_hit = 1u;
        resp->state_mutation = 0u;
        resp->full_count = 0u;
        return NINLIL_MFDT_V1_OK;
    }
    rc = nrc1_insert(nblob, eng->cfg.session_generation, request_id, dig,
                     resp_type, resp_body, resp_len);
    if (rc != NINLIL_MFDT_V1_OK) {
        resp->message_type = NINLIL_MFDT_V1_MSG_BUSY;
        resp->reject_code = NINLIL_MFDT_V1_REJ_CAPACITY;
        if (mutate_active != 0) {
            restore_active_from_durable(eng, x);
        }
        return rc;
    }
    make_key(nkey, "NRC1", x->transfer_id);
    if (mutate_active) {
        rc = pack_active(eng, x, rec, &rec_len);
        if (rc != NINLIL_MFDT_V1_OK) {
            restore_active_from_durable(eng, x);
            return rc;
        }
        make_key(akey, x->role == 1u ? "NM3S" : "NM3R", x->transfer_id);
        /* CU capture uses cu_observe_key after FULL; no dual 35KB BSS. */
        rc = full_put_active_and_nrc1(eng, akey, rec, rec_len, nkey, nblob,
                                      NINLIL_MFDT_V1_NRC1_VALUE_BYTES);
    } else {
        rc = full_put_one(eng, nkey, nblob, NINLIL_MFDT_V1_NRC1_VALUE_BYTES);
    }
    if (rc != NINLIL_MFDT_V1_OK) {
        if (mutate_active) {
            /*
             * Never leave volatile progress ahead of durable truth. Reload the
             * exact raw active record (OLD or NEW after CU); if no active key
             * exists, clear the provisional receiver/sender image.
             */
            restore_active_from_durable(eng, x);
        }
        return rc;
    }
    resp->message_type = resp_type;
    resp->body_len = resp_len;
    (void)memcpy(resp->body, resp_body, resp_len);
    if (resp_type == NINLIL_MFDT_V1_MSG_REJECT && resp_len == 60u) {
        resp->reject_code = ninlil_mfdt_v1_get_u16(resp_body + 54);
    }
    resp->from_nrc1_hit = 0u;
    resp->state_mutation = 1u;
    resp->full_count = 1u;
    return NINLIL_MFDT_V1_OK;
}

/*
 * A semantic rejection of an already-active receiver request is itself a
 * first response.  Cache the exact BIND52 REJECT in NRC1 before it may reach
 * the wire; no active progress field changes in this dedicated FULL.
 */
static int commit_active_reject(
    ninlil_mfdt_v1_engine_t *eng, mfdt_xfer_t *x,
    uint8_t request_type, const uint8_t *request_body,
    uint16_t request_body_len, uint64_t request_id,
    uint16_t reject_code, uint32_t detail,
    ninlil_mfdt_v1_response_t *resp)
{
    uint8_t reject_body[60];
    ninlil_mfdt_v1_response_t exact;
    const uint16_t stage = request_stage_for_type(request_type);
    int rc;
    if (eng == NULL || x == NULL || request_body == NULL ||
        request_body_len == 0u || request_id == 0ull ||
        stage == 0u || resp == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    rc = fill_reject_for_active(
        eng, stage, reject_code, detail, &exact);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    (void)memcpy(reject_body, exact.body, sizeof(reject_body));
    return commit_resp_with_active(
        eng, x, 0, request_type, request_body, request_body_len,
        request_id, NINLIL_MFDT_V1_MSG_REJECT, reject_body,
        (uint16_t)sizeof(reject_body), resp);
}

/*
 * A request-triggered terminal fence is one indivisible group transition:
 * cache its exact REJECT, erase active, and publish NM30 in the same
 * three-operation FULL.  A dedicated REJECT FULL followed by terminal FULL
 * would create a crash-visible split and is forbidden.
 */
static int commit_terminal_request_reject(
    ninlil_mfdt_v1_engine_t *eng, mfdt_xfer_t *x,
    uint8_t request_type, const uint8_t *request_body,
    uint16_t request_body_len, uint64_t request_id,
    uint16_t terminal_state, uint16_t terminal_reason,
    uint16_t reject_code, const uint8_t *terminal_evidence,
    const uint8_t *terminal_acceptance,
    const uint8_t terminal_anchor_epoch[16],
    uint64_t terminal_anchor_ms,
    ninlil_mfdt_v1_response_t *resp)
{
    ninlil_mfdt_v1_response_t exact;
    uint8_t *nrc1 = engine_nrc1_scratch(eng);
    uint8_t request_digest[32];
    uint8_t nm30[NINLIL_MFDT_V1_NM30_BYTES];
    uint8_t active_key[20];
    uint8_t terminal_key[20];
    uint8_t nrc1_key[20];
    int present = 0;
    int rc;
    if (eng == NULL || x == NULL || request_body == NULL ||
        request_body_len < 52u || request_id == 0ull ||
        resp == NULL || nrc1 == NULL || x->occupied == 0u ||
        x->terminal != 0u || x->role != 2u ||
        terminal_anchor_epoch == NULL ||
        is_zero16(terminal_anchor_epoch) ||
        terminal_anchor_ms == 0ull) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    rc = fill_reject_for_active(
        eng, request_stage_for_type(request_type),
        reject_code, 0u, &exact);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = nrc1_load(eng, x->transfer_id, nrc1, &present);
    if (rc != NINLIL_MFDT_V1_OK || present == 0) {
        return rc != NINLIL_MFDT_V1_OK
                   ? rc : NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (nrc1_find(
            nrc1, eng->cfg.session_generation, request_id) >= 0) {
        /*
         * nrc1_try_hit() must have handled a hit or digest conflict before
         * this helper.  Reaching the terminal mutation with an occupied RID
         * would risk replacing immutable replay evidence.
         */
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    ninlil_mfdt_v1_request_body_digest(
        request_type, request_body, request_body_len, request_digest);
    rc = nrc1_insert(
        nrc1, eng->cfg.session_generation, request_id, request_digest,
        NINLIL_MFDT_V1_MSG_REJECT, exact.body, exact.body_len);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = build_nm30(
        nm30, eng, x, terminal_state, terminal_reason, 0u,
        terminal_evidence, terminal_acceptance, NULL,
        terminal_anchor_epoch, terminal_anchor_ms);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    make_key(active_key, "NM3R", x->transfer_id);
    make_key(terminal_key, "NM30", x->transfer_id);
    make_key(nrc1_key, "NRC1", x->transfer_id);
    rc = full_terminal_with_nrc1(
        eng, active_key, terminal_key, nm30,
        NINLIL_MFDT_V1_NM30_BYTES, nrc1_key, nrc1,
        NINLIL_MFDT_V1_NRC1_VALUE_BYTES);
    if (rc != NINLIL_MFDT_V1_OK) {
        restore_active_from_durable(eng, x);
        return rc;
    }
    x->terminal = 1u;
    eng->active_count = 0u;
    eng->publication_ready = 0u;
    eng->handoff_complete = 0u;
    *resp = exact;
    resp->state_mutation = 1u;
    resp->full_count = 1u;
    return NINLIL_MFDT_V1_OK;
}

static int commit_expired_request_reject(
    ninlil_mfdt_v1_engine_t *eng, mfdt_xfer_t *x,
    uint8_t request_type, const uint8_t *request_body,
    uint16_t request_body_len, uint64_t request_id,
    ninlil_mfdt_v1_response_t *resp)
{
    if (eng == NULL || x == NULL || !expired_now(eng, x) ||
        x->state_code >= NINLIL_MFDT_V1_R_CONTENT_VERIFIED) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    return commit_terminal_request_reject(
        eng, x, request_type, request_body, request_body_len,
        request_id, NINLIL_MFDT_V1_TERM_ABORTED,
        NINLIL_MFDT_V1_TERM_REASON_EXPIRED,
        NINLIL_MFDT_V1_REJ_EXPIRED, NULL, NULL,
        x->res_epoch, eng->cfg.now_ms, resp);
}

static int fence_request_if_local_epoch_changed(
    ninlil_mfdt_v1_engine_t *eng, mfdt_xfer_t *x,
    uint8_t request_type, const uint8_t *request_body,
    uint16_t request_body_len, uint64_t request_id,
    ninlil_mfdt_v1_response_t *resp)
{
    const uint8_t *evidence = NULL;
    const uint8_t *acceptance = NULL;
    int rc;
    if (eng == NULL || x == NULL || x->occupied == 0u ||
        x->terminal != 0u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (is_zero16(x->durable_local_epoch) ||
        ninlil_mfdt_v1_memeq(
            x->durable_local_epoch,
            eng->cfg.local_clock_epoch.bytes, 16u)) {
        return NINLIL_MFDT_V1_OK;
    }
    if (!is_zero16(x->evidence_id) &&
        !is_zero32(x->acceptance_record_digest)) {
        evidence = x->evidence_id;
        acceptance = x->acceptance_record_digest;
    }
    rc = commit_terminal_request_reject(
        eng, x, request_type, request_body, request_body_len,
        request_id, NINLIL_MFDT_V1_TERM_CORRUPT_FENCED,
        NINLIL_MFDT_V1_TERM_REASON_EPOCH,
        NINLIL_MFDT_V1_REJ_STATE, evidence, acceptance,
        x->durable_local_epoch, x->durable_local_mono_ms, resp);
    return rc == NINLIL_MFDT_V1_OK
               ? NINLIL_MFDT_V1_ERR_STATE : rc;
}

/* ---- Engine init -------------------------------------------------------- */

int ninlil_mfdt_v1_engine_init(ninlil_mfdt_v1_engine_t *eng,
                               ninlil_mfdt_v1_workspace_t *ws,
                               ninlil_mfdt_v1_lab_store_t *store,
                               const ninlil_mfdt_v1_config_t *cfg)
{
    if (eng == NULL || ws == NULL || store == NULL || cfg == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_memzero(eng, sizeof(*eng));
    ninlil_mfdt_v1_memzero(ws, sizeof(*ws));
    eng->ws = ws;
    eng->store = store;
    eng->cfg = *cfg;
    eng->slot_record_memory = ws->bytes + MFDT_WS_RECORD_OFF;
    eng->slot_nrc1_memory = ws->bytes + MFDT_WS_NRC1_OFF;
    eng->slot_xfer_memory = ws->bytes + MFDT_WS_XFER_OFF;
    eng->slot_open_staging = ws->bytes + MFDT_WS_OPEN_OFF;
    eng->slot_entries_staging = ws->bytes + MFDT_WS_ENTRIES_OFF;
    eng->slot_record_memory_bytes = (uint32_t)MFDT_WS_RECORD_BYTES;
    eng->slot_nrc1_memory_bytes = (uint32_t)MFDT_WS_NRC1_BYTES;
    eng->slot_xfer_memory_bytes = (uint32_t)MFDT_WS_XFER_BYTES;
    eng->slot_open_staging_bytes = (uint32_t)MFDT_WS_OPEN_MAX;
    eng->slot_entries_staging_bytes = (uint32_t)MFDT_WS_ENTRIES_BYTES;
    eng->slot_layout = 1u;
    eng->active_count = 0u;
    eng->fulls_this_transfer = 0u;
    return NINLIL_MFDT_V1_OK;
}

void ninlil_mfdt_v1_engine_fini(ninlil_mfdt_v1_engine_t *eng)
{
    ninlil_mfdt_v1_workspace_t *workspace;

    if (eng == NULL) {
        return;
    }
    workspace = eng->ws;
    if (workspace != NULL) {
        ninlil_mfdt_v1_memzero(workspace, sizeof(*workspace));
    } else if (eng->slot_layout != 0u) {
        if (eng->slot_record_memory != NULL) {
            ninlil_mfdt_v1_memzero(
                eng->slot_record_memory, eng->slot_record_memory_bytes);
        }
        if (eng->slot_nrc1_memory != NULL) {
            ninlil_mfdt_v1_memzero(
                eng->slot_nrc1_memory, eng->slot_nrc1_memory_bytes);
        }
        if (eng->slot_xfer_memory != NULL) {
            ninlil_mfdt_v1_memzero(
                eng->slot_xfer_memory, eng->slot_xfer_memory_bytes);
        }
        if (eng->slot_open_staging != NULL) {
            ninlil_mfdt_v1_memzero(
                eng->slot_open_staging, eng->slot_open_staging_bytes);
        }
        if (eng->slot_entries_staging != NULL) {
            ninlil_mfdt_v1_memzero(
                eng->slot_entries_staging, eng->slot_entries_staging_bytes);
        }
    }
    ninlil_mfdt_v1_memzero(eng, sizeof(*eng));
}

typedef struct mfdt_memory_range {
    uintptr_t begin;
    uintptr_t end;
} mfdt_memory_range_t;

static int memory_range_make(
    const void *pointer, size_t length, mfdt_memory_range_t *out)
{
    const uintptr_t begin = (uintptr_t)pointer;
    if (pointer == NULL || out == NULL || length == 0u ||
        begin > UINTPTR_MAX - length) {
        return 0;
    }
    out->begin = begin;
    out->end = begin + length;
    return 1;
}

static int memory_ranges_overlap(
    const mfdt_memory_range_t *a, const mfdt_memory_range_t *b)
{
    return a->begin < b->end && b->begin < a->end;
}

static int slot_memory_binding_safe(
    ninlil_mfdt_v1_engine_t *eng,
    const ninlil_mfdt_v1_engine_slot_memory_t *memory,
    struct ninlil_mfdt_v1_store_port *store_port,
    uint32_t *committed_keys,
    uint64_t *committed_logical_bytes,
    uint8_t *full_locked,
    uint8_t *inventory_uncertain,
    const ninlil_mfdt_v1_config_t *cfg)
{
    mfdt_memory_range_t regions[5];
    mfdt_memory_range_t protected_objects[8];
    size_t i;
    size_t j;
    if (((uintptr_t)memory->record_memory & 7u) != 0u ||
        ((uintptr_t)memory->nrc1_memory & 7u) != 0u ||
        ((uintptr_t)memory->xfer_memory & 7u) != 0u ||
        ((uintptr_t)memory->open_staging & 7u) != 0u ||
        ((uintptr_t)memory->entries_staging & 7u) != 0u ||
        !memory_range_make(
            memory->record_memory, memory->record_memory_bytes, &regions[0]) ||
        !memory_range_make(
            memory->nrc1_memory, memory->nrc1_memory_bytes, &regions[1]) ||
        !memory_range_make(
            memory->xfer_memory, memory->xfer_memory_bytes, &regions[2]) ||
        !memory_range_make(
            memory->open_staging, memory->open_staging_bytes, &regions[3]) ||
        !memory_range_make(
            memory->entries_staging, memory->entries_staging_bytes,
            &regions[4]) ||
        !memory_range_make(eng, sizeof(*eng), &protected_objects[0]) ||
        !memory_range_make(memory, sizeof(*memory), &protected_objects[1]) ||
        !memory_range_make(
            store_port, sizeof(*store_port), &protected_objects[2]) ||
        !memory_range_make(
            committed_keys, sizeof(*committed_keys), &protected_objects[3]) ||
        !memory_range_make(
            committed_logical_bytes, sizeof(*committed_logical_bytes),
            &protected_objects[4]) ||
        !memory_range_make(
            full_locked, sizeof(*full_locked), &protected_objects[5]) ||
        !memory_range_make(
            inventory_uncertain, sizeof(*inventory_uncertain),
            &protected_objects[6]) ||
        !memory_range_make(cfg, sizeof(*cfg), &protected_objects[7])) {
        return 0;
    }
    for (i = 0u; i < 8u; ++i) {
        for (j = i + 1u; j < 8u; ++j) {
            if (memory_ranges_overlap(
                    &protected_objects[i], &protected_objects[j])) {
                return 0;
            }
        }
    }
    for (i = 0u; i < 5u; ++i) {
        for (j = i + 1u; j < 5u; ++j) {
            if (memory_ranges_overlap(&regions[i], &regions[j])) {
                return 0;
            }
        }
        for (j = 0u; j < 8u; ++j) {
            if (memory_ranges_overlap(&regions[i], &protected_objects[j])) {
                return 0;
            }
        }
    }
    return 1;
}

int ninlil_mfdt_v1_engine_init_slot(
    ninlil_mfdt_v1_engine_t *eng,
    const ninlil_mfdt_v1_engine_slot_memory_t *memory,
    struct ninlil_mfdt_v1_store_port *store_port,
    uint32_t *committed_keys,
    uint64_t *committed_logical_bytes,
    uint8_t *full_locked,
    uint8_t *inventory_uncertain,
    const ninlil_mfdt_v1_config_t *cfg)
{
    if (eng == NULL || memory == NULL || store_port == NULL ||
        committed_keys == NULL || committed_logical_bytes == NULL ||
        full_locked == NULL || inventory_uncertain == NULL || cfg == NULL ||
        memory->record_memory == NULL ||
        memory->record_memory_bytes <
            NINLIL_MFDT_V1_ACTIVE_VALUE_MAX + 1u ||
        memory->nrc1_memory == NULL ||
        memory->nrc1_memory_bytes < NINLIL_MFDT_V1_NRC1_VALUE_BYTES ||
        memory->xfer_memory == NULL ||
        memory->xfer_memory_bytes < sizeof(mfdt_xfer_t) ||
        memory->open_staging == NULL ||
        memory->open_staging_bytes < MFDT_WS_OPEN_MAX ||
        memory->entries_staging == NULL ||
        memory->entries_staging_bytes <
            (uint32_t)NINLIL_MFDT_V1_MAX_CHUNKS *
                NINLIL_MFDT_V1_ENTRY_BYTES ||
        !slot_memory_binding_safe(
            eng, memory, store_port, committed_keys,
            committed_logical_bytes, full_locked, inventory_uncertain, cfg) ||
        ninlil_mfdt_v1_store_guarantees_validate(
            &store_port->guarantees) != NINLIL_MFDT_V1_OK) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_memzero(eng, sizeof(*eng));
    ninlil_mfdt_v1_memzero(
        memory->record_memory, memory->record_memory_bytes);
    ninlil_mfdt_v1_memzero(
        memory->nrc1_memory, memory->nrc1_memory_bytes);
    ninlil_mfdt_v1_memzero(
        memory->xfer_memory, memory->xfer_memory_bytes);
    ninlil_mfdt_v1_memzero(
        memory->open_staging, memory->open_staging_bytes);
    ninlil_mfdt_v1_memzero(
        memory->entries_staging, memory->entries_staging_bytes);
    eng->cfg = *cfg;
    eng->cfg.host_mode = 1u;
    eng->store_port = store_port;
    eng->slot_record_memory = memory->record_memory;
    eng->slot_nrc1_memory = memory->nrc1_memory;
    eng->slot_xfer_memory = memory->xfer_memory;
    eng->slot_open_staging = memory->open_staging;
    eng->slot_entries_staging = memory->entries_staging;
    eng->slot_record_memory_bytes = memory->record_memory_bytes;
    eng->slot_nrc1_memory_bytes = memory->nrc1_memory_bytes;
    eng->slot_xfer_memory_bytes = memory->xfer_memory_bytes;
    eng->slot_open_staging_bytes = memory->open_staging_bytes;
    eng->slot_entries_staging_bytes = memory->entries_staging_bytes;
    eng->host_committed_keys = committed_keys;
    eng->host_committed_logical_bytes = committed_logical_bytes;
    eng->host_full_locked = full_locked;
    eng->host_inventory_uncertain = inventory_uncertain;
    eng->slot_layout = 1u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_engine_rehydrate_captured(
    ninlil_mfdt_v1_engine_t *eng,
    const uint8_t *active_record,
    uint32_t active_record_len,
    const uint8_t *nrc1_record,
    uint32_t nrc1_record_len,
    const ninlil_mfdt_v1_config_t *cfg)
{
    ninlil_mfdt_v1_store_port_t *store_port;
    uint8_t *record_memory;
    uint8_t *nrc1_memory;
    uint8_t *xfer_memory;
    uint8_t *open_staging;
    uint8_t *entries_staging;
    uint32_t record_memory_bytes;
    uint32_t nrc1_memory_bytes;
    uint32_t xfer_memory_bytes;
    uint32_t open_staging_bytes;
    uint32_t entries_staging_bytes;
    uint32_t *committed_keys;
    uint64_t *committed_bytes;
    uint8_t *full_locked;
    uint8_t *inventory_uncertain;
    uint8_t transfer_id[16];
    uint8_t peer[16];
    uint32_t session_generation = 0u;
    uint8_t role;
    mfdt_xfer_t *x;
    int rc;
    if (eng == NULL || active_record == NULL || nrc1_record == NULL ||
        cfg == NULL ||
        eng->slot_layout == 0u ||
        active_record_len > NINLIL_MFDT_V1_ACTIVE_VALUE_MAX ||
        nrc1_record_len != NINLIL_MFDT_V1_NRC1_VALUE_BYTES) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    role = active_record_len > 13u ? active_record[12] : 0u;
    if (active_record_len < 32u) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    (void)memcpy(transfer_id, active_record + 16, 16u);
    rc = ninlil_mfdt_v1_validate_active_record(
        active_record, active_record_len, transfer_id, role,
        &session_generation, peer);
    if (rc != NINLIL_MFDT_V1_OK ||
        session_generation != cfg->session_generation ||
        !ninlil_mfdt_v1_memeq(
            active_record + 200, cfg->local_clock_epoch.bytes, 16u)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    rc = ninlil_mfdt_v1_validate_nrc1_record(
        nrc1_record, nrc1_record_len, transfer_id,
        session_generation);
    if (rc != NINLIL_MFDT_V1_OK) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    store_port = eng->store_port;
    record_memory = eng->slot_record_memory;
    nrc1_memory = eng->slot_nrc1_memory;
    xfer_memory = eng->slot_xfer_memory;
    open_staging = eng->slot_open_staging;
    entries_staging = eng->slot_entries_staging;
    record_memory_bytes = eng->slot_record_memory_bytes;
    nrc1_memory_bytes = eng->slot_nrc1_memory_bytes;
    xfer_memory_bytes = eng->slot_xfer_memory_bytes;
    open_staging_bytes = eng->slot_open_staging_bytes;
    entries_staging_bytes = eng->slot_entries_staging_bytes;
    committed_keys = eng->host_committed_keys;
    committed_bytes = eng->host_committed_logical_bytes;
    full_locked = eng->host_full_locked;
    inventory_uncertain = eng->host_inventory_uncertain;
    if (store_port == NULL || record_memory == NULL || nrc1_memory == NULL ||
        xfer_memory == NULL || open_staging == NULL ||
        entries_staging == NULL || committed_keys == NULL ||
        committed_bytes == NULL || full_locked == NULL ||
        inventory_uncertain == NULL ||
        record_memory_bytes < NINLIL_MFDT_V1_ACTIVE_VALUE_MAX + 1u ||
        nrc1_memory_bytes < NINLIL_MFDT_V1_NRC1_VALUE_BYTES ||
        xfer_memory_bytes < sizeof(mfdt_xfer_t) ||
        open_staging_bytes < MFDT_WS_OPEN_MAX ||
        entries_staging_bytes <
            (uint32_t)NINLIL_MFDT_V1_MAX_CHUNKS *
                NINLIL_MFDT_V1_ENTRY_BYTES) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (active_record != record_memory) {
        (void)memmove(record_memory, active_record, active_record_len);
    }
    if (nrc1_record != nrc1_memory) {
        (void)memmove(nrc1_memory, nrc1_record, nrc1_record_len);
    }
    ninlil_mfdt_v1_memzero(
        record_memory + active_record_len,
        (size_t)record_memory_bytes - active_record_len);
    ninlil_mfdt_v1_memzero(
        nrc1_memory + nrc1_record_len,
        (size_t)nrc1_memory_bytes - nrc1_record_len);
    ninlil_mfdt_v1_memzero(eng, sizeof(*eng));
    ninlil_mfdt_v1_memzero(xfer_memory, xfer_memory_bytes);
    ninlil_mfdt_v1_memzero(open_staging, open_staging_bytes);
    ninlil_mfdt_v1_memzero(entries_staging, entries_staging_bytes);
    eng->cfg = *cfg;
    eng->cfg.host_mode = 1u;
    eng->store_port = store_port;
    eng->slot_record_memory = record_memory;
    eng->slot_nrc1_memory = nrc1_memory;
    eng->slot_xfer_memory = xfer_memory;
    eng->slot_open_staging = open_staging;
    eng->slot_entries_staging = entries_staging;
    eng->slot_record_memory_bytes = record_memory_bytes;
    eng->slot_nrc1_memory_bytes = nrc1_memory_bytes;
    eng->slot_xfer_memory_bytes = xfer_memory_bytes;
    eng->slot_open_staging_bytes = open_staging_bytes;
    eng->slot_entries_staging_bytes = entries_staging_bytes;
    eng->host_committed_keys = committed_keys;
    eng->host_committed_logical_bytes = committed_bytes;
    eng->host_full_locked = full_locked;
    eng->host_inventory_uncertain = inventory_uncertain;
    eng->slot_layout = 1u;
    eng->slot_record_packed = 1u;
    x = xfer_ptr(eng);
    (void)memcpy(x->transfer_id, transfer_id, 16u);
    x->occupied = 1u;
    x->role = role;
    rc = project_active_record(
        eng, x, record_memory, active_record_len);
    if (rc != NINLIL_MFDT_V1_OK) {
        ninlil_mfdt_v1_memzero(x, sizeof(*x));
        eng->slot_record_packed = 0u;
        return rc;
    }
    eng->active_count = 1u;
    x->terminal = 0u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_engine_preallocate(void)
{
    /* Compatibility no-op: all operational scratch is caller-owned now. */
    return NINLIL_MFDT_V1_OK;
}

void ninlil_mfdt_v1_engine_set_now(ninlil_mfdt_v1_engine_t *eng, uint64_t now_ms)
{
    if (eng != NULL) {
        eng->cfg.now_ms = now_ms;
    }
}

int ninlil_mfdt_v1_engine_observe_time(
    ninlil_mfdt_v1_engine_t *eng,
    const uint8_t local_clock_epoch[16],
    uint64_t now_ms,
    uint8_t *epoch_changed_out)
{
    mfdt_xfer_t *x;
    int changed;
    int rc;

    if (eng == NULL || local_clock_epoch == NULL
        || epoch_changed_out == NULL || is_zero16(local_clock_epoch)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    changed = !ninlil_mfdt_v1_memeq(
        eng->cfg.local_clock_epoch.bytes, local_clock_epoch, 16u);
    *epoch_changed_out = changed != 0 ? 1u : 0u;
    if (changed == 0 && now_ms < eng->cfg.now_ms) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (changed != 0) {
        (void)memcpy(
            eng->cfg.local_clock_epoch.bytes, local_clock_epoch, 16u);
    }
    eng->cfg.now_ms = now_ms;

    x = xfer_ptr(eng);
    if (eng->active_count == 0u || x == NULL || !x->occupied
        || x->terminal) {
        return NINLIL_MFDT_V1_OK;
    }
    if (!is_zero16(x->durable_local_epoch)
        && !ninlil_mfdt_v1_memeq(
            x->durable_local_epoch, local_clock_epoch, 16u)) {
        *epoch_changed_out = 1u;
    }
    rc = fence_if_local_epoch_changed(eng, x, 0u, NULL);
    return rc == NINLIL_MFDT_V1_ERR_STATE && x->terminal
        ? NINLIL_MFDT_V1_OK : rc;
}

void ninlil_mfdt_v1_engine_set_policy(ninlil_mfdt_v1_engine_t *eng,
                                      ninlil_mfdt_v1_policy_t policy)
{
    if (eng != NULL) {
        eng->cfg.policy = policy;
    }
}

void ninlil_mfdt_v1_engine_set_admission_version(ninlil_mfdt_v1_engine_t *eng,
                                       uint16_t mfdt_admission_version)
{
    if (eng != NULL) {
        eng->cfg.mfdt_admission_version = mfdt_admission_version;
    }
}

/* ---- Sender ------------------------------------------------------------- */

int ninlil_mfdt_v1_sender_open_with_metadata(
    ninlil_mfdt_v1_engine_t *eng, const uint8_t transfer_id[16],
    const uint8_t *content, uint32_t content_len,
    const ninlil_mfdt_v1_open_metadata_t *metadata,
    uint8_t *open_body_out, uint16_t *open_body_len_out, uint64_t request_id)
{
    ninlil_mfdt_v1_geometry_t geo;
    mfdt_xfer_t *x;
    uint8_t *entries;
    uint8_t whole[32];
    uint8_t md[32];
    uint16_t entry_bytes = 0u;
    int rc;
    uint8_t key[20];
    uint8_t nkey[20];
    uint8_t *rec = engine_record_scratch(eng);
    uint8_t *nrc1 = engine_nrc1_scratch(eng);
    if (rec == NULL || nrc1 == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    uint32_t rec_len = 0u;
    (void)request_id;
    if (eng == NULL || transfer_id == NULL || open_body_out == NULL ||
        open_body_len_out == NULL || metadata == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (content_len > 0u && content == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (is_zero16(transfer_id)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (is_zero16(metadata->origin_transaction_id) ||
        is_zero16(metadata->source_runtime_id) ||
        is_zero16(metadata->target_runtime_id) ||
        metadata->service_descriptor_revision == 0ull ||
        is_zero32(metadata->service_descriptor_digest) ||
        !manifest_text_id_ok(metadata->namespace_bytes,
                             metadata->namespace_length, 1) ||
        !manifest_text_id_ok(metadata->service_bytes,
                             metadata->service_length, 0) ||
        !manifest_text_id_ok(metadata->schema_bytes,
                             metadata->schema_length, 0) ||
        (is_zero16(metadata->deadline_clock_epoch_id) &&
         metadata->absolute_effect_deadline_ms != UINT64_MAX) ||
        (!is_zero16(metadata->deadline_clock_epoch_id) &&
         (metadata->absolute_effect_deadline_ms == 0ull ||
          metadata->absolute_effect_deadline_ms == UINT64_MAX))) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    rc = policy_ok(eng);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = ninlil_mfdt_v1_geometry(content_len, &geo);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    if (eng->active_count >= active_max(eng)) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    x = xfer_ptr(eng);
    if (x->occupied && !x->terminal) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    if (eng->slot_layout != 0u) {
        eng->slot_record_packed = 0u;
        ninlil_mfdt_v1_memzero(
            eng->slot_record_memory, NINLIL_MFDT_V1_ACTIVE_VALUE_MAX + 1u);
        ninlil_mfdt_v1_memzero(
            eng->slot_open_staging, MFDT_WS_OPEN_MAX);
        ninlil_mfdt_v1_memzero(
            eng->slot_entries_staging,
            (size_t)NINLIL_MFDT_V1_MAX_CHUNKS *
                NINLIL_MFDT_V1_ENTRY_BYTES);
    }
    ninlil_mfdt_v1_memzero(x, sizeof(*x));
    (void)memcpy(x->transfer_id, transfer_id, 16u);
    x->occupied = 1u;
    x->role = 1u;
    x->state_code = NINLIL_MFDT_V1_S_OPEN_PENDING;
    x->retry_budget = NINLIL_MFDT_V1_RETRY_BUDGET_MAX;
    x->chunk_count = geo.chunk_count;
    x->page_count = geo.page_count;
    x->total_length = content_len;
    x->record_generation = 1u;
    x->revision = 1u;
    if (content_len > 0u) {
        (void)memcpy(content_ptr(eng), content, content_len);
    }
    entries = entries_ptr(eng);
    rc = ninlil_mfdt_v1_encode_open(
        transfer_id, content_len, content_len ? content : NULL, metadata,
        open_body_out, open_body_len_out, entries, &entry_bytes, md, whole);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    (void)memcpy(x->manifest_digest, md, 32u);
    (void)memcpy(x->whole_digest, whole, 32u);
    x->open_len = *open_body_len_out;
    (void)memcpy(open_ptr(eng), open_body_out, x->open_len);
    make_key(key, "NM3S", transfer_id);
    make_key(nkey, "NRC1", transfer_id);
    nrc1_init_empty(nrc1, transfer_id, eng->cfg.session_generation);
    rc = pack_active(eng, x, rec, &rec_len);
    if (rc != NINLIL_MFDT_V1_OK) {
        restore_active_from_durable(eng, x);
        return rc;
    }
    rc = full_put_active_and_nrc1(
        eng, key, rec, rec_len, nkey, nrc1,
        NINLIL_MFDT_V1_NRC1_VALUE_BYTES);
    if (rc != NINLIL_MFDT_V1_OK) {
        restore_active_from_durable(eng, x);
        return rc;
    }
    eng->active_count = (uint8_t)(eng->active_count + 1u);
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_sender_open(ninlil_mfdt_v1_engine_t *eng,
                               const uint8_t transfer_id[16],
                               const uint8_t *content, uint32_t content_len,
                               uint8_t *open_body_out,
                               uint16_t *open_body_len_out,
                               uint64_t request_id)
{
    ninlil_mfdt_v1_open_metadata_t metadata;
    static const uint8_t ns[] = {'n'};
    static const uint8_t service[] = {'s'};
    static const uint8_t schema[] = {'x'};

    ninlil_mfdt_v1_memzero(&metadata, sizeof(metadata));
    metadata.origin_transaction_id[0] = 0x20u;
    metadata.origin_event_id[0] = 0x30u;
    metadata.source_runtime_id[0] = 0x40u;
    metadata.target_runtime_id[0] = 0x50u;
    metadata.service_descriptor_revision = 1ull;
    ninlil_mfdt_v1_sha256(
        (const uint8_t *)"mfdt-service-descriptor", 23u,
        metadata.service_descriptor_digest);
    metadata.original_attempt_id[0] = 0x60u;
    metadata.source_application_instance_id[0] = 0x70u;
    metadata.target_application_instance_id[0] = 0x80u;
    metadata.service_schema_major = 1u;
    metadata.service_family = 1u;
    metadata.absolute_effect_deadline_ms = UINT64_MAX;
    metadata.required_evidence = 1u;
    metadata.namespace_bytes = ns;
    metadata.namespace_length = (uint16_t)sizeof(ns);
    metadata.service_bytes = service;
    metadata.service_length = (uint16_t)sizeof(service);
    metadata.schema_bytes = schema;
    metadata.schema_length = (uint16_t)sizeof(schema);
    return ninlil_mfdt_v1_sender_open_with_metadata(
        eng, transfer_id, content, content_len, &metadata, open_body_out,
        open_body_len_out, request_id);
}

/* BIND52: transfer_id[16] + revision[4] + manifest_digest[32] at body[0..51]. */
static int accept_bind52_ok(const uint8_t *body, uint16_t len,
                            const mfdt_xfer_t *x)
{
    uint32_t rev;
    if (body == NULL || x == NULL || len < 52u) {
        return 0;
    }
    if (!ninlil_mfdt_v1_memeq(body + 0, x->transfer_id, 16u)) {
        return 0;
    }
    rev = ninlil_mfdt_v1_get_u32(body + 16);
    if (rev != x->revision) {
        return 0;
    }
    if (!ninlil_mfdt_v1_memeq(body + 20, x->manifest_digest, 32u)) {
        return 0;
    }
    return 1;
}

static void acceptance_digest(const mfdt_xfer_t *x, uint64_t acceptance_gen,
                              uint8_t out[32])
{
    uint8_t pre[141];
    size_t off = 0u;

    (void)memcpy(pre + off, "NM3-ACCEPT-V1", 13u);
    off += 13u;
    ninlil_mfdt_v1_bind52(x->transfer_id, x->revision, x->manifest_digest,
                          pre + off);
    off += 52u;
    (void)memcpy(pre + off, x->whole_digest, 32u);
    off += 32u;
    ninlil_mfdt_v1_put_u32(pre + off, x->total_length);
    off += 4u;
    (void)memcpy(pre + off, x->evidence_id, 16u);
    off += 16u;
    ninlil_mfdt_v1_put_u64(pre + off, acceptance_gen);
    off += 8u;
    (void)memcpy(pre + off, x->reservation_id, 16u);
    off += 16u;
    ninlil_mfdt_v1_sha256(pre, off, out);
}

int ninlil_mfdt_v1_sender_reissue_open(ninlil_mfdt_v1_engine_t *eng,
                                       uint8_t *open_body_out,
                                       uint16_t *open_body_len_out)
{
    mfdt_xfer_t *x;
    if (eng == NULL || open_body_out == NULL || open_body_len_out == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    x = xfer_ptr(eng);
    if (!x->occupied || x->terminal || x->role != 1u ||
        x->state_code != NINLIL_MFDT_V1_S_OPEN_PENDING ||
        x->open_len < NINLIL_MFDT_V1_OPEN_BODY_MIN ||
        x->open_len > NINLIL_MFDT_V1_OPEN_BODY_MAX) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    (void)memcpy(open_body_out, open_ptr(eng), x->open_len);
    *open_body_len_out = x->open_len;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_sender_on_open_accept(ninlil_mfdt_v1_engine_t *eng,
                                         const uint8_t *accept_body,
                                         uint16_t accept_len,
                                         uint64_t request_id)
{
    mfdt_xfer_t *x;
    uint8_t key[20];
    uint8_t *rec;
    uint32_t rec_len = 0u;
    int rc;

    (void)request_id; /* correlated by pipeline; body bind still required */
    if (eng == NULL || accept_body == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    /*
     * Exact wire minimum = 100 (encode_open_accept). Lengths 16..99 are
     * trunc mutations: reject before any +52 memcpy.
     */
    if (accept_len < 100u) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    rec = engine_record_scratch(eng);
    if (rec == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    x = xfer_ptr(eng);
    if (!x->occupied || x->role != 1u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (!accept_bind52_ok(accept_body, accept_len, x)) {
        return NINLIL_MFDT_V1_ERR_DIGEST;
    }
    if (is_zero16(accept_body + 52) ||
        ninlil_mfdt_v1_get_u32(accept_body + 68) != x->total_length ||
        is_zero16(accept_body + 72) ||
        ninlil_mfdt_v1_get_u64(accept_body + 88) == 0ull ||
        (ninlil_mfdt_v1_memeq(
             accept_body + 72, eng->cfg.local_clock_epoch.bytes, 16u) &&
         ninlil_mfdt_v1_get_u64(accept_body + 88) <= eng->cfg.now_ms) ||
        accept_body[96] > 1u || accept_body[97] != 0u ||
        accept_body[98] != 0u || accept_body[99] != 0u ||
        (x->total_length == 0u ? accept_body[96] != 1u
                               : accept_body[96] != 0u)) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    /* Bounds OK: bind52 + reservation fields. */
    (void)memcpy(x->reservation_id, accept_body + 52, 16u);
    (void)memcpy(x->res_epoch, accept_body + 72, 16u);
    x->not_after_ms = ninlil_mfdt_v1_get_u64(accept_body + 88);
    x->state_code = NINLIL_MFDT_V1_S_OPEN_ACCEPTED;
    x->record_generation += 1u;
    make_key(key, "NM3S", x->transfer_id);
    rc = pack_active(eng, x, rec, &rec_len);
    if (rc != NINLIL_MFDT_V1_OK) {
        restore_active_from_durable(eng, x);
        return rc;
    }
    return full_put_active_reload_on_failure(eng, x, key, rec, rec_len);
}

int ninlil_mfdt_v1_sender_offer_page(ninlil_mfdt_v1_engine_t *eng,
                                     uint16_t page_index, uint64_t request_id,
                                     uint8_t *page_body_out,
                                     uint16_t *page_body_len_out)
{
    mfdt_xfer_t *x;
    uint16_t first;
    uint16_t count;
    (void)request_id;
    if (eng == NULL || page_body_out == NULL || page_body_len_out == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    x = xfer_ptr(eng);
    if (!x->occupied || x->role != 1u || page_index >= x->page_count) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (x->retry_budget == 0u) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    first = (uint16_t)(page_index * NINLIL_MFDT_V1_ENTRIES_PER_PAGE);
    count = (uint16_t)(x->chunk_count - first);
    if (count > NINLIL_MFDT_V1_ENTRIES_PER_PAGE) {
        count = NINLIL_MFDT_V1_ENTRIES_PER_PAGE;
    }
    return ninlil_mfdt_v1_encode_page(
        x->transfer_id, x->revision, x->manifest_digest, page_index, x->page_count,
        first, count, entries_ptr(eng) + (size_t)first * 40u, page_body_out,
        page_body_len_out);
}

int ninlil_mfdt_v1_sender_on_page_accept(ninlil_mfdt_v1_engine_t *eng,
                                         const uint8_t *body, uint16_t len,
                                         uint64_t request_id)
{
    mfdt_xfer_t *x;
    uint16_t page_index;
    uint8_t key[20];
    uint8_t *rec;
    uint8_t expected_page[1024];
    uint16_t expected_len = 0u;
    uint16_t first;
    uint16_t count;
    uint8_t expected_bitmap;
    uint8_t expected_complete;
    uint16_t expected_received = 0u;
    uint8_t bits;
    int mutate_active;
    uint32_t rec_len = 0u;
    int rc;

    (void)request_id;
    if (eng == NULL || body == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (len != 108u) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    rec = engine_record_scratch(eng);
    if (rec == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    x = xfer_ptr(eng);
    if (!x->occupied || x->role != 1u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (!accept_bind52_ok(body, len, x)) {
        return NINLIL_MFDT_V1_ERR_DIGEST;
    }
    page_index = ninlil_mfdt_v1_get_u16(body + 52);
    if (page_index >= x->page_count || page_index >= 8u ||
        !ninlil_mfdt_v1_memeq(body + 88, x->reservation_id, 16u) ||
        body[104] > 1u || body[105] != 0u || body[106] != 0u ||
        body[107] != 0u) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    first = (uint16_t)(page_index * NINLIL_MFDT_V1_ENTRIES_PER_PAGE);
    count = (uint16_t)(x->chunk_count - first);
    if (count > NINLIL_MFDT_V1_ENTRIES_PER_PAGE) {
        count = NINLIL_MFDT_V1_ENTRIES_PER_PAGE;
    }
    rc = ninlil_mfdt_v1_encode_page(
        x->transfer_id, x->revision, x->manifest_digest, page_index,
        x->page_count, first, count,
        entries_ptr(eng) + (size_t)first * 40u, expected_page, &expected_len);
    if (rc != NINLIL_MFDT_V1_OK || expected_len < 92u ||
        !ninlil_mfdt_v1_memeq(body + 56, expected_page + 60, 32u)) {
        return NINLIL_MFDT_V1_ERR_DIGEST;
    }
    expected_bitmap =
        (uint8_t)(x->page_bitmap | (uint8_t)(1u << page_index));
    bits = expected_bitmap;
    while (bits != 0u) {
        expected_received = (uint16_t)(expected_received + (bits & 1u));
        bits = (uint8_t)(bits >> 1);
    }
    expected_complete =
        expected_bitmap == (uint8_t)((1u << x->page_count) - 1u) ? 1u : 0u;
    if (ninlil_mfdt_v1_get_u16(body + 54) != expected_received ||
        body[104] != expected_complete) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    mutate_active = expected_bitmap != x->page_bitmap ? 1 : 0;
    x->page_bitmap = expected_bitmap;
    if (x->page_bitmap == (uint8_t)((1u << x->page_count) - 1u)) {
        x->state_code = NINLIL_MFDT_V1_S_MANIFEST_ACCEPTED;
    }
    if (mutate_active != 0) {
        x->record_generation += 1u;
    }
    make_key(key, "NM3S", x->transfer_id);
    rc = pack_active(eng, x, rec, &rec_len);
    if (rc != NINLIL_MFDT_V1_OK) {
        if (mutate_active != 0) {
            restore_active_from_durable(eng, x);
        }
        return rc;
    }
    if (mutate_active == 0) {
        return NINLIL_MFDT_V1_OK;
    }
    return full_put_active_reload_on_failure(eng, x, key, rec, rec_len);
}

int ninlil_mfdt_v1_sender_offer_chunk(ninlil_mfdt_v1_engine_t *eng,
                                      uint16_t chunk_index, uint64_t request_id,
                                      uint8_t *offer_out, uint16_t *offer_len_out)
{
    mfdt_xfer_t *x;
    uint32_t off;
    uint16_t clen;
    (void)request_id;
    if (eng == NULL || offer_out == NULL || offer_len_out == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    x = xfer_ptr(eng);
    if (!x->occupied || x->role != 1u || chunk_index >= x->chunk_count) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (x->unpaid_chunk) {
        return NINLIL_MFDT_V1_ERR_BUSY; /* fairness: one unpaid offer */
    }
    if (x->retry_budget == 0u) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    off = (uint32_t)chunk_index * NINLIL_MFDT_V1_CHUNK_SIZE;
    clen = (chunk_index + 1u == x->chunk_count)
               ? (uint16_t)(x->total_length - off)
               : NINLIL_MFDT_V1_CHUNK_SIZE;
    x->unpaid_chunk = 1u;
    eng->unpaid_chunk_offer = 1u;
    return ninlil_mfdt_v1_encode_chunk_offer(
        x->transfer_id, x->revision, x->manifest_digest, chunk_index,
        x->chunk_count, off, clen, content_ptr(eng) + off, offer_out,
        offer_len_out);
}

int ninlil_mfdt_v1_sender_on_chunk_accept(ninlil_mfdt_v1_engine_t *eng,
                                          const uint8_t *body, uint16_t len,
                                          uint64_t request_id)
{
    mfdt_xfer_t *x;
    uint16_t idx;
    uint8_t key[20];
    uint8_t *rec;
    uint32_t rec_len = 0u;
    int rc;

    (void)request_id;
    if (eng == NULL || body == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (len != 88u) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    rec = engine_record_scratch(eng);
    if (rec == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    x = xfer_ptr(eng);
    if (!x->occupied || x->role != 1u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (!accept_bind52_ok(body, len, x)) {
        return NINLIL_MFDT_V1_ERR_DIGEST;
    }
    idx = ninlil_mfdt_v1_get_u16(body + 52);
    if (idx >= x->chunk_count || idx >= 64u || body[54] != 0u ||
        body[55] != 0u) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    if (!ninlil_mfdt_v1_memeq(body + 56,
                              entries_ptr(eng) + (size_t)idx * 40u + 8u,
                              32u)) {
        return NINLIL_MFDT_V1_ERR_DIGEST;
    }
    {
        const uint64_t bit = (uint64_t)1u << idx;
        const int mutate_active =
            (x->chunk_bitmap & bit) == 0ull ? 1 : 0;
        x->chunk_bitmap |= bit;
        x->unpaid_chunk = 0u;
        eng->unpaid_chunk_offer = 0u;
        x->state_code = NINLIL_MFDT_V1_S_CHUNKS_PARTIAL;
        if (x->chunk_count > 0u &&
            x->chunk_bitmap == (((uint64_t)1u << x->chunk_count) - 1u)) {
            x->state_code = NINLIL_MFDT_V1_S_FINAL_WAIT;
        }
        if (mutate_active != 0) {
            x->record_generation += 1u;
        }
        make_key(key, "NM3S", x->transfer_id);
        rc = pack_active(eng, x, rec, &rec_len);
        if (rc != NINLIL_MFDT_V1_OK) {
            if (mutate_active != 0) {
                restore_active_from_durable(eng, x);
            }
            return rc;
        }
        if (mutate_active == 0) {
            return NINLIL_MFDT_V1_OK;
        }
    }
    return full_put_active_reload_on_failure(eng, x, key, rec, rec_len);
}

int ninlil_mfdt_v1_sender_finalize(ninlil_mfdt_v1_engine_t *eng,
                                   uint64_t request_id, uint8_t *fin_out,
                                   uint16_t *fin_len_out)
{
    mfdt_xfer_t *x;
    (void)request_id;
    if (eng == NULL || fin_out == NULL || fin_len_out == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    x = xfer_ptr(eng);
    if (!x->occupied || x->role != 1u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    return ninlil_mfdt_v1_encode_finalize(x->transfer_id, x->revision,
                                          x->manifest_digest, x->whole_digest,
                                          x->total_length, fin_out, fin_len_out);
}

int ninlil_mfdt_v1_sender_on_transfer_accept(ninlil_mfdt_v1_engine_t *eng,
                                             const uint8_t *body, uint16_t len,
                                             uint64_t request_id)
{
    mfdt_xfer_t *x;
    uint8_t key[20];
    uint8_t *rec;
    uint32_t rec_len = 0u;
    int rc;

    (void)request_id;
    if (eng == NULL || body == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (len != 160u) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    rec = engine_record_scratch(eng);
    if (rec == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    x = xfer_ptr(eng);
    if (!x->occupied || x->role != 1u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (!accept_bind52_ok(body, len, x)) {
        return NINLIL_MFDT_V1_ERR_DIGEST;
    }
    if (!ninlil_mfdt_v1_memeq(body + 52, x->whole_digest, 32u)) {
        return NINLIL_MFDT_V1_ERR_DIGEST;
    }
    if (ninlil_mfdt_v1_get_u32(body + 84) != x->total_length ||
        is_zero16(body + 88) || ninlil_mfdt_v1_get_u64(body + 104) == 0ull ||
        !ninlil_mfdt_v1_memeq(body + 112, x->reservation_id, 16u)) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    {
        uint8_t expected_acceptance_digest[32];
        mfdt_xfer_t evidence_view = *x;
        (void)memcpy(evidence_view.evidence_id, body + 88, 16u);
        acceptance_digest(&evidence_view, ninlil_mfdt_v1_get_u64(body + 104),
                          expected_acceptance_digest);
        if (!ninlil_mfdt_v1_memeq(body + 128, expected_acceptance_digest,
                                  32u)) {
            return NINLIL_MFDT_V1_ERR_DIGEST;
        }
    }
    /*
     * The sender's durable ACCEPT_RX evidence is part of terminal proof and
     * must survive restart.  Do not merely validate the wire bytes.
     */
    (void)memcpy(x->evidence_id, body + 88, 16u);
    x->acceptance_record_generation = ninlil_mfdt_v1_get_u64(body + 104);
    (void)memcpy(x->acceptance_record_digest, body + 128, 32u);
    x->state_code = NINLIL_MFDT_V1_S_ACCEPT_RX;
    x->record_generation += 1u;
    make_key(key, "NM3S", x->transfer_id);
    rc = pack_active(eng, x, rec, &rec_len);
    if (rc != NINLIL_MFDT_V1_OK) {
        restore_active_from_durable(eng, x);
        return rc;
    }
    return full_put_active_reload_on_failure(eng, x, key, rec, rec_len);
}

/* ---- Receiver ----------------------------------------------------------- */

int ninlil_mfdt_v1_receiver_on_open(ninlil_mfdt_v1_engine_t *eng,
                                    const uint8_t *open_body, uint16_t open_len,
                                    uint64_t request_id,
                                    ninlil_mfdt_v1_response_t *resp)
{
    mfdt_xfer_t *x;
    ninlil_mfdt_v1_geometry_t geo;
    uint8_t accept[100];
    uint16_t alen = 0u;
    int rc;
    int hit;
    uint8_t md[32];
    uint8_t res_id[16];
    uint8_t res_epoch[16];
    uint64_t reservation_not_after;
    uint64_t effect_deadline;
    uint8_t complete;
    int active_same;
    if (eng == NULL || open_body == NULL || resp == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_memzero(resp, sizeof(*resp));
    if (open_len < 16u) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    x = xfer_ptr(eng);
    active_same =
        x->occupied != 0u && x->role == 2u && x->terminal == 0u &&
        ninlil_mfdt_v1_memeq(
            x->transfer_id, open_body, 16u);
    /* NRC1 lookup BEFORE any mutation */
    hit = nrc1_try_hit(eng, open_body, request_id, NINLIL_MFDT_V1_MSG_OPEN,
                       open_body, open_len, resp);
    if (hit == 1) {
        return NINLIL_MFDT_V1_OK;
    }
    if (hit < 0) {
        return hit;
    }
    /*
     * An already-active transfer whose durable clock epoch no longer
     * matches this process is terminally fenced by the triggering request.
     * The replay lookup above must win first: an immutable response already
     * committed for this RID is never replaced by the epoch fence.
     */
    if (active_same != 0 && open_len >= 52u) {
        rc = fence_request_if_local_epoch_changed(
            eng, x, NINLIL_MFDT_V1_MSG_OPEN,
            open_body, open_len, request_id, resp);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc;
        }
    }
    rc = policy_ok(eng);
    if (rc != NINLIL_MFDT_V1_OK) {
        ninlil_mfdt_v1_geometry_t rejected_geo;
        if (validate_open_body(
                open_body, open_len, &rejected_geo) ==
            NINLIL_MFDT_V1_OK) {
            if (active_same != 0) {
                return commit_active_reject(
                    eng, x, NINLIL_MFDT_V1_MSG_OPEN,
                    open_body, open_len, request_id,
                    NINLIL_MFDT_V1_REJ_UNSUPPORTED, 0u, resp);
            }
            fill_reject_for_open_bind(
                open_body, NINLIL_MFDT_V1_REJ_UNSUPPORTED, 0u, resp);
        }
        return rc;
    }
    rc = validate_open_body(open_body, open_len, &geo);
    if (rc != NINLIL_MFDT_V1_OK) {
        if (active_same != 0 && open_len >= 52u) {
            return commit_active_reject(
                eng, x, NINLIL_MFDT_V1_MSG_OPEN,
                open_body, open_len, request_id,
                rc == NINLIL_MFDT_V1_ERR_DIGEST
                    ? NINLIL_MFDT_V1_REJ_DIGEST
                    : NINLIL_MFDT_V1_REJ_LAYOUT,
                0u, resp);
        }
        if (open_len >= 234u && !is_zero16(open_body) &&
            ninlil_mfdt_v1_get_u32(open_body + 16) != 0u &&
            !is_zero32(open_body + 202)) {
            fill_reject_for_open_bind(
                open_body,
                rc == NINLIL_MFDT_V1_ERR_DIGEST
                    ? NINLIL_MFDT_V1_REJ_DIGEST
                    : NINLIL_MFDT_V1_REJ_LAYOUT,
                0u, resp);
        }
        return rc;
    }
    if (is_zero16(eng->cfg.local_clock_epoch.bytes)) {
        if (active_same != 0) {
            return commit_active_reject(
                eng, x, NINLIL_MFDT_V1_MSG_OPEN,
                open_body, open_len, request_id,
                NINLIL_MFDT_V1_REJ_STATE, 0u, resp);
        }
        fill_reject_for_open_bind(
            open_body, NINLIL_MFDT_V1_REJ_STATE, 0u, resp);
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (eng->cfg.now_ms > UINT64_MAX - NINLIL_MFDT_V1_RESERVATION_MS) {
        if (active_same != 0) {
            return commit_active_reject(
                eng, x, NINLIL_MFDT_V1_MSG_OPEN,
                open_body, open_len, request_id,
                NINLIL_MFDT_V1_REJ_EXPIRED, 0u, resp);
        }
        fill_reject_for_open_bind(
            open_body, NINLIL_MFDT_V1_REJ_EXPIRED, 0u, resp);
        return NINLIL_MFDT_V1_ERR_EXPIRED;
    }
    reservation_not_after =
        eng->cfg.now_ms + NINLIL_MFDT_V1_RESERVATION_MS;
    effect_deadline = ninlil_mfdt_v1_get_u64(open_body + 194);
    if (!is_zero16(open_body + 178)) {
        if (!ninlil_mfdt_v1_memeq(open_body + 178,
                                  eng->cfg.local_clock_epoch.bytes, 16u)) {
            if (active_same != 0) {
                return commit_active_reject(
                    eng, x, NINLIL_MFDT_V1_MSG_OPEN,
                    open_body, open_len, request_id,
                    NINLIL_MFDT_V1_REJ_STATE, 0u, resp);
            }
            fill_reject_for_open_bind(
                open_body, NINLIL_MFDT_V1_REJ_STATE, 0u, resp);
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        if (effect_deadline <= eng->cfg.now_ms) {
            if (active_same != 0) {
                if (expired_now(eng, x)) {
                    return commit_expired_request_reject(
                        eng, x, NINLIL_MFDT_V1_MSG_OPEN,
                        open_body, open_len, request_id, resp);
                }
                return commit_active_reject(
                    eng, x, NINLIL_MFDT_V1_MSG_OPEN,
                    open_body, open_len, request_id,
                    NINLIL_MFDT_V1_REJ_EXPIRED, 0u, resp);
            }
            fill_reject_for_open_bind(
                open_body, NINLIL_MFDT_V1_REJ_EXPIRED, 0u, resp);
            return NINLIL_MFDT_V1_ERR_EXPIRED;
        }
        if (effect_deadline < reservation_not_after) {
            reservation_not_after = effect_deadline;
        }
    }
    (void)memcpy(md, open_body + 202, 32u); /* exact digest offset 202 */
    if (x->occupied && !x->terminal &&
        !ninlil_mfdt_v1_memeq(x->transfer_id, open_body, 16u)) {
        /*
         * A single engine has exactly one transfer slot in both profiles.
         * In particular, never synthesize an OPEN_ACCEPT by combining the
         * incumbent reservation with a different transfer's manifest.
         */
        resp->message_type = NINLIL_MFDT_V1_MSG_BUSY;
        resp->reject_code = NINLIL_MFDT_V1_REJ_CAPACITY;
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    if (!x->occupied || x->terminal) {
        if (eng->slot_layout != 0u) {
            eng->slot_record_packed = 0u;
            ninlil_mfdt_v1_memzero(
                eng->slot_record_memory,
                NINLIL_MFDT_V1_ACTIVE_VALUE_MAX + 1u);
            ninlil_mfdt_v1_memzero(
                eng->slot_open_staging, MFDT_WS_OPEN_MAX);
            ninlil_mfdt_v1_memzero(
                eng->slot_entries_staging,
                (size_t)NINLIL_MFDT_V1_MAX_CHUNKS *
                    NINLIL_MFDT_V1_ENTRY_BYTES);
        }
        ninlil_mfdt_v1_memzero(x, sizeof(*x));
        (void)memcpy(x->transfer_id, open_body, 16u);
        x->occupied = 1u;
        x->role = 2u;
        x->state_code = NINLIL_MFDT_V1_R_RESERVED_OPEN;
        x->retry_budget = NINLIL_MFDT_V1_RETRY_BUDGET_MAX;
        x->chunk_count = geo.chunk_count;
        x->page_count = geo.page_count;
        x->total_length = geo.total_length;
        x->record_generation = 1u;
        x->revision = ninlil_mfdt_v1_get_u32(open_body + 16);
        x->open_len = open_len;
        (void)memcpy(open_ptr(eng), open_body, open_len);
        (void)memcpy(x->whole_digest, open_body + 32, 32u);
        (void)memcpy(x->manifest_digest, md, 32u);
        /* zero content/entries until pages/chunks FULL */
        ninlil_mfdt_v1_memzero(content_ptr(eng), NINLIL_MFDT_V1_MAX_CONTENT);
        ninlil_mfdt_v1_memzero(entries_ptr(eng), 40u * 37u);
        (void)memcpy(res_id, open_body, 16u);
        (void)memcpy(res_epoch, eng->cfg.local_clock_epoch.bytes, 16u);
        (void)memcpy(x->reservation_id, res_id, 16u);
        (void)memcpy(x->res_epoch, res_epoch, 16u);
        x->not_after_ms = reservation_not_after;
        if (geo.total_length == 0u) {
            x->state_code = NINLIL_MFDT_V1_R_CONTENT_VERIFIED;
            x->publication_state = 1u;
            {
                uint8_t ev[16];
                ninlil_mfdt_v1_memzero(ev, 16u);
                ev[0] = 0xd0u;
                (void)memcpy(x->evidence_id, ev, 16u);
                ninlil_mfdt_v1_publication_token(
                    x->transfer_id, x->revision, x->manifest_digest,
                    x->whole_digest, 0u, ev, x->publication_token);
            }
            x->acceptance_record_generation = x->record_generation;
            acceptance_digest(x, x->acceptance_record_generation,
                              x->acceptance_record_digest);
            eng->publication_ready = 1u;
            (void)memcpy(eng->publication_token, x->publication_token, 16u);
        }
        eng->active_count = 1u;
        complete = (geo.total_length == 0u) ? 1u : 0u;
        rc = ninlil_mfdt_v1_encode_open_accept(
            x->transfer_id, x->revision, md, res_id, geo.total_length, res_epoch,
            x->not_after_ms, complete, accept, &alen);
        if (rc != NINLIL_MFDT_V1_OK) {
            restore_active_from_durable(eng, x);
            return rc;
        }
        return commit_resp_with_active(
            eng, x, 1, NINLIL_MFDT_V1_MSG_OPEN, open_body, open_len, request_id,
            NINLIL_MFDT_V1_MSG_OPEN_ACCEPT, accept, alen, resp);
    }
    /* same transfer late path */
    complete = (x->total_length == 0u) ? 1u : 0u;
    rc = ninlil_mfdt_v1_encode_open_accept(
        x->transfer_id, x->revision, md, x->reservation_id, x->total_length,
        x->res_epoch, x->not_after_ms, complete, accept, &alen);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    return commit_resp_with_active(eng, x, 0, NINLIL_MFDT_V1_MSG_OPEN, open_body,
                                   open_len, request_id,
                                   NINLIL_MFDT_V1_MSG_OPEN_ACCEPT, accept, alen,
                                   resp);
}

int ninlil_mfdt_v1_receiver_on_page(ninlil_mfdt_v1_engine_t *eng,
                                    const uint8_t *page_body, uint16_t page_len,
                                    uint64_t request_id,
                                    ninlil_mfdt_v1_response_t *resp)
{
    mfdt_xfer_t *x;
    uint16_t page_index;
    uint16_t count;
    uint16_t first;
    uint8_t acc[108];
    uint16_t alen = 0u;
    uint8_t page_dig[32];
    uint8_t complete;
    uint8_t expected_page[1024];
    uint16_t expected_page_len = 0u;
    uint16_t expected_first;
    uint16_t expected_count;
    uint8_t saved_entries[NINLIL_MFDT_V1_ENTRIES_PER_PAGE *
                          NINLIL_MFDT_V1_ENTRY_BYTES];
    uint8_t prior_page_bitmap;
    uint8_t prior_state;
    int hit;
    int rc;
    int mutate_active;
    uint16_t received;
    uint8_t pb;
    if (eng == NULL || page_body == NULL || resp == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_memzero(resp, sizeof(*resp));
    x = xfer_ptr(eng);
    if (!x->occupied || x->role != 2u || x->terminal) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (page_len < 52u) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    /* NRC1 first — no RAM mutation on hit */
    hit = nrc1_try_hit(eng, x->transfer_id, request_id,
                       NINLIL_MFDT_V1_MSG_MANIFEST_PAGE, page_body, page_len,
                       resp);
    if (hit == 1) {
        return NINLIL_MFDT_V1_OK;
    }
    if (hit < 0) {
        return hit;
    }
    rc = fence_request_if_local_epoch_changed(
        eng, x, NINLIL_MFDT_V1_MSG_MANIFEST_PAGE,
        page_body, page_len, request_id, resp);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    if (page_len < 92u) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_MANIFEST_PAGE,
            page_body, page_len, request_id,
            NINLIL_MFDT_V1_REJ_LAYOUT, 0u, resp);
    }
    if (expired_now(eng, x) &&
        x->state_code < NINLIL_MFDT_V1_R_CONTENT_VERIFIED) {
        return commit_expired_request_reject(
            eng, x, NINLIL_MFDT_V1_MSG_MANIFEST_PAGE,
            page_body, page_len, request_id, resp);
    }
    if (!ninlil_mfdt_v1_memeq(page_body, x->transfer_id, 16u) ||
        ninlil_mfdt_v1_get_u32(page_body + 16) != x->revision ||
        !ninlil_mfdt_v1_memeq(page_body + 20, x->manifest_digest, 32u)) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_MANIFEST_PAGE,
            page_body, page_len, request_id,
            NINLIL_MFDT_V1_REJ_DIGEST, 0u, resp);
    }
    page_index = ninlil_mfdt_v1_get_u16(page_body + 52);
    count = ninlil_mfdt_v1_get_u16(page_body + 58);
    first = ninlil_mfdt_v1_get_u16(page_body + 56);
    expected_first =
        (uint16_t)(page_index * NINLIL_MFDT_V1_ENTRIES_PER_PAGE);
    expected_count = page_index < x->page_count
                         ? (uint16_t)(x->chunk_count - expected_first)
                         : 0u;
    if (expected_count > NINLIL_MFDT_V1_ENTRIES_PER_PAGE) {
        expected_count = NINLIL_MFDT_V1_ENTRIES_PER_PAGE;
    }
    if (page_index >= x->page_count || count == 0u ||
        ninlil_mfdt_v1_get_u16(page_body + 54) != x->page_count ||
        first != expected_first || count != expected_count ||
        page_len != (uint16_t)(92u + count * 40u)) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_MANIFEST_PAGE,
            page_body, page_len, request_id,
            NINLIL_MFDT_V1_REJ_LAYOUT, 0u, resp);
    }
    rc = ninlil_mfdt_v1_encode_page(
        x->transfer_id, x->revision, x->manifest_digest, page_index,
        x->page_count, first, count, page_body + 92, expected_page,
        &expected_page_len);
    if (rc != NINLIL_MFDT_V1_OK || expected_page_len != page_len ||
        !ninlil_mfdt_v1_memeq(expected_page, page_body, page_len)) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_MANIFEST_PAGE,
            page_body, page_len, request_id,
            NINLIL_MFDT_V1_REJ_DIGEST, 0u, resp);
    }
    prior_page_bitmap = x->page_bitmap;
    prior_state = x->state_code;
    mutate_active =
        (x->page_bitmap & (uint8_t)(1u << page_index)) == 0u ? 1 : 0;
    if (mutate_active == 0 &&
        !ninlil_mfdt_v1_memeq(entries_ptr(eng) + (size_t)first * 40u,
                              page_body + 92, (size_t)count * 40u)) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_MANIFEST_PAGE,
            page_body, page_len, request_id,
            NINLIL_MFDT_V1_REJ_DIGEST, 0u, resp);
    }
    /* store entries into durable image */
    (void)memcpy(saved_entries, entries_ptr(eng) + (size_t)first * 40u,
                 (size_t)count * 40u);
    (void)memcpy(entries_ptr(eng) + (size_t)first * 40u, page_body + 92,
                 (size_t)count * 40u);
    if (page_index < 8u) {
        x->page_bitmap = (uint8_t)(x->page_bitmap | (uint8_t)(1u << page_index));
    }
    complete = (x->page_bitmap == (uint8_t)((1u << x->page_count) - 1u)) ? 1u : 0u;
    if (complete) {
        uint8_t recomputed_manifest[32];
        ninlil_mfdt_v1_manifest_digest(
            open_ptr(eng), open_ptr(eng) + 234u,
            open_ptr(eng) + NINLIL_MFDT_V1_OPEN_TEXT_OFFSET,
            (uint16_t)(x->open_len - NINLIL_MFDT_V1_OPEN_TEXT_OFFSET),
            entries_ptr(eng), x->chunk_count, recomputed_manifest);
        if (!ninlil_mfdt_v1_memeq(recomputed_manifest, x->manifest_digest,
                                  32u)) {
            (void)memcpy(entries_ptr(eng) + (size_t)first * 40u,
                         saved_entries, (size_t)count * 40u);
            x->page_bitmap = prior_page_bitmap;
            x->state_code = prior_state;
            return commit_active_reject(
                eng, x, NINLIL_MFDT_V1_MSG_MANIFEST_PAGE,
                page_body, page_len, request_id,
                NINLIL_MFDT_V1_REJ_DIGEST, 0u, resp);
        }
        x->state_code = NINLIL_MFDT_V1_R_MANIFEST_ACCEPTED;
    } else {
        x->state_code = NINLIL_MFDT_V1_R_MANIFEST_PARTIAL;
    }
    if (mutate_active != 0) {
        x->record_generation += 1u;
    }
    (void)memcpy(page_dig, page_body + 60, 32u);
    received = 0u;
    pb = x->page_bitmap;
    while (pb != 0u) {
        received = (uint16_t)(received + (pb & 1u));
        pb = (uint8_t)(pb >> 1);
    }
    rc = ninlil_mfdt_v1_encode_page_accept(
        x->transfer_id, x->revision, x->manifest_digest, page_index, received,
        page_dig, x->reservation_id, complete, acc, &alen);
    if (rc != NINLIL_MFDT_V1_OK) {
        if (mutate_active != 0) {
            (void)memcpy(entries_ptr(eng) + (size_t)first * 40u,
                         saved_entries, (size_t)count * 40u);
            x->page_bitmap = prior_page_bitmap;
            x->state_code = prior_state;
            x->record_generation -= 1u;
        }
        return rc;
    }
    return commit_resp_with_active(
        eng, x, mutate_active, NINLIL_MFDT_V1_MSG_MANIFEST_PAGE, page_body,
        page_len, request_id, NINLIL_MFDT_V1_MSG_PAGE_ACCEPT, acc, alen, resp);
}

int ninlil_mfdt_v1_receiver_on_chunk(ninlil_mfdt_v1_engine_t *eng,
                                     const uint8_t *offer_body, uint16_t offer_len,
                                     uint64_t request_id,
                                     ninlil_mfdt_v1_response_t *resp)
{
    mfdt_xfer_t *x;
    uint16_t idx;
    uint16_t clen;
    uint32_t off;
    const uint8_t *payload;
    uint8_t dig[32];
    uint8_t claimed[32];
    uint8_t acc[88];
    uint8_t saved_chunk[NINLIL_MFDT_V1_CHUNK_SIZE];
    uint16_t alen = 0u;
    const uint8_t *entry;
    uint8_t prior_state = 0u;
    uint64_t prior_bitmap = 0ull;
    int hit;
    int rc;
    int mutate_active = 0;
    if (eng == NULL || offer_body == NULL || resp == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_memzero(resp, sizeof(*resp));
    x = xfer_ptr(eng);
    if (!x->occupied || x->role != 2u || x->terminal) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (offer_len < 52u) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    /* NRC1 lookup BEFORE mutation */
    hit = nrc1_try_hit(eng, x->transfer_id, request_id,
                       NINLIL_MFDT_V1_MSG_CHUNK_OFFER, offer_body, offer_len,
                       resp);
    if (hit == 1) {
        return NINLIL_MFDT_V1_OK;
    }
    if (hit < 0) {
        return hit;
    }
    rc = fence_request_if_local_epoch_changed(
        eng, x, NINLIL_MFDT_V1_MSG_CHUNK_OFFER,
        offer_body, offer_len, request_id, resp);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    if (offer_len < 96u) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_CHUNK_OFFER,
            offer_body, offer_len, request_id,
            NINLIL_MFDT_V1_REJ_LAYOUT, 0u, resp);
    }
    if (expired_now(eng, x) &&
        x->state_code < NINLIL_MFDT_V1_R_CONTENT_VERIFIED) {
        return commit_expired_request_reject(
            eng, x, NINLIL_MFDT_V1_MSG_CHUNK_OFFER,
            offer_body, offer_len, request_id, resp);
    }
    if (x->state_code < NINLIL_MFDT_V1_R_MANIFEST_ACCEPTED &&
        x->page_count > 0u) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_CHUNK_OFFER,
            offer_body, offer_len, request_id,
            NINLIL_MFDT_V1_REJ_STATE, 0u, resp);
    }
    if (!ninlil_mfdt_v1_memeq(offer_body, x->transfer_id, 16u) ||
        ninlil_mfdt_v1_get_u32(offer_body + 16) != x->revision ||
        !ninlil_mfdt_v1_memeq(offer_body + 20, x->manifest_digest, 32u)) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_CHUNK_OFFER,
            offer_body, offer_len, request_id,
            NINLIL_MFDT_V1_REJ_DIGEST, 0u, resp);
    }
    idx = ninlil_mfdt_v1_get_u16(offer_body + 52);
    if (idx >= x->chunk_count ||
        ninlil_mfdt_v1_get_u16(offer_body + 54) != x->chunk_count) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_CHUNK_OFFER,
            offer_body, offer_len, request_id,
            NINLIL_MFDT_V1_REJ_LAYOUT, 0u, resp);
    }
    clen = ninlil_mfdt_v1_get_u16(offer_body + 60);
    payload = offer_body + 96;
    off = (uint32_t)idx * NINLIL_MFDT_V1_CHUNK_SIZE;
    if (clen == 0u || clen > NINLIL_MFDT_V1_CHUNK_SIZE ||
        offer_len != (uint16_t)(96u + clen) ||
        ninlil_mfdt_v1_get_u32(offer_body + 56) != off ||
        ninlil_mfdt_v1_get_u16(offer_body + 62) != 0u ||
        off > x->total_length || (uint32_t)clen > x->total_length - off) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_CHUNK_OFFER,
            offer_body, offer_len, request_id,
            NINLIL_MFDT_V1_REJ_LAYOUT, 0u, resp);
    }
    (void)memcpy(claimed, offer_body + 64, 32u);
    ninlil_mfdt_v1_sha256(payload, clen, dig);
    if (!ninlil_mfdt_v1_memeq(dig, claimed, 32u)) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_CHUNK_OFFER,
            offer_body, offer_len, request_id,
            NINLIL_MFDT_V1_REJ_DIGEST, 0u, resp);
    }
    /* Manifest commit check: entry digest must match offer */
    entry = entries_ptr(eng) + (size_t)idx * 40u;
    if (!ninlil_mfdt_v1_memeq(entry + 8, dig, 32u) ||
        ninlil_mfdt_v1_get_u16(entry + 0) != idx ||
        ninlil_mfdt_v1_get_u16(entry + 2) != clen ||
        ninlil_mfdt_v1_get_u32(entry + 4) != off) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_CHUNK_OFFER,
            offer_body, offer_len, request_id,
            NINLIL_MFDT_V1_REJ_DIGEST, 0u, resp);
    }
    if ((x->chunk_bitmap & ((uint64_t)1u << idx)) != 0u) {
        if (!ninlil_mfdt_v1_memeq(content_ptr(eng) + off, payload, clen)) {
            return commit_active_reject(
                eng, x, NINLIL_MFDT_V1_MSG_CHUNK_OFFER,
                offer_body, offer_len, request_id,
                NINLIL_MFDT_V1_REJ_DIGEST, 0u, resp);
        }
    } else {
        prior_state = x->state_code;
        prior_bitmap = x->chunk_bitmap;
        (void)memcpy(saved_chunk, content_ptr(eng) + off, clen);
        (void)memcpy(content_ptr(eng) + off, payload, clen);
        x->chunk_bitmap |= (uint64_t)1u << idx;
        x->state_code = NINLIL_MFDT_V1_R_CHUNKS_PARTIAL;
        mutate_active = 1;
    }
    if (x->chunk_count == 0u ||
        x->chunk_bitmap == (((uint64_t)1u << x->chunk_count) - 1u)) {
        uint8_t whole[32];
        ninlil_mfdt_v1_sha256(content_ptr(eng), x->total_length, whole);
        if (!ninlil_mfdt_v1_memeq(whole, x->whole_digest, 32u)) {
            if (mutate_active != 0) {
                (void)memcpy(content_ptr(eng) + off, saved_chunk, clen);
                x->chunk_bitmap = prior_bitmap;
                x->state_code = prior_state;
            }
            return commit_active_reject(
                eng, x, NINLIL_MFDT_V1_MSG_CHUNK_OFFER,
                offer_body, offer_len, request_id,
                NINLIL_MFDT_V1_REJ_DIGEST, 0u, resp);
        }
        if (x->publication_state == 0u) {
            x->state_code = NINLIL_MFDT_V1_R_CONTENT_VERIFIED;
            x->publication_state = 1u;
            {
                uint8_t ev[16];
                ninlil_mfdt_v1_memzero(ev, 16u);
                ev[0] = 0xd0u;
                (void)memcpy(x->evidence_id, ev, 16u);
                ninlil_mfdt_v1_publication_token(
                    x->transfer_id, x->revision, x->manifest_digest, whole,
                    x->total_length, ev, x->publication_token);
            }
            x->acceptance_record_generation = x->record_generation + 1u;
            acceptance_digest(x, x->acceptance_record_generation,
                              x->acceptance_record_digest);
            mutate_active = 1;
        }
        eng->publication_ready = 1u;
        (void)memcpy(eng->publication_token, x->publication_token, 16u);
    }
    if (mutate_active != 0) {
        x->record_generation += 1u;
    }
    rc = ninlil_mfdt_v1_encode_chunk_accept(x->transfer_id, x->revision,
                                            x->manifest_digest, idx, dig, acc,
                                            &alen);
    if (rc != NINLIL_MFDT_V1_OK) {
        if (mutate_active != 0) {
            restore_active_from_durable(eng, x);
        }
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    return commit_resp_with_active(
        eng, x, mutate_active, NINLIL_MFDT_V1_MSG_CHUNK_OFFER, offer_body,
        offer_len,
        request_id, NINLIL_MFDT_V1_MSG_CHUNK_ACCEPT, acc, alen, resp);
}

int ninlil_mfdt_v1_receiver_on_finalize(ninlil_mfdt_v1_engine_t *eng,
                                        const uint8_t *fin_body, uint16_t fin_len,
                                        uint64_t request_id,
                                        ninlil_mfdt_v1_response_t *resp)
{
    mfdt_xfer_t *x;
    uint8_t acc[160];
    uint16_t alen = 0u;
    uint8_t whole[32];
    int hit;
    int rc;
    int mutate_active;
    if (eng == NULL || fin_body == NULL || resp == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_memzero(resp, sizeof(*resp));
    x = xfer_ptr(eng);
    if (!x->occupied || x->role != 2u || x->terminal) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (fin_len < 52u) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    hit = nrc1_try_hit(eng, x->transfer_id, request_id, NINLIL_MFDT_V1_MSG_FINALIZE,
                       fin_body, fin_len, resp);
    if (hit == 1) {
        return NINLIL_MFDT_V1_OK;
    }
    if (hit < 0) {
        return hit;
    }
    rc = fence_request_if_local_epoch_changed(
        eng, x, NINLIL_MFDT_V1_MSG_FINALIZE,
        fin_body, fin_len, request_id, resp);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    if (fin_len != 92u) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_FINALIZE,
            fin_body, fin_len, request_id,
            NINLIL_MFDT_V1_REJ_LAYOUT, 0u, resp);
    }
    if (x->state_code < NINLIL_MFDT_V1_R_CONTENT_VERIFIED) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_FINALIZE,
            fin_body, fin_len, request_id,
            NINLIL_MFDT_V1_REJ_STATE, 0u, resp);
    }
    if (!accept_bind52_ok(fin_body, fin_len, x) ||
        ninlil_mfdt_v1_get_u32(fin_body + 84) != x->total_length ||
        ninlil_mfdt_v1_get_u32(fin_body + 88) != 0u) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_FINALIZE,
            fin_body, fin_len, request_id,
            NINLIL_MFDT_V1_REJ_LAYOUT, 0u, resp);
    }
    (void)memcpy(whole, fin_body + 52, 32u);
    if (!ninlil_mfdt_v1_memeq(whole, x->whole_digest, 32u)) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_FINALIZE,
            fin_body, fin_len, request_id,
            NINLIL_MFDT_V1_REJ_DIGEST, 0u, resp);
    }
    if (x->acceptance_record_generation == 0ull ||
        is_zero16(x->evidence_id) ||
        is_zero32(x->acceptance_record_digest)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    mutate_active = x->accept_notified == 0u ? 1 : 0;
    if (mutate_active != 0) {
        x->state_code = NINLIL_MFDT_V1_R_ACCEPT_NOTIFIED;
        x->accept_notified = 1u;
        x->record_generation += 1u;
    }
    rc = ninlil_mfdt_v1_encode_transfer_accept(
        x->transfer_id, x->revision, x->manifest_digest, x->whole_digest,
        x->total_length, x->evidence_id, x->acceptance_record_generation,
        x->reservation_id, x->acceptance_record_digest, acc, &alen);
    if (rc != NINLIL_MFDT_V1_OK) {
        if (mutate_active != 0) {
            restore_active_from_durable(eng, x);
        }
        return rc;
    }
    return commit_resp_with_active(
        eng, x, mutate_active, NINLIL_MFDT_V1_MSG_FINALIZE, fin_body, fin_len,
        request_id, NINLIL_MFDT_V1_MSG_TRANSFER_ACCEPT, acc, alen, resp);
}

int ninlil_mfdt_v1_receiver_on_resume(ninlil_mfdt_v1_engine_t *eng,
                                      const uint8_t *query_body, uint16_t query_len,
                                      uint64_t request_id,
                                      ninlil_mfdt_v1_response_t *resp)
{
    mfdt_xfer_t *x;
    uint32_t qgen;
    uint8_t st[108];
    uint8_t dig[32];
    int hit;
    int mutate_active;
    if (eng == NULL || query_body == NULL || resp == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_memzero(resp, sizeof(*resp));
    x = xfer_ptr(eng);
    if (!x->occupied || x->role != 2u || x->terminal) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (query_len < 52u) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    hit = nrc1_try_hit(eng, x->transfer_id, request_id,
                       NINLIL_MFDT_V1_MSG_RESUME_QUERY, query_body, query_len,
                       resp);
    if (hit == 1) {
        return NINLIL_MFDT_V1_OK;
    }
    if (hit < 0) {
        return hit;
    }
    {
        const int epoch_rc =
            fence_request_if_local_epoch_changed(
                eng, x, NINLIL_MFDT_V1_MSG_RESUME_QUERY,
                query_body, query_len, request_id, resp);
        if (epoch_rc != NINLIL_MFDT_V1_OK) {
            return epoch_rc;
        }
    }
    if (query_len != 60u) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_RESUME_QUERY,
            query_body, query_len, request_id,
            NINLIL_MFDT_V1_REJ_LAYOUT, 0u, resp);
    }
    if (!accept_bind52_ok(query_body, query_len, x) ||
        ninlil_mfdt_v1_get_u32(query_body + 56) != 0u) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_RESUME_QUERY,
            query_body, query_len, request_id,
            NINLIL_MFDT_V1_REJ_LAYOUT, 0u, resp);
    }
    qgen = ninlil_mfdt_v1_get_u32(query_body + 52);
    /* reject zero, gap, >8, rollback */
    if (qgen == 0u || qgen > NINLIL_MFDT_V1_RESUME_MAX) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_RESUME_QUERY,
            query_body, query_len, request_id,
            NINLIL_MFDT_V1_REJ_STATE, 0u, resp);
    }
    if (qgen < x->last_resume_gen) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_RESUME_QUERY,
            query_body, query_len, request_id,
            NINLIL_MFDT_V1_REJ_STATE, 0u, resp);
    }
    if (qgen > x->last_resume_gen + 1u) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_RESUME_QUERY,
            query_body, query_len, request_id,
            NINLIL_MFDT_V1_REJ_STATE, 0u, resp);
    }
    mutate_active = qgen > x->last_resume_gen ? 1 : 0;
    if (mutate_active != 0) {
        x->last_resume_gen = qgen;
        x->record_generation += 1u;
    }
    ninlil_mfdt_v1_memzero(st, sizeof(st));
    ninlil_mfdt_v1_bind52(x->transfer_id, x->revision, x->manifest_digest, st);
    ninlil_mfdt_v1_put_u32(st + 52, qgen);
    ninlil_mfdt_v1_put_u64(st + 56, x->record_generation);
    ninlil_mfdt_v1_put_u64(st + 64, x->chunk_bitmap);
    ninlil_mfdt_v1_put_u16(st + 72, x->state_code);
    {
        uint8_t dom[16 + 76];
        (void)memcpy(dom, "NM3-RESUME-V1", 13u);
        (void)memcpy(dom + 13, st, 76u);
        ninlil_mfdt_v1_sha256(dom, 13u + 76u, dig);
    }
    (void)memcpy(st + 76, dig, 32u);
    return commit_resp_with_active(
        eng, x, mutate_active, NINLIL_MFDT_V1_MSG_RESUME_QUERY, query_body,
        query_len, request_id, NINLIL_MFDT_V1_MSG_RESUME_STATE, st, 108u,
        resp);
}

int ninlil_mfdt_v1_receiver_on_abort(ninlil_mfdt_v1_engine_t *eng,
                                     const uint8_t *abort_body, uint16_t abort_len,
                                     uint64_t request_id,
                                     ninlil_mfdt_v1_response_t *resp)
{
    mfdt_xfer_t *x;
    uint8_t ack[92];
    uint8_t nm30[NINLIL_MFDT_V1_NM30_BYTES];
    uint8_t observed_nm30[NINLIL_MFDT_V1_NM30_BYTES];
    uint8_t tombstone_digest[32];
    uint8_t request_digest[32];
    uint8_t *nblob = engine_nrc1_scratch(eng);
    uint8_t akey[20];
    uint8_t tkey[20];
    uint8_t nkey[20];
    uint32_t observed_len = 0u;
    uint16_t reason;
    uint32_t generation;
    int present = 0;
    int hit;
    int rc;
    if (eng == NULL || abort_body == NULL || resp == NULL || nblob == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_memzero(resp, sizeof(*resp));
    x = xfer_ptr(eng);
    if (!x->occupied || x->role != 2u || x->terminal) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (abort_len < 52u) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    hit = nrc1_try_hit(eng, x->transfer_id, request_id, NINLIL_MFDT_V1_MSG_ABORT,
                       abort_body, abort_len, resp);
    if (hit == 1) {
        return NINLIL_MFDT_V1_OK;
    }
    if (hit < 0) {
        return hit;
    }
    rc = fence_request_if_local_epoch_changed(
        eng, x, NINLIL_MFDT_V1_MSG_ABORT,
        abort_body, abort_len, request_id, resp);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    if (abort_len != 76u || !accept_bind52_ok(abort_body, abort_len, x) ||
        ninlil_mfdt_v1_get_u16(abort_body + 54) != 0u ||
        is_zero16(abort_body + 56)) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_ABORT,
            abort_body, abort_len, request_id,
            NINLIL_MFDT_V1_REJ_LAYOUT, 0u, resp);
    }
    reason = ninlil_mfdt_v1_get_u16(abort_body + 52);
    generation = ninlil_mfdt_v1_get_u32(abort_body + 72);
    if (reason < NINLIL_MFDT_V1_TERM_REASON_OPERATOR ||
        reason > NINLIL_MFDT_V1_TERM_REASON_POLICY ||
        generation == 0u || generation > NINLIL_MFDT_V1_ABORT_GEN_MAX) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_ABORT,
            abort_body, abort_len, request_id,
            NINLIL_MFDT_V1_REJ_AUTHORITY, 0u, resp);
    }
    if (x->state_code >= NINLIL_MFDT_V1_R_CONTENT_VERIFIED) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_ABORT,
            abort_body, abort_len, request_id,
            NINLIL_MFDT_V1_REJ_ABORT_DENIED, 0u, resp);
    }
    if (generation != x->abort_generation + 1u) {
        return commit_active_reject(
            eng, x, NINLIL_MFDT_V1_MSG_ABORT,
            abort_body, abort_len, request_id,
            NINLIL_MFDT_V1_REJ_STATE, 0u, resp);
    }

    rc = build_nm30(
        nm30, eng, x, NINLIL_MFDT_V1_TERM_ABORTED, reason, generation,
        NULL, NULL,
        abort_body + 56, eng->cfg.local_clock_epoch.bytes, eng->cfg.now_ms);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    ninlil_mfdt_v1_sha256(nm30, NINLIL_MFDT_V1_NM30_BYTES,
                          tombstone_digest);
    ninlil_mfdt_v1_memzero(ack, sizeof(ack));
    ninlil_mfdt_v1_bind52(x->transfer_id, x->revision, x->manifest_digest, ack);
    ninlil_mfdt_v1_put_u32(ack + 52, generation);
    ninlil_mfdt_v1_put_u16(ack + 56, NINLIL_MFDT_V1_TERM_ABORTED);
    (void)memcpy(ack + 60, tombstone_digest, 32u);

    rc = nrc1_load(eng, x->transfer_id, nblob, &present);
    if (rc != NINLIL_MFDT_V1_OK || present == 0) {
        return rc != NINLIL_MFDT_V1_OK
                   ? rc : NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    ninlil_mfdt_v1_request_body_digest(
        NINLIL_MFDT_V1_MSG_ABORT, abort_body, abort_len, request_digest);
    rc = nrc1_insert(nblob, eng->cfg.session_generation, request_id,
                     request_digest, NINLIL_MFDT_V1_MSG_ABORT_ACK, ack,
                     (uint16_t)sizeof(ack));
    if (rc != NINLIL_MFDT_V1_OK) {
        resp->message_type = NINLIL_MFDT_V1_MSG_BUSY;
        resp->reject_code = NINLIL_MFDT_V1_REJ_CAPACITY;
        return rc;
    }
    make_key(akey, "NM3R", x->transfer_id);
    make_key(tkey, "NM30", x->transfer_id);
    make_key(nkey, "NRC1", x->transfer_id);
    rc = full_terminal_with_nrc1(
        eng, akey, tkey, nm30, NINLIL_MFDT_V1_NM30_BYTES, nkey, nblob,
        NINLIL_MFDT_V1_NRC1_VALUE_BYTES);
    if (rc != NINLIL_MFDT_V1_OK) {
        restore_active_from_durable(eng, x);
        return rc;
    }
    rc = store_get(
        eng, tkey, observed_nm30, sizeof(observed_nm30), &observed_len);
    if (rc != NINLIL_MFDT_V1_OK ||
        nm30_schema2_validate(
            observed_nm30, observed_len, x->transfer_id) !=
            NINLIL_MFDT_V1_OK ||
        !ninlil_mfdt_v1_memeq(observed_nm30, nm30, sizeof(nm30))) {
        ninlil_mfdt_v1_memzero(resp, sizeof(*resp));
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    x->abort_generation = generation;
    x->terminal = 1u;
    eng->active_count = 0u;
    eng->publication_ready = 0u;
    eng->handoff_complete = 0u;
    resp->message_type = NINLIL_MFDT_V1_MSG_ABORT_ACK;
    resp->body_len = (uint16_t)sizeof(ack);
    (void)memcpy(resp->body, ack, sizeof(ack));
    resp->state_mutation = 1u;
    resp->full_count = 1u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_receiver_publication_view(
    const ninlil_mfdt_v1_engine_t *eng, const uint8_t **content_out,
    uint32_t *content_len_out, uint8_t publication_token_out[16],
    uint64_t *acceptance_generation_out)
{
    const mfdt_xfer_t *x;
    if (eng == NULL ||
        (eng->ws == NULL && eng->slot_layout == 0u) ||
        content_out == NULL ||
        content_len_out == NULL || publication_token_out == NULL ||
        acceptance_generation_out == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    x = eng->slot_layout != 0u
            ? (const mfdt_xfer_t *)(const void *)eng->slot_xfer_memory
            : (const mfdt_xfer_t *)(const void *)eng->ws->bytes;
    if (!x->occupied || x->terminal || x->role != 2u ||
        x->publication_state == 0u ||
        x->state_code < NINLIL_MFDT_V1_R_ACCEPT_NOTIFIED ||
        x->acceptance_record_generation == 0ull ||
        is_zero16(x->publication_token)) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    *content_out = content_ptr((ninlil_mfdt_v1_engine_t *)(uintptr_t)eng);
    *content_len_out = x->total_length;
    (void)memcpy(publication_token_out, x->publication_token, 16u);
    *acceptance_generation_out = x->acceptance_record_generation;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_receiver_commit_publication(
    ninlil_mfdt_v1_engine_t *eng, const uint8_t publication_token[16],
    const uint8_t publication_evidence_digest[32])
{
    mfdt_xfer_t *x;
    mfdt_xfer_t before;
    uint8_t key[20];
    uint8_t *rec;
    uint32_t rec_len = 0u;
    int rc;
    if (eng == NULL || publication_token == NULL ||
        publication_evidence_digest == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    rec = engine_record_scratch(eng);
    if (rec == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    x = xfer_ptr(eng);
    if (!x->occupied || x->role != 2u || !eng->publication_ready) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (x->state_code < NINLIL_MFDT_V1_R_ACCEPT_NOTIFIED ||
        !ninlil_mfdt_v1_memeq(publication_token, x->publication_token, 16u) ||
        is_zero32(publication_evidence_digest)) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (x->publication_state == 2u && x->handoff_state == 1u) {
        if (!ninlil_mfdt_v1_memeq(x->publication_evidence_digest,
                                  publication_evidence_digest, 32u)) {
            return NINLIL_MFDT_V1_ERR_DIGEST;
        }
        eng->handoff_complete = 1u;
        return NINLIL_MFDT_V1_OK;
    }
    before = *x;
    x->state_code = NINLIL_MFDT_V1_R_HANDED_OFF;
    x->handoff_state = 1u;
    x->publication_state = 2u; /* PUBLISHED */
    (void)memcpy(x->publication_evidence_digest,
                 publication_evidence_digest, 32u);
    x->record_generation += 1u;
    make_key(key, "NM3R", x->transfer_id);
    rc = pack_active(eng, x, rec, &rec_len);
    if (rc != NINLIL_MFDT_V1_OK) {
        *x = before;
        return rc;
    }
    rc = full_put_active_reload_on_failure(
        eng, x, key, rec, rec_len);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    eng->handoff_complete = 1u;
    (void)memcpy(eng->upper_dedupe_token, x->publication_token, 16u);
    eng->upper_dedupe_valid = 1u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_receiver_complete_handoff(ninlil_mfdt_v1_engine_t *eng)
{
    uint8_t evidence[32];
    if (eng == NULL || !eng->publication_ready) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    /*
     * Compatibility-only lab helper. Production bearers must call
     * receiver_commit_publication with the upper durable evidence digest.
     */
    ninlil_mfdt_v1_sha256(eng->publication_token, 16u, evidence);
    return ninlil_mfdt_v1_receiver_commit_publication(
        eng, eng->publication_token, evidence);
}

int ninlil_mfdt_v1_terminal_complete(ninlil_mfdt_v1_engine_t *eng)
{
    mfdt_xfer_t *x;
    uint8_t akey[20], nkey[20];
    uint8_t nm30[NINLIL_MFDT_V1_NM30_BYTES];
    int rc;
    if (eng == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    x = xfer_ptr(eng);
    if (!x->occupied || x->terminal) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    /* Gate: receiver only after HANDOFF; sender only after ACCEPT_RX */
    if (x->role == 2u) {
        if (x->state_code != NINLIL_MFDT_V1_R_HANDED_OFF ||
            x->handoff_state != 1u) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        make_key(akey, "NM3R", x->transfer_id);
    } else if (x->role == 1u) {
        if (x->state_code != NINLIL_MFDT_V1_S_ACCEPT_RX) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        make_key(akey, "NM3S", x->transfer_id);
    } else {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    make_key(nkey, "NM30", x->transfer_id);
    rc = build_nm30(
        nm30, eng, x, NINLIL_MFDT_V1_TERM_COMPLETE,
        NINLIL_MFDT_V1_TERM_REASON_NONE, 0u, x->evidence_id,
        x->acceptance_record_digest, NULL, eng->cfg.local_clock_epoch.bytes,
        eng->cfg.now_ms);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = full_terminal(eng, akey, nkey, nm30, NINLIL_MFDT_V1_NM30_BYTES);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    x->terminal = 1u;
    eng->active_count = 0u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_retention_gc(ninlil_mfdt_v1_engine_t *eng)
{
    mfdt_xfer_t *x;
    uint8_t k30[20], kn[20];
    uint8_t nm30[NINLIL_MFDT_V1_NM30_BYTES];
    uint8_t *nrc1 = engine_nrc1_scratch(eng);
    uint32_t len = 0u;
    uint32_t nrc1_len = 0u;
    uint64_t anchor;
    uint64_t duration;
    uint64_t boundary;
    uint8_t replay_eligible;
    uint8_t terminal_peer[16];
    uint8_t terminal_role;
    int rc;
    if (eng == NULL || nrc1 == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    x = xfer_ptr(eng);
    if (is_zero16(x->transfer_id)) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    make_key(k30, "NM30", x->transfer_id);
    rc = store_get(eng, k30, nm30, sizeof(nm30), &len);
    if (rc != NINLIL_MFDT_V1_OK) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    rc = ninlil_mfdt_v1_validate_nm30_recovery_record(
        nm30, len, x->transfer_id, &replay_eligible,
        terminal_peer, &terminal_role);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    if (is_zero16(eng->cfg.local_clock_epoch.bytes) ||
        !ninlil_mfdt_v1_memeq(nm30 + 132,
                              eng->cfg.local_clock_epoch.bytes, 16u)) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    anchor = ninlil_mfdt_v1_get_u64(nm30 + 148);
    duration = eng->cfg.retention_ms;
    if (duration < NINLIL_MFDT_V1_RETENTION_MS_DEFAULT) {
        duration = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    }
    if (anchor > UINT64_MAX - duration) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    boundary = anchor + duration;
    if (eng->cfg.now_ms < anchor || eng->cfg.now_ms < boundary) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    make_key(kn, "NRC1", x->transfer_id);
    rc = store_get(
        eng, kn, nrc1, NINLIL_MFDT_V1_NRC1_VALUE_BYTES, &nrc1_len);
    if (rc != NINLIL_MFDT_V1_OK ||
        nrc1_validate(nrc1, nrc1_len, x->transfer_id) !=
            NINLIL_MFDT_V1_OK) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    rc = full_gc(eng, k30, kn);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    ninlil_mfdt_v1_memzero(x, sizeof(*x));
    eng->publication_ready = 0u;
    eng->handoff_complete = 0u;
    eng->upper_dedupe_valid = 0u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_restart_scan(ninlil_mfdt_v1_engine_t *eng)
{
    mfdt_xfer_t *x;
    uint8_t key[20];
    uint8_t other_key[20];
    uint8_t terminal_key[20];
    uint8_t nrc1_key[20];
    uint8_t nm30[NINLIL_MFDT_V1_NM30_BYTES];
    uint8_t *nrc1 = engine_nrc1_scratch(eng);
    uint32_t len = 0u;
    uint32_t other_len = 0u;
    uint32_t terminal_len = 0u;
    uint32_t nrc1_len = 0u;
    int has_active;
    int has_other_active;
    int has_terminal;
    int has_nrc1;
    int rc;
    if (eng == NULL || nrc1 == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    /* Clear volatile only; rehydrate from durable if active present. */
    eng->publication_ready = 0u;
    eng->handoff_complete = 0u;
    eng->unpaid_chunk_offer = 0u;
    x = xfer_ptr(eng);
    if (!x->occupied || is_zero16(x->transfer_id)) {
        eng->active_count = 0u;
        /* Meta empty: caller should use restart_scan_transfer(tid, role). */
        return NINLIL_MFDT_V1_OK;
    }
    make_key(key, x->role == 1u ? "NM3S" : "NM3R", x->transfer_id);
    make_key(other_key, x->role == 1u ? "NM3R" : "NM3S",
             x->transfer_id);
    make_key(terminal_key, "NM30", x->transfer_id);
    make_key(nrc1_key, "NRC1", x->transfer_id);
    has_active = store_get(
                     eng, key, NULL, 0u, &len) ==
                 NINLIL_MFDT_V1_OK;
    has_other_active = store_get(
                           eng, other_key, NULL, 0u, &other_len) ==
                       NINLIL_MFDT_V1_OK;
    has_terminal = store_get(
                       eng, terminal_key, nm30, sizeof(nm30),
                       &terminal_len) == NINLIL_MFDT_V1_OK;
    has_nrc1 = store_get(
                   eng, nrc1_key, nrc1,
                   NINLIL_MFDT_V1_NRC1_VALUE_BYTES, &nrc1_len) ==
               NINLIL_MFDT_V1_OK;
    if (has_other_active || (has_active && has_terminal) ||
        ((has_active || has_terminal) && !has_nrc1) ||
        (!has_active && !has_terminal && has_nrc1)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (has_nrc1 &&
        (nrc1_validate(nrc1, nrc1_len, x->transfer_id) !=
             NINLIL_MFDT_V1_OK ||
         ninlil_mfdt_v1_get_u32(nrc1 + 24) !=
             eng->cfg.session_generation)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (!has_active) {
        uint8_t replay_eligible;
        uint8_t terminal_peer[16];
        uint8_t terminal_role;
        if (!has_terminal ||
            ninlil_mfdt_v1_validate_nm30_recovery_record(
                nm30, terminal_len, x->transfer_id,
                &replay_eligible, terminal_peer, &terminal_role) !=
                NINLIL_MFDT_V1_OK) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        x->terminal = 1u;
        eng->active_count = 0u;
        return NINLIL_MFDT_V1_OK;
    }
    rc = load_active_from_store(eng, x);
    if (rc != NINLIL_MFDT_V1_OK) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    eng->active_count = 1u;
    x->terminal = 0u;
    rc = fence_if_local_epoch_changed(eng, x, 0u, NULL);
    if (rc != NINLIL_MFDT_V1_OK) {
        return x->terminal ? NINLIL_MFDT_V1_OK : rc;
    }
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_restart_scan_transfer(ninlil_mfdt_v1_engine_t *eng,
                                         const uint8_t transfer_id[16],
                                         uint8_t role)
{
    mfdt_xfer_t *x;
    if (eng == NULL || transfer_id == NULL || is_zero16(transfer_id)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (role != 1u && role != 2u) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if ((eng->ws == NULL && eng->slot_layout == 0u) ||
        (eng->store == NULL && eng->store_port == NULL)) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    /*
     * Seed only transfer identity into workspace meta, then load durable
     * active via restart_scan. No pipeline/process struct import.
     */
    x = xfer_ptr(eng);
    ninlil_mfdt_v1_memzero(x, sizeof(*x));
    (void)memcpy(x->transfer_id, transfer_id, 16u);
    x->occupied = 1u;
    x->role = role;
    return ninlil_mfdt_v1_restart_scan(eng);
}

int ninlil_mfdt_v1_engine_active_snapshot(
    const ninlil_mfdt_v1_engine_t *eng, ninlil_mfdt_v1_active_snapshot_t *out)
{
    const mfdt_xfer_t *x;
    if (eng == NULL || out == NULL ||
        (eng->ws == NULL && eng->slot_layout == 0u)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    x = eng->slot_layout != 0u
            ? (const mfdt_xfer_t *)(const void *)eng->slot_xfer_memory
            : (const mfdt_xfer_t *)(const void *)eng->ws->bytes;
    if (!x->occupied || is_zero16(x->transfer_id)) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    ninlil_mfdt_v1_memzero(out, sizeof(*out));
    out->role = x->role;
    out->state_code = x->state_code;
    out->page_bitmap = x->page_bitmap;
    out->publication_state = x->publication_state;
    out->page_count = x->page_count;
    out->chunk_count = x->chunk_count;
    out->total_length = x->total_length;
    out->chunk_bitmap = x->chunk_bitmap;
    out->record_generation = x->record_generation;
    out->acceptance_record_generation = x->acceptance_record_generation;
    (void)memcpy(out->transfer_id, x->transfer_id, 16u);
    (void)memcpy(out->publication_token, x->publication_token, 16u);
    (void)memcpy(out->publication_evidence_digest,
                 x->publication_evidence_digest, 32u);
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_admission_check(const ninlil_mfdt_v1_config_t *cfg)
{
    if (cfg == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (cfg->policy != NINLIL_MFDT_V1_POLICY_ON) {
        return NINLIL_MFDT_V1_ERR_POLICY_OFF;
    }
    if (cfg->mfdt_admission_version !=
        NINLIL_MFDT_V1_ADMISSION_VERSION) {
        return NINLIL_MFDT_V1_ERR_VERSION;
    }
    if (cfg->mfdt_capability == 0u ||
        cfg->session_generation == 0u) {
        return NINLIL_MFDT_V1_ERR_VERSION;
    }
    return NINLIL_MFDT_V1_OK;
}

uint8_t ninlil_mfdt_v1_retry_budget_remaining(const ninlil_mfdt_v1_engine_t *eng)
{
    const mfdt_xfer_t *x;
    if (eng == NULL || (eng->ws == NULL && eng->slot_layout == 0u)) {
        return 0u;
    }
    x = eng->slot_layout != 0u
            ? (const mfdt_xfer_t *)(const void *)eng->slot_xfer_memory
            : (const mfdt_xfer_t *)(const void *)eng->ws->bytes;
    if (!x->occupied) {
        return 0u;
    }
    return x->retry_budget;
}

int ninlil_mfdt_v1_owner_timeout_retry_charge(ninlil_mfdt_v1_engine_t *eng)
{
    mfdt_xfer_t *x;
    uint8_t key[20];
    uint8_t *rec = engine_record_scratch(eng);
    if (rec == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    uint32_t rec_len = 0u;
    int rc;
    if (eng == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    x = xfer_ptr(eng);
    if (!x->occupied || x->terminal) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (x->retry_budget == 0u) {
        return NINLIL_MFDT_V1_ERR_CAPACITY; /* exhaustion: no new-ID timeout retry */
    }
    x->retry_budget = (uint8_t)(x->retry_budget - 1u);
    x->record_generation += 1u;
    make_key(key, x->role == 1u ? "NM3S" : "NM3R", x->transfer_id);
    rc = pack_active(eng, x, rec, &rec_len);
    if (rc != NINLIL_MFDT_V1_OK) {
        restore_active_from_durable(eng, x);
        return rc;
    }
    /* G_*_RETRY_BUDGET owner FULL before wire of the new-ID request */
    return full_put_active_reload_on_failure(eng, x, key, rec, rec_len);
}

int ninlil_mfdt_v1_advance_session_generation(ninlil_mfdt_v1_engine_t *eng)
{
    mfdt_xfer_t *x;
    uint8_t *blob = engine_nrc1_scratch(eng);
    uint8_t *rec = engine_record_scratch(eng);
    uint8_t akey[20];
    uint8_t nkey[20];
    uint32_t rec_len = 0u;
    uint32_t old_generation;
    uint32_t new_generation;
    uint32_t old_last_resume;
    uint64_t old_record_generation;
    int present = 0;
    int rc;
    uint16_t i;
    uint16_t occ;
    uint8_t has_anchor = 0u;
    uint8_t has_prior_generation = 0u;
    if (eng == NULL || blob == NULL || rec == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    x = xfer_ptr(eng);
    if (!x->occupied || is_zero16(x->transfer_id)) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    /*
     * SESSION_GEN_MAX_PER_TRANSFER=2 counts distinct consecutive values; it
     * is not a numeric ceiling. UINT32_MAX cannot advance without wrap.
     */
    old_generation = eng->cfg.session_generation;
    if (old_generation == 0u || old_generation == UINT32_MAX) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    rc = nrc1_load(eng, x->transfer_id, blob, &present);
    if (rc != NINLIL_MFDT_V1_OK || present == 0 ||
        ninlil_mfdt_v1_get_u32(blob + 24) != old_generation) {
        return rc == NINLIL_MFDT_V1_OK ? NINLIL_MFDT_V1_ERR_CORRUPT : rc;
    }
    if (is_zero16(x->durable_local_epoch) ||
        !ninlil_mfdt_v1_memeq(x->durable_local_epoch,
                              eng->cfg.local_clock_epoch.bytes, 16u)) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    for (i = 0u; i < NINLIL_MFDT_V1_NRC1_SLOT_COUNT; ++i) {
        const uint8_t *s = nrc1_slot_at(blob, i);
        if (ninlil_mfdt_v1_get_u64(s + 0) == 0ull) {
            continue;
        }
        if (ninlil_mfdt_v1_get_u16(s + 44) ==
                (uint16_t)NINLIL_MFDT_V1_MSG_OPEN_ACCEPT) {
            has_anchor = 1u;
        }
        if (ninlil_mfdt_v1_get_u32(s + 8) != old_generation) {
            has_prior_generation = 1u;
        }
    }
    if (has_anchor == 0u) {
        /* Empty/sender-only cache cannot prove the transfer generation. */
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (has_prior_generation != 0u) {
        /* A prior slot proves that the one allowed advance was already used. */
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    new_generation = old_generation + 1u;
    old_last_resume = x->last_resume_gen;
    old_record_generation = x->record_generation;
    /* Reclaim prior-generation RESUME response slots only. */
    occ = ninlil_mfdt_v1_get_u16(blob + 30);
    for (i = 0; i < NINLIL_MFDT_V1_NRC1_SLOT_COUNT; ++i) {
        uint8_t *s = nrc1_slot_at(blob, i);
        uint16_t rtype = ninlil_mfdt_v1_get_u16(s + 44);
        uint32_t slot_generation = ninlil_mfdt_v1_get_u32(s + 8);
        if (ninlil_mfdt_v1_get_u64(s + 0) != 0ull &&
            slot_generation == old_generation &&
            rtype == (uint16_t)NINLIL_MFDT_V1_MSG_RESUME_STATE) {
            ninlil_mfdt_v1_memzero(
                s, NINLIL_MFDT_V1_NRC1_SLOT_BYTES);
            occ = (uint16_t)(occ - 1u);
        }
    }
    ninlil_mfdt_v1_put_u16(blob + 30, occ);
    /* No per-slot sequence is stored; canonical compaction sequence is count. */
    ninlil_mfdt_v1_put_u32(blob + 32, (uint32_t)occ);
    ninlil_mfdt_v1_put_u32(blob + 24, new_generation);
    nrc1_recompute_crc(blob);
    if (nrc1_validate(blob, NINLIL_MFDT_V1_NRC1_VALUE_BYTES,
                      x->transfer_id) != NINLIL_MFDT_V1_OK) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }

    eng->cfg.session_generation = new_generation;
    x->last_resume_gen = 0u;
    x->record_generation += 1u;
    rc = pack_active(eng, x, rec, &rec_len);
    if (rc != NINLIL_MFDT_V1_OK) {
        eng->cfg.session_generation = old_generation;
        x->last_resume_gen = old_last_resume;
        x->record_generation = old_record_generation;
        return rc;
    }
    make_key(akey, x->role == 1u ? "NM3S" : "NM3R", x->transfer_id);
    make_key(nkey, "NRC1", x->transfer_id);
    /* G_*_SESSION_GEN: active header/reset and NRC1 generation/reclaim atomic. */
    rc = full_put_active_and_nrc1(
        eng, akey, rec, rec_len, nkey, blob,
        NINLIL_MFDT_V1_NRC1_VALUE_BYTES);
    if (rc != NINLIL_MFDT_V1_OK) {
        eng->cfg.session_generation = old_generation;
        restore_active_from_durable(eng, x);
        return rc;
    }
    return NINLIL_MFDT_V1_OK;
}

ninlil_mfdt_v1_cu_class_t ninlil_mfdt_v1_cu_observe_key(
    const ninlil_mfdt_v1_lab_store_t *st, uint8_t *scratch,
    uint32_t scratch_bytes, const uint8_t key[20],
    const uint8_t *old_bytes, uint32_t old_len, int has_old,
    const uint8_t *new_bytes, uint32_t new_len, int has_new)
{
    uint32_t olen = 0u;
    int present;
    if (st == NULL || scratch == NULL ||
        scratch_bytes < NINLIL_MFDT_V1_ACTIVE_VALUE_MAX || key == NULL) {
        return NINLIL_MFDT_V1_CU_ABSENT;
    }
    present = ninlil_mfdt_v1_lab_get(
                  st, key, scratch, scratch_bytes, &olen) ==
              NINLIL_MFDT_V1_OK;
    return ninlil_mfdt_v1_classify_cu_bytes(
        scratch, olen, present, old_bytes, old_len, has_old,
        new_bytes, new_len, has_new);
}

int ninlil_mfdt_v1_on_reservation_expired(ninlil_mfdt_v1_engine_t *eng)
{
    mfdt_xfer_t *x;
    uint8_t akey[20], nkey[20];
    uint8_t nm30[NINLIL_MFDT_V1_NM30_BYTES];
    int rc;
    if (eng == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    x = xfer_ptr(eng);
    if (!x->occupied || x->terminal) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    rc = fence_if_local_epoch_changed(eng, x, 0u, NULL);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    if (x->state_code >= NINLIL_MFDT_V1_R_CONTENT_VERIFIED && x->role == 2u) {
        return NINLIL_MFDT_V1_ERR_STATE; /* content-verified not expiry-freed */
    }
    if (!expired_now(eng, x)) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    /* Mandatory G_*_EXPIRY FULL: NM30 ABORTED EXPIRED + erase active; keep NRC1 */
    make_key(akey, x->role == 1u ? "NM3S" : "NM3R", x->transfer_id);
    make_key(nkey, "NM30", x->transfer_id);
    rc = build_nm30(
        nm30, eng, x, NINLIL_MFDT_V1_TERM_ABORTED,
        NINLIL_MFDT_V1_TERM_REASON_EXPIRED, 0u, NULL, NULL, NULL,
        x->res_epoch, eng->cfg.now_ms);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = full_terminal(eng, akey, nkey, nm30, NINLIL_MFDT_V1_NM30_BYTES);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    x->terminal = 1u;
    eng->active_count = 0u;
    eng->publication_ready = 0u;
    return NINLIL_MFDT_V1_OK;
}
