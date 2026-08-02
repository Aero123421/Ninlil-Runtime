/* SPDX-License-Identifier: Apache-2.0
 * Spine-bound MFDT: durable arm + real outbound ownership. No self-loop.
 * ESP: spine ctx via SPIRAM/heap. Every entry: spine_mut() once + NULL check.
 */
#include "mfdt_v1_spine.h"
#include "mfdt_v1_target_alloc.h"

#include <string.h>

#if defined(ESP_PLATFORM)
static ninlil_mfdt_v1_spine_ctx_t *g_spine_p;

static ninlil_mfdt_v1_spine_ctx_t *spine_mut(void)
{
    return g_spine_p;
}
#else
static ninlil_mfdt_v1_spine_ctx_t g_spine_storage;
static uint8_t g_spine_preallocated;

static ninlil_mfdt_v1_spine_ctx_t *spine_mut(void)
{
    return g_spine_preallocated != 0u ? &g_spine_storage : NULL;
}
#endif

int ninlil_mfdt_v1_spine_preallocate(void)
{
#if defined(ESP_PLATFORM)
    ninlil_mfdt_v1_spine_ctx_t *fresh = NULL;
    if (g_spine_p == NULL) {
        fresh = (ninlil_mfdt_v1_spine_ctx_t *)ninlil_mfdt_v1_target_zalloc(
            sizeof(*fresh));
        if (fresh == NULL) {
            return NINLIL_MFDT_V1_ERR_STORAGE;
        }
        g_spine_p = fresh;
    }
    if (ninlil_mfdt_v1_engine_preallocate() != NINLIL_MFDT_V1_OK) {
        if (fresh != NULL) {
            ninlil_mfdt_v1_target_free(fresh);
            g_spine_p = NULL;
        }
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
#else
    if (g_spine_preallocated != 0u) {
        return NINLIL_MFDT_V1_OK;
    }
    if (ninlil_mfdt_v1_engine_preallocate() != NINLIL_MFDT_V1_OK) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    g_spine_preallocated = 1u;
#endif
    return NINLIL_MFDT_V1_OK;
}

ninlil_mfdt_v1_spine_ctx_t *ninlil_mfdt_v1_spine_ctx(void)
{
    if (ninlil_mfdt_v1_spine_preallocate() != NINLIL_MFDT_V1_OK) {
        return NULL;
    }
    return spine_mut();
}

int ninlil_mfdt_v1_spine_should_use_mfdt(uint32_t payload_length)
{
    ninlil_mfdt_v1_config_t cfg;
    ninlil_mfdt_v1_spine_ctx_t *sp;

    sp = spine_mut();
    if (sp == NULL) {
        return 0;
    }
    ninlil_mfdt_v1_memzero(&cfg, sizeof(cfg));
    cfg.policy = sp->seam.policy_on ? NINLIL_MFDT_V1_POLICY_ON
                                    : NINLIL_MFDT_V1_POLICY_OFF;
    cfg.mfdt_admission_version = sp->seam.mfdt_admission_version;
    cfg.mfdt_capability = sp->seam.capability;
    cfg.host_mode = sp->seam.host_mode;
    cfg.session_generation = sp->seam.session_generation;
    if (ninlil_mfdt_v1_admission_check(&cfg) != NINLIL_MFDT_V1_OK) {
        return 0;
    }
    return ninlil_mfdt_v1_pipeline_requires_mfdt(&cfg, payload_length) ||
           (payload_length > NINLIL_MFDT_V1_U6_SINGLE_FRAME_MAX);
}

static int ensure_engines(ninlil_mfdt_v1_spine_ctx_t *sp)
{
    ninlil_mfdt_v1_config_t cfg;

    if (sp == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    if (sp->engines_ready != 0u) {
        return NINLIL_MFDT_V1_OK;
    }
    ninlil_mfdt_v1_memzero(&cfg, sizeof(cfg));
    cfg.policy = sp->seam.policy_on ? NINLIL_MFDT_V1_POLICY_ON
                                    : NINLIL_MFDT_V1_POLICY_OFF;
    cfg.mfdt_admission_version = sp->seam.mfdt_admission_version;
    cfg.mfdt_capability = sp->seam.capability;
    cfg.host_mode = sp->seam.host_mode;
    cfg.session_generation = sp->seam.session_generation;
    cfg.now_ms = sp->seam.now_ms;
    (void)memcpy(cfg.local_clock_epoch.bytes,
                 sp->seam.local_clock_epoch, 16u);
    cfg.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    if (ninlil_mfdt_v1_admission_check(&cfg) != NINLIL_MFDT_V1_OK ||
        sp->seam.session_cookie == 0ull) {
        return NINLIL_MFDT_V1_ERR_VERSION;
    }
    if (sp->store_inited == 0u) {
        ninlil_mfdt_v1_lab_store_init(&sp->store);
        sp->store_inited = 1u;
    }
    if (ninlil_mfdt_v1_engine_init(&sp->eng, &sp->ws, &sp->store, &cfg) !=
        NINLIL_MFDT_V1_OK) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    ninlil_mfdt_v1_pipeline_init(
        &sp->pipe, &sp->eng, NULL, NULL, NULL, cfg.session_generation,
        sp->seam.session_cookie);
    sp->engines_ready = 1u;
    return NINLIL_MFDT_V1_OK;
}

static void make_nm3s_key(uint8_t key[20], const uint8_t tid[16])
{
    (void)memcpy(key, "NM3S", 4u);
    (void)memcpy(key + 4, tid, 16u);
}

ninlil_mfdt_v1_cu_class_t ninlil_mfdt_v1_spine_classify_delete_group(
    const ninlil_mfdt_v1_cu_class_t observations[4])
{
    uint8_t saw_old = 0u;
    uint8_t saw_new = 0u;
    size_t i;

    if (observations == NULL) {
        return NINLIL_MFDT_V1_CU_THIRD;
    }
    for (i = 0u; i < 4u; ++i) {
        if (observations[i] == NINLIL_MFDT_V1_CU_EXTRA) {
            return NINLIL_MFDT_V1_CU_EXTRA;
        }
    }
    for (i = 0u; i < 4u; ++i) {
        if (observations[i] == NINLIL_MFDT_V1_CU_THIRD ||
            observations[i] == NINLIL_MFDT_V1_CU_BOTH) {
            return NINLIL_MFDT_V1_CU_THIRD;
        }
    }
    for (i = 0u; i < 4u; ++i) {
        if (observations[i] == NINLIL_MFDT_V1_CU_PARTIAL) {
            return NINLIL_MFDT_V1_CU_PARTIAL;
        }
        if (observations[i] == NINLIL_MFDT_V1_CU_OLD) {
            saw_old = 1u;
        } else if (observations[i] == NINLIL_MFDT_V1_CU_NEW) {
            saw_new = 1u;
        } else if (observations[i] != NINLIL_MFDT_V1_CU_ABSENT) {
            return NINLIL_MFDT_V1_CU_THIRD;
        }
    }
    if (saw_old != 0u && saw_new != 0u) {
        return NINLIL_MFDT_V1_CU_PARTIAL;
    }
    if (saw_old != 0u) {
        return NINLIL_MFDT_V1_CU_OLD;
    }
    return NINLIL_MFDT_V1_CU_NEW;
}

static int del_custody_keys(ninlil_mfdt_v1_spine_ctx_t *sp,
                            const uint8_t transaction_id[16])
{
    static const char prefixes[4][4] = {
        {'N', 'M', '3', 'S'},
        {'N', 'R', 'C', '1'},
        {'N', 'M', '3', '0'},
        {'N', 'M', '3', 'R'},
    };
    uint8_t key[20];
    uint8_t old_digest[4][32];
    uint32_t old_len[4];
    uint8_t old_present[4];
    ninlil_mfdt_v1_cu_class_t observed[4];
    uint32_t observed_len;
    size_t i;
    int rc;
    int commit_rc;

    if (sp == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_memzero(old_digest, sizeof(old_digest));
    ninlil_mfdt_v1_memzero(old_len, sizeof(old_len));
    ninlil_mfdt_v1_memzero(old_present, sizeof(old_present));
    for (i = 0u; i < 4u; ++i) {
        observed[i] = NINLIL_MFDT_V1_CU_ABSENT;
    }
    for (i = 0u; i < 4u; ++i) {
        (void)memcpy(key, prefixes[i], 4u);
        (void)memcpy(key + 4, transaction_id, 16u);
        observed_len = 0u;
        rc = ninlil_mfdt_v1_lab_get(&sp->store, key, NULL, 0u, &observed_len);
        if (rc == NINLIL_MFDT_V1_OK) {
            if (observed_len > sizeof(sp->ws.bytes) ||
                ninlil_mfdt_v1_lab_get(&sp->store, key, sp->ws.bytes,
                                       sizeof(sp->ws.bytes), &observed_len) !=
                    NINLIL_MFDT_V1_OK) {
                sp->last_cleanup_cu = NINLIL_MFDT_V1_CU_THIRD;
                return NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN;
            }
            old_present[i] = 1u;
            old_len[i] = observed_len;
            ninlil_mfdt_v1_sha256(sp->ws.bytes, observed_len, old_digest[i]);
        } else if (rc != NINLIL_MFDT_V1_ERR_STATE) {
            return rc;
        }
    }
    rc = ninlil_mfdt_v1_lab_full_begin(&sp->store);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    for (i = 0u; i < 4u; ++i) {
        (void)memcpy(key, prefixes[i], 4u);
        (void)memcpy(key + 4, transaction_id, 16u);
        rc = ninlil_mfdt_v1_lab_del(&sp->store, key);
        if (rc != NINLIL_MFDT_V1_OK) {
            (void)ninlil_mfdt_v1_lab_full_rollback(&sp->store);
            return rc;
        }
    }
    commit_rc = ninlil_mfdt_v1_lab_full_commit(&sp->store);

    /* Exact read-back classification for the whole four-key delete group. */
    for (i = 0u; i < 4u; ++i) {
        uint8_t digest[32];
        (void)memcpy(key, prefixes[i], 4u);
        (void)memcpy(key + 4, transaction_id, 16u);
        observed_len = 0u;
        rc = ninlil_mfdt_v1_lab_get(&sp->store, key, NULL, 0u, &observed_len);
        if (rc == NINLIL_MFDT_V1_ERR_STATE) {
            if (old_present[i] != 0u) {
                observed[i] = NINLIL_MFDT_V1_CU_NEW;
            }
            continue;
        }
        if (rc != NINLIL_MFDT_V1_OK ||
            observed_len > sizeof(sp->ws.bytes) ||
            ninlil_mfdt_v1_lab_get(&sp->store, key, sp->ws.bytes,
                                   sizeof(sp->ws.bytes), &observed_len) !=
                NINLIL_MFDT_V1_OK) {
            observed[i] = NINLIL_MFDT_V1_CU_THIRD;
            continue;
        }
        if (old_present[i] == 0u) {
            observed[i] = NINLIL_MFDT_V1_CU_EXTRA;
            continue;
        }
        ninlil_mfdt_v1_sha256(sp->ws.bytes, observed_len, digest);
        if (observed_len == old_len[i] &&
            ninlil_mfdt_v1_memeq(digest, old_digest[i], 32u)) {
            observed[i] = NINLIL_MFDT_V1_CU_OLD;
        } else {
            observed[i] = NINLIL_MFDT_V1_CU_THIRD;
        }
    }
    sp->last_cleanup_cu =
        ninlil_mfdt_v1_spine_classify_delete_group(observed);
    if (sp->last_cleanup_cu != NINLIL_MFDT_V1_CU_NEW) {
        return commit_rc == NINLIL_MFDT_V1_ERR_STORAGE
                   ? NINLIL_MFDT_V1_ERR_STORAGE
                   : NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN;
    }
    if (commit_rc == NINLIL_MFDT_V1_ERR_CU_NEW_NOT_PROMOTED) {
        return NINLIL_MFDT_V1_ERR_CU_NEW_NOT_PROMOTED;
    }
    return commit_rc;
}

static void spine_mark_outcome_unknown(ninlil_mfdt_v1_spine_ctx_t *sp,
                                       const uint8_t transaction_id[16])
{
    if (sp == NULL || transaction_id == NULL) {
        return;
    }
    sp->outcome_unknown = 1u;
    (void)memcpy(sp->outcome_tid, transaction_id, 16u);
    sp->armed = 0u;
    sp->role = 0u;
    sp->pipe.complete = 0u;
    sp->pipe.outbox_valid = 0u;
    sp->pipe.phase = NINLIL_MFDT_V1_PHASE_IDLE;
}

static void spine_clear_outcome_unknown(ninlil_mfdt_v1_spine_ctx_t *sp)
{
    if (sp == NULL) {
        return;
    }
    sp->outcome_unknown = 0u;
    ninlil_mfdt_v1_memzero(sp->outcome_tid, 16u);
}

int ninlil_mfdt_v1_spine_arm_sender(const uint8_t transaction_id[16],
                                    const uint8_t *payload, uint32_t payload_len)
{
    ninlil_mfdt_v1_spine_ctx_t *sp;
    int rc;
    int clean_rc;

    sp = spine_mut();
    if (sp == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    if (transaction_id == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (payload_len > NINLIL_MFDT_V1_MAX_CONTENT) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    if (payload_len > 0u && payload == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (sp->armed != 0u && sp->role == 1u &&
        !ninlil_mfdt_v1_memeq(sp->transfer_id, transaction_id, 16u)) {
        return NINLIL_MFDT_V1_ERR_BUSY;
    }
    if (sp->armed != 0u && sp->role == 1u &&
        ninlil_mfdt_v1_memeq(sp->transfer_id, transaction_id, 16u)) {
        return NINLIL_MFDT_V1_OK;
    }
    rc = ensure_engines(sp);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    ninlil_mfdt_v1_pipeline_init(
        &sp->pipe, &sp->eng, NULL, NULL, NULL,
        sp->seam.session_generation != 0u ? sp->seam.session_generation : 1u,
        sp->seam.session_cookie != 0ull ? sp->seam.session_cookie
                                        : 0x4d464454ull);
    (void)memcpy(sp->transfer_id, transaction_id, 16u);
    sp->content_len = payload_len;
    sp->role = 1u;
    ninlil_mfdt_v1_sha256(payload != NULL ? payload : (const uint8_t *)"",
                          payload_len, sp->whole_digest);
    rc = ninlil_mfdt_v1_pipeline_sender_begin(&sp->pipe, transaction_id, payload,
                                              payload_len);
    if (rc != NINLIL_MFDT_V1_OK) {
        sp->armed = 0u;
        sp->pipe.complete = 0u;
        if (sp->store_inited != 0u) {
            clean_rc = del_custody_keys(sp, transaction_id);
            if (clean_rc == NINLIL_MFDT_V1_OK) {
                spine_clear_outcome_unknown(sp);
                sp->engines_ready = 0u;
                ninlil_mfdt_v1_memzero(sp->transfer_id, 16u);
                return rc;
            }
            spine_mark_outcome_unknown(sp, transaction_id);
            (void)memcpy(sp->transfer_id, transaction_id, 16u);
            return NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN;
        }
        sp->engines_ready = 0u;
        ninlil_mfdt_v1_memzero(sp->transfer_id, 16u);
        return rc;
    }
    spine_clear_outcome_unknown(sp);
    sp->armed = 1u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_spine_disarm(const uint8_t transaction_id[16])
{
    ninlil_mfdt_v1_spine_ctx_t *sp;
    int rc;

    sp = spine_mut();
    if (sp == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    if (transaction_id == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    rc = NINLIL_MFDT_V1_OK;
    if (sp->store_inited != 0u) {
        rc = del_custody_keys(sp, transaction_id);
    }
    if (rc != NINLIL_MFDT_V1_OK) {
        spine_mark_outcome_unknown(sp, transaction_id);
        if (rc == NINLIL_MFDT_V1_ERR_STORAGE ||
            rc == NINLIL_MFDT_V1_ERR_CU_NEW_NOT_PROMOTED ||
            rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN) {
            return NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN;
        }
        return rc;
    }
    spine_clear_outcome_unknown(sp);
    if (sp->armed != 0u &&
        ninlil_mfdt_v1_memeq(sp->transfer_id, transaction_id, 16u)) {
        sp->armed = 0u;
        sp->role = 0u;
        sp->engines_ready = 0u;
        sp->pipe.complete = 0u;
        sp->pipe.outbox_valid = 0u;
        sp->pipe.phase = NINLIL_MFDT_V1_PHASE_IDLE;
        ninlil_mfdt_v1_memzero(sp->transfer_id, 16u);
    } else if (sp->armed == 0u) {
        sp->engines_ready = 0u;
        sp->pipe.complete = 0u;
        sp->pipe.outbox_valid = 0u;
        sp->pipe.phase = NINLIL_MFDT_V1_PHASE_IDLE;
    }
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_spine_outcome_unknown(void)
{
    ninlil_mfdt_v1_spine_ctx_t *sp;

    sp = spine_mut();
    if (sp == NULL) {
        return 0;
    }
    return sp->outcome_unknown != 0u ? 1 : 0;
}

int ninlil_mfdt_v1_spine_is_armed(const uint8_t transaction_id[16])
{
    ninlil_mfdt_v1_spine_ctx_t *sp;

    sp = spine_mut();
    if (sp == NULL || transaction_id == NULL || sp->armed == 0u) {
        return 0;
    }
    return ninlil_mfdt_v1_memeq(sp->transfer_id, transaction_id, 16u) ? 1 : 0;
}

int ninlil_mfdt_v1_spine_recover_transaction(const uint8_t transaction_id[16])
{
    ninlil_mfdt_v1_spine_ctx_t *sp;
    uint8_t key[20];
    uint32_t len;
    int rc;

    sp = spine_mut();
    if (sp == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    if (transaction_id == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    rc = ensure_engines(sp);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    make_nm3s_key(key, transaction_id);
    len = 0u;
    if (ninlil_mfdt_v1_lab_get(&sp->store, key, NULL, 0u, &len) !=
        NINLIL_MFDT_V1_OK) {
        if (sp->armed != 0u &&
            ninlil_mfdt_v1_memeq(sp->transfer_id, transaction_id, 16u)) {
            sp->armed = 0u;
            sp->role = 0u;
            sp->pipe.complete = 0u;
            sp->pipe.phase = NINLIL_MFDT_V1_PHASE_IDLE;
            ninlil_mfdt_v1_memzero(sp->transfer_id, 16u);
        }
        return NINLIL_MFDT_V1_OK;
    }
    rc = ninlil_mfdt_v1_restart_scan_transfer(&sp->eng, transaction_id, 1u);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    (void)memcpy(sp->transfer_id, transaction_id, 16u);
    sp->role = 1u;
    sp->armed = 1u;
    return ninlil_mfdt_v1_pipeline_sender_rehydrate(
        &sp->pipe, &sp->eng, transaction_id,
        sp->seam.session_generation != 0u ? sp->seam.session_generation : 1u,
        sp->seam.session_cookie != 0ull ? sp->seam.session_cookie
                                        : 0x4d464454ull);
}

int ninlil_mfdt_v1_spine_recover(void)
{
    ninlil_mfdt_v1_spine_ctx_t *sp;

    sp = spine_mut();
    if (sp == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    if (sp->armed == 0u) {
        return NINLIL_MFDT_V1_OK;
    }
    return ninlil_mfdt_v1_spine_recover_transaction(sp->transfer_id);
}

int ninlil_mfdt_v1_spine_arm_receiver(void)
{
    ninlil_mfdt_v1_spine_ctx_t *sp;
    int rc;

    sp = spine_mut();
    if (sp == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    rc = ensure_engines(sp);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    ninlil_mfdt_v1_pipeline_init(
        &sp->pipe, NULL, &sp->eng, NULL, NULL,
        sp->seam.session_generation != 0u ? sp->seam.session_generation : 1u,
        sp->seam.session_cookie != 0ull ? sp->seam.session_cookie
                                        : 0x4d464454ull);
    sp->role = 2u;
    sp->armed = 1u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_spine_sender_pump(void)
{
    ninlil_mfdt_v1_spine_ctx_t *sp;

    sp = spine_mut();
    if (sp == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    if (sp->engines_ready == 0u || sp->role != 1u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    return ninlil_mfdt_v1_pipeline_sender_pump(&sp->pipe);
}

int ninlil_mfdt_v1_spine_outbox_pending(void)
{
    ninlil_mfdt_v1_spine_ctx_t *sp;

    sp = spine_mut();
    if (sp == NULL) {
        return 0;
    }
    return ninlil_mfdt_v1_pipeline_outbox_pending(&sp->pipe);
}

int ninlil_mfdt_v1_spine_take_outbound_ncl1(uint8_t *out, size_t cap,
                                            size_t *out_len)
{
    ninlil_mfdt_v1_spine_ctx_t *sp;

    sp = spine_mut();
    if (sp == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    return ninlil_mfdt_v1_pipeline_take_outbound(&sp->pipe, out, cap, out_len);
}

int ninlil_mfdt_v1_spine_on_ncl1_data(const uint8_t *ncl1, size_t ncl1_len)
{
    ninlil_mfdt_v1_spine_ctx_t *sp;
    int rc;

    sp = spine_mut();
    if (sp == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    if (ncl1 == NULL || ncl1_len == 0u) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    rc = ensure_engines(sp);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    if (sp->armed == 0u) {
        ninlil_mfdt_v1_pipeline_init(
            &sp->pipe, NULL, &sp->eng, NULL, NULL,
            sp->seam.session_generation != 0u ? sp->seam.session_generation
                                              : 1u,
            sp->seam.session_cookie != 0ull ? sp->seam.session_cookie
                                            : 0x4d464454ull);
        sp->role = 2u;
        sp->armed = 1u;
    }
    return ninlil_mfdt_v1_pipeline_on_ncl1_ingress(&sp->pipe, ncl1, ncl1_len);
}

int ninlil_mfdt_v1_spine_restart_scan(void)
{
    ninlil_mfdt_v1_spine_ctx_t *sp;

    sp = spine_mut();
    if (sp == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    if (sp->engines_ready == 0u) {
        return NINLIL_MFDT_V1_OK;
    }
    return ninlil_mfdt_v1_restart_scan(&sp->eng);
}

int ninlil_mfdt_v1_spine_transfer_complete(void)
{
    ninlil_mfdt_v1_spine_ctx_t *sp;

    sp = spine_mut();
    if (sp == NULL) {
        return 0;
    }
    return sp->pipe.complete != 0u ? 1 : 0;
}

ninlil_mfdt_v1_cu_class_t ninlil_mfdt_v1_spine_cu_key(
    const uint8_t key[20], const uint8_t *oldb, uint32_t oldn, int has_old,
    const uint8_t *newb, uint32_t newn, int has_new)
{
    ninlil_mfdt_v1_spine_ctx_t *sp;

    sp = spine_mut();
    if (sp == NULL || sp->engines_ready == 0u) {
        return NINLIL_MFDT_V1_CU_ABSENT;
    }
    return ninlil_mfdt_v1_cu_observe_key(&sp->store, key, oldb, oldn, has_old,
                                         newb, newn, has_new);
}
