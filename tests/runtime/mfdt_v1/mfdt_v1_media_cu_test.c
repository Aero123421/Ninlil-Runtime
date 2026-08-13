/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Media FULL COMMIT_UNKNOWN / read-classify / restart (software, host lab).
 * Not physical power-cut HIL.
 */
#include "mfdt_v1.h"
#include "mfdt_v1_session.h"
#include "mfdt_v1_spine.h"

#include <stdio.h>
#include <string.h>

static int g_fail;
static ninlil_mfdt_v1_spine_ctx_t g_spine;
static ninlil_mfdt_v1_spine_ctx_t g_spine_peer;
static ninlil_mfdt_v1_workspace_t g_cu_scratch;

/* Keep the test cases terse while the production API remains explicit-owner. */
#define ninlil_mfdt_v1_spine_should_use_mfdt(payload_) \
    ninlil_mfdt_v1_spine_should_use_mfdt(&g_spine, (payload_))
#define ninlil_mfdt_v1_spine_arm_sender(...) \
    ninlil_mfdt_v1_spine_arm_sender(&g_spine, __VA_ARGS__)
#define ninlil_mfdt_v1_spine_disarm(...) \
    ninlil_mfdt_v1_spine_disarm(&g_spine, __VA_ARGS__)
#define ninlil_mfdt_v1_spine_outcome_unknown() \
    ninlil_mfdt_v1_spine_outcome_unknown(&g_spine)
#define ninlil_mfdt_v1_spine_is_armed(...) \
    ninlil_mfdt_v1_spine_is_armed(&g_spine, __VA_ARGS__)
#define ninlil_mfdt_v1_spine_recover_transaction(...) \
    ninlil_mfdt_v1_spine_recover_transaction(&g_spine, __VA_ARGS__)
#define ninlil_mfdt_v1_spine_recover() \
    ninlil_mfdt_v1_spine_recover(&g_spine)
#define ninlil_mfdt_v1_spine_restart_scan() \
    ninlil_mfdt_v1_spine_restart_scan(&g_spine)
#define ninlil_mfdt_v1_spine_transfer_complete() \
    ninlil_mfdt_v1_spine_transfer_complete(&g_spine)
#define ninlil_mfdt_v1_spine_outbox_pending() \
    ninlil_mfdt_v1_spine_outbox_pending(&g_spine)

static int bytes_are_zero(const void *memory, size_t length)
{
    const uint8_t *bytes = (const uint8_t *)memory;
    size_t index;
    for (index = 0u; index < length; ++index) {
        if (bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static void expect(int c, const char *m)
{
    if (!c) {
        fprintf(stderr, "FAIL: %s\n", m);
        g_fail = 1;
    }
}

/* Reset one caller-owned spine between cases. */
static void spine_test_reset(ninlil_mfdt_v1_seam_config_t *sc)
{
    ninlil_mfdt_v1_spine_fini(&g_spine);
    expect(ninlil_mfdt_v1_spine_init(&g_spine) == NINLIL_MFDT_V1_OK,
           "spine owner init");
    if (sc != NULL) {
        expect(ninlil_mfdt_v1_spine_set_config(&g_spine, sc) ==
                   NINLIL_MFDT_V1_OK,
               "spine owner config");
    }
}

static void test_session_mfn1_negotiation(void)
{
    ninlil_mfdt_v1_session_t a;
    ninlil_mfdt_v1_session_t b;
    ninlil_mfdt_v1_session_t denied;
    uint8_t aid[16];
    uint8_t bid[16];
    uint8_t request_nonce[16];
    uint8_t responder_nonce[16];
    uint8_t conflicting_nonce[16];
    uint8_t offer[NINLIL_MFDT_V1_NEGOTIATE_MAX_WIRE_BYTES];
    uint8_t accept[NINLIL_MFDT_V1_NEGOTIATE_MAX_WIRE_BYTES];
    uint8_t duplicate[NINLIL_MFDT_V1_NEGOTIATE_MAX_WIRE_BYTES];
    size_t offer_len = 0u;
    size_t accept_len = 0u;
    size_t duplicate_len = 0u;

    memset(aid, 0xa1, sizeof(aid));
    memset(bid, 0xb2, sizeof(bid));
    memset(request_nonce, 0x31, sizeof(request_nonce));
    memset(responder_nonce, 0x42, sizeof(responder_nonce));
    memset(conflicting_nonce, 0x53, sizeof(conflicting_nonce));

    ninlil_mfdt_v1_session_init(
        &a, 1u, NINLIL_MFDT_V1_CAP_REQUIRED);
    ninlil_mfdt_v1_session_init(
        &b, 1u, NINLIL_MFDT_V1_CAP_REQUIRED);
    expect(ninlil_mfdt_v1_session_bind(
               &a, 2u, 7u, 0x1122334455667788ull, 1u, aid, bid) == 0,
           "MFN1 bind initiator on Accepted v2");
    expect(ninlil_mfdt_v1_session_bind(
               &b, 2u, 7u, 0x1122334455667788ull, 0u, bid, aid) == 0,
           "MFN1 bind responder on Accepted v2");
    expect(!ninlil_mfdt_v1_session_carrier_ncl1_data_ok(&a),
           "carrier closed before transcript");

    expect(ninlil_mfdt_v1_session_build_offer(
               &a, 0x10203040u, request_nonce, offer, sizeof(offer),
               &offer_len) == 0,
           "MFN1 offer");
    expect(offer_len ==
               26u + NINLIL_MFDT_V1_NEGOTIATE_OFFER_BODY_BYTES &&
               offer[5] == NINLIL_MFDT_V1_NEGOTIATE_OFFER,
           "MFN1 offer exact envelope");
    expect(ninlil_mfdt_v1_session_on_offer(
               &b, offer, offer_len, responder_nonce, accept,
               sizeof(accept), &accept_len) == 0,
           "MFN1 accept emit");
    expect(ninlil_mfdt_v1_session_carrier_ncl1_data_ok(&b),
           "responder admitted only after ACCEPT materialized");
    expect(accept_len ==
               26u + NINLIL_MFDT_V1_NEGOTIATE_ACCEPT_BODY_BYTES &&
               accept[5] == NINLIL_MFDT_V1_NEGOTIATE_ACCEPT,
           "MFN1 accept exact envelope");
    expect(ninlil_mfdt_v1_session_on_accept(&a, accept, accept_len) == 0,
           "MFN1 accept validate");
    expect(ninlil_mfdt_v1_session_carrier_ncl1_data_ok(&a),
           "initiator admitted after correlated ACCEPT");
    expect(a.base_control_version == 2u &&
               a.mfdt_admission_version ==
                   NINLIL_MFDT_V1_ADMISSION_VERSION,
           "Accepted control v2 remains separate from MFDT v1");

    expect(ninlil_mfdt_v1_session_on_offer(
               &b, offer, offer_len, NULL, duplicate, sizeof(duplicate),
               &duplicate_len) == 0 &&
               duplicate_len == accept_len &&
               memcmp(duplicate, accept, accept_len) == 0,
           "exact duplicate OFFER returns cached ACCEPT");

    expect(ninlil_mfdt_v1_session_build_offer(
               &a, 0x10203040u, conflicting_nonce, offer, sizeof(offer),
               &offer_len) == NINLIL_MFDT_V1_ERR_STATE &&
               a.state == NINLIL_MFDT_V1_SESSION_FENCED,
           "conflicting local OFFER fences");

    ninlil_mfdt_v1_session_init(&denied, 1u, 0u);
    expect(ninlil_mfdt_v1_session_bind(
               &denied, 2u, 7u, 0x1122334455667788ull, 1u, aid,
               bid) == 0,
           "capability-absent bind remains possible");
    expect(ninlil_mfdt_v1_session_build_offer(
               &denied, 1u, request_nonce, offer, sizeof(offer),
               &offer_len) == NINLIL_MFDT_V1_ERR_POLICY_OFF,
           "capability-absent cannot negotiate");
    expect(ninlil_mfdt_v1_session_bind(
               &denied, 3u, 7u, 0x1122334455667788ull, 1u, aid,
               bid) == NINLIL_MFDT_V1_ERR_PARAM,
           "HELLO selected=3 is forbidden");
}

static void test_full_crash_cu_restart(void)
{
    ninlil_mfdt_v1_lab_store_t st;
    uint8_t key[20];
    uint8_t oldv[64];
    uint8_t newv[64];
    uint8_t out[64];
    uint32_t len = 0;
    ninlil_mfdt_v1_cu_class_t c;
    memset(key, 0x4e, 20);
    memcpy(key, "NM3R", 4);
    memset(oldv, 0x11, sizeof(oldv));
    memset(newv, 0x22, sizeof(newv));
    ninlil_mfdt_v1_lab_store_init(&st);
    expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "b1");
    expect(ninlil_mfdt_v1_lab_put(&st, key, oldv, 64) == 0, "p1");
    expect(ninlil_mfdt_v1_lab_full_commit(&st) == 0, "c1");
    /* multi-key co-FULL staging then crash before apply */
    expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "b2");
    expect(ninlil_mfdt_v1_lab_put(&st, key, newv, 64) == 0, "p2");
    {
        uint8_t nkey[20];
        uint8_t nval[32];
        memset(nkey, 0, 20);
        memcpy(nkey, "NRC1", 4);
        memset(nval, 0x33, 32);
        expect(ninlil_mfdt_v1_lab_put(&st, nkey, nval, 32) == 0, "p nrc1");
    }
    st.crash_after_fulls = 1;
    st.full_count = 1;
    expect(ninlil_mfdt_v1_lab_full_commit(&st) == NINLIL_MFDT_V1_ERR_STORAGE,
           "crash commit");
    expect(st.crash_armed == 1, "armed");
    /* OLD still visible */
    expect(ninlil_mfdt_v1_lab_get(&st, key, out, 64, &len) == 0 && len == 64, "get");
    expect(ninlil_mfdt_v1_memeq(out, oldv, 64), "old retained");
    c = ninlil_mfdt_v1_cu_observe_key(
        &st, g_cu_scratch.bytes, sizeof(g_cu_scratch.bytes), key,
        oldv, 64, 1, newv, 64, 1);
    expect(c == NINLIL_MFDT_V1_CU_OLD, "cu old after crash");
    /* successful multi-key FULL */
    ninlil_mfdt_v1_lab_store_init(&st);
    expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "b3");
    expect(ninlil_mfdt_v1_lab_put(&st, key, oldv, 64) == 0, "p3");
    expect(ninlil_mfdt_v1_lab_full_commit(&st) == 0, "c3");
    expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "b4");
    expect(ninlil_mfdt_v1_lab_put(&st, key, newv, 64) == 0, "p4");
    expect(ninlil_mfdt_v1_lab_full_commit(&st) == 0, "c4");
    c = ninlil_mfdt_v1_cu_observe_key(
        &st, g_cu_scratch.bytes, sizeof(g_cu_scratch.bytes), key,
        oldv, 64, 1, newv, 64, 1);
    expect(c == NINLIL_MFDT_V1_CU_NEW, "cu new");
}

static void test_delete_group_exact_classification(void)
{
    ninlil_mfdt_v1_cu_class_t obs[4];

    obs[0] = NINLIL_MFDT_V1_CU_NEW;
    obs[1] = NINLIL_MFDT_V1_CU_ABSENT;
    obs[2] = NINLIL_MFDT_V1_CU_NEW;
    obs[3] = NINLIL_MFDT_V1_CU_ABSENT;
    expect(ninlil_mfdt_v1_spine_classify_delete_group(obs) ==
               NINLIL_MFDT_V1_CU_NEW,
           "delete group NEW");

    obs[0] = NINLIL_MFDT_V1_CU_OLD;
    obs[1] = NINLIL_MFDT_V1_CU_ABSENT;
    obs[2] = NINLIL_MFDT_V1_CU_OLD;
    obs[3] = NINLIL_MFDT_V1_CU_ABSENT;
    expect(ninlil_mfdt_v1_spine_classify_delete_group(obs) ==
               NINLIL_MFDT_V1_CU_OLD,
           "delete group OLD");

    obs[1] = NINLIL_MFDT_V1_CU_NEW;
    expect(ninlil_mfdt_v1_spine_classify_delete_group(obs) ==
               NINLIL_MFDT_V1_CU_PARTIAL,
           "delete group mixed partial");
    obs[1] = NINLIL_MFDT_V1_CU_PARTIAL;
    expect(ninlil_mfdt_v1_spine_classify_delete_group(obs) ==
               NINLIL_MFDT_V1_CU_PARTIAL,
           "delete group partial image");
    obs[2] = NINLIL_MFDT_V1_CU_EXTRA;
    expect(ninlil_mfdt_v1_spine_classify_delete_group(obs) ==
               NINLIL_MFDT_V1_CU_EXTRA,
           "delete group extra");
    obs[2] = NINLIL_MFDT_V1_CU_NEW;
    obs[3] = NINLIL_MFDT_V1_CU_THIRD;
    expect(ninlil_mfdt_v1_spine_classify_delete_group(obs) ==
               NINLIL_MFDT_V1_CU_THIRD,
           "delete group third");
}

static void test_spine_arm_and_restart(void)
{
    ninlil_mfdt_v1_seam_config_t sc;
    uint8_t tid[16];
    uint8_t content[4] = {1, 2, 3, 4};
    memset(&sc, 0, sizeof(sc));
    sc.policy_on = 1;
    sc.capability = 2;
    sc.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    sc.host_mode = 1;
    sc.session_generation = 1;
    sc.session_cookie = 9;
    sc.now_ms = 100;
    memset(sc.local_clock_epoch, 0xc0, 16u);
    spine_test_reset(&sc);
    memset(tid, 7, 16);
    tid[0] = 1;
    expect(ninlil_mfdt_v1_spine_should_use_mfdt(4) == 0,
           "single-frame payload does not consume MFDT");
    expect(ninlil_mfdt_v1_spine_arm_sender(tid, content, 4) == 0, "arm");
    /* Idempotent re-arm: no duplicate apply */
    expect(ninlil_mfdt_v1_spine_arm_sender(tid, content, 4) == 0, "rearm same");
    expect(ninlil_mfdt_v1_spine_is_armed(tid) == 1, "armed");
    expect(ninlil_mfdt_v1_spine_restart_scan() == 0, "restart");
    expect(ninlil_mfdt_v1_spine_recover() == 0, "recover with NM3S");
}

static void test_disarm_after_failed_commit_semantics(void)
{
    ninlil_mfdt_v1_seam_config_t sc;
    uint8_t tid[16];
    uint8_t content[8];
    memset(&sc, 0, sizeof(sc));
    sc.policy_on = 1;
    sc.capability = 2;
    sc.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    sc.host_mode = 1;
    sc.session_generation = 1;
    sc.session_cookie = 0x4d464454ull;
    sc.now_ms = 50;
    memset(sc.local_clock_epoch, 0xc0, 16u);
    spine_test_reset(&sc);
    memset(tid, 8, 16);
    tid[0] = 2;
    memset(content, 0xab, sizeof(content));
    expect(ninlil_mfdt_v1_spine_arm_sender(tid, content, 8) == 0, "arm2");
    /* Simulate admission FULL failure after arm: disarm, no orphan apply. */
    expect(ninlil_mfdt_v1_spine_disarm(tid) == 0, "disarm");
    expect(ninlil_mfdt_v1_spine_is_armed(tid) == 0, "not armed");
    /* Disarm again is idempotent */
    expect(ninlil_mfdt_v1_spine_disarm(tid) == 0, "disarm2");
    /* Recover with no arm is OK */
    expect(ninlil_mfdt_v1_spine_recover() == 0, "recover empty");
    /* recover_txn after disarm: terminalize, never armed (no false re-apply) */
    expect(ninlil_mfdt_v1_spine_recover_transaction(tid) == 0, "recover term");
    expect(ninlil_mfdt_v1_spine_is_armed(tid) == 0, "still not armed");
}

/*
 * Post-admission-FULL path: arm succeeded (NM3S durable), RAM arm lost
 * (engine re-init), recover_transaction resumes without re-admit / re-apply.
 */
static void test_post_commit_recover_resume_no_duplicate(void)
{
    ninlil_mfdt_v1_seam_config_t sc;
    ninlil_mfdt_v1_spine_ctx_t *sp;
    uint8_t tid[16];
    uint8_t content[6] = {9, 8, 7, 6, 5, 4};
    uint8_t key[20];
    uint32_t len = 0u;

    memset(&sc, 0, sizeof(sc));
    sc.policy_on = 1;
    sc.capability = 2;
    sc.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    sc.host_mode = 1;
    sc.session_generation = 1;
    sc.session_cookie = 0x4d464454ull;
    sc.now_ms = 200;
    memset(sc.local_clock_epoch, 0xc0, 16u);
    spine_test_reset(&sc);
    sp = &g_spine;

    memset(tid, 3, 16);
    tid[0] = 0xa1;
    expect(ninlil_mfdt_v1_spine_arm_sender(tid, content, 6) == 0, "arm post");
    expect(ninlil_mfdt_v1_spine_is_armed(tid) == 1, "armed post");
    expect(ninlil_mfdt_v1_spine_transfer_complete() == 0, "not wire complete");
    expect(ninlil_mfdt_v1_spine_outbox_pending() == 1, "OPEN outbox owned");
    memcpy(key, "NM3S", 4);
    memcpy(key + 4, tid, 16);
    expect(ninlil_mfdt_v1_lab_get(&sp->store, key, NULL, 0u, &len) == 0 &&
               len > 0u,
           "NM3S durable pre-wipe");

    /* Simulate post-FULL RAM loss while durable store survives. */
    sp->armed = 0u;
    sp->role = 0u;
    sp->engines_ready = 0u;
    sp->pipe.complete = 0u;
    memset(sp->transfer_id, 0, 16);

    expect(ninlil_mfdt_v1_spine_recover_transaction(tid) == 0, "recover resume");
    expect(ninlil_mfdt_v1_spine_is_armed(tid) == 1, "rearmed from NM3S");
    /* Wire not auto-complete; re-arm same tid is idempotent. */
    expect(ninlil_mfdt_v1_spine_transfer_complete() == 0, "still wire incomplete");
    expect(ninlil_mfdt_v1_spine_arm_sender(tid, content, 6) == 0, "rearm idemp");
    expect(ninlil_mfdt_v1_spine_is_armed(tid) == 1, "still armed");
    expect(ninlil_mfdt_v1_lab_get(&sp->store, key, NULL, 0u, &len) == 0, "NM3S kept");
}

/*
 * Commit-fail path: arm then disarm; recover_transaction terminalizes with
 * no custody and no arm (caller must not map to SUBMISSION_REJECTED for a
 * durable admit that never happened — admit was rolled back).
 */
static void test_commit_fail_disarm_then_terminalize(void)
{
    ninlil_mfdt_v1_seam_config_t sc;
    ninlil_mfdt_v1_spine_ctx_t *sp;
    uint8_t tid[16];
    uint8_t content[4] = {0xde, 0xad, 0xbe, 0xef};
    uint8_t key[20];
    uint32_t len = 0u;

    memset(&sc, 0, sizeof(sc));
    sc.policy_on = 1;
    sc.capability = 2;
    sc.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    sc.host_mode = 1;
    sc.session_generation = 1;
    sc.session_cookie = 0x4d464454ull;
    sc.now_ms = 300;
    memset(sc.local_clock_epoch, 0xc0, 16u);
    spine_test_reset(&sc);
    sp = &g_spine;

    memset(tid, 4, 16);
    tid[0] = 0xb2;
    expect(ninlil_mfdt_v1_spine_arm_sender(tid, content, 4) == 0, "arm cf");
    expect(ninlil_mfdt_v1_spine_disarm(tid) == 0, "disarm cf");
    memcpy(key, "NM3S", 4);
    memcpy(key + 4, tid, 16);
    expect(ninlil_mfdt_v1_lab_get(&sp->store, key, NULL, 0u, &len) != 0,
           "NM3S gone after disarm");
    expect(ninlil_mfdt_v1_spine_recover_transaction(tid) == 0, "term recover");
    expect(ninlil_mfdt_v1_spine_is_armed(tid) == 0, "not armed after term");
}

static int key_absent(ninlil_mfdt_v1_lab_store_t *st, const char *pfx4,
                      const uint8_t tid[16])
{
    uint8_t key[20];
    uint32_t len = 0u;
    memcpy(key, pfx4, 4);
    memcpy(key + 4, tid, 16);
    return ninlil_mfdt_v1_lab_get(st, key, NULL, 0u, &len) != 0;
}

static int orphan_count(ninlil_mfdt_v1_lab_store_t *st, const uint8_t tid[16])
{
    int n = 0;
    if (!key_absent(st, "NM3S", tid)) {
        n++;
    }
    if (!key_absent(st, "NRC1", tid)) {
        n++;
    }
    if (!key_absent(st, "NM30", tid)) {
        n++;
    }
    if (!key_absent(st, "NM3R", tid)) {
        n++;
    }
    return n;
}

/* (1) arm success → disarm → all four custody keys absent (FULL-group erase). */
static void test_arm_disarm_four_keys_absent(void)
{
    ninlil_mfdt_v1_seam_config_t sc;
    ninlil_mfdt_v1_spine_ctx_t *sp;
    uint8_t tid[16];
    uint8_t content[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    memset(&sc, 0, sizeof(sc));
    sc.policy_on = 1;
    sc.capability = 2;
    sc.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    sc.host_mode = 1;
    sc.session_generation = 1;
    sc.session_cookie = 0x4d464454ull;
    sc.now_ms = 400;
    memset(sc.local_clock_epoch, 0xc0, 16u);
    spine_test_reset(&sc);
    sp = &g_spine;
    memset(tid, 0x51, 16);
    tid[0] = 0xc1;

    expect(ninlil_mfdt_v1_spine_arm_sender(tid, content, 8) == 0, "arm ok");
    expect(ninlil_mfdt_v1_spine_is_armed(tid) == 1, "armed");
    /* Sender OPEN durable custody is NM3S (NRC1/NM30/NM3R may be absent yet). */
    expect(!key_absent(&sp->store, "NM3S", tid), "NM3S present after arm");
    expect(ninlil_mfdt_v1_spine_disarm(tid) == 0, "disarm ok");
    expect(sp->last_cleanup_cu == NINLIL_MFDT_V1_CU_NEW,
           "delete FULL read-back NEW");
    expect(ninlil_mfdt_v1_spine_is_armed(tid) == 0, "disarmed");
    /* FULL-group erase: all four prefixes must be absent after disarm. */
    expect(key_absent(&sp->store, "NM3S", tid), "NM3S absent");
    expect(key_absent(&sp->store, "NRC1", tid), "NRC1 absent");
    expect(key_absent(&sp->store, "NM30", tid), "NM30 absent");
    expect(key_absent(&sp->store, "NM3R", tid), "NM3R absent");
    expect(orphan_count(&sp->store, tid) == 0, "orphan 0 after disarm");
}

/*
 * (2) arm OK → admission FULL fault (disarm) → cold restart → no recover of
 * rejected TID (no false re-arm / no durable apply resume).
 */
static void test_admission_fault_cold_restart_no_recover(void)
{
    ninlil_mfdt_v1_seam_config_t sc;
    ninlil_mfdt_v1_spine_ctx_t *sp;
    ninlil_mfdt_v1_lab_store_t saved;
    uint8_t tid[16];
    uint8_t content[5] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    uint8_t store_inited;

    memset(&sc, 0, sizeof(sc));
    sc.policy_on = 1;
    sc.capability = 2;
    sc.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    sc.host_mode = 1;
    sc.session_generation = 1;
    sc.session_cookie = 0x4d464454ull;
    sc.now_ms = 500;
    memset(sc.local_clock_epoch, 0xc0, 16u);
    spine_test_reset(&sc);
    sp = &g_spine;
    memset(tid, 0x62, 16);
    tid[0] = 0xd2;

    expect(ninlil_mfdt_v1_spine_arm_sender(tid, content, 5) == 0, "arm admit");
    /* Admission commit fault: disarm drops FULL custody before restart. */
    expect(ninlil_mfdt_v1_spine_disarm(tid) == 0, "disarm admit fault");
    expect(orphan_count(&sp->store, tid) == 0, "no custody pre-restart");

    /* Cold restart: durable store image survives; process BSS rehydrated. */
    saved = sp->store;
    store_inited = 1u;
    ninlil_mfdt_v1_spine_fini(sp);
    expect(ninlil_mfdt_v1_spine_init(sp) == NINLIL_MFDT_V1_OK,
           "cold process spine init");
    expect(ninlil_mfdt_v1_spine_set_config(sp, &sc) ==
               NINLIL_MFDT_V1_OK,
           "cold process spine config");
    sp->store = saved;
    sp->store_inited = store_inited;

    expect(ninlil_mfdt_v1_spine_recover_transaction(tid) == 0, "recover cold");
    expect(ninlil_mfdt_v1_spine_is_armed(tid) == 0, "no recover re-arm");
    expect(orphan_count(&sp->store, tid) == 0, "still no orphans");
    expect(key_absent(&sp->store, "NM3S", tid), "NM3S still absent cold");
}

/*
 * (3) CU_NEW_NOT_PROMOTED arm failure: durable NEW may appear, cleanup FULL
 * erase must leave orphan 0; external stays fail-closed (gate OFF).
 */
static void test_cu_new_not_promoted_arm_fail_orphan_zero(void)
{
    ninlil_mfdt_v1_seam_config_t sc;
    ninlil_mfdt_v1_spine_ctx_t *sp;
    uint8_t tid[16];
    uint8_t content[4] = {0x11, 0x22, 0x33, 0x44};
    int arm_rc;

    memset(&sc, 0, sizeof(sc));
    sc.policy_on = 1;
    sc.capability = 2;
    sc.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    sc.host_mode = 1;
    sc.session_generation = 1;
    sc.session_cookie = 0x4d464454ull;
    sc.now_ms = 600;
    memset(sc.local_clock_epoch, 0xc0, 16u);
    spine_test_reset(&sc);
    sp = &g_spine;
    memset(tid, 0x73, 16);
    tid[0] = 0xe3;

    expect(ninlil_mfdt_v1_hil_full_promotion_enabled() == 0, "gate default OFF");
    /* Warm store init, then inject CU-NEW-not-promoted on next FULL apply. */
    expect(ninlil_mfdt_v1_spine_arm_sender(tid, content, 4) == 0, "warm arm");
    expect(ninlil_mfdt_v1_spine_disarm(tid) == 0, "warm disarm");
    expect(orphan_count(&sp->store, tid) == 0, "warm clean");

    sp->store.force_cu_new_not_promoted = 1u;
    arm_rc = ninlil_mfdt_v1_spine_arm_sender(tid, content, 4);
    expect(arm_rc != 0, "arm fails under CU inject");
    expect(arm_rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN ||
               arm_rc == NINLIL_MFDT_V1_ERR_CU_NEW_NOT_PROMOTED ||
               arm_rc == NINLIL_MFDT_V1_ERR_STORAGE,
           "arm fail is CU/fence class");
    expect(ninlil_mfdt_v1_spine_is_armed(tid) == 0, "not armed after CU fail");
    expect(orphan_count(&sp->store, tid) == 0, "orphan 0 after CU arm fail");
    expect(ninlil_mfdt_v1_spine_outcome_unknown() == 0,
           "cleanup confirmed → not outcome_unknown");
    expect(ninlil_mfdt_v1_hil_full_promotion_enabled() == 0, "gate still OFF");
}

/*
 * Arm CU + cleanup delete OLD/crash → fence outcome_unknown (reconcile).
 * Not a clean RAM clear / not SUBMISSION_REJECTED-empty-custody.
 */
static void test_arm_cleanup_old_outcome_unknown(void)
{
    ninlil_mfdt_v1_seam_config_t sc;
    ninlil_mfdt_v1_spine_ctx_t *sp;
    uint8_t tid[16];
    uint8_t content[4] = {0x55, 0x66, 0x77, 0x88};
    int arm_rc;
    uint32_t f;

    memset(&sc, 0, sizeof(sc));
    sc.policy_on = 1;
    sc.capability = 2;
    sc.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    sc.host_mode = 1;
    sc.session_generation = 1;
    sc.session_cookie = 0x4d464454ull;
    sc.now_ms = 700;
    memset(sc.local_clock_epoch, 0xc0, 16u);
    spine_test_reset(&sc);
    sp = &g_spine;
    memset(tid, 0x84, 16);
    tid[0] = 0xf4;

    expect(ninlil_mfdt_v1_spine_arm_sender(tid, content, 4) == 0, "warm");
    expect(ninlil_mfdt_v1_spine_disarm(tid) == 0, "warm disarm");
    f = sp->store.full_count;
    sp->store.force_cu_new_not_promoted = 1u;
    /* Next FULL after force_cu success will crash (cleanup delete). */
    sp->store.crash_after_fulls = f + 1u;
    arm_rc = ninlil_mfdt_v1_spine_arm_sender(tid, content, 4);
    expect(arm_rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN, "fence not clean reject");
    expect(sp->last_cleanup_cu == NINLIL_MFDT_V1_CU_OLD,
           "crashed cleanup read-back OLD");
    expect(ninlil_mfdt_v1_spine_outcome_unknown() == 1, "outcome_unknown set");
    expect(ninlil_mfdt_v1_spine_is_armed(tid) == 0, "not transfer-armed");
    /* Durable may still hold NM3S (cleanup failed) — not pretend empty. */
    expect(!key_absent(&sp->store, "NM3S", tid) ||
               orphan_count(&sp->store, tid) > 0,
           "custody residual or orphan requires reconcile");
}

/* Each engine binds scratch to its own exact 64 KiB owner workspace. */
static void test_engine_owner_isolation_and_fini(void)
{
    static ninlil_mfdt_v1_engine_t eng;
    static ninlil_mfdt_v1_engine_t peer;
    static ninlil_mfdt_v1_workspace_t ws;
    static ninlil_mfdt_v1_workspace_t peer_ws;
    static ninlil_mfdt_v1_lab_store_t store;
    static ninlil_mfdt_v1_lab_store_t peer_store;
    ninlil_mfdt_v1_config_t cfg;
    uint8_t tid[16];
    uint8_t content[4] = {1, 2, 3, 4};
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t key[20];
    uint16_t open_len = 0u;
    uint32_t len = 0;

    memset(&cfg, 0, sizeof(cfg));
    cfg.policy = NINLIL_MFDT_V1_POLICY_ON;
    cfg.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    cfg.mfdt_capability = 1u;
    cfg.host_mode = 1u;
    cfg.session_generation = 1u;
    cfg.now_ms = 800ull;
    cfg.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    memset(cfg.local_clock_epoch.bytes, 0xc0, 16u);
    ninlil_mfdt_v1_lab_store_init(&store);
    ninlil_mfdt_v1_lab_store_init(&peer_store);
    expect(ninlil_mfdt_v1_engine_init(&eng, &ws, &store, &cfg) == 0,
           "owner A engine init");
    expect(ninlil_mfdt_v1_engine_init(
               &peer, &peer_ws, &peer_store, &cfg) == 0,
           "owner B engine init");
    expect(eng.slot_record_memory != peer.slot_record_memory &&
               eng.slot_nrc1_memory != peer.slot_nrc1_memory,
           "engine owners have disjoint scratch");
    memset(tid, 0x91, 16);
    expect(ninlil_mfdt_v1_sender_open(
               &eng, tid, content, sizeof(content), open, &open_len, 1ull) == 0,
           "owner A sender open");
    expect(bytes_are_zero(&peer_ws, sizeof(peer_ws)),
           "owner A cannot mutate owner B workspace");
    memcpy(key, "NM3S", 4u);
    memcpy(key + 4u, tid, 16u);
    expect(ninlil_mfdt_v1_lab_get(&store, key, NULL, 0u, &len) == 0 &&
               len > 0u,
           "owner A committed durable custody");
    ninlil_mfdt_v1_engine_fini(&eng);
    expect(bytes_are_zero(&eng, sizeof(eng)) && bytes_are_zero(&ws, sizeof(ws)),
           "engine A fini zeroizes handle and workspace");
    ninlil_mfdt_v1_engine_fini(&peer);
    expect(bytes_are_zero(&peer, sizeof(peer)) &&
               bytes_are_zero(&peer_ws, sizeof(peer_ws)),
           "engine B fini zeroizes handle and workspace");
}

/* Two caller-owned spines are isolated; same-owner reentry fails closed. */
static void test_spine_owner_isolation_reentry_and_fini(void)
{
    ninlil_mfdt_v1_seam_config_t sc;
    ninlil_mfdt_v1_seam_config_t peer_sc;
    ninlil_mfdt_v1_session_t session;
    uint8_t tid[16];
    uint8_t peer_tid[16];
    uint8_t local_id[16];
    uint8_t peer_id[16];
    uint8_t content[4] = {4, 3, 2, 1};

    memset(&sc, 0, sizeof(sc));
    sc.policy_on = 1u;
    sc.capability = 2u;
    sc.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    sc.host_mode = 1u;
    sc.session_generation = 1u;
    sc.session_cookie = 0x4d464454ull;
    sc.now_ms = 900u;
    memset(sc.local_clock_epoch, 0xc0, 16u);
    memset(tid, 0xa5, sizeof(tid));
    memset(peer_tid, 0xb6, sizeof(peer_tid));
    memset(local_id, 0x71, sizeof(local_id));
    memset(peer_id, 0x82, sizeof(peer_id));

    expect(ninlil_mfdt_v1_spine_init(&g_spine) == NINLIL_MFDT_V1_OK,
           "owner A spine init");
    expect(ninlil_mfdt_v1_spine_init(&g_spine_peer) == NINLIL_MFDT_V1_OK,
           "owner B spine init");
    peer_sc = sc;
    peer_sc.session_cookie += 1ull;
    expect(ninlil_mfdt_v1_spine_set_config(&g_spine, &sc) ==
               NINLIL_MFDT_V1_OK,
           "owner A spine config");
    expect(ninlil_mfdt_v1_spine_set_config(&g_spine_peer, &peer_sc) ==
               NINLIL_MFDT_V1_OK,
           "owner B spine config");
    g_spine.busy = 1u;
    expect((ninlil_mfdt_v1_spine_arm_sender)(
               &g_spine_peer, peer_tid, content, sizeof(content)) ==
               NINLIL_MFDT_V1_OK,
           "owner B remains usable while owner A is busy");
    expect((ninlil_mfdt_v1_spine_is_armed)(&g_spine_peer, peer_tid) == 1 &&
               g_spine.armed == 0u && g_spine.engines_ready == 0u,
           "owner B cannot mutate busy owner A");
    expect(ninlil_mfdt_v1_spine_arm_sender(tid, content, sizeof(content)) ==
               NINLIL_MFDT_V1_ERR_BUSY,
           "same-owner reentry rejected");
    g_spine.busy = 0u;
    expect(ninlil_mfdt_v1_spine_outbox_pending() == 0,
           "reentry creates no wire ownership");
    expect(ninlil_mfdt_v1_spine_outcome_unknown() == 0,
           "reentry invents no CU outcome");
    expect(ninlil_mfdt_v1_spine_arm_sender(
               tid, content, sizeof(content)) == NINLIL_MFDT_V1_OK,
           "owner A arm");
    expect((ninlil_mfdt_v1_spine_is_armed)(&g_spine_peer, peer_tid) == 1 &&
               (ninlil_mfdt_v1_spine_is_armed)(&g_spine_peer, tid) == 0,
           "owner A cannot mutate owner B spine");
    ninlil_mfdt_v1_session_init(
        &session, 1u, NINLIL_MFDT_V1_CAP_REQUIRED);
    expect(ninlil_mfdt_v1_session_bind(
               &session, 2u, 1u, 0x4d464454ull, 1u, local_id,
               peer_id) == 0,
           "session mutation has no implicit global apply");
    expect(g_spine_peer.seam.session_cookie == peer_sc.session_cookie,
           "session cannot mutate unrelated spine config");
    ninlil_mfdt_v1_spine_fini(&g_spine_peer);
    expect(bytes_are_zero(&g_spine_peer, sizeof(g_spine_peer)),
           "owner B fini zeroizes complete spine");
    ninlil_mfdt_v1_spine_fini(&g_spine);
    expect(bytes_are_zero(&g_spine, sizeof(g_spine)),
           "owner A fini zeroizes complete spine");
}

int main(void)
{
    g_fail = 0;
    test_spine_owner_isolation_reentry_and_fini();
    test_session_mfn1_negotiation();
    test_full_crash_cu_restart();
    test_delete_group_exact_classification();
    test_spine_arm_and_restart();
    test_disarm_after_failed_commit_semantics();
    test_post_commit_recover_resume_no_duplicate();
    test_commit_fail_disarm_then_terminalize();
    test_arm_disarm_four_keys_absent();
    test_admission_fault_cold_restart_no_recover();
    test_cu_new_not_promoted_arm_fail_orphan_zero();
    test_arm_cleanup_old_outcome_unknown();
    test_engine_owner_isolation_and_fini();
    if (g_fail) {
        fprintf(stderr, "mfdt_v1_media_cu_test FAILED\n");
        return 1;
    }
    printf("mfdt_v1_media_cu_test OK\n");
    return 0;
}
