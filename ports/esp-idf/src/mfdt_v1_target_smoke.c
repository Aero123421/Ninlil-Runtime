/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ESP MFDT feature-ON target smoke (not map-symbol-only completion).
 *
 * Required PASS (return 0):
 *   1) Live symbols: bound MFN1 OFFER/ACCEPT, ncl1_encode, spine callable
 *   2) Raw durable NEW classification after FULL (CU read-back or STORAGE_OK)
 *   3) HIL full-promotion gate remains OFF (release path NOT_PROMOTED)
 *
 * Engine external/wire success after CU-NEW is intentionally fail-closed
 * without physical HIL (ADR-0021 §738-740). Fault-inject CU/OLD/fence lives in
 * host mfdt_v1_esp_store_cu_test.
 */
#include "mfdt_v1_target_smoke.h"

#include "mfdt_v1.h"
#include "mfdt_v1_bearer_worker.h"
#include "mfdt_v1_foundation_carrier.h"
#include "mfdt_v1_ncl1.h"
#include "mfdt_v1_session.h"
#include "mfdt_v1_spine.h"
#include "mfdt_v1_target_alloc.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

size_t ninlil_mfdt_v1_target_smoke_rx_workspace_bytes(void)
{
    return (size_t)NINLIL_MFDT_V1_WORKSPACE_BYTES;
}

static int32_t target_smoke_finish(
    ninlil_mfdt_v1_spine_ctx_t *spine, int32_t result)
{
    ninlil_mfdt_v1_spine_fini(spine);
    ninlil_mfdt_v1_target_free(spine);
    return result;
}

int32_t ninlil_mfdt_v1_target_smoke_run(const void *storage_ops,
                                        void *storage_handle)
{
    ninlil_mfdt_v1_session_t sess;
    ninlil_mfdt_v1_session_t peer;
    ninlil_service_identity_t carrier_service;
    ninlil_mfdt_v1_seam_config_t sc;
    ninlil_mfdt_v1_spine_ctx_t *sp;
    ninlil_mfdt_v1_lab_store_t *st;
    uint8_t key[20];
    uint8_t newv[16];
    uint8_t out[16];
    uint8_t ncl1_probe[64];
    uint8_t body[8];
    uint8_t tid[16];
    uint8_t local_id[16];
    uint8_t peer_id[16];
    uint8_t offer_nonce[16];
    uint8_t accept_nonce[16];
    uint8_t offer[NINLIL_MFDT_V1_NEGOTIATE_MAX_WIRE_BYTES];
    uint8_t accept[NINLIL_MFDT_V1_NEGOTIATE_MAX_WIRE_BYTES];
    size_t ncl1_len = 0u;
    size_t offer_len = 0u;
    size_t accept_len = 0u;
    uint32_t len = 0u;
    int rc;
    int cu;
    int arm_rc;

    if (storage_ops == NULL) {
        return -18;
    }

    /* Production bearer worker TU is live and its invalid seam fails closed. */
    if (ninlil_mfdt_v1_bearer_worker_init(
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0u) !=
            NINLIL_MFDT_V1_ERR_PARAM ||
        ninlil_mfdt_v1_bearer_worker_step(NULL) !=
            NINLIL_MFDT_V1_ERR_PARAM) {
        return -16;
    }
    /*
     * Target-link the exact private Foundation/Fabric service identity. This
     * is a compile/map proof only; physical Wi-Fi/RF carriage remains HIL.
     */
    if (ninlil_mfdt_v1_foundation_carrier_service_identity(
            &carrier_service) != NINLIL_MFDT_V1_OK
        || carrier_service.family != NINLIL_FAMILY_TRANSFER_RESERVED
        || carrier_service.namespace_id.length == 0u
        || carrier_service.service_id.length == 0u
        || carrier_service.schema_id.length == 0u) {
        return -17;
    }

    /* Gate must stay fail-closed in CI / pre-HIL release path. */
    if (ninlil_mfdt_v1_hil_full_promotion_enabled() != 0) {
        return -1; /* refuse forged/fixed ON */
    }

    /* 1) Live session + ncl1 symbols */
    (void)memset(local_id, 0x61, sizeof(local_id));
    (void)memset(peer_id, 0x72, sizeof(peer_id));
    (void)memset(offer_nonce, 0x83, sizeof(offer_nonce));
    (void)memset(accept_nonce, 0x94, sizeof(accept_nonce));
    ninlil_mfdt_v1_session_init(
        &sess, 1u, NINLIL_MFDT_V1_CAP_REQUIRED);
    ninlil_mfdt_v1_session_init(
        &peer, 1u, NINLIL_MFDT_V1_CAP_REQUIRED);
    if (ninlil_mfdt_v1_session_bind(
            &sess, 2u, 1u, 0x4d464454ull, 0u, local_id, peer_id) != 0 ||
        ninlil_mfdt_v1_session_bind(
            &peer, 2u, 1u, 0x4d464454ull, 0u, peer_id, local_id) != 0 ||
        ninlil_mfdt_v1_session_build_offer(
            &sess, 1u, offer_nonce, offer, sizeof(offer), &offer_len) != 0 ||
        ninlil_mfdt_v1_session_on_offer(
            &peer, offer, offer_len, accept_nonce, accept, sizeof(accept),
            &accept_len) != 0 ||
        ninlil_mfdt_v1_session_on_accept(&sess, accept, accept_len) != 0) {
        return -2;
    }
    if (sess.base_control_version != 2u ||
        sess.mfdt_admission_version !=
            NINLIL_MFDT_V1_ADMISSION_VERSION ||
        !ninlil_mfdt_v1_session_carrier_ncl1_data_ok(&sess)) {
        return -3;
    }
    (void)memset(body, 0xa5, sizeof(body));
    if (ninlil_mfdt_v1_ncl1_encode(NINLIL_MFDT_V1_MSG_OPEN, 1u, 1u, 0x4d464454ull,
                                   body, (uint16_t)sizeof(body), ncl1_probe,
                                   sizeof(ncl1_probe), &ncl1_len) != 0 ||
        ncl1_len == 0u) {
        return -4;
    }

    /* 2) Raw store NEW classification on bound ESP media (small key). */
    sp = (ninlil_mfdt_v1_spine_ctx_t *)ninlil_mfdt_v1_target_zalloc(
        sizeof(*sp));
    if (sp == NULL) {
        return -5;
    }
    if (ninlil_mfdt_v1_spine_init(sp) != NINLIL_MFDT_V1_OK) {
        return target_smoke_finish(sp, -5);
    }
    st = &sp->store;
    if (ninlil_mfdt_v1_esp_store_bind(
            st, storage_ops, storage_handle) != NINLIL_MFDT_V1_OK) {
        return target_smoke_finish(sp, -6);
    }
    (void)memset(&sc, 0, sizeof(sc));
    sc.policy_on = 1u;
    sc.capability = 2u;
    sc.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    sc.host_mode = 0u;
    sc.session_generation = 1u;
    sc.session_cookie = 0x4d464454ull;
    sc.now_ms = 1000u;
    (void)memset(sc.local_clock_epoch, 0xc0,
                 sizeof(sc.local_clock_epoch));
    if (ninlil_mfdt_v1_spine_set_config(sp, &sc) !=
        NINLIL_MFDT_V1_OK) {
        return target_smoke_finish(sp, -5);
    }

    (void)memset(key, 0x4d, sizeof(key));
    (void)memcpy(key, "NM3S", 4u);
    (void)memset(newv, 0xCE, sizeof(newv));
    newv[0] = 0x4eu; /* 'N' */
    newv[1] = 0x45u; /* 'E' */
    newv[2] = 0x57u; /* 'W' */

    if (ninlil_mfdt_v1_lab_full_begin(st) != 0) {
        return target_smoke_finish(sp, -6);
    }
    if (ninlil_mfdt_v1_lab_put(st, key, newv, (uint32_t)sizeof(newv)) != 0) {
        (void)ninlil_mfdt_v1_lab_full_rollback(st);
        return target_smoke_finish(sp, -7);
    }
    rc = ninlil_mfdt_v1_lab_full_commit(st);
    /*
     * Accept STORAGE_OK (true FULL) or CU_NEW_NOT_PROMOTED (raw NEW after
     * read-back). Never accept silent OK promotion of unattested CU via gate.
     */
    if (rc != NINLIL_MFDT_V1_OK &&
        rc != NINLIL_MFDT_V1_ERR_CU_NEW_NOT_PROMOTED) {
        return target_smoke_finish(
            sp, -8); /* OLD/fence/storage — not a residual pass */
    }
    if (rc == NINLIL_MFDT_V1_ERR_CU_NEW_NOT_PROMOTED) {
        cu = ninlil_mfdt_v1_esp_last_cu_class(st);
        if (cu != (int)NINLIL_MFDT_V1_CU_NEW) {
            return target_smoke_finish(sp, -8);
        }
    }
    len = 0u;
    if (ninlil_mfdt_v1_lab_get(st, key, out, (uint32_t)sizeof(out), &len) != 0 ||
        len != (uint32_t)sizeof(newv) ||
        !ninlil_mfdt_v1_memeq(out, newv, sizeof(newv))) {
        return target_smoke_finish(sp, -9); /* durable NEW read-back failed */
    }
    /* Length-probe ABI (engine restart path). */
    len = 0u;
    if (ninlil_mfdt_v1_lab_get(st, key, NULL, 0u, &len) != 0 ||
        len != (uint32_t)sizeof(newv)) {
        return target_smoke_finish(sp, -10);
    }

    /* 3) Release path NOT_PROMOTED: gate OFF; engine arm must not claim success
     * solely from unattested CU-NEW (may still fail for other reasons). */
    if (ninlil_mfdt_v1_hil_full_promotion_enabled() != 0) {
        return target_smoke_finish(sp, -11);
    }
    (void)memset(tid, 0x42, sizeof(tid));
    tid[0] = 0xA1;
    arm_rc = ninlil_mfdt_v1_spine_arm_sender(
        sp, tid, newv, (uint32_t)sizeof(newv));
    /*
     * With gate OFF, CU-NEW becomes ERR_COMMIT_UNKNOWN at engine boundary.
     * True STORAGE_OK media might still arm; either way we require gate OFF
     * and raw NEW already proven above. If arm succeeds, transfer must not be
     * "complete" from self-loop.
     */
    if (arm_rc == 0) {
        if (ninlil_mfdt_v1_spine_transfer_complete(sp) != 0) {
            return target_smoke_finish(sp, -12);
        }
        (void)ninlil_mfdt_v1_spine_disarm(sp, tid);
    } else if (arm_rc != NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN &&
               arm_rc != NINLIL_MFDT_V1_ERR_STORAGE &&
               arm_rc != NINLIL_MFDT_V1_ERR_CU_NEW_NOT_PROMOTED) {
        return target_smoke_finish(sp, -13);
    }

    if (ninlil_mfdt_v1_hil_full_promotion_enabled() != 0) {
        return target_smoke_finish(sp, -14);
    }
    if (ncl1_probe[0] == 0u && ncl1_len == 0u) {
        return target_smoke_finish(sp, -15);
    }
    /*
     * Keep live wire ownership symbols reachable from smoke (map proof):
     * take_outbound / on_ncl1_data must not be GC'd from the final ELF.
     */
    if (ninlil_mfdt_v1_spine_outbox_pending(sp) != 0) {
        size_t out_len = 0u;
        uint8_t out_frame[64];
        (void)ninlil_mfdt_v1_spine_take_outbound_ncl1(
            sp, out_frame, sizeof(out_frame), &out_len);
        (void)out_len;
    }
    /* Reject empty ingress (symbol pin); no self-loop complete. */
    (void)ninlil_mfdt_v1_spine_on_ncl1_data(sp, NULL, 0u);
    return target_smoke_finish(
        sp, 0); /* raw NEW PASS + release NOT_PROMOTED */
}
