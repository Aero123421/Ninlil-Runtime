/* SPDX-License-Identifier: Apache-2.0 */
/*
 * M4 linear capability: owner-registry + 128-bit entropy cap_id + capacity
 * fail-closed + alias invalidation + session cancel/close.
 */
#include "wifi_attachment_m4.h"
#include "wifi_session.h"

#include "in_memory_storage.h"

#include <stdio.h>
#include <string.h>

static int failures;
#define CHECK(c)                                                                \
    do {                                                                        \
        if (!(c)) {                                                             \
            (void)fprintf(stderr, "FAIL %s:%d\n", __FILE__, __LINE__);          \
            failures += 1;                                                      \
        }                                                                       \
    } while (0)

static const uint8_t k_fab[32] = {
    0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
};
static const uint8_t k_cred[32] = {
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
    0xd0, 0xe0, 0xf0, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89,
    0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf1, 0x02
};

static void mint_ready_evidence(
    ninlil_wifi_m4_owner_t *owner,
    const ninlil_storage_ops_t *ops,
    void *store,
    ninlil_wifi_m4_full_evidence_t *ev,
    ninlil_wifi_m4_fabric_registry_t *reg,
    const uint8_t peer[16],
    const uint8_t auth[16],
    const uint8_t epoch[16])
{
    CHECK(ninlil_wifi_m4_evidence_reset(owner, ev) == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_m4_membership_load_classify(
              owner, ops, store, "m4", 5000u, ev)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_m4_credential_load_classify(owner, ops, store, "m4", ev)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_m4_attachment_load_classify(owner, ops, store, "m4", peer, ev)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_m4_fabric_registry_bind(reg, k_fab, auth, epoch)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_m4_evidence_apply_fabric_registry(ev, reg)
        == NINLIL_WIFI_OK);
    /* Session-authority mint required — raw durable fill alone is not ready. */
    CHECK(ninlil_wifi_m4_evidence_ready_for_attach(ev) == NINLIL_WIFI_DENIED);
    CHECK(ninlil_wifi_m4_evidence_mark_session_authority(ev) == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_m4_evidence_ready_for_attach(ev) == NINLIL_WIFI_OK);
}

int main(void)
{
    ninlil_wifi_m4_owner_t m4_owner;
    ninlil_wifi_m4_owner_init(&m4_owner);

    ninlil_test_storage_t *store;
    ninlil_test_storage_config_t cfg;
    const ninlil_storage_ops_t *ops;
    ninlil_wifi_m4_full_evidence_t ev;
    ninlil_wifi_m4_membership_lease_t lease;
    ninlil_wifi_m4_fabric_registry_t reg;
    ninlil_wifi_m4_attach_material_t mat;
    uint8_t peer[16];
    uint8_t auth[16];
    uint8_t bind[32];
    uint8_t epoch[16];
    failures = 0;

    CHECK(ninlil_wifi_m4_owner_restart(&m4_owner) == NINLIL_WIFI_OK);

    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.max_namespaces = 4u;
    cfg.max_entries_per_namespace = 32u;
    cfg.max_bytes_per_namespace = 65536u;
    store = ninlil_test_storage_create(&cfg);
    CHECK(store != NULL);
    ops = ninlil_test_storage_ops(store);

    (void)memset(peer, 0xab, sizeof(peer));
    (void)memset(auth, 0xd0, sizeof(auth));
    (void)memset(bind, 0xb1, sizeof(bind));
    (void)memset(epoch, 0xe1, sizeof(epoch));

    CHECK(ninlil_wifi_m4_evidence_reset(&m4_owner, &ev) == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&ev) == NINLIL_WIFI_DENIED);

    (void)memset(&lease, 0, sizeof(lease));
    (void)memcpy(lease.member_runtime_id, peer, 16u);
    lease.lease_not_before_ms = 1000u;
    lease.lease_not_after_ms = 999999u;
    (void)memcpy(lease.authority_id, auth, 16u);
    (void)memcpy(lease.binding_digest, bind, 32u);
    CHECK(ninlil_wifi_m4_membership_store_full(ops, store, "m4", &lease)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_m4_membership_load_classify(
              &m4_owner, ops, store, "m4", 5000u, &ev)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_m4_evidence_membership_live(&ev) == 1);
    CHECK(ninlil_wifi_m4_evidence_class_membership(&ev)
        == NINLIL_WIFI_M4_CLASS_FULL);

    CHECK(ninlil_wifi_m4_credential_store_full(ops, store, "m4", k_cred, 1u)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_m4_credential_load_classify(&m4_owner, ops, store, "m4", &ev)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_m4_attachment_store_full(
              ops, store, "m4", peer, auth, bind, k_cred, k_fab)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_m4_attachment_load_classify(&m4_owner, ops, store, "m4", peer, &ev)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_m4_fabric_registry_bind(&reg, k_fab, auth, epoch)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_m4_evidence_apply_fabric_registry(&ev, &reg)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&ev) == NINLIL_WIFI_DENIED);
    CHECK(ninlil_wifi_m4_evidence_mark_session_authority(&ev) == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&ev) == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_m4_evidence_export_attach_material(&ev, &mat)
        == NINLIL_WIFI_OK);

    /* Alias: copy initially ready; reset/consume invalidates all copies. */
    {
        ninlil_wifi_m4_full_evidence_t alias = ev;
        CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&alias)
            == NINLIL_WIFI_OK);
        CHECK(ninlil_wifi_m4_evidence_reset(&m4_owner, &ev) == NINLIL_WIFI_OK);
        CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&ev)
            == NINLIL_WIFI_DENIED);
        CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&alias)
            == NINLIL_WIFI_DENIED);
        ninlil_wifi_m4_evidence_consume(&ev);
    }

    {
        ninlil_wifi_m4_full_evidence_t alias;
        mint_ready_evidence(&m4_owner, ops, store, &ev, &reg, peer, auth, epoch);
        alias = ev;
        ninlil_wifi_m4_evidence_consume(&ev);
        CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&ev)
            == NINLIL_WIFI_DENIED);
        CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&alias)
            == NINLIL_WIFI_DENIED);
    }

    /* Owner restart rejects old handles (including relocated copies). */
    {
        ninlil_wifi_m4_full_evidence_t relocated;
        mint_ready_evidence(&m4_owner, ops, store, &ev, &reg, peer, auth, epoch);
        relocated = ev;
        CHECK(ninlil_wifi_m4_owner_restart(&m4_owner) == NINLIL_WIFI_OK);
        CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&ev)
            == NINLIL_WIFI_DENIED);
        CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&relocated)
            == NINLIL_WIFI_DENIED);
        mint_ready_evidence(&m4_owner, ops, store, &ev, &reg, peer, auth, epoch);
        CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&relocated)
            == NINLIL_WIFI_DENIED);
        ninlil_wifi_m4_evidence_consume(&ev);
    }

    /*
     * Capacity: fill all slots, further reset returns CAPACITY without
     * mutating/evicting live capabilities; recovery after consume.
     */
    {
        ninlil_wifi_m4_full_evidence_t live[NINLIL_WIFI_M4_OWNER_SLOT_COUNT];
        ninlil_wifi_m4_full_evidence_t extra;
        ninlil_wifi_m4_full_evidence_t live_copy[NINLIL_WIFI_M4_OWNER_SLOT_COUNT];
        uint32_t i;
        CHECK(ninlil_wifi_m4_owner_restart(&m4_owner) == NINLIL_WIFI_OK);
        for (i = 0u; i < NINLIL_WIFI_M4_OWNER_SLOT_COUNT; ++i) {
            mint_ready_evidence(
                &m4_owner, ops, store, &live[i], &reg, peer, auth, epoch);
            live_copy[i] = live[i];
            CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&live[i])
                == NINLIL_WIFI_OK);
        }
        CHECK(ninlil_wifi_m4_evidence_reset(&m4_owner, &extra) == NINLIL_WIFI_CAPACITY);
        CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&extra)
            == NINLIL_WIFI_DENIED);
        /* No eviction: all prior live handles still ready. */
        for (i = 0u; i < NINLIL_WIFI_M4_OWNER_SLOT_COUNT; ++i) {
            CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&live[i])
                == NINLIL_WIFI_OK);
            CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&live_copy[i])
                == NINLIL_WIFI_OK);
        }
        /* Free one via consume; reset recovers. */
        ninlil_wifi_m4_evidence_consume(&live[0]);
        CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&live_copy[0])
            == NINLIL_WIFI_DENIED);
        CHECK(ninlil_wifi_m4_evidence_reset(&m4_owner, &extra) == NINLIL_WIFI_OK);
        CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&extra)
            == NINLIL_WIFI_DENIED); /* empty not ready */
        for (i = 1u; i < NINLIL_WIFI_M4_OWNER_SLOT_COUNT; ++i) {
            ninlil_wifi_m4_evidence_consume(&live[i]);
        }
        ninlil_wifi_m4_evidence_consume(&extra);
    }

    /* Wrong cap_id on otherwise correct-looking handle → DENIED. */
    {
        ninlil_wifi_m4_full_evidence_t forged;
        mint_ready_evidence(&m4_owner, ops, store, &ev, &reg, peer, auth, epoch);
        forged = ev;
        /*
         * Private handle: magic@0 slot@4 gen@8 epoch@16 cap_id@24 (16B).
         * Flip cap_id only; counters left intact.
         */
        forged.opaque[24] ^= 0x5au;
        forged.opaque[31] ^= 0xa5u;
        forged.opaque[39] ^= 0x3cu;
        CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&forged)
            == NINLIL_WIFI_DENIED);
        CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&ev) == NINLIL_WIFI_OK);
        ninlil_wifi_m4_evidence_consume(&ev);
    }

    /* Free-assert DENIED; forged accept does not confirm. */
    {
        ninlil_wifi_session_t s;
        ninlil_wifi_m4_full_evidence_t forged;
        ninlil_wifi_session_init(&s);
        s.phase = NINLIL_WIFI_PHASE_PEER_SESSION;
        s.peer_session_valid = 1;
        (void)memcpy(s.ids.peer_session_id, peer, 16u);
        CHECK(ninlil_wifi_session_confirm_m4_pa_full(&s, auth, bind)
            == NINLIL_WIFI_DENIED);
        (void)memset(&forged, 0, sizeof(forged));
        CHECK(ninlil_wifi_session_accept_m4_full_evidence(&s, &forged)
            == NINLIL_WIFI_OK);
        CHECK(s.m4_pa_full_confirmed == 0);
        ninlil_wifi_session_close(&s);
        ninlil_wifi_session_fence(&s);
        CHECK(s.m4_pa_full_confirmed == 0);
    }

    /* Session close does not re-mint; consume cancels aliases. */
    {
        ninlil_wifi_session_t s;
        ninlil_wifi_m4_full_evidence_t alias;
        mint_ready_evidence(&m4_owner, ops, store, &ev, &reg, peer, auth, epoch);
        alias = ev;
        ninlil_wifi_session_init(&s);
        ninlil_wifi_session_close(&s);
        CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&ev) == NINLIL_WIFI_OK);
        ninlil_wifi_m4_evidence_consume(&ev);
        CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&alias)
            == NINLIL_WIFI_DENIED);
    }


    /* Forged/random handle must not be admitted by load_classify. */
    {
        ninlil_wifi_m4_full_evidence_t forged;
        ninlil_wifi_m4_owner_t other;
        ninlil_wifi_m4_owner_init(&other);

        /* Pattern 1: random non-empty opaque. */
        (void)memset(&forged, 0x5a, sizeof(forged));
        CHECK(ninlil_wifi_m4_membership_load_classify(
                  &other, ops, store, "m4", 5000u, &forged)
            == NINLIL_WIFI_DENIED);
        CHECK(ninlil_wifi_m4_attachment_load_classify(
                  &other, ops, store, "m4", peer, &forged)
            == NINLIL_WIFI_DENIED);
        CHECK(ninlil_wifi_m4_credential_load_classify(
                  &other, ops, store, "m4", &forged)
            == NINLIL_WIFI_DENIED);
        CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&forged)
            == NINLIL_WIFI_DENIED);

        /* Pattern 2: synthetic first-slot (magic/gen/epoch, no real cap_id). */
        (void)memset(&forged, 0, sizeof(forged));
        forged.opaque[0] = 0x4cu;
        forged.opaque[1] = 0x48u;
        forged.opaque[2] = 0x34u;
        forged.opaque[3] = 0x4du; /* 'M4HL' LE */
        forged.opaque[8] = 1u; /* generation = 1 */
        forged.opaque[16] = 1u; /* owner_epoch = 1 */
        CHECK(ninlil_wifi_m4_membership_load_classify(
                  &other, ops, store, "m4", 5000u, &forged)
            == NINLIL_WIFI_DENIED);

        /* Pattern 3: all-FF. */
        (void)memset(forged.opaque, 0xff, sizeof(forged.opaque));
        CHECK(ninlil_wifi_m4_membership_load_classify(
                  &other, ops, store, "m4", 5000u, &forged)
            == NINLIL_WIFI_DENIED);

        /* Owner A restart must not clear owner B (instance-scoped). */
        {
            ninlil_wifi_m4_full_evidence_t a_ev;
            ninlil_wifi_m4_full_evidence_t b_ev;
            ninlil_wifi_m4_owner_t a;
            ninlil_wifi_m4_owner_t b;
            ninlil_wifi_m4_owner_init(&a);
            ninlil_wifi_m4_owner_init(&b);
            CHECK(ninlil_wifi_m4_evidence_reset(&a, &a_ev) == NINLIL_WIFI_OK);
            CHECK(ninlil_wifi_m4_evidence_reset(&b, &b_ev) == NINLIL_WIFI_OK);
            CHECK(ninlil_wifi_m4_owner_restart(&a) == NINLIL_WIFI_OK);
            CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&a_ev)
                == NINLIL_WIFI_DENIED);
            /* b still a live empty handle for owner b (not ready, but owned) */
            CHECK(ninlil_wifi_m4_evidence_class_membership(&b_ev)
                == NINLIL_WIFI_M4_CLASS_MISSING);
            ninlil_wifi_m4_evidence_consume(&b_ev);
        }
    }

    ninlil_test_storage_destroy(store);
    CHECK(ninlil_wifi_m4_owner_restart(&m4_owner) == NINLIL_WIFI_OK);
    if (failures != 0) {
        return 1;
    }
    (void)printf("wifi_v1_m4_evidence_test PASS\n");
    return 0;
}

/* Linked as part of same binary: forged/random handle into load_classify. */
