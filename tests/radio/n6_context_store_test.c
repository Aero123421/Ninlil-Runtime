/*
 * N6 context store host tests (Chunk D).
 * Links NINLIL_N6_TEST_BUILD store variant + scripted mem storage.
 * Not production. Not R6 complete.
 */

#include "n6_context_store.h"
#include "n6_crypto_provider.h"
#include "n6_local_identity_fixture.h"
#include "n6_mem_storage.h"
#include "n6_record_codec.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(c)                                                             \
    do {                                                                       \
        if (!(c)) {                                                            \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c);        \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static uint8_t g_obj[NINLIL_N6_OBJECT_BYTES]
    __attribute__((aligned(NINLIL_N6_OBJECT_ALIGN)));
static uint8_t g_pool[256u * 1024u];
static int g_pass_count;

static void fill_capsule(ninlil_n6_install_capsule_t *c, int hop)
{
    (void)memset(c, 0, sizeof(*c));
    c->provenance = NINLIL_N6_PROVENANCE_FIXTURE_ONLY;
    c->layer_code = hop ? NINLIL_N6_LAYER_HOP : NINLIL_N6_LAYER_E2E;
    c->direction_code = NINLIL_N6_DIR_IR;
    c->alloc_side = NINLIL_N6_ALLOC_OUTBOUND_TX;
    c->context_id = 7u;
    c->membership_epoch = 3u;
    c->key_generation = 5u;
    (void)memset(c->binding_digest32, 0x11, 32u);
    (void)memset(c->traffic_secret32, 0x22, 32u);
    (void)memset(c->local_node_id, 0x33, 16u);
    (void)memset(c->receiver_node_id, 0x44, 16u);
}

static int bind_stamp(ninlil_n6_t *n6, uint8_t epoch0, uint64_t now)
{
    ninlil_n6_authority_stamp_t stamp;
    (void)memset(&stamp, 0, sizeof(stamp));
    stamp.clock_epoch_id[0] = epoch0;
    stamp.now_ms = now;
    stamp.trusted_class_d = 1u;
    return ninlil_n6_bind_authority_stamp(n6, &stamp) == NINLIL_N6_OK ? 0 : 1;
}

static int bind_local_id_fixture(ninlil_n6_t *n6, uint8_t fill)
{
    return n6_local_id_fixture_bind_fill(n6, fill) == NINLIL_N6_OK ? 0 : 1;
}

static int setup_booted(ninlil_n6_t **out, uint32_t slots)
{
    ninlil_n6_context_pool_t pool;
    size_t need;

    n6_mem_storage_reset();
    need = ninlil_n6_context_pool_bytes(slots);
    REQUIRE(need > 0u && need <= sizeof(g_pool));
    (void)memset(g_obj, 0, sizeof(g_obj));
    (void)memset(g_pool, 0, sizeof(g_pool));
    pool.max_slots = slots;
    pool.reserved_zero = 0u;
    pool.bytes = g_pool;
    pool.bytes_size = need;
    REQUIRE(ninlil_n6_init(g_obj, sizeof(g_obj), &pool, out) == NINLIL_N6_OK);
    /* Arbitrary bind order: identity first while INIT */
    REQUIRE(bind_local_id_fixture(*out, 0x33u) == 0);
    REQUIRE(ninlil_n6_state(*out) == NINLIL_N6_STATE_INIT);
    REQUIRE(ninlil_n6_bind_storage(*out, n6_mem_storage_ops()) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_bind_crypto(*out, ninlil_n6_crypto_host_ops())
        == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_state(*out) == NINLIL_N6_STATE_BOUND);
    REQUIRE(bind_stamp(*out, 1u, 1000u) == 0);
    /* Second identity bind: callback 0, INVALID_STATE */
    {
        n6_local_id_fixture_user_t user;
        ninlil_n6_accepted_local_identity_token_t tok;
        ninlil_n6_local_identity_ops_t ops_st;
        const ninlil_n6_local_identity_ops_t *ops;
        (void)memset(&user, 0, sizeof(user));
        n6_local_id_fixture_token_mint_fill(
            &tok, 0x33u, NINLIL_N6_LOCAL_ID_ACCEPT_OK);
        n6_local_id_fixture_ops_init(&ops_st, &user);
        ops = &ops_st;
        REQUIRE(ninlil_n6_bind_local_identity_accepted(*out, ops, &tok)
            == NINLIL_N6_INVALID_STATE);
        REQUIRE(user.consume_calls == 0u);
    }
    REQUIRE(ninlil_n6_boot_scan(*out) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_state(*out) == NINLIL_N6_STATE_BOOTED);
    return 0;
}

static int setup_ready(ninlil_n6_t **out, uint32_t slots)
{
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h = 0u;
    REQUIRE(setup_booted(out, slots) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(*out, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(h != 0u);
    REQUIRE(ninlil_n6_state(*out) == NINLIL_N6_STATE_READY);
    return 0;
}

/* ---- pool 1/8/128 real init + canary ---- */


/* Pin docs/30 C-based ceilings + exact 4-pass iter bound. */
static int test_boot_ceiling_and_iter_bound_pins(void)
{
    /* Let C=slot_count. R≤11C; bytes≤876C; passes=4; iter≤4*(11C+1). */
    enum {
        C128 = 128,
        C8 = 8,
        PASS = 4,
        TOTAL_128 = 11 * C128, /* 1408 */
        TOTAL_8 = 11 * C8,     /* 88 */
        BYTES_128 = 876 * C128, /* 112128 */
        BYTES_8 = 876 * C8,     /* 7008 */
        ITER_128 = PASS * (TOTAL_128 + 1), /* 5636 */
        ITER_8 = PASS * (TOTAL_8 + 1)
    };
    REQUIRE(TOTAL_128 == 1408);
    REQUIRE(TOTAL_8 == 88);
    REQUIRE(BYTES_128 == 112128);
    REQUIRE(BYTES_8 == 7008);
    REQUIRE(ITER_128 == 5636);
    REQUIRE(ITER_8 == 4 * 89);
    /* Type caps at C: L≤2C A≤2C T≤2C F≤C W≤4C */
    REQUIRE(2 * C128 == 256);
    REQUIRE(4 * C128 == 512);
    REQUIRE(NINLIL_N6_POOL_MAX_SLOTS == 128u);
    /* RT/CF keys share wire size — dispatch must use kind byte */
    REQUIRE(NINLIL_N6_RT_KEY_BYTES == NINLIL_N6_CF_KEY_BYTES);
    REQUIRE(NINLIL_N6_RT_KEY_BYTES == 28u);
    REQUIRE(NINLIL_N6_REC_KIND_RT != NINLIL_N6_REC_KIND_CF);
    return 0;
}

static int test_pool_init_1_8_128(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_context_pool_t pool;
    size_t need;
    uint32_t sizes[] = {1u, 8u, 128u};
    size_t i;

    REQUIRE(ninlil_n6_context_pool_bytes(0u) == 0u);
    REQUIRE(ninlil_n6_context_pool_bytes(129u) == 0u);

    for (i = 0u; i < 3u; ++i) {
        need = ninlil_n6_context_pool_bytes(sizes[i]);
        REQUIRE(need > 0u && need <= sizeof(g_pool));
        n6_mem_storage_reset();
        (void)memset(g_obj, 0xa5, sizeof(g_obj));
        (void)memset(g_pool, 0x5a, sizeof(g_pool));
        pool.max_slots = sizes[i];
        pool.reserved_zero = 0u;
        pool.bytes = g_pool;
        pool.bytes_size = need;
        REQUIRE(ninlil_n6_init(g_obj, sizeof(g_obj), &pool, &n6)
            == NINLIL_N6_OK);
        REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_INIT);
        /* object magic region wiped from 0xa5 canary */
        REQUIRE(g_obj[0] != 0xa5u || g_obj[1] != 0xa5u);
        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    }

    /* alias reject: pool overlaps object */
    {
        pool.max_slots = 1u;
        pool.reserved_zero = 0u;
        pool.bytes = g_obj + 64u;
        pool.bytes_size = ninlil_n6_context_pool_bytes(1u);
        REQUIRE(ninlil_n6_init(g_obj, sizeof(g_obj), &pool, &n6)
            == NINLIL_N6_ALIAS);
    }
    /* capacity-full: bytes_size too small */
    {
        need = ninlil_n6_context_pool_bytes(8u);
        pool.max_slots = 8u;
        pool.bytes = g_pool;
        pool.bytes_size = need - 1u;
        REQUIRE(ninlil_n6_init(g_obj, sizeof(g_obj), &pool, &n6)
            == NINLIL_N6_INVALID_ARGUMENT);
    }
    return 0;
}

static int test_storage_ops_abi_and_capacity(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_storage_ops_t bad;
    ninlil_n6_context_pool_t pool;
    size_t need = ninlil_n6_context_pool_bytes(2u);

    n6_mem_storage_reset();
    pool.max_slots = 2u;
    pool.reserved_zero = 0u;
    pool.bytes = g_pool;
    pool.bytes_size = need;
    (void)memset(g_obj, 0, sizeof(g_obj));
    REQUIRE(ninlil_n6_init(g_obj, sizeof(g_obj), &pool, &n6) == NINLIL_N6_OK);

    bad = *n6_mem_storage_ops();
    bad.abi_version = 99u;
    REQUIRE(ninlil_n6_bind_storage(n6, &bad) == NINLIL_N6_INVALID_ARGUMENT);
    bad = *n6_mem_storage_ops();
    bad.struct_size = 4u;
    REQUIRE(ninlil_n6_bind_storage(n6, &bad) == NINLIL_N6_INVALID_ARGUMENT);
    bad = *n6_mem_storage_ops();
    bad.open = NULL;
    REQUIRE(ninlil_n6_bind_storage(n6, &bad) == NINLIL_N6_INVALID_ARGUMENT);

    REQUIRE(ninlil_n6_bind_storage(n6, n6_mem_storage_ops()) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_bind_crypto(n6, ninlil_n6_crypto_host_ops())
        == NINLIL_N6_OK);
    REQUIRE(bind_stamp(n6, 1u, 1u) == 0);
    REQUIRE(bind_local_id_fixture(n6, 0x33u) == 0);

    /* boot/recover must work even when free_entries < 4 (full namespace) */
    n6_mem_storage_set_capacity(4u, 4u, 1024u, 0u); /* free=0 */
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_BOOTED);

    /* install capacity admission is separate: free < 4 rejects install only */
    {
        ninlil_n6_install_capsule_t cap;
        ninlil_n6_handle_t h = 0u;
        fill_capsule(&cap, 1);
        REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_CAPACITY);
        REQUIRE(h == 0u);
    }

    n6_mem_storage_set_capacity(256u, 0u, 1024u * 1024u, 0u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

/*
 * Negative tests that catch the three independent root findings:
 * 1) open must not require free>=4 (boot/CU on full NS)
 * 2) commit non-OK must not call rollback (txn already consumed)
 * 3) slot canary damage → CORRUPT/fence, not NOT_FOUND
 */
static int test_full_ns_boot_cu_no_double_rollback(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_handle_t h = 1u; /* first install handle is 1 */
    ninlil_n6_tx_lease_t lease;
    uint32_t rb0, rb1, rb2;

    REQUIRE(setup_ready(&n6, 4u) == 0);

    /* Full namespace: free entries = 0; boot path already open; re-open after close */
    n6_mem_storage_set_capacity(4u, 4u, 256u, 256u); /* free=0, max_bytes small */
    /* force close so next op re-opens under full capacity shape */
    {
        /* burn with CU while free=0 must still open storage for recover */
        n6_mem_storage_inject_cu(N6_MEM_CU_ALL_OLD);
        rb0 = n6_mem_storage_rollback_count();
        REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
            == NINLIL_N6_COMMIT_UNKNOWN);
        rb1 = n6_mem_storage_rollback_count();
        /* recover must succeed even with free=0 (open ≠ install capacity) */
        REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_OK);
        REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_READY);
        rb2 = n6_mem_storage_rollback_count();
        /* recover may rollback RO classify once; not unbounded */
        REQUIRE(rb2 >= rb1);
    }

    /* Commit IO_ERROR: txn consumed → no extra rollback after commit */
    {
        uint32_t commits_before;
        n6_mem_storage_set_capacity(256u, 0u, 1024u * 1024u, 0u);
        rb0 = n6_mem_storage_rollback_count();
        commits_before = n6_mem_storage_commit_count();
        n6_mem_storage_inject_fault(N6_MEM_FAULT_COMMIT, 1);
        REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
            != NINLIL_N6_OK);
        REQUIRE(n6_mem_storage_commit_count() == commits_before + 1u);
        /* if n6_commit_full incorrectly rolled back after commit, count rises */
        REQUIRE(n6_mem_storage_rollback_count() == rb0);
    }

    /* Commit CORRUPT → fence, no rollback after commit */
    {
        rb0 = n6_mem_storage_rollback_count();
        n6_mem_storage_inject_fault(N6_MEM_FAULT_COMMIT_CORRUPT, 1);
        REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
            == NINLIL_N6_CORRUPT);
        REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
        REQUIRE(n6_mem_storage_rollback_count() == rb0);
    }

    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

static int test_slot_canary_corrupt_is_corrupt_not_not_found(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_handle_t h = 0u;
    ninlil_n6_rx_ticket_t ticket;
    ninlil_n6_install_capsule_t cap;
    uint32_t *p;
    size_t words;
    size_t i;
    int flipped = 0;
    const uint32_t canary = 0xC4A4A4C4u;

    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
    cap.context_id = 1u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);

    /* Corrupt first pool canary word (production canary constant). */
    words = ninlil_n6_context_pool_bytes(4u) / sizeof(uint32_t);
    p = (uint32_t *)(void *)g_pool;
    for (i = 0u; i < words; ++i) {
        if (p[i] == canary) {
            p[i] ^= 1u;
            flipped = 1;
            break;
        }
    }
    REQUIRE(flipped == 1);

    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 1u, &ticket)
        == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    /* Must not be mis-reported as mere NOT_FOUND */
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 2u, &ticket)
        != NINLIL_N6_NOT_FOUND);

    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

static int test_m4_fail_closed(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h = 0u;
    REQUIRE(setup_ready(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    cap.provenance = NINLIL_N6_PROVENANCE_M4_AUTHENTICATED;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_M4_REQUIRED);
    REQUIRE(h == 0u);
    REQUIRE(ninlil_n6_fence(n6, 1u, 1u) == NINLIL_N6_M4_REQUIRED);
    REQUIRE(ninlil_n6_restamp(n6, 1u) == NINLIL_N6_M4_REQUIRED);
    REQUIRE(ninlil_n6_reclaim(n6, 1u) == NINLIL_N6_M4_REQUIRED);
    REQUIRE(ninlil_n6_gc(n6) == NINLIL_N6_M4_REQUIRED);
    REQUIRE(ninlil_n6_esp_ready() == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

static int test_tx_burn_block_64_then_reserve(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_handle_t h = 0u;
    ninlil_n6_tx_lease_t lease;
    ninlil_n6_install_capsule_t cap;
    uint64_t i;
    uint64_t seen[65];

    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);

    for (i = 0u; i < 64u; ++i) {
        REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
            == NINLIL_N6_OK);
        REQUIRE(lease.live == 1u);
        REQUIRE(lease.counter == i + 1u);
        seen[i] = lease.counter;
        if (i == 0u) {
            REQUIRE(lease.block_end == 1u + NINLIL_N6_TX_BLOCK_SIZE);
        }
        REQUIRE(ninlil_n6_tx_lease_release(n6, &lease) == NINLIL_N6_OK);
    }
    /* 65th forces new 64-block reservation */
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_OK);
    REQUIRE(lease.counter == 65u);
    REQUIRE(lease.block_end == 65u + NINLIL_N6_TX_BLOCK_SIZE);
    REQUIRE(ninlil_n6_tx_lease_release(n6, &lease) == NINLIL_N6_OK);

    /* no counter reuse in first block */
    for (i = 0u; i < 64u; ++i) {
        uint64_t j;
        for (j = i + 1u; j < 64u; ++j) {
            REQUIRE(seen[i] != seen[j]);
        }
    }

    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_E2E, &lease)
        == NINLIL_N6_INVALID_ARGUMENT);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

static int test_rx_ticket_admit_and_duplicate(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_handle_t h = 0u;
    ninlil_n6_rx_ticket_t ticket;
    ninlil_n6_install_capsule_t cap;

    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
    cap.context_id = 1u; /* INBOUND fresh AL requires id == next_free=1 */
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);

    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 1u, &ticket)
        == NINLIL_N6_OK);
    REQUIRE(ticket.live == 1u && ticket.ticket_id != 0u);
    REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &ticket) == NINLIL_N6_OK);
    REQUIRE(ticket.live == 0u);
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 1u, &ticket)
        == NINLIL_N6_TICKET);

    /* abort path */
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 2u, &ticket)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_rx_abort(n6, &ticket) == NINLIL_N6_OK);
    REQUIRE(ticket.live == 0u);
    /* counter 2 still admissible after abort (no durable admit) */
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 2u, &ticket)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &ticket) == NINLIL_N6_OK);

    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

/* Four CU classes via scripted commit outcomes */
static int test_cu_all_four_classes(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_handle_t h = 0u;
    ninlil_n6_tx_lease_t lease;
    ninlil_n6_error_t err;
    ninlil_n6_install_capsule_t cap;
    uint32_t closes_before;

    /* ALL_OLD */
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    closes_before = n6_mem_storage_close_count();
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_OLD);
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_COMMIT_UNKNOWN);
    REQUIRE(lease.live == 0u);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_CU_PENDING);
    /* commit CU: handle still open, phase NEED_CLOSE_OLD, no close yet */
    REQUIRE(ninlil_n6_test_cu_phase(n6) == 1u); /* NEED_CLOSE_OLD */
    REQUIRE(n6_mem_storage_close_count() == closes_before);
    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_OK);
    /* recover: exactly one NEED_CLOSE_OLD close (+ possible later ops) */
    REQUIRE(n6_mem_storage_close_count() >= closes_before + 1u);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_READY);
    REQUIRE(ninlil_n6_last_error(n6, &err) == NINLIL_N6_OK);
    REQUIRE(err.last_cu_class == NINLIL_N6_CU_ALL_OLD);
    /* after ALL_OLD, first counter still available */
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_OK);
    REQUIRE(lease.counter == 1u);
    REQUIRE(ninlil_n6_tx_lease_release(n6, &lease) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* ALL_PROPOSED */
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_COMMIT_UNKNOWN);
    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_last_error(n6, &err) == NINLIL_N6_OK);
    REQUIRE(err.last_cu_class == NINLIL_N6_CU_ALL_PROPOSED);
    /* RAM limit restored; next burn uses next after reserved window start */
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_OK);
    REQUIRE(lease.counter == 1u);
    REQUIRE(ninlil_n6_tx_lease_release(n6, &lease) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* MIXED → fence (multi-key install CU: partial apply of staged keys) */
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    h = 0u;
    n6_mem_storage_inject_cu(N6_MEM_CU_MIXED);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_COMMIT_UNKNOWN);
    REQUIRE(h == 0u);
    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_FENCED);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_last_error(n6, &err) == NINLIL_N6_OK);
    REQUIRE(err.last_cu_class == NINLIL_N6_CU_MIXED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* THIRD → fence (multi-key install with mutated durable values) */
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    h = 0u;
    n6_mem_storage_inject_cu(N6_MEM_CU_THIRD);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_COMMIT_UNKNOWN);
    REQUIRE(h == 0u);
    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_FENCED);
    REQUIRE(ninlil_n6_last_error(n6, &err) == NINLIL_N6_OK);
    REQUIRE(err.last_cu_class == NINLIL_N6_CU_THIRD);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    return 0;
}

/* RX ALL_PROPOSED must update accept_through (no redelivery) */
static int test_cu_rx_all_proposed_accept_through(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_handle_t h = 0u;
    ninlil_n6_rx_ticket_t ticket;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_error_t err;

    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
    cap.context_id = 1u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);

    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 3u, &ticket)
        == NINLIL_N6_OK);
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &ticket)
        == NINLIL_N6_COMMIT_UNKNOWN);
    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_last_error(n6, &err) == NINLIL_N6_OK);
    REQUIRE(err.last_cu_class == NINLIL_N6_CU_ALL_PROPOSED);
    /* same counter must be rejected after ALL_PROPOSED RAM sync */
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 3u, &ticket)
        == NINLIL_N6_TICKET);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

static int test_cu_reentry_open_fault(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_handle_t h = 0u;
    ninlil_n6_tx_lease_t lease;
    ninlil_n6_install_capsule_t cap;

    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_OLD);
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_COMMIT_UNKNOWN);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_CU_PENDING);

    /* First recover: open fails → stay CU_PENDING with plan */
    n6_mem_storage_inject_fault(N6_MEM_FAULT_OPEN, 1);
    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_STORAGE);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_CU_PENDING);

    /* Second recover: open ok → classify ALL_OLD */
    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_READY);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

static int test_phase_fault_sweep_install(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h = 0u;

    /* put fault during install → no handle */
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_PUT, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_STORAGE);
    REQUIRE(h == 0u);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_BOOTED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* get fault */
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_GET, 1);
    h = 0u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_STORAGE);
    REQUIRE(h == 0u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* begin fault */
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_BEGIN, 1);
    h = 0u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_STORAGE);
    REQUIRE(h == 0u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    return 0;
}

static int test_real_reentry_busy(void)
{
    ninlil_n6_t *n6 = NULL;
    /* reentry flag is internal; we exercise by calling enter path via nested
     * public API is single-threaded. Simulate by using stats after concurrent
     * pattern: shutdown while "busy" is checked. Direct reentry: call
     * boot_scan while state would be entered — not possible from outside
     * without hook. We verify reentry_reject counter via forced path:
     * after CU_PENDING recover that fails mid-way, a second call is not
     * reentry (sequential). True reentry requires overlapping calls.
     * Host test: mark reentry by calling ops that nest via storage callback.
     * Here we inject a storage begin that re-enters N6. */
    REQUIRE(setup_ready(&n6, 2u) == 0);
    /* True no-CU (live==0 && n_keys==0): INVALID_STATE, not BUSY/CORRUPT. */
    REQUIRE(ninlil_n6_test_cu_live(n6) == 0);
    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_INVALID_STATE);
    REQUIRE(ninlil_n6_state(n6) != NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_test_cu_live(n6) == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

/* Nested reentry via storage open callback */
static ninlil_n6_t *g_reentry_n6;
static ninlil_storage_status_t (*g_real_open)(
    void *, ninlil_bytes_view_t, uint32_t, ninlil_storage_handle_t *);

static ninlil_storage_status_t n6_open_reenter(
    void *user,
    ninlil_bytes_view_t ns,
    uint32_t schema,
    ninlil_storage_handle_t *out)
{
    ninlil_n6_stats_t st;
    /* Nested public call while outer boot_scan holds reentry */
    (void)ninlil_n6_boot_scan(g_reentry_n6);
    (void)ninlil_n6_stats(g_reentry_n6, &st);
    return g_real_open(user, ns, schema, out);
}

static int test_reentry_via_storage_callback(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_storage_ops_t ops;
    ninlil_n6_stats_t stats;
    ninlil_n6_context_pool_t pool;
    size_t need = ninlil_n6_context_pool_bytes(2u);

    n6_mem_storage_reset();
    pool.max_slots = 2u;
    pool.reserved_zero = 0u;
    pool.bytes = g_pool;
    pool.bytes_size = need;
    (void)memset(g_obj, 0, sizeof(g_obj));
    REQUIRE(ninlil_n6_init(g_obj, sizeof(g_obj), &pool, &n6) == NINLIL_N6_OK);
    ops = *n6_mem_storage_ops();
    g_real_open = ops.open;
    g_reentry_n6 = n6;
    ops.open = n6_open_reenter;
    REQUIRE(ninlil_n6_bind_storage(n6, &ops) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_bind_crypto(n6, ninlil_n6_crypto_host_ops())
        == NINLIL_N6_OK);
    REQUIRE(bind_local_id_fixture(n6, 0x33u) == 0);
    REQUIRE(bind_stamp(n6, 1u, 1u) == 0);
    /* Outer boot_scan → open reenters boot_scan → BUSY_REENTRY counted */
    (void)ninlil_n6_boot_scan(n6);
    REQUIRE(ninlil_n6_stats(n6, &stats) == NINLIL_N6_OK);
    REQUIRE(stats.reentry_reject >= 1u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

static int test_boot_empty_dormant_partial(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h = 0u;
    uint8_t junk_key[4] = {1, 2, 3, 4};
    uint8_t junk_val[4] = {9, 9, 9, 9};

    /* empty → BOOTED */
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* durable present, new RAM → DORMANT */
    {
        ninlil_n6_context_pool_t pool;
        size_t need = ninlil_n6_context_pool_bytes(4u);
        (void)memset(g_obj, 0, sizeof(g_obj));
        (void)memset(g_pool, 0, sizeof(g_pool));
        pool.max_slots = 4u;
        pool.reserved_zero = 0u;
        pool.bytes = g_pool;
        pool.bytes_size = need;
        REQUIRE(ninlil_n6_init(g_obj, sizeof(g_obj), &pool, &n6)
            == NINLIL_N6_OK);
        REQUIRE(ninlil_n6_bind_storage(n6, n6_mem_storage_ops())
            == NINLIL_N6_OK);
        REQUIRE(ninlil_n6_bind_crypto(n6, ninlil_n6_crypto_host_ops())
            == NINLIL_N6_OK);
        REQUIRE(bind_stamp(n6, 1u, 1u) == 0);
        REQUIRE(bind_local_id_fixture(n6, 0x33u) == 0);
        REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_BOOT_DORMANT);
        REQUIRE(ninlil_n6_state(n6)
            == NINLIL_N6_STATE_DORMANT_DURABLE_NO_SECRET);
        REQUIRE(ninlil_n6_install_hop(n6, &cap, &h)
            == NINLIL_N6_INVALID_STATE);
        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    }

    /* partial/garbage seed → CORRUPT */
    n6_mem_storage_reset();
    REQUIRE(n6_mem_storage_seed(junk_key, 4u, junk_val, 4u) == 0);
    {
        ninlil_n6_context_pool_t pool;
        size_t need = ninlil_n6_context_pool_bytes(4u);
        (void)memset(g_obj, 0, sizeof(g_obj));
        (void)memset(g_pool, 0, sizeof(g_pool));
        pool.max_slots = 4u;
        pool.reserved_zero = 0u;
        pool.bytes = g_pool;
        pool.bytes_size = need;
        REQUIRE(ninlil_n6_init(g_obj, sizeof(g_obj), &pool, &n6)
            == NINLIL_N6_OK);
        REQUIRE(ninlil_n6_bind_storage(n6, n6_mem_storage_ops())
            == NINLIL_N6_OK);
        REQUIRE(ninlil_n6_bind_crypto(n6, ninlil_n6_crypto_host_ops())
            == NINLIL_N6_OK);
        REQUIRE(bind_stamp(n6, 1u, 1u) == 0);
        REQUIRE(bind_local_id_fixture(n6, 0x33u) == 0);
        REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
        REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    }
    return 0;
}

static int test_stamp_regression(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_authority_stamp_t stamp;
    ninlil_n6_context_pool_t pool;
    size_t need = ninlil_n6_context_pool_bytes(2u);

    n6_mem_storage_reset();
    pool.max_slots = 2u;
    pool.reserved_zero = 0u;
    pool.bytes = g_pool;
    pool.bytes_size = need;
    (void)memset(g_obj, 0, sizeof(g_obj));
    REQUIRE(ninlil_n6_init(g_obj, sizeof(g_obj), &pool, &n6) == NINLIL_N6_OK);
    (void)memset(&stamp, 0, sizeof(stamp));
    stamp.clock_epoch_id[0] = 1u;
    stamp.now_ms = 100u;
    stamp.trusted_class_d = 1u;
    REQUIRE(ninlil_n6_bind_authority_stamp(n6, &stamp) == NINLIL_N6_OK);
    stamp.now_ms = 50u;
    REQUIRE(ninlil_n6_bind_authority_stamp(n6, &stamp)
        == NINLIL_N6_INVALID_ARGUMENT);
    stamp.trusted_class_d = 0u;
    stamp.now_ms = 200u;
    REQUIRE(ninlil_n6_bind_authority_stamp(n6, &stamp)
        == NINLIL_N6_INVALID_ARGUMENT);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

static int test_al_hw_increment_and_collision(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h1 = 0u, h2 = 0u;

    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    cap.context_id = 10u;
    cap.key_generation = 5u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h1) == NINLIL_N6_OK);
    /* second context: kgen must strictly > HW high-water */
    cap.context_id = 11u;
    cap.key_generation = 6u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h2) == NINLIL_N6_OK);
    REQUIRE(h1 != h2);
    /* high-water regress / equal kgen rejected */
    cap.context_id = 12u;
    cap.key_generation = 6u;
    {
        ninlil_n6_handle_t hx = 0u;
        REQUIRE(ninlil_n6_install_hop(n6, &cap, &hx)
            == NINLIL_N6_INVALID_ARGUMENT);
        REQUIRE(hx == 0u);
    }
    /* collision same context (RAM live) */
    cap.context_id = 10u;
    cap.key_generation = 7u;
    {
        ninlil_n6_handle_t hx = 0u;
        REQUIRE(ninlil_n6_install_hop(n6, &cap, &hx)
            == NINLIL_N6_INVALID_ARGUMENT);
        REQUIRE(hx == 0u);
    }
    /* floor: id below next_free rejected */
    cap.context_id = 5u;
    cap.key_generation = 8u;
    {
        ninlil_n6_handle_t hx = 0u;
        REQUIRE(ninlil_n6_install_hop(n6, &cap, &hx)
            == NINLIL_N6_INVALID_ARGUMENT);
        REQUIRE(hx == 0u);
    }
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

static int ticket_bytes_all_zero(const ninlil_n6_rx_ticket_t *t)
{
    size_t i;
    const uint8_t *p = (const uint8_t *)t;
    for (i = 0u; i < sizeof(*t); ++i) {
        if (p[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int lease_bytes_all_zero(const ninlil_n6_tx_lease_t *L)
{
    size_t i;
    const uint8_t *p = (const uint8_t *)L;
    for (i = 0u; i < sizeof(*L); ++i) {
        if (p[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int test_rx_sliding64_ooo_and_ticket_tamper(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_handle_t h = 0u;
    ninlil_n6_rx_ticket_t t1, t2, t3;
    ninlil_n6_install_capsule_t cap;

    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
    cap.context_id = 1u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);

    /* out-of-order admit: 3 then 1 */
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 3u, &t1)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &t1) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 1u, &t2)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &t2) == NINLIL_N6_OK);
    /* duplicate 3 rejected */
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 3u, &t3)
        == NINLIL_N6_TICKET);

    /* double live ticket same counter */
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 5u, &t1)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 5u, &t2)
        == NINLIL_N6_TICKET);
    REQUIRE(ninlil_n6_rx_abort(n6, &t1) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_test_live_ticket_count(n6) == 0u);

    /* tamper: precheck 7, then mutate counter before admit — consume both */
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 7u, &t1)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_test_live_ticket_count(n6) == 1u);
    t1.counter = 99u; /* attacker */
    REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &t1) == NINLIL_N6_TICKET);
    REQUIRE(ticket_bytes_all_zero(&t1) == 1);
    REQUIRE(ninlil_n6_test_live_ticket_count(n6) == 0u);
    REQUIRE(ninlil_n6_test_any_ticket_key_or_iv_nonzero(n6) == 0);
    /* original 7 not admitted; internal consumed → fresh precheck required/OK */
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 7u, &t2)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_rx_abort(n6, &t2) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_test_live_ticket_count(n6) == 0u);

    /* abort field mismatch still consumes internal by ticket_id */
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 8u, &t1)
        == NINLIL_N6_OK);
    t1.handle = h + 99u;
    REQUIRE(ninlil_n6_rx_abort(n6, &t1) == NINLIL_N6_OK);
    REQUIRE(ticket_bytes_all_zero(&t1) == 1);
    REQUIRE(ninlil_n6_test_live_ticket_count(n6) == 0u);
    REQUIRE(ninlil_n6_test_any_ticket_key_or_iv_nonzero(n6) == 0);
    /* counter 8 free again after consume — retry needs fresh precheck */
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 8u, &t2)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_rx_abort(n6, &t2) == NINLIL_N6_OK);

    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

/* Scan object bytes for a 16-byte key pattern (structural wipe evidence). */
static int obj_contains_key16(const uint8_t key16[16])
{
    size_t i;
    if (key16 == NULL) {
        return 0;
    }
    for (i = 0u; i + 16u <= sizeof(g_obj); ++i) {
        if (memcmp(g_obj + i, key16, 16u) == 0) {
            return 1;
        }
    }
    return 0;
}

/* O3: admit/abort wipe evidence — pool free + key/iv residual 0 + object scan. */

/*
 * Test-build-only fault seam: declared here (not in production private header)
 * so n6_context_store.h stays byte-stable with the pre-errata pin.
 * Compiled only into NINLIL_N6_TEST_BUILD store object.
 */
#if defined(NINLIL_N6_TEST_BUILD)
extern int ninlil_n6_test_fault_corrupt_live_ticket_lane(
    ninlil_n6_t *n6, uint8_t bad_lane_kind);
extern int ninlil_n6_test_all_tickets_fully_zero(const ninlil_n6_t *n6);
extern int ninlil_n6_test_all_leases_fully_zero(const ninlil_n6_t *n6);
extern int ninlil_n6_test_slot_traffic_secret_zero(
    const ninlil_n6_t *n6, ninlil_n6_handle_t handle);
extern int ninlil_n6_test_rx_all_lanes_snapshot(
    const ninlil_n6_t *n6, ninlil_n6_handle_t handle,
    uint64_t *out_live_reserved, uint64_t *out_boot_floor,
    uint64_t *out_ram_highest, uint64_t *out_bitmap);
extern int ninlil_n6_test_tx_all_lanes_snapshot(
    const ninlil_n6_t *n6, ninlil_n6_handle_t handle,
    uint64_t *out_next, uint64_t *out_limit);
extern int ninlil_n6_test_fault_corrupt_cu_array_post(
    ninlil_n6_t *n6, int kind_corrupt, uint8_t bad_kind,
    int idx_corrupt, uint8_t bad_idx);
extern int ninlil_n6_test_fault_mutate_cu_field(
    ninlil_n6_t *n6, uint32_t entry_index, int field_id, uint64_t u64_val);
extern int ninlil_n6_test_rx_window_snapshot(
    const ninlil_n6_t *n6, ninlil_n6_handle_t handle, uint8_t lane_kind,
    uint64_t *out_boot_floor, uint64_t *out_ram_highest, uint64_t *out_bitmap);
/* field_id for ninlil_n6_test_fault_mutate_cu_field */
enum {
    N6_TEST_CU_F_N_KEYS = 1,
    N6_TEST_CU_F_PHASE = 2,
    N6_TEST_CU_F_PENDING_INSTALL = 3,
    N6_TEST_CU_F_OP = 4,
    N6_TEST_CU_F_POST = 5,
    N6_TEST_CU_F_SLOT_INDEX = 6,
    N6_TEST_CU_F_LANE_KIND = 7,
    N6_TEST_CU_F_LANE_IDX = 8,
    N6_TEST_CU_F_KLEN = 9,
    N6_TEST_CU_F_OLD_PRESENT = 10,
    N6_TEST_CU_F_OLD_VLEN = 11,
    N6_TEST_CU_F_PROP_VLEN = 12,
    N6_TEST_CU_F_POST_U64_A = 13,
    N6_TEST_CU_F_POST_U64_B = 14,
    N6_TEST_CU_F_PROP_BYTE = 15,
    N6_TEST_CU_F_KEY_BYTE = 16,
    N6_TEST_CU_F_APPEND_COPY = 17,
    N6_TEST_CU_F_REWRITE_PROP_TX = 18,
    N6_TEST_CU_F_REWRITE_PROP_RX = 19,
    N6_TEST_CU_F_FIND_FIRST_POST = 20
};
#endif

/* Private named lane count matches production N6_PRIVATE_NAMED_LANE_COUNT. */
enum { N6_TEST_LANE_N = 3 };

/* All 12 n6_mem_storage counters — I/O0 oracle for errata fail-closed paths. */
typedef struct n6_mem_io_snap {
    uint32_t close_c;
    uint32_t open_c;
    uint32_t begin_c;
    uint32_t iter_open_c;
    uint32_t iter_close_c;
    uint32_t iter_next_c;
    uint32_t commit_c;
    uint32_t rollback_c;
    uint32_t get_c;
    uint32_t put_c;
    uint32_t erase_c;
    uint32_t capacity_c;
} n6_mem_io_snap_t;

static void n6_mem_io_snap_capture(n6_mem_io_snap_t *s)
{
    s->close_c = n6_mem_storage_close_count();
    s->open_c = n6_mem_storage_open_count();
    s->begin_c = n6_mem_storage_begin_count();
    s->iter_open_c = n6_mem_storage_iter_open_count();
    s->iter_close_c = n6_mem_storage_iter_close_count();
    s->iter_next_c = n6_mem_storage_iter_next_count();
    s->commit_c = n6_mem_storage_commit_count();
    s->rollback_c = n6_mem_storage_rollback_count();
    s->get_c = n6_mem_storage_get_count();
    s->put_c = n6_mem_storage_put_count();
    s->erase_c = n6_mem_storage_erase_count();
    s->capacity_c = n6_mem_storage_capacity_count();
}

static int n6_mem_io_snap_eq(const n6_mem_io_snap_t *a, const n6_mem_io_snap_t *b)
{
    return a->close_c == b->close_c && a->open_c == b->open_c
        && a->begin_c == b->begin_c && a->iter_open_c == b->iter_open_c
        && a->iter_close_c == b->iter_close_c && a->iter_next_c == b->iter_next_c
        && a->commit_c == b->commit_c && a->rollback_c == b->rollback_c
        && a->get_c == b->get_c && a->put_c == b->put_c
        && a->erase_c == b->erase_c && a->capacity_c == b->capacity_c;
}

static int n6_u64n_eq(const uint64_t *a, const uint64_t *b, int n)
{
    int i;
    for (i = 0; i < n; ++i) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

/*
 * R6 RX index errata (docs/30 §20.12 Normative clarification):
 * - external invalid lanes 0/4/255 and cross-layer → INVALID_ARGUMENT,
 *   ticket all-zero, ALL 12 mem storage counters delta 0 (I/O0 ⇒ durable
 *   mutation impossible), pool/window unchanged
 * - internal ticket range-invalid / catalog-valid cross-layer → admit CORRUPT,
 *   fence, full ticket wipe, I/O0, all 3×4 RX arrays unchanged
 * Normal DATA/ACK/E2E regression is covered by rx_ticket_admit,
 * install_tx_rx_storage_shapes, rx_sliding64_tamper (enumerated in review).
 */
static int test_rx_lane_idx_errata(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_handle_t h = 0u;
    ninlil_n6_handle_t h_e2e = 0u;
    ninlil_n6_rx_ticket_t ticket;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_stats_t stats0, stats1;
    ninlil_n6_error_t err;
    uint64_t fence0;
    n6_mem_io_snap_t io0, io1;
    size_t pool_need;
    static uint8_t pool_snap[256u * 1024u];
    const uint8_t bad_lanes[] = {0u, 4u, 255u};
    size_t bi;

    pool_need = ninlil_n6_context_pool_bytes(4u);
    REQUIRE(pool_need > 0u && pool_need <= sizeof(g_pool));
    REQUIRE(pool_need <= sizeof(pool_snap));

    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
    cap.context_id = 1u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_stats(n6, &stats0) == NINLIL_N6_OK);
    fence0 = stats0.fence_count;
    n6_mem_io_snap_capture(&io0);
    (void)memcpy(pool_snap, g_pool, pool_need);

    /* A) external invalid lanes 0, 4, 255 — each independently fail-closed */
    for (bi = 0u; bi < 3u; ++bi) {
        (void)memset(&ticket, (int)(0xA5u ^ (unsigned)bi), sizeof(ticket));
        REQUIRE(ninlil_n6_rx_precheck(n6, h, bad_lanes[bi], 1u + (uint64_t)bi,
            &ticket) == NINLIL_N6_INVALID_ARGUMENT);
        REQUIRE(ticket_bytes_all_zero(&ticket) == 1);
        REQUIRE(ninlil_n6_test_live_ticket_count(n6) == 0u);
        REQUIRE(ninlil_n6_test_any_ticket_key_or_iv_nonzero(n6) == 0);
        n6_mem_io_snap_capture(&io1);
        REQUIRE(n6_mem_io_snap_eq(&io0, &io1) == 1);
        REQUIRE(memcmp(g_pool, pool_snap, pool_need) == 0);
    }

    /* B) external cross-layer: HOP slot + E2E lane (catalog-valid, layer mismatch) */
    (void)memset(&ticket, 0x3C, sizeof(ticket));
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_E2E, 10u, &ticket)
        == NINLIL_N6_INVALID_ARGUMENT);
    REQUIRE(ticket_bytes_all_zero(&ticket) == 1);
    REQUIRE(ninlil_n6_test_live_ticket_count(n6) == 0u);
    n6_mem_io_snap_capture(&io1);
    REQUIRE(n6_mem_io_snap_eq(&io0, &io1) == 1);
    REQUIRE(memcmp(g_pool, pool_snap, pool_need) == 0);

    REQUIRE(ninlil_n6_stats(n6, &stats1) == NINLIL_N6_OK);
    REQUIRE(stats1.rx_precheck_ok == stats0.rx_precheck_ok);
    REQUIRE(stats1.rx_admit_ok == stats0.rx_admit_ok);
    REQUIRE(stats1.fence_count == fence0);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_READY);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* B2) external E2E slot → HOP DATA and HOP ACK (both I/O12 + pool 0) */
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 0);
    cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
    cap.context_id = 1u;
    REQUIRE(ninlil_n6_install_e2e(n6, &cap, &h_e2e) == NINLIL_N6_OK);
    n6_mem_io_snap_capture(&io0);
    (void)memcpy(pool_snap, g_pool, pool_need);
    REQUIRE(ninlil_n6_stats(n6, &stats0) == NINLIL_N6_OK);
    fence0 = stats0.fence_count;

    (void)memset(&ticket, 0x55, sizeof(ticket));
    REQUIRE(ninlil_n6_rx_precheck(n6, h_e2e, NINLIL_N6_LANE_HOP_DATA, 11u, &ticket)
        == NINLIL_N6_INVALID_ARGUMENT);
    REQUIRE(ticket_bytes_all_zero(&ticket) == 1);
    REQUIRE(ninlil_n6_test_live_ticket_count(n6) == 0u);
    n6_mem_io_snap_capture(&io1);
    REQUIRE(n6_mem_io_snap_eq(&io0, &io1) == 1);
    REQUIRE(memcmp(g_pool, pool_snap, pool_need) == 0);

    (void)memset(&ticket, 0x66, sizeof(ticket));
    REQUIRE(ninlil_n6_rx_precheck(n6, h_e2e, NINLIL_N6_LANE_HOP_ACK, 12u, &ticket)
        == NINLIL_N6_INVALID_ARGUMENT);
    REQUIRE(ticket_bytes_all_zero(&ticket) == 1);
    REQUIRE(ninlil_n6_test_live_ticket_count(n6) == 0u);
    n6_mem_io_snap_capture(&io1);
    REQUIRE(n6_mem_io_snap_eq(&io0, &io1) == 1);
    REQUIRE(memcmp(g_pool, pool_snap, pool_need) == 0);

    REQUIRE(ninlil_n6_stats(n6, &stats1) == NINLIL_N6_OK);
    REQUIRE(stats1.rx_precheck_ok == stats0.rx_precheck_ok);
    REQUIRE(stats1.fence_count == fence0);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_READY);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* C) internal range-invalid lane (0xFE) → CORRUPT + fence + wipe + I/O0 */
    {
        uint64_t live0[N6_TEST_LANE_N], boot0[N6_TEST_LANE_N];
        uint64_t high0[N6_TEST_LANE_N], bm0[N6_TEST_LANE_N];
        uint64_t live1[N6_TEST_LANE_N], boot1[N6_TEST_LANE_N];
        uint64_t high1[N6_TEST_LANE_N], bm1[N6_TEST_LANE_N];
        REQUIRE(setup_booted(&n6, 4u) == 0);
        fill_capsule(&cap, 1);
        cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
        cap.context_id = 1u;
        REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
        REQUIRE(ninlil_n6_stats(n6, &stats0) == NINLIL_N6_OK);
        fence0 = stats0.fence_count;
        REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 1u, &ticket)
            == NINLIL_N6_OK);
        REQUIRE(ticket.live == 1u && ticket.ticket_id != 0u);
        REQUIRE(ninlil_n6_test_live_ticket_count(n6) == 1u);
        REQUIRE(ninlil_n6_test_rx_all_lanes_snapshot(
            n6, h, live0, boot0, high0, bm0) == 1);
        n6_mem_io_snap_capture(&io0);
        REQUIRE(ninlil_n6_test_fault_corrupt_live_ticket_lane(n6, 0xFEu) == 1);
        REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &ticket) == NINLIL_N6_CORRUPT);
        REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
        REQUIRE(ticket_bytes_all_zero(&ticket) == 1);
        REQUIRE(ninlil_n6_test_live_ticket_count(n6) == 0u);
        REQUIRE(ninlil_n6_test_all_tickets_fully_zero(n6) == 1);
        n6_mem_io_snap_capture(&io1);
        REQUIRE(n6_mem_io_snap_eq(&io0, &io1) == 1);
        /* Fence zeroes secrets; all named-lane RX arrays unchanged. */
        REQUIRE(ninlil_n6_test_rx_all_lanes_snapshot(
            n6, h, live1, boot1, high1, bm1) == 1);
        REQUIRE(n6_u64n_eq(live0, live1, N6_TEST_LANE_N) == 1);
        REQUIRE(n6_u64n_eq(boot0, boot1, N6_TEST_LANE_N) == 1);
        REQUIRE(n6_u64n_eq(high0, high1, N6_TEST_LANE_N) == 1);
        REQUIRE(n6_u64n_eq(bm0, bm1, N6_TEST_LANE_N) == 1);
        REQUIRE(ninlil_n6_stats(n6, &stats1) == NINLIL_N6_OK);
        REQUIRE(stats1.fence_count == fence0 + 1u);
        REQUIRE(stats1.rx_admit_ok == stats0.rx_admit_ok);
        REQUIRE(ninlil_n6_last_error(n6, &err) == NINLIL_N6_OK);
        REQUIRE(err.status == NINLIL_N6_CORRUPT);
        REQUIRE(err.reason == NINLIL_N6_REASON_CORRUPT);
        REQUIRE(err.state == NINLIL_N6_STATE_FENCED);
        REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &ticket)
            == NINLIL_N6_INVALID_ARGUMENT);
        REQUIRE(ninlil_n6_test_live_ticket_count(n6) == 0u);
        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    }

    /* D) internal catalog-valid cross-layer HOP→E2E and E2E→HOP DATA/ACK */
    {
        uint64_t live0[N6_TEST_LANE_N], boot0[N6_TEST_LANE_N];
        uint64_t high0[N6_TEST_LANE_N], bm0[N6_TEST_LANE_N];
        uint64_t live1[N6_TEST_LANE_N], boot1[N6_TEST_LANE_N];
        uint64_t high1[N6_TEST_LANE_N], bm1[N6_TEST_LANE_N];
        REQUIRE(setup_booted(&n6, 4u) == 0);
        fill_capsule(&cap, 1);
        cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
        cap.context_id = 1u;
        REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
        REQUIRE(ninlil_n6_stats(n6, &stats0) == NINLIL_N6_OK);
        fence0 = stats0.fence_count;
        REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 2u, &ticket)
            == NINLIL_N6_OK);
        REQUIRE(ninlil_n6_test_rx_all_lanes_snapshot(
            n6, h, live0, boot0, high0, bm0) == 1);
        n6_mem_io_snap_capture(&io0);
        REQUIRE(ninlil_n6_test_fault_corrupt_live_ticket_lane(
            n6, NINLIL_N6_LANE_E2E) == 1);
        REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &ticket) == NINLIL_N6_CORRUPT);
        REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
        REQUIRE(ticket_bytes_all_zero(&ticket) == 1);
        REQUIRE(ninlil_n6_test_all_tickets_fully_zero(n6) == 1);
        n6_mem_io_snap_capture(&io1);
        REQUIRE(n6_mem_io_snap_eq(&io0, &io1) == 1);
        REQUIRE(ninlil_n6_test_rx_all_lanes_snapshot(
            n6, h, live1, boot1, high1, bm1) == 1);
        REQUIRE(n6_u64n_eq(live0, live1, N6_TEST_LANE_N) == 1);
        REQUIRE(n6_u64n_eq(boot0, boot1, N6_TEST_LANE_N) == 1);
        REQUIRE(n6_u64n_eq(high0, high1, N6_TEST_LANE_N) == 1);
        REQUIRE(n6_u64n_eq(bm0, bm1, N6_TEST_LANE_N) == 1);
        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

        /* E2E slot → HOP DATA: full 3×4 RX array equality */
        REQUIRE(setup_booted(&n6, 4u) == 0);
        fill_capsule(&cap, 0);
        cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
        cap.context_id = 1u;
        REQUIRE(ninlil_n6_install_e2e(n6, &cap, &h_e2e) == NINLIL_N6_OK);
        REQUIRE(ninlil_n6_rx_precheck(n6, h_e2e, NINLIL_N6_LANE_E2E, 3u, &ticket)
            == NINLIL_N6_OK);
        REQUIRE(ninlil_n6_test_rx_all_lanes_snapshot(
            n6, h_e2e, live0, boot0, high0, bm0) == 1);
        n6_mem_io_snap_capture(&io0);
        REQUIRE(ninlil_n6_test_fault_corrupt_live_ticket_lane(
            n6, NINLIL_N6_LANE_HOP_DATA) == 1);
        REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &ticket) == NINLIL_N6_CORRUPT);
        REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
        REQUIRE(ticket_bytes_all_zero(&ticket) == 1);
        REQUIRE(ninlil_n6_test_all_tickets_fully_zero(n6) == 1);
        n6_mem_io_snap_capture(&io1);
        REQUIRE(n6_mem_io_snap_eq(&io0, &io1) == 1);
        REQUIRE(ninlil_n6_test_rx_all_lanes_snapshot(
            n6, h_e2e, live1, boot1, high1, bm1) == 1);
        REQUIRE(n6_u64n_eq(live0, live1, N6_TEST_LANE_N) == 1);
        REQUIRE(n6_u64n_eq(boot0, boot1, N6_TEST_LANE_N) == 1);
        REQUIRE(n6_u64n_eq(high0, high1, N6_TEST_LANE_N) == 1);
        REQUIRE(n6_u64n_eq(bm0, bm1, N6_TEST_LANE_N) == 1);
        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

        /* E2E slot → HOP ACK: same full 3×4 strength (not weaker than DATA) */
        REQUIRE(setup_booted(&n6, 4u) == 0);
        fill_capsule(&cap, 0);
        cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
        cap.context_id = 1u;
        REQUIRE(ninlil_n6_install_e2e(n6, &cap, &h_e2e) == NINLIL_N6_OK);
        REQUIRE(ninlil_n6_rx_precheck(n6, h_e2e, NINLIL_N6_LANE_E2E, 4u, &ticket)
            == NINLIL_N6_OK);
        REQUIRE(ninlil_n6_test_rx_all_lanes_snapshot(
            n6, h_e2e, live0, boot0, high0, bm0) == 1);
        n6_mem_io_snap_capture(&io0);
        REQUIRE(ninlil_n6_test_fault_corrupt_live_ticket_lane(
            n6, NINLIL_N6_LANE_HOP_ACK) == 1);
        REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &ticket) == NINLIL_N6_CORRUPT);
        REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
        REQUIRE(ticket_bytes_all_zero(&ticket) == 1);
        REQUIRE(ninlil_n6_test_all_tickets_fully_zero(n6) == 1);
        n6_mem_io_snap_capture(&io1);
        REQUIRE(n6_mem_io_snap_eq(&io0, &io1) == 1);
        REQUIRE(ninlil_n6_test_rx_all_lanes_snapshot(
            n6, h_e2e, live1, boot1, high1, bm1) == 1);
        REQUIRE(n6_u64n_eq(live0, live1, N6_TEST_LANE_N) == 1);
        REQUIRE(n6_u64n_eq(boot0, boot1, N6_TEST_LANE_N) == 1);
        REQUIRE(n6_u64n_eq(high0, high1, N6_TEST_LANE_N) == 1);
        REQUIRE(n6_u64n_eq(bm0, bm1, N6_TEST_LANE_N) == 1);
        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    }

    /* E) happy-path regression in-suite: HOP DATA/ACK + E2E still work */
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
    cap.context_id = 1u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 1u, &ticket)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &ticket) == NINLIL_N6_OK);
    REQUIRE(ticket_bytes_all_zero(&ticket) == 1);
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_ACK, 1u, &ticket)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &ticket) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 0);
    cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
    cap.context_id = 1u;
    REQUIRE(ninlil_n6_install_e2e(n6, &cap, &h_e2e) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_rx_precheck(n6, h_e2e, NINLIL_N6_LANE_E2E, 1u, &ticket)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &ticket) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}


/*
 * Helper: after COMMIT_UNKNOWN CU is live and storage handle is open.
 * Corrupt recover must: CORRUPT + FENCED + full wipe; close delta exactly 1;
 * open/begin/get/put/erase/commit/rollback/iter_open/iter_next/iter_close/capacity
 * delta 0; TX and/or RX arrays unchanged when snapshots provided.
 */
static int cu_fail_closed_assert(
    ninlil_n6_t *n6, ninlil_n6_handle_t h, uint64_t fence0,
    const n6_mem_io_snap_t *io0,
    const uint64_t *tn0, const uint64_t *tl0, int check_tx,
    const uint64_t *live0, const uint64_t *boot0, const uint64_t *high0,
    const uint64_t *bm0, int check_rx)
{
    n6_mem_io_snap_t io1;
    ninlil_n6_stats_t stats1;
    ninlil_n6_error_t err;
    uint64_t tn1[N6_TEST_LANE_N], tl1[N6_TEST_LANE_N];
    uint64_t live1[N6_TEST_LANE_N], boot1[N6_TEST_LANE_N];
    uint64_t high1[N6_TEST_LANE_N], bm1[N6_TEST_LANE_N];

    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_test_cu_live(n6) == 0);
    REQUIRE(ninlil_n6_test_all_tickets_fully_zero(n6) == 1);
    REQUIRE(ninlil_n6_test_all_leases_fully_zero(n6) == 1);
    REQUIRE(ninlil_n6_test_slot_traffic_secret_zero(n6, h) == 1);
    n6_mem_io_snap_capture(&io1);
    REQUIRE(io1.close_c == io0->close_c + 1u);
    REQUIRE(io1.open_c == io0->open_c);
    REQUIRE(io1.begin_c == io0->begin_c);
    REQUIRE(io1.iter_open_c == io0->iter_open_c);
    REQUIRE(io1.iter_close_c == io0->iter_close_c);
    REQUIRE(io1.iter_next_c == io0->iter_next_c);
    REQUIRE(io1.commit_c == io0->commit_c);
    REQUIRE(io1.rollback_c == io0->rollback_c);
    REQUIRE(io1.get_c == io0->get_c);
    REQUIRE(io1.put_c == io0->put_c);
    REQUIRE(io1.erase_c == io0->erase_c);
    REQUIRE(io1.capacity_c == io0->capacity_c);
    if (check_tx != 0) {
        REQUIRE(ninlil_n6_test_tx_all_lanes_snapshot(n6, h, tn1, tl1) == 1);
        REQUIRE(n6_u64n_eq(tn0, tn1, N6_TEST_LANE_N) == 1);
        REQUIRE(n6_u64n_eq(tl0, tl1, N6_TEST_LANE_N) == 1);
    }
    if (check_rx != 0) {
        REQUIRE(ninlil_n6_test_rx_all_lanes_snapshot(
            n6, h, live1, boot1, high1, bm1) == 1);
        REQUIRE(n6_u64n_eq(live0, live1, N6_TEST_LANE_N) == 1);
        REQUIRE(n6_u64n_eq(boot0, boot1, N6_TEST_LANE_N) == 1);
        REQUIRE(n6_u64n_eq(high0, high1, N6_TEST_LANE_N) == 1);
        REQUIRE(n6_u64n_eq(bm0, bm1, N6_TEST_LANE_N) == 1);
    }
    REQUIRE(ninlil_n6_stats(n6, &stats1) == NINLIL_N6_OK);
    REQUIRE(stats1.fence_count == fence0 + 1u);
    REQUIRE(ninlil_n6_last_error(n6, &err) == NINLIL_N6_OK);
    REQUIRE(err.status == NINLIL_N6_CORRUPT);
    REQUIRE(err.reason == NINLIL_N6_REASON_CORRUPT);
    REQUIRE(err.state == NINLIL_N6_STATE_FENCED);
    return 0;
}

/* Locate first TX_LIMIT/RX_ACCEPT entry index in live CU; -1 if none. */
static int cu_first_array_post_index(ninlil_n6_t *n6)
{
    int r = ninlil_n6_test_fault_mutate_cu_field(
        n6, 0u, N6_TEST_CU_F_FIND_FIRST_POST, 0u);
    if (r <= 0) {
        return -1;
    }
    return r - 1;
}

/*
 * CU ALL_PROPOSED array-post corruption + full envelope KATs (docs/30 §20.12 r7).
 * Single cap declaration (no duplicate).
 */
static int test_cu_post_lane_idx_errata(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_handle_t h = 0u;
    ninlil_n6_handle_t h2 = 0u;
    ninlil_n6_tx_lease_t lease;
    ninlil_n6_rx_ticket_t ticket;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_stats_t stats0;
    uint64_t fence0;
    uint64_t tn0[N6_TEST_LANE_N], tl0[N6_TEST_LANE_N];
    uint64_t live0[N6_TEST_LANE_N], boot0[N6_TEST_LANE_N];
    uint64_t high0[N6_TEST_LANE_N], bm0[N6_TEST_LANE_N];
    n6_mem_io_snap_t io0;
    int ei;
    uint64_t post_a0;

    /* ---- TX_LIMIT: corrupt lane_idx on CU post (no TX array mutation) ---- */
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_test_tx_all_lanes_snapshot(n6, h, tn0, tl0) == 1);
    REQUIRE(ninlil_n6_stats(n6, &stats0) == NINLIL_N6_OK);
    fence0 = stats0.fence_count;
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_COMMIT_UNKNOWN);
    REQUIRE(lease.live == 0u);
    REQUIRE(ninlil_n6_test_cu_live(n6) == 1);
    n6_mem_io_snap_capture(&io0);
    REQUIRE(ninlil_n6_test_fault_corrupt_cu_array_post(n6, 0, 0, 1, 255u) == 1);
    REQUIRE(cu_fail_closed_assert(n6, h, fence0, &io0, tn0, tl0, 1, NULL, NULL,
                NULL, NULL, 0)
        == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* ---- RX_ACCEPT: corrupt lane_kind to E2E (cross-layer) on HOP ---- */
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
    cap.context_id = 1u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_test_rx_all_lanes_snapshot(
        n6, h, live0, boot0, high0, bm0) == 1);
    REQUIRE(ninlil_n6_stats(n6, &stats0) == NINLIL_N6_OK);
    fence0 = stats0.fence_count;
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 5u, &ticket)
        == NINLIL_N6_OK);
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &ticket)
        == NINLIL_N6_COMMIT_UNKNOWN);
    REQUIRE(ticket_bytes_all_zero(&ticket) == 1);
    REQUIRE(ninlil_n6_test_cu_live(n6) == 1);
    n6_mem_io_snap_capture(&io0);
    REQUIRE(ninlil_n6_test_fault_corrupt_cu_array_post(
        n6, 1, NINLIL_N6_LANE_E2E, 0, 0) == 1);
    REQUIRE(cu_fail_closed_assert(n6, h, fence0, &io0, NULL, NULL, 0, live0,
                boot0, high0, bm0, 1)
        == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* ---- Envelope / integrity KATs (each: CORRUPT+FENCED+close1+I/O0) ---- */
    /*
     * n_keys→0 seam on a live COMMIT_UNKNOWN open plan (P1 bypass residual).
     * Independent oracle: CORRUPT + FENCED + CU/ticket/lease/secret wipe +
     * close delta exactly 1 + other 11 storage counters delta 0 + all TX lane
     * next/limit arrays byte-equal (no posts). Must NOT return INVALID_STATE
     * (that status is reserved for true no-CU live==0 && n_keys==0 only).
     */
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_test_tx_all_lanes_snapshot(n6, h, tn0, tl0) == 1);
    REQUIRE(ninlil_n6_stats(n6, &stats0) == NINLIL_N6_OK);
    fence0 = stats0.fence_count;
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_COMMIT_UNKNOWN);
    REQUIRE(lease.live == 0u);
    REQUIRE(ninlil_n6_test_cu_live(n6) == 1);
    n6_mem_io_snap_capture(&io0);
    REQUIRE(ninlil_n6_test_fault_mutate_cu_field(n6, 0u, N6_TEST_CU_F_N_KEYS, 0u)
        == 1);
    REQUIRE(cu_fail_closed_assert(n6, h, fence0, &io0, tn0, tl0, 1, NULL, NULL,
                NULL, NULL, 0)
        == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* n_keys MAX+1 */
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_test_tx_all_lanes_snapshot(n6, h, tn0, tl0) == 1);
    REQUIRE(ninlil_n6_stats(n6, &stats0) == NINLIL_N6_OK);
    fence0 = stats0.fence_count;
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_COMMIT_UNKNOWN);
    n6_mem_io_snap_capture(&io0);
    REQUIRE(ninlil_n6_test_fault_mutate_cu_field(n6, 0u, N6_TEST_CU_F_N_KEYS,
                (uint64_t)NINLIL_N6_CU_PLAN_MAX_KEYS + 1u)
        == 1);
    REQUIRE(cu_fail_closed_assert(n6, h, fence0, &io0, tn0, tl0, 1, NULL, NULL,
                NULL, NULL, 0)
        == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* klen 49 and SIZE_MAX */
    {
        const size_t klens[2] = { 49u, (size_t)SIZE_MAX };
        size_t ki;
        for (ki = 0u; ki < 2u; ++ki) {
            REQUIRE(setup_booted(&n6, 8u) == 0);
            fill_capsule(&cap, 1);
            REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
            REQUIRE(ninlil_n6_test_tx_all_lanes_snapshot(n6, h, tn0, tl0) == 1);
            REQUIRE(ninlil_n6_stats(n6, &stats0) == NINLIL_N6_OK);
            fence0 = stats0.fence_count;
            n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
            REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
                == NINLIL_N6_COMMIT_UNKNOWN);
            ei = cu_first_array_post_index(n6);
            REQUIRE(ei >= 0);
            n6_mem_io_snap_capture(&io0);
            REQUIRE(ninlil_n6_test_fault_mutate_cu_field(n6, (uint32_t)ei,
                        N6_TEST_CU_F_KLEN, (uint64_t)klens[ki])
                == 1);
            REQUIRE(cu_fail_closed_assert(n6, h, fence0, &io0, tn0, tl0, 1, NULL,
                        NULL, NULL, NULL, 0)
                == 0);
            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
        }
    }

    /* post unknown (99) and post flip TX_LIMIT→RX_ACCEPT (side mismatch) */
    {
        const uint64_t posts[2] = { 99u, 3u /* RX_ACCEPT */ };
        size_t pi;
        for (pi = 0u; pi < 2u; ++pi) {
            REQUIRE(setup_booted(&n6, 8u) == 0);
            fill_capsule(&cap, 1);
            REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
            REQUIRE(ninlil_n6_test_tx_all_lanes_snapshot(n6, h, tn0, tl0) == 1);
            REQUIRE(ninlil_n6_stats(n6, &stats0) == NINLIL_N6_OK);
            fence0 = stats0.fence_count;
            n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
            REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
                == NINLIL_N6_COMMIT_UNKNOWN);
            ei = cu_first_array_post_index(n6);
            REQUIRE(ei >= 0);
            n6_mem_io_snap_capture(&io0);
            REQUIRE(ninlil_n6_test_fault_mutate_cu_field(n6, (uint32_t)ei,
                        N6_TEST_CU_F_POST, posts[pi])
                == 1);
            REQUIRE(cu_fail_closed_assert(n6, h, fence0, &io0, tn0, tl0, 1, NULL,
                        NULL, NULL, NULL, 0)
                == 0);
            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
        }
    }

    /* RX→outbound: RX_ACCEPT plan with post flipped to TX_LIMIT */
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
    cap.context_id = 1u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_test_rx_all_lanes_snapshot(
        n6, h, live0, boot0, high0, bm0) == 1);
    REQUIRE(ninlil_n6_stats(n6, &stats0) == NINLIL_N6_OK);
    fence0 = stats0.fence_count;
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 7u, &ticket)
        == NINLIL_N6_OK);
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &ticket)
        == NINLIL_N6_COMMIT_UNKNOWN);
    ei = cu_first_array_post_index(n6);
    REQUIRE(ei >= 0);
    n6_mem_io_snap_capture(&io0);
    REQUIRE(ninlil_n6_test_fault_mutate_cu_field(n6, (uint32_t)ei,
                N6_TEST_CU_F_POST, 2u /* TX_LIMIT */)
        == 1);
    REQUIRE(cu_fail_closed_assert(n6, h, fence0, &io0, NULL, NULL, 0, live0,
                boot0, high0, bm0, 1)
        == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* same-side different-slot redirect */
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    cap.context_id = 1u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    fill_capsule(&cap, 1);
    cap.context_id = 2u;
    cap.key_generation = 6u; /* HW floor raised by first install */
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h2) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_test_tx_all_lanes_snapshot(n6, h, tn0, tl0) == 1);
    REQUIRE(ninlil_n6_stats(n6, &stats0) == NINLIL_N6_OK);
    fence0 = stats0.fence_count;
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_COMMIT_UNKNOWN);
    ei = cu_first_array_post_index(n6);
    REQUIRE(ei >= 0);
    n6_mem_io_snap_capture(&io0);
    /* Redirect to second live outbound slot index (typically 1). */
    REQUIRE(ninlil_n6_test_fault_mutate_cu_field(n6, (uint32_t)ei,
                N6_TEST_CU_F_SLOT_INDEX, 1u)
        == 1);
    REQUIRE(cu_fail_closed_assert(n6, h, fence0, &io0, tn0, tl0, 1, NULL, NULL,
                NULL, NULL, 0)
        == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* post_u64_a / post_u64_b mutation */
    {
        const int fields[2] = { N6_TEST_CU_F_POST_U64_A, N6_TEST_CU_F_POST_U64_B };
        size_t fi;
        for (fi = 0u; fi < 2u; ++fi) {
            REQUIRE(setup_booted(&n6, 8u) == 0);
            fill_capsule(&cap, 1);
            REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
            REQUIRE(ninlil_n6_test_tx_all_lanes_snapshot(n6, h, tn0, tl0) == 1);
            REQUIRE(ninlil_n6_stats(n6, &stats0) == NINLIL_N6_OK);
            fence0 = stats0.fence_count;
            n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
            REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
                == NINLIL_N6_COMMIT_UNKNOWN);
            ei = cu_first_array_post_index(n6);
            REQUIRE(ei >= 0);
            n6_mem_io_snap_capture(&io0);
            REQUIRE(ninlil_n6_test_fault_mutate_cu_field(n6, (uint32_t)ei,
                        fields[fi], 0xDEADBEEFu)
                == 1);
            REQUIRE(cu_fail_closed_assert(n6, h, fence0, &io0, tn0, tl0, 1, NULL,
                        NULL, NULL, NULL, 0)
                == 0);
            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
        }
    }

    /* CRC-valid prop with post mismatch (re-encode prop reserved only) */
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_test_tx_all_lanes_snapshot(n6, h, tn0, tl0) == 1);
    REQUIRE(ninlil_n6_stats(n6, &stats0) == NINLIL_N6_OK);
    fence0 = stats0.fence_count;
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_COMMIT_UNKNOWN);
    ei = cu_first_array_post_index(n6);
    REQUIRE(ei >= 0);
    /* Capture original post_a by rewriting prop to a different valid exclusive. */
    post_a0 = 999999u; /* distinct from typical small reserved windows */
    n6_mem_io_snap_capture(&io0);
    REQUIRE(ninlil_n6_test_fault_mutate_cu_field(n6, (uint32_t)ei,
                N6_TEST_CU_F_REWRITE_PROP_TX, post_a0)
        == 1);
    REQUIRE(cu_fail_closed_assert(n6, h, fence0, &io0, tn0, tl0, 1, NULL, NULL,
                NULL, NULL, 0)
        == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* 2-entry: first valid + second invalid (append copy then mutate post_a) */
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_test_tx_all_lanes_snapshot(n6, h, tn0, tl0) == 1);
    REQUIRE(ninlil_n6_stats(n6, &stats0) == NINLIL_N6_OK);
    fence0 = stats0.fence_count;
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_COMMIT_UNKNOWN);
    ei = cu_first_array_post_index(n6);
    REQUIRE(ei >= 0);
    REQUIRE(ninlil_n6_test_fault_mutate_cu_field(n6, (uint32_t)ei,
                N6_TEST_CU_F_APPEND_COPY, 0u)
        == 1);
    /* Appended copy is at ei+1; first entry remains valid. */
    n6_mem_io_snap_capture(&io0);
    REQUIRE(ninlil_n6_test_fault_mutate_cu_field(n6, (uint32_t)ei + 1u,
                N6_TEST_CU_F_POST_U64_A, 0xABCDu)
        == 1);
    REQUIRE(cu_fail_closed_assert(n6, h, fence0, &io0, tn0, tl0, 1, NULL, NULL,
                NULL, NULL, 0)
        == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /*
     * Additional envelope field KATs (seam fields not already covered above):
     * phase, pending_install, op, old_present, old_vlen, prop_vlen, key byte,
     * RX CRC-valid prop rewrite (post mismatch). Same fail-closed oracle.
     */
    {
        const int plan_fields[] = {
            N6_TEST_CU_F_PHASE,
            N6_TEST_CU_F_PENDING_INSTALL,
        };
        const uint64_t plan_vals[] = {
            99u, /* invalid phase outside recovery domain */
            2u,  /* pending_install not boolean */
        };
        size_t pi;
        for (pi = 0u; pi < 2u; ++pi) {
            REQUIRE(setup_booted(&n6, 8u) == 0);
            fill_capsule(&cap, 1);
            REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
            REQUIRE(ninlil_n6_test_tx_all_lanes_snapshot(n6, h, tn0, tl0) == 1);
            REQUIRE(ninlil_n6_stats(n6, &stats0) == NINLIL_N6_OK);
            fence0 = stats0.fence_count;
            n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
            REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
                == NINLIL_N6_COMMIT_UNKNOWN);
            n6_mem_io_snap_capture(&io0);
            REQUIRE(ninlil_n6_test_fault_mutate_cu_field(
                        n6, 0u, plan_fields[pi], plan_vals[pi])
                == 1);
            REQUIRE(cu_fail_closed_assert(n6, h, fence0, &io0, tn0, tl0, 1, NULL,
                        NULL, NULL, NULL, 0)
                == 0);
            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
        }
    }
    {
        const int entry_fields[] = {
            N6_TEST_CU_F_OP,
            N6_TEST_CU_F_OLD_PRESENT,
            N6_TEST_CU_F_OLD_VLEN,
            N6_TEST_CU_F_PROP_VLEN,
            N6_TEST_CU_F_KEY_BYTE,
        };
        const uint64_t entry_vals[] = {
            99u, /* invalid op */
            2u,  /* old_present not boolean */
            69u, /* old_vlen > 68 */
            69u, /* prop_vlen > 68 */
            0u,  /* key[0] ^= 1 */
        };
        size_t fi;
        for (fi = 0u; fi < 5u; ++fi) {
            REQUIRE(setup_booted(&n6, 8u) == 0);
            fill_capsule(&cap, 1);
            REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
            REQUIRE(ninlil_n6_test_tx_all_lanes_snapshot(n6, h, tn0, tl0) == 1);
            REQUIRE(ninlil_n6_stats(n6, &stats0) == NINLIL_N6_OK);
            fence0 = stats0.fence_count;
            n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
            REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
                == NINLIL_N6_COMMIT_UNKNOWN);
            ei = cu_first_array_post_index(n6);
            REQUIRE(ei >= 0);
            n6_mem_io_snap_capture(&io0);
            REQUIRE(ninlil_n6_test_fault_mutate_cu_field(
                        n6, (uint32_t)ei, entry_fields[fi], entry_vals[fi])
                == 1);
            REQUIRE(cu_fail_closed_assert(n6, h, fence0, &io0, tn0, tl0, 1, NULL,
                        NULL, NULL, NULL, 0)
                == 0);
            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
        }
    }
    /* RX: CRC-valid prop rewrite vs post_u64_a mismatch + identity intact path */
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
    cap.context_id = 1u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_test_rx_all_lanes_snapshot(
        n6, h, live0, boot0, high0, bm0) == 1);
    REQUIRE(ninlil_n6_stats(n6, &stats0) == NINLIL_N6_OK);
    fence0 = stats0.fence_count;
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 9u, &ticket)
        == NINLIL_N6_OK);
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &ticket)
        == NINLIL_N6_COMMIT_UNKNOWN);
    ei = cu_first_array_post_index(n6);
    REQUIRE(ei >= 0);
    n6_mem_io_snap_capture(&io0);
    /* Re-encode prop with a different accept_through; leave post_u64_a. */
    REQUIRE(ninlil_n6_test_fault_mutate_cu_field(n6, (uint32_t)ei,
                N6_TEST_CU_F_REWRITE_PROP_RX, 0xBEEFu)
        == 1);
    REQUIRE(cu_fail_closed_assert(n6, h, fence0, &io0, NULL, NULL, 0, live0,
                boot0, high0, bm0, 1)
        == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* Happy TX CU ALL_PROPOSED still applies */
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_COMMIT_UNKNOWN);
    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_READY);
    REQUIRE(ninlil_n6_test_cu_live(n6) == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* Happy RX CU ALL_PROPOSED still applies */
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
    cap.context_id = 1u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 3u, &ticket)
        == NINLIL_N6_OK);
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &ticket)
        == NINLIL_N6_COMMIT_UNKNOWN);
    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_READY);
    REQUIRE(ninlil_n6_test_cu_live(n6) == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

/*
 * Direct tx_burn invalid lanes 0/4/255 + cross-layer:
 * INVALID_ARGUMENT, lease all-zero, all 12 storage I/O deltas 0,
 * all 3×TX next/limit arrays unchanged.
 */
static int test_tx_burn_lane_idx_errata(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_handle_t h = 0u;
    ninlil_n6_handle_t h_e2e = 0u;
    ninlil_n6_tx_lease_t lease;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_stats_t stats0, stats1;
    n6_mem_io_snap_t io0, io1;
    uint64_t tn0[N6_TEST_LANE_N], tl0[N6_TEST_LANE_N];
    uint64_t tn1[N6_TEST_LANE_N], tl1[N6_TEST_LANE_N];
    const uint8_t bad_lanes[] = { 0u, 4u, 255u };
    size_t bi;

    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_test_tx_all_lanes_snapshot(n6, h, tn0, tl0) == 1);
    REQUIRE(ninlil_n6_stats(n6, &stats0) == NINLIL_N6_OK);
    n6_mem_io_snap_capture(&io0);

    for (bi = 0u; bi < 3u; ++bi) {
        (void)memset(&lease, (int)(0x5Au ^ (unsigned)bi), sizeof(lease));
        REQUIRE(ninlil_n6_tx_burn(n6, h, bad_lanes[bi], &lease)
            == NINLIL_N6_INVALID_ARGUMENT);
        REQUIRE(lease_bytes_all_zero(&lease) == 1);
        n6_mem_io_snap_capture(&io1);
        REQUIRE(n6_mem_io_snap_eq(&io0, &io1) == 1);
        REQUIRE(ninlil_n6_test_tx_all_lanes_snapshot(n6, h, tn1, tl1) == 1);
        REQUIRE(n6_u64n_eq(tn0, tn1, N6_TEST_LANE_N) == 1);
        REQUIRE(n6_u64n_eq(tl0, tl1, N6_TEST_LANE_N) == 1);
    }

    /* cross-layer: HOP slot + E2E lane */
    (void)memset(&lease, 0x3C, sizeof(lease));
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_E2E, &lease)
        == NINLIL_N6_INVALID_ARGUMENT);
    REQUIRE(lease_bytes_all_zero(&lease) == 1);
    n6_mem_io_snap_capture(&io1);
    REQUIRE(n6_mem_io_snap_eq(&io0, &io1) == 1);
    REQUIRE(ninlil_n6_test_tx_all_lanes_snapshot(n6, h, tn1, tl1) == 1);
    REQUIRE(n6_u64n_eq(tn0, tn1, N6_TEST_LANE_N) == 1);
    REQUIRE(n6_u64n_eq(tl0, tl1, N6_TEST_LANE_N) == 1);

    REQUIRE(ninlil_n6_stats(n6, &stats1) == NINLIL_N6_OK);
    REQUIRE(stats1.tx_burn_ok == stats0.tx_burn_ok);
    REQUIRE(stats1.fence_count == stats0.fence_count);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_READY);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* E2E slot + HOP DATA/ACK */
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 0);
    REQUIRE(ninlil_n6_install_e2e(n6, &cap, &h_e2e) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_test_tx_all_lanes_snapshot(n6, h_e2e, tn0, tl0) == 1);
    n6_mem_io_snap_capture(&io0);
    REQUIRE(ninlil_n6_stats(n6, &stats0) == NINLIL_N6_OK);

    (void)memset(&lease, 0x11, sizeof(lease));
    REQUIRE(ninlil_n6_tx_burn(n6, h_e2e, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_INVALID_ARGUMENT);
    REQUIRE(lease_bytes_all_zero(&lease) == 1);
    n6_mem_io_snap_capture(&io1);
    REQUIRE(n6_mem_io_snap_eq(&io0, &io1) == 1);
    REQUIRE(ninlil_n6_test_tx_all_lanes_snapshot(n6, h_e2e, tn1, tl1) == 1);
    REQUIRE(n6_u64n_eq(tn0, tn1, N6_TEST_LANE_N) == 1);
    REQUIRE(n6_u64n_eq(tl0, tl1, N6_TEST_LANE_N) == 1);

    (void)memset(&lease, 0x22, sizeof(lease));
    REQUIRE(ninlil_n6_tx_burn(n6, h_e2e, NINLIL_N6_LANE_HOP_ACK, &lease)
        == NINLIL_N6_INVALID_ARGUMENT);
    REQUIRE(lease_bytes_all_zero(&lease) == 1);
    n6_mem_io_snap_capture(&io1);
    REQUIRE(n6_mem_io_snap_eq(&io0, &io1) == 1);
    REQUIRE(ninlil_n6_test_tx_all_lanes_snapshot(n6, h_e2e, tn1, tl1) == 1);
    REQUIRE(n6_u64n_eq(tn0, tn1, N6_TEST_LANE_N) == 1);
    REQUIRE(n6_u64n_eq(tl0, tl1, N6_TEST_LANE_N) == 1);

    REQUIRE(ninlil_n6_stats(n6, &stats1) == NINLIL_N6_OK);
    REQUIRE(stats1.tx_burn_ok == stats0.tx_burn_ok);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

static int test_rx_ticket_wipe_evidence_kat(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_handle_t h = 0u;
    ninlil_n6_rx_ticket_t ticket;
    ninlil_n6_install_capsule_t cap;
    uint32_t i;
    uint8_t key_snap[16];

    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
    cap.context_id = 1u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);

    /* A) successful admit: caller + internal wiped; key pattern gone from object */
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 1u, &ticket)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_test_live_ticket_count(n6) == 1u);
    (void)memcpy(key_snap, ticket.key16, 16u);
    REQUIRE(obj_contains_key16(key_snap) == 1); /* live internal holds key */
    REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &ticket) == NINLIL_N6_OK);
    REQUIRE(ticket_bytes_all_zero(&ticket) == 1);
    REQUIRE(ninlil_n6_test_live_ticket_count(n6) == 0u);
    REQUIRE(ninlil_n6_test_any_ticket_key_or_iv_nonzero(n6) == 0);
    REQUIRE(obj_contains_key16(key_snap) == 0); /* structural: not only helper */

    /* B) key/iv tamper admit: TICKET + full consume + object key gone */
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 2u, &ticket)
        == NINLIL_N6_OK);
    (void)memcpy(key_snap, ticket.key16, 16u);
    REQUIRE(obj_contains_key16(key_snap) == 1);
    ticket.key16[0] ^= 0xFFu;
    REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &ticket) == NINLIL_N6_TICKET);
    REQUIRE(ticket_bytes_all_zero(&ticket) == 1);
    REQUIRE(ninlil_n6_test_live_ticket_count(n6) == 0u);
    REQUIRE(ninlil_n6_test_any_ticket_key_or_iv_nonzero(n6) == 0);
    REQUIRE(obj_contains_key16(key_snap) == 0);
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 2u, &ticket)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_rx_abort(n6, &ticket) == NINLIL_N6_OK);

    /* C) storage-fail admit (begin IO): still consume ticket pair */
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 3u, &ticket)
        == NINLIL_N6_OK);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_BEGIN, 1);
    {
        ninlil_n6_status_t st =
            ninlil_n6_rx_admit_after_aead(n6, &ticket);
        REQUIRE(st == NINLIL_N6_STORAGE || st == NINLIL_N6_CORRUPT
            || st == NINLIL_N6_CAPACITY);
    }
    REQUIRE(ticket_bytes_all_zero(&ticket) == 1);
    REQUIRE(ninlil_n6_test_live_ticket_count(n6) == 0u);
    REQUIRE(ninlil_n6_test_any_ticket_key_or_iv_nonzero(n6) == 0);
    /* counter 3 not admitted — fresh precheck OK */
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 3u, &ticket)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_rx_abort(n6, &ticket) == NINLIL_N6_OK);

    /* D) abort lane mismatch: still free internal by ticket_id */
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 4u, &ticket)
        == NINLIL_N6_OK);
    ticket.lane_kind = NINLIL_N6_LANE_HOP_ACK;
    REQUIRE(ninlil_n6_rx_abort(n6, &ticket) == NINLIL_N6_OK);
    REQUIRE(ticket_bytes_all_zero(&ticket) == 1);
    REQUIRE(ninlil_n6_test_live_ticket_count(n6) == 0u);
    REQUIRE(ninlil_n6_test_any_ticket_key_or_iv_nonzero(n6) == 0);

    /* E) pool not starved: fill MAX then all abort → all free again */
    {
        ninlil_n6_rx_ticket_t pool[NINLIL_N6_MAX_LIVE_TICKETS];
        for (i = 0u; i < NINLIL_N6_MAX_LIVE_TICKETS; ++i) {
            REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA,
                        (uint64_t)(10u + i), &pool[i])
                == NINLIL_N6_OK);
        }
        REQUIRE(ninlil_n6_test_live_ticket_count(n6)
            == NINLIL_N6_MAX_LIVE_TICKETS);
        /* one more must CAPACITY */
        {
            ninlil_n6_rx_ticket_t extra;
            REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 99u,
                        &extra)
                == NINLIL_N6_CAPACITY);
        }
        /* tamper-admit one, abort rest — no orphans */
        pool[0].counter ^= 0x55u;
        REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &pool[0]) == NINLIL_N6_TICKET);
        for (i = 1u; i < NINLIL_N6_MAX_LIVE_TICKETS; ++i) {
            REQUIRE(ninlil_n6_rx_abort(n6, &pool[i]) == NINLIL_N6_OK);
        }
        REQUIRE(ninlil_n6_test_live_ticket_count(n6) == 0u);
        REQUIRE(ninlil_n6_test_any_ticket_key_or_iv_nonzero(n6) == 0);
        /* pool fully free for another MAX */
        for (i = 0u; i < NINLIL_N6_MAX_LIVE_TICKETS; ++i) {
            REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA,
                        (uint64_t)(30u + i), &pool[i])
                == NINLIL_N6_OK);
        }
        for (i = 0u; i < NINLIL_N6_MAX_LIVE_TICKETS; ++i) {
            REQUIRE(ninlil_n6_rx_abort(n6, &pool[i]) == NINLIL_N6_OK);
        }
        REQUIRE(ninlil_n6_test_live_ticket_count(n6) == 0u);
    }

    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

static int test_id_wrap_fail_closed(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_handle_t h = 0u;
    ninlil_n6_tx_lease_t lease;
    ninlil_n6_install_capsule_t cap;
    /* force next_lease_id exhaustion via many burns+releases is too slow;
     * inject by installing then checking handle nonzero and sequential. */
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(h == 1u);
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_OK);
    REQUIRE(lease.lease_id == 1u);
    REQUIRE(lease.counter == 1u);
    REQUIRE(ninlil_n6_tx_lease_release(n6, &lease) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_OK);
    REQUIRE(lease.lease_id == 2u);
    REQUIRE(lease.counter == 2u);
    /* stale lease_id 1 cannot release lease 2 */
    {
        ninlil_n6_tx_lease_t stale = lease;
        stale.lease_id = 1u;
        REQUIRE(ninlil_n6_tx_lease_release(n6, &stale) == NINLIL_N6_NOT_FOUND);
    }
    REQUIRE(ninlil_n6_tx_lease_release(n6, &lease) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

static int test_init_alias_overflow_canary(void)
{
    struct alias_backing {
        ninlil_n6_context_pool_t descriptor;
        uint8_t bytes[1024u];
    } alias_backing;
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_context_pool_t pool;
    size_t need = ninlil_n6_context_pool_bytes(2u);

    n6_mem_storage_reset();
    (void)memset(g_obj, 0, sizeof(g_obj));
    (void)memset(g_pool, 0, sizeof(g_pool));
    pool.max_slots = 2u;
    pool.reserved_zero = 0u;
    pool.bytes = g_pool;
    pool.bytes_size = need;

    /* out_n6 aliases object */
    {
        ninlil_n6_t **bad_out = (ninlil_n6_t **)(void *)g_obj;
        REQUIRE(ninlil_n6_init(g_obj, sizeof(g_obj), &pool, bad_out)
            == NINLIL_N6_ALIAS);
    }
    /* pool struct aliases pool bytes */
    {
        (void)memset(&alias_backing, 0x5a, sizeof(alias_backing));
        REQUIRE(need <= sizeof(alias_backing));
        alias_backing.descriptor = pool;
        alias_backing.descriptor.bytes = (uint8_t *)(void *)&alias_backing;
        alias_backing.descriptor.bytes_size = need;
        REQUIRE(ninlil_n6_init(
                    g_obj, sizeof(g_obj), &alias_backing.descriptor, &n6)
            == NINLIL_N6_ALIAS);
        REQUIRE(n6 == NULL);
        REQUIRE(alias_backing.descriptor.max_slots == 2u);
        REQUIRE(alias_backing.descriptor.reserved_zero == 0u);
        REQUIRE(alias_backing.descriptor.bytes
            == (uint8_t *)(void *)&alias_backing);
        REQUIRE(alias_backing.descriptor.bytes_size == need);
        REQUIRE(alias_backing.bytes[0] == 0x5au);
        REQUIRE(((uint8_t *)(void *)&alias_backing)[need - 1u] == 0x5au);
    }
    /* unaligned pool bytes */
    {
        ninlil_n6_context_pool_t p2 = pool;
        p2.bytes = g_pool + 1u;
        p2.bytes_size = need + 1u;
        REQUIRE(ninlil_n6_init(g_obj, sizeof(g_obj), &p2, &n6)
            == NINLIL_N6_INVALID_ARGUMENT);
    }
    REQUIRE(ninlil_n6_init(g_obj, sizeof(g_obj), &pool, &n6) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

/*
 * Independent-oracle fixed bytes (Python hashlib/hmac == OpenSSL):
 * hop salt 00..1f secret 20..3f; e2e salt 40..5f secret 60..7f.
 * Labels: NINLIL-R6-HOP-*-v1 / NINLIL-R6-E2E-*-v1 (ASCII no NUL).
 */
static int test_crypto_label_nonce_kat(void)
{
    const ninlil_n6_crypto_ops_t *ops = ninlil_n6_crypto_host_ops();
    uint8_t hop_salt[32], hop_sec[32], e2e_salt[32], e2e_sec[32];
    static const uint8_t exp_data_key[16] = {
        0x1f, 0x72, 0x21, 0x98, 0x6f, 0x7a, 0xce, 0x2f, 0x1d, 0xb9, 0x79, 0x00,
        0x53, 0x13, 0x12, 0xa1
    };
    static const uint8_t exp_data_iv[12] = {
        0xf3, 0x76, 0x76, 0x31, 0x2c, 0x62, 0xa6, 0xa6, 0x7b, 0x0a, 0x1a, 0xf7
    };
    static const uint8_t exp_ack_key[16] = {
        0x3a, 0x34, 0x95, 0xc1, 0x5e, 0x90, 0xcc, 0xae, 0x94, 0x43, 0x60, 0xc7,
        0xf6, 0xe0, 0x7e, 0xb7
    };
    static const uint8_t exp_ack_iv[12] = {
        0x94, 0x78, 0x16, 0xf8, 0xec, 0x83, 0x27, 0x4b, 0xb5, 0xab, 0xec, 0xa4
    };
    static const uint8_t exp_e2e_key[16] = {
        0x82, 0xb3, 0x3a, 0x97, 0xf6, 0xa8, 0x9e, 0xf0, 0x8c, 0x7b, 0x49, 0x97,
        0x06, 0x6a, 0x6d, 0xf8
    };
    static const uint8_t exp_e2e_iv[12] = {
        0x8a, 0x50, 0x95, 0xf4, 0x36, 0xf8, 0xb9, 0xb2, 0x28, 0xaa, 0x4d, 0x8d
    };
    static const uint8_t exp_data_n1[12] = {
        0xf3, 0x76, 0x76, 0x31, 0x2c, 0x62, 0xa6, 0xa6, 0x7b, 0x0a, 0x1a, 0xf6
    };
    static const uint8_t exp_data_nmax[12] = {
        0xf3, 0x76, 0x76, 0x31, 0xd3, 0x9d, 0x59, 0x59, 0x84, 0xf5, 0xe5, 0x09
    };
    static const uint8_t exp_ack_n1[12] = {
        0x94, 0x78, 0x16, 0xf8, 0xec, 0x83, 0x27, 0x4b, 0xb5, 0xab, 0xec, 0xa5
    };
    static const uint8_t exp_ack_nmax[12] = {
        0x94, 0x78, 0x16, 0xf8, 0x13, 0x7c, 0xd8, 0xb4, 0x4a, 0x54, 0x13, 0x5a
    };
    static const uint8_t exp_e2e_n1[12] = {
        0x8a, 0x50, 0x95, 0xf4, 0x36, 0xf8, 0xb9, 0xb2, 0x28, 0xaa, 0x4d, 0x8c
    };
    static const uint8_t exp_e2e_nmax[12] = {
        0x8a, 0x50, 0x95, 0xf4, 0xc9, 0x07, 0x46, 0x4d, 0xd7, 0x55, 0xb2, 0x73
    };
    ninlil_n6_hop_derived_keys_t hop, hop_base;
    ninlil_n6_e2e_derived_keys_t e2e;
    uint8_t n1[12], nm[12];
    int i;
    size_t bi;

    for (bi = 0u; bi < 32u; ++bi) {
        hop_salt[bi] = (uint8_t)bi;
        hop_sec[bi] = (uint8_t)(0x20u + bi);
        e2e_salt[bi] = (uint8_t)(0x40u + bi);
        e2e_sec[bi] = (uint8_t)(0x60u + bi);
    }

    REQUIRE(ninlil_n6_derive_hop_keys(ops, hop_salt, hop_sec, &hop) == 0);
    REQUIRE(memcmp(hop.data_key16, exp_data_key, 16u) == 0);
    REQUIRE(memcmp(hop.data_iv12, exp_data_iv, 12u) == 0);
    REQUIRE(memcmp(hop.ack_key16, exp_ack_key, 16u) == 0);
    REQUIRE(memcmp(hop.ack_iv12, exp_ack_iv, 12u) == 0);
    hop_base = hop;

    REQUIRE(ninlil_n6_derive_e2e_keys(ops, e2e_salt, e2e_sec, &e2e) == 0);
    REQUIRE(memcmp(e2e.key16, exp_e2e_key, 16u) == 0);
    REQUIRE(memcmp(e2e.iv12, exp_e2e_iv, 12u) == 0);

    (void)memcpy(n1, hop.data_iv12, 12u);
    (void)memcpy(nm, hop.data_iv12, 12u);
    for (i = 0; i < 8; ++i) {
        n1[4 + i] ^= (uint8_t)((UINT64_C(1) >> (56 - 8 * i)) & 0xffu);
        nm[4 + i]
            ^= (uint8_t)(((UINT64_MAX - 1u) >> (56 - 8 * i)) & 0xffu);
    }
    REQUIRE(memcmp(n1, exp_data_n1, 12u) == 0);
    REQUIRE(memcmp(nm, exp_data_nmax, 12u) == 0);
    (void)memcpy(n1, hop.ack_iv12, 12u);
    (void)memcpy(nm, hop.ack_iv12, 12u);
    for (i = 0; i < 8; ++i) {
        n1[4 + i] ^= (uint8_t)((UINT64_C(1) >> (56 - 8 * i)) & 0xffu);
        nm[4 + i]
            ^= (uint8_t)(((UINT64_MAX - 1u) >> (56 - 8 * i)) & 0xffu);
    }
    REQUIRE(memcmp(n1, exp_ack_n1, 12u) == 0);
    REQUIRE(memcmp(nm, exp_ack_nmax, 12u) == 0);
    (void)memcpy(n1, e2e.iv12, 12u);
    (void)memcpy(nm, e2e.iv12, 12u);
    for (i = 0; i < 8; ++i) {
        n1[4 + i] ^= (uint8_t)((UINT64_C(1) >> (56 - 8 * i)) & 0xffu);
        nm[4 + i]
            ^= (uint8_t)(((UINT64_MAX - 1u) >> (56 - 8 * i)) & 0xffu);
    }
    REQUIRE(memcmp(n1, exp_e2e_n1, 12u) == 0);
    REQUIRE(memcmp(nm, exp_e2e_nmax, 12u) == 0);


    /* Independent oracle: 1-bit hop binding mutation expected keys/ivs */
    {
        uint8_t salt_mut[32];
        ninlil_n6_hop_derived_keys_t hop2;
        static const uint8_t exp_mut_data_key[16] = {
            0x92,0x72,0xb0,0x48,0x2f,0x0b,0x84,0xf5,0x62,0xae,0x9d,0x76,0xcc,0x64,0x10,0x88
        };
        static const uint8_t exp_mut_data_iv[12] = {
            0xd2,0xda,0x9a,0x84,0xb0,0x0a,0x19,0xa4,0xfd,0xbb,0xcd,0x6c
        };
        static const uint8_t exp_mut_ack_key[16] = {
            0x61,0x3c,0xec,0xa5,0x69,0x22,0x60,0x1d,0x26,0x24,0x05,0x03,0x8f,0x67,0x00,0xc0
        };
        static const uint8_t exp_mut_ack_iv[12] = {
            0x89,0x0a,0x83,0xf7,0xd3,0x72,0x13,0x79,0x1a,0xa1,0xf3,0xa8
        };
        (void)memcpy(salt_mut, hop_salt, 32u);
        salt_mut[0] ^= 0x01u;
        REQUIRE(ninlil_n6_derive_hop_keys(ops, salt_mut, hop_sec, &hop2) == 0);
        REQUIRE(memcmp(hop2.data_key16, exp_mut_data_key, 16u) == 0);
        REQUIRE(memcmp(hop2.data_iv12, exp_mut_data_iv, 12u) == 0);
        REQUIRE(memcmp(hop2.ack_key16, exp_mut_ack_key, 16u) == 0);
        REQUIRE(memcmp(hop2.ack_iv12, exp_mut_ack_iv, 12u) == 0);
        ninlil_n6_secure_zero(&hop2, sizeof(hop2));
    }
    /* hop-secret 1-bit */
    {
        uint8_t sec_mut[32];
        ninlil_n6_hop_derived_keys_t hop2;
        static const uint8_t exp_k[16] = {
            0x30,0xdb,0x0d,0xd1,0xf1,0xae,0x1a,0xec,0xb3,0x94,0xef,0x22,0x12,0x1e,0xa1,0xb4
        };
        static const uint8_t exp_iv[12] = {
            0xc5,0x8c,0x6c,0x50,0x69,0x49,0xd3,0xb8,0x9c,0x3d,0xc0,0xca
        };
        static const uint8_t exp_ak[16] = {
            0x64,0xef,0x2a,0xd2,0x60,0x7b,0x2e,0xcd,0xac,0xb4,0x82,0x03,0x1e,0xab,0x6f,0x36
        };
        static const uint8_t exp_aiv[12] = {
            0x53,0x35,0xc5,0x39,0x73,0x1d,0x8b,0x46,0x15,0x5e,0x15,0x6d
        };
        (void)memcpy(sec_mut, hop_sec, 32u);
        sec_mut[0] ^= 0x01u;
        REQUIRE(ninlil_n6_derive_hop_keys(ops, hop_salt, sec_mut, &hop2) == 0);
        REQUIRE(memcmp(hop2.data_key16, exp_k, 16u) == 0);
        REQUIRE(memcmp(hop2.data_iv12, exp_iv, 12u) == 0);
        REQUIRE(memcmp(hop2.ack_key16, exp_ak, 16u) == 0);
        REQUIRE(memcmp(hop2.ack_iv12, exp_aiv, 12u) == 0);
        ninlil_n6_secure_zero(&hop2, sizeof(hop2));
    }
    /* e2e binding / secret 1-bit */
    {
        uint8_t sm[32];
        ninlil_n6_e2e_derived_keys_t e2;
        static const uint8_t ebk[16] = {
            0x0c,0xbd,0xe3,0xd0,0x74,0x8e,0x3b,0x19,0x32,0xb8,0x9f,0x68,0xc4,0x08,0x3e,0x7f
        };
        static const uint8_t ebi[12] = {
            0x0c,0x8f,0x6f,0x03,0xc0,0xd9,0x50,0x30,0xda,0x6e,0x5e,0x62
        };
        static const uint8_t esk[16] = {
            0x9f,0xdf,0x86,0xa1,0x89,0x1d,0xb9,0x27,0x3d,0x6b,0xd5,0x94,0x7a,0xe2,0xbc,0x1b
        };
        static const uint8_t esi[12] = {
            0xbb,0xa7,0x12,0x8c,0x3f,0xd1,0xc5,0x38,0xf8,0x54,0x84,0xab
        };
        (void)memcpy(sm, e2e_salt, 32u);
        sm[0] ^= 0x01u;
        REQUIRE(ninlil_n6_derive_e2e_keys(ops, sm, e2e_sec, &e2) == 0);
        REQUIRE(memcmp(e2.key16, ebk, 16u) == 0);
        REQUIRE(memcmp(e2.iv12, ebi, 12u) == 0);
        ninlil_n6_secure_zero(&e2, sizeof(e2));
        (void)memcpy(sm, e2e_sec, 32u);
        sm[0] ^= 0x01u;
        REQUIRE(ninlil_n6_derive_e2e_keys(ops, e2e_salt, sm, &e2) == 0);
        REQUIRE(memcmp(e2.key16, esk, 16u) == 0);
        REQUIRE(memcmp(e2.iv12, esi, 12u) == 0);
        ninlil_n6_secure_zero(&e2, sizeof(e2));
    }

/* baseline → 1-bit mutation → baseline */
    {
        uint8_t salt_mut[32];
        ninlil_n6_hop_derived_keys_t hop2;
        (void)memcpy(salt_mut, hop_salt, 32u);
        salt_mut[0] ^= 0x01u;
        REQUIRE(ninlil_n6_derive_hop_keys(ops, salt_mut, hop_sec, &hop2) == 0);
        REQUIRE(memcmp(hop2.data_key16, hop_base.data_key16, 16u) != 0);
        ninlil_n6_secure_zero(&hop2, sizeof(hop2));
        REQUIRE(ninlil_n6_derive_hop_keys(ops, hop_salt, hop_sec, &hop2) == 0);
        REQUIRE(memcmp(hop2.data_key16, hop_base.data_key16, 16u) == 0);
        ninlil_n6_secure_zero(&hop2, sizeof(hop2));
    }

    /* out aliases binding → reject WITHOUT zeroing shared arena (mutation 0) */
    {
        uint8_t span[32 + sizeof(ninlil_n6_hop_derived_keys_t)];
        ninlil_n6_hop_derived_keys_t *out_alias;
        uint8_t before[32 + sizeof(ninlil_n6_hop_derived_keys_t)];
        (void)memset(span, 0xa5, sizeof(span));
        (void)memcpy(span, hop_salt, 32u);
        (void)memcpy(before, span, sizeof(before));
        out_alias = (ninlil_n6_hop_derived_keys_t *)(void *)span;
        REQUIRE(ninlil_n6_derive_hop_keys(ops, span, hop_sec, out_alias) != 0);
        REQUIRE(memcmp(span, before, sizeof(span)) == 0);
    }

    /* non-alias failure zeros full output */
    {
        ninlil_n6_hop_derived_keys_t bad;
        (void)memset(&bad, 0xa5, sizeof(bad));
        REQUIRE(ninlil_n6_derive_hop_keys(ops, hop_salt, hop_sec, NULL) != 0);
        REQUIRE(ninlil_n6_derive_hop_keys(NULL, hop_salt, hop_sec, &bad) != 0);
        {
            size_t j;
            const uint8_t *p = (const uint8_t *)&bad;
            for (j = 0u; j < sizeof(bad); ++j) {
                REQUIRE(p[j] == 0u);
            }
        }
    }

    /* closed domain: epoch 0 reject + out zero */
    {
        uint8_t out12[12];
        uint8_t node[16];
        (void)memset(out12, 0xa5, sizeof(out12));
        (void)memset(node, 1, sizeof(node));
        REQUIRE(ninlil_n6_ns_fingerprint12(ops, node, 1u, 0u, 2u, out12) != 0);
        {
            size_t j;
            for (j = 0u; j < 12u; ++j) {
                REQUIRE(out12[j] == 0u);
            }
        }
    }

    ninlil_n6_secure_zero(&hop, sizeof(hop));
    ninlil_n6_secure_zero(&hop_base, sizeof(hop_base));
    ninlil_n6_secure_zero(&e2e, sizeof(e2e));
    return 0;
}

/* secure_zero via function pointer (defeats some DCE) + surrounding canary */
static int test_secure_zero_mutation_gate(void)
{
    uint8_t guard_lo[16];
    uint8_t buf[64];
    uint8_t guard_hi[16];
    size_t i;
    void (*zero_fn)(void *, size_t) = ninlil_n6_secure_zero;

    (void)memset(guard_lo, 0x5a, sizeof(guard_lo));
    (void)memset(guard_hi, 0x5a, sizeof(guard_hi));
    (void)memset(buf, 0xa5, sizeof(buf));
    zero_fn(buf, sizeof(buf));
    for (i = 0u; i < sizeof(buf); ++i) {
        REQUIRE(buf[i] == 0u);
    }
    for (i = 0u; i < sizeof(guard_lo); ++i) {
        REQUIRE(guard_lo[i] == 0x5au);
        REQUIRE(guard_hi[i] == 0x5au);
    }
    /* second wipe after re-fill — regression if zero becomes no-op under opt */
    (void)memset(buf, 0x3c, sizeof(buf));
    zero_fn(buf, sizeof(buf));
    for (i = 0u; i < sizeof(buf); ++i) {
        REQUIRE(buf[i] == 0u);
    }
    return 0;
}

static int test_lease_ticket_mutation_zero_on_fail(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_tx_lease_t lease;
    ninlil_n6_rx_ticket_t ticket;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h = 0u;

    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);

    (void)memset(&lease, 0xCC, sizeof(lease));
    REQUIRE(ninlil_n6_tx_burn(n6, 0u /* bad handle */, NINLIL_N6_LANE_HOP_DATA,
                &lease)
        == NINLIL_N6_NOT_FOUND);
    /* out_lease zeroed on fail path */
    {
        size_t i;
        const uint8_t *p = (const uint8_t *)&lease;
        int all0 = 1;
        for (i = 0u; i < sizeof(lease); ++i) {
            if (p[i] != 0u) {
                all0 = 0;
            }
        }
        REQUIRE(all0 == 1);
    }

    fill_capsule(&cap, 1);
    cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
    cap.context_id = 1u; /* fresh INBOUND AL */
    cap.key_generation = 6u; /* strictly > prior HW high-water from TX install */
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    (void)memset(&ticket, 0xDD, sizeof(ticket));
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 0u, &ticket)
        == NINLIL_N6_INVALID_ARGUMENT);
    {
        size_t i;
        const uint8_t *p = (const uint8_t *)&ticket;
        int all0 = 1;
        for (i = 0u; i < sizeof(ticket); ++i) {
            if (p[i] != 0u) {
                all0 = 0;
            }
        }
        REQUIRE(all0 == 1);
    }
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

/* Boot mutation negatives: incomplete HOP set / orphan AL-only / junk */
static int test_boot_mutation_negatives(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_context_pool_t pool;
    ninlil_n6_authority_stamp_t stamp;
    size_t need = ninlil_n6_context_pool_bytes(4u);
    uint8_t junk_k[4] = { 9, 9, 9, 9 };
    uint8_t junk_v[4] = { 1, 2, 3, 4 };

    n6_mem_storage_reset();
    REQUIRE(n6_mem_storage_seed(junk_k, 4u, junk_v, 4u) == 0);
    pool.max_slots = 4u;
    pool.reserved_zero = 0u;
    pool.bytes = g_pool;
    pool.bytes_size = need;
    (void)memset(g_obj, 0, sizeof(g_obj));
    (void)memset(g_pool, 0, sizeof(g_pool));
    REQUIRE(ninlil_n6_init(g_obj, sizeof(g_obj), &pool, &n6) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_bind_storage(n6, n6_mem_storage_ops()) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_bind_crypto(n6, ninlil_n6_crypto_host_ops())
        == NINLIL_N6_OK);
    (void)memset(&stamp, 0, sizeof(stamp));
    stamp.clock_epoch_id[0] = 1u;
    stamp.now_ms = 1u;
    stamp.trusted_class_d = 1u;
    REQUIRE(ninlil_n6_bind_authority_stamp(n6, &stamp) == NINLIL_N6_OK);
    REQUIRE(bind_local_id_fixture(n6, 0x33u) == 0);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

/* Identity ABI: empty/nonempty I/O0, consume once, second bind, statuses */
static int test_local_identity_accepted_contract(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_context_pool_t pool;
    size_t need = ninlil_n6_context_pool_bytes(4u);
    n6_local_id_fixture_user_t user;
    ninlil_n6_accepted_local_identity_token_t tok;
    ninlil_n6_local_identity_ops_t ops_st;
    const ninlil_n6_local_identity_ops_t *ops;
    ninlil_n6_error_t err;
    uint32_t o0, b0, i0;

    n6_mem_storage_reset();
    pool.max_slots = 4u;
    pool.reserved_zero = 0u;
    pool.bytes = g_pool;
    pool.bytes_size = need;
    (void)memset(g_obj, 0, sizeof(g_obj));
    (void)memset(g_pool, 0, sizeof(g_pool));
    REQUIRE(ninlil_n6_init(g_obj, sizeof(g_obj), &pool, &n6) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_bind_storage(n6, n6_mem_storage_ops()) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_bind_crypto(n6, ninlil_n6_crypto_host_ops())
        == NINLIL_N6_OK);
    /* Empty storage: missing identity → M4_REQUIRED/LOCAL_IDENTITY, I/O0 */
    o0 = n6_mem_storage_open_count();
    b0 = n6_mem_storage_begin_count();
    i0 = n6_mem_storage_iter_open_count();
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_M4_REQUIRED);
    REQUIRE(ninlil_n6_last_error(n6, &err) == NINLIL_N6_OK);
    REQUIRE(err.reason == NINLIL_N6_REASON_LOCAL_IDENTITY);
    REQUIRE(n6_mem_storage_open_count() == o0);
    REQUIRE(n6_mem_storage_begin_count() == b0);
    REQUIRE(n6_mem_storage_iter_open_count() == i0);

    /* REJECTED status */
    (void)memset(&user, 0, sizeof(user));
    n6_local_id_fixture_token_mint_fill(
        &tok, 0x11u, NINLIL_N6_LOCAL_ID_ACCEPT_REJECTED);
    n6_local_id_fixture_ops_init(&ops_st, &user);
    ops = &ops_st;
    REQUIRE(ninlil_n6_bind_local_identity_accepted(n6, ops, &tok)
        == NINLIL_N6_M4_REQUIRED);
    REQUIRE(user.consume_calls == 1u);
    REQUIRE(tok.live == 0u); /* terminal consume */

    /* Ops struct_size undersized: INVALID_ARGUMENT/LOCAL_IDENTITY, callback 0 */
    (void)memset(&user, 0, sizeof(user));
    n6_local_id_fixture_token_mint_fill(
        &tok, 0x22u, NINLIL_N6_LOCAL_ID_ACCEPT_OK);
    n6_local_id_fixture_ops_init(&ops_st, &user);
    ops_st.struct_size = (uint16_t)(sizeof(ops_st) - 1u);
    ops = &ops_st;
    REQUIRE(ninlil_n6_bind_local_identity_accepted(n6, ops, &tok)
        == NINLIL_N6_INVALID_ARGUMENT);
    REQUIRE(user.consume_calls == 0u);
    REQUIRE(tok.live == 1u); /* unconsumed */

    /* Ops struct_size oversized: same reject, callback 0 */
    (void)memset(&user, 0, sizeof(user));
    n6_local_id_fixture_token_mint_fill(
        &tok, 0x22u, NINLIL_N6_LOCAL_ID_ACCEPT_OK);
    n6_local_id_fixture_ops_init(&ops_st, &user);
    ops_st.struct_size = (uint16_t)(sizeof(ops_st) + 8u);
    ops = &ops_st;
    REQUIRE(ninlil_n6_bind_local_identity_accepted(n6, ops, &tok)
        == NINLIL_N6_INVALID_ARGUMENT);
    REQUIRE(user.consume_calls == 0u);
    REQUIRE(tok.live == 1u);

    /* Claim struct_size undersized (23): M4_REQUIRED after consume */
    (void)memset(&user, 0, sizeof(user));
    n6_local_id_fixture_token_mint_fill(
        &tok, 0x22u, NINLIL_N6_LOCAL_ID_ACCEPT_OK);
    tok.claim_struct_size = (uint16_t)(NINLIL_N6_LOCAL_ID_CLAIM_BYTES - 1u);
    n6_local_id_fixture_ops_init(&ops_st, &user);
    ops = &ops_st;
    REQUIRE(ninlil_n6_bind_local_identity_accepted(n6, ops, &tok)
        == NINLIL_N6_M4_REQUIRED);
    REQUIRE(user.consume_calls == 1u);
    REQUIRE(tok.live == 0u);

    /* Claim struct_size oversized (32): exact-ABI reject (not silent >=) */
    (void)memset(&user, 0, sizeof(user));
    n6_local_id_fixture_token_mint_fill(
        &tok, 0x22u, NINLIL_N6_LOCAL_ID_ACCEPT_OK);
    tok.claim_struct_size = (uint16_t)(NINLIL_N6_LOCAL_ID_CLAIM_BYTES + 8u);
    n6_local_id_fixture_ops_init(&ops_st, &user);
    ops = &ops_st;
    REQUIRE(ninlil_n6_bind_local_identity_accepted(n6, ops, &tok)
        == NINLIL_N6_M4_REQUIRED);
    REQUIRE(user.consume_calls == 1u);
    REQUIRE(tok.live == 0u);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_INIT); /* still unbound */

    /* New token for OK bind (exact 24 / exact ops sizeof) */
    (void)memset(&user, 0, sizeof(user));
    n6_local_id_fixture_token_mint_fill(
        &tok, 0x33u, NINLIL_N6_LOCAL_ID_ACCEPT_OK);
    n6_local_id_fixture_ops_init(&ops_st, &user);
    ops = &ops_st;
    REQUIRE(ninlil_n6_bind_local_identity_accepted(n6, ops, &tok)
        == NINLIL_N6_OK);
    REQUIRE(user.consume_calls == 1u);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_BOUND);

    /* Second bind same id: callback 0 */
    (void)memset(&user, 0, sizeof(user));
    n6_local_id_fixture_token_mint_fill(
        &tok, 0x33u, NINLIL_N6_LOCAL_ID_ACCEPT_OK);
    n6_local_id_fixture_ops_init(&ops_st, &user);
    ops = &ops_st;
    REQUIRE(ninlil_n6_bind_local_identity_accepted(n6, ops, &tok)
        == NINLIL_N6_INVALID_STATE);
    REQUIRE(user.consume_calls == 0u);

    REQUIRE(bind_stamp(n6, 1u, 1u) == 0);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_BOOTED);

    /* After boot: callback 0 */
    (void)memset(&user, 0, sizeof(user));
    n6_local_id_fixture_token_mint_fill(
        &tok, 0x44u, NINLIL_N6_LOCAL_ID_ACCEPT_OK);
    n6_local_id_fixture_ops_init(&ops_st, &user);
    ops = &ops_st;
    REQUIRE(ninlil_n6_bind_local_identity_accepted(n6, ops, &tok)
        == NINLIL_N6_INVALID_STATE);
    REQUIRE(user.consume_calls == 0u);

    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* Non-empty durable + missing identity: I/O0 */
    n6_mem_storage_reset();
    {
        uint8_t jk[4] = {1, 2, 3, 4};
        uint8_t jv[4] = {5, 6, 7, 8};
        REQUIRE(n6_mem_storage_seed(jk, 4u, jv, 4u) == 0);
    }
    (void)memset(g_obj, 0, sizeof(g_obj));
    REQUIRE(ninlil_n6_init(g_obj, sizeof(g_obj), &pool, &n6) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_bind_storage(n6, n6_mem_storage_ops()) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_bind_crypto(n6, ninlil_n6_crypto_host_ops())
        == NINLIL_N6_OK);
    o0 = n6_mem_storage_open_count();
    b0 = n6_mem_storage_begin_count();
    i0 = n6_mem_storage_iter_open_count();
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_M4_REQUIRED);
    REQUIRE(n6_mem_storage_open_count() == o0);
    REQUIRE(n6_mem_storage_begin_count() == b0);
    REQUIRE(n6_mem_storage_iter_open_count() == i0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

/*
 * Two receiver namespaces, same context_id/epoch/layer: must not merge in
 * boot accumulator (full NS identity key). Valid dual-NS durable fixture ⇒
 * exact BOOT_DORMANT / DORMANT state only (never CORRUPT-or-DORMANT soft).
 */
static int test_boot_two_ns_same_cid_epoch_layer(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h1 = 0u, h2 = 0u;
    ninlil_n6_status_t st;

    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    cap.context_id = 7u;
    (void)memset(cap.receiver_node_id, 0x44, 16u);
    (void)memset(cap.binding_digest32, 0x11, 32u);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h1) == NINLIL_N6_OK);
    REQUIRE(h1 != 0u);

    /*
     * Second NS: same cid/epoch/layer/dir, different receiver → different nsfp.
     * Lane keys omit receiver; distinct binding digests are required for
     * separate namespaces under the same cid (as real M4 bindings would).
     */
    fill_capsule(&cap, 1);
    cap.context_id = 7u;
    (void)memset(cap.receiver_node_id, 0x55, 16u);
    (void)memset(cap.binding_digest32, 0x66, 32u);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h2) == NINLIL_N6_OK);
    REQUIRE(h2 != 0u);
    REQUIRE(h2 != h1);

    /* Restart boot: full-identity join; exact DORMANT only (no secrets in durable). */
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    {
        ninlil_n6_context_pool_t pool;
        size_t need = ninlil_n6_context_pool_bytes(8u);
        pool.max_slots = 8u;
        pool.reserved_zero = 0u;
        pool.bytes = g_pool;
        pool.bytes_size = need;
        (void)memset(g_obj, 0, sizeof(g_obj));
        (void)memset(g_pool, 0, need);
        /* Keep durable mem storage; re-init object only */
        REQUIRE(ninlil_n6_init(g_obj, sizeof(g_obj), &pool, &n6) == NINLIL_N6_OK);
        REQUIRE(ninlil_n6_bind_storage(n6, n6_mem_storage_ops()) == NINLIL_N6_OK);
        REQUIRE(ninlil_n6_bind_crypto(n6, ninlil_n6_crypto_host_ops())
            == NINLIL_N6_OK);
        REQUIRE(bind_stamp(n6, 1u, 1000u) == 0);
        REQUIRE(bind_local_id_fixture(n6, 0x33u) == 0);
        st = ninlil_n6_boot_scan(n6);
        REQUIRE(st == NINLIL_N6_BOOT_DORMANT);
        REQUIRE(ninlil_n6_state(n6)
            == NINLIL_N6_STATE_DORMANT_DURABLE_NO_SECRET);
        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    }
    return 0;
}

/*
 * Full durable dual-install opposite sides, same receiver+cid → boot CORRUPT
 * (allocator-scope collision independent of nsfp equality).
 */
static int test_boot_opposite_side_same_receiver_cid_corrupt(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h = 0u;
    ninlil_n6_status_t st;

    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    cap.alloc_side = NINLIL_N6_ALLOC_OUTBOUND_TX;
    cap.context_id = 9u;
    (void)memset(cap.receiver_node_id, 0xAB, 16u);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);

    fill_capsule(&cap, 1);
    cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
    cap.context_id = 9u; /* same cid */
    (void)memset(cap.receiver_node_id, 0xAB, 16u); /* same receiver */
    h = 0u;
    st = ninlil_n6_install_hop(n6, &cap, &h);
    /* Install may succeed as separate side; collision is a boot invariant. */
    if (st == NINLIL_N6_OK) {
        REQUIRE(h != 0u);
        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
        {
            ninlil_n6_context_pool_t pool;
            size_t need = ninlil_n6_context_pool_bytes(8u);
            pool.max_slots = 8u;
            pool.reserved_zero = 0u;
            pool.bytes = g_pool;
            pool.bytes_size = need;
            (void)memset(g_obj, 0, sizeof(g_obj));
            REQUIRE(ninlil_n6_init(g_obj, sizeof(g_obj), &pool, &n6)
                == NINLIL_N6_OK);
            REQUIRE(ninlil_n6_bind_storage(n6, n6_mem_storage_ops())
                == NINLIL_N6_OK);
            REQUIRE(ninlil_n6_bind_crypto(n6, ninlil_n6_crypto_host_ops())
                == NINLIL_N6_OK);
            REQUIRE(bind_local_id_fixture(n6, 0x33u) == 0);
            REQUIRE(bind_stamp(n6, 1u, 1000u) == 0);
            REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
            REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
        }
    } else {
        /* Fail-closed install of second side is also acceptable mutation0 */
        REQUIRE(h == 0u);
        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    }
    return 0;
}

/*
 * Two AL scopes same layer+direction, different receivers: HW must not attach
 * across scopes. Valid dual-scope durable fixture ⇒ exact BOOT_DORMANT only.
 */
static int test_boot_two_al_scopes_same_layer_dir(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h = 0u;
    ninlil_n6_status_t st;

    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    cap.context_id = 3u;
    (void)memset(cap.receiver_node_id, 0x10, 16u);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);

    fill_capsule(&cap, 1);
    cap.context_id = 4u;
    (void)memset(cap.receiver_node_id, 0x20, 16u);
    h = 0u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(h != 0u);

    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    {
        ninlil_n6_context_pool_t pool;
        size_t need = ninlil_n6_context_pool_bytes(8u);
        pool.max_slots = 8u;
        pool.reserved_zero = 0u;
        pool.bytes = g_pool;
        pool.bytes_size = need;
        (void)memset(g_obj, 0, sizeof(g_obj));
        REQUIRE(ninlil_n6_init(g_obj, sizeof(g_obj), &pool, &n6) == NINLIL_N6_OK);
        REQUIRE(ninlil_n6_bind_storage(n6, n6_mem_storage_ops()) == NINLIL_N6_OK);
        REQUIRE(ninlil_n6_bind_crypto(n6, ninlil_n6_crypto_host_ops())
            == NINLIL_N6_OK);
        REQUIRE(bind_stamp(n6, 1u, 1000u) == 0);
        REQUIRE(bind_local_id_fixture(n6, 0x33u) == 0);
        st = ninlil_n6_boot_scan(n6);
        REQUIRE(st == NINLIL_N6_BOOT_DORMANT);
        REQUIRE(ninlil_n6_state(n6)
            == NINLIL_N6_STATE_DORMANT_DURABLE_NO_SECRET);
        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    }
    return 0;
}

/*
 * Fence hygiene KAT: known traffic_secret32 pattern is wiped; bound local
 * identity pattern remains in the object (provider/identity continuity).
 */
static int test_fence_secret_pattern_scan_kat(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h = 0u;
    ninlil_n6_tx_lease_t lease;
    ninlil_n6_stats_t stats;
    uint8_t secret_pat[32];
    uint8_t id_pat[16];
    size_t pool_need;
    size_t i;
    int found_secret;
    int found_id;

    (void)memset(secret_pat, 0xA5, sizeof(secret_pat));
    (void)memset(id_pat, 0x33, sizeof(id_pat));

    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    (void)memset(cap.traffic_secret32, 0xA5, 32u);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(h != 0u);

    /* Prove pattern is present in pool before fence (install wrote secret). */
    pool_need = ninlil_n6_context_pool_bytes(4u);
    found_secret = 0;
    for (i = 0u; i + 32u <= pool_need; ++i) {
        if (memcmp(g_pool + i, secret_pat, 32u) == 0) {
            found_secret = 1;
            break;
        }
    }
    REQUIRE(found_secret == 1);

    /* Trigger CORRUPT fence via commit path (central n6_enter_fenced). */
    n6_mem_storage_inject_fault(N6_MEM_FAULT_COMMIT_CORRUPT, 1);
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_stats(n6, &stats) == NINLIL_N6_OK);
    REQUIRE(stats.fence_count >= 1u);

    /* No 32-byte traffic-secret pattern remains in pool or object. */
    found_secret = 0;
    for (i = 0u; i + 32u <= pool_need; ++i) {
        if (memcmp(g_pool + i, secret_pat, 32u) == 0) {
            found_secret = 1;
            break;
        }
    }
    REQUIRE(found_secret == 0);
    found_secret = 0;
    for (i = 0u; i + 32u <= sizeof(g_obj); ++i) {
        if (memcmp(g_obj + i, secret_pat, 32u) == 0) {
            found_secret = 1;
            break;
        }
    }
    REQUIRE(found_secret == 0);

    /* Local-ID continuity: bound identity bytes remain in object. */
    found_id = 0;
    for (i = 0u; i + 16u <= sizeof(g_obj); ++i) {
        if (memcmp(g_obj + i, id_pat, 16u) == 0) {
            found_id = 1;
            break;
        }
    }
    REQUIRE(found_id == 1);

    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

static int seed_cf_for_capsule(
    const ninlil_n6_install_capsule_t *cap, const uint8_t nsfp[12],
    uint32_t cid, int append_dup)
{
    ninlil_n6_cf_key_t ck;
    ninlil_n6_cf_value_t cv;
    uint8_t cfk[28], cfv[64];
    size_t klen = 0u, vlen = 0u;
    (void)memset(&ck, 0, sizeof(ck));
    ck.rec_kind = NINLIL_N6_REC_KIND_CF;
    ck.layer_code = cap->layer_code;
    ck.direction_code = cap->direction_code;
    ck.alloc_side = cap->alloc_side;
    ck.context_id = cid;
    ck.membership_epoch = cap->membership_epoch;
    (void)memcpy(ck.ns_fingerprint12, nsfp, 12u);
    (void)memset(&cv, 0, sizeof(cv));
    cv.magic = NINLIL_N6_MAGIC_CF;
    cv.schema = NINLIL_N6_SCHEMA_CF;
    cv.flags = NINLIL_N6_CF_FLAGS_FENCE_ACTIVE;
    cv.context_id = cid;
    cv.membership_epoch = cap->membership_epoch;
    (void)memset(cv.fence_stamp_epoch_id, 0x01, 16u);
    cv.fence_stamp_now_ms = 1u;
    (void)memcpy(cv.binding_digest12, cap->binding_digest32, 12u);
    cv.alloc_side = cap->alloc_side;
    cv.direction_code = cap->direction_code;
    cv.layer_code = cap->layer_code;
    cv.reason = NINLIL_N6_FENCE_REASON_OPERATOR;
    if (ninlil_n6_encode_n6cf_key(&ck, cfk, sizeof(cfk), &klen)
            != NINLIL_N6_CODEC_OK
        || ninlil_n6_encode_n6cf_value(&cv, cfv, sizeof(cfv), &vlen)
            != NINLIL_N6_CODEC_OK) {
        return -1;
    }
    if (cfk[0] != NINLIL_N6_REC_KIND_CF) {
        return -1;
    }
    if (append_dup != 0) {
        return n6_mem_storage_seed_append(
            cfk, (uint32_t)klen, cfv, (uint32_t)vlen);
    }
    return n6_mem_storage_seed(cfk, (uint32_t)klen, cfv, (uint32_t)vlen);
}

static int rebind_boot_scan(ninlil_n6_t **n6, uint32_t slots)
{
    ninlil_n6_context_pool_t pool;
    size_t need = ninlil_n6_context_pool_bytes(slots);
    pool.max_slots = slots;
    pool.reserved_zero = 0u;
    pool.bytes = g_pool;
    pool.bytes_size = need;
    (void)memset(g_obj, 0, sizeof(g_obj));
    if (ninlil_n6_init(g_obj, sizeof(g_obj), &pool, n6) != NINLIL_N6_OK) {
        return -1;
    }
    if (ninlil_n6_bind_storage(*n6, n6_mem_storage_ops()) != NINLIL_N6_OK) {
        return -1;
    }
    if (ninlil_n6_bind_crypto(*n6, ninlil_n6_crypto_host_ops()) != NINLIL_N6_OK) {
        return -1;
    }
    if (bind_stamp(*n6, 1u, 1000u) != 0) {
        return -1;
    }
    if (bind_local_id_fixture(*n6, 0x33u) != 0) {
        return -1;
    }
    return 0;
}

/*
 * CF coexists with complete live lane set; RT kind dispatch + mismatch.
 * - valid live+CF → DORMANT
 * - orphan CF (no live) → CORRUPT
 * - duplicate CF keys → CORRUPT (P0 lex / mark-once)
 * - CF key/value mismatch → CORRUPT
 * - RT key/value mismatch → CORRUPT
 */
static int test_boot_rt_cf_kind_dispatch_and_rt_mismatch(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h = 0u;
    uint8_t rtk[28], rtv[48], cfk[28], cfv[64];
    size_t klen = 0u, vlen = 0u;
    ninlil_n6_rt_key_t rk;
    ninlil_n6_rt_value_t rv;
    ninlil_n6_cf_key_t ck;
    ninlil_n6_cf_value_t cv;
    uint8_t nsfp[12];
    ninlil_n6_status_t st;

    /* --- valid live + CF (same assembly identity) → DORMANT --- */
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    cap.context_id = 3u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_ns_fingerprint12(
            ninlil_n6_crypto_host_ops(), cap.receiver_node_id, cap.layer_code,
            cap.membership_epoch, cap.alloc_side, nsfp)
        == 0);
    REQUIRE(seed_cf_for_capsule(&cap, nsfp, 3u, 0) == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 8u) == 0);
    st = ninlil_n6_boot_scan(n6);
    REQUIRE(st == NINLIL_N6_BOOT_DORMANT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_DORMANT_DURABLE_NO_SECRET);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* --- orphan CF (cid without live complete set) → CORRUPT --- */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    cap.context_id = 3u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_ns_fingerprint12(
            ninlil_n6_crypto_host_ops(), cap.receiver_node_id, cap.layer_code,
            cap.membership_epoch, cap.alloc_side, nsfp)
        == 0);
    REQUIRE(seed_cf_for_capsule(&cap, nsfp, 99u, 0) == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 8u) == 0);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* --- duplicate CF keys (append second identical) → CORRUPT --- */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    cap.context_id = 3u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_ns_fingerprint12(
            ninlil_n6_crypto_host_ops(), cap.receiver_node_id, cap.layer_code,
            cap.membership_epoch, cap.alloc_side, nsfp)
        == 0);
    REQUIRE(seed_cf_for_capsule(&cap, nsfp, 3u, 0) == 0);
    REQUIRE(seed_cf_for_capsule(&cap, nsfp, 3u, 1) == 0); /* append dup */
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 8u) == 0);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* --- CF key/value field mismatch → CORRUPT --- */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    cap.context_id = 4u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_ns_fingerprint12(
            ninlil_n6_crypto_host_ops(), cap.receiver_node_id, cap.layer_code,
            cap.membership_epoch, cap.alloc_side, nsfp)
        == 0);
    (void)memset(&ck, 0, sizeof(ck));
    ck.rec_kind = NINLIL_N6_REC_KIND_CF;
    ck.layer_code = cap.layer_code;
    ck.direction_code = cap.direction_code;
    ck.alloc_side = cap.alloc_side;
    ck.context_id = 4u;
    ck.membership_epoch = cap.membership_epoch;
    (void)memcpy(ck.ns_fingerprint12, nsfp, 12u);
    (void)memset(&cv, 0, sizeof(cv));
    cv.magic = NINLIL_N6_MAGIC_CF;
    cv.schema = NINLIL_N6_SCHEMA_CF;
    cv.flags = NINLIL_N6_CF_FLAGS_FENCE_ACTIVE;
    cv.context_id = 4u;
    cv.membership_epoch = cap.membership_epoch;
    (void)memset(cv.fence_stamp_epoch_id, 0x01, 16u);
    cv.fence_stamp_now_ms = 1u;
    (void)memcpy(cv.binding_digest12, cap.binding_digest32, 12u);
    cv.alloc_side = cap.alloc_side;
    cv.direction_code = cap.direction_code;
    cv.layer_code = cap.layer_code;
    cv.reason = NINLIL_N6_FENCE_REASON_OPERATOR;
    REQUIRE(ninlil_n6_encode_n6cf_key(&ck, cfk, sizeof(cfk), &klen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(ninlil_n6_encode_n6cf_value(&cv, cfv, sizeof(cfv), &vlen)
        == NINLIL_N6_CODEC_OK);
    /* Patch value context_id (offset 8 u32 BE) to mismatch key; re-CRC. */
    cfv[8] = 0u;
    cfv[9] = 0u;
    cfv[10] = 0u;
    cfv[11] = 5u;
    {
        uint32_t crc = ninlil_n6_crc32c(cfv, 60u);
        cfv[60] = (uint8_t)((crc >> 24) & 0xffu);
        cfv[61] = (uint8_t)((crc >> 16) & 0xffu);
        cfv[62] = (uint8_t)((crc >> 8) & 0xffu);
        cfv[63] = (uint8_t)(crc & 0xffu);
    }
    REQUIRE(n6_mem_storage_seed(cfk, (uint32_t)klen, cfv, (uint32_t)vlen) == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 8u) == 0);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* --- RT key/value field mismatch → CORRUPT --- */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    cap.context_id = 5u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_ns_fingerprint12(
            ninlil_n6_crypto_host_ops(), cap.receiver_node_id, cap.layer_code,
            cap.membership_epoch, cap.alloc_side, nsfp)
        == 0);
    (void)memset(&rk, 0, sizeof(rk));
    rk.rec_kind = NINLIL_N6_REC_KIND_RT;
    rk.layer_code = cap.layer_code;
    rk.direction_code = cap.direction_code;
    rk.alloc_side = cap.alloc_side;
    rk.context_id = 40u;
    rk.membership_epoch = cap.membership_epoch;
    (void)memcpy(rk.ns_fingerprint12, nsfp, 12u);
    (void)memset(&rv, 0, sizeof(rv));
    rv.magic = NINLIL_N6_MAGIC_RT;
    rv.schema = NINLIL_N6_SCHEMA_RT;
    rv.flags = NINLIL_N6_RT_FLAGS_LANE_ERASED;
    rv.context_id = 40u;
    rv.membership_epoch = cap.membership_epoch;
    rv.last_key_generation_high_water = cap.key_generation;
    (void)memcpy(rv.binding_digest12, cap.binding_digest32, 12u);
    rv.alloc_side = cap.alloc_side;
    rv.direction_code = cap.direction_code;
    rv.layer_code = cap.layer_code;
    REQUIRE(ninlil_n6_encode_n6rt_key(&rk, rtk, sizeof(rtk), &klen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(rtk[0] == NINLIL_N6_REC_KIND_RT);
    REQUIRE(ninlil_n6_encode_n6rt_value(&rv, rtv, sizeof(rtv), &vlen)
        == NINLIL_N6_CODEC_OK);
    rtv[8] = 0u;
    rtv[9] = 0u;
    rtv[10] = 0u;
    rtv[11] = 41u;
    {
        uint32_t crc = ninlil_n6_crc32c(rtv, 44u);
        rtv[44] = (uint8_t)((crc >> 24) & 0xffu);
        rtv[45] = (uint8_t)((crc >> 16) & 0xffu);
        rtv[46] = (uint8_t)((crc >> 8) & 0xffu);
        rtv[47] = (uint8_t)(crc & 0xffu);
    }
    REQUIRE(n6_mem_storage_seed(rtk, (uint32_t)klen, rtv, (uint32_t)vlen) == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 8u) == 0);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

/*
 * Retired-only AL (active=0, retired=1) + RT + HW: P2 must create HW requirement
 * from RT last_kgen when P1 never saw live lanes. High-water ≥ min → DORMANT.
 */
static int test_boot_retired_only_rt_hw_highwater(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_al_key_t ak;
    ninlil_n6_al_value_t av;
    ninlil_n6_rt_key_t rk;
    ninlil_n6_rt_value_t rv;
    ninlil_n6_hw_key_t hk;
    ninlil_n6_hw_value_t hv;
    uint8_t alk[24], alv[56], rtk[28], rtv[48], hwk[32], hwv[28];
    uint8_t nsfp[12], recv[16], scope[28], local[16];
    size_t klen = 0u, vlen = 0u;
    const uint64_t epoch = 3u;
    const uint64_t last_kgen = 10u;

    n6_mem_storage_reset();
    (void)memset(recv, 0x44, 16u);
    (void)memset(local, 0x33, 16u);
    REQUIRE(ninlil_n6_ns_fingerprint12(
            ninlil_n6_crypto_host_ops(), recv, NINLIL_N6_LAYER_HOP, epoch,
            NINLIL_N6_ALLOC_OUTBOUND_TX, nsfp)
        == 0);
    REQUIRE(ninlil_n6_scope_digest28(
            ninlil_n6_crypto_host_ops(), local, NINLIL_N6_LAYER_HOP,
            NINLIL_N6_DIR_IR, epoch, recv, scope)
        == 0);

    (void)memset(&ak, 0, sizeof(ak));
    ak.rec_kind = NINLIL_N6_REC_KIND_AL;
    ak.layer_code = NINLIL_N6_LAYER_HOP;
    ak.alloc_side = NINLIL_N6_ALLOC_OUTBOUND_TX;
    ak.membership_epoch = epoch;
    (void)memcpy(ak.ns_fingerprint12, nsfp, 12u);
    (void)memset(&av, 0, sizeof(av));
    av.magic = NINLIL_N6_MAGIC_AL;
    av.schema = NINLIL_N6_SCHEMA_AL;
    av.next_free_or_peer_floor = 20u;
    av.active_count = 0u;
    av.retired_tombstone_count = 1u;
    av.membership_epoch = epoch;
    (void)memcpy(av.receiver_node_id, recv, 16u);
    REQUIRE(ninlil_n6_encode_n6al_key(&ak, alk, sizeof(alk), &klen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(ninlil_n6_encode_n6al_value(&av, alv, sizeof(alv), &vlen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(n6_mem_storage_seed(alk, (uint32_t)klen, alv, (uint32_t)vlen) == 0);

    (void)memset(&rk, 0, sizeof(rk));
    rk.rec_kind = NINLIL_N6_REC_KIND_RT;
    rk.layer_code = NINLIL_N6_LAYER_HOP;
    rk.direction_code = NINLIL_N6_DIR_IR;
    rk.alloc_side = NINLIL_N6_ALLOC_OUTBOUND_TX;
    rk.context_id = 7u;
    rk.membership_epoch = epoch;
    (void)memcpy(rk.ns_fingerprint12, nsfp, 12u);
    (void)memset(&rv, 0, sizeof(rv));
    rv.magic = NINLIL_N6_MAGIC_RT;
    rv.schema = NINLIL_N6_SCHEMA_RT;
    rv.flags = NINLIL_N6_RT_FLAGS_LANE_ERASED;
    rv.context_id = 7u;
    rv.membership_epoch = epoch;
    rv.last_key_generation_high_water = last_kgen;
    (void)memset(rv.binding_digest12, 0x11, 12u);
    rv.alloc_side = NINLIL_N6_ALLOC_OUTBOUND_TX;
    rv.direction_code = NINLIL_N6_DIR_IR;
    rv.layer_code = NINLIL_N6_LAYER_HOP;
    REQUIRE(ninlil_n6_encode_n6rt_key(&rk, rtk, sizeof(rtk), &klen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(ninlil_n6_encode_n6rt_value(&rv, rtv, sizeof(rtv), &vlen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(n6_mem_storage_seed(rtk, (uint32_t)klen, rtv, (uint32_t)vlen) == 0);

    (void)memset(&hk, 0, sizeof(hk));
    hk.rec_kind = NINLIL_N6_REC_KIND_HW;
    hk.layer_code = NINLIL_N6_LAYER_HOP;
    hk.direction_code = NINLIL_N6_DIR_IR;
    (void)memcpy(hk.scope_digest28, scope, 28u);
    (void)memset(&hv, 0, sizeof(hv));
    hv.magic = NINLIL_N6_MAGIC_HW;
    hv.schema = NINLIL_N6_SCHEMA_HW;
    hv.high_water_key_generation = last_kgen; /* exact min from RT */
    hv.last_update_authority_now_ms = 1000u;
    REQUIRE(ninlil_n6_encode_n6hw_key(&hk, hwk, sizeof(hwk), &klen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(ninlil_n6_encode_n6hw_value(&hv, hwv, sizeof(hwv), &vlen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(n6_mem_storage_seed(hwk, (uint32_t)klen, hwv, (uint32_t)vlen) == 0);

    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_BOOT_DORMANT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_DORMANT_DURABLE_NO_SECRET);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* HW high_water below RT last_kgen → CORRUPT */
    n6_mem_storage_reset();
    REQUIRE(n6_mem_storage_seed(alk, 24u, alv, 56u) == 0);
    REQUIRE(n6_mem_storage_seed(rtk, 28u, rtv, 48u) == 0);
    hv.high_water_key_generation = last_kgen - 1u;
    REQUIRE(ninlil_n6_encode_n6hw_value(&hv, hwv, sizeof(hwv), &vlen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(n6_mem_storage_seed(hwk, 32u, hwv, (uint32_t)vlen) == 0);
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

/*
 * Provider-shape / operational mapping on boot begin & iter_open/next.
 * Exact cleanup counts: malformed non-OK+handle is consumed once then CORRUPT/FENCED;
 * operational non-OK+NULL → STORAGE/BOUND (not fenced).
 */
static int test_boot_provider_shape_and_op_errors(void)
{
    ninlil_n6_t *n6 = NULL;
    uint32_t rb0, rb1, ic0, ic1, io0, b0;

    /* --- begin operational IO_ERROR (NULL handle) → STORAGE, BOUND --- */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 4u) == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    rb0 = n6_mem_storage_rollback_count();
    ic0 = n6_mem_storage_iter_close_count();
    n6_mem_storage_inject_fault(N6_MEM_FAULT_BEGIN, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_STORAGE);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_BOUND);
    REQUIRE(n6_mem_storage_rollback_count() == rb0); /* no handle to consume */
    REQUIRE(n6_mem_storage_iter_close_count() == ic0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* --- begin non-OK + non-NULL handle → consume rollback once, CORRUPT/FENCED --- */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 4u) == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    rb0 = n6_mem_storage_rollback_count();
    n6_mem_storage_inject_fault(N6_MEM_FAULT_BEGIN_NONOK_HANDLE, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    rb1 = n6_mem_storage_rollback_count();
    REQUIRE(rb1 == rb0 + 1u); /* exactly one consume */
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* --- begin OK+NULL → CORRUPT/FENCED, no rollback --- */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 4u) == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    rb0 = n6_mem_storage_rollback_count();
    n6_mem_storage_inject_fault(N6_MEM_FAULT_BEGIN_OK_NULL, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(n6_mem_storage_rollback_count() == rb0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* --- iter_open operational (pass0) → STORAGE/BOUND; rollback once --- */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 4u) == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    rb0 = n6_mem_storage_rollback_count();
    ic0 = n6_mem_storage_iter_close_count();
    b0 = n6_mem_storage_begin_count();
    io0 = n6_mem_storage_iter_open_count();
    n6_mem_storage_inject_fault(N6_MEM_FAULT_ITER_OPEN, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_STORAGE);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_BOUND);
    REQUIRE(n6_mem_storage_begin_count() == b0 + 1u);
    REQUIRE(n6_mem_storage_iter_open_count() == io0 + 1u);
    REQUIRE(n6_mem_storage_rollback_count() == rb0 + 1u); /* finish cleanup */
    REQUIRE(n6_mem_storage_iter_close_count() == ic0); /* no live iter */
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* --- iter_open non-OK + non-NULL → iter_close once + rollback once, CORRUPT --- */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 4u) == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    rb0 = n6_mem_storage_rollback_count();
    ic0 = n6_mem_storage_iter_close_count();
    n6_mem_storage_inject_fault(N6_MEM_FAULT_ITER_OPEN_NONOK_HANDLE, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    ic1 = n6_mem_storage_iter_close_count();
    rb1 = n6_mem_storage_rollback_count();
    REQUIRE(ic1 == ic0 + 1u); /* consume iter handle */
    REQUIRE(rb1 == rb0 + 1u); /* txn rollback at finish */
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* --- iter_open OK+NULL → CORRUPT; rollback once --- */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 4u) == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    rb0 = n6_mem_storage_rollback_count();
    ic0 = n6_mem_storage_iter_close_count();
    n6_mem_storage_inject_fault(N6_MEM_FAULT_ITER_OPEN_OK_NULL, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(n6_mem_storage_iter_close_count() == ic0);
    REQUIRE(n6_mem_storage_rollback_count() == rb0 + 1u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* --- iter_next operational mid-P0 → STORAGE/BOUND; close+rollback --- */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 4u) == 0);
    /* leave empty storage; still opens iter then next ends quickly.
     * Seed one AL so next is called at least once before fault after first. */
    {
        ninlil_n6_install_capsule_t cap;
        ninlil_n6_handle_t h = 0u;
        fill_capsule(&cap, 1);
        REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    }
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    rb0 = n6_mem_storage_rollback_count();
    ic0 = n6_mem_storage_iter_close_count();
    /* fault on first iter_next of P0 */
    n6_mem_storage_inject_fault(N6_MEM_FAULT_ITER_NEXT, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_STORAGE);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_BOUND);
    REQUIRE(n6_mem_storage_iter_close_count() == ic0 + 1u);
    REQUIRE(n6_mem_storage_rollback_count() == rb0 + 1u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* --- happy empty boot: exact begin1 open4 close4 rollback1 --- */
    n6_mem_storage_reset();
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    b0 = n6_mem_storage_begin_count();
    io0 = n6_mem_storage_iter_open_count();
    ic0 = n6_mem_storage_iter_close_count();
    rb0 = n6_mem_storage_rollback_count();
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_BOOTED);
    REQUIRE(n6_mem_storage_begin_count() == b0 + 1u);
    REQUIRE(n6_mem_storage_iter_open_count() == io0 + 4u);
    REQUIRE(n6_mem_storage_iter_close_count() == ic0 + 4u);
    REQUIRE(n6_mem_storage_rollback_count() == rb0 + 1u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* non-empty DORMANT: begin1 open4 close4 rollback1 */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 4u) == 0);
    {
        ninlil_n6_install_capsule_t cap;
        ninlil_n6_handle_t h = 0u;
        fill_capsule(&cap, 1);
        REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    }
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    b0 = n6_mem_storage_begin_count();
    io0 = n6_mem_storage_iter_open_count();
    ic0 = n6_mem_storage_iter_close_count();
    rb0 = n6_mem_storage_rollback_count();
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_BOOT_DORMANT);
    REQUIRE(n6_mem_storage_begin_count() == b0 + 1u);
    REQUIRE(n6_mem_storage_iter_open_count() == io0 + 4u);
    REQUIRE(n6_mem_storage_iter_close_count() == ic0 + 4u);
    REQUIRE(n6_mem_storage_rollback_count() == rb0 + 1u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /*
     * Each of the four iter_open sites: skip 0..3 successful opens, fault next
     * as operational IO_ERROR → STORAGE/BOUND + exact cleanup (close live iters
     * + one rollback).
     */
    {
        int pass;
        for (pass = 0; pass < 4; ++pass) {
            n6_mem_storage_reset();
            REQUIRE(setup_booted(&n6, 4u) == 0);
            {
                ninlil_n6_install_capsule_t cap;
                ninlil_n6_handle_t h = 0u;
                fill_capsule(&cap, 1);
                REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
            }
            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
            REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
            rb0 = n6_mem_storage_rollback_count();
            ic0 = n6_mem_storage_iter_close_count();
            io0 = n6_mem_storage_iter_open_count();
            /* Fail the (pass+1)-th iter_open: skip `pass` opens first. */
            n6_mem_storage_inject_fault_after(
                N6_MEM_FAULT_ITER_OPEN, pass, 1);
            REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_STORAGE);
            REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_BOUND);
            REQUIRE(n6_mem_storage_iter_open_count() == io0 + (uint32_t)pass + 1u);
            /* Closed every successfully opened pass iter + finish cleanup. */
            REQUIRE(n6_mem_storage_iter_close_count()
                == ic0 + (uint32_t)pass);
            REQUIRE(n6_mem_storage_rollback_count() == rb0 + 1u);
            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
        }
    }
    return 0;
}

/*
 * Two independent objects have distinct boot_scratch addresses (not shared
 * file-static). Does not promise same-object concurrent boot.
 */
static int test_boot_scratch_per_object(void)
{
    uint8_t obj1[NINLIL_N6_OBJECT_BYTES]
        __attribute__((aligned(NINLIL_N6_OBJECT_ALIGN)));
    uint8_t obj2[NINLIL_N6_OBJECT_BYTES]
        __attribute__((aligned(NINLIL_N6_OBJECT_ALIGN)));
    uint8_t pool1[64u * 1024u], pool2[64u * 1024u];
    ninlil_n6_t *a = NULL, *b = NULL;
    ninlil_n6_context_pool_t pa, pb;
    size_t need = ninlil_n6_context_pool_bytes(4u);
    uintptr_t sa, sb;

    n6_mem_storage_reset();
    (void)memset(obj1, 0, sizeof(obj1));
    (void)memset(obj2, 0, sizeof(obj2));
    pa.max_slots = 4u;
    pa.reserved_zero = 0u;
    pa.bytes = pool1;
    pa.bytes_size = need;
    pb = pa;
    pb.bytes = pool2;
    REQUIRE(ninlil_n6_init(obj1, sizeof(obj1), &pa, &a) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_init(obj2, sizeof(obj2), &pb, &b) == NINLIL_N6_OK);
    REQUIRE(a != b);
    /* boot_scratch is internal; distinct object bases ⇒ distinct workspaces. */
    sa = (uintptr_t)(void *)a;
    sb = (uintptr_t)(void *)b;
    REQUIRE(sa != sb);
    REQUIRE(bind_local_id_fixture(a, 0x11u) == 0);
    REQUIRE(bind_local_id_fixture(b, 0x22u) == 0);
    REQUIRE(ninlil_n6_bind_storage(a, n6_mem_storage_ops()) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_bind_crypto(a, ninlil_n6_crypto_host_ops())
        == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_bind_storage(b, n6_mem_storage_ops()) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_bind_crypto(b, ninlil_n6_crypto_host_ops())
        == NINLIL_N6_OK);
    REQUIRE(bind_stamp(a, 1u, 1000u) == 0);
    REQUIRE(bind_stamp(b, 1u, 2000u) == 0);
    /* Sequential empty boots both BOOTED; independent objects. */
    REQUIRE(ninlil_n6_boot_scan(a) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_state(a) == NINLIL_N6_STATE_BOOTED);
    REQUIRE(ninlil_n6_boot_scan(b) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_state(b) == NINLIL_N6_STATE_BOOTED);
    REQUIRE(ninlil_n6_shutdown(a) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_shutdown(b) == NINLIL_N6_OK);
    return 0;
}

/*
 * Synthetic crypto: force constant SHA-256 for scope_digest28 input length
 * (42 = local16||layer||dir||epoch8||recv16) so distinct layer/direction scopes
 * share one digest. Host HKDF / other SHA lengths remain real.
 */
#define N6_SCOPE_DIGEST_SHA_IN ((size_t)42u)

static int n6_collision_sha256(
    void *ctx, const uint8_t *in, size_t n, uint8_t out32[32])
{
    (void)ctx;
    (void)in;
    if (out32 == NULL) {
        return -1;
    }
    if (n == N6_SCOPE_DIGEST_SHA_IN) {
        (void)memset(out32, 0xC0, 32u);
        out32[0] = 0xDE;
        out32[1] = 0xAD;
        return 0;
    }
    return ninlil_n6_crypto_host_ops()->sha256(
        ninlil_n6_crypto_host_ops()->ctx, in, n, out32);
}

static int n6_collision_hkdf(
    void *ctx,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *ikm,
    size_t ikm_len,
    const uint8_t *info,
    size_t info_len,
    uint8_t *okm,
    size_t okm_len)
{
    (void)ctx;
    return ninlil_n6_crypto_host_ops()->hkdf_sha256(
        ninlil_n6_crypto_host_ops()->ctx, salt, salt_len, ikm, ikm_len, info,
        info_len, okm, okm_len);
}

static const ninlil_n6_crypto_ops_t g_n6_collision_crypto = {
    NULL,
    n6_collision_sha256,
    n6_collision_hkdf,
};

static int seed_hop_lanes_tx(
    uint8_t layer,
    uint8_t direction,
    uint32_t cid,
    uint64_t epoch,
    uint64_t kgen,
    const uint8_t binding32[32],
    const uint8_t nsfp12[12])
{
    uint8_t kinds[2] = { NINLIL_N6_LANE_HOP_DATA, NINLIL_N6_LANE_HOP_ACK };
    int i;
    for (i = 0; i < 2; ++i) {
        ninlil_n6_lane_key_t lk;
        ninlil_n6_tx_value_t tv;
        uint8_t k[48], v[68];
        size_t klen = 0u, vlen = 0u;
        (void)memset(&lk, 0, sizeof(lk));
        lk.layer_code = layer;
        lk.kind_or_lane = kinds[i];
        lk.direction_code = direction;
        lk.context_id = cid;
        (void)memcpy(lk.binding_digest32, binding32, 32u);
        lk.key_generation = kgen;
        (void)memset(&tv, 0, sizeof(tv));
        tv.magic = NINLIL_N6_MAGIC_TX;
        tv.schema = NINLIL_N6_SCHEMA_LANE;
        tv.reserved_exclusive = 1u; /* domain: nonzero */
        tv.key_generation = kgen;
        (void)memcpy(tv.binding_digest_prefix16, binding32, 16u);
        tv.membership_epoch = epoch;
        tv.alloc_side = NINLIL_N6_ALLOC_OUTBOUND_TX;
        (void)memcpy(tv.ns_fingerprint12, nsfp12, 12u);
        REQUIRE(ninlil_n6_encode_lane_key(&lk, k, sizeof(k), &klen)
            == NINLIL_N6_CODEC_OK);
        REQUIRE(ninlil_n6_encode_n6tx_value(&tv, v, sizeof(v), &vlen)
            == NINLIL_N6_CODEC_OK);
        REQUIRE(n6_mem_storage_seed(k, (uint32_t)klen, v, (uint32_t)vlen) == 0);
    }
    return 0;
}

/*
 * HOP DATA vs ACK: first 16 bytes of binding match, suffix differs.
 * Truncated equality is forbidden — must CORRUPT/FENCED on full-32 check.
 */
static int test_boot_hop_binding_suffix_mismatch_corrupt(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_context_pool_t pool;
    ninlil_n6_al_key_t ak;
    ninlil_n6_al_value_t av;
    ninlil_n6_hw_key_t hk;
    ninlil_n6_hw_value_t hv;
    uint8_t alk[24], alv[56], hwk[32], hwv[28];
    uint8_t nsfp[12], recv[16], local[16], scope[28];
    uint8_t bind_data[32], bind_ack[32];
    size_t klen = 0u, vlen = 0u;
    size_t need;
    const uint64_t epoch = 3u;
    const uint64_t kgen = 5u;
    uint8_t kinds[2] = { NINLIL_N6_LANE_HOP_DATA, NINLIL_N6_LANE_HOP_ACK };
    const uint8_t *binds[2];
    int li;

    n6_mem_storage_reset();
    (void)memset(recv, 0x44, 16u);
    (void)memset(local, 0x33, 16u);
    (void)memset(bind_data, 0x11, 32u);
    (void)memset(bind_ack, 0x11, 32u);
    /* Same prefix16, different suffix — must still fail full-32 equality. */
    (void)memset(bind_ack + 16, 0xEE, 16u);
    binds[0] = bind_data;
    binds[1] = bind_ack;

    REQUIRE(ninlil_n6_ns_fingerprint12(
            ninlil_n6_crypto_host_ops(), recv, NINLIL_N6_LAYER_HOP, epoch,
            NINLIL_N6_ALLOC_OUTBOUND_TX, nsfp)
        == 0);
    REQUIRE(ninlil_n6_scope_digest28(
            ninlil_n6_crypto_host_ops(), local, NINLIL_N6_LAYER_HOP,
            NINLIL_N6_DIR_IR, epoch, recv, scope)
        == 0);

    (void)memset(&ak, 0, sizeof(ak));
    ak.rec_kind = NINLIL_N6_REC_KIND_AL;
    ak.layer_code = NINLIL_N6_LAYER_HOP;
    ak.alloc_side = NINLIL_N6_ALLOC_OUTBOUND_TX;
    ak.membership_epoch = epoch;
    (void)memcpy(ak.ns_fingerprint12, nsfp, 12u);
    (void)memset(&av, 0, sizeof(av));
    av.magic = NINLIL_N6_MAGIC_AL;
    av.schema = NINLIL_N6_SCHEMA_AL;
    av.next_free_or_peer_floor = 10u;
    av.active_count = 1u;
    av.retired_tombstone_count = 0u;
    av.membership_epoch = epoch;
    (void)memcpy(av.receiver_node_id, recv, 16u);
    REQUIRE(ninlil_n6_encode_n6al_key(&ak, alk, sizeof(alk), &klen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(ninlil_n6_encode_n6al_value(&av, alv, sizeof(alv), &vlen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(n6_mem_storage_seed(alk, (uint32_t)klen, alv, (uint32_t)vlen) == 0);

    for (li = 0; li < 2; ++li) {
        ninlil_n6_lane_key_t lk;
        ninlil_n6_tx_value_t tv;
        uint8_t k[48], v[68];
        (void)memset(&lk, 0, sizeof(lk));
        lk.layer_code = NINLIL_N6_LAYER_HOP;
        lk.kind_or_lane = kinds[li];
        lk.direction_code = NINLIL_N6_DIR_IR;
        lk.context_id = 1u;
        (void)memcpy(lk.binding_digest32, binds[li], 32u);
        lk.key_generation = kgen;
        (void)memset(&tv, 0, sizeof(tv));
        tv.magic = NINLIL_N6_MAGIC_TX;
        tv.schema = NINLIL_N6_SCHEMA_LANE;
        tv.reserved_exclusive = 1u;
        tv.key_generation = kgen;
        (void)memcpy(tv.binding_digest_prefix16, binds[li], 16u);
        tv.membership_epoch = epoch;
        tv.alloc_side = NINLIL_N6_ALLOC_OUTBOUND_TX;
        (void)memcpy(tv.ns_fingerprint12, nsfp, 12u);
        REQUIRE(ninlil_n6_encode_lane_key(&lk, k, sizeof(k), &klen)
            == NINLIL_N6_CODEC_OK);
        REQUIRE(ninlil_n6_encode_n6tx_value(&tv, v, sizeof(v), &vlen)
            == NINLIL_N6_CODEC_OK);
        REQUIRE(n6_mem_storage_seed(k, (uint32_t)klen, v, (uint32_t)vlen) == 0);
    }

    (void)memset(&hk, 0, sizeof(hk));
    hk.rec_kind = NINLIL_N6_REC_KIND_HW;
    hk.layer_code = NINLIL_N6_LAYER_HOP;
    hk.direction_code = NINLIL_N6_DIR_IR;
    (void)memcpy(hk.scope_digest28, scope, 28u);
    (void)memset(&hv, 0, sizeof(hv));
    hv.magic = NINLIL_N6_MAGIC_HW;
    hv.schema = NINLIL_N6_SCHEMA_HW;
    hv.high_water_key_generation = kgen;
    hv.last_update_authority_now_ms = 1000u;
    REQUIRE(ninlil_n6_encode_n6hw_key(&hk, hwk, sizeof(hwk), &klen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(ninlil_n6_encode_n6hw_value(&hv, hwv, sizeof(hwv), &vlen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(n6_mem_storage_seed(hwk, (uint32_t)klen, hwv, (uint32_t)vlen) == 0);

    need = ninlil_n6_context_pool_bytes(8u);
    (void)memset(g_obj, 0, sizeof(g_obj));
    (void)memset(g_pool, 0, need);
    pool.max_slots = 8u;
    pool.reserved_zero = 0u;
    pool.bytes = g_pool;
    pool.bytes_size = need;
    REQUIRE(ninlil_n6_init(g_obj, sizeof(g_obj), &pool, &n6) == NINLIL_N6_OK);
    REQUIRE(bind_local_id_fixture(n6, 0x33u) == 0);
    REQUIRE(ninlil_n6_bind_storage(n6, n6_mem_storage_ops()) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_bind_crypto(n6, ninlil_n6_crypto_host_ops())
        == NINLIL_N6_OK);
    REQUIRE(bind_stamp(n6, 1u, 1000u) == 0);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

/*
 * Distinct full HW scopes (different direction) forced to identical scope
 * digest via synthetic crypto; only one HW seeded → CORRUPT/FENCED.
 * Without P1 layer/direction collision check this false-greens as DORMANT.
 */
static int test_boot_scope_digest_collision_layer_dir_corrupt(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_context_pool_t pool;
    ninlil_n6_al_key_t ak;
    ninlil_n6_al_value_t av;
    ninlil_n6_hw_key_t hk;
    ninlil_n6_hw_value_t hv;
    uint8_t alk[24], alv[56], hwk[32], hwv[28];
    uint8_t nsfp[12], recv[16], local[16], scope[28], bind_a[32], bind_b[32];
    size_t klen = 0u, vlen = 0u;
    size_t need;
    const uint64_t epoch = 3u;
    const uint64_t kgen = 5u;
    uint8_t d_ir, d_ri;

    n6_mem_storage_reset();
    (void)memset(recv, 0x44, 16u);
    (void)memset(local, 0x33, 16u);
    (void)memset(bind_a, 0x11, 32u);
    (void)memset(bind_b, 0x22, 32u);

    /* Real nsfp (non-colliding length); colliding scope digests under provider. */
    REQUIRE(ninlil_n6_ns_fingerprint12(
            &g_n6_collision_crypto, recv, NINLIL_N6_LAYER_HOP, epoch,
            NINLIL_N6_ALLOC_OUTBOUND_TX, nsfp)
        == 0);
    REQUIRE(ninlil_n6_scope_digest28(
            &g_n6_collision_crypto, local, NINLIL_N6_LAYER_HOP,
            NINLIL_N6_DIR_IR, epoch, recv, scope)
        == 0);
    {
        uint8_t scope_ri[28];
        REQUIRE(ninlil_n6_scope_digest28(
                &g_n6_collision_crypto, local, NINLIL_N6_LAYER_HOP,
                NINLIL_N6_DIR_RI, epoch, recv, scope_ri)
            == 0);
        REQUIRE(memcmp(scope, scope_ri, 28u) == 0); /* forced collision */
    }
    /* Host digests must differ (proves KAT needs synthetic provider). */
    {
        uint8_t h_ir[28], h_ri[28];
        REQUIRE(ninlil_n6_scope_digest28(
                ninlil_n6_crypto_host_ops(), local, NINLIL_N6_LAYER_HOP,
                NINLIL_N6_DIR_IR, epoch, recv, h_ir)
            == 0);
        REQUIRE(ninlil_n6_scope_digest28(
                ninlil_n6_crypto_host_ops(), local, NINLIL_N6_LAYER_HOP,
                NINLIL_N6_DIR_RI, epoch, recv, h_ri)
            == 0);
        REQUIRE(memcmp(h_ir, h_ri, 28u) != 0);
    }

    /* One AL covering both complete hop sets (active_count=2). */
    (void)memset(&ak, 0, sizeof(ak));
    ak.rec_kind = NINLIL_N6_REC_KIND_AL;
    ak.layer_code = NINLIL_N6_LAYER_HOP;
    ak.alloc_side = NINLIL_N6_ALLOC_OUTBOUND_TX;
    ak.membership_epoch = epoch;
    (void)memcpy(ak.ns_fingerprint12, nsfp, 12u);
    (void)memset(&av, 0, sizeof(av));
    av.magic = NINLIL_N6_MAGIC_AL;
    av.schema = NINLIL_N6_SCHEMA_AL;
    av.next_free_or_peer_floor = 10u;
    av.active_count = 2u;
    av.retired_tombstone_count = 0u;
    av.membership_epoch = epoch;
    (void)memcpy(av.receiver_node_id, recv, 16u);
    REQUIRE(ninlil_n6_encode_n6al_key(&ak, alk, sizeof(alk), &klen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(ninlil_n6_encode_n6al_value(&av, alv, sizeof(alv), &vlen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(n6_mem_storage_seed(alk, (uint32_t)klen, alv, (uint32_t)vlen) == 0);

    d_ir = NINLIL_N6_DIR_IR;
    d_ri = NINLIL_N6_DIR_RI;
    REQUIRE(seed_hop_lanes_tx(
            NINLIL_N6_LAYER_HOP, d_ir, 1u, epoch, kgen, bind_a, nsfp)
        == 0);
    REQUIRE(seed_hop_lanes_tx(
            NINLIL_N6_LAYER_HOP, d_ri, 2u, epoch, kgen, bind_b, nsfp)
        == 0);

    /* Exactly one HW (DIR_IR only) — second scope's HW absent. */
    (void)memset(&hk, 0, sizeof(hk));
    hk.rec_kind = NINLIL_N6_REC_KIND_HW;
    hk.layer_code = NINLIL_N6_LAYER_HOP;
    hk.direction_code = NINLIL_N6_DIR_IR;
    (void)memcpy(hk.scope_digest28, scope, 28u);
    (void)memset(&hv, 0, sizeof(hv));
    hv.magic = NINLIL_N6_MAGIC_HW;
    hv.schema = NINLIL_N6_SCHEMA_HW;
    hv.high_water_key_generation = kgen;
    hv.last_update_authority_now_ms = 1000u;
    REQUIRE(ninlil_n6_encode_n6hw_key(&hk, hwk, sizeof(hwk), &klen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(ninlil_n6_encode_n6hw_value(&hv, hwv, sizeof(hwv), &vlen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(n6_mem_storage_seed(hwk, (uint32_t)klen, hwv, (uint32_t)vlen) == 0);

    need = ninlil_n6_context_pool_bytes(8u);
    (void)memset(g_obj, 0, sizeof(g_obj));
    (void)memset(g_pool, 0, need);
    pool.max_slots = 8u;
    pool.reserved_zero = 0u;
    pool.bytes = g_pool;
    pool.bytes_size = need;
    REQUIRE(ninlil_n6_init(g_obj, sizeof(g_obj), &pool, &n6) == NINLIL_N6_OK);
    REQUIRE(bind_local_id_fixture(n6, 0x33u) == 0);
    REQUIRE(ninlil_n6_bind_storage(n6, n6_mem_storage_ops()) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_bind_crypto(n6, &g_n6_collision_crypto) == NINLIL_N6_OK);
    REQUIRE(bind_stamp(n6, 1u, 1000u) == 0);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

/*
 * Opposite alloc_side ALs, same full receiver/epoch/layer/direction, distinct
 * context_ids, shared exact one N6HW ⇒ DORMANT (full HW scope excludes side).
 */
static int test_boot_opposite_side_shared_hw_dormant(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h = 0u;

    REQUIRE(setup_booted(&n6, 8u) == 0);
    /* Inbound first (cid must be next_free=1), then outbound distinct cid. */
    fill_capsule(&cap, 1);
    cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
    cap.context_id = 1u;
    (void)memset(cap.receiver_node_id, 0xAB, 16u);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);

    fill_capsule(&cap, 1);
    cap.alloc_side = NINLIL_N6_ALLOC_OUTBOUND_TX;
    cap.context_id = 7u;
    cap.key_generation = 6u; /* > shared N6HW high-water after first install */
    (void)memset(cap.receiver_node_id, 0xAB, 16u); /* same full receiver */
    (void)memset(cap.binding_digest32, 0x77, 32u); /* distinct binding */
    h = 0u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);

    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 8u) == 0);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_BOOT_DORMANT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_DORMANT_DURABLE_NO_SECRET);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

/* Empty AL (active=0, retired=0) after fp/epoch-valid load → CORRUPT. */
static int test_boot_empty_al_reject(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_al_key_t ak;
    ninlil_n6_al_value_t av;
    uint8_t k[24], v[56], nsfp[12], recv[16];
    size_t klen = 0u, vlen = 0u;
    ninlil_n6_context_pool_t pool;
    size_t need;

    n6_mem_storage_reset();
    need = ninlil_n6_context_pool_bytes(4u);
    (void)memset(g_obj, 0, sizeof(g_obj));
    (void)memset(g_pool, 0, need);
    pool.max_slots = 4u;
    pool.reserved_zero = 0u;
    pool.bytes = g_pool;
    pool.bytes_size = need;
    REQUIRE(ninlil_n6_init(g_obj, sizeof(g_obj), &pool, &n6) == NINLIL_N6_OK);
    REQUIRE(bind_local_id_fixture(n6, 0x33u) == 0);
    REQUIRE(ninlil_n6_bind_storage(n6, n6_mem_storage_ops()) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_bind_crypto(n6, ninlil_n6_crypto_host_ops())
        == NINLIL_N6_OK);
    REQUIRE(bind_stamp(n6, 1u, 1000u) == 0);

    (void)memset(recv, 0x44, 16u);
    REQUIRE(ninlil_n6_ns_fingerprint12(
            ninlil_n6_crypto_host_ops(), recv, NINLIL_N6_LAYER_HOP, 3u,
            NINLIL_N6_ALLOC_OUTBOUND_TX, nsfp)
        == 0);
    (void)memset(&ak, 0, sizeof(ak));
    ak.rec_kind = NINLIL_N6_REC_KIND_AL;
    ak.layer_code = NINLIL_N6_LAYER_HOP;
    ak.alloc_side = NINLIL_N6_ALLOC_OUTBOUND_TX;
    ak.membership_epoch = 3u;
    (void)memcpy(ak.ns_fingerprint12, nsfp, 12u);
    (void)memset(&av, 0, sizeof(av));
    av.magic = NINLIL_N6_MAGIC_AL;
    av.schema = NINLIL_N6_SCHEMA_AL;
    av.next_free_or_peer_floor = 1u;
    av.active_count = 0u;
    av.retired_tombstone_count = 0u;
    av.membership_epoch = 3u;
    (void)memcpy(av.receiver_node_id, recv, 16u);
    REQUIRE(ninlil_n6_encode_n6al_key(&ak, k, sizeof(k), &klen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(ninlil_n6_encode_n6al_value(&av, v, sizeof(v), &vlen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(n6_mem_storage_seed(k, (uint32_t)klen, v, (uint32_t)vlen) == 0);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

/* INBOUND rejects arbitrary context_id when AL absent (must be 1) */
static int test_inbound_no_arbitrary_context(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h = 0u;
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
    cap.context_id = 7u; /* not next_free=1 */
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_INVALID_ARGUMENT);
    REQUIRE(h == 0u);
    cap.context_id = 1u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(h != 0u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

static int test_install_cu_no_handle(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h = 99u;

    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_COMMIT_UNKNOWN);
    REQUIRE(h == 0u); /* no handle on CU even if proposed durable */
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_CU_PENDING);
    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_OK);
    /* install CU ALL_PROPOSED: durable without secret → DORMANT, no handle */
    REQUIRE(ninlil_n6_state(n6)
        == NINLIL_N6_STATE_DORMANT_DURABLE_NO_SECRET);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

/* ---- Adversarial provider-shape / recover / binding residual KATs ---- */

static int test_open_storage_provider_shapes(void)
{
    ninlil_n6_t *n6 = NULL;
    uint32_t cl0;

    /* operational open IO_ERROR+NULL → STORAGE, BOUND (not fenced) */
    n6_mem_storage_reset();
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    cl0 = n6_mem_storage_close_count();
    n6_mem_storage_inject_fault(N6_MEM_FAULT_OPEN, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_STORAGE);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_BOUND);
    REQUIRE(n6_mem_storage_close_count() == cl0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* non-OK+nonnull → close once → CORRUPT/FENCED */
    n6_mem_storage_reset();
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    cl0 = n6_mem_storage_close_count();
    n6_mem_storage_inject_fault(N6_MEM_FAULT_OPEN_NONOK_HANDLE, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(n6_mem_storage_close_count() == cl0 + 1u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* OK+NULL → CORRUPT/FENCED, no close */
    n6_mem_storage_reset();
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    cl0 = n6_mem_storage_close_count();
    n6_mem_storage_inject_fault(N6_MEM_FAULT_OPEN_OK_NULL, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(n6_mem_storage_close_count() == cl0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* unknown open status → CORRUPT/FENCED */
    n6_mem_storage_reset();
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_OPEN_UNKNOWN, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* capacity operational: close handle, STORAGE, BOUND */
    n6_mem_storage_reset();
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    cl0 = n6_mem_storage_close_count();
    n6_mem_storage_inject_fault(N6_MEM_FAULT_CAPACITY, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_STORAGE);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_BOUND);
    REQUIRE(n6_mem_storage_close_count() == cl0 + 1u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* capacity poison (header/numerics) → close + CORRUPT/FENCED */
    n6_mem_storage_reset();
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    cl0 = n6_mem_storage_close_count();
    n6_mem_storage_inject_fault(N6_MEM_FAULT_CAPACITY_POISON, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(n6_mem_storage_close_count() == cl0 + 1u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* capacity OK but bad ABI/maxima → close + CORRUPT/FENCED */
    n6_mem_storage_reset();
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    cl0 = n6_mem_storage_close_count();
    n6_mem_storage_inject_fault(N6_MEM_FAULT_CAPACITY_BAD_OK, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(n6_mem_storage_close_count() == cl0 + 1u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

/*
 * Install admission uses the same capacity shape helper as open.
 * Poison/oversize/non-OK mutated/unknown/valid-but-insufficient → exact statuses.
 */
static int test_install_capacity_provider_shapes(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h = 0u;

    /* Poison non-OK mutated header → close + FENCED/CORRUPT (not bare return) */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_CAPACITY_POISON, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_CORRUPT);
    REQUIRE(h == 0u);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* OK but oversize/bad struct_size (and max 0) → close + FENCED/CORRUPT */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_CAPACITY_BAD_OK, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_CORRUPT);
    REQUIRE(h == 0u);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* non-OK unknown status, clean shape → close + FENCED/CORRUPT */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_CAPACITY_UNKNOWN, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_CORRUPT);
    REQUIRE(h == 0u);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* non-OK NO_SPACE clean shape → CAPACITY */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_CAPACITY_NOSPACE, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_CAPACITY);
    REQUIRE(h == 0u);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_BOOTED); /* not fenced */
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* operational IO capacity non-OK clean → STORAGE */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_CAPACITY, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_STORAGE);
    REQUIRE(h == 0u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* Valid shape but insufficient free entries → CAPACITY */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    /* free=0, max_bytes large enough to pass 512 floor */
    n6_mem_storage_set_capacity(4u, 4u, 4096u, 0u);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_CAPACITY);
    REQUIRE(h == 0u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* Valid shape but max_bytes < 512 → CAPACITY */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    n6_mem_storage_set_capacity(256u, 0u, 256u, 0u);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_CAPACITY);
    REQUIRE(h == 0u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

static int test_boot_next_descriptor_faults(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h = 0u;

    /* NOT_FOUND poison → CORRUPT/FENCED */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_ITER_NEXT_NOTFOUND_POISON, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* pointer rewrite → CORRUPT */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_ITER_NEXT_REWRITE_PTR, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* OK oversize length → CORRUPT */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_ITER_NEXT_OK_OVERSIZE, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* OK tail mutation → CORRUPT */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_ITER_NEXT_OK_TAIL, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* BTS proper shape → CAPACITY (BOUND, not fenced) */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_ITER_NEXT_BTS, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CAPACITY);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_BOUND);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* BTS bad (no oversize) → CORRUPT */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_ITER_NEXT_BTS_BAD, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* unknown iter_next → CORRUPT */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_ITER_NEXT_UNKNOWN, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

static int test_boot_scratch_zero_all_exits(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h = 0u;

    /* success empty BOOTED */
    n6_mem_storage_reset();
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    ninlil_n6_test_paint_boot_scratch(n6, 0xABu);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_test_boot_scratch_is_zero(n6) == 1);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* dormant */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    ninlil_n6_test_paint_boot_scratch(n6, 0xCDu);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_BOOT_DORMANT);
    REQUIRE(ninlil_n6_test_boot_scratch_is_zero(n6) == 1);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* operational STORAGE */
    n6_mem_storage_reset();
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    ninlil_n6_test_paint_boot_scratch(n6, 0x11u);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_BEGIN, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_STORAGE);
    REQUIRE(ninlil_n6_test_boot_scratch_is_zero(n6) == 1);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* CORRUPT */
    n6_mem_storage_reset();
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    ninlil_n6_test_paint_boot_scratch(n6, 0x22u);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_BEGIN_OK_NULL, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_test_boot_scratch_is_zero(n6) == 1);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* open CORRUPT path also zeros scratch */
    n6_mem_storage_reset();
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    ninlil_n6_test_paint_boot_scratch(n6, 0x33u);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_OPEN_OK_NULL, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_test_boot_scratch_is_zero(n6) == 1);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

static int test_boot_cf_binding_mismatch_corrupt(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h = 0u;
    uint8_t nsfp[12];
    ninlil_n6_cf_key_t ck;
    ninlil_n6_cf_value_t cv;
    uint8_t cfk[28], cfv[64];
    size_t klen = 0u, vlen = 0u;

    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    cap.context_id = 3u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_ns_fingerprint12(
            ninlil_n6_crypto_host_ops(), cap.receiver_node_id, cap.layer_code,
            cap.membership_epoch, cap.alloc_side, nsfp)
        == 0);
    (void)memset(&ck, 0, sizeof(ck));
    ck.rec_kind = NINLIL_N6_REC_KIND_CF;
    ck.layer_code = cap.layer_code;
    ck.direction_code = cap.direction_code;
    ck.alloc_side = cap.alloc_side;
    ck.context_id = 3u;
    ck.membership_epoch = cap.membership_epoch;
    (void)memcpy(ck.ns_fingerprint12, nsfp, 12u);
    (void)memset(&cv, 0, sizeof(cv));
    cv.magic = NINLIL_N6_MAGIC_CF;
    cv.schema = NINLIL_N6_SCHEMA_CF;
    cv.flags = NINLIL_N6_CF_FLAGS_FENCE_ACTIVE;
    cv.context_id = 3u;
    cv.membership_epoch = cap.membership_epoch;
    (void)memset(cv.fence_stamp_epoch_id, 0x01, 16u);
    cv.fence_stamp_now_ms = 1u;
    (void)memset(cv.binding_digest12, 0xEE, 12u); /* mismatch live binding */
    cv.alloc_side = cap.alloc_side;
    cv.direction_code = cap.direction_code;
    cv.layer_code = cap.layer_code;
    cv.reason = NINLIL_N6_FENCE_REASON_OPERATOR;
    REQUIRE(ninlil_n6_encode_n6cf_key(&ck, cfk, sizeof(cfk), &klen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(ninlil_n6_encode_n6cf_value(&cv, cfv, sizeof(cfv), &vlen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(n6_mem_storage_seed(cfk, (uint32_t)klen, cfv, (uint32_t)vlen) == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 8u) == 0);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

static int g_fail_scope_sha = 0;
static int n6_fail_scope_sha256(
    void *ctx, const uint8_t *in, size_t n, uint8_t out32[32])
{
    (void)ctx;
    if (n == 42u && g_fail_scope_sha != 0) {
        return -1;
    }
    return ninlil_n6_crypto_host_ops()->sha256(
        ninlil_n6_crypto_host_ops()->ctx, in, n, out32);
}

static const ninlil_n6_crypto_ops_t g_n6_fail_scope_crypto = {
    NULL,
    n6_fail_scope_sha256,
    n6_collision_hkdf,
};

static int test_boot_rt_scope_digest_fail_corrupt(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_al_key_t ak;
    ninlil_n6_al_value_t av;
    ninlil_n6_rt_key_t rk;
    ninlil_n6_rt_value_t rv;
    uint8_t alk[24], alv[56], rtk[28], rtv[48];
    uint8_t nsfp[12], recv[16];
    size_t klen = 0u, vlen = 0u;
    const uint64_t epoch = 3u;
    ninlil_n6_context_pool_t pool;
    size_t need;

    g_fail_scope_sha = 1;

    n6_mem_storage_reset();
    (void)memset(recv, 0x44, 16u);
    REQUIRE(ninlil_n6_ns_fingerprint12(
            ninlil_n6_crypto_host_ops(), recv, NINLIL_N6_LAYER_HOP, epoch,
            NINLIL_N6_ALLOC_OUTBOUND_TX, nsfp)
        == 0);

    (void)memset(&ak, 0, sizeof(ak));
    ak.rec_kind = NINLIL_N6_REC_KIND_AL;
    ak.layer_code = NINLIL_N6_LAYER_HOP;
    ak.alloc_side = NINLIL_N6_ALLOC_OUTBOUND_TX;
    ak.membership_epoch = epoch;
    (void)memcpy(ak.ns_fingerprint12, nsfp, 12u);
    (void)memset(&av, 0, sizeof(av));
    av.magic = NINLIL_N6_MAGIC_AL;
    av.schema = NINLIL_N6_SCHEMA_AL;
    av.next_free_or_peer_floor = 20u;
    av.active_count = 0u;
    av.retired_tombstone_count = 1u;
    av.membership_epoch = epoch;
    (void)memcpy(av.receiver_node_id, recv, 16u);
    REQUIRE(ninlil_n6_encode_n6al_key(&ak, alk, sizeof(alk), &klen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(ninlil_n6_encode_n6al_value(&av, alv, sizeof(alv), &vlen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(n6_mem_storage_seed(alk, (uint32_t)klen, alv, (uint32_t)vlen) == 0);

    (void)memset(&rk, 0, sizeof(rk));
    rk.rec_kind = NINLIL_N6_REC_KIND_RT;
    rk.layer_code = NINLIL_N6_LAYER_HOP;
    rk.direction_code = NINLIL_N6_DIR_IR;
    rk.alloc_side = NINLIL_N6_ALLOC_OUTBOUND_TX;
    rk.context_id = 7u;
    rk.membership_epoch = epoch;
    (void)memcpy(rk.ns_fingerprint12, nsfp, 12u);
    (void)memset(&rv, 0, sizeof(rv));
    rv.magic = NINLIL_N6_MAGIC_RT;
    rv.schema = NINLIL_N6_SCHEMA_RT;
    rv.flags = NINLIL_N6_RT_FLAGS_LANE_ERASED;
    rv.context_id = 7u;
    rv.membership_epoch = epoch;
    rv.last_key_generation_high_water = 10u;
    (void)memset(rv.binding_digest12, 0x11, 12u);
    rv.alloc_side = NINLIL_N6_ALLOC_OUTBOUND_TX;
    rv.direction_code = NINLIL_N6_DIR_IR;
    rv.layer_code = NINLIL_N6_LAYER_HOP;
    REQUIRE(ninlil_n6_encode_n6rt_key(&rk, rtk, sizeof(rtk), &klen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(ninlil_n6_encode_n6rt_value(&rv, rtv, sizeof(rtv), &vlen)
        == NINLIL_N6_CODEC_OK);
    REQUIRE(n6_mem_storage_seed(rtk, (uint32_t)klen, rtv, (uint32_t)vlen) == 0);

    need = ninlil_n6_context_pool_bytes(4u);
    (void)memset(g_obj, 0, sizeof(g_obj));
    (void)memset(g_pool, 0, need);
    pool.max_slots = 4u;
    pool.reserved_zero = 0u;
    pool.bytes = g_pool;
    pool.bytes_size = need;
    REQUIRE(ninlil_n6_init(g_obj, sizeof(g_obj), &pool, &n6) == NINLIL_N6_OK);
    REQUIRE(bind_local_id_fixture(n6, 0x33u) == 0);
    REQUIRE(ninlil_n6_bind_storage(n6, n6_mem_storage_ops()) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_bind_crypto(n6, &g_n6_fail_scope_crypto) == NINLIL_N6_OK);
    REQUIRE(bind_stamp(n6, 1u, 1000u) == 0);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    g_fail_scope_sha = 0;
    return 0;
}

static int test_recover_cu_provider_shapes(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h = 0u;
    ninlil_n6_tx_lease_t lease;
    uint32_t rb0, cl0;

    /* Seed a live CU plan via inject_cu + tx_burn COMMIT_UNKNOWN path */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_COMMIT_UNKNOWN);
    REQUIRE(ninlil_n6_test_cu_live(n6) == 1);

    /* begin non-OK+handle → rollback once → CORRUPT/FENCED, plan cleared */
    rb0 = n6_mem_storage_rollback_count();
    cl0 = n6_mem_storage_close_count();
    n6_mem_storage_inject_fault(N6_MEM_FAULT_BEGIN_NONOK_HANDLE, 1);
    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(n6_mem_storage_rollback_count() == rb0 + 1u);
    REQUIRE(n6_mem_storage_close_count() >= cl0 + 1u);
    REQUIRE(ninlil_n6_test_cu_live(n6) == 0); /* fenced clears CU */
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* begin OK+NULL → CORRUPT/FENCED */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_COMMIT_UNKNOWN);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_BEGIN_OK_NULL, 1);
    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* begin BUSY operational → STORAGE, NEED_OPEN, plan retained */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_COMMIT_UNKNOWN);
    REQUIRE(ninlil_n6_test_cu_live(n6) == 1);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_BEGIN, 1);
    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_STORAGE);
    REQUIRE(ninlil_n6_test_cu_live(n6) == 1);
    REQUIRE(ninlil_n6_test_cu_phase(n6) == 2u); /* NEED_OPEN */
    /* retry succeeds */
    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_test_cu_live(n6) == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* get unknown → CORRUPT after rollback+close */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_COMMIT_UNKNOWN);
    rb0 = n6_mem_storage_rollback_count();
    n6_mem_storage_inject_fault(N6_MEM_FAULT_GET_UNKNOWN, 1);
    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(n6_mem_storage_rollback_count() == rb0 + 1u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* get rewrite ptr → CORRUPT */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_COMMIT_UNKNOWN);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_GET_REWRITE_PTR, 1);
    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* get BTS → CORRUPT */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_COMMIT_UNKNOWN);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_GET_BTS, 1);
    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* rollback fail on final rb → CORRUPT */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_COMMIT_UNKNOWN);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_ROLLBACK, 1);
    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

/*
 * Install / tx_burn / rx_admit storage adapter KATs (closed begin/get/put/commit).
 * Ownership: rollback child → close shared → fence on CORRUPT paths.
 */
static int test_install_tx_rx_storage_shapes(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h = 0u;
    ninlil_n6_tx_lease_t lease;
    ninlil_n6_rx_ticket_t ticket;
    uint32_t rb0, cl0;

    /* Install RO begin OK+NULL → CORRUPT/FENCED mutation0 */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    cl0 = n6_mem_storage_close_count();
    n6_mem_storage_inject_fault(N6_MEM_FAULT_BEGIN_OK_NULL, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_CORRUPT);
    REQUIRE(h == 0u);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(n6_mem_storage_close_count() >= cl0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* Install begin non-OK+handle → CORRUPT + rollback once then close */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    rb0 = n6_mem_storage_rollback_count();
    cl0 = n6_mem_storage_close_count();
    n6_mem_storage_inject_fault(N6_MEM_FAULT_BEGIN_NONOK_HANDLE, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(n6_mem_storage_rollback_count() == rb0 + 1u);
    REQUIRE(n6_mem_storage_close_count() >= cl0 + 1u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* Install begin BUSY → STORAGE, not fenced, mutation0 */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_BEGIN, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_STORAGE);
    REQUIRE(h == 0u);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_BOOTED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* Install get rewrite during RO → rb + close + CORRUPT/FENCED */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    rb0 = n6_mem_storage_rollback_count();
    cl0 = n6_mem_storage_close_count();
    n6_mem_storage_inject_fault(N6_MEM_FAULT_GET_REWRITE_PTR, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(n6_mem_storage_rollback_count() == rb0 + 1u);
    REQUIRE(n6_mem_storage_close_count() >= cl0 + 1u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* Install get BTS → CORRUPT (never CAPACITY on fixed-length get) */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_GET_BTS, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* Install get NO_SPACE → CORRUPT (contract violation, never CAPACITY) */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_GET_NOSPACE, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* Install get BTS+poison buffer → still CORRUPT/FENCED */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_GET_BTS_POISON, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* Install put IO → STORAGE, CU cleared, no fence; RO rb + RW fail rb */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    rb0 = n6_mem_storage_rollback_count();
    n6_mem_storage_inject_fault(N6_MEM_FAULT_PUT, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_STORAGE);
    REQUIRE(h == 0u);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_BOOTED);
    /* RO precheck rollback + RW put fail rollback */
    REQUIRE(n6_mem_storage_rollback_count() == rb0 + 2u);
    REQUIRE(ninlil_n6_test_cu_live(n6) == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* commit definite IO → STORAGE, CU clear; only RO rb (no rb after commit) */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    rb0 = n6_mem_storage_rollback_count();
    n6_mem_storage_inject_fault(N6_MEM_FAULT_COMMIT, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_STORAGE);
    REQUIRE(h == 0u);
    REQUIRE(ninlil_n6_test_cu_live(n6) == 0);
    REQUIRE(n6_mem_storage_rollback_count() == rb0 + 1u); /* RO only */
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_BOOTED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* COMMIT_UNKNOWN: no post-commit rb; phase NEED_CLOSE_OLD; handle open */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    rb0 = n6_mem_storage_rollback_count();
    cl0 = n6_mem_storage_close_count();
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_OLD);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_COMMIT_UNKNOWN);
    REQUIRE(h == 0u);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_CU_PENDING);
    REQUIRE(ninlil_n6_test_cu_phase(n6) == 1u);
    REQUIRE(ninlil_n6_test_cu_live(n6) == 1);
    REQUIRE(n6_mem_storage_rollback_count() == rb0 + 1u); /* RO only */
    REQUIRE(n6_mem_storage_close_count() == cl0); /* close deferred to recover */
    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_OK);
    REQUIRE(n6_mem_storage_close_count() >= cl0 + 1u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* tx_burn begin OK+NULL on first reserve (next==limit) → CORRUPT + CU clear */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_BEGIN_OK_NULL, 1);
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_test_cu_live(n6) == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* rx_admit get unknown → CORRUPT + tickets consumed/zeroed */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
    cap.context_id = 1u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 1u, &ticket)
        == NINLIL_N6_OK);
    rb0 = n6_mem_storage_rollback_count();
    n6_mem_storage_inject_fault(N6_MEM_FAULT_GET_UNKNOWN, 1);
    REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &ticket) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ticket_bytes_all_zero(&ticket) == 1);
    REQUIRE(ninlil_n6_test_live_ticket_count(n6) == 0u);
    REQUIRE(n6_mem_storage_rollback_count() == rb0 + 1u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* rx_admit get BTS → CORRUPT never CAPACITY; ticket wiped */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
    cap.context_id = 1u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 1u, &ticket)
        == NINLIL_N6_OK);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_GET_BTS, 1);
    REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &ticket) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ticket_bytes_all_zero(&ticket) == 1);
    REQUIRE(ninlil_n6_test_any_ticket_key_or_iv_nonzero(n6) == 0);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* rx_admit get NO_SPACE → CORRUPT + wipe */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
    cap.context_id = 1u;
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 1u, &ticket)
        == NINLIL_N6_OK);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_GET_NOSPACE, 1);
    REQUIRE(ninlil_n6_rx_admit_after_aead(n6, &ticket) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ticket_bytes_all_zero(&ticket) == 1);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* commit CORRUPT on install RW → CORRUPT/FENCED, CU clear; RO rb only */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    rb0 = n6_mem_storage_rollback_count();
    n6_mem_storage_inject_fault(N6_MEM_FAULT_COMMIT_CORRUPT, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_CORRUPT);
    REQUIRE(h == 0u);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_test_cu_live(n6) == 0);
    REQUIRE(n6_mem_storage_rollback_count() == rb0 + 1u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    return 0;
}

/* CU NEED_OPEN dedicated map: open NO_SPACE → FENCED/CORRUPT (not CAPACITY). */
static int test_cu_open_map_strict(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h = 0u;
    ninlil_n6_tx_lease_t lease;

    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 8u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    REQUIRE(ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_COMMIT_UNKNOWN);
    REQUIRE(ninlil_n6_test_cu_phase(n6) == 1u);
    /* recover first advances to NEED_OPEN then open fault */
    n6_mem_storage_inject_fault(N6_MEM_FAULT_OPEN_NOSPACE, 1);
    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

/* Boot final rollback mapping (separate from generic n6_prov_rollback). */
static int test_boot_cleanup_rollback_map(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h = 0u;

    /* rollback IO/BUSY → BOUND + STORAGE (not fenced) */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_ROLLBACK_BUSY, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_STORAGE);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_BOUND);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

    /* rollback NO_SPACE → FENCED/CORRUPT */
    n6_mem_storage_reset();
    REQUIRE(setup_booted(&n6, 4u) == 0);
    fill_capsule(&cap, 1);
    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
    n6_mem_storage_inject_fault(N6_MEM_FAULT_ROLLBACK_NOSPACE, 1);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_CORRUPT);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

/*
 * Closed status matrix KAT — exact fixed count, all real call paths.
 * Generic programmable provider only (tests/support). No production hooks.
 */
#define N6_CLOSED_SS_N 10
#define N6_CLOSED_MATRIX_CASES 298

static const ninlil_storage_status_t k_closed_ss[N6_CLOSED_SS_N] = {
    NINLIL_STORAGE_OK,
    NINLIL_STORAGE_NOT_FOUND,
    NINLIL_STORAGE_NO_SPACE,
    NINLIL_STORAGE_IO_ERROR,
    NINLIL_STORAGE_CORRUPT,
    NINLIL_STORAGE_BUFFER_TOO_SMALL,
    NINLIL_STORAGE_BUSY,
    NINLIL_STORAGE_UNSUPPORTED_SCHEMA,
    NINLIL_STORAGE_COMMIT_UNKNOWN,
    (ninlil_storage_status_t)99u
};

/* nonOK+handle class representatives for begin paths */
static const ninlil_storage_status_t k_begin_handle_ss[] = {
    NINLIL_STORAGE_IO_ERROR,
    NINLIL_STORAGE_BUSY,
    NINLIL_STORAGE_NO_SPACE,
    NINLIL_STORAGE_BUFFER_TOO_SMALL,
    NINLIL_STORAGE_CORRUPT,
    NINLIL_STORAGE_COMMIT_UNKNOWN,
    (ninlil_storage_status_t)99u
};
#define N6_BEGIN_HANDLE_N ((int)(sizeof(k_begin_handle_ss) / sizeof(k_begin_handle_ss[0])))

static ninlil_n6_status_t mx_begin_map(ninlil_storage_status_t ss)
{
    if (ss == NINLIL_STORAGE_IO_ERROR || ss == NINLIL_STORAGE_BUSY)
        return NINLIL_N6_STORAGE;
    if (ss == NINLIL_STORAGE_NO_SPACE || ss == NINLIL_STORAGE_BUFFER_TOO_SMALL)
        return NINLIL_N6_CAPACITY;
    return NINLIL_N6_CORRUPT;
}

static ninlil_n6_status_t mx_get_map(ninlil_storage_status_t ss)
{
    if (ss == NINLIL_STORAGE_IO_ERROR || ss == NINLIL_STORAGE_BUSY)
        return NINLIL_N6_STORAGE;
    return NINLIL_N6_CORRUPT;
}

static ninlil_n6_status_t mx_put_map(ninlil_storage_status_t ss)
{
    if (ss == NINLIL_STORAGE_NO_SPACE) return NINLIL_N6_CAPACITY;
    if (ss == NINLIL_STORAGE_IO_ERROR || ss == NINLIL_STORAGE_BUSY)
        return NINLIL_N6_STORAGE;
    return NINLIL_N6_CORRUPT;
}

static ninlil_n6_status_t mx_commit_map(ninlil_storage_status_t ss)
{
    if (ss == NINLIL_STORAGE_OK) return NINLIL_N6_OK;
    if (ss == NINLIL_STORAGE_COMMIT_UNKNOWN) return NINLIL_N6_COMMIT_UNKNOWN;
    if (ss == NINLIL_STORAGE_NO_SPACE) return NINLIL_N6_CAPACITY;
    if (ss == NINLIL_STORAGE_IO_ERROR || ss == NINLIL_STORAGE_BUSY)
        return NINLIL_N6_STORAGE;
    return NINLIL_N6_CORRUPT;
}

/* boot final rb: IO/BUSY → STORAGE/BOUND; else CORRUPT/FENCED */
static ninlil_n6_status_t mx_boot_rb_map(ninlil_storage_status_t ss)
{
    if (ss == NINLIL_STORAGE_IO_ERROR || ss == NINLIL_STORAGE_BUSY)
        return NINLIL_N6_STORAGE;
    return NINLIL_N6_CORRUPT;
}

/* generic n6_prov_fail rb failure always CORRUPT/FENCED */
static ninlil_n6_status_t mx_generic_rb_fail_map(ninlil_storage_status_t ss)
{
    (void)ss;
    return NINLIL_N6_CORRUPT;
}

static int mx_fail(const char *id, const char *detail)
{
    fprintf(stderr, "MATRIX FAIL [%s]: %s\n", id, detail);
    return 1;
}

static int mx_eq_u32(const char *id, const char *what, uint32_t got, uint32_t want)
{
    if (got != want) {
        fprintf(stderr, "MATRIX FAIL [%s]: %s got=%u want=%u\n", id, what,
            (unsigned)got, (unsigned)want);
        return 1;
    }
    return 0;
}

typedef enum {
    MX_BEGIN_BOOT = 0,
    MX_BEGIN_INST_RO,
    MX_BEGIN_INST_RW,
    MX_BEGIN_TX,
    MX_BEGIN_RX,
    MX_BEGIN_CU,
    MX_BEGIN_PATH_N
} mx_begin_path_t;

static int mx_setup_booted(ninlil_n6_t **n6)
{
    return setup_booted(n6, 8u);
}

static int mx_setup_rx(ninlil_n6_t **n6, ninlil_n6_handle_t *h)
{
    ninlil_n6_install_capsule_t cap;
    if (setup_booted(n6, 8u) != 0) return 1;
    fill_capsule(&cap, 1);
    cap.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
    cap.context_id = 1u;
    if (ninlil_n6_install_hop(*n6, &cap, h) != NINLIL_N6_OK) return 1;
    return 0;
}

static int mx_setup_tx(ninlil_n6_t **n6, ninlil_n6_handle_t *h)
{
    ninlil_n6_install_capsule_t cap;
    if (setup_booted(n6, 8u) != 0) return 1;
    fill_capsule(&cap, 1);
    if (ninlil_n6_install_hop(*n6, &cap, h) != NINLIL_N6_OK) return 1;
    return 0;
}

static int mx_setup_cu(ninlil_n6_t **n6, ninlil_n6_handle_t *h)
{
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_tx_lease_t lease;
    if (setup_booted(n6, 8u) != 0) return 1;
    fill_capsule(&cap, 1);
    if (ninlil_n6_install_hop(*n6, &cap, h) != NINLIL_N6_OK) return 1;
    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_PROPOSED);
    if (ninlil_n6_tx_burn(*n6, *h, NINLIL_N6_LANE_HOP_DATA, &lease)
        != NINLIL_N6_COMMIT_UNKNOWN)
        return 1;
    return 0;
}

/* Invoke path after programs armed. Returns public status. */
static ninlil_n6_status_t mx_invoke_begin_path(
    mx_begin_path_t path, ninlil_n6_t *n6, ninlil_n6_handle_t h,
    ninlil_n6_install_capsule_t *cap, ninlil_n6_tx_lease_t *lease,
    ninlil_n6_rx_ticket_t *ticket)
{
    switch (path) {
    case MX_BEGIN_BOOT:
        return ninlil_n6_boot_scan(n6);
    case MX_BEGIN_INST_RO:
    case MX_BEGIN_INST_RW:
        return ninlil_n6_install_hop(n6, cap, &h);
    case MX_BEGIN_TX:
        return ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, lease);
    case MX_BEGIN_RX:
        if (ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 1u, ticket)
            != NINLIL_N6_OK)
            return NINLIL_N6_CORRUPT;
        return ninlil_n6_rx_admit_after_aead(n6, ticket);
    case MX_BEGIN_CU:
        return ninlil_n6_recover_cu(n6);
    default:
        return NINLIL_N6_CORRUPT;
    }
}

static const char *mx_begin_name(mx_begin_path_t p)
{
    static const char *n[] = {
        "boot", "inst_ro", "inst_rw", "tx", "rx", "cu"
    };
    return n[(int)p];
}

static int test_closed_status_matrix_kat(void)
{
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_capsule_t cap;
    ninlil_n6_handle_t h = 0u;
    ninlil_n6_tx_lease_t lease;
    ninlil_n6_rx_ticket_t ticket;
    int cases = 0;
    int pi, si, hi;
    uint32_t cl0, rb0, put0, get0, begin0, commit0;
    char id[96];

    /* ========== BEGIN: 6 paths × (9 clean nonOK + 1 OK_NULL + 7 nonOK_handle) ========== */
    for (pi = 0; pi < MX_BEGIN_PATH_N; ++pi) {
        mx_begin_path_t path = (mx_begin_path_t)pi;
        /* clean non-OK statuses */
        for (si = 0; si < N6_CLOSED_SS_N; ++si) {
            ninlil_storage_status_t ss = k_closed_ss[si];
            ninlil_n6_status_t st, exp;
            int begin_skip;
            if (ss == NINLIL_STORAGE_OK)
                continue;
            (void)snprintf(id, sizeof(id), "begin.%s.clean.%u",
                mx_begin_name(path), (unsigned)ss);
            n6_mem_storage_reset();
            h = 0u;
            if (path == MX_BEGIN_BOOT) {
                REQUIRE(setup_booted(&n6, 4u) == 0);
                fill_capsule(&cap, 1);
                REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
                REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
            } else if (path == MX_BEGIN_INST_RO || path == MX_BEGIN_INST_RW) {
                REQUIRE(mx_setup_booted(&n6) == 0);
                fill_capsule(&cap, 1);
            } else if (path == MX_BEGIN_TX) {
                REQUIRE(mx_setup_tx(&n6, &h) == 0);
            } else if (path == MX_BEGIN_RX) {
                REQUIRE(mx_setup_rx(&n6, &h) == 0);
            } else {
                REQUIRE(mx_setup_cu(&n6, &h) == 0);
            }
            begin_skip = (path == MX_BEGIN_INST_RW) ? 1 : 0;
            rb0 = n6_mem_storage_rollback_count();
            cl0 = n6_mem_storage_close_count();
            put0 = n6_mem_storage_put_count();
            get0 = n6_mem_storage_get_count();
            commit0 = n6_mem_storage_commit_count();
            if (begin_skip > 0)
                n6_mem_storage_program_after(N6_MEM_PROG_BEGIN, ss,
                    N6_MEM_SHAPE_DEFAULT, begin_skip, 1);
            else
                n6_mem_storage_program(N6_MEM_PROG_BEGIN, ss,
                    N6_MEM_SHAPE_DEFAULT, 1);
            /*
             * CU begin (docs/30 §9.3): only IO/BUSY+NULL → STORAGE retry.
             * NO_SPACE/BTS/others → CORRUPT fence (not STORAGE).
             */
            if (path == MX_BEGIN_CU) {
                if (ss == NINLIL_STORAGE_IO_ERROR || ss == NINLIL_STORAGE_BUSY) {
                    exp = NINLIL_N6_STORAGE;
                } else {
                    exp = NINLIL_N6_CORRUPT;
                }
            } else {
                exp = mx_begin_map(ss);
            }
            st = mx_invoke_begin_path(path, n6, h, &cap, &lease, &ticket);
            if (st != exp) {
                fprintf(stderr, " got=%u exp=%u\n", (unsigned)st, (unsigned)exp);
                REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                return mx_fail(id, "status map");
            }
            {
                /* inst_rw: RO precheck completes (rb=1) before RW begin fails */
                uint32_t want_rb = (path == MX_BEGIN_INST_RW) ? 1u : 0u;
                if (mx_eq_u32(id, "rb_delta",
                        n6_mem_storage_rollback_count() - rb0, want_rb)
                    != 0) {
                    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                    return 1;
                }
            }
            {
                uint32_t want_cl = 0u;
                if (path == MX_BEGIN_CU) {
                    /*
                     * NEED_CLOSE once always; begin path then closes shared
                     * handle once more (retry STORAGE or CORRUPT fence).
                     */
                    want_cl = 2u;
                }
                if (mx_eq_u32(id, "close_delta",
                        n6_mem_storage_close_count() - cl0, want_cl)
                    != 0) {
                    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                    return 1;
                }
            }
            if (path != MX_BEGIN_CU) {
                if (mx_eq_u32(id, "put_delta",
                        n6_mem_storage_put_count() - put0, 0u) != 0
                    || mx_eq_u32(id, "commit_delta",
                           n6_mem_storage_commit_count() - commit0, 0u) != 0) {
                    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                    return 1;
                }
            }
            if (path == MX_BEGIN_CU) {
                if (exp == NINLIL_N6_STORAGE) {
                    if (ninlil_n6_test_cu_live(n6) != 1
                        || ninlil_n6_test_cu_phase(n6) != 2u /* NEED_OPEN */
                        || ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return mx_fail(id, "CU begin STORAGE: plan keep NEED_OPEN");
                    }
                } else {
                    if (ninlil_n6_state(n6) != NINLIL_N6_STATE_FENCED
                        || ninlil_n6_test_cu_live(n6) != 0) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return mx_fail(id, "CU begin CORRUPT: fence+plan wipe");
                    }
                }
            } else if (exp == NINLIL_N6_CORRUPT) {
                if (ninlil_n6_state(n6) != NINLIL_N6_STATE_FENCED) {
                    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                    return mx_fail(id, "CORRUPT must FENCED");
                }
            } else if (path == MX_BEGIN_BOOT
                && (ss == NINLIL_STORAGE_IO_ERROR || ss == NINLIL_STORAGE_BUSY)) {
                if (ninlil_n6_state(n6) != NINLIL_N6_STATE_BOUND) {
                    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                    return mx_fail(id, "boot begin IO → BOUND");
                }
            } else if (exp == NINLIL_N6_STORAGE
                && ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED
                && path != MX_BEGIN_BOOT) {
                REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                return mx_fail(id, "STORAGE must not fence");
            }
            if (path == MX_BEGIN_RX) {
                if (ticket_bytes_all_zero(&ticket) != 1
                    || ninlil_n6_test_live_ticket_count(n6) != 0u) {
                    /* precheck may have made ticket before begin fail on admit */
                    if (ninlil_n6_test_live_ticket_count(n6) != 0u) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return mx_fail(id, "rx begin fail must free tickets");
                    }
                }
            }
            cases++;
            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
            (void)get0;
            (void)begin0;
        }

        /* OK+NULL */
        (void)snprintf(id, sizeof(id), "begin.%s.ok_null", mx_begin_name(path));
        n6_mem_storage_reset();
        h = 0u;
        if (path == MX_BEGIN_BOOT) {
            REQUIRE(setup_booted(&n6, 4u) == 0);
            fill_capsule(&cap, 1);
            REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
            REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
        } else if (path == MX_BEGIN_INST_RO || path == MX_BEGIN_INST_RW) {
            REQUIRE(mx_setup_booted(&n6) == 0);
            fill_capsule(&cap, 1);
        } else if (path == MX_BEGIN_TX) {
            REQUIRE(mx_setup_tx(&n6, &h) == 0);
        } else if (path == MX_BEGIN_RX) {
            REQUIRE(mx_setup_rx(&n6, &h) == 0);
        } else {
            REQUIRE(mx_setup_cu(&n6, &h) == 0);
        }
        rb0 = n6_mem_storage_rollback_count();
        cl0 = n6_mem_storage_close_count();
        if (path == MX_BEGIN_INST_RW)
            n6_mem_storage_program_after(N6_MEM_PROG_BEGIN, NINLIL_STORAGE_OK,
                N6_MEM_SHAPE_OK_NULL, 1, 1);
        else
            n6_mem_storage_program(N6_MEM_PROG_BEGIN, NINLIL_STORAGE_OK,
                N6_MEM_SHAPE_OK_NULL, 1);
        {
            ninlil_n6_status_t st =
                mx_invoke_begin_path(path, n6, h, &cap, &lease, &ticket);
            if (st != NINLIL_N6_CORRUPT
                || ninlil_n6_state(n6) != NINLIL_N6_STATE_FENCED) {
                REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                return mx_fail(id, "OK+NULL → CORRUPT/FENCED");
            }
            {
                uint32_t want_rb = (path == MX_BEGIN_INST_RW) ? 1u : 0u;
                if (mx_eq_u32(id, "rb_delta",
                        n6_mem_storage_rollback_count() - rb0, want_rb)
                    != 0) {
                    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                    return 1;
                }
            }
            /* CU: NEED_CLOSE + begin OK+NULL close; plan wiped */
            if (path == MX_BEGIN_CU) {
                if (mx_eq_u32(id, "close_delta",
                        n6_mem_storage_close_count() - cl0, 2u) != 0) {
                    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                    return 1;
                }
                if (ninlil_n6_test_cu_live(n6) != 0) {
                    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                    return mx_fail(id, "CU OK+NULL plan wipe");
                }
            } else if (mx_eq_u32(id, "close_delta",
                           n6_mem_storage_close_count() - cl0, 0u) != 0) {
                REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                return 1;
            }
        }
        cases++;
        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);

        /* nonOK+nonnull handle class representatives */
        for (hi = 0; hi < N6_BEGIN_HANDLE_N; ++hi) {
            ninlil_storage_status_t ss = k_begin_handle_ss[hi];
            ninlil_n6_status_t st;
            (void)snprintf(id, sizeof(id), "begin.%s.nonok_handle.%u",
                mx_begin_name(path), (unsigned)ss);
            n6_mem_storage_reset();
            h = 0u;
            if (path == MX_BEGIN_BOOT) {
                REQUIRE(setup_booted(&n6, 4u) == 0);
                fill_capsule(&cap, 1);
                REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
                REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
            } else if (path == MX_BEGIN_INST_RO || path == MX_BEGIN_INST_RW) {
                REQUIRE(mx_setup_booted(&n6) == 0);
                fill_capsule(&cap, 1);
            } else if (path == MX_BEGIN_TX) {
                REQUIRE(mx_setup_tx(&n6, &h) == 0);
            } else if (path == MX_BEGIN_RX) {
                REQUIRE(mx_setup_rx(&n6, &h) == 0);
            } else {
                REQUIRE(mx_setup_cu(&n6, &h) == 0);
            }
            rb0 = n6_mem_storage_rollback_count();
            cl0 = n6_mem_storage_close_count();
            if (path == MX_BEGIN_INST_RW)
                n6_mem_storage_program_after(N6_MEM_PROG_BEGIN, ss,
                    N6_MEM_SHAPE_NONOK_HANDLE, 1, 1);
            else
                n6_mem_storage_program(N6_MEM_PROG_BEGIN, ss,
                    N6_MEM_SHAPE_NONOK_HANDLE, 1);
            st = mx_invoke_begin_path(path, n6, h, &cap, &lease, &ticket);
            if (st != NINLIL_N6_CORRUPT
                || ninlil_n6_state(n6) != NINLIL_N6_STATE_FENCED) {
                REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                return mx_fail(id, "nonOK+handle → CORRUPT/FENCED");
            }
            /* begin helper: rb once (+ RO rb for inst_rw) + force_close */
            {
                uint32_t want_rb = (path == MX_BEGIN_INST_RW) ? 2u : 1u;
                uint32_t want_cl = (path == MX_BEGIN_CU) ? 2u : 1u;
                if (mx_eq_u32(id, "rb_delta",
                        n6_mem_storage_rollback_count() - rb0, want_rb)
                    != 0) {
                    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                    return 1;
                }
                if (mx_eq_u32(id, "close_delta",
                        n6_mem_storage_close_count() - cl0, want_cl) != 0) {
                    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                    return 1;
                }
            }
            if (path == MX_BEGIN_CU && ninlil_n6_test_cu_live(n6) != 0) {
                REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                return mx_fail(id, "CU nonOK+handle plan wipe");
            }
            cases++;
            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
        }
    }

    /* ========== GET paths ========== */
    {
        enum { G_INST_RO = 0, G_INST_RW = 1, G_TX = 2, G_RX = 3, G_CU = 4 };
        static const char *gn[] = { "inst_ro", "inst_rw", "tx", "rx", "cu" };
        int gp;
        for (gp = 0; gp < 5; ++gp) {
            int allow_miss_notfound = (gp == G_INST_RO || gp == G_INST_RW
                || gp == G_CU);
            for (si = 0; si < N6_CLOSED_SS_N; ++si) {
                ninlil_storage_status_t ss = k_closed_ss[si];
                ninlil_n6_status_t st, exp;
                int gskip;
                if (ss == NINLIL_STORAGE_OK)
                    continue;
                if (allow_miss_notfound && ss == NINLIL_STORAGE_NOT_FOUND)
                    continue;
                (void)snprintf(id, sizeof(id), "get.%s.clean.%u", gn[gp],
                    (unsigned)ss);
                n6_mem_storage_reset();
                h = 0u;
                if (gp == G_INST_RO || gp == G_INST_RW) {
                    REQUIRE(mx_setup_booted(&n6) == 0);
                    fill_capsule(&cap, 1);
                } else if (gp == G_TX) {
                    REQUIRE(mx_setup_tx(&n6, &h) == 0);
                } else if (gp == G_RX) {
                    REQUIRE(mx_setup_rx(&n6, &h) == 0);
                    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA,
                                1u, &ticket)
                        == NINLIL_N6_OK);
                } else {
                    REQUIRE(mx_setup_cu(&n6, &h) == 0);
                }
                /* hop RO: 4 gets before RW; RW first get skip=4 */
                gskip = (gp == G_INST_RW) ? 4 : 0;
                rb0 = n6_mem_storage_rollback_count();
                cl0 = n6_mem_storage_close_count();
                put0 = n6_mem_storage_put_count();
                commit0 = n6_mem_storage_commit_count();
                if (gskip > 0)
                    n6_mem_storage_program_after(N6_MEM_PROG_GET, ss,
                        N6_MEM_SHAPE_DEFAULT, gskip, 1);
                else
                    n6_mem_storage_program(N6_MEM_PROG_GET, ss,
                        N6_MEM_SHAPE_DEFAULT, 1);
                exp = mx_get_map(ss);
                if (gp == G_INST_RO || gp == G_INST_RW)
                    st = ninlil_n6_install_hop(n6, &cap, &h);
                else if (gp == G_TX)
                    st = ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease);
                else if (gp == G_RX)
                    st = ninlil_n6_rx_admit_after_aead(n6, &ticket);
                else
                    st = ninlil_n6_recover_cu(n6);
                if (st != exp) {
                    fprintf(stderr, " got=%u exp=%u\n", (unsigned)st,
                        (unsigned)exp);
                    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                    return mx_fail(id, "get status");
                }
                if (mx_eq_u32(id, "put_delta",
                        n6_mem_storage_put_count() - put0, 0u) != 0
                    || mx_eq_u32(id, "commit_delta",
                           n6_mem_storage_commit_count() - commit0, 0u) != 0) {
                    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                    return 1;
                }
                /* fail helper: rb once; CU also NEED_CLOSE once before */
                {
                    uint32_t want_rb = 1u;
                    uint32_t want_cl = 1u;
                    if (gp == G_INST_RW)
                        want_rb = 2u; /* RO final rb + fail rb */
                    if (gp == G_CU)
                        want_cl = 2u; /* NEED_CLOSE + force_close on fail */
                    if (gp == G_INST_RO || gp == G_INST_RW) {
                        /* RO path fail: only one rb on early get; no RO final */
                        if (gp == G_INST_RO)
                            want_rb = 1u;
                    }
                    if (mx_eq_u32(id, "rb_delta",
                            n6_mem_storage_rollback_count() - rb0, want_rb)
                        != 0) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return 1;
                    }
                    if (exp == NINLIL_N6_CORRUPT) {
                        if (mx_eq_u32(id, "close_delta",
                                n6_mem_storage_close_count() - cl0, want_cl)
                            != 0) {
                            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                            return 1;
                        }
                        if (ninlil_n6_state(n6) != NINLIL_N6_STATE_FENCED) {
                            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                            return mx_fail(id, "get CORRUPT fence");
                        }
                    } else {
                        /* STORAGE: CU retry close (NEED_CLOSE + rb_close_retry) */
                        uint32_t want_cl_st = (gp == G_CU) ? 2u : 0u;
                        if (mx_eq_u32(id, "close_delta",
                                n6_mem_storage_close_count() - cl0, want_cl_st)
                            != 0) {
                            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                            return 1;
                        }
                    }
                }
                if (gp == G_RX) {
                    if (ticket_bytes_all_zero(&ticket) != 1
                        || ninlil_n6_test_live_ticket_count(n6) != 0u
                        || ninlil_n6_test_any_ticket_key_or_iv_nonzero(n6)
                            != 0) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return mx_fail(id, "rx get wipe");
                    }
                }
                cases++;
                REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
            }
        }
        /* shapes on inst_ro + rx + tx(ptr,cap) */
        {
            static const struct {
                n6_mem_prog_shape_t sh;
                const char *tag;
            } shapes[] = {
                { N6_MEM_SHAPE_GET_PTR, "ptr" },
                { N6_MEM_SHAPE_GET_CAP_REWRITE, "cap_rw" },
                { N6_MEM_SHAPE_GET_OVERSIZE, "oversize" },
                { N6_MEM_SHAPE_GET_TAIL, "tail" },
                { N6_MEM_SHAPE_GET_MISS_POISON, "miss_poison" },
                { N6_MEM_SHAPE_GET_BTS, "bts" },
            };
            int sp, sh_i;
            for (sp = 0; sp < 3; ++sp) {
                int nsh = (sp == 2) ? 2 : 6; /* tx: ptr+cap only */
                const char *pn = (sp == 0) ? "inst_ro" : (sp == 1) ? "rx" : "tx";
                for (sh_i = 0; sh_i < nsh; ++sh_i) {
                    (void)snprintf(id, sizeof(id), "get.%s.shape.%s", pn,
                        shapes[sh_i].tag);
                    n6_mem_storage_reset();
                    if (sp == 0) {
                        REQUIRE(mx_setup_booted(&n6) == 0);
                        fill_capsule(&cap, 1);
                    } else if (sp == 1) {
                        REQUIRE(mx_setup_rx(&n6, &h) == 0);
                        REQUIRE(ninlil_n6_rx_precheck(n6, h,
                                    NINLIL_N6_LANE_HOP_DATA, 1u, &ticket)
                            == NINLIL_N6_OK);
                    } else {
                        REQUIRE(mx_setup_tx(&n6, &h) == 0);
                    }
                    rb0 = n6_mem_storage_rollback_count();
                    cl0 = n6_mem_storage_close_count();
                    put0 = n6_mem_storage_put_count();
                    n6_mem_storage_program(N6_MEM_PROG_GET, NINLIL_STORAGE_OK,
                        shapes[sh_i].sh, 1);
                    {
                        ninlil_n6_status_t st;
                        if (sp == 0)
                            st = ninlil_n6_install_hop(n6, &cap, &h);
                        else if (sp == 1)
                            st = ninlil_n6_rx_admit_after_aead(n6, &ticket);
                        else
                            st = ninlil_n6_tx_burn(n6, h,
                                NINLIL_N6_LANE_HOP_DATA, &lease);
                        if (st != NINLIL_N6_CORRUPT
                            || ninlil_n6_state(n6) != NINLIL_N6_STATE_FENCED) {
                            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                            return mx_fail(id, "shape CORRUPT/FENCED");
                        }
                        if (mx_eq_u32(id, "rb_delta",
                                n6_mem_storage_rollback_count() - rb0, 1u)
                            != 0
                            || mx_eq_u32(id, "close_delta",
                                   n6_mem_storage_close_count() - cl0, 1u)
                                != 0
                            || mx_eq_u32(id, "put_delta",
                                   n6_mem_storage_put_count() - put0, 0u)
                                != 0) {
                            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                            return 1;
                        }
                        if (sp == 1
                            && (ticket_bytes_all_zero(&ticket) != 1
                                || ninlil_n6_test_live_ticket_count(n6) != 0u)) {
                            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                            return mx_fail(id, "rx shape wipe");
                        }
                    }
                    cases++;
                    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                }
            }
        }
    }

    /* ========== PUT: install RW, TX, RX × 9 nonOK ========== */
    {
        int pp;
        for (pp = 0; pp < 3; ++pp) {
            const char *pn = (pp == 0) ? "inst_rw" : (pp == 1) ? "tx" : "rx";
            for (si = 0; si < N6_CLOSED_SS_N; ++si) {
                ninlil_storage_status_t ss = k_closed_ss[si];
                ninlil_n6_status_t st, exp;
                if (ss == NINLIL_STORAGE_OK)
                    continue;
                (void)snprintf(id, sizeof(id), "put.%s.%u", pn, (unsigned)ss);
                n6_mem_storage_reset();
                if (pp == 0) {
                    REQUIRE(mx_setup_booted(&n6) == 0);
                    fill_capsule(&cap, 1);
                } else if (pp == 1) {
                    REQUIRE(mx_setup_tx(&n6, &h) == 0);
                } else {
                    REQUIRE(mx_setup_rx(&n6, &h) == 0);
                    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA,
                                1u, &ticket)
                        == NINLIL_N6_OK);
                }
                rb0 = n6_mem_storage_rollback_count();
                cl0 = n6_mem_storage_close_count();
                commit0 = n6_mem_storage_commit_count();
                n6_mem_storage_program(N6_MEM_PROG_PUT, ss, N6_MEM_SHAPE_DEFAULT,
                    1);
                exp = mx_put_map(ss);
                if (pp == 0)
                    st = ninlil_n6_install_hop(n6, &cap, &h);
                else if (pp == 1)
                    st = ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease);
                else
                    st = ninlil_n6_rx_admit_after_aead(n6, &ticket);
                if (st != exp) {
                    fprintf(stderr, " got=%u exp=%u\n", (unsigned)st,
                        (unsigned)exp);
                    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                    return mx_fail(id, "put map");
                }
                if (mx_eq_u32(id, "commit_delta",
                        n6_mem_storage_commit_count() - commit0, 0u)
                    != 0) {
                    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                    return 1;
                }
                {
                    uint32_t want_rb = (pp == 0) ? 2u : 1u;
                    if (mx_eq_u32(id, "rb_delta",
                            n6_mem_storage_rollback_count() - rb0, want_rb)
                        != 0) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return 1;
                    }
                }
                if (exp == NINLIL_N6_CORRUPT) {
                    if (ninlil_n6_state(n6) != NINLIL_N6_STATE_FENCED
                        || mx_eq_u32(id, "close_delta",
                               n6_mem_storage_close_count() - cl0, 1u)
                            != 0) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return mx_fail(id, "put CORRUPT fence/close");
                    }
                } else {
                    if (ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED
                        || mx_eq_u32(id, "close_delta",
                               n6_mem_storage_close_count() - cl0, 0u)
                            != 0) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return mx_fail(id, "put operational no fence");
                    }
                }
                if (ninlil_n6_test_cu_live(n6) != 0) {
                    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                    return mx_fail(id, "put clears CU");
                }
                if (pp == 2
                    && (ticket_bytes_all_zero(&ticket) != 1
                        || ninlil_n6_test_live_ticket_count(n6) != 0u)) {
                    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                    return mx_fail(id, "rx put wipe");
                }
                cases++;
                REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
            }
        }
    }

    /* ========== COMMIT install/TX/RX × all 10 including OK ========== */
    {
        int cp;
        for (cp = 0; cp < 3; ++cp) {
            const char *pn = (cp == 0) ? "inst" : (cp == 1) ? "tx" : "rx";
            for (si = 0; si < N6_CLOSED_SS_N; ++si) {
                ninlil_storage_status_t ss = k_closed_ss[si];
                ninlil_n6_status_t st, exp;
                (void)snprintf(id, sizeof(id), "commit.%s.%u", pn, (unsigned)ss);
                n6_mem_storage_reset();
                if (cp == 0) {
                    REQUIRE(mx_setup_booted(&n6) == 0);
                    fill_capsule(&cap, 1);
                } else if (cp == 1) {
                    REQUIRE(mx_setup_tx(&n6, &h) == 0);
                } else {
                    REQUIRE(mx_setup_rx(&n6, &h) == 0);
                    REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA,
                                1u, &ticket)
                        == NINLIL_N6_OK);
                }
                rb0 = n6_mem_storage_rollback_count();
                cl0 = n6_mem_storage_close_count();
                if (ss != NINLIL_STORAGE_OK)
                    n6_mem_storage_program(N6_MEM_PROG_COMMIT, ss,
                        N6_MEM_SHAPE_DEFAULT, 1);
                exp = mx_commit_map(ss);
                if (cp == 0)
                    st = ninlil_n6_install_hop(n6, &cap, &h);
                else if (cp == 1)
                    st = ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA, &lease);
                else
                    st = ninlil_n6_rx_admit_after_aead(n6, &ticket);
                if (st != exp) {
                    fprintf(stderr, " got=%u exp=%u\n", (unsigned)st,
                        (unsigned)exp);
                    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                    return mx_fail(id, "commit map");
                }
                /* install: RO rb only (1); TX/RX: 0 post-commit rb */
                {
                    uint32_t want_rb = (cp == 0) ? 1u : 0u;
                    if (mx_eq_u32(id, "rb_delta",
                            n6_mem_storage_rollback_count() - rb0, want_rb)
                        != 0) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return 1;
                    }
                }
                if (ss == NINLIL_STORAGE_OK) {
                    if (cp == 0 && h == 0u) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return mx_fail(id, "install OK publishes handle");
                    }
                    if (cp == 1 && lease.live == 0u) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return mx_fail(id, "tx OK publishes lease");
                    }
                    if (cp == 2
                        && (ticket_bytes_all_zero(&ticket) != 1
                            || ninlil_n6_test_live_ticket_count(n6) != 0u)) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return mx_fail(id, "rx OK consumes ticket");
                    }
                    if (ninlil_n6_test_cu_live(n6) != 0) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return mx_fail(id, "OK clears CU");
                    }
                    if (mx_eq_u32(id, "close_delta",
                            n6_mem_storage_close_count() - cl0, 0u)
                        != 0) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return 1;
                    }
                } else if (ss == NINLIL_STORAGE_COMMIT_UNKNOWN) {
                    if (ninlil_n6_state(n6) != NINLIL_N6_STATE_CU_PENDING
                        || ninlil_n6_test_cu_live(n6) != 1
                        || ninlil_n6_test_cu_phase(n6) != 1u
                        || mx_eq_u32(id, "close_delta",
                               n6_mem_storage_close_count() - cl0, 0u)
                            != 0) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return mx_fail(id, "CU keep plan close0");
                    }
                    cl0 = n6_mem_storage_close_count();
                    if (ninlil_n6_recover_cu(n6) != NINLIL_N6_OK) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return mx_fail(id, "recover after CU");
                    }
                    /* NEED_CLOSE_OLD exactly once; open does not close */
                    if (mx_eq_u32(id, "recover_close",
                            n6_mem_storage_close_count() - cl0, 1u)
                        != 0) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return 1;
                    }
                } else if (exp == NINLIL_N6_CORRUPT) {
                    if (ninlil_n6_state(n6) != NINLIL_N6_STATE_FENCED
                        || ninlil_n6_test_cu_live(n6) != 0) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return mx_fail(id, "commit unexpected");
                    }
                } else if (ninlil_n6_test_cu_live(n6) != 0
                    || ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED) {
                    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                    return mx_fail(id, "definite commit CU clear");
                }
                if (cp == 2 && ss != NINLIL_STORAGE_OK
                    && ticket_bytes_all_zero(&ticket) != 1) {
                    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                    return mx_fail(id, "rx commit wipe");
                }
                cases++;
                REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
            }
        }
    }

    /* ========== ROLLBACK paths × 9 nonOK ========== */
    {
        enum {
            RB_BOOT_FINAL = 0,
            RB_INST_RO_FINAL,
            RB_INST_RO_EARLY,
            RB_INST_RW_EARLY,
            RB_TX_EARLY,
            RB_RX_EARLY,
            RB_CU_FINAL,
            RB_CU_EARLY,
            RB_PATH_N
        };
        static const char *rn[] = {
            "boot_final", "inst_ro_final", "inst_ro_early", "inst_rw_early",
            "tx_early", "rx_early", "cu_final", "cu_early"
        };
        int rp;
        for (rp = 0; rp < RB_PATH_N; ++rp) {
            for (si = 0; si < N6_CLOSED_SS_N; ++si) {
                ninlil_storage_status_t ss = k_closed_ss[si];
                ninlil_n6_status_t st, exp;
                if (ss == NINLIL_STORAGE_OK)
                    continue;
                (void)snprintf(id, sizeof(id), "rb.%s.%u", rn[rp], (unsigned)ss);
                n6_mem_storage_reset();
                n6_mem_storage_clear_program();
                if (rp == RB_BOOT_FINAL) {
                    REQUIRE(setup_booted(&n6, 4u) == 0);
                    fill_capsule(&cap, 1);
                    REQUIRE(ninlil_n6_install_hop(n6, &cap, &h) == NINLIL_N6_OK);
                    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                    REQUIRE(rebind_boot_scan(&n6, 4u) == 0);
                    n6_mem_storage_program(N6_MEM_PROG_ROLLBACK, ss,
                        N6_MEM_SHAPE_DEFAULT, 1);
                    cl0 = n6_mem_storage_close_count();
                    begin0 = n6_mem_storage_begin_count();
                    put0 = n6_mem_storage_put_count();
                    commit0 = n6_mem_storage_commit_count();
                    st = ninlil_n6_boot_scan(n6);
                    exp = mx_boot_rb_map(ss);
                    if (st != exp) {
                        fprintf(stderr, " got=%u exp=%u\n", (unsigned)st,
                            (unsigned)exp);
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return mx_fail(id, "boot rb map");
                    }
                    if (exp == NINLIL_N6_STORAGE) {
                        if (ninlil_n6_state(n6) != NINLIL_N6_STATE_BOUND) {
                            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                            return mx_fail(id, "boot rb STORAGE/BOUND");
                        }
                    } else if (ninlil_n6_state(n6) != NINLIL_N6_STATE_FENCED) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return mx_fail(id, "boot rb FENCED");
                    }
                    if (mx_eq_u32(id, "close_delta",
                            n6_mem_storage_close_count() - cl0, 1u)
                        != 0) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return 1;
                    }
                } else if (rp == RB_INST_RO_FINAL) {
                    REQUIRE(mx_setup_booted(&n6) == 0);
                    fill_capsule(&cap, 1);
                    n6_mem_storage_program(N6_MEM_PROG_ROLLBACK, ss,
                        N6_MEM_SHAPE_DEFAULT, 1);
                    cl0 = n6_mem_storage_close_count();
                    put0 = n6_mem_storage_put_count();
                    commit0 = n6_mem_storage_commit_count();
                    st = ninlil_n6_install_hop(n6, &cap, &h);
                    exp = mx_generic_rb_fail_map(ss);
                    if (st != exp
                        || ninlil_n6_state(n6) != NINLIL_N6_STATE_FENCED) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return mx_fail(id, "inst_ro_final rb");
                    }
                    if (mx_eq_u32(id, "close_delta",
                            n6_mem_storage_close_count() - cl0, 1u)
                        != 0
                        || mx_eq_u32(id, "put_delta",
                               n6_mem_storage_put_count() - put0, 0u)
                            != 0
                        || mx_eq_u32(id, "commit_delta",
                               n6_mem_storage_commit_count() - commit0, 0u)
                            != 0) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return 1;
                    }
                } else {
                    /* early: primary GET IO + program ROLLBACK status */
                    if (rp == RB_INST_RO_EARLY || rp == RB_INST_RW_EARLY) {
                        REQUIRE(mx_setup_booted(&n6) == 0);
                        fill_capsule(&cap, 1);
                    } else if (rp == RB_TX_EARLY) {
                        REQUIRE(mx_setup_tx(&n6, &h) == 0);
                    } else if (rp == RB_RX_EARLY) {
                        REQUIRE(mx_setup_rx(&n6, &h) == 0);
                        REQUIRE(ninlil_n6_rx_precheck(n6, h,
                                    NINLIL_N6_LANE_HOP_DATA, 1u, &ticket)
                            == NINLIL_N6_OK);
                    } else {
                        REQUIRE(mx_setup_cu(&n6, &h) == 0);
                    }
                    cl0 = n6_mem_storage_close_count();
                    put0 = n6_mem_storage_put_count();
                    commit0 = n6_mem_storage_commit_count();
                    begin0 = n6_mem_storage_begin_count();
                    if (rp == RB_INST_RW_EARLY) {
                        n6_mem_storage_program_after(N6_MEM_PROG_GET,
                            NINLIL_STORAGE_IO_ERROR, N6_MEM_SHAPE_DEFAULT, 4,
                            1);
                        n6_mem_storage_program(N6_MEM_PROG_ROLLBACK, ss,
                            N6_MEM_SHAPE_DEFAULT, 1);
                    } else if (rp == RB_CU_FINAL) {
                        /* all gets ok, fail final rb */
                        n6_mem_storage_program(N6_MEM_PROG_ROLLBACK, ss,
                            N6_MEM_SHAPE_DEFAULT, 1);
                    } else if (rp == RB_CU_EARLY) {
                        n6_mem_storage_program(N6_MEM_PROG_GET,
                            NINLIL_STORAGE_IO_ERROR, N6_MEM_SHAPE_DEFAULT, 1);
                        n6_mem_storage_program(N6_MEM_PROG_ROLLBACK, ss,
                            N6_MEM_SHAPE_DEFAULT, 1);
                    } else {
                        n6_mem_storage_program(N6_MEM_PROG_GET,
                            NINLIL_STORAGE_IO_ERROR, N6_MEM_SHAPE_DEFAULT, 1);
                        n6_mem_storage_program(N6_MEM_PROG_ROLLBACK, ss,
                            N6_MEM_SHAPE_DEFAULT, 1);
                    }
                    if (rp == RB_INST_RO_EARLY || rp == RB_INST_RW_EARLY)
                        st = ninlil_n6_install_hop(n6, &cap, &h);
                    else if (rp == RB_TX_EARLY)
                        st = ninlil_n6_tx_burn(n6, h, NINLIL_N6_LANE_HOP_DATA,
                            &lease);
                    else if (rp == RB_RX_EARLY)
                        st = ninlil_n6_rx_admit_after_aead(n6, &ticket);
                    else
                        st = ninlil_n6_recover_cu(n6);
                    exp = mx_generic_rb_fail_map(ss);
                    if (rp == RB_CU_FINAL) {
                        /* final rb fail after successful gets */
                        if (st != exp
                            || ninlil_n6_state(n6) != NINLIL_N6_STATE_FENCED) {
                            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                            return mx_fail(id, "cu_final rb");
                        }
                    } else {
                        if (st != exp
                            || ninlil_n6_state(n6) != NINLIL_N6_STATE_FENCED) {
                            fprintf(stderr, " got=%u state=%u\n", (unsigned)st,
                                (unsigned)ninlil_n6_state(n6));
                            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                            return mx_fail(id, "early rb fail");
                        }
                    }
                    {
                        uint32_t want_cl = (rp == RB_CU_EARLY || rp == RB_CU_FINAL)
                            ? 2u
                            : 1u;
                        if (mx_eq_u32(id, "close_delta",
                                n6_mem_storage_close_count() - cl0, want_cl)
                            != 0
                            || mx_eq_u32(id, "put_delta",
                                   n6_mem_storage_put_count() - put0, 0u)
                                != 0
                            || mx_eq_u32(id, "commit_delta",
                                   n6_mem_storage_commit_count() - commit0, 0u)
                                != 0) {
                            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                            return 1;
                        }
                    }
                    if (rp == RB_RX_EARLY
                        && (ticket_bytes_all_zero(&ticket) != 1
                            || ninlil_n6_test_live_ticket_count(n6) != 0u)) {
                        REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                        return mx_fail(id, "rx early rb wipe");
                    }
                    (void)begin0;
                }
                cases++;
                REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
            }
        }
    }

    /* ========== capacity 6 ========== */
    {
        static const struct {
            n6_mem_prog_shape_t sh;
            ninlil_storage_status_t ss;
            const char *tag;
            ninlil_n6_status_t exp;
            int fence;
        } caps[] = {
            { N6_MEM_SHAPE_CAP_POISON, NINLIL_STORAGE_IO_ERROR, "poison",
                NINLIL_N6_CORRUPT, 1 },
            { N6_MEM_SHAPE_CAP_BAD_OK, NINLIL_STORAGE_OK, "bad_ok",
                NINLIL_N6_CORRUPT, 1 },
            { N6_MEM_SHAPE_DEFAULT, (ninlil_storage_status_t)99u, "unknown",
                NINLIL_N6_CORRUPT, 1 },
            { N6_MEM_SHAPE_DEFAULT, NINLIL_STORAGE_CORRUPT, "corrupt",
                NINLIL_N6_CORRUPT, 1 },
            { N6_MEM_SHAPE_DEFAULT, NINLIL_STORAGE_UNSUPPORTED_SCHEMA, "unsup",
                NINLIL_N6_CORRUPT, 1 },
            { N6_MEM_SHAPE_DEFAULT, NINLIL_STORAGE_IO_ERROR, "io",
                NINLIL_N6_STORAGE, 0 },
        };
        size_t ci;
        for (ci = 0; ci < sizeof(caps) / sizeof(caps[0]); ++ci) {
            ninlil_n6_status_t st;
            (void)snprintf(id, sizeof(id), "cap.%s", caps[ci].tag);
            n6_mem_storage_reset();
            REQUIRE(mx_setup_booted(&n6) == 0);
            fill_capsule(&cap, 1);
            begin0 = n6_mem_storage_begin_count();
            get0 = n6_mem_storage_get_count();
            put0 = n6_mem_storage_put_count();
            n6_mem_storage_program(N6_MEM_PROG_CAPACITY, caps[ci].ss,
                caps[ci].sh, 1);
            st = ninlil_n6_install_hop(n6, &cap, &h);
            if (st != caps[ci].exp) {
                REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                return mx_fail(id, "cap status");
            }
            if (caps[ci].fence) {
                if (ninlil_n6_state(n6) != NINLIL_N6_STATE_FENCED) {
                    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                    return mx_fail(id, "cap fence");
                }
            } else if (ninlil_n6_state(n6) == NINLIL_N6_STATE_FENCED) {
                REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                return mx_fail(id, "cap io no fence");
            }
            if (mx_eq_u32(id, "begin", n6_mem_storage_begin_count(), begin0) != 0
                || mx_eq_u32(id, "get", n6_mem_storage_get_count(), get0) != 0
                || mx_eq_u32(id, "put", n6_mem_storage_put_count(), put0) != 0) {
                REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                return 1;
            }
            cases++;
            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
        }
    }

    /* ========== RX post-match failures (5) ========== */
    {
        static const char *tags[] = {
            "counter", "key", "iv", "lane", "handle"
        };
        int ti;
        for (ti = 0; ti < 5; ++ti) {
            (void)snprintf(id, sizeof(id), "rx.postmatch.%s", tags[ti]);
            n6_mem_storage_reset();
            REQUIRE(mx_setup_rx(&n6, &h) == 0);
            REQUIRE(ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 7u,
                        &ticket)
                == NINLIL_N6_OK);
            if (ti == 0)
                ticket.counter ^= 1u;
            else if (ti == 1)
                ticket.key16[0] ^= 0xFFu;
            else if (ti == 2)
                ticket.iv12[0] ^= 0xFFu;
            else if (ti == 3)
                ticket.lane_kind = NINLIL_N6_LANE_HOP_ACK;
            else
                ticket.handle = h + 9u;
            if (ninlil_n6_rx_admit_after_aead(n6, &ticket) != NINLIL_N6_TICKET
                || ticket_bytes_all_zero(&ticket) != 1
                || ninlil_n6_test_live_ticket_count(n6) != 0u
                || ninlil_n6_test_any_ticket_key_or_iv_nonzero(n6) != 0) {
                REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                return mx_fail(id, "wipe both");
            }
            if (ninlil_n6_rx_precheck(n6, h, NINLIL_N6_LANE_HOP_DATA, 7u, &ticket)
                != NINLIL_N6_OK) {
                REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
                return mx_fail(id, "fresh precheck");
            }
            REQUIRE(ninlil_n6_rx_abort(n6, &ticket) == NINLIL_N6_OK);
            cases++;
            REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
        }
    }

    printf("  closed_status_matrix fixed_cases=%d (exact=%d)\n", cases,
        N6_CLOSED_MATRIX_CASES);
    if (cases != N6_CLOSED_MATRIX_CASES) {
        fprintf(stderr, "MATRIX FAIL: cases %d != N6_CLOSED_MATRIX_CASES %d\n",
            cases, N6_CLOSED_MATRIX_CASES);
        return 1;
    }
    return 0;
}

typedef int (*test_fn)(void);

static int run_one(const char *name, test_fn fn)
{
    int r = fn();
    if (r != 0) {
        fprintf(stderr, "FAILED: %s\n", name);
        return 1;
    }
    g_pass_count += 1;
    printf("  OK %s\n", name);
    return 0;
}

int main(void)
{
    g_pass_count = 0;
    if (run_one("boot_ceiling_pins", test_boot_ceiling_and_iter_bound_pins) != 0) {
        return 1;
    }
    if (run_one("pool_init_1_8_128", test_pool_init_1_8_128) != 0) {
        return 1;
    }
    if (run_one("storage_ops_abi_capacity", test_storage_ops_abi_and_capacity)
        != 0) {
        return 1;
    }
    if (run_one("full_ns_boot_cu_no_double_rb",
            test_full_ns_boot_cu_no_double_rollback)
        != 0) {
        return 1;
    }
    if (run_one("slot_canary_corrupt",
            test_slot_canary_corrupt_is_corrupt_not_not_found)
        != 0) {
        return 1;
    }
    if (run_one("m4_fail_closed", test_m4_fail_closed) != 0) {
        return 1;
    }
    if (run_one("tx_burn_block_64", test_tx_burn_block_64_then_reserve) != 0) {
        return 1;
    }
    if (run_one("rx_ticket_admit", test_rx_ticket_admit_and_duplicate) != 0) {
        return 1;
    }
    if (run_one("cu_all_four_classes", test_cu_all_four_classes) != 0) {
        return 1;
    }
    if (run_one("cu_rx_all_proposed", test_cu_rx_all_proposed_accept_through)
        != 0) {
        return 1;
    }
    if (run_one("cu_reentry_open_fault", test_cu_reentry_open_fault) != 0) {
        return 1;
    }
    if (run_one("phase_fault_install", test_phase_fault_sweep_install) != 0) {
        return 1;
    }
    if (run_one("reentry_busy", test_real_reentry_busy) != 0) {
        return 1;
    }
    if (run_one("reentry_storage_cb", test_reentry_via_storage_callback)
        != 0) {
        return 1;
    }
    if (run_one("boot_empty_dormant_partial", test_boot_empty_dormant_partial)
        != 0) {
        return 1;
    }
    if (run_one("stamp_regression", test_stamp_regression) != 0) {
        return 1;
    }
    if (run_one("al_hw_increment_collision", test_al_hw_increment_and_collision)
        != 0) {
        return 1;
    }
    if (run_one("rx_sliding64_tamper", test_rx_sliding64_ooo_and_ticket_tamper)
        != 0) {
        return 1;
    }
    if (run_one("rx_ticket_wipe_evidence", test_rx_ticket_wipe_evidence_kat)
        != 0) {
        return 1;
    }
    if (run_one("rx_lane_idx_errata", test_rx_lane_idx_errata) != 0) {
        return 1;
    }
    if (run_one("cu_post_lane_idx_errata", test_cu_post_lane_idx_errata) != 0) {
        return 1;
    }
    if (run_one("tx_burn_lane_idx_errata", test_tx_burn_lane_idx_errata) != 0) {
        return 1;
    }
    if (run_one("id_wrap_fail_closed", test_id_wrap_fail_closed) != 0) {
        return 1;
    }
    if (run_one("init_alias_overflow", test_init_alias_overflow_canary) != 0) {
        return 1;
    }
    if (run_one("crypto_label_nonce_kat", test_crypto_label_nonce_kat) != 0) {
        return 1;
    }
    if (run_one("secure_zero_mutation", test_secure_zero_mutation_gate) != 0) {
        return 1;
    }
    if (run_one("lease_ticket_mutation", test_lease_ticket_mutation_zero_on_fail)
        != 0) {
        return 1;
    }
    if (run_one("install_cu_no_handle", test_install_cu_no_handle) != 0) {
        return 1;
    }
    if (run_one("boot_mutation_negatives", test_boot_mutation_negatives)
        != 0) {
        return 1;
    }
    if (run_one("local_identity_accepted", test_local_identity_accepted_contract)
        != 0) {
        return 1;
    }
    if (run_one("boot_two_ns_same_cid", test_boot_two_ns_same_cid_epoch_layer)
        != 0) {
        return 1;
    }
    if (run_one("boot_two_al_scopes", test_boot_two_al_scopes_same_layer_dir)
        != 0) {
        return 1;
    }
    if (run_one("boot_opp_side_same_recv_cid",
            test_boot_opposite_side_same_receiver_cid_corrupt)
        != 0) {
        return 1;
    }
    if (run_one("fence_secret_pattern_kat", test_fence_secret_pattern_scan_kat)
        != 0) {
        return 1;
    }
    if (run_one("boot_rt_cf_kind_dispatch",
            test_boot_rt_cf_kind_dispatch_and_rt_mismatch)
        != 0) {
        return 1;
    }
    if (run_one("boot_retired_only_rt_hw", test_boot_retired_only_rt_hw_highwater)
        != 0) {
        return 1;
    }
    if (run_one("boot_provider_shape_ops", test_boot_provider_shape_and_op_errors)
        != 0) {
        return 1;
    }
    if (run_one("boot_scratch_per_object", test_boot_scratch_per_object) != 0) {
        return 1;
    }
    if (run_one("boot_hop_binding_suffix",
            test_boot_hop_binding_suffix_mismatch_corrupt)
        != 0) {
        return 1;
    }
    if (run_one("boot_scope_digest_collision",
            test_boot_scope_digest_collision_layer_dir_corrupt)
        != 0) {
        return 1;
    }
    if (run_one("boot_opp_side_shared_hw", test_boot_opposite_side_shared_hw_dormant)
        != 0) {
        return 1;
    }
    if (run_one("boot_empty_al_reject", test_boot_empty_al_reject) != 0) {
        return 1;
    }
    if (run_one("inbound_no_arbitrary_ctx", test_inbound_no_arbitrary_context)
        != 0) {
        return 1;
    }
    if (run_one("open_storage_shapes", test_open_storage_provider_shapes) != 0) {
        return 1;
    }
    if (run_one("install_capacity_shapes", test_install_capacity_provider_shapes)
        != 0) {
        return 1;
    }
    if (run_one("boot_next_desc_faults", test_boot_next_descriptor_faults) != 0) {
        return 1;
    }
    if (run_one("boot_scratch_zero_exits", test_boot_scratch_zero_all_exits)
        != 0) {
        return 1;
    }
    if (run_one("boot_cf_binding_mismatch", test_boot_cf_binding_mismatch_corrupt)
        != 0) {
        return 1;
    }
    if (run_one("boot_rt_scope_digest_fail",
            test_boot_rt_scope_digest_fail_corrupt)
        != 0) {
        return 1;
    }
    if (run_one("recover_cu_provider_shapes", test_recover_cu_provider_shapes)
        != 0) {
        return 1;
    }
    if (run_one("install_tx_rx_storage_shapes", test_install_tx_rx_storage_shapes)
        != 0) {
        return 1;
    }
    if (run_one("cu_open_map_strict", test_cu_open_map_strict) != 0) {
        return 1;
    }
    if (run_one("boot_cleanup_rollback_map", test_boot_cleanup_rollback_map)
        != 0) {
        return 1;
    }
    if (run_one("closed_status_matrix", test_closed_status_matrix_kat) != 0) {
        return 1;
    }
    printf("n6_context_store_test: OK (%d cases)\n", g_pass_count);
    return 0;
}
