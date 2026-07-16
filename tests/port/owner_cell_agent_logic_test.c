/*
 * Host pure tests: lease single-use registry, pointer non-overlap, authority.
 */

#include "abi_header_stage_logic.h"
#include "cell_config_stage_logic.h"
#include "loopback_tx_permit_logic.h"
#include "owner_authority_logic.h"
#include "owner_config_stage_logic.h"
#include "owner_lifecycle_logic.h"
#include "owner_mailbox_logic.h"
#include "pointer_range_logic.h"
#include "tx_gate_lease_logic.h"

#include "ninlil_esp_idf/cell_agent.h"
#include "ninlil_esp_idf/detail/tx_gate_lease_registry.h"
#include "ninlil_esp_idf/loopback_tx_permit.h"
#include "ninlil_esp_idf/owner_task.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(c)                                                             \
    do {                                                                       \
        if (!(c)) {                                                            \
            (void)fprintf(stderr, "%s:%d fail %s\n", __FILE__, __LINE__, #c); \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static ninlil_tx_gate_status_t dummy_acq(
    void *u,
    const ninlil_tx_request_t *r,
    const ninlil_time_sample_t *n,
    ninlil_tx_permit_t *o)
{
    (void)u;
    (void)r;
    (void)n;
    (void)o;
    return NINLIL_TX_GATE_DENIED;
}

static void dummy_rel(void *u, const ninlil_tx_permit_t *p)
{
    (void)u;
    (void)p;
}

static void fill_ops(ninlil_tx_gate_ops_t *ops, void *user)
{
    (void)memset(ops, 0, sizeof(*ops));
    ops->abi_version = NINLIL_ABI_VERSION;
    ops->struct_size = (uint16_t)sizeof(*ops);
    ops->user = user;
    ops->acquire = dummy_acq;
    ops->release_unused = dummy_rel;
}

static int test_lease_two_borrowers_and_forgeries(void)
{
    ninlil_esp_idf_tx_gate_lease_registry_t reg;
    ninlil_tx_gate_ops_t ops_a;
    ninlil_tx_gate_ops_t ops_b;
    ninlil_esp_idf_tx_gate_lease_t la;
    ninlil_esp_idf_tx_gate_lease_t lb;
    ninlil_esp_idf_tx_gate_lease_t forged;
    uint32_t occ_before;

    fill_ops(&ops_a, &ops_a);
    fill_ops(&ops_b, &ops_b);

    ninlil_esp_idf_tx_gate_lease_registry_clear(&reg);
    REQUIRE(ninlil_esp_idf_tx_gate_lease_registry_set_ops(&reg, &ops_a) == 0);
    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_acquire(&reg, &la)
        == NINLIL_ESP_IDF_OWNER_OK);
    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_acquire(&reg, &lb)
        == NINLIL_ESP_IDF_OWNER_OK);
    REQUIRE(reg.occupied_count == 2u);

    /* set / shutdown-idle gate blocked while B held (BUSY contract) */
    REQUIRE(ninlil_esp_idf_tx_gate_lease_registry_set_ops(&reg, &ops_b) != 0);

    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_release(&reg, &la)
        == NINLIL_ESP_IDF_OWNER_OK);
    REQUIRE(reg.occupied_count == 1u);

    occ_before = reg.occupied_count;
    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_release(&reg, &la)
        == NINLIL_ESP_IDF_OWNER_LEASE_STALE);
    REQUIRE(reg.occupied_count == occ_before);

    forged = lb;
    forged.token ^= 0xdeadu;
    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_release(&reg, &forged)
        == NINLIL_ESP_IDF_OWNER_LEASE_STALE);
    REQUIRE(reg.occupied_count == 1u);

    forged = lb;
    forged.epoch ^= 1u;
    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_release(&reg, &forged)
        == NINLIL_ESP_IDF_OWNER_LEASE_STALE);

    forged = lb;
    forged.ops = &ops_b;
    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_release(&reg, &forged)
        == NINLIL_ESP_IDF_OWNER_LEASE_STALE);
    REQUIRE(reg.occupied_count == 1u);

    REQUIRE(ninlil_esp_idf_tx_gate_lease_registry_set_ops(&reg, &ops_b) != 0);

    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_release(&reg, &lb)
        == NINLIL_ESP_IDF_OWNER_OK);
    REQUIRE(reg.occupied_count == 0u);
    REQUIRE(ninlil_esp_idf_tx_gate_lease_registry_set_ops(&reg, &ops_b) == 0);
    return 0;
}

static int test_lease_full_and_token_exhaust_issue(void)
{
    ninlil_esp_idf_tx_gate_lease_registry_t reg;
    ninlil_tx_gate_ops_t ops;
    ninlil_esp_idf_tx_gate_lease_t leases[NINLIL_ESP_IDF_OWNER_MAX_TX_GATE_LEASES];
    ninlil_esp_idf_tx_gate_lease_t extra;
    ninlil_esp_idf_tx_gate_lease_t last;
    uint32_t i;

    fill_ops(&ops, &ops);

    ninlil_esp_idf_tx_gate_lease_registry_clear(&reg);
    REQUIRE(ninlil_esp_idf_tx_gate_lease_registry_set_ops(&reg, &ops) == 0);
    for (i = 0u; i < NINLIL_ESP_IDF_OWNER_MAX_TX_GATE_LEASES; ++i) {
        REQUIRE(
            ninlil_esp_idf_tx_gate_lease_registry_acquire(&reg, &leases[i])
            == NINLIL_ESP_IDF_OWNER_OK);
    }
    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_acquire(&reg, &extra)
        == NINLIL_ESP_IDF_OWNER_LEASE_FULL);

    for (i = 0u; i < NINLIL_ESP_IDF_OWNER_MAX_TX_GATE_LEASES; ++i) {
        REQUIRE(
            ninlil_esp_idf_tx_gate_lease_registry_release(&reg, &leases[i])
            == NINLIL_ESP_IDF_OWNER_OK);
    }

    /* Actually issue token UINT32_MAX-1 then next acquire exhausts. */
    reg.next_token = UINT32_MAX - 1u;
    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_acquire(&reg, &last)
        == NINLIL_ESP_IDF_OWNER_OK);
    REQUIRE(last.token == (UINT32_MAX - 1u));
    REQUIRE(reg.next_token == UINT32_MAX);
    REQUIRE(reg.occupied_count == 1u);
    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_acquire(&reg, &extra)
        == NINLIL_ESP_IDF_OWNER_TOKEN_EXHAUSTED);
    REQUIRE(reg.occupied_count == 1u);

    /* shutdown BUSY contract: idle set blocked while borrowers>0 */
    REQUIRE(ninlil_esp_idf_tx_gate_lease_registry_set_ops(&reg, &ops) != 0);
    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_release(&reg, &last)
        == NINLIL_ESP_IDF_OWNER_OK);
    REQUIRE(reg.occupied_count == 0u);

    /* epoch no-wrap */
    reg.epoch = UINT32_MAX;
    REQUIRE(ninlil_esp_idf_tx_gate_lease_registry_set_ops(&reg, &ops) != 0);
    return 0;
}

static int test_registry_alias_null_head_tail_partial(void)
{
    ninlil_esp_idf_tx_gate_lease_registry_t reg;
    ninlil_tx_gate_ops_t ops;
    ninlil_esp_idf_tx_gate_lease_t ok_lease;
    ninlil_esp_idf_tx_gate_lease_t *alias_head;
    ninlil_esp_idf_tx_gate_lease_t *alias_interior;
    ninlil_esp_idf_tx_gate_lease_t *alias_tail;
    uint32_t next_before;
    uint32_t occ_before;
    uint32_t epoch_before;
    uint8_t *base;

    fill_ops(&ops, &ops);
    ninlil_esp_idf_tx_gate_lease_registry_clear(&reg);
    REQUIRE(ninlil_esp_idf_tx_gate_lease_registry_set_ops(&reg, &ops) == 0);
    epoch_before = reg.epoch;
    next_before = reg.next_token;
    occ_before = reg.occupied_count;

    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_acquire(&reg, NULL)
        == NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT);
    REQUIRE(reg.occupied_count == occ_before);
    REQUIRE(reg.next_token == next_before);

    /* Registry head full overlap. */
    alias_head = (ninlil_esp_idf_tx_gate_lease_t *)(void *)&reg;
    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_acquire(&reg, alias_head)
        == NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT);

    /* Interior partial (offset into slots). */
    base = (uint8_t *)(void *)&reg;
    alias_interior =
        (ninlil_esp_idf_tx_gate_lease_t *)(void *)(base + sizeof(uint32_t));
    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_acquire(&reg, alias_interior)
        == NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT);

    /* Tail partial: last bytes of registry overlap lease object start. */
    alias_tail = (ninlil_esp_idf_tx_gate_lease_t *)(void *)(
        base + sizeof(reg) - (sizeof(ninlil_esp_idf_tx_gate_lease_t) / 2u));
    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_acquire(&reg, alias_tail)
        == NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT);

    REQUIRE(reg.occupied_count == 0u);
    REQUIRE(reg.next_token == next_before);
    REQUIRE(reg.epoch == epoch_before);
    REQUIRE(reg.slots[0].occupied == 0u);

    /* Separate object OK. */
    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_acquire(&reg, &ok_lease)
        == NINLIL_ESP_IDF_OWNER_OK);
    REQUIRE(reg.occupied_count == 1u);

    /* Release alias of registry → INVALID, count/token unchanged. */
    occ_before = reg.occupied_count;
    next_before = reg.next_token;
    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_release(&reg, alias_head)
        == NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT);
    REQUIRE(reg.occupied_count == occ_before);
    REQUIRE(reg.next_token == next_before);

    /* ops alias of registry → set fails, state unchanged */
    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_release(&reg, &ok_lease)
        == NINLIL_ESP_IDF_OWNER_OK);
    REQUIRE(reg.occupied_count == 0u);
    {
        ninlil_tx_gate_ops_t *ops_alias =
            (ninlil_tx_gate_ops_t *)(void *)&reg.slots[0];
        epoch_before = reg.epoch;
        REQUIRE(
            ninlil_esp_idf_tx_gate_lease_registry_set_ops(&reg, ops_alias)
            != 0);
        REQUIRE(reg.epoch == epoch_before);
        REQUIRE(reg.current_ops == &ops);
    }
    return 0;
}

static int test_pointer_range_owner_blob_regions(void)
{
    /*
     * Synthetic owner storage blob: mux / lifecycle / stack / queue regions.
     * Mirrors backend non-overlap of public args vs full owner storage.
     */
    uint8_t owner_blob[8192];
    ninlil_esp_idf_tx_gate_lease_t lease;
    ninlil_esp_idf_owner_snapshot_t snap;
    ninlil_tx_gate_ops_t ops;
    ninlil_esp_idf_cell_assignment_t asg;
    uint8_t *mux_region = owner_blob + 0u;
    uint8_t *lifecycle_region = owner_blob + 64u;
    uint8_t *stack_region = owner_blob + 512u;
    uint8_t *queue_region = owner_blob + 4608u;
    uint8_t separate[256];

    (void)memset(owner_blob, 0, sizeof(owner_blob));
    (void)memset(&lease, 0, sizeof(lease));
    (void)memset(&snap, 0, sizeof(snap));
    fill_ops(&ops, &ops);
    (void)memset(&asg, 0, sizeof(asg));

    /* Normal separate objects do not alias. */
    REQUIRE(!ninlil_esp_idf_pointer_ranges_overlap(
        owner_blob, sizeof(owner_blob), &lease, sizeof(lease)));
    REQUIRE(!ninlil_esp_idf_pointer_ranges_overlap(
        owner_blob, sizeof(owner_blob), &snap, sizeof(snap)));
    REQUIRE(!ninlil_esp_idf_pointer_ranges_overlap(
        owner_blob, sizeof(owner_blob), &ops, sizeof(ops)));
    REQUIRE(!ninlil_esp_idf_pointer_ranges_overlap(
        owner_blob, sizeof(owner_blob), separate, sizeof(separate)));

    /* Mux / lifecycle / stack / queue interior aliases reject. */
    REQUIRE(ninlil_esp_idf_pointer_ranges_overlap(
        owner_blob,
        sizeof(owner_blob),
        mux_region,
        sizeof(ninlil_esp_idf_tx_gate_lease_t)));
    REQUIRE(ninlil_esp_idf_pointer_ranges_overlap(
        owner_blob,
        sizeof(owner_blob),
        lifecycle_region,
        sizeof(ninlil_esp_idf_owner_snapshot_t)));
    REQUIRE(ninlil_esp_idf_pointer_ranges_overlap(
        owner_blob, sizeof(owner_blob), stack_region, sizeof(ops)));
    REQUIRE(ninlil_esp_idf_pointer_ranges_overlap(
        owner_blob, sizeof(owner_blob), queue_region, sizeof(asg)));

    /* Snapshot / lease / ops placed inside blob → alias. */
    REQUIRE(ninlil_esp_idf_pointer_ranges_overlap(
        owner_blob,
        sizeof(owner_blob),
        owner_blob + 100u,
        sizeof(snap)));
    REQUIRE(ninlil_esp_idf_pointer_ranges_overlap(
        owner_blob,
        sizeof(owner_blob),
        owner_blob + 200u,
        sizeof(lease)));

    /* Representable edge: size 0 never overlaps. */
    REQUIRE(!ninlil_esp_idf_pointer_ranges_overlap(
        owner_blob, sizeof(owner_blob), &lease, 0u));
    REQUIRE(ninlil_esp_idf_pointer_range_representable(NULL, 0u));
    REQUIRE(!ninlil_esp_idf_pointer_range_representable(NULL, 1u));

    /* Adjacent non-overlap (end == start). */
    {
        uint8_t pair[32];
        REQUIRE(!ninlil_esp_idf_pointer_ranges_overlap(
            pair, 16u, pair + 16u, 16u));
        REQUIRE(ninlil_esp_idf_pointer_ranges_overlap(
            pair, 17u, pair + 16u, 16u));
    }
    return 0;
}

static int test_snapshot_borrower_count_direct(void)
{
    /* Direct borrower count == occupied_count (snapshot field source). */
    ninlil_esp_idf_tx_gate_lease_registry_t reg;
    ninlil_tx_gate_ops_t ops;
    ninlil_esp_idf_tx_gate_lease_t a;
    ninlil_esp_idf_tx_gate_lease_t b;
    uint32_t snapshot_borrowers;

    fill_ops(&ops, &ops);
    ninlil_esp_idf_tx_gate_lease_registry_clear(&reg);
    REQUIRE(ninlil_esp_idf_tx_gate_lease_registry_set_ops(&reg, &ops) == 0);
    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_acquire(&reg, &a)
        == NINLIL_ESP_IDF_OWNER_OK);
    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_acquire(&reg, &b)
        == NINLIL_ESP_IDF_OWNER_OK);
    snapshot_borrowers = reg.occupied_count;
    REQUIRE(snapshot_borrowers == 2u);
    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_release(&reg, &a)
        == NINLIL_ESP_IDF_OWNER_OK);
    snapshot_borrowers = reg.occupied_count;
    REQUIRE(snapshot_borrowers == 1u);
    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_release(&reg, &b)
        == NINLIL_ESP_IDF_OWNER_OK);
    snapshot_borrowers = reg.occupied_count;
    REQUIRE(snapshot_borrowers == 0u);
    return 0;
}

static int test_authority_and_mailbox(void)
{
    ninlil_esp_idf_owner_authority_t a;
    ninlil_esp_idf_owner_pure_mailbox_t mb;
    ninlil_esp_idf_owner_msg_t m;
    uint32_t tok;
    uint32_t i;

    ninlil_esp_idf_owner_authority_init(&a);
    a.handle_live = 1u;
    a.accepting = 1u;
    a.published_lifecycle = NINLIL_ESP_IDF_OWNER_LC_RUNNING;
    REQUIRE(ninlil_esp_idf_owner_authority_try_claim(&a, &tok));
    ninlil_esp_idf_owner_authority_release_claim(&a, tok);
    REQUIRE(ninlil_esp_idf_owner_authority_admit_post(&a));
    ninlil_esp_idf_owner_authority_complete_post(&a);

    ninlil_esp_idf_owner_pure_mailbox_clear(&mb);
    (void)memset(&m, 0, sizeof(m));
    m.kind = NINLIL_ESP_IDF_OWNER_MSG_TICK;
    for (i = 0; i < NINLIL_ESP_IDF_OWNER_MAILBOX_DEPTH; ++i) {
        REQUIRE(
            ninlil_esp_idf_owner_pure_mailbox_push(&mb, &m)
            == NINLIL_ESP_IDF_OWNER_OK);
    }
    REQUIRE(
        ninlil_esp_idf_owner_pure_mailbox_push(&mb, &m)
        == NINLIL_ESP_IDF_OWNER_MAILBOX_FULL);
    REQUIRE(sizeof(ninlil_esp_idf_owner_core_t)
        < sizeof(ninlil_esp_idf_owner_msg_t)
            * NINLIL_ESP_IDF_OWNER_MAILBOX_DEPTH);
    return 0;
}

/* Known prefix size; declared = known + tail; only tail overlaps target. */
enum {
    NINLIL_TEST_OPS_KNOWN = 32, /* sizeof(ninlil_tx_gate_ops_t) on this ABI */
    NINLIL_TEST_OPS_TAIL = 16,
    NINLIL_TEST_OPS_DECLARED = NINLIL_TEST_OPS_KNOWN + NINLIL_TEST_OPS_TAIL,
    NINLIL_TEST_PERMIT_KNOWN = 64, /* sizeof(ninlil_tx_permit_t) */
    NINLIL_TEST_PERMIT_TAIL = 16,
    NINLIL_TEST_PERMIT_DECLARED =
        NINLIL_TEST_PERMIT_KNOWN + NINLIL_TEST_PERMIT_TAIL
};

typedef struct {
    ninlil_tx_gate_ops_t known;
    uint8_t tail[NINLIL_TEST_OPS_TAIL];
} extended_ops_t;

typedef struct {
    ninlil_tx_permit_t known;
    uint8_t tail[NINLIL_TEST_PERMIT_TAIL];
} extended_permit_t;

typedef struct {
    ninlil_esp_idf_cell_agent_config_t known;
    uint8_t tail_poison[64];
} extended_cell_cfg_t;

typedef struct {
    ninlil_esp_idf_owner_task_config_t known;
    uint8_t tail[24];
} extended_owner_cfg_t;

/*
 * Geometry (byte formula, static + runtime):
 *   ops_start
 *   [ known = K bytes fully outside target ]
 *   target_start == ops_start + K
 *   [ declared = K+T overlaps target head by T only ]
 */
static int assert_tail_only_ops_geometry(
    const void *ops,
    size_t known,
    size_t declared,
    const void *target,
    size_t target_size)
{
    const uint8_t *o = (const uint8_t *)ops;
    const uint8_t *t = (const uint8_t *)target;

    REQUIRE(known > 0u);
    REQUIRE(declared > known);
    REQUIRE(target_size > 0u);
    REQUIRE(t == o + known); /* target starts exactly where known ends */
    REQUIRE(!ninlil_esp_idf_pointer_ranges_overlap(ops, known, target, target_size));
    REQUIRE(ninlil_esp_idf_pointer_ranges_overlap(
        ops, declared, target, target_size));
    /* Exact tail length into target start; independent of bounds check. */
    REQUIRE((size_t)((o + declared) - t) == (declared - known));
    REQUIRE((declared - known) <= target_size);
    return 0;
}

static int test_abi_stage_tail_only_and_overflow(void)
{
    /*
     * Layout (not nested full extended object before reg):
     *   [known ops K][reg R...]
     * declared size = K+T so only T bytes of declared range enter reg.
     */
    typedef struct ninlil_test_ops_reg_pack {
        ninlil_tx_gate_ops_t known;
        ninlil_esp_idf_tx_gate_lease_registry_t reg;
    } ninlil_test_ops_reg_pack_t;
    ninlil_test_ops_reg_pack_t pack;
    ninlil_tx_gate_ops_t local;
    ninlil_esp_idf_abi_header_t hdr;
    ninlil_esp_idf_tx_gate_lease_registry_t snap;
    uint8_t storage[256];
    const size_t known = (size_t)NINLIL_TEST_OPS_KNOWN;
    const size_t declared = (size_t)NINLIL_TEST_OPS_DECLARED;

    _Static_assert(
        sizeof(ninlil_tx_gate_ops_t) == (size_t)NINLIL_TEST_OPS_KNOWN,
        "ops known size");
    _Static_assert(
        offsetof(ninlil_test_ops_reg_pack_t, reg) == (size_t)NINLIL_TEST_OPS_KNOWN,
        "reg must start at known end");

    (void)memset(&pack, 0x5A, sizeof(pack));
    fill_ops(&pack.known, &pack.known);
    pack.known.struct_size = (uint16_t)declared;
    ninlil_esp_idf_tx_gate_lease_registry_clear(&pack.reg);

    REQUIRE(
        assert_tail_only_ops_geometry(
            &pack.known, known, declared, &pack.reg, sizeof(pack.reg))
        == 0);

    snap = pack.reg;
    REQUIRE(
        ninlil_esp_idf_abi_stage_known_prefix(
            &pack.known, known, &pack.reg, sizeof(pack.reg), &local, &hdr)
        != 0);
    REQUIRE(memcmp(&pack.reg, &snap, sizeof(pack.reg)) == 0);

    fill_ops(&pack.known, &pack.known);
    pack.known.struct_size = (uint16_t)declared;
    ninlil_esp_idf_tx_gate_lease_registry_clear(&pack.reg);
    snap = pack.reg;
    REQUIRE(
        assert_tail_only_ops_geometry(
            &pack.known, known, declared, &pack.reg, sizeof(pack.reg))
        == 0);
    REQUIRE(ninlil_esp_idf_tx_gate_lease_registry_set_ops(&pack.reg, &pack.known)
        != 0);
    REQUIRE(memcmp(&pack.reg, &snap, sizeof(pack.reg)) == 0);

    /* Disjoint forward-extended ops OK. */
    {
        extended_ops_t ext;
        (void)memset(storage, 0xA5, sizeof(storage));
        fill_ops(&ext.known, &ext.known);
        ext.known.struct_size = (uint16_t)sizeof(ext);
        (void)memset(ext.tail, 0x11, sizeof(ext.tail));
        REQUIRE(
            ninlil_esp_idf_abi_stage_known_prefix(
                &ext, sizeof(ext.known), storage, sizeof(storage), &local, &hdr)
            == 0);
        REQUIRE(hdr.struct_size == (uint16_t)sizeof(ext));
        REQUIRE(memcmp(&local, &ext.known, sizeof(local)) == 0);
    }

    REQUIRE(!ninlil_esp_idf_pointer_range_representable(
        (const void *)(uintptr_t)1u, (size_t)UINTPTR_MAX));
    REQUIRE(
        ninlil_esp_idf_abi_declared_range_rejects(
            NULL, (uint16_t)known, storage, sizeof(storage))
        != 0);
    return 0;
}

/* Instrumented: post-validation poison of original; trusted must not re-read. */
static int test_trusted_publish_no_post_write_reread(void)
{
    ninlil_esp_idf_tx_gate_lease_registry_t reg;
    ninlil_esp_idf_tx_gate_lease_registry_t reg_before;
    ninlil_tx_gate_ops_t identity;
    ninlil_tx_gate_ops_t proof;
    ninlil_tx_gate_ops_t poisoned_copy;

    fill_ops(&identity, &identity);
    identity.struct_size = (uint16_t)sizeof(identity);
    proof = identity;

    ninlil_esp_idf_tx_gate_lease_registry_clear(&reg);
    REQUIRE(ninlil_esp_idf_tx_gate_ops_validate(&proof));

    /* Simulate post-owner-write poison of caller identity memory. */
    poisoned_copy = identity;
    (void)memset(&identity, 0xFF, sizeof(identity));

    /* Public path re-stages identity → must fail on poisoned memory shape. */
    reg_before = reg;
    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_set_ops(&reg, &identity) != 0);
    REQUIRE(memcmp(&reg, &reg_before, sizeof(reg)) == 0);

    /* Trusted seam: proof + original identity pointer, no re-read of identity. */
    REQUIRE(
        ninlil_esp_idf_tx_gate_lease_registry_set_ops_trusted(
            &reg, &identity, &proof)
        == 0);
    REQUIRE(reg.current_ops == &identity);
    REQUIRE(reg.current_ops != &proof);
    REQUIRE(reg.occupied_count == 0u);
    REQUIRE(reg.epoch == 1u);

    /* Double-check poisoned identity was not required to be valid shape. */
    REQUIRE(memcmp(&identity, &poisoned_copy, sizeof(identity)) != 0);
    return 0;
}

/*
 * cell_config_stage_nested_owner failure atomicity: same contract as
 * owner_config_stage. Outer reserved / nested exact-size rejects must not
 * poison out_outer_local / out_owner_local / out_hdr or storage.
 */
static int test_nested_owner_exact_size_matrix(void)
{
    uint8_t storage[512];
    uint8_t storage_snap[512];
    ninlil_esp_idf_cell_agent_config_t cfg;
    ninlil_esp_idf_cell_agent_config_t outer_local;
    ninlil_esp_idf_cell_agent_config_t outer_poison;
    ninlil_esp_idf_owner_task_config_t owner_local;
    ninlil_esp_idf_owner_task_config_t owner_poison;
    ninlil_esp_idf_abi_header_t ohdr;
    ninlil_esp_idf_abi_header_t hdr_poison;
    extended_cell_cfg_t huge;

    (void)memset(storage, 0x3C, sizeof(storage));
    (void)memcpy(storage_snap, storage, sizeof(storage_snap));
    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.abi_version = NINLIL_ABI_VERSION;
    cfg.struct_size = (uint16_t)sizeof(cfg);
    cfg.owner.abi_version = NINLIL_ABI_VERSION;
    cfg.owner.struct_size = (uint16_t)sizeof(cfg.owner);
    cfg.owner.task_priority = 5u;
    cfg.tx_gate = NULL;
    cfg.reserved_zero = 0u;

    (void)memset(&outer_poison, 0xA5, sizeof(outer_poison));
    (void)memset(&owner_poison, 0x5A, sizeof(owner_poison));
    (void)memset(&hdr_poison, 0xC3, sizeof(hdr_poison));

    /* Happy path: exact nested size. */
    REQUIRE(
        ninlil_esp_idf_cell_config_stage_nested_owner(
            &cfg, storage, sizeof(storage), &outer_local, &owner_local, &ohdr)
        == 0);
    REQUIRE(owner_local.struct_size == (uint16_t)sizeof(owner_local));
    REQUIRE(owner_local.task_priority == 5u);
    REQUIRE(outer_local.reserved_zero == 0u);
    REQUIRE(memcmp(storage, storage_snap, sizeof(storage)) == 0);

    /* Huge nested size: outer stage would succeed; nested reject must not
     * commit any out (isomorphic failure-atomicity bug). */
    {
        ninlil_esp_idf_cell_agent_config_t bad = cfg;
        bad.owner.struct_size = (uint16_t)(sizeof(bad.owner) + 64u);
        outer_local = outer_poison;
        owner_local = owner_poison;
        ohdr = hdr_poison;
        REQUIRE(
            ninlil_esp_idf_cell_config_stage_nested_owner(
                &bad, storage, sizeof(storage), &outer_local, &owner_local, &ohdr)
            != 0);
        REQUIRE(memcmp(&outer_local, &outer_poison, sizeof(outer_local)) == 0);
        REQUIRE(memcmp(&owner_local, &owner_poison, sizeof(owner_local)) == 0);
        REQUIRE(memcmp(&ohdr, &hdr_poison, sizeof(ohdr)) == 0);
        REQUIRE(memcmp(storage, storage_snap, sizeof(storage)) == 0);
    }

    /* Outer reserved_zero semantic reject after known-prefix stage. */
    {
        ninlil_esp_idf_cell_agent_config_t bad = cfg;
        bad.reserved_zero = 1u;
        outer_local = outer_poison;
        owner_local = owner_poison;
        ohdr = hdr_poison;
        REQUIRE(
            ninlil_esp_idf_cell_config_stage_nested_owner(
                &bad, storage, sizeof(storage), &outer_local, &owner_local, &ohdr)
            != 0);
        REQUIRE(memcmp(&outer_local, &outer_poison, sizeof(outer_local)) == 0);
        REQUIRE(memcmp(&owner_local, &owner_poison, sizeof(owner_local)) == 0);
        REQUIRE(memcmp(&ohdr, &hdr_poison, sizeof(ohdr)) == 0);
        REQUIRE(memcmp(storage, storage_snap, sizeof(storage)) == 0);
    }

    /* Undersize nested rejected; outs unchanged. */
    {
        ninlil_esp_idf_cell_agent_config_t bad = cfg;
        bad.owner.struct_size = 4u;
        outer_local = outer_poison;
        owner_local = owner_poison;
        ohdr = hdr_poison;
        REQUIRE(
            ninlil_esp_idf_cell_config_stage_nested_owner(
                &bad, storage, sizeof(storage), &outer_local, &owner_local, &ohdr)
            != 0);
        REQUIRE(memcmp(&outer_local, &outer_poison, sizeof(outer_local)) == 0);
        REQUIRE(memcmp(&owner_local, &owner_poison, sizeof(owner_local)) == 0);
        REQUIRE(memcmp(&ohdr, &hdr_poison, sizeof(ohdr)) == 0);
        REQUIRE(memcmp(storage, storage_snap, sizeof(storage)) == 0);
    }

    /* storage NULL with non-zero size closed reject. */
    {
        outer_local = outer_poison;
        owner_local = owner_poison;
        ohdr = hdr_poison;
        REQUIRE(
            ninlil_esp_idf_cell_config_stage_nested_owner(
                &cfg, NULL, sizeof(storage), &outer_local, &owner_local, &ohdr)
            != 0);
        REQUIRE(memcmp(&outer_local, &outer_poison, sizeof(outer_local)) == 0);
        REQUIRE(memcmp(&owner_local, &owner_poison, sizeof(owner_local)) == 0);
        REQUIRE(memcmp(&ohdr, &hdr_poison, sizeof(ohdr)) == 0);
    }

    /* non-NULL storage with size 0 closed reject. */
    {
        outer_local = outer_poison;
        owner_local = owner_poison;
        ohdr = hdr_poison;
        REQUIRE(
            ninlil_esp_idf_cell_config_stage_nested_owner(
                &cfg, storage, 0u, &outer_local, &owner_local, &ohdr)
            != 0);
        REQUIRE(memcmp(&outer_local, &outer_poison, sizeof(outer_local)) == 0);
        REQUIRE(memcmp(&owner_local, &owner_poison, sizeof(owner_local)) == 0);
        REQUIRE(memcmp(&ohdr, &hdr_poison, sizeof(ohdr)) == 0);
        REQUIRE(memcmp(storage, storage_snap, sizeof(storage)) == 0);
    }

    /* Optional out_hdr NULL remains legal on success. */
    REQUIRE(
        ninlil_esp_idf_cell_config_stage_nested_owner(
            &cfg, storage, sizeof(storage), &outer_local, &owner_local, NULL)
        == 0);
    REQUIRE(owner_local.task_priority == 5u);

    /* Outer extended OK if nested exact and contained; outer tail disjoint. */
    (void)memset(&huge, 0, sizeof(huge));
    huge.known = cfg;
    huge.known.struct_size = (uint16_t)sizeof(huge);
    huge.known.owner.struct_size = (uint16_t)sizeof(huge.known.owner);
    (void)memset(huge.tail_poison, 0xCD, sizeof(huge.tail_poison));
    REQUIRE(
        ninlil_esp_idf_cell_config_stage_nested_owner(
            &huge.known,
            storage,
            sizeof(storage),
            &outer_local,
            &owner_local,
            &ohdr)
        == 0);
    REQUIRE(ohdr.struct_size == (uint16_t)sizeof(huge));
    REQUIRE(owner_local.struct_size == (uint16_t)sizeof(owner_local));
    REQUIRE(memcmp(storage, storage_snap, sizeof(storage)) == 0);
    return 0;
}

static int test_loopback_extended_permit_release(void)
{
    ninlil_esp_idf_loopback_tx_permit_t gate;
    ninlil_esp_idf_loopback_tx_permit_config_t lcfg;
    ninlil_tx_request_t req;
    ninlil_time_sample_t now;
    ninlil_tx_permit_t base;
    extended_permit_t ext;
    ninlil_esp_idf_loopback_tx_permit_t snap;
    uint32_t live;

    _Static_assert(
        sizeof(((extended_permit_t *)0)->known)
            == (size_t)NINLIL_TEST_PERMIT_KNOWN,
        "permit known size");
    _Static_assert(
        sizeof(extended_permit_t) == (size_t)NINLIL_TEST_PERMIT_DECLARED,
        "permit declared size");

    (void)memset(&gate, 0, sizeof(gate));
    (void)memset(&lcfg, 0, sizeof(lcfg));
    lcfg.abi_version = NINLIL_ABI_VERSION;
    lcfg.struct_size = (uint16_t)sizeof(lcfg);
    lcfg.environment = NINLIL_ENV_TEST;
    lcfg.loopback_enabled = 1u;
    REQUIRE(
        ninlil_esp_idf_loopback_tx_permit_init_pure(
            &gate, &lcfg, dummy_acq, dummy_rel)
        == 0);

    (void)memset(&req, 0, sizeof(req));
    req.abi_version = NINLIL_ABI_VERSION;
    req.struct_size = (uint16_t)sizeof(req);
    req.transaction_id.bytes[0] = 1u;
    req.attempt_id.bytes[0] = 2u;
    req.message_kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    req.logical_bytes = 8u;
    req.content_digest.algorithm = NINLIL_DIGEST_SHA256;
    (void)memset(&now, 0, sizeof(now));
    now.abi_version = NINLIL_ABI_VERSION;
    now.struct_size = (uint16_t)sizeof(now);
    now.clock_epoch_id.bytes[0] = 3u;
    now.now_ms = 20u;
    now.trust = NINLIL_CLOCK_TRUSTED;

    REQUIRE(
        ninlil_esp_idf_loopback_tx_permit_acquire_pure(&gate, &req, &now, &base)
        == NINLIL_TX_GATE_OK);
    REQUIRE(gate.live_count == 1u);

    /* Disjoint extended permit: same semantic identity, larger struct_size. */
    (void)memset(&ext, 0, sizeof(ext));
    ext.known = base;
    ext.known.struct_size = (uint16_t)sizeof(ext);
    (void)memset(ext.tail, 0x11, sizeof(ext.tail));
    ninlil_esp_idf_loopback_tx_permit_release_unused_pure(&gate, &ext.known);
    REQUIRE(gate.live_count == 0u);

    /* Re-acquire for double-release. */
    REQUIRE(
        ninlil_esp_idf_loopback_tx_permit_acquire_pure(&gate, &req, &now, &base)
        == NINLIL_TX_GATE_OK);
    ninlil_esp_idf_loopback_tx_permit_release_unused_pure(&gate, &base);
    REQUIRE(gate.live_count == 0u);
    live = gate.live_count;
    snap = gate;
    ninlil_esp_idf_loopback_tx_permit_release_unused_pure(&gate, &base);
    /* Double release may only bump reuse_denied. */
    snap.stats.reuse_denied += 1u;
    REQUIRE(memcmp(&gate, &snap, sizeof(gate)) == 0);
    REQUIRE(gate.live_count == live);
    REQUIRE(ninlil_esp_idf_loopback_tx_permit_shutdown_blocked_by_live(&gate)
        == 0);

    /*
     * Tail-only permit vs gate:
     *   [permit known K][gate R...]
     * declared = K+T overlaps only gate head. Snapshot API gate only.
     */
    {
        typedef struct ninlil_test_permit_gate_pack {
            ninlil_tx_permit_t known;
            ninlil_esp_idf_loopback_tx_permit_t gate;
        } ninlil_test_permit_gate_pack_t;
        ninlil_test_permit_gate_pack_t pack;
        ninlil_esp_idf_loopback_tx_permit_t expected;
        const size_t pknown = (size_t)NINLIL_TEST_PERMIT_KNOWN;
        const size_t pdecl = (size_t)NINLIL_TEST_PERMIT_DECLARED;

        _Static_assert(
            offsetof(ninlil_test_permit_gate_pack_t, gate)
                == (size_t)NINLIL_TEST_PERMIT_KNOWN,
            "gate must start at permit known end");

        (void)memset(&pack, 0, sizeof(pack));
        REQUIRE(
            ninlil_esp_idf_loopback_tx_permit_init_pure(
                &pack.gate, &lcfg, dummy_acq, dummy_rel)
            == 0);
        REQUIRE(
            ninlil_esp_idf_loopback_tx_permit_acquire_pure(
                &pack.gate, &req, &now, &base)
            == NINLIL_TX_GATE_OK);

        pack.known = base;
        pack.known.struct_size = (uint16_t)pdecl;

        REQUIRE(
            assert_tail_only_ops_geometry(
                &pack.known, pknown, pdecl, &pack.gate, sizeof(pack.gate))
            == 0);

        expected = pack.gate;
        ninlil_esp_idf_loopback_tx_permit_release_unused_pure(
            &pack.gate, &pack.known);
        expected.stats.reuse_denied += 1u;
        REQUIRE(memcmp(&pack.gate, &expected, sizeof(pack.gate)) == 0);
        REQUIRE(pack.gate.live_count == 1u);

        ninlil_esp_idf_loopback_tx_permit_release_unused_pure(
            &pack.gate, &base);
        REQUIRE(pack.gate.live_count == 0u);
        REQUIRE(ninlil_esp_idf_loopback_tx_permit_shutdown_blocked_by_live(
                    &pack.gate)
            == 0);
    }
    return 0;
}

/*
 * Standalone owner forward-extension via production helper
 * ninlil_esp_idf_owner_config_stage (same path as owner_task_init).
 * Generic abi_stage_known_prefix alone is not used as the contract test.
 *
 * Private contract: out_local/out_hdr only written on success. Every
 * failure path must leave outputs byte-exact unchanged and storage
 * immutable (reserved reject, null, bad size, overlap, etc.).
 */
static int test_standalone_owner_forward_extension(void)
{
    /* Synthetic owner storage blob (host cannot sizeof FreeRTOS owner_task). */
    uint8_t owner_storage[4096];
    uint8_t storage_snap[4096];
    extended_owner_cfg_t ext;
    ninlil_esp_idf_owner_task_config_t local;
    ninlil_esp_idf_owner_task_config_t local_poison;
    ninlil_esp_idf_abi_header_t hdr;
    ninlil_esp_idf_abi_header_t hdr_poison;

    (void)memset(owner_storage, 0x3C, sizeof(owner_storage));
    (void)memcpy(storage_snap, owner_storage, sizeof(storage_snap));
    (void)memset(&ext, 0, sizeof(ext));
    ext.known.abi_version = NINLIL_ABI_VERSION;
    ext.known.struct_size = (uint16_t)sizeof(ext); /* forward extension */
    ext.known.task_priority = 7u;
    ext.known.reserved_zero = 0u;
    (void)memset(ext.tail, 0x44, sizeof(ext.tail));

    /* Caller extension tail must not overlap owner storage. */
    REQUIRE(!ninlil_esp_idf_pointer_ranges_overlap(
        &ext, sizeof(ext), owner_storage, sizeof(owner_storage)));
    REQUIRE(
        ninlil_esp_idf_owner_config_stage(
            (const ninlil_esp_idf_owner_task_config_t *)(const void *)&ext,
            owner_storage,
            sizeof(owner_storage),
            &local,
            &hdr)
        == 0);
    /* Declared extension preserved in header; known fields exact in local. */
    REQUIRE(hdr.struct_size == (uint16_t)sizeof(ext));
    REQUIRE(local.abi_version == NINLIL_ABI_VERSION);
    REQUIRE(local.task_priority == 7u);
    REQUIRE(local.reserved_zero == 0u);
    /* Local known prefix only — struct_size reflects caller declared value. */
    REQUIRE(local.struct_size == (uint16_t)sizeof(ext));
    /* Owner storage bytes completely unchanged. */
    REQUIRE(memcmp(owner_storage, storage_snap, sizeof(owner_storage)) == 0);

    /*
     * Failure-path output immutability: poison both outs, then every reject
     * path must leave them byte-exact and leave storage unchanged.
     */
    (void)memset(&local_poison, 0xA5, sizeof(local_poison));
    (void)memset(&hdr_poison, 0x5C, sizeof(hdr_poison));

    /* reserved_zero semantic reject after known-prefix stage. */
    local = local_poison;
    hdr = hdr_poison;
    ext.known.reserved_zero = 1u;
    REQUIRE(
        ninlil_esp_idf_owner_config_stage(
            (const ninlil_esp_idf_owner_task_config_t *)(const void *)&ext,
            owner_storage,
            sizeof(owner_storage),
            &local,
            &hdr)
        != 0);
    REQUIRE(memcmp(&local, &local_poison, sizeof(local)) == 0);
    REQUIRE(memcmp(&hdr, &hdr_poison, sizeof(hdr)) == 0);
    REQUIRE(memcmp(owner_storage, storage_snap, sizeof(owner_storage)) == 0);

    /* NULL cfg. */
    local = local_poison;
    hdr = hdr_poison;
    REQUIRE(
        ninlil_esp_idf_owner_config_stage(
            NULL,
            owner_storage,
            sizeof(owner_storage),
            &local,
            &hdr)
        != 0);
    REQUIRE(memcmp(&local, &local_poison, sizeof(local)) == 0);
    REQUIRE(memcmp(&hdr, &hdr_poison, sizeof(hdr)) == 0);
    REQUIRE(memcmp(owner_storage, storage_snap, sizeof(owner_storage)) == 0);

    /* NULL out_local (hdr must also stay unchanged). */
    local = local_poison;
    hdr = hdr_poison;
    ext.known.reserved_zero = 0u;
    REQUIRE(
        ninlil_esp_idf_owner_config_stage(
            (const ninlil_esp_idf_owner_task_config_t *)(const void *)&ext,
            owner_storage,
            sizeof(owner_storage),
            NULL,
            &hdr)
        != 0);
    REQUIRE(memcmp(&hdr, &hdr_poison, sizeof(hdr)) == 0);
    REQUIRE(memcmp(owner_storage, storage_snap, sizeof(owner_storage)) == 0);

    /* Bad struct_size (below known min). */
    local = local_poison;
    hdr = hdr_poison;
    ext.known.struct_size =
        (uint16_t)(sizeof(ninlil_esp_idf_owner_task_config_t) - 1u);
    REQUIRE(
        ninlil_esp_idf_owner_config_stage(
            (const ninlil_esp_idf_owner_task_config_t *)(const void *)&ext,
            owner_storage,
            sizeof(owner_storage),
            &local,
            &hdr)
        != 0);
    REQUIRE(memcmp(&local, &local_poison, sizeof(local)) == 0);
    REQUIRE(memcmp(&hdr, &hdr_poison, sizeof(hdr)) == 0);
    REQUIRE(memcmp(owner_storage, storage_snap, sizeof(owner_storage)) == 0);

    /* Bad abi_version. */
    local = local_poison;
    hdr = hdr_poison;
    ext.known.struct_size = (uint16_t)sizeof(ext);
    ext.known.abi_version = (uint16_t)(NINLIL_ABI_VERSION ^ 0xFFFFu);
    REQUIRE(
        ninlil_esp_idf_owner_config_stage(
            (const ninlil_esp_idf_owner_task_config_t *)(const void *)&ext,
            owner_storage,
            sizeof(owner_storage),
            &local,
            &hdr)
        != 0);
    REQUIRE(memcmp(&local, &local_poison, sizeof(local)) == 0);
    REQUIRE(memcmp(&hdr, &hdr_poison, sizeof(hdr)) == 0);
    REQUIRE(memcmp(owner_storage, storage_snap, sizeof(owner_storage)) == 0);

    /* Declared range overlaps synthetic owner storage (geometry reject). */
    {
        /* Layout: [known K][storage...]; declared = K+T overlaps storage head. */
        typedef struct {
            ninlil_esp_idf_owner_task_config_t known;
            uint8_t storage_body[256];
        } overlap_pack_t;
        overlap_pack_t pack;
        uint8_t pack_snap[sizeof(pack)];
        const size_t known_sz = sizeof(pack.known);
        const size_t tail_overlap = 32u;

        (void)memset(&pack, 0x11, sizeof(pack));
        pack.known.abi_version = NINLIL_ABI_VERSION;
        pack.known.struct_size = (uint16_t)(known_sz + tail_overlap);
        pack.known.task_priority = 3u;
        pack.known.reserved_zero = 0u;
        (void)memcpy(pack_snap, &pack, sizeof(pack));

        REQUIRE(offsetof(overlap_pack_t, storage_body) == known_sz);
        REQUIRE(ninlil_esp_idf_pointer_ranges_overlap(
            &pack.known,
            (size_t)pack.known.struct_size,
            pack.storage_body,
            sizeof(pack.storage_body)));

        local = local_poison;
        hdr = hdr_poison;
        REQUIRE(
            ninlil_esp_idf_owner_config_stage(
                &pack.known,
                pack.storage_body,
                sizeof(pack.storage_body),
                &local,
                &hdr)
            != 0);
        REQUIRE(memcmp(&local, &local_poison, sizeof(local)) == 0);
        REQUIRE(memcmp(&hdr, &hdr_poison, sizeof(hdr)) == 0);
        REQUIRE(memcmp(&pack, pack_snap, sizeof(pack)) == 0);
    }

    /* owner_storage==NULL && size!=0 closed reject. */
    local = local_poison;
    hdr = hdr_poison;
    ext.known.abi_version = NINLIL_ABI_VERSION;
    ext.known.struct_size = (uint16_t)sizeof(ext);
    ext.known.reserved_zero = 0u;
    REQUIRE(
        ninlil_esp_idf_owner_config_stage(
            (const ninlil_esp_idf_owner_task_config_t *)(const void *)&ext,
            NULL,
            sizeof(owner_storage),
            &local,
            &hdr)
        != 0);
    REQUIRE(memcmp(&local, &local_poison, sizeof(local)) == 0);
    REQUIRE(memcmp(&hdr, &hdr_poison, sizeof(hdr)) == 0);
    REQUIRE(memcmp(owner_storage, storage_snap, sizeof(owner_storage)) == 0);

    /* owner_storage non-NULL && size==0 closed reject. */
    local = local_poison;
    hdr = hdr_poison;
    REQUIRE(
        ninlil_esp_idf_owner_config_stage(
            (const ninlil_esp_idf_owner_task_config_t *)(const void *)&ext,
            owner_storage,
            0u,
            &local,
            &hdr)
        != 0);
    REQUIRE(memcmp(&local, &local_poison, sizeof(local)) == 0);
    REQUIRE(memcmp(&hdr, &hdr_poison, sizeof(hdr)) == 0);
    REQUIRE(memcmp(owner_storage, storage_snap, sizeof(owner_storage)) == 0);

    /* Both-absent storage (NULL,0) is legal vacuous non-overlap. */
    REQUIRE(
        ninlil_esp_idf_owner_config_stage(
            (const ninlil_esp_idf_owner_task_config_t *)(const void *)&ext,
            NULL,
            0u,
            &local,
            &hdr)
        == 0);
    REQUIRE(local.task_priority == 7u);
    REQUIRE(hdr.struct_size == (uint16_t)sizeof(ext));

    /* Optional out_hdr NULL remains legal. */
    (void)memset(&local, 0xA5, sizeof(local));
    REQUIRE(
        ninlil_esp_idf_owner_config_stage(
            (const ninlil_esp_idf_owner_task_config_t *)(const void *)&ext,
            owner_storage,
            sizeof(owner_storage),
            &local,
            NULL)
        == 0);
    REQUIRE(local.task_priority == 7u);
    REQUIRE(memcmp(owner_storage, storage_snap, sizeof(owner_storage)) == 0);

    /*
     * out_local / out_hdr / storage alias matrix (uintptr overlap helper).
     * Positive non-overlap already covered; boundary adjacency ok;
     * head/tail/partial/full overlap of outs vs storage rejected.
     */
    {
        typedef struct {
            ninlil_esp_idf_owner_task_config_t local_slot;
            ninlil_esp_idf_abi_header_t hdr_slot;
            uint8_t gap;
            uint8_t storage_body[128];
        } alias_pack_t;
        alias_pack_t pack;
        uint8_t pack_snap[sizeof(pack)];
        ninlil_esp_idf_owner_task_config_t cfg_ok;

        (void)memset(&pack, 0x22, sizeof(pack));
        (void)memset(&cfg_ok, 0, sizeof(cfg_ok));
        cfg_ok.abi_version = NINLIL_ABI_VERSION;
        cfg_ok.struct_size = (uint16_t)sizeof(cfg_ok);
        cfg_ok.task_priority = 4u;
        cfg_ok.reserved_zero = 0u;
        (void)memcpy(pack_snap, &pack, sizeof(pack));

        /* Boundary: local immediately before storage with gap — non-overlap. */
        REQUIRE(!ninlil_esp_idf_pointer_ranges_overlap(
            &pack.local_slot,
            sizeof(pack.local_slot),
            pack.storage_body,
            sizeof(pack.storage_body)));
        REQUIRE(
            ninlil_esp_idf_owner_config_stage(
                &cfg_ok,
                pack.storage_body,
                sizeof(pack.storage_body),
                &pack.local_slot,
                &pack.hdr_slot)
            == 0);
        REQUIRE(pack.local_slot.task_priority == 4u);
        /* storage body must remain pre-stage poison (stage does not write it). */
        REQUIRE(memcmp(
            pack.storage_body,
            pack_snap + offsetof(alias_pack_t, storage_body),
            sizeof(pack.storage_body))
            == 0);

        /* out_local aliases storage head → reject, storage/hdr unchanged. */
        {
            typedef struct {
                union {
                    ninlil_esp_idf_owner_task_config_t as_local;
                    uint8_t as_storage[sizeof(ninlil_esp_idf_owner_task_config_t)
                        + 32u];
                } u;
                ninlil_esp_idf_abi_header_t hdr_slot;
            } local_storage_alias_t;
            local_storage_alias_t alias;
            uint8_t alias_snap[sizeof(alias)];
            ninlil_esp_idf_abi_header_t hdr_before;

            (void)memset(&alias, 0x77, sizeof(alias));
            (void)memcpy(alias_snap, &alias, sizeof(alias));
            hdr_before = alias.hdr_slot;
            REQUIRE(
                ninlil_esp_idf_owner_config_stage(
                    &cfg_ok,
                    alias.u.as_storage,
                    sizeof(alias.u.as_storage),
                    &alias.u.as_local,
                    &alias.hdr_slot)
                != 0);
            REQUIRE(memcmp(&alias, alias_snap, sizeof(alias)) == 0);
            REQUIRE(memcmp(&alias.hdr_slot, &hdr_before, sizeof(hdr_before))
                == 0);
        }

        /* out_local aliases out_hdr → reject (commit-order corruption). */
        {
            typedef struct {
                ninlil_esp_idf_owner_task_config_t local_slot;
            } local_only_t;
            /* Place hdr inside local object bytes via char overlay. */
            local_only_t lo;
            ninlil_esp_idf_abi_header_t *hdr_alias;
            uint8_t lo_snap[sizeof(lo)];

            (void)memset(&lo, 0x88, sizeof(lo));
            (void)memcpy(lo_snap, &lo, sizeof(lo));
            hdr_alias = (ninlil_esp_idf_abi_header_t *)(void *)&lo.local_slot;
            REQUIRE(ninlil_esp_idf_pointer_ranges_overlap(
                &lo.local_slot,
                sizeof(lo.local_slot),
                hdr_alias,
                sizeof(*hdr_alias)));
            REQUIRE(
                ninlil_esp_idf_owner_config_stage(
                    &cfg_ok,
                    owner_storage,
                    sizeof(owner_storage),
                    &lo.local_slot,
                    hdr_alias)
                != 0);
            REQUIRE(memcmp(&lo, lo_snap, sizeof(lo)) == 0);
            REQUIRE(
                memcmp(owner_storage, storage_snap, sizeof(owner_storage))
                == 0);
        }
    }

    return 0;
}

int main(void)
{
    if (test_lease_two_borrowers_and_forgeries() != 0
        || test_lease_full_and_token_exhaust_issue() != 0
        || test_registry_alias_null_head_tail_partial() != 0
        || test_pointer_range_owner_blob_regions() != 0
        || test_snapshot_borrower_count_direct() != 0
        || test_authority_and_mailbox() != 0
        || test_abi_stage_tail_only_and_overflow() != 0
        || test_trusted_publish_no_post_write_reread() != 0
        || test_nested_owner_exact_size_matrix() != 0
        || test_loopback_extended_permit_release() != 0
        || test_standalone_owner_forward_extension() != 0) {
        return 1;
    }
    return 0;
}
