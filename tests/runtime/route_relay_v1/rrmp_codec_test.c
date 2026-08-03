#include "rrmp_test_common.h"
#include "rrmp_store.h"

#include <stddef.h>

static void repair_nps1(uint8_t raw[NINLIL_RRMP_NPS1_BYTES])
{
    ninlil_rrmp_sha256(raw, 212u, raw + 212u);
    ninlil_rrmp_put_u32_be(raw + 244u, 0u);
    ninlil_rrmp_put_u32_be(
        raw + 244u, ninlil_rrmp_crc32c(raw, NINLIL_RRMP_NPS1_BYTES));
}

static void repair_noa1(uint8_t raw[NINLIL_RRMP_NOA1_BYTES])
{
    ninlil_rrmp_sha256(raw, 224u, raw + 224u);
    ninlil_rrmp_put_u32_be(raw + 256u, 0u);
    ninlil_rrmp_put_u32_be(
        raw + 256u, ninlil_rrmp_crc32c(raw, NINLIL_RRMP_NOA1_BYTES));
}

static void repair_nph1(uint8_t raw[NINLIL_RRMP_NPH1_BYTES])
{
    ninlil_rrmp_sha256(raw, 160u, raw + 160u);
    ninlil_rrmp_put_u32_be(raw + 192u, 0u);
    ninlil_rrmp_put_u32_be(
        raw + 192u, ninlil_rrmp_crc32c(raw, NINLIL_RRMP_NPH1_BYTES));
}

static void repair_page_crc(uint8_t *raw, size_t bytes, size_t crc_offset)
{
    ninlil_rrmp_put_u32_be(raw + crc_offset, 0u);
    ninlil_rrmp_put_u32_be(
        raw + crc_offset, ninlil_rrmp_crc32c(raw, bytes));
}

static void repair_prefix_crc(uint8_t *raw, size_t crc_offset)
{
    ninlil_rrmp_put_u32_be(raw + crc_offset, 0u);
    ninlil_rrmp_put_u32_be(
        raw + crc_offset, ninlil_rrmp_crc32c(raw, crc_offset));
}

static int test_sha_kat(void)
{
    uint8_t dig[32];
    static const uint8_t empty[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8,
        0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
    static const uint8_t abc[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
        0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    RRMP_CHECK(ninlil_rrmp_sha256_selftest());
    ninlil_rrmp_sha256((const uint8_t *)"", 0u, dig);
    RRMP_CHECK(memcmp(dig, empty, 32u) == 0);
    ninlil_rrmp_sha256((const uint8_t *)"abc", 3u, dig);
    RRMP_CHECK(memcmp(dig, abc, 32u) == 0);
    return 0;
}

static int test_static_abi(void)
{
    RRMP_CHECK_EQ(sizeof(ninlil_rrmp_preamble_v1_t), 16u);
    RRMP_CHECK_EQ(sizeof(ninlil_route_result_v1_t), 128u);
    RRMP_CHECK_EQ(sizeof(ninlil_parent_result_v1_t), 128u);
    RRMP_CHECK_EQ(NINLIL_RRMP_PKEY_COUNT, 22u);
    RRMP_CHECK_EQ(NINLIL_RRMP_PKEY_NPP1_BASE, 1u);
    RRMP_CHECK_EQ(NINLIL_RRMP_PKEY_NPA1_BASE, 6u);
    RRMP_CHECK_EQ(NINLIL_RRMP_PKEY_NPT1_BASE, 14u);
    RRMP_CHECK_EQ(NINLIL_RRMP_NPP1_PAGE_COUNT, 5u);
    RRMP_CHECK_EQ(NINLIL_RRMP_NPA1_PAGE_COUNT, 8u);
    RRMP_CHECK_EQ(NINLIL_RRMP_NPT1_PAGE_COUNT, 8u);
    RRMP_CHECK_EQ(NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY, 64u);
    RRMP_CHECK_EQ(NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES, 64u);
    RRMP_CHECK_EQ(NINLIL_RRMP_ROUTE_STATE_EXPIRED, 4u);
    RRMP_CHECK_EQ(NINLIL_RRMP_ROUTE_STATE_RETIRED, 5u);
    RRMP_CHECK_EQ(NINLIL_RRMP_LIFE_EXPIRED, 4u);
    RRMP_CHECK_EQ(NINLIL_RRMP_LIFE_RETIRED, 5u);
    RRMP_CHECK_EQ(offsetof(ninlil_parent_result_v1_t, status), 16u);
    RRMP_CHECK_EQ(offsetof(ninlil_parent_result_v1_t, owner_scope_id), 32u);
    RRMP_CHECK_EQ(offsetof(ninlil_parent_result_v1_t, handoff_step), 72u);
    RRMP_CHECK_EQ(offsetof(ninlil_parent_result_v1_t, seal_allowed), 75u);
    RRMP_CHECK_EQ(
        offsetof(ninlil_parent_result_v1_t, token_or_commit_digest32), 80u);
    RRMP_CHECK_EQ(sizeof(ninlil_route_activate_req_v1_t), 64u);
    RRMP_CHECK_EQ(sizeof(ninlil_route_forward_admit_req_v1_t), 128u);
    RRMP_CHECK_EQ(sizeof(ninlil_parent_set_install_req_v1_t), 240u);
    RRMP_CHECK_EQ(sizeof(ninlil_parent_owner_prepare_req_v1_t), 464u);
    RRMP_CHECK(ninlil_rrmp_owner_workspace_bytes() > 0u);
    RRMP_CHECK(
        ninlil_rrmp_owner_workspace_bytes() <=
        NINLIL_RRMP_OWNER_WORKSPACE_BUDGET_BYTES);
    /* Encode scratch is inside owner; exact size must fit the 384 KiB gate. */
    return 0;
}

static int test_precedence_matrix(void)
{
    uint8_t f[22];
    size_t i;
    const char *const *names = ninlil_rrmp_route_precedence_names();
    RRMP_CHECK(names != NULL);
    RRMP_CHECK_EQ(strcmp(names[0], "INVALID_ARGUMENT"), 0);
    RRMP_CHECK_EQ(strcmp(names[4], "FEATURE_OFF"), 0);
    for (i = 0u; i < 21u; ++i) {
        ninlil_rrmp_memzero(f, sizeof(f));
        f[i] = 1u;
        RRMP_CHECK(ninlil_rrmp_route_precedence_pick(f) != 0u);
    }
    ninlil_rrmp_memzero(f, sizeof(f));
    f[0] = 1u;
    f[4] = 1u;
    RRMP_CHECK_EQ(
        ninlil_rrmp_route_precedence_pick(f), NINLIL_ROUTE_INVALID_ARGUMENT);
    return 0;
}

static int test_codecs_semantic(void)
{
    ninlil_rrmp_nrm1_fields_t in, out;
    ninlil_rrmp_nev1_fields_t evi_in, evi_out;
    uint8_t raw[NINLIL_RRMP_NRM1_BYTES];
    uint8_t slot[NINLIL_RRMP_SLOT_BYTES];
    uint8_t nrp1[NINLIL_RRMP_NRP1_BYTES];
    uint8_t npp1[NINLIL_RRMP_NPP1_BYTES];
    uint8_t npa1[NINLIL_RRMP_NPA1_BYTES];
    uint8_t npts[NINLIL_RRMP_NPT1_SLOT_BYTES];
    uint8_t npt1[NINLIL_RRMP_NPT1_BYTES];
    uint8_t exact[NINLIL_RRMP_EXACT_BODY_BYTES];
    uint8_t dig32[32];
    uint8_t state;
    uint64_t seq;
    const uint8_t *slots[NINLIL_RRMP_SLOTS_PER_PAGE];
    const uint8_t *aslots[NINLIL_RRMP_ASSIGNMENT_SLOTS_PER_PAGE];
    size_t i;
    ninlil_rrmp_nps1_fields_t nps;
    uint8_t nps_raw[NINLIL_RRMP_NPS1_BYTES];
    ninlil_rrmp_id16_t ids[1];
    ninlil_rrmp_digest32_t pdig;

    /* Round-trip NRM1 + reserved zero + ranges */
    rrmp_fill_nrm1(&in, 7u, 1u, 1u);
    RRMP_CHECK(ninlil_rrmp_encode_nrm1(&in, raw));
    RRMP_CHECK(ninlil_rrmp_decode_nrm1(raw, &out));
    RRMP_CHECK_EQ(out.route_handle, 7u);
    RRMP_CHECK_EQ(out.terminal_flag, 1u);
    RRMP_CHECK_EQ(out.max_hops, 1u);
    RRMP_CHECK_EQ(raw[122], 0u); /* reserved */
    RRMP_CHECK_EQ(raw[131], 0u); /* reserved */

    /* all-zero body rejected (bad magic/digest) */
    ninlil_rrmp_memzero(raw, sizeof(raw));
    RRMP_CHECK(!ninlil_rrmp_decode_nrm1(raw, &out));

    /* materialize cross-ref: exact body from NRM1 fields */
    RRMP_CHECK(ninlil_rrmp_materialize_exact(&in, exact));
    RRMP_CHECK(memcmp(exact, in.egress_peer_id.bytes, 16u) == 0);

    /* Slot kinds: ACTIVE/EXPIRED/RETIRED encode/decode */
    RRMP_CHECK(ninlil_rrmp_encode_slot(
        NINLIL_RRMP_ROUTE_STATE_ACTIVE, &in, 3u, NULL, slot));
    RRMP_CHECK(ninlil_rrmp_decode_slot_state(slot, &state, &out, &seq));
    RRMP_CHECK_EQ(state, NINLIL_RRMP_ROUTE_STATE_ACTIVE);
    RRMP_CHECK_EQ(seq, 3u);
    RRMP_CHECK(ninlil_rrmp_encode_slot(
        NINLIL_RRMP_ROUTE_STATE_EXPIRED, &in, 9u, NULL, slot));
    RRMP_CHECK(ninlil_rrmp_decode_slot_state(slot, &state, &out, &seq));
    RRMP_CHECK_EQ(state, NINLIL_RRMP_ROUTE_STATE_EXPIRED);
    RRMP_CHECK(ninlil_rrmp_encode_slot(
        NINLIL_RRMP_ROUTE_STATE_RETIRED, &in, 1u, NULL, slot));
    RRMP_CHECK(ninlil_rrmp_decode_slot_state(slot, &state, &out, &seq));
    RRMP_CHECK_EQ(state, NINLIL_RRMP_ROUTE_STATE_RETIRED);

    /* NRP1 page with one slot + empty rest */
    for (i = 0u; i < NINLIL_RRMP_SLOTS_PER_PAGE; ++i) {
        slots[i] = NULL;
    }
    slots[0] = slot;
    RRMP_CHECK(ninlil_rrmp_encode_nrp1(0u, 1u, slots, nrp1));
    RRMP_CHECK(ninlil_rrmp_validate_nrp1(nrp1));
    /* page_index out of range */
    RRMP_CHECK(!ninlil_rrmp_encode_nrp1(NINLIL_RRMP_PAGE_COUNT, 1u, slots, nrp1));

    /* NEV1 lifecycle LIVE */
    ninlil_rrmp_memzero(&evi_in, sizeof(evi_in));
    evi_in.route_handle = 7u;
    evi_in.route_generation = 1u;
    evi_in.admission_seq = 1u;
    evi_in.lifecycle = NINLIL_RRMP_EVIDENCE_LIFECYCLE_LIVE;
    evi_in.hop_remaining_in = 1u;
    evi_in.hop_remaining_out = 0u;
    evi_in.result_status = NINLIL_ROUTE_OK;
    rrmp_fill_id(evi_in.local_runtime_id.bytes, 0x10u);
    RRMP_CHECK(ninlil_rrmp_encode_nev1(&evi_in, raw));
    RRMP_CHECK(ninlil_rrmp_decode_nev1(raw, &evi_out));
    RRMP_CHECK_EQ(evi_out.lifecycle, NINLIL_RRMP_EVIDENCE_LIFECYCLE_LIVE);

    /* NPP1 empty page (all pages 0..4 encodeable) */
    {
        const uint8_t *nps_slots[NINLIL_RRMP_NPP1_SLOTS];
        for (i = 0u; i < NINLIL_RRMP_NPP1_SLOTS; ++i) {
            nps_slots[i] = NULL;
        }
        for (i = 0u; i < NINLIL_RRMP_NPP1_PAGE_COUNT; ++i) {
            RRMP_CHECK(ninlil_rrmp_encode_npp1((uint16_t)i, 1u, nps_slots, npp1));
            RRMP_CHECK(ninlil_rrmp_validate_npp1(npp1));
        }
    }

    /* NPA1 assignment page */
    for (i = 0u; i < NINLIL_RRMP_ASSIGNMENT_SLOTS_PER_PAGE; ++i) {
        aslots[i] = NULL;
    }
    RRMP_CHECK(ninlil_rrmp_encode_npa1_page(0u, 1u, aslots, npa1));
    RRMP_CHECK(ninlil_rrmp_validate_npa1(npa1));

    /* NPT1 token kinds: LIVE + TOMBSTONE */
    memset(dig32, 0xAAu, sizeof(dig32));
    RRMP_CHECK(ninlil_rrmp_encode_npt1_slot(
        dig32, NINLIL_RRMP_NPT1_KIND_TOKEN_LIVE, 1000000u, npts));
    RRMP_CHECK(ninlil_rrmp_encode_npt1_page(0u, 1u, npts, 1u, npt1));
    RRMP_CHECK(ninlil_rrmp_validate_npt1(npt1));
    RRMP_CHECK(ninlil_rrmp_encode_npt1_slot(
        dig32, NINLIL_RRMP_NPT1_KIND_TOMBSTONE_USED, 1000001u, npts));
    RRMP_CHECK(ninlil_rrmp_encode_npt1_page(0u, 1u, npts, 1u, npt1));
    RRMP_CHECK(ninlil_rrmp_validate_npt1(npt1));

    /* NPS1 parent-set record */
    ninlil_rrmp_memzero(&nps, sizeof(nps));
    rrmp_fill_id(nps.owner_scope_id.bytes, 0x5Cu);
    rrmp_fill_id(nps.parent_set_id.bytes, 0x50u);
    nps.parent_set_revision = 1u;
    nps.parent_count = 1u;
    rrmp_fill_id(ids[0].bytes, 0x30u);
    nps.parent_ids[0] = ids[0];
    RRMP_CHECK(ninlil_rrmp_parent_set_digest(ids, 1u, &pdig));
    nps.parent_set_digest = pdig;
    RRMP_CHECK(ninlil_rrmp_encode_nps1(&nps, nps_raw));
    RRMP_CHECK(ninlil_rrmp_validate_nps1(nps_raw));

    return 0;
}

static int test_owner_scope_derivation(void)
{
    uint8_t ep[16], pp_a[16], pp_b[16], sc_a[16], sc_b[16];
    const uint8_t ns[] = "nspc";
    const uint8_t svc[] = "svc";
    size_t i;
    for (i = 0u; i < 16u; ++i) {
        ep[i] = (uint8_t)(0x10u + i);
        pp_a[i] = (uint8_t)(0x80u + i);
        pp_b[i] = (uint8_t)(0x81u + i);
    }
    RRMP_CHECK(ninlil_rrmp_derive_owner_scope_id(
        ep, 0u, ns, 4u, svc, 3u, 1u, pp_a, sc_a));
    RRMP_CHECK(ninlil_rrmp_derive_owner_scope_id(
        ep, 0u, ns, 4u, svc, 3u, 1u, pp_b, sc_b));
    RRMP_CHECK(memcmp(sc_a, sc_b, 16u) != 0);
    RRMP_CHECK(memcmp(sc_a, pp_a, 16u) != 0);
    /* invalid lengths fail closed */
    RRMP_CHECK(!ninlil_rrmp_derive_owner_scope_id(
        ep, 0u, ns, 0u, svc, 3u, 1u, pp_a, sc_a));
    RRMP_CHECK(!ninlil_rrmp_derive_owner_scope_id(
        ep, 2u, ns, 4u, svc, 3u, 1u, pp_a, sc_a));
    return 0;
}

static int test_parent_codecs_reject_semantic_corruption(void)
{
    ninlil_rrmp_id16_t parent_ids[2];
    ninlil_rrmp_digest32_t parent_digest;
    ninlil_rrmp_nps1_fields_t nps;
    ninlil_rrmp_noa1_fields_t noa;
    ninlil_rrmp_nph1_fields_t nph;
    uint8_t nps_good[NINLIL_RRMP_NPS1_BYTES];
    uint8_t nps_mut[NINLIL_RRMP_NPS1_BYTES];
    uint8_t noa_good[NINLIL_RRMP_NOA1_BYTES];
    uint8_t noa_mut[NINLIL_RRMP_NOA1_BYTES];
    uint8_t nph_good[NINLIL_RRMP_NPH1_BYTES];
    uint8_t nph_mut[NINLIL_RRMP_NPH1_BYTES];
    uint8_t npp[NINLIL_RRMP_NPP1_BYTES];
    uint8_t npa[NINLIL_RRMP_NPA1_BYTES];
    uint8_t assignment[NINLIL_RRMP_ASSIGNMENT_SLOT_BYTES];
    uint8_t state_slot[NINLIL_RRMP_ASSIGNMENT_SLOT_BYTES];
    uint8_t token_slot[NINLIL_RRMP_NPT1_SLOT_BYTES];
    uint8_t npt[NINLIL_RRMP_NPT1_BYTES];
    uint8_t token[32];
    uint8_t proof[32];
    uint8_t receipt[32];
    const uint8_t *nps_slots[NINLIL_RRMP_NPP1_SLOTS];
    const uint8_t *assignment_slots[NINLIL_RRMP_ASSIGNMENT_SLOTS_PER_PAGE];
    size_t i;

    rrmp_fill_id(parent_ids[0].bytes, 0x31u);
    rrmp_fill_id(parent_ids[1].bytes, 0x41u);
    RRMP_CHECK(ninlil_rrmp_parent_set_digest(
        parent_ids, 2u, &parent_digest));
    ninlil_rrmp_memzero(&nps, sizeof(nps));
    rrmp_fill_id(nps.owner_scope_id.bytes, 0x11u);
    rrmp_fill_id(nps.parent_set_id.bytes, 0x21u);
    nps.parent_set_revision = 1u;
    nps.parent_count = 2u;
    nps.parent_ids[0] = parent_ids[0];
    nps.parent_ids[1] = parent_ids[1];
    nps.parent_set_digest = parent_digest;
    RRMP_CHECK(ninlil_rrmp_encode_nps1(&nps, nps_good));
    RRMP_CHECK(ninlil_rrmp_validate_nps1(nps_good));

    memcpy(nps_mut, nps_good, sizeof(nps_mut));
    nps_mut[255u] = 1u; /* normative reserved tail */
    repair_page_crc(nps_mut, sizeof(nps_mut), 244u);
    RRMP_CHECK(!ninlil_rrmp_validate_nps1(nps_mut));
    memcpy(nps_mut, nps_good, sizeof(nps_mut));
    memset(nps_mut + 8u, 0, 16u); /* zero scope with repaired hashes */
    repair_nps1(nps_mut);
    RRMP_CHECK(!ninlil_rrmp_validate_nps1(nps_mut));
    memcpy(nps_mut, nps_good, sizeof(nps_mut));
    memset(nps_mut + 100u, 0, 16u); /* active parent id */
    repair_nps1(nps_mut);
    RRMP_CHECK(!ninlil_rrmp_validate_nps1(nps_mut));

    for (i = 0u; i < NINLIL_RRMP_NPP1_SLOTS; ++i) {
        nps_slots[i] = NULL;
    }
    nps_slots[0] = nps_good;
    RRMP_CHECK(ninlil_rrmp_encode_npp1(0u, 1u, nps_slots, npp));
    RRMP_CHECK(ninlil_rrmp_validate_npp1(npp));
    ninlil_rrmp_put_u16_be(npp + 6u, NINLIL_RRMP_NPP1_PAGE_COUNT);
    repair_page_crc(npp, sizeof(npp), 12u);
    RRMP_CHECK(!ninlil_rrmp_validate_npp1(npp));
    RRMP_CHECK(ninlil_rrmp_encode_npp1(0u, 1u, nps_slots, npp));
    npp[NINLIL_RRMP_NPP1_BYTES - 1u] = 1u;
    repair_page_crc(npp, sizeof(npp), 12u);
    RRMP_CHECK(!ninlil_rrmp_validate_npp1(npp));

    ninlil_rrmp_memzero(&noa, sizeof(noa));
    noa.owner_scope_id = nps.owner_scope_id;
    rrmp_fill_id(noa.authority_id.bytes, 0xA0u);
    noa.controller_term = 5u;
    noa.assignment_epoch = 1u;
    noa.assignment_revision = 1u;
    rrmp_fill_id(noa.owner_controller_id.bytes, 0xB0u);
    rrmp_fill_id(noa.owner_cell_id.bytes, 0xC0u);
    noa.direction = 1u;
    noa.e2e_context_id = 7u;
    noa.key_generation = 1u;
    rrmp_fill_id(noa.e2e_security_id.bytes, 0xD0u);
    noa.e2e_security_epoch = 1u;
    memset(noa.e2e_binding_digest.bytes, 0xE1, 32u);
    rrmp_fill_id(noa.authority_clock_epoch_id.bytes, 0x50u);
    noa.lease_not_after_authority_ms = 5000000u;
    memset(noa.handoff_token_digest.bytes, 0x77, 32u);
    noa.parent_set_digest = parent_digest;
    noa.parent_set_count = 2u;
    noa.parent_set_id = nps.parent_set_id;
    RRMP_CHECK(ninlil_rrmp_encode_noa1(&noa, noa_good));
    RRMP_CHECK(ninlil_rrmp_validate_noa1(noa_good));

    memcpy(noa_mut, noa_good, sizeof(noa_mut));
    ninlil_rrmp_put_u32_be(noa_mut + 100u, 0u);
    repair_noa1(noa_mut);
    RRMP_CHECK(!ninlil_rrmp_validate_noa1(noa_mut));
    memcpy(noa_mut, noa_good, sizeof(noa_mut));
    noa_mut[97u] = 1u;
    repair_noa1(noa_mut);
    RRMP_CHECK(!ninlil_rrmp_validate_noa1(noa_mut));
    memcpy(noa_mut, noa_good, sizeof(noa_mut));
    noa_mut[399u] = 1u;
    repair_page_crc(noa_mut, sizeof(noa_mut), 256u);
    RRMP_CHECK(!ninlil_rrmp_validate_noa1(noa_mut));

    memset(proof, 0x91, sizeof(proof));
    memset(receipt, 0x92, sizeof(receipt));
    RRMP_CHECK(ninlil_rrmp_encode_assignment_slot(
        noa_good,
        NINLIL_RRMP_HANDOFF_AUTHORITY_COMMITTED,
        proof,
        receipt,
        assignment));
    for (i = NINLIL_RRMP_HANDOFF_PREPARED_NEW;
         i <= NINLIL_RRMP_HANDOFF_OLD_RETIRED;
         ++i) {
        const uint8_t *state_proof =
            i >= NINLIL_RRMP_HANDOFF_OLD_FENCED_PROOF ? proof : NULL;
        const uint8_t *state_receipt =
            i >= NINLIL_RRMP_HANDOFF_AUTHORITY_COMMITTED ? receipt : NULL;
        RRMP_CHECK(ninlil_rrmp_encode_assignment_slot(
            noa_good, (uint8_t)i, state_proof, state_receipt, state_slot));
        memset(assignment_slots, 0, sizeof(assignment_slots));
        assignment_slots[0] = state_slot;
        RRMP_CHECK(ninlil_rrmp_encode_npa1_page(
            0u, (uint32_t)i, assignment_slots, npa));
        RRMP_CHECK(ninlil_rrmp_validate_npa1(npa));
    }
    RRMP_CHECK(!ninlil_rrmp_encode_assignment_slot(
        noa_good,
        NINLIL_RRMP_HANDOFF_PREPARED_NEW,
        proof,
        NULL,
        state_slot));
    RRMP_CHECK(!ninlil_rrmp_encode_assignment_slot(
        noa_good,
        NINLIL_RRMP_HANDOFF_OLD_FENCED_PROOF,
        proof,
        receipt,
        state_slot));
    RRMP_CHECK(!ninlil_rrmp_encode_assignment_slot(
        noa_good,
        NINLIL_RRMP_HANDOFF_NEW_OWNER_ACTIVATED,
        proof,
        NULL,
        state_slot));
    for (i = 0u; i < NINLIL_RRMP_ASSIGNMENT_SLOTS_PER_PAGE; ++i) {
        assignment_slots[i] = NULL;
    }
    assignment_slots[0] = assignment;
    RRMP_CHECK(ninlil_rrmp_encode_npa1_page(
        0u, 1u, assignment_slots, npa));
    RRMP_CHECK(ninlil_rrmp_validate_npa1(npa));
    npa[NINLIL_RRMP_NPA1_HEADER_BYTES + 400u] = 0u;
    repair_prefix_crc(npa + NINLIL_RRMP_NPA1_HEADER_BYTES, 468u);
    repair_page_crc(npa, sizeof(npa), 12u);
    RRMP_CHECK(!ninlil_rrmp_validate_npa1(npa));
    RRMP_CHECK(ninlil_rrmp_encode_npa1_page(
        0u, 1u, assignment_slots, npa));
    npa[NINLIL_RRMP_NPA1_HEADER_BYTES + 400u] =
        NINLIL_RRMP_HANDOFF_NEW_OWNER_ACTIVATED;
    memset(
        npa + NINLIL_RRMP_NPA1_HEADER_BYTES + 436u, 0, 32u);
    repair_prefix_crc(npa + NINLIL_RRMP_NPA1_HEADER_BYTES, 468u);
    repair_page_crc(npa, sizeof(npa), 12u);
    RRMP_CHECK(!ninlil_rrmp_validate_npa1(npa));
    RRMP_CHECK(ninlil_rrmp_encode_npa1_page(
        0u, 1u, assignment_slots, npa));
    npa[NINLIL_RRMP_NPA1_HEADER_BYTES + 401u] = 1u;
    repair_prefix_crc(npa + NINLIL_RRMP_NPA1_HEADER_BYTES, 468u);
    repair_page_crc(npa, sizeof(npa), 12u);
    RRMP_CHECK(!ninlil_rrmp_validate_npa1(npa));

    memset(token, 0xA5, sizeof(token));
    RRMP_CHECK(ninlil_rrmp_encode_npt1_slot(
        token, NINLIL_RRMP_NPT1_KIND_TOKEN_LIVE, 1000000u, token_slot));
    RRMP_CHECK(ninlil_rrmp_encode_npt1_page(
        0u, 1u, token_slot, 1u, npt));
    RRMP_CHECK(ninlil_rrmp_validate_npt1(npt));
    npt[NINLIL_RRMP_NPT1_HEADER_BYTES + 32u] = 3u;
    repair_prefix_crc(npt + NINLIL_RRMP_NPT1_HEADER_BYTES, 44u);
    repair_page_crc(npt, sizeof(npt), 20u);
    RRMP_CHECK(!ninlil_rrmp_validate_npt1(npt));
    RRMP_CHECK(ninlil_rrmp_encode_npt1_page(
        0u, 1u, token_slot, 1u, npt));
    npt[NINLIL_RRMP_NPT1_HEADER_BYTES + NINLIL_RRMP_NPT1_SLOT_BYTES] = 1u;
    repair_page_crc(npt, sizeof(npt), 20u);
    RRMP_CHECK(!ninlil_rrmp_validate_npt1(npt));

    ninlil_rrmp_memzero(&nph, sizeof(nph));
    nph.authority_id = noa.authority_id;
    nph.writer_controller_id = noa.owner_controller_id;
    nph.controller_term = 5u;
    nph.writer_epoch = 1u;
    nph.lease_not_after_ms = noa.lease_not_after_authority_ms;
    nph.authority_clock_epoch_id = noa.authority_clock_epoch_id;
    memset(nph.writer_proof_digest.bytes, 0x93, 32u);
    nph.header_generation = 1u;
    nph.assignment_page_bitmap = 0x00ffu;
    nph.token_page_bitmap = 0x00ffu;
    memset(nph.authority_commit_digest.bytes, 0x94, 32u);
    RRMP_CHECK(ninlil_rrmp_encode_nph1(&nph, nph_good));
    RRMP_CHECK(ninlil_rrmp_validate_nph1(nph_good));
    memcpy(nph_mut, nph_good, sizeof(nph_mut));
    nph_mut[124u] = 1u;
    repair_nph1(nph_mut);
    RRMP_CHECK(!ninlil_rrmp_validate_nph1(nph_mut));
    memcpy(nph_mut, nph_good, sizeof(nph_mut));
    memset(nph_mut + 80u, 0, 32u);
    repair_nph1(nph_mut);
    RRMP_CHECK(!ninlil_rrmp_validate_nph1(nph_mut));

    return 0;
}

int main(void)
{
    if (test_sha_kat() != 0) {
        return 1;
    }
    if (test_static_abi() != 0) {
        return 1;
    }
    if (test_precedence_matrix() != 0) {
        return 1;
    }
    if (test_codecs_semantic() != 0) {
        return 1;
    }
    if (test_owner_scope_derivation() != 0) {
        return 1;
    }
    if (test_parent_codecs_reject_semantic_corruption() != 0) {
        return 1;
    }
    printf("rrmp_codec_test OK ws=%zu\n", ninlil_rrmp_owner_workspace_bytes());
    return 0;
}
