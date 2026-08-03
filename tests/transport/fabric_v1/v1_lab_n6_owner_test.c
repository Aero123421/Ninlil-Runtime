#include "n6_crypto_provider.h"
#include "n6_mem_storage.h"
#include "r7_context_binding.h"
#include "r7_crypto_openssl3.h"
#include "v1_lab_binding.h"
#include "v1_lab_n6_owner.h"

#include "ninlil/fabric_v1.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(c)                                                             \
    do {                                                                       \
        if (!(c)) {                                                            \
            (void)fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static void fill_bytes(uint8_t *out, size_t length, uint8_t seed)
{
    size_t i;
    for (i = 0u; i < length; ++i) {
        out[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static void fill_endpoint(ninlil_v1_lab_endpoint_t *endpoint, uint8_t seed)
{
    (void)memset(endpoint, 0, sizeof(*endpoint));
    fill_bytes(endpoint->runtime_id, 16u, seed);
    fill_bytes(endpoint->application_id, 16u, (uint8_t)(seed + 0x10u));
    fill_bytes(endpoint->device_id, 16u, (uint8_t)(seed + 0x20u));
    fill_bytes(endpoint->installation_id, 16u, (uint8_t)(seed + 0x30u));
    fill_bytes(endpoint->site_id, 16u, (uint8_t)(seed + 0x40u));
    endpoint->binding_epoch = 4u;
    endpoint->membership_epoch = 9u;
    endpoint->identity_flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    fill_bytes(endpoint->clock_epoch_id, 16u, (uint8_t)(seed + 0x50u));
    endpoint->clock_trust = NINLIL_CLOCK_TRUSTED;
}

static void fill_binding(
    ninlil_v1_lab_binding_t *binding, uint8_t controller_side)
{
    ninlil_v1_lab_service_row_t *row;

    (void)memset(binding, 0, sizeof(*binding));
    binding->service_count = 1u;
    binding->pair_generation = 3u;
    fill_endpoint(&binding->endpoint_a, 0x10u);
    fill_endpoint(&binding->endpoint_b, 0x30u);
    (void)memcpy(
        binding->endpoint_b.clock_epoch_id,
        binding->endpoint_a.clock_epoch_id,
        16u);
    fill_bytes(binding->radio_site_domain_id, 16u, 0x90u);
    binding->radio_membership_epoch = 11u;
    /* Fresh inbound allocator floor is one per receiver/layer namespace. */
    binding->a_to_b_hop_context_id = 1u;
    binding->a_to_b_e2e_context_id = 1u;
    binding->b_to_a_hop_context_id = 1u;
    binding->b_to_a_e2e_context_id = 1u;
    fill_bytes(binding->a_to_b_hop_secret, 32u, 0xa0u);
    fill_bytes(binding->a_to_b_e2e_secret, 32u, 0xb0u);
    fill_bytes(binding->b_to_a_hop_secret, 32u, 0xc0u);
    fill_bytes(binding->b_to_a_e2e_secret, 32u, 0xd0u);

    row = &binding->services[0];
    row->slot = 1u;
    row->flow = controller_side == NINLIL_V1_LAB_SIDE_A
        ? NINLIL_V1_LAB_FLOW_A_TO_B
        : NINLIL_V1_LAB_FLOW_B_TO_A;
    row->namespace_length = 1u;
    row->service_length = 1u;
    row->schema_length = 1u;
    row->namespace_id[0] = 'n';
    row->service_id[0] = 's';
    row->schema_id[0] = 'v';
    row->descriptor_revision = 1u;
    fill_bytes(row->descriptor_digest, 32u, 0x70u);
    row->schema_major = 1u;
    row->family = NINLIL_FAMILY_DESIRED_STATE;
    row->direction = NINLIL_DIRECTION_DOWNLINK;
    row->traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    row->evidence_grace_ms = 500u;
}

static void fill_class_d(
    ninlil_r2_authority_clock_result_t *result,
    const uint8_t clock_epoch_id[16])
{
    (void)memset(result, 0, sizeof(*result));
    result->typed_class = NINLIL_R2_SAMPLE_TRUSTED_SAME_EPOCH;
    (void)memcpy(result->sample_epoch_id, clock_epoch_id, 16u);
    result->sample_now_ms = 1000u;
    result->sample_trust = NINLIL_CLOCK_TRUSTED;
    result->sample_fields_valid = 1u;
    result->result_catalog = NINLIL_R2_SAMPLE_RESULT_CATALOG_R2_PCP;
    result->exact_status = NINLIL_PCP_OK;
}

static const ninlil_v1_lab_endpoint_t *test_endpoint(
    const ninlil_v1_lab_binding_t *binding, uint8_t side)
{
    return side == NINLIL_V1_LAB_SIDE_A ? &binding->endpoint_a
                                        : &binding->endpoint_b;
}

static uint8_t other_side(uint8_t side)
{
    return side == NINLIL_V1_LAB_SIDE_A ? NINLIL_V1_LAB_SIDE_B
                                        : NINLIL_V1_LAB_SIDE_A;
}

static int verify_context_oracle(
    ninlil_n6_t *n6,
    const ninlil_r7_crypto_provider *crypto,
    const ninlil_v1_lab_binding_t *binding,
    uint8_t local_side,
    uint8_t flow,
    uint8_t layer,
    uint32_t context_id,
    const uint8_t secret[32],
    ninlil_n6_handle_t handle)
{
    uint8_t sender_side = flow == NINLIL_V1_LAB_FLOW_A_TO_B
        ? NINLIL_V1_LAB_SIDE_A
        : NINLIL_V1_LAB_SIDE_B;
    uint8_t receiver_side = other_side(sender_side);
    uint8_t direction = sender_side == binding->controller_side
        ? NINLIL_R7_BINDING_DIR_IR
        : NINLIL_R7_BINDING_DIR_RI;
    const ninlil_v1_lab_endpoint_t *controller =
        test_endpoint(binding, binding->controller_side);
    const ninlil_v1_lab_endpoint_t *peer =
        test_endpoint(binding, other_side(binding->controller_side));
    const ninlil_v1_lab_endpoint_t *sender =
        test_endpoint(binding, sender_side);
    const ninlil_v1_lab_endpoint_t *receiver =
        test_endpoint(binding, receiver_side);
    uint8_t expected_key[16];
    uint8_t expected_iv[12];
    uint8_t digest[32];
    uint8_t lane = layer == NINLIL_N6_LAYER_HOP
        ? NINLIL_N6_LANE_HOP_DATA
        : NINLIL_N6_LANE_E2E;

    if (layer == NINLIL_N6_LAYER_HOP) {
        ninlil_r7_hop_binding_input input;
        ninlil_r7_hop_key_bundle bundle;
        (void)memset(&input, 0, sizeof(input));
        input.environment_code = NINLIL_R7_BINDING_ENV_LAB;
        input.site_domain.bytes = binding->radio_site_domain_id;
        input.site_domain.length = 16u;
        input.membership_epoch = binding->radio_membership_epoch;
        input.attachment_id.bytes = binding->pair_binding_digest;
        input.attachment_id.length = 32u;
        input.attachment_epoch = binding->pair_generation;
        input.initiator_stable_id.bytes = controller->runtime_id;
        input.initiator_stable_id.length = 16u;
        input.responder_stable_id.bytes = peer->runtime_id;
        input.responder_stable_id.length = 16u;
        input.controller_authority_id.bytes = controller->runtime_id;
        input.controller_authority_id.length = 16u;
        input.controller_term = binding->pair_generation;
        input.hop_context_id = context_id;
        input.direction_code = direction;
        REQUIRE(ninlil_r7_digest_hop_binding(crypto, &input, digest)
            == NINLIL_R7_BINDING_OK);
        REQUIRE(ninlil_r7_derive_hop_key_bundle_verified(
                    crypto, &input, digest, secret, &bundle)
            == NINLIL_R7_BINDING_OK);
        (void)memcpy(expected_key, bundle.data_key16, 16u);
        (void)memcpy(expected_iv, bundle.data_iv12, 12u);
    } else {
        ninlil_r7_e2e_binding_input input;
        ninlil_r7_e2e_key_bundle bundle;
        (void)memset(&input, 0, sizeof(input));
        input.environment_code = NINLIL_R7_BINDING_ENV_LAB;
        input.site_domain.bytes = binding->radio_site_domain_id;
        input.site_domain.length = 16u;
        input.membership_epoch = binding->radio_membership_epoch;
        input.e2e_security_id.bytes = binding->e2e_security_id;
        input.e2e_security_id.length = 32u;
        input.e2e_security_epoch = binding->pair_generation;
        input.sender_stable_id.bytes = sender->runtime_id;
        input.sender_stable_id.length = 16u;
        input.receiver_stable_id.bytes = receiver->runtime_id;
        input.receiver_stable_id.length = 16u;
        input.authority_id.bytes = controller->runtime_id;
        input.authority_id.length = 16u;
        input.authority_term = binding->pair_generation;
        input.e2e_context_id = context_id;
        input.direction_code = direction;
        REQUIRE(ninlil_r7_digest_e2e_binding(crypto, &input, digest)
            == NINLIL_R7_BINDING_OK);
        REQUIRE(ninlil_r7_derive_e2e_key_bundle_verified(
                    crypto, &input, digest, secret, &bundle)
            == NINLIL_R7_BINDING_OK);
        (void)memcpy(expected_key, bundle.key16, 16u);
        (void)memcpy(expected_iv, bundle.iv12, 12u);
    }

    if (local_side == receiver_side) {
        ninlil_n6_rx_ticket_t ticket;
        REQUIRE(ninlil_n6_rx_precheck(n6, handle, lane, 1u, &ticket)
            == NINLIL_N6_OK);
        REQUIRE(ticket.layer_code == layer
            && ticket.direction_code == direction
            && ticket.context_id == context_id && ticket.lane_kind == lane);
        REQUIRE(memcmp(ticket.key16, expected_key, 16u) == 0);
        REQUIRE(memcmp(ticket.iv12, expected_iv, 12u) == 0);
        REQUIRE(ninlil_n6_rx_abort(n6, &ticket) == NINLIL_N6_OK);
    } else {
        ninlil_n6_tx_lease_t lease;
        REQUIRE(ninlil_n6_tx_burn(n6, handle, lane, &lease)
            == NINLIL_N6_OK);
        REQUIRE(lease.layer_code == layer
            && lease.direction_code == direction
            && lease.context_id == context_id && lease.lane_kind == lane);
        REQUIRE(memcmp(lease.key16, expected_key, 16u) == 0);
        REQUIRE(memcmp(lease.iv12, expected_iv, 12u) == 0);
        REQUIRE(ninlil_n6_tx_lease_release(n6, &lease) == NINLIL_N6_OK);
    }
    return 0;
}

static int verify_all_contexts(
    ninlil_n6_t *n6,
    const ninlil_r7_crypto_provider *crypto,
    const ninlil_v1_lab_binding_t *binding,
    uint8_t local_side,
    const ninlil_v1_lab_n6_handles_t *handles)
{
    REQUIRE(verify_context_oracle(n6, crypto, binding, local_side,
                NINLIL_V1_LAB_FLOW_A_TO_B, NINLIL_N6_LAYER_HOP,
                binding->a_to_b_hop_context_id, binding->a_to_b_hop_secret,
                handles->a_to_b_hop)
        == 0);
    REQUIRE(verify_context_oracle(n6, crypto, binding, local_side,
                NINLIL_V1_LAB_FLOW_A_TO_B, NINLIL_N6_LAYER_E2E,
                binding->a_to_b_e2e_context_id, binding->a_to_b_e2e_secret,
                handles->a_to_b_e2e)
        == 0);
    REQUIRE(verify_context_oracle(n6, crypto, binding, local_side,
                NINLIL_V1_LAB_FLOW_B_TO_A, NINLIL_N6_LAYER_HOP,
                binding->b_to_a_hop_context_id, binding->b_to_a_hop_secret,
                handles->b_to_a_hop)
        == 0);
    REQUIRE(verify_context_oracle(n6, crypto, binding, local_side,
                NINLIL_V1_LAB_FLOW_B_TO_A, NINLIL_N6_LAYER_E2E,
                binding->b_to_a_e2e_context_id, binding->b_to_a_e2e_secret,
                handles->b_to_a_e2e)
        == 0);
    return 0;
}

static int run_successful_side(
    const ninlil_r7_crypto_provider *r7_crypto,
    const ninlil_v1_lab_binding_t *binding,
    uint8_t side)
{
    static uint8_t object[NINLIL_N6_OBJECT_BYTES]
        __attribute__((aligned(NINLIL_N6_OBJECT_ALIGN)));
    static uint8_t pool_bytes[4096u];
    ninlil_n6_context_pool_t pool;
    ninlil_n6_t *n6 = NULL;
    ninlil_v1_lab_n6_owner_t owner;
    ninlil_v1_lab_n6_handles_t handles;
    ninlil_r2_authority_clock_result_t sample;
    const ninlil_v1_lab_endpoint_t *local = side == NINLIL_V1_LAB_SIDE_A
        ? &binding->endpoint_a
        : &binding->endpoint_b;

    (void)memset(object, 0, sizeof(object));
    (void)memset(pool_bytes, 0, sizeof(pool_bytes));
    n6_mem_storage_reset();
    pool.max_slots = 8u;
    pool.reserved_zero = 0u;
    pool.bytes = pool_bytes;
    pool.bytes_size = ninlil_n6_context_pool_bytes(pool.max_slots);
    REQUIRE(pool.bytes_size <= sizeof(pool_bytes));
    REQUIRE(ninlil_n6_init(object, sizeof(object), &pool, &n6)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_v1_lab_n6_owner_init(&owner, n6,
                n6_mem_storage_ops(), ninlil_n6_crypto_host_ops(), r7_crypto,
                local->runtime_id)
        == NINLIL_N6_OK);

    fill_class_d(&sample, local->clock_epoch_id);
    sample.sample_fields_valid = 0u;
    REQUIRE(ninlil_v1_lab_n6_owner_boot_from_class_d(&owner, &sample)
        == NINLIL_N6_M4_REQUIRED);
    REQUIRE(ninlil_v1_lab_n6_owner_is_fenced(&owner) == 0);
    fill_class_d(&sample, local->clock_epoch_id);
    REQUIRE(ninlil_v1_lab_n6_owner_boot_from_class_d(&owner, &sample)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_v1_lab_n6_owner_install_pair(
                &owner, binding->raw, binding->raw_length, &handles)
        == NINLIL_N6_OK);
    REQUIRE(handles.a_to_b_hop != 0u && handles.a_to_b_e2e != 0u
        && handles.b_to_a_hop != 0u && handles.b_to_a_e2e != 0u);
    REQUIRE(owner.last_install_count == 4u);
    REQUIRE(ninlil_v1_lab_n6_owner_is_fenced(&owner) == 0);
    REQUIRE(verify_all_contexts(
                n6, r7_crypto, binding, side, &handles)
        == 0);
    ninlil_v1_lab_n6_owner_clear(&owner);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_SHUTDOWN);
    return 0;
}

static int test_failure_invalidates_prior_handles(
    const ninlil_r7_crypto_provider *r7_crypto, int commit_unknown)
{
    static uint8_t object[NINLIL_N6_OBJECT_BYTES]
        __attribute__((aligned(NINLIL_N6_OBJECT_ALIGN)));
    static uint8_t pool_bytes[4096u];
    ninlil_n6_context_pool_t pool;
    ninlil_n6_t *n6 = NULL;
    ninlil_v1_lab_n6_owner_t owner;
    ninlil_v1_lab_n6_handles_t first_handles;
    ninlil_v1_lab_n6_handles_t second_handles;
    ninlil_v1_lab_binding_t first;
    ninlil_v1_lab_binding_t second;
    ninlil_r2_authority_clock_result_t sample;
    ninlil_n6_tx_lease_t lease;
    ninlil_n6_status_t expected;

    fill_binding(&first, NINLIL_V1_LAB_SIDE_A);
    REQUIRE(ninlil_v1_lab_binding_finalize(r7_crypto, &first)
        == NINLIL_V1_LAB_BINDING_OK);
    fill_binding(&second, NINLIL_V1_LAB_SIDE_A);
    fill_endpoint(&second.endpoint_b, 0x50u);
    (void)memcpy(
        second.endpoint_b.clock_epoch_id,
        second.endpoint_a.clock_epoch_id,
        16u);
    second.pair_generation = 4u;
    second.b_to_a_hop_context_id = 2u;
    second.b_to_a_e2e_context_id = 2u;
    fill_bytes(second.a_to_b_hop_secret, 32u, 0x21u);
    fill_bytes(second.a_to_b_e2e_secret, 32u, 0x41u);
    fill_bytes(second.b_to_a_hop_secret, 32u, 0x61u);
    fill_bytes(second.b_to_a_e2e_secret, 32u, 0x81u);
    if (commit_unknown == 0) {
        second.b_to_a_hop_context_id = 3u;
    }
    REQUIRE(ninlil_v1_lab_binding_finalize(r7_crypto, &second)
        == NINLIL_V1_LAB_BINDING_OK);
    (void)memset(object, 0, sizeof(object));
    (void)memset(pool_bytes, 0, sizeof(pool_bytes));
    n6_mem_storage_reset();
    pool.max_slots = 8u;
    pool.reserved_zero = 0u;
    pool.bytes = pool_bytes;
    pool.bytes_size = ninlil_n6_context_pool_bytes(pool.max_slots);
    REQUIRE(ninlil_n6_init(object, sizeof(object), &pool, &n6)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_v1_lab_n6_owner_init(&owner, n6,
                n6_mem_storage_ops(), ninlil_n6_crypto_host_ops(), r7_crypto,
                first.endpoint_a.runtime_id)
        == NINLIL_N6_OK);
    fill_class_d(&sample, first.endpoint_a.clock_epoch_id);
    REQUIRE(ninlil_v1_lab_n6_owner_boot_from_class_d(&owner, &sample)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_v1_lab_n6_owner_install_pair(
                &owner, first.raw, first.raw_length, &first_handles)
        == NINLIL_N6_OK);
    REQUIRE(first_handles.a_to_b_hop != 0u);

    if (commit_unknown != 0) {
        n6_mem_storage_inject_cu(N6_MEM_CU_ALL_OLD);
        expected = NINLIL_N6_COMMIT_UNKNOWN;
    } else {
        expected = NINLIL_N6_INVALID_ARGUMENT;
    }
    (void)memset(&second_handles, 0xa5, sizeof(second_handles));
    REQUIRE(ninlil_v1_lab_n6_owner_install_pair(
                &owner, second.raw, second.raw_length, &second_handles)
        == expected);
    REQUIRE(memcmp(&second_handles, &(ninlil_v1_lab_n6_handles_t){0},
                sizeof(second_handles))
        == 0);
    REQUIRE(owner.last_install_count == (commit_unknown != 0 ? 0u : 2u));
    REQUIRE(ninlil_v1_lab_n6_owner_is_fenced(&owner) == 1);
    (void)memset(&lease, 0xa5, sizeof(lease));
    REQUIRE(ninlil_n6_tx_burn(n6, first_handles.a_to_b_hop,
                NINLIL_N6_LANE_HOP_DATA, &lease)
        == NINLIL_N6_SHUTDOWN);
    REQUIRE(ninlil_n6_state(n6) == NINLIL_N6_STATE_SHUTDOWN);
    REQUIRE(ninlil_v1_lab_n6_owner_install_pair(
                &owner, second.raw, second.raw_length, &second_handles)
        == NINLIL_N6_FENCED);
    ninlil_v1_lab_n6_owner_clear(&owner);
    ninlil_v1_lab_binding_clear(&first);
    ninlil_v1_lab_binding_clear(&second);
    return 0;
}

int main(void)
{
    ninlil_r7_crypto_provider r7_crypto;
    ninlil_v1_lab_binding_t binding;

    REQUIRE(ninlil_r7_crypto_openssl3_provider_init(&r7_crypto)
        == NINLIL_R7_CRYPTO_OK);
    fill_binding(&binding, NINLIL_V1_LAB_SIDE_A);
    REQUIRE(ninlil_v1_lab_binding_finalize(&r7_crypto, &binding)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(run_successful_side(
                &r7_crypto, &binding, NINLIL_V1_LAB_SIDE_A)
        == 0);
    REQUIRE(run_successful_side(
                &r7_crypto, &binding, NINLIL_V1_LAB_SIDE_B)
        == 0);
    ninlil_v1_lab_binding_clear(&binding);
    fill_binding(&binding, NINLIL_V1_LAB_SIDE_B);
    REQUIRE(ninlil_v1_lab_binding_finalize(&r7_crypto, &binding)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(binding.controller_side == NINLIL_V1_LAB_SIDE_B);
    REQUIRE(run_successful_side(
                &r7_crypto, &binding, NINLIL_V1_LAB_SIDE_A)
        == 0);
    REQUIRE(run_successful_side(
                &r7_crypto, &binding, NINLIL_V1_LAB_SIDE_B)
        == 0);
    REQUIRE(test_failure_invalidates_prior_handles(&r7_crypto, 0) == 0);
    REQUIRE(test_failure_invalidates_prior_handles(&r7_crypto, 1) == 0);
    ninlil_v1_lab_binding_clear(&binding);
    (void)fprintf(stdout, "v1_lab_n6_owner_test OK\n");
    return 0;
}
