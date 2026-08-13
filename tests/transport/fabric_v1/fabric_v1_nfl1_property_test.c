/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Property / light fuzz: NFL1 encode→decode for all 6 kinds (deterministic PRNG).
 * CRC bit-flip fail-closed. Private only.
 */
#include "fabric_v1_test_common.h"

static uint32_t g_rng = 0xC0FFEEu;
static uint32_t rnd(void)
{
    g_rng = g_rng * 1664525u + 1013904223u;
    return g_rng;
}

static void fill_env(ninlil_fabric_private_nfl1_envelope_t *e, uint32_t kind)
{
    static uint8_t ns = (uint8_t)'n';
    static uint8_t svc = (uint8_t)'s';
    static uint8_t sch = (uint8_t)'x';
    uint8_t dig[32];
    ninlil_fabric_private_memzero(e, sizeof(*e));
    e->api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    e->struct_size = (uint16_t)sizeof(*e);
    e->message_kind = kind;
    fabric_test_pattern(e->transaction_id.bytes, 0x10u, 16u);
    fabric_test_pattern(e->attempt_id.bytes, 0x20u, 16u);
    fabric_test_pattern(e->source_runtime_id.bytes, 0x30u, 16u);
    fabric_test_pattern(e->source_application_id.bytes, 0x40u, 16u);
    fabric_test_pattern(e->source_device_id.bytes, 0x50u, 16u);
    fabric_test_pattern(e->source_installation_id.bytes, 0x60u, 16u);
    fabric_test_pattern(e->source_site_id.bytes, 0x70u, 16u);
    e->source_binding_epoch = 7u;
    e->source_membership_epoch = 9u;
    e->source_flags = 7u;
    fabric_test_pattern(e->target_runtime_id.bytes, 0x80u, 16u);
    fabric_test_pattern(e->target_application_id.bytes, 0x90u, 16u);
    fabric_test_pattern(e->target_device_id.bytes, 0xA0u, 16u);
    fabric_test_pattern(e->target_installation_id.bytes, 0xB0u, 16u);
    fabric_test_pattern(e->target_site_id.bytes, 0xC0u, 16u);
    e->target_binding_epoch = 11u;
    e->target_membership_epoch = 13u;
    e->target_flags = 7u;
    fabric_test_pattern(e->authority_id.bytes, 0xD0u, 16u);
    e->authority_term = 17u;
    e->assignment_epoch = 19u;
    e->descriptor_revision = 23u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-vector-descriptor", 24u, dig);
    e->descriptor_digest.algorithm = 1u;
    (void)memcpy(e->descriptor_digest.bytes, dig, 32u);
    e->schema_major = 1u;
    e->schema_minor = 0u;
    e->family = 2u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-vector-content", 21u, dig);
    e->content_digest.algorithm = 1u;
    (void)memcpy(e->content_digest.bytes, dig, 32u);
    e->generation = 29u;
    fabric_test_pattern(e->deadline_clock_epoch_id.bytes, 0xA1u, 16u);
    e->absolute_effect_deadline_ms = 200000u;
    e->evidence_grace_ms = 5000u;
    e->required_evidence = 3u;
    fabric_test_pattern(e->route_policy_id.bytes, 0xF0u, 16u);
    e->route_policy_revision = 31u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-vector-route-policy", 26u, dig);
    e->route_policy_digest.algorithm = 1u;
    (void)memcpy(e->route_policy_digest.bytes, dig, 32u);
    fabric_test_pattern(e->selected_path_id.bytes, 0x01u, 16u);
    e->path_selection_epoch = 37u;
    e->namespace_id.bytes = &ns;
    e->namespace_id.length = 1u;
    e->service_id.bytes = &svc;
    e->service_id.length = 1u;
    e->schema_id.bytes = &sch;
    e->schema_id.length = 1u;
    if (kind == 2u || kind == 3u || kind == 5u || kind == 6u) {
        ninlil_id128_t tmp;
        tmp = e->source_runtime_id;
        e->source_runtime_id = e->target_runtime_id;
        e->target_runtime_id = tmp;
    }
    if (kind == 1u) {
        static uint8_t pay[16];
        uint32_t i;
        for (i = 0u; i < 8u; ++i) {
            pay[i] = (uint8_t)(rnd() & 0xffu);
        }
        e->payload.bytes = pay;
        e->payload.length = 8u;
    } else if (kind == 2u) {
        static uint8_t ev[8];
        ev[0] = (uint8_t)(rnd() & 0xffu);
        e->evidence.bytes = ev;
        e->evidence.length = 1u;
        e->receipt_stage = 1u;
        e->required_evidence = 1u;
    } else if (kind == 3u) {
        e->disposition = 1u;
        e->effect_certainty = 1u;
        e->required_evidence = 0u;
    } else if (kind == 4u) {
        e->cancel_kind = 1u;
        e->required_evidence = 0u;
    } else if (kind == 5u) {
        static uint8_t ev[4];
        e->evidence.bytes = ev;
        e->evidence.length = 0u;
        e->required_evidence = 0u;
    } else if (kind == 6u) {
        e->cancel_kind = 1u;
        e->effect_certainty = 1u;
        e->required_evidence = 0u;
    }
}

int main(void)
{
    uint32_t kind;
    uint32_t t;
    g_fabric_test_failures = 0;
    for (kind = 1u; kind <= 6u; ++kind) {
        for (t = 0u; t < 32u; ++t) {
            ninlil_fabric_private_nfl1_envelope_t in;
            ninlil_fabric_private_nfl1_envelope_t out;
            ninlil_fabric_private_nfl1_workspace_t ws;
            uint8_t packet[2048];
            uint32_t len = 0u;
            uint32_t required = 0u;
            fill_env(&in, kind);
            if (ninlil_fabric_private_nfl1_encode(
                    &in, packet, sizeof(packet), &len)
                != NINLIL_FABRIC_PRIVATE_NFL1_OK) {
                continue; /* matrix-invalid randomizations skipped */
            }
            FABRIC_REQUIRE(len >= NINLIL_FABRIC_NFL1_STRUCTURAL_MIN);
            FABRIC_REQUIRE(len <= NINLIL_FABRIC_NFL1_STRUCTURAL_MAX);
            ninlil_fabric_private_memzero(&ws, sizeof(ws));
            FABRIC_REQUIRE_EQ_U32(
                ninlil_fabric_private_nfl1_decode(
                    packet, len, &ws, &out, &required),
                NINLIL_FABRIC_PRIVATE_NFL1_OK);
            FABRIC_REQUIRE_EQ_U32(out.message_kind, kind);
        }
    }
    /* CRC bit-flip fail closed */
    {
        ninlil_fabric_private_nfl1_envelope_t in;
        ninlil_fabric_private_nfl1_envelope_t out;
        ninlil_fabric_private_nfl1_workspace_t ws;
        uint8_t packet[2048];
        uint32_t len = 0u;
        uint32_t required = 0u;
        fill_env(&in, 1u);
        if (ninlil_fabric_private_nfl1_encode(
                &in, packet, sizeof(packet), &len)
            == NINLIL_FABRIC_PRIVATE_NFL1_OK
            && len > 20u) {
            packet[20] ^= 0x01u;
            ninlil_fabric_private_memzero(&ws, sizeof(ws));
            FABRIC_REQUIRE(
                ninlil_fabric_private_nfl1_decode(
                    packet, len, &ws, &out, &required)
                != NINLIL_FABRIC_PRIVATE_NFL1_OK);
        }
    }
    if (g_fabric_test_failures != 0) {
        (void)fprintf(
            stderr, "fabric_v1_nfl1_property_test failures=%d\n",
            g_fabric_test_failures);
        return 1;
    }
    (void)printf("fabric_v1_nfl1_property_test OK\n");
    return 0;
}
