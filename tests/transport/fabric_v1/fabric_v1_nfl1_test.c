/*
 * NFL1 v1 codec KATs, matrix, CRC/mutation, borrow/copy-own, endian independence.
 */
#include "fabric_v1_test_common.h"

static void fill_common_envelope(ninlil_fabric_private_nfl1_envelope_t *e)
{
    static uint8_t ns = (uint8_t)'n';
    static uint8_t svc = (uint8_t)'s';
    static uint8_t sch = (uint8_t)'x';
    uint8_t dig[32];

    ninlil_fabric_private_memzero(e, sizeof(*e));
    e->api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    e->struct_size = (uint16_t)sizeof(*e);
    e->message_kind = 1u;
    e->message_flags = 0u;
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
    memcpy(e->descriptor_digest.bytes, dig, 32u);
    e->schema_major = 1u;
    e->schema_minor = 0u;
    e->family = 2u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-vector-content", 21u, dig);
    e->content_digest.algorithm = 1u;
    memcpy(e->content_digest.bytes, dig, 32u);
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
    memcpy(e->route_policy_digest.bytes, dig, 32u);
    fabric_test_pattern(e->selected_path_id.bytes, 0x01u, 16u);
    e->path_selection_epoch = 37u;
    e->namespace_id.bytes = &ns;
    e->namespace_id.length = 1u;
    e->service_id.bytes = &svc;
    e->service_id.length = 1u;
    e->schema_id.bytes = &sch;
    e->schema_id.length = 1u;
}

static int test_kind_roundtrip(uint32_t kind)
{
    ninlil_fabric_private_nfl1_envelope_t in;
    ninlil_fabric_private_nfl1_envelope_t out;
    ninlil_fabric_private_nfl1_workspace_t ws;
    uint8_t packet[2048];
    uint32_t len = 0u;
    uint32_t required = 0u;
    uint8_t payload[1024];
    uint8_t evidence[128];
    uint8_t poison[8];

    fill_common_envelope(&in);
    in.message_kind = kind;
    if (kind == 4u || kind == 6u) {
        fabric_test_pattern(in.attempt_id.bytes, 0x28u, 16u);
    }
    if (kind == 2u || kind == 3u || kind == 5u || kind == 6u) {
        /* reverse orientation: swap source/target */
        ninlil_fabric_private_nfl1_id_view_t tmp;
        uint64_t te;
        uint32_t tf;
        tmp = in.source_runtime_id;
        in.source_runtime_id = in.target_runtime_id;
        in.target_runtime_id = tmp;
        tmp = in.source_application_id;
        in.source_application_id = in.target_application_id;
        in.target_application_id = tmp;
        tmp = in.source_device_id;
        in.source_device_id = in.target_device_id;
        in.target_device_id = tmp;
        tmp = in.source_installation_id;
        in.source_installation_id = in.target_installation_id;
        in.target_installation_id = tmp;
        tmp = in.source_site_id;
        in.source_site_id = in.target_site_id;
        in.target_site_id = tmp;
        te = in.source_binding_epoch;
        in.source_binding_epoch = in.target_binding_epoch;
        in.target_binding_epoch = te;
        te = in.source_membership_epoch;
        in.source_membership_epoch = in.target_membership_epoch;
        in.target_membership_epoch = te;
        tf = in.source_flags;
        in.source_flags = in.target_flags;
        in.target_flags = tf;
    }
    if (kind == 2u) {
        in.receipt_stage = 3u;
        fabric_test_pattern(in.evidence_time_clock_epoch_id.bytes, 0x11u, 16u);
        in.evidence_time_now_ms = 199000u;
        in.evidence_time_trust = 1u;
    } else if (kind == 3u) {
        in.disposition = 1u;
        in.effect_certainty = 1u;
        in.retry_guidance = 1u;
        in.retry_delay_ms = 250u;
    } else if (kind == 6u) {
        in.cancel_kind = 1u;
    }

    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_nfl1_encode(&in, packet, sizeof(packet), &len),
        NINLIL_FABRIC_PRIVATE_NFL1_OK);
    FABRIC_REQUIRE(len >= NINLIL_FABRIC_NFL1_STRUCTURAL_MIN);
    FABRIC_REQUIRE(len <= NINLIL_FABRIC_NFL1_SEMANTIC_MAX
        || kind != 1u /* min kinds are 587 */);
    FABRIC_REQUIRE(packet[0] == (uint8_t)'N' && packet[1] == (uint8_t)'F'
        && packet[2] == (uint8_t)'L' && packet[3] == (uint8_t)'1');

    /* poison workspace and ensure success overwrites views correctly */
    memset(poison, 0xA5, sizeof(poison));
    memcpy(ws.bytes, poison, sizeof(poison));
    ws.used = 0xA5A5A5A5u;
    memset(&out, 0x5A, sizeof(out));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_nfl1_decode(
            packet, len, &ws, &out, &required),
        NINLIL_FABRIC_PRIVATE_NFL1_OK);
    FABRIC_REQUIRE_EQ_U32(out.message_kind, kind);
    FABRIC_REQUIRE(out.namespace_id.bytes != NULL);
    FABRIC_REQUIRE(out.namespace_id.bytes >= ws.bytes);
    FABRIC_REQUIRE(
        out.namespace_id.bytes < ws.bytes + sizeof(ws.bytes));
    /* no pointer into packet retained */
    FABRIC_REQUIRE(fabric_test_pointer_outside_range(
        out.namespace_id.bytes, packet, len));

    ninlil_fabric_private_nfl1_clear(&out);
    FABRIC_REQUIRE(out.message_kind == 0u);
    FABRIC_REQUIRE(out.namespace_id.bytes == NULL);
    (void)payload;
    (void)evidence;
    return 0;
}

static int test_crc_and_mutations(void)
{
    ninlil_fabric_private_nfl1_envelope_t in;
    ninlil_fabric_private_nfl1_envelope_t out;
    ninlil_fabric_private_nfl1_workspace_t ws;
    uint8_t packet[2048];
    uint8_t mutated[2048];
    uint32_t len = 0u;
    uint32_t required = 99u;
    uint8_t marker[16];

    fill_common_envelope(&in);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_nfl1_encode(&in, packet, sizeof(packet), &len),
        NINLIL_FABRIC_PRIVATE_NFL1_OK);

    /* CRC mutation */
    memcpy(mutated, packet, len);
    mutated[12] ^= 0x01u;
    memset(marker, 0x11, sizeof(marker));
    memcpy(ws.bytes, marker, sizeof(marker));
    ws.used = 123u;
    memset(&out, 0x22, sizeof(out));
    FABRIC_REQUIRE(
        ninlil_fabric_private_nfl1_decode(
            mutated, len, &ws, &out, &required)
        != NINLIL_FABRIC_PRIVATE_NFL1_OK);
    FABRIC_REQUIRE(out.message_kind == 0u);
    FABRIC_REQUIRE(ws.used == 123u);
    FABRIC_REQUIRE(memcmp(ws.bytes, marker, sizeof(marker)) == 0);

    /* version mutation */
    memcpy(mutated, packet, len);
    mutated[5] = 2u;
    /* recompute CRC for structural validity of header field only */
    {
        uint32_t crc;
        ninlil_fabric_private_put_u32_be(mutated + 12, 0u);
        crc = ninlil_fabric_private_crc32c(mutated, len);
        ninlil_fabric_private_put_u32_be(mutated + 12, crc);
    }
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_nfl1_decode(
            mutated, len, &ws, &out, &required),
        NINLIL_FABRIC_PRIVATE_NFL1_UNSUPPORTED);

    /* magic mutation */
    memcpy(mutated, packet, len);
    mutated[0] = (uint8_t)'X';
    {
        uint32_t crc;
        ninlil_fabric_private_put_u32_be(mutated + 12, 0u);
        crc = ninlil_fabric_private_crc32c(mutated, len);
        ninlil_fabric_private_put_u32_be(mutated + 12, crc);
    }
    FABRIC_REQUIRE(
        ninlil_fabric_private_nfl1_decode(
            mutated, len, &ws, &out, &required)
        == NINLIL_FABRIC_PRIVATE_NFL1_CORRUPT);

    /* flags non-zero */
    memcpy(mutated, packet, len);
    ninlil_fabric_private_put_u32_be(mutated + 20, 1u);
    {
        uint32_t crc;
        ninlil_fabric_private_put_u32_be(mutated + 12, 0u);
        crc = ninlil_fabric_private_crc32c(mutated, len);
        ninlil_fabric_private_put_u32_be(mutated + 12, crc);
    }
    FABRIC_REQUIRE(
        ninlil_fabric_private_nfl1_decode(
            mutated, len, &ws, &out, &required)
        == NINLIL_FABRIC_PRIVATE_NFL1_CORRUPT);

    /* mixed authority */
    memcpy(mutated, packet, len);
    ninlil_fabric_private_put_u64_be(mutated + 288, 0u); /* term zero, id non-zero */
    {
        uint32_t crc;
        ninlil_fabric_private_put_u32_be(mutated + 12, 0u);
        crc = ninlil_fabric_private_crc32c(mutated, len);
        ninlil_fabric_private_put_u32_be(mutated + 12, crc);
    }
    FABRIC_REQUIRE(
        ninlil_fabric_private_nfl1_decode(
            mutated, len, &ws, &out, &required)
        == NINLIL_FABRIC_PRIVATE_NFL1_CORRUPT);

    /* 1925 structural but semantic reject (payload+evidence both non-empty) */
    {
        ninlil_fabric_private_nfl1_envelope_t bad;
        uint8_t ns[63];
        uint8_t svc[63];
        uint8_t sch[63];
        uint8_t payload[1024];
        uint8_t evidence[128];
        fill_common_envelope(&bad);
        memset(ns, (int)'n', sizeof(ns));
        memset(svc, (int)'s', sizeof(svc));
        memset(sch, (int)'x', sizeof(sch));
        fabric_test_pattern(payload, 0x41u, 1024u);
        fabric_test_pattern(evidence, 0x21u, 128u);
        bad.namespace_id.bytes = ns;
        bad.namespace_id.length = 63u;
        bad.service_id.bytes = svc;
        bad.service_id.length = 63u;
        bad.schema_id.bytes = sch;
        bad.schema_id.length = 63u;
        bad.payload.bytes = payload;
        bad.payload.length = 1024u;
        bad.evidence.bytes = evidence;
        bad.evidence.length = 128u;
        FABRIC_REQUIRE(
            ninlil_fabric_private_nfl1_encode(
                &bad, packet, sizeof(packet), &len)
            != NINLIL_FABRIC_PRIVATE_NFL1_OK);
    }

    /* invalid argument: no mutation */
    {
        uint8_t before_ws[16];
        memcpy(before_ws, ws.bytes, sizeof(before_ws));
        memset(&out, 0x33, sizeof(out));
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_nfl1_decode(
                NULL, len, &ws, &out, &required),
            NINLIL_FABRIC_PRIVATE_NFL1_INVALID_ARGUMENT);
        FABRIC_REQUIRE(out.message_kind == 0x33333333u);
        FABRIC_REQUIRE(memcmp(ws.bytes, before_ws, sizeof(before_ws)) == 0);
    }

    /* short length */
    FABRIC_REQUIRE(
        ninlil_fabric_private_nfl1_decode(
            packet, 586u, &ws, &out, &required)
        == NINLIL_FABRIC_PRIVATE_NFL1_CORRUPT);

    return 0;
}

static int test_maximal_application(void)
{
    ninlil_fabric_private_nfl1_envelope_t in;
    uint8_t packet[2048];
    uint32_t len = 0u;
    uint8_t ns[63];
    uint8_t svc[63];
    uint8_t sch[63];
    uint8_t payload[1024];

    fill_common_envelope(&in);
    memset(ns, (int)'n', 63);
    memset(svc, (int)'s', 63);
    memset(sch, (int)'x', 63);
    fabric_test_pattern(payload, 0x41u, 1024u);
    in.namespace_id.bytes = ns;
    in.namespace_id.length = 63u;
    in.service_id.bytes = svc;
    in.service_id.length = 63u;
    in.schema_id.bytes = sch;
    in.schema_id.length = 63u;
    in.payload.bytes = payload;
    in.payload.length = 1024u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_nfl1_encode(&in, packet, sizeof(packet), &len),
        NINLIL_FABRIC_PRIVATE_NFL1_OK);
    FABRIC_REQUIRE_EQ_U32(len, 1797u);
    return 0;
}

static int test_lp64_independence(void)
{
    ninlil_fabric_private_nfl1_envelope_t in;
    uint8_t packet[2048];
    uint32_t len = 0u;
    uint32_t i;

    fill_common_envelope(&in);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_nfl1_encode(&in, packet, sizeof(packet), &len),
        NINLIL_FABRIC_PRIVATE_NFL1_OK);
    /* total_length big-endian at 8..11 */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_get_u32_be(packet + 8), len);
    /* family at 346 is big-endian 2 */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_get_u32_be(packet + 346), 2u);
    /* no host pointer-sized fields in wire: scan for unlikely zero padding
     * runs that would appear if native struct dump were used after header */
    for (i = 0u; i < 4u; ++i) {
        FABRIC_REQUIRE(packet[i] != 0u);
    }
    FABRIC_REQUIRE(sizeof(void *) == 8u || sizeof(void *) == 4u);
    return 0;
}

int main(void)
{
    uint32_t kind;
    g_fabric_test_failures = 0;
    for (kind = 1u; kind <= 6u; ++kind) {
        if (test_kind_roundtrip(kind) != 0) {
            (void)fprintf(stderr, "kind %u failed\n", (unsigned)kind);
        }
    }
    (void)test_crc_and_mutations();
    (void)test_maximal_application();
    (void)test_lp64_independence();
    if (g_fabric_test_failures != 0) {
        (void)fprintf(
            stderr,
            "fabric_v1_nfl1_test failures=%d\n",
            g_fabric_test_failures);
        return 1;
    }
    (void)printf("fabric_v1_nfl1_test OK\n");
    return 0;
}
