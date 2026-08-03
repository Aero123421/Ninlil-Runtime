/*
 * Adversarial external-consumer forge probe for M4 evidence.
 *
 * Public header only. Includes the exact fresh-process first-slot synthetic
 * counterexample (magic/slot/gen/epoch without owner-minted cap_id).
 * Independent probe must fail closed: forged_ready=DENIED.
 */
#include "wifi_attachment_m4.h"

#include <stdio.h>
#include <string.h>

static int failures;
#define CHECK(c)                                                                \
    do {                                                                        \
        if (!(c)) {                                                             \
            (void)fprintf(                                                      \
                stderr, "FORGE_PROBE FAIL %s:%d\n", __FILE__, __LINE__);        \
            failures += 1;                                                      \
        }                                                                       \
    } while (0)

static void expect_denied(const ninlil_wifi_m4_full_evidence_t *ev)
{
    ninlil_wifi_m4_attach_material_t mat;
    ninlil_wifi_status_t st = ninlil_wifi_m4_evidence_ready_for_attach(ev);
    CHECK(st == NINLIL_WIFI_DENIED);
    CHECK(st != NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_m4_evidence_export_attach_material(ev, &mat)
        == NINLIL_WIFI_DENIED);
    CHECK(ninlil_wifi_m4_evidence_membership_live(ev) == 0);
}

/*
 * Exact first-slot synthetic counterexample for a fresh owner epoch:
 * constant magic + slot 0 + generation 1 + owner_epoch 1 + zero/guessed
 * cap_id. Without a subsystem-minted 128-bit cap_id this must DENY even
 * before any legitimate object is copied.
 */
static void synthesize_first_slot_handle(
    ninlil_wifi_m4_full_evidence_t *out,
    uint64_t generation,
    uint64_t owner_epoch,
    const uint8_t cap_id[16])
{
    /* Little-endian packing matching private m4_handle layout. */
    uint8_t *p;
    uint32_t magic = 0x4d34484cu; /* guessed 'M4HL' */
    uint32_t slot = 0u;
    (void)memset(out, 0, sizeof(*out));
    p = out->opaque;
    p[0] = (uint8_t)(magic);
    p[1] = (uint8_t)(magic >> 8);
    p[2] = (uint8_t)(magic >> 16);
    p[3] = (uint8_t)(magic >> 24);
    p[4] = (uint8_t)(slot);
    p[5] = (uint8_t)(slot >> 8);
    p[6] = (uint8_t)(slot >> 16);
    p[7] = (uint8_t)(slot >> 24);
    p[8] = (uint8_t)(generation);
    p[9] = (uint8_t)(generation >> 8);
    p[10] = (uint8_t)(generation >> 16);
    p[11] = (uint8_t)(generation >> 24);
    p[12] = (uint8_t)(generation >> 32);
    p[13] = (uint8_t)(generation >> 40);
    p[14] = (uint8_t)(generation >> 48);
    p[15] = (uint8_t)(generation >> 56);
    p[16] = (uint8_t)(owner_epoch);
    p[17] = (uint8_t)(owner_epoch >> 8);
    p[18] = (uint8_t)(owner_epoch >> 16);
    p[19] = (uint8_t)(owner_epoch >> 24);
    p[20] = (uint8_t)(owner_epoch >> 32);
    p[21] = (uint8_t)(owner_epoch >> 40);
    p[22] = (uint8_t)(owner_epoch >> 48);
    p[23] = (uint8_t)(owner_epoch >> 56);
    if (cap_id != NULL) {
        (void)memcpy(p + 24, cap_id, 16u);
    }
}

int main(void)
{
    ninlil_wifi_m4_owner_t m4_owner;
    ninlil_wifi_m4_owner_init(&m4_owner);

    ninlil_wifi_m4_full_evidence_t forged;
    ninlil_wifi_m4_full_evidence_t real;
    ninlil_wifi_m4_fabric_registry_t reg;
    uint8_t zero_cap[16];
    uint8_t ones_cap[16];
    uint8_t auth[16];
    uint8_t fab[32];
    uint8_t epoch[16];
    uint32_t patterns[] = {
        0x4d34484cu, 0x4d344556u, 0xffffffffu, 0x00000001u, 0x03030303u
    };
    size_t pi;
    size_t off;
    failures = 0;

    (void)memset(zero_cap, 0, sizeof(zero_cap));
    (void)memset(ones_cap, 0xff, sizeof(ones_cap));
    (void)memset(auth, 0xd0, sizeof(auth));
    (void)memset(fab, 0xf1, sizeof(fab));
    (void)memset(epoch, 0xe1, sizeof(epoch));

    /*
     * Fresh-process / fresh-owner first-slot synthetic BEFORE any mint.
     * Predictable counters alone must not grant readiness.
     */
    CHECK(ninlil_wifi_m4_owner_restart(&m4_owner) == NINLIL_WIFI_OK);
    synthesize_first_slot_handle(&forged, 1u, 1u, zero_cap);
    expect_denied(&forged);
    synthesize_first_slot_handle(&forged, 1u, 1u, ones_cap);
    expect_denied(&forged);
    synthesize_first_slot_handle(&forged, 1u, 1u, NULL);
    expect_denied(&forged);

    /* all-0 / all-FF */
    (void)memset(&forged, 0, sizeof(forged));
    expect_denied(&forged);
    (void)memset(forged.opaque, 0xff, sizeof(forged.opaque));
    expect_denied(&forged);

    /* Pattern fills */
    for (pi = 0u; pi < sizeof(patterns) / sizeof(patterns[0]); ++pi) {
        uint32_t tok = patterns[pi];
        (void)memset(&forged, 0, sizeof(forged));
        for (off = 0u; off + 4u <= sizeof(forged.opaque); off += 4u) {
            forged.opaque[off] = (uint8_t)(tok);
            forged.opaque[off + 1u] = (uint8_t)(tok >> 8);
            forged.opaque[off + 2u] = (uint8_t)(tok >> 16);
            forged.opaque[off + 3u] = (uint8_t)(tok >> 24);
        }
        expect_denied(&forged);
    }

    /* Empty mint is not ready; synthetic first-slot still DENIED after mint. */
    CHECK(ninlil_wifi_m4_evidence_reset(&m4_owner, &real) == NINLIL_WIFI_OK);
    expect_denied(&real);
    synthesize_first_slot_handle(&forged, 1u, 1u, zero_cap);
    expect_denied(&forged);
    synthesize_first_slot_handle(&forged, 1u, 2u, zero_cap);
    expect_denied(&forged);

    /*
     * After real mint, bit-identical alias is intended; synthetic with
     * zero/ones cap_id but matching counters is not.
     */
    {
        ninlil_wifi_m4_full_evidence_t alias;
        alias = real;
        /* real is empty-live (not ready) but is a valid alias handle */
        CHECK(ninlil_wifi_m4_evidence_class_membership(&alias)
            == NINLIL_WIFI_M4_CLASS_MISSING);
        synthesize_first_slot_handle(&forged, 1u, 1u, zero_cap);
        expect_denied(&forged);
        /* Mutate only presumed cap_id region of a real handle → DENIED. */
        forged = real;
        forged.opaque[24] ^= 0x01u;
        expect_denied(&forged);
        ninlil_wifi_m4_evidence_consume(&real);
        expect_denied(&alias);
    }

    /* Fabric bind alone cannot mint readiness. */
    (void)memset(&forged, 0, sizeof(forged));
    synthesize_first_slot_handle(&forged, 1u, 1u, ones_cap);
    CHECK(ninlil_wifi_m4_fabric_registry_bind(&reg, fab, auth, epoch)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_m4_evidence_apply_fabric_registry(&forged, &reg)
        == NINLIL_WIFI_DENIED);
    expect_denied(&forged);

    /* Restart: stale synthetic and stale real handles fail. */
    CHECK(ninlil_wifi_m4_evidence_reset(&m4_owner, &real) == NINLIL_WIFI_OK);
    {
        ninlil_wifi_m4_full_evidence_t stale = real;
        CHECK(ninlil_wifi_m4_owner_restart(&m4_owner) == NINLIL_WIFI_OK);
        expect_denied(&real);
        expect_denied(&stale);
        synthesize_first_slot_handle(&forged, 1u, 1u, zero_cap);
        expect_denied(&forged);
        /* Fresh epoch after restart still rejects synthetic without cap_id. */
        synthesize_first_slot_handle(&forged, 1u, 2u, zero_cap);
        expect_denied(&forged);
        synthesize_first_slot_handle(&forged, 1u, 2u, ones_cap);
        expect_denied(&forged);
    }

    if (failures != 0) {
        (void)fprintf(
            stderr, "wifi_v1_m4_forge_probe_test: FAIL failures=%d\n", failures);
        return 1;
    }
    (void)printf(
        "wifi_v1_m4_forge_probe_test: PASS forged_ready=DENIED (closed)\n");
    return 0;
}
