#include "v1_lab_binding.h"

#include "ninlil/fabric_v1.h"
#include "ninlil/platform.h"
#include "ninlil/version.h"

#include <stdint.h>
#include <string.h>

#define V1_LAB_IDENTITY_KNOWN_FLAGS                                        \
    (NINLIL_LOCAL_IDENTITY_HAS_DEVICE                                      \
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION                           \
        | NINLIL_LOCAL_IDENTITY_HAS_SITE)
#define V1_LAB_POLICY_CAPS                                                  \
    (NINLIL_FABRIC_CAP_SLEEP_COMPATIBLE | NINLIL_FABRIC_CAP_UNICAST        \
        | NINLIL_FABRIC_CAP_RESERVATION                                    \
        | NINLIL_FABRIC_CAP_REGULATED_RF | NINLIL_FABRIC_CAP_EVIDENCE)
#define V1_LAB_POLICY_SECURITY                                              \
    (NINLIL_FABRIC_SECURITY_INTEGRITY                                      \
        | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY                           \
        | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION                         \
        | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS)

static void v1_zero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    size_t i;
    if (p == NULL) {
        return;
    }
    for (i = 0u; i < n; ++i) {
        v[i] = 0u;
    }
}

void ninlil_v1_lab_binding_clear(ninlil_v1_lab_binding_t *binding)
{
    if (binding != NULL) {
        v1_zero(binding, sizeof(*binding));
    }
}

static void put_u16(uint8_t *out, uint16_t v)
{
    out[0] = (uint8_t)(v >> 8);
    out[1] = (uint8_t)v;
}

static void put_u32(uint8_t *out, uint32_t v)
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
}

static void put_u64(uint8_t *out, uint64_t v)
{
    size_t i;
    for (i = 0u; i < 8u; ++i) {
        out[i] = (uint8_t)(v >> (56u - (unsigned)(8u * i)));
    }
}

static uint16_t get_u16(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

static uint32_t get_u32(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static uint64_t get_u64(const uint8_t *in)
{
    uint64_t v = 0u;
    size_t i;
    for (i = 0u; i < 8u; ++i) {
        v = (v << 8) | (uint64_t)in[i];
    }
    return v;
}

static int is_zero(const uint8_t *p, size_t n)
{
    size_t i;
    uint8_t any = 0u;
    if (p == NULL) {
        return 1;
    }
    for (i = 0u; i < n; ++i) {
        any = (uint8_t)(any | p[i]);
    }
    return any == 0u;
}

static int add_ok(uintptr_t base, size_t length, uintptr_t *end)
{
    if (length > (size_t)(UINTPTR_MAX - base)) {
        return 0;
    }
    *end = base + (uintptr_t)length;
    return 1;
}

static int disjoint(
    const void *a, size_t a_length, const void *b, size_t b_length)
{
    uintptr_t ab;
    uintptr_t ae;
    uintptr_t bb;
    uintptr_t be;

    if (a_length == 0u || b_length == 0u) {
        return 1;
    }
    if (a == NULL || b == NULL) {
        return 0;
    }
    ab = (uintptr_t)a;
    bb = (uintptr_t)b;
    if (!add_ok(ab, a_length, &ae) || !add_ok(bb, b_length, &be)) {
        return 0;
    }
    return ae <= bb || be <= ab;
}

static int crypto_ok(const ninlil_r7_crypto_provider *crypto)
{
    return crypto != NULL && crypto->sha256 != NULL;
}

static int sha256(
    const ninlil_r7_crypto_provider *crypto,
    const uint8_t *p,
    size_t n,
    uint8_t out[32])
{
    return ninlil_r7_crypto_sha256(crypto, p, n, out)
            == NINLIL_R7_CRYPTO_OK
        ? 1
        : 0;
}

static int hash_join(
    const ninlil_r7_crypto_provider *crypto,
    const char *tag,
    const uint8_t *a,
    size_t an,
    const uint8_t *b,
    size_t bn,
    uint8_t out[32])
{
    uint8_t scratch[1100];
    size_t tn;
    size_t total;

    if (tag == NULL || out == NULL || (an != 0u && a == NULL)
        || (bn != 0u && b == NULL)) {
        return 0;
    }
    tn = strlen(tag);
    total = tn + an + bn;
    if (total > sizeof(scratch)) {
        return 0;
    }
    (void)memcpy(scratch, tag, tn);
    if (an != 0u) {
        (void)memcpy(scratch + tn, a, an);
    }
    if (bn != 0u) {
        (void)memcpy(scratch + tn + an, b, bn);
    }
    if (!sha256(crypto, scratch, total, out)) {
        v1_zero(scratch, total);
        return 0;
    }
    v1_zero(scratch, total);
    return 1;
}

static int endpoint_valid(const ninlil_v1_lab_endpoint_t *e)
{
    uint32_t f;
    int has_device;
    int has_installation;
    int has_site;

    if (e == NULL || is_zero(e->runtime_id, 16u)
        || is_zero(e->application_id, 16u)
        || is_zero(e->clock_epoch_id, 16u)
        || (e->clock_trust != NINLIL_CLOCK_TRUSTED
            && e->clock_trust != NINLIL_CLOCK_UNCERTAIN)) {
        return 0;
    }
    f = e->identity_flags;
    if ((f & ~V1_LAB_IDENTITY_KNOWN_FLAGS) != 0u) {
        return 0;
    }
    has_device = (f & NINLIL_LOCAL_IDENTITY_HAS_DEVICE) != 0u;
    has_installation =
        (f & NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION) != 0u;
    has_site = (f & NINLIL_LOCAL_IDENTITY_HAS_SITE) != 0u;
    return has_device && has_site
        && (is_zero(e->device_id, 16u) == !has_device)
        && (is_zero(e->installation_id, 16u) == !has_installation)
        && (is_zero(e->site_id, 16u) == !has_site)
        && ((e->binding_epoch != 0u) == (has_device || has_installation))
        && ((e->membership_epoch != 0u) == has_site);
}

static int context_id_valid(uint32_t id)
{
    return id != 0u && id != UINT32_MAX;
}

static int row_shape_valid(const ninlil_v1_lab_service_row_t *r)
{
    if (r == NULL || r->slot == 0u || r->slot > 31u
        || (r->flow != NINLIL_V1_LAB_FLOW_A_TO_B
            && r->flow != NINLIL_V1_LAB_FLOW_B_TO_A)
        || r->namespace_length == 0u
        || r->namespace_length > NINLIL_V1_LAB_TEXT_MAX
        || r->service_length == 0u
        || r->service_length > NINLIL_V1_LAB_TEXT_MAX
        || r->schema_length == 0u
        || r->schema_length > NINLIL_V1_LAB_TEXT_MAX
        || r->descriptor_revision == 0u
        || is_zero(r->descriptor_digest, 32u) || r->schema_major == 0u
        || r->traffic_class != NINLIL_FABRIC_TRAFFIC_APPLICATION) {
        return 0;
    }
    if (r->family == NINLIL_FAMILY_EVENT_FACT) {
        return r->direction == NINLIL_DIRECTION_UPLINK
            && r->evidence_grace_ms == 0u;
    }
    if (r->family == NINLIL_FAMILY_DESIRED_STATE) {
        return r->direction == NINLIL_DIRECTION_DOWNLINK;
    }
    return 0;
}

static uint8_t row_controller_side(const ninlil_v1_lab_service_row_t *r)
{
    if (r->family == NINLIL_FAMILY_DESIRED_STATE) {
        return r->flow == NINLIL_V1_LAB_FLOW_A_TO_B
            ? NINLIL_V1_LAB_SIDE_A
            : NINLIL_V1_LAB_SIDE_B;
    }
    return r->flow == NINLIL_V1_LAB_FLOW_A_TO_B
        ? NINLIL_V1_LAB_SIDE_B
        : NINLIL_V1_LAB_SIDE_A;
}

static int service_digest(
    const ninlil_r7_crypto_provider *crypto,
    const ninlil_v1_lab_service_row_t *r,
    uint8_t out[32])
{
    uint8_t c[128];
    size_t o = 0u;

    put_u16(c + o, r->namespace_length);
    o += 2u;
    (void)memcpy(c + o, r->namespace_id, r->namespace_length);
    o += r->namespace_length;
    put_u16(c + o, r->service_length);
    o += 2u;
    (void)memcpy(c + o, r->service_id, r->service_length);
    o += r->service_length;
    put_u16(c + o, r->schema_length);
    o += 2u;
    (void)memcpy(c + o, r->schema_id, r->schema_length);
    o += r->schema_length;
    put_u64(c + o, r->descriptor_revision);
    o += 8u;
    put_u16(c + o, 1u);
    o += 2u;
    (void)memcpy(c + o, r->descriptor_digest, 32u);
    o += 32u;
    put_u16(c + o, r->schema_major);
    o += 2u;
    put_u16(c + o, r->schema_minor);
    o += 2u;
    put_u32(c + o, r->family);
    o += 4u;
    if (!hash_join(
            crypto, "NINLIL-FABRIC-SERVICE-IDENTITY-V1", c, o, NULL, 0u,
            out)) {
        v1_zero(c, o);
        return 0;
    }
    v1_zero(c, o);
    return 1;
}

static int row_ids(
    const ninlil_r7_crypto_provider *crypto,
    const ninlil_v1_lab_binding_t *b,
    ninlil_v1_lab_service_row_t *r)
{
    uint8_t common[41];
    uint8_t policy_material[74];
    uint8_t digest[32];

    (void)memcpy(common, b->endpoint_a.runtime_id, 16u);
    (void)memcpy(common + 16u, b->endpoint_b.runtime_id, 16u);
    put_u64(common + 32u, b->pair_generation);
    common[40] = r->flow;
    if (!hash_join(
            crypto, "NINLIL-V1-LAB-PATH-ID", common, sizeof(common), NULL,
            0u, digest)) {
        return 0;
    }
    (void)memcpy(r->selected_path_id, digest, 16u);
    (void)memcpy(policy_material, common, sizeof(common));
    policy_material[41] = r->slot;
    (void)memcpy(policy_material + 42u, r->service_identity_digest, 32u);
    if (!hash_join(
            crypto, "NINLIL-V1-LAB-POLICY-ID", policy_material,
            sizeof(policy_material), NULL, 0u, digest)) {
        v1_zero(policy_material, sizeof(policy_material));
        return 0;
    }
    (void)memcpy(r->policy_id, digest, 16u);
    v1_zero(common, sizeof(common));
    v1_zero(policy_material, sizeof(policy_material));
    v1_zero(digest, sizeof(digest));
    return 1;
}

static int policy_digest(
    const ninlil_r7_crypto_provider *crypto,
    const ninlil_v1_lab_binding_t *b,
    const ninlil_v1_lab_service_row_t *r,
    uint8_t out[32])
{
    uint8_t p[328];

    (void)memset(p, 0, sizeof(p));
    (void)memcpy(p, r->policy_id, 16u);
    put_u64(p + 16u, b->pair_generation);
    (void)memcpy(p + 56u, r->service_identity_digest, 32u);
    put_u32(p + 88u, r->family);
    put_u32(p + 92u, NINLIL_FABRIC_POLICY_DIRECTION_FORWARD);
    put_u16(p + 96u, NINLIL_FABRIC_TRAFFIC_APPLICATION);
    put_u16(p + 98u, NINLIL_FABRIC_SCOPE_TARGET_RUNTIME);
    put_u32(p + 100u, V1_LAB_POLICY_CAPS);
    put_u32(p + 104u, V1_LAB_POLICY_SECURITY);
    put_u16(p + 108u, 0u);
    put_u16(p + 110u, 0u);
    put_u32(p + 112u, 587u);
    p[116] = NINLIL_FABRIC_AUTHORITY_MODE_BOUND_REQUIRED;
    put_u64(p + 120u, 0u);
    put_u16(p + 128u, 1u);
    (void)memcpy(p + 136u, r->selected_path_id, 16u);
    put_u16(p + 152u, 1u);
    put_u16(p + 154u, 0u);
    put_u16(p + 156u, 1u);
    put_u16(p + 158u, 0u);
    if (!hash_join(
            crypto, "NINLIL-FABRIC-POLICY-V1", p, sizeof(p), NULL, 0u,
            out)) {
        v1_zero(p, sizeof(p));
        return 0;
    }
    v1_zero(p, sizeof(p));
    return 1;
}

static ninlil_v1_lab_binding_status_t validate_and_derive_rows(
    const ninlil_r7_crypto_provider *crypto,
    ninlil_v1_lab_binding_t *b,
    int require_wire_digests)
{
    uint8_t controller = 0u;
    uint8_t i;

    if (b->service_count == 0u
        || b->service_count > NINLIL_V1_LAB_SERVICE_MAX) {
        return NINLIL_V1_LAB_BINDING_STRUCTURAL;
    }
    for (i = 0u; i < b->service_count; ++i) {
        ninlil_v1_lab_service_row_t *r = &b->services[i];
        uint8_t sid[32];
        uint8_t pd[32];
        uint8_t side;
        uint8_t j;

        if (!row_shape_valid(r)
            || (i != 0u && b->services[i - 1u].slot >= r->slot)) {
            return NINLIL_V1_LAB_BINDING_SEMANTIC;
        }
        side = row_controller_side(r);
        if (controller == 0u) {
            controller = side;
        } else if (controller != side) {
            return NINLIL_V1_LAB_BINDING_SEMANTIC;
        }
        if (!service_digest(crypto, r, sid)) {
            return NINLIL_V1_LAB_BINDING_CRYPTO;
        }
        if (require_wire_digests != 0
            && memcmp(sid, r->service_identity_digest, 32u) != 0) {
            v1_zero(sid, sizeof(sid));
            return NINLIL_V1_LAB_BINDING_DIGEST;
        }
        (void)memcpy(r->service_identity_digest, sid, 32u);
        if (!row_ids(crypto, b, r) || !policy_digest(crypto, b, r, pd)) {
            v1_zero(sid, sizeof(sid));
            return NINLIL_V1_LAB_BINDING_CRYPTO;
        }
        if (require_wire_digests != 0
            && memcmp(pd, r->path_policy_digest, 32u) != 0) {
            v1_zero(sid, sizeof(sid));
            v1_zero(pd, sizeof(pd));
            return NINLIL_V1_LAB_BINDING_DIGEST;
        }
        (void)memcpy(r->path_policy_digest, pd, 32u);
        for (j = 0u; j < i; ++j) {
            if (memcmp(
                    r->service_identity_digest,
                    b->services[j].service_identity_digest,
                    32u)
                == 0) {
                v1_zero(sid, sizeof(sid));
                v1_zero(pd, sizeof(pd));
                return NINLIL_V1_LAB_BINDING_SEMANTIC;
            }
        }
        v1_zero(sid, sizeof(sid));
        v1_zero(pd, sizeof(pd));
    }
    b->controller_side = controller;
    return NINLIL_V1_LAB_BINDING_OK;
}

static ninlil_v1_lab_binding_status_t validate_base(
    const ninlil_r7_crypto_provider *crypto,
    const ninlil_v1_lab_binding_t *b)
{
    if (!crypto_ok(crypto) || b == NULL) {
        return NINLIL_V1_LAB_BINDING_INVALID_ARGUMENT;
    }
    if (b->pair_generation == 0u || b->pair_generation > UINT32_MAX
        || !endpoint_valid(&b->endpoint_a) || !endpoint_valid(&b->endpoint_b)
        || memcmp(
               b->endpoint_a.runtime_id, b->endpoint_b.runtime_id, 16u)
            >= 0
        || memcmp(
               b->endpoint_a.clock_epoch_id,
               b->endpoint_b.clock_epoch_id,
               16u)
            != 0
        || is_zero(b->radio_site_domain_id, 16u)
        || b->radio_membership_epoch == 0u
        || !context_id_valid(b->a_to_b_hop_context_id)
        || !context_id_valid(b->a_to_b_e2e_context_id)
        || !context_id_valid(b->b_to_a_hop_context_id)
        || !context_id_valid(b->b_to_a_e2e_context_id)
        || is_zero(b->a_to_b_hop_secret, 32u)
        || is_zero(b->a_to_b_e2e_secret, 32u)
        || is_zero(b->b_to_a_hop_secret, 32u)
        || is_zero(b->b_to_a_e2e_secret, 32u)) {
        return NINLIL_V1_LAB_BINDING_STRUCTURAL;
    }
    return NINLIL_V1_LAB_BINDING_OK;
}

static void endpoint_encode(uint8_t *out, const ninlil_v1_lab_endpoint_t *e)
{
    (void)memcpy(out, e->runtime_id, 16u);
    (void)memcpy(out + 16u, e->application_id, 16u);
    (void)memcpy(out + 32u, e->device_id, 16u);
    (void)memcpy(out + 48u, e->installation_id, 16u);
    (void)memcpy(out + 64u, e->site_id, 16u);
    put_u64(out + 80u, e->binding_epoch);
    put_u64(out + 88u, e->membership_epoch);
    put_u32(out + 96u, e->identity_flags);
    (void)memcpy(out + 100u, e->clock_epoch_id, 16u);
    put_u32(out + 116u, e->clock_trust);
}

static void endpoint_decode(const uint8_t *in, ninlil_v1_lab_endpoint_t *e)
{
    (void)memcpy(e->runtime_id, in, 16u);
    (void)memcpy(e->application_id, in + 16u, 16u);
    (void)memcpy(e->device_id, in + 32u, 16u);
    (void)memcpy(e->installation_id, in + 48u, 16u);
    (void)memcpy(e->site_id, in + 64u, 16u);
    e->binding_epoch = get_u64(in + 80u);
    e->membership_epoch = get_u64(in + 88u);
    e->identity_flags = get_u32(in + 96u);
    (void)memcpy(e->clock_epoch_id, in + 100u, 16u);
    e->clock_trust = get_u32(in + 116u);
}

static size_t encoded_length(const ninlil_v1_lab_binding_t *b)
{
    size_t n = NINLIL_V1_LAB_BINDING_FIXED_BYTES;
    uint8_t i;
    for (i = 0u; i < b->service_count; ++i) {
        n += NINLIL_V1_LAB_SERVICE_FIXED_BYTES
            + b->services[i].namespace_length + b->services[i].service_length
            + b->services[i].schema_length;
    }
    return n;
}

static void encode_exact(const ninlil_v1_lab_binding_t *b, uint8_t *out)
{
    size_t o = NINLIL_V1_LAB_BINDING_FIXED_BYTES;
    uint8_t i;

    (void)memset(out, 0, encoded_length(b));
    out[0] = 1u;
    out[1] = b->service_count;
    put_u64(out + 4u, b->pair_generation);
    endpoint_encode(out + 12u, &b->endpoint_a);
    endpoint_encode(out + 132u, &b->endpoint_b);
    (void)memcpy(out + 252u, b->radio_site_domain_id, 16u);
    put_u64(out + 268u, b->radio_membership_epoch);
    put_u32(out + 276u, b->a_to_b_hop_context_id);
    put_u32(out + 280u, b->a_to_b_e2e_context_id);
    (void)memcpy(out + 284u, b->a_to_b_hop_secret, 32u);
    (void)memcpy(out + 316u, b->a_to_b_e2e_secret, 32u);
    put_u32(out + 348u, b->b_to_a_hop_context_id);
    put_u32(out + 352u, b->b_to_a_e2e_context_id);
    (void)memcpy(out + 356u, b->b_to_a_hop_secret, 32u);
    (void)memcpy(out + 388u, b->b_to_a_e2e_secret, 32u);
    for (i = 0u; i < b->service_count; ++i) {
        const ninlil_v1_lab_service_row_t *r = &b->services[i];
        out[o] = r->slot;
        out[o + 1u] = r->flow;
        out[o + 2u] = r->namespace_length;
        out[o + 3u] = r->service_length;
        out[o + 4u] = r->schema_length;
        put_u64(out + o + 6u, r->descriptor_revision);
        (void)memcpy(out + o + 14u, r->descriptor_digest, 32u);
        put_u16(out + o + 46u, r->schema_major);
        put_u16(out + o + 48u, r->schema_minor);
        put_u32(out + o + 50u, r->family);
        put_u32(out + o + 54u, r->direction);
        put_u16(out + o + 58u, r->traffic_class);
        put_u64(out + o + 62u, r->evidence_grace_ms);
        (void)memcpy(out + o + 70u, r->service_identity_digest, 32u);
        (void)memcpy(out + o + 102u, r->path_policy_digest, 32u);
        o += NINLIL_V1_LAB_SERVICE_FIXED_BYTES;
        (void)memcpy(out + o, r->namespace_id, r->namespace_length);
        o += r->namespace_length;
        (void)memcpy(out + o, r->service_id, r->service_length);
        o += r->service_length;
        (void)memcpy(out + o, r->schema_id, r->schema_length);
        o += r->schema_length;
    }
}

static int derive_binding_ids(
    const ninlil_r7_crypto_provider *crypto,
    ninlil_v1_lab_binding_t *b,
    const uint8_t *raw,
    size_t raw_length)
{
    uint8_t pair_material[64];
    uint8_t e2e_material[NINLIL_V1_LAB_BINDING_MAX_BYTES];
    size_t e = 0u;

    (void)memcpy(pair_material, b->endpoint_a.runtime_id, 16u);
    (void)memcpy(pair_material + 16u, b->endpoint_a.application_id, 16u);
    (void)memcpy(pair_material + 32u, b->endpoint_b.runtime_id, 16u);
    (void)memcpy(pair_material + 48u, b->endpoint_b.application_id, 16u);
    if (!hash_join(
            crypto, "NINLIL-V1-LAB-PAIR-ID", pair_material,
            sizeof(pair_material), NULL, 0u, b->pair_id)
        || !sha256(crypto, raw, raw_length, b->pair_binding_digest)) {
        v1_zero(pair_material, sizeof(pair_material));
        return 0;
    }
    (void)memcpy(e2e_material + e, raw, 276u);
    e += 276u;
    (void)memcpy(e2e_material + e, raw + 280u, 4u);
    e += 4u;
    (void)memcpy(e2e_material + e, raw + 352u, 4u);
    e += 4u;
    (void)memcpy(e2e_material + e, raw + 420u, raw_length - 420u);
    e += raw_length - 420u;
    if (!hash_join(
            crypto, "NINLIL-V1-LAB-E2E-ID", e2e_material, e, NULL, 0u,
            b->e2e_security_id)) {
        v1_zero(pair_material, sizeof(pair_material));
        v1_zero(e2e_material, e);
        return 0;
    }
    v1_zero(pair_material, sizeof(pair_material));
    v1_zero(e2e_material, e);
    return 1;
}

ninlil_v1_lab_binding_status_t ninlil_v1_lab_binding_finalize(
    const ninlil_r7_crypto_provider *crypto,
    ninlil_v1_lab_binding_t *binding)
{
    ninlil_v1_lab_binding_status_t st;
    size_t n;

    st = validate_base(crypto, binding);
    if (st != NINLIL_V1_LAB_BINDING_OK) {
        return st;
    }
    st = validate_and_derive_rows(crypto, binding, 0);
    if (st != NINLIL_V1_LAB_BINDING_OK) {
        return st;
    }
    n = encoded_length(binding);
    if (n < NINLIL_V1_LAB_BINDING_MIN_BYTES
        || n > NINLIL_V1_LAB_BINDING_MAX_BYTES) {
        return NINLIL_V1_LAB_BINDING_LENGTH;
    }
    encode_exact(binding, binding->raw);
    binding->raw_length = n;
    if (!derive_binding_ids(crypto, binding, binding->raw, n)) {
        return NINLIL_V1_LAB_BINDING_CRYPTO;
    }
    return NINLIL_V1_LAB_BINDING_OK;
}

ninlil_v1_lab_binding_status_t ninlil_v1_lab_binding_encode(
    const ninlil_r7_crypto_provider *crypto,
    const ninlil_v1_lab_binding_t *binding,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_length)
{
    ninlil_v1_lab_binding_t candidate;
    ninlil_v1_lab_binding_status_t st;
    size_t n;

    if (!crypto_ok(crypto) || binding == NULL || out == NULL
        || out_length == NULL) {
        return NINLIL_V1_LAB_BINDING_INVALID_ARGUMENT;
    }
    if (!disjoint(binding, sizeof(*binding), out, out_capacity)
        || !disjoint(out_length, sizeof(*out_length), out, out_capacity)) {
        return NINLIL_V1_LAB_BINDING_ALIAS;
    }
    candidate = *binding;
    st = validate_base(crypto, &candidate);
    if (st == NINLIL_V1_LAB_BINDING_OK) {
        st = validate_and_derive_rows(crypto, &candidate, 1);
    }
    if (st != NINLIL_V1_LAB_BINDING_OK) {
        *out_length = 0u;
        ninlil_v1_lab_binding_clear(&candidate);
        return st;
    }
    n = encoded_length(&candidate);
    if (n < NINLIL_V1_LAB_BINDING_MIN_BYTES
        || n > NINLIL_V1_LAB_BINDING_MAX_BYTES) {
        *out_length = 0u;
        ninlil_v1_lab_binding_clear(&candidate);
        return NINLIL_V1_LAB_BINDING_LENGTH;
    }
    if (out_capacity < n) {
        *out_length = n;
        ninlil_v1_lab_binding_clear(&candidate);
        return NINLIL_V1_LAB_BINDING_CAPACITY;
    }
    encode_exact(&candidate, out);
    *out_length = n;
    ninlil_v1_lab_binding_clear(&candidate);
    return NINLIL_V1_LAB_BINDING_OK;
}

ninlil_v1_lab_binding_status_t ninlil_v1_lab_binding_decode(
    const ninlil_r7_crypto_provider *crypto,
    const uint8_t *encoded,
    size_t encoded_length,
    ninlil_v1_lab_binding_t *out_binding)
{
    ninlil_v1_lab_binding_t b;
    ninlil_v1_lab_binding_status_t st;
    size_t o;
    uint8_t i;

    if (!crypto_ok(crypto) || encoded == NULL || out_binding == NULL) {
        return NINLIL_V1_LAB_BINDING_INVALID_ARGUMENT;
    }
    if (!disjoint(
            encoded, encoded_length, out_binding, sizeof(*out_binding))) {
        return NINLIL_V1_LAB_BINDING_ALIAS;
    }
    if (encoded_length < NINLIL_V1_LAB_BINDING_MIN_BYTES
        || encoded_length > NINLIL_V1_LAB_BINDING_MAX_BYTES) {
        return NINLIL_V1_LAB_BINDING_LENGTH;
    }
    (void)memset(&b, 0, sizeof(b));
    if (encoded[0] != 1u || encoded[1] == 0u
        || encoded[1] > NINLIL_V1_LAB_SERVICE_MAX || encoded[2] != 0u
        || encoded[3] != 0u) {
        return NINLIL_V1_LAB_BINDING_STRUCTURAL;
    }
    b.service_count = encoded[1];
    b.pair_generation = get_u64(encoded + 4u);
    endpoint_decode(encoded + 12u, &b.endpoint_a);
    endpoint_decode(encoded + 132u, &b.endpoint_b);
    (void)memcpy(b.radio_site_domain_id, encoded + 252u, 16u);
    b.radio_membership_epoch = get_u64(encoded + 268u);
    b.a_to_b_hop_context_id = get_u32(encoded + 276u);
    b.a_to_b_e2e_context_id = get_u32(encoded + 280u);
    (void)memcpy(b.a_to_b_hop_secret, encoded + 284u, 32u);
    (void)memcpy(b.a_to_b_e2e_secret, encoded + 316u, 32u);
    b.b_to_a_hop_context_id = get_u32(encoded + 348u);
    b.b_to_a_e2e_context_id = get_u32(encoded + 352u);
    (void)memcpy(b.b_to_a_hop_secret, encoded + 356u, 32u);
    (void)memcpy(b.b_to_a_e2e_secret, encoded + 388u, 32u);
    o = NINLIL_V1_LAB_BINDING_FIXED_BYTES;
    for (i = 0u; i < b.service_count; ++i) {
        ninlil_v1_lab_service_row_t *r = &b.services[i];
        size_t variable;
        if (encoded_length - o < NINLIL_V1_LAB_SERVICE_FIXED_BYTES) {
            ninlil_v1_lab_binding_clear(&b);
            return NINLIL_V1_LAB_BINDING_LENGTH;
        }
        r->slot = encoded[o];
        r->flow = encoded[o + 1u];
        r->namespace_length = encoded[o + 2u];
        r->service_length = encoded[o + 3u];
        r->schema_length = encoded[o + 4u];
        if (encoded[o + 5u] != 0u || get_u16(encoded + o + 60u) != 0u) {
            ninlil_v1_lab_binding_clear(&b);
            return NINLIL_V1_LAB_BINDING_STRUCTURAL;
        }
        variable = (size_t)r->namespace_length + r->service_length
            + r->schema_length;
        if (r->namespace_length == 0u
            || r->namespace_length > NINLIL_V1_LAB_TEXT_MAX
            || r->service_length == 0u
            || r->service_length > NINLIL_V1_LAB_TEXT_MAX
            || r->schema_length == 0u
            || r->schema_length > NINLIL_V1_LAB_TEXT_MAX
            || encoded_length - o - NINLIL_V1_LAB_SERVICE_FIXED_BYTES
                < variable) {
            ninlil_v1_lab_binding_clear(&b);
            return NINLIL_V1_LAB_BINDING_LENGTH;
        }
        r->descriptor_revision = get_u64(encoded + o + 6u);
        (void)memcpy(r->descriptor_digest, encoded + o + 14u, 32u);
        r->schema_major = get_u16(encoded + o + 46u);
        r->schema_minor = get_u16(encoded + o + 48u);
        r->family = get_u32(encoded + o + 50u);
        r->direction = get_u32(encoded + o + 54u);
        r->traffic_class = get_u16(encoded + o + 58u);
        r->evidence_grace_ms = get_u64(encoded + o + 62u);
        (void)memcpy(
            r->service_identity_digest, encoded + o + 70u, 32u);
        (void)memcpy(r->path_policy_digest, encoded + o + 102u, 32u);
        o += NINLIL_V1_LAB_SERVICE_FIXED_BYTES;
        (void)memcpy(r->namespace_id, encoded + o, r->namespace_length);
        o += r->namespace_length;
        (void)memcpy(r->service_id, encoded + o, r->service_length);
        o += r->service_length;
        (void)memcpy(r->schema_id, encoded + o, r->schema_length);
        o += r->schema_length;
    }
    if (o != encoded_length) {
        ninlil_v1_lab_binding_clear(&b);
        return NINLIL_V1_LAB_BINDING_LENGTH;
    }
    st = validate_base(crypto, &b);
    if (st == NINLIL_V1_LAB_BINDING_OK) {
        st = validate_and_derive_rows(crypto, &b, 1);
    }
    if (st != NINLIL_V1_LAB_BINDING_OK) {
        ninlil_v1_lab_binding_clear(&b);
        return st;
    }
    (void)memcpy(b.raw, encoded, encoded_length);
    b.raw_length = encoded_length;
    if (!derive_binding_ids(crypto, &b, encoded, encoded_length)) {
        ninlil_v1_lab_binding_clear(&b);
        return NINLIL_V1_LAB_BINDING_CRYPTO;
    }
    *out_binding = b;
    ninlil_v1_lab_binding_clear(&b);
    return NINLIL_V1_LAB_BINDING_OK;
}

ninlil_v1_lab_binding_status_t ninlil_v1_lab_binding_local_side(
    const ninlil_v1_lab_binding_t *binding,
    const uint8_t runtime_id[16],
    uint8_t *out_side)
{
    if (binding == NULL || runtime_id == NULL || out_side == NULL) {
        return NINLIL_V1_LAB_BINDING_INVALID_ARGUMENT;
    }
    if (memcmp(runtime_id, binding->endpoint_a.runtime_id, 16u) == 0) {
        *out_side = NINLIL_V1_LAB_SIDE_A;
        return NINLIL_V1_LAB_BINDING_OK;
    }
    if (memcmp(runtime_id, binding->endpoint_b.runtime_id, 16u) == 0) {
        *out_side = NINLIL_V1_LAB_SIDE_B;
        return NINLIL_V1_LAB_BINDING_OK;
    }
    return NINLIL_V1_LAB_BINDING_SEMANTIC;
}
