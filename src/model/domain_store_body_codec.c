#include "domain_store_body_codec.h"
#include "domain_store_codec_internal.h"

#include <ninlil/version.h>
#include <string.h>

/*
 * D1-B1 + D1-B2 + D1-B3a body codec. Boundary notes for later milestones:
 * - D2: bounded recovery scan, row budget, workspace state machine.
 * - D3: cross-row primary/index/backlink, ATTEMPT_REUSE_FENCE vs CLEANUP_PLAN
 *   active_plan_count equality, HEAD_INDEX member get/value mutual proof,
 *   family 3/4 capacity/counter mutual recompute, live SERVICE_QUOTA active
 *   counts from TRANSACTION RESERVATION contributions, primary_value_digest
 *   exact get of live primary complete value; SCHEDULER_OWNER 1:1 cardinality,
 *   counter/cursor upper bound, ready semantics, ingress→delivery owner
 *   transfer (same-record codec alone does not prove these).
 * - D4: COMMIT_UNKNOWN old/new complete-value digest convergence.
 */

static const char PREIMAGE_INVARIANT[] = "NINLIL-DOMAIN-INVARIANT-V1";

static const uint8_t KEY_ROOT[8] = {
    0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x01u
};

/* Presence flags: same bits for local_identity and concrete target (docs12). */
#define PRESENCE_DEVICE ((uint32_t)1u << 0)
#define PRESENCE_INSTALLATION ((uint32_t)1u << 1)
#define PRESENCE_SITE ((uint32_t)1u << 2)
#define PRESENCE_ALLOWED (PRESENCE_DEVICE | PRESENCE_INSTALLATION | PRESENCE_SITE)

static int range_address_is_valid(const void *pointer, size_t length)
{
    uintptr_t start;
    if (length == 0u) {
        return 1;
    }
    if (pointer == NULL) {
        return 0;
    }
    start = (uintptr_t)pointer;
    return length <= UINTPTR_MAX - start;
}

static int multi_ranges_ok(const void *const *ptrs, const size_t *lens, size_t n)
{
    size_t i;
    size_t j;
    for (i = 0u; i < n; ++i) {
        if (!range_address_is_valid(ptrs[i], lens[i])) {
            return 0;
        }
        for (j = i + 1u; j < n; ++j) {
            if (!ninlil_model_domain_ranges_are_disjoint(
                    ptrs[i], lens[i], ptrs[j], lens[j])) {
                return 0;
            }
        }
    }
    return 1;
}

static int encode_alias_ok(
    const void *input,
    size_t input_size,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    return ninlil_model_domain_encode_ranges_are_disjoint(
        input, input_size, out_bytes, capacity, out_length);
}

/*
 * Variable-length encode gate: validate the body object range first without
 * dereferencing nested fields. Returns 1 only when body is NULL or its full
 * object range is address-valid. Nested RAW16 ranges are gathered only after
 * this succeeds.
 */
static int encode_body_object_range_ok(const void *body, size_t body_size)
{
    if (body == NULL) {
        return 1;
    }
    return range_address_is_valid(body, body_size);
}

/*
 * Decode body range gate for all D1-B1/D1-B2 body decode APIs.
 * Independently validates the output object range and any nonzero encoded
 * range, then pairwise disjointness. Does not mutate any range.
 *
 * Returns 0 → caller must return INVALID_ARGUMENT with output untouched
 *   (NULL out, address overflow of out/encoded, or encoded↔out alias).
 * Returns 1 → ranges are admissible; caller may zero out and continue.
 *
 * Shape defects such as (NULL, nonzero length) are not address overflow;
 * they are reported after zeroing as CORRUPT by the decode body.
 */
static int decode_body_ranges_ok(
    ninlil_bytes_view_t encoded,
    const void *out_body,
    size_t out_size)
{
    if (out_body == NULL || !range_address_is_valid(out_body, out_size)) {
        return 0;
    }
    if (encoded.data != NULL && encoded.length != 0u) {
        if (!range_address_is_valid(encoded.data, encoded.length)) {
            return 0;
        }
        if (!ninlil_model_domain_ranges_are_disjoint(
                encoded.data, encoded.length, out_body, out_size)) {
            return 0;
        }
    }
    return 1;
}

static int checked_add_u32(uint32_t a, uint32_t b, uint32_t *out)
{
    if (a > UINT32_MAX - b) {
        return 0;
    }
    *out = a + b;
    return 1;
}

static int id_is_zero(const uint8_t id[NINLIL_MODEL_DOMAIN_ID_BYTES])
{
    return ninlil_model_domain_id_is_zero(id);
}

static int digest_is_zero(const uint8_t d[NINLIL_MODEL_DOMAIN_DIGEST_BYTES])
{
    return ninlil_model_domain_digest_is_zero(d);
}

static int digest_is_nonzero(const uint8_t d[NINLIL_MODEL_DOMAIN_DIGEST_BYTES])
{
    return !digest_is_zero(d);
}

static int ascii_lower_or_digit(uint8_t value)
{
    return (value >= (uint8_t)'a' && value <= (uint8_t)'z')
        || (value >= (uint8_t)'0' && value <= (uint8_t)'9');
}

/* --- subject / family34 / reason helpers (D1-B1) --- */

int ninlil_model_domain_invariant_subject_kind_is_valid(uint16_t subject_kind)
{
    uint8_t subtype;
    if (subject_kind == NINLIL_MODEL_DOMAIN_SUBJECT_KIND_NAMESPACE
        || subject_kind == NINLIL_MODEL_DOMAIN_SUBJECT_KIND_FAMILY3
        || subject_kind == NINLIL_MODEL_DOMAIN_SUBJECT_KIND_FAMILY4) {
        return 1;
    }
    if ((subject_kind & 0xff00u) != NINLIL_MODEL_DOMAIN_SUBJECT_KIND_FAMILY6_BASE) {
        return 0;
    }
    subtype = (uint8_t)(subject_kind & 0x00ffu);
    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER) {
        return 0;
    }
    return ninlil_model_domain_subtype_is_known(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN, subtype);
}

int ninlil_model_domain_family34_member_key_is_valid(ninlil_bytes_view_t member_key)
{
    if (!ninlil_model_domain_bytes_view_shape_is_valid(member_key)
        || member_key.length != NINLIL_MODEL_DOMAIN_HEAD_INDEX_MEMBER_KEY_BYTES
        || member_key.data == NULL) {
        return 0;
    }
    if (memcmp(member_key.data, KEY_ROOT, 8u) != 0) {
        return 0;
    }
    if (member_key.data[8] == 0x03u) {
        return member_key.data[9] >= 0x01u && member_key.data[9] <= 0x04u;
    }
    if (member_key.data[8] == 0x04u) {
        return member_key.data[9] >= 0x01u && member_key.data[9] <= 0x0bu;
    }
    return 0;
}

int ninlil_model_domain_reason_is_known_public(uint32_t reason)
{
    if (reason == 0u) {
        return 1;
    }
    if (reason >= 1u && reason <= 24u) {
        return 1;
    }
    if (reason >= 64u && reason <= 66u) {
        return 1;
    }
    if (reason >= 68u && reason <= 86u) {
        return 1;
    }
    if (reason >= 128u && reason <= 132u) {
        return 1;
    }
    if (reason == 4096u || reason == 4097u) {
        return 1;
    }
    return 0;
}

static int evidence_stage_is_known(uint32_t stage)
{
    return stage <= NINLIL_EVIDENCE_VERIFIED;
}

static int evidence_mask_is_valid(uint32_t mask)
{
    uint32_t allowed = NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_DURABLY_RECORDED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_VERIFIED);
    return mask != 0u && (mask & ~allowed) == 0u;
}

static int txn_state_is_known(uint32_t state)
{
    return state >= NINLIL_TXN_READY && state <= NINLIL_TXN_WAITING_WINDOW;
}

static int outcome_is_known(uint32_t outcome)
{
    return outcome <= NINLIL_OUTCOME_SUPERSEDED_RESERVED;
}

static int deadline_verdict_is_known(uint32_t v)
{
    return v <= NINLIL_DEADLINE_NOT_APPLICABLE;
}

static int park_cause_is_known(uint32_t c)
{
    return c <= NINLIL_EVENT_PARK_CAUSE_COUNTER_EXHAUSTED;
}

static int family_is_m1a(uint32_t family)
{
    return family == NINLIL_FAMILY_EVENT_FACT
        || family == NINLIL_FAMILY_DESIRED_STATE;
}

/* --- reusable TEXT_ID / PARTY / TARGET / SERVICE_IDENTITY / RESOURCE --- */

uint32_t ninlil_model_domain_text_id_encoded_length(
    const ninlil_model_domain_text_id_t *text)
{
    if (text == NULL || text->length == 0u
        || text->length > NINLIL_MODEL_DOMAIN_TEXT_ID_MAX) {
        return 0u;
    }
    return 1u + (uint32_t)text->length;
}

uint32_t ninlil_model_domain_party_encoded_length(void)
{
    return NINLIL_MODEL_DOMAIN_PARTY_BYTES;
}

uint32_t ninlil_model_domain_target_encoded_length(void)
{
    return NINLIL_MODEL_DOMAIN_TARGET_BYTES;
}

uint32_t ninlil_model_domain_resource_vector_encoded_length(void)
{
    return NINLIL_MODEL_DOMAIN_RESOURCE_VECTOR_BYTES;
}

uint32_t ninlil_model_domain_service_identity_encoded_length(
    const ninlil_model_domain_service_identity_t *identity)
{
    uint32_t n = 0u;
    uint32_t t;
    if (identity == NULL) {
        return 0u;
    }
    t = ninlil_model_domain_text_id_encoded_length(&identity->namespace_id);
    if (t == 0u || !checked_add_u32(n, t, &n)) {
        return 0u;
    }
    t = ninlil_model_domain_text_id_encoded_length(&identity->service_id);
    if (t == 0u || !checked_add_u32(n, t, &n)) {
        return 0u;
    }
    t = ninlil_model_domain_text_id_encoded_length(&identity->schema_id);
    if (t == 0u || !checked_add_u32(n, t, &n)) {
        return 0u;
    }
    if (!checked_add_u32(n, 8u + 32u + 2u + 2u + 4u, &n)) {
        return 0u;
    }
    return n;
}

int ninlil_model_domain_text_id_is_valid(
    const ninlil_model_domain_text_id_t *text,
    int namespace_grammar)
{
    size_t index;
    if (text == NULL || text->length == 0u
        || text->length > NINLIL_MODEL_DOMAIN_TEXT_ID_MAX
        || !ascii_lower_or_digit(text->bytes[0])) {
        return 0;
    }
    for (index = 1u; index < text->length; ++index) {
        uint8_t value = text->bytes[index];
        if (!ascii_lower_or_digit(value) && value != (uint8_t)'.'
            && value != (uint8_t)'-'
            && (namespace_grammar != 0 || value != (uint8_t)'_')) {
            return 0;
        }
    }
    for (index = text->length; index < sizeof(text->bytes); ++index) {
        if (text->bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int presence_is_valid(
    uint32_t flags,
    const uint8_t device[16],
    const uint8_t installation[16],
    const uint8_t site[16],
    uint64_t binding_epoch,
    uint64_t membership_epoch)
{
    int has_device = (flags & PRESENCE_DEVICE) != 0u;
    int has_installation = (flags & PRESENCE_INSTALLATION) != 0u;
    int has_site = (flags & PRESENCE_SITE) != 0u;

    return (flags & ~PRESENCE_ALLOWED) == 0u
        && id_is_zero(device) == !has_device
        && id_is_zero(installation) == !has_installation
        && id_is_zero(site) == !has_site
        && (binding_epoch != 0u) == (has_device || has_installation)
        && (membership_epoch != 0u) == has_site;
}

int ninlil_model_domain_party_is_valid(const ninlil_model_domain_party_t *party)
{
    if (party == NULL) {
        return 0;
    }
    return !id_is_zero(party->runtime_id)
        && !id_is_zero(party->application_instance_id)
        && presence_is_valid(
            party->local_identity.flags,
            party->local_identity.device,
            party->local_identity.installation,
            party->local_identity.site,
            party->local_identity.binding_epoch,
            party->local_identity.membership_epoch);
}

int ninlil_model_domain_target_is_valid(
    const ninlil_model_domain_target_t *target)
{
    if (target == NULL) {
        return 0;
    }
    return !id_is_zero(target->target_runtime)
        && !id_is_zero(target->target_application)
        && presence_is_valid(
            target->flags,
            target->device,
            target->installation,
            target->site,
            target->binding_epoch,
            target->membership_epoch);
}

int ninlil_model_domain_service_identity_is_valid(
    const ninlil_model_domain_service_identity_t *identity)
{
    if (identity == NULL) {
        return 0;
    }
    return ninlil_model_domain_text_id_is_valid(&identity->namespace_id, 1)
        && ninlil_model_domain_text_id_is_valid(&identity->service_id, 0)
        && ninlil_model_domain_text_id_is_valid(&identity->schema_id, 0)
        && identity->descriptor_revision != 0u
        && digest_is_nonzero(identity->descriptor_digest)
        && family_is_m1a(identity->family);
}

int ninlil_model_domain_resource_vector_is_valid(
    const ninlil_model_domain_resource_vector_t *vector,
    uint32_t released_mask)
{
    uint32_t i;
    if (vector == NULL
        || (released_mask & ~NINLIL_MODEL_DOMAIN_RESERVATION_RELEASED_MASK_KNOWN)
            != 0u) {
        return 0;
    }
    for (i = 0u; i < NINLIL_MODEL_DOMAIN_RESOURCE_KIND_COUNT; ++i) {
        if ((released_mask & (1u << i)) != 0u) {
            if (vector->used[i] != 0u || vector->reserved[i] != 0u) {
                return 0;
            }
        }
    }
    return 1;
}

static uint32_t encode_text_id(
    uint8_t *out, const ninlil_model_domain_text_id_t *text)
{
    out[0] = text->length;
    (void)memcpy(&out[1], text->bytes, text->length);
    return 1u + (uint32_t)text->length;
}

static int decode_text_id(
    const uint8_t *data,
    uint32_t remaining,
    ninlil_model_domain_text_id_t *out,
    uint32_t *consumed)
{
    uint8_t len;
    if (remaining < 1u) {
        return 0;
    }
    len = data[0];
    if (len == 0u || len > NINLIL_MODEL_DOMAIN_TEXT_ID_MAX
        || remaining < 1u + (uint32_t)len) {
        return 0;
    }
    (void)memset(out, 0, sizeof(*out));
    out->length = len;
    (void)memcpy(out->bytes, &data[1], len);
    *consumed = 1u + (uint32_t)len;
    return 1;
}

static void encode_local_identity(
    uint8_t *out, const ninlil_model_domain_local_identity_t *id)
{
    ninlil_model_domain_encode_u32_be(&out[0], id->flags);
    (void)memcpy(&out[4], id->device, 16u);
    (void)memcpy(&out[20], id->installation, 16u);
    (void)memcpy(&out[36], id->site, 16u);
    ninlil_model_domain_encode_u64_be(&out[52], id->binding_epoch);
    ninlil_model_domain_encode_u64_be(&out[60], id->membership_epoch);
}

static void decode_local_identity(
    const uint8_t *data, ninlil_model_domain_local_identity_t *id)
{
    id->flags = ninlil_model_domain_decode_u32_be(&data[0]);
    (void)memcpy(id->device, &data[4], 16u);
    (void)memcpy(id->installation, &data[20], 16u);
    (void)memcpy(id->site, &data[36], 16u);
    id->binding_epoch = ninlil_model_domain_decode_u64_be(&data[52]);
    id->membership_epoch = ninlil_model_domain_decode_u64_be(&data[60]);
}

static void encode_party(uint8_t *out, const ninlil_model_domain_party_t *p)
{
    (void)memcpy(&out[0], p->runtime_id, 16u);
    (void)memcpy(&out[16], p->application_instance_id, 16u);
    encode_local_identity(&out[32], &p->local_identity);
}

static void decode_party(const uint8_t *data, ninlil_model_domain_party_t *p)
{
    (void)memcpy(p->runtime_id, &data[0], 16u);
    (void)memcpy(p->application_instance_id, &data[16], 16u);
    decode_local_identity(&data[32], &p->local_identity);
}

static void encode_target(uint8_t *out, const ninlil_model_domain_target_t *t)
{
    ninlil_model_domain_encode_u32_be(&out[0], t->flags);
    (void)memcpy(&out[4], t->target_runtime, 16u);
    (void)memcpy(&out[20], t->target_application, 16u);
    (void)memcpy(&out[36], t->device, 16u);
    (void)memcpy(&out[52], t->installation, 16u);
    (void)memcpy(&out[68], t->site, 16u);
    ninlil_model_domain_encode_u64_be(&out[84], t->binding_epoch);
    ninlil_model_domain_encode_u64_be(&out[92], t->membership_epoch);
}

static void decode_target(const uint8_t *data, ninlil_model_domain_target_t *t)
{
    t->flags = ninlil_model_domain_decode_u32_be(&data[0]);
    (void)memcpy(t->target_runtime, &data[4], 16u);
    (void)memcpy(t->target_application, &data[20], 16u);
    (void)memcpy(t->device, &data[36], 16u);
    (void)memcpy(t->installation, &data[52], 16u);
    (void)memcpy(t->site, &data[68], 16u);
    t->binding_epoch = ninlil_model_domain_decode_u64_be(&data[84]);
    t->membership_epoch = ninlil_model_domain_decode_u64_be(&data[92]);
}

static uint32_t encode_service_identity(
    uint8_t *out, const ninlil_model_domain_service_identity_t *s)
{
    uint32_t o = 0u;
    o += encode_text_id(&out[o], &s->namespace_id);
    o += encode_text_id(&out[o], &s->service_id);
    o += encode_text_id(&out[o], &s->schema_id);
    ninlil_model_domain_encode_u64_be(&out[o], s->descriptor_revision);
    o += 8u;
    (void)memcpy(&out[o], s->descriptor_digest, 32u);
    o += 32u;
    ninlil_model_domain_encode_u16_be(&out[o], s->schema_major);
    o += 2u;
    ninlil_model_domain_encode_u16_be(&out[o], s->schema_minor);
    o += 2u;
    ninlil_model_domain_encode_u32_be(&out[o], s->family);
    o += 4u;
    return o;
}

static int decode_service_identity(
    const uint8_t *data,
    uint32_t remaining,
    ninlil_model_domain_service_identity_t *s,
    uint32_t *consumed)
{
    uint32_t o = 0u;
    uint32_t c = 0u;
    (void)memset(s, 0, sizeof(*s));
    if (!decode_text_id(data + o, remaining - o, &s->namespace_id, &c)) {
        return 0;
    }
    o += c;
    if (!decode_text_id(data + o, remaining - o, &s->service_id, &c)) {
        return 0;
    }
    o += c;
    if (!decode_text_id(data + o, remaining - o, &s->schema_id, &c)) {
        return 0;
    }
    o += c;
    if (remaining - o < 48u) {
        return 0;
    }
    s->descriptor_revision = ninlil_model_domain_decode_u64_be(&data[o]);
    o += 8u;
    (void)memcpy(s->descriptor_digest, &data[o], 32u);
    o += 32u;
    s->schema_major = ninlil_model_domain_decode_u16_be(&data[o]);
    o += 2u;
    s->schema_minor = ninlil_model_domain_decode_u16_be(&data[o]);
    o += 2u;
    s->family = ninlil_model_domain_decode_u32_be(&data[o]);
    o += 4u;
    *consumed = o;
    return 1;
}

static void encode_resource_vector(
    uint8_t *out, const ninlil_model_domain_resource_vector_t *v)
{
    uint32_t i;
    for (i = 0u; i < NINLIL_MODEL_DOMAIN_RESOURCE_KIND_COUNT; ++i) {
        ninlil_model_domain_encode_u64_be(&out[i * 16u], v->used[i]);
        ninlil_model_domain_encode_u64_be(&out[i * 16u + 8u], v->reserved[i]);
    }
}

static void decode_resource_vector(
    const uint8_t *data, ninlil_model_domain_resource_vector_t *v)
{
    uint32_t i;
    for (i = 0u; i < NINLIL_MODEL_DOMAIN_RESOURCE_KIND_COUNT; ++i) {
        v->used[i] = ninlil_model_domain_decode_u64_be(&data[i * 16u]);
        v->reserved[i] = ninlil_model_domain_decode_u64_be(&data[i * 16u + 8u]);
    }
}

static uint32_t encode_raw16(
    uint8_t *out, uint16_t length, const uint8_t *bytes)
{
    ninlil_model_domain_encode_u16_be(&out[0], length);
    if (length != 0u && bytes != NULL) {
        (void)memcpy(&out[2], bytes, length);
    }
    return 2u + (uint32_t)length;
}

static int decode_raw16_view(
    const uint8_t *data,
    uint32_t remaining,
    uint16_t max_len,
    uint16_t *out_len,
    const uint8_t **out_bytes,
    uint32_t *consumed)
{
    uint16_t len;
    if (remaining < 2u) {
        return 0;
    }
    len = ninlil_model_domain_decode_u16_be(data);
    if (len > max_len || remaining < 2u + (uint32_t)len) {
        return 0;
    }
    *out_len = len;
    *out_bytes = len == 0u ? NULL : &data[2];
    *consumed = 2u + (uint32_t)len;
    return 1;
}

/* Build service_key_raw contents from SERVICE body fields. */
static int build_service_key_raw_contents(
    const uint8_t app[16],
    const ninlil_model_domain_text_id_t *ns,
    const ninlil_model_domain_text_id_t *svc,
    uint64_t rev,
    const uint8_t dig[32],
    uint8_t *out,
    uint32_t capacity,
    uint16_t *out_len)
{
    uint32_t o = 0u;
    uint32_t t;
    if (out == NULL || out_len == NULL) {
        return 0;
    }
    if (capacity < 16u) {
        return 0;
    }
    (void)memcpy(&out[0], app, 16u);
    o = 16u;
    t = ninlil_model_domain_text_id_encoded_length(ns);
    if (t == 0u || o + t > capacity) {
        return 0;
    }
    o += encode_text_id(&out[o], ns);
    t = ninlil_model_domain_text_id_encoded_length(svc);
    if (t == 0u || o + t > capacity) {
        return 0;
    }
    o += encode_text_id(&out[o], svc);
    if (o + 40u > capacity) {
        return 0;
    }
    ninlil_model_domain_encode_u64_be(&out[o], rev);
    o += 8u;
    (void)memcpy(&out[o], dig, 32u);
    o += 32u;
    if (o > 255u) {
        return 0;
    }
    *out_len = (uint16_t)o;
    return 1;
}

static int service_key_raw_matches_fields(
    uint16_t raw_len,
    const uint8_t *raw,
    const uint8_t app[16],
    const ninlil_model_domain_text_id_t *ns,
    const ninlil_model_domain_text_id_t *svc,
    uint64_t rev,
    const uint8_t dig[32])
{
    uint8_t expect[255];
    uint16_t elen = 0u;
    if (!build_service_key_raw_contents(
            app, ns, svc, rev, dig, expect, sizeof(expect), &elen)) {
        return 0;
    }
    return raw_len == elen && raw != NULL && memcmp(raw, expect, elen) == 0;
}

/* scope_raw = application_instance_id[16] || ns:TEXT_ID || svc:TEXT_ID */
static int scope_raw_is_valid(
    uint16_t len, const uint8_t *raw)
{
    uint32_t o;
    uint32_t c;
    ninlil_model_domain_text_id_t ns;
    ninlil_model_domain_text_id_t svc;
    if (raw == NULL || len < 20u) {
        return 0;
    }
    if (id_is_zero(raw)) {
        return 0;
    }
    o = 16u;
    if (!decode_text_id(raw + o, (uint32_t)len - o, &ns, &c)
        || !ninlil_model_domain_text_id_is_valid(&ns, 1)) {
        return 0;
    }
    o += c;
    if (!decode_text_id(raw + o, (uint32_t)len - o, &svc, &c)
        || !ninlil_model_domain_text_id_is_valid(&svc, 0)) {
        return 0;
    }
    o += c;
    return o == (uint32_t)len;
}

static int reservation_owner_raw_is_valid(
    uint16_t owner_kind, uint16_t len, const uint8_t *raw)
{
    if (raw == NULL && len != 0u) {
        return 0;
    }
    switch (owner_kind) {
    case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_SERVICE: {
        uint32_t o;
        uint32_t c;
        ninlil_model_domain_text_id_t ns;
        ninlil_model_domain_text_id_t svc;
        if (len < 60u || raw == NULL) {
            return 0;
        }
        if (id_is_zero(raw)) {
            return 0;
        }
        o = 16u;
        if (!decode_text_id(raw + o, (uint32_t)len - o, &ns, &c)
            || !ninlil_model_domain_text_id_is_valid(&ns, 1)) {
            return 0;
        }
        o += c;
        if (!decode_text_id(raw + o, (uint32_t)len - o, &svc, &c)
            || !ninlil_model_domain_text_id_is_valid(&svc, 0)) {
            return 0;
        }
        o += c;
        if ((uint32_t)len - o != 40u) {
            return 0;
        }
        if (ninlil_model_domain_decode_u64_be(raw + o) == 0u) {
            return 0;
        }
        o += 8u;
        return digest_is_nonzero(raw + o);
    }
    case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_TRANSACTION:
        return len == 16u && raw != NULL && !id_is_zero(raw);
    case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_INGRESS:
        return len == 8u && raw != NULL
            && ninlil_model_domain_decode_u64_be(raw) != 0u;
    case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_DELIVERY:
        return len == NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES
            && raw != NULL
            && !id_is_zero(raw) /* source.runtime */
            && !id_is_zero(raw + 16) /* source.app */
            && !id_is_zero(raw + 32) /* txn */
            && !id_is_zero(raw + 48) /* target.runtime */
            && !id_is_zero(raw + 64); /* target.app */
    case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_CALLBACK: {
        uint16_t dlen;
        uint32_t need;
        if (raw == NULL || len < 2u + 8u) {
            return 0;
        }
        dlen = ninlil_model_domain_decode_u16_be(raw);
        if (dlen != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES) {
            return 0;
        }
        need = 2u + (uint32_t)dlen + 8u;
        if ((uint32_t)len != need) {
            return 0;
        }
        if (!reservation_owner_raw_is_valid(
                NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_DELIVERY,
                dlen,
                raw + 2u)) {
            return 0;
        }
        return ninlil_model_domain_decode_u64_be(raw + 2u + dlen) != 0u;
    }
    default:
        return 0;
    }
}

static int composite_identity_matches(
    uint8_t subtype,
    ninlil_bytes_view_t components,
    const uint8_t *key_identity,
    uint8_t key_identity_length)
{
    ninlil_model_domain_digest_t dig;
    if (key_identity == NULL || key_identity_length != 32u) {
        return 0;
    }
    if (ninlil_model_domain_composite_digest(subtype, components, &dig)
        != NINLIL_OK) {
        return 0;
    }
    return memcmp(key_identity, dig.bytes, 32u) == 0;
}

/*
 * KEY_DIGEST(complete encoded key) helpers (docs17 §5.1).
 * Stack-bounded: one key_t + digest at a time, no heap/VLA/recursion.
 */
static int complete_key_digest(
    uint8_t family,
    uint8_t subtype,
    uint8_t identity_kind,
    const uint8_t *identity,
    uint8_t identity_length,
    uint8_t out_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES])
{
    ninlil_model_domain_key_t key;
    ninlil_model_domain_digest_t dig;
    ninlil_bytes_view_t idv;

    if (out_digest == NULL
        || (identity_length != 0u && identity == NULL)) {
        return 0;
    }
    idv.data = identity;
    idv.length = identity_length;
    if (ninlil_model_domain_build_key(
            family, subtype, identity_kind, idv, &key)
        != NINLIL_OK) {
        return 0;
    }
    if (ninlil_model_domain_key_digest(
            (ninlil_bytes_view_t){key.bytes, key.length}, &dig)
        != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(out_digest, dig.bytes, NINLIL_MODEL_DOMAIN_DIGEST_BYTES);
    return 1;
}

/* KEY_DIGEST of composite-identity domain key (kind 5). */
static int composite_complete_key_digest(
    uint8_t subtype,
    ninlil_bytes_view_t components,
    uint8_t out_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES])
{
    ninlil_model_domain_digest_t comp;

    if (ninlil_model_domain_composite_digest(subtype, components, &comp)
        != NINLIL_OK) {
        return 0;
    }
    return complete_key_digest(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        subtype,
        NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
        comp.bytes,
        (uint8_t)NINLIL_MODEL_DOMAIN_DIGEST_BYTES,
        out_digest);
}

static int digest_eq_complete_key(
    const uint8_t actual[NINLIL_MODEL_DOMAIN_DIGEST_BYTES],
    uint8_t family,
    uint8_t subtype,
    uint8_t identity_kind,
    const uint8_t *identity,
    uint8_t identity_length)
{
    uint8_t expect[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];

    if (actual == NULL) {
        return 0;
    }
    if (!complete_key_digest(
            family, subtype, identity_kind, identity, identity_length,
            expect)) {
        return 0;
    }
    return memcmp(actual, expect, NINLIL_MODEL_DOMAIN_DIGEST_BYTES) == 0;
}

static int digest_eq_composite_key(
    const uint8_t actual[NINLIL_MODEL_DOMAIN_DIGEST_BYTES],
    uint8_t subtype,
    ninlil_bytes_view_t components)
{
    uint8_t expect[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];

    if (actual == NULL) {
        return 0;
    }
    if (!composite_complete_key_digest(subtype, components, expect)) {
        return 0;
    }
    return memcmp(actual, expect, NINLIL_MODEL_DOMAIN_DIGEST_BYTES) == 0;
}

/* Wrap raw contents as RAW16 into out (max contents 255). */
static int encode_raw16_into(
    uint16_t raw_length,
    const uint8_t *raw,
    uint8_t *out,
    uint32_t capacity,
    uint32_t *out_length)
{
    if (out == NULL || out_length == NULL
        || raw_length > 255u
        || (raw_length != 0u && raw == NULL)
        || capacity < 2u + (uint32_t)raw_length) {
        return 0;
    }
    ninlil_model_domain_encode_u16_be(out, raw_length);
    if (raw_length != 0u) {
        (void)memcpy(&out[2], raw, raw_length);
    }
    *out_length = 2u + (uint32_t)raw_length;
    return 1;
}

/* scope_raw contents = app[16] || ns:TEXT_ID || svc:TEXT_ID */
static int build_scope_raw_contents(
    const uint8_t app[16],
    const ninlil_model_domain_text_id_t *ns,
    const ninlil_model_domain_text_id_t *svc,
    uint8_t *out,
    uint32_t capacity,
    uint16_t *out_len)
{
    uint32_t o = 0u;
    uint32_t t;

    if (out == NULL || out_len == NULL || app == NULL || ns == NULL
        || svc == NULL || capacity < 16u) {
        return 0;
    }
    (void)memcpy(&out[0], app, 16u);
    o = 16u;
    t = ninlil_model_domain_text_id_encoded_length(ns);
    if (t == 0u || o + t > capacity) {
        return 0;
    }
    o += encode_text_id(&out[o], ns);
    t = ninlil_model_domain_text_id_encoded_length(svc);
    if (t == 0u || o + t > capacity) {
        return 0;
    }
    o += encode_text_id(&out[o], svc);
    if (o > 255u) {
        return 0;
    }
    *out_len = (uint16_t)o;
    return 1;
}

/* --- D1-B1 field validators --- */

static int internal_invariant_fields_ok(
    const ninlil_model_domain_body_internal_invariant_t *body)
{
    if (body == NULL || body->reserved != 0u) {
        return 0;
    }
    if (!ninlil_model_domain_reason_is_known_public(body->reason)) {
        return 0;
    }
    if (!ninlil_model_domain_invariant_subject_kind_is_valid(body->subject_kind)) {
        return 0;
    }
    if (body->subject_kind == NINLIL_MODEL_DOMAIN_SUBJECT_KIND_NAMESPACE) {
        if (!digest_is_zero(body->subject_digest)) {
            return 0;
        }
    } else if (digest_is_zero(body->subject_digest)) {
        return 0;
    }
    return 1;
}

static int bearer_fields_ok(const ninlil_model_domain_body_bearer_state_t *body)
{
    if (body == NULL) {
        return 0;
    }
    if (body->availability_epoch == 0u) {
        return 0;
    }
    if (body->available > 1u) {
        return 0;
    }
    if (id_is_zero(body->observation_clock_epoch)) {
        return 0;
    }
    return 1;
}

static int clock_fields_ok(const ninlil_model_domain_body_clock_baseline_t *body)
{
    if (body == NULL || body->reserved != 0u) {
        return 0;
    }
    if (body->baseline_state
        == NINLIL_MODEL_DOMAIN_BASELINE_STATE_UNINITIALIZED) {
        return id_is_zero(body->trusted_clock_epoch)
            && body->last_trusted_now_ms == 0u
            && body->publish_generation == 0u;
    }
    if (body->baseline_state == NINLIL_MODEL_DOMAIN_BASELINE_STATE_TRUSTED) {
        return !id_is_zero(body->trusted_clock_epoch)
            && body->publish_generation >= 1u;
    }
    return 0;
}

static int fence_fields_ok(
    const ninlil_model_domain_body_attempt_reuse_fence_t *body)
{
    if (body == NULL || body->reserved != 0u) {
        return 0;
    }
    if (body->active_plan_count == 0u || body->fence_generation == 0u) {
        return 0;
    }
    return 1;
}

static int head_index_fields_ok(
    const ninlil_model_domain_body_witness_head_index_t *body)
{
    ninlil_model_domain_digest_t kd;
    ninlil_bytes_view_t key_view;

    if (body == NULL || body->reserved0 != 0u || body->reserved1 != 0u) {
        return 0;
    }
    if (body->index_state != NINLIL_MODEL_DOMAIN_INDEX_STATE_BASELINE
        && body->index_state != NINLIL_MODEL_DOMAIN_INDEX_STATE_WITNESSED) {
        return 0;
    }
    if (body->member_key_length
            != NINLIL_MODEL_DOMAIN_HEAD_INDEX_MEMBER_KEY_BYTES
        || body->member_key_bytes == NULL) {
        return 0;
    }
    key_view.data = body->member_key_bytes;
    key_view.length = body->member_key_length;
    if (!ninlil_model_domain_family34_member_key_is_valid(key_view)) {
        return 0;
    }
    if (ninlil_model_domain_key_digest(key_view, &kd) != NINLIL_OK
        || memcmp(kd.bytes, body->member_key_digest,
            NINLIL_MODEL_DOMAIN_DIGEST_BYTES)
            != 0) {
        return 0;
    }
    if (body->index_state == NINLIL_MODEL_DOMAIN_INDEX_STATE_BASELINE) {
        if (!digest_is_zero(body->member_head_witness_digest)) {
            return 0;
        }
    } else if (digest_is_zero(body->member_head_witness_digest)) {
        return 0;
    }
    return 1;
}

/* --- D1-B2 field validators --- */

static int service_descriptor_contract_ok(
    const ninlil_model_domain_body_service_t *body)
{
    if (body == NULL) {
        return 0;
    }
    if (!family_is_m1a(body->family)) {
        return 0;
    }
    if (!ninlil_model_domain_text_id_is_valid(&body->namespace_id, 1)
        || !ninlil_model_domain_text_id_is_valid(&body->service_id, 0)
        || !ninlil_model_domain_text_id_is_valid(&body->schema_id, 0)) {
        return 0;
    }
    if (body->descriptor_revision == 0u
        || digest_is_zero(body->descriptor_digest)
        || id_is_zero(body->local_application_instance_id)) {
        return 0;
    }
    if (body->minor_min > body->minor_max) {
        return 0;
    }
    if (body->custody_policy != NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE) {
        return 0;
    }
    if (!evidence_mask_is_valid(body->supported_evidence_mask)) {
        return 0;
    }
    if (body->logical_payload_limit == 0u || body->inflight_limit == 0u
        || body->target_limit != 1u
        || body->attempts_per_cycle == 0u
        || body->attempts_per_cycle > NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE
        || body->admission_window_ms == 0u
        || body->admission_window_ms > NINLIL_M1A_MAX_RETRY_DELAY_MS
        || body->max_admissions_window == 0u
        || body->max_payload_window < body->logical_payload_limit
        || body->attempt_receipt_timeout_ms == 0u
        || body->attempt_receipt_timeout_ms
            > NINLIL_M1A_MAX_ATTEMPT_RECEIPT_TIMEOUT_MS
        || body->retry_backoff_ms == 0u
        || body->retry_backoff_ms > NINLIL_M1A_MAX_RETRY_BACKOFF_MS
        || body->application_completion_timeout_ms == 0u
        || body->application_completion_timeout_ms
            > NINLIL_M1A_MAX_APPLICATION_COMPLETION_TIMEOUT_MS
        || body->required_dedup_window_ms == 0u) {
        return 0;
    }
    if (body->family == NINLIL_FAMILY_EVENT_FACT) {
        if (body->attempts_per_cycle != NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE
            || body->direction != NINLIL_DIRECTION_UPLINK
            || body->admission_authority != NINLIL_AUTHORITY_ORIGIN_WITH_GRANT
            || body->apply_contract != NINLIL_APPLY_APPLICATION_DEDUP
            || body->minimum_deadline_ms != NINLIL_NO_DEADLINE
            || body->maximum_deadline_ms != NINLIL_NO_DEADLINE
            || body->maximum_evidence_grace_ms != 0u) {
            return 0;
        }
    } else {
        if (body->direction != NINLIL_DIRECTION_DOWNLINK
            || body->admission_authority != NINLIL_AUTHORITY_CONTROLLER_ONLY
            || (body->apply_contract != NINLIL_APPLY_IDEMPOTENT
                && body->apply_contract != NINLIL_APPLY_APPLICATION_DEDUP)
            || body->minimum_deadline_ms < 1u
            || body->minimum_deadline_ms > body->maximum_deadline_ms
            || body->maximum_deadline_ms >= NINLIL_NO_DEADLINE) {
            return 0;
        }
    }
    if (body->service_key_raw_length == 0u
        || body->service_key_raw_length > NINLIL_MODEL_DOMAIN_RAW16_SERVICE_KEY_MAX
        || body->service_key_raw == NULL) {
        return 0;
    }
    if (!service_key_raw_matches_fields(
            body->service_key_raw_length,
            body->service_key_raw,
            body->local_application_instance_id,
            &body->namespace_id,
            &body->service_id,
            body->descriptor_revision,
            body->descriptor_digest)) {
        return 0;
    }
    /*
     * Same-body: quota_key_digest / reservation_key_digest are KEY_DIGEST of
     * complete SERVICE_QUOTA and SERVICE-owner RESERVATION keys (docs17 §5.1).
     */
    {
        uint8_t raw16[257];
        uint8_t res_comp[4u + 255u];
        ninlil_bytes_view_t sk_components;
        ninlil_bytes_view_t res_components;
        uint32_t sk_raw16_len = 0u;

        if (!encode_raw16_into(
                body->service_key_raw_length,
                body->service_key_raw,
                raw16,
                sizeof(raw16),
                &sk_raw16_len)) {
            return 0;
        }
        sk_components.data = raw16;
        sk_components.length = sk_raw16_len;
        if (!digest_eq_composite_key(
                body->quota_key_digest,
                NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE_QUOTA,
                sk_components)) {
            return 0;
        }
        ninlil_model_domain_encode_u16_be(
            res_comp, NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_SERVICE);
        (void)memcpy(&res_comp[2], raw16, sk_raw16_len);
        res_components.data = res_comp;
        res_components.length = 2u + sk_raw16_len;
        if (!digest_eq_composite_key(
                body->reservation_key_digest,
                NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION,
                res_components)) {
            return 0;
        }
    }
    return 1;
}

static int service_quota_fields_ok(
    const ninlil_model_domain_body_service_quota_t *body)
{
    uint8_t raw16[257];
    ninlil_bytes_view_t components;
    uint32_t raw16_len = 0u;

    if (body == NULL
        || body->service_key_raw_length == 0u
        || body->service_key_raw_length
            > NINLIL_MODEL_DOMAIN_RAW16_SERVICE_KEY_MAX
        || body->service_key_raw == NULL
        || id_is_zero(body->window_clock_epoch)) {
        return 0;
    }
    /* service_key_raw must parse as service key contents (shape only). */
    if (!reservation_owner_raw_is_valid(
            NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_SERVICE,
            body->service_key_raw_length,
            body->service_key_raw)) {
        return 0;
    }
    /* service_key_digest = KEY_DIGEST(complete SERVICE key). */
    if (!encode_raw16_into(
            body->service_key_raw_length,
            body->service_key_raw,
            raw16,
            sizeof(raw16),
            &raw16_len)) {
        return 0;
    }
    components.data = raw16;
    components.length = raw16_len;
    if (!digest_eq_composite_key(
            body->service_key_digest,
            NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE,
            components)) {
        return 0;
    }
    return 1;
}

static int transaction_anchor_fields_ok(
    const ninlil_model_domain_body_transaction_anchor_t *body)
{
    int is_event;
    uint8_t expect_scope[255];
    uint16_t expect_scope_len = 0u;
    uint8_t seq_be[8];
    uint8_t im_comp[2u + 255u + 2u + 64u];
    uint8_t em_comp[2u + 255u + 16u];
    uint8_t res_comp[2u + 2u + 16u];
    ninlil_bytes_view_t im_view;
    ninlil_bytes_view_t em_view;
    ninlil_bytes_view_t res_view;
    uint32_t o;

    if (body == NULL || id_is_zero(body->transaction_id)
        || body->transaction_sequence == 0u
        || body->scheduler_owner_sequence == 0u
        || !family_is_m1a(body->family)
        || !ninlil_model_domain_party_is_valid(&body->source)
        || !ninlil_model_domain_service_identity_is_valid(&body->service)
        || body->service.family != body->family
        || digest_is_zero(body->content_digest)
        || digest_is_zero(body->canonical_submission_digest)
        || id_is_zero(body->admission_clock_epoch)
        || body->target_count != 1u
        || !ninlil_model_domain_target_is_valid(&body->target)
        || body->idempotency_scope_raw_length == 0u
        || body->idempotency_scope_raw_length
            > NINLIL_MODEL_DOMAIN_RAW16_SCOPE_MAX
        || body->idempotency_scope_raw == NULL
        || body->idempotency_key_length == 0u
        || body->idempotency_key_length
            > NINLIL_MODEL_DOMAIN_RAW16_IDEMPOTENCY_KEY_MAX
        || body->idempotency_key == NULL
        || body->scheduler_owner_key_sequence == 0u
        || body->scheduler_owner_key_sequence != body->scheduler_owner_sequence
        || digest_is_zero(body->payload_blob_key_digest)
        || !evidence_stage_is_known(body->required_evidence)
        || body->required_evidence == NINLIL_EVIDENCE_NONE) {
        return 0;
    }
    /*
     * scope_raw must equal exact encoding of
     * source.application_instance_id || service.namespace || service.service
     * (docs17 §5.1), not merely start with app ID + parseable names.
     */
    if (!build_scope_raw_contents(
            body->source.application_instance_id,
            &body->service.namespace_id,
            &body->service.service_id,
            expect_scope,
            sizeof(expect_scope),
            &expect_scope_len)
        || body->idempotency_scope_raw_length != expect_scope_len
        || memcmp(
               body->idempotency_scope_raw, expect_scope, expect_scope_len)
            != 0) {
        return 0;
    }
    is_event = body->family == NINLIL_FAMILY_EVENT_FACT;
    if (is_event) {
        if (id_is_zero(body->event_id) || body->generation != 0u
            || !id_is_zero(body->deadline_clock_epoch)
            || body->absolute_effect_deadline_ms != NINLIL_NO_DEADLINE
            || body->evidence_grace_ms != 0u) {
            return 0;
        }
    } else {
        if (!id_is_zero(body->event_id) || body->generation == 0u
            || id_is_zero(body->deadline_clock_epoch)
            || body->absolute_effect_deadline_ms == NINLIL_NO_DEADLINE) {
            return 0;
        }
        /* deadline epoch equals admission epoch for DesiredState */
        if (memcmp(
                body->deadline_clock_epoch,
                body->admission_clock_epoch,
                16u)
            != 0) {
            return 0;
        }
    }

    /* sequence_index_key_digest: family6 subtype21, u64 transaction_sequence */
    ninlil_model_domain_encode_u64_be(seq_be, body->transaction_sequence);
    if (!digest_eq_complete_key(
            body->sequence_index_key_digest,
            NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
            NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_SEQUENCE_INDEX,
            NINLIL_MODEL_DOMAIN_ID_KIND_U64,
            seq_be,
            8u)) {
        return 0;
    }

    /* idempotency_map_key_digest: subtype24, scope_raw:RAW16 || key:RAW16 */
    o = 0u;
    o += encode_raw16(
        &im_comp[o], body->idempotency_scope_raw_length,
        body->idempotency_scope_raw);
    o += encode_raw16(
        &im_comp[o], body->idempotency_key_length, body->idempotency_key);
    im_view.data = im_comp;
    im_view.length = o;
    if (!digest_eq_composite_key(
            body->idempotency_map_key_digest,
            NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP,
            im_view)) {
        return 0;
    }

    /* event_map_key_digest: DesiredState zero; EventFact subtype25 composite */
    if (is_event) {
        o = 0u;
        o += encode_raw16(
            &em_comp[o], body->idempotency_scope_raw_length,
            body->idempotency_scope_raw);
        (void)memcpy(&em_comp[o], body->event_id, 16u);
        o += 16u;
        em_view.data = em_comp;
        em_view.length = o;
        if (!digest_eq_composite_key(
                body->event_map_key_digest,
                NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_ID_MAP,
                em_view)) {
            return 0;
        }
    } else if (!digest_is_zero(body->event_map_key_digest)) {
        return 0;
    }

    /* reservation_key_digest: subtype23 TRANSACTION owner + txn id RAW16 */
    ninlil_model_domain_encode_u16_be(
        res_comp, NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_TRANSACTION);
    ninlil_model_domain_encode_u16_be(&res_comp[2], 16u);
    (void)memcpy(&res_comp[4], body->transaction_id, 16u);
    res_view.data = res_comp;
    res_view.length = 4u + 16u;
    if (!digest_eq_composite_key(
            body->reservation_key_digest,
            NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION,
            res_view)) {
        return 0;
    }
    /* payload_blob_key_digest: non-zero only (blob kind/length are cross-record) */
    return 1;
}

static int sequence_index_fields_ok(
    const ninlil_model_domain_body_transaction_sequence_index_t *body)
{
    return body != NULL && body->transaction_sequence != 0u
        && !id_is_zero(body->transaction_id)
        && digest_is_nonzero(body->anchor_value_digest);
}

static int transaction_state_fields_ok(
    const ninlil_model_domain_body_transaction_state_t *body)
{
    if (body == NULL || id_is_zero(body->transaction_id)
        || digest_is_zero(body->anchor_value_digest)
        || !txn_state_is_known(body->state)
        || !outcome_is_known(body->outcome)
        || !deadline_verdict_is_known(body->deadline_verdict)
        || !evidence_stage_is_known(body->latest_evidence)
        || !ninlil_model_domain_reason_is_known_public(body->reason)
        || !park_cause_is_known(body->event_park_cause)
        || body->attempt_in_cycle > NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE
        || body->has_late_evidence > 1u
        || body->explicitly_discarded > 1u
        || !ninlil_model_domain_target_is_valid(&body->target)
        || body->target_state != body->state
        || body->target_outcome != body->outcome
        || body->target_reason != body->reason
        || body->target_latest_evidence != body->latest_evidence) {
        return 0;
    }
    return 1;
}

/*
 * primary_key_digest = KEY_DIGEST of referenced primary complete key
 * (docs17 §5.1 / §9). Separate from common primary_id hint.
 */
static int reservation_primary_key_digest_ok(
    const ninlil_model_domain_body_reservation_t *body)
{
    uint8_t raw16[257];
    ninlil_bytes_view_t components;
    uint32_t raw16_len = 0u;

    if (body == NULL || body->owner_key_raw == NULL) {
        return 0;
    }
    switch (body->owner_kind) {
    case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_SERVICE:
        if (!encode_raw16_into(
                body->owner_key_raw_length,
                body->owner_key_raw,
                raw16,
                sizeof(raw16),
                &raw16_len)) {
            return 0;
        }
        components.data = raw16;
        components.length = raw16_len;
        return digest_eq_composite_key(
            body->primary_key_digest,
            NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE,
            components);
    case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_TRANSACTION:
        if (body->owner_key_raw_length != 16u) {
            return 0;
        }
        return digest_eq_complete_key(
            body->primary_key_digest,
            NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
            NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR,
            NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
            body->owner_key_raw,
            16u);
    case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_INGRESS:
        if (body->owner_key_raw_length != 8u) {
            return 0;
        }
        return digest_eq_complete_key(
            body->primary_key_digest,
            NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
            NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS,
            NINLIL_MODEL_DOMAIN_ID_KIND_U64,
            body->owner_key_raw,
            8u);
    case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_DELIVERY:
        if (!encode_raw16_into(
                body->owner_key_raw_length,
                body->owner_key_raw,
                raw16,
                sizeof(raw16),
                &raw16_len)) {
            return 0;
        }
        components.data = raw16;
        components.length = raw16_len;
        return digest_eq_composite_key(
            body->primary_key_digest,
            NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
            components);
    case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_CALLBACK: {
        uint16_t dlen;

        if (body->owner_key_raw_length < 2u + 8u) {
            return 0;
        }
        dlen = ninlil_model_domain_decode_u16_be(body->owner_key_raw);
        if (dlen != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES
            || (uint32_t)body->owner_key_raw_length
                != 2u + (uint32_t)dlen + 8u) {
            return 0;
        }
        /* Prefix is already delivery_key_raw:RAW16 (ignore token generation). */
        components.data = body->owner_key_raw;
        components.length = 2u + (uint32_t)dlen;
        return digest_eq_composite_key(
            body->primary_key_digest,
            NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
            components);
    }
    default:
        return 0;
    }
}

static int reservation_fields_ok(
    const ninlil_model_domain_body_reservation_t *body)
{
    if (body == NULL || body->reserved != 0u
        || body->owner_kind < NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_SERVICE
        || body->owner_kind > NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_CALLBACK
        || body->owner_key_raw_length == 0u
        || body->owner_key_raw_length > NINLIL_MODEL_DOMAIN_RAW16_OWNER_KEY_MAX
        || body->owner_key_raw == NULL
        || !reservation_owner_raw_is_valid(
            body->owner_kind, body->owner_key_raw_length, body->owner_key_raw)
        || !reservation_primary_key_digest_ok(body)
        || !ninlil_model_domain_resource_vector_is_valid(
            &body->resources, body->released_mask)) {
        return 0;
    }
    return 1;
}

static int idempotency_map_fields_ok(
    const ninlil_model_domain_body_idempotency_map_t *body)
{
    return body != NULL
        && body->scope_raw_length > 0u
        && body->scope_raw_length <= NINLIL_MODEL_DOMAIN_RAW16_SCOPE_MAX
        && body->scope_raw != NULL
        && scope_raw_is_valid(body->scope_raw_length, body->scope_raw)
        && body->idempotency_key_length > 0u
        && body->idempotency_key_length
            <= NINLIL_MODEL_DOMAIN_RAW16_IDEMPOTENCY_KEY_MAX
        && body->idempotency_key != NULL
        && !id_is_zero(body->transaction_id)
        && digest_is_nonzero(body->canonical_submission_digest)
        && digest_is_nonzero(body->anchor_value_digest);
}

static int event_id_map_fields_ok(
    const ninlil_model_domain_body_event_id_map_t *body)
{
    return body != NULL
        && body->scope_raw_length > 0u
        && body->scope_raw_length <= NINLIL_MODEL_DOMAIN_RAW16_SCOPE_MAX
        && body->scope_raw != NULL
        && scope_raw_is_valid(body->scope_raw_length, body->scope_raw)
        && !id_is_zero(body->event_id)
        && !id_is_zero(body->transaction_id)
        && digest_is_nonzero(body->canonical_submission_digest)
        && body->idempotency_key_length > 0u
        && body->idempotency_key_length
            <= NINLIL_MODEL_DOMAIN_RAW16_IDEMPOTENCY_KEY_MAX
        && body->idempotency_key != NULL
        && digest_is_nonzero(body->anchor_value_digest);
}

/*
 * Scheduler subject raw reuses reservation owner raw formulas for the three
 * overlapping owner kinds (docs17 §7.1 / §8.3). Enum values differ:
 * scheduler TRANSACTION=1/DELIVERY=2/INGRESS=3 vs reservation 2/4/3.
 */
static int scheduler_subject_raw_is_valid(
    uint16_t owner_kind, uint16_t len, const uint8_t *raw)
{
    switch (owner_kind) {
    case NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_TRANSACTION:
        return reservation_owner_raw_is_valid(
            NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_TRANSACTION, len, raw);
    case NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_DELIVERY:
        return reservation_owner_raw_is_valid(
            NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_DELIVERY, len, raw);
    case NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_INGRESS:
        return reservation_owner_raw_is_valid(
            NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_INGRESS, len, raw);
    default:
        return 0;
    }
}

/*
 * primary_key_digest = KEY_DIGEST of referenced primary complete key
 * (TRANSACTION_ANCHOR / DELIVERY / ORDERED_INGRESS). Not identity digest.
 */
static int scheduler_primary_key_digest_ok(
    const ninlil_model_domain_body_scheduler_owner_t *body)
{
    uint8_t raw16[257];
    ninlil_bytes_view_t components;
    uint32_t raw16_len = 0u;

    if (body == NULL || body->subject_key_raw == NULL) {
        return 0;
    }
    switch (body->owner_kind) {
    case NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_TRANSACTION:
        if (body->subject_key_raw_length != 16u) {
            return 0;
        }
        return digest_eq_complete_key(
            body->primary_key_digest,
            NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
            NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR,
            NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
            body->subject_key_raw,
            16u);
    case NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_DELIVERY:
        if (!encode_raw16_into(
                body->subject_key_raw_length,
                body->subject_key_raw,
                raw16,
                sizeof(raw16),
                &raw16_len)) {
            return 0;
        }
        components.data = raw16;
        components.length = raw16_len;
        return digest_eq_composite_key(
            body->primary_key_digest,
            NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
            components);
    case NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_INGRESS:
        if (body->subject_key_raw_length != 8u) {
            return 0;
        }
        return digest_eq_complete_key(
            body->primary_key_digest,
            NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
            NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS,
            NINLIL_MODEL_DOMAIN_ID_KIND_U64,
            body->subject_key_raw,
            8u);
    default:
        return 0;
    }
}

/* Next wake: both zero OR epoch non-zero and time non-zero (docs17 §8.3). */
static int scheduler_next_wake_pair_ok(
    const uint8_t epoch[NINLIL_MODEL_DOMAIN_ID_BYTES], uint64_t at_ms)
{
    if (epoch == NULL) {
        return 0;
    }
    if (id_is_zero(epoch)) {
        return at_ms == 0u;
    }
    return at_ms != 0u;
}

static int scheduler_owner_fields_ok(
    const ninlil_model_domain_body_scheduler_owner_t *body)
{
    if (body == NULL || body->owner_sequence == 0u
        || body->owner_kind < NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_TRANSACTION
        || body->owner_kind > NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_INGRESS
        || body->work_class < NINLIL_MODEL_DOMAIN_WORK_CLASS_REDUCE
        || body->work_class > NINLIL_MODEL_DOMAIN_WORK_CLASS_RECOVERY
        || body->subject_key_raw_length == 0u
        || body->subject_key_raw_length
            > NINLIL_MODEL_DOMAIN_RAW16_SUBJECT_KEY_MAX
        || body->subject_key_raw == NULL
        || !scheduler_subject_raw_is_valid(
            body->owner_kind,
            body->subject_key_raw_length,
            body->subject_key_raw)
        || !scheduler_primary_key_digest_ok(body)
        || body->state_revision == 0u
        || id_is_zero(body->logical_clock_epoch)
        || !scheduler_next_wake_pair_ok(
            body->next_wake_clock_epoch, body->next_wake_at_ms)
        || body->ready > 1u) {
        return 0;
    }
    return 1;
}

/* --- INTERNAL_INVARIANT --- */

uint32_t ninlil_model_domain_body_internal_invariant_encoded_length(void)
{
    return NINLIL_MODEL_DOMAIN_BODY_INTERNAL_INVARIANT_BYTES;
}

ninlil_status_t ninlil_model_domain_invariant_marker_id(
    uint32_t reason,
    uint16_t subject_kind,
    const uint8_t subject_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES],
    uint8_t out_marker_id[NINLIL_MODEL_DOMAIN_ID_BYTES])
{
    ninlil_model_domain_sha256_ctx_t ctx;
    ninlil_model_domain_digest_t dig;
    uint8_t scratch[6];
    ninlil_status_t status;

    if (out_marker_id == NULL
        || !range_address_is_valid(
            out_marker_id, NINLIL_MODEL_DOMAIN_ID_BYTES)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (subject_digest != NULL) {
        if (!range_address_is_valid(
                subject_digest, NINLIL_MODEL_DOMAIN_DIGEST_BYTES)
            || !ninlil_model_domain_ranges_are_disjoint(
                subject_digest, NINLIL_MODEL_DOMAIN_DIGEST_BYTES,
                out_marker_id, NINLIL_MODEL_DOMAIN_ID_BYTES)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
    }
    (void)memset(out_marker_id, 0, NINLIL_MODEL_DOMAIN_ID_BYTES);
    if (subject_digest == NULL
        || !ninlil_model_domain_reason_is_known_public(reason)
        || !ninlil_model_domain_invariant_subject_kind_is_valid(subject_kind)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (subject_kind == NINLIL_MODEL_DOMAIN_SUBJECT_KIND_NAMESPACE) {
        if (!ninlil_model_domain_digest_is_zero(subject_digest)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
    } else if (ninlil_model_domain_digest_is_zero(subject_digest)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_sha256_init(&ctx);
    status = ninlil_model_domain_sha256_update(
        &ctx, (const uint8_t *)PREIMAGE_INVARIANT,
        (uint32_t)(sizeof(PREIMAGE_INVARIANT) - 1u));
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_model_domain_encode_u32_be(&scratch[0], reason);
    status = ninlil_model_domain_sha256_update(&ctx, scratch, 4u);
    if (status != NINLIL_OK) {
        (void)memset(out_marker_id, 0, NINLIL_MODEL_DOMAIN_ID_BYTES);
        return status;
    }
    ninlil_model_domain_encode_u16_be(&scratch[0], subject_kind);
    status = ninlil_model_domain_sha256_update(&ctx, scratch, 2u);
    if (status != NINLIL_OK) {
        (void)memset(out_marker_id, 0, NINLIL_MODEL_DOMAIN_ID_BYTES);
        return status;
    }
    status = ninlil_model_domain_sha256_update(
        &ctx, subject_digest, NINLIL_MODEL_DOMAIN_DIGEST_BYTES);
    if (status != NINLIL_OK) {
        (void)memset(out_marker_id, 0, NINLIL_MODEL_DOMAIN_ID_BYTES);
        return status;
    }
    status = ninlil_model_domain_sha256_final(&ctx, &dig);
    if (status != NINLIL_OK) {
        (void)memset(out_marker_id, 0, NINLIL_MODEL_DOMAIN_ID_BYTES);
        return status;
    }
    (void)memcpy(out_marker_id, dig.bytes, NINLIL_MODEL_DOMAIN_ID_BYTES);
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_encode_body_internal_invariant(
    const ninlil_model_domain_body_internal_invariant_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    const uint32_t required = NINLIL_MODEL_DOMAIN_BODY_INTERNAL_INVARIANT_BYTES;
    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_alias_ok(
            body, body == NULL ? 0u : sizeof(*body),
            out_bytes, capacity, out_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || !internal_invariant_fields_ok(body)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    ninlil_model_domain_encode_u32_be(&out_bytes[0], body->reason);
    ninlil_model_domain_encode_u16_be(&out_bytes[4], body->subject_kind);
    ninlil_model_domain_encode_u16_be(&out_bytes[6], 0u);
    (void)memcpy(&out_bytes[8], body->subject_digest, 32u);
    (void)memcpy(&out_bytes[40], body->first_clock_epoch, 16u);
    ninlil_model_domain_encode_u64_be(&out_bytes[56], body->first_at_ms);
    (void)memcpy(&out_bytes[64], body->detail_digest, 32u);
    *out_length = required;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_internal_invariant(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_internal_invariant_t *out_body)
{
    ninlil_model_domain_body_internal_invariant_t tmp;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length
            != NINLIL_MODEL_DOMAIN_BODY_INTERNAL_INVARIANT_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.reason = ninlil_model_domain_decode_u32_be(&encoded.data[0]);
    tmp.subject_kind = ninlil_model_domain_decode_u16_be(&encoded.data[4]);
    tmp.reserved = ninlil_model_domain_decode_u16_be(&encoded.data[6]);
    (void)memcpy(tmp.subject_digest, &encoded.data[8], 32u);
    (void)memcpy(tmp.first_clock_epoch, &encoded.data[40], 16u);
    tmp.first_at_ms = ninlil_model_domain_decode_u64_be(&encoded.data[56]);
    (void)memcpy(tmp.detail_digest, &encoded.data[64], 32u);
    if (!internal_invariant_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- BEARER_STATE --- */

uint32_t ninlil_model_domain_body_bearer_state_encoded_length(void)
{
    return NINLIL_MODEL_DOMAIN_BODY_BEARER_STATE_BYTES;
}

ninlil_status_t ninlil_model_domain_encode_body_bearer_state(
    const ninlil_model_domain_body_bearer_state_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    const uint32_t required = NINLIL_MODEL_DOMAIN_BODY_BEARER_STATE_BYTES;
    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_alias_ok(
            body, body == NULL ? 0u : sizeof(*body),
            out_bytes, capacity, out_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || !bearer_fields_ok(body)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    ninlil_model_domain_encode_u64_be(&out_bytes[0], body->availability_epoch);
    ninlil_model_domain_encode_u32_be(&out_bytes[8], body->available);
    (void)memcpy(&out_bytes[12], body->observation_clock_epoch, 16u);
    ninlil_model_domain_encode_u64_be(&out_bytes[28], body->observed_at_ms);
    *out_length = required;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_bearer_state(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_bearer_state_t *out_body)
{
    ninlil_model_domain_body_bearer_state_t tmp;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length != NINLIL_MODEL_DOMAIN_BODY_BEARER_STATE_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.availability_epoch =
        ninlil_model_domain_decode_u64_be(&encoded.data[0]);
    tmp.available = ninlil_model_domain_decode_u32_be(&encoded.data[8]);
    (void)memcpy(tmp.observation_clock_epoch, &encoded.data[12], 16u);
    tmp.observed_at_ms = ninlil_model_domain_decode_u64_be(&encoded.data[28]);
    if (!bearer_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- CLOCK_BASELINE --- */

uint32_t ninlil_model_domain_body_clock_baseline_encoded_length(void)
{
    return NINLIL_MODEL_DOMAIN_BODY_CLOCK_BASELINE_BYTES;
}

ninlil_status_t ninlil_model_domain_encode_body_clock_baseline(
    const ninlil_model_domain_body_clock_baseline_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    const uint32_t required = NINLIL_MODEL_DOMAIN_BODY_CLOCK_BASELINE_BYTES;
    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_alias_ok(
            body, body == NULL ? 0u : sizeof(*body),
            out_bytes, capacity, out_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || !clock_fields_ok(body)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    ninlil_model_domain_encode_u32_be(&out_bytes[0], body->baseline_state);
    ninlil_model_domain_encode_u32_be(&out_bytes[4], 0u);
    (void)memcpy(&out_bytes[8], body->trusted_clock_epoch, 16u);
    ninlil_model_domain_encode_u64_be(&out_bytes[24], body->last_trusted_now_ms);
    ninlil_model_domain_encode_u64_be(&out_bytes[32], body->publish_generation);
    *out_length = required;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_clock_baseline(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_clock_baseline_t *out_body)
{
    ninlil_model_domain_body_clock_baseline_t tmp;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length != NINLIL_MODEL_DOMAIN_BODY_CLOCK_BASELINE_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.baseline_state = ninlil_model_domain_decode_u32_be(&encoded.data[0]);
    tmp.reserved = ninlil_model_domain_decode_u32_be(&encoded.data[4]);
    (void)memcpy(tmp.trusted_clock_epoch, &encoded.data[8], 16u);
    tmp.last_trusted_now_ms =
        ninlil_model_domain_decode_u64_be(&encoded.data[24]);
    tmp.publish_generation =
        ninlil_model_domain_decode_u64_be(&encoded.data[32]);
    if (!clock_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- ATTEMPT_REUSE_FENCE --- */

uint32_t ninlil_model_domain_body_attempt_reuse_fence_encoded_length(void)
{
    return NINLIL_MODEL_DOMAIN_BODY_ATTEMPT_REUSE_FENCE_BYTES;
}

ninlil_status_t ninlil_model_domain_encode_body_attempt_reuse_fence(
    const ninlil_model_domain_body_attempt_reuse_fence_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    const uint32_t required =
        NINLIL_MODEL_DOMAIN_BODY_ATTEMPT_REUSE_FENCE_BYTES;
    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_alias_ok(
            body, body == NULL ? 0u : sizeof(*body),
            out_bytes, capacity, out_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || !fence_fields_ok(body)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    ninlil_model_domain_encode_u32_be(&out_bytes[0], body->active_plan_count);
    ninlil_model_domain_encode_u32_be(&out_bytes[4], 0u);
    ninlil_model_domain_encode_u64_be(&out_bytes[8], body->fence_generation);
    *out_length = required;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_attempt_reuse_fence(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_attempt_reuse_fence_t *out_body)
{
    ninlil_model_domain_body_attempt_reuse_fence_t tmp;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length
            != NINLIL_MODEL_DOMAIN_BODY_ATTEMPT_REUSE_FENCE_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.active_plan_count =
        ninlil_model_domain_decode_u32_be(&encoded.data[0]);
    tmp.reserved = ninlil_model_domain_decode_u32_be(&encoded.data[4]);
    tmp.fence_generation =
        ninlil_model_domain_decode_u64_be(&encoded.data[8]);
    if (!fence_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- WITNESS_HEAD_INDEX --- */

uint32_t ninlil_model_domain_body_witness_head_index_encoded_length(
    uint16_t member_key_length)
{
    /* v1: only exact family 3/4 member keys of length 10 are legal. */
    if (member_key_length
        != NINLIL_MODEL_DOMAIN_HEAD_INDEX_MEMBER_KEY_BYTES) {
        return 0u;
    }
    return NINLIL_MODEL_DOMAIN_BODY_WITNESS_HEAD_INDEX_BYTES;
}

ninlil_status_t ninlil_model_domain_encode_body_witness_head_index(
    const ninlil_model_domain_body_witness_head_index_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    uint32_t required;
    size_t n = 0u;
    const void *ptrs[4];
    size_t lens[4];

    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /* Body object range first; nested key bytes only after it is valid. */
    if (!encode_body_object_range_ok(body, sizeof(*body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (body != NULL) {
        ptrs[n] = body;
        lens[n] = sizeof(*body);
        n++;
        if (body->member_key_bytes != NULL && body->member_key_length != 0u) {
            ptrs[n] = body->member_key_bytes;
            lens[n] = body->member_key_length;
            n++;
        }
    }
    if (out_bytes != NULL && capacity != 0u) {
        ptrs[n] = out_bytes;
        lens[n] = capacity;
        n++;
    }
    ptrs[n] = out_length;
    lens[n] = sizeof(*out_length);
    n++;
    if (!multi_ranges_ok(ptrs, lens, n)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || !head_index_fields_ok(body)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    required = ninlil_model_domain_body_witness_head_index_encoded_length(
        body->member_key_length);
    if (required > NINLIL_MODEL_DOMAIN_PRIVATE_BODY_MAX_BYTES) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    ninlil_model_domain_encode_u16_be(&out_bytes[0], body->index_state);
    ninlil_model_domain_encode_u16_be(&out_bytes[2], 0u);
    (void)memcpy(&out_bytes[4], body->member_key_digest, 32u);
    ninlil_model_domain_encode_u16_be(&out_bytes[36], body->member_key_length);
    ninlil_model_domain_encode_u16_be(&out_bytes[38], 0u);
    (void)memcpy(
        &out_bytes[40], body->member_key_bytes, body->member_key_length);
    (void)memcpy(
        &out_bytes[40u + body->member_key_length],
        body->member_value_digest,
        32u);
    (void)memcpy(
        &out_bytes[72u + body->member_key_length],
        body->member_head_witness_digest,
        32u);
    *out_length = required;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_witness_head_index(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_witness_head_index_t *out_body)
{
    ninlil_model_domain_body_witness_head_index_t tmp;
    uint16_t key_len;
    uint32_t required;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length < 104u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.index_state = ninlil_model_domain_decode_u16_be(&encoded.data[0]);
    tmp.reserved0 = ninlil_model_domain_decode_u16_be(&encoded.data[2]);
    (void)memcpy(tmp.member_key_digest, &encoded.data[4], 32u);
    key_len = ninlil_model_domain_decode_u16_be(&encoded.data[36]);
    tmp.reserved1 = ninlil_model_domain_decode_u16_be(&encoded.data[38]);
    required =
        ninlil_model_domain_body_witness_head_index_encoded_length(key_len);
    if (required == 0u || encoded.length != required) {
        /* unknown key length, short, or trailing rejected */
        return NINLIL_E_STORAGE_CORRUPT;
    }
    tmp.member_key_length = key_len;
    tmp.member_key_bytes = &encoded.data[40];
    (void)memcpy(
        tmp.member_value_digest, &encoded.data[40u + key_len], 32u);
    (void)memcpy(
        tmp.member_head_witness_digest,
        &encoded.data[72u + key_len],
        32u);
    if (!head_index_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}


/* --- SERVICE --- */

uint32_t ninlil_model_domain_body_service_encoded_length(
    const ninlil_model_domain_body_service_t *body)
{
    uint32_t n = 0u;
    uint32_t t;
    if (body == NULL || !service_descriptor_contract_ok(body)) {
        return 0u;
    }
    if (!checked_add_u32(2u + (uint32_t)body->service_key_raw_length, 0u, &n)) {
        return 0u;
    }
    /* fixed after raw: 8+32+16 = 56 */
    if (!checked_add_u32(n, 56u, &n)) {
        return 0u;
    }
    t = ninlil_model_domain_text_id_encoded_length(&body->namespace_id);
    if (t == 0u || !checked_add_u32(n, t, &n)) {
        return 0u;
    }
    t = ninlil_model_domain_text_id_encoded_length(&body->service_id);
    if (t == 0u || !checked_add_u32(n, t, &n)) {
        return 0u;
    }
    t = ninlil_model_domain_text_id_encoded_length(&body->schema_id);
    if (t == 0u || !checked_add_u32(n, t, &n)) {
        return 0u;
    }
    /* schema_major+minors(6) + 13*u32(52) + 7*u64(56) + 2*digest(64) = 178
     * u32: family, direction, admission_authority, apply_contract,
     * custody_policy, supported_evidence_mask, logical_payload_limit,
     * target_limit, inflight_limit, attempts_per_cycle, admission_window_ms,
     * max_admissions_window, max_payload_window (docs17 section 8.1). */
    if (!checked_add_u32(n, 6u + 52u + 56u + 64u, &n)) {
        return 0u;
    }
    if (n > NINLIL_MODEL_DOMAIN_BODY_SERVICE_MAX) {
        return 0u;
    }
    return n;
}

ninlil_status_t ninlil_model_domain_encode_body_service(
    const ninlil_model_domain_body_service_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    uint32_t required;
    size_t n = 0u;
    const void *ptrs[4];
    size_t lens[4];
    uint32_t o;

    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_body_object_range_ok(body, sizeof(*body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (body != NULL) {
        ptrs[n] = body;
        lens[n] = sizeof(*body);
        n++;
        if (body->service_key_raw != NULL && body->service_key_raw_length != 0u) {
            ptrs[n] = body->service_key_raw;
            lens[n] = body->service_key_raw_length;
            n++;
        }
    }
    if (out_bytes != NULL && capacity != 0u) {
        ptrs[n] = out_bytes;
        lens[n] = capacity;
        n++;
    }
    ptrs[n] = out_length;
    lens[n] = sizeof(*out_length);
    n++;
    if (!multi_ranges_ok(ptrs, lens, n)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    required = ninlil_model_domain_body_service_encoded_length(body);
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || required == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    o = 0u;
    o += encode_raw16(
        &out_bytes[o], body->service_key_raw_length, body->service_key_raw);
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->descriptor_revision);
    o += 8u;
    (void)memcpy(&out_bytes[o], body->descriptor_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->local_application_instance_id, 16u);
    o += 16u;
    o += encode_text_id(&out_bytes[o], &body->namespace_id);
    o += encode_text_id(&out_bytes[o], &body->service_id);
    o += encode_text_id(&out_bytes[o], &body->schema_id);
    ninlil_model_domain_encode_u16_be(&out_bytes[o], body->schema_major);
    o += 2u;
    ninlil_model_domain_encode_u16_be(&out_bytes[o], body->minor_min);
    o += 2u;
    ninlil_model_domain_encode_u16_be(&out_bytes[o], body->minor_max);
    o += 2u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->family);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->direction);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->admission_authority);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->apply_contract);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->custody_policy);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->supported_evidence_mask);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->logical_payload_limit);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->target_limit);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->inflight_limit);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->attempts_per_cycle);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->admission_window_ms);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->max_admissions_window);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->max_payload_window);
    o += 4u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->minimum_deadline_ms);
    o += 8u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->maximum_deadline_ms);
    o += 8u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->maximum_evidence_grace_ms);
    o += 8u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->attempt_receipt_timeout_ms);
    o += 8u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->retry_backoff_ms);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->application_completion_timeout_ms);
    o += 8u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->required_dedup_window_ms);
    o += 8u;
    (void)memcpy(&out_bytes[o], body->quota_key_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->reservation_key_digest, 32u);
    o += 32u;
    *out_length = o;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_service(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_service_t *out_body)
{
    ninlil_model_domain_body_service_t tmp;
    uint32_t o = 0u;
    uint32_t c = 0u;
    uint32_t rem;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length == 0u
        || encoded.length > NINLIL_MODEL_DOMAIN_BODY_SERVICE_MAX) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    rem = encoded.length;
    if (!decode_raw16_view(
            encoded.data + o, rem - o,
            (uint16_t)NINLIL_MODEL_DOMAIN_RAW16_SERVICE_KEY_MAX,
            &tmp.service_key_raw_length, &tmp.service_key_raw, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += c;
    if (rem - o < 56u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    tmp.descriptor_revision =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    (void)memcpy(tmp.descriptor_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.local_application_instance_id, &encoded.data[o], 16u);
    o += 16u;
    if (!decode_text_id(
            encoded.data + o, rem - o, &tmp.namespace_id, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += c;
    if (!decode_text_id(
            encoded.data + o, rem - o, &tmp.service_id, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += c;
    if (!decode_text_id(
            encoded.data + o, rem - o, &tmp.schema_id, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += c;
    /* 13*u32 + 7*u64 + 2*digest after schema majors (see encoded_length). */
    if (rem - o < 6u + 52u + 56u + 64u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    tmp.schema_major = ninlil_model_domain_decode_u16_be(&encoded.data[o]);
    o += 2u;
    tmp.minor_min = ninlil_model_domain_decode_u16_be(&encoded.data[o]);
    o += 2u;
    tmp.minor_max = ninlil_model_domain_decode_u16_be(&encoded.data[o]);
    o += 2u;
    tmp.family = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.direction = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.admission_authority =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.apply_contract = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.custody_policy = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.supported_evidence_mask =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.logical_payload_limit =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.target_limit = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.inflight_limit = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.attempts_per_cycle =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.admission_window_ms =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.max_admissions_window =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.max_payload_window =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.minimum_deadline_ms =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.maximum_deadline_ms =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.maximum_evidence_grace_ms =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.attempt_receipt_timeout_ms =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.retry_backoff_ms = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.application_completion_timeout_ms =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.required_dedup_window_ms =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    (void)memcpy(tmp.quota_key_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.reservation_key_digest, &encoded.data[o], 32u);
    o += 32u;
    if (o != encoded.length || !service_descriptor_contract_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- SERVICE_QUOTA --- */

uint32_t ninlil_model_domain_body_service_quota_encoded_length(
    const ninlil_model_domain_body_service_quota_t *body)
{
    uint32_t n;
    if (body == NULL || !service_quota_fields_ok(body)) {
        return 0u;
    }
    n = 2u + (uint32_t)body->service_key_raw_length + 32u + 16u + 8u + 4u + 8u
        + 4u + 4u + 8u;
    if (n > NINLIL_MODEL_DOMAIN_BODY_SERVICE_QUOTA_MAX) {
        return 0u;
    }
    return n;
}

ninlil_status_t ninlil_model_domain_encode_body_service_quota(
    const ninlil_model_domain_body_service_quota_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    uint32_t required;
    size_t n = 0u;
    const void *ptrs[4];
    size_t lens[4];
    uint32_t o;

    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_body_object_range_ok(body, sizeof(*body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (body != NULL) {
        ptrs[n] = body;
        lens[n] = sizeof(*body);
        n++;
        if (body->service_key_raw != NULL && body->service_key_raw_length != 0u) {
            ptrs[n] = body->service_key_raw;
            lens[n] = body->service_key_raw_length;
            n++;
        }
    }
    if (out_bytes != NULL && capacity != 0u) {
        ptrs[n] = out_bytes;
        lens[n] = capacity;
        n++;
    }
    ptrs[n] = out_length;
    lens[n] = sizeof(*out_length);
    n++;
    if (!multi_ranges_ok(ptrs, lens, n)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    required = ninlil_model_domain_body_service_quota_encoded_length(body);
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || required == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    o = encode_raw16(
        out_bytes, body->service_key_raw_length, body->service_key_raw);
    (void)memcpy(&out_bytes[o], body->service_key_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->window_clock_epoch, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->window_start_ms);
    o += 8u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->admissions_in_window);
    o += 4u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->payload_bytes_in_window);
    o += 8u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->active_transaction_count);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->active_spool_count);
    o += 4u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->active_spool_bytes);
    o += 8u;
    *out_length = o;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_service_quota(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_service_quota_t *out_body)
{
    ninlil_model_domain_body_service_quota_t tmp;
    uint32_t o = 0u;
    uint32_t c = 0u;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length == 0u
        || encoded.length > NINLIL_MODEL_DOMAIN_BODY_SERVICE_QUOTA_MAX) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    if (!decode_raw16_view(
            encoded.data, encoded.length,
            (uint16_t)NINLIL_MODEL_DOMAIN_RAW16_SERVICE_KEY_MAX,
            &tmp.service_key_raw_length, &tmp.service_key_raw, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o = c;
    if (encoded.length - o < 32u + 16u + 8u + 4u + 8u + 4u + 4u + 8u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(tmp.service_key_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.window_clock_epoch, &encoded.data[o], 16u);
    o += 16u;
    tmp.window_start_ms = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.admissions_in_window =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.payload_bytes_in_window =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.active_transaction_count =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.active_spool_count =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.active_spool_bytes =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    if (o != encoded.length || !service_quota_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}


/* --- TRANSACTION_ANCHOR --- */

uint32_t ninlil_model_domain_body_transaction_anchor_encoded_length(
    const ninlil_model_domain_body_transaction_anchor_t *body)
{
    uint32_t n = 0u;
    uint32_t t;
    if (body == NULL || !transaction_anchor_fields_ok(body)) {
        return 0u;
    }
    /* txn_id(16)+seq(8)+sched(8)+family(4) = 36 */
    n = 36u;
    if (!checked_add_u32(n, NINLIL_MODEL_DOMAIN_PARTY_BYTES, &n)) {
        return 0u;
    }
    t = ninlil_model_domain_service_identity_encoded_length(&body->service);
    if (t == 0u || !checked_add_u32(n, t, &n)) {
        return 0u;
    }
    /* content+canon digests 64 + event 16 + gen 8 + adm epoch 16 + adm ms 8
     * + ddl epoch 16 + abs ddl 8 + grace 8 + req_ev 4 + tcount 4 + TARGET 100
     * + 2 RAW16 + 4 digests 128 + sched_key_seq 8 + payload dig 32 */
    if (!checked_add_u32(n, 64u + 16u + 8u + 16u + 8u + 16u + 8u + 8u + 4u + 4u
            + NINLIL_MODEL_DOMAIN_TARGET_BYTES, &n)) {
        return 0u;
    }
    if (!checked_add_u32(
            n, 2u + (uint32_t)body->idempotency_scope_raw_length, &n)) {
        return 0u;
    }
    if (!checked_add_u32(
            n, 2u + (uint32_t)body->idempotency_key_length, &n)) {
        return 0u;
    }
    if (!checked_add_u32(n, 128u + 8u + 32u, &n)) {
        return 0u;
    }
    if (n > NINLIL_MODEL_DOMAIN_BODY_TRANSACTION_ANCHOR_MAX) {
        return 0u;
    }
    return n;
}

static int anchor_alias_ok(
    const ninlil_model_domain_body_transaction_anchor_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    size_t n = 0u;
    const void *ptrs[6];
    size_t lens[6];
    /* Body object range first; nested RAW16 ranges only after it is valid. */
    if (!encode_body_object_range_ok(body, sizeof(*body))) {
        return 0;
    }
    if (body != NULL) {
        ptrs[n] = body;
        lens[n] = sizeof(*body);
        n++;
        if (body->idempotency_scope_raw != NULL
            && body->idempotency_scope_raw_length != 0u) {
            ptrs[n] = body->idempotency_scope_raw;
            lens[n] = body->idempotency_scope_raw_length;
            n++;
        }
        if (body->idempotency_key != NULL
            && body->idempotency_key_length != 0u) {
            ptrs[n] = body->idempotency_key;
            lens[n] = body->idempotency_key_length;
            n++;
        }
    }
    if (out_bytes != NULL && capacity != 0u) {
        ptrs[n] = out_bytes;
        lens[n] = capacity;
        n++;
    }
    if (out_length != NULL) {
        ptrs[n] = out_length;
        lens[n] = sizeof(*out_length);
        n++;
    }
    return multi_ranges_ok(ptrs, lens, n);
}

ninlil_status_t ninlil_model_domain_encode_body_transaction_anchor(
    const ninlil_model_domain_body_transaction_anchor_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    uint32_t required;
    uint32_t o;

    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!anchor_alias_ok(body, out_bytes, capacity, out_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    required = ninlil_model_domain_body_transaction_anchor_encoded_length(body);
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || required == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    o = 0u;
    (void)memcpy(&out_bytes[o], body->transaction_id, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->transaction_sequence);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->scheduler_owner_sequence);
    o += 8u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->family);
    o += 4u;
    encode_party(&out_bytes[o], &body->source);
    o += NINLIL_MODEL_DOMAIN_PARTY_BYTES;
    o += encode_service_identity(&out_bytes[o], &body->service);
    (void)memcpy(&out_bytes[o], body->content_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->canonical_submission_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->event_id, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->generation);
    o += 8u;
    (void)memcpy(&out_bytes[o], body->admission_clock_epoch, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->admitted_at_ms);
    o += 8u;
    (void)memcpy(&out_bytes[o], body->deadline_clock_epoch, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->absolute_effect_deadline_ms);
    o += 8u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->evidence_grace_ms);
    o += 8u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->required_evidence);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->target_count);
    o += 4u;
    encode_target(&out_bytes[o], &body->target);
    o += NINLIL_MODEL_DOMAIN_TARGET_BYTES;
    o += encode_raw16(
        &out_bytes[o], body->idempotency_scope_raw_length,
        body->idempotency_scope_raw);
    o += encode_raw16(
        &out_bytes[o], body->idempotency_key_length, body->idempotency_key);
    (void)memcpy(&out_bytes[o], body->sequence_index_key_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->idempotency_map_key_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->event_map_key_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->reservation_key_digest, 32u);
    o += 32u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->scheduler_owner_key_sequence);
    o += 8u;
    (void)memcpy(&out_bytes[o], body->payload_blob_key_digest, 32u);
    o += 32u;
    *out_length = o;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_transaction_anchor(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_transaction_anchor_t *out_body)
{
    ninlil_model_domain_body_transaction_anchor_t tmp;
    uint32_t o = 0u;
    uint32_t c = 0u;
    uint32_t rem;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length == 0u
        || encoded.length > NINLIL_MODEL_DOMAIN_BODY_TRANSACTION_ANCHOR_MAX) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    rem = encoded.length;
    if (rem < 36u + NINLIL_MODEL_DOMAIN_PARTY_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(tmp.transaction_id, &encoded.data[o], 16u);
    o += 16u;
    tmp.transaction_sequence =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.scheduler_owner_sequence =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.family = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    decode_party(&encoded.data[o], &tmp.source);
    o += NINLIL_MODEL_DOMAIN_PARTY_BYTES;
    if (!decode_service_identity(
            encoded.data + o, rem - o, &tmp.service, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += c;
    if (rem - o < 64u + 16u + 8u + 16u + 8u + 16u + 8u + 8u + 4u + 4u
            + NINLIL_MODEL_DOMAIN_TARGET_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(tmp.content_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.canonical_submission_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.event_id, &encoded.data[o], 16u);
    o += 16u;
    tmp.generation = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    (void)memcpy(tmp.admission_clock_epoch, &encoded.data[o], 16u);
    o += 16u;
    tmp.admitted_at_ms = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    (void)memcpy(tmp.deadline_clock_epoch, &encoded.data[o], 16u);
    o += 16u;
    tmp.absolute_effect_deadline_ms =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.evidence_grace_ms =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.required_evidence =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.target_count = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    decode_target(&encoded.data[o], &tmp.target);
    o += NINLIL_MODEL_DOMAIN_TARGET_BYTES;
    if (!decode_raw16_view(
            encoded.data + o, rem - o,
            (uint16_t)NINLIL_MODEL_DOMAIN_RAW16_SCOPE_MAX,
            &tmp.idempotency_scope_raw_length, &tmp.idempotency_scope_raw,
            &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += c;
    if (!decode_raw16_view(
            encoded.data + o, rem - o,
            (uint16_t)NINLIL_MODEL_DOMAIN_RAW16_IDEMPOTENCY_KEY_MAX,
            &tmp.idempotency_key_length, &tmp.idempotency_key, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += c;
    if (rem - o < 128u + 8u + 32u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(tmp.sequence_index_key_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.idempotency_map_key_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.event_map_key_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.reservation_key_digest, &encoded.data[o], 32u);
    o += 32u;
    tmp.scheduler_owner_key_sequence =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    (void)memcpy(tmp.payload_blob_key_digest, &encoded.data[o], 32u);
    o += 32u;
    if (o != encoded.length || !transaction_anchor_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- TRANSACTION_SEQUENCE_INDEX --- */

uint32_t ninlil_model_domain_body_transaction_sequence_index_encoded_length(
    void)
{
    return NINLIL_MODEL_DOMAIN_BODY_TRANSACTION_SEQUENCE_INDEX_BYTES;
}

ninlil_status_t ninlil_model_domain_encode_body_transaction_sequence_index(
    const ninlil_model_domain_body_transaction_sequence_index_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    const uint32_t required =
        NINLIL_MODEL_DOMAIN_BODY_TRANSACTION_SEQUENCE_INDEX_BYTES;
    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_alias_ok(
            body, body == NULL ? 0u : sizeof(*body),
            out_bytes, capacity, out_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || !sequence_index_fields_ok(body)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    ninlil_model_domain_encode_u64_be(&out_bytes[0], body->transaction_sequence);
    (void)memcpy(&out_bytes[8], body->transaction_id, 16u);
    (void)memcpy(&out_bytes[24], body->anchor_value_digest, 32u);
    *out_length = required;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_transaction_sequence_index(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_transaction_sequence_index_t *out_body)
{
    ninlil_model_domain_body_transaction_sequence_index_t tmp;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length
            != NINLIL_MODEL_DOMAIN_BODY_TRANSACTION_SEQUENCE_INDEX_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.transaction_sequence =
        ninlil_model_domain_decode_u64_be(&encoded.data[0]);
    (void)memcpy(tmp.transaction_id, &encoded.data[8], 16u);
    (void)memcpy(tmp.anchor_value_digest, &encoded.data[24], 32u);
    if (!sequence_index_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- TRANSACTION_STATE --- */

uint32_t ninlil_model_domain_body_transaction_state_encoded_length(void)
{
    return NINLIL_MODEL_DOMAIN_BODY_TRANSACTION_STATE_BYTES;
}

ninlil_status_t ninlil_model_domain_encode_body_transaction_state(
    const ninlil_model_domain_body_transaction_state_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    const uint32_t required =
        NINLIL_MODEL_DOMAIN_BODY_TRANSACTION_STATE_BYTES;
    uint32_t o;
    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_alias_ok(
            body, body == NULL ? 0u : sizeof(*body),
            out_bytes, capacity, out_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || !transaction_state_fields_ok(body)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    o = 0u;
    (void)memcpy(&out_bytes[o], body->transaction_id, 16u);
    o += 16u;
    (void)memcpy(&out_bytes[o], body->anchor_value_digest, 32u);
    o += 32u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->state);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->outcome);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->deadline_verdict);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->latest_evidence);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->reason);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->event_park_cause);
    o += 4u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->retry_cycle_id);
    o += 8u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->attempt_in_cycle);
    o += 4u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->cumulative_attempts);
    o += 8u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->event_spool_revision);
    o += 8u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->has_late_evidence);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->explicitly_discarded);
    o += 4u;
    encode_target(&out_bytes[o], &body->target);
    o += NINLIL_MODEL_DOMAIN_TARGET_BYTES;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->target_state);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->target_outcome);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->target_reason);
    o += 4u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->target_latest_evidence);
    o += 4u;
    *out_length = o;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_transaction_state(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_transaction_state_t *out_body)
{
    ninlil_model_domain_body_transaction_state_t tmp;
    uint32_t o = 0u;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length
            != NINLIL_MODEL_DOMAIN_BODY_TRANSACTION_STATE_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    (void)memcpy(tmp.transaction_id, &encoded.data[o], 16u);
    o += 16u;
    (void)memcpy(tmp.anchor_value_digest, &encoded.data[o], 32u);
    o += 32u;
    tmp.state = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.outcome = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.deadline_verdict = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.latest_evidence = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.reason = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.event_park_cause = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.retry_cycle_id = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.attempt_in_cycle = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.cumulative_attempts =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.event_spool_revision =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.has_late_evidence =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.explicitly_discarded =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    decode_target(&encoded.data[o], &tmp.target);
    o += NINLIL_MODEL_DOMAIN_TARGET_BYTES;
    tmp.target_state = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.target_outcome = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.target_reason = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.target_latest_evidence =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    if (o != encoded.length || !transaction_state_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}


/* --- RESERVATION --- */

uint32_t ninlil_model_domain_body_reservation_encoded_length(
    const ninlil_model_domain_body_reservation_t *body)
{
    uint32_t n;
    if (body == NULL || !reservation_fields_ok(body)) {
        return 0u;
    }
    n = 4u + 2u + (uint32_t)body->owner_key_raw_length + 32u
        + NINLIL_MODEL_DOMAIN_RESOURCE_VECTOR_BYTES + 4u + 4u + 8u + 4u;
    if (n > NINLIL_MODEL_DOMAIN_BODY_RESERVATION_MAX) {
        return 0u;
    }
    return n;
}

ninlil_status_t ninlil_model_domain_encode_body_reservation(
    const ninlil_model_domain_body_reservation_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    uint32_t required;
    size_t n = 0u;
    const void *ptrs[4];
    size_t lens[4];
    uint32_t o;

    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_body_object_range_ok(body, sizeof(*body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (body != NULL) {
        ptrs[n] = body;
        lens[n] = sizeof(*body);
        n++;
        if (body->owner_key_raw != NULL && body->owner_key_raw_length != 0u) {
            ptrs[n] = body->owner_key_raw;
            lens[n] = body->owner_key_raw_length;
            n++;
        }
    }
    if (out_bytes != NULL && capacity != 0u) {
        ptrs[n] = out_bytes;
        lens[n] = capacity;
        n++;
    }
    ptrs[n] = out_length;
    lens[n] = sizeof(*out_length);
    n++;
    if (!multi_ranges_ok(ptrs, lens, n)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    required = ninlil_model_domain_body_reservation_encoded_length(body);
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || required == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    ninlil_model_domain_encode_u16_be(&out_bytes[0], body->owner_kind);
    ninlil_model_domain_encode_u16_be(&out_bytes[2], 0u);
    o = 4u;
    o += encode_raw16(
        &out_bytes[o], body->owner_key_raw_length, body->owner_key_raw);
    (void)memcpy(&out_bytes[o], body->primary_key_digest, 32u);
    o += 32u;
    encode_resource_vector(&out_bytes[o], &body->resources);
    o += NINLIL_MODEL_DOMAIN_RESOURCE_VECTOR_BYTES;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->service_inflight);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->grant_active_count);
    o += 4u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->grant_active_bytes);
    o += 8u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->released_mask);
    o += 4u;
    *out_length = o;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_reservation(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_reservation_t *out_body)
{
    ninlil_model_domain_body_reservation_t tmp;
    uint32_t o = 0u;
    uint32_t c = 0u;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length < 4u + 2u
        || encoded.length > NINLIL_MODEL_DOMAIN_BODY_RESERVATION_MAX) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.owner_kind = ninlil_model_domain_decode_u16_be(&encoded.data[0]);
    tmp.reserved = ninlil_model_domain_decode_u16_be(&encoded.data[2]);
    o = 4u;
    if (!decode_raw16_view(
            encoded.data + o, encoded.length - o,
            (uint16_t)NINLIL_MODEL_DOMAIN_RAW16_OWNER_KEY_MAX,
            &tmp.owner_key_raw_length, &tmp.owner_key_raw, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += c;
    if (encoded.length - o
        < 32u + NINLIL_MODEL_DOMAIN_RESOURCE_VECTOR_BYTES + 20u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(tmp.primary_key_digest, &encoded.data[o], 32u);
    o += 32u;
    decode_resource_vector(&encoded.data[o], &tmp.resources);
    o += NINLIL_MODEL_DOMAIN_RESOURCE_VECTOR_BYTES;
    tmp.service_inflight = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.grant_active_count =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.grant_active_bytes =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.released_mask = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    if (o != encoded.length || !reservation_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- IDEMPOTENCY_MAP --- */

uint32_t ninlil_model_domain_body_idempotency_map_encoded_length(
    const ninlil_model_domain_body_idempotency_map_t *body)
{
    uint32_t n;
    if (body == NULL || !idempotency_map_fields_ok(body)) {
        return 0u;
    }
    n = 2u + (uint32_t)body->scope_raw_length + 2u
        + (uint32_t)body->idempotency_key_length + 16u + 32u + 32u;
    if (n > NINLIL_MODEL_DOMAIN_BODY_IDEMPOTENCY_MAP_MAX) {
        return 0u;
    }
    return n;
}

ninlil_status_t ninlil_model_domain_encode_body_idempotency_map(
    const ninlil_model_domain_body_idempotency_map_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    uint32_t required;
    size_t n = 0u;
    const void *ptrs[5];
    size_t lens[5];
    uint32_t o;

    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_body_object_range_ok(body, sizeof(*body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (body != NULL) {
        ptrs[n] = body;
        lens[n] = sizeof(*body);
        n++;
        if (body->scope_raw != NULL && body->scope_raw_length != 0u) {
            ptrs[n] = body->scope_raw;
            lens[n] = body->scope_raw_length;
            n++;
        }
        if (body->idempotency_key != NULL && body->idempotency_key_length != 0u) {
            ptrs[n] = body->idempotency_key;
            lens[n] = body->idempotency_key_length;
            n++;
        }
    }
    if (out_bytes != NULL && capacity != 0u) {
        ptrs[n] = out_bytes;
        lens[n] = capacity;
        n++;
    }
    ptrs[n] = out_length;
    lens[n] = sizeof(*out_length);
    n++;
    if (!multi_ranges_ok(ptrs, lens, n)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    required = ninlil_model_domain_body_idempotency_map_encoded_length(body);
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || required == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    o = encode_raw16(out_bytes, body->scope_raw_length, body->scope_raw);
    o += encode_raw16(
        &out_bytes[o], body->idempotency_key_length, body->idempotency_key);
    (void)memcpy(&out_bytes[o], body->transaction_id, 16u);
    o += 16u;
    (void)memcpy(&out_bytes[o], body->canonical_submission_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->anchor_value_digest, 32u);
    o += 32u;
    *out_length = o;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_idempotency_map(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_idempotency_map_t *out_body)
{
    ninlil_model_domain_body_idempotency_map_t tmp;
    uint32_t o = 0u;
    uint32_t c = 0u;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length == 0u
        || encoded.length > NINLIL_MODEL_DOMAIN_BODY_IDEMPOTENCY_MAP_MAX) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    if (!decode_raw16_view(
            encoded.data, encoded.length,
            (uint16_t)NINLIL_MODEL_DOMAIN_RAW16_SCOPE_MAX,
            &tmp.scope_raw_length, &tmp.scope_raw, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o = c;
    if (!decode_raw16_view(
            encoded.data + o, encoded.length - o,
            (uint16_t)NINLIL_MODEL_DOMAIN_RAW16_IDEMPOTENCY_KEY_MAX,
            &tmp.idempotency_key_length, &tmp.idempotency_key, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += c;
    if (encoded.length - o < 16u + 32u + 32u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(tmp.transaction_id, &encoded.data[o], 16u);
    o += 16u;
    (void)memcpy(tmp.canonical_submission_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.anchor_value_digest, &encoded.data[o], 32u);
    o += 32u;
    if (o != encoded.length || !idempotency_map_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- EVENT_ID_MAP --- */

uint32_t ninlil_model_domain_body_event_id_map_encoded_length(
    const ninlil_model_domain_body_event_id_map_t *body)
{
    uint32_t n;
    if (body == NULL || !event_id_map_fields_ok(body)) {
        return 0u;
    }
    n = 2u + (uint32_t)body->scope_raw_length + 16u + 16u + 32u + 2u
        + (uint32_t)body->idempotency_key_length + 32u;
    if (n > NINLIL_MODEL_DOMAIN_BODY_EVENT_ID_MAP_MAX) {
        return 0u;
    }
    return n;
}

ninlil_status_t ninlil_model_domain_encode_body_event_id_map(
    const ninlil_model_domain_body_event_id_map_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    uint32_t required;
    size_t n = 0u;
    const void *ptrs[5];
    size_t lens[5];
    uint32_t o;

    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_body_object_range_ok(body, sizeof(*body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (body != NULL) {
        ptrs[n] = body;
        lens[n] = sizeof(*body);
        n++;
        if (body->scope_raw != NULL && body->scope_raw_length != 0u) {
            ptrs[n] = body->scope_raw;
            lens[n] = body->scope_raw_length;
            n++;
        }
        if (body->idempotency_key != NULL && body->idempotency_key_length != 0u) {
            ptrs[n] = body->idempotency_key;
            lens[n] = body->idempotency_key_length;
            n++;
        }
    }
    if (out_bytes != NULL && capacity != 0u) {
        ptrs[n] = out_bytes;
        lens[n] = capacity;
        n++;
    }
    ptrs[n] = out_length;
    lens[n] = sizeof(*out_length);
    n++;
    if (!multi_ranges_ok(ptrs, lens, n)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    required = ninlil_model_domain_body_event_id_map_encoded_length(body);
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || required == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    o = encode_raw16(out_bytes, body->scope_raw_length, body->scope_raw);
    (void)memcpy(&out_bytes[o], body->event_id, 16u);
    o += 16u;
    (void)memcpy(&out_bytes[o], body->transaction_id, 16u);
    o += 16u;
    (void)memcpy(&out_bytes[o], body->canonical_submission_digest, 32u);
    o += 32u;
    o += encode_raw16(
        &out_bytes[o], body->idempotency_key_length, body->idempotency_key);
    (void)memcpy(&out_bytes[o], body->anchor_value_digest, 32u);
    o += 32u;
    *out_length = o;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_event_id_map(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_event_id_map_t *out_body)
{
    ninlil_model_domain_body_event_id_map_t tmp;
    uint32_t o = 0u;
    uint32_t c = 0u;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length == 0u
        || encoded.length > NINLIL_MODEL_DOMAIN_BODY_EVENT_ID_MAP_MAX) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    if (!decode_raw16_view(
            encoded.data, encoded.length,
            (uint16_t)NINLIL_MODEL_DOMAIN_RAW16_SCOPE_MAX,
            &tmp.scope_raw_length, &tmp.scope_raw, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o = c;
    if (encoded.length - o < 16u + 16u + 32u + 2u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(tmp.event_id, &encoded.data[o], 16u);
    o += 16u;
    (void)memcpy(tmp.transaction_id, &encoded.data[o], 16u);
    o += 16u;
    (void)memcpy(tmp.canonical_submission_digest, &encoded.data[o], 32u);
    o += 32u;
    if (!decode_raw16_view(
            encoded.data + o, encoded.length - o,
            (uint16_t)NINLIL_MODEL_DOMAIN_RAW16_IDEMPOTENCY_KEY_MAX,
            &tmp.idempotency_key_length, &tmp.idempotency_key, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += c;
    if (encoded.length - o < 32u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(tmp.anchor_value_digest, &encoded.data[o], 32u);
    o += 32u;
    if (o != encoded.length || !event_id_map_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- SCHEDULER_OWNER --- */

uint32_t ninlil_model_domain_body_scheduler_owner_encoded_length(
    const ninlil_model_domain_body_scheduler_owner_t *body)
{
    uint32_t n;
    if (body == NULL || !scheduler_owner_fields_ok(body)) {
        return 0u;
    }
    /* u64+u16+u16 + RAW16 + dig32 + u64 + id16 + u64 + id16 + u64 + u32 */
    n = 8u + 2u + 2u + 2u + (uint32_t)body->subject_key_raw_length + 32u
        + 8u + 16u + 8u + 16u + 8u + 4u;
    if (n > NINLIL_MODEL_DOMAIN_BODY_SCHEDULER_OWNER_MAX) {
        return 0u;
    }
    return n;
}

ninlil_status_t ninlil_model_domain_encode_body_scheduler_owner(
    const ninlil_model_domain_body_scheduler_owner_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    uint32_t required;
    size_t n = 0u;
    const void *ptrs[4];
    size_t lens[4];
    uint32_t o;

    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_body_object_range_ok(body, sizeof(*body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (body != NULL) {
        ptrs[n] = body;
        lens[n] = sizeof(*body);
        n++;
        if (body->subject_key_raw != NULL && body->subject_key_raw_length != 0u) {
            ptrs[n] = body->subject_key_raw;
            lens[n] = body->subject_key_raw_length;
            n++;
        }
    }
    if (out_bytes != NULL && capacity != 0u) {
        ptrs[n] = out_bytes;
        lens[n] = capacity;
        n++;
    }
    ptrs[n] = out_length;
    lens[n] = sizeof(*out_length);
    n++;
    if (!multi_ranges_ok(ptrs, lens, n)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    required = ninlil_model_domain_body_scheduler_owner_encoded_length(body);
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || required == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    ninlil_model_domain_encode_u64_be(&out_bytes[0], body->owner_sequence);
    ninlil_model_domain_encode_u16_be(&out_bytes[8], body->owner_kind);
    ninlil_model_domain_encode_u16_be(&out_bytes[10], body->work_class);
    o = 12u;
    o += encode_raw16(
        &out_bytes[o], body->subject_key_raw_length, body->subject_key_raw);
    (void)memcpy(&out_bytes[o], body->primary_key_digest, 32u);
    o += 32u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->state_revision);
    o += 8u;
    (void)memcpy(&out_bytes[o], body->logical_clock_epoch, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->logical_at_ms);
    o += 8u;
    (void)memcpy(&out_bytes[o], body->next_wake_clock_epoch, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->next_wake_at_ms);
    o += 8u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->ready);
    o += 4u;
    *out_length = o;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_scheduler_owner(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_scheduler_owner_t *out_body)
{
    ninlil_model_domain_body_scheduler_owner_t tmp;
    uint32_t o = 0u;
    uint32_t c = 0u;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length < 12u + 2u
        || encoded.length > NINLIL_MODEL_DOMAIN_BODY_SCHEDULER_OWNER_MAX) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.owner_sequence = ninlil_model_domain_decode_u64_be(&encoded.data[0]);
    tmp.owner_kind = ninlil_model_domain_decode_u16_be(&encoded.data[8]);
    tmp.work_class = ninlil_model_domain_decode_u16_be(&encoded.data[10]);
    o = 12u;
    if (!decode_raw16_view(
            encoded.data + o, encoded.length - o,
            (uint16_t)NINLIL_MODEL_DOMAIN_RAW16_SUBJECT_KEY_MAX,
            &tmp.subject_key_raw_length, &tmp.subject_key_raw, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += c;
    /* dig32 + u64 + id16 + u64 + id16 + u64 + u32 = 92 */
    if (encoded.length - o < 92u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(tmp.primary_key_digest, &encoded.data[o], 32u);
    o += 32u;
    tmp.state_revision = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    (void)memcpy(tmp.logical_clock_epoch, &encoded.data[o], 16u);
    o += 16u;
    tmp.logical_at_ms = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    (void)memcpy(tmp.next_wake_clock_epoch, &encoded.data[o], 16u);
    o += 16u;
    tmp.next_wake_at_ms = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.ready = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    if (o != encoded.length || !scheduler_owner_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}


/* --- typed record validation --- */

static int subtype_is_d1b_supported(uint8_t family, uint8_t subtype)
{
    if (family == NINLIL_MODEL_DOMAIN_FAMILY_HEALTH
        && subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_INTERNAL_INVARIANT) {
        return 1;
    }
    if (family != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN) {
        return 0;
    }
    switch (subtype) {
    case NINLIL_MODEL_DOMAIN_SUBTYPE_BEARER_STATE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_REUSE_FENCE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE_QUOTA:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_SEQUENCE_INDEX:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_ID_MAP:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SCHEDULER_OWNER:
        return 1;
    default:
        return 0;
    }
}

static int primary_allows_zero_pvd(uint8_t family, uint8_t subtype)
{
    if (family == NINLIL_MODEL_DOMAIN_FAMILY_HEALTH) {
        return 1;
    }
    return subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_BEARER_STATE
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_REUSE_FENCE
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK;
}

static int allows_zero_head(uint8_t family, uint8_t subtype)
{
    if (family == NINLIL_MODEL_DOMAIN_FAMILY_HEALTH
        && subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_INTERNAL_INVARIANT) {
        return 1;
    }
    return subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK;
}

/*
 * docs17 §4: primary_id is own identity only for primary records; for
 * secondaries it is the referenced primary identity. Common validation must
 * not impose own-key primary_id on secondaries — each typed branch validates
 * the exact expected primary after body decode. primary_value_digest remains
 * zero/non-zero by primary vs secondary role (orthogonal to primary_id).
 */
static int header_primary_id_eq(
    const ninlil_model_domain_envelope_t *env,
    const uint8_t expect[NINLIL_MODEL_DOMAIN_ID_BYTES])
{
    return memcmp(
               env->header.primary_id, expect, NINLIL_MODEL_DOMAIN_ID_BYTES)
        == 0;
}

static ninlil_status_t primary_id_from_own_key(
    const ninlil_model_domain_key_view_t *key,
    uint8_t out_primary_id[NINLIL_MODEL_DOMAIN_ID_BYTES])
{
    ninlil_bytes_view_t identity;

    identity.data = key->identity;
    identity.length = key->identity_length;
    if (ninlil_model_domain_primary_id_from_identity(
            key->identity_kind, identity, out_primary_id)
        != NINLIL_OK) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    return NINLIL_OK;
}

static ninlil_status_t primary_id_from_composite_components(
    uint8_t primary_subtype,
    ninlil_bytes_view_t components,
    uint8_t out_primary_id[NINLIL_MODEL_DOMAIN_ID_BYTES])
{
    ninlil_model_domain_digest_t dig;

    if (ninlil_model_domain_composite_digest(
            primary_subtype, components, &dig)
        != NINLIL_OK) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(out_primary_id, dig.bytes, NINLIL_MODEL_DOMAIN_ID_BYTES);
    return NINLIL_OK;
}

/* COMPOSITE(primary_subtype, raw_contents:RAW16) first 16 bytes. */
static ninlil_status_t primary_id_from_raw_contents_as_raw16(
    uint8_t primary_subtype,
    uint16_t raw_length,
    const uint8_t *raw,
    uint8_t out_primary_id[NINLIL_MODEL_DOMAIN_ID_BYTES])
{
    uint8_t raw16[257];
    ninlil_bytes_view_t components;

    if (raw_length > 255u || (raw_length != 0u && raw == NULL)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    ninlil_model_domain_encode_u16_be(raw16, raw_length);
    if (raw_length != 0u) {
        (void)memcpy(&raw16[2], raw, raw_length);
    }
    components.data = raw16;
    components.length = 2u + (uint32_t)raw_length;
    return primary_id_from_composite_components(
        primary_subtype, components, out_primary_id);
}

/*
 * RESERVATION common primary_id is the owner primary identity (docs17 §4/§9):
 * SERVICE → SERVICE composite(service_key_raw:RAW16) first 16
 * TRANSACTION → transaction_id
 * INGRESS → ordered_sequence u64 left-zero-padded
 * DELIVERY / CALLBACK → DELIVERY composite(delivery_key_raw:RAW16) first 16
 *   (CALLBACK owner raw = delivery_key_raw:RAW16 || token_generation:u64)
 */
static ninlil_status_t reservation_expected_primary_id(
    const ninlil_model_domain_body_reservation_t *body,
    uint8_t out_primary_id[NINLIL_MODEL_DOMAIN_ID_BYTES])
{
    switch (body->owner_kind) {
    case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_SERVICE:
        return primary_id_from_raw_contents_as_raw16(
            NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE,
            body->owner_key_raw_length,
            body->owner_key_raw,
            out_primary_id);
    case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_TRANSACTION:
        if (body->owner_key_raw_length != 16u || body->owner_key_raw == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        (void)memcpy(out_primary_id, body->owner_key_raw, 16u);
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_INGRESS:
        if (body->owner_key_raw_length != 8u || body->owner_key_raw == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        (void)memset(out_primary_id, 0, NINLIL_MODEL_DOMAIN_ID_BYTES);
        (void)memcpy(&out_primary_id[8], body->owner_key_raw, 8u);
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_DELIVERY:
        return primary_id_from_raw_contents_as_raw16(
            NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
            body->owner_key_raw_length,
            body->owner_key_raw,
            out_primary_id);
    case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_CALLBACK: {
        uint16_t dlen;
        ninlil_bytes_view_t components;

        if (body->owner_key_raw == NULL
            || body->owner_key_raw_length < 2u + 8u) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        dlen = ninlil_model_domain_decode_u16_be(body->owner_key_raw);
        if (dlen != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES
            || (uint32_t)body->owner_key_raw_length
                != 2u + (uint32_t)dlen + 8u) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        /* Prefix is already delivery_key_raw:RAW16 for DELIVERY composite. */
        components.data = body->owner_key_raw;
        components.length = 2u + (uint32_t)dlen;
        return primary_id_from_composite_components(
            NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY, components, out_primary_id);
    }
    default:
        return NINLIL_E_STORAGE_CORRUPT;
    }
}

/*
 * SCHEDULER common primary_id is the referenced primary identity (docs17 §4/§9):
 * TRANSACTION → transaction_id
 * DELIVERY → DELIVERY composite(delivery_key_raw:RAW16) first 16
 * INGRESS → ordered_sequence u64 left-zero-padded
 * Not the SCHEDULER key's owner_sequence when different.
 */
static ninlil_status_t scheduler_expected_primary_id(
    const ninlil_model_domain_body_scheduler_owner_t *body,
    uint8_t out_primary_id[NINLIL_MODEL_DOMAIN_ID_BYTES])
{
    switch (body->owner_kind) {
    case NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_TRANSACTION:
        if (body->subject_key_raw_length != 16u
            || body->subject_key_raw == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        (void)memcpy(out_primary_id, body->subject_key_raw, 16u);
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_DELIVERY:
        return primary_id_from_raw_contents_as_raw16(
            NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
            body->subject_key_raw_length,
            body->subject_key_raw,
            out_primary_id);
    case NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_INGRESS:
        if (body->subject_key_raw_length != 8u
            || body->subject_key_raw == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        (void)memset(out_primary_id, 0, NINLIL_MODEL_DOMAIN_ID_BYTES);
        (void)memcpy(&out_primary_id[8], body->subject_key_raw, 8u);
        return NINLIL_OK;
    default:
        return NINLIL_E_STORAGE_CORRUPT;
    }
}

static ninlil_status_t validate_common_header_local(
    uint8_t family,
    uint8_t subtype,
    const ninlil_model_domain_key_view_t *key,
    const ninlil_model_domain_envelope_t *env)
{
    if (env->header.subtype != subtype
        || env->header.domain_format != NINLIL_MODEL_DOMAIN_FORMAT_VERSION
        || env->header.flags != 0u
        || env->header.record_revision == 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (family == NINLIL_MODEL_DOMAIN_FAMILY_HEALTH) {
        if (env->record_type != NINLIL_MODEL_DOMAIN_RECORD_TYPE_HEALTH) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
    } else if (env->record_type != NINLIL_MODEL_DOMAIN_RECORD_TYPE_DOMAIN) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (key->family != family || key->subtype != subtype) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    /* primary_id: validated per subtype after body decode (not own-key). */
    if (primary_allows_zero_pvd(family, subtype)) {
        if (!digest_is_zero(env->header.primary_value_digest)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
    } else if (digest_is_zero(env->header.primary_value_digest)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (!allows_zero_head(family, subtype)
        && digest_is_zero(env->header.head_witness_digest)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    return NINLIL_OK;
}

static ninlil_status_t validate_header_body_local(
    uint8_t family,
    uint8_t subtype,
    const ninlil_model_domain_key_view_t *key,
    const ninlil_model_domain_envelope_t *env,
    ninlil_model_domain_typed_record_t *out)
{
    ninlil_status_t status;

    status = validate_common_header_local(family, subtype, key, env);
    if (status != NINLIL_OK) {
        return status;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_INTERNAL_INVARIANT) {
        uint8_t marker[NINLIL_MODEL_DOMAIN_ID_BYTES];
        status = ninlil_model_domain_decode_body_internal_invariant(
            env->body, &out->internal_invariant);
        if (status != NINLIL_OK) {
            return status;
        }
        if (env->header.record_revision != 1u
            || !digest_is_zero(env->header.head_witness_digest)
            || !digest_is_zero(env->header.primary_value_digest)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (ninlil_model_domain_invariant_marker_id(
                out->internal_invariant.reason,
                out->internal_invariant.subject_kind,
                out->internal_invariant.subject_digest,
                marker)
            != NINLIL_OK) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (key->identity_kind != NINLIL_MODEL_DOMAIN_ID_KIND_ID128
            || key->identity_length != 16u
            || key->identity == NULL
            || memcmp(key->identity, marker, 16u) != 0
            || !header_primary_id_eq(env, marker)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_BEARER_STATE) {
        uint8_t expect_pid[NINLIL_MODEL_DOMAIN_ID_BYTES];

        status = ninlil_model_domain_decode_body_bearer_state(
            env->body, &out->bearer_state);
        if (status != NINLIL_OK) {
            return status;
        }
        if (digest_is_zero(env->header.head_witness_digest)
            || !digest_is_zero(env->header.primary_value_digest)
            || key->identity_kind != NINLIL_MODEL_DOMAIN_ID_KIND_SINGLETON
            || primary_id_from_own_key(key, expect_pid) != NINLIL_OK
            || !header_primary_id_eq(env, expect_pid)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE) {
        uint8_t expect_pid[NINLIL_MODEL_DOMAIN_ID_BYTES];

        status = ninlil_model_domain_decode_body_clock_baseline(
            env->body, &out->clock_baseline);
        if (status != NINLIL_OK) {
            return status;
        }
        if (!digest_is_zero(env->header.primary_value_digest)
            || key->identity_kind != NINLIL_MODEL_DOMAIN_ID_KIND_SINGLETON
            || primary_id_from_own_key(key, expect_pid) != NINLIL_OK
            || !header_primary_id_eq(env, expect_pid)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (out->clock_baseline.publish_generation == UINT64_MAX
            || env->header.record_revision
                != out->clock_baseline.publish_generation + 1u) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (out->clock_baseline.baseline_state
            == NINLIL_MODEL_DOMAIN_BASELINE_STATE_UNINITIALIZED) {
            if (env->header.record_revision != 1u
                || !digest_is_zero(env->header.head_witness_digest)) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
        } else if (env->header.record_revision < 2u) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_REUSE_FENCE) {
        uint8_t expect_pid[NINLIL_MODEL_DOMAIN_ID_BYTES];

        status = ninlil_model_domain_decode_body_attempt_reuse_fence(
            env->body, &out->attempt_reuse_fence);
        if (status != NINLIL_OK) {
            return status;
        }
        if (digest_is_zero(env->header.head_witness_digest)
            || !digest_is_zero(env->header.primary_value_digest)
            || key->identity_kind != NINLIL_MODEL_DOMAIN_ID_KIND_SINGLETON
            || primary_id_from_own_key(key, expect_pid) != NINLIL_OK
            || !header_primary_id_eq(env, expect_pid)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (env->header.record_revision
            != out->attempt_reuse_fence.fence_generation) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX) {
        ninlil_model_domain_digest_t composite;
        ninlil_bytes_view_t components;
        uint8_t expect_pid[NINLIL_MODEL_DOMAIN_ID_BYTES];

        status = ninlil_model_domain_decode_body_witness_head_index(
            env->body, &out->witness_head_index);
        if (status != NINLIL_OK) {
            return status;
        }
        if (!digest_is_zero(env->header.primary_value_digest)
            || key->identity_kind
                != NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE
            || key->identity_length != 32u
            || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (out->witness_head_index.index_state
            == NINLIL_MODEL_DOMAIN_INDEX_STATE_BASELINE) {
            if (!digest_is_zero(env->header.head_witness_digest)
                || !digest_is_zero(
                    out->witness_head_index.member_head_witness_digest)) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            if (env->header.record_revision != 1u) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
        } else {
            if (digest_is_zero(env->header.head_witness_digest)
                || memcmp(
                       env->header.head_witness_digest,
                       out->witness_head_index.member_head_witness_digest,
                       NINLIL_MODEL_DOMAIN_DIGEST_BYTES)
                    != 0) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            if (env->header.record_revision < 2u) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
        }
        components.data = out->witness_head_index.member_key_digest;
        components.length = NINLIL_MODEL_DOMAIN_DIGEST_BYTES;
        if (ninlil_model_domain_composite_digest(
                NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX,
                components,
                &composite)
            != NINLIL_OK
            || memcmp(key->identity, composite.bytes, 32u) != 0
            || primary_id_from_composite_components(
                   NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX,
                   components,
                   expect_pid)
                != NINLIL_OK
            || !header_primary_id_eq(env, expect_pid)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE) {
        uint8_t raw16[257];
        ninlil_bytes_view_t components;
        ninlil_model_domain_digest_t dig;
        uint8_t expect_pid[NINLIL_MODEL_DOMAIN_ID_BYTES];

        status = ninlil_model_domain_decode_body_service(
            env->body, &out->service);
        if (status != NINLIL_OK) {
            return status;
        }
        /* immutable primary: revision 1, zero pvd, non-zero head */
        if (env->header.record_revision != 1u
            || key->identity_kind
                != NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE
            || key->identity_length != 32u
            || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        ninlil_model_domain_encode_u16_be(
            raw16, out->service.service_key_raw_length);
        (void)memcpy(
            &raw16[2], out->service.service_key_raw,
            out->service.service_key_raw_length);
        components.data = raw16;
        components.length = 2u + (uint32_t)out->service.service_key_raw_length;
        if (ninlil_model_domain_composite_digest(
                NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE, components, &dig)
            != NINLIL_OK
            || memcmp(key->identity, dig.bytes, 32u) != 0
            || primary_id_from_composite_components(
                   NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE, components, expect_pid)
                != NINLIL_OK
            || !header_primary_id_eq(env, expect_pid)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        /*
         * quota/reservation KEY_DIGEST same-body rules are enforced by
         * decode_body_service / service_descriptor_contract_ok.
         */
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE_QUOTA) {
        uint8_t raw16[257];
        ninlil_bytes_view_t components;
        uint8_t expect_pid[NINLIL_MODEL_DOMAIN_ID_BYTES];

        status = ninlil_model_domain_decode_body_service_quota(
            env->body, &out->service_quota);
        if (status != NINLIL_OK) {
            return status;
        }
        if (key->identity_kind
                != NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE
            || key->identity_length != 32u || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        ninlil_model_domain_encode_u16_be(
            raw16, out->service_quota.service_key_raw_length);
        (void)memcpy(
            &raw16[2], out->service_quota.service_key_raw,
            out->service_quota.service_key_raw_length);
        components.data = raw16;
        components.length =
            2u + (uint32_t)out->service_quota.service_key_raw_length;
        if (!composite_identity_matches(
                NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE_QUOTA, components,
                key->identity, key->identity_length)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        /* primary_id = SERVICE composite identity first 16, not QUOTA key. */
        if (primary_id_from_composite_components(
                NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE, components, expect_pid)
                != NINLIL_OK
            || !header_primary_id_eq(env, expect_pid)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        /* primary_value_digest non-zero already checked; live SERVICE get is D3 */
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR) {
        status = ninlil_model_domain_decode_body_transaction_anchor(
            env->body, &out->transaction_anchor);
        if (status != NINLIL_OK) {
            return status;
        }
        if (env->header.record_revision != 1u
            || key->identity_kind != NINLIL_MODEL_DOMAIN_ID_KIND_ID128
            || key->identity_length != 16u || key->identity == NULL
            || memcmp(
                   key->identity, out->transaction_anchor.transaction_id, 16u)
                != 0
            || !header_primary_id_eq(
                   env, out->transaction_anchor.transaction_id)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_SEQUENCE_INDEX) {
        uint8_t seq_be[8];
        status = ninlil_model_domain_decode_body_transaction_sequence_index(
            env->body, &out->transaction_sequence_index);
        if (status != NINLIL_OK) {
            return status;
        }
        if (key->identity_kind != NINLIL_MODEL_DOMAIN_ID_KIND_U64
            || key->identity_length != 8u || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        ninlil_model_domain_encode_u64_be(
            seq_be, out->transaction_sequence_index.transaction_sequence);
        if (memcmp(key->identity, seq_be, 8u) != 0) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        /* primary_id = anchor transaction_id, not left-padded sequence. */
        if (!header_primary_id_eq(
                env, out->transaction_sequence_index.transaction_id)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE) {
        status = ninlil_model_domain_decode_body_transaction_state(
            env->body, &out->transaction_state);
        if (status != NINLIL_OK) {
            return status;
        }
        if (key->identity_kind != NINLIL_MODEL_DOMAIN_ID_KIND_ID128
            || key->identity_length != 16u || key->identity == NULL
            || memcmp(
                   key->identity, out->transaction_state.transaction_id, 16u)
                != 0
            || !header_primary_id_eq(
                   env, out->transaction_state.transaction_id)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        /*
         * docs17: TRANSACTION_STATE public record_revision equals common
         * header revision — already same field storage path; no extra body
         * field. Cross-row anchor_value_digest equality is D3.
         * primary_id = body transaction_id (same bytes as key ID128; validated
         * from body, not by treating secondary self-key as primary generically).
         */
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION) {
        uint8_t comp[4 + 257];
        ninlil_bytes_view_t components;
        uint8_t expect_pid[NINLIL_MODEL_DOMAIN_ID_BYTES];

        status = ninlil_model_domain_decode_body_reservation(
            env->body, &out->reservation);
        if (status != NINLIL_OK) {
            return status;
        }
        if (key->identity_kind
                != NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE
            || key->identity_length != 32u || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        ninlil_model_domain_encode_u16_be(
            comp, out->reservation.owner_kind);
        ninlil_model_domain_encode_u16_be(
            &comp[2], out->reservation.owner_key_raw_length);
        (void)memcpy(
            &comp[4], out->reservation.owner_key_raw,
            out->reservation.owner_key_raw_length);
        components.data = comp;
        components.length =
            4u + (uint32_t)out->reservation.owner_key_raw_length;
        if (!composite_identity_matches(
                NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION, components,
                key->identity, key->identity_length)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (reservation_expected_primary_id(&out->reservation, expect_pid)
                != NINLIL_OK
            || !header_primary_id_eq(env, expect_pid)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP) {
        uint8_t comp[2 + 255 + 2 + 64];
        uint32_t cl = 0u;
        ninlil_bytes_view_t components;

        status = ninlil_model_domain_decode_body_idempotency_map(
            env->body, &out->idempotency_map);
        if (status != NINLIL_OK) {
            return status;
        }
        if (key->identity_kind
                != NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE
            || key->identity_length != 32u || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        cl = encode_raw16(
            comp, out->idempotency_map.scope_raw_length,
            out->idempotency_map.scope_raw);
        cl += encode_raw16(
            &comp[cl], out->idempotency_map.idempotency_key_length,
            out->idempotency_map.idempotency_key);
        components.data = comp;
        components.length = cl;
        if (!composite_identity_matches(
                NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP, components,
                key->identity, key->identity_length)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        /* primary_id = body transaction_id (anchor), not map composite. */
        if (!header_primary_id_eq(
                env, out->idempotency_map.transaction_id)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_ID_MAP) {
        uint8_t comp[2 + 255 + 16];
        uint32_t cl = 0u;
        ninlil_bytes_view_t components;

        status = ninlil_model_domain_decode_body_event_id_map(
            env->body, &out->event_id_map);
        if (status != NINLIL_OK) {
            return status;
        }
        if (key->identity_kind
                != NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE
            || key->identity_length != 32u || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        cl = encode_raw16(
            comp, out->event_id_map.scope_raw_length,
            out->event_id_map.scope_raw);
        (void)memcpy(&comp[cl], out->event_id_map.event_id, 16u);
        cl += 16u;
        components.data = comp;
        components.length = cl;
        if (!composite_identity_matches(
                NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_ID_MAP, components,
                key->identity, key->identity_length)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        /* primary_id = body transaction_id (anchor), not map composite. */
        if (!header_primary_id_eq(env, out->event_id_map.transaction_id)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_SCHEDULER_OWNER) {
        uint8_t seq_be[8];
        uint8_t expect_pid[NINLIL_MODEL_DOMAIN_ID_BYTES];

        status = ninlil_model_domain_decode_body_scheduler_owner(
            env->body, &out->scheduler_owner);
        if (status != NINLIL_OK) {
            return status;
        }
        /*
         * Same-record: key u64 identity == owner_sequence BE8.
         * primary_id = referenced primary identity, not scheduler self-key.
         * D3 deferred (not proven here): live primary get / value digest,
         * exact 1:1 cardinality, family-3 counter/cursor upper bound,
         * ready semantics vs step cut, ingress→delivery owner transfer.
         */
        if (key->identity_kind != NINLIL_MODEL_DOMAIN_ID_KIND_U64
            || key->identity_length != 8u || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        ninlil_model_domain_encode_u64_be(
            seq_be, out->scheduler_owner.owner_sequence);
        if (memcmp(key->identity, seq_be, 8u) != 0) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (scheduler_expected_primary_id(&out->scheduler_owner, expect_pid)
                != NINLIL_OK
            || !header_primary_id_eq(env, expect_pid)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    return NINLIL_E_INVALID_ARGUMENT;
}

ninlil_status_t ninlil_model_domain_validate_typed_record(
    ninlil_bytes_view_t encoded_key,
    ninlil_bytes_view_t encoded_value,
    ninlil_model_domain_typed_record_t *out_record)
{
    ninlil_model_domain_typed_record_t local;
    ninlil_status_t status;
    size_t n = 0u;
    const void *ptrs[4];
    size_t lens[4];

    if (encoded_key.data != NULL && encoded_key.length != 0u) {
        ptrs[n] = encoded_key.data;
        lens[n] = encoded_key.length;
        n++;
    }
    if (encoded_value.data != NULL && encoded_value.length != 0u) {
        ptrs[n] = encoded_value.data;
        lens[n] = encoded_value.length;
        n++;
    }
    if (out_record != NULL) {
        ptrs[n] = out_record;
        lens[n] = sizeof(*out_record);
        n++;
    }
    if (!multi_ranges_ok(ptrs, lens, n)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    (void)memset(&local, 0, sizeof(local));
    if (out_record != NULL) {
        (void)memset(out_record, 0, sizeof(*out_record));
    }
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded_key)
        || !ninlil_model_domain_bytes_view_shape_is_valid(encoded_value)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    status = ninlil_model_domain_parse_key(encoded_key, &local.key);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_model_domain_decode_envelope(encoded_value, &local.envelope);
    if (status != NINLIL_OK) {
        return status;
    }

    local.family = local.key.family;
    local.subtype = local.key.subtype;

    if (!subtype_is_d1b_supported(local.family, local.subtype)) {
        if (out_record != NULL) {
            (void)memset(out_record, 0, sizeof(*out_record));
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }

    status = validate_header_body_local(
        local.family, local.subtype, &local.key, &local.envelope, &local);
    if (status != NINLIL_OK) {
        if (out_record != NULL) {
            (void)memset(out_record, 0, sizeof(*out_record));
        }
        return status;
    }

    if (out_record != NULL) {
        *out_record = local;
    }
    return NINLIL_OK;
}
