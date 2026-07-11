#include "domain_store_body_codec.h"
#include "domain_store_codec_internal.h"

#include <ninlil/version.h>
#include <string.h>

/*
 * D1-B1 + D1-B2 + D1-B3a..o body codec. Boundary notes for later milestones:
 * - D2: bounded recovery scan, row budget, workspace state machine.
 * - D3: cross-row primary/index/backlink, ATTEMPT_REUSE_FENCE vs CLEANUP_PLAN
 *   active_plan_count equality, HEAD_INDEX member get/value mutual proof,
 *   family 3/4 capacity/counter mutual recompute, live SERVICE_QUOTA active
 *   counts from TRANSACTION RESERVATION contributions, primary_value_digest
 *   exact get of live primary complete value; SCHEDULER_OWNER 1:1 cardinality,
 *   counter/cursor upper bound, ready semantics, ingress→delivery owner
 *   transfer; ORDERED_INGRESS live owner/SCHEDULER/RESERVATION/BLOB 0/1
 *   cardinality and non-zero BLOB stream recompute of message_semantic_digest,
 *   SERVICE supported evidence mask vs receipt_stage, namespace counter upper
 *   bound, reduction erase (B3b must not guess BLOB keys from body alone);
 *   BLOB live owner/manifest get, primary value digest equality, chunk
 *   0..count-1 enumeration, multi-chunk stream digest, owner semantic content
 *   match, same-owner/kind/content manifest alias, lifecycle erase / capacity
 *   accounting (B3c proves same-record body/key/blob_id/local length only);
 *   ATTEMPT live owner, ATTEMPT_ID_INDEX cardinality, CANCEL_STATE gate,
 *   family COMMAND/EVENT kind, current/stale attempt, primary value digest,
 *   target/semantic digest recompute, SEND_COUNTER health/cardinality
 *   (B3d proves same-record body/key/matrix only); ATTEMPT_ID_INDEX live
 *   TRANSACTION_ANCHOR PVD, live/current ATTEMPT binding, CREATE manifest
 *   new digest equality (not current ATTEMPT value after replacement), local
 *   ATTEMPT/index cardinality, DELIVERY/remote no-index, reverse reply
 *   no-index, co-create witness, fenced pair cleanup/fence counts,
 *   family-kind and CANCEL_STATE cross proofs (B3e proves same-record
 *   body/key/record-key-digest/primary binding only); CANCEL_STATE live
 *   primary PVD, live CANCEL ATTEMPT/index/cardinality, message recompute
 *   (NZ cases from live owner/empty CANCEL_REQUEST view; preimage
 *   cancel_kind=0), RESULT/REVERSE_REPLY, prior transition/gate history,
 *   timeout scheduling, family/owner/cardinality/reply proofs (B3f proves
 *   same-record body/key/matrix/bijection/primary binding only); EVIDENCE_CELL
 *   live primary PVD, live TARGET→target_digest, exact L and L+1 cardinality /
 *   slot continuity, valid_material_count=M+overflow, owner family/content/
 *   required_evidence/supported mask, STATE latest_evidence / has_late_evidence
 *   projection, RESULT_CACHE evidence_cell_key_digest, EVIDENCE used/reserved,
 *   admission journal headroom, CANCEL_FIRST EVIDENCE 0, deadline proof,
 *   retention erase (B3g proves same-record body/key/matrix/digest recompute/
 *   counter/family-generation/primary binding only); DELIVERY live RESULT_CACHE
 *   exact 1 and delivery_state/token/reply, SCHEDULER_OWNER / DELIVERY
 *   RESERVATION live cardinality, APPLICATION/CANCEL ATTEMPT, EVIDENCE_CELL
 *   L+1 or CANCEL_FIRST 0, CANCEL_STATE, payload BLOB live, ORDERED_INGRESS
 *   erase and admission witness, later APPLICATION attach / binding conflict,
 *   public ABSENT projection, supported evidence mask, evidence grace live
 *   SERVICE max, deadline proof, retention cleanup (B3h proves same-record
 *   body/key/family matrix/payload presence/result and reservation KEY_DIGEST/
 *   primary binding only; RESULT_CACHE body is next slice).
 * - D4: COMMIT_UNKNOWN old/new complete-value digest convergence.
 */

static const char PREIMAGE_INVARIANT[] = "NINLIL-DOMAIN-INVARIANT-V1";
static const char PREIMAGE_BLOB_ID[] = "NINLIL-DOMAIN-BLOB-ID-V1";
static const char PREIMAGE_EVENT_RESUME[] = "NINLIL-M1A-EVENT-RESUME";
static const char PREIMAGE_EVENT_DISCARD[] = "NINLIL-M1A-EVENT-DISCARD";

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

/* --- ORDERED_INGRESS helpers (D1-B3b) --- */

static int bearer_message_kind_is_known(uint32_t kind)
{
    return kind >= NINLIL_BEARER_MESSAGE_APPLICATION
        && kind <= NINLIL_BEARER_MESSAGE_CANCEL_RESULT;
}

static int clock_trust_is_known(uint32_t trust)
{
    return trust == NINLIL_CLOCK_TRUSTED || trust == NINLIL_CLOCK_UNCERTAIN;
}

/*
 * docs12 §7.2 Disposition / effect_certainty / retry_guidance / retry_delay
 * closed combination table (Bearer DISPOSITION and APP_RESULT_DISPOSITION).
 */
static int disposition_tuple_is_valid(
    uint32_t disposition,
    uint32_t effect_certainty,
    uint32_t retry_guidance,
    uint64_t retry_delay_ms)
{
    switch (disposition) {
    case NINLIL_DISPOSITION_RETRY_LATER:
        return effect_certainty == NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN
            && retry_guidance == NINLIL_RETRY_SAME_AFTER
            && retry_delay_ms <= NINLIL_M1A_MAX_RETRY_DELAY_MS;
    case NINLIL_DISPOSITION_INVALID_PAYLOAD:
    case NINLIL_DISPOSITION_UNSUPPORTED_SCHEMA:
        return effect_certainty == NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN
            && retry_guidance == NINLIL_RETRY_MODIFIED
            && retry_delay_ms == 0u;
    case NINLIL_DISPOSITION_UNAUTHORIZED_SERVICE:
        return effect_certainty == NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN
            && retry_guidance == NINLIL_RETRY_MODIFIED
            && retry_delay_ms == 0u;
    case NINLIL_DISPOSITION_STALE_NOT_APPLIED:
        return effect_certainty == NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN
            && retry_guidance == NINLIL_RETRY_NEVER
            && retry_delay_ms == 0u;
    case NINLIL_DISPOSITION_APPLICATION_BUSY:
    case NINLIL_DISPOSITION_CAPACITY_EXHAUSTED:
        return effect_certainty == NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN
            && retry_guidance == NINLIL_RETRY_SAME_AFTER
            && retry_delay_ms <= NINLIL_M1A_MAX_RETRY_DELAY_MS;
    case NINLIL_DISPOSITION_APPLY_FAILED:
        if (effect_certainty == NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN
            && retry_guidance == NINLIL_RETRY_SAME_AFTER
            && retry_delay_ms <= NINLIL_M1A_MAX_RETRY_DELAY_MS) {
            return 1;
        }
        return effect_certainty == NINLIL_EFFECT_CERTAINTY_POSSIBLE
            && retry_guidance == NINLIL_RETRY_OPERATOR_ACTION
            && retry_delay_ms == 0u;
    case NINLIL_DISPOSITION_VERIFY_FAILED:
    case NINLIL_DISPOSITION_OUTCOME_UNKNOWN:
        return effect_certainty == NINLIL_EFFECT_CERTAINTY_POSSIBLE
            && retry_guidance == NINLIL_RETRY_OPERATOR_ACTION
            && retry_delay_ms == 0u;
    default:
        return 0;
    }
}

static int zero_disposition_tuple_ok(
    uint32_t disposition,
    uint32_t effect_certainty,
    uint32_t retry_guidance,
    uint64_t retry_delay_ms)
{
    return disposition == NINLIL_DISPOSITION_NONE
        && effect_certainty == NINLIL_EFFECT_CERTAINTY_NONE
        && retry_guidance == NINLIL_RETRY_NEVER
        && retry_delay_ms == 0u;
}

static int ingress_binding_ok_for_kind(
    uint32_t message_kind, uint16_t binding)
{
    switch (message_kind) {
    case NINLIL_BEARER_MESSAGE_APPLICATION:
    case NINLIL_BEARER_MESSAGE_CANCEL_REQUEST:
        return binding == NINLIL_MODEL_DOMAIN_INGRESS_BINDING_EXISTING_DELIVERY
            || binding == NINLIL_MODEL_DOMAIN_INGRESS_BINDING_NEW_DELIVERY;
    case NINLIL_BEARER_MESSAGE_RECEIPT:
    case NINLIL_BEARER_MESSAGE_DISPOSITION:
    case NINLIL_BEARER_MESSAGE_CUSTODY_ACCEPTED:
    case NINLIL_BEARER_MESSAGE_CANCEL_RESULT:
        return binding
            == NINLIL_MODEL_DOMAIN_INGRESS_BINDING_EXISTING_TRANSACTION;
    default:
        return 0;
    }
}

static int ordered_ingress_reservation_digest_ok(
    const ninlil_model_domain_body_ordered_ingress_t *body)
{
    uint8_t seq_be[8];
    uint8_t comp[2u + 2u + 8u];
    ninlil_bytes_view_t components;

    if (body == NULL) {
        return 0;
    }
    ninlil_model_domain_encode_u64_be(seq_be, body->ordered_sequence);
    ninlil_model_domain_encode_u16_be(
        comp, NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_INGRESS);
    ninlil_model_domain_encode_u16_be(&comp[2], 8u);
    (void)memcpy(&comp[4], seq_be, 8u);
    components.data = comp;
    components.length = 12u;
    return digest_eq_composite_key(
        body->reservation_key_digest,
        NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION,
        components);
}

static int ordered_ingress_semantic_empty_ok(
    const ninlil_model_domain_body_ordered_ingress_t *body)
{
    ninlil_model_domain_message_semantic_prefix_t prefix;
    ninlil_model_domain_digest_t dig;
    ninlil_bytes_view_t empty;

    (void)memset(&prefix, 0, sizeof(prefix));
    prefix.kind = body->message_kind;
    prefix.flags = body->message_flags;
    (void)memcpy(prefix.transaction_id, body->transaction_id, 16u);
    (void)memcpy(prefix.attempt_id, body->attempt_id, 16u);
    (void)memcpy(prefix.event_id, body->event_id, 16u);
    prefix.source = body->source;
    prefix.target = body->target;
    prefix.service = body->service;
    (void)memcpy(prefix.content_digest, body->content_digest, 32u);
    prefix.generation = body->generation;
    (void)memcpy(prefix.deadline_clock_epoch, body->deadline_clock_epoch, 16u);
    prefix.absolute_effect_deadline_ms = body->absolute_effect_deadline_ms;
    prefix.evidence_grace_ms = body->evidence_grace_ms;
    prefix.required_evidence = body->required_evidence;
    prefix.receipt_stage = body->receipt_stage;
    prefix.disposition = body->disposition;
    prefix.effect_certainty = body->effect_certainty;
    prefix.retry_guidance = body->retry_guidance;
    prefix.cancel_kind = body->cancel_kind;
    prefix.retry_delay_ms = body->retry_delay_ms;
    (void)memcpy(prefix.evidence_clock_epoch, body->evidence_clock_epoch, 16u);
    prefix.evidence_now_ms = body->evidence_now_ms;
    prefix.evidence_trust = body->evidence_trust;
    prefix.payload_length = 0u;
    empty.data = NULL;
    empty.length = 0u;
    if (ninlil_model_domain_message_semantic_digest(
            &prefix, empty, empty, &dig)
        != NINLIL_OK) {
        return 0;
    }
    return memcmp(body->message_semantic_digest, dig.bytes, 32u) == 0;
}

/*
 * Same-record ORDERED_INGRESS field contract (docs17 §8.3 + docs12 §5.4/7.2).
 * Does not look up BLOB rows or guess blob_id / complete BLOB keys.
 */
static int ordered_ingress_fields_ok(
    const ninlil_model_domain_body_ordered_ingress_t *body)
{
    int is_event;
    int is_app;
    int is_receipt;
    int is_disp;
    int is_cancel_req;
    int is_cancel_res;
    int payload_present;
    int evidence_present;
    ninlil_model_domain_digest_t empty_content;

    if (body == NULL || body->ordered_sequence == 0u
        || body->owner_sequence == 0u
        || body->reserved0 != 0u
        || body->reserved1 != 0u
        || body->controller_ingress_reserved != 0u
        || body->message_flags != 0u
        || !bearer_message_kind_is_known(body->message_kind)
        || !ingress_binding_ok_for_kind(
            body->message_kind, body->owner_binding_kind)
        || id_is_zero(body->transaction_id)
        || id_is_zero(body->attempt_id)
        || !ninlil_model_domain_party_is_valid(&body->source)
        || !ninlil_model_domain_target_is_valid(&body->target)
        || !ninlil_model_domain_service_identity_is_valid(&body->service)
        || digest_is_zero(body->content_digest)
        || !evidence_stage_is_known(body->required_evidence)
        || body->required_evidence == NINLIL_EVIDENCE_NONE
        || body->ingress_state != NINLIL_MODEL_DOMAIN_INGRESS_STATE_PENDING
        || !ordered_ingress_reservation_digest_ok(body)) {
        return 0;
    }

    is_event = body->service.family == NINLIL_FAMILY_EVENT_FACT;
    if (!is_event && body->service.family != NINLIL_FAMILY_DESIRED_STATE) {
        return 0;
    }
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
    }

    is_app = body->message_kind == NINLIL_BEARER_MESSAGE_APPLICATION;
    is_receipt = body->message_kind == NINLIL_BEARER_MESSAGE_RECEIPT;
    is_disp = body->message_kind == NINLIL_BEARER_MESSAGE_DISPOSITION;
    is_cancel_req = body->message_kind == NINLIL_BEARER_MESSAGE_CANCEL_REQUEST;
    is_cancel_res = body->message_kind == NINLIL_BEARER_MESSAGE_CANCEL_RESULT;

    /* CANCEL_REQUEST / CANCEL_RESULT are DesiredState only (docs12 §5.4). */
    if ((is_cancel_req || is_cancel_res) && is_event) {
        return 0;
    }

    /* Kind-specific enum / zero tuples (docs12 §5.4 table). */
    if (is_app) {
        if (body->receipt_stage != NINLIL_EVIDENCE_NONE
            || !zero_disposition_tuple_ok(
                body->disposition,
                body->effect_certainty,
                body->retry_guidance,
                body->retry_delay_ms)
            || body->cancel_kind != 0u
            || !id_is_zero(body->evidence_clock_epoch)
            || body->evidence_now_ms != 0u
            || body->evidence_trust != 0u
            || !id_is_zero(body->controller_ingress_clock_epoch)
            || body->controller_ingress_at_ms != 0u
            || body->controller_ingress_trust != 0u) {
            return 0;
        }
    } else if (is_receipt) {
        /*
         * receipt_stage: known non-zero only. SERVICE supported-mask match
         * is D3 (requires live SERVICE row); not proven here.
         * controller_ingress_*: local durable-copy sample (docs17 §8.3);
         * epoch non-zero, trust TRUSTED/UNCERTAIN, at_ms 0 valid.
         */
        if (body->receipt_stage == NINLIL_EVIDENCE_NONE
            || !evidence_stage_is_known(body->receipt_stage)
            || !zero_disposition_tuple_ok(
                body->disposition,
                body->effect_certainty,
                body->retry_guidance,
                body->retry_delay_ms)
            || body->cancel_kind != 0u
            || id_is_zero(body->evidence_clock_epoch)
            || !clock_trust_is_known(body->evidence_trust)
            || id_is_zero(body->controller_ingress_clock_epoch)
            || !clock_trust_is_known(body->controller_ingress_trust)) {
            /* evidence_now_ms / controller_ingress_at_ms == 0 valid. */
            return 0;
        }
    } else if (is_disp) {
        if (body->receipt_stage != NINLIL_EVIDENCE_NONE
            || !disposition_tuple_is_valid(
                body->disposition,
                body->effect_certainty,
                body->retry_guidance,
                body->retry_delay_ms)
            || body->cancel_kind != 0u
            || !id_is_zero(body->evidence_clock_epoch)
            || body->evidence_now_ms != 0u
            || body->evidence_trust != 0u
            || !id_is_zero(body->controller_ingress_clock_epoch)
            || body->controller_ingress_at_ms != 0u
            || body->controller_ingress_trust != 0u) {
            return 0;
        }
    } else if (is_cancel_res) {
        if (body->receipt_stage != NINLIL_EVIDENCE_NONE
            || !zero_disposition_tuple_ok(
                body->disposition,
                body->effect_certainty,
                body->retry_guidance,
                body->retry_delay_ms)
            || (body->cancel_kind != NINLIL_CANCEL_FENCED_BEFORE_DISPATCH
                && body->cancel_kind != NINLIL_CANCEL_TOO_LATE_EFFECT_POSSIBLE)
            || !id_is_zero(body->evidence_clock_epoch)
            || body->evidence_now_ms != 0u
            || body->evidence_trust != 0u
            || !id_is_zero(body->controller_ingress_clock_epoch)
            || body->controller_ingress_at_ms != 0u
            || body->controller_ingress_trust != 0u) {
            return 0;
        }
    } else {
        /* CANCEL_REQUEST or CUSTODY_ACCEPTED: all disposition/evidence zero. */
        if (body->receipt_stage != NINLIL_EVIDENCE_NONE
            || !zero_disposition_tuple_ok(
                body->disposition,
                body->effect_certainty,
                body->retry_guidance,
                body->retry_delay_ms)
            || body->cancel_kind != 0u
            || !id_is_zero(body->evidence_clock_epoch)
            || body->evidence_now_ms != 0u
            || body->evidence_trust != 0u
            || !id_is_zero(body->controller_ingress_clock_epoch)
            || body->controller_ingress_at_ms != 0u
            || body->controller_ingress_trust != 0u) {
            return 0;
        }
    }

    /*
     * BLOB key digest presence (docs17 §8.3): APPLICATION payload 0/1,
     * RECEIPT evidence 0/1; opposite and other kinds must be zero.
     * D3 validates live BLOB 0/1 cardinality and content; D1 must not invent
     * blob_id or complete BLOB keys from body alone.
     */
    payload_present = !digest_is_zero(body->payload_blob_key_digest);
    evidence_present = !digest_is_zero(body->evidence_blob_key_digest);
    if (is_app) {
        if (evidence_present) {
            return 0;
        }
    } else if (is_receipt) {
        if (payload_present) {
            return 0;
        }
    } else if (payload_present || evidence_present) {
        return 0;
    }

    /* APPLICATION + empty payload: content_digest = SHA-256(empty). */
    if (is_app && !payload_present) {
        if (ninlil_model_domain_sha256(NULL, 0u, &empty_content) != NINLIL_OK
            || memcmp(body->content_digest, empty_content.bytes, 32u) != 0) {
            return 0;
        }
    }

    if (!payload_present && !evidence_present) {
        if (!ordered_ingress_semantic_empty_ok(body)) {
            return 0;
        }
    } else if (digest_is_zero(body->message_semantic_digest)) {
        /* Non-zero BLOB path: semantic digest must be non-zero; recompute D3. */
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

/* --- message_semantic_digest streaming helper (docs17 §5.1) --- */

static const char PREIMAGE_BEARER_MESSAGE[] = "NINLIL-BEARER-MESSAGE-V1";

/*
 * Failure / alias policy for the MSD state machine:
 * - Alias / address-overflow failures never write any participating range
 *   (ctx, prefix, data, out_digest). They return INVALID_ARGUMENT only.
 * - After address + pairwise-disjoint gates pass, non-alias failures that
 *   involve a writable ctx transition phase to FAILED (wrong phase, length
 *   overflow, counter incoherence, SHA structural failure). init also zeros
 *   the full ctx object on non-alias prefix/nested failure.
 * - final zeros out_digest on non-alias failure after range gates pass.
 * - Wrong-phase misuse is treated as a non-alias semantic failure and
 *   transitions FAILED (once ctx address range is known-valid).
 */

static void msd_fail(ninlil_model_domain_message_semantic_digest_ctx_t *ctx)
{
    ctx->phase = NINLIL_MODEL_DOMAIN_MSD_PHASE_FAILED;
}

static ninlil_status_t msd_sha_update(
    ninlil_model_domain_message_semantic_digest_ctx_t *ctx,
    const uint8_t *data,
    uint32_t length)
{
    ninlil_status_t status;

    status = ninlil_model_domain_sha256_update(&ctx->sha, data, length);
    if (status != NINLIL_OK) {
        msd_fail(ctx);
    }
    return status;
}

/* Reject caller-mutated counters that would underflow remaining math. */
static int msd_payload_counters_ok(
    const ninlil_model_domain_message_semantic_digest_ctx_t *ctx)
{
    return ctx->received_payload_length <= ctx->declared_payload_length;
}

static int msd_evidence_counters_ok(
    const ninlil_model_domain_message_semantic_digest_ctx_t *ctx)
{
    return ctx->received_evidence_length <= ctx->declared_evidence_length
        && ctx->declared_evidence_length
            <= NINLIL_MODEL_DOMAIN_EVIDENCE_BYTES_MAX;
}

static ninlil_status_t msd_hash_prefix_fields(
    ninlil_model_domain_message_semantic_digest_ctx_t *ctx,
    const ninlil_model_domain_message_semantic_prefix_t *prefix)
{
    uint8_t scratch[100];
    uint8_t be[8];
    uint32_t o;
    ninlil_status_t status;

    status = msd_sha_update(
        ctx,
        (const uint8_t *)PREIMAGE_BEARER_MESSAGE,
        (uint32_t)(sizeof(PREIMAGE_BEARER_MESSAGE) - 1u));
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_model_domain_encode_u32_be(be, prefix->kind);
    status = msd_sha_update(ctx, be, 4u);
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_model_domain_encode_u32_be(be, prefix->flags);
    status = msd_sha_update(ctx, be, 4u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = msd_sha_update(ctx, prefix->transaction_id, 16u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = msd_sha_update(ctx, prefix->attempt_id, 16u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = msd_sha_update(ctx, prefix->event_id, 16u);
    if (status != NINLIL_OK) {
        return status;
    }
    /* Domain PARTY encoding (100 bytes) — not public ABI party layout. */
    encode_party(scratch, &prefix->source);
    status = msd_sha_update(ctx, scratch, NINLIL_MODEL_DOMAIN_PARTY_BYTES);
    if (status != NINLIL_OK) {
        return status;
    }
    encode_target(scratch, &prefix->target);
    status = msd_sha_update(ctx, scratch, NINLIL_MODEL_DOMAIN_TARGET_BYTES);
    if (status != NINLIL_OK) {
        return status;
    }
    /* SERVICE_IDENTITY: stream TEXT_IDs + fixed tail without full-body scratch. */
    o = encode_text_id(scratch, &prefix->service.namespace_id);
    status = msd_sha_update(ctx, scratch, o);
    if (status != NINLIL_OK) {
        return status;
    }
    o = encode_text_id(scratch, &prefix->service.service_id);
    status = msd_sha_update(ctx, scratch, o);
    if (status != NINLIL_OK) {
        return status;
    }
    o = encode_text_id(scratch, &prefix->service.schema_id);
    status = msd_sha_update(ctx, scratch, o);
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_model_domain_encode_u64_be(be, prefix->service.descriptor_revision);
    status = msd_sha_update(ctx, be, 8u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = msd_sha_update(ctx, prefix->service.descriptor_digest, 32u);
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_model_domain_encode_u16_be(be, prefix->service.schema_major);
    status = msd_sha_update(ctx, be, 2u);
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_model_domain_encode_u16_be(be, prefix->service.schema_minor);
    status = msd_sha_update(ctx, be, 2u);
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_model_domain_encode_u32_be(be, prefix->service.family);
    status = msd_sha_update(ctx, be, 4u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = msd_sha_update(ctx, prefix->content_digest, 32u);
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_model_domain_encode_u64_be(be, prefix->generation);
    status = msd_sha_update(ctx, be, 8u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = msd_sha_update(ctx, prefix->deadline_clock_epoch, 16u);
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_model_domain_encode_u64_be(be, prefix->absolute_effect_deadline_ms);
    status = msd_sha_update(ctx, be, 8u);
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_model_domain_encode_u64_be(be, prefix->evidence_grace_ms);
    status = msd_sha_update(ctx, be, 8u);
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_model_domain_encode_u32_be(be, prefix->required_evidence);
    status = msd_sha_update(ctx, be, 4u);
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_model_domain_encode_u32_be(be, prefix->receipt_stage);
    status = msd_sha_update(ctx, be, 4u);
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_model_domain_encode_u32_be(be, prefix->disposition);
    status = msd_sha_update(ctx, be, 4u);
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_model_domain_encode_u32_be(be, prefix->effect_certainty);
    status = msd_sha_update(ctx, be, 4u);
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_model_domain_encode_u32_be(be, prefix->retry_guidance);
    status = msd_sha_update(ctx, be, 4u);
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_model_domain_encode_u32_be(be, prefix->cancel_kind);
    status = msd_sha_update(ctx, be, 4u);
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_model_domain_encode_u64_be(be, prefix->retry_delay_ms);
    status = msd_sha_update(ctx, be, 8u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = msd_sha_update(ctx, prefix->evidence_clock_epoch, 16u);
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_model_domain_encode_u64_be(be, prefix->evidence_now_ms);
    status = msd_sha_update(ctx, be, 8u);
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_model_domain_encode_u32_be(be, prefix->evidence_trust);
    status = msd_sha_update(ctx, be, 4u);
    if (status != NINLIL_OK) {
        return status;
    }
    /* Declared payload_length before any payload data bytes. */
    ninlil_model_domain_encode_u32_be(be, prefix->payload_length);
    return msd_sha_update(ctx, be, 4u);
}

ninlil_status_t ninlil_model_domain_message_semantic_digest_init(
    ninlil_model_domain_message_semantic_digest_ctx_t *ctx,
    const ninlil_model_domain_message_semantic_prefix_t *prefix)
{
    ninlil_status_t status;

    /* Address + pairwise-disjoint gates before any write. */
    if (ctx == NULL || !range_address_is_valid(ctx, sizeof(*ctx))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (prefix != NULL) {
        if (!range_address_is_valid(prefix, sizeof(*prefix))
            || !ninlil_model_domain_ranges_are_disjoint(
                ctx, sizeof(*ctx), prefix, sizeof(*prefix))) {
            /* Alias/address: leave ctx and prefix untouched. */
            return NINLIL_E_INVALID_ARGUMENT;
        }
    }
    /*
     * Non-alias path: missing/invalid nested prefix zeros and fails ctx.
     * Nested service TEXT_ID / PARTY / TARGET must be shape-valid first.
     */
    if (prefix == NULL
        || !ninlil_model_domain_service_identity_is_valid(&prefix->service)
        || !ninlil_model_domain_party_is_valid(&prefix->source)
        || !ninlil_model_domain_target_is_valid(&prefix->target)) {
        (void)memset(ctx, 0, sizeof(*ctx));
        msd_fail(ctx);
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(ctx, 0, sizeof(*ctx));
    ninlil_model_domain_sha256_init(&ctx->sha);
    ctx->declared_payload_length = prefix->payload_length;
    ctx->phase = NINLIL_MODEL_DOMAIN_MSD_PHASE_PAYLOAD;
    status = msd_hash_prefix_fields(ctx, prefix);
    if (status != NINLIL_OK) {
        (void)memset(ctx, 0, sizeof(*ctx));
        msd_fail(ctx);
        return status;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_message_semantic_digest_update_payload(
    ninlil_model_domain_message_semantic_digest_ctx_t *ctx,
    const uint8_t *data,
    uint32_t length)
{
    uint32_t remaining;
    ninlil_status_t status;

    if (ctx == NULL || !range_address_is_valid(ctx, sizeof(*ctx))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /* Data range + alias gates before any ctx field write (or phase read path
     * that can fail the machine). length 0 has no data range to validate. */
    if (length != 0u) {
        if (data == NULL
            || !range_address_is_valid(data, length)
            || !ninlil_model_domain_ranges_are_disjoint(
                data, length, ctx, sizeof(*ctx))) {
            /* Alias/address: leave ctx and data untouched (no FAILED). */
            return NINLIL_E_INVALID_ARGUMENT;
        }
    }
    /* Non-alias semantic gates may transition FAILED. */
    if (ctx->phase != NINLIL_MODEL_DOMAIN_MSD_PHASE_PAYLOAD) {
        msd_fail(ctx);
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /* Reject received > declared before any subtraction (no underflow). */
    if (!msd_payload_counters_ok(ctx)) {
        msd_fail(ctx);
        return NINLIL_E_INVALID_ARGUMENT;
    }
    remaining = ctx->declared_payload_length - ctx->received_payload_length;
    if (length > remaining) {
        msd_fail(ctx);
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (length == 0u) {
        return NINLIL_OK;
    }
    status = msd_sha_update(ctx, data, length);
    if (status != NINLIL_OK) {
        return status;
    }
    ctx->received_payload_length += length;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_message_semantic_digest_begin_evidence(
    ninlil_model_domain_message_semantic_digest_ctx_t *ctx,
    uint32_t evidence_length)
{
    uint8_t be[4];
    ninlil_status_t status;

    if (ctx == NULL || !range_address_is_valid(ctx, sizeof(*ctx))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (ctx->phase != NINLIL_MODEL_DOMAIN_MSD_PHASE_PAYLOAD) {
        msd_fail(ctx);
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!msd_payload_counters_ok(ctx)
        || ctx->received_payload_length != ctx->declared_payload_length) {
        msd_fail(ctx);
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (evidence_length > NINLIL_MODEL_DOMAIN_EVIDENCE_BYTES_MAX) {
        msd_fail(ctx);
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u32_be(be, evidence_length);
    status = msd_sha_update(ctx, be, 4u);
    if (status != NINLIL_OK) {
        return status;
    }
    ctx->declared_evidence_length = evidence_length;
    ctx->received_evidence_length = 0u;
    ctx->phase = NINLIL_MODEL_DOMAIN_MSD_PHASE_EVIDENCE;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_message_semantic_digest_update_evidence(
    ninlil_model_domain_message_semantic_digest_ctx_t *ctx,
    const uint8_t *data,
    uint32_t length)
{
    uint32_t remaining;
    ninlil_status_t status;

    if (ctx == NULL || !range_address_is_valid(ctx, sizeof(*ctx))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (length != 0u) {
        if (data == NULL
            || !range_address_is_valid(data, length)
            || !ninlil_model_domain_ranges_are_disjoint(
                data, length, ctx, sizeof(*ctx))) {
            /* Alias/address: leave ctx and data untouched (no FAILED). */
            return NINLIL_E_INVALID_ARGUMENT;
        }
    }
    if (ctx->phase != NINLIL_MODEL_DOMAIN_MSD_PHASE_EVIDENCE) {
        msd_fail(ctx);
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /* Reject received > declared / declared > max before subtraction. */
    if (!msd_evidence_counters_ok(ctx)) {
        msd_fail(ctx);
        return NINLIL_E_INVALID_ARGUMENT;
    }
    remaining = ctx->declared_evidence_length - ctx->received_evidence_length;
    if (length > remaining) {
        msd_fail(ctx);
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (length == 0u) {
        return NINLIL_OK;
    }
    status = msd_sha_update(ctx, data, length);
    if (status != NINLIL_OK) {
        return status;
    }
    ctx->received_evidence_length += length;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_message_semantic_digest_final(
    ninlil_model_domain_message_semantic_digest_ctx_t *ctx,
    ninlil_model_domain_digest_t *out_digest)
{
    ninlil_status_t status;

    if (out_digest == NULL
        || !range_address_is_valid(out_digest, sizeof(*out_digest))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /*
     * Full address + disjoint gates before zeroing out or reading ctx.
     * Alias/address failure leaves both ranges untouched.
     */
    if (ctx != NULL) {
        if (!range_address_is_valid(ctx, sizeof(*ctx))
            || !ninlil_model_domain_ranges_are_disjoint(
                ctx, sizeof(*ctx), out_digest, sizeof(*out_digest))) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
    }
    (void)memset(out_digest, 0, sizeof(*out_digest));
    if (ctx == NULL || ctx->phase != NINLIL_MODEL_DOMAIN_MSD_PHASE_EVIDENCE
        || !msd_evidence_counters_ok(ctx)
        || !msd_payload_counters_ok(ctx)
        || ctx->received_evidence_length != ctx->declared_evidence_length
        || ctx->received_payload_length != ctx->declared_payload_length) {
        if (ctx != NULL) {
            msd_fail(ctx);
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_model_domain_sha256_final(&ctx->sha, out_digest);
    if (status != NINLIL_OK) {
        msd_fail(ctx);
        (void)memset(out_digest, 0, sizeof(*out_digest));
        return status;
    }
    ctx->phase = NINLIL_MODEL_DOMAIN_MSD_PHASE_DONE;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_message_semantic_digest(
    const ninlil_model_domain_message_semantic_prefix_t *prefix,
    ninlil_bytes_view_t payload,
    ninlil_bytes_view_t evidence,
    ninlil_model_domain_digest_t *out_digest)
{
    ninlil_model_domain_message_semantic_digest_ctx_t ctx;
    ninlil_status_t status;
    size_t n = 0u;
    const void *ptrs[5];
    size_t lens[5];

    if (out_digest == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /*
     * Address + pairwise-disjoint gates across every present participating
     * range BEFORE any write to out_digest (or any other range).
     * Overlap with out is rejected with out left untouched.
     */
    if (prefix != NULL) {
        ptrs[n] = prefix;
        lens[n] = sizeof(*prefix);
        n++;
    }
    if (payload.data != NULL && payload.length != 0u) {
        ptrs[n] = payload.data;
        lens[n] = payload.length;
        n++;
    }
    if (evidence.data != NULL && evidence.length != 0u) {
        ptrs[n] = evidence.data;
        lens[n] = evidence.length;
        n++;
    }
    ptrs[n] = out_digest;
    lens[n] = sizeof(*out_digest);
    n++;
    if (!multi_ranges_ok(ptrs, lens, n)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /* Non-alias path may zero out_digest. */
    (void)memset(out_digest, 0, sizeof(*out_digest));
    if (prefix == NULL
        || !ninlil_model_domain_bytes_view_shape_is_valid(payload)
        || !ninlil_model_domain_bytes_view_shape_is_valid(evidence)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (payload.length != prefix->payload_length) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (evidence.length > NINLIL_MODEL_DOMAIN_EVIDENCE_BYTES_MAX) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_model_domain_message_semantic_digest_init(&ctx, prefix);
    if (status != NINLIL_OK) {
        return status;
    }
    if (payload.length != 0u) {
        status = ninlil_model_domain_message_semantic_digest_update_payload(
            &ctx, payload.data, payload.length);
        if (status != NINLIL_OK) {
            return status;
        }
    }
    status = ninlil_model_domain_message_semantic_digest_begin_evidence(
        &ctx, evidence.length);
    if (status != NINLIL_OK) {
        return status;
    }
    if (evidence.length != 0u) {
        status = ninlil_model_domain_message_semantic_digest_update_evidence(
            &ctx, evidence.data, evidence.length);
        if (status != NINLIL_OK) {
            return status;
        }
    }
    return ninlil_model_domain_message_semantic_digest_final(&ctx, out_digest);
}

/* --- ORDERED_INGRESS --- */

uint32_t ninlil_model_domain_body_ordered_ingress_encoded_length(
    const ninlil_model_domain_body_ordered_ingress_t *body)
{
    uint32_t n;
    uint32_t svc;

    if (body == NULL || !ordered_ingress_fields_ok(body)) {
        return 0u;
    }
    svc = ninlil_model_domain_service_identity_encoded_length(&body->service);
    if (svc == 0u) {
        return 0u;
    }
    /*
     * fixed before service = 276; after service = 300 (docs17 §8.3 layout
     * with controller_ingress_* 32-byte block after reserved1).
     */
    n = 276u + svc + 300u;
    if (n > NINLIL_MODEL_DOMAIN_BODY_ORDERED_INGRESS_MAX) {
        return 0u;
    }
    return n;
}

ninlil_status_t ninlil_model_domain_encode_body_ordered_ingress(
    const ninlil_model_domain_body_ordered_ingress_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    uint32_t required;
    uint32_t o;
    uint32_t svc_len;

    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_alias_ok(body, sizeof(*body), out_bytes, capacity, out_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    required = ninlil_model_domain_body_ordered_ingress_encoded_length(body);
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || required == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    ninlil_model_domain_encode_u64_be(&out_bytes[0], body->ordered_sequence);
    ninlil_model_domain_encode_u64_be(&out_bytes[8], body->owner_sequence);
    ninlil_model_domain_encode_u16_be(&out_bytes[16], body->owner_binding_kind);
    ninlil_model_domain_encode_u16_be(&out_bytes[18], body->reserved0);
    ninlil_model_domain_encode_u32_be(&out_bytes[20], body->message_kind);
    ninlil_model_domain_encode_u32_be(&out_bytes[24], body->message_flags);
    (void)memcpy(&out_bytes[28], body->transaction_id, 16u);
    (void)memcpy(&out_bytes[44], body->attempt_id, 16u);
    (void)memcpy(&out_bytes[60], body->event_id, 16u);
    encode_party(&out_bytes[76], &body->source);
    encode_target(&out_bytes[176], &body->target);
    o = 276u;
    svc_len = encode_service_identity(&out_bytes[o], &body->service);
    o += svc_len;
    (void)memcpy(&out_bytes[o], body->content_digest, 32u);
    o += 32u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->generation);
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
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->receipt_stage);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->disposition);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->effect_certainty);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->retry_guidance);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->cancel_kind);
    o += 4u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->retry_delay_ms);
    o += 8u;
    (void)memcpy(&out_bytes[o], body->evidence_clock_epoch, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->evidence_now_ms);
    o += 8u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->evidence_trust);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->reserved1);
    o += 4u;
    (void)memcpy(&out_bytes[o], body->controller_ingress_clock_epoch, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->controller_ingress_at_ms);
    o += 8u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->controller_ingress_trust);
    o += 4u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->controller_ingress_reserved);
    o += 4u;
    (void)memcpy(&out_bytes[o], body->message_semantic_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->payload_blob_key_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->evidence_blob_key_digest, 32u);
    o += 32u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->ingress_state);
    o += 4u;
    (void)memcpy(&out_bytes[o], body->reservation_key_digest, 32u);
    o += 32u;
    *out_length = o;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_ordered_ingress(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_ordered_ingress_t *out_body)
{
    ninlil_model_domain_body_ordered_ingress_t tmp;
    uint32_t o = 0u;
    uint32_t c = 0u;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length < 276u + 54u + 300u
        || encoded.length > NINLIL_MODEL_DOMAIN_BODY_ORDERED_INGRESS_MAX) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.ordered_sequence = ninlil_model_domain_decode_u64_be(&encoded.data[0]);
    tmp.owner_sequence = ninlil_model_domain_decode_u64_be(&encoded.data[8]);
    tmp.owner_binding_kind =
        ninlil_model_domain_decode_u16_be(&encoded.data[16]);
    tmp.reserved0 = ninlil_model_domain_decode_u16_be(&encoded.data[18]);
    tmp.message_kind = ninlil_model_domain_decode_u32_be(&encoded.data[20]);
    tmp.message_flags = ninlil_model_domain_decode_u32_be(&encoded.data[24]);
    (void)memcpy(tmp.transaction_id, &encoded.data[28], 16u);
    (void)memcpy(tmp.attempt_id, &encoded.data[44], 16u);
    (void)memcpy(tmp.event_id, &encoded.data[60], 16u);
    decode_party(&encoded.data[76], &tmp.source);
    decode_target(&encoded.data[176], &tmp.target);
    o = 276u;
    if (!decode_service_identity(
            encoded.data + o, encoded.length - o, &tmp.service, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += c;
    if (encoded.length - o < 300u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(tmp.content_digest, &encoded.data[o], 32u);
    o += 32u;
    tmp.generation = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    (void)memcpy(tmp.deadline_clock_epoch, &encoded.data[o], 16u);
    o += 16u;
    tmp.absolute_effect_deadline_ms =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.evidence_grace_ms = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.required_evidence = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.receipt_stage = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.disposition = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.effect_certainty = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.retry_guidance = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.cancel_kind = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.retry_delay_ms = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    (void)memcpy(tmp.evidence_clock_epoch, &encoded.data[o], 16u);
    o += 16u;
    tmp.evidence_now_ms = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.evidence_trust = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.reserved1 = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    (void)memcpy(tmp.controller_ingress_clock_epoch, &encoded.data[o], 16u);
    o += 16u;
    tmp.controller_ingress_at_ms =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.controller_ingress_trust =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.controller_ingress_reserved =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    (void)memcpy(tmp.message_semantic_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.payload_blob_key_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.evidence_blob_key_digest, &encoded.data[o], 32u);
    o += 32u;
    tmp.ingress_state = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    (void)memcpy(tmp.reservation_key_digest, &encoded.data[o], 32u);
    o += 32u;
    if (o != encoded.length || !ordered_ingress_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- BLOB helpers (D1-B3c) --- */

static int blob_owner_kind_is_known(uint16_t owner_kind)
{
    return owner_kind == NINLIL_MODEL_DOMAIN_BLOB_OWNER_TRANSACTION
        || owner_kind == NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS
        || owner_kind == NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY;
}

static int blob_kind_is_known(uint16_t blob_kind)
{
    return blob_kind >= NINLIL_MODEL_DOMAIN_BLOB_KIND_COMMAND_PAYLOAD
        && blob_kind <= NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY;
}

/* Allowed (owner, blob_kind) pairs — docs17 §8.3. */
static int blob_owner_kind_pair_ok(uint16_t owner_kind, uint16_t blob_kind)
{
    if (!blob_owner_kind_is_known(owner_kind) || !blob_kind_is_known(blob_kind)) {
        return 0;
    }
    switch (owner_kind) {
    case NINLIL_MODEL_DOMAIN_BLOB_OWNER_TRANSACTION:
        return blob_kind == NINLIL_MODEL_DOMAIN_BLOB_KIND_COMMAND_PAYLOAD
            || blob_kind == NINLIL_MODEL_DOMAIN_BLOB_KIND_EVENT_PAYLOAD;
    case NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS:
        return blob_kind == NINLIL_MODEL_DOMAIN_BLOB_KIND_INGRESS_PAYLOAD
            || blob_kind == NINLIL_MODEL_DOMAIN_BLOB_KIND_EVIDENCE;
    case NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY:
        return blob_kind == NINLIL_MODEL_DOMAIN_BLOB_KIND_COMMAND_PAYLOAD
            || blob_kind == NINLIL_MODEL_DOMAIN_BLOB_KIND_EVENT_PAYLOAD
            || blob_kind == NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY;
    default:
        return 0;
    }
}

static int blob_owner_raw_is_valid(
    uint16_t owner_kind, uint16_t len, const uint8_t *raw)
{
    if (raw == NULL || len == 0u) {
        return 0;
    }
    switch (owner_kind) {
    case NINLIL_MODEL_DOMAIN_BLOB_OWNER_TRANSACTION:
        return len == NINLIL_MODEL_DOMAIN_BLOB_OWNER_KEY_TX_BYTES
            && !id_is_zero(raw);
    case NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS:
        return len == NINLIL_MODEL_DOMAIN_BLOB_OWNER_KEY_INGRESS_BYTES
            && (raw[0] | raw[1] | raw[2] | raw[3] | raw[4] | raw[5] | raw[6]
                | raw[7])
            != 0u;
    case NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY:
        return reservation_owner_raw_is_valid(
            NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_DELIVERY, len, raw);
    default:
        return 0;
    }
}

static int blob_owner_primary_key_digest_ok(
    uint16_t owner_kind,
    uint16_t owner_key_raw_length,
    const uint8_t *owner_key_raw,
    const uint8_t actual[NINLIL_MODEL_DOMAIN_DIGEST_BYTES])
{
    uint8_t raw16[257];
    ninlil_bytes_view_t components;
    uint32_t raw16_len = 0u;

    if (actual == NULL || owner_key_raw == NULL) {
        return 0;
    }
    switch (owner_kind) {
    case NINLIL_MODEL_DOMAIN_BLOB_OWNER_TRANSACTION:
        if (owner_key_raw_length != 16u) {
            return 0;
        }
        return digest_eq_complete_key(
            actual,
            NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
            NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR,
            NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
            owner_key_raw,
            16u);
    case NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS:
        if (owner_key_raw_length != 8u) {
            return 0;
        }
        return digest_eq_complete_key(
            actual,
            NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
            NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS,
            NINLIL_MODEL_DOMAIN_ID_KIND_U64,
            owner_key_raw,
            8u);
    case NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY:
        if (!encode_raw16_into(
                owner_key_raw_length, owner_key_raw, raw16, sizeof(raw16),
                &raw16_len)) {
            return 0;
        }
        components.data = raw16;
        components.length = raw16_len;
        return digest_eq_composite_key(
            actual, NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY, components);
    default:
        return 0;
    }
}

static int blob_id_matches(
    const ninlil_model_domain_body_blob_manifest_t *body)
{
    ninlil_model_domain_digest_t dig;

    if (body == NULL) {
        return 0;
    }
    if (ninlil_model_domain_blob_id_digest(
            body->blob_owner_kind, body->owner_key_raw_length,
            body->owner_key_raw, body->blob_kind, body->content_digest,
            body->total_length, &dig)
        != NINLIL_OK) {
        return 0;
    }
    return memcmp(body->blob_id_digest, dig.bytes, 32u) == 0;
}

static int blob_manifest_length_count_ok(
    uint64_t total_length, uint32_t chunk_count,
    const uint8_t content_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES])
{
    uint32_t expect = 0u;
    ninlil_model_domain_digest_t empty;

    if (content_digest == NULL) {
        return 0;
    }
    if (ninlil_model_domain_blob_chunk_count_for_total(total_length, &expect)
        != NINLIL_OK) {
        return 0;
    }
    if (chunk_count != expect) {
        return 0;
    }
    if (total_length == 0u) {
        if (ninlil_model_domain_sha256(NULL, 0u, &empty) != NINLIL_OK) {
            return 0;
        }
        return memcmp(content_digest, empty.bytes, 32u) == 0;
    }
    return 1;
}

static int blob_manifest_fields_ok(
    const ninlil_model_domain_body_blob_manifest_t *body)
{
    if (body == NULL
        || digest_is_zero(body->blob_id_digest)
        || digest_is_zero(body->content_digest)
        || !blob_owner_kind_pair_ok(body->blob_owner_kind, body->blob_kind)
        || !blob_owner_raw_is_valid(
            body->blob_owner_kind, body->owner_key_raw_length,
            body->owner_key_raw)
        || !blob_owner_primary_key_digest_ok(
            body->blob_owner_kind, body->owner_key_raw_length,
            body->owner_key_raw, body->owner_primary_key_digest)
        || !blob_id_matches(body)
        || !blob_manifest_length_count_ok(
            body->total_length, body->chunk_count, body->content_digest)) {
        return 0;
    }
    return 1;
}

/* KEY_DIGEST of complete BLOB manifest key for this blob_id. */
static int blob_manifest_key_digest_ok(
    const uint8_t blob_id[NINLIL_MODEL_DOMAIN_DIGEST_BYTES],
    const uint8_t actual[NINLIL_MODEL_DOMAIN_DIGEST_BYTES])
{
    uint8_t components[1u + 32u];
    ninlil_bytes_view_t cv;

    if (blob_id == NULL || actual == NULL) {
        return 0;
    }
    components[0] = 1u;
    (void)memcpy(&components[1], blob_id, 32u);
    cv.data = components;
    cv.length = 33u;
    return digest_eq_composite_key(
        actual, NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB, cv);
}

static int blob_chunk_local_length_ok(
    uint32_t chunk_index,
    uint32_t chunk_count,
    uint64_t total_length,
    uint32_t chunk_length)
{
    uint32_t expect_count = 0u;
    uint64_t prior;
    uint64_t final_len;

    if (chunk_count == 0u || chunk_index >= chunk_count
        || total_length == 0u
        || chunk_length == 0u
        || chunk_length > NINLIL_MODEL_DOMAIN_BLOB_CHUNK_DATA_MAX_BYTES) {
        return 0;
    }
    if (ninlil_model_domain_blob_chunk_count_for_total(
            total_length, &expect_count)
            != NINLIL_OK
        || expect_count != chunk_count) {
        return 0;
    }
    if (chunk_index + 1u < chunk_count) {
        /* Non-final: exact full chunk. */
        return chunk_length == NINLIL_MODEL_DOMAIN_BLOB_CHUNK_DATA_MAX_BYTES;
    }
    /* Final: total_length - 3072*(chunk_count-1) in 1..3072. */
    prior = (uint64_t)(chunk_count - 1u)
        * (uint64_t)NINLIL_MODEL_DOMAIN_BLOB_CHUNK_DATA_MAX_BYTES;
    if (total_length <= prior) {
        return 0;
    }
    final_len = total_length - prior;
    if (final_len == 0u
        || final_len > NINLIL_MODEL_DOMAIN_BLOB_CHUNK_DATA_MAX_BYTES
        || final_len != (uint64_t)chunk_length) {
        return 0;
    }
    return 1;
}

static int blob_chunk_content_digest_ok(
    const ninlil_model_domain_body_blob_chunk_t *body)
{
    ninlil_model_domain_digest_t dig;

    if (body == NULL || body->chunk_bytes == NULL
        || digest_is_zero(body->content_digest)) {
        return 0;
    }
    /* Multi-chunk stream digest is D3 — do not recompute from one chunk. */
    if (body->chunk_count != 1u) {
        return 1;
    }
    if (ninlil_model_domain_sha256(
            body->chunk_bytes, body->chunk_length, &dig)
        != NINLIL_OK) {
        return 0;
    }
    return memcmp(body->content_digest, dig.bytes, 32u) == 0;
}

static int blob_chunk_fields_ok(
    const ninlil_model_domain_body_blob_chunk_t *body)
{
    if (body == NULL
        || body->chunk_bytes == NULL
        || digest_is_zero(body->blob_id_digest)
        || digest_is_zero(body->manifest_key_digest)
        || !blob_chunk_local_length_ok(
            body->chunk_index, body->chunk_count, body->total_length,
            body->chunk_length)
        || !blob_manifest_key_digest_ok(
            body->blob_id_digest, body->manifest_key_digest)
        || !blob_chunk_content_digest_ok(body)) {
        return 0;
    }
    return 1;
}

ninlil_status_t ninlil_model_domain_blob_id_digest(
    uint16_t blob_owner_kind,
    uint16_t owner_key_raw_length,
    const uint8_t *owner_key_raw,
    uint16_t blob_kind,
    const uint8_t content_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES],
    uint64_t total_length,
    ninlil_model_domain_digest_t *out_digest)
{
    ninlil_model_domain_sha256_ctx_t ctx;
    uint8_t be16[2];
    uint8_t be64[8];
    size_t n = 0u;
    const void *ptrs[4];
    size_t lens[4];

    if (out_digest != NULL) {
        ptrs[n] = out_digest;
        lens[n] = sizeof(*out_digest);
        n++;
    }
    if (owner_key_raw != NULL && owner_key_raw_length != 0u) {
        ptrs[n] = owner_key_raw;
        lens[n] = owner_key_raw_length;
        n++;
    }
    if (content_digest != NULL) {
        ptrs[n] = content_digest;
        lens[n] = NINLIL_MODEL_DOMAIN_DIGEST_BYTES;
        n++;
    }
    if (!multi_ranges_ok(ptrs, lens, n)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (out_digest == NULL || content_digest == NULL
        || owner_key_raw_length > 255u
        || (owner_key_raw_length != 0u && owner_key_raw == NULL)
        || digest_is_zero(content_digest)
        || !blob_owner_kind_pair_ok(blob_owner_kind, blob_kind)
        || !blob_owner_raw_is_valid(
            blob_owner_kind, owner_key_raw_length, owner_key_raw)) {
        if (out_digest != NULL) {
            (void)memset(out_digest, 0, sizeof(*out_digest));
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }

    ninlil_model_domain_sha256_init(&ctx);
    if (ninlil_model_domain_sha256_update(
            &ctx, (const uint8_t *)PREIMAGE_BLOB_ID,
            (uint32_t)(sizeof(PREIMAGE_BLOB_ID) - 1u))
        != NINLIL_OK) {
        (void)memset(out_digest, 0, sizeof(*out_digest));
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u16_be(be16, blob_owner_kind);
    if (ninlil_model_domain_sha256_update(&ctx, be16, 2u) != NINLIL_OK) {
        (void)memset(out_digest, 0, sizeof(*out_digest));
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u16_be(be16, owner_key_raw_length);
    if (ninlil_model_domain_sha256_update(&ctx, be16, 2u) != NINLIL_OK
        || (owner_key_raw_length != 0u
            && ninlil_model_domain_sha256_update(
                   &ctx, owner_key_raw, owner_key_raw_length)
                != NINLIL_OK)) {
        (void)memset(out_digest, 0, sizeof(*out_digest));
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u16_be(be16, blob_kind);
    if (ninlil_model_domain_sha256_update(&ctx, be16, 2u) != NINLIL_OK
        || ninlil_model_domain_sha256_update(
               &ctx, content_digest, NINLIL_MODEL_DOMAIN_DIGEST_BYTES)
            != NINLIL_OK) {
        (void)memset(out_digest, 0, sizeof(*out_digest));
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u64_be(be64, total_length);
    if (ninlil_model_domain_sha256_update(&ctx, be64, 8u) != NINLIL_OK
        || ninlil_model_domain_sha256_final(&ctx, out_digest) != NINLIL_OK) {
        (void)memset(out_digest, 0, sizeof(*out_digest));
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_blob_chunk_count_for_total(
    uint64_t total_length,
    uint32_t *out_chunk_count)
{
    uint64_t chunks;
    const uint64_t max_chunk =
        (uint64_t)NINLIL_MODEL_DOMAIN_BLOB_CHUNK_DATA_MAX_BYTES;

    /*
     * Address-first: forged near-UINTPTR_MAX outputs must return
     * INVALID_ARGUMENT without writing or crashing. Only after the full
     * out_chunk_count object range is known-valid may we zero or store.
     */
    if (out_chunk_count == NULL
        || !range_address_is_valid(
            out_chunk_count, sizeof(*out_chunk_count))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_chunk_count = 0u;
    if (total_length == 0u) {
        return NINLIL_OK;
    }
    /* checked ceil: (total + max - 1) / max, result must fit u32 */
    if (total_length > UINT64_MAX - (max_chunk - 1u)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    chunks = (total_length + max_chunk - 1u) / max_chunk;
    if (chunks == 0u || chunks > (uint64_t)UINT32_MAX) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_chunk_count = (uint32_t)chunks;
    return NINLIL_OK;
}

uint32_t ninlil_model_domain_body_blob_manifest_encoded_length(
    const ninlil_model_domain_body_blob_manifest_t *body)
{
    uint32_t n;
    if (body == NULL || !blob_manifest_fields_ok(body)) {
        return 0u;
    }
    /* dig32 + u16 + u16 + RAW16 + dig32 + u64 + u32 + dig32 */
    n = 32u + 2u + 2u + 2u + (uint32_t)body->owner_key_raw_length + 32u + 8u
        + 4u + 32u;
    if (n > NINLIL_MODEL_DOMAIN_BODY_BLOB_MAX) {
        return 0u;
    }
    return n;
}

ninlil_status_t ninlil_model_domain_encode_body_blob_manifest(
    const ninlil_model_domain_body_blob_manifest_t *body,
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
    required = ninlil_model_domain_body_blob_manifest_encoded_length(body);
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || required == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    (void)memcpy(&out_bytes[0], body->blob_id_digest, 32u);
    ninlil_model_domain_encode_u16_be(&out_bytes[32], body->blob_owner_kind);
    ninlil_model_domain_encode_u16_be(&out_bytes[34], body->blob_kind);
    o = 36u;
    o += encode_raw16(
        &out_bytes[o], body->owner_key_raw_length, body->owner_key_raw);
    (void)memcpy(&out_bytes[o], body->owner_primary_key_digest, 32u);
    o += 32u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->total_length);
    o += 8u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->chunk_count);
    o += 4u;
    (void)memcpy(&out_bytes[o], body->content_digest, 32u);
    o += 32u;
    *out_length = o;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_blob_manifest(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_blob_manifest_t *out_body)
{
    ninlil_model_domain_body_blob_manifest_t tmp;
    uint32_t o = 0u;
    uint32_t c = 0u;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length < 36u + 2u
        || encoded.length > NINLIL_MODEL_DOMAIN_BODY_BLOB_MAX) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    (void)memcpy(tmp.blob_id_digest, &encoded.data[0], 32u);
    tmp.blob_owner_kind = ninlil_model_domain_decode_u16_be(&encoded.data[32]);
    tmp.blob_kind = ninlil_model_domain_decode_u16_be(&encoded.data[34]);
    o = 36u;
    if (!decode_raw16_view(
            encoded.data + o, encoded.length - o,
            (uint16_t)NINLIL_MODEL_DOMAIN_RAW16_OWNER_KEY_MAX,
            &tmp.owner_key_raw_length, &tmp.owner_key_raw, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += c;
    /* dig32 + u64 + u32 + dig32 = 76 */
    if (encoded.length - o < 76u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(tmp.owner_primary_key_digest, &encoded.data[o], 32u);
    o += 32u;
    tmp.total_length = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.chunk_count = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    (void)memcpy(tmp.content_digest, &encoded.data[o], 32u);
    o += 32u;
    if (o != encoded.length || !blob_manifest_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

uint32_t ninlil_model_domain_body_blob_chunk_encoded_length(
    const ninlil_model_domain_body_blob_chunk_t *body)
{
    uint32_t n;
    if (body == NULL || !blob_chunk_fields_ok(body)) {
        return 0u;
    }
    /* dig32 + dig32 + u32 + u32 + u64 + dig32 + u32 + bytes */
    n = 32u + 32u + 4u + 4u + 8u + 32u + 4u + body->chunk_length;
    if (n > NINLIL_MODEL_DOMAIN_BODY_BLOB_MAX) {
        return 0u;
    }
    return n;
}

ninlil_status_t ninlil_model_domain_encode_body_blob_chunk(
    const ninlil_model_domain_body_blob_chunk_t *body,
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
        if (body->chunk_bytes != NULL && body->chunk_length != 0u) {
            ptrs[n] = body->chunk_bytes;
            lens[n] = body->chunk_length;
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
    required = ninlil_model_domain_body_blob_chunk_encoded_length(body);
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || required == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    (void)memcpy(&out_bytes[0], body->blob_id_digest, 32u);
    (void)memcpy(&out_bytes[32], body->manifest_key_digest, 32u);
    ninlil_model_domain_encode_u32_be(&out_bytes[64], body->chunk_index);
    ninlil_model_domain_encode_u32_be(&out_bytes[68], body->chunk_count);
    ninlil_model_domain_encode_u64_be(&out_bytes[72], body->total_length);
    (void)memcpy(&out_bytes[80], body->content_digest, 32u);
    ninlil_model_domain_encode_u32_be(&out_bytes[112], body->chunk_length);
    o = 116u;
    if (body->chunk_length != 0u) {
        (void)memcpy(&out_bytes[o], body->chunk_bytes, body->chunk_length);
        o += body->chunk_length;
    }
    *out_length = o;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_blob_chunk(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_blob_chunk_t *out_body)
{
    ninlil_model_domain_body_blob_chunk_t tmp;
    uint32_t o = 0u;
    uint32_t clen;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length < 116u
        || encoded.length > NINLIL_MODEL_DOMAIN_BODY_BLOB_MAX) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    (void)memcpy(tmp.blob_id_digest, &encoded.data[0], 32u);
    (void)memcpy(tmp.manifest_key_digest, &encoded.data[32], 32u);
    tmp.chunk_index = ninlil_model_domain_decode_u32_be(&encoded.data[64]);
    tmp.chunk_count = ninlil_model_domain_decode_u32_be(&encoded.data[68]);
    tmp.total_length = ninlil_model_domain_decode_u64_be(&encoded.data[72]);
    (void)memcpy(tmp.content_digest, &encoded.data[80], 32u);
    clen = ninlil_model_domain_decode_u32_be(&encoded.data[112]);
    o = 116u;
    /*
     * Zero length is always corrupt for a stored chunk row. Do not treat
     * the generic D1-A 0..3072 logical-view bound as sufficient validity.
     */
    if (clen == 0u
        || clen > NINLIL_MODEL_DOMAIN_BLOB_CHUNK_DATA_MAX_BYTES
        || encoded.length - o != clen) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    tmp.chunk_length = clen;
    tmp.chunk_bytes = &encoded.data[o];
    o += clen;
    if (o != encoded.length || !blob_chunk_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- ATTEMPT helpers (D1-B3d) --- */

static int attempt_owner_kind_is_known(uint16_t owner_kind)
{
    return owner_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION
        || owner_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_DELIVERY;
}

static int attempt_kind_is_known(uint16_t attempt_kind)
{
    return attempt_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_KIND_COMMAND
        || attempt_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_KIND_EVENT
        || attempt_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_KIND_CANCEL;
}

static int attempt_state_is_known(uint16_t attempt_state)
{
    return attempt_state == NINLIL_MODEL_DOMAIN_ATTEMPT_STATE_PREPARED
        || attempt_state == NINLIL_MODEL_DOMAIN_ATTEMPT_STATE_OBSERVED_SENT
        || attempt_state == NINLIL_MODEL_DOMAIN_ATTEMPT_STATE_RESOLVED
        || attempt_state
            == NINLIL_MODEL_DOMAIN_ATTEMPT_STATE_RECOVERY_REQUIRED;
}

static int attempt_send_state_is_known(uint32_t send_state)
{
    return send_state == NINLIL_MODEL_DOMAIN_ATTEMPT_SEND_PREPARED
        || send_state == NINLIL_MODEL_DOMAIN_ATTEMPT_SEND_RETRYABLE_NO_SEND
        || send_state == NINLIL_MODEL_DOMAIN_ATTEMPT_SEND_SENT_POSSIBLE
        || send_state == NINLIL_MODEL_DOMAIN_ATTEMPT_SEND_CLOSED_DENIED
        || send_state == NINLIL_MODEL_DOMAIN_ATTEMPT_SEND_RECOVERY_REQUIRED;
}

/* Receipt timeout: (0,0) or (epoch non-zero, at_ms non-zero) only. */
static int attempt_timeout_pair_ok(
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

/*
 * send_counter_exhausted exact 0/1; =1 iff gen==UINT64_MAX or inv==UINT64_MAX.
 * Always require inv <= gen.
 */
static int attempt_counter_rules_ok(
    uint64_t gen, uint64_t inv, uint32_t exhausted)
{
    int at_max;

    if (inv > gen) {
        return 0;
    }
    if (exhausted != 0u && exhausted != 1u) {
        return 0;
    }
    at_max = (gen == UINT64_MAX) || (inv == UINT64_MAX);
    if (exhausted == 1u) {
        return at_max;
    }
    return !at_max;
}

static int attempt_counters_all_zero(
    uint64_t gen, uint64_t inv, uint32_t exhausted)
{
    return gen == 0u && inv == 0u && exhausted == 0u;
}

/* Local TX COMMAND/EVENT cycle fields (docs17 §8.3). */
static int attempt_local_cycle_ok(
    uint16_t attempt_kind,
    uint64_t retry_cycle_id,
    uint32_t attempt_in_cycle,
    uint64_t cumulative_attempts)
{
    if (attempt_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_KIND_COMMAND) {
        return retry_cycle_id == 0u && attempt_in_cycle == 0u
            && cumulative_attempts >= 1u;
    }
    if (attempt_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_KIND_EVENT) {
        return retry_cycle_id >= 1u
            && attempt_in_cycle >= 1u
            && attempt_in_cycle <= NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE
            && cumulative_attempts >= (uint64_t)attempt_in_cycle;
    }
    if (attempt_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_KIND_CANCEL) {
        return retry_cycle_id == 0u && attempt_in_cycle == 0u
            && cumulative_attempts == 0u;
    }
    return 0;
}

/* DELIVERY remote: cycle always zero (not local COMMAND/EVENT cycle rules). */
static int attempt_remote_cycle_zero(
    uint64_t retry_cycle_id,
    uint32_t attempt_in_cycle,
    uint64_t cumulative_attempts)
{
    return retry_cycle_id == 0u && attempt_in_cycle == 0u
        && cumulative_attempts == 0u;
}

/*
 * TxGate path: gen>=1, inv=0, availability=0.
 * Bearer path: gen>=1, inv>=1, inv<=gen, availability non-zero.
 * Exact either for RESOLVED + RETRYABLE_NO_SEND / CLOSED_DENIED (CMD/EVT).
 */
static int attempt_txgate_path_ok(uint64_t gen, uint64_t inv, uint64_t avail)
{
    return gen >= 1u && inv == 0u && avail == 0u;
}

static int attempt_bearer_path_ok(uint64_t gen, uint64_t inv, uint64_t avail)
{
    return gen >= 1u && inv >= 1u && inv <= gen && avail != 0u;
}

static int attempt_resolved_path_ok(uint64_t gen, uint64_t inv, uint64_t avail)
{
    return attempt_txgate_path_ok(gen, inv, avail)
        || attempt_bearer_path_ok(gen, inv, avail);
}

/*
 * TRANSACTION-owned local closed matrix (docs17 §8.3). Rows outside the table
 * are corrupt. CANCEL counters always 0; CMD/EVT follow path coupling.
 */
static int attempt_local_matrix_ok(
    const ninlil_model_domain_body_attempt_t *body)
{
    uint16_t kind;
    uint16_t state;
    uint32_t send;
    uint64_t gen;
    uint64_t inv;
    uint32_t exhausted;
    uint64_t avail;
    int timeout_cleared;
    int timeout_ok;

    if (body == NULL) {
        return 0;
    }
    kind = body->attempt_kind;
    state = body->attempt_state;
    send = body->send_state;
    gen = body->send_operation_generation;
    inv = body->send_invocation_count;
    exhausted = body->send_counter_exhausted;
    avail = body->availability_epoch;
    timeout_ok = attempt_timeout_pair_ok(
        body->receipt_timeout_clock_epoch, body->receipt_timeout_at_ms);
    timeout_cleared = id_is_zero(body->receipt_timeout_clock_epoch)
        && body->receipt_timeout_at_ms == 0u;
    if (!timeout_ok) {
        return 0;
    }
    if (!attempt_local_cycle_ok(
            kind, body->retry_cycle_id, body->attempt_in_cycle,
            body->cumulative_attempts)) {
        return 0;
    }

    if (kind == NINLIL_MODEL_DOMAIN_ATTEMPT_KIND_COMMAND
        || kind == NINLIL_MODEL_DOMAIN_ATTEMPT_KIND_EVENT) {
        if (!attempt_counter_rules_ok(gen, inv, exhausted)) {
            return 0;
        }
        if (state == NINLIL_MODEL_DOMAIN_ATTEMPT_STATE_PREPARED
            && send == NINLIL_MODEL_DOMAIN_ATTEMPT_SEND_PREPARED) {
            return gen == 0u && inv == 0u && exhausted == 0u && avail == 0u
                && timeout_cleared;
        }
        if (state == NINLIL_MODEL_DOMAIN_ATTEMPT_STATE_RESOLVED
            && send == NINLIL_MODEL_DOMAIN_ATTEMPT_SEND_RETRYABLE_NO_SEND) {
            return timeout_cleared
                && attempt_resolved_path_ok(gen, inv, avail);
        }
        if (state == NINLIL_MODEL_DOMAIN_ATTEMPT_STATE_RESOLVED
            && send == NINLIL_MODEL_DOMAIN_ATTEMPT_SEND_CLOSED_DENIED) {
            return timeout_cleared
                && attempt_resolved_path_ok(gen, inv, avail);
        }
        if (state == NINLIL_MODEL_DOMAIN_ATTEMPT_STATE_OBSERVED_SENT
            && send == NINLIL_MODEL_DOMAIN_ATTEMPT_SEND_SENT_POSSIBLE) {
            /* timeout active or cleared; both exact 2-forms already checked */
            return gen >= 1u && inv >= 1u && inv <= gen && avail != 0u;
        }
        if (state == NINLIL_MODEL_DOMAIN_ATTEMPT_STATE_RESOLVED
            && send == NINLIL_MODEL_DOMAIN_ATTEMPT_SEND_SENT_POSSIBLE) {
            return gen >= 1u && inv >= 1u && inv <= gen && avail != 0u
                && timeout_cleared;
        }
        if (state == NINLIL_MODEL_DOMAIN_ATTEMPT_STATE_RECOVERY_REQUIRED
            && send == NINLIL_MODEL_DOMAIN_ATTEMPT_SEND_RECOVERY_REQUIRED) {
            /* frozen counters (rules already ok); avail any; timeout 2-form */
            return 1;
        }
        return 0;
    }

    if (kind == NINLIL_MODEL_DOMAIN_ATTEMPT_KIND_CANCEL) {
        if (!attempt_counters_all_zero(gen, inv, exhausted)) {
            return 0;
        }
        if (state == NINLIL_MODEL_DOMAIN_ATTEMPT_STATE_PREPARED
            && send == NINLIL_MODEL_DOMAIN_ATTEMPT_SEND_PREPARED) {
            return avail == 0u && timeout_cleared;
        }
        if (state == NINLIL_MODEL_DOMAIN_ATTEMPT_STATE_PREPARED
            && send == NINLIL_MODEL_DOMAIN_ATTEMPT_SEND_RETRYABLE_NO_SEND) {
            return avail != 0u && timeout_cleared;
        }
        if (state == NINLIL_MODEL_DOMAIN_ATTEMPT_STATE_RESOLVED
            && send == NINLIL_MODEL_DOMAIN_ATTEMPT_SEND_SENT_POSSIBLE) {
            return avail != 0u && timeout_cleared;
        }
        if (state == NINLIL_MODEL_DOMAIN_ATTEMPT_STATE_RESOLVED
            && send == NINLIL_MODEL_DOMAIN_ATTEMPT_SEND_CLOSED_DENIED) {
            /* avail 0 (TxGate) or non-zero (Bearer) — both legal */
            return timeout_cleared;
        }
        if (state == NINLIL_MODEL_DOMAIN_ATTEMPT_STATE_RECOVERY_REQUIRED
            && send == NINLIL_MODEL_DOMAIN_ATTEMPT_SEND_RECOVERY_REQUIRED) {
            return 1;
        }
        return 0;
    }
    return 0;
}

/* DELIVERY-owned remote ingress: RESOLVED/SENT_POSSIBLE + all cycle/counters 0. */
static int attempt_remote_matrix_ok(
    const ninlil_model_domain_body_attempt_t *body)
{
    if (body == NULL) {
        return 0;
    }
    if (body->attempt_state != NINLIL_MODEL_DOMAIN_ATTEMPT_STATE_RESOLVED
        || body->send_state != NINLIL_MODEL_DOMAIN_ATTEMPT_SEND_SENT_POSSIBLE) {
        return 0;
    }
    if (!attempt_kind_is_known(body->attempt_kind)) {
        return 0;
    }
    if (!attempt_remote_cycle_zero(
            body->retry_cycle_id, body->attempt_in_cycle,
            body->cumulative_attempts)) {
        return 0;
    }
    if (!attempt_counters_all_zero(
            body->send_operation_generation, body->send_invocation_count,
            body->send_counter_exhausted)) {
        return 0;
    }
    if (body->availability_epoch != 0u) {
        return 0;
    }
    if (!id_is_zero(body->receipt_timeout_clock_epoch)
        || body->receipt_timeout_at_ms != 0u) {
        return 0;
    }
    return 1;
}

static int attempt_owner_raw_is_valid(
    uint16_t owner_kind,
    uint16_t len,
    const uint8_t *raw,
    const uint8_t transaction_id[NINLIL_MODEL_DOMAIN_ID_BYTES])
{
    if (raw == NULL || transaction_id == NULL) {
        return 0;
    }
    if (owner_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION) {
        return len == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_KEY_TX_BYTES
            && !id_is_zero(raw)
            && memcmp(raw, transaction_id, 16u) == 0;
    }
    if (owner_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_DELIVERY) {
        /* Exact 80; txn component [32,48) matches body transaction_id. */
        if (len != NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_KEY_DELIVERY_BYTES) {
            return 0;
        }
        if (!reservation_owner_raw_is_valid(
                NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_DELIVERY, len, raw)) {
            return 0;
        }
        return memcmp(raw + 32, transaction_id, 16u) == 0;
    }
    return 0;
}

static int attempt_primary_key_digest_ok(
    uint16_t owner_kind,
    uint16_t owner_key_raw_length,
    const uint8_t *owner_key_raw,
    const uint8_t transaction_id[NINLIL_MODEL_DOMAIN_ID_BYTES],
    const uint8_t actual[NINLIL_MODEL_DOMAIN_DIGEST_BYTES])
{
    /* 2-byte RAW16 length prefix + attempt owner_key_raw max (TX=16 / DLV=80). */
    uint8_t raw16[2u + NINLIL_MODEL_DOMAIN_RAW16_ATTEMPT_OWNER_KEY_MAX];
    ninlil_bytes_view_t components;
    uint32_t raw16_len = 0u;

    if (actual == NULL || owner_key_raw == NULL || transaction_id == NULL) {
        return 0;
    }
    if (owner_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION) {
        if (owner_key_raw_length != 16u) {
            return 0;
        }
        return digest_eq_complete_key(
            actual,
            NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
            NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR,
            NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
            transaction_id,
            16u);
    }
    if (owner_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_DELIVERY) {
        if (!encode_raw16_into(
                owner_key_raw_length, owner_key_raw, raw16, sizeof(raw16),
                &raw16_len)) {
            return 0;
        }
        components.data = raw16;
        components.length = raw16_len;
        return digest_eq_composite_key(
            actual, NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY, components);
    }
    return 0;
}

static int attempt_fields_ok(const ninlil_model_domain_body_attempt_t *body)
{
    if (body == NULL
        || id_is_zero(body->attempt_id)
        || id_is_zero(body->transaction_id)
        || digest_is_zero(body->target_digest)
        || digest_is_zero(body->primary_key_digest)
        || digest_is_zero(body->message_semantic_digest)
        || body->reserved0 != 0u
        || body->reserved1 != 0u
        || id_is_zero(body->prepared_clock_epoch)
        || !attempt_owner_kind_is_known(body->attempt_owner_kind)
        || !attempt_kind_is_known(body->attempt_kind)
        || !attempt_state_is_known(body->attempt_state)
        || !attempt_send_state_is_known(body->send_state)
        || !attempt_owner_raw_is_valid(
            body->attempt_owner_kind, body->owner_key_raw_length,
            body->owner_key_raw, body->transaction_id)
        || !attempt_primary_key_digest_ok(
            body->attempt_owner_kind, body->owner_key_raw_length,
            body->owner_key_raw, body->transaction_id,
            body->primary_key_digest)) {
        return 0;
    }
    if (body->attempt_owner_kind
        == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION) {
        return attempt_local_matrix_ok(body);
    }
    if (body->attempt_owner_kind
        == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_DELIVERY) {
        return attempt_remote_matrix_ok(body);
    }
    return 0;
}

uint32_t ninlil_model_domain_body_attempt_encoded_length(
    const ninlil_model_domain_body_attempt_t *body)
{
    uint32_t n;
    if (body == NULL || !attempt_fields_ok(body)) {
        return 0u;
    }
    /*
     * attempt_id16 + owner_kind u16 + reserved0 u16 + RAW16 + pkd32 +
     * txn16 + target32 + kind u16 + state u16 + cycle u64 + in_cycle u32 +
     * cum u64 + gen u64 + inv u64 + exhausted u32 + reserved1 u32 +
     * semantic32 + prepared_ep16 + prepared_at u64 + send u32 +
     * avail u64 + timeout_ep16 + timeout_at u64
     * = 242 + owner_key_raw_length
     */
    n = 242u + (uint32_t)body->owner_key_raw_length;
    if (n > NINLIL_MODEL_DOMAIN_BODY_ATTEMPT_MAX) {
        return 0u;
    }
    return n;
}

ninlil_status_t ninlil_model_domain_encode_body_attempt(
    const ninlil_model_domain_body_attempt_t *body,
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
    required = ninlil_model_domain_body_attempt_encoded_length(body);
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || required == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    (void)memcpy(&out_bytes[0], body->attempt_id, 16u);
    ninlil_model_domain_encode_u16_be(&out_bytes[16], body->attempt_owner_kind);
    ninlil_model_domain_encode_u16_be(&out_bytes[18], body->reserved0);
    o = 20u;
    o += encode_raw16(
        &out_bytes[o], body->owner_key_raw_length, body->owner_key_raw);
    (void)memcpy(&out_bytes[o], body->primary_key_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->transaction_id, 16u);
    o += 16u;
    (void)memcpy(&out_bytes[o], body->target_digest, 32u);
    o += 32u;
    ninlil_model_domain_encode_u16_be(&out_bytes[o], body->attempt_kind);
    o += 2u;
    ninlil_model_domain_encode_u16_be(&out_bytes[o], body->attempt_state);
    o += 2u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->retry_cycle_id);
    o += 8u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->attempt_in_cycle);
    o += 4u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->cumulative_attempts);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->send_operation_generation);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->send_invocation_count);
    o += 8u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->send_counter_exhausted);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->reserved1);
    o += 4u;
    (void)memcpy(&out_bytes[o], body->message_semantic_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->prepared_clock_epoch, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->prepared_at_ms);
    o += 8u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->send_state);
    o += 4u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->availability_epoch);
    o += 8u;
    (void)memcpy(&out_bytes[o], body->receipt_timeout_clock_epoch, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->receipt_timeout_at_ms);
    o += 8u;
    *out_length = o;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_attempt(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_attempt_t *out_body)
{
    ninlil_model_domain_body_attempt_t tmp;
    uint32_t o = 0u;
    uint32_t c = 0u;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length < 20u + 2u
        || encoded.length > NINLIL_MODEL_DOMAIN_BODY_ATTEMPT_MAX) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    (void)memcpy(tmp.attempt_id, &encoded.data[0], 16u);
    tmp.attempt_owner_kind =
        ninlil_model_domain_decode_u16_be(&encoded.data[16]);
    tmp.reserved0 = ninlil_model_domain_decode_u16_be(&encoded.data[18]);
    o = 20u;
    if (!decode_raw16_view(
            encoded.data + o, encoded.length - o,
            (uint16_t)NINLIL_MODEL_DOMAIN_RAW16_ATTEMPT_OWNER_KEY_MAX,
            &tmp.owner_key_raw_length, &tmp.owner_key_raw, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += c;
    /* After RAW16: 32+16+32+2+2+8+4+8+8+8+4+4+32+16+8+4+8+16+8 = 220 */
    if (encoded.length - o < 220u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(tmp.primary_key_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.transaction_id, &encoded.data[o], 16u);
    o += 16u;
    (void)memcpy(tmp.target_digest, &encoded.data[o], 32u);
    o += 32u;
    tmp.attempt_kind = ninlil_model_domain_decode_u16_be(&encoded.data[o]);
    o += 2u;
    tmp.attempt_state = ninlil_model_domain_decode_u16_be(&encoded.data[o]);
    o += 2u;
    tmp.retry_cycle_id = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.attempt_in_cycle = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.cumulative_attempts =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.send_operation_generation =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.send_invocation_count =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.send_counter_exhausted =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.reserved1 = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    (void)memcpy(tmp.message_semantic_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.prepared_clock_epoch, &encoded.data[o], 16u);
    o += 16u;
    tmp.prepared_at_ms = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.send_state = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.availability_epoch =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    (void)memcpy(tmp.receipt_timeout_clock_epoch, &encoded.data[o], 16u);
    o += 16u;
    tmp.receipt_timeout_at_ms =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    if (o != encoded.length || !attempt_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- ATTEMPT_ID_INDEX helpers (D1-B3e) --- */

/*
 * attempt_record_key_digest must equal KEY_DIGEST(complete ATTEMPT key)
 * where ATTEMPT identity is COMPOSITE(31, TRANSACTION owner kind u16=1 ||
 * RAW16(len16, transaction_id) || attempt_id). Bare composite digest alone
 * is never accepted (docs17 §8.4).
 */
static int attempt_id_index_record_key_digest_ok(
    const ninlil_model_domain_body_attempt_id_index_t *body)
{
    uint8_t components[2u + 2u + 16u + 16u];
    ninlil_bytes_view_t cv;
    uint32_t o;

    if (body == NULL) {
        return 0;
    }
    ninlil_model_domain_encode_u16_be(
        components, NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION);
    o = 2u;
    o += encode_raw16(
        &components[o], NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_KEY_TX_BYTES,
        body->transaction_id);
    (void)memcpy(
        &components[o], body->attempt_id, NINLIL_MODEL_DOMAIN_ID_BYTES);
    o += NINLIL_MODEL_DOMAIN_ID_BYTES;
    cv.data = components;
    cv.length = o;
    return digest_eq_composite_key(
        body->attempt_record_key_digest,
        NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT,
        cv);
}

static int attempt_id_index_fields_ok(
    const ninlil_model_domain_body_attempt_id_index_t *body)
{
    if (body == NULL) {
        return 0;
    }
    if (id_is_zero(body->attempt_id) || id_is_zero(body->transaction_id)) {
        return 0;
    }
    if (!attempt_kind_is_known(body->attempt_kind) || body->reserved != 0u) {
        return 0;
    }
    if (digest_is_zero(body->attempt_creation_value_digest)) {
        return 0;
    }
    return attempt_id_index_record_key_digest_ok(body);
}

/* --- ATTEMPT_ID_INDEX (0x34) --- */

uint32_t ninlil_model_domain_body_attempt_id_index_encoded_length(void)
{
    return NINLIL_MODEL_DOMAIN_BODY_ATTEMPT_ID_INDEX_BYTES;
}

ninlil_status_t ninlil_model_domain_encode_body_attempt_id_index(
    const ninlil_model_domain_body_attempt_id_index_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    const uint32_t required =
        NINLIL_MODEL_DOMAIN_BODY_ATTEMPT_ID_INDEX_BYTES;
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
        || !attempt_id_index_fields_ok(body)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    (void)memcpy(&out_bytes[0], body->attempt_id, 16u);
    (void)memcpy(&out_bytes[16], body->transaction_id, 16u);
    ninlil_model_domain_encode_u16_be(&out_bytes[32], body->attempt_kind);
    ninlil_model_domain_encode_u16_be(&out_bytes[34], 0u);
    (void)memcpy(&out_bytes[36], body->attempt_record_key_digest, 32u);
    (void)memcpy(&out_bytes[68], body->attempt_creation_value_digest, 32u);
    *out_length = required;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_attempt_id_index(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_attempt_id_index_t *out_body)
{
    ninlil_model_domain_body_attempt_id_index_t tmp;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length
            != NINLIL_MODEL_DOMAIN_BODY_ATTEMPT_ID_INDEX_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    (void)memcpy(tmp.attempt_id, &encoded.data[0], 16u);
    (void)memcpy(tmp.transaction_id, &encoded.data[16], 16u);
    tmp.attempt_kind = ninlil_model_domain_decode_u16_be(&encoded.data[32]);
    tmp.reserved = ninlil_model_domain_decode_u16_be(&encoded.data[34]);
    (void)memcpy(tmp.attempt_record_key_digest, &encoded.data[36], 32u);
    (void)memcpy(tmp.attempt_creation_value_digest, &encoded.data[68], 32u);
    if (!attempt_id_index_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- CANCEL_STATE helpers (D1-B3f) --- */

static int cancel_owner_kind_is_known(uint16_t owner_kind)
{
    return owner_kind == NINLIL_MODEL_DOMAIN_CANCEL_OWNER_TRANSACTION
        || owner_kind == NINLIL_MODEL_DOMAIN_CANCEL_OWNER_DELIVERY;
}

static int cancel_state_is_known(uint32_t cancel_state)
{
    return cancel_state == NINLIL_MODEL_DOMAIN_CANCEL_STATE_NONE
        || cancel_state
            == NINLIL_MODEL_DOMAIN_CANCEL_STATE_PENDING_REMOTE_FENCE
        || cancel_state
            == NINLIL_MODEL_DOMAIN_CANCEL_STATE_FENCED_BEFORE_DISPATCH
        || cancel_state
            == NINLIL_MODEL_DOMAIN_CANCEL_STATE_TOO_LATE_EFFECT_POSSIBLE;
}

static int cancel_gate_is_known(uint32_t gate)
{
    return gate == NINLIL_MODEL_DOMAIN_CANCEL_GATE_NEVER_INVOKED
        || gate == NINLIL_MODEL_DOMAIN_CANCEL_GATE_WOULD_BLOCK_RETRYABLE
        || gate == NINLIL_MODEL_DOMAIN_CANCEL_GATE_INVOKED_CLOSED;
}

/* Timeout: (0,0) or (epoch non-zero, at_ms non-zero) only. */
static int cancel_timeout_pair_ok(
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

/*
 * Exact public-result bijection (docs17 §8.4). ALREADY_TERMINAL(4) never
 * stored — no matrix row maps to it.
 */
static int cancel_bijection_ok(
    uint32_t cancel_state,
    uint32_t cancel_kind,
    uint32_t reason,
    uint32_t effect_certainty)
{
    if (cancel_state == NINLIL_MODEL_DOMAIN_CANCEL_STATE_NONE) {
        return cancel_kind == NINLIL_MODEL_DOMAIN_CANCEL_KIND_NONE
            && reason == 0u
            && effect_certainty == NINLIL_EFFECT_CERTAINTY_NONE;
    }
    if (cancel_state
        == NINLIL_MODEL_DOMAIN_CANCEL_STATE_PENDING_REMOTE_FENCE) {
        return cancel_kind
                == NINLIL_MODEL_DOMAIN_CANCEL_KIND_PENDING_REMOTE_FENCE
            && reason == NINLIL_REASON_CANCEL_PENDING_REMOTE_FENCE
            && effect_certainty == NINLIL_EFFECT_CERTAINTY_NONE;
    }
    if (cancel_state
        == NINLIL_MODEL_DOMAIN_CANCEL_STATE_FENCED_BEFORE_DISPATCH) {
        return cancel_kind
                == NINLIL_MODEL_DOMAIN_CANCEL_KIND_FENCED_BEFORE_DISPATCH
            && reason == NINLIL_REASON_CANCEL_FENCED_BEFORE_DISPATCH
            && effect_certainty == NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN;
    }
    if (cancel_state
        == NINLIL_MODEL_DOMAIN_CANCEL_STATE_TOO_LATE_EFFECT_POSSIBLE) {
        return cancel_kind
                == NINLIL_MODEL_DOMAIN_CANCEL_KIND_TOO_LATE_EFFECT_POSSIBLE
            && reason == NINLIL_REASON_CANCEL_AFTER_EFFECT_POSSIBLE
            && effect_certainty == NINLIL_EFFECT_CERTAINTY_POSSIBLE;
    }
    return 0;
}

static int cancel_owner_raw_is_valid(
    uint16_t owner_kind,
    uint16_t len,
    const uint8_t *raw,
    const uint8_t transaction_id[NINLIL_MODEL_DOMAIN_ID_BYTES])
{
    if (raw == NULL || transaction_id == NULL) {
        return 0;
    }
    if (owner_kind == NINLIL_MODEL_DOMAIN_CANCEL_OWNER_TRANSACTION) {
        return len == NINLIL_MODEL_DOMAIN_CANCEL_OWNER_KEY_TX_BYTES
            && !id_is_zero(raw)
            && memcmp(raw, transaction_id, 16u) == 0;
    }
    if (owner_kind == NINLIL_MODEL_DOMAIN_CANCEL_OWNER_DELIVERY) {
        if (len != NINLIL_MODEL_DOMAIN_CANCEL_OWNER_KEY_DELIVERY_BYTES) {
            return 0;
        }
        if (!reservation_owner_raw_is_valid(
                NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_DELIVERY, len, raw)) {
            return 0;
        }
        return memcmp(raw + 32, transaction_id, 16u) == 0;
    }
    return 0;
}

static int cancel_primary_key_digest_ok(
    uint16_t owner_kind,
    uint16_t owner_key_raw_length,
    const uint8_t *owner_key_raw,
    const uint8_t transaction_id[NINLIL_MODEL_DOMAIN_ID_BYTES],
    const uint8_t actual[NINLIL_MODEL_DOMAIN_DIGEST_BYTES])
{
    uint8_t raw16[2u + NINLIL_MODEL_DOMAIN_RAW16_CANCEL_OWNER_KEY_MAX];
    ninlil_bytes_view_t components;
    uint32_t raw16_len = 0u;

    if (actual == NULL || owner_key_raw == NULL || transaction_id == NULL) {
        return 0;
    }
    if (owner_kind == NINLIL_MODEL_DOMAIN_CANCEL_OWNER_TRANSACTION) {
        if (owner_key_raw_length != 16u) {
            return 0;
        }
        return digest_eq_complete_key(
            actual,
            NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
            NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR,
            NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
            transaction_id,
            16u);
    }
    if (owner_kind == NINLIL_MODEL_DOMAIN_CANCEL_OWNER_DELIVERY) {
        if (!encode_raw16_into(
                owner_key_raw_length, owner_key_raw, raw16, sizeof(raw16),
                &raw16_len)) {
            return 0;
        }
        components.data = raw16;
        components.length = raw16_len;
        return digest_eq_composite_key(
            actual, NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY, components);
    }
    return 0;
}

/*
 * Closed snapshot matrix (docs17 §8.4). Seven legal shapes only.
 * D1 does not prove transition history: TX PENDING + CLOSED + timeout zero
 * is a valid pre-send crash/denial/post-fire snapshot.
 */
static int cancel_matrix_ok(const ninlil_model_domain_body_cancel_state_t *body)
{
    int attempt_zero;
    int digest_zero;
    int timeout_cleared;
    int gate_never;
    int gate_retry;
    int gate_closed;
    uint16_t owner;
    uint32_t state;
    uint32_t gate;

    if (body == NULL) {
        return 0;
    }
    attempt_zero = id_is_zero(body->cancel_attempt_id);
    digest_zero = digest_is_zero(body->message_semantic_digest);
    /* Global: both zero or both non-zero. */
    if (attempt_zero != digest_zero) {
        return 0;
    }
    if (!cancel_timeout_pair_ok(
            body->timeout_clock_epoch, body->timeout_at_ms)) {
        return 0;
    }
    if (!cancel_bijection_ok(
            body->cancel_state, body->cancel_kind, body->reason,
            body->effect_certainty)) {
        return 0;
    }
    if (!cancel_gate_is_known(body->cancel_send_gate_state)) {
        return 0;
    }
    timeout_cleared = id_is_zero(body->timeout_clock_epoch)
        && body->timeout_at_ms == 0u;
    owner = body->cancel_owner_kind;
    state = body->cancel_state;
    gate = body->cancel_send_gate_state;
    gate_never = gate == NINLIL_MODEL_DOMAIN_CANCEL_GATE_NEVER_INVOKED;
    gate_retry =
        gate == NINLIL_MODEL_DOMAIN_CANCEL_GATE_WOULD_BLOCK_RETRYABLE;
    gate_closed = gate == NINLIL_MODEL_DOMAIN_CANCEL_GATE_INVOKED_CLOSED;

    /* Shape 1: TX or DLV NONE — zero pair, NEVER, timeout0. */
    if (state == NINLIL_MODEL_DOMAIN_CANCEL_STATE_NONE) {
        return attempt_zero && gate_never && timeout_cleared;
    }

    if (owner == NINLIL_MODEL_DOMAIN_CANCEL_OWNER_TRANSACTION) {
        /* Shape 2: TX PENDING — NZ pair; NEVER/RETRYABLE => t0; CLOSED => t0|active. */
        if (state
            == NINLIL_MODEL_DOMAIN_CANCEL_STATE_PENDING_REMOTE_FENCE) {
            if (attempt_zero) {
                return 0;
            }
            if (gate_never || gate_retry) {
                return timeout_cleared;
            }
            if (gate_closed) {
                return 1; /* timeout already exact 2-form */
            }
            return 0;
        }
        /* Shapes 3/4: TX FENCED local (zero/NEVER/t0) or remote (NZ/CLOSED/t0). */
        if (state
            == NINLIL_MODEL_DOMAIN_CANCEL_STATE_FENCED_BEFORE_DISPATCH) {
            if (attempt_zero) {
                return gate_never && timeout_cleared;
            }
            return gate_closed && timeout_cleared;
        }
        /* Shape 6: TX TOO_LATE — NZ pair, CLOSED, timeout0. */
        if (state
            == NINLIL_MODEL_DOMAIN_CANCEL_STATE_TOO_LATE_EFFECT_POSSIBLE) {
            return !attempt_zero && gate_closed && timeout_cleared;
        }
        return 0;
    }

    if (owner == NINLIL_MODEL_DOMAIN_CANCEL_OWNER_DELIVERY) {
        /* DLV PENDING illegal; DLV gate always NEVER. */
        if (state
            == NINLIL_MODEL_DOMAIN_CANCEL_STATE_PENDING_REMOTE_FENCE) {
            return 0;
        }
        if (!gate_never) {
            return 0;
        }
        /* Shape 5: DLV FENCED — NZ pair, NEVER, timeout0. */
        if (state
            == NINLIL_MODEL_DOMAIN_CANCEL_STATE_FENCED_BEFORE_DISPATCH) {
            return !attempt_zero && timeout_cleared;
        }
        /* Shape 7: DLV TOO_LATE — NZ pair, NEVER, timeout0. */
        if (state
            == NINLIL_MODEL_DOMAIN_CANCEL_STATE_TOO_LATE_EFFECT_POSSIBLE) {
            return !attempt_zero && timeout_cleared;
        }
        return 0;
    }
    return 0;
}

static int cancel_fields_ok(const ninlil_model_domain_body_cancel_state_t *body)
{
    if (body == NULL
        || id_is_zero(body->transaction_id)
        || digest_is_zero(body->primary_key_digest)
        || body->reserved != 0u
        || !cancel_owner_kind_is_known(body->cancel_owner_kind)
        || !cancel_state_is_known(body->cancel_state)
        || !cancel_owner_raw_is_valid(
            body->cancel_owner_kind, body->owner_key_raw_length,
            body->owner_key_raw, body->transaction_id)
        || !cancel_primary_key_digest_ok(
            body->cancel_owner_kind, body->owner_key_raw_length,
            body->owner_key_raw, body->transaction_id,
            body->primary_key_digest)) {
        return 0;
    }
    return cancel_matrix_ok(body);
}

/* --- CANCEL_STATE (0x33) --- */

uint32_t ninlil_model_domain_body_cancel_state_encoded_length(
    const ninlil_model_domain_body_cancel_state_t *body)
{
    uint32_t n;
    if (body == NULL || !cancel_fields_ok(body)) {
        return 0u;
    }
    /* fixed 146 + owner_key_raw contents (TX16 => 162, DLV80 => 226). */
    n = NINLIL_MODEL_DOMAIN_BODY_CANCEL_STATE_FIXED
        + (uint32_t)body->owner_key_raw_length;
    if (n > NINLIL_MODEL_DOMAIN_BODY_CANCEL_STATE_MAX) {
        return 0u;
    }
    return n;
}

ninlil_status_t ninlil_model_domain_encode_body_cancel_state(
    const ninlil_model_domain_body_cancel_state_t *body,
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
    required = ninlil_model_domain_body_cancel_state_encoded_length(body);
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || required == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    ninlil_model_domain_encode_u16_be(&out_bytes[0], body->cancel_owner_kind);
    ninlil_model_domain_encode_u16_be(&out_bytes[2], body->reserved);
    o = 4u;
    o += encode_raw16(
        &out_bytes[o], body->owner_key_raw_length, body->owner_key_raw);
    (void)memcpy(&out_bytes[o], body->primary_key_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->transaction_id, 16u);
    o += 16u;
    (void)memcpy(&out_bytes[o], body->cancel_attempt_id, 16u);
    o += 16u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->cancel_state);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->cancel_kind);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->reason);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->effect_certainty);
    o += 4u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->cancel_send_gate_state);
    o += 4u;
    (void)memcpy(&out_bytes[o], body->message_semantic_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->timeout_clock_epoch, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->timeout_at_ms);
    o += 8u;
    *out_length = o;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_cancel_state(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_cancel_state_t *out_body)
{
    ninlil_model_domain_body_cancel_state_t tmp;
    uint32_t o = 0u;
    uint32_t c = 0u;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length < 4u + 2u
        || encoded.length > NINLIL_MODEL_DOMAIN_BODY_CANCEL_STATE_MAX) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.cancel_owner_kind =
        ninlil_model_domain_decode_u16_be(&encoded.data[0]);
    tmp.reserved = ninlil_model_domain_decode_u16_be(&encoded.data[2]);
    o = 4u;
    if (!decode_raw16_view(
            encoded.data + o, encoded.length - o,
            (uint16_t)NINLIL_MODEL_DOMAIN_RAW16_CANCEL_OWNER_KEY_MAX,
            &tmp.owner_key_raw_length, &tmp.owner_key_raw, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += c;
    /* After RAW16: 32+16+16+4+4+4+4+4+32+16+8 = 140 */
    if (encoded.length - o < 140u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(tmp.primary_key_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.transaction_id, &encoded.data[o], 16u);
    o += 16u;
    (void)memcpy(tmp.cancel_attempt_id, &encoded.data[o], 16u);
    o += 16u;
    tmp.cancel_state = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.cancel_kind = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.reason = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.effect_certainty =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.cancel_send_gate_state =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    (void)memcpy(tmp.message_semantic_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.timeout_clock_epoch, &encoded.data[o], 16u);
    o += 16u;
    tmp.timeout_at_ms = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    if (o != encoded.length || !cancel_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- EVIDENCE_CELL helpers (D1-B3g) --- */

static int evidence_owner_kind_is_known(uint16_t owner_kind)
{
    return owner_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_TRANSACTION
        || owner_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_DELIVERY;
}

static int evidence_cell_kind_is_known(uint16_t cell_kind)
{
    return cell_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_KIND_SUMMARY
        || cell_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_KIND_RAW;
}

static int evidence_cell_state_is_known(uint16_t cell_state)
{
    return cell_state == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_STATE_UNUSED
        || cell_state
            == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_STATE_MATERIALIZED;
}

static int evidence_material_stage_is_known(uint32_t stage)
{
    return stage >= NINLIL_EVIDENCE_RECEIVED
        && stage <= NINLIL_EVIDENCE_VERIFIED;
}

static int evidence_trust_is_known(uint32_t trust)
{
    return trust == NINLIL_CLOCK_TRUSTED || trust == NINLIL_CLOCK_UNCERTAIN;
}

static int bytes_are_zero(const uint8_t *p, size_t n)
{
    size_t i;
    if (p == NULL) {
        return n == 0u;
    }
    for (i = 0u; i < n; ++i) {
        if (p[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

/*
 * Field-wise zero for inactive EVIDENCE issuer/service. Do not memcmp the
 * whole object: local_identity has padding before u64 epochs (wire PARTY is
 * exact 100; object representation may be larger), and service may gain
 * alignment padding. Only wire-present semantic fields are required zero.
 */
static int text_id_fields_are_zero(const ninlil_model_domain_text_id_t *text)
{
    size_t i;
    if (text == NULL || text->length != 0u) {
        return 0;
    }
    for (i = 0u; i < sizeof(text->bytes); ++i) {
        if (text->bytes[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int party_is_all_zero(const ninlil_model_domain_party_t *party)
{
    if (party == NULL) {
        return 0;
    }
    return id_is_zero(party->runtime_id)
        && id_is_zero(party->application_instance_id)
        && party->local_identity.flags == 0u
        && id_is_zero(party->local_identity.device)
        && id_is_zero(party->local_identity.installation)
        && id_is_zero(party->local_identity.site)
        && party->local_identity.binding_epoch == 0u
        && party->local_identity.membership_epoch == 0u;
}

static int service_is_all_zero(
    const ninlil_model_domain_service_identity_t *service)
{
    if (service == NULL) {
        return 0;
    }
    return text_id_fields_are_zero(&service->namespace_id)
        && text_id_fields_are_zero(&service->service_id)
        && text_id_fields_are_zero(&service->schema_id)
        && service->descriptor_revision == 0u
        && digest_is_zero(service->descriptor_digest)
        && service->schema_major == 0u && service->schema_minor == 0u
        && service->family == 0u;
}

static int evidence_owner_raw_is_valid(
    uint16_t owner_kind, uint16_t len, const uint8_t *raw)
{
    if (raw == NULL && len != 0u) {
        return 0;
    }
    if (owner_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_TRANSACTION) {
        return len == NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_KEY_TX_BYTES
            && raw != NULL && !id_is_zero(raw);
    }
    if (owner_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_DELIVERY) {
        return reservation_owner_raw_is_valid(
            NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_DELIVERY, len, raw);
    }
    return 0;
}

static int evidence_primary_key_digest_ok(
    uint16_t owner_kind,
    uint16_t owner_key_raw_length,
    const uint8_t *owner_key_raw,
    const uint8_t actual[NINLIL_MODEL_DOMAIN_DIGEST_BYTES])
{
    uint8_t raw16[2u + NINLIL_MODEL_DOMAIN_RAW16_EVIDENCE_OWNER_KEY_MAX];
    ninlil_bytes_view_t components;
    uint32_t raw16_len = 0u;

    if (actual == NULL || owner_key_raw == NULL) {
        return 0;
    }
    if (owner_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_TRANSACTION) {
        if (owner_key_raw_length != 16u) {
            return 0;
        }
        return digest_eq_complete_key(
            actual,
            NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
            NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR,
            NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
            owner_key_raw,
            16u);
    }
    if (owner_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_DELIVERY) {
        if (!encode_raw16_into(
                owner_key_raw_length, owner_key_raw, raw16, sizeof(raw16),
                &raw16_len)) {
            return 0;
        }
        components.data = raw16;
        components.length = raw16_len;
        return digest_eq_composite_key(
            actual, NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY, components);
    }
    return 0;
}

static int evidence_matrix_shape_ok(
    const ninlil_model_domain_body_evidence_cell_t *body)
{
    if (body == NULL) {
        return 0;
    }
    /* Shape 1: SUMMARY MATERIALIZED slot 0. SUMMARY+UNUSED illegal. */
    if (body->cell_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_KIND_SUMMARY) {
        return body->cell_state
                == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_STATE_MATERIALIZED
            && body->slot_index == 0u;
    }
    /* Shapes 2/3: RAW UNUSED/MATERIALIZED slot 1..8. RAW+slot0 illegal. */
    if (body->cell_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_KIND_RAW) {
        if (body->slot_index < 1u || body->slot_index > 8u) {
            return 0;
        }
        return body->cell_state
                == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_STATE_UNUSED
            || body->cell_state
                == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_STATE_MATERIALIZED;
    }
    return 0;
}

static int evidence_is_summary_empty(
    const ninlil_model_domain_body_evidence_cell_t *body)
{
    return body->cell_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_KIND_SUMMARY
        && body->cell_state
            == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_STATE_MATERIALIZED
        && body->valid_material_count == 0u;
}

static int evidence_is_raw_unused(
    const ninlil_model_domain_body_evidence_cell_t *body)
{
    return body->cell_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_KIND_RAW
        && body->cell_state
            == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_STATE_UNUSED;
}

static int evidence_is_summary_material(
    const ninlil_model_domain_body_evidence_cell_t *body)
{
    return body->cell_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_KIND_SUMMARY
        && body->cell_state
            == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_STATE_MATERIALIZED
        && body->valid_material_count >= 1u;
}

static int evidence_is_raw_materialized(
    const ninlil_model_domain_body_evidence_cell_t *body)
{
    return body->cell_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_KIND_RAW
        && body->cell_state
            == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_STATE_MATERIALIZED;
}

static int evidence_is_material_active(
    const ninlil_model_domain_body_evidence_cell_t *body)
{
    return evidence_is_summary_material(body)
        || evidence_is_raw_materialized(body);
}

static int evidence_is_inactive(
    const ninlil_model_domain_body_evidence_cell_t *body)
{
    return evidence_is_summary_empty(body) || evidence_is_raw_unused(body);
}

static int evidence_digest_matches(
    const ninlil_model_domain_body_evidence_cell_t *body)
{
    ninlil_model_domain_digest_t dig;
    const uint8_t *data;

    if (body->evidence_length > NINLIL_MODEL_DOMAIN_EVIDENCE_BYTES_MAX) {
        return 0;
    }
    if (!bytes_are_zero(
            body->evidence_bytes + body->evidence_length,
            (size_t)(NINLIL_MODEL_DOMAIN_EVIDENCE_BYTES_MAX
                - body->evidence_length))) {
        return 0;
    }
    /* domain_sha256 requires data==NULL when length==0. */
    data = body->evidence_length == 0u ? NULL : body->evidence_bytes;
    if (ninlil_model_domain_sha256(data, body->evidence_length, &dig)
        != NINLIL_OK) {
        return 0;
    }
    return memcmp(body->evidence_digest, dig.bytes, 32u) == 0;
}

static int evidence_material_tuple_ok(
    const ninlil_model_domain_body_evidence_cell_t *body,
    int is_summary)
{
    if (body->disposition != 0u || body->effect_certainty != 0u) {
        return 0;
    }
    if (body->late_material != 0u && body->late_material != 1u) {
        return 0;
    }
    if (!ninlil_model_domain_party_is_valid(&body->issuer)) {
        return 0;
    }
    if (!ninlil_model_domain_service_identity_is_valid(&body->service)) {
        return 0;
    }
    /* family already restricted to EventFact/DesiredState by is_valid. */
    if (body->service.family == NINLIL_FAMILY_EVENT_FACT) {
        if (body->generation != 0u) {
            return 0;
        }
    } else if (body->service.family == NINLIL_FAMILY_DESIRED_STATE) {
        if (body->generation == 0u) {
            return 0;
        }
    } else {
        return 0;
    }
    if (digest_is_zero(body->content_digest)
        || body->durable_ingress_sequence == 0u
        || id_is_zero(body->evidence_clock_epoch)
        || !evidence_trust_is_known(body->evidence_trust)) {
        return 0;
    }
    /* evidence_at_ms == 0 is valid. */
    if (body->evidence_length > NINLIL_MODEL_DOMAIN_EVIDENCE_BYTES_MAX
        || !evidence_digest_matches(body)) {
        return 0;
    }
    if (is_summary) {
        if (!evidence_material_stage_is_known(body->highest_receipt_stage)
            || body->highest_receipt_stage != body->latest_evidence_stage
            || body->highest_receipt_stage != body->material_receipt_stage) {
            return 0;
        }
        /* late_material == (late_evidence_count > 0) exact 0/1. */
        if (body->late_material
            != (body->late_evidence_count > 0u ? 1u : 0u)) {
            return 0;
        }
        if (body->raw_overflow_count > body->valid_material_count
            || body->late_evidence_count > body->valid_material_count) {
            return 0;
        }
        if (body->exact_duplicate_count > 0u
            && body->valid_material_count < 1u) {
            return 0;
        }
        if (body->counter_saturated != 0u
            && body->counter_saturated != 1u) {
            return 0;
        }
        if (body->counter_saturated == 0u) {
            if (body->valid_material_count == UINT64_MAX
                || body->exact_duplicate_count == UINT64_MAX
                || body->raw_overflow_count == UINT64_MAX
                || body->late_evidence_count == UINT64_MAX) {
                return 0;
            }
        } else {
            if (body->valid_material_count != UINT64_MAX
                && body->exact_duplicate_count != UINT64_MAX
                && body->raw_overflow_count != UINT64_MAX
                && body->late_evidence_count != UINT64_MAX) {
                return 0;
            }
        }
        return 1;
    }
    /* RAW MATERIALIZED: no SUMMARY aggregate counters; stage triple split. */
    if (body->highest_receipt_stage != 0u
        || body->latest_evidence_stage != 0u
        || !evidence_material_stage_is_known(body->material_receipt_stage)
        || body->valid_material_count != 0u
        || body->exact_duplicate_count != 0u
        || body->raw_overflow_count != 0u
        || body->late_evidence_count != 0u
        || body->counter_saturated != 0u) {
        return 0;
    }
    return 1;
}

static int evidence_empty_fields_ok(
    const ninlil_model_domain_body_evidence_cell_t *body)
{
    return body->highest_receipt_stage == 0u
        && body->latest_evidence_stage == 0u
        && body->material_receipt_stage == 0u
        && body->disposition == 0u && body->effect_certainty == 0u
        && body->late_material == 0u && party_is_all_zero(&body->issuer)
        && service_is_all_zero(&body->service)
        && digest_is_zero(body->content_digest) && body->generation == 0u
        && body->durable_ingress_sequence == 0u
        && id_is_zero(body->evidence_clock_epoch)
        && body->evidence_at_ms == 0u && body->evidence_trust == 0u
        && body->counter_saturated == 0u
        && digest_is_zero(body->evidence_digest)
        && body->evidence_length == 0u && body->reserved1 == 0u
        && bytes_are_zero(
            body->evidence_bytes, NINLIL_MODEL_DOMAIN_EVIDENCE_BYTES_MAX)
        && body->valid_material_count == 0u
        && body->exact_duplicate_count == 0u
        && body->raw_overflow_count == 0u
        && body->late_evidence_count == 0u;
}

static int evidence_fields_ok(
    const ninlil_model_domain_body_evidence_cell_t *body)
{
    if (body == NULL
        || !evidence_owner_kind_is_known(body->evidence_owner_kind)
        || !evidence_cell_kind_is_known(body->cell_kind)
        || !evidence_cell_state_is_known(body->cell_state)
        || body->reserved0 != 0u || body->reserved1 != 0u
        || digest_is_zero(body->primary_key_digest)
        || digest_is_zero(body->target_digest)
        || !evidence_owner_raw_is_valid(
            body->evidence_owner_kind, body->owner_key_raw_length,
            body->owner_key_raw)
        || !evidence_primary_key_digest_ok(
            body->evidence_owner_kind, body->owner_key_raw_length,
            body->owner_key_raw, body->primary_key_digest)
        || !evidence_matrix_shape_ok(body)) {
        return 0;
    }
    /* disposition/effect always 0 on every legal shape. */
    if (body->disposition != 0u || body->effect_certainty != 0u) {
        return 0;
    }
    if (evidence_is_inactive(body)) {
        return evidence_empty_fields_ok(body);
    }
    if (evidence_is_summary_material(body)) {
        return evidence_material_tuple_ok(body, 1);
    }
    if (evidence_is_raw_materialized(body)) {
        return evidence_material_tuple_ok(body, 0);
    }
    return 0;
}

/* --- EVIDENCE_CELL (0x32) --- */

uint32_t ninlil_model_domain_body_evidence_cell_encoded_length(
    const ninlil_model_domain_body_evidence_cell_t *body)
{
    uint32_t n;
    if (body == NULL || !evidence_fields_ok(body)) {
        return 0u;
    }
    /* fixed 718 + owner_key_raw contents (TX16 => 734, DLV80 => 798). */
    n = NINLIL_MODEL_DOMAIN_BODY_EVIDENCE_CELL_FIXED
        + (uint32_t)body->owner_key_raw_length;
    if (n > NINLIL_MODEL_DOMAIN_BODY_EVIDENCE_CELL_MAX) {
        return 0u;
    }
    return n;
}

ninlil_status_t ninlil_model_domain_encode_body_evidence_cell(
    const ninlil_model_domain_body_evidence_cell_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    uint32_t required;
    size_t n = 0u;
    const void *ptrs[4];
    size_t lens[4];
    uint32_t o;
    uint32_t svc_len;
    uint8_t slot[NINLIL_MODEL_DOMAIN_BODY_EVIDENCE_SERVICE_SLOT_BYTES];

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
    required = ninlil_model_domain_body_evidence_cell_encoded_length(body);
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || required == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }

    (void)memset(slot, 0, sizeof(slot));
    if (evidence_is_material_active(body)) {
        svc_len = encode_service_identity(slot, &body->service);
        if (svc_len == 0u
            || svc_len > NINLIL_MODEL_DOMAIN_BODY_EVIDENCE_SERVICE_SLOT_BYTES) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
    }

    ninlil_model_domain_encode_u16_be(
        &out_bytes[0], body->evidence_owner_kind);
    ninlil_model_domain_encode_u16_be(&out_bytes[2], body->cell_kind);
    o = 4u;
    o += encode_raw16(
        &out_bytes[o], body->owner_key_raw_length, body->owner_key_raw);
    (void)memcpy(&out_bytes[o], body->primary_key_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->target_digest, 32u);
    o += 32u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->slot_index);
    o += 4u;
    ninlil_model_domain_encode_u16_be(&out_bytes[o], body->cell_state);
    o += 2u;
    ninlil_model_domain_encode_u16_be(&out_bytes[o], body->reserved0);
    o += 2u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->highest_receipt_stage);
    o += 4u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->latest_evidence_stage);
    o += 4u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->material_receipt_stage);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->disposition);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->effect_certainty);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->late_material);
    o += 4u;
    encode_party(&out_bytes[o], &body->issuer);
    o += NINLIL_MODEL_DOMAIN_PARTY_BYTES;
    (void)memcpy(
        &out_bytes[o], slot,
        NINLIL_MODEL_DOMAIN_BODY_EVIDENCE_SERVICE_SLOT_BYTES);
    o += NINLIL_MODEL_DOMAIN_BODY_EVIDENCE_SERVICE_SLOT_BYTES;
    (void)memcpy(&out_bytes[o], body->content_digest, 32u);
    o += 32u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->generation);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->durable_ingress_sequence);
    o += 8u;
    (void)memcpy(&out_bytes[o], body->evidence_clock_epoch, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->evidence_at_ms);
    o += 8u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->evidence_trust);
    o += 4u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->counter_saturated);
    o += 4u;
    (void)memcpy(&out_bytes[o], body->evidence_digest, 32u);
    o += 32u;
    ninlil_model_domain_encode_u16_be(&out_bytes[o], body->evidence_length);
    o += 2u;
    ninlil_model_domain_encode_u16_be(&out_bytes[o], body->reserved1);
    o += 2u;
    (void)memcpy(
        &out_bytes[o], body->evidence_bytes,
        NINLIL_MODEL_DOMAIN_EVIDENCE_BYTES_MAX);
    o += NINLIL_MODEL_DOMAIN_EVIDENCE_BYTES_MAX;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->valid_material_count);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->exact_duplicate_count);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->raw_overflow_count);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->late_evidence_count);
    o += 8u;
    *out_length = o;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_evidence_cell(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_evidence_cell_t *out_body)
{
    ninlil_model_domain_body_evidence_cell_t tmp;
    uint32_t o = 0u;
    uint32_t c = 0u;
    uint32_t svc_consumed = 0u;
    const uint8_t *slot;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length < 4u + 2u
        || encoded.length > NINLIL_MODEL_DOMAIN_BODY_EVIDENCE_CELL_MAX) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.evidence_owner_kind =
        ninlil_model_domain_decode_u16_be(&encoded.data[0]);
    tmp.cell_kind = ninlil_model_domain_decode_u16_be(&encoded.data[2]);
    o = 4u;
    if (!decode_raw16_view(
            encoded.data + o, encoded.length - o,
            (uint16_t)NINLIL_MODEL_DOMAIN_RAW16_EVIDENCE_OWNER_KEY_MAX,
            &tmp.owner_key_raw_length, &tmp.owner_key_raw, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += c;
    /*
     * After RAW16: 32+32+4+2+2 + 4*6 + 100 + 240 + 32 + 8+8 + 16 + 8 + 4+4
     * + 32 + 2+2 + 128 + 8*4 = 712 (= FIXED 718 - kind/kind/len 6)
     */
    if (encoded.length - o < 712u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(tmp.primary_key_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.target_digest, &encoded.data[o], 32u);
    o += 32u;
    tmp.slot_index = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.cell_state = ninlil_model_domain_decode_u16_be(&encoded.data[o]);
    o += 2u;
    tmp.reserved0 = ninlil_model_domain_decode_u16_be(&encoded.data[o]);
    o += 2u;
    tmp.highest_receipt_stage =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.latest_evidence_stage =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.material_receipt_stage =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.disposition = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.effect_certainty =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.late_material = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    decode_party(&encoded.data[o], &tmp.issuer);
    o += NINLIL_MODEL_DOMAIN_PARTY_BYTES;
    slot = &encoded.data[o];
    o += NINLIL_MODEL_DOMAIN_BODY_EVIDENCE_SERVICE_SLOT_BYTES;
    (void)memcpy(tmp.content_digest, &encoded.data[o], 32u);
    o += 32u;
    tmp.generation = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.durable_ingress_sequence =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    (void)memcpy(tmp.evidence_clock_epoch, &encoded.data[o], 16u);
    o += 16u;
    tmp.evidence_at_ms = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.evidence_trust = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.counter_saturated =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    (void)memcpy(tmp.evidence_digest, &encoded.data[o], 32u);
    o += 32u;
    tmp.evidence_length =
        ninlil_model_domain_decode_u16_be(&encoded.data[o]);
    o += 2u;
    tmp.reserved1 = ninlil_model_domain_decode_u16_be(&encoded.data[o]);
    o += 2u;
    (void)memcpy(
        tmp.evidence_bytes, &encoded.data[o],
        NINLIL_MODEL_DOMAIN_EVIDENCE_BYTES_MAX);
    o += NINLIL_MODEL_DOMAIN_EVIDENCE_BYTES_MAX;
    tmp.valid_material_count =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.exact_duplicate_count =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.raw_overflow_count =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.late_evidence_count =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    if (o != encoded.length) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    /*
     * Decode service_slot before fields_ok so value-owned service is filled.
     * Inactive: exact 240 zero (no SERVICE_IDENTITY shape check).
     * Active: canonical SERVICE_IDENTITY prefix + zero pad.
     */
    if (evidence_is_inactive(&tmp)
        || (tmp.cell_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_KIND_SUMMARY
            && tmp.cell_state
                == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_STATE_MATERIALIZED
            && tmp.valid_material_count == 0u)
        || (tmp.cell_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_KIND_RAW
            && tmp.cell_state
                == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_STATE_UNUSED)) {
        if (!bytes_are_zero(
                slot, NINLIL_MODEL_DOMAIN_BODY_EVIDENCE_SERVICE_SLOT_BYTES)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        (void)memset(&tmp.service, 0, sizeof(tmp.service));
    } else if (
        (tmp.cell_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_KIND_SUMMARY
            && tmp.cell_state
                == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_STATE_MATERIALIZED
            && tmp.valid_material_count >= 1u)
        || (tmp.cell_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_KIND_RAW
            && tmp.cell_state
                == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_STATE_MATERIALIZED)) {
        if (!decode_service_identity(
                slot, NINLIL_MODEL_DOMAIN_BODY_EVIDENCE_SERVICE_SLOT_BYTES,
                &tmp.service, &svc_consumed)
            || svc_consumed
                > NINLIL_MODEL_DOMAIN_BODY_EVIDENCE_SERVICE_SLOT_BYTES
            || !bytes_are_zero(
                slot + svc_consumed,
                (size_t)(NINLIL_MODEL_DOMAIN_BODY_EVIDENCE_SERVICE_SLOT_BYTES
                    - svc_consumed))) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
    } else {
        /* Matrix-illegal kind/state — still reject via fields_ok. */
        if (!bytes_are_zero(
                slot, NINLIL_MODEL_DOMAIN_BODY_EVIDENCE_SERVICE_SLOT_BYTES)) {
            /* leave service zero for inactive-like pad check failures */
        }
        if (!decode_service_identity(
                slot, NINLIL_MODEL_DOMAIN_BODY_EVIDENCE_SERVICE_SLOT_BYTES,
                &tmp.service, &svc_consumed)) {
            (void)memset(&tmp.service, 0, sizeof(tmp.service));
        }
    }

    if (!evidence_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- DELIVERY (0x40) helpers (D1-B3h) --- */

static int delivery_creation_kind_is_known(uint16_t creation_kind)
{
    return creation_kind
            == NINLIL_MODEL_DOMAIN_DELIVERY_CREATION_APPLICATION_FIRST
        || creation_kind
            == NINLIL_MODEL_DOMAIN_DELIVERY_CREATION_CANCEL_FIRST;
}

/*
 * delivery_key_raw contents exact 80 must bijection body source / txn /
 * local_target (docs17 §8.5). Field-wise compares only — no padding.
 */
static int delivery_key_bijection_ok(
    const ninlil_model_domain_body_delivery_t *body)
{
    if (body == NULL || body->delivery_key_raw == NULL
        || body->delivery_key_raw_length
            != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES) {
        return 0;
    }
    if (!reservation_owner_raw_is_valid(
            NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_DELIVERY,
            body->delivery_key_raw_length,
            body->delivery_key_raw)) {
        return 0;
    }
    if (memcmp(body->delivery_key_raw, body->source.runtime_id, 16u) != 0
        || memcmp(
               body->delivery_key_raw + 16,
               body->source.application_instance_id,
               16u)
            != 0
        || memcmp(body->delivery_key_raw + 32, body->transaction_id, 16u)
            != 0
        || memcmp(
               body->delivery_key_raw + 48,
               body->local_target.target_runtime,
               16u)
            != 0
        || memcmp(
               body->delivery_key_raw + 64,
               body->local_target.target_application,
               16u)
            != 0) {
        return 0;
    }
    return 1;
}

static int delivery_result_cache_key_digest_ok(
    const ninlil_model_domain_body_delivery_t *body)
{
    uint8_t raw16_buf[2u + NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES];
    ninlil_bytes_view_t components;
    uint32_t raw16_len = 0u;

    if (body == NULL || body->delivery_key_raw == NULL) {
        return 0;
    }
    if (!encode_raw16_into(
            body->delivery_key_raw_length, body->delivery_key_raw, raw16_buf,
            sizeof(raw16_buf), &raw16_len)) {
        return 0;
    }
    components.data = raw16_buf;
    components.length = raw16_len;
    return digest_eq_composite_key(
        body->result_cache_key_digest,
        NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE,
        components);
}

static int delivery_reservation_key_digest_ok(
    const ninlil_model_domain_body_delivery_t *body)
{
    uint8_t comp[2u + 2u + NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES];
    ninlil_bytes_view_t components;

    if (body == NULL || body->delivery_key_raw == NULL
        || body->delivery_key_raw_length
            != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES) {
        return 0;
    }
    ninlil_model_domain_encode_u16_be(
        comp, NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_DELIVERY);
    ninlil_model_domain_encode_u16_be(
        &comp[2], body->delivery_key_raw_length);
    (void)memcpy(
        &comp[4], body->delivery_key_raw, body->delivery_key_raw_length);
    components.data = comp;
    components.length = 4u + (uint32_t)body->delivery_key_raw_length;
    return digest_eq_composite_key(
        body->reservation_key_digest,
        NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION,
        components);
}

static int delivery_fields_ok(const ninlil_model_domain_body_delivery_t *body)
{
    int is_event;
    int is_cancel_first;
    int payload_zero;

    if (body == NULL
        || !delivery_creation_kind_is_known(body->creation_kind)
        || body->reserved != 0u
        || body->scheduler_owner_sequence == 0u
        || id_is_zero(body->transaction_id)
        || digest_is_zero(body->content_digest)
        || !ninlil_model_domain_party_is_valid(&body->source)
        || !ninlil_model_domain_target_is_valid(&body->local_target)
        || !ninlil_model_domain_service_identity_is_valid(&body->service)
        || !family_is_m1a(body->service.family)
        || !evidence_stage_is_known(body->required_evidence)
        || body->required_evidence == NINLIL_EVIDENCE_NONE
        || !delivery_key_bijection_ok(body)
        || !delivery_result_cache_key_digest_ok(body)
        || !delivery_reservation_key_digest_ok(body)) {
        return 0;
    }

    is_cancel_first = body->creation_kind
        == NINLIL_MODEL_DOMAIN_DELIVERY_CREATION_CANCEL_FIRST;
    is_event = body->service.family == NINLIL_FAMILY_EVENT_FACT;
    if (is_cancel_first && is_event) {
        return 0;
    }

    if (is_event) {
        if (id_is_zero(body->event_id) || body->generation != 0u
            || !id_is_zero(body->deadline_clock_epoch)
            || body->absolute_effect_deadline_ms != NINLIL_NO_DEADLINE
            || body->evidence_grace_ms != 0u) {
            return 0;
        }
    } else {
        /* DesiredState: same-record level as ORDERED_INGRESS (no >0 force). */
        if (!id_is_zero(body->event_id) || body->generation == 0u
            || id_is_zero(body->deadline_clock_epoch)
            || body->absolute_effect_deadline_ms == NINLIL_NO_DEADLINE) {
            return 0;
        }
    }

    payload_zero = digest_is_zero(body->payload_blob_key_digest);
    if (is_cancel_first) {
        if (!payload_zero) {
            return 0;
        }
    } else if (payload_zero) {
        /* APPLICATION_FIRST: non-zero even for empty payload manifest. */
        return 0;
    }
    return 1;
}

/* --- DELIVERY (0x40) --- */

uint32_t ninlil_model_domain_body_delivery_encoded_length(
    const ninlil_model_domain_body_delivery_t *body)
{
    uint32_t svc;
    uint32_t n;

    if (body == NULL || !delivery_fields_ok(body)) {
        return 0u;
    }
    svc = ninlil_model_domain_service_identity_encoded_length(&body->service);
    if (svc == 0u) {
        return 0u;
    }
    if (!checked_add_u32(
            NINLIL_MODEL_DOMAIN_BODY_DELIVERY_FIXED_WITH_RAW80, svc, &n)) {
        return 0u;
    }
    if (n < NINLIL_MODEL_DOMAIN_BODY_DELIVERY_MIN
        || n > NINLIL_MODEL_DOMAIN_BODY_DELIVERY_MAX_CANONICAL
        || n > NINLIL_MODEL_DOMAIN_BODY_DELIVERY_MAX) {
        return 0u;
    }
    return n;
}

ninlil_status_t ninlil_model_domain_encode_body_delivery(
    const ninlil_model_domain_body_delivery_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    uint32_t required;
    size_t n = 0u;
    const void *ptrs[4];
    size_t lens[4];
    uint32_t o;
    uint32_t svc_len;

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
        if (body->delivery_key_raw != NULL
            && body->delivery_key_raw_length != 0u) {
            ptrs[n] = body->delivery_key_raw;
            lens[n] = body->delivery_key_raw_length;
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
    required = ninlil_model_domain_body_delivery_encoded_length(body);
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
        &out_bytes[o], body->delivery_key_raw_length, body->delivery_key_raw);
    ninlil_model_domain_encode_u16_be(&out_bytes[o], body->creation_kind);
    o += 2u;
    ninlil_model_domain_encode_u16_be(&out_bytes[o], body->reserved);
    o += 2u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->scheduler_owner_sequence);
    o += 8u;
    (void)memcpy(&out_bytes[o], body->transaction_id, 16u);
    o += 16u;
    (void)memcpy(&out_bytes[o], body->event_id, 16u);
    o += 16u;
    encode_party(&out_bytes[o], &body->source);
    o += NINLIL_MODEL_DOMAIN_PARTY_BYTES;
    encode_target(&out_bytes[o], &body->local_target);
    o += NINLIL_MODEL_DOMAIN_TARGET_BYTES;
    svc_len = encode_service_identity(&out_bytes[o], &body->service);
    o += svc_len;
    (void)memcpy(&out_bytes[o], body->content_digest, 32u);
    o += 32u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->generation);
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
    (void)memcpy(&out_bytes[o], body->payload_blob_key_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->result_cache_key_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->reservation_key_digest, 32u);
    o += 32u;
    *out_length = o;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_delivery(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_delivery_t *out_body)
{
    ninlil_model_domain_body_delivery_t tmp;
    uint32_t o = 0u;
    uint32_t c = 0u;
    uint32_t svc_consumed = 0u;
    uint32_t rem;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length < NINLIL_MODEL_DOMAIN_BODY_DELIVERY_MIN
        || encoded.length > NINLIL_MODEL_DOMAIN_BODY_DELIVERY_MAX_CANONICAL
        || encoded.length > NINLIL_MODEL_DOMAIN_BODY_DELIVERY_MAX) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    /* RAW16 max contents 128 (body field bound); canonical exact 80 in fields_ok. */
    if (!decode_raw16_view(
            encoded.data + o, encoded.length - o, (uint16_t)128u,
            &tmp.delivery_key_raw_length, &tmp.delivery_key_raw, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += c;
    /*
     * After RAW16: creation/reserved 4 + sched 8 + txn/event 32 +
     * PARTY 100 + TARGET 100 = 244 fixed before SERVICE_IDENTITY.
     * After service: content..reservation = 32+8+16+8+8+4+32+32+32 = 172.
     */
    if (encoded.length < o || encoded.length - o < 244u + 54u + 172u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    tmp.creation_kind = ninlil_model_domain_decode_u16_be(&encoded.data[o]);
    o += 2u;
    tmp.reserved = ninlil_model_domain_decode_u16_be(&encoded.data[o]);
    o += 2u;
    tmp.scheduler_owner_sequence =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    (void)memcpy(tmp.transaction_id, &encoded.data[o], 16u);
    o += 16u;
    (void)memcpy(tmp.event_id, &encoded.data[o], 16u);
    o += 16u;
    decode_party(&encoded.data[o], &tmp.source);
    o += NINLIL_MODEL_DOMAIN_PARTY_BYTES;
    decode_target(&encoded.data[o], &tmp.local_target);
    o += NINLIL_MODEL_DOMAIN_TARGET_BYTES;
    rem = encoded.length - o;
    if (rem < 54u + 172u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (!decode_service_identity(
            &encoded.data[o], rem - 172u, &tmp.service, &svc_consumed)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += svc_consumed;
    if (encoded.length - o != 172u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(tmp.content_digest, &encoded.data[o], 32u);
    o += 32u;
    tmp.generation = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
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
    (void)memcpy(tmp.payload_blob_key_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.result_cache_key_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.reservation_key_digest, &encoded.data[o], 32u);
    o += 32u;
    if (o != encoded.length || !delivery_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}


/* --- RESULT_CACHE (0x41) --- */

static int result_cache_delivery_raw_ok(
    uint16_t raw_len, const uint8_t *raw, const uint8_t *transaction_id)
{
    size_t i;
    if (raw_len != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES
        || raw == NULL || transaction_id == NULL) {
        return 0;
    }
    for (i = 0u; i < 5u; ++i) {
        if (id_is_zero(raw + (i * 16u))) {
            return 0;
        }
    }
    return memcmp(raw + 32u, transaction_id, 16u) == 0;
}

static int result_cache_delivery_key_digest_ok(
    const ninlil_model_domain_body_result_cache_t *body)
{
    uint8_t raw16_buf[2u + NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES];
    ninlil_bytes_view_t components;
    uint32_t raw16_len = 0u;

    if (body == NULL || body->delivery_key_raw == NULL) {
        return 0;
    }
    if (!encode_raw16_into(
            body->delivery_key_raw_length, body->delivery_key_raw, raw16_buf,
            sizeof(raw16_buf), &raw16_len)) {
        return 0;
    }
    components.data = raw16_buf;
    components.length = raw16_len;
    return digest_eq_composite_key(
        body->delivery_key_digest, NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
        components);
}

static int result_cache_evidence_cell_key_digest_ok(
    const ninlil_model_domain_body_result_cache_t *body, int expect_zero)
{
    uint8_t comp[2u + 2u + 80u + 4u];
    ninlil_bytes_view_t components;
    uint32_t o = 0u;

    if (body == NULL) {
        return 0;
    }
    if (expect_zero) {
        return digest_is_zero(body->evidence_cell_key_digest);
    }
    if (body->delivery_key_raw == NULL
        || body->delivery_key_raw_length
            != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES
        || digest_is_zero(body->evidence_cell_key_digest)) {
        return 0;
    }
    ninlil_model_domain_encode_u16_be(
        &comp[o], NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_DELIVERY);
    o += 2u;
    ninlil_model_domain_encode_u16_be(
        &comp[o], body->delivery_key_raw_length);
    o += 2u;
    (void)memcpy(&comp[o], body->delivery_key_raw, 80u);
    o += 80u;
    ninlil_model_domain_encode_u32_be(&comp[o], 0u); /* slot 0 SUMMARY */
    o += 4u;
    components.data = comp;
    components.length = o;
    return digest_eq_composite_key(
        body->evidence_cell_key_digest,
        NINLIL_MODEL_DOMAIN_SUBTYPE_EVIDENCE_CELL, components);
}

static int result_timer_tuple_legal(
    const ninlil_model_domain_body_result_cache_t *body)
{
    if (body == NULL) {
        return 0;
    }
    if (id_is_zero(body->token_clock_epoch)
        || id_is_zero(body->delivery_started_clock_epoch)
        || memcmp(
               body->token_clock_epoch, body->delivery_started_clock_epoch,
               16u)
            != 0) {
        return 0;
    }
    if (body->completion_expires_at_ms == 0u
        || body->token_expires_at_ms == 0u
        || body->token_expires_at_ms != body->completion_expires_at_ms) {
        return 0;
    }
    /*
     * docs17 §8.5: completion_expires =
     * checked(delivery_started_at + application_completion_timeout_ms) with
     * timeout >= 1, so same-record requires completion_expires > started_at
     * (started_at may be 0; equality or less is corrupt).
     */
    if (body->completion_expires_at_ms <= body->delivery_started_at_ms) {
        return 0;
    }
    return 1;
}

static int result_timer_tuple_zero(
    const ninlil_model_domain_body_result_cache_t *body)
{
    return id_is_zero(body->token_clock_epoch)
        && body->token_expires_at_ms == 0u
        && id_is_zero(body->delivery_started_clock_epoch)
        && body->delivery_started_at_ms == 0u
        && body->completion_expires_at_ms == 0u;
}

static int result_completed_zero(
    const ninlil_model_domain_body_result_cache_t *body)
{
    return id_is_zero(body->completed_clock_epoch)
        && body->completed_at_ms == 0u;
}

static int result_completed_nz(
    const ninlil_model_domain_body_result_cache_t *body)
{
    return !id_is_zero(body->completed_clock_epoch)
        && body->completed_at_ms != 0u;
}

static int result_token_context_zero(
    const ninlil_model_domain_body_result_cache_t *body)
{
    return id_is_zero(body->token_context_id);
}

static int result_token_context_is_txn(
    const ninlil_model_domain_body_result_cache_t *body)
{
    return memcmp(body->token_context_id, body->transaction_id, 16u) == 0
        && !id_is_zero(body->token_context_id);
}

static int result_e_rec_reason_ok(uint32_t reason, uint32_t guidance)
{
    switch (reason) {
    case NINLIL_REASON_APPLICATION_FAILED:
    case NINLIL_REASON_CALLBACK_CONTRACT:
    case NINLIL_REASON_COUNTER_EXHAUSTED:
    case NINLIL_REASON_OUTCOME_UNKNOWN:
        return guidance == NINLIL_RETRY_OPERATOR_ACTION;
    case NINLIL_REASON_APPLICATION_COMPLETION_TIMEOUT:
        return guidance == NINLIL_RETRY_SAME_AFTER;
    default:
        return 0;
    }
}

/*
 * docs17 §8.5 E_REC reason × token_state reachability (state 6/7).
 * CALLBACK_CONTRACT may retain prior tombstone identity after unknown
 * reconcile / invalid KNOWN_RESULT (CONSUMED/EXPIRED/RECOVERY_TOMB), not only
 * direct invalid-callback RECOVERY_REQUIRED_TOMBSTONE.
 */
static int result_retained_tombstone(uint32_t token_state)
{
    return token_state == NINLIL_MODEL_DOMAIN_TOKEN_STATE_CONSUMED
        || token_state == NINLIL_MODEL_DOMAIN_TOKEN_STATE_EXPIRED
        || token_state
            == NINLIL_MODEL_DOMAIN_TOKEN_STATE_RECOVERY_REQUIRED_TOMBSTONE;
}

static int result_e_rec_token_pair_ok(
    uint32_t reason, uint32_t token_state, uint64_t n)
{
    switch (reason) {
    case NINLIL_REASON_APPLICATION_COMPLETION_TIMEOUT:
        return n >= 1u
            && token_state == NINLIL_MODEL_DOMAIN_TOKEN_STATE_EXPIRED;
    case NINLIL_REASON_APPLICATION_FAILED:
        return n >= 1u
            && token_state
                == NINLIL_MODEL_DOMAIN_TOKEN_STATE_RECOVERY_REQUIRED_TOMBSTONE;
    case NINLIL_REASON_CALLBACK_CONTRACT:
        /* Direct invalid complete → RECOVERY_TOMB; unknown reconcile keeps prior
         * retained tombstone (CONSUMED/EXPIRED/RECOVERY_TOMB). Same-record
         * cannot distinguish history, so all three retained forms are legal. */
        return n >= 1u && result_retained_tombstone(token_state);
    case NINLIL_REASON_OUTCOME_UNKNOWN:
        return n >= 1u
            && (token_state == NINLIL_MODEL_DOMAIN_TOKEN_STATE_EXPIRED
                || token_state
                    == NINLIL_MODEL_DOMAIN_TOKEN_STATE_RECOVERY_REQUIRED_TOMBSTONE);
    case NINLIL_REASON_COUNTER_EXHAUSTED:
        return n == UINT64_MAX && result_retained_tombstone(token_state);
    default:
        return 0;
    }
}

static int result_e_zero_ok(const ninlil_model_domain_body_result_cache_t *body)
{
    return body->application_result_kind == 0u
        && body->evidence_stage == NINLIL_EVIDENCE_NONE
        && body->disposition == NINLIL_DISPOSITION_NONE
        && body->reason == NINLIL_REASON_NONE
        && body->effect_certainty == NINLIL_EFFECT_CERTAINTY_NONE
        && body->retry_guidance == NINLIL_RETRY_NEVER
        && body->retry_delay_ms == 0u
        && result_completed_zero(body);
}

static int result_e_pos_ok(const ninlil_model_domain_body_result_cache_t *body)
{
    return body->application_result_kind == NINLIL_APP_RESULT_POSITIVE_EVIDENCE
        && body->evidence_stage != NINLIL_EVIDENCE_NONE
        && evidence_stage_is_known(body->evidence_stage)
        && body->disposition == NINLIL_DISPOSITION_NONE
        && body->reason == NINLIL_REASON_NONE
        && body->effect_certainty == NINLIL_EFFECT_CERTAINTY_NONE
        && body->retry_guidance == NINLIL_RETRY_NEVER
        && body->retry_delay_ms == 0u
        && result_completed_nz(body);
}

static int result_disp_reason_ok(
    uint32_t disposition, uint32_t reason, uint32_t effect_certainty)
{
    switch (disposition) {
    case NINLIL_DISPOSITION_RETRY_LATER:
        return reason == NINLIL_REASON_RECONCILE_RETRY_LATER;
    case NINLIL_DISPOSITION_INVALID_PAYLOAD:
    case NINLIL_DISPOSITION_UNSUPPORTED_SCHEMA:
    case NINLIL_DISPOSITION_STALE_NOT_APPLIED:
        return reason == NINLIL_REASON_APPLICATION_FAILED;
    case NINLIL_DISPOSITION_UNAUTHORIZED_SERVICE:
        return reason == NINLIL_REASON_TARGET_UNAUTHORIZED;
    case NINLIL_DISPOSITION_APPLICATION_BUSY:
        return reason == NINLIL_REASON_RECEIVER_UNAVAILABLE;
    case NINLIL_DISPOSITION_APPLY_FAILED:
        return reason == NINLIL_REASON_APPLICATION_FAILED;
    case NINLIL_DISPOSITION_VERIFY_FAILED:
        return reason == NINLIL_REASON_APPLICATION_FAILED;
    case NINLIL_DISPOSITION_CAPACITY_EXHAUSTED:
        return reason == NINLIL_REASON_CAPACITY_EXHAUSTED;
    case NINLIL_DISPOSITION_OUTCOME_UNKNOWN:
        return reason == NINLIL_REASON_OUTCOME_UNKNOWN
            && effect_certainty == NINLIL_EFFECT_CERTAINTY_POSSIBLE;
    default:
        return 0;
    }
}

static int result_e_disp_ok(const ninlil_model_domain_body_result_cache_t *body)
{
    return body->application_result_kind == NINLIL_APP_RESULT_DISPOSITION
        && body->evidence_stage == NINLIL_EVIDENCE_NONE
        && disposition_tuple_is_valid(
               body->disposition, body->effect_certainty, body->retry_guidance,
               body->retry_delay_ms)
        && result_disp_reason_ok(
               body->disposition, body->reason, body->effect_certainty)
        && result_completed_nz(body);
}

static int result_e_rec_ok(const ninlil_model_domain_body_result_cache_t *body)
{
    return body->application_result_kind == 0u
        && body->evidence_stage == NINLIL_EVIDENCE_NONE
        && body->disposition == NINLIL_DISPOSITION_NONE
        && body->effect_certainty == NINLIL_EFFECT_CERTAINTY_POSSIBLE
        && body->retry_delay_ms == 0u
        && result_e_rec_reason_ok(body->reason, body->retry_guidance)
        && result_completed_zero(body);
}

static int result_token_shape_ok(
    const ninlil_model_domain_body_result_cache_t *body)
{
    uint64_t n;

    if (body == NULL) {
        return 0;
    }
    n = body->delivery_count;
    if (body->callback_invocations != n || body->token_generation != n) {
        return 0;
    }
    switch (body->token_state) {
    case NINLIL_MODEL_DOMAIN_TOKEN_STATE_NONE:
        return n == 0u && result_token_context_zero(body)
            && body->token_generation == 0u && result_timer_tuple_zero(body);
    case NINLIL_MODEL_DOMAIN_TOKEN_STATE_ACTIVE:
        return n >= 1u && result_token_context_is_txn(body)
            && result_timer_tuple_legal(body);
    case NINLIL_MODEL_DOMAIN_TOKEN_STATE_CONSUMED:
    case NINLIL_MODEL_DOMAIN_TOKEN_STATE_EXPIRED:
    case NINLIL_MODEL_DOMAIN_TOKEN_STATE_RECOVERY_REQUIRED_TOMBSTONE:
        return n >= 1u && result_token_context_is_txn(body)
            && result_timer_tuple_legal(body);
    default:
        return 0;
    }
}

static int result_product_ok(
    const ninlil_model_domain_body_result_cache_t *body)
{
    uint64_t n;
    uint32_t st;
    uint32_t ts;
    uint32_t f;
    int a_app;
    int a_cancel;
    int tombstone;
    int e_zero;
    int e_pos;
    int e_disp;
    int e_rec;
    uint64_t g;
    uint64_t ri;
    int d_idle;
    int d_open;
    int d_wait;
    int d_held;

    if (body == NULL) {
        return 0;
    }
    n = body->delivery_count;
    st = body->delivery_state;
    ts = body->token_state;
    f = body->cancel_result_kind;
    g = body->reconcile_retry_generation;
    ri = body->reconcile_invocation_count;

    if (st == 3u) {
        return 0; /* DEFERRED_WAIT illegal on wire */
    }
    if (body->reply_count > 4u) {
        return 0;
    }
    if (!result_token_shape_ok(body)) {
        return 0;
    }

    a_app = body->application_seen == 1u && body->application_attempt_count >= 1u
        && result_cache_evidence_cell_key_digest_ok(body, 0);
    a_cancel = body->application_seen == 0u
        && body->application_attempt_count == 0u && n == 0u
        && result_cache_evidence_cell_key_digest_ok(body, 1);

    e_zero = result_e_zero_ok(body);
    e_pos = result_e_pos_ok(body);
    e_disp = result_e_disp_ok(body);
    e_rec = result_e_rec_ok(body);

    d_idle = (g == 0u && ri == 0u
        && id_is_zero(body->reconcile_not_before_clock_epoch)
        && body->reconcile_not_before_ms == 0u);
    d_open = (g >= 1u
        && (ri == UINT64_MAX || g <= ri + 1u)
        && id_is_zero(body->reconcile_not_before_clock_epoch)
        && body->reconcile_not_before_ms == 0u);
    d_wait = (g >= 1u
        && (ri == UINT64_MAX || g <= ri + 1u)
        && !id_is_zero(body->reconcile_not_before_clock_epoch)
        && body->reconcile_not_before_ms != 0u);
    d_held = (g >= 1u && ri >= 1u && ri >= g
        && id_is_zero(body->reconcile_not_before_clock_epoch)
        && body->reconcile_not_before_ms == 0u);

    tombstone = ts == NINLIL_MODEL_DOMAIN_TOKEN_STATE_CONSUMED
        || ts == NINLIL_MODEL_DOMAIN_TOKEN_STATE_EXPIRED
        || ts == NINLIL_MODEL_DOMAIN_TOKEN_STATE_RECOVERY_REQUIRED_TOMBSTONE;

    /* F rules */
    if (f == NINLIL_CANCEL_FENCED_BEFORE_DISPATCH) {
        if (n != 0u || ts != NINLIL_MODEL_DOMAIN_TOKEN_STATE_NONE
            || (st != NINLIL_MODEL_DOMAIN_DELIVERY_STATE_INBOX_COMMITTED
                && st
                    != NINLIL_MODEL_DOMAIN_DELIVERY_STATE_CANCEL_TOMBSTONE_ONLY)) {
            return 0;
        }
    } else if (f == NINLIL_CANCEL_TOO_LATE_EFFECT_POSSIBLE) {
        if (st == NINLIL_MODEL_DOMAIN_DELIVERY_STATE_CANCEL_TOMBSTONE_ONLY) {
            return 0;
        }
        if (n == 0u
            && st != NINLIL_MODEL_DOMAIN_DELIVERY_STATE_DISPOSITION_COMMITTED
            && st != NINLIL_MODEL_DOMAIN_DELIVERY_STATE_RESULT_COMMITTED
            && st != NINLIL_MODEL_DOMAIN_DELIVERY_STATE_RECOVERY_REQUIRED
            && st != NINLIL_MODEL_DOMAIN_DELIVERY_STATE_RECONCILE_WAIT
            && st != NINLIL_MODEL_DOMAIN_DELIVERY_STATE_DELIVERY_STARTED) {
            /* F_LATE requires N>=1 or post-start/recovery shapes */
            return 0;
        }
        if (n == 0u) {
            return 0; /* F_LATE needs N>=1 for same-record */
        }
    } else if (f != 0u) {
        return 0; /* unknown cancel kind / PENDING not stored on RESULT */
    }

    switch (st) {
    case NINLIL_MODEL_DOMAIN_DELIVERY_STATE_INBOX_COMMITTED:
        if (!a_app || !e_zero) {
            return 0;
        }
        if (n == 0u) {
            return ts == NINLIL_MODEL_DOMAIN_TOKEN_STATE_NONE && d_idle
                && (f == 0u || f == NINLIL_CANCEL_FENCED_BEFORE_DISPATCH);
        }
        return tombstone && d_held
            && (f == 0u || f == NINLIL_CANCEL_TOO_LATE_EFFECT_POSSIBLE);
    case NINLIL_MODEL_DOMAIN_DELIVERY_STATE_DELIVERY_STARTED:
        return a_app && n >= 1u
            && ts == NINLIL_MODEL_DOMAIN_TOKEN_STATE_ACTIVE && e_zero
            && (d_idle || d_held)
            && (f == 0u || f == NINLIL_CANCEL_TOO_LATE_EFFECT_POSSIBLE)
            && result_completed_zero(body);
    case NINLIL_MODEL_DOMAIN_DELIVERY_STATE_RESULT_COMMITTED:
        return a_app && n >= 1u
            && ts == NINLIL_MODEL_DOMAIN_TOKEN_STATE_CONSUMED && e_pos
            && (d_idle || d_held)
            && (f == 0u || f == NINLIL_CANCEL_TOO_LATE_EFFECT_POSSIBLE);
    case NINLIL_MODEL_DOMAIN_DELIVERY_STATE_DISPOSITION_COMMITTED:
        if (!a_app || !e_disp) {
            return 0;
        }
        if (n == 0u) {
            return ts == NINLIL_MODEL_DOMAIN_TOKEN_STATE_NONE && d_idle
                && f == 0u; /* pre-callback F_NONE only */
        }
        return ts == NINLIL_MODEL_DOMAIN_TOKEN_STATE_CONSUMED
            && (d_idle || d_held)
            && (f == 0u || f == NINLIL_CANCEL_TOO_LATE_EFFECT_POSSIBLE);
    case NINLIL_MODEL_DOMAIN_DELIVERY_STATE_RECOVERY_REQUIRED:
        if (!a_app || !e_rec || !d_open) {
            return 0;
        }
        if (!result_e_rec_token_pair_ok(body->reason, ts, n)) {
            return 0;
        }
        return f == 0u || f == NINLIL_CANCEL_TOO_LATE_EFFECT_POSSIBLE;
    case NINLIL_MODEL_DOMAIN_DELIVERY_STATE_RECONCILE_WAIT:
        /* Same E_REC×token reachability as state 6; D_WAIT only. */
        if (!a_app || !e_rec || !d_wait) {
            return 0;
        }
        if (!result_e_rec_token_pair_ok(body->reason, ts, n)) {
            return 0;
        }
        return f == 0u || f == NINLIL_CANCEL_TOO_LATE_EFFECT_POSSIBLE;
    case NINLIL_MODEL_DOMAIN_DELIVERY_STATE_CANCEL_TOMBSTONE_ONLY:
        return a_cancel && n == 0u
            && ts == NINLIL_MODEL_DOMAIN_TOKEN_STATE_NONE && d_idle && e_zero
            && f == NINLIL_CANCEL_FENCED_BEFORE_DISPATCH
            && result_completed_zero(body);
    default:
        return 0;
    }
}

static int result_cache_fields_ok(
    const ninlil_model_domain_body_result_cache_t *body)
{
    if (body == NULL
        || !result_cache_delivery_raw_ok(
               body->delivery_key_raw_length, body->delivery_key_raw,
               body->transaction_id)
        || id_is_zero(body->transaction_id)
        || !result_cache_delivery_key_digest_ok(body)) {
        return 0;
    }
    if (body->application_seen > 1u) {
        return 0;
    }
    if (body->reconcile_retry_generation == 0u) {
        if (body->reconcile_invocation_count != 0u
            || !id_is_zero(body->reconcile_not_before_clock_epoch)
            || body->reconcile_not_before_ms != 0u) {
            return 0;
        }
    } else if (
        body->reconcile_invocation_count != UINT64_MAX
        && body->reconcile_retry_generation
            > body->reconcile_invocation_count + 1u) {
        return 0;
    }
    /* mixed not-before (one zero one not) illegal */
    if (id_is_zero(body->reconcile_not_before_clock_epoch)
        != (body->reconcile_not_before_ms == 0u)) {
        return 0;
    }
    return result_product_ok(body);
}

uint32_t ninlil_model_domain_body_result_cache_encoded_length(
    const ninlil_model_domain_body_result_cache_t *body)
{
    if (body == NULL || !result_cache_fields_ok(body)) {
        return 0u;
    }
    return NINLIL_MODEL_DOMAIN_BODY_RESULT_CACHE_BYTES;
}

ninlil_status_t ninlil_model_domain_encode_body_result_cache(
    const ninlil_model_domain_body_result_cache_t *body,
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
        if (body->delivery_key_raw != NULL
            && body->delivery_key_raw_length != 0u) {
            ptrs[n] = body->delivery_key_raw;
            lens[n] = body->delivery_key_raw_length;
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
    required = ninlil_model_domain_body_result_cache_encoded_length(body);
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL) || required == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    o = 0u;
    o += encode_raw16(
        &out_bytes[o], body->delivery_key_raw_length, body->delivery_key_raw);
    (void)memcpy(&out_bytes[o], body->delivery_key_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->transaction_id, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->delivery_count);
    o += 8u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->application_seen);
    o += 4u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->application_attempt_count);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->delivery_state);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->reply_count);
    o += 4u;
    (void)memcpy(&out_bytes[o], body->token_context_id, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->token_generation);
    o += 8u;
    (void)memcpy(&out_bytes[o], body->token_clock_epoch, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->token_expires_at_ms);
    o += 8u;
    (void)memcpy(&out_bytes[o], body->delivery_started_clock_epoch, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->delivery_started_at_ms);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->completion_expires_at_ms);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->callback_invocations);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->reconcile_invocation_count);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->reconcile_retry_generation);
    o += 8u;
    (void)memcpy(&out_bytes[o], body->reconcile_not_before_clock_epoch, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->reconcile_not_before_ms);
    o += 8u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->application_result_kind);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->evidence_stage);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->disposition);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->reason);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->effect_certainty);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->retry_guidance);
    o += 4u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->retry_delay_ms);
    o += 8u;
    (void)memcpy(&out_bytes[o], body->evidence_cell_key_digest, 32u);
    o += 32u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->token_state);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->cancel_result_kind);
    o += 4u;
    (void)memcpy(&out_bytes[o], body->completed_clock_epoch, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->completed_at_ms);
    o += 8u;
    if (o != NINLIL_MODEL_DOMAIN_BODY_RESULT_CACHE_BYTES) {
        *out_length = 0u;
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = o;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_result_cache(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_result_cache_t *out_body)
{
    ninlil_model_domain_body_result_cache_t tmp;
    uint32_t o = 0u;
    uint32_t c = 0u;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length != NINLIL_MODEL_DOMAIN_BODY_RESULT_CACHE_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    if (!decode_raw16_view(
            encoded.data + o, encoded.length - o, (uint16_t)128u,
            &tmp.delivery_key_raw_length, &tmp.delivery_key_raw, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += c;
    if (encoded.length - o != NINLIL_MODEL_DOMAIN_BODY_RESULT_CACHE_FIXED) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(tmp.delivery_key_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.transaction_id, &encoded.data[o], 16u);
    o += 16u;
    tmp.delivery_count = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.application_seen = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.application_attempt_count =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.delivery_state = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.reply_count = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    (void)memcpy(tmp.token_context_id, &encoded.data[o], 16u);
    o += 16u;
    tmp.token_generation = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    (void)memcpy(tmp.token_clock_epoch, &encoded.data[o], 16u);
    o += 16u;
    tmp.token_expires_at_ms =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    (void)memcpy(tmp.delivery_started_clock_epoch, &encoded.data[o], 16u);
    o += 16u;
    tmp.delivery_started_at_ms =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.completion_expires_at_ms =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.callback_invocations =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.reconcile_invocation_count =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.reconcile_retry_generation =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    (void)memcpy(tmp.reconcile_not_before_clock_epoch, &encoded.data[o], 16u);
    o += 16u;
    tmp.reconcile_not_before_ms =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.application_result_kind =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.evidence_stage = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.disposition = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.reason = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.effect_certainty = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.retry_guidance = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.retry_delay_ms = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    (void)memcpy(tmp.evidence_cell_key_digest, &encoded.data[o], 32u);
    o += 32u;
    tmp.token_state = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.cancel_result_kind =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    (void)memcpy(tmp.completed_clock_epoch, &encoded.data[o], 16u);
    o += 16u;
    tmp.completed_at_ms = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    if (o != encoded.length || !result_cache_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- REVERSE_REPLY (0x42) docs17 §8.5 D1-B3j --- */

/* Exact delivery contents: 5 non-zero IDs; txn at [32,48). */
static int reverse_reply_delivery_raw_ok(
    uint16_t raw_len, const uint8_t *raw, const uint8_t *transaction_id)
{
    size_t i;
    if (raw_len != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES
        || raw == NULL || transaction_id == NULL) {
        return 0;
    }
    for (i = 0u; i < 5u; ++i) {
        if (id_is_zero(raw + (i * 16u))) {
            return 0;
        }
    }
    return memcmp(raw + 32u, transaction_id, 16u) == 0;
}

/*
 * reply_key_raw contents = delivery_key_raw:RAW16 (82) || reply_kind:u32 (4).
 * Exact 86 bytes; body reply_kind must match trailing u32.
 */
static int reverse_reply_reply_raw_ok(
    const ninlil_model_domain_body_reverse_reply_t *body)
{
    uint8_t expect[86];
    uint32_t o = 0u;
    uint32_t kind_wire;

    if (body == NULL || body->reply_key_raw == NULL
        || body->delivery_key_raw == NULL
        || body->reply_key_raw_length != 86u
        || body->delivery_key_raw_length
            != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES) {
        return 0;
    }
    o += encode_raw16(
        expect, body->delivery_key_raw_length, body->delivery_key_raw);
    if (o != 82u) {
        return 0;
    }
    ninlil_model_domain_encode_u32_be(&expect[o], body->reply_kind);
    o += 4u;
    if (o != 86u) {
        return 0;
    }
    if (memcmp(body->reply_key_raw, expect, 86u) != 0) {
        return 0;
    }
    kind_wire = ninlil_model_domain_decode_u32_be(body->reply_key_raw + 82u);
    return kind_wire == body->reply_kind;
}

static int reverse_reply_kind_ok(uint32_t kind)
{
    return kind == NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT
        || kind == NINLIL_MODEL_DOMAIN_REPLY_KIND_DISPOSITION
        || kind == NINLIL_MODEL_DOMAIN_REPLY_KIND_CUSTODY
        || kind == NINLIL_MODEL_DOMAIN_REPLY_KIND_CANCEL_RESULT;
}

/* Retry timer: (epoch zero, ms 0) or (epoch nz, ms nz) only. */
static int reverse_reply_timer_pair_ok(
    const uint8_t epoch[NINLIL_MODEL_DOMAIN_ID_BYTES], uint64_t ms)
{
    if (epoch == NULL) {
        return 0;
    }
    if (id_is_zero(epoch)) {
        return ms == 0u;
    }
    return ms != 0u;
}

static int reverse_reply_timer_zero(
    const ninlil_model_domain_body_reverse_reply_t *body)
{
    return id_is_zero(body->retry_clock_epoch)
        && body->retry_not_before_ms == 0u;
}

static int reverse_reply_timer_nz(
    const ninlil_model_domain_body_reverse_reply_t *body)
{
    return !id_is_zero(body->retry_clock_epoch)
        && body->retry_not_before_ms != 0u;
}

/* I==0 iff availability 0; I>0 iff availability non-zero. Always I<=G. */
static int reverse_reply_i_avail_ok(uint64_t g, uint64_t i, uint64_t avail)
{
    if (i > g) {
        return 0;
    }
    if (i == 0u) {
        return avail == 0u;
    }
    return avail != 0u;
}

/*
 * Closed send-state matrix (docs17 §8.5 D1-B3j).
 * not MAX means both G and I are strictly less than UINT64_MAX.
 * exhausted=1 iff (G or I is MAX) and iff state 5.
 */
static int reverse_reply_matrix_ok(
    const ninlil_model_domain_body_reverse_reply_t *body)
{
    uint32_t st;
    uint64_t g;
    uint64_t i;
    uint32_t exhausted;
    uint64_t avail;
    int at_max;
    int not_max;
    int timer_ok;
    int timer_zero;
    int timer_nz;
    int i_ok;

    if (body == NULL) {
        return 0;
    }
    st = body->send_state;
    g = body->send_operation_generation;
    i = body->send_invocation_count;
    exhausted = body->send_counter_exhausted;
    avail = body->availability_epoch;

    if (exhausted != 0u && exhausted != 1u) {
        return 0;
    }
    at_max = (g == UINT64_MAX) || (i == UINT64_MAX);
    not_max = !at_max;
    timer_ok = reverse_reply_timer_pair_ok(
        body->retry_clock_epoch, body->retry_not_before_ms);
    if (!timer_ok) {
        return 0;
    }
    timer_zero = reverse_reply_timer_zero(body);
    timer_nz = reverse_reply_timer_nz(body);
    i_ok = reverse_reply_i_avail_ok(g, i, avail);
    if (!i_ok) {
        return 0;
    }

    switch (st) {
    case NINLIL_MODEL_DOMAIN_REPLY_SEND_PENDING:
        /* virgin: G=0,I=0,avail=0,exh=0,timer zero */
        if (g == 0u) {
            return i == 0u && avail == 0u && exhausted == 0u && timer_zero;
        }
        /* reopened: G>=1 not MAX, I 0..G coupled, exh=0, timer zero */
        return not_max && exhausted == 0u && timer_zero;
    case NINLIL_MODEL_DOMAIN_REPLY_SEND_WAITING_RETRY:
        return g >= 1u && not_max && exhausted == 0u && timer_nz;
    case NINLIL_MODEL_DOMAIN_REPLY_SEND_CLOSED_SENT_OR_UNKNOWN:
        /* I is 1..G (strictly positive), availability non-zero via coupling */
        return g >= 1u && not_max && i >= 1u && exhausted == 0u && timer_zero;
    case NINLIL_MODEL_DOMAIN_REPLY_SEND_CLOSED_DENIED:
        return g >= 1u && not_max && exhausted == 0u && timer_zero;
    case NINLIL_MODEL_DOMAIN_REPLY_SEND_CLOSED_COUNTER_EXHAUSTED:
        return at_max && exhausted == 1u && timer_zero;
    default:
        return 0;
    }
}

static int reverse_reply_fields_ok(
    const ninlil_model_domain_body_reverse_reply_t *body)
{
    if (body == NULL
        || !reverse_reply_delivery_raw_ok(
               body->delivery_key_raw_length, body->delivery_key_raw,
               body->transaction_id)
        || !reverse_reply_reply_raw_ok(body)
        || !reverse_reply_kind_ok(body->reply_kind)
        || id_is_zero(body->transaction_id)
        || id_is_zero(body->attempt_id)
        || digest_is_zero(body->semantic_digest)
        || digest_is_zero(body->body_blob_key_digest)
        || body->reserved != 0u) {
        return 0;
    }
    return reverse_reply_matrix_ok(body);
}

uint32_t ninlil_model_domain_body_reverse_reply_encoded_length(
    const ninlil_model_domain_body_reverse_reply_t *body)
{
    if (body == NULL || !reverse_reply_fields_ok(body)) {
        return 0u;
    }
    return NINLIL_MODEL_DOMAIN_BODY_REVERSE_REPLY_BYTES;
}

ninlil_status_t ninlil_model_domain_encode_body_reverse_reply(
    const ninlil_model_domain_body_reverse_reply_t *body,
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
        if (body->reply_key_raw != NULL && body->reply_key_raw_length != 0u) {
            ptrs[n] = body->reply_key_raw;
            lens[n] = body->reply_key_raw_length;
            n++;
        }
        if (body->delivery_key_raw != NULL
            && body->delivery_key_raw_length != 0u) {
            ptrs[n] = body->delivery_key_raw;
            lens[n] = body->delivery_key_raw_length;
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
    required = ninlil_model_domain_body_reverse_reply_encoded_length(body);
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL) || required == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    o = 0u;
    o += encode_raw16(
        &out_bytes[o], body->reply_key_raw_length, body->reply_key_raw);
    o += encode_raw16(
        &out_bytes[o], body->delivery_key_raw_length, body->delivery_key_raw);
    (void)memcpy(&out_bytes[o], body->transaction_id, 16u);
    o += 16u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->reply_kind);
    o += 4u;
    (void)memcpy(&out_bytes[o], body->semantic_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->body_blob_key_digest, 32u);
    o += 32u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->send_state);
    o += 4u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->send_operation_generation);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->send_invocation_count);
    o += 8u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->send_counter_exhausted);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->reserved);
    o += 4u;
    (void)memcpy(&out_bytes[o], body->attempt_id, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->availability_epoch);
    o += 8u;
    (void)memcpy(&out_bytes[o], body->retry_clock_epoch, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->retry_not_before_ms);
    o += 8u;
    if (o != NINLIL_MODEL_DOMAIN_BODY_REVERSE_REPLY_BYTES) {
        *out_length = 0u;
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = o;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_reverse_reply(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_reverse_reply_t *out_body)
{
    ninlil_model_domain_body_reverse_reply_t tmp;
    uint32_t o = 0u;
    uint32_t c = 0u;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length != NINLIL_MODEL_DOMAIN_BODY_REVERSE_REPLY_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    /* reply RAW16 max 192 */
    if (!decode_raw16_view(
            encoded.data + o, encoded.length - o, (uint16_t)192u,
            &tmp.reply_key_raw_length, &tmp.reply_key_raw, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += c;
    /* delivery RAW16 max 128 */
    if (!decode_raw16_view(
            encoded.data + o, encoded.length - o, (uint16_t)128u,
            &tmp.delivery_key_raw_length, &tmp.delivery_key_raw, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += c;
    if (encoded.length - o != NINLIL_MODEL_DOMAIN_BODY_REVERSE_REPLY_FIXED) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(tmp.transaction_id, &encoded.data[o], 16u);
    o += 16u;
    tmp.reply_kind = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    (void)memcpy(tmp.semantic_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.body_blob_key_digest, &encoded.data[o], 32u);
    o += 32u;
    tmp.send_state = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.send_operation_generation =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.send_invocation_count =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.send_counter_exhausted =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.reserved = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    (void)memcpy(tmp.attempt_id, &encoded.data[o], 16u);
    o += 16u;
    tmp.availability_epoch =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    (void)memcpy(tmp.retry_clock_epoch, &encoded.data[o], 16u);
    o += 16u;
    tmp.retry_not_before_ms =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    if (o != encoded.length || !reverse_reply_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- EVENT_SPOOL (0x50) docs17 §8.6 D1-B3k --- */

static int spool_state_is_known(uint32_t st)
{
    return st == NINLIL_MODEL_DOMAIN_SPOOL_STATE_ACTIVE
        || st == NINLIL_MODEL_DOMAIN_SPOOL_STATE_PARKED_RETRY
        || st == NINLIL_MODEL_DOMAIN_SPOOL_STATE_RELEASED
        || st == NINLIL_MODEL_DOMAIN_SPOOL_STATE_DISCARDED;
}

/*
 * state × cause matrix (docs17 §8.6):
 * ACTIVE / RELEASED / DISCARDED → park_cause exact NONE(0)
 * PARKED_RETRY → park_cause exact 1..5
 */
static int event_spool_state_cause_ok(uint32_t state, uint32_t cause)
{
    if (!spool_state_is_known(state) || !park_cause_is_known(cause)) {
        return 0;
    }
    if (state == NINLIL_MODEL_DOMAIN_SPOOL_STATE_PARKED_RETRY) {
        return cause >= NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT
            && cause <= NINLIL_EVENT_PARK_CAUSE_COUNTER_EXHAUSTED;
    }
    return cause == NINLIL_EVENT_PARK_CAUSE_NONE;
}

static int event_spool_reservation_key_digest_ok(
    const ninlil_model_domain_body_event_spool_t *body)
{
    uint8_t res_comp[4u + 16u];
    ninlil_bytes_view_t res_view;

    if (body == NULL) {
        return 0;
    }
    /* owner_kind:u16=TRANSACTION(2) || owner_key_raw:RAW16(tx exact 16) */
    ninlil_model_domain_encode_u16_be(
        res_comp, NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_TRANSACTION);
    ninlil_model_domain_encode_u16_be(&res_comp[2], 16u);
    (void)memcpy(&res_comp[4], body->transaction_id, 16u);
    res_view.data = res_comp;
    res_view.length = 4u + 16u;
    return digest_eq_composite_key(
        body->reservation_key_digest,
        NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION,
        res_view);
}

static int event_spool_fields_ok(
    const ninlil_model_domain_body_event_spool_t *body)
{
    if (body == NULL
        || id_is_zero(body->transaction_id)
        || id_is_zero(body->event_id)
        || body->spool_revision < 1u
        || !event_spool_state_cause_ok(body->spool_state, body->park_cause)
        || body->retry_cycle_id < 1u
        || digest_is_zero(body->payload_blob_key_digest)
        || body->successful_resume_count
            > NINLIL_MODEL_DOMAIN_EVENT_SPOOL_RESUME_MAX
        || (body->discard_committed != 0u && body->discard_committed != 1u)
        || ((body->discard_committed == 1u)
            != (body->spool_state
                == NINLIL_MODEL_DOMAIN_SPOOL_STATE_DISCARDED))) {
        return 0;
    }
    return event_spool_reservation_key_digest_ok(body);
}

uint32_t ninlil_model_domain_body_event_spool_encoded_length(
    const ninlil_model_domain_body_event_spool_t *body)
{
    if (body == NULL || !event_spool_fields_ok(body)) {
        return 0u;
    }
    return NINLIL_MODEL_DOMAIN_BODY_EVENT_SPOOL_BYTES;
}

ninlil_status_t ninlil_model_domain_encode_body_event_spool(
    const ninlil_model_domain_body_event_spool_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    uint32_t required;
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
    required = ninlil_model_domain_body_event_spool_encoded_length(body);
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL) || required == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    o = 0u;
    (void)memcpy(&out_bytes[o], body->transaction_id, 16u);
    o += 16u;
    (void)memcpy(&out_bytes[o], body->event_id, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->spool_revision);
    o += 8u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->spool_state);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->park_cause);
    o += 4u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->retry_cycle_id);
    o += 8u;
    (void)memcpy(&out_bytes[o], body->payload_blob_key_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->provider_id, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->provider_revision);
    o += 8u;
    (void)memcpy(&out_bytes[o], body->decision_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->grant_id, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->grant_revision);
    o += 8u;
    (void)memcpy(&out_bytes[o], body->decision_clock_epoch, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->evaluated_at_ms);
    o += 8u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->valid_from_ms);
    o += 8u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->expires_at_ms);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->provider_retry_delay_ms);
    o += 8u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->grant_limit_payload);
    o += 4u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->grant_limit_active_count);
    o += 4u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->grant_limit_active_bytes);
    o += 8u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->grant_window_ms);
    o += 4u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->grant_max_admissions_per_window);
    o += 4u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->grant_attempts_per_cycle);
    o += 4u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->last_seen_availability_epoch);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->last_consumed_availability_epoch);
    o += 8u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->successful_resume_count);
    o += 4u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->discard_committed);
    o += 4u;
    (void)memcpy(&out_bytes[o], body->reservation_key_digest, 32u);
    o += 32u;
    if (o != NINLIL_MODEL_DOMAIN_BODY_EVENT_SPOOL_BYTES) {
        *out_length = 0u;
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = o;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_event_spool(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_event_spool_t *out_body)
{
    ninlil_model_domain_body_event_spool_t tmp;
    uint32_t o = 0u;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length != NINLIL_MODEL_DOMAIN_BODY_EVENT_SPOOL_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    (void)memcpy(tmp.transaction_id, &encoded.data[o], 16u);
    o += 16u;
    (void)memcpy(tmp.event_id, &encoded.data[o], 16u);
    o += 16u;
    tmp.spool_revision = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.spool_state = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.park_cause = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.retry_cycle_id = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    (void)memcpy(tmp.payload_blob_key_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.provider_id, &encoded.data[o], 16u);
    o += 16u;
    tmp.provider_revision =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    (void)memcpy(tmp.decision_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.grant_id, &encoded.data[o], 16u);
    o += 16u;
    tmp.grant_revision = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    (void)memcpy(tmp.decision_clock_epoch, &encoded.data[o], 16u);
    o += 16u;
    tmp.evaluated_at_ms = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.valid_from_ms = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.expires_at_ms = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.provider_retry_delay_ms =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.grant_limit_payload =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.grant_limit_active_count =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.grant_limit_active_bytes =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.grant_window_ms = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.grant_max_admissions_per_window =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.grant_attempts_per_cycle =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.last_seen_availability_epoch =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.last_consumed_availability_epoch =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.successful_resume_count =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.discard_committed =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    (void)memcpy(tmp.reservation_key_digest, &encoded.data[o], 32u);
    o += 32u;
    if (o != encoded.length || !event_spool_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- RETRY_SUMMARY (0x51) docs17 §8.6 D1-B3l --- */

static uint64_t retry_summary_expected_folded(uint64_t total)
{
    /* folded = max(total - 4, 0); checked u64; no underflow. */
    if (total >= NINLIL_MODEL_DOMAIN_RETRY_SUMMARY_FOLD_WINDOW) {
        return total - NINLIL_MODEL_DOMAIN_RETRY_SUMMARY_FOLD_WINDOW;
    }
    return 0u;
}

static int retry_summary_bool_ok(uint32_t v)
{
    return v == 0u || v == 1u;
}

static int retry_summary_cumulative_fields_ok(
    const ninlil_model_domain_body_retry_summary_t *body)
{
    const ninlil_model_domain_body_retry_summary_cumulative_t *c;

    if (body == NULL
        || body->summary_kind
            != NINLIL_MODEL_DOMAIN_RETRY_SUMMARY_KIND_CUMULATIVE
        || id_is_zero(body->transaction_id)
        || body->slot_index != 0u) {
        return 0;
    }
    c = &body->cumulative;
    if (c->folded_cycle_count
            != retry_summary_expected_folded(c->total_completed_cycle_count)
        || !retry_summary_bool_ok(c->delivery_possible_any)
        || !retry_summary_bool_ok(c->counter_saturated)) {
        return 0;
    }
    /* folded=0 ⇒ all folded aggregates exact zero (incl. 16-byte clock). */
    if (c->folded_cycle_count == 0u) {
        if (c->cumulative_attempt_count != 0u || c->last_outcome != 0u
            || c->last_reason != 0u || c->last_ended_at_ms != 0u
            || c->delivery_possible_any != 0u || c->counter_saturated != 0u
            || !id_is_zero(c->last_ended_clock_epoch)) {
            return 0;
        }
    }
    return 1;
}

static int retry_summary_recent_fields_ok(
    const ninlil_model_domain_body_retry_summary_t *body)
{
    const ninlil_model_domain_body_retry_summary_recent_t *r;
    uint64_t expect_slot;

    if (body == NULL
        || body->summary_kind != NINLIL_MODEL_DOMAIN_RETRY_SUMMARY_KIND_RECENT
        || id_is_zero(body->transaction_id)
        || body->slot_index > NINLIL_MODEL_DOMAIN_RETRY_SUMMARY_SLOT_MAX) {
        return 0;
    }
    r = &body->recent;
    if (r->retry_cycle_id < 1u
        || r->attempt_count < 1u
        || r->attempt_count > NINLIL_MODEL_DOMAIN_RETRY_SUMMARY_ATTEMPT_MAX
        || !retry_summary_bool_ok(r->delivery_possible)
        || r->reserved != 0u) {
        return 0;
    }
    /* slot = (retry_cycle_id - 1) mod 4; no underflow (cycle >= 1). */
    expect_slot = (r->retry_cycle_id - 1u) % 4u;
    if ((uint64_t)body->slot_index != expect_slot) {
        return 0;
    }
    return 1;
}

static int retry_summary_fields_ok(
    const ninlil_model_domain_body_retry_summary_t *body)
{
    if (body == NULL) {
        return 0;
    }
    if (body->summary_kind
        == NINLIL_MODEL_DOMAIN_RETRY_SUMMARY_KIND_CUMULATIVE) {
        return retry_summary_cumulative_fields_ok(body);
    }
    if (body->summary_kind == NINLIL_MODEL_DOMAIN_RETRY_SUMMARY_KIND_RECENT) {
        return retry_summary_recent_fields_ok(body);
    }
    return 0;
}

uint32_t ninlil_model_domain_body_retry_summary_encoded_length(
    const ninlil_model_domain_body_retry_summary_t *body)
{
    if (body == NULL || !retry_summary_fields_ok(body)) {
        return 0u;
    }
    if (body->summary_kind
        == NINLIL_MODEL_DOMAIN_RETRY_SUMMARY_KIND_CUMULATIVE) {
        return NINLIL_MODEL_DOMAIN_BODY_RETRY_SUMMARY_CUMULATIVE_BYTES;
    }
    return NINLIL_MODEL_DOMAIN_BODY_RETRY_SUMMARY_RECENT_BYTES;
}

ninlil_status_t ninlil_model_domain_encode_body_retry_summary(
    const ninlil_model_domain_body_retry_summary_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    uint32_t required;
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
    required = ninlil_model_domain_body_retry_summary_encoded_length(body);
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL) || required == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    o = 0u;
    (void)memcpy(&out_bytes[o], body->transaction_id, 16u);
    o += 16u;
    ninlil_model_domain_encode_u16_be(&out_bytes[o], body->summary_kind);
    o += 2u;
    ninlil_model_domain_encode_u16_be(&out_bytes[o], body->slot_index);
    o += 2u;
    if (body->summary_kind
        == NINLIL_MODEL_DOMAIN_RETRY_SUMMARY_KIND_CUMULATIVE) {
        const ninlil_model_domain_body_retry_summary_cumulative_t *c =
            &body->cumulative;

        ninlil_model_domain_encode_u64_be(
            &out_bytes[o], c->total_completed_cycle_count);
        o += 8u;
        ninlil_model_domain_encode_u64_be(
            &out_bytes[o], c->folded_cycle_count);
        o += 8u;
        ninlil_model_domain_encode_u64_be(
            &out_bytes[o], c->cumulative_attempt_count);
        o += 8u;
        ninlil_model_domain_encode_u32_be(&out_bytes[o], c->last_outcome);
        o += 4u;
        ninlil_model_domain_encode_u32_be(&out_bytes[o], c->last_reason);
        o += 4u;
        (void)memcpy(&out_bytes[o], c->last_ended_clock_epoch, 16u);
        o += 16u;
        ninlil_model_domain_encode_u64_be(
            &out_bytes[o], c->last_ended_at_ms);
        o += 8u;
        ninlil_model_domain_encode_u32_be(
            &out_bytes[o], c->delivery_possible_any);
        o += 4u;
        ninlil_model_domain_encode_u32_be(
            &out_bytes[o], c->counter_saturated);
        o += 4u;
        if (o != NINLIL_MODEL_DOMAIN_BODY_RETRY_SUMMARY_CUMULATIVE_BYTES) {
            *out_length = 0u;
            return NINLIL_E_INVALID_ARGUMENT;
        }
    } else {
        const ninlil_model_domain_body_retry_summary_recent_t *r =
            &body->recent;

        ninlil_model_domain_encode_u64_be(&out_bytes[o], r->retry_cycle_id);
        o += 8u;
        ninlil_model_domain_encode_u32_be(&out_bytes[o], r->attempt_count);
        o += 4u;
        ninlil_model_domain_encode_u32_be(&out_bytes[o], r->last_outcome);
        o += 4u;
        ninlil_model_domain_encode_u32_be(&out_bytes[o], r->last_reason);
        o += 4u;
        ninlil_model_domain_encode_u64_be(
            &out_bytes[o], r->availability_epoch);
        o += 8u;
        (void)memcpy(&out_bytes[o], r->ended_clock_epoch, 16u);
        o += 16u;
        ninlil_model_domain_encode_u64_be(&out_bytes[o], r->ended_at_ms);
        o += 8u;
        ninlil_model_domain_encode_u32_be(
            &out_bytes[o], r->delivery_possible);
        o += 4u;
        ninlil_model_domain_encode_u32_be(&out_bytes[o], r->reserved);
        o += 4u;
        if (o != NINLIL_MODEL_DOMAIN_BODY_RETRY_SUMMARY_RECENT_BYTES) {
            *out_length = 0u;
            return NINLIL_E_INVALID_ARGUMENT;
        }
    }
    *out_length = o;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_retry_summary(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_retry_summary_t *out_body)
{
    ninlil_model_domain_body_retry_summary_t tmp;
    uint32_t o = 0u;
    uint16_t kind;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || (encoded.length
                != NINLIL_MODEL_DOMAIN_BODY_RETRY_SUMMARY_CUMULATIVE_BYTES
            && encoded.length
                != NINLIL_MODEL_DOMAIN_BODY_RETRY_SUMMARY_RECENT_BYTES)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    (void)memcpy(tmp.transaction_id, &encoded.data[o], 16u);
    o += 16u;
    kind = ninlil_model_domain_decode_u16_be(&encoded.data[o]);
    o += 2u;
    tmp.summary_kind = kind;
    tmp.slot_index = ninlil_model_domain_decode_u16_be(&encoded.data[o]);
    o += 2u;

    /* Declared kind must match wire length (variant mismatch = corrupt). */
    if (kind == NINLIL_MODEL_DOMAIN_RETRY_SUMMARY_KIND_CUMULATIVE) {
        ninlil_model_domain_body_retry_summary_cumulative_t *c =
            &tmp.cumulative;

        if (encoded.length
            != NINLIL_MODEL_DOMAIN_BODY_RETRY_SUMMARY_CUMULATIVE_BYTES) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        c->total_completed_cycle_count =
            ninlil_model_domain_decode_u64_be(&encoded.data[o]);
        o += 8u;
        c->folded_cycle_count =
            ninlil_model_domain_decode_u64_be(&encoded.data[o]);
        o += 8u;
        c->cumulative_attempt_count =
            ninlil_model_domain_decode_u64_be(&encoded.data[o]);
        o += 8u;
        c->last_outcome =
            ninlil_model_domain_decode_u32_be(&encoded.data[o]);
        o += 4u;
        c->last_reason =
            ninlil_model_domain_decode_u32_be(&encoded.data[o]);
        o += 4u;
        (void)memcpy(c->last_ended_clock_epoch, &encoded.data[o], 16u);
        o += 16u;
        c->last_ended_at_ms =
            ninlil_model_domain_decode_u64_be(&encoded.data[o]);
        o += 8u;
        c->delivery_possible_any =
            ninlil_model_domain_decode_u32_be(&encoded.data[o]);
        o += 4u;
        c->counter_saturated =
            ninlil_model_domain_decode_u32_be(&encoded.data[o]);
        o += 4u;
    } else if (kind == NINLIL_MODEL_DOMAIN_RETRY_SUMMARY_KIND_RECENT) {
        ninlil_model_domain_body_retry_summary_recent_t *r = &tmp.recent;

        if (encoded.length
            != NINLIL_MODEL_DOMAIN_BODY_RETRY_SUMMARY_RECENT_BYTES) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        r->retry_cycle_id =
            ninlil_model_domain_decode_u64_be(&encoded.data[o]);
        o += 8u;
        r->attempt_count =
            ninlil_model_domain_decode_u32_be(&encoded.data[o]);
        o += 4u;
        r->last_outcome =
            ninlil_model_domain_decode_u32_be(&encoded.data[o]);
        o += 4u;
        r->last_reason =
            ninlil_model_domain_decode_u32_be(&encoded.data[o]);
        o += 4u;
        r->availability_epoch =
            ninlil_model_domain_decode_u64_be(&encoded.data[o]);
        o += 8u;
        (void)memcpy(r->ended_clock_epoch, &encoded.data[o], 16u);
        o += 16u;
        r->ended_at_ms =
            ninlil_model_domain_decode_u64_be(&encoded.data[o]);
        o += 8u;
        r->delivery_possible =
            ninlil_model_domain_decode_u32_be(&encoded.data[o]);
        o += 4u;
        r->reserved = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
        o += 4u;
    } else {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    if (o != encoded.length || !retry_summary_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- MANAGEMENT_LEDGER (0x52) docs17 §8.6 D1-B3m / docs12 §10 --- */

/*
 * Independent streaming SHA-256 of management request preimage from body
 * fields only (docs17 §5.1 / docs12 §10). Never hashes ABI header/pointer/
 * reserved/padding. audit_length is widened u16→u32 for metadata_length.
 */
static int management_canonical_digest_matches(
    const ninlil_model_domain_body_management_ledger_t *body)
{
    ninlil_model_domain_sha256_ctx_t ctx;
    ninlil_model_domain_digest_t dig;
    uint8_t scratch[8];
    ninlil_status_t status;

    if (body == NULL) {
        return 0;
    }
    ninlil_model_domain_sha256_init(&ctx);
    if (body->operation_kind
        == NINLIL_MODEL_DOMAIN_MANAGEMENT_KIND_EVENT_RESUME) {
        status = ninlil_model_domain_sha256_update(
            &ctx, (const uint8_t *)PREIMAGE_EVENT_RESUME,
            (uint32_t)(sizeof(PREIMAGE_EVENT_RESUME) - 1u));
        if (status != NINLIL_OK) {
            return 0;
        }
        status = ninlil_model_domain_sha256_update(
            &ctx, body->transaction_id, 16u);
        if (status != NINLIL_OK) {
            return 0;
        }
        status = ninlil_model_domain_sha256_update(
            &ctx, body->operation_id, 16u);
        if (status != NINLIL_OK) {
            return 0;
        }
        status = ninlil_model_domain_sha256_update(
            &ctx, body->actor_id, 16u);
        if (status != NINLIL_OK) {
            return 0;
        }
        ninlil_model_domain_encode_u64_be(
            scratch, body->expected_spool_revision);
        status = ninlil_model_domain_sha256_update(&ctx, scratch, 8u);
        if (status != NINLIL_OK) {
            return 0;
        }
        ninlil_model_domain_encode_u32_be(scratch, body->request_reason);
        status = ninlil_model_domain_sha256_update(&ctx, scratch, 4u);
        if (status != NINLIL_OK) {
            return 0;
        }
        /* metadata_length:u32 — widen persist audit_length:u16 (no overflow). */
        ninlil_model_domain_encode_u32_be(
            scratch, (uint32_t)body->audit_length);
        status = ninlil_model_domain_sha256_update(&ctx, scratch, 4u);
        if (status != NINLIL_OK) {
            return 0;
        }
        if (body->audit_length > 0u) {
            status = ninlil_model_domain_sha256_update(
                &ctx, body->audit_bytes, (uint32_t)body->audit_length);
            if (status != NINLIL_OK) {
                return 0;
            }
        }
    } else if (body->operation_kind
        == NINLIL_MODEL_DOMAIN_MANAGEMENT_KIND_EVENT_DISCARD) {
        status = ninlil_model_domain_sha256_update(
            &ctx, (const uint8_t *)PREIMAGE_EVENT_DISCARD,
            (uint32_t)(sizeof(PREIMAGE_EVENT_DISCARD) - 1u));
        if (status != NINLIL_OK) {
            return 0;
        }
        status = ninlil_model_domain_sha256_update(
            &ctx, body->transaction_id, 16u);
        if (status != NINLIL_OK) {
            return 0;
        }
        status = ninlil_model_domain_sha256_update(
            &ctx, body->operation_id, 16u);
        if (status != NINLIL_OK) {
            return 0;
        }
        status = ninlil_model_domain_sha256_update(
            &ctx, body->actor_id, 16u);
        if (status != NINLIL_OK) {
            return 0;
        }
        status = ninlil_model_domain_sha256_update(
            &ctx, body->expected_event_id, 16u);
        if (status != NINLIL_OK) {
            return 0;
        }
        ninlil_model_domain_encode_u16_be(
            scratch, body->expected_content_digest_algorithm);
        status = ninlil_model_domain_sha256_update(&ctx, scratch, 2u);
        if (status != NINLIL_OK) {
            return 0;
        }
        status = ninlil_model_domain_sha256_update(
            &ctx, body->expected_content_digest, 32u);
        if (status != NINLIL_OK) {
            return 0;
        }
        ninlil_model_domain_encode_u64_be(
            scratch, body->expected_spool_revision);
        status = ninlil_model_domain_sha256_update(&ctx, scratch, 8u);
        if (status != NINLIL_OK) {
            return 0;
        }
        ninlil_model_domain_encode_u32_be(scratch, body->request_reason);
        status = ninlil_model_domain_sha256_update(&ctx, scratch, 4u);
        if (status != NINLIL_OK) {
            return 0;
        }
        ninlil_model_domain_encode_u32_be(scratch, body->acknowledge_flag);
        status = ninlil_model_domain_sha256_update(&ctx, scratch, 4u);
        if (status != NINLIL_OK) {
            return 0;
        }
        ninlil_model_domain_encode_u32_be(
            scratch, (uint32_t)body->audit_length);
        status = ninlil_model_domain_sha256_update(&ctx, scratch, 4u);
        if (status != NINLIL_OK) {
            return 0;
        }
        if (body->audit_length > 0u) {
            status = ninlil_model_domain_sha256_update(
                &ctx, body->audit_bytes, (uint32_t)body->audit_length);
            if (status != NINLIL_OK) {
                return 0;
            }
        }
    } else {
        return 0;
    }
    status = ninlil_model_domain_sha256_final(&ctx, &dig);
    if (status != NINLIL_OK) {
        return 0;
    }
    return memcmp(
               dig.bytes, body->canonical_request_digest,
               NINLIL_MODEL_DOMAIN_DIGEST_BYTES)
        == 0;
}

static int management_audit_tail_zero(
    const ninlil_model_domain_body_management_ledger_t *body)
{
    uint32_t i;

    if (body == NULL
        || body->audit_length < 1u
        || body->audit_length
            > NINLIL_MODEL_DOMAIN_MANAGEMENT_AUDIT_BYTES) {
        return 0;
    }
    for (i = (uint32_t)body->audit_length;
         i < NINLIL_MODEL_DOMAIN_MANAGEMENT_AUDIT_BYTES;
         ++i) {
        if (body->audit_bytes[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

/*
 * Kind matrix (docs17 §8.6):
 * 15 EVENT_RESUME: algo0; expected_event/digest zero; ack0; audit epoch+time
 *   zero; spool_released0; reason1..5; replay kind2 + reason NONE; cycle NZ;
 *   revision = expected+1.
 * 16 EVENT_DISCARD: algo1; expected_event/digest NZ; event==expected; ack1;
 *   audit epoch NZ (time may0); spool_released1; reason1..4; replay kind2 +
 *   OPERATOR_DISCARDED; cycle0; revision = expected+1.
 */
static int management_ledger_fields_ok(
    const ninlil_model_domain_body_management_ledger_t *body)
{
    uint64_t expect_replay_rev;

    if (body == NULL
        || body->reserved0 != 0u
        || body->reserved1 != 0u
        || body->reserved2 != 0u
        || body->reserved3 != 0u
        || id_is_zero(body->operation_id)
        || id_is_zero(body->transaction_id)
        || id_is_zero(body->event_id)
        || id_is_zero(body->actor_id)
        || body->ordered_sequence < 1u
        || body->expected_spool_revision < 1u
        || body->expected_spool_revision == UINT64_MAX
        || body->audit_length < 1u
        || body->audit_length > NINLIL_MODEL_DOMAIN_MANAGEMENT_AUDIT_BYTES
        || !management_audit_tail_zero(body)) {
        return 0;
    }
    /* expected_spool_revision exact 1..UINT64_MAX-1; +1 cannot overflow. */
    expect_replay_rev = body->expected_spool_revision + 1u;
    if (body->replay_spool_revision != expect_replay_rev) {
        return 0;
    }

    if (body->operation_kind
        == NINLIL_MODEL_DOMAIN_MANAGEMENT_KIND_EVENT_RESUME) {
        if (body->expected_content_digest_algorithm
                != NINLIL_MODEL_DOMAIN_CONTENT_DIGEST_NONE
            || !id_is_zero(body->expected_event_id)
            || !digest_is_zero(body->expected_content_digest)
            || body->acknowledge_flag != 0u
            || !id_is_zero(body->audit_clock_epoch)
            || body->audit_committed_at_ms != 0u
            || body->replay_spool_released != 0u
            || body->request_reason
                < NINLIL_RESUME_CONNECTIVITY_REMEDIATED
            || body->request_reason > NINLIL_RESUME_TEST
            || body->replay_result_kind
                != NINLIL_EVENT_RESUME_ALREADY_RESUMED
            || body->replay_result_reason != NINLIL_REASON_NONE
            || body->replay_retry_cycle_id < 1u) {
            return 0;
        }
    } else if (body->operation_kind
        == NINLIL_MODEL_DOMAIN_MANAGEMENT_KIND_EVENT_DISCARD) {
        if (body->expected_content_digest_algorithm
                != NINLIL_MODEL_DOMAIN_CONTENT_DIGEST_SHA256
            || id_is_zero(body->expected_event_id)
            || digest_is_zero(body->expected_content_digest)
            || memcmp(
                   body->event_id, body->expected_event_id,
                   NINLIL_MODEL_DOMAIN_ID_BYTES)
                != 0
            || body->acknowledge_flag != 1u
            || id_is_zero(body->audit_clock_epoch)
            || body->replay_spool_released != 1u
            || body->request_reason
                < NINLIL_DISCARD_DEVICE_DECOMMISSIONED
            || body->request_reason > NINLIL_DISCARD_TEST_CLEANUP
            || body->replay_result_kind
                != NINLIL_EVENT_DISCARD_ALREADY_DISCARDED
            || body->replay_result_reason
                != NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT
            || body->replay_retry_cycle_id != 0u) {
            return 0;
        }
    } else {
        return 0;
    }

    return management_canonical_digest_matches(body);
}

uint32_t ninlil_model_domain_body_management_ledger_encoded_length(
    const ninlil_model_domain_body_management_ledger_t *body)
{
    if (body == NULL || !management_ledger_fields_ok(body)) {
        return 0u;
    }
    return NINLIL_MODEL_DOMAIN_BODY_MANAGEMENT_LEDGER_BYTES;
}

ninlil_status_t ninlil_model_domain_encode_body_management_ledger(
    const ninlil_model_domain_body_management_ledger_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    uint32_t required;
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
    required = ninlil_model_domain_body_management_ledger_encoded_length(body);
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL) || required == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    o = 0u;
    (void)memcpy(&out_bytes[o], body->operation_id, 16u);
    o += 16u;
    ninlil_model_domain_encode_u16_be(&out_bytes[o], body->operation_kind);
    o += 2u;
    ninlil_model_domain_encode_u16_be(&out_bytes[o], body->reserved0);
    o += 2u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->ordered_sequence);
    o += 8u;
    (void)memcpy(&out_bytes[o], body->transaction_id, 16u);
    o += 16u;
    (void)memcpy(&out_bytes[o], body->event_id, 16u);
    o += 16u;
    (void)memcpy(&out_bytes[o], body->actor_id, 16u);
    o += 16u;
    (void)memcpy(
        &out_bytes[o], body->canonical_request_digest, 32u);
    o += 32u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->expected_spool_revision);
    o += 8u;
    (void)memcpy(&out_bytes[o], body->expected_event_id, 16u);
    o += 16u;
    ninlil_model_domain_encode_u16_be(
        &out_bytes[o], body->expected_content_digest_algorithm);
    o += 2u;
    ninlil_model_domain_encode_u16_be(&out_bytes[o], body->reserved1);
    o += 2u;
    (void)memcpy(&out_bytes[o], body->expected_content_digest, 32u);
    o += 32u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->request_reason);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->acknowledge_flag);
    o += 4u;
    ninlil_model_domain_encode_u16_be(&out_bytes[o], body->audit_length);
    o += 2u;
    ninlil_model_domain_encode_u16_be(&out_bytes[o], body->reserved2);
    o += 2u;
    (void)memcpy(
        &out_bytes[o], body->audit_bytes,
        NINLIL_MODEL_DOMAIN_MANAGEMENT_AUDIT_BYTES);
    o += NINLIL_MODEL_DOMAIN_MANAGEMENT_AUDIT_BYTES;
    (void)memcpy(&out_bytes[o], body->audit_clock_epoch, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->audit_committed_at_ms);
    o += 8u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->replay_result_kind);
    o += 4u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->replay_result_reason);
    o += 4u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->replay_retry_cycle_id);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->replay_spool_revision);
    o += 8u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->replay_spool_released);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->reserved3);
    o += 4u;
    if (o != NINLIL_MODEL_DOMAIN_BODY_MANAGEMENT_LEDGER_BYTES) {
        *out_length = 0u;
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = o;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_management_ledger(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_management_ledger_t *out_body)
{
    ninlil_model_domain_body_management_ledger_t tmp;
    uint32_t o = 0u;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length
            != NINLIL_MODEL_DOMAIN_BODY_MANAGEMENT_LEDGER_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    (void)memcpy(tmp.operation_id, &encoded.data[o], 16u);
    o += 16u;
    tmp.operation_kind =
        ninlil_model_domain_decode_u16_be(&encoded.data[o]);
    o += 2u;
    tmp.reserved0 = ninlil_model_domain_decode_u16_be(&encoded.data[o]);
    o += 2u;
    tmp.ordered_sequence =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    (void)memcpy(tmp.transaction_id, &encoded.data[o], 16u);
    o += 16u;
    (void)memcpy(tmp.event_id, &encoded.data[o], 16u);
    o += 16u;
    (void)memcpy(tmp.actor_id, &encoded.data[o], 16u);
    o += 16u;
    (void)memcpy(tmp.canonical_request_digest, &encoded.data[o], 32u);
    o += 32u;
    tmp.expected_spool_revision =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    (void)memcpy(tmp.expected_event_id, &encoded.data[o], 16u);
    o += 16u;
    tmp.expected_content_digest_algorithm =
        ninlil_model_domain_decode_u16_be(&encoded.data[o]);
    o += 2u;
    tmp.reserved1 = ninlil_model_domain_decode_u16_be(&encoded.data[o]);
    o += 2u;
    (void)memcpy(tmp.expected_content_digest, &encoded.data[o], 32u);
    o += 32u;
    tmp.request_reason =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.acknowledge_flag =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.audit_length =
        ninlil_model_domain_decode_u16_be(&encoded.data[o]);
    o += 2u;
    tmp.reserved2 = ninlil_model_domain_decode_u16_be(&encoded.data[o]);
    o += 2u;
    (void)memcpy(
        tmp.audit_bytes, &encoded.data[o],
        NINLIL_MODEL_DOMAIN_MANAGEMENT_AUDIT_BYTES);
    o += NINLIL_MODEL_DOMAIN_MANAGEMENT_AUDIT_BYTES;
    (void)memcpy(tmp.audit_clock_epoch, &encoded.data[o], 16u);
    o += 16u;
    tmp.audit_committed_at_ms =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.replay_result_kind =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.replay_result_reason =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.replay_retry_cycle_id =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.replay_spool_revision =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.replay_spool_released =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.reserved3 = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;

    if (o != NINLIL_MODEL_DOMAIN_BODY_MANAGEMENT_LEDGER_BYTES
        || !management_ledger_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- RETENTION_BASIS (0x61) docs17 §8.6 D1-B3n --- */

static int retention_subject_kind_is_known(uint16_t subject_kind)
{
    return subject_kind
            == NINLIL_MODEL_DOMAIN_RETENTION_SUBJECT_TRANSACTION
        || subject_kind
            == NINLIL_MODEL_DOMAIN_RETENTION_SUBJECT_DELIVERY;
}

static int retention_subject_raw_is_valid(
    uint16_t subject_kind, uint16_t len, const uint8_t *raw)
{
    if (raw == NULL && len != 0u) {
        return 0;
    }
    if (subject_kind
        == NINLIL_MODEL_DOMAIN_RETENTION_SUBJECT_TRANSACTION) {
        return len == NINLIL_MODEL_DOMAIN_RETENTION_SUBJECT_KEY_TX_BYTES
            && raw != NULL && !id_is_zero(raw);
    }
    if (subject_kind
        == NINLIL_MODEL_DOMAIN_RETENTION_SUBJECT_DELIVERY) {
        return reservation_owner_raw_is_valid(
            NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_DELIVERY, len, raw);
    }
    return 0;
}

/*
 * subject_primary_key_digest = KEY_DIGEST(complete primary key).
 * TX: family6 subtype 0x20 ID128 identity = raw exact 16.
 * DELIVERY: family6 subtype 0x40 COMPOSITE(40, delivery_key_raw:RAW16).
 * Bare composite digest is not stored or compared.
 */
static int retention_primary_key_digest_ok(
    uint16_t subject_kind,
    uint16_t subject_key_raw_length,
    const uint8_t *subject_key_raw,
    const uint8_t actual[NINLIL_MODEL_DOMAIN_DIGEST_BYTES])
{
    uint8_t raw16[2u + NINLIL_MODEL_DOMAIN_RAW16_RETENTION_SUBJECT_KEY_MAX];
    ninlil_bytes_view_t components;
    uint32_t raw16_len = 0u;

    if (actual == NULL || subject_key_raw == NULL) {
        return 0;
    }
    if (subject_kind
        == NINLIL_MODEL_DOMAIN_RETENTION_SUBJECT_TRANSACTION) {
        if (subject_key_raw_length != 16u) {
            return 0;
        }
        return digest_eq_complete_key(
            actual,
            NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
            NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR,
            NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
            subject_key_raw,
            16u);
    }
    if (subject_kind
        == NINLIL_MODEL_DOMAIN_RETENTION_SUBJECT_DELIVERY) {
        if (!encode_raw16_into(
                subject_key_raw_length, subject_key_raw, raw16,
                sizeof(raw16), &raw16_len)) {
            return 0;
        }
        components.data = raw16;
        components.length = raw16_len;
        return digest_eq_composite_key(
            actual, NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY, components);
    }
    return 0;
}

/*
 * Closed retention field matrix (docs17 §8.6):
 * ACTIVE pending: pending1 overflow0 window>0 epoch/time/delete all-zero
 * ACTIVE overflow: pending0 overflow1 window>0 epoch NZ, basis_at 0 ok, delete0
 * ACTIVE trusted / ELIGIBLE / CLEANUP_COMMITTED: pending0 overflow0,
 *   epoch NZ, window>0, delete=checked(basis_at+window); basis_at 0 legal.
 * bool flags exact 0/1; addition overflow invalid.
 */
static int retention_basis_matrix_ok(
    const ninlil_model_domain_body_retention_basis_t *body)
{
    int epoch_zero;
    int epoch_nz;
    uint64_t sum;

    if (body == NULL) {
        return 0;
    }
    if (body->basis_pending > 1u || body->retention_overflow > 1u) {
        return 0;
    }
    if (body->required_window_ms == 0u) {
        return 0;
    }
    epoch_zero = id_is_zero(body->basis_clock_epoch);
    epoch_nz = !epoch_zero;

    if (body->retention_state
        == NINLIL_MODEL_DOMAIN_RETENTION_STATE_ACTIVE) {
        if (body->basis_pending == 1u && body->retention_overflow == 0u) {
            return epoch_zero && body->basis_at_ms == 0u
                && body->exclusive_cleanup_at_ms == 0u;
        }
        if (body->basis_pending == 0u && body->retention_overflow == 1u) {
            return epoch_nz && body->exclusive_cleanup_at_ms == 0u;
        }
        if (body->basis_pending == 0u && body->retention_overflow == 0u) {
            if (!epoch_nz) {
                return 0;
            }
            /* checked basis_at + window; overflow invalid. */
            if (body->basis_at_ms
                > UINT64_MAX - body->required_window_ms) {
                return 0;
            }
            sum = body->basis_at_ms + body->required_window_ms;
            return body->exclusive_cleanup_at_ms == sum;
        }
        return 0;
    }
    if (body->retention_state
            == NINLIL_MODEL_DOMAIN_RETENTION_STATE_ELIGIBLE
        || body->retention_state
            == NINLIL_MODEL_DOMAIN_RETENTION_STATE_CLEANUP_COMMITTED) {
        if (body->basis_pending != 0u || body->retention_overflow != 0u
            || !epoch_nz) {
            return 0;
        }
        if (body->basis_at_ms
            > UINT64_MAX - body->required_window_ms) {
            return 0;
        }
        sum = body->basis_at_ms + body->required_window_ms;
        return body->exclusive_cleanup_at_ms == sum;
    }
    return 0;
}

static int retention_basis_fields_ok(
    const ninlil_model_domain_body_retention_basis_t *body)
{
    if (body == NULL || body->reserved != 0u
        || !retention_subject_kind_is_known(body->subject_kind)
        || !retention_subject_raw_is_valid(
               body->subject_kind, body->subject_key_raw_length,
               body->subject_key_raw)
        || !retention_primary_key_digest_ok(
               body->subject_kind, body->subject_key_raw_length,
               body->subject_key_raw, body->subject_primary_key_digest)) {
        return 0;
    }
    return retention_basis_matrix_ok(body);
}

uint32_t ninlil_model_domain_body_retention_basis_encoded_length(
    const ninlil_model_domain_body_retention_basis_t *body)
{
    uint32_t n;

    if (body == NULL || !retention_basis_fields_ok(body)) {
        return 0u;
    }
    /* fixed 90 includes RAW16 length prefix; contents add N. */
    n = NINLIL_MODEL_DOMAIN_BODY_RETENTION_BASIS_FIXED
        + (uint32_t)body->subject_key_raw_length;
    if (n > NINLIL_MODEL_DOMAIN_BODY_RETENTION_BASIS_MAX) {
        return 0u;
    }
    return n;
}

ninlil_status_t ninlil_model_domain_encode_body_retention_basis(
    const ninlil_model_domain_body_retention_basis_t *body,
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
        if (body->subject_key_raw != NULL
            && body->subject_key_raw_length != 0u) {
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
    required = ninlil_model_domain_body_retention_basis_encoded_length(body);
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || required == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    ninlil_model_domain_encode_u16_be(&out_bytes[0], body->subject_kind);
    ninlil_model_domain_encode_u16_be(&out_bytes[2], body->reserved);
    o = 4u;
    o += encode_raw16(
        &out_bytes[o], body->subject_key_raw_length, body->subject_key_raw);
    (void)memcpy(&out_bytes[o], body->subject_primary_key_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->basis_clock_epoch, 16u);
    o += 16u;
    ninlil_model_domain_encode_u64_be(&out_bytes[o], body->basis_at_ms);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->exclusive_cleanup_at_ms);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->required_window_ms);
    o += 8u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->retention_state);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->basis_pending);
    o += 4u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->retention_overflow);
    o += 4u;
    if (o != required) {
        *out_length = 0u;
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = o;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_retention_basis(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_retention_basis_t *out_body)
{
    ninlil_model_domain_body_retention_basis_t tmp;
    uint32_t o = 0u;
    uint32_t c = 0u;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length < 4u + 2u
        || encoded.length > NINLIL_MODEL_DOMAIN_BODY_RETENTION_BASIS_MAX) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.subject_kind = ninlil_model_domain_decode_u16_be(&encoded.data[0]);
    tmp.reserved = ninlil_model_domain_decode_u16_be(&encoded.data[2]);
    o = 4u;
    if (!decode_raw16_view(
            encoded.data + o, encoded.length - o,
            (uint16_t)NINLIL_MODEL_DOMAIN_RAW16_RETENTION_SUBJECT_KEY_MAX,
            &tmp.subject_key_raw_length, &tmp.subject_key_raw, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += c;
    /* After RAW16: 32+16+8+8+8+4+4+4 = 84 */
    if (encoded.length - o < 84u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(tmp.subject_primary_key_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.basis_clock_epoch, &encoded.data[o], 16u);
    o += 16u;
    tmp.basis_at_ms = ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.exclusive_cleanup_at_ms =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.required_window_ms =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.retention_state =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.basis_pending =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.retention_overflow =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    if (o != encoded.length || !retention_basis_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- CLEANUP_PLAN (0x63) docs17 §8.6 D1-B3o --- */

static int cleanup_subject_kind_is_known(uint16_t subject_kind)
{
    return subject_kind
            == NINLIL_MODEL_DOMAIN_CLEANUP_SUBJECT_TRANSACTION
        || subject_kind
            == NINLIL_MODEL_DOMAIN_CLEANUP_SUBJECT_DELIVERY;
}

static int cleanup_phase_is_known(uint16_t phase)
{
    return phase == NINLIL_MODEL_DOMAIN_CLEANUP_PHASE_DELETE_NON_INDEX
        || phase == NINLIL_MODEL_DOMAIN_CLEANUP_PHASE_DELETE_ATTEMPT_INDEX
        || phase == NINLIL_MODEL_DOMAIN_CLEANUP_PHASE_FINALIZE;
}

static int cleanup_subject_raw_is_valid(
    uint16_t subject_kind, uint16_t len, const uint8_t *raw)
{
    if (raw == NULL && len != 0u) {
        return 0;
    }
    if (subject_kind
        == NINLIL_MODEL_DOMAIN_CLEANUP_SUBJECT_TRANSACTION) {
        return len == NINLIL_MODEL_DOMAIN_CLEANUP_SUBJECT_KEY_TX_BYTES
            && raw != NULL && !id_is_zero(raw);
    }
    if (subject_kind
        == NINLIL_MODEL_DOMAIN_CLEANUP_SUBJECT_DELIVERY) {
        return reservation_owner_raw_is_valid(
            NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_DELIVERY, len, raw);
    }
    return 0;
}

/*
 * subject_primary_key_digest = KEY_DIGEST(complete primary key).
 * TX: family6 subtype 0x20 ID128 identity = raw exact 16.
 * DELIVERY: family6 subtype 0x40 COMPOSITE(40, delivery_key_raw:RAW16).
 * Bare composite digest is not stored or compared.
 */
static int cleanup_primary_key_digest_ok(
    uint16_t subject_kind,
    uint16_t subject_key_raw_length,
    const uint8_t *subject_key_raw,
    const uint8_t actual[NINLIL_MODEL_DOMAIN_DIGEST_BYTES])
{
    uint8_t raw16[2u + NINLIL_MODEL_DOMAIN_RAW16_CLEANUP_SUBJECT_KEY_MAX];
    ninlil_bytes_view_t components;
    uint32_t raw16_len = 0u;

    if (actual == NULL || subject_key_raw == NULL) {
        return 0;
    }
    if (subject_kind
        == NINLIL_MODEL_DOMAIN_CLEANUP_SUBJECT_TRANSACTION) {
        if (subject_key_raw_length != 16u) {
            return 0;
        }
        return digest_eq_complete_key(
            actual,
            NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
            NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR,
            NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
            subject_key_raw,
            16u);
    }
    if (subject_kind
        == NINLIL_MODEL_DOMAIN_CLEANUP_SUBJECT_DELIVERY) {
        if (!encode_raw16_into(
                subject_key_raw_length, subject_key_raw, raw16,
                sizeof(raw16), &raw16_len)) {
            return 0;
        }
        components.data = raw16;
        components.length = raw16_len;
        return digest_eq_composite_key(
            actual, NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY, components);
    }
    return 0;
}

/*
 * Closed cleanup phase/count matrix (docs17 §8.6 D1-B3o):
 * common: initial_attempt >= initial_index;
 *         remaining_attempt <= initial_attempt;
 *         remaining_index <= initial_index;
 *         cleanup_generation/batch_generation >= 1;
 *         fenced is 0 or 1 only.
 * phase1: remaining_attempt >= remaining_index,
 *         remaining_index == initial_index, fenced=0
 * phase2: remaining_attempt == remaining_index && >=1, fenced=1,
 *         initial_index >= 1
 * phase3: both remaining 0; fenced=1 iff initial_index > 0 else 0
 * Live counts/basis/fence aggregate/writer +1 are D3.
 */
static int cleanup_plan_matrix_ok(
    const ninlil_model_domain_body_cleanup_plan_t *body)
{
    if (body == NULL) {
        return 0;
    }
    if (body->cleanup_generation < 1u || body->batch_generation < 1u) {
        return 0;
    }
    if (body->initial_attempt_count < body->initial_attempt_index_count) {
        return 0;
    }
    if (body->remaining_attempt_count > body->initial_attempt_count) {
        return 0;
    }
    if (body->remaining_attempt_index_count
        > body->initial_attempt_index_count) {
        return 0;
    }
    if (body->attempt_reuse_fenced > 1u || body->reserved != 0u) {
        return 0;
    }
    if (body->cleanup_phase
        == NINLIL_MODEL_DOMAIN_CLEANUP_PHASE_DELETE_NON_INDEX) {
        return body->remaining_attempt_count
                >= body->remaining_attempt_index_count
            && body->remaining_attempt_index_count
                == body->initial_attempt_index_count
            && body->attempt_reuse_fenced == 0u;
    }
    if (body->cleanup_phase
        == NINLIL_MODEL_DOMAIN_CLEANUP_PHASE_DELETE_ATTEMPT_INDEX) {
        return body->remaining_attempt_count
                == body->remaining_attempt_index_count
            && body->remaining_attempt_count >= 1u
            && body->attempt_reuse_fenced == 1u
            && body->initial_attempt_index_count >= 1u;
    }
    if (body->cleanup_phase
        == NINLIL_MODEL_DOMAIN_CLEANUP_PHASE_FINALIZE) {
        if (body->remaining_attempt_count != 0u
            || body->remaining_attempt_index_count != 0u) {
            return 0;
        }
        if (body->initial_attempt_index_count > 0u) {
            return body->attempt_reuse_fenced == 1u;
        }
        return body->attempt_reuse_fenced == 0u;
    }
    return 0;
}

static int cleanup_plan_fields_ok(
    const ninlil_model_domain_body_cleanup_plan_t *body)
{
    if (body == NULL || body->reserved != 0u
        || !cleanup_subject_kind_is_known(body->subject_kind)
        || !cleanup_phase_is_known(body->cleanup_phase)
        || !cleanup_subject_raw_is_valid(
               body->subject_kind, body->subject_key_raw_length,
               body->subject_key_raw)
        || !cleanup_primary_key_digest_ok(
               body->subject_kind, body->subject_key_raw_length,
               body->subject_key_raw, body->subject_primary_key_digest)
        || digest_is_zero(body->subject_primary_value_digest)) {
        return 0;
    }
    return cleanup_plan_matrix_ok(body);
}

uint32_t ninlil_model_domain_body_cleanup_plan_encoded_length(
    const ninlil_model_domain_body_cleanup_plan_t *body)
{
    uint32_t n;

    if (body == NULL || !cleanup_plan_fields_ok(body)) {
        return 0u;
    }
    /* fixed 126 includes RAW16 length prefix; contents add N. */
    n = NINLIL_MODEL_DOMAIN_BODY_CLEANUP_PLAN_FIXED
        + (uint32_t)body->subject_key_raw_length;
    if (n > NINLIL_MODEL_DOMAIN_BODY_CLEANUP_PLAN_MAX) {
        return 0u;
    }
    return n;
}

ninlil_status_t ninlil_model_domain_encode_body_cleanup_plan(
    const ninlil_model_domain_body_cleanup_plan_t *body,
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
        if (body->subject_key_raw != NULL
            && body->subject_key_raw_length != 0u) {
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
    required = ninlil_model_domain_body_cleanup_plan_encoded_length(body);
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || required == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    ninlil_model_domain_encode_u16_be(&out_bytes[0], body->subject_kind);
    ninlil_model_domain_encode_u16_be(&out_bytes[2], body->cleanup_phase);
    o = 4u;
    o += encode_raw16(
        &out_bytes[o], body->subject_key_raw_length, body->subject_key_raw);
    (void)memcpy(&out_bytes[o], body->subject_primary_key_digest, 32u);
    o += 32u;
    (void)memcpy(&out_bytes[o], body->subject_primary_value_digest, 32u);
    o += 32u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->cleanup_generation);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->batch_generation);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->initial_attempt_count);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->remaining_attempt_count);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->initial_attempt_index_count);
    o += 8u;
    ninlil_model_domain_encode_u64_be(
        &out_bytes[o], body->remaining_attempt_index_count);
    o += 8u;
    ninlil_model_domain_encode_u32_be(
        &out_bytes[o], body->attempt_reuse_fenced);
    o += 4u;
    ninlil_model_domain_encode_u32_be(&out_bytes[o], body->reserved);
    o += 4u;
    if (o != required) {
        *out_length = 0u;
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = o;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_cleanup_plan(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_cleanup_plan_t *out_body)
{
    ninlil_model_domain_body_cleanup_plan_t tmp;
    uint32_t o = 0u;
    uint32_t c = 0u;

    if (!decode_body_ranges_ok(encoded, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length < 4u + 2u
        || encoded.length > NINLIL_MODEL_DOMAIN_BODY_CLEANUP_PLAN_MAX) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.subject_kind = ninlil_model_domain_decode_u16_be(&encoded.data[0]);
    tmp.cleanup_phase = ninlil_model_domain_decode_u16_be(&encoded.data[2]);
    o = 4u;
    if (!decode_raw16_view(
            encoded.data + o, encoded.length - o,
            (uint16_t)NINLIL_MODEL_DOMAIN_RAW16_CLEANUP_SUBJECT_KEY_MAX,
            &tmp.subject_key_raw_length, &tmp.subject_key_raw, &c)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    o += c;
    /* After RAW16: 32+32+8*6+4+4 = 120 */
    if (encoded.length - o < 120u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(tmp.subject_primary_key_digest, &encoded.data[o], 32u);
    o += 32u;
    (void)memcpy(tmp.subject_primary_value_digest, &encoded.data[o], 32u);
    o += 32u;
    tmp.cleanup_generation =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.batch_generation =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.initial_attempt_count =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.remaining_attempt_count =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.initial_attempt_index_count =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.remaining_attempt_index_count =
        ninlil_model_domain_decode_u64_be(&encoded.data[o]);
    o += 8u;
    tmp.attempt_reuse_fenced =
        ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    tmp.reserved = ninlil_model_domain_decode_u32_be(&encoded.data[o]);
    o += 4u;
    if (o != encoded.length || !cleanup_plan_fields_ok(&tmp)) {
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
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_CANCEL_STATE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVIDENCE_CELL:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_SPOOL:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RETRY_SUMMARY:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_MANAGEMENT_LEDGER:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RETENTION_BASIS:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_CLEANUP_PLAN:
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
        || env->header.record_revision == 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    /* BLOB flags are exact one of manifest/chunk; all other subtypes flags=0. */
    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB) {
        if (env->header.flags != NINLIL_MODEL_DOMAIN_FLAG_BLOB_MANIFEST
            && env->header.flags != NINLIL_MODEL_DOMAIN_FLAG_BLOB_CHUNK) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
    } else if (env->header.flags != 0u) {
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

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS) {
        uint8_t seq_be[8];
        uint8_t expect_pid[NINLIL_MODEL_DOMAIN_ID_BYTES];

        status = ninlil_model_domain_decode_body_ordered_ingress(
            env->body, &out->ordered_ingress);
        if (status != NINLIL_OK) {
            return status;
        }
        /*
         * Immutable primary (docs17 §8.3 / §9):
         * - key u64 identity == ordered_sequence BE8
         * - common primary_id = left-zero-pad(BE8)
         * - revision 1, flags 0, PVD zero, head non-zero
         * D3 deferred (not proven here): live owner/SCHEDULER/RESERVATION/BLOB
         * presence and 0/1 cardinality, BLOB stream recompute when digests
         * non-zero, owner transfer, reduction erase, namespace counters,
         * SERVICE supported-mask vs receipt_stage. B3b does not invent BLOB
         * keys from body fields alone.
         */
        if (env->header.record_revision != 1u
            || key->identity_kind != NINLIL_MODEL_DOMAIN_ID_KIND_U64
            || key->identity_length != 8u || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        ninlil_model_domain_encode_u64_be(
            seq_be, out->ordered_ingress.ordered_sequence);
        if (memcmp(key->identity, seq_be, 8u) != 0) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        (void)memset(expect_pid, 0, NINLIL_MODEL_DOMAIN_ID_BYTES);
        (void)memcpy(&expect_pid[8], seq_be, 8u);
        if (!header_primary_id_eq(env, expect_pid)
            || digest_is_zero(env->header.head_witness_digest)
            || !digest_is_zero(env->header.primary_value_digest)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB) {
        uint8_t expect_pid[NINLIL_MODEL_DOMAIN_ID_BYTES];
        uint8_t components[1u + 32u + 4u];
        ninlil_bytes_view_t cv;

        /*
         * BLOB same-record (docs17 §8.3):
         * - flags exact 1=manifest / 2=chunk matching body variant
         * - immutable revision 1; head and PVD non-zero
         * - key COMPOSITE(30, u8=1|2 || blob_id [|| index])
         * - primary_id: owner identity (manifest) or manifest composite
         *   first 16 (chunk)
         * D3 deferred: live owner/manifest get, PVD live value equality,
         * chunk 0..count-1 enumeration, multi-chunk stream, owner semantic
         * content match, manifest alias, lifecycle erase/capacity.
         */
        if (env->header.record_revision != 1u
            || digest_is_zero(env->header.head_witness_digest)
            || digest_is_zero(env->header.primary_value_digest)
            || key->identity_kind
                != NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE
            || key->identity_length != 32u || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }

        if (env->header.flags == NINLIL_MODEL_DOMAIN_FLAG_BLOB_MANIFEST) {
            status = ninlil_model_domain_decode_body_blob_manifest(
                env->body, &out->blob_manifest);
            if (status != NINLIL_OK) {
                return status;
            }
            components[0] = 1u;
            (void)memcpy(
                &components[1], out->blob_manifest.blob_id_digest, 32u);
            cv.data = components;
            cv.length = 33u;
            if (!composite_identity_matches(
                    NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB, cv, key->identity,
                    key->identity_length)) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            switch (out->blob_manifest.blob_owner_kind) {
            case NINLIL_MODEL_DOMAIN_BLOB_OWNER_TRANSACTION:
                if (out->blob_manifest.owner_key_raw_length != 16u
                    || out->blob_manifest.owner_key_raw == NULL) {
                    return NINLIL_E_STORAGE_CORRUPT;
                }
                (void)memcpy(
                    expect_pid, out->blob_manifest.owner_key_raw, 16u);
                break;
            case NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS:
                if (out->blob_manifest.owner_key_raw_length != 8u
                    || out->blob_manifest.owner_key_raw == NULL) {
                    return NINLIL_E_STORAGE_CORRUPT;
                }
                (void)memset(expect_pid, 0, NINLIL_MODEL_DOMAIN_ID_BYTES);
                (void)memcpy(
                    &expect_pid[8], out->blob_manifest.owner_key_raw, 8u);
                break;
            case NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY:
                if (primary_id_from_raw_contents_as_raw16(
                        NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
                        out->blob_manifest.owner_key_raw_length,
                        out->blob_manifest.owner_key_raw, expect_pid)
                    != NINLIL_OK) {
                    return NINLIL_E_STORAGE_CORRUPT;
                }
                break;
            default:
                return NINLIL_E_STORAGE_CORRUPT;
            }
            if (!header_primary_id_eq(env, expect_pid)) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            return NINLIL_OK;
        }

        if (env->header.flags == NINLIL_MODEL_DOMAIN_FLAG_BLOB_CHUNK) {
            status = ninlil_model_domain_decode_body_blob_chunk(
                env->body, &out->blob_chunk);
            if (status != NINLIL_OK) {
                return status;
            }
            components[0] = 2u;
            (void)memcpy(&components[1], out->blob_chunk.blob_id_digest, 32u);
            ninlil_model_domain_encode_u32_be(
                &components[33], out->blob_chunk.chunk_index);
            cv.data = components;
            cv.length = 37u;
            if (!composite_identity_matches(
                    NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB, cv, key->identity,
                    key->identity_length)) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            /* primary_id = manifest composite identity first 16 */
            components[0] = 1u;
            (void)memcpy(&components[1], out->blob_chunk.blob_id_digest, 32u);
            cv.data = components;
            cv.length = 33u;
            if (primary_id_from_composite_components(
                    NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB, cv, expect_pid)
                    != NINLIL_OK
                || !header_primary_id_eq(env, expect_pid)) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            return NINLIL_OK;
        }

        return NINLIL_E_STORAGE_CORRUPT;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT) {
        uint8_t expect_pid[NINLIL_MODEL_DOMAIN_ID_BYTES];
        uint8_t components[2u + 2u + 128u + 16u];
        ninlil_bytes_view_t cv;
        uint32_t o;

        /*
         * ATTEMPT same-record (docs17 §8.3):
         * - flags 0; revision >= 1; head and PVD non-zero
         * - key COMPOSITE(31, owner_kind:u16 || owner_key_raw:RAW16 ||
         *   attempt_id[16])
         * - primary_id: transaction_id (TX) or DELIVERY composite first 16
         * D3 deferred: live owner, ATTEMPT_ID_INDEX, CANCEL_STATE gate,
         * family kind, current/stale, PVD live equality, target/semantic
         * recompute, SEND_COUNTER health/cardinality.
         */
        if (env->header.record_revision < 1u
            || digest_is_zero(env->header.head_witness_digest)
            || digest_is_zero(env->header.primary_value_digest)
            || key->identity_kind
                != NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE
            || key->identity_length != 32u || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        status = ninlil_model_domain_decode_body_attempt(
            env->body, &out->attempt);
        if (status != NINLIL_OK) {
            return status;
        }
        ninlil_model_domain_encode_u16_be(
            components, out->attempt.attempt_owner_kind);
        o = 2u;
        o += encode_raw16(
            &components[o], out->attempt.owner_key_raw_length,
            out->attempt.owner_key_raw);
        (void)memcpy(
            &components[o], out->attempt.attempt_id,
            NINLIL_MODEL_DOMAIN_ID_BYTES);
        o += NINLIL_MODEL_DOMAIN_ID_BYTES;
        cv.data = components;
        cv.length = o;
        if (!composite_identity_matches(
                NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT, cv, key->identity,
                key->identity_length)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (out->attempt.attempt_owner_kind
            == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION) {
            (void)memcpy(expect_pid, out->attempt.transaction_id, 16u);
        } else if (
            out->attempt.attempt_owner_kind
            == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_DELIVERY) {
            if (primary_id_from_raw_contents_as_raw16(
                    NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
                    out->attempt.owner_key_raw_length,
                    out->attempt.owner_key_raw, expect_pid)
                != NINLIL_OK) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
        } else {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (!header_primary_id_eq(env, expect_pid)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX) {
        /*
         * ATTEMPT_ID_INDEX same-record (docs17 §8.4):
         * - flags 0; revision exact 1; head and PVD non-zero
         * - key direct ID128 equals body attempt_id
         * - primary_id equals body transaction_id
         * - body: nonzero ids/kind/reserved0/creation digest +
         *   attempt_record_key_digest = KEY_DIGEST(complete TX ATTEMPT key)
         * D3 deferred: live TRANSACTION_ANCHOR PVD; live/current ATTEMPT
         * binding; CREATE manifest new digest equality; local ATTEMPT/index
         * cardinality; DELIVERY/remote no-index; reverse reply no-index;
         * co-create witness; fenced pair cleanup/fence counts; family-kind
         * and CANCEL_STATE cross proofs. CANCEL_STATE 0x33 is out of B3e.
         */
        if (env->header.record_revision != 1u
            || digest_is_zero(env->header.head_witness_digest)
            || digest_is_zero(env->header.primary_value_digest)
            || key->identity_kind != NINLIL_MODEL_DOMAIN_ID_KIND_ID128
            || key->identity_length != 16u || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        status = ninlil_model_domain_decode_body_attempt_id_index(
            env->body, &out->attempt_id_index);
        if (status != NINLIL_OK) {
            return status;
        }
        if (memcmp(
                key->identity, out->attempt_id_index.attempt_id, 16u)
                != 0
            || !header_primary_id_eq(
                   env, out->attempt_id_index.transaction_id)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_CANCEL_STATE) {
        uint8_t expect_pid[NINLIL_MODEL_DOMAIN_ID_BYTES];
        uint8_t components[2u + 2u + 128u];
        ninlil_bytes_view_t cv;
        uint32_t o;

        /*
         * CANCEL_STATE same-record (docs17 §8.4):
         * - flags 0; revision >= 1; head and PVD non-zero
         * - key COMPOSITE(33, cancel_owner_kind:u16 || owner_key_raw:RAW16)
         * - primary_id: transaction_id (TX) or DELIVERY composite first 16
         * D3 deferred: live primary PVD; live CANCEL ATTEMPT/index/
         * cardinality; message recompute; RESULT/REVERSE_REPLY; prior
         * transition/gate history; timeout scheduling; family/owner/
         * cardinality/reply proofs.
         */
        if (env->header.record_revision < 1u
            || digest_is_zero(env->header.head_witness_digest)
            || digest_is_zero(env->header.primary_value_digest)
            || key->identity_kind
                != NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE
            || key->identity_length != 32u || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        status = ninlil_model_domain_decode_body_cancel_state(
            env->body, &out->cancel_state);
        if (status != NINLIL_OK) {
            return status;
        }
        ninlil_model_domain_encode_u16_be(
            components, out->cancel_state.cancel_owner_kind);
        o = 2u;
        o += encode_raw16(
            &components[o], out->cancel_state.owner_key_raw_length,
            out->cancel_state.owner_key_raw);
        cv.data = components;
        cv.length = o;
        if (!composite_identity_matches(
                NINLIL_MODEL_DOMAIN_SUBTYPE_CANCEL_STATE, cv, key->identity,
                key->identity_length)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (out->cancel_state.cancel_owner_kind
            == NINLIL_MODEL_DOMAIN_CANCEL_OWNER_TRANSACTION) {
            (void)memcpy(expect_pid, out->cancel_state.transaction_id, 16u);
        } else if (
            out->cancel_state.cancel_owner_kind
            == NINLIL_MODEL_DOMAIN_CANCEL_OWNER_DELIVERY) {
            if (primary_id_from_raw_contents_as_raw16(
                    NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
                    out->cancel_state.owner_key_raw_length,
                    out->cancel_state.owner_key_raw, expect_pid)
                != NINLIL_OK) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
        } else {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (!header_primary_id_eq(env, expect_pid)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_EVIDENCE_CELL) {
        uint8_t expect_pid[NINLIL_MODEL_DOMAIN_ID_BYTES];
        uint8_t components[2u + 2u + 128u + 4u];
        ninlil_bytes_view_t cv;
        uint32_t o;

        /*
         * EVIDENCE_CELL same-record (docs17 §8.3):
         * - flags 0; revision >= 1; head and PVD non-zero
         * - key COMPOSITE(32, evidence_owner_kind:u16 || owner_key_raw:RAW16
         *   || slot_index:u32)
         * - primary_id: TX owner raw / DELIVERY composite first 16
         * D3 deferred: live primary PVD; live TARGET; exact L and L+1
         * cardinality/slot continuity; valid_material_count=M+overflow;
         * owner family/content/required_evidence/supported mask; STATE
         * projection; RESULT_CACHE key; used/reserved accounting; admission
         * headroom; CANCEL_FIRST EVIDENCE 0; deadline proof; retention erase.
         */
        if (env->header.record_revision < 1u
            || digest_is_zero(env->header.head_witness_digest)
            || digest_is_zero(env->header.primary_value_digest)
            || key->identity_kind
                != NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE
            || key->identity_length != 32u || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        status = ninlil_model_domain_decode_body_evidence_cell(
            env->body, &out->evidence_cell);
        if (status != NINLIL_OK) {
            return status;
        }
        ninlil_model_domain_encode_u16_be(
            components, out->evidence_cell.evidence_owner_kind);
        o = 2u;
        o += encode_raw16(
            &components[o], out->evidence_cell.owner_key_raw_length,
            out->evidence_cell.owner_key_raw);
        ninlil_model_domain_encode_u32_be(
            &components[o], out->evidence_cell.slot_index);
        o += 4u;
        cv.data = components;
        cv.length = o;
        if (!composite_identity_matches(
                NINLIL_MODEL_DOMAIN_SUBTYPE_EVIDENCE_CELL, cv, key->identity,
                key->identity_length)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (out->evidence_cell.evidence_owner_kind
            == NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_TRANSACTION) {
            if (out->evidence_cell.owner_key_raw_length != 16u
                || out->evidence_cell.owner_key_raw == NULL) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            (void)memcpy(
                expect_pid, out->evidence_cell.owner_key_raw, 16u);
        } else if (
            out->evidence_cell.evidence_owner_kind
            == NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_DELIVERY) {
            if (primary_id_from_raw_contents_as_raw16(
                    NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
                    out->evidence_cell.owner_key_raw_length,
                    out->evidence_cell.owner_key_raw, expect_pid)
                != NINLIL_OK) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
        } else {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (!header_primary_id_eq(env, expect_pid)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY) {
        uint8_t expect_pid[NINLIL_MODEL_DOMAIN_ID_BYTES];
        uint8_t components[2u + 128u];
        ninlil_bytes_view_t cv;
        uint32_t o;

        /*
         * DELIVERY same-record (docs17 §8.5 D1-B3h):
         * - immutable primary: revision=1, flags 0, head non-zero, PVD zero
         * - key COMPOSITE(40, delivery_key_raw:RAW16)
         * - primary_id = composite identity first 16
         * D3 deferred: live RESULT_CACHE / SCHEDULER / RESERVATION /
         * ATTEMPT / EVIDENCE / CANCEL / BLOB / attach / ABSENT / deadline
         * proof / retention. RESULT_CACHE body is next slice.
         */
        if (env->header.record_revision != 1u
            || env->header.flags != 0u
            || digest_is_zero(env->header.head_witness_digest)
            || !digest_is_zero(env->header.primary_value_digest)
            || key->identity_kind
                != NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE
            || key->identity_length != 32u || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        status = ninlil_model_domain_decode_body_delivery(
            env->body, &out->delivery);
        if (status != NINLIL_OK) {
            return status;
        }
        o = encode_raw16(
            components, out->delivery.delivery_key_raw_length,
            out->delivery.delivery_key_raw);
        cv.data = components;
        cv.length = o;
        if (!composite_identity_matches(
                NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY, cv, key->identity,
                key->identity_length)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (primary_id_from_raw_contents_as_raw16(
                NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
                out->delivery.delivery_key_raw_length,
                out->delivery.delivery_key_raw, expect_pid)
            != NINLIL_OK) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (!header_primary_id_eq(env, expect_pid)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE) {
        uint8_t expect_pid[NINLIL_MODEL_DOMAIN_ID_BYTES];
        uint8_t components[2u + 128u];
        ninlil_bytes_view_t cv;
        uint32_t o;

        /*
         * RESULT_CACHE same-record (docs17 §8.5 D1-B3i):
         * - mutable secondary: revision>=1, flags 0, head non-zero, PVD non-zero
         * - key COMPOSITE(41, delivery_key_raw:RAW16)
         * - primary_id = DELIVERY composite identity first 16
         * D3: live DELIVERY PVD / reply_count / ATTEMPT / CANCEL live.
         */
        if (env->header.record_revision < 1u
            || env->header.flags != 0u
            || digest_is_zero(env->header.head_witness_digest)
            || digest_is_zero(env->header.primary_value_digest)
            || key->identity_kind
                != NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE
            || key->identity_length != 32u || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        status = ninlil_model_domain_decode_body_result_cache(
            env->body, &out->result_cache);
        if (status != NINLIL_OK) {
            return status;
        }
        o = encode_raw16(
            components, out->result_cache.delivery_key_raw_length,
            out->result_cache.delivery_key_raw);
        cv.data = components;
        cv.length = o;
        if (!composite_identity_matches(
                NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE, cv, key->identity,
                key->identity_length)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (primary_id_from_raw_contents_as_raw16(
                NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
                out->result_cache.delivery_key_raw_length,
                out->result_cache.delivery_key_raw, expect_pid)
            != NINLIL_OK) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (!header_primary_id_eq(env, expect_pid)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY) {
        uint8_t expect_pid[NINLIL_MODEL_DOMAIN_ID_BYTES];
        uint8_t components[2u + 192u];
        ninlil_bytes_view_t cv;
        uint32_t o;

        /*
         * REVERSE_REPLY same-record (docs17 §8.5 D1-B3j):
         * - mutable secondary: revision>=1, flags 0, head non-zero, PVD non-zero
         * - key COMPOSITE(42, reply_key_raw:RAW16)
         * - primary_id = DELIVERY composite identity first 16
         * D3: live DELIVERY PVD / reply BLOB / RESULT reply_count / kind exact1.
         */
        if (env->header.record_revision < 1u
            || env->header.flags != 0u
            || digest_is_zero(env->header.head_witness_digest)
            || digest_is_zero(env->header.primary_value_digest)
            || key->identity_kind
                != NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE
            || key->identity_length != 32u || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        status = ninlil_model_domain_decode_body_reverse_reply(
            env->body, &out->reverse_reply);
        if (status != NINLIL_OK) {
            return status;
        }
        o = encode_raw16(
            components, out->reverse_reply.reply_key_raw_length,
            out->reverse_reply.reply_key_raw);
        cv.data = components;
        cv.length = o;
        if (!composite_identity_matches(
                NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY, cv, key->identity,
                key->identity_length)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (primary_id_from_raw_contents_as_raw16(
                NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
                out->reverse_reply.delivery_key_raw_length,
                out->reverse_reply.delivery_key_raw, expect_pid)
            != NINLIL_OK) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (!header_primary_id_eq(env, expect_pid)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_SPOOL) {
        /*
         * EVENT_SPOOL same-record (docs17 §8.6 D1-B3k):
         * - family 6 secondary: flags 0, head NZ, PVD NZ
         * - key ID128 == body transaction_id
         * - primary_id == body transaction_id
         * - record_revision == spool_revision >= 1
         * - body state×cause / resume / discard / reservation KEY_DIGEST
         * D3: live ANCHOR PVD / grant re-verify / BLOB cardinality.
         */
        if (env->header.flags != 0u
            || digest_is_zero(env->header.head_witness_digest)
            || digest_is_zero(env->header.primary_value_digest)
            || key->identity_kind != NINLIL_MODEL_DOMAIN_ID_KIND_ID128
            || key->identity_length != 16u || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        status = ninlil_model_domain_decode_body_event_spool(
            env->body, &out->event_spool);
        if (status != NINLIL_OK) {
            return status;
        }
        if (env->header.record_revision != out->event_spool.spool_revision
            || env->header.record_revision < 1u
            || memcmp(
                   key->identity, out->event_spool.transaction_id, 16u)
                != 0
            || !header_primary_id_eq(
                   env, out->event_spool.transaction_id)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_RETRY_SUMMARY) {
        uint8_t components[16u + 2u + 2u];
        ninlil_bytes_view_t cv;

        /*
         * RETRY_SUMMARY same-record (docs17 §8.6 D1-B3l):
         * - family 6 secondary: flags 0, head NZ, PVD NZ, revision >= 1
         * - key COMPOSITE(51, tx16||kind:u16||slot:u16) == body fields
         * - primary_id == body transaction_id
         * - body kind/slot/fold/bool/reserved closed above
         * D3: live ANCHOR PVD / cross-row fold cardinality.
         */
        if (env->header.record_revision < 1u
            || env->header.flags != 0u
            || digest_is_zero(env->header.head_witness_digest)
            || digest_is_zero(env->header.primary_value_digest)
            || key->identity_kind
                != NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE
            || key->identity_length != 32u || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        status = ninlil_model_domain_decode_body_retry_summary(
            env->body, &out->retry_summary);
        if (status != NINLIL_OK) {
            return status;
        }
        (void)memcpy(components, out->retry_summary.transaction_id, 16u);
        ninlil_model_domain_encode_u16_be(
            &components[16], out->retry_summary.summary_kind);
        ninlil_model_domain_encode_u16_be(
            &components[18], out->retry_summary.slot_index);
        cv.data = components;
        cv.length = 20u;
        if (!composite_identity_matches(
                NINLIL_MODEL_DOMAIN_SUBTYPE_RETRY_SUMMARY, cv, key->identity,
                key->identity_length)
            || !header_primary_id_eq(
                   env, out->retry_summary.transaction_id)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_MANAGEMENT_LEDGER) {
        uint8_t components[16u + 16u];
        ninlil_bytes_view_t cv;

        /*
         * MANAGEMENT_LEDGER same-record (docs17 §8.6 D1-B3m):
         * - family 6 secondary: flags 0, head NZ, PVD NZ
         * - immutable record_revision exact 1
         * - key COMPOSITE(52, tx16||op16) plain components (no RAW16)
         * - primary_id == body transaction_id
         * - body kind15/16 matrix + canonical digest recompute above
         * D3: live SPOOL/STATE/RESERVATION counters / sequence upper bound.
         */
        if (env->header.record_revision != 1u
            || env->header.flags != 0u
            || digest_is_zero(env->header.head_witness_digest)
            || digest_is_zero(env->header.primary_value_digest)
            || key->identity_kind
                != NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE
            || key->identity_length != 32u || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        status = ninlil_model_domain_decode_body_management_ledger(
            env->body, &out->management_ledger);
        if (status != NINLIL_OK) {
            return status;
        }
        (void)memcpy(
            components, out->management_ledger.transaction_id, 16u);
        (void)memcpy(
            &components[16], out->management_ledger.operation_id, 16u);
        cv.data = components;
        cv.length = 32u;
        if (!composite_identity_matches(
                NINLIL_MODEL_DOMAIN_SUBTYPE_MANAGEMENT_LEDGER, cv,
                key->identity, key->identity_length)
            || !header_primary_id_eq(
                   env, out->management_ledger.transaction_id)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_RETENTION_BASIS) {
        uint8_t expect_pid[NINLIL_MODEL_DOMAIN_ID_BYTES];
        /* kind:u16 + RAW16(max255) = 2 + 2 + 255 */
        uint8_t components[2u + 2u + 255u];
        ninlil_bytes_view_t cv;
        uint32_t o;

        /*
         * RETENTION_BASIS same-record (docs17 §8.6 D1-B3n):
         * - family 6 secondary: flags 0, revision >= 1, head NZ, PVD NZ
         * - key COMPOSITE(61, subject_kind:u16 || subject_key_raw:RAW16)
         * - primary_id: TX raw16 / DELIVERY COMPOSITE(40,RAW16 raw80) first 16
         * - body matrix + KEY_DIGEST recompute above
         * D3: live now / profile window / plan / live primary PVD.
         */
        if (env->header.record_revision < 1u
            || env->header.flags != 0u
            || digest_is_zero(env->header.head_witness_digest)
            || digest_is_zero(env->header.primary_value_digest)
            || key->identity_kind
                != NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE
            || key->identity_length != 32u || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        status = ninlil_model_domain_decode_body_retention_basis(
            env->body, &out->retention_basis);
        if (status != NINLIL_OK) {
            return status;
        }
        ninlil_model_domain_encode_u16_be(
            components, out->retention_basis.subject_kind);
        o = 2u;
        o += encode_raw16(
            &components[o], out->retention_basis.subject_key_raw_length,
            out->retention_basis.subject_key_raw);
        cv.data = components;
        cv.length = o;
        if (!composite_identity_matches(
                NINLIL_MODEL_DOMAIN_SUBTYPE_RETENTION_BASIS, cv,
                key->identity, key->identity_length)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (out->retention_basis.subject_kind
            == NINLIL_MODEL_DOMAIN_RETENTION_SUBJECT_TRANSACTION) {
            if (out->retention_basis.subject_key_raw_length != 16u
                || out->retention_basis.subject_key_raw == NULL) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            (void)memcpy(
                expect_pid, out->retention_basis.subject_key_raw, 16u);
        } else if (
            out->retention_basis.subject_kind
            == NINLIL_MODEL_DOMAIN_RETENTION_SUBJECT_DELIVERY) {
            if (primary_id_from_raw_contents_as_raw16(
                    NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
                    out->retention_basis.subject_key_raw_length,
                    out->retention_basis.subject_key_raw, expect_pid)
                != NINLIL_OK) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
        } else {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (!header_primary_id_eq(env, expect_pid)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_CLEANUP_PLAN) {
        uint8_t expect_pid[NINLIL_MODEL_DOMAIN_ID_BYTES];
        /* subject_kind:u16 || subject_primary_key_digest[32] */
        uint8_t components[2u + NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
        ninlil_bytes_view_t cv;

        /*
         * CLEANUP_PLAN same-record (docs17 §8.6 D1-B3o):
         * - family 6 secondary: flags 0, revision==batch_generation >=1,
         *   head NZ, PVD NZ
         * - key COMPOSITE(63, subject_kind:u16 || subject_primary_key_digest)
         * - primary_id: TX raw16 / DELIVERY COMPOSITE(40,RAW16 raw80) first 16
         * - subject_primary_value_digest == header primary_value_digest NZ
         * - body matrix + KEY_DIGEST recompute above
         * D3: live counts / basis / fence aggregate / writer +1.
         */
        if (env->header.record_revision < 1u
            || env->header.flags != 0u
            || digest_is_zero(env->header.head_witness_digest)
            || digest_is_zero(env->header.primary_value_digest)
            || key->identity_kind
                != NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE
            || key->identity_length != 32u || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        status = ninlil_model_domain_decode_body_cleanup_plan(
            env->body, &out->cleanup_plan);
        if (status != NINLIL_OK) {
            return status;
        }
        if (env->header.record_revision
                != out->cleanup_plan.batch_generation
            || memcmp(
                   out->cleanup_plan.subject_primary_value_digest,
                   env->header.primary_value_digest,
                   NINLIL_MODEL_DOMAIN_DIGEST_BYTES)
                != 0) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        ninlil_model_domain_encode_u16_be(
            components, out->cleanup_plan.subject_kind);
        (void)memcpy(
            &components[2], out->cleanup_plan.subject_primary_key_digest,
            NINLIL_MODEL_DOMAIN_DIGEST_BYTES);
        cv.data = components;
        cv.length = 2u + NINLIL_MODEL_DOMAIN_DIGEST_BYTES;
        if (!composite_identity_matches(
                NINLIL_MODEL_DOMAIN_SUBTYPE_CLEANUP_PLAN, cv,
                key->identity, key->identity_length)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (out->cleanup_plan.subject_kind
            == NINLIL_MODEL_DOMAIN_CLEANUP_SUBJECT_TRANSACTION) {
            if (out->cleanup_plan.subject_key_raw_length != 16u
                || out->cleanup_plan.subject_key_raw == NULL) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            (void)memcpy(
                expect_pid, out->cleanup_plan.subject_key_raw, 16u);
        } else if (
            out->cleanup_plan.subject_kind
            == NINLIL_MODEL_DOMAIN_CLEANUP_SUBJECT_DELIVERY) {
            if (primary_id_from_raw_contents_as_raw16(
                    NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
                    out->cleanup_plan.subject_key_raw_length,
                    out->cleanup_plan.subject_key_raw, expect_pid)
                != NINLIL_OK) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
        } else {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (!header_primary_id_eq(env, expect_pid)) {
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
