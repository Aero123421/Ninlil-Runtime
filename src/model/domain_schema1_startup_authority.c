/*
 * ADR-0022 private Domain schema1 startup authority (T1b–T7, kind-1, LAB).
 * Feature-gated. Not public ABI. No runtime_public integration.
 */

#include "domain_schema1_startup_authority.h"

#include "domain_store_body_codec.h"
#include "domain_store_codec.h"

#include <stdint.h>
#include <string.h>

#if !defined(NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING) \
    || (NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING == 0)
#error "domain_schema1_startup_authority.c requires NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=1"
#endif

static const uint8_t k_export_magic[8] = {
    'N', 'L', 'E', 'X', 'P', '0', '0', '1'
};

enum {
    k_meta_magic = NINLIL_DOMAIN_SCHEMA1_STARTUP_SEAL_MAGIC,
    k_bootstrap_members_start = 2u, /* after binding+identity */
    k_bootstrap_members_end = 17u
};

static uint32_t crc32c_bytes(const uint8_t *data, size_t length)
{
    uint32_t crc = 0xFFFFFFFFu;
    size_t i;
    unsigned int bit;
    for (i = 0u; i < length; ++i) {
        crc ^= data[i];
        for (bit = 0u; bit < 8u; ++bit) {
            uint32_t mask = (uint32_t)-(int32_t)(crc & 1u);
            crc = (crc >> 1) ^ (0x82F63B78u & mask);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

static int plan_bootstrap_sealed(
    const ninlil_domain_schema1_bootstrap_plan_t *plan)
{
    ninlil_domain_schema1_bootstrap_record_t rec;
    if (plan == NULL) {
        return 0;
    }
    /* Touch sealed path: record_at rejects unsealed/tampered plans. */
    if (ninlil_domain_schema1_bootstrap_record_at(plan, 0u, &rec) != NINLIL_OK) {
        return 0;
    }
    return plan->record_count == NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_RECORD_COUNT
        && plan->sealed_record_count
        == NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_RECORD_COUNT
        && plan->sealed_magic == NINLIL_DOMAIN_SCHEMA1_PLAN_SEAL_MAGIC;
}

static uint32_t metadata_plan_crc(
    const ninlil_domain_schema1_metadata_plan_t *plan)
{
    uint8_t buf[16];
    uint32_t o = 0u;
    buf[o++] = (uint8_t)(plan->sealed_bootstrap.sealed_crc32c >> 24);
    buf[o++] = (uint8_t)(plan->sealed_bootstrap.sealed_crc32c >> 16);
    buf[o++] = (uint8_t)(plan->sealed_bootstrap.sealed_crc32c >> 8);
    buf[o++] = (uint8_t)plan->sealed_bootstrap.sealed_crc32c;
    buf[o++] = (uint8_t)(plan->record_count >> 24);
    buf[o++] = (uint8_t)(plan->record_count >> 16);
    buf[o++] = (uint8_t)(plan->record_count >> 8);
    buf[o++] = (uint8_t)plan->record_count;
    buf[o++] = (uint8_t)(plan->sealed_magic >> 24);
    buf[o++] = (uint8_t)(plan->sealed_magic >> 16);
    buf[o++] = (uint8_t)(plan->sealed_magic >> 8);
    buf[o++] = (uint8_t)plan->sealed_magic;
    return crc32c_bytes(buf, o);
}

static int metadata_plan_is_sealed(
    const ninlil_domain_schema1_metadata_plan_t *plan)
{
    return plan != NULL
        && plan->sealed_magic == k_meta_magic
        && plan->record_count == NINLIL_DOMAIN_SCHEMA1_METADATA_RECORD_COUNT
        && plan->sealed_record_count
        == NINLIL_DOMAIN_SCHEMA1_METADATA_RECORD_COUNT
        && plan->sealed_crc32c == metadata_plan_crc(plan)
        && plan_bootstrap_sealed(&plan->sealed_bootstrap);
}

static ninlil_status_t encode_clock_uninitialized(
    ninlil_domain_schema1_metadata_record_t *out)
{
    ninlil_model_domain_key_t key;
    ninlil_model_domain_common_header_t header;
    ninlil_model_domain_body_clock_baseline_t body;
    uint8_t body_bytes[NINLIL_MODEL_DOMAIN_BODY_CLOCK_BASELINE_BYTES];
    uint32_t body_len = 0u;
    uint32_t value_len = 0u;
    ninlil_status_t st;
    ninlil_bytes_view_t empty = {NULL, 0u};

    (void)memset(out, 0, sizeof(*out));
    st = ninlil_model_domain_build_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE,
        NINLIL_MODEL_DOMAIN_ID_KIND_SINGLETON,
        empty,
        &key);
    if (st != NINLIL_OK) {
        return st;
    }
    (void)memset(&body, 0, sizeof(body));
    body.baseline_state =
        NINLIL_MODEL_DOMAIN_BASELINE_STATE_UNINITIALIZED;
    st = ninlil_model_domain_encode_body_clock_baseline(
        &body, body_bytes, sizeof(body_bytes), &body_len);
    if (st != NINLIL_OK) {
        return st;
    }
    (void)memset(&header, 0, sizeof(header));
    header.domain_format = 1u;
    header.subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE;
    header.flags = 0u;
    header.record_revision = 1u;
    header.body_length = body_len;
    st = ninlil_model_domain_encode_envelope(
        6u,
        &header,
        (ninlil_bytes_view_t){body_bytes, body_len},
        out->value,
        sizeof(out->value),
        &value_len);
    if (st != NINLIL_OK) {
        return st;
    }
    if (key.length > sizeof(out->key)) {
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    (void)memcpy(out->key, key.bytes, key.length);
    out->key_length = key.length;
    out->value_length = value_len;
    return NINLIL_OK;
}

static ninlil_status_t encode_clock_trusted(
    const uint8_t epoch[16],
    uint64_t now_ms,
    uint64_t publish_generation,
    ninlil_domain_schema1_metadata_record_t *out)
{
    ninlil_model_domain_key_t key;
    ninlil_model_domain_common_header_t header;
    ninlil_model_domain_body_clock_baseline_t body;
    uint8_t body_bytes[NINLIL_MODEL_DOMAIN_BODY_CLOCK_BASELINE_BYTES];
    uint32_t body_len = 0u;
    uint32_t value_len = 0u;
    ninlil_status_t st;
    ninlil_bytes_view_t empty = {NULL, 0u};

    if (epoch == NULL || out == NULL || publish_generation == 0u
        || publish_generation == UINT64_MAX) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out, 0, sizeof(*out));
    st = ninlil_model_domain_build_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE,
        NINLIL_MODEL_DOMAIN_ID_KIND_SINGLETON,
        empty,
        &key);
    if (st != NINLIL_OK) {
        return st;
    }
    (void)memset(&body, 0, sizeof(body));
    body.baseline_state = NINLIL_MODEL_DOMAIN_BASELINE_STATE_TRUSTED;
    (void)memcpy(body.trusted_clock_epoch, epoch, 16u);
    body.last_trusted_now_ms = now_ms;
    body.publish_generation = publish_generation;
    st = ninlil_model_domain_encode_body_clock_baseline(
        &body, body_bytes, sizeof(body_bytes), &body_len);
    if (st != NINLIL_OK) {
        return st;
    }
    (void)memset(&header, 0, sizeof(header));
    header.domain_format = 1u;
    header.subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE;
    header.flags = 0u;
    header.record_revision = publish_generation + 1u;
    header.body_length = body_len;
    st = ninlil_model_domain_encode_envelope(
        6u,
        &header,
        (ninlil_bytes_view_t){body_bytes, body_len},
        out->value,
        sizeof(out->value),
        &value_len);
    if (st != NINLIL_OK) {
        return st;
    }
    (void)memcpy(out->key, key.bytes, key.length);
    out->key_length = key.length;
    out->value_length = value_len;
    return NINLIL_OK;
}

static ninlil_status_t encode_head_index(
    const ninlil_domain_schema1_bootstrap_record_t *member,
    ninlil_domain_schema1_metadata_record_t *out)
{
    ninlil_model_domain_digest_t key_dig;
    ninlil_model_domain_digest_t composite;
    ninlil_model_domain_digest_t value_dig;
    ninlil_model_domain_key_t key;
    ninlil_model_domain_common_header_t header;
    ninlil_model_domain_body_witness_head_index_t body;
    uint8_t body_bytes[NINLIL_MODEL_DOMAIN_BODY_WITNESS_HEAD_INDEX_BYTES];
    uint32_t body_len = 0u;
    uint32_t value_len = 0u;
    ninlil_status_t st;
    ninlil_bytes_view_t member_key_view;
    ninlil_bytes_view_t identity_view;

    (void)memset(out, 0, sizeof(*out));
    member_key_view.data = member->key.bytes;
    member_key_view.length = member->key.length;
    st = ninlil_model_domain_key_digest(member_key_view, &key_dig);
    if (st != NINLIL_OK) {
        return st;
    }
    st = ninlil_model_domain_composite_digest(
        NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX,
        (ninlil_bytes_view_t){key_dig.bytes, 32u},
        &composite);
    if (st != NINLIL_OK) {
        return st;
    }
    st = ninlil_model_domain_sha256(
        member->value, member->value_length, &value_dig);
    if (st != NINLIL_OK) {
        return st;
    }
    identity_view.data = composite.bytes;
    identity_view.length = 32u;
    st = ninlil_model_domain_build_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX,
        NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
        identity_view,
        &key);
    if (st != NINLIL_OK) {
        return st;
    }
    (void)memset(&body, 0, sizeof(body));
    body.index_state = NINLIL_MODEL_DOMAIN_INDEX_STATE_BASELINE;
    (void)memcpy(body.member_key_digest, key_dig.bytes, 32u);
    body.member_key_length = (uint16_t)member->key.length;
    body.member_key_bytes = member->key.bytes;
    (void)memcpy(body.member_value_digest, value_dig.bytes, 32u);
    /* head digest remains zero for BASELINE. */
    st = ninlil_model_domain_encode_body_witness_head_index(
        &body, body_bytes, sizeof(body_bytes), &body_len);
    if (st != NINLIL_OK) {
        return st;
    }
    (void)memset(&header, 0, sizeof(header));
    header.domain_format = 1u;
    header.subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX;
    header.flags = 0u;
    header.record_revision = 1u;
    (void)memcpy(header.primary_id, composite.bytes, 16u);
    header.body_length = body_len;
    st = ninlil_model_domain_encode_envelope(
        6u,
        &header,
        (ninlil_bytes_view_t){body_bytes, body_len},
        out->value,
        sizeof(out->value),
        &value_len);
    if (st != NINLIL_OK) {
        return st;
    }
    if (key.length > sizeof(out->key)) {
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    (void)memcpy(out->key, key.bytes, key.length);
    out->key_length = key.length;
    out->value_length = value_len;
    return NINLIL_OK;
}

/*
 * Materialise all 16 metadata records into a fixed stack workspace and sort
 * by unsigned key order. Caller provides workspace[16].
 */
static ninlil_status_t materialise_metadata_sorted(
    const ninlil_domain_schema1_bootstrap_plan_t *bootstrap,
    ninlil_domain_schema1_metadata_record_t workspace[16])
{
    ninlil_domain_schema1_bootstrap_record_t member;
    ninlil_domain_schema1_metadata_record_t unsorted[16];
    uint32_t i;
    uint32_t j;
    ninlil_status_t st;

    for (i = 0u; i < NINLIL_DOMAIN_SCHEMA1_INDEX_MEMBER_COUNT; ++i) {
        st = ninlil_domain_schema1_bootstrap_record_at(
            bootstrap, k_bootstrap_members_start + i, &member);
        if (st != NINLIL_OK) {
            return st;
        }
        st = encode_head_index(&member, &unsorted[i]);
        if (st != NINLIL_OK) {
            return st;
        }
    }
    st = encode_clock_uninitialized(
        &unsorted[NINLIL_DOMAIN_SCHEMA1_INDEX_MEMBER_COUNT]);
    if (st != NINLIL_OK) {
        return st;
    }
    /* Insertion sort by key bytes (unsigned lexicographic). */
    for (i = 0u; i < 16u; ++i) {
        workspace[i] = unsorted[i];
        for (j = i; j > 0u; --j) {
            uint32_t a_len = workspace[j - 1u].key_length;
            uint32_t b_len = workspace[j].key_length;
            uint32_t n = a_len < b_len ? a_len : b_len;
            int cmp = memcmp(workspace[j - 1u].key, workspace[j].key, n);
            if (cmp < 0 || (cmp == 0 && a_len <= b_len)) {
                break;
            }
            {
                ninlil_domain_schema1_metadata_record_t tmp = workspace[j - 1u];
                workspace[j - 1u] = workspace[j];
                workspace[j] = tmp;
            }
        }
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_schema1_build_metadata_plan(
    const ninlil_domain_schema1_bootstrap_plan_t *bootstrap_plan,
    ninlil_domain_schema1_metadata_plan_t *out_plan)
{
    ninlil_domain_schema1_metadata_record_t probe[16];
    ninlil_status_t st;

    if (out_plan == NULL || !plan_bootstrap_sealed(bootstrap_plan)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_plan, 0, sizeof(*out_plan));
    out_plan->sealed_bootstrap = *bootstrap_plan;
    out_plan->record_count = NINLIL_DOMAIN_SCHEMA1_METADATA_RECORD_COUNT;
    out_plan->sealed_record_count = NINLIL_DOMAIN_SCHEMA1_METADATA_RECORD_COUNT;
    st = materialise_metadata_sorted(
        &out_plan->sealed_bootstrap, probe);
    if (st != NINLIL_OK) {
        (void)memset(out_plan, 0, sizeof(*out_plan));
        return st;
    }
    out_plan->sealed_magic = k_meta_magic;
    out_plan->sealed_crc32c = metadata_plan_crc(out_plan);
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_schema1_metadata_record_at(
    const ninlil_domain_schema1_metadata_plan_t *plan,
    uint32_t index,
    ninlil_domain_schema1_metadata_record_t *out_record)
{
    ninlil_domain_schema1_metadata_record_t workspace[16];
    ninlil_status_t st;

    if (out_record == NULL || !metadata_plan_is_sealed(plan)
        || index >= NINLIL_DOMAIN_SCHEMA1_METADATA_RECORD_COUNT) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    st = materialise_metadata_sorted(&plan->sealed_bootstrap, workspace);
    if (st != NINLIL_OK) {
        return st;
    }
    *out_record = workspace[index];
    return NINLIL_OK;
}

static int row_equals(
    const ninlil_domain_schema1_snapshot_row_t *row,
    const uint8_t *key,
    uint32_t key_length,
    const uint8_t *value,
    uint32_t value_length)
{
    return row != NULL
        && row->key.data != NULL
        && row->value.data != NULL
        && row->key.length == key_length
        && row->value.length == value_length
        && memcmp(row->key.data, key, key_length) == 0
        && memcmp(row->value.data, value, value_length) == 0;
}

static int find_exact_row(
    const ninlil_domain_schema1_snapshot_row_t *rows,
    uint32_t row_count,
    const uint8_t *key,
    uint32_t key_length,
    const uint8_t *value,
    uint32_t value_length)
{
    uint32_t i;
    for (i = 0u; i < row_count; ++i) {
        if (row_equals(&rows[i], key, key_length, value, value_length)) {
            return 1;
        }
    }
    return 0;
}

ninlil_status_t ninlil_domain_schema1_classify_t1b_commit_unknown(
    const ninlil_domain_schema1_bootstrap_plan_t *bootstrap_plan,
    const ninlil_domain_schema1_metadata_plan_t *metadata_plan,
    const ninlil_domain_schema1_snapshot_row_t *rows,
    uint32_t row_count,
    ninlil_domain_schema1_group_class_t *out_class)
{
    ninlil_domain_schema1_bootstrap_record_t boot_rec;
    ninlil_domain_schema1_metadata_record_t meta_ws[16];
    uint32_t boot_hits = 0u;
    uint32_t meta_hits = 0u;
    uint32_t i;
    ninlil_status_t st;

    if (out_class == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
    if (!plan_bootstrap_sealed(bootstrap_plan)
        || !metadata_plan_is_sealed(metadata_plan)
        || (row_count != 0u && rows == NULL)
        || row_count > NINLIL_DOMAIN_SCHEMA1_COUNT_HARD_CAP) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /* Unconditional materialised count coherence for corrupt undercount fence. */
    st = materialise_metadata_sorted(bootstrap_plan, meta_ws);
    if (st != NINLIL_OK) {
        return st;
    }

    for (i = 0u; i < NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_RECORD_COUNT; ++i) {
        st = ninlil_domain_schema1_bootstrap_record_at(
            bootstrap_plan, i, &boot_rec);
        if (st != NINLIL_OK) {
            return st;
        }
        if (find_exact_row(
                rows,
                row_count,
                boot_rec.key.bytes,
                boot_rec.key.length,
                boot_rec.value,
                boot_rec.value_length)) {
            boot_hits += 1u;
        }
    }
    for (i = 0u; i < 16u; ++i) {
        if (find_exact_row(
                rows,
                row_count,
                meta_ws[i].key,
                meta_ws[i].key_length,
                meta_ws[i].value,
                meta_ws[i].value_length)) {
            meta_hits += 1u;
        }
    }

    if (boot_hits == 17u && meta_hits == 0u && row_count == 17u) {
        *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_OLD;
        return NINLIL_OK;
    }
    if (boot_hits == 17u && meta_hits == 16u && row_count == 33u) {
        *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_NEW;
        return NINLIL_OK;
    }
    *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
    return NINLIL_OK;
}

static uint32_t t5_plan_crc(const ninlil_domain_schema1_t5_clock_plan_t *plan)
{
    uint8_t buf[48];
    uint32_t o = 0u;
    uint32_t i;
    for (i = 0u; i < 16u; ++i) {
        buf[o++] = plan->trusted_clock_epoch[i];
    }
    buf[o++] = (uint8_t)(plan->now_ms >> 56);
    buf[o++] = (uint8_t)(plan->now_ms >> 48);
    buf[o++] = (uint8_t)(plan->now_ms >> 40);
    buf[o++] = (uint8_t)(plan->now_ms >> 32);
    buf[o++] = (uint8_t)(plan->now_ms >> 24);
    buf[o++] = (uint8_t)(plan->now_ms >> 16);
    buf[o++] = (uint8_t)(plan->now_ms >> 8);
    buf[o++] = (uint8_t)plan->now_ms;
    buf[o++] = (uint8_t)(plan->publish_generation >> 24);
    buf[o++] = (uint8_t)(plan->publish_generation >> 16);
    buf[o++] = (uint8_t)(plan->publish_generation >> 8);
    buf[o++] = (uint8_t)plan->publish_generation;
    return crc32c_bytes(buf, o);
}

ninlil_status_t ninlil_domain_schema1_build_t5_clock_plan(
    const uint8_t trusted_clock_epoch[16],
    uint64_t now_ms,
    uint64_t publish_generation,
    ninlil_domain_schema1_t5_clock_plan_t *out_plan)
{
    ninlil_domain_schema1_metadata_record_t old_rec;
    ninlil_domain_schema1_metadata_record_t new_rec;
    ninlil_status_t st;

    if (out_plan == NULL || trusted_clock_epoch == NULL
        || publish_generation == 0u
        || publish_generation == UINT64_MAX) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_plan, 0, sizeof(*out_plan));
    (void)memcpy(out_plan->trusted_clock_epoch, trusted_clock_epoch, 16u);
    out_plan->now_ms = now_ms;
    out_plan->publish_generation = publish_generation;
    st = encode_clock_uninitialized(&old_rec);
    if (st != NINLIL_OK) {
        return st;
    }
    st = encode_clock_trusted(
        trusted_clock_epoch, now_ms, publish_generation, &new_rec);
    if (st != NINLIL_OK) {
        return st;
    }
    if (old_rec.key_length != new_rec.key_length
        || memcmp(old_rec.key, new_rec.key, old_rec.key_length) != 0) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memcpy(out_plan->clock_key, old_rec.key, old_rec.key_length);
    out_plan->clock_key_length = old_rec.key_length;
    (void)memcpy(out_plan->old_value, old_rec.value, old_rec.value_length);
    out_plan->old_value_length = old_rec.value_length;
    (void)memcpy(out_plan->new_value, new_rec.value, new_rec.value_length);
    out_plan->new_value_length = new_rec.value_length;
    out_plan->sealed_magic = k_meta_magic;
    out_plan->sealed_crc32c = t5_plan_crc(out_plan);
    return NINLIL_OK;
}

static int t5_plan_sealed(const ninlil_domain_schema1_t5_clock_plan_t *plan)
{
    return plan != NULL
        && plan->sealed_magic == k_meta_magic
        && plan->sealed_crc32c == t5_plan_crc(plan)
        && plan->clock_key_length != 0u
        && plan->old_value_length != 0u
        && plan->new_value_length != 0u;
}

ninlil_status_t ninlil_domain_schema1_classify_t5_commit_unknown(
    const ninlil_domain_schema1_t5_clock_plan_t *plan,
    const ninlil_domain_schema1_snapshot_row_t *rows,
    uint32_t row_count,
    ninlil_domain_schema1_group_class_t *out_class)
{
    int has_old = 0;
    int has_new = 0;
    uint32_t clock_rows = 0u;
    uint32_t i;

    if (out_class == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
    if (!t5_plan_sealed(plan) || (row_count != 0u && rows == NULL)
        || row_count > NINLIL_DOMAIN_SCHEMA1_COUNT_HARD_CAP) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    for (i = 0u; i < row_count; ++i) {
        if (rows[i].key.data == NULL || rows[i].key.length == 0u) {
            continue;
        }
        if (rows[i].key.length == plan->clock_key_length
            && memcmp(rows[i].key.data, plan->clock_key, plan->clock_key_length)
                == 0) {
            clock_rows += 1u;
            if (rows[i].value.length == plan->old_value_length
                && rows[i].value.data != NULL
                && memcmp(
                       rows[i].value.data,
                       plan->old_value,
                       plan->old_value_length)
                    == 0) {
                has_old = 1;
            }
            if (rows[i].value.length == plan->new_value_length
                && rows[i].value.data != NULL
                && memcmp(
                       rows[i].value.data,
                       plan->new_value,
                       plan->new_value_length)
                    == 0) {
                has_new = 1;
            }
        }
    }
    if (clock_rows != 1u) {
        *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
        return NINLIL_OK;
    }
    if (has_old && !has_new) {
        *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_OLD;
        return NINLIL_OK;
    }
    if (has_new && !has_old) {
        *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_NEW;
        return NINLIL_OK;
    }
    *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
    return NINLIL_OK;
}

/* --- Startup stage machine --- */

static uint32_t stage_bit(ninlil_domain_schema1_startup_stage_t stage)
{
    return 1u << (uint32_t)stage;
}

static int all_prior_complete(
    const ninlil_domain_schema1_startup_state_t *state,
    ninlil_domain_schema1_startup_stage_t stage)
{
    uint32_t s;
    for (s = 0u; s < (uint32_t)stage; ++s) {
        if ((state->completed_mask & (1u << s)) == 0u) {
            return 0;
        }
    }
    return 1;
}

ninlil_status_t ninlil_domain_schema1_startup_init(
    ninlil_domain_schema1_startup_state_t *state)
{
    if (state == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(state, 0, sizeof(*state));
    state->fault_stage = 0xFFu;
    state->sealed_magic = k_meta_magic;
    return NINLIL_OK;
}

static int startup_live(const ninlil_domain_schema1_startup_state_t *state)
{
    return state != NULL && state->sealed_magic == k_meta_magic
        && state->fenced == 0u;
}

ninlil_status_t ninlil_domain_schema1_startup_complete_stage(
    ninlil_domain_schema1_startup_state_t *state,
    ninlil_domain_schema1_startup_stage_t stage)
{
    if (!startup_live(state)
        || (uint32_t)stage >= NINLIL_DOMAIN_SCHEMA1_STARTUP_STAGE_COUNT) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    state->attempted_mask |= stage_bit(stage);
    if (!all_prior_complete(state, stage)) {
        state->fenced = 1u;
        state->fault_stage = (uint32_t)stage;
        return NINLIL_E_INVALID_STATE;
    }
    if (stage == NINLIL_DOMAIN_SCHEMA1_STAGE_T5_COMMIT) {
        state->t5_commit_attempt_count += 1u;
    }
    if (stage == NINLIL_DOMAIN_SCHEMA1_STAGE_T6) {
        state->t6_health_attempt_count += 1u;
    }
    /* Side-effect bits: exact ADR order. */
    if (stage == NINLIL_DOMAIN_SCHEMA1_STAGE_BEARER_OPEN) {
        /* Bearer only after T6. */
        if ((state->completed_mask & stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_T6))
            == 0u) {
            state->fenced = 1u;
            return NINLIL_E_INVALID_STATE;
        }
        state->bearer_open = 1u;
    }
    if (stage == NINLIL_DOMAIN_SCHEMA1_STAGE_METRICS_ENTROPY) {
        state->metrics_entropy = 1u;
    }
    if (stage == NINLIL_DOMAIN_SCHEMA1_STAGE_PUBLISH) {
        if ((state->completed_mask & stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_T7))
            == 0u) {
            state->fenced = 1u;
            return NINLIL_E_INVALID_STATE;
        }
        state->public_handle = 1u;
        state->publish = 1u;
        /* callback remains 0: no automatic callback publication. */
    }
    state->completed_mask |= stage_bit(stage);
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_schema1_startup_fault(
    ninlil_domain_schema1_startup_state_t *state,
    ninlil_domain_schema1_startup_stage_t fault_stage,
    ninlil_status_t fault_status)
{
    if (state == NULL || state->sealed_magic != k_meta_magic) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)fault_status;
    state->attempted_mask |= stage_bit(fault_stage);
    state->fenced = 1u;
    state->fault_stage = (uint32_t)fault_stage;
    /* Publication bits stay at whatever was already zero; never advance. */
    state->callback = 0u;
    if ((state->completed_mask & stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_PUBLISH))
        == 0u) {
        state->public_handle = 0u;
        state->publish = 0u;
    }
    if ((uint32_t)fault_stage
        <= (uint32_t)NINLIL_DOMAIN_SCHEMA1_STAGE_T6) {
        state->bearer_open = 0u;
    }
    return NINLIL_OK;
}

int ninlil_domain_schema1_startup_publication_allowed(
    const ninlil_domain_schema1_startup_state_t *state)
{
    if (state == NULL || state->sealed_magic != k_meta_magic
        || state->fenced != 0u) {
        return 0;
    }
    return (state->completed_mask & stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_PUBLISH))
        != 0u
        && state->public_handle == 1u
        && state->publish == 1u
        && state->callback == 0u;
}

int ninlil_domain_schema1_startup_pre_publish_side_effects_zero(
    const ninlil_domain_schema1_startup_state_t *state)
{
    uint32_t mask_before_bearer =
        stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_T0)
        | stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_T1A)
        | stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_T1B)
        | stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_T2)
        | stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_T3)
        | stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_T4)
        | stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_T5_SAMPLE)
        | stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_T5_COMMIT)
        | stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_T6);

    if (state == NULL || state->sealed_magic != k_meta_magic) {
        return 0;
    }
    /* Until T6 complete: no Bearer/callback/handle/publish. */
    if ((state->completed_mask & mask_before_bearer) != mask_before_bearer) {
        return state->bearer_open == 0u
            && state->callback == 0u
            && state->public_handle == 0u
            && state->publish == 0u;
    }
    /* T6 done, before T7/PUBLISH: Bearer may be open; still no handle. */
    if ((state->completed_mask & stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_PUBLISH))
        == 0u) {
        return state->callback == 0u
            && state->public_handle == 0u
            && state->publish == 0u;
    }
    return 1;
}

ninlil_status_t ninlil_domain_schema1_startup_export_transcript(
    const ninlil_domain_schema1_startup_state_t *state,
    ninlil_domain_schema1_startup_transcript_t *out_transcript)
{
    if (state == NULL || out_transcript == NULL
        || state->sealed_magic != k_meta_magic) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_transcript, 0, sizeof(*out_transcript));
    out_transcript->T0_complete =
        (state->completed_mask & stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_T0))
        != 0u;
    out_transcript->T1a_complete =
        (state->completed_mask & stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_T1A))
        != 0u;
    out_transcript->T1b_complete =
        (state->completed_mask & stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_T1B))
        != 0u;
    out_transcript->T2_complete =
        (state->completed_mask & stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_T2))
        != 0u;
    out_transcript->T3_complete =
        (state->completed_mask & stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_T3))
        != 0u;
    out_transcript->T4_complete =
        (state->completed_mask & stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_T4))
        != 0u;
    out_transcript->T5_commit_attempt_count = state->t5_commit_attempt_count;
    out_transcript->T5_complete =
        (state->completed_mask
         & stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_T5_COMMIT))
        != 0u;
    out_transcript->T6_complete =
        (state->completed_mask & stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_T6))
        != 0u;
    out_transcript->T6_health_attempt_count = state->t6_health_attempt_count;
    out_transcript->T7_complete =
        (state->completed_mask & stage_bit(NINLIL_DOMAIN_SCHEMA1_STAGE_T7))
        != 0u;
    out_transcript->bearer_open = state->bearer_open;
    out_transcript->metrics_entropy = state->metrics_entropy;
    out_transcript->callback = state->callback;
    out_transcript->public_handle = state->public_handle;
    out_transcript->publish = state->publish;
    out_transcript->storage_recovery_complete =
        out_transcript->T0_complete
        && out_transcript->T1a_complete
        && out_transcript->T1b_complete
        && out_transcript->T2_complete
        && out_transcript->T3_complete
        && out_transcript->T4_complete;
    return NINLIL_OK;
}

/* --- Kind-1 --- */

static uint32_t kind1_crc(const ninlil_domain_schema1_kind1_plan_t *plan)
{
    /*
     * Members always seal. When post_record_count==7, include full 7-record
     * inventory so header/chunk digests cannot be swapped under a stale CRC.
     */
    if (plan->post_record_count
        == NINLIL_DOMAIN_SCHEMA1_KIND1_POST_RECORD_COUNT) {
        uint8_t buf[sizeof(plan->members) + 4u + sizeof(plan->post_records)];
        uint32_t o = 0u;
        (void)memcpy(buf + o, plan->members, sizeof(plan->members));
        o += (uint32_t)sizeof(plan->members);
        buf[o++] = (uint8_t)(plan->post_record_count >> 24);
        buf[o++] = (uint8_t)(plan->post_record_count >> 16);
        buf[o++] = (uint8_t)(plan->post_record_count >> 8);
        buf[o++] = (uint8_t)plan->post_record_count;
        (void)memcpy(buf + o, plan->post_records, sizeof(plan->post_records));
        o += (uint32_t)sizeof(plan->post_records);
        return crc32c_bytes(buf, o);
    }
    return crc32c_bytes(
        (const uint8_t *)plan->members, sizeof(plan->members));
}

static ninlil_status_t copy_key(
    uint8_t *dst,
    uint32_t dst_cap,
    uint32_t *out_len,
    const uint8_t *src,
    uint32_t src_len)
{
    if (src == NULL || src_len == 0u || src_len > dst_cap) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memcpy(dst, src, src_len);
    *out_len = src_len;
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_schema1_kind1_build_plan(
    const uint8_t *capacity_service_key,
    uint32_t capacity_service_key_length,
    const uint8_t capacity_post_value_digest[32],
    const uint8_t *service_key,
    uint32_t service_key_length,
    const uint8_t service_post_value_digest[32],
    const uint8_t *quota_key,
    uint32_t quota_key_length,
    const uint8_t quota_post_value_digest[32],
    const uint8_t *reservation_key,
    uint32_t reservation_key_length,
    const uint8_t reservation_post_value_digest[32],
    const uint8_t *head_index_key,
    uint32_t head_index_key_length,
    const uint8_t head_index_post_value_digest[32],
    const uint8_t service_complete_key_digest[32],
    ninlil_domain_schema1_kind1_plan_t *out_plan)
{
    ninlil_model_domain_digest_t w;
    ninlil_status_t st;
    ninlil_domain_schema1_kind1_member_t raw[5];
    uint32_t i;
    uint32_t j;

    if (out_plan == NULL || capacity_post_value_digest == NULL
        || service_post_value_digest == NULL || quota_post_value_digest == NULL
        || reservation_post_value_digest == NULL
        || head_index_post_value_digest == NULL
        || service_complete_key_digest == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_plan, 0, sizeof(*out_plan));
    (void)memset(raw, 0, sizeof(raw));
    /* Ordinal order before sort: REPLACE capacity, CREATE service/quota/res,
     * REPLACE head — then sort by complete key unsigned order for manifest. */
    raw[0].action = NINLIL_DOMAIN_SCHEMA1_KIND1_ACTION_REPLACE;
    st = copy_key(
        raw[0].key,
        sizeof(raw[0].key),
        &raw[0].key_length,
        capacity_service_key,
        capacity_service_key_length);
    if (st != NINLIL_OK) {
        return st;
    }
    (void)memcpy(raw[0].value_digest, capacity_post_value_digest, 32u);

    raw[1].action = NINLIL_DOMAIN_SCHEMA1_KIND1_ACTION_CREATE;
    st = copy_key(
        raw[1].key,
        sizeof(raw[1].key),
        &raw[1].key_length,
        service_key,
        service_key_length);
    if (st != NINLIL_OK) {
        return st;
    }
    (void)memcpy(raw[1].value_digest, service_post_value_digest, 32u);

    raw[2].action = NINLIL_DOMAIN_SCHEMA1_KIND1_ACTION_CREATE;
    st = copy_key(
        raw[2].key,
        sizeof(raw[2].key),
        &raw[2].key_length,
        quota_key,
        quota_key_length);
    if (st != NINLIL_OK) {
        return st;
    }
    (void)memcpy(raw[2].value_digest, quota_post_value_digest, 32u);

    raw[3].action = NINLIL_DOMAIN_SCHEMA1_KIND1_ACTION_CREATE;
    st = copy_key(
        raw[3].key,
        sizeof(raw[3].key),
        &raw[3].key_length,
        reservation_key,
        reservation_key_length);
    if (st != NINLIL_OK) {
        return st;
    }
    (void)memcpy(raw[3].value_digest, reservation_post_value_digest, 32u);

    raw[4].action = NINLIL_DOMAIN_SCHEMA1_KIND1_ACTION_REPLACE;
    st = copy_key(
        raw[4].key,
        sizeof(raw[4].key),
        &raw[4].key_length,
        head_index_key,
        head_index_key_length);
    if (st != NINLIL_OK) {
        return st;
    }
    (void)memcpy(raw[4].value_digest, head_index_post_value_digest, 32u);

    /* Sort members by complete key (unsigned lexicographic). */
    for (i = 0u; i < 5u; ++i) {
        out_plan->members[i] = raw[i];
        for (j = i; j > 0u; --j) {
            uint32_t a = out_plan->members[j - 1u].key_length;
            uint32_t b = out_plan->members[j].key_length;
            uint32_t n = a < b ? a : b;
            int cmp = memcmp(
                out_plan->members[j - 1u].key, out_plan->members[j].key, n);
            if (cmp < 0 || (cmp == 0 && a <= b)) {
                break;
            }
            {
                ninlil_domain_schema1_kind1_member_t tmp =
                    out_plan->members[j - 1u];
                out_plan->members[j - 1u] = out_plan->members[j];
                out_plan->members[j] = tmp;
            }
        }
    }
    out_plan->member_count = 5u;
    (void)memcpy(
        out_plan->operation_identity, service_complete_key_digest, 32u);
    st = ninlil_model_domain_witness_identity_digest(
        1u,
        (ninlil_bytes_view_t){service_complete_key_digest, 32u},
        &w);
    if (st != NINLIL_OK) {
        (void)memset(out_plan, 0, sizeof(*out_plan));
        return st;
    }
    (void)memcpy(out_plan->witness_composite, w.bytes, 32u);
    out_plan->sealed_magic = k_meta_magic;
    out_plan->sealed_crc32c = kind1_crc(out_plan);
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_schema1_kind1_member_at(
    const ninlil_domain_schema1_kind1_plan_t *plan,
    uint32_t ordinal,
    ninlil_domain_schema1_kind1_member_t *out_member)
{
    if (plan == NULL || out_member == NULL
        || plan->sealed_magic != k_meta_magic
        || plan->sealed_crc32c != kind1_crc(plan)
        || plan->member_count != 5u
        || ordinal >= 5u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_member = plan->members[ordinal];
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_schema1_kind1_plan_finish(
    ninlil_domain_schema1_kind1_plan_t *plan)
{
    uint32_t i;
    if (plan == NULL || plan->member_count != 5u
        || plan->post_record_count
            != NINLIL_DOMAIN_SCHEMA1_KIND1_POST_RECORD_COUNT) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    for (i = 0u; i < NINLIL_DOMAIN_SCHEMA1_KIND1_POST_RECORD_COUNT; ++i) {
        if (plan->post_records[i].key_length == 0u
            || plan->post_records[i].key_length
                > NINLIL_DOMAIN_SCHEMA1_METADATA_KEY_MAX_BYTES) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
    }
    plan->sealed_magic = k_meta_magic;
    plan->sealed_crc32c = kind1_crc(plan);
    return NINLIL_OK;
}

static int kind1_key_eq(
    const ninlil_domain_schema1_snapshot_row_t *row,
    const uint8_t *key,
    uint32_t key_len)
{
    return row != NULL && row->key.data != NULL && key != NULL
        && row->key.length == key_len
        && memcmp(row->key.data, key, key_len) == 0;
}

static int kind1_find_row(
    const ninlil_domain_schema1_snapshot_row_t *rows,
    uint32_t row_count,
    const uint8_t *key,
    uint32_t key_len,
    uint32_t *out_index)
{
    uint32_t i;
    for (i = 0u; i < row_count; ++i) {
        if (kind1_key_eq(&rows[i], key, key_len)) {
            if (out_index != NULL) {
                *out_index = i;
            }
            return 1;
        }
    }
    return 0;
}

static ninlil_status_t kind1_row_d1_ok(
    const ninlil_domain_schema1_snapshot_row_t *row)
{
    ninlil_model_domain_key_class_t kc;
    ninlil_status_t st;
    if (row == NULL || row->key.data == NULL || row->value.data == NULL
        || row->key.length == 0u || row->value.length == 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    /* Domain schema1 and V1-LAB operational namespaces never cohabit. */
    if (ninlil_domain_schema1_is_lab_operational_key(
            row->key.data, row->key.length)
        != 0) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    /*
     * Family 3/4 (runtime-store capacity/counter keys): key shape only.
     * Full classify_row is domain family-6 oriented and rejects capacity.
     */
    if (row->key.length >= 10u
        && (row->key.data[8] == 0x03u || row->key.data[8] == 0x04u)) {
        return NINLIL_OK;
    }
    st = ninlil_model_domain_classify_key(
        (ninlil_bytes_view_t){row->key.data, row->key.length}, &kc);
    if (st != NINLIL_OK || kc == NINLIL_MODEL_DOMAIN_KEY_CLASS_MALFORMED) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (kc == NINLIL_MODEL_DOMAIN_KEY_CLASS_RECOGNIZABLE_FUTURE) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    st = ninlil_model_domain_classify_row(
        (ninlil_bytes_view_t){row->key.data, row->key.length},
        (ninlil_bytes_view_t){row->value.data, row->value.length},
        &kc);
    if (st != NINLIL_OK || kc != NINLIL_MODEL_DOMAIN_KEY_CLASS_CURRENT) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_schema1_classify_kind1_commit_unknown(
    const ninlil_domain_schema1_kind1_plan_t *plan,
    const ninlil_domain_schema1_snapshot_row_t *pre_rows,
    uint32_t pre_row_count,
    const ninlil_domain_schema1_snapshot_row_t *post_rows,
    uint32_t post_row_count,
    ninlil_domain_schema1_group_class_t *out_class)
{
    uint32_t new_hits = 0u;
    uint32_t old_hits = 0u;
    uint32_t absent = 0u;
    uint32_t third = 0u;
    uint32_t m;
    uint32_t i;
    uint32_t create_absent = 0u;
    uint32_t create_total = 0u;
    uint32_t replace_old = 0u;
    uint32_t replace_total = 0u;
    int extra = 0;

    if (out_class == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
    if (plan == NULL || plan->sealed_magic != k_meta_magic
        || plan->sealed_crc32c != kind1_crc(plan)
        || plan->member_count != 5u
        || plan->post_record_count
            != NINLIL_DOMAIN_SCHEMA1_KIND1_POST_RECORD_COUNT
        || (pre_row_count != 0u && pre_rows == NULL)
        || (post_row_count != 0u && post_rows == NULL)
        || post_row_count > NINLIL_DOMAIN_SCHEMA1_COUNT_HARD_CAP) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    /*
     * Fail closed on D1 for the 7-group keys only. Format-2 binding/bootstrap
     * sealed rows are not all domain-envelope CURRENT; those are covered by
     * existing-namespace adopt / bootstrap exact matching.
     */
    for (m = 0u; m < NINLIL_DOMAIN_SCHEMA1_KIND1_POST_RECORD_COUNT; ++m) {
        uint32_t idx = 0u;
        if (kind1_find_row(
                post_rows,
                post_row_count,
                plan->post_records[m].key,
                plan->post_records[m].key_length,
                &idx)
            != 0) {
            if (kind1_row_d1_ok(&post_rows[idx]) != NINLIL_OK) {
                *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
                return NINLIL_OK;
            }
        }
    }

    for (m = 0u; m < NINLIL_DOMAIN_SCHEMA1_KIND1_POST_RECORD_COUNT; ++m) {
        const ninlil_domain_schema1_kind1_post_record_t *pr =
            &plan->post_records[m];
        uint32_t idx = 0u;
        ninlil_model_domain_digest_t dig;
        int found;

        if (pr->key_length == 0u || pr->key_length > sizeof(pr->key)) {
            *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
            return NINLIL_OK;
        }
        if (pr->action == NINLIL_DOMAIN_SCHEMA1_KIND1_ACTION_CREATE) {
            create_total += 1u;
        } else {
            replace_total += 1u;
        }
        found = kind1_find_row(
            post_rows, post_row_count, pr->key, pr->key_length, &idx);
        if (found == 0) {
            absent += 1u;
            if (pr->action == NINLIL_DOMAIN_SCHEMA1_KIND1_ACTION_CREATE) {
                create_absent += 1u;
            }
            continue;
        }
        if (ninlil_model_domain_sha256(
                post_rows[idx].value.data,
                post_rows[idx].value.length,
                &dig)
            != NINLIL_OK) {
            *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
            return NINLIL_OK;
        }
        if (memcmp(dig.bytes, pr->post_value_digest, 32u) == 0) {
            new_hits += 1u;
            continue;
        }
        if (pr->action == NINLIL_DOMAIN_SCHEMA1_KIND1_ACTION_REPLACE
            && memcmp(dig.bytes, pr->pre_value_digest, 32u) == 0) {
            old_hits += 1u;
            replace_old += 1u;
            continue;
        }
        third += 1u;
    }

    /* EXTRA: post keys neither in pre_rows nor in the 7-record group. */
    if (pre_row_count > 0u) {
        for (i = 0u; i < post_row_count; ++i) {
            int in_pre = 0;
            int in_group = 0;
            uint32_t p;
            for (p = 0u; p < pre_row_count; ++p) {
                if (kind1_key_eq(
                        &post_rows[i],
                        pre_rows[p].key.data,
                        pre_rows[p].key.length)) {
                    in_pre = 1;
                    break;
                }
            }
            for (m = 0u; m < NINLIL_DOMAIN_SCHEMA1_KIND1_POST_RECORD_COUNT;
                 ++m) {
                if (kind1_key_eq(
                        &post_rows[i],
                        plan->post_records[m].key,
                        plan->post_records[m].key_length)) {
                    in_group = 1;
                    break;
                }
            }
            if (in_pre == 0 && in_group == 0) {
                extra = 1;
                break;
            }
        }
    }
    if (third != 0u) {
        *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_THIRD;
        return NINLIL_OK;
    }
    if (new_hits == NINLIL_DOMAIN_SCHEMA1_KIND1_POST_RECORD_COUNT
        && absent == 0u && old_hits == 0u) {
        if (extra != 0) {
            *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_EXTRA;
        } else {
            *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_NEW;
        }
        return NINLIL_OK;
    }
    /* ALL_OLD: CREATE targets (+header/chunk) absent; REPLACE exact pre. */
    if (create_total > 0u && create_absent == create_total
        && replace_total > 0u && replace_old == replace_total
        && new_hits == 0u && third == 0u) {
        *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_OLD;
        return NINLIL_OK;
    }
    if (absent == NINLIL_DOMAIN_SCHEMA1_KIND1_POST_RECORD_COUNT
        && new_hits == 0u && old_hits == 0u) {
        *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_ABSENT;
        return NINLIL_OK;
    }
    if (new_hits > 0u
        && new_hits < NINLIL_DOMAIN_SCHEMA1_KIND1_POST_RECORD_COUNT) {
        *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_PARTIAL;
        return NINLIL_OK;
    }
    if (extra != 0) {
        *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_EXTRA;
        return NINLIL_OK;
    }
    *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_schema1_classify_existing_namespace_adopt(
    const ninlil_domain_schema1_bootstrap_plan_t *bootstrap_plan,
    const ninlil_domain_schema1_snapshot_row_t *rows,
    uint32_t row_count,
    ninlil_domain_schema1_group_class_t *out_class)
{
    ninlil_domain_schema1_bootstrap_record_t br_bind;
    ninlil_domain_schema1_bootstrap_record_t br_id;
    uint32_t i;
    int bind_ok = 0;
    int id_ok = 0;
    ninlil_status_t st;

    if (out_class == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
    if (bootstrap_plan == NULL || (row_count != 0u && rows == NULL)
        || row_count < 33u
        || row_count > NINLIL_DOMAIN_SCHEMA1_COUNT_HARD_CAP) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    st = ninlil_domain_schema1_bootstrap_record_at(
        bootstrap_plan, 0u, &br_bind);
    if (st != NINLIL_OK) {
        return st;
    }
    st = ninlil_domain_schema1_bootstrap_record_at(
        bootstrap_plan, 1u, &br_id);
    if (st != NINLIL_OK) {
        return st;
    }
    for (i = 0u; i < row_count; ++i) {
        int bootstrap_exact = 0;
        uint32_t bi;
        if (rows[i].key.length == br_bind.key.length
            && memcmp(rows[i].key.data, br_bind.key.bytes, br_bind.key.length)
                == 0
            && rows[i].value.length == br_bind.value_length
            && memcmp(rows[i].value.data, br_bind.value, br_bind.value_length)
                == 0) {
            bind_ok = 1;
            bootstrap_exact = 1;
        }
        if (rows[i].key.length == br_id.key.length
            && memcmp(rows[i].key.data, br_id.key.bytes, br_id.key.length)
                == 0
            && rows[i].value.length == br_id.value_length
            && memcmp(rows[i].value.data, br_id.value, br_id.value_length)
                == 0) {
            id_ok = 1;
            bootstrap_exact = 1;
        }
        /* Other sealed bootstrap members may still match pre-mutation bytes. */
        for (bi = 2u; bi < NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_RECORD_COUNT
             && bootstrap_exact == 0;
             ++bi) {
            ninlil_domain_schema1_bootstrap_record_t br;
            if (ninlil_domain_schema1_bootstrap_record_at(
                    bootstrap_plan, bi, &br)
                != NINLIL_OK) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            if (rows[i].key.length == br.key.length
                && memcmp(rows[i].key.data, br.key.bytes, br.key.length) == 0
                && rows[i].value.length == br.value_length
                && memcmp(rows[i].value.data, br.value, br.value_length)
                    == 0) {
                bootstrap_exact = 1;
            }
        }
        /*
         * Rows not exact-matching sealed bootstrap must still pass D1/current
         * framing (capacity post-kind1, TRUSTED clock, services, witnesses).
         */
        if (bootstrap_exact == 0
            && kind1_row_d1_ok(&rows[i]) != NINLIL_OK) {
            *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
            return NINLIL_OK;
        }
    }
    if (bind_ok == 0 || id_ok == 0) {
        *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
        return NINLIL_OK;
    }
    /* Adopted existing Domain truth (not count-only). */
    *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_NEW;
    return NINLIL_OK;
}

/* --- LAB quarantine --- */

ninlil_status_t ninlil_domain_schema1_lab_classify_namespace(
    uint32_t binding_format,
    uint32_t bootstrap_exact,
    uint32_t metadata_exact_uninit,
    uint32_t metadata_partial,
    uint32_t lab_distinct_present,
    uint32_t domain_semantic_present,
    uint32_t duplicate_same_key,
    ninlil_domain_schema1_lab_namespace_class_t *out_class)
{
    if (out_class == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (duplicate_same_key != 0u || metadata_partial != 0u) {
        *out_class = NINLIL_DOMAIN_SCHEMA1_LAB_NS_CORRUPT;
        return NINLIL_OK;
    }
    if (binding_format == 0u && bootstrap_exact == 0u
        && metadata_exact_uninit == 0u && lab_distinct_present == 0u
        && domain_semantic_present == 0u) {
        *out_class = NINLIL_DOMAIN_SCHEMA1_LAB_NS_EMPTY;
        return NINLIL_OK;
    }
    if (binding_format == 2u) {
        if (lab_distinct_present != 0u) {
            *out_class = NINLIL_DOMAIN_SCHEMA1_LAB_NS_MIXED;
            return NINLIL_OK;
        }
        if (bootstrap_exact != 0u) {
            *out_class = NINLIL_DOMAIN_SCHEMA1_LAB_NS_EXACT_DOMAIN;
            return NINLIL_OK;
        }
        *out_class = NINLIL_DOMAIN_SCHEMA1_LAB_NS_CORRUPT;
        return NINLIL_OK;
    }
    if (binding_format == 1u) {
        if (domain_semantic_present != 0u && metadata_exact_uninit == 0u) {
            *out_class = NINLIL_DOMAIN_SCHEMA1_LAB_NS_MIXED;
            return NINLIL_OK;
        }
        if (bootstrap_exact != 0u) {
            /* format1 bootstrap exact => EXACT_LAB (metadata optional 0/16). */
            *out_class = NINLIL_DOMAIN_SCHEMA1_LAB_NS_EXACT_LAB;
            return NINLIL_OK;
        }
        if (lab_distinct_present != 0u) {
            *out_class = NINLIL_DOMAIN_SCHEMA1_LAB_NS_UNSUPPORTED;
            return NINLIL_OK;
        }
        *out_class = NINLIL_DOMAIN_SCHEMA1_LAB_NS_CORRUPT;
        return NINLIL_OK;
    }
    if (lab_distinct_present != 0u) {
        *out_class = NINLIL_DOMAIN_SCHEMA1_LAB_NS_UNSUPPORTED;
        return NINLIL_OK;
    }
    *out_class = NINLIL_DOMAIN_SCHEMA1_LAB_NS_CORRUPT;
    return NINLIL_OK;
}

int ninlil_domain_schema1_export_magic_match(
    const uint8_t *bytes,
    uint32_t length)
{
    if (bytes == NULL || length < 8u) {
        return 0;
    }
    return memcmp(bytes, k_export_magic, 8u) == 0;
}

int ninlil_domain_schema1_is_lab_operational_key(
    const uint8_t *key,
    uint32_t key_length)
{
    uint16_t prefix;

    if (key == NULL || key_length < 2u) {
        return 0;
    }
    /* Two-byte spine markers: TX CN DS EV OC ES RT AP RV BS ER ED. */
    prefix = (uint16_t)(((uint16_t)key[0] << 8) | (uint16_t)key[1]);
    switch (prefix) {
    case 0x5458u: /* TX */
    case 0x434eu: /* CN */
    case 0x4453u: /* DS */
    case 0x4556u: /* EV */
    case 0x4f43u: /* OC */
    case 0x4553u: /* ES */
    case 0x5254u: /* RT */
    case 0x4150u: /* AP */
    case 0x5256u: /* RV */
    case 0x4253u: /* BS */
    case 0x4552u: /* ER */
    case 0x4544u: /* ED */
        return 1;
    default:
        break;
    }
    if (key_length >= 3u && key[0] == 0x4eu && key[1] == 0x52u
        && key[2] == 0x53u) {
        return 1; /* NRS service ledger */
    }
    if (key_length >= 3u && key[0] == 0x4du && key[1] == 0x34u
        && key[2] == 0x54u) {
        return 1; /* M4T */
    }
    if (key_length >= 3u && key[0] == 0x43u && key[1] == 0x33u
        && key[2] == 0x52u) {
        return 1; /* C3R */
    }
    return 0;
}
