/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ADR-0022 kind-1 M=5 SERVICE_REGISTER encode + full-namespace FULL commit.
 * Feature-gated HOST_CANDIDATE. Production encoders only.
 */

#include "domain_schema1_kind1_register.h"

#include "domain_store_body_codec.h"
#include "domain_store_codec.h"
#include "runtime_internal.h"
#include "runtime_store_codec.h"

#include <stdalign.h>
#include <stdint.h>
#include <string.h>

#if !defined(NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING) \
    || (NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING == 0)
#error "domain_schema1_kind1_register.c requires feature ON"
#endif

static void sort_rows(ninlil_storage_canonical_row_t *rows, uint32_t count)
{
    uint32_t i;
    uint32_t j;
    for (i = 1u; i < count; ++i) {
        ninlil_storage_canonical_row_t key = rows[i];
        j = i;
        while (j > 0u) {
            uint32_t a = rows[j - 1u].key.length;
            uint32_t b = key.key.length;
            uint32_t n = a < b ? a : b;
            int cmp = memcmp(rows[j - 1u].key.data, key.key.data, n);
            if (cmp < 0 || (cmp == 0 && a <= b)) {
                break;
            }
            rows[j] = rows[j - 1u];
            j -= 1u;
        }
        rows[j] = key;
    }
}

static ninlil_status_t map_storage(ninlil_storage_status_t st)
{
    if (st == NINLIL_STORAGE_OK) {
        return NINLIL_OK;
    }
    if (st == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    }
    if (st == NINLIL_STORAGE_CORRUPT) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (st == NINLIL_STORAGE_NO_SPACE) {
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }
    return NINLIL_E_STORAGE;
}

static int clock_epoch_nonzero(const ninlil_id128_t *id)
{
    uint32_t index;

    for (index = 0u; index < (uint32_t)sizeof(id->bytes); ++index) {
        if (id->bytes[index] != 0u) {
            return 1;
        }
    }
    return 0;
}

static ninlil_status_t pack_text(
    uint8_t *out,
    uint32_t cap,
    uint32_t *off,
    ninlil_bytes_view_t text)
{
    if (text.length == 0u || text.length > 63u || text.data == NULL
        || *off + 1u + text.length > cap) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    out[(*off)++] = (uint8_t)text.length;
    (void)memcpy(out + *off, text.data, text.length);
    *off += text.length;
    return NINLIL_OK;
}

static ninlil_status_t build_service_raw(
    const ninlil_service_descriptor_t *d,
    uint8_t *out,
    uint32_t cap,
    uint32_t *out_len)
{
    uint32_t o = 0u;
    ninlil_status_t st;
    if (d == NULL || out == NULL || out_len == NULL || cap < 32u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memcpy(out + o, d->local_application_instance_id.bytes, 16u);
    o += 16u;
    st = pack_text(out, cap, &o, d->namespace_id);
    if (st != NINLIL_OK) {
        return st;
    }
    st = pack_text(out, cap, &o, d->service_id);
    if (st != NINLIL_OK) {
        return st;
    }
    out[o++] = (uint8_t)(d->descriptor_revision >> 56);
    out[o++] = (uint8_t)(d->descriptor_revision >> 48);
    out[o++] = (uint8_t)(d->descriptor_revision >> 40);
    out[o++] = (uint8_t)(d->descriptor_revision >> 32);
    out[o++] = (uint8_t)(d->descriptor_revision >> 24);
    out[o++] = (uint8_t)(d->descriptor_revision >> 16);
    out[o++] = (uint8_t)(d->descriptor_revision >> 8);
    out[o++] = (uint8_t)d->descriptor_revision;
    if (d->descriptor_digest.algorithm != NINLIL_DIGEST_SHA256
        || o + 32u > cap) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memcpy(out + o, d->descriptor_digest.bytes, 32u);
    o += 32u;
    *out_len = o;
    return NINLIL_OK;
}

static ninlil_status_t fill_text_id(
    ninlil_model_domain_text_id_t *tid,
    ninlil_bytes_view_t src)
{
    if (src.length == 0u || src.length > 63u || src.data == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    tid->length = (uint8_t)src.length;
    (void)memcpy(tid->bytes, src.data, src.length);
    return NINLIL_OK;
}

static ninlil_status_t encode_domain_record(
    uint8_t subtype,
    uint64_t revision,
    const uint8_t primary_id[16],
    const uint8_t head[32],
    const uint8_t pvd[32],
    const uint8_t *body,
    uint32_t body_len,
    uint8_t *out,
    uint32_t cap,
    uint32_t *out_len)
{
    ninlil_model_domain_common_header_t hdr;
    (void)memset(&hdr, 0, sizeof(hdr));
    hdr.domain_format = 1u;
    hdr.subtype = subtype;
    hdr.flags = 0u;
    hdr.record_revision = revision;
    (void)memcpy(hdr.primary_id, primary_id, 16u);
    if (head != NULL) {
        (void)memcpy(hdr.head_witness_digest, head, 32u);
    }
    if (pvd != NULL) {
        (void)memcpy(hdr.primary_value_digest, pvd, 32u);
    }
    hdr.body_length = body_len;
    return ninlil_model_domain_encode_envelope(
        6u,
        &hdr,
        (ninlil_bytes_view_t){body, body_len},
        out,
        cap,
        out_len);
}

static ninlil_status_t scan_ns(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t handle,
    ninlil_domain_schema1_kind1_workspace_t *ws)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_iter_t iter = NULL;
    ninlil_storage_status_t st;
    ninlil_bytes_view_t prefix = {NULL, 0u};
    uint32_t count = 0u;

    ws->snap_count = 0u;
    st = storage->begin(
        storage->user, handle, NINLIL_STORAGE_READ_ONLY, &txn);
    if (st != NINLIL_STORAGE_OK) {
        return map_storage(st);
    }
    st = storage->iter_open(storage->user, txn, prefix, &iter);
    if (st != NINLIL_STORAGE_OK) {
        (void)storage->rollback(storage->user, txn);
        return map_storage(st);
    }
    for (;;) {
        ninlil_mut_bytes_t k;
        ninlil_mut_bytes_t v;

        k.data = ws->scan_tmp_key;
        k.capacity = sizeof(ws->scan_tmp_key);
        k.length = 0u;
        v.data = ws->scan_tmp_value;
        v.capacity = sizeof(ws->scan_tmp_value);
        v.length = 0u;
        st = storage->iter_next(storage->user, iter, &k, &v);
        if (st == NINLIL_STORAGE_NOT_FOUND) {
            break;
        }
        if (st == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
            storage->iter_close(storage->user, iter);
            (void)storage->rollback(storage->user, txn);
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (st != NINLIL_STORAGE_OK) {
            storage->iter_close(storage->user, iter);
            (void)storage->rollback(storage->user, txn);
            return map_storage(st);
        }
        if (ninlil_domain_schema1_is_lab_operational_key(k.data, k.length)
            != 0) {
            storage->iter_close(storage->user, iter);
            (void)storage->rollback(storage->user, txn);
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (count >= NINLIL_DOMAIN_SCHEMA1_KIND1_NS_ROW_CAP) {
            storage->iter_close(storage->user, iter);
            (void)storage->rollback(storage->user, txn);
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (k.length > NINLIL_DOMAIN_SCHEMA1_OWNER_SCAN_KEY_CAP
            || v.length > NINLIL_DOMAIN_SCHEMA1_OWNER_SNAP_VALUE_CAP) {
            storage->iter_close(storage->user, iter);
            (void)storage->rollback(storage->user, txn);
            return NINLIL_E_STORAGE_CORRUPT;
        }
        (void)memcpy(ws->snap_key[count], k.data, k.length);
        ws->snap_key_len[count] = k.length;
        (void)memcpy(ws->snap_value[count], v.data, v.length);
        ws->snap_value_len[count] = v.length;
        count += 1u;
    }
    storage->iter_close(storage->user, iter);
    (void)storage->rollback(storage->user, txn);
    ws->snap_count = count;
    return NINLIL_OK;
}

static uint16_t record_role_for_key(const uint8_t *key, uint32_t key_len)
{
    if (key_len >= 10u && key[0] == 0x4eu) {
        uint8_t family = key[8];
        uint8_t subtype = key[9];
        if (family == 0x03u || family == 0x04u) {
            return (uint16_t)((uint16_t)family << 8);
        }
        return (uint16_t)(((uint16_t)family << 8) | (uint16_t)subtype);
    }
    return 0u;
}

static ninlil_status_t encode_witness_envelope(
    uint8_t subtype,
    const uint8_t identity[32],
    ninlil_bytes_view_t body,
    uint8_t *out_key,
    uint32_t *out_key_len,
    uint8_t *out_value,
    uint32_t value_cap,
    uint32_t *out_value_len)
{
    ninlil_model_domain_key_t domain_key;
    ninlil_model_domain_common_header_t hdr;
    ninlil_bytes_view_t identity_view;
    ninlil_status_t st;

    identity_view.data = identity;
    identity_view.length = 32u;
    st = ninlil_model_domain_build_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        subtype,
        NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
        identity_view,
        &domain_key);
    if (st != NINLIL_OK) {
        return st;
    }
    if (domain_key.length > NINLIL_DOMAIN_SCHEMA1_KIND1_MEMBER_KEY_CAP) {
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    (void)memcpy(out_key, domain_key.bytes, domain_key.length);
    *out_key_len = domain_key.length;
    (void)memset(&hdr, 0, sizeof(hdr));
    hdr.domain_format = NINLIL_MODEL_DOMAIN_FORMAT_VERSION;
    hdr.subtype = subtype;
    hdr.flags = 0u;
    hdr.record_revision = 1u;
    hdr.body_length = body.length;
    st = ninlil_model_domain_primary_id_from_identity(
        NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
        identity_view,
        hdr.primary_id);
    if (st != NINLIL_OK) {
        return st;
    }
    return ninlil_model_domain_encode_envelope(
        NINLIL_MODEL_DOMAIN_RECORD_TYPE_DOMAIN,
        &hdr,
        body,
        out_value,
        value_cap,
        out_value_len);
}

ninlil_status_t ninlil_domain_schema1_kind1_encode_members(
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_time_sample_t *trusted_clock,
    const uint8_t *old_capacity_value,
    uint32_t old_capacity_value_len,
    const uint8_t *old_head_value,
    uint32_t old_head_value_len,
    uint32_t increment_capacity,
    ninlil_domain_schema1_kind1_workspace_t *ws)
{
    ninlil_status_t st;
    ninlil_model_domain_digest_t dig;
    ninlil_model_domain_digest_t service_id_comp;
    ninlil_model_domain_digest_t quota_id_comp;
    ninlil_model_domain_digest_t res_id_comp;
    ninlil_model_domain_digest_t head_id_comp;
    ninlil_model_domain_digest_t capacity_kd;
    ninlil_model_domain_digest_t service_kd;
    ninlil_model_domain_digest_t quota_kd;
    ninlil_model_domain_digest_t res_kd;
    ninlil_model_domain_digest_t witness;
    ninlil_model_domain_key_t skey;
    ninlil_model_domain_key_t qkey;
    ninlil_model_domain_key_t rkey;
    ninlil_model_domain_key_t hkey;
    ninlil_model_runtime_store_key_t ckey;
    ninlil_model_runtime_store_capacity_t cap;
    ninlil_model_domain_body_service_t svc_body;
    ninlil_model_domain_body_service_quota_t quota_body;
    ninlil_model_domain_body_reservation_t res_body;
    ninlil_model_domain_body_witness_head_index_t head_body;
    uint8_t body_buf[480];
    uint32_t body_len = 0u;
    uint8_t service_components[260];
    uint32_t sc_len = 0u;
    uint8_t res_components[270];
    uint32_t rc_len = 0u;
    uint8_t zero32[32];
    uint64_t window_start;
    ninlil_model_domain_digest_t service_value_dig;
    ninlil_bytes_view_t id_view;

    if (descriptor == NULL || trusted_clock == NULL || ws == NULL
        || old_capacity_value == NULL || old_capacity_value_len == 0u
        || increment_capacity > 1u
        || trusted_clock->trust != NINLIL_CLOCK_TRUSTED) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /*
     * Do not wipe snap_* : service_register may scan the namespace before
     * encode and re-use the snapshot for reattach group classification.
     */
    (void)memset(ws->member_key, 0, sizeof(ws->member_key));
    (void)memset(ws->member_key_len, 0, sizeof(ws->member_key_len));
    (void)memset(ws->member_value, 0, sizeof(ws->member_value));
    (void)memset(ws->member_value_len, 0, sizeof(ws->member_value_len));
    (void)memset(&ws->plan, 0, sizeof(ws->plan));
    (void)memset(ws->service_raw, 0, sizeof(ws->service_raw));
    ws->service_raw_len = 0u;
    (void)memset(ws->service_key_digest, 0, sizeof(ws->service_key_digest));
    (void)memset(ws->witness, 0, sizeof(ws->witness));
    (void)memset(ws->capacity_key, 0, sizeof(ws->capacity_key));
    ws->capacity_key_len = 0u;
    (void)memset(ws->old_capacity_value, 0, sizeof(ws->old_capacity_value));
    ws->old_capacity_value_len = 0u;
    (void)memset(ws->old_head_value, 0, sizeof(ws->old_head_value));
    ws->old_head_value_len = 0u;
    (void)memset(ws->chunk_body, 0, sizeof(ws->chunk_body));
    ws->chunk_body_len = 0u;
    (void)memset(ws->header_body, 0, sizeof(ws->header_body));
    ws->header_body_len = 0u;
    (void)memset(zero32, 0, sizeof(zero32));
    (void)memcpy(
        ws->old_capacity_value, old_capacity_value, old_capacity_value_len);
    ws->old_capacity_value_len = old_capacity_value_len;
    if (old_head_value != NULL && old_head_value_len > 0u
        && old_head_value_len
            <= NINLIL_DOMAIN_SCHEMA1_KIND1_MEMBER_VALUE_CAP) {
        (void)memcpy(ws->old_head_value, old_head_value, old_head_value_len);
        ws->old_head_value_len = old_head_value_len;
    }

    st = build_service_raw(
        descriptor, ws->service_raw, sizeof(ws->service_raw), &ws->service_raw_len);
    if (st != NINLIL_OK) {
        return st;
    }
    /* RAW16(service_raw) for composite identity components. */
    service_components[0] = (uint8_t)(ws->service_raw_len >> 8);
    service_components[1] = (uint8_t)ws->service_raw_len;
    (void)memcpy(
        service_components + 2u, ws->service_raw, ws->service_raw_len);
    sc_len = 2u + ws->service_raw_len;
    st = ninlil_model_domain_composite_digest(
        0x10u, (ninlil_bytes_view_t){service_components, sc_len}, &service_id_comp);
    if (st != NINLIL_OK) {
        return st;
    }
    st = ninlil_model_domain_composite_digest(
        0x11u, (ninlil_bytes_view_t){service_components, sc_len}, &quota_id_comp);
    if (st != NINLIL_OK) {
        return st;
    }
    /* reservation_components = u16(owner_kind=1) || RAW16(service_raw) */
    res_components[0] = 0u;
    res_components[1] = 1u;
    res_components[2] = (uint8_t)(ws->service_raw_len >> 8);
    res_components[3] = (uint8_t)ws->service_raw_len;
    (void)memcpy(res_components + 4u, ws->service_raw, ws->service_raw_len);
    rc_len = 4u + ws->service_raw_len;
    st = ninlil_model_domain_composite_digest(
        0x23u, (ninlil_bytes_view_t){res_components, rc_len}, &res_id_comp);
    if (st != NINLIL_OK) {
        return st;
    }

    id_view.data = service_id_comp.bytes;
    id_view.length = 32u;
    st = ninlil_model_domain_build_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE,
        NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
        id_view,
        &skey);
    if (st != NINLIL_OK) {
        return st;
    }
    id_view.data = quota_id_comp.bytes;
    st = ninlil_model_domain_build_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE_QUOTA,
        NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
        id_view,
        &qkey);
    if (st != NINLIL_OK) {
        return st;
    }
    id_view.data = res_id_comp.bytes;
    st = ninlil_model_domain_build_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION,
        NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
        id_view,
        &rkey);
    if (st != NINLIL_OK) {
        return st;
    }
    st = ninlil_model_runtime_store_build_key(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE, &ckey);
    if (st != NINLIL_OK) {
        return st;
    }
    st = ninlil_model_domain_key_digest(
        (ninlil_bytes_view_t){ckey.bytes, ckey.length}, &capacity_kd);
    if (st != NINLIL_OK) {
        return st;
    }
    st = ninlil_model_domain_composite_digest(
        0x7du,
        (ninlil_bytes_view_t){capacity_kd.bytes, 32u},
        &head_id_comp);
    if (st != NINLIL_OK) {
        return st;
    }
    id_view.data = head_id_comp.bytes;
    st = ninlil_model_domain_build_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX,
        NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
        id_view,
        &hkey);
    if (st != NINLIL_OK) {
        return st;
    }

    st = ninlil_model_domain_key_digest(
        (ninlil_bytes_view_t){skey.bytes, skey.length}, &service_kd);
    if (st != NINLIL_OK) {
        return st;
    }
    st = ninlil_model_domain_key_digest(
        (ninlil_bytes_view_t){qkey.bytes, qkey.length}, &quota_kd);
    if (st != NINLIL_OK) {
        return st;
    }
    st = ninlil_model_domain_key_digest(
        (ninlil_bytes_view_t){rkey.bytes, rkey.length}, &res_kd);
    if (st != NINLIL_OK) {
        return st;
    }
    (void)memcpy(ws->service_key_digest, service_kd.bytes, 32u);

    /* W = COMPOSITE(0x7f, u16(op=1) || RAW16(service_key_digest)). */
    {
        uint8_t wcomp[2u + 2u + 32u];
        wcomp[0] = 0u;
        wcomp[1] = 1u;
        wcomp[2] = 0u;
        wcomp[3] = 32u;
        (void)memcpy(wcomp + 4u, service_kd.bytes, 32u);
        st = ninlil_model_domain_composite_digest(
            0x7fu, (ninlil_bytes_view_t){wcomp, sizeof(wcomp)}, &witness);
        if (st != NINLIL_OK) {
            return st;
        }
    }
    (void)memcpy(ws->witness, witness.bytes, 32u);
    (void)memcpy(ws->capacity_key, ckey.bytes, ckey.length);
    ws->capacity_key_len = ckey.length;

    /* Decode old capacity and build post capacity. */
    st = ninlil_model_runtime_store_decode_capacity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
        (ninlil_bytes_view_t){old_capacity_value, old_capacity_value_len},
        &cap);
    if (st != NINLIL_OK) {
        return st;
    }
    if (increment_capacity != 0u) {
        if (cap.used == UINT64_MAX || cap.capacity_epoch == UINT64_MAX) {
            return NINLIL_E_CAPACITY_EXHAUSTED;
        }
        cap.used += 1u;
        if (cap.used + cap.reserved < cap.used
            || cap.used + cap.reserved > cap.high_water) {
            if (cap.used + cap.reserved < cap.used) {
                return NINLIL_E_CAPACITY_EXHAUSTED;
            }
            cap.high_water = cap.used + cap.reserved;
        }
        cap.capacity_epoch += 1u;
    }

    /* Order in plan before sort: capacity, service, quota, res, head. */
    {
        uint32_t new_cap_len = 0u;
        st = ninlil_model_runtime_store_encode_capacity(
            NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
            &cap,
            ws->member_value[0],
            sizeof(ws->member_value[0]),
            &new_cap_len);
        if (st != NINLIL_OK) {
            return st;
        }
        ws->member_value_len[0] = new_cap_len;
        (void)memcpy(ws->member_key[0], ckey.bytes, ckey.length);
        ws->member_key_len[0] = ckey.length;
    }

    /* SERVICE body. */
    (void)memset(&svc_body, 0, sizeof(svc_body));
    svc_body.service_key_raw = ws->service_raw;
    svc_body.service_key_raw_length = (uint16_t)ws->service_raw_len;
    svc_body.descriptor_revision = descriptor->descriptor_revision;
    (void)memcpy(
        svc_body.descriptor_digest, descriptor->descriptor_digest.bytes, 32u);
    (void)memcpy(
        svc_body.local_application_instance_id,
        descriptor->local_application_instance_id.bytes,
        16u);
    st = fill_text_id(&svc_body.namespace_id, descriptor->namespace_id);
    if (st != NINLIL_OK) {
        return st;
    }
    st = fill_text_id(&svc_body.service_id, descriptor->service_id);
    if (st != NINLIL_OK) {
        return st;
    }
    st = fill_text_id(&svc_body.schema_id, descriptor->schema_id);
    if (st != NINLIL_OK) {
        return st;
    }
    svc_body.schema_major = descriptor->schema_major;
    svc_body.minor_min = descriptor->schema_minor_min;
    svc_body.minor_max = descriptor->schema_minor_max;
    svc_body.family = (uint32_t)descriptor->family;
    svc_body.direction = (uint32_t)descriptor->direction;
    svc_body.admission_authority = (uint32_t)descriptor->admission_authority;
    svc_body.apply_contract = (uint32_t)descriptor->apply_contract;
    svc_body.custody_policy = (uint32_t)descriptor->custody_policy;
    svc_body.supported_evidence_mask = descriptor->supported_evidence_mask;
    svc_body.logical_payload_limit = descriptor->logical_payload_limit;
    svc_body.target_limit = descriptor->target_limit;
    svc_body.inflight_limit = descriptor->inflight_limit;
    svc_body.attempts_per_cycle = descriptor->max_attempts_per_target_per_cycle;
    svc_body.admission_window_ms = descriptor->admission_window_ms;
    svc_body.max_admissions_window = descriptor->max_admissions_per_window;
    svc_body.max_payload_window = descriptor->max_payload_bytes_per_window;
    svc_body.minimum_deadline_ms = descriptor->minimum_deadline_ms;
    svc_body.maximum_deadline_ms = descriptor->maximum_deadline_ms;
    svc_body.maximum_evidence_grace_ms = descriptor->maximum_evidence_grace_ms;
    svc_body.attempt_receipt_timeout_ms = descriptor->attempt_receipt_timeout_ms;
    svc_body.retry_backoff_ms = descriptor->retry_backoff_ms;
    svc_body.application_completion_timeout_ms =
        descriptor->application_completion_timeout_ms;
    svc_body.required_dedup_window_ms = descriptor->required_dedup_window_ms;
    (void)memcpy(svc_body.quota_key_digest, quota_kd.bytes, 32u);
    (void)memcpy(svc_body.reservation_key_digest, res_kd.bytes, 32u);
    body_len = 0u;
    st = ninlil_model_domain_encode_body_service(
        &svc_body, body_buf, sizeof(body_buf), &body_len);
    if (st != NINLIL_OK) {
        return st;
    }
    st = encode_domain_record(
        0x10u,
        1u,
        service_id_comp.bytes,
        witness.bytes,
        zero32,
        body_buf,
        body_len,
        ws->member_value[1],
        sizeof(ws->member_value[1]),
        &ws->member_value_len[1]);
    if (st != NINLIL_OK) {
        return st;
    }
    (void)memcpy(ws->member_key[1], skey.bytes, skey.length);
    ws->member_key_len[1] = skey.length;
    st = ninlil_model_domain_sha256(
        ws->member_value[1], ws->member_value_len[1], &service_value_dig);
    if (st != NINLIL_OK) {
        return st;
    }

    /* QUOTA. */
    (void)memset(&quota_body, 0, sizeof(quota_body));
    quota_body.service_key_raw = ws->service_raw;
    quota_body.service_key_raw_length = (uint16_t)ws->service_raw_len;
    (void)memcpy(quota_body.service_key_digest, service_kd.bytes, 32u);
    (void)memcpy(
        quota_body.window_clock_epoch,
        trusted_clock->clock_epoch_id.bytes,
        16u);
    if (descriptor->admission_window_ms == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    window_start = (trusted_clock->now_ms / descriptor->admission_window_ms)
        * (uint64_t)descriptor->admission_window_ms;
    quota_body.window_start_ms = window_start;
    body_len = 0u;
    st = ninlil_model_domain_encode_body_service_quota(
        &quota_body, body_buf, sizeof(body_buf), &body_len);
    if (st != NINLIL_OK) {
        return st;
    }
    st = encode_domain_record(
        0x11u,
        1u,
        service_id_comp.bytes,
        witness.bytes,
        service_value_dig.bytes,
        body_buf,
        body_len,
        ws->member_value[2],
        sizeof(ws->member_value[2]),
        &ws->member_value_len[2]);
    if (st != NINLIL_OK) {
        return st;
    }
    (void)memcpy(ws->member_key[2], qkey.bytes, qkey.length);
    ws->member_key_len[2] = qkey.length;

    /* RESERVATION. */
    (void)memset(&res_body, 0, sizeof(res_body));
    res_body.owner_kind = 1u;
    res_body.owner_key_raw = ws->service_raw;
    res_body.owner_key_raw_length = (uint16_t)ws->service_raw_len;
    (void)memcpy(res_body.primary_key_digest, service_kd.bytes, 32u);
    res_body.resources.used[0] = 1u; /* kind 1 SERVICE used=1 */
    body_len = 0u;
    st = ninlil_model_domain_encode_body_reservation(
        &res_body, body_buf, sizeof(body_buf), &body_len);
    if (st != NINLIL_OK) {
        return st;
    }
    st = encode_domain_record(
        0x23u,
        1u,
        service_id_comp.bytes,
        witness.bytes,
        service_value_dig.bytes,
        body_buf,
        body_len,
        ws->member_value[3],
        sizeof(ws->member_value[3]),
        &ws->member_value_len[3]);
    if (st != NINLIL_OK) {
        return st;
    }
    (void)memcpy(ws->member_key[3], rkey.bytes, rkey.length);
    ws->member_key_len[3] = rkey.length;

    /*
     * Restart reattach is a read-only proof, not a second SERVICE_REGISTER.
     * The exact service/reservation values and all seven durable keys are
     * sufficient for the classifier below.  Do not synthesize a no-op
     * REPLACE witness (capacity/head old == new), which is not a valid
     * operation manifest and must never be committed.
     */
    if (increment_capacity == 0u) {
        ninlil_model_domain_digest_t chunk_identity;
        ninlil_model_domain_key_t chunk_key;
        ninlil_model_domain_key_t header_key;
        uint8_t chunk_components[34];

        (void)memcpy(ws->member_key[4], hkey.bytes, hkey.length);
        ws->member_key_len[4] = hkey.length;

        (void)memcpy(chunk_components, witness.bytes, 32u);
        chunk_components[32] = 0u;
        chunk_components[33] = 0u;
        st = ninlil_model_domain_composite_digest(
            NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK,
            (ninlil_bytes_view_t){chunk_components, sizeof(chunk_components)},
            &chunk_identity);
        if (st != NINLIL_OK) {
            return st;
        }
        id_view.data = chunk_identity.bytes;
        id_view.length = 32u;
        st = ninlil_model_domain_build_key(
            NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
            NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK,
            NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
            id_view,
            &chunk_key);
        if (st != NINLIL_OK) {
            return st;
        }
        id_view.data = witness.bytes;
        st = ninlil_model_domain_build_key(
            NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
            NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER,
            NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
            id_view,
            &header_key);
        if (st != NINLIL_OK) {
            return st;
        }
        (void)memcpy(
            ws->member_key[5], chunk_key.bytes, chunk_key.length);
        ws->member_key_len[5] = chunk_key.length;
        (void)memcpy(
            ws->member_key[6], header_key.bytes, header_key.length);
        ws->member_key_len[6] = header_key.length;
        return NINLIL_OK;
    }

    /* HEAD_INDEX WITNESSED rev 2. */
    (void)memset(&head_body, 0, sizeof(head_body));
    head_body.index_state = NINLIL_MODEL_DOMAIN_INDEX_STATE_WITNESSED;
    (void)memcpy(head_body.member_key_digest, capacity_kd.bytes, 32u);
    head_body.member_key_length = (uint16_t)ckey.length;
    head_body.member_key_bytes = ckey.bytes;
    st = ninlil_model_domain_sha256(
        ws->member_value[0], ws->member_value_len[0], &dig);
    if (st != NINLIL_OK) {
        return st;
    }
    (void)memcpy(head_body.member_value_digest, dig.bytes, 32u);
    (void)memcpy(head_body.member_head_witness_digest, witness.bytes, 32u);
    body_len = 0u;
    st = ninlil_model_domain_encode_body_witness_head_index(
        &head_body, body_buf, sizeof(body_buf), &body_len);
    if (st != NINLIL_OK) {
        return st;
    }
    st = encode_domain_record(
        0x7du,
        2u,
        head_id_comp.bytes,
        witness.bytes,
        zero32,
        body_buf,
        body_len,
        ws->member_value[4],
        sizeof(ws->member_value[4]),
        &ws->member_value_len[4]);
    if (st != NINLIL_OK) {
        return st;
    }
    (void)memcpy(ws->member_key[4], hkey.bytes, hkey.length);
    ws->member_key_len[4] = hkey.length;
    (void)memcpy(ws->service_key_digest, service_kd.bytes, 32u);
    (void)memcpy(ws->witness, witness.bytes, 32u);

    /* ACTIVE WITNESS_MANIFEST_CHUNK + WITNESS_HEADER (post slots 5,6). */
    {
        ninlil_model_domain_witness_chunk_t chunk;
        ninlil_model_domain_witness_header_t wh;
        ninlil_model_domain_digest_t digests[5];
        ninlil_model_domain_digest_t manifest_dig;
        ninlil_model_domain_digest_t canon_dig;
        ninlil_model_domain_digest_t chunk_identity;
        ninlil_model_domain_manifest_digest_ctx_t mctx;
        uint8_t chunk_components[34];
        uint32_t order[5];
        uint32_t oi;
        uint32_t oj;
        ninlil_bytes_view_t body_view;
        ninlil_bytes_view_t op_id;

        for (oi = 0u; oi < 5u; ++oi) {
            st = ninlil_model_domain_sha256(
                ws->member_value[oi], ws->member_value_len[oi], &digests[oi]);
            if (st != NINLIL_OK) {
                return st;
            }
            order[oi] = oi;
        }
        /* Lexicographic key order for manifest entries. */
        for (oi = 1u; oi < 5u; ++oi) {
            uint32_t key_i = order[oi];
            oj = oi;
            while (oj > 0u) {
                uint32_t left = order[oj - 1u];
                uint32_t kl = ws->member_key_len[left];
                uint32_t kr = ws->member_key_len[key_i];
                uint32_t n = kl < kr ? kl : kr;
                int cmp = memcmp(
                    ws->member_key[left], ws->member_key[key_i], n);
                if (cmp < 0 || (cmp == 0 && kl <= kr)) {
                    break;
                }
                order[oj] = left;
                oj -= 1u;
            }
            order[oj] = key_i;
        }

        (void)memset(&chunk, 0, sizeof(chunk));
        (void)memcpy(chunk.witness_digest, witness.bytes, 32u);
        chunk.chunk_index = 0u;
        chunk.chunk_count = 1u;
        chunk.entry_count = 5u;
        for (oi = 0u; oi < 5u; ++oi) {
            uint32_t mi = order[oi];
            ninlil_model_domain_witness_entry_t *e = &chunk.entries[oi];
            e->record_role = record_role_for_key(
                ws->member_key[mi], ws->member_key_len[mi]);
            e->action =
                (mi == 0u || mi == 4u)
                ? NINLIL_MODEL_DOMAIN_WITNESS_ACTION_REPLACE
                : NINLIL_MODEL_DOMAIN_WITNESS_ACTION_CREATE;
            e->key_length = (uint16_t)ws->member_key_len[mi];
            e->key_bytes = ws->member_key[mi];
            if (e->action == NINLIL_MODEL_DOMAIN_WITNESS_ACTION_CREATE) {
                e->old_present = 0u;
                e->new_present = 1u;
            } else {
                e->old_present = 1u;
                e->new_present = 1u;
                if (mi == 0u) {
                    st = ninlil_model_domain_sha256(
                        ws->old_capacity_value,
                        ws->old_capacity_value_len,
                        &dig);
                    if (st != NINLIL_OK) {
                        return st;
                    }
                    (void)memcpy(e->old_value_digest, dig.bytes, 32u);
                } else if (
                    mi == 4u && ws->old_head_value_len > 0u) {
                    st = ninlil_model_domain_sha256(
                        ws->old_head_value,
                        ws->old_head_value_len,
                        &dig);
                    if (st != NINLIL_OK) {
                        return st;
                    }
                    (void)memcpy(e->old_value_digest, dig.bytes, 32u);
                }
            }
            (void)memcpy(
                e->new_value_digest, digests[mi].bytes, 32u);
        }
        st = ninlil_model_domain_encode_witness_chunk(
            &chunk,
            ws->chunk_body,
            sizeof(ws->chunk_body),
            &ws->chunk_body_len);
        if (st != NINLIL_OK) {
            return st;
        }
        st = ninlil_model_domain_manifest_digest_init(&mctx);
        if (st != NINLIL_OK) {
            return st;
        }
        st = ninlil_model_domain_manifest_digest_update(
            &mctx,
            (ninlil_bytes_view_t){ws->chunk_body, ws->chunk_body_len});
        if (st != NINLIL_OK) {
            return st;
        }
        st = ninlil_model_domain_manifest_digest_final(&mctx, &manifest_dig);
        if (st != NINLIL_OK) {
            return st;
        }
        (void)memcpy(chunk_components, witness.bytes, 32u);
        chunk_components[32] = 0u;
        chunk_components[33] = 0u;
        st = ninlil_model_domain_composite_digest(
            NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK,
            (ninlil_bytes_view_t){chunk_components, 34u},
            &chunk_identity);
        if (st != NINLIL_OK) {
            return st;
        }
        body_view.data = ws->chunk_body;
        body_view.length = ws->chunk_body_len;
        st = encode_witness_envelope(
            NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK,
            chunk_identity.bytes,
            body_view,
            ws->member_key[5],
            &ws->member_key_len[5],
            ws->member_value[5],
            sizeof(ws->member_value[5]),
            &ws->member_value_len[5]);
        if (st != NINLIL_OK) {
            return st;
        }

        (void)memset(&wh, 0, sizeof(wh));
        wh.operation_kind = 1u;
        wh.witness_state = NINLIL_MODEL_DOMAIN_WITNESS_STATE_ACTIVE;
        wh.operation_identity_length = 32u;
        (void)memcpy(wh.operation_identity, service_kd.bytes, 32u);
        (void)memcpy(wh.subject_id, service_kd.bytes, 16u);
        wh.member_count = 5u;
        wh.chunk_count = 1u;
        (void)memcpy(wh.manifest_digest, manifest_dig.bytes, 32u);
        wh.retention_kind = 0u;
        op_id.data = service_kd.bytes;
        op_id.length = 32u;
        st = ninlil_model_domain_canonical_operation_digest(
            1u,
            op_id,
            wh.subject_id,
            wh.manifest_digest,
            wh.retention_kind,
            wh.retention_subject_key_digest,
            &canon_dig);
        if (st != NINLIL_OK) {
            return st;
        }
        (void)memcpy(wh.canonical_digest, canon_dig.bytes, 32u);
        st = ninlil_model_domain_encode_witness_header(
            &wh,
            ws->header_body,
            sizeof(ws->header_body),
            &ws->header_body_len);
        if (st != NINLIL_OK) {
            return st;
        }
        body_view.data = ws->header_body;
        body_view.length = ws->header_body_len;
        st = encode_witness_envelope(
            NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER,
            witness.bytes,
            body_view,
            ws->member_key[6],
            &ws->member_key_len[6],
            ws->member_value[6],
            sizeof(ws->member_value[6]),
            &ws->member_value_len[6]);
        if (st != NINLIL_OK) {
            return st;
        }
    }

    /* Seal M=5 plan + 7 post-record inventory. */
    {
        uint8_t digests[5][32];
        uint32_t mi;
        for (mi = 0u; mi < 5u; ++mi) {
            st = ninlil_model_domain_sha256(
                ws->member_value[mi],
                ws->member_value_len[mi],
                &dig);
            if (st != NINLIL_OK) {
                return st;
            }
            (void)memcpy(digests[mi], dig.bytes, 32u);
        }
        st = ninlil_domain_schema1_kind1_build_plan(
            ws->member_key[0],
            ws->member_key_len[0],
            digests[0],
            ws->member_key[1],
            ws->member_key_len[1],
            digests[1],
            ws->member_key[2],
            ws->member_key_len[2],
            digests[2],
            ws->member_key[3],
            ws->member_key_len[3],
            digests[3],
            ws->member_key[4],
            ws->member_key_len[4],
            digests[4],
            service_kd.bytes,
            &ws->plan);
        if (st != NINLIL_OK) {
            return st;
        }
        ws->plan.post_record_count = NINLIL_DOMAIN_SCHEMA1_KIND1_POST_RECORD_COUNT;
        for (mi = 0u; mi < NINLIL_DOMAIN_SCHEMA1_KIND1_POST_RECORD_COUNT; ++mi) {
            ninlil_domain_schema1_kind1_post_record_t *pr =
                &ws->plan.post_records[mi];
            (void)memset(pr, 0, sizeof(*pr));
            if (mi < 5u) {
                pr->action =
                    (mi == 0u || mi == 4u)
                    ? NINLIL_DOMAIN_SCHEMA1_KIND1_ACTION_REPLACE
                    : NINLIL_DOMAIN_SCHEMA1_KIND1_ACTION_CREATE;
            } else {
                pr->action = NINLIL_DOMAIN_SCHEMA1_KIND1_ACTION_CREATE;
            }
            (void)memcpy(pr->key, ws->member_key[mi], ws->member_key_len[mi]);
            pr->key_length = ws->member_key_len[mi];
            st = ninlil_model_domain_sha256(
                ws->member_value[mi], ws->member_value_len[mi], &dig);
            if (st != NINLIL_OK) {
                return st;
            }
            (void)memcpy(pr->post_value_digest, dig.bytes, 32u);
            if (mi == 0u) {
                st = ninlil_model_domain_sha256(
                    ws->old_capacity_value,
                    ws->old_capacity_value_len,
                    &dig);
                if (st != NINLIL_OK) {
                    return st;
                }
                (void)memcpy(pr->pre_value_digest, dig.bytes, 32u);
            } else if (mi == 4u && ws->old_head_value_len > 0u) {
                st = ninlil_model_domain_sha256(
                    ws->old_head_value, ws->old_head_value_len, &dig);
                if (st != NINLIL_OK) {
                    return st;
                }
                (void)memcpy(pr->pre_value_digest, dig.bytes, 32u);
            }
        }
        st = ninlil_domain_schema1_kind1_plan_finish(&ws->plan);
        if (st != NINLIL_OK) {
            return st;
        }
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_schema1_kind1_commit_full(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_domain_schema1_kind1_workspace_t *ws,
    ninlil_domain_schema1_kind1_register_result_t *out_result)
{
    ninlil_status_t st;
    ninlil_storage_canonical_view_t begin_view;
    ninlil_storage_canonical_view_t final_view;
    ninlil_storage_canonical_result_t apply;
    ninlil_storage_status_t sst;
    uint32_t i;
    uint32_t m;

    if (out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    out_result->class = NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
    if (storage == NULL || inout_handle == NULL || *inout_handle == NULL
        || ws == NULL || ws->plan.member_count != 5u
        || ws->plan.post_record_count
            != NINLIL_DOMAIN_SCHEMA1_KIND1_POST_RECORD_COUNT) {
        out_result->status = NINLIL_E_INVALID_ARGUMENT;
        return NINLIL_E_INVALID_ARGUMENT;
    }

    st = scan_ns(storage, *inout_handle, ws);
    if (st != NINLIL_OK) {
        out_result->status = st;
        return st;
    }

    /* begin = all current rows. */
    for (i = 0u; i < ws->snap_count; ++i) {
        ws->begin_rows[i].key.data = ws->snap_key[i];
        ws->begin_rows[i].key.length = ws->snap_key_len[i];
        ws->begin_rows[i].value.data = ws->snap_value[i];
        ws->begin_rows[i].value.length = ws->snap_value_len[i];
        ws->final_rows[i] = ws->begin_rows[i];
    }
    ws->begin_count = ws->snap_count;
    ws->final_count = ws->snap_count;

    /* Upsert 7 post records (5 members + chunk + header). */
    for (m = 0u; m < NINLIL_DOMAIN_SCHEMA1_KIND1_POST_RECORD_COUNT; ++m) {
        int found = 0;
        for (i = 0u; i < ws->final_count; ++i) {
            if (ws->final_rows[i].key.length == ws->member_key_len[m]
                && memcmp(
                       ws->final_rows[i].key.data,
                       ws->member_key[m],
                       ws->member_key_len[m])
                    == 0) {
                ws->final_rows[i].key.data = ws->member_key[m];
                ws->final_rows[i].key.length = ws->member_key_len[m];
                ws->final_rows[i].value.data = ws->member_value[m];
                ws->final_rows[i].value.length = ws->member_value_len[m];
                found = 1;
                break;
            }
        }
        if (found == 0) {
            if (ws->final_count >= NINLIL_DOMAIN_SCHEMA1_KIND1_NS_ROW_CAP) {
                out_result->status = NINLIL_E_CAPACITY_EXHAUSTED;
                return NINLIL_E_CAPACITY_EXHAUSTED;
            }
            ws->final_rows[ws->final_count].key.data = ws->member_key[m];
            ws->final_rows[ws->final_count].key.length = ws->member_key_len[m];
            ws->final_rows[ws->final_count].value.data = ws->member_value[m];
            ws->final_rows[ws->final_count].value.length =
                ws->member_value_len[m];
            ws->final_count += 1u;
        }
    }
    sort_rows(ws->begin_rows, ws->begin_count);
    sort_rows(ws->final_rows, ws->final_count);

    begin_view.rows = ws->begin_rows;
    begin_view.row_count = ws->begin_count;
    final_view.rows = ws->final_rows;
    final_view.row_count = ws->final_count;
    (void)memset(&apply, 0, sizeof(apply));
    sst = ninlil_storage_canonical_apply(
        storage, *inout_handle, begin_view, final_view, NULL, NULL, &apply);
    if (sst == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        if (storage->close != NULL) {
            storage->close(storage->user, *inout_handle);
            *inout_handle = NULL;
        }
        out_result->reopen_required = 1u;
        out_result->status = NINLIL_E_STORAGE_COMMIT_UNKNOWN;
        /* class stays CORRUPT until readback after reopen. */
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    }
    if (sst != NINLIL_STORAGE_OK) {
        out_result->status = map_storage(sst);
        return out_result->status;
    }
    out_result->wrote = 1u;
    out_result->durable_adopted = 1u;
    out_result->class = NINLIL_DOMAIN_SCHEMA1_GROUP_NEW;
    out_result->status = NINLIL_OK;
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_schema1_kind1_classify_readback(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t handle,
    ninlil_domain_schema1_kind1_workspace_t *ws,
    const ninlil_domain_schema1_snapshot_row_t *pre_rows,
    uint32_t pre_row_count,
    ninlil_domain_schema1_group_class_t *out_class)
{
    ninlil_domain_schema1_snapshot_row_t rows[
        NINLIL_DOMAIN_SCHEMA1_KIND1_NS_ROW_CAP];
    ninlil_status_t st;
    uint32_t i;

    if (out_class == NULL || ws == NULL || storage == NULL || handle == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_class = NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
    st = scan_ns(storage, handle, ws);
    if (st != NINLIL_OK) {
        return st;
    }
    for (i = 0u; i < ws->snap_count; ++i) {
        rows[i].key.data = ws->snap_key[i];
        rows[i].key.length = ws->snap_key_len[i];
        rows[i].value.data = ws->snap_value[i];
        rows[i].value.length = ws->snap_value_len[i];
    }
    return ninlil_domain_schema1_classify_kind1_commit_unknown(
        &ws->plan,
        pre_rows,
        pre_row_count,
        rows,
        ws->snap_count,
        out_class);
}

ninlil_status_t ninlil_domain_schema1_service_register(
    ninlil_runtime_t *runtime,
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_service_callbacks_t *callbacks,
    ninlil_rt_service_slot_t *slot,
    uint32_t free_index,
    uint32_t reattach_only_candidate,
    ninlil_domain_schema1_kind1_register_result_t *out_result)
{
    ninlil_domain_schema1_kind1_workspace_t *ws = NULL;
    ninlil_status_t st;
    ninlil_time_sample_t sample;
    ninlil_model_runtime_store_capacity_t cap0;
    uint8_t old_cap[NINLIL_MODEL_RUNTIME_STORE_CAPACITY_VALUE_BYTES];
    uint32_t old_cap_len = 0u;
    ninlil_domain_schema1_group_class_t cls;

    (void)free_index;
    if (out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    out_result->class = NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
    if (runtime == NULL || descriptor == NULL || callbacks == NULL || slot == NULL
        || runtime->platform == NULL || runtime->platform->storage == NULL
        || runtime->platform->allocator == NULL
        || runtime->platform->allocator->allocate == NULL
        || runtime->platform->clock == NULL
        || reattach_only_candidate > 1u) {
        out_result->status = NINLIL_E_INVALID_ARGUMENT;
        return NINLIL_E_INVALID_ARGUMENT;
    }

    ws = runtime->platform->allocator->allocate(
        runtime->platform->allocator->user,
        sizeof(*ws),
        (uint32_t)alignof(ninlil_domain_schema1_kind1_workspace_t));
    if (ws == NULL) {
        out_result->status = NINLIL_E_CAPACITY_EXHAUSTED;
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }
    (void)memset(ws, 0, sizeof(*ws));

    /* Trusted clock sample for quota window. */
    {
        (void)memset(&sample, 0, sizeof(sample));
        ninlil_port_status_t pst = runtime->platform->clock->now(
            runtime->platform->clock->user, &sample);
        if (pst == NINLIL_PORT_TEMPORARY_FAILURE
            || (pst == NINLIL_PORT_OK
                && sample.abi_version == NINLIL_ABI_VERSION
                && sample.struct_size == sizeof(sample)
                && sample.trust == NINLIL_CLOCK_UNCERTAIN
                && clock_epoch_nonzero(&sample.clock_epoch_id)
                && sample.reserved_zero == 0u)) {
            st = NINLIL_E_CLOCK_UNCERTAIN;
            goto out;
        }
        if (pst != NINLIL_PORT_OK
            || sample.abi_version != NINLIL_ABI_VERSION
            || sample.struct_size != sizeof(sample)
            || sample.trust != NINLIL_CLOCK_TRUSTED
            || !clock_epoch_nonzero(&sample.clock_epoch_id)
            || sample.reserved_zero != 0u) {
            st = NINLIL_E_DEGRADED;
            goto out;
        }
        st = ninlil_rt_accept_trusted_clock_sample(runtime, &sample);
        if (st != NINLIL_OK) {
            goto out;
        }
    }

    /*
     * Load real SERVICE capacity from the namespace (bootstrap used=0 is only
     * a fallback when the capacity key is absent — that is corrupt post-T1a).
     * Reattach must not invent used=0→1; that double-bumps capacity on restart.
     */
    st = scan_ns(runtime->platform->storage, runtime->storage, ws);
    if (st != NINLIL_OK) {
        goto out;
    }
    {
        uint32_t i;
        int found_cap = 0;
        int found_head = 0;
        uint8_t old_head[NINLIL_DOMAIN_SCHEMA1_KIND1_MEMBER_VALUE_CAP];
        uint32_t old_head_len = 0u;

        for (i = 0u; i < ws->snap_count; ++i) {
            if (ws->snap_key_len[i] == 10u
                && ws->snap_key[i][8] == 0x04u
                && ws->snap_key[i][9] == 0x01u) {
                if (ws->snap_value_len[i]
                    > NINLIL_MODEL_RUNTIME_STORE_CAPACITY_VALUE_BYTES) {
                    st = NINLIL_E_STORAGE_CORRUPT;
                    goto out;
                }
                (void)memcpy(
                    old_cap, ws->snap_value[i], ws->snap_value_len[i]);
                old_cap_len = ws->snap_value_len[i];
                found_cap = 1;
            }
            if (ws->snap_key_len[i] >= 10u
                && ws->snap_key[i][8] == 0x06u
                && ws->snap_key[i][9] == 0x7du) {
                if (ws->snap_value_len[i]
                    > NINLIL_DOMAIN_SCHEMA1_KIND1_MEMBER_VALUE_CAP) {
                    st = NINLIL_E_STORAGE_CORRUPT;
                    goto out;
                }
                (void)memcpy(
                    old_head, ws->snap_value[i], ws->snap_value_len[i]);
                old_head_len = ws->snap_value_len[i];
                found_head = 1;
            }
        }
        if (found_cap == 0) {
            (void)memset(&cap0, 0, sizeof(cap0));
            cap0.kind = NINLIL_RESOURCE_SERVICE;
            cap0.limit = runtime->config.limits.max_services;
            cap0.used = 0u;
            cap0.reserved = 0u;
            cap0.high_water = 0u;
            cap0.capacity_epoch = 1u;
            st = ninlil_model_runtime_store_encode_capacity(
                NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
                &cap0,
                old_cap,
                sizeof(old_cap),
                &old_cap_len);
            if (st != NINLIL_OK) {
                goto out;
            }
        }
        st = ninlil_domain_schema1_kind1_encode_members(
            descriptor,
            &sample,
            old_cap,
            old_cap_len,
            found_head != 0 ? old_head : NULL,
            old_head_len,
            reattach_only_candidate == 0u ? 1u : 0u,
            ws);
        if (st != NINLIL_OK) {
goto out;
        }
    }

    /*
     * Reattach full group truth for this service:
     * - SERVICE / RESERVATION exact post digests (identity-stable primaries)
     * - SERVICE_QUOTA: key present + CURRENT only — body counters and window
     *   advance on admit REPLACE and clock roll; never pin to re-encoded
     *   register-zero digest
     * - ACTIVE header + chunk keys present (W-keyed) with D1-current values
     * - capacity + HEAD_INDEX keys present (shared; digests may advance)
     * Capacity/head digests are not pinned to a used+1 re-encode after later
     * multi-service registers.
     */
    {
        const uint32_t exact_idx[3] = {1u, 2u, 3u};
        const uint32_t witness_idx[2] = {5u, 6u};
        const uint32_t shared_idx[2] = {0u, 4u};
        uint32_t gi;
        uint32_t exact_hits = 0u;
        uint32_t witness_hits = 0u;
        uint32_t shared_hits = 0u;
        uint32_t thirds = 0u;
        for (gi = 0u; gi < 3u; ++gi) {
            uint32_t mi = exact_idx[gi];
            uint32_t si;
            ninlil_model_domain_digest_t expected;
            ninlil_model_domain_digest_t stored;
            int found = 0;

            /*
             * QUOTA (member index 2) is secondary and mutates under admit.
             * Match by key + CURRENT classification, not register-time digest.
             */
            if (mi == 2u) {
                for (si = 0u; si < ws->snap_count; ++si) {
                    ninlil_model_domain_key_class_t kc;
                    if (ws->snap_key_len[si] != ws->member_key_len[mi]
                        || memcmp(
                               ws->snap_key[si],
                               ws->member_key[mi],
                               ws->member_key_len[mi])
                            != 0) {
                        continue;
                    }
                    found = 1;
                    st = ninlil_model_domain_classify_row(
                        (ninlil_bytes_view_t){
                            ws->snap_key[si], ws->snap_key_len[si]},
                        (ninlil_bytes_view_t){
                            ws->snap_value[si], ws->snap_value_len[si]},
                        &kc);
                    if (st != NINLIL_OK
                        || kc != NINLIL_MODEL_DOMAIN_KEY_CLASS_CURRENT) {
                        thirds += 1u;
                    } else {
                        exact_hits += 1u;
                    }
                    break;
                }
                (void)found;
                continue;
            }

            st = ninlil_model_domain_sha256(
                ws->member_value[mi], ws->member_value_len[mi], &expected);
            if (st != NINLIL_OK) {
                goto out;
            }
            for (si = 0u; si < ws->snap_count; ++si) {
                if (ws->snap_key_len[si] != ws->member_key_len[mi]
                    || memcmp(
                           ws->snap_key[si],
                           ws->member_key[mi],
                           ws->member_key_len[mi])
                        != 0) {
                    continue;
                }
                found = 1;
                st = ninlil_model_domain_sha256(
                    ws->snap_value[si], ws->snap_value_len[si], &stored);
                if (st != NINLIL_OK) {
                    goto out;
                }
                if (memcmp(stored.bytes, expected.bytes, 32u) == 0) {
                    exact_hits += 1u;
                } else {
                    thirds += 1u;
                }
                break;
            }
            (void)found;
        }
        for (gi = 0u; gi < 2u; ++gi) {
            uint32_t mi = witness_idx[gi];
            uint32_t si;
            for (si = 0u; si < ws->snap_count; ++si) {
                ninlil_model_domain_key_class_t kc;
                if (ws->snap_key_len[si] != ws->member_key_len[mi]
                    || memcmp(
                           ws->snap_key[si],
                           ws->member_key[mi],
                           ws->member_key_len[mi])
                        != 0) {
                    continue;
                }
                st = ninlil_model_domain_classify_row(
                    (ninlil_bytes_view_t){
                        ws->snap_key[si], ws->snap_key_len[si]},
                    (ninlil_bytes_view_t){
                        ws->snap_value[si], ws->snap_value_len[si]},
                    &kc);
                if (st != NINLIL_OK
                    || kc != NINLIL_MODEL_DOMAIN_KEY_CLASS_CURRENT) {
                    thirds += 1u;
                } else {
                    witness_hits += 1u;
                }
                break;
            }
        }
        for (gi = 0u; gi < 2u; ++gi) {
            uint32_t mi = shared_idx[gi];
            uint32_t si;
            for (si = 0u; si < ws->snap_count; ++si) {
                if (ws->snap_key_len[si] == ws->member_key_len[mi]
                    && memcmp(
                           ws->snap_key[si],
                           ws->member_key[mi],
                           ws->member_key_len[mi])
                        == 0
                    && ws->snap_value_len[si] > 0u) {
                    shared_hits += 1u;
                    break;
                }
            }
        }
        if (thirds != 0u) {
            out_result->class = NINLIL_DOMAIN_SCHEMA1_GROUP_THIRD;
            out_result->status = NINLIL_E_STORAGE_CORRUPT;
            st = NINLIL_E_STORAGE_CORRUPT;
            goto out;
        }
        if (exact_hits == 3u && witness_hits == 2u && shared_hits == 2u) {
            out_result->class = NINLIL_DOMAIN_SCHEMA1_GROUP_NEW;
            out_result->reattach_only = 1u;
            out_result->durable_adopted = 1u;
            out_result->wrote = 0u;
            out_result->status = NINLIL_OK;
            st = NINLIL_OK;
            goto out;
        }
        /*
         * Capacity/head always exist post-T5; shared_hits alone is not
         * reattach. PARTIAL only when service-group members partially present.
         */
        if (exact_hits > 0u || witness_hits > 0u) {
            out_result->class = NINLIL_DOMAIN_SCHEMA1_GROUP_PARTIAL;
            out_result->status = NINLIL_E_STORAGE_CORRUPT;
            st = NINLIL_E_STORAGE_CORRUPT;
            goto out;
        }
    }

    if (reattach_only_candidate != 0u) {
        out_result->class = NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
        out_result->status = NINLIL_E_STORAGE_CORRUPT;
        st = NINLIL_E_STORAGE_CORRUPT;
        goto out;
    }

    st = ninlil_domain_schema1_kind1_commit_full(
        runtime->platform->storage, &runtime->storage, ws, out_result);
    if (st == NINLIL_E_STORAGE_COMMIT_UNKNOWN) {
        runtime->commit_unknown_fence = 1u;
        goto out;
    }
    if (st != NINLIL_OK) {
goto out;
    }

    st = ninlil_domain_schema1_kind1_classify_readback(
        runtime->platform->storage,
        runtime->storage,
        ws,
        NULL,
        0u,
        &cls);
    if (st != NINLIL_OK || cls != NINLIL_DOMAIN_SCHEMA1_GROUP_NEW) {
out_result->class =
            (st == NINLIL_OK) ? cls : NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
        out_result->status = NINLIL_E_STORAGE_CORRUPT;
        st = NINLIL_E_STORAGE_CORRUPT;
        goto out;
    }
    out_result->class = cls;
    out_result->durable_adopted = 1u;
    out_result->status = NINLIL_OK;
    st = NINLIL_OK;

out:
    if (ws != NULL && runtime->platform->allocator->deallocate != NULL) {
        runtime->platform->allocator->deallocate(
            runtime->platform->allocator->user,
            ws,
            sizeof(*ws),
            (uint32_t)alignof(ninlil_domain_schema1_kind1_workspace_t));
    }
    (void)callbacks;
    (void)slot;
    return st;
}

static int service_identity_equal(
    const ninlil_service_descriptor_t *left,
    const ninlil_service_descriptor_t *right)
{
    if (left == NULL || right == NULL) {
        return 0;
    }
    return left->namespace_id.length == right->namespace_id.length
        && left->service_id.length == right->service_id.length
        && left->descriptor_revision == right->descriptor_revision
        && memcmp(
               left->local_application_instance_id.bytes,
               right->local_application_instance_id.bytes,
               16u)
            == 0
        && memcmp(
               left->namespace_id.data,
               right->namespace_id.data,
               left->namespace_id.length)
            == 0
        && memcmp(
               left->service_id.data,
               right->service_id.data,
               left->service_id.length)
            == 0
        && memcmp(
               left->descriptor_digest.bytes,
               right->descriptor_digest.bytes,
               32u)
            == 0;
}

ninlil_status_t ninlil_domain_schema1_service_registry_restore(
    ninlil_runtime_t *runtime)
{
    ninlil_domain_schema1_kind1_workspace_t *ws = NULL;
    ninlil_status_t st;
    uint32_t i;
    uint32_t j;

    if (runtime == NULL || runtime->platform == NULL
        || runtime->platform->storage == NULL
        || runtime->platform->allocator == NULL
        || runtime->platform->allocator->allocate == NULL
        || runtime->services == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ws = runtime->platform->allocator->allocate(
        runtime->platform->allocator->user,
        sizeof(*ws),
        (uint32_t)alignof(ninlil_domain_schema1_kind1_workspace_t));
    if (ws == NULL) {
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }
    (void)memset(ws, 0, sizeof(*ws));
    st = scan_ns(runtime->platform->storage, runtime->storage, ws);
    if (st != NINLIL_OK) {
        goto out;
    }
    /* Pass 1: SERVICE rows → unattached slots. */
    for (i = 0u; i < ws->snap_count; ++i) {
        ninlil_model_domain_envelope_t env;
        ninlil_model_domain_body_service_t body;
        ninlil_bytes_view_t key_view;
        ninlil_bytes_view_t val_view;
        ninlil_model_domain_key_class_t kc;
        ninlil_rt_service_slot_t *slot = NULL;
        uint32_t free_index;
        ninlil_status_t dst;

        key_view.data = ws->snap_key[i];
        key_view.length = ws->snap_key_len[i];
        val_view.data = ws->snap_value[i];
        val_view.length = ws->snap_value_len[i];
        if (key_view.length < 10u || key_view.data[8] != 0x06u
            || key_view.data[9] != 0x10u) {
            continue;
        }
        dst = ninlil_model_domain_classify_row(key_view, val_view, &kc);
        if (dst != NINLIL_OK
            || kc != NINLIL_MODEL_DOMAIN_KEY_CLASS_CURRENT) {
            st = NINLIL_E_STORAGE_CORRUPT;
            goto out;
        }
        (void)memset(&env, 0, sizeof(env));
        dst = ninlil_model_domain_decode_envelope(val_view, &env);
        if (dst != NINLIL_OK || env.header.subtype != 0x10u) {
            st = NINLIL_E_STORAGE_CORRUPT;
            goto out;
        }
        (void)memset(&body, 0, sizeof(body));
        dst = ninlil_model_domain_decode_body_service(env.body, &body);
        if (dst != NINLIL_OK) {
            st = NINLIL_E_STORAGE_CORRUPT;
            goto out;
        }
        for (free_index = 0u; free_index < runtime->service_capacity;
             ++free_index) {
            if (runtime->services[free_index].in_use == 0u) {
                slot = &runtime->services[free_index];
                break;
            }
        }
        if (slot == NULL) {
            st = NINLIL_E_CAPACITY_EXHAUSTED;
            goto out;
        }
        (void)memset(slot, 0, sizeof(*slot));
        slot->in_use = 1u;
        slot->attached = 0u;
        slot->descriptor.abi_version = NINLIL_ABI_VERSION;
        slot->descriptor.struct_size =
            (uint16_t)sizeof(slot->descriptor);
        /* Populate descriptor from body (volatile callbacks remain zero). */
        slot->descriptor.descriptor_revision = body.descriptor_revision;
        slot->descriptor.descriptor_digest.algorithm = NINLIL_DIGEST_SHA256;
        (void)memcpy(
            slot->descriptor.descriptor_digest.bytes,
            body.descriptor_digest,
            32u);
        (void)memcpy(
            slot->descriptor.local_application_instance_id.bytes,
            body.local_application_instance_id,
            16u);
        if (body.namespace_id.length == 0u
            || body.namespace_id.length > sizeof(slot->owned_namespace)
            || body.service_id.length == 0u
            || body.service_id.length > sizeof(slot->owned_service_id)
            || body.schema_id.length == 0u
            || body.schema_id.length > sizeof(slot->owned_schema_id)
            || body.admission_window_ms == 0u) {
            st = NINLIL_E_STORAGE_CORRUPT;
            goto out;
        }
        (void)memcpy(
            slot->owned_namespace,
            body.namespace_id.bytes,
            body.namespace_id.length);
        slot->descriptor.namespace_id.data = slot->owned_namespace;
        slot->descriptor.namespace_id.length = body.namespace_id.length;
        (void)memcpy(
            slot->owned_service_id,
            body.service_id.bytes,
            body.service_id.length);
        slot->descriptor.service_id.data = slot->owned_service_id;
        slot->descriptor.service_id.length = body.service_id.length;
        (void)memcpy(
            slot->owned_schema_id,
            body.schema_id.bytes,
            body.schema_id.length);
        slot->descriptor.schema_id.data = slot->owned_schema_id;
        slot->descriptor.schema_id.length = body.schema_id.length;
        slot->descriptor.schema_major = body.schema_major;
        slot->descriptor.schema_minor_min = body.minor_min;
        slot->descriptor.schema_minor_max = body.minor_max;
        slot->descriptor.family = (ninlil_family_t)body.family;
        slot->descriptor.direction = (ninlil_direction_t)body.direction;
        slot->descriptor.admission_authority =
            (ninlil_admission_authority_t)body.admission_authority;
        slot->descriptor.apply_contract =
            (ninlil_apply_contract_t)body.apply_contract;
        slot->descriptor.custody_policy =
            (ninlil_custody_policy_t)body.custody_policy;
        slot->descriptor.supported_evidence_mask =
            body.supported_evidence_mask;
        slot->descriptor.logical_payload_limit = body.logical_payload_limit;
        slot->descriptor.target_limit = body.target_limit;
        slot->descriptor.inflight_limit = body.inflight_limit;
        slot->descriptor.max_attempts_per_target_per_cycle =
            body.attempts_per_cycle;
        slot->descriptor.admission_window_ms = body.admission_window_ms;
        slot->descriptor.max_admissions_per_window =
            body.max_admissions_window;
        slot->descriptor.max_payload_bytes_per_window =
            body.max_payload_window;
        slot->descriptor.minimum_deadline_ms = body.minimum_deadline_ms;
        slot->descriptor.maximum_deadline_ms = body.maximum_deadline_ms;
        slot->descriptor.maximum_evidence_grace_ms =
            body.maximum_evidence_grace_ms;
        slot->descriptor.attempt_receipt_timeout_ms =
            body.attempt_receipt_timeout_ms;
        slot->descriptor.retry_backoff_ms = body.retry_backoff_ms;
        slot->descriptor.application_completion_timeout_ms =
            body.application_completion_timeout_ms;
        slot->descriptor.required_dedup_window_ms =
            body.required_dedup_window_ms;
        slot->public_handle.magic = 0u;
        slot->public_handle.runtime = NULL;
        slot->public_handle.slot_index = free_index;
        /* Mark quota unrestored via reserved admissions sentinel (UINT64_MAX). */
        slot->quota_admissions = UINT64_MAX;
        runtime->service_count += 1u;
        /* Exact-duplicate SERVICE identity is corrupt durable truth. */
        for (j = 0u; j < free_index; ++j) {
            if (runtime->services[j].in_use != 0u
                && service_identity_equal(
                    &runtime->services[j].descriptor, &slot->descriptor)) {
                st = NINLIL_E_STORAGE_CORRUPT;
                goto out;
            }
        }
    }

    /* Pass 2: SERVICE_QUOTA rows → admission quota window counters. */
    for (i = 0u; i < ws->snap_count; ++i) {
        ninlil_model_domain_envelope_t env;
        ninlil_model_domain_body_service_quota_t qbody;
        ninlil_bytes_view_t key_view;
        ninlil_bytes_view_t val_view;
        ninlil_model_domain_key_class_t kc;
        ninlil_status_t dst;
        uint32_t matched = 0u;
        ninlil_rt_service_slot_t *slot = NULL;

        key_view.data = ws->snap_key[i];
        key_view.length = ws->snap_key_len[i];
        val_view.data = ws->snap_value[i];
        val_view.length = ws->snap_value_len[i];
        if (key_view.length < 10u || key_view.data[8] != 0x06u
            || key_view.data[9] != 0x11u) {
            continue;
        }
        dst = ninlil_model_domain_classify_row(key_view, val_view, &kc);
        if (dst != NINLIL_OK
            || kc != NINLIL_MODEL_DOMAIN_KEY_CLASS_CURRENT) {
            st = NINLIL_E_STORAGE_CORRUPT;
            goto out;
        }
        (void)memset(&env, 0, sizeof(env));
        dst = ninlil_model_domain_decode_envelope(val_view, &env);
        if (dst != NINLIL_OK || env.header.subtype != 0x11u) {
            st = NINLIL_E_STORAGE_CORRUPT;
            goto out;
        }
        (void)memset(&qbody, 0, sizeof(qbody));
        dst = ninlil_model_domain_decode_body_service_quota(env.body, &qbody);
        if (dst != NINLIL_OK) {
            st = NINLIL_E_STORAGE_CORRUPT;
            goto out;
        }
        for (j = 0u; j < runtime->service_capacity; ++j) {
            ninlil_rt_service_slot_t *cand = &runtime->services[j];
            uint8_t sraw[256];
            uint32_t sraw_len = 0u;

            if (cand->in_use == 0u) {
                continue;
            }
            if (build_service_raw(
                    &cand->descriptor, sraw, sizeof(sraw), &sraw_len)
                != NINLIL_OK) {
                continue;
            }
            /*
             * Prefer exact service_key_raw identity from the QUOTA body
             * (authority for the durable pairing). Digest alone is secondary.
             */
            if (qbody.service_key_raw != NULL
                && qbody.service_key_raw_length == (uint16_t)sraw_len
                && memcmp(qbody.service_key_raw, sraw, sraw_len) == 0) {
                matched += 1u;
                slot = cand;
                continue;
            }
            {
                ninlil_model_domain_digest_t skd;

                if (ninlil_model_domain_sha256(sraw, sraw_len, &skd)
                        == NINLIL_OK
                    && memcmp(skd.bytes, qbody.service_key_digest, 32u)
                        == 0) {
                    matched += 1u;
                    slot = cand;
                }
            }
        }
        if (matched != 1u || slot == NULL) {
            st = NINLIL_E_STORAGE_CORRUPT;
            goto out;
        }
        slot->quota_inflight = qbody.active_transaction_count;
        slot->quota_admissions = qbody.admissions_in_window;
        slot->quota_payload_bytes = qbody.payload_bytes_in_window;
        (void)memcpy(
            slot->quota_window_epoch,
            qbody.window_clock_epoch,
            sizeof(slot->quota_window_epoch));
        slot->quota_window_start_ms = qbody.window_start_ms;
    }
    /* Every restored SERVICE must have exactly one paired QUOTA row. */
    for (j = 0u; j < runtime->service_capacity; ++j) {
        if (runtime->services[j].in_use != 0u
            && runtime->services[j].quota_admissions == UINT64_MAX) {
            st = NINLIL_E_STORAGE_CORRUPT;
            goto out;
        }
    }
    st = NINLIL_OK;
out:
    if (ws != NULL && runtime->platform->allocator->deallocate != NULL) {
        runtime->platform->allocator->deallocate(
            runtime->platform->allocator->user,
            ws,
            sizeof(*ws),
            (uint32_t)alignof(ninlil_domain_schema1_kind1_workspace_t));
    }
    return st;
}

/*
 * Stage Domain SERVICE_QUOTA REPLACE into an open admission FULL txn.
 * When Domain is ON this is the admission quota authority; NRS is co-staged
 * by the caller when present. Header digests match kind-1 register:
 *   head = COMPOSITE(0x7f, u16(op=1) || RAW16(service_key_digest))
 *   PVD  = SHA256(live SERVICE envelope value)
 * SERVICE_QUOTA is secondary: head and PVD must both be non-zero for encode.
 */
ninlil_status_t ninlil_domain_schema1_quota_stage(
    ninlil_runtime_t *runtime,
    ninlil_storage_txn_t txn,
    const ninlil_rt_service_slot_t *slot)
{
    uint8_t service_raw[256];
    uint32_t service_raw_len = 0u;
    uint8_t service_components[260];
    uint32_t sc_len = 0u;
    ninlil_model_domain_digest_t service_kd;
    ninlil_model_domain_digest_t service_id_comp;
    ninlil_model_domain_digest_t quota_id_comp;
    ninlil_model_domain_digest_t witness;
    ninlil_model_domain_digest_t service_value_dig;
    ninlil_model_domain_key_t skey;
    ninlil_model_domain_key_t qkey;
    ninlil_model_domain_body_service_quota_t quota_body;
    uint8_t body_buf[512];
    uint32_t body_len = 0u;
    uint8_t value_buf[NINLIL_DOMAIN_SCHEMA1_KIND1_MEMBER_VALUE_CAP];
    uint32_t value_len = 0u;
    uint8_t service_value[NINLIL_DOMAIN_SCHEMA1_KIND1_MEMBER_VALUE_CAP];
    ninlil_mut_bytes_t service_value_mut;
    uint64_t revision = 1u;
    ninlil_bytes_view_t id_view;
    ninlil_status_t st;
    ninlil_storage_status_t sst;
    const ninlil_storage_ops_t *storage;

    if (runtime == NULL || txn == NULL || slot == NULL
        || runtime->platform == NULL || runtime->platform->storage == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    storage = runtime->platform->storage;
    st = build_service_raw(
        &slot->descriptor, service_raw, sizeof(service_raw), &service_raw_len);
    if (st != NINLIL_OK) {
        return st;
    }
    service_components[0] = (uint8_t)(service_raw_len >> 8);
    service_components[1] = (uint8_t)service_raw_len;
    (void)memcpy(service_components + 2u, service_raw, service_raw_len);
    sc_len = 2u + service_raw_len;
    st = ninlil_model_domain_composite_digest(
        0x10u,
        (ninlil_bytes_view_t){service_components, sc_len},
        &service_id_comp);
    if (st != NINLIL_OK) {
        return st;
    }
    st = ninlil_model_domain_composite_digest(
        0x11u,
        (ninlil_bytes_view_t){service_components, sc_len},
        &quota_id_comp);
    if (st != NINLIL_OK) {
        return st;
    }
    id_view.data = service_id_comp.bytes;
    id_view.length = 32u;
    st = ninlil_model_domain_build_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE,
        NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
        id_view,
        &skey);
    if (st != NINLIL_OK) {
        return st;
    }
    /* Body field service_key_digest = KEY_DIGEST(complete SERVICE key). */
    st = ninlil_model_domain_key_digest(
        (ninlil_bytes_view_t){skey.bytes, skey.length}, &service_kd);
    if (st != NINLIL_OK) {
        return st;
    }
    id_view.data = quota_id_comp.bytes;
    id_view.length = 32u;
    st = ninlil_model_domain_build_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE_QUOTA,
        NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
        id_view,
        &qkey);
    if (st != NINLIL_OK) {
        return st;
    }

    /* W = COMPOSITE(0x7f, u16(op=1) || RAW16(service_key_digest)). */
    {
        uint8_t wcomp[2u + 2u + 32u];
        wcomp[0] = 0u;
        wcomp[1] = 1u;
        wcomp[2] = 0u;
        wcomp[3] = 32u;
        (void)memcpy(wcomp + 4u, service_kd.bytes, 32u);
        st = ninlil_model_domain_composite_digest(
            0x7fu, (ninlil_bytes_view_t){wcomp, sizeof(wcomp)}, &witness);
        if (st != NINLIL_OK) {
            return st;
        }
    }

    /* PVD = SHA256(live SERVICE envelope); secondary requires non-zero PVD. */
    service_value_mut.data = service_value;
    service_value_mut.capacity = sizeof(service_value);
    service_value_mut.length = 0u;
    sst = storage->get(
        storage->user,
        txn,
        (ninlil_bytes_view_t){skey.bytes, skey.length},
        &service_value_mut);
    if (sst == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        runtime->commit_unknown_fence = 1u;
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    }
    if (sst != NINLIL_STORAGE_OK || service_value_mut.length == 0u
        || service_value_mut.length > sizeof(service_value)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    st = ninlil_model_domain_sha256(
        service_value, service_value_mut.length, &service_value_dig);
    if (st != NINLIL_OK) {
        return st;
    }

    /* Monotonic revision on REPLACE when a prior QUOTA row is present. */
    {
        uint8_t prior[NINLIL_DOMAIN_SCHEMA1_KIND1_MEMBER_VALUE_CAP];
        ninlil_mut_bytes_t prior_mut;
        ninlil_model_domain_envelope_t env;

        prior_mut.data = prior;
        prior_mut.capacity = sizeof(prior);
        prior_mut.length = 0u;
        sst = storage->get(
            storage->user,
            txn,
            (ninlil_bytes_view_t){qkey.bytes, qkey.length},
            &prior_mut);
        if (sst == NINLIL_STORAGE_COMMIT_UNKNOWN) {
            runtime->commit_unknown_fence = 1u;
            return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
        }
        if (sst == NINLIL_STORAGE_OK && prior_mut.length > 0u) {
            st = ninlil_model_domain_decode_envelope(
                (ninlil_bytes_view_t){prior, prior_mut.length}, &env);
            if (st == NINLIL_OK && env.header.record_revision < UINT64_MAX) {
                revision = env.header.record_revision + 1u;
            }
        } else if (sst != NINLIL_STORAGE_NOT_FOUND
            && sst != NINLIL_STORAGE_OK) {
            return map_storage(sst);
        }
    }

    (void)memset(&quota_body, 0, sizeof(quota_body));
    quota_body.service_key_raw = service_raw;
    quota_body.service_key_raw_length = (uint16_t)service_raw_len;
    (void)memcpy(quota_body.service_key_digest, service_kd.bytes, 32u);
    (void)memcpy(
        quota_body.window_clock_epoch,
        slot->quota_window_epoch,
        16u);
    quota_body.window_start_ms = slot->quota_window_start_ms;
    quota_body.admissions_in_window = (uint32_t)slot->quota_admissions;
    quota_body.payload_bytes_in_window = slot->quota_payload_bytes;
    quota_body.active_transaction_count = (uint32_t)slot->quota_inflight;
    st = ninlil_model_domain_encode_body_service_quota(
        &quota_body, body_buf, sizeof(body_buf), &body_len);
    if (st != NINLIL_OK) {
        return st;
    }
    st = encode_domain_record(
        0x11u,
        revision,
        service_id_comp.bytes,
        witness.bytes,
        service_value_dig.bytes,
        body_buf,
        body_len,
        value_buf,
        sizeof(value_buf),
        &value_len);
    if (st != NINLIL_OK) {
        return st;
    }
    sst = storage->put(
        storage->user,
        txn,
        (ninlil_bytes_view_t){qkey.bytes, qkey.length},
        (ninlil_bytes_view_t){value_buf, value_len});
    if (sst == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        runtime->commit_unknown_fence = 1u;
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    }
    if (sst != NINLIL_STORAGE_OK) {
        return map_storage(sst);
    }
    return NINLIL_OK;
}
