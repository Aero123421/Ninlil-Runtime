/* SPDX-License-Identifier: Apache-2.0 */
#include "v1_durable_allowlist.h"

#include "domain_store_body_codec.h"
#include "domain_store_codec.h"
#include "runtime_store_codec.h"
#include "runtime_v1_bearer_wire.h"
#include "runtime_v1_capability.h"
#include "runtime_v1_event_ledger_codec.h"
#include "runtime_v1_transaction_codec.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

const ninlil_v1_durable_allowlist_row_t g_ninlil_v1_durable_allowlist_table[
    NINLIL_V1_DURABLE_ALLOWLIST_RECORD_KIND_COUNT] = {
    {NINLIL_V1_DURABLE_KIND_RS_BINDING, NINLIL_V1_DURABLE_OWNER_S1,
        "RS_BINDING"},
    {NINLIL_V1_DURABLE_KIND_RS_IDENTITY, NINLIL_V1_DURABLE_OWNER_S1,
        "RS_IDENTITY"},
    {NINLIL_V1_DURABLE_KIND_RS_COUNTER_TRANSACTION, NINLIL_V1_DURABLE_OWNER_S1,
        "RS_COUNTER_TRANSACTION"},
    {NINLIL_V1_DURABLE_KIND_RS_COUNTER_ORDERED_INPUT,
        NINLIL_V1_DURABLE_OWNER_S1, "RS_COUNTER_ORDERED_INPUT"},
    {NINLIL_V1_DURABLE_KIND_RS_COUNTER_ASSIGNED_OWNER,
        NINLIL_V1_DURABLE_OWNER_S1, "RS_COUNTER_ASSIGNED_OWNER"},
    {NINLIL_V1_DURABLE_KIND_RS_COUNTER_VISITED_OWNER,
        NINLIL_V1_DURABLE_OWNER_S1, "RS_COUNTER_VISITED_OWNER"},
    {NINLIL_V1_DURABLE_KIND_RS_CAPACITY_SERVICE, NINLIL_V1_DURABLE_OWNER_S1,
        "RS_CAPACITY_SERVICE"},
    {NINLIL_V1_DURABLE_KIND_RS_CAPACITY_TRANSACTION,
        NINLIL_V1_DURABLE_OWNER_S1, "RS_CAPACITY_TRANSACTION"},
    {NINLIL_V1_DURABLE_KIND_RS_CAPACITY_TARGET, NINLIL_V1_DURABLE_OWNER_S1,
        "RS_CAPACITY_TARGET"},
    {NINLIL_V1_DURABLE_KIND_RS_CAPACITY_OUTBOX_BYTES,
        NINLIL_V1_DURABLE_OWNER_S1, "RS_CAPACITY_OUTBOX_BYTES"},
    {NINLIL_V1_DURABLE_KIND_RS_CAPACITY_DELIVERY, NINLIL_V1_DURABLE_OWNER_S1,
        "RS_CAPACITY_DELIVERY"},
    {NINLIL_V1_DURABLE_KIND_RS_CAPACITY_EVENT_SPOOL_COUNT,
        NINLIL_V1_DURABLE_OWNER_S1, "RS_CAPACITY_EVENT_SPOOL_COUNT"},
    {NINLIL_V1_DURABLE_KIND_RS_CAPACITY_EVENT_SPOOL_BYTES,
        NINLIL_V1_DURABLE_OWNER_S1, "RS_CAPACITY_EVENT_SPOOL_BYTES"},
    {NINLIL_V1_DURABLE_KIND_RS_CAPACITY_RESULT_CACHE,
        NINLIL_V1_DURABLE_OWNER_S1, "RS_CAPACITY_RESULT_CACHE"},
    {NINLIL_V1_DURABLE_KIND_RS_CAPACITY_EVIDENCE, NINLIL_V1_DURABLE_OWNER_S1,
        "RS_CAPACITY_EVIDENCE"},
    {NINLIL_V1_DURABLE_KIND_RS_CAPACITY_INGRESS, NINLIL_V1_DURABLE_OWNER_S1,
        "RS_CAPACITY_INGRESS"},
    {NINLIL_V1_DURABLE_KIND_RS_CAPACITY_DEFERRED_TOKEN,
        NINLIL_V1_DURABLE_OWNER_S1, "RS_CAPACITY_DEFERRED_TOKEN"},
    {NINLIL_V1_DURABLE_KIND_DOM_WITNESS_HEAD_INDEX, NINLIL_V1_DURABLE_OWNER_S1,
        "DOM_WITNESS_HEAD_INDEX"},
    {NINLIL_V1_DURABLE_KIND_DOM_CLOCK_BASELINE, NINLIL_V1_DURABLE_OWNER_S1,
        "DOM_CLOCK_BASELINE"},
    {NINLIL_V1_DURABLE_KIND_SPINE_SERVICE_MARKER, NINLIL_V1_DURABLE_OWNER_S1,
        "SPINE_SERVICE_MARKER"},
    {NINLIL_V1_DURABLE_KIND_SPINE_TXN_ADMISSION, NINLIL_V1_DURABLE_OWNER_S1,
        "SPINE_TXN_ADMISSION"},
    {NINLIL_V1_DURABLE_KIND_SPINE_CANCEL_ADMISSION, NINLIL_V1_DURABLE_OWNER_S1,
        "SPINE_CANCEL_ADMISSION"},
    {NINLIL_V1_DURABLE_KIND_SPINE_DELIVERY_STARTED, NINLIL_V1_DURABLE_OWNER_S1,
        "SPINE_DELIVERY_STARTED"},
    {NINLIL_V1_DURABLE_KIND_SPINE_DELIVERY_EVIDENCE, NINLIL_V1_DURABLE_OWNER_S1,
        "SPINE_DELIVERY_EVIDENCE"},
    {NINLIL_V1_DURABLE_KIND_SPINE_DELIVERY_OUTCOME, NINLIL_V1_DURABLE_OWNER_S1,
        "SPINE_DELIVERY_OUTCOME"},
    {NINLIL_V1_DURABLE_KIND_SPINE_EVENT_SPOOL, NINLIL_V1_DURABLE_OWNER_S1,
        "SPINE_EVENT_SPOOL"},
    {NINLIL_V1_DURABLE_KIND_SPINE_EVENT_RESUME, NINLIL_V1_DURABLE_OWNER_S1,
        "SPINE_EVENT_RESUME"},
    {NINLIL_V1_DURABLE_KIND_SPINE_EVENT_DISCARD, NINLIL_V1_DURABLE_OWNER_S1,
        "SPINE_EVENT_DISCARD"},
    {NINLIL_V1_DURABLE_KIND_SPINE_RETRY_STATE, NINLIL_V1_DURABLE_OWNER_S1,
        "SPINE_RETRY_STATE"},
    {NINLIL_V1_DURABLE_KIND_SPINE_RESERVATION, NINLIL_V1_DURABLE_OWNER_S1,
        "SPINE_RESERVATION"},
    {NINLIL_V1_DURABLE_KIND_M4_INSTALL_TOKEN, NINLIL_V1_DURABLE_OWNER_M4,
        "M4_INSTALL_TOKEN"},
    {NINLIL_V1_DURABLE_KIND_C3_REPLAY_ADMISSION, NINLIL_V1_DURABLE_OWNER_C3,
        "C3_REPLAY_ADMISSION"},
    {NINLIL_V1_DURABLE_KIND_SPINE_BEARER_STATE,
        NINLIL_V1_DURABLE_OWNER_S1, "SPINE_BEARER_STATE"},
    {NINLIL_V1_DURABLE_KIND_SPINE_ATTEMPT_PREPARE,
        NINLIL_V1_DURABLE_OWNER_S1, "SPINE_ATTEMPT_PREPARE"},
    {NINLIL_V1_DURABLE_KIND_DOM_IDEMPOTENCY_MAP, NINLIL_V1_DURABLE_OWNER_S1,
        "DOM_IDEMPOTENCY_MAP"},
    {NINLIL_V1_DURABLE_KIND_DOM_EVENT_ID_MAP, NINLIL_V1_DURABLE_OWNER_S1,
        "DOM_EVENT_ID_MAP"},
    {NINLIL_V1_DURABLE_KIND_DOM_WITNESS_HEADER, NINLIL_V1_DURABLE_OWNER_S1,
        "DOM_WITNESS_HEADER"},
    {NINLIL_V1_DURABLE_KIND_DOM_WITNESS_MANIFEST_CHUNK,
        NINLIL_V1_DURABLE_OWNER_S1, "DOM_WITNESS_MANIFEST_CHUNK"},
    {NINLIL_V1_DURABLE_KIND_DOM_SERVICE, NINLIL_V1_DURABLE_OWNER_S1,
        "DOM_SERVICE"},
    {NINLIL_V1_DURABLE_KIND_DOM_SERVICE_QUOTA, NINLIL_V1_DURABLE_OWNER_S1,
        "DOM_SERVICE_QUOTA"},
    {NINLIL_V1_DURABLE_KIND_DOM_RESERVATION, NINLIL_V1_DURABLE_OWNER_S1,
        "DOM_RESERVATION"}
};

static ninlil_v1_durable_record_kind_t key_id_to_kind(
    ninlil_model_runtime_store_key_id_t key_id)
{
    switch (key_id) {
    case NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING:
        return NINLIL_V1_DURABLE_KIND_RS_BINDING;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_IDENTITY:
        return NINLIL_V1_DURABLE_KIND_RS_IDENTITY;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION:
        return NINLIL_V1_DURABLE_KIND_RS_COUNTER_TRANSACTION;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_ORDERED_INPUT:
        return NINLIL_V1_DURABLE_KIND_RS_COUNTER_ORDERED_INPUT;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_ASSIGNED_OWNER:
        return NINLIL_V1_DURABLE_KIND_RS_COUNTER_ASSIGNED_OWNER;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_VISITED_OWNER:
        return NINLIL_V1_DURABLE_KIND_RS_COUNTER_VISITED_OWNER;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE:
        return NINLIL_V1_DURABLE_KIND_RS_CAPACITY_SERVICE;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_TRANSACTION:
        return NINLIL_V1_DURABLE_KIND_RS_CAPACITY_TRANSACTION;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_TARGET:
        return NINLIL_V1_DURABLE_KIND_RS_CAPACITY_TARGET;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_OUTBOX_BYTES:
        return NINLIL_V1_DURABLE_KIND_RS_CAPACITY_OUTBOX_BYTES;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_DELIVERY:
        return NINLIL_V1_DURABLE_KIND_RS_CAPACITY_DELIVERY;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_EVENT_SPOOL_COUNT:
        return NINLIL_V1_DURABLE_KIND_RS_CAPACITY_EVENT_SPOOL_COUNT;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_EVENT_SPOOL_BYTES:
        return NINLIL_V1_DURABLE_KIND_RS_CAPACITY_EVENT_SPOOL_BYTES;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_RESULT_CACHE:
        return NINLIL_V1_DURABLE_KIND_RS_CAPACITY_RESULT_CACHE;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_EVIDENCE:
        return NINLIL_V1_DURABLE_KIND_RS_CAPACITY_EVIDENCE;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_INGRESS:
        return NINLIL_V1_DURABLE_KIND_RS_CAPACITY_INGRESS;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_DEFERRED_TOKEN:
        return NINLIL_V1_DURABLE_KIND_RS_CAPACITY_DEFERRED_TOKEN;
    default:
        return (ninlil_v1_durable_record_kind_t)0;
    }
}

static ninlil_status_t classify_runtime_store_row(
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value,
    ninlil_v1_durable_record_kind_t *out_kind)
{
    ninlil_model_runtime_store_key_id_t key_id;
    ninlil_status_t status;

    (void)value;
    status = ninlil_model_runtime_store_parse_key(key, &key_id);
    if (status != NINLIL_OK) {
        return status;
    }
    *out_kind = key_id_to_kind(key_id);
    if (*out_kind == (ninlil_v1_durable_record_kind_t)0) {
        return NINLIL_E_UNSUPPORTED;
    }
    return NINLIL_OK;
}

/*
 * Same-record local classification for WITNESS_HEADER / MANIFEST_CHUNK
 * (docs/17 §10; scanner validate_witness_row_local contract). Typed D1-B
 * validate_typed_record does not yet host 7e/7f body unions.
 */
static ninlil_status_t classify_witness_metadata_row(
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value,
    ninlil_v1_durable_record_kind_t *out_kind)
{
    ninlil_model_domain_key_view_t key_view;
    ninlil_model_domain_envelope_t envelope;
    ninlil_model_domain_digest_t expected_identity;
    uint8_t expect_primary_id[NINLIL_MODEL_DOMAIN_ID_BYTES];
    ninlil_status_t status;
    ninlil_bytes_view_t id_view;

    status = ninlil_model_domain_parse_key(key, &key_view);
    if (status != NINLIL_OK) {
        return status;
    }
    if (key_view.family != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN
        || (key_view.subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER
            && key_view.subtype
                != NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK)
        || key_view.identity_kind
            != NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE
        || key_view.identity_length != NINLIL_MODEL_DOMAIN_DIGEST_BYTES
        || key_view.identity == NULL) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    status = ninlil_model_domain_decode_envelope(value, &envelope);
    if (status != NINLIL_OK) {
        return status == NINLIL_E_INVALID_ARGUMENT
            ? NINLIL_E_STORAGE_CORRUPT
            : status;
    }
    {
        uint32_t zi;
        int pvd_nonzero = 0;
        for (zi = 0u; zi < 32u; ++zi) {
            if (envelope.header.primary_value_digest[zi] != 0u) {
                pvd_nonzero = 1;
                break;
            }
        }
        if (envelope.record_type != NINLIL_MODEL_DOMAIN_RECORD_TYPE_DOMAIN
            || envelope.header.subtype != key_view.subtype
            || envelope.header.flags != 0u
            || pvd_nonzero != 0) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
    }

    if (key_view.subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER) {
        ninlil_model_domain_witness_header_t header;
        ninlil_bytes_view_t op_identity;

        status = ninlil_model_domain_decode_witness_header(
            envelope.body, &header);
        if (status != NINLIL_OK) {
            return status == NINLIL_E_INVALID_ARGUMENT
                ? NINLIL_E_STORAGE_CORRUPT
                : status;
        }
        op_identity.data = header.operation_identity_length == 0u
            ? NULL
            : header.operation_identity;
        op_identity.length = header.operation_identity_length;
        status = ninlil_model_domain_witness_identity_digest(
            header.operation_kind, op_identity, &expected_identity);
        if (status != NINLIL_OK) {
            return status == NINLIL_E_INVALID_ARGUMENT
                ? NINLIL_E_STORAGE_CORRUPT
                : status;
        }
        if (memcmp(
                key_view.identity,
                expected_identity.bytes,
                NINLIL_MODEL_DOMAIN_DIGEST_BYTES)
            != 0) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        id_view.data = key_view.identity;
        id_view.length = key_view.identity_length;
        if (ninlil_model_domain_primary_id_from_identity(
                key_view.identity_kind, id_view, expect_primary_id)
                != NINLIL_OK
            || memcmp(
                   envelope.header.primary_id,
                   expect_primary_id,
                   NINLIL_MODEL_DOMAIN_ID_BYTES)
                != 0) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        *out_kind = NINLIL_V1_DURABLE_KIND_DOM_WITNESS_HEADER;
        return NINLIL_OK;
    }

    {
        ninlil_model_domain_witness_chunk_t chunk;
        uint8_t components[34];
        ninlil_bytes_view_t components_view;

        status = ninlil_model_domain_decode_witness_chunk(
            envelope.body, &chunk);
        if (status != NINLIL_OK) {
            return status == NINLIL_E_INVALID_ARGUMENT
                ? NINLIL_E_STORAGE_CORRUPT
                : status;
        }
        (void)memcpy(components, chunk.witness_digest, 32u);
        components[32] = (uint8_t)((chunk.chunk_index >> 8) & 0xffu);
        components[33] = (uint8_t)(chunk.chunk_index & 0xffu);
        components_view.data = components;
        components_view.length = 34u;
        status = ninlil_model_domain_composite_digest(
            NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK,
            components_view,
            &expected_identity);
        if (status != NINLIL_OK) {
            return status == NINLIL_E_INVALID_ARGUMENT
                ? NINLIL_E_STORAGE_CORRUPT
                : status;
        }
        if (memcmp(
                key_view.identity,
                expected_identity.bytes,
                NINLIL_MODEL_DOMAIN_DIGEST_BYTES)
            != 0) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        id_view.data = key_view.identity;
        id_view.length = key_view.identity_length;
        if (ninlil_model_domain_primary_id_from_identity(
                key_view.identity_kind, id_view, expect_primary_id)
                != NINLIL_OK
            || memcmp(
                   envelope.header.primary_id,
                   expect_primary_id,
                   NINLIL_MODEL_DOMAIN_ID_BYTES)
                != 0) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        *out_kind = NINLIL_V1_DURABLE_KIND_DOM_WITNESS_MANIFEST_CHUNK;
        return NINLIL_OK;
    }
}

static ninlil_status_t classify_domain_row(
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value,
    ninlil_v1_durable_record_kind_t *out_kind)
{
    ninlil_model_domain_key_class_t key_class;
    ninlil_model_domain_key_view_t key_view;
    ninlil_model_domain_typed_record_t typed;
    ninlil_status_t status;

    status = ninlil_model_domain_classify_key(key, &key_class);
    if (status != NINLIL_OK) {
        return status;
    }
    if (key_class == NINLIL_MODEL_DOMAIN_KEY_CLASS_RECOGNIZABLE_FUTURE) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (key_class != NINLIL_MODEL_DOMAIN_KEY_CLASS_CURRENT) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    status = ninlil_model_domain_parse_key(key, &key_view);
    if (status != NINLIL_OK) {
        return status;
    }
    if (key_view.family == NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN
        && (key_view.subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER
            || key_view.subtype
                == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK)) {
        return classify_witness_metadata_row(key, value, out_kind);
    }
    status = ninlil_model_domain_validate_typed_record(key, value, &typed);
    if (status != NINLIL_OK) {
        return status;
    }
    if (typed.family != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (typed.subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX) {
        *out_kind = NINLIL_V1_DURABLE_KIND_DOM_WITNESS_HEAD_INDEX;
        return NINLIL_OK;
    }
    if (typed.subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE) {
        *out_kind = NINLIL_V1_DURABLE_KIND_DOM_CLOCK_BASELINE;
        return NINLIL_OK;
    }
    if (typed.subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP) {
        *out_kind = NINLIL_V1_DURABLE_KIND_DOM_IDEMPOTENCY_MAP;
        return NINLIL_OK;
    }
    if (typed.subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_ID_MAP) {
        *out_kind = NINLIL_V1_DURABLE_KIND_DOM_EVENT_ID_MAP;
        return NINLIL_OK;
    }
    if (typed.subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE) {
        *out_kind = NINLIL_V1_DURABLE_KIND_DOM_SERVICE;
        return NINLIL_OK;
    }
    if (typed.subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE_QUOTA) {
        *out_kind = NINLIL_V1_DURABLE_KIND_DOM_SERVICE_QUOTA;
        return NINLIL_OK;
    }
    if (typed.subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION) {
        *out_kind = NINLIL_V1_DURABLE_KIND_DOM_RESERVATION;
        return NINLIL_OK;
    }
    return NINLIL_E_UNSUPPORTED;
}

static ninlil_status_t classify_m4_row(
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value,
    ninlil_v1_durable_record_kind_t *out_kind)
{
    uint32_t crc_wire;
    uint32_t crc_calc;

    (void)value;
    if (key.length != 16u || key.data == NULL) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (key.data[0] != 0x4du || key.data[1] != 0x34u || key.data[2] != 0x54u) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (value.length != 72u || value.data == NULL) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (value.data[0] != 1u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (value.data[1] != 1u && value.data[1] != 2u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    crc_wire = ((uint32_t)value.data[68] << 24)
        | ((uint32_t)value.data[69] << 16)
        | ((uint32_t)value.data[70] << 8)
        | (uint32_t)value.data[71];
    crc_calc = ninlil_model_domain_crc32c(value.data, 68u);
    if (crc_wire != crc_calc) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_kind = NINLIL_V1_DURABLE_KIND_M4_INSTALL_TOKEN;
    return NINLIL_OK;
}

static ninlil_status_t classify_c3_row(
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value,
    ninlil_v1_durable_record_kind_t *out_kind)
{
    uint32_t crc_wire;
    uint32_t crc_calc;

    (void)value;
    if (key.length != 16u || key.data == NULL) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (key.data[0] != 0x43u || key.data[1] != 0x33u || key.data[2] != 0x52u) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (value.length != 48u || value.data == NULL) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (value.data[0] != 1u || value.data[1] != 1u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    crc_wire = ((uint32_t)value.data[44] << 24)
        | ((uint32_t)value.data[45] << 16)
        | ((uint32_t)value.data[46] << 8)
        | (uint32_t)value.data[47];
    crc_calc = ninlil_model_domain_crc32c(value.data, 44u);
    if (crc_wire != crc_calc) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_kind = NINLIL_V1_DURABLE_KIND_C3_REPLAY_ADMISSION;
    return NINLIL_OK;
}

static ninlil_status_t classify_spine_marker_row(
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value,
    ninlil_v1_durable_record_kind_t *out_kind)
{
    ninlil_status_t status = NINLIL_OK;

    if (key.length < 2u || key.data == NULL) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (key.length >= 3u && key.data[0] == 0x4eu && key.data[1] == 0x52u
        && key.data[2] == 0x53u) {
        *out_kind = NINLIL_V1_DURABLE_KIND_SPINE_SERVICE_MARKER;
        return NINLIL_OK;
    }
    if (key.data[0] == 0x54u && key.data[1] == 0x58u) {
        *out_kind = NINLIL_V1_DURABLE_KIND_SPINE_TXN_ADMISSION;
        if (key.length != 18u) {
            return NINLIL_E_UNSUPPORTED;
        }
        return ninlil_rt_v1_transaction_record_validate_envelope(value);
    }
    if (key.data[0] == 0x43u && key.data[1] == 0x4eu) {
        *out_kind = NINLIL_V1_DURABLE_KIND_SPINE_CANCEL_ADMISSION;
        if (key.length != 18u) {
            return NINLIL_E_UNSUPPORTED;
        }
        return ninlil_rt_v1_transaction_record_validate_envelope(value);
    }
    if (key.data[0] == 0x44u && key.data[1] == 0x53u) {
        *out_kind = NINLIL_V1_DURABLE_KIND_SPINE_DELIVERY_STARTED;
        if (key.length != 18u) {
            return NINLIL_E_UNSUPPORTED;
        }
        status = ninlil_rt_v1_transaction_record_validate_envelope(value);
        return status;
    }
    if (key.data[0] == 0x45u && key.data[1] == 0x56u) {
        *out_kind = NINLIL_V1_DURABLE_KIND_SPINE_DELIVERY_EVIDENCE;
        if (key.length != 18u) {
            return NINLIL_E_UNSUPPORTED;
        }
        status = ninlil_rt_v1_transaction_record_validate_envelope(value);
        return status;
    }
    if (key.data[0] == 0x4fu && key.data[1] == 0x43u) {
        *out_kind = NINLIL_V1_DURABLE_KIND_SPINE_DELIVERY_OUTCOME;
        if (key.length != 18u) {
            return NINLIL_E_UNSUPPORTED;
        }
        status = ninlil_rt_v1_transaction_record_validate_envelope(value);
        return status;
    }
    if (key.data[0] == 0x45u && key.data[1] == 0x53u) {
        *out_kind = NINLIL_V1_DURABLE_KIND_SPINE_EVENT_SPOOL;
        if (key.length != 18u) {
            return NINLIL_E_UNSUPPORTED;
        }
        status = ninlil_rt_v1_transaction_record_validate_envelope(value);
        return status;
    }
    if (key.data[0] == 0x45u && key.data[1] == 0x52u) {
        *out_kind = NINLIL_V1_DURABLE_KIND_SPINE_EVENT_RESUME;
        if (key.length != NINLIL_RT_V1_EVENT_LEDGER_KEY_BYTES) {
            return NINLIL_E_UNSUPPORTED;
        }
        return ninlil_rt_v1_event_ledger_validate(
            NINLIL_RT_V1_EVENT_LEDGER_KIND_RESUME, value);
    }
    if (key.data[0] == 0x45u && key.data[1] == 0x44u) {
        *out_kind = NINLIL_V1_DURABLE_KIND_SPINE_EVENT_DISCARD;
        if (key.length != NINLIL_RT_V1_EVENT_LEDGER_KEY_BYTES) {
            return NINLIL_E_UNSUPPORTED;
        }
        return ninlil_rt_v1_event_ledger_validate(
            NINLIL_RT_V1_EVENT_LEDGER_KIND_DISCARD, value);
    }
    if (key.data[0] == 0x52u && key.data[1] == 0x54u) {
        *out_kind = NINLIL_V1_DURABLE_KIND_SPINE_RETRY_STATE;
        if (key.length != 18u) {
            return NINLIL_E_UNSUPPORTED;
        }
        status = ninlil_rt_v1_transaction_record_validate_envelope(value);
        return status;
    }
    if (key.data[0] == 0x52u && key.data[1] == 0x56u) {
        *out_kind = NINLIL_V1_DURABLE_KIND_SPINE_RESERVATION;
        if (key.length != 18u) {
            return NINLIL_E_UNSUPPORTED;
        }
        return ninlil_rt_v1_reservation_marker_validate(value);
    }
    if (key.data[0] == 0x42u && key.data[1] == 0x53u) {
        *out_kind = NINLIL_V1_DURABLE_KIND_SPINE_BEARER_STATE;
        return ninlil_rt_v1_bearer_state_marker_validate(key, value);
    }
    if (key.data[0] == 0x41u && key.data[1] == 0x50u) {
        *out_kind = NINLIL_V1_DURABLE_KIND_SPINE_ATTEMPT_PREPARE;
        if (key.length != 18u) {
            return NINLIL_E_UNSUPPORTED;
        }
        status = ninlil_rt_v1_transaction_record_validate_envelope(value);
        return status;
    }
    return NINLIL_E_UNSUPPORTED;
}

ninlil_status_t ninlil_v1_durable_classify_row(
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value,
    ninlil_v1_durable_record_kind_t *out_kind)
{
    if (out_kind == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_kind = (ninlil_v1_durable_record_kind_t)0;
    if ((key.length != 0u && key.data == NULL)
        || (value.length != 0u && value.data == NULL)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    {
        ninlil_status_t spine_status =
            classify_spine_marker_row(key, value, out_kind);
        if (spine_status == NINLIL_OK
            || *out_kind != (ninlil_v1_durable_record_kind_t)0) {
            return spine_status;
        }
    }
    if (key.length >= 9u
        && key.data != NULL
        && key.data[7] == 0x01u
        && (key.data[8] == 0x01u || key.data[8] == 0x02u
            || key.data[8] == 0x03u || key.data[8] == 0x04u)) {
        return classify_runtime_store_row(key, value, out_kind);
    }
    if (key.length >= 3u && key.data != NULL
        && key.data[0] == 0x4du && key.data[1] == 0x34u
        && key.data[2] == 0x54u) {
        return classify_m4_row(key, value, out_kind);
    }
    if (key.length >= 3u && key.data != NULL
        && key.data[0] == 0x43u && key.data[1] == 0x33u
        && key.data[2] == 0x52u) {
        return classify_c3_row(key, value, out_kind);
    }
    return classify_domain_row(key, value, out_kind);
}

typedef struct ninlil_v1_durable_operation_kind_mask {
    ninlil_v1_durable_operation_t operation;
    uint64_t kind_mask;
} ninlil_v1_durable_operation_kind_mask_t;

/*
 * Closed operation->record-kind authority. Bit zero represents kind 1.
 * Keep every operation explicit so the source gate can reject an omitted
 * operation, an extra operation, or any changed operation/kind pair.
 */
static const ninlil_v1_durable_operation_kind_mask_t
    g_ninlil_v1_durable_operation_kind_masks[
        NINLIL_V1_DURABLE_ALLOWLIST_OPERATION_COUNT] = {
        {NINLIL_V1_DURABLE_OP_BOOTSTRAP_COMMIT, UINT64_C(0x00001ffff)},
        {NINLIL_V1_DURABLE_OP_METADATA_INIT_COMMIT, UINT64_C(0x000060000)},
        {NINLIL_V1_DURABLE_OP_CLOCK_TRUSTED_COMMIT, UINT64_C(0x000040000)},
        /*
         * First registration only: NRS SERVICE marker + SERVICE capacity row
         * in the same FULL transaction. Never other capacity kinds or an
         * admission quota rewrite.
         */
        {NINLIL_V1_DURABLE_OP_SERVICE_REGISTER_COMMIT, UINT64_C(0x000080040)},
        /*
         * SUBMIT admits TX + reservation + capacities + SERVICE ledger rewrite
         * (kind 20 / bit 19) + IDEMPOTENCY_MAP (35) + EVENT_ID_MAP (36) +
         * WITNESS_HEADER (37) + WITNESS_MANIFEST_CHUNK (38).
         * Base 0x02011ffc0 | 0x80000 | bits 34..37.
         */
        {NINLIL_V1_DURABLE_OP_SUBMIT_ADMISSION_COMMIT,
            UINT64_C(0x3c2019ffc0)},
        /*
         * Terminal / release paths that may co-stage SERVICE quota decrement
         * (bit 19 / kind 20 SPINE_SERVICE_MARKER) with TX + capacity rows.
         */
        {NINLIL_V1_DURABLE_OP_CANCEL_ADMISSION_COMMIT, UINT64_C(0x00029ffc8)},
        {NINLIL_V1_DURABLE_OP_DELIVERY_STARTED_COMMIT, UINT64_C(0x00049ffc8)},
        {NINLIL_V1_DURABLE_OP_DELIVERY_EVIDENCE_COMMIT, UINT64_C(0x00089ffc8)},
        {NINLIL_V1_DURABLE_OP_DELIVERY_OUTCOME_COMMIT, UINT64_C(0x00109ffc0)},
        {NINLIL_V1_DURABLE_OP_EVENT_SPOOL_COMMIT, UINT64_C(0x002000000)},
        {NINLIL_V1_DURABLE_OP_EVENT_RESUME_COMMIT, UINT64_C(0x00409ffc8)},
        {NINLIL_V1_DURABLE_OP_EVENT_DISCARD_COMMIT, UINT64_C(0x00809ffc8)},
        {NINLIL_V1_DURABLE_OP_RETRY_STATE_COMMIT, UINT64_C(0x010000000)},
        {NINLIL_V1_DURABLE_OP_RESERVATION_COMMIT, UINT64_C(0x020000000)},
        {NINLIL_V1_DURABLE_OP_M4_INSTALL_TOKEN_COMMIT, UINT64_C(0x040000000)},
        {NINLIL_V1_DURABLE_OP_C3_REPLAY_ADMISSION_COMMIT,
            UINT64_C(0x080000000)},
        {NINLIL_V1_DURABLE_OP_BEARER_STATE_COMMIT, UINT64_C(0x100000000)},
        {NINLIL_V1_DURABLE_OP_APPLICATION_ATTEMPT_PREPARE_COMMIT,
            UINT64_C(0x200000000)},
        {NINLIL_V1_DURABLE_OP_DESTROY_RECOVERY_COMMIT,
            UINT64_C(0x00089ffc0)}
};

static int operation_allows_kind(
    ninlil_v1_durable_operation_t operation,
    ninlil_v1_durable_record_kind_t kind)
{
    size_t index;
    uint32_t kind_index;

    if (kind < NINLIL_V1_DURABLE_KIND_RS_BINDING
        || kind > NINLIL_V1_DURABLE_KIND_DOM_RESERVATION) {
        return 0;
    }
    kind_index = (uint32_t)kind - 1u;
    for (index = 0u;
         index < NINLIL_V1_DURABLE_ALLOWLIST_OPERATION_COUNT;
         ++index) {
        if (g_ninlil_v1_durable_operation_kind_masks[index].operation
            == operation) {
            return (g_ninlil_v1_durable_operation_kind_masks[index].kind_mask
                       & (UINT64_C(1) << kind_index))
                != UINT64_C(0);
        }
    }
    return 0;
}

static ninlil_status_t validate_allowed_state(
    ninlil_v1_durable_operation_t operation,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value,
    ninlil_v1_durable_record_kind_t kind)
{
    ninlil_model_domain_typed_record_t typed;
    ninlil_status_t status;

    if (kind != NINLIL_V1_DURABLE_KIND_DOM_WITNESS_HEAD_INDEX
        && kind != NINLIL_V1_DURABLE_KIND_DOM_CLOCK_BASELINE) {
        return NINLIL_OK;
    }
    status = ninlil_model_domain_validate_typed_record(key, value, &typed);
    if (status != NINLIL_OK) {
        return status;
    }
    if (kind == NINLIL_V1_DURABLE_KIND_DOM_WITNESS_HEAD_INDEX) {
        if (typed.witness_head_index.index_state
                != NINLIL_MODEL_DOMAIN_INDEX_STATE_BASELINE) {
            return NINLIL_E_UNSUPPORTED;
        }
        return NINLIL_OK;
    }
    if (operation == NINLIL_V1_DURABLE_OP_METADATA_INIT_COMMIT) {
        if (typed.clock_baseline.baseline_state
                != NINLIL_MODEL_DOMAIN_BASELINE_STATE_UNINITIALIZED) {
            return NINLIL_E_UNSUPPORTED;
        }
        return NINLIL_OK;
    }
    if (operation == NINLIL_V1_DURABLE_OP_CLOCK_TRUSTED_COMMIT) {
        if (typed.clock_baseline.baseline_state
                != NINLIL_MODEL_DOMAIN_BASELINE_STATE_TRUSTED) {
            return NINLIL_E_UNSUPPORTED;
        }
        return NINLIL_OK;
    }
    return NINLIL_E_UNSUPPORTED;
}

ninlil_status_t ninlil_v1_durable_writer_gate_check(
    ninlil_v1_durable_operation_t operation,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    ninlil_v1_durable_record_kind_t kind;
    ninlil_status_t status;

    if (operation < NINLIL_V1_DURABLE_OP_BOOTSTRAP_COMMIT
        || operation
            > NINLIL_V1_DURABLE_OP_DESTROY_RECOVERY_COMMIT) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_v1_durable_classify_row(key, value, &kind);
    if (status != NINLIL_OK) {
        return status;
    }
    if (!operation_allows_kind(operation, kind)) {
        return NINLIL_E_UNSUPPORTED;
    }
    return validate_allowed_state(operation, key, value, kind);
}

static ninlil_status_t map_storage_status(ninlil_storage_status_t status)
{
    switch (status) {
    case NINLIL_STORAGE_OK:
        return NINLIL_OK;
    case NINLIL_STORAGE_BUSY:
        return NINLIL_E_WOULD_BLOCK;
    case NINLIL_STORAGE_NO_SPACE:
        return NINLIL_E_CAPACITY_EXHAUSTED;
    case NINLIL_STORAGE_IO_ERROR:
        return NINLIL_E_STORAGE;
    case NINLIL_STORAGE_CORRUPT:
    case NINLIL_STORAGE_NOT_FOUND:
    case NINLIL_STORAGE_BUFFER_TOO_SMALL:
        return NINLIL_E_STORAGE_CORRUPT;
    case NINLIL_STORAGE_UNSUPPORTED_SCHEMA:
        return NINLIL_E_UNSUPPORTED;
    case NINLIL_STORAGE_COMMIT_UNKNOWN:
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    default:
        return NINLIL_E_STORAGE_CORRUPT;
    }
}

static int storage_put_status_requires_fence(ninlil_storage_status_t status)
{
    return status == NINLIL_STORAGE_COMMIT_UNKNOWN
        || (status != NINLIL_STORAGE_OK
            && status != NINLIL_STORAGE_NOT_FOUND
            && status != NINLIL_STORAGE_BUSY
            && status != NINLIL_STORAGE_NO_SPACE
            && status != NINLIL_STORAGE_IO_ERROR
            && status != NINLIL_STORAGE_CORRUPT
            && status != NINLIL_STORAGE_BUFFER_TOO_SMALL
            && status != NINLIL_STORAGE_UNSUPPORTED_SCHEMA);
}

static void storage_put_fence_or(uint32_t *inout_fence, ninlil_storage_status_t status)
{
    if (inout_fence != NULL && storage_put_status_requires_fence(status) != 0) {
        *inout_fence = 1u;
    }
}

ninlil_status_t ninlil_v1_durable_storage_put(
    ninlil_v1_durable_operation_t operation,
    const ninlil_storage_ops_t *storage,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value,
    uint32_t *inout_fence)
{
    ninlil_status_t gate_status;
    ninlil_storage_status_t put_status;

    if (storage == NULL || storage->put == NULL || txn == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    gate_status = ninlil_v1_durable_writer_gate_check(operation, key, value);
    if (gate_status != NINLIL_OK) {
        return gate_status;
    }
    put_status = storage->put(storage->user, txn, key, value);
    storage_put_fence_or(inout_fence, put_status);
    return map_storage_status(put_status);
}

static void publication_reject(
    ninlil_v1_durable_recovery_publication_result_t *out_result,
    ninlil_v1_durable_recovery_reject_reason_t reason)
{
    out_result->adopted = 0u;
    out_result->success_evidence_count = 0u;
    out_result->reject_reason = reason;
}

static ninlil_status_t publication_gate_from_counts(
    uint32_t ok_count,
    uint32_t corrupt_count,
    uint32_t unknown_count,
    uint32_t external_count,
    uint32_t success_evidence_rows,
    ninlil_v1_durable_recovery_publication_result_t *out_result)
{
    if (ok_count > 0u
        && (corrupt_count > 0u || unknown_count > 0u || external_count > 0u)) {
        publication_reject(out_result, NINLIL_V1_DURABLE_RECOVERY_REJECT_MIXED);
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (corrupt_count != 0u) {
        publication_reject(
            out_result, NINLIL_V1_DURABLE_RECOVERY_REJECT_CORRUPT);
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (unknown_count != 0u) {
        publication_reject(
            out_result, NINLIL_V1_DURABLE_RECOVERY_REJECT_UNKNOWN);
        return NINLIL_E_UNSUPPORTED;
    }
    if (external_count != 0u) {
        publication_reject(out_result,
            NINLIL_V1_DURABLE_RECOVERY_REJECT_ALLOWLIST_EXTERNAL);
        return NINLIL_E_UNSUPPORTED;
    }

    out_result->adopted = 1u;
    out_result->success_evidence_count = success_evidence_rows;
    out_result->reject_reason = NINLIL_V1_DURABLE_RECOVERY_REJECT_NONE;
    return NINLIL_OK;
}

static void publication_classify_row(
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value,
    uint32_t *ok_count,
    uint32_t *corrupt_count,
    uint32_t *unknown_count,
    uint32_t *external_count)
{
    ninlil_v1_durable_record_kind_t kind;
    ninlil_status_t status = ninlil_v1_durable_classify_row(key, value, &kind);

    if (status == NINLIL_E_STORAGE_CORRUPT) {
        *corrupt_count += 1u;
        return;
    }
    if (status == NINLIL_E_UNSUPPORTED) {
        *unknown_count += 1u;
        return;
    }
    if (status != NINLIL_OK) {
        *corrupt_count += 1u;
        return;
    }
    if (kind >= NINLIL_V1_DURABLE_KIND_RS_BINDING
        && kind <= NINLIL_V1_DURABLE_KIND_DOM_CLOCK_BASELINE) {
        *ok_count += 1u;
        return;
    }
    if (kind >= NINLIL_V1_DURABLE_KIND_SPINE_SERVICE_MARKER
        && kind <= NINLIL_V1_DURABLE_KIND_SPINE_RESERVATION) {
        *ok_count += 1u;
        return;
    }
    if (kind == NINLIL_V1_DURABLE_KIND_M4_INSTALL_TOKEN) {
        *ok_count += 1u;
        return;
    }
    if (kind == NINLIL_V1_DURABLE_KIND_C3_REPLAY_ADMISSION) {
        *ok_count += 1u;
        return;
    }
    if (kind == NINLIL_V1_DURABLE_KIND_SPINE_BEARER_STATE
        || kind == NINLIL_V1_DURABLE_KIND_SPINE_ATTEMPT_PREPARE
        || kind == NINLIL_V1_DURABLE_KIND_DOM_IDEMPOTENCY_MAP
        || kind == NINLIL_V1_DURABLE_KIND_DOM_EVENT_ID_MAP
        || kind == NINLIL_V1_DURABLE_KIND_DOM_WITNESS_HEADER
        || kind == NINLIL_V1_DURABLE_KIND_DOM_WITNESS_MANIFEST_CHUNK
        || kind == NINLIL_V1_DURABLE_KIND_DOM_SERVICE
        || kind == NINLIL_V1_DURABLE_KIND_DOM_SERVICE_QUOTA
        || kind == NINLIL_V1_DURABLE_KIND_DOM_RESERVATION) {
        *ok_count += 1u;
        return;
    }
    *external_count += 1u;
}

ninlil_status_t ninlil_v1_durable_recovery_publication_gate(
    const ninlil_bytes_view_t *row_keys,
    const ninlil_bytes_view_t *row_values,
    uint32_t row_count,
    uint32_t commit_unknown_active,
    ninlil_v1_durable_recovery_publication_result_t *out_result)
{
    uint32_t index;
    uint32_t ok_count = 0u;
    uint32_t corrupt_count = 0u;
    uint32_t unknown_count = 0u;
    uint32_t external_count = 0u;

    if (out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    if (row_count != 0u
        && (row_keys == NULL || row_values == NULL)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (commit_unknown_active != 0u) {
        publication_reject(
            out_result, NINLIL_V1_DURABLE_RECOVERY_REJECT_COMMIT_UNKNOWN);
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    }

    for (index = 0u; index < row_count; ++index) {
        publication_classify_row(
            row_keys[index],
            row_values[index],
            &ok_count,
            &corrupt_count,
            &unknown_count,
            &external_count);
    }

    return publication_gate_from_counts(
        ok_count,
        corrupt_count,
        unknown_count,
        external_count,
        row_count,
        out_result);
}

ninlil_status_t ninlil_v1_durable_recovery_publication_gate_storage(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t handle,
    uint32_t commit_unknown_active,
    ninlil_v1_durable_recovery_publication_result_t *out_result)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_iter_t iter = NULL;
    ninlil_storage_status_t st;
    uint32_t ok_count = 0u;
    uint32_t corrupt_count = 0u;
    uint32_t unknown_count = 0u;
    uint32_t external_count = 0u;
    uint32_t row_count = 0u;
    uint8_t key_buf[255];
    uint8_t value_buf[NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES];
    ninlil_mut_bytes_t key;
    ninlil_mut_bytes_t value;
    ninlil_bytes_view_t prefix;

    if (out_result == NULL || storage == NULL || handle == NULL
        || storage->begin == NULL || storage->iter_open == NULL
        || storage->iter_next == NULL || storage->iter_close == NULL
        || storage->rollback == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    if (commit_unknown_active != 0u) {
        publication_reject(
            out_result, NINLIL_V1_DURABLE_RECOVERY_REJECT_COMMIT_UNKNOWN);
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    }

    st = storage->begin(
        storage->user, handle, NINLIL_STORAGE_READ_ONLY, &txn);
    if (st != NINLIL_STORAGE_OK) {
        return map_storage_status(st);
    }

    prefix.data = NULL;
    prefix.length = 0u;
    st = storage->iter_open(storage->user, txn, prefix, &iter);
    if (st != NINLIL_STORAGE_OK) {
        (void)storage->rollback(storage->user, txn);
        return map_storage_status(st);
    }

    for (;;) {
        key.data = key_buf;
        key.capacity = (uint32_t)sizeof(key_buf);
        key.length = 0u;
        value.data = value_buf;
        value.capacity = (uint32_t)sizeof(value_buf);
        value.length = 0u;
        st = storage->iter_next(storage->user, iter, &key, &value);
        if (st == NINLIL_STORAGE_NOT_FOUND) {
            break;
        }
        if (st == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
            storage->iter_close(storage->user, iter);
            (void)storage->rollback(storage->user, txn);
            publication_reject(
                out_result, NINLIL_V1_DURABLE_RECOVERY_REJECT_CORRUPT);
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (st != NINLIL_STORAGE_OK) {
            storage->iter_close(storage->user, iter);
            (void)storage->rollback(storage->user, txn);
            return map_storage_status(st);
        }
        if (row_count == UINT32_MAX) {
            storage->iter_close(storage->user, iter);
            (void)storage->rollback(storage->user, txn);
            publication_reject(
                out_result, NINLIL_V1_DURABLE_RECOVERY_REJECT_CORRUPT);
            return NINLIL_E_STORAGE_CORRUPT;
        }
        row_count += 1u;
        publication_classify_row(
            (ninlil_bytes_view_t){key.data, key.length},
            (ninlil_bytes_view_t){value.data, value.length},
            &ok_count,
            &corrupt_count,
            &unknown_count,
            &external_count);
    }

    storage->iter_close(storage->user, iter);
    st = storage->rollback(storage->user, txn);
    if (st != NINLIL_STORAGE_OK) {
        return map_storage_status(st);
    }

    return publication_gate_from_counts(
        ok_count,
        corrupt_count,
        unknown_count,
        external_count,
        row_count,
        out_result);
}

ninlil_status_t ninlil_v1_durable_probe_disallowed_writer_kind(
    ninlil_v1_durable_operation_t operation,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    (void)operation;
    (void)key;
    (void)value;
    return NINLIL_E_UNSUPPORTED;
}
