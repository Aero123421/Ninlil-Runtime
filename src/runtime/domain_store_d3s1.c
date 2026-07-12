#include "domain_store_d3s1.h"

#include "domain_store_body_codec.h"
#include "domain_store_codec.h"
#include "domain_store_codec_internal.h"
#include "domain_store_scanner.h"

#include <string.h>

/*
 * D3-S1 chunk-A/B/C: fixed context, Modes 1–20 peer-key rebuild + evaluator.
 * No KEY_DIGEST reverse. No second 4096. No heap/VLA. No Storage mutation.
 * Modes 1–16 forward; Mode 17 REV_PRIMARY reverse table; Modes 18–20 gates.
 * D3-S1 crossrow oracle/bridge complete. Stage5 D3 bind, D3-S2..S12,
 * D3 overall, D4, and public Runtime remain pending.
 */

static ninlil_status_t write_complete_key(
    uint8_t family,
    uint8_t subtype,
    uint8_t identity_kind,
    ninlil_bytes_view_t identity,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    ninlil_model_domain_key_t key;
    ninlil_status_t status;

    if (out_key == NULL || out_key_len == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (identity.length != 0u && identity.data != NULL
        && !ninlil_model_domain_ranges_are_disjoint(
            identity.data, identity.length, out_key,
            NINLIL_DOMAIN_SCAN_D3S1_PEER_KEY_CAPACITY)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_model_domain_build_key(
        family, subtype, identity_kind, identity, &key);
    if (status != NINLIL_OK) {
        *out_key_len = 0u;
        return status;
    }
    if (key.length == 0u
        || key.length > NINLIL_DOMAIN_SCAN_D3S1_PEER_KEY_CAPACITY
        || key.length > NINLIL_MODEL_DOMAIN_KEY_MAX_CURRENT_BYTES) {
        *out_key_len = 0u;
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memcpy(out_key, key.bytes, key.length);
    *out_key_len = (uint8_t)key.length;
    return NINLIL_OK;
}

static ninlil_status_t write_composite_key(
    uint8_t subtype,
    ninlil_bytes_view_t components,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    ninlil_model_domain_digest_t dig;
    ninlil_bytes_view_t identity;
    ninlil_status_t status;

    if (out_key == NULL || out_key_len == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (components.length != 0u && components.data != NULL
        && !ninlil_model_domain_ranges_are_disjoint(
            components.data, components.length, out_key,
            NINLIL_DOMAIN_SCAN_D3S1_PEER_KEY_CAPACITY)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_model_domain_composite_digest(subtype, components, &dig);
    if (status != NINLIL_OK) {
        *out_key_len = 0u;
        return status;
    }
    identity.data = dig.bytes;
    identity.length = NINLIL_MODEL_DOMAIN_DIGEST_BYTES;
    return write_complete_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        subtype,
        NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
        identity,
        out_key,
        out_key_len);
}

static int encode_raw16(
    uint8_t *out,
    uint32_t capacity,
    uint16_t raw_length,
    const uint8_t *raw,
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

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_service_quota_key(
    const uint8_t *service_key_raw,
    uint16_t service_key_raw_length,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 255u];
    uint32_t comp_len = 0u;
    ninlil_bytes_view_t view;

    if (service_key_raw_length == 0u
        || service_key_raw_length > 255u
        || service_key_raw == NULL) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_raw16(
            components, (uint32_t)sizeof(components), service_key_raw_length,
            service_key_raw, &comp_len)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    view.data = components;
    view.length = comp_len;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE_QUOTA, view, out_key, out_key_len);
}

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_service_reservation_key(
    const uint8_t *service_key_raw,
    uint16_t service_key_raw_length,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 2u + 255u];
    uint32_t o = 0u;
    uint32_t raw16_len = 0u;
    ninlil_bytes_view_t view;

    if (service_key_raw_length == 0u
        || service_key_raw_length > 255u
        || service_key_raw == NULL) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u16_be(
        components, NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_SERVICE);
    o = 2u;
    if (!encode_raw16(
            &components[o], (uint32_t)sizeof(components) - o,
            service_key_raw_length, service_key_raw, &raw16_len)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    o += raw16_len;
    view.data = components;
    view.length = o;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION, view, out_key, out_key_len);
}

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_tx_sequence_index_key(
    uint64_t transaction_sequence,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t seq_be[8];
    ninlil_bytes_view_t identity;

    if (transaction_sequence == 0u) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u64_be(seq_be, transaction_sequence);
    identity.data = seq_be;
    identity.length = 8u;
    return write_complete_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_SEQUENCE_INDEX,
        NINLIL_MODEL_DOMAIN_ID_KIND_U64,
        identity,
        out_key,
        out_key_len);
}

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_tx_state_key(
    const uint8_t transaction_id[NINLIL_MODEL_DOMAIN_ID_BYTES],
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    ninlil_bytes_view_t identity;

    if (transaction_id == NULL
        || ninlil_model_domain_id_is_zero(transaction_id)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    identity.data = transaction_id;
    identity.length = NINLIL_MODEL_DOMAIN_ID_BYTES;
    return write_complete_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE,
        NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
        identity,
        out_key,
        out_key_len);
}

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_tx_idempotency_map_key(
    const uint8_t *scope_raw,
    uint16_t scope_raw_length,
    const uint8_t *idempotency_key,
    uint16_t idempotency_key_length,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 255u + 2u + 64u];
    uint32_t o = 0u;
    uint32_t part = 0u;
    ninlil_bytes_view_t view;

    if (scope_raw_length == 0u || scope_raw_length > 255u || scope_raw == NULL
        || idempotency_key_length == 0u || idempotency_key_length > 64u
        || idempotency_key == NULL) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_raw16(
            components, (uint32_t)sizeof(components), scope_raw_length,
            scope_raw, &part)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    o = part;
    if (!encode_raw16(
            &components[o], (uint32_t)sizeof(components) - o,
            idempotency_key_length, idempotency_key, &part)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    o += part;
    view.data = components;
    view.length = o;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP, view, out_key,
        out_key_len);
}

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_tx_reservation_key(
    const uint8_t transaction_id[NINLIL_MODEL_DOMAIN_ID_BYTES],
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 2u + 16u];
    ninlil_bytes_view_t view;

    if (transaction_id == NULL
        || ninlil_model_domain_id_is_zero(transaction_id)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u16_be(
        components, NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_TRANSACTION);
    ninlil_model_domain_encode_u16_be(&components[2], 16u);
    (void)memcpy(&components[4], transaction_id, 16u);
    view.data = components;
    view.length = 4u + 16u;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION, view, out_key, out_key_len);
}

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_tx_scheduler_owner_key(
    uint64_t scheduler_owner_sequence,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t seq_be[8];
    ninlil_bytes_view_t identity;

    if (scheduler_owner_sequence == 0u) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u64_be(seq_be, scheduler_owner_sequence);
    identity.data = seq_be;
    identity.length = 8u;
    return write_complete_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_SCHEDULER_OWNER,
        NINLIL_MODEL_DOMAIN_ID_KIND_U64,
        identity,
        out_key,
        out_key_len);
}

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_tx_event_id_map_key(
    const uint8_t *scope_raw,
    uint16_t scope_raw_length,
    const uint8_t event_id[NINLIL_MODEL_DOMAIN_ID_BYTES],
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 255u + 16u];
    uint32_t o = 0u;
    uint32_t part = 0u;
    ninlil_bytes_view_t view;

    if (scope_raw_length == 0u || scope_raw_length > 255u || scope_raw == NULL
        || event_id == NULL) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_raw16(
            components, (uint32_t)sizeof(components), scope_raw_length,
            scope_raw, &part)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    o = part;
    (void)memcpy(&components[o], event_id, 16u);
    o += 16u;
    view.data = components;
    view.length = o;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_ID_MAP, view, out_key, out_key_len);
}

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_tx_event_spool_key(
    const uint8_t transaction_id[NINLIL_MODEL_DOMAIN_ID_BYTES],
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    ninlil_bytes_view_t identity;

    if (transaction_id == NULL
        || ninlil_model_domain_id_is_zero(transaction_id)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    identity.data = transaction_id;
    identity.length = NINLIL_MODEL_DOMAIN_ID_BYTES;
    return write_complete_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_SPOOL,
        NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
        identity,
        out_key,
        out_key_len);
}

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_tx_cancel_state_key(
    const uint8_t transaction_id[NINLIL_MODEL_DOMAIN_ID_BYTES],
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 2u + 16u];
    ninlil_bytes_view_t view;

    if (transaction_id == NULL
        || ninlil_model_domain_id_is_zero(transaction_id)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u16_be(
        components, NINLIL_MODEL_DOMAIN_CANCEL_OWNER_TRANSACTION);
    ninlil_model_domain_encode_u16_be(&components[2], 16u);
    (void)memcpy(&components[4], transaction_id, 16u);
    view.data = components;
    view.length = 4u + 16u;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_CANCEL_STATE, view, out_key, out_key_len);
}

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_delivery_result_cache_key(
    const uint8_t *delivery_key_raw,
    uint16_t delivery_key_raw_length,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES];
    uint32_t comp_len = 0u;
    ninlil_bytes_view_t view;

    if (delivery_key_raw_length
            != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES
        || delivery_key_raw == NULL) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_raw16(
            components, (uint32_t)sizeof(components), delivery_key_raw_length,
            delivery_key_raw, &comp_len)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    view.data = components;
    view.length = comp_len;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE, view, out_key, out_key_len);
}

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_delivery_reservation_key(
    const uint8_t *delivery_key_raw,
    uint16_t delivery_key_raw_length,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 2u + NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES];
    ninlil_bytes_view_t view;

    if (delivery_key_raw_length
            != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES
        || delivery_key_raw == NULL) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u16_be(
        components, NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_DELIVERY);
    ninlil_model_domain_encode_u16_be(
        &components[2], delivery_key_raw_length);
    (void)memcpy(
        &components[4], delivery_key_raw, delivery_key_raw_length);
    view.data = components;
    view.length = 4u + (uint32_t)delivery_key_raw_length;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION, view, out_key, out_key_len);
}

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_delivery_scheduler_owner_key(
    uint64_t scheduler_owner_sequence,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    /* Same U64 identity key as TX / ingress scheduler owner. */
    return ninlil_domain_scan_d3s1_rebuild_tx_scheduler_owner_key(
        scheduler_owner_sequence, out_key, out_key_len);
}

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_delivery_cancel_state_key(
    const uint8_t *delivery_key_raw,
    uint16_t delivery_key_raw_length,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 2u + NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES];
    ninlil_bytes_view_t view;

    if (delivery_key_raw_length
            != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES
        || delivery_key_raw == NULL) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u16_be(
        components, NINLIL_MODEL_DOMAIN_CANCEL_OWNER_DELIVERY);
    ninlil_model_domain_encode_u16_be(
        &components[2], delivery_key_raw_length);
    (void)memcpy(
        &components[4], delivery_key_raw, delivery_key_raw_length);
    view.data = components;
    view.length = 4u + (uint32_t)delivery_key_raw_length;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_CANCEL_STATE, view, out_key, out_key_len);
}

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_ingress_reservation_key(
    uint64_t ordered_sequence,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 2u + 8u];
    uint8_t seq_be[8];
    ninlil_bytes_view_t view;

    if (ordered_sequence == 0u) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u64_be(seq_be, ordered_sequence);
    ninlil_model_domain_encode_u16_be(
        components, NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_INGRESS);
    ninlil_model_domain_encode_u16_be(&components[2], 8u);
    (void)memcpy(&components[4], seq_be, 8u);
    view.data = components;
    view.length = 12u;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION, view, out_key, out_key_len);
}

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_ingress_scheduler_owner_key(
    uint64_t owner_sequence,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    return ninlil_domain_scan_d3s1_rebuild_tx_scheduler_owner_key(
        owner_sequence, out_key, out_key_len);
}

/* --- primary reverse / gate peer rebuild helpers (Modes 17–20) --- */

static ninlil_status_t rebuild_service_primary_key(
    const uint8_t *service_key_raw,
    uint16_t service_key_raw_length,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 255u];
    uint32_t comp_len = 0u;
    ninlil_bytes_view_t view;

    if (service_key_raw_length == 0u || service_key_raw_length > 255u
        || service_key_raw == NULL) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_raw16(
            components, (uint32_t)sizeof(components), service_key_raw_length,
            service_key_raw, &comp_len)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    view.data = components;
    view.length = comp_len;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE, view, out_key, out_key_len);
}

static ninlil_status_t rebuild_anchor_primary_key(
    const uint8_t transaction_id[NINLIL_MODEL_DOMAIN_ID_BYTES],
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    ninlil_bytes_view_t identity;

    if (transaction_id == NULL
        || ninlil_model_domain_id_is_zero(transaction_id)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    identity.data = transaction_id;
    identity.length = NINLIL_MODEL_DOMAIN_ID_BYTES;
    return write_complete_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR,
        NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
        identity,
        out_key,
        out_key_len);
}

static ninlil_status_t rebuild_delivery_primary_key(
    const uint8_t *delivery_key_raw,
    uint16_t delivery_key_raw_length,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES];
    uint32_t comp_len = 0u;
    ninlil_bytes_view_t view;

    if (delivery_key_raw_length
            != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES
        || delivery_key_raw == NULL) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_raw16(
            components, (uint32_t)sizeof(components), delivery_key_raw_length,
            delivery_key_raw, &comp_len)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    view.data = components;
    view.length = comp_len;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY, view, out_key, out_key_len);
}

static ninlil_status_t rebuild_ingress_primary_key(
    uint64_t ordered_sequence,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t seq_be[8];
    ninlil_bytes_view_t identity;

    if (ordered_sequence == 0u) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u64_be(seq_be, ordered_sequence);
    identity.data = seq_be;
    identity.length = 8u;
    return write_complete_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS,
        NINLIL_MODEL_DOMAIN_ID_KIND_U64,
        identity,
        out_key,
        out_key_len);
}

/* CALLBACK RES owner_key_raw = delivery_key_raw:RAW16 || token_generation:u64. */
static int parse_callback_owner_nested(
    const uint8_t *owner_raw,
    uint16_t owner_raw_len,
    const uint8_t **out_delivery_raw,
    uint64_t *out_token_generation)
{
    uint16_t dlen;

    if (owner_raw == NULL || owner_raw_len < 2u + 8u || out_delivery_raw == NULL
        || out_token_generation == NULL) {
        return 0;
    }
    dlen = ninlil_model_domain_decode_u16_be(owner_raw);
    if (dlen != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES
        || (uint32_t)owner_raw_len != 2u + (uint32_t)dlen + 8u) {
        return 0;
    }
    *out_delivery_raw = &owner_raw[2];
    *out_token_generation =
        ninlil_model_domain_decode_u64_be(&owner_raw[2u + dlen]);
    return 1;
}

static ninlil_status_t rebuild_callback_reservation_key(
    const uint8_t *delivery_key_raw,
    uint16_t delivery_key_raw_length,
    uint64_t token_generation,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 2u + 2u + 80u + 8u];
    ninlil_bytes_view_t view;
    uint32_t o = 0u;

    if (delivery_key_raw_length
            != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES
        || delivery_key_raw == NULL) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u16_be(
        components, NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_CALLBACK);
    o = 2u;
    ninlil_model_domain_encode_u16_be(
        &components[o],
        (uint16_t)(2u + delivery_key_raw_length + 8u));
    o += 2u;
    ninlil_model_domain_encode_u16_be(&components[o], delivery_key_raw_length);
    o += 2u;
    (void)memcpy(&components[o], delivery_key_raw, delivery_key_raw_length);
    o += delivery_key_raw_length;
    ninlil_model_domain_encode_u64_be(&components[o], token_generation);
    o += 8u;
    view.data = components;
    view.length = o;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION, view, out_key, out_key_len);
}

static ninlil_status_t rebuild_attempt_key_tx(
    const uint8_t transaction_id[NINLIL_MODEL_DOMAIN_ID_BYTES],
    const uint8_t attempt_id[NINLIL_MODEL_DOMAIN_ID_BYTES],
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 2u + 16u + 16u];
    ninlil_bytes_view_t view;
    uint32_t o;

    if (transaction_id == NULL || attempt_id == NULL
        || ninlil_model_domain_id_is_zero(transaction_id)
        || ninlil_model_domain_id_is_zero(attempt_id)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u16_be(
        components, NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION);
    o = 2u;
    ninlil_model_domain_encode_u16_be(&components[o], 16u);
    o += 2u;
    (void)memcpy(&components[o], transaction_id, 16u);
    o += 16u;
    (void)memcpy(&components[o], attempt_id, 16u);
    o += 16u;
    view.data = components;
    view.length = o;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT, view, out_key, out_key_len);
}

static ninlil_status_t rebuild_attempt_id_index_key(
    const uint8_t attempt_id[NINLIL_MODEL_DOMAIN_ID_BYTES],
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    ninlil_bytes_view_t identity;

    if (attempt_id == NULL || ninlil_model_domain_id_is_zero(attempt_id)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    identity.data = attempt_id;
    identity.length = NINLIL_MODEL_DOMAIN_ID_BYTES;
    return write_complete_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX,
        NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
        identity,
        out_key,
        out_key_len);
}

static ninlil_status_t rebuild_retention_basis_key(
    uint16_t subject_kind,
    const uint8_t *subject_key_raw,
    uint16_t subject_key_raw_length,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 2u + 255u];
    ninlil_bytes_view_t view;
    uint32_t o = 0u;
    uint32_t part = 0u;

    if (subject_key_raw == NULL || subject_key_raw_length == 0u
        || subject_key_raw_length > 255u) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (subject_kind == NINLIL_MODEL_DOMAIN_RETENTION_SUBJECT_TRANSACTION) {
        if (subject_key_raw_length != 16u) {
            if (out_key_len != NULL) {
                *out_key_len = 0u;
            }
            return NINLIL_E_INVALID_ARGUMENT;
        }
    } else if (subject_kind == NINLIL_MODEL_DOMAIN_RETENTION_SUBJECT_DELIVERY) {
        if (subject_key_raw_length
            != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES) {
            if (out_key_len != NULL) {
                *out_key_len = 0u;
            }
            return NINLIL_E_INVALID_ARGUMENT;
        }
    } else {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u16_be(components, subject_kind);
    o = 2u;
    if (!encode_raw16(
            &components[o], (uint32_t)sizeof(components) - o,
            subject_key_raw_length, subject_key_raw, &part)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    o += part;
    view.data = components;
    view.length = o;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_RETENTION_BASIS, view, out_key, out_key_len);
}

/*
 * Mode 17 closed reverse: source_subtype (+ owner_kind / subject kind) →
 * true-primary complete key. No KEY_DIGEST reverse. Excluded subtypes skip.
 */
static ninlil_status_t rebuild_mode17_rev_primary(
    const ninlil_domain_scan_d3s1_context_t *context,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t subtype;
    uint16_t owner_kind;
    const uint8_t *delivery_raw = NULL;
    uint64_t token_gen = 0u;

    if (context == NULL || out_key == NULL || out_key_len == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    subtype = context->source_subtype;
    owner_kind = context->owner_kind;

    switch (subtype) {
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE_QUOTA:
        return rebuild_service_primary_key(
            context->source_raw, context->source_raw_len, out_key, out_key_len);
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION:
        if (owner_kind == NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_SERVICE) {
            return rebuild_service_primary_key(
                context->source_raw, context->source_raw_len, out_key,
                out_key_len);
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_TRANSACTION) {
            if (context->source_raw_len != 16u) {
                return NINLIL_E_INVALID_ARGUMENT;
            }
            return rebuild_anchor_primary_key(
                context->source_raw, out_key, out_key_len);
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_INGRESS) {
            if (context->source_raw_len != 8u) {
                return NINLIL_E_INVALID_ARGUMENT;
            }
            return rebuild_ingress_primary_key(
                ninlil_model_domain_decode_u64_be(context->source_raw), out_key,
                out_key_len);
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_DELIVERY) {
            return rebuild_delivery_primary_key(
                context->source_raw, context->source_raw_len, out_key,
                out_key_len);
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_CALLBACK) {
            /* Nested delivery RAW16; primary is DELIVERY never RESULT. */
            if (!parse_callback_owner_nested(
                    context->source_raw, context->source_raw_len, &delivery_raw,
                    &token_gen)) {
                return NINLIL_E_INVALID_ARGUMENT;
            }
            (void)token_gen;
            return rebuild_delivery_primary_key(
                delivery_raw, NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES,
                out_key, out_key_len);
        }
        return NINLIL_E_INVALID_ARGUMENT;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP:
        /* Dual-raw: source_raw=scope, source_raw2=idem_key, source_aux=tx_id. */
        if (context->source_aux_len != 16u) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        return rebuild_anchor_primary_key(
            context->source_aux, out_key, out_key_len);
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_SEQUENCE_INDEX:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_ID_MAP:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_SPOOL:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RETRY_SUMMARY:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_MANAGEMENT_LEDGER:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX:
        if (context->source_raw_len != 16u) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        return rebuild_anchor_primary_key(
            context->source_raw, out_key, out_key_len);
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SCHEDULER_OWNER:
        if (owner_kind == NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_TRANSACTION) {
            if (context->source_raw_len != 16u) {
                return NINLIL_E_INVALID_ARGUMENT;
            }
            return rebuild_anchor_primary_key(
                context->source_raw, out_key, out_key_len);
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_DELIVERY) {
            return rebuild_delivery_primary_key(
                context->source_raw, context->source_raw_len, out_key,
                out_key_len);
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_INGRESS) {
            if (context->source_raw_len != 8u) {
                return NINLIL_E_INVALID_ARGUMENT;
            }
            return rebuild_ingress_primary_key(
                ninlil_model_domain_decode_u64_be(context->source_raw), out_key,
                out_key_len);
        }
        return NINLIL_E_INVALID_ARGUMENT;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT:
        if (owner_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION) {
            if (context->source_raw_len != 16u) {
                return NINLIL_E_INVALID_ARGUMENT;
            }
            return rebuild_anchor_primary_key(
                context->source_raw, out_key, out_key_len);
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_DELIVERY) {
            return rebuild_delivery_primary_key(
                context->source_raw, context->source_raw_len, out_key,
                out_key_len);
        }
        return NINLIL_E_INVALID_ARGUMENT;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_CANCEL_STATE:
        if (owner_kind == NINLIL_MODEL_DOMAIN_CANCEL_OWNER_TRANSACTION) {
            if (context->source_raw_len != 16u) {
                return NINLIL_E_INVALID_ARGUMENT;
            }
            return rebuild_anchor_primary_key(
                context->source_raw, out_key, out_key_len);
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_CANCEL_OWNER_DELIVERY) {
            return rebuild_delivery_primary_key(
                context->source_raw, context->source_raw_len, out_key,
                out_key_len);
        }
        return NINLIL_E_INVALID_ARGUMENT;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVIDENCE_CELL:
        if (owner_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_TRANSACTION) {
            if (context->source_raw_len != 16u) {
                return NINLIL_E_INVALID_ARGUMENT;
            }
            return rebuild_anchor_primary_key(
                context->source_raw, out_key, out_key_len);
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_DELIVERY) {
            return rebuild_delivery_primary_key(
                context->source_raw, context->source_raw_len, out_key,
                out_key_len);
        }
        return NINLIL_E_INVALID_ARGUMENT;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY:
        return rebuild_delivery_primary_key(
            context->source_raw, context->source_raw_len, out_key, out_key_len);
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RETENTION_BASIS:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_CLEANUP_PLAN:
        if (owner_kind == NINLIL_MODEL_DOMAIN_RETENTION_SUBJECT_TRANSACTION) {
            if (context->source_raw_len != 16u) {
                return NINLIL_E_INVALID_ARGUMENT;
            }
            return rebuild_anchor_primary_key(
                context->source_raw, out_key, out_key_len);
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_RETENTION_SUBJECT_DELIVERY) {
            return rebuild_delivery_primary_key(
                context->source_raw, context->source_raw_len, out_key,
                out_key_len);
        }
        return NINLIL_E_INVALID_ARGUMENT;
    default:
        /* BLOB/witness/zero-PVD markers and primaries: not reverse sources. */
        return NINLIL_E_INVALID_ARGUMENT;
    }
}

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_peer_key_dispatch(
    ninlil_domain_scan_d3s1_context_t *context)
{
    ninlil_status_t status;
    uint8_t key[NINLIL_DOMAIN_SCAN_D3S1_PEER_KEY_CAPACITY];
    uint8_t key_len = 0u;
    uint8_t mode;

    if (context == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    mode = context->mode;
    if (mode < NINLIL_DOMAIN_SCAN_D3S1_MODE_MIN
        || mode > NINLIL_DOMAIN_SCAN_D3S1_MODE_MAX) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    switch (mode) {
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_SERVICE_QUOTA:
        status = ninlil_domain_scan_d3s1_rebuild_service_quota_key(
            context->source_raw, context->source_raw_len, key, &key_len);
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_SERVICE_RESERVATION:
        status = ninlil_domain_scan_d3s1_rebuild_service_reservation_key(
            context->source_raw, context->source_raw_len, key, &key_len);
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_SEQUENCE_INDEX:
        if (context->source_aux_len != 8u) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        status = ninlil_domain_scan_d3s1_rebuild_tx_sequence_index_key(
            ninlil_model_domain_decode_u64_be(context->source_aux), key,
            &key_len);
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_STATE:
        if (context->source_raw_len != 16u) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        status = ninlil_domain_scan_d3s1_rebuild_tx_state_key(
            context->source_raw, key, &key_len);
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_IDEMPOTENCY_MAP:
        status = ninlil_domain_scan_d3s1_rebuild_tx_idempotency_map_key(
            context->source_raw, context->source_raw_len, context->source_raw2,
            context->source_raw2_len, key, &key_len);
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_RESERVATION:
        if (context->source_raw_len != 16u) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        status = ninlil_domain_scan_d3s1_rebuild_tx_reservation_key(
            context->source_raw, key, &key_len);
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_SCHEDULER_OWNER:
        if (context->source_aux_len != 8u) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        status = ninlil_domain_scan_d3s1_rebuild_tx_scheduler_owner_key(
            ninlil_model_domain_decode_u64_be(context->source_aux), key,
            &key_len);
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_EVENT_ID_MAP:
        if (context->source_aux_len != 16u) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        status = ninlil_domain_scan_d3s1_rebuild_tx_event_id_map_key(
            context->source_raw, context->source_raw_len, context->source_aux,
            key, &key_len);
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_EVENT_SPOOL:
        if (context->source_raw_len != 16u) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        status = ninlil_domain_scan_d3s1_rebuild_tx_event_spool_key(
            context->source_raw, key, &key_len);
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_CANCEL_STATE:
        if (context->source_raw_len != 16u) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        status = ninlil_domain_scan_d3s1_rebuild_tx_cancel_state_key(
            context->source_raw, key, &key_len);
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_DELIVERY_RESULT_CACHE:
        status = ninlil_domain_scan_d3s1_rebuild_delivery_result_cache_key(
            context->source_raw, context->source_raw_len, key, &key_len);
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_DELIVERY_RESERVATION:
        status = ninlil_domain_scan_d3s1_rebuild_delivery_reservation_key(
            context->source_raw, context->source_raw_len, key, &key_len);
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_DELIVERY_SCHEDULER_OWNER:
        if (context->source_aux_len != 8u) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        status = ninlil_domain_scan_d3s1_rebuild_delivery_scheduler_owner_key(
            ninlil_model_domain_decode_u64_be(context->source_aux), key,
            &key_len);
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_DELIVERY_CANCEL_STATE:
        status = ninlil_domain_scan_d3s1_rebuild_delivery_cancel_state_key(
            context->source_raw, context->source_raw_len, key, &key_len);
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_INGRESS_RESERVATION:
        if (context->source_aux_len != 8u) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        status = ninlil_domain_scan_d3s1_rebuild_ingress_reservation_key(
            ninlil_model_domain_decode_u64_be(context->source_aux), key,
            &key_len);
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_INGRESS_SCHEDULER_OWNER:
        if (context->source_aux_len != 8u) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        status = ninlil_domain_scan_d3s1_rebuild_ingress_scheduler_owner_key(
            ninlil_model_domain_decode_u64_be(context->source_aux), key,
            &key_len);
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_REV_PRIMARY:
        status = rebuild_mode17_rev_primary(context, key, &key_len);
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_ATTEMPT_INDEX_LOCAL:
        /* Peer key already prepared into peer_key by prepare; re-derive. */
        if (context->source_subtype
            == NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT) {
            if (context->owner_kind
                == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION) {
                /* TX-local: index key = ID128(attempt_id) in source_aux. */
                if (context->source_aux_len != 16u) {
                    return NINLIL_E_INVALID_ARGUMENT;
                }
                status = rebuild_attempt_id_index_key(
                    context->source_aux, key, &key_len);
            } else {
                /* DELIVERY-owned: expect ABSENT; peer key unused for get skip
                 * path uses expect_presence; still need a well-formed key for
                 * ABSENT probe — use ID128 attempt_id when available. */
                if (context->source_aux_len != 16u) {
                    return NINLIL_E_INVALID_ARGUMENT;
                }
                status = rebuild_attempt_id_index_key(
                    context->source_aux, key, &key_len);
            }
        } else if (
            context->source_subtype
            == NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX) {
            if (context->source_raw_len != 16u
                || context->source_aux_len != 16u) {
                return NINLIL_E_INVALID_ARGUMENT;
            }
            status = rebuild_attempt_key_tx(
                context->source_raw, context->source_aux, key, &key_len);
        } else {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_RESULT_CALLBACK_RES:
        if (context->source_raw_len
                != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES
            || context->source_aux_len != 8u) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        status = rebuild_callback_reservation_key(
            context->source_raw, context->source_raw_len,
            ninlil_model_domain_decode_u64_be(context->source_aux), key,
            &key_len);
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_GATE_RETENTION_BASIS:
        status = rebuild_retention_basis_key(
            (uint16_t)context->owner_kind, context->source_raw,
            context->source_raw_len, key, &key_len);
        break;
    default:
        return NINLIL_E_INVALID_ARGUMENT;
    }

    if (status != NINLIL_OK) {
        context->peer_key_len = 0u;
        return status;
    }
    (void)memcpy(context->peer_key, key, key_len);
    context->peer_key_len = key_len;
    return NINLIL_OK;
}

static int copy_bytes_capped(
    uint8_t *dst,
    uint8_t dst_cap,
    uint8_t *out_len,
    const uint8_t *src,
    uint16_t src_len)
{
    if (src_len > dst_cap || (src_len != 0u && src == NULL)) {
        return 0;
    }
    if (src_len != 0u) {
        (void)memcpy(dst, src, src_len);
    }
    *out_len = (uint8_t)src_len;
    return 1;
}

/*
 * owner_kind context slot is u8. Closed owner kinds are small enums and
 * unknown values are S3-closed on the CURRENT source row; still refuse any
 * value that would truncate on cast to u8 (lossy binding).
 */
static int owner_kind_fits_u8(uint16_t owner_kind)
{
    return owner_kind <= 255u;
}

static int store_owner_kind_u8(
    ninlil_domain_scan_d3s1_context_t *ctx,
    uint16_t owner_kind)
{
    if (ctx == NULL || !owner_kind_fits_u8(owner_kind)) {
        return 0;
    }
    ctx->owner_kind = (uint8_t)owner_kind;
    return 1;
}

static ninlil_status_t prepare_service_modes(
    ninlil_domain_scan_d3s1_context_t *ctx,
    const ninlil_model_domain_body_service_t *svc,
    uint8_t mode)
{
    if (svc == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!copy_bytes_capped(
            ctx->source_raw, (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
            &ctx->source_raw_len, svc->service_key_raw,
            svc->service_key_raw_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ctx->source_raw2_len = 0u;
    ctx->source_aux_len = 0u;
    ctx->source_subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE;
    ctx->expect_presence = (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_PRESENT;
    if (mode == NINLIL_DOMAIN_SCAN_D3S1_MODE_SERVICE_RESERVATION) {
        if (!store_owner_kind_u8(
                ctx, NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_SERVICE)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
    } else {
        ctx->owner_kind = 0u;
    }
    return NINLIL_OK;
}

static ninlil_status_t prepare_tx_modes(
    ninlil_domain_scan_d3s1_context_t *ctx,
    const ninlil_model_domain_body_transaction_anchor_t *tx,
    uint8_t mode)
{
    int is_event;

    if (tx == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    is_event = (tx->family == NINLIL_FAMILY_EVENT_FACT) ? 1 : 0;
    ctx->source_subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR;
    ctx->source_raw2_len = 0u;
    ctx->source_aux_len = 0u;
    ctx->owner_kind = 0u;

    switch (mode) {
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_SEQUENCE_INDEX:
        ninlil_model_domain_encode_u64_be(
            ctx->source_aux, tx->transaction_sequence);
        ctx->source_aux_len = 8u;
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, tx->transaction_id, 16u)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        ctx->expect_presence = (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_PRESENT;
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_STATE:
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, tx->transaction_id, 16u)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        ctx->expect_presence = (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_PRESENT;
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_IDEMPOTENCY_MAP:
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, tx->idempotency_scope_raw,
                tx->idempotency_scope_raw_length)
            || !copy_bytes_capped(
                ctx->source_raw2,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW2_CAPACITY,
                &ctx->source_raw2_len, tx->idempotency_key,
                tx->idempotency_key_length)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        ctx->expect_presence = (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_PRESENT;
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_RESERVATION:
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, tx->transaction_id, 16u)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        if (!store_owner_kind_u8(
                ctx, NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_TRANSACTION)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        ctx->expect_presence = (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_PRESENT;
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_SCHEDULER_OWNER:
        ninlil_model_domain_encode_u64_be(
            ctx->source_aux, tx->scheduler_owner_sequence);
        ctx->source_aux_len = 8u;
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, tx->transaction_id, 16u)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        if (!store_owner_kind_u8(
                ctx, NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_TRANSACTION)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        ctx->expect_presence = (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_PRESENT;
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_EVENT_ID_MAP:
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, tx->idempotency_scope_raw,
                tx->idempotency_scope_raw_length)
            || !copy_bytes_capped(
                ctx->source_aux,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_AUX_CAPACITY,
                &ctx->source_aux_len, tx->event_id, 16u)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        /* EventFact PRESENT; DesiredState ABSENT. */
        ctx->expect_presence = is_event
            ? (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_PRESENT
            : (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_ABSENT;
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_EVENT_SPOOL:
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, tx->transaction_id, 16u)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        ctx->expect_presence = is_event
            ? (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_PRESENT
            : (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_ABSENT;
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_CANCEL_STATE:
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, tx->transaction_id, 16u)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        if (!store_owner_kind_u8(
                ctx, NINLIL_MODEL_DOMAIN_CANCEL_OWNER_TRANSACTION)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        /* DesiredState PRESENT; EventFact ABSENT. */
        ctx->expect_presence = is_event
            ? (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_ABSENT
            : (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_PRESENT;
        break;
    default:
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return NINLIL_OK;
}

static ninlil_status_t prepare_delivery_modes(
    ninlil_domain_scan_d3s1_context_t *ctx,
    const ninlil_model_domain_body_delivery_t *dlv,
    uint8_t mode)
{
    int is_event;

    if (dlv == NULL
        || dlv->delivery_key_raw_length
            != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES
        || dlv->delivery_key_raw == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    is_event = (dlv->service.family == NINLIL_FAMILY_EVENT_FACT) ? 1 : 0;
    ctx->source_subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY;
    ctx->source_raw2_len = 0u;
    ctx->source_aux_len = 0u;
    ctx->owner_kind = 0u;
    ctx->flags = 0u;
    if (!copy_bytes_capped(
            ctx->source_raw,
            (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
            &ctx->source_raw_len, dlv->delivery_key_raw,
            dlv->delivery_key_raw_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    switch (mode) {
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_DELIVERY_RESULT_CACHE:
        ctx->expect_presence = (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_PRESENT;
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_DELIVERY_RESERVATION:
        if (!store_owner_kind_u8(
                ctx, NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_DELIVERY)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        ctx->expect_presence = (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_PRESENT;
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_DELIVERY_SCHEDULER_OWNER:
        ninlil_model_domain_encode_u64_be(
            ctx->source_aux, dlv->scheduler_owner_sequence);
        ctx->source_aux_len = 8u;
        if (!store_owner_kind_u8(
                ctx, NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_DELIVERY)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        ctx->expect_presence = (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_PRESENT;
        break;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_DELIVERY_CANCEL_STATE:
        if (!store_owner_kind_u8(
                ctx, NINLIL_MODEL_DOMAIN_CANCEL_OWNER_DELIVERY)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        /* DesiredState PRESENT; EventFact ABSENT. */
        ctx->expect_presence = is_event
            ? (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_ABSENT
            : (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_PRESENT;
        break;
    default:
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return NINLIL_OK;
}

/*
 * Compose delivery_key_raw contents (exact 80) from ORDERED_INGRESS fields
 * for Mode 16 EXISTING_DELIVERY raw/kind match against referenced delivery
 * owner. Same field order as DELIVERY body bijection (docs17 §8.5).
 */
static int compose_delivery_raw_from_ingress(
    const ninlil_model_domain_body_ordered_ingress_t *ing,
    uint8_t out_raw[NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES])
{
    if (ing == NULL || out_raw == NULL) {
        return 0;
    }
    (void)memcpy(out_raw, ing->source.runtime_id, 16u);
    (void)memcpy(out_raw + 16, ing->source.application_instance_id, 16u);
    (void)memcpy(out_raw + 32, ing->transaction_id, 16u);
    (void)memcpy(out_raw + 48, ing->target.target_runtime, 16u);
    (void)memcpy(out_raw + 64, ing->target.target_application, 16u);
    return 1;
}

static ninlil_status_t prepare_ingress_modes(
    ninlil_domain_scan_d3s1_context_t *ctx,
    const ninlil_model_domain_body_ordered_ingress_t *ing,
    uint8_t mode)
{
    uint8_t seq_be[8];
    uint8_t delivery_raw[NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES];

    if (ing == NULL || ing->ordered_sequence == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ctx->source_subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS;
    ctx->source_raw2_len = 0u;
    ctx->source_aux_len = 0u;
    ctx->owner_kind = 0u;
    ctx->flags = 0u;
    ctx->source_raw_len = 0u;

    if (mode == NINLIL_DOMAIN_SCAN_D3S1_MODE_INGRESS_RESERVATION) {
        /*
         * Mode 15: only PENDING is applicable (Normative). Non-PENDING is
         * skip (caller must not call prepare); treat as invalid here.
         */
        if (ing->ingress_state != NINLIL_MODEL_DOMAIN_INGRESS_STATE_PENDING) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        ninlil_model_domain_encode_u64_be(seq_be, ing->ordered_sequence);
        ninlil_model_domain_encode_u64_be(
            ctx->source_aux, ing->ordered_sequence);
        ctx->source_aux_len = 8u;
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, seq_be, 8u)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        if (!store_owner_kind_u8(
                ctx, NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_INGRESS)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        ctx->expect_presence = (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_PRESENT;
        return NINLIL_OK;
    }

    if (mode != NINLIL_DOMAIN_SCAN_D3S1_MODE_INGRESS_SCHEDULER_OWNER) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (ing->owner_sequence == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u64_be(ctx->source_aux, ing->owner_sequence);
    ctx->source_aux_len = 8u;
    /* Mode 16 always PRESENT (ABSENT prohibited for all binding variants). */
    ctx->expect_presence = (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_PRESENT;

    switch (ing->owner_binding_kind) {
    case NINLIL_MODEL_DOMAIN_INGRESS_BINDING_NEW_DELIVERY:
        /* Ingress-owned SCHEDULER_OWNER; compare peer PVD to ingress. */
        ninlil_model_domain_encode_u64_be(seq_be, ing->ordered_sequence);
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, seq_be, 8u)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        if (!store_owner_kind_u8(
                ctx, NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_INGRESS)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        ctx->flags = 0u;
        break;
    case NINLIL_MODEL_DOMAIN_INGRESS_BINDING_EXISTING_TRANSACTION:
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, ing->transaction_id, 16u)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        if (!store_owner_kind_u8(
                ctx, NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_TRANSACTION)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        /* Peer PVD points at referenced TX primary — Mode 17 owns live PVD. */
        ctx->flags = NINLIL_DOMAIN_SCAN_D3S1_FLAG_SKIP_PEER_PVD;
        break;
    case NINLIL_MODEL_DOMAIN_INGRESS_BINDING_EXISTING_DELIVERY:
        if (!compose_delivery_raw_from_ingress(ing, delivery_raw)
            || !copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, delivery_raw,
                (uint16_t)NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        if (!store_owner_kind_u8(
                ctx, NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_DELIVERY)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        ctx->flags = NINLIL_DOMAIN_SCAN_D3S1_FLAG_SKIP_PEER_PVD;
        break;
    default:
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return NINLIL_OK;
}

/*
 * For ABSENT-expect modes with zero event_id (DesiredState Mode 8), still
 * rebuild a well-defined key from scope + zero event_id for the absence get.
 */
static int mode17_reverse_source_subtype(uint8_t subtype)
{
    switch (subtype) {
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE_QUOTA:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_SEQUENCE_INDEX:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_ID_MAP:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_SPOOL:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RETRY_SUMMARY:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_MANAGEMENT_LEDGER:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SCHEDULER_OWNER:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_CANCEL_STATE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVIDENCE_CELL:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RETENTION_BASIS:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_CLEANUP_PLAN:
        return 1;
    default:
        /* BLOB / witness / zero-PVD markers / primaries: not reverse sources. */
        return 0;
    }
}

static int mode_applicable(
    uint8_t mode,
    uint8_t family,
    uint8_t subtype)
{
    (void)family;
    if (mode == NINLIL_DOMAIN_SCAN_D3S1_MODE_SERVICE_QUOTA
        || mode == NINLIL_DOMAIN_SCAN_D3S1_MODE_SERVICE_RESERVATION) {
        return subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE;
    }
    if (mode >= NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_SEQUENCE_INDEX
        && mode <= NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_CANCEL_STATE) {
        return subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR;
    }
    if (mode >= NINLIL_DOMAIN_SCAN_D3S1_MODE_DELIVERY_RESULT_CACHE
        && mode <= NINLIL_DOMAIN_SCAN_D3S1_MODE_DELIVERY_CANCEL_STATE) {
        return subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY;
    }
    if (mode == NINLIL_DOMAIN_SCAN_D3S1_MODE_INGRESS_RESERVATION
        || mode == NINLIL_DOMAIN_SCAN_D3S1_MODE_INGRESS_SCHEDULER_OWNER) {
        return subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS;
    }
    if (mode == NINLIL_DOMAIN_SCAN_D3S1_MODE_REV_PRIMARY) {
        return mode17_reverse_source_subtype(subtype);
    }
    if (mode == NINLIL_DOMAIN_SCAN_D3S1_MODE_ATTEMPT_INDEX_LOCAL) {
        return subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT
            || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX;
    }
    if (mode == NINLIL_DOMAIN_SCAN_D3S1_MODE_RESULT_CALLBACK_RES) {
        return subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE;
    }
    if (mode == NINLIL_DOMAIN_SCAN_D3S1_MODE_GATE_RETENTION_BASIS) {
        return subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE
            || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE;
    }
    return 0;
}

static ninlil_status_t note_finding(ninlil_domain_scan_session_t *session)
{
    return ninlil_domain_scan_note_terminal_corrupt(session);
}

/* Mode 17 true-primary subtype from closed reverse table. */
static uint8_t mode17_expected_primary_subtype(
    const ninlil_domain_scan_d3s1_context_t *ctx)
{
    if (ctx == NULL) {
        return 0u;
    }
    switch (ctx->source_subtype) {
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE_QUOTA:
        return NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION:
        if (ctx->owner_kind == NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_SERVICE) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE;
        }
        if (ctx->owner_kind
            == NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_TRANSACTION) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR;
        }
        if (ctx->owner_kind == NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_INGRESS) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS;
        }
        if (ctx->owner_kind == NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_DELIVERY
            || ctx->owner_kind
                == NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_CALLBACK) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY;
        }
        return 0u;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_SEQUENCE_INDEX:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_ID_MAP:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_SPOOL:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RETRY_SUMMARY:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_MANAGEMENT_LEDGER:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX:
        return NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SCHEDULER_OWNER:
        if (ctx->owner_kind
            == NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_TRANSACTION) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR;
        }
        if (ctx->owner_kind == NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_DELIVERY) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY;
        }
        if (ctx->owner_kind == NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_INGRESS) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS;
        }
        return 0u;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT:
        if (ctx->owner_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR;
        }
        if (ctx->owner_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_DELIVERY) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY;
        }
        return 0u;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_CANCEL_STATE:
        if (ctx->owner_kind == NINLIL_MODEL_DOMAIN_CANCEL_OWNER_TRANSACTION) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR;
        }
        if (ctx->owner_kind == NINLIL_MODEL_DOMAIN_CANCEL_OWNER_DELIVERY) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY;
        }
        return 0u;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVIDENCE_CELL:
        if (ctx->owner_kind
            == NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_TRANSACTION) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR;
        }
        if (ctx->owner_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_DELIVERY) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY;
        }
        return 0u;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY:
        return NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RETENTION_BASIS:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_CLEANUP_PLAN:
        if (ctx->owner_kind
            == NINLIL_MODEL_DOMAIN_RETENTION_SUBJECT_TRANSACTION) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR;
        }
        if (ctx->owner_kind
            == NINLIL_MODEL_DOMAIN_RETENTION_SUBJECT_DELIVERY) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY;
        }
        return 0u;
    default:
        return 0u;
    }
}

/*
 * Mode → expected peer domain subtype (never accept wrong subtype silently).
 * Mode 18 peer depends on source side.
 */
static uint8_t expected_peer_subtype(
    const ninlil_domain_scan_d3s1_context_t *ctx)
{
    uint8_t mode;

    if (ctx == NULL) {
        return 0u;
    }
    mode = ctx->mode;
    switch (mode) {
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_SERVICE_QUOTA:
        return NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE_QUOTA;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_SERVICE_RESERVATION:
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_RESERVATION:
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_DELIVERY_RESERVATION:
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_INGRESS_RESERVATION:
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_RESULT_CALLBACK_RES:
        return NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_SEQUENCE_INDEX:
        return NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_SEQUENCE_INDEX;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_STATE:
        return NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_IDEMPOTENCY_MAP:
        return NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_SCHEDULER_OWNER:
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_DELIVERY_SCHEDULER_OWNER:
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_INGRESS_SCHEDULER_OWNER:
        return NINLIL_MODEL_DOMAIN_SUBTYPE_SCHEDULER_OWNER;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_EVENT_ID_MAP:
        return NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_ID_MAP;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_EVENT_SPOOL:
        return NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_SPOOL;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_CANCEL_STATE:
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_DELIVERY_CANCEL_STATE:
        return NINLIL_MODEL_DOMAIN_SUBTYPE_CANCEL_STATE;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_DELIVERY_RESULT_CACHE:
        return NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_REV_PRIMARY:
        return mode17_expected_primary_subtype(ctx);
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_ATTEMPT_INDEX_LOCAL:
        if (ctx->source_subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX;
        }
        if (ctx->source_subtype
            == NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT;
        }
        return 0u;
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_GATE_RETENTION_BASIS:
        return NINLIL_MODEL_DOMAIN_SUBTYPE_RETENTION_BASIS;
    default:
        return 0u;
    }
}

/*
 * PRESENT peer verification layering (chunk-A/B/C):
 *   1) peer key: parse CURRENT key → expected subtype (+ domain family)
 *   Mode 17 only (before envelope):
 *     ALWAYS VALUE_DIGEST(complete peer value) vs source header PVD.
 *     Mismatch is D3 CORRUPT even when envelope framing is future.
 *   2) envelope: current framing decode; header.subtype must match
 *   3) (non-17) header PVD vs source value-digest (unless FLAG_SKIP_PEER_PVD)
 *      + mode body raw
 *   Mode 17 after envelope: primary raw bijection only when current-framed.
 *
 * Full peer same-record typed structural validation is intentionally NOT
 * re-run here: S3 owns full peer structural closure when the peer is visited
 * as a normal current row. Framing-future peer values (decode UNSUPPORTED)
 * may skip only the body/raw layer after PVD matched; presence already
 * succeeded via exact_get — leave structural/future non-terminal ownership
 * to S3.
 */
static ninlil_status_t verify_mode17_primary_raw(
    const ninlil_domain_scan_d3s1_context_t *ctx,
    const ninlil_model_domain_envelope_t *env,
    uint8_t expect_subtype);

static ninlil_status_t verify_peer_present(
    ninlil_domain_scan_d3s1_context_t *ctx,
    ninlil_bytes_view_t peer_value)
{
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_key_view_t key_view;
    ninlil_bytes_view_t peer_key_view;
    ninlil_status_t status;
    uint8_t expect_subtype;

    if (ctx == NULL || ctx->peer_key_len == 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    expect_subtype = expected_peer_subtype(ctx);
    if (expect_subtype == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    peer_key_view.data = ctx->peer_key;
    peer_key_view.length = ctx->peer_key_len;
    status = ninlil_model_domain_parse_key(peer_key_view, &key_view);
    if (status != NINLIL_OK) {
        /* Rebuild always emits CURRENT keys; any other class is corrupt. */
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (key_view.family != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN
        || key_view.subtype != expect_subtype) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    /* Mode 17: live primary VALUE_DIGEST vs source header PVD — before decode. */
    if (ctx->mode == NINLIL_DOMAIN_SCAN_D3S1_MODE_REV_PRIMARY) {
        ninlil_model_domain_digest_t live;
        status = ninlil_model_domain_value_digest(peer_value, &live);
        if (status != NINLIL_OK
            || memcmp(
                   live.bytes, ctx->expected_pvd,
                   NINLIL_MODEL_DOMAIN_DIGEST_BYTES)
                != 0) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        status = ninlil_model_domain_decode_envelope(peer_value, &env);
        if (status == NINLIL_E_UNSUPPORTED) {
            /*
             * Framing-future primary: PVD already matched. Skip body/raw only;
             * future non-terminal ownership remains at normal S3 visit.
             */
            return NINLIL_OK;
        }
        if (status != NINLIL_OK) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (env.header.subtype != expect_subtype) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return verify_mode17_primary_raw(ctx, &env, expect_subtype);
    }

    status = ninlil_model_domain_decode_envelope(peer_value, &env);
    if (status == NINLIL_E_UNSUPPORTED) {
        /*
         * Framing-future peer value: not false CORRUPT. Full peer structural
         * / future non-terminal ownership remains at normal S3 visit.
         * Future/current handling preserves unsupported precedence.
         */
        return NINLIL_OK;
    }
    if (status != NINLIL_OK) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (env.header.subtype != expect_subtype) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    /*
     * Mode 16 EXISTING_*: peer PVD is the referenced primary's live digest,
     * not the ingress value digest. Mode 19: never compare reservation PVD
     * to RESULT value (PVD is DELIVERY; Mode 17 proves CALLBACK RES→DELIVERY).
     */
    if ((ctx->flags & NINLIL_DOMAIN_SCAN_D3S1_FLAG_SKIP_PEER_PVD) == 0u
        && memcmp(
               env.header.primary_value_digest, ctx->expected_pvd,
               NINLIL_MODEL_DOMAIN_DIGEST_BYTES)
            != 0) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    switch (ctx->mode) {
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_SERVICE_QUOTA: {
        ninlil_model_domain_body_service_quota_t body;
        status = ninlil_model_domain_decode_body_service_quota(env.body, &body);
        if (status != NINLIL_OK
            || body.service_key_raw_length != ctx->source_raw_len
            || (ctx->source_raw_len != 0u
                && memcmp(
                       body.service_key_raw, ctx->source_raw,
                       ctx->source_raw_len)
                    != 0)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        break;
    }
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_SERVICE_RESERVATION:
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_RESERVATION:
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_DELIVERY_RESERVATION:
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_INGRESS_RESERVATION: {
        ninlil_model_domain_body_reservation_t body;
        status = ninlil_model_domain_decode_body_reservation(env.body, &body);
        if (status != NINLIL_OK
            || body.owner_kind != ctx->owner_kind
            || body.owner_key_raw_length != ctx->source_raw_len
            || (ctx->source_raw_len != 0u
                && memcmp(
                       body.owner_key_raw, ctx->source_raw, ctx->source_raw_len)
                    != 0)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        break;
    }
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_DELIVERY_RESULT_CACHE: {
        ninlil_model_domain_body_result_cache_t body;
        status = ninlil_model_domain_decode_body_result_cache(env.body, &body);
        if (status != NINLIL_OK
            || body.delivery_key_raw_length != ctx->source_raw_len
            || (ctx->source_raw_len != 0u
                && memcmp(
                       body.delivery_key_raw, ctx->source_raw,
                       ctx->source_raw_len)
                    != 0)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        break;
    }
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_SEQUENCE_INDEX: {
        ninlil_model_domain_body_transaction_sequence_index_t body;
        status = ninlil_model_domain_decode_body_transaction_sequence_index(
            env.body, &body);
        if (status != NINLIL_OK
            || body.transaction_sequence
                != ninlil_model_domain_decode_u64_be(ctx->source_aux)
            || memcmp(body.transaction_id, ctx->source_raw, 16u) != 0) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        break;
    }
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_STATE: {
        ninlil_model_domain_body_transaction_state_t body;
        status = ninlil_model_domain_decode_body_transaction_state(
            env.body, &body);
        if (status != NINLIL_OK
            || memcmp(body.transaction_id, ctx->source_raw, 16u) != 0) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        break;
    }
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_IDEMPOTENCY_MAP: {
        ninlil_model_domain_body_idempotency_map_t body;
        status = ninlil_model_domain_decode_body_idempotency_map(
            env.body, &body);
        if (status != NINLIL_OK
            || body.scope_raw_length != ctx->source_raw_len
            || body.idempotency_key_length != ctx->source_raw2_len
            || (ctx->source_raw_len != 0u
                && memcmp(body.scope_raw, ctx->source_raw, ctx->source_raw_len)
                    != 0)
            || (ctx->source_raw2_len != 0u
                && memcmp(
                       body.idempotency_key, ctx->source_raw2,
                       ctx->source_raw2_len)
                    != 0)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        break;
    }
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_SCHEDULER_OWNER:
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_DELIVERY_SCHEDULER_OWNER:
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_INGRESS_SCHEDULER_OWNER: {
        ninlil_model_domain_body_scheduler_owner_t body;
        status = ninlil_model_domain_decode_body_scheduler_owner(
            env.body, &body);
        if (status != NINLIL_OK
            || body.owner_sequence
                != ninlil_model_domain_decode_u64_be(ctx->source_aux)
            || body.owner_kind != ctx->owner_kind
            || body.subject_key_raw_length != ctx->source_raw_len
            || (ctx->source_raw_len != 0u
                && memcmp(
                       body.subject_key_raw, ctx->source_raw,
                       ctx->source_raw_len)
                    != 0)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        break;
    }
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_EVENT_ID_MAP: {
        ninlil_model_domain_body_event_id_map_t body;
        status = ninlil_model_domain_decode_body_event_id_map(env.body, &body);
        if (status != NINLIL_OK
            || body.scope_raw_length != ctx->source_raw_len
            || (ctx->source_raw_len != 0u
                && memcmp(body.scope_raw, ctx->source_raw, ctx->source_raw_len)
                    != 0)
            || memcmp(body.event_id, ctx->source_aux, 16u) != 0) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        break;
    }
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_EVENT_SPOOL: {
        ninlil_model_domain_body_event_spool_t body;
        status = ninlil_model_domain_decode_body_event_spool(env.body, &body);
        if (status != NINLIL_OK
            || memcmp(body.transaction_id, ctx->source_raw, 16u) != 0) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        break;
    }
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_CANCEL_STATE:
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_DELIVERY_CANCEL_STATE: {
        ninlil_model_domain_body_cancel_state_t body;
        status = ninlil_model_domain_decode_body_cancel_state(env.body, &body);
        if (status != NINLIL_OK
            || body.cancel_owner_kind != ctx->owner_kind
            || body.owner_key_raw_length != ctx->source_raw_len
            || (ctx->source_raw_len != 0u
                && memcmp(
                       body.owner_key_raw, ctx->source_raw, ctx->source_raw_len)
                    != 0)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        break;
    }
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_ATTEMPT_INDEX_LOCAL: {
        if (ctx->source_raw2_len != 2u) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (ctx->source_subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT) {
            ninlil_model_domain_body_attempt_id_index_t body;
            status = ninlil_model_domain_decode_body_attempt_id_index(
                env.body, &body);
            if (status != NINLIL_OK
                || memcmp(body.attempt_id, ctx->source_aux, 16u) != 0
                || memcmp(body.transaction_id, ctx->source_raw, 16u) != 0
                || body.attempt_kind
                    != ninlil_model_domain_decode_u16_be(
                           &ctx->source_raw2[0])) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            /* Exact TX attempt key digest binding (no counts). */
            {
                uint8_t att_key[NINLIL_DOMAIN_SCAN_D3S1_PEER_KEY_CAPACITY];
                uint8_t att_key_len = 0u;
                ninlil_model_domain_digest_t dig;
                ninlil_bytes_view_t kv;
                if (rebuild_attempt_key_tx(
                        ctx->source_raw, ctx->source_aux, att_key, &att_key_len)
                    != NINLIL_OK) {
                    return NINLIL_E_STORAGE_CORRUPT;
                }
                kv.data = att_key;
                kv.length = att_key_len;
                if (ninlil_model_domain_key_digest(kv, &dig) != NINLIL_OK
                    || memcmp(
                           dig.bytes, body.attempt_record_key_digest,
                           NINLIL_MODEL_DOMAIN_DIGEST_BYTES)
                        != 0) {
                    return NINLIL_E_STORAGE_CORRUPT;
                }
            }
        } else {
            /* AII → ATT: attempt_kind equality via source_raw2 (symmetric). */
            ninlil_model_domain_body_attempt_t body;
            status = ninlil_model_domain_decode_body_attempt(env.body, &body);
            if (status != NINLIL_OK
                || body.attempt_owner_kind
                    != NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION
                || memcmp(body.attempt_id, ctx->source_aux, 16u) != 0
                || memcmp(body.transaction_id, ctx->source_raw, 16u) != 0
                || body.owner_key_raw_length != 16u
                || memcmp(body.owner_key_raw, ctx->source_raw, 16u) != 0
                || body.attempt_kind
                    != ninlil_model_domain_decode_u16_be(
                           &ctx->source_raw2[0])) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
        }
        break;
    }
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_RESULT_CALLBACK_RES: {
        /* Presence + nested delivery raw + token only; never RESULT↔PVD. */
        ninlil_model_domain_body_reservation_t body;
        const uint8_t *nested_dlv = NULL;
        uint64_t nested_tok = 0u;
        status = ninlil_model_domain_decode_body_reservation(env.body, &body);
        if (status != NINLIL_OK
            || body.owner_kind
                != NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_CALLBACK
            || !parse_callback_owner_nested(
                   body.owner_key_raw, body.owner_key_raw_length, &nested_dlv,
                   &nested_tok)
            || ctx->source_raw_len
                != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES
            || memcmp(nested_dlv, ctx->source_raw, ctx->source_raw_len) != 0
            || nested_tok
                != ninlil_model_domain_decode_u64_be(ctx->source_aux)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        break;
    }
    case NINLIL_DOMAIN_SCAN_D3S1_MODE_GATE_RETENTION_BASIS: {
        ninlil_model_domain_body_retention_basis_t body;
        status = ninlil_model_domain_decode_body_retention_basis(
            env.body, &body);
        if (status != NINLIL_OK
            || body.subject_kind != ctx->owner_kind
            || body.subject_key_raw_length != ctx->source_raw_len
            || (ctx->source_raw_len != 0u
                && memcmp(
                       body.subject_key_raw, ctx->source_raw,
                       ctx->source_raw_len)
                    != 0)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        break;
    }
    default:
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return NINLIL_OK;
}

/* Mode 17: byte-exact raw identity of true primary vs source rebuild material. */
static ninlil_status_t verify_mode17_primary_raw(
    const ninlil_domain_scan_d3s1_context_t *ctx,
    const ninlil_model_domain_envelope_t *env,
    uint8_t expect_subtype)
{
    ninlil_status_t status;

    if (ctx == NULL || env == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    switch (expect_subtype) {
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE: {
        ninlil_model_domain_body_service_t body;
        status = ninlil_model_domain_decode_body_service(env->body, &body);
        if (status != NINLIL_OK
            || body.service_key_raw_length != ctx->source_raw_len
            || (ctx->source_raw_len != 0u
                && memcmp(
                       body.service_key_raw, ctx->source_raw,
                       ctx->source_raw_len)
                    != 0)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR: {
        ninlil_model_domain_body_transaction_anchor_t body;
        const uint8_t *tx_id;
        status = ninlil_model_domain_decode_body_transaction_anchor(
            env->body, &body);
        if (status != NINLIL_OK) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (ctx->source_subtype
            == NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP) {
            /* source_aux=tx, source_raw=scope, source_raw2=idem_key. */
            if (ctx->source_aux_len != 16u
                || memcmp(body.transaction_id, ctx->source_aux, 16u) != 0
                || body.idempotency_scope_raw_length != ctx->source_raw_len
                || body.idempotency_key_length != ctx->source_raw2_len
                || (ctx->source_raw_len != 0u
                    && memcmp(
                           body.idempotency_scope_raw, ctx->source_raw,
                           ctx->source_raw_len)
                        != 0)
                || (ctx->source_raw2_len != 0u
                    && memcmp(
                           body.idempotency_key, ctx->source_raw2,
                           ctx->source_raw2_len)
                        != 0)) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            return NINLIL_OK;
        }
        tx_id = ctx->source_raw;
        if (ctx->source_raw_len != 16u
            || memcmp(body.transaction_id, tx_id, 16u) != 0) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }
    case NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY: {
        ninlil_model_domain_body_delivery_t body;
        const uint8_t *expect_raw = ctx->source_raw;
        uint16_t expect_len = ctx->source_raw_len;
        const uint8_t *nested = NULL;
        uint64_t tok = 0u;

        status = ninlil_model_domain_decode_body_delivery(env->body, &body);
        if (status != NINLIL_OK) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (ctx->source_subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION
            && ctx->owner_kind
                == NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_CALLBACK) {
            if (!parse_callback_owner_nested(
                    ctx->source_raw, ctx->source_raw_len, &nested, &tok)) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            (void)tok;
            expect_raw = nested;
            expect_len = NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES;
        }
        if (body.delivery_key_raw_length != expect_len
            || (expect_len != 0u
                && memcmp(body.delivery_key_raw, expect_raw, expect_len)
                    != 0)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS: {
        ninlil_model_domain_body_ordered_ingress_t body;
        status = ninlil_model_domain_decode_body_ordered_ingress(
            env->body, &body);
        if (status != NINLIL_OK || ctx->source_raw_len != 8u
            || body.ordered_sequence
                != ninlil_model_domain_decode_u64_be(ctx->source_raw)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }
    default:
        return NINLIL_E_INVALID_ARGUMENT;
    }
}

/*
 * Mode 17 prepare: copy source header PVD before get; fill rebuild material.
 * Returns INVALID_ARGUMENT for excluded / non-reverse subtypes (caller skip).
 */
static ninlil_status_t prepare_mode17_rev_primary(
    ninlil_domain_scan_d3s1_context_t *ctx,
    const ninlil_model_domain_typed_record_t *typed)
{
    if (ctx == NULL || typed == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memcpy(
        ctx->expected_pvd, typed->envelope.header.primary_value_digest,
        NINLIL_MODEL_DOMAIN_DIGEST_BYTES);
    ctx->source_subtype = typed->subtype;
    ctx->source_raw_len = 0u;
    ctx->source_raw2_len = 0u;
    ctx->source_aux_len = 0u;
    ctx->owner_kind = 0u;
    ctx->expect_presence = (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_PRESENT;
    ctx->flags = 0u;

    switch (typed->subtype) {
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE_QUOTA:
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, typed->service_quota.service_key_raw,
                typed->service_quota.service_key_raw_length)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION:
        if (!store_owner_kind_u8(ctx, typed->reservation.owner_kind)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, typed->reservation.owner_key_raw,
                typed->reservation.owner_key_raw_length)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_SEQUENCE_INDEX:
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len,
                typed->transaction_sequence_index.transaction_id, 16u)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE:
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, typed->transaction_state.transaction_id,
                16u)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP:
        /* source_raw=scope, source_raw2=idem_key, source_aux=tx_id. */
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, typed->idempotency_map.scope_raw,
                typed->idempotency_map.scope_raw_length)
            || !copy_bytes_capped(
                ctx->source_raw2,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW2_CAPACITY,
                &ctx->source_raw2_len, typed->idempotency_map.idempotency_key,
                typed->idempotency_map.idempotency_key_length)
            || !copy_bytes_capped(
                ctx->source_aux,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_AUX_CAPACITY,
                &ctx->source_aux_len, typed->idempotency_map.transaction_id,
                16u)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_ID_MAP:
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, typed->event_id_map.transaction_id,
                16u)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_SPOOL:
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, typed->event_spool.transaction_id,
                16u)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RETRY_SUMMARY:
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, typed->retry_summary.transaction_id,
                16u)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_MANAGEMENT_LEDGER:
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, typed->management_ledger.transaction_id,
                16u)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SCHEDULER_OWNER:
        if (!store_owner_kind_u8(ctx, typed->scheduler_owner.owner_kind)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, typed->scheduler_owner.subject_key_raw,
                typed->scheduler_owner.subject_key_raw_length)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT:
        if (!store_owner_kind_u8(ctx, typed->attempt.attempt_owner_kind)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, typed->attempt.owner_key_raw,
                typed->attempt.owner_key_raw_length)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX:
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, typed->attempt_id_index.transaction_id,
                16u)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_CANCEL_STATE:
        if (!store_owner_kind_u8(
                ctx, typed->cancel_state.cancel_owner_kind)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, typed->cancel_state.owner_key_raw,
                typed->cancel_state.owner_key_raw_length)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVIDENCE_CELL:
        if (!store_owner_kind_u8(
                ctx, typed->evidence_cell.evidence_owner_kind)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, typed->evidence_cell.owner_key_raw,
                typed->evidence_cell.owner_key_raw_length)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE:
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, typed->result_cache.delivery_key_raw,
                typed->result_cache.delivery_key_raw_length)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY:
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, typed->reverse_reply.delivery_key_raw,
                typed->reverse_reply.delivery_key_raw_length)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RETENTION_BASIS:
        if (!store_owner_kind_u8(ctx, typed->retention_basis.subject_kind)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, typed->retention_basis.subject_key_raw,
                typed->retention_basis.subject_key_raw_length)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_CLEANUP_PLAN:
        if (!store_owner_kind_u8(ctx, typed->cleanup_plan.subject_kind)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, typed->cleanup_plan.subject_key_raw,
                typed->cleanup_plan.subject_key_raw_length)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        return NINLIL_OK;
    default:
        return NINLIL_E_INVALID_ARGUMENT;
    }
}

/* Mode 18: ATTEMPT ↔ ATTEMPT_ID_INDEX local gate (no counts). */
static ninlil_status_t prepare_mode18_attempt_index(
    ninlil_domain_scan_d3s1_context_t *ctx,
    const ninlil_model_domain_typed_record_t *typed)
{
    if (ctx == NULL || typed == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ctx->source_subtype = typed->subtype;
    ctx->source_raw2_len = 0u;
    ctx->flags = NINLIL_DOMAIN_SCAN_D3S1_FLAG_SKIP_PEER_PVD;
    if (typed->subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT) {
        if (!store_owner_kind_u8(ctx, typed->attempt.attempt_owner_kind)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        if (!copy_bytes_capped(
                ctx->source_aux,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_AUX_CAPACITY,
                &ctx->source_aux_len, typed->attempt.attempt_id, 16u)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        if (typed->attempt.attempt_owner_kind
            == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION) {
            if (!copy_bytes_capped(
                    ctx->source_raw,
                    (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                    &ctx->source_raw_len, typed->attempt.transaction_id,
                    16u)) {
                return NINLIL_E_INVALID_ARGUMENT;
            }
            ninlil_model_domain_encode_u16_be(
                ctx->source_raw2, typed->attempt.attempt_kind);
            ctx->source_raw2_len = 2u;
            ctx->expect_presence = (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_PRESENT;
        } else if (
            typed->attempt.attempt_owner_kind
            == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_DELIVERY) {
            /* DELIVERY-owned index ABSENT. */
            ctx->source_raw_len = 0u;
            ctx->expect_presence = (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_ABSENT;
        } else {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        return NINLIL_OK;
    }
    if (typed->subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX) {
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, typed->attempt_id_index.transaction_id,
                16u)
            || !copy_bytes_capped(
                ctx->source_aux,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_AUX_CAPACITY,
                &ctx->source_aux_len, typed->attempt_id_index.attempt_id,
                16u)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        ninlil_model_domain_encode_u16_be(
            ctx->source_raw2, typed->attempt_id_index.attempt_kind);
        ctx->source_raw2_len = 2u;
        if (!store_owner_kind_u8(
                ctx, NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        ctx->expect_presence = (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_PRESENT;
        return NINLIL_OK;
    }
    return NINLIL_E_INVALID_ARGUMENT;
}

/* Mode 19: RESULT_CACHE → CALLBACK RES ACTIVE gate (presence/raw/token only). */
static ninlil_status_t prepare_mode19_result_callback(
    ninlil_domain_scan_d3s1_context_t *ctx,
    const ninlil_model_domain_body_result_cache_t *rc)
{
    int active;

    if (ctx == NULL || rc == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ctx->source_subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE;
    if (!store_owner_kind_u8(
            ctx, NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_CALLBACK)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /* Never compare reservation header PVD to RESULT value. */
    ctx->flags = NINLIL_DOMAIN_SCAN_D3S1_FLAG_SKIP_PEER_PVD;
    ctx->source_raw2_len = 0u;
    if (!copy_bytes_capped(
            ctx->source_raw,
            (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
            &ctx->source_raw_len, rc->delivery_key_raw,
            rc->delivery_key_raw_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u64_be(ctx->source_aux, rc->token_generation);
    ctx->source_aux_len = 8u;
    active = (rc->delivery_state
                  == NINLIL_MODEL_DOMAIN_DELIVERY_STATE_DELIVERY_STARTED
              && rc->token_state == NINLIL_MODEL_DOMAIN_TOKEN_STATE_ACTIVE)
        ? 1
        : 0;
    ctx->expect_presence = active != 0
        ? (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_PRESENT
        : (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_ABSENT;
    return NINLIL_OK;
}

/*
 * Mode 20: §9 terminal retained PRESENT / active ABSENT matrix.
 * TX: only NINLIL_TXN_TERMINAL is terminal retained.
 * Delivery (via RESULT_CACHE.delivery_state): RESULT_COMMITTED,
 * DISPOSITION_COMMITTED, CANCEL_TOMBSTONE_ONLY terminal/cancel-only;
 * other legal states active.
 */
static int mode20_tx_terminal_retained(uint32_t state)
{
    return state == NINLIL_TXN_TERMINAL ? 1 : 0;
}

static int mode20_delivery_terminal_retained(uint32_t delivery_state)
{
    return delivery_state
            == NINLIL_MODEL_DOMAIN_DELIVERY_STATE_RESULT_COMMITTED
        || delivery_state
            == NINLIL_MODEL_DOMAIN_DELIVERY_STATE_DISPOSITION_COMMITTED
        || delivery_state
            == NINLIL_MODEL_DOMAIN_DELIVERY_STATE_CANCEL_TOMBSTONE_ONLY;
}

static ninlil_status_t prepare_mode20_retention(
    ninlil_domain_scan_d3s1_context_t *ctx,
    const ninlil_model_domain_typed_record_t *typed)
{
    int present;

    if (ctx == NULL || typed == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ctx->source_subtype = typed->subtype;
    ctx->source_raw2_len = 0u;
    ctx->source_aux_len = 0u;
    /* Peer retention PVD is ANCHOR/DELIVERY; Mode 17 proves it. */
    ctx->flags = NINLIL_DOMAIN_SCAN_D3S1_FLAG_SKIP_PEER_PVD;

    if (typed->subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE) {
        if (!store_owner_kind_u8(
                ctx, NINLIL_MODEL_DOMAIN_RETENTION_SUBJECT_TRANSACTION)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, typed->transaction_state.transaction_id,
                16u)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        present = mode20_tx_terminal_retained(typed->transaction_state.state);
        ctx->expect_presence = present != 0
            ? (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_PRESENT
            : (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_ABSENT;
        return NINLIL_OK;
    }
    if (typed->subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE) {
        if (!store_owner_kind_u8(
                ctx, NINLIL_MODEL_DOMAIN_RETENTION_SUBJECT_DELIVERY)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        if (!copy_bytes_capped(
                ctx->source_raw,
                (uint8_t)NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY,
                &ctx->source_raw_len, typed->result_cache.delivery_key_raw,
                typed->result_cache.delivery_key_raw_length)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        present = mode20_delivery_terminal_retained(
            typed->result_cache.delivery_state);
        ctx->expect_presence = present != 0
            ? (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_PRESENT
            : (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_ABSENT;
        return NINLIL_OK;
    }
    return NINLIL_E_INVALID_ARGUMENT;
}

ninlil_status_t ninlil_domain_scan_d3s1_evaluate_after_s3(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    uint32_t key_length,
    uint32_t value_length)
{
    ninlil_domain_scan_d3s1_context_t *ctx;
    ninlil_model_domain_typed_record_t *typed;
    ninlil_model_domain_digest_t pvd;
    ninlil_bytes_view_t value_view;
    ninlil_bytes_view_t peer_key;
    ninlil_domain_scan_exact_get_result_t exact;
    ninlil_status_t status;
    uint8_t mode;
    uint8_t family;
    uint8_t subtype;

    if (session == NULL || workspace == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ctx = session->bound_d3_context;
    if (ctx == NULL) {
        return NINLIL_OK;
    }
    /* profile_mismatch / future_profile_candidate: evaluator off (§18.12.7). */
    if (session->profile_mismatch != 0u
        || session->future_profile_candidate != 0u
        || session->profile_exact_active == 0u) {
        return NINLIL_OK;
    }
    if (key_length < NINLIL_MODEL_DOMAIN_KEY_MIN_BYTES
        || key_length > NINLIL_DOMAIN_SCAN_KEY_CAPACITY) {
        return NINLIL_OK;
    }
    family = workspace->key[8];
    subtype = workspace->key[9];
    if (family != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN) {
        return NINLIL_OK;
    }

    mode = ctx->mode;
    if (mode < NINLIL_DOMAIN_SCAN_D3S1_MODE_MIN
        || mode > NINLIL_DOMAIN_SCAN_D3S1_MODE_IMPLEMENTED_MAX) {
        return NINLIL_OK;
    }
    if (!mode_applicable(mode, family, subtype)) {
        return NINLIL_OK;
    }

    /*
     * Caller (process_ok_row) must only invoke after typed_current_ok==1 for
     * this row. typed scratch then describes the current source row.
     */
    typed = &workspace->row_validate_scratch.typed;
    if (typed->subtype != subtype) {
        return note_finding(session);
    }

    /*
     * Mode 15: non-PENDING ORDERED_INGRESS is non-applicable (Normative
     * permits skip; v1 body is PENDING-only but gate stays explicit).
     */
    if (mode == NINLIL_DOMAIN_SCAN_D3S1_MODE_INGRESS_RESERVATION
        && typed->ordered_ingress.ingress_state
            != NINLIL_MODEL_DOMAIN_INGRESS_STATE_PENDING) {
        return NINLIL_OK;
    }

    ctx->mode = mode;
    ctx->flags = 0u;
    ctx->peer_key_len = 0u;

    if (mode == NINLIL_DOMAIN_SCAN_D3S1_MODE_REV_PRIMARY) {
        /* Source header PVD copied before get (not secondary value digest). */
        status = prepare_mode17_rev_primary(ctx, typed);
    } else if (mode == NINLIL_DOMAIN_SCAN_D3S1_MODE_ATTEMPT_INDEX_LOCAL) {
        /*
         * Mode 18 sets FLAG_SKIP_PEER_PVD: expected_pvd unused. Do not
         * compute source VALUE_DIGEST (Modes 18–20 local gates only).
         */
        status = prepare_mode18_attempt_index(ctx, typed);
    } else if (mode == NINLIL_DOMAIN_SCAN_D3S1_MODE_RESULT_CALLBACK_RES) {
        /* Mode 19 SKIP_PEER_PVD: never PVD-to-RESULT; expected_pvd unused. */
        status = prepare_mode19_result_callback(ctx, &typed->result_cache);
    } else if (mode == NINLIL_DOMAIN_SCAN_D3S1_MODE_GATE_RETENTION_BASIS) {
        /* Mode 20 SKIP_PEER_PVD: retention header PVD is Mode 17. */
        status = prepare_mode20_retention(ctx, typed);
    } else if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE) {
        value_view.data = value_length == 0u ? NULL : workspace->value;
        value_view.length = value_length;
        status = ninlil_model_domain_value_digest(value_view, &pvd);
        if (status != NINLIL_OK) {
            return note_finding(session);
        }
        (void)memcpy(
            ctx->expected_pvd, pvd.bytes, NINLIL_MODEL_DOMAIN_DIGEST_BYTES);
        status = prepare_service_modes(ctx, &typed->service, mode);
    } else if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR) {
        value_view.data = value_length == 0u ? NULL : workspace->value;
        value_view.length = value_length;
        status = ninlil_model_domain_value_digest(value_view, &pvd);
        if (status != NINLIL_OK) {
            return note_finding(session);
        }
        (void)memcpy(
            ctx->expected_pvd, pvd.bytes, NINLIL_MODEL_DOMAIN_DIGEST_BYTES);
        status = prepare_tx_modes(ctx, &typed->transaction_anchor, mode);
    } else if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY) {
        value_view.data = value_length == 0u ? NULL : workspace->value;
        value_view.length = value_length;
        status = ninlil_model_domain_value_digest(value_view, &pvd);
        if (status != NINLIL_OK) {
            return note_finding(session);
        }
        (void)memcpy(
            ctx->expected_pvd, pvd.bytes, NINLIL_MODEL_DOMAIN_DIGEST_BYTES);
        status = prepare_delivery_modes(ctx, &typed->delivery, mode);
    } else if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS) {
        value_view.data = value_length == 0u ? NULL : workspace->value;
        value_view.length = value_length;
        status = ninlil_model_domain_value_digest(value_view, &pvd);
        if (status != NINLIL_OK) {
            return note_finding(session);
        }
        (void)memcpy(
            ctx->expected_pvd, pvd.bytes, NINLIL_MODEL_DOMAIN_DIGEST_BYTES);
        status = prepare_ingress_modes(ctx, &typed->ordered_ingress, mode);
    } else {
        return NINLIL_OK;
    }
    if (status != NINLIL_OK) {
        return note_finding(session);
    }

    status = ninlil_domain_scan_d3s1_rebuild_peer_key_dispatch(ctx);
    if (status != NINLIL_OK) {
        return note_finding(session);
    }

    /*
     * exact_get contract: writes workspace->value only. Peer key lives in
     * external context->peer_key (legal exact_get key region). Iterator
     * workspace->key is unchanged; previous_key later copies that source key.
     * No saved_key[255] stack save/restore.
     */
    peer_key.data = ctx->peer_key;
    peer_key.length = ctx->peer_key_len;
    (void)memset(&exact, 0, sizeof(exact));
    status = ninlil_domain_scan_exact_get(session, peer_key, &exact);
    if (status != NINLIL_OK) {
        /* Port-path terminal: D2 sticky only; no note (§18.12.7). */
        return status;
    }

    if (ctx->expect_presence == (uint8_t)NINLIL_DOMAIN_SCAN_EXACT_ABSENT) {
        if (exact.presence != NINLIL_DOMAIN_SCAN_EXACT_ABSENT) {
            return note_finding(session);
        }
        return NINLIL_OK;
    }

    /* PRESENT expected. */
    if (exact.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
        return note_finding(session);
    }
    status = verify_peer_present(ctx, exact.value);
    if (status != NINLIL_OK) {
        return note_finding(session);
    }
    return NINLIL_OK;
}
