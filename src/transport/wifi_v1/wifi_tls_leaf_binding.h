/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_TLS_LEAF_BINDING_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_TLS_LEAF_BINDING_H

/*
 * ADR-0018 §14.2 exact leaf identity binding (82-byte binding_value).
 * Codec + field validation; Host/ESP backends extract SAN raw DER separately.
 */
#include "wifi_private_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_WIFI_LEAF_BINDING_BYTES 82u
#define NINLIL_WIFI_LEAF_BINDING_VERSION 0x01u
#define NINLIL_WIFI_LEAF_ROLE_CLIENT 0x01u
#define NINLIL_WIFI_LEAF_ROLE_SERVER 0x02u

/* Exact SAN GeneralNames DER layout constants (ADR-0018 §14.2). */
#define NINLIL_WIFI_LEAF_SAN_GN_LEN 112u
#define NINLIL_WIFI_LEAF_SAN_EXT_PREFIX_LEN 12u
#define NINLIL_WIFI_LEAF_SAN_EXT_TOTAL_LEN 124u

typedef struct ninlil_wifi_leaf_binding {
    uint8_t version;
    uint8_t role;
    uint8_t runtime_id[16];
    uint8_t authorized_attachment_binding_digest[32];
    uint8_t authority_id[16];
    uint64_t authority_term;
    uint32_t credential_generation;
    uint32_t revocation_generation;
} ninlil_wifi_leaf_binding_t;

/* Encode fields → exact 82-byte binding_value (BE integers). */
ninlil_wifi_status_t ninlil_wifi_leaf_binding_encode(
    const ninlil_wifi_leaf_binding_t *in,
    uint8_t out[NINLIL_WIFI_LEAF_BINDING_BYTES]);

/* Decode + reject zero required fields / bad version/role. */
ninlil_wifi_status_t ninlil_wifi_leaf_binding_decode(
    const uint8_t in[NINLIL_WIFI_LEAF_BINDING_BYTES],
    ninlil_wifi_leaf_binding_t *out);

/*
 * Validate raw GeneralNames DER (112B) wrapping binding_value[82].
 * Expects exact form from ADR-0018 §14.2 (a0/06/a0/04 nest).
 */
ninlil_wifi_status_t ninlil_wifi_leaf_binding_parse_general_names(
    const uint8_t *gn_der,
    size_t gn_len,
    ninlil_wifi_leaf_binding_t *out);

/* Exact OID DER for 2.25.<uuid-decimal> (20-byte content after 06 14). */
extern const uint8_t ninlil_wifi_leaf_binding_oid_der[20];

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_TLS_LEAF_BINDING_H */
