/*
 * Private Wi-Fi v1 types (ADR-0018). Default-OFF. Not installed.
 */
#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_PRIVATE_TYPES_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_PRIVATE_TYPES_H

#include "wifi_budget.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t ninlil_wifi_status_t;

#define NINLIL_WIFI_OK ((ninlil_wifi_status_t)0u)
#define NINLIL_WIFI_WOULD_BLOCK ((ninlil_wifi_status_t)1u)
#define NINLIL_WIFI_INVALID_ARGUMENT ((ninlil_wifi_status_t)2u)
#define NINLIL_WIFI_INVALID_STATE ((ninlil_wifi_status_t)3u)
#define NINLIL_WIFI_CORRUPT ((ninlil_wifi_status_t)4u)
#define NINLIL_WIFI_UNSUPPORTED ((ninlil_wifi_status_t)5u)
#define NINLIL_WIFI_CAPACITY ((ninlil_wifi_status_t)6u)
#define NINLIL_WIFI_UNAVAILABLE ((ninlil_wifi_status_t)7u)
#define NINLIL_WIFI_DENIED ((ninlil_wifi_status_t)8u)
#define NINLIL_WIFI_CLOSED ((ninlil_wifi_status_t)9u)
#define NINLIL_WIFI_TLS_FAILED ((ninlil_wifi_status_t)10u)
#define NINLIL_WIFI_IO_ERROR ((ninlil_wifi_status_t)11u)
#define NINLIL_WIFI_FENCED ((ninlil_wifi_status_t)12u)
#define NINLIL_WIFI_SEQUENCE_REJECT ((ninlil_wifi_status_t)13u)
#define NINLIL_WIFI_WRONG_SESSION ((ninlil_wifi_status_t)14u)
#define NINLIL_WIFI_BACKPRESSURE ((ninlil_wifi_status_t)15u)
#define NINLIL_WIFI_CREDENTIAL ((ninlil_wifi_status_t)16u)
#define NINLIL_WIFI_STORAGE_COMMIT_UNKNOWN ((ninlil_wifi_status_t)17u)

/*
 * Exact post-COMMIT_UNKNOWN durable classification.  The original
 * COMMIT_UNKNOWN status is never promoted to success by this observation.
 */
typedef uint32_t ninlil_wifi_cu_class_t;
#define NINLIL_WIFI_CU_NONE ((ninlil_wifi_cu_class_t)0u)
#define NINLIL_WIFI_CU_INTENDED ((ninlil_wifi_cu_class_t)1u)
#define NINLIL_WIFI_CU_OLD ((ninlil_wifi_cu_class_t)2u)
#define NINLIL_WIFI_CU_ABSENT ((ninlil_wifi_cu_class_t)3u)
#define NINLIL_WIFI_CU_OTHER ((ninlil_wifi_cu_class_t)4u)

/*
 * ADR-0018 operational phases (subset used by Host/ESP owners).
 * TLS alone never yields ATTACHED. NWB1 only after M4 PA-confirmed + exporter2.
 */
typedef uint32_t ninlil_wifi_phase_t;
#define NINLIL_WIFI_PHASE_CLOSED 0u
#define NINLIL_WIFI_PHASE_CONNECTING 1u
#define NINLIL_WIFI_PHASE_HANDSHAKING 2u
#define NINLIL_WIFI_PHASE_CHANNEL_AUTHENTICATED 3u
#define NINLIL_WIFI_PHASE_PEER_SESSION 4u
#define NINLIL_WIFI_PHASE_ATTACHMENT_NEGOTIATING 5u
#define NINLIL_WIFI_PHASE_ATTACHED 6u
#define NINLIL_WIFI_PHASE_FENCED 7u
#define NINLIL_WIFI_PHASE_RECONNECT_WAIT 8u

typedef struct ninlil_wifi_endpoint {
    uint8_t address_kind; /* 1=IPv4, 2=IPv6 */
    uint8_t reserved0;
    uint16_t port;
    uint32_t scope_id_u32; /* required non-zero for fe80::/10 */
    uint8_t address[16];
} ninlil_wifi_endpoint_t;

typedef struct ninlil_wifi_session_ids {
    uint8_t peer_session_id[16];
    uint8_t attached_session_id[16];
    uint8_t association_authority_digest[32];
} ninlil_wifi_session_ids_t;

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_PRIVATE_TYPES_H */
