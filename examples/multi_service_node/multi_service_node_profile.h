/*
 * Role-neutral multi-Service node example profile.
 *
 * This module is an OSS application example built only from Ninlil public
 * types. It is not part of the installed Core ABI and contains no product-
 * specific vocabulary.
 */
#ifndef NINLIL_EXAMPLES_MULTI_SERVICE_NODE_PROFILE_H
#define NINLIL_EXAMPLES_MULTI_SERVICE_NODE_PROFILE_H

#include <ninlil/service.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_MULTI_SERVICE_NODE_DISPLAY_COMMAND ((uint32_t)0u)
#define NINLIL_MULTI_SERVICE_NODE_ACCESS_EVENT ((uint32_t)1u)
#define NINLIL_MULTI_SERVICE_NODE_TEMPERATURE_TELEMETRY ((uint32_t)2u)
#define NINLIL_MULTI_SERVICE_NODE_TEMPERATURE_QUERY ((uint32_t)3u)
#define NINLIL_MULTI_SERVICE_NODE_SERVICE_COUNT ((uint32_t)4u)

#define NINLIL_MULTI_SERVICE_NODE_SERVICE_MASK(index) \
    ((uint32_t)1u << (index))
#define NINLIL_MULTI_SERVICE_NODE_ALL_SERVICES_MASK \
    ((uint32_t)0x0fu)
#define NINLIL_MULTI_SERVICE_NODE_RECEIVE_MASK \
    (NINLIL_MULTI_SERVICE_NODE_SERVICE_MASK( \
         NINLIL_MULTI_SERVICE_NODE_DISPLAY_COMMAND) \
     | NINLIL_MULTI_SERVICE_NODE_SERVICE_MASK( \
         NINLIL_MULTI_SERVICE_NODE_TEMPERATURE_QUERY))
#define NINLIL_MULTI_SERVICE_NODE_ORIGINATE_MASK \
    (NINLIL_MULTI_SERVICE_NODE_SERVICE_MASK( \
         NINLIL_MULTI_SERVICE_NODE_ACCESS_EVENT) \
     | NINLIL_MULTI_SERVICE_NODE_SERVICE_MASK( \
         NINLIL_MULTI_SERVICE_NODE_TEMPERATURE_TELEMETRY))

/*
 * Zero means the application profile is not fixed to one Runtime role.
 * Deployment policy chooses the Runtime role(s); the node manifest remains a
 * set of simultaneous Services/capabilities.
 */
#define NINLIL_MULTI_SERVICE_NODE_ROLE_NEUTRAL ((uint32_t)0u)

typedef struct ninlil_multi_service_node_manifest {
    NINLIL_STRUCT_HEADER;
    uint32_t runtime_role_constraint;
    uint32_t service_count;
    uint32_t service_mask;
    uint32_t receive_service_mask;
    uint32_t originate_service_mask;
    uint32_t response_service_index;
    uint32_t reserved_zero;
} ninlil_multi_service_node_manifest_t;

typedef struct ninlil_multi_service_node_profile {
    NINLIL_STRUCT_HEADER;
    ninlil_multi_service_node_manifest_t manifest;
    ninlil_service_descriptor_t
        services[NINLIL_MULTI_SERVICE_NODE_SERVICE_COUNT];
} ninlil_multi_service_node_profile_t;

#define NINLIL_MULTI_SERVICE_NODE_RESPONSE_IDLE ((uint32_t)0u)
#define NINLIL_MULTI_SERVICE_NODE_RESPONSE_PENDING ((uint32_t)1u)
#define NINLIL_MULTI_SERVICE_NODE_RESPONSE_IN_FLIGHT ((uint32_t)2u)

typedef struct ninlil_multi_service_node_state {
    NINLIL_STRUCT_HEADER;
    uint32_t response_phase;
    uint32_t reserved_zero;
    uint64_t pending_query_correlation;
    uint64_t display_commands_received;
    uint64_t access_events_originated;
    uint64_t temperature_periodic_originated;
    uint64_t temperature_queries_received;
    uint64_t temperature_responses_originated;
} ninlil_multi_service_node_state_t;

ninlil_status_t ninlil_multi_service_node_profile_init(
    ninlil_multi_service_node_profile_t *out_profile,
    uint8_t application_instance_seed);

ninlil_status_t ninlil_multi_service_node_profile_validate(
    const ninlil_multi_service_node_profile_t *profile);

ninlil_status_t ninlil_multi_service_node_state_init(
    ninlil_multi_service_node_state_t *out_state);

ninlil_status_t ninlil_multi_service_node_note_originated(
    ninlil_multi_service_node_state_t *state,
    uint32_t service_index);

ninlil_status_t ninlil_multi_service_node_note_delivery(
    ninlil_multi_service_node_state_t *state,
    uint32_t service_index,
    uint64_t query_correlation);

uint32_t ninlil_multi_service_node_temperature_response_pending(
    const ninlil_multi_service_node_state_t *state);

ninlil_status_t ninlil_multi_service_node_temperature_response_begin(
    ninlil_multi_service_node_state_t *state,
    uint64_t *out_query_correlation);

ninlil_status_t ninlil_multi_service_node_temperature_response_finish(
    ninlil_multi_service_node_state_t *state,
    uint32_t admitted);

ninlil_status_t ninlil_multi_service_node_acceptance_complete(
    const ninlil_multi_service_node_state_t *state);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_EXAMPLES_MULTI_SERVICE_NODE_PROFILE_H */
