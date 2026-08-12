/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Ninlil POSIX TLS Fabric reference port.
 *
 * Experimental 0.x Host-only composition surface fixed by ADR-0030.  The
 * operating system owns network association; this object owns one
 * nonblocking TCP/TLS connection (or one listener and accepted connection)
 * and exposes it only through Ninlil::fabric_v1.
 *
 * ADR-0030 is normative. The caller owns the workspace through successful
 * destroy. create copies path, namespace and vtable values; function code and
 * non-NULL user pointees remain caller-owned through destroy. A registration
 * handle is a port-owned borrow through unregister_poll(done=1). Calls are
 * owner-context-only and reject re-entry except the documented controlled
 * registration handshake. ninlil_posix_tls_status_t is invocation status;
 * operational state/reason and Fabric token completion are separate. TLS/TCP
 * completion is not Application success, and COMMIT_UNKNOWN fences the port.
 */
#ifndef NINLIL_POSIX_TLS_V1_H
#define NINLIL_POSIX_TLS_V1_H

#include "ninlil/fabric_v1.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_POSIX_TLS_API_VERSION ((uint16_t)0x0001u)

typedef struct ninlil_posix_tls_v1 ninlil_posix_tls_v1_t;
typedef struct ninlil_posix_tls_registration_v1
    ninlil_posix_tls_registration_v1_t;

typedef uint32_t ninlil_posix_tls_status_t;
#define NINLIL_POSIX_TLS_OK 0u
#define NINLIL_POSIX_TLS_INVALID_ARGUMENT 1u
#define NINLIL_POSIX_TLS_WRONG_THREAD 2u
#define NINLIL_POSIX_TLS_REENTRANT 3u
#define NINLIL_POSIX_TLS_UNSUPPORTED 4u
#define NINLIL_POSIX_TLS_WOULD_BLOCK 5u
#define NINLIL_POSIX_TLS_UNAVAILABLE 6u
#define NINLIL_POSIX_TLS_DENIED 7u
#define NINLIL_POSIX_TLS_CAPACITY 8u
#define NINLIL_POSIX_TLS_CORRUPT 9u
#define NINLIL_POSIX_TLS_CLOSED 10u
#define NINLIL_POSIX_TLS_IO 11u
#define NINLIL_POSIX_TLS_TLS 12u
#define NINLIL_POSIX_TLS_STORAGE 13u
#define NINLIL_POSIX_TLS_STORAGE_COMMIT_UNKNOWN 14u

typedef uint32_t ninlil_posix_tls_role_t;
#define NINLIL_POSIX_TLS_ROLE_CLIENT 1u
#define NINLIL_POSIX_TLS_ROLE_SERVER 2u

#define NINLIL_POSIX_TLS_ADDRESS_IPV4 1u
#define NINLIL_POSIX_TLS_ADDRESS_IPV6 2u

typedef uint32_t ninlil_posix_tls_operational_state_t;
#define NINLIL_POSIX_TLS_STATE_CREATED 1u
#define NINLIL_POSIX_TLS_STATE_LISTENING 2u
#define NINLIL_POSIX_TLS_STATE_CONNECTING 3u
#define NINLIL_POSIX_TLS_STATE_HANDSHAKING 4u
#define NINLIL_POSIX_TLS_STATE_AUTHENTICATED 5u
#define NINLIL_POSIX_TLS_STATE_ATTACHED 6u
#define NINLIL_POSIX_TLS_STATE_BACKOFF 7u
#define NINLIL_POSIX_TLS_STATE_UNAVAILABLE 8u
#define NINLIL_POSIX_TLS_STATE_DRAINING 9u
#define NINLIL_POSIX_TLS_STATE_CLOSED 10u
#define NINLIL_POSIX_TLS_STATE_FENCED 11u

#define NINLIL_POSIX_TLS_REASON_NONE 0u
#define NINLIL_POSIX_TLS_REASON_CONFIG 1u
#define NINLIL_POSIX_TLS_REASON_PEER_AUTHORIZATION 2u
#define NINLIL_POSIX_TLS_REASON_TLS 3u
#define NINLIL_POSIX_TLS_REASON_IO 4u
#define NINLIL_POSIX_TLS_REASON_STORAGE 5u
#define NINLIL_POSIX_TLS_REASON_LOST_UNKNOWN 6u
#define NINLIL_POSIX_TLS_REASON_LOCAL_CLOSE 7u

typedef struct ninlil_posix_tls_endpoint_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    uint32_t address_kind;
    uint16_t port;
    uint16_t reserved_zero_u16;
    uint32_t scope_id;
    uint8_t address[16];
} ninlil_posix_tls_endpoint_v1_t;

typedef struct ninlil_posix_tls_paths_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    const char *ca_pem_path;
    const char *cert_pem_path;
    const char *key_pem_path;
} ninlil_posix_tls_paths_v1_t;

typedef struct ninlil_posix_tls_leaf_expectation_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    uint32_t role;
    ninlil_id128_t runtime_id;
    uint8_t leaf_spki_sha256[32];
    ninlil_id128_t authority_id;
    uint64_t authority_term;
    uint8_t authorized_attachment_binding_digest[32];
    uint32_t credential_generation;
    uint32_t revocation_generation;
} ninlil_posix_tls_leaf_expectation_v1_t;

typedef struct ninlil_posix_tls_authorization_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    uint32_t assignment_epoch;
    uint32_t reserved_zero;
    ninlil_posix_tls_leaf_expectation_v1_t local_leaf;
    ninlil_posix_tls_leaf_expectation_v1_t peer_leaf;
    ninlil_id128_t registry_epoch_id;
    uint8_t credential_reference_digest[32];
    uint64_t credential_revision;
} ninlil_posix_tls_authorization_v1_t;

typedef struct ninlil_posix_tls_config_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    uint32_t role;
    uint32_t flags;
    ninlil_id128_t instance_id;
    ninlil_posix_tls_endpoint_v1_t endpoint;
    ninlil_posix_tls_paths_v1_t tls_paths;
    ninlil_posix_tls_authorization_v1_t authorization;
    ninlil_fabric_link_descriptor_v1_t link_descriptor;
    ninlil_bytes_view_t storage_namespace;
    const ninlil_storage_ops_t *storage;
    const ninlil_clock_ops_t *clock;
    const ninlil_execution_ops_t *execution;
} ninlil_posix_tls_config_v1_t;

typedef struct ninlil_posix_tls_state_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    uint32_t operational_state;
    uint32_t reason;
    uint64_t availability_epoch;
    uint16_t local_port;
    uint16_t reserved_zero_u16;
    uint32_t reconnect_count;
    uint64_t accepted_send_count;
    uint64_t accepted_receive_count;
} ninlil_posix_tls_state_v1_t;

ninlil_posix_tls_status_t ninlil_posix_tls_v1_workspace_required(
    uint32_t *out_bytes, uint32_t *out_alignment);
ninlil_posix_tls_status_t ninlil_posix_tls_v1_create(
    const ninlil_posix_tls_config_v1_t *config,
    void *workspace,
    uint32_t workspace_bytes,
    ninlil_posix_tls_v1_t **out_port);
ninlil_posix_tls_status_t ninlil_posix_tls_v1_descriptor_snapshot(
    ninlil_posix_tls_v1_t *port,
    ninlil_fabric_link_descriptor_v1_t *out_descriptor);
ninlil_posix_tls_status_t ninlil_posix_tls_v1_register_fabric(
    ninlil_posix_tls_v1_t *port,
    ninlil_fabric_v1_t *fabric,
    ninlil_posix_tls_registration_v1_t **out_registration);
ninlil_posix_tls_status_t ninlil_posix_tls_v1_unregister_begin(
    ninlil_posix_tls_v1_t *port,
    ninlil_posix_tls_registration_v1_t *registration);
ninlil_posix_tls_status_t ninlil_posix_tls_v1_unregister_poll(
    ninlil_posix_tls_v1_t *port,
    ninlil_posix_tls_registration_v1_t *registration,
    uint32_t *out_done);
ninlil_posix_tls_status_t ninlil_posix_tls_v1_step(
    ninlil_posix_tls_v1_t *port,
    uint32_t work_budget,
    uint32_t *out_work_done);
ninlil_posix_tls_status_t ninlil_posix_tls_v1_state(
    ninlil_posix_tls_v1_t *port,
    ninlil_posix_tls_state_v1_t *out_state);
ninlil_posix_tls_status_t ninlil_posix_tls_v1_close_begin(
    ninlil_posix_tls_v1_t *port);
ninlil_posix_tls_status_t ninlil_posix_tls_v1_close_poll(
    ninlil_posix_tls_v1_t *port, uint32_t *out_done);
ninlil_posix_tls_status_t ninlil_posix_tls_v1_destroy(
    ninlil_posix_tls_v1_t *port);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_POSIX_TLS_V1_H */
