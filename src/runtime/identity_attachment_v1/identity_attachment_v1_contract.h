/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Private, exact C11 provider ABI for ADR-0039.  It is deliberately not an
 * installed header: Composition wiring and Production Attachment are later
 * tranches.  The field order is the manifest authority verbatim.
 */
#ifndef NINLIL_RUNTIME_IDENTITY_ATTACHMENT_V1_CONTRACT_H
#define NINLIL_RUNTIME_IDENTITY_ATTACHMENT_V1_CONTRACT_H

#include "ninlil/version.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_IDENTITY_ATTACHMENT_PROVIDER_ABI_V1 ((uint32_t)1u)
#define NINLIL_IDENTITY_ATTACHMENT_FALSE ((uint32_t)0u)
#define NINLIL_IDENTITY_ATTACHMENT_TRUE ((uint32_t)1u)
/* Manifest provider status 19; public Runtime has not allocated this name. */
#define NINLIL_IDENTITY_ATTACHMENT_E_AUTHENTICATION_FAILED ((ninlil_status_t)19)

#define NINLIL_IDENTITY_BINDING_INVALID ((uint32_t)0u)
#define NINLIL_IDENTITY_BINDING_VALID ((uint32_t)1u)
#define NINLIL_IDENTITY_BINDING_NOT_YET_VALID ((uint32_t)2u)
#define NINLIL_IDENTITY_BINDING_EXPIRED ((uint32_t)3u)
#define NINLIL_IDENTITY_BINDING_REVOKED ((uint32_t)4u)
#define NINLIL_IDENTITY_BINDING_SUPERSEDED ((uint32_t)5u)
#define NINLIL_IDENTITY_BINDING_STALE ((uint32_t)6u)
#define NINLIL_IDENTITY_BINDING_CROSS_INSTANCE ((uint32_t)7u)
#define NINLIL_IDENTITY_BINDING_ROLLBACK ((uint32_t)8u)

#define NINLIL_IDENTITY_SCOPE_LOCAL_ACTIVE_SESSION ((uint32_t)1u)
#define NINLIL_IDENTITY_SCOPE_PEER_ACTIVE_SESSION ((uint32_t)2u)
#define NINLIL_IDENTITY_SCOPE_CONTROLLER_ACTIVE_SESSION ((uint32_t)3u)

#define NINLIL_IDENTITY_INVALIDATION_REVOKED ((uint32_t)1u)
#define NINLIL_IDENTITY_INVALIDATION_EXPIRED ((uint32_t)2u)
#define NINLIL_IDENTITY_INVALIDATION_SUPERSEDED ((uint32_t)3u)
#define NINLIL_IDENTITY_INVALIDATION_MEMBERSHIP_CHANGED ((uint32_t)4u)
#define NINLIL_IDENTITY_INVALIDATION_ATTACHMENT_CHANGED ((uint32_t)5u)
#define NINLIL_IDENTITY_INVALIDATION_SESSION_CHANGED ((uint32_t)6u)
#define NINLIL_IDENTITY_INVALIDATION_SECURITY_CHANGED ((uint32_t)7u)
#define NINLIL_IDENTITY_INVALIDATION_PROVIDER_RESTARTED ((uint32_t)8u)

#define NINLIL_IDENTITY_FLOOR_PROVIDER_GENERATION ((uint32_t)1u)
#define NINLIL_IDENTITY_FLOOR_CREDENTIAL_REVISION ((uint32_t)2u)
#define NINLIL_IDENTITY_FLOOR_MEMBERSHIP_EPOCH ((uint32_t)4u)
#define NINLIL_IDENTITY_FLOOR_ATTACHMENT_GENERATION ((uint32_t)8u)
#define NINLIL_IDENTITY_FLOOR_SESSION_GENERATION ((uint32_t)16u)
#define NINLIL_IDENTITY_FLOOR_SECURITY_EPOCH ((uint32_t)32u)
#define NINLIL_IDENTITY_FLOOR_EXPIRY_EPOCH ((uint32_t)64u)
#define NINLIL_IDENTITY_FLOOR_INVALIDATION_EPOCH ((uint32_t)128u)
#define NINLIL_IDENTITY_FLOOR_BINDING_HANDLE_GENERATION ((uint32_t)256u)
#define NINLIL_IDENTITY_FLOOR_KEY_GENERATION ((uint32_t)512u)
#define NINLIL_IDENTITY_FLOOR_ALLOWED_MASK ((uint32_t)1023u)

#define NINLIL_KEY_OPERATION_AUTH_TAG ((uint32_t)1u)
#define NINLIL_KEY_OPERATION_AUTH_VERIFY ((uint32_t)2u)
#define NINLIL_KEY_OPERATION_AEAD_SEAL ((uint32_t)3u)
#define NINLIL_KEY_OPERATION_AEAD_OPEN ((uint32_t)4u)
#define NINLIL_KEY_OPERATION_SIGN_DIGEST ((uint32_t)5u)
#define NINLIL_KEY_OPERATION_VERIFY_DIGEST ((uint32_t)6u)

#define NINLIL_KEY_USAGE_AUTH_TAG ((uint32_t)1u)
#define NINLIL_KEY_USAGE_AUTH_VERIFY ((uint32_t)2u)
#define NINLIL_KEY_USAGE_AEAD_SEAL ((uint32_t)4u)
#define NINLIL_KEY_USAGE_AEAD_OPEN ((uint32_t)8u)
#define NINLIL_KEY_USAGE_SIGN_DIGEST ((uint32_t)16u)
#define NINLIL_KEY_USAGE_VERIFY_DIGEST ((uint32_t)32u)
#define NINLIL_KEY_USAGE_ALLOWED_MASK ((uint32_t)63u)

#define NINLIL_KEY_HANDLE_NON_EXPORTABLE ((uint32_t)1u)
#define NINLIL_KEY_HANDLE_PROVIDER_BOUND ((uint32_t)2u)
#define NINLIL_KEY_HANDLE_SESSION_BOUND ((uint32_t)4u)
#define NINLIL_KEY_HANDLE_REQUIRED_FLAGS_MASK ((uint32_t)7u)
#define NINLIL_KEY_HANDLE_ALLOWED_FLAGS_MASK ((uint32_t)7u)

typedef struct ninlil_identity_attachment_binding_handle_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t provider_instance_id[16];
    uint64_t provider_generation;
    uint8_t binding_handle_id[16];
    uint64_t binding_handle_generation;
    uint8_t runtime_instance_id[16];
    uint64_t runtime_generation;
    uint8_t module_instance_id[16];
    uint64_t module_generation;
    uint8_t opaque_token[32];
} ninlil_identity_attachment_binding_handle_v1_t;

typedef struct ninlil_identity_attachment_binding_snapshot_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t provider_instance_id[16];
    uint64_t provider_generation;
    uint8_t runtime_instance_id[16];
    uint64_t runtime_generation;
    uint8_t module_instance_id[16];
    uint64_t module_generation;
    uint8_t stable_identity_id[16];
    uint64_t credential_revision;
    uint8_t identity_binding_digest[32];
    uint8_t membership_authority_id[16];
    uint64_t membership_epoch;
    uint8_t membership_set_digest[32];
    uint8_t attachment_id[16];
    uint64_t attachment_generation;
    uint8_t session_id[16];
    uint64_t session_generation;
    uint8_t security_context_id[16];
    uint64_t security_epoch;
    uint8_t expiry_authority_id[16];
    uint64_t expiry_epoch;
    uint64_t not_before_tick;
    uint64_t expires_at_tick;
    uint64_t invalidation_epoch;
} ninlil_identity_attachment_binding_snapshot_v1_t;

typedef struct ninlil_nonexporting_key_handle_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t provider_instance_id[16];
    uint64_t provider_generation;
    uint8_t binding_handle_id[16];
    uint64_t binding_handle_generation;
    uint8_t key_handle_id[16];
    uint64_t key_generation;
    uint32_t usage_mask;
    uint32_t flags;
    uint8_t opaque_token[32];
} ninlil_nonexporting_key_handle_v1_t;

typedef struct ninlil_identity_attachment_subscription_handle_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t provider_instance_id[16];
    uint64_t provider_generation;
    uint8_t binding_handle_id[16];
    uint64_t binding_handle_generation;
    uint8_t subscription_id[16];
    uint64_t subscription_generation;
    uint8_t opaque_token[32];
} ninlil_identity_attachment_subscription_handle_v1_t;

typedef struct ninlil_identity_attachment_resolve_request_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t provider_instance_id[16];
    uint64_t provider_generation;
    uint8_t runtime_instance_id[16];
    uint64_t runtime_generation;
    uint8_t module_instance_id[16];
    uint64_t module_generation;
    uint32_t binding_scope;
    uint32_t requested_usage_mask;
    uint8_t subject_identity_id[16];
    uint64_t deadline_tick;
    uint32_t flags;
    uint32_t reserved_zero;
} ninlil_identity_attachment_resolve_request_v1_t;

typedef struct ninlil_identity_attachment_resolve_result_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t binding_verdict;
    uint32_t flags;
    ninlil_identity_attachment_binding_snapshot_v1_t snapshot;
    ninlil_identity_attachment_binding_handle_v1_t binding_handle;
    ninlil_nonexporting_key_handle_v1_t key_handle;
} ninlil_identity_attachment_resolve_result_v1_t;

typedef struct ninlil_identity_attachment_validate_request_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    ninlil_identity_attachment_binding_handle_v1_t binding_handle;
    uint32_t required_usage_mask;
    uint32_t flags;
    uint8_t operation_context_digest[32];
    uint64_t deadline_tick;
} ninlil_identity_attachment_validate_request_v1_t;

typedef struct ninlil_identity_attachment_validate_result_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t binding_verdict;
    uint32_t flags;
    uint64_t authoritative_invalidation_epoch;
    uint64_t authoritative_expiry_epoch;
} ninlil_identity_attachment_validate_result_v1_t;

typedef struct ninlil_identity_attachment_key_operation_request_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    ninlil_identity_attachment_binding_handle_v1_t binding_handle;
    ninlil_nonexporting_key_handle_v1_t key_handle;
    uint32_t operation;
    uint32_t flags;
    const uint8_t *nonce;
    uint32_t nonce_size;
    const uint8_t *aad;
    uint32_t aad_size;
    const uint8_t *input;
    uint32_t input_size;
    const uint8_t *authenticator;
    uint32_t authenticator_size;
    uint64_t deadline_tick;
} ninlil_identity_attachment_key_operation_request_v1_t;

typedef struct ninlil_identity_attachment_key_operation_result_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t operation;
    uint32_t flags;
    uint8_t *output;
    uint32_t output_capacity;
    uint32_t output_size;
    uint32_t verified;
    uint32_t reserved_zero;
} ninlil_identity_attachment_key_operation_result_v1_t;

typedef struct ninlil_identity_attachment_release_request_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    ninlil_identity_attachment_binding_handle_v1_t binding_handle;
    uint32_t flags;
    uint32_t reserved_zero;
} ninlil_identity_attachment_release_request_v1_t;

typedef struct ninlil_identity_attachment_release_result_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t released;
    uint32_t flags;
} ninlil_identity_attachment_release_result_v1_t;

struct ninlil_identity_attachment_invalidation_event_v1;
typedef void (*ninlil_identity_attachment_on_invalidation_v1_fn)(
    void *callback_context,
    const struct ninlil_identity_attachment_invalidation_event_v1 *event);

typedef struct ninlil_identity_attachment_subscribe_request_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    ninlil_identity_attachment_binding_handle_v1_t binding_handle;
    void *callback_context;
    ninlil_identity_attachment_on_invalidation_v1_fn on_invalidation;
    uint32_t flags;
    uint32_t reserved_zero;
} ninlil_identity_attachment_subscribe_request_v1_t;

typedef struct ninlil_identity_attachment_subscribe_result_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    ninlil_identity_attachment_subscription_handle_v1_t subscription_handle;
    uint64_t subscribed_invalidation_epoch;
    uint32_t flags;
    uint32_t reserved_zero;
} ninlil_identity_attachment_subscribe_result_v1_t;

typedef struct ninlil_identity_attachment_invalidation_event_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    ninlil_identity_attachment_binding_handle_v1_t binding_handle;
    uint32_t reason;
    uint32_t changed_floor_mask;
    uint64_t invalidation_epoch;
    uint64_t provider_generation;
    uint64_t binding_handle_generation;
    uint64_t key_generation;
    uint32_t flags;
    uint32_t reserved_zero;
} ninlil_identity_attachment_invalidation_event_v1_t;

typedef struct ninlil_identity_attachment_unsubscribe_request_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    ninlil_identity_attachment_subscription_handle_v1_t subscription_handle;
    uint32_t flags;
    uint32_t reserved_zero;
} ninlil_identity_attachment_unsubscribe_request_v1_t;

typedef struct ninlil_identity_attachment_unsubscribe_result_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint64_t final_invalidation_epoch;
    uint32_t callbacks_drained;
    uint32_t flags;
} ninlil_identity_attachment_unsubscribe_result_v1_t;

typedef ninlil_status_t (*ninlil_identity_attachment_resolve_v1_fn)(
    void *context,
    const ninlil_identity_attachment_resolve_request_v1_t *request,
    ninlil_identity_attachment_resolve_result_v1_t *result);
typedef ninlil_status_t (*ninlil_identity_attachment_validate_v1_fn)(
    void *context,
    const ninlil_identity_attachment_validate_request_v1_t *request,
    ninlil_identity_attachment_validate_result_v1_t *result);
typedef ninlil_status_t (*ninlil_identity_attachment_key_operation_v1_fn)(
    void *context,
    const ninlil_identity_attachment_key_operation_request_v1_t *request,
    ninlil_identity_attachment_key_operation_result_v1_t *result);
typedef ninlil_status_t (*ninlil_identity_attachment_release_v1_fn)(
    void *context,
    const ninlil_identity_attachment_release_request_v1_t *request,
    ninlil_identity_attachment_release_result_v1_t *result);
typedef ninlil_status_t (*ninlil_identity_attachment_subscribe_v1_fn)(
    void *context,
    const ninlil_identity_attachment_subscribe_request_v1_t *request,
    ninlil_identity_attachment_subscribe_result_v1_t *result);
typedef ninlil_status_t (*ninlil_identity_attachment_unsubscribe_v1_fn)(
    void *context,
    const ninlil_identity_attachment_unsubscribe_request_v1_t *request,
    ninlil_identity_attachment_unsubscribe_result_v1_t *result);

typedef struct ninlil_identity_attachment_provider_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    void *context;
    ninlil_identity_attachment_resolve_v1_fn resolve_binding;
    ninlil_identity_attachment_validate_v1_fn validate_binding;
    ninlil_identity_attachment_key_operation_v1_fn perform_key_operation;
    ninlil_identity_attachment_release_v1_fn release_binding;
    ninlil_identity_attachment_subscribe_v1_fn subscribe_invalidation;
    ninlil_identity_attachment_unsubscribe_v1_fn unsubscribe_invalidation;
} ninlil_identity_attachment_provider_v1_t;

/* The spec vectors are the independent layout oracle. */
_Static_assert(sizeof(ninlil_identity_attachment_binding_handle_v1_t) == 136u,
    "identity attachment binding handle ABI");
_Static_assert(_Alignof(ninlil_identity_attachment_binding_handle_v1_t) == 8u,
    "identity attachment binding handle alignment");
_Static_assert(sizeof(ninlil_nonexporting_key_handle_v1_t) == 120u,
    "identity attachment key handle ABI");
_Static_assert(_Alignof(ninlil_nonexporting_key_handle_v1_t) == 8u,
    "identity attachment key handle alignment");
_Static_assert(sizeof(ninlil_identity_attachment_binding_snapshot_v1_t) == 312u,
    "identity attachment snapshot ABI");
_Static_assert(offsetof(ninlil_identity_attachment_binding_handle_v1_t,
        provider_generation) == 24u, "binding provider generation offset");
_Static_assert(offsetof(ninlil_nonexporting_key_handle_v1_t,
        usage_mask) == 80u, "key usage offset");
_Static_assert(offsetof(ninlil_identity_attachment_key_operation_request_v1_t,
        binding_handle) == 8u, "key request binding offset");

/* All 18 layouts and fields: exact LP64 / ESP32-S3 vector bridge. */
#include "identity_attachment_v1_layout_asserts.inc"

#if defined(ESP_PLATFORM)
_Static_assert(sizeof(void *) == 4u && _Alignof(void *) == 4u,
    "ESP32-S3 data pointer ABI");
_Static_assert(sizeof(ninlil_identity_attachment_provider_v1_t) == 36u,
    "ESP32-S3 provider ABI");
_Static_assert(sizeof(ninlil_identity_attachment_key_operation_request_v1_t) == 312u,
    "ESP32-S3 key operation ABI");
_Static_assert(offsetof(ninlil_identity_attachment_key_operation_request_v1_t,
        nonce) == 272u, "ESP32-S3 nonce offset");
_Static_assert(offsetof(ninlil_identity_attachment_key_operation_request_v1_t,
        deadline_tick) == 304u, "ESP32-S3 deadline offset");
#else
_Static_assert(sizeof(void *) == 8u && _Alignof(void *) == 8u,
    "LP64 provider ABI build required");
_Static_assert(sizeof(ninlil_identity_attachment_provider_v1_t) == 64u,
    "LP64 provider ABI");
_Static_assert(sizeof(ninlil_identity_attachment_key_operation_request_v1_t) == 344u,
    "LP64 key operation ABI");
_Static_assert(offsetof(ninlil_identity_attachment_key_operation_request_v1_t,
        nonce) == 272u, "LP64 nonce offset");
_Static_assert(offsetof(ninlil_identity_attachment_key_operation_request_v1_t,
        deadline_tick) == 336u, "LP64 deadline offset");
#endif

#ifdef __cplusplus
}
#endif

#endif
