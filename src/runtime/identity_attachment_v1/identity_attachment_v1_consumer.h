/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_RUNTIME_IDENTITY_ATTACHMENT_V1_CONSUMER_H
#define NINLIL_RUNTIME_IDENTITY_ATTACHMENT_V1_CONSUMER_H

#include "identity_attachment_v1_contract.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ninlil_identity_attachment_consumer_state_v1 {
    NINLIL_IDENTITY_ATTACHMENT_CONSUMER_EMPTY = 0,
    NINLIL_IDENTITY_ATTACHMENT_CONSUMER_PREPARED_FENCED = 1,
    NINLIL_IDENTITY_ATTACHMENT_CONSUMER_CLOSING = 2
} ninlil_identity_attachment_consumer_state_v1_t;

typedef struct ninlil_identity_attachment_consumer_config_v1 {
    uint64_t owner_context_id;
    uint8_t provider_instance_id[16];
    uint64_t provider_generation;
    uint8_t runtime_instance_id[16];
    uint64_t runtime_generation;
    uint8_t module_instance_id[16];
    uint64_t module_generation;
    uint8_t subject_identity_id[16];
    uint32_t binding_scope;
    uint32_t required_usage_mask;
    uint64_t deadline_tick;
} ninlil_identity_attachment_consumer_config_v1_t;

typedef struct ninlil_identity_attachment_consumer_v1 {
    uint64_t owner_context_id;
    ninlil_identity_attachment_provider_v1_t provider;
    ninlil_identity_attachment_consumer_config_v1_t config;
    ninlil_identity_attachment_binding_handle_v1_t binding_handle;
    ninlil_identity_attachment_binding_snapshot_v1_t binding_snapshot;
    ninlil_nonexporting_key_handle_v1_t key_handle;
    ninlil_identity_attachment_subscription_handle_v1_t subscription_handle;
    uint32_t state;
    uint32_t has_binding;
    uint32_t has_subscription;
    uint32_t subscription_uncertain;
    uint32_t fenced;
    uint32_t in_call;
} ninlil_identity_attachment_consumer_v1_t;

#if defined(__GNUC__) || defined(__clang__)
#define NINLIL_IDENTITY_ATTACHMENT_PRIVATE __attribute__((visibility("hidden")))
#else
#define NINLIL_IDENTITY_ATTACHMENT_PRIVATE
#endif

/*
 * After successful init, the caller owns this object until close returns OK.
 * If prepare leaves CLOSING because cleanup could not complete, retain it and
 * retry close. An uncertain subscription remains fenced and must stay alive
 * through provider teardown; it cannot be closed by guessing a handle.
 */
NINLIL_IDENTITY_ATTACHMENT_PRIVATE ninlil_status_t ninlil_identity_attachment_consumer_v1_init(
    ninlil_identity_attachment_consumer_v1_t *consumer,
    const ninlil_identity_attachment_consumer_config_v1_t *config,
    const ninlil_identity_attachment_provider_v1_t *provider);
NINLIL_IDENTITY_ATTACHMENT_PRIVATE ninlil_status_t ninlil_identity_attachment_consumer_v1_prepare(
    ninlil_identity_attachment_consumer_v1_t *consumer,
    uint64_t owner_context_id);
NINLIL_IDENTITY_ATTACHMENT_PRIVATE ninlil_status_t ninlil_identity_attachment_consumer_v1_close(
    ninlil_identity_attachment_consumer_v1_t *consumer,
    uint64_t owner_context_id);
NINLIL_IDENTITY_ATTACHMENT_PRIVATE uint32_t ninlil_identity_attachment_consumer_v1_available(
    const ninlil_identity_attachment_consumer_v1_t *consumer);

#ifdef __cplusplus
}
#endif

#endif
