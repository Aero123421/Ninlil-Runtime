/* SPDX-License-Identifier: Apache-2.0 */
/* Private PA-S2a libedhoc symmetric/hash candidate. Not installed ABI. */
#ifndef NINLIL_RUNTIME_PRODUCTION_ATTACHMENT_V1_PA_S2_EDHOC_CRYPTO_H
#define NINLIL_RUNTIME_PRODUCTION_ATTACHMENT_V1_PA_S2_EDHOC_CRYPTO_H

#include "edhoc_config.h"
#include "edhoc_crypto.h"

#include <stddef.h>
#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define NINLIL_PA_S2_EDHOC_PRIVATE __attribute__((visibility("hidden")))
#else
#define NINLIL_PA_S2_EDHOC_PRIVATE
#endif

#define NINLIL_PA_S2_EDHOC_SUITE_2 ((uint32_t)2u)
#define NINLIL_PA_S2_EDHOC_SUITE_3 ((uint32_t)3u)
#define NINLIL_PA_S2_EDHOC_KEY_ID_BYTES ((uint32_t)4u)
#define NINLIL_PA_S2_EDHOC_KEY_SLOTS ((uint32_t)2u)
#define NINLIL_PA_S2_EDHOC_KEY_BYTES_MAX ((uint32_t)64u)
#define NINLIL_PA_S2_EDHOC_BODY_BYTES_MAX ((uint32_t)512u)
#define NINLIL_PA_S2_EDHOC_TAG_BYTES_MAX ((uint32_t)16u)
#define NINLIL_PA_S2_EDHOC_WORKSPACE_BYTES \
    (NINLIL_PA_S2_EDHOC_BODY_BYTES_MAX + NINLIL_PA_S2_EDHOC_TAG_BYTES_MAX)

typedef struct ninlil_pa_s2_edhoc_key_slot_v1 {
    uint8_t bytes[NINLIL_PA_S2_EDHOC_KEY_BYTES_MAX];
    uint32_t bytes_used;
    uint32_t generation;
    uint32_t key_type;
    uint32_t live;
} ninlil_pa_s2_edhoc_key_slot_v1_t;

/*
 * Caller-owned and serialized. Zero-initialize before first begin.
 * The 2 x 64-byte key slots are a PA-S2a KAT ceiling, not a completed EDHOC
 * owner resource profile. The only externally returned key value is the
 * exact four-byte slot/generation token; generation never wraps within a begun
 * owner lifetime. No raw-key/backend-pointer getter exists. Owner or I/O
 * overlap is rejected; `end` wipes the complete object.
 */
typedef struct ninlil_pa_s2_edhoc_crypto_owner_v1 {
    ninlil_pa_s2_edhoc_key_slot_v1_t key_slots[NINLIL_PA_S2_EDHOC_KEY_SLOTS];
    uint8_t workspace[NINLIL_PA_S2_EDHOC_WORKSPACE_BYTES];
    uint32_t suite;
    uint32_t next_generation;
    uint32_t active;
    uint32_t in_call;
} ninlil_pa_s2_edhoc_crypto_owner_v1_t;

NINLIL_PA_S2_EDHOC_PRIVATE int ninlil_pa_s2_edhoc_crypto_owner_v1_begin(
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner, uint32_t suite);
NINLIL_PA_S2_EDHOC_PRIVATE int ninlil_pa_s2_edhoc_crypto_owner_v1_bindings(
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner,
    struct edhoc_keys *keys,
    struct edhoc_crypto *crypto);
NINLIL_PA_S2_EDHOC_PRIVATE int ninlil_pa_s2_edhoc_crypto_owner_v1_end(
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner);

#endif
