/* SPDX-License-Identifier: Apache-2.0
 * Portable HIL full-promotion gate + ESP CU class latch (ADR-0021 §738-740).
 *
 * Always linked with PRODUCTION MFDT sources (engine depends on the gate).
 * Default OFF / fail-closed. No public mutable setter. The verifier is
 * intentionally unavailable until a platform trust-root format and physical
 * power-cut HIL acceptance process are specified and implemented.
 *
 * Not a port of ESP storage. ESP store_esp only latches raw CU class here;
 * host lab store leaves class unset (-1).
 */
#include "mfdt_v1.h"

#include <stddef.h>

/* Default OFF: no external FULL success promotion without HIL attestation. */
static int g_hil_full_promotion_enabled = 0;

/* -1 = unset / host lab; else ninlil_mfdt_v1_cu_class_t value. */
static int g_esp_last_cu_class = -1;

int ninlil_mfdt_v1_hil_full_promotion_enabled(void)
{
    return g_hil_full_promotion_enabled != 0 ? 1 : 0;
}

int ninlil_mfdt_v1_hil_full_promotion_apply_target_attestation(
    const uint8_t *sealed_evidence, size_t sealed_len)
{
    if (sealed_evidence == NULL || sealed_len == 0u) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    /*
     * Reserved, deliberately not a parser. Magic prefixes, non-zero tails and
     * digest-shaped bytes are not authentication. A future implementation
     * must verify a platform-rooted signature plus device/build/profile bind,
     * anti-rollback, expiry/revocation and the accepted physical HIL matrix.
     */
    (void)sealed_evidence;
    (void)sealed_len;
    return NINLIL_MFDT_V1_ERR_STATE;
}

int ninlil_mfdt_v1_esp_last_cu_class(void)
{
    return g_esp_last_cu_class;
}

void ninlil_mfdt_v1_esp_last_cu_class_set(int cu_class_or_neg1)
{
    g_esp_last_cu_class = cu_class_or_neg1;
}
