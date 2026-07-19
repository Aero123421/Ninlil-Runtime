/*
 * R7 sole nonce helper: static_iv12 XOR counter_u64_be (docs/31 §8).
 * Private C11. No provider, heap, VLA, OS, or crypto headers.
 */

#include "r7_crypto_provider.h"

ninlil_r7_crypto_status ninlil_r7_crypto_nonce_from_counter(
    const uint8_t static_iv12[NINLIL_R7_CRYPTO_AES128_NONCE_LEN],
    uint64_t counter,
    uint8_t out_nonce12[NINLIL_R7_CRYPTO_AES128_NONCE_LEN])
{
    uint8_t work[NINLIL_R7_CRYPTO_AES128_NONCE_LEN];
    uint8_t ctr_be[8];
    size_t i;

    if (static_iv12 == NULL || out_nonce12 == NULL) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (counter == 0u || counter == UINT64_MAX) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }

    /* Reject exact / partial alias between static_iv and out. Adjacent ok. */
    {
        uintptr_t a = (uintptr_t)static_iv12;
        uintptr_t b = (uintptr_t)out_nonce12;
        uintptr_t ae;
        uintptr_t be;

        if (a > (UINTPTR_MAX - NINLIL_R7_CRYPTO_AES128_NONCE_LEN) ||
            b > (UINTPTR_MAX - NINLIL_R7_CRYPTO_AES128_NONCE_LEN)) {
            return NINLIL_R7_CRYPTO_ALIAS;
        }
        ae = a + NINLIL_R7_CRYPTO_AES128_NONCE_LEN;
        be = b + NINLIL_R7_CRYPTO_AES128_NONCE_LEN;
        if (a < be && b < ae) {
            return NINLIL_R7_CRYPTO_ALIAS;
        }
    }

    /* counter as big-endian u64 */
    ctr_be[0] = (uint8_t)((counter >> 56) & 0xffu);
    ctr_be[1] = (uint8_t)((counter >> 48) & 0xffu);
    ctr_be[2] = (uint8_t)((counter >> 40) & 0xffu);
    ctr_be[3] = (uint8_t)((counter >> 32) & 0xffu);
    ctr_be[4] = (uint8_t)((counter >> 24) & 0xffu);
    ctr_be[5] = (uint8_t)((counter >> 16) & 0xffu);
    ctr_be[6] = (uint8_t)((counter >> 8) & 0xffu);
    ctr_be[7] = (uint8_t)(counter & 0xffu);

    /* nonce[0..3] = static_iv[0..3]; nonce[4..11] = static_iv[4..11] XOR ctr */
    for (i = 0u; i < 4u; i++) {
        work[i] = static_iv12[i];
    }
    for (i = 0u; i < 8u; i++) {
        work[4u + i] = (uint8_t)(static_iv12[4u + i] ^ ctr_be[i]);
    }

    for (i = 0u; i < NINLIL_R7_CRYPTO_AES128_NONCE_LEN; i++) {
        out_nonce12[i] = work[i];
    }

    /* Best-effort wipe of temporaries (not secret key material, still clean). */
    {
        volatile uint8_t *v;
        size_t k;

        v = (volatile uint8_t *)work;
        for (k = 0u; k < sizeof(work); k++) {
            v[k] = 0u;
        }
        v = (volatile uint8_t *)ctr_be;
        for (k = 0u; k < sizeof(ctr_be); k++) {
            v[k] = 0u;
        }
    }

    return NINLIL_R7_CRYPTO_OK;
}
