#ifndef NINLIL_R7_CRYPTO_OPENSSL3_H
#define NINLIL_R7_CRYPTO_OPENSSL3_H

/*
 * R7 private Host crypto adapter for OpenSSL 3.x.
 *
 * This header deliberately exposes no OpenSSL type.  The adapter owns all
 * OpenSSL objects for the duration of each synchronous callback and installs
 * an exact ninlil_r7_crypto_provider ABI v1 value with a NULL context.
 */

#include "r7_crypto_provider.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize an exact provider ABI v1 value backed by OpenSSL >= 3.
 *
 * Success publishes the whole provider to *out_provider.  Failure leaves
 * *out_provider byte-unchanged.  NULL is INVALID_ARGUMENT; a runtime OpenSSL
 * major version below 3 is BACKEND_FAILED.
 */
ninlil_r7_crypto_status ninlil_r7_crypto_openssl3_provider_init(
    ninlil_r7_crypto_provider *out_provider);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_R7_CRYPTO_OPENSSL3_H */
