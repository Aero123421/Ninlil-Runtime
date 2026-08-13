/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Host OpenSSL 3 adapter for the private RRMP SHA-256 contract.
 */
#include "rrmp_sha256_provider.h"

#include <openssl/evp.h>

int ninlil_rrmp_sha256_provider(
    const uint8_t *bytes, size_t length, uint8_t out[32])
{
    EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    unsigned int produced = 0u;
    int ok = 0;

    if (bytes == NULL || out == NULL) {
        return 0;
    }
    md = EVP_MD_fetch(NULL, "SHA256", NULL);
    ctx = EVP_MD_CTX_new();
    if (md != NULL && ctx != NULL
        && EVP_DigestInit_ex(ctx, md, NULL) > 0
        && (length == 0u || EVP_DigestUpdate(ctx, bytes, length) > 0)
        && EVP_DigestFinal_ex(ctx, out, &produced) > 0
        && produced == 32u) {
        ok = 1;
    }
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    if (!ok) {
        size_t i;
        for (i = 0u; i < 32u; ++i) {
            out[i] = 0u;
        }
    }
    return ok;
}
