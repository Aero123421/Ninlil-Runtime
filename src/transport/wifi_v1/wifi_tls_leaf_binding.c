#include "wifi_tls_leaf_binding.h"

#include <string.h>

/* OID content (after tag/len 06 14) for
 * 2.25.259582855280982876264288537151153425322
 * = UUID c349d6e3-2623-59b6-96cb-faca1fa0cbaa under 2.25.
 * DER from ADR-0018 §14.2 GeneralNames form:
 * 06 14 69 83 86 c9 eb b8 e4 e2 9a e6 ed 96 e5 fe d9 a1 fd 83 97 2a
 */
const uint8_t ninlil_wifi_leaf_binding_oid_der[20] = {
    0x69, 0x83, 0x86, 0xc9, 0xeb, 0xb8, 0xe4, 0xe2, 0x9a, 0xe6,
    0xed, 0x96, 0xe5, 0xfe, 0xd9, 0xa1, 0xfd, 0x83, 0x97, 0x2a
};

static int is_all_zero(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0u; i < n; ++i) {
        if (p[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static void be_u64(uint8_t *p, uint64_t v)
{
    uint32_t i;
    for (i = 0u; i < 8u; ++i) {
        p[7u - i] = (uint8_t)((v >> (8u * i)) & 0xffu);
    }
}

static void be_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xffu);
    p[1] = (uint8_t)((v >> 16) & 0xffu);
    p[2] = (uint8_t)((v >> 8) & 0xffu);
    p[3] = (uint8_t)(v & 0xffu);
}

static uint64_t rd_be_u64(const uint8_t *p)
{
    uint64_t v = 0u;
    uint32_t i;
    for (i = 0u; i < 8u; ++i) {
        v = (v << 8) | (uint64_t)p[i];
    }
    return v;
}

static uint32_t rd_be_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
        | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

ninlil_wifi_status_t ninlil_wifi_leaf_binding_encode(
    const ninlil_wifi_leaf_binding_t *in,
    uint8_t out[NINLIL_WIFI_LEAF_BINDING_BYTES])
{
    if (in == NULL || out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (in->version != NINLIL_WIFI_LEAF_BINDING_VERSION
        || (in->role != NINLIL_WIFI_LEAF_ROLE_CLIENT
            && in->role != NINLIL_WIFI_LEAF_ROLE_SERVER)
        || is_all_zero(in->runtime_id, 16u)
        || is_all_zero(in->authorized_attachment_binding_digest, 32u)
        || is_all_zero(in->authority_id, 16u) || in->authority_term == 0u
        || in->credential_generation == 0u
        || in->revocation_generation == 0u) {
        return NINLIL_WIFI_DENIED;
    }
    (void)memset(out, 0, NINLIL_WIFI_LEAF_BINDING_BYTES);
    out[0] = in->version;
    out[1] = in->role;
    (void)memcpy(out + 2, in->runtime_id, 16u);
    (void)memcpy(out + 18, in->authorized_attachment_binding_digest, 32u);
    (void)memcpy(out + 50, in->authority_id, 16u);
    be_u64(out + 66, in->authority_term);
    be_u32(out + 74, in->credential_generation);
    be_u32(out + 78, in->revocation_generation);
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_leaf_binding_decode(
    const uint8_t in[NINLIL_WIFI_LEAF_BINDING_BYTES],
    ninlil_wifi_leaf_binding_t *out)
{
    if (in == NULL || out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    (void)memset(out, 0, sizeof(*out));
    out->version = in[0];
    out->role = in[1];
    (void)memcpy(out->runtime_id, in + 2, 16u);
    (void)memcpy(out->authorized_attachment_binding_digest, in + 18, 32u);
    (void)memcpy(out->authority_id, in + 50, 16u);
    out->authority_term = rd_be_u64(in + 66);
    out->credential_generation = rd_be_u32(in + 74);
    out->revocation_generation = rd_be_u32(in + 78);
    if (out->version != NINLIL_WIFI_LEAF_BINDING_VERSION
        || (out->role != NINLIL_WIFI_LEAF_ROLE_CLIENT
            && out->role != NINLIL_WIFI_LEAF_ROLE_SERVER)
        || is_all_zero(out->runtime_id, 16u)
        || is_all_zero(out->authorized_attachment_binding_digest, 32u)
        || is_all_zero(out->authority_id, 16u) || out->authority_term == 0u
        || out->credential_generation == 0u
        || out->revocation_generation == 0u) {
        return NINLIL_WIFI_DENIED;
    }
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_leaf_binding_parse_general_names(
    const uint8_t *gn_der,
    size_t gn_len,
    ninlil_wifi_leaf_binding_t *out)
{
    /*
     * Exact form (112 bytes):
     * 30 6e
     *   a0 6c
     *     06 14 <oid 20>
     *     a0 54
     *       04 52
     *         binding_value[82]
     */
    const uint8_t *p;
    if (gn_der == NULL || out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (gn_len != NINLIL_WIFI_LEAF_SAN_GN_LEN) {
        return NINLIL_WIFI_DENIED;
    }
    p = gn_der;
    if (p[0] != 0x30u || p[1] != 0x6eu || p[2] != 0xa0u || p[3] != 0x6cu
        || p[4] != 0x06u || p[5] != 0x14u) {
        return NINLIL_WIFI_DENIED;
    }
    if (memcmp(p + 6, ninlil_wifi_leaf_binding_oid_der, 20u) != 0) {
        return NINLIL_WIFI_DENIED;
    }
    if (p[26] != 0xa0u || p[27] != 0x54u || p[28] != 0x04u || p[29] != 0x52u) {
        return NINLIL_WIFI_DENIED;
    }
    return ninlil_wifi_leaf_binding_decode(p + 30, out);
}
