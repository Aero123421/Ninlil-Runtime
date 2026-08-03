#include "fabric_private_util.h"

void ninlil_fabric_private_put_u16_be(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)((value >> 8) & 0xffu);
    out[1] = (uint8_t)(value & 0xffu);
}

void ninlil_fabric_private_put_u32_be(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)((value >> 24) & 0xffu);
    out[1] = (uint8_t)((value >> 16) & 0xffu);
    out[2] = (uint8_t)((value >> 8) & 0xffu);
    out[3] = (uint8_t)(value & 0xffu);
}

void ninlil_fabric_private_put_u64_be(uint8_t *out, uint64_t value)
{
    out[0] = (uint8_t)((value >> 56) & 0xffu);
    out[1] = (uint8_t)((value >> 48) & 0xffu);
    out[2] = (uint8_t)((value >> 40) & 0xffu);
    out[3] = (uint8_t)((value >> 32) & 0xffu);
    out[4] = (uint8_t)((value >> 24) & 0xffu);
    out[5] = (uint8_t)((value >> 16) & 0xffu);
    out[6] = (uint8_t)((value >> 8) & 0xffu);
    out[7] = (uint8_t)(value & 0xffu);
}

uint16_t ninlil_fabric_private_get_u16_be(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

uint32_t ninlil_fabric_private_get_u32_be(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

uint64_t ninlil_fabric_private_get_u64_be(const uint8_t *in)
{
    return ((uint64_t)in[0] << 56) | ((uint64_t)in[1] << 48)
        | ((uint64_t)in[2] << 40) | ((uint64_t)in[3] << 32)
        | ((uint64_t)in[4] << 24) | ((uint64_t)in[5] << 16)
        | ((uint64_t)in[6] << 8) | (uint64_t)in[7];
}

void ninlil_fabric_private_memzero(void *dst, size_t length)
{
    if (dst == NULL || length == 0u) {
        return;
    }
    (void)memset(dst, 0, length);
}

int ninlil_fabric_private_memeq(
    const void *a, const void *b, size_t length)
{
    const uint8_t *x;
    const uint8_t *y;
    size_t i;
    uint8_t diff;

    if (a == NULL || b == NULL) {
        return 0;
    }
    x = (const uint8_t *)a;
    y = (const uint8_t *)b;
    diff = 0u;
    for (i = 0u; i < length; ++i) {
        diff = (uint8_t)(diff | (uint8_t)(x[i] ^ y[i]));
    }
    return diff == 0u;
}

int ninlil_fabric_private_is_zero(const uint8_t *bytes, size_t length)
{
    size_t i;
    if (bytes == NULL) {
        return 0;
    }
    for (i = 0u; i < length; ++i) {
        if (bytes[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

int ninlil_fabric_private_id_is_zero(const uint8_t id[16])
{
    return ninlil_fabric_private_is_zero(id, 16u);
}

void ninlil_fabric_private_id_copy(uint8_t dst[16], const uint8_t src[16])
{
    (void)memcpy(dst, src, 16u);
}

int ninlil_fabric_private_id_cmp(const uint8_t a[16], const uint8_t b[16])
{
    size_t i;
    for (i = 0u; i < 16u; ++i) {
        if (a[i] < b[i]) {
            return -1;
        }
        if (a[i] > b[i]) {
            return 1;
        }
    }
    return 0;
}

uint32_t ninlil_fabric_private_crc32c(
    const uint8_t *data, size_t length)
{
    uint32_t crc = UINT32_C(0xffffffff);
    size_t i;
    unsigned bit;

    if (data == NULL && length != 0u) {
        return 0u;
    }
    for (i = 0u; i < length; ++i) {
        crc ^= (uint32_t)data[i];
        for (bit = 0u; bit < 8u; ++bit) {
            if ((crc & 1u) != 0u) {
                crc = (crc >> 1) ^ UINT32_C(0x82f63b78);
            } else {
                crc >>= 1;
            }
        }
    }
    return crc ^ UINT32_C(0xffffffff);
}

static uint32_t fabric_rotr32(uint32_t value, unsigned bits)
{
    return (value >> bits) | (value << (32u - bits));
}

void ninlil_fabric_private_sha256(
    const uint8_t *data, size_t length, uint8_t out[32])
{
    static const uint32_t k[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
        0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
        0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
        0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
        0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
        0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
        0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
        0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
        0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
        0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
    };
    uint32_t h[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    uint8_t block[64];
    uint64_t bit_len = (uint64_t)length * 8u;
    size_t offset = 0u;
    size_t remain = length;
    int done = 0;
    size_t i;

    if (out == NULL) {
        return;
    }
    if (data == NULL && length != 0u) {
        ninlil_fabric_private_memzero(out, 32u);
        return;
    }

    while (!done) {
        uint32_t w[64];
        uint32_t a, b, c, d, e, f, g, hh;
        size_t take = remain > 64u ? 64u : remain;
        ninlil_fabric_private_memzero(block, sizeof(block));
        if (take > 0u) {
            (void)memcpy(block, data + offset, take);
            offset += take;
            remain -= take;
        }
        if (take < 64u) {
            block[take] = 0x80u;
            if (take < 56u) {
                for (i = 0u; i < 8u; ++i) {
                    block[63u - i] = (uint8_t)(bit_len >> (8u * i));
                }
                done = 1;
            }
        }
        for (i = 0u; i < 16u; ++i) {
            w[i] = ((uint32_t)block[i * 4u] << 24)
                | ((uint32_t)block[i * 4u + 1u] << 16)
                | ((uint32_t)block[i * 4u + 2u] << 8)
                | (uint32_t)block[i * 4u + 3u];
        }
        for (i = 16u; i < 64u; ++i) {
            uint32_t s0 = fabric_rotr32(w[i - 15u], 7u)
                ^ fabric_rotr32(w[i - 15u], 18u) ^ (w[i - 15u] >> 3);
            uint32_t s1 = fabric_rotr32(w[i - 2u], 17u)
                ^ fabric_rotr32(w[i - 2u], 19u) ^ (w[i - 2u] >> 10);
            w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
        }
        a = h[0];
        b = h[1];
        c = h[2];
        d = h[3];
        e = h[4];
        f = h[5];
        g = h[6];
        hh = h[7];
        for (i = 0u; i < 64u; ++i) {
            uint32_t S1 = fabric_rotr32(e, 6u) ^ fabric_rotr32(e, 11u)
                ^ fabric_rotr32(e, 25u);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = hh + S1 + ch + k[i] + w[i];
            uint32_t S0 = fabric_rotr32(a, 2u) ^ fabric_rotr32(a, 13u)
                ^ fabric_rotr32(a, 22u);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            hh = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
        if (!done && take == 64u && remain == 0u) {
            /* fall through to final padding block next loop */
        }
    }
    for (i = 0u; i < 8u; ++i) {
        out[i * 4u] = (uint8_t)(h[i] >> 24);
        out[i * 4u + 1u] = (uint8_t)(h[i] >> 16);
        out[i * 4u + 2u] = (uint8_t)(h[i] >> 8);
        out[i * 4u + 3u] = (uint8_t)h[i];
    }
}

void ninlil_fabric_private_tagged_sha256(
    const char *tag_ascii,
    const uint8_t *value,
    size_t value_len,
    uint8_t out[32])
{
    uint8_t buffer[4096];
    size_t tag_len;
    size_t total;

    if (out == NULL || tag_ascii == NULL) {
        return;
    }
    tag_len = strlen(tag_ascii);
    total = tag_len + value_len;
    if (total > sizeof(buffer)) {
        /* Fixed-capacity only; oversized inputs are fail-closed zero. */
        ninlil_fabric_private_memzero(out, 32u);
        return;
    }
    (void)memcpy(buffer, tag_ascii, tag_len);
    if (value_len > 0u && value != NULL) {
        (void)memcpy(buffer + tag_len, value, value_len);
    }
    ninlil_fabric_private_sha256(buffer, total, out);
    ninlil_fabric_private_memzero(buffer, total);
}
