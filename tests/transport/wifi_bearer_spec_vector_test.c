/*
 * Independent C11 semantic gate for ADR-0018 Wi-Fi bearer candidate.
 * Every acceptance ID has a distinct substantive assertion; the executed
 * ledger is marked only after that assertion returns success. No inventory
 * mark-only path. Donor row body under the wrong ID index must fail.
 *
 * Proposed/spec-only: no production Wi-Fi/TLS/HIL claim.
 */

#include "wifi_bearer_spec_fixture.h"

#include <stdio.h>
#include <string.h>

enum wifi_class {
    WIFI_OK = 0,
    WIFI_CORRUPT = 1,
    WIFI_UNSUPPORTED = 2,
    WIFI_WRONG_SESSION = 3,
    WIFI_SEQUENCE_REJECT = 4,
    WIFI_INVALID_NFL1 = 5
};

static int g_quiet;

#define REQUIRE(cond)                                                       \
    do {                                                                    \
        if (!(cond)) {                                                      \
            if (!g_quiet) {                                                 \
                (void)fprintf(                                              \
                    stderr,                                                 \
                    "wifi_bearer_spec FAIL %s:%d: %s\n",                    \
                    __FILE__,                                               \
                    __LINE__,                                               \
                    #cond);                                                 \
            }                                                               \
            return 1;                                                       \
        }                                                                   \
    } while (0)

static uint8_t g_executed[NINLIL_WIFI_ACCEPTANCE_ID_COUNT];

static uint32_t wifi_u16(const uint8_t *value)
{
    return ((uint32_t)value[0] << 8) | (uint32_t)value[1];
}

static uint32_t wifi_u32(const uint8_t *value)
{
    return ((uint32_t)value[0] << 24) | ((uint32_t)value[1] << 16)
        | ((uint32_t)value[2] << 8) | (uint32_t)value[3];
}

static void wifi_put_u32(uint8_t *value, uint32_t input)
{
    value[0] = (uint8_t)(input >> 24);
    value[1] = (uint8_t)(input >> 16);
    value[2] = (uint8_t)(input >> 8);
    value[3] = (uint8_t)input;
}

static uint32_t wifi_crc32c(const uint8_t *value, size_t size)
{
    uint32_t crc = UINT32_C(0xffffffff);
    size_t index;
    unsigned int bit;
    for (index = 0u; index < size; ++index) {
        crc ^= (uint32_t)value[index];
        for (bit = 0u; bit < 8u; ++bit) {
            crc = (crc >> 1)
                ^ ((crc & UINT32_C(1)) != 0u ? UINT32_C(0x82f63b78)
                                              : UINT32_C(0));
        }
    }
    return crc ^ UINT32_C(0xffffffff);
}

static int wifi_any_nonzero(const uint8_t *value, size_t size)
{
    size_t index;
    for (index = 0u; index < size; ++index) {
        if (value[index] != 0u) {
            return 1;
        }
    }
    return 0;
}

static uint32_t wifi_rotr32(uint32_t value, unsigned int bits)
{
    return (value >> bits) | (value << (32u - bits));
}

static void wifi_sha256(const uint8_t *message, size_t length, uint8_t out[32])
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

    while (!done) {
        size_t i;
        uint32_t w[64];
        uint32_t a, b, c, d, e, f, g, hh;
        size_t take = remain > 64u ? 64u : remain;
        (void)memset(block, 0, sizeof(block));
        if (take > 0u) {
            (void)memcpy(block, message + offset, take);
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
            uint32_t s0 = wifi_rotr32(w[i - 15u], 7u)
                ^ wifi_rotr32(w[i - 15u], 18u) ^ (w[i - 15u] >> 3);
            uint32_t s1 = wifi_rotr32(w[i - 2u], 17u)
                ^ wifi_rotr32(w[i - 2u], 19u) ^ (w[i - 2u] >> 10);
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
            uint32_t S1 = wifi_rotr32(e, 6u) ^ wifi_rotr32(e, 11u)
                ^ wifi_rotr32(e, 25u);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = hh + S1 + ch + k[i] + w[i];
            uint32_t S0 = wifi_rotr32(a, 2u) ^ wifi_rotr32(a, 13u)
                ^ wifi_rotr32(a, 22u);
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
        if (take < 64u && !done) {
            (void)memset(block, 0, sizeof(block));
            for (i = 0u; i < 8u; ++i) {
                block[63u - i] = (uint8_t)(bit_len >> (8u * i));
            }
            for (i = 0u; i < 16u; ++i) {
                w[i] = ((uint32_t)block[i * 4u] << 24)
                    | ((uint32_t)block[i * 4u + 1u] << 16)
                    | ((uint32_t)block[i * 4u + 2u] << 8)
                    | (uint32_t)block[i * 4u + 3u];
            }
            for (i = 16u; i < 64u; ++i) {
                uint32_t s0 = wifi_rotr32(w[i - 15u], 7u)
                    ^ wifi_rotr32(w[i - 15u], 18u) ^ (w[i - 15u] >> 3);
                uint32_t s1 = wifi_rotr32(w[i - 2u], 17u)
                    ^ wifi_rotr32(w[i - 2u], 19u) ^ (w[i - 2u] >> 10);
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
                uint32_t S1 = wifi_rotr32(e, 6u) ^ wifi_rotr32(e, 11u)
                    ^ wifi_rotr32(e, 25u);
                uint32_t ch = (e & f) ^ ((~e) & g);
                uint32_t temp1 = hh + S1 + ch + k[i] + w[i];
                uint32_t S0 = wifi_rotr32(a, 2u) ^ wifi_rotr32(a, 13u)
                    ^ wifi_rotr32(a, 22u);
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
            done = 1;
        }
    }
    {
        size_t i;
        for (i = 0u; i < 8u; ++i) {
            out[i * 4u] = (uint8_t)(h[i] >> 24);
            out[i * 4u + 1u] = (uint8_t)(h[i] >> 16);
            out[i * 4u + 2u] = (uint8_t)(h[i] >> 8);
            out[i * 4u + 3u] = (uint8_t)h[i];
        }
    }
}

static int classify_nfl1_structural(const uint8_t *packet, size_t length)
{
    uint32_t version;
    uint32_t header_length;
    uint32_t total_length;
    uint32_t stored_crc;
    uint32_t ns_len;
    uint32_t svc_len;
    uint32_t schema_len;
    uint32_t payload_len;
    uint32_t evidence_len;
    uint8_t scratch[1925];
    size_t index;

    if (length < (size_t)NINLIL_WIFI_NFL1_HEADER || length > 1925u) {
        return 0;
    }
    if (packet[0] != (uint8_t)'N' || packet[1] != (uint8_t)'F'
        || packet[2] != (uint8_t)'L' || packet[3] != (uint8_t)'1') {
        return 0;
    }
    version = wifi_u16(packet + 4);
    header_length = wifi_u16(packet + 6);
    total_length = wifi_u32(packet + 8);
    stored_crc = wifi_u32(packet + 12);
    if (header_length != NINLIL_WIFI_NFL1_HEADER || total_length != (uint32_t)length) {
        return 0;
    }
    if (total_length < 587u || version != NINLIL_WIFI_NFL1_VERSION) {
        return 0;
    }
    for (index = 0u; index < length; ++index) {
        scratch[index] = packet[index];
    }
    scratch[12] = 0u;
    scratch[13] = 0u;
    scratch[14] = 0u;
    scratch[15] = 0u;
    if (wifi_crc32c(scratch, length) != stored_crc) {
        return 0;
    }
    ns_len = wifi_u16(packet + 570);
    svc_len = wifi_u16(packet + 572);
    schema_len = wifi_u16(packet + 574);
    payload_len = wifi_u32(packet + 576);
    evidence_len = wifi_u32(packet + 580);
    if (ns_len > 63u || svc_len > 63u || schema_len > 63u) {
        return 0;
    }
    if (NINLIL_WIFI_NFL1_HEADER + ns_len + svc_len + schema_len + payload_len
            + evidence_len
        != total_length) {
        return 0;
    }
    if ((wifi_u32(packet + 20) & UINT32_C(0xffff0000)) != 0u) {
        return 0;
    }
    return 1;
}

static int validate_nwd1(const uint8_t *record, size_t length)
{
    if (length != 160u) {
        return 0;
    }
    if (record[0] != (uint8_t)'N' || record[1] != (uint8_t)'W'
        || record[2] != (uint8_t)'D' || record[3] != (uint8_t)'1') {
        return 0;
    }
    if (wifi_u16(record + 4) != 1u || wifi_u16(record + 6) != 128u
        || wifi_u32(record + 8) != 160u) {
        return 0;
    }
    if (record[126] != 0u || record[127] != 0u) {
        return 0;
    }
    if (record[84] < 1u || record[84] > 32u) {
        return 0;
    }
    if (!wifi_any_nonzero(record + 12, 16u)) {
        return 0;
    }
    if (!wifi_any_nonzero(record + 28, 8u)) {
        return 0;
    }
    if (!wifi_any_nonzero(record + 36, 32u) || !wifi_any_nonzero(record + 68, 16u)
        || !wifi_any_nonzero(record + 128, 32u)) {
        return 0;
    }
    return 1;
}

static int verify_assoc_tag(
    const uint8_t *input,
    size_t input_len,
    const uint8_t *digest32)
{
    uint8_t material[256];
    uint8_t out[32];
    size_t tag_len = sizeof(NINLIL_WIFI_ASSOC_TAG) - 1u;
    size_t index;

    REQUIRE(input_len == 80u);
    REQUIRE(input_len + tag_len <= sizeof(material));
    for (index = 0u; index < tag_len; ++index) {
        material[index] = (uint8_t)NINLIL_WIFI_ASSOC_TAG[index];
    }
    (void)memcpy(material + tag_len, input, input_len);
    wifi_sha256(material, tag_len + input_len, out);
    REQUIRE(memcmp(out, digest32, 32u) == 0);
    /* Wrong tag domain must not match. */
    material[tag_len - 2u] = (uint8_t)'X';
    wifi_sha256(material, tag_len + input_len, out);
    REQUIRE(memcmp(out, digest32, 32u) != 0);
    return 0;
}

/* Association authority input layout (80 bytes, big-endian). */
static uint64_t wifi_u64(const uint8_t *value)
{
    return ((uint64_t)value[0] << 56) | ((uint64_t)value[1] << 48)
        | ((uint64_t)value[2] << 40) | ((uint64_t)value[3] << 32)
        | ((uint64_t)value[4] << 24) | ((uint64_t)value[5] << 16)
        | ((uint64_t)value[6] << 8) | (uint64_t)value[7];
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    return -1;
}

static int decode_hex64(const char *hex, uint8_t out[32])
{
    size_t i;
    if (hex == NULL || strlen(hex) != 64u) {
        return 1;
    }
    for (i = 0u; i < 32u; ++i) {
        int hi = hex_nibble(hex[i * 2u]);
        int lo = hex_nibble(hex[i * 2u + 1u]);
        if (hi < 0 || lo < 0) {
            return 1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static int verify_nwd1_kat_independent(void)
{
    uint8_t material[256];
    uint8_t out[32];
    static const char auth_tag[] = "NINLIL-WIFI-NWD1-AUTH-V1";
    static const char complete_tag[] = "NINLIL-WIFI-NWD1-COMPLETE-V1";
    size_t auth_tag_len = sizeof(auth_tag) - 1u;
    size_t complete_tag_len = sizeof(complete_tag) - 1u;
    uint32_t crc;

    REQUIRE(sizeof(ninlil_wifi_nwd1_kat_value) == 160u);
    REQUIRE(validate_nwd1(ninlil_wifi_nwd1_kat_value, 160u));
    crc = wifi_crc32c(ninlil_wifi_nwd1_kat_value, 128u);
    REQUIRE(crc == NINLIL_WIFI_NWD1_KAT_HEADER_CRC);
    /* Fixed SSID pin; must not be lab default. */
    REQUIRE(memcmp(ninlil_wifi_nwd1_kat_value + 85, "KAT-NWD1-FIXED", 14) == 0);
    REQUIRE(memcmp(ninlil_wifi_nwd1_kat_value + 85, "ninlil-lab-ssid", 14) != 0);
    /* Auth digest */
    REQUIRE(auth_tag_len + 160u <= sizeof(material));
    (void)memcpy(material, auth_tag, auth_tag_len);
    (void)memcpy(material + auth_tag_len, ninlil_wifi_nwd1_kat_value, 160u);
    wifi_sha256(material, auth_tag_len + 160u, out);
    REQUIRE(memcmp(out, ninlil_wifi_nwd1_kat_auth, 32u) == 0);
    /* Complete digest */
    REQUIRE(complete_tag_len + 160u <= sizeof(material));
    (void)memcpy(material, complete_tag, complete_tag_len);
    (void)memcpy(material + complete_tag_len, ninlil_wifi_nwd1_kat_value, 160u);
    wifi_sha256(material, complete_tag_len + 160u, out);
    REQUIRE(memcmp(out, ninlil_wifi_nwd1_kat_complete, 32u) == 0);
    return 0;
}

static enum wifi_class classify_nwb1(
    const uint8_t *record,
    size_t length,
    const uint8_t *expected_session_or_null,
    int has_expected_sequence,
    uint32_t expected_sequence)
{
    uint32_t version;
    uint32_t header_length;
    uint32_t total_length;
    uint32_t payload_length;
    uint32_t sequence;
    uint32_t stored_crc;
    uint8_t scratch[1965];
    size_t index;

    if (length < 40u || length > 1965u) {
        return WIFI_CORRUPT;
    }
    if (record[0] != (uint8_t)'N' || record[1] != (uint8_t)'W'
        || record[2] != (uint8_t)'B' || record[3] != (uint8_t)'1') {
        return WIFI_CORRUPT;
    }
    version = wifi_u16(record + 4);
    header_length = wifi_u16(record + 6);
    total_length = wifi_u32(record + 8);
    payload_length = wifi_u32(record + 12);
    sequence = wifi_u32(record + 32);
    stored_crc = wifi_u32(record + 36);
    if (header_length != 40u || total_length != (uint32_t)length
        || payload_length != (uint32_t)length - 40u) {
        return WIFI_CORRUPT;
    }
    if (payload_length < 587u || payload_length > 1925u
        || total_length < 627u || total_length > 1965u) {
        return WIFI_CORRUPT;
    }
    for (index = 0u; index < length; ++index) {
        scratch[index] = record[index];
    }
    scratch[36] = 0u;
    scratch[37] = 0u;
    scratch[38] = 0u;
    scratch[39] = 0u;
    if (wifi_crc32c(scratch, length) != stored_crc) {
        return WIFI_CORRUPT;
    }
    if (version > 1u) {
        return WIFI_UNSUPPORTED;
    }
    if (version != 1u || !wifi_any_nonzero(record + 16, 16u)) {
        return WIFI_CORRUPT;
    }
    if (expected_session_or_null != NULL
        && memcmp(record + 16, expected_session_or_null, 16u) != 0) {
        return WIFI_WRONG_SESSION;
    }
    if (sequence == UINT32_C(0xffffffff)) {
        return WIFI_SEQUENCE_REJECT;
    }
    if (has_expected_sequence && sequence != expected_sequence) {
        return WIFI_SEQUENCE_REJECT;
    }
    if (!classify_nfl1_structural(record + 40, length - 40u)) {
        return WIFI_INVALID_NFL1;
    }
    return WIFI_OK;
}

static int streq(const char *left, const char *right)
{
    return left != NULL && right != NULL && strcmp(left, right) == 0;
}

/*
 * Hard-coded independent authority per ID index. Validates fixture row `row`
 * against the contract for `case_index` (not row->id alone, so donor swaps fail).
 */
static int assert_case_index(size_t case_index, const ninlil_wifi_case_row_t *row)
{
    uint8_t digest[32];
    const char *expect_id;
    int id_index;

    REQUIRE(case_index < (size_t)NINLIL_WIFI_ACCEPTANCE_ID_COUNT);
    REQUIRE(row != NULL);
    expect_id = ninlil_wifi_acceptance_ids[case_index];
    REQUIRE(streq(row->id, expect_id));

    /* Dispatch by stable acceptance ID string (not brittle numeric shifts). */
    if (streq(expect_id, "WIFI-ASSOC-AUTHORITY-EPOCH-BASELINE")) {
        id_index = 0;
    } else if (streq(expect_id, "WIFI-ASSOC-SAME-SSID-BSSID-CHANGE-FENCE")) {
        id_index = 1;
    } else if (streq(expect_id, "WIFI-ASSOC-SAME-SSID-CHANNEL-CHANGE-FENCE")) {
        id_index = 2;
    } else if (streq(expect_id, "WIFI-ASSOC-PROFILE-DIGEST-CHANGE-FENCE")) {
        id_index = 3;
    } else if (streq(expect_id, "WIFI-ASSOC-SAME-TUPLE-NO-EPOCH")) {
        id_index = 4;
    } else if (streq(expect_id, "WIFI-ASSOC-SESSION-FENCE-AVAILABILITY-PLUS-ONE")) {
        id_index = 5;
    } else if (streq(expect_id, "WIFI-LIVENESS-KEEPALIVE-EXCLUSIVE-TIMER")) {
        id_index = 6;
    } else if (streq(expect_id, "WIFI-LIVENESS-MISSED-RESPONSE-THRESHOLD")) {
        id_index = 7;
    } else if (streq(expect_id, "WIFI-LIVENESS-BLACKHOLE-DETECTION")) {
        id_index = 8;
    } else if (streq(expect_id, "WIFI-LIVENESS-TCP-HALF-OPEN")) {
        id_index = 9;
    } else if (streq(expect_id, "WIFI-LIVENESS-AP-DEAD-BACKHAUL")) {
        id_index = 10;
    } else if (streq(expect_id, "WIFI-LIVENESS-AVAILABILITY-EPOCH-CHANGE")) {
        id_index = 11;
    } else if (streq(expect_id, "WIFI-NETCRED-FULL-OLD")) {
        id_index = 12;
    } else if (streq(expect_id, "WIFI-NETCRED-FULL-NEW")) {
        id_index = 13;
    } else if (streq(expect_id, "WIFI-NETCRED-FULL-ABSENT")) {
        id_index = 14;
    } else if (streq(expect_id, "WIFI-NETCRED-FULL-BOTH")) {
        id_index = 100; /* dedicated BOTH */
    } else if (streq(expect_id, "WIFI-NETCRED-PARTIAL")) {
        id_index = 15;
    } else if (streq(expect_id, "WIFI-NETCRED-EXTRA")) {
        id_index = 16;
    } else if (streq(expect_id, "WIFI-NETCRED-THIRD")) {
        id_index = 17;
    } else if (streq(expect_id, "WIFI-NETCRED-DUPLICATE-KEY")) {
        id_index = 18;
    } else if (streq(expect_id, "WIFI-NETCRED-COMMIT-UNKNOWN-RECOVERY")) {
        id_index = 19;
    } else if (streq(expect_id, "WIFI-NETCRED-ROLLBACK-REJECT")) {
        id_index = 20;
    } else if (streq(expect_id, "WIFI-NETCRED-SAME-REVISION-DIGEST-CONFLICT")) {
        id_index = 21;
    } else if (streq(expect_id, "WIFI-NETCRED-NO-PLAINTEXT-SECRET")) {
        id_index = 22;
    } else if (streq(expect_id, "WIFI-ENDPOINT-IPV4-SCOPE")) {
        id_index = 23;
    } else if (streq(expect_id, "WIFI-ENDPOINT-IPV6-SCOPE")) {
        id_index = 24;
    } else if (streq(expect_id, "WIFI-ENDPOINT-LINK-LOCAL-SCOPE-ID")) {
        id_index = 25;
    } else if (streq(expect_id, "WIFI-ENDPOINT-DNS-MDNS-NON-AUTHORITY")) {
        id_index = 26;
    } else if (streq(expect_id, "WIFI-ENDPOINT-ADDRESS-CHANGE-FENCE")) {
        id_index = 27;
    } else if (strncmp(expect_id, "WIFI-NWB1-", 10) == 0) {
        /* Map NWB1 family by original numeric order offset 28..50 */
        id_index = -1;
        {
            static const char *const nwb_ids[] = {
                "WIFI-NWB1-HEADER-40",
                "WIFI-NWB1-PAYLOAD-586-REJECT",
                "WIFI-NWB1-PAYLOAD-587-ACCEPT",
                "WIFI-NWB1-PAYLOAD-1925-ACCEPT",
                "WIFI-NWB1-PAYLOAD-1926-REJECT",
                "WIFI-NWB1-TOTAL-626-REJECT",
                "WIFI-NWB1-TOTAL-627-ACCEPT",
                "WIFI-NWB1-TOTAL-1965-ACCEPT",
                "WIFI-NWB1-TOTAL-1966-REJECT",
                "WIFI-NWB1-CRC32C-INDEPENDENT",
                "WIFI-NWB1-PARTIAL-HEADER",
                "WIFI-NWB1-PARTIAL-BODY",
                "WIFI-NWB1-COALESCED-RECORDS",
                "WIFI-NWB1-READ-AHEAD-BOUND",
                "WIFI-NWB1-WRONG-SESSION",
                "WIFI-NWB1-SEQUENCE-0",
                "WIFI-NWB1-SEQUENCE-MAX-MINUS-ONE",
                "WIFI-NWB1-SEQUENCE-UINT32-MAX-REJECT",
                "WIFI-NWB1-DUPLICATE",
                "WIFI-NWB1-GAP",
                "WIFI-NWB1-OUT-OF-ORDER",
                "WIFI-NWB1-WRAP-REJECT",
                "WIFI-NWB1-INVALID-NFL1",
            };
            size_t ni;
            for (ni = 0u; ni < sizeof(nwb_ids) / sizeof(nwb_ids[0]); ++ni) {
                if (streq(expect_id, nwb_ids[ni])) {
                    id_index = 28 + (int)ni;
                    break;
                }
            }
            REQUIRE(id_index >= 0);
        }
    } else if (strncmp(expect_id, "WIFI-TLS-", 9) == 0) {
        static const char *const tls_ids[] = {
            "WIFI-TLS-SUITE-GROUP-SIGNATURE-EXACT",
            "WIFI-TLS-X509-ROLE-RUNTIME-ATTACHMENT",
            "WIFI-TLS-EXPORTER-PEER-CONTEXT-62",
            "WIFI-TLS-EXPORTER-ATTACHED-CONTEXT-64",
            "WIFI-TLS-AUTHORITY-ALL-ZERO-GROUP",
            "WIFI-TLS-AUTHORITY-MIXED-REJECT",
            "WIFI-TLS-TICKET-0RTT-RENEGOTIATION-FENCE",
            "WIFI-TLS-REVOCATION-CLOCK-RULES",
            "WIFI-TLS-R7-OPENSSL-GENERIC-NON-AUTHORITY",
            "WIFI-TLS-HOST-OPENSSL-PIN-AUTHORITY",
            "WIFI-TLS-ESP-MBEDTLS-PIN-AUTHORITY",
        };
        size_t ti;
        id_index = -1;
        for (ti = 0u; ti < sizeof(tls_ids) / sizeof(tls_ids[0]); ++ti) {
            if (streq(expect_id, tls_ids[ti])) {
                id_index = 51 + (int)ti;
                break;
            }
        }
        REQUIRE(id_index >= 0);
    } else if (streq(expect_id, "WIFI-PREATTACH-CARRIER-NOT-NWB1")) {
        id_index = 62;
    } else if (streq(expect_id, "WIFI-PREATTACH-PEER-SESSION-ONLY-NO-NWB1")) {
        id_index = 63;
    } else if (streq(expect_id, "WIFI-PREATTACH-NWB1-REQUIRES-PA-FULL")) {
        id_index = 64;
    } else if (streq(expect_id, "WIFI-RESOURCE-ESP-CAPACITY")) {
        id_index = 65;
    } else if (streq(expect_id, "WIFI-RESOURCE-HOST-CAPACITY")) {
        id_index = 66;
    } else if (streq(expect_id, "WIFI-RESOURCE-PRIORITY-ISOLATION")) {
        id_index = 67;
    } else if (streq(expect_id, "WIFI-RESOURCE-RETAINED-TOKEN-PARTIAL-WRITE")) {
        id_index = 68;
    } else if (streq(expect_id, "WIFI-RESOURCE-RELEASE-SEMANTICS")) {
        id_index = 69;
    } else if (streq(expect_id, "WIFI-RESOURCE-NO-FALSE-CUSTODY")) {
        id_index = 70;
    } else if (streq(expect_id, "WIFI-RESOURCE-STORAGE-ARITHMETIC")) {
        id_index = 71;
    } else if (streq(expect_id, "WIFI-ROLE-HOST-POSIX-TCP-TLS")) {
        id_index = 72;
    } else if (streq(expect_id, "WIFI-ROLE-ESP32S3-STA-LWIP-MBEDTLS")) {
        id_index = 73;
    } else if (streq(expect_id, "WIFI-RACE-DISCONNECT-RECONNECT")) {
        id_index = 74;
    } else if (streq(expect_id, "WIFI-RACE-SLEEP-DRAIN")) {
        id_index = 75;
    } else if (streq(expect_id, "WIFI-RACE-EVENT-OVERFLOW")) {
        id_index = 76;
    } else if (streq(expect_id, "WIFI-BACKOFF-DETERMINISTIC")) {
        id_index = 77;
    } else {
        REQUIRE(0 && "unmapped acceptance id");
        id_index = -1;
    }

    switch (id_index) {
    case 0: /* WIFI-ASSOC-AUTHORITY-EPOCH-BASELINE */
        REQUIRE(row->f[0] == 0 && row->f[1] == 0);
        REQUIRE(streq(row->s0, "OK_ATTACHED_ELIGIBLE"));
        REQUIRE(row->sha_len == 32u && row->b0_len == 80u);
        if (verify_assoc_tag(row->b0, row->b0_len, row->sha) != 0) {
            return 1;
        }
        /* Bind channel/auth from canonical input (not opaque blob). */
        REQUIRE(row->b0[78] >= 1u);
        REQUIRE(row->b0[79] >= 1u);
        REQUIRE(wifi_u64(row->b0 + 16) == 1ull);
        break;
    case 1: /* BSSID change fence — full old/new tuple bind */
        REQUIRE(row->f[0] == 1 && row->f[1] == 1 && row->f[2] == 0);
        REQUIRE(row->f[3] == 0);
        REQUIRE(streq(row->s0, "FENCED_STALE_SESSION"));
        REQUIRE(row->b0_len == 80u && row->b1_len == 80u && row->sha_len == 32u);
        if (verify_assoc_tag(row->b0, row->b0_len, row->sha) != 0) {
            return 1;
        }
        REQUIRE(row->s1 != NULL && strlen(row->s1) == 64u);
        {
            uint8_t new_digest[32];
            REQUIRE(decode_hex64(row->s1, new_digest) == 0);
            if (verify_assoc_tag(row->b1, row->b1_len, new_digest) != 0) {
                return 1;
            }
            /* BSSID at offset 72 differs; profile_id/binding/channel/auth match. */
            REQUIRE(memcmp(row->b0 + 72, row->b1 + 72, 6u) != 0);
            REQUIRE(memcmp(row->b0 + 0, row->b1 + 0, 16u) == 0); /* profile_id */
            REQUIRE(memcmp(row->b0 + 56, row->b1 + 56, 16u) == 0); /* binding */
            REQUIRE(row->b0[78] == row->b1[78]); /* channel */
            REQUIRE(row->b0[79] == row->b1[79]); /* auth */
            REQUIRE(wifi_u64(row->b0 + 16) == wifi_u64(row->b1 + 16)); /* epoch */
            /* profile_digest differs when BSSID present tuple changes */
            REQUIRE(memcmp(row->b0 + 24, row->b1 + 24, 32u) != 0);
            REQUIRE(memcmp(row->sha, new_digest, 32u) != 0);
        }
        break;
    case 2: /* channel change — bind channel field from canonical inputs */
        REQUIRE(row->f[0] == 1 && row->f[1] == 1);
        REQUIRE(row->f[6] == 6 && row->f[7] == 11);
        REQUIRE(streq(row->s0, "FENCED_STALE_SESSION"));
        REQUIRE(row->b0_len == 80u && row->b1_len == 80u && row->sha_len == 32u);
        if (verify_assoc_tag(row->b0, row->b0_len, row->sha) != 0) {
            return 1;
        }
        {
            uint8_t new_digest[32];
            REQUIRE(row->s1 != NULL && decode_hex64(row->s1, new_digest) == 0);
            if (verify_assoc_tag(row->b1, row->b1_len, new_digest) != 0) {
                return 1;
            }
            REQUIRE(row->b0[78] == 6u);
            REQUIRE(row->b1[78] == 11u);
            REQUIRE(memcmp(row->b0 + 72, row->b1 + 72, 6u) == 0); /* same bssid */
        }
        break;
    case 3: /* profile digest */
        REQUIRE(row->f[0] == 1 && row->f[1] == 1);
        REQUIRE(row->f[4] == 1 && row->f[5] == 2);
        REQUIRE(streq(row->s0, "FENCED_STALE_SESSION"));
        REQUIRE(row->b0_len == 80u && row->b1_len == 80u && row->sha_len == 32u);
        if (verify_assoc_tag(row->b0, row->b0_len, row->sha) != 0) {
            return 1;
        }
        {
            uint8_t new_digest[32];
            REQUIRE(row->s1 != NULL && decode_hex64(row->s1, new_digest) == 0);
            if (verify_assoc_tag(row->b1, row->b1_len, new_digest) != 0) {
                return 1;
            }
            REQUIRE(wifi_u64(row->b0 + 16) == 1ull);
            REQUIRE(wifi_u64(row->b1 + 16) == 2ull);
            REQUIRE(memcmp(row->b0 + 24, row->b1 + 24, 32u) != 0);
        }
        break;
    case 4: /* same tuple */
        REQUIRE(row->f[0] == 0 && row->f[1] == 0 && row->f[8] == 1);
        REQUIRE(streq(row->s0, "OK_NO_FENCE"));
        REQUIRE(row->b0_len > 0u && row->sha_len == 32u);
        if (verify_assoc_tag(row->b0, row->b0_len, row->sha) != 0) {
            return 1;
        }
        break;
    case 5: /* availability plus one once */
        REQUIRE(row->f[1] == 1 && row->f[9] == 1);
        REQUIRE(row->f[10] == 2 && row->f[11] == 1);
        REQUIRE(streq(row->s0, "AVAILABILITY_PLUS_ONE_ONCE"));
        break;
    case 6: /* keepalive exclusive */
        REQUIRE(row->f[0] == (int32_t)NINLIL_WIFI_KEEPALIVE_MS);
        REQUIRE(row->f[1] == (int32_t)NINLIL_WIFI_KEEPALIVE_MS);
        REQUIRE(row->f[2] == 0);
        REQUIRE(streq(row->s0, "OK_EXCLUSIVE"));
        REQUIRE(streq(row->s1, "ATTACHED"));
        break;
    case 7: /* missed threshold */
        REQUIRE(row->f[3] == (int32_t)NINLIL_WIFI_MISSED_THRESHOLD);
        REQUIRE(row->f[4] == (int32_t)NINLIL_WIFI_MISSED_THRESHOLD);
        REQUIRE(row->f[5] == (int32_t)NINLIL_WIFI_MISSED_THRESHOLD - 1);
        REQUIRE(streq(row->s0, "FAIL_AT_THRESHOLD"));
        break;
    case 8: /* blackhole */
        REQUIRE(row->f[6] == (int32_t)NINLIL_WIFI_BLACKHOLE_MS);
        REQUIRE(row->f[7] == 1);
        REQUIRE(
            NINLIL_WIFI_BLACKHOLE_MS
            == NINLIL_WIFI_KEEPALIVE_MS * NINLIL_WIFI_MISSED_THRESHOLD);
        REQUIRE(streq(row->s0, "FENCED_ON_BLACKHOLE"));
        break;
    case 9: /* half-open */
        REQUIRE(row->f[8] == 0 && row->f[9] == 1);
        REQUIRE(streq(row->s0, "FENCED_HALF_OPEN"));
        REQUIRE(streq(row->s1, "PEER_SILENT_TCP_STILL_WRITABLE"));
        break;
    case 10: /* dead backhaul */
        REQUIRE(row->f[10] == 1 && row->f[11] == 0);
        REQUIRE(streq(row->s0, "FENCED_DEAD_BACKHAUL"));
        break;
    case 11: /* liveness epoch */
        REQUIRE(row->f[0] == 1 && row->f[1] == 0 && row->f[2] == 1);
        REQUIRE(row->f[3] == 1 && row->f[4] == 1);
        REQUIRE(streq(row->s0, "AVAILABILITY_PLUS_ONE"));
        break;
    case 12: /* NETCRED OLD */
        REQUIRE(row->f[0] == 1 && row->f[1] == 0);
        /* Coherent equality still requires NWD1 framing (not XWD1). */
        REQUIRE(row->b0_len == 0u || validate_nwd1(row->b0, row->b0_len));
        break;
    case 13: /* NEW */
        REQUIRE(row->f[0] == 2 && row->f[1] == 0 && row->f[2] == 1);
        break;
    case 14: /* ABSENT */
        REQUIRE(row->f[0] == 6 && row->f[1] == 0);
        REQUIRE(row->f[9] == 0 && row->f[11] == 0 && row->f[10] >= 1);
        REQUIRE(streq(row->s0, "ABSENT_RECLASSIFY_ONLY"));
        break;
    case 100: /* BOTH */
        REQUIRE(row->f[0] == 8);
        REQUIRE(streq(row->s0, "BOTH_OLD_AND_NEW_PRESENT"));
        REQUIRE(row->b0_len == 0u || validate_nwd1(row->b0, row->b0_len));
        break;
    case 15: /* PARTIAL */
        REQUIRE(row->f[0] == 3 && row->f[1] == 0);
        REQUIRE(streq(row->s0, "CORRUPT_OR_COMMIT_UNKNOWN_NO_PUBLISH"));
        break;
    case 16: /* EXTRA */
        REQUIRE(row->f[0] == 4);
        break;
    case 17: /* THIRD */
        REQUIRE(row->f[0] == 5);
        break;
    case 18: /* DUPLICATE-KEY CORRUPT */
        REQUIRE(row->f[0] == 7 && row->f[5] == 1);
        REQUIRE(streq(row->s0, "CORRUPT_DUPLICATE_KEY"));
        break;
    case 19: /* COMMIT_UNKNOWN recovery includes CORRUPT */
        REQUIRE(row->f[6] == 1);
        REQUIRE(row->f[7] == 1 && row->f[8] == 0);
        REQUIRE(streq(row->s0, "RECLASSIFY_ONLY"));
        break;
    case 20: /* rollback */
        REQUIRE(row->f[3] == 2 && row->f[4] == 1 && row->f[1] == 0);
        REQUIRE(streq(row->s0, "FENCED_ROLLBACK"));
        REQUIRE(row->b0_len == (size_t)NINLIL_WIFI_NWD1_RECORD_BYTES);
        REQUIRE(validate_nwd1(row->b0, row->b0_len));
        break;
    case 21: /* same-revision conflict */
        REQUIRE(row->f[5] == 2 && row->f[6] == 0 && row->f[1] == 0);
        REQUIRE(streq(row->s0, "FENCED_DIGEST_CONFLICT"));
        REQUIRE(row->b0_len == row->b1_len && row->b0_len > 0u);
        REQUIRE(memcmp(row->b0, row->b1, row->b0_len) != 0);
        REQUIRE(validate_nwd1(row->b0, row->b0_len));
        REQUIRE(validate_nwd1(row->b1, row->b1_len));
        break;
    case 22: /* no plaintext secret + independent NWD1 KAT */
        REQUIRE(streq(row->s0, "OK_NO_PLAINTEXT"));
        REQUIRE(row->b0_len == (size_t)NINLIL_WIFI_NWD1_RECORD_BYTES);
        REQUIRE(row->b1_len == (size_t)NINLIL_WIFI_NWD1_RECORD_BYTES);
        REQUIRE(validate_nwd1(row->b0, row->b0_len));
        REQUIRE(validate_nwd1(row->b1, row->b1_len));
        REQUIRE(row->sha_len == 32u);
        /* secret_ref preimage: trailing 32 bytes of old NWD1 value. */
        REQUIRE(memcmp(row->b0 + 128, row->sha, 32u) == 0);
        if (verify_nwd1_kat_independent() != 0) {
            return 1;
        }
        /* Inventory + document model hardpins (Py/Node parity surface). */
        REQUIRE(NINLIL_WIFI_OBJECT_PATH_COUNT == 117u);
        REQUIRE(NINLIL_WIFI_INTEGER_LEAF_COUNT == 386u);
        REQUIRE(NINLIL_WIFI_STRING_LEAF_COUNT == 692u);
        REQUIRE(NINLIL_WIFI_DIGEST_LEAF_COUNT == 96u);
        REQUIRE(
            streq(
                NINLIL_WIFI_VECTOR_DOCUMENT_SHA256,
                "38d8050206d8de832dfe9395f6f39b99e1119eb06fa60ee2112af2cd375b25ff"));
        break;
    case 23: /* IPv4 */
        REQUIRE(row->f[0] == 1 && row->f[1] == 8443 && row->f[2] == 0);
        REQUIRE(row->f[3] == 1);
        REQUIRE(row->b0_len == 16u);
        REQUIRE(row->b0[4] == 0u && row->b0[15] == 0u);
        REQUIRE(streq(row->s0, "OK"));
        break;
    case 24: /* IPv6 */
        REQUIRE(row->f[0] == 2 && row->f[1] == 8443);
        REQUIRE(row->b0_len == 16u);
        REQUIRE(streq(row->s0, "OK"));
        break;
    case 25: /* link-local scope */
        REQUIRE(row->f[4] == 1 && row->f[5] == 1);
        REQUIRE(row->f[6] >= 1 && row->f[6] < 0x7fffffff);
        REQUIRE(row->b0_len == 16u && row->b0[0] == 0xfeu);
        REQUIRE(streq(row->s0, "OK_WITH_SCOPE_ID"));
        break;
    case 26: /* dns/mdns non-authority */
        REQUIRE(row->f[11] == 1);
        REQUIRE(streq(row->s0, "AUXILIARY_ONLY"));
        break;
    case 27: /* address change fence */
        REQUIRE(row->f[7] == 1 && row->f[8] == 1 && row->f[9] == 1);
        REQUIRE(streq(row->s0, "FENCED"));
        break;
    case 28: /* NWB1 header 40 */
        REQUIRE(row->b0_len >= 40u);
        REQUIRE(wifi_u16(row->b0 + 6) == NINLIL_WIFI_NWB1_HEADER);
        REQUIRE(
            classify_nwb1(
                row->b0, row->b0_len, ninlil_wifi_session_id, 1, 0u)
            == WIFI_OK);
        break;
    case 29: /* payload 586 reject */
        REQUIRE(row->f[0] == 586);
        REQUIRE(classify_nwb1(row->b0, row->b0_len, NULL, 0, 0u) == WIFI_CORRUPT);
        break;
    case 30: /* 587 accept */
        REQUIRE(row->f[0] == (int32_t)NINLIL_WIFI_NWB1_PAYLOAD_MIN);
        REQUIRE(row->f[1] == (int32_t)NINLIL_WIFI_NWB1_TOTAL_MIN);
        REQUIRE(row->b0_len == (size_t)NINLIL_WIFI_NWB1_TOTAL_MIN);
        REQUIRE(
            classify_nwb1(
                row->b0, row->b0_len, ninlil_wifi_session_id, 1, 0u)
            == WIFI_OK);
        REQUIRE(classify_nfl1_structural(row->b0 + 40, row->b0_len - 40u));
        /* NFL1 version mutation after NWB1 CRC repair must fail. */
        {
            uint8_t mut[627];
            REQUIRE(row->b0_len == sizeof(mut));
            (void)memcpy(mut, row->b0, sizeof(mut));
            mut[44] = 0x00u;
            mut[45] = 0xffu;
            mut[36] = 0u;
            mut[37] = 0u;
            mut[38] = 0u;
            mut[39] = 0u;
            wifi_put_u32(mut + 36, wifi_crc32c(mut, sizeof(mut)));
            REQUIRE(
                classify_nwb1(mut, sizeof(mut), ninlil_wifi_session_id, 1, 0u)
                == WIFI_INVALID_NFL1);
        }
        wifi_sha256(row->b0, row->b0_len, digest);
        REQUIRE(memcmp(digest, ninlil_wifi_nwb1_min_sha256, 32u) == 0);
        break;
    case 31: /* 1925 accept */
        REQUIRE(row->f[0] == (int32_t)NINLIL_WIFI_NWB1_PAYLOAD_MAX);
        REQUIRE(row->f[1] == (int32_t)NINLIL_WIFI_NWB1_TOTAL_MAX);
        REQUIRE(row->b0_len == (size_t)NINLIL_WIFI_NWB1_TOTAL_MAX);
        REQUIRE(
            classify_nwb1(
                row->b0, row->b0_len, ninlil_wifi_session_id, 1, 0u)
            == WIFI_OK);
        break;
    case 32: /* 1926 reject */
        REQUIRE(row->f[0] == 1926);
        REQUIRE(classify_nwb1(row->b0, row->b0_len, NULL, 0, 0u) == WIFI_CORRUPT);
        break;
    case 33: /* total 626 */
        REQUIRE(row->f[1] == 626);
        REQUIRE(classify_nwb1(row->b0, row->b0_len, NULL, 0, 0u) == WIFI_CORRUPT);
        break;
    case 34: /* total 627 */
        REQUIRE(row->f[1] == (int32_t)NINLIL_WIFI_NWB1_TOTAL_MIN);
        REQUIRE(classify_nwb1(row->b0, row->b0_len, NULL, 0, 0u) == WIFI_OK);
        break;
    case 35: /* total 1965 */
        REQUIRE(row->f[1] == (int32_t)NINLIL_WIFI_NWB1_TOTAL_MAX);
        REQUIRE(classify_nwb1(row->b0, row->b0_len, NULL, 0, 0u) == WIFI_OK);
        break;
    case 36: /* total 1966 */
        REQUIRE(row->f[1] == 1966);
        REQUIRE(classify_nwb1(row->b0, row->b0_len, NULL, 0, 0u) == WIFI_CORRUPT);
        break;
    case 37: /* CRC independent */
        REQUIRE(row->b0_len > 40u && row->b1_len == row->b0_len);
        REQUIRE(classify_nwb1(row->b0, row->b0_len, NULL, 0, 0u) == WIFI_OK);
        REQUIRE(classify_nwb1(row->b1, row->b1_len, NULL, 0, 0u) == WIFI_CORRUPT);
        {
            uint8_t repaired[1965];
            REQUIRE(row->b1_len <= sizeof(repaired));
            (void)memcpy(repaired, row->b1, row->b1_len);
            repaired[36] = 0u;
            repaired[37] = 0u;
            repaired[38] = 0u;
            repaired[39] = 0u;
            wifi_put_u32(repaired + 36, wifi_crc32c(repaired, row->b1_len));
            REQUIRE(memcmp(repaired, row->b0, row->b0_len) == 0);
        }
        REQUIRE(streq(row->s0, "OK") && streq(row->s1, "CORRUPT"));
        break;
    case 38: /* partial header */
        REQUIRE(row->f[6] == 0 && row->f[8] == 40 && row->f[7] < 40);
        REQUIRE(streq(row->s0, "WANT_READ_NO_DELIVERY"));
        REQUIRE(row->b0_len == (size_t)row->f[7]);
        break;
    case 39: /* partial body */
        REQUIRE(row->f[6] == 0 && row->f[8] == 627);
        REQUIRE(row->f[7] > 40 && row->f[7] < 627);
        REQUIRE(streq(row->s0, "WANT_READ_NO_DELIVERY"));
        break;
    case 40: /* coalesced */
        REQUIRE(row->f[9] == 2 && row->f[2] == 0 && row->f[5] == 1);
        REQUIRE(row->b0_len >= 1254u);
        REQUIRE(
            classify_nwb1(
                row->b0, 627u, ninlil_wifi_session_id, 1, 0u)
            == WIFI_OK);
        REQUIRE(
            classify_nwb1(
                row->b0 + 627, 627u, ninlil_wifi_session_id, 1, 1u)
            == WIFI_OK);
        break;
    case 41: /* read-ahead */
        REQUIRE(row->f[0] == 1 && row->f[1] == 1965 && row->f[2] == 1);
        REQUIRE(streq(row->s0, "BOUND_OK"));
        break;
    case 42: /* wrong session */
        REQUIRE(
            classify_nwb1(
                row->b0, row->b0_len, ninlil_wifi_session_id, 0, 0u)
            == WIFI_WRONG_SESSION);
        REQUIRE(row->f[10] == 0 && row->f[11] == 1);
        break;
    case 43: /* sequence 0 */
        REQUIRE(row->f[2] == 0);
        REQUIRE(
            classify_nwb1(
                row->b0, row->b0_len, ninlil_wifi_session_id, 1, 0u)
            == WIFI_OK);
        break;
    case 44: /* max-1 */
        REQUIRE((uint32_t)row->f[2] == UINT32_C(0xfffffffe)
            || row->f[2] == (int32_t)UINT32_C(0xfffffffe));
        REQUIRE(
            classify_nwb1(
                row->b0,
                row->b0_len,
                ninlil_wifi_session_id,
                1,
                UINT32_C(0xfffffffe))
            == WIFI_OK);
        break;
    case 45: /* UINT32_MAX reject */
        REQUIRE(wifi_u32(row->b0 + 32) == UINT32_C(0xffffffff));
        REQUIRE(
            classify_nwb1(row->b0, row->b0_len, ninlil_wifi_session_id, 0, 0u)
            == WIFI_SEQUENCE_REJECT);
        REQUIRE(row->f[11] == 1);
        break;
    case 46: /* DUPLICATE prior=1 expected=2 received=1 */
        REQUIRE(row->f[3] == 1 && row->f[5] == 2 && row->f[4] == 1);
        REQUIRE(row->f[10] == 0 && row->f[11] == 1);
        REQUIRE(streq(row->s0, "CLOSE_NO_DELIVERY"));
        REQUIRE(wifi_u32(row->b0 + 32) == 1u);
        REQUIRE(
            classify_nwb1(
                row->b0, row->b0_len, ninlil_wifi_session_id, 1, 2u)
            == WIFI_SEQUENCE_REJECT);
        break;
    case 47: /* GAP */
        REQUIRE(row->f[3] == 0 && row->f[5] == 1 && row->f[4] == 2);
        REQUIRE(streq(row->s0, "CLOSE_NO_DELIVERY"));
        REQUIRE(
            classify_nwb1(
                row->b0, row->b0_len, ninlil_wifi_session_id, 1, 1u)
            == WIFI_SEQUENCE_REJECT);
        break;
    case 48: /* OUT-OF-ORDER */
        REQUIRE(row->f[3] == 1 && row->f[5] == 2 && row->f[4] == 1);
        REQUIRE(streq(row->s0, "CLOSE_NO_DELIVERY"));
        break;
    case 49: /* WRAP */
        REQUIRE((uint32_t)row->f[2] == UINT32_C(0xfffffffe)
            || row->f[2] == (int32_t)UINT32_C(0xfffffffe));
        REQUIRE(row->f[5] == 0 && row->f[11] == 1);
        REQUIRE(streq(row->s0, "CLEAN_CLOSE_FRESH_HANDSHAKE"));
        break;
    case 50: /* INVALID NFL1 */
        REQUIRE(
            classify_nwb1(
                row->b0, row->b0_len, ninlil_wifi_session_id, 1, 0u)
            == WIFI_INVALID_NFL1);
        REQUIRE(row->f[10] == 0 && row->f[11] == 1);
        break;
    case 51: /* TLS suite */
        REQUIRE(row->f[0] == (int32_t)NINLIL_WIFI_TLS_SUITE_ID);
        REQUIRE(row->f[1] == (int32_t)NINLIL_WIFI_TLS_GROUP_ID);
        REQUIRE(row->f[2] == (int32_t)NINLIL_WIFI_TLS_SIG_ID);
        REQUIRE(streq(row->s0, "OK_EXACT"));
        break;
    case 52: /* X509 roles */
        REQUIRE(row->f[3] == 82 && row->f[4] == 1 && row->f[5] == 2);
        REQUIRE(row->f[6] == 1);
        REQUIRE(row->b0_len == 82u && row->b1_len == 82u);
        REQUIRE(row->b0[1] == 0x01u && row->b1[1] == 0x02u);
        REQUIRE(memcmp(row->b0, row->b1, 82u) != 0);
        break;
    case 53: /* peer context 62 */
        REQUIRE(row->b0_len == (size_t)NINLIL_WIFI_PEER_CONTEXT_LEN);
        REQUIRE(row->b0[28] == 0x01u && row->b0[45] == 0x02u);
        wifi_sha256(row->b0, row->b0_len, digest);
        REQUIRE(memcmp(digest, ninlil_wifi_peer_context_sha256, 32u) == 0);
        REQUIRE(streq(row->s0, "OK"));
        break;
    case 54: /* attached 64 */
        REQUIRE(row->b0_len == (size_t)NINLIL_WIFI_ATTACHED_CONTEXT_LEN);
        REQUIRE(row->f[6] == 1);
        wifi_sha256(row->b0, row->b0_len, digest);
        REQUIRE(memcmp(digest, ninlil_wifi_attached_context_sha256, 32u) == 0);
        break;
    case 55: /* all-zero group */
        REQUIRE(streq(row->s0, "PROFILE_CONDITIONAL"));
        REQUIRE(streq(row->s1, "ALL_ZERO"));
        REQUIRE(row->b0_len == 62u);
        break;
    case 56: /* mixed */
        REQUIRE(streq(row->s0, "REJECT"));
        REQUIRE(streq(row->s1, "MIXED"));
        REQUIRE(row->f[7] == 0);
        break;
    case 57: /* ticket/0rtt */
        REQUIRE(row->f[6] == 0 && row->f[7] == 0 && row->f[8] == 0);
        REQUIRE(row->f[9] == 0 && row->f[10] == 0);
        REQUIRE(streq(row->s0, "FENCED_IF_OBSERVED"));
        break;
    case 58: /* revocation clock */
        REQUIRE(row->f[8] == 1 && row->f[9] == 0);
        REQUIRE(row->f[10] == 300000 && row->f[11] == 1);
        REQUIRE(streq(row->s0, "OK_RULES"));
        break;
    case 59: /* R7 non-authority */
        REQUIRE(row->f[10] == 0 && row->f[11] == 1);
        REQUIRE(streq(row->s0, "NON_AUTHORITY_FOR_WIFI_PROFILE"));
        break;
    case 60: /* Host OpenSSL pin */
        REQUIRE(streq(row->s0, NINLIL_WIFI_HOST_OPENSSL_TAG));
        REQUIRE(streq(row->s1, NINLIL_WIFI_HOST_OPENSSL_PEELED));
        REQUIRE(row->f[11] == 1);
        break;
    case 61: /* ESP mbedTLS pin */
        REQUIRE(streq(row->s0, NINLIL_WIFI_ESP_IDF_COMMIT));
        REQUIRE(streq(row->s1, NINLIL_WIFI_ESP_MBEDTLS_COMMIT));
        REQUIRE(row->f[10] == 1 && row->f[11] == 1);
        break;
    case 62: /* preattach carrier */
        REQUIRE(row->f[0] == 0 && row->f[1] == 1);
        REQUIRE(streq(row->s0, "BOUNDARY_OK"));
        break;
    case 63: /* peer session only */
        REQUIRE(row->f[0] == 0 && row->f[1] == 0);
        REQUIRE(row->f[3] == 0 && row->f[4] == 0);
        REQUIRE(streq(row->s0, "NO_NWB1"));
        REQUIRE(streq(row->s1, "PEER_SESSION"));
        break;
    case 64: /* PA full required */
        REQUIRE(row->f[0] == 1 && row->f[1] == 1 && row->f[5] == 0);
        REQUIRE(streq(row->s0, "OK_POST_ATTACHMENT"));
        REQUIRE(streq(row->s1, "ATTACHED"));
        break;
    case 65: /* ESP capacity */
        REQUIRE(row->f[0] == 1 && row->f[1] == 2 && row->f[3] == 8);
        REQUIRE(row->f[4] == 9 && row->f[8] == 1965);
        REQUIRE(
            NINLIL_WIFI_ESP_TLS_SESSION_INTERNAL
                + NINLIL_WIFI_ESP_TLS_SESSION_PSRAM
            == NINLIL_WIFI_ESP_TLS_SESSION_TOTAL);
        REQUIRE(NINLIL_WIFI_ESP_TLS_SESSION_TOTAL == 98304u);
        REQUIRE(NINLIL_WIFI_ESP_TLS_CRYPTO_GLOBAL_INTERNAL == 65536u);
        REQUIRE(NINLIL_WIFI_ESP_TLS_INTERNAL_FLOOR == 65536u);
        REQUIRE(
            NINLIL_WIFI_ESP_TLS_ORIGINAL_INTERNAL_ONLY_REQUIREMENT
            == 327680u);
        REQUIRE(
            2u * NINLIL_WIFI_ESP_TLS_SESSION_TOTAL
                + NINLIL_WIFI_ESP_TLS_CRYPTO_GLOBAL_INTERNAL
                + NINLIL_WIFI_ESP_TLS_INTERNAL_FLOOR
            == NINLIL_WIFI_ESP_TLS_ORIGINAL_INTERNAL_ONLY_REQUIREMENT);
        REQUIRE(NINLIL_WIFI_ESP_TLS_EXECUTION_STACK == 8192u);
        REQUIRE(
            NINLIL_WIFI_ESP_TLS_CRYPTO_GLOBAL_INTERNAL
                + 2u * NINLIL_WIFI_ESP_TLS_SESSION_INTERNAL
                + NINLIL_WIFI_ESP_TLS_INTERNAL_FLOOR
                + NINLIL_WIFI_ESP_TLS_EXECUTION_STACK
            == NINLIL_WIFI_ESP_TLS_INTERNAL_ENVELOPE);
        REQUIRE(NINLIL_WIFI_ESP_TLS_INTERNAL_ENVELOPE == 163840u);
        REQUIRE(
            NINLIL_WIFI_ESP_TLS_MAP_REMAINDER_OBS
                - NINLIL_WIFI_ESP_TLS_INTERNAL_ENVELOPE
            == NINLIL_WIFI_ESP_TLS_MAP_SLACK_OBS);
        REQUIRE(NINLIL_WIFI_ESP_TLS_MAP_SLACK_OBS == 7985u);
        REQUIRE(NINLIL_WIFI_ESP_TLS_IN_BUFFER == 16685u);
        REQUIRE(NINLIL_WIFI_ESP_TLS_OUT_BUFFER == 4415u);
        REQUIRE(NINLIL_WIFI_ESP_TLS_EXACT_LIVE_REQUIRED == 1u);
        REQUIRE(NINLIL_WIFI_ESP_TLS_INTERIOR_POINTER_ALLOWED == 0u);
        REQUIRE(NINLIL_WIFI_ESP_TLS_FREE_POINTER_ALLOWED == 0u);
        REQUIRE(NINLIL_WIFI_ESP_TLS_WRONG_SIZE_ALLOWED == 0u);
        REQUIRE(NINLIL_WIFI_ESP_TLS_CROSS_OWNER_FREE_ALLOWED == 0u);
        REQUIRE(NINLIL_WIFI_ESP_TLS_CONTRACT_NULL_SPILL_ALLOWED == 0u);
        REQUIRE(NINLIL_WIFI_ESP_TLS_ORDINARY_OOM_GLOBAL_FATAL == 0u);
        REQUIRE(NINLIL_WIFI_ESP_TLS_CANARY_GLOBAL_FATAL == 1u);
        REQUIRE(streq(row->s0, "ESP_BOUNDS"));
        break;
    case 66: /* Host capacity */
        REQUIRE(row->f[0] == 64 && row->f[1] == 64 && row->f[6] == 8);
        REQUIRE(streq(row->s0, "HOST_BOUNDS"));
        break;
    case 67: /* priority */
        REQUIRE(row->f[8] == 0 && row->f[11] == 3);
        REQUIRE(streq(row->s0, "ISOLATED"));
        REQUIRE(streq(
            row->s1, "critical_control,application_data,management_bulk"));
        break;
    case 68: /* retained partial write */
        REQUIRE(row->f[0] == 1 && row->f[1] == 0 && row->f[2] == 1 && row->f[3] == 1);
        REQUIRE(streq(row->s0, "OK"));
        break;
    case 69: /* release semantics */
        REQUIRE(row->f[4] == 1 && row->f[5] == 1);
        REQUIRE(streq(row->s0, "OK"));
        break;
    case 70: /* no false custody */
        REQUIRE(row->f[0] == 0 && row->f[1] == 0 && row->f[2] == 0 && row->f[3] == 0);
        REQUIRE(streq(row->s0, "NO_CUSTODY"));
        break;
    case 71: /* storage arithmetic */
        REQUIRE(row->f[0] == (int32_t)NINLIL_WIFI_NWD1_RECORD_BYTES);
        REQUIRE(row->f[1] == 8);
        REQUIRE(row->f[2] == (int32_t)NINLIL_WIFI_NWD1_COMMITTED_CU);
        REQUIRE(row->f[3] == (int32_t)NINLIL_WIFI_NWD1_STAGING_CU);
        REQUIRE(row->f[2] == row->f[0] * row->f[1]);
        REQUIRE(row->f[3] == row->f[2] * 2);
        REQUIRE(row->f[4] == 0 && row->f[5] == 0 && row->f[6] == 1);
        REQUIRE(streq(row->s0, "ARITHMETIC_OK"));
        break;
    case 72: /* Host role */
        REQUIRE(row->f[0] == 1 && row->f[1] == 1 && row->f[2] == 1 && row->f[3] == 0);
        REQUIRE(streq(row->s0, "HOST_RESPONSIBILITY"));
        REQUIRE(streq(row->s1, "PINNED_OPENSSL_3_5_7_STATIC"));
        break;
    case 73: /* ESP role */
        REQUIRE(row->f[0] == 2 && row->f[3] == 1 && row->f[4] == 1);
        REQUIRE(streq(row->s0, "ESP_RESPONSIBILITY"));
        REQUIRE(streq(row->s1, "ESP_IDF_SUPPLIED_MBEDTLS_DIRECT"));
        break;
    case 74: /* disconnect race */
        REQUIRE(row->f[0] == 1 && row->f[5] == 6);
        REQUIRE(streq(row->s0, "DETERMINISTIC"));
        REQUIRE(streq(
            row->s1,
            "DISCONNECT_EVENT>FENCE_SESSIONS>AVAILABILITY_PLUS_ONE>"
            "CLOSE_SOCKETS>BACKOFF_NOT_BEFORE>RECONNECT_ATTEMPT"));
        break;
    case 75: /* sleep drain */
        REQUIRE(row->f[0] == 1 && row->f[1] == 1 && row->f[2] == 0 && row->f[3] == 1);
        REQUIRE(streq(row->s0, "DETERMINISTIC"));
        break;
    case 76: /* event overflow */
        REQUIRE(row->f[0] == 8 && row->f[1] == 9 && row->f[2] == 0 && row->f[3] == 1);
        REQUIRE(streq(row->s0, "OVERFLOW_FENCE"));
        REQUIRE(streq(row->s1, "FENCED"));
        break;
    case 77: { /* backoff deterministic recompute sample0 */
        uint8_t genbuf[8];
        uint8_t jdigest[32];
        uint32_t jitter;
        REQUIRE(row->f[0] == 1 && row->f[1] == 1);
        REQUIRE(row->f[7] == 32000 && row->f[6] >= 1);
        REQUIRE(row->b0_len == 16u);
        REQUIRE(memcmp(row->b0, ninlil_wifi_instance_id, 16u) == 0);
        REQUIRE(row->f[10] == 1);
        REQUIRE(row->f[8] == 1000);
        wifi_put_u32(genbuf, 0u);
        wifi_put_u32(genbuf + 4, (uint32_t)row->f[10]);
        /* big-endian u64 generation: high 0, low gen */
        genbuf[0] = 0u;
        genbuf[1] = 0u;
        genbuf[2] = 0u;
        genbuf[3] = 0u;
        wifi_put_u32(genbuf + 4, (uint32_t)row->f[10]);
        {
            uint8_t material[24];
            (void)memcpy(material, row->b0, 16u);
            (void)memcpy(material + 16, genbuf, 8u);
            wifi_sha256(material, 24u, jdigest);
        }
        jitter = ((uint32_t)jdigest[0] << 8 | (uint32_t)jdigest[1]) % 1000u;
        REQUIRE(row->f[9] == (int32_t)jitter);
        REQUIRE(row->f[11] == row->f[8] + row->f[9]);
        REQUIRE(streq(row->s0, "DETERMINISTIC"));
        break;
    }
    default:
        REQUIRE(0 && "unknown case index");
        break;
    }
    return 0;
}

static int run_all_cases(void)
{
    size_t index;
    size_t executed = 0u;

    (void)memset(g_executed, 0, sizeof(g_executed));
    REQUIRE(NINLIL_WIFI_ACCEPTANCE_ID_COUNT == 79u);
    for (index = 0u; index < (size_t)NINLIL_WIFI_ACCEPTANCE_ID_COUNT; ++index) {
        REQUIRE(streq(
            ninlil_wifi_cases[index].id, ninlil_wifi_acceptance_ids[index]));
        if (assert_case_index(index, &ninlil_wifi_cases[index]) != 0) {
            return 1;
        }
        /* Mark only after successful substantive assertion. */
        g_executed[index] = 1u;
        executed += 1u;
    }
    REQUIRE(executed == 79u);
    for (index = 0u; index < 79u; ++index) {
        REQUIRE(g_executed[index] == 1u);
    }
    return 0;
}

static int run_donor_self_test(void)
{
    size_t victim;
    size_t donor;
    size_t rejects = 0u;

    g_quiet = 1;
    for (victim = 0u; victim < 79u; ++victim) {
        for (donor = 0u; donor < 79u; ++donor) {
            int failed;
            if (donor == victim) {
                continue;
            }
            /* Same-ID contract (victim index) vs donor body must fail. */
            failed = assert_case_index(victim, &ninlil_wifi_cases[donor]);
            if (failed == 0) {
                g_quiet = 0;
                (void)fprintf(
                    stderr,
                    "donor self-test false-green victim=%zu donor=%zu "
                    "(%s <- %s)\n",
                    victim,
                    donor,
                    ninlil_wifi_acceptance_ids[victim],
                    ninlil_wifi_acceptance_ids[donor]);
                return 1;
            }
            rejects += 1u;
        }
    }
    g_quiet = 0;
    if (rejects != 79u * 78u) {
        return 1;
    }
    (void)printf("wifi_bearer_spec donor_self_test rejects=%zu\n", rejects);
    return 0;
}

int main(void)
{
    if (run_all_cases() != 0) {
        return 1;
    }
    if (run_donor_self_test() != 0) {
        return 1;
    }
    (void)printf(
        "wifi_bearer_spec_vector_test: PASS executed_ids=79 "
        "donor_rejects=%u\n",
        (unsigned)(79u * 78u));
    return 0;
}
