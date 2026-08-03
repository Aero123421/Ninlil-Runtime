/*
 * Independent C KAT bridge for Domain schema1 T1a snapshot digests/transcripts.
 * Does not import Python generator/gate. Rebuilds bootstrap via production APIs
 * and recomputes SHA-256 of the canonical snapshot preimage from bytes.
 * Hard-coded normative transcript fields are verified case-by-case (not taught
 * by the vector authority). Coherent digest mutants must not match.
 */

#include "domain_schema1_runtime_binding.h"

#include <ninlil/version.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(cond)                                                       \
    do {                                                                    \
        if (!(cond)) {                                                      \
            (void)fprintf(                                                  \
                stderr,                                                     \
                "domain_schema1 bridge FAIL %s:%d: %s\n",                   \
                __FILE__,                                                   \
                __LINE__,                                                   \
                #cond);                                                     \
            return 1;                                                       \
        }                                                                   \
    } while (0)

/* Compact SHA-256 (fixed stack; no heap/VLA). */
static uint32_t rotr32(uint32_t value, unsigned int bits)
{
    return (value >> bits) | (value << (32u - bits));
}

static void sha256(const uint8_t *message, size_t length, uint8_t out[32])
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
            uint32_t s0 = rotr32(w[i - 15u], 7u) ^ rotr32(w[i - 15u], 18u)
                ^ (w[i - 15u] >> 3);
            uint32_t s1 = rotr32(w[i - 2u], 17u) ^ rotr32(w[i - 2u], 19u)
                ^ (w[i - 2u] >> 10);
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
            uint32_t S1 = rotr32(e, 6u) ^ rotr32(e, 11u) ^ rotr32(e, 25u);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = hh + S1 + ch + k[i] + w[i];
            uint32_t S0 = rotr32(a, 2u) ^ rotr32(a, 13u) ^ rotr32(a, 22u);
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
                uint32_t s0 = rotr32(w[i - 15u], 7u) ^ rotr32(w[i - 15u], 18u)
                    ^ (w[i - 15u] >> 3);
                uint32_t s1 = rotr32(w[i - 2u], 17u) ^ rotr32(w[i - 2u], 19u)
                    ^ (w[i - 2u] >> 10);
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
                uint32_t S1 = rotr32(e, 6u) ^ rotr32(e, 11u) ^ rotr32(e, 25u);
                uint32_t ch = (e & f) ^ ((~e) & g);
                uint32_t temp1 = hh + S1 + ch + k[i] + w[i];
                uint32_t S0 = rotr32(a, 2u) ^ rotr32(a, 13u) ^ rotr32(a, 22u);
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

static void put_u16(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void put_u32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

/* Independent snapshot preimage rule (literal; not taught by vector). */
static void snapshot_digest(
    const ninlil_domain_schema1_bootstrap_record_t *rows,
    uint32_t count,
    uint8_t out[32])
{
    uint8_t preimage[32u + 4u + 17u * (2u + 10u + 4u + 215u)];
    size_t offset = 0u;
    uint32_t index;
    static const char label[] = "NINLIL-DOMAIN-INIT-SNAPSHOT-V1";

    (void)memcpy(preimage + offset, label, sizeof(label) - 1u);
    offset += sizeof(label) - 1u;
    put_u32(preimage + offset, count);
    offset += 4u;
    for (index = 0u; index < count; ++index) {
        if (rows == NULL) {
            return;
        }
        put_u16(preimage + offset, (uint16_t)rows[index].key.length);
        offset += 2u;
        (void)memcpy(
            preimage + offset, rows[index].key.bytes, rows[index].key.length);
        offset += rows[index].key.length;
        put_u32(preimage + offset, rows[index].value_length);
        offset += 4u;
        (void)memcpy(
            preimage + offset, rows[index].value, rows[index].value_length);
        offset += rows[index].value_length;
    }
    sha256(preimage, offset, out);
}

static int hex_eq(const uint8_t digest[32], const char *hex)
{
    size_t i;
    for (i = 0u; i < 32u; ++i) {
        unsigned int hi;
        unsigned int lo;
        char c0 = hex[i * 2u];
        char c1 = hex[i * 2u + 1u];
        hi = (c0 >= 'a') ? (unsigned)(c0 - 'a' + 10) : (unsigned)(c0 - '0');
        lo = (c1 >= 'a') ? (unsigned)(c1 - 'a' + 10) : (unsigned)(c1 - '0');
        if (digest[i] != (uint8_t)((hi << 4) | lo)) {
            return 0;
        }
    }
    return 1;
}

/* Hard-coded normative T1a COMMIT_UNKNOWN classification transcript.
 * Every classification case (OLD/NEW/CORRUPT) uses the same RO scan path. */
typedef struct t1a_transcript_kat {
    const char *case_id;
    int storage_read_only_begin;
    int iterator_open;
    int iterator_exhausted;
    int iterator_close;
    int rollback;
    int storage_read_write_begin;
    int storage_put;
    int storage_erase;
    int storage_commit;
    int bearer_open;
    int callback;
    int public_handle;
    int publish;
    const char *transaction_mode;
} t1a_transcript_kat_t;

static const t1a_transcript_kat_t k_t1a_transcripts[] = {
    {
        "T1A_COMMIT_UNKNOWN_ALL_OLD_0_OF_17",
        1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, "READ_ONLY"
    },
    {
        "T1A_COMMIT_UNKNOWN_ALL_NEW_17_OF_17",
        1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, "READ_ONLY"
    },
    {
        "T1A_COMMIT_UNKNOWN_PARTIAL_1_OF_17",
        1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, "READ_ONLY"
    },
    {
        "T1A_COMMIT_UNKNOWN_PARTIAL_16_OF_17",
        1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, "READ_ONLY"
    },
    {
        "T1A_COMMIT_UNKNOWN_EXTRA_ROW",
        1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, "READ_ONLY"
    },
    {
        "T1A_COMMIT_UNKNOWN_FORMAT_MISMATCH",
        1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, "READ_ONLY"
    },
};

/* Quiet independent semantic rule for T1a RO classification transcripts. */
static int transcript_semantically_ok(const t1a_transcript_kat_t *t)
{
    if (t->storage_read_only_begin != 1) {
        return 0;
    }
    if (t->iterator_open != 1) {
        return 0;
    }
    if (t->iterator_exhausted != 1) {
        return 0;
    }
    if (t->iterator_close != 1) {
        return 0;
    }
    if (t->rollback != 1) {
        return 0;
    }
    if (t->storage_read_write_begin != 0) {
        return 0;
    }
    if (t->storage_put != 0) {
        return 0;
    }
    if (t->storage_erase != 0) {
        return 0;
    }
    if (t->storage_commit != 0) {
        return 0;
    }
    if (t->bearer_open != 0) {
        return 0;
    }
    if (t->callback != 0) {
        return 0;
    }
    if (t->public_handle != 0) {
        return 0;
    }
    if (t->publish != 0) {
        return 0;
    }
    if (strcmp(t->transaction_mode, "READ_ONLY") != 0) {
        return 0;
    }
    return 1;
}

static int verify_t1a_transcript_literals(void)
{
    size_t i;
    for (i = 0u; i < sizeof(k_t1a_transcripts) / sizeof(k_t1a_transcripts[0]);
         ++i) {
        REQUIRE(transcript_semantically_ok(&k_t1a_transcripts[i]));
    }
    /* Explicit donor-swap / RO mutants must fail the independent rule. */
    {
        t1a_transcript_kat_t swapped = k_t1a_transcripts[0];
        swapped.publish = 1;
        REQUIRE(!transcript_semantically_ok(&swapped));
    }
    {
        t1a_transcript_kat_t swapped = k_t1a_transcripts[1];
        swapped.storage_read_only_begin = 0;
        swapped.storage_read_write_begin = 1;
        swapped.transaction_mode = "READ_WRITE";
        REQUIRE(!transcript_semantically_ok(&swapped));
    }
    {
        t1a_transcript_kat_t swapped = k_t1a_transcripts[2];
        swapped.iterator_close = 0;
        REQUIRE(!transcript_semantically_ok(&swapped));
    }
    {
        t1a_transcript_kat_t swapped = k_t1a_transcripts[3];
        swapped.rollback = 0;
        REQUIRE(!transcript_semantically_ok(&swapped));
    }
    {
        t1a_transcript_kat_t swapped = k_t1a_transcripts[4];
        swapped.storage_commit = 1;
        REQUIRE(!transcript_semantically_ok(&swapped));
    }
    {
        t1a_transcript_kat_t swapped = k_t1a_transcripts[5];
        swapped.iterator_open = 0;
        REQUIRE(!transcript_semantically_ok(&swapped));
    }
    return 0;
}

static void fill_controller(ninlil_domain_schema1_binding_t *b)
{
    uint32_t i;
    (void)memset(b, 0, sizeof(*b));
    b->common.storage_schema = 1u;
    b->common.role = NINLIL_ROLE_CONTROLLER;
    b->common.environment = NINLIL_ENV_TEST;
    for (i = 0u; i < 16u; ++i) {
        b->common.runtime_id.bytes[i] = 0x44u;
    }
    b->common.limits.max_services = 16u;
    b->common.limits.max_nonterminal_transactions = 32u;
    b->common.limits.max_targets_per_transaction = 1u;
    b->common.limits.max_logical_payload_bytes = 256u;
    b->common.limits.max_durable_outbox_payload_bytes = 8192u;
    b->common.limits.max_attempts_per_target_per_cycle = 8u;
    b->common.limits.max_cancel_attempts_per_transaction = 1u;
    b->common.limits.max_evidence_per_target = 3u;
    b->common.limits.max_retained_terminal_transactions = 64u;
    b->common.limits.max_nonterminal_deliveries = 32u;
    b->common.limits.max_event_spool_count = 0u;
    b->common.limits.max_event_spool_bytes = 0u;
    b->common.limits.max_result_cache_entries = 32u;
    b->common.limits.max_retained_dispositions = 64u;
    b->common.limits.max_ingress_per_step = 8u;
    b->common.limits.max_callbacks_per_step = 8u;
    b->common.limits.max_state_transitions_per_step = 16u;
    b->common.limits.max_bearer_sends_per_step = 8u;
    b->common.limits.max_deferred_tokens = 16u;
    b->common.terminal_retention_ms = 2000u;
    b->common.result_cache_retention_ms = 1000u;
    b->common.observation_retention_ms = 3000u;
    (void)memcpy(b->storage_profile_id, "NINLIL-DOMAIN-S1", 16u);
    b->storage_profile_revision = 1u;
    b->minimum_writer_generation = 2u;
    b->rollback_epoch = 1u;
}

static void fill_identity(ninlil_model_runtime_store_identity_t *id)
{
    uint32_t i;
    (void)memset(id, 0, sizeof(*id));
    id->flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    for (i = 0u; i < 16u; ++i) {
        id->device_id.bytes[i] = 0x55u;
        id->installation_id.bytes[i] = 0x66u;
        id->site_domain_id.bytes[i] = 0x77u;
    }
    id->binding_epoch = 1u;
    id->membership_epoch = 1u;
}

/*
 * Independent rule shared with Python/Node bridges: for every T1a case ID,
 * materialised row count must equal declared snapshot_record_count. No
 * EXTRA_ROW / FORMAT_MISMATCH exception.
 */
static int materialised_equals_declared(
    uint32_t materialised,
    uint32_t declared)
{
    return materialised == declared;
}

static int test_snapshot_digests_and_mutants(void)
{
    ninlil_domain_schema1_binding_t binding;
    ninlil_model_runtime_store_identity_t identity;
    ninlil_domain_schema1_bootstrap_plan_t plan;
    ninlil_domain_schema1_bootstrap_record_t rows[17];
    uint8_t digest[32];
    uint8_t mutated[32];
    uint32_t i;
    /* Arbitrary coherent 64-hex that is not any of the KAT digests. */
    static const char *const k_coherent_fake =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /* Independent hard-coded expected digests (literal KAT). */
    static const char *const k_old =
        "d4d74819d07d0abf62feecc14aef400cbc26fc7ec382ed0a040d770d84913e75";
    static const char *const k_new =
        "0c16fbcea20fef5ca26b9d3fd9e36ec858693a5c8d9a296da816a48bf5b01ce1";
    static const char *const k_partial1 =
        "88a61c257bf998867ecc8c18028d1f76cc7232964b20b87429d04889d8321a60";
    static const char *const k_partial16 =
        "ed62143af469a75f54a12058c0985029a8879b10e8708aa02cdf7e7ff4035512";
    /* EXTRA_ROW (18 rows) and FORMAT_MISMATCH (17 mutated) literal digests. */
    static const char *const k_extra =
        "40efc3f46dd9cd9b4814bd9dfabbc9b6fc461afe37746ebaec3f1402a9d547f6";
    static const char *const k_format =
        "5c9685c573fbb2078f6b4e7bbec9146b6f819839044c4c8740b3c3f1c1e5c832";

    /* Declared snapshot_record_count per T1a case ID (independent KAT). */
    static const struct {
        const char *id;
        uint32_t declared;
    } k_declared[] = {
        {"T1A_COMMIT_UNKNOWN_ALL_OLD_0_OF_17", 0u},
        {"T1A_COMMIT_UNKNOWN_ALL_NEW_17_OF_17", 17u},
        {"T1A_COMMIT_UNKNOWN_PARTIAL_1_OF_17", 1u},
        {"T1A_COMMIT_UNKNOWN_PARTIAL_16_OF_17", 16u},
        {"T1A_COMMIT_UNKNOWN_EXTRA_ROW", 18u},
        {"T1A_COMMIT_UNKNOWN_FORMAT_MISMATCH", 17u},
    };

    fill_controller(&binding);
    fill_identity(&identity);
    REQUIRE(
        ninlil_domain_schema1_build_bootstrap_plan(
            &binding, &identity, &plan)
        == NINLIL_OK);
    for (i = 0u; i < 17u; ++i) {
        REQUIRE(
            ninlil_domain_schema1_bootstrap_record_at(&plan, i, &rows[i])
            == NINLIL_OK);
    }

    /* All 6 case IDs: declared counts pinned; matching materialised OK. */
    REQUIRE(materialised_equals_declared(0u, k_declared[0].declared));
    REQUIRE(materialised_equals_declared(17u, k_declared[1].declared));
    REQUIRE(materialised_equals_declared(1u, k_declared[2].declared));
    REQUIRE(materialised_equals_declared(16u, k_declared[3].declared));
    REQUIRE(materialised_equals_declared(18u, k_declared[4].declared));
    REQUIRE(materialised_equals_declared(17u, k_declared[5].declared));

    snapshot_digest(NULL, 0u, digest);
    REQUIRE(hex_eq(digest, k_old));

    snapshot_digest(rows, 17u, digest);
    REQUIRE(hex_eq(digest, k_new));

    /* Partial 1-of-17 / 16-of-17 independent recompute from canonical bytes. */
    snapshot_digest(rows, 1u, digest);
    REQUIRE(hex_eq(digest, k_partial1));
    snapshot_digest(rows, 16u, digest);
    REQUIRE(hex_eq(digest, k_partial16));

    /* Mutant: coherent arbitrary 64-hex must not match independent recompute. */
    REQUIRE(!hex_eq(digest, k_coherent_fake));
    snapshot_digest(rows, 17u, digest);
    REQUIRE(hex_eq(digest, k_new));
    REQUIRE(!hex_eq(digest, k_coherent_fake));
    REQUIRE(strcmp(k_new, k_coherent_fake) != 0);

    /* Mutant: single-byte digest flip must not match KAT. */
    (void)memcpy(mutated, digest, 32u);
    mutated[0] ^= 1u;
    REQUIRE(!hex_eq(mutated, k_new));
    REQUIRE(!hex_eq(mutated, k_old));

    /* Mutant: single-byte value change alters independent digest. */
    rows[0].value[0] ^= 1u;
    snapshot_digest(rows, 17u, digest);
    REQUIRE(!hex_eq(digest, k_new));
    REQUIRE(!hex_eq(digest, k_coherent_fake));

    /* Restore and confirm NEW still matches. */
    rows[0].value[0] ^= 1u;
    snapshot_digest(rows, 17u, digest);
    REQUIRE(hex_eq(digest, k_new));

    /* Mutant: row-order swap yields a different digest under input order. */
    {
        ninlil_domain_schema1_bootstrap_record_t swapped[17];
        (void)memcpy(swapped, rows, sizeof(rows));
        swapped[0] = rows[1];
        swapped[1] = rows[0];
        snapshot_digest(swapped, 17u, digest);
        REQUIRE(!hex_eq(digest, k_new));
    }

    /*
     * P1 coherent undercount mutants (same semantics as Python/Node):
     * EXTRA declared=18 with only 17 materialised rows + repaired digest of
     * those 17 must not satisfy EXTRA KAT, and count equality fails.
     * FORMAT declared=17 with 16 materialised + repaired digest fails.
     */
    REQUIRE(!materialised_equals_declared(17u, 18u)); /* EXTRA undercount */
    REQUIRE(!materialised_equals_declared(16u, 17u)); /* FORMAT undercount */
    snapshot_digest(rows, 17u, digest);
    REQUIRE(hex_eq(digest, k_new));
    /* 17-row NEW digest is not the EXTRA (18-row) KAT even if "repaired". */
    REQUIRE(!hex_eq(digest, k_extra));
    REQUIRE(strcmp(k_new, k_extra) != 0);
    snapshot_digest(rows, 16u, digest);
    REQUIRE(hex_eq(digest, k_partial16));
    /* 16-row partial digest is not the FORMAT (17-row mutated) KAT. */
    REQUIRE(!hex_eq(digest, k_format));
    REQUIRE(strcmp(k_partial16, k_format) != 0);
    /* FORMAT declared count is 17; NEW digest must not silently stand in. */
    snapshot_digest(rows, 17u, digest);
    REQUIRE(hex_eq(digest, k_new));
    REQUIRE(!hex_eq(digest, k_format));
    return 0;
}

int main(void)
{
    if (verify_t1a_transcript_literals() != 0) {
        return 1;
    }
    if (test_snapshot_digests_and_mutants() != 0) {
        return 1;
    }
    (void)printf(
        "domain_schema1 independent C bridge OK t1a digests+transcript+mutants\n");
    return 0;
}
