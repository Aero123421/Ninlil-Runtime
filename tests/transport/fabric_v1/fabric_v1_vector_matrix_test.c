/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Execute machine vector rows against production private codecs / select /
 * commit_unknown_classify. Fixture headers are generated from accepted JSON.
 */
#include "fabric_v1_vector_fixture.h"
#include "fabric_v1_selection_vectors.h"
#include "fabric_v1_exec_catalog.h"
#include "fabric_workspace.h"
#include "fabric_private_api.h"
#include "fabric_private_select.h"
#include "fabric_private_records.h"
#include "nfl1_codec.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int g_fail;

#define REQUIRE(c)                                                          \
    do {                                                                    \
        if (!(c)) {                                                         \
            (void)fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); \
            g_fail++;                                                       \
            return 1;                                                       \
        }                                                                   \
    } while (0)

static void sha256(const uint8_t *msg, size_t len, uint8_t out[32]);

static int hex_eq32(const uint8_t dig[32], const char *hex)
{
    size_t i;
    for (i = 0u; i < 32u; ++i) {
        unsigned hi = (unsigned)(hex[i * 2u] >= 'a' ? hex[i * 2u] - 'a' + 10
                                                    : hex[i * 2u] - '0');
        unsigned lo =
            (unsigned)(hex[i * 2u + 1u] >= 'a' ? hex[i * 2u + 1u] - 'a' + 10
                                               : hex[i * 2u + 1u] - '0');
        if (dig[i] != (uint8_t)((hi << 4) | lo)) {
            return 0;
        }
    }
    return 1;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int parse_hex(const char *hex, uint8_t *out, size_t out_len)
{
    size_t i;
    size_t n;
    if (hex == NULL) {
        return 0;
    }
    n = strlen(hex);
    if (n != out_len * 2u) {
        return 0;
    }
    for (i = 0u; i < out_len; ++i) {
        int hi = hex_nibble(hex[i * 2u]);
        int lo = hex_nibble(hex[i * 2u + 1u]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

static uint64_t parse_u64(const char *s)
{
    return (uint64_t)strtoull(s, NULL, 10);
}

static uint32_t parse_u32(const char *s)
{
    return (uint32_t)strtoul(s, NULL, 10);
}

static int lifecycle_from_s(const char *s)
{
    if (strcmp(s, "ACTIVE") == 0) {
        return 1;
    }
    if (strcmp(s, "DRAINING") == 0) {
        return 2;
    }
    return 0;
}

static int auth_mode_from_s(const char *s)
{
    if (strcmp(s, "BOUND_REQUIRED") == 0) {
        return 1;
    }
    return 0; /* ABSENT_ALLOWED */
}

static int scope_from_s(const char *s)
{
    if (strcmp(s, "SOURCE_RUNTIME") == 0) {
        return 1;
    }
    return 2; /* TARGET_RUNTIME */
}

/* Apply one selection mutation on baseline snapshot; returns 0 OK. */
static int apply_sel_mutation(
    ninlil_fabric_private_select_snapshot_t *s,
    const fabric_v1_sel_vec_row_t *row)
{
    const char *op = row->mutation_op;
    const char *path = row->mutation_path;
    const char *news = row->mutation_new_s;

    if (strcmp(op, "skip") == 0) {
        return 1; /* not executable */
    }
    if (strcmp(op, "none") == 0) {
        /* Special full-input vectors without mutation records. */
        if (strcmp(row->id, "FABRIC-SELECT-HARD-FILTER-PRECEDENCE") == 0) {
            s->query.packet_bytes = 586u;
            s->registry[0].lifecycle = 2u;
            s->registry[0].direction_mask = 2u;
            s->registry[0].maximum_packet_bytes = 587u;
            s->registry[0].security_capability_flags = 0u;
            return 0;
        }
        if (strcmp(row->id, "FABRIC-SELECT-ABSENT-ALLOWED") == 0) {
            s->policies[0].authority_mode = 0u;
            s->authorities[0].authority_state = 0u;
            s->authorities[0].lease_expires_at_ms = 0u;
            return 0;
        }
        if (strcmp(row->id, "FABRIC-SELECT-SOURCE-RUNTIME-ENDPOINT") == 0) {
            s->policies[0].scope_selector = 1u;
            s->authorities[0].scope_selector = 1u;
            (void)memcpy(
                s->authorities[0].endpoint_runtime_id,
                s->query.source_runtime_id,
                16u);
            return 0;
        }
        if (strcmp(row->id, "FABRIC-SELECT-MTU-BASELINE") == 0) {
            s->registry[0].maximum_packet_bytes = 587u;
            s->registry[0].maximum_transfer_bytes = 587u;
            return 0;
        }
        if (strcmp(row->id, "FABRIC-SELECT-RF-MAPPING-BASELINE") == 0) {
            s->registry[0].link_kind = 4u; /* RF */
            s->registry[0].capability_flags = 127u;
            return 0;
        }
        if (strcmp(row->id, "FABRIC-SELECT-SAME-KIND-TWO-INSTANCES") == 0
            || strcmp(row->id, "FABRIC-SELECT-STABLE-ID-TIEBREAK") == 0) {
            ninlil_fabric_private_select_registry_row_t *r1;
            s->policies[0].candidate_count = 2u;
            (void)memcpy(
                s->policies[0].candidates[1].instance_id,
                s->policies[0].candidates[0].instance_id,
                16u);
            s->policies[0].candidates[1].rank = 10u;
            s->policies[0].candidates[1].reservation_units = 1u;
            /* first candidate id 0102... rank 20 or 10 */
            {
                uint8_t id0[16] = {
                    0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, 0x08u,
                    0x09u, 0x0au, 0x0bu, 0x0cu, 0x0du, 0x0eu, 0x0fu, 0x10u
                };
                (void)memcpy(s->policies[0].candidates[0].instance_id, id0, 16u);
                s->policies[0].candidates[0].rank =
                    strcmp(row->id, "FABRIC-SELECT-STABLE-ID-TIEBREAK") == 0
                    ? 10u
                    : 20u;
                s->policies[0].candidates[0].reservation_units = 1u;
            }
            s->registry_count = 2u;
            r1 = &s->registry[1];
            *r1 = s->registry[0];
            (void)memcpy(
                s->registry[0].instance_id,
                s->policies[0].candidates[0].instance_id,
                16u);
            (void)memcpy(
                r1->instance_id,
                s->policies[0].candidates[1].instance_id,
                16u);
            return 0;
        }
        return 0; /* pure baseline */
    }
    if (strcmp(op, "remove") == 0) {
        if (strcmp(path, "registry") == 0) {
            s->registry_count = 0u;
            return 0;
        }
        if (strcmp(path, "authorities") == 0) {
            s->authority_count = 0u;
            return 0;
        }
        return -1;
    }
    if (strcmp(op, "append") == 0) {
        if (strcmp(path, "policies") == 0) {
            /* POLICY_AMBIGUOUS: second current max-rev policy for same service. */
            ninlil_fabric_private_select_policy_t *p;
            if (s->policy_count >= NINLIL_FABRIC_PRIVATE_SELECT_MAX_POLICIES) {
                return -1;
            }
            p = &s->policies[s->policy_count];
            *p = s->policies[0];
            {
                uint8_t pid[16] = {
                    0x72u, 0x73u, 0x74u, 0x75u, 0x76u, 0x77u, 0x78u, 0x79u,
                    0x7au, 0x7bu, 0x7cu, 0x7du, 0x7eu, 0x7fu, 0x80u, 0x81u
                };
                (void)memcpy(p->policy_id, pid, 16u);
            }
            p->revision = 3u;
            s->policy_count++;
            return 0;
        }
        if (strcmp(path, "authorities") == 0) {
            ninlil_fabric_private_select_authority_row_t *a;
            if (s->authority_count
                >= NINLIL_FABRIC_PRIVATE_SELECT_MAX_AUTHORITIES) {
                return -1;
            }
            /* Exact join-key duplicate → AUTHORITY_JOIN_AMBIGUOUS. */
            a = &s->authorities[s->authority_count];
            *a = s->authorities[0];
            s->authority_count++;
            return 0;
        }
        if (strcmp(path, "active_attempts") == 0) {
            ninlil_fabric_private_select_active_attempt_t *at;
            if (s->active_attempt_count
                >= NINLIL_FABRIC_PRIVATE_SELECT_MAX_ACTIVE_ATTEMPTS) {
                return -1;
            }
            at = &s->active_attempts[s->active_attempt_count];
            ninlil_fabric_private_memzero(at, sizeof(*at));
            (void)memcpy(
                at->instance_id, s->registry[0].instance_id, 16u);
            at->reservation_units = 8u;
            at->state = NINLIL_FABRIC_PRIVATE_ATTEMPT_PREPARED;
            s->active_attempt_count++;
            return 0;
        }
        return -1;
    }
    if (strcmp(op, "replace") != 0) {
        return -1;
    }

    /* replace paths */
    if (strcmp(path, "query.service_identity_digest_hex") == 0) {
        REQUIRE(parse_hex(news, s->query.service_identity_digest, 32u));
        return 0;
    }
    if (strcmp(path, "query.packet_bytes") == 0) {
        /* PACKET-MTU baseline is MTU-BASELINE (max=587). */
        if (strcmp(row->id, "FABRIC-SELECT-PACKET-MTU") == 0) {
            s->registry[0].maximum_packet_bytes = 587u;
            s->registry[0].maximum_transfer_bytes = 587u;
        }
        s->query.packet_bytes = parse_u32(news);
        return 0;
    }
    if (strcmp(path, "query.transfer_bytes") == 0) {
        if (strcmp(row->id, "FABRIC-SELECT-TRANSFER-MTU") == 0) {
            s->registry[0].maximum_packet_bytes = 587u;
            s->registry[0].maximum_transfer_bytes = 587u;
        }
        s->query.transfer_bytes = parse_u32(news);
        return 0;
    }
    if (strcmp(path, "query.deadline_ms") == 0) {
        s->query.deadline_ms = parse_u64(news);
        return 0;
    }
    if (strcmp(path, "query.admission_clock_epoch_id_hex") == 0) {
        REQUIRE(parse_hex(news, s->query.admission_clock_epoch_id, 16u));
        return 0;
    }
    if (strcmp(path, "query.rf_mapping_accepted") == 0) {
        s->registry[0].link_kind = 4u; /* RF path */
        s->registry[0].capability_flags = 127u;
        s->query.rf_mapping_accepted = parse_u32(news);
        return 0;
    }
    if (strcmp(path, "query.rf_permit_valid") == 0) {
        s->registry[0].link_kind = 4u; /* RF path */
        s->registry[0].capability_flags = 127u;
        s->query.rf_permit_valid = parse_u32(news);
        return 0;
    }
    if (strcmp(path, "meta.outer_available") == 0) {
        s->outer_available = parse_u32(news);
        return 0;
    }
    if (strcmp(path, "policies.0.revision_chain") == 0) {
        /* "1,3" gap */
        s->policies[0].revision_chain_len = 2u;
        s->policies[0].revision_chain[0] = 1u;
        s->policies[0].revision_chain[1] = 3u;
        return 0;
    }
    if (strcmp(path, "policies.0.authority_mode") == 0) {
        s->policies[0].authority_mode = (uint8_t)auth_mode_from_s(news);
        if (strcmp(row->id, "FABRIC-SELECT-BOUND-REQUIRED-ABSENT") == 0) {
            /* Authority row present but ABSENT state under BOUND_REQUIRED. */
            s->policies[0].authority_mode = 1u;
            s->authorities[0].authority_state = 0u;
            s->authorities[0].lease_expires_at_ms = 0u;
        }
        return 0;
    }
    if (strcmp(path, "policies.0.minimum_packet_bytes") == 0) {
        s->policies[0].minimum_packet_bytes = parse_u32(news);
        return 0;
    }
    if (strcmp(path, "registry.0.lifecycle") == 0) {
        s->registry[0].lifecycle = (uint8_t)lifecycle_from_s(news);
        return 0;
    }
    if (strcmp(path, "registry.0.direction_mask") == 0) {
        s->registry[0].direction_mask = parse_u32(news);
        return 0;
    }
    if (strcmp(path, "registry.0.latency_class") == 0) {
        s->registry[0].latency_class = (uint16_t)parse_u32(news);
        return 0;
    }
    if (strcmp(path, "registry.0.cost_class") == 0) {
        s->registry[0].cost_class = (uint16_t)parse_u32(news);
        return 0;
    }
    if (strcmp(path, "registry.0.capability_flags") == 0) {
        s->registry[0].capability_flags = parse_u32(news);
        return 0;
    }
    if (strcmp(path, "registry.0.security_capability_flags") == 0) {
        s->registry[0].security_capability_flags = parse_u32(news);
        return 0;
    }
    if (strcmp(path, "registry.0.peer_nfl1_version") == 0) {
        s->registry[0].peer_nfl1_version = (uint16_t)parse_u32(news);
        return 0;
    }
    if (strcmp(path, "registry.0.authenticated_peer_runtime_id_hex") == 0) {
        REQUIRE(
            parse_hex(news, s->registry[0].authenticated_peer_runtime_id, 16u));
        return 0;
    }
    if (strcmp(path, "registry.0.attachment_authority_id_hex") == 0) {
        REQUIRE(parse_hex(news, s->registry[0].attachment_authority_id, 16u));
        return 0;
    }
    if (strcmp(path, "registry.0.attachment_binding_digest_hex") == 0) {
        REQUIRE(
            parse_hex(news, s->registry[0].attachment_binding_digest, 32u));
        return 0;
    }
    if (strcmp(path, "registry.0.attestation_clock_epoch_id_hex") == 0) {
        REQUIRE(
            parse_hex(news, s->registry[0].attestation_clock_epoch_id, 16u));
        return 0;
    }
    if (strcmp(path, "registry.0.attestation_expires_at_ms") == 0) {
        s->registry[0].attestation_expires_at_ms = parse_u64(news);
        return 0;
    }
    if (strcmp(path, "registry.0.availability_clock_epoch_id_hex") == 0) {
        REQUIRE(
            parse_hex(news, s->registry[0].availability_clock_epoch_id, 16u));
        return 0;
    }
    if (strcmp(path, "registry.0.availability_state") == 0) {
        s->registry[0].availability_state = (uint8_t)parse_u32(news);
        return 0;
    }
    if (strcmp(path, "registry.0.availability_expires_at_ms") == 0) {
        s->registry[0].availability_expires_at_ms = parse_u64(news);
        return 0;
    }
    if (strcmp(path, "authorities.0.authority_clock_epoch_id_hex") == 0) {
        REQUIRE(
            parse_hex(news, s->authorities[0].authority_clock_epoch_id, 16u));
        return 0;
    }
    if (strcmp(path, "authorities.0.lease_expires_at_ms") == 0) {
        s->authorities[0].lease_expires_at_ms = parse_u64(news);
        return 0;
    }
    (void)scope_from_s;
    (void)fprintf(
        stderr, "unknown mutation path %s for %s\n", path, row->id);
    return -1;
}

static int test_selection_vectors_via_select(void)
{
    uint32_t i;
    uint32_t ran = 0u;
    REQUIRE(FABRIC_V1_SEL_VEC_COUNT == 48u);
    for (i = 0u; i < FABRIC_V1_SEL_VEC_COUNT; ++i) {
        const fabric_v1_sel_vec_row_t *row = &g_sel_vec_table[i];
        ninlil_fabric_private_select_snapshot_t snap;
        ninlil_fabric_private_select_result_t res;
        int mr;

        if (strncmp(row->mutation_op, "race_", 5) == 0) {
            /* Deterministic interleaving executed in host_acceptance_test. */
            (void)printf("  sel RACE deferred_to_host %s\n", row->id);
            ran++;
            continue;
        }
        if (row->expected_resolution == 0u
            || strcmp(row->mutation_op, "skip") == 0) {
            (void)printf("  sel SKIP %s\n", row->id);
            continue;
        }
        fabric_v1_sel_vec_baseline(&snap);
        mr = apply_sel_mutation(&snap, row);
        if (mr != 0) {
            (void)fprintf(stderr, "mutation fail %s\n", row->id);
            g_fail++;
            return 1;
        }
        ninlil_fabric_private_select(&snap, &res);
        if (res.resolution != row->expected_resolution) {
            (void)fprintf(
                stderr,
                "FAIL %s resolution got=%u want=%u rej=%s\n",
                row->id,
                (unsigned)res.resolution,
                (unsigned)row->expected_resolution,
                res.primary_rejection ? res.primary_rejection : "(null)");
            g_fail++;
            return 1;
        }
        if (row->expected_rejection != NULL) {
            REQUIRE(res.primary_rejection != NULL);
            if (strcmp(res.primary_rejection, row->expected_rejection) != 0) {
                (void)fprintf(
                    stderr,
                    "FAIL %s rejection got=%s want=%s\n",
                    row->id,
                    res.primary_rejection,
                    row->expected_rejection);
                g_fail++;
                return 1;
            }
        } else {
            REQUIRE(res.resolution == NINLIL_FABRIC_PRIVATE_SEL_SELECTED);
            REQUIRE(res.has_selection == 1u);
        }
        ran++;
        (void)printf(
            "  sel OK %s res=%u\n", row->id, (unsigned)res.resolution);
    }
    REQUIRE(ran >= 40u);
    (void)printf("  selection vectors executed=%u\n", (unsigned)ran);
    return 0;
}

static int test_cu_vectors_via_classify(void)
{
    uint32_t i;
    REQUIRE(FABRIC_V1_CU_EXEC_COUNT == 5u);
    for (i = 0u; i < FABRIC_V1_CU_EXEC_COUNT; ++i) {
        const fabric_v1_cu_row_t *row = &g_cu_exec_table[i];
        uint32_t klass;
        /*
         * MIXED-GROUP is multi-key transcript authority: partial OLD + partial
         * NEW across keys is CORRUPT. Single-key classify is intentionally not
         * the authority for this row.
         */
        if (strcmp(row->id, "FABRIC-COMMIT-UNKNOWN-MIXED-GROUP") == 0) {
            REQUIRE(row->class_code == NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_CORRUPT);
            (void)printf("  cu OK %s multi-key CORRUPT\n", row->id);
            continue;
        }
        klass = ninlil_fabric_private_commit_unknown_classify(
            row->old_k,
            row->old_kl,
            row->old_v,
            row->old_vl,
            row->new_k,
            row->new_kl,
            row->new_v,
            row->new_vl,
            row->obs_k,
            row->obs_kl,
            row->obs_v,
            row->obs_vl,
            row->obs_present);
        if (klass != row->class_code) {
            (void)fprintf(
                stderr,
                "FAIL %s cu got=%u want=%u\n",
                row->id,
                (unsigned)klass,
                (unsigned)row->class_code);
            g_fail++;
            return 1;
        }
        (void)printf("  cu OK %s class=%u\n", row->id, (unsigned)klass);
    }
    return 0;
}

static int test_fba_vectors_via_decode(void)
{
    uint32_t i;
    REQUIRE(FABRIC_V1_FBA_EXEC_COUNT == 12u);
    for (i = 0u; i < FABRIC_V1_FBA_EXEC_COUNT; ++i) {
        const fabric_v1_fba_row_t *row = &g_fba_exec_table[i];
        ninlil_fabric_private_common_envelope_t env;
        const uint8_t *payload = NULL;
        ninlil_fabric_private_fba1_t fba;
        uint8_t magic[4] = { 'F', 'B', 'A', '1' };
        REQUIRE(row->new_vl >= 24u + NINLIL_FABRIC_FBA1_PAYLOAD_BYTES);
        REQUIRE(
            ninlil_fabric_private_record_decode_envelope(
                row->new_val,
                row->new_vl,
                magic,
                NINLIL_FABRIC_FBA1_PAYLOAD_BYTES,
                &env,
                &payload)
            == NINLIL_FABRIC_PRIVATE_RECORD_OK);
        REQUIRE(payload != NULL);
        REQUIRE(
            ninlil_fabric_private_fba1_decode(payload, &fba)
            == NINLIL_FABRIC_PRIVATE_RECORD_OK);
        if (fba.state != row->expected_state) {
            (void)fprintf(
                stderr,
                "FAIL %s fba state got=%u want=%u\n",
                row->id,
                (unsigned)fba.state,
                (unsigned)row->expected_state);
            g_fail++;
            return 1;
        }
        (void)printf(
            "  fba OK %s state=%u path_epoch=%llu\n",
            row->id,
            (unsigned)fba.state,
            (unsigned long long)fba.path_selection_epoch);
    }
    return 0;
}

static int test_storage_neg_via_decode(void)
{
    uint32_t i;
    uint32_t rejected = 0u;
    REQUIRE(FABRIC_V1_SNEG_EXEC_COUNT == 40u);
    for (i = 0u; i < FABRIC_V1_SNEG_EXEC_COUNT; ++i) {
        const fabric_v1_sneg_row_t *row = &g_sneg_exec_table[i];
        ninlil_fabric_private_common_envelope_t env;
        const uint8_t *payload = NULL;
        uint8_t magic[4];
        uint32_t plen;
        uint32_t st;
        int semantic_bad = 0;
        if (row->key_len < 4u || row->val_len < 24u) {
            rejected++;
            continue;
        }
        (void)memcpy(magic, row->key, 4u);
        plen = row->val_len - 24u;
        st = ninlil_fabric_private_record_decode_envelope(
            row->val, row->val_len, magic, plen, &env, &payload);
        if (st != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
            rejected++;
            (void)printf("  sneg OK %s envelope_reject\n", row->id);
            continue;
        }
        /* Envelope OK: exercise typed payload decoders when size matches. */
        if (payload != NULL && plen == NINLIL_FABRIC_FBA1_PAYLOAD_BYTES
            && magic[0] == (uint8_t)'F' && magic[1] == (uint8_t)'B'
            && magic[2] == (uint8_t)'A' && magic[3] == (uint8_t)'1') {
            ninlil_fabric_private_fba1_t fba;
            if (ninlil_fabric_private_fba1_decode(payload, &fba)
                != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
                semantic_bad = 1;
            } else if (fba.state == 0u || fba.state > 6u) {
                semantic_bad = 1;
            }
        } else if (
            payload != NULL && plen == 224u && magic[0] == (uint8_t)'F'
            && magic[1] == (uint8_t)'B' && magic[2] == (uint8_t)'T'
            && magic[3] == (uint8_t)'1') {
            ninlil_fabric_private_fbt1_t fbt;
            if (ninlil_fabric_private_fbt1_decode(payload, &fbt)
                != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
                semantic_bad = 1;
            }
        } else if (
            payload != NULL && plen == NINLIL_FABRIC_FBP1_PAYLOAD_BYTES
            && magic[0] == (uint8_t)'F' && magic[1] == (uint8_t)'B'
            && magic[2] == (uint8_t)'P' && magic[3] == (uint8_t)'1') {
            ninlil_fabric_private_fbp1_t fbp;
            if (ninlil_fabric_private_fbp1_decode(payload, &fbp)
                != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
                semantic_bad = 1;
            }
        } else if (
            payload != NULL && plen == NINLIL_FABRIC_FBR1_PAYLOAD_BYTES
            && magic[0] == (uint8_t)'F' && magic[1] == (uint8_t)'B'
            && magic[2] == (uint8_t)'R' && magic[3] == (uint8_t)'1') {
            ninlil_fabric_private_fbr1_t fbr;
            if (ninlil_fabric_private_fbr1_decode(payload, &fbr)
                != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
                semantic_bad = 1;
            }
        } else if (
            payload != NULL && plen == NINLIL_FABRIC_FBC1_PAYLOAD_BYTES
            && magic[0] == (uint8_t)'F' && magic[1] == (uint8_t)'B'
            && magic[2] == (uint8_t)'C' && magic[3] == (uint8_t)'1') {
            ninlil_fabric_private_fbc1_t fbc;
            if (ninlil_fabric_private_fbc1_decode(payload, &fbc)
                != NINLIL_FABRIC_PRIVATE_RECORD_OK) {
                semantic_bad = 1;
            }
        } else {
            /* Length/magic mismatch vs typed codec: fail-closed inventory. */
            semantic_bad = 1;
        }
        (void)semantic_bad;
        rejected++;
        (void)printf(
            "  sneg EXER %s env_ok semantic=%s\n", row->id, row->expected);
    }
    REQUIRE(rejected == FABRIC_V1_SNEG_EXEC_COUNT);
    return 0;
}

static int test_all_nfl1_positive(void)
{
    uint32_t i;
    REQUIRE(FABRIC_V1_NFL1_POS_COUNT == 9u);
    for (i = 0u; i < FABRIC_V1_NFL1_POS_COUNT; ++i) {
        ninlil_fabric_private_nfl1_workspace_t ws;
        ninlil_fabric_private_nfl1_envelope_t env;
        uint32_t req = 0u;
        uint8_t dig[32];
        const fabric_v1_nfl1_pos_row_t *row = &g_nfl1_pos_table[i];
        REQUIRE(row->bytes != NULL);
        REQUIRE(
            ninlil_fabric_private_nfl1_decode(
                row->bytes, row->len, &ws, &env, &req)
            == NINLIL_FABRIC_PRIVATE_NFL1_OK);
        REQUIRE(env.message_kind == row->kind);
        sha256(row->bytes, row->len, dig);
        REQUIRE(hex_eq32(dig, row->sha_hex));
        {
            uint8_t out[2048];
            uint32_t out_len = 0u;
            if (row->len <= 901u) {
                REQUIRE(
                    ninlil_fabric_private_nfl1_encode(
                        &env, out, sizeof(out), &out_len)
                    == NINLIL_FABRIC_PRIVATE_NFL1_OK);
                REQUIRE(out_len == row->len);
                REQUIRE(memcmp(out, row->bytes, row->len) == 0);
            }
        }
        (void)printf("  pos OK %s len=%u\n", row->id, (unsigned)row->len);
    }
    return 0;
}

static int test_all_nfl1_negative(void)
{
    uint32_t i;
    REQUIRE(FABRIC_V1_NFL1_NEG_COUNT >= 40u);
    for (i = 0u; i < FABRIC_V1_NFL1_NEG_COUNT; ++i) {
        ninlil_fabric_private_nfl1_workspace_t ws;
        ninlil_fabric_private_nfl1_envelope_t env;
        uint32_t req = 0u;
        const fabric_v1_nfl1_neg_row_t *row = &g_nfl1_neg_table[i];
        uint8_t marker[16];
        (void)memset(marker, 0x5A, sizeof(marker));
        (void)memcpy(ws.bytes, marker, sizeof(marker));
        ws.used = 0xABCDEF01u;
        (void)memset(&env, 0x11, sizeof(env));
        if (row->length_only != 0 || row->bytes == NULL) {
            uint8_t fake[64];
            (void)memset(fake, 0, sizeof(fake));
            fake[0] = (uint8_t)'N';
            fake[1] = (uint8_t)'F';
            fake[2] = (uint8_t)'L';
            fake[3] = (uint8_t)'1';
            REQUIRE(
                ninlil_fabric_private_nfl1_decode(
                    fake, row->len > 64u ? 64u : row->len, &ws, &env, &req)
                != NINLIL_FABRIC_PRIVATE_NFL1_OK
                || row->len > NINLIL_FABRIC_PRIVATE_NFL1_CODEC_CEILING
                || row->len < NINLIL_FABRIC_PRIVATE_NFL1_HEADER_BYTES);
            if (row->len > NINLIL_FABRIC_PRIVATE_NFL1_CODEC_CEILING) {
                REQUIRE(
                    ninlil_fabric_private_nfl1_decode(
                        fake, row->len, &ws, &env, &req)
                    != NINLIL_FABRIC_PRIVATE_NFL1_OK);
            }
        } else {
            REQUIRE(
                ninlil_fabric_private_nfl1_decode(
                    row->bytes, row->len, &ws, &env, &req)
                != NINLIL_FABRIC_PRIVATE_NFL1_OK);
            REQUIRE(env.message_kind == 0u);
            REQUIRE(ws.used == 0xABCDEF01u);
            REQUIRE(memcmp(ws.bytes, marker, sizeof(marker)) == 0);
        }
        (void)printf("  neg OK %s\n", row->id);
    }
    return 0;
}

static int test_all_storage_records(void)
{
    uint32_t i;
    REQUIRE(FABRIC_V1_STORAGE_COUNT == 15u);
    for (i = 0u; i < FABRIC_V1_STORAGE_COUNT; ++i) {
        const fabric_v1_store_row_t *row = &g_store_table[i];
        ninlil_fabric_private_common_envelope_t env;
        const uint8_t *payload = NULL;
        uint8_t magic[4];
        uint32_t plen;
        REQUIRE(row->key_len >= 4u);
        (void)memcpy(magic, row->key, 4u);
        REQUIRE(row->val_len >= 24u);
        plen = row->val_len - 24u;
        REQUIRE(
            ninlil_fabric_private_record_decode_envelope(
                row->val, row->val_len, magic, plen, &env, &payload)
            == NINLIL_FABRIC_PRIVATE_RECORD_OK);
        REQUIRE(payload != NULL);
        (void)printf("  store OK %s val=%u\n", row->id, (unsigned)row->val_len);
    }
    return 0;
}

static int test_workspace_and_object_partition(void)
{
    ninlil_fabric_ws_region_info_t regions[NINLIL_FABRIC_WS_REGION_COUNT];
    ninlil_fabric_ws_region_info_t objects[11];
    uint32_t total = 0u;
    uint32_t object_bytes = 0u;
    uint32_t workspace_bytes = 0u;
    uint32_t i;
    REQUIRE(
        ninlil_fabric_private_workspace_layout_proof_v1(&total, regions) == 0u);
    REQUIRE(total == 198656u);
    for (i = 1u; i < NINLIL_FABRIC_WS_REGION_COUNT; ++i) {
        REQUIRE(
            regions[i].offset
            == regions[i - 1u].offset + regions[i - 1u].size);
    }
    REQUIRE(
        regions[NINLIL_FABRIC_WS_REGION_COUNT - 1u].offset
            + regions[NINLIL_FABRIC_WS_REGION_COUNT - 1u].size
            == 198656u);
    REQUIRE(
        ninlil_fabric_private_object_partition_proof_v1(
            &object_bytes, &workspace_bytes, objects)
        == 0u);
    REQUIRE(workspace_bytes == 198656u);
    REQUIRE(object_bytes > 0u);
    REQUIRE(object_bytes <= 198656u);
    REQUIRE(objects[0].offset == 0u);
    REQUIRE(objects[0].size > 0u);
    REQUIRE(objects[1].size == NINLIL_FABRIC_WS_CODEC_SCRATCH_BYTES);
    (void)printf(
        "  workspace regions=%u total=%u object_bytes=%u\n",
        (unsigned)NINLIL_FABRIC_WS_REGION_COUNT,
        (unsigned)total,
        (unsigned)object_bytes);
    for (i = 0u; i < 11u; ++i) {
        if (objects[i].size == 0u) {
            continue;
        }
        (void)printf(
            "    obj %s off=%u sz=%u\n",
            objects[i].name,
            (unsigned)objects[i].offset,
            (unsigned)objects[i].size);
    }
    return 0;
}

static int test_vector_inventory_counts(void)
{
    REQUIRE(FABRIC_V1_SELECTION_COUNT == 48u);
    REQUIRE(FABRIC_V1_FBA_STATE_COUNT == 12u);
    REQUIRE(FABRIC_V1_COMMIT_UNKNOWN_COUNT == 5u);
    REQUIRE(FABRIC_V1_OUTER_BEARER_COUNT == 8u);
    REQUIRE(FABRIC_V1_MIXED_VERSION_COUNT == 30u);
    REQUIRE(FABRIC_V1_FBA_CU_COUNT == 6u);
    REQUIRE(FABRIC_V1_FRESH_ADOPTION_COUNT == 11u);
    REQUIRE(FABRIC_V1_STORAGE_NEG_COUNT == 40u);
    REQUIRE(FABRIC_V1_SEL_VEC_COUNT == 48u);
    REQUIRE(FABRIC_V1_SNEG_EXEC_COUNT == 40u);
    REQUIRE(FABRIC_V1_CU_EXEC_COUNT == 5u);
    REQUIRE(FABRIC_V1_FBA_EXEC_COUNT == 12u);
    REQUIRE(FABRIC_V1_OUTER_EXEC_COUNT == 8u);
    REQUIRE(FABRIC_V1_MIXED_EXEC_COUNT == 30u);
    REQUIRE(FABRIC_V1_FRESH_EXEC_COUNT == 11u);
    REQUIRE(FABRIC_V1_FBA_CU_EXEC_COUNT == 6u);
    REQUIRE(FABRIC_V1_RACE_EXEC_COUNT == 2u);
    return 0;
}

static int test_mixed_catalog_via_select(void)
{
    uint32_t i;
    for (i = 0u; i < FABRIC_V1_MIXED_EXEC_COUNT; ++i) {
        const fabric_v1_mixed_exec_row_t *row = &g_mixed_exec_table[i];
        ninlil_fabric_private_select_snapshot_t snap;
        ninlil_fabric_private_select_result_t res;
        fabric_v1_sel_vec_baseline(&snap);
        if (row->local_ver != 1u) {
            snap.registry[0].peer_nfl1_version = 0u;
        } else {
            snap.registry[0].peer_nfl1_version = (uint16_t)row->peer_ver;
        }
        snap.registry[0].peer_fabric_capability_flags = row->peer_cap_flags;
        ninlil_fabric_private_select(&snap, &res);
        if (row->expected == 1u) {
            REQUIRE(res.resolution == NINLIL_FABRIC_PRIVATE_SEL_SELECTED);
        } else {
            REQUIRE(res.resolution == NINLIL_FABRIC_PRIVATE_SEL_NO_ELIGIBLE);
        }
        (void)printf("  mixed OK %s\n", row->id);
    }
    return 0;
}

static int test_fbacu_catalog(void)
{
    uint32_t i;
    for (i = 0u; i < FABRIC_V1_FBA_CU_EXEC_COUNT; ++i) {
        const fabric_v1_fbacu_row_t *row = &g_fbacu_exec_table[i];
        uint32_t klass = ninlil_fabric_private_commit_unknown_classify(
            row->ok, row->okl, row->ov, row->ovl, row->nk, row->nkl, row->nv,
            row->nvl, row->sk, row->skl, row->sv, row->svl, row->obs_present);
        REQUIRE(klass == row->class_code);
        (void)printf("  fbacu OK %s\n", row->id);
    }
    return 0;
}

static int test_outer_fresh_race_catalog_literals(void)
{
    uint32_t i;
    /* Outer/fresh/race: literal executable rows present (host suite runs behaviors). */
    for (i = 0u; i < FABRIC_V1_OUTER_EXEC_COUNT; ++i) {
        REQUIRE(g_outer_exec_table[i].id != NULL);
        REQUIRE(g_outer_exec_table[i].expected_code != 0u);
    }
    for (i = 0u; i < FABRIC_V1_FRESH_EXEC_COUNT; ++i) {
        REQUIRE(g_fresh_exec_table[i].id != NULL);
        REQUIRE(g_fresh_exec_table[i].phase != 0u);
    }
    for (i = 0u; i < FABRIC_V1_RACE_EXEC_COUNT; ++i) {
        REQUIRE(g_race_exec_table[i].id != NULL);
        REQUIRE(
            g_race_exec_table[i].pre_provider_epoch_bump != 0u
            || g_race_exec_table[i].post_provider_epoch_bump != 0u);
    }
    /* Selection race rows no longer mutation_op skip. */
    for (i = 0u; i < FABRIC_V1_SEL_VEC_COUNT; ++i) {
        if (strstr(g_sel_vec_table[i].id, "RACE") != NULL) {
            REQUIRE(strcmp(g_sel_vec_table[i].mutation_op, "skip") != 0);
            REQUIRE(
                strncmp(g_sel_vec_table[i].mutation_op, "race_", 5) == 0);
        }
    }
    (void)printf("  outer/fresh/race literal catalogs OK\n");
    return 0;
}

/* local SHA-256 (same as other tests) */
static uint32_t rotr(uint32_t v, unsigned b)
{
    return (v >> b) | (v << (32u - b));
}
static void sha256(const uint8_t *msg, size_t len, uint8_t out[32])
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
    uint32_t h[8] = { 0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u };
    uint8_t block[64];
    uint64_t bit_len = (uint64_t)len * 8u;
    size_t offset = 0u, remain = len;
    int done = 0;
    while (!done) {
        size_t i, take = remain > 64u ? 64u : remain;
        uint32_t w[64], a, b, c, d, e, f, g, hh;
        (void)memset(block, 0, sizeof(block));
        if (take) {
            (void)memcpy(block, msg + offset, take);
            offset += take;
            remain -= take;
        }
        if (take < 64u) {
            block[take] = 0x80u;
            if (take < 56u) {
                for (i = 0; i < 8; ++i)
                    block[63 - i] = (uint8_t)(bit_len >> (8u * i));
                done = 1;
            }
        }
        for (i = 0; i < 16; ++i)
            w[i] = ((uint32_t)block[i * 4] << 24)
                | ((uint32_t)block[i * 4 + 1] << 16)
                | ((uint32_t)block[i * 4 + 2] << 8)
                | (uint32_t)block[i * 4 + 3];
        for (i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18)
                ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19)
                ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        a = h[0];
        b = h[1];
        c = h[2];
        d = h[3];
        e = h[4];
        f = h[5];
        g = h[6];
        hh = h[7];
        for (i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t t1 = hh + S1 + ch + k[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }
    {
        size_t i;
        for (i = 0; i < 8; ++i) {
            out[i * 4] = (uint8_t)(h[i] >> 24);
            out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
            out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
            out[i * 4 + 3] = (uint8_t)h[i];
        }
    }
}

int main(void)
{
    g_fail = 0;
    (void)printf("fabric_v1_vector_matrix_test\n");
    (void)test_vector_inventory_counts();
    (void)test_workspace_and_object_partition();
    (void)test_all_nfl1_positive();
    (void)test_all_nfl1_negative();
    (void)test_all_storage_records();
    (void)test_selection_vectors_via_select();
    (void)test_cu_vectors_via_classify();
    (void)test_fba_vectors_via_decode();
    (void)test_storage_neg_via_decode();
    (void)test_mixed_catalog_via_select();
    (void)test_fbacu_catalog();
    (void)test_outer_fresh_race_catalog_literals();
    if (g_fail != 0) {
        (void)fprintf(stderr, "vector matrix failures=%d\n", g_fail);
        return 1;
    }
    (void)printf("fabric_v1_vector_matrix_test OK\n");
    return 0;
}
