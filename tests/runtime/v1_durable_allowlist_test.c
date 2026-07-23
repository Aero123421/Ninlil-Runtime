/*
 * V1-LAB durable allowlist profile tests (unit 1a).
 * Writer gate RED probe + recovery publication rejection (4 kinds) +
 * COMMIT_UNKNOWN restart (no false success).
 */

#include "v1_durable_allowlist.h"

#include "domain_store_codec.h"
#include "runtime_store_bootstrap.h"
#include "runtime_store_codec.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",         \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static int test_writer_gate_red_probe(void)
{
    ninlil_model_runtime_store_key_t rs_key;
    ninlil_status_t status;

    REQUIRE(ninlil_model_runtime_store_build_key(
                NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, &rs_key)
        == NINLIL_OK);

    /*
     * RED: bootstrap operation must not emit domain metadata rows.
     * put count 0 (gate rejects before storage).
     */
    status = ninlil_v1_durable_writer_gate_check(
        NINLIL_V1_DURABLE_OP_BOOTSTRAP_COMMIT,
        (ninlil_bytes_view_t){rs_key.bytes, rs_key.length},
        (ninlil_bytes_view_t){NULL, 0u});
    REQUIRE(status == NINLIL_OK);

    {
        ninlil_model_runtime_store_key_t rs_key;
        ninlil_status_t status;

        REQUIRE(ninlil_model_runtime_store_build_key(
                    NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, &rs_key)
            == NINLIL_OK);
        /* RED: metadata operation must not emit bootstrap rows. */
        status = ninlil_v1_durable_writer_gate_check(
            NINLIL_V1_DURABLE_OP_METADATA_INIT_COMMIT,
            (ninlil_bytes_view_t){rs_key.bytes, rs_key.length},
            (ninlil_bytes_view_t){NULL, 0u});
        REQUIRE(status == NINLIL_E_UNSUPPORTED);
    }

    status = ninlil_v1_durable_probe_disallowed_writer_kind(
        NINLIL_V1_DURABLE_OP_METADATA_INIT_COMMIT,
        (ninlil_bytes_view_t){NULL, 0u},
        (ninlil_bytes_view_t){NULL, 0u});
    REQUIRE(status == NINLIL_E_UNSUPPORTED);

    return 0;
}

static int test_recovery_reject_unknown(void)
{
    /*
     * Recognizable future root (docs/17 §5): version byte 2, valid min key.
     * Classifies as RECOGNIZABLE_FUTURE → UNSUPPORTED (unknown to V1 profile).
     */
    static const uint8_t future_key[] = {
        0x4e, 0x49, 0x4e, 0x4c, 0x49, 0x4c, 0x00, 0x02,
        0x06, 0x10, 0x01, 0x02, 0x10
    };
    ninlil_bytes_view_t keys[1];
    ninlil_bytes_view_t values[1];
    ninlil_v1_durable_recovery_publication_result_t result;
    ninlil_status_t status;

    keys[0] = (ninlil_bytes_view_t){future_key, sizeof(future_key)};
    values[0] = (ninlil_bytes_view_t){NULL, 0u};
    status = ninlil_v1_durable_recovery_publication_gate(
        keys, values, 1u, 0u, &result);
    REQUIRE(status == NINLIL_E_UNSUPPORTED);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.success_evidence_count == 0u);
    REQUIRE(result.reject_reason
        == NINLIL_V1_DURABLE_RECOVERY_REJECT_UNKNOWN);
    return 0;
}

static int test_recovery_reject_corrupt(void)
{
    static const uint8_t corrupt_key[] = {
        0x4e, 0x49, 0x4e, 0x4c, 0x49, 0x4c, 0x00, 0x01,
        0x06, 0x62, 0x01, 0x01, 0x00
    };
    static const uint8_t corrupt_value[] = {0x4e, 0x4c, 0x52, 0x31};
    ninlil_bytes_view_t keys[1];
    ninlil_bytes_view_t values[1];
    ninlil_v1_durable_recovery_publication_result_t result;
    ninlil_status_t status;

    keys[0] = (ninlil_bytes_view_t){corrupt_key, sizeof(corrupt_key)};
    values[0] = (ninlil_bytes_view_t){corrupt_value, sizeof(corrupt_value)};
    status = ninlil_v1_durable_recovery_publication_gate(
        keys, values, 1u, 0u, &result);
    REQUIRE(status == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.success_evidence_count == 0u);
    REQUIRE(result.reject_reason
        == NINLIL_V1_DURABLE_RECOVERY_REJECT_CORRUPT);
    return 0;
}

static int test_recovery_reject_mixed(void)
{
    ninlil_model_runtime_store_key_t rs_key;
    static const uint8_t unknown_key[] = {0xde, 0xad};
    ninlil_bytes_view_t keys[2];
    ninlil_bytes_view_t values[2];
    ninlil_v1_durable_recovery_publication_result_t result;
    ninlil_status_t status;

    REQUIRE(ninlil_model_runtime_store_build_key(
                NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, &rs_key)
        == NINLIL_OK);
    keys[0] = (ninlil_bytes_view_t){rs_key.bytes, rs_key.length};
    values[0] = (ninlil_bytes_view_t){NULL, 0u};
    keys[1] = (ninlil_bytes_view_t){unknown_key, sizeof(unknown_key)};
    values[1] = (ninlil_bytes_view_t){NULL, 0u};
    status = ninlil_v1_durable_recovery_publication_gate(
        keys, values, 2u, 0u, &result);
    REQUIRE(status == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.success_evidence_count == 0u);
    REQUIRE(result.reject_reason == NINLIL_V1_DURABLE_RECOVERY_REJECT_MIXED);
    return 0;
}

static int test_recovery_reject_commit_unknown_restart(void)
{
    ninlil_model_runtime_store_key_t rs_key;
    ninlil_bytes_view_t keys[1];
    ninlil_bytes_view_t values[1];
    ninlil_v1_durable_recovery_publication_result_t result;
    ninlil_status_t status;

    REQUIRE(ninlil_model_runtime_store_build_key(
                NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, &rs_key)
        == NINLIL_OK);
    keys[0] = (ninlil_bytes_view_t){rs_key.bytes, rs_key.length};
    values[0] = (ninlil_bytes_view_t){NULL, 0u};
    status = ninlil_v1_durable_recovery_publication_gate(
        keys, values, 1u, 1u, &result);
    REQUIRE(status == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.success_evidence_count == 0u);
    REQUIRE(result.reject_reason
        == NINLIL_V1_DURABLE_RECOVERY_REJECT_COMMIT_UNKNOWN);
    return 0;
}

static int test_allowlist_table_closed(void)
{
    REQUIRE(NINLIL_V1_DURABLE_ALLOWLIST_RECORD_KIND_COUNT == 19u);
    REQUIRE(NINLIL_V1_DURABLE_ALLOWLIST_OPERATION_COUNT == 3u);
    REQUIRE(g_ninlil_v1_durable_allowlist_table[0].kind
        == NINLIL_V1_DURABLE_KIND_RS_BINDING);
    REQUIRE(g_ninlil_v1_durable_allowlist_table[18].kind
        == NINLIL_V1_DURABLE_KIND_DOM_CLOCK_BASELINE);
    return 0;
}

int main(void)
{
    REQUIRE(test_allowlist_table_closed() == 0);
    REQUIRE(test_writer_gate_red_probe() == 0);
    REQUIRE(test_recovery_reject_unknown() == 0);
    REQUIRE(test_recovery_reject_corrupt() == 0);
    REQUIRE(test_recovery_reject_mixed() == 0);
    REQUIRE(test_recovery_reject_commit_unknown_restart() == 0);
    (void)printf("v1_durable_allowlist_test ok\n");
    return 0;
}
