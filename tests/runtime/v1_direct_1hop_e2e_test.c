/*
 * V1-LAB unit 5: B4 PC間 direct 1-hop E2E (2-process loopback bearer).
 */

#include "ninlil_posix_lab_platform.h"
#include "ninlil_posix_lab_platform_test.h"
#include "ninlil_posix_loopback_bearer.h"
#include "ninlil_posix_loopback_bearer_inject.h"
#include "platform_basic_fixtures.h"
#include "runtime_lifecycle_model.h"

#include <ninlil/runtime.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",           \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

#define SCENARIO_HAPPY 1u
#define SCENARIO_ACK_LOSS 2u
#define SCENARIO_DATA_LOSS 3u
#define SCENARIO_TIMEOUT 4u
#define SCENARIO_RESTART 5u
#define SCENARIO_DUPLICATE 6u
#define SCENARIO_LATEST_STATE 7u

static const uint8_t CTRL_NS[] = "v1-direct-1hop-ctrl";
static const uint8_t END_NS[] = "v1-direct-1hop-end";
static const char NS_TEXT[] = "org.ninlil.examples";
static const char *g_program_path;
static char g_program_path_storage[PATH_MAX];

static void close_all_fds_except(int keep[], int keep_count)
{
    int fd;
    int max_fd;
    int index;
    int should_keep;

    max_fd = (int)sysconf(_SC_OPEN_MAX);
    if (max_fd < 0 || max_fd > 4096) {
        max_fd = 4096;
    }
    for (fd = 3; fd < max_fd; ++fd) {
        should_keep = 0;
        for (index = 0; index < keep_count; ++index) {
            if (keep[index] == fd) {
                should_keep = 1;
                break;
            }
        }
        if (!should_keep) {
            (void)close(fd);
        }
    }
}

static uint32_t g_delivery_calls;
static uint32_t g_outcome_satisfied;

static void set_id(ninlil_id128_t *id, uint8_t first)
{
    uint32_t index;
    for (index = 0u; index < 16u; ++index) {
        id->bytes[index] = (uint8_t)(first + index);
    }
}

static void set_digest(ninlil_digest256_t *digest, uint8_t value)
{
    (void)memset(digest, 0, sizeof(*digest));
    digest->algorithm = NINLIL_DIGEST_SHA256;
    digest->bytes[sizeof(digest->bytes) - 1u] = value;
}

static void set_header(uint16_t *version, uint16_t *size, size_t value)
{
    *version = NINLIL_ABI_VERSION;
    *size = (uint16_t)value;
}

static ninlil_reconcile_action_t endpoint_reconcile_cb(
    void *user,
    const ninlil_reconcile_view_t *delivery,
    ninlil_application_result_t *out_known_result)
{
    (void)user;
    (void)delivery;
    (void)out_known_result;
    return NINLIL_RECONCILE_REDELIVER;
}

static ninlil_callback_action_t endpoint_delivery_cb(
    void *user,
    const ninlil_delivery_token_t *token,
    const ninlil_delivery_view_t *delivery,
    ninlil_application_result_t *out_sync_result)
{
    (void)user;
    (void)token;
    (void)delivery;
    g_delivery_calls += 1u;
    out_sync_result->kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    out_sync_result->evidence_stage = NINLIL_EVIDENCE_APPLIED;
    return NINLIL_CALLBACK_COMPLETE;
}

static ninlil_service_descriptor_t desired_descriptor(uint8_t app_tag, ninlil_role_t role)
{
    ninlil_service_descriptor_t descriptor;
    (void)memset(&descriptor, 0, sizeof(descriptor));
    set_header(&descriptor.abi_version, &descriptor.struct_size, sizeof(descriptor));
    descriptor.namespace_id.data = (const uint8_t *)NS_TEXT;
    descriptor.namespace_id.length = sizeof(NS_TEXT) - 1u;
    descriptor.service_id.data = (const uint8_t *)"absolute-state";
    descriptor.service_id.length = sizeof("absolute-state") - 1u;
    descriptor.schema_id.data = (const uint8_t *)"absolute-state";
    descriptor.schema_id.length = sizeof("absolute-state") - 1u;
    descriptor.descriptor_revision = 1u;
    set_digest(&descriptor.descriptor_digest, 0x11u);
    set_id(&descriptor.local_application_instance_id, app_tag);
    descriptor.schema_major = 1u;
    descriptor.family = NINLIL_FAMILY_DESIRED_STATE;
    descriptor.direction = NINLIL_DIRECTION_DOWNLINK;
    descriptor.admission_authority = NINLIL_AUTHORITY_CONTROLLER_ONLY;
    descriptor.apply_contract = NINLIL_APPLY_APPLICATION_DEDUP;
    descriptor.custody_policy = NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE;
    descriptor.supported_evidence_mask =
        NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_DURABLY_RECORDED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED);
    descriptor.logical_payload_limit = 1000u;
    descriptor.target_limit = 1u;
    descriptor.inflight_limit = 8u;
    descriptor.max_attempts_per_target_per_cycle = NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    descriptor.admission_window_ms = 10000u;
    descriptor.max_admissions_per_window = 20u;
    descriptor.max_payload_bytes_per_window = 20480u;
    descriptor.minimum_deadline_ms = 5000u;
    descriptor.maximum_deadline_ms = 5000u;
    descriptor.maximum_evidence_grace_ms = 1000u;
    descriptor.attempt_receipt_timeout_ms = 1000u;
    descriptor.retry_backoff_ms = 100u;
    descriptor.application_completion_timeout_ms = 60000u;
    descriptor.required_dedup_window_ms = 1000u;
    (void)role;
    return descriptor;
}

static ninlil_service_descriptor_t latest_state_descriptor(
    uint8_t app_tag,
    ninlil_role_t role)
{
    ninlil_service_descriptor_t descriptor;

    (void)memset(&descriptor, 0, sizeof(descriptor));
    set_header(&descriptor.abi_version, &descriptor.struct_size, sizeof(descriptor));
    descriptor.namespace_id.data = (const uint8_t *)NS_TEXT;
    descriptor.namespace_id.length = sizeof(NS_TEXT) - 1u;
    descriptor.service_id.data = (const uint8_t *)"latest-state";
    descriptor.service_id.length = sizeof("latest-state") - 1u;
    descriptor.schema_id.data = (const uint8_t *)"latest-state";
    descriptor.schema_id.length = sizeof("latest-state") - 1u;
    descriptor.descriptor_revision = 1u;
    set_digest(&descriptor.descriptor_digest, 0x31u);
    set_id(&descriptor.local_application_instance_id, app_tag);
    descriptor.schema_major = 1u;
    descriptor.family = NINLIL_FAMILY_LATEST_STATE_RESERVED;
    descriptor.direction = NINLIL_DIRECTION_UPLINK;
    descriptor.admission_authority = NINLIL_AUTHORITY_ORIGIN_WITH_GRANT;
    descriptor.apply_contract = NINLIL_APPLY_APPLICATION_DEDUP;
    descriptor.custody_policy = NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE;
    descriptor.supported_evidence_mask =
        NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED);
    descriptor.logical_payload_limit = 512u;
    descriptor.target_limit = 1u;
    descriptor.inflight_limit = 8u;
    descriptor.max_attempts_per_target_per_cycle = NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    descriptor.admission_window_ms = 10000u;
    descriptor.max_admissions_per_window = 20u;
    descriptor.max_payload_bytes_per_window = 20480u;
    descriptor.minimum_deadline_ms = NINLIL_NO_DEADLINE;
    descriptor.maximum_deadline_ms = NINLIL_NO_DEADLINE;
    descriptor.maximum_evidence_grace_ms = 0u;
    descriptor.attempt_receipt_timeout_ms = 1000u;
    descriptor.retry_backoff_ms = 100u;
    descriptor.application_completion_timeout_ms = 60000u;
    descriptor.required_dedup_window_ms = 1000u;
    (void)role;
    return descriptor;
}

static ninlil_runtime_config_t runtime_config(
    ninlil_role_t role,
    const uint8_t *storage_ns,
    size_t storage_ns_len,
    uint8_t runtime_tag)
{
    ninlil_runtime_config_t config;
    (void)memset(&config, 0, sizeof(config));
    set_header(&config.abi_version, &config.struct_size, sizeof(config));
    config.role = role;
    config.environment = NINLIL_ENV_TEST;
    set_id(&config.runtime_id, runtime_tag);
    set_header(
        &config.local_identity.abi_version,
        &config.local_identity.struct_size,
        sizeof(config.local_identity));
    config.local_identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    set_id(&config.local_identity.device_id, (uint8_t)(runtime_tag + 0x10u));
    set_id(&config.local_identity.installation_id, (uint8_t)(runtime_tag + 0x20u));
    set_id(&config.local_identity.site_domain_id, (uint8_t)(runtime_tag + 0x30u));
    config.local_identity.binding_epoch = 1u;
    config.local_identity.membership_epoch = 1u;
    config.storage_namespace.data = storage_ns;
    config.storage_namespace.length = storage_ns_len;
    set_header(&config.limits.abi_version, &config.limits.struct_size, sizeof(config.limits));
    config.limits.max_services = 4u;
    config.limits.max_nonterminal_transactions =
        role == NINLIL_ROLE_ENDPOINT ? 32u : 16u;
    config.limits.max_targets_per_transaction = 1u;
    config.limits.max_logical_payload_bytes = 1000u;
    config.limits.max_durable_outbox_payload_bytes =
        role == NINLIL_ROLE_CONTROLLER ? 5000u : 0u;
    config.limits.max_attempts_per_target_per_cycle = 8u;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 3u;
    config.limits.max_retained_terminal_transactions = 16u;
    config.limits.max_nonterminal_deliveries = 16u;
    config.limits.max_event_spool_count = role == NINLIL_ROLE_ENDPOINT ? 32u : 0u;
    config.limits.max_event_spool_bytes =
        role == NINLIL_ROLE_ENDPOINT ? 32768u : 0u;
    config.limits.max_result_cache_entries = 16u;
    config.limits.max_retained_dispositions = 16u;
    config.limits.max_ingress_per_step = 8u;
    config.limits.max_callbacks_per_step = 8u;
    config.limits.max_state_transitions_per_step = 16u;
    config.limits.max_bearer_sends_per_step = 8u;
    config.limits.max_deferred_tokens = 8u;
    config.terminal_retention_ms = 4242u;
    config.result_cache_retention_ms = 2000u;
    config.observation_retention_ms = 800u;
    return config;
}

static void fill_step_budget(ninlil_step_budget_t *budget)
{
    (void)memset(budget, 0, sizeof(*budget));
    set_header(&budget->abi_version, &budget->struct_size, sizeof(*budget));
    budget->max_ingress_messages = 8u;
    budget->max_callbacks = 8u;
    budget->max_state_transitions = 16u;
    budget->max_bearer_sends = 8u;
}

static int parse_u32(const char *text, uint32_t *out)
{
    char *end = NULL;
    unsigned long value;
    if (text == NULL || out == NULL) {
        return 0;
    }
    value = strtoul(text, &end, 10);
    if (end == text || *end != '\0' || value > UINT32_MAX) {
        return 0;
    }
    *out = (uint32_t)value;
    return 1;
}

static int parse_fd(const char *text, int *out)
{
    long value;
    char *end = NULL;
    if (text == NULL || out == NULL) {
        return 0;
    }
    if (strcmp(text, "none") == 0) {
        *out = -1;
        return 1;
    }
    value = strtol(text, &end, 10);
    if (end == text || *end != '\0' || value < 0 || value > INT_MAX) {
        return 0;
    }
    *out = (int)value;
    return 1;
}

static int write_byte(int fd, char value)
{
    return write(fd, &value, 1) == 1;
}

static int read_byte(int fd, char *out)
{
    return read(fd, out, 1) == 1;
}

static int platform_config_for_role(
    ninlil_posix_lab_platform_config_t *config,
    ninlil_role_t role,
    const char *socket_path,
    const char *db_path,
    uint32_t scenario,
    uint64_t seed)
{
    ninlil_posix_lab_platform_config_defaults(config);
    config->database_path = db_path;
    config->role = role;
    config->bearer_kind = NINLIL_POSIX_LAB_PLATFORM_BEARER_LOOPBACK;
    config->loopback_socket_path = socket_path;
    config->loopback_role = role == NINLIL_ROLE_CONTROLLER
        ? NINLIL_POSIX_LOOPBACK_BEARER_ROLE_SERVER
        : NINLIL_POSIX_LOOPBACK_BEARER_ROLE_CLIENT;
    config->inject_seed = seed;
    if (role != NINLIL_ROLE_CONTROLLER) {
        return 1;
    }
    if (scenario == SCENARIO_ACK_LOSS) {
        config->inject_mode = NINLIL_POSIX_LOOPBACK_INJECT_MODE_DROP_ACK;
        config->inject_drop_budget = 1u;
    } else if (scenario == SCENARIO_DATA_LOSS) {
        config->inject_mode = NINLIL_POSIX_LOOPBACK_INJECT_MODE_DROP_DATA;
        config->inject_drop_budget = 1u;
    } else if (scenario == SCENARIO_DUPLICATE) {
        config->inject_mode = NINLIL_POSIX_LOOPBACK_INJECT_MODE_DUPLICATE;
        config->inject_duplicate_budget = 1u;
    }
    return 1;
}

static int run_endpoint_process(
    const char *socket_path,
    const char *db_path,
    uint32_t scenario,
    uint64_t seed,
    int go_fd,
    int result_fd,
    int restart_fd,
    int sync_fd)
{
    ninlil_posix_lab_platform_config_t pconfig;
    ninlil_posix_lab_platform_t *platform;
    ninlil_runtime_config_t config;
    ninlil_runtime_t *runtime = NULL;
    ninlil_model_runtime_validation_result_t validation;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_service_t *service = NULL;
    ninlil_submission_t submission;
    ninlil_submission_result_t submit_result;
    ninlil_concrete_target_t target;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    static const uint8_t latest_idem_key[] = "latest-state-uplink";
    uint8_t latest_payload[8];
    char gate = 0;
    uint32_t step;
    int restarted = 0;

    g_delivery_calls = 0u;
    if (!read_byte(go_fd, &gate) || gate != 'G') {
        (void)write_byte(result_fd, 'F');
        return 2;
    }
    platform_config_for_role(
        &pconfig, NINLIL_ROLE_ENDPOINT, socket_path, db_path, scenario, seed);
    platform = ninlil_posix_lab_platform_create(&pconfig);
    if (platform == NULL) {
        (void)write_byte(result_fd, 'F');
        return 3;
    }
    config = runtime_config(NINLIL_ROLE_ENDPOINT, END_NS, sizeof(END_NS) - 1u, 0x21u);
    if (ninlil_model_runtime_validate_and_derive(
            &config, ninlil_posix_lab_platform_ops(platform), &validation)
            != NINLIL_OK) {
        ninlil_posix_lab_platform_destroy(platform);
        (void)write_byte(result_fd, 'F');
        return 4;
    }
    if (ninlil_runtime_create(
            &config, ninlil_posix_lab_platform_ops(platform), &runtime)
        != NINLIL_OK) {
        ninlil_posix_lab_platform_destroy(platform);
        (void)write_byte(result_fd, 'F');
        return 4;
    }
    descriptor = scenario == SCENARIO_LATEST_STATE
        ? latest_state_descriptor(0x81u, NINLIL_ROLE_ENDPOINT)
        : desired_descriptor(0x81u, NINLIL_ROLE_ENDPOINT);
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    if (scenario != SCENARIO_LATEST_STATE) {
        callbacks.on_delivery = endpoint_delivery_cb;
        callbacks.on_reconcile = endpoint_reconcile_cb;
    }
    if (ninlil_service_register(runtime, &descriptor, &callbacks, &service)
        != NINLIL_OK) {
        (void)ninlil_runtime_destroy(runtime);
        ninlil_posix_lab_platform_destroy(platform);
        (void)write_byte(result_fd, 'F');
        return 5;
    }
    if (sync_fd >= 0) {
        char sync = 0;
        if (!read_byte(sync_fd, &sync) || sync != 'R') {
            (void)ninlil_runtime_destroy(runtime);
            ninlil_posix_lab_platform_destroy(platform);
            (void)write_byte(result_fd, 'F');
            return 11;
        }
    }
    if (scenario == SCENARIO_LATEST_STATE) {
        (void)memset(latest_payload, 0x4cu, sizeof(latest_payload));
        (void)memset(&submission, 0, sizeof(submission));
        set_header(&submission.abi_version, &submission.struct_size, sizeof(submission));
        submission.schema_major = 1u;
        (void)memset(&target, 0, sizeof(target));
        set_header(&target.abi_version, &target.struct_size, sizeof(target));
        set_id(&target.target_runtime_id, 0x10u);
        set_id(&target.target_application_instance_id, 0x70u);
        submission.targets = &target;
        submission.target_count = 1u;
        submission.required_evidence = NINLIL_EVIDENCE_APPLIED;
        submission.effect_deadline_ms = NINLIL_NO_DEADLINE;
        submission.evidence_grace_ms = 0u;
        submission.generation = 9u;
        submission.idempotency_key.data = latest_idem_key;
        submission.idempotency_key.length = sizeof(latest_idem_key) - 1u;
        submission.payload.data = latest_payload;
        submission.payload.length = sizeof(latest_payload);
        set_digest(&submission.content_digest, 0x39u);
        {
            ninlil_status_t submit_status =
                ninlil_submit(service, &submission, &submit_result);
            if (submit_status != NINLIL_OK
                || submit_result.kind != NINLIL_SUBMISSION_ADMITTED_READY) {
                (void)ninlil_runtime_destroy(runtime);
                ninlil_posix_lab_platform_destroy(platform);
                (void)write_byte(result_fd, 'F');
                return 6;
            }
        }
        {
            char workdir[512];
            char ready_path[1024];
            int ready_fd;
            if (getcwd(workdir, sizeof(workdir)) == NULL
                || snprintf(ready_path, sizeof(ready_path),
                       "%s/direct-1hop-%u-ready", workdir, scenario)
                    <= 0) {
                (void)ninlil_runtime_destroy(runtime);
                ninlil_posix_lab_platform_destroy(platform);
                (void)write_byte(result_fd, 'F');
                return 12;
            }
            ready_fd = open(ready_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
            if (ready_fd < 0
                || write(ready_fd, "S", 1) != 1
                || close(ready_fd) != 0) {
                (void)ninlil_runtime_destroy(runtime);
                ninlil_posix_lab_platform_destroy(platform);
                (void)write_byte(result_fd, 'F');
                return 12;
            }
        }
    }
    for (step = 0u; step < 512u; ++step) {
        char cmd = 0;
        if (scenario == SCENARIO_RESTART && step == 8u && restarted == 0) {
            if (read_byte(restart_fd, &cmd) && cmd == 'R') {
                (void)ninlil_runtime_destroy(runtime);
                runtime = NULL;
                REQUIRE(ninlil_posix_lab_platform_restart(platform) == 1);
                REQUIRE(ninlil_runtime_create(
                            &config, ninlil_posix_lab_platform_ops(platform), &runtime)
                    == NINLIL_OK);
                REQUIRE(ninlil_service_register(
                            runtime, &descriptor, &callbacks, &service)
                    == NINLIL_OK);
                restarted = 1;
            }
        }
        fill_step_budget(&budget);
        (void)memset(&step_result, 0, sizeof(step_result));
        (void)ninlil_runtime_step(runtime, &budget, &step_result);
        if (scenario == SCENARIO_TIMEOUT && step > 16u) {
            break;
        }
        if (scenario == SCENARIO_HAPPY && g_delivery_calls >= 1u) {
            break;
        }
        if (scenario == SCENARIO_DATA_LOSS && g_delivery_calls >= 1u) {
            break;
        }
        if (scenario == SCENARIO_RESTART && restarted != 0 && g_delivery_calls >= 1u) {
            break;
        }
        if (scenario == SCENARIO_DUPLICATE && g_delivery_calls >= 1u && step > 12u) {
            break;
        }
        if (scenario == SCENARIO_LATEST_STATE
            && ninlil_posix_lab_platform_test_inject_send_count(platform) >= 1u
            && ninlil_posix_lab_platform_test_inject_recv_count(platform) >= 1u) {
            break;
        }
    }
    if (scenario == SCENARIO_DUPLICATE && g_delivery_calls != 1u) {
        (void)write_byte(result_fd, 'F');
        (void)ninlil_runtime_destroy(runtime);
        ninlil_posix_lab_platform_destroy(platform);
        return 6;
    }
    if (scenario == SCENARIO_TIMEOUT) {
        (void)write_byte(result_fd, 'O');
        (void)ninlil_runtime_destroy(runtime);
        ninlil_posix_lab_platform_destroy(platform);
        return 0;
    }
    if (scenario == SCENARIO_LATEST_STATE) {
        if (ninlil_posix_lab_platform_test_inject_send_count(platform) < 1u
            || ninlil_posix_lab_platform_test_inject_recv_count(platform) < 1u) {
            (void)write_byte(result_fd, 'F');
            (void)ninlil_runtime_destroy(runtime);
            ninlil_posix_lab_platform_destroy(platform);
            return 7;
        }
        (void)write_byte(result_fd, 'O');
        (void)ninlil_runtime_destroy(runtime);
        ninlil_posix_lab_platform_destroy(platform);
        return 0;
    }
    if (g_delivery_calls < 1u) {
        (void)write_byte(result_fd, 'F');
        (void)ninlil_runtime_destroy(runtime);
        ninlil_posix_lab_platform_destroy(platform);
        return 7;
    }
    (void)write_byte(result_fd, 'O');
    (void)ninlil_runtime_destroy(runtime);
    ninlil_posix_lab_platform_destroy(platform);
    return 0;
}

static int run_controller_process(
    const char *socket_path,
    const char *db_path,
    uint32_t scenario,
    uint64_t seed,
    int go_fd,
    int result_fd,
    int restart_fd,
    int sync_fd)
{
    ninlil_posix_lab_platform_config_t pconfig;
    ninlil_posix_lab_platform_t *platform;
    ninlil_runtime_config_t config;
    ninlil_runtime_t *runtime = NULL;
    ninlil_model_runtime_validation_result_t validation;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_service_t *service = NULL;
    ninlil_submission_t submission;
    ninlil_submission_result_t submit_result;
    ninlil_concrete_target_t target;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    static const uint8_t idem_key[] = "direct-1hop-idem";
    uint8_t payload[16];
    char gate = 0;
    uint32_t step;
    int restarted = 0;
    uint32_t idle_steps = 0u;

    g_outcome_satisfied = 0u;
    g_delivery_calls = 0u;
    if (!read_byte(go_fd, &gate) || gate != 'G') {
        (void)write_byte(result_fd, 'F');
        if (sync_fd >= 0) {
            (void)write_byte(sync_fd, 'F');
        }
        return 2;
    }
    platform_config_for_role(
        &pconfig, NINLIL_ROLE_CONTROLLER, socket_path, db_path, scenario, seed);
    platform = ninlil_posix_lab_platform_create(&pconfig);
    if (platform == NULL) {
        (void)write_byte(result_fd, 'F');
        return 3;
    }
    config = runtime_config(NINLIL_ROLE_CONTROLLER, CTRL_NS, sizeof(CTRL_NS) - 1u, 0x10u);
    if (ninlil_model_runtime_validate_and_derive(
            &config, ninlil_posix_lab_platform_ops(platform), &validation)
            != NINLIL_OK
        || ninlil_runtime_create(
               &config, ninlil_posix_lab_platform_ops(platform), &runtime)
            != NINLIL_OK) {
        ninlil_posix_lab_platform_destroy(platform);
        (void)write_byte(result_fd, 'F');
        return 4;
    }
    descriptor = scenario == SCENARIO_LATEST_STATE
        ? latest_state_descriptor(0x70u, NINLIL_ROLE_CONTROLLER)
        : desired_descriptor(0x70u, NINLIL_ROLE_CONTROLLER);
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    if (scenario == SCENARIO_LATEST_STATE) {
        callbacks.on_delivery = endpoint_delivery_cb;
        callbacks.on_reconcile = endpoint_reconcile_cb;
    }
    if (ninlil_service_register(runtime, &descriptor, &callbacks, &service)
        != NINLIL_OK) {
        (void)ninlil_runtime_destroy(runtime);
        ninlil_posix_lab_platform_destroy(platform);
        (void)write_byte(result_fd, 'F');
        if (sync_fd >= 0) {
            (void)write_byte(sync_fd, 'F');
        }
        return 5;
    }
    if (scenario != SCENARIO_LATEST_STATE) {
        (void)memset(payload, 0x42, sizeof(payload));
        (void)memset(&submission, 0, sizeof(submission));
        set_header(&submission.abi_version, &submission.struct_size, sizeof(submission));
        submission.schema_major = 1u;
        (void)memset(&target, 0, sizeof(target));
        set_header(&target.abi_version, &target.struct_size, sizeof(target));
        set_id(&target.target_runtime_id, 0x21u);
        set_id(&target.target_application_instance_id, 0x81u);
        submission.targets = &target;
        submission.target_count = 1u;
        submission.required_evidence = NINLIL_EVIDENCE_APPLIED;
        submission.effect_deadline_ms = 5000u;
        submission.evidence_grace_ms = 1000u;
        submission.generation = 1u;
        submission.idempotency_key.data = idem_key;
        submission.idempotency_key.length = sizeof(idem_key) - 1u;
        submission.payload.data = payload;
        submission.payload.length = sizeof(payload);
        set_digest(&submission.content_digest, 0x55u);
        if (ninlil_submit(service, &submission, &submit_result) != NINLIL_OK
            || submit_result.kind != NINLIL_SUBMISSION_ADMITTED_READY) {
            (void)ninlil_runtime_destroy(runtime);
            ninlil_posix_lab_platform_destroy(platform);
            (void)write_byte(result_fd, 'F');
            if (sync_fd >= 0) {
                (void)write_byte(sync_fd, 'F');
            }
            return 6;
        }
    }
    if (sync_fd >= 0) {
        (void)write_byte(sync_fd, 'R');
    }
    if (scenario == SCENARIO_LATEST_STATE) {
        char ready_path[1024];
        char workdir[512];
        uint32_t wait;
        if (getcwd(workdir, sizeof(workdir)) == NULL
            || snprintf(ready_path, sizeof(ready_path),
                   "%s/direct-1hop-%u-ready", workdir, scenario)
                <= 0) {
            (void)write_byte(result_fd, 'F');
            (void)ninlil_runtime_destroy(runtime);
            ninlil_posix_lab_platform_destroy(platform);
            return 12;
        }
        for (wait = 0u; wait < 2000u; ++wait) {
            if (access(ready_path, F_OK) == 0) {
                break;
            }
            (void)usleep(1000);
        }
        if (wait >= 2000u) {
            (void)write_byte(result_fd, 'F');
            (void)ninlil_runtime_destroy(runtime);
            ninlil_posix_lab_platform_destroy(platform);
            return 12;
        }
        (void)unlink(ready_path);
    }
    for (step = 0u; step < 512u; ++step) {
        if (scenario == SCENARIO_RESTART && step == 4u && restarted == 0) {
            (void)write_byte(restart_fd, 'R');
            (void)ninlil_runtime_destroy(runtime);
            runtime = NULL;
            if (ninlil_posix_lab_platform_restart(platform) != 1
                || ninlil_runtime_create(
                       &config, ninlil_posix_lab_platform_ops(platform), &runtime)
                    != NINLIL_OK
                || ninlil_service_register(
                       runtime, &descriptor, &callbacks, &service)
                    != NINLIL_OK) {
                (void)write_byte(result_fd, 'F');
                ninlil_posix_lab_platform_destroy(platform);
                return 8;
            }
            restarted = 1;
        }
        fill_step_budget(&budget);
        if (scenario == SCENARIO_ACK_LOSS) {
            ninlil_test_clock_t *clock =
                ninlil_posix_lab_platform_test_clock(platform);
            if (clock != NULL && step == 6u) {
                (void)ninlil_test_clock_advance(clock, 1200u);
            }
        } else if (scenario == SCENARIO_DATA_LOSS) {
            ninlil_test_clock_t *clock =
                ninlil_posix_lab_platform_test_clock(platform);
            if (clock != NULL && step > 1u) {
                (void)ninlil_test_clock_advance(clock, 800u);
            }
        }
        if (scenario == SCENARIO_TIMEOUT && step > 4u) {
            ninlil_test_clock_t *clock =
                ninlil_posix_lab_platform_test_clock(platform);
            if (clock != NULL) {
                (void)ninlil_test_clock_advance(clock, 6000u);
            }
        }
        (void)memset(&step_result, 0, sizeof(step_result));
        (void)ninlil_runtime_step(runtime, &budget, &step_result);
        if (step_result.more_work == 0u) {
            idle_steps += 1u;
        } else {
            idle_steps = 0u;
        }
        if (scenario == SCENARIO_TIMEOUT) {
            if (step > 20u) {
                break;
            }
            continue;
        }
        if (scenario == SCENARIO_HAPPY
            && ninlil_posix_lab_platform_test_inject_recv_count(platform) >= 1u) {
            g_outcome_satisfied = 1u;
            break;
        }
        if (scenario == SCENARIO_DATA_LOSS
            && ninlil_posix_lab_platform_test_inject_drop_count(platform) >= 1u
            && ninlil_posix_lab_platform_test_inject_send_count(platform) >= 1u) {
            g_outcome_satisfied = 1u;
            break;
        }
        if (scenario == SCENARIO_ACK_LOSS
            && ninlil_posix_lab_platform_test_inject_drop_count(platform) >= 1u
            && ninlil_posix_lab_platform_test_inject_recv_count(platform) >= 1u) {
            g_outcome_satisfied = 1u;
            break;
        }
        if (scenario == SCENARIO_RESTART
            && restarted != 0
            && step > 40u) {
            g_outcome_satisfied = 1u;
            break;
        }
        if (scenario == SCENARIO_DUPLICATE && idle_steps >= 3u
            && ninlil_posix_lab_platform_test_inject_recv_count(platform) >= 1u) {
            g_outcome_satisfied = 1u;
            break;
        }
        if (scenario == SCENARIO_LATEST_STATE && g_delivery_calls >= 1u) {
            g_outcome_satisfied = 1u;
            break;
        }
    }
    if (scenario == SCENARIO_TIMEOUT) {
        if (g_outcome_satisfied != 0u) {
            (void)write_byte(result_fd, 'F');
            (void)ninlil_runtime_destroy(runtime);
            ninlil_posix_lab_platform_destroy(platform);
            return 9;
        }
        (void)write_byte(result_fd, 'O');
        (void)ninlil_runtime_destroy(runtime);
        ninlil_posix_lab_platform_destroy(platform);
        return 0;
    }
    if (g_outcome_satisfied == 0u) {
        (void)write_byte(result_fd, 'F');
        (void)ninlil_runtime_destroy(runtime);
        ninlil_posix_lab_platform_destroy(platform);
        return 10;
    }
    (void)write_byte(result_fd, 'O');
    (void)ninlil_runtime_destroy(runtime);
    ninlil_posix_lab_platform_destroy(platform);
    return 0;
}

static int child_main(int argc, char **argv)
{
    const char *role;
    const char *socket_path;
    const char *db_path;
    uint32_t scenario;
    uint64_t seed;
    int go_fd;
    int result_fd;
    int restart_fd;
    int sync_fd;

    if (argc < 10 || argv == NULL) {
        return 126;
    }
    role = argv[2];
    socket_path = argv[3];
    db_path = argv[4];
    if (!parse_u32(argv[5], &scenario)) {
        return 125;
    }
    seed = strtoull(argv[6], NULL, 10);
    sync_fd = -1;
    if (argc >= 11 && !parse_fd(argv[10], &sync_fd)) {
        return 123;
    }
    if (!parse_fd(argv[7], &go_fd) || !parse_fd(argv[8], &result_fd)
        || !parse_fd(argv[9], &restart_fd)) {
        return 124;
    }
    if (strcmp(role, "endpoint") == 0) {
        return run_endpoint_process(
            socket_path,
            db_path,
            scenario,
            seed,
            go_fd,
            result_fd,
            restart_fd,
            sync_fd);
    }
    if (strcmp(role, "controller") == 0) {
        return run_controller_process(
            socket_path,
            db_path,
            scenario,
            seed,
            go_fd,
            result_fd,
            restart_fd,
            sync_fd);
    }
    return 126;
}

static int spawn_peer(
    const char *role,
    const char *socket_path,
    const char *db_path,
    uint32_t scenario,
    uint64_t seed,
    int go_fd,
    int result_fd,
    int restart_fd,
    int sync_fd,
    pid_t *out_pid)
{
    char scenario_text[16];
    char seed_text[32];
    char go_fd_text[16];
    char result_fd_text[16];
    char restart_fd_text[16];
    char sync_fd_text[16];
    char *argv[13];

    REQUIRE(snprintf(scenario_text, sizeof(scenario_text), "%u", scenario) > 0);
    REQUIRE(snprintf(seed_text, sizeof(seed_text), "%llu", (unsigned long long)seed)
        > 0);
    REQUIRE(snprintf(go_fd_text, sizeof(go_fd_text), "%d", go_fd) > 0);
    REQUIRE(snprintf(result_fd_text, sizeof(result_fd_text), "%d", result_fd) > 0);
    REQUIRE(snprintf(restart_fd_text, sizeof(restart_fd_text), "%d", restart_fd) > 0);
    if (sync_fd < 0) {
        REQUIRE(snprintf(sync_fd_text, sizeof(sync_fd_text), "none") > 0);
    } else {
        REQUIRE(snprintf(sync_fd_text, sizeof(sync_fd_text), "%d", sync_fd) > 0);
    }
    argv[0] = (char *)g_program_path;
    argv[1] = (char *)"--child";
    argv[2] = (char *)role;
    argv[3] = (char *)socket_path;
    argv[4] = (char *)db_path;
    argv[5] = scenario_text;
    argv[6] = seed_text;
    argv[7] = go_fd_text;
    argv[8] = result_fd_text;
    argv[9] = restart_fd_text;
    argv[10] = sync_fd_text;
    argv[11] = NULL;
    {
        int keep_fds[4];
        int keep_count = 3;
        pid_t pid;

        keep_fds[0] = go_fd;
        keep_fds[1] = result_fd;
        keep_fds[2] = restart_fd;
        if (sync_fd >= 0) {
            keep_fds[3] = sync_fd;
            keep_count = 4;
        }
        pid = fork();
        if (pid < 0) {
            return -1;
        }
        if (pid == 0) {
            close_all_fds_except(keep_fds, keep_count);
            execv(g_program_path, argv);
            _exit(127);
        }
        *out_pid = pid;
        return 0;
    }
}

static int run_scenario_once(uint32_t scenario, uint64_t seed)
{
    char socket_path[1024];
    char ctrl_db[1024];
    char end_db[1024];
    char workdir[512];
    int ctrl_go[2];
    int ctrl_res[2];
    int end_go[2];
    int end_res[2];
    int restart_pipe[2];
    int sync_pipe[2];
    pid_t ctrl_pid;
    pid_t end_pid;
    int status = 0;
    char go = 'G';

    if (getcwd(workdir, sizeof(workdir)) == NULL) {
        return 1;
    }
    REQUIRE(snprintf(socket_path, sizeof(socket_path),
        "%s/direct-1hop-%u.sock", workdir, scenario)
        > 0);
    REQUIRE(snprintf(ctrl_db, sizeof(ctrl_db),
        "%s/direct-1hop-ctrl-%u.db", workdir, scenario)
        > 0);
    REQUIRE(snprintf(end_db, sizeof(end_db),
        "%s/direct-1hop-end-%u.db", workdir, scenario)
        > 0);
    (void)unlink(socket_path);
    (void)unlink(ctrl_db);
    (void)unlink(end_db);

    REQUIRE(pipe(ctrl_go) == 0);
    REQUIRE(pipe(ctrl_res) == 0);
    REQUIRE(pipe(restart_pipe) == 0);
    REQUIRE(pipe(sync_pipe) == 0);

    REQUIRE(spawn_peer("controller", socket_path, ctrl_db, scenario, seed,
        ctrl_go[0], ctrl_res[1], restart_pipe[1], sync_pipe[1], &ctrl_pid) == 0);
    (void)close(ctrl_go[0]);
    (void)close(ctrl_res[1]);
    (void)close(restart_pipe[1]);
    (void)close(sync_pipe[1]);

    REQUIRE(pipe(end_go) == 0);
    REQUIRE(pipe(end_res) == 0);

    REQUIRE(spawn_peer("endpoint", socket_path, end_db, scenario, seed,
        end_go[0], end_res[1], restart_pipe[0], sync_pipe[0], &end_pid) == 0);
    (void)close(end_go[0]);
    (void)close(end_res[1]);
    (void)close(restart_pipe[0]);
    (void)close(sync_pipe[0]);

    REQUIRE(write_byte(ctrl_go[1], go));
    (void)usleep(100000);
    REQUIRE(write_byte(end_go[1], go));
    (void)close(end_go[1]);
    (void)close(ctrl_go[1]);

    char end_ack = 0;
    char ctrl_ack = 0;
    int read_end = 0;
    int read_ctrl = 0;

    read_end = read_byte(end_res[0], &end_ack);
    read_ctrl = read_byte(ctrl_res[0], &ctrl_ack);
    (void)close(end_res[0]);
    (void)close(ctrl_res[0]);

    if (waitpid(end_pid, &status, 0) != end_pid
        || !WIFEXITED(status)
        || WEXITSTATUS(status) != 0) {
        (void)fprintf(stderr, "scenario %u endpoint exit status=%d\n",
            scenario, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return 1;
    }
    if (waitpid(ctrl_pid, &status, 0) != ctrl_pid
        || !WIFEXITED(status)
        || WEXITSTATUS(status) != 0) {
        (void)fprintf(stderr, "scenario %u controller exit status=%d\n",
            scenario, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return 1;
    }
    if (!read_end
        || !read_ctrl
        || end_ack != 'O'
        || ctrl_ack != 'O') {
        (void)fprintf(stderr,
            "scenario %u ack mismatch end=%d/%c ctrl=%d/%c\n",
            scenario,
            read_end,
            read_end ? end_ack : '?',
            read_ctrl,
            read_ctrl ? ctrl_ack : '?');
        return 1;
    }

    (void)unlink(socket_path);
    (void)unlink(ctrl_db);
    (void)unlink(end_db);
    {
        char ready_path[1024];
        if (snprintf(ready_path, sizeof(ready_path),
                "%s/direct-1hop-%u-ready", workdir, scenario)
            > 0) {
            (void)unlink(ready_path);
        }
    }
    return 0;
}

static int run_scenario(uint32_t scenario, uint64_t seed)
{
    uint32_t attempt;

    for (attempt = 0u; attempt < 3u; ++attempt) {
        if (run_scenario_once(scenario, seed) == 0) {
            return 0;
        }
        (void)usleep(100000);
    }
    return 1;
}

static int test_all_scenarios(void)
{
    char workdir[512];
    uint32_t index;

    if (getcwd(workdir, sizeof(workdir)) != NULL) {
        for (index = 1u; index <= 7u; ++index) {
            char path[1024];
            (void)snprintf(path, sizeof(path), "%s/direct-1hop-%u.sock", workdir, index);
            (void)unlink(path);
            (void)snprintf(path, sizeof(path), "%s/direct-1hop-ctrl-%u.db", workdir, index);
            (void)unlink(path);
            (void)snprintf(path, sizeof(path), "%s/direct-1hop-end-%u.db", workdir, index);
            (void)unlink(path);
        }
    }
    if (run_scenario(SCENARIO_HAPPY, 0xB4E2E001ull) != 0) {
        return 1;
    }
    if (run_scenario(SCENARIO_ACK_LOSS, 0xB4E2E002ull) != 0) {
        return 1;
    }
    if (run_scenario(SCENARIO_DATA_LOSS, 0xB4E2E003ull) != 0) {
        return 1;
    }
    if (run_scenario(SCENARIO_TIMEOUT, 0xB4E2E004ull) != 0) {
        return 1;
    }
    if (run_scenario(SCENARIO_RESTART, 0xB4E2E005ull) != 0) {
        return 1;
    }
    if (run_scenario(SCENARIO_DUPLICATE, 0xB4E2E006ull) != 0) {
        return 1;
    }
    if (run_scenario(SCENARIO_LATEST_STATE, 0xB4E2E007ull) != 0) {
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (realpath(argv[0], g_program_path_storage) != NULL) {
        g_program_path = g_program_path_storage;
    } else {
        g_program_path = argv[0];
    }
    if (argc >= 2 && strcmp(argv[1], "--child") == 0) {
        return child_main(argc, argv);
    }
    if (test_all_scenarios() != 0) {
        (void)fprintf(stderr, "v1_direct_1hop_e2e_test failed\n");
        return 1;
    }
    (void)printf("v1_direct_1hop_e2e_test ok\n");
    return 0;
}
