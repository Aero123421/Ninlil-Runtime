/*
 * V1-LAB item 10b: 2-process loopback uplink for Display / Leak node examples.
 * Derived from tests/runtime/v1_direct_1hop_e2e_test.c (scenario 7 pattern).
 */

#include "v1_lab_loopback_uplink.h"

#include "ninlil_posix_lab_platform.h"
#include "ninlil_posix_lab_platform_test.h"
#include "ninlil_posix_loopback_bearer.h"
#include "runtime_lifecycle_model.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define REQUIRE(c)                                                             \
    do {                                                                       \
        if (!(c)) {                                                            \
            return 0;                                                          \
        }                                                                      \
    } while (0)

#define UPLINK_SCENARIO_LATEST 1u
#define UPLINK_SCENARIO_MEASUREMENT 2u

static const uint8_t CTRL_NS[] = "v1-lab-uplink-ctrl";
static const uint8_t END_NS[] = "v1-lab-uplink-end";
static const char NS_TEXT[] = "org.ninlil.examples";
static const char *g_program_path;

static uint32_t g_delivery_calls;

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

static ninlil_service_descriptor_t uplink_descriptor(
    ninlil_family_t family,
    uint8_t app_tag,
    const char *service_id)
{
    ninlil_service_descriptor_t descriptor;

    (void)memset(&descriptor, 0, sizeof(descriptor));
    set_header(&descriptor.abi_version, &descriptor.struct_size, sizeof(descriptor));
    descriptor.namespace_id.data = (const uint8_t *)NS_TEXT;
    descriptor.namespace_id.length = sizeof(NS_TEXT) - 1u;
    descriptor.service_id.data = (const uint8_t *)service_id;
    descriptor.service_id.length = strlen(service_id);
    descriptor.schema_id.data = (const uint8_t *)service_id;
    descriptor.schema_id.length = strlen(service_id);
    descriptor.descriptor_revision = 1u;
    set_digest(&descriptor.descriptor_digest, 0x31u);
    set_id(&descriptor.local_application_instance_id, app_tag);
    descriptor.schema_major = 1u;
    descriptor.family = family;
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

static int write_byte(int fd, char value)
{
    return write(fd, &value, 1) == 1;
}

static int read_byte(int fd, char *out)
{
    return read(fd, out, 1) == 1;
}

static uint32_t family_to_scenario(ninlil_family_t family)
{
    if (family == NINLIL_FAMILY_MEASUREMENT_RESERVED) {
        return UPLINK_SCENARIO_MEASUREMENT;
    }
    return UPLINK_SCENARIO_LATEST;
}

static const char *family_service_id(ninlil_family_t family)
{
    if (family == NINLIL_FAMILY_MEASUREMENT_RESERVED) {
        return "leak-measurement";
    }
    return "latest-state";
}

static int platform_config_for_role(
    ninlil_posix_lab_platform_config_t *config,
    ninlil_role_t role,
    const char *socket_path,
    const char *db_path,
    uint64_t seed)
{
    ninlil_posix_lab_platform_config_defaults(config);
    config->database_path = db_path;
    config->role = role;
    config->inject_seed = seed;
    config->bearer_kind = NINLIL_POSIX_LAB_PLATFORM_BEARER_LOOPBACK;
    config->loopback_socket_path = socket_path;
    config->loopback_role = role == NINLIL_ROLE_CONTROLLER
        ? NINLIL_POSIX_LOOPBACK_BEARER_ROLE_SERVER
        : NINLIL_POSIX_LOOPBACK_BEARER_ROLE_CLIENT;
    return 1;
}

static int run_endpoint_child(
    uint32_t scenario,
    const char *socket_path,
    const char *db_path,
    ninlil_family_t family,
    uint64_t seed,
    int go_fd,
    int result_fd,
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
    static const uint8_t idem_key[] = "v1-lab-uplink-idem";
    uint8_t payload[8];
    char gate = 0;
    uint32_t step;

    g_delivery_calls = 0u;
    if (!read_byte(go_fd, &gate) || gate != 'G') {
        (void)write_byte(result_fd, 'F');
        return 2;
    }
    platform_config_for_role(
        &pconfig, NINLIL_ROLE_ENDPOINT, socket_path, db_path, seed);
    platform = ninlil_posix_lab_platform_create(&pconfig);
    if (platform == NULL) {
        (void)write_byte(result_fd, 'F');
        return 3;
    }
    config = runtime_config(NINLIL_ROLE_ENDPOINT, END_NS, sizeof(END_NS) - 1u, 0x21u);
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
    descriptor = uplink_descriptor(family, 0x81u, family_service_id(family));
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
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
    (void)memset(payload, 0x4cu, sizeof(payload));
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
    submission.idempotency_key.data = idem_key;
    submission.idempotency_key.length = sizeof(idem_key) - 1u;
    submission.payload.data = payload;
    submission.payload.length = sizeof(payload);
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
        char ready_path[512];
        int ready_fd;
        if (getcwd(workdir, sizeof(workdir)) == NULL
            || snprintf(ready_path, sizeof(ready_path),
                   "%s/v1-lab-uplink-%u-ready", workdir, scenario)
                <= 0) {
            (void)ninlil_runtime_destroy(runtime);
            ninlil_posix_lab_platform_destroy(platform);
            (void)write_byte(result_fd, 'F');
            return 12;
        }
        ready_fd = open(ready_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (ready_fd < 0 || write(ready_fd, "S", 1) != 1 || close(ready_fd) != 0) {
            (void)ninlil_runtime_destroy(runtime);
            ninlil_posix_lab_platform_destroy(platform);
            (void)write_byte(result_fd, 'F');
            return 12;
        }
    }
    for (step = 0u; step < 512u; ++step) {
        fill_step_budget(&budget);
        (void)memset(&step_result, 0, sizeof(step_result));
        (void)ninlil_runtime_step(runtime, &budget, &step_result);
        if (family == NINLIL_FAMILY_MEASUREMENT_RESERVED
            && ninlil_posix_lab_platform_test_inject_send_count(platform) >= 1u) {
            break;
        }
        if (ninlil_posix_lab_platform_test_inject_send_count(platform) >= 1u
            && ninlil_posix_lab_platform_test_inject_recv_count(platform) >= 1u) {
            break;
        }
        if (step > 8u) {
            ninlil_test_clock_t *clock =
                ninlil_posix_lab_platform_test_clock(platform);
            if (clock != NULL) {
                (void)ninlil_test_clock_advance(clock, 400u);
            }
        }
    }
    if (family == NINLIL_FAMILY_MEASUREMENT_RESERVED) {
        if (ninlil_posix_lab_platform_test_inject_send_count(platform) < 1u) {
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

static int run_controller_child(
    uint32_t scenario,
    const char *socket_path,
    const char *db_path,
    ninlil_family_t family,
    uint64_t seed,
    int go_fd,
    int result_fd,
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
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    char gate = 0;
    uint32_t step;

    g_delivery_calls = 0u;
    if (!read_byte(go_fd, &gate) || gate != 'G') {
        (void)write_byte(result_fd, 'F');
        return 2;
    }
    platform_config_for_role(
        &pconfig, NINLIL_ROLE_CONTROLLER, socket_path, db_path, seed);
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
    descriptor = uplink_descriptor(family, 0x70u, family_service_id(family));
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    callbacks.on_delivery = endpoint_delivery_cb;
    callbacks.on_reconcile = endpoint_reconcile_cb;
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
    if (sync_fd >= 0) {
        (void)write_byte(sync_fd, 'R');
    }
    if (family == NINLIL_FAMILY_MEASUREMENT_RESERVED) {
        char workdir[512];
        char ready_path[512];
        uint32_t wait;
        if (getcwd(workdir, sizeof(workdir)) == NULL
            || snprintf(ready_path, sizeof(ready_path),
                   "%s/v1-lab-uplink-%u-ready", workdir, scenario)
                <= 0) {
            (void)write_byte(result_fd, 'F');
            (void)ninlil_runtime_destroy(runtime);
            ninlil_posix_lab_platform_destroy(platform);
            return 8;
        }
        for (wait = 0u; wait < 2000u; ++wait) {
            if (access(ready_path, F_OK) == 0) {
                break;
            }
            (void)usleep(1000);
        }
        (void)unlink(ready_path);
        (void)write_byte(result_fd, 'O');
        (void)ninlil_runtime_destroy(runtime);
        ninlil_posix_lab_platform_destroy(platform);
        return 0;
    }
    {
        char workdir[512];
        char ready_path[512];
        uint32_t wait;
        if (getcwd(workdir, sizeof(workdir)) == NULL
            || snprintf(ready_path, sizeof(ready_path),
                   "%s/v1-lab-uplink-%u-ready", workdir, scenario)
                <= 0) {
            (void)write_byte(result_fd, 'F');
            (void)ninlil_runtime_destroy(runtime);
            ninlil_posix_lab_platform_destroy(platform);
            return 8;
        }
        for (wait = 0u; wait < 2000u; ++wait) {
            if (access(ready_path, F_OK) == 0) {
                break;
            }
            (void)usleep(1000);
        }
        if (access(ready_path, F_OK) != 0) {
            (void)write_byte(result_fd, 'F');
            (void)ninlil_runtime_destroy(runtime);
            ninlil_posix_lab_platform_destroy(platform);
            return 8;
        }
        (void)unlink(ready_path);
    }
    for (step = 0u; step < 512u; ++step) {
        fill_step_budget(&budget);
        (void)memset(&step_result, 0, sizeof(step_result));
        (void)ninlil_runtime_step(runtime, &budget, &step_result);
        if (g_delivery_calls >= 1u) {
            break;
        }
        if (step > 8u) {
            ninlil_test_clock_t *clock =
                ninlil_posix_lab_platform_test_clock(platform);
            if (clock != NULL) {
                (void)ninlil_test_clock_advance(clock, 400u);
            }
        }
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

static int spawn_peer(
    const char *role,
    const char *socket_path,
    const char *db_path,
    uint32_t scenario,
    ninlil_family_t family,
    uint64_t seed,
    int go_fd,
    int result_fd,
    int sync_fd,
    pid_t *out_pid)
{
    char scenario_text[16];
    char family_text[16];
    char seed_text[32];
    char go_fd_text[16];
    char result_fd_text[16];
    char sync_fd_text[16];
    char *argv[12];
    int keep_fds[3];
    int keep_count = 2;
    pid_t pid;

    if (snprintf(scenario_text, sizeof(scenario_text), "%u", scenario) <= 0
        || snprintf(family_text, sizeof(family_text), "%u", (unsigned)family) <= 0
        || snprintf(seed_text, sizeof(seed_text), "%llu", (unsigned long long)seed)
            <= 0
        || snprintf(go_fd_text, sizeof(go_fd_text), "%d", go_fd) <= 0
        || snprintf(result_fd_text, sizeof(result_fd_text), "%d", result_fd) <= 0) {
        return -1;
    }
    if (sync_fd < 0) {
        if (snprintf(sync_fd_text, sizeof(sync_fd_text), "none") <= 0) {
            return -1;
        }
    } else if (snprintf(sync_fd_text, sizeof(sync_fd_text), "%d", sync_fd) <= 0) {
        return -1;
    }
    argv[0] = (char *)g_program_path;
    argv[1] = (char *)"--child";
    argv[2] = (char *)role;
    argv[3] = (char *)socket_path;
    argv[4] = (char *)db_path;
    argv[5] = scenario_text;
    argv[6] = family_text;
    argv[7] = seed_text;
    argv[8] = go_fd_text;
    argv[9] = result_fd_text;
    argv[10] = sync_fd_text;
    argv[11] = NULL;
    keep_fds[0] = go_fd;
    keep_fds[1] = result_fd;
    if (sync_fd >= 0) {
        keep_fds[2] = sync_fd;
        keep_count = 3;
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

static int parse_u64(const char *text, uint64_t *out)
{
    char *end = NULL;
    unsigned long long value;
    if (text == NULL || out == NULL) {
        return 0;
    }
    value = strtoull(text, &end, 10);
    if (end == text || *end != '\0') {
        return 0;
    }
    *out = (uint64_t)value;
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

int v1_lab_loopback_uplink_child_main(int argc, char **argv)
{
    uint32_t scenario;
    uint32_t family_u32;
    uint64_t seed;
    int go_fd;
    int result_fd;
    int sync_fd;
    ninlil_family_t family;

    if (argc < 11 || strcmp(argv[1], "--child") != 0) {
        return 126;
    }
    if (!parse_u32(argv[5], &scenario) || !parse_u32(argv[6], &family_u32)
        || !parse_u64(argv[7], &seed)
        || !parse_fd(argv[8], &go_fd) || !parse_fd(argv[9], &result_fd)
        || !parse_fd(argv[10], &sync_fd)) {
        return 126;
    }
    family = (ninlil_family_t)family_u32;
    if (strcmp(argv[2], "endpoint") == 0) {
        return run_endpoint_child(
            scenario, argv[3], argv[4], family, seed, go_fd, result_fd, sync_fd);
    }
    if (strcmp(argv[2], "controller") == 0) {
        return run_controller_child(
            scenario, argv[3], argv[4], family, seed, go_fd, result_fd, sync_fd);
    }
    return 126;
}

static int run_once(ninlil_family_t family, uint64_t seed)
{
    char socket_path[512];
    char ctrl_db[512];
    char end_db[512];
    char workdir[512];
    uint32_t scenario = family_to_scenario(family);
    int ctrl_go[2];
    int ctrl_res[2];
    int end_go[2];
    int end_res[2];
    int sync_pipe[2];
    pid_t ctrl_pid;
    pid_t end_pid;
    int status = 0;
    char go = 'G';
    char end_ack = 0;
    char ctrl_ack = 0;
    int read_end;
    int read_ctrl;

    if (getcwd(workdir, sizeof(workdir)) == NULL) {
        return 0;
    }
    if (snprintf(socket_path, sizeof(socket_path),
            "%s/v1-lab-uplink-%u.sock", workdir, scenario)
            <= 0
        || snprintf(ctrl_db, sizeof(ctrl_db),
               "%s/v1-lab-uplink-ctrl-%u.db", workdir, scenario)
            <= 0
        || snprintf(end_db, sizeof(end_db),
               "%s/v1-lab-uplink-end-%u.db", workdir, scenario)
            <= 0) {
        return 0;
    }
    (void)unlink(socket_path);
    (void)unlink(ctrl_db);
    (void)unlink(end_db);

    if (pipe(ctrl_go) != 0 || pipe(ctrl_res) != 0 || pipe(end_go) != 0
        || pipe(end_res) != 0 || pipe(sync_pipe) != 0) {
        return 0;
    }
    if (spawn_peer("controller", socket_path, ctrl_db, scenario, family, seed,
            ctrl_go[0], ctrl_res[1], sync_pipe[1], &ctrl_pid)
            != 0
        || spawn_peer("endpoint", socket_path, end_db, scenario, family, seed,
               end_go[0], end_res[1], sync_pipe[0], &end_pid)
            != 0) {
        return 0;
    }
    (void)close(ctrl_go[0]);
    (void)close(ctrl_res[1]);
    (void)close(end_go[0]);
    (void)close(end_res[1]);
    (void)close(sync_pipe[0]);
    (void)close(sync_pipe[1]);
    if (!write_byte(end_go[1], go) || !write_byte(ctrl_go[1], go)) {
        return 0;
    }
    (void)close(end_go[1]);
    (void)close(ctrl_go[1]);
    read_end = read_byte(end_res[0], &end_ack);
    (void)close(end_res[0]);
    read_ctrl = read_byte(ctrl_res[0], &ctrl_ack);
    (void)close(ctrl_res[0]);
    if (waitpid(end_pid, &status, 0) != end_pid || !WIFEXITED(status)
        || WEXITSTATUS(status) != 0) {
        return 0;
    }
    if (waitpid(ctrl_pid, &status, 0) != ctrl_pid || !WIFEXITED(status)
        || WEXITSTATUS(status) != 0) {
        return 0;
    }
    if (!read_end || !read_ctrl || end_ack != 'O' || ctrl_ack != 'O') {
        return 0;
    }
    (void)unlink(socket_path);
    (void)unlink(ctrl_db);
    (void)unlink(end_db);
    return 1;
}

int v1_lab_loopback_uplink_run(
    const char *program_path,
    ninlil_family_t family,
    uint64_t seed)
{
    uint32_t attempt;
    if (program_path == NULL) {
        return 0;
    }
    g_program_path = program_path;
    for (attempt = 0u; attempt < 3u; ++attempt) {
        if (run_once(family, seed)) {
            return 1;
        }
        (void)usleep(100000);
    }
    return 0;
}
