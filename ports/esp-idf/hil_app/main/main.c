/* Executable power-cut HIL firmware. Hardware evidence is intentionally not claimed. */

#include "ninlil/platform.h"
#include "ninlil_port/esp_storage.h"
#include "ninlil_port/esp_storage_flash.h"
#include "esp_storage_hil_observer.h"
#include "esp_storage_private.h"

#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "mbedtls/sha256.h"

#include <stdio.h>
#include <string.h>

static const char *TAG = "ninlil_storage_hil";
static ninlil_port_esp_storage_flash_binding_t *g_binding;
static ninlil_port_esp_storage_t *g_storage;
static const ninlil_storage_ops_t *g_ops;
static const char *g_armed_scenario;
static ninlil_port_esp_storage_hil_event_t g_armed_event;
static int g_boundary_emitted;
static int g_continue_accepted;
static QueueHandle_t g_command_queue;
static QueueHandle_t g_continue_queue;

static const uint8_t HIL_NS[] = {'H', 'I', 'L'};
static const uint8_t KEY_A[] = {'a'};
static const uint8_t KEY_B[] = {'b'};
static const uint8_t KEY_C[] = {'c'};
static const uint8_t OLD_A[] = {'o', 'l', 'd', '-', 'A'};
static const uint8_t OLD_B[] = {'o', 'l', 'd', '-', 'B'};
static const uint8_t NEW_A[] = {
    'n', 'e', 'w', '-', 'A', '-', 'l', 'o', 'n', 'g'};
static const uint8_t NEW_C[] = {'n', 'e', 'w', '-', 'C'};
static const uint8_t SNAPSHOT_DOMAIN[] = "NINLIL-HIL-SNAPSHOT-V1";
static const uint8_t DIRECTORY_DOMAIN[] = "NINLIL-HIL-DIRECTORY-V1";

typedef enum hil_snapshot_state {
    HIL_SNAPSHOT_INVALID = 0,
    HIL_SNAPSHOT_OLD = 1,
    HIL_SNAPSHOT_NEW = 2
} hil_snapshot_state_t;

typedef struct hil_observed_value {
    ninlil_storage_status_t status;
    uint8_t bytes[16];
    uint32_t length;
} hil_observed_value_t;

typedef struct hil_line {
    char text[96];
} hil_line_t;

static ninlil_bytes_view_t view(const uint8_t *data, uint32_t length)
{
    ninlil_bytes_view_t result;
    result.data = data;
    result.length = length;
    return result;
}

static const char *event_name(ninlil_port_esp_storage_hil_event_t event)
{
    switch (event) {
    case NINLIL_PORT_ESP_STORAGE_HIL_DIRECTORY_BEFORE_ERASE:
        return "DIR_BEFORE_ERASE";
    case NINLIL_PORT_ESP_STORAGE_HIL_DIRECTORY_BEFORE_WRITE:
        return "DIR_BEFORE_WRITE";
    case NINLIL_PORT_ESP_STORAGE_HIL_DIRECTORY_BEFORE_SEAL:
        return "DIR_BEFORE_SEAL";
    case NINLIL_PORT_ESP_STORAGE_HIL_DATA_BEFORE_ERASE:
        return "DATA_BEFORE_ERASE";
    case NINLIL_PORT_ESP_STORAGE_HIL_DATA_BEFORE_WRITE:
        return "DATA_BEFORE_WRITE";
    case NINLIL_PORT_ESP_STORAGE_HIL_DATA_AFTER_SYNC_BEFORE_RETURN:
        return "DATA_AFTER_SYNC_BEFORE_RETURN";
    default:
        return "INVALID_EVENT";
    }
}

static int scenario_event(
    const char *scenario,
    ninlil_port_esp_storage_hil_event_t *out_event)
{
    if (scenario == NULL || out_event == NULL) {
        return 0;
    }
    if (strcmp(scenario, "D0") == 0) {
        *out_event = NINLIL_PORT_ESP_STORAGE_HIL_DIRECTORY_BEFORE_ERASE;
    } else if (strcmp(scenario, "D1") == 0) {
        *out_event = NINLIL_PORT_ESP_STORAGE_HIL_DIRECTORY_BEFORE_WRITE;
    } else if (strcmp(scenario, "D2") == 0) {
        *out_event = NINLIL_PORT_ESP_STORAGE_HIL_DIRECTORY_BEFORE_SEAL;
    } else if (strcmp(scenario, "S0") == 0) {
        *out_event = NINLIL_PORT_ESP_STORAGE_HIL_DATA_BEFORE_ERASE;
    } else if (strcmp(scenario, "S1") == 0) {
        *out_event = NINLIL_PORT_ESP_STORAGE_HIL_DATA_BEFORE_WRITE;
    } else if (strcmp(scenario, "S2") == 0) {
        *out_event =
            NINLIL_PORT_ESP_STORAGE_HIL_DATA_AFTER_SYNC_BEFORE_RETURN;
    } else {
        return 0;
    }
    return 1;
}

static int hil_observer(
    void *observer_user,
    ninlil_port_esp_storage_hil_event_t event)
{
    hil_line_t line;
    char expected[96];
    (void)observer_user;
    if (g_armed_scenario == NULL || g_boundary_emitted
        || event != g_armed_event) {
        return 1;
    }
    g_boundary_emitted = 1;
    g_continue_accepted = 0;
    printf("HIL_BOUNDARY %s %s\n",
           g_armed_scenario,
           event_name(event));
    (void)fflush(stdout);
    (void)snprintf(
        expected,
        sizeof(expected),
        "CONTINUE %s %s",
        g_armed_scenario,
        event_name(event));
    if (xQueueReceive(
            g_continue_queue, &line, pdMS_TO_TICKS(15000u))
        != pdPASS) {
        printf("HIL_ERROR continue_timeout %s %s\n",
               g_armed_scenario,
               event_name(event));
        (void)fflush(stdout);
        return 0;
    }
    if (strcmp(line.text, expected) != 0) {
        printf("HIL_ERROR continue_mismatch %s %s\n",
               g_armed_scenario,
               event_name(event));
        (void)fflush(stdout);
        return 0;
    }
    g_continue_accepted = 1;
    printf("HIL_CONTINUE %s %s\n",
           g_armed_scenario,
           event_name(event));
    (void)fflush(stdout);
    if (event
        == NINLIL_PORT_ESP_STORAGE_HIL_DATA_AFTER_SYNC_BEFORE_RETURN) {
        /* Deliberate HIL-only observation window; production has no observer. */
        vTaskDelay(pdMS_TO_TICKS(10000u));
    }
    return 1;
}

static int append_bytes(
    uint8_t *buffer,
    size_t capacity,
    size_t *inout_length,
    const uint8_t *data,
    size_t length)
{
    if (buffer == NULL || inout_length == NULL || data == NULL
        || *inout_length > capacity || length > capacity - *inout_length) {
        return 0;
    }
    if (length != 0u) {
        (void)memcpy(buffer + *inout_length, data, length);
    }
    *inout_length += length;
    return 1;
}

static int append_u16_be(
    uint8_t *buffer,
    size_t capacity,
    size_t *inout_length,
    uint16_t value)
{
    uint8_t bytes[2];
    bytes[0] = (uint8_t)(value >> 8u);
    bytes[1] = (uint8_t)value;
    return append_bytes(buffer, capacity, inout_length, bytes, sizeof(bytes));
}

static int append_u32_be(
    uint8_t *buffer,
    size_t capacity,
    size_t *inout_length,
    uint32_t value)
{
    uint8_t bytes[4];
    bytes[0] = (uint8_t)(value >> 24u);
    bytes[1] = (uint8_t)(value >> 16u);
    bytes[2] = (uint8_t)(value >> 8u);
    bytes[3] = (uint8_t)value;
    return append_bytes(buffer, capacity, inout_length, bytes, sizeof(bytes));
}

static int append_record(
    uint8_t *buffer,
    size_t capacity,
    size_t *inout_length,
    const uint8_t *key,
    uint16_t key_length,
    const uint8_t *value,
    uint32_t value_length)
{
    return append_u16_be(buffer, capacity, inout_length, key_length)
        && append_bytes(buffer, capacity, inout_length, key, key_length)
        && append_u32_be(buffer, capacity, inout_length, value_length)
        && append_bytes(buffer, capacity, inout_length, value, value_length);
}

static int data_snapshot_digest(
    hil_snapshot_state_t state,
    uint8_t out_digest[32])
{
    uint8_t canonical[128];
    uint8_t entry_count = 2u;
    size_t length = 0u;

    if (!append_bytes(
            canonical,
            sizeof(canonical),
            &length,
            SNAPSHOT_DOMAIN,
            sizeof(SNAPSHOT_DOMAIN) - 1u)
        || !append_bytes(
            canonical, sizeof(canonical), &length, &entry_count, 1u)) {
        return 0;
    }
    if (state == HIL_SNAPSHOT_OLD) {
        if (!append_record(
                canonical,
                sizeof(canonical),
                &length,
                KEY_A,
                sizeof(KEY_A),
                OLD_A,
                sizeof(OLD_A))
            || !append_record(
                canonical,
                sizeof(canonical),
                &length,
                KEY_B,
                sizeof(KEY_B),
                OLD_B,
                sizeof(OLD_B))) {
            return 0;
        }
    } else if (state == HIL_SNAPSHOT_NEW) {
        if (!append_record(
                canonical,
                sizeof(canonical),
                &length,
                KEY_A,
                sizeof(KEY_A),
                NEW_A,
                sizeof(NEW_A))
            || !append_record(
                canonical,
                sizeof(canonical),
                &length,
                KEY_C,
                sizeof(KEY_C),
                NEW_C,
                sizeof(NEW_C))) {
            return 0;
        }
    } else {
        return 0;
    }
    return mbedtls_sha256(canonical, length, out_digest, 0) == 0;
}

static int directory_snapshot_digest(
    const char *scenario,
    hil_snapshot_state_t state,
    const uint8_t data_digest[32],
    uint8_t out_digest[32])
{
    uint8_t canonical[96];
    uint8_t state_byte = (uint8_t)state;
    size_t length = 0u;
    if (scenario == NULL || strlen(scenario) != 2u) {
        return 0;
    }
    if (!append_bytes(
            canonical,
            sizeof(canonical),
            &length,
            DIRECTORY_DOMAIN,
            sizeof(DIRECTORY_DOMAIN) - 1u)
        || !append_bytes(
            canonical,
            sizeof(canonical),
            &length,
            (const uint8_t *)scenario,
            2u)
        || !append_bytes(
            canonical, sizeof(canonical), &length, &state_byte, 1u)
        || !append_bytes(
            canonical, sizeof(canonical), &length, data_digest, 32u)) {
        return 0;
    }
    return mbedtls_sha256(canonical, length, out_digest, 0) == 0;
}

static void digest_hex(const uint8_t digest[32], char out_hex[65])
{
    static const char HEX[] = "0123456789abcdef";
    uint32_t index;
    for (index = 0u; index < 32u; ++index) {
        out_hex[index * 2u] = HEX[digest[index] >> 4u];
        out_hex[index * 2u + 1u] = HEX[digest[index] & 0x0fu];
    }
    out_hex[64] = '\0';
}

static ninlil_storage_status_t write_data_snapshot(hil_snapshot_state_t state)
{
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t status;

    status = g_ops->open(
        g_ops->user,
        view(HIL_NS, sizeof(HIL_NS)),
        NINLIL_STORAGE_SCHEMA_M1A,
        &handle);
    if (status != NINLIL_STORAGE_OK) {
        return status;
    }
    status = g_ops->begin(
        g_ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn);
    if (status == NINLIL_STORAGE_OK && state == HIL_SNAPSHOT_OLD) {
        status = g_ops->put(
            g_ops->user,
            txn,
            view(KEY_A, sizeof(KEY_A)),
            view(OLD_A, sizeof(OLD_A)));
        if (status == NINLIL_STORAGE_OK) {
            status = g_ops->put(
                g_ops->user,
                txn,
                view(KEY_B, sizeof(KEY_B)),
                view(OLD_B, sizeof(OLD_B)));
        }
        if (status == NINLIL_STORAGE_OK) {
            status = g_ops->erase(
                g_ops->user, txn, view(KEY_C, sizeof(KEY_C)));
        }
    } else if (status == NINLIL_STORAGE_OK && state == HIL_SNAPSHOT_NEW) {
        status = g_ops->put(
            g_ops->user,
            txn,
            view(KEY_A, sizeof(KEY_A)),
            view(NEW_A, sizeof(NEW_A)));
        if (status == NINLIL_STORAGE_OK) {
            status = g_ops->erase(
                g_ops->user, txn, view(KEY_B, sizeof(KEY_B)));
        }
        if (status == NINLIL_STORAGE_OK) {
            status = g_ops->put(
                g_ops->user,
                txn,
                view(KEY_C, sizeof(KEY_C)),
                view(NEW_C, sizeof(NEW_C)));
        }
    } else if (status == NINLIL_STORAGE_OK) {
        status = NINLIL_STORAGE_CORRUPT;
    }
    if (status == NINLIL_STORAGE_OK) {
        status = g_ops->commit(g_ops->user, txn, NINLIL_DURABILITY_FULL);
        txn = NULL;
    }
    if (txn != NULL) {
        (void)g_ops->rollback(g_ops->user, txn);
    }
    g_ops->close(g_ops->user, handle);
    return status;
}

static void observe_key(
    ninlil_storage_txn_t txn,
    const uint8_t *key,
    uint32_t key_length,
    hil_observed_value_t *out)
{
    ninlil_mut_bytes_t bytes;
    (void)memset(out, 0, sizeof(*out));
    bytes.data = out->bytes;
    bytes.capacity = sizeof(out->bytes);
    bytes.length = 0u;
    out->status = g_ops->get(
        g_ops->user, txn, view(key, key_length), &bytes);
    out->length = bytes.length;
}

static int value_equals(
    const hil_observed_value_t *observed,
    const uint8_t *expected,
    uint32_t expected_length)
{
    return observed->status == NINLIL_STORAGE_OK
        && observed->length == expected_length
        && memcmp(observed->bytes, expected, expected_length) == 0;
}

static int value_absent(const hil_observed_value_t *observed)
{
    return observed->status == NINLIL_STORAGE_NOT_FOUND
        && observed->length == 0u;
}

static int directory_hil_only(void)
{
    uint32_t index;
    uint32_t occupied = 0u;
    uint32_t hil = 0u;
    for (index = 0u; index < g_storage->config.max_namespaces; ++index) {
        if (g_storage->directory.state[index]
            == NINLIL_PORT_ESP_STORAGE_DIR_STATE_FREE) {
            continue;
        }
        if (g_storage->directory.state[index]
                != NINLIL_PORT_ESP_STORAGE_DIR_STATE_OCCUPIED
            || g_storage->directory.data_seed_generation[index] == 0u) {
            return 0;
        }
        occupied += 1u;
        if (g_storage->directory.name_length[index] == sizeof(HIL_NS)
            && memcmp(
                   g_storage->directory.name[index], HIL_NS, sizeof(HIL_NS))
                == 0) {
            hil += 1u;
        }
    }
    return occupied == 1u && hil == 1u;
}

static hil_snapshot_state_t classify_hil_namespace(uint8_t out_digest[32])
{
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_capacity_t capacity;
    hil_observed_value_t a;
    hil_observed_value_t b;
    hil_observed_value_t c;
    hil_snapshot_state_t state = HIL_SNAPSHOT_INVALID;
    ninlil_storage_status_t status;

    status = g_ops->open(
        g_ops->user,
        view(HIL_NS, sizeof(HIL_NS)),
        NINLIL_STORAGE_SCHEMA_M1A,
        &handle);
    if (status != NINLIL_STORAGE_OK || handle == NULL) {
        return HIL_SNAPSHOT_INVALID;
    }
    (void)memset(&capacity, 0, sizeof(capacity));
    capacity.abi_version = NINLIL_ABI_VERSION;
    capacity.struct_size = (uint16_t)sizeof(capacity);
    status = g_ops->capacity(g_ops->user, handle, &capacity);
    if (status == NINLIL_STORAGE_OK) {
        status = g_ops->begin(
            g_ops->user, handle, NINLIL_STORAGE_READ_ONLY, &txn);
    }
    if (status == NINLIL_STORAGE_OK) {
        observe_key(txn, KEY_A, sizeof(KEY_A), &a);
        observe_key(txn, KEY_B, sizeof(KEY_B), &b);
        observe_key(txn, KEY_C, sizeof(KEY_C), &c);
        if (capacity.used_entries == 2u
            && capacity.used_bytes == 44u
            && value_equals(&a, OLD_A, sizeof(OLD_A))
            && value_equals(&b, OLD_B, sizeof(OLD_B))
            && value_absent(&c)) {
            state = HIL_SNAPSHOT_OLD;
        } else if (capacity.used_entries == 2u
            && capacity.used_bytes == 49u
            && value_equals(&a, NEW_A, sizeof(NEW_A))
            && value_absent(&b)
            && value_equals(&c, NEW_C, sizeof(NEW_C))) {
            state = HIL_SNAPSHOT_NEW;
        }
    }
    if (txn != NULL) {
        (void)g_ops->rollback(g_ops->user, txn);
    }
    g_ops->close(g_ops->user, handle);
    if (state != HIL_SNAPSHOT_INVALID
        && !data_snapshot_digest(state, out_digest)) {
        return HIL_SNAPSHOT_INVALID;
    }
    return state;
}

static hil_snapshot_state_t classify_data_snapshot(uint8_t out_digest[32])
{
    if (!directory_hil_only()) {
        return HIL_SNAPSHOT_INVALID;
    }
    return classify_hil_namespace(out_digest);
}

static void scenario_namespace(const char *scenario, uint8_t out_ns[6])
{
    out_ns[0] = 'H';
    out_ns[1] = 'I';
    out_ns[2] = 'L';
    out_ns[3] = '-';
    out_ns[4] = (uint8_t)scenario[0];
    out_ns[5] = (uint8_t)scenario[1];
}

/* -1 invalid directory, 0 scenario absent, 1 scenario present exactly once. */
static int directory_scenario_presence(const char *scenario)
{
    uint8_t ns[6];
    uint32_t index;
    uint32_t occupied = 0u;
    uint32_t hil = 0u;
    uint32_t scenario_count = 0u;
    scenario_namespace(scenario, ns);
    for (index = 0u; index < g_storage->config.max_namespaces; ++index) {
        if (g_storage->directory.state[index]
            == NINLIL_PORT_ESP_STORAGE_DIR_STATE_FREE) {
            continue;
        }
        if (g_storage->directory.state[index]
                != NINLIL_PORT_ESP_STORAGE_DIR_STATE_OCCUPIED
            || g_storage->directory.data_seed_generation[index] == 0u) {
            return -1;
        }
        occupied += 1u;
        if (g_storage->directory.name_length[index] == sizeof(HIL_NS)
            && memcmp(
                   g_storage->directory.name[index], HIL_NS, sizeof(HIL_NS))
                == 0) {
            hil += 1u;
        } else if (g_storage->directory.name_length[index] == sizeof(ns)
            && memcmp(g_storage->directory.name[index], ns, sizeof(ns)) == 0) {
            scenario_count += 1u;
        } else {
            return -1;
        }
    }
    if (hil != 1u || scenario_count > 1u
        || occupied != 1u + scenario_count) {
        return -1;
    }
    return scenario_count == 1u ? 1 : 0;
}

static int namespace_is_empty_existing(const uint8_t *ns, uint32_t ns_length)
{
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_capacity_t capacity;
    ninlil_storage_status_t status;
    status = g_ops->open(
        g_ops->user,
        view(ns, ns_length),
        NINLIL_STORAGE_SCHEMA_M1A,
        &handle);
    if (status != NINLIL_STORAGE_OK || handle == NULL) {
        return 0;
    }
    (void)memset(&capacity, 0, sizeof(capacity));
    capacity.abi_version = NINLIL_ABI_VERSION;
    capacity.struct_size = (uint16_t)sizeof(capacity);
    status = g_ops->capacity(g_ops->user, handle, &capacity);
    g_ops->close(g_ops->user, handle);
    return status == NINLIL_STORAGE_OK && capacity.used_entries == 0u
        && capacity.used_bytes == 0u;
}

static hil_snapshot_state_t classify_directory_snapshot(
    const char *scenario,
    uint8_t out_digest[32])
{
    uint8_t data_digest[32];
    uint8_t ns[6];
    int presence = directory_scenario_presence(scenario);
    if (presence < 0
        || classify_hil_namespace(data_digest) != HIL_SNAPSHOT_OLD) {
        return HIL_SNAPSHOT_INVALID;
    }
    if (presence == 0) {
        return directory_snapshot_digest(
                   scenario, HIL_SNAPSHOT_OLD, data_digest, out_digest)
            ? HIL_SNAPSHOT_OLD
            : HIL_SNAPSHOT_INVALID;
    }
    scenario_namespace(scenario, ns);
    if (!namespace_is_empty_existing(ns, sizeof(ns))) {
        return HIL_SNAPSHOT_INVALID;
    }
    return directory_snapshot_digest(
               scenario, HIL_SNAPSHOT_NEW, data_digest, out_digest)
        ? HIL_SNAPSHOT_NEW
        : HIL_SNAPSHOT_INVALID;
}

static ninlil_storage_status_t create_directory_scenario(const char *scenario)
{
    uint8_t ns[6];
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_status_t status;
    scenario_namespace(scenario, ns);
    status = g_ops->open(
        g_ops->user, view(ns, sizeof(ns)), NINLIL_STORAGE_SCHEMA_M1A, &handle);
    if (handle != NULL) {
        g_ops->close(g_ops->user, handle);
    }
    return status;
}

static void print_snapshot_result(
    const char *scenario,
    ninlil_port_esp_storage_hil_event_t event,
    hil_snapshot_state_t state,
    const uint8_t digest[32])
{
    char hex[65];
    if (state == HIL_SNAPSHOT_INVALID) {
        printf("HIL_RESULT %s %s INVALID -\n",
               scenario,
               event_name(event));
        return;
    }
    digest_hex(digest, hex);
    printf("HIL_RESULT %s %s %s %s\n",
           scenario,
           event_name(event),
           state == HIL_SNAPSHOT_OLD ? "OLD" : "NEW",
           hex);
}

static void run_command(const char *command)
{
    if (strcmp(command, "BASELINE") == 0) {
        uint8_t digest[32];
        char hex[65];
        ninlil_storage_status_t status = write_data_snapshot(HIL_SNAPSHOT_OLD);
        hil_snapshot_state_t state = classify_data_snapshot(digest);
        if (state != HIL_SNAPSHOT_OLD
            || status != NINLIL_STORAGE_COMMIT_UNKNOWN) {
            printf("HIL_BASELINE INVALID - status=%u\n", (unsigned)status);
        } else {
            digest_hex(digest, hex);
            printf("HIL_BASELINE OLD %s COMMIT_UNKNOWN\n", hex);
        }
    } else if (strncmp(command, "ARM ", 4u) == 0) {
        const char *scenario = command + 4u;
        ninlil_storage_status_t status;
        if (!scenario_event(scenario, &g_armed_event)) {
            printf("HIL_ERROR invalid_scenario\n");
            (void)fflush(stdout);
            return;
        }
        g_armed_scenario = scenario;
        g_boundary_emitted = 0;
        g_continue_accepted = 0;
        if (scenario[0] == 'D') {
            status = create_directory_scenario(scenario);
        } else {
            status = write_data_snapshot(HIL_SNAPSHOT_NEW);
        }
        printf("HIL_COMMIT %s %s status=%u boundary=%u continued=%u\n",
               scenario,
               event_name(g_armed_event),
               (unsigned)status,
               (unsigned)g_boundary_emitted,
               (unsigned)g_continue_accepted);
        g_armed_scenario = NULL;
        g_armed_event = (ninlil_port_esp_storage_hil_event_t)0;
    } else if (strncmp(command, "VERIFY ", 7u) == 0) {
        uint8_t digest[32] = {0};
        const char *scenario = command + 7u;
        ninlil_port_esp_storage_hil_event_t event;
        hil_snapshot_state_t state;
        if (!scenario_event(scenario, &event)) {
            printf("HIL_ERROR invalid_scenario\n");
            (void)fflush(stdout);
            return;
        }
        state = scenario[0] == 'D'
            ? classify_directory_snapshot(scenario, digest)
            : classify_data_snapshot(digest);
        print_snapshot_result(scenario, event, state, digest);
    } else {
        printf("HIL_ERROR unknown_command\n");
    }
    (void)fflush(stdout);
}

static void cleanup(void)
{
    if (g_binding != NULL) {
        ninlil_port_esp_storage_flash_unbind(g_binding);
    }
    g_binding = NULL;
    g_storage = NULL;
    g_ops = NULL;
    if (g_command_queue != NULL) {
        vQueueDelete(g_command_queue);
        g_command_queue = NULL;
    }
    if (g_continue_queue != NULL) {
        vQueueDelete(g_continue_queue);
        g_continue_queue = NULL;
    }
}

static void serial_reader_task(void *argument)
{
    hil_line_t line;
    (void)argument;
    while (fgets(line.text, sizeof(line.text), stdin) != NULL) {
        size_t length = strlen(line.text);
        QueueHandle_t destination;
        while (length != 0u
               && (line.text[length - 1u] == '\n'
                   || line.text[length - 1u] == '\r')) {
            line.text[--length] = '\0';
        }
        destination = strncmp(line.text, "CONTINUE ", 9u) == 0
            ? g_continue_queue
            : g_command_queue;
        if (xQueueSend(destination, &line, pdMS_TO_TICKS(1000u)) != pdPASS) {
            printf("HIL_ERROR input_queue_full\n");
            (void)fflush(stdout);
        }
    }
    (void)memset(&line, 0, sizeof(line));
    (void)xQueueSend(g_command_queue, &line, 0u);
    vTaskDelete(NULL);
}

void app_main(void)
{
    ninlil_port_esp_storage_config_t config;
    hil_line_t command;
    uint64_t boot_nonce;

    (void)setvbuf(stdin, NULL, _IONBF, 0);
    (void)setvbuf(stdout, NULL, _IONBF, 0);
    ninlil_port_esp_storage_config_production(&config);
    if (ninlil_port_esp_storage_flash_bind(
            "ninlil_st", &config, &g_binding, &g_ops)
        != 0) {
        ESP_LOGE(TAG, "wear-levelled storage bind failed");
        cleanup();
        return;
    }
    g_storage = &g_binding->storage;
    if (g_ops == NULL
        || ninlil_port_esp_storage_flash_set_hil_observer(
               g_binding, hil_observer, NULL)
            != 0) {
        ESP_LOGE(TAG, "HIL observer installation failed");
        cleanup();
        return;
    }
    g_command_queue = xQueueCreate(4u, sizeof(hil_line_t));
    g_continue_queue = xQueueCreate(2u, sizeof(hil_line_t));
    if (g_command_queue == NULL || g_continue_queue == NULL
        || xTaskCreate(
               serial_reader_task,
               "hil_serial_rx",
               4096u,
               NULL,
               tskIDLE_PRIORITY + 1u,
               NULL)
            != pdPASS) {
        ESP_LOGE(TAG, "HIL serial queue/task allocation failed");
        cleanup();
        return;
    }
    do {
        boot_nonce = ((uint64_t)esp_random() << 32u) | esp_random();
    } while (boot_nonce == 0u);
    printf("HIL_READY format=%u policy=ESP_UNPROVEN protocol=3 "
           "boot_nonce=%016llx reset_reason=%u\n",
           (unsigned)NINLIL_PORT_ESP_STORAGE_FORMAT_VERSION,
           (unsigned long long)boot_nonce,
           (unsigned)esp_reset_reason());
    while (xQueueReceive(g_command_queue, &command, portMAX_DELAY) == pdPASS) {
        if (command.text[0] == '\0') {
            break;
        }
        run_command(command.text);
    }
    cleanup();
}
