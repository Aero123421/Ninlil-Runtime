/*
 * ESP32-S3 Wi-Fi STA: sole driver owner, WIFI_STORAGE_RAM.
 * Callbacks enqueue fixed records only — no owner state mutation.
 * Secrets never logged. Private candidate.
 */
#include "wifi_esp_sta.h"

#include "wifi_esp_events.h"
#include "wifi_sha256.h"

#include <string.h>

typedef struct sta_network_material {
    wifi_network_credential_metadata_v1_t metadata;
    uint8_t secret[WIFI_NETCRED_SECRET_BYTES];
    const wifi_network_credential_provider_ops_v1_t *provider;
    ninlil_id128_t profile_id;
    int acquired;
} sta_network_material_t;

static int bytes_zero(const uint8_t *p, size_t n)
{
    size_t i;
    if (p == NULL) {
        return 1;
    }
    for (i = 0u; i < n; ++i) {
        if (p[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static void secure_zero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n > 0u) {
        *v++ = 0u;
        n -= 1u;
    }
}

static void put_u64_be(uint8_t *p, uint64_t v)
{
    uint32_t i;
    for (i = 0u; i < 8u; ++i) {
        p[7u - i] = (uint8_t)(v >> (8u * i));
    }
}

static int network_profile_digest_ok(
    const wifi_network_credential_metadata_v1_t *m)
{
    static const uint8_t tag[] = "NINLIL-WIFI-NETWORK-PROFILE-V1";
    uint8_t canonical[192];
    uint8_t digest[32];
    size_t n = 0u;
    (void)memcpy(canonical + n, tag, sizeof(tag) - 1u);
    n += sizeof(tag) - 1u;
    (void)memcpy(canonical + n, m->profile_id.bytes, 16u);
    n += 16u;
    put_u64_be(canonical + n, m->revision);
    n += 8u;
    (void)memset(canonical + n, 0, 32u);
    n += 32u;
    (void)memcpy(canonical + n, m->credential_binding_id.bytes, 16u);
    n += 16u;
    canonical[n++] = m->ssid_length;
    (void)memcpy(canonical + n, m->ssid, 32u);
    n += 32u;
    canonical[n++] = m->auth_mode;
    canonical[n++] = m->password_length;
    canonical[n++] = m->pmf_required;
    canonical[n++] = m->optional_bssid_present;
    (void)memcpy(canonical + n, m->bssid, 6u);
    n += 6u;
    canonical[n++] = m->channel;
    (void)memcpy(canonical + n, m->reserved_zero, 7u);
    n += 7u;
    ninlil_wifi_sha256(canonical, n, digest);
    secure_zero(canonical, sizeof(canonical));
    return memcmp(digest, m->digest, 32u) == 0;
}

static int ascii_hex(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0u; i < n; ++i) {
        uint8_t c = p[i];
        if (!((c >= (uint8_t)'0' && c <= (uint8_t)'9')
              || (c >= (uint8_t)'a' && c <= (uint8_t)'f')
              || (c >= (uint8_t)'A' && c <= (uint8_t)'F'))) {
            return 0;
        }
    }
    return 1;
}

static int material_valid(
    const ninlil_wifi_esp_sta_config_t *cfg,
    const sta_network_material_t *mat)
{
    const wifi_network_credential_metadata_v1_t *m = &mat->metadata;
    size_t i;
    if (m->api_version != NINLIL_WIFI_PRIVATE_API_VERSION
        || m->struct_size != (uint16_t)sizeof(*m)
        || memcmp(m->profile_id.bytes, cfg->network_profile_id.bytes, 16u) != 0
        || m->revision != cfg->network_profile_revision
        || memcmp(m->digest, cfg->network_profile_digest, 32u) != 0
        || bytes_zero(m->credential_binding_id.bytes, 16u)
        || m->ssid_length == 0u || m->ssid_length > 32u
        || (m->auth_mode != WIFI_NETCRED_AUTH_WPA2_PSK
            && m->auth_mode != WIFI_NETCRED_AUTH_WPA3_SAE
            && m->auth_mode != WIFI_NETCRED_AUTH_WPA2_WPA3_TRANSITION)
        || m->pmf_required != 1u || m->optional_bssid_present > 1u
        || m->channel > 14u || !bytes_zero(m->reserved_zero, 7u)
        || !network_profile_digest_ok(m)) {
        return 0;
    }
    for (i = m->ssid_length; i < sizeof(m->ssid); ++i) {
        if (m->ssid[i] != 0u) {
            return 0;
        }
    }
    if (m->password_length < 8u || m->password_length > 64u) {
        return 0;
    }
    for (i = 0u; i < m->password_length; ++i) {
        if (mat->secret[i] == 0u) {
            return 0;
        }
    }
    for (i = m->password_length; i < sizeof(mat->secret); ++i) {
        if (mat->secret[i] != 0u) {
            return 0;
        }
    }
    if (m->password_length == 64u
        && !ascii_hex(mat->secret, sizeof(mat->secret))) {
        return 0;
    }
    if (m->optional_bssid_present == 0u) {
        if (!bytes_zero(m->bssid, 6u)) {
            return 0;
        }
    } else if (
        bytes_zero(m->bssid, 6u) || (m->bssid[0] & 1u) != 0u) {
        return 0;
    }
    return 1;
}

static ninlil_wifi_status_t provider_status(
    wifi_network_credential_status_v1_t status)
{
    if (status == WIFI_NETCRED_NOT_FOUND
        || status == WIFI_NETCRED_TEMPORARY) {
        return NINLIL_WIFI_UNAVAILABLE;
    }
    if (status == WIFI_NETCRED_CAPACITY) {
        return NINLIL_WIFI_CAPACITY;
    }
    if (status == WIFI_NETCRED_PERMANENT) {
        return NINLIL_WIFI_CREDENTIAL;
    }
    return NINLIL_WIFI_CORRUPT;
}

static ninlil_wifi_status_t network_material_acquire(
    const ninlil_wifi_esp_sta_config_t *cfg,
    sta_network_material_t *out)
{
    wifi_network_credential_status_v1_t status;
    const wifi_network_credential_provider_ops_v1_t *provider;
    if (cfg == NULL || out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    (void)memset(out, 0, sizeof(*out));
    provider = cfg->credential_provider;
    if (cfg->connect_timeout_ms != 0u
        || bytes_zero(cfg->network_profile_id.bytes, 16u)
        || cfg->network_profile_revision == 0u
        || bytes_zero(cfg->network_profile_digest, 32u) || provider == NULL
        || provider->api_version != NINLIL_WIFI_PRIVATE_API_VERSION
        || provider->struct_size != (uint16_t)sizeof(*provider)
        || provider->get == NULL || provider->release == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    out->provider = provider;
    out->profile_id = cfg->network_profile_id;
    status = provider->get(
        provider->user,
        &cfg->network_profile_id,
        cfg->network_profile_revision,
        cfg->network_profile_digest,
        &out->metadata,
        out->secret);
    if (status != WIFI_NETCRED_OK) {
        if (!bytes_zero((const uint8_t *)&out->metadata, sizeof(out->metadata))
            || !bytes_zero(out->secret, sizeof(out->secret))) {
            secure_zero(out, sizeof(*out));
            return NINLIL_WIFI_CORRUPT;
        }
        secure_zero(out, sizeof(*out));
        return provider_status(status);
    }
    out->acquired = 1;
    if (!material_valid(cfg, out)) {
        secure_zero(out->secret, sizeof(out->secret));
        provider->release(
            provider->user, &out->profile_id, out->secret);
        secure_zero(out, sizeof(*out));
        return NINLIL_WIFI_CREDENTIAL;
    }
    return NINLIL_WIFI_OK;
}

static void network_material_release(sta_network_material_t *material)
{
    if (material == NULL) {
        return;
    }
    if (material->acquired && material->provider != NULL) {
        /* ADR-0018: zero caller secret before the exact-one release callback. */
        secure_zero(material->secret, sizeof(material->secret));
        material->provider->release(
            material->provider->user,
            &material->profile_id,
            material->secret);
    }
    secure_zero(material, sizeof(*material));
}

#if defined(ESP_PLATFORM)

#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "lwip/ip_addr.h"

struct ninlil_wifi_esp_sta {
    ninlil_wifi_esp_event_sink_fn sink;
    void *sink_user;
    int started;
    int got_ip_obs; /* observational mirror only */
    int has_last_ip;
    uint8_t last_ip[4];
};

size_t ninlil_wifi_esp_sta_sizeof(void)
{
    return sizeof(struct ninlil_wifi_esp_sta);
}

static void sink_event(
    ninlil_wifi_esp_sta_t *sta,
    uint8_t kind,
    uint8_t disconnect_reason,
    uint8_t ip_change,
    const uint8_t *ip4)
{
    if (sta == NULL || sta->sink == NULL) {
        return;
    }
    /* Enqueue only — sink must not re-enter Wi-Fi/TLS. */
    (void)sta->sink(
        sta->sink_user, kind, disconnect_reason, ip_change, ip4);
}

static void wifi_event_handler(
    void *arg,
    esp_event_base_t base,
    int32_t id,
    void *data)
{
    ninlil_wifi_esp_sta_t *sta = (ninlil_wifi_esp_sta_t *)arg;
    if (sta == NULL) {
        return;
    }
    if (base == WIFI_EVENT) {
        if (id == WIFI_EVENT_STA_START) {
            /* Do not call esp_wifi_connect here — owner step owns connect. */
            sink_event(sta, NINLIL_WIFI_ESP_EV_STA_START, 0u, 0u, NULL);
        } else if (id == WIFI_EVENT_STA_CONNECTED) {
            sink_event(
                sta, NINLIL_WIFI_ESP_EV_STA_CONNECTED, 0u, 0u, NULL);
        } else if (id == WIFI_EVENT_STA_DISCONNECTED) {
            uint8_t reason = 0u;
            if (data != NULL) {
                const wifi_event_sta_disconnected_t *d =
                    (const wifi_event_sta_disconnected_t *)data;
                reason = d->reason;
            }
            sink_event(
                sta,
                NINLIL_WIFI_ESP_EV_STA_DISCONNECTED,
                reason,
                0u,
                NULL);
        }
        return;
    }
    if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        uint8_t ip_change = 0u;
        uint8_t ip4[4] = {0u, 0u, 0u, 0u};
        const uint8_t *ip4_or_null = NULL;
        if (data != NULL) {
            const ip_event_got_ip_t *event = (const ip_event_got_ip_t *)data;
            ip4[0] = esp_ip4_addr1_16(&event->ip_info.ip);
            ip4[1] = esp_ip4_addr2_16(&event->ip_info.ip);
            ip4[2] = esp_ip4_addr3_16(&event->ip_info.ip);
            ip4[3] = esp_ip4_addr4_16(&event->ip_info.ip);
            ip4_or_null = ip4;
            if (event->ip_changed) {
                ip_change = 1u;
            }
        }
        sink_event(
            sta,
            NINLIL_WIFI_ESP_EV_GOT_IP,
            0u,
            ip_change,
            ip4_or_null);
        return;
    }
    if (base == IP_EVENT && id == IP_EVENT_STA_LOST_IP) {
        sink_event(sta, NINLIL_WIFI_ESP_EV_LOST_IP, 0u, 0u, NULL);
    }
}

ninlil_wifi_status_t ninlil_wifi_esp_sta_init(ninlil_wifi_esp_sta_t *sta)
{
    if (sta == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    (void)memset(sta, 0, sizeof(*sta));
    return NINLIL_WIFI_OK;
}

void ninlil_wifi_esp_sta_bind_event_sink(
    ninlil_wifi_esp_sta_t *sta,
    ninlil_wifi_esp_event_sink_fn sink,
    void *user)
{
    if (sta == NULL) {
        return;
    }
    sta->sink = sink;
    sta->sink_user = user;
}

ninlil_wifi_status_t ninlil_wifi_esp_sta_start(
    ninlil_wifi_esp_sta_t *sta,
    const ninlil_wifi_esp_sta_config_t *cfg)
{
    wifi_init_config_t wifi_cfg;
    wifi_config_t sta_cfg;
    sta_network_material_t material;
    ninlil_wifi_status_t material_status;
    esp_err_t err;

    if (sta == NULL || cfg == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (cfg->connect_timeout_ms != 0u) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    /* Never log SSID, password, or BSSID. */
    err = esp_netif_init();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        return NINLIL_WIFI_IO_ERROR;
    }
    err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        return NINLIL_WIFI_IO_ERROR;
    }
    (void)esp_netif_create_default_wifi_sta();

    wifi_cfg = (wifi_init_config_t)WIFI_INIT_CONFIG_DEFAULT();
    err = esp_wifi_init(&wifi_cfg);
    if (err != ESP_OK) {
        return NINLIL_WIFI_IO_ERROR;
    }
    err = esp_wifi_set_storage(WIFI_STORAGE_RAM);
    if (err != ESP_OK) {
        return NINLIL_WIFI_IO_ERROR;
    }
    err = esp_event_handler_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, sta);
    if (err != ESP_OK) {
        return NINLIL_WIFI_IO_ERROR;
    }
    err = esp_event_handler_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, sta);
    if (err != ESP_OK) {
        return NINLIL_WIFI_IO_ERROR;
    }
    err = esp_event_handler_register(
        IP_EVENT, IP_EVENT_STA_LOST_IP, &wifi_event_handler, sta);
    if (err != ESP_OK) {
        return NINLIL_WIFI_IO_ERROR;
    }
    err = esp_wifi_set_mode(WIFI_MODE_STA);
    if (err != ESP_OK) {
        return NINLIL_WIFI_IO_ERROR;
    }

    /*
     * Fetch synchronously at the last possible point. No credential bytes are
     * retained in this control block and the provider is released immediately
     * after esp_wifi_set_config() returns, on both success and failure.
     */
    material_status = network_material_acquire(cfg, &material);
    if (material_status != NINLIL_WIFI_OK) {
        return material_status;
    }
    (void)memset(&sta_cfg, 0, sizeof(sta_cfg));
    (void)memcpy(
        sta_cfg.sta.ssid,
        material.metadata.ssid,
        material.metadata.ssid_length);
    (void)memcpy(
        sta_cfg.sta.password,
        material.secret,
        material.metadata.password_length);
    if (material.metadata.auth_mode == WIFI_NETCRED_AUTH_WPA2_PSK) {
        sta_cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    } else if (material.metadata.auth_mode == WIFI_NETCRED_AUTH_WPA3_SAE) {
        sta_cfg.sta.threshold.authmode = WIFI_AUTH_WPA3_PSK;
    } else {
        sta_cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_WPA3_PSK;
    }
    sta_cfg.sta.pmf_cfg.capable = true;
    sta_cfg.sta.pmf_cfg.required = true;
    if (material.metadata.optional_bssid_present != 0u) {
        sta_cfg.sta.bssid_set = true;
        (void)memcpy(
            sta_cfg.sta.bssid, material.metadata.bssid, sizeof(sta_cfg.sta.bssid));
    }
    sta_cfg.sta.channel = material.metadata.channel;
    err = esp_wifi_set_config(WIFI_IF_STA, &sta_cfg);
    secure_zero(&sta_cfg, sizeof(sta_cfg));
    network_material_release(&material);
    if (err != ESP_OK) {
        return NINLIL_WIFI_IO_ERROR;
    }
    err = esp_wifi_start();
    if (err != ESP_OK) {
        return NINLIL_WIFI_IO_ERROR;
    }
    sta->started = 1;

    /*
     * The sole-owner path is intentionally asynchronous. owner_step consumes
     * STA_START and issues esp_wifi_connect().
     */
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_sta_request_connect(
    ninlil_wifi_esp_sta_t *sta)
{
    esp_err_t err;
    if (sta == NULL || !sta->started) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    err = esp_wifi_connect();
    if (err != ESP_OK) {
        return NINLIL_WIFI_IO_ERROR;
    }
    return NINLIL_WIFI_OK;
}

void ninlil_wifi_esp_sta_stop(ninlil_wifi_esp_sta_t *sta)
{
    if (sta == NULL) {
        return;
    }
    if (sta->started) {
        (void)esp_wifi_stop();
        (void)esp_wifi_deinit();
        sta->started = 0;
    }
    sta->got_ip_obs = 0;
    sta->has_last_ip = 0;
}

void ninlil_wifi_esp_sta_owner_note_got_ip(
    ninlil_wifi_esp_sta_t *sta,
    const uint8_t ip4[4])
{
    if (sta == NULL || ip4 == NULL) {
        return;
    }
    (void)memcpy(sta->last_ip, ip4, 4u);
    sta->has_last_ip = 1;
    sta->got_ip_obs = 1;
}

void ninlil_wifi_esp_sta_owner_note_lost_ip(ninlil_wifi_esp_sta_t *sta)
{
    if (sta == NULL) {
        return;
    }
    sta->got_ip_obs = 0;
    sta->has_last_ip = 0;
    (void)memset(sta->last_ip, 0, sizeof(sta->last_ip));
}

void ninlil_wifi_esp_sta_owner_note_fail(ninlil_wifi_esp_sta_t *sta)
{
    ninlil_wifi_esp_sta_owner_note_lost_ip(sta);
}

int ninlil_wifi_esp_sta_is_got_ip(const ninlil_wifi_esp_sta_t *sta)
{
    return sta != NULL && sta->got_ip_obs != 0;
}

_Static_assert(
    sizeof(struct ninlil_wifi_esp_sta) <= NINLIL_WIFI_ESP_STA_STORAGE_BYTES,
    "esp sta control size");

#else /* !ESP_PLATFORM */

/*
 * Host software STA: event sink + synthetic lifecycle for owner SM tests.
 * Not a physical radio. Not AP HIL.
 */
struct ninlil_wifi_esp_sta {
    ninlil_wifi_esp_event_sink_fn sink;
    void *sink_user;
    int started;
    int got_ip_obs;
    int connected;
};

size_t ninlil_wifi_esp_sta_sizeof(void)
{
    return sizeof(struct ninlil_wifi_esp_sta);
}

ninlil_wifi_status_t ninlil_wifi_esp_sta_init(ninlil_wifi_esp_sta_t *sta)
{
    if (sta == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    (void)memset(sta, 0, sizeof(*sta));
    return NINLIL_WIFI_OK;
}

void ninlil_wifi_esp_sta_bind_event_sink(
    ninlil_wifi_esp_sta_t *sta,
    ninlil_wifi_esp_event_sink_fn sink,
    void *user)
{
    if (sta == NULL) {
        return;
    }
    sta->sink = sink;
    sta->sink_user = user;
}

ninlil_wifi_status_t ninlil_wifi_esp_sta_start(
    ninlil_wifi_esp_sta_t *sta,
    const ninlil_wifi_esp_sta_config_t *cfg)
{
    sta_network_material_t material;
    ninlil_wifi_status_t status;
    uint8_t simulated_driver_copy[WIFI_NETCRED_SECRET_BYTES];
    if (sta == NULL || cfg == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    status = network_material_acquire(cfg, &material);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }
    /*
     * Host-only semantic double: model the exact driver-copy boundary without
     * retaining secret material in the STA object.
     */
    (void)memset(simulated_driver_copy, 0, sizeof(simulated_driver_copy));
    (void)memcpy(
        simulated_driver_copy,
        material.secret,
        material.metadata.password_length);
    network_material_release(&material);
    secure_zero(simulated_driver_copy, sizeof(simulated_driver_copy));
    sta->started = 1;
    sta->got_ip_obs = 0;
    sta->connected = 0;
    if (sta->sink != NULL) {
        (void)sta->sink(
            sta->sink_user, NINLIL_WIFI_ESP_EV_STA_START, 0u, 0u, NULL);
    }
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_sta_request_connect(
    ninlil_wifi_esp_sta_t *sta)
{
    if (sta == NULL || !sta->started) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    sta->connected = 1;
    if (sta->sink != NULL) {
        (void)sta->sink(
            sta->sink_user,
            NINLIL_WIFI_ESP_EV_STA_CONNECTED,
            0u,
            0u,
            NULL);
        (void)sta->sink(
            sta->sink_user,
            NINLIL_WIFI_ESP_EV_GOT_IP,
            0u,
            0u,
            NULL);
    }
    return NINLIL_WIFI_OK;
}

void ninlil_wifi_esp_sta_stop(ninlil_wifi_esp_sta_t *sta)
{
    if (sta == NULL) {
        return;
    }
    if (sta->started && sta->sink != NULL && sta->got_ip_obs) {
        (void)sta->sink(
            sta->sink_user,
            NINLIL_WIFI_ESP_EV_STA_DISCONNECTED,
            0u,
            0u,
            NULL);
    }
    sta->started = 0;
    sta->got_ip_obs = 0;
    sta->connected = 0;
}

void ninlil_wifi_esp_sta_owner_note_got_ip(
    ninlil_wifi_esp_sta_t *sta,
    const uint8_t ip4[4])
{
    (void)ip4;
    if (sta != NULL) {
        sta->got_ip_obs = 1;
    }
}

void ninlil_wifi_esp_sta_owner_note_lost_ip(ninlil_wifi_esp_sta_t *sta)
{
    if (sta != NULL) {
        sta->got_ip_obs = 0;
    }
}

void ninlil_wifi_esp_sta_owner_note_fail(ninlil_wifi_esp_sta_t *sta)
{
    ninlil_wifi_esp_sta_owner_note_lost_ip(sta);
}

int ninlil_wifi_esp_sta_is_got_ip(const ninlil_wifi_esp_sta_t *sta)
{
    return sta != NULL && sta->got_ip_obs != 0;
}

#endif /* ESP_PLATFORM */
