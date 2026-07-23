/*
 * TEST_ONLY LAB credential fixtures.
 */

#include "m4_lab_credential_fixture.h"

#include <string.h>

static const char k_site_domain[] = "ninlil-lab-site";
static const char k_controller_id[] = "lab-controller-01";
static const char k_endpoint_id[] = "lab-endpoint-01";

/* Public LAB test vectors — isolated environment only (docs/05). */
static const uint8_t k_controller_root[32] = {
    0xa1u, 0xb2u, 0xc3u, 0xd4u, 0xe5u, 0xf6u, 0x07u, 0x18u,
    0x29u, 0x3au, 0x4bu, 0x5cu, 0x6du, 0x7eu, 0x8fu, 0x90u,
    0x01u, 0x12u, 0x23u, 0x34u, 0x45u, 0x56u, 0x67u, 0x78u,
    0x89u, 0x9au, 0xabu, 0xbcu, 0xcdu, 0xdeu, 0xefu, 0xf0u
};

static const uint8_t k_endpoint_root[32] = {
    0x10u, 0x21u, 0x32u, 0x43u, 0x54u, 0x65u, 0x76u, 0x87u,
    0x98u, 0xa9u, 0xbau, 0xcbu, 0xdcu, 0xedu, 0xfeu, 0x0fu,
    0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u, 0x88u,
    0x99u, 0xaau, 0xbbu, 0xccu, 0xddu, 0xeeu, 0xffu, 0x00u
};

static const uint8_t k_wrong_root[32] = {
    0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
    0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
    0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
    0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu
};

void m4_lab_fixture_site_config(ninlil_m4_lab_handshake_config_t *config)
{
    if (config == NULL) {
        return;
    }
    (void)memset(config, 0, sizeof(*config));
    config->site_domain_len = (uint8_t)(sizeof(k_site_domain) - 1u);
    (void)memcpy(config->site_domain, k_site_domain, config->site_domain_len);
    config->controller_stable_id_len =
        (uint8_t)(sizeof(k_controller_id) - 1u);
    (void)memcpy(
        config->controller_stable_id,
        k_controller_id,
        config->controller_stable_id_len);
    config->membership_epoch = 42u;
    config->next_session_id = 1000u;
    config->next_hop_context_id = 7u;
}

static void m4_fill_cred(
    ninlil_m4_lab_credential_t *cred,
    const uint8_t root[32],
    const char *stable_id)
{
    size_t len;

    (void)memset(cred, 0, sizeof(*cred));
    (void)memcpy(cred->root_key32, root, 32u);
    len = strlen(stable_id);
    cred->stable_id_len = (uint8_t)len;
    (void)memcpy(cred->stable_id, stable_id, len);
}

void m4_lab_fixture_controller_credential(ninlil_m4_lab_credential_t *cred)
{
    m4_fill_cred(cred, k_controller_root, k_controller_id);
}

void m4_lab_fixture_endpoint_credential(ninlil_m4_lab_credential_t *cred)
{
    m4_fill_cred(cred, k_endpoint_root, k_endpoint_id);
}

void m4_lab_fixture_wrong_credential(ninlil_m4_lab_credential_t *cred)
{
    m4_fill_cred(cred, k_wrong_root, k_endpoint_id);
}

void m4_lab_fixture_seed_membership(
    ninlil_m4_lab_membership_registry_t *reg)
{
    ninlil_m4_lab_bytes_t endpoint;
    ninlil_m4_lab_bytes_t controller;

    ninlil_m4_lab_membership_init(reg);
    endpoint.bytes = (const uint8_t *)k_endpoint_id;
    endpoint.length = (uint16_t)(sizeof(k_endpoint_id) - 1u);
    controller.bytes = (const uint8_t *)k_controller_id;
    controller.length = (uint16_t)(sizeof(k_controller_id) - 1u);
    (void)ninlil_m4_lab_membership_register(
        reg,
        endpoint,
        NINLIL_M4_LAB_MEMBERSHIP_ACTIVE,
        42u);
    (void)ninlil_m4_lab_membership_register(
        reg,
        controller,
        NINLIL_M4_LAB_MEMBERSHIP_ACTIVE,
        42u);
}
