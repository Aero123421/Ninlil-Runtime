#ifndef NINLIL_M4_LAB_CREDENTIAL_FIXTURE_H
#define NINLIL_M4_LAB_CREDENTIAL_FIXTURE_H

/*
 * TEST_ONLY LAB credential fixtures (docs/05 LAB profile; isolated environment).
 */

#include "m4_lab_handshake.h"

#ifdef __cplusplus
extern "C" {
#endif

void m4_lab_fixture_site_config(ninlil_m4_lab_handshake_config_t *config);

void m4_lab_fixture_controller_credential(ninlil_m4_lab_credential_t *cred);

void m4_lab_fixture_endpoint_credential(ninlil_m4_lab_credential_t *cred);

void m4_lab_fixture_wrong_credential(ninlil_m4_lab_credential_t *cred);

void m4_lab_fixture_seed_membership(
    ninlil_m4_lab_membership_registry_t *reg);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_M4_LAB_CREDENTIAL_FIXTURE_H */
