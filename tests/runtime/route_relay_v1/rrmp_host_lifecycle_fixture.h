/*
 * Host-only RRMP software lifecycle fixture (not RF/HIL, not public ABI).
 * Synthetic platform-shaped FULL store + outbound submit used for host KAT.
 * Not linked into ESP production archives.
 */
#ifndef NINLIL_TESTS_RRMP_HOST_LIFECYCLE_FIXTURE_H
#define NINLIL_TESTS_RRMP_HOST_LIFECYCLE_FIXTURE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_RRMP_HOST_LIFE_OK 0
#define NINLIL_RRMP_HOST_LIFE_E_SHA (-1)
#define NINLIL_RRMP_HOST_LIFE_E_WORKSPACE (-2)
#define NINLIL_RRMP_HOST_LIFE_E_INIT (-3)
#define NINLIL_RRMP_HOST_LIFE_E_STORAGE (-4)
#define NINLIL_RRMP_HOST_LIFE_E_ROUTE (-5)
#define NINLIL_RRMP_HOST_LIFE_E_PARENT (-6)
#define NINLIL_RRMP_HOST_LIFE_E_PROVIDER (-7)
#define NINLIL_RRMP_HOST_LIFE_E_ACK (-8)
#define NINLIL_RRMP_HOST_LIFE_E_RESTART (-9)
#define NINLIL_RRMP_HOST_LIFE_E_FABRIC (-10)

/*
 * Host software path:
 *  - production composition_bind(real store ops) + recover
 *  - FULL commit/readback
 *  - 2-parent install/select/ordinal failover + same-attempt fence
 *  - cold restart: route ACTIVE + parent + attempt fence
 *  - admit LIVE + cold restart: LIVE evidence REPLAY + parent/attempt resume
 *  - outbound ACCEPTED → ACK lost → same-attempt retry → auth ACK → complete
 *  - parent_loss → unique SPLIT_BRAIN on further select
 *  - fabric reject zero mutation
 *  - force retire + cold restart not ACTIVE
 */
int32_t ninlil_rrmp_host_lifecycle_run(void *workspace, size_t workspace_bytes);

#ifdef __cplusplus
}
#endif

#endif
