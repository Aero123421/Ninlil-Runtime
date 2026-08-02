/* SPDX-License-Identifier: Apache-2.0
 *
 * Standalone ADR-0021 repaired-contract promotion KAT.
 *
 * Phase 1 used this same source as an executable RED witness. The GREEN
 * implementation tranche registers it in CTest; every closed allocation and
 * resource pin below must now pass against private production headers.
 */

#include "mfdt_v1.h"
#include "mfdt_v1_session.h"

#include <stdio.h>

static unsigned failures;

#define CONTRACT_EQ(actual, expected, name)                                    \
    do {                                                                       \
        unsigned long long got_ = (unsigned long long)(actual);                \
        unsigned long long want_ = (unsigned long long)(expected);             \
        if (got_ != want_) {                                                    \
            (void)fprintf(stderr, "RED %-34s got=%llu expected=%llu\n",        \
                          (name), got_, want_);                                 \
            failures += 1u;                                                     \
        }                                                                      \
    } while (0)

int main(void)
{
    /* MFN1 is independent of selected control [1,2] and owns 0x34..0x35. */
    CONTRACT_EQ(NINLIL_MFDT_V1_NEGOTIATE_OFFER, 0x34u, "MFN1_OFFER");
    CONTRACT_EQ(NINLIL_MFDT_V1_NEGOTIATE_ACCEPT, 0x35u, "MFN1_ACCEPT");

    /* The minimal contiguous transfer allocation is exactly 0x36..0x43. */
    CONTRACT_EQ(NINLIL_MFDT_V1_MSG_OPEN, 0x36u, "OPEN");
    CONTRACT_EQ(NINLIL_MFDT_V1_MSG_OPEN_ACCEPT, 0x37u, "OPEN_ACCEPT");
    CONTRACT_EQ(NINLIL_MFDT_V1_MSG_MANIFEST_PAGE, 0x38u, "MANIFEST_PAGE");
    CONTRACT_EQ(NINLIL_MFDT_V1_MSG_PAGE_ACCEPT, 0x39u, "PAGE_ACCEPT");
    CONTRACT_EQ(NINLIL_MFDT_V1_MSG_REJECT, 0x3au, "REJECT");
    CONTRACT_EQ(NINLIL_MFDT_V1_MSG_BUSY, 0x3bu, "BUSY");
    CONTRACT_EQ(NINLIL_MFDT_V1_MSG_CHUNK_OFFER, 0x3cu, "CHUNK_OFFER");
    CONTRACT_EQ(NINLIL_MFDT_V1_MSG_CHUNK_ACCEPT, 0x3du, "CHUNK_ACCEPT");
    CONTRACT_EQ(NINLIL_MFDT_V1_MSG_RESUME_QUERY, 0x3eu, "RESUME_QUERY");
    CONTRACT_EQ(NINLIL_MFDT_V1_MSG_RESUME_STATE, 0x3fu, "RESUME_STATE");
    CONTRACT_EQ(NINLIL_MFDT_V1_MSG_FINALIZE, 0x40u, "FINALIZE");
    CONTRACT_EQ(NINLIL_MFDT_V1_MSG_TRANSFER_ACCEPT, 0x41u, "TRANSFER_ACCEPT");
    CONTRACT_EQ(NINLIL_MFDT_V1_MSG_ABORT, 0x42u, "ABORT");
    CONTRACT_EQ(NINLIL_MFDT_V1_MSG_ABORT_ACK, 0x43u, "ABORT_ACK");

    /* NRC1 identity is (session_generation, request_id); slot grew by u32. */
    CONTRACT_EQ(NINLIL_MFDT_V1_NRC1_SLOT_BYTES, 208u, "NRC1_SLOT_BYTES");
    CONTRACT_EQ(NINLIL_MFDT_V1_NRC1_VALUE_BYTES, 15020u, "NRC1_VALUE_BYTES");
    CONTRACT_EQ(NINLIL_MFDT_V1_NRC1_LOGICAL_BYTES, 15056u, "NRC1_LOGICAL_BYTES");

    /* Host profile remains an exact four-slot contract. */
    CONTRACT_EQ(NINLIL_MFDT_V1_HOST_ACTIVE_MAX, 4u, "HOST_SLOT_COUNT");
    CONTRACT_EQ(NINLIL_MFDT_V1_WORKSPACE_BYTES, 65536u, "HOST_SLOT_WORKSPACE");

    if (failures != 0u) {
        (void)fprintf(stderr,
                      "MFDT repaired-contract production RED: %u gap(s)\n",
                      failures);
        return 1;
    }
    (void)printf("MFDT repaired-contract production GREEN\n");
    return 0;
}
