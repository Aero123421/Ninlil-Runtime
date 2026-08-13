/* SPDX-License-Identifier: Apache-2.0 */
/* libFuzzer entry: untrusted NFL1 packet bytes.  The input is never mutated. */
#include "nfl1_codec.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ninlil_fabric_private_nfl1_workspace_t workspace;
    ninlil_fabric_private_nfl1_envelope_t out;
    uint32_t required = 0u;

    if (data == NULL || size > UINT32_MAX) {
        return 0;
    }
    memset(&workspace, 0, sizeof(workspace));
    memset(&out, 0, sizeof(out));
    (void)ninlil_fabric_private_nfl1_decode(
        data, (uint32_t)size, &workspace, &out, &required);
    return 0;
}
