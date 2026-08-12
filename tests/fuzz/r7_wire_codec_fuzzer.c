/* SPDX-License-Identifier: Apache-2.0 */
/* libFuzzer entry: NRW1 AAD parsers consume the fuzzer bytes read-only. */
#include "r7_wire_codec.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ninlil_r7_wire_outer_data_fields outer;
    ninlil_r7_wire_e2e_single_fields e2e;

    memset(&outer, 0, sizeof(outer));
    memset(&e2e, 0, sizeof(e2e));
    (void)ninlil_r7_wire_parse_outer_data_aad(data, size, &outer);
    (void)ninlil_r7_wire_parse_e2e_single_aad(data, size, &e2e);
    return 0;
}
