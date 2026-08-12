/* SPDX-License-Identifier: Apache-2.0 */
/* libFuzzer entry: fixed-size RRMP records use a private zero-padded copy. */
#include "rrmp_codec.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t record[NINLIL_RRMP_NRM1_BYTES];
    ninlil_rrmp_nrm1_fields_t out;
    size_t copied = size < sizeof(record) ? size : sizeof(record);

    memset(record, 0, sizeof(record));
    memset(&out, 0, sizeof(out));
    if (data != NULL) {
        memcpy(record, data, copied);
    }
    (void)ninlil_rrmp_decode_nrm1(record, &out);
    return 0;
}
