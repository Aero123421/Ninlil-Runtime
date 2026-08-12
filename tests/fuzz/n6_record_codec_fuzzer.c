/* SPDX-License-Identifier: Apache-2.0 */
/*
 * libFuzzer entry: byte 0 selects one of the 11 exact N6 forms; the remaining
 * bytes are passed unchanged with their true length.  Keeping the selector
 * outside the wire image lets the committed independent KAT records seed the
 * matching decoder instead of being rejected by an artificial leading byte.
 */
#include "n6_record_codec.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef union n6_fuzz_output {
    ninlil_n6_lane_key_t lane;
    ninlil_n6_tx_value_t tx;
    ninlil_n6_rx_value_t rx;
    ninlil_n6_hw_key_t hw_key;
    ninlil_n6_hw_value_t hw_value;
    ninlil_n6_al_key_t al_key;
    ninlil_n6_al_value_t al_value;
    ninlil_n6_rt_key_t rt_key;
    ninlil_n6_rt_value_t rt_value;
    ninlil_n6_cf_key_t cf_key;
    ninlil_n6_cf_value_t cf_value;
} n6_fuzz_output_t;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    n6_fuzz_output_t out;
    const uint8_t *wire;
    size_t wire_size;
    unsigned which;

    if (data == NULL || size == 0u) {
        return 0;
    }
    which = (unsigned)(data[0] % 11u);
    wire = data + 1u;
    wire_size = size - 1u;

    memset(&out, 0, sizeof(out));
    switch (which) {
    case 0: (void)ninlil_n6_decode_lane_key(wire, wire_size, &out.lane); break;
    case 1: (void)ninlil_n6_decode_n6tx_value(wire, wire_size, &out.tx); break;
    case 2: (void)ninlil_n6_decode_n6rx_value(wire, wire_size, &out.rx); break;
    case 3: (void)ninlil_n6_decode_n6hw_key(wire, wire_size, &out.hw_key); break;
    case 4: (void)ninlil_n6_decode_n6hw_value(wire, wire_size, &out.hw_value); break;
    case 5: (void)ninlil_n6_decode_n6al_key(wire, wire_size, &out.al_key); break;
    case 6: (void)ninlil_n6_decode_n6al_value(wire, wire_size, &out.al_value); break;
    case 7: (void)ninlil_n6_decode_n6rt_key(wire, wire_size, &out.rt_key); break;
    case 8: (void)ninlil_n6_decode_n6rt_value(wire, wire_size, &out.rt_value); break;
    case 9: (void)ninlil_n6_decode_n6cf_key(wire, wire_size, &out.cf_key); break;
    default:
        (void)ninlil_n6_decode_n6cf_value(wire, wire_size, &out.cf_value);
        break;
    }
    return 0;
}
