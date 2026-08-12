/* SPDX-License-Identifier: Apache-2.0 */
/* libFuzzer entry: FRAG plaintext parsing borrows, but never writes, input. */
#include "r7_frag.h"
#include "r7_frag_internal.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef NINLIL_FUZZ_REACHABILITY_MAIN
#include <stdio.h>
#endif

static ninlil_r7_frag_status ninlil_r7_frag_fuzz_parse(
    uint8_t parser,
    const uint8_t *data,
    size_t size)
{
    ninlil_r7_frag_start_body start;
    ninlil_r7_frag_cont_body cont;
    ninlil_r7_frag_ack_body ack;
    ninlil_r7_frag_link_ack_body link_ack;
    const uint8_t *chunk = NULL;
    size_t chunk_len = 0u;

    memset(&start, 0, sizeof(start));
    memset(&cont, 0, sizeof(cont));
    memset(&ack, 0, sizeof(ack));
    memset(&link_ack, 0, sizeof(link_ack));
    switch (parser) {
    case 0u:
        return ninlil_r7_frag_parse_start_pt(
            data, size, &start, &chunk, &chunk_len);
    case 1u:
        return ninlil_r7_frag_parse_cont_pt(
            data, size, &cont, &chunk, &chunk_len);
    case 2u:
        if (size != NINLIL_R7_FRAG_ACK_PT_LEN) {
            return NINLIL_R7_FRAG_STRUCTURAL;
        }
        return ninlil_r7_frag_parse_ack_pt(data, &ack);
    case 3u:
        if (size != NINLIL_R7_FRAG_LINK_ACK_PT_LEN) {
            return NINLIL_R7_FRAG_STRUCTURAL;
        }
        return ninlil_r7_frag_parse_link_ack_body(data, &link_ack);
    default:
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
}

#ifdef NINLIL_FUZZ_REACHABILITY_MAIN
int main(int argc, char **argv)
{
    uint8_t input[4097];
    uint8_t parser;
    size_t size;

    if (argc != 2 || argv[1][0] < '0' || argv[1][0] > '3'
        || argv[1][1] != '\0') {
        return 2;
    }
    parser = (uint8_t)(argv[1][0] - '0');
    size = fread(input, 1u, sizeof(input), stdin);
    if (size == 0u || size == sizeof(input) || ferror(stdin) != 0) {
        return 2;
    }
    return ninlil_r7_frag_fuzz_parse(parser, input, size)
            == NINLIL_R7_FRAG_OK
        ? 0
        : 1;
}
#else
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void)ninlil_r7_frag_fuzz_parse(0u, data, size);
    (void)ninlil_r7_frag_fuzz_parse(1u, data, size);
    if (size == NINLIL_R7_FRAG_ACK_PT_LEN) {
        (void)ninlil_r7_frag_fuzz_parse(2u, data, size);
    }
    if (size == NINLIL_R7_FRAG_LINK_ACK_PT_LEN) {
        (void)ninlil_r7_frag_fuzz_parse(3u, data, size);
    }
    return 0;
}
#endif
