/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_INSTALLED_FABRIC_DIRECT_PACKET_LINK_H
#define NINLIL_INSTALLED_FABRIC_DIRECT_PACKET_LINK_H

#include <ninlil/fabric_v1.h>

#define INSTALLED_PAIR_QUEUE_CAPACITY 16u
#define INSTALLED_PAIR_TOKEN_CAPACITY 16u
#define INSTALLED_PAIR_PERMIT_CAPACITY 64u
#define INSTALLED_PAIR_PACKET_MAX 1925u

typedef struct installed_pair_frame {
    uint32_t used;
    uint32_t loaned;
    uint32_t length;
    uint8_t bytes[INSTALLED_PAIR_PACKET_MAX];
} installed_pair_frame_t;

typedef struct installed_pair_token {
    uint32_t used;
    uint32_t terminal;
    uint32_t generation;
} installed_pair_token_t;

typedef struct installed_pair_link {
    struct installed_pair_link *peer;
    const ninlil_clock_ops_t *clock;
    uint32_t open;
    uint32_t available;
    uint64_t availability_epoch;
    uint32_t next_generation;
    uint32_t start_calls;
    uint32_t accepted_packets;
    uint32_t permit_count;
    uint8_t consumed_permits[INSTALLED_PAIR_PERMIT_CAPACITY][16];
    installed_pair_token_t tokens[INSTALLED_PAIR_TOKEN_CAPACITY];
    installed_pair_frame_t queue[INSTALLED_PAIR_QUEUE_CAPACITY];
    uint32_t queue_head;
    uint32_t queue_count;
} installed_pair_link_t;

void installed_pair_link_init(
    installed_pair_link_t *link, const ninlil_clock_ops_t *clock);
void installed_pair_link_connect(
    installed_pair_link_t *left, installed_pair_link_t *right);
void installed_pair_link_ops(
    installed_pair_link_t *link, ninlil_fabric_packet_link_ops_v1_t *out_ops);

#endif
