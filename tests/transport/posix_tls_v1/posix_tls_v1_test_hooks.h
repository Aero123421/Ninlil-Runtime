/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_POSIX_TLS_V1_TEST_HOOKS_H
#define NINLIL_POSIX_TLS_V1_TEST_HOOKS_H

#include <ninlil/posix_tls_v1.h>

#include <stddef.h>
#include <stdint.h>

ninlil_fabric_link_status_t ninlil_posix_tls_v1_test_start_send(
    ninlil_posix_tls_v1_t *port,
    const ninlil_fabric_packet_view_v1_t *packet,
    ninlil_fabric_packet_token_t *out_token);
ninlil_fabric_link_status_t ninlil_posix_tls_v1_test_poll_send(
    ninlil_posix_tls_v1_t *port,
    ninlil_fabric_packet_token_t token,
    ninlil_fabric_link_completion_v1_t *out_completion);
ninlil_fabric_link_status_t ninlil_posix_tls_v1_test_cancel_send(
    ninlil_posix_tls_v1_t *port,
    ninlil_fabric_packet_token_t token);
void ninlil_posix_tls_v1_test_release_send(
    ninlil_posix_tls_v1_t *port,
    ninlil_fabric_packet_token_t token);
ninlil_fabric_link_status_t ninlil_posix_tls_v1_test_receive_next(
    ninlil_posix_tls_v1_t *port,
    const uint8_t **out_bytes,
    uint32_t *out_length,
    void **out_receive_token);
void ninlil_posix_tls_v1_test_release_received(
    ninlil_posix_tls_v1_t *port,
    void *receive_token);

void ninlil_posix_tls_v1_test_set_write_limit(
    ninlil_posix_tls_v1_t *port, size_t write_limit);
void ninlil_posix_tls_v1_test_fail_next_write_before_positive(
    ninlil_posix_tls_v1_t *port);
int ninlil_posix_tls_v1_test_corrupt_pending_record(
    ninlil_posix_tls_v1_t *port);
int ninlil_posix_tls_v1_test_set_pending_sequence(
    ninlil_posix_tls_v1_t *port, uint32_t sequence);
int ninlil_posix_tls_v1_test_session_snapshot(
    ninlil_posix_tls_v1_t *port,
    uint8_t out_attached_session_id[16],
    uint32_t *out_next_tx_sequence,
    size_t *out_tx_offset,
    uint32_t *out_crossed_uncertain_boundary);
int ninlil_posix_tls_v1_test_prime_coalesced_rx(
    ninlil_posix_tls_v1_t *port,
    const uint8_t *first_packet,
    uint32_t first_length,
    const uint8_t *second_packet,
    uint32_t second_length);
int ninlil_posix_tls_v1_test_abandon_without_clean_marker(
    ninlil_posix_tls_v1_t *port);

#endif /* NINLIL_POSIX_TLS_V1_TEST_HOOKS_H */
