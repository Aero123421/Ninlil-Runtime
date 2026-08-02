#!/usr/bin/env node
// Independent Node.js gate for ADR-0018 Wi-Fi bearer candidate vectors.
// Hard-coded per-ID semantic contracts; does not import generator/Python/prod code.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const here = path.dirname(fileURLToPath(import.meta.url));
const defaultVector = path.join(here, "..", "spec", "vectors", "wifi-bearer-spec-v1.json");
const REQUIRED = [
  "WIFI-ASSOC-AUTHORITY-EPOCH-BASELINE","WIFI-ASSOC-SAME-SSID-BSSID-CHANGE-FENCE","WIFI-ASSOC-SAME-SSID-CHANNEL-CHANGE-FENCE","WIFI-ASSOC-PROFILE-DIGEST-CHANGE-FENCE","WIFI-ASSOC-SAME-TUPLE-NO-EPOCH","WIFI-ASSOC-SESSION-FENCE-AVAILABILITY-PLUS-ONE",
  "WIFI-LIVENESS-KEEPALIVE-EXCLUSIVE-TIMER","WIFI-LIVENESS-MISSED-RESPONSE-THRESHOLD","WIFI-LIVENESS-BLACKHOLE-DETECTION","WIFI-LIVENESS-TCP-HALF-OPEN","WIFI-LIVENESS-AP-DEAD-BACKHAUL","WIFI-LIVENESS-AVAILABILITY-EPOCH-CHANGE",
  "WIFI-NETCRED-FULL-OLD","WIFI-NETCRED-FULL-NEW","WIFI-NETCRED-FULL-ABSENT","WIFI-NETCRED-FULL-BOTH","WIFI-NETCRED-PARTIAL","WIFI-NETCRED-EXTRA","WIFI-NETCRED-THIRD","WIFI-NETCRED-DUPLICATE-KEY","WIFI-NETCRED-COMMIT-UNKNOWN-RECOVERY","WIFI-NETCRED-ROLLBACK-REJECT","WIFI-NETCRED-SAME-REVISION-DIGEST-CONFLICT","WIFI-NETCRED-NO-PLAINTEXT-SECRET",
  "WIFI-ENDPOINT-IPV4-SCOPE","WIFI-ENDPOINT-IPV6-SCOPE","WIFI-ENDPOINT-LINK-LOCAL-SCOPE-ID","WIFI-ENDPOINT-DNS-MDNS-NON-AUTHORITY","WIFI-ENDPOINT-ADDRESS-CHANGE-FENCE",
  "WIFI-NWB1-HEADER-40","WIFI-NWB1-PAYLOAD-586-REJECT","WIFI-NWB1-PAYLOAD-587-ACCEPT","WIFI-NWB1-PAYLOAD-1925-ACCEPT","WIFI-NWB1-PAYLOAD-1926-REJECT","WIFI-NWB1-TOTAL-626-REJECT","WIFI-NWB1-TOTAL-627-ACCEPT","WIFI-NWB1-TOTAL-1965-ACCEPT","WIFI-NWB1-TOTAL-1966-REJECT","WIFI-NWB1-CRC32C-INDEPENDENT","WIFI-NWB1-PARTIAL-HEADER","WIFI-NWB1-PARTIAL-BODY","WIFI-NWB1-COALESCED-RECORDS","WIFI-NWB1-READ-AHEAD-BOUND","WIFI-NWB1-WRONG-SESSION","WIFI-NWB1-SEQUENCE-0","WIFI-NWB1-SEQUENCE-MAX-MINUS-ONE","WIFI-NWB1-SEQUENCE-UINT32-MAX-REJECT","WIFI-NWB1-DUPLICATE","WIFI-NWB1-GAP","WIFI-NWB1-OUT-OF-ORDER","WIFI-NWB1-WRAP-REJECT","WIFI-NWB1-INVALID-NFL1",
  "WIFI-TLS-SUITE-GROUP-SIGNATURE-EXACT","WIFI-TLS-X509-ROLE-RUNTIME-ATTACHMENT","WIFI-TLS-EXPORTER-PEER-CONTEXT-62","WIFI-TLS-EXPORTER-ATTACHED-CONTEXT-64","WIFI-TLS-AUTHORITY-ALL-ZERO-GROUP","WIFI-TLS-AUTHORITY-MIXED-REJECT","WIFI-TLS-TICKET-0RTT-RENEGOTIATION-FENCE","WIFI-TLS-REVOCATION-CLOCK-RULES","WIFI-TLS-R7-OPENSSL-GENERIC-NON-AUTHORITY","WIFI-TLS-HOST-OPENSSL-PIN-AUTHORITY","WIFI-TLS-ESP-MBEDTLS-PIN-AUTHORITY",
  "WIFI-PREATTACH-CARRIER-NOT-NWB1","WIFI-PREATTACH-PEER-SESSION-ONLY-NO-NWB1","WIFI-PREATTACH-NWB1-REQUIRES-PA-FULL",
  "WIFI-RESOURCE-ESP-CAPACITY","WIFI-RESOURCE-HOST-CAPACITY","WIFI-RESOURCE-PRIORITY-ISOLATION","WIFI-RESOURCE-RETAINED-TOKEN-PARTIAL-WRITE","WIFI-RESOURCE-RELEASE-SEMANTICS","WIFI-RESOURCE-NO-FALSE-CUSTODY","WIFI-RESOURCE-STORAGE-ARITHMETIC",
  "WIFI-ROLE-HOST-POSIX-TCP-TLS","WIFI-ROLE-ESP32S3-STA-LWIP-MBEDTLS",
  "WIFI-RACE-DISCONNECT-RECONNECT","WIFI-RACE-SLEEP-DRAIN","WIFI-RACE-EVENT-OVERFLOW","WIFI-BACKOFF-DETERMINISTIC",
];
const GROUPS = ["association_authority_vectors","liveness_vectors","network_credential_rotation_vectors","endpoint_vectors","nwb1_vectors","tls_profile_vectors","preattachment_boundary_vectors","resource_queue_vectors","role_responsibility_vectors","race_backoff_vectors"];
const CLOSED = ["OLD","NEW","BOTH","PARTIAL","EXTRA","THIRD","ABSENT","CORRUPT"];
const DISCONNECT = ["DISCONNECT_EVENT","FENCE_SESSIONS","AVAILABILITY_PLUS_ONE","CLOSE_SOCKETS","BACKOFF_NOT_BEFORE","RECONNECT_ATTEMPT"];
const PIN = {
  hostTag: "openssl-3.5.7",
  hostPeeled: "8cf17aaeb4599f8af87fefd810b5b5fee90fe69e",
  espIdf: "2c211b236707889e8400c4dc5644dd5c4ee071e0",
  espMbed: "ffb280bb63c78bfec1e1ab55040671768c85c923",
  suite: 0x1301, group: 0x0017, sig: 0x0403,
  ka: 15000, miss: 3, bh: 45000,
  hdr: 40, pmin: 587, pmax: 1925, tmin: 627, tmax: 1965,
  peer: 62, att: 64, nwd1: 160, keys: 8, cu: 1280, st: 2560, eq: 8,
  backoff: [1000,2000,4000,8000,16000,32000],
  assocTag: Buffer.from("NINLIL-WIFI-ASSOC-AUTHORITY-V1"),
  nwd1AuthTag: Buffer.from("NINLIL-WIFI-NWD1-AUTH-V1"),
  nwd1CompleteTag: Buffer.from("NINLIL-WIFI-NWD1-COMPLETE-V1"),
  nfl1Header: 584,
  nfl1Version: 1,
  assocInputLen: 80,
  schema: "ninlil.wifi.bearer.spec.v1",
  status: "PROPOSED_CANDIDATE_NOT_SPEC_ACCEPTED",
  adr: "docs/adr/0018-wifi-bearer.md",
  generator: "tools/wifi_bearer_spec_vector_gen.py",
  gatePy: "tools/wifi_bearer_spec_gate.py",
  gateMjs: "tools/wifi_bearer_spec_gate.mjs",
  vector: "spec/vectors/wifi-bearer-spec-v1.json",
  cTest: "tests/transport/wifi_bearer_spec_vector_test.c",
  toolPaths: [
    "docs/adr/0018-wifi-bearer.md",
    "tools/wifi_bearer_spec_vector_gen.py",
    "tools/wifi_bearer_spec_gate.py",
    "tools/wifi_bearer_spec_gate.mjs",
    "spec/vectors/wifi-bearer-spec-v1.json",
    "tests/transport/wifi_bearer_spec_vector_test.c",
  ],
  // Independent NWD1 KAT (literal 160B; not generator lab SSID).
  katValue:
    "4e57443100010080000000a00102030405060708090a0b0c0d0e0f10" +
    "0000000000000007" +
    "3030303030303030303030303030303030303030303030303030303030303030" +
    "1112131415161718191a1b1c1d1e1f20" +
    "0e4b41542d4e5744312d4649584544" +
    "000000000000000000000000000000000000" +
    "010b01aabbccddeeff0000" +
    "4040404040404040404040404040404040404040404040404040404040404040",
  katCrc: 0xe1a712fa,
  katAuth: "147db4b100c073732c8a837f88cd9e3b2600f2c1cb5f64b237e91bf234c45f04",
  katComplete: "479d037f00eac79ab4c4b14f91d60b7d7b50830e4bfb82c47ed1acad828cb744",
};
const ROOT = path.join(here, "..");
const FORBIDDEN_KEYS = new Set(["authority_override"]);
const CLOSED_ROOT = new Set(["acceptance_id_count","acceptance_ids_emitted","adr","association_authority_vectors","constants","endpoint_vectors","generator","liveness_vectors","network_credential_rotation_vectors","nonclaims","nwb1_vectors","pins","preattachment_boundary_vectors","race_backoff_vectors","required_acceptance_ids","resource_queue_vectors","role_responsibility_vectors","schema","source_vector_restoration","status","storage_arithmetic","tls_profile_vectors"]);
const CLOSED_ON_LIVENESS = new Set(["availability_epoch_delta","connection_close","double_add_forbidden","nwb1_delivery","session_fence"]);
const CLOSED_NWD1_ITEM = new Set(["auth_digest_hex","complete_digest_hex","header_crc32c","key_hex","value_hex"]);
const CLOSED_SAMPLE = new Set(["backoff_ms","failure_generation","jitter_ms","not_before_offset_ms"]);
const CLOSED_CONSTANTS = new Set(["attached_context_bytes","blackhole_detect_ms","esp_tls_canary_corruption_is_global_fatal","esp_tls_contract_null_spill_allowed","esp_tls_cross_owner_free_allowed","esp_tls_crypto_dma_bytes","esp_tls_crypto_global_internal_bytes","esp_tls_execution_stack_bytes","esp_tls_generic_spill_allowed","esp_tls_in_buffer_bytes","esp_tls_map_observation_slack_bytes","esp_tls_map_remainder_observation_bytes","esp_tls_ordinary_oom_is_global_fatal","esp_tls_original_internal_only_requirement_bytes","esp_tls_out_buffer_bytes","esp_tls_post_admission_internal_floor_bytes","esp_tls_psram_exact_live_allocation_required","esp_tls_psram_free_pointer_allowed","esp_tls_psram_interior_pointer_allowed","esp_tls_psram_required","esp_tls_psram_wrong_size_allowed","esp_tls_session_internal_bytes","esp_tls_session_psram_bytes","esp_tls_session_total_bytes","esp_tls_two_session_internal_envelope_bytes","keepalive_exclusive_deadline_ms","keepalive_interval_ms","missed_response_threshold","network_namespace","nwb1_header_bytes","nwb1_payload_max","nwb1_payload_min","nwb1_payload_reject_high","nwb1_payload_reject_low","nwb1_total_max","nwb1_total_min","nwb1_total_reject_high","nwb1_total_reject_low","nwd1_committed_cu_bytes","nwd1_record_bytes","nwd1_staging_cu_bytes","peer_context_bytes","record_bytes_fixed","session_lifetime_ms","tls_ciphersuite_id","tls_group_id","tls_signature_id"]);
const CLOSED_PINS = new Set(["assoc_authority_a_hex","assoc_authority_input_a_hex","assoc_authority_tag_ascii","attached_context_sha256_hex","esp_idf_commit","esp_mbedtls_commit","host_openssl_peeled","host_openssl_tag","instance_id_hex","network_profile_digest_a_hex","nfl1_header_bytes","nfl1_version","nwb1_max_record_sha256_hex","nwb1_min_record_sha256_hex","nwd1_new_complete_sha256_hex","nwd1_old_complete_sha256_hex","peer_context_sha256_hex","session_id_hex"]);
const CLOSED_STORAGE = new Set(["committed_cu_bytes","committed_formula","esp_nwd1_active_profiles_max","host_nwd1_active_profiles_max","nwd1_keys_max","nwd1_record_bytes","plaintext_password_in_storage","plaintext_password_in_vectors","secret_ref_digest_only","staging_cu_bytes","staging_formula"]);
const CLOSED_RESTORATION = new Set(["absent_row_id","acceptance_id_count","adr","c_test","commit_unknown_includes_corrupt","digest_leaf_count","digest_leaf_paths_sha256_hex","duplicate_expected_sequence_rule","gate_mjs","gate_py","generator","independent_nwd1_kat_auth_digest_hex","independent_nwd1_kat_complete_digest_hex","independent_nwd1_kat_header_crc32c","independent_nwd1_kat_value_hex","integer_leaf_count","integer_leaf_paths_sha256_hex","nwb1_max_total","nwb1_min_total","object_path_count","release_before_terminal_forbidden","schema","string_leaf_count","string_leaf_paths_sha256_hex","tool_paths","vector"]);
const CLOSED_ROW_KEYS = new Set([
  "absent_example_classification",
  "active_binding_match",
  "adapter_kind",
  "adapter_max",
  "address_hex",
  "address_kind",
  "age_300000_ok",
  "age_300001_reject",
  "allowed_only_if_controllerless_profile_explicit",
  "application_publish",
  "association_authority_digest_hex",
  "association_authority_input_hex",
  "association_epoch",
  "attached_stable_reset_ms",
  "attachment_authority_match",
  "auth_mode",
  "authority_clock_only",
  "authority_endpoint_change_requires_config_revision",
  "availability",
  "availability_epoch_delta",
  "availability_epoch_delta_on_sleep",
  "bad_classification",
  "binding_id_hex",
  "binding_length",
  "blackhole_detect_ms",
  "both_example_classification",
  "bound_profile_rejects_all_zero",
  "bssid_hex",
  "buffer_bytes",
  "bulk_may_starve_critical",
  "bytes_available",
  "canonical_complete_digest_hex",
  "canonical_value_hex",
  "cap_ms",
  "channel",
  "ciphersuite",
  "ciphersuite_id",
  "classification",
  "classifications_allowed_on_reopen",
  "client_binding_hex",
  "client_role",
  "closed_classification_set",
  "committed_cu_bytes",
  "committed_formula",
  "condition",
  "conflicting_complete_digest_hex",
  "conflicting_value_hex",
  "connect_attempt_max",
  "connection_close",
  "context_hex",
  "context_length",
  "context_sha256_hex",
  "crc_init",
  "crc_polynomial",
  "crc_xorout",
  "create_result",
  "credential_provider_null_required",
  "credential_provider_required",
  "current_revision",
  "deliverable",
  "delivery",
  "depends_on_m4_full",
  "digests_equal",
  "direct_mbedtls_only",
  "dns_authority",
  "dns_name",
  "double_count_forbidden",
  "drain_blocks_new_send_retention",
  "duplicate_old_key_classification",
  "early_data_bytes_publish",
  "emit_forbidden",
  "entropy_forbidden",
  "esp_idf_commit",
  "esp_nwd1_active_profiles_max",
  "esp_tls_public_api_forbidden",
  "event",
  "event_queue_max",
  "event_queue_overflow_at",
  "exclusive_deadline_ms",
  "expected",
  "expected_bad",
  "expected_class",
  "expected_classification",
  "expected_duplicate_old_key_classification",
  "expected_first",
  "expected_good",
  "expected_length",
  "expected_observed_complete_digests",
  "expected_second",
  "expected_sequence",
  "expected_session_hex",
  "fabric_availability",
  "fabric_cap_custody_advertised",
  "fake_available_while_asleep",
  "first_classification",
  "first_sequence",
  "formula",
  "fresh_session_sequence",
  "good_classification",
  "group",
  "group_class",
  "group_id",
  "header_length",
  "host_nwd1_active_profiles_max",
  "id",
  "instance_id_hex",
  "ip_ready",
  "is_duplicate_of_prior",
  "is_gap",
  "is_out_of_order",
  "keepalive_interval_ms",
  "key_update_local_emit",
  "label",
  "last_known_address_authority",
  "last_sent_sequence",
  "m4_carrier_required",
  "m4_full_durable",
  "m4_missing_nwb1_allowed",
  "max_records_read_ahead",
  "may_use_system_openssl_3",
  "mbedtls_commit",
  "mdns_browse",
  "missed_count_at_fail",
  "missed_count_still_ok",
  "missed_response_threshold",
  "mutated_record_hex",
  "need_bytes",
  "network_profile_nonzero_required",
  "network_profile_zero_required",
  "new_association_authority_digest_hex",
  "new_association_authority_input_hex",
  "new_association_epoch",
  "new_auth_digest_hex",
  "new_auth_mode",
  "new_binding_id_hex",
  "new_bssid_hex",
  "new_channel",
  "new_complete_digest_hex",
  "new_header_crc32c",
  "new_profile_digest_hex",
  "new_profile_id_hex",
  "new_profile_revision",
  "new_revision",
  "new_rows",
  "new_value_hex",
  "next_action",
  "next_sequence_same_session_forbidden",
  "now_equals_valid_until_reject",
  "nwb1_allowed",
  "nwb1_as_attachment_carrier",
  "nwb1_or_probe_response_required",
  "nwb1_publish",
  "nwb1_receive",
  "nwb1_send",
  "nwb1_socket_write_is_custody",
  "nwd1_kat_auth_digest_hex",
  "nwd1_kat_complete_digest_hex",
  "nwd1_kat_header_crc32c",
  "nwd1_kat_value_hex",
  "nwd1_keys_max",
  "nwd1_record_bytes",
  "observed_auth_digest_hex",
  "observed_complete_digest_hex",
  "observed_header_crc32c",
  "observed_revision",
  "observed_rows",
  "observed_value_hex",
  "old_association_authority_digest_hex",
  "old_association_authority_input_hex",
  "old_association_epoch",
  "old_auth_digest_hex",
  "old_auth_mode",
  "old_binding_id_hex",
  "old_bssid_hex",
  "old_channel",
  "old_complete_digest_hex",
  "old_header_crc32c",
  "old_profile_digest_hex",
  "old_profile_id_hex",
  "old_profile_revision",
  "old_revision",
  "old_rows",
  "old_value_hex",
  "on_liveness_fail",
  "order",
  "os_random_forbidden",
  "os_tcp_keepalive_is_authority",
  "os_wall_clock_authority",
  "overflow_count",
  "partial_tcp_tls_write_outer_would_block",
  "password_substrings_forbidden",
  "payload_length",
  "peeled_commit",
  "peer_kernel_ack_is_custody",
  "peer_probe_ok",
  "peer_session_id_nonzero",
  "physical_events_observed",
  "plaintext_password_in_storage",
  "plaintext_password_in_vectors",
  "poll_send_internal",
  "port",
  "post_handshake_auth",
  "power_cut_after",
  "prior_delivered_sequence",
  "profile_digest_hex",
  "profile_id_hex",
  "profile_revision",
  "protocol",
  "publish",
  "publish_before_reclassify",
  "queues",
  "r7_rule",
  "received_sequence",
  "reconnect_before_fence_forbidden",
  "record_bytes",
  "record_count",
  "record_hex",
  "record_sha256_hex",
  "release_before_terminal_forbidden",
  "release_send_exact_count_after_terminal",
  "renegotiation",
  "reobserve_same_tuple",
  "requires_fresh_association",
  "result",
  "result_state",
  "reuse_old_socket_forbidden",
  "revision",
  "rx_loan_max",
  "rx_record_max",
  "rx_record_per_session",
  "samples",
  "satisfies_wifi_host_pin",
  "schedule_ms",
  "scope_id_required",
  "scope_id_u32",
  "scope_id_zero_rejected",
  "scope_id_zero_result",
  "second_classification",
  "second_exporter_ok",
  "second_sequence",
  "secret_field",
  "secret_ref_digest_hex",
  "secret_ref_digest_only",
  "sequence",
  "server_binding_hex",
  "server_role",
  "session_established",
  "session_fence",
  "session_fence_generation",
  "session_max",
  "session_tickets",
  "shared_leaf_forbidden",
  "signature_id",
  "signature_scheme",
  "silent_fallback_forbidden",
  "sleep_marks_unavailable",
  "slice_hex",
  "snapshot_age_max_ms",
  "sockets_closed",
  "ssid_hex",
  "staging_cu_bytes",
  "staging_formula",
  "start_send_full_copy_own",
  "state",
  "static_only",
  "stream_hex",
  "tag",
  "targets",
  "tcp_ack_alone_not_liveness",
  "timer_shares_phase_deadline",
  "tls_backend",
  "tls_record_success_is_custody",
  "token_null_means_retain_0",
  "total_length",
  "transport",
  "tx_token_max",
  "tx_token_per_session",
  "unlimited_read_ahead_forbidden",
  "unused_tail_must_be_zero",
  "wifi_associated",
  "wifi_driver_owner",
  "wifi_driver_sole_owner",
  "wifi_storage_ram",
  "wrap_to_zero_same_session_forbidden"
]);

const PIN_OBJECT_PATH_COUNT = 117;
const PIN_INTEGER_LEAF_COUNT = 386;
const PIN_STRING_LEAF_COUNT = 692;
const PIN_DIGEST_LEAF_COUNT = 96;
const PIN_INTEGER_LEAF_PATHS_SHA256 = "2f3294d2c15bd5f670c4e770dc1b9523974fc27bd462168eb015b399576082bb";
const PIN_STRING_LEAF_PATHS_SHA256 = "7014fc9b3e73e0b74223c85f039f15d27e87e8478d899def03f0830133de1ece";
const PIN_DIGEST_LEAF_PATHS_SHA256 = "f874aa983793212f5f0ef07422d0338d558f08e27e13c00262fb1ab89fa05da0";
const PIN_VECTOR_DOCUMENT_SHA256 = "38d8050206d8de832dfe9395f6f39b99e1119eb06fa60ee2112af2cd375b25ff";
const PIN_ACCEPTANCE_ID_COUNT = 79;
const PIN_NONCLAIMS = ["SPEC_ACCEPTED","implementation","HIL","RELEASE_SUPPORTED","public_API","production_support","target_execution","P0_closure","independent_review_GO"];
const DESCRIPTIVE_SCALAR_ALLOWLIST = new Set();

class GateError extends Error {}
const fail = (m) => { throw new GateError(m); };
const require = (c, m) => { if (!c) fail(m); };
const hex = (v, f) => {
  if (typeof v !== "string" || v.length % 2 || v !== v.toLowerCase() || !/^[0-9a-f]*$/.test(v)) fail(`${f}: hex`);
  return Buffer.from(v, "hex");
};
const sha = (v) => crypto.createHash("sha256").update(v).digest();
const eq = (a, b) => a.length === b.length && crypto.timingSafeEqual(a, b);
function crc32c(value) {
  let crc = 0xffffffff;
  for (const o of value) {
    crc = (crc ^ o) >>> 0;
    for (let b = 0; b < 8; b++) crc = ((crc >>> 1) ^ ((crc & 1) ? 0x82f63b78 : 0)) >>> 0;
  }
  return (crc ^ 0xffffffff) >>> 0;
}
function exactInt(v, f) {
  // Accept safe Number or BigInt; never silently round u64 > 2^53.
  if (typeof v === "bigint") {
    return v;
  }
  if (typeof v !== "number" || !Number.isInteger(v)) fail(`${f}: exact int`);
  if (!Number.isSafeInteger(v)) fail(`${f}: unsafe Number (use BigInt)`);
  return v;
}
function asBig(v) {
  if (typeof v === "bigint") return v;
  if (typeof v === "number" && Number.isSafeInteger(v)) return BigInt(v);
  fail("asBig");
}
function intEq(a, b) {
  return asBig(a) === asBig(b);
}
function classifyNfl1(packet) {
  if (packet.length < PIN.nfl1Header) return "INVALID_NFL1";
  if (packet.subarray(0, 4).toString() !== "NFL1") return "INVALID_NFL1";
  const version = packet.readUInt16BE(4);
  const headerLength = packet.readUInt16BE(6);
  const totalLength = packet.readUInt32BE(8);
  const storedCrc = packet.readUInt32BE(12);
  if (headerLength !== PIN.nfl1Header || totalLength !== packet.length) return "INVALID_NFL1";
  if (totalLength < 587 || totalLength > 1925) return "INVALID_NFL1";
  if (version !== PIN.nfl1Version) return "INVALID_NFL1";
  const scratch = Buffer.from(packet); scratch.fill(0, 12, 16);
  if (crc32c(scratch) !== storedCrc) return "INVALID_NFL1";
  const ns = packet.readUInt16BE(570), svc = packet.readUInt16BE(572), schema = packet.readUInt16BE(574);
  const payload = packet.readUInt32BE(576), evidence = packet.readUInt32BE(580);
  if (ns > 63 || svc > 63 || schema > 63) return "INVALID_NFL1";
  if (PIN.nfl1Header + ns + svc + schema + payload + evidence !== totalLength) return "INVALID_NFL1";
  if ((packet.readUInt32BE(20) & 0xffff0000) !== 0) return "INVALID_NFL1";
  return "OK";
}
function validateNwd1(record) {
  if (record.length !== 160) return "CORRUPT";
  if (record.subarray(0, 4).toString() !== "NWD1") return "CORRUPT";
  if (record.readUInt16BE(4) !== 1 || record.readUInt16BE(6) !== 128 || record.readUInt32BE(8) !== 160) return "CORRUPT";
  if (record[126] !== 0 || record[127] !== 0) return "CORRUPT";
  if (record[84] < 1 || record[84] > 32) return "CORRUPT";
  if (record.subarray(12, 28).every((b) => b === 0)) return "CORRUPT";
  if (record.readBigUInt64BE(28) === 0n) return "CORRUPT";
  if (record.subarray(36, 68).every((b) => b === 0)) return "CORRUPT";
  if (record.subarray(68, 84).every((b) => b === 0)) return "CORRUPT";
  if (record.subarray(128, 160).every((b) => b === 0)) return "CORRUPT";
  return "OK";
}
function parseAssoc(ain) {
  require(ain.length === PIN.assocInputLen, "assoc len");
  return {
    profile_id: ain.subarray(0,16),
    association_epoch: ain.readBigUInt64BE(16),
    profile_digest: ain.subarray(24,56),
    binding_id: ain.subarray(56,72),
    bssid: ain.subarray(72,78),
    channel: ain[78],
    auth_mode: ain[79],
  };
}
function verifyAssoc(row, digF, inF) {
  const ain = hex(row[inF], inF);
  const dig = hex(row[digF], digF);
  const got = sha(Buffer.concat([PIN.assocTag, ain]));
  require(eq(got, dig), `assoc tag ${digF}`);
  require(!eq(sha(Buffer.concat([Buffer.from("NINLIL-WIFI-ASSOC-AUTHORITY-X1"), ain])), dig), "wrong tag");
  const p = parseAssoc(ain);
  let prefix = "";
  if (inF.startsWith("old_")) prefix = "old_";
  else if (inF.startsWith("new_")) prefix = "new_";
  const bindHex = (field, expected) => {
    const key = prefix ? `${prefix}${field}` : field;
    if (prefix) {
      require(row[key] !== undefined, `missing ${key}`);
      require(row[key] === expected.toString("hex"), `${key} bind`);
    } else if (row[key] !== undefined) {
      require(row[key] === expected.toString("hex"), `${key} bind`);
    }
  };
  const bindInt = (field, expected) => {
    const key = prefix ? `${prefix}${field}` : field;
    if (prefix) {
      require(row[key] !== undefined, `missing ${key}`);
      exactInt(row[key], key);
      require(intEq(row[key], expected), `${key} bind`);
    } else if (row[key] !== undefined) {
      exactInt(row[key], key);
      require(intEq(row[key], expected), `${key} bind`);
    }
  };
  bindHex("profile_id_hex", p.profile_id);
  bindInt("association_epoch", p.association_epoch);
  const revKey = prefix ? `${prefix}profile_revision` : "profile_revision";
  if (row[revKey] !== undefined) {
    exactInt(row[revKey], revKey);
    require(intEq(row[revKey], p.association_epoch), `${revKey} bind`);
  }
  bindHex("profile_digest_hex", p.profile_digest);
  bindHex("binding_id_hex", p.binding_id);
  bindHex("bssid_hex", p.bssid);
  bindInt("channel", p.channel);
  bindInt("auth_mode", p.auth_mode);
}
function nwd1HeaderCrc(rec) { return crc32c(rec.subarray(0,128)); }
function nwd1Auth(rec) { return sha(Buffer.concat([PIN.nwd1AuthTag, rec.subarray(0,128), rec.subarray(128)])); }
function nwd1Complete(rec) { return sha(Buffer.concat([PIN.nwd1CompleteTag, rec])); }
function verifyNwd1Item(item, f) {
  const v = hex(item.value_hex, f+".v");
  require(validateNwd1(v)==="OK", f+" framing");
  exactInt(item.header_crc32c, f+".crc");
  require(item.header_crc32c === nwd1HeaderCrc(v), f+" crc");
  require(eq(hex(item.auth_digest_hex,f+".a"), nwd1Auth(v)), f+" auth");
  require(eq(hex(item.complete_digest_hex,f+".c"), nwd1Complete(v)), f+" complete");
  return v;
}
function classifyNwb1(record, expectedSession, expectedSequence) {
  if (record.length < 40 || record.subarray(0, 4).toString() !== "NWB1") return "CORRUPT";
  const version = record.readUInt16BE(4);
  const headerLength = record.readUInt16BE(6);
  const totalLength = record.readUInt32BE(8);
  const payloadLength = record.readUInt32BE(12);
  const sessionId = record.subarray(16, 32);
  const sequence = record.readUInt32BE(32);
  const storedCrc = record.readUInt32BE(36);
  if (headerLength !== 40) return "CORRUPT";
  if (totalLength !== record.length || payloadLength !== record.length - 40) return "CORRUPT";
  if (payloadLength < 587 || payloadLength > 1925) return "CORRUPT";
  if (totalLength < 627 || totalLength > 1965) return "CORRUPT";
  const scratch = Buffer.from(record); scratch.fill(0, 36, 40);
  if (crc32c(scratch) !== storedCrc) return "CORRUPT";
  if (version > 1) return "UNSUPPORTED";
  if (version !== 1) return "CORRUPT";
  if (sessionId.every((b) => b === 0)) return "CORRUPT";
  if (expectedSession && !eq(sessionId, expectedSession)) return "WRONG_SESSION";
  if (sequence === 0xffffffff) return "SEQUENCE_REJECT";
  if (expectedSequence !== undefined && sequence !== expectedSequence) return "SEQUENCE_REJECT";
  if (classifyNfl1(record.subarray(40)) !== "OK") return "INVALID_NFL1";
  return "OK";
}

function mapRows(rows, f) {
  return rows.map((r, i) => {
    if (r.header_crc32c !== undefined) {
      const v = verifyNwd1Item(r, `${f}[${i}]`);
      return [hex(r.key_hex, `${f}[${i}].k`), v];
    }
    return [hex(r.key_hex, `${f}[${i}].k`), hex(r.value_hex, `${f}[${i}].v`)];
  });
}
function classifyCU(oldRows, newRows, obsRows) {
  const asMap = (rows) => {
    const m = new Map();
    for (const [k, v] of rows) {
      const key = k.toString("hex");
      if (m.has(key)) return null;
      if (validateNwd1(v) !== "OK") return null;
      m.set(key, v.toString("hex"));
    }
    return m;
  };
  const o = asMap(oldRows), n = asMap(newRows), s = asMap(obsRows);
  if (!o || !n || !s) return "CORRUPT";
  const eqMap = (a, b) => a.size === b.size && [...a].every(([k, v]) => b.get(k) === v);
  if (o.size === 0 && s.size === 0 && n.size > 0) return "ABSENT";
  if (eqMap(s, o) && o.size > 0) return "OLD";
  if (eqMap(s, n) && n.size > 0) return "NEW";
  const oKeys=[...o.keys()], nKeys=[...n.keys()], sKeys=[...s.keys()];
  if (o.size>0 && n.size>0 && !eqMap(o,n) && oKeys.every(k=>!n.has(k)) && oKeys.every(k=>s.has(k)&&s.get(k)===o.get(k)) && nKeys.every(k=>s.has(k)&&s.get(k)===n.get(k))) return "BOTH";
  if (s.size > 0 && s.size < n.size && [...s.keys()].every((k) => n.has(k) && s.get(k) === n.get(k))) return "PARTIAL";
  if (n.size > 0 && n.size < s.size && [...n.keys()].every((k) => s.has(k) && s.get(k) === n.get(k))) return "EXTRA";
  return "THIRD";
}
function index(doc) {
  const m = new Map();
  for (const g of GROUPS) {
    require(Array.isArray(doc[g]), g);
    for (const row of doc[g]) {
      require(typeof row.id === "string", "id");
      require(!m.has(row.id), `dup ${row.id}`);
      m.set(row.id, row);
    }
  }
  return m;
}
// Field equality helper for hard contracts
const E = (row, k, v) => require(row[k] === v, `${row.id}.${k}`);
const ASSERTERS = {
  "WIFI-ASSOC-AUTHORITY-EPOCH-BASELINE": (r,d) => { E(r,"result","OK_ATTACHED_ELIGIBLE"); exactInt(r.session_fence,"session_fence"); E(r,"session_fence",0); E(r,"availability_epoch_delta",0); E(r,"profile_revision",1); verifyAssoc(r,"association_authority_digest_hex","association_authority_input_hex"); require(r.association_authority_digest_hex===d.pins.assoc_authority_a_hex,"pin"); },
  "WIFI-ASSOC-SAME-SSID-BSSID-CHANGE-FENCE": (r) => { E(r,"result","FENCED_STALE_SESSION"); exactInt(r.session_fence,"session_fence"); E(r,"session_fence",1); E(r,"availability_epoch_delta",1); E(r,"nwb1_publish",0); E(r,"digests_equal",0); for (const pfx of ["old_","new_"]) for (const f of ["profile_id_hex","association_epoch","profile_digest_hex","binding_id_hex","bssid_hex","channel","auth_mode","association_authority_input_hex","association_authority_digest_hex"]) require(r[pfx+f]!==undefined, `missing ${pfx}${f}`); require(!eq(hex(r.old_bssid_hex,"ob"), hex(r.new_bssid_hex,"nb")),"bssid"); verifyAssoc(r,"old_association_authority_digest_hex","old_association_authority_input_hex"); verifyAssoc(r,"new_association_authority_digest_hex","new_association_authority_input_hex"); require(r.old_profile_id_hex===r.new_profile_id_hex,"same pid"); require(r.old_binding_id_hex===r.new_binding_id_hex,"same binding"); require(intEq(r.old_channel,r.new_channel),"same channel"); },
  "WIFI-ASSOC-SAME-SSID-CHANNEL-CHANGE-FENCE": (r) => { E(r,"result","FENCED_STALE_SESSION"); exactInt(r.session_fence,"session_fence"); E(r,"session_fence",1); E(r,"availability_epoch_delta",1); E(r,"old_channel",6); E(r,"new_channel",11); E(r,"digests_equal",0); verifyAssoc(r,"old_association_authority_digest_hex","old_association_authority_input_hex"); verifyAssoc(r,"new_association_authority_digest_hex","new_association_authority_input_hex"); },
  "WIFI-ASSOC-PROFILE-DIGEST-CHANGE-FENCE": (r) => { E(r,"result","FENCED_STALE_SESSION"); exactInt(r.session_fence,"session_fence"); E(r,"session_fence",1); E(r,"availability_epoch_delta",1); E(r,"old_revision",1); E(r,"new_revision",2); require(r.old_profile_digest_hex!==r.new_profile_digest_hex,"pd"); verifyAssoc(r,"old_association_authority_digest_hex","old_association_authority_input_hex"); verifyAssoc(r,"new_association_authority_digest_hex","new_association_authority_input_hex"); },
  "WIFI-ASSOC-SAME-TUPLE-NO-EPOCH": (r) => { E(r,"result","OK_NO_FENCE"); exactInt(r.session_fence,"session_fence"); E(r,"session_fence",0); E(r,"availability_epoch_delta",0); E(r,"reobserve_same_tuple",1); verifyAssoc(r,"association_authority_digest_hex","association_authority_input_hex"); },
  "WIFI-ASSOC-SESSION-FENCE-AVAILABILITY-PLUS-ONE": (r) => { E(r,"result","AVAILABILITY_PLUS_ONE_ONCE"); E(r,"availability_epoch_delta",1); E(r,"double_count_forbidden",1); E(r,"event","ASSOCIATION_AUTHORITY_DIGEST_CHANGED"); E(r,"physical_events_observed",2); E(r,"session_fence_generation",1); },
  "WIFI-LIVENESS-KEEPALIVE-EXCLUSIVE-TIMER": (r) => { E(r,"result","OK_EXCLUSIVE"); E(r,"state","ATTACHED"); E(r,"keepalive_interval_ms",PIN.ka); E(r,"exclusive_deadline_ms",PIN.ka); E(r,"timer_shares_phase_deadline",0); },
  "WIFI-LIVENESS-MISSED-RESPONSE-THRESHOLD": (r) => { E(r,"result","FAIL_AT_THRESHOLD"); E(r,"missed_response_threshold",PIN.miss); E(r,"missed_count_at_fail",PIN.miss); E(r,"missed_count_still_ok",PIN.miss-1); },
  "WIFI-LIVENESS-BLACKHOLE-DETECTION": (r) => { E(r,"result","FENCED_ON_BLACKHOLE"); E(r,"blackhole_detect_ms",PIN.bh); E(r,"tcp_ack_alone_not_liveness",1); },
  "WIFI-LIVENESS-TCP-HALF-OPEN": (r) => { E(r,"result","FENCED_HALF_OPEN"); E(r,"condition","PEER_SILENT_TCP_STILL_WRITABLE"); E(r,"os_tcp_keepalive_is_authority",0); E(r,"nwb1_or_probe_response_required",1); },
  "WIFI-LIVENESS-AP-DEAD-BACKHAUL": (r) => { E(r,"result","FENCED_DEAD_BACKHAUL"); E(r,"wifi_associated",1); E(r,"ip_ready",1); E(r,"peer_probe_ok",0); E(r,"nwb1_publish",0); },
  "WIFI-LIVENESS-AVAILABILITY-EPOCH-CHANGE": (r) => { E(r,"result","AVAILABILITY_PLUS_ONE"); const f=r.on_liveness_fail; require(f&&f.session_fence===1&&f.nwb1_delivery===0&&f.connection_close===1&&f.availability_epoch_delta===1&&f.double_add_forbidden===1,"lf"); },
  "WIFI-NETCRED-FULL-OLD": (r) => netClass(r,"OLD"),
  "WIFI-NETCRED-FULL-NEW": (r) => { netClass(r,"NEW"); E(r,"requires_fresh_association",1); },
  "WIFI-NETCRED-FULL-ABSENT": (r) => { netClass(r,"ABSENT"); E(r,"result","ABSENT_RECLASSIFY_ONLY"); E(r,"create_result","COMMIT_UNKNOWN_NO_PUBLISH"); require(Array.isArray(r.old_rows)&&r.old_rows.length===0,"old0"); require(Array.isArray(r.observed_rows)&&r.observed_rows.length===0,"obs0"); },
  "WIFI-NETCRED-FULL-BOTH": (r) => { netClass(r,"BOTH"); E(r,"result","BOTH_OLD_AND_NEW_PRESENT"); },
  "WIFI-NETCRED-PARTIAL": (r) => { netClass(r,"PARTIAL"); E(r,"result","CORRUPT_OR_COMMIT_UNKNOWN_NO_PUBLISH"); },
  "WIFI-NETCRED-EXTRA": (r) => netClass(r,"EXTRA"),
  "WIFI-NETCRED-THIRD": (r) => netClass(r,"THIRD"),
  "WIFI-NETCRED-DUPLICATE-KEY": (r) => { netClass(r,"CORRUPT"); E(r,"result","CORRUPT_DUPLICATE_KEY"); E(r,"expected_duplicate_old_key_classification","CORRUPT"); E(r,"duplicate_old_key_classification","CORRUPT"); const old=mapRows(r.old_rows,"o"); const neu=mapRows(r.new_rows,"n"); require(classifyCU([old[0],old[0]], neu, old)==="CORRUPT","dupold"); },
  "WIFI-NETCRED-COMMIT-UNKNOWN-RECOVERY": (r) => { E(r,"result","RECLASSIFY_ONLY"); E(r,"silent_fallback_forbidden",1); E(r,"publish_before_reclassify",0); require(new Set(r.classifications_allowed_on_reopen).size===CLOSED.length && CLOSED.every((x)=>r.classifications_allowed_on_reopen.includes(x)),"allowed"); require(r.classifications_allowed_on_reopen.includes("CORRUPT"),"corrupt"); E(r,"absent_example_classification","ABSENT"); },
  "WIFI-NETCRED-ROLLBACK-REJECT": (r) => { E(r,"result","FENCED_ROLLBACK"); E(r,"current_revision",2); E(r,"observed_revision",1); E(r,"publish",0); require(hex(r.observed_value_hex,"v").subarray(0,4).toString()==="NWD1","magic"); },
  "WIFI-NETCRED-SAME-REVISION-DIGEST-CONFLICT": (r) => { E(r,"result","FENCED_DIGEST_CONFLICT"); E(r,"revision",2); E(r,"digests_equal",0); E(r,"publish",0); require(!eq(hex(r.canonical_value_hex,"a"), hex(r.conflicting_value_hex,"b")),"diff"); },
  "WIFI-NETCRED-NO-PLAINTEXT-SECRET": (r) => { E(r,"result","OK_NO_PLAINTEXT"); E(r,"secret_field","secret_ref_digest_only"); for (const f of ["old_value_hex","new_value_hex"]) { const raw=hex(r[f],f); require(raw.length===PIN.nwd1,"len"); require(validateNwd1(raw)==="OK","frame"); require(!raw.toString("latin1").toLowerCase().includes("hunter2"),"pw"); } require(r.nwd1_kat_value_hex===PIN.katValue,"kat value pin"); require(intEq(r.nwd1_kat_header_crc32c, PIN.katCrc),"kat crc pin"); require(r.nwd1_kat_auth_digest_hex===PIN.katAuth,"kat auth pin"); require(r.nwd1_kat_complete_digest_hex===PIN.katComplete,"kat complete pin"); const kat=hex(PIN.katValue,"kat"); require(validateNwd1(kat)==="OK","kat frame"); require(nwd1HeaderCrc(kat)===PIN.katCrc,"kat crc re"); require(eq(nwd1Auth(kat), hex(PIN.katAuth,"ka")),"kat auth re"); require(eq(nwd1Complete(kat), hex(PIN.katComplete,"kc")),"kat complete re"); require(!kat.includes(Buffer.from("ninlil-lab-ssid")),"not lab"); require(kat.includes(Buffer.from("KAT-NWD1-FIXED")),"fixed ssid"); },
  "WIFI-ENDPOINT-IPV4-SCOPE": (r) => { E(r,"result","OK"); E(r,"address_kind",1); E(r,"dns_authority",0); E(r,"unused_tail_must_be_zero",1); E(r,"port",8443); const a=hex(r.address_hex,"a"); require(a.length===16 && a.subarray(4).equals(Buffer.alloc(12)),"tail"); },
  "WIFI-ENDPOINT-IPV6-SCOPE": (r) => { E(r,"result","OK"); E(r,"address_kind",2); E(r,"port",8443); require(hex(r.address_hex,"a").length===16,"len"); },
  "WIFI-ENDPOINT-LINK-LOCAL-SCOPE-ID": (r) => { E(r,"result","OK_WITH_SCOPE_ID"); E(r,"scope_id_required",1); E(r,"scope_id_zero_rejected",1); E(r,"scope_id_zero_result","REJECT"); require(Number.isInteger(r.scope_id_u32)&&r.scope_id_u32>=1&&r.scope_id_u32<2**32,"scope"); const a=hex(r.address_hex,"a"); require(a[0]===0xfe && (a[1]&0xc0)===0x80,"fe80"); },
  "WIFI-ENDPOINT-DNS-MDNS-NON-AUTHORITY": (r) => { E(r,"result","AUXILIARY_ONLY"); E(r,"last_known_address_authority",0); E(r,"mdns_browse",1); E(r,"authority_endpoint_change_requires_config_revision",1); },
  "WIFI-ENDPOINT-ADDRESS-CHANGE-FENCE": (r) => { E(r,"result","FENCED"); E(r,"session_fence",1); E(r,"availability_epoch_delta",1); E(r,"reuse_old_socket_forbidden",1); E(r,"nwb1_publish",0); E(r,"event","IP_EVENT_STA_GOT_IP_CHANGE_OR_LOST"); },
};
function netClass(r, exp) {
  const got = classifyCU(mapRows(r.old_rows,"o"), mapRows(r.new_rows,"n"), mapRows(r.observed_rows,"s"));
  require(got===exp, `class ${got}`); E(r,"classification",exp); E(r,"expected_classification",exp); E(r,"publish",0);
}
function nwb(r, doc, exp, bind=false, seq=undefined) {
  const rec = hex(r.record_hex,"r");
  const session = hex(doc.pins.session_id_hex,"s");
  const got = bind ? classifyNwb1(rec, session, seq) : classifyNwb1(rec);
  require(got===exp, `nwb ${got}`);
  if (r.classification !== undefined) E(r,"classification",exp);
  if (r.expected !== undefined) E(r,"expected",exp);
}
// NWB/TLS/resource/race asserters continued
Object.assign(ASSERTERS, {
  "WIFI-NWB1-HEADER-40": (r,d)=>{ E(r,"header_length",40); nwb(r,d,"OK",true,0); },
  "WIFI-NWB1-PAYLOAD-586-REJECT": (r,d)=>{ E(r,"payload_length",586); nwb(r,d,"CORRUPT"); },
  "WIFI-NWB1-PAYLOAD-587-ACCEPT": (r,d)=>{ E(r,"payload_length",587); E(r,"total_length",627); nwb(r,d,"OK",true,0); require(hex(r.record_hex,"r").length===627,"len"); require(eq(sha(hex(r.record_hex,"r")), hex(d.pins.nwb1_min_record_sha256_hex,"p")),"pin"); },
  "WIFI-NWB1-PAYLOAD-1925-ACCEPT": (r,d)=>{ E(r,"payload_length",1925); E(r,"total_length",1965); nwb(r,d,"OK",true,0); },
  "WIFI-NWB1-PAYLOAD-1926-REJECT": (r,d)=>{ E(r,"payload_length",1926); nwb(r,d,"CORRUPT"); },
  "WIFI-NWB1-TOTAL-626-REJECT": (r,d)=>{ E(r,"total_length",626); nwb(r,d,"CORRUPT"); },
  "WIFI-NWB1-TOTAL-627-ACCEPT": (r,d)=>{ E(r,"total_length",627); nwb(r,d,"OK"); },
  "WIFI-NWB1-TOTAL-1965-ACCEPT": (r,d)=>{ E(r,"total_length",1965); nwb(r,d,"OK"); },
  "WIFI-NWB1-TOTAL-1966-REJECT": (r,d)=>{ E(r,"total_length",1966); nwb(r,d,"CORRUPT"); },
  "WIFI-NWB1-CRC32C-INDEPENDENT": (r)=>{ const good=hex(r.record_hex,"g"); const bad=hex(r.mutated_record_hex,"b"); require(classifyNwb1(good)==="OK"&&classifyNwb1(bad)==="CORRUPT","crc"); E(r,"expected_good","OK"); E(r,"expected_bad","CORRUPT"); const rep=Buffer.from(bad); rep.fill(0,36,40); rep.writeUInt32BE(crc32c(rep),36); require(eq(rep,good),"rest"); },
  "WIFI-NWB1-PARTIAL-HEADER": (r)=>{ E(r,"result","WANT_READ_NO_DELIVERY"); E(r,"deliverable",0); E(r,"need_bytes",40); require(r.bytes_available<40,"av"); },
  "WIFI-NWB1-PARTIAL-BODY": (r)=>{ E(r,"result","WANT_READ_NO_DELIVERY"); E(r,"deliverable",0); E(r,"need_bytes",627); require(r.bytes_available>40&&r.bytes_available<627,"av"); },
  "WIFI-NWB1-COALESCED-RECORDS": (r,d)=>{ E(r,"record_count",2); E(r,"first_sequence",0); E(r,"second_sequence",1); const stream=hex(r.stream_hex,"s"); const session=hex(d.pins.session_id_hex,"ss"); require(classifyNwb1(stream.subarray(0,627),session,0)==="OK","f"); require(classifyNwb1(stream.subarray(627,1254),session,1)==="OK","s"); },
  "WIFI-NWB1-READ-AHEAD-BOUND": (r)=>{ E(r,"result","BOUND_OK"); E(r,"max_records_read_ahead",1); E(r,"unlimited_read_ahead_forbidden",1); E(r,"buffer_bytes",1965); },
  "WIFI-NWB1-WRONG-SESSION": (r,d)=>{ const session=hex(d.pins.session_id_hex,"s"); require(classifyNwb1(hex(r.record_hex,"r"),session)==="WRONG_SESSION","ws"); E(r,"expected","WRONG_SESSION"); E(r,"connection_close",1); E(r,"delivery",0); },
  "WIFI-NWB1-SEQUENCE-0": (r,d)=>{ E(r,"sequence",0); nwb(r,d,"OK",true,0); },
  "WIFI-NWB1-SEQUENCE-MAX-MINUS-ONE": (r,d)=>{ E(r,"sequence",0xfffffffe); nwb(r,d,"OK",true,0xfffffffe); E(r,"next_action","CLEAN_CLOSE_THEN_FRESH_SESSION"); },
  "WIFI-NWB1-SEQUENCE-UINT32-MAX-REJECT": (r,d)=>{ E(r,"sequence",0xffffffff); E(r,"emit_forbidden",1); nwb(r,d,"SEQUENCE_REJECT"); require(r.sequence<2**32,"ov"); },
  "WIFI-NWB1-DUPLICATE": (r)=>{ E(r,"prior_delivered_sequence",1); E(r,"expected_sequence",2); E(r,"received_sequence",1); E(r,"is_duplicate_of_prior",1); E(r,"result","CLOSE_NO_DELIVERY"); E(r,"delivery",0); E(r,"connection_close",1); require(r.expected_sequence===r.prior_delivered_sequence+1,"next"); require(r.received_sequence!==r.expected_sequence,"dup"); require(hex(r.record_hex,"r").readUInt32BE(32)===1,"wire"); },
  "WIFI-NWB1-GAP": (r)=>{ E(r,"prior_delivered_sequence",0); E(r,"expected_sequence",1); E(r,"received_sequence",2); E(r,"is_gap",1); E(r,"result","CLOSE_NO_DELIVERY"); E(r,"delivery",0); E(r,"connection_close",1); },
  "WIFI-NWB1-OUT-OF-ORDER": (r)=>{ E(r,"prior_delivered_sequence",1); E(r,"expected_sequence",2); E(r,"received_sequence",1); E(r,"is_out_of_order",1); E(r,"result","CLOSE_NO_DELIVERY"); E(r,"delivery",0); E(r,"connection_close",1); },
  "WIFI-NWB1-WRAP-REJECT": (r)=>{ E(r,"result","CLEAN_CLOSE_FRESH_HANDSHAKE"); E(r,"last_sent_sequence",0xfffffffe); E(r,"wrap_to_zero_same_session_forbidden",1); E(r,"fresh_session_sequence",0); },
  "WIFI-NWB1-INVALID-NFL1": (r,d)=>{ nwb(r,d,"INVALID_NFL1",true,0); E(r,"delivery",0); E(r,"connection_close",1); require(hex(r.record_hex,"r").subarray(40,44).toString()!=="NFL1","magic"); },
  "WIFI-TLS-SUITE-GROUP-SIGNATURE-EXACT": (r)=>{ E(r,"result","OK_EXACT"); E(r,"protocol","TLS1.3"); E(r,"ciphersuite_id",PIN.suite); E(r,"group_id",PIN.group); E(r,"signature_id",PIN.sig); },
  "WIFI-TLS-X509-ROLE-RUNTIME-ATTACHMENT": (r)=>{ E(r,"result","OK"); E(r,"binding_length",82); E(r,"client_role",1); E(r,"server_role",2); E(r,"shared_leaf_forbidden",1); const c=hex(r.client_binding_hex,"c"), s=hex(r.server_binding_hex,"s"); require(c[1]===1&&s[1]===2&&!eq(c,s),"roles"); },
  "WIFI-TLS-EXPORTER-PEER-CONTEXT-62": (r,d)=>{ E(r,"result","OK"); E(r,"label","EXPORTER-Ninlil-PeerSession-v1"); const c=hex(r.context_hex,"c"); require(c.length===62&&c[28]===1&&c[45]===2,"ctx"); require(eq(sha(c),hex(d.pins.peer_context_sha256_hex,"p")),"pin"); },
  "WIFI-TLS-EXPORTER-ATTACHED-CONTEXT-64": (r,d)=>{ E(r,"result","OK"); E(r,"depends_on_m4_full",1); const c=hex(r.context_hex,"c"); require(c.length===64,"len"); require(eq(sha(c),hex(d.pins.attached_context_sha256_hex,"p")),"pin"); },
  "WIFI-TLS-AUTHORITY-ALL-ZERO-GROUP": (r)=>{ E(r,"result","PROFILE_CONDITIONAL"); E(r,"group_class","ALL_ZERO"); E(r,"expected_class","ALL_ZERO"); E(r,"bound_profile_rejects_all_zero",1); },
  "WIFI-TLS-AUTHORITY-MIXED-REJECT": (r)=>{ E(r,"result","REJECT"); E(r,"group_class","MIXED"); E(r,"session_established",0); },
  "WIFI-TLS-TICKET-0RTT-RENEGOTIATION-FENCE": (r)=>{ E(r,"result","FENCED_IF_OBSERVED"); E(r,"session_tickets",0); E(r,"early_data_bytes_publish",0); E(r,"renegotiation",0); E(r,"post_handshake_auth",0); E(r,"key_update_local_emit",0); },
  "WIFI-TLS-REVOCATION-CLOCK-RULES": (r)=>{ E(r,"result","OK_RULES"); E(r,"authority_clock_only",1); E(r,"os_wall_clock_authority",0); E(r,"snapshot_age_max_ms",300000); E(r,"age_300001_reject",1); E(r,"now_equals_valid_until_reject",1); },
  "WIFI-TLS-R7-OPENSSL-GENERIC-NON-AUTHORITY": (r)=>{ E(r,"result","NON_AUTHORITY_FOR_WIFI_PROFILE"); E(r,"satisfies_wifi_host_pin",0); E(r,"may_use_system_openssl_3",1); },
  "WIFI-TLS-HOST-OPENSSL-PIN-AUTHORITY": (r)=>{ E(r,"result","HOST_WIFI_AUTHORITY"); E(r,"tag",PIN.hostTag); E(r,"peeled_commit",PIN.hostPeeled); E(r,"static_only",1); require(Array.isArray(r.targets)&&r.targets.length===2,"t"); },
  "WIFI-TLS-ESP-MBEDTLS-PIN-AUTHORITY": (r)=>{ E(r,"result","ESP_WIFI_AUTHORITY"); E(r,"esp_idf_commit",PIN.espIdf); E(r,"mbedtls_commit",PIN.espMbed); E(r,"esp_tls_public_api_forbidden",1); E(r,"direct_mbedtls_only",1); },
  "WIFI-PREATTACH-CARRIER-NOT-NWB1": (r)=>{ E(r,"result","BOUNDARY_OK"); E(r,"nwb1_as_attachment_carrier",0); E(r,"m4_carrier_required",1); },
  "WIFI-PREATTACH-PEER-SESSION-ONLY-NO-NWB1": (r)=>{ E(r,"result","NO_NWB1"); E(r,"state","PEER_SESSION"); E(r,"nwb1_send",0); E(r,"nwb1_receive",0); E(r,"fabric_availability",0); E(r,"application_publish",0); },
  "WIFI-PREATTACH-NWB1-REQUIRES-PA-FULL": (r)=>{ E(r,"result","OK_POST_ATTACHMENT"); E(r,"state","ATTACHED"); E(r,"m4_full_durable",1); E(r,"nwb1_allowed",1); E(r,"m4_missing_nwb1_allowed",0); },
  "WIFI-RESOURCE-ESP-CAPACITY": (r,d)=>{ E(r,"result","ESP_BOUNDS"); E(r,"adapter_max",1); E(r,"session_max",2); E(r,"event_queue_max",PIN.eq); E(r,"event_queue_overflow_at",PIN.eq+1); E(r,"record_bytes",1965); const c=d.constants; E(c,"esp_tls_session_total_bytes",98304); E(c,"esp_tls_session_internal_bytes",12288); E(c,"esp_tls_session_psram_bytes",86016); require(c.esp_tls_session_internal_bytes+c.esp_tls_session_psram_bytes===c.esp_tls_session_total_bytes,"tier sum"); E(c,"esp_tls_crypto_global_internal_bytes",65536); E(c,"esp_tls_post_admission_internal_floor_bytes",65536); E(c,"esp_tls_execution_stack_bytes",8192); E(c,"esp_tls_crypto_dma_bytes",0); const envelope=c.esp_tls_crypto_global_internal_bytes+2*c.esp_tls_session_internal_bytes+c.esp_tls_post_admission_internal_floor_bytes+c.esp_tls_execution_stack_bytes+c.esp_tls_crypto_dma_bytes; E(c,"esp_tls_two_session_internal_envelope_bytes",163840); require(envelope===c.esp_tls_two_session_internal_envelope_bytes,"envelope"); E(c,"esp_tls_map_remainder_observation_bytes",171825); E(c,"esp_tls_map_observation_slack_bytes",7985); require(c.esp_tls_map_remainder_observation_bytes-envelope===c.esp_tls_map_observation_slack_bytes,"slack"); E(c,"esp_tls_in_buffer_bytes",16685); E(c,"esp_tls_out_buffer_bytes",4415); E(c,"esp_tls_psram_required",1); E(c,"esp_tls_generic_spill_allowed",0); E(c,"esp_tls_psram_exact_live_allocation_required",1); E(c,"esp_tls_psram_interior_pointer_allowed",0); E(c,"esp_tls_psram_free_pointer_allowed",0); E(c,"esp_tls_psram_wrong_size_allowed",0); E(c,"esp_tls_cross_owner_free_allowed",0); E(c,"esp_tls_contract_null_spill_allowed",0); E(c,"esp_tls_ordinary_oom_is_global_fatal",0); E(c,"esp_tls_canary_corruption_is_global_fatal",1); },
  "WIFI-RESOURCE-HOST-CAPACITY": (r)=>{ E(r,"result","HOST_BOUNDS"); E(r,"adapter_max",64); E(r,"session_max",64); E(r,"tx_token_per_session",8); },
  "WIFI-RESOURCE-PRIORITY-ISOLATION": (r)=>{ E(r,"result","ISOLATED"); E(r,"bulk_may_starve_critical",0); require(JSON.stringify(r.queues)===JSON.stringify(["critical_control","application_data","management_bulk"]),"q"); },
  "WIFI-RESOURCE-RETAINED-TOKEN-PARTIAL-WRITE": (r)=>{ E(r,"result","OK"); E(r,"start_send_full_copy_own",1); E(r,"partial_tcp_tls_write_outer_would_block",0); E(r,"poll_send_internal",1); E(r,"token_null_means_retain_0",1); },
  "WIFI-RESOURCE-RELEASE-SEMANTICS": (r)=>{ E(r,"result","OK"); E(r,"release_send_exact_count_after_terminal",1); E(r,"release_before_terminal_forbidden",1); },
  "WIFI-RESOURCE-NO-FALSE-CUSTODY": (r)=>{ E(r,"result","NO_CUSTODY"); E(r,"nwb1_socket_write_is_custody",0); E(r,"tls_record_success_is_custody",0); E(r,"peer_kernel_ack_is_custody",0); E(r,"fabric_cap_custody_advertised",0); },
  "WIFI-RESOURCE-STORAGE-ARITHMETIC": (r)=>{ E(r,"result","ARITHMETIC_OK"); E(r,"nwd1_record_bytes",PIN.nwd1); E(r,"nwd1_keys_max",PIN.keys); E(r,"committed_cu_bytes",PIN.cu); E(r,"staging_cu_bytes",PIN.st); E(r,"plaintext_password_in_storage",0); require(r.committed_cu_bytes===r.nwd1_keys_max*r.nwd1_record_bytes,"cu"); require(r.staging_cu_bytes===r.committed_cu_bytes*2,"st"); },
  "WIFI-ROLE-HOST-POSIX-TCP-TLS": (r)=>{ E(r,"result","HOST_RESPONSIBILITY"); E(r,"adapter_kind",1); E(r,"tls_backend","PINNED_OPENSSL_3_5_7_STATIC"); E(r,"network_profile_zero_required",1); E(r,"credential_provider_null_required",1); E(r,"wifi_driver_owner",0); },
  "WIFI-ROLE-ESP32S3-STA-LWIP-MBEDTLS": (r)=>{ E(r,"result","ESP_RESPONSIBILITY"); E(r,"adapter_kind",2); E(r,"tls_backend","ESP_IDF_SUPPLIED_MBEDTLS_DIRECT"); E(r,"wifi_driver_sole_owner",1); E(r,"wifi_storage_ram",1); E(r,"credential_provider_required",1); },
  "WIFI-RACE-DISCONNECT-RECONNECT": (r)=>{ E(r,"result","DETERMINISTIC"); E(r,"reconnect_before_fence_forbidden",1); require(JSON.stringify(r.order)===JSON.stringify(DISCONNECT),"ord"); },
  "WIFI-RACE-SLEEP-DRAIN": (r)=>{ E(r,"result","DETERMINISTIC"); E(r,"sleep_marks_unavailable",1); E(r,"availability_epoch_delta_on_sleep",1); E(r,"fake_available_while_asleep",0); E(r,"drain_blocks_new_send_retention",1); },
  "WIFI-RACE-EVENT-OVERFLOW": (r)=>{ E(r,"result","OVERFLOW_FENCE"); E(r,"event_queue_max",PIN.eq); E(r,"overflow_count",PIN.eq+1); E(r,"result_state","FENCED"); E(r,"availability",0); E(r,"sockets_closed",1); },
  "WIFI-BACKOFF-DETERMINISTIC": (r,d)=>{ E(r,"result","DETERMINISTIC"); require(JSON.stringify(r.schedule_ms)===JSON.stringify(PIN.backoff),"sch"); E(r,"cap_ms",32000); E(r,"entropy_forbidden",1); E(r,"os_random_forbidden",1); const inst=hex(r.instance_id_hex,"i"); require(eq(inst,hex(d.pins.instance_id_hex,"p")),"ipin"); for (const s of r.samples) { const gen=s.failure_generation; const bo=gen<=6?PIN.backoff[gen-1]:32000; const gb=Buffer.alloc(8); gb.writeBigUInt64BE(BigInt(gen)); const j=sha(Buffer.concat([inst,gb])).readUInt16BE(0)%1000; require(s.backoff_ms===bo&&s.jitter_ms===j&&s.not_before_offset_ms===bo+j,`g${gen}`); } },
});
function exactKeys(obj, allowed, path) {
  require(obj && typeof obj === "object" && !Array.isArray(obj), `${path} object`);
  for (const k of Object.keys(obj)) {
    if (FORBIDDEN_KEYS.has(k)) fail(`${path}: forbidden ${k}`);
    if (!allowed.has(k)) fail(`${path}: unknown ${k}`);
  }
}
function isVectorRowPath(path) {
  for (const g of GROUPS) {
    const prefix = `$.${g}[`;
    if (path.startsWith(prefix) && (path.match(/\[/g) || []).length === 1 && path.endsWith("]")) return true;
  }
  return false;
}
function walkClosed(value, path) {
  if (value === null) fail(`${path}: null`);
  // Normative integers are 0/1; JSON booleans are never allowed at any leaf.
  if (typeof value === "boolean") fail(`${path}: bool forbidden (normative integers are 0/1, not JSON bool)`);
  if (typeof value === "number" || typeof value === "bigint" || typeof value === "string") return;
  if (Array.isArray(value)) {
    value.forEach((item, i) => walkClosed(item, `${path}[${i}]`));
    return;
  }
  if (typeof value === "object") {
    for (const k of Object.keys(value)) {
      if (FORBIDDEN_KEYS.has(k)) fail(`${path}: forbidden ${k}`);
    }
    if (path === "$.constants") exactKeys(value, CLOSED_CONSTANTS, path);
    else if (path === "$.pins") exactKeys(value, CLOSED_PINS, path);
    else if (path === "$.storage_arithmetic") exactKeys(value, CLOSED_STORAGE, path);
    else if (path === "$.source_vector_restoration") exactKeys(value, CLOSED_RESTORATION, path);
    else if (path.endsWith(".on_liveness_fail")) exactKeys(value, CLOSED_ON_LIVENESS, path);
    else if (/\.(old_rows|new_rows|observed_rows)\[\d+\]$/.test(path)) exactKeys(value, CLOSED_NWD1_ITEM, path);
    else if (/\.samples\[\d+\]$/.test(path)) exactKeys(value, CLOSED_SAMPLE, path);
    else if (isVectorRowPath(path)) {
      for (const k of Object.keys(value)) {
        if (!CLOSED_ROW_KEYS.has(k)) fail(`${path}: unknown row key ${k}`);
      }
    }
    for (const [k, v] of Object.entries(value)) walkClosed(v, `${path}.${k}`);
    return;
  }
  fail(`${path}: type`);
}
function assertDocumentStructure(doc) {
  require(doc && typeof doc === "object" && !Array.isArray(doc), "root object");
  for (const k of Object.keys(doc)) require(CLOSED_ROOT.has(k), `unknown root ${k}`);
  if (doc.adr !== undefined) {
    require(typeof doc.adr === "string", "adr type");
    require(doc.adr !== true && doc.adr !== false, "adr bool");
  }
  walkClosed(doc, "$");
}
function iterObjectPaths(value, path = "$") {
  const out = [];
  if (value && typeof value === "object" && !Array.isArray(value)) {
    out.push(path);
    for (const [k, v] of Object.entries(value)) {
      out.push(...iterObjectPaths(v, path === "$" ? `$.${k}` : `${path}.${k}`));
    }
  } else if (Array.isArray(value)) {
    value.forEach((item, i) => out.push(...iterObjectPaths(item, `${path}[${i}]`)));
  }
  return out;
}
function iterIntegerLeafPaths(value, path = "$") {
  const out = [];
  if (typeof value === "boolean") return out;
  if (typeof value === "number" || typeof value === "bigint") {
    out.push(path);
    return out;
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    for (const [k, v] of Object.entries(value)) {
      out.push(...iterIntegerLeafPaths(v, path === "$" ? `$.${k}` : `${path}.${k}`));
    }
  } else if (Array.isArray(value)) {
    value.forEach((item, i) => out.push(...iterIntegerLeafPaths(item, `${path}[${i}]`)));
  }
  return out;
}
function iterStringLeafPaths(value, path = "$") {
  const out = [];
  if (typeof value === "string") { out.push(path); return out; }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    for (const [k, v] of Object.entries(value)) {
      out.push(...iterStringLeafPaths(v, path === "$" ? `$.${k}` : `${path}.${k}`));
    }
  } else if (Array.isArray(value)) {
    value.forEach((item, i) => out.push(...iterStringLeafPaths(item, `${path}[${i}]`)));
  }
  return out;
}
function iterDigestLeafPaths(value, path = "$") {
  const out = [];
  if (value && typeof value === "object" && !Array.isArray(value)) {
    for (const [k, v] of Object.entries(value)) {
      const child = path === "$" ? `$.${k}` : `${path}.${k}`;
      if (typeof v === "string" && (k.endsWith("digest_hex") || k.endsWith("sha256_hex"))) out.push(child);
      out.push(...iterDigestLeafPaths(v, child));
    }
  } else if (Array.isArray(value)) {
    value.forEach((item, i) => out.push(...iterDigestLeafPaths(item, `${path}[${i}]`)));
  }
  return out;
}
function pathsSha256(paths) {
  return crypto.createHash("sha256").update(paths.join("\n") + "\n").digest("hex");
}
function navigateSet(doc, path, key, value) {
  let cur = doc;
  const s = path.slice(1);
  let i = 0;
  const segs = [];
  while (i < s.length) {
    if (s[i] === ".") {
      i++;
      const m = /^[A-Za-z0-9_]+/.exec(s.slice(i));
      segs.push(m[0]); i += m[0].length;
    } else if (s[i] === "[") {
      const m = /^\[(\d+)\]/.exec(s.slice(i));
      segs.push(Number(m[1])); i += m[0].length;
    } else fail(`bad path ${path}`);
  }
  for (const seg of segs) cur = cur[seg];
  cur[key] = value;
}
function navigateAssignLeaf(doc, path, value) {
  const s = path.slice(1);
  let i = 0;
  const segs = [];
  while (i < s.length) {
    if (s[i] === ".") {
      i++;
      const m = /^[A-Za-z0-9_]+/.exec(s.slice(i));
      segs.push(m[0]); i += m[0].length;
    } else if (s[i] === "[") {
      const m = /^\[(\d+)\]/.exec(s.slice(i));
      segs.push(Number(m[1])); i += m[0].length;
    } else fail(`bad path ${path}`);
  }
  let cur = doc;
  for (const seg of segs.slice(0, -1)) cur = cur[seg];
  cur[segs[segs.length - 1]] = value;
}
function assertTypeInventory(doc) {
  const objects = iterObjectPaths(doc);
  const ints = iterIntegerLeafPaths(doc).sort();
  const strs = iterStringLeafPaths(doc).sort();
  const digs = iterDigestLeafPaths(doc).sort();
  require(objects.length === PIN_OBJECT_PATH_COUNT, `object_path_count ${objects.length}`);
  require(ints.length === PIN_INTEGER_LEAF_COUNT, `integer_leaf_count ${ints.length}`);
  require(strs.length === PIN_STRING_LEAF_COUNT, `string_leaf_count ${strs.length}`);
  require(digs.length === PIN_DIGEST_LEAF_COUNT, `digest_leaf_count ${digs.length}`);
  require(pathsSha256(ints) === PIN_INTEGER_LEAF_PATHS_SHA256, "integer leaf paths sha");
  require(pathsSha256(strs) === PIN_STRING_LEAF_PATHS_SHA256, "string leaf paths sha");
  require(pathsSha256(digs) === PIN_DIGEST_LEAF_PATHS_SHA256, "digest leaf paths sha");
  const rest = doc.source_vector_restoration;
  require(intEq(rest.object_path_count, PIN_OBJECT_PATH_COUNT), "rest opc");
  require(intEq(rest.integer_leaf_count, PIN_INTEGER_LEAF_COUNT), "rest ilc");
  require(intEq(rest.string_leaf_count, PIN_STRING_LEAF_COUNT), "rest slc");
  require(intEq(rest.digest_leaf_count, PIN_DIGEST_LEAF_COUNT), "rest dlc");
  require(rest.integer_leaf_paths_sha256_hex === PIN_INTEGER_LEAF_PATHS_SHA256, "rest int sha");
  require(rest.string_leaf_paths_sha256_hex === PIN_STRING_LEAF_PATHS_SHA256, "rest str sha");
  require(rest.digest_leaf_paths_sha256_hex === PIN_DIGEST_LEAF_PATHS_SHA256, "rest dig sha");
}
function assertAllDigestPreimages(doc) {
  const pins = doc.pins;
  for (const g of GROUPS) {
    for (const row of doc[g]) {
      const rid = row.id || "?";
      for (const prefix of ["", "old_", "new_"]) {
        const digF = `${prefix}association_authority_digest_hex`;
        const inF = `${prefix}association_authority_input_hex`;
        if (row[digF] !== undefined && row[inF] !== undefined) {
          const ain = hex(row[inF], inF);
          const dig = hex(row[digF], digF);
          require(eq(sha(Buffer.concat([PIN.assocTag, ain])), dig), `${rid} ${digF} preimage`);
          const p = parseAssoc(ain);
          const binds = [
            [`${prefix}profile_id_hex`, p.profile_id.toString("hex")],
            [`${prefix}profile_digest_hex`, p.profile_digest.toString("hex")],
            [`${prefix}binding_id_hex`, p.binding_id.toString("hex")],
            [`${prefix}bssid_hex`, p.bssid.toString("hex")],
          ];
          for (const [f, exp] of binds) if (row[f] !== undefined) require(row[f] === exp, `${rid} ${f} bind`);
          if (row[`${prefix}association_epoch`] !== undefined) {
            exactInt(row[`${prefix}association_epoch`], "epoch");
            require(intEq(row[`${prefix}association_epoch`], p.association_epoch), `${rid} epoch bind`);
          }
          if (row[`${prefix}channel`] !== undefined) {
            exactInt(row[`${prefix}channel`], "ch");
            require(intEq(row[`${prefix}channel`], p.channel), `${rid} ch bind`);
          }
          if (row[`${prefix}auth_mode`] !== undefined) {
            exactInt(row[`${prefix}auth_mode`], "auth");
            require(intEq(row[`${prefix}auth_mode`], p.auth_mode), `${rid} auth bind`);
          }
        }
      }
      const pairs = [
        ["old_value_hex", "old_auth_digest_hex", "old_complete_digest_hex", "old_header_crc32c"],
        ["new_value_hex", "new_auth_digest_hex", "new_complete_digest_hex", "new_header_crc32c"],
        ["observed_value_hex", "observed_auth_digest_hex", "observed_complete_digest_hex", "observed_header_crc32c"],
        ["canonical_value_hex", null, "canonical_complete_digest_hex", null],
        ["conflicting_value_hex", null, "conflicting_complete_digest_hex", null],
        ["nwd1_kat_value_hex", "nwd1_kat_auth_digest_hex", "nwd1_kat_complete_digest_hex", "nwd1_kat_header_crc32c"],
      ];
      for (const [vf, af, cf, crcf] of pairs) {
        if (row[vf] === undefined) continue;
        const raw = hex(row[vf], vf);
        if (cf && row[cf] !== undefined) require(eq(nwd1Complete(raw), hex(row[cf], cf)), `${rid} ${cf}`);
        if (af && row[af] !== undefined) require(eq(nwd1Auth(raw), hex(row[af], af)), `${rid} ${af}`);
        if (crcf && row[crcf] !== undefined) {
          exactInt(row[crcf], crcf);
          require(intEq(row[crcf], nwd1HeaderCrc(raw)), `${rid} ${crcf}`);
        }
      }
      if (row.secret_ref_digest_hex !== undefined && row.old_value_hex !== undefined) {
        const oldV = hex(row.old_value_hex, "old");
        require(oldV.length === PIN.nwd1, "sref len");
        require(eq(oldV.subarray(128, 160), hex(row.secret_ref_digest_hex, "sref")), `${rid} secret_ref`);
      }
      for (const field of ["old_rows", "new_rows", "observed_rows"]) {
        const items = row[field] || [];
        items.forEach((item, index) => {
          if (item && item.value_hex !== undefined && item.header_crc32c !== undefined) {
            verifyNwd1Item(item, `${rid}.${field}[${index}]`);
          }
        });
      }
      if (row.record_sha256_hex !== undefined && row.record_hex !== undefined) {
        require(eq(sha(hex(row.record_hex, "r")), hex(row.record_sha256_hex, "rs")), `${rid} record_sha`);
      }
      if (row.context_sha256_hex !== undefined && row.context_hex !== undefined) {
        require(eq(sha(hex(row.context_hex, "c")), hex(row.context_sha256_hex, "cs")), `${rid} ctx_sha`);
      }
      if (row.digests_equal !== undefined && row.old_association_authority_digest_hex !== undefined) {
        exactInt(row.digests_equal, "de");
        require(intEq(row.digests_equal, row.old_association_authority_digest_hex === row.new_association_authority_digest_hex ? 1 : 0), `${rid} digests_equal`);
      }
      if (row.digests_equal !== undefined && row.canonical_value_hex !== undefined) {
        exactInt(row.digests_equal, "de2");
        require(intEq(row.digests_equal, eq(hex(row.canonical_value_hex, "a"), hex(row.conflicting_value_hex, "b")) ? 1 : 0), `${rid} value digests_equal`);
      }
    }
  }
  const findId = (id) => { for (const g of GROUPS) for (const r of doc[g]) if (r.id === id) return r; fail(id); };
  const minRow = findId("WIFI-NWB1-PAYLOAD-587-ACCEPT");
  const maxRow = findId("WIFI-NWB1-PAYLOAD-1925-ACCEPT");
  require(eq(sha(hex(minRow.record_hex, "min")), hex(pins.nwb1_min_record_sha256_hex, "pmin")), "pin min");
  require(eq(sha(hex(maxRow.record_hex, "max")), hex(pins.nwb1_max_record_sha256_hex, "pmax")), "pin max");
  const peer = findId("WIFI-TLS-EXPORTER-PEER-CONTEXT-62");
  const att = findId("WIFI-TLS-EXPORTER-ATTACHED-CONTEXT-64");
  require(eq(sha(hex(peer.context_hex, "peer")), hex(pins.peer_context_sha256_hex, "pp")), "pin peer");
  require(eq(sha(hex(att.context_hex, "att")), hex(pins.attached_context_sha256_hex, "pa")), "pin att");
  const oldNc = findId("WIFI-NETCRED-FULL-OLD");
  const newNc = findId("WIFI-NETCRED-FULL-NEW");
  require(eq(nwd1Complete(hex(oldNc.observed_rows[0].value_hex, "o")), hex(pins.nwd1_old_complete_sha256_hex, "po")), "pin nwd1 old");
  require(eq(nwd1Complete(hex(newNc.observed_rows[0].value_hex, "n")), hex(pins.nwd1_new_complete_sha256_hex, "pn")), "pin nwd1 new");
  const base = findId("WIFI-ASSOC-AUTHORITY-EPOCH-BASELINE");
  require(base.association_authority_digest_hex === pins.assoc_authority_a_hex, "assoc pin dig");
  require(base.association_authority_input_hex === pins.assoc_authority_input_a_hex, "assoc pin in");
  require(base.profile_digest_hex === pins.network_profile_digest_a_hex, "profile pin");
  const rest = doc.source_vector_restoration;
  require(rest.independent_nwd1_kat_auth_digest_hex === PIN.katAuth, "rest kat auth");
  require(rest.independent_nwd1_kat_complete_digest_hex === PIN.katComplete, "rest kat complete");
}
function exhaustiveStructureSelfTest(doc) {
  const objectPaths = iterObjectPaths(doc);
  const intLeaves = iterIntegerLeafPaths(doc);
  const strLeaves = iterStringLeafPaths(doc);
  const digLeaves = iterDigestLeafPaths(doc);
  assertDocumentStructure(doc);
  assertTypeInventory(doc);
  assertAllDigestPreimages(doc);
  let unknownAccepted = 0;
  for (const p of objectPaths) {
    const c = deep(doc);
    navigateSet(c, p, "__audit_unknown__", 1);
    try { assertDocumentStructure(c); unknownAccepted++; } catch (e) { if (!(e instanceof GateError)) throw e; }
  }
  require(unknownAccepted === 0, `exhaustive unknown-key accepted=${unknownAccepted}`);
  let boolAccepted = 0;
  for (const p of intLeaves) {
    const c = deep(doc);
    navigateAssignLeaf(c, p, true);
    try { assertDocumentStructure(c); assertTypeInventory(c); boolAccepted++; } catch (e) { if (!(e instanceof GateError)) throw e; }
  }
  require(boolAccepted === 0, `exhaustive bool-as-int accepted=${boolAccepted}`);
  let intAsStr = 0;
  for (const p of intLeaves) {
    const c = deep(doc);
    navigateAssignLeaf(c, p, "0");
    try { assertDocumentStructure(c); assertTypeInventory(c); intAsStr++; } catch (e) { if (!(e instanceof GateError)) throw e; }
  }
  require(intAsStr === 0, `exhaustive int-as-str accepted=${intAsStr}`);
  let strAsInt = 0;
  for (const p of strLeaves) {
    const c = deep(doc);
    navigateAssignLeaf(c, p, 0);
    try { assertDocumentStructure(c); assertTypeInventory(c); strAsInt++; } catch (e) { if (!(e instanceof GateError)) throw e; }
  }
  require(strAsInt === 0, `exhaustive str-as-int accepted=${strAsInt}`);
  let digFlip = 0;
  for (const p of digLeaves) {
    const c = deep(doc);
    // read and flip
    const s = p.slice(1); let i = 0; const segs = [];
    while (i < s.length) {
      if (s[i] === ".") { i++; const m = /^[A-Za-z0-9_]+/.exec(s.slice(i)); segs.push(m[0]); i += m[0].length; }
      else if (s[i] === "[") { const m = /^\[(\d+)\]/.exec(s.slice(i)); segs.push(Number(m[1])); i += m[0].length; }
      else fail(p);
    }
    let cur = c; for (const seg of segs.slice(0, -1)) cur = cur[seg];
    const v = cur[segs[segs.length - 1]];
    cur[segs[segs.length - 1]] = (v[0] !== "0" ? "0" : "1") + v.slice(1);
    try {
      assertDocumentStructure(c); assertTypeInventory(c); assertAllDigestPreimages(c);
      digFlip++;
    } catch (e) { if (!(e instanceof GateError)) throw e; }
  }
  require(digFlip === 0, `exhaustive digest-flip accepted=${digFlip}`);
  console.log(`wifi bearer Node gate exhaustive structure: OK object_paths=${objectPaths.length} unknown_accepted=0 integer_leaves=${intLeaves.length} bool_accepted=0 int_as_str_accepted=0 string_leaves=${strLeaves.length} str_as_int_accepted=0 digest_leaves=${digLeaves.length} digest_flip_accepted=0`);
}

function canonicalDocumentBytes(doc) {
  // Match Python json.dumps(indent=2, sort_keys=True) + "\\n"
  const sorted = sortKeysDeep(doc);
  return Buffer.from(JSON.stringify(sorted, null, 2) + "\n", "utf8");
}
function sortKeysDeep(value) {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value && typeof value === "object") {
    const out = {};
    for (const k of Object.keys(value).sort()) out[k] = sortKeysDeep(value[k]);
    return out;
  }
  return value;
}
function assertCanonicalDocumentModel(doc) {
  const got = crypto.createHash("sha256").update(canonicalDocumentBytes(doc)).digest("hex");
  require(got === PIN_VECTOR_DOCUMENT_SHA256, `document model sha ${got}`);
}
function assertMachineFieldPins(doc) {
  require(intEq(doc.acceptance_id_count, PIN_ACCEPTANCE_ID_COUNT), "acceptance_id_count");
  require(JSON.stringify(doc.nonclaims) === JSON.stringify(PIN_NONCLAIMS), "nonclaims");
  const c = doc.constants;
  require(c.nwb1_header_bytes === 40 && c.nwb1_payload_min === 587 && c.nwb1_payload_max === 1925, "nwb bounds");
  require(c.nwb1_total_min === 627 && c.nwb1_total_max === 1965, "nwb totals");
  require(c.nwb1_payload_reject_low === 586 && c.nwb1_payload_reject_high === 1926, "nwb reject pl");
  require(c.nwb1_total_reject_low === 626 && c.nwb1_total_reject_high === 1966, "nwb reject tl");
  require(c.peer_context_bytes === 62 && c.attached_context_bytes === 64, "ctx");
  require(c.keepalive_interval_ms === 15000 && c.keepalive_exclusive_deadline_ms === 15000, "ka");
  require(c.missed_response_threshold === 3 && c.blackhole_detect_ms === 45000, "live");
  require(c.session_lifetime_ms === 3600000, "session life");
  require(c.nwd1_record_bytes === 160 && c.nwd1_committed_cu_bytes === 1280 && c.nwd1_staging_cu_bytes === 2560, "nwd1");
  require(c.record_bytes_fixed === 1965, "rec fixed");
  require(c.esp_tls_session_total_bytes === 98304, "tls total");
  require(c.esp_tls_session_internal_bytes === 12288 && c.esp_tls_session_psram_bytes === 86016, "tls tiers");
  require(c.esp_tls_session_internal_bytes + c.esp_tls_session_psram_bytes === c.esp_tls_session_total_bytes, "tls tier sum");
  require(c.esp_tls_crypto_global_internal_bytes === 65536 && c.esp_tls_post_admission_internal_floor_bytes === 65536, "tls global floor");
  require(c.esp_tls_original_internal_only_requirement_bytes === 327680, "tls original internal-only");
  require(2 * c.esp_tls_session_total_bytes + c.esp_tls_crypto_global_internal_bytes + c.esp_tls_post_admission_internal_floor_bytes === c.esp_tls_original_internal_only_requirement_bytes, "tls original internal-only arithmetic");
  require(c.esp_tls_execution_stack_bytes === 8192 && c.esp_tls_crypto_dma_bytes === 0, "tls stack dma");
  const tlsEnvelope = c.esp_tls_crypto_global_internal_bytes + 2 * c.esp_tls_session_internal_bytes + c.esp_tls_post_admission_internal_floor_bytes + c.esp_tls_execution_stack_bytes + c.esp_tls_crypto_dma_bytes;
  require(tlsEnvelope === 163840 && c.esp_tls_two_session_internal_envelope_bytes === tlsEnvelope, "tls envelope");
  require(c.esp_tls_map_remainder_observation_bytes === 171825 && c.esp_tls_map_observation_slack_bytes === 7985, "tls map obs");
  require(c.esp_tls_map_remainder_observation_bytes - tlsEnvelope === c.esp_tls_map_observation_slack_bytes, "tls map arithmetic");
  require(c.esp_tls_in_buffer_bytes === 16685 && c.esp_tls_out_buffer_bytes === 4415, "tls io buffers");
  require(c.esp_tls_psram_required === 1 && c.esp_tls_generic_spill_allowed === 0, "tls psram spill");
  require(c.esp_tls_psram_exact_live_allocation_required === 1, "tls exact live");
  require(c.esp_tls_psram_interior_pointer_allowed === 0 && c.esp_tls_psram_free_pointer_allowed === 0 && c.esp_tls_psram_wrong_size_allowed === 0, "tls pointer reject");
  require(c.esp_tls_cross_owner_free_allowed === 0 && c.esp_tls_contract_null_spill_allowed === 0, "tls owner spill");
  require(c.esp_tls_ordinary_oom_is_global_fatal === 0 && c.esp_tls_canary_corruption_is_global_fatal === 1, "tls failure classes");
  require(c.tls_ciphersuite_id === 0x1301 && c.tls_group_id === 0x0017 && c.tls_signature_id === 0x0403, "tls ids");
  require(c.network_namespace === "ninlil.wifi.network.v1", "ns");
  const p = doc.pins;
  require(p.host_openssl_tag === PIN.hostTag && p.host_openssl_peeled === PIN.hostPeeled, "host pin");
  require(p.esp_idf_commit === PIN.espIdf && p.esp_mbedtls_commit === PIN.espMbed, "esp pin");
  require(p.assoc_authority_tag_ascii === "NINLIL-WIFI-ASSOC-AUTHORITY-V1", "assoc tag");
  require(intEq(p.nfl1_header_bytes, 584) && intEq(p.nfl1_version, 1), "nfl1 pin");
  const s = doc.storage_arithmetic;
  require(intEq(s.nwd1_record_bytes, 160) && intEq(s.nwd1_keys_max, 8), "st rec");
  require(intEq(s.committed_cu_bytes, 1280) && intEq(s.staging_cu_bytes, 2560), "st cu");
  require(s.committed_formula === "keys_max * record_bytes" && s.staging_formula === "committed_cu_bytes * 2", "st form");
  require(intEq(s.esp_nwd1_active_profiles_max, 1) && intEq(s.host_nwd1_active_profiles_max, 8), "st profiles");
  require(intEq(s.plaintext_password_in_storage, 0) && intEq(s.plaintext_password_in_vectors, 0), "st plain");
  require(intEq(s.secret_ref_digest_only, 1), "st sref");
  const r = doc.source_vector_restoration;
  require(r.schema === PIN.schema && r.adr === PIN.adr && r.generator === PIN.generator, "rest meta");
  require(r.gate_py === PIN.gatePy && r.gate_mjs === PIN.gateMjs && r.vector === PIN.vector && r.c_test === PIN.cTest, "rest paths");
  require(JSON.stringify(r.tool_paths) === JSON.stringify(PIN.toolPaths), "rest tools");
  require(r.absent_row_id === "WIFI-NETCRED-FULL-ABSENT", "rest absent");
  require(r.duplicate_expected_sequence_rule === "prior_delivered + 1", "rest dup");
  require(intEq(r.acceptance_id_count, 79) && intEq(r.nwb1_min_total, 627) && intEq(r.nwb1_max_total, 1965), "rest counts");
  require(intEq(r.commit_unknown_includes_corrupt, 1) && intEq(r.release_before_terminal_forbidden, 1), "rest flags");
  require(r.independent_nwd1_kat_value_hex === PIN.katValue, "rest kat v");
  require(intEq(r.independent_nwd1_kat_header_crc32c, PIN.katCrc), "rest kat c");
  require(r.independent_nwd1_kat_auth_digest_hex === PIN.katAuth && r.independent_nwd1_kat_complete_digest_hex === PIN.katComplete, "rest kat d");
  const secret = byId(doc, "WIFI-NETCRED-NO-PLAINTEXT-SECRET");
  require(JSON.stringify(secret.password_substrings_forbidden) === JSON.stringify(["hunter2","p@ssw0rd","correct-horse-battery"]), "pw sub");
  const recovery = byId(doc, "WIFI-NETCRED-COMMIT-UNKNOWN-RECOVERY");
  require(recovery.both_example_classification === "BOTH", "both ex");
}
function iterScalarLeaves(value, path = "$") {
  const out = [];
  if (typeof value === "boolean") return out;
  if (typeof value === "number" || typeof value === "bigint" || typeof value === "string") {
    out.push([path, value]);
    return out;
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    for (const [k, v] of Object.entries(value)) out.push(...iterScalarLeaves(v, path === "$" ? `$.${k}` : `${path}.${k}`));
  } else if (Array.isArray(value)) {
    value.forEach((item, i) => out.push(...iterScalarLeaves(item, `${path}[${i}]`)));
  }
  return out;
}
function typePreservingMutate(value) {
  if (typeof value === "number" || typeof value === "bigint") return typeof value === "bigint" ? value + 1n : value + 1;
  if (typeof value === "string") {
    if (value && /^[0-9a-f]*$/.test(value) && value.length % 2 === 0) return (value[0] !== "0" ? "0" : "1") + value.slice(1);
    return value + "_DRIFT";
  }
  return value;
}
function exhaustiveScalarValueSelfTest(doc) {
  const leaves = iterScalarLeaves(doc);
  require(leaves.length === 1078, `scalar leaves ${leaves.length}`);
  let accepted = 0;
  for (const [path, original] of leaves) {
    if (DESCRIPTIVE_SCALAR_ALLOWLIST.has(path)) continue;
    const c = deep(doc);
    navigateAssignLeaf(c, path, typePreservingMutate(original));
    try {
      assertDocumentStructure(c);
      assertTypeInventory(c);
      assertAllDigestPreimages(c);
      assertMachineFieldPins(c);
      assertCanonicalDocumentModel(c);
      accepted++;
    } catch (e) {
      if (!(e instanceof GateError)) throw e;
    }
  }
  require(accepted === 0, `exhaustive scalar-value accepted=${accepted}`);
  console.log(`wifi bearer Node gate exhaustive scalar-value: OK leaves=${leaves.length} accepted=0 allowlist=0`);
}
function validate(doc) {
  require(Object.keys(ASSERTERS).length===REQUIRED.length,"map size");
  require(REQUIRED.every((id)=>ASSERTERS[id]),"map keys");
  if (doc.adr !== undefined) require(typeof doc.adr === "string", "adr type");
  require(doc.schema===PIN.schema,"schema");
  require(doc.status===PIN.status,"status");
  require(doc.adr===PIN.adr,"adr pin");
  require(doc.generator===PIN.generator,"generator pin");
  assertDocumentStructure(doc);
  assertTypeInventory(doc);
  assertAllDigestPreimages(doc);
  assertMachineFieldPins(doc);
  assertCanonicalDocumentModel(doc);
  const rest = doc.source_vector_restoration;
  require(rest && rest.adr===PIN.adr && rest.generator===PIN.generator, "restoration meta");
  require(rest.gate_py===PIN.gatePy && rest.gate_mjs===PIN.gateMjs, "restoration gates");
  require(rest.vector===PIN.vector && rest.c_test===PIN.cTest, "restoration paths");
  require(JSON.stringify(rest.tool_paths)===JSON.stringify(PIN.toolPaths), "tool_paths");
  require(rest.independent_nwd1_kat_value_hex===PIN.katValue, "rest kat value");
  require(intEq(rest.independent_nwd1_kat_header_crc32c, PIN.katCrc), "rest kat crc");
  require(rest.independent_nwd1_kat_auth_digest_hex===PIN.katAuth, "rest kat auth");
  require(rest.independent_nwd1_kat_complete_digest_hex===PIN.katComplete, "rest kat complete");
  for (const rel of PIN.toolPaths) {
    require(fs.existsSync(path.join(ROOT, rel)), `missing path ${rel}`);
  }
  for (const b of ["SPEC_ACCEPTED","implementation","HIL","RELEASE_SUPPORTED","public_API"]) require(doc.nonclaims?.includes(b),b);
  const c=doc.constants;
  require(c.nwb1_header_bytes===40&&c.nwb1_payload_min===587&&c.nwb1_payload_max===1925,"bounds");
  require(c.nwb1_total_min===627&&c.nwb1_total_max===1965,"totals");
  require(c.blackhole_detect_ms===c.keepalive_interval_ms*c.missed_response_threshold,"bh");
  require(JSON.stringify(doc.required_acceptance_ids)===JSON.stringify(REQUIRED),"req");
  const by=index(doc);
  require(by.size===REQUIRED.length,"rows");
  const ledger=new Set();
  for (const id of REQUIRED) {
    const row=by.get(id); require(row, id);
    ASSERTERS[id](row, doc);
    require(!ledger.has(id),"double");
    ledger.add(id);
  }
  require(ledger.size===REQUIRED.length,"ledger");
  return ledger.size;
}
function deep(v){return JSON.parse(JSON.stringify(v));}
function mustFail(doc,label,mut){
  const c=deep(doc); mut(c);
  try { validate(c); } catch (e) {
    if (e instanceof GateError || e instanceof TypeError || e instanceof Error) return;
    throw e;
  }
  fail(`mutation survived: ${label}`);
}
function byId(doc,id){ for (const g of GROUPS) for (const r of doc[g]) if (r.id===id) return r; fail(id); }
function selfTest(doc){
  const n=validate(doc);
  let donors=0;
  for (const victim of REQUIRED) {
    const donor = REQUIRED.find((x)=>x!==victim);
    mustFail(doc, `donor ${donor}->${victim}`, (c)=>{
      let vi, vg, drow;
      for (const g of GROUPS) {
        c[g].forEach((r,i)=>{ if(r.id===victim){vi=i;vg=g;} if(r.id===donor) drow=r; });
      }
      const body=deep(drow); body.id=victim; c[vg][vi]=body;
    });
    donors++;
  }
  mustFail(doc,"dup expected", (c)=> { byId(c,"WIFI-NWB1-DUPLICATE").expected_sequence=1; });
  mustFail(doc,"release", (c)=> { byId(c,"WIFI-RESOURCE-RELEASE-SEMANTICS").release_before_terminal_forbidden=0; });
  mustFail(doc,"corrupt omit", (c)=> { byId(c,"WIFI-NETCRED-COMMIT-UNKNOWN-RECOVERY").classifications_allowed_on_reopen=["OLD","NEW","ABSENT","PARTIAL","EXTRA","THIRD"]; });
  mustFail(doc,"absent lie", (c)=> { byId(c,"WIFI-NETCRED-FULL-ABSENT").classification="OLD"; });
  mustFail(doc,"host pin", (c)=> { byId(c,"WIFI-TLS-HOST-OPENSSL-PIN-AUTHORITY").tag="openssl-3.0.0"; });
  mustFail(doc,"esp pin", (c)=> { byId(c,"WIFI-TLS-ESP-MBEDTLS-PIN-AUTHORITY").esp_tls_public_api_forbidden=0; });
  mustFail(doc,"half-open", (c)=> { byId(c,"WIFI-LIVENESS-TCP-HALF-OPEN").result="OK_EXCLUSIVE"; });
  mustFail(doc,"ipv4 tail", (c)=> { byId(c,"WIFI-ENDPOINT-IPV4-SCOPE").address_hex=Buffer.concat([Buffer.from([192,0,2,10,1]),Buffer.alloc(11)]).toString("hex"); });
  mustFail(doc,"scope ov", (c)=> { byId(c,"WIFI-ENDPOINT-LINK-LOCAL-SCOPE-ID").scope_id_u32=2**32; });
  mustFail(doc,"status", (c)=> { c.status="SPEC_ACCEPTED"; });
  mustFail(doc,"dupkey", (c)=> { byId(c,"WIFI-NETCRED-DUPLICATE-KEY").classification="THIRD"; });
  mustFail(doc,"conflict", (c)=> { byId(c,"WIFI-NETCRED-SAME-REVISION-DIGEST-CONFLICT").digests_equal=1; });
  console.log(`wifi bearer Node gate self-test: OK ids=${n} donor_rejects=${donors} extra_mutations=12`);
}
const mode=process.argv[2];
const vectorPath=process.argv.includes("--vector")?process.argv[process.argv.indexOf("--vector")+1]:defaultVector;
if(mode!=="--check"&&mode!=="--self-test"){ console.error("usage"); process.exit(2);}
function parseStrict(src) {
  let i = 0;
  const n = src.length;
  const skipWs = () => { while (i < n && /[ \t\r\n]/.test(src[i])) i++; };
  const parseString = () => {
    if (src[i] !== '"') fail("json string");
    i++;
    let out = "";
    while (i < n) {
      const c = src[i++];
      if (c === '"') return out;
      if (c === "\\") {
        if (i >= n) fail("json string escape eof");
        const e = src[i++];
        if (e === '"' || e === "\\" || e === "/") out += e;
        else if (e === "b") out += "\b";
        else if (e === "f") out += "\f";
        else if (e === "n") out += "\n";
        else if (e === "r") out += "\r";
        else if (e === "t") out += "\t";
        else if (e === "u") {
          const h = src.slice(i, i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(h)) fail("json unicode");
          out += String.fromCharCode(parseInt(h, 16));
          i += 4;
        } else fail("json bad escape");
        continue;
      }
      out += c;
    }
    fail("json string eof");
  };
  const parseValue = () => {
    skipWs();
    if (src[i] === "{") return parseObject();
    if (src[i] === "[") return parseArray();
    if (src[i] === '"') return parseString();
    if (src.startsWith("true", i)) { i += 4; return true; }
    if (src.startsWith("false", i)) { i += 5; return false; }
    if (src.startsWith("null", i)) { i += 4; fail("json null forbidden"); }
    if (src[i] === "+") fail("json +number");
    const start = i;
    if (src[i] === "-") i++;
    if (src[i] === "0" && i+1 < n && /[0-9]/.test(src[i+1])) fail("json leading zero");
    while (i < n && /[0-9]/.test(src[i])) i++;
    if (src[i] === ".") fail("json non-integer number forbidden");
    if (src[i] === "e" || src[i] === "E") fail("json exponent forbidden for strict int");
    const lit = src.slice(start, i);
    if (!lit || lit === "-" || lit === "+") fail("json number");
    // BigInt for values outside safe Number range (no silent u64 rounding).
    try {
      const bi = BigInt(lit);
      if (bi <= BigInt(Number.MAX_SAFE_INTEGER) && bi >= BigInt(Number.MIN_SAFE_INTEGER)) {
        return Number(bi);
      }
      return bi;
    } catch {
      fail("json number");
    }
  };
  const parseArray = () => {
    i++;
    const arr = [];
    skipWs();
    if (src[i] === "]") { i++; return arr; }
    for (;;) {
      arr.push(parseValue());
      skipWs();
      if (src[i] === ",") { i++; continue; }
      if (src[i] === "]") { i++; return arr; }
      fail("json array");
    }
  };
  const parseObject = () => {
    i++;
    const obj = {};
    const seen = new Set();
    skipWs();
    if (src[i] === "}") { i++; return obj; }
    for (;;) {
      skipWs();
      const key = parseString();
      if (seen.has(key)) fail(`duplicate JSON key: ${key}`);
      seen.add(key);
      skipWs();
      if (src[i] !== ":") fail("json colon");
      i++;
      obj[key] = parseValue();
      skipWs();
      if (src[i] === ",") { i++; continue; }
      if (src[i] === "}") { i++; return obj; }
      fail("json object");
    }
  };
  const value = parseValue();
  skipWs();
  if (i !== n) fail("json trailing");
  return value;
}
try{
  const text=fs.readFileSync(vectorPath,"utf8");
  const doc=parseStrict(text);
  if(mode==="--self-test") {
    selfTest(doc);
    exhaustiveStructureSelfTest(doc);
    exhaustiveScalarValueSelfTest(doc);
    mustFail(doc,"bool fence",(c)=>{ byId(c,"WIFI-ASSOC-AUTHORITY-EPOCH-BASELINE").session_fence=true; });
    mustFail(doc,"nfl1 ver",(c)=>{
      const r=byId(c,"WIFI-NWB1-PAYLOAD-587-ACCEPT");
      const raw=Buffer.from(r.record_hex,"hex");
      raw.writeUInt16BE(0x00ff,44);
      raw.fill(0,36,40); raw.writeUInt32BE(crc32c(raw),36);
      r.record_hex=raw.toString("hex"); r.classification="OK"; r.expected="OK";
    });
    mustFail(doc,"xwd1",(c)=>{
      const r=byId(c,"WIFI-NETCRED-FULL-OLD");
      const v=Buffer.from(r.observed_rows[0].value_hex,"hex");
      Buffer.from("XWD1").copy(v,0);
      const h=v.toString("hex");
      for (const f of ["old_rows","new_rows","observed_rows"]) for (const it of r[f]) it.value_hex=h;
      r.classification="OLD"; r.expected_classification="OLD";
    });
    try {
      parseStrict(text.replace(/\n}\s*$/, ',\n  "schema": "dup"\n}\n'));
      fail("dup key accepted");
    } catch (e) {
      if (!(e instanceof GateError)) throw e;
    }
    // Semantic unicode-escape duplicate: "schema" vs "\u0073chema"
    try {
      parseStrict(text.replace(/\n}\s*$/, ',\n  "\\u0073chema": "unicode-dup"\n}\n'));
      fail("unicode semantic duplicate accepted");
    } catch (e) {
      if (!(e instanceof GateError)) throw e;
    }
    // "\n" vs "\u000a" semantic key collision
    try {
      parseStrict('{"\\n":1,"\\u000a":2}');
      fail("newline key semantic duplicate accepted");
    } catch (e) {
      if (!(e instanceof GateError)) throw e;
    }
    // u64 > 2^53 must parse as BigInt, not rounded Number
    {
      const huge = parseStrict('{"v":9007199254740993}');
      require(typeof huge.v === "bigint" && huge.v === 9007199254740993n, "bigint u64");
    }
    mustFail(doc,"old_bssid desync",(c)=>{ const r=byId(c,"WIFI-ASSOC-SAME-SSID-BSSID-CHANGE-FENCE"); r.old_bssid_hex=r.new_bssid_hex; });
    mustFail(doc,"old_profile desync",(c)=>{ byId(c,"WIFI-ASSOC-SAME-SSID-BSSID-CHANGE-FENCE").old_profile_id_hex="00".repeat(16); });
    mustFail(doc,"old_epoch desync",(c)=>{ byId(c,"WIFI-ASSOC-SAME-SSID-BSSID-CHANGE-FENCE").old_association_epoch=99; });
    mustFail(doc,"kat value drift",(c)=>{ byId(c,"WIFI-NETCRED-NO-PLAINTEXT-SECRET").nwd1_kat_value_hex="00".repeat(160); });
    mustFail(doc,"kat crc drift",(c)=>{ byId(c,"WIFI-NETCRED-NO-PLAINTEXT-SECRET").nwd1_kat_header_crc32c=0; });
    mustFail(doc,"authority_override",(c)=>{ byId(c,"WIFI-ASSOC-AUTHORITY-EPOCH-BASELINE").authority_override=1; });
    mustFail(doc,"meta adr drift",(c)=>{ c.adr="docs/adr/does-not-exist.md"; });
    mustFail(doc,"tool path drift",(c)=>{ c.source_vector_restoration.tool_paths=[...PIN.toolPaths.slice(0,-1),"tools/missing_wifi_gate.py"]; });
    mustFail(doc,"rest kat drift",(c)=>{ c.source_vector_restoration.independent_nwd1_kat_value_hex="ff".repeat(160); });
    console.log("wifi bearer Node gate self-test extra: nfl1/xwd1/bool/dup-key/unicode/bigint/assoc/kat/meta OK");
  }
  else console.log(`wifi bearer Node gate: PASS executed=${validate(doc)}`);
}catch(e){ console.error(`wifi bearer Node gate: FAIL: ${e.message}`); process.exit(1);}
