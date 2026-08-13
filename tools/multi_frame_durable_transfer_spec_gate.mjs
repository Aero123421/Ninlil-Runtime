#!/usr/bin/env node
// Independent Node gate for the ADR-0021 application-handoff review candidate.
// Full fixture byte recompute, strict JSON, exhaustive same-family donors.
// Does not import generator/Python gate/production code.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const VECTOR = path.join(path.dirname(here), "spec", "vectors", "multi-frame-durable-transfer-spec-v1.json");

const REQUIRED_VECTOR_IDS = [
  "MF-CONSTANTS-PINNED",
  "MF-VERSION-CATALOG-INHERITANCE",
  "MF-CARRIER-MAPPING-MATRIX",
  "MF-PUBLICATION-OWNER-MATRIX",
  "MF-ROLE-BOUNDARIES",
  "MF-PRIVATE-API-SURFACE",
  "MF-FSM-STORAGE-SIDECAR-PROFILE",
  "MF-POS-OPEN-APPLICATION-BINDING-LAYOUT-KAT",
  "MF-NEG-OPEN-APPLICATION-BINDING-FIELD-MUTATION",
  "MF-NEG-CARRIER-OPEN-BINDING-MISMATCH-PREFULL",
  "MF-NEG-ADMISSION-REV1-REV2-MIXED",
  "MF-POS-APPLICATION-EVIDENCE-DIGEST-KAT",
  "MF-BUDGET-ARITHMETIC-REFERENCE",
  "MF-BUDGET-EMPTY-TRANSFER",
  "MF-BUDGET-OBSOLETE-80-REJECTED",
  "MF-BUDGET-RESTORATION-HASH",
  "MF-BUDGET-NRC1-LOGICAL-BYTES",
  "MF-BUDGET-FULL-MAX-WITH-REQID",
  "MF-POS-EMPTY-PAYLOAD",
  "MF-POS-ONE-BYTE",
  "MF-POS-EXACT-MULTIPLE-FINAL",
  "MF-POS-ONE-BYTE-FINAL",
  "MF-POS-MAX-PAYLOAD-37-CHUNKS",
  "MF-POS-TWO-PAGE-MANIFEST",
  "MF-POS-COMPLETION-RECEIPT-REPLAY",
  "MF-POS-REQID-CACHE-SAME-ID-STABLE",
  "MF-POS-REQID-NEW-ID-CURRENT-COMPLETE",
  "MF-POS-REQID-NRC1-LAYOUT-KAT",
  "MF-POS-REQID-MAX-TRANSFER-OCCUPIED-41",
  "MF-POS-REQID-RETRY-BUDGET-SM",
  "MF-POS-REQID-REACHABLE-MAX-COUNT",
  "MF-POS-REQID-SESSION-GEN-RESUME-RECLAIM",
  "MF-NEG-REQID-TWO-GEN-NO-RECLAIM-CAPACITY",
  "MF-POS-REQID-MAX-RETRY-TRACE",
  "MF-POS-REQID-TERMINAL-LATE-DUP-MATRIX",
  "MF-POS-NM30-SCHEMA2-LAYOUT-KAT",
  "MF-NEG-NM30-SCHEMA1-COLD-REPLAY-DENY",
  "MF-TX-HOST-TERMINAL-COLD-REBIND-HIT",
  "MF-NEG-HOST-TERMINAL-BIND-MATRIX",
  "MF-POS-HOST-FOUR-ACTIVE-TERMINAL-HIT",
  "MF-NEG-HOST-FOUR-ACTIVE-FRESH-OPEN-BUSY",
  "MF-NEG-HOST-CONTROL-OUTBOX-BACKPRESSURE",
  "MF-NEG-PREADMISSION-POLICY-STATELESS",
  "MF-NEG-PREADMISSION-DEADLINE-STATELESS",
  "MF-NEG-ACTIVE-SEMANTIC-REJECT-CACHED",
  "MF-FSM-TERMINAL-ACTIVE-CODES-UNREACHABLE",
  "MF-TRACE-S1-S6-HAPPY-PATH",
  "MF-NEG-STALE-GENERATION",
  "MF-NEG-STALE-VERSION-SELECTED-2",
  "MF-NEG-MIXED-VERSION-PEER",
  "MF-NEG-RF-MAPPING-UNAVAILABLE",
  "MF-NEG-WIFI-MAPPING-UNAVAILABLE",
  "MF-NEG-NFL1-CONTROL-FORBIDDEN",
  "MF-NEG-DUPLICATE-CHUNK-CONFLICT",
  "MF-NEG-REORDER-GAP",
  "MF-NEG-DIGEST-CORRUPTION-REPAIRED",
  "MF-NEG-WHOLE-DIGEST-MISMATCH",
  "MF-NEG-EXPIRY-BOUNDARY-EQ",
  "MF-NEG-EXPIRY-BOUNDARY-BEFORE",
  "MF-NEG-ABORT-AFTER-CONTENT-VERIFIED",
  "MF-NEG-ABORT-RACE-FINALIZE-FIRST",
  "MF-NEG-ABORT-RACE-ABORT-FIRST",
  "MF-NEG-PARTIAL-APPLY-FORBIDDEN",
  "MF-NEG-FALSE-CUSTODY-BITMAP",
  "MF-NEG-RESOURCE-EXHAUSTION-KEYS",
  "MF-NEG-RESOURCE-EXHAUSTION-BYTES",
  "MF-NEG-FAIRNESS-TWO-OUTSTANDING",
  "MF-NEG-MAX-CHUNKS-PLUS-ONE",
  "MF-NEG-DEFAULT-OFF-POLICY",
  "MF-NEG-STORAGE-SIDECAR-COLLISION",
  "MF-NEG-REQID-BODY-CONFLICT",
  "MF-NEG-REQID-CACHE-FULL",
  "MF-NEG-REQID-DIGEST-OPEN-PREIMAGE",
  "MF-NEG-REQID-POST-RETENTION-EXPIRED",
  "MF-NEG-EPOCH-CHANGE-MID-TRANSFER",
  "MF-CU-STORAGE-BINDING-NEW",
  "MF-CU-STORAGE-BINDING-PARTIAL",
  "MF-CU-STORAGE-BINDING-EXTRA",
  "MF-CU-STORAGE-BINDING-THIRD",
  "MF-CU-STORAGE-BINDING-ABSENT",
  "MF-CU-RECEIVER-CHUNK-OLD",
  "MF-CU-RECEIVER-CHUNK-NEW",
  "MF-CU-RECEIVER-CHUNK-PARTIAL",
  "MF-CU-RECEIVER-CHUNK-EXTRA",
  "MF-CU-RECEIVER-CHUNK-THIRD",
  "MF-CU-RECEIVER-CHUNK-ABSENT",
  "MF-CU-TERMINAL-GROUP-OLD",
  "MF-CU-TERMINAL-GROUP-NEW",
  "MF-CU-TERMINAL-GROUP-PARTIAL",
  "MF-CU-TERMINAL-GROUP-EXTRA",
  "MF-CU-TERMINAL-GROUP-THIRD",
  "MF-CU-TERMINAL-GROUP-ABSENT",
  "MF-CU-TERMINAL-GROUP-BOTH",
  "MF-CU-NRC1-ABSENT-MID-TRANSFER",
  "MF-CU-NRC1-OLD",
  "MF-CU-NRC1-NEW",
  "MF-CU-NRC1-PARTIAL",
  "MF-CU-NRC1-EXTRA",
  "MF-CU-NRC1-THIRD",
  "MF-CU-NRC1-ABSENT-POST-TERMINAL",
  "MF-TX-CROSS-NAMESPACE-ADMISSION-MATRIX",
  "MF-TX-EXPIRY-MANDATORY-TOMBSTONE",
  "MF-POS-EXPIRY-SLOT-REUSE",
  "MF-TX-POWER-CUT-AFTER-CHUNK-FULL",
  "MF-TX-POWER-CUT-AFTER-CONTENT-VERIFIED",
  "MF-TX-POWER-CUT-DURING-TERMINAL",
  "MF-TX-RESUME-AFTER-RESTART",
  "MF-TX-CLEANUP-RETENTION-GC",
  "MF-TX-ROLLBACK-POLICY-OFF",
  "MF-TX-TERMINAL-CRASH-ACTIVE-ONLY",
  "MF-TX-TERMINAL-CRASH-NM30-ONLY",
  "MF-TX-EPOCH-CHANGE-TERMINAL",
  "MF-TX-REQID-CACHE-CRASH-RESTART",
  "MF-TX-REQID-TERMINAL-RESTART-LATE-DUP",
  "MF-INV-REQUIRED-IDS-INTEGRITY",
  "MF-GATE-SELF-TEST-PIN"
];

// Authority seal SHA covers hard-pinned metadata + source digests + per-ID index.
const AUTHORITY_MAP_SHA256_HEX = "e691f98d786708a981234f4c3f77c50d8cc4a6f968585f39204acb6a3f309c8f";

// Independently hard-pinned machine metadata (gates do not learn these from vector).
const PINNED_SCHEMA = "ninlil.multi-frame-durable-transfer.spec.v1";
const PINNED_STATUS = "SPEC_ACCEPTED";
const PINNED_ADR = "ADR-0021";
const PINNED_ADR_PATH = "docs/adr/0021-multi-frame-durable-custody.md";
const PINNED_TITLE = "Multi-frame Durable Transfer / full fragmentation design authority";
const PINNED_NONCLAIMS = [
  "implementation",
  "HIL",
  "RELEASE_SUPPORTED",
  "public_abi",
  "compact_rf_mapping",
  "wifi_mapping",
  "docs_25_26_refreeze_done",
  "application_handoff_implementation",
  "nts3_schema_1_2_implementation",
];
const PINNED_SOURCES = [
  PINNED_ADR_PATH,
  "tools/multi_frame_durable_transfer_spec_vector_gen.py",
];
// Source content digests: ADR + generator. Gates pin both. Generator pins only ADR
// (avoids self-circular self-SHA inside the generator file).
const PINNED_SOURCE_SHA256_HEX = {
  [PINNED_ADR_PATH]: "15bd999eb3240672f65089aa2ba12ba481c552688fda262aa221ebf4f2ed4ac9",
  "tools/multi_frame_durable_transfer_spec_vector_gen.py":
    "5517ef34707ff18b9623c69dd6c88b9af495940274b326208991769c7b69c8d3",
};

const AUTHORITY = {"MF-BUDGET-ARITHMETIC-REFERENCE":{"authority_fingerprint_hex":"dda356b0f772334c5448dc39b190ed02b2a2334345011c0cfa46ce67c46d0a4d","expected":{"receiver_fulls":77,"required_receiver_reference":154,"required_sender_reference":134,"sender_fulls":67,"status":"OK"},"family":"budget"},"MF-BUDGET-EMPTY-TRANSFER":{"authority_fingerprint_hex":"713b328f3586e4bf4de86e944f51c2ad874cff360b9dba6957624c7e1c2bf178","expected":{"receiver_fulls":5,"sender_fulls":5,"status":"OK"},"family":"budget"},"MF-BUDGET-FULL-MAX-WITH-REQID":{"authority_fingerprint_hex":"df1f6c07d3bc75d8c28ccc3af927607c6aa4630234bbae0ee313324f91ce26d9","expected":{"branch":"full_max_with_reqid","nrc1_retained_until_gc":true,"obsolete_80_infeasible":true,"receiver_base":44,"receiver_fulls":77,"receiver_reqid_cache":16,"receiver_resume":8,"required_receiver_reference":154,"required_sender_reference":134,"sender_base":42,"sender_fulls":67,"sender_reqid_cache":8,"sender_resume":8,"status":"OK","terminal_erases_nrc1":false},"family":"budget"},"MF-BUDGET-NRC1-LOGICAL-BYTES":{"authority_fingerprint_hex":"35d49d2f1511682252dfb43f4e6fcaef327902ccd0ff7b3d3af5b4e3198535b4","expected":{"admission_reserved_entries":3,"admission_reserved_logical_bytes":50519,"branch":"nrc1_budget","capacity_spare":7,"esp_active_transfers_max":1,"fixed16_rejected":true,"happy_path_max_ids":41,"host_active_transfers_max":4,"host_begin_final_union_logical_bytes_hard_max":434779,"host_committed_logical_bytes_hard_max":384476,"host_four_active_committed_logical_bytes":201212,"logical_bytes":15056,"n_abort":64,"n_complete":65,"naive_union_not_single_path":57,"reachable_max_ids":65,"slot_bytes":208,"slot_count":72,"slot_count_ge_reachable":true,"status":"OK","timeout_retry_max":8,"value_bytes":15020},"family":"budget"},"MF-BUDGET-OBSOLETE-80-REJECTED":{"authority_fingerprint_hex":"ac0839abf90dc46ed571bf754a1c76c87eac42b178d898c0e1daff5b79361423","expected":{"obsolete_cap":80,"reason":"OBSOLETE_80_INFEASIBLE","required_receiver_fulls":154,"status":"REJECT"},"family":"budget"},"MF-BUDGET-RESTORATION-HASH":{"authority_fingerprint_hex":"1f307334ede3b7000614aebdf9e79b399d1f08363b8c8ff204ae8ea71c97848e","expected":{"restoration_sha256_hex":"7833c693c278cef6d59fa742a3b94e678378b7ca32d1ee0184a0fef7e9a6f2f5","status":"OK"},"family":"budget"},"MF-CARRIER-MAPPING-MATRIX":{"authority_fingerprint_hex":"2ad800c69a4ac3eca95b4bfa82d467afdd48825ad3686890d90fe579d5bb7220","expected":{"fabric":"MAPPING_CANDIDATE","ncl1":"MAPPING_CANDIDATE","rf":"MAPPING_UNAVAILABLE","status":"OK","wifi":"MAPPING_UNAVAILABLE"},"family":"catalog"},"MF-CONSTANTS-PINNED":{"authority_fingerprint_hex":"6fa255cd38ec25cd53bf621f0a3dc58f109d11beff61dad4eaab115d4e7b55b0","expected":{"branch":"constants","status":"OK"},"family":"catalog"},"MF-CU-NRC1-ABSENT-MID-TRANSFER":{"authority_fingerprint_hex":"20429e037a8c9e8435388b350a4bbde01f72686cc7a0010c9ecda8a8a0a0c194","expected":{"action":"CORRUPT_fence","classification":"ABSENT","reason":"nrc1_missing_after_prior_success","send_or_accept":0,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-NRC1-ABSENT-POST-TERMINAL":{"authority_fingerprint_hex":"477b60c7a009b8e2782d7defe8c92dbb2a9b78e62089fec3c38f49ea7904c502","expected":{"action":"CORRUPT_fence","classification":"ABSENT","nm30_alone_cannot_synthesize_response":true,"nrc1_retained_post_terminal":true,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-NRC1-EXTRA":{"authority_fingerprint_hex":"300f28ad85cf011444df64bbc18d6dfa1807eb0265804c193df5b9ec481c29e6","expected":{"action":"CORRUPT_fence","classification":"EXTRA","nm30_alone_cannot_synthesize_response":true,"nrc1_retained_post_terminal":true,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-NRC1-NEW":{"authority_fingerprint_hex":"fa5797f1a2f8a66a4fa8945e851e7f483dd8ba160dc69269e23a0ae5285fcec2","expected":{"action":"adopt_new_state_no_target_replay_before_attestation","attestation_magic_only_accepted":false,"classification":"NEW","host_full_capable_replay":"OK","nm30_alone_cannot_synthesize_response":true,"nrc1_retained_post_terminal":true,"status":"COMMIT_UNKNOWN_CLASSIFIED","target_active_plus_nrc1_replay":"COMMIT_UNKNOWN","target_cold_restart_retry":"COMMIT_UNKNOWN","target_nrc1_only_replay":"COMMIT_UNKNOWN","target_same_id_retry":"COMMIT_UNKNOWN","wire_success":0},"family":"commit_unknown"},"MF-CU-NRC1-OLD":{"authority_fingerprint_hex":"6c72792fdb8e28eb5813799d1785bb0eb365a0de3c0165277bb519e711f081ec","expected":{"action":"replay_bit_exact_from_nrc1","classification":"OLD","nm30_alone_cannot_synthesize_response":true,"nrc1_retained_post_terminal":true,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-NRC1-PARTIAL":{"authority_fingerprint_hex":"aaf6b588b99193ca726bd11795a8606ff3cb3c462ec769d1e8c057795a944725","expected":{"action":"CORRUPT_fence","classification":"PARTIAL","nm30_alone_cannot_synthesize_response":true,"nrc1_retained_post_terminal":true,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-NRC1-THIRD":{"authority_fingerprint_hex":"22c98535dfcb9ed5a75e730d7132ae17d24a8c9a4cc042522513e4ca4e54bdd0","expected":{"action":"CORRUPT_fence","classification":"THIRD","nm30_alone_cannot_synthesize_response":true,"nrc1_retained_post_terminal":true,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-RECEIVER-CHUNK-ABSENT":{"authority_fingerprint_hex":"1311b2d6b873eda2983dfcbe52ae1cef0e3b67dd302a0e7606a7aebd9607cee9","expected":{"classification":"ABSENT","send_or_accept":0,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-RECEIVER-CHUNK-EXTRA":{"authority_fingerprint_hex":"142ee4117eae17bc9f414ae44e0bc4028a5ea4a69c98e3881ed3110c9ac22a8a","expected":{"classification":"EXTRA","send_or_accept":0,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-RECEIVER-CHUNK-NEW":{"authority_fingerprint_hex":"314d3b47f23e89468bdac5174af4109dd8b25007ac20dedac3b1effa9e7823dd","expected":{"classification":"NEW","send_or_accept":0,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-RECEIVER-CHUNK-OLD":{"authority_fingerprint_hex":"4487e9662149ae1c8cc4be233b4f313782e8371c982f04e2a48f658d8609e68e","expected":{"classification":"OLD","send_or_accept":0,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-RECEIVER-CHUNK-PARTIAL":{"authority_fingerprint_hex":"8c0e670ca8b071290221d60b7c1bf8e7a4ccf02dd3e1bc0f8292c080ab7c24a0","expected":{"classification":"PARTIAL","send_or_accept":0,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-RECEIVER-CHUNK-THIRD":{"authority_fingerprint_hex":"130f0a5565b23f3b19af40124e8111dcae9f201ca4b1a6d1a8b298acd7e4ef75","expected":{"classification":"THIRD","send_or_accept":0,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-STORAGE-BINDING-ABSENT":{"authority_fingerprint_hex":"64ca06b3a4c554c78a3449ec689ff66f7b53b009c3c8f52823378eb942242e15","expected":{"classification":"ABSENT","foundation_mutation":0,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-STORAGE-BINDING-EXTRA":{"authority_fingerprint_hex":"87d178076f53727734d984ffe360b8427699aeb4b24b78b029703125d439322a","expected":{"classification":"EXTRA","foundation_mutation":0,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-STORAGE-BINDING-NEW":{"authority_fingerprint_hex":"4c4fadb648b2f100b88057648d8d88d1f8ae51663291937750b0dd6e60fba222","expected":{"classification":"NEW","foundation_mutation":0,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-STORAGE-BINDING-PARTIAL":{"authority_fingerprint_hex":"665e3b24693241fd1a789e8b45c0a6899639624159f7c32640a61cdf2c0ebc04","expected":{"classification":"PARTIAL","foundation_mutation":0,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-STORAGE-BINDING-THIRD":{"authority_fingerprint_hex":"9f26a30990f43fc4792aedae5b99af2c84c674bf27647b8d999ccb101eda21fb","expected":{"classification":"THIRD","foundation_mutation":0,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-TERMINAL-GROUP-ABSENT":{"authority_fingerprint_hex":"1114f60ab947e11f580fc6fbe812bb1da6d5782968eb71342d44af19fa003fe8","expected":{"classification":"ABSENT","send_or_accept":0,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-TERMINAL-GROUP-BOTH":{"authority_fingerprint_hex":"ae7ba2c5f196babb50cfdd708e5dbbb9343abbdc6c2cf344acfae3da21047679","expected":{"classification":"BOTH","send_or_accept":0,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-TERMINAL-GROUP-EXTRA":{"authority_fingerprint_hex":"44b4e17807eed9a365ad88159681530865f8a032cba49c91d938149b606eb44b","expected":{"classification":"EXTRA","send_or_accept":0,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-TERMINAL-GROUP-NEW":{"authority_fingerprint_hex":"04dd0912e7c5c4d48afecefdc7ea36c126b93ee5c5902f7673e2dec8fa8a3d86","expected":{"classification":"NEW","send_or_accept":0,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-TERMINAL-GROUP-OLD":{"authority_fingerprint_hex":"888526b853b28a5a0f11c3a2f9325d8a1055ce48edf9c2cdc8b9ff18ec8f0c2e","expected":{"classification":"OLD","send_or_accept":0,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-TERMINAL-GROUP-PARTIAL":{"authority_fingerprint_hex":"4bbd8af73a0c11f9f11e79a85520b8006b46ea531dfb6443972960473e71955a","expected":{"classification":"PARTIAL","send_or_accept":0,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-CU-TERMINAL-GROUP-THIRD":{"authority_fingerprint_hex":"fa40ccb60c830a153040b70f741fc85092732beb3b3cccba105ec498dbc45141","expected":{"classification":"THIRD","send_or_accept":0,"status":"COMMIT_UNKNOWN_CLASSIFIED","wire_success":0},"family":"commit_unknown"},"MF-FSM-STORAGE-SIDECAR-PROFILE":{"authority_fingerprint_hex":"d57e4992eb76beff18980d3a5d557bc67522dd927c4118062a4ba8842a604390","expected":{"active_schema1_replay_eligible":false,"binding_value_max":307,"binding_value_min":53,"branch":"derived_sidecar_binding_profile","collision_fail_closed":true,"cross_namespace_atomic_commit_claimed":false,"derived_namespace_length":36,"destroy_close_order":["BEARER","MFDT_SIDECAR","FOUNDATION_STORAGE"],"foundation_scanner_value_max":4096,"mfdt_active_record_schema":2,"mfdt_active_value_max":35211,"nrc1_value_bytes":15020,"same_handle_forbidden":true,"status":"OK"},"family":"catalog"},"MF-FSM-TERMINAL-ACTIVE-CODES-UNREACHABLE":{"authority_fingerprint_hex":"8f5b4f442959f16dcc6d5b4e5590e4ad19cb36d7c97fbfe01f6f3ce73e5de6be","expected":{"both_active_and_nm30":"CORRUPT","branch":"fsm_terminal_active_removed","durable_active_forbidden_codes":[7,9,39],"durable_terminal_kind":"NM30_ONLY","status":"OK"},"family":"catalog"},"MF-GATE-SELF-TEST-PIN":{"authority_fingerprint_hex":"9b7783fe3cb78bc063abee8f85dbe5da860a59e5dd8df1159ca1ec861826f7eb","expected":{"gate_must_reject_duplicate_id":true,"gate_must_reject_extra_id":true,"gate_must_reject_missing_id":true,"gate_must_reject_substituted_id":true,"mutations_repair_digest":true,"status":"OK"},"family":"catalog"},"MF-INV-REQUIRED-IDS-INTEGRITY":{"authority_fingerprint_hex":"1f4dc5749d250fce20944e02d5ace9dc72e3c309b86c5ebb638dc84c35748dd9","expected":{"duplicate_count":0,"required_count":116,"status":"OK"},"family":"catalog"},"MF-NEG-ABORT-AFTER-CONTENT-VERIFIED":{"authority_fingerprint_hex":"f6f977e108f3488f30c2137bdc156060621a3528ef8a905f78a0015542cc8fac","expected":{"reason":"receiver_already_content_verified","reject_code":10,"stage":6,"status":"REJECT"},"family":"negative"},"MF-NEG-ABORT-RACE-ABORT-FIRST":{"authority_fingerprint_hex":"9e9aae774b718df70cedfcfa892eed810565748f5b631192999c0ecf372c16b3","expected":{"abort_ack_hex":"9e7c9d4b8f7fd07d4849d5a88ca349e200000001ac79ca0089d32eb4a4e02ce9f097f8a055fc6bc89fe70c4b91e658c2ca8491f70000000100020000d3cf20daca6b1410feef9e22238584deedc18d3ae8a149d908710782bb2d2c06","branch":"aborted_terminal","status":"OK","tombstone_digest_hex":"d3cf20daca6b1410feef9e22238584deedc18d3ae8a149d908710782bb2d2c06","winner":"ABORT_FULL"},"family":"negative"},"MF-NEG-ABORT-RACE-FINALIZE-FIRST":{"authority_fingerprint_hex":"2ecd7cbbd6bc1d2e8f1fb4def083cb7484a1a298423365d6e9d59f3f6cbe0165","expected":{"reject_code":10,"status":"REJECT","winner":"FINALIZE_FULL"},"family":"negative"},"MF-NEG-ACTIVE-SEMANTIC-REJECT-CACHED":{"authority_fingerprint_hex":"42186184d24e10096da8ee22064d456aa035f867655968f33e9b86aa1e51546c","expected":{"active_group_present":true,"branch":"active_semantic_reject_cached","cacheable":true,"durable_cache_mutation":1,"nrc1_full_count":1,"nrc1_miss":true,"owned_active_slot_outbox":true,"reject_code":8,"response_body_length":60,"semantic_response_type":58,"status":"OK","transfer_state_mutation":0,"transport_status":"OK","uses_control_outbox":false,"wire_after_full_only":true},"family":"negative"},"MF-NEG-ADMISSION-REV1-REV2-MIXED":{"authority_fingerprint_hex":"f9d35e0d4fd4bfbccf29b6d7e6fe061e1622133bfb7b29b3b6f6e73a749c7f7b","expected":{"durable_state_mutation":0,"full_count":0,"migration_attempted":false,"reason":"admission_profile_or_active_schema_revision_mismatch","reject_code":4,"status":"REJECT"},"family":"negative"},"MF-NEG-CARRIER-OPEN-BINDING-MISMATCH-PREFULL":{"authority_fingerprint_hex":"5fceb1124a4e5e5993ed5e29fb531a57b6102582de2930962828f84201b66c04","expected":{"callback_count":0,"durable_rows_created":0,"durable_state_mutation":0,"full_count":0,"reason":"pre_full_application_handoff_boundary_reject","receipt_count":0,"reject_code":9,"stage":1,"status":"REJECT"},"family":"negative"},"MF-NEG-DEFAULT-OFF-POLICY":{"authority_fingerprint_hex":"38bde5d5966456455d011e17ab28a00092a3ae94c4b87027a7aa98fd72e968b1","expected":{"reason":"mf_policy_default_off","reject_code":4,"status":"REJECT"},"family":"negative"},"MF-NEG-DIGEST-CORRUPTION-REPAIRED":{"authority_fingerprint_hex":"2b94f3f1279d87bab8d755079cee3ea198ce6e96c7706677566f0db361bb32f3","expected":{"manifest_digest_hex":"c421858f87a9029f499c6719fc83a64ab585e01a78b12c2efb2102b6fa07c2bd","reason":"whole_content_digest_mismatch_vs_bytes","reject_code":2,"status":"REJECT"},"family":"negative"},"MF-NEG-DUPLICATE-CHUNK-CONFLICT":{"authority_fingerprint_hex":"a64b7fdab1874856b37d2c7443b2590d3ec5ea83a278f344ffb834f1ebc435e8","expected":{"reason":"same_index_different_bytes","reject_code":2,"stage":3,"status":"TERMINAL_CONFLICT"},"family":"negative"},"MF-NEG-EPOCH-CHANGE-MID-TRANSFER":{"authority_fingerprint_hex":"3e79329b79829267822c339c15d357373b4243b48f8db5e91a52ae5aca0c8872","expected":{"prepare_forbidden":true,"publication_after":"NONE","reason":"local_clock_epoch_changed","reject_code":8,"status":"REJECT"},"family":"negative"},"MF-NEG-EXPIRY-BOUNDARY-BEFORE":{"authority_fingerprint_hex":"979f37cdc3fe049ac98d733a396408d5598add2c9ab1a35763a34bec0b89476d","expected":{"branch":"reservation_valid","status":"OK"},"family":"negative"},"MF-NEG-EXPIRY-BOUNDARY-EQ":{"authority_fingerprint_hex":"afa8581f9705a080b511d1fcd3fa747b8f9fdce658c02510e81b61a25a406ad4","expected":{"deadline_matrix_all_exact":true,"different_epoch_direct_compare_forbidden":true,"overflow_reject_mutation_zero":true,"reason":"now_ge_not_after","reject_code":7,"status":"REJECT"},"family":"negative"},"MF-NEG-FAIRNESS-TWO-OUTSTANDING":{"authority_fingerprint_hex":"ae3414b0686ce6a0b1238969a2f9fae57a0b9c39a125cc742d30934e396f0bde","expected":{"blocked_peer_slots_skipped":[0,2],"branch":"host_deterministic_round_robin_and_peer_backpressure","different_peer_slot_selected":1,"fair_selection_bound":4,"max_outstanding":1,"reason":"more_than_one_unpaid_chunk_offer_per_peer_forbidden","restart_next_slot":0,"selection_trace":[0,1,2,3,0,1,2,3],"status":"OK"},"family":"negative"},"MF-NEG-FALSE-CUSTODY-BITMAP":{"authority_fingerprint_hex":"97672c50b53987202ae156e01cea199c73032fbf3f2e8e5c80439b36f3633dc6","expected":{"reason":"resume_bitmap_is_hint_not_custody_completion","sender_may_release_payload":false,"status":"REJECT"},"family":"negative"},"MF-NEG-HOST-CONTROL-OUTBOX-BACKPRESSURE":{"authority_fingerprint_hex":"b36956f1f900c98e8adea8a26dcbe3ccae068affa4892d7556c6acdb2f469ba2","expected":{"active_fairness_blocked":false,"branch":"control_outbox_no_overwrite","catalog_mutation":0,"control_outbox_capacity_frames":1,"first_frame_retained_bit_exact":true,"full_count":0,"scheduler_cursor_unchanged":true,"second_frame_enqueued":false,"second_wire_response_count":0,"state_mutation":0,"status":"ERR_BUSY","store_mutation":0},"family":"negative"},"MF-NEG-HOST-FOUR-ACTIVE-FRESH-OPEN-BUSY":{"authority_fingerprint_hex":"80996ef80c43721990ccd27ea5707189e22365ece30b4ab42bdd3833242371da","expected":{"active_after":4,"active_before":4,"branch":"four_active_fresh_open_capacity_busy","cacheable":false,"catalog_unchanged":true,"control_route":255,"durable_state_mutation":0,"full_count":0,"owned_control_outbox":true,"reject_code_sidecar":5,"response_body_length":60,"scheduler_cursor_unchanged":true,"semantic_response_type":59,"stateless":true,"status":"OK","store_unchanged":true,"transport_status":"OK"},"family":"negative"},"MF-NEG-HOST-TERMINAL-BIND-MATRIX":{"authority_fingerprint_hex":"9912ea0cea4032a26b35826bc12e18cf1b6e6585a7e38d593a1aa74c66053879","expected":{"branch":"host_terminal_bind_matrix","cookie_swap":"ERR_STATE","exact_initial_rebind":"OK","generation_mismatch":"ERR_STATE","mismatch_outbox_mutation":0,"mismatch_state_mutation":0,"mismatch_store_mutation":0,"mismatch_wire_response_count":0,"peer_mismatch":"ERR_STATE","role_mismatch":"ERR_STATE","same_cookie_after_bind":"OK","status":"REJECT","zero_cookie":"ERR_STATE"},"family":"negative"},"MF-NEG-MAX-CHUNKS-PLUS-ONE":{"authority_fingerprint_hex":"8e1672136742e2e5edb3688c244a07c51f530cf68ab9b487e48c886fe05a3fa5","expected":{"reason":"chunk_count_exceeds_37","reject_code":1,"status":"REJECT"},"family":"negative"},"MF-NEG-MIXED-VERSION-PEER":{"authority_fingerprint_hex":"342ff23001923c796eff1e227ba59350bf03ff1a5a0a1d694ad5baf7012c9a96","expected":{"reason":"stale_or_unbound_mfn1_session","reject_code":4,"status":"REJECT"},"family":"negative"},"MF-NEG-NFL1-CONTROL-FORBIDDEN":{"authority_fingerprint_hex":"90bc8ed6679e7d920f3f33edc22f28f63d3dcf887af5b8a9530f1074fac33d8a","expected":{"reason":"ordinary_public_nfl1_must_not_carry_raw_mf_control","reject_code":4,"status":"REJECT"},"family":"negative"},"MF-NEG-NM30-SCHEMA1-COLD-REPLAY-DENY":{"authority_fingerprint_hex":"6bdd4432da0e505d44a128d71e5c23e74957e9e1b1a27dc865f53137a0e0c192","expected":{"accounting_allowed":true,"branch":"legacy_nm30_schema1_replay_ineligible","canonical_legacy_validation":true,"peer_role_cookie_inference_forbidden":true,"rebind_allowed":false,"replay_eligible":false,"retention_gc_allowed":true,"schema":1,"status":"REJECT","transport_ok":false,"value_length":164,"wire_response_count":0},"family":"negative"},"MF-NEG-OPEN-APPLICATION-BINDING-FIELD-MUTATION":{"authority_fingerprint_hex":"23e01a3a025e74d5cec6d03e8acf8c4d66169d639a790b0fdc4c021775705581","expected":{"durable_state_mutation":0,"mutation_count":25,"reason":"every_binding_field_is_manifest_bound","reject_code":2,"stage":1,"status":"REJECT"},"family":"negative"},"MF-NEG-PARTIAL-APPLY-FORBIDDEN":{"authority_fingerprint_hex":"7b75fe1e55cd0f2107d0034b89f89b08b68ebacc6942a6071a6b09e30cb24276","expected":{"publication_state":0,"reason":"publication_before_content_verified","status":"REJECT"},"family":"negative"},"MF-NEG-PREADMISSION-DEADLINE-STATELESS":{"authority_fingerprint_hex":"7db67791e29cad9d5c6942972b4c5fcb1096cbda9f844f49106ad1639efe4045","expected":{"bind52_safe":true,"branch":"preadmission_deadline_stateless","cacheable":false,"control_route":255,"durable_rows_created":0,"durable_state_mutation":0,"full_count":0,"late_duplicate_may_be_reevaluated":true,"owned_control_outbox":true,"reject_code":7,"response_body_length":60,"retry_requires_fresh_nonzero_request_id":true,"semantic_response_type":58,"status":"OK","transport_status":"OK"},"family":"negative"},"MF-NEG-PREADMISSION-POLICY-STATELESS":{"authority_fingerprint_hex":"3aae613ffad39336e668737986f4f321a5d8f15e65c953d85579cc64f91c74ef","expected":{"bind52_safe":true,"branch":"preadmission_policy_stateless","cacheable":false,"control_route":255,"durable_rows_created":0,"durable_state_mutation":0,"full_count":0,"late_duplicate_may_be_reevaluated":true,"owned_control_outbox":true,"reject_code":4,"response_body_length":60,"retry_requires_fresh_nonzero_request_id":true,"semantic_response_type":58,"status":"OK","transport_status":"OK"},"family":"negative"},"MF-NEG-REORDER-GAP":{"authority_fingerprint_hex":"8b0b9d7281da2c75369ae70fafbe51cb43d22f93fafad452310068fb0dfcb0de","expected":{"bitmap_after":2,"gap_does_not_imply_complete":true,"missing_indices":[0],"status":"OK_REORDER_ACCEPT"},"family":"negative"},"MF-NEG-REQID-BODY-CONFLICT":{"authority_fingerprint_hex":"074725ddb8e99edb0bec9bc5dba2935aa54c7c2d200676abd0bf2cee204ccb55","expected":{"reason":"request_id_body_digest_conflict","reject_code":3,"state_mutation":0,"status":"REJECT"},"family":"negative"},"MF-NEG-REQID-CACHE-FULL":{"authority_fingerprint_hex":"a528d9efcc12aa6679653777b120ac0db207c62049bfa4f45e4a53f85f24d702","expected":{"no_silent_eviction":true,"reason":"request_id_cache_full","reject_code":5,"slot_count":72,"state_mutation":0,"status":"BUSY_OR_REJECT"},"family":"negative"},"MF-NEG-REQID-DIGEST-OPEN-PREIMAGE":{"authority_fingerprint_hex":"bc751a28a45e689878bd8f8662739353d22d192b5ccde8f9f146007ced56b158","expected":{"bind52_strip_digest_differs":true,"branch":"open_digest_preimage","includes_bind52_strip":false,"message_type":54,"preimage":"type_u8||len_u16be||full_open_body","status":"OK"},"family":"negative"},"MF-NEG-REQID-POST-RETENTION-EXPIRED":{"authority_fingerprint_hex":"6403986bee1d5aa9d78bf0bc32261b9ce5c5518d7d43536e862c46e46db615f9","expected":{"bit_exact_replay_forbidden":true,"nm30_present":false,"nrc1_present":false,"reason":"transfer_expired","reject_code":7,"state_mutation":0,"status":"REJECT"},"family":"negative"},"MF-NEG-REQID-TWO-GEN-NO-RECLAIM-CAPACITY":{"authority_fingerprint_hex":"3f492941a0beee3bb2808a324ab1ad4271c6bb3f59d6cb08058d7ca473273452","expected":{"branch":"two_gen_resume_without_reclaim","code":5,"exceeds":true,"illegal_occupancy":73,"slot_count":72,"status":"REJECT"},"family":"negative"},"MF-NEG-RESOURCE-EXHAUSTION-BYTES":{"authority_fingerprint_hex":"b714f355cb5296f0e973e3347011a900acb9cb6f408501e222cdca36057c0b5e","expected":{"reject_code":5,"state_mutation":0,"status":"BUSY_OR_REJECT"},"family":"negative"},"MF-NEG-RESOURCE-EXHAUSTION-KEYS":{"authority_fingerprint_hex":"8ba6acb623b8a9313c3928da6df2e83302c48e67034543934b0fd41b36cef716","expected":{"branch":"bounded_host_and_esp_admission","esp_active_after_second":1,"esp_first_admitted":true,"esp_second_rejected":true,"host_active_after_fifth":4,"host_fifth_rejected":true,"host_first_four_admitted":true,"host_slot_order":[0,1,2,3],"reject_code":5,"state_mutation":0,"status":"OK"},"family":"negative"},"MF-NEG-RF-MAPPING-UNAVAILABLE":{"authority_fingerprint_hex":"e7cb22ce0410b2f349c7cfcb2d8d8fa4244708294bedc2fd2e83aeb160c0baac","expected":{"carrier":"compact_rf_nrw1","mapping":"MAPPING_UNAVAILABLE","reject_code":4,"status":"REJECT"},"family":"negative"},"MF-NEG-STALE-GENERATION":{"authority_fingerprint_hex":"9c454f67ff7fd569db1f2fd74917f07c8ccd4b877f5cb4c38fb10612415c54fe","expected":{"reason":"query_generation_gap_or_rollback","reject_code":8,"stage":5,"status":"REJECT"},"family":"negative"},"MF-NEG-STALE-VERSION-SELECTED-2":{"authority_fingerprint_hex":"ca90f9419adef814f16006960e805afd3c1db14824b76ab77433d6e02b1737b9","expected":{"reason":"mfn1_not_established","reject_code":4,"status":"REJECT"},"family":"negative"},"MF-NEG-STORAGE-SIDECAR-COLLISION":{"authority_fingerprint_hex":"071ba42df4ef1ca400e8b9f9a0ce9fb5a17202af8d4db6f02370bf8453c033a1","expected":{"branch":"derived_namespace_collision_binding_mismatch","existing_rows_overwritten":false,"foundation_scan_relaxed":false,"reason":"base_namespace_binding_mismatch","status":"REJECT","wire_or_apply":0},"family":"negative"},"MF-NEG-WHOLE-DIGEST-MISMATCH":{"authority_fingerprint_hex":"aec9b39a853706ea703ec777315f8b6fc7dd542655187b3ac5f7e776b8bd284c","expected":{"reject_code":2,"stage":4,"status":"REJECT"},"family":"negative"},"MF-NEG-WIFI-MAPPING-UNAVAILABLE":{"authority_fingerprint_hex":"ea119b274ea76e182b0a7d4c9790022e1d97cee12948edf4042cd7a3091e641b","expected":{"carrier":"wifi_nwb1","mapping":"MAPPING_UNAVAILABLE","reject_code":4,"status":"REJECT"},"family":"negative"},"MF-POS-APPLICATION-EVIDENCE-DIGEST-KAT":{"authority_fingerprint_hex":"bfab372cadd3c7059983dfdc033fd74a24c7124a624c2abfa265d55dd7e76e07","expected":{"application_evidence_digest_hex":"111189981b337d4bd82e94afb15e89e6b5ac6e07ffd729208ed99b9a015fb0b3","branch":"positive_required_evidence_handoff","disposition_fatal_recovery_may_advance":false,"evidence_length":10,"evidence_stage":3,"handoff_may_advance":true,"receipt_may_advance_after_handoff_full":true,"required_evidence":3,"status":"OK"},"family":"positive"},"MF-POS-COMPLETION-RECEIPT-REPLAY":{"authority_fingerprint_hex":"ffd9bfde136d57eacd97f33aea0b2425cc27095a4a7043d9c765a7ce1fbbd12f","expected":{"branch":"idempotent_accept_replay","state_mutation_on_replay":0,"status":"OK","transfer_accept_hex":"c9ccb68aea4d21db421738c08d2e5f6d0000000141a673e85caa860c346328f0407f3813f7f6bc5966815f04073260a0d7c3adbecf9d32a697a67f9a0644a06f44ee1f657b179b848990d93b92d50aaad782d6ab000000105758595a5b5c5d5e5f6061626364656600000000000000641718191a1b1c1d1e1f20212223242526af0364918131b6861e0b23994fa2eb1d1806222b5338bac98052fd5abb0264e8"},"family":"positive"},"MF-POS-EMPTY-PAYLOAD":{"authority_fingerprint_hex":"108d0dac0b4616f6c30b5f9334c602ed4554efa4b296649872d25cce68f52a89","expected":{"branch":"positive_transfer","chunk_count":0,"final_chunk_length":0,"manifest_digest_hex":"cb46359b17ce129af28d1cb098f83a5df324e2f67eb953274ac7fdfad31113e2","manifest_page_count":0,"open_accept_length":100,"publication_token_hex":"8761b3b0fbf62abbc6be6228421a6d82","status":"OK","total_length":0,"transfer_accept_length":160,"whole_content_sha256_hex":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},"family":"positive"},"MF-POS-EXACT-MULTIPLE-FINAL":{"authority_fingerprint_hex":"c1c9eaa62d215c74bd1988f9268c1ebcf5ebb28413e8f37a1b0d8c15c91c834d","expected":{"branch":"positive_transfer","chunk_count":2,"final_chunk_length":896,"manifest_digest_hex":"2f98cd7015a785f21ed36efb3352e37cf3a074acd47bf0a15e9fbc7cf72bda0c","manifest_page_count":1,"open_accept_length":100,"publication_token_hex":"8c83cfaf42920202ad24c04d35213b7a","status":"OK","total_length":1792,"transfer_accept_length":160,"whole_content_sha256_hex":"eb6cac7f35e334b7e5a3d37740446fb9a72a8974604e7ab6e60a8f5c98643478"},"family":"positive"},"MF-POS-EXPIRY-SLOT-REUSE":{"authority_fingerprint_hex":"7f3bae95dfdf11225cf5e47cd326eb6c293a41e5330ee924640535bd649a0f94","expected":{"active_count_after_expiry":0,"branch":"expiry_slot_reuse","esp_active_max":1,"new_transfer_open_admitted":true,"reuse_after":"G_R_EXPIRY_or_G_RETENTION_GC","status":"OK"},"family":"positive"},"MF-POS-HOST-FOUR-ACTIVE-TERMINAL-HIT":{"authority_fingerprint_hex":"793e6e30501366de5098434d274247323e884172be79d06219e88e9a3eacb0db","expected":{"active_after":4,"active_before":4,"active_slot_allocations":0,"branch":"four_active_terminal_hit_control_route","control_route":255,"full_count":0,"nrc1_hit":true,"owned_control_outbox":true,"peer_unpaid_fence_unchanged":true,"scheduler_cursor_unchanged":true,"status":"OK","store_mutation":0,"terminal_catalog_count":1,"transport_status":"OK"},"family":"positive"},"MF-POS-MAX-PAYLOAD-37-CHUNKS":{"authority_fingerprint_hex":"a783d2eee475966e29ef3cc2016db0b290ac1be35bc97174352ce5e13935d55c","expected":{"branch":"positive_transfer","chunk_count":37,"final_chunk_length":512,"manifest_digest_hex":"21931b7f1e06699f5d9b15014dfd92997fe1a34a2b76c87abefd2111324fad42","manifest_page_count":2,"open_accept_length":100,"publication_token_hex":"34728a95989d14084bccabafb09f5f07","status":"OK","total_length":32768,"transfer_accept_length":160,"whole_content_sha256_hex":"a77047432e200ebc2a7aa399be532389407248cb85693b978efb2754d244111c"},"family":"positive"},"MF-POS-NM30-SCHEMA2-LAYOUT-KAT":{"authority_fingerprint_hex":"c62b4e55fd03ab5899b1f47ea74b307988ccea012801f684ac423630be93adf2","expected":{"branch":"nm30_schema2_layout","crc_offset":176,"crc_preimage_bytes":176,"owner_role":2,"owner_role_offset":172,"peer_endpoint_id_bytes":16,"peer_endpoint_id_nonzero":true,"peer_endpoint_id_offset":156,"reserved_bytes":3,"reserved_offset":173,"reserved_zero":true,"schema":2,"session_cookie_durable":false,"session_generation_authority":"NRC1_header_offset_24","status":"OK","value_length":180},"family":"positive"},"MF-POS-ONE-BYTE":{"authority_fingerprint_hex":"8d07e19acc5c8182b292e4c609db659d6093ad23ccf2578728e9b4dd5041fc19","expected":{"branch":"positive_transfer","chunk_count":1,"final_chunk_length":1,"manifest_digest_hex":"e536bbd435a20beaffc8bd0bf37aa23dcd3b38752283327e480b9d35b404a19e","manifest_page_count":1,"open_accept_length":100,"publication_token_hex":"0f1ea7ab66554f029dfc667fa439849b","status":"OK","total_length":1,"transfer_accept_length":160,"whole_content_sha256_hex":"559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd"},"family":"positive"},"MF-POS-ONE-BYTE-FINAL":{"authority_fingerprint_hex":"48d00c9ee7551e784da8c8a3004f081824b34ab200812c51469c80d475b4a6d5","expected":{"branch":"positive_transfer","chunk_count":2,"final_chunk_length":1,"manifest_digest_hex":"4106142e74f2e7258c79e75274f19eee76d285dfd618d7b54c0a051ea4a85f49","manifest_page_count":1,"open_accept_length":100,"publication_token_hex":"36074561c35acee4d9edd781d4ea474d","status":"OK","total_length":897,"transfer_accept_length":160,"whole_content_sha256_hex":"524ae03737bd1d4a3e07bbeabaab592e6d07c99bc13ab465df93361757bd405b"},"family":"positive"},"MF-POS-OPEN-APPLICATION-BINDING-LAYOUT-KAT":{"authority_fingerprint_hex":"ffae95a8027ca737dd25489737c487dc687d1a883954c513b8ee256f597be892","expected":{"active_record_schema":2,"active_schema1_replay_eligible":false,"admission_profile_revision":2,"application_binding_bytes":228,"base_fixed_bytes":234,"branch":"open_application_binding_revision2","deadline_normalization_forbidden":true,"deadline_sentinel_erratum":"foundation_canonical_bit_exact","deadline_zero_rejected":true,"downlink_no_deadline_rejected":true,"finite_downlink_deadline_max_u64_hex":"fffffffffffffffe","finite_downlink_deadline_min_u64_hex":"0000000000000001","manifest_binds_entire_application_binding":true,"no_deadline_u64_hex":"ffffffffffffffff","nts3_future_fields":["mfdt_transfer_id[16]","mfdt_target_ordinal_u32"],"nts3_future_mfdt_record_max_bytes":3185,"nts3_future_mfdt_target_rule":"transfer_id_nonzero__sender_ordinal_eq_bound_target_index__receiver_ordinal_eq_open_origin_ordinal_lt4_u32_be","nts3_future_non_mfdt_memory_rule":"transfer_id_zero16_and_ordinal_zero","nts3_future_non_mfdt_suffix_bytes":0,"nts3_future_schema":"1.2","nts3_future_target_count_max":4,"nts3_future_target_suffix_bytes":20,"nts3_future_target_suffix_placement":"canonical_target_encoding_tail","nts3_future_target_suffix_presence":"bearer_route_eq_MFDT_V1_3","nts3_record_ceiling_bytes":4096,"nts3_schema11_inline_payload_max_bytes":926,"nts3_schema11_record_max_bytes":4031,"open_body_max":651,"open_body_min":465,"public_callback_context_id":"foundation_transaction_id","publication_token_scope":"private_mfdt_handoff_dedupe_only","status":"OK","text_offset":462},"family":"positive"},"MF-POS-REQID-CACHE-SAME-ID-STABLE":{"authority_fingerprint_hex":"8d773c00c4e6f00a63b451e2c3d7a1d5931e13817088d97461e6a3dddade0ee3","expected":{"branch":"request_id_cache_hit","cached_manifest_complete":0,"durable_cache":true,"first_manifest_complete":0,"nrc1_kind":"NRC1","request_id":7,"state_mutation_on_same_request_id":0,"status":"OK","storage_profile":"HOST_FULL_CAPABLE","target_unattested_replay_forbidden":true},"family":"positive"},"MF-POS-REQID-MAX-RETRY-TRACE":{"authority_fingerprint_hex":"b5956adba33c2e1a68227fa6b72655e5a1782d9296ae68695032db6487cccda7","expected":{"branch":"max_timeout_retry_trace","first_attempts":1,"fits_in_capacity":true,"new_request_id_each_retry":true,"occupied_count":9,"slot_count":72,"status":"OK","timeout_retries":8,"timeout_retry_max":8},"family":"positive"},"MF-POS-REQID-MAX-TRANSFER-OCCUPIED-41":{"authority_fingerprint_hex":"c84624f891530d2876b020dc26a9ca703251c8d38f95b7569eda51b7cbdabe4e","expected":{"branch":"max_transfer_nrc1_occupancy","cache_full":false,"chunk_ids":37,"exceeds_obsolete_fixed16":true,"finalize_ids":1,"fits":true,"occupied_count":41,"open_ids":1,"page_ids":2,"slot_count":72,"status":"OK"},"family":"positive"},"MF-POS-REQID-NEW-ID-CURRENT-COMPLETE":{"authority_fingerprint_hex":"313b469bd9fdea0d6c79fb7584e3cbf11898a4164646ccd4c319c81b4fc08456","expected":{"branch":"new_request_id_current_state","first_manifest_complete":0,"first_request_id":7,"nrc1_occupied_after":2,"second_manifest_complete":1,"second_request_id":8,"status":"OK"},"family":"positive"},"MF-POS-REQID-NRC1-LAYOUT-KAT":{"authority_fingerprint_hex":"d808d8449b8a803f2df29596d3730165575b6ab46484895c5988087feeebd133","expected":{"branch":"nrc1_layout","empty_slot":"ALL_ZERO_ACCEPTED","first_slot_session_generation":1,"happy_path_max_ids":41,"key_length":20,"logical_bytes":15056,"lookup_identity":"session_generation_plus_request_id","occupied_l0_mutant":"REJECT_SEMANTIC","occupied_response_length_min":1,"reachable_max_ids":65,"slot_bytes":208,"slot_count":72,"slot_session_generation_offset":8,"status":"OK","timeout_retry_max":8,"value_length":15020},"family":"positive"},"MF-POS-REQID-REACHABLE-MAX-COUNT":{"authority_fingerprint_hex":"8b82c3f3211513ded355559c901aad7969faf86714a511ee858c591ea0e0e2df","expected":{"abort_gen_max":8,"branch":"nrc1_reachable_max","capacity_spare":7,"denied_abort_after_content_verified_consumes_slot":true,"derived_from_retry_budget_sm":true,"finalize_abort_success_exclusive":true,"happy_first":41,"illegal_two_gen_exceeds_72":true,"illegal_two_gen_no_reclaim":73,"n_abort":64,"n_complete":65,"naive_union":57,"naive_union_is_single_path":false,"reachable_max":65,"resume_max":8,"resume_reclaim_on_session_gen_advance":true,"slot_count":72,"slot_count_ge_reachable":true,"status":"OK","terminal_outcomes_exclusive":true,"timeout_retry_max":8},"family":"positive"},"MF-POS-REQID-RETRY-BUDGET-SM":{"authority_fingerprint_hex":"407c2dff061e6cb54da4adb87c8be85abd860cf40c622d63188b12f1f0da4165","expected":{"branch":"retry_budget_sm","decrement_event":"timeout_retry_with_new_request_id","decrement_requires_full_before_wire":true,"exhaustion_forbids_new_request_id_timeout_retry":true,"exhaustion_is_nrc1_eviction":false,"exhaustion_is_terminal":false,"header_offset":105,"initial_value":8,"max_value":8,"min_value":0,"not_per_request_id":true,"not_per_stage":true,"owner":"requestor_of_outbound_mfdt_control","scope":"per_transfer_per_owner_side","status":"OK"},"family":"positive"},"MF-POS-REQID-SESSION-GEN-RESUME-RECLAIM":{"authority_fingerprint_hex":"1f0008d5cd7c03151ccb310465a4e51ee969d9ee39bf3c3dd35fd20ee13a99c6","expected":{"active_header_session_generation_offset":300,"advance_rule":"current_plus_1_no_wrap","allowed_slot_generations":"current_or_exact_prior","anchor":"initial_non_resume_open_accept_slot","branch":"session_gen_resume_reclaim","future_generation_record_status":"CORRUPT","gap_generation_record_status":"CORRUPT","initial_occupied":2,"initial_session_generation":7,"initial_session_generation_domain":"u32_nonzero","lifetime_resume_attempts_max":16,"lookup_identity":"session_generation_plus_request_id","non_resume_retained_whole_lifetime":true,"peak_with_reclaim":65,"reclaim_resume_class_only":true,"resume_counter_reset":true,"resume_per_gen":8,"same_request_id_across_generation_distinct":true,"second_advance_status":"CAPACITY","session_advance_full_members":["ACTIVE","NRC1"],"session_gen_is_distinct_count_not_numeric_max":true,"session_gen_max":2,"slot_bound_session_generation":true,"status":"OK","successor_occupied_after_reclaim":2,"successor_session_generation":8,"third_generation_record_status":"CORRUPT","uint32_max_advance_status":"CAPACITY"},"family":"positive"},"MF-POS-REQID-TERMINAL-LATE-DUP-MATRIX":{"authority_fingerprint_hex":"8e98f7150e9e890269e50b9dfe40e64b627549f39c5b861b7dc10d09c0e272de","expected":{"all_bit_exact":true,"branch":"terminal_late_dup_matrix","nrc1_retained_with_nm30":true,"operation_count":6,"state_mutation_on_hit":0,"status":"OK","terminal_erases_nrc1":false},"family":"positive"},"MF-POS-TWO-PAGE-MANIFEST":{"authority_fingerprint_hex":"1a592cd81198871721a283d02656e68ada6e53f2a467cd5eb509fa60adc5f313","expected":{"branch":"positive_transfer","chunk_count":23,"final_chunk_length":896,"manifest_digest_hex":"66f64044d900b7f1a5a8ce816a972edd96045bc506429704b266b92bc91e8d52","manifest_page_count":2,"open_accept_length":100,"publication_token_hex":"e9540f71d893043b3ad567b1f5c528e0","status":"OK","total_length":20608,"transfer_accept_length":160,"whole_content_sha256_hex":"550dbf37283cf5e4fbae21e5aa8ab083ae8004137e429767543093d8d55f1834"},"family":"positive"},"MF-PRIVATE-API-SURFACE":{"authority_fingerprint_hex":"6cac832128fc9f82b567053f311cb33ab8c22e086df364683857c75e0001eae4","expected":{"default_off":true,"host_fifth_active":"CAPACITY_BUSY_control_outbox_state_mutation_0","host_owner_workspace_bytes":280064,"host_slot_count":4,"per_slot_workspace_bytes":65536,"public_abi":false,"status":"OK"},"family":"catalog"},"MF-PUBLICATION-OWNER-MATRIX":{"authority_fingerprint_hex":"2888849effb9dd08c4353addb636770bc196739098ba09aee9f2514dc40f9e2d","expected":{"sole_prepare_caller":"receiver_multi_frame_owner","status":"OK"},"family":"catalog"},"MF-ROLE-BOUNDARIES":{"authority_fingerprint_hex":"1d32e0382a504f0aade7992f8099a1bc9128d66fd5089e9e5784dbf4aade405b","expected":{"false_custody":false,"status":"OK"},"family":"catalog"},"MF-TRACE-S1-S6-HAPPY-PATH":{"authority_fingerprint_hex":"2446e736b03afcd7cdae240daaee27b39b129070f4cc7fba7f81938b5f8afcf6","expected":{"branch":"s1_s6_trace","s6_durable":"NM30_ONLY","stages":["S1","S2","S3","S4","S5","S6"],"status":"OK"},"family":"catalog"},"MF-TX-CLEANUP-RETENTION-GC":{"authority_fingerprint_hex":"215528840e59dc4570533fa9e697c7524cebf16a74599810d2cc046bf3bb43be","expected":{"active_eviction_forbidden":true,"after_boundary":"OK_DELETE","before_boundary":"REJECT_NOT_ELAPSED","branch":"gc_after_retention","epoch_mismatch":"REJECT_STATE","equal_boundary":"OK_DELETE","group":"G_R_RETENTION_GC","nrc1_deleted_with_nm30":true,"status":"OK"},"family":"transcript"},"MF-TX-CROSS-NAMESPACE-ADMISSION-MATRIX":{"authority_fingerprint_hex":"e733b6e4b24fba4f5d9623d392a6faaa97497689bfc056bd396d48eae23c8208","expected":{"admission_execution_scope":"owner_thread_call","attempt_candidate_bound_to_target_open":true,"attempt_candidate_nonzero":true,"attempt_collision_set":"durable_active_retained_plus_prior_same_admission_candidates","attempt_consumed_claim_before_foundation_full":0,"attempt_draw_order":"canonical_target_order","attempt_draws_max_per_target":4,"blind_attempt_redraw_forbidden":true,"branch":"canonical_roster_target_attempt_prearm_foundation_full_reconcile","compound_receiver_key_created":false,"duplicate_runtime_api_status":"NINLIL_OK","duplicate_runtime_entropy_draws":0,"duplicate_runtime_foundation_mutations":0,"duplicate_runtime_reason":"TARGET_COUNT_UNSUPPORTED","duplicate_runtime_sidecar_mutations":0,"duplicate_runtime_submission_state":"REJECTED","foundation_admission_atomic_members":["exact_target_roster","per_target_attempt_index_and_binding","attempt_budget_and_counters","ATTEMPT_PREPARED_and_pending_state","per_target_mfdt_transfer_id_and_origin_ordinal"],"foundation_admission_full_count":1,"foundation_commit_unknown_deletes_sidecar":false,"matching_both":"RESUME_ELIGIBLE","missing_sidecar_for_durable_mfdt":"CORRUPT_FENCE","new_durable_state_added":false,"nts3_target_local_suffix_rule_changed":false,"orphan_cleanup_before_wire_or_apply":true,"restart_reconcile_before_bearer_open":true,"runtime_uniqueness_scope":"MFDT_V1_ONLY","same_runtime_different_application_instance_rejected":true,"sidecar_prearm_before_foundation_full":true,"status":"OK","target_count_max":4,"target_count_min":1,"target_runtime_unique_within_origin":true,"wire_or_apply_before_match":0,"wire_txgate_callback_before_foundation_full":0},"family":"transcript"},"MF-TX-EPOCH-CHANGE-TERMINAL":{"authority_fingerprint_hex":"7240c3b18a501913dbd4f4be5709b1f34f4f0692f1389842aaff8431dbcc6e98","expected":{"active_erased":true,"branch":"epoch_changed_terminal","nm30_terminal_reason":32770,"nm30_terminal_state":3,"publish_forbidden":true,"status":"OK"},"family":"transcript"},"MF-TX-EXPIRY-MANDATORY-TOMBSTONE":{"authority_fingerprint_hex":"b473043632cd1b8d75e9ea54164ce9d462cc1fd8c8483d4c123978918e9019de","expected":{"abort_generation":0,"active_slot_freed":true,"authority_actor_zero":true,"branch":"expiry_mandatory_tombstone","mandatory_full":"G_R_EXPIRY","nm30_present":true,"nm30_value_bytes":180,"nrc1_retained_until_gc":true,"reject_code":7,"status":"OK","terminal_catalog_all_canonical":true,"terminal_catalog_count":8,"terminal_reason":5,"terminal_state":2,"wire_abort_reason_5_forbidden":true,"wire_abort_reason_max":4,"wire_abort_reason_min":1},"family":"transcript"},"MF-TX-HOST-TERMINAL-COLD-REBIND-HIT":{"authority_fingerprint_hex":"b8666a9a0647ffcd4120ccf535a200201c29e041ed5019e1456952bb4268e9a6","expected":{"active_slots_consumed":0,"branch":"host_terminal_cold_rebind_hit","cacheable":true,"catalog_schema":2,"control_route":255,"cookie_restored_from_storage":false,"fresh_nonzero_cookie":true,"full_count":0,"generation_exact":true,"nrc1_generation_offset":24,"nrc1_hit":true,"owned_control_outbox":true,"peer_exact":true,"post_terminal_miss_cacheable":true,"post_terminal_miss_full_count":1,"post_terminal_miss_transfer_state_mutation":0,"response_bit_exact":true,"role_exact":true,"status":"OK","transfer_state_mutation":0,"transport_status":"OK"},"family":"transcript"},"MF-TX-POWER-CUT-AFTER-CHUNK-FULL":{"authority_fingerprint_hex":"6563193d5c8ee6a347ad636c7324475b86f7810cf580b2369f711c44c9aa9469","expected":{"branch":"resume_from_bitmap","sender_release":false,"status":"RECOVER","wire_success_at_cut":0},"family":"transcript"},"MF-TX-POWER-CUT-AFTER-CONTENT-VERIFIED":{"authority_fingerprint_hex":"5fbe2724e0887537a88b240d1c5e99166476f2a823e8cf937322d38c6a64af4a","expected":{"accept_notified":0,"branch":"ready_token_reprompt","publication_state":1,"status":"RECOVER"},"family":"transcript"},"MF-TX-POWER-CUT-DURING-TERMINAL":{"authority_fingerprint_hex":"f99aab9105993e64b46a4071f098f659f9dc0570bb2ff9ae3771c96fd6b2831a","expected":{"classify":true,"group":"G_R_TERMINAL","status":"COMMIT_UNKNOWN"},"family":"transcript"},"MF-TX-REQID-CACHE-CRASH-RESTART":{"authority_fingerprint_hex":"272b1e00d004c2ea8ea12126ae9dba6a25462ae952c84a264178d058f1396874","expected":{"branch":"nrc1_restart_hit","re_evaluation_forbidden":true,"response_bodies_equal":true,"state_mutation_on_restart_hit":0,"status":"OK"},"family":"transcript"},"MF-TX-REQID-TERMINAL-RESTART-LATE-DUP":{"authority_fingerprint_hex":"8f1d6bcb3f5b5986953e220ff1c9e9c24458edd00828ebde335d5772176148cb","expected":{"branch":"terminal_restart_late_dup","nrc1_retained_with_nm30":true,"re_evaluation_forbidden":true,"response_bodies_equal":true,"state_mutation_on_hit":0,"status":"OK"},"family":"transcript"},"MF-TX-RESUME-AFTER-RESTART":{"authority_fingerprint_hex":"f5a284edf2c37e7e050d2e42355902fc8f142e49b38d841e31634c6449c59893","expected":{"bitmap":1,"branch":"resume_state","sender_may_release":false,"state_digest_hex":"9b1852bef5184a0e0f0152bb825362d4875f84b799a5266e6d98439254013bbc","status":"OK"},"family":"transcript"},"MF-TX-ROLLBACK-POLICY-OFF":{"authority_fingerprint_hex":"510b22a7563e5489802a34185c386f5f324d9152fd309d86b791aecdc781038f","expected":{"branch":"rollback","in_place_v3_to_v2_conversion":false,"rehello_max_control_version":2,"status":"OK"},"family":"transcript"},"MF-TX-TERMINAL-CRASH-ACTIVE-ONLY":{"authority_fingerprint_hex":"588aee1a00342bbb225d38f734937a0e86c9bd67770864c3e8c9fcb18b1b27b5","expected":{"action":"retry_terminal_full","classification":"OLD","durable_kinds":["NM3R"],"group":"G_R_TERMINAL","status":"COMMIT_UNKNOWN"},"family":"transcript"},"MF-TX-TERMINAL-CRASH-NM30-ONLY":{"authority_fingerprint_hex":"2ef5dddcf73f208ead616317ab1a9252a07517b52ec0220fcc64743acbbcf241","expected":{"action":"adopt_nm30","classification":"NEW","durable_kinds":["NM30"],"group":"G_R_TERMINAL","status":"COMMIT_UNKNOWN"},"family":"transcript"},"MF-VERSION-CATALOG-INHERITANCE":{"authority_fingerprint_hex":"fb9d1c9219608ddd86e88be7d87bb1afbcc4397f49bbee5144aca1d2253e9e4c","expected":{"accepted_control_selected_values":[1,2],"accepted_wire_changed":false,"docs_25_26_refreeze_forbidden_in_this_candidate":true,"mf_o01_status":"SPEC_ACCEPTED_GREEN_BASELINE_HISTORY","mf_o09_status":"SPEC_ACCEPTED_CLOSED","mfdt_accept_type":53,"mfdt_candidate_type_count":16,"mfdt_candidate_type_range":"0x34..0x43","mfdt_negotiation_independent_of_selected_control_version":true,"mfdt_offer_type":52,"mfdt_transfer_type_count":14,"selected_3_includes_u5_u6_mf":false,"selected_control_version_3":"REJECT","silent_ge2_forbidden":true,"status":"OK","target_promotion_on":"UNALLOCATED_UNSUPPORTED"},"family":"catalog"}};

const CHUNK_SIZE = 896;
const MAX_CONTENT = 32768;
const MAX_CHUNKS = 37;
const ENTRIES_PER_PAGE = 22;
const HEADER_BYTES = 308;
const NM30_BYTES = 180;
const NM30_LEGACY_SCHEMA1_BYTES = 164;
const RECEIVER_FULLS_MAX = 77;
const SENDER_FULLS_MAX = 67;
const RECEIVER_FULLS_EMPTY = 5;
const SENDER_FULLS_EMPTY = 5;
const GATE_INDEPENDENT_CONSTANTS = {
  chunk_size: 896,
  max_content_bytes: 32768,
  max_chunk_count: 37,
  entries_per_page: 22,
  max_manifest_pages: 2,
  active_header_bytes: 308,
  nm30_value_bytes: 180,
  nm30_legacy_schema1_value_bytes: 164,
  receiver_fulls_max_transfer: 77,
  sender_fulls_max_transfer: 67,
  receiver_fulls_empty_transfer: 5,
  sender_fulls_empty_transfer: 5,
  required_receiver_fulls_reference: 154,
  required_sender_fulls_reference: 134,
  obsolete_rejected_mf_fulls_per_day: 80,
  ncl1_body_max: 998,
  workspace_bytes: 65536,
  open_base_fixed_bytes: 234,
  application_binding_bytes: 228,
  open_fixed_bytes: 462,
  open_body_min: 465,
  open_body_max: 651,
  page_header_bytes: 92,
  chunk_offer_header_bytes: 96,
  transfer_accept_bytes: 160,
  bind52_bytes: 52,
  nrc1_slot_bytes: 208,
  nrc1_value_bytes: 15020,
  nrc1_logical_bytes: 15056,
  active_record_schema: 2,
  active_value_max: 35211,
  active_row_logical_bytes_max: 35247,
  active_replacement_begin_final_logical_bytes_max: 70494,
  admission_reserved_logical_bytes: 50519,
  host_slot_count: 4,
  host_coordinator_bytes: 512,
  host_control_arena_bytes: 17920,
  host_terminal_catalog_entries: 16,
  host_terminal_catalog_entry_bytes: 64,
  host_control_outbox_bytes: 1024,
  host_control_route_sentinel: 255,
  host_owner_workspace_bytes: 280064,
  host_active_group_logical_bytes: 50303,
  host_four_active_committed_logical_bytes: 201212,
  host_committed_logical_bytes_hard_max: 384476,
  host_serialized_full_staging_logical_bytes_max: 50303,
  host_begin_final_union_logical_bytes_hard_max: 434779,
};

const APPLICATION_BINDING_LAYOUT_GATE = [
  ["original_attempt_id", 234, 16], ["target_ordinal_u32", 250, 4],
  ["source_application_instance_id", 254, 16], ["source_device_id", 270, 16],
  ["source_installation_id", 286, 16], ["source_site_domain_id", 302, 16],
  ["source_binding_epoch_u64", 318, 8], ["source_membership_epoch_u64", 326, 8],
  ["source_identity_flags_u32", 334, 4], ["source_reserved_u32", 338, 4],
  ["target_application_instance_id", 342, 16], ["target_device_id", 358, 16],
  ["target_installation_id", 374, 16], ["target_site_domain_id", 390, 16],
  ["target_binding_epoch_u64", 406, 8], ["target_membership_epoch_u64", 414, 8],
  ["target_identity_flags_u32", 422, 4], ["target_reserved_u32", 426, 4],
  ["service_schema_major_u16", 430, 2], ["service_schema_minor_u16", 432, 2],
  ["service_family_u32", 434, 4], ["application_generation_u64", 438, 8],
  ["evidence_grace_ms_u64", 446, 8], ["required_evidence_u32", 454, 4],
  ["application_binding_flags_u32", 458, 4],
];

const JSON_SAFE_INT_MAX = Number.MAX_SAFE_INTEGER; // 2^53 - 1
const DOCUMENT_TOP_LEVEL_KEYS = new Set([
  "schema", "status", "adr", "title", "nonclaims", "constants", "version_catalog",
  "carrier_mapping", "publication_owner", "role_boundaries", "private_api", "budget",
  "required_vector_ids", "required_gate_cases", "authority_map_sha256_hex",
  "authority_index", "vectors", "sources", "source_sha256_hex",
]);
const VECTOR_COMMON_REQUIRED = new Set(["id", "family", "expected", "authority_fingerprint_hex"]);
const VECTOR_OPTIONAL_BY_FAMILY = {
  catalog: new Set([
    "constants", "version_catalog", "carrier_mapping", "publication_owner", "role_boundaries", "private_api",
    "storage_profile", "required_vector_ids", "pin", "forbidden_active_state_codes", "allowed_pre_terminal_active_codes", "stages",
  ]),
  budget: new Set([
    "budget", "groups", "receiver_fulls", "sender_fulls", "feasible", "obsolete_cap", "required_receiver_fulls",
    "restoration_object", "restoration_sha256_hex", "value_bytes", "logical_bytes", "slot_count", "min_lifecycle_ids",
    "happy_path_max_ids", "reachable_max_ids", "n_complete", "n_abort", "timeout_retry_max", "capacity_spare",
    "admission_reserved_entries", "admission_reserved_logical_bytes", "note", "nrc1_retained_until_gc", "terminal_erases_nrc1",
    "receiver_fulls", "sender_fulls", "receiver_base", "receiver_resume", "receiver_reqid_cache", "sender_base", "sender_resume", "sender_reqid_cache",
    "receiver_retry_budget", "sender_retry_budget", "session_gen", "groups",
    "host_four_active_committed_logical_bytes", "host_committed_logical_bytes_hard_max",
    "host_begin_final_union_logical_bytes_hard_max",
  ]),
  positive: new Set([
    "fixture", "first_accept_hex", "replay_accept_hex", "fixture_ids", "request_id", "first_page_accept_hex",
    "cached_retry_page_accept_hex", "note", "first_request_id", "second_request_id", "second_page_accept_hex", "nrc1_key_hex",
    "nrc1_value_hex", "nrc1_value_after_second_hex", "request_body_digest_hex", "nrc1_magic", "header_crc_ok", "record_crc_ok",
    "occupied_count", "exceeds_obsolete_fixed16", "happy_first", "n_complete", "n_abort", "reachable_max", "timeout_retry_max",
    "resume_max", "abort_gen_max", "slot_count", "capacity_spare", "naive_union", "formula_complete", "formula_abort",
    "retry_request_ids", "transcript", "retry_budget_sm", "first_units", "phase", "note",
    "nm30_key_hex", "nm30_value_hex", "nm30_sha256_hex", "transfer_id_hex",
    "peer_endpoint_id_hex", "owner_role_name", "durable_fields_exclude", "operations",
    "active_transfer_ids", "terminal_transfer_id_hex", "terminal_request_id",
    "terminal_response_body_hex",
    "session_gen_max", "resume_per_gen", "peak_with_reclaim",
    "first_slot_hex", "first_slot_session_generation_hex", "empty_slot_hex",
    "occupied_l0_repaired_crc_mutant_hex", "generation_1_nrc1_value_hex",
    "generation_2_nrc1_value_hex", "retained_non_resume_slot_hex",
    "reclaimed_generation_1_resume_slot_hex", "admitted_generation_2_resume_slot_hex",
    "request_id_reused_across_generation", "initial_session_generation",
    "successor_session_generation", "future_generation_nrc1_value_hex",
    "gap_generation_nrc1_value_hex", "third_generation_nrc1_value_hex",
    "application_binding_layout", "minimum_open_body_hex", "minimum_manifest_digest_hex",
    "minimum_facts", "maximum_open_body_hex", "maximum_manifest_digest_hex", "maximum_facts",
    "deadline_shape_cases",
    "domain_ascii", "publication_token_hex", "origin_transaction_id_hex", "original_attempt_id_hex",
    "target_ordinal", "evidence_stage", "evidence_bytes_hex", "evidence_preimage_hex",
    "application_evidence_digest_hex", "callback_context_id_hex", "callback_context_authority",
    "publication_token_scope",
  ]),
  negative: new Set(["nrc1_slot_occupied", "nrc1_key_hex", "nrc1_value_hex", "occupied_count", "new_request_id",
    "illegal_occupancy", "slot_count",
    "abort_ack_hex", "abort_hex", "actual_whole_hex", "admission", "attempted_message_type", "bytes_hard_max", "carrier",
    "chunk_bitmap", "chunk_count", "chunk_index", "claimed_total_length", "claimed_whole_hex", "content_hex", "expected_whole_hex",
    "finalize_hex", "first_digest_hex", "first_full", "first_offer_hex", "keys_hard_max", "last_query_generation", "local_policy",
    "local_selected", "max_content", "may_prepare", "message_type", "namespace_keys_in_use", "namespace_logical_bytes_in_use",
    "nm30_hex", "note", "now_ms", "offer_0_hex", "offer_1_hex", "offered_query_generation", "offers_in_order", "open_body_hex",
    "open_preimage_hex", "request_body_digest_hex", "wrong_bind52_strip_digest_hex",
    "outstanding_unpaid_offers", "peer_selected", "receiver_state", "reservation_not_after_ms", "resume_bitmap", "resume_query_hex",
  "same_epoch", "second", "second_digest_hex", "second_offer_hex", "selected_control_version",
  "base_selected_control_version", "mfdt_admission_version", "mfn1_session_generation",
  "active_session_generation", "transfer_accept_received",
    "mfdt_requires_bytes", "mfdt_requires_keys", "request_id", "first_request_body_digest_hex", "second_request_body_digest_hex",
    "host_admission_trace", "host_restart_input_transfer_ids",
    "host_restart_canonical_slot_transfer_ids", "esp_admission_trace", "host_bounds",
    "reservation_deadline_matrix", "initial_next_slot", "continuously_eligible_slots",
    "successful_selection_trace", "peer_assignment_by_slot", "peer_a_has_unpaid_offer",
    "scan_from_slot", "selected_slot_with_peer_a_blocked", "next_slot_after_selection",
    "restart_next_slot",
    "epoch_before_hex", "epoch_after_hex", "transfer_state_before", "phase", "nrc1_present", "nm30_present",
    "legacy_nm30_value_hex", "catalog_state", "permitted_actions", "forbidden_actions",
    "authority", "cases", "fresh_open_body_hex", "busy_body_hex", "busy_layout",
    "first_owned_frame", "blocked_second_frame", "response_body_hex", "admission_policy",
    "g_r_open_started", "deadline_relation", "request_type", "request_body_hex",
    "nrc1_slot_hex", "active_slot", "full_group",
    "manifest_entries_hex", "manifest_digest_hex", "mutations", "mismatch_fields", "validation_boundary",
  ]),
  commit_unknown: new Set(["group", "old_rows", "new_rows", "observed_rows", "note"]),
  transcript: new Set(["post_restart_page_accept_hex", "nrc1_key_hex", "nrc1_value_hex", "request_id", "first_page_accept_hex",
    "committed_chunk_bitmap", "fixture_ids", "last_full_group", "now_ms", "publication_token_hex", "resume_state_hex",
    "resume_state_length", "retention_ms", "retention_epoch_id_hex", "retention_anchor_ms",
    "retention_duration_ms", "retention_boundary_ms", "boundary_matrix", "terminal_catalog",
    "tombstone_digest_hex", "steps", "tombstone_present_after", "tombstone_present_before", "transcript",
    "observed_kinds", "pre_terminal_state", "nm30_terminal_state", "terminal_reason",
    "nrc1_present_before", "nrc1_present_after", "nm30_key_hex", "nm30_value_hex", "phase", "note",
    "recovered_catalog_entry", "rebind", "hit", "post_terminal_miss",
  ]),
};
const AUTHORITY_INDEX_ROW_KEYS = new Set(["family", "expected", "authority_fingerprint_hex"]);
const FIXTURE_KEYS = new Set([
  "acceptance_record_digest_hex", "chunk_accepts", "chunks", "content_hex", "content_sha256_hex", "entries_hex", "facts",
  "finalize_hex", "finalize_length", "full_chunk_bitmap", "full_page_bitmap", "ids", "manifest_digest_hex", "nm30_key_hex",
  "nm30_value_hex", "open_accept_hex", "open_accept_length", "open_body_hex", "page_accepts", "pages", "publication_token_hex",
  "receiver_content_verified_key_hex", "receiver_content_verified_sha256_hex", "receiver_content_verified_value_hex",
  "reservation_not_after_ms", "tombstone_digest_hex", "transfer_accept_hex", "transfer_accept_length",
]);
const FIXTURE_FACTS_KEYS = new Set([
  "application_binding_hex", "application_binding_length", "application_binding_offset", "application_generation",
  "chunk_count", "chunk_size", "evidence_grace_ms", "manifest_digest_hex", "manifest_page_count",
  "manifest_revision", "namespace", "open_body_length", "required_evidence", "schema", "service",
  "service_family", "service_schema_major", "service_schema_minor", "target_ordinal", "text_offset",
  "total_length", "whole_content_sha256_hex",
]);
const FIXTURE_IDS_KEYS = new Set([
  "authority_actor_id", "deadline_clock_epoch_id", "origin_event_id", "origin_transaction_id", "original_attempt_id",
  "receiver_evidence_id", "reservation_clock_epoch_id", "reservation_id", "service_descriptor_digest",
  "source_runtime_id", "source_application_instance_id", "source_device_id", "source_installation_id",
  "source_site_domain_id", "target_runtime_id", "target_application_instance_id", "target_device_id",
  "target_installation_id", "target_site_domain_id", "transfer_id",
]);
const PAGE_META_KEYS = new Set(["body_hex", "body_length", "entry_count", "first_chunk_index", "page_count", "page_digest_hex", "page_index"]);
const CHUNK_META_KEYS = new Set(["body_hex", "body_length", "chunk_bytes_hex", "chunk_count", "chunk_index", "chunk_length", "chunk_offset", "chunk_sha256_hex"]);
const PAGE_ACCEPT_KEYS = new Set(["body_hex", "body_length", "manifest_complete", "page_index"]);
const CHUNK_ACCEPT_KEYS = new Set(["body_hex", "body_length", "chunk_index"]);
const CU_ROW_KEYS = new Set(["key_hex", "value_hex"]);
const CONSTANTS_KEYS = new Set([
  "abort_generation_max", "active_header_bytes", "active_header_session_generation_offset", "active_record_schema",
  "active_schema1_replay_eligible", "active_value_max", "application_binding_bytes", "application_binding_layout",
  "chunk_size", "different_epoch_numeric_deadline_compare_forbidden", "digest_domains", "entries_per_page",
  "esp_active_transfers_max", "host_active_transfers_max", "host_control_arena_bytes",
  "host_control_nm30_scratch_bytes", "host_control_nrc1_scratch_bytes",
  "host_control_outbox_bytes", "host_control_outbox_metadata_bytes",
  "host_control_recovery_reserved_bytes", "host_control_route_sentinel",
  "host_coordinator_bytes", "host_fair_selection_bound",
  "host_owner_full_transactions_max", "host_owner_workspace_bytes", "host_peer_unpaid_chunk_offer_max",
  "host_scheduler_next_slot_initial", "host_scheduler_scan_bound", "host_slot_count",
  "host_terminal_catalog_bytes", "host_terminal_catalog_entries",
  "host_terminal_catalog_entry_bytes", "manifest_digest_preimage",
  "manifest_entry_bytes", "manifest_entry_layout", "mfdt_admission_profile_revision", "max_chunk_count", "max_content_bytes", "max_manifest_pages",
  "no_deadline_u64_hex", "finite_downlink_deadline_min_u64_hex", "finite_downlink_deadline_max_u64_hex",
  "uplink_eventfact_deadline_shape", "finite_downlink_deadline_shape", "original_application_open_deadline_mapping",
  "message_types", "ncl1_body_max", "nm30_crc_offset", "nm30_crc_preimage_bytes",
  "nm30_expired_reason_terminal_only", "nm30_legacy_schema1_replay_eligible",
  "nm30_legacy_schema1_value_bytes", "nm30_owner_role_offset",
  "nm30_peer_endpoint_id_bytes", "nm30_peer_endpoint_id_offset",
  "nm30_reserved_bytes", "nm30_reserved_offset", "nm30_schema",
  "nm30_session_cookie_durable", "nm30_terminal_reasons",
  "nm30_terminal_states", "nm30_value_bytes", "nrc1_capacity_spare", "nrc1_empty_slot_all_zero",
  "nrc1_happy_path_max_ids", "nrc1_illegal_two_gen_no_reclaim", "nrc1_logical_bytes", "nrc1_n_abort",
  "nrc1_n_complete", "nrc1_naive_union_ids_rejected_as_single_path", "nrc1_occupied_response_length_max",
  "nrc1_occupied_response_length_min", "nrc1_reachable_max_ids",
  "nrc1_resume_reclaim_on_session_gen_advance", "nrc1_session_gen_max_per_transfer", "nrc1_slot_bytes",
  "nrc1_header_session_generation_offset", "nrc1_slot_count", "nrc1_slot_lookup_identity",
  "nrc1_slot_session_generation_offset", "nrc1_value_bytes",
  "nts3_current_schema_major", "nts3_current_schema_minor", "nts3_future_fields", "nts3_future_schema_minor",
  "nts3_future_target_suffix_placement", "nts3_future_target_suffix_presence",
  "nts3_future_target_suffix_bytes", "nts3_future_target_count_max",
  "nts3_future_mfdt_target_rule", "nts3_future_non_mfdt_suffix_bytes",
  "nts3_future_non_mfdt_memory_rule", "nts3_schema11_record_max_bytes",
  "nts3_schema11_inline_payload_max_bytes", "nts3_future_mfdt_record_max_bytes",
  "nts3_record_ceiling_bytes",
  "open_base_fixed_bytes", "open_body_max", "open_body_min", "open_fixed_bytes",
  "open_growth_bytes_redistributed_within_each_slot", "open_text_offset", "public_callback_context_id",
  "publication_token_scope", "reject_codes", "request_body_digest_preimage",
  "reservation_add_overflow_threshold_u64_hex", "reservation_lifetime_ms",
  "restart_requires_full_semantic_validation_before_install", "resume_query_max", "retention_ms",
  "retention_requires_same_trusted_epoch", "retry_budget_decrement_event", "retry_budget_header_offset",
  "retry_budget_initial", "retry_budget_owner", "retry_budget_remaining_max", "retry_budget_remaining_min",
  "retry_budget_scope", "sha256_empty_hex", "stages", "storage_key_bytes", "storage_kinds",
  "terminal_session_generation_authority", "timeout_retry_max", "wire_abort_reasons",
  "workspace_bytes", "workspace_growth_bytes", "workspace_scope",
]);
const BUDGET_KEYS = new Set([
  "active_replacement_begin_final_logical_bytes_max", "active_row_logical_bytes_max",
  "admission_reserved_entries", "admission_reserved_logical_bytes", "groups",
  "host_active_group_logical_bytes", "host_begin_final_union_logical_bytes_hard_max", "host_committed_keys_hard_max",
  "host_committed_logical_bytes_hard_max", "host_four_active_committed_logical_bytes",
  "host_serialized_full_staging_logical_bytes_max", "host_serialized_full_staging_row_images_max",
  "host_slot_count", "host_terminal_group_logical_bytes", "host_tracked_transfer_groups_max",
  "namespace_keys_hard_max", "namespace_logical_bytes_hard_max", "nrc1_capacity_spare",
  "nrc1_happy_path_max_ids", "nrc1_n_abort", "nrc1_n_complete", "nrc1_reachable_max_ids",
  "nrc1_retained_until_gc", "nrc1_row_logical_bytes", "nrc1_slot_count", "nrc1_timeout_retry_max",
  "nrc1_value_bytes", "obsolete_80_feasible_for_reference_receiver", "obsolete_rejected_mf_fulls_per_day",
  "planned_mf_maxsize_transfers_per_day_reference", "post_terminal_retained_entries",
  "post_terminal_retained_logical_bytes", "receiver_fulls_base", "receiver_fulls_empty_transfer",
  "receiver_fulls_max_transfer", "receiver_fulls_reqid_cache", "receiver_fulls_resume",
  "receiver_fulls_retry_budget", "receiver_fulls_session_gen", "required_receiver_fulls_for_reference",
  "required_sender_fulls_for_reference", "restoration_object", "restoration_sha256_hex", "sender_fulls_base",
  "sender_fulls_empty_transfer", "sender_fulls_max_transfer", "sender_fulls_reqid_cache", "sender_fulls_resume",
  "sender_fulls_retry_budget", "sender_fulls_session_gen", "session_gen_max_per_transfer",
  "terminal_row_logical_bytes",
]);
const VERSION_CATALOG_KEYS = new Set([
  "accepted_control_selected_values", "accepted_freeze_docs_untouched", "accepted_ncl1_type_values",
  "accepted_u5_u6_selected_exact", "accepted_wire_changed", "default_policy",
  "docs_25_26_current_selected_exact_2", "docs_25_26_refreeze_forbidden_in_this_candidate",
  "hello_body_bytes", "mf_o01_false_close_forbidden", "mf_o01_status", "mf_o09_status", "mfdt_admission_requires",
  "mfdt_accept_body_bytes", "mfdt_accept_digest_preimage", "mfdt_accept_type", "mfdt_base_control_versions",
  "mfdt_candidate_contiguous_minimal_after_accepted", "mfdt_candidate_type_count",
  "mfdt_candidate_type_values", "mfdt_does_not_claim_selected_3_includes_u5_u6", "mfdt_message_types", "mfdt_negotiation_domain",
  "mfdt_negotiation_independent_of_selected_control_version", "mixed_version_fail_closed",
  "mfdt_negotiation_version", "mfdt_offer_body_bytes", "mfdt_offer_digest_preimage", "mfdt_offer_type", "mfdt_transfer_type_count",
  "obsolete_selected_3_inheritance_table", "private_admission_without_policy", "revision1_revision2_interop", "silent_ge2_forbidden",
  "selected_control_version_3", "target_promotion_off", "target_promotion_on", "u5_u6_wire_body",
  "void_old_proposed_type_values",
]);

class GateError extends Error {}
const fail = (m) => { throw new GateError(m); };
const sha = (v) => crypto.createHash("sha256").update(v).digest();
const shaHex = (v) => sha(v).toString("hex");
const equal = (a, b) => a.length === b.length && crypto.timingSafeEqual(a, b);

function crc32c(value) {
  let crc = 0xffffffff;
  for (const octet of value) {
    crc = (crc ^ octet) >>> 0;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = ((crc >>> 1) ^ ((crc & 1) !== 0 ? 0x82f63b78 : 0)) >>> 0;
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function hx(value, field) {
  if (typeof value !== "string" || value.length % 2 !== 0 || value !== value.toLowerCase() || !/^[0-9a-f]*$/.test(value)) {
    fail(`${field}: non-canonical hex`);
  }
  return Buffer.from(value, "hex");
}
const u16 = (b, o) => b.readUInt16BE(o);
const u32 = (b, o) => b.readUInt32BE(o);
const u64 = (b, o) => b.readBigUInt64BE(o);

function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((x) => stableStringify(x)).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(",")}}`;
}

function familyOf(id) {
  if (id.startsWith("MF-POS-")) return "positive";
  if (id.startsWith("MF-NEG-")) return "negative";
  if (id.startsWith("MF-CU-")) return "commit_unknown";
  if (id.startsWith("MF-TX-")) return "transcript";
  if (id.startsWith("MF-BUDGET-")) return "budget";
  if (id.startsWith("MF-FSM-") || id.startsWith("MF-TRACE-")) return "catalog";
  return "catalog";
}

function authorityMaterial(entry) {
  const material = { id: entry.id, family: familyOf(entry.id), expected: entry.expected };
  if (entry.fixture) material.fixture = entry.fixture;
  if (entry.old_rows) {
    material.commit_unknown = {
      group: entry.group,
      old_rows: entry.old_rows,
      new_rows: entry.new_rows,
      observed_rows: entry.observed_rows,
    };
  }
  const skip = new Set(["id", "expected", "fixture", "old_rows", "new_rows", "observed_rows", "authority_fingerprint_hex", "family"]);
  for (const key of Object.keys(entry).sort()) {
    if (!skip.has(key)) material[key] = entry[key];
  }
  return material;
}
const authorityFingerprint = (entry) => shaHex(Buffer.from(stableStringify(authorityMaterial(entry)), "utf8"));
const deepClone = (v) => JSON.parse(JSON.stringify(v));
const deepEqual = (a, b) => stableStringify(a) === stableStringify(b);

/** Decode a JSON string token into the actual key/value string (Unicode escapes applied). */
function decodeJsonStringContent(body) {
  let out = "";
  for (let i = 0; i < body.length; ) {
    const c = body[i];
    if (c !== "\\") {
      out += c;
      i += 1;
      continue;
    }
    i += 1;
    if (i >= body.length) fail("escape eof");
    const e = body[i++];
    if (e === '"' || e === "\\" || e === "/") out += e;
    else if (e === "b") out += "\b";
    else if (e === "f") out += "\f";
    else if (e === "n") out += "\n";
    else if (e === "r") out += "\r";
    else if (e === "t") out += "\t";
    else if (e === "u") {
      if (i + 4 > body.length) fail("unicode eof");
      const hex = body.slice(i, i + 4);
      if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail(`unicode hex: ${hex}`);
      out += String.fromCharCode(parseInt(hex, 16));
      i += 4;
    } else fail(`bad escape: \\${e}`);
  }
  return out;
}

/** Strict JSON: duplicate keys on decoded strings, no NaN/Infinity, canonical ints only. */
function loadStrictJson(raw) {
  const text = Buffer.isBuffer(raw) ? raw.toString("utf8") : raw;
  if (/\bNaN\b|\bInfinity\b|\b-Infinity\b/.test(text)) fail("json constant forbidden");
  // Canonical numeric grammar + duplicate-key scan on decoded key strings first.
  detectDuplicateKeysAndNumbers(text);
  let parsed;
  try {
    parsed = JSON.parse(text, (key, value) => {
      if (typeof value === "number") {
        if (!Number.isFinite(value)) fail("non-finite number");
        if (!Number.isInteger(value)) fail(`non-integer json number forbidden: ${value}`);
        if (!Number.isSafeInteger(value)) fail(`unsafe integer: ${value}`);
      }
      return value;
    });
  } catch (e) {
    if (e instanceof GateError) throw e;
    fail(`json decode: ${e.message}`);
  }
  return parsed;
}

function detectDuplicateKeysAndNumbers(text) {
  // Stack-based scan: object keys compared as *decoded* JSON strings so that
  // "status" and "\u0073tatus" collide; numbers must be canonical safe integers.
  let i = 0;
  const n = text.length;
  const skipWs = () => { while (i < n && /\s/.test(text[i])) i += 1; };
  const parseString = () => {
    if (text[i] !== '"') fail("json string");
    i += 1;
    let rawBody = "";
    while (i < n) {
      const c = text[i];
      if (c === '"') {
        i += 1;
        return decodeJsonStringContent(rawBody);
      }
      if (c === "\\") {
        rawBody += text[i];
        i += 1;
        if (i >= n) fail("escape eof");
        // Keep escape body (including \uXXXX) for decodeJsonStringContent.
        if (text[i] === "u") {
          rawBody += text.slice(i, i + 5);
          i += 5;
        } else {
          rawBody += text[i];
          i += 1;
        }
        continue;
      }
      if (c.charCodeAt(0) < 0x20) fail("control char in string");
      rawBody += c;
      i += 1;
    }
    fail("unterminated string");
  };
  const parseValue = () => {
    skipWs();
    if (i >= n) fail("eof");
    const c = text[i];
    if (c === "{") {
      i += 1;
      const keys = new Set();
      skipWs();
      if (text[i] === "}") { i += 1; return; }
      while (i < n) {
        skipWs();
        const key = parseString(); // decoded key string
        if (keys.has(key)) fail(`duplicate json key: ${key}`);
        keys.add(key);
        skipWs();
        if (text[i] !== ":") fail("expected :");
        i += 1;
        parseValue();
        skipWs();
        if (text[i] === ",") { i += 1; continue; }
        if (text[i] === "}") { i += 1; return; }
        fail("object");
      }
    } else if (c === "[") {
      i += 1;
      skipWs();
      if (text[i] === "]") { i += 1; return; }
      while (i < n) {
        parseValue();
        skipWs();
        if (text[i] === ",") { i += 1; continue; }
        if (text[i] === "]") { i += 1; return; }
        fail("array");
      }
    } else if (c === '"') {
      parseString();
    } else if (c === "t" || c === "f" || c === "n") {
      if (text.startsWith("true", i)) i += 4;
      else if (text.startsWith("false", i)) i += 5;
      else if (text.startsWith("null", i)) i += 4;
      else fail("literal");
    } else if (c === "-" || (c >= "0" && c <= "9")) {
      const start = i;
      if (text[i] === "-") i += 1;
      if (i >= n || text[i] < "0" || text[i] > "9") fail(`noncanonical numeric token near ${start}`);
      if (text[i] === "0") {
        i += 1;
        if (i < n && text[i] >= "0" && text[i] <= "9") fail(`leading-zero numeric token: ${text.slice(start, i + 1)}`);
      } else {
        while (i < n && text[i] >= "0" && text[i] <= "9") i += 1;
      }
      if (i < n && (text[i] === "." || text[i] === "e" || text[i] === "E" || text[i] === "+")) {
        fail(`non-integer json number forbidden: ${text.slice(start, i + 8)}`);
      }
      const token = text.slice(start, i);
      if (token === "-0" || token === "+0" || token.startsWith("+")) fail(`noncanonical numeric token: ${token}`);
      // BigInt path so unsafe integers are detected before Number coercion.
      let asBig;
      try { asBig = BigInt(token); } catch { fail(`noncanonical numeric token: ${token}`); }
      if (asBig > BigInt(JSON_SAFE_INT_MAX) || asBig < -BigInt(JSON_SAFE_INT_MAX)) {
        fail(`unsafe integer: ${token}`);
      }
    } else fail(`unexpected ${c}`);
  };
  parseValue();
  skipWs();
  if (i !== n) fail("json trailing");
}

function assertExactKeys(obj, allowed, path) {
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) fail(`${path}: expected object`);
  const keys = Object.keys(obj);
  for (const k of keys) if (!allowed.has(k)) fail(`${path}: unknown keys ${k}`);
  for (const k of allowed) if (!(k in obj)) fail(`${path}: missing keys ${k}`);
}

function assertType(value, kind, path) {
  if (kind === "str") {
    if (typeof value !== "string") fail(`${path}: expected string, got ${typeof value}`);
    return;
  }
  if (kind === "bool") {
    if (typeof value !== "boolean") fail(`${path}: expected bool, got ${typeof value}`);
    return;
  }
  if (kind === "int") {
    if (typeof value !== "number" || !Number.isInteger(value) || !Number.isSafeInteger(value)) {
      fail(`${path}: expected int, got ${typeof value}`);
    }
    return;
  }
  if (kind === "list") {
    if (!Array.isArray(value)) fail(`${path}: expected array, got ${typeof value}`);
    return;
  }
  if (kind === "dict") {
    if (value === null || typeof value !== "object" || Array.isArray(value)) fail(`${path}: expected object`);
    return;
  }
  fail(`${path}: unknown type kind ${kind}`);
}

function assertStrList(value, path) {
  assertType(value, "list", path);
  value.forEach((item, index) => assertType(item, "str", `${path}[${index}]`));
}

function assertIntMap(value, path, keys = null) {
  assertType(value, "dict", path);
  if (keys) assertExactKeys(value, keys, path);
  for (const [k, v] of Object.entries(value)) assertType(v, "int", `${path}.${k}`);
}

function assertExpectedObject(value, path, requiredKeys = null) {
  assertType(value, "dict", path);
  if (requiredKeys) assertExactKeys(value, requiredKeys, path);
  for (const [k, item] of Object.entries(value)) {
    if (typeof item === "boolean") continue;
    if (typeof item === "number") {
      if (!Number.isInteger(item) || !Number.isSafeInteger(item)) fail(`${path}.${k}: unsafe/non-int`);
      continue;
    }
    if (typeof item === "string") continue;
    if (Array.isArray(item)) {
      item.forEach((elem, index) => {
        if (typeof elem === "string") return;
        if (typeof elem === "number" && Number.isInteger(elem) && Number.isSafeInteger(elem)) return;
        fail(`${path}.${k}[${index}]: expected int|str`);
      });
      continue;
    }
    fail(`${path}.${k}: expected int|str|bool|list, got ${typeof item}`);
  }
}

function validateCuRows(rows, path) {
  assertType(rows, "list", path);
  rows.forEach((row, index) => {
    const rpath = `${path}[${index}]`;
    assertExactKeys(row, CU_ROW_KEYS, rpath);
    assertType(row.key_hex, "str", `${rpath}.key_hex`);
    assertType(row.value_hex, "str", `${rpath}.value_hex`);
  });
}

function validateFixtureClosed(fixture, path) {
  assertExactKeys(fixture, FIXTURE_KEYS, path);
  for (const key of [
    "acceptance_record_digest_hex", "content_hex", "content_sha256_hex", "finalize_hex", "manifest_digest_hex",
    "nm30_key_hex", "nm30_value_hex", "open_accept_hex", "open_body_hex", "publication_token_hex",
    "receiver_content_verified_key_hex", "receiver_content_verified_sha256_hex", "receiver_content_verified_value_hex",
    "tombstone_digest_hex", "transfer_accept_hex",
  ]) assertType(fixture[key], "str", `${path}.${key}`);
  for (const key of [
    "finalize_length", "full_chunk_bitmap", "full_page_bitmap", "open_accept_length",
    "reservation_not_after_ms", "transfer_accept_length",
  ]) assertType(fixture[key], "int", `${path}.${key}`);
  assertStrList(fixture.entries_hex, `${path}.entries_hex`);
  assertExactKeys(fixture.facts, FIXTURE_FACTS_KEYS, `${path}.facts`);
  for (const key of [
    "application_binding_length", "application_binding_offset", "application_generation", "chunk_count", "chunk_size",
    "evidence_grace_ms", "manifest_page_count", "manifest_revision", "open_body_length", "required_evidence",
    "service_family", "service_schema_major", "service_schema_minor", "target_ordinal", "text_offset", "total_length",
  ]) {
    assertType(fixture.facts[key], "int", `${path}.facts.${key}`);
  }
  for (const key of ["application_binding_hex", "manifest_digest_hex", "namespace", "schema", "service", "whole_content_sha256_hex"]) {
    assertType(fixture.facts[key], "str", `${path}.facts.${key}`);
  }
  assertExactKeys(fixture.ids, FIXTURE_IDS_KEYS, `${path}.ids`);
  for (const key of FIXTURE_IDS_KEYS) assertType(fixture.ids[key], "str", `${path}.ids.${key}`);
  assertType(fixture.pages, "list", `${path}.pages`);
  fixture.pages.forEach((page, index) => {
    const ppath = `${path}.pages[${index}]`;
    assertExactKeys(page, PAGE_META_KEYS, ppath);
    assertType(page.body_hex, "str", `${ppath}.body_hex`);
    assertType(page.page_digest_hex, "str", `${ppath}.page_digest_hex`);
    for (const key of ["body_length", "entry_count", "first_chunk_index", "page_count", "page_index"]) {
      assertType(page[key], "int", `${ppath}.${key}`);
    }
  });
  assertType(fixture.chunks, "list", `${path}.chunks`);
  fixture.chunks.forEach((chunk, index) => {
    const cpath = `${path}.chunks[${index}]`;
    assertExactKeys(chunk, CHUNK_META_KEYS, cpath);
    for (const key of ["body_hex", "chunk_bytes_hex", "chunk_sha256_hex"]) assertType(chunk[key], "str", `${cpath}.${key}`);
    for (const key of ["body_length", "chunk_count", "chunk_index", "chunk_length", "chunk_offset"]) {
      assertType(chunk[key], "int", `${cpath}.${key}`);
    }
  });
  assertType(fixture.page_accepts, "list", `${path}.page_accepts`);
  fixture.page_accepts.forEach((acc, index) => {
    const apath = `${path}.page_accepts[${index}]`;
    assertExactKeys(acc, PAGE_ACCEPT_KEYS, apath);
    assertType(acc.body_hex, "str", `${apath}.body_hex`);
    for (const key of ["body_length", "manifest_complete", "page_index"]) assertType(acc[key], "int", `${apath}.${key}`);
  });
  assertType(fixture.chunk_accepts, "list", `${path}.chunk_accepts`);
  fixture.chunk_accepts.forEach((acc, index) => {
    const apath = `${path}.chunk_accepts[${index}]`;
    assertExactKeys(acc, CHUNK_ACCEPT_KEYS, apath);
    assertType(acc.body_hex, "str", `${apath}.body_hex`);
    for (const key of ["body_length", "chunk_index"]) assertType(acc[key], "int", `${apath}.${key}`);
  });
}

function validateClosedSchema(document) {
  assertType(document, "dict", "$");
  assertExactKeys(document, DOCUMENT_TOP_LEVEL_KEYS, "$");
  for (const key of ["schema", "status", "adr", "title", "authority_map_sha256_hex"]) {
    assertType(document[key], "str", `$.${key}`);
  }
  assertStrList(document.nonclaims, "$.nonclaims");
  assertStrList(document.required_vector_ids, "$.required_vector_ids");
  assertStrList(document.required_gate_cases, "$.required_gate_cases");
  assertStrList(document.sources, "$.sources");
  assertType(document.source_sha256_hex, "dict", "$.source_sha256_hex");
  assertExactKeys(document.source_sha256_hex, new Set(PINNED_SOURCES), "$.source_sha256_hex");
  for (const rel of PINNED_SOURCES) {
    assertType(document.source_sha256_hex[rel], "str", `$.source_sha256_hex.${rel}`);
  }

  const constants = document.constants;
  assertExactKeys(constants, CONSTANTS_KEYS, "$.constants");
  for (const key of [
    "abort_generation_max", "active_header_bytes", "active_header_session_generation_offset", "active_record_schema",
    "active_value_max", "application_binding_bytes", "chunk_size", "entries_per_page", "esp_active_transfers_max", "host_active_transfers_max",
    "host_control_arena_bytes", "host_control_nm30_scratch_bytes", "host_control_nrc1_scratch_bytes",
    "host_control_outbox_bytes", "host_control_outbox_metadata_bytes",
    "host_control_recovery_reserved_bytes", "host_control_route_sentinel",
    "host_coordinator_bytes", "host_fair_selection_bound", "host_owner_full_transactions_max",
    "host_owner_workspace_bytes", "host_peer_unpaid_chunk_offer_max", "host_scheduler_next_slot_initial",
    "host_scheduler_scan_bound", "host_slot_count", "host_terminal_catalog_bytes",
    "host_terminal_catalog_entries", "host_terminal_catalog_entry_bytes",
    "manifest_entry_bytes", "mfdt_admission_profile_revision", "max_chunk_count",
    "max_content_bytes", "max_manifest_pages", "ncl1_body_max", "nm30_expired_reason_terminal_only",
    "nm30_crc_offset", "nm30_crc_preimage_bytes", "nm30_legacy_schema1_value_bytes",
    "nm30_owner_role_offset", "nm30_peer_endpoint_id_bytes", "nm30_peer_endpoint_id_offset",
    "nm30_reserved_bytes", "nm30_reserved_offset", "nm30_schema", "nm30_value_bytes",
    "nrc1_capacity_spare", "nrc1_happy_path_max_ids",
    "nrc1_illegal_two_gen_no_reclaim", "nrc1_logical_bytes", "nrc1_n_abort", "nrc1_n_complete",
    "nrc1_naive_union_ids_rejected_as_single_path", "nrc1_occupied_response_length_max",
    "nrc1_occupied_response_length_min", "nrc1_reachable_max_ids",
    "nrc1_header_session_generation_offset", "nrc1_session_gen_max_per_transfer",
    "nrc1_slot_bytes", "nrc1_slot_count",
    "nrc1_slot_session_generation_offset", "nrc1_value_bytes", "nts3_current_schema_major",
    "nts3_current_schema_minor", "nts3_future_schema_minor", "open_base_fixed_bytes", "open_body_max", "open_body_min",
    "open_fixed_bytes", "open_growth_bytes_redistributed_within_each_slot", "open_text_offset",
    "reservation_lifetime_ms", "resume_query_max", "retention_ms",
    "retry_budget_header_offset", "retry_budget_initial", "retry_budget_remaining_max",
    "retry_budget_remaining_min", "storage_key_bytes", "timeout_retry_max", "workspace_bytes", "workspace_growth_bytes",
  ]) assertType(constants[key], "int", `$.constants.${key}`);
  for (const key of [
    "manifest_digest_preimage", "manifest_entry_layout", "nrc1_slot_lookup_identity",
    "request_body_digest_preimage", "reservation_add_overflow_threshold_u64_hex",
    "no_deadline_u64_hex", "finite_downlink_deadline_min_u64_hex", "finite_downlink_deadline_max_u64_hex",
    "uplink_eventfact_deadline_shape", "finite_downlink_deadline_shape", "original_application_open_deadline_mapping",
    "retry_budget_decrement_event", "retry_budget_owner", "retry_budget_scope",
    "public_callback_context_id", "publication_token_scope", "sha256_empty_hex",
    "terminal_session_generation_authority", "workspace_scope",
  ]) assertType(constants[key], "str", `$.constants.${key}`);
  for (const key of [
    "active_schema1_replay_eligible", "different_epoch_numeric_deadline_compare_forbidden", "nm30_legacy_schema1_replay_eligible",
    "nm30_session_cookie_durable", "nrc1_empty_slot_all_zero",
    "nrc1_resume_reclaim_on_session_gen_advance",
    "restart_requires_full_semantic_validation_before_install", "retention_requires_same_trusted_epoch",
  ]) assertType(constants[key], "bool", `$.constants.${key}`);
  assertType(constants.digest_domains, "dict", "$.constants.digest_domains");
  for (const [k, v] of Object.entries(constants.digest_domains)) assertType(v, "str", `$.constants.digest_domains.${k}`);
  assertIntMap(constants.message_types, "$.constants.message_types");
  assertIntMap(constants.nm30_terminal_reasons, "$.constants.nm30_terminal_reasons");
  assertIntMap(constants.nm30_terminal_states, "$.constants.nm30_terminal_states");
  assertIntMap(constants.reject_codes, "$.constants.reject_codes");
  assertIntMap(constants.stages, "$.constants.stages");
  assertIntMap(constants.wire_abort_reasons, "$.constants.wire_abort_reasons");
  assertStrList(constants.storage_kinds, "$.constants.storage_kinds");
  assertStrList(constants.nts3_future_fields, "$.constants.nts3_future_fields");
  assertType(constants.application_binding_layout, "list", "$.constants.application_binding_layout");
  constants.application_binding_layout.forEach((field, index) => {
    const p = `$.constants.application_binding_layout[${index}]`;
    assertExactKeys(field, new Set(["field", "offset", "bytes"]), p);
    assertType(field.field, "str", `${p}.field`);
    assertType(field.offset, "int", `${p}.offset`);
    assertType(field.bytes, "int", `${p}.bytes`);
  });

  const catalog = document.version_catalog;
  assertExactKeys(catalog, VERSION_CATALOG_KEYS, "$.version_catalog");
  for (const key of [
    "default_policy", "mf_o01_status", "mf_o09_status", "mfdt_message_types", "mfdt_accept_digest_preimage",
    "mfdt_negotiation_domain", "mfdt_offer_digest_preimage",
    "obsolete_selected_3_inheritance_table", "private_admission_without_policy", "revision1_revision2_interop",
    "selected_control_version_3", "target_promotion_off", "target_promotion_on", "u5_u6_wire_body",
  ]) {
    assertType(catalog[key], "str", `$.version_catalog.${key}`);
  }
  for (const key of [
    "docs_25_26_current_selected_exact_2", "docs_25_26_refreeze_forbidden_in_this_candidate",
    "accepted_wire_changed", "mfdt_candidate_contiguous_minimal_after_accepted",
    "mf_o01_false_close_forbidden", "mfdt_does_not_claim_selected_3_includes_u5_u6",
    "mfdt_negotiation_independent_of_selected_control_version",
    "mixed_version_fail_closed", "silent_ge2_forbidden",
  ]) assertType(catalog[key], "bool", `$.version_catalog.${key}`);
  for (const key of [
    "accepted_u5_u6_selected_exact", "hello_body_bytes", "mfdt_accept_body_bytes",
    "mfdt_accept_type", "mfdt_negotiation_version", "mfdt_offer_body_bytes", "mfdt_offer_type",
    "mfdt_candidate_type_count", "mfdt_transfer_type_count",
  ]) {
    assertType(catalog[key], "int", `$.version_catalog.${key}`);
  }
  assertStrList(catalog.accepted_freeze_docs_untouched, "$.version_catalog.accepted_freeze_docs_untouched");
  assertStrList(catalog.mfdt_admission_requires, "$.version_catalog.mfdt_admission_requires");
  for (const key of [
    "accepted_control_selected_values", "accepted_ncl1_type_values", "mfdt_base_control_versions",
    "mfdt_candidate_type_values", "void_old_proposed_type_values",
  ]) {
    if (!Array.isArray(catalog[key])) fail(`$.version_catalog.${key}: expected list`);
    catalog[key].forEach((item, index) => assertType(item, "int", `$.version_catalog.${key}[${index}]`));
  }
  if (catalog.mf_o01_status !== "SPEC_ACCEPTED_GREEN_BASELINE_HISTORY" || catalog.mf_o09_status !== "SPEC_ACCEPTED_CLOSED") {
    fail("MFDT baseline/amendment accepted status");
  }
  if (stableStringify(catalog.mfdt_base_control_versions) !== "[1,2]") fail("MFDT base versions");
  if (catalog.mfdt_negotiation_version !== 2 || catalog.mfdt_offer_type !== 0x34 ||
      catalog.mfdt_accept_type !== 0x35 || catalog.mfdt_offer_body_bytes !== 112 ||
      catalog.mfdt_accept_body_bytes !== 160) fail("MFN1 catalog/layout pin");
  if (catalog.mfdt_negotiation_domain !== "private_mfdt_admission_v2" ||
      catalog.revision1_revision2_interop !== "REJECT_MUTATION_ZERO") fail("MFN1 revision-2 fail closed");
  if (!deepEqual(catalog.accepted_control_selected_values, [1, 2]) ||
      catalog.selected_control_version_3 !== "REJECT" ||
      !deepEqual(catalog.mfdt_candidate_type_values, Array.from({length: 16}, (_, i) => 0x34 + i)) ||
      catalog.mfdt_candidate_type_count !== 16 || catalog.mfdt_transfer_type_count !== 14 ||
      catalog.target_promotion_on !== "UNALLOCATED_UNSUPPORTED" ||
      catalog.accepted_wire_changed !== false) fail("MFDT candidate allocation/promotion contract");
  if (catalog.mfdt_negotiation_independent_of_selected_control_version !== true) fail("MFDT independent");
  if (catalog.accepted_u5_u6_selected_exact !== 2) fail("Accepted U5/U6 selected exact 2");

  const carriers = document.carrier_mapping;
  assertExactKeys(carriers, new Set([
    "compact_rf_nrw1", "generic_fabric_control_plane", "ncg1_ncl1", "nfl1_application_packet", "wifi_nwb1",
  ]), "$.carrier_mapping");
  for (const [name, obj] of Object.entries(carriers)) {
    assertType(obj, "dict", `$.carrier_mapping.${name}`);
    if (!("status" in obj)) fail(`$.carrier_mapping.${name}: missing status`);
    assertType(obj.status, "str", `$.carrier_mapping.${name}.status`);
    for (const [k, item] of Object.entries(obj)) {
      if (typeof item !== "string" && typeof item !== "boolean" &&
          !(typeof item === "number" && Number.isInteger(item))) {
        fail(`$.carrier_mapping.${name}.${k}: unsupported primitive type`);
      }
    }
  }

  const pub = document.publication_owner;
  assertExactKeys(pub, new Set([
    "forbidden_prepare_callers", "sole_application_effect_owner", "sole_prepare_caller", "sole_publication_token_owner",
  ]), "$.publication_owner");
  assertStrList(pub.forbidden_prepare_callers, "$.publication_owner.forbidden_prepare_callers");
  for (const key of ["sole_application_effect_owner", "sole_prepare_caller", "sole_publication_token_owner"]) {
    assertType(pub[key], "str", `$.publication_owner.${key}`);
  }

  const roles = document.role_boundaries;
  assertExactKeys(roles, new Set(["controller", "receiver", "relay_neutral_bearer", "sender"]), "$.role_boundaries");
  assertExactKeys(roles.controller, new Set(["assignment_only", "multi_frame_messages"]), "$.role_boundaries.controller");
  assertType(roles.controller.assignment_only, "bool", "$.role_boundaries.controller.assignment_only");
  assertType(roles.controller.multi_frame_messages, "bool", "$.role_boundaries.controller.multi_frame_messages");
  assertExactKeys(roles.receiver, new Set(["may_partial_apply", "may_publish", "responsibility_ends_on"]), "$.role_boundaries.receiver");
  assertType(roles.receiver.may_partial_apply, "bool", "$.role_boundaries.receiver.may_partial_apply");
  assertType(roles.receiver.may_publish, "bool", "$.role_boundaries.receiver.may_publish");
  assertStrList(roles.receiver.responsibility_ends_on, "$.role_boundaries.receiver.responsibility_ends_on");
  assertExactKeys(roles.relay_neutral_bearer, new Set(["completion_authority", "custody_authority"]), "$.role_boundaries.relay_neutral_bearer");
  assertType(roles.relay_neutral_bearer.completion_authority, "bool", "$.role_boundaries.relay_neutral_bearer.completion_authority");
  assertType(roles.relay_neutral_bearer.custody_authority, "bool", "$.role_boundaries.relay_neutral_bearer.custody_authority");
  assertExactKeys(roles.sender, new Set([
    "may_claim_complete_before_accept_full", "may_publish", "may_release_on_chunk_accept_only",
  ]), "$.role_boundaries.sender");
  for (const key of ["may_claim_complete_before_accept_full", "may_publish", "may_release_on_chunk_accept_only"]) {
    assertType(roles.sender[key], "bool", `$.role_boundaries.sender.${key}`);
  }

  const api = document.private_api;
  assertExactKeys(api, new Set([
    "active_record_schema", "active_schema1_replay_eligible", "borrow_until_full", "copy_owned_after_full",
    "default_off", "heap_growth", "host_coordinator_bytes",
    "host_control_arena_bytes", "host_control_outbox_backpressure", "host_control_outbox_bytes",
    "host_control_outbox_count", "host_control_route_sentinel",
    "host_control_traffic_advances_scheduler", "host_fair_selection_bound", "host_fifth_active",
    "host_full_transaction_parallelism",
    "host_owner_workspace_bytes", "host_peer_unpaid_chunk_offer_max", "host_restart_slot_allocation",
    "host_scheduler", "host_schema1_terminal_replay_eligible", "host_slot_allocation",
    "host_slot_count", "host_terminal_catalog_entries", "host_terminal_catalog_entry_bytes",
    "host_terminal_catalog_rebind", "host_terminal_route_without_active_slot",
    "host_transfer_route_key",
    "open_growth_bytes_redistributed_within_each_slot", "operations", "prefix", "public_abi",
    "workspace_bytes", "workspace_growth_bytes", "workspace_scope",
  ]), "$.private_api");
  for (const key of [
    "active_schema1_replay_eligible", "borrow_until_full", "copy_owned_after_full", "default_off", "heap_growth",
    "host_control_traffic_advances_scheduler", "host_schema1_terminal_replay_eligible",
    "host_terminal_route_without_active_slot", "public_abi",
  ]) {
    assertType(api[key], "bool", `$.private_api.${key}`);
  }
  for (const key of [
    "prefix", "workspace_scope", "host_fifth_active", "host_restart_slot_allocation",
    "host_scheduler", "host_slot_allocation", "host_terminal_catalog_rebind",
    "host_transfer_route_key", "host_control_outbox_backpressure",
  ]) assertType(api[key], "str", `$.private_api.${key}`);
  for (const key of [
    "active_record_schema", "workspace_bytes", "workspace_growth_bytes",
    "open_growth_bytes_redistributed_within_each_slot", "host_coordinator_bytes", "host_control_arena_bytes",
    "host_control_outbox_bytes", "host_control_outbox_count", "host_control_route_sentinel",
    "host_fair_selection_bound",
    "host_full_transaction_parallelism", "host_owner_workspace_bytes",
    "host_peer_unpaid_chunk_offer_max", "host_slot_count", "host_terminal_catalog_entries",
    "host_terminal_catalog_entry_bytes",
  ]) assertType(api[key], "int", `$.private_api.${key}`);
  assertStrList(api.operations, "$.private_api.operations");

  const budget = document.budget;
  assertExactKeys(budget, BUDGET_KEYS, "$.budget");
  for (const key of BUDGET_KEYS) {
    if (key === "groups" || key === "restoration_object") assertType(budget[key], "dict", `$.budget.${key}`);
    else if (key === "obsolete_80_feasible_for_reference_receiver" || key === "nrc1_retained_until_gc") assertType(budget[key], "bool", `$.budget.${key}`);
    else if (key === "restoration_sha256_hex") assertType(budget[key], "str", `$.budget.${key}`);
    else assertType(budget[key], "int", `$.budget.${key}`);
  }
  assertExactKeys(budget.groups, new Set(["empty_receiver", "empty_sender", "receiver", "sender"]), "$.budget.groups");
  for (const [name, obj] of Object.entries(budget.groups)) assertIntMap(obj, `$.budget.groups.${name}`);
  const rest = budget.restoration_object;
  assertExactKeys(rest, new Set([
    "obsolete_fulls_day", "obsolete_infeasible", "receiver_fulls_max", "receiver_groups", "reference_transfers_day",
    "required_receiver_fulls_reference", "required_sender_fulls_reference", "sender_fulls_max", "sender_groups",
  ]), "$.budget.restoration_object");
  assertType(rest.obsolete_infeasible, "bool", "$.budget.restoration_object.obsolete_infeasible");
  for (const key of [
    "obsolete_fulls_day", "receiver_fulls_max", "reference_transfers_day", "required_receiver_fulls_reference",
    "required_sender_fulls_reference", "sender_fulls_max",
  ]) assertType(rest[key], "int", `$.budget.restoration_object.${key}`);
  assertIntMap(rest.receiver_groups, "$.budget.restoration_object.receiver_groups");
  assertIntMap(rest.sender_groups, "$.budget.restoration_object.sender_groups");

  const index = document.authority_index;
  assertType(index, "dict", "$.authority_index");
  for (const [vid, row] of Object.entries(index)) {
    const rpath = `$.authority_index.${vid}`;
    assertExactKeys(row, AUTHORITY_INDEX_ROW_KEYS, rpath);
    assertType(row.family, "str", `${rpath}.family`);
    assertType(row.authority_fingerprint_hex, "str", `${rpath}.authority_fingerprint_hex`);
    const expectedKeys = AUTHORITY[vid] ? new Set(Object.keys(AUTHORITY[vid].expected)) : null;
    assertExpectedObject(row.expected, `${rpath}.expected`, expectedKeys);
  }

  assertType(document.vectors, "list", "$.vectors");
  document.vectors.forEach((entry, indexI) => {
    const path = `$.vectors[${indexI}]`;
    assertType(entry, "dict", path);
    for (const k of VECTOR_COMMON_REQUIRED) if (!(k in entry)) fail(`${path}: missing common key ${k}`);
    assertType(entry.id, "str", `${path}.id`);
    assertType(entry.family, "str", `${path}.family`);
    assertType(entry.authority_fingerprint_hex, "str", `${path}.authority_fingerprint_hex`);
    const optional = VECTOR_OPTIONAL_BY_FAMILY[entry.family];
    if (!optional) fail(`${path}: unknown family ${entry.family}`);
    for (const k of Object.keys(entry)) {
      if (!VECTOR_COMMON_REQUIRED.has(k) && !optional.has(k)) fail(`${path}: unknown keys ${k}`);
    }
    const expectedKeys = AUTHORITY[entry.id] ? new Set(Object.keys(AUTHORITY[entry.id].expected)) : null;
    assertExpectedObject(entry.expected, `${path}.expected`, expectedKeys);
    if (entry.fixture) validateFixtureClosed(entry.fixture, `${path}.fixture`);
    if (entry.family === "commit_unknown") {
      for (const req of ["group", "old_rows", "new_rows", "observed_rows"]) {
        if (!(req in entry)) fail(`${path}: missing ${req}`);
      }
      assertType(entry.group, "str", `${path}.group`);
      validateCuRows(entry.old_rows, `${path}.old_rows`);
      validateCuRows(entry.new_rows, `${path}.new_rows`);
      validateCuRows(entry.observed_rows, `${path}.observed_rows`);
    }
    if (entry.family === "transcript") {
      if (entry.transcript) assertStrList(entry.transcript, `${path}.transcript`);
      if (entry.steps) assertStrList(entry.steps, `${path}.steps`);
      if (entry.fixture_ids) {
        assertType(entry.fixture_ids, "dict", `${path}.fixture_ids`);
        for (const [k, v] of Object.entries(entry.fixture_ids)) assertType(v, "str", `${path}.fixture_ids.${k}`);
      }
      if ("resume_state_hex" in entry) assertType(entry.resume_state_hex, "str", `${path}.resume_state_hex`);
      if ("resume_state_length" in entry) assertType(entry.resume_state_length, "int", `${path}.resume_state_length`);
      for (const key of ["committed_chunk_bitmap", "now_ms", "retention_ms"]) {
        if (key in entry) assertType(entry[key], "int", `${path}.${key}`);
      }
      for (const key of ["last_full_group", "publication_token_hex"]) {
        if (key in entry) assertType(entry[key], "str", `${path}.${key}`);
      }
      for (const key of ["tombstone_present_before", "tombstone_present_after"]) {
        if (key in entry) assertType(entry[key], "bool", `${path}.${key}`);
      }
    }
  });
}

function derive(total) {
  if (total < 0 || total > MAX_CONTENT) fail("total");
  if (total === 0) return [0, 0];
  const chunks = Math.floor((total + CHUNK_SIZE - 1) / CHUNK_SIZE);
  if (chunks > MAX_CHUNKS) fail("chunks");
  return [chunks, Math.floor((chunks + ENTRIES_PER_PAGE - 1) / ENTRIES_PER_PAGE)];
}
function chunkRange(total, index) {
  const offset = CHUNK_SIZE * index;
  const length = Math.min(CHUNK_SIZE, total - offset);
  if (length <= 0) fail("range");
  return [offset, length];
}

function requireValidRecordCrc(value, field) {
  if (value.length < HEADER_BYTES + 4) fail(`${field}: short`);
  const magic = value.subarray(0, 4).toString();
  if (magic !== "NM3R" && magic !== "NM3S") fail(`${field}: magic`);
  if (u32(value, 304) !== crc32c(value.subarray(0, 304))) fail(`${field}: hdr`);
  if (value.readUInt32BE(value.length - 4) !== crc32c(value.subarray(0, value.length - 4))) fail(`${field}: rec`);
}

function requireValidActive(value, field) {
  requireValidRecordCrc(value, field);
  if (u16(value, 4) !== 2 || u16(value, 6) !== HEADER_BYTES) fail(`${field}: active schema/header`);
  if (u32(value, 8) !== value.length) fail(`${field}: active total length`);
  const owner = value[12];
  const magic = value.subarray(0, 4).toString();
  if (!((magic === "NM3S" && owner === 1) || (magic === "NM3R" && owner === 2))) {
    fail(`${field}: active magic/owner`);
  }
  const senderStates = new Set([1, 2, 3, 4, 5, 6, 8, 10]);
  const receiverStates = new Set([32, 33, 34, 35, 36, 37, 38, 40, 41]);
  if (!(owner === 1 ? senderStates : receiverStates).has(value[13])) fail(`${field}: active state closed set`);
  if (!equal(value.subarray(14, 16), Buffer.alloc(2)) ||
      !equal(value.subarray(110, 112), Buffer.alloc(2)) ||
      !equal(value.subarray(230, 232), Buffer.alloc(2)) ||
      !equal(value.subarray(296, 300), Buffer.alloc(4))) fail(`${field}: active reserved`);
  if (equal(value.subarray(16, 32), Buffer.alloc(16)) || u32(value, 32) === 0 ||
      equal(value.subarray(36, 68), Buffer.alloc(32))) fail(`${field}: active bind`);
  if (u64(value, 68) === 0n || value[105] > 8 || u32(value, 300) === 0) fail(`${field}: active generation/budget`);
  if (value[106] !== 1 || value[107] > 2 || value[108] > 1 || value[109] > 1) {
    fail(`${field}: active policy/publication flags`);
  }
  const openLen = u16(value, 84);
  const entryBytes = u16(value, 86);
  const contentLen = u32(value, 88);
  if (openLen < 465 || openLen > 651 ||
      HEADER_BYTES + openLen + entryBytes + contentLen + 4 !== value.length) fail(`${field}: active body geometry`);
  const openBody = value.subarray(HEADER_BYTES, HEADER_BYTES + openLen);
  if (!equal(openBody.subarray(0, 16), value.subarray(16, 32)) ||
      u32(openBody, 16) !== u32(value, 32) ||
      !equal(openBody.subarray(202, 234), value.subarray(36, 68))) fail(`${field}: active embedded OPEN bind`);
  const total = u32(openBody, 20);
  if (total > MAX_CONTENT || contentLen !== total || u16(openBody, 24) !== CHUNK_SIZE) fail(`${field}: active content geometry`);
  const [chunks, pages] = derive(total);
  if (u16(openBody, 26) !== chunks || u16(openBody, 28) !== pages ||
      u16(openBody, 30) !== ENTRIES_PER_PAGE || u16(value, 92) !== chunks ||
      u16(value, 94) !== pages || entryBytes !== chunks * 40) fail(`${field}: active manifest geometry`);
  const lengths = [u16(openBody, 170), u16(openBody, 172), u16(openBody, 174)];
  if (!lengths.every((n) => n >= 1 && n <= 63) ||
      openLen !== 462 + lengths.reduce((a, b) => a + b, 0) ||
      u16(openBody, 176) !== 0) fail(`${field}: active OPEN text/reserved`);
  if (equal(openBody.subarray(234, 250), Buffer.alloc(16)) || u32(openBody, 250) === 0 ||
      equal(openBody.subarray(338, 342), Buffer.alloc(4)) === false ||
      equal(openBody.subarray(426, 430), Buffer.alloc(4)) === false ||
      u16(openBody, 430) === 0 || u32(openBody, 434) === 0 ||
      u32(openBody, 454) === 0 || !equal(openBody.subarray(458, 462), Buffer.alloc(4))) {
    fail(`${field}: active application binding`);
  }
  let derivedTransferId = sha(Buffer.concat([
    openBody.subarray(64, 80), openBody.subarray(112, 128), openBody.subarray(250, 254),
    Buffer.from("ninlil-mfdt-v1id", "ascii"),
  ])).subarray(0, 16);
  if (equal(derivedTransferId, Buffer.alloc(16))) {
    derivedTransferId = Buffer.from(derivedTransferId); derivedTransferId[15] = 1;
  }
  if (!equal(openBody.subarray(0, 16), derivedTransferId)) fail(`${field}: transfer id derivation`);
  const entryStart = HEADER_BYTES + openLen;
  const entryBlob = value.subarray(entryStart, entryStart + entryBytes);
  const manifest = sha(Buffer.concat([
    Buffer.from("NM3-MANIFEST-V1", "ascii"), openBody.subarray(0, 202),
    openBody.subarray(234, 462), openBody.subarray(462), entryBlob,
  ]));
  if (!equal(openBody.subarray(202, 234), manifest)) fail(`${field}: manifest/application binding digest`);
  const family = u32(openBody, 434);
  const originEventZero = equal(openBody.subarray(80, 96), Buffer.alloc(16));
  const generation = u64(openBody, 438);
  const deadlineEpochZero = equal(openBody.subarray(178, 194), Buffer.alloc(16));
  const deadline = u64(openBody, 194);
  const grace = u64(openBody, 446);
  const downlink = family === 2 || family === 5 || family === 6;
  const uplink = family === 1 || family === 3 || family === 4;
  if (!(downlink || uplink) ||
      (family === 1 && (originEventZero || generation !== 0n)) ||
      (family !== 1 && (!originEventZero || generation === 0n)) ||
      (downlink && (deadlineEpochZero || deadline === 0n || deadline === 0xffffffffffffffffn)) ||
      (uplink && (!deadlineEpochZero || deadline !== 0xffffffffffffffffn || grace !== 0n))) {
    fail(`${field}: active family/deadline shape`);
  }
  if (chunks < 64 && (u64(value, 96) >> BigInt(chunks)) !== 0n) fail(`${field}: active chunk bitmap range`);
  if (pages < 8 && (value[104] >> pages) !== 0) fail(`${field}: active page bitmap range`);
  const reservationZero = equal(value.subarray(112, 128), Buffer.alloc(16));
  const reservationEpochZero = equal(value.subarray(128, 144), Buffer.alloc(16));
  const reservationDeadlineZero = u64(value, 144) === 0n;
  if (!((reservationZero && reservationEpochZero && reservationDeadlineZero) ||
        (!reservationZero && !reservationEpochZero && !reservationDeadlineZero))) {
    fail(`${field}: active reservation correlation`);
  }
  const acceptGen = u64(value, 76);
  const evidenceZero = equal(value.subarray(152, 168), Buffer.alloc(16));
  const acceptDigestZero = equal(value.subarray(168, 200), Buffer.alloc(32));
  if ((acceptGen === 0n) !== (evidenceZero && acceptDigestZero)) fail(`${field}: active acceptance evidence correlation`);
  if (equal(value.subarray(200, 216), Buffer.alloc(16)) || u64(value, 216) === 0n) fail(`${field}: active trusted clock sample`);
  const abortGen = u32(value, 224);
  const abortReason = u16(value, 228);
  const actorZero = equal(value.subarray(232, 248), Buffer.alloc(16));
  if (abortGen === 0) {
    if (abortReason !== 0 || !actorZero) fail(`${field}: active abort-zero correlation`);
  } else if (!(abortGen >= 1 && abortGen <= 8 && abortReason >= 1 && abortReason <= 4 && !actorZero)) {
    fail(`${field}: active abort correlation`);
  }
  if (value[107] === 0) {
    if (!equal(value.subarray(248, 264), Buffer.alloc(16)) ||
        !equal(value.subarray(264, 296), Buffer.alloc(32))) fail(`${field}: active unpublished evidence`);
  } else if (equal(value.subarray(248, 264), Buffer.alloc(16))) {
    fail(`${field}: active publication token`);
  }
}

function requireValidNm30(value, field) {
  if (value.length !== NM30_BYTES || value.subarray(0, 4).toString() !== "NM30") fail(`${field}: nm30 framing`);
  if (u16(value, 4) !== 2 || u16(value, 6) !== NM30_BYTES) fail(`${field}: nm30 schema/length`);
  if (u32(value, 176) !== crc32c(value.subarray(0, 176))) fail(`${field}: nm30 crc`);
  if (equal(value.subarray(8, 24), Buffer.alloc(16)) || u32(value, 24) === 0 ||
      equal(value.subarray(28, 60), Buffer.alloc(32)) ||
      equal(value.subarray(132, 148), Buffer.alloc(16)) || u64(value, 148) === 0n ||
      equal(value.subarray(156, 172), Buffer.alloc(16)) ||
      ![1, 2].includes(value[172]) ||
      !equal(value.subarray(173, 176), Buffer.alloc(3))) fail(`${field}: nm30 common semantics`);
  const state = u16(value, 60);
  const reason = u16(value, 62);
  const generation = u32(value, 64);
  const evidenceZero = equal(value.subarray(68, 84), Buffer.alloc(16));
  const digestZero = equal(value.subarray(84, 116), Buffer.alloc(32));
  const actorZero = equal(value.subarray(116, 132), Buffer.alloc(16));
  if (state === 1) {
    if (reason !== 0 || generation !== 0 || !actorZero || evidenceZero || digestZero) fail(`${field}: nm30 COMPLETE`);
  } else if (state === 2) {
    if ([1, 2, 3, 4].includes(reason)) {
      if (!(generation >= 1 && generation <= 8 && !actorZero && evidenceZero && digestZero)) fail(`${field}: nm30 authority ABORTED`);
    } else if (reason === 5) {
      if (generation !== 0 || !actorZero || !evidenceZero || !digestZero) fail(`${field}: nm30 automatic EXPIRED`);
    } else {
      fail(`${field}: nm30 ABORTED reason`);
    }
  } else if (state === 3) {
    if (![0x8001, 0x8002].includes(reason) || generation !== 0 || !actorZero || evidenceZero !== digestZero) {
      fail(`${field}: nm30 CORRUPT`);
    }
  } else {
    fail(`${field}: nm30 terminal state`);
  }
}

function requireValidNm30LegacySchema1(value, field) {
  // Legacy schema-1 validation grants only accounting/retention authority.
  if (value.length !== NM30_LEGACY_SCHEMA1_BYTES ||
      value.subarray(0, 4).toString() !== "NM30") fail(`${field}: legacy nm30 framing`);
  if (u16(value, 4) !== 1 || u16(value, 6) !== NM30_LEGACY_SCHEMA1_BYTES) {
    fail(`${field}: legacy nm30 schema/length`);
  }
  if (u32(value, 160) !== crc32c(value.subarray(0, 160))) fail(`${field}: legacy nm30 crc`);
  if (!equal(value.subarray(156, 160), Buffer.alloc(4))) fail(`${field}: legacy nm30 reserved`);
  if (equal(value.subarray(8, 24), Buffer.alloc(16)) || u32(value, 24) === 0 ||
      equal(value.subarray(28, 60), Buffer.alloc(32)) ||
      equal(value.subarray(132, 148), Buffer.alloc(16)) || u64(value, 148) === 0n) {
    fail(`${field}: legacy nm30 common fields`);
  }
}

function requireValidNrc1(value, field, expectedTransferId = null) {
  if (value.length !== 15020 || value.subarray(0, 4).toString() !== "NRC1") fail(`${field}: NRC1 framing`);
  if (u16(value, 4) !== 1 || u16(value, 6) !== 15020) fail(`${field}: NRC1 schema/length`);
  if (expectedTransferId !== null && !equal(value.subarray(8, 24), expectedTransferId)) fail(`${field}: NRC1 transfer bind`);
  if (equal(value.subarray(8, 24), Buffer.alloc(16)) || u32(value, 24) === 0) fail(`${field}: NRC1 bind/generation`);
  if (u16(value, 28) !== 72 || u16(value, 30) > 72) fail(`${field}: NRC1 counts`);
  if (u32(value, 36) !== crc32c(value.subarray(0, 36)) ||
      u32(value, 15016) !== crc32c(value.subarray(0, 15016))) fail(`${field}: NRC1 CRC`);
  const responseLengths = new Map([
    [0x37, 100], [0x39, 108], [0x3a, 60], [0x3b, 60],
    [0x3d, 88], [0x3f, 108], [0x41, 160], [0x43, 92],
  ]);
  let occupied = 0;
  const currentGeneration = u32(value, 24);
  let anchorGeneration = 0;
  const generations = new Set([currentGeneration]);
  const identities = new Set();
  for (let index = 0; index < 72; index += 1) {
    const off = 40 + index * 208;
    const slot = value.subarray(off, off + 208);
    const requestId = u64(slot, 0);
    if (requestId === 0n) {
      if (!equal(slot, Buffer.alloc(208))) fail(`${field}: NRC1 empty slot ${index} not all-zero`);
      continue;
    }
    occupied += 1;
    const generation = u32(slot, 8);
    const responseType = u16(slot, 44);
    const bodyLen = u16(slot, 46);
    if (generation === 0 ||
        (generation !== currentGeneration &&
         (currentGeneration === 1 || generation !== currentGeneration - 1)) ||
        equal(slot.subarray(12, 44), Buffer.alloc(32))) {
      fail(`${field}: NRC1 occupied slot ${index} generation/digest`);
    }
    generations.add(generation);
    if (generation !== currentGeneration && responseType === 0x3f) {
      fail(`${field}: prior-generation RESUME slot not reclaimed`);
    }
    if (responseType === 0x37 &&
        (anchorGeneration === 0 || generation < anchorGeneration)) {
      anchorGeneration = generation;
    }
    const identity = `${generation}:${requestId.toString()}`;
    if (identities.has(identity)) fail(`${field}: NRC1 duplicate generation/request_id`);
    identities.add(identity);
    if (!responseLengths.has(responseType) || bodyLen !== responseLengths.get(responseType)) {
      fail(`${field}: NRC1 slot ${index} response type/length`);
    }
    if (!equal(slot.subarray(48 + bodyLen), Buffer.alloc(160 - bodyLen))) {
      fail(`${field}: NRC1 slot ${index} trailing bytes`);
    }
  }
  if (occupied !== u16(value, 30) || u32(value, 32) < occupied) fail(`${field}: NRC1 occupied/sequence`);
  if (generations.size > 2) fail(`${field}: NRC1 has more than two transfer generations`);
  if (generations.size === 2) {
    if (anchorGeneration !== currentGeneration - 1) fail(`${field}: NRC1 initial OPEN anchor generation`);
  }
}

function markComplete(vid, entry, executed) {
  const auth = AUTHORITY[vid];
  if (!auth) fail(`no authority ${vid}`);
  if (familyOf(vid) !== auth.family) fail(`${vid}: family`);
  if (!deepEqual(entry.expected, auth.expected)) fail(`${vid}: expected authority`);
  const fp = authorityFingerprint(entry);
  if (fp !== auth.authority_fingerprint_hex) fail(`${vid}: fingerprint`);
  if (entry.authority_fingerprint_hex !== auth.authority_fingerprint_hex) fail(`${vid}: fp field`);
  if (executed.has(vid)) fail(`${vid}: double`);
  executed.add(vid);
}

function validatePageBody(vid, body, openBody, manifestDigest, pageIndex, pages, entries, pageMeta) {
  if (pages <= 0) fail(`${vid}: unexpected page`);
  const first = pageIndex * ENTRIES_PER_PAGE;
  const pageEntries = pageIndex + 1 < pages ? entries.slice(first, first + ENTRIES_PER_PAGE) : entries.slice(first);
  const entryCount = pageEntries.length;
  const entryBytes = Buffer.concat(pageEntries);
  const expectedLen = 92 + 40 * entryCount;
  if (body.length !== expectedLen) fail(`${vid}: page len`);
  const tid = openBody.subarray(0, 16);
  const rev = openBody.subarray(16, 20);
  if (!equal(body.subarray(0, 16), tid)) fail(`${vid}: page tid`);
  if (!equal(body.subarray(16, 20), rev)) fail(`${vid}: page rev`);
  if (!equal(body.subarray(20, 52), manifestDigest)) fail(`${vid}: page md`);
  if (u16(body, 52) !== pageIndex) fail(`${vid}: page index hdr`);
  if (u16(body, 54) !== pages) fail(`${vid}: page count hdr`);
  if (u16(body, 56) !== first) fail(`${vid}: first hdr`);
  if (u16(body, 58) !== entryCount) fail(`${vid}: entry count hdr`);
  const pageDigest = sha(Buffer.concat([
    Buffer.from("NM3-PAGE-V1"), tid, rev, manifestDigest,
    Buffer.from([(pageIndex >> 8) & 0xff, pageIndex & 0xff]),
    Buffer.from([(pages >> 8) & 0xff, pages & 0xff]),
    Buffer.from([(first >> 8) & 0xff, first & 0xff]),
    Buffer.from([(entryCount >> 8) & 0xff, entryCount & 0xff]),
    entryBytes,
  ]));
  if (!equal(body.subarray(60, 92), pageDigest)) fail(`${vid}: page digest`);
  if (!equal(body.subarray(92), entryBytes)) fail(`${vid}: page entries`);
  if (pageMeta.page_index !== pageIndex || pageMeta.page_count !== pages) fail(`${vid}: page meta`);
  if (pageMeta.page_digest_hex !== pageDigest.toString("hex")) fail(`${vid}: page meta digest`);
}

function validateChunkBody(vid, body, openBody, manifestDigest, content, chunkIndex, chunkCount, chunkMeta) {
  const [offset, length] = chunkRange(content.length, chunkIndex);
  if (body.length !== 96 + length) fail(`${vid}: chunk len`);
  if (!equal(body.subarray(0, 16), openBody.subarray(0, 16))) fail(`${vid}: chunk tid`);
  if (!equal(body.subarray(16, 20), openBody.subarray(16, 20))) fail(`${vid}: chunk rev`);
  if (!equal(body.subarray(20, 52), manifestDigest)) fail(`${vid}: chunk md`);
  if (u16(body, 52) !== chunkIndex) fail(`${vid}: chunk index hdr`);
  if (u16(body, 54) !== chunkCount) fail(`${vid}: chunk count hdr`);
  if (u32(body, 56) !== offset) fail(`${vid}: chunk offset hdr`);
  if (u16(body, 60) !== length) fail(`${vid}: chunk length hdr`);
  if (u16(body, 62) !== 0) fail(`${vid}: chunk reserved`);
  const payload = body.subarray(96);
  if (!equal(payload, content.subarray(offset, offset + length))) fail(`${vid}: payload`);
  const digest = sha(payload);
  if (!equal(body.subarray(64, 96), digest)) fail(`${vid}: chunk sha hdr`);
  if (chunkMeta.chunk_sha256_hex !== digest.toString("hex")) fail(`${vid}: chunk meta sha`);
}

function validatePositiveFixture(entry) {
  const vid = entry.id;
  const fx = entry.fixture;
  if (!fx || typeof fx !== "object") fail(`${vid}: fixture`);
  const content = hx(fx.content_hex, `${vid}.content`);
  const openBody = hx(fx.open_body_hex, `${vid}.open`);
  const entries = fx.entries_hex.map((e, i) => hx(e, `${vid}.e${i}`));
  const total = content.length;
  const [chunks, pages] = derive(total);
  const exp = entry.expected;
  if (exp.total_length !== total || exp.chunk_count !== chunks) fail(`${vid} geo`);
  if (exp.manifest_page_count !== pages) fail(`${vid} pages`);
  if (u32(openBody, 20) !== total || u16(openBody, 24) !== CHUNK_SIZE) fail(`${vid} open`);
  if (u16(openBody, 26) !== chunks || u16(openBody, 28) !== pages) fail(`${vid} counts`);
  if (openBody.length < 465 || openBody.length > 651 ||
      fx.facts.open_body_length !== openBody.length || fx.facts.application_binding_offset !== 234 ||
      fx.facts.application_binding_length !== 228 || fx.facts.text_offset !== 462 ||
      fx.facts.application_binding_hex !== openBody.subarray(234, 462).toString("hex")) fail(`${vid}: binding facts`);
  const whole = sha(content);
  if (!equal(openBody.subarray(32, 64), whole)) fail(`${vid} whole`);
  const manifestDigest = sha(Buffer.concat([
    Buffer.from("NM3-MANIFEST-V1"), openBody.subarray(0, 202),
    openBody.subarray(234, 462), openBody.subarray(462), ...entries,
  ]));
  if (!equal(openBody.subarray(202, 234), manifestDigest)) fail(`${vid} md`);
  if (fx.manifest_digest_hex !== manifestDigest.toString("hex")) fail(`${vid} md pin`);
  const targetOrdinal = Buffer.alloc(4); targetOrdinal.writeUInt32BE(fx.facts.target_ordinal);
  let derivedTransferId = sha(Buffer.concat([
    Buffer.from(fx.ids.origin_transaction_id, "hex"), Buffer.from(fx.ids.target_runtime_id, "hex"),
    targetOrdinal, Buffer.from("ninlil-mfdt-v1id", "ascii"),
  ])).subarray(0, 16);
  if (equal(derivedTransferId, Buffer.alloc(16))) {
    derivedTransferId = Buffer.from(derivedTransferId); derivedTransferId[15] = 1;
  }
  if (!equal(openBody.subarray(0, 16), derivedTransferId)) fail(`${vid}: transfer id derivation`);
  if (!Array.isArray(fx.pages)) fail(`${vid}: pages list`);
  if (fx.pages.length !== pages) fail(`${vid}: page list length want ${pages} got ${fx.pages.length}`);
  if (pages === 0 && fx.pages.length !== 0) fail(`${vid}: empty pages`);
  if (pages > 0) {
    const order = fx.pages.map((p) => p.page_index);
    if (!deepEqual(order, [...Array(pages).keys()])) fail(`${vid}: page order`);
  }
  for (const page of fx.pages) {
    validatePageBody(vid, hx(page.body_hex, `${vid}.page`), openBody, manifestDigest, page.page_index, pages, entries, page);
  }
  if (!Array.isArray(fx.chunks) || fx.chunks.length !== chunks) fail(`${vid}: chunks`);
  for (const chunk of fx.chunks) {
    validateChunkBody(vid, hx(chunk.body_hex, `${vid}.chunk`), openBody, manifestDigest, content, chunk.chunk_index, chunks, chunk);
  }
  const openAccept = hx(fx.open_accept_hex, `${vid}.oa`);
  if (openAccept.length !== 100) fail(`${vid}: oa len`);
  if (!equal(openAccept.subarray(0, 16), openBody.subarray(0, 16))) fail(`${vid}: oa tid`);
  if (!equal(openAccept.subarray(20, 52), manifestDigest)) fail(`${vid}: oa md`);
  if (u32(openAccept, 68) !== total) fail(`${vid}: oa total`);
  if (total === 0 && openAccept[96] !== 1) fail(`${vid}: oa complete empty`);
  if (total > 0 && openAccept[96] !== 0) fail(`${vid}: oa complete`);
  const pageAccepts = fx.page_accepts || [];
  if (pageAccepts.length !== pages) fail(`${vid}: page_accepts`);
  for (const pa of pageAccepts) {
    const body = hx(pa.body_hex, `${vid}.pa`);
    if (body.length !== 108) fail(`${vid}: pa len`);
    if (!equal(body.subarray(0, 16), openBody.subarray(0, 16))) fail(`${vid}: pa tid`);
    if (!equal(body.subarray(20, 52), manifestDigest)) fail(`${vid}: pa md`);
    const match = fx.pages.find((p) => p.page_index === pa.page_index);
    if (!equal(body.subarray(56, 88), Buffer.from(match.page_digest_hex, "hex"))) fail(`${vid}: pa dig`);
  }
  const chunkAccepts = fx.chunk_accepts || [];
  if (chunkAccepts.length !== chunks) fail(`${vid}: chunk_accepts`);
  for (const ca of chunkAccepts) {
    const body = hx(ca.body_hex, `${vid}.ca`);
    if (body.length !== 88) fail(`${vid}: ca len`);
    if (!equal(body.subarray(0, 16), openBody.subarray(0, 16))) fail(`${vid}: ca tid`);
    const match = fx.chunks.find((c) => c.chunk_index === ca.chunk_index);
    if (!equal(body.subarray(56, 88), Buffer.from(match.chunk_sha256_hex, "hex"))) fail(`${vid}: ca dig`);
  }
  const finalize = hx(fx.finalize_hex, `${vid}.fin`);
  if (finalize.length !== 92) fail(`${vid}: fin len`);
  if (!equal(finalize.subarray(0, 16), openBody.subarray(0, 16))) fail(`${vid}: fin tid`);
  if (!equal(finalize.subarray(20, 52), manifestDigest)) fail(`${vid}: fin md`);
  if (!equal(finalize.subarray(52, 84), whole)) fail(`${vid}: fin whole`);
  if (u32(finalize, 84) !== total) fail(`${vid}: fin total`);
  const accept = hx(fx.transfer_accept_hex, `${vid}.accept`);
  if (accept.length !== 160) fail(`${vid}: accept len`);
  if (!equal(accept.subarray(128), sha(Buffer.concat([Buffer.from("NM3-ACCEPT-V1"), accept.subarray(0, 128)])))) fail(`${vid}: accept dig`);
  if (!equal(accept.subarray(0, 16), openBody.subarray(0, 16))) fail(`${vid}: accept tid`);
  if (!equal(accept.subarray(20, 52), manifestDigest)) fail(`${vid}: accept md`);
  if (!equal(accept.subarray(52, 84), whole)) fail(`${vid}: accept whole`);
  if (fx.ids.transfer_id !== openBody.subarray(0, 16).toString("hex")) fail(`${vid}: ids tid`);
  if (accept.subarray(0, 16).toString("hex") !== fx.ids.transfer_id) fail(`${vid}: accept context`);
  const totalBuf = Buffer.alloc(4); totalBuf.writeUInt32BE(total);
  const pub = sha(Buffer.concat([
    Buffer.from("NM3-PUBLISH-V1"), openBody.subarray(0, 16), openBody.subarray(16, 20),
    manifestDigest, whole, totalBuf, accept.subarray(88, 104),
  ])).subarray(0, 16);
  if (fx.publication_token_hex !== pub.toString("hex")) fail(`${vid}: pub`);
  const rec = hx(fx.receiver_content_verified_value_hex, `${vid}.nm3r`);
  requireValidActive(rec, `${vid}.nm3r`);
  if (!equal(rec.subarray(16, 32), openBody.subarray(0, 16))) fail(`${vid}: nm3r tid`);
  const nm30 = hx(fx.nm30_value_hex, `${vid}.nm30`);
  requireValidNm30(nm30, `${vid}.nm30`);
  if (fx.tombstone_digest_hex !== shaHex(nm30)) fail(`${vid}: tomb`);
  if (!equal(nm30.subarray(8, 24), openBody.subarray(0, 16))) fail(`${vid}: nm30 tid`);
  const finalLen = chunks ? fx.chunks[chunks - 1].chunk_length : 0;
  if (exp.final_chunk_length !== finalLen) fail(`${vid}: final`);
}

function classifyCommitUnknown(oldRows, newRows, observedRows) {
  const oldMap = Object.fromEntries(oldRows.map((r) => [r.key_hex, r.value_hex]));
  const newMap = Object.fromEntries(newRows.map((r) => [r.key_hex, r.value_hex]));
  const obsMap = Object.fromEntries(observedRows.map((r) => [r.key_hex, r.value_hex]));
  const oldKeys = new Set(Object.keys(oldMap));
  const newKeys = new Set(Object.keys(newMap));
  const obsKeys = new Set(Object.keys(obsMap));
  const expected = new Set([...oldKeys, ...newKeys]);
  if (observedRows.length === 0) return "ABSENT";
  for (const k of obsKeys) if (!expected.has(k)) return "EXTRA";
  const disjoint =
    oldKeys.size > 0 &&
    newKeys.size > 0 &&
    (oldKeys.size !== newKeys.size || ![...oldKeys].every((k) => newKeys.has(k)));
  if (
    disjoint &&
    obsKeys.size === expected.size &&
    [...obsKeys].every((k) => expected.has(k))
  ) {
    return "BOTH";
  }
  for (const [key, value] of Object.entries(obsMap)) {
    if (newMap[key] === value) continue;
    if (oldMap[key] === value) continue;
    if (newMap[key] && Buffer.from(value, "hex").length < Buffer.from(newMap[key], "hex").length) return "PARTIAL";
    if (oldMap[key] && Buffer.from(value, "hex").length < Buffer.from(oldMap[key], "hex").length) return "PARTIAL";
    return "THIRD";
  }
  if (stableStringify(obsMap) === stableStringify(newMap) && stableStringify(obsMap) === stableStringify(oldMap) && oldKeys.size > 0) {
    return "OLD";
  }
  if (stableStringify(obsMap) === stableStringify(newMap) && oldKeys.size === 0) return "NEW";
  if (stableStringify(obsMap) === stableStringify(newMap) && oldKeys.size > 0 && stableStringify(obsMap) !== stableStringify(oldMap)) {
    return "NEW";
  }
  if (stableStringify(obsMap) === stableStringify(oldMap)) return "OLD";
  return "THIRD";
}

function sumValues(obj) { return Object.values(obj).reduce((a, b) => a + b, 0); }

function validateApplicationHandoffAmendment(vectors, executed) {
  const layout = vectors.get("MF-POS-OPEN-APPLICATION-BINDING-LAYOUT-KAT");
  const expectedLayout = APPLICATION_BINDING_LAYOUT_GATE.map(([field, offset, bytes]) => ({field, offset, bytes}));
  if (!deepEqual(layout.application_binding_layout, expectedLayout)) fail("application binding layout KAT");
  for (const [prefix, wanted] of [["minimum", 465], ["maximum", 651]]) {
    const body = hx(layout[`${prefix}_open_body_hex`], `${prefix} revised OPEN`);
    const facts = layout[`${prefix}_facts`];
    if (body.length !== wanted || facts.open_body_length !== wanted ||
        facts.application_binding_offset !== 234 || facts.application_binding_length !== 228 ||
        facts.text_offset !== 462 || facts.application_binding_hex !== body.subarray(234, 462).toString("hex")) {
      fail(`${prefix} revised OPEN geometry`);
    }
    const digest = sha(Buffer.concat([
      Buffer.from("NM3-MANIFEST-V1", "ascii"), body.subarray(0, 202),
      body.subarray(234, 462), body.subarray(462),
    ]));
    if (!equal(body.subarray(202, 234), digest) ||
        layout[`${prefix}_manifest_digest_hex`] !== digest.toString("hex")) fail(`${prefix} revised OPEN digest`);
  }
  const minimumBody = hx(layout.minimum_open_body_hex, "minimum deadline OPEN");
  const maximumBody = hx(layout.maximum_open_body_hex, "maximum deadline OPEN");
  const maximumEpochHex = maximumBody.subarray(178, 194).toString("hex");
  const deadlineCases = [
    {
      case: "uplink_eventfact_no_deadline", service_family: 1,
      deadline_epoch_hex: "00".repeat(16),
      absolute_effect_deadline_ms_u64_hex: "ffffffffffffffff",
      evidence_grace_ms_u64_hex: "0000000000000000", status: "OK",
    },
    {
      case: "uplink_eventfact_deadline_zero", service_family: 1,
      deadline_epoch_hex: "00".repeat(16),
      absolute_effect_deadline_ms_u64_hex: "0000000000000000",
      evidence_grace_ms_u64_hex: "0000000000000000", status: "REJECT",
    },
    {
      case: "finite_downlink_min", service_family: 2,
      deadline_epoch_hex: maximumEpochHex,
      absolute_effect_deadline_ms_u64_hex: "0000000000000001", status: "OK",
    },
    {
      case: "finite_downlink_max", service_family: 2,
      deadline_epoch_hex: maximumEpochHex,
      absolute_effect_deadline_ms_u64_hex: "fffffffffffffffe", status: "OK",
    },
    {
      case: "downlink_no_deadline", service_family: 2,
      deadline_epoch_hex: maximumEpochHex,
      absolute_effect_deadline_ms_u64_hex: "ffffffffffffffff", status: "REJECT",
    },
  ];
  if (equal(minimumBody.subarray(80, 96), Buffer.alloc(16)) ||
      !equal(minimumBody.subarray(178, 194), Buffer.alloc(16)) ||
      u64(minimumBody, 194) !== 0xffffffffffffffffn ||
      u32(minimumBody, 434) !== 1 || u64(minimumBody, 438) !== 0n ||
      u64(minimumBody, 446) !== 0n ||
      !equal(maximumBody.subarray(80, 96), Buffer.alloc(16)) ||
      equal(maximumBody.subarray(178, 194), Buffer.alloc(16)) ||
      u64(maximumBody, 194) < 1n || u64(maximumBody, 194) >= 0xffffffffffffffffn ||
      u32(maximumBody, 434) !== 2 || !deepEqual(layout.deadline_shape_cases, deadlineCases)) {
    fail("Foundation deadline sentinel OPEN authority");
  }
  if (!deepEqual(layout.expected, {
    status: "OK",
    branch: "open_application_binding_revision2",
    admission_profile_revision: 2,
    active_record_schema: 2,
    active_schema1_replay_eligible: false,
    base_fixed_bytes: 234,
    application_binding_bytes: 228,
    text_offset: 462,
    open_body_min: 465,
    open_body_max: 651,
    manifest_binds_entire_application_binding: true,
    public_callback_context_id: "foundation_transaction_id",
    publication_token_scope: "private_mfdt_handoff_dedupe_only",
    nts3_future_schema: "1.2",
    nts3_future_fields: ["mfdt_transfer_id[16]", "mfdt_target_ordinal_u32"],
    nts3_future_target_suffix_placement: "canonical_target_encoding_tail",
    nts3_future_target_suffix_presence: "bearer_route_eq_MFDT_V1_3",
    nts3_future_target_suffix_bytes: 20,
    nts3_future_target_count_max: 4,
    nts3_future_mfdt_target_rule:
      "transfer_id_nonzero__sender_ordinal_eq_bound_target_index__receiver_ordinal_eq_open_origin_ordinal_lt4_u32_be",
    nts3_future_non_mfdt_suffix_bytes: 0,
    nts3_future_non_mfdt_memory_rule: "transfer_id_zero16_and_ordinal_zero",
    nts3_schema11_record_max_bytes: 4031,
    nts3_schema11_inline_payload_max_bytes: 926,
    nts3_future_mfdt_record_max_bytes: 3185,
    nts3_record_ceiling_bytes: 4096,
    deadline_sentinel_erratum: "foundation_canonical_bit_exact",
    no_deadline_u64_hex: "ffffffffffffffff",
    finite_downlink_deadline_min_u64_hex: "0000000000000001",
    finite_downlink_deadline_max_u64_hex: "fffffffffffffffe",
    deadline_zero_rejected: true,
    downlink_no_deadline_rejected: true,
    deadline_normalization_forbidden: true,
  })) fail("application binding layout expected authority");
  markComplete("MF-POS-OPEN-APPLICATION-BINDING-LAYOUT-KAT", layout, executed);

  const mutation = vectors.get("MF-NEG-OPEN-APPLICATION-BINDING-FIELD-MUTATION");
  const body = hx(mutation.open_body_hex, "binding mutation OPEN");
  const entries = Buffer.concat(mutation.manifest_entries_hex.map((item) => hx(item, "binding mutation entry")));
  const digestOf = (candidate) => sha(Buffer.concat([
    Buffer.from("NM3-MANIFEST-V1", "ascii"), candidate.subarray(0, 202),
    candidate.subarray(234, 462), candidate.subarray(462), entries,
  ]));
  const baseline = digestOf(body);
  const expectedMutations = APPLICATION_BINDING_LAYOUT_GATE.map(([field, offset, bytes]) => ({
    field, offset, bytes, xor_first_byte: 1,
  }));
  if (!equal(body.subarray(202, 234), baseline) || mutation.manifest_digest_hex !== baseline.toString("hex") ||
      !deepEqual(mutation.mutations, expectedMutations)) fail("binding mutation baseline/matrix");
  for (const row of mutation.mutations) {
    const altered = Buffer.from(body); altered[row.offset] ^= row.xor_first_byte;
    if (equal(digestOf(altered), baseline)) fail(`binding field not digest-bound: ${row.field}`);
  }

  const carrier = vectors.get("MF-NEG-CARRIER-OPEN-BINDING-MISMATCH-PREFULL");
  const boundaryMatrix = [
    "sender_original_application_exact.origin_transaction_attempt_event",
    "sender_original_application_exact.source_runtime_application_instance_identity_epochs_flags",
    "sender_original_application_exact.target_runtime_application_instance_identity_epochs_flags",
    "sender_original_application_exact.service_text_revision_digest_schema_family",
    "sender_original_application_exact.content_length_and_digest",
    "sender_original_application_exact.application_generation",
    "sender_original_application_exact.deadline_and_evidence",
    "sender_original_application_exact.target_ordinal",
    "receiver_private_carrier_exact.source_runtime_application_instance_identity_epochs_flags",
    "receiver_private_carrier_exact.target_runtime_application_instance_identity_epochs_flags",
    "receiver_open_canonical_validation.original_application_fields",
    "receiver_open_canonical_validation.target_ordinal_lt4_and_local_target_identity",
    "receiver_open_canonical_validation.transfer_id_rederivation",
  ];
  if (hx(carrier.open_body_hex, "carrier mismatch OPEN").length < 465 ||
      carrier.validation_boundary !==
        "sender_before_G_S_OPEN_full_original_exact__receiver_before_G_R_OPEN_party_target_subset_exact_canonical_open_no_private_control_equality" ||
      !deepEqual(carrier.mismatch_fields, boundaryMatrix) ||
      carrier.expected.full_count !== 0 || carrier.expected.durable_rows_created !== 0 ||
      carrier.expected.callback_count !== 0 || carrier.expected.receipt_count !== 0) fail("carrier/OPEN pre-FULL mismatch");

  const mixed = vectors.get("MF-NEG-ADMISSION-REV1-REV2-MIXED");
  if (!deepEqual(mixed.cases, [
    {local_admission_revision: 2, peer_admission_revision: 1, open_layout_revision: 1, active_record_schema: 1},
    {local_admission_revision: 1, peer_admission_revision: 2, open_layout_revision: 2, active_record_schema: 2},
    {local_admission_revision: 2, peer_admission_revision: 2, open_layout_revision: 1, active_record_schema: 1},
  ]) || mixed.expected.full_count !== 0 || mixed.expected.durable_state_mutation !== 0 ||
      mixed.expected.migration_attempted !== false) fail("revision-1/revision-2 mixed fail closed");

  const evidence = vectors.get("MF-POS-APPLICATION-EVIDENCE-DIGEST-KAT");
  const evidenceBytes = hx(evidence.evidence_bytes_hex, "application evidence");
  const u32be = (value) => { const out = Buffer.alloc(4); out.writeUInt32BE(value); return out; };
  const preimage = Buffer.concat([
    Buffer.from("NINLIL-MFDT-APPLICATION-EVIDENCE-V1", "ascii"),
    hx(evidence.publication_token_hex, "publication token"),
    hx(evidence.origin_transaction_id_hex, "origin transaction"),
    hx(evidence.original_attempt_id_hex, "original attempt"),
    u32be(evidence.target_ordinal), u32be(evidence.evidence_stage), u32be(evidenceBytes.length), evidenceBytes,
  ]);
  const evidenceDigest = sha(preimage);
  if (evidence.domain_ascii !== "NINLIL-MFDT-APPLICATION-EVIDENCE-V1" ||
      evidence.evidence_preimage_hex !== preimage.toString("hex") ||
      evidence.application_evidence_digest_hex !== evidenceDigest.toString("hex") ||
      evidence.expected.application_evidence_digest_hex !== evidenceDigest.toString("hex") ||
      evidence.callback_context_id_hex !== evidence.origin_transaction_id_hex ||
      evidence.callback_context_authority !== "foundation_transaction_id" ||
      evidence.publication_token_scope !== "private_mfdt_handoff_dedupe_only" ||
      evidence.expected.handoff_may_advance !== true ||
      evidence.expected.receipt_may_advance_after_handoff_full !== true ||
      evidence.expected.disposition_fatal_recovery_may_advance !== false) fail("application evidence digest/handoff");
  markComplete("MF-POS-APPLICATION-EVIDENCE-DIGEST-KAT", evidence, executed);
}

function validatePinnedMetadata(document) {
  // Exact closed metadata authority from gate hard pins (not from vector).
  if (document.schema !== PINNED_SCHEMA) fail("schema pin");
  if (document.status !== PINNED_STATUS) fail("status pin");
  if (document.adr !== PINNED_ADR) fail(`adr pin: ${document.adr}`);
  if (document.title !== PINNED_TITLE) fail(`title pin: ${document.title}`);
  if (!deepEqual(document.nonclaims, PINNED_NONCLAIMS)) fail("nonclaims exact closed set");
  if (!deepEqual(document.sources, PINNED_SOURCES)) fail("sources exact ordered set");
  const expected = {};
  for (const rel of PINNED_SOURCES) expected[rel] = PINNED_SOURCE_SHA256_HEX[rel];
  if (!deepEqual(document.source_sha256_hex, expected)) fail("source_sha256_hex pin");
  const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
  for (const rel of PINNED_SOURCES) {
    const full = path.join(repoRoot, rel);
    if (!fs.existsSync(full) || !fs.statSync(full).isFile()) fail(`missing source file: ${rel}`);
    const live = shaHex(fs.readFileSync(full));
    if (live !== PINNED_SOURCE_SHA256_HEX[rel]) fail(`source content sha drift: ${rel}`);
  }
  const semanticSurfaces = [
    "docs/adr/0021-multi-frame-durable-custody.md",
    "docs/06-versioning-and-compatibility.md",
    "docs/34-v2-runtime-fabric-completion.md",
    "docs/work/2026-08-01-mfdt-spec-accepted-promotion.md",
    "README.md",
  ];
  const forbidden = [
    "14732", "14768", "49987", "68/58", "136/116", "CLOSED_CANDIDATE",
    "v3_requires", "0x40 OPEN", "0x41 OPEN_ACCEPT", "0x43 PAGE_ACCEPT",
  ];
  for (const rel of semanticSurfaces) {
    const text = fs.readFileSync(path.join(repoRoot, rel), "utf8");
    for (const token of forbidden) {
      if (text.includes(token)) fail(`stale MFDT semantic token ${JSON.stringify(token)} in ${rel}`);
    }
  }
}

function validate(document) {
  const executed = new Set();
  try {
    validateClosedSchema(document);
    validatePinnedMetadata(document);
    if (!deepEqual(document.required_vector_ids, REQUIRED_VECTOR_IDS)) fail("required ids");
    if (!deepEqual(document.required_gate_cases, REQUIRED_VECTOR_IDS)) fail("gate cases");
    const ids = document.vectors.map((v) => v.id);
    if (!deepEqual(ids, REQUIRED_VECTOR_IDS)) fail("vector inventory");
    if (new Set(ids).size !== ids.length) fail("dup ids");
    const recomputed = {};
    for (const vid of REQUIRED_VECTOR_IDS) {
      recomputed[vid] = {
        family: AUTHORITY[vid].family,
        expected: AUTHORITY[vid].expected,
        authority_fingerprint_hex: AUTHORITY[vid].authority_fingerprint_hex,
      };
      if (!deepEqual(document.authority_index[vid], recomputed[vid])) fail(`index ${vid}`);
    }
    // Seal material uses gate hard pins only (not values taught by the vector).
    const seal = {
      metadata: {
        schema: PINNED_SCHEMA,
        status: PINNED_STATUS,
        adr: PINNED_ADR,
        title: PINNED_TITLE,
        nonclaims: PINNED_NONCLAIMS.slice(),
        sources: PINNED_SOURCES.slice(),
      },
      source_sha256_hex: Object.fromEntries(PINNED_SOURCES.map((rel) => [rel, PINNED_SOURCE_SHA256_HEX[rel]])),
      authority_index: recomputed,
    };
    if (shaHex(Buffer.from(stableStringify(seal), "utf8")) !== AUTHORITY_MAP_SHA256_HEX) fail("map sha");
    if (document.authority_map_sha256_hex !== AUTHORITY_MAP_SHA256_HEX) fail("map sha vector");

    const vectors = new Map(document.vectors.map((v) => [v.id, v]));
    const c = document.constants;
    if (c.chunk_size !== CHUNK_SIZE || c.max_content_bytes !== MAX_CONTENT || c.max_chunk_count !== MAX_CHUNKS) fail("constants");
    if (c.sha256_empty_hex !== shaHex(Buffer.alloc(0))) fail("empty sha");
    const applicationLayout = c.application_binding_layout.map((field) => [field.field, field.offset, field.bytes]);
    if (!deepEqual(applicationLayout, APPLICATION_BINDING_LAYOUT_GATE) ||
        c.active_record_schema !== 2 || c.active_schema1_replay_eligible !== false || c.active_value_max !== 35211 ||
        c.open_base_fixed_bytes !== 234 || c.application_binding_bytes !== 228 || c.open_fixed_bytes !== 462 ||
        c.open_text_offset !== 462 || c.open_body_min !== 465 || c.open_body_max !== 651 ||
        c.mfdt_admission_profile_revision !== 2 || c.workspace_bytes !== 65536 || c.workspace_growth_bytes !== 0 ||
        c.open_growth_bytes_redistributed_within_each_slot !== 228 ||
        c.nts3_current_schema_major !== 1 || c.nts3_current_schema_minor !== 1 || c.nts3_future_schema_minor !== 2 ||
        !deepEqual(c.nts3_future_fields, ["mfdt_transfer_id[16]", "mfdt_target_ordinal_u32"]) ||
        c.nts3_future_target_suffix_placement !== "canonical_target_encoding_tail" ||
        c.nts3_future_target_suffix_presence !== "bearer_route_eq_MFDT_V1_3" ||
        c.nts3_future_target_suffix_bytes !== 20 || c.nts3_future_target_count_max !== 4 ||
        c.nts3_future_mfdt_target_rule !==
          "transfer_id_nonzero__sender_ordinal_eq_bound_target_index__receiver_ordinal_eq_open_origin_ordinal_lt4_u32_be" ||
        c.nts3_future_non_mfdt_suffix_bytes !== 0 ||
        c.nts3_future_non_mfdt_memory_rule !== "transfer_id_zero16_and_ordinal_zero" ||
        c.nts3_schema11_record_max_bytes !== 4031 ||
        c.nts3_schema11_inline_payload_max_bytes !== 926 ||
        c.nts3_future_mfdt_record_max_bytes !== 3185 || c.nts3_record_ceiling_bytes !== 4096 ||
        c.nts3_schema11_record_max_bytes - c.nts3_schema11_inline_payload_max_bytes +
          c.nts3_future_target_count_max * c.nts3_future_target_suffix_bytes !== c.nts3_future_mfdt_record_max_bytes ||
        c.nts3_future_mfdt_record_max_bytes > c.nts3_record_ceiling_bytes ||
        c.public_callback_context_id !== "foundation_transaction_id" ||
        c.publication_token_scope !== "private_mfdt_handoff_dedupe_only") fail("application binding constants");
    if (c.no_deadline_u64_hex !== "ffffffffffffffff" ||
        c.finite_downlink_deadline_min_u64_hex !== "0000000000000001" ||
        c.finite_downlink_deadline_max_u64_hex !== "fffffffffffffffe" ||
        c.uplink_eventfact_deadline_shape !== "epoch_zero__absolute_no_deadline__grace_zero" ||
        c.finite_downlink_deadline_shape !== "epoch_nonzero__absolute_1_to_uint64_max_minus_1" ||
        c.original_application_open_deadline_mapping !== "bit_exact_no_normalization") {
      fail("Foundation deadline sentinel constants");
    }
    if (c.manifest_digest_preimage !== "NM3-MANIFEST-V1(15 ascii no NUL)||open[0,202)||open[234,462)||open[462,open_body_length)||entries" ||
        c.digest_domains.application_evidence !== "NINLIL-MFDT-APPLICATION-EVIDENCE-V1") fail("digest authority");
    if (c.nm30_schema !== 2 || c.nm30_value_bytes !== 180 ||
        c.nm30_peer_endpoint_id_offset !== 156 || c.nm30_peer_endpoint_id_bytes !== 16 ||
        c.nm30_owner_role_offset !== 172 || c.nm30_reserved_offset !== 173 ||
        c.nm30_reserved_bytes !== 3 || c.nm30_crc_offset !== 176 ||
        c.nm30_crc_preimage_bytes !== 176 || c.nm30_legacy_schema1_value_bytes !== 164 ||
        c.nm30_session_cookie_durable !== false ||
        c.nm30_legacy_schema1_replay_eligible !== false ||
        c.terminal_session_generation_authority !== "NRC1_header_offset_24" ||
        c.nrc1_header_session_generation_offset !== 24) fail("constants NM30 schema-2/legacy boundary");
    if (c.host_slot_count !== 4 || c.host_coordinator_bytes !== 512 ||
        c.host_control_arena_bytes !== 17920 || c.host_terminal_catalog_entries !== 16 ||
        c.host_terminal_catalog_entry_bytes !== 64 || c.host_terminal_catalog_bytes !== 1024 ||
        c.host_control_outbox_metadata_bytes !== 64 || c.host_control_outbox_bytes !== 1024 ||
        c.host_control_nrc1_scratch_bytes !== 15024 || c.host_control_nm30_scratch_bytes !== 184 ||
        c.host_control_recovery_reserved_bytes !== 88 || c.host_control_route_sentinel !== 0xff ||
        c.host_owner_workspace_bytes !== 280064) fail("constants Host owner bounds");
    markComplete("MF-CONSTANTS-PINNED", vectors.get("MF-CONSTANTS-PINNED"), executed);

    const cat = document.version_catalog;
    if (cat.mf_o01_status !== "SPEC_ACCEPTED_GREEN_BASELINE_HISTORY" || cat.mf_o09_status !== "SPEC_ACCEPTED_CLOSED" ||
        cat.mfdt_negotiation_independent_of_selected_control_version !== true ||
        stableStringify(cat.mfdt_base_control_versions) !== "[1,2]" ||
        cat.mfdt_negotiation_version !== 2 || cat.mfdt_negotiation_domain !== "private_mfdt_admission_v2" ||
        cat.revision1_revision2_interop !== "REJECT_MUTATION_ZERO" || cat.mfdt_offer_type !== 0x34 ||
        cat.mfdt_accept_type !== 0x35 || cat.mfdt_offer_body_bytes !== 112 ||
        cat.mfdt_accept_body_bytes !== 160) fail("catalog3");
    if (!deepEqual(cat.accepted_control_selected_values, [1, 2]) ||
        cat.selected_control_version_3 !== "REJECT" ||
        !deepEqual(cat.mfdt_candidate_type_values, Array.from({length: 16}, (_, i) => 0x34 + i)) ||
        cat.mfdt_candidate_type_count !== 16 || cat.mfdt_transfer_type_count !== 14 ||
        cat.target_promotion_on !== "UNALLOCATED_UNSUPPORTED" ||
        cat.accepted_wire_changed !== false) fail("catalog allocation/promotion");
    markComplete("MF-VERSION-CATALOG-INHERITANCE", vectors.get("MF-VERSION-CATALOG-INHERITANCE"), executed);
    const cm = document.carrier_mapping;
    if (cm.compact_rf_nrw1.status !== "MAPPING_UNAVAILABLE" || cm.wifi_nwb1.status !== "MAPPING_UNAVAILABLE") fail("carrier");
    if (cm.ncg1_ncl1.status !== "MAPPING_CANDIDATE") fail("ncl1");
    const fc = cm.generic_fabric_control_plane;
    if (fc.status !== "MAPPING_CANDIDATE" ||
        fc.mapping !== "FOUNDATION_TRANSFER_RESERVED_APPLICATION" ||
        fc.namespace_id !== "org.ninlil.private" ||
        fc.service_id !== "mfdt-control" ||
        fc.schema_id !== "ncl1-mfdt-v1" ||
        fc.mfdt_admission_profile_revision !== 2 || fc.open_layout_revision !== 2 ||
        fc.descriptor_revision !== 1 ||
        fc.descriptor_digest_domain !== "NINLIL-MFDT-FOUNDATION-CARRIER-V1" ||
        fc.schema_major !== 1 || fc.schema_minor !== 0 ||
        fc.family !== "TRANSFER_RESERVED" ||
        fc.payload !== "exact_ncl1_data_bytes_26_to_1024" ||
        fc.transaction_id_domain !== "NINLIL-MFDT-FABRIC-TRANSACTION-V1" ||
        fc.attempt_id_domain !== "NINLIL-MFDT-FABRIC-ATTEMPT-V1" ||
        fc.ingress_rederives_transaction_and_attempt_ids !== true ||
        fc.tx_permit_required !== true ||
        fc.public_service_registration !== false) fail("generic Fabric MFDT mapping");
    markComplete("MF-CARRIER-MAPPING-MATRIX", vectors.get("MF-CARRIER-MAPPING-MATRIX"), executed);
    if (document.publication_owner.sole_prepare_caller !== "foundation_runtime_callback_reconcile_owner") fail("publication owner");
    markComplete("MF-PUBLICATION-OWNER-MATRIX", vectors.get("MF-PUBLICATION-OWNER-MATRIX"), executed);
    markComplete("MF-ROLE-BOUNDARIES", vectors.get("MF-ROLE-BOUNDARIES"), executed);
    const api = document.private_api;
    if (api.public_abi !== false || api.default_off !== true || api.active_record_schema !== 2 ||
        api.active_schema1_replay_eligible !== false || api.workspace_bytes !== 65536 || api.workspace_growth_bytes !== 0 ||
        api.open_growth_bytes_redistributed_within_each_slot !== 228 ||
        api.workspace_scope !== "per_active_transfer_slot" || api.host_slot_count !== 4 ||
        api.host_coordinator_bytes !== 512 || api.host_control_arena_bytes !== 17920 ||
        api.host_terminal_catalog_entries !== 16 || api.host_terminal_catalog_entry_bytes !== 64 ||
        api.host_control_outbox_count !== 1 || api.host_control_outbox_bytes !== 1024 ||
        api.host_control_route_sentinel !== 0xff || api.host_owner_workspace_bytes !== 280064 ||
        api.host_fifth_active !== "CAPACITY_BUSY_control_outbox_state_mutation_0" ||
        api.host_terminal_route_without_active_slot !== true ||
        api.host_terminal_catalog_rebind !== "peer_role_generation_exact_fresh_nonzero_cookie" ||
        api.host_schema1_terminal_replay_eligible !== false ||
        api.host_control_outbox_backpressure !== "ERR_BUSY_no_overwrite" ||
        api.host_control_traffic_advances_scheduler !== false ||
        api.host_full_transaction_parallelism !== 1 ||
        api.host_peer_unpaid_chunk_offer_max !== 1 || api.host_fair_selection_bound !== 4) {
      fail("Host private owner profile");
    }
    if (!deepEqual(vectors.get("MF-PRIVATE-API-SURFACE").private_api, api)) fail("private api body");
    markComplete("MF-PRIVATE-API-SURFACE", vectors.get("MF-PRIVATE-API-SURFACE"), executed);

    const sidecarEntry = vectors.get("MF-FSM-STORAGE-SIDECAR-PROFILE");
    const sidecar = sidecarEntry.storage_profile;
    if (sidecar === null || typeof sidecar !== "object" || Array.isArray(sidecar)) {
      fail("MFDT sidecar profile type");
    }
    const sidecarKeys = new Set([
      "base_namespace_hex", "base_namespace_length", "derived_namespace_hex",
      "derived_namespace_length", "namespace_magic", "namespace_derivation_domain",
      "namespace_preimage", "storage_expected_schema", "foundation_scanner_value_max",
      "sidecar_single_value_max", "binding_key_hex", "binding_magic",
      "binding_schema", "binding_header_bytes", "binding_fixed_bytes",
      "binding_value_hex", "binding_value_length", "binding_crc32c_hex",
      "binding_base_digest_domain", "binding_base_digest_hex",
      "collision_base_namespace_hex", "collision_binding_value_hex",
      "collision_binding_differs", "known_key_magics", "active_record_schema",
      "active_schema1_replay_eligible", "foreign_key_policy",
      "missing_binding_policy", "host_transfer_keys_hard_max",
      "host_total_keys_hard_max", "esp_total_keys_hard_max",
      "esp_total_logical_bytes_hard_max", "production_open_phase",
      "destroy_close_order", "cross_namespace_atomic_commit_claimed",
      "foundation_large_value_skip_forbidden",
    ]);
    if (!deepEqual(Object.keys(sidecar).sort(), [...sidecarKeys].sort())) {
      fail("MFDT sidecar profile closed keys");
    }
    const baseNamespace = hx(sidecar.base_namespace_hex, "sidecar base");
    const derivedNamespace = hx(sidecar.derived_namespace_hex, "sidecar namespace");
    const bindingKey = hx(sidecar.binding_key_hex, "sidecar binding key");
    const bindingValue = hx(sidecar.binding_value_hex, "sidecar binding");
    const collisionBase = hx(sidecar.collision_base_namespace_hex, "sidecar collision base");
    const collisionBinding = hx(sidecar.collision_binding_value_hex, "sidecar collision binding");
    const namespaceDomain = Buffer.from("NINLIL-MFDT-STORAGE-NAMESPACE-V1", "ascii");
    const bindingDomain = Buffer.from("NINLIL-MFDT-BASE-NAMESPACE-V1", "ascii");
    const encodeU16 = (value) => {
      const out = Buffer.alloc(2);
      out.writeUInt16BE(value);
      return out;
    };
    const encodeU32 = (value) => {
      const out = Buffer.alloc(4);
      out.writeUInt32BE(value);
      return out;
    };
    const derivedExpected = Buffer.concat([
      Buffer.from("NMF1", "ascii"),
      sha(Buffer.concat([namespaceDomain, encodeU16(baseNamespace.length), baseNamespace])),
    ]);
    const expectedBinding = (base) => {
      const total = 52 + base.length;
      const prefix = Buffer.concat([
        Buffer.from("NMS1", "ascii"),
        encodeU16(1),
        encodeU16(48),
        encodeU32(total),
        encodeU16(base.length),
        Buffer.alloc(2),
        sha(Buffer.concat([bindingDomain, encodeU16(base.length), base])),
        base,
      ]);
      return Buffer.concat([prefix, encodeU32(crc32c(prefix))]);
    };
    const bindingExpected = expectedBinding(baseNamespace);
    const collisionBindingExpected = expectedBinding(collisionBase);
    if (
      baseNamespace.length < 1 || baseNamespace.length > 255 ||
      sidecar.base_namespace_length !== baseNamespace.length ||
      !equal(derivedNamespace, derivedExpected) ||
      derivedNamespace.length !== 36 ||
      sidecar.derived_namespace_length !== derivedNamespace.length ||
      sidecar.namespace_magic !== "NMF1" ||
      sidecar.namespace_derivation_domain !== namespaceDomain.toString("ascii") ||
      sidecar.namespace_preimage !== "domain_ascii||base_length_u16be||base_namespace_exact" ||
      sidecar.storage_expected_schema !== 1 ||
      sidecar.foundation_scanner_value_max !== 4096 ||
      sidecar.sidecar_single_value_max !== 65536 ||
      !equal(bindingKey, Buffer.concat([Buffer.from("NMS1", "ascii"), Buffer.alloc(16)])) ||
      !equal(bindingValue, bindingExpected) ||
      sidecar.binding_magic !== "NMS1" ||
      sidecar.binding_schema !== 1 ||
      sidecar.binding_header_bytes !== 48 ||
      sidecar.binding_fixed_bytes !== 52 ||
      sidecar.binding_value_length !== bindingValue.length ||
      sidecar.binding_crc32c_hex !== crc32c(bindingValue.subarray(0, -4)).toString(16).padStart(8, "0") ||
      sidecar.binding_base_digest_domain !== bindingDomain.toString("ascii") ||
      sidecar.binding_base_digest_hex !== shaHex(Buffer.concat([
        bindingDomain, encodeU16(baseNamespace.length), baseNamespace,
      ])) ||
      !equal(collisionBase, derivedNamespace) ||
      !equal(collisionBinding, collisionBindingExpected) ||
      sidecar.collision_binding_differs !== true ||
      equal(bindingValue, collisionBinding) ||
      !deepEqual(sidecar.known_key_magics, ["NMS1", "NM3S", "NM3R", "NM30", "NRC1"]) ||
      sidecar.active_record_schema !== 2 || sidecar.active_schema1_replay_eligible !== false ||
      sidecar.foreign_key_policy !== "CORRUPT_FENCE" ||
      sidecar.missing_binding_policy !== "CREATE_ONLY_IF_NAMESPACE_EMPTY" ||
      sidecar.host_transfer_keys_hard_max !== 32 ||
      sidecar.host_total_keys_hard_max !== 33 ||
      sidecar.esp_total_keys_hard_max !== 32 ||
      sidecar.esp_total_logical_bytes_hard_max !== 69632 ||
      sidecar.production_open_phase !== "BEFORE_BEARER" ||
      !deepEqual(sidecar.destroy_close_order, ["BEARER", "MFDT_SIDECAR", "FOUNDATION_STORAGE"]) ||
      sidecar.cross_namespace_atomic_commit_claimed !== false ||
      sidecar.foundation_large_value_skip_forbidden !== true
    ) {
      fail("MFDT sidecar profile semantics");
    }
    if (bindingValue.length < 53 || bindingValue.length > 307) {
      fail("MFDT sidecar binding length");
    }
    const sidecarExpected = sidecarEntry.expected;
    if (
      sidecarExpected.derived_namespace_length !== 36 ||
      sidecarExpected.binding_value_min !== 53 ||
      sidecarExpected.binding_value_max !== 307 ||
      sidecarExpected.foundation_scanner_value_max !== 4096 ||
      sidecarExpected.mfdt_active_value_max !== 35211 ||
      sidecarExpected.mfdt_active_record_schema !== 2 ||
      sidecarExpected.active_schema1_replay_eligible !== false ||
      sidecarExpected.nrc1_value_bytes !== 15020 ||
      sidecarExpected.same_handle_forbidden !== true ||
      sidecarExpected.collision_fail_closed !== true ||
      sidecarExpected.cross_namespace_atomic_commit_claimed !== false ||
      !deepEqual(sidecarExpected.destroy_close_order, [
        "BEARER", "MFDT_SIDECAR", "FOUNDATION_STORAGE",
      ])
    ) {
      fail("MFDT sidecar profile expected");
    }
    markComplete("MF-FSM-STORAGE-SIDECAR-PROFILE", sidecarEntry, executed);

    const b = document.budget;
    if (sumValues(b.groups.receiver) !== RECEIVER_FULLS_MAX) fail("rx");
    if (sumValues(b.groups.sender) !== SENDER_FULLS_MAX) fail("tx");
    if (b.receiver_fulls_max_transfer !== RECEIVER_FULLS_MAX) fail("rx max");
    if (b.required_receiver_fulls_for_reference !== 154) fail("rx ref");
    if (!deepEqual(vectors.get("MF-BUDGET-ARITHMETIC-REFERENCE").budget, b)) fail("budget body");
    markComplete("MF-BUDGET-ARITHMETIC-REFERENCE", vectors.get("MF-BUDGET-ARITHMETIC-REFERENCE"), executed);
    markComplete("MF-BUDGET-EMPTY-TRANSFER", vectors.get("MF-BUDGET-EMPTY-TRANSFER"), executed);
    markComplete("MF-BUDGET-OBSOLETE-80-REJECTED", vectors.get("MF-BUDGET-OBSOLETE-80-REJECTED"), executed);
    markComplete("MF-BUDGET-RESTORATION-HASH", vectors.get("MF-BUDGET-RESTORATION-HASH"), executed);
    const nrc1b = vectors.get("MF-BUDGET-NRC1-LOGICAL-BYTES");
    if (nrc1b.expected.value_bytes !== 15020 || nrc1b.expected.logical_bytes !== 15056 ||
        nrc1b.expected.slot_bytes !== 208) fail("nrc1 budget size");
    if (nrc1b.expected.slot_count !== 72 || nrc1b.expected.reachable_max_ids !== 65) fail("nrc1 budget slots");
    if (nrc1b.expected.n_complete !== 65 || nrc1b.expected.n_abort !== 64) fail("nrc1 budget paths");
    if (nrc1b.expected.timeout_retry_max !== 8) fail("nrc1 budget timeout");
    if (nrc1b.expected.happy_path_max_ids !== 41 || nrc1b.expected.fixed16_rejected !== true) fail("nrc1 budget happy");
    if (nrc1b.expected.slot_count_ge_reachable !== true) fail("nrc1 budget ge");
    if (nrc1b.expected.admission_reserved_entries !== 3 || nrc1b.expected.admission_reserved_logical_bytes !== 50519) fail("nrc1 budget adm");
    if (nrc1b.expected.host_four_active_committed_logical_bytes !== 201212 ||
        nrc1b.expected.host_committed_logical_bytes_hard_max !== 384476 ||
        nrc1b.expected.host_begin_final_union_logical_bytes_hard_max !== 434779) fail("nrc1 host bounds");
    if (b.active_row_logical_bytes_max !== 35247 || b.active_replacement_begin_final_logical_bytes_max !== 70494 ||
        b.admission_reserved_logical_bytes !== 50519 || b.nrc1_row_logical_bytes !== 15056) fail("budget nrc1 fields");
    if (b.host_slot_count !== 4 || b.host_active_group_logical_bytes !== 50303 ||
        b.host_four_active_committed_logical_bytes !== 201212 ||
        b.terminal_row_logical_bytes !== 216 || b.host_terminal_group_logical_bytes !== 15272 ||
        b.post_terminal_retained_logical_bytes !== 15272 ||
        b.host_committed_logical_bytes_hard_max !== 384476 ||
        b.host_begin_final_union_logical_bytes_hard_max !== 434779 ||
        b.host_serialized_full_staging_logical_bytes_max !== 50303 ||
        b.host_tracked_transfer_groups_max !== 16) fail("budget host bounds");
    if (b.nrc1_reachable_max_ids !== 65) fail("budget reachable");
    if (b.nrc1_retained_until_gc !== true) fail("budget nrc1 retain");
    if (b.receiver_fulls_base !== 44 || b.receiver_fulls_reqid_cache !== 16) fail("budget rx breakdown");
    markComplete("MF-BUDGET-NRC1-LOGICAL-BYTES", nrc1b, executed);
    const fullm = vectors.get("MF-BUDGET-FULL-MAX-WITH-REQID");
    if (fullm.expected.receiver_fulls !== 77 || fullm.expected.sender_fulls !== 67) fail("full max totals");
    if (fullm.expected.receiver_reqid_cache !== 16 || fullm.expected.required_receiver_reference !== 154) fail("full max reqid");
    if (fullm.expected.nrc1_retained_until_gc !== true || fullm.expected.terminal_erases_nrc1 !== false) fail("full max retain");
    markComplete("MF-BUDGET-FULL-MAX-WITH-REQID", fullm, executed);

    validateApplicationHandoffAmendment(vectors, executed);

    for (const [vid, total, chunks, finalLen] of [
      ["MF-POS-EMPTY-PAYLOAD", 0, 0, 0],
      ["MF-POS-ONE-BYTE", 1, 1, 1],
      ["MF-POS-EXACT-MULTIPLE-FINAL", CHUNK_SIZE * 2, 2, CHUNK_SIZE],
      ["MF-POS-ONE-BYTE-FINAL", CHUNK_SIZE + 1, 2, 1],
      ["MF-POS-MAX-PAYLOAD-37-CHUNKS", MAX_CONTENT, 37, 512],
      ["MF-POS-TWO-PAGE-MANIFEST", CHUNK_SIZE * 23, 23, CHUNK_SIZE],
    ]) {
      const entry = vectors.get(vid);
      validatePositiveFixture(entry);
      if (entry.expected.total_length !== total || entry.expected.chunk_count !== chunks) fail(`${vid} auth`);
      if (entry.expected.final_chunk_length !== finalLen) fail(`${vid} final`);
      markComplete(vid, entry, executed);
    }
    const replay = vectors.get("MF-POS-COMPLETION-RECEIPT-REPLAY");
    if (replay.first_accept_hex !== replay.replay_accept_hex) fail("replay");
    markComplete("MF-POS-COMPLETION-RECEIPT-REPLAY", replay, executed);

    const sameId = vectors.get("MF-POS-REQID-CACHE-SAME-ID-STABLE");
    if (sameId.first_page_accept_hex !== sameId.cached_retry_page_accept_hex) fail("reqid cache body");
    if (sameId.expected.first_manifest_complete !== 0 || sameId.expected.cached_manifest_complete !== 0) fail("reqid complete");
    markComplete("MF-POS-REQID-CACHE-SAME-ID-STABLE", sameId, executed);
    const newId = vectors.get("MF-POS-REQID-NEW-ID-CURRENT-COMPLETE");
    if (newId.first_request_id === newId.second_request_id) fail("reqid new same");
    if (newId.expected.second_manifest_complete !== 1) fail("reqid new complete");
    markComplete("MF-POS-REQID-NEW-ID-CURRENT-COMPLETE", newId, executed);
    const nrc1 = vectors.get("MF-POS-REQID-NRC1-LAYOUT-KAT");
    if (nrc1.expected.value_length !== 15020 || nrc1.expected.slot_bytes !== 208 ||
        nrc1.expected.slot_count !== 72 || nrc1.expected.first_slot_session_generation !== 1 ||
        nrc1.expected.lookup_identity !== "session_generation_plus_request_id") fail("nrc1 layout");
    if (nrc1.expected.reachable_max_ids !== 65 || nrc1.expected.happy_path_max_ids !== 41) fail("nrc1 lifecycle");
    if (nrc1.expected.logical_bytes !== 15056 || nrc1.expected.timeout_retry_max !== 8) fail("nrc1 logical/timeout");
    if (nrc1.nrc1_key_hex.length !== 40 || nrc1.nrc1_value_hex.length !== 15020 * 2) fail("nrc1 key/value");
    requireValidNrc1(hx(nrc1.nrc1_value_hex, "nrc1 layout"), "nrc1 layout");
    const l0Mutant = hx(nrc1.occupied_l0_repaired_crc_mutant_hex, "nrc1 l0 mutant");
    let l0Rejected = false;
    try { requireValidNrc1(l0Mutant, "nrc1 l0 mutant"); } catch (e) {
      if (!(e instanceof GateError)) throw e;
      l0Rejected = true;
    }
    if (!l0Rejected) fail("nrc1 occupied L=0 mutant accepted");
    markComplete("MF-POS-REQID-NRC1-LAYOUT-KAT", nrc1, executed);
    const max41 = vectors.get("MF-POS-REQID-MAX-TRANSFER-OCCUPIED-41");
    if (max41.expected.occupied_count !== 41 || max41.expected.slot_count !== 72) fail("max41 occ");
    if (max41.expected.fits !== true || max41.expected.cache_full !== false) fail("max41 fit");
    if (max41.expected.exceeds_obsolete_fixed16 !== true) fail("max41 fixed16");
    if (max41.expected.open_ids !== 1 || max41.expected.page_ids !== 2 || max41.expected.chunk_ids !== 37 || max41.expected.finalize_ids !== 1) fail("max41 br");
    if (max41.nrc1_value_hex.length !== 15020 * 2) fail("max41 value");
    requireValidNrc1(hx(max41.nrc1_value_hex, "max41 NRC1"), "max41 NRC1");
    markComplete("MF-POS-REQID-MAX-TRANSFER-OCCUPIED-41", max41, executed);
    const smv = vectors.get("MF-POS-REQID-RETRY-BUDGET-SM");
    if (smv.expected.scope !== "per_transfer_per_owner_side") fail("sm scope");
    if (smv.expected.owner !== "requestor_of_outbound_mfdt_control") fail("sm owner");
    if (smv.expected.initial_value !== 8 || smv.expected.max_value !== 8 || smv.expected.min_value !== 0) fail("sm range");
    if (smv.expected.header_offset !== 105) fail("sm offset");
    if (smv.expected.decrement_event !== "timeout_retry_with_new_request_id") fail("sm dec");
    if (smv.expected.exhaustion_is_terminal !== false || smv.expected.exhaustion_is_nrc1_eviction !== false) fail("sm exh");
    if (smv.expected.exhaustion_forbids_new_request_id_timeout_retry !== true) fail("sm forbid");
    if (smv.expected.not_per_request_id !== true || smv.expected.not_per_stage !== true) fail("sm not-per");
    if (!smv.retry_budget_sm || smv.retry_budget_sm.initial_value !== 8) fail("sm body");
    markComplete("MF-POS-REQID-RETRY-BUDGET-SM", smv, executed);
    const reach = vectors.get("MF-POS-REQID-REACHABLE-MAX-COUNT");
    if (reach.expected.n_complete !== 65 || reach.expected.n_abort !== 64 || reach.expected.reachable_max !== 65) fail("reach paths");
    if (reach.expected.timeout_retry_max !== 8 || reach.expected.slot_count !== 72) fail("reach budget");
    if (reach.expected.slot_count_ge_reachable !== true || reach.expected.naive_union_is_single_path !== false) fail("reach flags");
    if (reach.expected.naive_union !== 57 || reach.expected.terminal_outcomes_exclusive !== true) fail("reach exclusive");
    if (reach.expected.finalize_abort_success_exclusive !== true || reach.expected.derived_from_retry_budget_sm !== true) fail("reach sm");
    if (reach.n_complete !== 1 + 2 + 37 + 8 + 1 + 8 + 8 || reach.n_abort !== 1 + 2 + 37 + 8 + 8 + 8) fail("reach formula fields");
    if (!reach.first_units || reach.first_units.retry_new_ids !== 8 || reach.first_units.finalize !== 1) fail("reach units");
    markComplete("MF-POS-REQID-REACHABLE-MAX-COUNT", reach, executed);
    const rtry = vectors.get("MF-POS-REQID-MAX-RETRY-TRACE");
    if (rtry.expected.timeout_retries !== 8 || rtry.expected.occupied_count !== 9) fail("retry counts");
    if (rtry.expected.new_request_id_each_retry !== true || rtry.expected.fits_in_capacity !== true) fail("retry flags");
    if (rtry.expected.slot_count !== 72 || rtry.retry_request_ids.length !== 8) fail("retry list");
    if (new Set(rtry.retry_request_ids).size !== 8) fail("retry unique");
    if (rtry.nrc1_value_hex.length !== 15020 * 2) fail("retry value");
    requireValidNrc1(hx(rtry.nrc1_value_hex, "retry NRC1"), "retry NRC1");
    markComplete("MF-POS-REQID-MAX-RETRY-TRACE", rtry, executed);
    const tld = vectors.get("MF-POS-REQID-TERMINAL-LATE-DUP-MATRIX");
    if (tld.expected.operation_count !== 6 || tld.expected.all_bit_exact !== true) fail("tld");
    if (tld.expected.nrc1_retained_with_nm30 !== true || tld.expected.terminal_erases_nrc1 !== false) fail("tld retain");
    if (!Array.isArray(tld.operations) || tld.operations.length !== 6) fail("tld ops");
    if (tld.nrc1_value_hex.length !== 15020 * 2 || tld.nm30_value_hex.length !== 180 * 2) fail("tld sizes");
    requireValidNrc1(hx(tld.nrc1_value_hex, "terminal NRC1"), "terminal NRC1");
    requireValidNm30(hx(tld.nm30_value_hex, "terminal NM30"), "terminal NM30");
    markComplete("MF-POS-REQID-TERMINAL-LATE-DUP-MATRIX", tld, executed);
    const nm30v = vectors.get("MF-POS-NM30-SCHEMA2-LAYOUT-KAT");
    const nm30 = hx(nm30v.nm30_value_hex, "schema2 NM30");
    requireValidNm30(nm30, "schema2 NM30");
    if (nm30v.expected.schema !== 2 || nm30v.expected.value_length !== 180 ||
        nm30v.expected.peer_endpoint_id_offset !== 156 ||
        nm30v.expected.peer_endpoint_id_bytes !== 16 ||
        nm30v.expected.owner_role_offset !== 172 ||
        nm30v.expected.reserved_offset !== 173 || nm30v.expected.reserved_bytes !== 3 ||
        nm30v.expected.crc_offset !== 176 || nm30v.expected.crc_preimage_bytes !== 176 ||
        nm30v.expected.session_cookie_durable !== false ||
        nm30v.expected.session_generation_authority !== "NRC1_header_offset_24" ||
        nm30.subarray(156, 172).toString("hex") !== nm30v.peer_endpoint_id_hex ||
        nm30[172] !== 2 || !equal(nm30.subarray(173, 176), Buffer.alloc(3)) ||
        shaHex(nm30) !== nm30v.nm30_sha256_hex ||
        !deepEqual([...new Set(nm30v.durable_fields_exclude)].sort(),
          ["session_cookie", "session_generation"])) {
      fail("schema2 NM30 exact layout authority");
    }
    markComplete("MF-POS-NM30-SCHEMA2-LAYOUT-KAT", nm30v, executed);
    const fourHit = vectors.get("MF-POS-HOST-FOUR-ACTIVE-TERMINAL-HIT");
    if (fourHit.expected.active_before !== 4 || fourHit.expected.active_after !== 4 ||
        fourHit.expected.active_slot_allocations !== 0 || fourHit.expected.control_route !== 0xff ||
        fourHit.expected.nrc1_hit !== true || fourHit.expected.full_count !== 0 ||
        fourHit.expected.store_mutation !== 0 || fourHit.expected.owned_control_outbox !== true ||
        fourHit.expected.transport_status !== "OK" ||
        fourHit.expected.scheduler_cursor_unchanged !== true ||
        fourHit.expected.peer_unpaid_fence_unchanged !== true ||
        fourHit.active_transfer_ids.length !== 4 ||
        hx(fourHit.terminal_response_body_hex, "four hit body").length !== 108) {
      fail("four-active terminal control hit");
    }
    markComplete("MF-POS-HOST-FOUR-ACTIVE-TERMINAL-HIT", fourHit, executed);
    const fsm = vectors.get("MF-FSM-TERMINAL-ACTIVE-CODES-UNREACHABLE");
    if (!deepEqual(fsm.forbidden_active_state_codes, [7, 9, 39])) fail("fsm codes");
    if (fsm.expected.durable_terminal_kind !== "NM30_ONLY") fail("fsm kind");
    markComplete("MF-FSM-TERMINAL-ACTIVE-CODES-UNREACHABLE", fsm, executed);
    const trace = vectors.get("MF-TRACE-S1-S6-HAPPY-PATH");
    if (!deepEqual(trace.expected.stages, ["S1", "S2", "S3", "S4", "S5", "S6"])) fail("trace");
    markComplete("MF-TRACE-S1-S6-HAPPY-PATH", trace, executed);

    const storageCollision = vectors.get("MF-NEG-STORAGE-SIDECAR-COLLISION");
    if (
      !deepEqual(storageCollision.authority, sidecar) ||
      !deepEqual(storageCollision.cases, [
        "caller_base_equals_derived_namespace",
        "different_base_same_derived_namespace_simulation",
        "binding_missing_with_foreign_rows",
        "binding_wrong_base_digest",
        "binding_wrong_full_base_bytes",
        "binding_wrong_crc32c",
        "foreign_key_present",
      ]) ||
      storageCollision.expected.existing_rows_overwritten !== false ||
      storageCollision.expected.foundation_scan_relaxed !== false ||
      storageCollision.expected.wire_or_apply !== 0
    ) {
      fail("MFDT sidecar collision matrix");
    }
    // Negatives — authority expected + key fields
    for (const vid of REQUIRED_VECTOR_IDS.filter((id) => id.startsWith("MF-NEG-"))) {
      const entry = vectors.get(vid);
      if (vid === "MF-NEG-DUPLICATE-CHUNK-CONFLICT") {
        const first = hx(entry.first_offer_hex, "d1");
        const second = hx(entry.second_offer_hex, "d2");
        if (equal(first.subarray(64, 96), second.subarray(64, 96))) fail("dup");
        if (!equal(sha(second.subarray(96)), second.subarray(64, 96))) fail("dup repair");
      }
      if (vid === "MF-NEG-STALE-VERSION-SELECTED-2") {
        if (typeof entry.base_selected_control_version !== "number" ||
            !Number.isInteger(entry.base_selected_control_version) ||
            typeof entry.mfdt_admission_version !== "number" ||
            !Number.isInteger(entry.mfdt_admission_version)) fail("int type");
        if (entry.base_selected_control_version !== 2 ||
            entry.mfdt_admission_version !== 0 || entry.message_type !== 0x36) fail("MFN1 absent");
      }
      if (vid === "MF-NEG-MIXED-VERSION-PEER") {
        if (entry.base_selected_control_version !== 2 ||
            entry.mfn1_session_generation !== 7 ||
            entry.active_session_generation !== 8) fail("stale MFN1 session");
      }
      if (vid === "MF-NEG-DEFAULT-OFF-POLICY") {
        if (entry.local_policy !== "OFF" ||
            entry.base_selected_control_version !== 2 ||
            entry.mfdt_admission_version !== 2) fail("default off");
      }
      if (vid === "MF-NEG-REQID-CACHE-FULL") {
        if (entry.occupied_count !== 72 || entry.expected.slot_count !== 72) fail("cache full 72");
        if (entry.expected.no_silent_eviction !== true) fail("cache full eviction");
        if (entry.nrc1_value_hex.length !== 15020 * 2) fail("cache full value");
        requireValidNrc1(hx(entry.nrc1_value_hex, "cache full NRC1"), "cache full NRC1");
      }
      if (vid === "MF-NEG-REQID-DIGEST-OPEN-PREIMAGE") {
        if (entry.message_type !== 0x36) fail("open dig type");
        if (entry.expected.includes_bind52_strip !== false) fail("open dig strip");
        if (entry.expected.preimage !== "type_u8||len_u16be||full_open_body") fail("open dig label");
        const openBody = hx(entry.open_body_hex, "open dig body");
        const pre = hx(entry.open_preimage_hex, "open pre");
        const expectedPre = Buffer.concat([Buffer.from([0x36]), Buffer.from([(openBody.length >> 8) & 0xff, openBody.length & 0xff]), openBody]);
        if (!equal(pre, expectedPre)) fail("open dig preimage");
        if (sha(pre).toString("hex") !== entry.request_body_digest_hex) fail("open dig recompute");
        if (entry.request_body_digest_hex === entry.wrong_bind52_strip_digest_hex) fail("open dig collide");
        if (entry.expected.bind52_strip_digest_differs !== true) fail("open dig differs");
      }
      if (vid === "MF-NEG-NM30-SCHEMA1-COLD-REPLAY-DENY") {
        const legacy = hx(entry.legacy_nm30_value_hex, "legacy NM30");
        requireValidNm30LegacySchema1(legacy, "legacy NM30");
        if (entry.expected.schema !== 1 || entry.expected.value_length !== 164 ||
            entry.expected.canonical_legacy_validation !== true ||
            entry.expected.accounting_allowed !== true ||
            entry.expected.retention_gc_allowed !== true ||
            entry.expected.replay_eligible !== false ||
            entry.expected.rebind_allowed !== false ||
            entry.expected.wire_response_count !== 0 ||
            entry.expected.transport_ok !== false ||
            entry.catalog_state !== "replay_ineligible" ||
            !deepEqual(entry.permitted_actions, ["charge_actual_row", "retention_gc"]) ||
            !entry.forbidden_actions.includes("infer_peer") ||
            !entry.forbidden_actions.includes("infer_role") ||
            !entry.forbidden_actions.includes("infer_cookie")) {
          fail("legacy NM30 cold replay denial");
        }
      }
      if (vid === "MF-NEG-HOST-TERMINAL-BIND-MATRIX") {
        if (!Array.isArray(entry.cases) || entry.cases.length !== 7) fail("terminal bind cases");
        const results = Object.fromEntries(entry.cases.map((item) => [item.name, item.result]));
        const expectedResults = {
          exact_initial_rebind: "OK",
          same_cookie_after_bind: "OK",
          peer_mismatch: "ERR_STATE",
          role_mismatch: "ERR_STATE",
          generation_mismatch: "ERR_STATE",
          zero_cookie: "ERR_STATE",
          cookie_swap: "ERR_STATE",
        };
        const auth = entry.authority;
        if (!deepEqual(results, expectedResults) || auth.owner_role !== 2 ||
            auth.nrc1_session_generation !== 1 || auth.cookie_at_recovery !== 0 ||
            entry.cases[0].peer_endpoint_id_hex !== auth.peer_endpoint_id_hex ||
            entry.cases[0].owner_role !== auth.owner_role ||
            entry.cases[0].session_generation !== auth.nrc1_session_generation ||
            entry.cases[0].session_cookie_hex === "0000000000000000" ||
            entry.cases[5].session_cookie_hex !== "0000000000000000" ||
            entry.cases[6].session_cookie_hex === entry.cases[0].session_cookie_hex ||
            entry.expected.mismatch_wire_response_count !== 0 ||
            entry.expected.mismatch_state_mutation !== 0 ||
            entry.expected.mismatch_store_mutation !== 0 ||
            entry.expected.mismatch_outbox_mutation !== 0) fail("terminal bind exact authority");
      }
      if (vid === "MF-NEG-HOST-FOUR-ACTIVE-FRESH-OPEN-BUSY") {
        const open = hx(entry.fresh_open_body_hex, "fresh capacity OPEN");
        const busy = hx(entry.busy_body_hex, "fresh capacity BUSY");
        if (open.length < 234 || equal(open.subarray(0, 16), Buffer.alloc(16)) ||
            u32(open, 16) === 0 || equal(open.subarray(202, 234), Buffer.alloc(32)) ||
            busy.length !== 60 || !equal(busy.subarray(0, 16), open.subarray(0, 16)) ||
            !equal(busy.subarray(16, 20), open.subarray(16, 20)) ||
            !equal(busy.subarray(20, 52), open.subarray(202, 234)) ||
            u16(busy, 52) !== 1 || u16(busy, 54) !== 0 || u32(busy, 56) !== 0 ||
            entry.expected.semantic_response_type !== 0x3b ||
            entry.expected.reject_code_sidecar !== 5 || entry.expected.cacheable !== false ||
            entry.expected.full_count !== 0 || entry.expected.durable_state_mutation !== 0 ||
            entry.expected.active_before !== 4 || entry.expected.active_after !== 4 ||
            entry.expected.owned_control_outbox !== true || entry.expected.control_route !== 0xff ||
            entry.expected.transport_status !== "OK") fail("four-active fresh OPEN BUSY");
      }
      if (vid === "MF-NEG-HOST-CONTROL-OUTBOX-BACKPRESSURE") {
        const first = entry.first_owned_frame;
        const blocked = entry.blocked_second_frame;
        const capacity = vectors.get("MF-NEG-HOST-FOUR-ACTIVE-FRESH-OPEN-BUSY");
        if (first.route !== 0xff || first.message_type !== 0x3b ||
            first.body_hex !== capacity.busy_body_hex || blocked.message_type !== 0x3a ||
            blocked.result !== "ERR_BUSY" || entry.expected.status !== "ERR_BUSY" ||
            entry.expected.control_outbox_capacity_frames !== 1 ||
            entry.expected.first_frame_retained_bit_exact !== true ||
            entry.expected.second_frame_enqueued !== false ||
            entry.expected.second_wire_response_count !== 0 || entry.expected.full_count !== 0 ||
            entry.expected.state_mutation !== 0 || entry.expected.store_mutation !== 0 ||
            entry.expected.catalog_mutation !== 0 ||
            entry.expected.active_fairness_blocked !== false ||
            entry.expected.scheduler_cursor_unchanged !== true) {
          fail("Host control outbox backpressure");
        }
      }
      if (vid === "MF-NEG-PREADMISSION-POLICY-STATELESS" ||
          vid === "MF-NEG-PREADMISSION-DEADLINE-STATELESS") {
        const isPolicy = vid === "MF-NEG-PREADMISSION-POLICY-STATELESS";
        const code = isPolicy ? 4 : 7;
        const branch = isPolicy ? "preadmission_policy_stateless" : "preadmission_deadline_stateless";
        const open = hx(entry.fresh_open_body_hex, `${vid} OPEN`);
        const response = hx(entry.response_body_hex, `${vid} response`);
        if (open.length < 234 || equal(open.subarray(0, 16), Buffer.alloc(16)) ||
            u32(open, 16) === 0 || equal(open.subarray(202, 234), Buffer.alloc(32)) ||
            response.length !== 60 ||
            !equal(response.subarray(0, 16), open.subarray(0, 16)) ||
            !equal(response.subarray(16, 20), open.subarray(16, 20)) ||
            !equal(response.subarray(20, 52), open.subarray(202, 234)) ||
            u16(response, 52) !== 1 || u16(response, 54) !== code || u32(response, 56) !== 0 ||
            entry.expected.status !== "OK" || entry.expected.branch !== branch ||
            entry.expected.semantic_response_type !== 0x3a ||
            entry.expected.reject_code !== code || entry.expected.cacheable !== false ||
            entry.expected.full_count !== 0 || entry.expected.durable_rows_created !== 0 ||
            entry.expected.durable_state_mutation !== 0 ||
            entry.expected.owned_control_outbox !== true ||
            entry.expected.control_route !== 0xff || entry.expected.transport_status !== "OK" ||
            entry.expected.late_duplicate_may_be_reevaluated !== true ||
            entry.expected.retry_requires_fresh_nonzero_request_id !== true ||
            entry.g_r_open_started !== false) fail(`${vid}: stateless carve-out`);
      }
      if (vid === "MF-NEG-ACTIVE-SEMANTIC-REJECT-CACHED") {
        const request = hx(entry.request_body_hex, "active semantic request");
        const response = hx(entry.response_body_hex, "active semantic response");
        const slot = hx(entry.nrc1_slot_hex, "active semantic NRC1 slot");
        const preimage = Buffer.concat([
          Buffer.from([entry.request_type]),
          Buffer.from([(request.length >> 8) & 0xff, request.length & 0xff]),
          request,
        ]);
        if (response.length !== 60 || u16(response, 52) !== 5 || u16(response, 54) !== 8 ||
            slot.length !== 208 || u64(slot, 0) !== BigInt(entry.request_id) ||
            u32(slot, 8) !== 1 || !equal(slot.subarray(12, 44), sha(preimage)) ||
            u16(slot, 44) !== 0x3a || u16(slot, 46) !== 60 ||
            !equal(slot.subarray(48, 108), response) ||
            !equal(slot.subarray(108), Buffer.alloc(100)) ||
            entry.expected.status !== "OK" || entry.expected.active_group_present !== true ||
            entry.expected.cacheable !== true || entry.expected.nrc1_miss !== true ||
            entry.expected.nrc1_full_count !== 1 ||
            entry.expected.transfer_state_mutation !== 0 ||
            entry.expected.durable_cache_mutation !== 1 ||
            entry.expected.wire_after_full_only !== true ||
            entry.expected.owned_active_slot_outbox !== true ||
            entry.expected.uses_control_outbox !== false ||
            entry.expected.transport_status !== "OK") fail("active semantic reject NRC1 cache");
      }
      markComplete(vid, entry, executed);
    }

    for (const vid of REQUIRED_VECTOR_IDS.filter((id) => id.startsWith("MF-CU-"))) {
      const entry = vectors.get(vid);
      const classification = classifyCommitUnknown(entry.old_rows, entry.new_rows, entry.observed_rows);
      if (entry.expected.classification !== classification) fail(`${vid} class ${classification}`);
      if (entry.expected.wire_success !== 0) fail(`${vid} wire`);
      if (vid.startsWith("MF-CU-STORAGE-BINDING-")) {
        const bindingKeyHex = sidecar.binding_key_hex;
        const bindingValueHex = sidecar.binding_value_hex;
        if (
          entry.group !== "MFDT_NAMESPACE_BINDING_BOOTSTRAP" ||
          !deepEqual(entry.old_rows, []) ||
          entry.expected.foundation_mutation !== 0
        ) {
          fail(`${vid}: binding CU shape`);
        }
        if (classification === "NEW") {
          if (!deepEqual(entry.observed_rows, [{
            key_hex: bindingKeyHex,
            value_hex: bindingValueHex,
          }])) {
            fail(`${vid}: binding NEW`);
          }
        } else if (classification === "ABSENT") {
          if (!deepEqual(entry.observed_rows, [])) fail(`${vid}: binding ABSENT`);
        } else if (classification === "PARTIAL") {
          if (
            entry.observed_rows.length !== 1 ||
            entry.observed_rows[0].key_hex !== bindingKeyHex ||
            entry.observed_rows[0].value_hex.length >= bindingValueHex.length
          ) {
            fail(`${vid}: binding PARTIAL`);
          }
        } else if (classification === "EXTRA") {
          if (
            entry.observed_rows.length !== 2 ||
            !deepEqual(entry.observed_rows[0], {
              key_hex: bindingKeyHex,
              value_hex: bindingValueHex,
            })
          ) {
            fail(`${vid}: binding EXTRA`);
          }
        } else if (classification === "THIRD") {
          if (
            entry.observed_rows.length !== 1 ||
            entry.observed_rows[0].key_hex !== bindingKeyHex ||
            entry.observed_rows[0].value_hex === bindingValueHex
          ) {
            fail(`${vid}: binding THIRD`);
          }
        }
      }
      if (vid === "MF-CU-NRC1-NEW") {
        for (const field of [
          "target_same_id_retry",
          "target_cold_restart_retry",
          "target_active_plus_nrc1_replay",
          "target_nrc1_only_replay",
        ]) {
          if (entry.expected[field] !== "COMMIT_UNKNOWN") fail(`${vid} ${field}`);
        }
        if (entry.expected.host_full_capable_replay !== "OK") fail(`${vid} host replay`);
        if (entry.expected.attestation_magic_only_accepted !== false) fail(`${vid} magic-only attestation`);
      }
      for (const row of entry.observed_rows) {
        const key = hx(row.key_hex, `${vid}.key`);
        const value = hx(row.value_hex, `${vid}.v`);
        if (classification === "PARTIAL") continue;
        if (value.length >= HEADER_BYTES + 4) {
          const magic = value.subarray(0, 4).toString();
          if (magic === "NM3R" || magic === "NM3S") {
            requireValidRecordCrc(value, `${vid}.rec`);
            if (classification === "THIRD") {
              let rejected = false;
              try { requireValidActive(value, `${vid}.semantic-mutant`); } catch (e) {
                if (!(e instanceof GateError)) throw e;
                rejected = true;
              }
              if (!rejected) fail(`${vid}: repaired-CRC active semantic mutant accepted`);
            } else {
              requireValidActive(value, `${vid}.rec`);
            }
          }
        }
        if (value.length === NM30_BYTES && value.subarray(0, 4).toString() === "NM30") {
          if (classification === "THIRD") {
            let rejected = false;
            try { requireValidNm30(value, `${vid}.semantic-mutant`); } catch (e) {
              if (!(e instanceof GateError)) throw e;
              rejected = true;
            }
            if (!rejected) fail(`${vid}: repaired-CRC NM30 semantic mutant accepted`);
          } else {
            requireValidNm30(value, `${vid}.nm30`);
          }
        }
        if (value.length === 15020 && value.subarray(0, 4).toString() === "NRC1") {
          const transferId = key.subarray(4, 20);
          if (classification === "THIRD") {
            let rejected = false;
            try { requireValidNrc1(value, `${vid}.semantic-mutant`, transferId); } catch (e) {
              if (!(e instanceof GateError)) throw e;
              rejected = true;
            }
            if (!rejected) fail(`${vid}: repaired-CRC NRC1 semantic mutant accepted`);
          } else if (classification === "EXTRA" && !equal(transferId, value.subarray(8, 24))) {
            let rejected = false;
            try { requireValidNrc1(value, `${vid}.extra-nrc1`, transferId); } catch (e) {
              if (!(e instanceof GateError)) throw e;
              rejected = true;
            }
            if (!rejected) fail(`${vid}: misbound extra NRC1 accepted`);
          } else {
            requireValidNrc1(value, `${vid}.nrc1`, transferId);
          }
        }
      }
      markComplete(vid, entry, executed);
    }

    const crossNamespace = vectors.get("MF-TX-CROSS-NAMESPACE-ADMISSION-MATRIX");
    const crossExpected = {
      status: "OK",
      branch: "canonical_roster_target_attempt_prearm_foundation_full_reconcile",
      target_count_min: 1,
      target_count_max: 4,
      runtime_uniqueness_scope: "MFDT_V1_ONLY",
      target_runtime_unique_within_origin: true,
      same_runtime_different_application_instance_rejected: true,
      duplicate_runtime_api_status: "NINLIL_OK",
      duplicate_runtime_submission_state: "REJECTED",
      duplicate_runtime_reason: "TARGET_COUNT_UNSUPPORTED",
      duplicate_runtime_entropy_draws: 0,
      duplicate_runtime_sidecar_mutations: 0,
      duplicate_runtime_foundation_mutations: 0,
      compound_receiver_key_created: false,
      nts3_target_local_suffix_rule_changed: false,
      attempt_draw_order: "canonical_target_order",
      attempt_draws_max_per_target: 4,
      attempt_collision_set: "durable_active_retained_plus_prior_same_admission_candidates",
      attempt_candidate_nonzero: true,
      attempt_candidate_bound_to_target_open: true,
      attempt_consumed_claim_before_foundation_full: 0,
      sidecar_prearm_before_foundation_full: true,
      wire_txgate_callback_before_foundation_full: 0,
      foundation_admission_full_count: 1,
      foundation_admission_atomic_members: [
        "exact_target_roster",
        "per_target_attempt_index_and_binding",
        "attempt_budget_and_counters",
        "ATTEMPT_PREPARED_and_pending_state",
        "per_target_mfdt_transfer_id_and_origin_ordinal",
      ],
      admission_execution_scope: "owner_thread_call",
      restart_reconcile_before_bearer_open: true,
      new_durable_state_added: false,
      foundation_commit_unknown_deletes_sidecar: false,
      blind_attempt_redraw_forbidden: true,
      orphan_cleanup_before_wire_or_apply: true,
      missing_sidecar_for_durable_mfdt: "CORRUPT_FENCE",
      matching_both: "RESUME_ELIGIBLE",
      wire_or_apply_before_match: 0,
    };
    const crossSteps = [
      "OWNER_THREAD_CANONICALIZE_ROSTER_AND_REJECT_DUPLICATE_RUNTIME",
      "DRAW_NONZERO_UNIQUE_ATTEMPT_MAX4_PER_TARGET_CANONICAL_ORDER",
      "COLLISION_SET_INCLUDES_PRIOR_SAME_ADMISSION_CANDIDATES",
      "BIND_EACH_ATTEMPT_TO_ITS_TARGET_OPEN",
      "FULL_SIDECAR_ARM_EACH_TARGET_WITH_WIRE_TXGATE_CALLBACK_ZERO",
      "FULL_FOUNDATION_ADMISSION_ONCE_ONLY_AFTER_ALL_ARMS_NEW",
      "FOUNDATION_FULL_ATOMIC_ROSTER_ATTEMPTS_BUDGET_COUNTERS_PREPARED_PENDING_MFDT_BINDING",
      "DEFINITE_CANDIDATE_OR_ARM_FAILURE_CLEAN_CREATED_ARMS_FOUNDATION_FULL_ZERO",
      "DEFINITE_FOUNDATION_FAILURE_CLEAN_ALL_ARMS",
      "ARM_OR_CLEANUP_COMMIT_UNKNOWN_FENCE_FOR_COLD_RECONCILE",
      "FOUNDATION_COMMIT_UNKNOWN_KEEP_ARMS_FENCE_RECONCILE_NO_REDRAW",
      "RESTART_RECONCILE_BEFORE_BEARER_OPEN_WITHOUT_NEW_STATE",
      "ONLY_MATCHED_ROWS_MAY_DISPATCH_OR_APPLY",
    ];
    const crossMatrix = [
      {
        case: "four_unique_runtime_targets",
        result: "ADMIT_AFTER_FOUNDATION_FULL",
        attempt_draws: "ONE_TO_FOUR_EACH_CANONICAL_ORDER",
        collision_set: "DURABLE_ACTIVE_RETAINED_PLUS_PRIOR_SAME_ADMISSION",
        sidecar_arms_full: 4,
        foundation_full_attempts: 1,
        wire_txgate_callback_before_foundation_ok: 0,
      },
      {
        case: "duplicate_runtime_same_application_instance",
        api_status: "NINLIL_OK",
        submission_state: "REJECTED",
        reason: "TARGET_COUNT_UNSUPPORTED",
        entropy_draws: 0,
        sidecar_mutations: 0,
        foundation_mutations: 0,
        compound_receiver_key: false,
      },
      {
        case: "duplicate_runtime_different_application_instance",
        api_status: "NINLIL_OK",
        submission_state: "REJECTED",
        reason: "TARGET_COUNT_UNSUPPORTED",
        entropy_draws: 0,
        sidecar_mutations: 0,
        foundation_mutations: 0,
        compound_receiver_key: false,
      },
      {
        case: "candidate_max4_exhausted_after_prior_arm",
        result: "NINLIL_E_ENTROPY",
        foundation_full_attempts: 0,
        cleanup: "CREATED_ARMS_BOUNDED_FULL",
        wire_txgate_callback: 0,
        attempt_redraw_while_unresolved: 0,
      },
      {
        case: "sidecar_arm_definite_failure",
        foundation_full_attempts: 0,
        cleanup: "CREATED_ARMS_BOUNDED_FULL",
        wire_txgate_callback: 0,
      },
      {
        case: "arm_or_cleanup_commit_unknown",
        result: "FENCE_COLD_RECONCILE",
        foundation_full_attempts: 0,
        sidecar_delete_claim: false,
        attempt_redraw: 0,
        wire_txgate_callback: 0,
      },
      {
        case: "foundation_full_definite_failure",
        foundation_full_attempts: 1,
        foundation_committed: false,
        cleanup: "ALL_ARMS_BOUNDED_FULL",
        wire_txgate_callback: 0,
      },
      {
        case: "foundation_full_commit_unknown",
        foundation_full_attempts: 1,
        result: "KEEP_ARMS_FENCE_COLD_RECONCILE",
        sidecar_delete_claim: false,
        attempt_redraw: 0,
        wire_txgate_callback: 0,
      },
      {
        case: "restart_matching_foundation_and_arms",
        result: "RESUME_SAME_ATTEMPTS",
        reconcile_before: "BEARER_OPEN",
        new_state: false,
        attempt_redraw: 0,
      },
    ];
    if (
      !deepEqual(crossNamespace.expected, crossExpected) ||
      !deepEqual(crossNamespace.steps, crossSteps) ||
      !deepEqual(crossNamespace.boundary_matrix, crossMatrix) ||
      !deepEqual(crossNamespace.observed_kinds, [
        "NMS1", "NM3S", "NRC1", "FOUNDATION_TX",
      ]) ||
      crossNamespace.note !==
        "candidate-only; no cross-namespace atomic commit or production implementation claim"
    ) {
      fail("MFDT cross-namespace admission matrix");
    }

    for (const vid of REQUIRED_VECTOR_IDS.filter((id) => id.startsWith("MF-TX-"))) {
      const entry = vectors.get(vid);
      if (vid === "MF-TX-RESUME-AFTER-RESTART") {
        const body = hx(entry.resume_state_hex, "resume");
        if (body.length !== 108) fail("resume len");
        if (!equal(body.subarray(76), sha(Buffer.concat([Buffer.from("NM3-RESUME-V1"), body.subarray(0, 76)])))) fail("resume dig");
      }
      if (vid === "MF-TX-HOST-TERMINAL-COLD-REBIND-HIT") {
        const nm30 = hx(entry.nm30_value_hex, "cold terminal NM30");
        const nrc1 = hx(entry.nrc1_value_hex, "cold terminal NRC1");
        requireValidNm30(nm30, "cold terminal NM30");
        requireValidNrc1(nrc1, "cold terminal NRC1");
        const catalog = entry.recovered_catalog_entry;
        const rebind = entry.rebind;
        const hit = entry.hit;
        const miss = entry.post_terminal_miss;
        let hitSlot = null;
        for (let index = 0; index < 72; index += 1) {
          const slot = nrc1.subarray(40 + index * 208, 40 + (index + 1) * 208);
          if (u64(slot, 0) === BigInt(hit.request_id)) {
            hitSlot = slot;
            break;
          }
        }
        const missSlot = hx(miss.nrc1_slot_hex, "post-terminal miss NRC1 slot");
        const missRequest = hx(miss.request_body_hex, "post-terminal miss request");
        const missResponse = hx(miss.response_body_hex, "post-terminal miss response");
        const missPreimage = Buffer.concat([
          Buffer.from([miss.request_type]),
          Buffer.from([(missRequest.length >> 8) & 0xff, missRequest.length & 0xff]),
          missRequest,
        ]);
        const hitResponse = hx(hit.response_body_hex, "cold hit body");
        if (catalog.transfer_id_hex !== nm30.subarray(8, 24).toString("hex") ||
            catalog.peer_endpoint_id_hex !== nm30.subarray(156, 172).toString("hex") ||
            catalog.owner_role !== nm30[172] ||
            catalog.nrc1_session_generation !== u32(nrc1, 24) ||
            catalog.nm30_schema !== 2 || catalog.replay_eligible !== true ||
            catalog.session_cookie !== 0 || catalog.bind_valid !== false ||
            rebind.peer_endpoint_id_hex !== catalog.peer_endpoint_id_hex ||
            rebind.owner_role !== catalog.owner_role ||
            rebind.session_generation !== catalog.nrc1_session_generation ||
            rebind.session_cookie_hex === "0000000000000000" || rebind.result !== "OK" ||
            hitSlot === null ||
            hitSlot.subarray(12, 44).toString("hex") !== hit.request_body_digest_hex ||
            u16(hitSlot, 44) !== hit.response_type ||
            u16(hitSlot, 46) !== hitResponse.length ||
            !equal(hitSlot.subarray(48, 48 + hitResponse.length), hitResponse) ||
            missSlot.length !== 208 || u64(missSlot, 0) !== BigInt(miss.request_id) ||
            u32(missSlot, 8) !== u32(nrc1, 24) ||
            !equal(missSlot.subarray(12, 44), sha(missPreimage)) ||
            u16(missSlot, 44) !== 0x3a || u16(missSlot, 46) !== missResponse.length ||
            !equal(missSlot.subarray(48, 48 + missResponse.length), missResponse) ||
            u16(missResponse, 54) !== 8 || miss.full_group !== "G_R_REQID_CACHE" ||
            miss.wire_after_full_only !== true ||
            entry.expected.control_route !== 0xff ||
            entry.expected.active_slots_consumed !== 0 ||
            entry.expected.cookie_restored_from_storage !== false ||
            entry.expected.nrc1_generation_offset !== 24 ||
            entry.expected.cacheable !== true || entry.expected.nrc1_hit !== true ||
            entry.expected.full_count !== 0 || entry.expected.transfer_state_mutation !== 0 ||
            entry.expected.response_bit_exact !== true ||
            entry.expected.owned_control_outbox !== true ||
            entry.expected.transport_status !== "OK" ||
            entry.expected.post_terminal_miss_cacheable !== true ||
            entry.expected.post_terminal_miss_full_count !== 1 ||
            entry.expected.post_terminal_miss_transfer_state_mutation !== 0) {
          fail("Host terminal cold rebind/hit/miss");
        }
      }
      markComplete(vid, entry, executed);
    }

    const inv = vectors.get("MF-INV-REQUIRED-IDS-INTEGRITY");
    if (inv.expected.required_count !== REQUIRED_VECTOR_IDS.length) fail("inv count");
    markComplete("MF-INV-REQUIRED-IDS-INTEGRITY", inv, executed);
    markComplete("MF-GATE-SELF-TEST-PIN", vectors.get("MF-GATE-SELF-TEST-PIN"), executed);
    // POS-only session/expiry IDs (NEG/TX loops already markComplete their families).
    const sgen = vectors.get("MF-POS-REQID-SESSION-GEN-RESUME-RECLAIM");
    const initialNrc1 = hx(sgen.generation_1_nrc1_value_hex, "session initial NRC1");
    const successorNrc1 = hx(sgen.generation_2_nrc1_value_hex, "session successor NRC1");
    requireValidNrc1(initialNrc1, "session initial NRC1");
    requireValidNrc1(successorNrc1, "session successor NRC1");
    if (sgen.initial_session_generation !== 7 ||
        sgen.successor_session_generation !== 8 ||
        u32(initialNrc1, 24) !== 7 || u32(successorNrc1, 24) !== 8 ||
        !equal(successorNrc1.subarray(40, 248), initialNrc1.subarray(40, 248)) ||
        u64(successorNrc1, 248) !== 9001n || u32(successorNrc1, 256) !== 8) {
      fail("session arbitrary initial/successor authority");
    }
    for (const field of [
      "future_generation_nrc1_value_hex",
      "gap_generation_nrc1_value_hex",
      "third_generation_nrc1_value_hex",
    ]) {
      let rejected = false;
      try { requireValidNrc1(hx(sgen[field], field), field); } catch (e) {
        if (!(e instanceof GateError)) throw e;
        rejected = true;
      }
      if (!rejected) fail(`${field}: invalid generation record accepted`);
    }
    if (sgen.expected.second_advance_status !== "CAPACITY" ||
        sgen.expected.uint32_max_advance_status !== "CAPACITY") {
      fail("session advance capacity authority");
    }
    markComplete("MF-POS-REQID-SESSION-GEN-RESUME-RECLAIM", sgen, executed);
    markComplete("MF-POS-EXPIRY-SLOT-REUSE", vectors.get("MF-POS-EXPIRY-SLOT-REUSE"), executed);
  } catch (e) {
    if (e instanceof GateError) throw e;
    fail(`structural: ${e.message || e}`);
  }
  if (executed.size !== REQUIRED_VECTOR_IDS.length) fail("executed count");
  for (const id of REQUIRED_VECTOR_IDS) if (!executed.has(id)) fail(`missing ${id}`);
  return executed;
}

function expectFail(doc, label) {
  try { validate(doc); } catch (e) { if (e instanceof GateError) return; throw e; }
  throw new Error(`self-test failed: ${label} accepted`);
}

function selfTest() {
  const raw = fs.readFileSync(VECTOR);
  const document = loadStrictJson(raw);
  validate(document);
  if (!raw.equals(fs.readFileSync(VECTOR))) throw new Error("vector mutated");

  // Permanent counterexamples: duplicate / escaped-key parity / float / NaN /
  // raw -0 / unsafe integer / adr bool / unexpected_top_level / chunk_count bool.
  try { loadStrictJson('{"a":1,"a":2}'); throw new Error("dup key"); } catch (e) { if (!(e instanceof GateError)) throw e; }
  try {
    loadStrictJson('{"status":"OK","\\u0073tatus":"BAD"}');
    throw new Error("escaped-key dup accepted");
  } catch (e) { if (!(e instanceof GateError)) throw e; }
  try { loadStrictJson('{"selected_control_version": 3.0}'); throw new Error("float"); } catch (e) { if (!(e instanceof GateError)) throw e; }
  try { loadStrictJson('{"x": NaN}'); throw new Error("nan"); } catch (e) { if (!(e instanceof GateError)) throw e; }
  try { loadStrictJson('{"chunk_count": -0}'); throw new Error("raw -0"); } catch (e) { if (!(e instanceof GateError)) throw e; }
  try { loadStrictJson('{"n": 9007199254740993}'); throw new Error("unsafe int"); } catch (e) { if (!(e instanceof GateError)) throw e; }
  {
    const adrDoc = deepClone(document);
    adrDoc.adr = true;
    expectFail(adrDoc, "adr bool true");
  }
  {
    const unexpected = deepClone(document);
    unexpected.unexpected_top_level = 1;
    expectFail(unexpected, "unexpected_top_level");
  }
  {
    const boolChunk = deepClone(document);
    for (const v of boolChunk.vectors) {
      if (v.id === "MF-POS-ONE-BYTE") { v.fixture.facts.chunk_count = true; break; }
    }
    expectFail(boolChunk, "chunk_count bool true");
  }
  // Metadata authority permanent counterexamples (hard pins; not vector-taught).
  {
    const meta = deepClone(document); meta.adr = "ADR-9999"; expectFail(meta, "adr=ADR-9999");
  }
  {
    const meta = deepClone(document); meta.title = "UNRELATED AUTHORITY"; expectFail(meta, "title");
  }
  {
    const meta = deepClone(document);
    meta.sources = ["docs/adr/does-not-exist-9999.md"];
    meta.source_sha256_hex = { "docs/adr/does-not-exist-9999.md": "00".repeat(32) };
    expectFail(meta, "nonexistent sources");
  }
  {
    const meta = deepClone(document);
    meta.nonclaims = ["SPEC_ACCEPTED", "implementation", "HIL", "RELEASE_SUPPORTED"];
    expectFail(meta, "nonclaims only 4");
  }
  {
    const meta = deepClone(document);
    meta.nonclaims = PINNED_NONCLAIMS.concat(["EXTRA_NONCLAIM"]);
    expectFail(meta, "nonclaims extra");
  }
  {
    const meta = deepClone(document);
    meta.nonclaims = PINNED_NONCLAIMS.slice().reverse();
    expectFail(meta, "nonclaims order donor");
  }
  {
    const meta = deepClone(document);
    meta.sources = [PINNED_SOURCES[1], PINNED_SOURCES[0]];
    expectFail(meta, "sources order donor");
  }
  {
    const meta = deepClone(document);
    meta.source_sha256_hex = { ...meta.source_sha256_hex, [PINNED_ADR_PATH]: "11".repeat(32) };
    expectFail(meta, "source digest donor");
  }
  try {
    loadStrictJson('{"adr":"ADR-0021","\\u0061dr":"ADR-9999"}');
    throw new Error("decoded duplicate adr accepted");
  } catch (e) { if (!(e instanceof GateError)) throw e; }
  {
    const meta = deepClone(document); delete meta.title; expectFail(meta, "missing title");
  }
  {
    const meta = deepClone(document); meta.nonclaims = "SPEC_ACCEPTED"; expectFail(meta, "nonclaims type");
  }
  {
    const sentinel = deepClone(document);
    sentinel.constants.no_deadline_u64_hex = "0000000000000000";
    expectFail(sentinel, "no-deadline sentinel drift");
  }

  const byId = Object.fromEntries(document.vectors.map((v) => [v.id, v]));
  const byFamily = {};
  for (const id of REQUIRED_VECTOR_IDS) {
    const f = familyOf(id);
    (byFamily[f] ||= []).push(id);
  }
  let sameFamilyPairs = 0;
  const assertDonor = (targetId, donorId) => {
    const row = deepClone(byId[donorId]);
    row.id = targetId;
    row.family = familyOf(targetId);
    const executed = new Set();
    try {
      if (familyOf(targetId) === "positive" && row.fixture) {
        try { validatePositiveFixture(row); } catch (e) { if (e instanceof GateError) return; throw e; }
      }
      if (familyOf(targetId) === "commit_unknown" && row.old_rows) {
        const c = classifyCommitUnknown(row.old_rows, row.new_rows, row.observed_rows);
        if (c !== AUTHORITY[targetId].expected.classification) return;
      }
      markComplete(targetId, row, executed);
      throw new Error(`donor accepted ${targetId}<={donorId}`);
    } catch (e) {
      if (e instanceof GateError) return;
      throw e;
    }
  };
  for (const members of Object.values(byFamily)) {
    for (const t of members) for (const d of members) {
      if (t === d) continue;
      assertDonor(t, d);
      sameFamilyPairs += 1;
    }
  }
  const expectedPairs = Object.values(byFamily).reduce((a, m) => a + m.length * (m.length - 1), 0);
  if (sameFamilyPairs !== expectedPairs) throw new Error(`pairs ${sameFamilyPairs}!=${expectedPairs}`);

  // Byte corruptions on ONE-BYTE
  const xor = (hex, i = 0) => {
    const b = Buffer.from(hex, "hex"); b[i] ^= 1; return b.toString("hex");
  };
  for (const [label, mut] of [
    ["page0", (v) => { v.fixture.pages[0].body_hex = xor(v.fixture.pages[0].body_hex); }],
    ["chunk0", (v) => { v.fixture.chunks[0].body_hex = xor(v.fixture.chunks[0].body_hex); }],
    ["open_accept", (v) => { v.fixture.open_accept_hex = xor(v.fixture.open_accept_hex); }],
    ["finalize", (v) => { v.fixture.finalize_hex = xor(v.fixture.finalize_hex); }],
    ["pages empty", (v) => { v.fixture.pages = []; }],
  ]) {
    const d = deepClone(document);
    for (const v of d.vectors) if (v.id === "MF-POS-ONE-BYTE") mut(v);
    expectFail(d, label);
  }
  // accept transfer_id mutation + digest repair
  {
    const d = deepClone(document);
    for (const v of d.vectors) {
      if (v.id !== "MF-POS-ONE-BYTE") continue;
      const accept = Buffer.from(v.fixture.transfer_accept_hex, "hex");
      accept[0] ^= 1;
      const dig = sha(Buffer.concat([Buffer.from("NM3-ACCEPT-V1"), accept.subarray(0, 128)]));
      dig.copy(accept, 128);
      v.fixture.transfer_accept_hex = accept.toString("hex");
    }
    expectFail(d, "accept tid repaired");
  }

  if (document.constants.chunk_size !== GATE_INDEPENDENT_CONSTANTS.chunk_size) throw new Error("const drift");
  if (document.budget.receiver_fulls_max_transfer !== GATE_INDEPENDENT_CONSTANTS.receiver_fulls_max_transfer) throw new Error("budget drift");
  if (!raw.equals(fs.readFileSync(VECTOR))) throw new Error("mutated end");
  console.log(`self-test OK same_family_pairs=${sameFamilyPairs} authority_ids=${REQUIRED_VECTOR_IDS.length} map_sha=${AUTHORITY_MAP_SHA256_HEX}`);
}

function main() {
  const mode = process.argv[2];
  if (mode === "--self-test") { selfTest(); return; }
  if (mode !== "--check") { console.error("usage: --check|--self-test"); process.exit(2); }
  const document = loadStrictJson(fs.readFileSync(VECTOR));
  const executed = validate(document);
  console.log(`OK vectors=${executed.size} authority_ids=${Object.keys(AUTHORITY).length} map_sha=${AUTHORITY_MAP_SHA256_HEX} sha256=${shaHex(fs.readFileSync(VECTOR))}`);
}

try { main(); } catch (e) {
  if (e instanceof GateError) { console.error(`GATE FAIL: ${e.message}`); process.exit(2); }
  console.error(e); process.exit(1);
}
