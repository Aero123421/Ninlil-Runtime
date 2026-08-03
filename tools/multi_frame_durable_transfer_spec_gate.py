#!/usr/bin/env python3
"""Independent Python semantic gate for ADR-0021 multi-frame durable transfer.

Hard-coded per-ID authority map binds each required ID to exact expected semantics
and a canonical authority fingerprint. executed.add runs only after assertions.
Does not import the generator or production code. Source vector is read-only.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "spec/vectors/multi-frame-durable-transfer-spec-v1.json"

REQUIRED_VECTOR_IDS: tuple[str, ...] = (
    'MF-CONSTANTS-PINNED',
    'MF-VERSION-CATALOG-INHERITANCE',
    'MF-CARRIER-MAPPING-MATRIX',
    'MF-PUBLICATION-OWNER-MATRIX',
    'MF-ROLE-BOUNDARIES',
    'MF-PRIVATE-API-SURFACE',
    'MF-FSM-STORAGE-SIDECAR-PROFILE',
    'MF-POS-OPEN-APPLICATION-BINDING-LAYOUT-KAT',
    'MF-NEG-OPEN-APPLICATION-BINDING-FIELD-MUTATION',
    'MF-NEG-CARRIER-OPEN-BINDING-MISMATCH-PREFULL',
    'MF-NEG-ADMISSION-REV1-REV2-MIXED',
    'MF-POS-APPLICATION-EVIDENCE-DIGEST-KAT',
    'MF-BUDGET-ARITHMETIC-REFERENCE',
    'MF-BUDGET-EMPTY-TRANSFER',
    'MF-BUDGET-OBSOLETE-80-REJECTED',
    'MF-BUDGET-RESTORATION-HASH',
    'MF-BUDGET-NRC1-LOGICAL-BYTES',
    'MF-BUDGET-FULL-MAX-WITH-REQID',
    'MF-POS-EMPTY-PAYLOAD',
    'MF-POS-ONE-BYTE',
    'MF-POS-EXACT-MULTIPLE-FINAL',
    'MF-POS-ONE-BYTE-FINAL',
    'MF-POS-MAX-PAYLOAD-37-CHUNKS',
    'MF-POS-TWO-PAGE-MANIFEST',
    'MF-POS-COMPLETION-RECEIPT-REPLAY',
    'MF-POS-REQID-CACHE-SAME-ID-STABLE',
    'MF-POS-REQID-NEW-ID-CURRENT-COMPLETE',
    'MF-POS-REQID-NRC1-LAYOUT-KAT',
    'MF-POS-REQID-MAX-TRANSFER-OCCUPIED-41',
    'MF-POS-REQID-RETRY-BUDGET-SM',
    'MF-POS-REQID-REACHABLE-MAX-COUNT',
    'MF-POS-REQID-SESSION-GEN-RESUME-RECLAIM',
    'MF-NEG-REQID-TWO-GEN-NO-RECLAIM-CAPACITY',
    'MF-POS-REQID-MAX-RETRY-TRACE',
    'MF-POS-REQID-TERMINAL-LATE-DUP-MATRIX',
    'MF-POS-NM30-SCHEMA2-LAYOUT-KAT',
    'MF-NEG-NM30-SCHEMA1-COLD-REPLAY-DENY',
    'MF-TX-HOST-TERMINAL-COLD-REBIND-HIT',
    'MF-NEG-HOST-TERMINAL-BIND-MATRIX',
    'MF-POS-HOST-FOUR-ACTIVE-TERMINAL-HIT',
    'MF-NEG-HOST-FOUR-ACTIVE-FRESH-OPEN-BUSY',
    'MF-NEG-HOST-CONTROL-OUTBOX-BACKPRESSURE',
    'MF-NEG-PREADMISSION-POLICY-STATELESS',
    'MF-NEG-PREADMISSION-DEADLINE-STATELESS',
    'MF-NEG-ACTIVE-SEMANTIC-REJECT-CACHED',
    'MF-FSM-TERMINAL-ACTIVE-CODES-UNREACHABLE',
    'MF-TRACE-S1-S6-HAPPY-PATH',
    'MF-NEG-STALE-GENERATION',
    'MF-NEG-STALE-VERSION-SELECTED-2',
    'MF-NEG-MIXED-VERSION-PEER',
    'MF-NEG-RF-MAPPING-UNAVAILABLE',
    'MF-NEG-WIFI-MAPPING-UNAVAILABLE',
    'MF-NEG-NFL1-CONTROL-FORBIDDEN',
    'MF-NEG-DUPLICATE-CHUNK-CONFLICT',
    'MF-NEG-REORDER-GAP',
    'MF-NEG-DIGEST-CORRUPTION-REPAIRED',
    'MF-NEG-WHOLE-DIGEST-MISMATCH',
    'MF-NEG-EXPIRY-BOUNDARY-EQ',
    'MF-NEG-EXPIRY-BOUNDARY-BEFORE',
    'MF-NEG-ABORT-AFTER-CONTENT-VERIFIED',
    'MF-NEG-ABORT-RACE-FINALIZE-FIRST',
    'MF-NEG-ABORT-RACE-ABORT-FIRST',
    'MF-NEG-PARTIAL-APPLY-FORBIDDEN',
    'MF-NEG-FALSE-CUSTODY-BITMAP',
    'MF-NEG-RESOURCE-EXHAUSTION-KEYS',
    'MF-NEG-RESOURCE-EXHAUSTION-BYTES',
    'MF-NEG-FAIRNESS-TWO-OUTSTANDING',
    'MF-NEG-MAX-CHUNKS-PLUS-ONE',
    'MF-NEG-DEFAULT-OFF-POLICY',
    'MF-NEG-STORAGE-SIDECAR-COLLISION',
    'MF-NEG-REQID-BODY-CONFLICT',
    'MF-NEG-REQID-CACHE-FULL',
    'MF-NEG-REQID-DIGEST-OPEN-PREIMAGE',
    'MF-NEG-REQID-POST-RETENTION-EXPIRED',
    'MF-NEG-EPOCH-CHANGE-MID-TRANSFER',
    'MF-CU-STORAGE-BINDING-NEW',
    'MF-CU-STORAGE-BINDING-PARTIAL',
    'MF-CU-STORAGE-BINDING-EXTRA',
    'MF-CU-STORAGE-BINDING-THIRD',
    'MF-CU-STORAGE-BINDING-ABSENT',
    'MF-CU-RECEIVER-CHUNK-OLD',
    'MF-CU-RECEIVER-CHUNK-NEW',
    'MF-CU-RECEIVER-CHUNK-PARTIAL',
    'MF-CU-RECEIVER-CHUNK-EXTRA',
    'MF-CU-RECEIVER-CHUNK-THIRD',
    'MF-CU-RECEIVER-CHUNK-ABSENT',
    'MF-CU-TERMINAL-GROUP-OLD',
    'MF-CU-TERMINAL-GROUP-NEW',
    'MF-CU-TERMINAL-GROUP-PARTIAL',
    'MF-CU-TERMINAL-GROUP-EXTRA',
    'MF-CU-TERMINAL-GROUP-THIRD',
    'MF-CU-TERMINAL-GROUP-ABSENT',
    'MF-CU-TERMINAL-GROUP-BOTH',
    'MF-CU-NRC1-ABSENT-MID-TRANSFER',
    'MF-CU-NRC1-OLD',
    'MF-CU-NRC1-NEW',
    'MF-CU-NRC1-PARTIAL',
    'MF-CU-NRC1-EXTRA',
    'MF-CU-NRC1-THIRD',
    'MF-CU-NRC1-ABSENT-POST-TERMINAL',
    'MF-TX-CROSS-NAMESPACE-ADMISSION-MATRIX',
    'MF-TX-EXPIRY-MANDATORY-TOMBSTONE',
    'MF-POS-EXPIRY-SLOT-REUSE',
    'MF-TX-POWER-CUT-AFTER-CHUNK-FULL',
    'MF-TX-POWER-CUT-AFTER-CONTENT-VERIFIED',
    'MF-TX-POWER-CUT-DURING-TERMINAL',
    'MF-TX-RESUME-AFTER-RESTART',
    'MF-TX-CLEANUP-RETENTION-GC',
    'MF-TX-ROLLBACK-POLICY-OFF',
    'MF-TX-TERMINAL-CRASH-ACTIVE-ONLY',
    'MF-TX-TERMINAL-CRASH-NM30-ONLY',
    'MF-TX-EPOCH-CHANGE-TERMINAL',
    'MF-TX-REQID-CACHE-CRASH-RESTART',
    'MF-TX-REQID-TERMINAL-RESTART-LATE-DUP',
    'MF-INV-REQUIRED-IDS-INTEGRITY',
    'MF-GATE-SELF-TEST-PIN',
)




# Authority seal SHA covers hard-pinned metadata + source digests + per-ID index.
# Not equal to the legacy index-only map hash.
AUTHORITY_MAP_SHA256_HEX = "169ca9605a46222fd582bee3207f5c223dccb9400cf6e1fb52923276ef23a48f"

# Independently hard-pinned machine metadata (gates do not learn these from vector).
PINNED_SCHEMA = "ninlil.multi-frame-durable-transfer.spec.v1"
PINNED_STATUS = "SPEC_ACCEPTED"
PINNED_ADR = "ADR-0021"
PINNED_ADR_PATH = "docs/adr/0021-multi-frame-durable-custody.md"
PINNED_TITLE = (
    "Multi-frame Durable Transfer / full fragmentation design authority"
)
PINNED_NONCLAIMS: tuple[str, ...] = (
    "implementation",
    "HIL",
    "RELEASE_SUPPORTED",
    "public_abi",
    "compact_rf_mapping",
    "wifi_mapping",
    "docs_25_26_refreeze_done",
    "application_handoff_implementation",
    "nts3_schema_1_2_implementation",
)
PINNED_SOURCES: tuple[str, ...] = (
    PINNED_ADR_PATH,
    "tools/multi_frame_durable_transfer_spec_vector_gen.py",
)
# Source content digests: ADR + generator. Gates pin both. Generator pins only ADR
# (avoids self-circular self-SHA inside the generator file).
PINNED_SOURCE_SHA256_HEX: dict[str, str] = {
    PINNED_ADR_PATH: "39e010f2e31b13fffd198af39ac993a1a4a4173c68fbe99c5d6e409684a74049",
    "tools/multi_frame_durable_transfer_spec_vector_gen.py": (
        "ffe0b4ea350508eb72c9cb815401bba800ba316d53193f80cc2a9c144cd4679e"
    ),
}

AUTHORITY: dict[str, dict[str, Any]] = {'MF-BUDGET-ARITHMETIC-REFERENCE': {'authority_fingerprint_hex': 'dda356b0f772334c5448dc39b190ed02b2a2334345011c0cfa46ce67c46d0a4d',
                                    'expected': {'receiver_fulls': 77,
                                                 'required_receiver_reference': 154,
                                                 'required_sender_reference': 134,
                                                 'sender_fulls': 67,
                                                 'status': 'OK'},
                                    'family': 'budget'},
 'MF-BUDGET-EMPTY-TRANSFER': {'authority_fingerprint_hex': '713b328f3586e4bf4de86e944f51c2ad874cff360b9dba6957624c7e1c2bf178',
                              'expected': {'receiver_fulls': 5, 'sender_fulls': 5, 'status': 'OK'},
                              'family': 'budget'},
 'MF-BUDGET-FULL-MAX-WITH-REQID': {'authority_fingerprint_hex': 'df1f6c07d3bc75d8c28ccc3af927607c6aa4630234bbae0ee313324f91ce26d9',
                                   'expected': {'branch': 'full_max_with_reqid',
                                                'nrc1_retained_until_gc': True,
                                                'obsolete_80_infeasible': True,
                                                'receiver_base': 44,
                                                'receiver_fulls': 77,
                                                'receiver_reqid_cache': 16,
                                                'receiver_resume': 8,
                                                'required_receiver_reference': 154,
                                                'required_sender_reference': 134,
                                                'sender_base': 42,
                                                'sender_fulls': 67,
                                                'sender_reqid_cache': 8,
                                                'sender_resume': 8,
                                                'status': 'OK',
                                                'terminal_erases_nrc1': False},
                                   'family': 'budget'},
 'MF-BUDGET-NRC1-LOGICAL-BYTES': {'authority_fingerprint_hex': '35d49d2f1511682252dfb43f4e6fcaef327902ccd0ff7b3d3af5b4e3198535b4',
                                  'expected': {'admission_reserved_entries': 3,
                                               'admission_reserved_logical_bytes': 50519,
                                               'branch': 'nrc1_budget',
                                               'capacity_spare': 7,
                                               'esp_active_transfers_max': 1,
                                               'fixed16_rejected': True,
                                               'happy_path_max_ids': 41,
                                               'host_active_transfers_max': 4,
                                               'host_begin_final_union_logical_bytes_hard_max': 434779,
                                               'host_committed_logical_bytes_hard_max': 384476,
                                               'host_four_active_committed_logical_bytes': 201212,
                                               'logical_bytes': 15056,
                                               'n_abort': 64,
                                               'n_complete': 65,
                                               'naive_union_not_single_path': 57,
                                               'reachable_max_ids': 65,
                                               'slot_bytes': 208,
                                               'slot_count': 72,
                                               'slot_count_ge_reachable': True,
                                               'status': 'OK',
                                               'timeout_retry_max': 8,
                                               'value_bytes': 15020},
                                  'family': 'budget'},
 'MF-BUDGET-OBSOLETE-80-REJECTED': {'authority_fingerprint_hex': 'ac0839abf90dc46ed571bf754a1c76c87eac42b178d898c0e1daff5b79361423',
                                    'expected': {'obsolete_cap': 80,
                                                 'reason': 'OBSOLETE_80_INFEASIBLE',
                                                 'required_receiver_fulls': 154,
                                                 'status': 'REJECT'},
                                    'family': 'budget'},
 'MF-BUDGET-RESTORATION-HASH': {'authority_fingerprint_hex': '1f307334ede3b7000614aebdf9e79b399d1f08363b8c8ff204ae8ea71c97848e',
                                'expected': {'restoration_sha256_hex': '7833c693c278cef6d59fa742a3b94e678378b7ca32d1ee0184a0fef7e9a6f2f5',
                                             'status': 'OK'},
                                'family': 'budget'},
 'MF-CARRIER-MAPPING-MATRIX': {'authority_fingerprint_hex': '2ad800c69a4ac3eca95b4bfa82d467afdd48825ad3686890d90fe579d5bb7220',
                               'expected': {'fabric': 'MAPPING_CANDIDATE',
                                            'ncl1': 'MAPPING_CANDIDATE',
                                            'rf': 'MAPPING_UNAVAILABLE',
                                            'status': 'OK',
                                            'wifi': 'MAPPING_UNAVAILABLE'},
                               'family': 'catalog'},
 'MF-CONSTANTS-PINNED': {'authority_fingerprint_hex': '6fa255cd38ec25cd53bf621f0a3dc58f109d11beff61dad4eaab115d4e7b55b0',
                         'expected': {'branch': 'constants', 'status': 'OK'},
                         'family': 'catalog'},
 'MF-CU-NRC1-ABSENT-MID-TRANSFER': {'authority_fingerprint_hex': '20429e037a8c9e8435388b350a4bbde01f72686cc7a0010c9ecda8a8a0a0c194',
                                    'expected': {'action': 'CORRUPT_fence',
                                                 'classification': 'ABSENT',
                                                 'reason': 'nrc1_missing_after_prior_success',
                                                 'send_or_accept': 0,
                                                 'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                                 'wire_success': 0},
                                    'family': 'commit_unknown'},
 'MF-CU-NRC1-ABSENT-POST-TERMINAL': {'authority_fingerprint_hex': '477b60c7a009b8e2782d7defe8c92dbb2a9b78e62089fec3c38f49ea7904c502',
                                     'expected': {'action': 'CORRUPT_fence',
                                                  'classification': 'ABSENT',
                                                  'nm30_alone_cannot_synthesize_response': True,
                                                  'nrc1_retained_post_terminal': True,
                                                  'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                                  'wire_success': 0},
                                     'family': 'commit_unknown'},
 'MF-CU-NRC1-EXTRA': {'authority_fingerprint_hex': '300f28ad85cf011444df64bbc18d6dfa1807eb0265804c193df5b9ec481c29e6',
                      'expected': {'action': 'CORRUPT_fence',
                                   'classification': 'EXTRA',
                                   'nm30_alone_cannot_synthesize_response': True,
                                   'nrc1_retained_post_terminal': True,
                                   'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                   'wire_success': 0},
                      'family': 'commit_unknown'},
 'MF-CU-NRC1-NEW': {'authority_fingerprint_hex': 'fa5797f1a2f8a66a4fa8945e851e7f483dd8ba160dc69269e23a0ae5285fcec2',
                    'expected': {'action': 'adopt_new_state_no_target_replay_before_attestation',
                                 'attestation_magic_only_accepted': False,
                                 'classification': 'NEW',
                                 'host_full_capable_replay': 'OK',
                                 'nm30_alone_cannot_synthesize_response': True,
                                 'nrc1_retained_post_terminal': True,
                                 'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                 'target_active_plus_nrc1_replay': 'COMMIT_UNKNOWN',
                                 'target_cold_restart_retry': 'COMMIT_UNKNOWN',
                                 'target_nrc1_only_replay': 'COMMIT_UNKNOWN',
                                 'target_same_id_retry': 'COMMIT_UNKNOWN',
                                 'wire_success': 0},
                    'family': 'commit_unknown'},
 'MF-CU-NRC1-OLD': {'authority_fingerprint_hex': '6c72792fdb8e28eb5813799d1785bb0eb365a0de3c0165277bb519e711f081ec',
                    'expected': {'action': 'replay_bit_exact_from_nrc1',
                                 'classification': 'OLD',
                                 'nm30_alone_cannot_synthesize_response': True,
                                 'nrc1_retained_post_terminal': True,
                                 'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                 'wire_success': 0},
                    'family': 'commit_unknown'},
 'MF-CU-NRC1-PARTIAL': {'authority_fingerprint_hex': 'aaf6b588b99193ca726bd11795a8606ff3cb3c462ec769d1e8c057795a944725',
                        'expected': {'action': 'CORRUPT_fence',
                                     'classification': 'PARTIAL',
                                     'nm30_alone_cannot_synthesize_response': True,
                                     'nrc1_retained_post_terminal': True,
                                     'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                     'wire_success': 0},
                        'family': 'commit_unknown'},
 'MF-CU-NRC1-THIRD': {'authority_fingerprint_hex': '22c98535dfcb9ed5a75e730d7132ae17d24a8c9a4cc042522513e4ca4e54bdd0',
                      'expected': {'action': 'CORRUPT_fence',
                                   'classification': 'THIRD',
                                   'nm30_alone_cannot_synthesize_response': True,
                                   'nrc1_retained_post_terminal': True,
                                   'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                   'wire_success': 0},
                      'family': 'commit_unknown'},
 'MF-CU-RECEIVER-CHUNK-ABSENT': {'authority_fingerprint_hex': '1311b2d6b873eda2983dfcbe52ae1cef0e3b67dd302a0e7606a7aebd9607cee9',
                                 'expected': {'classification': 'ABSENT',
                                              'send_or_accept': 0,
                                              'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                              'wire_success': 0},
                                 'family': 'commit_unknown'},
 'MF-CU-RECEIVER-CHUNK-EXTRA': {'authority_fingerprint_hex': '142ee4117eae17bc9f414ae44e0bc4028a5ea4a69c98e3881ed3110c9ac22a8a',
                                'expected': {'classification': 'EXTRA',
                                             'send_or_accept': 0,
                                             'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                             'wire_success': 0},
                                'family': 'commit_unknown'},
 'MF-CU-RECEIVER-CHUNK-NEW': {'authority_fingerprint_hex': '314d3b47f23e89468bdac5174af4109dd8b25007ac20dedac3b1effa9e7823dd',
                              'expected': {'classification': 'NEW',
                                           'send_or_accept': 0,
                                           'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                           'wire_success': 0},
                              'family': 'commit_unknown'},
 'MF-CU-RECEIVER-CHUNK-OLD': {'authority_fingerprint_hex': '4487e9662149ae1c8cc4be233b4f313782e8371c982f04e2a48f658d8609e68e',
                              'expected': {'classification': 'OLD',
                                           'send_or_accept': 0,
                                           'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                           'wire_success': 0},
                              'family': 'commit_unknown'},
 'MF-CU-RECEIVER-CHUNK-PARTIAL': {'authority_fingerprint_hex': '8c0e670ca8b071290221d60b7c1bf8e7a4ccf02dd3e1bc0f8292c080ab7c24a0',
                                  'expected': {'classification': 'PARTIAL',
                                               'send_or_accept': 0,
                                               'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                               'wire_success': 0},
                                  'family': 'commit_unknown'},
 'MF-CU-RECEIVER-CHUNK-THIRD': {'authority_fingerprint_hex': '130f0a5565b23f3b19af40124e8111dcae9f201ca4b1a6d1a8b298acd7e4ef75',
                                'expected': {'classification': 'THIRD',
                                             'send_or_accept': 0,
                                             'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                             'wire_success': 0},
                                'family': 'commit_unknown'},
 'MF-CU-STORAGE-BINDING-ABSENT': {'authority_fingerprint_hex': '64ca06b3a4c554c78a3449ec689ff66f7b53b009c3c8f52823378eb942242e15',
                                  'expected': {'classification': 'ABSENT',
                                               'foundation_mutation': 0,
                                               'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                               'wire_success': 0},
                                  'family': 'commit_unknown'},
 'MF-CU-STORAGE-BINDING-EXTRA': {'authority_fingerprint_hex': '87d178076f53727734d984ffe360b8427699aeb4b24b78b029703125d439322a',
                                 'expected': {'classification': 'EXTRA',
                                              'foundation_mutation': 0,
                                              'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                              'wire_success': 0},
                                 'family': 'commit_unknown'},
 'MF-CU-STORAGE-BINDING-NEW': {'authority_fingerprint_hex': '4c4fadb648b2f100b88057648d8d88d1f8ae51663291937750b0dd6e60fba222',
                               'expected': {'classification': 'NEW',
                                            'foundation_mutation': 0,
                                            'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                            'wire_success': 0},
                               'family': 'commit_unknown'},
 'MF-CU-STORAGE-BINDING-PARTIAL': {'authority_fingerprint_hex': '665e3b24693241fd1a789e8b45c0a6899639624159f7c32640a61cdf2c0ebc04',
                                   'expected': {'classification': 'PARTIAL',
                                                'foundation_mutation': 0,
                                                'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                                'wire_success': 0},
                                   'family': 'commit_unknown'},
 'MF-CU-STORAGE-BINDING-THIRD': {'authority_fingerprint_hex': '9f26a30990f43fc4792aedae5b99af2c84c674bf27647b8d999ccb101eda21fb',
                                 'expected': {'classification': 'THIRD',
                                              'foundation_mutation': 0,
                                              'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                              'wire_success': 0},
                                 'family': 'commit_unknown'},
 'MF-CU-TERMINAL-GROUP-ABSENT': {'authority_fingerprint_hex': '1114f60ab947e11f580fc6fbe812bb1da6d5782968eb71342d44af19fa003fe8',
                                 'expected': {'classification': 'ABSENT',
                                              'send_or_accept': 0,
                                              'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                              'wire_success': 0},
                                 'family': 'commit_unknown'},
 'MF-CU-TERMINAL-GROUP-BOTH': {'authority_fingerprint_hex': 'ae7ba2c5f196babb50cfdd708e5dbbb9343abbdc6c2cf344acfae3da21047679',
                               'expected': {'classification': 'BOTH',
                                            'send_or_accept': 0,
                                            'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                            'wire_success': 0},
                               'family': 'commit_unknown'},
 'MF-CU-TERMINAL-GROUP-EXTRA': {'authority_fingerprint_hex': '44b4e17807eed9a365ad88159681530865f8a032cba49c91d938149b606eb44b',
                                'expected': {'classification': 'EXTRA',
                                             'send_or_accept': 0,
                                             'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                             'wire_success': 0},
                                'family': 'commit_unknown'},
 'MF-CU-TERMINAL-GROUP-NEW': {'authority_fingerprint_hex': '04dd0912e7c5c4d48afecefdc7ea36c126b93ee5c5902f7673e2dec8fa8a3d86',
                              'expected': {'classification': 'NEW',
                                           'send_or_accept': 0,
                                           'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                           'wire_success': 0},
                              'family': 'commit_unknown'},
 'MF-CU-TERMINAL-GROUP-OLD': {'authority_fingerprint_hex': '888526b853b28a5a0f11c3a2f9325d8a1055ce48edf9c2cdc8b9ff18ec8f0c2e',
                              'expected': {'classification': 'OLD',
                                           'send_or_accept': 0,
                                           'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                           'wire_success': 0},
                              'family': 'commit_unknown'},
 'MF-CU-TERMINAL-GROUP-PARTIAL': {'authority_fingerprint_hex': '4bbd8af73a0c11f9f11e79a85520b8006b46ea531dfb6443972960473e71955a',
                                  'expected': {'classification': 'PARTIAL',
                                               'send_or_accept': 0,
                                               'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                               'wire_success': 0},
                                  'family': 'commit_unknown'},
 'MF-CU-TERMINAL-GROUP-THIRD': {'authority_fingerprint_hex': 'fa40ccb60c830a153040b70f741fc85092732beb3b3cccba105ec498dbc45141',
                                'expected': {'classification': 'THIRD',
                                             'send_or_accept': 0,
                                             'status': 'COMMIT_UNKNOWN_CLASSIFIED',
                                             'wire_success': 0},
                                'family': 'commit_unknown'},
 'MF-FSM-STORAGE-SIDECAR-PROFILE': {'authority_fingerprint_hex': 'd57e4992eb76beff18980d3a5d557bc67522dd927c4118062a4ba8842a604390',
                                    'expected': {'active_schema1_replay_eligible': False,
                                                 'binding_value_max': 307,
                                                 'binding_value_min': 53,
                                                 'branch': 'derived_sidecar_binding_profile',
                                                 'collision_fail_closed': True,
                                                 'cross_namespace_atomic_commit_claimed': False,
                                                 'derived_namespace_length': 36,
                                                 'destroy_close_order': ['BEARER',
                                                                         'MFDT_SIDECAR',
                                                                         'FOUNDATION_STORAGE'],
                                                 'foundation_scanner_value_max': 4096,
                                                 'mfdt_active_record_schema': 2,
                                                 'mfdt_active_value_max': 35211,
                                                 'nrc1_value_bytes': 15020,
                                                 'same_handle_forbidden': True,
                                                 'status': 'OK'},
                                    'family': 'catalog'},
 'MF-FSM-TERMINAL-ACTIVE-CODES-UNREACHABLE': {'authority_fingerprint_hex': '8f5b4f442959f16dcc6d5b4e5590e4ad19cb36d7c97fbfe01f6f3ce73e5de6be',
                                              'expected': {'both_active_and_nm30': 'CORRUPT',
                                                           'branch': 'fsm_terminal_active_removed',
                                                           'durable_active_forbidden_codes': [7, 9, 39],
                                                           'durable_terminal_kind': 'NM30_ONLY',
                                                           'status': 'OK'},
                                              'family': 'catalog'},
 'MF-GATE-SELF-TEST-PIN': {'authority_fingerprint_hex': '9b7783fe3cb78bc063abee8f85dbe5da860a59e5dd8df1159ca1ec861826f7eb',
                           'expected': {'gate_must_reject_duplicate_id': True,
                                        'gate_must_reject_extra_id': True,
                                        'gate_must_reject_missing_id': True,
                                        'gate_must_reject_substituted_id': True,
                                        'mutations_repair_digest': True,
                                        'status': 'OK'},
                           'family': 'catalog'},
 'MF-INV-REQUIRED-IDS-INTEGRITY': {'authority_fingerprint_hex': '1f4dc5749d250fce20944e02d5ace9dc72e3c309b86c5ebb638dc84c35748dd9',
                                   'expected': {'duplicate_count': 0, 'required_count': 116, 'status': 'OK'},
                                   'family': 'catalog'},
 'MF-NEG-ABORT-AFTER-CONTENT-VERIFIED': {'authority_fingerprint_hex': 'f6f977e108f3488f30c2137bdc156060621a3528ef8a905f78a0015542cc8fac',
                                         'expected': {'reason': 'receiver_already_content_verified',
                                                      'reject_code': 10,
                                                      'stage': 6,
                                                      'status': 'REJECT'},
                                         'family': 'negative'},
 'MF-NEG-ABORT-RACE-ABORT-FIRST': {'authority_fingerprint_hex': '9e9aae774b718df70cedfcfa892eed810565748f5b631192999c0ecf372c16b3',
                                   'expected': {'abort_ack_hex': '9e7c9d4b8f7fd07d4849d5a88ca349e200000001ac79ca0089d32eb4a4e02ce9f097f8a055fc6bc89fe70c4b91e658c2ca8491f70000000100020000d3cf20daca6b1410feef9e22238584deedc18d3ae8a149d908710782bb2d2c06',
                                                'branch': 'aborted_terminal',
                                                'status': 'OK',
                                                'tombstone_digest_hex': 'd3cf20daca6b1410feef9e22238584deedc18d3ae8a149d908710782bb2d2c06',
                                                'winner': 'ABORT_FULL'},
                                   'family': 'negative'},
 'MF-NEG-ABORT-RACE-FINALIZE-FIRST': {'authority_fingerprint_hex': '2ecd7cbbd6bc1d2e8f1fb4def083cb7484a1a298423365d6e9d59f3f6cbe0165',
                                      'expected': {'reject_code': 10, 'status': 'REJECT', 'winner': 'FINALIZE_FULL'},
                                      'family': 'negative'},
 'MF-NEG-ACTIVE-SEMANTIC-REJECT-CACHED': {'authority_fingerprint_hex': '42186184d24e10096da8ee22064d456aa035f867655968f33e9b86aa1e51546c',
                                          'expected': {'active_group_present': True,
                                                       'branch': 'active_semantic_reject_cached',
                                                       'cacheable': True,
                                                       'durable_cache_mutation': 1,
                                                       'nrc1_full_count': 1,
                                                       'nrc1_miss': True,
                                                       'owned_active_slot_outbox': True,
                                                       'reject_code': 8,
                                                       'response_body_length': 60,
                                                       'semantic_response_type': 58,
                                                       'status': 'OK',
                                                       'transfer_state_mutation': 0,
                                                       'transport_status': 'OK',
                                                       'uses_control_outbox': False,
                                                       'wire_after_full_only': True},
                                          'family': 'negative'},
 'MF-NEG-ADMISSION-REV1-REV2-MIXED': {'authority_fingerprint_hex': 'f9d35e0d4fd4bfbccf29b6d7e6fe061e1622133bfb7b29b3b6f6e73a749c7f7b',
                                      'expected': {'durable_state_mutation': 0,
                                                   'full_count': 0,
                                                   'migration_attempted': False,
                                                   'reason': 'admission_profile_or_active_schema_revision_mismatch',
                                                   'reject_code': 4,
                                                   'status': 'REJECT'},
                                      'family': 'negative'},
 'MF-NEG-CARRIER-OPEN-BINDING-MISMATCH-PREFULL': {'authority_fingerprint_hex': '5fceb1124a4e5e5993ed5e29fb531a57b6102582de2930962828f84201b66c04',
                                                  'expected': {'callback_count': 0,
                                                               'durable_rows_created': 0,
                                                               'durable_state_mutation': 0,
                                                               'full_count': 0,
                                                               'reason': 'pre_full_application_handoff_boundary_reject',
                                                               'receipt_count': 0,
                                                               'reject_code': 9,
                                                               'stage': 1,
                                                               'status': 'REJECT'},
                                                  'family': 'negative'},
 'MF-NEG-DEFAULT-OFF-POLICY': {'authority_fingerprint_hex': '38bde5d5966456455d011e17ab28a00092a3ae94c4b87027a7aa98fd72e968b1',
                               'expected': {'reason': 'mf_policy_default_off', 'reject_code': 4, 'status': 'REJECT'},
                               'family': 'negative'},
 'MF-NEG-DIGEST-CORRUPTION-REPAIRED': {'authority_fingerprint_hex': '2b94f3f1279d87bab8d755079cee3ea198ce6e96c7706677566f0db361bb32f3',
                                       'expected': {'manifest_digest_hex': 'c421858f87a9029f499c6719fc83a64ab585e01a78b12c2efb2102b6fa07c2bd',
                                                    'reason': 'whole_content_digest_mismatch_vs_bytes',
                                                    'reject_code': 2,
                                                    'status': 'REJECT'},
                                       'family': 'negative'},
 'MF-NEG-DUPLICATE-CHUNK-CONFLICT': {'authority_fingerprint_hex': 'a64b7fdab1874856b37d2c7443b2590d3ec5ea83a278f344ffb834f1ebc435e8',
                                     'expected': {'reason': 'same_index_different_bytes',
                                                  'reject_code': 2,
                                                  'stage': 3,
                                                  'status': 'TERMINAL_CONFLICT'},
                                     'family': 'negative'},
 'MF-NEG-EPOCH-CHANGE-MID-TRANSFER': {'authority_fingerprint_hex': '3e79329b79829267822c339c15d357373b4243b48f8db5e91a52ae5aca0c8872',
                                      'expected': {'prepare_forbidden': True,
                                                   'publication_after': 'NONE',
                                                   'reason': 'local_clock_epoch_changed',
                                                   'reject_code': 8,
                                                   'status': 'REJECT'},
                                      'family': 'negative'},
 'MF-NEG-EXPIRY-BOUNDARY-BEFORE': {'authority_fingerprint_hex': '979f37cdc3fe049ac98d733a396408d5598add2c9ab1a35763a34bec0b89476d',
                                   'expected': {'branch': 'reservation_valid', 'status': 'OK'},
                                   'family': 'negative'},
 'MF-NEG-EXPIRY-BOUNDARY-EQ': {'authority_fingerprint_hex': 'afa8581f9705a080b511d1fcd3fa747b8f9fdce658c02510e81b61a25a406ad4',
                               'expected': {'deadline_matrix_all_exact': True,
                                            'different_epoch_direct_compare_forbidden': True,
                                            'overflow_reject_mutation_zero': True,
                                            'reason': 'now_ge_not_after',
                                            'reject_code': 7,
                                            'status': 'REJECT'},
                               'family': 'negative'},
 'MF-NEG-FAIRNESS-TWO-OUTSTANDING': {'authority_fingerprint_hex': 'ae3414b0686ce6a0b1238969a2f9fae57a0b9c39a125cc742d30934e396f0bde',
                                     'expected': {'blocked_peer_slots_skipped': [0, 2],
                                                  'branch': 'host_deterministic_round_robin_and_peer_backpressure',
                                                  'different_peer_slot_selected': 1,
                                                  'fair_selection_bound': 4,
                                                  'max_outstanding': 1,
                                                  'reason': 'more_than_one_unpaid_chunk_offer_per_peer_forbidden',
                                                  'restart_next_slot': 0,
                                                  'selection_trace': [0, 1, 2, 3, 0, 1, 2, 3],
                                                  'status': 'OK'},
                                     'family': 'negative'},
 'MF-NEG-FALSE-CUSTODY-BITMAP': {'authority_fingerprint_hex': '97672c50b53987202ae156e01cea199c73032fbf3f2e8e5c80439b36f3633dc6',
                                 'expected': {'reason': 'resume_bitmap_is_hint_not_custody_completion',
                                              'sender_may_release_payload': False,
                                              'status': 'REJECT'},
                                 'family': 'negative'},
 'MF-NEG-HOST-CONTROL-OUTBOX-BACKPRESSURE': {'authority_fingerprint_hex': 'b36956f1f900c98e8adea8a26dcbe3ccae068affa4892d7556c6acdb2f469ba2',
                                             'expected': {'active_fairness_blocked': False,
                                                          'branch': 'control_outbox_no_overwrite',
                                                          'catalog_mutation': 0,
                                                          'control_outbox_capacity_frames': 1,
                                                          'first_frame_retained_bit_exact': True,
                                                          'full_count': 0,
                                                          'scheduler_cursor_unchanged': True,
                                                          'second_frame_enqueued': False,
                                                          'second_wire_response_count': 0,
                                                          'state_mutation': 0,
                                                          'status': 'ERR_BUSY',
                                                          'store_mutation': 0},
                                             'family': 'negative'},
 'MF-NEG-HOST-FOUR-ACTIVE-FRESH-OPEN-BUSY': {'authority_fingerprint_hex': '80996ef80c43721990ccd27ea5707189e22365ece30b4ab42bdd3833242371da',
                                             'expected': {'active_after': 4,
                                                          'active_before': 4,
                                                          'branch': 'four_active_fresh_open_capacity_busy',
                                                          'cacheable': False,
                                                          'catalog_unchanged': True,
                                                          'control_route': 255,
                                                          'durable_state_mutation': 0,
                                                          'full_count': 0,
                                                          'owned_control_outbox': True,
                                                          'reject_code_sidecar': 5,
                                                          'response_body_length': 60,
                                                          'scheduler_cursor_unchanged': True,
                                                          'semantic_response_type': 59,
                                                          'stateless': True,
                                                          'status': 'OK',
                                                          'store_unchanged': True,
                                                          'transport_status': 'OK'},
                                             'family': 'negative'},
 'MF-NEG-HOST-TERMINAL-BIND-MATRIX': {'authority_fingerprint_hex': '9912ea0cea4032a26b35826bc12e18cf1b6e6585a7e38d593a1aa74c66053879',
                                      'expected': {'branch': 'host_terminal_bind_matrix',
                                                   'cookie_swap': 'ERR_STATE',
                                                   'exact_initial_rebind': 'OK',
                                                   'generation_mismatch': 'ERR_STATE',
                                                   'mismatch_outbox_mutation': 0,
                                                   'mismatch_state_mutation': 0,
                                                   'mismatch_store_mutation': 0,
                                                   'mismatch_wire_response_count': 0,
                                                   'peer_mismatch': 'ERR_STATE',
                                                   'role_mismatch': 'ERR_STATE',
                                                   'same_cookie_after_bind': 'OK',
                                                   'status': 'REJECT',
                                                   'zero_cookie': 'ERR_STATE'},
                                      'family': 'negative'},
 'MF-NEG-MAX-CHUNKS-PLUS-ONE': {'authority_fingerprint_hex': '8e1672136742e2e5edb3688c244a07c51f530cf68ab9b487e48c886fe05a3fa5',
                                'expected': {'reason': 'chunk_count_exceeds_37', 'reject_code': 1, 'status': 'REJECT'},
                                'family': 'negative'},
 'MF-NEG-MIXED-VERSION-PEER': {'authority_fingerprint_hex': '342ff23001923c796eff1e227ba59350bf03ff1a5a0a1d694ad5baf7012c9a96',
                               'expected': {'reason': 'stale_or_unbound_mfn1_session',
                                            'reject_code': 4,
                                            'status': 'REJECT'},
                               'family': 'negative'},
 'MF-NEG-NFL1-CONTROL-FORBIDDEN': {'authority_fingerprint_hex': '90bc8ed6679e7d920f3f33edc22f28f63d3dcf887af5b8a9530f1074fac33d8a',
                                   'expected': {'reason': 'ordinary_public_nfl1_must_not_carry_raw_mf_control',
                                                'reject_code': 4,
                                                'status': 'REJECT'},
                                   'family': 'negative'},
 'MF-NEG-NM30-SCHEMA1-COLD-REPLAY-DENY': {'authority_fingerprint_hex': '6bdd4432da0e505d44a128d71e5c23e74957e9e1b1a27dc865f53137a0e0c192',
                                          'expected': {'accounting_allowed': True,
                                                       'branch': 'legacy_nm30_schema1_replay_ineligible',
                                                       'canonical_legacy_validation': True,
                                                       'peer_role_cookie_inference_forbidden': True,
                                                       'rebind_allowed': False,
                                                       'replay_eligible': False,
                                                       'retention_gc_allowed': True,
                                                       'schema': 1,
                                                       'status': 'REJECT',
                                                       'transport_ok': False,
                                                       'value_length': 164,
                                                       'wire_response_count': 0},
                                          'family': 'negative'},
 'MF-NEG-OPEN-APPLICATION-BINDING-FIELD-MUTATION': {'authority_fingerprint_hex': '23e01a3a025e74d5cec6d03e8acf8c4d66169d639a790b0fdc4c021775705581',
                                                    'expected': {'durable_state_mutation': 0,
                                                                 'mutation_count': 25,
                                                                 'reason': 'every_binding_field_is_manifest_bound',
                                                                 'reject_code': 2,
                                                                 'stage': 1,
                                                                 'status': 'REJECT'},
                                                    'family': 'negative'},
 'MF-NEG-PARTIAL-APPLY-FORBIDDEN': {'authority_fingerprint_hex': '7b75fe1e55cd0f2107d0034b89f89b08b68ebacc6942a6071a6b09e30cb24276',
                                    'expected': {'publication_state': 0,
                                                 'reason': 'publication_before_content_verified',
                                                 'status': 'REJECT'},
                                    'family': 'negative'},
 'MF-NEG-PREADMISSION-DEADLINE-STATELESS': {'authority_fingerprint_hex': '7db67791e29cad9d5c6942972b4c5fcb1096cbda9f844f49106ad1639efe4045',
                                            'expected': {'bind52_safe': True,
                                                         'branch': 'preadmission_deadline_stateless',
                                                         'cacheable': False,
                                                         'control_route': 255,
                                                         'durable_rows_created': 0,
                                                         'durable_state_mutation': 0,
                                                         'full_count': 0,
                                                         'late_duplicate_may_be_reevaluated': True,
                                                         'owned_control_outbox': True,
                                                         'reject_code': 7,
                                                         'response_body_length': 60,
                                                         'retry_requires_fresh_nonzero_request_id': True,
                                                         'semantic_response_type': 58,
                                                         'status': 'OK',
                                                         'transport_status': 'OK'},
                                            'family': 'negative'},
 'MF-NEG-PREADMISSION-POLICY-STATELESS': {'authority_fingerprint_hex': '3aae613ffad39336e668737986f4f321a5d8f15e65c953d85579cc64f91c74ef',
                                          'expected': {'bind52_safe': True,
                                                       'branch': 'preadmission_policy_stateless',
                                                       'cacheable': False,
                                                       'control_route': 255,
                                                       'durable_rows_created': 0,
                                                       'durable_state_mutation': 0,
                                                       'full_count': 0,
                                                       'late_duplicate_may_be_reevaluated': True,
                                                       'owned_control_outbox': True,
                                                       'reject_code': 4,
                                                       'response_body_length': 60,
                                                       'retry_requires_fresh_nonzero_request_id': True,
                                                       'semantic_response_type': 58,
                                                       'status': 'OK',
                                                       'transport_status': 'OK'},
                                          'family': 'negative'},
 'MF-NEG-REORDER-GAP': {'authority_fingerprint_hex': '8b0b9d7281da2c75369ae70fafbe51cb43d22f93fafad452310068fb0dfcb0de',
                        'expected': {'bitmap_after': 2,
                                     'gap_does_not_imply_complete': True,
                                     'missing_indices': [0],
                                     'status': 'OK_REORDER_ACCEPT'},
                        'family': 'negative'},
 'MF-NEG-REQID-BODY-CONFLICT': {'authority_fingerprint_hex': '074725ddb8e99edb0bec9bc5dba2935aa54c7c2d200676abd0bf2cee204ccb55',
                                'expected': {'reason': 'request_id_body_digest_conflict',
                                             'reject_code': 3,
                                             'state_mutation': 0,
                                             'status': 'REJECT'},
                                'family': 'negative'},
 'MF-NEG-REQID-CACHE-FULL': {'authority_fingerprint_hex': 'a528d9efcc12aa6679653777b120ac0db207c62049bfa4f45e4a53f85f24d702',
                             'expected': {'no_silent_eviction': True,
                                          'reason': 'request_id_cache_full',
                                          'reject_code': 5,
                                          'slot_count': 72,
                                          'state_mutation': 0,
                                          'status': 'BUSY_OR_REJECT'},
                             'family': 'negative'},
 'MF-NEG-REQID-DIGEST-OPEN-PREIMAGE': {'authority_fingerprint_hex': 'bc751a28a45e689878bd8f8662739353d22d192b5ccde8f9f146007ced56b158',
                                       'expected': {'bind52_strip_digest_differs': True,
                                                    'branch': 'open_digest_preimage',
                                                    'includes_bind52_strip': False,
                                                    'message_type': 54,
                                                    'preimage': 'type_u8||len_u16be||full_open_body',
                                                    'status': 'OK'},
                                       'family': 'negative'},
 'MF-NEG-REQID-POST-RETENTION-EXPIRED': {'authority_fingerprint_hex': '6403986bee1d5aa9d78bf0bc32261b9ce5c5518d7d43536e862c46e46db615f9',
                                         'expected': {'bit_exact_replay_forbidden': True,
                                                      'nm30_present': False,
                                                      'nrc1_present': False,
                                                      'reason': 'transfer_expired',
                                                      'reject_code': 7,
                                                      'state_mutation': 0,
                                                      'status': 'REJECT'},
                                         'family': 'negative'},
 'MF-NEG-REQID-TWO-GEN-NO-RECLAIM-CAPACITY': {'authority_fingerprint_hex': '3f492941a0beee3bb2808a324ab1ad4271c6bb3f59d6cb08058d7ca473273452',
                                              'expected': {'branch': 'two_gen_resume_without_reclaim',
                                                           'code': 5,
                                                           'exceeds': True,
                                                           'illegal_occupancy': 73,
                                                           'slot_count': 72,
                                                           'status': 'REJECT'},
                                              'family': 'negative'},
 'MF-NEG-RESOURCE-EXHAUSTION-BYTES': {'authority_fingerprint_hex': 'b714f355cb5296f0e973e3347011a900acb9cb6f408501e222cdca36057c0b5e',
                                      'expected': {'reject_code': 5, 'state_mutation': 0, 'status': 'BUSY_OR_REJECT'},
                                      'family': 'negative'},
 'MF-NEG-RESOURCE-EXHAUSTION-KEYS': {'authority_fingerprint_hex': '8ba6acb623b8a9313c3928da6df2e83302c48e67034543934b0fd41b36cef716',
                                     'expected': {'branch': 'bounded_host_and_esp_admission',
                                                  'esp_active_after_second': 1,
                                                  'esp_first_admitted': True,
                                                  'esp_second_rejected': True,
                                                  'host_active_after_fifth': 4,
                                                  'host_fifth_rejected': True,
                                                  'host_first_four_admitted': True,
                                                  'host_slot_order': [0, 1, 2, 3],
                                                  'reject_code': 5,
                                                  'state_mutation': 0,
                                                  'status': 'OK'},
                                     'family': 'negative'},
 'MF-NEG-RF-MAPPING-UNAVAILABLE': {'authority_fingerprint_hex': 'e7cb22ce0410b2f349c7cfcb2d8d8fa4244708294bedc2fd2e83aeb160c0baac',
                                   'expected': {'carrier': 'compact_rf_nrw1',
                                                'mapping': 'MAPPING_UNAVAILABLE',
                                                'reject_code': 4,
                                                'status': 'REJECT'},
                                   'family': 'negative'},
 'MF-NEG-STALE-GENERATION': {'authority_fingerprint_hex': '9c454f67ff7fd569db1f2fd74917f07c8ccd4b877f5cb4c38fb10612415c54fe',
                             'expected': {'reason': 'query_generation_gap_or_rollback',
                                          'reject_code': 8,
                                          'stage': 5,
                                          'status': 'REJECT'},
                             'family': 'negative'},
 'MF-NEG-STALE-VERSION-SELECTED-2': {'authority_fingerprint_hex': 'ca90f9419adef814f16006960e805afd3c1db14824b76ab77433d6e02b1737b9',
                                     'expected': {'reason': 'mfn1_not_established',
                                                  'reject_code': 4,
                                                  'status': 'REJECT'},
                                     'family': 'negative'},
 'MF-NEG-STORAGE-SIDECAR-COLLISION': {'authority_fingerprint_hex': '071ba42df4ef1ca400e8b9f9a0ce9fb5a17202af8d4db6f02370bf8453c033a1',
                                      'expected': {'branch': 'derived_namespace_collision_binding_mismatch',
                                                   'existing_rows_overwritten': False,
                                                   'foundation_scan_relaxed': False,
                                                   'reason': 'base_namespace_binding_mismatch',
                                                   'status': 'REJECT',
                                                   'wire_or_apply': 0},
                                      'family': 'negative'},
 'MF-NEG-WHOLE-DIGEST-MISMATCH': {'authority_fingerprint_hex': 'aec9b39a853706ea703ec777315f8b6fc7dd542655187b3ac5f7e776b8bd284c',
                                  'expected': {'reject_code': 2, 'stage': 4, 'status': 'REJECT'},
                                  'family': 'negative'},
 'MF-NEG-WIFI-MAPPING-UNAVAILABLE': {'authority_fingerprint_hex': 'ea119b274ea76e182b0a7d4c9790022e1d97cee12948edf4042cd7a3091e641b',
                                     'expected': {'carrier': 'wifi_nwb1',
                                                  'mapping': 'MAPPING_UNAVAILABLE',
                                                  'reject_code': 4,
                                                  'status': 'REJECT'},
                                     'family': 'negative'},
 'MF-POS-APPLICATION-EVIDENCE-DIGEST-KAT': {'authority_fingerprint_hex': 'bfab372cadd3c7059983dfdc033fd74a24c7124a624c2abfa265d55dd7e76e07',
                                            'expected': {'application_evidence_digest_hex': '111189981b337d4bd82e94afb15e89e6b5ac6e07ffd729208ed99b9a015fb0b3',
                                                         'branch': 'positive_required_evidence_handoff',
                                                         'disposition_fatal_recovery_may_advance': False,
                                                         'evidence_length': 10,
                                                         'evidence_stage': 3,
                                                         'handoff_may_advance': True,
                                                         'receipt_may_advance_after_handoff_full': True,
                                                         'required_evidence': 3,
                                                         'status': 'OK'},
                                            'family': 'positive'},
 'MF-POS-COMPLETION-RECEIPT-REPLAY': {'authority_fingerprint_hex': 'ffd9bfde136d57eacd97f33aea0b2425cc27095a4a7043d9c765a7ce1fbbd12f',
                                      'expected': {'branch': 'idempotent_accept_replay',
                                                   'state_mutation_on_replay': 0,
                                                   'status': 'OK',
                                                   'transfer_accept_hex': 'c9ccb68aea4d21db421738c08d2e5f6d0000000141a673e85caa860c346328f0407f3813f7f6bc5966815f04073260a0d7c3adbecf9d32a697a67f9a0644a06f44ee1f657b179b848990d93b92d50aaad782d6ab000000105758595a5b5c5d5e5f6061626364656600000000000000641718191a1b1c1d1e1f20212223242526af0364918131b6861e0b23994fa2eb1d1806222b5338bac98052fd5abb0264e8'},
                                      'family': 'positive'},
 'MF-POS-EMPTY-PAYLOAD': {'authority_fingerprint_hex': '108d0dac0b4616f6c30b5f9334c602ed4554efa4b296649872d25cce68f52a89',
                          'expected': {'branch': 'positive_transfer',
                                       'chunk_count': 0,
                                       'final_chunk_length': 0,
                                       'manifest_digest_hex': 'cb46359b17ce129af28d1cb098f83a5df324e2f67eb953274ac7fdfad31113e2',
                                       'manifest_page_count': 0,
                                       'open_accept_length': 100,
                                       'publication_token_hex': '8761b3b0fbf62abbc6be6228421a6d82',
                                       'status': 'OK',
                                       'total_length': 0,
                                       'transfer_accept_length': 160,
                                       'whole_content_sha256_hex': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
                          'family': 'positive'},
 'MF-POS-EXACT-MULTIPLE-FINAL': {'authority_fingerprint_hex': 'c1c9eaa62d215c74bd1988f9268c1ebcf5ebb28413e8f37a1b0d8c15c91c834d',
                                 'expected': {'branch': 'positive_transfer',
                                              'chunk_count': 2,
                                              'final_chunk_length': 896,
                                              'manifest_digest_hex': '2f98cd7015a785f21ed36efb3352e37cf3a074acd47bf0a15e9fbc7cf72bda0c',
                                              'manifest_page_count': 1,
                                              'open_accept_length': 100,
                                              'publication_token_hex': '8c83cfaf42920202ad24c04d35213b7a',
                                              'status': 'OK',
                                              'total_length': 1792,
                                              'transfer_accept_length': 160,
                                              'whole_content_sha256_hex': 'eb6cac7f35e334b7e5a3d37740446fb9a72a8974604e7ab6e60a8f5c98643478'},
                                 'family': 'positive'},
 'MF-POS-EXPIRY-SLOT-REUSE': {'authority_fingerprint_hex': '7f3bae95dfdf11225cf5e47cd326eb6c293a41e5330ee924640535bd649a0f94',
                              'expected': {'active_count_after_expiry': 0,
                                           'branch': 'expiry_slot_reuse',
                                           'esp_active_max': 1,
                                           'new_transfer_open_admitted': True,
                                           'reuse_after': 'G_R_EXPIRY_or_G_RETENTION_GC',
                                           'status': 'OK'},
                              'family': 'positive'},
 'MF-POS-HOST-FOUR-ACTIVE-TERMINAL-HIT': {'authority_fingerprint_hex': '793e6e30501366de5098434d274247323e884172be79d06219e88e9a3eacb0db',
                                          'expected': {'active_after': 4,
                                                       'active_before': 4,
                                                       'active_slot_allocations': 0,
                                                       'branch': 'four_active_terminal_hit_control_route',
                                                       'control_route': 255,
                                                       'full_count': 0,
                                                       'nrc1_hit': True,
                                                       'owned_control_outbox': True,
                                                       'peer_unpaid_fence_unchanged': True,
                                                       'scheduler_cursor_unchanged': True,
                                                       'status': 'OK',
                                                       'store_mutation': 0,
                                                       'terminal_catalog_count': 1,
                                                       'transport_status': 'OK'},
                                          'family': 'positive'},
 'MF-POS-MAX-PAYLOAD-37-CHUNKS': {'authority_fingerprint_hex': 'a783d2eee475966e29ef3cc2016db0b290ac1be35bc97174352ce5e13935d55c',
                                  'expected': {'branch': 'positive_transfer',
                                               'chunk_count': 37,
                                               'final_chunk_length': 512,
                                               'manifest_digest_hex': '21931b7f1e06699f5d9b15014dfd92997fe1a34a2b76c87abefd2111324fad42',
                                               'manifest_page_count': 2,
                                               'open_accept_length': 100,
                                               'publication_token_hex': '34728a95989d14084bccabafb09f5f07',
                                               'status': 'OK',
                                               'total_length': 32768,
                                               'transfer_accept_length': 160,
                                               'whole_content_sha256_hex': 'a77047432e200ebc2a7aa399be532389407248cb85693b978efb2754d244111c'},
                                  'family': 'positive'},
 'MF-POS-NM30-SCHEMA2-LAYOUT-KAT': {'authority_fingerprint_hex': 'c62b4e55fd03ab5899b1f47ea74b307988ccea012801f684ac423630be93adf2',
                                    'expected': {'branch': 'nm30_schema2_layout',
                                                 'crc_offset': 176,
                                                 'crc_preimage_bytes': 176,
                                                 'owner_role': 2,
                                                 'owner_role_offset': 172,
                                                 'peer_endpoint_id_bytes': 16,
                                                 'peer_endpoint_id_nonzero': True,
                                                 'peer_endpoint_id_offset': 156,
                                                 'reserved_bytes': 3,
                                                 'reserved_offset': 173,
                                                 'reserved_zero': True,
                                                 'schema': 2,
                                                 'session_cookie_durable': False,
                                                 'session_generation_authority': 'NRC1_header_offset_24',
                                                 'status': 'OK',
                                                 'value_length': 180},
                                    'family': 'positive'},
 'MF-POS-ONE-BYTE': {'authority_fingerprint_hex': '8d07e19acc5c8182b292e4c609db659d6093ad23ccf2578728e9b4dd5041fc19',
                     'expected': {'branch': 'positive_transfer',
                                  'chunk_count': 1,
                                  'final_chunk_length': 1,
                                  'manifest_digest_hex': 'e536bbd435a20beaffc8bd0bf37aa23dcd3b38752283327e480b9d35b404a19e',
                                  'manifest_page_count': 1,
                                  'open_accept_length': 100,
                                  'publication_token_hex': '0f1ea7ab66554f029dfc667fa439849b',
                                  'status': 'OK',
                                  'total_length': 1,
                                  'transfer_accept_length': 160,
                                  'whole_content_sha256_hex': '559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd'},
                     'family': 'positive'},
 'MF-POS-ONE-BYTE-FINAL': {'authority_fingerprint_hex': '48d00c9ee7551e784da8c8a3004f081824b34ab200812c51469c80d475b4a6d5',
                           'expected': {'branch': 'positive_transfer',
                                        'chunk_count': 2,
                                        'final_chunk_length': 1,
                                        'manifest_digest_hex': '4106142e74f2e7258c79e75274f19eee76d285dfd618d7b54c0a051ea4a85f49',
                                        'manifest_page_count': 1,
                                        'open_accept_length': 100,
                                        'publication_token_hex': '36074561c35acee4d9edd781d4ea474d',
                                        'status': 'OK',
                                        'total_length': 897,
                                        'transfer_accept_length': 160,
                                        'whole_content_sha256_hex': '524ae03737bd1d4a3e07bbeabaab592e6d07c99bc13ab465df93361757bd405b'},
                           'family': 'positive'},
 'MF-POS-OPEN-APPLICATION-BINDING-LAYOUT-KAT': {'authority_fingerprint_hex': 'ffae95a8027ca737dd25489737c487dc687d1a883954c513b8ee256f597be892',
                                                'expected': {'active_record_schema': 2,
                                                             'active_schema1_replay_eligible': False,
                                                             'admission_profile_revision': 2,
                                                             'application_binding_bytes': 228,
                                                             'base_fixed_bytes': 234,
                                                             'branch': 'open_application_binding_revision2',
                                                             'deadline_normalization_forbidden': True,
                                                             'deadline_sentinel_erratum': 'foundation_canonical_bit_exact',
                                                             'deadline_zero_rejected': True,
                                                             'downlink_no_deadline_rejected': True,
                                                             'finite_downlink_deadline_max_u64_hex': 'fffffffffffffffe',
                                                             'finite_downlink_deadline_min_u64_hex': '0000000000000001',
                                                             'manifest_binds_entire_application_binding': True,
                                                             'no_deadline_u64_hex': 'ffffffffffffffff',
                                                             'nts3_future_fields': ['mfdt_transfer_id[16]',
                                                                                    'mfdt_target_ordinal_u32'],
                                                             'nts3_future_mfdt_record_max_bytes': 3185,
                                                             'nts3_future_mfdt_target_rule': 'transfer_id_nonzero__sender_ordinal_eq_bound_target_index__receiver_ordinal_eq_open_origin_ordinal_lt4_u32_be',
                                                             'nts3_future_non_mfdt_memory_rule': 'transfer_id_zero16_and_ordinal_zero',
                                                             'nts3_future_non_mfdt_suffix_bytes': 0,
                                                             'nts3_future_schema': '1.2',
                                                             'nts3_future_target_count_max': 4,
                                                             'nts3_future_target_suffix_bytes': 20,
                                                             'nts3_future_target_suffix_placement': 'canonical_target_encoding_tail',
                                                             'nts3_future_target_suffix_presence': 'bearer_route_eq_MFDT_V1_3',
                                                             'nts3_record_ceiling_bytes': 4096,
                                                             'nts3_schema11_inline_payload_max_bytes': 926,
                                                             'nts3_schema11_record_max_bytes': 4031,
                                                             'open_body_max': 651,
                                                             'open_body_min': 465,
                                                             'public_callback_context_id': 'foundation_transaction_id',
                                                             'publication_token_scope': 'private_mfdt_handoff_dedupe_only',
                                                             'status': 'OK',
                                                             'text_offset': 462},
                                                'family': 'positive'},
 'MF-POS-REQID-CACHE-SAME-ID-STABLE': {'authority_fingerprint_hex': '8d773c00c4e6f00a63b451e2c3d7a1d5931e13817088d97461e6a3dddade0ee3',
                                       'expected': {'branch': 'request_id_cache_hit',
                                                    'cached_manifest_complete': 0,
                                                    'durable_cache': True,
                                                    'first_manifest_complete': 0,
                                                    'nrc1_kind': 'NRC1',
                                                    'request_id': 7,
                                                    'state_mutation_on_same_request_id': 0,
                                                    'status': 'OK',
                                                    'storage_profile': 'HOST_FULL_CAPABLE',
                                                    'target_unattested_replay_forbidden': True},
                                       'family': 'positive'},
 'MF-POS-REQID-MAX-RETRY-TRACE': {'authority_fingerprint_hex': 'b5956adba33c2e1a68227fa6b72655e5a1782d9296ae68695032db6487cccda7',
                                  'expected': {'branch': 'max_timeout_retry_trace',
                                               'first_attempts': 1,
                                               'fits_in_capacity': True,
                                               'new_request_id_each_retry': True,
                                               'occupied_count': 9,
                                               'slot_count': 72,
                                               'status': 'OK',
                                               'timeout_retries': 8,
                                               'timeout_retry_max': 8},
                                  'family': 'positive'},
 'MF-POS-REQID-MAX-TRANSFER-OCCUPIED-41': {'authority_fingerprint_hex': 'c84624f891530d2876b020dc26a9ca703251c8d38f95b7569eda51b7cbdabe4e',
                                           'expected': {'branch': 'max_transfer_nrc1_occupancy',
                                                        'cache_full': False,
                                                        'chunk_ids': 37,
                                                        'exceeds_obsolete_fixed16': True,
                                                        'finalize_ids': 1,
                                                        'fits': True,
                                                        'occupied_count': 41,
                                                        'open_ids': 1,
                                                        'page_ids': 2,
                                                        'slot_count': 72,
                                                        'status': 'OK'},
                                           'family': 'positive'},
 'MF-POS-REQID-NEW-ID-CURRENT-COMPLETE': {'authority_fingerprint_hex': '313b469bd9fdea0d6c79fb7584e3cbf11898a4164646ccd4c319c81b4fc08456',
                                          'expected': {'branch': 'new_request_id_current_state',
                                                       'first_manifest_complete': 0,
                                                       'first_request_id': 7,
                                                       'nrc1_occupied_after': 2,
                                                       'second_manifest_complete': 1,
                                                       'second_request_id': 8,
                                                       'status': 'OK'},
                                          'family': 'positive'},
 'MF-POS-REQID-NRC1-LAYOUT-KAT': {'authority_fingerprint_hex': 'd808d8449b8a803f2df29596d3730165575b6ab46484895c5988087feeebd133',
                                  'expected': {'branch': 'nrc1_layout',
                                               'empty_slot': 'ALL_ZERO_ACCEPTED',
                                               'first_slot_session_generation': 1,
                                               'happy_path_max_ids': 41,
                                               'key_length': 20,
                                               'logical_bytes': 15056,
                                               'lookup_identity': 'session_generation_plus_request_id',
                                               'occupied_l0_mutant': 'REJECT_SEMANTIC',
                                               'occupied_response_length_min': 1,
                                               'reachable_max_ids': 65,
                                               'slot_bytes': 208,
                                               'slot_count': 72,
                                               'slot_session_generation_offset': 8,
                                               'status': 'OK',
                                               'timeout_retry_max': 8,
                                               'value_length': 15020},
                                  'family': 'positive'},
 'MF-POS-REQID-REACHABLE-MAX-COUNT': {'authority_fingerprint_hex': '8b82c3f3211513ded355559c901aad7969faf86714a511ee858c591ea0e0e2df',
                                      'expected': {'abort_gen_max': 8,
                                                   'branch': 'nrc1_reachable_max',
                                                   'capacity_spare': 7,
                                                   'denied_abort_after_content_verified_consumes_slot': True,
                                                   'derived_from_retry_budget_sm': True,
                                                   'finalize_abort_success_exclusive': True,
                                                   'happy_first': 41,
                                                   'illegal_two_gen_exceeds_72': True,
                                                   'illegal_two_gen_no_reclaim': 73,
                                                   'n_abort': 64,
                                                   'n_complete': 65,
                                                   'naive_union': 57,
                                                   'naive_union_is_single_path': False,
                                                   'reachable_max': 65,
                                                   'resume_max': 8,
                                                   'resume_reclaim_on_session_gen_advance': True,
                                                   'slot_count': 72,
                                                   'slot_count_ge_reachable': True,
                                                   'status': 'OK',
                                                   'terminal_outcomes_exclusive': True,
                                                   'timeout_retry_max': 8},
                                      'family': 'positive'},
 'MF-POS-REQID-RETRY-BUDGET-SM': {'authority_fingerprint_hex': '407c2dff061e6cb54da4adb87c8be85abd860cf40c622d63188b12f1f0da4165',
                                  'expected': {'branch': 'retry_budget_sm',
                                               'decrement_event': 'timeout_retry_with_new_request_id',
                                               'decrement_requires_full_before_wire': True,
                                               'exhaustion_forbids_new_request_id_timeout_retry': True,
                                               'exhaustion_is_nrc1_eviction': False,
                                               'exhaustion_is_terminal': False,
                                               'header_offset': 105,
                                               'initial_value': 8,
                                               'max_value': 8,
                                               'min_value': 0,
                                               'not_per_request_id': True,
                                               'not_per_stage': True,
                                               'owner': 'requestor_of_outbound_mfdt_control',
                                               'scope': 'per_transfer_per_owner_side',
                                               'status': 'OK'},
                                  'family': 'positive'},
 'MF-POS-REQID-SESSION-GEN-RESUME-RECLAIM': {'authority_fingerprint_hex': '1f0008d5cd7c03151ccb310465a4e51ee969d9ee39bf3c3dd35fd20ee13a99c6',
                                             'expected': {'active_header_session_generation_offset': 300,
                                                          'advance_rule': 'current_plus_1_no_wrap',
                                                          'allowed_slot_generations': 'current_or_exact_prior',
                                                          'anchor': 'initial_non_resume_open_accept_slot',
                                                          'branch': 'session_gen_resume_reclaim',
                                                          'future_generation_record_status': 'CORRUPT',
                                                          'gap_generation_record_status': 'CORRUPT',
                                                          'initial_occupied': 2,
                                                          'initial_session_generation': 7,
                                                          'initial_session_generation_domain': 'u32_nonzero',
                                                          'lifetime_resume_attempts_max': 16,
                                                          'lookup_identity': 'session_generation_plus_request_id',
                                                          'non_resume_retained_whole_lifetime': True,
                                                          'peak_with_reclaim': 65,
                                                          'reclaim_resume_class_only': True,
                                                          'resume_counter_reset': True,
                                                          'resume_per_gen': 8,
                                                          'same_request_id_across_generation_distinct': True,
                                                          'second_advance_status': 'CAPACITY',
                                                          'session_advance_full_members': ['ACTIVE', 'NRC1'],
                                                          'session_gen_is_distinct_count_not_numeric_max': True,
                                                          'session_gen_max': 2,
                                                          'slot_bound_session_generation': True,
                                                          'status': 'OK',
                                                          'successor_occupied_after_reclaim': 2,
                                                          'successor_session_generation': 8,
                                                          'third_generation_record_status': 'CORRUPT',
                                                          'uint32_max_advance_status': 'CAPACITY'},
                                             'family': 'positive'},
 'MF-POS-REQID-TERMINAL-LATE-DUP-MATRIX': {'authority_fingerprint_hex': '8e98f7150e9e890269e50b9dfe40e64b627549f39c5b861b7dc10d09c0e272de',
                                           'expected': {'all_bit_exact': True,
                                                        'branch': 'terminal_late_dup_matrix',
                                                        'nrc1_retained_with_nm30': True,
                                                        'operation_count': 6,
                                                        'state_mutation_on_hit': 0,
                                                        'status': 'OK',
                                                        'terminal_erases_nrc1': False},
                                           'family': 'positive'},
 'MF-POS-TWO-PAGE-MANIFEST': {'authority_fingerprint_hex': '1a592cd81198871721a283d02656e68ada6e53f2a467cd5eb509fa60adc5f313',
                              'expected': {'branch': 'positive_transfer',
                                           'chunk_count': 23,
                                           'final_chunk_length': 896,
                                           'manifest_digest_hex': '66f64044d900b7f1a5a8ce816a972edd96045bc506429704b266b92bc91e8d52',
                                           'manifest_page_count': 2,
                                           'open_accept_length': 100,
                                           'publication_token_hex': 'e9540f71d893043b3ad567b1f5c528e0',
                                           'status': 'OK',
                                           'total_length': 20608,
                                           'transfer_accept_length': 160,
                                           'whole_content_sha256_hex': '550dbf37283cf5e4fbae21e5aa8ab083ae8004137e429767543093d8d55f1834'},
                              'family': 'positive'},
 'MF-PRIVATE-API-SURFACE': {'authority_fingerprint_hex': '6cac832128fc9f82b567053f311cb33ab8c22e086df364683857c75e0001eae4',
                            'expected': {'default_off': True,
                                         'host_fifth_active': 'CAPACITY_BUSY_control_outbox_state_mutation_0',
                                         'host_owner_workspace_bytes': 280064,
                                         'host_slot_count': 4,
                                         'per_slot_workspace_bytes': 65536,
                                         'public_abi': False,
                                         'status': 'OK'},
                            'family': 'catalog'},
 'MF-PUBLICATION-OWNER-MATRIX': {'authority_fingerprint_hex': '2888849effb9dd08c4353addb636770bc196739098ba09aee9f2514dc40f9e2d',
                                 'expected': {'sole_prepare_caller': 'receiver_multi_frame_owner', 'status': 'OK'},
                                 'family': 'catalog'},
 'MF-ROLE-BOUNDARIES': {'authority_fingerprint_hex': '1d32e0382a504f0aade7992f8099a1bc9128d66fd5089e9e5784dbf4aade405b',
                        'expected': {'false_custody': False, 'status': 'OK'},
                        'family': 'catalog'},
 'MF-TRACE-S1-S6-HAPPY-PATH': {'authority_fingerprint_hex': '2446e736b03afcd7cdae240daaee27b39b129070f4cc7fba7f81938b5f8afcf6',
                               'expected': {'branch': 's1_s6_trace',
                                            's6_durable': 'NM30_ONLY',
                                            'stages': ['S1', 'S2', 'S3', 'S4', 'S5', 'S6'],
                                            'status': 'OK'},
                               'family': 'catalog'},
 'MF-TX-CLEANUP-RETENTION-GC': {'authority_fingerprint_hex': '215528840e59dc4570533fa9e697c7524cebf16a74599810d2cc046bf3bb43be',
                                'expected': {'active_eviction_forbidden': True,
                                             'after_boundary': 'OK_DELETE',
                                             'before_boundary': 'REJECT_NOT_ELAPSED',
                                             'branch': 'gc_after_retention',
                                             'epoch_mismatch': 'REJECT_STATE',
                                             'equal_boundary': 'OK_DELETE',
                                             'group': 'G_R_RETENTION_GC',
                                             'nrc1_deleted_with_nm30': True,
                                             'status': 'OK'},
                                'family': 'transcript'},
 'MF-TX-CROSS-NAMESPACE-ADMISSION-MATRIX': {'authority_fingerprint_hex': 'e733b6e4b24fba4f5d9623d392a6faaa97497689bfc056bd396d48eae23c8208',
                                            'expected': {'admission_execution_scope': 'owner_thread_call',
                                                         'attempt_candidate_bound_to_target_open': True,
                                                         'attempt_candidate_nonzero': True,
                                                         'attempt_collision_set': 'durable_active_retained_plus_prior_same_admission_candidates',
                                                         'attempt_consumed_claim_before_foundation_full': 0,
                                                         'attempt_draw_order': 'canonical_target_order',
                                                         'attempt_draws_max_per_target': 4,
                                                         'blind_attempt_redraw_forbidden': True,
                                                         'branch': 'canonical_roster_target_attempt_prearm_foundation_full_reconcile',
                                                         'compound_receiver_key_created': False,
                                                         'duplicate_runtime_api_status': 'NINLIL_OK',
                                                         'duplicate_runtime_entropy_draws': 0,
                                                         'duplicate_runtime_foundation_mutations': 0,
                                                         'duplicate_runtime_reason': 'TARGET_COUNT_UNSUPPORTED',
                                                         'duplicate_runtime_sidecar_mutations': 0,
                                                         'duplicate_runtime_submission_state': 'REJECTED',
                                                         'foundation_admission_atomic_members': ['exact_target_roster',
                                                                                                 'per_target_attempt_index_and_binding',
                                                                                                 'attempt_budget_and_counters',
                                                                                                 'ATTEMPT_PREPARED_and_pending_state',
                                                                                                 'per_target_mfdt_transfer_id_and_origin_ordinal'],
                                                         'foundation_admission_full_count': 1,
                                                         'foundation_commit_unknown_deletes_sidecar': False,
                                                         'matching_both': 'RESUME_ELIGIBLE',
                                                         'missing_sidecar_for_durable_mfdt': 'CORRUPT_FENCE',
                                                         'new_durable_state_added': False,
                                                         'nts3_target_local_suffix_rule_changed': False,
                                                         'orphan_cleanup_before_wire_or_apply': True,
                                                         'restart_reconcile_before_bearer_open': True,
                                                         'runtime_uniqueness_scope': 'MFDT_V1_ONLY',
                                                         'same_runtime_different_application_instance_rejected': True,
                                                         'sidecar_prearm_before_foundation_full': True,
                                                         'status': 'OK',
                                                         'target_count_max': 4,
                                                         'target_count_min': 1,
                                                         'target_runtime_unique_within_origin': True,
                                                         'wire_or_apply_before_match': 0,
                                                         'wire_txgate_callback_before_foundation_full': 0},
                                            'family': 'transcript'},
 'MF-TX-EPOCH-CHANGE-TERMINAL': {'authority_fingerprint_hex': '7240c3b18a501913dbd4f4be5709b1f34f4f0692f1389842aaff8431dbcc6e98',
                                 'expected': {'active_erased': True,
                                              'branch': 'epoch_changed_terminal',
                                              'nm30_terminal_reason': 32770,
                                              'nm30_terminal_state': 3,
                                              'publish_forbidden': True,
                                              'status': 'OK'},
                                 'family': 'transcript'},
 'MF-TX-EXPIRY-MANDATORY-TOMBSTONE': {'authority_fingerprint_hex': 'b473043632cd1b8d75e9ea54164ce9d462cc1fd8c8483d4c123978918e9019de',
                                      'expected': {'abort_generation': 0,
                                                   'active_slot_freed': True,
                                                   'authority_actor_zero': True,
                                                   'branch': 'expiry_mandatory_tombstone',
                                                   'mandatory_full': 'G_R_EXPIRY',
                                                   'nm30_present': True,
                                                   'nm30_value_bytes': 180,
                                                   'nrc1_retained_until_gc': True,
                                                   'reject_code': 7,
                                                   'status': 'OK',
                                                   'terminal_catalog_all_canonical': True,
                                                   'terminal_catalog_count': 8,
                                                   'terminal_reason': 5,
                                                   'terminal_state': 2,
                                                   'wire_abort_reason_5_forbidden': True,
                                                   'wire_abort_reason_max': 4,
                                                   'wire_abort_reason_min': 1},
                                      'family': 'transcript'},
 'MF-TX-HOST-TERMINAL-COLD-REBIND-HIT': {'authority_fingerprint_hex': 'b8666a9a0647ffcd4120ccf535a200201c29e041ed5019e1456952bb4268e9a6',
                                         'expected': {'active_slots_consumed': 0,
                                                      'branch': 'host_terminal_cold_rebind_hit',
                                                      'cacheable': True,
                                                      'catalog_schema': 2,
                                                      'control_route': 255,
                                                      'cookie_restored_from_storage': False,
                                                      'fresh_nonzero_cookie': True,
                                                      'full_count': 0,
                                                      'generation_exact': True,
                                                      'nrc1_generation_offset': 24,
                                                      'nrc1_hit': True,
                                                      'owned_control_outbox': True,
                                                      'peer_exact': True,
                                                      'post_terminal_miss_cacheable': True,
                                                      'post_terminal_miss_full_count': 1,
                                                      'post_terminal_miss_transfer_state_mutation': 0,
                                                      'response_bit_exact': True,
                                                      'role_exact': True,
                                                      'status': 'OK',
                                                      'transfer_state_mutation': 0,
                                                      'transport_status': 'OK'},
                                         'family': 'transcript'},
 'MF-TX-POWER-CUT-AFTER-CHUNK-FULL': {'authority_fingerprint_hex': '6563193d5c8ee6a347ad636c7324475b86f7810cf580b2369f711c44c9aa9469',
                                      'expected': {'branch': 'resume_from_bitmap',
                                                   'sender_release': False,
                                                   'status': 'RECOVER',
                                                   'wire_success_at_cut': 0},
                                      'family': 'transcript'},
 'MF-TX-POWER-CUT-AFTER-CONTENT-VERIFIED': {'authority_fingerprint_hex': '5fbe2724e0887537a88b240d1c5e99166476f2a823e8cf937322d38c6a64af4a',
                                            'expected': {'accept_notified': 0,
                                                         'branch': 'ready_token_reprompt',
                                                         'publication_state': 1,
                                                         'status': 'RECOVER'},
                                            'family': 'transcript'},
 'MF-TX-POWER-CUT-DURING-TERMINAL': {'authority_fingerprint_hex': 'f99aab9105993e64b46a4071f098f659f9dc0570bb2ff9ae3771c96fd6b2831a',
                                     'expected': {'classify': True,
                                                  'group': 'G_R_TERMINAL',
                                                  'status': 'COMMIT_UNKNOWN'},
                                     'family': 'transcript'},
 'MF-TX-REQID-CACHE-CRASH-RESTART': {'authority_fingerprint_hex': '272b1e00d004c2ea8ea12126ae9dba6a25462ae952c84a264178d058f1396874',
                                     'expected': {'branch': 'nrc1_restart_hit',
                                                  're_evaluation_forbidden': True,
                                                  'response_bodies_equal': True,
                                                  'state_mutation_on_restart_hit': 0,
                                                  'status': 'OK'},
                                     'family': 'transcript'},
 'MF-TX-REQID-TERMINAL-RESTART-LATE-DUP': {'authority_fingerprint_hex': '8f1d6bcb3f5b5986953e220ff1c9e9c24458edd00828ebde335d5772176148cb',
                                           'expected': {'branch': 'terminal_restart_late_dup',
                                                        'nrc1_retained_with_nm30': True,
                                                        're_evaluation_forbidden': True,
                                                        'response_bodies_equal': True,
                                                        'state_mutation_on_hit': 0,
                                                        'status': 'OK'},
                                           'family': 'transcript'},
 'MF-TX-RESUME-AFTER-RESTART': {'authority_fingerprint_hex': 'f5a284edf2c37e7e050d2e42355902fc8f142e49b38d841e31634c6449c59893',
                                'expected': {'bitmap': 1,
                                             'branch': 'resume_state',
                                             'sender_may_release': False,
                                             'state_digest_hex': '9b1852bef5184a0e0f0152bb825362d4875f84b799a5266e6d98439254013bbc',
                                             'status': 'OK'},
                                'family': 'transcript'},
 'MF-TX-ROLLBACK-POLICY-OFF': {'authority_fingerprint_hex': '510b22a7563e5489802a34185c386f5f324d9152fd309d86b791aecdc781038f',
                               'expected': {'branch': 'rollback',
                                            'in_place_v3_to_v2_conversion': False,
                                            'rehello_max_control_version': 2,
                                            'status': 'OK'},
                               'family': 'transcript'},
 'MF-TX-TERMINAL-CRASH-ACTIVE-ONLY': {'authority_fingerprint_hex': '588aee1a00342bbb225d38f734937a0e86c9bd67770864c3e8c9fcb18b1b27b5',
                                      'expected': {'action': 'retry_terminal_full',
                                                   'classification': 'OLD',
                                                   'durable_kinds': ['NM3R'],
                                                   'group': 'G_R_TERMINAL',
                                                   'status': 'COMMIT_UNKNOWN'},
                                      'family': 'transcript'},
 'MF-TX-TERMINAL-CRASH-NM30-ONLY': {'authority_fingerprint_hex': '2ef5dddcf73f208ead616317ab1a9252a07517b52ec0220fcc64743acbbcf241',
                                    'expected': {'action': 'adopt_nm30',
                                                 'classification': 'NEW',
                                                 'durable_kinds': ['NM30'],
                                                 'group': 'G_R_TERMINAL',
                                                 'status': 'COMMIT_UNKNOWN'},
                                    'family': 'transcript'},
 'MF-VERSION-CATALOG-INHERITANCE': {'authority_fingerprint_hex': 'fb9d1c9219608ddd86e88be7d87bb1afbcc4397f49bbee5144aca1d2253e9e4c',
                                    'expected': {'accepted_control_selected_values': [1, 2],
                                                 'accepted_wire_changed': False,
                                                 'docs_25_26_refreeze_forbidden_in_this_candidate': True,
                                                 'mf_o01_status': 'SPEC_ACCEPTED_GREEN_BASELINE_HISTORY',
                                                 'mf_o09_status': 'SPEC_ACCEPTED_CLOSED',
                                                 'mfdt_accept_type': 53,
                                                 'mfdt_candidate_type_count': 16,
                                                 'mfdt_candidate_type_range': '0x34..0x43',
                                                 'mfdt_negotiation_independent_of_selected_control_version': True,
                                                 'mfdt_offer_type': 52,
                                                 'mfdt_transfer_type_count': 14,
                                                 'selected_3_includes_u5_u6_mf': False,
                                                 'selected_control_version_3': 'REJECT',
                                                 'silent_ge2_forbidden': True,
                                                 'status': 'OK',
                                                 'target_promotion_on': 'UNALLOCATED_UNSUPPORTED'},
                                    'family': 'catalog'}}

CHUNK_SIZE = 896
MAX_CONTENT = 32768
MAX_CHUNKS = 37
ENTRIES_PER_PAGE = 22
HEADER_BYTES = 308
NM30_BYTES = 180
NM30_LEGACY_SCHEMA1_BYTES = 164
RECEIVER_FULLS_MAX = 77
SENDER_FULLS_MAX = 67
RECEIVER_FULLS_EMPTY = 5
SENDER_FULLS_EMPTY = 5

# Independent constants (not taken from vector trust alone).
GATE_INDEPENDENT_CONSTANTS: dict[str, int] = {
    "chunk_size": 896,
    "max_content_bytes": 32768,
    "max_chunk_count": 37,
    "entries_per_page": 22,
    "max_manifest_pages": 2,
    "active_header_bytes": 308,
    "nm30_value_bytes": 180,
    "nm30_legacy_schema1_value_bytes": 164,
    "receiver_fulls_max_transfer": 77,
    "sender_fulls_max_transfer": 67,
    "receiver_fulls_empty_transfer": 5,
    "sender_fulls_empty_transfer": 5,
    "required_receiver_fulls_reference": 154,
    "required_sender_fulls_reference": 134,
    "obsolete_rejected_mf_fulls_per_day": 80,
    "ncl1_body_max": 998,
    "workspace_bytes": 65536,
    "open_base_fixed_bytes": 234,
    "application_binding_bytes": 228,
    "open_fixed_bytes": 462,
    "open_body_min": 465,
    "open_body_max": 651,
    "page_header_bytes": 92,
    "chunk_offer_header_bytes": 96,
    "transfer_accept_bytes": 160,
    "bind52_bytes": 52,
    "nrc1_slot_bytes": 208,
    "nrc1_value_bytes": 15020,
    "nrc1_logical_bytes": 15056,
    "active_record_schema": 2,
    "active_value_max": 35211,
    "active_row_logical_bytes_max": 35247,
    "active_replacement_begin_final_logical_bytes_max": 70494,
    "admission_reserved_logical_bytes": 50519,
    "host_slot_count": 4,
    "host_coordinator_bytes": 512,
    "host_control_arena_bytes": 17920,
    "host_terminal_catalog_entries": 16,
    "host_terminal_catalog_entry_bytes": 64,
    "host_control_outbox_bytes": 1024,
    "host_control_route_sentinel": 255,
    "host_owner_workspace_bytes": 280064,
    "host_active_group_logical_bytes": 50303,
    "host_four_active_committed_logical_bytes": 201212,
    "host_committed_logical_bytes_hard_max": 384476,
    "host_serialized_full_staging_logical_bytes_max": 50303,
    "host_begin_final_union_logical_bytes_hard_max": 434779,
}

APPLICATION_BINDING_LAYOUT_GATE: tuple[tuple[str, int, int], ...] = (
    ("original_attempt_id", 234, 16),
    ("target_ordinal_u32", 250, 4),
    ("source_application_instance_id", 254, 16),
    ("source_device_id", 270, 16),
    ("source_installation_id", 286, 16),
    ("source_site_domain_id", 302, 16),
    ("source_binding_epoch_u64", 318, 8),
    ("source_membership_epoch_u64", 326, 8),
    ("source_identity_flags_u32", 334, 4),
    ("source_reserved_u32", 338, 4),
    ("target_application_instance_id", 342, 16),
    ("target_device_id", 358, 16),
    ("target_installation_id", 374, 16),
    ("target_site_domain_id", 390, 16),
    ("target_binding_epoch_u64", 406, 8),
    ("target_membership_epoch_u64", 414, 8),
    ("target_identity_flags_u32", 422, 4),
    ("target_reserved_u32", 426, 4),
    ("service_schema_major_u16", 430, 2),
    ("service_schema_minor_u16", 432, 2),
    ("service_family_u32", 434, 4),
    ("application_generation_u64", 438, 8),
    ("evidence_grace_ms_u64", 446, 8),
    ("required_evidence_u32", 454, 4),
    ("application_binding_flags_u32", 458, 4),
)

DOCUMENT_TOP_LEVEL_KEYS = frozenset(
    {
        "schema",
        "status",
        "adr",
        "title",
        "nonclaims",
        "constants",
        "version_catalog",
        "carrier_mapping",
        "publication_owner",
        "role_boundaries",
        "private_api",
        "budget",
        "required_vector_ids",
        "required_gate_cases",
        "authority_map_sha256_hex",
        "authority_index",
        "vectors",
        "sources",
        "source_sha256_hex",
    }
)

VECTOR_COMMON_REQUIRED = frozenset(
    {"id", "family", "expected", "authority_fingerprint_hex"}
)

# Closed optional extras by family (exact required/optional sets).
VECTOR_OPTIONAL_BY_FAMILY: dict[str, frozenset[str]] = {
    "catalog": frozenset(
        {
            "constants",
            "version_catalog",
            "carrier_mapping",
            "publication_owner",
            "role_boundaries",
            "private_api",
            "storage_profile",
            "required_vector_ids",
            "pin",
            "forbidden_active_state_codes",
            "allowed_pre_terminal_active_codes",
            "stages",
        }
    ),
    "budget": frozenset(
        {
            "budget",
            "groups",
            "receiver_fulls",
            "sender_fulls",
            "feasible",
            "obsolete_cap",
            "required_receiver_fulls",
            "restoration_object",
            "restoration_sha256_hex",
            "value_bytes",
            "logical_bytes",
            "slot_count",
            "min_lifecycle_ids",
            "happy_path_max_ids",
            "reachable_max_ids",
            "n_complete",
            "n_abort",
            "timeout_retry_max",
            "capacity_spare",
            "admission_reserved_entries",
            "admission_reserved_logical_bytes",
            "note",
            "nrc1_retained_until_gc",
            "terminal_erases_nrc1",
            "receiver_fulls",
            "sender_fulls",
            "receiver_base",
            "receiver_resume",
            "receiver_reqid_cache",
            "sender_base",
            "sender_resume",
            "sender_reqid_cache",
            "receiver_retry_budget",
            "sender_retry_budget",
            "session_gen",
            "groups",
            "host_four_active_committed_logical_bytes",
            "host_committed_logical_bytes_hard_max",
            "host_begin_final_union_logical_bytes_hard_max",
        }
    ),
    "positive": frozenset(
        {
            "fixture",
            "first_accept_hex",
            "replay_accept_hex",
            "fixture_ids",
            "request_id",
            "first_page_accept_hex",
            "cached_retry_page_accept_hex",
            "note",
            "first_request_id",
            "second_request_id",
            "second_page_accept_hex",
            "nrc1_key_hex",
            "nrc1_value_hex",
            "nrc1_value_after_second_hex",
            "request_body_digest_hex",
            "nrc1_magic",
            "header_crc_ok",
            "record_crc_ok",
            "occupied_count",
            "exceeds_obsolete_fixed16",
            "happy_first",
            "n_complete",
            "n_abort",
            "reachable_max",
            "timeout_retry_max",
            "resume_max",
            "abort_gen_max",
            "slot_count",
            "capacity_spare",
            "naive_union",
            "formula_complete",
            "formula_abort",
            "retry_request_ids",
            "transcript",
            "retry_budget_sm",
            "session_gen_max",
            "resume_per_gen",
            "peak_with_reclaim",
            "first_units",
            "phase",
            "nm30_key_hex",
            "nm30_value_hex",
            "nm30_sha256_hex",
            "transfer_id_hex",
            "peer_endpoint_id_hex",
            "owner_role_name",
            "durable_fields_exclude",
            "operations",
            "active_transfer_ids",
            "terminal_transfer_id_hex",
            "terminal_request_id",
            "terminal_response_body_hex",
            "first_slot_hex",
            "first_slot_session_generation_hex",
            "empty_slot_hex",
            "occupied_l0_repaired_crc_mutant_hex",
            "generation_1_nrc1_value_hex",
            "generation_2_nrc1_value_hex",
            "retained_non_resume_slot_hex",
            "reclaimed_generation_1_resume_slot_hex",
            "admitted_generation_2_resume_slot_hex",
            "request_id_reused_across_generation",
            "initial_session_generation",
            "successor_session_generation",
            "future_generation_nrc1_value_hex",
            "gap_generation_nrc1_value_hex",
            "third_generation_nrc1_value_hex",
            "application_binding_layout",
            "minimum_open_body_hex",
            "minimum_manifest_digest_hex",
            "minimum_facts",
            "maximum_open_body_hex",
            "maximum_manifest_digest_hex",
            "maximum_facts",
            "deadline_shape_cases",
            "domain_ascii",
            "publication_token_hex",
            "origin_transaction_id_hex",
            "original_attempt_id_hex",
            "target_ordinal",
            "evidence_stage",
            "evidence_bytes_hex",
            "evidence_preimage_hex",
            "application_evidence_digest_hex",
            "callback_context_id_hex",
            "callback_context_authority",
            "publication_token_scope",
        }
    ),
    "negative": frozenset(
        {
            "abort_ack_hex",
            "abort_hex",
            "actual_whole_hex",
            "admission",
            "attempted_message_type",
            "bytes_hard_max",
            "carrier",
            "chunk_bitmap",
            "chunk_count",
            "chunk_index",
            "claimed_total_length",
            "claimed_whole_hex",
            "content_hex",
            "expected_whole_hex",
            "finalize_hex",
            "first_digest_hex",
            "first_full",
            "first_offer_hex",
            "keys_hard_max",
            "request_id",
            "first_request_body_digest_hex",
            "second_request_body_digest_hex",
            "epoch_before_hex",
            "epoch_after_hex",
            "transfer_state_before",
            "nrc1_slot_occupied",
            "nrc1_key_hex",
            "nrc1_value_hex",
            "occupied_count",
            "new_request_id",
            "last_query_generation",
            "base_selected_control_version",
            "mfdt_admission_version",
            "mfn1_session_generation",
            "active_session_generation",
            "local_policy",
            "local_selected",
            "max_content",
            "may_prepare",
            "message_type",
            "namespace_keys_in_use",
            "namespace_logical_bytes_in_use",
            "nm30_hex",
            "note",
            "now_ms",
            "offer_0_hex",
            "offer_1_hex",
            "offered_query_generation",
            "offers_in_order",
            "open_body_hex",
            "open_preimage_hex",
            "request_body_digest_hex",
            "wrong_bind52_strip_digest_hex",
            "outstanding_unpaid_offers",
            "peer_selected",
            "receiver_state",
            "reservation_not_after_ms",
            "resume_bitmap",
            "resume_query_hex",
            "same_epoch",
            "second",
            "second_digest_hex",
            "second_offer_hex",
            "selected_control_version",
            "transfer_accept_received",
            "mfdt_requires_bytes",
            "mfdt_requires_keys",
            "host_admission_trace",
            "host_restart_input_transfer_ids",
            "host_restart_canonical_slot_transfer_ids",
            "esp_admission_trace",
            "host_bounds",
            "reservation_deadline_matrix",
            "initial_next_slot",
            "continuously_eligible_slots",
            "successful_selection_trace",
            "peer_assignment_by_slot",
            "peer_a_has_unpaid_offer",
            "scan_from_slot",
            "selected_slot_with_peer_a_blocked",
            "next_slot_after_selection",
            "restart_next_slot",
            "phase",
            "nrc1_present",
            "nm30_present",
            "illegal_occupancy",
            "slot_count",
            "legacy_nm30_value_hex",
            "catalog_state",
            "permitted_actions",
            "forbidden_actions",
            "authority",
            "cases",
            "fresh_open_body_hex",
            "busy_body_hex",
            "busy_layout",
            "first_owned_frame",
            "blocked_second_frame",
            "response_body_hex",
            "admission_policy",
            "g_r_open_started",
            "deadline_relation",
            "request_type",
            "request_body_hex",
            "nrc1_slot_hex",
            "active_slot",
            "full_group",
            "manifest_entries_hex",
            "manifest_digest_hex",
            "mutations",
            "mismatch_fields",
            "validation_boundary",
        }
    ),
    "commit_unknown": frozenset(
        {"group", "old_rows", "new_rows", "observed_rows", "note"}
    ),
    "transcript": frozenset(
        {
            "committed_chunk_bitmap",
            "fixture_ids",
            "observed_kinds",
            "pre_terminal_state",
            "nm30_terminal_state",
            "terminal_reason",
            "post_restart_page_accept_hex",
            "nrc1_key_hex",
            "nrc1_value_hex",
            "request_id",
            "first_page_accept_hex",
            "transcript",
            "last_full_group",
            "now_ms",
            "publication_token_hex",
            "resume_state_hex",
            "resume_state_length",
            "retention_ms",
            "retention_epoch_id_hex",
            "retention_anchor_ms",
            "retention_duration_ms",
            "retention_boundary_ms",
            "boundary_matrix",
            "terminal_catalog",
            "tombstone_digest_hex",
            "steps",
            "tombstone_present_after",
            "tombstone_present_before",
            "nrc1_present_before",
            "nrc1_present_after",
            "nm30_key_hex",
            "nm30_value_hex",
            "phase",
            "note",
            "recovered_catalog_entry",
            "rebind",
            "hit",
            "post_terminal_miss",
        }
    ),
}

AUTHORITY_INDEX_ROW_KEYS = frozenset(
    {"family", "expected", "authority_fingerprint_hex"}
)

FIXTURE_KEYS = frozenset(
    {
        "acceptance_record_digest_hex",
        "chunk_accepts",
        "chunks",
        "content_hex",
        "content_sha256_hex",
        "entries_hex",
        "facts",
        "finalize_hex",
        "finalize_length",
        "full_chunk_bitmap",
        "full_page_bitmap",
        "ids",
        "manifest_digest_hex",
        "nm30_key_hex",
        "nm30_value_hex",
        "open_accept_hex",
        "open_accept_length",
        "open_body_hex",
        "page_accepts",
        "pages",
        "publication_token_hex",
        "receiver_content_verified_key_hex",
        "receiver_content_verified_sha256_hex",
        "receiver_content_verified_value_hex",
        "reservation_not_after_ms",
        "tombstone_digest_hex",
        "transfer_accept_hex",
        "transfer_accept_length",
    }
)

FIXTURE_FACTS_KEYS = frozenset(
    {
        "application_binding_hex",
        "application_binding_length",
        "application_binding_offset",
        "application_generation",
        "chunk_count",
        "chunk_size",
        "evidence_grace_ms",
        "manifest_digest_hex",
        "manifest_page_count",
        "manifest_revision",
        "namespace",
        "open_body_length",
        "required_evidence",
        "schema",
        "service",
        "service_family",
        "service_schema_major",
        "service_schema_minor",
        "target_ordinal",
        "text_offset",
        "total_length",
        "whole_content_sha256_hex",
    }
)

FIXTURE_IDS_KEYS = frozenset(
    {
        "authority_actor_id",
        "deadline_clock_epoch_id",
        "origin_event_id",
        "origin_transaction_id",
        "original_attempt_id",
        "receiver_evidence_id",
        "reservation_clock_epoch_id",
        "reservation_id",
        "service_descriptor_digest",
        "source_runtime_id",
        "source_application_instance_id",
        "source_device_id",
        "source_installation_id",
        "source_site_domain_id",
        "target_runtime_id",
        "target_application_instance_id",
        "target_device_id",
        "target_installation_id",
        "target_site_domain_id",
        "transfer_id",
    }
)

PAGE_META_KEYS = frozenset(
    {
        "body_hex",
        "body_length",
        "entry_count",
        "first_chunk_index",
        "page_count",
        "page_digest_hex",
        "page_index",
    }
)

CHUNK_META_KEYS = frozenset(
    {
        "body_hex",
        "body_length",
        "chunk_bytes_hex",
        "chunk_count",
        "chunk_index",
        "chunk_length",
        "chunk_offset",
        "chunk_sha256_hex",
    }
)

PAGE_ACCEPT_KEYS = frozenset(
    {"body_hex", "body_length", "manifest_complete", "page_index"}
)
CHUNK_ACCEPT_KEYS = frozenset({"body_hex", "body_length", "chunk_index"})
CU_ROW_KEYS = frozenset({"key_hex", "value_hex"})

JSON_SAFE_INT_MAX = (1 << 53) - 1

CONSTANTS_KEYS = frozenset(
    {
        "abort_generation_max",
        "active_header_bytes",
        "active_header_session_generation_offset",
        "active_value_max",
        "active_record_schema",
        "active_schema1_replay_eligible",
        "application_binding_bytes",
        "application_binding_layout",
        "chunk_size",
        "digest_domains",
        "entries_per_page",
        "esp_active_transfers_max",
        "host_active_transfers_max",
        "host_control_arena_bytes",
        "host_control_nm30_scratch_bytes",
        "host_control_nrc1_scratch_bytes",
        "host_control_outbox_bytes",
        "host_control_outbox_metadata_bytes",
        "host_control_recovery_reserved_bytes",
        "host_control_route_sentinel",
        "host_coordinator_bytes",
        "host_fair_selection_bound",
        "host_owner_full_transactions_max",
        "host_owner_workspace_bytes",
        "host_peer_unpaid_chunk_offer_max",
        "host_scheduler_next_slot_initial",
        "host_scheduler_scan_bound",
        "host_slot_count",
        "host_terminal_catalog_bytes",
        "host_terminal_catalog_entries",
        "host_terminal_catalog_entry_bytes",
        "manifest_entry_bytes",
        "mfdt_admission_profile_revision",
        "max_chunk_count",
        "max_content_bytes",
        "max_manifest_pages",
        "message_types",
        "ncl1_body_max",
        "nm30_value_bytes",
        "nm30_schema",
        "nm30_peer_endpoint_id_offset",
        "nm30_peer_endpoint_id_bytes",
        "nm30_owner_role_offset",
        "nm30_reserved_offset",
        "nm30_reserved_bytes",
        "nm30_crc_offset",
        "nm30_crc_preimage_bytes",
        "nm30_session_cookie_durable",
        "nm30_legacy_schema1_value_bytes",
        "nm30_legacy_schema1_replay_eligible",
        "nm30_expired_reason_terminal_only",
        "nm30_terminal_reasons",
        "nm30_terminal_states",
        "nrc1_capacity_spare",
        "nrc1_happy_path_max_ids",
        "nrc1_illegal_two_gen_no_reclaim",
        "nrc1_logical_bytes",
        "nrc1_n_abort",
        "nrc1_n_complete",
        "nrc1_naive_union_ids_rejected_as_single_path",
        "nrc1_reachable_max_ids",
        "nrc1_resume_reclaim_on_session_gen_advance",
        "nrc1_session_gen_max_per_transfer",
        "nrc1_slot_bytes",
        "nrc1_slot_count",
        "nrc1_slot_lookup_identity",
        "nrc1_slot_session_generation_offset",
        "nrc1_header_session_generation_offset",
        "nrc1_occupied_response_length_min",
        "nrc1_occupied_response_length_max",
        "nrc1_empty_slot_all_zero",
        "nrc1_value_bytes",
        "nts3_current_schema_major",
        "nts3_current_schema_minor",
        "nts3_future_fields",
        "nts3_future_schema_minor",
        "nts3_future_target_suffix_placement",
        "nts3_future_target_suffix_presence",
        "nts3_future_target_suffix_bytes",
        "nts3_future_target_count_max",
        "nts3_future_mfdt_target_rule",
        "nts3_future_non_mfdt_suffix_bytes",
        "nts3_future_non_mfdt_memory_rule",
        "nts3_schema11_record_max_bytes",
        "nts3_schema11_inline_payload_max_bytes",
        "nts3_future_mfdt_record_max_bytes",
        "nts3_record_ceiling_bytes",
        "open_base_fixed_bytes",
        "open_body_max",
        "open_body_min",
        "open_fixed_bytes",
        "open_growth_bytes_redistributed_within_each_slot",
        "open_text_offset",
        "manifest_digest_preimage",
        "manifest_entry_layout",
        "no_deadline_u64_hex",
        "finite_downlink_deadline_min_u64_hex",
        "finite_downlink_deadline_max_u64_hex",
        "uplink_eventfact_deadline_shape",
        "finite_downlink_deadline_shape",
        "original_application_open_deadline_mapping",
        "public_callback_context_id",
        "publication_token_scope",
        "reject_codes",
        "request_body_digest_preimage",
        "reservation_lifetime_ms",
        "reservation_add_overflow_threshold_u64_hex",
        "different_epoch_numeric_deadline_compare_forbidden",
        "restart_requires_full_semantic_validation_before_install",
        "resume_query_max",
        "retention_ms",
        "retention_requires_same_trusted_epoch",
        "retry_budget_decrement_event",
        "retry_budget_header_offset",
        "retry_budget_initial",
        "retry_budget_owner",
        "retry_budget_remaining_max",
        "retry_budget_remaining_min",
        "retry_budget_scope",
        "sha256_empty_hex",
        "stages",
        "storage_key_bytes",
        "storage_kinds",
        "timeout_retry_max",
        "terminal_session_generation_authority",
        "workspace_bytes",
        "workspace_growth_bytes",
        "workspace_scope",
        "wire_abort_reasons",
    }
)

BUDGET_KEYS = frozenset(
    {
        "active_row_logical_bytes_max",
        "active_replacement_begin_final_logical_bytes_max",
        "admission_reserved_entries",
        "admission_reserved_logical_bytes",
        "groups",
        "host_active_group_logical_bytes",
        "host_begin_final_union_logical_bytes_hard_max",
        "host_committed_keys_hard_max",
        "host_committed_logical_bytes_hard_max",
        "host_four_active_committed_logical_bytes",
        "host_serialized_full_staging_logical_bytes_max",
        "host_serialized_full_staging_row_images_max",
        "host_slot_count",
        "host_terminal_group_logical_bytes",
        "host_tracked_transfer_groups_max",
        "namespace_keys_hard_max",
        "namespace_logical_bytes_hard_max",
        "nrc1_capacity_spare",
        "nrc1_happy_path_max_ids",
        "nrc1_n_abort",
        "nrc1_n_complete",
        "nrc1_reachable_max_ids",
        "nrc1_retained_until_gc",
        "nrc1_row_logical_bytes",
        "nrc1_slot_count",
        "nrc1_timeout_retry_max",
        "nrc1_value_bytes",
        "obsolete_80_feasible_for_reference_receiver",
        "obsolete_rejected_mf_fulls_per_day",
        "planned_mf_maxsize_transfers_per_day_reference",
        "post_terminal_retained_entries",
        "post_terminal_retained_logical_bytes",
        "receiver_fulls_base",
        "receiver_fulls_empty_transfer",
        "receiver_fulls_max_transfer",
        "receiver_fulls_reqid_cache",
        "receiver_fulls_resume",
        "receiver_fulls_retry_budget",
        "receiver_fulls_session_gen",
        "required_receiver_fulls_for_reference",
        "required_sender_fulls_for_reference",
        "restoration_object",
        "restoration_sha256_hex",
        "sender_fulls_base",
        "sender_fulls_empty_transfer",
        "sender_fulls_max_transfer",
        "sender_fulls_reqid_cache",
        "sender_fulls_resume",
        "sender_fulls_retry_budget",
        "sender_fulls_session_gen",
        "session_gen_max_per_transfer",
        "terminal_row_logical_bytes",
    }
)

VERSION_CATALOG_KEYS = frozenset(
    {
        "accepted_freeze_docs_untouched",
        "accepted_control_selected_values",
        "accepted_ncl1_type_values",
        "accepted_u5_u6_selected_exact",
        "accepted_wire_changed",
        "default_policy",
        "docs_25_26_current_selected_exact_2",
        "docs_25_26_refreeze_forbidden_in_this_candidate",
        "hello_body_bytes",
        "mf_o01_false_close_forbidden",
        "mf_o01_status",
        "mf_o09_status",
        "mfdt_admission_requires",
        "mfdt_does_not_claim_selected_3_includes_u5_u6",
        "mfdt_message_types",
        "mfdt_accept_body_bytes",
        "mfdt_accept_digest_preimage",
        "mfdt_accept_type",
        "mfdt_base_control_versions",
        "mfdt_candidate_contiguous_minimal_after_accepted",
        "mfdt_candidate_type_count",
        "mfdt_candidate_type_values",
        "mfdt_negotiation_domain",
        "mfdt_negotiation_independent_of_selected_control_version",
        "mfdt_negotiation_version",
        "mfdt_offer_body_bytes",
        "mfdt_offer_digest_preimage",
        "mfdt_offer_type",
        "mfdt_transfer_type_count",
        "mixed_version_fail_closed",
        "obsolete_selected_3_inheritance_table",
        "private_admission_without_policy",
        "revision1_revision2_interop",
        "selected_control_version_3",
        "silent_ge2_forbidden",
        "target_promotion_off",
        "target_promotion_on",
        "u5_u6_wire_body",
        "void_old_proposed_type_values",
    }
)


class GateError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise GateError(message)


def sha(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def reject_json_constant(value: str) -> None:
    fail(f"json constant forbidden: {value}")


def _reject_noncanonical_number_tokens(text: str) -> None:
    """Reject raw non-canonical JSON number tokens (-0, leading zeros, floats, exp, unsafe)."""

    i = 0
    n = len(text)
    in_string = False
    escape = False
    while i < n:
        c = text[i]
        if in_string:
            if escape:
                escape = False
                i += 1
                continue
            if c == "\\":
                escape = True
                i += 1
                continue
            if c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
            i += 1
            continue
        if c == "-" or ("0" <= c <= "9"):
            start = i
            if c == "-":
                i += 1
                if i >= n or not ("0" <= text[i] <= "9"):
                    fail(f"noncanonical numeric token near {start}")
            if text[i] == "0":
                i += 1
                if i < n and "0" <= text[i] <= "9":
                    fail(f"leading-zero numeric token: {text[start:i+1]}")
            else:
                while i < n and "0" <= text[i] <= "9":
                    i += 1
            if i < n and text[i] in ".eE+":
                fail(f"non-integer json number forbidden: {text[start:i+8]}")
            token = text[start:i]
            if token in ("-0", "+0") or token.startswith("+"):
                fail(f"noncanonical numeric token: {token}")
            try:
                value = int(token, 10)
            except ValueError as error:
                raise GateError(f"noncanonical numeric token: {token}") from error
            if abs(value) > JSON_SAFE_INT_MAX:
                fail(f"unsafe integer: {token}")
            continue
        i += 1


def load_strict_json(raw: bytes | str) -> Any:
    """Parse JSON with duplicate-key rejection and no NaN/Infinity.

    Numbers that are not integers (e.g. 3.0, 1e2, -0) are rejected so that
    selected_control_version and other closed integer fields cannot coerce.
    Duplicate keys are compared on decoded JSON key strings (Unicode escapes).
    """

    text = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw
    _reject_noncanonical_number_tokens(text)

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                fail(f"duplicate json key: {key}")
            out[key] = value
        return out

    def parse_float(token: str) -> Any:
        # Reject all non-integer JSON numbers (3.0, 1.5, 1e3, NaN, Infinity).
        fail(f"non-integer json number forbidden: {token}")

    def parse_int(token: str) -> int:
        if token in ("-0", "+0") or token.startswith("+"):
            fail(f"noncanonical numeric token: {token}")
        value = int(token, 10)
        if abs(value) > JSON_SAFE_INT_MAX:
            fail(f"unsafe integer: {token}")
        return value

    try:
        document = json.loads(
            text,
            parse_int=parse_int,
            parse_float=parse_float,
            parse_constant=reject_json_constant,
            object_pairs_hook=object_pairs,
        )
    except GateError:
        raise
    except json.JSONDecodeError as error:
        fail(f"json decode: {error}")
    _reject_noncanonical_numbers(document, "$")
    return document


def _reject_noncanonical_numbers(value: Any, path: str) -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, float):
        fail(f"float at {path}")
    if isinstance(value, int):
        if abs(value) > JSON_SAFE_INT_MAX:
            fail(f"unsafe integer at {path}: {value}")
        return
    if isinstance(value, str) or value is None:
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_noncanonical_numbers(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                fail(f"non-string key at {path}")
            _reject_noncanonical_numbers(item, f"{path}.{key}")
        return
    fail(f"unsupported json type at {path}: {type(value).__name__}")


def assert_exact_keys(obj: dict[str, Any], allowed: frozenset[str], path: str) -> None:
    if not isinstance(obj, dict):
        fail(f"{path}: expected object")
    keys = set(obj.keys())
    unknown = keys - allowed
    if unknown:
        fail(f"{path}: unknown keys {sorted(unknown)}")
    missing = allowed - keys
    if missing:
        fail(f"{path}: missing keys {sorted(missing)}")


def assert_type(value: Any, kind: str, path: str) -> None:
    if kind == "str":
        if not isinstance(value, str):
            fail(f"{path}: expected string, got {type(value).__name__}")
        return
    if kind == "bool":
        if not isinstance(value, bool):
            fail(f"{path}: expected bool, got {type(value).__name__}")
        return
    if kind == "int":
        # bool is a subclass of int in Python — fence bools off integers.
        if isinstance(value, bool) or not isinstance(value, int):
            fail(f"{path}: expected int, got {type(value).__name__}")
        if abs(value) > JSON_SAFE_INT_MAX:
            fail(f"{path}: unsafe integer {value}")
        return
    if kind == "list":
        if not isinstance(value, list):
            fail(f"{path}: expected array, got {type(value).__name__}")
        return
    if kind == "dict":
        if not isinstance(value, dict):
            fail(f"{path}: expected object, got {type(value).__name__}")
        return
    fail(f"{path}: unknown type kind {kind}")


def assert_str_list(value: Any, path: str) -> None:
    assert_type(value, "list", path)
    for index, item in enumerate(value):
        assert_type(item, "str", f"{path}[{index}]")


def assert_int_map(value: Any, path: str, keys: frozenset[str] | None = None) -> None:
    assert_type(value, "dict", path)
    if keys is not None:
        assert_exact_keys(value, keys, path)
    for key, item in value.items():
        if not isinstance(key, str):
            fail(f"{path}: non-string key")
        assert_type(item, "int", f"{path}.{key}")


def assert_expected_object(value: Any, path: str, required_keys: frozenset[str] | None = None) -> None:
    assert_type(value, "dict", path)
    if required_keys is not None:
        assert_exact_keys(value, required_keys, path)
    for key, item in value.items():
        if not isinstance(key, str):
            fail(f"{path}: non-string key")
        if isinstance(item, bool):
            continue
        if isinstance(item, int):
            if abs(item) > JSON_SAFE_INT_MAX:
                fail(f"{path}.{key}: unsafe integer")
            continue
        if isinstance(item, str):
            continue
        if isinstance(item, list):
            for index, elem in enumerate(item):
                if isinstance(elem, bool):
                    fail(f"{path}.{key}[{index}]: bool not allowed in expected list")
                if isinstance(elem, int):
                    if abs(elem) > JSON_SAFE_INT_MAX:
                        fail(f"{path}.{key}[{index}]: unsafe integer")
                    continue
                if isinstance(elem, str):
                    continue
                fail(f"{path}.{key}[{index}]: expected int|str")
            continue
        fail(f"{path}.{key}: expected int|str|bool|list, got {type(item).__name__}")


def validate_cu_rows(rows: Any, path: str) -> None:
    assert_type(rows, "list", path)
    for index, row in enumerate(rows):
        rpath = f"{path}[{index}]"
        assert_exact_keys(row, CU_ROW_KEYS, rpath)
        assert_type(row["key_hex"], "str", f"{rpath}.key_hex")
        assert_type(row["value_hex"], "str", f"{rpath}.value_hex")


def validate_fixture_closed(fixture: Any, path: str) -> None:
    assert_exact_keys(fixture, FIXTURE_KEYS, path)
    for key in (
        "acceptance_record_digest_hex",
        "content_hex",
        "content_sha256_hex",
        "finalize_hex",
        "manifest_digest_hex",
        "nm30_key_hex",
        "nm30_value_hex",
        "open_accept_hex",
        "open_body_hex",
        "publication_token_hex",
        "receiver_content_verified_key_hex",
        "receiver_content_verified_sha256_hex",
        "receiver_content_verified_value_hex",
        "tombstone_digest_hex",
        "transfer_accept_hex",
    ):
        assert_type(fixture[key], "str", f"{path}.{key}")
    for key in (
        "finalize_length",
        "full_chunk_bitmap",
        "full_page_bitmap",
        "open_accept_length",
        "reservation_not_after_ms",
        "transfer_accept_length",
    ):
        assert_type(fixture[key], "int", f"{path}.{key}")
    assert_str_list(fixture["entries_hex"], f"{path}.entries_hex")
    assert_exact_keys(fixture["facts"], FIXTURE_FACTS_KEYS, f"{path}.facts")
    for key in (
        "application_binding_length",
        "application_binding_offset",
        "application_generation",
        "chunk_count",
        "chunk_size",
        "evidence_grace_ms",
        "manifest_page_count",
        "manifest_revision",
        "open_body_length",
        "required_evidence",
        "service_family",
        "service_schema_major",
        "service_schema_minor",
        "target_ordinal",
        "text_offset",
        "total_length",
    ):
        assert_type(fixture["facts"][key], "int", f"{path}.facts.{key}")
    for key in (
        "application_binding_hex",
        "manifest_digest_hex",
        "namespace",
        "schema",
        "service",
        "whole_content_sha256_hex",
    ):
        assert_type(fixture["facts"][key], "str", f"{path}.facts.{key}")
    assert_exact_keys(fixture["ids"], FIXTURE_IDS_KEYS, f"{path}.ids")
    for key in FIXTURE_IDS_KEYS:
        assert_type(fixture["ids"][key], "str", f"{path}.ids.{key}")
    assert_type(fixture["pages"], "list", f"{path}.pages")
    for index, page in enumerate(fixture["pages"]):
        ppath = f"{path}.pages[{index}]"
        assert_exact_keys(page, PAGE_META_KEYS, ppath)
        assert_type(page["body_hex"], "str", f"{ppath}.body_hex")
        assert_type(page["page_digest_hex"], "str", f"{ppath}.page_digest_hex")
        for key in (
            "body_length",
            "entry_count",
            "first_chunk_index",
            "page_count",
            "page_index",
        ):
            assert_type(page[key], "int", f"{ppath}.{key}")
    assert_type(fixture["chunks"], "list", f"{path}.chunks")
    for index, chunk in enumerate(fixture["chunks"]):
        cpath = f"{path}.chunks[{index}]"
        assert_exact_keys(chunk, CHUNK_META_KEYS, cpath)
        for key in ("body_hex", "chunk_bytes_hex", "chunk_sha256_hex"):
            assert_type(chunk[key], "str", f"{cpath}.{key}")
        for key in (
            "body_length",
            "chunk_count",
            "chunk_index",
            "chunk_length",
            "chunk_offset",
        ):
            assert_type(chunk[key], "int", f"{cpath}.{key}")
    assert_type(fixture["page_accepts"], "list", f"{path}.page_accepts")
    for index, acc in enumerate(fixture["page_accepts"]):
        apath = f"{path}.page_accepts[{index}]"
        assert_exact_keys(acc, PAGE_ACCEPT_KEYS, apath)
        assert_type(acc["body_hex"], "str", f"{apath}.body_hex")
        for key in ("body_length", "manifest_complete", "page_index"):
            assert_type(acc[key], "int", f"{apath}.{key}")
    assert_type(fixture["chunk_accepts"], "list", f"{path}.chunk_accepts")
    for index, acc in enumerate(fixture["chunk_accepts"]):
        apath = f"{path}.chunk_accepts[{index}]"
        assert_exact_keys(acc, CHUNK_ACCEPT_KEYS, apath)
        assert_type(acc["body_hex"], "str", f"{apath}.body_hex")
        for key in ("body_length", "chunk_index"):
            assert_type(acc[key], "int", f"{apath}.{key}")


def validate_closed_schema(document: Any) -> None:
    """Recursive closed schema/type validator for the MFDT SPEC vector document."""

    assert_type(document, "dict", "$")
    assert_exact_keys(document, DOCUMENT_TOP_LEVEL_KEYS, "$")
    for key in (
        "schema",
        "status",
        "adr",
        "title",
        "authority_map_sha256_hex",
    ):
        assert_type(document[key], "str", f"$.{key}")
    assert_str_list(document["nonclaims"], "$.nonclaims")
    assert_str_list(document["required_vector_ids"], "$.required_vector_ids")
    assert_str_list(document["required_gate_cases"], "$.required_gate_cases")
    assert_str_list(document["sources"], "$.sources")
    assert_type(document["source_sha256_hex"], "dict", "$.source_sha256_hex")
    assert_exact_keys(
        document["source_sha256_hex"],
        frozenset(PINNED_SOURCES),
        "$.source_sha256_hex",
    )
    for rel in PINNED_SOURCES:
        assert_type(
            document["source_sha256_hex"][rel],
            "str",
            f"$.source_sha256_hex.{rel}",
        )

    constants = document["constants"]
    assert_exact_keys(constants, CONSTANTS_KEYS, "$.constants")
    for key, kind in (
        ("abort_generation_max", "int"),
        ("active_header_bytes", "int"),
        ("active_header_session_generation_offset", "int"),
        ("active_record_schema", "int"),
        ("active_value_max", "int"),
        ("application_binding_bytes", "int"),
        ("chunk_size", "int"),
        ("entries_per_page", "int"),
        ("esp_active_transfers_max", "int"),
        ("host_active_transfers_max", "int"),
        ("host_control_arena_bytes", "int"),
        ("host_control_nm30_scratch_bytes", "int"),
        ("host_control_nrc1_scratch_bytes", "int"),
        ("host_control_outbox_bytes", "int"),
        ("host_control_outbox_metadata_bytes", "int"),
        ("host_control_recovery_reserved_bytes", "int"),
        ("host_control_route_sentinel", "int"),
        ("host_coordinator_bytes", "int"),
        ("host_fair_selection_bound", "int"),
        ("host_owner_full_transactions_max", "int"),
        ("host_owner_workspace_bytes", "int"),
        ("host_peer_unpaid_chunk_offer_max", "int"),
        ("host_scheduler_next_slot_initial", "int"),
        ("host_scheduler_scan_bound", "int"),
        ("host_slot_count", "int"),
        ("host_terminal_catalog_bytes", "int"),
        ("host_terminal_catalog_entries", "int"),
        ("host_terminal_catalog_entry_bytes", "int"),
        ("manifest_entry_bytes", "int"),
        ("mfdt_admission_profile_revision", "int"),
        ("max_chunk_count", "int"),
        ("max_content_bytes", "int"),
        ("max_manifest_pages", "int"),
        ("ncl1_body_max", "int"),
        ("nm30_crc_offset", "int"),
        ("nm30_crc_preimage_bytes", "int"),
        ("nm30_legacy_schema1_value_bytes", "int"),
        ("nm30_owner_role_offset", "int"),
        ("nm30_peer_endpoint_id_bytes", "int"),
        ("nm30_peer_endpoint_id_offset", "int"),
        ("nm30_reserved_bytes", "int"),
        ("nm30_reserved_offset", "int"),
        ("nm30_schema", "int"),
        ("nm30_value_bytes", "int"),
        ("nm30_expired_reason_terminal_only", "int"),
        ("nts3_current_schema_major", "int"),
        ("nts3_current_schema_minor", "int"),
        ("nts3_future_schema_minor", "int"),
        ("open_base_fixed_bytes", "int"),
        ("open_body_max", "int"),
        ("open_body_min", "int"),
        ("open_fixed_bytes", "int"),
        ("open_growth_bytes_redistributed_within_each_slot", "int"),
        ("open_text_offset", "int"),
        ("no_deadline_u64_hex", "str"),
        ("finite_downlink_deadline_min_u64_hex", "str"),
        ("finite_downlink_deadline_max_u64_hex", "str"),
        ("uplink_eventfact_deadline_shape", "str"),
        ("finite_downlink_deadline_shape", "str"),
        ("original_application_open_deadline_mapping", "str"),
        ("public_callback_context_id", "str"),
        ("publication_token_scope", "str"),
        ("reservation_lifetime_ms", "int"),
        ("reservation_add_overflow_threshold_u64_hex", "str"),
        ("resume_query_max", "int"),
        ("retention_ms", "int"),
        ("retry_budget_header_offset", "int"),
        ("retry_budget_initial", "int"),
        ("retry_budget_remaining_max", "int"),
        ("retry_budget_remaining_min", "int"),
        ("timeout_retry_max", "int"),
        ("nrc1_slot_count", "int"),
        ("nrc1_slot_bytes", "int"),
        ("nrc1_header_session_generation_offset", "int"),
        ("nrc1_slot_session_generation_offset", "int"),
        ("nrc1_occupied_response_length_min", "int"),
        ("nrc1_occupied_response_length_max", "int"),
        ("nrc1_value_bytes", "int"),
        ("nrc1_logical_bytes", "int"),
        ("nrc1_happy_path_max_ids", "int"),
        ("nrc1_reachable_max_ids", "int"),
        ("nrc1_n_complete", "int"),
        ("nrc1_n_abort", "int"),
        ("nrc1_capacity_spare", "int"),
        ("nrc1_naive_union_ids_rejected_as_single_path", "int"),
        ("nrc1_session_gen_max_per_transfer", "int"),
        ("nrc1_illegal_two_gen_no_reclaim", "int"),
        ("sha256_empty_hex", "str"),
        ("storage_key_bytes", "int"),
        ("workspace_bytes", "int"),
        ("workspace_growth_bytes", "int"),
        ("workspace_scope", "str"),
        ("terminal_session_generation_authority", "str"),
        ("nrc1_slot_lookup_identity", "str"),
        ("request_body_digest_preimage", "str"),
        ("manifest_digest_preimage", "str"),
        ("manifest_entry_layout", "str"),
        ("retry_budget_scope", "str"),
        ("retry_budget_owner", "str"),
        ("retry_budget_decrement_event", "str"),
    ):
        assert_type(constants[key], kind, f"$.constants.{key}")
    assert_type(constants["digest_domains"], "dict", "$.constants.digest_domains")
    for key, item in constants["digest_domains"].items():
        assert_type(item, "str", f"$.constants.digest_domains.{key}")
    assert_int_map(constants["message_types"], "$.constants.message_types")
    assert_int_map(constants["nm30_terminal_reasons"], "$.constants.nm30_terminal_reasons")
    assert_int_map(constants["nm30_terminal_states"], "$.constants.nm30_terminal_states")
    assert_int_map(constants["reject_codes"], "$.constants.reject_codes")
    assert_int_map(constants["stages"], "$.constants.stages")
    assert_int_map(constants["wire_abort_reasons"], "$.constants.wire_abort_reasons")
    assert_str_list(constants["storage_kinds"], "$.constants.storage_kinds")
    assert_str_list(constants["nts3_future_fields"], "$.constants.nts3_future_fields")
    assert_type(constants["application_binding_layout"], "list", "$.constants.application_binding_layout")
    for index, field in enumerate(constants["application_binding_layout"]):
        path = f"$.constants.application_binding_layout[{index}]"
        assert_exact_keys(field, frozenset({"field", "offset", "bytes"}), path)
        assert_type(field["field"], "str", f"{path}.field")
        assert_type(field["offset"], "int", f"{path}.offset")
        assert_type(field["bytes"], "int", f"{path}.bytes")
    for key in (
        "active_schema1_replay_eligible",
        "different_epoch_numeric_deadline_compare_forbidden",
        "nm30_legacy_schema1_replay_eligible",
        "nm30_session_cookie_durable",
        "nrc1_empty_slot_all_zero",
        "nrc1_resume_reclaim_on_session_gen_advance",
        "restart_requires_full_semantic_validation_before_install",
        "retention_requires_same_trusted_epoch",
    ):
        assert_type(constants[key], "bool", f"$.constants.{key}")
        if key in (
            "active_schema1_replay_eligible",
            "nm30_legacy_schema1_replay_eligible",
            "nm30_session_cookie_durable",
        ):
            if constants[key] is not False:
                fail(f"constants {key} must be false")
        elif constants[key] is not True:
            fail(f"constants {key} must be true")
    if [
        (field["field"], field["offset"], field["bytes"])
        for field in constants["application_binding_layout"]
    ] != list(APPLICATION_BINDING_LAYOUT_GATE):
        fail("constants application binding layout")
    if (
        constants["active_record_schema"] != 2
        or constants["active_value_max"] != 35211
        or constants["open_base_fixed_bytes"] != 234
        or constants["application_binding_bytes"] != 228
        or constants["open_fixed_bytes"] != 462
        or constants["open_text_offset"] != 462
        or constants["open_body_min"] != 465
        or constants["open_body_max"] != 651
        or constants["mfdt_admission_profile_revision"] != 2
    ):
        fail("constants application binding revision 2")
    if (
        constants["workspace_bytes"] != 65536
        or constants["workspace_growth_bytes"] != 0
        or constants["open_growth_bytes_redistributed_within_each_slot"] != 228
    ):
        fail("constants workspace redistribution")
    if (
        constants["no_deadline_u64_hex"] != "ffffffffffffffff"
        or constants["finite_downlink_deadline_min_u64_hex"]
        != "0000000000000001"
        or constants["finite_downlink_deadline_max_u64_hex"]
        != "fffffffffffffffe"
        or constants["uplink_eventfact_deadline_shape"]
        != "epoch_zero__absolute_no_deadline__grace_zero"
        or constants["finite_downlink_deadline_shape"]
        != "epoch_nonzero__absolute_1_to_uint64_max_minus_1"
        or constants["original_application_open_deadline_mapping"]
        != "bit_exact_no_normalization"
    ):
        fail("constants Foundation deadline sentinel erratum")
    if (
        constants["nts3_current_schema_major"] != 1
        or constants["nts3_current_schema_minor"] != 1
        or constants["nts3_future_schema_minor"] != 2
        or constants["nts3_future_fields"]
        != ["mfdt_transfer_id[16]", "mfdt_target_ordinal_u32"]
        or constants["nts3_future_target_suffix_placement"]
        != "canonical_target_encoding_tail"
        or constants["nts3_future_target_suffix_presence"]
        != "bearer_route_eq_MFDT_V1_3"
        or constants["nts3_future_target_suffix_bytes"] != 20
        or constants["nts3_future_target_count_max"] != 4
        or constants["nts3_future_mfdt_target_rule"]
        != (
            "transfer_id_nonzero__sender_ordinal_eq_bound_target_index__"
            "receiver_ordinal_eq_open_origin_ordinal_lt4_u32_be"
        )
        or constants["nts3_future_non_mfdt_suffix_bytes"] != 0
        or constants["nts3_future_non_mfdt_memory_rule"]
        != "transfer_id_zero16_and_ordinal_zero"
        or constants["nts3_schema11_record_max_bytes"] != 4031
        or constants["nts3_schema11_inline_payload_max_bytes"] != 926
        or constants["nts3_future_mfdt_record_max_bytes"] != 3185
        or constants["nts3_record_ceiling_bytes"] != 4096
        or (
            constants["nts3_schema11_record_max_bytes"]
            - constants["nts3_schema11_inline_payload_max_bytes"]
            + constants["nts3_future_target_count_max"]
            * constants["nts3_future_target_suffix_bytes"]
        )
        != constants["nts3_future_mfdt_record_max_bytes"]
        or constants["nts3_future_mfdt_record_max_bytes"]
        > constants["nts3_record_ceiling_bytes"]
        or constants["public_callback_context_id"] != "foundation_transaction_id"
        or constants["publication_token_scope"]
        != "private_mfdt_handoff_dedupe_only"
    ):
        fail("constants application handoff/NTS3 authority")
    if constants["nrc1_illegal_two_gen_no_reclaim"] != 73:
        fail("constants illegal two-gen occupancy must be 73")
    if constants["nrc1_session_gen_max_per_transfer"] != 2:
        fail("constants session gen max")
    # Normative retry-budget SM pins (closes intermediate gate reds on nrc1_* keys).
    if constants["retry_budget_remaining_max"] != 8:
        fail("constants retry max")
    if constants["retry_budget_remaining_min"] != 0:
        fail("constants retry min")
    if constants["retry_budget_initial"] != 8:
        fail("constants retry initial")
    if constants["retry_budget_scope"] != "per_transfer_per_owner_side":
        fail("constants retry scope")
    if constants["retry_budget_owner"] != "requestor_of_outbound_mfdt_control":
        fail("constants retry owner")
    if constants["retry_budget_decrement_event"] != "timeout_retry_with_new_request_id":
        fail("constants retry decrement")
    if constants["retry_budget_header_offset"] != 105:
        fail("constants retry offset")
    if constants["nrc1_slot_count"] != 72:
        fail("constants nrc1 slots")
    if constants["nrc1_slot_bytes"] != 208:
        fail("constants nrc1 slot")
    if constants["nrc1_value_bytes"] != 15020:
        fail("constants nrc1 value")
    if constants["nrc1_logical_bytes"] != 15056:
        fail("constants nrc1 logical")
    if constants["nrc1_slot_session_generation_offset"] != 8:
        fail("constants nrc1 slot generation offset")
    if constants["nrc1_header_session_generation_offset"] != 24:
        fail("constants nrc1 header generation offset")
    if constants["nrc1_slot_lookup_identity"] != "session_generation_plus_request_id":
        fail("constants nrc1 lookup identity")
    if (
        constants["nrc1_occupied_response_length_min"] != 1
        or constants["nrc1_occupied_response_length_max"] != 160
    ):
        fail("constants nrc1 response length")
    if constants["nrc1_reachable_max_ids"] != 65:
        fail("constants nrc1 reachable")
    if constants["nrc1_n_complete"] != 65 or constants["nrc1_n_abort"] != 64:
        fail("constants nrc1 paths")
    if constants["request_body_digest_preimage"] != "type_u8||len_u16be||full_body":
        fail("constants open digest preimage")
    if (
        constants["manifest_digest_preimage"]
        != "NM3-MANIFEST-V1(15 ascii no NUL)||open[0,202)||open[234,462)||open[462,open_body_length)||entries"
        or constants["digest_domains"].get("application_evidence")
        != "NINLIL-MFDT-APPLICATION-EVIDENCE-V1"
    ):
        fail("constants manifest/application-evidence digest authority")
    if constants["message_types"] != {
        "TRANSFER_OPEN": 0x36,
        "TRANSFER_OPEN_ACCEPT": 0x37,
        "MANIFEST_PAGE": 0x38,
        "MANIFEST_PAGE_ACCEPT": 0x39,
        "TRANSFER_REJECT": 0x3A,
        "TRANSFER_BUSY": 0x3B,
        "CHUNK_OFFER": 0x3C,
        "CHUNK_ACCEPT": 0x3D,
        "RESUME_QUERY": 0x3E,
        "RESUME_STATE": 0x3F,
        "TRANSFER_FINALIZE": 0x40,
        "TRANSFER_ACCEPT": 0x41,
        "TRANSFER_ABORT": 0x42,
        "TRANSFER_ABORT_ACK": 0x43,
    }:
        fail("constants MFDT transfer type allocation")
    if constants["wire_abort_reasons"] != {
        "OPERATOR": 1,
        "SUPERSEDED": 2,
        "DEADLINE": 3,
        "POLICY": 4,
    }:
        fail("constants wire abort reasons")
    if constants["nm30_expired_reason_terminal_only"] != 5:
        fail("constants terminal-only expiry reason")
    if (
        constants["nm30_schema"] != 2
        or constants["nm30_value_bytes"] != 180
        or constants["nm30_peer_endpoint_id_offset"] != 156
        or constants["nm30_peer_endpoint_id_bytes"] != 16
        or constants["nm30_owner_role_offset"] != 172
        or constants["nm30_reserved_offset"] != 173
        or constants["nm30_reserved_bytes"] != 3
        or constants["nm30_crc_offset"] != 176
        or constants["nm30_crc_preimage_bytes"] != 176
        or constants["nm30_legacy_schema1_value_bytes"] != 164
        or constants["terminal_session_generation_authority"]
        != "NRC1_header_offset_24"
    ):
        fail("constants NM30 schema-2/legacy boundary")
    if constants["reservation_add_overflow_threshold_u64_hex"] != "fffffffffffb6c1f":
        fail("constants reservation overflow threshold")
    if (
        constants["host_slot_count"] != 4
        or constants["host_coordinator_bytes"] != 512
        or constants["host_control_arena_bytes"] != 17920
        or constants["host_terminal_catalog_entries"] != 16
        or constants["host_terminal_catalog_entry_bytes"] != 64
        or constants["host_terminal_catalog_bytes"] != 1024
        or constants["host_control_outbox_metadata_bytes"] != 64
        or constants["host_control_outbox_bytes"] != 1024
        or constants["host_control_nrc1_scratch_bytes"] != 15024
        or constants["host_control_nm30_scratch_bytes"] != 184
        or constants["host_control_recovery_reserved_bytes"] != 88
        or constants["host_control_route_sentinel"] != 0xFF
        or constants["host_owner_workspace_bytes"] != 280064
    ):
        fail("constants Host owner bounds")

    catalog = document["version_catalog"]
    assert_exact_keys(catalog, VERSION_CATALOG_KEYS, "$.version_catalog")
    for key in (
        "default_policy",
        "mf_o01_status",
        "mf_o09_status",
        "mfdt_message_types",
        "mfdt_accept_digest_preimage",
        "mfdt_negotiation_domain",
        "mfdt_offer_digest_preimage",
        "obsolete_selected_3_inheritance_table",
        "private_admission_without_policy",
        "revision1_revision2_interop",
        "selected_control_version_3",
        "target_promotion_off",
        "target_promotion_on",
        "u5_u6_wire_body",
    ):
        assert_type(catalog[key], "str", f"$.version_catalog.{key}")
    for key in (
        "docs_25_26_current_selected_exact_2",
        "docs_25_26_refreeze_forbidden_in_this_candidate",
        "mf_o01_false_close_forbidden",
        "mfdt_does_not_claim_selected_3_includes_u5_u6",
        "mfdt_negotiation_independent_of_selected_control_version",
        "mixed_version_fail_closed",
        "silent_ge2_forbidden",
        "accepted_wire_changed",
        "mfdt_candidate_contiguous_minimal_after_accepted",
    ):
        assert_type(catalog[key], "bool", f"$.version_catalog.{key}")
    for key in (
        "accepted_u5_u6_selected_exact",
        "hello_body_bytes",
        "mfdt_accept_body_bytes",
        "mfdt_accept_type",
        "mfdt_negotiation_version",
        "mfdt_offer_body_bytes",
        "mfdt_offer_type",
        "mfdt_candidate_type_count",
        "mfdt_transfer_type_count",
    ):
        assert_type(catalog[key], "int", f"$.version_catalog.{key}")
    assert_str_list(
        catalog["accepted_freeze_docs_untouched"],
        "$.version_catalog.accepted_freeze_docs_untouched",
    )
    assert_str_list(
        catalog["mfdt_admission_requires"],
        "$.version_catalog.mfdt_admission_requires",
    )
    for key in (
        "accepted_control_selected_values",
        "accepted_ncl1_type_values",
        "mfdt_base_control_versions",
        "mfdt_candidate_type_values",
        "void_old_proposed_type_values",
    ):
        assert_type(catalog[key], "list", f"$.version_catalog.{key}")
        for index, item in enumerate(catalog[key]):
            assert_type(item, "int", f"$.version_catalog.{key}[{index}]")
    if catalog["mf_o01_status"] != "SPEC_ACCEPTED_GREEN_BASELINE_HISTORY":
        fail("MF-O01 accepted baseline history")
    if catalog["mf_o09_status"] != "SPEC_ACCEPTED_CLOSED":
        fail("MF-O09 amendment accepted status")
    if catalog["mfdt_base_control_versions"] != [1, 2]:
        fail("MFDT base control versions must remain exact [1,2]")
    if (
        catalog["mfdt_negotiation_version"] != 2
        or catalog["mfdt_offer_type"] != 0x34
        or catalog["mfdt_accept_type"] != 0x35
        or catalog["mfdt_offer_body_bytes"] != 112
        or catalog["mfdt_accept_body_bytes"] != 160
    ):
        fail("MFN1 catalog/layout pin")
    if (
        catalog["mfdt_negotiation_domain"] != "private_mfdt_admission_v2"
        or catalog["mfdt_offer_digest_preimage"]
        != "NINLIL-MFDT-OFFER-V2||request_id_u32be||offer_body[0,80)"
        or catalog["mfdt_accept_digest_preimage"]
        != "NINLIL-MFDT-ACCEPT-V2||request_id_u32be||accept_body[0,128)"
        or catalog["revision1_revision2_interop"] != "REJECT_MUTATION_ZERO"
    ):
        fail("MFN1 revision-2 fail-closed authority")
    if (
        catalog["accepted_control_selected_values"] != [1, 2]
        or catalog["selected_control_version_3"] != "REJECT"
        or catalog["mfdt_candidate_type_values"] != list(range(0x34, 0x44))
        or catalog["mfdt_candidate_type_count"] != 16
        or catalog["mfdt_transfer_type_count"] != 14
        or catalog["target_promotion_on"] != "UNALLOCATED_UNSUPPORTED"
        or catalog["accepted_wire_changed"] is not False
    ):
        fail("MFDT candidate allocation/promotion contract")
    if catalog["mfdt_negotiation_independent_of_selected_control_version"] is not True:
        fail("MFDT negotiation must be independent of selected_control_version")
    if catalog["accepted_u5_u6_selected_exact"] != 2:
        fail("Accepted U5/U6 selected must remain exact 2")

    carriers = document["carrier_mapping"]
    assert_exact_keys(
        carriers,
        frozenset(
            {
                "compact_rf_nrw1",
                "generic_fabric_control_plane",
                "ncg1_ncl1",
                "nfl1_application_packet",
                "wifi_nwb1",
            }
        ),
        "$.carrier_mapping",
    )
    for name, obj in carriers.items():
        assert_type(obj, "dict", f"$.carrier_mapping.{name}")
        if "status" not in obj:
            fail(f"$.carrier_mapping.{name}: missing status")
        assert_type(obj["status"], "str", f"$.carrier_mapping.{name}.status")
        for key, item in obj.items():
            if isinstance(item, bool):
                continue
            if isinstance(item, str):
                continue
            if isinstance(item, int):
                continue
            fail(f"$.carrier_mapping.{name}.{key}: unsupported primitive type")

    pub = document["publication_owner"]
    assert_exact_keys(
        pub,
        frozenset(
            {
                "forbidden_prepare_callers",
                "sole_application_effect_owner",
                "sole_prepare_caller",
                "sole_publication_token_owner",
            }
        ),
        "$.publication_owner",
    )
    assert_str_list(pub["forbidden_prepare_callers"], "$.publication_owner.forbidden_prepare_callers")
    for key in (
        "sole_application_effect_owner",
        "sole_prepare_caller",
        "sole_publication_token_owner",
    ):
        assert_type(pub[key], "str", f"$.publication_owner.{key}")

    roles = document["role_boundaries"]
    assert_exact_keys(
        roles,
        frozenset({"controller", "receiver", "relay_neutral_bearer", "sender"}),
        "$.role_boundaries",
    )
    assert_exact_keys(
        roles["controller"],
        frozenset({"assignment_only", "multi_frame_messages"}),
        "$.role_boundaries.controller",
    )
    assert_type(roles["controller"]["assignment_only"], "bool", "$.role_boundaries.controller.assignment_only")
    assert_type(
        roles["controller"]["multi_frame_messages"],
        "bool",
        "$.role_boundaries.controller.multi_frame_messages",
    )
    assert_exact_keys(
        roles["receiver"],
        frozenset({"may_partial_apply", "may_publish", "responsibility_ends_on"}),
        "$.role_boundaries.receiver",
    )
    assert_type(roles["receiver"]["may_partial_apply"], "bool", "$.role_boundaries.receiver.may_partial_apply")
    assert_type(roles["receiver"]["may_publish"], "bool", "$.role_boundaries.receiver.may_publish")
    assert_str_list(
        roles["receiver"]["responsibility_ends_on"],
        "$.role_boundaries.receiver.responsibility_ends_on",
    )
    assert_exact_keys(
        roles["relay_neutral_bearer"],
        frozenset({"completion_authority", "custody_authority"}),
        "$.role_boundaries.relay_neutral_bearer",
    )
    assert_type(
        roles["relay_neutral_bearer"]["completion_authority"],
        "bool",
        "$.role_boundaries.relay_neutral_bearer.completion_authority",
    )
    assert_type(
        roles["relay_neutral_bearer"]["custody_authority"],
        "bool",
        "$.role_boundaries.relay_neutral_bearer.custody_authority",
    )
    assert_exact_keys(
        roles["sender"],
        frozenset(
            {
                "may_claim_complete_before_accept_full",
                "may_publish",
                "may_release_on_chunk_accept_only",
            }
        ),
        "$.role_boundaries.sender",
    )
    for key in (
        "may_claim_complete_before_accept_full",
        "may_publish",
        "may_release_on_chunk_accept_only",
    ):
        assert_type(roles["sender"][key], "bool", f"$.role_boundaries.sender.{key}")

    api = document["private_api"]
    assert_exact_keys(
        api,
        frozenset(
            {
                "active_record_schema",
                "active_schema1_replay_eligible",
                "borrow_until_full",
                "copy_owned_after_full",
                "default_off",
                "heap_growth",
                "host_coordinator_bytes",
                "host_control_arena_bytes",
                "host_control_outbox_backpressure",
                "host_control_outbox_bytes",
                "host_control_outbox_count",
                "host_control_route_sentinel",
                "host_control_traffic_advances_scheduler",
                "host_fair_selection_bound",
                "host_fifth_active",
                "host_full_transaction_parallelism",
                "host_owner_workspace_bytes",
                "host_peer_unpaid_chunk_offer_max",
                "host_restart_slot_allocation",
                "host_scheduler",
                "host_schema1_terminal_replay_eligible",
                "host_slot_allocation",
                "host_slot_count",
                "host_terminal_catalog_entries",
                "host_terminal_catalog_entry_bytes",
                "host_terminal_catalog_rebind",
                "host_terminal_route_without_active_slot",
                "host_transfer_route_key",
                "operations",
                "open_growth_bytes_redistributed_within_each_slot",
                "prefix",
                "public_abi",
                "workspace_bytes",
                "workspace_growth_bytes",
                "workspace_scope",
            }
        ),
        "$.private_api",
    )
    for key in (
        "active_schema1_replay_eligible",
        "borrow_until_full",
        "copy_owned_after_full",
        "default_off",
        "heap_growth",
        "host_control_traffic_advances_scheduler",
        "host_schema1_terminal_replay_eligible",
        "host_terminal_route_without_active_slot",
        "public_abi",
    ):
        assert_type(api[key], "bool", f"$.private_api.{key}")
    for key in (
        "prefix",
        "workspace_scope",
        "host_fifth_active",
        "host_restart_slot_allocation",
        "host_scheduler",
        "host_slot_allocation",
        "host_terminal_catalog_rebind",
        "host_transfer_route_key",
        "host_control_outbox_backpressure",
    ):
        assert_type(api[key], "str", f"$.private_api.{key}")
    for key in (
        "active_record_schema",
        "workspace_bytes",
        "workspace_growth_bytes",
        "open_growth_bytes_redistributed_within_each_slot",
        "host_coordinator_bytes",
        "host_control_arena_bytes",
        "host_control_outbox_bytes",
        "host_control_outbox_count",
        "host_control_route_sentinel",
        "host_fair_selection_bound",
        "host_full_transaction_parallelism",
        "host_owner_workspace_bytes",
        "host_peer_unpaid_chunk_offer_max",
        "host_slot_count",
        "host_terminal_catalog_entries",
        "host_terminal_catalog_entry_bytes",
    ):
        assert_type(api[key], "int", f"$.private_api.{key}")
    assert_str_list(api["operations"], "$.private_api.operations")

    budget = document["budget"]
    assert_exact_keys(budget, BUDGET_KEYS, "$.budget")
    for key in BUDGET_KEYS:
        if key in ("groups", "restoration_object"):
            assert_type(budget[key], "dict", f"$.budget.{key}")
        elif key in (
            "obsolete_80_feasible_for_reference_receiver",
            "nrc1_retained_until_gc",
        ):
            assert_type(budget[key], "bool", f"$.budget.{key}")
        elif key == "restoration_sha256_hex":
            assert_type(budget[key], "str", f"$.budget.{key}")
        else:
            assert_type(budget[key], "int", f"$.budget.{key}")
    groups = budget["groups"]
    assert_exact_keys(
        groups,
        frozenset({"empty_receiver", "empty_sender", "receiver", "sender"}),
        "$.budget.groups",
    )
    for name, obj in groups.items():
        assert_int_map(obj, f"$.budget.groups.{name}")
    rest = budget["restoration_object"]
    assert_exact_keys(
        rest,
        frozenset(
            {
                "obsolete_fulls_day",
                "obsolete_infeasible",
                "receiver_fulls_max",
                "receiver_groups",
                "reference_transfers_day",
                "required_receiver_fulls_reference",
                "required_sender_fulls_reference",
                "sender_fulls_max",
                "sender_groups",
            }
        ),
        "$.budget.restoration_object",
    )
    assert_type(rest["obsolete_infeasible"], "bool", "$.budget.restoration_object.obsolete_infeasible")
    for key in (
        "obsolete_fulls_day",
        "receiver_fulls_max",
        "reference_transfers_day",
        "required_receiver_fulls_reference",
        "required_sender_fulls_reference",
        "sender_fulls_max",
    ):
        assert_type(rest[key], "int", f"$.budget.restoration_object.{key}")
    assert_int_map(rest["receiver_groups"], "$.budget.restoration_object.receiver_groups")
    assert_int_map(rest["sender_groups"], "$.budget.restoration_object.sender_groups")

    index = document["authority_index"]
    assert_type(index, "dict", "$.authority_index")
    for vid, row in index.items():
        if not isinstance(vid, str):
            fail("$.authority_index: non-string id")
        rpath = f"$.authority_index.{vid}"
        assert_exact_keys(row, AUTHORITY_INDEX_ROW_KEYS, rpath)
        assert_type(row["family"], "str", f"{rpath}.family")
        assert_type(row["authority_fingerprint_hex"], "str", f"{rpath}.authority_fingerprint_hex")
        expected_keys = None
        if vid in AUTHORITY:
            expected_keys = frozenset(AUTHORITY[vid]["expected"].keys())
        assert_expected_object(row["expected"], f"{rpath}.expected", expected_keys)

    vectors = document["vectors"]
    assert_type(vectors, "list", "$.vectors")
    for index_i, entry in enumerate(vectors):
        path = f"$.vectors[{index_i}]"
        assert_type(entry, "dict", path)
        if not VECTOR_COMMON_REQUIRED <= set(entry.keys()):
            fail(f"{path}: missing common keys")
        family = entry.get("family")
        assert_type(entry["id"], "str", f"{path}.id")
        assert_type(family, "str", f"{path}.family")
        assert_type(entry["authority_fingerprint_hex"], "str", f"{path}.authority_fingerprint_hex")
        optional = VECTOR_OPTIONAL_BY_FAMILY.get(family)
        if optional is None:
            fail(f"{path}: unknown family {family}")
        allowed = VECTOR_COMMON_REQUIRED | optional
        unknown = set(entry.keys()) - allowed
        if unknown:
            fail(f"{path}: unknown keys {sorted(unknown)}")
        expected_keys = None
        if entry["id"] in AUTHORITY:
            expected_keys = frozenset(AUTHORITY[entry["id"]]["expected"].keys())
        assert_expected_object(entry["expected"], f"{path}.expected", expected_keys)
        if "fixture" in entry:
            validate_fixture_closed(entry["fixture"], f"{path}.fixture")
        if family == "commit_unknown":
            for req in ("group", "old_rows", "new_rows", "observed_rows"):
                if req not in entry:
                    fail(f"{path}: missing {req}")
            assert_type(entry["group"], "str", f"{path}.group")
            validate_cu_rows(entry["old_rows"], f"{path}.old_rows")
            validate_cu_rows(entry["new_rows"], f"{path}.new_rows")
            validate_cu_rows(entry["observed_rows"], f"{path}.observed_rows")
        if family == "transcript":
            if "transcript" in entry:
                assert_str_list(entry["transcript"], f"{path}.transcript")
            if "steps" in entry:
                assert_str_list(entry["steps"], f"{path}.steps")
            if "fixture_ids" in entry:
                assert_type(entry["fixture_ids"], "dict", f"{path}.fixture_ids")
                for key, item in entry["fixture_ids"].items():
                    assert_type(item, "str", f"{path}.fixture_ids.{key}")
            if "resume_state_hex" in entry:
                assert_type(entry["resume_state_hex"], "str", f"{path}.resume_state_hex")
            if "resume_state_length" in entry:
                assert_type(entry["resume_state_length"], "int", f"{path}.resume_state_length")
            for key in (
                "committed_chunk_bitmap",
                "now_ms",
                "retention_ms",
            ):
                if key in entry:
                    assert_type(entry[key], "int", f"{path}.{key}")
            for key in (
                "last_full_group",
                "publication_token_hex",
            ):
                if key in entry:
                    assert_type(entry[key], "str", f"{path}.{key}")
            for key in ("tombstone_present_before", "tombstone_present_after"):
                if key in entry:
                    assert_type(entry[key], "bool", f"{path}.{key}")


def crc32c(value: bytes) -> int:
    crc = 0xFFFFFFFF
    for octet in value:
        crc ^= octet
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def hx(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or len(value) % 2:
        fail(f"{field}: non-even hex")
    if value.lower() != value or any(c not in "0123456789abcdef" for c in value):
        fail(f"{field}: non-canonical hex")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise GateError(f"{field}: invalid hex") from error


def u16(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off : off + 2], "big")


def u32(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off : off + 4], "big")


def u64(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off : off + 8], "big")


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def family_of(vector_id: str) -> str:
    if vector_id.startswith("MF-POS-"):
        return "positive"
    if vector_id.startswith("MF-NEG-"):
        return "negative"
    if vector_id.startswith("MF-CU-"):
        return "commit_unknown"
    if vector_id.startswith("MF-TX-"):
        return "transcript"
    if vector_id.startswith("MF-BUDGET-"):
        return "budget"
    if vector_id.startswith("MF-FSM-") or vector_id.startswith("MF-TRACE-"):
        return "catalog"
    if vector_id in {
        "MF-CONSTANTS-PINNED",
        "MF-VERSION-CATALOG-INHERITANCE",
        "MF-CARRIER-MAPPING-MATRIX",
        "MF-PUBLICATION-OWNER-MATRIX",
        "MF-ROLE-BOUNDARIES",
        "MF-PRIVATE-API-SURFACE",
        "MF-INV-REQUIRED-IDS-INTEGRITY",
        "MF-GATE-SELF-TEST-PIN",
    }:
        return "catalog"
    return "other"


def authority_material(entry: dict[str, Any]) -> dict[str, Any]:
    material: dict[str, Any] = {
        "id": entry["id"],
        "family": family_of(entry["id"]),
        "expected": entry["expected"],
    }
    if "fixture" in entry:
        material["fixture"] = entry["fixture"]
    if "old_rows" in entry:
        material["commit_unknown"] = {
            "group": entry.get("group"),
            "old_rows": entry.get("old_rows"),
            "new_rows": entry.get("new_rows"),
            "observed_rows": entry.get("observed_rows"),
        }
    skip = {
        "id",
        "expected",
        "fixture",
        "old_rows",
        "new_rows",
        "observed_rows",
        "authority_fingerprint_hex",
        "family",
    }
    for key in sorted(entry.keys()):
        if key in skip:
            continue
        material[key] = entry[key]
    return material


def authority_fingerprint(entry: dict[str, Any]) -> str:
    return sha(stable_json(authority_material(entry)).encode("utf-8")).hex()


def derive(total_length: int) -> tuple[int, int]:
    if not 0 <= total_length <= MAX_CONTENT:
        fail("total_length range")
    if total_length == 0:
        return 0, 0
    chunks = (total_length + CHUNK_SIZE - 1) // CHUNK_SIZE
    if chunks > MAX_CHUNKS:
        fail("chunk overflow")
    pages = (chunks + ENTRIES_PER_PAGE - 1) // ENTRIES_PER_PAGE
    return chunks, pages


def chunk_range(total: int, index: int) -> tuple[int, int]:
    offset = CHUNK_SIZE * index
    length = min(CHUNK_SIZE, total - offset)
    if length <= 0:
        fail("chunk range")
    return offset, length


def by_id(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for entry in document["vectors"]:
        vid = entry["id"]
        if vid in out:
            fail(f"duplicate id {vid}")
        out[vid] = entry
    return out


def mark_complete(vid: str, entry: dict[str, Any], executed: set[str]) -> None:
    """Bind ID to semantics/fingerprint; only then record execution."""

    if vid not in AUTHORITY:
        fail(f"no authority for {vid}")
    auth = AUTHORITY[vid]
    if family_of(vid) != auth["family"]:
        fail(f"{vid}: family")
    if entry.get("family", family_of(vid)) != auth["family"]:
        fail(f"{vid}: entry family")
    if entry.get("expected") != auth["expected"]:
        fail(f"{vid}: expected authority mismatch")
    fp = authority_fingerprint(entry)
    if fp != auth["authority_fingerprint_hex"]:
        fail(f"{vid}: authority fingerprint mismatch")
    if entry.get("authority_fingerprint_hex") != auth["authority_fingerprint_hex"]:
        fail(f"{vid}: vector fingerprint field")
    if vid in executed:
        fail(f"{vid}: double complete")
    executed.add(vid)


def require_valid_record_crc(value: bytes, field: str) -> None:
    if len(value) < HEADER_BYTES + 4:
        fail(f"{field}: short record")
    if value[0:4] not in (b"NM3R", b"NM3S"):
        fail(f"{field}: magic")
    if u32(value, 304) != crc32c(value[0:304]):
        fail(f"{field}: header crc invalid")
    if int.from_bytes(value[-4:], "big") != crc32c(value[:-4]):
        fail(f"{field}: record crc invalid")


def require_valid_active_semantics(value: bytes, field: str) -> None:
    """Independent canonical NM3S/NM3R reader; CRC integrity alone is insufficient."""

    require_valid_record_crc(value, field)
    if u16(value, 4) != 2 or u16(value, 6) != HEADER_BYTES:
        fail(f"{field}: active schema/header")
    if u32(value, 8) != len(value):
        fail(f"{field}: active total length")
    owner = value[12]
    if (value[0:4], owner) not in ((b"NM3S", 1), (b"NM3R", 2)):
        fail(f"{field}: active magic/owner")
    sender_states = {1, 2, 3, 4, 5, 6, 8, 10}
    receiver_states = {32, 33, 34, 35, 36, 37, 38, 40, 41}
    if value[13] not in (sender_states if owner == 1 else receiver_states):
        fail(f"{field}: active state closed set")
    if value[14:16] != b"\x00\x00" or value[110:112] != b"\x00\x00":
        fail(f"{field}: active reserved header")
    if value[230:232] != b"\x00\x00" or value[296:300] != bytes(4):
        fail(f"{field}: active reserved tail")
    if value[16:32] == bytes(16) or u32(value, 32) == 0 or value[36:68] == bytes(32):
        fail(f"{field}: active bind")
    if u64(value, 68) == 0 or value[105] > 8 or u32(value, 300) == 0:
        fail(f"{field}: active generation/budget")
    if value[106] != 1:
        fail(f"{field}: active release policy")
    if value[107] > 2 or value[108] > 1 or value[109] > 1:
        fail(f"{field}: active publication flags")

    open_len = u16(value, 84)
    entry_bytes = u16(value, 86)
    content_len = u32(value, 88)
    if not 465 <= open_len <= 651:
        fail(f"{field}: active OPEN length")
    if HEADER_BYTES + open_len + entry_bytes + content_len + 4 != len(value):
        fail(f"{field}: active body geometry")
    open_body = value[HEADER_BYTES : HEADER_BYTES + open_len]
    if (
        open_body[0:16] != value[16:32]
        or u32(open_body, 16) != u32(value, 32)
        or open_body[202:234] != value[36:68]
    ):
        fail(f"{field}: active embedded OPEN bind")
    total = u32(open_body, 20)
    if total > MAX_CONTENT or content_len != total or u16(open_body, 24) != CHUNK_SIZE:
        fail(f"{field}: active content geometry")
    chunks, pages = derive(total)
    if (
        u16(open_body, 26) != chunks
        or u16(open_body, 28) != pages
        or u16(open_body, 30) != ENTRIES_PER_PAGE
        or u16(value, 92) != chunks
        or u16(value, 94) != pages
        or entry_bytes != chunks * 40
    ):
        fail(f"{field}: active manifest geometry")
    nlen, slen, clen = u16(open_body, 170), u16(open_body, 172), u16(open_body, 174)
    if not all(1 <= n <= 63 for n in (nlen, slen, clen)):
        fail(f"{field}: active text lengths")
    if open_len != 462 + nlen + slen + clen or u16(open_body, 176) != 0:
        fail(f"{field}: active OPEN text/reserved")
    if (
        open_body[234:250] == bytes(16)
        or u32(open_body, 250) == 0
        or open_body[254:318] == bytes(64)
        or open_body[338:342] != bytes(4)
        or open_body[342:406] == bytes(64)
        or open_body[426:430] != bytes(4)
        or u16(open_body, 430) == 0
        or u32(open_body, 434) == 0
        or u32(open_body, 454) == 0
        or open_body[458:462] != bytes(4)
    ):
        fail(f"{field}: active application binding")
    derived_transfer_id = sha(
        open_body[64:80]
        + open_body[112:128]
        + open_body[250:254]
        + b"ninlil-mfdt-v1id"
    )[:16]
    if derived_transfer_id == bytes(16):
        derived_transfer_id = derived_transfer_id[:-1] + b"\x01"
    if open_body[0:16] != derived_transfer_id:
        fail(f"{field}: transfer id derivation")
    entry_start = HEADER_BYTES + open_len
    entry_blob = value[entry_start : entry_start + entry_bytes]
    if open_body[202:234] != sha(
        b"NM3-MANIFEST-V1"
        + open_body[0:202]
        + open_body[234:462]
        + open_body[462:]
        + entry_blob
    ):
        fail(f"{field}: manifest/application binding digest")
    family = u32(open_body, 434)
    origin_event_zero = open_body[80:96] == bytes(16)
    generation = u64(open_body, 438)
    deadline_epoch_zero = open_body[178:194] == bytes(16)
    deadline = u64(open_body, 194)
    grace = u64(open_body, 446)
    downlink = family in (2, 5, 6)
    uplink = family in (1, 3, 4)
    if (
        not (downlink or uplink)
        or (family == 1 and (origin_event_zero or generation != 0))
        or (family != 1 and (not origin_event_zero or generation == 0))
        or (
            downlink
            and (deadline_epoch_zero or deadline == 0 or deadline == (1 << 64) - 1)
        )
        or (
            uplink
            and (
                not deadline_epoch_zero
                or deadline != (1 << 64) - 1
                or grace != 0
            )
        )
    ):
        fail(f"{field}: active family/deadline shape")
    if chunks < 64 and (u64(value, 96) >> chunks) != 0:
        fail(f"{field}: active chunk bitmap range")
    if pages < 8 and (value[104] >> pages) != 0:
        fail(f"{field}: active page bitmap range")

    reservation_zero = value[112:128] == bytes(16)
    reservation_epoch_zero = value[128:144] == bytes(16)
    reservation_deadline_zero = u64(value, 144) == 0
    if not (
        (reservation_zero and reservation_epoch_zero and reservation_deadline_zero)
        or (not reservation_zero and not reservation_epoch_zero and not reservation_deadline_zero)
    ):
        fail(f"{field}: active reservation correlation")
    accept_gen = u64(value, 76)
    evidence_zero = value[152:168] == bytes(16)
    accept_digest_zero = value[168:200] == bytes(32)
    if (accept_gen == 0) != (evidence_zero and accept_digest_zero):
        fail(f"{field}: active acceptance evidence correlation")
    if value[200:216] == bytes(16) or u64(value, 216) == 0:
        fail(f"{field}: active trusted clock sample")
    abort_gen = u32(value, 224)
    abort_reason = u16(value, 228)
    actor_zero = value[232:248] == bytes(16)
    if abort_gen == 0:
        if abort_reason != 0 or not actor_zero:
            fail(f"{field}: active abort-zero correlation")
    elif not (1 <= abort_gen <= 8 and 1 <= abort_reason <= 4 and not actor_zero):
        fail(f"{field}: active abort correlation")
    if value[107] == 0:
        if value[248:264] != bytes(16) or value[264:296] != bytes(32):
            fail(f"{field}: active unpublished evidence")
    elif value[248:264] == bytes(16):
        fail(f"{field}: active publication token")


def require_valid_nm30_semantics(value: bytes, field: str) -> None:
    """Independent NM30 terminal-class cross-product validator."""

    if len(value) != NM30_BYTES or value[0:4] != b"NM30":
        fail(f"{field}: nm30 framing")
    if u16(value, 4) != 2 or u16(value, 6) != NM30_BYTES:
        fail(f"{field}: nm30 schema/length")
    if u32(value, 176) != crc32c(value[0:176]):
        fail(f"{field}: nm30 crc invalid")
    if (
        value[8:24] == bytes(16)
        or u32(value, 24) == 0
        or value[28:60] == bytes(32)
        or value[132:148] == bytes(16)
        or u64(value, 148) == 0
        or value[156:172] == bytes(16)
        or value[172] not in (1, 2)
        or value[173:176] != bytes(3)
    ):
        fail(f"{field}: nm30 common semantic fields")
    state, reason, generation = u16(value, 60), u16(value, 62), u32(value, 64)
    evidence_zero = value[68:84] == bytes(16)
    digest_zero = value[84:116] == bytes(32)
    actor_zero = value[116:132] == bytes(16)
    if state == 1:
        if reason != 0 or generation != 0 or actor_zero is False:
            fail(f"{field}: nm30 COMPLETE authority")
        if evidence_zero or digest_zero:
            fail(f"{field}: nm30 COMPLETE evidence")
    elif state == 2:
        if reason in (1, 2, 3, 4):
            if not (1 <= generation <= 8 and not actor_zero and evidence_zero and digest_zero):
                fail(f"{field}: nm30 authority ABORTED")
        elif reason == 5:
            if generation != 0 or not actor_zero or not evidence_zero or not digest_zero:
                fail(f"{field}: nm30 automatic EXPIRED")
        else:
            fail(f"{field}: nm30 ABORTED reason")
    elif state == 3:
        if reason not in (0x8001, 0x8002) or generation != 0 or not actor_zero:
            fail(f"{field}: nm30 CORRUPT authority")
        if evidence_zero != digest_zero:
            fail(f"{field}: nm30 CORRUPT evidence pair")
    else:
        fail(f"{field}: nm30 terminal state")


def require_valid_nm30_legacy_schema1(value: bytes, field: str) -> None:
    """Validate legacy media only; this function grants no replay authority."""

    if len(value) != NM30_LEGACY_SCHEMA1_BYTES or value[0:4] != b"NM30":
        fail(f"{field}: legacy nm30 framing")
    if u16(value, 4) != 1 or u16(value, 6) != NM30_LEGACY_SCHEMA1_BYTES:
        fail(f"{field}: legacy nm30 schema/length")
    if u32(value, 160) != crc32c(value[0:160]):
        fail(f"{field}: legacy nm30 crc")
    if value[156:160] != bytes(4):
        fail(f"{field}: legacy nm30 reserved")
    if (
        value[8:24] == bytes(16)
        or u32(value, 24) == 0
        or value[28:60] == bytes(32)
        or value[132:148] == bytes(16)
        or u64(value, 148) == 0
    ):
        fail(f"{field}: legacy nm30 common fields")


def require_valid_nm30_crc(value: bytes, field: str) -> None:
    require_valid_nm30_semantics(value, field)


def require_valid_nrc1_semantics(
    value: bytes, field: str, *, expected_transfer_id: bytes | None = None
) -> None:
    """Independent fixed-row NRC1 reader including per-slot generation semantics."""

    if len(value) != 15020 or value[0:4] != b"NRC1":
        fail(f"{field}: NRC1 framing")
    if u16(value, 4) != 1 or u16(value, 6) != 15020:
        fail(f"{field}: NRC1 schema/length")
    if expected_transfer_id is not None and value[8:24] != expected_transfer_id:
        fail(f"{field}: NRC1 transfer bind")
    if value[8:24] == bytes(16) or u32(value, 24) == 0:
        fail(f"{field}: NRC1 bind/generation")
    if u16(value, 28) != 72 or u16(value, 30) > 72:
        fail(f"{field}: NRC1 counts")
    if u32(value, 36) != crc32c(value[:36]) or u32(value, 15016) != crc32c(value[:15016]):
        fail(f"{field}: NRC1 CRC")
    response_lengths = {
        0x37: 100,
        0x39: 108,
        0x3A: 60,
        0x3B: 60,
        0x3D: 88,
        0x3F: 108,
        0x41: 160,
        0x43: 92,
    }
    occupied = 0
    current_generation = u32(value, 24)
    anchor_generation = 0
    generations: set[int] = {current_generation}
    identities: set[tuple[int, int]] = set()
    for index in range(72):
        off = 40 + index * 208
        slot = value[off : off + 208]
        request_id = u64(slot, 0)
        if request_id == 0:
            if slot != bytes(208):
                fail(f"{field}: NRC1 empty slot {index} not all-zero")
            continue
        occupied += 1
        generation = u32(slot, 8)
        response_type = u16(slot, 44)
        body_len = u16(slot, 46)
        if (
            generation == 0
            or (
                generation != current_generation
                and (
                    current_generation == 1
                    or generation != current_generation - 1
                )
            )
            or slot[12:44] == bytes(32)
        ):
            fail(f"{field}: NRC1 occupied slot {index} generation/digest")
        generations.add(generation)
        if generation != current_generation and response_type == 0x3F:
            fail(f"{field}: prior-generation RESUME slot not reclaimed")
        if response_type == 0x37 and (
            anchor_generation == 0 or generation < anchor_generation
        ):
            anchor_generation = generation
        identity = (generation, request_id)
        if identity in identities:
            fail(f"{field}: NRC1 duplicate generation/request_id")
        identities.add(identity)
        if response_type not in response_lengths or body_len != response_lengths[response_type]:
            fail(f"{field}: NRC1 slot {index} response type/length")
        if slot[48 + body_len :] != bytes(160 - body_len):
            fail(f"{field}: NRC1 slot {index} trailing bytes")
    if occupied != u16(value, 30) or u32(value, 32) < occupied:
        fail(f"{field}: NRC1 occupied/sequence")
    if len(generations) > 2:
        fail(f"{field}: NRC1 has more than two transfer generations")
    if len(generations) == 2:
        if anchor_generation != current_generation - 1:
            fail(f"{field}: NRC1 initial OPEN anchor generation")


def validate_inventory_structure(document: dict[str, Any]) -> None:
    if document.get("required_vector_ids") != list(REQUIRED_VECTOR_IDS):
        fail("required_vector_ids")
    if document.get("required_gate_cases") != list(REQUIRED_VECTOR_IDS):
        fail("required_gate_cases")
    ids = [v["id"] for v in document["vectors"]]
    if ids != list(REQUIRED_VECTOR_IDS):
        fail("vector order/id inventory")
    if len(ids) != len(set(ids)):
        fail("duplicate vector ids")
    if set(AUTHORITY) != set(REQUIRED_VECTOR_IDS):
        fail("AUTHORITY map size/ids")
    index = document.get("authority_index")
    if not isinstance(index, dict) or set(index) != set(REQUIRED_VECTOR_IDS):
        fail("authority_index inventory")
    recomputed_index = {
        vid: {
            "family": AUTHORITY[vid]["family"],
            "expected": AUTHORITY[vid]["expected"],
            "authority_fingerprint_hex": AUTHORITY[vid]["authority_fingerprint_hex"],
        }
        for vid in REQUIRED_VECTOR_IDS
    }
    # Compare to hard-coded AUTHORITY and document index fields.
    for vid in REQUIRED_VECTOR_IDS:
        row = index[vid]
        if row.get("family") != AUTHORITY[vid]["family"]:
            fail(f"index family {vid}")
        if row.get("expected") != AUTHORITY[vid]["expected"]:
            fail(f"index expected {vid}")
        if row.get("authority_fingerprint_hex") != AUTHORITY[vid]["authority_fingerprint_hex"]:
            fail(f"index fp {vid}")
    # Seal material uses gate hard pins only (not values taught by the vector).
    seal = {
        "metadata": {
            "schema": PINNED_SCHEMA,
            "status": PINNED_STATUS,
            "adr": PINNED_ADR,
            "title": PINNED_TITLE,
            "nonclaims": list(PINNED_NONCLAIMS),
            "sources": list(PINNED_SOURCES),
        },
        "source_sha256_hex": {rel: PINNED_SOURCE_SHA256_HEX[rel] for rel in PINNED_SOURCES},
        "authority_index": recomputed_index,
    }
    map_fp = sha(stable_json(seal).encode("utf-8")).hex()
    if map_fp != AUTHORITY_MAP_SHA256_HEX:
        fail("authority map sha hardcode")
    if document.get("authority_map_sha256_hex") != AUTHORITY_MAP_SHA256_HEX:
        fail("authority map sha vector")


def validate_pinned_metadata(document: dict[str, Any]) -> None:
    """Exact closed metadata authority from gate hard pins (not from vector)."""

    if document.get("schema") != PINNED_SCHEMA:
        fail("schema pin")
    if document.get("status") != PINNED_STATUS:
        fail("status pin")
    if document.get("adr") != PINNED_ADR:
        fail(f"adr pin: {document.get('adr')!r}")
    if document.get("title") != PINNED_TITLE:
        fail(f"title pin: {document.get('title')!r}")
    if document.get("nonclaims") != list(PINNED_NONCLAIMS):
        fail("nonclaims exact closed set")
    if document.get("sources") != list(PINNED_SOURCES):
        fail("sources exact ordered set")
    digests = document.get("source_sha256_hex")
    if not isinstance(digests, dict):
        fail("source_sha256_hex type")
    expected = {rel: PINNED_SOURCE_SHA256_HEX[rel] for rel in PINNED_SOURCES}
    if digests != expected:
        fail("source_sha256_hex pin")
    # Existence + live content SHA vs hard pins (independent of vector body).
    for rel in PINNED_SOURCES:
        path = ROOT / rel
        if not path.is_file():
            fail(f"missing source file: {rel}")
        live = sha(path.read_bytes()).hex()
        if live != PINNED_SOURCE_SHA256_HEX[rel]:
            fail(f"source content sha drift: {rel}")

    # Production remains intentionally RED in this tranche, so this fence is
    # limited to normative/current explanatory surfaces. Historical candidate
    # numerics must not silently re-enter the contract prose.
    semantic_surfaces = (
        "docs/adr/0021-multi-frame-durable-custody.md",
        "docs/06-versioning-and-compatibility.md",
        "docs/34-v2-runtime-fabric-completion.md",
        "docs/work/2026-08-01-mfdt-spec-accepted-promotion.md",
        "README.md",
    )
    forbidden = (
        "14732",
        "14768",
        "49987",
        "68/58",
        "136/116",
        "CLOSED_CANDIDATE",
        "v3_requires",
        "0x40 OPEN",
        "0x41 OPEN_ACCEPT",
        "0x43 PAGE_ACCEPT",
    )
    for rel in semantic_surfaces:
        text = (ROOT / rel).read_text(encoding="utf-8")
        for token in forbidden:
            if token in text:
                fail(f"stale MFDT semantic token {token!r} in {rel}")


def validate_document_shell(document: dict[str, Any]) -> None:
    validate_pinned_metadata(document)


def validate_constants(document: dict[str, Any], vectors: dict[str, dict[str, Any]], executed: set[str]) -> None:
    c = document["constants"]
    if (
        c["max_content_bytes"] != MAX_CONTENT
        or c["chunk_size"] != CHUNK_SIZE
        or c["max_chunk_count"] != MAX_CHUNKS
        or c["entries_per_page"] != ENTRIES_PER_PAGE
        or c["active_header_bytes"] != HEADER_BYTES
        or c["nm30_value_bytes"] != NM30_BYTES
        or c["sha256_empty_hex"] != sha(b"").hex()
    ):
        fail("constants pin")
    entry = vectors["MF-CONSTANTS-PINNED"]
    if entry.get("constants") != c:
        fail("constants vector body")
    mark_complete("MF-CONSTANTS-PINNED", entry, executed)


def validate_catalog(document: dict[str, Any], vectors: dict[str, dict[str, Any]], executed: set[str]) -> None:
    cat = document["version_catalog"]
    if cat.get("selected_catalog") is not None:
        fail("obsolete selected_catalog inheritance present")
    if cat["mf_o01_status"] != "SPEC_ACCEPTED_GREEN_BASELINE_HISTORY":
        fail("MF-O01 accepted baseline history")
    if cat["mf_o09_status"] != "SPEC_ACCEPTED_CLOSED":
        fail("MF-O09 must remain SPEC_ACCEPTED/CLOSED")
    if (
        cat["mfdt_base_control_versions"] != [1, 2]
        or cat["mfdt_negotiation_version"] != 2
        or cat["mfdt_offer_type"] != 0x34
        or cat["mfdt_accept_type"] != 0x35
        or cat["mfdt_offer_body_bytes"] != 112
        or cat["mfdt_accept_body_bytes"] != 160
    ):
        fail("MFN1 catalog")
    if (
        cat["mfdt_negotiation_domain"] != "private_mfdt_admission_v2"
        or cat["revision1_revision2_interop"] != "REJECT_MUTATION_ZERO"
    ):
        fail("MFN1 revision-2 fail-closed authority")
    if (
        cat["accepted_control_selected_values"] != [1, 2]
        or cat["selected_control_version_3"] != "REJECT"
        or cat["mfdt_candidate_type_values"] != list(range(0x34, 0x44))
        or cat["mfdt_candidate_type_count"] != 16
        or cat["mfdt_transfer_type_count"] != 14
        or cat["target_promotion_on"] != "UNALLOCATED_UNSUPPORTED"
        or cat["target_promotion_off"] != "ONLY_ALLOCATED_TARGET_PROFILE"
        or cat["accepted_wire_changed"] is not False
    ):
        fail("MFN1 allocation/promotion boundary")
    if cat["mfdt_negotiation_independent_of_selected_control_version"] is not True:
        fail("MFDT negotiation domain must be independent")
    if cat["accepted_u5_u6_selected_exact"] != 2:
        fail("Accepted U5/U6 selected exact 2")
    if cat["silent_ge2_forbidden"] is not True or cat["default_policy"] != "OFF":
        fail("version flags")
    if vectors["MF-VERSION-CATALOG-INHERITANCE"].get("version_catalog") != cat:
        fail("version body")
    mark_complete("MF-VERSION-CATALOG-INHERITANCE", vectors["MF-VERSION-CATALOG-INHERITANCE"], executed)

    cm = document["carrier_mapping"]
    if cm["compact_rf_nrw1"]["status"] != "MAPPING_UNAVAILABLE":
        fail("rf")
    if cm["wifi_nwb1"]["status"] != "MAPPING_UNAVAILABLE":
        fail("wifi")
    if cm["ncg1_ncl1"]["status"] != "MAPPING_CANDIDATE":
        fail("ncl1")
    fabric_carrier = cm["generic_fabric_control_plane"]
    if (
        fabric_carrier["status"] != "MAPPING_CANDIDATE"
        or fabric_carrier["mapping"]
        != "FOUNDATION_TRANSFER_RESERVED_APPLICATION"
        or fabric_carrier["namespace_id"] != "org.ninlil.private"
        or fabric_carrier["service_id"] != "mfdt-control"
        or fabric_carrier["schema_id"] != "ncl1-mfdt-v1"
        or fabric_carrier["mfdt_admission_profile_revision"] != 2
        or fabric_carrier["open_layout_revision"] != 2
        or fabric_carrier["descriptor_revision"] != 1
        or fabric_carrier["descriptor_digest_domain"]
        != "NINLIL-MFDT-FOUNDATION-CARRIER-V1"
        or fabric_carrier["schema_major"] != 1
        or fabric_carrier["schema_minor"] != 0
        or fabric_carrier["family"] != "TRANSFER_RESERVED"
        or fabric_carrier["payload"]
        != "exact_ncl1_data_bytes_26_to_1024"
        or fabric_carrier["transaction_id_domain"]
        != "NINLIL-MFDT-FABRIC-TRANSACTION-V1"
        or fabric_carrier["attempt_id_domain"]
        != "NINLIL-MFDT-FABRIC-ATTEMPT-V1"
        or fabric_carrier[
            "ingress_rederives_transaction_and_attempt_ids"
        ] is not True
        or fabric_carrier["tx_permit_required"] is not True
        or fabric_carrier["public_service_registration"] is not False
    ):
        fail("generic Fabric MFDT mapping")
    if cm["nfl1_application_packet"]["carries_control"] is not False:
        fail("nfl1")
    if vectors["MF-CARRIER-MAPPING-MATRIX"].get("carrier_mapping") != cm:
        fail("carrier body")
    mark_complete("MF-CARRIER-MAPPING-MATRIX", vectors["MF-CARRIER-MAPPING-MATRIX"], executed)

    po = document["publication_owner"]
    if po["sole_prepare_caller"] != "foundation_runtime_callback_reconcile_owner":
        fail("pub owner")
    if vectors["MF-PUBLICATION-OWNER-MATRIX"].get("publication_owner") != po:
        fail("pub body")
    mark_complete("MF-PUBLICATION-OWNER-MATRIX", vectors["MF-PUBLICATION-OWNER-MATRIX"], executed)

    roles = document["role_boundaries"]
    if roles["relay_neutral_bearer"]["custody_authority"] is not False:
        fail("relay")
    if vectors["MF-ROLE-BOUNDARIES"].get("role_boundaries") != roles:
        fail("roles body")
    mark_complete("MF-ROLE-BOUNDARIES", vectors["MF-ROLE-BOUNDARIES"], executed)

    api = document["private_api"]
    if api["public_abi"] is not False or api["default_off"] is not True:
        fail("api")
    if api["workspace_bytes"] != 65536:
        fail("workspace")
    if (
        api["active_record_schema"] != 2
        or api["active_schema1_replay_eligible"] is not False
        or api["workspace_growth_bytes"] != 0
        or api["open_growth_bytes_redistributed_within_each_slot"] != 228
        or api["workspace_scope"] != "per_active_transfer_slot"
        or api["host_slot_count"] != 4
        or api["host_coordinator_bytes"] != 512
        or api["host_control_arena_bytes"] != 17920
        or api["host_terminal_catalog_entries"] != 16
        or api["host_terminal_catalog_entry_bytes"] != 64
        or api["host_control_outbox_count"] != 1
        or api["host_control_outbox_bytes"] != 1024
        or api["host_control_route_sentinel"] != 0xFF
        or api["host_owner_workspace_bytes"] != 280064
        or api["host_fifth_active"]
        != "CAPACITY_BUSY_control_outbox_state_mutation_0"
        or api["host_terminal_route_without_active_slot"] is not True
        or api["host_terminal_catalog_rebind"]
        != "peer_role_generation_exact_fresh_nonzero_cookie"
        or api["host_schema1_terminal_replay_eligible"] is not False
        or api["host_control_outbox_backpressure"] != "ERR_BUSY_no_overwrite"
        or api["host_control_traffic_advances_scheduler"] is not False
        or api["host_full_transaction_parallelism"] != 1
        or api["host_peer_unpaid_chunk_offer_max"] != 1
        or api["host_fair_selection_bound"] != 4
    ):
        fail("Host private owner profile")
    if vectors["MF-PRIVATE-API-SURFACE"].get("private_api") != api:
        fail("api body")
    mark_complete("MF-PRIVATE-API-SURFACE", vectors["MF-PRIVATE-API-SURFACE"], executed)

    sidecar_entry = vectors["MF-FSM-STORAGE-SIDECAR-PROFILE"]
    sidecar = sidecar_entry.get("storage_profile")
    if not isinstance(sidecar, dict):
        fail("MFDT sidecar profile type")
    expected_keys = {
        "base_namespace_hex",
        "base_namespace_length",
        "derived_namespace_hex",
        "derived_namespace_length",
        "namespace_magic",
        "namespace_derivation_domain",
        "namespace_preimage",
        "storage_expected_schema",
        "foundation_scanner_value_max",
        "sidecar_single_value_max",
        "binding_key_hex",
        "binding_magic",
        "binding_schema",
        "binding_header_bytes",
        "binding_fixed_bytes",
        "binding_value_hex",
        "binding_value_length",
        "binding_crc32c_hex",
        "binding_base_digest_domain",
        "binding_base_digest_hex",
        "collision_base_namespace_hex",
        "collision_binding_value_hex",
        "collision_binding_differs",
        "known_key_magics",
        "active_record_schema",
        "active_schema1_replay_eligible",
        "foreign_key_policy",
        "missing_binding_policy",
        "host_transfer_keys_hard_max",
        "host_total_keys_hard_max",
        "esp_total_keys_hard_max",
        "esp_total_logical_bytes_hard_max",
        "production_open_phase",
        "destroy_close_order",
        "cross_namespace_atomic_commit_claimed",
        "foundation_large_value_skip_forbidden",
    }
    if set(sidecar) != expected_keys:
        fail("MFDT sidecar profile closed keys")
    base = hx(sidecar["base_namespace_hex"], "sidecar base")
    derived = hx(sidecar["derived_namespace_hex"], "sidecar namespace")
    binding_key = hx(sidecar["binding_key_hex"], "sidecar binding key")
    binding = hx(sidecar["binding_value_hex"], "sidecar binding")
    collision_base = hx(
        sidecar["collision_base_namespace_hex"], "sidecar collision base"
    )
    collision_binding = hx(
        sidecar["collision_binding_value_hex"], "sidecar collision binding"
    )
    namespace_domain = b"NINLIL-MFDT-STORAGE-NAMESPACE-V1"
    binding_domain = b"NINLIL-MFDT-BASE-NAMESPACE-V1"
    derived_expected = b"NMF1" + sha(
        namespace_domain + len(base).to_bytes(2, "big") + base
    )

    def expected_binding(base_namespace: bytes) -> bytes:
        total = 52 + len(base_namespace)
        prefix = (
            b"NMS1"
            + (1).to_bytes(2, "big")
            + (48).to_bytes(2, "big")
            + total.to_bytes(4, "big")
            + len(base_namespace).to_bytes(2, "big")
            + bytes(2)
            + sha(
                binding_domain
                + len(base_namespace).to_bytes(2, "big")
                + base_namespace
            )
            + base_namespace
        )
        return prefix + crc32c(prefix).to_bytes(4, "big")

    binding_expected = expected_binding(base)
    collision_binding_expected = expected_binding(collision_base)
    if (
        not 1 <= len(base) <= 255
        or sidecar["base_namespace_length"] != len(base)
        or derived != derived_expected
        or len(derived) != 36
        or sidecar["derived_namespace_length"] != len(derived)
        or sidecar["namespace_magic"] != "NMF1"
        or sidecar["namespace_derivation_domain"]
        != namespace_domain.decode("ascii")
        or sidecar["namespace_preimage"]
        != "domain_ascii||base_length_u16be||base_namespace_exact"
        or sidecar["storage_expected_schema"] != 1
        or sidecar["foundation_scanner_value_max"] != 4096
        or sidecar["sidecar_single_value_max"] != 65536
        or binding_key != b"NMS1" + bytes(16)
        or binding != binding_expected
        or sidecar["binding_magic"] != "NMS1"
        or sidecar["binding_schema"] != 1
        or sidecar["binding_header_bytes"] != 48
        or sidecar["binding_fixed_bytes"] != 52
        or sidecar["binding_value_length"] != len(binding)
        or sidecar["binding_crc32c_hex"] != f"{crc32c(binding[:-4]):08x}"
        or sidecar["binding_base_digest_domain"]
        != binding_domain.decode("ascii")
        or sidecar["binding_base_digest_hex"]
        != sha(binding_domain + len(base).to_bytes(2, "big") + base).hex()
        or collision_base != derived
        or collision_binding != collision_binding_expected
        or sidecar["collision_binding_differs"] is not True
        or binding == collision_binding
        or sidecar["known_key_magics"]
        != ["NMS1", "NM3S", "NM3R", "NM30", "NRC1"]
        or sidecar["active_record_schema"] != 2
        or sidecar["active_schema1_replay_eligible"] is not False
        or sidecar["foreign_key_policy"] != "CORRUPT_FENCE"
        or sidecar["missing_binding_policy"]
        != "CREATE_ONLY_IF_NAMESPACE_EMPTY"
        or sidecar["host_transfer_keys_hard_max"] != 32
        or sidecar["host_total_keys_hard_max"] != 33
        or sidecar["esp_total_keys_hard_max"] != 32
        or sidecar["esp_total_logical_bytes_hard_max"] != 69632
        or sidecar["production_open_phase"] != "BEFORE_BEARER"
        or sidecar["destroy_close_order"]
        != ["BEARER", "MFDT_SIDECAR", "FOUNDATION_STORAGE"]
        or sidecar["cross_namespace_atomic_commit_claimed"] is not False
        or sidecar["foundation_large_value_skip_forbidden"] is not True
    ):
        fail("MFDT sidecar profile semantics")
    if not 53 <= len(binding) <= 307:
        fail("MFDT sidecar binding length")
    profile_expected = sidecar_entry["expected"]
    if (
        profile_expected.get("derived_namespace_length") != 36
        or profile_expected.get("binding_value_min") != 53
        or profile_expected.get("binding_value_max") != 307
        or profile_expected.get("foundation_scanner_value_max") != 4096
        or profile_expected.get("mfdt_active_value_max") != 35211
        or profile_expected.get("mfdt_active_record_schema") != 2
        or profile_expected.get("active_schema1_replay_eligible") is not False
        or profile_expected.get("nrc1_value_bytes") != 15020
        or profile_expected.get("same_handle_forbidden") is not True
        or profile_expected.get("collision_fail_closed") is not True
        or profile_expected.get("cross_namespace_atomic_commit_claimed")
        is not False
        or profile_expected.get("destroy_close_order")
        != ["BEARER", "MFDT_SIDECAR", "FOUNDATION_STORAGE"]
    ):
        fail("MFDT sidecar profile expected")
    mark_complete(
        "MF-FSM-STORAGE-SIDECAR-PROFILE", sidecar_entry, executed
    )


def validate_budget(document: dict[str, Any], vectors: dict[str, dict[str, Any]], executed: set[str]) -> None:
    b = document["budget"]
    if sum(b["groups"]["receiver"].values()) != RECEIVER_FULLS_MAX:
        fail("rx groups")
    if sum(b["groups"]["sender"].values()) != SENDER_FULLS_MAX:
        fail("tx groups")
    if sum(b["groups"]["empty_receiver"].values()) != RECEIVER_FULLS_EMPTY:
        fail("empty rx")
    if sum(b["groups"]["empty_sender"].values()) != SENDER_FULLS_EMPTY:
        fail("empty tx")
    if b.get("receiver_fulls_max_transfer") != RECEIVER_FULLS_MAX:
        fail("budget rx max field")
    if b.get("sender_fulls_max_transfer") != SENDER_FULLS_MAX:
        fail("budget tx max field")
    if b["required_receiver_fulls_for_reference"] != 154:
        fail("rx ref")
    if b["required_sender_fulls_for_reference"] != 134:
        fail("tx ref")
    if b["obsolete_80_feasible_for_reference_receiver"] is not False:
        fail("obsolete flag")
    if b.get("receiver_fulls_base") != 44 or b.get("receiver_fulls_resume") != 8:
        fail("rx full breakdown")
    if b.get("receiver_fulls_reqid_cache") != 16:
        fail("rx reqid fulls")
    if b.get("sender_fulls_base") != 42 or b.get("sender_fulls_resume") != 8:
        fail("tx full breakdown")
    if b.get("sender_fulls_reqid_cache") != 8:
        fail("tx reqid fulls")
    if b.get("nrc1_retained_until_gc") is not True:
        fail("nrc1 retained pin")
    if b.get("post_terminal_retained_entries") != 2:
        fail("post-terminal keys")
    rest = b["restoration_object"]
    if sha(stable_json(rest).encode("utf-8")).hex() != b["restoration_sha256_hex"]:
        fail("restoration hash")
    arith = vectors["MF-BUDGET-ARITHMETIC-REFERENCE"]
    if arith.get("budget") != b:
        fail("budget body drift vs document")
    mark_complete(
        "MF-BUDGET-ARITHMETIC-REFERENCE",
        arith,
        executed,
    )
    empty = vectors["MF-BUDGET-EMPTY-TRANSFER"]
    if empty.get("receiver_fulls") != 5 or empty.get("sender_fulls") != 5:
        fail("empty fulls fields")
    mark_complete("MF-BUDGET-EMPTY-TRANSFER", empty, executed)
    obs = vectors["MF-BUDGET-OBSOLETE-80-REJECTED"]
    if obs.get("feasible") is not False or obs.get("required_receiver_fulls") != 154:
        fail("obsolete fields")
    mark_complete("MF-BUDGET-OBSOLETE-80-REJECTED", obs, executed)
    rh = vectors["MF-BUDGET-RESTORATION-HASH"]
    if rh.get("restoration_sha256_hex") != b["restoration_sha256_hex"]:
        fail("restoration vector")
    mark_complete("MF-BUDGET-RESTORATION-HASH", rh, executed)

    nrc1b = vectors["MF-BUDGET-NRC1-LOGICAL-BYTES"]
    if nrc1b["expected"]["value_bytes"] != 15020:
        fail("nrc1 budget value")
    if nrc1b["expected"]["logical_bytes"] != 15056:
        fail("nrc1 budget logical")
    if nrc1b["expected"]["slot_bytes"] != 208:
        fail("nrc1 budget slot")
    if nrc1b["expected"]["slot_count"] != 72:
        fail("nrc1 budget slots")
    if nrc1b["expected"]["reachable_max_ids"] != 65:
        fail("nrc1 budget reachable")
    if nrc1b["expected"]["n_complete"] != 65 or nrc1b["expected"]["n_abort"] != 64:
        fail("nrc1 budget path counts")
    if nrc1b["expected"]["timeout_retry_max"] != 8:
        fail("nrc1 budget timeout")
    if nrc1b["expected"]["happy_path_max_ids"] != 41:
        fail("nrc1 budget happy")
    if nrc1b["expected"]["fixed16_rejected"] is not True:
        fail("nrc1 budget fixed16")
    if nrc1b["expected"]["slot_count_ge_reachable"] is not True:
        fail("nrc1 budget ge reachable")
    if nrc1b["expected"]["admission_reserved_entries"] != 3:
        fail("nrc1 budget entries")
    if nrc1b["expected"]["admission_reserved_logical_bytes"] != 50519:
        fail("nrc1 budget admission bytes")
    if b.get("admission_reserved_logical_bytes") != 50519:
        fail("budget doc admission bytes")
    if b.get("nrc1_row_logical_bytes") != 15056:
        fail("budget doc nrc1 row")
    if b.get("admission_reserved_entries") != 3:
        fail("budget doc entries")
    if b.get("nrc1_reachable_max_ids") != 65:
        fail("budget doc reachable")
    if (
        b.get("host_slot_count") != 4
        or b.get("active_row_logical_bytes_max") != 35247
        or b.get("active_replacement_begin_final_logical_bytes_max") != 70494
        or b.get("host_active_group_logical_bytes") != 50303
        or b.get("host_four_active_committed_logical_bytes") != 201212
        or b.get("terminal_row_logical_bytes") != 216
        or b.get("host_terminal_group_logical_bytes") != 15272
        or b.get("post_terminal_retained_logical_bytes") != 15272
        or b.get("host_committed_logical_bytes_hard_max") != 384476
        or b.get("host_begin_final_union_logical_bytes_hard_max") != 434779
        or b.get("host_serialized_full_staging_logical_bytes_max") != 50303
        or b.get("host_tracked_transfer_groups_max") != 16
    ):
        fail("budget Host four-slot bounds")
    mark_complete("MF-BUDGET-NRC1-LOGICAL-BYTES", nrc1b, executed)

    fullm = vectors["MF-BUDGET-FULL-MAX-WITH-REQID"]
    if fullm["expected"]["receiver_fulls"] != 77 or fullm["expected"]["sender_fulls"] != 67:
        fail("full max totals")
    if fullm["expected"]["receiver_base"] != 44 or fullm["expected"]["receiver_resume"] != 8:
        fail("full max rx parts")
    if fullm["expected"]["receiver_reqid_cache"] != 16:
        fail("full max rx reqid")
    if fullm["expected"]["sender_base"] != 42 or fullm["expected"]["sender_reqid_cache"] != 8:
        fail("full max tx parts")
    if fullm["expected"]["required_receiver_reference"] != 154:
        fail("full max daily rx")
    if fullm["expected"]["required_sender_reference"] != 134:
        fail("full max daily tx")
    if fullm["expected"]["nrc1_retained_until_gc"] is not True:
        fail("full max nrc1 retain")
    if fullm["expected"]["terminal_erases_nrc1"] is not False:
        fail("full max terminal erase nrc1")
    if "154/134" not in fullm.get("note", "") or "136/116" in fullm.get("note", ""):
        fail("full max explanatory daily arithmetic")
    mark_complete("MF-BUDGET-FULL-MAX-WITH-REQID", fullm, executed)


def validate_page_body(
    *,
    vid: str,
    body: bytes,
    open_body: bytes,
    manifest_digest: bytes,
    page_index: int,
    pages: int,
    entries: list[bytes],
    page_meta: dict[str, Any],
) -> bytes:
    """Validate full MANIFEST_PAGE header bytes + recomputed page digest."""

    if pages <= 0:
        fail(f"{vid}: unexpected page when pages=0")
    first = page_index * ENTRIES_PER_PAGE
    page_entries = (
        entries[first : first + ENTRIES_PER_PAGE]
        if page_index + 1 < pages
        else entries[first:]
    )
    entry_count = len(page_entries)
    entry_bytes = b"".join(page_entries)
    expected_len = 92 + 40 * entry_count
    if len(body) != expected_len:
        fail(f"{vid}: page body length want {expected_len} got {len(body)}")
    tid = open_body[0:16]
    rev = open_body[16:20]
    # Exact header fields (not digest-only).
    if body[0:16] != tid:
        fail(f"{vid}: page transfer_id header")
    if body[16:20] != rev:
        fail(f"{vid}: page revision header")
    if body[20:52] != manifest_digest:
        fail(f"{vid}: page manifest_digest header")
    if u16(body, 52) != page_index:
        fail(f"{vid}: page_index header")
    if u16(body, 54) != pages:
        fail(f"{vid}: page_count header")
    if u16(body, 56) != first:
        fail(f"{vid}: first_chunk_index header")
    if u16(body, 58) != entry_count:
        fail(f"{vid}: entry_count header")
    page_digest = sha(
        b"NM3-PAGE-V1"
        + tid
        + rev
        + manifest_digest
        + page_index.to_bytes(2, "big")
        + pages.to_bytes(2, "big")
        + first.to_bytes(2, "big")
        + entry_count.to_bytes(2, "big")
        + entry_bytes
    )
    if body[60:92] != page_digest:
        fail(f"{vid}: page_digest field")
    if body[92:] != entry_bytes:
        fail(f"{vid}: page entry bytes")
    # Metadata must match recomputed header, not the other way around.
    if page_meta.get("page_index") != page_index:
        fail(f"{vid}: page_meta index")
    if page_meta.get("page_count") != pages:
        fail(f"{vid}: page_meta count")
    if page_meta.get("first_chunk_index") != first:
        fail(f"{vid}: page_meta first")
    if page_meta.get("entry_count") != entry_count:
        fail(f"{vid}: page_meta entry_count")
    if page_meta.get("page_digest_hex") != page_digest.hex():
        fail(f"{vid}: page_meta digest")
    if page_meta.get("body_length") != expected_len:
        fail(f"{vid}: page_meta body_length")
    return page_digest


def validate_chunk_offer_body(
    *,
    vid: str,
    body: bytes,
    open_body: bytes,
    manifest_digest: bytes,
    content: bytes,
    chunk_index: int,
    chunk_count: int,
    chunk_meta: dict[str, Any],
) -> None:
    """Validate full CHUNK_OFFER header bytes + payload digest from actual bytes."""

    offset, length = chunk_range(len(content), chunk_index)
    expected_len = 96 + length
    if len(body) != expected_len:
        fail(f"{vid}: chunk body length want {expected_len} got {len(body)}")
    tid = open_body[0:16]
    rev = open_body[16:20]
    if body[0:16] != tid:
        fail(f"{vid}: chunk transfer_id header")
    if body[16:20] != rev:
        fail(f"{vid}: chunk revision header")
    if body[20:52] != manifest_digest:
        fail(f"{vid}: chunk manifest_digest header")
    if u16(body, 52) != chunk_index:
        fail(f"{vid}: chunk_index header")
    if u16(body, 54) != chunk_count:
        fail(f"{vid}: chunk_count header")
    if u32(body, 56) != offset:
        fail(f"{vid}: chunk_offset header")
    if u16(body, 60) != length:
        fail(f"{vid}: chunk_length header")
    if u16(body, 62) != 0:
        fail(f"{vid}: chunk reserved header")
    payload = body[96:]
    if len(payload) != length:
        fail(f"{vid}: chunk payload length")
    if payload != content[offset : offset + length]:
        fail(f"{vid}: chunk payload bytes")
    digest = sha(payload)
    if body[64:96] != digest:
        fail(f"{vid}: chunk_sha256 header (recomputed from payload)")
    if chunk_meta.get("chunk_index") != chunk_index:
        fail(f"{vid}: chunk_meta index")
    if chunk_meta.get("chunk_count") != chunk_count:
        fail(f"{vid}: chunk_meta count")
    if chunk_meta.get("chunk_offset") != offset:
        fail(f"{vid}: chunk_meta offset")
    if chunk_meta.get("chunk_length") != length:
        fail(f"{vid}: chunk_meta length")
    if chunk_meta.get("chunk_sha256_hex") != digest.hex():
        fail(f"{vid}: chunk_meta digest")
    if chunk_meta.get("body_length") != expected_len:
        fail(f"{vid}: chunk_meta body_length")
    if chunk_meta.get("chunk_bytes_hex") != payload.hex():
        fail(f"{vid}: chunk_meta bytes")


def validate_positive_fixture(entry: dict[str, Any]) -> None:
    vid = entry["id"]
    fx = entry["fixture"]
    if not isinstance(fx, dict):
        fail(f"{vid}: fixture type")
    content = hx(fx["content_hex"], f"{vid}.content")
    open_body = hx(fx["open_body_hex"], f"{vid}.open")
    entries = [hx(e, f"{vid}.entry") for e in fx["entries_hex"]]
    total = len(content)
    chunks, pages = derive(total)
    exp = entry["expected"]
    if exp["total_length"] != total or exp["chunk_count"] != chunks:
        fail(f"{vid}: geometry")
    if exp["manifest_page_count"] != pages:
        fail(f"{vid}: pages")
    if u32(open_body, 20) != total or u16(open_body, 24) != CHUNK_SIZE:
        fail(f"{vid}: open geo")
    if u16(open_body, 26) != chunks or u16(open_body, 28) != pages:
        fail(f"{vid}: open counts")
    if not 465 <= len(open_body) <= 651:
        fail(f"{vid}: revised OPEN length")
    facts = fx["facts"]
    if (
        facts["open_body_length"] != len(open_body)
        or facts["application_binding_offset"] != 234
        or facts["application_binding_length"] != 228
        or facts["text_offset"] != 462
        or facts["application_binding_hex"] != open_body[234:462].hex()
    ):
        fail(f"{vid}: application binding facts")
    whole = sha(content)
    if open_body[32:64] != whole:
        fail(f"{vid}: open whole mismatch (positive requires integrity)")
    head = open_body[0:202]
    binding = open_body[234:462]
    text = open_body[462:]
    manifest_digest = sha(
        b"NM3-MANIFEST-V1" + head + binding + text + b"".join(entries)
    )
    if open_body[202:234] != manifest_digest:
        fail(f"{vid}: manifest digest")
    if fx["manifest_digest_hex"] != manifest_digest.hex():
        fail(f"{vid}: fixture md")
    if exp["whole_content_sha256_hex"] != whole.hex():
        fail(f"{vid}: expected whole")
    if exp["manifest_digest_hex"] != manifest_digest.hex():
        fail(f"{vid}: expected md")
    ids = fx["ids"]
    derived_transfer_id = sha(
        bytes.fromhex(ids["origin_transaction_id"])
        + bytes.fromhex(ids["target_runtime_id"])
        + facts["target_ordinal"].to_bytes(4, "big")
        + b"ninlil-mfdt-v1id"
    )[:16]
    if derived_transfer_id == bytes(16):
        derived_transfer_id = derived_transfer_id[:-1] + b"\x01"
    if open_body[0:16] != derived_transfer_id:
        fail(f"{vid}: transfer id derivation")
    if len(entries) != chunks:
        fail(f"{vid}: entries")
    for index, entry_b in enumerate(entries):
        if len(entry_b) != 40 or u16(entry_b, 0) != index:
            fail(f"{vid}: entry index")
        offset, length = chunk_range(total, index)
        if u16(entry_b, 2) != length or u32(entry_b, 4) != offset:
            fail(f"{vid}: entry range")
        if entry_b[8:40] != sha(content[offset : offset + length]):
            fail(f"{vid}: entry digest")
    page_list = fx.get("pages")
    if not isinstance(page_list, list):
        fail(f"{vid}: pages must be list")
    if len(page_list) != pages:
        fail(f"{vid}: page list length want {pages} got {len(page_list)}")
    if pages == 0 and page_list != []:
        fail(f"{vid}: empty transfer pages must be []")
    for page in page_list:
        if not isinstance(page, dict):
            fail(f"{vid}: page meta type")
        body = hx(page["body_hex"], f"{vid}.page")
        page_index = page["page_index"]
        if not isinstance(page_index, int) or isinstance(page_index, bool):
            fail(f"{vid}: page_index type")
        validate_page_body(
            vid=vid,
            body=body,
            open_body=open_body,
            manifest_digest=manifest_digest,
            page_index=page_index,
            pages=pages,
            entries=entries,
            page_meta=page,
        )
    chunk_list = fx.get("chunks")
    if not isinstance(chunk_list, list):
        fail(f"{vid}: chunks must be list")
    if len(chunk_list) != chunks:
        fail(f"{vid}: chunk list length want {chunks} got {len(chunk_list)}")
    for chunk in chunk_list:
        if not isinstance(chunk, dict):
            fail(f"{vid}: chunk meta type")
        body = hx(chunk["body_hex"], f"{vid}.chunk")
        index = chunk["chunk_index"]
        if not isinstance(index, int) or isinstance(index, bool):
            fail(f"{vid}: chunk_index type")
        validate_chunk_offer_body(
            vid=vid,
            body=body,
            open_body=open_body,
            manifest_digest=manifest_digest,
            content=content,
            chunk_index=index,
            chunk_count=chunks,
            chunk_meta=chunk,
        )
    # Page order must be contiguous 0..pages-1.
    if pages > 0:
        order = [p["page_index"] for p in page_list]
        if order != list(range(pages)):
            fail(f"{vid}: page order want {list(range(pages))} got {order}")

    final_len = chunk_list[-1]["chunk_length"] if chunks else 0
    if exp["final_chunk_length"] != final_len:
        fail(f"{vid}: final")

    # open_accept_hex: full BIND52 + reservation fields from fixture bytes.
    open_accept = hx(fx["open_accept_hex"], f"{vid}.open_accept")
    if len(open_accept) != 100 or fx.get("open_accept_length") != 100:
        fail(f"{vid}: open_accept length")
    if open_accept[0:16] != open_body[0:16]:
        fail(f"{vid}: open_accept transfer_id")
    if open_accept[16:20] != open_body[16:20]:
        fail(f"{vid}: open_accept revision")
    if open_accept[20:52] != manifest_digest:
        fail(f"{vid}: open_accept manifest")
    if u32(open_accept, 68) != total:
        fail(f"{vid}: open_accept reserved_total_length")
    # layout: BIND52(52) + reservation_id(16) + total(4) + epoch(16) + not_after(8) + complete(1) + res(3)
    complete = open_accept[96]
    if total == 0 and complete != 1:
        fail(f"{vid}: open_accept empty complete")
    if total > 0 and complete != 0:
        fail(f"{vid}: open_accept nonempty complete")
    if any(open_accept[97:100]):
        fail(f"{vid}: open_accept reserved")

    # page_accepts / chunk_accepts control messages bind transfer_id + digests.
    page_accepts = fx.get("page_accepts") or []
    if not isinstance(page_accepts, list) or len(page_accepts) != pages:
        fail(f"{vid}: page_accepts count")
    for pa in page_accepts:
        body = hx(pa["body_hex"], f"{vid}.page_accept")
        if len(body) != 108:
            fail(f"{vid}: page_accept length")
        if body[0:16] != open_body[0:16] or body[20:52] != manifest_digest:
            fail(f"{vid}: page_accept bind")
        pidx = pa["page_index"]
        if u16(body, 52) != pidx:
            fail(f"{vid}: page_accept index")
        # page digest field must match sealed page body digest
        matching = next(p for p in page_list if p["page_index"] == pidx)
        if body[56:88] != bytes.fromhex(matching["page_digest_hex"]):
            fail(f"{vid}: page_accept digest field")

    chunk_accepts = fx.get("chunk_accepts") or []
    if not isinstance(chunk_accepts, list) or len(chunk_accepts) != chunks:
        fail(f"{vid}: chunk_accepts count")
    for ca in chunk_accepts:
        body = hx(ca["body_hex"], f"{vid}.chunk_accept")
        if len(body) != 88:
            fail(f"{vid}: chunk_accept length")
        if body[0:16] != open_body[0:16] or body[20:52] != manifest_digest:
            fail(f"{vid}: chunk_accept bind")
        cidx = ca["chunk_index"]
        if u16(body, 52) != cidx:
            fail(f"{vid}: chunk_accept index")
        matching_c = next(c for c in chunk_list if c["chunk_index"] == cidx)
        if body[56:88] != bytes.fromhex(matching_c["chunk_sha256_hex"]):
            fail(f"{vid}: chunk_accept digest")

    # finalize_hex recomputed from actual whole/total/bind.
    finalize = hx(fx["finalize_hex"], f"{vid}.finalize")
    if len(finalize) != 92 or fx.get("finalize_length") != 92:
        fail(f"{vid}: finalize length")
    if finalize[0:16] != open_body[0:16] or finalize[16:20] != open_body[16:20]:
        fail(f"{vid}: finalize transfer_id/rev")
    if finalize[20:52] != manifest_digest:
        fail(f"{vid}: finalize manifest")
    if finalize[52:84] != whole:
        fail(f"{vid}: finalize whole")
    if u32(finalize, 84) != total or u32(finalize, 88) != 0:
        fail(f"{vid}: finalize total/reserved")

    accept = hx(fx["transfer_accept_hex"], f"{vid}.accept")
    if len(accept) != 160:
        fail(f"{vid}: accept len")
    # Recompute acceptance digest from actual preceding bytes.
    if accept[128:] != sha(b"NM3-ACCEPT-V1" + accept[:128]):
        fail(f"{vid}: accept digest integrity")
    if accept[0:16] != open_body[0:16] or accept[16:20] != open_body[16:20]:
        fail(f"{vid}: accept bind id/rev")
    if accept[20:52] != manifest_digest:
        fail(f"{vid}: accept bind manifest")
    if accept[52:84] != whole:
        fail(f"{vid}: accept whole")
    if u32(accept, 84) != total:
        fail(f"{vid}: accept total")
    # transfer_id must match session/transaction context (OPEN transfer_id).
    ids = fx.get("ids") or {}
    if ids.get("transfer_id") != open_body[0:16].hex():
        fail(f"{vid}: fixture ids transfer_id")
    evidence = accept[88:104]
    pub = sha(
        b"NM3-PUBLISH-V1"
        + open_body[0:16]
        + open_body[16:20]
        + manifest_digest
        + whole
        + total.to_bytes(4, "big")
        + evidence
    )[:16]
    if fx["publication_token_hex"] != pub.hex() or exp["publication_token_hex"] != pub.hex():
        fail(f"{vid}: publication")
    # Mutating transfer_id in ACCEPT while repairing digest must still fail context bind.
    # (Checked in self-test; here enforce accept transfer_id == open transfer_id.)
    if accept[0:16] != bytes.fromhex(ids["transfer_id"]):
        fail(f"{vid}: accept transfer_id context")
    rec = hx(fx["receiver_content_verified_value_hex"], f"{vid}.nm3r")
    require_valid_active_semantics(rec, f"{vid}.nm3r")
    if sha(rec).hex() != fx["receiver_content_verified_sha256_hex"]:
        fail(f"{vid}: nm3r sha")
    if rec[16:32] != open_body[0:16]:
        fail(f"{vid}: nm3r transfer_id")
    nm30 = hx(fx["nm30_value_hex"], f"{vid}.nm30")
    require_valid_nm30_crc(nm30, f"{vid}.nm30")
    if fx["tombstone_digest_hex"] != sha(nm30).hex():
        fail(f"{vid}: tombstone")
    if nm30[8:24] != open_body[0:16]:
        fail(f"{vid}: nm30 transfer_id")


def validate_positives(vectors: dict[str, dict[str, Any]], executed: set[str]) -> None:
    specs = [
        ("MF-POS-EMPTY-PAYLOAD", 0, 0, 0),
        ("MF-POS-ONE-BYTE", 1, 1, 1),
        ("MF-POS-EXACT-MULTIPLE-FINAL", CHUNK_SIZE * 2, 2, CHUNK_SIZE),
        ("MF-POS-ONE-BYTE-FINAL", CHUNK_SIZE + 1, 2, 1),
        ("MF-POS-MAX-PAYLOAD-37-CHUNKS", MAX_CONTENT, 37, 512),
        ("MF-POS-TWO-PAGE-MANIFEST", CHUNK_SIZE * 23, 23, CHUNK_SIZE),
    ]
    for vid, total, chunks, final in specs:
        entry = vectors[vid]
        validate_positive_fixture(entry)
        if entry["expected"]["total_length"] != total:
            fail(f"{vid}: auth total")
        if entry["expected"]["chunk_count"] != chunks:
            fail(f"{vid}: auth chunks")
        if entry["expected"]["final_chunk_length"] != final:
            fail(f"{vid}: auth final")
        if vid == "MF-POS-EMPTY-PAYLOAD":
            if entry["fixture"]["content_sha256_hex"] != sha(b"").hex():
                fail("empty sha")
        if vid == "MF-POS-TWO-PAGE-MANIFEST" and entry["expected"]["manifest_page_count"] != 2:
            fail("two pages")
        mark_complete(vid, entry, executed)

    replay = vectors["MF-POS-COMPLETION-RECEIPT-REPLAY"]
    if replay["first_accept_hex"] != replay["replay_accept_hex"]:
        fail("replay bodies")
    if replay["expected"]["state_mutation_on_replay"] != 0:
        fail("replay mut")
    if replay["expected"]["transfer_accept_hex"] != replay["first_accept_hex"]:
        fail("replay expected body")
    mark_complete("MF-POS-COMPLETION-RECEIPT-REPLAY", replay, executed)

    same = vectors["MF-POS-REQID-CACHE-SAME-ID-STABLE"]
    if same["first_page_accept_hex"] != same["cached_retry_page_accept_hex"]:
        fail("reqid cache bodies diverge")
    if same["expected"]["first_manifest_complete"] != 0:
        fail("reqid first complete")
    if same["expected"]["cached_manifest_complete"] != 0:
        fail("reqid cached complete")
    if same["expected"]["state_mutation_on_same_request_id"] != 0:
        fail("reqid mutation")
    mark_complete("MF-POS-REQID-CACHE-SAME-ID-STABLE", same, executed)

    adv = vectors["MF-POS-REQID-NEW-ID-CURRENT-COMPLETE"]
    if adv["expected"]["first_manifest_complete"] != 0:
        fail("reqid adv first")
    if adv["expected"]["second_manifest_complete"] != 1:
        fail("reqid adv second")
    if adv["first_request_id"] == adv["second_request_id"]:
        fail("reqid adv same id")
    if adv["first_page_accept_hex"] == adv["second_page_accept_hex"]:
        fail("reqid adv same body")
    mark_complete("MF-POS-REQID-NEW-ID-CURRENT-COMPLETE", adv, executed)

    nrc1 = vectors["MF-POS-REQID-NRC1-LAYOUT-KAT"]
    if nrc1["expected"]["value_length"] != 15020:
        fail("nrc1 value length")
    if nrc1["expected"]["slot_count"] != 72:
        fail("nrc1 slots")
    if nrc1["expected"]["reachable_max_ids"] != 65:
        fail("nrc1 reachable")
    if nrc1["expected"]["happy_path_max_ids"] != 41:
        fail("nrc1 happy path max")
    if nrc1["expected"]["slot_bytes"] != 208:
        fail("nrc1 slot bytes")
    if nrc1["expected"]["logical_bytes"] != 15056:
        fail("nrc1 logical")
    if nrc1["expected"]["timeout_retry_max"] != 8:
        fail("nrc1 timeout")
    if len(nrc1["nrc1_key_hex"]) != 40:
        fail("nrc1 key len")
    if len(nrc1["nrc1_value_hex"]) != 15020 * 2:
        fail("nrc1 value hex len")
    nrc_value = hx(nrc1["nrc1_value_hex"], "nrc1 layout value")
    nrc_key = hx(nrc1["nrc1_key_hex"], "nrc1 layout key")
    require_valid_nrc1_semantics(
        nrc_value, "nrc1 layout value", expected_transfer_id=nrc_key[4:20]
    )
    first_slot = hx(nrc1["first_slot_hex"], "nrc1 first slot")
    if len(first_slot) != 208 or u32(first_slot, 8) != 1:
        fail("nrc1 per-slot session generation KAT")
    if hx(nrc1["empty_slot_hex"], "nrc1 empty slot") != bytes(208):
        fail("nrc1 empty slot all-zero")
    try:
        require_valid_nrc1_semantics(
            hx(nrc1["occupied_l0_repaired_crc_mutant_hex"], "nrc1 l0 mutant"),
            "nrc1 occupied L0 mutant",
        )
    except GateError:
        pass
    else:
        fail("nrc1 occupied L=0 repaired-CRC mutant accepted")
    mark_complete("MF-POS-REQID-NRC1-LAYOUT-KAT", nrc1, executed)

    max41 = vectors["MF-POS-REQID-MAX-TRANSFER-OCCUPIED-41"]
    if max41["expected"]["occupied_count"] != 41:
        fail("max41 occupied")
    if max41["expected"]["slot_count"] != 72:
        fail("max41 slots")
    if max41["expected"]["fits"] is not True:
        fail("max41 fits")
    if max41["expected"]["cache_full"] is not False:
        fail("max41 cache_full")
    if max41["expected"]["exceeds_obsolete_fixed16"] is not True:
        fail("max41 exceeds16")
    if (
        max41["expected"].get("open_ids") != 1
        or max41["expected"].get("page_ids") != 2
        or max41["expected"].get("chunk_ids") != 37
        or max41["expected"].get("finalize_ids") != 1
    ):
        fail("max41 breakdown ids")
    if max41["occupied_count"] != 41:
        fail("max41 field occupied")
    if len(max41["nrc1_value_hex"]) != 15020 * 2:
        fail("max41 value hex")
    require_valid_nrc1_semantics(
        hx(max41["nrc1_value_hex"], "max41 NRC1"), "max41 NRC1"
    )
    mark_complete("MF-POS-REQID-MAX-TRANSFER-OCCUPIED-41", max41, executed)

    smv = vectors["MF-POS-REQID-RETRY-BUDGET-SM"]
    if smv["expected"]["scope"] != "per_transfer_per_owner_side":
        fail("sm scope")
    if smv["expected"]["owner"] != "requestor_of_outbound_mfdt_control":
        fail("sm owner")
    if smv["expected"]["initial_value"] != 8 or smv["expected"]["max_value"] != 8:
        fail("sm initial/max")
    if smv["expected"]["min_value"] != 0:
        fail("sm min")
    if smv["expected"]["header_offset"] != 105:
        fail("sm offset")
    if smv["expected"]["decrement_event"] != "timeout_retry_with_new_request_id":
        fail("sm decrement")
    if smv["expected"]["exhaustion_is_terminal"] is not False:
        fail("sm exhaustion terminal")
    if smv["expected"]["exhaustion_is_nrc1_eviction"] is not False:
        fail("sm exhaustion eviction")
    if smv["expected"]["exhaustion_forbids_new_request_id_timeout_retry"] is not True:
        fail("sm exhaustion forbid")
    if smv["expected"]["not_per_request_id"] is not True or smv["expected"]["not_per_stage"] is not True:
        fail("sm not per req/stage")
    sm_body = smv.get("retry_budget_sm")
    if not isinstance(sm_body, dict):
        fail("sm body type")
    if sm_body.get("initial_value") != 8 or sm_body.get("scope") != "per_transfer_per_owner_side":
        fail("sm body pins")
    mark_complete("MF-POS-REQID-RETRY-BUDGET-SM", smv, executed)

    reach = vectors["MF-POS-REQID-REACHABLE-MAX-COUNT"]
    if reach["expected"]["n_complete"] != 65:
        fail("reach n_complete")
    if reach["expected"]["n_abort"] != 64:
        fail("reach n_abort")
    if reach["expected"]["reachable_max"] != 65:
        fail("reach max")
    if reach["expected"]["timeout_retry_max"] != 8:
        fail("reach timeout")
    if reach["expected"]["slot_count"] != 72:
        fail("reach slots")
    if reach["expected"]["slot_count_ge_reachable"] is not True:
        fail("reach ge")
    if reach["expected"]["naive_union_is_single_path"] is not False:
        fail("reach naive")
    if reach["expected"]["naive_union"] != 57:
        fail("reach naive union value")
    if reach["expected"]["terminal_outcomes_exclusive"] is not True:
        fail("reach exclusive")
    if reach["expected"]["finalize_abort_success_exclusive"] is not True:
        fail("reach finalize/abort exclusive")
    if reach["expected"]["derived_from_retry_budget_sm"] is not True:
        fail("reach derived from sm")
    if reach["n_complete"] != 1 + 2 + 37 + 8 + 1 + 8 + 8:
        fail("reach formula complete field")
    if reach["n_abort"] != 1 + 2 + 37 + 8 + 8 + 8:
        fail("reach formula abort field")
    fu = reach.get("first_units")
    if not isinstance(fu, dict):
        fail("reach first_units")
    if fu.get("retry_new_ids") != 8 or fu.get("finalize") != 1 or fu.get("abort") != 8:
        fail("reach first_units values")
    if reach["expected"].get("illegal_two_gen_no_reclaim") != 73:
        fail("reach illegal two-gen")
    if reach["expected"].get("resume_reclaim_on_session_gen_advance") is not True:
        fail("reach reclaim")
    mark_complete("MF-POS-REQID-REACHABLE-MAX-COUNT", reach, executed)

    sgen = vectors["MF-POS-REQID-SESSION-GEN-RESUME-RECLAIM"]
    if sgen["expected"]["session_gen_max"] != 2:
        fail("sgen max")
    if sgen["expected"]["resume_per_gen"] != 8:
        fail("sgen resume")
    if sgen["expected"]["peak_with_reclaim"] != 65:
        fail("sgen peak")
    if sgen["expected"]["reclaim_resume_class_only"] is not True:
        fail("sgen reclaim class")
    gen1 = hx(sgen["generation_1_nrc1_value_hex"], "session gen1 NRC1")
    gen2 = hx(sgen["generation_2_nrc1_value_hex"], "session gen2 NRC1")
    require_valid_nrc1_semantics(gen1, "session gen1 NRC1")
    require_valid_nrc1_semantics(gen2, "session gen2 NRC1")
    if (
        sgen["initial_session_generation"] != 7
        or sgen["successor_session_generation"] != 8
        or u32(gen1, 24) != 7
        or u32(gen2, 24) != 8
    ):
        fail("session generation row header")
    if gen2[40:248] != gen1[40:248]:
        fail("prior-generation non-RESUME slot not retained bit-exact")
    second_slot = 40 + 208
    if u64(gen2, second_slot) != 9001 or u32(gen2, second_slot + 8) != 8:
        fail("same request ID not rebound to successor generation")
    for key in (
        "future_generation_nrc1_value_hex",
        "gap_generation_nrc1_value_hex",
        "third_generation_nrc1_value_hex",
    ):
        rejected = False
        try:
            require_valid_nrc1_semantics(
                hx(sgen[key], f"{key} mutant"), f"{key} mutant"
            )
        except GateError:
            rejected = True
        if not rejected:
            fail(f"{key}: invalid generation record accepted")
    mark_complete("MF-POS-REQID-SESSION-GEN-RESUME-RECLAIM", sgen, executed)

    twogen = vectors["MF-NEG-REQID-TWO-GEN-NO-RECLAIM-CAPACITY"]
    if twogen["expected"]["illegal_occupancy"] != 73:
        fail("twogen occ")
    if twogen["expected"]["slot_count"] != 72:
        fail("twogen slots")
    if twogen["expected"]["exceeds"] is not True:
        fail("twogen exceeds")
    mark_complete("MF-NEG-REQID-TWO-GEN-NO-RECLAIM-CAPACITY", twogen, executed)
    rtry = vectors["MF-POS-REQID-MAX-RETRY-TRACE"]
    if rtry["expected"]["timeout_retries"] != 8:
        fail("retry count")
    if rtry["expected"]["occupied_count"] != 9:
        fail("retry occupied")
    if rtry["expected"]["new_request_id_each_retry"] is not True:
        fail("retry new ids")
    if rtry["expected"]["fits_in_capacity"] is not True:
        fail("retry fits")
    if rtry["expected"]["slot_count"] != 72:
        fail("retry slots")
    if len(rtry["retry_request_ids"]) != 8:
        fail("retry id list len")
    if rtry["first_request_id"] in rtry["retry_request_ids"]:
        fail("retry id overlap first")
    if len(set(rtry["retry_request_ids"])) != 8:
        fail("retry ids unique")
    if len(rtry["nrc1_value_hex"]) != 15020 * 2:
        fail("retry value hex")
    require_valid_nrc1_semantics(
        hx(rtry["nrc1_value_hex"], "retry NRC1"), "retry NRC1"
    )
    mark_complete("MF-POS-REQID-MAX-RETRY-TRACE", rtry, executed)

    tld = vectors["MF-POS-REQID-TERMINAL-LATE-DUP-MATRIX"]
    if tld["expected"]["nrc1_retained_with_nm30"] is not True:
        fail("tld retain")
    if tld["expected"]["terminal_erases_nrc1"] is not False:
        fail("tld erase")
    if tld["expected"]["operation_count"] != 6:
        fail("tld op count")
    if tld["expected"]["all_bit_exact"] is not True:
        fail("tld bit exact")
    if tld["expected"]["state_mutation_on_hit"] != 0:
        fail("tld mutation")
    ops = tld.get("operations")
    if not isinstance(ops, list) or len(ops) != 6:
        fail("tld operations list")
    names = {o.get("operation") for o in ops if isinstance(o, dict)}
    for need in (
        "OPEN_ACCEPT",
        "PAGE_ACCEPT",
        "CHUNK_ACCEPT",
        "RESUME_STATE",
        "TRANSFER_ACCEPT",
        "ABORT_DENIED",
    ):
        if need not in names:
            fail(f"tld missing {need}")
    if len(tld["nrc1_value_hex"]) != 15020 * 2:
        fail("tld nrc1 value")
    if len(tld["nm30_value_hex"]) != 180 * 2:
        fail("tld nm30 value")
    require_valid_nrc1_semantics(
        hx(tld["nrc1_value_hex"], "terminal NRC1"), "terminal NRC1"
    )
    require_valid_nm30_semantics(
        hx(tld["nm30_value_hex"], "terminal NM30"), "terminal NM30"
    )
    mark_complete("MF-POS-REQID-TERMINAL-LATE-DUP-MATRIX", tld, executed)

    nm30v = vectors["MF-POS-NM30-SCHEMA2-LAYOUT-KAT"]
    nm30 = hx(nm30v["nm30_value_hex"], "schema2 NM30")
    require_valid_nm30_semantics(nm30, "schema2 NM30")
    if (
        nm30v["expected"]["schema"] != 2
        or nm30v["expected"]["value_length"] != 180
        or nm30v["expected"]["peer_endpoint_id_offset"] != 156
        or nm30v["expected"]["peer_endpoint_id_bytes"] != 16
        or nm30v["expected"]["owner_role_offset"] != 172
        or nm30v["expected"]["reserved_offset"] != 173
        or nm30v["expected"]["reserved_bytes"] != 3
        or nm30v["expected"]["crc_offset"] != 176
        or nm30v["expected"]["crc_preimage_bytes"] != 176
        or nm30v["expected"]["session_cookie_durable"] is not False
        or nm30v["expected"]["session_generation_authority"]
        != "NRC1_header_offset_24"
        or nm30[156:172].hex() != nm30v["peer_endpoint_id_hex"]
        or nm30[172] != 2
        or nm30[173:176] != bytes(3)
        or sha(nm30).hex() != nm30v["nm30_sha256_hex"]
        or set(nm30v["durable_fields_exclude"])
        != {"session_cookie", "session_generation"}
    ):
        fail("schema2 NM30 exact layout authority")
    mark_complete("MF-POS-NM30-SCHEMA2-LAYOUT-KAT", nm30v, executed)

    four_hit = vectors["MF-POS-HOST-FOUR-ACTIVE-TERMINAL-HIT"]
    if (
        four_hit["expected"]["active_before"] != 4
        or four_hit["expected"]["active_after"] != 4
        or four_hit["expected"]["active_slot_allocations"] != 0
        or four_hit["expected"]["control_route"] != 0xFF
        or four_hit["expected"]["nrc1_hit"] is not True
        or four_hit["expected"]["full_count"] != 0
        or four_hit["expected"]["store_mutation"] != 0
        or four_hit["expected"]["owned_control_outbox"] is not True
        or four_hit["expected"]["transport_status"] != "OK"
        or four_hit["expected"]["scheduler_cursor_unchanged"] is not True
        or four_hit["expected"]["peer_unpaid_fence_unchanged"] is not True
        or len(four_hit["active_transfer_ids"]) != 4
        or len(hx(four_hit["terminal_response_body_hex"], "four hit body")) != 108
    ):
        fail("four-active terminal control hit")
    mark_complete("MF-POS-HOST-FOUR-ACTIVE-TERMINAL-HIT", four_hit, executed)

    fsm = vectors["MF-FSM-TERMINAL-ACTIVE-CODES-UNREACHABLE"]
    if fsm["forbidden_active_state_codes"] != [7, 9, 39]:
        fail("fsm forbidden codes")
    if fsm["expected"]["durable_terminal_kind"] != "NM30_ONLY":
        fail("fsm terminal kind")
    if fsm["expected"]["both_active_and_nm30"] != "CORRUPT":
        fail("fsm both")
    mark_complete("MF-FSM-TERMINAL-ACTIVE-CODES-UNREACHABLE", fsm, executed)

    trace = vectors["MF-TRACE-S1-S6-HAPPY-PATH"]
    if trace["stages"] != [
        "S1_OPEN",
        "S2_MANIFEST",
        "S3_CHUNKS",
        "S4_FINALIZE_ACCEPT",
        "S5_HANDOFF",
        "S6_TERMINAL_NM30",
    ]:
        fail("trace stages")
    if trace["expected"]["s6_durable"] != "NM30_ONLY":
        fail("trace s6")
    mark_complete("MF-TRACE-S1-S6-HAPPY-PATH", trace, executed)


def validate_application_handoff_amendment(
    vectors: dict[str, dict[str, Any]], executed: set[str]
) -> None:
    layout = vectors["MF-POS-OPEN-APPLICATION-BINDING-LAYOUT-KAT"]
    expected_layout = [
        {"field": field, "offset": offset, "bytes": size}
        for field, offset, size in APPLICATION_BINDING_LAYOUT_GATE
    ]
    if layout.get("application_binding_layout") != expected_layout:
        fail("application binding layout KAT")
    for prefix, wanted_length in (("minimum", 465), ("maximum", 651)):
        body = hx(layout[f"{prefix}_open_body_hex"], f"{prefix} revised OPEN")
        facts = layout[f"{prefix}_facts"]
        if (
            len(body) != wanted_length
            or facts.get("open_body_length") != wanted_length
            or facts.get("application_binding_offset") != 234
            or facts.get("application_binding_length") != 228
            or facts.get("text_offset") != 462
            or facts.get("application_binding_hex") != body[234:462].hex()
        ):
            fail(f"{prefix} revised OPEN geometry")
        digest = sha(
            b"NM3-MANIFEST-V1"
            + body[0:202]
            + body[234:462]
            + body[462:]
        )
        if (
            body[202:234] != digest
            or layout[f"{prefix}_manifest_digest_hex"] != digest.hex()
        ):
            fail(f"{prefix} revised OPEN manifest digest")
    minimum_body = hx(layout["minimum_open_body_hex"], "minimum deadline OPEN")
    maximum_body = hx(layout["maximum_open_body_hex"], "maximum deadline OPEN")
    expected_deadline_cases = [
        {
            "case": "uplink_eventfact_no_deadline",
            "service_family": 1,
            "deadline_epoch_hex": "00" * 16,
            "absolute_effect_deadline_ms_u64_hex": "ffffffffffffffff",
            "evidence_grace_ms_u64_hex": "0000000000000000",
            "status": "OK",
        },
        {
            "case": "uplink_eventfact_deadline_zero",
            "service_family": 1,
            "deadline_epoch_hex": "00" * 16,
            "absolute_effect_deadline_ms_u64_hex": "0000000000000000",
            "evidence_grace_ms_u64_hex": "0000000000000000",
            "status": "REJECT",
        },
        {
            "case": "finite_downlink_min",
            "service_family": 2,
            "deadline_epoch_hex": maximum_body[178:194].hex(),
            "absolute_effect_deadline_ms_u64_hex": "0000000000000001",
            "status": "OK",
        },
        {
            "case": "finite_downlink_max",
            "service_family": 2,
            "deadline_epoch_hex": maximum_body[178:194].hex(),
            "absolute_effect_deadline_ms_u64_hex": "fffffffffffffffe",
            "status": "OK",
        },
        {
            "case": "downlink_no_deadline",
            "service_family": 2,
            "deadline_epoch_hex": maximum_body[178:194].hex(),
            "absolute_effect_deadline_ms_u64_hex": "ffffffffffffffff",
            "status": "REJECT",
        },
    ]
    if (
        minimum_body[80:96] == bytes(16)
        or minimum_body[178:194] != bytes(16)
        or minimum_body[194:202] != bytes.fromhex("ffffffffffffffff")
        or int.from_bytes(minimum_body[434:438], "big") != 1
        or int.from_bytes(minimum_body[438:446], "big") != 0
        or int.from_bytes(minimum_body[446:454], "big") != 0
        or maximum_body[80:96] != bytes(16)
        or maximum_body[178:194] == bytes(16)
        or not 1 <= int.from_bytes(maximum_body[194:202], "big") < (1 << 64) - 1
        or int.from_bytes(maximum_body[434:438], "big") != 2
        or layout.get("deadline_shape_cases") != expected_deadline_cases
    ):
        fail("Foundation deadline sentinel OPEN authority")
    if layout["expected"] != {
        "status": "OK",
        "branch": "open_application_binding_revision2",
        "base_fixed_bytes": 234,
        "application_binding_bytes": 228,
        "text_offset": 462,
        "open_body_min": 465,
        "open_body_max": 651,
        "manifest_binds_entire_application_binding": True,
        "admission_profile_revision": 2,
        "active_record_schema": 2,
        "active_schema1_replay_eligible": False,
        "nts3_future_schema": "1.2",
        "nts3_future_fields": ["mfdt_transfer_id[16]", "mfdt_target_ordinal_u32"],
        "nts3_future_target_suffix_placement": "canonical_target_encoding_tail",
        "nts3_future_target_suffix_presence": "bearer_route_eq_MFDT_V1_3",
        "nts3_future_target_suffix_bytes": 20,
        "nts3_future_target_count_max": 4,
        "nts3_future_mfdt_target_rule": (
            "transfer_id_nonzero__sender_ordinal_eq_bound_target_index__"
            "receiver_ordinal_eq_open_origin_ordinal_lt4_u32_be"
        ),
        "nts3_future_non_mfdt_suffix_bytes": 0,
        "nts3_future_non_mfdt_memory_rule": (
            "transfer_id_zero16_and_ordinal_zero"
        ),
        "nts3_schema11_record_max_bytes": 4031,
        "nts3_schema11_inline_payload_max_bytes": 926,
        "nts3_future_mfdt_record_max_bytes": 3185,
        "nts3_record_ceiling_bytes": 4096,
        "public_callback_context_id": "foundation_transaction_id",
        "publication_token_scope": "private_mfdt_handoff_dedupe_only",
        "deadline_sentinel_erratum": "foundation_canonical_bit_exact",
        "no_deadline_u64_hex": "ffffffffffffffff",
        "finite_downlink_deadline_min_u64_hex": "0000000000000001",
        "finite_downlink_deadline_max_u64_hex": "fffffffffffffffe",
        "deadline_zero_rejected": True,
        "downlink_no_deadline_rejected": True,
        "deadline_normalization_forbidden": True,
    }:
        fail("application binding layout expected authority")
    mark_complete("MF-POS-OPEN-APPLICATION-BINDING-LAYOUT-KAT", layout, executed)

    mutation = vectors["MF-NEG-OPEN-APPLICATION-BINDING-FIELD-MUTATION"]
    body = hx(mutation["open_body_hex"], "binding mutation OPEN")
    entries = b"".join(
        hx(item, "binding mutation entry")
        for item in mutation["manifest_entries_hex"]
    )
    baseline = sha(
        b"NM3-MANIFEST-V1"
        + body[0:202]
        + body[234:462]
        + body[462:]
        + entries
    )
    if baseline.hex() != mutation["manifest_digest_hex"] or body[202:234] != baseline:
        fail("binding mutation baseline manifest")
    if mutation.get("mutations") != [
        {"field": field, "offset": offset, "bytes": size, "xor_first_byte": 1}
        for field, offset, size in APPLICATION_BINDING_LAYOUT_GATE
    ]:
        fail("binding mutation matrix")
    for row in mutation["mutations"]:
        altered = bytearray(body)
        altered[row["offset"]] ^= row["xor_first_byte"]
        repaired = sha(
            b"NM3-MANIFEST-V1"
            + altered[0:202]
            + altered[234:462]
            + altered[462:]
            + entries
        )
        if repaired == baseline:
            fail(f"binding field not digest-bound: {row['field']}")
    mark_complete("MF-NEG-OPEN-APPLICATION-BINDING-FIELD-MUTATION", mutation, executed)

    carrier = vectors["MF-NEG-CARRIER-OPEN-BINDING-MISMATCH-PREFULL"]
    boundary_matrix = [
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
    ]
    if (
        len(hx(carrier["open_body_hex"], "carrier mismatch OPEN")) < 465
        or carrier.get("validation_boundary")
        != (
            "sender_before_G_S_OPEN_full_original_exact__"
            "receiver_before_G_R_OPEN_party_target_subset_exact_"
            "canonical_open_no_private_control_equality"
        )
        or carrier["expected"].get("full_count") != 0
        or carrier["expected"].get("durable_rows_created") != 0
        or carrier["expected"].get("callback_count") != 0
        or carrier["expected"].get("receipt_count") != 0
        or carrier.get("mismatch_fields") != boundary_matrix
    ):
        fail("carrier/OPEN pre-FULL mismatch authority")
    mark_complete("MF-NEG-CARRIER-OPEN-BINDING-MISMATCH-PREFULL", carrier, executed)

    mixed = vectors["MF-NEG-ADMISSION-REV1-REV2-MIXED"]
    if mixed.get("cases") != [
        {
            "local_admission_revision": 2,
            "peer_admission_revision": 1,
            "open_layout_revision": 1,
            "active_record_schema": 1,
        },
        {
            "local_admission_revision": 1,
            "peer_admission_revision": 2,
            "open_layout_revision": 2,
            "active_record_schema": 2,
        },
        {
            "local_admission_revision": 2,
            "peer_admission_revision": 2,
            "open_layout_revision": 1,
            "active_record_schema": 1,
        },
    ] or (
        mixed["expected"].get("full_count") != 0
        or mixed["expected"].get("durable_state_mutation") != 0
        or mixed["expected"].get("migration_attempted") is not False
    ):
        fail("admission revision mixed fail-closed authority")
    mark_complete("MF-NEG-ADMISSION-REV1-REV2-MIXED", mixed, executed)

    evidence = vectors["MF-POS-APPLICATION-EVIDENCE-DIGEST-KAT"]
    evidence_bytes = hx(evidence["evidence_bytes_hex"], "application evidence")
    preimage = (
        b"NINLIL-MFDT-APPLICATION-EVIDENCE-V1"
        + hx(evidence["publication_token_hex"], "publication token")
        + hx(evidence["origin_transaction_id_hex"], "origin transaction")
        + hx(evidence["original_attempt_id_hex"], "original attempt")
        + evidence["target_ordinal"].to_bytes(4, "big")
        + evidence["evidence_stage"].to_bytes(4, "big")
        + len(evidence_bytes).to_bytes(4, "big")
        + evidence_bytes
    )
    digest = sha(preimage)
    if (
        evidence["domain_ascii"] != "NINLIL-MFDT-APPLICATION-EVIDENCE-V1"
        or evidence["evidence_preimage_hex"] != preimage.hex()
        or evidence["application_evidence_digest_hex"] != digest.hex()
        or evidence["expected"].get("application_evidence_digest_hex") != digest.hex()
        or evidence["callback_context_id_hex"] != evidence["origin_transaction_id_hex"]
        or evidence["callback_context_authority"] != "foundation_transaction_id"
        or evidence["publication_token_scope"] != "private_mfdt_handoff_dedupe_only"
        or evidence["expected"].get("handoff_may_advance") is not True
        or evidence["expected"].get("receipt_may_advance_after_handoff_full") is not True
        or evidence["expected"].get("disposition_fatal_recovery_may_advance") is not False
    ):
        fail("application evidence digest/handoff authority")
    mark_complete("MF-POS-APPLICATION-EVIDENCE-DIGEST-KAT", evidence, executed)


def validate_negatives(vectors: dict[str, dict[str, Any]], executed: set[str]) -> None:
    collision = vectors["MF-NEG-STORAGE-SIDECAR-COLLISION"]
    profile = vectors["MF-FSM-STORAGE-SIDECAR-PROFILE"]["storage_profile"]
    if (
        collision.get("authority") != profile
        or collision.get("cases")
        != [
            "caller_base_equals_derived_namespace",
            "different_base_same_derived_namespace_simulation",
            "binding_missing_with_foreign_rows",
            "binding_wrong_base_digest",
            "binding_wrong_full_base_bytes",
            "binding_wrong_crc32c",
            "foreign_key_present",
        ]
        or collision["expected"].get("existing_rows_overwritten") is not False
        or collision["expected"].get("foundation_scan_relaxed") is not False
        or collision["expected"].get("wire_or_apply") != 0
    ):
        fail("MFDT sidecar collision matrix")
    mark_complete(
        "MF-NEG-STORAGE-SIDECAR-COLLISION", collision, executed
    )

    # Per-ID semantic invariants beyond expected authority equality.
    stale = vectors["MF-NEG-STALE-GENERATION"]
    if stale["last_query_generation"] >= stale["offered_query_generation"]:
        fail("stale gen arithmetic")
    mark_complete("MF-NEG-STALE-GENERATION", stale, executed)

    v2 = vectors["MF-NEG-STALE-VERSION-SELECTED-2"]
    if (
        v2["base_selected_control_version"] != 2
        or v2["mfdt_admission_version"] != 0
        or v2["message_type"] != 0x36
    ):
        fail("MFN1 absent")
    mark_complete("MF-NEG-STALE-VERSION-SELECTED-2", v2, executed)

    mixed = vectors["MF-NEG-MIXED-VERSION-PEER"]
    if (
        mixed["base_selected_control_version"] != 2
        or mixed["mfn1_session_generation"] != 7
        or mixed["active_session_generation"] != 8
    ):
        fail("stale MFN1 session")
    mark_complete("MF-NEG-MIXED-VERSION-PEER", mixed, executed)

    rf = vectors["MF-NEG-RF-MAPPING-UNAVAILABLE"]
    if rf["carrier"] != "compact_rf_nrw1":
        fail("rf carrier")
    mark_complete("MF-NEG-RF-MAPPING-UNAVAILABLE", rf, executed)

    wifi = vectors["MF-NEG-WIFI-MAPPING-UNAVAILABLE"]
    if wifi["carrier"] != "wifi_nwb1":
        fail("wifi carrier")
    mark_complete("MF-NEG-WIFI-MAPPING-UNAVAILABLE", wifi, executed)

    nfl1 = vectors["MF-NEG-NFL1-CONTROL-FORBIDDEN"]
    if nfl1["carrier"] != "nfl1_application_packet":
        fail("nfl1 carrier")
    mark_complete("MF-NEG-NFL1-CONTROL-FORBIDDEN", nfl1, executed)

    dup = vectors["MF-NEG-DUPLICATE-CHUNK-CONFLICT"]
    first = hx(dup["first_offer_hex"], "dup.first")
    second = hx(dup["second_offer_hex"], "dup.second")
    if first[64:96] == second[64:96]:
        fail("dup same digest")
    if sha(second[96:]) != second[64:96]:
        fail("dup unrepaired digest (must be integrity-repaired)")
    if first[96:] == second[96:]:
        fail("dup same payload")
    mark_complete("MF-NEG-DUPLICATE-CHUNK-CONFLICT", dup, executed)

    reorder = vectors["MF-NEG-REORDER-GAP"]
    if reorder["expected"]["bitmap_after"] != 0b10:
        fail("reorder bitmap")
    if reorder["expected"]["gap_does_not_imply_complete"] is not True:
        fail("reorder complete")
    mark_complete("MF-NEG-REORDER-GAP", reorder, executed)

    dig = vectors["MF-NEG-DIGEST-CORRUPTION-REPAIRED"]
    claimed = hx(dig["claimed_whole_hex"], "claimed")
    actual = hx(dig["actual_whole_hex"], "actual")
    content = hx(dig["content_hex"], "content")
    open_body = hx(dig["open_body_hex"], "open")
    if claimed == actual:
        fail("claimed==actual")
    if sha(content) != actual:
        fail("actual whole")
    if open_body[32:64] != claimed:
        fail("open claimed")
    # Semantic negative: claimed whole mismatches bytes, but OPEN digest field is
    # integrity-repaired to the corrupted head (valid structural digest).
    head = open_body[0:202]
    binding = open_body[234:462]
    text = open_body[462:]
    # entries not embedded; gate trusts repaired digest pin in expected after checking field equals pin
    if open_body[202:234].hex() != dig["expected"]["manifest_digest_hex"]:
        fail("repaired md")
    if open_body[202:234] == bytes(32):
        fail("zero digest forbidden")
    mark_complete("MF-NEG-DIGEST-CORRUPTION-REPAIRED", dig, executed)

    whole_m = vectors["MF-NEG-WHOLE-DIGEST-MISMATCH"]
    finalize = hx(whole_m["finalize_hex"], "finalize")
    if len(finalize) != 92:
        fail("finalize len")
    if finalize[52:84].hex() == whole_m["expected_whole_hex"]:
        fail("finalize whole not mismatched")
    if finalize[52:84].hex() == "00" * 32:
        fail("finalize whole zero")
    mark_complete("MF-NEG-WHOLE-DIGEST-MISMATCH", whole_m, executed)

    exp_eq = vectors["MF-NEG-EXPIRY-BOUNDARY-EQ"]
    if exp_eq["now_ms"] != exp_eq["reservation_not_after_ms"] or not exp_eq["same_epoch"]:
        fail("expiry eq")
    matrix = exp_eq.get("reservation_deadline_matrix")
    if not isinstance(matrix, list) or len(matrix) != 7:
        fail("deadline checked matrix")
    by_case = {row.get("case"): row for row in matrix if isinstance(row, dict)}
    if (
        by_case.get("no_deadline", {}).get("not_after_ms") != 301000
        or by_case.get("no_deadline", {}).get("deadline_ms_u64_hex")
        != "ffffffffffffffff"
    ):
        fail("deadline no-deadline bound")
    if by_case.get("same_epoch_before_now", {}).get("state_mutation") != 0:
        fail("deadline before mutation")
    if by_case.get("same_epoch_equal_now", {}).get("status") != "REJECT":
        fail("deadline equal")
    if by_case.get("same_epoch_earlier_bound", {}).get("not_after_ms") != 2000:
        fail("deadline earlier min")
    if by_case.get("same_epoch_later_bound", {}).get("not_after_ms") != 301000:
        fail("deadline later min")
    if (
        by_case.get("different_epoch_without_projection", {})
        .get("numeric_compare_performed") is not False
    ):
        fail("deadline cross-epoch direct compare")
    overflow = by_case.get("reservation_add_overflow", {})
    if (
        overflow.get("status") != "REJECT"
        or overflow.get("state_mutation") != 0
        or overflow.get("deadline_ms_u64_hex") != "ffffffffffffffff"
    ):
        fail("deadline overflow")
    mark_complete("MF-NEG-EXPIRY-BOUNDARY-EQ", exp_eq, executed)

    exp_b = vectors["MF-NEG-EXPIRY-BOUNDARY-BEFORE"]
    if exp_b["now_ms"] >= exp_b["reservation_not_after_ms"]:
        fail("expiry before")
    mark_complete("MF-NEG-EXPIRY-BOUNDARY-BEFORE", exp_b, executed)

    ab = vectors["MF-NEG-ABORT-AFTER-CONTENT-VERIFIED"]
    if ab["receiver_state"] != 36:
        fail("abort after state")
    mark_complete("MF-NEG-ABORT-AFTER-CONTENT-VERIFIED", ab, executed)

    race_f = vectors["MF-NEG-ABORT-RACE-FINALIZE-FIRST"]
    if race_f["first_full"] != "FINALIZE_ACCEPT":
        fail("race finalize first")
    mark_complete("MF-NEG-ABORT-RACE-FINALIZE-FIRST", race_f, executed)

    race_a = vectors["MF-NEG-ABORT-RACE-ABORT-FIRST"]
    nm30 = hx(race_a["nm30_hex"], "abort.nm30")
    require_valid_nm30_crc(nm30, "abort.nm30")
    if sha(nm30).hex() != race_a["expected"]["tombstone_digest_hex"]:
        fail("abort tomb")
    ack = hx(race_a["abort_ack_hex"], "abort.ack")
    if ack[60:92] != sha(nm30):
        fail("abort ack digest integrity")
    mark_complete("MF-NEG-ABORT-RACE-ABORT-FIRST", race_a, executed)

    partial = vectors["MF-NEG-PARTIAL-APPLY-FORBIDDEN"]
    if partial["may_prepare"] is not False or partial["receiver_state"] != 35:
        fail("partial")
    mark_complete("MF-NEG-PARTIAL-APPLY-FORBIDDEN", partial, executed)

    false_c = vectors["MF-NEG-FALSE-CUSTODY-BITMAP"]
    if false_c["transfer_accept_received"] is not False:
        fail("false custody")
    mark_complete("MF-NEG-FALSE-CUSTODY-BITMAP", false_c, executed)

    keys = vectors["MF-NEG-RESOURCE-EXHAUSTION-KEYS"]
    if keys["namespace_keys_in_use"] + keys["mfdt_requires_keys"] <= keys["keys_hard_max"]:
        fail("keys arith")
    host_trace = keys.get("host_admission_trace")
    if not isinstance(host_trace, list) or len(host_trace) != 5:
        fail("Host admission trace")
    if [row.get("slot") for row in host_trace[:4]] != [0, 1, 2, 3]:
        fail("Host lowest-free slots")
    if (
        host_trace[4].get("status") != "REJECT_CAPACITY"
        or host_trace[4].get("state_mutation") != 0
    ):
        fail("Host fifth reject")
    if keys.get("host_restart_canonical_slot_transfer_ids") != sorted(
        keys.get("host_restart_input_transfer_ids", [])
    ):
        fail("Host restart canonical order")
    esp_trace = keys.get("esp_admission_trace")
    if (
        not isinstance(esp_trace, list)
        or len(esp_trace) != 2
        or esp_trace[0].get("status") != "ADMITTED"
        or esp_trace[1].get("status") != "REJECT_CAPACITY"
        or esp_trace[1].get("state_mutation") != 0
    ):
        fail("ESP one-slot admission")
    mark_complete("MF-NEG-RESOURCE-EXHAUSTION-KEYS", keys, executed)

    byts = vectors["MF-NEG-RESOURCE-EXHAUSTION-BYTES"]
    if (
        byts["namespace_logical_bytes_in_use"] + byts["mfdt_requires_bytes"]
        <= byts["bytes_hard_max"]
    ):
        fail("bytes arith")
    hb = byts.get("host_bounds")
    if not isinstance(hb, dict) or hb != {
        "slot_count": 4,
        "per_slot_workspace_bytes": 65536,
        "coordinator_bytes": 512,
        "aggregate_workspace_bytes": 280064,
        "active_group_logical_bytes": 50303,
        "terminal_group_logical_bytes": 15272,
        "four_active_committed_logical_bytes": 201212,
        "tracked_transfer_groups_max": 16,
        "committed_logical_bytes_hard_max": 384476,
        "serialized_full_staging_logical_bytes_max": 50303,
        "begin_final_union_logical_bytes_hard_max": 434779,
    }:
        fail("Host durable/RAM bounds")
    mark_complete("MF-NEG-RESOURCE-EXHAUSTION-BYTES", byts, executed)

    fair = vectors["MF-NEG-FAIRNESS-TWO-OUTSTANDING"]
    if fair["outstanding_unpaid_offers"] <= fair["expected"]["max_outstanding"]:
        fail("fairness")
    if fair.get("successful_selection_trace") != [0, 1, 2, 3, 0, 1, 2, 3]:
        fail("Host round-robin trace")
    if (
        fair.get("selected_slot_with_peer_a_blocked") != 1
        or fair.get("next_slot_after_selection") != 2
        or fair.get("restart_next_slot") != 0
    ):
        fail("Host peer backpressure/restart cursor")
    mark_complete("MF-NEG-FAIRNESS-TWO-OUTSTANDING", fair, executed)

    maxp = vectors["MF-NEG-MAX-CHUNKS-PLUS-ONE"]
    if maxp["claimed_total_length"] <= maxp["max_content"]:
        fail("max+1")
    mark_complete("MF-NEG-MAX-CHUNKS-PLUS-ONE", maxp, executed)

    doff = vectors["MF-NEG-DEFAULT-OFF-POLICY"]
    if (
        doff["local_policy"] != "OFF"
        or doff["base_selected_control_version"] != 2
        or doff["mfdt_admission_version"] != 2
    ):
        fail("default off")
    mark_complete("MF-NEG-DEFAULT-OFF-POLICY", doff, executed)

    legacy = vectors["MF-NEG-NM30-SCHEMA1-COLD-REPLAY-DENY"]
    legacy_nm30 = hx(legacy["legacy_nm30_value_hex"], "legacy NM30")
    require_valid_nm30_legacy_schema1(legacy_nm30, "legacy NM30")
    if (
        legacy["expected"]["schema"] != 1
        or legacy["expected"]["value_length"] != 164
        or legacy["expected"]["canonical_legacy_validation"] is not True
        or legacy["expected"]["accounting_allowed"] is not True
        or legacy["expected"]["retention_gc_allowed"] is not True
        or legacy["expected"]["replay_eligible"] is not False
        or legacy["expected"]["rebind_allowed"] is not False
        or legacy["expected"]["wire_response_count"] != 0
        or legacy["expected"]["transport_ok"] is not False
        or legacy["catalog_state"] != "replay_ineligible"
        or legacy["permitted_actions"] != ["charge_actual_row", "retention_gc"]
        or "infer_peer" not in legacy["forbidden_actions"]
        or "infer_role" not in legacy["forbidden_actions"]
        or "infer_cookie" not in legacy["forbidden_actions"]
    ):
        fail("legacy NM30 cold replay denial")
    mark_complete("MF-NEG-NM30-SCHEMA1-COLD-REPLAY-DENY", legacy, executed)

    bindv = vectors["MF-NEG-HOST-TERMINAL-BIND-MATRIX"]
    cases = bindv.get("cases")
    if not isinstance(cases, list) or len(cases) != 7:
        fail("terminal bind cases")
    results = {
        case.get("name"): case.get("result")
        for case in cases
        if isinstance(case, dict)
    }
    if results != {
        "exact_initial_rebind": "OK",
        "same_cookie_after_bind": "OK",
        "peer_mismatch": "ERR_STATE",
        "role_mismatch": "ERR_STATE",
        "generation_mismatch": "ERR_STATE",
        "zero_cookie": "ERR_STATE",
        "cookie_swap": "ERR_STATE",
    }:
        fail("terminal bind matrix results")
    auth = bindv.get("authority")
    if (
        not isinstance(auth, dict)
        or auth.get("owner_role") != 2
        or auth.get("nrc1_session_generation") != 1
        or auth.get("cookie_at_recovery") != 0
        or cases[0].get("peer_endpoint_id_hex") != auth.get("peer_endpoint_id_hex")
        or cases[0].get("owner_role") != auth.get("owner_role")
        or cases[0].get("session_generation")
        != auth.get("nrc1_session_generation")
        or cases[0].get("session_cookie_hex") == "0000000000000000"
        or cases[5].get("session_cookie_hex") != "0000000000000000"
        or cases[6].get("session_cookie_hex")
        == cases[0].get("session_cookie_hex")
        or bindv["expected"]["mismatch_wire_response_count"] != 0
        or bindv["expected"]["mismatch_state_mutation"] != 0
        or bindv["expected"]["mismatch_store_mutation"] != 0
        or bindv["expected"]["mismatch_outbox_mutation"] != 0
    ):
        fail("terminal bind exact authority")
    mark_complete("MF-NEG-HOST-TERMINAL-BIND-MATRIX", bindv, executed)

    fresh_busy = vectors["MF-NEG-HOST-FOUR-ACTIVE-FRESH-OPEN-BUSY"]
    fresh_open = hx(fresh_busy["fresh_open_body_hex"], "fresh capacity OPEN")
    busy_body = hx(fresh_busy["busy_body_hex"], "fresh capacity BUSY")
    if (
        len(fresh_open) < 234
        or fresh_open[0:16] == bytes(16)
        or u32(fresh_open, 16) == 0
        or fresh_open[202:234] == bytes(32)
        or len(busy_body) != 60
        or busy_body[0:16] != fresh_open[0:16]
        or busy_body[16:20] != fresh_open[16:20]
        or busy_body[20:52] != fresh_open[202:234]
        or u16(busy_body, 52) != 1
        or u16(busy_body, 54) != 0
        or u32(busy_body, 56) != 0
        or fresh_busy["expected"]["semantic_response_type"] != 0x3B
        or fresh_busy["expected"]["reject_code_sidecar"] != 5
        or fresh_busy["expected"]["cacheable"] is not False
        or fresh_busy["expected"]["full_count"] != 0
        or fresh_busy["expected"]["durable_state_mutation"] != 0
        or fresh_busy["expected"]["active_before"] != 4
        or fresh_busy["expected"]["active_after"] != 4
        or fresh_busy["expected"]["owned_control_outbox"] is not True
        or fresh_busy["expected"]["control_route"] != 0xFF
        or fresh_busy["expected"]["transport_status"] != "OK"
    ):
        fail("four-active fresh OPEN BUSY")
    mark_complete("MF-NEG-HOST-FOUR-ACTIVE-FRESH-OPEN-BUSY", fresh_busy, executed)

    backpressure = vectors["MF-NEG-HOST-CONTROL-OUTBOX-BACKPRESSURE"]
    first_owned = backpressure.get("first_owned_frame")
    blocked = backpressure.get("blocked_second_frame")
    if (
        not isinstance(first_owned, dict)
        or not isinstance(blocked, dict)
        or first_owned.get("route") != 0xFF
        or first_owned.get("message_type") != 0x3B
        or first_owned.get("body_hex") != fresh_busy["busy_body_hex"]
        or blocked.get("message_type") != 0x3A
        or blocked.get("result") != "ERR_BUSY"
        or backpressure["expected"]["status"] != "ERR_BUSY"
        or backpressure["expected"]["control_outbox_capacity_frames"] != 1
        or backpressure["expected"]["first_frame_retained_bit_exact"] is not True
        or backpressure["expected"]["second_frame_enqueued"] is not False
        or backpressure["expected"]["second_wire_response_count"] != 0
        or backpressure["expected"]["full_count"] != 0
        or backpressure["expected"]["state_mutation"] != 0
        or backpressure["expected"]["store_mutation"] != 0
        or backpressure["expected"]["catalog_mutation"] != 0
        or backpressure["expected"]["active_fairness_blocked"] is not False
    ):
        fail("Host control outbox backpressure")
    mark_complete("MF-NEG-HOST-CONTROL-OUTBOX-BACKPRESSURE", backpressure, executed)

    for pre_id, branch, code in (
        ("MF-NEG-PREADMISSION-POLICY-STATELESS", "preadmission_policy_stateless", 4),
        ("MF-NEG-PREADMISSION-DEADLINE-STATELESS", "preadmission_deadline_stateless", 7),
    ):
        pre = vectors[pre_id]
        open_body = hx(pre["fresh_open_body_hex"], f"{pre_id} OPEN")
        response = hx(pre["response_body_hex"], f"{pre_id} response")
        if (
            len(open_body) < 234
            or open_body[0:16] == bytes(16)
            or u32(open_body, 16) == 0
            or open_body[202:234] == bytes(32)
            or len(response) != 60
            or response[0:16] != open_body[0:16]
            or response[16:20] != open_body[16:20]
            or response[20:52] != open_body[202:234]
            or u16(response, 52) != 1
            or u16(response, 54) != code
            or u32(response, 56) != 0
            or pre["expected"]["status"] != "OK"
            or pre["expected"]["branch"] != branch
            or pre["expected"]["semantic_response_type"] != 0x3A
            or pre["expected"]["reject_code"] != code
            or pre["expected"]["cacheable"] is not False
            or pre["expected"]["full_count"] != 0
            or pre["expected"]["durable_rows_created"] != 0
            or pre["expected"]["durable_state_mutation"] != 0
            or pre["expected"]["owned_control_outbox"] is not True
            or pre["expected"]["control_route"] != 0xFF
            or pre["expected"]["transport_status"] != "OK"
            or pre["expected"]["late_duplicate_may_be_reevaluated"] is not True
            or pre["expected"]["retry_requires_fresh_nonzero_request_id"] is not True
            or pre["g_r_open_started"] is not False
        ):
            fail(f"{pre_id}: stateless carve-out")
        mark_complete(pre_id, pre, executed)

    active_reject = vectors["MF-NEG-ACTIVE-SEMANTIC-REJECT-CACHED"]
    active_request = hx(active_reject["request_body_hex"], "active semantic request")
    active_response = hx(active_reject["response_body_hex"], "active semantic response")
    active_slot = hx(active_reject["nrc1_slot_hex"], "active semantic NRC1 slot")
    request_preimage = (
        bytes([active_reject["request_type"]])
        + len(active_request).to_bytes(2, "big")
        + active_request
    )
    if (
        len(active_response) != 60
        or u16(active_response, 52) != 5
        or u16(active_response, 54) != 8
        or len(active_slot) != 208
        or u64(active_slot, 0) != active_reject["request_id"]
        or u32(active_slot, 8) != 1
        or active_slot[12:44] != sha(request_preimage)
        or u16(active_slot, 44) != 0x3A
        or u16(active_slot, 46) != 60
        or active_slot[48:108] != active_response
        or active_slot[108:] != bytes(100)
        or active_reject["expected"]["status"] != "OK"
        or active_reject["expected"]["active_group_present"] is not True
        or active_reject["expected"]["cacheable"] is not True
        or active_reject["expected"]["nrc1_miss"] is not True
        or active_reject["expected"]["nrc1_full_count"] != 1
        or active_reject["expected"]["transfer_state_mutation"] != 0
        or active_reject["expected"]["durable_cache_mutation"] != 1
        or active_reject["expected"]["wire_after_full_only"] is not True
        or active_reject["expected"]["owned_active_slot_outbox"] is not True
        or active_reject["expected"]["uses_control_outbox"] is not False
        or active_reject["expected"]["transport_status"] != "OK"
    ):
        fail("active semantic reject NRC1 cache")
    mark_complete("MF-NEG-ACTIVE-SEMANTIC-REJECT-CACHED", active_reject, executed)

    rqc = vectors["MF-NEG-REQID-BODY-CONFLICT"]
    if rqc["first_request_body_digest_hex"] == rqc["second_request_body_digest_hex"]:
        fail("reqid body digests equal")
    if rqc["expected"]["state_mutation"] != 0:
        fail("reqid conflict mutation")
    mark_complete("MF-NEG-REQID-BODY-CONFLICT", rqc, executed)

    fullc = vectors["MF-NEG-REQID-CACHE-FULL"]
    if fullc["occupied_count"] != 72:
        fail("cache full occupied")
    if fullc["expected"]["slot_count"] != 72:
        fail("cache full slots")
    if fullc["expected"]["no_silent_eviction"] is not True:
        fail("cache full eviction")
    if len(fullc["nrc1_value_hex"]) != 15020 * 2:
        fail("cache full value hex")
    require_valid_nrc1_semantics(
        hx(fullc["nrc1_value_hex"], "full NRC1"), "full NRC1"
    )
    mark_complete("MF-NEG-REQID-CACHE-FULL", fullc, executed)

    odig = vectors["MF-NEG-REQID-DIGEST-OPEN-PREIMAGE"]
    if odig["message_type"] != 0x36:
        fail("open digest type")
    if odig["expected"]["includes_bind52_strip"] is not False:
        fail("open digest bind52 strip forbidden")
    if odig["expected"]["preimage"] != "type_u8||len_u16be||full_open_body":
        fail("open digest preimage label")
    open_body = hx(odig["open_body_hex"], "open dig body")
    pre = hx(odig["open_preimage_hex"], "open preimage")
    expected_pre = bytes([0x36]) + len(open_body).to_bytes(2, "big") + open_body
    if pre != expected_pre:
        fail("open preimage bytes")
    if sha(pre).hex() != odig["request_body_digest_hex"]:
        fail("open digest recomputed")
    if odig["request_body_digest_hex"] == odig["wrong_bind52_strip_digest_hex"]:
        fail("open dig bind52-wrong collides")
    if odig["expected"]["bind52_strip_digest_differs"] is not True:
        fail("open dig differs flag")
    mark_complete("MF-NEG-REQID-DIGEST-OPEN-PREIMAGE", odig, executed)

    postret = vectors["MF-NEG-REQID-POST-RETENTION-EXPIRED"]
    if postret["expected"]["reason"] != "transfer_expired":
        fail("postret reason")
    if postret["expected"]["reject_code"] != 7:  # EXPIRED
        fail("postret code")
    if postret["expected"]["nrc1_present"] is not False or postret["expected"]["nm30_present"] is not False:
        fail("postret absent")
    if postret["expected"]["bit_exact_replay_forbidden"] is not True:
        fail("postret no replay")
    if postret["expected"]["state_mutation"] != 0:
        fail("postret mutation")
    mark_complete("MF-NEG-REQID-POST-RETENTION-EXPIRED", postret, executed)

    epoch = vectors["MF-NEG-EPOCH-CHANGE-MID-TRANSFER"]
    if epoch["epoch_before_hex"] == epoch["epoch_after_hex"]:
        fail("epoch same")
    if epoch["expected"]["prepare_forbidden"] is not True:
        fail("epoch prepare")
    if epoch["expected"]["publication_after"] != "NONE":
        fail("epoch pub")
    mark_complete("MF-NEG-EPOCH-CHANGE-MID-TRANSFER", epoch, executed)


def classify_commit_unknown(
    old_rows: list[dict[str, str]],
    new_rows: list[dict[str, str]],
    observed_rows: list[dict[str, str]],
) -> str:
    """ADR-0021 COMMIT_UNKNOWN classify including ABSENT/BOTH/MISSING_NEW."""

    old_map = {r["key_hex"]: r["value_hex"] for r in old_rows}
    new_map = {r["key_hex"]: r["value_hex"] for r in new_rows}
    obs_map = {r["key_hex"]: r["value_hex"] for r in observed_rows}
    old_keys = set(old_map)
    new_keys = set(new_map)
    obs_keys = set(obs_map)
    expected_keys = old_keys | new_keys
    if not observed_rows:
        return "ABSENT"
    if obs_keys - expected_keys:
        return "EXTRA"
    # Terminal multi-key groups: disjoint old/new keys (active erase + NM30 put).
    # Require both sides non-empty so first-insert NEW (old empty) is not BOTH.
    if old_keys and new_keys and old_keys != new_keys and obs_keys == expected_keys:
        return "BOTH"
    for key, value in obs_map.items():
        if key in new_map and value == new_map[key]:
            continue
        if key in old_map and value == old_map[key]:
            continue
        if key in new_map and len(bytes.fromhex(value)) < len(bytes.fromhex(new_map[key])):
            return "PARTIAL"
        if key in old_map and len(bytes.fromhex(value)) < len(bytes.fromhex(old_map[key])):
            return "PARTIAL"
        return "THIRD"
    # When old==new==obs (non-empty): durable success already present → OLD replay.
    # NEW is only first insert (old empty, obs==new).
    if obs_map == new_map and obs_map == old_map and old_map:
        return "OLD"
    if obs_map == new_map and not old_map:
        return "NEW"
    if obs_map == new_map and old_map and obs_map != old_map:
        return "NEW"
    if obs_map == old_map:
        # Terminal: only active remains / new NM30 marker missing → OLD retry path.
        return "OLD"
    return "THIRD"


def validate_commit_unknown(vectors: dict[str, dict[str, Any]], executed: set[str]) -> None:
    ids = [vid for vid in REQUIRED_VECTOR_IDS if vid.startswith("MF-CU-")]
    for vid in ids:
        entry = vectors[vid]
        classification = classify_commit_unknown(
            entry["old_rows"], entry["new_rows"], entry["observed_rows"]
        )
        if entry["expected"]["classification"] != classification:
            fail(f"{vid}: class {classification}")
        if entry["expected"].get("wire_success", 0) != 0:
            fail(f"{vid}: wire")
        if vid.startswith("MF-CU-STORAGE-BINDING-"):
            profile = vectors[
                "MF-FSM-STORAGE-SIDECAR-PROFILE"
            ]["storage_profile"]
            binding_key = profile["binding_key_hex"]
            binding_value = profile["binding_value_hex"]
            if (
                entry.get("group") != "MFDT_NAMESPACE_BINDING_BOOTSTRAP"
                or entry.get("old_rows") != []
                or entry["expected"].get("foundation_mutation") != 0
            ):
                fail(f"{vid}: binding CU shape")
            if classification == "NEW":
                if entry["observed_rows"] != [
                    {"key_hex": binding_key, "value_hex": binding_value}
                ]:
                    fail(f"{vid}: binding NEW")
            elif classification == "ABSENT":
                if entry["observed_rows"] != []:
                    fail(f"{vid}: binding ABSENT")
            elif classification == "PARTIAL":
                if (
                    len(entry["observed_rows"]) != 1
                    or entry["observed_rows"][0]["key_hex"] != binding_key
                    or len(entry["observed_rows"][0]["value_hex"])
                    >= len(binding_value)
                ):
                    fail(f"{vid}: binding PARTIAL")
            elif classification == "EXTRA":
                if (
                    len(entry["observed_rows"]) != 2
                    or entry["observed_rows"][0]
                    != {"key_hex": binding_key, "value_hex": binding_value}
                ):
                    fail(f"{vid}: binding EXTRA")
            elif classification == "THIRD":
                if (
                    len(entry["observed_rows"]) != 1
                    or entry["observed_rows"][0]["key_hex"] != binding_key
                    or entry["observed_rows"][0]["value_hex"] == binding_value
                ):
                    fail(f"{vid}: binding THIRD")
        if vid == "MF-CU-NRC1-NEW":
            expected = entry["expected"]
            for field in (
                "target_same_id_retry",
                "target_cold_restart_retry",
                "target_active_plus_nrc1_replay",
                "target_nrc1_only_replay",
            ):
                if expected.get(field) != "COMMIT_UNKNOWN":
                    fail(f"{vid}: {field}")
            if expected.get("host_full_capable_replay") != "OK":
                fail(f"{vid}: host replay")
            if expected.get("attestation_magic_only_accepted") is not False:
                fail(f"{vid}: magic-only attestation")
        if entry["expected"].get("send_or_accept", 0) not in (0, None) and entry[
            "expected"
        ].get("send_or_accept", 0) != 0:
            # optional field; when present must be 0 for CU
            if "send_or_accept" in entry["expected"] and entry["expected"]["send_or_accept"] != 0:
                fail(f"{vid}: send")
        auth_class = AUTHORITY[vid]["expected"]["classification"]
        if classification != auth_class:
            fail(f"{vid}: auth class")
        for row in entry["observed_rows"]:
            key = hx(row["key_hex"], f"{vid}.key")
            value = hx(row["value_hex"], f"{vid}.obs")
            if len(key) != 20:
                fail(f"{vid}: key len")
            if classification == "PARTIAL":
                # short value permitted; must not claim full valid CRC path
                if len(value) >= HEADER_BYTES + 4 and value[0:4] in (b"NM3R", b"NM3S"):
                    # if full-length, CRC must still be valid
                    if len(value) == int.from_bytes(value[8:12], "big") if len(value) >= 12 else False:
                        require_valid_record_crc(value, f"{vid}.partial-full")
                continue
            if classification in ("OLD", "NEW", "THIRD", "EXTRA"):
                if len(value) >= HEADER_BYTES + 4 and value[0:4] in (b"NM3R", b"NM3S"):
                    require_valid_record_crc(value, f"{vid}.rec")
                    if classification == "THIRD":
                        try:
                            require_valid_active_semantics(value, f"{vid}.semantic-mutant")
                        except GateError:
                            pass
                        else:
                            fail(f"{vid}: repaired-CRC active semantic mutant accepted")
                    else:
                        require_valid_active_semantics(value, f"{vid}.rec")
                if len(value) == NM30_BYTES and value[0:4] == b"NM30":
                    if classification == "THIRD":
                        try:
                            require_valid_nm30_semantics(value, f"{vid}.semantic-mutant")
                        except GateError:
                            pass
                        else:
                            fail(f"{vid}: repaired-CRC NM30 semantic mutant accepted")
                    else:
                        require_valid_nm30_semantics(value, f"{vid}.nm30")
                if len(value) == 15020 and value[0:4] == b"NRC1":
                    if classification == "THIRD":
                        try:
                            require_valid_nrc1_semantics(
                                value,
                                f"{vid}.semantic-mutant",
                                expected_transfer_id=key[4:20],
                            )
                        except GateError:
                            pass
                        else:
                            fail(f"{vid}: repaired-CRC NRC1 semantic mutant accepted")
                    elif classification == "EXTRA" and key[4:20] != value[8:24]:
                        # The deliberately extra/misbound row is itself a semantic fence.
                        try:
                            require_valid_nrc1_semantics(
                                value, f"{vid}.extra-nrc1", expected_transfer_id=key[4:20]
                            )
                        except GateError:
                            pass
                        else:
                            fail(f"{vid}: misbound extra NRC1 accepted")
                    else:
                        require_valid_nrc1_semantics(
                            value, f"{vid}.nrc1", expected_transfer_id=key[4:20]
                        )
        mark_complete(vid, entry, executed)


def validate_transcripts(vectors: dict[str, dict[str, Any]], executed: set[str]) -> None:
    cross = vectors["MF-TX-CROSS-NAMESPACE-ADMISSION-MATRIX"]
    cross_expected = {
        "status": "OK",
        "branch": "canonical_roster_target_attempt_prearm_foundation_full_reconcile",
        "target_count_min": 1,
        "target_count_max": 4,
        "runtime_uniqueness_scope": "MFDT_V1_ONLY",
        "target_runtime_unique_within_origin": True,
        "same_runtime_different_application_instance_rejected": True,
        "duplicate_runtime_api_status": "NINLIL_OK",
        "duplicate_runtime_submission_state": "REJECTED",
        "duplicate_runtime_reason": "TARGET_COUNT_UNSUPPORTED",
        "duplicate_runtime_entropy_draws": 0,
        "duplicate_runtime_sidecar_mutations": 0,
        "duplicate_runtime_foundation_mutations": 0,
        "compound_receiver_key_created": False,
        "nts3_target_local_suffix_rule_changed": False,
        "attempt_draw_order": "canonical_target_order",
        "attempt_draws_max_per_target": 4,
        "attempt_collision_set": (
            "durable_active_retained_plus_prior_same_admission_candidates"
        ),
        "attempt_candidate_nonzero": True,
        "attempt_candidate_bound_to_target_open": True,
        "attempt_consumed_claim_before_foundation_full": 0,
        "sidecar_prearm_before_foundation_full": True,
        "wire_txgate_callback_before_foundation_full": 0,
        "foundation_admission_full_count": 1,
        "foundation_admission_atomic_members": [
            "exact_target_roster",
            "per_target_attempt_index_and_binding",
            "attempt_budget_and_counters",
            "ATTEMPT_PREPARED_and_pending_state",
            "per_target_mfdt_transfer_id_and_origin_ordinal",
        ],
        "admission_execution_scope": "owner_thread_call",
        "restart_reconcile_before_bearer_open": True,
        "new_durable_state_added": False,
        "foundation_commit_unknown_deletes_sidecar": False,
        "blind_attempt_redraw_forbidden": True,
        "orphan_cleanup_before_wire_or_apply": True,
        "missing_sidecar_for_durable_mfdt": "CORRUPT_FENCE",
        "matching_both": "RESUME_ELIGIBLE",
        "wire_or_apply_before_match": 0,
    }
    cross_steps = [
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
    ]
    cross_matrix = [
        {
            "case": "four_unique_runtime_targets",
            "result": "ADMIT_AFTER_FOUNDATION_FULL",
            "attempt_draws": "ONE_TO_FOUR_EACH_CANONICAL_ORDER",
            "collision_set": "DURABLE_ACTIVE_RETAINED_PLUS_PRIOR_SAME_ADMISSION",
            "sidecar_arms_full": 4,
            "foundation_full_attempts": 1,
            "wire_txgate_callback_before_foundation_ok": 0,
        },
        {
            "case": "duplicate_runtime_same_application_instance",
            "api_status": "NINLIL_OK",
            "submission_state": "REJECTED",
            "reason": "TARGET_COUNT_UNSUPPORTED",
            "entropy_draws": 0,
            "sidecar_mutations": 0,
            "foundation_mutations": 0,
            "compound_receiver_key": False,
        },
        {
            "case": "duplicate_runtime_different_application_instance",
            "api_status": "NINLIL_OK",
            "submission_state": "REJECTED",
            "reason": "TARGET_COUNT_UNSUPPORTED",
            "entropy_draws": 0,
            "sidecar_mutations": 0,
            "foundation_mutations": 0,
            "compound_receiver_key": False,
        },
        {
            "case": "candidate_max4_exhausted_after_prior_arm",
            "result": "NINLIL_E_ENTROPY",
            "foundation_full_attempts": 0,
            "cleanup": "CREATED_ARMS_BOUNDED_FULL",
            "wire_txgate_callback": 0,
            "attempt_redraw_while_unresolved": 0,
        },
        {
            "case": "sidecar_arm_definite_failure",
            "foundation_full_attempts": 0,
            "cleanup": "CREATED_ARMS_BOUNDED_FULL",
            "wire_txgate_callback": 0,
        },
        {
            "case": "arm_or_cleanup_commit_unknown",
            "result": "FENCE_COLD_RECONCILE",
            "foundation_full_attempts": 0,
            "sidecar_delete_claim": False,
            "attempt_redraw": 0,
            "wire_txgate_callback": 0,
        },
        {
            "case": "foundation_full_definite_failure",
            "foundation_full_attempts": 1,
            "foundation_committed": False,
            "cleanup": "ALL_ARMS_BOUNDED_FULL",
            "wire_txgate_callback": 0,
        },
        {
            "case": "foundation_full_commit_unknown",
            "foundation_full_attempts": 1,
            "result": "KEEP_ARMS_FENCE_COLD_RECONCILE",
            "sidecar_delete_claim": False,
            "attempt_redraw": 0,
            "wire_txgate_callback": 0,
        },
        {
            "case": "restart_matching_foundation_and_arms",
            "result": "RESUME_SAME_ATTEMPTS",
            "reconcile_before": "BEARER_OPEN",
            "new_state": False,
            "attempt_redraw": 0,
        },
    ]
    if (
        cross.get("expected") != cross_expected
        or cross.get("steps") != cross_steps
        or cross.get("boundary_matrix") != cross_matrix
        or cross.get("observed_kinds")
        != ["NMS1", "NM3S", "NRC1", "FOUNDATION_TX"]
        or cross.get("note")
        != (
            "candidate-only; no cross-namespace atomic commit or "
            "production implementation claim"
        )
    ):
        fail("MFDT cross-namespace admission matrix")
    mark_complete(
        "MF-TX-CROSS-NAMESPACE-ADMISSION-MATRIX", cross, executed
    )

    cut1 = vectors["MF-TX-POWER-CUT-AFTER-CHUNK-FULL"]
    if "POWER_CUT" not in cut1["transcript"] or "RESUME_QUERY" not in cut1["transcript"]:
        fail("cut1 transcript")
    if cut1["expected"]["sender_release"] is not False:
        fail("cut1 release")
    mark_complete("MF-TX-POWER-CUT-AFTER-CHUNK-FULL", cut1, executed)

    cut2 = vectors["MF-TX-POWER-CUT-AFTER-CONTENT-VERIFIED"]
    if cut2["expected"]["publication_state"] != 1 or cut2["expected"]["accept_notified"] != 0:
        fail("cut2")
    mark_complete("MF-TX-POWER-CUT-AFTER-CONTENT-VERIFIED", cut2, executed)

    cut3 = vectors["MF-TX-POWER-CUT-DURING-TERMINAL"]
    if cut3["expected"]["group"] != "G_R_TERMINAL" or cut3["expected"]["classify"] is not True:
        fail("cut3")
    mark_complete("MF-TX-POWER-CUT-DURING-TERMINAL", cut3, executed)

    resume = vectors["MF-TX-RESUME-AFTER-RESTART"]
    body = hx(resume["resume_state_hex"], "resume")
    if len(body) != 108:
        fail("resume len")
    if body[76:108] != sha(b"NM3-RESUME-V1" + body[0:76]):
        fail("resume digest integrity")
    if resume["expected"]["state_digest_hex"] != body[76:108].hex():
        fail("resume pin")
    if resume["expected"]["sender_may_release"] is not False:
        fail("resume release")
    mark_complete("MF-TX-RESUME-AFTER-RESTART", resume, executed)

    gc = vectors["MF-TX-CLEANUP-RETENTION-GC"]
    matrix = gc.get("boundary_matrix")
    if not isinstance(matrix, list) or len(matrix) != 4:
        fail("gc boundary matrix")
    gc_cases = {row.get("case"): row for row in matrix if isinstance(row, dict)}
    if gc_cases.get("before", {}).get("delete") is not False:
        fail("gc before boundary")
    if gc_cases.get("equal", {}).get("delete") is not True:
        fail("gc equal boundary")
    if gc_cases.get("after", {}).get("delete") is not True:
        fail("gc after boundary")
    if gc_cases.get("epoch_mismatch", {}).get("delete") is not False:
        fail("gc epoch mismatch")
    if gc.get("retention_boundary_ms") != (
        gc.get("retention_anchor_ms", 0) + gc.get("retention_duration_ms", 0)
    ):
        fail("gc checked boundary arithmetic")
    if gc["expected"]["active_eviction_forbidden"] is not True:
        fail("gc eviction")
    if gc["expected"].get("nrc1_deleted_with_nm30") is not True:
        fail("gc nrc1 with nm30")
    if gc.get("nrc1_present_before") is not True or gc.get("nrc1_present_after") is not False:
        fail("gc nrc1 presence")
    mark_complete("MF-TX-CLEANUP-RETENTION-GC", gc, executed)

    exp_tomb = vectors["MF-TX-EXPIRY-MANDATORY-TOMBSTONE"]
    if exp_tomb["expected"]["mandatory_full"] != "G_R_EXPIRY":
        fail("expiry full")
    if exp_tomb["expected"]["active_slot_freed"] is not True:
        fail("expiry free")
    if exp_tomb["expected"]["nrc1_retained_until_gc"] is not True:
        fail("expiry nrc1")
    if exp_tomb["expected"]["reject_code"] != 7:
        fail("expiry code")
    expiry_nm30 = hx(exp_tomb["nm30_value_hex"], "expiry NM30")
    require_valid_nm30_semantics(expiry_nm30, "expiry NM30")
    if (
        u16(expiry_nm30, 60) != 2
        or u16(expiry_nm30, 62) != 5
        or u32(expiry_nm30, 64) != 0
        or expiry_nm30[116:132] != bytes(16)
    ):
        fail("expiry terminal-only reason semantics")
    if sha(expiry_nm30).hex() != exp_tomb["tombstone_digest_hex"]:
        fail("expiry tombstone digest")
    terminal_catalog = exp_tomb.get("terminal_catalog")
    if not isinstance(terminal_catalog, list) or len(terminal_catalog) != 8:
        fail("NM30 terminal catalog")
    classes = []
    for row in terminal_catalog:
        if not isinstance(row, dict):
            fail("NM30 terminal catalog row")
        require_valid_nm30_semantics(
            hx(row.get("nm30_hex"), f"terminal {row.get('class')}"),
            f"terminal {row.get('class')}",
        )
        classes.append(row.get("class"))
    if classes != [
        "COMPLETE",
        "ABORTED_OPERATOR",
        "ABORTED_SUPERSEDED",
        "ABORTED_DEADLINE",
        "ABORTED_POLICY",
        "ABORTED_EXPIRED",
        "CORRUPT_STORE_CORRUPT",
        "CORRUPT_EPOCH_CHANGED",
    ]:
        fail("NM30 terminal catalog class order")
    mark_complete("MF-TX-EXPIRY-MANDATORY-TOMBSTONE", exp_tomb, executed)

    exp_reuse = vectors["MF-POS-EXPIRY-SLOT-REUSE"]
    if exp_reuse["expected"]["active_count_after_expiry"] != 0:
        fail("reuse active")
    if exp_reuse["expected"]["new_transfer_open_admitted"] is not True:
        fail("reuse open")
    mark_complete("MF-POS-EXPIRY-SLOT-REUSE", exp_reuse, executed)

    rb = vectors["MF-TX-ROLLBACK-POLICY-OFF"]
    if rb["steps"][0] != "policy_off":
        fail("rollback steps")
    if rb["expected"]["in_place_v3_to_v2_conversion"] is not False:
        fail("rollback convert")
    mark_complete("MF-TX-ROLLBACK-POLICY-OFF", rb, executed)

    tca = vectors["MF-TX-TERMINAL-CRASH-ACTIVE-ONLY"]
    if tca["expected"]["classification"] != "OLD":
        fail("term crash active class")
    if tca["observed_kinds"] != ["NM3R"]:
        fail("term crash active kinds")
    mark_complete("MF-TX-TERMINAL-CRASH-ACTIVE-ONLY", tca, executed)

    tcn = vectors["MF-TX-TERMINAL-CRASH-NM30-ONLY"]
    if tcn["expected"]["classification"] != "NEW":
        fail("term crash nm30 class")
    if tcn["observed_kinds"] != ["NM30"]:
        fail("term crash nm30 kinds")
    mark_complete("MF-TX-TERMINAL-CRASH-NM30-ONLY", tcn, executed)

    cold = vectors["MF-TX-HOST-TERMINAL-COLD-REBIND-HIT"]
    cold_nm30 = hx(cold["nm30_value_hex"], "cold terminal NM30")
    cold_nrc1 = hx(cold["nrc1_value_hex"], "cold terminal NRC1")
    require_valid_nm30_semantics(cold_nm30, "cold terminal NM30")
    require_valid_nrc1_semantics(cold_nrc1, "cold terminal NRC1")
    catalog = cold.get("recovered_catalog_entry")
    rebind = cold.get("rebind")
    hit = cold.get("hit")
    miss = cold.get("post_terminal_miss")
    if not all(isinstance(v, dict) for v in (catalog, rebind, hit, miss)):
        fail("cold terminal nested authority")
    assert isinstance(catalog, dict)
    assert isinstance(rebind, dict)
    assert isinstance(hit, dict)
    assert isinstance(miss, dict)
    hit_slot = None
    for index in range(72):
        slot = cold_nrc1[40 + index * 208 : 40 + (index + 1) * 208]
        if u64(slot, 0) == hit.get("request_id"):
            hit_slot = slot
            break
    miss_slot = hx(miss.get("nrc1_slot_hex"), "post-terminal miss NRC1 slot")
    miss_request = hx(miss.get("request_body_hex"), "post-terminal miss request")
    miss_response = hx(miss.get("response_body_hex"), "post-terminal miss response")
    miss_preimage = (
        bytes([miss.get("request_type")])
        + len(miss_request).to_bytes(2, "big")
        + miss_request
    )
    if (
        catalog.get("transfer_id_hex") != cold_nm30[8:24].hex()
        or catalog.get("peer_endpoint_id_hex") != cold_nm30[156:172].hex()
        or catalog.get("owner_role") != cold_nm30[172]
        or catalog.get("nrc1_session_generation") != u32(cold_nrc1, 24)
        or catalog.get("nm30_schema") != 2
        or catalog.get("replay_eligible") is not True
        or catalog.get("session_cookie") != 0
        or catalog.get("bind_valid") is not False
        or rebind.get("peer_endpoint_id_hex") != catalog.get("peer_endpoint_id_hex")
        or rebind.get("owner_role") != catalog.get("owner_role")
        or rebind.get("session_generation")
        != catalog.get("nrc1_session_generation")
        or rebind.get("session_cookie_hex") == "0000000000000000"
        or rebind.get("result") != "OK"
        or hit_slot is None
        or hit_slot[12:44].hex() != hit.get("request_body_digest_hex")
        or u16(hit_slot, 44) != hit.get("response_type")
        or u16(hit_slot, 46) != len(hx(hit.get("response_body_hex"), "cold hit body"))
        or hit_slot[48 : 48 + u16(hit_slot, 46)].hex() != hit.get("response_body_hex")
        or len(miss_slot) != 208
        or u64(miss_slot, 0) != miss.get("request_id")
        or u32(miss_slot, 8) != u32(cold_nrc1, 24)
        or miss_slot[12:44] != sha(miss_preimage)
        or u16(miss_slot, 44) != 0x3A
        or u16(miss_slot, 46) != len(miss_response)
        or miss_slot[48 : 48 + len(miss_response)] != miss_response
        or u16(miss_response, 54) != 8
        or miss.get("full_group") != "G_R_REQID_CACHE"
        or miss.get("wire_after_full_only") is not True
        or cold["expected"]["control_route"] != 0xFF
        or cold["expected"]["active_slots_consumed"] != 0
        or cold["expected"]["cookie_restored_from_storage"] is not False
        or cold["expected"]["nrc1_generation_offset"] != 24
        or cold["expected"]["cacheable"] is not True
        or cold["expected"]["nrc1_hit"] is not True
        or cold["expected"]["full_count"] != 0
        or cold["expected"]["transfer_state_mutation"] != 0
        or cold["expected"]["response_bit_exact"] is not True
        or cold["expected"]["owned_control_outbox"] is not True
        or cold["expected"]["transport_status"] != "OK"
        or cold["expected"]["post_terminal_miss_cacheable"] is not True
        or cold["expected"]["post_terminal_miss_full_count"] != 1
        or cold["expected"]["post_terminal_miss_transfer_state_mutation"] != 0
    ):
        fail("Host terminal cold rebind/hit/miss")
    mark_complete("MF-TX-HOST-TERMINAL-COLD-REBIND-HIT", cold, executed)

    ep = vectors["MF-TX-EPOCH-CHANGE-TERMINAL"]
    if ep["expected"]["nm30_terminal_state"] != 3:
        fail("epoch term state")
    if ep["expected"]["nm30_terminal_reason"] != 0x8002:
        fail("epoch term reason")
    if ep["expected"]["active_erased"] is not True:
        fail("epoch active erased")
    mark_complete("MF-TX-EPOCH-CHANGE-TERMINAL", ep, executed)

    rst = vectors["MF-TX-REQID-CACHE-CRASH-RESTART"]
    if rst["first_page_accept_hex"] != rst["post_restart_page_accept_hex"]:
        fail("nrc1 restart body")
    if rst["expected"]["re_evaluation_forbidden"] is not True:
        fail("nrc1 restart reeval")
    require_valid_nrc1_semantics(
        hx(rst["nrc1_value_hex"], "restart NRC1"), "restart NRC1"
    )
    mark_complete("MF-TX-REQID-CACHE-CRASH-RESTART", rst, executed)

    trst = vectors["MF-TX-REQID-TERMINAL-RESTART-LATE-DUP"]
    if trst["expected"]["nrc1_retained_with_nm30"] is not True:
        fail("term restart retain")
    if trst["first_page_accept_hex"] != trst["post_restart_page_accept_hex"]:
        fail("term restart body")
    if trst["expected"]["re_evaluation_forbidden"] is not True:
        fail("term restart reeval")
    if trst["expected"]["state_mutation_on_hit"] != 0:
        fail("term restart mutation")
    if len(trst["nrc1_value_hex"]) != 15020 * 2:
        fail("term restart nrc1")
    if len(trst["nm30_value_hex"]) != 180 * 2:
        fail("term restart nm30")
    require_valid_nrc1_semantics(
        hx(trst["nrc1_value_hex"], "terminal restart NRC1"),
        "terminal restart NRC1",
    )
    require_valid_nm30_semantics(
        hx(trst["nm30_value_hex"], "terminal restart NM30"),
        "terminal restart NM30",
    )
    mark_complete("MF-TX-REQID-TERMINAL-RESTART-LATE-DUP", trst, executed)


def validate_meta(vectors: dict[str, dict[str, Any]], executed: set[str]) -> None:
    inv = vectors["MF-INV-REQUIRED-IDS-INTEGRITY"]
    if inv["required_vector_ids"] != list(REQUIRED_VECTOR_IDS):
        fail("inv list")
    if inv["expected"]["required_count"] != len(REQUIRED_VECTOR_IDS) or inv["expected"]["duplicate_count"] != 0:
        fail("inv expected")
    mark_complete("MF-INV-REQUIRED-IDS-INTEGRITY", inv, executed)

    pin = vectors["MF-GATE-SELF-TEST-PIN"]
    for key in (
        "gate_must_reject_missing_id",
        "gate_must_reject_extra_id",
        "gate_must_reject_duplicate_id",
        "gate_must_reject_substituted_id",
        "mutations_repair_digest",
    ):
        if pin["expected"].get(key) is not True:
            fail(f"pin {key}")
    mark_complete("MF-GATE-SELF-TEST-PIN", pin, executed)


def validate(document: dict[str, Any]) -> set[str]:
    executed: set[str] = set()
    try:
        validate_closed_schema(document)
        validate_document_shell(document)
        validate_inventory_structure(document)
        vectors = by_id(document)
        validate_constants(document, vectors, executed)
        validate_catalog(document, vectors, executed)
        validate_budget(document, vectors, executed)
        validate_application_handoff_amendment(vectors, executed)
        validate_positives(vectors, executed)
        validate_negatives(vectors, executed)
        validate_commit_unknown(vectors, executed)
        validate_transcripts(vectors, executed)
        validate_meta(vectors, executed)
    except GateError:
        raise
    except (KeyError, TypeError, ValueError, IndexError, AttributeError) as error:
        fail(f"structural validation fault: {error}")

    if executed != set(REQUIRED_VECTOR_IDS):
        missing = set(REQUIRED_VECTOR_IDS) - executed
        extra = executed - set(REQUIRED_VECTOR_IDS)
        fail(f"executed mismatch missing={sorted(missing)} extra={sorted(extra)}")
    if len(executed) != len(REQUIRED_VECTOR_IDS):
        fail("executed count")
    return executed


def expect_fail(document: dict[str, Any], label: str) -> None:
    try:
        validate(document)
    except GateError:
        return
    raise SystemExit(f"self-test failed: {label} accepted")


def _replace_vector(document: dict[str, Any], vector_id: str, row: dict[str, Any]) -> None:
    for i, r in enumerate(document["vectors"]):
        if r["id"] == vector_id:
            document["vectors"][i] = row
            return
    fail(f"missing vector {vector_id}")


def self_test() -> None:
    raw = VECTOR.read_bytes()
    document = load_strict_json(raw)
    validate(document)
    if VECTOR.read_bytes() != raw:
        raise SystemExit("self-test failed: source vector mutated")

    # Inventory faults
    missing_doc = copy.deepcopy(document)
    missing_doc["vectors"] = [v for v in missing_doc["vectors"] if v["id"] != "MF-POS-ONE-BYTE"]
    missing_doc["required_vector_ids"] = [
        i for i in missing_doc["required_vector_ids"] if i != "MF-POS-ONE-BYTE"
    ]
    missing_doc["required_gate_cases"] = list(missing_doc["required_vector_ids"])
    expect_fail(missing_doc, "missing id")

    extra_doc = copy.deepcopy(document)
    clone = copy.deepcopy(extra_doc["vectors"][0])
    clone["id"] = "MF-EXTRA-SHOULD-FAIL"
    extra_doc["vectors"].append(clone)
    expect_fail(extra_doc, "extra id")

    dup_doc = copy.deepcopy(document)
    dup_doc["vectors"].append(copy.deepcopy(dup_doc["vectors"][0]))
    expect_fail(dup_doc, "duplicate id")

    rename_doc = copy.deepcopy(document)
    rename_doc["vectors"][10]["id"] = "MF-SUBSTITUTED"
    expect_fail(rename_doc, "renamed id")

    # Strict JSON permanent counterexamples: duplicate / escaped-key parity /
    # float / NaN / -0 / unsafe integer / bool-as-int fence.
    try:
        load_strict_json('{"a":1,"a":2}')
        raise SystemExit("self-test failed: duplicate key accepted")
    except GateError:
        pass
    try:
        # Decoded-key parity: status and \u0073tatus are the same key.
        load_strict_json('{"status":"OK","\\u0073tatus":"BAD"}')
        raise SystemExit("self-test failed: escaped-key duplicate accepted")
    except GateError:
        pass
    try:
        load_strict_json('{"selected_control_version": 3.0}')
        raise SystemExit("self-test failed: float 3.0 accepted")
    except GateError:
        pass
    try:
        load_strict_json('{"x": NaN}')
        raise SystemExit("self-test failed: NaN accepted")
    except GateError:
        pass
    try:
        load_strict_json('{"chunk_count": -0}')
        raise SystemExit("self-test failed: raw chunk_count -0 accepted")
    except GateError:
        pass
    try:
        load_strict_json('{"n": 9007199254740993}')
        raise SystemExit("self-test failed: unsafe integer accepted")
    except GateError:
        pass
    # Closed schema: top-level adr string→bool and unexpected top-level key.
    adr_doc = copy.deepcopy(document)
    adr_doc["adr"] = True
    expect_fail(adr_doc, "adr bool true")
    unexpected_doc = copy.deepcopy(document)
    unexpected_doc["unexpected_top_level"] = 1
    expect_fail(unexpected_doc, "unexpected_top_level")
    bool_chunk = copy.deepcopy(document)
    for v in bool_chunk["vectors"]:
        if v["id"] == "MF-POS-ONE-BYTE":
            v["fixture"]["facts"]["chunk_count"] = True
            break
    expect_fail(bool_chunk, "chunk_count bool true")

    # Metadata authority permanent counterexamples (hard pins; not vector-taught).
    meta = copy.deepcopy(document)
    meta["adr"] = "ADR-9999"
    expect_fail(meta, "adr=ADR-9999")
    meta = copy.deepcopy(document)
    meta["title"] = "UNRELATED AUTHORITY"
    expect_fail(meta, "title=UNRELATED AUTHORITY")
    meta = copy.deepcopy(document)
    meta["sources"] = ["docs/adr/does-not-exist-9999.md"]
    meta["source_sha256_hex"] = {"docs/adr/does-not-exist-9999.md": "00" * 32}
    expect_fail(meta, "nonexistent sources")
    meta = copy.deepcopy(document)
    meta["nonclaims"] = [
        "SPEC_ACCEPTED",
        "implementation",
        "HIL",
        "RELEASE_SUPPORTED",
    ]
    expect_fail(meta, "nonclaims only 4 items")
    meta = copy.deepcopy(document)
    meta["nonclaims"] = list(PINNED_NONCLAIMS) + ["EXTRA_NONCLAIM"]
    expect_fail(meta, "nonclaims extra")
    meta = copy.deepcopy(document)
    meta["nonclaims"] = list(reversed(PINNED_NONCLAIMS))
    expect_fail(meta, "nonclaims order donor")
    meta = copy.deepcopy(document)
    meta["sources"] = [PINNED_SOURCES[1], PINNED_SOURCES[0]]
    expect_fail(meta, "sources order donor")
    meta = copy.deepcopy(document)
    meta["source_sha256_hex"] = dict(meta["source_sha256_hex"])
    meta["source_sha256_hex"][PINNED_ADR_PATH] = "11" * 32
    expect_fail(meta, "source digest donor")
    # Decoded duplicate metadata key at JSON parse layer.
    try:
        load_strict_json('{"adr":"ADR-0021","\\u0061dr":"ADR-9999"}')
        raise SystemExit("self-test failed: decoded duplicate adr key accepted")
    except GateError:
        pass
    # Missing metadata key / wrong type.
    meta = copy.deepcopy(document)
    del meta["title"]
    expect_fail(meta, "missing title key")
    meta = copy.deepcopy(document)
    meta["nonclaims"] = "SPEC_ACCEPTED"
    expect_fail(meta, "nonclaims string type")

    vectors_by_id = {v["id"]: v for v in document["vectors"]}
    id_list = list(REQUIRED_VECTOR_IDS)

    def assert_donor_row_rejected(target_id: str, donor_id: str) -> None:
        """Exhaustive ID↔semantics donor: preserve target ID, substitute donor body.

        Uses authority fingerprint + expected binding (and positive fixture byte
        recompute when applicable) without re-validating the entire document for
        every pair — equivalent coverage of same-ID donor-body rejection.
        """

        row = copy.deepcopy(vectors_by_id[donor_id])
        row["id"] = target_id
        row["family"] = family_of(target_id)
        executed: set[str] = set()
        try:
            if family_of(target_id) == "positive" and "fixture" in row:
                # May pass fixture geometry if donor is also positive — still must
                # fail mark_complete against target authority fingerprint/expected.
                try:
                    validate_positive_fixture(row)
                except GateError:
                    return
            if family_of(target_id) == "commit_unknown" and "old_rows" in row:
                classification = classify_commit_unknown(
                    row["old_rows"], row["new_rows"], row["observed_rows"]
                )
                if classification != AUTHORITY[target_id]["expected"].get("classification"):
                    return
            mark_complete(target_id, row, executed)
            raise SystemExit(
                f"self-test failed: donor body accepted for {target_id}<={donor_id}"
            )
        except GateError:
            return

    # Exhaustive same-family ordered donor pairs (complete deterministic set).
    by_family: dict[str, list[str]] = {}
    for vid in id_list:
        by_family.setdefault(family_of(vid), []).append(vid)
    same_family_pairs = 0
    for _fam, members in by_family.items():
        for target_id in members:
            for donor_id in members:
                if donor_id == target_id:
                    continue
                assert_donor_row_rejected(target_id, donor_id)
                same_family_pairs += 1
    expected_pairs = sum(len(v) * (len(v) - 1) for v in by_family.values())
    if same_family_pairs != expected_pairs:
        raise SystemExit(
            f"self-test failed: same-family pairs {same_family_pairs} != {expected_pairs}"
        )

    # Cross-family donor for every ID (one each).
    family_fail_counts = {f: 0 for f in by_family}
    for index, target_id in enumerate(id_list):
        donor_id = id_list[(index + 1) % len(id_list)]
        if family_of(donor_id) == family_of(target_id):
            for offset in range(2, len(id_list)):
                cand = id_list[(index + offset) % len(id_list)]
                if family_of(cand) != family_of(target_id):
                    donor_id = cand
                    break
        assert_donor_row_rejected(target_id, donor_id)
        family_fail_counts[family_of(target_id)] += 1

    # Full-document sample donors still prove inventory path rejects substitutions.
    for target_id, donor_id in (
        ("MF-POS-EMPTY-PAYLOAD", "MF-POS-ONE-BYTE"),
        ("MF-CU-RECEIVER-CHUNK-OLD", "MF-CU-RECEIVER-CHUNK-NEW"),
        ("MF-CU-TERMINAL-GROUP-ABSENT", "MF-CU-TERMINAL-GROUP-BOTH"),
        ("MF-BUDGET-EMPTY-TRANSFER", "MF-BUDGET-ARITHMETIC-REFERENCE"),
    ):
        d = copy.deepcopy(document)
        row = copy.deepcopy(vectors_by_id[donor_id])
        row["id"] = target_id
        row["family"] = family_of(target_id)
        _replace_vector(d, target_id, row)
        expect_fail(d, f"full-doc donor {target_id}<={donor_id}")

    # expected/status/classification substitution
    exp_doc = copy.deepcopy(document)
    for v in exp_doc["vectors"]:
        if v["id"] == "MF-CU-RECEIVER-CHUNK-OLD":
            v["expected"] = copy.deepcopy(AUTHORITY["MF-CU-RECEIVER-CHUNK-NEW"]["expected"])
            break
    expect_fail(exp_doc, "classification expected swap")

    status_doc = copy.deepcopy(document)
    for v in status_doc["vectors"]:
        if v["id"] == "MF-NEG-STALE-GENERATION":
            v["expected"] = dict(v["expected"])
            v["expected"]["status"] = "OK"
            break
    expect_fail(status_doc, "status substitution")

    # constants / budget / custody / CU tamper
    cdoc = copy.deepcopy(document)
    cdoc["constants"]["chunk_size"] = 895
    expect_fail(cdoc, "constants tamper")
    cdoc = copy.deepcopy(document)
    cdoc["constants"]["no_deadline_u64_hex"] = "0000000000000000"
    expect_fail(cdoc, "deadline sentinel tamper")
    bdoc = copy.deepcopy(document)
    bdoc["budget"]["receiver_fulls_max_transfer"] = 43
    expect_fail(bdoc, "budget tamper")
    custody = copy.deepcopy(document)
    for v in custody["vectors"]:
        if v["id"] == "MF-NEG-FALSE-CUSTODY-BITMAP":
            v["transfer_accept_received"] = True
            break
    expect_fail(custody, "custody tamper")
    cu = copy.deepcopy(document)
    for v in cu["vectors"]:
        if v["id"] == "MF-CU-RECEIVER-CHUNK-NEW":
            v["observed_rows"] = copy.deepcopy(v["old_rows"])
            break
    expect_fail(cu, "COMMIT_UNKNOWN observed tamper")

    # Positive single-byte corruptions (page/chunk/open_accept/finalize/accept transfer_id)
    def mutate_one_byte(path_label: str, mutator) -> None:
        d = copy.deepcopy(document)
        for v in d["vectors"]:
            if v["id"] == "MF-POS-ONE-BYTE":
                mutator(v)
                break
        expect_fail(d, path_label)

    def xor_hex_field(obj: dict[str, Any], field: str, index: int = 0) -> None:
        raw = bytearray(bytes.fromhex(obj[field]))
        raw[index] ^= 0x01
        obj[field] = raw.hex()

    mutate_one_byte(
        "page body byte0",
        lambda v: xor_hex_field(v["fixture"]["pages"][0], "body_hex", 0),
    )
    mutate_one_byte(
        "chunk body byte0",
        lambda v: xor_hex_field(v["fixture"]["chunks"][0], "body_hex", 0),
    )
    mutate_one_byte(
        "open_accept byte0",
        lambda v: xor_hex_field(v["fixture"], "open_accept_hex", 0),
    )
    mutate_one_byte(
        "finalize byte0",
        lambda v: xor_hex_field(v["fixture"], "finalize_hex", 0),
    )
    mutate_one_byte(
        "content byte0",
        lambda v: xor_hex_field(v["fixture"], "content_hex", 0),
    )

    # TRANSFER_ACCEPT transfer_id mutation with recomputed accept digest still fails context.
    d = copy.deepcopy(document)
    for v in d["vectors"]:
        if v["id"] != "MF-POS-ONE-BYTE":
            continue
        accept = bytearray(bytes.fromhex(v["fixture"]["transfer_accept_hex"]))
        accept[0] ^= 0x01  # transfer_id first byte
        # recompute acceptance digest over preceding 128 bytes
        digest = __import__("hashlib").sha256(b"NM3-ACCEPT-V1" + bytes(accept[:128])).digest()
        accept[128:] = digest
        v["fixture"]["transfer_accept_hex"] = accept.hex()
        break
    expect_fail(d, "accept transfer_id mutation with repaired digest")

    # pages=[] when pages required
    d = copy.deepcopy(document)
    for v in d["vectors"]:
        if v["id"] == "MF-POS-ONE-BYTE":
            v["fixture"]["pages"] = []
            break
    expect_fail(d, "pages=[] nonempty required")

    # fingerprint / map / THIRD CRC
    fp_doc = copy.deepcopy(document)
    for v in fp_doc["vectors"]:
        if v["id"] == "MF-POS-EMPTY-PAYLOAD":
            v["authority_fingerprint_hex"] = "00" * 32
            break
    expect_fail(fp_doc, "fingerprint field tamper")
    map_doc = copy.deepcopy(document)
    map_doc["authority_map_sha256_hex"] = "11" * 32
    expect_fail(map_doc, "map sha tamper")
    third_doc = copy.deepcopy(document)
    for v in third_doc["vectors"]:
        if v["id"] == "MF-CU-RECEIVER-CHUNK-THIRD":
            raw_v = bytearray(bytes.fromhex(v["observed_rows"][0]["value_hex"]))
            raw_v[-1] ^= 0x01
            v["observed_rows"][0]["value_hex"] = raw_v.hex()
            break
    expect_fail(third_doc, "THIRD invalid CRC")

    # Independent constants vs document (known-answer, not regenerated from vector alone).
    c = document["constants"]
    b = document["budget"]
    if c["chunk_size"] != GATE_INDEPENDENT_CONSTANTS["chunk_size"]:
        raise SystemExit("independent constant drift chunk_size")
    if c["max_content_bytes"] != GATE_INDEPENDENT_CONSTANTS["max_content_bytes"]:
        raise SystemExit("independent constant drift max_content")
    if c["max_chunk_count"] != GATE_INDEPENDENT_CONSTANTS["max_chunk_count"]:
        raise SystemExit("independent constant drift max_chunk_count")
    if b["receiver_fulls_max_transfer"] != GATE_INDEPENDENT_CONSTANTS["receiver_fulls_max_transfer"]:
        raise SystemExit("independent budget drift receiver_fulls")
    if b["required_receiver_fulls_for_reference"] != GATE_INDEPENDENT_CONSTANTS["required_receiver_fulls_reference"]:
        raise SystemExit("independent budget drift required_rx")

    if VECTOR.read_bytes() != raw:
        raise SystemExit("self-test failed: source vector mutated at end")

    print(
        "self-test OK "
        f"same_family_pairs={same_family_pairs} "
        f"cross_family={family_fail_counts} "
        f"authority_ids={len(AUTHORITY)} map_sha={AUTHORITY_MAP_SHA256_HEX}"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    document = load_strict_json(VECTOR.read_bytes())
    executed = validate(document)
    print(
        f"OK vectors={len(executed)} "
        f"authority_ids={len(AUTHORITY)} "
        f"map_sha={AUTHORITY_MAP_SHA256_HEX} "
        f"sha256={sha(VECTOR.read_bytes()).hex()}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateError as error:
        print(f"GATE FAIL: {error}", file=sys.stderr)
        raise SystemExit(2) from error
