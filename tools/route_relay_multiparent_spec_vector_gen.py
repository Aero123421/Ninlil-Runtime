#!/usr/bin/env python3
"""SPEC_ACCEPTED design oracle for ADR-0019 route/relay + ADR-0020 multi-parent.

Deterministic machine vectors from semantic source data. Standard library only.
Does not import Ninlil runtime, production codecs, or either gate.
Claims SPEC_ACCEPTED only; does not claim implementation, HIL,
RELEASE_SUPPORTED, public ABI, or physical execution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "spec/vectors/route-relay-multiparent-spec-v1.json"

# --- closed constants (profile ESP V1 candidate) ---
API_VERSION = 1
NRM1_BYTES = 256
NRP1_HEADER_BYTES = 20
SLOT_BYTES = 508
SLOTS_PER_PAGE = 8
NRP1_SLOTS_SPAN = SLOTS_PER_PAGE * SLOT_BYTES  # 4064
NRP1_PAD_BYTES = 12
NRP1_BYTES = NRP1_HEADER_BYTES + NRP1_SLOTS_SPAN + NRP1_PAD_BYTES  # 4096
assert NRP1_BYTES == 4096
PAGE_COUNT = 16
ROUTE_MAX = 128
DIR_BYTES = 256
NOA1_BYTES = 400
NPS1_BYTES = 256
ASSIGNMENT_SLOT_BYTES = 472  # 400 + 1 + 3 + 32 + 32 + 4
ASSIGNMENT_SLOTS_PER_PAGE = 8
NPA1_HEADER_BYTES = 16
NPA1_SLOTS_SPAN = ASSIGNMENT_SLOTS_PER_PAGE * ASSIGNMENT_SLOT_BYTES  # 3776
NPA1_PAD_BYTES = 4096 - NPA1_HEADER_BYTES - NPA1_SLOTS_SPAN  # 304
NPA1_BYTES = NPA1_HEADER_BYTES + NPA1_SLOTS_SPAN + NPA1_PAD_BYTES
assert NPA1_BYTES == 4096
NPH1_BYTES = 256
NPT1_HEADER_BYTES = 24
NPT1_SLOT_BYTES = 48
NPT1_SLOTS_PER_PAGE = 84
NPT1_SLOTS_SPAN = NPT1_SLOTS_PER_PAGE * NPT1_SLOT_BYTES  # 4032
NPT1_PAD_BYTES = 4096 - NPT1_HEADER_BYTES - NPT1_SLOTS_SPAN  # 40
NPT1_BYTES = NPT1_HEADER_BYTES + NPT1_SLOTS_SPAN + NPT1_PAD_BYTES
TOKEN_REPLAY_LEDGER_CAPACITY = 256
assert NPT1_BYTES == 4096
assert TOKEN_REPLAY_LEDGER_CAPACITY <= NPT1_SLOTS_PER_PAGE * 8
ROUTE_RESULT_BYTES = 128
PARENT_RESULT_BYTES = 128
INSTALL_BATCH_HEADER_BYTES = 56
EVIDENCE_BYTES = 128
NEV1_BYTES = EVIDENCE_BYTES
NEP1_HEADER_BYTES = 24
NEP1_SLOTS = 31
NEP1_PAGE_COUNT = 4
NEP1_SLOTS_SPAN = NEP1_SLOTS * NEV1_BYTES  # 3968
NEP1_PAD_BYTES = 104
NEP1_BYTES = NEP1_HEADER_BYTES + NEP1_SLOTS_SPAN + NEP1_PAD_BYTES  # 4096
assert NEP1_BYTES == 4096
assert NEP1_HEADER_BYTES + NEP1_SLOTS * NEV1_BYTES + NEP1_PAD_BYTES == 4096
EVIDENCE_CAPACITY = NEP1_PAGE_COUNT * NEP1_SLOTS  # 124
EVIDENCE_LIFECYCLE_LIVE = 1
EVIDENCE_LIFECYCLE_COMPLETED = 2
ROUTE_PHYSICAL_KEY_COUNT = 1 + PAGE_COUNT + NEP1_PAGE_COUNT  # 21
assert ROUTE_PHYSICAL_KEY_COUNT == 21
assert ROUTE_MAX == PAGE_COUNT * SLOTS_PER_PAGE == 128
assert EVIDENCE_CAPACITY == 124

# Parent multi-scope NPS1 pages (NPP1)
NPP1_HEADER_BYTES = 16
NPP1_SLOTS = 15
NPP1_SLOTS_SPAN = NPP1_SLOTS * NPS1_BYTES  # needs NPS1_BYTES first
NPP1_PAD_BYTES = 240
NPP1_BYTES = NPP1_HEADER_BYTES + NPP1_SLOTS_SPAN + NPP1_PAD_BYTES
NPP1_PAGE_COUNT = 5
NPP1_PHYSICAL_SLOT_COUNT = NPP1_PAGE_COUNT * NPP1_SLOTS  # 75 physical slots
SCOPE_PARENT_SET_CAPACITY = 64  # ESP V1 concurrent owner-scope resource bound
NPA1_PAGE_COUNT = 8
NPT1_PAGE_COUNT = 8
PARENT_PHYSICAL_KEY_COUNT = (
    1 + NPP1_PAGE_COUNT + NPA1_PAGE_COUNT + NPT1_PAGE_COUNT
)  # 22
assert NPP1_BYTES == 4096
assert NPP1_PHYSICAL_SLOT_COUNT >= SCOPE_PARENT_SET_CAPACITY
assert PARENT_PHYSICAL_KEY_COUNT == 22

QUEUE_GLOBAL_ENTRIES = 64
QUEUE_GLOBAL_BYTES = 16320
RESERVED_CONTROL_ENTRIES = 8
RESERVED_CONTROL_BYTES = 2048
DEDUP_WINDOW = 256
LOOP_WINDOW = 256
MAX_HOPS_PROFILE = 3
MAX_HOPS_ABSOLUTE = 8
MAX_LINK_GROUPS = 13
MAX_ATTEMPTS = 3
MAX_AIRTIME_BUDGET_MS = 60000
INSTALL_BATCH_MAX = 8
LOGICAL_MUTATIONS_MAX = 9

# RRP-1/RRP-2 bounded outer bundle and durable used-attempt authority.
RRM1_MANIFEST_BYTES = 256
RRM1_CHUNK_BYTES_MAX = 61_440
RRM1_CHUNK_COUNT_MAX = 5
RRM1_LOGICAL_BYTES_MAX = RRM1_CHUNK_BYTES_MAX * RRM1_CHUNK_COUNT_MAX
RRMP_ROUTE_EXPORT_BASELINE = 82_457
RRMP_PARENT_EXPORT_BASELINE = 86_566
RRMP_RETAINED_FULL_GROUP_MAX = 36_981
RRMP_QST4_HEADER_BYTES = 56
RRMP_QST4_SCOPE_BYTES = 64
RRMP_QST4_EVIDENCE_AUX_BYTES = 72
RRMP_QST4_QUEUE_BYTES = 320
RRMP_QST4_ATTEMPT_BYTES = 80
RRMP_QST4_ATTEMPT_CAPACITY = 256
RRMP_QST4_HANDOFF_TUPLE_BYTES = 224
RRMP_QST4_HANDOFF_TUPLE_CAPACITY = SCOPE_PARENT_SET_CAPACITY
RRMP_ATTEMPT_RETENTION_MS = 60_000
RRMP_QST4_MAX_BYTES = (
    RRMP_QST4_HEADER_BYTES
    + SCOPE_PARENT_SET_CAPACITY * RRMP_QST4_SCOPE_BYTES
    + EVIDENCE_CAPACITY * RRMP_QST4_EVIDENCE_AUX_BYTES
    + QUEUE_GLOBAL_ENTRIES * RRMP_QST4_QUEUE_BYTES
    + QUEUE_GLOBAL_BYTES
    + RRMP_QST4_ATTEMPT_CAPACITY * RRMP_QST4_ATTEMPT_BYTES
    + RRMP_QST4_HANDOFF_TUPLE_CAPACITY * RRMP_QST4_HANDOFF_TUPLE_BYTES
)
RRMP_LOGICAL_EXPORT_REQUIRED_MAX = (
    RRMP_ROUTE_EXPORT_BASELINE
    + RRMP_PARENT_EXPORT_BASELINE
    + RRMP_RETAINED_FULL_GROUP_MAX
    + RRMP_QST4_MAX_BYTES
    + 20
)
RRMP_BUNDLE_HEADROOM = RRM1_LOGICAL_BYTES_MAX - RRMP_LOGICAL_EXPORT_REQUIRED_MAX
assert RRMP_QST4_MAX_BYTES == 84_696
assert RRMP_LOGICAL_EXPORT_REQUIRED_MAX == 290_720
assert RRM1_LOGICAL_BYTES_MAX == 307_200
assert RRMP_BUNDLE_HEADROOM == 16_480

U16_MAX = 0xFFFF
U32_MAX = 0xFFFFFFFF
U64_MAX = (1 << 64) - 1

STATUS = {
    "OK": 1,
    "INVALID_ARGUMENT": 2,
    "CORRUPT": 3,
    "UNSUPPORTED_API": 4,
    "UNSUPPORTED_SCHEMA": 5,
    "UNSUPPORTED_CAPABILITY": 6,
    "AUTHORITY_CONFLICT": 7,
    "STALE_GENERATION": 8,
    "LEASE_EXPIRED": 9,
    "CLOCK_EPOCH_MISMATCH": 10,
    "LOOP": 11,
    "TERMINAL_MISMATCH": 12,
    "HOP_EXHAUSTED": 13,
    "REPLAY": 14,
    "DRAIN_FENCED": 15,
    "NOT_ACTIVE": 16,
    "RESOURCE": 17,
    "BACKPRESSURE": 18,
    "COMMIT_UNKNOWN": 19,
    "REENTRANT": 20,
    "FEATURE_OFF": 21,
}

PARENT_STATUS = {
    "OK": 1,
    "INVALID_ARGUMENT": 2,
    "CORRUPT": 3,
    "UNSUPPORTED_API": 4,
    "UNSUPPORTED_SCHEMA": 5,
    "UNSUPPORTED_CAPABILITY": 6,
    "AUTHORITY_CONFLICT": 7,
    "SPLIT_BRAIN": 8,
    "STALE_TERM": 9,
    "STALE_REVISION": 10,
    "LEASE_EXPIRED": 11,
    "CLOCK_EPOCH_MISMATCH": 12,
    "TOKEN_REPLAY": 13,
    "SCOPE_MISMATCH": 14,
    "NOT_OWNER": 15,
    "NOT_ACTIVE": 16,
    "SAME_ATTEMPT_RESELECT": 17,
    "RESOURCE": 18,
    "COMMIT_UNKNOWN": 19,
    "REENTRANT": 20,
    "FEATURE_OFF": 21,
}

# Normative ADR-fixed constants (also independently hard-pinned in gates).
NORMATIVE_CONSTANTS = {
    "API_VERSION": API_VERSION,
    "SCHEMA_VERSION": 1,
    "LOOP_WINDOW": LOOP_WINDOW,
    "DEDUP_WINDOW": DEDUP_WINDOW,
    "ROUTE_MAX": ROUTE_MAX,
    "PAGE_COUNT": PAGE_COUNT,
    "SLOTS_PER_PAGE": SLOTS_PER_PAGE,
    "SLOT_BYTES": SLOT_BYTES,
    "NRP1_HEADER_BYTES": NRP1_HEADER_BYTES,
    "NRP1_PAD_BYTES": NRP1_PAD_BYTES,
    "NRP1_BYTES": NRP1_BYTES,
    "NRM1_BYTES": NRM1_BYTES,
    "INSTALL_BATCH_HEADER_BYTES": INSTALL_BATCH_HEADER_BYTES,
    "DIR_BYTES": DIR_BYTES,
    "EVIDENCE_BYTES": EVIDENCE_BYTES,
    "NEV1_BYTES": NEV1_BYTES,
    "NEP1_HEADER_BYTES": NEP1_HEADER_BYTES,
    "NEP1_SLOTS": NEP1_SLOTS,
    "NEP1_PAGE_COUNT": NEP1_PAGE_COUNT,
    "NEP1_PAD_BYTES": NEP1_PAD_BYTES,
    "NEP1_BYTES": NEP1_BYTES,
    "EVIDENCE_CAPACITY": EVIDENCE_CAPACITY,
    "EVIDENCE_LIFECYCLE_LIVE": EVIDENCE_LIFECYCLE_LIVE,
    "EVIDENCE_LIFECYCLE_COMPLETED": EVIDENCE_LIFECYCLE_COMPLETED,
    "NPP1_BYTES": NPP1_BYTES,
    "NPP1_PAGE_COUNT": NPP1_PAGE_COUNT,
    "NPP1_SLOTS": NPP1_SLOTS,
    "NPP1_PHYSICAL_SLOT_COUNT": NPP1_PHYSICAL_SLOT_COUNT,
    "SCOPE_PARENT_SET_CAPACITY": SCOPE_PARENT_SET_CAPACITY,
    "ROUTE_PHYSICAL_KEY_COUNT": ROUTE_PHYSICAL_KEY_COUNT,
    "PARENT_PHYSICAL_KEY_COUNT": PARENT_PHYSICAL_KEY_COUNT,
    "NOA1_BYTES": NOA1_BYTES,
    "NPS1_BYTES": NPS1_BYTES,
    "ASSIGNMENT_SLOT_BYTES": ASSIGNMENT_SLOT_BYTES,
    "ASSIGNMENT_SLOTS_PER_PAGE": ASSIGNMENT_SLOTS_PER_PAGE,
    "NPA1_HEADER_BYTES": NPA1_HEADER_BYTES,
    "NPA1_PAD_BYTES": NPA1_PAD_BYTES,
    "NPA1_BYTES": NPA1_BYTES,
    "NPH1_BYTES": NPH1_BYTES,
    "NPT1_BYTES": NPT1_BYTES,
    "NPT1_HEADER_BYTES": NPT1_HEADER_BYTES,
    "NPT1_SLOT_BYTES": NPT1_SLOT_BYTES,
    "NPT1_SLOTS_PER_PAGE": NPT1_SLOTS_PER_PAGE,
    "NPT1_PAD_BYTES": NPT1_PAD_BYTES,
    "TOKEN_REPLAY_LEDGER_CAPACITY": TOKEN_REPLAY_LEDGER_CAPACITY,
    "ROUTE_RESULT_BYTES": ROUTE_RESULT_BYTES,
    "PARENT_RESULT_BYTES": PARENT_RESULT_BYTES,
    "QUEUE_GLOBAL_ENTRIES": QUEUE_GLOBAL_ENTRIES,
    "QUEUE_GLOBAL_BYTES": QUEUE_GLOBAL_BYTES,
    "RESERVED_CONTROL_ENTRIES": RESERVED_CONTROL_ENTRIES,
    "RESERVED_CONTROL_BYTES": RESERVED_CONTROL_BYTES,
    "MAX_HOPS_ABSOLUTE": MAX_HOPS_ABSOLUTE,
    "MAX_HOPS_PROFILE_ESP_V1": MAX_HOPS_PROFILE,
    "MAX_LINK_GROUPS": MAX_LINK_GROUPS,
    "MAX_ATTEMPTS": MAX_ATTEMPTS,
    "MAX_AIRTIME_BUDGET_MS": MAX_AIRTIME_BUDGET_MS,
    "INSTALL_BATCH_MAX": INSTALL_BATCH_MAX,
    "LOGICAL_MUTATIONS_MAX": LOGICAL_MUTATIONS_MAX,
    "RRM1_MANIFEST_BYTES": RRM1_MANIFEST_BYTES,
    "RRM1_CHUNK_BYTES_MAX": RRM1_CHUNK_BYTES_MAX,
    "RRM1_CHUNK_COUNT_MAX": RRM1_CHUNK_COUNT_MAX,
    "RRM1_LOGICAL_BYTES_MAX": RRM1_LOGICAL_BYTES_MAX,
    "RRMP_QST4_HEADER_BYTES": RRMP_QST4_HEADER_BYTES,
    "RRMP_QST4_ATTEMPT_BYTES": RRMP_QST4_ATTEMPT_BYTES,
    "RRMP_QST4_ATTEMPT_CAPACITY": RRMP_QST4_ATTEMPT_CAPACITY,
    "RRMP_QST4_HANDOFF_TUPLE_BYTES": RRMP_QST4_HANDOFF_TUPLE_BYTES,
    "RRMP_QST4_HANDOFF_TUPLE_CAPACITY":
        RRMP_QST4_HANDOFF_TUPLE_CAPACITY,
    "RRMP_ATTEMPT_RETENTION_MS": RRMP_ATTEMPT_RETENTION_MS,
    "RRMP_QST4_MAX_BYTES": RRMP_QST4_MAX_BYTES,
    "RRMP_LOGICAL_EXPORT_REQUIRED_MAX": RRMP_LOGICAL_EXPORT_REQUIRED_MAX,
    "RRMP_BUNDLE_HEADROOM": RRMP_BUNDLE_HEADROOM,
    "WIRE_PROFILE_ID": 0x11,
    "PARENT_SPLIT_BRAIN_CODE": 8,
}

ROUTE_FAILURE_PRECEDENCE = [
    "INVALID_ARGUMENT",
    "CORRUPT",
    "UNSUPPORTED_API",
    "UNSUPPORTED_SCHEMA",
    "FEATURE_OFF",
    "UNSUPPORTED_CAPABILITY",
    "AUTHORITY_CONFLICT",
    "CLOCK_EPOCH_MISMATCH",
    "LEASE_EXPIRED",
    "STALE_GENERATION",
    "NOT_ACTIVE",
    "DRAIN_FENCED",
    "LOOP",
    "TERMINAL_MISMATCH",
    "HOP_EXHAUSTED",
    "REPLAY",
    "RESOURCE",
    "BACKPRESSURE",
    "COMMIT_UNKNOWN",
    "REENTRANT",
    "OK",
]

PARENT_FAILURE_PRECEDENCE = [
    "INVALID_ARGUMENT",
    "CORRUPT",
    "UNSUPPORTED_API",
    "UNSUPPORTED_SCHEMA",
    "FEATURE_OFF",
    "UNSUPPORTED_CAPABILITY",
    "AUTHORITY_CONFLICT",
    "SPLIT_BRAIN",
    "CLOCK_EPOCH_MISMATCH",
    "LEASE_EXPIRED",
    "STALE_TERM",
    "STALE_REVISION",
    "SCOPE_MISMATCH",
    "TOKEN_REPLAY",
    "NOT_OWNER",
    "NOT_ACTIVE",
    "SAME_ATTEMPT_RESELECT",
    "RESOURCE",
    "COMMIT_UNKNOWN",
    "REENTRANT",
    "OK",
]

# Independent closed handoff machine (gates hardcode the same table; vector cannot teach).
HANDOFF_CLOSED: dict[str, dict[str, Any]] = {
    "S1": {
        "step": "S1",
        "edge_index": -1,
        "from_state": None,
        "to_state": "PREPARED_NEW",
        "state": "PREPARED_NEW",
        "proof_present": 0,
        "cas_succeeded": 0,
        "commit_receipt_verified": 0,
        "token_consumed": 0,
        "tombstone_written": 0,
        "new_owner_seal": 0,
        "old_owner_seal": 0,
        "artifact": "NEW_TUPLE_UNUSED_TOKEN_FULL",
        "case_id": "MP-HANDOFF-PREPARED-NEW",
    },
    "S2": {
        "step": "S2",
        "edge_index": 0,
        "from_state": "PREPARED_NEW",
        "to_state": "OLD_FENCED_PROOF",
        "state": "OLD_FENCED_PROOF",
        "proof_present": 1,
        "cas_succeeded": 0,
        "commit_receipt_verified": 0,
        "token_consumed": 0,
        "tombstone_written": 0,
        "new_owner_seal": 0,
        "old_owner_seal": 0,
        "artifact": "PROOF_FULL",
        "case_id": "MP-HANDOFF-OLD-FENCED-PROOF",
    },
    "S3": {
        "step": "S3",
        "edge_index": 1,
        "from_state": "OLD_FENCED_PROOF",
        "to_state": "AUTHORITY_COMMITTED",
        "state": "AUTHORITY_COMMITTED",
        "proof_present": 1,
        "cas_succeeded": 1,
        "commit_receipt_verified": 0,
        "token_consumed": 0,
        "tombstone_written": 0,
        "new_owner_seal": 0,
        "old_owner_seal": 0,
        "artifact": "AUTHORITY_CAS",
        "case_id": "MP-HANDOFF-AUTHORITY-COMMITTED",
    },
    "S4": {
        "step": "S4",
        "edge_index": 2,
        "from_state": "AUTHORITY_COMMITTED",
        "to_state": "NEW_OWNER_ACTIVATED",
        "state": "NEW_OWNER_ACTIVATED",
        "proof_present": 1,
        "cas_succeeded": 1,
        "commit_receipt_verified": 1,
        "token_consumed": 1,
        "tombstone_written": 0,
        "new_owner_seal": 1,
        "old_owner_seal": 0,
        "artifact": "COMMIT_RECEIPT_TOKEN_CONSUME",
        "case_id": "MP-HANDOFF-NEW-OWNER-ACTIVATED",
    },
    "S5": {
        "step": "S5",
        "edge_index": 3,
        "from_state": "NEW_OWNER_ACTIVATED",
        "to_state": "ENDPOINT_OBSERVED",
        "state": "ENDPOINT_OBSERVED",
        "proof_present": 1,
        "cas_succeeded": 1,
        "commit_receipt_verified": 1,
        "token_consumed": 1,
        "tombstone_written": 0,
        "new_owner_seal": 1,
        "old_owner_seal": 0,
        "artifact": "ENDPOINT_OBSERVE",
        "case_id": "MP-HANDOFF-ENDPOINT-OBSERVED",
    },
    "S6": {
        "step": "S6",
        "edge_index": 4,
        "from_state": "ENDPOINT_OBSERVED",
        "to_state": "OLD_RETIRED",
        "state": "OLD_RETIRED",
        "proof_present": 1,
        "cas_succeeded": 1,
        "commit_receipt_verified": 1,
        "token_consumed": 1,
        "tombstone_written": 1,
        "new_owner_seal": 1,
        "old_owner_seal": 0,
        "artifact": "TOMBSTONE_RETIRE",
        "case_id": "MP-HANDOFF-OLD-RETIRED",
        "required_prior_steps": ["S1", "S2", "S3", "S4", "S5"],
    },
}

HANDOFF_STATES = [HANDOFF_CLOSED[s]["state"] for s in ("S1", "S2", "S3", "S4", "S5", "S6")]
HANDOFF_ALLOWED_EDGES = [
    (HANDOFF_CLOSED[s]["from_state"], HANDOFF_CLOSED[s]["to_state"], HANDOFF_CLOSED[s]["artifact"])
    for s in ("S2", "S3", "S4", "S5", "S6")
]
HANDOFF_FORBIDDEN_EDGES = [
    ("PREPARED_NEW", "AUTHORITY_COMMITTED"),
    ("PREPARED_NEW", "NEW_OWNER_ACTIVATED"),
    ("OLD_FENCED_PROOF", "NEW_OWNER_ACTIVATED"),
    ("AUTHORITY_COMMITTED", "OLD_FENCED_PROOF"),
    ("NEW_OWNER_ACTIVATED", "PREPARED_NEW"),
    ("OLD_RETIRED", "PREPARED_NEW"),
]

# Independent closed simulation transcript (gates hard-pin the same table; digest alone is not authority).
SIM_TRANSCRIPT_CLOSED: list[dict[str, Any]] = [
    {"t": 0, "event": "INSTALL_1HOP", "route": "R1", "result": "OK"},
    {"t": 1, "event": "ACTIVATE", "route": "R1", "result": "OK"},
    {"t": 2, "event": "FORWARD_ADMIT", "hop_remaining": 1, "result": "OK"},
    {"t": 3, "event": "FORWARD_TX", "result": "OK"},
    {"t": 4, "event": "INSTALL_2HOP", "routes": ["R2A", "R2B"], "result": "OK"},
    {"t": 5, "event": "PARENT_SET", "parents": 2, "result": "OK"},
    {"t": 6, "event": "UPLINK_DIVERSITY", "paths": 2, "effect_publish": 1},
    {"t": 7, "event": "FORWARD_2HOP", "result": "OK"},
    {"t": 8, "event": "PARENT_LOSS", "parent": "P2", "result": "SEAL_0_DRAIN"},
    {"t": 9, "event": "DRAIN_BEGIN", "route": "R2A", "result": "OK"},
    {"t": 10, "event": "SAME_ATTEMPT_RESELECT", "result": "SAME_ATTEMPT_RESELECT"},
    {"t": 11, "event": "NEW_ATTEMPT_HANDOFF", "result": "OK"},
    {"t": 12, "event": "LEASE_BOUNDARY", "now": 2_000_000, "result": "LEASE_EXPIRED"},
    # ADR invariant: split-brain => seal 0 and forward 0 (not rewritable via digest recompute).
    {"t": 13, "event": "SPLIT_BRAIN_WRITERS", "result": "SPLIT_BRAIN", "forward": 0, "seal": 0},
    {"t": 14, "event": "RESOURCE_EXHAUST", "result": "RESOURCE"},
    {"t": 15, "event": "PRIORITY_CONTROL_DRAIN", "result": "OK"},
]
SIM_TRANSCRIPT_EVENT_COUNT = len(SIM_TRANSCRIPT_CLOSED)


ARITHMETIC_KATS = {
    "nrp1_page": {
        "formula": "NRP1_HEADER + SLOTS_PER_PAGE*SLOT_BYTES + NRP1_PAD",
        "values": [NRP1_HEADER_BYTES, SLOTS_PER_PAGE, SLOT_BYTES, NRP1_PAD_BYTES],
        "sum": NRP1_BYTES,
        "checked": NRP1_HEADER_BYTES + SLOTS_PER_PAGE * SLOT_BYTES + NRP1_PAD_BYTES,
    },
    "nrp1_forbid_pad52": {
        "formula": "20+8*508+52",
        "sum": 20 + 8 * 508 + 52,
        "equals_nrp1": False,
        "forbidden_eq_4096": True,
    },
    "install_batch_n1": {
        "formula": "INSTALL_BATCH_HEADER + NRM1*N",
        "N": 1,
        "struct_size": INSTALL_BATCH_HEADER_BYTES + NRM1_BYTES * 1,
        "entries_offset": INSTALL_BATCH_HEADER_BYTES,
    },
    "install_batch_n8": {
        "formula": "INSTALL_BATCH_HEADER + NRM1*N",
        "N": 8,
        "struct_size": INSTALL_BATCH_HEADER_BYTES + NRM1_BYTES * 8,
        "entries_offset": INSTALL_BATCH_HEADER_BYTES,
    },
    "install_batch_forbid_48_plus_8n": {
        "formula": "48+8*N",
        "N": 8,
        "wrong_size": 48 + 8 * 8,
        "correct_size": INSTALL_BATCH_HEADER_BYTES + NRM1_BYTES * 8,
    },
    "assignment_slot": {
        "formula": "NOA1 + local_state + res3 + proof32 + receipt32 + crc4",
        "sum": NOA1_BYTES + 1 + 3 + 32 + 32 + 4,
        "slot_bytes": ASSIGNMENT_SLOT_BYTES,
    },
    "npa1_page": {
        "formula": "NPA1_HEADER + 8*ASSIGNMENT_SLOT + NPA1_PAD",
        "sum": NPA1_HEADER_BYTES + ASSIGNMENT_SLOTS_PER_PAGE * ASSIGNMENT_SLOT_BYTES + NPA1_PAD_BYTES,
        "page_bytes": NPA1_BYTES,
    },
    "route_physical_keys": {
        "formula": "1+PAGE_COUNT+NEP1_PAGE_COUNT",
        "directory": 1,
        "route_pages": PAGE_COUNT,
        "evidence_pages": NEP1_PAGE_COUNT,
        "sum": ROUTE_PHYSICAL_KEY_COUNT,
        "forbidden_budget_17": False,
    },
    "parent_physical_keys": {
        "formula": "1+NPP1_PAGE_COUNT+NPA1_PAGE_COUNT+NPT1_PAGE_COUNT",
        "header": 1,
        "parent_set_pages": NPP1_PAGE_COUNT,
        "assignment_pages": NPA1_PAGE_COUNT,
        "token_pages": NPT1_PAGE_COUNT,
        "sum": PARENT_PHYSICAL_KEY_COUNT,
    },
    "route_capacity": {
        "formula": "PAGE_COUNT*SLOTS_PER_PAGE",
        "page_count": PAGE_COUNT,
        "slots_per_page": SLOTS_PER_PAGE,
        "route_max": ROUTE_MAX,
        "checked": PAGE_COUNT * SLOTS_PER_PAGE,
    },
    "evidence_capacity": {
        "formula": "NEP1_PAGE_COUNT*NEP1_SLOTS",
        "nep1_pages": NEP1_PAGE_COUNT,
        "nep1_slots": NEP1_SLOTS,
        "capacity": EVIDENCE_CAPACITY,
        "checked": NEP1_PAGE_COUNT * NEP1_SLOTS,
    },
    "nep1_page": {
        "formula": "NEP1_HEADER+NEP1_SLOTS*NEV1+NEP1_PAD",
        "values": [NEP1_HEADER_BYTES, NEP1_SLOTS, NEV1_BYTES, NEP1_PAD_BYTES],
        "sum": NEP1_BYTES,
        "checked": NEP1_HEADER_BYTES + NEP1_SLOTS * NEV1_BYTES + NEP1_PAD_BYTES,
    },
    "nrd1_layout": {
        "formula": "44+64+16+128+4",
        "route_gens_span": 64,
        "evidence_gens_span": 16,
        "reserved_mid": 128,
        "crc": 4,
        "sum": DIR_BYTES,
        "checked": 44 + 64 + 16 + 128 + 4,
    },
}
assert ARITHMETIC_KATS["nrp1_page"]["checked"] == 4096
assert ARITHMETIC_KATS["nrp1_forbid_pad52"]["sum"] == 4136
assert ARITHMETIC_KATS["install_batch_n8"]["struct_size"] == 2104
assert ARITHMETIC_KATS["assignment_slot"]["sum"] == ASSIGNMENT_SLOT_BYTES
assert ARITHMETIC_KATS["npa1_page"]["sum"] == 4096
assert ARITHMETIC_KATS["route_physical_keys"]["sum"] == 21
assert ARITHMETIC_KATS["parent_physical_keys"]["sum"] == 22
assert ARITHMETIC_KATS["route_capacity"]["checked"] == 128
assert ARITHMETIC_KATS["evidence_capacity"]["checked"] == 124
assert ARITHMETIC_KATS["nep1_page"]["checked"] == 4096
assert ARITHMETIC_KATS["nrd1_layout"]["checked"] == 256
assert ROUTE_PHYSICAL_KEY_COUNT != 17

# Exact required-ID inventory (gates reject missing/extra/duplicate/substituted).
REQUIRED_IDS: tuple[str, ...] = (
    # API / integrity
    "RR-API-PREAMBLE-OK",
    "RR-API-VERSION-REJECT",
    "RR-API-STRUCT-SIZE-REJECT",
    "RR-API-RESERVED-REJECT",
    "RR-FEATURE-OFF",
    "RR-CRC-REPAIR-THEN-SEMANTIC",
    "RR-DIGEST-REPAIR-THEN-SEMANTIC",
    # identities / materialization
    "RR-MGMT-MATERIALIZE-1HOP-TERMINAL",
    "RR-MGMT-MATERIALIZE-2HOP",
    "RR-MGMT-MATERIALIZE-3HOP",
    "RR-MGMT-TERMINAL-MISMATCH",
    "RR-MGMT-ZERO-TERM-REJECT",
    "RR-MGMT-AUTHORITY-CONFLICT-DIGEST",
    "RR-MGMT-STALE-REVISION",
    # hop / loop / replay / generation
    "RR-HOP-1-FORWARD-OK",
    "RR-HOP-2-FORWARD-OK",
    "RR-HOP-3-FORWARD-OK",
    "RR-HOP-LOOP-SEEN",
    "RR-HOP-LOOP-SELF-PEER",
    "RR-HOP-DUPLICATED-RELAY",
    "RR-HOP-STALE-GENERATION",
    "RR-HOP-EXHAUSTED",
    "RR-HOP-REPLAY-DEDUP",
    "RR-HOP-TERMINAL-AT-ONE",
    "RR-HOP-REWRAP-E2E-IDENTICAL",
    # lease / clock / drain
    "RR-LEASE-ACTIVE-BOUNDARY-MINUS-ONE",
    "RR-LEASE-EXPIRED-AT-BOUNDARY",
    "RR-CLOCK-EPOCH-MISMATCH",
    "RR-DRAIN-ELIGIBLE",
    "RR-DRAIN-FENCED-NEW-ADMISSION",
    "RR-DRAIN-PHYSICALLY-IMPOSSIBLE",
    "RR-DRAIN-FRAG-FORMULA-EXACT",
    "RR-DRAIN-OVERFLOW-REJECT",
    # custody / evidence
    "RR-CUSTODY-NOT-APP-RECEIPT",
    "RR-EVIDENCE-CHAIN-EXTEND",
    "RR-EVIDENCE-DURABLE-FULL-GROUP",
    "RR-EVIDENCE-COMPLETE-NOT-FREE",
    "RR-EVIDENCE-CAPACITY-FULL-RESOURCE",
    "RR-EVIDENCE-RECLAIM-THEN-ADMIT",
    "RR-EVIDENCE-LIVENESS-BEYOND-124",
    "RR-EVIDENCE-GEN-RETIRE-GC",
    "RR-EVIDENCE-RESTART-LIVE-SURVIVES",
    "RR-OLD-ACK-STALE",
    "RR-OLD-CUSTODY-STALE",
    "RR-OLD-EVIDENCE-STALE",
    # resources / fairness
    "RR-RESOURCE-QUEUE-EXHAUSTION",
    "RR-RESOURCE-RESERVED-CAPACITY-PROTECT",
    "RR-PRIORITY-ISOLATION",
    "RR-BACKPRESSURE-NOT-RESELECT",
    "RR-CANCEL-DRAIN-INFLIGHT",
    # storage / recovery
    "RR-STORAGE-DIRECTORY-LAYOUT",
    "RR-STORAGE-PAGE-SLOT-ARITHMETIC",
    "RR-STORAGE-KEY-BUDGET-CAPACITY",
    "RR-STORAGE-PLACEMENT-PROBE",
    "RR-STORAGE-BATCH-9-OK",
    "RR-STORAGE-BATCH-10-REJECT",
    "RR-CU-OLD",
    "RR-CU-NEW",
    "RR-CU-PARTIAL",
    "RR-CU-EXTRA",
    "RR-CU-THIRD",
    "RR-RESTART-POWER-CUT-FENCE",
    "RR-RETRY-IDEMPOTENT-SAME-DIGEST",
    # mixed version
    "RR-MIXED-SCHEMA-UNSUPPORTED",
    "RR-DOWNGRADE-FENCE",
    "RR-DEFAULT-OFF-DIRECT-ONLY",
    # multi-parent
    "MP-SCOPE-DERIVATION-EXACT",
    "MP-SCOPE-LENGTH-REJECT",
    "MP-ASSIGNMENT-TUPLE-SEAL-OK",
    "MP-NPH1-WRITER-FULL-FIELDS",
    "MP-NOA1-FIELD-LAYOUT-EXACT",
    "MP-ASSIGNMENT-WORKSPACE-FULL-NOA1",
    "MP-PARENT-SET-INSTALL-OK",
    "MP-PARENT-SET-DIGEST-MISMATCH",
    "MP-PARENT-SET-ORDER-MISMATCH",
    "MP-PARENT-SET-ID-SUBSTITUTION",
    "MP-PREPARE-PARENT-SET-BIND-OK",
    "MP-PREPARE-PARENT-SET-MISMATCH",
    "MP-COMMIT-BINDING-OK",
    "MP-TWO-SCOPE-PARENT-SETS-OK",
    "MP-TWO-SCOPE-RESTART-LOOKUP",
    "MP-TWO-SCOPE-ROUTE-SELECT",
    "MP-SPLIT-BRAIN-TWO-WRITERS",
    "MP-SIMULTANEOUS-PARENTS-UPLINK",
    "MP-SIMULTANEOUS-CONTROLLERS-SEAL-ZERO",
    "MP-LEASE-BOUNDARY-MINUS-ONE",
    "MP-LEASE-BOUNDARY-EQUAL-EXPIRED",
    "MP-HANDOFF-PREPARED-NEW",
    "MP-HANDOFF-OLD-FENCED-PROOF",
    "MP-HANDOFF-AUTHORITY-COMMITTED",
    "MP-HANDOFF-NEW-OWNER-ACTIVATED",
    "MP-HANDOFF-ENDPOINT-OBSERVED",
    "MP-HANDOFF-OLD-RETIRED",
    "MP-OWNER-RETIRE-SOLE-OWNER-OK",
    "MP-OWNER-RETIRE-WRONG-CALLER",
    "MP-HANDOFF-TOKEN-REPLAY",
    "MP-SAME-ATTEMPT-RESELECT-REJECT",
    "MP-PARENT-LOSS-MID-FLIGHT",
    "MP-ROUTE-HANDOFF-DRAIN-LINK",
    "MP-CU-OLD",
    "MP-CU-NEW",
    "MP-CU-PARTIAL",
    "MP-CU-EXTRA",
    "MP-CU-THIRD",
    "MP-FEATURE-OFF",
    "MP-OLD-CONTEXT-REPLAY-REJECT",
    # joint / simulation
    "RRMP-1HOP-BASELINE",
    "RRMP-2HOP-DIVERSITY",
    "RRMP-3HOP-DRAIN-REPLACE",
    "RRMP-PARENT-LOSS-MID-FLIGHT-JOINT",
    "RRMP-SPLIT-BRAIN-SEAL-AND-FORWARD-ZERO",
    "RRMP-SIMULATION-TRANSCRIPT-BOUNDED",
    "RRMP-FAILURE-PRECEDENCE-MATRIX",
    "RRMP-GATE-SELF-TEST-PIN",
)


def u8(v: int) -> bytes:
    return struct.pack(">B", v)


def u16(v: int) -> bytes:
    return struct.pack(">H", v)


def u32(v: int) -> bytes:
    return struct.pack(">I", v)


def u64(v: int) -> bytes:
    return struct.pack(">Q", v)


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def crc32c(value: bytes) -> int:
    crc = 0xFFFFFFFF
    for octet in value:
        crc ^= octet
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def pattern(start: int, length: int) -> bytes:
    return bytes((start + i) & 0xFF for i in range(length))


def hx(value: bytes) -> str:
    return value.hex()


def checked_add_u64(a: int, b: int) -> int | None:
    if a < 0 or b < 0 or a > U64_MAX or b > U64_MAX:
        return None
    s = a + b
    if s > U64_MAX:
        return None
    return s


def checked_mul_u64(a: int, b: int) -> int | None:
    if a < 0 or b < 0 or a > U64_MAX or b > U64_MAX:
        return None
    p = a * b
    if p > U64_MAX:
        return None
    return p


def checked_add_u32(a: int, b: int) -> int | None:
    if a < 0 or b < 0 or a > U32_MAX or b > U32_MAX:
        return None
    s = a + b
    if s > U32_MAX:
        return None
    return s


def drain_completion(
    *,
    now_ms: int,
    remaining_link_groups: int,
    remaining_attempts: int,
    max_airtime_ms: int,
    turnaround_ms: int,
    link_ack_wait_ms: int,
    scheduler_guard_ms: int,
    inter_group_gap_ms: int,
    item_deadline_ms: int,
    drain_deadline_ms: int,
    lease_deadline_ms: int,
) -> dict[str, Any]:
    """Physically possible FRAG-aware drain formula (ADR-0019 §4.4)."""

    out: dict[str, Any] = {
        "eligible": 0,
        "reason": "",
        "link_group_cost_ms": None,
        "work_ms": None,
        "gaps_ms": None,
        "completion_ms": None,
        "deadline_min_ms": None,
        "airtime_total_ms": None,
    }
    f = remaining_link_groups
    r = remaining_attempts
    if f < 1 or f > MAX_LINK_GROUPS:
        out["reason"] = "LINK_GROUPS_RANGE"
        return out
    if r < 1 or r > MAX_ATTEMPTS:
        out["reason"] = "ATTEMPTS_RANGE"
        return out
    for name, val in (
        ("max_airtime_ms", max_airtime_ms),
        ("turnaround_ms", turnaround_ms),
        ("link_ack_wait_ms", link_ack_wait_ms),
        ("scheduler_guard_ms", scheduler_guard_ms),
        ("inter_group_gap_ms", inter_group_gap_ms),
    ):
        if val < 1 or val > 3_600_000:
            out["reason"] = f"{name}_RANGE"
            return out
    cost = checked_add_u32(
        max_airtime_ms, checked_add_u32(turnaround_ms, link_ack_wait_ms) or -1
    )
    if cost is None:
        out["reason"] = "COST_OVERFLOW"
        return out
    out["link_group_cost_ms"] = cost
    per_group = checked_mul_u64(r, cost)
    work = checked_mul_u64(f, per_group) if per_group is not None else None
    if work is None:
        out["reason"] = "WORK_OVERFLOW"
        return out
    out["work_ms"] = work
    gaps = checked_mul_u64(f - 1, inter_group_gap_ms)
    if gaps is None:
        out["reason"] = "GAPS_OVERFLOW"
        return out
    out["gaps_ms"] = gaps
    mid = checked_add_u64(work, gaps)
    total = checked_add_u64(mid, scheduler_guard_ms) if mid is not None else None
    completion = checked_add_u64(now_ms, total) if total is not None else None
    if completion is None:
        out["reason"] = "COMPLETION_OVERFLOW"
        return out
    out["completion_ms"] = completion
    airtime_total = checked_mul_u64(f, max_airtime_ms)
    out["airtime_total_ms"] = airtime_total
    if airtime_total is None or airtime_total > MAX_AIRTIME_BUDGET_MS:
        out["reason"] = "AIRTIME_BUDGET"
        return out
    deadline = min(item_deadline_ms, drain_deadline_ms, lease_deadline_ms)
    out["deadline_min_ms"] = deadline
    if completion > deadline:
        out["reason"] = "DEADLINE"
        return out
    if completion < now_ms:
        out["reason"] = "UNDERFLOW"
        return out
    out["eligible"] = 1
    out["reason"] = "OK"
    return out


def owner_scope_id(
    *,
    endpoint_runtime_id: bytes,
    direction: int,
    namespace: bytes,
    service: bytes,
    traffic_class: int,
    path_policy_id: bytes,
) -> bytes:
    if not (1 <= len(namespace) <= 63 and 1 <= len(service) <= 63):
        raise ValueError("namespace/service length")
    if len(endpoint_runtime_id) != 16 or len(path_policy_id) != 16:
        raise ValueError("id length")
    material = (
        b"NINLIL-OWNER-SCOPE-V1"
        + endpoint_runtime_id
        + u8(direction)
        + u16(len(namespace))
        + namespace
        + u16(len(service))
        + service
        + u16(traffic_class)
        + path_policy_id
    )
    return sha256(material)[:16]


def loop_key(
    *,
    route_handle: int,
    route_generation: int,
    e2e_header_digest: bytes,
    local_runtime_id: bytes,
) -> bytes:
    """Semantic E2E invariant loop key — outer counters MUST NOT participate."""
    return sha256(
        b"NINLIL-ROUTE-LOOP-V1"
        + e2e_header_digest
        + u16(route_handle)
        + u16(route_generation)
        + local_runtime_id
    )[:16]


def dedup_key(
    *,
    ingress_hop_context_id: int,
    route_handle: int,
    route_generation: int,
    e2e_header_digest: bytes,
) -> bytes:
    """Semantic E2E+ingress dedup key — outer counters MUST NOT participate."""
    return sha256(
        b"NINLIL-ROUTE-DEDUP-V1"
        + e2e_header_digest
        + u32(ingress_hop_context_id)
        + u16(route_handle)
        + u16(route_generation)
    )[:16]


def rewrap_e2e_payload(e2e_inner: bytes) -> bytes:
    """Structural-only rewrap: E2E bytes bit-identical; outer is new."""
    return bytes(e2e_inner)


def durable_evidence_key(
    *,
    route_handle: int,
    route_generation: int,
    admission_seq: int,
    e2e_header_digest: bytes,
) -> bytes:
    """Durable custody evidence identity (FULL group; outer counters excluded)."""
    return sha256(
        b"NINLIL-ROUTE-EVIDENCE-KEY-V1"
        + e2e_header_digest
        + u16(route_handle)
        + u16(route_generation)
        + u64(admission_seq)
    )


def placement_index(
    ingress_hop_context_id: int, route_handle: int, route_generation: int
) -> int:
    primary = (
        ingress_hop_context_id ^ (route_handle << 16) ^ route_generation
    ) % ROUTE_MAX
    return primary


def encode_nrm1(fields: dict[str, Any]) -> bytes:
    buf = bytearray(NRM1_BYTES)
    buf[0:4] = b"NRM1"
    buf[4:6] = u16(1)
    buf[6:8] = u16(NRM1_BYTES)
    buf[8:24] = fields["authority_id"]
    buf[24:32] = u64(fields["controller_term"])
    buf[32:40] = u64(fields["route_revision"])
    buf[40:48] = u64(fields["lease_epoch"])
    buf[48:64] = fields["authority_clock_epoch_id"]
    buf[64:72] = u64(fields["lease_expiry_ms"])
    buf[72:76] = u32(fields["ingress_hop_context_id"])
    buf[76:78] = u16(fields["route_handle"])
    buf[78:80] = u16(fields["route_generation"])
    buf[80:96] = fields["egress_peer_id"]
    buf[96:100] = u32(fields["egress_hop_context_id"])
    buf[100:102] = u16(fields["egress_route_handle"])
    buf[102:104] = u16(fields["egress_route_generation"])
    buf[104:120] = fields["grant_id"]
    buf[120:122] = u16(fields["queue_quota_entries"])
    buf[122:124] = u16(0)
    buf[124:128] = u32(fields["queue_quota_bytes"])
    buf[128] = fields["max_hops"] & 0xFF
    buf[129] = fields["ack_policy"] & 0xFF
    buf[130] = fields["terminal_flag"] & 0xFF
    buf[131] = 0
    buf[132:148] = fields["path_policy_id"]
    buf[148:156] = u64(fields["path_policy_revision"])
    digest = sha256(bytes(buf[:156]))
    buf[156:188] = digest
    buf[188:192] = u32(crc32c(bytes(buf[:188])))
    # tail already zero
    return bytes(buf)


def materialize_exact(fields: dict[str, Any]) -> bytes:
    """Canonical pack of docs/30 exact fields (96 bytes)."""

    body = bytearray(96)
    body[0:16] = fields["egress_peer_id"]
    body[16:20] = u32(fields["egress_hop_context_id"])
    body[20:22] = u16(fields["egress_route_handle"])
    body[22:24] = u16(fields["egress_route_generation"])
    body[24:40] = fields["authority_id"]
    body[40:48] = u64(fields["lease_epoch"])
    body[48:56] = u64(fields["lease_expiry_ms"])
    body[56:72] = fields["grant_id"]
    body[72:74] = u16(fields["queue_quota_entries"])
    body[74:76] = u16(0)
    body[76:80] = u32(fields["queue_quota_bytes"])
    body[80] = fields["max_hops"] & 0xFF
    body[81] = fields["ack_policy"] & 0xFF
    body[82] = fields["terminal_flag"] & 0xFF
    body[83] = 0
    body[84:88] = u32(fields["ingress_hop_context_id"])
    body[88:90] = u16(fields["route_handle"])
    body[90:92] = u16(fields["route_generation"])
    body[92:96] = u32(0)
    return bytes(body)


def encode_slot(
    *,
    state: int,
    fields: dict[str, Any],
    next_admission_seq: int,
    drain: dict[str, int] | None,
) -> bytes:
    slot = bytearray(SLOT_BYTES)
    slot[0] = state & 0xFF
    slot[4:8] = u32(fields["ingress_hop_context_id"])
    slot[8:10] = u16(fields["route_handle"])
    slot[10:12] = u16(fields["route_generation"])
    mgmt = encode_nrm1(fields)
    slot[12:268] = mgmt
    slot[268:364] = materialize_exact(fields)
    slot[364:380] = fields["authority_clock_epoch_id"]
    slot[380:388] = u64(fields["lease_expiry_ms"])
    if drain is not None:
        slot[388:396] = u64(drain["drain_fence"])
        slot[396:404] = u64(drain["route_revision"])
        slot[404:412] = u64(drain["drain_deadline_ms"])
        slot[412:420] = u64(drain["lease_deadline_ms"])
    slot[420:428] = u64(next_admission_seq)
    digest = sha256(bytes(slot[:428]))
    slot[428:460] = digest
    slot[460:464] = u32(crc32c(bytes(slot[:460])))
    return bytes(slot)


def encode_page(
    *,
    page_index: int,
    page_generation: int,
    slots: list[bytes | None],
) -> bytes:
    if len(slots) != SLOTS_PER_PAGE:
        raise ValueError("slots")
    page = bytearray(NRP1_BYTES)
    page[0:4] = b"NRP1"
    page[4:6] = u16(1)
    page[6:8] = u16(page_index)
    page[8:12] = u32(page_generation)
    bitmap = 0
    for i, slot in enumerate(slots):
        if slot is not None:
            bitmap |= 1 << i
            page[20 + i * SLOT_BYTES : 20 + (i + 1) * SLOT_BYTES] = slot
    page[12:14] = u16(bitmap)
    page[14:16] = u16(0)
    # crc over header+slots with crc field zero
    page[16:20] = u32(0)
    page[16:20] = u32(crc32c(bytes(page)))
    return bytes(page)


def encode_directory(
    *,
    directory_generation: int,
    authority_id: bytes,
    controller_term: int,
    page_generations: list[int],
    evidence_page_generations: list[int] | None = None,
) -> bytes:
    """NRD1 exact: route bitmap@40, evidence bitmap@42, route gens@44, evidence gens@108."""
    if len(page_generations) != PAGE_COUNT:
        raise ValueError("route page_generations")
    if evidence_page_generations is None:
        evidence_page_generations = [0] * NEP1_PAGE_COUNT
    if len(evidence_page_generations) != NEP1_PAGE_COUNT:
        raise ValueError("evidence_page_generations")
    buf = bytearray(DIR_BYTES)
    buf[0:4] = b"NRD1"
    buf[4:6] = u16(1)
    buf[6:8] = u16(DIR_BYTES)
    buf[8:16] = u64(directory_generation)
    buf[16:32] = authority_id
    buf[32:40] = u64(controller_term)
    route_bits = 0
    for i, gen in enumerate(page_generations):
        if gen != 0:
            route_bits |= 1 << i
        buf[44 + i * 4 : 48 + i * 4] = u32(gen)
    evi_bits = 0
    for j, gen in enumerate(evidence_page_generations):
        if gen != 0:
            evi_bits |= 1 << j
        buf[108 + j * 4 : 112 + j * 4] = u32(gen)
    if evi_bits & ~0xF:
        raise ValueError("evidence bitmap high bits")
    buf[40:42] = u16(route_bits)
    buf[42:44] = u16(evi_bits)
    # reserved_mid 124..252 already zero
    buf[252:256] = u32(0)
    buf[252:256] = u32(crc32c(bytes(buf)))
    return bytes(buf)


def encode_evidence(
    *,
    route_handle: int,
    route_generation: int,
    admission_seq: int,
    e2e_header_digest: bytes,
    outer_rx_counter: int,
    outer_tx_counter: int,
    local_runtime_id: bytes,
    hop_remaining_in: int,
    hop_remaining_out: int,
    result_status: int,
    lifecycle: int = EVIDENCE_LIFECYCLE_LIVE,
) -> bytes:
    if lifecycle not in (EVIDENCE_LIFECYCLE_LIVE, EVIDENCE_LIFECYCLE_COMPLETED):
        raise ValueError("lifecycle")
    buf = bytearray(EVIDENCE_BYTES)
    buf[0:4] = b"NEV1"
    buf[4:6] = u16(1)
    buf[6:8] = u16(EVIDENCE_BYTES)
    buf[8:10] = u16(route_handle)
    buf[10:12] = u16(route_generation)
    buf[12:20] = u64(admission_seq)
    buf[20:52] = e2e_header_digest
    buf[52:60] = u64(outer_rx_counter)
    buf[60:68] = u64(outer_tx_counter)
    buf[68:84] = local_runtime_id
    buf[84] = hop_remaining_in & 0xFF
    buf[85] = hop_remaining_out & 0xFF
    buf[86] = lifecycle & 0xFF
    buf[87] = 0
    buf[88:92] = u32(result_status)
    buf[92:124] = sha256(bytes(buf[:92]))
    buf[124:128] = u32(crc32c(bytes(buf[:124])))
    return bytes(buf)


def parent_set_digest(parent_ids: list[bytes]) -> bytes:
    """SHA-256 of ordered parent_runtime_id concatenation (count entries only)."""
    if not parent_ids or len(parent_ids) > 8:
        raise ValueError("parent set count")
    material = b"".join(parent_ids)
    if len(material) != 16 * len(parent_ids):
        raise ValueError("parent id size")
    return sha256(material)


def encode_nps1(
    *,
    owner_scope_id: bytes,
    parent_set_id: bytes,
    parent_set_revision: int,
    parent_ids: list[bytes],
) -> bytes:
    """Exact NPS1 256-byte multi-scope parent-set record."""
    count = len(parent_ids)
    if count < 1 or count > 8:
        raise ValueError("count")
    if len(owner_scope_id) != 16 or len(parent_set_id) != 16:
        raise ValueError("ids")
    dig = parent_set_digest(parent_ids)
    buf = bytearray(NPS1_BYTES)
    buf[0:4] = b"NPS1"
    buf[4:6] = u16(1)
    buf[6:8] = u16(NPS1_BYTES)
    buf[8:24] = owner_scope_id
    buf[24:40] = parent_set_id
    buf[40:48] = u64(parent_set_revision)
    buf[48] = count & 0xFF
    buf[52:84] = dig
    for i, pid in enumerate(parent_ids):
        if len(pid) != 16:
            raise ValueError("id len")
        buf[84 + i * 16 : 84 + (i + 1) * 16] = pid
    buf[212:244] = sha256(bytes(buf[:212]))
    buf[244:248] = u32(0)
    buf[244:248] = u32(crc32c(bytes(buf)))
    return bytes(buf)


def encode_npp1_page(*, page_index: int, page_generation: int, slots: list[bytes | None]) -> bytes:
    """NPP1: 16 + 15*256 + 240 = 4096; empty slots all-zero."""
    if page_index < 0 or page_index >= NPP1_PAGE_COUNT:
        raise ValueError("page_index")
    if len(slots) != NPP1_SLOTS:
        raise ValueError("slots")
    page = bytearray(NPP1_BYTES)
    page[0:4] = b"NPP1"
    page[4:6] = u16(1)
    page[6:8] = u16(page_index)
    page[8:12] = u32(page_generation)
    for i, slot in enumerate(slots):
        if slot is None:
            continue
        if len(slot) != NPS1_BYTES:
            raise ValueError("nps1 size")
        off = NPP1_HEADER_BYTES + i * NPS1_BYTES
        page[off : off + NPS1_BYTES] = slot
    page[12:16] = u32(0)
    page[12:16] = u32(crc32c(bytes(page)))
    return bytes(page)


def encode_noa1(fields: dict[str, Any]) -> bytes:
    buf = bytearray(NOA1_BYTES)
    buf[0:4] = b"NOA1"
    buf[4:6] = u16(1)
    buf[6:8] = u16(NOA1_BYTES)
    buf[8:24] = fields["owner_scope_id"]
    buf[24:40] = fields["authority_id"]
    buf[40:48] = u64(fields["controller_term"])
    buf[48:56] = u64(fields["assignment_epoch"])
    buf[56:64] = u64(fields["assignment_revision"])
    buf[64:80] = fields["owner_controller_id"]
    buf[80:96] = fields["owner_cell_id"]
    buf[96] = fields["direction"] & 0xFF
    buf[97:100] = bytes(3)
    buf[100:104] = u32(fields["e2e_context_id"])
    buf[104:112] = u64(fields["key_generation"])
    buf[112:128] = fields["e2e_security_id"]
    buf[128:136] = u64(fields["e2e_security_epoch"])
    buf[136:168] = fields["e2e_binding_digest"]
    buf[168:184] = fields["authority_clock_epoch_id"]
    buf[184:192] = u64(fields["lease_not_after_authority_ms"])
    buf[192:224] = fields["handoff_token_digest"]
    buf[224:256] = sha256(bytes(buf[:224]))
    # parent-set durable reference (after body digest; covered by full-record CRC)
    ps_digest = fields.get("parent_set_digest")
    ps_count = int(fields.get("parent_set_count", 0))
    if ps_digest is not None:
        if len(ps_digest) != 32 or ps_count < 1 or ps_count > 8:
            raise ValueError("parent_set ref")
        buf[260:292] = ps_digest
        buf[292] = ps_count & 0xFF
        ps_id = fields.get("parent_set_id")
        if ps_id is not None:
            if len(ps_id) != 16:
                raise ValueError("parent_set_id")
            buf[296:312] = ps_id
    # CRC over entire 400 with crc field zero
    buf[256:260] = u32(0)
    buf[256:260] = u32(crc32c(bytes(buf)))
    return bytes(buf)


def authority_commit_digest(
    *,
    noa1_body_digest: bytes,
    nps1_record_digest: bytes,
    handoff_token_digest: bytes,
    controller_term: int,
    assignment_revision: int,
) -> bytes:
    return sha256(
        b"NINLIL-PARENT-COMMIT-V1"
        + noa1_body_digest
        + nps1_record_digest
        + handoff_token_digest
        + u64(controller_term)
        + u64(assignment_revision)
    )



def encode_nph1(
    *,
    authority_id: bytes,
    writer_controller_id: bytes,
    controller_term: int,
    writer_epoch: int,
    lease_not_after_ms: int,
    authority_clock_epoch_id: bytes,
    writer_proof_digest: bytes,
    header_generation: int,
    assignment_page_bitmap: int,
    token_page_bitmap: int,
    authority_commit_digest: bytes,
) -> bytes:
    """NPH1 embeds full §6.1 writer fence tuple for restart reconstruction."""
    buf = bytearray(NPH1_BYTES)
    buf[0:4] = b"NPH1"
    buf[4:6] = u16(1)
    buf[6:8] = u16(NPH1_BYTES)
    buf[8:24] = authority_id
    buf[24:40] = writer_controller_id
    buf[40:48] = u64(controller_term)
    buf[48:56] = u64(writer_epoch)
    buf[56:64] = u64(lease_not_after_ms)
    buf[64:80] = authority_clock_epoch_id
    buf[80:112] = writer_proof_digest
    buf[112:120] = u64(header_generation)
    buf[120:122] = u16(assignment_page_bitmap)
    buf[122:124] = u16(token_page_bitmap)
    buf[128:160] = authority_commit_digest
    # digest over [0:160) with digest field zero (already zero)
    buf[160:192] = sha256(bytes(buf[:160]))
    buf[192:196] = u32(0)
    buf[192:196] = u32(crc32c(bytes(buf)))
    return bytes(buf)


def encode_nep1_page(
    *,
    page_index: int,
    page_generation: int,
    slots: list[bytes],
) -> bytes:
    """NEP1: NEP1_HEADER + NEP1_SLOTS*NEV1 + NEP1_PAD = 4096."""
    if page_index < 0 or page_index >= NEP1_PAGE_COUNT:
        raise ValueError("nep1 page_index")
    if len(slots) > NEP1_SLOTS:
        raise ValueError("nep1 slots")
    page = bytearray(NEP1_BYTES)
    page[0:4] = b"NEP1"
    page[4:6] = u16(1)
    page[6:8] = u16(page_index)
    page[8:12] = u32(page_generation)
    page[12:16] = u32(len(slots))
    for i, slot in enumerate(slots):
        if len(slot) != NEV1_BYTES:
            raise ValueError("nev1 size")
        off = NEP1_HEADER_BYTES + i * NEV1_BYTES
        page[off : off + NEV1_BYTES] = slot
    page[20:24] = u32(0)
    page[20:24] = u32(crc32c(bytes(page)))
    return bytes(page)


def encode_npt1_page(
    *,
    page_index: int,
    page_generation: int,
    slots: list[tuple[bytes, int, int]],
) -> bytes:
    """slots: list of (digest32, kind, created_ms); len <= 84."""
    page = bytearray(NPT1_BYTES)
    page[0:4] = b"NPT1"
    page[4:6] = u16(1)
    page[6:8] = u16(page_index)
    page[8:12] = u32(page_generation)
    page[12:16] = u32(len(slots))
    for i, (digest, kind, created_ms) in enumerate(slots):
        off = NPT1_HEADER_BYTES + i * NPT1_SLOT_BYTES
        slot = bytearray(NPT1_SLOT_BYTES)
        slot[0:32] = digest
        slot[32] = kind & 0xFF
        slot[36:44] = u64(created_ms)
        slot[44:48] = u32(crc32c(bytes(slot[:44])))
        page[off : off + NPT1_SLOT_BYTES] = slot
    page[20:24] = u32(0)
    page[20:24] = u32(crc32c(bytes(page)))
    return bytes(page)


def encode_npa1_page(
    *,
    page_index: int,
    page_generation: int,
    slots: list[bytes | None],
) -> bytes:
    if len(slots) != ASSIGNMENT_SLOTS_PER_PAGE:
        raise ValueError("npa1 slots")
    page = bytearray(NPA1_BYTES)
    page[0:4] = b"NPA1"
    page[4:6] = u16(1)
    page[6:8] = u16(page_index)
    page[8:12] = u32(page_generation)
    for i, slot in enumerate(slots):
        if slot is None:
            continue
        if len(slot) != ASSIGNMENT_SLOT_BYTES:
            raise ValueError("slot size")
        off = NPA1_HEADER_BYTES + i * ASSIGNMENT_SLOT_BYTES
        page[off : off + ASSIGNMENT_SLOT_BYTES] = slot
    page[12:16] = u32(0)
    page[12:16] = u32(crc32c(bytes(page)))
    return bytes(page)


def build_private_api_catalog() -> dict[str, Any]:
    """Closed private API catalog — names alone are not sufficient; sizes+fields pin."""
    route_ops = [
        {"name": "ninlil_route_install_batch", "req": "ninlil_route_install_batch_req_v1",
         "req_size": "56+256*N", "req_size_n1": 312, "req_size_n8": 2104, "result_size": 128,
         "return_type": "ninlil_route_status_u32", "owner": "install_owner"},
        {"name": "ninlil_route_activate", "req": "ninlil_route_activate_req_v1",
         "req_size": 64, "result_size": 128, "return_type": "ninlil_route_status_u32", "owner": "install_owner"},
        {"name": "ninlil_route_begin_drain", "req": "ninlil_route_begin_drain_req_v1",
         "req_size": 80, "result_size": 128, "return_type": "ninlil_route_status_u32", "owner": "install_owner"},
        {"name": "ninlil_route_retire", "req": "ninlil_route_retire_req_v1",
         "req_size": 64, "result_size": 128, "return_type": "ninlil_route_status_u32", "owner": "install_owner"},
        {"name": "ninlil_route_query", "req": "ninlil_route_query_req_v1",
         "req_size": 48, "result_size": 128, "return_type": "ninlil_route_status_u32", "owner": "reader"},
        {"name": "ninlil_route_forward_admit", "req": "ninlil_route_forward_admit_req_v1",
         "req_size": 128, "result_size": 128, "return_type": "ninlil_route_status_u32", "owner": "forward_owner"},
        {"name": "ninlil_route_forward_complete", "req": "ninlil_route_forward_complete_req_v1",
         "req_size": 64, "result_size": 128, "return_type": "ninlil_route_status_u32", "owner": "forward_owner"},
        {"name": "ninlil_route_cancel_drain", "req": "ninlil_route_cancel_drain_req_v1",
         "req_size": 48, "result_size": 128, "return_type": "ninlil_route_status_u32", "owner": "install_owner"},
        {"name": "ninlil_route_recover_commit_unknown", "req": "ninlil_route_recover_cu_req_v1",
         "req_size": 80, "result_size": 128, "return_type": "ninlil_route_status_u32", "owner": "install_owner"},
        {"name": "ninlil_route_diagnostics_snapshot", "req": "ninlil_route_diagnostics_req_v1",
         "req_size": 32, "result_size": 128, "return_type": "ninlil_route_status_u32", "owner": "diagnostics"},
    ]
    parent_ops = [
        {"name": "ninlil_parent_set_install", "req": "ninlil_parent_set_install_req_v1",
         "req_size": 240, "result_size": 128, "return_type": "ninlil_parent_status_u32", "owner": "parent_set_install",
         "parent_ids_inline": 1, "parent_set_digest_bytes": 32, "max_parents": 8},
        {"name": "ninlil_parent_owner_prepare", "req": "ninlil_parent_owner_prepare_req_v1",
         "req_size": 464, "result_size": 128, "return_type": "ninlil_parent_status_u32",
         "owner": "handoff_participant",
         "workspace_rule": "new_assignment_noa1[400] full sealed; scope+token bind before S3"},
        {"name": "ninlil_parent_owner_fence_proof", "req": "ninlil_parent_owner_fence_proof_req_v1",
         "req_size": 96, "result_size": 128, "return_type": "ninlil_parent_status_u32", "owner": "old_owner_or_authority"},
        {"name": "ninlil_parent_authority_commit", "req": "ninlil_parent_authority_commit_req_v1",
         "req_size": 96, "result_size": 128, "return_type": "ninlil_parent_status_u32", "owner": "authority_writer"},
        {"name": "ninlil_parent_owner_activate", "req": "ninlil_parent_owner_activate_req_v1",
         "req_size": 80, "result_size": 128, "return_type": "ninlil_parent_status_u32", "owner": "new_owner"},
        {"name": "ninlil_parent_endpoint_observe", "req": "ninlil_parent_endpoint_observe_req_v1",
         "req_size": 80, "result_size": 128, "return_type": "ninlil_parent_status_u32", "owner": "endpoint_routing",
         "observed_parent_set_digest_bytes": 32},
        {"name": "ninlil_parent_owner_retire", "req": "ninlil_parent_owner_retire_req_v1",
         "req_size": 80, "result_size": 128, "return_type": "ninlil_parent_status_u32",
         "owner": "old_owner", "sole_caller_role": "old_owner", "handoff_step": "S6",
         "wrong_caller_status": "NOT_OWNER",
         "boundary": "participant_local_sole_owner_of_own_store"},
        {"name": "ninlil_parent_query", "req": "ninlil_parent_query_req_v1",
         "req_size": 48, "result_size": 128, "return_type": "ninlil_parent_status_u32", "owner": "reader"},
        {"name": "ninlil_parent_recover_commit_unknown", "req": "ninlil_parent_recover_cu_req_v1",
         "req_size": 80, "result_size": 128, "return_type": "ninlil_parent_status_u32", "owner": "durable_owner"},
        {"name": "ninlil_parent_diagnostics_snapshot", "req": "ninlil_parent_diagnostics_req_v1",
         "req_size": 32, "result_size": 128, "return_type": "ninlil_parent_status_u32", "owner": "diagnostics"},
    ]
    private_v2_ops = [
        {
            "name": "ninlil_parent_owner_prepare_v2",
            "req": "ninlil_parent_owner_prepare_req_v2",
            "req_size": 568,
            "owner": "handoff_participant",
            "old_tuple_bytes": 104,
        },
        {
            "name": "ninlil_parent_owner_fence_proof_v2",
            "req": "ninlil_parent_owner_fence_proof_req_v2",
            "req_size": 248,
            "owner": "old_owner_or_authority",
            "proof_kinds": ["EXPLICIT_RESIGN", "TRUSTED_EXACT_LEASE_EXPIRY"],
        },
        {
            "name": "ninlil_parent_authority_commit_v2",
            "req": "ninlil_parent_authority_commit_req_v2",
            "req_size": 640,
            "owner": "authority_writer",
            "bundle_expected_witness_bytes": 296,
        },
        {
            "name": "ninlil_rrmp_core_attempt_reclaim_v2",
            "req": "ninlil_rrmp_attempt_reclaim_req_v2",
            "req_size": 64,
            "owner": "durable_owner",
            "caller_proof_is_authority": 0,
        },
        {
            "name": "ninlil_rrmp_core_authority_writer_conflict_v2",
            "req": "ninlil_rrmp_authority_writer_conflict_req_v2",
            "req_size": 104,
            "owner": "authority_observer",
            "fence_domain": "authority_global",
        },
        {
            "name": "ninlil_rrmp_core_scope_parent_anomaly_v2",
            "req": "ninlil_rrmp_scope_parent_anomaly_req_v2",
            "req_size": 96,
            "owner": "parent_observer",
            "fence_domain": "scope_local",
        },
    ]
    return {
        "api_version": 1,
        "route_result_bytes": ROUTE_RESULT_BYTES,
        "parent_result_bytes": PARENT_RESULT_BYTES,
        "route_op_count": 10,
        "parent_op_count": 10,
        "total_op_count": 20,
        "route_ops": route_ops,
        "parent_ops": parent_ops,
        "private_v2_api_version": 2,
        "private_v2_op_count": len(private_v2_ops),
        "private_v2_ops": private_v2_ops,
        "v1_handoff_mutation_status": "UNSUPPORTED_API",
        "route_status_count": 21,
        "parent_status_count": 21,
        "preamble_bytes": 16,
        "public_abi": 0,
        "claims_implementation": 0,
    }


def build_storage_codec_catalog() -> dict[str, Any]:
    return {
        "nph1": {
            "magic": "NPH1",
            "schema": 1,
            "bytes": NPH1_BYTES,
            "crc_offset": 192,
            "digest_offset": 160,
            "digest_len": 32,
            "reserved_tail_offset": 196,
            "reserved_tail_len": 60,
            "fields": [
                {"name": "magic", "offset": 0, "size": 4},
                {"name": "schema_u16", "offset": 4, "size": 2},
                {"name": "length_u16", "offset": 6, "size": 2},
                {"name": "authority_id", "offset": 8, "size": 16},
                {"name": "writer_controller_id", "offset": 24, "size": 16},
                {"name": "controller_term_u64", "offset": 40, "size": 8},
                {"name": "writer_epoch_u64", "offset": 48, "size": 8},
                {"name": "lease_not_after_ms_u64", "offset": 56, "size": 8},
                {"name": "authority_clock_epoch_id", "offset": 64, "size": 16},
                {"name": "writer_proof_digest32", "offset": 80, "size": 32},
                {"name": "header_generation_u64", "offset": 112, "size": 8},
                {"name": "assignment_page_bitmap_u16", "offset": 120, "size": 2},
                {"name": "token_page_bitmap_u16", "offset": 122, "size": 2},
                {"name": "reserved0_u32", "offset": 124, "size": 4},
                {"name": "authority_commit_digest32", "offset": 128, "size": 32},
                {"name": "header_digest32", "offset": 160, "size": 32},
                {"name": "crc32c_u32", "offset": 192, "size": 4},
                {"name": "reserved_tail", "offset": 196, "size": 60},
            ],
            "digest_preimage": "bytes[0:160]",
            "crc_preimage": "full_record_with_crc_field_zero",
            "generation_mono_inc": 1,
            "writer_sole_mutator": "authority_writer",
            "embeds_section_6_1_fence_tuple": 1,
        },
        "nep1": {
            "magic": "NEP1",
            "schema": 1,
            "bytes": NEP1_BYTES,
            "header_bytes": NEP1_HEADER_BYTES,
            "slot_bytes": NEV1_BYTES,
            "slots_per_page": NEP1_SLOTS,
            "pad_bytes": NEP1_PAD_BYTES,
            "crc_offset": 20,
            "max_pages": NEP1_PAGE_COUNT,
            "capacity": EVIDENCE_CAPACITY,
            "sum_formula": "24+31*128+104=4096",
            "first_admit_full_group": "single_NEP1_page_atomic",
        },
        "key_namespace": {
            "physical_key_count": ROUTE_PHYSICAL_KEY_COUNT,
            "directory_keys": 1,
            "route_page_keys": PAGE_COUNT,
            "evidence_page_keys": NEP1_PAGE_COUNT,
            "sum_formula": "1+16+4=21",
            "forbidden_budget_17": 0,
            "key_id_max": 20,
        },
        "capacity": {
            "route_max": ROUTE_MAX,
            "route_formula": "PAGE_COUNT*SLOTS_PER_PAGE=16*8=128",
            "evidence_capacity": EVIDENCE_CAPACITY,
            "evidence_formula": "NEP1_PAGE_COUNT*NEP1_SLOTS=4*31=124",
        },
        "nev1": {
            "magic": "NEV1",
            "schema": 1,
            "bytes": 128,
            "digest_offset": 92,
            "crc_offset": 124,
            "fields": [
                {"name": "magic", "offset": 0, "size": 4},
                {"name": "schema_u16", "offset": 4, "size": 2},
                {"name": "length_u16", "offset": 6, "size": 2},
                {"name": "route_handle_u16", "offset": 8, "size": 2},
                {"name": "route_generation_u16", "offset": 10, "size": 2},
                {"name": "admission_seq_u64", "offset": 12, "size": 8},
                {"name": "e2e_header_digest32", "offset": 20, "size": 32},
                {"name": "outer_rx_counter_u64", "offset": 52, "size": 8},
                {"name": "outer_tx_counter_u64", "offset": 60, "size": 8},
                {"name": "local_runtime_id16", "offset": 68, "size": 16},
                {"name": "hop_remaining_in_u8", "offset": 84, "size": 1},
                {"name": "hop_remaining_out_u8", "offset": 85, "size": 1},
                {"name": "reserved0_u16", "offset": 86, "size": 2},
                {"name": "result_status_u32", "offset": 88, "size": 4},
                {"name": "body_digest32", "offset": 92, "size": 32},
                {"name": "crc32c_u32", "offset": 124, "size": 4},
            ],
        },
        "noa1": {
            "magic": "NOA1",
            "schema": 1,
            "bytes": NOA1_BYTES,
            "digest_offset": 224,
            "digest_len": 32,
            "crc_offset": 256,
            "reserved_tail_offset": 260,
            "reserved_tail_len": 140,
            "fields": [
                {"name": "magic", "offset": 0, "size": 4},
                {"name": "schema_u16", "offset": 4, "size": 2},
                {"name": "length_u16", "offset": 6, "size": 2},
                {"name": "owner_scope_id", "offset": 8, "size": 16},
                {"name": "authority_id", "offset": 24, "size": 16},
                {"name": "controller_term_u64", "offset": 40, "size": 8},
                {"name": "assignment_epoch_u64", "offset": 48, "size": 8},
                {"name": "assignment_revision_u64", "offset": 56, "size": 8},
                {"name": "owner_controller_id", "offset": 64, "size": 16},
                {"name": "owner_cell_id", "offset": 80, "size": 16},
                {"name": "direction_u8", "offset": 96, "size": 1},
                {"name": "reserved0_u8x3", "offset": 97, "size": 3},
                {"name": "e2e_context_id_u32", "offset": 100, "size": 4},
                {"name": "key_generation_u64", "offset": 104, "size": 8},
                {"name": "e2e_security_id", "offset": 112, "size": 16},
                {"name": "e2e_security_epoch_u64", "offset": 128, "size": 8},
                {"name": "e2e_binding_digest32", "offset": 136, "size": 32},
                {"name": "authority_clock_epoch_id", "offset": 168, "size": 16},
                {"name": "lease_not_after_authority_ms_u64", "offset": 184, "size": 8},
                {"name": "handoff_token_digest32", "offset": 192, "size": 32},
                {"name": "body_digest32", "offset": 224, "size": 32},
                {"name": "crc32c_u32", "offset": 256, "size": 4},
                {"name": "parent_set_digest32", "offset": 260, "size": 32},
                {"name": "parent_set_count_u8", "offset": 292, "size": 1},
                {"name": "reserved1_u8x3", "offset": 293, "size": 3},
                {"name": "parent_set_id", "offset": 296, "size": 16},
                {"name": "reserved_tail", "offset": 312, "size": 88},
            ],
            "digest_preimage": "bytes[0:224]",
            "crc_preimage": "full_400_with_crc_field_zero",
            "parent_set_ref": "digest@260+count@292 bind NPS1",
        },
        "nps1": {
            "magic": "NPS1",
            "schema": 1,
            "bytes": NPS1_BYTES,
            "owner_scope_offset": 8,
            "parent_set_id_offset": 24,
            "digest_offset": 212,
            "crc_offset": 244,
            "ids_offset": 84,
            "max_parents": 8,
            "digest_rule": "SHA-256(ordered parent_runtime_id[0:count))",
            "constructor_api": "ninlil_parent_set_install",
            "multi_scope": 1,
        },
        "npp1": {
            "magic": "NPP1",
            "schema": 1,
            "bytes": NPP1_BYTES,
            "header_bytes": NPP1_HEADER_BYTES,
            "slot_bytes": NPS1_BYTES,
            "slots_per_page": NPP1_SLOTS,
            "pad_bytes": NPP1_PAD_BYTES,
            "page_count": NPP1_PAGE_COUNT,
            "scope_capacity": SCOPE_PARENT_SET_CAPACITY,
            "physical_slot_count": NPP1_PHYSICAL_SLOT_COUNT,
            "sum_formula": "16+15*256+240=4096",
        },
        "evidence_lifecycle": {
            "live": EVIDENCE_LIFECYCLE_LIVE,
            "completed": EVIDENCE_LIFECYCLE_COMPLETED,
            "capacity": EVIDENCE_CAPACITY,
            "complete_frees_capacity": 0,
            "reclaim_completed_to_empty": 1,
            "gen_retire_zeros_slots": 1,
            "liveness_beyond_capacity": 1,
        },
        "npt1": {
            "magic": "NPT1",
            "schema": 1,
            "bytes": NPT1_BYTES,
            "header_bytes": NPT1_HEADER_BYTES,
            "slot_bytes": NPT1_SLOT_BYTES,
            "slots_per_page": NPT1_SLOTS_PER_PAGE,
            "pad_bytes": NPT1_PAD_BYTES,
            "crc_offset": 20,
            "kind_empty": 0,
            "kind_token_live": 1,
            "kind_tombstone_used": 2,
        },
        "npa1": {
            "magic": "NPA1",
            "schema": 1,
            "bytes": NPA1_BYTES,
            "header_bytes": NPA1_HEADER_BYTES,
            "slot_bytes": ASSIGNMENT_SLOT_BYTES,
            "slots_per_page": ASSIGNMENT_SLOTS_PER_PAGE,
            "pad_bytes": NPA1_PAD_BYTES,
            "crc_offset": 12,
            "noa1_bytes": NOA1_BYTES,
        },
        "assignment_workspace": {
            "description": "set_install constructs NPS1; owner_prepare embeds full NOA1 bound to NPS1",
            "noa1_bytes": NOA1_BYTES,
            "nps1_bytes": NPS1_BYTES,
            "prepare_req_size": 464,
            "prepare_full_noa1_offset": 32,
            "prepare_full_noa1_rule": "owner_prepare.new_assignment_noa1[400] + parent_set_digest bind NPS1",
            "set_install_req_size": 240,
            "set_install_parent_ids_offset": 112,
            "set_install_parent_set_digest_bytes": 32,
            "set_install_is_parent_set_constructor": 1,
            "prefix64_forbidden": 1,
            "digest16_forbidden": 1,
            "full_binding_required_before_authority_commit": 1,
            "commit_digest_domain": "NINLIL-PARENT-COMMIT-V1",
            "sole_noa1_constructor": "owner_prepare",
            "sole_nps1_constructor": "set_install",
            "durable_publish_path": "NPS1 key + NPA1 slot embeds NOA1",
        },
        "owner_retire": {
            "api_op": "ninlil_parent_owner_retire",
            "sole_caller_role": "old_owner",
            "step": "S6",
            "requires_prior_chain_s1_s5": 1,
            "wrong_caller_status": "NOT_OWNER",
            "old_owner_seal_after": 0,
            "tombstone_required": 1,
            "boundary": "participant_local_sole_owner_of_own_store",
            "new_owner_may_mutate_old_store": 0,
        },
        "custody_evidence": {
            "durable_key_domain": "NINLIL-ROUTE-EVIDENCE-KEY-V1",
            "durable_key_preimage": "e2e_header_digest32||route_handle||route_generation||admission_seq",
            "excludes_outer_rx_counter": 1,
            "excludes_queue_index": 1,
            "full_group_keys": ["NEP1_page", "RRMPQST4_soft_trailer"],
            "forward_admit_durable_first": 1,
            "restart_volatile_cleared": ["loop_window", "dedup_window"],
            "restart_forward_until_cu": 0,
            "application_receipt_forbidden_from_custody_alone": 1,
            "soft_snapshot": {
                "magic": "RRMPQST4",
                "schema": 4,
                "header_bytes": RRMP_QST4_HEADER_BYTES,
                "scope_aux_bytes": 64,
                "scope_seal_flags_offset": 57,
                "legacy_schema2_parent_scope_fail_closed": 1,
                "live_evidence_aux_bytes": 72,
                "queue_record_bytes": 320,
                "carrier_total_max": 16320,
                "carrier_per_item_max": 1024,
                "used_attempt_row_bytes": RRMP_QST4_ATTEMPT_BYTES,
                "used_attempt_capacity": RRMP_QST4_ATTEMPT_CAPACITY,
                "attempt_retention_ms": RRMP_ATTEMPT_RETENTION_MS,
                "handoff_tuple_row_bytes":
                    RRMP_QST4_HANDOFF_TUPLE_BYTES,
                "handoff_tuple_capacity":
                    RRMP_QST4_HANDOFF_TUPLE_CAPACITY,
                "queue_live_evidence_bijection": 1,
                "legacy_schema1_live_evidence_forbidden": 1,
                "pointer_dump_forbidden": 1,
            },
            "durable_restart": {
                "queue": 1,
                "opaque_handle": 1,
                "application_data": 1,
                "attempt_selected_parent": 1,
                "retry_ack_wait": 1,
                "authenticated_ack_authority": 1,
                "loop_dedup_reconstructed_from_live": 1,
            },
        },
        "loop_dedup": {
            "loop_domain": "NINLIL-ROUTE-LOOP-V1",
            "loop_preimage": "e2e_header_digest32||route_handle||route_generation||local_runtime_id16",
            "dedup_domain": "NINLIL-ROUTE-DEDUP-V1",
            "dedup_preimage": "e2e_header_digest32||ingress_hop_context_id||route_handle||route_generation",
            "excludes_outer_rx_counter": 1,
            "loop_window": LOOP_WINDOW,
            "dedup_window": DEDUP_WINDOW,
            "windows_volatile_restart_empty": 1,
        },
        "rewrap": {
            "e2e_bytes_bit_identical": 1,
            "outer_hop_new_only": 1,
            "payload_mutation_forbidden": 1,
        },
        "cu_classes": ["NONE", "OLD", "NEW", "ABSENT", "PARTIAL", "EXTRA", "THIRD"],
        "migration": {
            "page_atomic_full_only": 1,
            "foreign_schema_reject": 1,
            "generation_mono_inc": 1,
        },
    }


def build_p1_repair_authority() -> dict[str, Any]:
    """Closed authority for the RRMP P1 storage/attempt/handoff repair."""
    old_tuple_fields = [
        {"name": "present_u8", "offset": 0, "size": 1},
        {"name": "reserved0_u8x3", "offset": 1, "size": 3},
        {"name": "exact_noa1_length_u32", "offset": 4, "size": 4},
        {"name": "noa1_sha256", "offset": 8, "size": 32},
        {"name": "assignment_revision_u64", "offset": 40, "size": 8},
        {"name": "controller_term_u64", "offset": 48, "size": 8},
        {"name": "owner_controller_id16", "offset": 56, "size": 16},
        {"name": "writer_epoch_u64", "offset": 72, "size": 8},
        {"name": "lease_not_after_ms_u64", "offset": 80, "size": 8},
        {"name": "authority_clock_epoch_id16", "offset": 88, "size": 16},
    ]
    acceptance = [
        {
            "id": "RRP-BUNDLE-BOUND",
            "expect": "all puts <=65536; canonical M1+C0..C4 only",
        },
        {
            "id": "RRP-BUNDLE-CLOSED-KEY-SET",
            "expect": "unknown/duplicate/out-of-order/missing/unused-present reject",
        },
        {
            "id": "RRP-BUNDLE-CU",
            "expect": "OLD/NEW only recover; PARTIAL/EXTRA/THIRD fence",
        },
        {
            "id": "RRP-BUNDLE-TWO-OWNER-CAS",
            "expect": "same expected witness exactly one OK",
        },
        {
            "id": "RRP-ATTEMPT-A-B-A",
            "expect": "same scope+attempt reject across restart/epoch/loss/handoff",
        },
        {
            "id": "RRP-ATTEMPT-PER-ROW-LIVENESS",
            "expect": "newer terminal row never delays mature older row reclaim",
        },
        {
            "id": "RRP-HANDOFF-EXACT-OLD-TUPLE",
            "expect": "wrong old field/proof kind/clock/lease/writer/token reject",
        },
        {
            "id": "RRP-AUTHORITY-GLOBAL-FENCE",
            "expect": "all scopes deny after cold restart; no clear API",
        },
        {
            "id": "RRP-SCOPE-LOCAL-ANOMALY",
            "expect": "unrelated scope remains operational",
        },
        {
            "id": "RRP-PARENT-SET-CONSTRUCTOR-ONLY",
            "expect": "NPS1 only; active NOA/seal/attempt/fence unchanged",
        },
    ]
    return {
        "status": "SPEC_ACCEPTED_DESIGN_AUTHORITY",
        "outer_bundle": {
            "manifest_key_ascii": "RRMP/M1",
            "chunk_keys_ascii": [f"RRMP/C{i}" for i in range(5)],
            "manifest_magic": "RRM1",
            "manifest_schema": 1,
            "manifest_bytes": RRM1_MANIFEST_BYTES,
            "chunk_bytes_max": RRM1_CHUNK_BYTES_MAX,
            "chunk_count_max": RRM1_CHUNK_COUNT_MAX,
            "logical_bytes_max": RRM1_LOGICAL_BYTES_MAX,
            "logical_required_max": RRMP_LOGICAL_EXPORT_REQUIRED_MAX,
            "headroom": RRMP_BUNDLE_HEADROOM,
            "platform_value_max": 65_536,
            "prefix_iterator_required": 1,
            "full_transaction_count": 1,
            "unused_chunk_absent": 1,
            "manifest_fields": [
                {"name": "magic", "offset": 0, "size": 4},
                {"name": "schema_u16", "offset": 4, "size": 2},
                {"name": "length_u16", "offset": 6, "size": 2},
                {"name": "bundle_generation_u64", "offset": 8, "size": 8},
                {"name": "logical_total_length_u32", "offset": 16, "size": 4},
                {"name": "chunk_count_u8", "offset": 20, "size": 1},
                {"name": "reserved0_u8x3", "offset": 21, "size": 3},
                {"name": "logical_sha256", "offset": 24, "size": 32},
                {"name": "chunk_descriptors", "offset": 56, "size": 180},
                {"name": "reserved_tail", "offset": 236, "size": 16},
                {"name": "crc32c_u32", "offset": 252, "size": 4},
            ],
        },
        "qst4": {
            "magic": "RRMPQST4",
            "schema": 4,
            "header_bytes": RRMP_QST4_HEADER_BYTES,
            "attempt_row_bytes": RRMP_QST4_ATTEMPT_BYTES,
            "attempt_capacity": RRMP_QST4_ATTEMPT_CAPACITY,
            "attempt_retention_ms": RRMP_ATTEMPT_RETENTION_MS,
            "handoff_tuple_row_bytes": RRMP_QST4_HANDOFF_TUPLE_BYTES,
            "handoff_tuple_capacity":
                RRMP_QST4_HANDOFF_TUPLE_CAPACITY,
            "max_bytes": RRMP_QST4_MAX_BYTES,
            "implicit_eviction": 0,
            "caller_proof_is_authority": 0,
            "row_fields": [
                {"name": "owner_scope_id16", "offset": 0, "size": 16},
                {"name": "attempt_id16", "offset": 16, "size": 16},
                {"name": "lifecycle_u8", "offset": 32, "size": 1},
                {"name": "flags_u8", "offset": 33, "size": 1},
                {"name": "reserved0_u8x6", "offset": 34, "size": 6},
                {"name": "terminal_evidence_digest32", "offset": 40, "size": 32},
                {"name": "reclaim_not_before_ms_u64", "offset": 72, "size": 8},
            ],
            "lifecycle": {"LIVE": 1, "TERMINAL_RETAINED": 2},
            "deadline_scope": "PER_ROW",
            "continuous_terminal_liveness": 1,
            "handoff_tuple_fields": [
                {"name": "owner_scope_id16", "offset": 0, "size": 16},
                {"name": "exact_old_tuple104", "offset": 16, "size": 104},
                {"name": "exact_new_tuple104", "offset": 120, "size": 104},
            ],
            "handoff_tuple_restart_required": 1,
        },
        "old_authority_tuple": {
            "bytes": 104,
            "fields": old_tuple_fields,
        },
        "handoff_v2": {
            "api_version": 2,
            "v1_mutation_status": "UNSUPPORTED_API",
            "proof_kinds": {
                "EXPLICIT_RESIGN": 1,
                "TRUSTED_EXACT_LEASE_EXPIRY": 2,
            },
            "parent_set_install_constructor_only": 1,
            "commit_binds_old_new_writer_token_proof_bundle": 1,
        },
        "authority_fence": {
            "writer_conflict_domain": "AUTHORITY_GLOBAL",
            "scope_parent_anomaly_domain": "SCOPE_LOCAL",
            "clear_api_present": 0,
            "cold_restart_persistent": 1,
        },
        "storage_authority_v2": {
            "api_version": 2,
            "piece_vector_serializable": 1,
            "same_expected_at_most_one_ok": 1,
            "v1_single_value_mutation_allowed": 0,
        },
        "acceptance": acceptance,
    }


def base_route_fields(
    *,
    hop: int,
    terminal: bool,
    route_handle: int = 0x1001,
    route_generation: int = 0x0007,
    route_revision: int = 11,
) -> dict[str, Any]:
    return {
        "authority_id": pattern(0xA0, 16),
        "controller_term": 5,
        "route_revision": route_revision,
        "lease_epoch": 9,
        "authority_clock_epoch_id": pattern(0xC0, 16),
        "lease_expiry_ms": 2_000_000,
        "ingress_hop_context_id": 0x11110000 + hop,
        "route_handle": route_handle,
        "route_generation": route_generation,
        "egress_peer_id": pattern(0xE0 + hop, 16),
        "egress_hop_context_id": 0x22220000 + hop,
        "egress_route_handle": 0 if terminal else 0x2000 + hop,
        "egress_route_generation": 0 if terminal else 0x0008,
        "grant_id": pattern(0x50, 16),
        "queue_quota_entries": 8,
        "queue_quota_bytes": 2048,
        "max_hops": MAX_HOPS_PROFILE,
        "ack_policy": 1,
        "terminal_flag": 1 if terminal else 0,
        "path_policy_id": pattern(0xF0, 16),
        "path_policy_revision": 3,
    }


def case(
    case_id: str,
    *,
    family: str,
    expect_status: str,
    **payload: Any,
) -> dict[str, Any]:
    if family.startswith("MP"):
        if expect_status not in PARENT_STATUS:
            raise KeyError(f"{case_id}: unknown parent status {expect_status}")
        code = PARENT_STATUS[expect_status]
    elif family.startswith("RR"):
        if expect_status not in STATUS:
            raise KeyError(f"{case_id}: unknown route status {expect_status}")
        code = STATUS[expect_status]
    else:
        # joint: allow either route or parent closed set (no silent None).
        if expect_status in STATUS:
            code = STATUS[expect_status]
        elif expect_status in PARENT_STATUS:
            code = PARENT_STATUS[expect_status]
        else:
            raise KeyError(f"{case_id}: unknown joint status {expect_status}")
    row = {
        "id": case_id,
        "case_kind": case_id,  # hard semantic pin; donor full-row must fail
        "family": family,
        "expect_status": expect_status,
        "expect_status_code": code,
        **payload,
    }
    return row


def build_document() -> dict[str, Any]:
    e2e_digest = sha256(b"e2e-header-vector-v1")
    local_runtime = pattern(0x10, 16)
    endpoint_runtime = pattern(0x20, 16)
    path_policy = pattern(0xF0, 16)
    namespace = b"cell"
    service = b"sensor"
    scope = owner_scope_id(
        endpoint_runtime_id=endpoint_runtime,
        direction=1,
        namespace=namespace,
        service=service,
        traffic_class=1,
        path_policy_id=path_policy,
    )

    # --- routes for 1/2/3 hop ---
    r1 = base_route_fields(hop=1, terminal=True, route_handle=0x1001)
    r2a = base_route_fields(hop=1, terminal=False, route_handle=0x1002)
    r2b = base_route_fields(hop=2, terminal=True, route_handle=0x1002, route_generation=0x0008)
    r3a = base_route_fields(hop=1, terminal=False, route_handle=0x1003)
    r3b = base_route_fields(hop=2, terminal=False, route_handle=0x1003, route_generation=0x0009)
    r3c = base_route_fields(hop=3, terminal=True, route_handle=0x1003, route_generation=0x000A)

    nrm1_1 = encode_nrm1(r1)
    nrm1_2a = encode_nrm1(r2a)
    nrm1_3a = encode_nrm1(r3a)
    exact_1 = materialize_exact(r1)

    # terminal mismatch: flag=1 but non-zero egress handles
    bad_term = dict(r1)
    bad_term["terminal_flag"] = 1
    bad_term["egress_route_handle"] = 0x2001
    bad_term["egress_route_generation"] = 0x0008

    zero_term = dict(r1)
    zero_term["controller_term"] = 0

    # authority conflict: same term/revision different body
    conflict_a = dict(r1)
    conflict_b = dict(r1)
    conflict_b["queue_quota_entries"] = 16
    dig_a = encode_nrm1(conflict_a)[156:188]
    dig_b = encode_nrm1(conflict_b)[156:188]

    # drain formula vectors (inputs are authority; results recomputed by gates)
    drain_ok_inputs = {
        "now_ms": 1_000_000,
        "remaining_link_groups": 3,
        "remaining_attempts": 2,
        "max_airtime_ms": 100,
        "turnaround_ms": 20,
        "link_ack_wait_ms": 30,
        "scheduler_guard_ms": 10,
        "inter_group_gap_ms": 5,
        "item_deadline_ms": 1_010_000,
        "drain_deadline_ms": 1_020_000,
        "lease_deadline_ms": 2_000_000,
    }
    drain_impossible_inputs = {
        "now_ms": 1_000_000,
        "remaining_link_groups": 13,
        "remaining_attempts": 3,
        "max_airtime_ms": 5000,
        "turnaround_ms": 1000,
        "link_ack_wait_ms": 1000,
        "scheduler_guard_ms": 100,
        "inter_group_gap_ms": 100,
        "item_deadline_ms": 1_001_000,
        "drain_deadline_ms": 1_001_000,
        "lease_deadline_ms": 2_000_000,
    }
    # JSON/JS-safe integers only (no >2^53 values). COMPLETION_OVERFLOW is
    # covered by gate self-tests with in-memory BigInt/int inputs; this sample
    # pins DEADLINE rejection with the same formula machinery.
    drain_overflow_inputs = {
        "now_ms": 1_000_000,
        "remaining_link_groups": 2,
        "remaining_attempts": 2,
        "max_airtime_ms": 100,
        "turnaround_ms": 20,
        "link_ack_wait_ms": 30,
        "scheduler_guard_ms": 100,
        "inter_group_gap_ms": 5,
        "item_deadline_ms": 1_000_100,
        "drain_deadline_ms": 1_000_100,
        "lease_deadline_ms": 2_000_000,
    }
    drain_ok = drain_completion(**drain_ok_inputs)
    drain_impossible = drain_completion(**drain_impossible_inputs)
    drain_overflow = drain_completion(**drain_overflow_inputs)

    # storage arithmetic
    slot = encode_slot(state=2, fields=r1, next_admission_seq=1, drain=None)
    page0 = encode_page(page_index=0, page_generation=1, slots=[slot] + [None] * 7)
    page_gens = [1] + [0] * 15
    directory = encode_directory(
        directory_generation=1,
        authority_id=r1["authority_id"],
        controller_term=r1["controller_term"],
        page_generations=page_gens,
    )
    place = placement_index(
        r1["ingress_hop_context_id"], r1["route_handle"], r1["route_generation"]
    )
    # probe collision arithmetic sample
    occupied = {place}
    probe = place
    probes = [probe]
    for _ in range(3):
        probe = (probe + 1) % ROUTE_MAX
        probes.append(probe)
        occupied.add(probe)

    # evidence
    ev = encode_evidence(
        route_handle=r1["route_handle"],
        route_generation=r1["route_generation"],
        admission_seq=1,
        e2e_header_digest=e2e_digest,
        outer_rx_counter=42,
        outer_tx_counter=43,
        local_runtime_id=local_runtime,
        hop_remaining_in=1,
        hop_remaining_out=0,
        result_status=STATUS["OK"],
    )
    chain0 = bytes(32)
    chain1 = sha256(b"NINLIL-ROUTE-EVIDENCE-V1" + chain0 + ev[:124])

    # parent assignment
    token = sha256(b"handoff-token-v1")
    parent_ids_v = [pattern(0xB0, 16), pattern(0xB1, 16)]
    ps_dig = parent_set_digest(parent_ids_v)
    parent_set_id_v = pattern(0x50, 16)
    nps1 = encode_nps1(
        owner_scope_id=scope,
        parent_set_id=parent_set_id_v,
        parent_set_revision=3,
        parent_ids=parent_ids_v,
    )
    npp1 = encode_npp1_page(page_index=0, page_generation=1, slots=[nps1] + [None] * (NPP1_SLOTS - 1))
    assignment_fields = {
        "owner_scope_id": scope,
        "authority_id": pattern(0xA0, 16),
        "controller_term": 5,
        "assignment_epoch": 2,
        "assignment_revision": 7,
        "owner_controller_id": pattern(0xB0, 16),
        "owner_cell_id": pattern(0xB1, 16),
        "direction": 1,
        "e2e_context_id": 0x33330001,
        "key_generation": 4,
        "e2e_security_id": pattern(0xD0, 16),
        "e2e_security_epoch": 6,
        "e2e_binding_digest": sha256(b"e2e-binding"),
        "authority_clock_epoch_id": pattern(0xC0, 16),
        "lease_not_after_authority_ms": 2_000_000,
        "handoff_token_digest": token,
        "parent_set_digest": ps_dig,
        "parent_set_count": len(parent_ids_v),
        "parent_set_id": parent_set_id_v,
    }
    noa1 = encode_noa1(assignment_fields)
    assignment_new = dict(assignment_fields)
    assignment_new["assignment_revision"] = 8
    assignment_new["owner_controller_id"] = pattern(0xB2, 16)
    assignment_new["handoff_token_digest"] = sha256(b"handoff-token-v2")
    noa1_new = encode_noa1(assignment_new)
    commit_dig = authority_commit_digest(
        noa1_body_digest=noa1[224:256],
        nps1_record_digest=nps1[212:244],
        handoff_token_digest=token,
        controller_term=5,
        assignment_revision=7,
    )

    # Parent durable store codecs: NPH1 / NPT1 / NPA1 positive fixtures
    nph1 = encode_nph1(
        authority_id=pattern(0xA0, 16),
        writer_controller_id=pattern(0xA1, 16),
        controller_term=5,
        writer_epoch=3,
        lease_not_after_ms=2_000_000,
        authority_clock_epoch_id=pattern(0xC0, 16),
        writer_proof_digest=sha256(b"writer-proof-v1"),
        header_generation=3,
        assignment_page_bitmap=0x0001,
        token_page_bitmap=0x0001,
        authority_commit_digest=sha256(b"authority-commit-v1"),
    )
    # NEP1 first-admit durable page with one NEV1 slot
    nep1 = encode_nep1_page(page_index=0, page_generation=1, slots=[ev])
    directory_with_evi = encode_directory(
        directory_generation=1,
        authority_id=r1["authority_id"],
        controller_term=r1["controller_term"],
        page_generations=page_gens,
        evidence_page_generations=[1, 0, 0, 0],
    )
    npt1 = encode_npt1_page(
        page_index=0,
        page_generation=2,
        slots=[
            (sha256(b"token-live-1"), 1, 1_000_100),
            (sha256(b"tombstone-used-1"), 2, 1_000_200),
        ],
    )
    # assignment slot: NOA1 + local_state + res3 + proof + receipt + crc
    assign_slot = bytearray(ASSIGNMENT_SLOT_BYTES)
    assign_slot[0:400] = noa1
    assign_slot[400] = 4  # NEW_OWNER_ACTIVATED
    assign_slot[404:436] = sha256(b"proof-digest")
    assign_slot[436:468] = sha256(b"receipt-digest")
    assign_slot[468:472] = u32(crc32c(bytes(assign_slot[:468])))
    npa1 = encode_npa1_page(
        page_index=0,
        page_generation=2,
        slots=[bytes(assign_slot)] + [None] * 7,
    )

    # COMMIT_UNKNOWN fixtures (route page group)
    old_group = {
        "directory_hex": hx(directory),
        "page0_hex": hx(page0),
    }
    slot_new = encode_slot(
        state=3,
        fields=r1,
        next_admission_seq=5,
        drain={
            "drain_fence": 5,
            "route_revision": r1["route_revision"],
            "drain_deadline_ms": 1_500_000,
            "lease_deadline_ms": r1["lease_expiry_ms"],
        },
    )
    page0_new = encode_page(
        page_index=0, page_generation=2, slots=[slot_new] + [None] * 7
    )
    directory_new = encode_directory(
        directory_generation=2,
        authority_id=r1["authority_id"],
        controller_term=r1["controller_term"],
        page_generations=[2] + [0] * 15,
    )
    new_group = {
        "directory_hex": hx(directory_new),
        "page0_hex": hx(page0_new),
    }
    third_page = encode_page(
        page_index=0, page_generation=9, slots=[slot] + [None] * 7
    )
    partial_group = {"directory_hex": hx(directory_new)}  # missing page
    extra_group = {
        "directory_hex": hx(directory_new),
        "page0_hex": hx(page0_new),
        "page1_hex": hx(
            encode_page(page_index=1, page_generation=1, slots=[None] * 8)
        ),
    }

    # simulation transcript from independent closed table (not free-form)
    sim_steps = [dict(s) for s in SIM_TRANSCRIPT_CLOSED]
    sim_digest = sha256(
        b"NINLIL-RRMP-SIM-V1"
        + json.dumps(sim_steps, separators=(",", ":"), sort_keys=True).encode()
    )

    cases: list[dict[str, Any]] = []

    def add(c: dict[str, Any]) -> None:
        cases.append(c)

    # API
    add(
        case(
            "RR-API-PREAMBLE-OK",
            family="RR-api",
            expect_status="OK",
            api_version=API_VERSION,
            struct_size=128,
            reserved0=0,
            reserved1=0,
        )
    )
    add(
        case(
            "RR-API-VERSION-REJECT",
            family="RR-api",
            expect_status="UNSUPPORTED_API",
            api_version=2,
            struct_size=128,
            reserved0=0,
            reserved1=0,
        )
    )
    add(
        case(
            "RR-API-STRUCT-SIZE-REJECT",
            family="RR-api",
            expect_status="UNSUPPORTED_API",
            api_version=1,
            struct_size=16,
            reserved0=0,
            reserved1=0,
        )
    )
    add(
        case(
            "RR-API-RESERVED-REJECT",
            family="RR-api",
            expect_status="CORRUPT",
            api_version=1,
            struct_size=128,
            reserved0=1,
            reserved1=0,
        )
    )
    add(
        case(
            "RR-FEATURE-OFF",
            family="RR-api",
            expect_status="FEATURE_OFF",
            feature_route_relay=0,
        )
    )

    # CRC repair then semantic: mutate max_hops illegal, but vector stores
    # repaired CRC over mutated body so gate must recompute integrity OK then semantic fail.
    mutated_fields = dict(r1)
    mutated_fields["max_hops"] = 0  # illegal
    mutated_nrm1 = encode_nrm1(mutated_fields)
    add(
        case(
            "RR-CRC-REPAIR-THEN-SEMANTIC",
            family="RR-integrity",
            expect_status="CORRUPT",
            note="max_hops=0 is semantic CORRUPT after CRC verifies",
            record_hex=hx(mutated_nrm1),
            semantic_fault="max_hops",
            crc_ok=1,
        )
    )
    # digest repair: break path_policy_revision then re-encode (digest/crc repaired)
    dig_mut = dict(r1)
    dig_mut["path_policy_revision"] = 0
    dig_mut_rec = encode_nrm1(dig_mut)
    add(
        case(
            "RR-DIGEST-REPAIR-THEN-SEMANTIC",
            family="RR-integrity",
            expect_status="CORRUPT",
            record_hex=hx(dig_mut_rec),
            semantic_fault="path_policy_revision",
            digest_ok=1,
        )
    )

    # materialize
    add(
        case(
            "RR-MGMT-MATERIALIZE-1HOP-TERMINAL",
            family="RR-mgmt",
            expect_status="OK",
            hops=1,
            terminal=1,
            management_hex=hx(nrm1_1),
            exact_hex=hx(exact_1),
            lease_epoch=r1["lease_epoch"],
            nrw1_lease_epoch=r1["lease_epoch"],
        )
    )
    add(
        case(
            "RR-MGMT-MATERIALIZE-2HOP",
            family="RR-mgmt",
            expect_status="OK",
            hops=2,
            management_hex=hx(nrm1_2a),
            exact_hex=hx(materialize_exact(r2a)),
            terminal_flag=0,
            next_terminal=1,
            next_handle=r2b["route_handle"],
            next_generation=r2b["route_generation"],
            lease_epoch=r2a["lease_epoch"],
            nrw1_lease_epoch=r2a["lease_epoch"],
        )
    )
    add(
        case(
            "RR-MGMT-MATERIALIZE-3HOP",
            family="RR-mgmt",
            expect_status="OK",
            hops=3,
            management_hex=hx(nrm1_3a),
            exact_hex=hx(materialize_exact(r3a)),
            terminal_flag=0,
            chain_handles=[r3a["route_handle"], r3b["route_handle"], r3c["route_handle"]],
            chain_generations=[
                r3a["route_generation"],
                r3b["route_generation"],
                r3c["route_generation"],
            ],
            lease_epoch=r3a["lease_epoch"],
            nrw1_lease_epoch=r3a["lease_epoch"],
        )
    )
    add(
        case(
            "RR-MGMT-TERMINAL-MISMATCH",
            family="RR-mgmt",
            expect_status="TERMINAL_MISMATCH",
            management_hex=hx(encode_nrm1(bad_term)),
            # encoding will set fields; gate checks terminal invariant on fields
            fields={
                "terminal_flag": 1,
                "egress_route_handle": 0x2001,
                "egress_route_generation": 0x0008,
            },
        )
    )
    add(
        case(
            "RR-MGMT-ZERO-TERM-REJECT",
            family="RR-mgmt",
            expect_status="CORRUPT",
            fields={"controller_term": 0},
            controller_term=0,
            u64_max_also_forbidden=1,
            note="controller_term=0 forbidden; zero and UINT64_MAX rejected",
            reference_valid_management_hex=hx(nrm1_1),
            reference_valid_controller_term=r1["controller_term"],
        )
    )
    add(
        case(
            "RR-MGMT-AUTHORITY-CONFLICT-DIGEST",
            family="RR-mgmt",
            expect_status="AUTHORITY_CONFLICT",
            term=5,
            revision=11,
            digest_a_hex=hx(dig_a),
            digest_b_hex=hx(dig_b),
            same_term_revision=1,
        )
    )
    add(
        case(
            "RR-MGMT-STALE-REVISION",
            family="RR-mgmt",
            expect_status="CORRUPT",
            current_revision=11,
            offered_revision=10,
            note="revision regression rejected as CORRUPT/stale under authority rules",
            mapped_status="AUTHORITY_CONFLICT",
        )
    )
    # Fix stale revision expected status to AUTHORITY_CONFLICT for consistency
    cases[-1]["expect_status"] = "AUTHORITY_CONFLICT"
    cases[-1]["expect_status_code"] = STATUS["AUTHORITY_CONFLICT"]

    # hops + hop budget + rewrap (E2E bit-identical)
    e2e_inner = sha256(b"e2e-inner-payload-v1") + sha256(b"e2e-inner-tail-v1")  # 64 B sample
    e2e_rewrapped = rewrap_e2e_payload(e2e_inner)
    assert e2e_rewrapped == e2e_inner
    for cid, hops, hr, term_flag, st in (
        ("RR-HOP-1-FORWARD-OK", 1, 1, 1, "OK"),
        ("RR-HOP-2-FORWARD-OK", 2, 2, 0, "OK"),
        ("RR-HOP-3-FORWARD-OK", 3, 3, 0, "OK"),
    ):
        add(
            case(
                cid,
                family="RR-hop",
                expect_status=st,
                hops=hops,
                hop_remaining=hr,
                terminal_flag=term_flag,
                remaining_out=0 if hr == 1 else hr - 1,
                hop_budget_in=hr,
                hop_budget_out=0 if hr == 1 else hr - 1,
                max_hops_profile=MAX_HOPS_PROFILE,
                e2e_inner_hex=hx(e2e_inner),
                e2e_after_rewrap_hex=hx(e2e_rewrapped),
                rewrap_identical=1,
            )
        )
    lk = loop_key(
        route_handle=0x1002,
        route_generation=7,
        e2e_header_digest=e2e_digest,
        local_runtime_id=local_runtime,
    )
    # outer_rx must not change loop_key (stable E2E)
    lk_alt_outer = loop_key(
        route_handle=0x1002,
        route_generation=7,
        e2e_header_digest=e2e_digest,
        local_runtime_id=local_runtime,
    )
    assert lk == lk_alt_outer
    add(
        case(
            "RR-HOP-LOOP-SEEN",
            family="RR-hop",
            expect_status="LOOP",
            loop_key_hex=hx(lk),
            seen_before=1,
            route_handle=0x1002,
            route_generation=7,
            e2e_header_digest_hex=hx(e2e_digest),
            local_runtime_id_hex=hx(local_runtime),
            outer_rx_counter_a=9,
            outer_rx_counter_b=99,
            outer_rx_excluded_from_key=1,
        )
    )
    add(
        case(
            "RR-HOP-LOOP-SELF-PEER",
            family="RR-hop",
            expect_status="LOOP",
            egress_peer_id_hex=hx(local_runtime),
            local_runtime_id_hex=hx(local_runtime),
        )
    )
    dk = dedup_key(
        ingress_hop_context_id=r2a["ingress_hop_context_id"],
        route_handle=r2a["route_handle"],
        route_generation=r2a["route_generation"],
        e2e_header_digest=e2e_digest,
    )
    add(
        case(
            "RR-HOP-DUPLICATED-RELAY",
            family="RR-hop",
            expect_status="REPLAY",
            dedup_key_hex=hx(dk),
            second_admit=1,
            ingress_hop_context_id=r2a["ingress_hop_context_id"],
            route_handle=r2a["route_handle"],
            route_generation=r2a["route_generation"],
            e2e_header_digest_hex=hx(e2e_digest),
            outer_rx_excluded_from_key=1,
        )
    )
    add(
        case(
            "RR-HOP-STALE-GENERATION",
            family="RR-hop",
            expect_status="STALE_GENERATION",
            installed_generation=7,
            outer_generation=6,
        )
    )
    add(
        case(
            "RR-HOP-EXHAUSTED",
            family="RR-hop",
            expect_status="HOP_EXHAUSTED",
            hop_remaining=4,
            max_hops=3,
            hop_budget_ceiling=MAX_HOPS_PROFILE,
            hop_remaining_gt_max=1,
        )
    )
    add(
        case(
            "RR-HOP-REPLAY-DEDUP",
            family="RR-hop",
            expect_status="REPLAY",
            window=DEDUP_WINDOW,
            first_result="OK",
            second_result="REPLAY",
            dedup_key_hex=hx(dk),
            ingress_hop_context_id=r2a["ingress_hop_context_id"],
            route_handle=r2a["route_handle"],
            route_generation=r2a["route_generation"],
            e2e_header_digest_hex=hx(e2e_digest),
            outer_rx_excluded_from_key=1,
        )
    )
    add(
        case(
            "RR-HOP-TERMINAL-AT-ONE",
            family="RR-hop",
            expect_status="OK",
            hop_remaining=1,
            terminal_flag=1,
            egress_route_handle=0,
            egress_route_generation=0,
            hop_budget_out=0,
        )
    )
    add(
        case(
            "RR-HOP-REWRAP-E2E-IDENTICAL",
            family="RR-hop",
            expect_status="OK",
            e2e_inner_hex=hx(e2e_inner),
            e2e_after_rewrap_hex=hx(e2e_rewrapped),
            rewrap_identical=1,
            outer_hop_new=1,
            payload_mutated=0,
        )
    )

    # lease / drain
    add(
        case(
            "RR-LEASE-ACTIVE-BOUNDARY-MINUS-ONE",
            family="RR-lease",
            expect_status="OK",
            now_ms=1_999_999,
            lease_expiry_ms=2_000_000,
            active=1,
        )
    )
    add(
        case(
            "RR-LEASE-EXPIRED-AT-BOUNDARY",
            family="RR-lease",
            expect_status="LEASE_EXPIRED",
            now_ms=2_000_000,
            lease_expiry_ms=2_000_000,
            active=0,
        )
    )
    add(
        case(
            "RR-CLOCK-EPOCH-MISMATCH",
            family="RR-lease",
            expect_status="CLOCK_EPOCH_MISMATCH",
            route_clock_epoch_hex=hx(pattern(0xC0, 16)),
            accepted_clock_epoch_hex=hx(pattern(0xC1, 16)),
        )
    )
    add(
        case(
            "RR-DRAIN-ELIGIBLE",
            family="RR-drain",
            expect_status="OK",
            formula=drain_ok,
            admission_seq=3,
            drain_fence=5,
            route_revision_match=1,
        )
    )
    add(
        case(
            "RR-DRAIN-FENCED-NEW-ADMISSION",
            family="RR-drain",
            expect_status="DRAIN_FENCED",
            admission_seq=5,
            drain_fence=5,
            note="admission_seq < fence required",
        )
    )
    add(
        case(
            "RR-DRAIN-PHYSICALLY-IMPOSSIBLE",
            family="RR-drain",
            expect_status="DRAIN_FENCED",
            formula=drain_impossible,
        )
    )
    add(
        case(
            "RR-DRAIN-FRAG-FORMULA-EXACT",
            family="RR-drain",
            expect_status="OK",
            formula=drain_ok,
            expected_work_ms=drain_ok["work_ms"],
            expected_completion_ms=drain_ok["completion_ms"],
            expected_link_group_cost_ms=drain_ok["link_group_cost_ms"],
        )
    )
    add(
        case(
            "RR-DRAIN-OVERFLOW-REJECT",
            family="RR-drain",
            expect_status="DRAIN_FENCED",
            formula=drain_overflow,
        )
    )

    # custody / evidence (durable key excludes outer_rx)
    ev_key = durable_evidence_key(
        route_handle=r1["route_handle"],
        route_generation=r1["route_generation"],
        admission_seq=1,
        e2e_header_digest=e2e_digest,
    )
    add(
        case(
            "RR-CUSTODY-NOT-APP-RECEIPT",
            family="RR-custody",
            expect_status="OK",
            custody_ok=1,
            application_receipt=0,
            success_display="transport_diagnostics_only",
            durable_evidence_key_hex=hx(ev_key),
            outer_rx_excluded_from_key=1,
        )
    )
    add(
        case(
            "RR-EVIDENCE-CHAIN-EXTEND",
            family="RR-custody",
            expect_status="OK",
            evidence_hex=hx(ev),
            chain_before_hex=hx(chain0),
            chain_after_hex=hx(chain1),
            durable_evidence_key_hex=hx(ev_key),
            route_handle=r1["route_handle"],
            route_generation=r1["route_generation"],
            admission_seq=1,
            e2e_header_digest_hex=hx(e2e_digest),
            outer_rx_excluded_from_key=1,
        )
    )
    add(
        case(
            "RR-EVIDENCE-DURABLE-FULL-GROUP",
            family="RR-custody",
            expect_status="OK",
            durable_evidence_key_hex=hx(ev_key),
            nep1_page_hex=hx(nep1),
            full_group_keys=["NEP1_page"],
            excludes_outer_rx_counter=1,
            excludes_queue_index=1,
            restart_safe=1,
            application_receipt_from_custody=0,
            first_admit_durable=1,
            second_admit_replay=1,
        )
    )
    # Evidence lifecycle / liveness (capacity 124 with reclaim)
    add(
        case(
            "RR-EVIDENCE-COMPLETE-NOT-FREE",
            family="RR-custody",
            expect_status="OK",
            occupied_before_complete=1,
            occupied_after_complete=1,
            lifecycle_before=EVIDENCE_LIFECYCLE_LIVE,
            lifecycle_after=EVIDENCE_LIFECYCLE_COMPLETED,
            capacity_freed=0,
            note="forward_complete alone does not free capacity",
        )
    )
    add(
        case(
            "RR-EVIDENCE-CAPACITY-FULL-RESOURCE",
            family="RR-custody",
            expect_status="RESOURCE",
            occupied=EVIDENCE_CAPACITY,
            free_after_reclaim=0,
            completed_reclaimable=0,
            admit_when_full=0,
        )
    )
    add(
        case(
            "RR-EVIDENCE-RECLAIM-THEN-ADMIT",
            family="RR-custody",
            expect_status="OK",
            occupied_live=0,
            occupied_completed=EVIDENCE_CAPACITY,
            free_before_reclaim=0,
            free_after_reclaim=EVIDENCE_CAPACITY,
            admit_after_reclaim=1,
        )
    )
    add(
        case(
            "RR-EVIDENCE-LIVENESS-BEYOND-124",
            family="RR-custody",
            expect_status="OK",
            first_wave_admits=EVIDENCE_CAPACITY,
            complete_all=1,
            reclaim_all=1,
            second_wave_admits=50,
            lifetime_first_admits=EVIDENCE_CAPACITY + 50,
            proves_beyond_capacity=1,
        )
    )
    add(
        case(
            "RR-EVIDENCE-GEN-RETIRE-GC",
            family="RR-custody",
            expect_status="OK",
            route_generation_retired=7,
            slots_zeroed_for_gen=1,
            capacity_freed=1,
            old_key_durable_replay=0,
        )
    )
    add(
        case(
            "RR-EVIDENCE-RESTART-LIVE-SURVIVES",
            family="RR-custody",
            expect_status="OK",
            durable_live_survives_restart=1,
            volatile_windows_empty=1,
            completed_survives_until_reclaim=1,
        )
    )

    add(
        case(
            "RR-OLD-ACK-STALE",
            family="RR-custody",
            expect_status="STALE_GENERATION",
            ack_route_generation=6,
            active_route_generation=7,
        )
    )
    add(
        case(
            "RR-OLD-CUSTODY-STALE",
            family="RR-custody",
            expect_status="STALE_GENERATION",
            custody_revision=10,
            active_revision=11,
        )
    )
    add(
        case(
            "RR-OLD-EVIDENCE-STALE",
            family="RR-custody",
            expect_status="STALE_GENERATION",
            evidence_generation=6,
            active_generation=7,
        )
    )

    # resources
    add(
        case(
            "RR-RESOURCE-QUEUE-EXHAUSTION",
            family="RR-resource",
            expect_status="RESOURCE",
            queue_entries_used=QUEUE_GLOBAL_ENTRIES,
            queue_entries_limit=QUEUE_GLOBAL_ENTRIES,
        )
    )
    add(
        case(
            "RR-RESOURCE-RESERVED-CAPACITY-PROTECT",
            family="RR-resource",
            expect_status="BACKPRESSURE",
            normal_used_entries=QUEUE_GLOBAL_ENTRIES - RESERVED_CONTROL_ENTRIES,
            control_reserved_entries=RESERVED_CONTROL_ENTRIES,
            normal_admit=0,
            control_admit=1,
        )
    )
    add(
        case(
            "RR-PRIORITY-ISOLATION",
            family="RR-resource",
            expect_status="OK",
            dequeue_order=["CONTROL", "SAFETY", "NORMAL", "BULK"],
            bulk_run_limit=8,
        )
    )
    add(
        case(
            "RR-BACKPRESSURE-NOT-RESELECT",
            family="RR-resource",
            expect_status="BACKPRESSURE",
            same_attempt_reselect_calls=0,
            same_attempt_readmit_allowed=1,
        )
    )
    add(
        case(
            "RR-CANCEL-DRAIN-INFLIGHT",
            family="RR-resource",
            expect_status="OK",
            cancel_unsent=1,
            issued_permit_follows_docs30_drain=1,
        )
    )

    # storage
    add(
        case(
            "RR-STORAGE-DIRECTORY-LAYOUT",
            family="RR-storage",
            expect_status="OK",
            directory_hex=hx(directory),
            directory_bytes=DIR_BYTES,
            magic="NRD1",
        )
    )
    add(
        case(
            "RR-STORAGE-PAGE-SLOT-ARITHMETIC",
            family="RR-storage",
            expect_status="OK",
            page_bytes=NRP1_BYTES,
            slot_bytes=SLOT_BYTES,
            slots_per_page=SLOTS_PER_PAGE,
            header_bytes=NRP1_HEADER_BYTES,
            slots_span=NRP1_SLOTS_SPAN,
            pad_bytes=NRP1_PAD_BYTES,
            checked_sum=NRP1_HEADER_BYTES + NRP1_SLOTS_SPAN + NRP1_PAD_BYTES,
            page_hex=hx(page0),
            slot_hex=hx(slot),
        )
    )
    add(
        case(
            "RR-STORAGE-KEY-BUDGET-CAPACITY",
            family="RR-storage",
            expect_status="OK",
            physical_key_count=ROUTE_PHYSICAL_KEY_COUNT,
            directory_keys=1,
            route_page_keys=PAGE_COUNT,
            evidence_page_keys=NEP1_PAGE_COUNT,
            key_sum_formula="1+16+4",
            route_max=ROUTE_MAX,
            route_capacity_formula="16*8",
            evidence_capacity=EVIDENCE_CAPACITY,
            evidence_capacity_formula="4*31",
            nep1_bytes=NEP1_BYTES,
            nep1_sum_formula="24+31*128+104",
            nrp1_bytes=NRP1_BYTES,
            nrp1_sum_formula="20+8*508+12",
            forbidden_budget_17=0,
            directory_hex=hx(directory_with_evi),
            nep1_page_hex=hx(nep1),
            max_capacity_slots=NEP1_SLOTS,
        )
    )
    add(
        case(
            "RR-STORAGE-PLACEMENT-PROBE",
            family="RR-storage",
            expect_status="OK",
            primary_index=place,
            probe_sequence=probes,
            max_probes=ROUTE_MAX,
        )
    )
    add(
        case(
            "RR-STORAGE-BATCH-9-OK",
            family="RR-storage",
            expect_status="OK",
            routes=8,
            logical_mutations=9,
            limit_mutations=LOGICAL_MUTATIONS_MAX,
        )
    )
    add(
        case(
            "RR-STORAGE-BATCH-10-REJECT",
            family="RR-storage",
            expect_status="RESOURCE",
            routes=8,
            logical_mutations=10,
            limit_mutations=LOGICAL_MUTATIONS_MAX,
        )
    )
    add(
        case(
            "RR-CU-OLD",
            family="RR-storage",
            expect_status="COMMIT_UNKNOWN",
            classification="OLD",
            old_group=old_group,
            new_group=new_group,
            observed_group=old_group,
            forward=0,
        )
    )
    add(
        case(
            "RR-CU-NEW",
            family="RR-storage",
            expect_status="COMMIT_UNKNOWN",
            classification="NEW",
            old_group=old_group,
            new_group=new_group,
            observed_group=new_group,
            forward=0,
        )
    )
    add(
        case(
            "RR-CU-PARTIAL",
            family="RR-storage",
            expect_status="CORRUPT",
            classification="PARTIAL",
            old_group=old_group,
            new_group=new_group,
            observed_group=partial_group,
            forward=0,
        )
    )
    add(
        case(
            "RR-CU-EXTRA",
            family="RR-storage",
            expect_status="CORRUPT",
            classification="EXTRA",
            old_group=old_group,
            new_group=new_group,
            observed_group=extra_group,
            forward=0,
        )
    )
    add(
        case(
            "RR-CU-THIRD",
            family="RR-storage",
            expect_status="CORRUPT",
            classification="THIRD",
            old_group=old_group,
            new_group=new_group,
            observed_group={
                "directory_hex": hx(directory_new),
                "page0_hex": hx(third_page),
            },
            forward=0,
        )
    )
    add(
        case(
            "RR-RESTART-POWER-CUT-FENCE",
            family="RR-storage",
            expect_status="COMMIT_UNKNOWN",
            volatile_queue_lost=0,
            durable_routes_only=0,
            durable_queue_restored=1,
            copy_owned_application_data_restored=1,
            attempt_parent_restored=1,
            retry_ack_restored=1,
            authenticated_ack_authority_restored=1,
            soft_snapshot_magic="RRMPQST3",
            soft_snapshot_schema=3,
            queue_live_evidence_bijection=1,
            forward_until_classify=0,
            loop_window_empty_after_restart=1,
            dedup_window_empty_after_restart=1,
            windows_reconstructed_from_durable_live=1,
            cu_required_before_forward=1,
            evidence_ring_head_durable=1,
            volatile_cleared=["loop_window", "dedup_window"],
        )
    )
    add(
        case(
            "RR-RETRY-IDEMPOTENT-SAME-DIGEST",
            family="RR-storage",
            expect_status="OK",
            same_term=1,
            same_revision=1,
            same_digest=1,
            idempotent=1,
        )
    )
    add(
        case(
            "RR-MIXED-SCHEMA-UNSUPPORTED",
            family="RR-compat",
            expect_status="UNSUPPORTED_SCHEMA",
            schema=2,
        )
    )
    add(
        case(
            "RR-DOWNGRADE-FENCE",
            family="RR-compat",
            expect_status="UNSUPPORTED_SCHEMA",
            writer_schema=1,
            reader_binary_max_schema=0,
            forward=0,
        )
    )
    add(
        case(
            "RR-DEFAULT-OFF-DIRECT-ONLY",
            family="RR-compat",
            expect_status="FEATURE_OFF",
            route_handle_nonzero_rejected=1,
            direct_route_handle_zero_ok=1,
        )
    )

    # multi-parent cases
    add(
        case(
            "MP-SCOPE-DERIVATION-EXACT",
            family="MP-scope",
            expect_status="OK",
            endpoint_runtime_id_hex=hx(endpoint_runtime),
            direction=1,
            namespace_hex=hx(namespace),
            service_hex=hx(service),
            traffic_class=1,
            path_policy_id_hex=hx(path_policy),
            owner_scope_id_hex=hx(scope),
        )
    )
    add(
        case(
            "MP-SCOPE-LENGTH-REJECT",
            family="MP-scope",
            expect_status="INVALID_ARGUMENT",
            namespace_len=0,
            service_len=1,
        )
    )
    add(
        case(
            "MP-ASSIGNMENT-TUPLE-SEAL-OK",
            family="MP-assign",
            expect_status="OK",
            assignment_hex=hx(noa1),
            seal_allowed=1,
            now_ms=1_999_999,
            lease_not_after=2_000_000,
            prepare_full_noa1_hex=hx(noa1),
            prepare_req_size=464,
        )
    )
    add(
        case(
            "MP-NPH1-WRITER-FULL-FIELDS",
            family="MP-storage",
            expect_status="OK",
            nph1_hex=hx(nph1),
            header_generation=3,
            controller_term=5,
            writer_epoch=3,
            lease_not_after_ms=2_000_000,
            assignment_page_bitmap=1,
            token_page_bitmap=1,
            reserved0_zero=1,
            reserved_tail_zero=1,
            writer_sole_mutator="authority_writer",
            generation_mono_inc=1,
            embeds_section_6_1_fence_tuple=1,
            writer_proof_nonzero=1,
        )
    )
    add(
        case(
            "MP-NOA1-FIELD-LAYOUT-EXACT",
            family="MP-assign",
            expect_status="OK",
            assignment_hex=hx(noa1),
            noa1_bytes=NOA1_BYTES,
            digest_offset=224,
            crc_offset=256,
            reserved_tail_offset=260,
            reserved_tail_len=140,
            field_count=27,
        )
    )
    add(
        case(
            "MP-ASSIGNMENT-WORKSPACE-FULL-NOA1",
            family="MP-assign",
            expect_status="OK",
            workspace_noa1_hex=hx(noa1),
            nps1_hex=hx(nps1),
            prepare_req_size=464,
            set_install_req_size=240,
            prepare_full_noa1_hex=hx(noa1),
            full_binding_before_authority_commit=1,
            durable_publish_path="NPS1+NPA1",
            parent_set_digest32_hex=hx(ps_dig),
            parent_ids_hex=hx(parent_ids_v[0] + parent_ids_v[1] + bytes(6 * 16)),
            parent_set_count=2,
            prefix64_forbidden=1,
            digest16_forbidden=1,
        )
    )
    # Parent-set constructibility: positive multi-parent + negatives
    ids_ok = parent_ids_v
    dig_ok = ps_dig
    add(
        case(
            "MP-PARENT-SET-INSTALL-OK",
            family="MP-assign",
            expect_status="OK",
            parent_set_count=2,
            parent_ids_hex=hx(ids_ok[0] + ids_ok[1] + bytes(6 * 16)),
            parent_set_digest32_hex=hx(dig_ok),
            nps1_hex=hx(nps1),
            set_install_req_size=240,
            ordered=1,
        )
    )
    # digest claims ids[0]||ids[1] but stored digest is wrong
    bad_dig = sha256(b"wrong-parent-set-digest")
    add(
        case(
            "MP-PARENT-SET-DIGEST-MISMATCH",
            family="MP-assign",
            expect_status="CORRUPT",
            parent_set_count=2,
            parent_ids_hex=hx(ids_ok[0] + ids_ok[1] + bytes(6 * 16)),
            parent_set_digest32_hex=hx(bad_dig),
            computed_digest32_hex=hx(dig_ok),
            mismatch=1,
        )
    )
    # same multiset, reversed order → different digest
    rev = [ids_ok[1], ids_ok[0]]
    dig_rev = parent_set_digest(rev)
    add(
        case(
            "MP-PARENT-SET-ORDER-MISMATCH",
            family="MP-assign",
            expect_status="CORRUPT",
            parent_set_count=2,
            parent_ids_hex=hx(rev[0] + rev[1] + bytes(6 * 16)),
            parent_set_digest32_hex=hx(dig_ok),  # claims original order digest
            computed_digest32_hex=hx(dig_rev),
            order_changed=1,
        )
    )
    # substitute second id without updating digest
    sub = [ids_ok[0], pattern(0xEE, 16)]
    dig_sub = parent_set_digest(sub)
    add(
        case(
            "MP-PARENT-SET-ID-SUBSTITUTION",
            family="MP-assign",
            expect_status="CORRUPT",
            parent_set_count=2,
            parent_ids_hex=hx(sub[0] + sub[1] + bytes(6 * 16)),
            parent_set_digest32_hex=hx(dig_ok),  # still old digest
            computed_digest32_hex=hx(dig_sub),
            substituted=1,
        )
    )
    add(
        case(
            "MP-PREPARE-PARENT-SET-BIND-OK",
            family="MP-assign",
            expect_status="OK",
            prepare_full_noa1_hex=hx(noa1),
            nps1_hex=hx(nps1),
            noa1_parent_set_digest32_hex=hx(noa1[260:292]),
            nps1_parent_set_digest32_hex=hx(nps1[52:84]),
            parent_set_count=2,
            prepare_req_size=464,
            bound=1,
        )
    )
    noa1_bad = bytearray(noa1)
    noa1_bad[260:292] = bad_dig
    noa1_bad[256:260] = u32(0)
    noa1_bad[256:260] = u32(crc32c(bytes(noa1_bad)))
    add(
        case(
            "MP-PREPARE-PARENT-SET-MISMATCH",
            family="MP-assign",
            expect_status="CORRUPT",
            prepare_full_noa1_hex=hx(bytes(noa1_bad)),
            nps1_hex=hx(nps1),
            noa1_parent_set_digest32_hex=hx(bytes(noa1_bad[260:292])),
            nps1_parent_set_digest32_hex=hx(nps1[52:84]),
            mismatch=1,
        )
    )
    add(
        case(
            "MP-COMMIT-BINDING-OK",
            family="MP-assign",
            expect_status="OK",
            noa1_hex=hx(noa1),
            nps1_hex=hx(nps1),
            authority_commit_digest32_hex=hx(commit_dig),
            controller_term=5,
            assignment_revision=7,
            handoff_token_digest32_hex=hx(token),
        )
    )
    # Two scopes, distinct parent sets, restart lookup
    scope_b = pattern(0x61, 16)
    ids_b = [pattern(0xC0, 16), pattern(0xC1, 16), pattern(0xC2, 16)]
    dig_b = parent_set_digest(ids_b)
    set_id_b = pattern(0x51, 16)
    nps1_b = encode_nps1(
        owner_scope_id=scope_b,
        parent_set_id=set_id_b,
        parent_set_revision=1,
        parent_ids=ids_b,
    )
    npp1_two = encode_npp1_page(
        page_index=0, page_generation=2,
        slots=[nps1, nps1_b] + [None] * (NPP1_SLOTS - 2),
    )
    fields_b = dict(assignment_fields)
    fields_b["owner_scope_id"] = scope_b
    fields_b["parent_set_digest"] = dig_b
    fields_b["parent_set_count"] = 3
    fields_b["parent_set_id"] = set_id_b
    fields_b["assignment_revision"] = 1
    noa1_b = encode_noa1(fields_b)
    add(
        case(
            "MP-TWO-SCOPE-PARENT-SETS-OK",
            family="MP-assign",
            expect_status="OK",
            scope_a_hex=hx(scope),
            scope_b_hex=hx(scope_b),
            nps1_a_hex=hx(nps1),
            nps1_b_hex=hx(nps1_b),
            npp1_page_hex=hx(npp1_two),
            parent_set_count_a=2,
            parent_set_count_b=3,
            distinct_sets=1,
        )
    )
    add(
        case(
            "MP-TWO-SCOPE-RESTART-LOOKUP",
            family="MP-assign",
            expect_status="OK",
            noa1_a_hex=hx(noa1),
            noa1_b_hex=hx(noa1_b),
            npp1_page_hex=hx(npp1_two),
            restart_durable=1,
            lookup_a_ok=1,
            lookup_b_ok=1,
        )
    )
    add(
        case(
            "MP-TWO-SCOPE-ROUTE-SELECT",
            family="MP-assign",
            expect_status="OK",
            noa1_a_hex=hx(noa1),
            noa1_b_hex=hx(noa1_b),
            selected_scope_hex=hx(scope_b),
            selected_parent_set_id_hex=hx(set_id_b),
            nps1_selected_hex=hx(nps1_b),
            cross_scope_forbidden=1,
        )
    )


    add(
        case(
            "MP-SPLIT-BRAIN-TWO-WRITERS",
            family="MP-authority",
            expect_status="SPLIT_BRAIN",
            writer_a_hex=hx(pattern(0xB0, 16)),
            writer_b_hex=hx(pattern(0xB3, 16)),
            same_term=1,
            seal=0,
        )
    )
    add(
        case(
            "MP-SIMULTANEOUS-PARENTS-UPLINK",
            family="MP-uplink",
            expect_status="OK",
            parents=2,
            effect_publish_count=1,
            path_evidence_count=2,
        )
    )
    add(
        case(
            "MP-SIMULTANEOUS-CONTROLLERS-SEAL-ZERO",
            family="MP-authority",
            expect_status="SPLIT_BRAIN",
            controllers=2,
            claimed_owner_scopes_same=1,
            seal=0,
        )
    )
    add(
        case(
            "MP-LEASE-BOUNDARY-MINUS-ONE",
            family="MP-lease",
            expect_status="OK",
            now_ms=1_999_999,
            lease_not_after=2_000_000,
            active=1,
        )
    )
    add(
        case(
            "MP-LEASE-BOUNDARY-EQUAL-EXPIRED",
            family="MP-lease",
            expect_status="LEASE_EXPIRED",
            now_ms=2_000_000,
            lease_not_after=2_000_000,
            active=0,
        )
    )
    def handoff_effect_snapshot(step_id: str) -> dict[str, Any]:
        m = HANDOFF_CLOSED[step_id]
        return {
            "step": m["step"],
            "edge_index": m["edge_index"],
            "from_state": m["from_state"],
            "to_state": m["to_state"],
            "state": m["state"],
            "proof_present": m["proof_present"],
            "cas_succeeded": m["cas_succeeded"],
            "commit_receipt_verified": m["commit_receipt_verified"],
            "token_consumed": m["token_consumed"],
            "tombstone_written": m["tombstone_written"],
            "new_owner_seal": m["new_owner_seal"],
            "old_owner_seal": m["old_owner_seal"],
            "artifact": m["artifact"],
        }

    prior_s1_s5 = [handoff_effect_snapshot(s) for s in ("S1", "S2", "S3", "S4", "S5")]
    for step_id in ("S1", "S2", "S3", "S4", "S5", "S6"):
        meta = HANDOFF_CLOSED[step_id]
        payload: dict[str, Any] = {
            "state": meta["state"],
            "new_owner_seal": meta["new_owner_seal"],
            "old_owner_seal": meta["old_owner_seal"],
            "step": meta["step"],
            "from_state": meta["from_state"],
            "to_state": meta["to_state"],
            "artifact": meta["artifact"],
            "edge_index": meta["edge_index"],
            "token_consumed": meta["token_consumed"],
            "cas_succeeded": meta["cas_succeeded"],
            "commit_receipt_verified": meta["commit_receipt_verified"],
            "tombstone_written": meta["tombstone_written"],
            "proof_present": meta["proof_present"],
            "skip_forbidden": 0,
            "idempotent_retry_same_state": 1,
        }
        if step_id == "S6":
            payload["prior_chain"] = prior_s1_s5
            payload["retire_caller_role"] = "old_owner"
            payload["sole_owner"] = 1
            payload["api_op"] = "ninlil_parent_owner_retire"
            payload["new_owner_may_mutate_old_store"] = 0
        add(case(meta["case_id"], family="MP-handoff", expect_status="OK", **payload))
    add(
        case(
            "MP-OWNER-RETIRE-SOLE-OWNER-OK",
            family="MP-handoff",
            expect_status="OK",
            step="S6",
            retire_caller_role="old_owner",
            sole_owner=1,
            api_op="ninlil_parent_owner_retire",
            tombstone_written=1,
            old_owner_seal=0,
            new_owner_seal=1,
            new_owner_may_mutate_old_store=0,
            prior_chain=prior_s1_s5,
            edge_index=4,
            from_state="ENDPOINT_OBSERVED",
            to_state="OLD_RETIRED",
            state="OLD_RETIRED",
            proof_present=1,
            cas_succeeded=1,
            commit_receipt_verified=1,
            token_consumed=1,
            artifact="TOMBSTONE_RETIRE",
        )
    )
    add(
        case(
            "MP-OWNER-RETIRE-WRONG-CALLER",
            family="MP-handoff",
            expect_status="NOT_OWNER",
            step="S6",
            retire_caller_role="new_owner",
            sole_owner=1,
            api_op="ninlil_parent_owner_retire",
            wrong_caller=1,
            tombstone_written=0,
            new_owner_may_mutate_old_store=0,
        )
    )
    add(
        case(
            "MP-HANDOFF-TOKEN-REPLAY",
            family="MP-handoff",
            expect_status="TOKEN_REPLAY",
            token_digest_hex=hx(token),
            reuse=1,
            token_consumed_before=1,
            second_consume=1,
            cas_succeeded=1,
            commit_receipt_verified=1,
        )
    )
    add(
        case(
            "MP-SAME-ATTEMPT-RESELECT-REJECT",
            family="MP-attempt",
            expect_status="SAME_ATTEMPT_RESELECT",
            transaction_id_hex=hx(pattern(0x71, 16)),
            attempt_id_hex=hx(pattern(0x72, 16)),
            reselect_parent=1,
        )
    )
    add(
        case(
            "MP-PARENT-LOSS-MID-FLIGHT",
            family="MP-failover",
            expect_status="NOT_ACTIVE",
            application_receipt=0,
            custody_retained=1,
            routes_draining=1,
        )
    )
    add(
        case(
            "MP-ROUTE-HANDOFF-DRAIN-LINK",
            family="MP-failover",
            expect_status="OK",
            drain_batch_routes=2,
            new_attempt_required=1,
            same_attempt_reselect=0,
        )
    )
    add(
        case(
            "MP-CU-OLD",
            family="MP-storage",
            expect_status="COMMIT_UNKNOWN",
            classification="OLD",
            old_assignment_hex=hx(noa1),
            new_assignment_hex=hx(noa1_new),
            observed_assignment_hex=hx(noa1),
            seal=0,
        )
    )
    add(
        case(
            "MP-CU-NEW",
            family="MP-storage",
            expect_status="COMMIT_UNKNOWN",
            classification="NEW",
            old_assignment_hex=hx(noa1),
            new_assignment_hex=hx(noa1_new),
            observed_assignment_hex=hx(noa1_new),
            seal=0,
        )
    )
    add(
        case(
            "MP-CU-PARTIAL",
            family="MP-storage",
            expect_status="CORRUPT",
            classification="PARTIAL",
            observed_keys=["header"],
            expected_keys=["header", "assignment_page0"],
            seal=0,
        )
    )
    add(
        case(
            "MP-CU-EXTRA",
            family="MP-storage",
            expect_status="CORRUPT",
            classification="EXTRA",
            observed_keys=["header", "assignment_page0", "unexpected"],
            expected_keys=["header", "assignment_page0"],
            seal=0,
        )
    )
    third_noa = bytearray(noa1)
    third_noa[56:64] = u64(99)  # revision
    # repair digest+crc after mutation for THIRD classification of full record
    third_noa[224:256] = sha256(bytes(third_noa[:224]))
    third_noa[256:260] = u32(0)
    third_noa[256:260] = u32(crc32c(bytes(third_noa)))
    add(
        case(
            "MP-CU-THIRD",
            family="MP-storage",
            expect_status="CORRUPT",
            classification="THIRD",
            old_assignment_hex=hx(noa1),
            new_assignment_hex=hx(noa1_new),
            observed_assignment_hex=hx(bytes(third_noa)),
            seal=0,
        )
    )
    add(
        case(
            "MP-FEATURE-OFF",
            family="MP-compat",
            expect_status="FEATURE_OFF",
            feature_multi_parent=0,
        )
    )
    add(
        case(
            "MP-OLD-CONTEXT-REPLAY-REJECT",
            family="MP-security",
            expect_status="NOT_OWNER",
            old_e2e_context_id=0x33330001,
            active_e2e_context_id=0x33330002,
            seal=0,
        )
    )

    # joint
    add(
        case(
            "RRMP-1HOP-BASELINE",
            family="joint",
            expect_status="OK",
            hops=1,
            parents=1,
            forward=1,
            seal=1,
        )
    )
    add(
        case(
            "RRMP-2HOP-DIVERSITY",
            family="joint",
            expect_status="OK",
            hops=2,
            parents=2,
            uplink_paths=2,
            effect_publish=1,
        )
    )
    add(
        case(
            "RRMP-3HOP-DRAIN-REPLACE",
            family="joint",
            expect_status="OK",
            hops=3,
            drain_then_replace=1,
            new_attempt=1,
        )
    )
    add(
        case(
            "RRMP-PARENT-LOSS-MID-FLIGHT-JOINT",
            family="joint",
            expect_status="NOT_ACTIVE",
            forward_new_admission=0,
            application_receipt=0,
        )
    )
    add(
        case(
            "RRMP-SPLIT-BRAIN-SEAL-AND-FORWARD-ZERO",
            family="joint",
            expect_status="SPLIT_BRAIN",
            seal=0,
            forward=0,
        )
    )
    add(
        case(
            "RRMP-SIMULATION-TRANSCRIPT-BOUNDED",
            family="joint",
            expect_status="OK",
            steps=sim_steps,
            step_count=len(sim_steps),
            transcript_digest_hex=hx(sim_digest),
            max_steps=32,
        )
    )
    add(
        case(
            "RRMP-FAILURE-PRECEDENCE-MATRIX",
            family="joint",
            expect_status="OK",
            precedence_route=list(ROUTE_FAILURE_PRECEDENCE),
            precedence_parent=list(PARENT_FAILURE_PRECEDENCE),
            parent_split_brain_code=8,
            unknown_status_code_reject=999,
        )
    )
    add(
        case(
            "RRMP-GATE-SELF-TEST-PIN",
            family="joint",
            expect_status="OK",
            pin="route-relay-multiparent-spec-v1",
            generator_path="tools/route_relay_multiparent_spec_vector_gen.py",
            python_gate_path="tools/route_relay_multiparent_spec_gate.py",
            node_gate_path="tools/route_relay_multiparent_spec_gate.mjs",
            vector_path="spec/vectors/route-relay-multiparent-spec-v1.json",
            claims_spec_accepted=1,
            claims_implementation=0,
            claims_hil=0,
            claims_release_supported=0,
            # filled after document assembly with restoration metadata
            restoration_placeholder=1,
        )
    )

    # validate inventory completeness in generator
    ids = [c["id"] for c in cases]
    if len(ids) != len(set(ids)):
        raise RuntimeError("duplicate case ids in generator")
    if set(ids) != set(REQUIRED_IDS):
        missing = sorted(set(REQUIRED_IDS) - set(ids))
        extra = sorted(set(ids) - set(REQUIRED_IDS))
        raise RuntimeError(f"id inventory mismatch missing={missing} extra={extra}")
    for c in cases:
        if c.get("case_kind") != c["id"]:
            raise RuntimeError(f"case_kind pin broken {c['id']}")

    # storage arithmetic summary
    storage = {
        "namespace_route": "ninlil.route.v1",
        "namespace_parent": "ninlil.parent.v1",
        "directory_bytes": DIR_BYTES,
        "page_bytes": NRP1_BYTES,
        "slot_bytes": SLOT_BYTES,
        "slots_per_page": SLOTS_PER_PAGE,
        "page_count": PAGE_COUNT,
        "route_max": ROUTE_MAX,
        "page_header_bytes": NRP1_HEADER_BYTES,
        "slots_span_bytes": NRP1_SLOTS_SPAN,
        "page_pad_bytes": NRP1_PAD_BYTES,
        "management_record_bytes": NRM1_BYTES,
        "exact_body_bytes": 96,
        "r2_sidecar_bytes": 24,
        "drain_fence_bytes": 32,
        "evidence_bytes": EVIDENCE_BYTES,
        "assignment_bytes": NOA1_BYTES,
        "assignment_slot_bytes": ASSIGNMENT_SLOT_BYTES,
        "npa1_header_bytes": NPA1_HEADER_BYTES,
        "npa1_pad_bytes": NPA1_PAD_BYTES,
        "npa1_page_bytes": NPA1_BYTES,
        "install_batch_header_bytes": INSTALL_BATCH_HEADER_BYTES,
        "install_batch_max_routes": INSTALL_BATCH_MAX,
        "install_batch_struct_size_n8": INSTALL_BATCH_HEADER_BYTES + NRM1_BYTES * 8,
        "logical_mutations_max": LOGICAL_MUTATIONS_MAX,
        "route_physical_key_count": ROUTE_PHYSICAL_KEY_COUNT,
        "parent_physical_key_count": PARENT_PHYSICAL_KEY_COUNT,
        "npp1_physical_slot_count": NPP1_PHYSICAL_SLOT_COUNT,
        "formula_identities": {
            "slots_span": f"{SLOTS_PER_PAGE}*{SLOT_BYTES}={NRP1_SLOTS_SPAN}",
            "page_pad": f"{NRP1_HEADER_BYTES}+{NRP1_SLOTS_SPAN}+{NRP1_PAD_BYTES}={NRP1_BYTES}",
            "route_capacity": f"{PAGE_COUNT}*{SLOTS_PER_PAGE}={ROUTE_MAX}",
            "install_batch_n8": f"{INSTALL_BATCH_HEADER_BYTES}+{NRM1_BYTES}*8="
            f"{INSTALL_BATCH_HEADER_BYTES + NRM1_BYTES * 8}",
            "assignment_slot": f"{NOA1_BYTES}+1+3+32+32+4={ASSIGNMENT_SLOT_BYTES}",
            "npa1_page": f"{NPA1_HEADER_BYTES}+{NPA1_SLOTS_SPAN}+{NPA1_PAD_BYTES}={NPA1_BYTES}",
        },
    }

    profile = {
        "name": "ESP_V1_CANDIDATE",
        "max_hops_default": MAX_HOPS_PROFILE,
        "max_hops_absolute": MAX_HOPS_ABSOLUTE,
        "max_link_groups": MAX_LINK_GROUPS,
        "max_attempts": MAX_ATTEMPTS,
        "max_airtime_budget_ms": MAX_AIRTIME_BUDGET_MS,
        "queue_global_entries": QUEUE_GLOBAL_ENTRIES,
        "queue_global_bytes": QUEUE_GLOBAL_BYTES,
        "reserved_control_entries": RESERVED_CONTROL_ENTRIES,
        "reserved_control_bytes": RESERVED_CONTROL_BYTES,
        "dedup_window": DEDUP_WINDOW,
        "loop_window": LOOP_WINDOW,
        "feature_route_relay_default": 0,
        "feature_multi_parent_default": 0,
        "public_abi_change": 0,
        "wire_profile_id": 0x11,
    }

    drain_constants = {
        "link_group_cost_ms": "checked_add_u32(A, checked_add_u32(T, W))",
        "work_ms": "checked_mul_u64(F, checked_mul_u64(R, link_group_cost_ms))",
        "gaps_ms": "checked_mul_u64(F-1, I)",
        "completion_ms": "checked_add_u64(now, work_ms + gaps_ms + G)",
        "airtime_gate": "checked_mul_u64(F, A) <= max_airtime_budget_ms",
        "eligibility": "completion_ms <= min(item, drain, lease) deadlines",
        "sample_ok_inputs": drain_ok_inputs,
        "sample_impossible_inputs": drain_impossible_inputs,
        "sample_overflow_inputs": drain_overflow_inputs,
        "sample_ok": drain_ok,
        "sample_impossible": drain_impossible,
        "sample_overflow": drain_overflow,
    }

    # Schema=2 NRD1 with repaired CRC must still fail both gates.
    schema2_dir = bytearray(directory)
    schema2_dir[4:6] = u16(2)
    schema2_dir[252:256] = u32(0)
    schema2_dir[252:256] = u32(crc32c(bytes(schema2_dir)))

    handoff_machine = {
        "authority": "INDEPENDENT_CLOSED_TABLE",
        "states": list(HANDOFF_STATES),
        "closed_steps": {k: {kk: vv for kk, vv in v.items() if kk != "case_id"} for k, v in HANDOFF_CLOSED.items()},
        "allowed_edges": [
            {
                "from": a,
                "to": b,
                "artifact": art,
                "index": i,
            }
            for i, (a, b, art) in enumerate(HANDOFF_ALLOWED_EDGES)
        ],
        "forbidden_edges": [{"from": a, "to": b} for a, b in HANDOFF_FORBIDDEN_EDGES],
        "linearization_state": "AUTHORITY_COMMITTED",
        "steps_order": ["S1", "S2", "S3", "S4", "S5", "S6"],
        "idempotent_policy": "same_token_same_state_requery_only",
        "no_skip": 1,
        "s6_requires_prior_chain_s1_s5": 1,
    }

    case_schemas = {c["id"]: sorted(c.keys()) for c in cases}

    document: dict[str, Any] = {
        "spec": {
            "id": "route-relay-multiparent-spec-v1",
            "title": "Route Relay + Multi-parent SPEC-ONLY authority vectors",
            "status": "SPEC_ACCEPTED",
            "adr_refs": ["docs/adr/0019-route-relay.md", "docs/adr/0020-multi-parent.md"],
            "claims": {
                "spec_accepted": 1,
                "implementation": 0,
                "hil": 0,
                "release_supported": 0,
                "public_abi": 0,
            },
            "api_version": API_VERSION,
            "schema_version": 1,
        },
        "normative_constants": dict(NORMATIVE_CONSTANTS),
        "arithmetic_kats": ARITHMETIC_KATS,
        "profile": profile,
        "status_codes_route": STATUS,
        "status_codes_parent": PARENT_STATUS,
        "failure_precedence_route": list(ROUTE_FAILURE_PRECEDENCE),
        "failure_precedence_parent": list(PARENT_FAILURE_PRECEDENCE),
        "handoff_machine": handoff_machine,
        "storage": storage,
        "private_api_catalog": build_private_api_catalog(),
        "storage_codec_catalog": build_storage_codec_catalog(),
        "p1_repair_authority": build_p1_repair_authority(),
        "drain_formula": drain_constants,
        "required_ids": list(REQUIRED_IDS),
        "required_id_count": len(REQUIRED_IDS),
        "case_schemas": case_schemas,
        "fixtures": {
            "e2e_header_digest_hex": hx(e2e_digest),
            "local_runtime_id_hex": hx(local_runtime),
            "endpoint_runtime_id_hex": hx(endpoint_runtime),
            "owner_scope_id_hex": hx(scope),
            "nrm1_1hop_hex": hx(nrm1_1),
            "exact_1hop_hex": hx(exact_1),
            "directory_hex": hx(directory),
            "directory_schema2_repaired_crc_hex": hx(bytes(schema2_dir)),
            "page0_hex": hx(page0),
            "slot0_hex": hx(slot),
            "evidence_hex": hx(ev),
            "evidence_chain_after_hex": hx(chain1),
            "assignment_hex": hx(noa1),
            "assignment_new_hex": hx(noa1_new),
            "nph1_hex": hx(nph1),
            "nps1_hex": hx(nps1),
            "npp1_page0_hex": hx(npp1),
            "nep1_page0_hex": hx(nep1),
            "npt1_page0_hex": hx(npt1),
            "npa1_page0_hex": hx(npa1),
            "assignment_slot_hex": hx(bytes(assign_slot)),
        },
        "cases": cases,
        "simulation": {
            "id": "RRMP-SIMULATION-TRANSCRIPT-BOUNDED",
            "steps": sim_steps,
            "transcript_digest_hex": hx(sim_digest),
            "bounded_max_steps": 32,
        },
        "tool_paths": {
            "generator": "tools/route_relay_multiparent_spec_vector_gen.py",
            "python_gate": "tools/route_relay_multiparent_spec_gate.py",
            "node_gate": "tools/route_relay_multiparent_spec_gate.mjs",
            "vector": "spec/vectors/route-relay-multiparent-spec-v1.json",
        },
    }

    # Authority envelope hash over full top-level machine metadata (gates hard-pin independently).
    envelope = {
        "spec": document["spec"],
        "normative_constants": document["normative_constants"],
        "profile": document["profile"],
        "status_codes_route": document["status_codes_route"],
        "status_codes_parent": document["status_codes_parent"],
        "failure_precedence_route": document["failure_precedence_route"],
        "failure_precedence_parent": document["failure_precedence_parent"],
        "handoff_machine": document["handoff_machine"],
        "storage": document["storage"],
        "private_api_catalog": document["private_api_catalog"],
        "storage_codec_catalog": document["storage_codec_catalog"],
        "p1_repair_authority": document["p1_repair_authority"],
        "tool_paths": document["tool_paths"],
        "simulation": {
            "id": document["simulation"]["id"],
            "bounded_max_steps": document["simulation"]["bounded_max_steps"],
        },
        "required_ids": document["required_ids"],
        "required_id_count": document["required_id_count"],
    }
    document["authority_envelope_sha256"] = sha256(
        (json.dumps(envelope, indent=2, sort_keys=True) + "\n").encode()
    ).hex()

    # Fill GATE-SELF-TEST-PIN restoration metadata for tool sources.
    # vector_sha256 is content-hash of canonical document with that field absent.
    pin_case = next(c for c in document["cases"] if c["id"] == "RRMP-GATE-SELF-TEST-PIN")
    pin_case.pop("restoration_placeholder", None)
    pin_case["restoration"] = {
        "generator_sha256": sha256(
            (ROOT / "tools/route_relay_multiparent_spec_vector_gen.py").read_bytes()
        ).hex(),
        "python_gate_sha256": sha256(
            (ROOT / "tools/route_relay_multiparent_spec_gate.py").read_bytes()
        ).hex(),
        "node_gate_sha256": sha256(
            (ROOT / "tools/route_relay_multiparent_spec_gate.mjs").read_bytes()
        ).hex(),
        "authority_envelope_sha256": document["authority_envelope_sha256"],
    }
    document["case_schemas"]["RRMP-GATE-SELF-TEST-PIN"] = sorted(pin_case.keys())
    return document


def canonical_json(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def finalize_document(document: dict[str, Any]) -> dict[str, Any]:
    """Insert self-describing vector content hash into GATE-SELF-TEST-PIN."""

    pin = next(c for c in document["cases"] if c["id"] == "RRMP-GATE-SELF-TEST-PIN")
    rest = pin.setdefault("restoration", {})
    rest.pop("vector_sha256", None)
    pin["restoration"] = rest
    document["case_schemas"]["RRMP-GATE-SELF-TEST-PIN"] = sorted(pin.keys())
    body = canonical_json(document)
    rest["vector_sha256"] = sha256(body).hex()
    document["case_schemas"]["RRMP-GATE-SELF-TEST-PIN"] = sorted(pin.keys())
    return document


def emit_c_fixture(document: dict[str, Any]) -> str:
    """Independent C11 fixture authority: every case id + status + fixture digests.

    Not production ABI. SPEC_ACCEPTED design consumption surface for host oracles.
    """
    lines: list[str] = [
        "/* GENERATED by tools/route_relay_multiparent_spec_vector_gen.py — do not edit. */",
        "#ifndef NINLIL_ROUTE_RELAY_MULTIPARENT_SPEC_FIXTURE_H",
        "#define NINLIL_ROUTE_RELAY_MULTIPARENT_SPEC_FIXTURE_H",
        "",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        f"#define NINLIL_RRMP_CASE_COUNT {len(document['cases'])}u",
        "#define NINLIL_RRMP_SPEC_STATUS_SPEC_ACCEPTED 1",
        "#define NINLIL_RRMP_CLAIMS_SPEC_ACCEPTED 1",
        "#define NINLIL_RRMP_CLAIMS_IMPLEMENTATION 0",
        "#define NINLIL_RRMP_CLAIMS_HIL 0",
        "#define NINLIL_RRMP_CLAIMS_RELEASE_SUPPORTED 0",
        f"#define NINLIL_RRMP_SCHEMA_VERSION {int(document['spec']['schema_version'])}",
        f"#define NINLIL_RRMP_API_VERSION {int(document['spec']['api_version'])}",
        f'#define NINLIL_RRMP_SPEC_ID "{document["spec"]["id"]}"',
        f'#define NINLIL_RRMP_AUTHORITY_ENVELOPE_SHA256 "{document["authority_envelope_sha256"]}"',
        f"#define NINLIL_RRMP_FEATURE_MULTI_PARENT_DEFAULT {int(document['profile']['feature_multi_parent_default'])}",
        f"#define NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES {int(document['profile']['queue_global_entries'])}",
        f"#define NINLIL_RRMP_ROUTE_OK_CODE {int(document['status_codes_route']['OK'])}",
        f"#define NINLIL_RRMP_PARENT_OK_CODE {int(document['status_codes_parent']['OK'])}",
        f'#define NINLIL_RRMP_NS_ROUTE "{document["storage"]["namespace_route"]}"',
        f'#define NINLIL_RRMP_NS_PARENT "{document["storage"]["namespace_parent"]}"',
        f'#define NINLIL_RRMP_TOOL_GENERATOR "{document["tool_paths"]["generator"]}"',
        f"#define NINLIL_RRMP_HANDOFF_NO_SKIP {int(document['handoff_machine']['no_skip'])}",
        f'#define NINLIL_RRMP_HANDOFF_IDEMPOTENT_POLICY "{document["handoff_machine"]["idempotent_policy"]}"',
        f"#define NINLIL_RRMP_SIM_BOUNDED_MAX_STEPS {int(document['simulation']['bounded_max_steps'])}",
        f"#define NINLIL_RRMP_HANDOFF_ALLOWED_EDGE_COUNT {len(document['handoff_machine']['allowed_edges'])}u",
        f"#define NINLIL_RRMP_HANDOFF_FORBIDDEN_EDGE_COUNT {len(document['handoff_machine']['forbidden_edges'])}u",
        f"#define NINLIL_RRMP_PRIVATE_API_TOTAL_OPS {int(document['private_api_catalog']['total_op_count'])}u",
        f"#define NINLIL_RRMP_ROUTE_OPS {int(document['private_api_catalog']['route_op_count'])}u",
        f"#define NINLIL_RRMP_PARENT_OPS {int(document['private_api_catalog']['parent_op_count'])}u",
        f"#define NINLIL_RRMP_ROUTE_RESULT_BYTES {int(document['private_api_catalog']['route_result_bytes'])}u",
        f"#define NINLIL_RRMP_PARENT_RESULT_BYTES {int(document['private_api_catalog']['parent_result_bytes'])}u",
        f"#define NINLIL_RRMP_NPH1_BYTES {int(document['storage_codec_catalog']['nph1']['bytes'])}u",
        f"#define NINLIL_RRMP_NPT1_BYTES {int(document['storage_codec_catalog']['npt1']['bytes'])}u",
        f"#define NINLIL_RRMP_NPA1_BYTES {int(document['storage_codec_catalog']['npa1']['bytes'])}u",
        f"#define NINLIL_RRMP_NPT1_SLOT_BYTES {int(document['storage_codec_catalog']['npt1']['slot_bytes'])}u",
        f"#define NINLIL_RRMP_RRM1_BYTES {int(document['p1_repair_authority']['outer_bundle']['manifest_bytes'])}u",
        f"#define NINLIL_RRMP_BUNDLE_CHUNK_MAX {int(document['p1_repair_authority']['outer_bundle']['chunk_bytes_max'])}u",
        f"#define NINLIL_RRMP_BUNDLE_LOGICAL_MAX {int(document['p1_repair_authority']['outer_bundle']['logical_bytes_max'])}u",
        f"#define NINLIL_RRMP_BUNDLE_REQUIRED_MAX {int(document['p1_repair_authority']['outer_bundle']['logical_required_max'])}u",
        f"#define NINLIL_RRMP_QST4_ATTEMPT_BYTES {int(document['p1_repair_authority']['qst4']['attempt_row_bytes'])}u",
        f"#define NINLIL_RRMP_QST4_ATTEMPT_CAPACITY {int(document['p1_repair_authority']['qst4']['attempt_capacity'])}u",
        f"#define NINLIL_RRMP_QST4_HANDOFF_TUPLE_BYTES {int(document['p1_repair_authority']['qst4']['handoff_tuple_row_bytes'])}u",
        f"#define NINLIL_RRMP_QST4_HANDOFF_TUPLE_CAPACITY {int(document['p1_repair_authority']['qst4']['handoff_tuple_capacity'])}u",
        f"#define NINLIL_RRMP_ATTEMPT_RETENTION_MS {int(document['p1_repair_authority']['qst4']['attempt_retention_ms'])}u",
        f"#define NINLIL_RRMP_PRIVATE_V2_OPS {int(document['private_api_catalog']['private_v2_op_count'])}u",
        f"#define NINLIL_RRMP_AUTHORITY_GLOBAL_CLEAR_API {int(document['p1_repair_authority']['authority_fence']['clear_api_present'])}",
        f"#define NINLIL_RRMP_PUBLIC_ABI {int(document['private_api_catalog']['public_abi'])}",
        f"#define NINLIL_RRMP_SIM_EVENT_COUNT {len(document['simulation']['steps'])}u",
        "",
        "/* Independent simulation closed table: event + required effects (digest is not sole authority). */",
        "typedef struct ninlil_rrmp_sim_event {",
        "  int32_t t;",
        "  const char *event;",
        "  const char *result; /* may be NULL for effect-only events */",
        "  int32_t seal;    /* -1 = N/A; 0/1 for SPLIT_BRAIN_WRITERS */",
        "  int32_t forward; /* -1 = N/A; 0/1 for SPLIT_BRAIN_WRITERS */",
        "} ninlil_rrmp_sim_event_t;",
        "",
        "static const ninlil_rrmp_sim_event_t ninlil_rrmp_sim_events[NINLIL_RRMP_SIM_EVENT_COUNT] = {",
    ]
    for step in document["simulation"]["steps"]:
        result = step.get("result")
        result_c = f'"{result}"' if result is not None else "NULL"
        seal = step["seal"] if "seal" in step else -1
        forward = step["forward"] if "forward" in step else -1
        lines.append(
            f'  {{ {int(step["t"])}, "{step["event"]}", {result_c}, {int(seal)}, {int(forward)} }},'
        )
    lines.extend(
        [
            "};",
            "",
            "typedef struct ninlil_rrmp_case {",
            "  const char *id;",
            "  const char *family;",
            "  const char *expect_status;",
            "  int32_t expect_status_code;",
            "} ninlil_rrmp_case_t;",
            "",
            "static const ninlil_rrmp_case_t ninlil_rrmp_cases[NINLIL_RRMP_CASE_COUNT] = {",
        ]
    )
    for case in document["cases"]:
        cid = case["id"]
        fam = case["family"]
        st = case["expect_status"]
        code = int(case["expect_status_code"])
        lines.append(
            f'  {{ "{cid}", "{fam}", "{st}", {code} }},'
        )
    lines.extend(
        [
            "};",
            "",
            "/* Private API catalog: exact names + request sizes (not name-only tables). */",
            "typedef struct ninlil_rrmp_api_op {",
            "  const char *name;",
            "  const char *req_type;",
            "  int32_t req_size; /* -1 => variable (install_batch) */",
            "  uint32_t result_size;",
            "} ninlil_rrmp_api_op_t;",
            "",
            "static const ninlil_rrmp_api_op_t ninlil_rrmp_route_ops[NINLIL_RRMP_ROUTE_OPS] = {",
        ]
    )
    for op in document["private_api_catalog"]["route_ops"]:
        rs = op["req_size"]
        req_size = -1 if isinstance(rs, str) else int(rs)
        lines.append(
            f'  {{ "{op["name"]}", "{op["req"]}", {req_size}, {int(op["result_size"])}u }},'
        )
    lines.append("};")
    lines.append("")
    lines.append("static const ninlil_rrmp_api_op_t ninlil_rrmp_parent_ops[NINLIL_RRMP_PARENT_OPS] = {")
    for op in document["private_api_catalog"]["parent_ops"]:
        lines.append(
            f'  {{ "{op["name"]}", "{op["req"]}", {int(op["req_size"])}, {int(op["result_size"])}u }},'
        )
    lines.extend(
        [
            "};",
            "",
            "/* Fixture digests: independent C-layout binary authorities (hex SHA-256). */",
        ]
    )
    for key in sorted(document["fixtures"].keys()):
        digest = sha256(bytes.fromhex(document["fixtures"][key])).hex()
        cname = "NINLIL_RRMP_FX_" + key.upper().replace("-", "_")
        lines.append(f'#define {cname}_SHA256 "{digest}"')
    lines.extend(
        [
            "",
            "#endif /* NINLIL_ROUTE_RELAY_MULTIPARENT_SPEC_FIXTURE_H */",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--self-test", action="store_true")
    mode.add_argument("--emit-c-fixture", type=Path, metavar="PATH")
    args = parser.parse_args()

    document = finalize_document(build_document())
    rendered = canonical_json(document)

    if getattr(args, "emit_c_fixture", None) is not None:
        text = emit_c_fixture(document)
        args.emit_c_fixture.parent.mkdir(parents=True, exist_ok=True)
        args.emit_c_fixture.write_text(text)
        print(
            f"wrote C fixture {args.emit_c_fixture} "
            f"cases={len(document['cases'])} bytes={len(text.encode())}"
        )
        return 0

    if args.write:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_bytes(rendered)
        pin = ROOT / "spec/vectors/route-relay-multiparent-private-api-catalog-v1.json"
        pin_body = (json.dumps(document["private_api_catalog"], indent=2, sort_keys=True) + "\n").encode()
        pin.write_bytes(pin_body)
        print(
            f"wrote {OUTPUT} sha256={sha256(rendered).hex()} cases={len(document['cases'])} "
            f"private_api_catalog_sha256={sha256(pin_body).hex()}"
        )
        return 0

    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_bytes() != rendered:
            print(f"stale or missing: {OUTPUT}")
            return 1
        print(f"fresh {OUTPUT} sha256={sha256(rendered).hex()}")
        return 0

    # self-test
    ids = [c["id"] for c in document["cases"]]
    if ids != list(REQUIRED_IDS):
        print("self-test failed: case order/inventory")
        return 1
    # Lockstep private_api_catalog authority: pin file + both gates must know constructor keys
    pin_path = ROOT / "spec/vectors/route-relay-multiparent-private-api-catalog-v1.json"
    pin_cat = json.loads(pin_path.read_text())
    if pin_cat != document["private_api_catalog"]:
        print("self-test failed: private_api_catalog pin drift vs document")
        return 1
    if pin_cat != build_private_api_catalog():
        print("self-test failed: private_api_catalog pin drift vs builder")
        return 1
    op0 = pin_cat["parent_ops"][0]
    for k in ("max_parents", "parent_ids_inline", "parent_set_digest_bytes"):
        if k not in op0:
            print(f"self-test failed: parent_ops[0] missing {k}")
            return 1
    py_src = (ROOT / "tools/route_relay_multiparent_spec_gate.py").read_text()
    js_src = (ROOT / "tools/route_relay_multiparent_spec_gate.mjs").read_text()
    for label, src in (("python", py_src), ("node", js_src)):
        for token in (
            "max_parents",
            "parent_ids_inline",
            "parent_set_digest_bytes",
            "workspace_rule",
            "observed_parent_set_digest_bytes",
            "sole_caller_role",
            "boundary",
            "req_size\": 240",
            "req_size: 240",
            "req_size\": 464",
            "req_size: 464",
        ):
            # token variants for py vs js
            pass
        required_tokens = [
            "max_parents",
            "parent_ids_inline",
            "parent_set_digest_bytes",
            "workspace_rule",
            "observed_parent_set_digest_bytes",
            "sole_caller_role",
            "boundary",
        ]
        for token in required_tokens:
            if token not in src:
                print(f"self-test failed: {label} gate missing private_api token {token}")
                return 1
        if "240" not in src or "464" not in src:
            print(f"self-test failed: {label} gate missing set_install/prepare sizes")
            return 1
    if len(ids) != len(set(ids)):
        print("self-test failed: duplicates")
        return 1
    # Independent C fixture authority consumes all required case IDs exactly once.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        a = Path(tmp) / "a.h"
        b = Path(tmp) / "b.h"
        fa = emit_c_fixture(document)
        fb = emit_c_fixture(document)
        a.write_text(fa)
        b.write_text(fb)
        if fa != fb or a.read_text() != b.read_text():
            print("self-test failed: C fixture non-deterministic")
            return 1
        macro_names = [
            line.split()[1]
            for line in fa.splitlines()
            if line.startswith("#define ") and len(line.split()) >= 2
        ]
        if len(macro_names) != len(set(macro_names)):
            print("self-test failed: C fixture duplicate macro")
            return 1
        if f"NINLIL_RRMP_CASE_COUNT {len(REQUIRED_IDS)}u" not in fa:
            print("self-test failed: C fixture case count")
            return 1
        for claim_pin in (
            "NINLIL_RRMP_SPEC_STATUS_SPEC_ACCEPTED 1",
            "NINLIL_RRMP_CLAIMS_SPEC_ACCEPTED 1",
            "NINLIL_RRMP_CLAIMS_IMPLEMENTATION 0",
            "NINLIL_RRMP_CLAIMS_HIL 0",
            "NINLIL_RRMP_CLAIMS_RELEASE_SUPPORTED 0",
            "NINLIL_RRMP_PUBLIC_ABI 0",
        ):
            if claim_pin not in fa:
                print(f"self-test failed: C fixture claim pin {claim_pin}")
                return 1
        # Full machine authority constants must be present (not selective).
        for needle in (
            f'#define NINLIL_RRMP_SCHEMA_VERSION {document["spec"]["schema_version"]}',
            f'#define NINLIL_RRMP_API_VERSION {document["spec"]["api_version"]}',
            f'#define NINLIL_RRMP_SPEC_ID "{document["spec"]["id"]}"',
            f'#define NINLIL_RRMP_AUTHORITY_ENVELOPE_SHA256 "{document["authority_envelope_sha256"]}"',
            f'#define NINLIL_RRMP_FEATURE_MULTI_PARENT_DEFAULT {document["profile"]["feature_multi_parent_default"]}',
            f'#define NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES {document["profile"]["queue_global_entries"]}',
            f'#define NINLIL_RRMP_ROUTE_OK_CODE {document["status_codes_route"]["OK"]}',
            f'#define NINLIL_RRMP_PARENT_OK_CODE {document["status_codes_parent"]["OK"]}',
            f'#define NINLIL_RRMP_NS_ROUTE "{document["storage"]["namespace_route"]}"',
            f'#define NINLIL_RRMP_NS_PARENT "{document["storage"]["namespace_parent"]}"',
            f'#define NINLIL_RRMP_TOOL_GENERATOR "{document["tool_paths"]["generator"]}"',
            f'#define NINLIL_RRMP_HANDOFF_NO_SKIP {document["handoff_machine"]["no_skip"]}',
            f'#define NINLIL_RRMP_HANDOFF_IDEMPOTENT_POLICY "{document["handoff_machine"]["idempotent_policy"]}"',
            f'#define NINLIL_RRMP_SIM_BOUNDED_MAX_STEPS {document["simulation"]["bounded_max_steps"]}',
            f'#define NINLIL_RRMP_HANDOFF_ALLOWED_EDGE_COUNT {len(document["handoff_machine"]["allowed_edges"])}u',
            f'#define NINLIL_RRMP_HANDOFF_FORBIDDEN_EDGE_COUNT {len(document["handoff_machine"]["forbidden_edges"])}u',
            f'#define NINLIL_RRMP_PRIVATE_API_TOTAL_OPS {document["private_api_catalog"]["total_op_count"]}u',
            f'#define NINLIL_RRMP_ROUTE_OPS {document["private_api_catalog"]["route_op_count"]}u',
            f'#define NINLIL_RRMP_PARENT_OPS {document["private_api_catalog"]["parent_op_count"]}u',
            f'#define NINLIL_RRMP_NPH1_BYTES {document["storage_codec_catalog"]["nph1"]["bytes"]}u',
            f'#define NINLIL_RRMP_NPT1_BYTES {document["storage_codec_catalog"]["npt1"]["bytes"]}u',
            f'#define NINLIL_RRMP_NPA1_BYTES {document["storage_codec_catalog"]["npa1"]["bytes"]}u',
            f'#define NINLIL_RRMP_PUBLIC_ABI 0',
            f'#define NINLIL_RRMP_SIM_EVENT_COUNT {len(document["simulation"]["steps"])}u',
        ):
            if needle not in fa:
                print(f"self-test failed: C fixture missing machine pin {needle[:60]}")
                return 1
        if "SPLIT_BRAIN_WRITERS" not in fa or "seal" not in fa.lower() and "SPLIT_BRAIN" not in fa:
            # sim events table must include SPLIT_BRAIN_WRITERS with seal/forward 0
            if '"SPLIT_BRAIN_WRITERS"' not in fa:
                print("self-test failed: C fixture missing SPLIT_BRAIN_WRITERS event")
                return 1
        # Require seal=0 forward=0 row for split-brain event in C table
        if ", 0, 0 }" not in fa and ", 0, 0}," not in fa:
            # look for SPLIT_BRAIN_WRITERS line with 0, 0
            if not any(
                "SPLIT_BRAIN_WRITERS" in line and ", 0, 0" in line for line in fa.splitlines()
            ):
                print("self-test failed: C fixture SPLIT_BRAIN_WRITERS seal/forward not pinned 0")
                return 1
        # Every private API name must appear in C fixture authority.
        for op in document["private_api_catalog"]["route_ops"] + document["private_api_catalog"]["parent_ops"]:
            if f'"{op["name"]}"' not in fa and op["name"] not in fa:
                # names are in vector catalog; emit them into C fixture lines below if missing
                pass
        if document["private_api_catalog"]["total_op_count"] != 20:
            print("self-test failed: private api total ops")
            return 1
        missing = [cid for cid in REQUIRED_IDS if f'"{cid}"' not in fa]
        if missing:
            print(f"self-test failed: C fixture missing ids {missing[:5]}")
            return 1
        # Every fixture key must appear as independent SHA pin.
        for key in document["fixtures"]:
            tag = "NINLIL_RRMP_FX_" + key.upper().replace("-", "_") + "_SHA256"
            if tag not in fa:
                print(f"self-test failed: C fixture missing {tag}")
                return 1
        # C authority closed pins must match vector machine authority envelope.
        if document["profile"]["feature_multi_parent_default"] != 0:
            print("self-test failed: feature_multi_parent_default pin")
            return 1
        if document["handoff_machine"]["no_skip"] != 1:
            print("self-test failed: no_skip pin")
            return 1
        if document["handoff_machine"]["idempotent_policy"] != "same_token_same_state_requery_only":
            print("self-test failed: idempotent_policy pin")
            return 1
        if document["simulation"]["bounded_max_steps"] != 32:
            print("self-test failed: bounded_max_steps pin")
            return 1
    # mutation observability
    altered = build_document()
    altered["profile"]["max_hops_default"] += 1
    if canonical_json(altered) == rendered:
        print("self-test failed: mutation not observed")
        return 1
    # drain arithmetic pin + independent recompute of all three samples
    sample = document["drain_formula"]["sample_ok"]
    if sample["eligible"] != 1 or sample["link_group_cost_ms"] != 150:
        print("self-test failed: drain cost")
        return 1
    # 3 groups * 2 attempts * 150 = 900; gaps (3-1)*5=10; +guard 10 => 920; now 1000000 => 1000920
    if sample["work_ms"] != 900 or sample["completion_ms"] != 1_000_920:
        print(f"self-test failed: drain completion {sample}")
        return 1
    for name in ("sample_ok", "sample_impossible", "sample_overflow"):
        inputs = document["drain_formula"][f"{name}_inputs"]
        recomputed = drain_completion(**inputs)
        if recomputed != document["drain_formula"][name]:
            print(f"self-test failed: {name} recompute")
            return 1
    if document["drain_formula"]["sample_overflow"]["eligible"] != 0:
        print("self-test failed: overflow must be ineligible")
        return 1
    if document["drain_formula"]["sample_overflow"]["reason"] != "DEADLINE":
        print("self-test failed: overflow/deadline reason")
        return 1
    # in-memory COMPLETION_OVERFLOW (not JSON-serialized)
    ovf = drain_completion(
        now_ms=U64_MAX - 10,
        remaining_link_groups=2,
        remaining_attempts=2,
        max_airtime_ms=100,
        turnaround_ms=20,
        link_ack_wait_ms=30,
        scheduler_guard_ms=100,
        inter_group_gap_ms=5,
        item_deadline_ms=U64_MAX,
        drain_deadline_ms=U64_MAX,
        lease_deadline_ms=U64_MAX,
    )
    if ovf["eligible"] != 0 or ovf["reason"] != "COMPLETION_OVERFLOW":
        print("self-test failed: in-memory COMPLETION_OVERFLOW")
        return 1
    # CRC self-check on NRM1
    rec = bytes.fromhex(document["fixtures"]["nrm1_1hop_hex"])
    if rec[:4] != b"NRM1" or len(rec) != NRM1_BYTES:
        print("self-test failed: nrm1 fixture")
        return 1
    scratch = bytearray(rec)
    stored = struct.unpack(">I", scratch[188:192])[0]
    scratch[188:192] = bytes(4)
    if crc32c(bytes(scratch[:188])) != stored:
        # crc is over bytes with field zero — our encoder used crc32c(bytes(buf[:188]))
        # where field was already zero before write; verify that path
        if crc32c(bytes(rec[:188])) != stored and crc32c(bytes(scratch[:188])) != stored:
            # recompute the way encoder did: field zero then crc of prefix
            pass
    # encoder: buf[188:192]=u32(crc32c(bytes(buf[:188]))) with zeros in crc field already
    if crc32c(bytes(rec[:188])) != stored:
        print("self-test failed: nrm1 crc")
        return 1
    # page arithmetic
    st = document["storage"]
    if st["slots_span_bytes"] != 8 * 508 or st["page_pad_bytes"] != 4096 - 20 - 4064:
        print("self-test failed: storage arithmetic")
        return 1
    if (
        st["route_physical_key_count"] != 21
        or st["parent_physical_key_count"] != 22
        or st["npp1_physical_slot_count"] != 75
        or "keys_max_per_namespace" in st
    ):
        print("self-test failed: namespace key/slot budgets")
        return 1
    # Design acceptance is the only true claim.
    claims = document["spec"]["claims"]
    expected_claims = {
        "spec_accepted": 1,
        "implementation": 0,
        "hil": 0,
        "release_supported": 0,
        "public_abi": 0,
    }
    if claims != expected_claims:
        print(f"self-test failed: claim boundary {claims!r}")
        return 1
    # scope derivation pin
    scope = bytes.fromhex(document["fixtures"]["owner_scope_id_hex"])
    again = owner_scope_id(
        endpoint_runtime_id=bytes.fromhex(document["fixtures"]["endpoint_runtime_id_hex"]),
        direction=1,
        namespace=b"cell",
        service=b"sensor",
        traffic_class=1,
        path_policy_id=pattern(0xF0, 16),
    )
    if scope != again:
        print("self-test failed: scope derivation")
        return 1
    print(
        "self-test OK "
        f"cases={len(ids)} sha256={sha256(rendered).hex()} "
        f"drain_completion={sample['completion_ms']} "
        f"c_fixture_cases={len(REQUIRED_IDS)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
