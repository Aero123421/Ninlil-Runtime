#!/usr/bin/env python3
"""R6 NRW1 docs gate — layouts, normative values, R3 oracle, non-noop mutations."""

from __future__ import annotations

import json
import hashlib
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Callable

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC30 = "docs/30-r6-secure-radio-wire.md"
ADR10 = "docs/adr/0010-r6-secure-radio-wire.md"
REVIEW = "docs/reviews/2026-07-17-r6-secure-radio-wire-freeze-self-review.md"
FINAL_REVIEW = "docs/reviews/2026-07-19-r6-final-integration-re-go.md"
DOC23 = "docs/23-usb-radio-boundary.md"
DOC29 = "docs/29-r5-lab-only-profile-loader.md"
ADR9 = "docs/adr/0009-r5-lab-only-profile-loader.md"
ORACLE = REPO_ROOT / "tools" / "airtime_r3_oracle.py"
DOC25_BYTES = 50395
DOC25_SHA256 = "08bfdec87112c31bf2e019da7cd2e5ce3c36e7ac67b372122dafae6e896aa224"

# docs/25 excluded from R6 edits; may be read-only verified if present.
CROSS = (
    "docs/01-architecture.md",
    "docs/05-security-and-compliance.md",
    "docs/06-versioning-and-compatibility.md",
    "docs/07-testing-and-quality.md",
    "docs/09-roadmap.md",
    "docs/15-glossary.md",
    DOC23,
    DOC29,
    "docs/README.md",
    ADR9,
    "docs/adr/README.md",
    "docs/reviews/README.md",
    "docs/release-history.md",
    "CHANGELOG.md",
)

MARKERS = (
    "SEMANTIC: WIRE_PROFILE_ID_0x11",
    "SEMANTIC: DIRECTION_CODE_0_IR_1_RI",
    "SEMANTIC: ONE_WAY_CONTEXT_EXACT",
    "SEMANTIC: HOP_DATA_ACK_SEPARATE_CRYPTO_LANES",
    "SEMANTIC: TX_RX_DO_NOT_SHARE_KEY_COUNTER_NS",
    "SEMANTIC: OUTER_FRAME_CONCAT_AAD19_CT_TAG16",
    "SEMANTIC: E2E_BLOB_CONCAT_AAD14_CT_TAG16",
    "SEMANTIC: CLOSED_LENGTH_DOMAINS",
    "SEMANTIC: STORAGE_ABI_PLATFORM_H_MAPPING",
    "SEMANTIC: COMMIT_UNKNOWN_RECOVERY_EXACT",
    "SEMANTIC: RX_BITMAP_UINT64_C1_SHIFT",
    "SEMANTIC: TX_EXCLUSIVE_RESERVATION_CHECKED_FINAL_TRANCHE",
    "SEMANTIC: KEY_GENERATION_U64_1_TO_MAX",
    "SEMANTIC: KEY_GENERATION_UINT64_MAX_TERMINAL",
    "SEMANTIC: NO_CONTEXT_ID_REUSE_IN_MEMBERSHIP_EPOCH",
    "SEMANTIC: NO_SAME_KEY_COUNTER_RESET_INSTALL",
    "SEMANTIC: HA_V1_SINGLE_SEALER_ONLY",
    "SEMANTIC: LINK_ACK_REQUIRES_ACK_REQUESTED_BIT",
    "SEMANTIC: LINK_RETRY_GROUP_EXACT",
    "SEMANTIC: LINK_RETRY_SAME_E2E_BLOB",
    "SEMANTIC: LINK_RETRY_BLOB_COPY_OWN",
    "SEMANTIC: LINK_RETRY_ELIGIBLE_AT_MAX",
    "SEMANTIC: TIMER_MONOTONIC_OWNER_CLOCK",
    "SEMANTIC: FRAG_ACK_RECEIVER_ONLY",
    "SEMANTIC: FRAG_DUAL_UNIQUE_INDEX_HANDLE_AND_TRANSFER_ID",
    "SEMANTIC: FRAG_CONFLICT_NO_REPLACE_EXISTING",
    "SEMANTIC: FRAG_START_EXACT_RETRY_NO_MUTATION",
    "SEMANTIC: FRAG_E2E_RETRY_FRESH_SEAL",
    "SEMANTIC: FRAG_MAX_OUTER_ATTEMPTS_PER_FRAGMENT_16",
    "SEMANTIC: FRAG_SENDER_TIMING_EXACT",
    "SEMANTIC: TOMBSTONE_VOLATILE_ON_RESTART",
    "SEMANTIC: RELAY_E2E_STRUCTURAL_ONLY_AFTER_OUTER",
    "SEMANTIC: RELAY_MUST_STRUCTURAL_E2E_HEADER",
    "SEMANTIC: ENDPOINT_E2E_INGRESS_QUEUE",
    "SEMANTIC: UPPER_TRANSPORT_QUEUE",
    "SEMANTIC: TOMBSTONE_CANONICAL_72B",
    "SEMANTIC: CELL_64_NO_SIZEOF_PORTABLE_BYTES",
    "SEMANTIC: PROFILE_CHANGE_REQUIRES_NEW_WIRE_PROFILE_ID",
    "SEMANTIC: FRAME_DIGEST_ALG_1_SHA256_OUTER",
    "SEMANTIC: ENCODE_CANON_BE_ONLY",
    "SEMANTIC: TYPE_FLAGS_LOW_NIBBLE_ZERO",
    "SEMANTIC: E2E_SECURITY_ID_NOT_ATTACHMENT",
    "SEMANTIC: WIRE_SIZE_SINGLE_EQ_65_PLUS_N",
    "SEMANTIC: CHANNEL_AIRTIME_FRACTION_NOT_LEGAL_DUTY",
    "SEMANTIC: UNIQUE_SECTION_HEADINGS",
    "SEMANTIC: FORBIDDEN_EDITOR_ARTIFACTS",
)

HKDF_LABELS = (
    "NINLIL-R6-HOP-DATA-KEY-v1",
    "NINLIL-R6-HOP-DATA-IV-v1",
    "NINLIL-R6-HOP-ACK-KEY-v1",
    "NINLIL-R6-HOP-ACK-IV-v1",
    "NINLIL-R6-E2E-KEY-v1",
    "NINLIL-R6-E2E-IV-v1",
)

FORBIDDEN = (
    "Wait - user said",
    "TODO(editor)",
    "FIXME(editor)",
    "implementation-defined",
    "duty_1ch_data",
    "duty_2ch_data",
    "major=1 minor=0",
    "WIRE_SIZE_FORMULA_OUTER_EQ_100_PLUS_N",
    "NINLIL-R6-KEY-v1",
    "entries × sizeof(entry)",
    "canonical 88 B/entry",
    "final-handoff queue",
    "fresh air counters",
    "wall clock",
    "wall-clock",
)

# expected layout: (off, end, sz, full field text exact)
OUTER_FIELDS = (
    (0, 1, 1, "wire_profile_id = 0x11"),
    (1, 2, 1, "kind_flags"),
    (2, 3, 1, "hop_remaining"),
    (3, 7, 4, "hop_context_id (u32 BE, nonzero)"),
    (7, 15, 8, "hop_counter (u64 BE)"),
    (15, 17, 2, "route_handle (u16 BE)"),
    (17, 19, 2, "route_generation (u16 BE)"),
)
E2E_FIELDS = (
    (0, 1, 1, "wire_profile_id = 0x11"),
    (1, 2, 1, "type_flags"),
    (2, 6, 4, "e2e_context_id (u32 BE, nonzero)"),
    (6, 14, 8, "e2e_counter (u64 BE)"),
)
LINK_ACK_FIELDS = (
    (0, 4, 4, "acked_hop_context_id (u32 BE)"),
    (4, 12, 8, "ack_base_counter (u64 BE)"),
    (12, 14, 2, "ack_bitmap (u16 BE)"),
    (14, 15, 1, "ack_code"),
    (15, 16, 1, "reserved0 = 0"),
)
FRAG_START_FIELDS = (
    (0, 16, 16, "transfer_id_128"),
    (16, 24, 8, "transfer_handle (u64 BE)"),
    (24, 28, 4, "total_len (u32 BE)"),
    (28, 30, 2, "frag_count (u16 BE)"),
    (30, 32, 2, "continuation_unit (u16 BE) = 180 exact"),
    (32, 64, 32, "content_digest (SHA-256)"),
)
FRAG_CONT_FIELDS = (
    (0, 8, 8, "transfer_handle (u64 BE)"),
    (8, 10, 2, "frag_index (u16 BE, 1..frag_count-1)"),
)
FRAG_ACK_FIELDS = (
    (0, 8, 8, "transfer_handle (u64 BE)   /* 8B exact; not u32 */"),
    (8, 10, 2, "frag_count (u16 BE)"),
    (10, 12, 2, "received_bitmap (u16 BE; bit0=LSB=START/index0)"),
    (12, 13, 1, "status"),
    (13, 14, 1, "reason"),
)

# Resource expected rows: ALL 21 rows; full set equality required
RESOURCE_EXPECTED = {
    "pairwise peers": ("pairwise peers", "64", "—", "—", "join reject RESOURCE"),
    "hop one-way TX contexts": ("hop one-way TX contexts", "128 (64+64)", "state-only", "context_fence_ttl_ms after fence", "install reject"),
    "hop one-way RX contexts": ("hop one-way RX contexts", "128 (64+64)", "state-only", "same", "install reject"),
    "E2E one-way TX / RX (controller)": ("E2E one-way TX / RX (controller)", "128 / 128", "state-only", "same", "install reject"),
    "Endpoint hop TX/RX each": ("Endpoint hop TX/RX each", "8", "state-only", "same", "install reject"),
    "Endpoint E2E TX/RX each": ("Endpoint E2E TX/RX each", "8", "state-only", "same", "install reject"),
    "route records": ("route records", "128", "state-only", "lease/expiry fields", "install reject; forward TX 0"),
    "endpoint E2E ingress queue (auth hop DATA / sealed E2E blob awaiting E2E processing)": (
        "endpoint E2E ingress queue (auth hop DATA / sealed E2E blob awaiting E2E processing)",
        "32", "8192 B aggregate owned blob payload", "e2e_ingress_queue_ttl_ms",
        "drop admit; LINK_ACK 0; structured RESOURCE",
    ),
    "upper-transport queue (validated SINGLE or completed reassembly app payload)": (
        "upper-transport queue (validated SINGLE or completed reassembly app payload)",
        "16", "8192 B aggregate owned payload", "upper_transport_queue_ttl_ms",
        "COMPLETE→ABORT RESOURCE path; SINGLE drop + structured RESOURCE",
    ),
    "outgoing SINGLE owners": (
        "outgoing SINGLE owners", "32", "6080 B aggregate app payload (32 × max 190 B)",
        "single_sender_item_ttl_ms", "local structured RESOURCE; Seal/Permit/TX 0",
    ),
    "forwarding queue": ("forwarding queue", "64", "16320 B aggregate owned blob payload", "forward_queue_ttl_ms", "forward TX 0; LINK_ACK 0; RESOURCE"),
    "forwarding / ingress peer": ("forwarding / ingress peer", "4", "1020 B", "forward_peer_ttl_ms", "same"),
    "LINK pending/retry groups": (
        "LINK pending/retry groups", "64 groups / 256 counters",
        "copy-own E2E sealed blob ≤220 B each; aggregate ≤14080 B actual blob bytes (independent of forward/ingress queues)",
        "link_retry_group_ttl_ms", "no new pending; §15.3.8 cleanup; local RESOURCE",
    ),
    "LINK pending max attempts": ("LINK pending max attempts", "4 hop air / group", "—", "—", "local fail; §15.3.8 cleanup before blob release"),
    "global issued Permit FIFO": (
        "global issued Permit FIFO", "8 references",
        "state-only; candidate bytes remain in exact owner/group",
        "exact candidate owner/group deadline", "no new issue; FIFO-head scheduler wait",
    ),
    "ACK coalesce": ("ACK coalesce", "32 entries", "32 × 16 B = 512 B canonical LINK_ACK PT coalesce state", "ack_coalesce_ttl_ms", "no expand; separate ACK or ACK 0"),
    "outgoing fragment transfers": ("outgoing fragment transfers", "16", "32768 B", "frag_sender_transfer_ttl_ms", "local abort + upper structured; FRAG_ACK TX 0"),
    "RX reassembly (controller)": (
        "RX reassembly (controller)", "16; max 2/peer", "32768 B",
        "absolute frag_receiver_transfer_ttl_ms + idle frag_idle_timeout_ms", "FRAG ABORT TIMEOUT/RESOURCE",
    ),
    "RX reassembly (endpoint)": ("RX reassembly (endpoint)", "2", "4096 B", "absolute+idle same", "same"),
    "terminal FRAG tombstones + START reservations": (
        "terminal FRAG tombstones + START reservations", "32",
        "TOMBSTONE_CANONICAL_72B = e2e_context_id4 + transfer_id16 + handle8 + frag_count2 + status1 + reason1 + fingerprint32 + expiry_u64_8 (72 B exact; START reservation = one future 72 B slot)",
        "tombstone_ttl_ms=90000", "START reject; ACK 0 only (no unowned ABORT RESOURCE)",
    ),
    "control ACK reserve": ("control ACK reserve", "8 frames", "8 × 79 B = 632 B max FRAG_ACK outer budget", "control_ack_reserve_ttl_ms", "non-control cannot use; TX 0"),
    "L1 Seal output slot registry": (
        "L1 Seal output slot registry",
        "128 live slots max",
        "per-slot capacity 1..255 B; aggregate capacity sum ≤ 32640 B; includes slots later adopted as LINK-group E2E blobs (do not double-allocate/count same bytes — ledger ownership moves; LINK group aggregate still applies simultaneously without second ownership of same bytes)",
        "prep-pair lifetime / release tables",
        "claim token+slot before STAMP and before any counter burn; capacity/bytes fail ⇒ STAMP/event 0, burn/Seal/Permit/TX 0 + structured RESOURCE; at most one output slot per live prep pair; unique nonzero token; release returns capacity",
    ),
}

TIMER_EXPECTED = {
    "link_ack_wait_ms": ("3000", "per-attempt ACK deadline component of eligible_at"),
    "link_retry_interval_ms": ("500", "min spacing component of eligible_at"),
    "link_retry_group_ttl_ms": ("15000", "group absolute fail; §15.3.8 cleanup before blob release"),
    "ack_coalesce_ttl_ms": ("200", "flush coalesce or drop expand"),
    "e2e_ingress_queue_ttl_ms": ("5000", "drop E2E ingress item; LINK_ACK 0; structured local fail"),
    "upper_transport_queue_ttl_ms": ("5000", "drop upper payload; structured local fail"),
    "single_sender_item_ttl_ms": ("30000", "local SINGLE fail; §15.3.8 cleanup before payload/candidate release; TX 0"),
    "forward_queue_ttl_ms": ("5000", "drop; TX 0 / RESOURCE"),
    "forward_peer_ttl_ms": ("5000", "same"),
    "frag_ack_wait_ms": ("5000", "after LINK group success, wait for covering FRAG_ACK"),
    "frag_retry_interval_ms": ("500", "min spacing before next E2E fragment attempt"),
    "frag_sender_transfer_ttl_ms": ("90000", "sender transfer absolute TTL; §15.3.8 cleanup before outgoing transfer release"),
    "frag_receiver_transfer_ttl_ms": ("90000", "receiver absolute transfer deadline from first START"),
    "frag_idle_timeout_ms": ("20000", "receiver idle deadline; refresh only on newly accepted CONT; ≤ absolute"),
    "frag_partial_ack_idle_ms": (
        "2000",
        "checked due for incomplete bitmap after START/incomplete new CONT/active exact duplicate; never postpone",
    ),
    "tombstone_ttl_ms": ("90000", "free tombstone slot (volatile; ≥ sender horizon; restart discards)"),
    "context_fence_ttl_ms": ("30000", "capacity reclaim after fence"),
    "route_lease_check_ms": ("1000", "revalidate lease/expiry"),
    "control_ack_reserve_ttl_ms": ("3000", "§15.3.8 cleanup before reserve release"),
    "permit_issue_retry_ms": ("100", "positive scheduler backoff; max 8 exact issue calls/candidate"),
    "permit_tx_retry_ms": ("100", "positive scheduler backoff; max 8 full transmit pipeline calls/candidate"),
}

OWNER_EXPECTED = (
    (
        "local source FRAG_START/CONT",
        "outgoing fragment transfer; sender_absolute_deadline",
        "yes",
        "group copy-owns sealed blob; transfer payload/state remains until terminal transfer",
    ),
    (
        "local source SINGLE",
        "outgoing SINGLE owner; single_sender_item_deadline",
        "yes",
        "after successful E2E Seal + group copy-own, release SINGLE payload entry; group reports ACKED/terminal to upper owner",
    ),
    (
        "relay DATA (opaque SINGLE/FRAG/FRAG_ACK blob)",
        "forwarding queue item; forward_item_deadline",
        "yes",
        "relay never uses source sender deadline; dequeue-to-group transfers deadline and copy-owns blob; group completion/fail applies §15.3.8 three-way cleanup before release",
    ),
    (
        "local fragment receiver FRAG_ACK",
        "control ACK reserve; min(control_ack_deadline, receiver_absolute_deadline) for active PARTIAL or min(control_ack_deadline, tombstone_expiry) for terminal ACK",
        "yes",
        "group owns sealed ACK blob; ACKED/terminal/deadline applies §15.3.8 three-way cleanup before reserve/blob release",
    ),
    (
        "local LINK_ACK",
        "ACK coalesce entry; ack_coalesce_deadline",
        "no (ACK-of-ACK forbidden)",
        "one prepared hop ACK candidate only; sole TX outcome/issue denial/deadline applies §15.3.8 three-way cleanup before release",
    ),
)

# Full PCP 0..23 must appear in §15.3.2
PCP_STATUS_SET = {
    "NINLIL_PCP_OK (0)",
    "NINLIL_PCP_INVALID_ARGUMENT (1)",
    "NINLIL_PCP_INVALID_STATE (2)",
    "NINLIL_PCP_STRUCT (3)",
    "NINLIL_PCP_CLOCK_UNCERTAIN (4)",
    "NINLIL_PCP_CLOCK_FAULT (5)",
    "NINLIL_PCP_PROFILE_MISMATCH (6)",
    "NINLIL_PCP_CAPACITY (7)",
    "NINLIL_PCP_SEQ_EXHAUSTED (8)",
    "NINLIL_PCP_STORAGE_FENCE (9)",
    "NINLIL_PCP_CORRUPT_FENCE (10)",
    "NINLIL_PCP_COMMIT_UNKNOWN (11)",
    "NINLIL_PCP_STORAGE_IO (12)",
    "NINLIL_PCP_BUSY (13)",
    "NINLIL_PCP_BUSY_OUTSTANDING (14)",
    "NINLIL_PCP_BUSY_REENTRY (15)",
    "NINLIL_PCP_ALIAS (16)",
    "NINLIL_PCP_UNBOUND_STORAGE (17)",
    "NINLIL_PCP_UNBOUND_CLOCK (18)",
    "NINLIL_PCP_UNBOUND_ASSIGNMENT (19)",
    "NINLIL_PCP_RECOVER_FAIL (20)",
    "NINLIL_PCP_STORAGE_UNSUPPORTED (21)",
    "NINLIL_PCP_SHUTDOWN (22)",
    "NINLIL_PCP_EMPTY_OK (23)",
}

R5_STATUS_SET = {
    f"NINLIL_R5_{name} ({code})"
    for code, name in enumerate((
        "OK", "INVALID_ARGUMENT", "INVALID_STATE", "STRUCT", "PROFILE_DENIED",
        "BIND_MISMATCH", "CAPACITY", "BUSY_OUTSTANDING", "AIRTIME", "PCP",
        "REGISTRY_MISS", "UNSUPPORTED", "SHUTDOWN", "ALIAS", "BUSY_REENTRY",
        "PROFILE_EXPIRED", "PROFILE_NOT_EFFECTIVE",
    ))
}

RECONCILE_PHASE_EXPECTED = (
    ("DRAIN_STOP", "L1 stops R1 TX edges and new issue; mark all live issued snapshots QUARANTINED; quarantine-linked groups/candidates", "sticky TX 0"),
    ("DRAIN_RECOVER_STORAGE", "if restart / COMMIT_UNKNOWN / STORAGE fence / durable ambiguity: ninlil_pcp_recover_storage only; copy-own inputs; else skip", "fail ⇒ sticky TX 0"),
    ("DRAIN_REVOKE", "ninlil_pcp_revoke_all_outstanding (clockless) until durable outstanding 0; never invent cancel; never ordinary fence_after_revoke", "non-OK after budget ⇒ OPERATOR_RECOVERY_REQUIRED"),
    ("DRAIN_CLOCK", "after outstanding 0: four-way classify / boot baseline or RAM arm + recover_clock / private adopt as class requires; hold L1 watermark until adopt done if class C; ordinary same-epoch cancel / owner deadline drain with class D and no CLOCK fence ⇒ CLOCK stage NOOP", "fail ⇒ sticky TX 0"),
    ("DRAIN_BASELINE_INIT", "typed baseline snapshot + L1 epoch/watermark init (class A repair or post-adopt sample_valid=1 or boot bootstrap); not exported recover_clock S", "fail ⇒ sticky TX 0"),
    ("DRAIN_R5_CLEAR", "only after durable outstanding zero: ninlil_r5_shutdown; MUST NOT before zero", "fail ⇒ sticky TX 0"),
    ("DRAIN_R5_REBUILD", "init; reload HW+REG; activate; ninlil_r5_bind_pcp", "fail ⇒ sticky TX 0"),
    ("DRAIN_PROFILE_EPOCH", "revalidate active profiles have profile_clock_epoch_id == L1 current epoch; else TX 0 until reload (sidecar; §15.3.1.1 / P1(40))", "no match ⇒ TX 0"),
    ("DRAIN_U5_RESUME", "U5 same-gen revalidate/bind or SET L0–L4 RESTORE/DUP / L5–L9 APPLY; ARW alone insufficient; generation bit-exact", "no active bind ⇒ TX 0"),
    ("DRAIN_OWNER_CLEANUP", "§15.3.3.1 all quarantined issued TERMINAL/STALE; FIFO full clear; unissued by trigger", "—"),
    ("DRAIN_OK", "resume issue only if U5 bind valid + generation bit-exact + profile epoch match", "—"),
)

DRAIN_COMMIT_UNKNOWN_REENTRY_EXPECTED = (
    ("DRAIN_RECOVER_STORAGE", "remain/re-enter storage-only; no revoke yet", "NO fence target"),
    ("DRAIN_REVOKE", "re-enter storage-only then revoke until OK + outstanding 0", "NO fence target"),
    ("DRAIN_CLOCK / DRAIN_BASELINE_INIT", "storage ambiguity → storage-only; else re-enter clock/baseline with outstanding 0; adopt UNKNOWN → proposed/old compare (§11.2.3.1)", "NO fence target"),
    ("DRAIN_R5_CLEAR / REBUILD / RESUME", "no R2 durable COMMIT_UNKNOWN ordinary path; failure sticky TX 0", "n/a"),
)

L1_RESULT_CLASS_SET = frozenset({
    "OK_ISSUED",
    "RETRYABLE_UNISSUED",
    "TERMINAL_UNISSUED",
    "CLOCK_PATH_DROP",
    "RECONCILE_REQUIRED",
    "AUTHORITY_DIVERGENCE",
    "EPOCH_TRANSITION_REQUIRED",
    "EPOCH_W1_REPAIR",
    "FIFO_OUT_OF_ORDER",
    "OPERATOR_RECOVERY_REQUIRED",
    "RETRYABLE_PIPELINE",
})

# Exact §15.3.4 closed table (post-_norm_cell; 8 rows; exact ordered equality)
R1_RESULT_EXPECTED = (
    (
        "NINLIL_RADIO_HAL_OK",
        "consume succeeded and sole TX edge was invoked once; increment hop air attempt; candidate/Permit never reusable",
    ),
    (
        "NINLIL_RADIO_HAL_NOT_BEFORE at validate/time (HAL reason 16), edge invocation 0",
        "raw retryable tuple (validate HAL16); L1 RETRY_GATE OPEN/CLOSED exclusive per §1.1.2 TX_RESULT_RETRY_GATE (OPEN ⇒ same-Permit full R1 only +100ms; CLOSED ⇒ TX_QUARANTINE/drain)",
    ),
    (
        "NINLIL_RADIO_HAL_CONSUME_DENIED at PERMIT_CONSUME with typed reason 16 NOT_BEFORE only, edge 0",
        "raw retryable tuple (consume HAL16; consume callback entered); L1 RETRY_GATE OPEN/CLOSED exclusive per §1.1.2 TX_RESULT_RETRY_GATE",
    ),
    (
        "NINLIL_RADIO_HAL_CONSUME_DENIED at PERMIT_CONSUME with typed reason 45 CONSUME_BUSY only, edge 0",
        "raw retryable tuple (consume HAL45; consume callback entered); L1 RETRY_GATE OPEN/CLOSED exclusive per §1.1.2 TX_RESULT_RETRY_GATE",
    ),
    (
        "NINLIL_RADIO_HAL_EXPIRED",
        "MUST NOT treat advance_expired_heads alone as cleanup; enter §15.3.3 exported private-module drain",
    ),
    (
        "NINLIL_RADIO_HAL_CONSUME_DENIED at PERMIT_CONSUME with R1 HAL reason 43 FIFO_OUT_OF_ORDER (see §15.3.4.1), edge invocation 0, mutation 0",
        "usual retry forbidden; no same-Permit +100ms path; enter §15.3.3 drain / FIFO reconcile",
    ),
    (
        "EDGE_ERROR after consume success + edge already invoked",
        "consume done and edge invoked ⇒ R5/R2 cleanup already applied for that Permit; no-drain terminal for that Permit; owner/LINK group terminal; no same-Permit reuse",
    ),
    (
        "NINLIL_RADIO_HAL_CONSUME_FENCED, CONSUME_ERROR, PERMIT_DENIED, PERMIT_ERROR, BUSY, FRAME_MISMATCH, SEQ_REUSE, LIVE_MISMATCH, UNSUPPORTED, SEQ_EXHAUSTED, invalid/default-deny, any stage/reason/plan-shape mismatch, or unknown with edge invocation 0",
        "no same-Permit reuse; R1 is entered only after OK_ISSUED ⇒ issued existence; MUST enter §15.3.3 drain / TX_QUARANTINE path; no mutation-0 unissued-proven local-terminal branch in R1 (unissued terminal is PRE_R1 only → OWNER_TERMINAL)",
    ),
)

# Exact §1.1.2 TX_RESULT mapping (post-_norm_cell; 12 rows × 11 cols; exact ordered equality)
TX_RESULT_MAP_EXPECTED = (
    (
        "1",
        "OK: consume success + sole TX edge entered once",
        "0 OK",
        "10 EDGE",
        "0 NONE",
        "TX_EDGE_DONE",
        "STALE_NO_RETRY",
        "1",
        "1",
        "pair terminal exactly once",
        "per TX_EDGE_DONE_ACK_POLICY",
    ),
    (
        "2",
        "validate HAL16 NOT_BEFORE RETRY_GATE_OPEN",
        "11 NOT_BEFORE",
        "7 PERMIT_VALIDATE",
        "16 NOT_BEFORE",
        "TX_RETRY_SAME_PERMIT",
        "RETAIN_SEALED",
        "0",
        "0",
        "pair nonterminal; full R1 only same Permit+sealed; calls_used<8; retry_not_before=permit_tx_retry_at",
        "unchanged",
    ),
    (
        "3",
        "validate HAL16 NOT_BEFORE RETRY_GATE_CLOSED",
        "11 NOT_BEFORE",
        "7 PERMIT_VALIDATE",
        "16 NOT_BEFORE",
        "TX_QUARANTINE",
        "QUARANTINE",
        "0",
        "0",
        "pair nonterminal quarantine; issued ⇒ drain (never local terminal/release); DRAIN then OWNER_TERMINAL",
        "as drain",
    ),
    (
        "4",
        "consume HAL16 NOT_BEFORE RETRY_GATE_OPEN",
        "6 CONSUME_DENIED",
        "8 PERMIT_CONSUME",
        "16 NOT_BEFORE",
        "TX_RETRY_SAME_PERMIT",
        "RETAIN_SEALED",
        "1",
        "0",
        "pair nonterminal; full R1 only same Permit+sealed; calls_used<8; retry_not_before=permit_tx_retry_at",
        "unchanged",
    ),
    (
        "5",
        "consume HAL16 NOT_BEFORE RETRY_GATE_CLOSED",
        "6 CONSUME_DENIED",
        "8 PERMIT_CONSUME",
        "16 NOT_BEFORE",
        "TX_QUARANTINE",
        "QUARANTINE",
        "1",
        "0",
        "pair nonterminal quarantine; issued ⇒ drain (never local terminal/release); DRAIN then OWNER_TERMINAL",
        "as drain",
    ),
    (
        "6",
        "consume HAL45 CONSUME_BUSY RETRY_GATE_OPEN",
        "6 CONSUME_DENIED",
        "8 PERMIT_CONSUME",
        "45 CONSUME_BUSY",
        "TX_RETRY_SAME_PERMIT",
        "RETAIN_SEALED",
        "1",
        "0",
        "pair nonterminal; full R1 only same Permit+sealed; calls_used<8; retry_not_before=permit_tx_retry_at",
        "unchanged",
    ),
    (
        "7",
        "consume HAL45 CONSUME_BUSY RETRY_GATE_CLOSED",
        "6 CONSUME_DENIED",
        "8 PERMIT_CONSUME",
        "45 CONSUME_BUSY",
        "TX_QUARANTINE",
        "QUARANTINE",
        "1",
        "0",
        "pair nonterminal quarantine; issued ⇒ drain (never local terminal/release); DRAIN then OWNER_TERMINAL",
        "as drain",
    ),
    (
        "8",
        "EDGE_ERROR after consume success + edge entered",
        "8 EDGE_ERROR",
        "10 EDGE",
        "12 EDGE_FAIL",
        "TX_STALE_NO_RETRY",
        "STALE_NO_RETRY",
        "1",
        "1",
        "pair terminal",
        "group cleanup §15.3.8; no-drain for that Permit",
    ),
    (
        "9",
        "FIFO HAL43 (consume callback entered)",
        "6 CONSUME_DENIED",
        "8 PERMIT_CONSUME",
        "43 FIFO_OUT_OF_ORDER",
        "TX_QUARANTINE",
        "QUARANTINE",
        "1",
        "0",
        "pair nonterminal quarantine; DRAIN + OWNER_TERMINAL after proof",
        "as drain",
    ),
    (
        "10",
        "CLOCK HAL44 (consume callback entered)",
        "6 CONSUME_DENIED",
        "8 PERMIT_CONSUME",
        "44 CONSUME_CLOCK_UNCERTAIN",
        "TX_QUARANTINE",
        "QUARANTINE",
        "1",
        "0",
        "pair nonterminal quarantine; global volatile freeze only borrow-safe/drain-safe; DRAIN + OWNER_TERMINAL",
        "as drain",
    ),
    (
        "11",
        "All other failures before consume callback entry, excluding exact validate HAL16 rows 2–3 (args/live/time/digest/validate/pre-consume seq/shape/default/EXPIRED at validate etc., not status=11/stage=7/reason=16)",
        "exact closed R1 status/stage/reason for that reject",
        "(as R1)",
        "(as R1)",
        "TX_QUARANTINE",
        "QUARANTINE",
        "0",
        "0",
        "pair nonterminal quarantine; OK_ISSUED exists ⇒ drain (never local TX_TERMINAL/release)",
        "as drain",
    ),
    (
        "12",
        "All other failures after consume callback entry but before edge, excluding exact consume HAL16 rows 4–5, consume HAL45 rows 6–7, HAL43 row 9, HAL44 row 10 (CONSUME_FENCED/ERROR, unexpected consume return, post-consume plan fault etc., not tuples 6/8/16, 6/8/45, 6/8/43, 6/8/44)",
        "exact closed R1 status/stage/reason for that reject",
        "(as R1)",
        "(as R1)",
        "TX_QUARANTINE",
        "QUARANTINE",
        "1",
        "0",
        "pair nonterminal quarantine; drain (never local unissued release)",
        "as drain",
    ),
)

# FRAME 2×4 exact ordered equality (post-_norm_cell)
FRAME_LAYER_BURN_EXPECTED = (
    ("E2E_BLOB", "1..4", "1 E2E", "E2E sealed blob in L1 output slot"),
    ("OUTER_FRAME", "1..5", "2 HOP", "final outer frame in L1 output slot"),
)

# TX_EDGE_DONE_ACK_POLICY 3×5 exact ordered equality (post-_norm_cell)
TX_EDGE_DONE_ACK_EXPECTED = (
    (
        "DATA + outer_ack_requested=1",
        "terminal-for-pair / nonterminal-for-group (never simply “non-terminal”)",
        "WAIT_LINK_ACK; may timeout→fresh HOP DATA; ACK timer path active (§11.2)",
        "retain",
        "release once after R1 return/TX_RESULT (OUTER_OUTPUT_SLOT_RELEASE_TABLE); fresh HOP gets fresh OUTER",
    ),
    (
        "DATA + outer_ack_requested=0",
        "terminal-for-pair; receiver ACK TX 0",
        "close group as UNACKED_LINK_SUCCESS (no WAIT_LINK_ACK / no ACK timer / no retry) after sibling/borrow cleanup",
        "release only after cleanup (E2E table)",
        "release once after R1 return/TX_RESULT",
    ),
    (
        "LOCAL_LINK_ACK",
        "terminal-for-pair",
        "no group; close ACK-coalesce owner",
        "n/a",
        "same pair result release rules",
    ),
)

CLOCK_HANDOFF_EXPECTED = (
    (
        "single domain for all CELL timers",
        "every §13.1 timer and every L1-stamped *_mono uses R2 authority domain inside one clock_epoch_id; no second local/OS mono",
    ),
    (
        "sample sole owner",
        "only §11.2.3 ninlil_r2_private_sample_authority_clock with closed request/result signatures may produce stampable samples",
    ),
    (
        "now_mono identity",
        "now_mono is accepted trusted sample now_ms; watermark rules in §11.2.2",
    ),
    (
        "sole-owner watermark",
        "L1 updates l1_last_accepted_now_ms / w1_last_accepted_now_ms only after accepted same-epoch class-D (fences clear); same-epoch regression ⇒ CLOCK_FAULT + durable latch",
    ),
    (
        "owner admission sample",
        "SAMPLE_TRUSTED_SAME_EPOCH only; store clock_epoch_id; set deadlines as checked_add(sample.now_ms, ttl)",
    ),
    (
        "issue primitive inputs",
        "static candidate + expected epoch + L1 watermark + owner deadline only; R5-internal window after S; same-S not_before/expiry; returned window registry/R1; forbids Algorithm E and pre-sample absolute window compose",
    ),
    ("four-way epoch class", "D same+fences clear; A L1 repair no adopt; B authority divergence drain bounded→OPERATOR_RECOVERY; C new-epoch drain+adopt; no OR-bulk recover"),
    (
        "TEMP/uncertain",
        "discard old work; later same-epoch class-D fresh admission OK",
    ),
    (
        "regression / CLOCK_FAULT",
        "same-epoch admission forbidden; durable latch survives restart; require fresh-epoch class-C adopt + latch clear; not RETRYABLE_UNISSUED",
    ),
    (
        "routine sample floors",
        "ram_trust mirror + L1 watermark; no storage RO on timer path; baseline snapshot boot/adopt only",
    ),
    (
        "route lease external domain",
        "not same domain ⇒ route TX 0; M4 same-domain deadline required",
    ),
    (
        "cross-epoch / race",
        "R7 vectors: classes A/B/C/D, adopt only C, baseline boot-only RO, L1 watermark held until adopt done, CU token lifetime, durable CLOCK_FAULT latch",
    ),
)

TIMER_DOMAIN_EXPECTED = {
    "link_ack_wait_ms": ("R2 authority epoch domain", "drop LINK group; TX 0"),
    "link_retry_interval_ms": ("R2 authority epoch domain", "drop LINK group; TX 0"),
    "link_retry_group_ttl_ms": ("R2 authority epoch domain", "drop LINK group + three-way cleanup"),
    "ack_coalesce_ttl_ms": ("R2 authority epoch domain", "drop coalesce entry; ACK 0"),
    "e2e_ingress_queue_ttl_ms": ("R2 authority epoch domain", "drop ingress item; LINK_ACK 0"),
    "upper_transport_queue_ttl_ms": ("R2 authority epoch domain", "drop upper item; deliver 0"),
    "single_sender_item_ttl_ms": ("R2 authority epoch domain", "drop SINGLE owner; three-way cleanup"),
    "forward_queue_ttl_ms": ("R2 authority epoch domain", "drop forward item; TX 0"),
    "forward_peer_ttl_ms": ("R2 authority epoch domain", "drop peer quota; TX 0"),
    "frag_ack_wait_ms": ("R2 authority epoch domain", "sender transfer terminal path; three-way cleanup"),
    "frag_retry_interval_ms": ("R2 authority epoch domain", "no schedule across epoch"),
    "frag_sender_transfer_ttl_ms": ("R2 authority epoch domain", "drop outgoing transfer; three-way cleanup"),
    "frag_receiver_transfer_ttl_ms": ("R2 authority epoch domain", "drop reassembly/reservation/tombstone/ACK intent"),
    "frag_idle_timeout_ms": ("R2 authority epoch domain", "same as receiver absolute"),
    "frag_partial_ack_idle_ms": ("R2 authority epoch domain", "drop PARTIAL intent; ACK 0"),
    "tombstone_ttl_ms": ("R2 authority epoch domain", "drop tombstone/reservation"),
    "context_fence_ttl_ms": ("R2 authority epoch domain", "reclaim only under CONTEXT_FENCE_STAMP_EPOCH_RECLAIM_CLOSED"),
    "route_lease_check_ms": ("R2 authority epoch domain; external lease not same-domain ⇒ route TX 0", "revalidate or TX 0"),
    "control_ack_reserve_ttl_ms": ("R2 authority epoch domain", "release reserve; ACK 0"),
    "permit_issue_retry_ms": ("R2 authority epoch domain", "cancel issue retry schedule; three-way cleanup"),
    "permit_tx_retry_ms": ("R2 authority epoch domain", "cancel full-pipeline retry; three-way cleanup"),
}

CANCEL_MATRIX_EXPECTED = (
    (
        "COMPLETE",
        "cancel; commit only after three-way cleanup / TERMINAL_PENDING",
        "unissued cancel/release with commit",
        "§15.3.3 drain before commit",
        "stale/no-retry; then commit",
    ),
    (
        "ABORT DIGEST",
        "same",
        "same",
        "§15.3.3 drain before commit",
        "stale/no-retry; then commit",
    ),
    (
        "ABORT RESOURCE",
        "same",
        "same",
        "§15.3.3 drain before commit",
        "stale/no-retry; then commit",
    ),
    (
        "ABORT CONFLICT",
        "same",
        "same",
        "§15.3.3 drain before commit",
        "stale/no-retry; then commit",
    ),
    (
        "ABORT TIMEOUT",
        "same",
        "same",
        "§15.3.3 drain before commit",
        "stale/no-retry; then commit",
    ),
    (
        "ABORT FENCED",
        "same",
        "same",
        "§15.3.3 drain before commit",
        "stale/no-retry; then commit",
    ),
    (
        "tombstone expiry overflow fence",
        "cancel; no reusable release",
        "cancel; no reusable release",
        "§15.3.3 if issued may exist",
        "irrevocable; TX 0",
    ),
    (
        "authority epoch change / uncertain / CLOCK_FAULT",
        "drop intent",
        "drop all volatile RX+TX",
        "§15.3.3 if issued",
        "stale; TX/ACK/deliver 0",
    ),
    (
        "owner/process restart",
        "discard volatile",
        "discard volatile",
        "TX 0 until exported private-module drain + U5 resume (§15.3.3)",
        "N/A (volatile)",
    ),
)


class GateFailure(Exception):
    pass


def fail(msg: str) -> None:
    raise GateFailure(msg)


def read(root: pathlib.Path, rel: str) -> str:
    path = root / rel
    if not path.is_file():
        fail(f"missing {rel}")
    return path.read_text(encoding="utf-8")


def require_contains(text: str, needle: str, where: str) -> None:
    if needle not in text:
        fail(f"{where} must contain {needle!r}")


def require_absent(text: str, needle: str, where: str) -> None:
    if needle in text:
        fail(f"{where} must not contain {needle!r}")


def require_exact_count(text: str, needle: str, count: int, where: str) -> None:
    actual = text.count(needle)
    if actual != count:
        fail(f"{where} must contain {needle!r} exactly {count} times, got {actual}")


def parse_layout(doc: str, begin: str, end: str) -> list[tuple[int, int, int, str]]:
    """Parse layout between exact whole-line BEGIN/END markers (each exactly once)."""
    lines = doc.splitlines()
    b_idxs = [i for i, ln in enumerate(lines) if ln.rstrip("\r") == begin]
    e_idxs = [i for i, ln in enumerate(lines) if ln.rstrip("\r") == end]
    if len(b_idxs) != 1:
        fail(f"layout begin {begin!r} count={len(b_idxs)} (need exactly 1)")
    if len(e_idxs) != 1:
        fail(f"layout end {end!r} count={len(e_idxs)} (need exactly 1)")
    bi, ei = b_idxs[0], e_idxs[0]
    if ei <= bi:
        fail(f"layout end before begin for {begin}")
    rows: list[tuple[int, int, int, str]] = []
    for line in lines[bi + 1 : ei]:
        m = re.match(r"^(\d+)\s+(\d+)\s+(\d+)\s+(\S+.*)$", line.strip())
        if m:
            rows.append(
                (int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4).strip())
            )
    if not rows:
        fail(f"empty {begin}")
    return rows


def check_layout_exact(
    rows: list[tuple[int, int, int, str]],
    expected: tuple[tuple[int, int, int, str], ...],
    title: str,
) -> None:
    if len(rows) != len(expected):
        fail(f"{title}: row count {len(rows)}!={len(expected)}")
    pos = 0
    for (off, end_o, sz, name), (eo, ee, es, en) in zip(rows, expected):
        if off != eo or end_o != ee or sz != es:
            fail(f"{title}: field {en!r} got off/end/sz={off}/{end_o}/{sz}")
        if off != pos or end_o != off + sz:
            fail(f"{title}: continuity fail at {en!r}")
        if name != en:
            fail(f"{title}: field text {name!r} != exact {en!r}")
        pos = end_o
    total = expected[-1][1]
    if pos != total:
        fail(f"{title}: coverage {pos}!={total}")


def _norm_cell(s: str) -> str:
    s = s.strip()
    s = s.replace("**", "")
    s = s.replace("`", "")
    s = re.sub(r"\s+", " ", s)
    return s


def _section(doc: str, start_h: str, end_h: str) -> str:
    """Slice between exact whole-line headings (start inclusive, end exclusive)."""
    lines = doc.splitlines(keepends=True)
    # rebuild without keepends for matching
    plain = [ln.rstrip("\r\n") for ln in doc.splitlines()]
    s_idxs = [i for i, ln in enumerate(plain) if ln == start_h]
    e_idxs = [i for i, ln in enumerate(plain) if ln == end_h]
    if len(s_idxs) != 1:
        fail(f"start heading {start_h!r} count={len(s_idxs)} (need exactly 1)")
    if len(e_idxs) != 1:
        fail(f"end heading {end_h!r} count={len(e_idxs)} (need exactly 1)")
    s, e = s_idxs[0], e_idxs[0]
    if e <= s:
        fail(f"end heading index {e} not after start {s}")
    return "".join(lines[s:e])


def _is_gfm_separator(cells: list[str], width: int) -> bool:
    return len(cells) == width and all(
        bool(cell.replace(" ", ""))
        and re.fullmatch(r":?-+:?", cell.replace(" ", "")) is not None
        for cell in cells
    )


def _count_gfm_tables(scope: str) -> int:
    """Count GFM tables as sequences starting at a header line followed by a separator line."""
    lines = [ln.rstrip("\r") for ln in scope.splitlines()]
    n = 0
    i = 0
    while i < len(lines) - 1:
        if lines[i].strip().startswith("|") and lines[i + 1].strip().startswith("|"):
            cells = [_norm_cell(c) for c in lines[i].strip().strip("|").split("|")]
            sep = [_norm_cell(c) for c in lines[i + 1].strip().strip("|").split("|")]
            if cells and _is_gfm_separator(sep, len(cells)):
                n += 1
                i += 2
                while i < len(lines) and lines[i].strip().startswith("|"):
                    i += 1
                continue
        i += 1
    return n


def _parse_table_in_scope(scope: str, expected_header: tuple[str, ...]) -> list[tuple[str, ...]]:
    """Require exactly one GFM table in scope; its header must exactly equal expected_header."""
    if _count_gfm_tables(scope) != 1:
        fail(f"scope must contain exactly one GFM table, found {_count_gfm_tables(scope)}")
    lines = scope.splitlines()
    start = None
    for i, line in enumerate(lines):
        if not line.strip().startswith("|"):
            continue
        cells = [_norm_cell(c) for c in line.strip().strip("|").split("|")]
        if _is_gfm_separator(cells, len(expected_header)):
            continue
        # header candidate: next line is separator
        if i + 1 >= len(lines) or not lines[i + 1].strip().startswith("|"):
            continue
        sep = [_norm_cell(c) for c in lines[i + 1].strip().strip("|").split("|")]
        if not _is_gfm_separator(sep, len(cells)):
            continue
        if tuple(cells) != expected_header:
            fail(f"table header {tuple(cells)!r} != exact {expected_header!r}")
        start = i
        break
    if start is None:
        fail(f"exact header {expected_header} not found as sole table in scope")
    rows: list[tuple[str, ...]] = []
    for line in lines[start + 2 :]:
        if not line.strip().startswith("|"):
            break
        cells = [_norm_cell(c) for c in line.strip().strip("|").split("|")]
        if _is_gfm_separator(cells, len(expected_header)):
            continue
        if len(cells) != len(expected_header):
            fail(f"table row width {len(cells)} != {len(expected_header)}: {cells}")
        rows.append(tuple(cells))
    if not rows:
        fail("empty table body in scope")
    return rows


def _parse_table_by_header(scope: str, expected_header: tuple[str, ...]) -> list[tuple[str, ...]]:
    """Find GFM table by exact header among zero or more tables in scope.

    Collects **all** exact-header table starts in scope and requires **exactly one**.
    0 or >1 matching headers is a contract failure (prevents silent first-table false-green).
    Other tables with different headers in the same scope remain allowed.
    """
    lines = scope.splitlines()
    starts: list[int] = []
    for i, line in enumerate(lines):
        if not line.strip().startswith("|"):
            continue
        cells = [_norm_cell(c) for c in line.strip().strip("|").split("|")]
        if i + 1 >= len(lines) or not lines[i + 1].strip().startswith("|"):
            continue
        sep = [_norm_cell(c) for c in lines[i + 1].strip().strip("|").split("|")]
        if not _is_gfm_separator(sep, len(cells)):
            continue
        if tuple(cells) != expected_header:
            continue
        starts.append(i)
    if not starts:
        fail(f"header {expected_header} not found in multi-table scope")
    if len(starts) > 1:
        fail(
            f"header {expected_header} matched {len(starts)} tables in scope "
            f"(require exactly one; starts at lines {starts!r})"
        )
    start = starts[0]
    rows: list[tuple[str, ...]] = []
    for line in lines[start + 2 :]:
        if not line.strip().startswith("|"):
            break
        cells = [_norm_cell(c) for c in line.strip().strip("|").split("|")]
        if _is_gfm_separator(cells, len(expected_header)):
            continue
        if len(cells) != len(expected_header):
            fail(f"table row width {len(cells)} != {len(expected_header)}: {cells}")
        rows.append(tuple(cells))
    if not rows:
        fail("empty table body for header")
    return rows


def check_resource_table(doc: str) -> None:
    scope = _section(
        doc,
        "## 13. Resources (CELL_64_V1)",
        "### 13.1 CELL_64_V1 exact default timers",
    )
    header = (
        "item",
        "entries",
        "owned payload / canonical bytes",
        "TTL",
        "overflow action",
    )
    rows = _parse_table_in_scope(scope, header)
    seen: dict[str, tuple[str, ...]] = {}
    for row in rows:
        item = row[0]
        if item in seen:
            fail(f"duplicate resource item {item!r}")
        seen[item] = row
    if set(seen) != set(RESOURCE_EXPECTED):
        fail(
            f"resource item set mismatch missing={sorted(set(RESOURCE_EXPECTED)-set(seen))} "
            f"extra={sorted(set(seen)-set(RESOURCE_EXPECTED))}"
        )
    for item, expected in RESOURCE_EXPECTED.items():
        if seen[item] != expected:
            fail(f"resource row mismatch for {item!r}: got {seen[item]!r} expected {expected!r}")


def check_timer_table(doc: str) -> None:
    scope = _section(
        doc,
        "### 13.1 CELL_64_V1 exact default timers",
        "### 13.2 Storage capacity preflight (honest; ESP not ready)",
    )
    header = ("timer", "value", "on expiry")
    rows = _parse_table_in_scope(scope, header)
    seen: dict[str, tuple[str, str]] = {}
    for row in rows:
        name, val, exp = row[0], row[1], row[2]
        if name in seen:
            fail(f"duplicate timer {name!r}")
        seen[name] = (val, exp)
    if set(seen) != set(TIMER_EXPECTED):
        missing = set(TIMER_EXPECTED) - set(seen)
        extra = set(seen) - set(TIMER_EXPECTED)
        fail(f"timer set mismatch missing={sorted(missing)} extra={sorted(extra)}")
    for name, expected in TIMER_EXPECTED.items():
        if seen[name] != expected:
            fail(f"timer {name!r}: got {seen[name]!r} expected {expected!r}")


def check_closed_transition_tables(doc: str) -> None:
    owner_scope = _section(
        doc,
        "##### 11.2.1 Outbound owner/deadline matrix (closed)",
        "##### 11.2.2 L1 authority-clock domain + watermark (closed)",
    )
    owner_rows = _parse_table_in_scope(
        owner_scope,
        ("outbound class", "owning resource and immutable enclosing_owner_deadline", "LINK retry group", "ownership / release"),
    )
    if tuple(owner_rows) != OWNER_EXPECTED:
        fail(f"owner/deadline matrix mismatch: got={owner_rows!r}")

    # timer domain table inside 11.2.2
    td_scope = _section(
        doc,
        "##### 11.2.2 L1 authority-clock domain + watermark (closed)",
        "#### 11.3 LINK_ACK RX validation (DATA sender / pending-owner)",
    )
    td_rows = _parse_table_by_header(td_scope, ("timer", "domain", "on epoch change / uncertain / regression"))
    seen = {r[0]: (r[1], r[2]) for r in td_rows}
    if set(seen) != set(TIMER_DOMAIN_EXPECTED):
        fail(
            f"timer domain set mismatch missing={sorted(set(TIMER_DOMAIN_EXPECTED)-set(seen))} "
            f"extra={sorted(set(seen)-set(TIMER_DOMAIN_EXPECTED))}"
        )
    for name, exp in TIMER_DOMAIN_EXPECTED.items():
        if seen[name] != exp:
            fail(f"timer domain row {name}: got {seen[name]!r} expected {exp!r}")

    sample_rows = _parse_table_by_header(
        td_scope,
        (
            "typed_class",
            "meaning (exact)",
            "sample fields valid",
            "business_mutation",
            "durable_meta_mutation",
            "txn_provenance",
            "L1 action",
        ),
    )
    if len(sample_rows) < 4:
        fail(f"sample class table too short: {len(sample_rows)}")
    classes = {r[0] for r in sample_rows}
    for need in (
        "SAMPLE_TRUSTED_SAME_EPOCH",
        "SAMPLE_W1_REPAIR",
        "SAMPLE_AUTHORITY_DIVERGENCE",
        "SAMPLE_EPOCH_TRANSITION_REQUIRED",
        "SAMPLE_TEMP_UNCERTAIN",
        "SAMPLE_CLOCK_FAULT",
    ):
        if need not in classes:
            fail(f"missing sample class {need}")
    # exact 3-axis tuples on key sample rows
    sample_by = {r[0]: r for r in sample_rows}
    scf = sample_by.get("SAMPLE_CLOCK_FAULT")
    if scf is None or scf[3:6] != ("BUSINESS_ZERO", "F_C_FULL", "CLOCK_FENCE_COMMITTED"):
        fail(f"SAMPLE_CLOCK_FAULT axes must be BUSINESS_ZERO/F_C_FULL/CLOCK_FENCE_COMMITTED; got {scf!r}")
    stu = sample_by.get("SAMPLE_TEMP_UNCERTAIN")
    if stu is None or stu[3:6] != ("BUSINESS_ZERO", "META_ZERO", "PRECHECK_ZERO"):
        fail(f"SAMPLE_TEMP_UNCERTAIN axes must be BUSINESS_ZERO/META_ZERO/PRECHECK_ZERO; got {stu!r}")
    ro_rows = _parse_table_by_header(
        td_scope,
        (
            "RO / precheck outcome (exact)",
            "typed_class",
            "sample fields",
            "business_mutation",
            "durable_meta_mutation",
            "txn_provenance",
            "L1 action",
        ),
    )
    ro_classes = {r[1] for r in ro_rows}
    for need in (
        "SAMPLE_UNBOUND",
        "SAMPLE_BUSY",
        "SAMPLE_REENTRY",
        "SAMPLE_ALIAS",
        "SAMPLE_SHUTDOWN",
        "SAMPLE_STORAGE_IO",
        "SAMPLE_COMMIT_UNKNOWN",
        "SAMPLE_CORRUPT",
        "SAMPLE_META_UNPUBLISHED",
        "SAMPLE_TRUST_MIRROR_INVALID",
    ):
        if need not in ro_classes:
            fail(f"missing sample RO class {need}")
    ro_by = {r[1]: r for r in ro_rows}
    scu = ro_by.get("SAMPLE_COMMIT_UNKNOWN")
    if scu is None or scu[3:6] != ("BUSINESS_ZERO", "META_AMBIGUOUS", "AMBIGUOUS"):
        fail(
            "SAMPLE_COMMIT_UNKNOWN axes must be BUSINESS_ZERO/META_AMBIGUOUS/AMBIGUOUS "
            f"(CU must not collapse to META_ZERO); got {scu!r}"
        )
    smu = ro_by.get("SAMPLE_META_UNPUBLISHED")
    if smu is None or smu[3:6] != ("BUSINESS_ZERO", "META_ZERO", "PRECHECK_ZERO"):
        fail(f"SAMPLE_META_UNPUBLISHED axes must be BUSINESS_ZERO/META_ZERO/PRECHECK_ZERO; got {smu!r}")
    require_contains(td_scope, "META_ZERO | F_C_FULL | META_AMBIGUOUS", "§11.2.3 durable_meta closed")
    require_contains(td_scope, "PRECHECK_ZERO | CLOCK_FENCE_COMMITTED | AMBIGUOUS", "§11.2.3 txn_provenance closed")
    require_contains(td_scope, "BUSINESS_ZERO` only", "§11.2.3 business_mutation closed")
    require_absent(td_scope, "FULL以外はmeta 0", "§11.2.3")
    require_absent(td_scope, "otherwise `durable_meta_mutation = 0`", "§11.2.3")
    epoch_rows = _parse_table_by_header(
        td_scope,
        ("class", "exact condition", "L1 action", "R2 adopt?"),
    )
    epoch_classes = {r[0] for r in epoch_rows}
    for need in ("D EPOCH_SAME", "A EPOCH_W1_REPAIR", "B EPOCH_AUTHORITY_DIVERGENCE", "C EPOCH_NEW"):
        if _norm_cell(need) not in {_norm_cell(c) for c in epoch_classes}:
            # cells may be "D `EPOCH_SAME`" after norm
            bare = {_norm_cell(c) for c in epoch_classes}
            if not any(need.split()[0] in c or need.replace(" ", " ") in c for c in bare):
                if not any(x in " ".join(bare) for x in ("EPOCH_SAME", "EPOCH_W1_REPAIR", "EPOCH_AUTHORITY_DIVERGENCE", "EPOCH_NEW")):
                    fail(f"missing epoch class table entries; have={sorted(bare)}")
    require_contains(td_scope, "EPOCH_CLASS_FOUR_WAY_CLOSED", "§11.2.2")
    require_contains(td_scope, "EPOCH_NO_OR_BULK_RECOVER", "§11.2.2")
    require_contains(td_scope, "R2 adopt forbidden", "§11.2.2")
    require_contains(td_scope, "CLOCK_UNCERTAIN_SAME_EPOCH_FRESH_OK", "§11.2.2")
    require_contains(td_scope, "CLOCK_FAULT_REQUIRES_FRESH_EPOCH_ADOPT", "§11.2.2")
    require_contains(td_scope, "SAMPLE_NO_ROUTINE_STORAGE_RO", "§11.2.3")
    require_contains(td_scope, "SAMPLE_USES_RAM_TRUST_MIRROR", "§11.2.3")
    require_contains(td_scope, "BASELINE_SNAPSHOT_BOOT_ADOPT_ONLY", "§11.2.3")
    require_contains(td_scope, "MUST NOT** map BUSY / STORAGE_IO / COMMIT_UNKNOWN / CORRUPT / ALIAS / REENTRY / SHUTDOWN into `SAMPLE_UNBOUND`", "§11.2.3")
    require_contains(td_scope, "watermark_valid,            /* 0 | 1 copy-in */", "§11.2.3")
    require_contains(td_scope, "SAMPLE_DURABLE_RO_OUTCOMES_CLOSED", "§11.2.3")
    require_contains(td_scope, "SAMPLE_NO_COLLAPSE_TO_UNBOUND", "§11.2.3")
    require_contains(td_scope, "W1_WATERMARK_HELD_UNTIL_ADOPT_DONE", "§11.2.3")
    adopt_rows = _parse_table_by_header(
        td_scope,
        ("phase", "exact steps", "success", "failure"),
    )
    phases = [r[0] for r in adopt_rows]
    for need in (
        "ADOPT_STOP",
        "ADOPT_DRAIN",
        "ADOPT_ATOMIC",
        "ADOPT_PROVE",
        "ADOPT_INIT",
        "ADOPT_FRESH_ADMISSION",
    ):
        if need not in phases:
            fail(f"missing adopt phase {need}")

    # issue exhaustive: require all PCP statuses present in 15.3.2
    issue_scope = _section(
        doc,
        "#### 15.3.2 Exhaustive issue outcome / provenance matrix (closed)",
        "#### 15.3.3 Issued Permit cleanup / exported-module drain orchestration (closed)",
    )
    for st in PCP_STATUS_SET:
        name, code = st.rsplit(" (", 1)
        code = code.rstrip(")")
        pattern = rf"\|[^|]*\|\s*`{re.escape(name)}`\s*\({re.escape(code)}\)(?:\s|\+|\|)"
        if re.search(pattern, issue_scope) is None:
            fail(f"issue matrix missing status {st}")
    for st in R5_STATUS_SET:
        name, code = st.rsplit(" (", 1)
        code = code.rstrip(")")
        pattern = rf"\|[^|]*\|[^|]*`{re.escape(name)}`\s*\({re.escape(code)}\)(?:\s|/|\|)"
        if re.search(pattern, issue_scope) is None:
            fail(f"issue matrix missing R5 status {st}")
    require_contains(issue_scope, "stage = NINLIL_PCP_STAGE_ISSUE", "§15.3.2")
    require_contains(issue_scope, "PRECHECK_ZERO", "§15.3.2")
    require_contains(issue_scope, "RW_ABORT_ZERO", "§15.3.2")
    require_contains(issue_scope, "ISSUED_COMMITTED", "§15.3.2")
    require_contains(issue_scope, "AMBIGUOUS", "§15.3.2")
    require_contains(
        issue_scope,
        "2:{INVALID_STATE(27), CONTRACT(28; callback reconcile exact only)}",
        "§15.3.2 reason map status2 closed",
    )
    require_contains(issue_scope, "0:NONE, 1:NULL_ARG, 2:{INVALID_STATE(27)", "§15.3.2")
    require_contains(issue_scope, "23:NONE", "§15.3.2")
    require_contains(issue_scope, "stage=ISSUE/reason=EPOCH_MISMATCH/PRECHECK_ZERO", "§15.3.2")
    require_contains(issue_scope, "BUSINESS_ZERO` + `META_ZERO` + `PRECHECK_ZERO`/`RW_ABORT_ZERO`", "§15.3.2")
    require_contains(issue_scope, "CLOCK_FENCE_COMMITTED", "§15.3.2")
    require_contains(issue_scope, "F_C_FULL", "§15.3.2")
    require_contains(issue_scope, "CLOCK_PATH_DROP", "§15.3.2")
    # extract L1 classes from matrix column
    class_rows = _parse_table_by_header(issue_scope, ("source", "exact status / condition", "business_mutation", "clock_fence_mutation", "txn_provenance", "L1 result class", "action"))
    got = {r[5] for r in class_rows}
    # status2 CONTRACT before generic status2 terminal; exact tuples (cells are _norm_cell'd)
    if not any(
        r[2:6] == ("BUSINESS_ZERO", "META_ZERO", "PRECHECK_ZERO", "RECONCILE_REQUIRED")
        for r in class_rows
        if "CONTRACT" in r[1] and "NINLIL_PCP_INVALID_STATE" in r[1]
    ):
        fail("issue matrix missing status2 CONTRACT(28) → RECONCILE_REQUIRED exact axes")
    if not any(
        r[2] == "BUSINESS_ZERO"
        and r[3] == "META_ZERO"
        and "PRECHECK_ZERO" in r[4]
        and r[5] == "TERMINAL_UNISSUED"
        for r in class_rows
        if "NINLIL_PCP_INVALID_STATE" in r[1] and "INVALID_STATE (27)" in r[1]
    ):
        fail("issue matrix missing status2 INVALID_STATE(27) sole terminal form")
    # unknown/outside must be META_AMBIGUOUS (not META_ZERO assert)
    unk_rows = [r for r in class_rows if "outside 0..23" in r[1] or "status/reason/output/txn field mismatch" in r[1]]
    if len(unk_rows) < 2:
        fail(f"issue matrix missing unknown/mismatch rows; got {unk_rows!r}")
    for r in unk_rows:
        if r[3] != "META_AMBIGUOUS":
            fail(f"unknown/mismatch row must use META_AMBIGUOUS (not META_ZERO assert): {r!r}")
    # R5 bind unknown: no bare business AMBIGUOUS
    for r in class_rows:
        if "unknown bind_item" in r[1]:
            if re.search(r"(?<!BUSINESS_)AMBIGUOUS", r[2]) and "BUSINESS_AMBIGUOUS" not in r[2]:
                fail(f"R5 bind unknown must not use bare business AMBIGUOUS: {r!r}")
            if "BUSINESS_ZERO" not in r[2] and "BUSINESS_AMBIGUOUS" not in r[2]:
                fail(f"R5 bind unknown business must be BUSINESS_ZERO or BUSINESS_AMBIGUOUS: {r!r}")
    # success row ISSUED_FULL exact
    ok_rows = [
        r
        for r in class_rows
        if r[1].startswith("NINLIL_PCP_OK") and "exact valid snapshot" in r[1]
    ]
    if not ok_rows or ok_rows[0][2] != "ISSUED_FULL":
        fail(f"issue success row must be ISSUED_FULL; got {ok_rows!r}")
    # matrix may not list every class; require closed set text block contains each
    for c in L1_RESULT_CLASS_SET:
        require_contains(doc, c, "docs/30 L1 result class set")
    # forbid unknown class tokens in L1 result class column (index 5)
    for c in got:
        if c in ("—", "-", ""):
            continue
        # allow compound cells that include a known class
        if c not in L1_RESULT_CLASS_SET:
            if not any(x in c for x in L1_RESULT_CLASS_SET):
                fail(f"unknown L1 result class in matrix: {c!r}")

    require_contains(issue_scope, "discard entire `radio_volatile_work` all owners", "§15.3.2")
    require_contains(issue_scope, "RETRYABLE_UNISSUED", "§15.3.2")
    require_contains(issue_scope, "no Algorithm E", "§15.3.2")
    require_contains(issue_scope, "prevents Algorithm E/R5 registry divergence", "§15.3.2")
    require_absent(issue_scope, "known terminal catchall", "§15.3.2")

    drain_scope = _section(
        doc,
        "#### 15.3.3 Issued Permit cleanup / exported-module drain orchestration (closed)",
        "#### 15.3.4 R1 full transmit pipeline result matrix (closed)",
    )
    drain_rows = _parse_table_by_header(
        drain_scope,
        ("phase", "exact steps", "result"),
    )
    if tuple(drain_rows) != RECONCILE_PHASE_EXPECTED:
        fail(f"drain phase matrix mismatch: got={drain_rows!r}")
    reentry_rows = _parse_table_by_header(
        drain_scope,
        ("phase that returned COMMIT_UNKNOWN", "re-entry action", "fence target"),
    )
    if tuple(reentry_rows) != DRAIN_COMMIT_UNKNOWN_REENTRY_EXPECTED:
        fail(f"drain COMMIT_UNKNOWN re-entry matrix mismatch: got={reentry_rows!r}")
    require_contains(drain_scope, "MUST NOT** before zero", "§15.3.3")
    require_contains(drain_scope, "never ordinary `fence_after_revoke`", "§15.3.3")
    require_contains(drain_scope, "permit_bind_generation` and U5 ARW bit-exact unchanged", "§15.3.3")
    require_contains(drain_scope, "docs/25 §8.5", "§15.3.3")
    require_contains(drain_scope, "DRAIN_RECOVER_STORAGE", "§15.3.3")
    require_contains(drain_scope, "DRAIN_BASELINE_INIT", "§15.3.3")
    require_contains(drain_scope, "DRAIN_CLOCK", "§15.3.3")
    require_contains(drain_scope, "DRAIN_PROFILE_EPOCH", "§15.3.3")
    require_contains(drain_scope, "DRAIN_OWNER_CLEANUP", "§15.3.3")
    require_contains(drain_scope, "RECOVERY_SERIES_SINGLE_PIPELINE_CLOSED", "§15.3.3")
    require_contains(drain_scope, "ORDINARY_SAME_EPOCH_CANCEL_CLOCK_NOOP", "§15.3.3")
    require_contains(drain_scope, "CLOCK stage NOOP", "§15.3.3")
    require_contains(drain_scope, "ninlil_pcp_recover_storage", "§15.3.3")
    require_contains(drain_scope, "DRAIN_STORAGE_BEFORE_REVOKE_BEFORE_CLOCK", "§15.3.3")
    require_contains(drain_scope, "DRAIN_NO_COMBINED_RECOVER_WHILE_OUTSTANDING", "§15.3.3")
    require_contains(drain_scope, "DRAIN_COMMIT_UNKNOWN_REENTRY_CLOSED", "§15.3.3")
    require_contains(drain_scope, "REVOKE_ALL_CLOCKLESS_UNDER_CLOCK_FENCE", "§15.3.3")
    require_contains(drain_scope, "DRAIN_CLOCK_ORDER_RESAMPLE_BEFORE_RECOVER_CLOCK", "§15.3.3")
    require_contains(drain_scope, "DRAIN_RETRY_BUDGET_CLOSED", "§15.3.3")
    require_contains(drain_scope, "DRAIN_NO_SAME_TICK_SPIN", "§15.3.3")
    require_contains(drain_scope, "OPERATOR_RECOVERY_REQUIRED", "§15.3.3")
    require_contains(drain_scope, "max **8** phase-retry attempts", "§15.3.3")
    require_contains(drain_scope, "RESTART_RECOVER_STORAGE_AFTER_BIND", "§15.3.3")
    require_contains(drain_scope, "RESTART_EMPTY_OK_PUBLISH_PATH", "§15.3.3")
    require_contains(drain_scope, "EMPTY_OK", "§15.3.3")
    require_contains(drain_scope, "NO fence target", "§15.3.3")
    require_contains(drain_scope, "DRAIN_OK_PER_OWNER_DISPOSITION_CLOSED", "§15.3.3")
    require_contains(drain_scope, "DRAIN_ALL_QUARANTINED_TERMINAL_OR_STALE", "§15.3.3")
    require_contains(drain_scope, "DRAIN_FIFO_FULL_CLEAR", "§15.3.3")
    require_contains(drain_scope, "DRAIN_NO_PREDRAIN_SNAPSHOT_REUSE", "§15.3.3")
    require_contains(drain_scope, "##### 15.3.3.1 Post-`DRAIN_OK` disposition (closed)", "§15.3.3")
    disp_rows = _parse_table_by_header(
        drain_scope,
        ("class at DRAIN_OK", "disposition", "exact steps"),
    )
    dispositions = {r[1] for r in disp_rows}
    for need in ("TERMINAL or STALE_NO_RETRY", "CANCEL"):
        if need not in dispositions and not any(need.split()[0] in d for d in dispositions):
            if "TERMINAL" not in " ".join(dispositions) or "CANCEL" not in " ".join(dispositions):
                fail(f"missing post-DRAIN_OK disposition; have={sorted(dispositions)}")
    require_contains(drain_scope, "MUST NOT:** resume TX on a pre-drain Permit sequence or snapshot", "§15.3.3")
    require_contains(drain_scope, "Global issued FIFO is fully deleted", "§15.3.3")
    require_contains(drain_scope, "Unissued work by trigger (closed)", "§15.3.3")
    require_absent(drain_scope, "mandatory private R5 reconciliation seam is the only", "§15.3.3")
    # ban old disposition that reused issued work after global drain
    if "| **unrelated owner**, enclosing deadline live" in drain_scope and "RETRY_PREP" in drain_scope:
        fail("stale RETRY_PREP disposition for unrelated issued owners remains")
    # forbid stale G+1 design as positive claim (negation sentences may mention it)
    if re.search(r"(?i)new checked G\+1|reconstruct R5 at recovered G", drain_scope):
        fail("stale G+1 drain design remains normative")
    # forbid pre-revoke combined recover as positive drain step
    if re.search(
        r"DRAIN_RECOVER(?!_STORAGE)|"
        r"if durable ambiguity/storage fence path requires:\s*public R2 recover",
        drain_scope,
    ):
        fail("stale combined DRAIN_RECOVER remains normative")

    r1_scope = _section(
        doc,
        "#### 15.3.4 R1 full transmit pipeline result matrix (closed)",
        "#### 15.3.5 Authority-time clock handoff (closed)",
    )
    r1_rows = _parse_table_by_header(r1_scope, ("exact R1 result", "action"))
    if tuple(r1_rows) != R1_RESULT_EXPECTED:
        fail(f"R1 result matrix mismatch: got={r1_rows!r} expected={R1_RESULT_EXPECTED!r}")
    if len(r1_rows) != 8:
        fail(f"R1 result matrix must have exactly 8 rows; got {len(r1_rows)}")
    require_contains(r1_scope, "FIFO_OOO_NO_HINT_PARSE", "§15.3.4")
    require_contains(r1_scope, "TWO_CATALOG_PCP_VS_HAL", "§15.3.4")
    require_contains(r1_scope, "**usual retry forbidden**; no same-Permit +100ms path; enter §15.3.3 drain / FIFO reconcile", "§15.3.4")
    require_contains(r1_scope, "HAL reason **16**", "§15.3.4")
    require_contains(r1_scope, "legacy production only", "§15.3.4")
    require_contains(r1_scope, "45 CONSUME_BUSY", "§15.3.4")
    require_contains(r1_scope, "consume HAL16", "§15.3.4")
    require_contains(r1_scope, "TX_RESULT_RETRY_GATE", "§15.3.4")
    require_contains(r1_scope, "Two-stage decision", "§15.3.4")
    require_absent(r1_scope, "| `OUT_OF_ORDER` (any stage) |", "§15.3.4")
    require_absent(r1_scope, "typed retryable UNCONSUMED", "§15.3.4")
    require_absent(r1_scope, "if mutation-0 unissued proven ⇒ owner/group terminal without drain", "§15.3.4")
    require_absent(r1_scope, "typed reason **NOT_BEFORE** or **45 CONSUME_BUSY**", "§15.3.4")

    clock_scope = _section(
        doc,
        "#### 15.3.5 Authority-time clock handoff (closed)",
        "#### 15.3.6 `e2e_attempt_start_mono` (closed)",
    )
    clock_rows = _parse_table_in_scope(clock_scope, ("step", "exact rule"))
    if tuple(clock_rows) != CLOCK_HANDOFF_EXPECTED:
        fail(f"clock handoff matrix mismatch: got={clock_rows!r}")

    # ACK section phrase checks (state machine)
    ack_scope = _section(
        doc,
        "#### 15.3.7 Generated ACK intent state machine + burn limits (closed)",
        "#### 15.3.8 Terminal PARTIAL / resource cancel matrix + TERMINAL_PENDING (closed)",
    )
    require_contains(ack_scope, "full canonical FRAG_ACK plaintext", "§15.3.7")
    require_contains(ack_scope, "transfer_handle, frag_count, received_bitmap, status, reason", "§15.3.7")
    require_contains(ack_scope, "INTENT_PENDING", "§15.3.7")
    require_contains(ack_scope, "INTENT_RETRY", "§15.3.7")
    require_contains(ack_scope, "INTENT_SEAL", "§15.3.7")
    require_contains(ack_scope, "semantic_burn_ledger", "§15.3.7")
    require_contains(ack_scope, "ack_intent_retry_at = checked_add(now_mono, frag_retry_interval_ms)", "§15.3.7")
    require_contains(ack_scope, "frag_retry_interval_ms` = 500", "§15.3.7")
    require_contains(ack_scope, "MUST NOT** reset or delete the ledger", "§15.3.7")
    require_contains(ack_scope, "##### 15.3.7.2 Closed state × event transition table", "§15.3.7")
    # parse transition table
    tr_rows = _parse_table_by_header(
        ack_scope,
        ("from_state", "event", "to_state", "exact effects"),
    )
    if len(tr_rows) < 15:
        fail(f"ACK transition table too short: {len(tr_rows)}")
    events = {r[1] for r in tr_rows}
    for need in (
        "control reserve fail (capacity/owner)",
        "durable reverse E2E burn fail (definite counter fail)",
        "E2E Seal/encode **failure** (post-burn)",
        "covering LINK success (ACKED)",
        "LINK `TERMINAL_FAIL` / group deadline / hop prep exhaust",
        "**semantic supersede** (new full plaintext identity)",
    ):
        if need not in events and need.replace("`", "") not in {e.replace("`", "") for e in events}:
            # normalized cells strip **
            bare = {_norm_cell(e) for e in events}
            if _norm_cell(need) not in bare:
                fail(f"ACK transition missing event {need!r}; have={sorted(events)[:8]}")

    cancel_scope = _section(
        doc,
        "#### 15.3.8 Terminal PARTIAL / resource cancel matrix + TERMINAL_PENDING (closed)",
        "#### 15.3.9 Burn/candidate bound summary",
    )
    cancel_rows = _parse_table_by_header(
        cancel_scope,
        (
            "terminal event",
            "pending PARTIAL intent",
            "reserve / sealed ACK blob / LINK group / unissued candidate",
            "issued Permit",
            "consume+edge already done",
        ),
    )
    if tuple(cancel_rows) != CANCEL_MATRIX_EXPECTED:
        fail(f"terminal cancel matrix mismatch: got={cancel_rows!r}")
    require_contains(cancel_scope, "TERMINAL_PENDING", "§15.3.8")
    require_contains(cancel_scope, "Three-way cleanup", "§15.3.8")
    require_contains(cancel_scope, "TERMINAL_PENDING_RX_BEHAVIOR_CLOSED", "§15.3.8")
    require_contains(cancel_scope, "TERMINAL_PENDING RX behavior (closed) / TERMINAL_PENDING_RX_BEHAVIOR_CLOSED", "§15.3.8")
    require_contains(cancel_scope, "**do not** overwrite the pending terminal with ABORT TIMEOUT", "§15.3.8")
    tp_rx = _parse_table_by_header(
        cancel_scope,
        ("RX / timer event during TERMINAL_PENDING(T)", "exact behavior"),
    )
    if len(tp_rx) < 5:
        fail(f"TERMINAL_PENDING RX table too short: {len(tp_rx)}")
    tp_events = {r[0] for r in tp_rx}
    for need in (
        "new START / CONT for same T (incl. exact duplicate)",
        "new START for different transfer T′",
        "receiver/idle deadline fire for T",
        "process restart",
    ):
        if _norm_cell(need) not in {_norm_cell(e) for e in tp_events}:
            fail(f"missing TERMINAL_PENDING RX event {need!r}")

    # issue primitive section
    prim = _section(
        doc,
        "#### 15.3.1 R7 private R2 checked-issue primitive (Normative blocker)",
        "#### 15.3.2 Exhaustive issue outcome / provenance matrix (closed)",
    )



def check_unique_h2(doc: str) -> None:
    heads = re.findall(r"^#{2,5} .+$", doc, re.M)
    if len(heads) != len(set(heads)):
        fail(f"duplicate H2-H5 headings: {heads}")
    nums = re.findall(r"^## (\d+)\.", doc, re.M)
    if len(nums) != len(set(nums)):
        fail(f"duplicate section numbers: {nums}")


def oracle_airtime(payload: int) -> int:
    if not ORACLE.is_file():
        fail("missing airtime_r3_oracle.py")
    inp = {
        "sf": 7,
        "cr": 1,
        "header_implicit": 0,
        "crc_on": 1,
        "ldro": 0,
        "payload_len_bytes": payload,
        "preamble_len_symbols": 8,
        "bw_hz": 125000,
    }
    r = subprocess.run(
        [sys.executable, str(ORACLE), "eval"],
        input=json.dumps(inp),
        text=True,
        capture_output=True,
        check=False,
    )
    if r.returncode != 0:
        fail(f"oracle eval failed payload={payload}: {r.stderr}")
    out = json.loads(r.stdout)
    if out.get("status") != 0:
        fail(f"oracle status {out}")
    return int(out["airtime_us"])


def _header_status_line(text: str) -> str:
    for ln in text.splitlines()[:12]:
        if ln.startswith("状態:"):
            return ln
    return ""


def check_docs30(root: pathlib.Path) -> str:
    doc = read(root, DOC30)
    for m in MARKERS:
        require_contains(doc, m, "docs/30")
    for bad in FORBIDDEN:
        require_absent(doc, bad, "docs/30")
    check_unique_h2(doc)
    # Final Accepted status only (provisional Accepted 仮 must not be current header status)
    status_line = _header_status_line(doc)
    if "Accepted 仮" in status_line:
        fail("docs/30 current status must not be Accepted 仮 (provisional)")
    if "**Normative / Accepted / Stage 9**" not in status_line:
        fail("docs/30 status must be Normative / Accepted / Stage 9")
    if "independent root QA re-GO 2026-07-19 P0=P1=P2=0" not in status_line:
        fail("docs/30 status must cite independent root QA re-GO 2026-07-19 P0=P1=P2=0")
    require_contains(doc, "R6 docs freeze Accepted", "docs/30")
    require_contains(doc, "R7 full AEAD codec", "docs/30")
    require_contains(doc, "ESP N6 capacity", "docs/30")
    require_contains(doc, "RF·USB 実機 HIL", "docs/30")
    require_contains(doc, "production radio 未完", "docs/30")
    require_contains(doc, "正本 ADR: [ADR-0010](adr/0010-r6-secure-radio-wire.md)（**Accepted**）", "docs/30")
    require_contains(doc, "fixed-hash integration GO", "docs/30")
    require_contains(doc, "R7/production completeではない", "docs/30")

    # Exact layouts with field names
    check_layout_exact(
        parse_layout(doc, "LAYOUT_OUTER_BEGIN", "LAYOUT_OUTER_END"), OUTER_FIELDS, "outer"
    )
    check_layout_exact(
        parse_layout(doc, "LAYOUT_E2E_BEGIN", "LAYOUT_E2E_END"), E2E_FIELDS, "e2e"
    )
    check_layout_exact(
        parse_layout(doc, "LAYOUT_LINK_ACK_BEGIN", "LAYOUT_LINK_ACK_END"),
        LINK_ACK_FIELDS,
        "LINK_ACK",
    )
    fs = parse_layout(doc, "LAYOUT_FRAG_START_BEGIN", "LAYOUT_FRAG_START_END")
    check_layout_exact([r for r in fs if r[0] < 64], FRAG_START_FIELDS, "FRAG_START")
    check_layout_exact(
        parse_layout(doc, "LAYOUT_FRAG_CONT_BEGIN", "LAYOUT_FRAG_CONT_END"),
        FRAG_CONT_FIELDS,
        "FRAG_CONT",
    )
    fa = parse_layout(doc, "LAYOUT_FRAG_ACK_BEGIN", "LAYOUT_FRAG_ACK_END")
    check_layout_exact(fa, FRAG_ACK_FIELDS, "FRAG_ACK")
    if any(r[2] == 4 and "transfer_handle" in r[3] for r in fa):
        fail("FRAG_ACK handle size must be 8")

    # kind/type from actual catalog lines
    require_contains(
        doc,
        "kind: `1=DATA`, `2=LINK_ACK`; **other including 3+ reject**",
        "docs/30",
    )
    require_contains(
        doc,
        "type high nibble: `1=SINGLE`, `2=FRAG_START`, `3=FRAG_CONT`, `4=FRAG_ACK`; other reject (**type=5+ reject**). low nibble MUST be 0 (**TYPE_FLAGS_LOW_NIBBLE_ZERO**); nonzero low nibble → reject.",
        "docs/30",
    )
    require_contains(doc, "fixed integers: BE exact width only (**ENCODE_CANON_BE_ONLY**; LE forbidden)", "docs/30")

    # Direction / one-way / durable all lanes
    require_contains(doc, "**0** | initiator → responder (IR) | initiator | responder", "docs/30")
    require_contains(doc, "MUST NOT interpret a single key+counter namespace as shared by both TX and RX", "docs/30")
    require_contains(
        doc,
        "§9 Durable TX and §10 Durable RX are **Normative for all** of: hop DATA lane, hop ACK lane, E2E lane",
        "docs/30",
    )
    require_contains(
        doc,
        "a numeric id that was ever successfully installed MUST NOT be reused for a different binding/key_generation",
        "docs/30",
    )
    require_contains(
        doc,
        "install that reuses same key/IV (or same key_generation + digest) while resetting durable counters/replay to initial is **forbidden** → fence or reject.",
        "docs/30",
    )

    # Relay MUST structural
    require_contains(doc, "the relay **MUST** structurally validate the **visible E2E header**", "docs/30")
    require_contains(doc, "before** forward-queue admit, radio forward TX, or LINK_ACK generation", "docs/30")
    require_contains(doc, "e2e_context_id` ∈ 1..UINT32_MAX-1", "docs/30")
    require_contains(doc, "e2e_counter` ∈ 1..UINT64_MAX-1", "docs/30")
    require_contains(doc, "MUST NOT** perform E2E context lookup, E2E replay precheck, E2E Open, or E2E body processing", "docs/30")

    # Retry layer split
    require_contains(doc, "one bit-identical E2E sealed blob** and its **same** `e2e_counter` for the whole group", "docs/30")
    require_contains(doc, "fresh hop DATA counter only**", "docs/30")
    require_contains(doc, "fresh `e2e_counter`** and **fresh E2E Seal/blob**", "docs/30")
    require_contains(doc, "reusing a prior E2E blob/counter for end-to-end fragment retry is forbidden", "docs/30")
    require_contains(doc, "Link retries MUST **not** change the E2E blob", "docs/30")

    # Exact START retry
    require_contains(doc, "**A. Exact same-fingerprint retry**", "docs/30")
    require_contains(doc, "second transfer/reassembly allocation/reservation **0**; **no** reassembly state / bitmap / payload / TTL mutation", "docs/30")
    require_contains(doc, "reassembly / re-handoff / upper-queue / tombstone field mutation **0**; **no** TTL extension", "docs/30")
    require_contains(doc, "Exact-retry MUST NOT be classified as CONFLICT", "docs/30")

    # Queues / resources
    require_contains(doc, "endpoint E2E ingress queue** (auth hop DATA / sealed E2E blob awaiting E2E processing)", "docs/30")
    require_contains(doc, "upper-transport queue** (validated SINGLE or completed reassembly app payload)", "docs/30")
    require_contains(doc, "copy-own E2E sealed blob ≤220 B each; aggregate ≤14080 B**", "docs/30")
    require_contains(doc, "TOMBSTONE_CANONICAL_72B** = e2e_context_id4 + transfer_id16 + handle8 + frag_count2 + status1 + reason1 + fingerprint32 + expiry_u64_8 (**72 B exact**", "docs/30")
    require_contains(doc, "independent of forward/ingress queues", "docs/30")
    require_absent(doc, "canonical 88 B/entry", "docs/30")

    # Timers
    require_contains(doc, "single R2 authority clock domain only (§11.2.2)", "docs/30")
    require_contains(doc, "Restart does not resume volatile", "docs/30")
    require_contains(doc, "Crash-atomic exactly-once is **not** claimed", "docs/30")

    # Storage / HA / LINK_ACK / FRAG retained
    require_contains(doc, "`NINLIL_STORAGE_OK` on commit | **FULL_OK**", "docs/30")
    require_contains(doc, "Ambiguous statuses MUST NOT be treated as success", "docs/30")
    require_contains(doc, "COMMIT_UNKNOWN_NAMESPACE_RECOVERY", "docs/30")
    require_contains(doc, "`key_generation == UINT64_MAX` is the **namespace terminal** high-water value", "docs/30")
    require_contains(doc, "bitmap |= (UINT64_C(1) << delta)", "docs/30")
    require_contains(doc, "grow = min(B, room)", "docs/30")
    require_contains(doc, "Atomic shared allocator enabling multiple sealers is not permitted", "docs/30")
    require_contains(doc, "Owner change / failover:** same-context resume is **forbidden**", "docs/30")
    require_contains(doc, "only if** that DATA outer has **ACK_REQUESTED=1**", "docs/30")
    require_contains(doc, "1 initial + max 3 retries = 4 hop air attempts", "docs/30")
    require_contains(doc, "if i >= ack_base:", "docs/30")
    require_contains(doc, "counter_i = ack_base - i", "docs/30")
    require_contains(doc, "FRAG_ACK may be sealed/TX only by the **fragment receiver**", "docs/30")
    require_contains(doc, "MUST **not** replace, overwrite, or rewrite the existing active state or COMPLETE/ABORT tombstone", "docs/30")
    require_contains(doc, "local abort + upper structured; FRAG_ACK TX 0", "docs/30")
    require_contains(doc, "Only then may emit FRAG_ACK COMPLETE.", "docs/30")
    require_contains(doc, "`link_retry_group_ttl_ms` | 15000", "docs/30")
    require_contains(doc, "upper-transport queue** item (**UPPER_TRANSPORT_QUEUE**", "docs/30")
    require_contains(doc, "frame_digest = SHA-256(B)", "docs/30")
    require_contains(doc, "requires a **new `wire_profile_id`**", "docs/30")
    require_contains(doc, "not `entries×sizeof(entry)`", "docs/30")

    # Concat / sizes / HKDF
    require_contains(doc, "outer_frame = outer_AAD_19 || hop_CT || hop_TAG_16", "docs/30")
    require_contains(doc, "e2e_sealed_blob = e2e_AAD_14 || e2e_CT || e2e_TAG_16", "docs/30")
    require_contains(doc, "OUTER_L_SINGLE(N) = 65 + N", "docs/30")
    require_contains(doc, "1 ≤ N ≤ 190   /* N=0 reject */", "docs/30")
    for n, L in ((16, 81), (24, 89), (32, 97)):
        if not re.search(rf"\|\s*{n}\s*\|[^|\n]*\**{L}\**", doc):
            fail(f"size table N={n} L={L}")
    require_contains(doc, "salt = hop_context_binding_digest", "docs/30")
    for lab in HKDF_LABELS:
        require_contains(doc, lab, "docs/30")

    e2e_bind = doc.find("e2e_binding_input = encode_canon(")
    if e2e_bind < 0:
        fail("missing e2e_binding_input")
    enc = doc[e2e_bind : doc.find("e2e_context_binding_digest", e2e_bind)]
    if re.search(r"^\s*opaque attachment_id", enc, re.M):
        fail("e2e_binding_input must not include attachment_id field")
    require_contains(doc, "opaque e2e_security_id (max 32, length 1..32)", "docs/30")

    if oracle_airtime(89) != 153856:
        fail("oracle 89")
    if oracle_airtime(51) != 102656:
        fail("oracle 51")
    require_contains(doc, "153856", "docs/30")
    require_contains(doc, "0.923136", "docs/30")
    require_contains(doc, "channel_airtime_fraction_1ch_data", "docs/30")

    require_contains(doc, "| DATA / SINGLE | **66..255**", "docs/30")
    require_contains(doc, "| DATA / FRAG_START | **130..255**", "docs/30")
    require_contains(doc, "require record.egress_route_handle == 0 AND record.egress_route_generation == 0", "docs/30")
    check_resource_table(doc)
    check_timer_table(doc)
    check_closed_transition_tables(doc)
    require_contains(doc, "FRAG_MAX_OUTER_ATTEMPTS_PER_FRAGMENT** | **16**", "docs/30")
    require_contains(doc, "**Valid LINK_ACK** = hop outer admission only", "docs/30")
    require_contains(doc, "retry_not_before = max(frag_ack_deadline, checked_add(group_completion_mono, frag_retry_interval_ms), checked_add(e2e_attempt_start_mono, frag_retry_interval_ms))", "docs/30")
    require_contains(doc, "group_start_mono", "docs/30")
    require_contains(doc, "Denied/unconsumed is **not** a sent/air attempt", "docs/30")
    require_contains(doc, "set **`transfer_start_mono = sample.now_ms`** once", "docs/30")
    require_contains(doc, "sender_absolute_deadline = checked_add(transfer_start_mono, frag_sender_transfer_ttl_ms)", "docs/30")
    require_contains(doc, "immutable** across every fragment and every E2E/LINK retry", "docs/30")
    require_contains(doc, "Do **not** recompute or reset them on retries", "docs/30")
    require_contains(doc, "checked fail-closed** u64 addition (**not saturating**)", "docs/30")
    require_exact_count(
        doc,
        "retry_not_before = max(frag_ack_deadline, checked_add(group_completion_mono, frag_retry_interval_ms), checked_add(e2e_attempt_start_mono, frag_retry_interval_ms))",
        3,
        "docs/30 sender, §15.1, and §15.3.6 retry formula",
    )
    require_contains(doc, "frag_sender_transfer_ttl_ms", "docs/30")
    require_contains(doc, "frag_idle_timeout_ms)` with **20000**", "docs/30")
    require_contains(doc, "tombstones and START reservations are volatile", "docs/30")
    require_contains(doc, "TOMBSTONE_VOLATILE_ON_RESTART", "docs/30")
    require_contains(doc, "No volatile state resumes across unknown clock/restart", "docs/30")
    # Stage 6 closed rules
    storage_scope = _section(
        doc,
        "### 9.3 COMMIT_UNKNOWN recovery (namespace-wide multi-key; Foundation Storage ABI closed)",
        "### 9.4 Storage result actions (TX)",
    )
    require_contains(storage_scope, "COMMIT_UNKNOWN_NAMESPACE_RECOVERY", "docs/30 §9.3")

    link_scope = _section(doc, "#### 11.2 LINK retry group (DATA sender)", "#### 11.3 LINK_ACK RX validation (DATA sender / pending-owner)")
    require_contains(link_scope, "A DATA LINK group copy-inherits the exact owner deadline", "docs/30 §11.2")
    require_contains(link_scope, "relay never uses source sender deadline", "docs/30 §11.2")
    require_contains(link_scope, "single_sender_item_deadline = checked_add(single_admit_mono, single_sender_item_ttl_ms)", "docs/30 §11.2")

    start_scope = _section(doc, "### 12.1 FRAG_START PT", "### 12.2 FRAG_CONT PT (single definition)")
    require_contains(start_scope, "fresh forward E2E counter was already durably admitted", "docs/30 §12.1")
    require_contains(start_scope, "distinct fresh counter in the paired reverse E2E lane", "docs/30 §12.1")

    frag_scope = _section(doc, "### 12.2 FRAG_CONT PT (single definition)", "### 12.2b CONT conflict")
    require_contains(frag_scope, "**Fragment sender state machine (exact):**", "docs/30 §12.2")
    require_contains(frag_scope, "`TERMINAL_FAIL`", "docs/30 §12.2")
    require_contains(frag_scope, "create no replacement hop candidate in that group", "docs/30 §12.2")
    require_contains(frag_scope, "including before LINK_ACK", "docs/30 §12.2")
    require_contains(frag_scope, "`SUPERSEDED_BY_FRAG_ACK`", "docs/30 §12.2")
    require_contains(frag_scope, "§15.3.3", "docs/30 §12.2")
    require_contains(frag_scope, "frag_ack_deadline = checked_add(group_completion_mono, frag_ack_wait_ms)", "docs/30 §12.2")
    require_contains(frag_scope, "fresh forward E2E counter has already been durably admitted", "docs/30 §12.2")
    require_contains(frag_scope, "distinct fresh reverse E2E counter", "docs/30 §12.2")
    require_contains(frag_scope, "tombstone_expiry = checked_add(terminal_commit_mono, tombstone_ttl_ms)", "docs/30 §12.2")
    require_contains(frag_scope, "Every 4 / optional-only PARTIAL generation is **not** sufficient", "docs/30 §12.2")
    require_contains(frag_scope, "checked_add(now_mono, frag_partial_ack_idle_ms)", "docs/30 §12.2")

    ack_scope = _section(doc, "### 12.3 FRAG_ACK", "### 12.4 ACK layering")
    require_contains(ack_scope, "**FRAG_ACK_RX_VALIDATION_CLOSED** — after reverse E2E structural/auth/durable admission", "docs/30 §12.3")
    require_contains(ack_scope, "after **each newly accepted CONT whose resulting bitmap is incomplete**", "docs/30 §12.3")
    require_contains(ack_scope, "makes the bitmap full MUST cancel PARTIAL", "docs/30 §12.3")
    require_contains(ack_scope, "“Every 4 fragments” or idle-only generation is forbidden", "docs/30 §12.3")
    require_absent(ack_scope, "every 4 newly accepted fragments", "docs/30 §12.3")
    require_contains(ack_scope, "checked-compute `tombstone_expiry = checked_add(terminal_commit_mono, tombstone_ttl_ms)`", "docs/30 §12.3")

    permit_intro_scope = _section(doc, "## 15. Permit pipeline and Seal/counter lifecycle", "### 15.1 Fresh E2E attempt (fragment or SINGLE)")
    require_exact_count(permit_intro_scope, "Seal after Permit success is forbidden", 1, "docs/30 §15 intro")
    require_absent(doc, "Seal after Permit success is required", "docs/30")
    permit_scope = _section(doc, "### 15.3 Prepared candidate rules", "### 15.4 Order summary (Normative)")
    require_contains(doc, "burn e2e_counter → E2E Seal", "docs/30")
    require_contains(doc, "burn hop_counter → outer Seal → digest/airtime", "docs/30")
    require_contains(permit_scope, "max **8 calls per candidate**", "docs/30 §15.3")
    require_contains(permit_scope, "positive fixed backoff, never same-tick spin", "docs/30 §15.3")
    require_contains(permit_scope, "only FIFO head may enter `transmit_with_permit`", "docs/30 §15.3")
    require_contains(permit_scope, "ascending `permit_sequence`", "docs/30 §15.3")
    require_contains(permit_scope, "Callers never invoke `consume` directly", "docs/30 §15.3")
    require_contains(permit_scope, "R2 durable ambiguity maps to terminal `CONSUME_FENCED`", "docs/30 §15.3")
    require_contains(permit_scope, "no unbounded sequence of replacement candidates/counter burns", "docs/30 §15.3")
    # Stage 9 closed tables / contracts
    require_contains(doc, "R7_PRIVATE_R2_CHECKED_ISSUE_PRIMITIVE", "docs/30")
    require_contains(doc, "CLOCK_PATH_DROP", "docs/30 §15.3.2")
    require_contains(doc, "discard entire `radio_volatile_work` all owners", "docs/30 §15.3.2")
    require_contains(doc, "OK_ISSUED", "docs/30 §15.3.2")
    require_contains(doc, "L1_RESULT_CLASS_SET_CLOSED", "docs/30")
    require_contains(doc, "Closed L1 result class set** (exact; gate set-equality; also §15.4 order + §18 + ADR-0010 must list the same set, no extras)", "docs/30")

    require_contains(doc, "RECOVERY_SERIES_SINGLE_PIPELINE_CLOSED / ORDINARY_SAME_EPOCH_CANCEL_CLOCK_NOOP (P1(37); sole L1 series)", "docs/30")
    require_contains(doc, "ordinary same-epoch cancel / owner deadline drain with class D and no CLOCK fence ⇒ CLOCK stage NOOP", "docs/30")
    require_contains(doc, "L1_RADIO_COORDINATOR_CLOSED", "docs/30")
    require_contains(doc, "W1_CODEC_NO_R2_R5_COMPILE_DEP", "docs/30")
    require_contains(doc, "W1_IMMUTABLE_CANDIDATE_TYPED_EVENT_ONLY", "docs/30")
    require_contains(doc, "ADOPT_CU_PROPOSED_VS_OLD_BASELINE_CLOSED", "docs/30")


    require_contains(doc, "PROFILE_CLOCK_EPOCH_SIDECAR_SUPERSEDES_WALL_CLOCK", "docs/30")

    require_contains(doc, "RECOVERY_SERIES_SINGLE_PIPELINE_CLOSED", "docs/30")
    require_contains(doc, "Closed L1 result class set", "docs/30")

    require_contains(doc, "RETRYABLE_UNISSUED", "docs/30 §15.3.2")
    require_contains(doc, "RECONCILE_REQUIRED", "docs/30 §15.3.2")
    require_contains(doc, "L1_EXPORTED_PRIVATE_MODULE_DRAIN_ORCHESTRATION_CLOSED", "docs/30")
    require_contains(doc, "DRAIN_STORAGE_BEFORE_REVOKE_BEFORE_CLOCK", "docs/30")
    require_contains(doc, "DRAIN_NO_COMBINED_RECOVER_WHILE_OUTSTANDING", "docs/30")
    require_contains(doc, "DRAIN_COMMIT_UNKNOWN_REENTRY_CLOSED", "docs/30")
    require_contains(doc, "REVOKE_ALL_CLOCKLESS_UNDER_CLOCK_FENCE", "docs/30")
    require_contains(doc, "RECOVERY_SERIES_SINGLE_PIPELINE_CLOSED", "docs/30 §15.3.3")
    require_contains(doc, "DRAIN_STOP", "docs/30 §15.3.3")
    require_contains(doc, "DRAIN_RECOVER_STORAGE", "docs/30 §15.3.3")
    require_contains(doc, "DRAIN_CLOCK", "docs/30 §15.3.3")
    require_contains(doc, "ninlil_pcp_recover_storage", "docs/30 §15.3.3")
    require_contains(doc, "MUST NOT** before zero", "docs/30 §15.3.3")
    require_contains(doc, "never ordinary `fence_after_revoke`", "docs/30 §15.3.3")
    require_contains(doc, "NO fence target", "docs/30 §15.3.3")
    require_contains(doc, "permit_bind_generation` and U5 ARW bit-exact unchanged", "docs/30 §15.3.3")
    require_contains(doc, "docs/25 §8.5", "docs/30 §15.3.3")
    require_contains(doc, "ARW alone never restores full body", "docs/30 §15.3.3")
    require_contains(doc, "L0–L4 RESTORE/DUP", "docs/30 §15.3.3")
    require_contains(doc, "L5–L9 APPLY", "docs/30 §15.3.3")
    require_contains(doc, "`advance_expired_heads` alone is **insufficient**", "docs/30 §15.3.3")
    require_contains(doc, "MUST NOT** call combined `ninlil_pcp_recover` while outstanding may be non-zero", "docs/30 §15.3.3")
    require_contains(doc, "local discard forbidden", "docs/30 §15.3")
    require_contains(doc, "no-drain terminal", "docs/30 §15.3.4")
    require_contains(doc, "w1_last_accepted_now_ms", "docs/30")
    require_contains(doc, "same-epoch", "docs/30")
    require_contains(doc, "CLOCK_FAULT", "docs/30")
    require_contains(doc, "##### 11.2.2 L1 authority-clock domain + watermark (closed)", "docs/30")
    require_contains(doc, "CELL_TIMER_DOMAIN_TABLE_CLOSED", "docs/30")
    require_contains(doc, "TERMINAL_PENDING", "docs/30")
    require_contains(doc, "full canonical FRAG_ACK plaintext", "docs/30 §15.3.7")
    require_contains(doc, "INTENT_RETRY", "docs/30 §15.3.7")
    require_contains(doc, "Three-way cleanup", "docs/30 §15.3.8")

    require_contains(doc, "SEMANTIC: ACK_SEAL_FAIL_CONSUMES_THEN_RETRY_OR_DROP", "docs/30")
    require_contains(doc, "SEMANTIC: ACK_RETRY_AT_USES_FRAG_RETRY_INTERVAL_MS_ONLY", "docs/30")
    require_contains(doc, "SEMANTIC: ACK_LEDGER_NOT_RESET_ON_ACKED_OR_DUPLICATE", "docs/30")
    require_contains(doc, "semantic_burn_ledger", "docs/30")
    require_contains(doc, "ack_intent_retry_at = checked_add(now_mono, frag_retry_interval_ms)", "docs/30")


    require_contains(doc, "RESTART_RECOVER_STORAGE_AFTER_BIND", "docs/30")
    require_contains(doc, "baseline snapshot", "docs/30")
    require_contains(doc, "non-regression vs watermark and ram_trust now", "docs/30")
    require_contains(doc, "Durable floor compare** uses ram_trust now", "docs/30")
    require_contains(doc, "R5_REQUIRED_CHECKED_ISSUE_ADAPTER", "docs/30")
    require_contains(doc, "ninlil_r5_private_issue_checked_with_owner_epoch", "docs/30")
    require_contains(doc, "AUTHORITY_DIVERGENCE", "docs/30")
    require_contains(doc, "SEMANTIC: PROFILE_MISMATCH_IS_AUTHORITY_DIVERGENCE", "docs/30")
    require_contains(doc, "SEMANTIC: PERMIT_GEN_BIND_IS_RECONCILE_REQUIRED", "docs/30")
    require_contains(doc, "SAMPLE_USES_RAM_TRUST_MIRROR", "docs/30")

    require_contains(doc, "bind_item `PERMIT_GEN`", "docs/30")
    require_contains(doc, "BIND_MISMATCH classification (closed)", "docs/30")
    require_absent(doc, "optional private R5 adapter", "docs/30")

    require_contains(doc, "CLOCK_UNCERTAIN/TEMP:** discard entire `radio_volatile_work`", "docs/30")
    require_contains(doc, "SEMANTIC: EPOCH_ADOPT_NO_INFINITE_DROP_LOOP", "docs/30")
    require_contains(doc, "SEMANTIC: SAMPLE_PRIMITIVE_SOLE_OWNER", "docs/30")
    require_contains(doc, "SEMANTIC: ISSUE_ORDER_SAMPLE_PROFILE_EPOCH_RW", "docs/30")
    require_contains(doc, "W1 codec and other callers **MUST NOT** sample the R2 compliance clock", "docs/30")
    require_contains(doc, "same-S not_before/expiry", "docs/30")
    require_contains(doc, "ninlil_r2_private_adopt_authority_epoch", "docs/30")
    require_contains(doc, "ADOPT_DRAIN", "docs/30")


    require_contains(doc, "ninlil_r2_private_sample_authority_clock", "docs/30")
    require_contains(doc, "ninlil_r2_private_load_authority_clock_baseline", "docs/30")
    require_contains(doc, "result_catalog = R2_PCP,   /* baseline is R2 catalog only */", "docs/30")
    require_contains(doc, "result_catalog = R2_PCP,   /* adopt/prove is R2 catalog only */", "docs/30")
    require_contains(doc, "**Closed private issue result:**", "docs/30")
    require_contains(doc, "R1 HAL values are forbidden in this object", "docs/30")
    require_contains(doc, "SAMPLE_PRIMITIVE_CLOSED_REQUEST_RESULT", "docs/30")
    require_contains(doc, "request = {", "docs/30")
    require_contains(doc, "expected_epoch_id", "docs/30")
    require_contains(doc, "watermark_valid", "docs/30")
    require_contains(doc, "There is no exported private-module R2/R5 getter for this baseline", "docs/30")
    require_contains(doc, "R5_ISSUE_ADAPTER_MANDATORY_STATIC_REGISTRY", "docs/30")
    require_absent(doc, "ADOPT_CLOCK_FENCE", "docs/30")

    require_contains(doc, "SAMPLE_EPOCH_TRANSITION_REQUIRED", "docs/30")
    require_contains(doc, "ADOPT_ATOMIC", "docs/30")
    require_contains(doc, "PRIVATE_ADOPT_ATOMIC_NO_ARM_FENCE", "docs/30")

    require_contains(doc, "ADOPT_COMMITTED", "docs/30")
    require_contains(doc, "sample_valid", "docs/30")
    require_contains(doc, "ADOPT_SAMPLE_COPYOUT_FULL_OK_ONLY", "docs/30")
    require_contains(doc, "ADOPT_COMMITTED_FROM_DURABLE_PROOF", "docs/30")
    require_contains(doc, "PUBLIC_RECOVER_CLOCK_NO_SAMPLE_VISIBILITY", "docs/30")
    require_contains(doc, "sample_source", "docs/30")
    require_contains(doc, "ACCEPTED_SAMPLE", "docs/30")
    require_contains(doc, "DURABLE_META_PROOF", "docs/30")
    require_contains(doc, "exported `ninlil_pcp_recover_clock` does not return a sample", "docs/30")
    require_absent(doc, "use internal `S_ad` from public recover_clock", "docs/30")

    require_contains(doc, "SEMANTIC: PRIVATE_ADOPT_API_REQUIRED", "docs/30")
    require_contains(doc, "SEMANTIC: SAMPLE_NO_IMPLICIT_W1_LOAD", "docs/30")
    require_contains(doc, "SEMANTIC: WATERMARK_INIT_FROM_BASELINE_LOAD", "docs/30")

    require_contains(doc, "ISSUE_PROFILE_SAME_SAMPLE_TOCTOU_CLOSED", "docs/30")
    require_contains(doc, "START_RESERVE_FAIL_ACK0_ONLY", "docs/30")
    require_contains(doc, "START reject; ACK 0 only (no unowned ABORT RESOURCE)", "docs/30")
    require_contains(doc, "SAMPLE_DURABLE_RO_OUTCOMES_CLOSED", "docs/30")
    require_contains(doc, "SAMPLE_NO_COLLAPSE_TO_UNBOUND", "docs/30")
    require_contains(doc, "TERMINAL_PENDING_RX_BEHAVIOR_CLOSED", "docs/30")
    require_contains(doc, "DRAIN_OK_PER_OWNER_DISPOSITION_CLOSED", "docs/30")
    require_contains(doc, "BIND_COMPARISON_LOCUS_CLOSED", "docs/30")
    require_contains(doc, "CANDIDATE_VS_R5_EXPECTED", "docs/30")
    require_contains(doc, "R5_EXPECTED_VS_R2_LIVE", "docs/30")
    require_contains(doc, "REGISTRY_POSTCOMMIT", "docs/30")
    require_contains(doc, "recompose **this** candidate only; not drain", "docs/30")
    require_contains(doc, "| `CANDIDATE_VS_R5_EXPECTED` | static candidate vs R5 expected plan (pre-commit) | `TERMINAL_UNISSUED` / recompose candidate |", "docs/30")
    require_contains(doc, "EPOCH_CLASS_FOUR_WAY_CLOSED", "docs/30")
    require_contains(doc, "After later **trusted same-epoch** class-D **and fences clear**, only **fresh** burn/stamp/seal/issue", "docs/30")
    require_contains(doc, "L1 compares platform sample **S** against **R2 ram_trust durable mirror**", "docs/30")
    require_contains(doc, "1. **`ninlil_pcp_recover_storage` only** when STORAGE fence / durable ambiguity requires it", "docs/30")

    require_contains(doc, "MUST NOT** treat A∨B∨C as one bulk", "docs/30")
    require_contains(doc, "same-epoch resume and same-epoch fresh admission both forbidden", "docs/30")
    require_contains(doc, "MUST NOT** open a storage RO txn each call", "docs/30")
    require_contains(doc, "same-tick / tight spin | **forbidden**", "docs/30")
    require_contains(doc, "R2 bind storage → **`recover_storage` mandatory**", "docs/30")
    require_contains(doc, "MUST NOT** run `recover_clock` before outstanding 0 + re-sample/classify", "docs/30")
    require_contains(doc, "old L1 watermark held until adopt completes", "docs/30")
    require_contains(doc, "MUST NOT:** leave any QUARANTINED issued without TERMINAL/STALE disposition", "docs/30")

    require_contains(doc, "TEMP_UNCERTAIN_DISCARD_ALL_VOLATILE", "docs/30")
    require_contains(doc, "later same-epoch class-D **fresh only**", "docs/30")
    require_contains(doc, "CONTEXT_FENCE_STAMP_EPOCH_RECLAIM_CLOSED", "docs/30")

    require_contains(doc, "DURABLE_LANE_RECORD_LAYOUTS_CLOSED", "docs/30")
    require_contains(doc, "DURABLE_NAMESPACE_ALLOCATOR_CLOSED", "docs/30")
    require_contains(doc, "DURABLE_RETIRED_CONTEXT_TOMBSTONE_CLOSED", "docs/30")
    require_contains(doc, "CONTEXT_ID_MONOTONIC_NEXT_FREE", "docs/30")
    require_contains(doc, "CONTEXT_ALLOCATOR_CELL64_BOUNDED", "docs/30")
    require_contains(doc, "RETIRED_GC_ONLY_AFTER_MEMBERSHIP_NAMESPACE", "docs/30")
    require_contains(doc, "FENCE_RECLAIM_VOLATILE_VS_DURABLE_SPLIT", "docs/30")
    require_contains(doc, "magic = 0x4E365458", "docs/30")
    require_contains(doc, "magic = 0x4E365258", "docs/30")
    require_contains(doc, "magic = 0x4E364857", "docs/30")
    require_contains(doc, "Canonical lane key (48 B BE)", "docs/30")
    require_contains(doc, "N6AL value (56 B BE; schema 2", "docs/30")
    require_contains(doc, "N6RT key (28 B BE) and value (48 B BE; schema 2)", "docs/30")
    require_contains(doc, "next_free_context_id", "docs/30")
    require_contains(doc, "active_count + 1 ≤ max_active", "docs/30")
    require_contains(doc, "max_retired_tombstones", "docs/30")

    require_contains(doc, "Exact size **68**", "docs/30")
    require_contains(doc, "Exact size **56**", "docs/30")
    require_contains(doc, "Exact size **48**", "docs/30")
    require_contains(doc, "Exact size **64**", "docs/30")
    require_contains(doc, "Exact size **28**", "docs/30")
    require_contains(doc, "value_crc32c", "docs/30")
    require_contains(doc, "CONTEXT_FENCE_DURABLE_TABLE_CLOSED", "docs/30")
    require_contains(doc, "QUARANTINED_ISSUED_TERMINAL_OR_STALE_ONLY", "docs/30")
    require_contains(doc, "N6_BOUNDED_GROWTH_NO_PHANTOM_ACTIVE", "docs/30")
    require_contains(doc, "L1_SOLE_OWNER_AUTHORITY_CLOCK_WATERMARK", "docs/30")
    require_contains(doc, "N6RT_FULL_NS_IDENTITY_NO_U32_TAG", "docs/30")
    require_contains(doc, "N6_MULTI_KEY_FULL_TXN_CLOSED", "docs/30")
    require_contains(doc, "N6_VALUE_CRC32C_CANONICAL", "docs/30")
    require_contains(doc, "CLOCK_FAULT_DURABLE_LATCH_RESTART_SURVIVES", "docs/30")
    require_contains(doc, "CLASS_D_REQUIRES_BLOCKING_FENCE_CLEAR", "docs/30")
    require_contains(doc, "CLASS_B_BOUNDED_THEN_OPERATOR_RECOVERY", "docs/30")
    require_contains(doc, "L1_W1_BIDIRECTIONAL_EVENT_SET_CLOSED", "docs/30")
    require_contains(doc, "expected_l1_epoch_id", "docs/30")

    require_contains(doc, "R5_ADAPTER_SINGLE_IN_API_OWNER_ORDER", "docs/30")
    require_contains(doc, "PROFILE_READY_GATE_BEFORE_COUNTER_BURN", "docs/30")
    require_contains(doc, "PROFILE_CLOCK_EPOCH_UNIFIED_SOURCE", "docs/30")
    require_contains(doc, "FRAG_ACK_INTENT_BURN_STORAGE_MATRIX_CLOSED", "docs/30")
    require_contains(doc, "TX_HOLDS_PEER_RECEIVER_ALLOCATED_CONTEXT_ID", "docs/30")
    require_contains(doc, "retained_uncompacted_count", "docs/30")
    require_contains(doc, "R5 static preflight (no sample)", "docs/30")

    # --- A–I re-audit structural requires ---
    require_contains(doc, "L1_R1_SOLE_PIPELINE_NO_W1_PERMIT", "docs/30")
    require_contains(doc, "STAMP_FIELDS", "docs/30")
    require_absent(doc, "| L1→W1 | `ISSUE_GRANTED`", "docs/30")
    require_absent(doc, "| L1→W1 | `TRANSMIT_EDGE`", "docs/30")
    require_contains(doc, "N6_EXACT_LANE_SET_HOP2_E2E1", "docs/30")
    require_contains(doc, "N6AL_ACTUAL_SIDE_ONLY", "docs/30")
    require_contains(doc, "peer_next_floor", "docs/30")
    require_contains(doc, "N6_CAPACITY_ACTIVE_VS_RETIRED_SPLIT", "docs/30")
    require_contains(doc, "retired_tombstone_count ≤ max_retired_tombstones", "docs/30")
    require_contains(doc, "tombstone-compact FULL", "docs/30")
    require_contains(doc, "N6HW_NAMESPACE_GLOBAL_NO_CONTEXT_ID", "docs/30")
    require_contains(doc, "scope_digest28", "docs/30")
    require_contains(doc, "N6CF_DURABLE_CONTEXT_FENCE_LAYOUT", "docs/30")
    require_contains(doc, "N6_MULTIKEY_CU_ALL_OLD_OR_ALL_PROPOSED", "docs/30")
    require_contains(doc, "ALL_OLD", "docs/30")
    require_contains(doc, "ALL_PROPOSED", "docs/30")
    require_contains(doc, "max write-set entries N", "docs/30")
    require_contains(doc, "CLOCK_FAULT_SOLE_R2_META_FC", "docs/30")
    require_contains(doc, "PROFILE_AUTHORITY_EPOCH_IN_DOCUMENT", "docs/30")
    require_contains(doc, "authority_clock_epoch_id", "docs/30")
    require_contains(doc, "ninlil_r5_private_activate_profiles_with_authority_epoch", "docs/30")
    require_contains(doc, "ADOPT_CU_EXPLICIT_PROOF_ONLY", "docs/30")
    require_contains(doc, "ninlil_r2_private_prove_adopt_authority_epoch", "docs/30")
    require_contains(doc, "proof_schema = 1", "docs/30")
    require_contains(doc, "INTENT_BURN_CU", "docs/30")
    require_contains(doc, "INTENT_BURN_CU_STATE_CLOSED", "docs/30")
    require_absent(doc, "radio-security alternate CLOCK", "docs/30")


    # structural A–I (must be mutated by self-test)
    require_contains(doc, "fences entire radio-security namespace", "docs/30")
    require_contains(doc, "Namespace length+bytes **MUST** differ from Foundation Runtime", "docs/30")
    require_contains(doc, "NEED_CLOSE_OLD → NEED_OPEN", "docs/30")
    require_contains(doc, "SEMANTIC: R6_DOCS_FREEZE_ONLY", "docs/30")
    require_contains(doc, "scan all N6* records", "docs/30")
    require_contains(doc, "NEED_CLOSE_OLD → NEED_OPEN → READ_CLASSIFY → RECOVERED | CORRUPT", "docs/30")
    require_contains(doc, "max value length", "docs/30")
    require_contains(doc, "exact count equality", "docs/30")
    require_contains(doc, "non-OK rollback ⇒ CORRUPT fence (close has no status)", "docs/30")
    require_contains(doc, "recovery_proof_valid", "docs/30")
    require_contains(doc, "class A forbidden", "docs/30")
    require_contains(doc, "Partial set ⇒ CORRUPT", "docs/30")
    require_contains(doc, "any THIRD or mix → CORRUPT", "docs/30")
    require_contains(doc, "N6CF", "docs/30")
    require_contains(doc, "M4 durable namespace retirement", "docs/30")
    require_contains(doc, "reclaim-compact", "docs/30")
    require_contains(doc, "authority domain", "docs/30")
    require_contains(doc, "never publish unaccepted S", "docs/30")


    # === 2026 re-audit structural requires (16-cluster) ===
    require_contains(doc, "L1_W1_SEVEN_EVENT_SET_TX_RESULT", "docs/30")
    require_contains(doc, "MUST NOT** sample clock; **MUST NOT** write R2 durable state", "docs/30")
    require_contains(doc, "status = validation_cb(user, &S_view, &static_plan, &out_window);", "docs/30")
    require_contains(doc, "L1 alone invokes docs/24 / R1 sole pipeline `transmit_with_permit` (validate→consume→edge).", "docs/30")
    require_contains(doc, "**ISSUE_GRANTED and TRANSMIT_EDGE are abolished.**", "docs/30")
    require_contains(doc, "`TX_RESULT`", "docs/30")
    require_contains(doc, "Closed L1↔W1 event set — exact 7 events", "docs/30")
    require_contains(doc, "R2_PRIVATE_ISSUE_COORDINATOR_SINGLE_SAMPLE", "docs/30")
    require_contains(doc, "validation_cb", "docs/30")
    require_contains(doc, "R2 samples S **once**", "docs/30")
    require_contains(doc, "PROFILE_ACTIVATION_SAME_S_SNAPSHOT", "docs/30")
    require_contains(doc, "accepted_class_D_snapshot", "docs/30")
    require_contains(doc, "REG_PROFILE_SCHEMA2_AUTHORITY_EPOCH", "docs/30")
    require_contains(doc, "N6AL_OUTBOUND_PEER_NEXT_FLOOR", "docs/30")
    require_contains(doc, "N6_NO_RETAINED_UNCOMPACTED", "docs/30")
    require_absent(doc, "retained_uncompacted_count u16", "docs/30")
    require_contains(doc, "N6_BOOT_EXACT_LANE_TO_N6AL_JOIN", "docs/30")
    require_contains(doc, "N6_NAMESPACE_GC_BOUNDED_BATCH_N32", "docs/30")
    require_contains(doc, "at most **32** write-set entries", "docs/30")
    require_contains(doc, "ADOPT_CU_PROOF_FIXED_120B_ONLY", "docs/30")
    require_contains(doc, "recovery_proof[120]", "docs/30")
    require_absent(doc, "recovery_proof[72]", "docs/30")
    require_absent(doc, "opaque recovery token OR", "docs/30")
    require_absent(doc, "ADOPT_CU_PROOF_FIXED_72B_ONLY", "docs/30")
    require_contains(doc, "pre_ram_next, pre_ram_limit, proposed_U, candidate_C", "docs/30")
    require_contains(doc, "CONSUME_TYPED_REASON_43_45_CLOSED", "docs/30")
    require_contains(doc, "NINLIL_PCP_REASON_FIFO_OUT_OF_ORDER", "docs/30")
    require_contains(doc, "**43**", "docs/30")
    require_contains(doc, "**44**", "docs/30")
    require_contains(doc, "**45**", "docs/30")
    require_contains(doc, "CLOCK_FAULT_FC_BY_R2_SAMPLE", "docs/30")
    require_contains(doc, "ESP_STORAGE_CAPACITY_NOT_READY_R6", "docs/30")
    require_contains(doc, "NOT READY", "docs/30")
    require_contains(doc, "TX lane value (68 B continuous BE; schema 2)", "docs/30")

    require_absent(doc, "§11.2.4", "docs/30")
    require_absent(doc, "§15.3.3 public drain", "docs/30")



    require_contains(doc, "ADR0010_SUPERSEDES_R5_RESTART_GEN_BUMP", "docs/30")
    require_contains(doc, "docs/29 §5.1 / ADR-0009 now distinguish LAB standalone assignment fence from R6 restart", "docs/30")
    require_contains(doc, "EXPORTED_PRIVATE_MODULE_C_API_NOT_OSS_PUBLIC", "docs/30")
    require_contains(doc, "Stale name `R7_STATUS_PRESERVING_R5_RECONCILE_SEAM` is **not** Normative", "docs/30")
    require_contains(doc, "discard entire `radio_volatile_work`", "docs/30")
    require_contains(doc, "CLOCK_UNCERTAIN_SAME_EPOCH_FRESH_OK", "docs/30")
    require_contains(doc, "R2 adopt forbidden", "docs/30")
    require_absent(doc, "mandatory private R5 reconciliation seam is the only implementable path", "docs/30")
    require_absent(doc, "permanent epoch-mismatch drop loop without adopt", "docs/30")


    require_contains(doc, "R6 never independently bumps/defers ARW generation", "docs/30")
    require_contains(doc, "same-epoch admit forbidden; fresh-epoch adopt", "docs/30")
    require_contains(doc, "**TERMINAL_PENDING:** if a receiver terminal (COMPLETE/ABORT*) is ready but an issued Permit still exists", "docs/30")
    require_contains(doc, "**no-drain terminal** for that Permit", "docs/30")
    require_contains(doc, "Never modified by burn, Seal, Permit denial, or hop retry", "docs/30")
    require_contains(doc, "Ordinary issued-Permit drain MUST keep `permit_bind_generation` and U5 ARW bit-exact unchanged", "docs/30")

    require_absent(doc, "Normative exception: issued Permit may be discarded locally", "docs/30")
    require_absent(doc, "Normative exception: create an unbounded sequence of replacement candidates", "docs/30")
    require_absent(doc, "detects arbitrary natural-language contradictions completely", "docs/30")
    # positive claims of forbidden designs
    require_absent(doc, "new checked G+1 fence target", "docs/30")
    require_absent(doc, "The private drain-reconciliation seam is mandatory", "docs/30")
    require_absent(doc, "Mandatory private status-preserving R5 **drain reconciliation** seam", "docs/30")
    acceptance_scope = _section(doc, "## 18. R7 acceptance (required negatives/goldens)", "## 19. Related")
    require_contains(acceptance_scope, "**Exported private-module drain orchestration:** no mandatory private R5 drain seam", "docs/30 §18")
    require_contains(acceptance_scope, "These symbols are not installed OSS public ABI", "docs/30 §18")
    require_contains(acceptance_scope, "R7-private extension is required for checked **issue**, not ordinary drain", "docs/30 §18")


    require_contains(doc, "increment `e2e_prepare_burn_count`", "docs/30 §15")
    require_contains(doc, "`hop_air_attempt_count ≤ hop_prepare_burn_count ≤ 4`", "docs/30 §15")
    require_absent(permit_scope, "zero backoff", "docs/30 §15.3")
    require_absent(permit_scope, "unbounded replacement", "docs/30 §15.3")
    require_absent(permit_scope, "call consume again", "docs/30 §15.3")
    require_absent(permit_scope, "replacement candidates are allowed", "docs/30 §15.3")
    require_contains(doc, "frag_receiver_transfer_ttl_ms = 90000", "docs/30")
    require_contains(doc, "tombstone_ttl_ms = 90000", "docs/30")
    require_contains(doc, "**CONT_CONFLICT_ABORT_TOMBSTONE:** same `frag_index` with **different bytes**", "docs/30")
    require_contains(doc, "Hop attempt count increments only when Permit consume succeeds", "docs/30")
    require_contains(doc, "`e2e_prepare_burn_count` increments on successful durable burn", "docs/30")
    require_contains(doc, "max **4 per fragment**, max **1 per SINGLE admission**", "docs/30 §15.1")
    require_contains(doc, "After successful durable burn the slot is permanently consumed", "docs/30 §15.1")
    require_contains(doc, "requires `hop_prepare_burn_count < 4`", "docs/30 §15.2")
    require_contains(doc, "no **seal/encode/AEAD failure replacement** in that group", "docs/30 §15.2")
    require_contains(doc, "hop_air_attempt_count ≤ hop_prepare_burn_count ≤ 4", "docs/30")

    acceptance_scope = _section(doc, "## 18. R7 acceptance (required negatives/goldens)", "## 19. Related")
    require_contains(acceptance_scope, "`spec/vectors/r7-radio-wire-v1.json`", "docs/30 §18")
    require_contains(acceptance_scope, "canonical lowercase hex + stable vector IDs", "docs/30 §18")
    require_contains(acceptance_scope, "HKDF extract/expand PRK/key/IV", "docs/30 §18")
    require_contains(acceptance_scope, "16. Independent oracle (not production codec helpers) **shall** generate vectors", "docs/30 §18")
    require_contains(acceptance_scope, "when artifacts exist, JSON/generated header freshness must match", "docs/30 §18")
    require_contains(acceptance_scope, "R7-FRAG-FINAL-GOOD", "docs/30 §18")
    require_contains(acceptance_scope, "R7-FRAG-FINAL-DIGEST-FAIL", "docs/30 §18")
    require_contains(acceptance_scope, "R7-FRAG-FINAL-RESOURCE-FAIL", "docs/30 §18")
    require_contains(acceptance_scope, "R7-FRAG-ACK-BEFORE-LINK-ACK", "docs/30 §18")
    require_contains(acceptance_scope, "round-trip-only tests are insufficient", "docs/30 §18")
    return doc


def check_adr(root: pathlib.Path) -> None:
    adr = read(root, ADR10)
    status_line = _header_status_line(adr)
    if "Accepted 仮" in status_line:
        fail("ADR-0010 current status must not be Accepted 仮 (provisional)")
    if "**Accepted**" not in status_line:
        fail("ADR-0010 status must be Accepted")
    if "independent root QA re-GO 2026-07-19 P0=P1=P2=0" not in status_line:
        fail("ADR-0010 status must cite independent root QA re-GO 2026-07-19 P0=P1=P2=0")
    require_contains(adr, "Stage 9 accepted — final re-GO complete", "ADR-0010")
    require_contains(adr, "R6 docs freeze Accepted", "ADR-0010")
    # Historical Round 3 / self-review era not-GO retained (revisionism ban)
    require_contains(adr, "not GO", "ADR-0010")
    require_contains(adr, "Round 3 repair (still not GO)", "ADR-0010")
    require_contains(adr, "host candidate **fixed-hash integration GO**", "ADR-0010")
    require_contains(adr, "R7 full AEAD codec 実装", "ADR-0010")
    require_contains(adr, "RF·USB 実機 HIL", "ADR-0010")
    require_contains(adr, "gate PASS ≠ GO", "ADR-0010")
    require_contains(adr, "gate PASS ≠ arbitrary natural-language proof", "ADR-0010")
    require_contains(adr, "72 B", "ADR-0010")
    require_contains(adr, "docs/25", "ADR-0010")
    require_contains(adr, "`transfer_start_mono` / immutable `sender_absolute_deadline` set once at outgoing transfer admission", "ADR-0010")
    require_contains(adr, "`retry_not_before` includes `frag_ack_deadline`", "ADR-0010")
    require_contains(adr, "non-retryable issue/expiry/plan fence terminally fails that LINK group", "ADR-0010")
    require_contains(adr, "definite unconsumed+retryable result before TX", "ADR-0010")
    require_contains(adr, "FRAG sender absolute deadline or SINGLE queue/item TTL", "ADR-0010")
    require_contains(adr, "every terminal tombstone expiry uses checked add before atomic commit", "ADR-0010")
    require_contains(adr, "every-4/idle-only generation is forbidden", "ADR-0010")
    require_contains(adr, "exact namespace distinct from Foundation Runtime storage namespace", "ADR-0010")
    require_contains(adr, "NEED_CLOSE_OLD→NEED_OPEN→READ_CLASSIFY", "ADR-0010")
    require_contains(adr, "copy-owned recovery inputs", "ADR-0010")
    require_contains(adr, "FRAG_ACK-before-LINK_ACK", "ADR-0010")
    require_contains(adr, "full CONT cancels PARTIAL", "ADR-0010")
    require_contains(adr, "positive 100ms/max8", "ADR-0010")
    require_contains(adr, "global Permit FIFO", "ADR-0010")
    require_contains(adr, "21-row", "ADR-0010")
    require_contains(adr, "artifacts pending", "ADR-0010")
    require_contains(adr, "authority-time", "ADR-0010")
    require_contains(adr, "ACK burn", "ADR-0010")
    require_contains(adr, "e2e_attempt_start_mono", "ADR-0010")
    require_contains(adr, "w1_last_accepted_now_ms", "ADR-0010")
    require_contains(adr, "no ordinary fence_after_revoke", "ADR-0010")


def check_review(root: pathlib.Path) -> None:
    """Historical 2026-07-17 self-review — MUST retain Accepted 仮 / not GO (no revisionism)."""
    rev = read(root, REVIEW)
    require_contains(rev, "Accepted 仮", "self-review")
    require_contains(rev, "Not claimed", "self-review")
    require_contains(rev, "timer-domain table", "self-review")
    require_contains(rev, "does not claim detection of arbitrary natural-language", "self-review")
    require_contains(rev, "not GO", "self-review")  # historical NO-GO snapshot


def check_final_review(root: pathlib.Path) -> None:
    """2026-07-19 final Accepted re-GO record."""
    fr = read(root, FINAL_REVIEW)
    status_lines = [
        line.rstrip() for line in fr.splitlines() if line.startswith("**状態:**")
    ]
    expected_status = "**状態:** **final Accepted re-GO**（R6 docs freeze Accepted / Stage 9）"
    if status_lines != [expected_status]:
        fail(f"final-review exact status mismatch: {status_lines!r}")
    integration_lines = [
        line.rstrip() for line in fr.splitlines()
        if line.startswith("**Independent integration re-audit:**")
    ]
    expected_integration = (
        "**Independent integration re-audit:** **P0=0 / P1=0 / P2=0 GO**"
    )
    if integration_lines != [expected_integration]:
        fail(f"final-review exact integration verdict mismatch: {integration_lines!r}")
    require_contains(fr, "final Accepted re-GO", "final-review")
    require_contains(fr, "R6 docs freeze Accepted", "final-review")
    require_contains(fr, "P0=0", "final-review")
    require_contains(fr, "P1=0", "final-review")
    require_contains(fr, "P2=0", "final-review")
    require_contains(fr, "independent integration re-audit", "final-review")
    require_contains(fr, "Storage header/pin separate re-audit", "final-review")
    require_contains(fr, "formal superseded", "final-review")
    require_contains(
        fr,
        "final status-only delta independent recheck P0=0 / P1=0 / P2=0 GO",
        "final-review",
    )
    require_contains(fr, "pre-status full audit", "final-review")
    require_contains(
        fr,
        "a63f43db8cd9fc396ca05677b2d240c5ddfea526a95aa7fadc4ff57c56969f14",
        "final-review",
    )
    require_contains(
        fr,
        "d5c4cf14ffd9bc6a042a1540aa00790f48151da6075d40a1c07cc8e46dc5a6c6",
        "final-review",
    )
    require_contains(fr, "R7 full AEAD", "final-review")
    require_contains(fr, "実機 HIL", "final-review")
    require_contains(fr, "production radio", "final-review")
    require_contains(fr, "compile/link **≠** HIL", "final-review")
    require_absent(fr, "PLACEHOLDER_", "final-review")
    require_contains(fr, "gate PASS ≠ arbitrary natural-language proof", "final-review")
    require_contains(fr, "R7 full AEAD / M4·M5 / ESP capacity / 実機 HIL / legal / production **未完**", "final-review")
    # Affirmative completion of R7/HIL/production forbidden (negations like "完了は主張しない" are OK)
    bad_complete = (
        "R7 full AEAD codec **complete**",
        "R7/HIL 完成",
        "R7 complete / HIL complete",
        "production radio **complete**",
        "all remaining incompletes complete",
        "実機 HIL 完了を確認",
        "実機 HIL PASS",
    )
    for b in bad_complete:
        if b in fr:
            fail(f"final-review must not claim incomplete work done: {b!r}")
    # Mutation target: replacing 未完 block with bold-complete claims must fail
    if "R7 full AEAD codec **complete** / 実機 HIL 完了 / production radio **complete**" in fr:
        fail("final-review must not claim R7/HIL/production complete")


def check_cross(root: pathlib.Path) -> None:
    for rel in CROSS:
        t = read(root, rel)
        for bad in ("116/124/132", "100+N", "duty_1ch_data", "major=1 minor=0"):
            if bad in t:
                fail(f"{rel} obsolete {bad!r}")

    d25 = root / "docs/25-u5-cell-operating-assignment.md"
    if d25.is_file():
        raw25 = d25.read_bytes()
        if len(raw25) != DOC25_BYTES:
            fail(f"docs/25 byte length {len(raw25)} != frozen {DOC25_BYTES}")
        digest25 = hashlib.sha256(raw25).hexdigest()
        if digest25 != DOC25_SHA256:
            fail(f"docs/25 sha256 {digest25} != frozen {DOC25_SHA256}")
        t25 = raw25.decode("utf-8")
        require_contains(t25, "unallocated", "docs/25")
        require_absent(t25, "wire_profile_id=0x11", "docs/25")

    d23 = read(root, DOC23)
    require_contains(d23, "wire_profile_id=0x11", "docs/23")
    require_contains(d23, "R2 authority clock の `{epoch_id, now_ms}` に束縛した時間窓", "docs/23")
    require_contains(d23, "`profile_clock_epoch_id` と Permit 発行時 `clock_epoch_id` の一致を必須", "docs/23")
    require_contains(d23, "host wall clock / Unix time を使わない", "docs/23")
    require_absent(d23, "major=1 minor=0", "docs/23")

    d29 = read(root, DOC29)
    require_contains(d29, "### 5.2 R6 authority-clock profile field + activation", "docs/29")
    require_contains(d29, "R6 `0x11` の通常 restart / issued cleanup", "docs/29")
    require_contains(d29, "`permit_bind_generation` / U5 ARW generation は **bit-exact 不変**", "docs/29")
    require_contains(d29, "authenticated SET L5–L9 が新 generation を決定", "docs/29")
    require_contains(d29, "schema = 2", "docs/29")
    require_contains(d29, "authority_clock_epoch_id", "docs/29")
    require_contains(d29, "ninlil_r5_private_activate_profiles_with_authority_epoch", "docs/29")

    a9 = read(root, ADR9)
    require_contains(a9, "R6 amendment: [ADR-0010]", "ADR-0009")
    require_contains(a9, "U5 SET L5–L9 が決めた generation", "ADR-0009")
    require_contains(a9, "`profile_clock_epoch_id` sidecar", "ADR-0009")
    require_contains(a9, "host wall clockを使用しない", "ADR-0009")

    d01 = read(root, "docs/01-architecture.md")
    require_contains(d01, "wire_profile_id=0x11", "docs/01")
    if "secure radio wire version は **unallocated**" in d01:
        fail("docs/01 current unallocated")

    d05 = read(root, "docs/05-security-and-compliance.md")
    require_contains(d05, "Attachment-only change** では E2E context を fence しない", "docs/05")

    readme = read(root, "docs/README.md")
    require_contains(readme, "R6 NRW1 secure radio wire docs freeze Accepted", "docs/README")
    require_contains(readme, "independent re-GO 2026-07-19 P0=P1=P2=0", "docs/README")
    require_absent(readme, "R6 NRW1 secure radio wire docs draft（Accepted 仮", "docs/README")

    for rel in (
        "docs/release-history.md",
        "CHANGELOG.md",
        "docs/README.md",
        "docs/adr/README.md",
        "docs/07-testing-and-quality.md",
        "docs/09-roadmap.md",
    ):
        require_contains(read(root, rel), "30-r6-secure-radio-wire", rel)

    # Index honesty: current status Accepted (not provisional) + incompletes separated
    for rel, needles in (
        (
            "docs/release-history.md",
            ("docs freeze Accepted", "re-GO 2026-07-19", "R7 full AEAD", "compile ≠ HIL"),
        ),
        ("CHANGELOG.md", ("docs freeze Accepted", "P0=0 / P1=0 / P2=0", "status-only", "R7 full AEAD")),
        ("docs/adr/README.md", ("**Accepted**", "re-GO 2026-07-19 P0=P1=P2=0", "R7 full AEAD")),
        ("docs/09-roadmap.md", ("Normative freeze Accepted", "re-GO 2026-07-19 P0=P1=P2=0", "R7 full AEAD")),
        ("docs/reviews/README.md", ("final Accepted re-GO", "P0=0 / P1=0 / P2=0 GO", "formal superseded", "status-only delta")),
    ):
        body = read(root, rel)
        for n in needles:
            require_contains(body, n, rel)


def check(root: pathlib.Path) -> None:
    check_docs30(root)
    check_adr(root)
    check_review(root)
    check_final_review(root)
    check_round2_structural(root)
    check_cross(root)



def check_chunk_c_l1_w1(doc: str) -> None:
    """Section-scoped Chunk C: events, SEAL_FAIL, LENGTH_CLASS, callback, clock discard."""
    # Scope: §1.1 through ## 2
    i0 = doc.find("### 1.1 L1 Radio Coordinator")
    i1 = doc.find("## 2. Wire profile pin")
    if i0 < 0 or i1 < 0 or i1 <= i0:
        fail("chunk C: §1.1 scope missing")
    s11 = doc[i0:i1]

    # Exact 7 event table rows (numbered)
    for row in (
        "| 1 | L1→W1 | `STAMP_FIELDS`",
        "| 2 | W1→L1 | `FRAME_READY`",
        "| 3 | W1→L1 | `SEAL_FAIL`",
        "| 4 | W1→L1 | `LENGTH_CLASS`",
        "| 5 | L1→W1 | `TX_RESULT`",
        "| 6 | L1→W1 | `DRAIN_QUARANTINE`",
        "| 7 | L1→W1 | `OWNER_TERMINAL`",
    ):
        if row not in s11:
            fail(f"chunk C: missing event table row {row}")
    if "ISSUE_GRANTED` allowed" in s11 or "| L1→W1 | `ISSUE_GRANTED`" in s11:
        fail("chunk C: ISSUE_GRANTED must not be live")
    if "Abolished: `ISSUE_GRANTED`, `TRANSMIT_EDGE`" not in s11:
        fail("chunk C: abolished ISSUE_GRANTED/TRANSMIT_EDGE required")
    if "event_schema    : u16  /* exact 1 */" not in s11 and "event_schema = 1" not in s11:
        if "event_schema" not in s11 or "exact 1" not in s11:
            fail("chunk C: missing event_schema u16 exact 1")
    if "owner_token     : u64  /* nonzero scalar */" not in s11 and "owner_token  : u64 nonzero scalar" not in s11:
        if "owner_token" not in s11 or "nonzero" not in s11:
            fail("chunk C: missing scalar u64 nonzero owner_token")
    if "candidate_token : u64  /* nonzero scalar */" not in s11 and "candidate_token : u64 nonzero scalar" not in s11:
        if "candidate_token" not in s11 or "nonzero" not in s11:
            fail("chunk C: missing scalar u64 nonzero candidate_token")
    if "per live (owner_token, candidate_token) pair" not in s11:
        fail("chunk C: owner-wide drain must be per live pair")
    if "No token set, no sentinel 0, no multi-token payload." not in s11:
        fail("chunk C: must forbid token set/sentinel/array")
    if "exactly once** per candidate_token" not in s11:
        fail("chunk C: STAMP_FIELDS exactly once required")
    if "exactly one** of `FRAME_READY` | `SEAL_FAIL` | `LENGTH_CLASS`" not in s11:
        fail("chunk C: W1 response exactly one of FRAME_READY|SEAL_FAIL|LENGTH_CLASS")
    if "terminal TX_RESULT forbidden" not in s11:
        fail("chunk C: SEAL_FAIL/LENGTH_CLASS must forbid terminal TX_RESULT")
    if "never both; never two terminals" not in s11:
        fail("chunk C: terminal uniqueness after FRAME_READY")

    # SEAL_FAIL phases 1..7 exact closed list fragment
    if "`1 PRE_BURN_VALIDATE` · `2 E2E_COUNTER_BURN` · `3 E2E_ENCODE` · `4 E2E_AEAD` · `5 HOP_COUNTER_BURN` · `6 HOP_ENCODE` · `7 HOP_AEAD`" not in s11:
        fail("chunk C: seal_phase closed list missing or altered")
    if "`1 STRUCT_INVALID` · `2 CONTEXT_UNAVAILABLE` · `3 COUNTER_DEFINITE_FAILURE` · `4 COUNTER_CORRUPT` · `5 ENCODE_FAILURE` · `6 AEAD_FAILURE` · `7 OUTPUT_SHAPE` · `8 ALIAS_OR_INTERNAL_CONTRACT`" not in s11:
        fail("chunk C: seal_cause closed list missing or altered")
    if "| E2E_ENCODE / E2E_AEAD | 1 E2E |" not in s11 and "| E2E_ENCODE / E2E_AEAD | E2E |" not in s11:
        fail("chunk C: E2E_ENCODE/AEAD must burn_state E2E")
    if "while burn CU is open, **do not** emit SEAL_FAIL" not in s11:
        fail("chunk C: CU must not emit SEAL_FAIL until classified")
    if "Forbidden: any blanket rule that “classification後必ずSEAL_FAIL”." not in s11:
        fail("chunk C: must explicitly forbid always-SEAL_FAIL-after-classify")
    if "Allowed: classification後必ずSEAL_FAIL" in s11:
        fail("chunk C: must not allow always-SEAL_FAIL-after-classify")
    if "Numeric length under/over/exact mismatch** is **LENGTH_CLASS only" not in s11:
        fail("chunk C: length mismatch is LENGTH_CLASS only")

    # length catalog bounds (domain headers may be sealed-blob; row sizes preserved)
    for needle in (
        "DATA_SINGLE` | 31..220 | 66..255",
        "DATA_FRAG_START` | 95..220 | 130..255",
        "DATA_FRAG_CONT` | 41..220 | 76..255",
        "DATA_FRAG_ACK` | 44 exact | 79 exact",
        "LINK_ACK` | N/A | 51 exact",
        "UNDER_MIN",
        "OVER_MAX",
        "EXACT_MISMATCH",
        "ARITHMETIC_OVERFLOW",
        "TYPE_UNCLASSIFIABLE",
    ):
        if needle not in s11:
            fail(f"chunk C: length catalog missing {needle!r}")
    if "| class | E2E PT domain" in s11 or "E2E PT domain |" in s11:
        fail("chunk C: old E2E PT domain header must be abolished")

    if "radio_volatile_work" not in s11:
        fail("chunk C: radio_volatile_work set missing in §1.1")
    for item in (
        "Permit snapshot",
        "outgoing SINGLE item",
        "ACK intent/ledger",
        "tombstone/reservation",
        "upper-transport queue item",
        "endpoint E2E ingress queue item",
        "forwarding queue item",
    ):
        if item not in s11:
            fail(f"chunk C: radio_volatile_work missing {item}")
    if re.search(r"radio_volatile_work\s*=\s*\{[^}]*forwarding/ingress queue item", s11, re.S):
        fail("chunk C: ambiguous forwarding/ingress aggregate token must be abolished from set")
    if "across **all** owners" not in s11:
        fail("chunk C: TEMP discard must be all owners")
    if "fresh** burn/stamp/seal/issue only" not in s11:
        fail("chunk C: later class-D must be fresh only")
    if "no old candidate/Permit resume" not in s11:
        fail("chunk C: must forbid old candidate/Permit resume after TEMP")

    # Callback section §15.3.1
    j0 = doc.find("#### 15.3.1 R7 private R2 checked-issue primitive")
    j1 = doc.find("#### 15.3.2 Exhaustive issue outcome")
    if j0 < 0 or j1 < 0 or j1 <= j0:
        fail("chunk C: §15.3.1 scope missing")
    iss = doc[j0:j1]
    if "VAL_CLOCK_DROP abolished" not in iss and "is not a Normative result" not in iss:
        fail("chunk C: must abolish VAL_CLOCK_DROP")
    if re.search(r"VAL_OK\|VAL_TERMINAL\|VAL_RETRYABLE\|VAL_AUTHORITY\|VAL_RECONCILE\|VAL_CLOCK_DROP", iss):
        fail("chunk C: VAL_CLOCK_DROP must not remain in closed result enum")
    if "| `VAL_CLOCK_DROP`" in iss:
        fail("chunk C: VAL_CLOCK_DROP must not be a mapping table row")
    if "R2 samples S **once**" not in iss:
        fail("chunk C: order must sample once before callback")
    if "**Only** trusted class-D: `status = validation_cb" not in iss:
        fail("chunk C: validation_cb only on trusted class-D")
    if "validation_cb runs before sample gates" in iss:
        fail("chunk C: validation_cb must not run before sample gates")
    for row in (
        "| `VAL_TERMINAL` | `NINLIL_PCP_STRUCT` (3)",
        "| `VAL_RETRYABLE` | `NINLIL_PCP_CAPACITY` (7)",
        "| `VAL_AUTHORITY` | `NINLIL_PCP_PROFILE_MISMATCH` (6)",
        "| `VAL_RECONCILE` | `NINLIL_PCP_INVALID_STATE` (2) | `CONTRACT` (28) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `RECONCILE_REQUIRED` |",
        "| `VAL_OK` |",
        "business_mutation",
        "clock_fence_mutation",
        "txn_provenance",
        "TERMINAL_UNISSUED",
        "RETRYABLE_UNISSUED",
        "AUTHORITY_DIVERGENCE",
        "RECONCILE_REQUIRED",
        "PRECHECK_ZERO",
        "proceed to RW ISSUED",
    ):
        if row not in iss:
            fail(f"chunk C: callback mapping missing {row}")
    if "| `VAL_RECONCILE` | `NINLIL_PCP_CORRUPT_FENCE` (5)" in iss or "| `VAL_RECONCILE` | `NINLIL_PCP_CORRUPT_FENCE` (10)" in iss:
        fail("chunk C: VAL_RECONCILE must not map to CORRUPT_FENCE (5 or 10)")
    # VAL_RECONCILE must not be terminal
    if re.search(
        r"\| `VAL_RECONCILE` \| `NINLIL_PCP_INVALID_STATE` \(2\) \| `CONTRACT` \(28\) \| BUSINESS_ZERO \| META_ZERO \| PRECHECK_ZERO \| `TERMINAL_UNISSUED` \|",
        iss,
    ):
        fail("chunk C: VAL_RECONCILE CONTRACT must be RECONCILE_REQUIRED not terminal")
    if "Non-OK: `out_window` all zero; RW begin 0; registry mutation 0" not in iss:
        fail("chunk C: non-OK out_window all zero")
    if "without** calling validation_cb" not in iss:
        fail("chunk C: clock faults skip validation_cb")

    # P1-B drain table vs global discard
    d331 = doc.find("##### 15.3.3.1 Post-`DRAIN_OK` disposition")
    d332 = doc.find("#### 15.3.4 R1 full transmit pipeline")
    if d331 < 0 or d332 <= d331:
        fail("chunk C repair: §15.3.3.1 scope missing")
    d31 = doc[d331:d332]
    if "unrelated unissued live owners" in d31 and "may remain" in d31:
        fail("chunk C repair: §15.3.3.1 must not allow unrelated unissued to remain on TEMP")
    if "globally discarded** before/while drain" not in d31 and "globally discarded" not in d31:
        fail("chunk C repair: TEMP unissued must be globally discarded")
    if "candidate/group/blob **MUST NOT** remain" not in d31 and "MUST NOT** remain" not in d31:
        fail("chunk C repair: forbid unrelated candidate/group/blob remain")

    # P1-C private issue two-axis
    i32 = doc.find("#### 15.3.2 Exhaustive issue outcome")
    i33 = doc.find("#### 15.3.3 Issued Permit cleanup")
    if i32 < 0 or i33 <= i32:
        fail("chunk C repair: §15.3.2 scope missing")
    i2 = doc[i32:i33]
    for tok in (
        "business_mutation",
        "clock_fence_mutation",
        "txn_provenance",
        "BUSINESS_ZERO",
        "ISSUED_FULL",
        "BUSINESS_AMBIGUOUS",
        "META_ZERO",
        "F_C_FULL",
        "META_AMBIGUOUS",
        "CLOCK_FENCE_COMMITTED",
        "ISSUED_COMMITTED",
    ):
        if tok not in i2:
            fail(f"chunk C repair: §15.3.2 missing {tok}")
    if "| R2 private issue | `NINLIL_PCP_CLOCK_FAULT` (5) after helper FULL OK | BUSINESS_ZERO | **F_C_FULL** | **CLOCK_FENCE_COMMITTED** |" not in i2:
        fail("chunk C repair: CLOCK_FAULT issue row must be BUSINESS_ZERO + F_C_FULL + CLOCK_FENCE_COMMITTED")
    if "claim business zero while hiding a meta F_c write" not in i2:
        fail("chunk C repair: must forbid business zero hiding meta mutation")


def _parse_marked_field_block(scope: str, begin: str, end: str) -> list[tuple[str, str, str]]:
    """Parse EVENT_*_BEGIN/END fenced text as ordered (name, type, constraint) tuples.

    Lines are either bare names (common_envelope) or `name : type /* constraint */`.
    Extra/missing/duplicate are detected by the caller via exact tuple equality.
    """
    b = scope.find(begin)
    e = scope.find(end)
    if b < 0 or e < 0 or e <= b:
        fail(f"chunk C-2: markers {begin}/{end} missing or reversed")
    body = scope[b + len(begin) : e]
    # strip fenced code if present
    m = re.search(r"```(?:text)?\n(.*?)```", body, re.S)
    text = m.group(1) if m else body
    rows: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("```"):
            continue
        # bare name only (optional trailing comma / comment for common_envelope,)
        bare = re.fullmatch(
            r"([A-Za-z_][A-Za-z0-9_]*)\s*,?(?:\s*/\*\s*(.*?)\s*\*/)?\s*",
            line,
        )
        if bare and ":" not in line:
            name, typ, cons = bare.group(1), "", (bare.group(2) or "").strip()
        else:
            mm = re.match(
                r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(\S+(?:\s+\S+)*?)(?:\s*/\*\s*(.*?)\s*\*/)?\s*$",
                line,
            )
            if not mm:
                fail(f"chunk C-2: unparseable field line in {begin}: {line!r}")
            name, typ, cons = mm.group(1), mm.group(2).strip(), (mm.group(3) or "").strip()
        if name in seen:
            fail(f"chunk C-2: duplicate field {name!r} in {begin}")
        seen.add(name)
        rows.append((name, typ, cons))
    if not rows:
        fail(f"chunk C-2: empty field block {begin}")
    return rows


def _parse_fenced_set_members(scope: str, set_name: str) -> list[str]:
    """Parse `set_name = { a, b, ... }` inside a ```text fence; preserve order; detect dups."""
    m = re.search(
        rf"{re.escape(set_name)}\s*=\s*\{{(.*?)\}}",
        scope,
        re.S,
    )
    if not m:
        fail(f"chunk C-2: fenced set {set_name} missing")
    body = m.group(1)
    members: list[str] = []
    seen: set[str] = set()
    for raw in body.splitlines():
        item = raw.strip().rstrip(",").strip()
        if not item:
            continue
        if item in seen:
            fail(f"chunk C-2: duplicate set member {item!r} in {set_name}")
        seen.add(item)
        members.append(item)
    return members



def check_chunk_c2_interop_events(doc: str) -> None:
    """Round4 Chunk C-2: logical C ABI, seal I/O slots, PRE_R1 11, TX closed, borrow, FIRST_FRAG, ACK0."""
    i0 = doc.find("#### 1.1.1 Closed L1↔W1 event set")
    i1 = doc.find("## 2. Wire profile pin")
    if i0 < 0 or i1 <= i0:
        fail("chunk C-2: §1.1.1 scope missing")
    s11 = doc[i0:i1]
    i_l1 = doc.find("### 1.1 L1 Radio Coordinator")
    s11_full = doc[i_l1:i1] if i_l1 >= 0 and i_l1 < i1 else s11

    # section order
    h111 = s11.find("##### 1.1.1.1 SEAL_FAIL")
    h112 = s11.find("##### 1.1.1.2 LENGTH_CLASS")
    h113 = s11.find("##### 1.1.1.3 radio_volatile_work")
    h114 = s11.find("##### 1.1.1.4 STAMP_FIELDS")
    h115 = s11.find("##### 1.1.1.5 FRAME_READY")
    h112t = s11.find("#### 1.1.2 TX_RESULT")
    if min(h111, h112, h113, h114, h115, h112t) < 0:
        fail("chunk C-2: missing §1.1.1.x / §1.1.2 headings")
    if not (h111 < h112 < h113 < h114 < h115 < h112t):
        fail("chunk C-2: section order must be 1.1.1.1→…→1.1.1.5→1.1.2")

    # --- Logical C host-value ABI ---
    if "L1_W1_LOGICAL_C_HOST_VALUE_ABI" not in s11 and "in-process logical C host values" not in s11:
        fail("chunk C-2: must state logical C host-value ABI")
    if "not** packed/serialized/radio wire bytes" not in s11 and "not packed/serialized/radio wire bytes" not in s11:
        fail("chunk C-2: event payload must not be packed/serialized/radio bytes")
    if "MUST NOT** `memcpy`" not in s11 and "MUST NOT memcpy" not in s11:
        if "MUST NOT** `memcpy` / hash / serialize" not in s11:
            fail("chunk C-2: MUST NOT memcpy/hash/serialize event struct as wire")
    if "little-endian" in s11:
        fail("chunk C-2: must delete STAMP integer fields little-endian wording")
    if "No C `enum` typed fields" not in s11 and "No C enum typed fields" not in s11:
        fail("chunk C-2: must forbid C enum fields in event payloads")

    # common envelope exact ordered fields
    env = _parse_marked_field_block(s11, "EVENT_COMMON_ENVELOPE_BEGIN", "EVENT_COMMON_ENVELOPE_END")
    env_exp = [
        ("event_schema", "u16", "exact 1"),
        ("event_kind", "u8", "exact 1..7 as table below"),
        ("owner_token", "u64", "nonzero scalar"),
        ("candidate_token", "u64", "nonzero scalar"),
    ]
    if env != env_exp:
        fail(f"chunk C-2: common envelope ordered mismatch got={env!r}")
    if env[0][1] != "u16":
        fail("chunk C-2: event_schema must be u16")
    if env[1][1] != "u8":
        fail("chunk C-2: event_kind must be u8")

    # --- BURN_CU ---
    b0 = s11.find("BURN_CU_W1_RESPONSE_CLOSED")
    if b0 < 0:
        fail("chunk C-2: BURN_CU_W1_RESPONSE_CLOSED marker missing")
    b1 = s11.find("**Next-state (exact closed fail split", b0)
    if b1 < 0:
        b1 = s11.find("##### 1.1.1.2", b0)
    burn = s11[b0:b1]
    burn_hdr = ("§9.3 class", "W1 response (immediate)", "L1/W1 next state (exact)")
    burn_rows = _parse_table_by_header(burn, burn_hdr)
    if len(burn_rows) != 4 or burn_rows[0][0] != "RETRY_LATER" or burn_rows[0][1] != "none":
        fail(f"chunk C-2: BURN_CU 4 rows missing got={burn_rows!r}")
    if burn_rows[1][1] != "none" or "ALL_PROPOSED" not in burn_rows[1][0]:
        fail("chunk C-2: ALL_PROPOSED must emit no immediate SEAL_FAIL")
    if "FIRST_FRAG_START_TEMPLATE" not in burn_rows[1][2]:
        fail("chunk C-2: ALL_PROPOSED must inject FIRST_FRAG_START_TEMPLATE proposed C")
    if burn_rows[2][1] != "none":
        fail("chunk C-2: ALL_OLD must emit none")
    if burn_rows[3][1] != "SEAL_FAIL exactly once":
        fail("chunk C-2: THIRD must SEAL_FAIL exactly once")
    if "AMBIGUOUS" not in burn_rows[3][2]:
        fail("chunk C-2: THIRD burn_state AMBIGUOUS required")
    if "while burn CU is open, **do not** emit SEAL_FAIL" not in s11:
        fail("chunk C-2: CU open must emit no SEAL_FAIL")
    if "Forbidden: any blanket rule that “classification後必ずSEAL_FAIL”." not in s11:
        fail("chunk C-2: must explicitly forbid always-SEAL_FAIL-after-classify")

    s157 = doc.find("##### 15.3.7.3 INTENT_BURN")
    s158 = doc.find("#### 15.3.8 Terminal PARTIAL")
    if s157 < 0 or s158 <= s157:
        fail("chunk C-2: §15.3.7.3 scope missing for BURN_CU cross-check")
    s7 = doc[s157:s158]
    if "BURN_CU_W1_RESPONSE_CLOSED" not in s7:
        fail("chunk C-2: §15.3.7.3 must cross-check BURN_CU_W1_RESPONSE_CLOSED")

    # --- HOP outer fail ---
    seal_sec = s11[s11.find("##### 1.1.1.1"): s11.find("##### 1.1.1.2")]
    for tok in (
        "HOP_OUTER_FAIL_SAME_GROUP_STRICT_TERMINAL",
        "SEAL_FAIL_NEXT_STATE_LAYER_SPLIT",
        "HOP_FAIL_TERMINAL_BY_GROUP_EXISTENCE",
        "Forbidden: inventing a LINK group for LOCAL_LINK_ACK pre-group fail.",
        "phase **1 or 5** ⇒ burn_state NONE",
        "Forbidden wording: “same already-emitted outer”.",
        "**no** another hop prep, **no** replacement outer, **no** same-group reuse of that failed outer attempt inside the failed group.",
    ):
        if tok not in seal_sec:
            fail(f"chunk C-2: HOP/SEAL next-state policy missing {tok!r}")
    # SEAL_FAIL burn_state u8
    seal_fields = _parse_marked_field_block(s11, "EVENT_SEAL_FAIL_FIELDS_BEGIN", "EVENT_SEAL_FAIL_FIELDS_END")
    seal_exp = [
        ("seal_layer", "u8", "1 E2E | 2 HOP"),
        ("seal_phase", "u8", "1..7 closed"),
        ("seal_cause", "u8", "1..8 closed"),
        ("burn_state", "u8", "0 NONE | 1 E2E | 2 HOP | 3 AMBIGUOUS"),
        ("counter_value_or_0", "u64", "0 if not a definite consumed counter; else burned counter 1..UINT64_MAX-1"),
        ("e2e_len_valid", "u8", "0|1"),
        ("expected_e2e_len", "u16", ""),
        ("observed_e2e_len", "u16", ""),
        ("outer_len_valid", "u8", "0|1"),
        ("expected_outer_len", "u16", ""),
        ("observed_outer_len", "u16", ""),
    ]
    if seal_fields != seal_exp:
        fail(f"chunk C-2: SEAL_FAIL fields exact ordered mismatch got={seal_fields!r}")
    bs = next((n, typ, c) for n, typ, c in seal_fields if n == "burn_state")
    if bs[1] != "u8":
        fail(f"chunk C-2: SEAL_FAIL burn_state must be u8 not enum; got {bs!r}")
    if "0 NONE | 1 E2E | 2 HOP | 3 AMBIGUOUS" not in bs[2]:
        fail(f"chunk C-2: SEAL_FAIL burn_state codes exact 0..3; got {bs[2]!r}")
    if any(n == "sealed_bytes" for n, _, _ in seal_fields):
        fail("chunk C-2: SEAL_FAIL must not carry sealed_bytes")

    s152 = doc.find("### 15.2 Hop / outer candidate")
    s153 = doc.find("### 15.3 Prepared candidate rules")
    if s152 < 0 or s153 <= s152:
        fail("chunk C-2: §15.2 scope missing")
    hop = doc[s152:s153]
    if "HOP_OUTER_FAIL_SAME_GROUP_STRICT_TERMINAL" not in hop:
        fail("chunk C-2: §15.2 must cross-check HOP_OUTER_FAIL_SAME_GROUP_STRICT_TERMINAL")
    if "fresh HOP DATA prep + fresh hop DATA counter + fresh outer" not in hop:
        fail("chunk C-2: §15.2 must allow LINK_ACK timeout fresh HOP DATA prep/counter/outer")
    path_hdr = ("path", "owner / group", "hop counter lane", "steps")
    path_rows = _parse_table_by_header(hop, path_hdr)
    if len(path_rows) != 2 or path_rows[0][2] != "DATA" or path_rows[1][2] != "ACK":
        fail(f"chunk C-2: §15.2 path lanes must be DATA then ACK; got {path_rows!r}")

    # --- LENGTH ---
    l0 = s11.find("##### 1.1.1.2 LENGTH_CLASS catalog")
    l1 = s11.find("##### 1.1.1.3 radio_volatile_work")
    leng = s11[l0:l1]
    if "E2E sealed blob domain (bytes)" not in leng or "final outer frame domain (bytes)" not in leng:
        fail("chunk C-2: LENGTH domain headers missing")
    length_class_enum = (
        "`0 UNCLASSIFIED` · `1 DATA_SINGLE` · `2 DATA_FRAG_START` · `3 DATA_FRAG_CONT` · "
        "`4 DATA_FRAG_ACK` · `5 LINK_ACK`"
    )
    if length_class_enum not in leng:
        fail("chunk C-2: length_class closed enum missing/altered (must use DATA_FRAG_* names)")
    if "**LINK_ACK** is **forbidden** on E2E check phases" not in leng:
        fail("chunk C-2: LINK_ACK forbidden on E2E phases")
    for tok in (
        "`observed_valid=0` **iff** the observed length is **unobtainable**",
        "`observed_valid=0` ⇒ `observed=0`",
        "`observed_valid=1` ⇒ `observed` is the **exact computed or measured byte length**",
        "`ARITHMETIC_OVERFLOW` ⇒ `observed_valid=0` and `observed=0` always",
    ):
        if tok not in leng:
            fail(f"chunk C-2: observed canon missing {tok!r}")

    # length event field block
    len_evt = _parse_marked_field_block(s11, "EVENT_LENGTH_CLASS_BEGIN", "EVENT_LENGTH_CLASS_END")
    len_exp = [
        ("common_envelope", "", ""),
        ("length_class", "u8", "0..5 closed §1.1.1.2"),
        ("check_phase", "u8", "1..4 closed"),
        ("expected_min", "u16", ""),
        ("expected_max", "u16", ""),
        ("observed", "u16", ""),
        ("observed_valid", "u8", "0|1"),
        ("burn_state", "u8", "0 NONE | 1 E2E | 2 HOP"),
        (
            "counter_value_or_0",
            "u64",
            "0 if burn_state=NONE; else exact burned layer/lane counter 1..UINT64_MAX-1",
        ),
        (
            "length_cause",
            "u8",
            "1 UNDER_MIN | 2 OVER_MAX | 3 EXACT_MISMATCH | 4 ARITHMETIC_OVERFLOW | 5 TYPE_UNCLASSIFIABLE",
        ),
    ]
    if len_evt != len_exp:
        fail(f"chunk C-2: LENGTH_CLASS event field block mismatch got={len_evt!r}")

    # radio_volatile_work
    vol_sec = s11[s11.find("##### 1.1.1.3"): s11.find("##### 1.1.1.4")]
    members = _parse_fenced_set_members(vol_sec, "radio_volatile_work")
    expected_members = [
        "candidate", "Permit snapshot", "LINK group", "prep", "timer row", "sealed blob",
        "outgoing SINGLE item", "forwarding queue item", "endpoint E2E ingress queue item",
        "upper-transport queue item", "fragment sender/reassembly state", "tombstone/reservation",
        "ACK coalesce/control reserve", "ACK intent/ledger",
    ]
    if members != expected_members:
        fail(f"chunk C-2: radio_volatile_work set inequality got={members!r} expected={expected_members!r}")
    if "RESPONSE_OBSERVED_PRIORITY" not in vol_sec and "response_observed=false" not in vol_sec:
        fail("chunk C-2: TEMP discard must honor response_observed priority")

    # SEAL allowed table
    if "OUTPUT_SHAPE` = NULL pointer / capacity / buffer shape only" not in seal_sec:
        fail("chunk C-2: OUTPUT_SHAPE duty missing")
    if "§9.3 CU outcome names (`RETRY_LATER`,`ALL_PROPOSED`,`ALL_OLD`,`THIRD`) are **not** seal_cause values." not in seal_sec:
        fail("chunk C-2: CU outcome names must not be seal_cause")
    if "both valid=1 forbidden" not in seal_sec:
        fail("chunk C-2: both e2e and outer valid=1 must be forbidden")
    if "may remain valid on both layers" in seal_sec and "Forbidden:" not in seal_sec[max(0, seal_sec.find("may remain valid on both layers")-40):]:
        fail("chunk C-2: SEAL_FAIL must not allow may remain valid on both layers")
    invent_forbid = "Forbidden: inventing a LINK group for LOCAL_LINK_ACK pre-group fail."
    if invent_forbid not in seal_sec:
        fail("chunk C-2: exact Forbidden inventing LINK group sentence missing in §1.1.1.1")
    for bad in (
        "Allowed: inventing a LINK group for LOCAL_LINK_ACK pre-group fail.",
        "MAY invent a LINK group for LOCAL_LINK_ACK",
    ):
        if bad in seal_sec:
            fail(f"chunk C-2: reverse polarity inventing LINK group: {bad!r}")
    if "seal_phase `2..4` ⇒ seal_layer **MUST** be `1 E2E`" not in seal_sec:
        fail("chunk C-2: seal_phase 2..4 ⇒ E2E binding missing/weakened")
    if "phase1 always E2E" in seal_sec:
        fail("chunk C-2: phase1 must not be blanket E2E")
    if "Forbidden: blanket “always hop DATA counter”." not in seal_sec:
        fail("chunk C-2: must forbid blanket hop DATA counter")
    if "0 means “no exact counter identity”** — **not** “durable mutation zero”" not in seal_sec:
        fail("chunk C-2: AMBIGUOUS value0 must not mean durable zero")
    if "`seal_layer=E2E` ⇒ `outer_len_valid=0` and `expected_outer_len=observed_outer_len=0`" not in seal_sec:
        fail("chunk C-2: seal_layer=E2E forces outer valid/values 0 missing")
    if "counter_value_or_0` **equals** the burned E2E counter" not in seal_sec:
        fail("chunk C-2: E2E_ENCODE/AEAD counter equality missing")

    # --- STAMP fields ---
    stamp_fields = _parse_marked_field_block(s11, "EVENT_STAMP_FIELDS_BEGIN", "EVENT_STAMP_FIELDS_END")
    stamp_expected = [
        ("common_envelope", "", ""),
        ("prep_layer", "u8", "1 E2E | 2 HOP"),
        ("owner_class", "u8", "1..5 closed below"),
        ("stamp_now_mono", "u64", "accepted R2 sample now_ms only"),
        ("enclosing_owner_deadline", "u64", ""),
        ("group_deadline_valid", "u8", "0|1"),
        ("group_absolute_deadline", "u64", "meaningful iff group_deadline_valid=1; else 0"),
        ("e2e_attempt_start_valid", "u8", "0|1"),
        ("e2e_attempt_start_mono", "u64", "meaningful iff e2e_attempt_start_valid=1; else 0"),
        ("requested_length_class", "u8", "1..5 closed; never 0"),
        ("seal_input_kind", "u8", "1 E2E_PLAINTEXT | 2 E2E_BLOB | 3 LINK_ACK_PLAINTEXT | 4 FIRST_FRAG_START_TEMPLATE"),
        ("seal_input_token", "u64", "L1-minted nonzero unique live borrow"),
        ("seal_input_len", "u16", "exact byte length of seal_input_bytes"),
        ("seal_input_bytes", "borrowed immutable const uint8_t*", "non-NULL; + seal_input_len"),
        ("seal_output_token", "u64", "L1-minted nonzero unique live output slot"),
        ("seal_output_capacity", "u16", "exact precomputed required sealed output length"),
        ("seal_output_bytes", "exclusive mutable borrowed uint8_t*", "non-NULL; capacity bytes"),
        ("seal_context_handle", "u64", "nonzero installed W1 OUTBOUND context handle; never a raw pointer"),
        ("outer_ack_requested", "u8", "0|1; HOP DATA only meaningful; else 0"),
        ("outer_hop_remaining", "u8", "HOP DATA only; else 0"),
        ("outer_route_handle", "u16", "HOP DATA only; else 0"),
        ("outer_route_generation", "u16", "HOP DATA only; else 0"),
    ]
    if stamp_fields != stamp_expected:
        fail(f"chunk C-2: STAMP_FIELDS exact ordered mismatch got={stamp_fields!r}")
    stamp_names = [n for n, _, _ in stamp_fields]
    if any("rogue" in n for n in stamp_names):
        fail("chunk C-2: STAMP_FIELDS rogue field present")
    for need in ("seal_output_token", "seal_output_capacity", "seal_output_bytes", "FIRST_FRAG_START_TEMPLATE"):
        if need == "FIRST_FRAG_START_TEMPLATE":
            if "4 FIRST_FRAG_START_TEMPLATE" not in stamp_fields[10][2]:
                fail("chunk C-2: seal_input_kind must include FIRST_FRAG_START_TEMPLATE")
        elif need not in stamp_names:
            fail(f"chunk C-2: STAMP missing {need}")
    if "STAMP_SEAL_OUTPUT_SLOT_ABI" not in s11 and "Caller-owned output slot" not in s11:
        fail("chunk C-2: STAMP_SEAL_OUTPUT_SLOT_ABI / caller-owned output slot missing")
    if "MUST NOT** overlap/alias" not in s11 and "MUST NOT overlap/alias" not in s11:
        fail("chunk C-2: input/output spans must not overlap/alias")
    if "never a raw pointer" not in s11:
        fail("chunk C-2: seal_context_handle never a raw pointer")
    abi_start = s11.find("**STAMP_SEAL_INPUT_ABI")
    abi_end = s11.find("**Stamp rules (exact):**", abi_start) if abi_start >= 0 else -1
    if abi_start < 0 or abi_end <= abi_start:
        fail("chunk C-2: STAMP_SEAL_INPUT_ABI scoped block missing")
    abi = s11[abi_start:abi_end]
    for tok in (
        "FIRST_FRAG_START_TEMPLATE",
        "octets **16..23 exact zero**",
        "exact 16 bytes",
        "MUST NOT** overwrite handle",
        "never a pointer",
        "Runtime slot",
    ):
        if tok not in abi and tok.replace("**", "") not in abi:
            # allow slight bold variance
            if tok.replace("**", "") not in abi.replace("**", ""):
                fail(f"chunk C-2: STAMP_SEAL_INPUT_ABI missing {tok!r}")
    borrow_exact = (
        "- W1 **immutable input borrow + exclusive mutable output borrow** lifetime = STAMP accept → that HOP/E2E prep pair’s **exactly one** "
        "W1 response; W1 **MUST NOT** retain/free/mutate/alias/re-emit bytes or tokens after response."
    )
    if borrow_exact not in abi:
        fail("chunk C-2: exact W1 immutable borrow lifetime + MUST NOT retain/free/mutate/alias/re-emit sentence missing in STAMP_SEAL_INPUT_ABI")
    for bad in (
        "W1 **MAY** retain bytes and token after response.",
        "W1 MAY retain bytes and token after response",
        "MAY retain bytes",
    ):
        if bad in abi:
            fail(f"chunk C-2: STAMP_SEAL_INPUT_ABI reverse polarity: {bad!r}")

    # matrix
    if "STAMP_OWNER_PREP_MATRIX_CLOSED" not in s11:
        fail("chunk C-2: STAMP_OWNER_PREP_MATRIX_CLOSED missing")
    mx_hdr = (
        "owner_class", "prep_layer", "group_deadline_valid",
        "seal_input_kind", "requested_length_class", "hop_counter_lane",
    )
    mx_scope = s11[s11.find("EVENT_STAMP_FIELDS_END"): s11.find("##### 1.1.1.5")]
    mx_rows = _parse_table_by_header(mx_scope, mx_hdr)
    mx_expected = (
        ("LOCAL_SINGLE", "E2E", "0", "E2E_PLAINTEXT", "1", "N/A"),
        ("LOCAL_SINGLE", "HOP", "1", "E2E_BLOB", "1", "DATA"),
        ("LOCAL_FRAGMENT", "E2E", "0", "FIRST_FRAG_START_TEMPLATE", "2", "N/A"),
        ("LOCAL_FRAGMENT", "E2E", "0", "E2E_PLAINTEXT", "2", "N/A"),
        ("LOCAL_FRAGMENT", "E2E", "0", "E2E_PLAINTEXT", "3", "N/A"),
        ("LOCAL_FRAGMENT", "HOP", "1", "E2E_BLOB", "2 or 3", "DATA"),
        ("RELAY_DATA", "HOP", "1", "E2E_BLOB", "1..4", "DATA"),
        ("LOCAL_FRAG_ACK", "E2E", "0", "E2E_PLAINTEXT", "4", "N/A"),
        ("LOCAL_FRAG_ACK", "HOP", "1", "E2E_BLOB", "4", "DATA"),
        ("LOCAL_LINK_ACK", "HOP", "0", "LINK_ACK_PLAINTEXT", "5", "ACK"),
    )
    if tuple(mx_rows) != mx_expected:
        fail(f"chunk C-2: STAMP owner×prep matrix mismatch got={mx_rows!r}")
    if "DATA owner→class5" not in s11:
        fail("chunk C-2: must explicitly reject DATA owner→class5")
    if "LOCAL_LINK_ACK→class1..4" not in s11:
        fail("chunk C-2: must explicitly reject LOCAL_LINK_ACK→class1..4")

    st_rules = s11[s11.find("**Stamp rules (exact):**"): s11.find("##### 1.1.1.5 FRAME_READY")]
    for tok in (
        "`stamp_now_mono` = accepted R2 `now_ms` only",
        "W1 **MUST NOT** carry epoch_id/watermark",
        "`e2e_attempt_start_valid=1` **iff** prep_layer=E2E",
        "distinct and non-reusable across layers",
    ):
        if tok not in st_rules:
            fail(f"chunk C-2: Stamp rule missing {tok!r}")
    if "`1 LOCAL_SINGLE` · `2 LOCAL_FRAGMENT` · `3 RELAY_DATA` · `4 LOCAL_FRAG_ACK` · `5 LOCAL_LINK_ACK`" not in s11:
        fail("chunk C-2: owner_class closed enum missing")

    # borrow-close
    if "STAMP_BORROW_CLOSE_HANDSHAKE" not in s11:
        fail("chunk C-2: STAMP_BORROW_CLOSE_HANDSHAKE missing")
    if "response_observed=true" not in s11:
        fail("chunk C-2: response_observed=true required before release")
    if "response_observed=false` is an explicit higher-priority exception" not in s11 and "RESPONSE_OBSERVED_PRIORITY" not in s11:
        fail("chunk C-2: response_observed=false higher-priority exception missing")
    if "MUST NOT** free borrowed inputs" not in s11 and "MUST NOT free borrowed inputs" not in s11:
        fail("chunk C-2: DRAIN must MUST NOT free borrowed inputs until response_observed")
    if "MAY free borrowed inputs" in s11:
        fail("chunk C-2: DRAIN must not allow early free of borrowed inputs")
    if "MUST NOT** emit `OWNER_TERMINAL` early" not in s11:
        fail("chunk C-2: DRAIN/cancel must not emit OWNER_TERMINAL early while response pending")
    if "Pending receives **E2E** `FRAME_READY`" not in s11 and "Pending receives **E2E**" not in s11:
        fail("chunk C-2: cancel/drain pending E2E FRAME_READY branch missing")
    if "Pending receives **OUTER** `FRAME_READY`" not in s11:
        fail("chunk C-2: cancel/drain pending OUTER FRAME_READY branch missing")
    pending_e2e = (
        "- Pending receives **E2E** `FRAME_READY`: **no** new LINK group / HOP; close E2E prep internally "
        "(`E2E_TRANSFERRED_CLOSED` not reopened); release output slot **exactly once** after response_observed; "
        "close upper owner per exact cancel/drain timing; **no** E2E-pair OWNER_TERMINAL/TX_RESULT."
    )
    if pending_e2e not in s11:
        fail("chunk C-2: exact pending E2E FRAME_READY cancel/drain branch missing (no group/leak)")
    if "create new LINK group and HOP" in s11 and "Pending receives **E2E**" in s11:
        # only fail if the bad wording is on the pending path
        bad_region = s11[s11.find("Cancel/drain while response pending"): s11.find("After `SEAL_FAIL` or `LENGTH_CLASS`")]
        if "create new LINK group and HOP" in bad_region:
            fail("chunk C-2: pending E2E FRAME_READY must not create LINK group")


    # --- FRAME_READY ---
    frame_fields = _parse_marked_field_block(s11, "EVENT_FRAME_READY_BEGIN", "EVENT_FRAME_READY_END")
    frame_expected = [
        ("common_envelope", "", ""),
        ("frame_layer", "u8", "1 E2E_BLOB | 2 OUTER_FRAME"),
        ("length_class", "u8", "1..5; never 0 UNCLASSIFIED"),
        ("burn_state", "u8", "1 E2E | 2 HOP"),
        ("counter_value", "u64", "exact domain 1..UINT64_MAX-1; reject 0 and UINT64_MAX"),
        ("seal_output_token", "u64", "same STAMP output token; L1 slot registry key"),
        ("sealed_len", "u16", "MUST equal STAMP seal_output_capacity"),
    ]
    if frame_fields != frame_expected:
        fail(f"chunk C-2: FRAME_READY exact ordered mismatch got={frame_fields!r}")
    if any(n == "sealed_bytes" for n, _, _ in frame_fields):
        fail("chunk C-2: FRAME_READY must not have sealed_bytes ownership field")
    fr_sec = s11[s11.find("##### 1.1.1.5"): s11.find("#### 1.1.2")]
    if "No `sealed_bytes` pointer" not in fr_sec and "No sealed_bytes pointer" not in fr_sec:
        fail("chunk C-2: FRAME_READY must forbid sealed_bytes pointer ownership transfer")
    if "W1→L1 exclusive ownership **exactly once**" not in fr_sec and "sole post-response access **exactly once**" not in fr_sec:
        fail("chunk C-2: FRAME_READY exclusive ownership exactly once required")
    if "MUST NOT** read/mutate/free/alias/re-emit" not in fr_sec:
        fail("chunk C-2: W1 must not retain sealed_bytes after FRAME_READY")
    if "no second FRAME_READY" not in fr_sec:
        fail("chunk C-2: mismatch must forbid second FRAME_READY")
    if "FRAME_READY_LAYER_BRANCH_CLOSED" not in fr_sec:
        fail("chunk C-2: FRAME_READY_LAYER_BRANCH_CLOSED missing")
    if "FRAME_STAMP_CROSS_PRODUCT_CLOSED" not in fr_sec:
        fail("chunk C-2: FRAME_STAMP_CROSS_PRODUCT_CLOSED missing")
    if "FRAME `length_class` **MUST equal** STAMP `requested_length_class`" not in fr_sec:
        fail("chunk C-2: FRAME length_class must equal STAMP requested_length_class")
    # FRAME↔STAMP token/capacity equality (section-scoped; positive + reverse polarity)
    fx_start = fr_sec.find("**STAMP→FRAME match (exact; FRAME_STAMP_CROSS_PRODUCT_CLOSED):**")
    fx_end = fr_sec.find("**Ownership + layer branch", fx_start) if fx_start >= 0 else -1
    if fx_start < 0 or fx_end <= fx_start:
        fail("chunk C-2: FRAME_STAMP_CROSS_PRODUCT scoped block missing in §1.1.1.5")
    fx = fr_sec[fx_start:fx_end]
    token_eq_exact = (
        "FRAME `seal_output_token` **MUST equal** STAMP `seal_output_token`; "
        "`sealed_len` **MUST equal** STAMP `seal_output_capacity`."
    )
    if token_eq_exact not in fx:
        fail(
            "chunk C-2: FRAME seal_output_token MUST equal STAMP token and "
            "sealed_len MUST equal STAMP seal_output_capacity (exact sentence missing in FRAME_STAMP cross-product)"
        )
    if "MUST equal** STAMP `seal_output_token`" not in fx or "MUST equal** STAMP `seal_output_capacity`" not in fx:
        fail("chunk C-2: FRAME token/capacity MUST-equal binding missing")
    for bad in (
        "FRAME seal_output_token MAY differ from STAMP",
        "FRAME `seal_output_token` MAY differ",
        "seal_output_token MAY differ from STAMP",
        "sealed_len MAY be smaller",
        "`sealed_len` MAY be smaller",
        "sealed_len may differ",
        "token MAY differ",
        "MAY differ from STAMP",
        "soft match on seal_output_token",
    ):
        if bad in fx or bad in fr_sec:
            fail(f"chunk C-2: FRAME token/capacity reverse polarity: {bad!r}")
    if "domain **1..UINT64_MAX-1** only" not in fr_sec:
        fail("chunk C-2: FRAME_READY counter domain 1..UINT64_MAX-1 missing")
    if "FRAME_READY_COUNTER_EMBEDDED_BINDING" not in fr_sec:
        fail("chunk C-2: FRAME_READY_COUNTER_EMBEDDED_BINDING missing")
    if "frame_layer=E2E_BLOB` ⇒ `counter_value` **MUST** be bit-exact equal to the `e2e_counter`" not in fr_sec:
        fail("chunk C-2: E2E_BLOB counter_value = embedded e2e_counter binding missing")
    if "length_class` ∈ 1..4 ⇒ `counter_value` **MUST** equal hop **DATA** lane" not in fr_sec:
        fail("chunk C-2: OUTER length_class 1..4 must bind DATA lane hop_counter")
    if "length_class=5` (`LINK_ACK`) / `owner_class=LOCAL_LINK_ACK` ⇒ `counter_value` **MUST** equal hop **ACK** lane" not in fr_sec:
        fail("chunk C-2: LINK_ACK OUTER must bind ACK lane counter")
    if "internal contract violation" not in fr_sec:
        fail("chunk C-2: FRAME_READY mismatch must be internal contract violation")
    if "Permit/issue/R1/TX_RESULT = **0**" not in fr_sec:
        fail("chunk C-2: FRAME_READY mismatch must force Permit/issue/R1/TX_RESULT = 0")
    if "may still issue Permit" in fr_sec:
        fail("chunk C-2: FRAME_READY mismatch must not allow Permit")
    if "MUST NOT** emit a corrective second FRAME_READY" not in fr_sec:
        fail("chunk C-2: must forbid corrective second FRAME_READY after mismatch")

    fl_hdr = ("frame_layer", "length_class", "burn_state (u8)", "domain")
    fl_rows = _parse_table_by_header(fr_sec, fl_hdr)
    if tuple(fl_rows) != FRAME_LAYER_BURN_EXPECTED:
        fail(
            f"chunk C-2: FRAME layer×class×burn exact ordered equality fail "
            f"got={fl_rows!r} expected={FRAME_LAYER_BURN_EXPECTED!r}"
        )

    # release table
    if "E2E_BLOB_RELEASE_TABLE" not in fr_sec:
        fail("chunk C-2: E2E_BLOB_RELEASE_TABLE missing")
    rel_hdr = ("event / state", "release L1-owned E2E sealed slot (seal_output_token)?")
    rel_rows = _parse_table_by_header(fr_sec, rel_hdr)
    # require key rows by substring match
    rel_join = "\n".join("|".join(r) for r in rel_rows)
    for need in (
        "E2E FRAME_READY",
        "pre-group fail",
        "ACK_REQUESTED=1",
        "ACK_REQUESTED=0",
        "TX_QUARANTINE",
        "cancel/drain pending received E2E FRAME_READY",
        "response never arrives",
        "SEAL_FAIL / LENGTH_CLASS after response_observed",
        "yes, exactly once",
    ):
        if need not in rel_join and need not in fr_sec:
            fail(f"chunk C-2: E2E_BLOB_RELEASE_TABLE missing row/content {need!r}")
    rel_first = [r[0] for r in rel_rows]
    for need_row in (
        "E2E FRAME_READY sole post-response access / E2E_TRANSFERRED_CLOSED",
        "cancel/drain pending received E2E FRAME_READY (no new LINK/HOP)",
        "LINK group admission / copy-own / deadline checked_add fail before admitted group (pre-group fail; no pending W1 borrow)",
        "TX_EDGE_DONE with ACK_REQUESTED=1 (pair closed; group WAIT_LINK_ACK)",
        "TX_EDGE_DONE with ACK_REQUESTED=0 until sibling/borrow cleanup complete",
        "individual OUTER prep terminal without group cleanup complete",
        "LINK_ACK timeout → fresh HOP DATA retry (same group, same blob)",
    ):
        if need_row not in rel_first:
            fail(f"chunk C-2: E2E_BLOB_RELEASE_TABLE missing exact row {need_row!r}; got={rel_first!r}")
    # polarity: early outer success must be no
    for r in rel_rows:
        if r[0].startswith("individual OUTER prep terminal") and r[1] != "no":
            fail(f"chunk C-2: individual OUTER prep terminal release must be no; got={r!r}")
        if "ACK_REQUESTED=1" in r[0] and r[1] != "no":
            fail(f"chunk C-2: ACK_REQUESTED=1 must not release blob; got={r!r}")
        if "timeout → fresh HOP DATA retry" in r[0] and r[1] != "no":
            fail(f"chunk C-2: timeout retry must not release blob; got={r!r}")
        if "pre-group fail" in r[0] and "yes, exactly once" not in r[1]:
            fail(f"chunk C-2: pre-group fail must release yes once; got={r!r}")
    if "requires response_observed=true before any yes" not in fr_sec:
        fail("chunk C-2: E2E_BLOB_RELEASE_TABLE must require response_observed=true")
    if "Forbidden: early release on OUTER success terminal alone" not in fr_sec:
        fail("chunk C-2: must forbid early release on OUTER success terminal alone")

    # lifecycle
    life_start = s11.find("**Per-prep-pair lifecycle")
    life_end = s11.find("| # | direction | event |", life_start)
    if life_start < 0 or life_end <= life_start:
        fail("chunk C-2: Per-prep-pair lifecycle scope missing")
    life = s11[life_start:life_end]
    e2e_br_start = life.find("**`E2E_BLOB`:**")
    e2e_br_end = life.find("**`OUTER_FRAME`:**", e2e_br_start)
    if e2e_br_start < 0 or e2e_br_end <= e2e_br_start:
        fail("chunk C-2: lifecycle E2E_BLOB branch missing between E2E_BLOB and OUTER_FRAME markers")
    e2e_br = life[e2e_br_start:e2e_br_end]
    transferred_exact = (
        "That prep pair transitions exactly once to internal state **`E2E_TRANSFERRED_CLOSED`** "
        "(leaves live prep-pair set / drain targets; **no** OWNER_TERMINAL/TX_RESULT event)."
    )
    if transferred_exact not in e2e_br:
        fail("chunk C-2: lifecycle E2E_BLOB branch must contain exact transitions exactly once → E2E_TRANSFERRED_CLOSED (leaves live prep-pair set/drain targets; no OWNER_TERMINAL/TX_RESULT event)")
    if "immutable handoff/borrow" not in e2e_br:
        fail("chunk C-2: lifecycle E2E_BLOB must state immutable handoff/borrow")
    if "Forbidden: routing `E2E_BLOB`" not in e2e_br and "Forbidden: routing `E2E_BLOB`" not in life:
        fail("chunk C-2: must forbid routing E2E_BLOB → Permit/R1/TX_RESULT")
    for bad in ("remains live", "may reopen E2E_TRANSFERRED_CLOSED"):
        if bad in e2e_br:
            fail(f"chunk C-2: lifecycle E2E_BLOB reverse polarity: {bad!r}")
    if "never both; never two terminals" not in life:
        fail("chunk C-2: OUTER lifecycle must state never both; never two terminals")
    outer_life_exact = (
        "OUTER output-slot lifetime (**OUTER_OUTPUT_SLOT_RELEASE_TABLE**): retain through issue/R1 as required "
        "(including same-Permit retry / drain uncertainty); after edge-invoked terminal R1 return + `TX_RESULT` dispatch "
        "release **exactly once**; **MUST NOT** retain old OUTER through ACK wait, fresh HOP retry, or group cleanup."
    )
    if outer_life_exact not in life and outer_life_exact not in s11:
        fail("chunk C-2: exact OUTER output-slot lifetime lifecycle wording missing")
    # Sentence-by-sentence OUTER retain/hold/keep polarity (case/markdown-normalized).
    # Reject a sentence that co-contains (any order): OUTER + retain|hold|keep family +
    # ACK wait|fresh HOP(+retry)|group cleanup. Same-sentence MUST NOT/Forbidden is allowed.
    # A MUST NOT in a different sentence does NOT exempt a positive sentence.
    life_outer = life[life.find("**`OUTER_FRAME`:**"):] if "**`OUTER_FRAME`:**" in life else life
    _outer_re = re.compile(r"\bouter\b", re.I)
    _verb_re = re.compile(
        r"\b(retain|retains|retained|retaining|hold|holds|held|holding|"
        r"keep|keeps|kept|keeping)\b",
        re.I,
    )
    _tgt_re = re.compile(
        r"\b(ack\s+wait|fresh\s+hop(?:\s+retry)?|group\s+cleanup)\b",
        re.I,
    )
    _neg_re = re.compile(r"\b(must\s+not|forbidden)\b", re.I)
    # Protect dotted section numbers (e.g. §1.1.2) so they are not sentence splits.
    _prot = re.sub(
        r"(§?\d+(?:\.\d+)+)",
        lambda m: m.group(0).replace(".", "\uE000"),
        life_outer,
    )
    for _raw_sent in re.split(r"(?<=[.!?])(?:\s+|$)", _prot):
        if not _raw_sent.strip():
            continue
        _sent = _raw_sent.replace("\uE000", ".")
        _sent = re.sub(r"[*`_]+", "", _sent)
        _sent = re.sub(r"\s+", " ", _sent).strip()
        if not _sent:
            continue
        if not (_outer_re.search(_sent) and _verb_re.search(_sent) and _tgt_re.search(_sent)):
            continue
        if _neg_re.search(_sent):
            continue
        fail(
            "chunk C-2: positive OUTER retain/hold/keep + ACK wait/fresh HOP/"
            f"group cleanup in same lifecycle sentence: {_sent!r}"
        )
    if "OUTER retains output slot through issue/R1/group cleanup" in s11:
        fail("chunk C-2: obsolete OUTER retains through group cleanup lifecycle line")

    if "hold sealed candidate + Permit after FRAME_READY" in s11_full:
        fail("chunk C-2: blanket hold sealed candidate + Permit after FRAME_READY forbidden")
    if "without** Permit" not in s11_full and "without Permit" not in s11_full:
        fail("chunk C-2: L1 ownership must state E2E_BLOB without Permit")
    if "only after** successful issue hold Permit" not in s11_full:
        fail("chunk C-2: L1 ownership must state OUTER_FRAME Permit only after issue")

    # DRAIN / OWNER
    drain_fields = _parse_marked_field_block(s11, "EVENT_DRAIN_QUARANTINE_BEGIN", "EVENT_DRAIN_QUARANTINE_END")
    if drain_fields != [
        ("common_envelope", "", ""),
        ("drain_disposition", "u8", "1 QUARANTINED exact"),
        ("drain_reason", "u8", "1 AMBIGUOUS_OR_FENCE | 2 OPERATOR | 3 RECOVERY"),
    ]:
        fail(f"chunk C-2: DRAIN_QUARANTINE field block mismatch got={drain_fields!r}")
    own_fields = _parse_marked_field_block(s11, "EVENT_OWNER_TERMINAL_BEGIN", "EVENT_OWNER_TERMINAL_END")
    if own_fields != [
        ("common_envelope", "", ""),
        ("terminal_kind", "u8", "1 TERMINAL | 2 STALE_NO_RETRY"),
    ]:
        fail(f"chunk C-2: OWNER_TERMINAL field block mismatch got={own_fields!r}")


    # --- LENGTH check_phase exact table ---
    leng = s11[s11.find("##### 1.1.1.2 LENGTH_CLASS catalog"): s11.find("##### 1.1.1.3 radio_volatile_work")]
    ph_hdr = ("check_phase", "allowed length_class", "checked length formula", "burn_state", "disposition")
    ph_rows = _parse_table_by_header(leng, ph_hdr)
    ph_exp = (
        ("E2E_PRE_BURN_COMPUTE", "1..4 or UNCLASSIFIED(0)", "14+PT+16", "NONE", "current prep-pair terminal; no counter issue; no same candidate retry"),
        ("E2E_POST_SEAL", "1..4 actual E2E sealed blob", "actual sealed blob len", "E2E", "current prep-pair terminal; FRAG only may open fresh bounded E2E prep; SINGLE terminal"),
        ("OUTER_PRE_BURN_COMPUTE", "1..5 or UNCLASSIFIED(0)", "19+HopPT+16", "NONE", "if admitted LINK group: group terminal + no replacement outer; if LOCAL_LINK_ACK pre-group: prep-pair + ACK owner terminal (no group)"),
        ("OUTER_POST_SEAL", "1..5 actual final outer", "actual final outer len", "HOP", "if admitted LINK group: group terminal + no replacement outer; if LOCAL_LINK_ACK pre-group: prep-pair + ACK owner terminal (no group)"),
    )
    if tuple(ph_rows) != ph_exp:
        fail(f"chunk C-2: LENGTH check_phase table mismatch got={ph_rows!r}")

    # --- SEAL allowed phase×cause exact ---
    seal_sec = s11[s11.find("##### 1.1.1.1"): s11.find("##### 1.1.1.2")]
    al_hdr = ("seal_phase", "allowed seal_cause (exact set)")
    al_rows = _parse_table_by_header(seal_sec, al_hdr)
    al_exp = (
        ("PRE_BURN_VALIDATE", "STRUCT_INVALID, CONTEXT_UNAVAILABLE, OUTPUT_SHAPE, ALIAS_OR_INTERNAL_CONTRACT"),
        ("E2E_COUNTER_BURN", "COUNTER_DEFINITE_FAILURE, COUNTER_CORRUPT"),
        ("E2E_ENCODE", "ENCODE_FAILURE, OUTPUT_SHAPE, ALIAS_OR_INTERNAL_CONTRACT"),
        ("E2E_AEAD", "AEAD_FAILURE, OUTPUT_SHAPE, ALIAS_OR_INTERNAL_CONTRACT"),
        ("HOP_COUNTER_BURN", "COUNTER_DEFINITE_FAILURE, COUNTER_CORRUPT"),
        ("HOP_ENCODE", "ENCODE_FAILURE, OUTPUT_SHAPE, ALIAS_OR_INTERNAL_CONTRACT"),
        ("HOP_AEAD", "AEAD_FAILURE, OUTPUT_SHAPE, ALIAS_OR_INTERNAL_CONTRACT"),
    )
    if tuple(al_rows) != al_exp:
        fail(f"chunk C-2: SEAL_FAIL allowed phase×cause mismatch got={al_rows!r}")
    if "Forbidden: any “may remain valid on both layers” exception." not in seal_sec:
        fail("chunk C-2: SEAL_FAIL must not allow e2e may remain valid on HOP")
    if "fresh hop DATA counter" not in seal_sec:
        fail("chunk C-2: HOP/SEAL next-state policy missing 'fresh hop DATA counter'")
    if "branch by `frame_layer`" not in s11:
        fail("chunk C-2: lifecycle must branch FRAME_READY by frame_layer")



    # --- OUTER_OUTPUT_SLOT_RELEASE_TABLE ---
    if "OUTER_OUTPUT_SLOT_RELEASE_TABLE" not in fr_sec and "OUTER_OUTPUT_SLOT_RELEASE_TABLE" not in s11:
        fail("chunk C-2: OUTER_OUTPUT_SLOT_RELEASE_TABLE missing")
    outer_sec = s11[s11.find("OUTER_OUTPUT_SLOT_RELEASE_TABLE"): s11.find("##### 1.1.1.6")]
    if "OUTER_OUTPUT_SLOT_RELEASE_TABLE" not in outer_sec:
        fail("chunk C-2: OUTER_OUTPUT_SLOT_RELEASE_TABLE scoped block missing")
    o_hdr = ("event / state", "release L1-owned OUTER sealed slot?")
    o_rows = _parse_table_by_header(outer_sec, o_hdr)
    o_first = [r[0] for r in o_rows]
    for need in (
        "STAMP accepted / W1 response pending",
        "OUTER FRAME_READY normal success",
        "PRE_R1 RETRYABLE_UNISSUED",
        "PRE_R1 TERMINAL_UNISSUED",
        "TX_RETRY_SAME_PERMIT",
        "TX_QUARANTINE",
        "TX_EDGE_DONE (ACK0 or ACK1)",
        "TX_STALE_NO_RETRY / EDGE_ERROR after edge",
        "SEAL_FAIL / LENGTH_CLASS / FRAME mismatch after response_observed",
    ):
        if not any(need in x for x in o_first):
            fail(f"chunk C-2: OUTER_OUTPUT_SLOT_RELEASE_TABLE missing row {need!r}; got={o_first!r}")
    for r in o_rows:
        if "TX_RETRY_SAME_PERMIT" in r[0] and r[1] != "no — retain same exact outer slot" and not r[1].startswith("no"):
            fail(f"chunk C-2: TX_RETRY must retain OUTER slot got={r!r}")
        if "TX_EDGE_DONE" in r[0] and "yes, exactly once" not in r[1]:
            fail(f"chunk C-2: TX_EDGE_DONE must release OUTER once got={r!r}")
        if "TX_EDGE_DONE" in r[0] and "retain OUTER through ACK" in r[1]:
            fail(f"chunk C-2: TX_EDGE_DONE must not retain OUTER through ACK wait got={r!r}")
        # TX_QUARANTINE OUTER: no until drain/proof (reject early yes/before proof)
        if r[0].strip() == "TX_QUARANTINE" or r[0].startswith("TX_QUARANTINE"):
            if not (
                r[1].startswith("no")
                and ("drain/proof" in r[1] or "drain" in r[1])
            ):
                fail(
                    f"chunk C-2: OUTER TX_QUARANTINE must be no-until-drain/proof; got={r!r}"
                )
            if re.search(r"\byes\b.*before", r[1], re.I) or "yes before proof" in r[1]:
                fail(f"chunk C-2: OUTER TX_QUARANTINE must not release before proof; got={r!r}")
            if r[1].startswith("yes"):
                fail(f"chunk C-2: OUTER TX_QUARANTINE first cell must not be yes-before-proof; got={r!r}")
    tq_outer = [r for r in o_rows if r[0].startswith("TX_QUARANTINE")]
    if not tq_outer:
        fail("chunk C-2: OUTER_OUTPUT_SLOT_RELEASE_TABLE missing TX_QUARANTINE row")
    if "ACK1 **MUST NOT** retain old OUTER" not in outer_sec and "MUST NOT** retain old OUTER" not in outer_sec:
        if "MUST NOT retain old OUTER" not in outer_sec and "MUST NOT retain old OUTER" not in s11:
            fail("chunk C-2: ACK1 must not retain old OUTER (exact wording missing in OUTER_OUTPUT_SLOT_RELEASE_TABLE)")
    if "Retain outer slot through issue/R1/group cleanup" in s11:
        fail("chunk C-2: obsolete OUTER retain through group cleanup wording")

    # FIRST_FRAG handle latch (section-scoped §1.1.1.8)
    latch_scope = s11[
        s11.find("**FIRST_FRAG_HANDLE_LATCH_RESPONSE_CLOSED")
        if s11.find("**FIRST_FRAG_HANDLE_LATCH_RESPONSE_CLOSED") >= 0
        else s11.find("FIRST_FRAG_HANDLE_LATCH_RESPONSE_CLOSED")
    : s11.find("#### 1.1.2 TX_RESULT")
    ]
    if "FIRST_FRAG_HANDLE_LATCH_RESPONSE_CLOSED" not in latch_scope and "FIRST_FRAG_HANDLE_LATCH_RESPONSE_CLOSED" not in s11:
        fail("chunk C-2: FIRST_FRAG_HANDLE_LATCH_RESPONSE_CLOSED missing")
    if "latches `original transfer_handle` **exactly once**" not in s11 and "latches original transfer_handle exactly once" not in s11:
        if "latches" not in s11 or "transfer_handle" not in s11:
            fail("chunk C-2: first START must latch transfer_handle exactly once from response counter")
    # exact Forbidden (not mere phrase presence — Allowed: must fail)
    if "**Forbidden:** parse a failed/mismatched output slot to recover handle." not in latch_scope and (
        "**Forbidden:** parse a failed/mismatched output slot to recover handle." not in s11
    ):
        fail("chunk C-2: must Forbidden parse failed/mismatched output slot for handle recovery")
    if "Allowed: parse a failed/mismatched output slot" in s11 or "Allowed:** parse a failed/mismatched" in s11:
        fail("chunk C-2: must not allow parse of failed/mismatched output slot for handle")
    if "fresh counters **MUST NOT** overwrite it" not in latch_scope and "fresh counters **MUST NOT** overwrite it" not in s11:
        if "MUST NOT** overwrite it" not in latch_scope and "MUST NOT** overwrite it" not in s11:
            fail("chunk C-2: fresh counters MUST NOT overwrite original transfer_handle")
    for bad in (
        "fresh counters may overwrite",
        "fresh counters **MAY** overwrite",
        "may overwrite it",
        "MAY overwrite original transfer_handle",
        "may overwrite original",
    ):
        if bad in latch_scope or bad in s11[
            max(0, s11.find("FIRST_FRAG_HANDLE_LATCH")) : s11.find("#### 1.1.2")
        ]:
            fail(f"chunk C-2: transfer_handle overwrite reverse polarity: {bad!r}")
    if "CU AMBIGUOUS **cannot** invent a handle" not in s11 and "cannot** invent a handle" not in s11:
        fail("chunk C-2: CU AMBIGUOUS must not invent handle")

    # LENGTH counter rules (§1.1.1.8 scoped)
    len_rules = s11[
        s11.find("##### 1.1.1.8 LENGTH_CLASS")
        if s11.find("##### 1.1.1.8 LENGTH_CLASS") >= 0
        else s11.find("**LENGTH counter rules")
    : s11.find("#### 1.1.2 TX_RESULT")
    ]
    if "`burn_state=0 NONE` ⇒ `counter_value_or_0=0`" not in len_rules and (
        "`burn_state=0 NONE` ⇒ `counter_value_or_0=0`." not in s11
    ):
        fail("chunk C-2: LENGTH NONE must force counter_value_or_0=0")
    if "may be nonzero" in len_rules and "NONE" in len_rules:
        fail("chunk C-2: LENGTH NONE counter must not allow nonzero")
    if re.search(r"burn_state=0 NONE[^\n]*may be nonzero|NONE[^\n]*counter[^\n]*may be nonzero", len_rules):
        fail("chunk C-2: LENGTH NONE reverse polarity nonzero counter")
    if "∈ **1..UINT64_MAX-1**" not in len_rules and "∈ 1..UINT64_MAX-1" not in len_rules:
        if "1..UINT64_MAX-1" not in len_rules:
            fail("chunk C-2: LENGTH E2E/HOP counter domain 1..UINT64_MAX-1 missing")
    if re.search(r"may be 0 or MAX|may be 0 or UINT64_MAX|0 or MAX", len_rules):
        fail("chunk C-2: LENGTH E2E/HOP counter must not allow 0 or MAX")
    if "exact burned layer/lane counter ∈ **1..UINT64_MAX-1**" not in len_rules and (
        "exact burned layer/lane counter ∈ **1..UINT64_MAX-1**" not in s11
    ):
        if "exact burned layer/lane counter" not in len_rules:
            fail("chunk C-2: LENGTH E2E/HOP must require exact burned counter 1..UINT64_MAX-1")

    # P1-5 definite counter failure — §1.1.1 + scoped §15.1
    if "SEAL_FAIL_E2E_DEFINITE_VS_POSTBURN_SPLIT" not in s11:
        fail("chunk C-2: SEAL_FAIL_E2E_DEFINITE_VS_POSTBURN_SPLIT missing")
    if "Definite counter-allocation failure before durable burn" not in s11 and "definite allocation fail" not in s11:
        fail("chunk C-2: definite E2E counter failure terminal rule missing")
    preburn_term = (
        "terminally fails the owning fragmented transfer or SINGLE; **no** fresh prep, **no** retry"
    )
    if preburn_term not in seal_sec and preburn_term not in s11:
        fail("chunk C-2: pre-burn definite fail must terminal FRAG and SINGLE with no retry")
    if "**Pre-burn / definite allocation fail**: FRAG may open next bounded fresh E2E prep" in s11:
        fail("chunk C-2: must not reintroduce FRAG retry for pre-burn definite counter failure")
    if "Post-burn only" not in seal_sec and "Post-burn only" not in s11:
        fail("chunk C-2: post-burn-only FRAG retry branch missing")
    s151 = doc.find("### 15.1 Fresh E2E attempt")
    s152 = doc.find("### 15.2 Hop / outer candidate", s151) if s151 >= 0 else -1
    if s151 < 0 or s152 <= s151:
        fail("chunk C-2: §15.1 scope missing for definite counter failure")
    sec151 = doc[s151:s152]
    def_ctr_151 = (
        "**Definite counter-allocation failure before durable burn** (phase `E2E_COUNTER_BURN` / pre-write fail): "
        "terminally fails the owning fragmented transfer or SINGLE; **no** fresh prep, **no** retry; "
        "handle remains **unset**; burn count/counter mutation **0**"
    )
    if def_ctr_151 not in sec151:
        fail("chunk C-2: §15.1 exact definite counter-allocation failure terminal sentence missing")
    if "FRAG may open next bounded fresh E2E prep" in sec151 and "Post-burn" not in sec151:
        fail("chunk C-2: §15.1 must not allow FRAG retry on definite pre-burn counter failure")

    # resource 128/32640
    if "L1 Seal output slot registry" not in doc:
        fail("chunk C-2: L1 Seal output slot registry resource row missing")
    if "**128** live slots max" not in doc and "128 live slots max" not in doc:
        fail("chunk C-2: seal output slots max 128 missing")
    if "32640" not in doc:
        fail("chunk C-2: aggregate capacity ≤32640 missing")
    if "1..255" not in doc:
        fail("chunk C-2: per-slot capacity 1..255 missing")


    # --- PRE_R1 11 + TX_RESULT ---
    i12 = s11.find("#### 1.1.2 TX_RESULT")
    i12e = s11.find("**R7 blocker:**", i12) if i12 >= 0 else -1
    if i12 < 0:
        fail("chunk C-2: §1.1.2 TX_RESULT heading missing")
    if i12e < 0:
        i12e = len(s11)
    tx_scope = s11[i12:i12e]
    if "PRE_R1_ISSUE_NEXT_ACTION" not in tx_scope:
        fail("chunk C-2: PRE_R1_ISSUE_NEXT_ACTION missing in §1.1.2")
    pre_hdr = ("L1 result class (§15.3.2 exact token)", "legal phase", "event of the 7", "L1 next (exact)")
    pre_rows = _parse_table_by_header(tx_scope, pre_hdr)
    if len(pre_rows) != 11:
        fail(f"chunk C-2: PRE_R1 must have exactly 11 rows got={len(pre_rows)} {pre_rows!r}")
    pre_classes = [r[0] for r in pre_rows]
    expected_11 = [
        "OK_ISSUED", "RETRYABLE_UNISSUED", "TERMINAL_UNISSUED", "CLOCK_PATH_DROP",
        "RECONCILE_REQUIRED", "AUTHORITY_DIVERGENCE", "EPOCH_TRANSITION_REQUIRED",
        "EPOCH_W1_REPAIR", "FIFO_OUT_OF_ORDER", "OPERATOR_RECOVERY_REQUIRED", "RETRYABLE_PIPELINE",
    ]
    if pre_classes != expected_11:
        fail(f"chunk C-2: PRE_R1 class set mismatch got={pre_classes!r}")
    if pre_rows[0][2] != "none" or "enter R1" not in pre_rows[0][3]:
        fail("chunk C-2: OK_ISSUED must emit none and enter R1")
    if pre_rows[1][2] != "none" or "issue only" not in pre_rows[1][3]:
        fail("chunk C-2: RETRYABLE_UNISSUED must emit none / issue only")
    if "OWNER_TERMINAL" not in pre_rows[2][2]:
        fail("chunk C-2: TERMINAL_UNISSUED must OWNER_TERMINAL")
    if "R1-only" not in pre_rows[8][1] or "R1-only" not in pre_rows[10][1]:
        fail("chunk C-2: FIFO_OUT_OF_ORDER and RETRYABLE_PIPELINE must be R1-only")
    if "…" in tx_scope[tx_scope.find("PRE_R1"):tx_scope.find("TX_RESULT exact")] or "ellipsis" in tx_scope.lower():
        # allow only if not in table - check table cells
        if any("…" in c or "..." in c or "etc" in c.lower() for r in pre_rows for c in r):
            fail("chunk C-2: PRE_R1 must not use ellipsis/catchall rows")
    if "TX_RESULT is forbidden" not in tx_scope:
        fail("chunk C-2: pre-R1 paths must forbid TX_RESULT")
    if "separate diagnostic objects" not in tx_scope:
        fail("chunk C-2: R2_PCP diagnostics must be separate from TX_RESULT event")

    tx_heading = "**TX_RESULT exact form = common envelope (§1.1.1) + TX_RESULT-specific fields only"
    if tx_heading not in tx_scope:
        fail("chunk C-2: §1.1.2 must have exact heading 'TX_RESULT exact form = common envelope (§1.1.1) + TX_RESULT-specific fields only'")
    if "common_envelope,      /* event_schema=1" not in tx_scope:
        fail("chunk C-2: TX_RESULT code block must list common_envelope with event_schema/event_kind/tokens")
    tx_fields = _parse_marked_field_block(tx_scope, "EVENT_TX_RESULT_BEGIN", "EVENT_TX_RESULT_END")
    tx_names = [n.rstrip(",") for n, _, _ in tx_fields]
    for need in (
        "common_envelope", "final_tx_outcome", "disposition", "consume_invoked", "edge_invoked",
        "permit_sequence", "retry_eligible", "retry_not_before_ms", "result_catalog",
        "exact_status", "stage", "reason",
    ):
        if need not in tx_names:
            fail(f"chunk C-2: TX_RESULT missing field {need}; got={tx_fields!r}")
    if "result_class" in tx_names:
        fail("chunk C-2: TX_RESULT must not keep redundant result_class field")
    by_name = {n.rstrip(","): (typ, cons) for n, typ, cons in tx_fields}
    for u8f in ("final_tx_outcome", "disposition", "consume_invoked", "edge_invoked", "retry_eligible", "result_catalog"):
        if by_name.get(u8f, ("", ""))[0] != "u8":
            fail(f"chunk C-2: {u8f} must be u8")
    for u64f in ("permit_sequence", "retry_not_before_ms"):
        if by_name.get(u64f, ("", ""))[0] != "u64":
            fail(f"chunk C-2: {u64f} must be u64")
    for u32f in ("exact_status", "stage", "reason"):
        if by_name.get(u32f, ("", ""))[0] != "u32":
            fail(f"chunk C-2: {u32f} must be u32")
    if "R1_HAL only" not in tx_scope:
        fail("chunk C-2: TX_RESULT result_catalog must be R1_HAL only")
    if "R2_PCP` and `NONE` are not permitted" not in tx_scope:
        fail("chunk C-2: TX_RESULT must forbid R2_PCP/NONE in event payload")
    if "REQUIRED closed: R1_HAL | R2_PCP | NONE" in tx_scope:
        fail("chunk C-2: TX_RESULT must not re-open R2_PCP|NONE catalog")
    if "MAY emit TX_RESULT with result_catalog=NONE" in tx_scope:
        fail("chunk C-2: seal-fail must not emit TX_RESULT NONE")
    # final_tx_outcome closed live set-equality (exact ordered codes 1..4; no extra/dead)
    fto_hdr = "**final_tx_outcome (closed u8 live set; dead codes abolished):**"
    fto_i = tx_scope.find(fto_hdr)
    if fto_i < 0:
        fail("chunk C-2: final_tx_outcome closed live set heading missing")
    fto_line = ""
    for ln in tx_scope[fto_i + len(fto_hdr) :].splitlines():
        s = ln.strip()
        if not s:
            continue
        if s.startswith("**") or s.startswith("Abolished"):
            break
        if "`" in s and "TX_" in s:
            fto_line = s
            break
    if not fto_line:
        fail("chunk C-2: final_tx_outcome live catalog line missing")
    fto_members = re.findall(r"`(\d+)\s+([A-Z0-9_]+)`", fto_line)
    fto_expected = [
        ("1", "TX_EDGE_DONE"),
        ("2", "TX_RETRY_SAME_PERMIT"),
        ("3", "TX_QUARANTINE"),
        ("4", "TX_STALE_NO_RETRY"),
    ]
    if fto_members != fto_expected:
        fail(
            f"chunk C-2: final_tx_outcome closed set-equality fail "
            f"got={fto_members!r} expected exactly 4 ordered {fto_expected!r}"
        )
    if len(fto_members) != 4:
        fail(f"chunk C-2: final_tx_outcome must have exactly 4 live codes; got {len(fto_members)}")
    if any(name == "TX_DROP_VOLATILE" for _, name in fto_members):
        fail("chunk C-2: TX_DROP_VOLATILE must not be live final_tx_outcome code")
    if any(int(n) > 4 for n, _ in fto_members):
        fail(f"chunk C-2: final_tx_outcome must not have codes >4; got={fto_members!r}")
    # disposition closed live set-equality (exact ordered codes 1..3)
    disp_hdr = "**disposition (closed u8 live set):**"
    disp_i = tx_scope.find(disp_hdr)
    if disp_i < 0:
        fail("chunk C-2: disposition closed live set heading missing")
    disp_line = ""
    for ln in tx_scope[disp_i + len(disp_hdr) :].splitlines():
        s = ln.strip()
        if not s:
            continue
        if s.startswith("**") or s.startswith("Abolished"):
            break
        if "`" in s:
            disp_line = s
            break
    if not disp_line:
        fail("chunk C-2: disposition live catalog line missing")
    disp_members = re.findall(r"`(\d+)\s+([A-Z0-9_]+)`", disp_line)
    disp_expected = [
        ("1", "RETAIN_SEALED"),
        ("2", "QUARANTINE"),
        ("3", "STALE_NO_RETRY"),
    ]
    if disp_members != disp_expected:
        fail(
            f"chunk C-2: disposition closed set-equality fail "
            f"got={disp_members!r} expected exactly 3 ordered {disp_expected!r}"
        )
    if any(name in ("DROP_SEALED", "TERMINAL", "TX_DROP_VOLATILE") for _, name in disp_members):
        fail(f"chunk C-2: disposition live set contains dead code; got={disp_members!r}")
    if "local TX_TERMINAL" not in tx_scope and "never local TX_TERMINAL" not in tx_scope and "MUST NOT** local TX_TERMINAL" not in tx_scope:
        if "MUST NOT** local TX_TERMINAL/release" not in tx_scope and "never local terminal release" not in tx_scope:
            fail("chunk C-2: after OK_ISSUED edge=0 non-retry must forbid local TX_TERMINAL release")
    # P1 issued-existence: exact After OK_ISSUED sentence (scoped §1.1.2)
    ok_issued_exact = (
        "After **OK_ISSUED**, every non-OPEN-retry edge=0 R1 result **MUST** enter `TX_QUARANTINE`/DRAIN (issued existence)."
    )
    if ok_issued_exact not in tx_scope:
        fail(
            "chunk C-2: exact After OK_ISSUED non-retry edge=0 MUST enter TX_QUARANTINE/DRAIN sentence missing in §1.1.2"
        )
    for bad in (
        "local release allowed",
        "MAY local release",
        "may local release",
        "local release without drain",
        "non-retry edge=0 R1 result **MAY** local release",
        "non-retry edge=0 R1 result may enter local release",
        "MUST enter local release",
    ):
        if bad in tx_scope:
            fail(f"chunk C-2: After OK_ISSUED reverse polarity local release: {bad!r}")

    # TX_RESULT fields: permit_sequence (not or_0)
    if "permit_sequence_or_0" in [n for n, _, _ in tx_fields]:
        fail("chunk C-2: permit_sequence_or_0 abolished; use permit_sequence")
    if "permit_sequence" not in tx_names:
        fail("chunk C-2: TX_RESULT missing permit_sequence")
    ps_cons = by_name.get("permit_sequence", ("", ""))[1]
    # exact domain 1..UINT64_MAX-1 (reject 0.. domain) — field + normative prose
    if "1..UINT64_MAX-1" not in ps_cons:
        fail("chunk C-2: permit_sequence field domain must be 1..UINT64_MAX-1")
    if "**permit_sequence (exact):** domain **1..UINT64_MAX-1**." not in tx_scope and (
        "permit_sequence (exact):** domain **1..UINT64_MAX-1**" not in tx_scope
    ):
        if "domain **1..UINT64_MAX-1**" not in tx_scope:
            fail("chunk C-2: permit_sequence exact prose domain **1..UINT64_MAX-1** missing")
    if re.search(r"domain\s+\*\*0\.\.UINT64_MAX-1\*\*", tx_scope) or "domain 0..UINT64_MAX-1" in tx_scope:
        fail("chunk C-2: permit_sequence domain must not be 0..UINT64_MAX-1")
    if "0..UINT64_MAX-1" in ps_cons:
        fail("chunk C-2: permit_sequence field domain must not start at 0")
    permit_eq_exact = (
        "Every valid TX_RESULT is after OK_ISSUED and **MUST** bit-exact equal the bound issued Permit sequence "
        "for this owner/candidate."
    )
    if permit_eq_exact not in tx_scope:
        fail("chunk C-2: permit_sequence MUST bit-exact equal bound issued Permit (exact sentence missing)")
    ps_block = tx_scope[
        tx_scope.find("**permit_sequence (exact):**")
        if "**permit_sequence (exact):**" in tx_scope
        else 0 : (
            tx_scope.find("**final_tx_outcome")
            if "**final_tx_outcome" in tx_scope
            else len(tx_scope)
        )
    ]
    for bad in (
        "may differ from the bound issued Permit",
        "MAY differ from the bound",
        "may differ from bound Permit",
        "may differ",
        "MAY differ",
    ):
        if bad in ps_block:
            fail(f"chunk C-2: permit_sequence reverse polarity: {bad!r}")
    if "normally nonzero" in tx_scope:
        fail("chunk C-2: permit_sequence must not use normally nonzero wording")
    if re.search(r"permit_sequence.*=\s*0 only when no bound", tx_scope) or "no bound Permit" in tx_scope:
        fail("chunk C-2: permit_sequence must not allow no-bound 0")
    if "consume_invoked=1` **iff** R1 entered the consume callback" not in tx_scope:
        fail("chunk C-2: consume_invoked must mean consume callback entry")
    if "edge_invoked=1` **iff** R1 entered the edge callback" not in tx_scope:
        fail("chunk C-2: edge_invoked must mean edge callback entry")
    # allow Forbidden: wording; reject live table cells with 0 or 1
    if re.search(r"\|\s*0 or 1\s*\|", tx_scope) or re.search(r"consume_invoked[^|\n]*0 or 1 per stage", tx_scope):
        fail("chunk C-2: forbidden merged 0-or-1 consume/edge table cells")
    if "0 or 1 per stage" in tx_scope and "Forbidden" not in tx_scope[max(0, tx_scope.find("0 or 1 per stage")-80):tx_scope.find("0 or 1 per stage")+1]:
        fail("chunk C-2: forbidden merged 0 or 1 per stage consume/edge cells without Forbidden")
    # success tuple
    if "TX_RESULT_SUCCESS_TUPLE_CANONICAL" not in tx_scope:
        fail("chunk C-2: TX_RESULT_SUCCESS_TUPLE_CANONICAL missing")
    if "`exact_status=0` (`NINLIL_RADIO_HAL_OK`) · `stage=10` (`NINLIL_RADIO_HAL_STAGE_EDGE`) · `reason=0` (`NINLIL_RADIO_HAL_REASON_NONE`)" not in tx_scope:
        fail("chunk C-2: success tuple must be exact_status=0 stage=10 reason=0")
    if "MUST NOT** copy it" not in tx_scope and "MUST NOT copy" not in tx_scope:
        fail("chunk C-2: success must not copy caller out_error")
    if "`status=8` / `stage=10` / `reason=12`" not in tx_scope:
        fail("chunk C-2: EDGE_ERROR tuple 8/10/12 missing")

    map_hdr = (
        "#",
        "R1 outcome (exact)",
        "exact_status",
        "stage",
        "reason",
        "final_tx_outcome",
        "disposition",
        "consume_invoked",
        "edge_invoked",
        "pair effect",
        "group effect",
    )
    map_rows = _parse_table_by_header(tx_scope, map_hdr)
    if tuple(map_rows) != TX_RESULT_MAP_EXPECTED:
        fail(
            f"chunk C-2: TX_RESULT mapping full table equality fail "
            f"got={map_rows!r} expected={TX_RESULT_MAP_EXPECTED!r}"
        )
    if len(map_rows) != 12:
        fail(f"chunk C-2: TX_RESULT mapping must have exactly 12 rows; got {len(map_rows)}")
    # RETRY_GATE prose + two-stage
    if "TX_RESULT_RETRY_GATE" not in tx_scope:
        fail("chunk C-2: TX_RESULT_RETRY_GATE missing")
    if "OPEN requires **`calls_used < 8`**" not in tx_scope and "OPEN requires `calls_used < 8`" not in tx_scope:
        fail("chunk C-2: RETRY_GATE OPEN requires exact calls_used < 8 predicate")
    if "calls_used <= 8" in tx_scope or "calls_used<=8" in tx_scope:
        fail("chunk C-2: RETRY_GATE must use strict calls_used < 8 (not <= 8)")
    if "current_accepted_now_mono" not in tx_scope:
        fail("chunk C-2: permit_tx_retry_at must use current_accepted_now_mono")
    if "strictly before" not in tx_scope:
        fail("chunk C-2: permit_tx_retry_at must be strictly before Permit/owner/group deadlines")
    if "Permit expiry" not in tx_scope or "enclosing owner deadline" not in tx_scope:
        fail("chunk C-2: RETRY_GATE must predicate Permit expiry and enclosing owner deadline")
    if "group_deadline_valid" not in tx_scope:
        fail("chunk C-2: RETRY_GATE must predicate group_deadline_valid when present")
    if "RETRY_GATE_OPEN" not in tx_scope or "RETRY_GATE_CLOSED" not in tx_scope:
        fail("chunk C-2: RETRY_GATE_OPEN/CLOSED tokens missing")
    if "consume HAL16" not in tx_scope:
        fail("chunk C-2: consume HAL16 specialized path missing")
    if "status=6 CONSUME_DENIED" not in tx_scope or "reason=16 NOT_BEFORE" not in tx_scope:
        fail("chunk C-2: consume HAL16 exact tuple 6/8/16 missing in prose")
    # mutual exclusivity wording (catchalls must exclude all specialized tuples)
    if "excluding exact validate HAL16 rows 2–3" not in map_rows[10][1]:
        fail("chunk C-2: TX map row11 must exclude exact validate HAL16 rows 2–3")
    if "excluding exact consume HAL16 rows 4–5" not in map_rows[11][1]:
        fail("chunk C-2: TX map row12 must exclude exact consume HAL16 rows 4–5")
    if "consume HAL45 rows 6–7" not in map_rows[11][1]:
        fail("chunk C-2: TX map row12 must exclude consume HAL45 rows 6–7")
    if "not tuples 6/8/16" not in map_rows[11][1]:
        fail("chunk C-2: TX map row12 must exclude tuple 6/8/16")
    if "6/8/45" not in map_rows[11][1]:
        fail("chunk C-2: TX map row12 must exclude tuple 6/8/45")
    # OPEN rows must be TX_RETRY; CLOSED rows TX_QUARANTINE
    for idx in (1, 3, 5):  # 0-based OPEN rows 2,4,6
        if map_rows[idx][5] != "TX_RETRY_SAME_PERMIT" or map_rows[idx][6] != "RETAIN_SEALED":
            fail(f"chunk C-2: RETRY_GATE_OPEN row {idx+1} must be TX_RETRY_SAME_PERMIT/RETAIN_SEALED")
        if "calls_used<8" not in map_rows[idx][9] and "calls_used < 8" not in map_rows[idx][9]:
            fail(f"chunk C-2: RETRY_GATE_OPEN row {idx+1} must state calls_used<8")
    for idx in (2, 4, 6):  # CLOSED rows 3,5,7
        if map_rows[idx][5] != "TX_QUARANTINE" or map_rows[idx][6] != "QUARANTINE":
            fail(f"chunk C-2: RETRY_GATE_CLOSED row {idx+1} must be TX_QUARANTINE/QUARANTINE")
        if "never local" not in map_rows[idx][9]:
            fail(f"chunk C-2: RETRY_GATE_CLOSED row {idx+1} must forbid local terminal/release")
    if any("RETRYABLE_UNISSUED" in r[1] or r[1] == "OK_ISSUED" for r in map_rows):
        fail("chunk C-2: TX_RESULT mapping must not contain pre-R1 issue classes")
    if "full R1 only" not in tx_scope and "full R1 pipeline only" not in tx_scope:
        fail("chunk C-2: R1 RETRYABLE must re-enter full R1 pipeline only on same Permit+sealed")
    if "mutation-0 unissued-proven local-terminal branch in R1" not in doc and "no** mutation-0 unissued" not in doc:
        if "unissued-proven local-terminal" not in doc:
            fail("chunk C-2: §15.3.4 must forbid R1 unissued local-terminal branch")
    if "if mutation-0 unissued proven ⇒ owner/group terminal without drain" in doc:
        fail("chunk C-2: R1 matrix must not reintroduce mutation-0 unissued local terminal")


    if "TX_EDGE_DONE_ACK_POLICY" not in tx_scope:
        fail("chunk C-2: TX_EDGE_DONE_ACK_POLICY missing")
    ack_hdr = ("path", "TX_EDGE_DONE meaning", "group state", "E2E slot", "OUTER slot")
    ack_rows = _parse_table_by_header(tx_scope, ack_hdr)
    if tuple(ack_rows) != TX_EDGE_DONE_ACK_EXPECTED:
        fail(
            f"chunk C-2: TX_EDGE_DONE_ACK_POLICY exact ordered equality fail "
            f"got={ack_rows!r} expected={TX_EDGE_DONE_ACK_EXPECTED!r}"
        )
    # ACK1 OUTER must release once / fresh OUTER; never retain old OUTER
    if "release once" not in ack_rows[0][4].lower():
        fail(f"chunk C-2: ACK1 OUTER must release once got={ack_rows[0][4]!r}")
    if "fresh OUTER" not in ack_rows[0][4] and "fresh outer" not in ack_rows[0][4].lower():
        fail(f"chunk C-2: ACK1 OUTER must allocate fresh OUTER got={ack_rows[0][4]!r}")
    if "retain old" in ack_rows[0][4].lower() or re.search(r"\bretain\b", ack_rows[0][4], re.I):
        fail(f"chunk C-2: ACK1 OUTER must not retain old OUTER got={ack_rows[0][4]!r}")

    # §11.2 ACK0 timer
    s112 = doc.find("#### 11.2 LINK retry group")
    s112e = doc.find("##### 11.2.2", s112) if s112 >= 0 else -1
    if s112 < 0 or s112e <= s112:
        fail("chunk C-2: §11.2 scope missing for ACK timer")
    ack_timer = doc[s112:s112e]
    if "ACK_REQUESTED0_SKIPS_ACK_TIMER" not in ack_timer and "outer_ack_requested=0" not in ack_timer:
        fail("chunk C-2: §11.2 must skip ACK timer when outer_ack_requested=0")
    if "skip** ACK timer" not in ack_timer and "skip ACK timer" not in ack_timer:
        fail("chunk C-2: §11.2 ack_requested=0 must skip ACK timer computation")
    if "only if `outer_ack_requested=1`" not in ack_timer and "only if outer_ack_requested=1" not in ack_timer:
        fail("chunk C-2: §11.2 ACK timers only if outer_ack_requested=1")
    ack1_exact = (
        "- **`outer_ack_requested=1`:** `ack_deadline = checked_add(prior_tx_mono, link_ack_wait_ms)`; "
        "`interval_at = checked_add(prior_tx_mono, link_retry_interval_ms)`; "
        "`eligible_at = max(ack_deadline, interval_at)` (checked_add overflow ⇒ terminal fail)."
    )
    if ack1_exact not in ack_timer:
        fail("chunk C-2: §11.2 outer_ack_requested=1 must compute ack_deadline/interval_at/eligible_at")
    if "outer_ack_requested=1`:** skip ACK timer" in ack_timer or "`outer_ack_requested=1`:** skip" in ack_timer:
        fail("chunk C-2: outer_ack_requested=1 must not skip ACK timer")


    # FIRST_FRAG transfer handle
    if "FIRST_FRAG_START_TEMPLATE_HANDLE_INJECT" not in doc and "FIRST_FRAG_START_TEMPLATE" not in doc:
        fail("chunk C-2: FIRST_FRAG_START_TEMPLATE handle inject missing")
    if "16..23 exact zero" not in doc:
        fail("chunk C-2: first START template handle octets 16..23 zero missing")
    if "MUST NOT** overwrite handle" not in doc and "MUST NOT overwrite handle" not in doc:
        fail("chunk C-2: E2E START retry must not overwrite transfer_handle")
    if "may overwrite handle" in doc or "MAY overwrite handle" in doc:
        fail("chunk C-2: transfer_handle must not allow may overwrite")

    e2e_zero = "Permit / R1 / TX_RESULT / OWNER_TERMINAL for that E2E pair = 0"
    if e2e_zero not in s11:
        fail("chunk C-2: E2E_BLOB must force Permit/R1/TX_RESULT/OWNER_TERMINAL = 0")
    if s11.count(e2e_zero) < 2:
        fail("chunk C-2: E2E_BLOB Permit=0 must appear in lifecycle and §1.1.1.5")
    if "Forbidden: routing `E2E_BLOB`" not in s11:
        fail("chunk C-2: must forbid E2E_BLOB → Permit/R1")
    if "immutable handoff/borrow" not in s11:
        fail("chunk C-2: E2E→HOP immutable handoff/borrow missing")
    if "E2E_BLOB_RELEASE_TABLE" not in s11:
        fail("chunk C-2: E2E_BLOB_RELEASE_TABLE missing for release once authority")
    if "OUTER sole air path" not in s11 and "sole air path is OUTER only" not in s11:
        fail("chunk C-2: §1.1.2 must state OUTER sole air path")
    if "Logical ordered C" not in s11:
        fail("chunk C-2: event ABI must state logical ordered C payload (not radio bytes)")
    stamp_body = s11[s11.find("EVENT_STAMP_FIELDS_BEGIN"): s11.find("EVENT_STAMP_FIELDS_END")]
    frame_body = s11[s11.find("EVENT_FRAME_READY_BEGIN"): s11.find("EVENT_FRAME_READY_END")]
    if re.search(r"\bepoch_id\b", stamp_body) or re.search(r"\bwatermark\b", stamp_body):
        fail("chunk C-2: STAMP block must not contain epoch_id/watermark")
    if re.search(r"\bepoch_id\b", frame_body) or re.search(r"\bwatermark\b", frame_body):
        fail("chunk C-2: FRAME block must not contain epoch_id/watermark")
    if "| 5 | L1→W1 | `TX_RESULT` | common_envelope + §1.1.2 TX_RESULT-specific fields |" not in s11:
        fail("chunk C-2: event table TX_RESULT row must be common_envelope + §1.1.2 specific fields")




def check_chunk_b2_crypto_state(root: pathlib.Path) -> None:
    """Round4 Chunk B-2: sample 3-axis, VAL_RECONCILE, Algorithm C order, prove, baseline."""
    doc = read(root, DOC30)
    d24 = read(root, "docs/24-r2-physical-compliance-permit-authority.md")

    # --- sample §11.2.3 three-axis closed enums (section-scoped) ---
    s0 = doc.find("##### 11.2.3 R7 private authority-clock sample primitive (closed)")
    s1 = doc.find("##### 11.2.3.1 Private authority-clock baseline family")
    if s0 < 0 or s1 < 0 or s1 <= s0:
        fail("chunk B-2: sample scope §11.2.3 missing")
    sample = doc[s0:s1]
    for tok in (
        "business_mutation",
        "durable_meta_mutation",
        "txn_provenance",
        "BUSINESS_ZERO` only",
        "META_ZERO | F_C_FULL | META_AMBIGUOUS",
        "PRECHECK_ZERO | CLOCK_FENCE_COMMITTED | AMBIGUOUS",
        "SAMPLE_COMMIT_UNKNOWN",
        "META_AMBIGUOUS",
        "MUST NOT** collapse CU to `META_ZERO`",
        "MUST NOT** reclassify as `SAMPLE_CLOCK_FAULT`",
    ):
        if tok not in sample:
            fail(f"chunk B-2 sample: missing {tok!r}")
    if "FULL以外はmeta 0" in sample or "FULL以外は meta 0" in sample:
        fail("chunk B-2 sample: forbidden non-FULL⇒META_ZERO blanket wording remains")
    # exact CU row fragment in RO table
    if "| `SAMPLE_COMMIT_UNKNOWN` | no | BUSINESS_ZERO | META_AMBIGUOUS | AMBIGUOUS |" not in sample:
        fail("chunk B-2 sample: SAMPLE_COMMIT_UNKNOWN must be BUSINESS_ZERO/META_AMBIGUOUS/AMBIGUOUS")
    if "| `SAMPLE_CLOCK_FAULT` |" not in sample or "F_C_FULL | CLOCK_FENCE_COMMITTED" not in sample:
        fail("chunk B-2 sample: SAMPLE_CLOCK_FAULT must carry F_C_FULL/CLOCK_FENCE_COMMITTED")

    # --- callback §15.3.1 7-col table ---
    j0 = doc.find("#### 15.3.1 R7 private R2 checked-issue primitive")
    j1 = doc.find("#### 15.3.2 Exhaustive issue outcome")
    if j0 < 0 or j1 <= j0:
        fail("chunk B-2: §15.3.1 scope missing")
    cb = doc[j0:j1]
    val_hdr = (
        "| callback result | R2 PCP status | reason | business_mutation | "
        "clock_fence_mutation | txn_provenance | L1 class |"
    )
    if val_hdr not in cb:
        fail("chunk B-2: validation_cb table must have business/clock_fence/txn columns")
    val_row = (
        "| `VAL_RECONCILE` | `NINLIL_PCP_INVALID_STATE` (2) | `CONTRACT` (28) | "
        "BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `RECONCILE_REQUIRED` |"
    )
    if val_row not in cb:
        fail("chunk B-2: VAL_RECONCILE exact RECONCILE_REQUIRED axes row missing")
    if "proceed to RW ISSUED" not in cb:
        fail("chunk B-2: VAL_OK must state pre-RW proceed")

    # --- issue matrix status2 + unknown ---
    i32 = doc.find("#### 15.3.2 Exhaustive issue outcome")
    i33 = doc.find("#### 15.3.3 Issued Permit cleanup")
    if i32 < 0 or i33 <= i32:
        fail("chunk B-2: §15.3.2 scope missing")
    i2 = doc[i32:i33]
    if "2:{INVALID_STATE(27), CONTRACT(28; callback reconcile exact only)}" not in i2:
        fail("chunk B-2: reason map status2 must close INVALID_STATE(27)+CONTRACT(28)")
    contract_issue = (
        "| R2 private issue | `NINLIL_PCP_INVALID_STATE` (2) + reason `CONTRACT` (28) + "
        "BUSINESS_ZERO/META_ZERO/PRECHECK_ZERO (VAL_RECONCILE or unknown callback normalize) | "
        "BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `RECONCILE_REQUIRED` |"
    )
    term_issue = (
        "| R2 private issue | `NINLIL_PCP_INVALID_STATE` (2) + reason `INVALID_STATE` (27) + "
        "PRECHECK/RW_ABORT zero | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO/RW_ABORT_ZERO | "
        "`TERMINAL_UNISSUED` |"
    )
    if contract_issue not in i2:
        fail("chunk B-2: issue matrix CONTRACT row missing/altered")
    if term_issue not in i2:
        fail("chunk B-2: issue matrix status2 terminal INVALID_STATE(27) row missing/altered")
    if i2.find(contract_issue) > i2.find(term_issue):
        fail("chunk B-2: CONTRACT row must appear before status2 terminal row")
    if (
        "| R2 private issue | status outside 0..23 / unknown | BUSINESS_AMBIGUOUS | META_AMBIGUOUS | AMBIGUOUS |"
        not in i2
    ):
        fail("chunk B-2: unknown status must be META_AMBIGUOUS")
    if (
        "| R2 private issue | status/reason/output/txn field mismatch | BUSINESS_AMBIGUOUS | META_AMBIGUOUS | AMBIGUOUS |"
        not in i2
    ):
        fail("chunk B-2: field mismatch must be META_AMBIGUOUS")
    if "BUSINESS_ZERO or BUSINESS_AMBIGUOUS" not in i2:
        fail("chunk B-2: R5 bind unknown must use BUSINESS_ZERO or BUSINESS_AMBIGUOUS")
    if re.search(
        r"unknown bind_item/locus \| BUSINESS_ZERO or AMBIGUOUS \|",
        i2,
    ):
        fail("chunk B-2: bare business AMBIGUOUS on R5 bind unknown forbidden")
    ok_success = (
        "| R2 private issue | `NINLIL_PCP_OK` (0) + exact valid snapshot + R5 registry insert OK | "
        "ISSUED_FULL | META_ZERO | ISSUED_COMMITTED | `OK_ISSUED` |"
    )
    if ok_success not in i2:
        fail("chunk B-2: issue success row must remain ISSUED_FULL")

    # --- §11.2.3.1 baseline load result closed table (state2 trusted=0 exact) ---
    b0 = doc.find("##### 11.2.3.1 Private authority-clock baseline family")
    b1 = doc.find("###### B. Atomic adopt")
    if b0 < 0 or b1 < 0 or b1 <= b0:
        fail("chunk B-2: §11.2.3.1 baseline family scope missing")
    bas = doc[b0:b1]
    bl_hdr = (
        "case",
        "published",
        "meta_state",
        "trusted_baseline_valid",
        "last_trusted epoch/now",
        "ram_trust.valid",
        "L1 action",
    )
    try:
        bl_rows = _parse_table_by_header(bas, bl_hdr)
    except GateFailure as e:
        fail(f"chunk B-2: baseline load result table missing/malformed ({e})")
    # closed set equality: unpublished / state1 / state2 (cells are _norm_cell'd)
    bl_expected = (
        (
            "unpublished",
            "0",
            "0",
            "0",
            "zero",
            "0",
            "TX 0 until first publish (no KEY_META)",
        ),
        (
            "state1 TRUSTED_BASELINE_PRESENT",
            "1",
            "1",
            "1",
            "nonzero + shape OK",
            "may set 1",
            "may install L1 watermark",
        ),
        (
            "state2 INITIAL_UNTRUSTED_FENCED",
            "1",
            "2",
            "0",
            "zero",
            "ram_trust.valid must remain 0",
            "L1 watermark absent; CLOCK fence present; TX 0 until fresh trusted recover/adopt to state1",
        ),
    )
    if tuple(bl_rows) != bl_expected:
        fail(f"chunk B-2: baseline load result closed set mismatch: got={bl_rows!r}")
    # structural fix on state2 tuple axes (false-green kill: trusted_baseline_valid must be 0)
    s2 = next((r for r in bl_rows if r[0].startswith("state2")), None)
    if s2 is None:
        fail("chunk B-2: baseline load state2 row missing")
    if s2[1:5] != ("1", "2", "0", "zero"):
        fail(
            "chunk B-2: state2 baseline row must be published=1 meta_state=2 "
            f"trusted_baseline_valid=0 last_trusted=zero; got {s2!r}"
        )
    if s2[3] != "0":
        fail("chunk B-2: state2 trusted_baseline_valid must be exactly 0 (not 1)")
    if "must remain 0" not in s2[5]:
        fail("chunk B-2: state2 ram_trust.valid must remain 0")
    if "fresh trusted recover/adopt" not in s2[6] and "recover/adopt to state1" not in s2[6]:
        fail("chunk B-2: state2 action must require fresh trusted recover/adopt to state1")
    # exact raw row anchor (pre-norm) — mut_one target site
    state2_raw = (
        "| state2 INITIAL_UNTRUSTED_FENCED | 1 | 2 | 0 | zero | "
        "ram_trust.valid **must remain 0** | L1 watermark absent; CLOCK fence present; "
        "**TX 0** until fresh trusted recover/adopt to state1 |"
    )
    if state2_raw not in bas:
        fail("chunk B-2: state2 baseline exact raw row missing/altered")
    if bas.count("| state2 INITIAL_UNTRUSTED_FENCED | 1 | 2 | 0 |") != 1:
        fail("chunk B-2: state2 trusted_baseline_valid=0 row must appear exactly once")
    if "| state2 INITIAL_UNTRUSTED_FENCED | 1 | 2 | 1 |" in bas:
        fail("chunk B-2: state2 must not claim trusted_baseline_valid=1")
    if "MUST NOT** set ram_trust.valid=1 for state2" not in bas:
        fail("chunk B-2: baseline must forbid ram_trust.valid=1 for state2")

    # --- adopt prove exact ---
    p0 = doc.find("###### C. `ninlil_r2_private_prove_adopt_authority_epoch`")
    p1 = doc.find("###### D.")
    if p1 < 0:
        p1 = doc.find("#### 11.3")
    if p0 < 0 or p1 <= p0:
        # broader prove region
        p0 = doc.find("ninlil_r2_private_prove_adopt_authority_epoch")
        p1 = doc.find("#### 11.3 LINK_ACK")
    if p0 < 0 or p1 <= p0:
        fail("chunk B-2: prove adopt scope missing")
    prove = doc[p0:p1]
    if "**old_present MUST equal 1**" not in prove:
        fail("chunk B-2: prove old_present MUST equal 1")
    if "old_present MUST equal 0|1" in prove or "old_present 0|1" in prove:
        fail("chunk B-2: prove must not relax old_present to 0|1")
    if "proof_crc32c exact Castagnoli parameters above" not in prove:
        fail("chunk B-2: prove must validate proof_crc32c")
    if "**NOT_FOUND** (clean or not) → **ADOPT_CORRUPT**" not in prove:
        fail("chunk B-2: prove NOT_FOUND must be ADOPT_CORRUPT")
    if re.search(r"NOT_FOUND[^\n]*retry", prove, re.I):
        fail("chunk B-2: prove NOT_FOUND must not be retry")

    # --- docs24 Algorithm C order: sample then state2/state1 precheck ---
    a0 = d24.find("### 3.7 CLOCK_FENCE 解除（Algorithm C; N15 閉包）")
    a1 = d24.find("### 3.8 API 別 clock map")
    if a0 < 0 or a1 <= a0:
        fail("chunk B-2: docs24 Algorithm C §3.7 missing")
    algo = d24[a0:a1]
    # must sample before state2 S-using precheck
    i_c1 = algo.find("C1 sample S")
    i_c1a = algo.find("C1a if meta_state==INITIAL_UNTRUSTED_FENCED")
    i_c2 = algo.find("C2 if meta_state==TRUSTED_BASELINE_PRESENT")
    i_c4 = algo.find("if old meta_state==INITIAL_UNTRUSTED_FENCED:")
    i_c4s = algo.find("meta_state=TRUSTED_BASELINE_PRESENT")
    if i_c1 < 0 or i_c1a < 0 or i_c2 < 0:
        fail("chunk B-2: Algorithm C must order C1 sample → C1a state2 → C2 state1")
    if not (i_c1 < i_c1a < i_c2):
        fail("chunk B-2: Algorithm C order must be sample S then state2 then state1 precheck")
    # forbid pre-sample C0a that references S requirements before C1
    pre_c1 = algo[:i_c1]
    if "C0a if meta_state==INITIAL_UNTRUSTED_FENCED" in pre_c1:
        fail("chunk B-2: C0a before sample S is forbidden (S not available)")
    if "require well-formed TRUSTED nonzero S" in pre_c1:
        fail("chunk B-2: must not require S before sample")
    if "invalid zero baseline" not in algo:
        fail("chunk B-2: state2 must state invalid zero baseline")
    if "ordinary floor compare" not in algo and "ordinary floor" not in algo:
        fail("chunk B-2: state2 must forbid ordinary floor compare")
    if i_c4 < 0 or i_c4s < 0 or i_c4s < i_c4:
        fail("chunk B-2: state2→state1 FULL transition in C4 must remain")

    # --- U0b normalize exact (section-scoped U0) ---
    u0 = d24.find("U0  Immediate after E6 returns COMMIT_UNKNOWN")
    u1 = d24.find("U1  Restart / later recovery entry")
    if u0 < 0 or u1 <= u0:
        fail("chunk B-2: U0 scope missing")
    u0s = d24[u0:u1]
    if "U0b  RAM: post_bits := fence_bits | STORAGE;" not in u0s:
        fail("chunk B-2: U0b RAM STORAGE sticky missing")
    if "fence_code := normalize_fence_code(post_bits, old_RAM_fence_code);" not in u0s:
        fail("chunk B-2: U0b must use normalize_fence_code (not fixed STORAGE code)")
    if "fence_code := STORAGE" in u0s or "fence_code = STORAGE" in u0s:
        fail("chunk B-2: U0b must not hardcode fence_code STORAGE")

    # --- U6 trusted_baseline_valid exact ---
    u6 = d24.find("U6  Issue-possible unique condition")
    u6e = d24.find("**MUST NOT:** STORAGE bit だけ clear")
    if u6 < 0 or u6e <= u6:
        fail("chunk B-2: U6 scope missing")
    u6s = d24[u6:u6e]
    if "AND trusted_baseline_valid==1" not in u6s:
        fail("chunk B-2: U6 must require trusted_baseline_valid==1")
    # published alone is not enough: still need trusted line
    if u6s.count("trusted_baseline_valid") < 1:
        fail("chunk B-2: U6 must not replace trusted_baseline_valid with published-only")


def check_round2_structural(root: pathlib.Path) -> None:
    """Structural re-audit checks for round 3 (not mere marker presence)."""
    doc = read(root, DOC30)
    d24 = read(root, "docs/24-r2-physical-compliance-permit-authority.md")
    d29 = read(root, DOC29)
    review = read(root, REVIEW)
    adr = read(root, ADR10)

    # --- forbid obsolete / false-green authorities ---
    if "ADOPT_CU_OPAQUE_RECOVERY_TOKEN_OR_PROOF" in doc:
        fail("docs30 must not retain ADOPT_CU_OPAQUE_RECOVERY_TOKEN_OR_PROOF")
    if "recovery_proof[72]" in doc or "ADOPT_CU_PROOF_FIXED_72B_ONLY" in doc:
        fail("docs30 must not retain 72B adopt proof form")
    if re.search(r"\| OUT_OF_ORDER \| 6 CONSUME_DENIED \| 8 PERMIT_CONSUME \| 41 UNCONSUMED \|", d24):
        fail("docs24 §10.10 must not map OUT_OF_ORDER to generic 41 UNCONSUMED")
    if "CLOCK_UNCERTAIN / NOT_BEFORE / BUSY pre-put" in d24 and "41 UNCONSUMED" in d24:
        # only fail if old combined row pattern remains as authority
        if re.search(r"CLOCK_UNCERTAIN / NOT_BEFORE / BUSY pre-put \| 6 CONSUME_DENIED \| 8 \| 41 UNCONSUMED \|", d24):
            fail("docs24 §10.10 must not map CLOCK_UNCERTAIN/NOT_BEFORE/BUSY to generic 41")
    if "A2 PERM/ill-formed/regression → F_c; PCP_CLOCK_FAULT; durable 0" in d24:
        fail("docs24 Algorithm A A2 must not claim CLOCK_FAULT durable 0")
    if "sample PERM/ill-formed/regression | 7 CLOCK_FAULT | 5 PCP_CLOCK_FAULT | 0 |" in d24:
        fail("docs24 issue table must not claim CLOCK_FAULT durable 0 for PERM sample")
    if "[UNCONSUMED/NOT_BEFORE" in doc:
        fail("docs30 must not use generic UNCONSUMED/NOT_BEFORE flow as target authority")
    if "typed retryable UNCONSUMED" in doc:
        fail("docs30 must not use generic typed retryable UNCONSUMED as target authority")
    if "Post-burn Seal/encode failure" in doc or "ninlil_r2_private_prove_durable_fifo_head" in doc:
        fail("docs30 must not retain orphan post-Related tail fragments")

    i53 = d29.find("### 5.3 R6 consume reason passthrough")
    i6 = d29.find("## 6. Packaging")
    i9 = d29.find("## 9. 関連")
    if i53 < 0 or i6 < 0 or i9 < 0 or not (i53 < i6 < i9):
        fail("docs29 §5.3 must sit before Packaging and Related")

    required_doc = [
        ("Exact size **68**", "N6TX/RX 68"),
        ("Exact size **56**", "N6AL 56"),
        ("Exact size **48**", "N6RT 48"),
        ("Exact size **64**", "N6CF 64"),
        ("Exact size **28**", "N6HW 28"),
        ("Exact key size **32**", "N6HW key 32"),
        ("Exact key size **28**", "N6RT/N6CF key 28"),
        ("recovery_proof[120]", "120B proof"),
        ("200-byte LE", "meta 200B"),
        ("ASCII(\"NINLIL-R2-META-V1\")", "digest domain"),
        ("are **void**", "void close"),
        ("close(user, h)                    # void; exactly once; no status check", "void close once"),
        ("non-OK rollback ⇒ CORRUPT fence (close has no status)", "rollback-only CORRUPT"),
        ("get() / output-shape anomalies", "get shape classify"),
        ("N6_NAMESPACE_GC_LEXICOGRAPHIC_RESCAN", "GC mode"),
        ("One FULL = one context unit", "GC atomic unit"),
        ("mutations ≤ 32", "GC ≤32 mutations"),
        ("1 ≤ peer_next_floor ≤ UINT32_MAX", "floor domain"),
        ("receiver_node_id[16]", "full receiver id"),
        ("magic = 0x4E365254 (\"N6RT\")", "N6RT magic"),
        ("magic = 0x4E364346 (\"N6CF\")", "N6CF magic"),
        ("byte-for-byte", "install collision full ID"),
        ("entries_required = A + 2*H + E + F + T + W", "capacity entries formula"),
        ("bytes_required   = 80*A + 232*H + 116*E + 92*F + 76*T + 60*W", "capacity bytes formula"),
        ("max_namespaces = 2", "ESP max namespaces 2"),
        ("minimum of **3** namespaces", "3 namespaces required"),
        ("never both; never two terminals", "terminal uniqueness"),
        ("not a fail path", "LENGTH_CLASS vs FRAME_READY"),
        ("full R1 pipeline only** on same Permit + same sealed candidate", "retry pipeline"),
        ("issue only** on same sealed candidate", "retry unissued"),
        ("owner_token, candidate_token", "event correlation tokens"),
        ("L1 sole owner of sealed candidate", "FRAME_READY L1 ownership"),
        ("later = fresh burn/stamp/seal/issue", "CLOCK_UNCERTAIN fresh only"),
        ("R5 `in_api` covers static preflight → R2 call → registry insert", "R5 guard whole path"),
        ("no clock sample", "callback no sample"),
        ("Single-use:** activate consumes snapshot_id", "snapshot single-use"),
        ("ADOPT_CU_PROOF_FIXED_120B_ONLY", "120B proof token"),
        ("ESP_STORAGE_CAPACITY_NOT_READY_R6", "ESP not ready"),
        ("TWO_CATALOG_PCP_VS_HAL", "two catalog marker"),
        ("PCP_REASON_NOT_BEFORE", "PCP NOT_BEFORE name"),
        ("PCP_REASON_CONSUME_CLOCK_UNCERTAIN", "PCP consume clock uncertain 44"),
        ("PCP_REASON_CONSUME_BUSY", "PCP consume busy 45"),
        ("PCP_REASON_FIFO_OUT_OF_ORDER", "PCP FIFO OOO 43"),
        ("NINLIL_RADIO_HAL_REASON_NOT_BEFORE", "HAL NOT_BEFORE name"),
        ("never call it a PCP code", "16 not PCP"),
        ("New burns only with counters ≥ U", "FRAG restart"),
        ("ALL_PROPOSED/OLD using pre-crash C is forbidden", "FRAG no pre-crash C"),
        ("HAL NOT_BEFORE=16 or HAL CONSUME_BUSY=45 only", "typed retry outcomes"),
    ]
    for needle, label in required_doc:
        if needle not in doc:
            fail(f"round3 structural missing {label}: {needle!r}")
    if "ninlil_r2_private_commit_clock_fault_fence" not in doc and "common R2 helper" not in doc:
        fail("docs30 missing F_c helper reference")

    if "Two catalogs (Normative; never conflate)" not in d24:
        fail("docs24 missing two-catalog Normative section")
    if "PCP_REASON_FIFO_OUT_OF_ORDER          43" not in d24:
        fail("docs24 missing FIFO_OUT_OF_ORDER 43 exact enum line")
    if "PCP_REASON_CONSUME_CLOCK_UNCERTAIN    44" not in d24:
        fail("docs24 missing CONSUME_CLOCK_UNCERTAIN 44 exact enum line")
    if "PCP_REASON_CONSUME_BUSY" not in d24:
        fail("docs24 missing CONSUME_BUSY")
    if "**16** `NINLIL_RADIO_HAL_REASON_NOT_BEFORE`" not in d24:
        fail("docs24 missing HAL NOT_BEFORE=16 mapping from PCP 9")
    if re.search(r"PCP_REASON_CLOCK_UNCERTAIN\s+44", d24):
        fail("docs24 must not assign generic CLOCK_UNCERTAIN=44")
    if not re.search(r"PCP_REASON_CLOCK_UNCERTAIN\s+6", d24):
        fail("docs24 must keep CLOCK_UNCERTAIN=6 for sample path")
    if "ninlil_r2_private_commit_clock_fault_fence" not in d24:
        fail("docs24 missing shared F_c helper name")
    if "ninlil_r2_private_commit_clock_fault_fence" not in d24 or "A2 PERM" not in d24:
        fail("docs24 Algorithm A A2 must require shared F_c helper")
    if "call shared helper" not in d24 and "call shared helper `ninlil_r2_private_commit_clock_fault_fence`" not in d24:
        if "ninlil_r2_private_commit_clock_fault_fence` (FULL CLOCK+F_c" not in d24:
            fail("docs24 Algorithm A A2 must call shared F_c helper")
    if "Legacy production fact (not R6 target)" not in d24:
        fail("docs24 must label 41/42 as legacy production only")

    if "R6 consume reason passthrough" not in d29:
        fail("docs29 missing consume passthrough section")
    if "PCP_REASON_NOT_BEFORE" not in d29:
        fail("docs29 must map PCP NOT_BEFORE=9 to HAL 16")

    if "not GO" not in adr:
        fail("ADR-0010 must contain 'not GO'")
    if "not GO" not in review:
        fail("self-review must contain 'not GO'")

    sec = doc[doc.find("### 1.1 "):doc.find("## 2. Wire")]
    if sec.count("**") % 2 != 0:
        fail("docs30 §1.1 unbalanced ** bold markers")
    check_chunk_c_l1_w1(doc)
    check_chunk_c2_interop_events(doc)
    check_chunk_b2_crypto_state(root)

    if "64 | 68 | 4 | value_crc32c" not in doc and "64 | 68 | 4 |" not in doc:
        if not re.search(r"64\s+68\s+4\s+value_crc32c", doc):
            fail("N6TX CRC row 64..68 missing")

    if "N6AL value (40 B" in doc or "TX lane value (56 B continuous" in doc:
        fail("docs30 must not retain superseded N6AL 40B / TX 56B layout claims")

    # --- round 4 N6 + retained non-N6 r3 checks that still apply ---
    # A N6: direction-independent allocator / 26B fingerprint / actual side only
    if "direction_code (0=IR, 1=RI; **not** reserved0)" in doc:
        fail("docs30 N6AL must not put direction in key byte3 (round3.1 obsolete)")
    if "reserved0 = 0 (**not** direction)" not in doc:
        fail("docs30 N6AL key byte3 must be reserved0=0 not direction")
    fp26 = "receiver_node_id[16] || layer_code:u8 || membership_epoch:u64 BE || alloc_side:u8"
    if fp26 not in doc:
        fail(f"docs30 missing exact 26B fingerprint domain (no direction): {fp26!r}")
    if "Fingerprint domain (exact 26 B concat; no direction)" not in doc:
        fail("docs30 must label fingerprint as exact 26 B no direction")
    if "receiver_node_id[16] || layer_code:u8 || direction_code:u8 || membership_epoch:u64 BE || alloc_side:u8" in doc:
        fail("docs30 must not use directionful N6AL fingerprint domain")
    if "always both sides" in doc.lower() or "N6AL always both sides" in doc:
        fail("docs30 must not require always-both-sides N6AL")
    if "Phantom paired N6AL forbidden" not in doc and "Phantom paired N6AL forbidden." not in doc:
        fail("docs30 must forbid phantom paired N6AL")
    if "Actual-side only" not in doc and "actual local side" not in doc:
        fail("docs30 must state actual-side only N6AL install")
    if 'ASCII("NINLIL-R6-NODE-ID-v1")' not in doc:
        fail("docs30 missing canonical node-id derivation domain label")
    if "Caller-supplied alternate node id forbidden" not in doc:
        fail("docs30 must forbid caller-supplied alternate node id")
    # GC: one N6AL + present direction N6HW
    if "M = (membership_epoch, layer_code, receiver_node_id, alloc_side)" not in doc:
        fail("docs30 GC M must be epoch,layer,receiver,alloc_side (no direction in M)")
    if "M = (membership_epoch, layer_code, direction_code, receiver_node_id)" in doc:
        fail("docs30 must not use directionful GC M")
    if "Normalized mutation count **1..3**" not in doc:
        fail("docs30 final GC cleanup mutation count must be 1..3")
    if "Mutation count = **exactly 3**" in doc and "2 N6AL" in doc:
        fail("docs30 must not require exactly-3 dual-N6AL final GC")
    if "W_M ≤ 2 typically" in doc or "every direction present under M" in doc:
        fail("docs30 must not retain vague multi-direction N6HW GC deletes")
    # Install linearization
    if "N6_FRESH_INSTALL_LINEARIZATION" not in doc:
        fail("docs30 missing fresh install linearization token")
    if "exact 2 lane values (N6TX or N6RX) + 1 N6AL put + 1 N6HW put = **4**" not in doc:
        fail("docs30 HOP install write-set must be max 4")
    if "Until M5 floor signature is frozen and materialized, resume = 0" not in doc:
        fail("docs30 resume must be blocked until M5")
    if "flags **exactly 0x0001**" not in doc:
        fail("docs30 N6RT/N6CF flags must be exactly 0x0001")
    if "S.now >= checked_add(stamp.now, 30000)" not in doc:
        fail("docs30 N6CF reclaim must use checked_add 30000 restamp rule")
    if "FULL **restamp** N6CF under current trusted epoch" not in doc:
        fail("docs30 must require FULL restamp before reclaim after epoch mismatch")
    if "high_water ≥ every active lane kgen" not in doc:
        fail("docs30 boot must require N6HW high_water vs lane/N6RT kgen")
    if "cross-direction conflict" not in doc:
        fail("docs30 boot must forbid same context_id both directions under allocator")

    if "SHA-256(domain||receiver_node_id" in doc or "SHA-256(domain || receiver_node_id" in doc:
        fail("docs30 must not use domain||receiver_node_id double-concat fingerprint")

    # retained cross-doc anchors (non-N6 mutations still in suite)
    if "typed provenance-preserving exact mapping" not in d29:
        fail("docs29 must state typed provenance-preserving exact mapping")
    if "bit-exact numeric preserve across catalogs" in d29:
        fail("docs29 must not claim bit-exact numeric preserve across catalogs")
    if "P3-FENCED path" in d24:
        if "meta_state=INITIAL_UNTRUSTED_FENCED(2)" not in d24:
            fail("docs24 P3-FENCED must FULL-commit meta_state=INITIAL_UNTRUSTED_FENCED(2)")


    # --- chunk B: meta_state / baseline trusted / adopt / U0-U6 / issue axes ---
    if "TRUSTED_BASELINE_PRESENT" not in d24:
        fail("docs24 missing TRUSTED_BASELINE_PRESENT meta_state=1")
    if "INITIAL_UNTRUSTED_FENCED" not in d24:
        fail("docs24 missing INITIAL_UNTRUSTED_FENCED meta_state=2")
    if "CLOCK_CONTRACT" in d24 or "CLOCK_CONTRACT" in doc:
        fail("docs must not use stale CLOCK_CONTRACT fence cause")
    if "PCP_FC_CLOCK_UNKNOWN" not in d24:
        fail("docs24 missing PCP_FC_CLOCK_UNKNOWN")
    if "if meta_state was 1, keep meta_state=1" not in d24 and "keep meta_state=1" not in d24:
        fail("docs24 F_c helper must preserve state1")
    if "trusted_baseline_valid" not in doc:
        fail("docs30 baseline must expose trusted_baseline_valid")
    if "published vs trusted (exact closed baseline load result rows)" not in doc:
        fail("docs30 must separate published vs trusted_baseline_valid (closed baseline load result rows)")
    if "normalize_fence_code" not in d24:
        fail("docs24 missing normalize_fence_code")
    if d24.count("normalize_fence_code") < 3:
        fail("docs24 must retain normalize_fence_code on U0b/U0c/U4-class paths")
    if "U0b" not in d24 or "U0c" not in d24:
        fail("docs24 missing U0b/U0c")
    if "ram_trust.valid := 1" not in d24:
        fail("docs24 U5 must set ram_trust.valid := 1 on trusted rebuild")
    if "ram_trust.valid := 0" not in d24:
        fail("docs24 must set ram_trust.valid := 0 on untrusted/state2 rebuild")
    if "trusted_baseline_valid=1" not in doc:
        fail("docs30 must have trusted_baseline_valid=1 success path")
    if "ram_trust.valid **must remain 0**" not in doc and "must remain 0" not in doc:
        fail("docs30 state2 must force ram_trust.valid remain 0")

    if "old_present=0 path" in doc:
        fail("docs30 must delete old_present=0 adopt branch")
    if "old_present = **1**" not in doc:
        fail("docs30 proof old_present must be REQUIRED constant 1")
    if (
        "Castagnoli poly `0x82f63b78`" not in doc
        or "proof_crc32c of bytes[0,116)" not in doc
    ):
        fail("docs30 must state proof CRC32C Castagnoli parameters")
    if "present_byte=0 image is **not** used for adopt" not in doc and "not** used for adopt" not in doc:
        if "Absent present_byte=0 image is **not** used for adopt" not in doc:
            fail("docs30 must forbid absent-meta adopt digest path")


def self_test(repo: pathlib.Path) -> None:
    check(repo)

    # Positive fixture: fake tables outside §13 must be ignored by section-scoped parser
    _copy_targets = (
        DOC30,
        ADR10,
        REVIEW,
        FINAL_REVIEW,
        DOC29,
        "docs/24-r2-physical-compliance-permit-authority.md",
    ) + CROSS

    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        for r in _copy_targets:
            src = repo / r
            if not src.is_file():
                continue
            dst = tmp / r
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        d25 = repo / "docs/25-u5-cell-operating-assignment.md"
        if d25.is_file():
            dst = tmp / "docs/25-u5-cell-operating-assignment.md"
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(d25, dst)
        docp = tmp / DOC30
        body = docp.read_text(encoding="utf-8")
        fake = "\n".join(
            [
                "",
                "## Fake earlier resource-looking table (out of scope)",
                "",
                "| item | entries | owned payload / canonical bytes | TTL | overflow action |",
                "| --- | ---: | ---: | ---: | --- |",
                "| endpoint E2E ingress queue (auth hop DATA / sealed E2E blob awaiting E2E processing) | 1 | 1 B | bad | silently evict |",
                "",
                "| timer | value | on expiry |",
                "| --- | ---: | --- |",
                "| link_ack_wait_ms | 1 | wrong |",
                "",
            ]
        ) + "\n"
        if "## 13. Resources (CELL_64_V1)" not in body:
            fail("positive fixture: missing §13")
        body2 = body.replace(
            "## 13. Resources (CELL_64_V1)", fake + "## 13. Resources (CELL_64_V1)", 1
        )
        if body2 == body:
            fail("positive fixture no-op")
        docp.write_text(body2, encoding="utf-8")
        check(tmp)
        print("  positive fixture: fake out-of-section tables ignored: OK")

    def mut_all(name: str, rel: str, old: str, new: str):
        def fn(t: str) -> str:
            if old not in t:
                raise RuntimeError(f"mutator {name}: missing anchor {old!r}")
            return t.replace(old, new)
        return (name, rel, fn)

    def mut_one(name: str, rel: str, old: str, new: str):
        """Single-site mutation: anchor must occur exactly once; replace once only."""
        def fn(t: str) -> str:
            n = t.count(old)
            if n != 1:
                raise RuntimeError(
                    f"mutator {name}: expected unique anchor count=1, got {n} for {old!r}"
                )
            out = t.replace(old, new, 1)
            if out == t:
                raise RuntimeError(f"mutator {name}: no-op after replace")
            if out.count(old) != 0:
                raise RuntimeError(f"mutator {name}: old still present after one replace")
            # deletion (new==""): length must drop by exactly len(old)
            if new == "":
                if len(t) - len(out) != len(old):
                    raise RuntimeError(
                        f"mutator {name}: deletion size mismatch "
                        f"delta={len(t)-len(out)} expected={len(old)}"
                    )
                return out
            if new not in out:
                raise RuntimeError(f"mutator {name}: new text not present after replace")
            # new text was absent: must appear exactly once after insert
            if new not in t and out.count(new) != 1:
                raise RuntimeError(
                    f"mutator {name}: expected new count=1 after insert, got {out.count(new)}"
                )
            # new already existed: count must increase by exactly 1
            if new in t and out.count(new) != t.count(new) + 1:
                raise RuntimeError(
                    f"mutator {name}: new count delta != 1 "
                    f"(before={t.count(new)} after={out.count(new)})"
                )
            return out
        return (name, rel, fn)

    DOC24 = "docs/24-r2-physical-compliance-permit-authority.md"

    cases: list[tuple[str, str, Callable[[str], str]]] = [
        # A events / retry
        mut_all("a_tokens_required", DOC30, "owner_token, candidate_token", "owner_token_only"),
        mut_all("a_l1_owns_sealed", DOC30, "L1 sole owner of sealed candidate", "W1 retains sealed candidate ownership"),
        mut_all("a_retry_pipeline_no_reseal", DOC30, "full R1 pipeline only** on same Permit + same sealed candidate", "may reseal and reissue on RETRYABLE_PIPELINE"),
        mut_all("a_retry_unissued_no_restamp", DOC30, "issue only** on same sealed candidate", "may restamp reseal on RETRYABLE_UNISSUED"),
        mut_all("a_double_terminal_ban", DOC30, "never both; never two terminals", "may emit both OWNER_TERMINAL and terminal TX_RESULT"),
        mut_all("a_length_class_exclusive", DOC30, "not a fail path", "LENGTH_CLASS may accompany FRAME_READY"),
        # B layouts
        mut_all("b_tx68", DOC30, "Exact size **68**", "Exact size **56**"),
        mut_all("b_n6al56", DOC30, "Exact size **56**. Coverage **[0,52)**.", "Exact size **40**."),
        mut_all("b_receiver_full", DOC30, "receiver_node_id[16]", "receiver_tag_u32"),
        mut_all("b_n6rt48", DOC30, 'magic = 0x4E365254 ("N6RT")', 'magic = 0x00000000'),
        mut_all("b_n6cf64", DOC30, 'magic = 0x4E364346 ("N6CF")', 'magic = 0x00000000'),
        mut_all("b_n6hw_key", DOC30, "Exact key size **32**", "Exact key size **16**"),
        mut_all("b_floor_domain", DOC30, "1 ≤ peer_next_floor ≤ UINT32_MAX", "peer_next_floor may be 0"),
        mut_all("b_join_collision", DOC30, "byte-for-byte", "fingerprint-only without full ID"),
        # C GC
        mut_all("c_gc_mode", DOC30, "N6_NAMESPACE_GC_LEXICOGRAPHIC_RESCAN", "N6_NAMESPACE_GC_DURABLE_CURSOR"),
        mut_all("c_one_context_full", DOC30, "One FULL = one context unit", "One FULL may delete entire NS"),
        mut_all("c_mutations_cap", DOC30, "mutations ≤ 32", "mutations ≤ 256"),
        # D void close
        mut_all("d_void_close", DOC30, "are **void**", "return status_t and must be checked"),
        mut_all("d_close_once", DOC30, "close(user, h)                    # void; exactly once; no status check", "st = close(user, h); if st != OK: CORRUPT"),
        mut_all("d_get_shape", DOC30, "get() / output-shape anomalies", "get shape ignored"),
        # E 120B proof
        mut_all("e_proof120", DOC30, "ADOPT_CU_PROOF_FIXED_120B_ONLY", "ADOPT_CU_PROOF_72B_OK"),
        mut_all("e_digest_def", DOC30, 'ASCII("NINLIL-R2-META-V1")', 'ASCII("META")'),
        mut_all("e_200b", DOC30, "200-byte LE", "partial field hash only"),
        mut_all("e_opaque_marker_reintro", DOC30, "ADOPT_CU_PROOF_FIXED_120B_ONLY", "ADOPT_CU_OPAQUE_RECOVERY_TOKEN_OR_PROOF"),
        # F consume chain / two catalogs
        mut_all("f_reason44_name", DOC30, "PCP_REASON_CONSUME_CLOCK_UNCERTAIN", "PCP_REASON_CLOCK_UNCERTAIN"),
        mut_all("f_uncertain_fresh", DOC30, "later = fresh burn/stamp/seal/issue", "later may reuse same sealed candidate"),
        mut_all("f_docs24_43", DOC24, "PCP_REASON_FIFO_OUT_OF_ORDER          43", "PCP_REASON_FIFO_OUT_OF_ORDER          41"),
        mut_all("f_docs24_44", DOC24, "PCP_REASON_CONSUME_CLOCK_UNCERTAIN    44", "PCP_REASON_CLOCK_UNCERTAIN            44"),
        mut_all("f_docs24_old_ooo_row", DOC24, "**43** `PCP_REASON_FIFO_OUT_OF_ORDER`", "OUT_OF_ORDER | 6 CONSUME_DENIED | 8 PERMIT_CONSUME | 41 UNCONSUMED"),
        mut_all("f_docs24_two_catalog", DOC24, "Two catalogs (Normative; never conflate)", "Single catalog PCP=HAL"),
        mut_all("f_docs24_hal16", DOC24, "**16** `NINLIL_RADIO_HAL_REASON_NOT_BEFORE`", "**16** `PCP_REASON_NOT_BEFORE`"),
        mut_all("f_docs29_passthrough", DOC29, "R6 consume reason passthrough", "R6 consume reason optional"),
        mut_all("f_docs29_typed_map", DOC29, "typed provenance-preserving exact mapping", "bit-exact numeric preserve across catalogs"),
        mut_all("f_generic_retry_flow", DOC30, "HAL NOT_BEFORE=16 or HAL CONSUME_BUSY=45 only", "[UNCONSUMED/NOT_BEFORE: same permit"),
        # G F_c
        mut_all("g_helper", DOC24, "ninlil_r2_private_commit_clock_fault_fence", "optional_fc_write"),
        mut_all("g_algo_a2", DOC24, "call shared helper `ninlil_r2_private_commit_clock_fault_fence` (FULL CLOCK+F_c on existing meta); then PCP_CLOCK_FAULT", "A2 PERM/ill-formed/regression → F_c; PCP_CLOCK_FAULT; durable 0"),
        # H issue guards
        mut_all("h_r5_guard", DOC30, "R5 `in_api` covers static preflight → R2 call → registry insert", "R5 guard ends before R2 call"),
        mut_all("h_callback_no_sample", DOC30, "no clock sample", "callback may sample clock"),
        mut_all("h_snapshot_single_use", DOC30, "Single-use:** activate consumes snapshot_id", "snapshot_id may be reused"),
        # I ESP
        mut_all("i_entries_formula", DOC30, "entries_required = A + 2*H + E + F + T + W", "entries_required = A + H"),
        mut_all("i_bytes_formula", DOC30, "bytes_required   = 80*A + 232*H + 116*E + 92*F + 76*T + 60*W", "bytes_required = unknown"),
        mut_all("i_max_ns2", DOC30, "max_namespaces = 2", "max_namespaces = 8"),
        mut_all("i_not_ready", DOC30, "ESP_STORAGE_CAPACITY_NOT_READY_R6", "ESP_R6_READY"),
        # J FRAG restart
        mut_all("j_restart_fresh", DOC30, "New burns only with counters ≥ U", "restart may resume pre-crash C"),
        mut_all("j_no_precrash_c", DOC30, "ALL_PROPOSED/OLD using pre-crash C is forbidden", "restart may classify pre-crash C"),
        # honesty / structure
        mut_all("k_not_go_adr", ADR10, "not GO", "GO"),
        mut_all("k_not_go_rev", REVIEW, "not GO", "self-GO"),
        mut_all("k_docs29_order", DOC29, "### 5.3 R6 consume reason passthrough", "## 9. 関連\n### 5.3 R6 consume reason passthrough"),
        # round 3.1
        # round 4 N6 (replaces obsolete round3.1 direction/dual-N6AL mutations)
        mut_all("r4_fp26", DOC30, "Fingerprint domain (exact 26 B concat; no direction)", "Fingerprint domain with direction"),
        mut_all("r4_fp26_bytes", DOC30, "receiver_node_id[16] || layer_code:u8 || membership_epoch:u64 BE || alloc_side:u8", "receiver_node_id[16] || layer_code:u8 || direction_code:u8 || membership_epoch:u64 BE || alloc_side:u8"),
        mut_all("r4_n6al_reserved0", DOC30, "reserved0 = 0 (**not** direction)", "direction_code (0=IR, 1=RI; **not** reserved0)"),
        mut_all("r4_no_both_sides", DOC30, "Phantom paired N6AL forbidden", "N6AL always both sides required"),
        mut_all("r4_gc_m", DOC30, "M = (membership_epoch, layer_code, receiver_node_id, alloc_side)", "M = (membership_epoch, layer_code, direction_code, receiver_node_id)"),
        mut_all("r4_gc_mut_1_3", DOC30, "Normalized mutation count **1..3**", "Mutation count = **exactly 3** dual N6AL"),
        mut_all("r4_node_id", DOC30, 'ASCII("NINLIL-R6-NODE-ID-v1")', 'ASCII("NODE")'),
        mut_all("r4_install4", DOC30, "exact 2 lane values (N6TX or N6RX) + 1 N6AL put + 1 N6HW put = **4**", "install may put lanes only without N6AL"),
        mut_all("r4_resume_m5", DOC30, "Until M5 floor signature is frozen and materialized, resume = 0", "resume always allowed without M5"),
        mut_all("r4_flags_0001", DOC30, "flags **exactly 0x0001**", "flags free-form"),
        mut_all("r4_reclaim_30s", DOC30, "S.now >= checked_add(stamp.now, 30000)", "reclaim immediately without 30000 wait"),
        mut_all("r4_high_water", DOC30, "high_water ≥ every active lane kgen", "high_water optional"),

        # chunk B
        mut_all("r4b_meta_state1", "docs/24-r2-physical-compliance-permit-authority.md", "TRUSTED_BASELINE_PRESENT", "ACTIVE_ONLY_NO_TRUSTED_BASELINE"),
        mut_all("r4b_meta_state2", "docs/24-r2-physical-compliance-permit-authority.md", "INITIAL_UNTRUSTED_FENCED", "FENCED_GENERIC"),
        mut_all("r4b_no_clock_contract", "docs/24-r2-physical-compliance-permit-authority.md", "PCP_FC_CLOCK_UNKNOWN", "CLOCK_CONTRACT"),
        mut_all("r4b_helper_keep_state1", "docs/24-r2-physical-compliance-permit-authority.md", "if meta_state was 1, keep meta_state=1", "helper demotes state1 to state2"),
        mut_all("r4b_trusted_baseline", DOC30, "trusted_baseline_valid", "trusted_always_equals_published"),
        mut_all(
            "r4b_pub_vs_trusted",
            DOC30,
            "published vs trusted (exact closed baseline load result rows)",
            "published implies trusted",
        ),
        mut_all("r4b_old_present1", DOC30, "old_present = **1**", "old_present 0|1"),
        mut_all("r4b_no_old0_path", DOC30, "old_present=0 branch deleted", "old_present=0 path"),
        mut_all("r4b_proof_crc", DOC30, "proof_crc32c of bytes[0,116)", "proof crc optional"),
        mut_all("r4b_castagnoli", DOC30, "Castagnoli poly `0x82f63b78`", "CRC poly free"),
        mut_all("r32_baseline_catalog", DOC30, "result_catalog = R2_PCP,   /* baseline is R2 catalog only */", "result_catalog = NONE,   /* baseline is R2 catalog only */"),
        mut_all("r32_adopt_catalog", DOC30, "result_catalog = R2_PCP,   /* adopt/prove is R2 catalog only */", "result_catalog = R1_HAL,   /* adopt/prove is R2 catalog only */"),
        mut_all("r32_issue_catalog", DOC30, "R1 HAL values are forbidden in this object", "R1 HAL values are permitted in this object"),
        # Chunk C events / SEAL_FAIL / LENGTH / callback / clock discard
        mut_all("c_drop_stamp", DOC30, "| 1 | L1→W1 | `STAMP_FIELDS`", "| 1 | L1→W1 | `STAMP_GONE`"),
        mut_all("c_drop_seal_fail", DOC30, "| 3 | W1→L1 | `SEAL_FAIL`", "| 3 | W1→L1 | `SEAL_OK`"),
        mut_all("c_add_event", DOC30, "Abolished: `ISSUE_GRANTED`, `TRANSMIT_EDGE`", "Live event: `ISSUE_GRANTED` allowed"),
        mut_all("c_token_wildcard", DOC30, "No token set, no sentinel 0, no multi-token payload.", "owner-wide token set and sentinel 0 allowed."),
        mut_all("c_double_terminal", DOC30, "never both; never two terminals", "may emit both OWNER_TERMINAL and terminal TX_RESULT"),
        mut_all("c_drop_phase_e2e_aead", DOC30, "`4 E2E_AEAD`", "`4 E2E_GONE`"),
        mut_all("c_drop_cause_aead", DOC30, "`6 AEAD_FAILURE`", "`6 AEAD_OPTIONAL`"),
        mut_all("c_phase_burn_flip", DOC30, "| E2E_ENCODE / E2E_AEAD | 1 E2E |", "| E2E_ENCODE / E2E_AEAD | 0 NONE |"),
        mut_all("c_cu_immediate_fail", DOC30, "while burn CU is open, **do not** emit SEAL_FAIL", "while burn CU is open, emit SEAL_FAIL immediately"),
        mut_all("c_len_single_lo", DOC30, "DATA_SINGLE` | 31..220 | 66..255", "DATA_SINGLE` | 30..220 | 66..255"),
        mut_all("c_len_ack", DOC30, "LINK_ACK` | N/A | 51 exact", "LINK_ACK` | N/A | 50 exact"),
        mut_all("c_val_clock_drop_reintro", DOC30, "VAL_CLOCK_DROP abolished", "VAL_OK|VAL_TERMINAL|VAL_RETRYABLE|VAL_AUTHORITY|VAL_RECONCILE|VAL_CLOCK_DROP"),
        mut_all("c_drop_val_terminal", DOC30, "| `VAL_TERMINAL` | `NINLIL_PCP_STRUCT` (3)", "| `VAL_GONE` | `NINLIL_PCP_STRUCT` (3)"),
        mut_all("c_cb_before_trusted", DOC30, "**Only** trusted class-D: `status = validation_cb", "validation_cb runs before sample gates: `status = validation_cb"),
        mut_all(
            "c_window_nonzero_nonok",
            DOC30,
            "Non-OK: `out_window` all zero; RW begin 0; registry mutation 0; axes **BUSINESS_ZERO / META_ZERO / PRECHECK_ZERO**.",
            "Non-OK: out_window may retain prior fields.",
        ),
        mut_all("c_discard_shrink", DOC30, "across **all** owners (not only the failing owner)", "only the failing owner"),
        mut_all("c_old_reuse", DOC30, "no old candidate/Permit resume", "may resume same sealed candidate after TEMP"),

        # P1-A/B/C repairs + chunk B U-path
        mut_all(
            "p1a_val_reconcile",
            DOC30,
            "| `VAL_RECONCILE` | `NINLIL_PCP_INVALID_STATE` (2) | `CONTRACT` (28) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `RECONCILE_REQUIRED` |",
            "| `VAL_RECONCILE` | `NINLIL_PCP_CORRUPT_FENCE` (5) | `CONTRACT` (28) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `RECONCILE_REQUIRED` |",
        ),
        mut_all(
            "p1a_val_reconcile_10",
            DOC30,
            "| `VAL_RECONCILE` | `NINLIL_PCP_INVALID_STATE` (2) | `CONTRACT` (28) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `RECONCILE_REQUIRED` |",
            "| `VAL_RECONCILE` | `NINLIL_PCP_CORRUPT_FENCE` (10) | `CONTRACT` (28) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `RECONCILE_REQUIRED` |",
        ),
        mut_all("p1b_unrelated_remain", DOC30, "globally discarded** before/while drain", "may remain only if never quarantined as issued"),
        mut_all("p1b_blob_remain", DOC30, "candidate/group/blob **MUST NOT** remain", "unrelated candidate/group/blob may remain"),
        mut_all("p1c_clock_fault_fc", DOC30, "BUSINESS_ZERO | **F_C_FULL** | **CLOCK_FENCE_COMMITTED**", "BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO"),
        mut_all("p1c_hide_meta", DOC30, "claim business zero while hiding a meta F_c write", "business mutation 0 may hide meta mutation"),
        mut_all("p1c_fc_to_precheck", DOC30, "CLOCK_FENCE_COMMITTED", "PRECHECK_ZERO"),
        mut_all("p1b_u0_normalize", "docs/24-r2-physical-compliance-permit-authority.md", "normalize_fence_code", "fence_code_fixed_NONE"),
        mut_all("p1b_ram_trust_state2", DOC30, "ram_trust.valid **must remain 0**", "ram_trust.valid may be 1 on state2"),
        mut_all("p1b_u6_trusted", DOC30, "trusted_baseline_valid=1", "trusted_baseline_valid_deleted"),

        # Chunk B-2 mut_one false-green kill suite (section-scoped unique anchors)
        # a: U0b only — normalize → fixed STORAGE
        mut_one(
            "b2_a_u0b_normalize_fixed",
            DOC24,
            "fence_code := normalize_fence_code(post_bits, old_RAM_fence_code);",
            "fence_code := STORAGE;  // false-green fixed STORAGE without normalize",
        ),
        # b: U6 only — trusted_baseline_valid → published
        mut_one(
            "b2_b_u6_trusted_to_published",
            DOC24,
            "AND trusted_baseline_valid==1",
            "AND published==1",
        ),
        # c: state2→state1 transition only deleted
        mut_one(
            "b2_c_drop_state2_to_state1",
            DOC24,
            "if old meta_state==INITIAL_UNTRUSTED_FENCED:\n     meta_state=TRUSTED_BASELINE_PRESENT",
            "if old meta_state==INITIAL_UNTRUSTED_FENCED:\n     pass  # state2→state1 deleted",
        ),
        # d: prove old_present MUST equal 1 → 0|1
        mut_one(
            "b2_d_old_present_relax",
            DOC30,
            "**old_present MUST equal 1**",
            "**old_present MUST equal 0|1**",
        ),
        # e: prove CRC verification only deleted
        mut_one(
            "b2_e_drop_prove_crc",
            DOC30,
            "proof_crc32c exact Castagnoli parameters above; ",
            "",
        ),
        # f: prove NOT_FOUND only → retry
        mut_one(
            "b2_f_not_found_retry",
            DOC30,
            "2. **NOT_FOUND** (clean or not) → **ADOPT_CORRUPT** (meta required).",
            "2. **NOT_FOUND** (clean or not) → retry (meta optional).",
        ),
        # g: issue success row only ISSUED_FULL → BUSINESS_ZERO
        mut_one(
            "b2_g_success_issued_to_zero",
            DOC30,
            "| R2 private issue | `NINLIL_PCP_OK` (0) + exact valid snapshot + R5 registry insert OK | ISSUED_FULL | META_ZERO | ISSUED_COMMITTED | `OK_ISSUED` |",
            "| R2 private issue | `NINLIL_PCP_OK` (0) + exact valid snapshot + R5 registry insert OK | BUSINESS_ZERO | META_ZERO | ISSUED_COMMITTED | `OK_ISSUED` |",
        ),
        # h: sample F_c CU row only META_AMBIGUOUS → META_ZERO
        mut_one(
            "b2_h_cu_meta_to_zero",
            DOC30,
            "| `COMMIT_UNKNOWN` / dual-truth (incl. F_c CU) | `SAMPLE_COMMIT_UNKNOWN` | no | BUSINESS_ZERO | META_AMBIGUOUS | AMBIGUOUS |",
            "| `COMMIT_UNKNOWN` / dual-truth (incl. F_c CU) | `SAMPLE_COMMIT_UNKNOWN` | no | BUSINESS_ZERO | META_ZERO | AMBIGUOUS |",
        ),
        # i: state2 baseline rule one place only valid=1 (docs24 Algorithm C wording)
        mut_one(
            "b2_i_state2_valid1",
            DOC24,
            "ram_trust is invalid; trusted baseline is invalid zero baseline",
            "ram_trust is invalid; trusted baseline is valid=1",
        ),
        # i2: docs30 §11.2.3.1 baseline load state2 row only — trusted_baseline_valid 0→1
        mut_one(
            "b2_i2_docs30_state2_trusted_valid1",
            DOC30,
            "| state2 INITIAL_UNTRUSTED_FENCED | 1 | 2 | 0 | zero |",
            "| state2 INITIAL_UNTRUSTED_FENCED | 1 | 2 | 1 | zero |",
        ),
        # extra: callback status2 CONTRACT row → terminal
        mut_one(
            "b2_x_contract_to_terminal",
            DOC30,
            "| `VAL_RECONCILE` | `NINLIL_PCP_INVALID_STATE` (2) | `CONTRACT` (28) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `RECONCILE_REQUIRED` |",
            "| `VAL_RECONCILE` | `NINLIL_PCP_INVALID_STATE` (2) | `CONTRACT` (28) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `TERMINAL_UNISSUED` |",
        ),
        # extra: unknown result META_AMBIGUOUS → META_ZERO
        mut_one(
            "b2_x_unknown_meta_to_zero",
            DOC30,
            "| R2 private issue | status outside 0..23 / unknown | BUSINESS_AMBIGUOUS | META_AMBIGUOUS | AMBIGUOUS |",
            "| R2 private issue | status outside 0..23 / unknown | BUSINESS_AMBIGUOUS | META_ZERO | AMBIGUOUS |",
        ),

        # ===== Chunk C-2 mut_one suite (≥19) =====
        # 1) BURN_CU 4 outcomes
        mut_one(
            "c2_burn_retry_to_seal",
            DOC30,
            "| RETRY_LATER | none | remain BURN_CU; hold resources; TX/ACK 0 |",
            "| RETRY_LATER | SEAL_FAIL exactly once | remain BURN_CU; hold resources; TX/ACK 0 |",
        ),
        mut_one(
            "c2_burn_all_proposed_to_seal",
            DOC30,
            "| ALL_PROPOSED | none | install proposed counter/RAM **exactly once**;",
            "| ALL_PROPOSED | SEAL_FAIL exactly once | install proposed counter/RAM **exactly once**;",
        ),
        mut_one(
            "c2_burn_all_old_to_seal",
            DOC30,
            "| ALL_OLD | none | restore pre-state; retry same preparation burn entry (same template/input); FRAG_ACK→INTENT_RESERVE; no new candidate/token/preparation |",
            "| ALL_OLD | SEAL_FAIL exactly once | restore pre-state; retry same preparation burn entry (same template/input); FRAG_ACK→INTENT_RESERVE; no new candidate/token/preparation |",
        ),
        mut_one(
            "c2_burn_third_drop_seal",
            DOC30,
            "| THIRD/CORRUPT | SEAL_FAIL **exactly once** | active E2E/HOP_COUNTER_BURN, cause COUNTER_CORRUPT, burn_state **AMBIGUOUS** (u8=3), value0 (=no exact counter, not durable-zero), corrupt/namespace fence; no rollback/reuse |",
            "| THIRD/CORRUPT | none | active E2E/HOP_COUNTER_BURN, cause COUNTER_CORRUPT, burn_state **AMBIGUOUS** (u8=3), value0 (=no exact counter, not durable-zero), corrupt/namespace fence; no rollback/reuse |",
        ),
        # 2) HOP outer fail terminal / replacement
        mut_one(
            "c2_hop_allow_same_group_prep",
            DOC30,
            "**no** another hop prep, **no** replacement outer, **no** same-group reuse of that failed outer attempt inside the failed group.",
            "**may** another hop prep and replacement outer inside the failed group.",
        ),
        mut_one(
            "c2_hop_allow_same_e2e_replacement",
            DOC30,
            "L1 **MAY** open a **fresh HOP prep** with **fresh hop DATA counter** and **fresh outer**",
            "L1 **MUST** reuse the failed outer without fresh hop prep",
        ),
        # 3) LENGTH ABI ≥4
        mut_one(
            "c2_len_reintro_pt_domain",
            DOC30,
            "| class | E2E sealed blob domain (bytes) | final outer frame domain (bytes) |",
            "| class | E2E PT domain | outer domain |",
        ),
        mut_one(
            "c2_len_outer_post_burn_none",
            DOC30,
            "| OUTER_POST_SEAL | 1..5 actual final outer | actual final outer len | HOP |",
            "| OUTER_POST_SEAL | 1..5 actual final outer | actual final outer len | NONE |",
        ),
        mut_one(
            "c2_len_allow_same_group_retry",
            DOC30,
            "| OUTER_PRE_BURN_COMPUTE | 1..5 or UNCLASSIFIED(0) | 19+HopPT+16 | NONE | if admitted LINK group: group terminal + no replacement outer; if LOCAL_LINK_ACK pre-group: prep-pair + ACK owner terminal (no group) |",
            "| OUTER_PRE_BURN_COMPUTE | 1..5 or UNCLASSIFIED(0) | 19+HopPT+16 | NONE | LINK group may retry replacement outer in same group |",
        ),
        mut_one(
            "c2_len_link_ack_on_e2e",
            DOC30,
            "**LINK_ACK** is **forbidden** on E2E check phases (E2E_PRE / E2E_POST).",
            "**LINK_ACK** is **allowed** on E2E check phases (E2E_PRE / E2E_POST).",
        ),
        # 4) radio_volatile_work upper-transport only
        mut_one(
            "c2_vol_drop_upper_transport",
            DOC30,
            "  upper-transport queue item,\n",
            "",
        ),
        # 5) SEAL_FAIL phase×cause ≥4
        mut_one(
            "c2_seal_preburn_add_aead",
            DOC30,
            "| PRE_BURN_VALIDATE | STRUCT_INVALID, CONTEXT_UNAVAILABLE, OUTPUT_SHAPE, ALIAS_OR_INTERNAL_CONTRACT |",
            "| PRE_BURN_VALIDATE | STRUCT_INVALID, CONTEXT_UNAVAILABLE, OUTPUT_SHAPE, ALIAS_OR_INTERNAL_CONTRACT, AEAD_FAILURE |",
        ),
        mut_one(
            "c2_seal_e2e_encode_drop_alias",
            DOC30,
            "| E2E_ENCODE | ENCODE_FAILURE, OUTPUT_SHAPE, ALIAS_OR_INTERNAL_CONTRACT |",
            "| E2E_ENCODE | ENCODE_FAILURE, OUTPUT_SHAPE |",
        ),
        mut_one(
            "c2_seal_output_shape_numeric",
            DOC30,
            "OUTPUT_SHAPE` = NULL pointer / capacity / buffer shape only",
            "OUTPUT_SHAPE` = NULL/alias/buffer-shape or numeric length under/over",
        ),
        mut_one(
            "c2_seal_cu_name_as_cause",
            DOC30,
            "§9.3 CU outcome names (`RETRY_LATER`,`ALL_PROPOSED`,`ALL_OLD`,`THIRD`) are **not** seal_cause values.",
            "§9.3 CU outcome names (`RETRY_LATER`,`ALL_PROPOSED`,`ALL_OLD`,`THIRD`) are valid seal_cause values.",
        ),
        # 6) STAMP/FRAME ≥4
        mut_one(
            "c2_stamp_drop_deadline",
            DOC30,
            "enclosing_owner_deadline   : u64\n",
            "",
        ),
        mut_one(
            "c2_stamp_relay_allow_e2e",
            DOC30,
            "| RELAY_DATA | HOP | 1 | E2E_BLOB | 1..4 | DATA |",
            "| RELAY_DATA | E2E | 0 | E2E_PLAINTEXT | 1 | N/A |",
        ),
        mut_one(
            "c2_frame_allow_class0",
            DOC30,
            "length_class      : u8   /* 1..5; never 0 UNCLASSIFIED */",
            "length_class      : u8   /* 0..5; class 0 allowed */",
        ),
        mut_one(
            "c2_frame_w1_retains",
            DOC30,
            "W1 **MUST NOT** read/mutate/free/alias/re-emit sealed slot bytes after emit",
            "W1 may retain and re-emit sealed slot bytes after emit",
        ),
        # extras for coverage
        mut_one(
            "c2_burn_forbid_always_seal_remove",
            DOC30,
            "Forbidden: any blanket rule that “classification後必ずSEAL_FAIL”.",
            "Allowed: classification後必ずSEAL_FAIL.",
        ),
        mut_one(
            "c2_stamp_drop_begin_marker",
            DOC30,
            "EVENT_STAMP_FIELDS_BEGIN",
            "EVENT_STAMP_FIELDS_START",
        ),
        mut_one(
            "c2_frame_drop_ownership_once",
            DOC30,
            "L1 sole post-response access **exactly once** at FRAME_READY",
            "L1 shared post-response access may repeat FRAME_READY",
        ),
        mut_one(
            "c2_len_enum_drop_unclassified",
            DOC30,
            "`0 UNCLASSIFIED` · `1 DATA_SINGLE` · `2 DATA_FRAG_START` · `3 DATA_FRAG_CONT` · `4 DATA_FRAG_ACK` · `5 LINK_ACK`",
            "`0 GONE` · `1 DATA_SINGLE` · `2 DATA_FRAG_START` · `3 DATA_FRAG_CONT` · `4 DATA_FRAG_ACK` · `5 LINK_ACK`",
        ),
        # length_class naming: forbid reintro of shortened FRAG_* as length_class authority
        mut_one(
            "c2_len_enum_short_frag_reintro",
            DOC30,
            "`0 UNCLASSIFIED` · `1 DATA_SINGLE` · `2 DATA_FRAG_START` · `3 DATA_FRAG_CONT` · `4 DATA_FRAG_ACK` · `5 LINK_ACK`",
            "`0 UNCLASSIFIED` · `1 DATA_SINGLE` · `2 FRAG_START` · `3 FRAG_CONT` · `4 FRAG_ACK` · `5 LINK_ACK`",
        ),
        mut_one(
            "c2_len_catalog_drop_data_frag_start",
            DOC30,
            "| `DATA_FRAG_START` | 95..220 | 130..255 |",
            "| `FRAG_START` | 95..220 | 130..255 |",
        ),

        # C-2 false-green kill suite (QA re-audit)
        mut_one(
            "c2_qa_stamp_rogue_field",
            DOC30,
            "outer_route_generation     : u16 /* HOP DATA only; else 0 */\n```",
            "outer_route_generation     : u16 /* HOP DATA only; else 0 */\nrogue_stamp_field          : u8\n```",
        ),
        mut_one(
            "c2_qa_stamp_group_valid_invert",
            DOC30,
            "| LOCAL_SINGLE | HOP | 1 | E2E_BLOB | 1 | DATA |",
            "| LOCAL_SINGLE | HOP | 0 | E2E_BLOB | 1 | DATA |",
        ),
        mut_one(
            "c2_qa_frame_rogue_field",
            DOC30,
            "sealed_len        : u16  /* MUST equal STAMP seal_output_capacity */\n```",
            "sealed_len        : u16  /* MUST equal STAMP seal_output_capacity */\nrogue_frame_field : u8\n```",
        ),
        mut_one(
            "c2_qa_counter_zero_allowed",
            DOC30,
            "counter_value     : u64  /* exact domain 1..UINT64_MAX-1; reject 0 and UINT64_MAX */",
            "counter_value     : u64  /* zero allowed */",
        ),
        mut_one(
            "c2_qa_counter_uint64_max_allowed",
            DOC30,
            "counter_value     : u64  /* exact domain 1..UINT64_MAX-1; reject 0 and UINT64_MAX */",
            "counter_value     : u64  /* exact domain 1..UINT64_MAX; UINT64_MAX allowed */",
        ),
        mut_all(
            "c2_qa_e2e_blob_to_permit",
            DOC30,
            "Permit / R1 / TX_RESULT / OWNER_TERMINAL for that E2E pair = 0",
            "Permit / R1 / TX_RESULT / OWNER_TERMINAL for that E2E pair proceed as sole air path",
        ),
        mut_one(
            "c2_qa_drop_layer_branch",
            DOC30,
            "branch by `frame_layer` (**FRAME_READY_LAYER_BRANCH_CLOSED**; §1.1.1.5):",
            "no layer branch (FRAME_READY_NO_LAYER_BRANCH); all FRAME_READY enter issue:",
        ),
        mut_one(
            "c2_qa_phase1_blanket_e2e",
            DOC30,
            "**E2E fail** ⇔ (`seal_phase=1 PRE_BURN_VALIDATE` ∧ `seal_layer=E2E`) **or** `seal_phase` ∈ {2,3,4} (**SEAL_FAIL_E2E_DEFINITE_VS_POSTBURN_SPLIT**):",
            "**E2E fail** ⇔ `seal_phase` ∈ {1,2,3,4} (phase1 always E2E; FRAG may always retry):",
        ),
        mut_one(
            "c2_qa_phase5_burned_wording",
            DOC30,
            "phase **1 or 5** ⇒ burn_state NONE / counter not consumed; phase **6 or 7** ⇒ HOP durable counter **was** consumed. Forbidden: calling phase **5** “hop prep is burned” as durable-counter language; forbidden blanket “all HOP fail = same LINK group strict terminal” without group-existence check.",
            "phase **5..7** ⇒ hop prep is burned (durable counter always consumed).",
        ),
        mut_one(
            "c2_qa_reintro_already_emitted_outer",
            DOC30,
            "Forbidden wording: “same already-emitted outer”.",
            "LINK_ACK timeout reuses the same already-emitted outer.",
        ),
        mut_one(
            "c2_qa_vol_rogue_member",
            DOC30,
            "  ACK intent/ledger\n",
            "  ACK intent/ledger,\n  rogue_volatile_member\n",
        ),
        mut_one(
            "c2_qa_seal_phase_bind_weaken",
            DOC30,
            "seal_phase `2..4` ⇒ seal_layer **MUST** be `1 E2E`",
            "seal_phase `2..3` ⇒ seal_layer **MUST** be `1 E2E`",
        ),
        mut_one(
            "c2_qa_observed_valid_sometimes",
            DOC30,
            "`observed_valid=0` **iff** the observed length is **unobtainable**",
            "`observed_valid=0` only sometimes when the observed length is **unobtainable**",
        ),
        mut_one(
            "c2_qa_section_order_swap_radio",
            DOC30,
            "##### 1.1.1.3 radio_volatile_work (closed set; CLOCK TEMP/UNCERTAIN discard)",
            "##### 1.1.1.9 radio_volatile_work (closed set; CLOCK TEMP/UNCERTAIN discard)",
        ),
        # P2: observed canonicalization weakenings
        mut_one(
            "c2_p2_obs_valid0_nonzero_observed",
            DOC30,
            "`observed_valid=0` ⇒ `observed=0`",
            "`observed_valid=0` ⇒ `observed` may retain prior non-zero",
        ),
        mut_one(
            "c2_p2_obs_valid1_not_exact",
            DOC30,
            "`observed_valid=1` ⇒ `observed` is the **exact computed or measured byte length**",
            "`observed_valid=1` ⇒ `observed` is approximate length",
        ),
        mut_one(
            "c2_p2_obs_overflow_skip_zero",
            DOC30,
            "`ARITHMETIC_OVERFLOW` ⇒ `observed_valid=0` and `observed=0` always",
            "`ARITHMETIC_OVERFLOW` ⇒ `observed_valid=0` always (observed may be non-zero)",
        ),
        # P2: SEAL_FAIL payload ABI mutations
        mut_one(
            "c2_p2_seal_fields_extra",
            DOC30,
            "observed_outer_len : u16\n```\n**EVENT_SEAL_FAIL_FIELDS_END**",
            "observed_outer_len : u16\nrogue_seal_field : u8\n```\n**EVENT_SEAL_FAIL_FIELDS_END**",
        ),
        mut_one(
            "c2_p2_seal_fields_drop_counter",
            DOC30,
            "counter_value_or_0 : u64  /* 0 if not a definite consumed counter; else burned counter 1..UINT64_MAX-1 */\n",
            "",
        ),
        mut_one(
            "c2_p2_seal_fields_reorder",
            DOC30,
            "seal_layer         : u8   /* 1 E2E | 2 HOP */\nseal_phase         : u8   /* 1..7 closed */",
            "seal_phase         : u8   /* 1..7 closed */\nseal_layer         : u8   /* 1 E2E | 2 HOP */",
        ),
        mut_one(
            "c2_p2_seal_counter_type_widen",
            DOC30,
            "counter_value_or_0 : u64  /* 0 if not a definite consumed counter; else burned counter 1..UINT64_MAX-1 */",
            "counter_value_or_0 : u32  /* 0 if not a definite consumed counter; else burned counter 1..UINT64_MAX-1 */",
        ),
        mut_one(
            "c2_p2_seal_len_valid0_nonzero",
            DOC30,
            "`seal_layer=E2E` ⇒ `outer_len_valid=0` and `expected_outer_len=observed_outer_len=0`",
            "`seal_layer=E2E` ⇒ `outer_len_valid` may be 1 with non-zero outer lengths",
        ),
        mut_one(
            "c2_p2_seal_counter_eq_weaken",
            DOC30,
            "counter_value_or_0` **equals** the burned E2E counter",
            "counter_value_or_0` may differ from the burned E2E counter",
        ),
        # P1-A handoff / release once
        mut_all(
            "c2_p2_drop_immutable_handoff",
            DOC30,
            "immutable handoff/borrow",
            "mutable alias share",
        ),
        mut_all(
            "c2_p2_drop_release_once",
            DOC30,
            "E2E_BLOB_RELEASE_TABLE",
            "E2E_BLOB_RELEASE_MULTI",
        ),
        # Independent QA A–E closures
        mut_one(
            "c2_qa_drop_e2e_counter_embed_eq",
            DOC30,
            "`frame_layer=E2E_BLOB` ⇒ `counter_value` **MUST** be bit-exact equal to the `e2e_counter` field inside the E2E header of the sealed bytes in the L1 output slot.",
            "`frame_layer=E2E_BLOB` ⇒ `counter_value` may differ from the `e2e_counter` field inside the E2E header of the sealed bytes in the L1 output slot.",
        ),
        mut_one(
            "c2_qa_drop_hop_counter_embed_eq",
            DOC30,
            "`frame_layer=OUTER_FRAME` and `length_class` ∈ 1..4 ⇒ `counter_value` **MUST** equal hop **DATA** lane `hop_counter` in the outer header.",
            "`frame_layer=OUTER_FRAME` and `length_class` ∈ 1..4 ⇒ `counter_value` may differ from hop **DATA** lane `hop_counter` in the outer header.",
        ),
        mut_one(
            "c2_qa_allow_counter_mismatch",
            DOC30,
            "On mismatch, field-parse failure, or `sealed_len ≠ seal_output_capacity`: **internal contract violation** — Permit/issue/R1/TX_RESULT = **0**;",
            "On mismatch, field-parse failure, or `sealed_len ≠ seal_output_capacity`: **may still issue Permit** — Permit/issue/R1/TX_RESULT may proceed;",
        ),
        mut_one(
            "c2_qa_mismatch_permit_ok",
            DOC30,
            "Permit/issue/R1/TX_RESULT = **0**; safely terminal that prep pair;",
            "Permit/issue/R1/TX_RESULT may be non-zero after mismatch; soft-fail that prep pair;",
        ),
        mut_one(
            "c2_qa_hop_fail_blanket_group",
            DOC30,
            "HOP_FAIL_TERMINAL_BY_GROUP_EXISTENCE",
            "HOP_FAIL_ALWAYS_SAME_GROUP_STRICT_TERMINAL",
        ),
        mut_one(
            "c2_qa_link_ack_invent_group",
            DOC30,
            "Forbidden: inventing a LINK group for LOCAL_LINK_ACK pre-group fail.",
            "Allowed: inventing a LINK group for LOCAL_LINK_ACK pre-group fail.",
        ),
        mut_one(
            "c2_qa_reintro_blanket_permit_after_frame",
            DOC30,
            "**after FRAME_READY branch (exact):** `E2E_BLOB` → own sealed E2E blob **without** Permit; `OUTER_FRAME` → own sealed outer and **only after** successful issue hold Permit",
            "hold sealed candidate + Permit after FRAME_READY",
        ),
        mut_one(
            "c2_qa_seal_len_both_valid",
            DOC30,
            "both valid=1 forbidden",
            "both valid=1 allowed when independently meaningful",
        ),
        mut_one(
            "c2_qa_seal_len_may_remain",
            DOC30,
            "Forbidden: any “may remain valid on both layers” exception.",
            "e2e may remain valid on HOP failures when independently meaningful.",
        ),
        mut_one(
            "c2_qa_tx_result_drop_common_envelope",
            DOC30,
            "**TX_RESULT exact form = common envelope (§1.1.1) + TX_RESULT-specific fields only (no re-declare/omit of event_schema/event_kind/owner_token/candidate_token):**",
            "**TX_RESULT exact form = TX_RESULT-specific fields only (no re-declare/omit of event_schema/event_kind/owner_token/candidate_token):**",
        ),
        # NO-GO audit P1-1..P1-6 + P2 mutations (final re-audit design)
        mut_one(
            "c2_p1_stamp_drop_seal_input_token",
            DOC30,
            "seal_input_token           : u64 /* L1-minted nonzero unique live borrow */\n",
            "",
        ),
        mut_one(
            "c2_p1_w1_borrow_may_retain",
            DOC30,
            "- W1 **immutable input borrow + exclusive mutable output borrow** lifetime = STAMP accept → that HOP/E2E prep pair’s **exactly one** W1 response; W1 **MUST NOT** retain/free/mutate/alias/re-emit bytes or tokens after response.",
            "- W1 **MAY** retain bytes and token after response.",
        ),
        mut_one(
            "c2_p1_stamp_matrix_link_ack_class1",
            DOC30,
            "| LOCAL_LINK_ACK | HOP | 0 | LINK_ACK_PLAINTEXT | 5 | ACK |",
            "| LOCAL_LINK_ACK | HOP | 0 | LINK_ACK_PLAINTEXT | 1 | ACK |",
        ),
        mut_one(
            "c2_p1_stamp_data_class5",
            DOC30,
            "| LOCAL_SINGLE | HOP | 1 | E2E_BLOB | 1 | DATA |",
            "| LOCAL_SINGLE | HOP | 1 | E2E_BLOB | 5 | DATA |",
        ),
        mut_one(
            "c2_p1_release_early_outer_success",
            DOC30,
            "| individual OUTER prep terminal without group cleanup complete | **no** |",
            "| individual OUTER prep terminal without group cleanup complete | **yes, exactly once** |",
        ),
        mut_one(
            "c2_p1_release_on_ack_wait",
            DOC30,
            "| TX_EDGE_DONE with ACK_REQUESTED=1 (pair closed; group WAIT_LINK_ACK) | **no** |",
            "| TX_EDGE_DONE with ACK_REQUESTED=1 (pair closed; group WAIT_LINK_ACK) | **yes, exactly once** |",
        ),
        mut_one(
            "c2_p1_release_on_timeout",
            DOC30,
            "| LINK_ACK timeout → fresh HOP DATA retry (same group, same blob) | **no** |",
            "| LINK_ACK timeout → fresh HOP DATA retry (same group, same blob) | **yes, exactly once** |",
        ),
        mut_one(
            "c2_p1_ack_req0_wait_ack",
            DOC30,
            "| DATA + outer_ack_requested=0 | terminal-for-pair; receiver ACK TX **0** | close group as UNACKED_LINK_SUCCESS (**no WAIT_LINK_ACK / no ACK timer / no retry**) after sibling/borrow cleanup | release only after cleanup (E2E table) | **release once** after R1 return/TX_RESULT |",
            "| DATA + outer_ack_requested=0 | terminal-for-pair; receiver ACK TX **0** | WAIT_LINK_ACK; may timeout→fresh HOP DATA; **ACK timer path active** (§11.2) | retain | retain through ACK wait |",
        ),
        mut_one(
            "c2_p1_ack_req1_immediate_release",
            DOC30,
            "| DATA + outer_ack_requested=1 | terminal-for-pair / **nonterminal-for-group** (never simply “non-terminal”) | WAIT_LINK_ACK; may timeout→fresh HOP DATA; **ACK timer path active** (§11.2) | retain | **release once** after R1 return/TX_RESULT (OUTER_OUTPUT_SLOT_RELEASE_TABLE); fresh HOP gets fresh OUTER |",
            "| DATA + outer_ack_requested=1 | terminal-for-pair / **nonterminal-for-group** (never simply “non-terminal”) | WAIT_LINK_ACK; may timeout→fresh HOP DATA; **ACK timer path active** (§11.2) | release immediately | retain OUTER through ACK |",
        ),
        mut_one(
            "c2_p1_drop_pregroup_release",
            DOC30,
            "| LINK group admission / copy-own / deadline checked_add **fail** before admitted group (pre-group fail; no pending W1 borrow) | **yes, exactly once** (then close upper owner internally; HOP STAMP/Permit/TX=0; **no** E2E-pair OWNER_TERMINAL/TX_RESULT) |",
            "| LINK group admission / copy-own / deadline checked_add **fail** before admitted group (pre-group fail; no pending W1 borrow) | **no** |",
        ),
        mut_one(
            "c2_p1_ack_lane_as_data",
            DOC30,
            "`frame_layer=OUTER_FRAME` and `length_class=5` (`LINK_ACK`) / `owner_class=LOCAL_LINK_ACK` ⇒ `counter_value` **MUST** equal hop **ACK** lane counter in the outer header (not DATA lane).",
            "`frame_layer=OUTER_FRAME` and `length_class=5` (`LINK_ACK`) / `owner_class=LOCAL_LINK_ACK` ⇒ `counter_value` **MUST** equal hop **DATA** lane counter in the outer header.",
        ),
        mut_one(
            "c2_p1_hop_seal_data_blanket",
            DOC30,
            "Forbidden: blanket “always hop DATA counter”.",
            "HOP_ENCODE/AEAD always hop DATA counter (ACK lane ignored).",
        ),
        mut_one(
            "c2_p1_cu_third_none",
            DOC30,
            "burn_state **AMBIGUOUS** (u8=3), value0 (=no exact counter, not durable-zero)",
            "burn_state **NONE** (u8=0), value0 (durable mutation zero)",
        ),
        mut_one(
            "c2_p1_ambiguous_as_durable_zero",
            DOC30,
            "0 means “no exact counter identity”** — **not** “durable mutation zero”",
            "0 means durable mutation zero",
        ),
        mut_one(
            "c2_p1_tx_result_allow_r2",
            DOC30,
            "result_catalog       : u8   /* exact 1 = R1_HAL only */",
            "result_catalog       : u8   /* REQUIRED closed: R1_HAL | R2_PCP | NONE */",
        ),
        mut_one(
            "c2_p1_tx_result_none_seal_fail",
            DOC30,
            "Fail: SEAL_FAIL/LENGTH_CLASS → OWNER_TERMINAL. Forbidden: E2E_BLOB → Permit/R1/TX_RESULT; pre-R1 class as TX_RESULT; pure local seal-fail as TX_RESULT with catalog NONE.",
            "Seal-fail MAY emit TX_RESULT with result_catalog=NONE.",
        ),
        mut_one(
            "c2_p1_pre_r1_ok_as_tx_result",
            DOC30,
            "| OK_ISSUED | pre-R1 issue success | **none** | enter R1 sole pipeline on same sealed outer + same Permit |",
            "| OK_ISSUED | pre-R1 issue success | TX_RESULT | enter R1 sole pipeline on same sealed outer + same Permit |",
        ),
        mut_one(
            "c2_p1_pre_r1_retry_as_tx_result",
            DOC30,
            "| RETRYABLE_UNISSUED | pre-R1 issue | **none** | L1 re-enters **issue only** on same sealed candidate (retains sealed outer/output slot; no re-stamp/re-seal) |",
            "| RETRYABLE_UNISSUED | pre-R1 issue | TX_RESULT | L1 re-enters **issue only** on same sealed candidate (retains sealed outer/output slot; no re-stamp/re-seal) |",
        ),
        mut_one(
            "c2_p1_tx_map_include_unissued",
            DOC30,
            "| 2 | validate HAL16 NOT_BEFORE RETRY_GATE_OPEN | 11 NOT_BEFORE | 7 PERMIT_VALIDATE | 16 NOT_BEFORE | TX_RETRY_SAME_PERMIT | RETAIN_SEALED | 0 | 0 | pair **nonterminal**; full R1 only same Permit+sealed; calls_used<8; retry_not_before=permit_tx_retry_at | unchanged |",
            "| 2 | RETRYABLE_UNISSUED | 0 | 0 | 0 | TX_RETRY_SAME_SEALED_ISSUE | RETAIN_SEALED | 0 | 0 | pair **nonterminal**; issue only | unchanged |",
        ),
        mut_one(
            "c2_p1_frame_class_mismatch_allow",
            DOC30,
            "FRAME `length_class` **MUST equal** STAMP `requested_length_class` (exact).",
            "FRAME `length_class` may differ from STAMP `requested_length_class` (soft match).",
        ),
        mut_one(
            "c2_p1_missing_e2e_plaintext",
            DOC30,
            "| LOCAL_SINGLE | E2E | 0 | E2E_PLAINTEXT | 1 | N/A |",
            "| LOCAL_SINGLE | E2E | 0 | E2E_BLOB | 1 | N/A |",
        ),
        mut_one(
            "c2_p1_missing_fixed16_ack",
            DOC30,
            "LOCAL_LINK_ACK HOP → `LINK_ACK_PLAINTEXT` **exact 16 bytes**; ACK lane; `outer_ack_requested=0`, route=0, generation=0, remaining=0.",
            "LOCAL_LINK_ACK HOP → `LINK_ACK_PLAINTEXT` variable length; ACK lane; `outer_ack_requested=0`, route=0, generation=0, remaining=0.",
        ),
        mut_one(
            "c2_p1_context_handle_as_pointer",
            DOC30,
            "seal_context_handle        : u64 /* nonzero installed W1 OUTBOUND context handle; never a raw pointer */",
            "seal_context_handle        : pointer /* raw W1 OUTBOUND context pointer */",
        ),
        mut_one(
            "c2_p1_drain_early_free",
            DOC30,
            "Freezes new work/issue for that prep pair only; **MUST NOT** free borrowed inputs or output slots or emit OWNER_TERMINAL until response_observed (§1.1 STAMP_BORROW_CLOSE_HANDSHAKE).",
            "Freezes new work/issue for that prep pair only; MAY free borrowed inputs and emit OWNER_TERMINAL before response_observed.",
        ),
        mut_one(
            "c2_p1_owner_terminal_before_response",
            DOC30,
            "**`response_observed=false` is an explicit higher-priority exception everywhere** (including TEMP immediate discard §1.1.1.3 and generic unissued cleanup §15.3.8): latch cancel/freeze only; **MUST NOT** free/mutate input or output slot; **MUST NOT** emit `OWNER_TERMINAL` early; **MUST NOT** start group/issue/new work; W1 **MUST** finish its exactly-one ordinary response.",
            "**`response_observed=false` is optional**: MAY free/mutate input or output slot; MAY emit `OWNER_TERMINAL` early; MAY start group/issue/new work before W1 response.",
        ),
        mut_one(
            "c2_p2_tx_status_widen",
            DOC30,
            "exact_status         : u32  /* NINLIL_RADIO_HAL status; matches radio_hal.h */",
            "exact_status         : u64  /* NINLIL_RADIO_HAL status; matches radio_hal.h */",
        ),
        mut_one(
            "c2_p2_tx_drop_reason",
            DOC30,
            "reason               : u32  /* NINLIL_RADIO_HAL reason */\n",
            "",
        ),
        mut_one(
            "c2_p2_drain_drop_reason",
            DOC30,
            "drain_reason      : u8  /* 1 AMBIGUOUS_OR_FENCE | 2 OPERATOR | 3 RECOVERY */\n",
            "",
        ),
        mut_one(
            "c2_p2_owner_kind_widen",
            DOC30,
            "terminal_kind : u8  /* 1 TERMINAL | 2 STALE_NO_RETRY */",
            "terminal_kind : u16  /* 1 TERMINAL | 2 STALE_NO_RETRY */",
        ),
        mut_one(
            "c2_p2_length_evt_reorder",
            DOC30,
            "length_class       : u8  /* 0..5 closed §1.1.1.2 */\ncheck_phase        : u8  /* 1..4 closed */",
            "check_phase        : u8  /* 1..4 closed */\nlength_class       : u8  /* 0..5 closed §1.1.1.2 */",
        ),
        mut_all(
            "c2_p2_drop_e2e_transferred_closed",
            DOC30,
            "E2E_TRANSFERRED_CLOSED",
            "E2E_STILL_LIVE",
        ),
        mut_one(
            "c2_p1_e2e_transferred_remains_live",
            DOC30,
            "That prep pair transitions exactly once to internal state **`E2E_TRANSFERRED_CLOSED`** (leaves live prep-pair set / drain targets; **no** OWNER_TERMINAL/TX_RESULT event).",
            "That prep pair remains live in internal state **`E2E_TRANSFERRED_CLOSED`** (leaves live prep-pair set / drain targets; **no** OWNER_TERMINAL/TX_RESULT event).",
        ),
        mut_one(
            "c2_p1_path_swap_lanes",
            DOC30,
            "| **DATA outer** | admitted LINK group; owner_class ∈ {LOCAL_SINGLE, LOCAL_FRAGMENT, RELAY_DATA, LOCAL_FRAG_ACK} HOP | **DATA** |",
            "| **DATA outer** | admitted LINK group; owner_class ∈ {LOCAL_SINGLE, LOCAL_FRAGMENT, RELAY_DATA, LOCAL_FRAG_ACK} HOP | **ACK** |",
        ),

        # ===== C2 re-audit 2026-07-18 (logical C ABI / output slot / PRE_R1 11 / TX closed / FIRST_FRAG / ACK0) =====
        mut_one(
            "c2_r_event_schema_widen",
            DOC30,
            "event_schema    : u16  /* exact 1 */",
            "event_schema    : u32  /* exact 1 */",
        ),
        mut_one(
            "c2_r_event_kind_widen",
            DOC30,
            "event_kind      : u8   /* exact 1..7 as table below */",
            "event_kind      : u16  /* exact 1..7 as table below */",
        ),
        mut_one(
            "c2_r_tx_consume_widen",
            DOC30,
            "consume_invoked      : u8   /* 0|1; whether R1 entered the consume callback (not success/mutation) */",
            "consume_invoked      : u16  /* 0|1; whether R1 entered the consume callback (not success/mutation) */",
        ),
        mut_one(
            "c2_r_tx_edge_widen",
            DOC30,
            "edge_invoked         : u8   /* 0|1; whether R1 entered the edge callback (not success) */",
            "edge_invoked         : u32  /* 0|1; whether R1 entered the edge callback (not success) */",
        ),
        mut_one(
            "c2_r_tx_retry_elig_widen",
            DOC30,
            "retry_eligible       : u8   /* 0|1 */",
            "retry_eligible       : u16  /* 0|1 */",
        ),
        mut_one(
            "c2_r_seal_burn_enum",
            DOC30,
            "burn_state         : u8   /* 0 NONE | 1 E2E | 2 HOP | 3 AMBIGUOUS */",
            "burn_state         : enum /* NONE | E2E | HOP | AMBIGUOUS */",
        ),
        mut_one(
            "c2_r_frame_burn_enum",
            DOC30,
            "burn_state        : u8   /* 1 E2E | 2 HOP */",
            "burn_state        : enum /* E2E | HOP */",
        ),
        mut_one(
            "c2_r_drop_output_token",
            DOC30,
            "seal_output_token          : u64 /* L1-minted nonzero unique live output slot */\n",
            "",
        ),
        mut_one(
            "c2_r_drop_output_capacity",
            DOC30,
            "seal_output_capacity       : u16 /* exact precomputed required sealed output length */\n",
            "",
        ),
        mut_one(
            "c2_r_allow_alias_io",
            DOC30,
            "Input and output spans **MUST NOT** overlap/alias.",
            "Input and output spans MAY overlap/alias.",
        ),
        mut_one(
            "c2_r_pre_r1_drop_ok",
            DOC30,
            "| OK_ISSUED | pre-R1 issue success | **none** | enter R1 sole pipeline on same sealed outer + same Permit |\n",
            "",
        ),
        mut_one(
            "c2_r_pre_r1_swap_fifo_phase",
            DOC30,
            "| FIFO_OUT_OF_ORDER | **R1-only** | if illegally surfaced pre-R1: DRAIN_QUARANTINE then OWNER_TERMINAL (contract violation) | **not** a legal pre-R1 issue class; **no** invented TX_RESULT |",
            "| FIFO_OUT_OF_ORDER | pre-R1 issue | TX_RESULT | invent TX_RESULT for FIFO pre-R1 |",
        ),
        mut_one(
            "c2_r_tx_reintro_drop_volatile",
            DOC30,
            "`1 TX_EDGE_DONE` · `2 TX_RETRY_SAME_PERMIT` · `3 TX_QUARANTINE` · `4 TX_STALE_NO_RETRY`",
            "`1 TX_EDGE_DONE` · `2 TX_RETRY_SAME_PERMIT` · `3 TX_DROP_VOLATILE` · `4 TX_QUARANTINE` · `5 TX_STALE_NO_RETRY`",
        ),
        # external false-green kill: append dead code while keeping 1..4 substring intact
        # (mut_one forbids old remaining as substring of new; use custom append)
        (
            "c2_ext_dead_tx_code_append5",
            DOC30,
            (lambda t: (
                t
                if t.count(
                    "`1 TX_EDGE_DONE` · `2 TX_RETRY_SAME_PERMIT` · `3 TX_QUARANTINE` · `4 TX_STALE_NO_RETRY`"
                )
                != 1
                else t.replace(
                    "`1 TX_EDGE_DONE` · `2 TX_RETRY_SAME_PERMIT` · `3 TX_QUARANTINE` · `4 TX_STALE_NO_RETRY`",
                    "`1 TX_EDGE_DONE` · `2 TX_RETRY_SAME_PERMIT` · `3 TX_QUARANTINE` · `4 TX_STALE_NO_RETRY` · `5 TX_DROP_VOLATILE`",
                    1,
                )
            )),
        ),
        (
            "c2_ext_dead_disp_code_append4",
            DOC30,
            (lambda t: (
                t
                if t.count("`1 RETAIN_SEALED` · `2 QUARANTINE` · `3 STALE_NO_RETRY`") != 1
                else t.replace(
                    "`1 RETAIN_SEALED` · `2 QUARANTINE` · `3 STALE_NO_RETRY`",
                    "`1 RETAIN_SEALED` · `2 QUARANTINE` · `3 STALE_NO_RETRY` · `4 TERMINAL`",
                    1,
                )
            )),
        ),
        # external false-green kill: FRAME token/capacity soft mismatch
        mut_one(
            "c2_ext_frame_token_mismatch",
            DOC30,
            "FRAME `seal_output_token` **MUST equal** STAMP `seal_output_token`; `sealed_len` **MUST equal** STAMP `seal_output_capacity`.",
            "FRAME seal_output_token MAY differ from STAMP; sealed_len MAY be smaller.",
        ),
        mut_one(
            "c2_r_tx_noedge_local_terminal",
            DOC30,
            "| 11 | All other failures **before** consume callback entry, excluding exact validate HAL16 rows 2–3 (args/live/time/digest/validate/pre-consume seq/shape/default/EXPIRED at validate etc., not status=11/stage=7/reason=16) | exact closed R1 status/stage/reason for that reject | (as R1) | (as R1) | TX_QUARANTINE | QUARANTINE | 0 | 0 | pair nonterminal quarantine; OK_ISSUED exists ⇒ drain (never local TX_TERMINAL/release) | as drain |",
            "| 11 | All failures **before** consume callback entry | 0 | 0 | 0 | TX_TERMINAL | TERMINAL | 0 | 0 | pair terminal local release without drain | group terminal |",
        ),
        mut_one(
            "c2_r_pending_e2e_creates_group",
            DOC30,
            "- Pending receives **E2E** `FRAME_READY`: **no** new LINK group / HOP; close E2E prep internally (`E2E_TRANSFERRED_CLOSED` not reopened); release output slot **exactly once** after response_observed; close upper owner per exact cancel/drain timing; **no** E2E-pair OWNER_TERMINAL/TX_RESULT.",
            "- Pending receives **E2E** `FRAME_READY`: create new LINK group and HOP; keep slot leaked; emit E2E OWNER_TERMINAL early.",
        ),
        mut_one(
            "c2_r_first_start_final_pt",
            DOC30,
            "| LOCAL_FRAGMENT | E2E | 0 | FIRST_FRAG_START_TEMPLATE | 2 | N/A |",
            "| LOCAL_FRAGMENT | E2E | 0 | E2E_PLAINTEXT | 2 | N/A |",
        ),
        mut_one(
            "c2_r_first_template_omit",
            DOC30,
            "seal_input_kind            : u8  /* 1 E2E_PLAINTEXT | 2 E2E_BLOB | 3 LINK_ACK_PLAINTEXT | 4 FIRST_FRAG_START_TEMPLATE */",
            "seal_input_kind            : u8  /* 1 E2E_PLAINTEXT | 2 E2E_BLOB | 3 LINK_ACK_PLAINTEXT */",
        ),
        mut_one(
            "c2_r_handle_overwrite_retry",
            DOC30,
            "E2E START **retry after first** uses `E2E_PLAINTEXT` carrying original **nonzero** `transfer_handle`; fresh `e2e_counter` **MUST NOT** overwrite handle.",
            "E2E START **retry after first** overwrites `transfer_handle` with fresh `e2e_counter`.",
        ),
        mut_one(
            "c2_r_ack0_computes_timer",
            DOC30,
            "- **`outer_ack_requested=0`:** **skip** ACK timer / `ack_deadline` / `interval_at` / `eligible_at` computation entirely; timer overflow **cannot** fail that path.",
            "- **`outer_ack_requested=0`:** still compute `ack_deadline`/`interval_at`/`eligible_at` and WAIT_LINK_ACK.",
        ),
        mut_one(
            "c2_r_ack1_skips_timer",
            DOC30,
            "- **`outer_ack_requested=1`:** `ack_deadline = checked_add(prior_tx_mono, link_ack_wait_ms)`; `interval_at = checked_add(prior_tx_mono, link_retry_interval_ms)`; `eligible_at = max(ack_deadline, interval_at)` (checked_add overflow ⇒ terminal fail).",
            "- **`outer_ack_requested=1`:** skip ACK timer computation entirely.",
        ),
        mut_one(
            "c2_r_reintro_little_endian",
            DOC30,
            "Borrow spans: non-NULL pointers + exact `u16` lengths; no LE/BE packing of the event itself.",
            "Portable C: integer fields little-endian fixed width; borrow spans non-NULL.",
        ),
        mut_one(
            "c2_r_frame_sealed_bytes_pointer",
            DOC30,
            "sealed_len        : u16  /* MUST equal STAMP seal_output_capacity */\n```",
            "sealed_len        : u16  /* MUST equal STAMP seal_output_capacity */\nsealed_bytes      : exact owned bytes of length sealed_len\n```",
        ),

        # ===== P1-1..P1-6 re-audit mutations =====
        mut_one(
            "c2_p1_hal45_consume0",
            DOC30,
            "| 6 | consume HAL45 CONSUME_BUSY RETRY_GATE_OPEN | 6 CONSUME_DENIED | 8 PERMIT_CONSUME | 45 CONSUME_BUSY | TX_RETRY_SAME_PERMIT | RETAIN_SEALED | 1 | 0 | pair **nonterminal**; full R1 only same Permit+sealed; calls_used<8; retry_not_before=permit_tx_retry_at | unchanged |",
            "| 6 | consume HAL45 CONSUME_BUSY RETRY_GATE_OPEN | 6 CONSUME_DENIED | 8 PERMIT_CONSUME | 45 CONSUME_BUSY | TX_RETRY_SAME_PERMIT | RETAIN_SEALED | 0 | 0 | pair **nonterminal**; full R1 only same Permit+sealed; calls_used<8; retry_not_before=permit_tx_retry_at | unchanged |",
        ),
        mut_one(
            "c2_p1_hal43_consume0",
            DOC30,
            "| 9 | FIFO HAL43 (consume callback entered) | 6 CONSUME_DENIED | 8 PERMIT_CONSUME | 43 FIFO_OUT_OF_ORDER | TX_QUARANTINE | QUARANTINE | 1 | 0 | pair nonterminal quarantine; DRAIN + OWNER_TERMINAL after proof | as drain |",
            "| 9 | FIFO HAL43 (consume callback entered) | 6 CONSUME_DENIED | 8 PERMIT_CONSUME | 43 FIFO_OUT_OF_ORDER | TX_QUARANTINE | QUARANTINE | 0 | 0 | pair nonterminal quarantine; DRAIN + OWNER_TERMINAL after proof | as drain |",
        ),
        mut_one(
            "c2_p1_hal44_consume0",
            DOC30,
            "| 10 | CLOCK HAL44 (consume callback entered) | 6 CONSUME_DENIED | 8 PERMIT_CONSUME | 44 CONSUME_CLOCK_UNCERTAIN | TX_QUARANTINE | QUARANTINE | 1 | 0 | pair nonterminal quarantine; global volatile freeze only borrow-safe/drain-safe; DRAIN + OWNER_TERMINAL | as drain |",
            "| 10 | CLOCK HAL44 (consume callback entered) | 6 CONSUME_DENIED | 8 PERMIT_CONSUME | 44 CONSUME_CLOCK_UNCERTAIN | TX_QUARANTINE | QUARANTINE | 0 | 0 | pair nonterminal quarantine; global volatile freeze only borrow-safe/drain-safe; DRAIN + OWNER_TERMINAL | as drain |",
        ),
        mut_one(
            "c2_p1_merge_pre_post_consume",
            DOC30,
            "| 11 | All other failures **before** consume callback entry, excluding exact validate HAL16 rows 2–3 (args/live/time/digest/validate/pre-consume seq/shape/default/EXPIRED at validate etc., not status=11/stage=7/reason=16) | exact closed R1 status/stage/reason for that reject | (as R1) | (as R1) | TX_QUARANTINE | QUARANTINE | 0 | 0 | pair nonterminal quarantine; OK_ISSUED exists ⇒ drain (never local TX_TERMINAL/release) | as drain |",
            "| 11 | All failures before or after consume | exact closed R1 | (as R1) | (as R1) | TX_QUARANTINE | QUARANTINE | 0 or 1 | 0 | pair nonterminal quarantine | as drain |",
        ),
        mut_one(
            "c2_p1_permit_seq_allow0",
            DOC30,
            "permit_sequence      : u64  /* exact bound issued Permit sequence; domain 1..UINT64_MAX-1 */",
            "permit_sequence_or_0 : u64  /* 0 if no bound Permit; else sequence */",
        ),
        mut_one(
            "c2_p1_success_stage0",
            DOC30,
            "`exact_status=0` (`NINLIL_RADIO_HAL_OK`) · `stage=10` (`NINLIL_RADIO_HAL_STAGE_EDGE`) · `reason=0` (`NINLIL_RADIO_HAL_REASON_NONE`).",
            "`exact_status=0` (`NINLIL_RADIO_HAL_OK`) · `stage=0` · `reason` = caller out_error unchanged.",
        ),
        mut_one(
            "c2_p1_length_drop_counter",
            DOC30,
            "counter_value_or_0 : u64 /* 0 if burn_state=NONE; else exact burned layer/lane counter 1..UINT64_MAX-1 */\n",
            "",
        ),
        mut_all(
            "c2_p1_drop_handle_latch",
            DOC30,
            "FIRST_FRAG_HANDLE_LATCH_RESPONSE_CLOSED",
            "FIRST_FRAG_HANDLE_NO_LATCH",
        ),
        mut_one(
            "c2_p1_definite_fail_frag_retry",
            DOC30,
            "**Pre-burn / definite allocation fail** (`PRE_BURN_VALIDATE` or `E2E_COUNTER_BURN` with `COUNTER_DEFINITE_FAILURE` / pre-write `COUNTER_CORRUPT`; burn_state NONE; burn count/counter mutation 0): terminally fails the owning fragmented transfer or SINGLE; **no** fresh prep, **no** retry; first-START `transfer_handle` remains **unset** (P1-5 / §15.1).",
            "**Pre-burn / definite allocation fail**: FRAG may open next bounded fresh E2E prep if budget remains; SINGLE terminal.",
        ),
        mut_one(
            "c2_p1_outer_release_on_retry",
            DOC30,
            "| TX_RETRY_SAME_PERMIT | **no** — retain same exact outer slot |",
            "| TX_RETRY_SAME_PERMIT | **yes, exactly once** |",
        ),
        mut_one(
            "c2_p1_outer_retain_ack_wait",
            DOC30,
            "| TX_EDGE_DONE (ACK0 or ACK1) after synchronous R1 return + TX_RESULT dispatch | **yes, exactly once** (OUTER only; E2E group blob separate per E2E_BLOB_RELEASE_TABLE; ACK1 **MUST NOT** retain old OUTER; ACK timeout fresh HOP allocates **fresh** OUTER slot) |",
            "| TX_EDGE_DONE (ACK0 or ACK1) after synchronous R1 return + TX_RESULT dispatch | **no** — retain OUTER through ACK wait |",
        ),
        mut_one(
            "c2_p1_slot_registry_129",
            DOC30,
            "| **L1 Seal output slot registry** | **128** live slots max |",
            "| **L1 Seal output slot registry** | **129** live slots max |",
        ),
        mut_one(
            "c2_p1_reintro_r1_unissued_local",
            DOC30,
            "**MUST** enter §15.3.3 drain / TX_QUARANTINE path; **no** mutation-0 unissued-proven local-terminal branch in R1 (unissued terminal is PRE_R1 only → OWNER_TERMINAL)",
            "if mutation-0 unissued proven ⇒ owner/group terminal without drain",
        ),

        # ===== P2 R1_RESULT_EXPECTED strict §15.3.4 set-equality =====
        mut_one(
            "c2_p2_r1_success_action_drift",
            DOC30,
            "| `NINLIL_RADIO_HAL_OK` | consume succeeded and sole TX edge was invoked once; increment hop air attempt; candidate/Permit never reusable |",
            "| `NINLIL_RADIO_HAL_OK` | soft success; may skip edge; hop air attempt optional |",
        ),
        mut_one(
            "c2_p2_r1_hal45_retry_row_drift",
            DOC30,
            "| `NINLIL_RADIO_HAL_CONSUME_DENIED` at `PERMIT_CONSUME` with typed reason **45 CONSUME_BUSY** only, edge 0 | raw retryable tuple (consume HAL45; consume callback entered); L1 **RETRY_GATE** OPEN/CLOSED exclusive per §1.1.2 TX_RESULT_RETRY_GATE |",
            "| `NINLIL_RADIO_HAL_CONSUME_DENIED` at `PERMIT_CONSUME` with typed reason **45 CONSUME_BUSY** only, edge 0 | drop Permit; no retry; owner terminal |",
        ),
        mut_one(
            "c2_p2_r1_row_delete_expired",
            DOC30,
            "| `NINLIL_RADIO_HAL_EXPIRED` | **MUST NOT** treat `advance_expired_heads` alone as cleanup; enter §15.3.3 exported private-module drain |\n",
            "",
        ),
        mut_one(
            "c2_p2_r1_row_reorder_ok_edge",
            DOC30,
            "| `NINLIL_RADIO_HAL_OK` | consume succeeded and sole TX edge was invoked once; increment hop air attempt; candidate/Permit never reusable |\n| `NINLIL_RADIO_HAL_NOT_BEFORE` at validate/time (HAL reason **16**), edge invocation 0 | raw retryable tuple (validate HAL16); L1 **RETRY_GATE** OPEN/CLOSED exclusive per §1.1.2 TX_RESULT_RETRY_GATE (OPEN ⇒ same-Permit full R1 only +100ms; CLOSED ⇒ TX_QUARANTINE/drain) |",
            "| `NINLIL_RADIO_HAL_NOT_BEFORE` at validate/time (HAL reason **16**), edge invocation 0 | raw retryable tuple (validate HAL16); L1 **RETRY_GATE** OPEN/CLOSED exclusive per §1.1.2 TX_RESULT_RETRY_GATE (OPEN ⇒ same-Permit full R1 only +100ms; CLOSED ⇒ TX_QUARANTINE/drain) |\n| `NINLIL_RADIO_HAL_OK` | consume succeeded and sole TX edge was invoked once; increment hop air attempt; candidate/Permit never reusable |",
        ),

        # ===== external false-green kill suite (root 8 MISSes) =====
        mut_one(
            "c2_ext_ok_issued_local_release",
            DOC30,
            "After **OK_ISSUED**, every non-OPEN-retry edge=0 R1 result **MUST** enter `TX_QUARANTINE`/DRAIN (issued existence).",
            "After **OK_ISSUED**, every non-OPEN-retry edge=0 R1 result may local release allowed without drain.",
        ),
        mut_one(
            "c2_ext_permit_domain_0",
            DOC30,
            "**permit_sequence (exact):** domain **1..UINT64_MAX-1**.",
            "**permit_sequence (exact):** domain **0..UINT64_MAX-1**.",
        ),
        mut_one(
            "c2_ext_permit_may_differ",
            DOC30,
            "Every valid TX_RESULT is after OK_ISSUED and **MUST** bit-exact equal the bound issued Permit sequence for this owner/candidate.",
            "Every valid TX_RESULT is after OK_ISSUED and may differ from the bound issued Permit sequence for this owner/candidate.",
        ),
        mut_one(
            "c2_ext_length_none_nonzero",
            DOC30,
            "- `burn_state=0 NONE` ⇒ `counter_value_or_0=0`.",
            "- `burn_state=0 NONE` ⇒ `counter_value_or_0` may be nonzero.",
        ),
        mut_one(
            "c2_ext_length_e2e_zero_max",
            DOC30,
            "- `burn_state=1 E2E` or `2 HOP` ⇒ `counter_value_or_0` = exact burned layer/lane counter ∈ **1..UINT64_MAX-1**.",
            "- `burn_state=1 E2E` or `2 HOP` ⇒ `counter_value_or_0` may be 0 or MAX.",
        ),
        mut_one(
            "c2_ext_slot_parse_allowed",
            DOC30,
            "**Forbidden:** parse a failed/mismatched output slot to recover handle.",
            "**Allowed:** parse a failed/mismatched output slot to recover handle.",
        ),
        mut_one(
            "c2_ext_handle_may_overwrite",
            DOC30,
            "Later retry uses `E2E_PLAINTEXT` with that original **nonzero** handle; fresh counters **MUST NOT** overwrite it.",
            "Later retry uses `E2E_PLAINTEXT` with that original **nonzero** handle; fresh counters may overwrite it.",
        ),
        mut_one(
            "c2_ext_outer_tq_yes_before_proof",
            DOC30,
            "| TX_QUARANTINE | **no** until drain/proof; then **yes, exactly once** with terminal cleanup |",
            "| TX_QUARANTINE | **yes before proof** |",
        ),
        # §15.1 scoped (phrase occurs twice; mutate §15.1 occurrence with unique context)
        mut_one(
            "c2_ext_s151_definite_counter_fail",
            DOC30,
            "1. Durable E2E counter **allocate/burn** (§9); on **successful durable burn** increment `e2e_prepare_burn_count`. **Definite counter-allocation failure before durable burn** (phase `E2E_COUNTER_BURN` / pre-write fail): terminally fails the owning fragmented transfer or SINGLE; **no** fresh prep, **no** retry; handle remains **unset**; burn count/counter mutation **0** (set-equal §1.1.1 SEAL_FAIL_E2E_DEFINITE_VS_POSTBURN_SPLIT).",
            "1. Durable E2E counter **allocate/burn** (§9); on **successful durable burn** increment `e2e_prepare_burn_count`. **Definite counter-allocation failure before durable burn** (phase `E2E_COUNTER_BURN` / pre-write fail): FRAG may open next bounded fresh E2E prep if budget remains; handle optional.",
        ),

        # P1: second exact-header R1 table in §15.3.4 after valid 7-row table must reject
        mut_one(
            "c2_p1_dup_r1_header_table",
            DOC30,
            (
                "| `NINLIL_RADIO_HAL_CONSUME_FENCED`, `CONSUME_ERROR`, `PERMIT_DENIED`, `PERMIT_ERROR`, `BUSY`, "
                "`FRAME_MISMATCH`, `SEQ_REUSE`, `LIVE_MISMATCH`, `UNSUPPORTED`, `SEQ_EXHAUSTED`, invalid/default-deny, "
                "any stage/reason/plan-shape mismatch, or unknown with edge invocation 0 | no same-Permit reuse; "
                "R1 is entered **only after OK_ISSUED** ⇒ issued existence; **MUST** enter §15.3.3 drain / TX_QUARANTINE path; "
                "**no** mutation-0 unissued-proven local-terminal branch in R1 (unissued terminal is PRE_R1 only → OWNER_TERMINAL) |\n\n"
                "R1 exposes no retryable consume-unknown/COMMIT_UNKNOWN."
            ),
            (
                "| `NINLIL_RADIO_HAL_CONSUME_FENCED`, `CONSUME_ERROR`, `PERMIT_DENIED`, `PERMIT_ERROR`, `BUSY`, "
                "`FRAME_MISMATCH`, `SEQ_REUSE`, `LIVE_MISMATCH`, `UNSUPPORTED`, `SEQ_EXHAUSTED`, invalid/default-deny, "
                "any stage/reason/plan-shape mismatch, or unknown with edge invocation 0 | no same-Permit reuse; "
                "R1 is entered **only after OK_ISSUED** ⇒ issued existence; **MUST** enter §15.3.3 drain / TX_QUARANTINE path; "
                "**no** mutation-0 unissued-proven local-terminal branch in R1 (unissued terminal is PRE_R1 only → OWNER_TERMINAL) |\n\n"
                "| exact R1 result | action |\n"
                "| --- | --- |\n"
                "| `NINLIL_RADIO_HAL_OK` | edge may be skipped and Permit may be reused |\n\n"
                "R1 exposes no retryable consume-unknown/COMMIT_UNKNOWN."
            ),
        ),

        # ===== self-test polarity / exclusivity / multi-header kill suite (+9) =====
        # Append after exact OUTER sentence (retain canonical; old not substring of new via following marker).
        mut_one(
            "outer_old_semantics_append",
            DOC30,
            (
                "**MUST NOT** retain old OUTER through ACK wait, fresh HOP retry, or group cleanup.  \n"
                "   Duplicate W1 response"
            ),
            (
                "**MUST NOT** retain old OUTER through ACK wait, fresh HOP retry, or group cleanup. "
                "OUTER retains output slot through issue/R1/group cleanup.  \n"
                "   Duplicate W1 response"
            ),
        ),
        mut_one(
            "outer_case_wording_append",
            DOC30,
            (
                "**MUST NOT** retain old OUTER through ACK wait, fresh HOP retry, or group cleanup.  \n"
                "   Duplicate W1 response"
            ),
            (
                "**MUST NOT** retain old OUTER through ACK wait, fresh HOP retry, or group cleanup. "
                "OUTER HOLDS THE OLD SLOT UNTIL ACK WAIT AND GROUP CLEANUP.  \n"
                "   Duplicate W1 response"
            ),
        ),
        mut_one(
            "tx_row1_stage_10_to_0",
            DOC30,
            "| 1 | OK: consume success + sole TX edge entered once | 0 OK | 10 EDGE | 0 NONE | TX_EDGE_DONE | STALE_NO_RETRY | 1 | 1 | pair **terminal exactly once** | per **TX_EDGE_DONE_ACK_POLICY** |",
            "| 1 | OK: consume success + sole TX edge entered once | 0 OK | 0 UNKNOWN | 0 NONE | TX_EDGE_DONE | STALE_NO_RETRY | 1 | 1 | pair **terminal exactly once** | per **TX_EDGE_DONE_ACK_POLICY** |",
        ),
        mut_one(
            "tx_row7_include_hal16",
            DOC30,
            "excluding exact validate HAL16 rows 2–3",
            "including exact validate HAL16 rows 2–3",
        ),
        mut_one(
            "tx_row8_include_hal45",
            DOC30,
            "excluding exact consume HAL16 rows 4–5, consume HAL45 rows 6–7, HAL43 row 9, HAL44 row 10",
            "including exact consume HAL45 rows 6–7",
        ),
        mut_one(
            "tx_row8_include_hal43",
            DOC30,
            "excluding exact consume HAL16 rows 4–5, consume HAL45 rows 6–7, HAL43 row 9, HAL44 row 10",
            "including exact HAL43 row 9",
        ),
        mut_one(
            "tx_row8_include_hal44",
            DOC30,
            "excluding exact consume HAL16 rows 4–5, consume HAL45 rows 6–7, HAL43 row 9, HAL44 row 10",
            "including exact HAL44 row 10",
        ),
        mut_one(
            "ack_duplicate_canonical_plus_legacy",
            DOC30,
            (
                "Never call TX_EDGE_DONE simply “non-terminal” without pair/group split. "
                "R1 retry TX_RESULT is nonterminal for pair; terminal R1 outcomes close pair.\n\n"
                "**Order (exact; sole air path is OUTER only / OUTER sole air path):**"
            ),
            (
                "Never call TX_EDGE_DONE simply “non-terminal” without pair/group split. "
                "R1 retry TX_RESULT is nonterminal for pair; terminal R1 outcomes close pair.\n\n"
                "| path | TX_EDGE_DONE meaning | group state | E2E slot | OUTER slot |\n"
                "| --- | --- | --- | --- | --- |\n"
                "| DATA + outer_ack_requested=1 | soft non-terminal | WAIT_LINK_ACK | retain | retain |\n\n"
                "| path | TX_EDGE_DONE meaning | group state | E2E slot |\n"
                "| --- | --- | --- | --- |\n"
                "| DATA + outer_ack_requested=1 | soft non-terminal | WAIT_LINK_ACK | retain |\n\n"
                "**Order (exact; sole air path is OUTER only / OUTER sole air path):**"
            ),
        ),
        mut_one(
            "frame_layer_duplicate_canonical_plus_legacy",
            DOC30,
            (
                "| frame_layer | length_class | burn_state (u8) | domain |\n"
                "| --- | --- | --- | --- |\n"
                "| E2E_BLOB | 1..4 | 1 E2E | E2E sealed blob in L1 output slot |\n"
                "| OUTER_FRAME | 1..5 | 2 HOP | final outer frame in L1 output slot |\n\n"
                "**counter_value (exact):**"
            ),
            (
                "| frame_layer | length_class | burn_state (u8) | domain |\n"
                "| --- | --- | --- | --- |\n"
                "| E2E_BLOB | 1..4 | 1 E2E | E2E sealed blob in L1 output slot |\n"
                "| OUTER_FRAME | 1..5 | 2 HOP | final outer frame in L1 output slot |\n\n"
                "| frame_layer | length_class | burn_state (u8) | domain |\n"
                "| --- | --- | --- | --- |\n"
                "| E2E_BLOB | 1..4 | 1 E2E | soft domain |\n\n"
                "| frame_layer | length_class | burn_state | domain |\n"
                "| --- | --- | --- | --- |\n"
                "| E2E_BLOB | 1..4 | 1 E2E | legacy domain |\n\n"
                "**counter_value (exact):**"
            ),
        ),
        # sentence-by-sentence OUTER polarity kill suite (+3; keep canonical exact sentence)
        mut_one(
            "outer_retained_until_ack_wait",
            DOC30,
            (
                "**MUST NOT** retain old OUTER through ACK wait, fresh HOP retry, or group cleanup.  \n"
                "   Duplicate W1 response"
            ),
            (
                "**MUST NOT** retain old OUTER through ACK wait, fresh HOP retry, or group cleanup. "
                "OLD OUTER WAS RETAINED UNTIL ACK WAIT.  \n"
                "   Duplicate W1 response"
            ),
        ),
        mut_one(
            "outer_keep_through_fresh_hop",
            DOC30,
            (
                "**MUST NOT** retain old OUTER through ACK wait, fresh HOP retry, or group cleanup.  \n"
                "   Duplicate W1 response"
            ),
            (
                "**MUST NOT** retain old OUTER through ACK wait, fresh HOP retry, or group cleanup. "
                "THROUGH FRESH HOP RETRY, KEEP OUTER.  \n"
                "   Duplicate W1 response"
            ),
        ),
        mut_one(
            "outer_held_for_group_cleanup",
            DOC30,
            (
                "**MUST NOT** retain old OUTER through ACK wait, fresh HOP retry, or group cleanup.  \n"
                "   Duplicate W1 response"
            ),
            (
                "**MUST NOT** retain old OUTER through ACK wait, fresh HOP retry, or group cleanup. "
                "OUTER WAS HELD FOR GROUP CLEANUP.  \n"
                "   Duplicate W1 response"
            ),
        ),

        # ===== P1/P2 audit kill suite (+8; 269→277) =====
        mut_one(
            "frame_e2e_class_1_4_to_1_5",
            DOC30,
            "| E2E_BLOB | 1..4 | 1 E2E | E2E sealed blob in L1 output slot |",
            "| E2E_BLOB | 1..5 | 1 E2E | E2E sealed blob in L1 output slot |",
        ),
        mut_one(
            "ack1_outer_release_to_retain_old",
            DOC30,
            "| DATA + outer_ack_requested=1 | terminal-for-pair / **nonterminal-for-group** (never simply “non-terminal”) | WAIT_LINK_ACK; may timeout→fresh HOP DATA; **ACK timer path active** (§11.2) | retain | **release once** after R1 return/TX_RESULT (OUTER_OUTPUT_SLOT_RELEASE_TABLE); fresh HOP gets fresh OUTER |",
            "| DATA + outer_ack_requested=1 | terminal-for-pair / **nonterminal-for-group** (never simply “non-terminal”) | WAIT_LINK_ACK; may timeout→fresh HOP DATA; **ACK timer path active** (§11.2) | retain | **retain old OUTER** through ACK wait |",
        ),
        mut_one(
            "consume_hal16_specialized_row_delete",
            DOC30,
            "| 4 | consume HAL16 NOT_BEFORE RETRY_GATE_OPEN | 6 CONSUME_DENIED | 8 PERMIT_CONSUME | 16 NOT_BEFORE | TX_RETRY_SAME_PERMIT | RETAIN_SEALED | 1 | 0 | pair **nonterminal**; full R1 only same Permit+sealed; calls_used<8; retry_not_before=permit_tx_retry_at | unchanged |\n",
            "",
        ),
        mut_one(
            "validate_hal16_closed_to_retry",
            DOC30,
            "| 3 | validate HAL16 NOT_BEFORE RETRY_GATE_CLOSED | 11 NOT_BEFORE | 7 PERMIT_VALIDATE | 16 NOT_BEFORE | TX_QUARANTINE | QUARANTINE | 0 | 0 | pair nonterminal quarantine; issued ⇒ drain (never local terminal/release); DRAIN then OWNER_TERMINAL | as drain |",
            "| 3 | validate HAL16 NOT_BEFORE RETRY_GATE_CLOSED | 11 NOT_BEFORE | 7 PERMIT_VALIDATE | 16 NOT_BEFORE | TX_RETRY_SAME_PERMIT | RETAIN_SEALED | 0 | 0 | pair nonterminal; force retry past closed gate | unchanged |",
        ),
        mut_one(
            "consume_hal16_closed_to_retry",
            DOC30,
            "| 5 | consume HAL16 NOT_BEFORE RETRY_GATE_CLOSED | 6 CONSUME_DENIED | 8 PERMIT_CONSUME | 16 NOT_BEFORE | TX_QUARANTINE | QUARANTINE | 1 | 0 | pair nonterminal quarantine; issued ⇒ drain (never local terminal/release); DRAIN then OWNER_TERMINAL | as drain |",
            "| 5 | consume HAL16 NOT_BEFORE RETRY_GATE_CLOSED | 6 CONSUME_DENIED | 8 PERMIT_CONSUME | 16 NOT_BEFORE | TX_RETRY_SAME_PERMIT | RETAIN_SEALED | 1 | 0 | pair nonterminal; force retry past closed gate | unchanged |",
        ),
        mut_one(
            "hal45_closed_to_retry",
            DOC30,
            "| 7 | consume HAL45 CONSUME_BUSY RETRY_GATE_CLOSED | 6 CONSUME_DENIED | 8 PERMIT_CONSUME | 45 CONSUME_BUSY | TX_QUARANTINE | QUARANTINE | 1 | 0 | pair nonterminal quarantine; issued ⇒ drain (never local terminal/release); DRAIN then OWNER_TERMINAL | as drain |",
            "| 7 | consume HAL45 CONSUME_BUSY RETRY_GATE_CLOSED | 6 CONSUME_DENIED | 8 PERMIT_CONSUME | 45 CONSUME_BUSY | TX_RETRY_SAME_PERMIT | RETAIN_SEALED | 1 | 0 | pair nonterminal; force retry past closed gate | unchanged |",
        ),
        mut_one(
            "post_consume_catchall_absorb_hal16",
            DOC30,
            "excluding exact consume HAL16 rows 4–5, consume HAL45 rows 6–7, HAL43 row 9, HAL44 row 10 (CONSUME_FENCED/ERROR, unexpected consume return, post-consume plan fault etc., not tuples 6/8/16, 6/8/45, 6/8/43, 6/8/44)",
            "excluding exact rows none (may absorb consume HAL16 6/8/16 into catchall)",
        ),
        mut_one(
            "retry_gate_calls_used_le8",
            DOC30,
            "OPEN requires **`calls_used < 8`**. When `calls_used=8` (call 8) ⇒ CLOSED.",
            "OPEN requires **`calls_used <= 8`**. When `calls_used=9` (call 9) ⇒ CLOSED.",
        ),

        # ===== status finalization kill suite (Accepted → provisional / re-GO → pending / incomplete → complete) =====
        mut_one(
            "final_docs30_status_to_provisional",
            DOC30,
            "状態: **Normative / Accepted / Stage 9**（independent root QA re-GO 2026-07-19 P0=P1=P2=0; Stage 9 crypto P1 closed in docs）",
            "状態: **Normative draft / Accepted 仮 / Stage 9**（独立 root QA re-GO まで完了扱い禁止; Stage 9 crypto P1 closed in docs only）",
        ),
        mut_one(
            "final_adr_status_to_provisional",
            ADR10,
            "状態: **Accepted**（independent root QA re-GO 2026-07-19 P0=P1=P2=0 complete; **Stage 9** docs freeze）",
            "状態: **Accepted 仮**（独立 root QA re-GO まで完了扱い禁止; **Stage 9** docs）",
        ),
        mut_one(
            "final_review_status_to_pre_go",
            FINAL_REVIEW,
            "**状態:** **final Accepted re-GO**（R6 docs freeze Accepted / Stage 9）",
            "**状態:** **closure candidate / final re-audit pending**",
        ),
        mut_one(
            "final_review_p0_unzero",
            FINAL_REVIEW,
            "**Independent integration re-audit:** **P0=0 / P1=0 / P2=0 GO**",
            "**Independent integration re-audit:** **P0=pending / P1=pending / P2=pending NO-GO**",
        ),
        mut_one(
            "final_review_r7_hil_claimed_complete",
            FINAL_REVIEW,
            "R7 full AEAD / M4·M5 / ESP capacity / 実機 HIL / legal / production **未完**。",
            "R7 full AEAD codec **complete** / 実機 HIL 完了 / production radio **complete**。",
        ),
        mut_one(
            "final_docs30_r7_hil_claimed_complete",
            DOC30,
            "（**R6 docs freeze Accepted** — R7 full AEAD codec / M4 handshake 実装 / M5 complete / ESP N6 capacity / Japan legal / RF·USB 実機 HIL / production radio 未完; public ABI 非主張; compile/link ≠ HIL）",
            "（**R6 docs freeze Accepted** — R7 full AEAD codec complete / M4 handshake complete / M5 complete / ESP N6 capacity ready / Japan legal complete / RF·USB 実機 HIL complete / production radio complete; public ABI 非主張）",
        ),
        mut_one(
            "final_adr_decision_to_not_go",
            ADR10,
            "## Decision (Stage 9 accepted — final re-GO complete)",
            "## Decision (Stage 9 repair candidate — independent re-audit)",
        ),
        mut_one(
            "final_reviews_readme_unsupersede",
            "docs/reviews/README.md",
            "（**final Accepted re-GO**; independent integration + storage pin re-audit **P0=0 / P1=0 / P2=0 GO**; status-only delta independent recheck **P0=0 / P1=0 / P2=0 GO**; R6 docs freeze Accepted; R7/M4/M5/ESP capacity/実機 HIL/legal/production 未完）",
            "（**closure candidate / final re-audit pending**; GO・Accepted・P0/P1/P2=0 は未確定）",
        ),
        mut_one(
            "final_status_delta_recheck_to_pending",
            FINAL_REVIEW,
            "**Status-only closure:** **final status-only delta independent recheck P0=0 / P1=0 / P2=0 GO**",
            "**Honest pending:** **final status-only delta independent recheck pending**",
        ),

    ]

    print(f"radio_wire_r6_docs_gate self-test: baseline OK; {len(cases)} mutations...")
    missed: list[str] = []
    for name, rel, fn in cases:
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            for r in _copy_targets:
                src = repo / r
                if not src.is_file():
                    continue
                dst = tmp / r
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
            d25 = repo / "docs/25-u5-cell-operating-assignment.md"
            if d25.is_file():
                dst = tmp / "docs/25-u5-cell-operating-assignment.md"
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(d25, dst)
            try:
                path = tmp / rel
                if not path.is_file():
                    fail(f"mutator {name}: target missing {rel}")
                old = path.read_text(encoding="utf-8")
                new = fn(old)
                if new == old:
                    fail(f"mutator no-op {name} on {rel}")
                if len(new) == len(old) and new == old:
                    fail(f"mutator no-op {name}")
                # assert intended file actually changed
                path.write_text(new, encoding="utf-8")
                if path.read_text(encoding="utf-8") == old:
                    fail(f"mutator {name}: write did not change {rel}")
            except GateFailure as e:
                print(f"  mutation setup FAIL: {name} ({e})")
                missed.append(name)
                continue
            except RuntimeError as e:
                print(f"  mutation setup FAIL: {name} ({e})")
                missed.append(name)
                continue
            try:
                check(tmp)
            except GateFailure as e:
                print(f"  mutation caught: {name} ({e})")
                continue
            print(f"  mutation MISSED: {name}")
            missed.append(name)
    if missed:
        fail(f"mutations not rejected: {missed}")
    print(f"radio_wire_r6_docs_gate self-test: OK ({len(cases)} mutations caught)")


def main(argv: list[str]) -> int:
    root = REPO_ROOT
    mode = None
    args = argv[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--root" and i + 1 < len(args):
            root = pathlib.Path(args[i + 1]).resolve()
            i += 2
            continue
        if a in ("--check", "check"):
            mode = "check"
            i += 1
            continue
        if a in ("--self-test", "self-test"):
            mode = "self-test"
            i += 1
            continue
        print("usage: radio_wire_r6_docs_gate.py [--root DIR] --check|--self-test", file=sys.stderr)
        return 2
    if mode is None:
        print("usage: radio_wire_r6_docs_gate.py [--root DIR] --check|--self-test", file=sys.stderr)
        return 2
    try:
        if mode == "check":
            check(root)
            print("radio_wire_r6_docs_gate: OK")
        else:
            self_test(root)
    except GateFailure as e:
        print(f"radio_wire_r6_docs_gate FAIL: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
